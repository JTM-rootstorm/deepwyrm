extern crate std;

use super::super::{MappingPermissions, PageTableRoot, PagingCapabilities};
use super::*;
use crate::memory::address_region::{AddressSpaceAuthority, Protection};
use crate::memory::frame_roles::synthetic_frame_role_manager;
use crate::memory::object::{MemoryObjectAuthority, MemoryObjectKind};
use crate::memory::physical::{PhysicalAddressLimit, PhysicalRange};
use crate::object::ObjectRegistry;
use deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT;
use std::collections::BTreeMap;
use std::vec::Vec;

#[derive(Default)]
struct FakeTarget {
    entries: BTreeMap<(u64, usize), u64>,
    applied: Vec<(u64, usize)>,
    invalidated: Vec<u64>,
    fail_apply: bool,
    read_count: usize,
    mutate_on_read: Option<(usize, (u64, usize), u64)>,
}

impl target_seal::Sealed for FakeTarget {}

#[allow(
    unsafe_code,
    reason = "the host fake clones state before publishing its atomic batch"
)]
unsafe impl AtomicPageTableTarget for FakeTarget {
    type Error = ();

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.read_count += 1;
        if let Some((read, location, value)) = self.mutate_on_read
            && self.read_count == read
        {
            self.entries.insert(location, value);
        }
        Ok(*self.entries.get(&(table.address(), index)).unwrap_or(&0))
    }

    fn apply(
        &mut self,
        writes: &[JournalWrite],
        invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error> {
        if self.fail_apply {
            return Err(());
        }
        let mut entries = self.entries.clone();
        for write in writes.iter().copied() {
            entries.insert((write.table().address(), write.index()), write.value());
        }
        self.entries = entries;
        self.applied.extend(
            writes
                .iter()
                .map(|write| (write.table().address(), write.index())),
        );
        self.invalidated
            .extend(invalidations.iter().map(|page| page.address()));
        Ok(())
    }
}

fn mutation(table: u64, index: usize, expected: u64, replacement: u64) -> EntryMutation {
    EntryMutation {
        table: FrameAddress(table),
        index,
        expected,
        compare_mask: u64::MAX,
        replacement,
        preserve_mask: 0,
    }
}

#[test]
fn journal_is_invisible_until_atomic_child_first_publication() {
    let mut target = FakeTarget::default();
    let page = VirtualPage::new(0x4000).unwrap();
    let mut journal = PageTableJournal::<_, 4, 1>::new(&mut target);
    let mut plan = MutationPlan::empty(FrameAddress(0x1000), page);
    plan.push_mutation(mutation(0x1000, 0, 0, 0x2003));
    plan.push_mutation(mutation(0x2000, 0, 0, 0x3003));
    journal.commit(&plan).unwrap();
    assert_eq!(journal.read_entry(FrameAddress(0x1000), 0), Ok(0x2003));
    journal.publish().unwrap();

    assert_eq!(target.entries.get(&(0x1000, 0)), Some(&0x2003));
    assert_eq!(target.entries.get(&(0x2000, 0)), Some(&0x3003));
    assert_eq!(target.applied, [(0x2000, 0), (0x1000, 0)]);
    assert_eq!(target.invalidated, [0x4000]);
}

#[test]
fn apply_failure_and_late_conflict_leave_the_target_unchanged() {
    let page = VirtualPage::new(0x4000).unwrap();
    let mut target = FakeTarget {
        fail_apply: true,
        ..FakeTarget::default()
    };
    let mut journal = PageTableJournal::<_, 2, 1>::new(&mut target);
    let mut plan = MutationPlan::empty(FrameAddress(0x1000), page);
    plan.push_mutation(mutation(0x1000, 0, 0, 0x2003));
    journal.commit(&plan).unwrap();
    assert_eq!(journal.publish(), Err(PageTableJournalError::Access(())));
    assert!(target.entries.is_empty());
    assert!(target.invalidated.is_empty());

    target.fail_apply = false;
    target.read_count = 0;
    target.mutate_on_read = Some((2, (0x1000, 0), 7));
    let mut journal = PageTableJournal::<_, 2, 1>::new(&mut target);
    journal.commit(&plan).unwrap();
    assert_eq!(journal.publish(), Err(PageTableJournalError::Conflict));
    assert_eq!(target.entries.get(&(0x1000, 0)), Some(&7));
    assert!(target.applied.is_empty());
    assert!(target.invalidated.is_empty());
}

#[test]
fn capacity_failure_rolls_back_the_entire_plan_overlay() {
    let mut target = FakeTarget::default();
    let page = VirtualPage::new(0x4000).unwrap();
    let mut journal = PageTableJournal::<_, 1, 1>::new(&mut target);
    let mut plan = MutationPlan::empty(FrameAddress(0x1000), page);
    plan.push_mutation(mutation(0x1000, 0, 0, 0x2003));
    plan.push_mutation(mutation(0x2000, 0, 0, 0x3003));
    assert_eq!(journal.commit(&plan), Err(CommitError::TableClaimRejected));
    assert_eq!(journal.read_entry(FrameAddress(0x1000), 0), Ok(0));
    journal.publish().unwrap();
    assert!(target.entries.is_empty());
    assert!(target.invalidated.is_empty());
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model attests synthetic frame zeroing and root ownership"
)]
fn owned_journal_claims_candidate_chain_only_after_target_publication() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
    let owner = roles.create_table_owner().unwrap();

    let root_allocation = roles.allocate(1).unwrap();
    let root = unsafe { roles.assume_zeroed(root_allocation) }.unwrap();
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

    let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
    for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
        .into_iter()
        .enumerate()
    {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
    }
    let candidate_addresses: [u64; 3] = core::array::from_fn(|slot| {
        candidates[slot]
            .as_ref()
            .expect("candidate slot is populated")
            .physical_start()
    });

    let backing_allocation = roles.allocate(1).unwrap();
    let backing = unsafe { roles.assume_zeroed(backing_allocation) }.unwrap();
    let backing = roles.assign_object_backing(backing).unwrap();
    let mut target = FakeTarget::default();
    let page = VirtualPage::new(0x4000).unwrap();

    let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
        &mut target,
        &mut roles,
        root,
        limit,
        &mut candidates,
    )
    .unwrap();
    journal
        .authorize_leaf(backing.identity(), backing.physical_start())
        .unwrap();
    page_tables
        .map_page(
            &mut journal,
            page,
            backing.physical_start(),
            MappingPermissions::USER_READ_WRITE,
            &candidate_addresses,
        )
        .unwrap();
    journal.publish().unwrap();

    assert!(candidates.iter().all(Option::is_none));
    assert_eq!(target.applied.len(), 4);
    assert_eq!(target.applied[0].0, candidate_addresses[2]);
    assert_eq!(target.applied[3].0, root.physical_start());
    for (address, level) in
        candidate_addresses
            .into_iter()
            .zip([TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt])
    {
        assert!(roles.table_identity(owner, level, address).is_ok());
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model attests synthetic frame zeroing and root ownership"
)]
fn owned_journal_upgrades_shared_supervisor_ancestors_without_exposing_the_leaf() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };
    let mut roles = synthetic_frame_role_manager::<1, 24>(0x1000, 12);
    let owner = roles.create_table_owner().unwrap();
    let allocation = roles.allocate(1).unwrap();
    let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

    let mut committed = [root; 3];
    let mut parent = root;
    for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
        .into_iter()
        .enumerate()
    {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let candidate = roles.prepare_table(zeroed, owner, level).unwrap();
        committed[slot] = roles.commit_table(candidate, Some(parent)).unwrap();
        parent = committed[slot];
    }
    let kernel_tables = committed.map(TableIdentity::physical_start);
    let kernel_page = VirtualPage::new(0x7000).unwrap();
    let mut target = FakeTarget::default();
    target.entries.insert(
        (root.physical_start(), kernel_page.index(3)),
        kernel_tables[0] | super::super::PRESENT | super::super::WRITABLE,
    );
    target.entries.insert(
        (kernel_tables[0], kernel_page.index(2)),
        kernel_tables[1] | super::super::PRESENT | super::super::WRITABLE,
    );
    target.entries.insert(
        (kernel_tables[1], kernel_page.index(1)),
        kernel_tables[2] | super::super::PRESENT | super::super::WRITABLE,
    );
    target.entries.insert(
        (kernel_tables[2], kernel_page.index(0)),
        0x9000 | super::super::PRESENT,
    );

    let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
    let allocation = roles.allocate(1).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let user_pt = roles.prepare_table(zeroed, owner, TableLevel::Pt).unwrap();
    let user_pt_address = user_pt.physical_start();
    candidates[0] = Some(user_pt);
    let allocation = roles.allocate(1).unwrap();
    let user_backing = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let user_backing = roles.assign_object_backing(user_backing).unwrap();
    let user_page = VirtualPage::new(0x400000).unwrap();
    let mut journal = OwnedPageTableJournal::<_, 1, 24, 3, 8, 1>::new(
        &mut target,
        &mut roles,
        root,
        limit,
        &mut candidates,
    )
    .unwrap();
    journal
        .authorize_leaf(user_backing.identity(), user_backing.physical_start())
        .unwrap();
    page_tables
        .map_page(
            &mut journal,
            user_page,
            user_backing.physical_start(),
            MappingPermissions::USER_READ_ONLY,
            &[user_pt_address],
        )
        .unwrap();
    journal.publish().unwrap();

    assert_ne!(
        target.entries[&(root.physical_start(), user_page.index(3))] & super::super::USER,
        0
    );
    assert_ne!(
        target.entries[&(kernel_tables[0], user_page.index(2))] & super::super::USER,
        0
    );
    assert_eq!(
        target.entries[&(kernel_tables[1], kernel_page.index(1))] & super::super::USER,
        0
    );
    assert_eq!(
        target.entries[&(kernel_tables[2], kernel_page.index(0))] & super::super::USER,
        0
    );
    assert_ne!(
        target.entries[&(kernel_tables[1], user_page.index(1))] & super::super::USER,
        0
    );
    assert_ne!(
        target.entries[&(user_pt_address, user_page.index(0))] & super::super::USER,
        0
    );
    assert_eq!(target.invalidated, [0x400000]);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model attests synthetic frame zeroing and root ownership"
)]
fn owned_journal_restores_candidate_grants_when_atomic_target_rejects() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
    let owner = roles.create_table_owner().unwrap();
    let allocation = roles.allocate(1).unwrap();
    let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

    let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
    for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
        .into_iter()
        .enumerate()
    {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
    }
    let addresses: [u64; 3] =
        core::array::from_fn(|slot| candidates[slot].as_ref().unwrap().physical_start());
    let allocation = roles.allocate(1).unwrap();
    let backing = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(backing).unwrap();
    let mut target = FakeTarget {
        fail_apply: true,
        ..FakeTarget::default()
    };
    let page = VirtualPage::new(0x4000).unwrap();

    let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
        &mut target,
        &mut roles,
        root,
        limit,
        &mut candidates,
    )
    .unwrap();
    journal
        .authorize_leaf(backing.identity(), backing.physical_start())
        .unwrap();
    page_tables
        .map_page(
            &mut journal,
            page,
            backing.physical_start(),
            MappingPermissions::USER_READ_ONLY,
            &addresses,
        )
        .unwrap();
    assert_eq!(
        journal.publish(),
        Err(OwnedPageTableJournalError::Target(()))
    );

    assert!(candidates.iter().all(Option::is_some));
    assert!(target.entries.is_empty());
    assert!(target.invalidated.is_empty());
    for (candidate, level) in
        candidates
            .iter()
            .zip([TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt])
    {
        assert_eq!(candidate.as_ref().unwrap().level(), level);
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model attests synthetic frame zeroing, root ownership, and immutable module provenance"
)]
fn owned_journal_derives_writability_from_the_leaf_replacement() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
    let owner = roles.create_table_owner().unwrap();
    let allocation = roles.allocate(1).unwrap();
    let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

    let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
    for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
        .into_iter()
        .enumerate()
    {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
    }
    let candidate_addresses: [u64; 3] = core::array::from_fn(|slot| {
        candidates[slot]
            .as_ref()
            .expect("candidate slot is populated")
            .physical_start()
    });

    let immutable_range = PhysicalRange::new(0x20_000, BASE_PAGE_SIZE).unwrap();
    let backing = unsafe { roles.import_immutable_module(immutable_range, 0) }.unwrap();
    let page = VirtualPage::new(0x4000).unwrap();
    let mut target = FakeTarget::default();

    {
        let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
            &mut target,
            &mut roles,
            root,
            limit,
            &mut candidates,
        )
        .unwrap();
        journal
            .authorize_leaf(backing.identity(), backing.physical_start())
            .unwrap();
        assert_eq!(
            page_tables.map_page(
                &mut journal,
                page,
                backing.physical_start(),
                MappingPermissions::USER_READ_WRITE,
                &candidate_addresses,
            ),
            Err(super::super::MapError::TableClaimRejected)
        );
    }
    assert!(candidates.iter().all(Option::is_some));
    assert!(target.entries.is_empty());

    {
        let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
            &mut target,
            &mut roles,
            root,
            limit,
            &mut candidates,
        )
        .unwrap();
        journal
            .authorize_leaf(backing.identity(), backing.physical_start())
            .unwrap();
        page_tables
            .map_page(
                &mut journal,
                page,
                backing.physical_start(),
                MappingPermissions::USER_READ_ONLY,
                &candidate_addresses,
            )
            .unwrap();
        journal.publish().unwrap();
    }
    assert!(candidates.iter().all(Option::is_none));
    let published = target.entries.clone();

    {
        let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
            &mut target,
            &mut roles,
            root,
            limit,
            &mut candidates,
        )
        .unwrap();
        journal
            .authorize_leaf(backing.identity(), backing.physical_start())
            .unwrap();
        assert_eq!(
            page_tables.protect_page(&mut journal, page, MappingPermissions::USER_READ_WRITE,),
            Err(super::super::MapError::TableClaimRejected)
        );
    }
    assert_eq!(target.entries, published);
    assert_eq!(target.invalidated, [page.address()]);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the negative host model deliberately presents mismatched authority and root identities"
)]
fn publisher_construction_rejects_mechanically_detectable_binding_mismatches() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
    let owner = roles.create_table_owner().unwrap();
    let allocation = roles.allocate(1).unwrap();
    let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

    let child = roles.allocate(1).unwrap();
    let child = unsafe { roles.assume_zeroed(child) }.unwrap();
    let child = roles.prepare_table(child, owner, TableLevel::Pdpt).unwrap();
    let child = roles.commit_table(child, Some(root)).unwrap();
    let child_as_root =
        unsafe { PageTableRoot::from_owned_root(child.physical_start(), capabilities) }.unwrap();
    let wrong_frame = unsafe { PageTableRoot::from_owned_root(0x20_000, capabilities) }.unwrap();

    let mut authority = unsafe { AddressSpaceAuthority::<1, 1>::new() };
    let address_space = authority.create_address_space().unwrap();
    let region = authority
        .create_region::<1>(address_space, 0x4000, BASE_PAGE_SIZE)
        .unwrap();
    let mut foreign_authority = unsafe { AddressSpaceAuthority::<1, 1>::new() };
    let foreign_address_space = foreign_authority.create_address_space().unwrap();
    let mut target = FakeTarget::default();
    let mut candidates: [Option<TableCandidateGrant>; 0] = [];

    assert!(matches!(
        unsafe {
            X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                foreign_address_space,
                region.region_key(),
                &page_tables,
                root,
                &mut roles,
                &mut target,
                &mut candidates,
            )
        },
        Err(X86AddressSpacePublishError::Identity)
    ));
    assert!(matches!(
        unsafe {
            X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                address_space,
                region.region_key(),
                &wrong_frame,
                root,
                &mut roles,
                &mut target,
                &mut candidates,
            )
        },
        Err(X86AddressSpacePublishError::Identity)
    ));
    assert!(matches!(
        unsafe {
            X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                address_space,
                region.region_key(),
                &child_as_root,
                child,
                &mut roles,
                &mut target,
                &mut candidates,
            )
        },
        Err(X86AddressSpacePublishError::Identity)
    ));

    let mut foreign_roles = synthetic_frame_role_manager::<1, 4>(0x1000, 2);
    let foreign_owner = foreign_roles.create_table_owner().unwrap();
    let foreign_root = foreign_roles.allocate(1).unwrap();
    let foreign_root = unsafe { foreign_roles.assume_zeroed(foreign_root) }.unwrap();
    let foreign_root = foreign_roles
        .prepare_table(foreign_root, foreign_owner, TableLevel::Pml4)
        .unwrap();
    let foreign_root = foreign_roles.commit_table(foreign_root, None).unwrap();
    let foreign_page_tables =
        unsafe { PageTableRoot::from_owned_root(foreign_root.physical_start(), capabilities) }
            .unwrap();
    assert!(matches!(
        unsafe {
            X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                address_space,
                region.region_key(),
                &foreign_page_tables,
                foreign_root,
                &mut roles,
                &mut target,
                &mut candidates,
            )
        },
        Err(X86AddressSpacePublishError::FrameRole(_))
    ));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host integration model attests synthetic frame zeroing, root ownership, and handle authority"
)]
fn address_region_bridge_commits_replacements_and_rolls_back_target_failure() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };
    let mut roles = synthetic_frame_role_manager::<1, 32>(0x1000, 16);
    let owner = roles.create_table_owner().unwrap();
    let allocation = roles.allocate(1).unwrap();
    let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

    let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
    for (slot, level) in [TableLevel::Pt, TableLevel::Pdpt, TableLevel::Pd]
        .into_iter()
        .enumerate()
    {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
    }
    let pt_address = candidates
        .iter()
        .flatten()
        .find(|candidate| candidate.level() == TableLevel::Pt)
        .unwrap()
        .physical_start();

    let allocation = roles.allocate(2).unwrap();
    let backing = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(backing).unwrap();
    let backing_start = backing.physical_start();
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut objects = MemoryObjectAuthority::<1, 8>::new();
    let object = objects
        .grant_backing(
            &creation,
            backing,
            BASE_PAGE_SIZE * 2,
            MemoryObjectKind::PageBacked,
            Protection::READ_WRITE_EXECUTE,
        )
        .unwrap();
    let object_owner = registry.creation_into_internal(creation).unwrap();
    assert_eq!(object.object_id(), Some(object_owner.id()));

    let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
    let address_space = spaces.create_address_space().unwrap();
    let mut region = spaces
        .create_region::<4>(address_space, 0x4000, BASE_PAGE_SIZE * 4)
        .unwrap();
    let mut target = FakeTarget::default();
    {
        let mut limited = unsafe {
            X86AddressSpacePublisher::<_, 1, 32, 3, 32, 1>::new(
                region.address_space_key(),
                region.region_key(),
                &page_tables,
                root,
                &mut roles,
                &mut target,
                &mut candidates,
            )
        }
        .unwrap();
        let resolved = crate::handle::resolve_test_internal_owner(
            &mut registry,
            &object_owner,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = region
            .authorize_map(&objects, resolved, Protection::READ_WRITE_EXECUTE)
            .unwrap();
        let failure = region
            .map(
                &mut objects,
                &mut registry,
                &mut limited,
                0x4000,
                authorization,
                0,
                BASE_PAGE_SIZE * 2,
                Protection::READ_WRITE,
            )
            .unwrap_err();
        assert!(matches!(
            failure.error(),
            crate::memory::address_region::AddressSpaceTransactionError::Publish(
                X86AddressSpacePublishError::Capacity
            )
        ));
        assert!(failure.into_final_releases().is_empty());
    }
    assert!(region.mappings().iter().all(Option::is_none));
    assert_eq!(objects.active_lease_count(), 0);
    assert!(target.entries.is_empty());
    assert!(candidates.iter().all(Option::is_some));

    {
        let mut publisher = unsafe {
            X86AddressSpacePublisher::<_, 1, 32, 3, 32, 8>::new(
                region.address_space_key(),
                region.region_key(),
                &page_tables,
                root,
                &mut roles,
                &mut target,
                &mut candidates,
            )
        }
        .unwrap();

        let resolved = crate::handle::resolve_test_internal_owner(
            &mut registry,
            &object_owner,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = region
            .authorize_map(&objects, resolved, Protection::READ_WRITE_EXECUTE)
            .unwrap();
        assert!(
            region
                .map(
                    &mut objects,
                    &mut registry,
                    &mut publisher,
                    0x4000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE * 2,
                    Protection::READ_WRITE,
                )
                .unwrap()
                .is_empty()
        );
        assert!(
            region
                .unmap(
                    &mut objects,
                    &mut registry,
                    &mut publisher,
                    0x4000,
                    BASE_PAGE_SIZE,
                )
                .unwrap()
                .is_empty()
        );
        assert!(
            region
                .protect(
                    &mut objects,
                    &mut registry,
                    &mut publisher,
                    0x5000,
                    BASE_PAGE_SIZE,
                    Protection::READ_EXECUTE,
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(region.mappings().iter().flatten().count(), 1);
        assert_eq!(objects.active_lease_count(), 1);

        publisher.target.fail_apply = true;
        let resolved = crate::handle::resolve_test_internal_owner(
            &mut registry,
            &object_owner,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = region
            .authorize_map(&objects, resolved, Protection::READ_EXECUTE)
            .unwrap();
        let failure = region
            .map(
                &mut objects,
                &mut registry,
                &mut publisher,
                0x4000,
                authorization,
                0,
                BASE_PAGE_SIZE,
                Protection::READ_EXECUTE,
            )
            .unwrap_err();
        assert!(matches!(
            failure.error(),
            crate::memory::address_region::AddressSpaceTransactionError::Publish(
                X86AddressSpacePublishError::Journal(OwnedPageTableJournalError::Target(()))
            )
        ));
        assert!(failure.into_final_releases().is_empty());
        assert_eq!(region.mappings().iter().flatten().count(), 1);
        assert_eq!(objects.active_lease_count(), 1);

        publisher.target.fail_apply = false;
        let resolved = crate::handle::resolve_test_internal_owner(
            &mut registry,
            &object_owner,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = region
            .authorize_map(&objects, resolved, Protection::READ_EXECUTE)
            .unwrap();
        assert!(
            region
                .map(
                    &mut objects,
                    &mut registry,
                    &mut publisher,
                    0x4000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE,
                    Protection::READ_EXECUTE,
                )
                .unwrap()
                .is_empty()
        );
    }

    let slot_zero = region.mappings()[0].expect("first mapping slot remains published");
    let slot_one = region.mappings()[1].expect("second mapping slot remains published");
    let (first_mapping, second_mapping) = if slot_zero.virtual_start() < slot_one.virtual_start() {
        (slot_zero, slot_one)
    } else {
        (slot_one, slot_zero)
    };
    let reverse_order = [second_mapping, first_mapping];
    assert_eq!(first_mapping_start(&reverse_order, &[]), Some(0x4000));
    assert_eq!(
        next_mapping_start(&reverse_order, &[], 0x4000),
        Some(0x5000)
    );
    assert_eq!(
        mapping_at::<()>(&reverse_order, 0x4000),
        Ok(Some(&reverse_order[1]))
    );
    assert_eq!(mapping_at::<()>(&reverse_order, 0x6000), Ok(None));
    assert_eq!(
        next_boundary::<()>(&reverse_order, &[], 0x4000, Some(&reverse_order[1]), None),
        Ok(0x5000)
    );
    assert!(candidates.iter().all(Option::is_none));
    assert_eq!(target.invalidated, [0x4000, 0x5000, 0x4000, 0x5000, 0x4000]);
    assert_eq!(
        target.entries.get(&(pt_address, 4)).copied(),
        Some(backing_start | super::super::PRESENT | super::super::USER)
    );
    assert_eq!(objects.active_lease_count(), 2);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host integration model supplies two independently typed inactive roots and zeroed frame grants"
)]
fn bounded_stack_mapping_crosses_every_lower_table_boundary_and_overflow_rolls_back() {
    const STACK_PAGES: u64 = 16;
    const STACK_START: u64 = 0x0000_007f_ffff_f000;
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };

    // The final page below 512 GiB crosses the PT, PD, PDPT, and PML4 entry
    // boundaries at once. A complete 16-page stack therefore needs two
    // candidates at every lower level, and 16 leaves plus six intermediate
    // journal writes.
    let mut roles = synthetic_frame_role_manager::<1, 64>(0x1000, 32);
    let owner = roles.create_table_owner().unwrap();
    let root_allocation = roles.allocate(1).unwrap();
    let root_zeroed = unsafe { roles.assume_zeroed(root_allocation) }.unwrap();
    let root = roles
        .prepare_table(root_zeroed, owner, TableLevel::Pml4)
        .unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();
    let mut candidates: [Option<TableCandidateGrant>; 6] = [const { None }; 6];
    for (slot, level) in [
        TableLevel::Pdpt,
        TableLevel::Pd,
        TableLevel::Pt,
        TableLevel::Pdpt,
        TableLevel::Pd,
        TableLevel::Pt,
    ]
    .into_iter()
    .enumerate()
    {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
    }
    let allocation = roles.allocate(STACK_PAGES).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut objects = MemoryObjectAuthority::<1, 2>::new();
    let object = objects
        .grant_backing(
            &creation,
            backing,
            STACK_PAGES * BASE_PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            Protection::READ_WRITE,
        )
        .unwrap();
    let object_owner = registry.creation_into_internal(creation).unwrap();
    assert_eq!(object.object_id(), Some(object_owner.id()));
    let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
    let address_space = spaces.create_address_space().unwrap();
    let mut region = spaces
        .create_region::<1>(address_space, STACK_START, STACK_PAGES * BASE_PAGE_SIZE)
        .unwrap();
    let mut target = FakeTarget::default();
    let mut publisher = unsafe {
        X86AddressSpacePublisher::<_, 1, 64, 6, 22, 16>::new(
            region.address_space_key(),
            region.region_key(),
            &page_tables,
            root,
            &mut roles,
            &mut target,
            &mut candidates,
        )
    }
    .unwrap();
    let resolved = crate::handle::resolve_test_internal_owner(
        &mut registry,
        &object_owner,
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let authorization = region
        .authorize_map(&objects, resolved, Protection::READ_WRITE)
        .unwrap();
    assert!(
        region
            .map(
                &mut objects,
                &mut registry,
                &mut publisher,
                STACK_START,
                authorization,
                0,
                STACK_PAGES * BASE_PAGE_SIZE,
                Protection::READ_WRITE,
            )
            .unwrap()
            .is_empty()
    );
    assert_eq!(region.mappings().iter().flatten().count(), 1);
    assert_eq!(objects.active_lease_count(), 1);
    assert_eq!(target.invalidated.len(), STACK_PAGES as usize);
    assert_eq!(candidates.iter().flatten().count(), 0, "{candidates:?}");
    assert_eq!(roles.check_invariants(), Ok(()));

    // The 17th changed page must fail at the publisher's fixed invalidation
    // bound before it can publish any table writes or consume model leases.
    let mut roles = synthetic_frame_role_manager::<1, 64>(0x20000, 32);
    let owner = roles.create_table_owner().unwrap();
    let root_allocation = roles.allocate(1).unwrap();
    let root_zeroed = unsafe { roles.assume_zeroed(root_allocation) }.unwrap();
    let root = roles
        .prepare_table(root_zeroed, owner, TableLevel::Pml4)
        .unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let page_tables =
        unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();
    let mut candidates: [Option<TableCandidateGrant>; 6] = [const { None }; 6];
    for (slot, level) in [
        TableLevel::Pdpt,
        TableLevel::Pd,
        TableLevel::Pt,
        TableLevel::Pdpt,
        TableLevel::Pd,
        TableLevel::Pt,
    ]
    .into_iter()
    .enumerate()
    {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
    }
    let allocation = roles.allocate(STACK_PAGES + 1).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut objects = MemoryObjectAuthority::<1, 2>::new();
    let object = objects
        .grant_backing(
            &creation,
            backing,
            (STACK_PAGES + 1) * BASE_PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            Protection::READ_WRITE,
        )
        .unwrap();
    let object_owner = registry.creation_into_internal(creation).unwrap();
    assert_eq!(object.object_id(), Some(object_owner.id()));
    let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
    let address_space = spaces.create_address_space().unwrap();
    let mut region = spaces
        .create_region::<1>(address_space, 0x400000, (STACK_PAGES + 1) * BASE_PAGE_SIZE)
        .unwrap();
    let mut target = FakeTarget::default();
    let mut publisher = unsafe {
        X86AddressSpacePublisher::<_, 1, 64, 6, 22, 16>::new(
            region.address_space_key(),
            region.region_key(),
            &page_tables,
            root,
            &mut roles,
            &mut target,
            &mut candidates,
        )
    }
    .unwrap();
    let resolved = crate::handle::resolve_test_internal_owner(
        &mut registry,
        &object_owner,
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let authorization = region
        .authorize_map(&objects, resolved, Protection::READ_WRITE)
        .unwrap();
    let failure = region
        .map(
            &mut objects,
            &mut registry,
            &mut publisher,
            0x400000,
            authorization,
            0,
            (STACK_PAGES + 1) * BASE_PAGE_SIZE,
            Protection::READ_WRITE,
        )
        .unwrap_err();
    assert!(matches!(
        failure.error(),
        crate::memory::address_region::AddressSpaceTransactionError::Publish(
            X86AddressSpacePublishError::Capacity
        )
    ));
    assert!(failure.into_final_releases().is_empty());
    assert!(region.mappings().iter().all(Option::is_none));
    assert_eq!(objects.active_lease_count(), 0);
    assert!(target.entries.is_empty());
    assert!(target.invalidated.is_empty());
    assert!(candidates.iter().all(Option::is_some));
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host integration model supplies two independently typed inactive roots and zeroed frame grants"
)]
fn two_bound_publishers_map_same_va_to_distinct_root_local_frames() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let capabilities = PagingCapabilities {
        physical_limit: limit,
    };
    let mut roles = synthetic_frame_role_manager::<1, 64>(0x20_000, 32);

    let owner_a = roles.create_table_owner().unwrap();
    let root_a = roles.allocate(1).unwrap();
    let root_a = unsafe { roles.assume_zeroed(root_a) }.unwrap();
    let root_a = roles
        .prepare_table(root_a, owner_a, TableLevel::Pml4)
        .unwrap();
    let root_a = roles.commit_table(root_a, None).unwrap();
    let page_tables_a =
        unsafe { PageTableRoot::from_owned_root(root_a.physical_start(), capabilities) }.unwrap();

    let owner_b = roles.create_table_owner().unwrap();
    let root_b = roles.allocate(1).unwrap();
    let root_b = unsafe { roles.assume_zeroed(root_b) }.unwrap();
    let root_b = roles
        .prepare_table(root_b, owner_b, TableLevel::Pml4)
        .unwrap();
    let root_b = roles.commit_table(root_b, None).unwrap();
    let page_tables_b =
        unsafe { PageTableRoot::from_owned_root(root_b.physical_start(), capabilities) }.unwrap();

    let mut candidates_a: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
    let mut candidates_b: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
    for (candidates, owner) in [(&mut candidates_a, owner_a), (&mut candidates_b, owner_b)] {
        for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
            .into_iter()
            .enumerate()
        {
            let allocation = roles.allocate(1).unwrap();
            let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
            candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
        }
    }

    let backing_a = roles.allocate(1).unwrap();
    let backing_a = unsafe { roles.assume_zeroed(backing_a) }.unwrap();
    let backing_a = roles.assign_object_backing(backing_a).unwrap();
    let physical_a = backing_a.physical_start();
    let backing_b = roles.allocate(1).unwrap();
    let backing_b = unsafe { roles.assume_zeroed(backing_b) }.unwrap();
    let backing_b = roles.assign_object_backing(backing_b).unwrap();
    let physical_b = backing_b.physical_start();
    assert_ne!(physical_a, physical_b);

    let mut registry = ObjectRegistry::<2>::new();
    let mut objects = MemoryObjectAuthority::<2, 4>::new();
    let creation_a = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let object_a = objects
        .grant_backing(
            &creation_a,
            backing_a,
            BASE_PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            Protection::READ_WRITE,
        )
        .unwrap();
    let owner_ref_a = registry.creation_into_internal(creation_a).unwrap();
    assert_eq!(object_a.object_id(), Some(owner_ref_a.id()));
    let creation_b = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let object_b = objects
        .grant_backing(
            &creation_b,
            backing_b,
            BASE_PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            Protection::READ_WRITE,
        )
        .unwrap();
    let owner_ref_b = registry.creation_into_internal(creation_b).unwrap();
    assert_eq!(object_b.object_id(), Some(owner_ref_b.id()));

    let mut spaces = unsafe { AddressSpaceAuthority::<2, 2>::new() };
    let key_a = spaces.create_address_space().unwrap();
    let key_b = spaces.create_address_space().unwrap();
    let mut region_a = spaces
        .create_region::<1>(key_a, 0x40_0000, BASE_PAGE_SIZE)
        .unwrap();
    let mut region_b = spaces
        .create_region::<1>(key_b, 0x40_0000, BASE_PAGE_SIZE)
        .unwrap();
    let mut target = FakeTarget::default();

    {
        let mut publisher = unsafe {
            X86AddressSpacePublisher::<_, 1, 64, 3, 32, 1>::new(
                key_a,
                region_a.region_key(),
                &page_tables_a,
                root_a,
                &mut roles,
                &mut target,
                &mut candidates_a,
            )
        }
        .unwrap();
        let resolved = crate::handle::resolve_test_internal_owner(
            &mut registry,
            &owner_ref_a,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = region_a
            .authorize_map(&objects, resolved, Protection::READ_WRITE)
            .unwrap();
        assert!(
            region_a
                .map(
                    &mut objects,
                    &mut registry,
                    &mut publisher,
                    0x40_0000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE,
                    Protection::READ_WRITE,
                )
                .unwrap()
                .is_empty()
        );
    }
    let entries_after_a = target.entries.clone();
    {
        let mut publisher = unsafe {
            X86AddressSpacePublisher::<_, 1, 64, 3, 32, 1>::new(
                key_b,
                region_b.region_key(),
                &page_tables_b,
                root_b,
                &mut roles,
                &mut target,
                &mut candidates_b,
            )
        }
        .unwrap();
        let resolved = crate::handle::resolve_test_internal_owner(
            &mut registry,
            &owner_ref_b,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = region_b
            .authorize_map(&objects, resolved, Protection::READ_WRITE)
            .unwrap();
        assert!(
            region_b
                .map(
                    &mut objects,
                    &mut registry,
                    &mut publisher,
                    0x40_0000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE,
                    Protection::READ_WRITE,
                )
                .unwrap()
                .is_empty()
        );
    }

    fn walk_leaf(entries: &BTreeMap<(u64, usize), u64>, root: u64, page: u64) -> u64 {
        let physical_mask = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);
        let mut table = root;
        for level in (1..=3).rev() {
            let entry = entries[&(table, ((page >> (12 + level * 9)) & 0x1ff) as usize)];
            table = entry & physical_mask;
        }
        entries[&(table, ((page >> 12) & 0x1ff) as usize)] & physical_mask
    }

    assert_eq!(
        walk_leaf(&target.entries, root_a.physical_start(), 0x40_0000),
        physical_a
    );
    assert_eq!(
        walk_leaf(&target.entries, root_b.physical_start(), 0x40_0000),
        physical_b
    );
    for (location, value) in &entries_after_a {
        assert_eq!(target.entries.get(location), Some(value));
    }

    let mut no_candidates: [Option<TableCandidateGrant>; 0] = [];
    assert!(matches!(
        unsafe {
            X86AddressSpacePublisher::<_, 1, 64, 0, 1, 1>::new(
                key_b,
                region_a.region_key(),
                &page_tables_a,
                root_a,
                &mut roles,
                &mut target,
                &mut no_candidates,
            )
        },
        Err(X86AddressSpacePublishError::Identity)
    ));
}

/// F3A.6w. The publisher's four capacity walls must stay distinct.
///
/// This test exists because a mutation check caught its absence: collapsing
/// `page-table-frames` onto `publisher-slots` left every other test in the
/// tree green. `is_capacity_error` answers the syscall boundary's question
/// with a bool, so these four named variants were already indistinguishable
/// to a reader *before* the status was chosen. It is the highest-value
/// collapse on the `address_region_map` path -- the path the production
/// Wyrmroot bootstrap fails on while mapping bootfs (F3A.6u).
#[test]
fn the_publisher_capacity_walls_each_name_a_distinct_resource() {
    use super::super::MapError;
    use super::publisher::X86AddressSpacePublishError;

    let cases: [(X86AddressSpacePublishError<()>, &'static str); 4] = [
        (X86AddressSpacePublishError::Capacity, "publisher-slots"),
        (
            X86AddressSpacePublishError::Journal(OwnedPageTableJournalError::JournalCapacity),
            "page-table-journal",
        ),
        (
            X86AddressSpacePublishError::Map(MapError::InsufficientTableFrames),
            "page-table-frames",
        ),
        (
            X86AddressSpacePublishError::Map(MapError::Access(
                OwnedPageTableJournalError::JournalCapacity,
            )),
            "page-table-journal-access",
        ),
    ];

    let mut names = std::vec::Vec::new();
    for (error, expected) in cases {
        // Paired against the bool that picks the status: a variant naming a
        // wall must be one the status boundary agrees is a capacity error.
        assert!(
            error.is_capacity_error(),
            "{expected} must be a capacity error"
        );
        assert_eq!(error.capacity_resource(), Some(expected));
        names.push(expected);
    }
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 4, "four distinct publisher walls: {names:?}");

    // The converse: a non-capacity variant names nothing, or a reader would be
    // told a resource ran out when the refusal was about identity or state.
    for error in [
        X86AddressSpacePublishError::<()>::Identity,
        X86AddressSpacePublishError::<()>::InvalidMapping,
    ] {
        assert!(!error.is_capacity_error());
        assert_eq!(error.capacity_resource(), None);
    }
}
