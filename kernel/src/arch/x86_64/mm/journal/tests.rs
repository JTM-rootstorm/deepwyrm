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
