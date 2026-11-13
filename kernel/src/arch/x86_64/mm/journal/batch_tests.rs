//! DW2 M4: a change larger than one journal is published in batches, the
//! table-candidate pool is refilled between them, and a failure after the
//! first batch undoes the ones already published.

use super::super::super::MapError;
use super::*;
use crate::memory::address_region::{AddressRegion, AddressSpaceTransactionError};
use crate::object::InternalRef;

const PT_SPAN: u64 = 512 * BASE_PAGE_SIZE;
/// Four pages straddling a page-table boundary: two under one PT, two under
/// the next. With room for two pages per journal, that is two batches, and
/// the second needs a PT the first one used up.
const START: u64 = PT_SPAN - 2 * BASE_PAGE_SIZE;
const PAGES: u64 = 4;

type Publisher<'a> = X86AddressSpacePublisher<'a, FakeTarget, 4, 64, 3, 32, 2>;

struct Fixture {
    roles: FrameRoleManager<4, 64>,
    root: TableIdentity,
    page_tables: PageTableRoot,
    candidates: [Option<TableCandidateGrant>; 3],
    backing_start: u64,
    registry: ObjectRegistry<1>,
    objects: MemoryObjectAuthority<1, 2>,
    owner: InternalRef,
    region: AddressRegion<1>,
    _spaces: AddressSpaceAuthority<1, 1>,
}

impl Fixture {
    /// A root, one candidate per level, and a four-page object, from
    /// `frames` frames.
    #[allow(
        unsafe_code,
        reason = "the host model attests synthetic frame zeroing and root ownership"
    )]
    fn new(frames: u64) -> Self {
        let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
        let mut roles = synthetic_frame_role_manager::<4, 64>(0x1000, frames);
        let owner = roles.create_table_owner().unwrap();
        let allocation = roles.allocate(1).unwrap();
        // SAFETY: an unused synthetic allocation is zero by construction.
        let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
        let root = roles.commit_table(root, None).unwrap();
        // SAFETY: `root` is the committed PML4 this model owns exclusively.
        let page_tables = unsafe {
            PageTableRoot::from_owned_root(
                root.physical_start(),
                PagingCapabilities {
                    physical_limit: limit,
                },
            )
        }
        .unwrap();
        let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
        for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
            .into_iter()
            .enumerate()
        {
            let allocation = roles.allocate(1).unwrap();
            // SAFETY: as for the root.
            let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
            candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
        }
        let allocation = roles.allocate(PAGES).unwrap();
        // SAFETY: as for the root.
        let backing = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let backing = roles.assign_object_backing(backing).unwrap();
        let backing_start = backing.physical_start();
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut objects = MemoryObjectAuthority::<1, 2>::new();
        objects
            .grant_backing(
                &creation,
                backing,
                PAGES * BASE_PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                Protection::READ_WRITE,
            )
            .unwrap();
        let owner = registry.creation_into_internal(creation).unwrap();
        // SAFETY: this model creates the only address-space authority it uses.
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let address_space = spaces.create_address_space().unwrap();
        let region = spaces
            .create_region::<1>(address_space, START, PAGES * BASE_PAGE_SIZE)
            .unwrap();
        Self {
            roles,
            root,
            page_tables,
            candidates,
            backing_start,
            registry,
            objects,
            owner,
            region,
            _spaces: spaces,
        }
    }

    #[allow(
        unsafe_code,
        reason = "the keys were issued for the root and region this binds"
    )]
    fn publisher<'a>(
        roles: &'a mut FrameRoleManager<4, 64>,
        root: TableIdentity,
        page_tables: &'a PageTableRoot,
        candidates: &'a mut [Option<TableCandidateGrant>; 3],
        region: &AddressRegion<1>,
        target: &'a mut FakeTarget,
    ) -> Publisher<'a> {
        // SAFETY: the keys were issued for the root and region this binds.
        unsafe {
            X86AddressSpacePublisher::new(
                region.address_space_key(),
                region.region_key(),
                page_tables,
                root,
                roles,
                target,
                candidates,
                storage(),
            )
        }
        .unwrap()
    }

    /// Maps the whole object over the region. The error, and whether the
    /// publisher reports batches published and undone.
    fn map(
        &mut self,
        target: &mut FakeTarget,
    ) -> (Result<(), X86AddressSpacePublishError<()>>, bool) {
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            target,
        );
        let resolved = crate::handle::resolve_test_internal_owner(
            &mut self.registry,
            &self.owner,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = self
            .region
            .authorize_map(&self.objects, resolved, Protection::READ_WRITE)
            .unwrap();
        let result = match self.region.map(
            &mut self.objects,
            &mut self.registry,
            &mut publisher,
            START,
            authorization,
            0,
            PAGES * BASE_PAGE_SIZE,
            Protection::READ_WRITE,
        ) {
            Ok(releases) => {
                assert!(releases.is_empty());
                Ok(())
            }
            Err(failure) => {
                let error = match failure.error() {
                    AddressSpaceTransactionError::Publish(error) => *error,
                    other => panic!("map failed outside the publisher: {other:?}"),
                };
                assert!(failure.into_final_releases().is_empty());
                Err(error)
            }
        };
        let undone = publisher.failed_after_publishing();
        (result, undone)
    }

    fn unmap(&mut self, target: &mut FakeTarget) {
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            target,
        );
        assert!(
            self.region
                .unmap(
                    &mut self.objects,
                    &mut self.registry,
                    &mut publisher,
                    START,
                    PAGES * BASE_PAGE_SIZE,
                )
                .unwrap_or_else(|failure| panic!("unmap failed: {:?}", failure.error()))
                .is_empty()
        );
    }

    /// The frame `page`'s leaf maps, if it is present.
    fn leaf(&self, target: &FakeTarget, page: u64) -> Option<u64> {
        let physical_mask = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);
        let mut table = self.root.physical_start();
        for level in (1..=3).rev() {
            let index = ((page >> (12 + level * 9)) & 0x1ff) as usize;
            table = target.entries.get(&(table, index)).copied()? & physical_mask;
            if table == 0 {
                return None;
            }
        }
        let leaf = target
            .entries
            .get(&(table, ((page >> 12) & 0x1ff) as usize))
            .copied()?;
        (leaf != 0).then_some(leaf & physical_mask)
    }

    fn pages() -> impl Iterator<Item = u64> {
        (0..PAGES).map(|page| START + page * BASE_PAGE_SIZE)
    }
}

#[test]
fn a_map_larger_than_the_journal_publishes_in_batches_and_refills_tables() {
    let mut fixture = Fixture::new(24);
    let mut target = FakeTarget::default();
    let (result, undone) = fixture.map(&mut target);
    assert_eq!(result, Ok(()));
    assert!(!undone);
    assert_eq!(target.apply_count, 2, "two pages per journal");
    for (index, page) in Fixture::pages().enumerate() {
        assert_eq!(
            fixture.leaf(&target, page),
            Some(fixture.backing_start + index as u64 * BASE_PAGE_SIZE),
            "page {page:#x}"
        );
    }
    // The second batch's PT came from the refill; the refilled PDPT and PD
    // were not needed and stay in the pool for the caller to recycle.
    let left: Vec<_> = fixture
        .candidates
        .iter()
        .flatten()
        .map(|candidate| candidate.level())
        .collect();
    assert_eq!(left, [TableLevel::Pdpt, TableLevel::Pd]);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));

    // An unmap of the same size takes two batches too.
    fixture.unmap(&mut target);
    assert_eq!(target.apply_count, 4);
    assert!(Fixture::pages().all(|page| fixture.leaf(&target, page).is_none()));
    assert_eq!(fixture.objects.active_lease_count(), 0);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_failed_later_batch_undoes_the_published_ones() {
    let mut fixture = Fixture::new(24);
    let mut target = FakeTarget {
        fail_apply_at: Some(2),
        ..FakeTarget::default()
    };
    let (result, undone) = fixture.map(&mut target);
    assert_eq!(
        result,
        Err(X86AddressSpacePublishError::Journal(
            OwnedPageTableJournalError::Target(())
        ))
    );
    assert!(undone, "the first batch was published, then undone");
    // Batch one, the failed batch two, and the undo of batch one.
    assert_eq!(target.apply_count, 3);
    assert!(Fixture::pages().all(|page| fixture.leaf(&target, page).is_none()));
    assert!(fixture.region.mappings().iter().all(Option::is_none));
    assert_eq!(fixture.objects.active_lease_count(), 0);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));

    // The tables batch one built stay; the next attempt maps every page.
    let (result, undone) = fixture.map(&mut target);
    assert_eq!(result, Ok(()));
    assert!(!undone);
    for (index, page) in Fixture::pages().enumerate() {
        assert_eq!(
            fixture.leaf(&target, page),
            Some(fixture.backing_start + index as u64 * BASE_PAGE_SIZE)
        );
    }
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn no_frame_for_a_refill_undoes_the_published_batches() {
    let mut fixture = Fixture::new(24);
    let _rest = fixture
        .roles
        .allocate(fixture.roles.available_frames())
        .unwrap();
    let mut target = FakeTarget::default();
    let (result, undone) = fixture.map(&mut target);
    assert_eq!(
        result,
        Err(X86AddressSpacePublishError::Map(
            MapError::InsufficientTableFrames
        ))
    );
    assert!(undone);
    assert_eq!(target.apply_count, 2, "batch one and its undo");
    assert!(Fixture::pages().all(|page| fixture.leaf(&target, page).is_none()));
    assert!(fixture.region.mappings().iter().all(Option::is_none));
    assert_eq!(fixture.objects.active_lease_count(), 0);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}
