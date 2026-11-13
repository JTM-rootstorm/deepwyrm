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
    /// Each object page's frame, in object order.
    frames: std::vec::Vec<u64>,
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
        Self::with_runs(frames, &[])
    }

    /// As [`Fixture::new`], with the object's backing taken from free runs
    /// of these sizes (summing to `PAGES`) when `runs` is not empty.
    #[allow(
        unsafe_code,
        reason = "the host model attests synthetic frame zeroing and root ownership"
    )]
    fn with_runs(frames: u64, runs: &[u64]) -> Self {
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
        let backing = if runs.is_empty() {
            let allocation = roles.allocate(PAGES).unwrap();
            // SAFETY: as for the root.
            let backing = unsafe { roles.assume_zeroed(allocation) }.unwrap();
            roles.assign_object_backing(backing).unwrap()
        } else {
            // Holes of the run sizes between held pages, and the rest held,
            // so the backing must take exactly those runs.
            let mut holes = std::vec::Vec::new();
            for &run in runs {
                holes.push(roles.allocate(run).unwrap());
                // Held for the test's life: the range has no destructor.
                let _ = roles.allocate(1).unwrap();
            }
            let rest = roles.allocate(roles.available_frames()).unwrap();
            for hole in holes {
                roles.cancel_allocation(hole).unwrap();
            }
            let allocation = roles.allocate_backing(PAGES).unwrap();
            roles.cancel_allocation(rest).unwrap();
            // SAFETY: the host model never dereferences synthetic frames.
            unsafe { roles.assume_backing_zeroed(allocation) }.unwrap()
        };
        let backing_start = backing.physical_start();
        let frames: std::vec::Vec<u64> = roles
            .object_segments(backing.identity(), 0, PAGES * BASE_PAGE_SIZE, true)
            .unwrap()
            .flat_map(|segment| {
                (0..segment.byte_len / BASE_PAGE_SIZE)
                    .map(move |page| segment.physical_start + page * BASE_PAGE_SIZE)
            })
            .collect();
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
            frames,
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
        let (result, undone) = self.change(target, None);
        assert_eq!(result, Ok(()));
        assert!(!undone);
    }

    /// Unmaps the region (`None`) or protects it, as `map` reports.
    fn change(
        &mut self,
        target: &mut FakeTarget,
        protection: Option<Protection>,
    ) -> (Result<(), X86AddressSpacePublishError<()>>, bool) {
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            target,
        );
        let changed = match protection {
            None => self.region.unmap(
                &mut self.objects,
                &mut self.registry,
                &mut publisher,
                START,
                PAGES * BASE_PAGE_SIZE,
            ),
            Some(protection) => self.region.protect(
                &mut self.objects,
                &mut self.registry,
                &mut publisher,
                START,
                PAGES * BASE_PAGE_SIZE,
                protection,
            ),
        };
        let result = match changed {
            Ok(_releases) => Ok(()),
            Err(failure) => match failure.error() {
                AddressSpaceTransactionError::Publish(error) => Err(*error),
                other => panic!("change failed outside the publisher: {other:?}"),
            },
        };
        (result, publisher.failed_after_publishing())
    }

    /// `page`'s raw leaf entry, if its tables exist.
    fn raw_leaf(&self, target: &FakeTarget, page: u64) -> Option<u64> {
        let physical_mask = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);
        let mut table = self.root.physical_start();
        for level in (1..=3).rev() {
            let index = ((page >> (12 + level * 9)) & 0x1ff) as usize;
            table = target.entries.get(&(table, index)).copied()? & physical_mask;
        }
        target
            .entries
            .get(&(table, ((page >> 12) & 0x1ff) as usize))
            .copied()
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

#[test]
fn a_failed_later_unmap_batch_restores_the_unmapped_pages() {
    let mut fixture = Fixture::new(24);
    let mut target = FakeTarget::default();
    assert_eq!(fixture.map(&mut target).0, Ok(()));
    target.fail_apply_at = Some(target.apply_count + 2);
    let (result, undone) = fixture.change(&mut target, None);
    assert_eq!(
        result,
        Err(X86AddressSpacePublishError::Journal(
            OwnedPageTableJournalError::Target(())
        ))
    );
    assert!(undone);
    // The undo maps the first batch's pages back under their own tables,
    // with no candidate.
    for (index, page) in Fixture::pages().enumerate() {
        assert_eq!(
            fixture.leaf(&target, page),
            Some(fixture.backing_start + index as u64 * BASE_PAGE_SIZE),
            "page {page:#x}"
        );
    }
    assert_eq!(fixture.region.mappings().iter().flatten().count(), 1);
    assert_eq!(fixture.objects.active_lease_count(), 1);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_failed_later_protect_batch_restores_the_old_permissions() {
    let mut fixture = Fixture::new(24);
    let mut target = FakeTarget::default();
    assert_eq!(fixture.map(&mut target).0, Ok(()));
    let before: Vec<_> = Fixture::pages()
        .map(|page| fixture.raw_leaf(&target, page))
        .collect();
    assert!(
        before
            .iter()
            .all(|leaf| leaf.is_some_and(|leaf| leaf & super::super::super::WRITABLE != 0))
    );
    target.fail_apply_at = Some(target.apply_count + 2);
    let (result, undone) = fixture.change(&mut target, Some(Protection::READ));
    assert!(result.is_err());
    assert!(undone);
    let after: Vec<_> = Fixture::pages()
        .map(|page| fixture.raw_leaf(&target, page))
        .collect();
    assert_eq!(after, before, "every leaf is writable again");
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_refill_whose_zeroing_fails_returns_its_frame_and_undoes() {
    let mut fixture = Fixture::new(24);
    let free = fixture.roles.available_frames();
    let mut target = FakeTarget {
        fail_zero: true,
        ..FakeTarget::default()
    };
    let (result, undone) = fixture.map(&mut target);
    assert_eq!(
        result,
        Err(X86AddressSpacePublishError::Journal(
            OwnedPageTableJournalError::Target(())
        ))
    );
    assert!(undone);
    assert!(Fixture::pages().all(|page| fixture.leaf(&target, page).is_none()));
    // Batch one turned its three candidates into tables; the failed
    // refill's frame went back.
    assert_eq!(fixture.roles.available_frames(), free);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// DW2 §7.1 G4: a batch may start partway into a run. With runs of three
/// and one page and two pages per journal, one batch starts inside the
/// three-page run; every page still maps its own frame, there and in the
/// unmap.
#[test]
fn a_batch_starting_inside_a_run_of_a_scattered_backing_maps_its_own_frames() {
    let mut fixture = Fixture::with_runs(40, &[3, 1]);
    let runs = fixture
        .frames
        .windows(2)
        .filter(|pair| pair[1] != pair[0] + BASE_PAGE_SIZE)
        .count()
        + 1;
    assert_eq!(runs, 2, "the backing is two runs");
    let mut target = FakeTarget::default();
    let (result, undone) = fixture.map(&mut target);
    assert_eq!(result, Ok(()));
    assert!(!undone);
    assert_eq!(target.apply_count, 2);
    for (index, page) in Fixture::pages().enumerate() {
        assert_eq!(
            fixture.leaf(&target, page),
            Some(fixture.frames[index]),
            "page {page:#x}"
        );
    }
    fixture.unmap(&mut target);
    assert!(Fixture::pages().all(|page| fixture.leaf(&target, page).is_none()));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}
