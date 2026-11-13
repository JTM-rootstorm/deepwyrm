//! DW2 M6 §8.6: an on-demand page committed in its object may have a leaf
//! in one mapping and none in another. Unmap, protect and teardown take
//! each address space's leaves as they are, and a touch publishes one leaf.

use super::super::super::MapError;
use super::*;
use crate::memory::address_region::{AddressRegion, AddressSpaceTransactionError, Mapping};
use crate::memory::frame_roles::IndexMemory;
use crate::object::InternalRef;
use std::boxed::Box;
use std::collections::BTreeSet;
use std::sync::Mutex;

/// Two mappings of one four-page object, side by side under one PT.
const START: u64 = 0x40_0000;
const PAGES: u64 = 4;
const SPAN: u64 = PAGES * BASE_PAGE_SIZE;
const ALIAS: u64 = START + SPAN;

type Publisher<'a> = X86AddressSpacePublisher<'a, FakeTarget, 4, 64, 3, 32, 4>;

/// Index pages as physical memory: zero once zeroed, written entries after.
#[derive(Default)]
struct Model {
    zeroed: Mutex<BTreeSet<u64>>,
    entries: Mutex<BTreeMap<(u64, usize), u64>>,
}

impl IndexMemory for Model {
    fn read(&self, node: u64, entry: usize) -> u64 {
        let entries = self.entries.lock().unwrap();
        match entries.get(&(node, entry)) {
            Some(value) => *value,
            None if self.zeroed.lock().unwrap().contains(&node) => 0,
            None => panic!("an index node is read before it is zeroed"),
        }
    }

    #[allow(
        unsafe_code,
        reason = "the model implements the trait's unsafe methods"
    )]
    unsafe fn write(&self, node: u64, entry: usize, value: u64) {
        self.entries.lock().unwrap().insert((node, entry), value);
    }

    #[allow(
        unsafe_code,
        reason = "the model implements the trait's unsafe methods"
    )]
    unsafe fn zero(&self, page: u64) -> bool {
        self.entries
            .lock()
            .unwrap()
            .retain(|(node, _), _| *node != page);
        self.zeroed.lock().unwrap().insert(page);
        true
    }
}

struct Fixture {
    roles: FrameRoleManager<4, 64>,
    root: TableIdentity,
    page_tables: PageTableRoot,
    candidates: [Option<TableCandidateGrant>; 3],
    backing: crate::memory::frame_roles::BackingIdentity,
    registry: ObjectRegistry<1>,
    objects: MemoryObjectAuthority<1, 4>,
    owner: InternalRef,
    region: AddressRegion<2>,
    spaces: AddressSpaceAuthority<2, 2>,
    target: FakeTarget,
    /// A second Process's root, candidates and region, swapped in by
    /// [`Fixture::swap_process`].
    other: Option<(
        TableIdentity,
        PageTableRoot,
        [Option<TableCandidateGrant>; 3],
        AddressRegion<2>,
    )>,
}

/// A committed PML4 for a new table owner, and one candidate per level.
#[allow(
    unsafe_code,
    reason = "the host model attests synthetic frame zeroing and root ownership"
)]
fn new_root(
    roles: &mut FrameRoleManager<4, 64>,
) -> (
    TableIdentity,
    PageTableRoot,
    [Option<TableCandidateGrant>; 3],
) {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
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
    (root, page_tables, candidates)
}

impl Fixture {
    /// A root, one candidate per level, and an on-demand object mapped at
    /// `START` and at `ALIAS`, no page committed.
    #[allow(
        unsafe_code,
        reason = "the host model attests synthetic frame zeroing and root ownership"
    )]
    fn new() -> Self {
        let mut roles = synthetic_frame_role_manager::<4, 64>(0x1000, 32);
        roles.set_index_memory(Box::leak(Box::<Model>::default()));
        let (root, page_tables, candidates) = new_root(&mut roles);
        let grant = roles.allocate_on_demand_backing(PAGES).unwrap();
        let backing = grant.identity();
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut objects = MemoryObjectAuthority::<1, 4>::new();
        objects
            .grant_backing(
                &creation,
                grant,
                SPAN,
                MemoryObjectKind::OnDemand,
                Protection::READ_WRITE,
            )
            .unwrap();
        let owner = registry.creation_into_internal(creation).unwrap();
        // SAFETY: this model creates the only address-space authority it uses.
        let mut spaces = unsafe { AddressSpaceAuthority::<2, 2>::new() };
        let address_space = spaces.create_address_space().unwrap();
        let region = spaces
            .create_region::<2>(address_space, START, 2 * SPAN)
            .unwrap();
        let mut fixture = Self {
            roles,
            root,
            page_tables,
            candidates,
            backing,
            registry,
            objects,
            owner,
            region,
            spaces,
            target: FakeTarget::default(),
            other: None,
        };
        fixture.map(START).unwrap();
        fixture.map(ALIAS).unwrap();
        fixture
    }

    /// Gives a second Process its own root and maps the same object at
    /// `START` and `ALIAS` there too; it is reached by swapping it in.
    fn add_process(&mut self) {
        let (root, page_tables, candidates) = new_root(&mut self.roles);
        let address_space = self.spaces.create_address_space().unwrap();
        let region = self
            .spaces
            .create_region::<2>(address_space, START, 2 * SPAN)
            .unwrap();
        self.other = Some((root, page_tables, candidates, region));
        self.swap_process();
        self.map(START).unwrap();
        self.map(ALIAS).unwrap();
        self.swap_process();
    }

    /// Makes the other Process's root and region the ones every helper uses.
    fn swap_process(&mut self) {
        let other = self.other.as_mut().expect("a second process");
        core::mem::swap(&mut self.root, &mut other.0);
        core::mem::swap(&mut self.page_tables, &mut other.1);
        core::mem::swap(&mut self.candidates, &mut other.2);
        core::mem::swap(&mut self.region, &mut other.3);
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
        region: &AddressRegion<2>,
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

    fn map(&mut self, at: u64) -> Result<(), X86AddressSpacePublishError<()>> {
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            &mut self.target,
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
        match self.region.map(
            &mut self.objects,
            &mut self.registry,
            &mut publisher,
            at,
            authorization,
            0,
            SPAN,
            Protection::READ_WRITE,
        ) {
            Ok(_) => Ok(()),
            Err(failure) => match failure.error() {
                AddressSpaceTransactionError::Publish(error) => Err(*error),
                other => panic!("map failed outside the publisher: {other:?}"),
            },
        }
    }

    /// Unmaps (`None`) or protects `[at, at + byte_len)`.
    fn change(
        &mut self,
        at: u64,
        byte_len: u64,
        protection: Option<Protection>,
    ) -> Result<(), X86AddressSpacePublishError<()>> {
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            &mut self.target,
        );
        let changed = match protection {
            None => self.region.unmap(
                &mut self.objects,
                &mut self.registry,
                &mut publisher,
                at,
                byte_len,
            ),
            Some(protection) => self.region.protect(
                &mut self.objects,
                &mut self.registry,
                &mut publisher,
                at,
                byte_len,
                protection,
            ),
        };
        match changed {
            Ok(_releases) => Ok(()),
            Err(failure) => match failure.error() {
                AddressSpaceTransactionError::Publish(error) => Err(*error),
                other => panic!("change failed outside the publisher: {other:?}"),
            },
        }
    }

    /// Commits object page `page`, as a touch's admitted commit does.
    fn commit(&mut self, page: u64) -> u64 {
        self.roles
            .commit_on_demand_page(self.backing, page)
            .unwrap()
            .physical_start
    }

    /// How many tables a touch at `address` would build.
    fn table_cost(&mut self, address: u64) -> usize {
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            &mut self.target,
        );
        publisher.touch_table_cost(address).unwrap()
    }

    /// Publishes the leaf a touch at `address` needs.
    fn touch(&mut self, address: u64) -> Result<bool, X86AddressSpacePublishError<()>> {
        let mapping: Mapping = self
            .region
            .mappings()
            .iter()
            .flatten()
            .copied()
            .find(|mapping| {
                mapping.virtual_start() <= address
                    && address < mapping.virtual_start() + mapping.byte_len()
            })
            .expect("a mapping covers the touch");
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            &mut self.target,
        );
        publisher.publish_touched_leaf(&mapping, address)
    }

    /// The frame `address`'s leaf maps, if it is present, and whether it is
    /// writable.
    fn leaf(&self, address: u64) -> Option<(u64, bool)> {
        let physical_mask = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);
        let mut table = self.root.physical_start();
        for level in (1..=3).rev() {
            let index = ((address >> (12 + level * 9)) & 0x1ff) as usize;
            table = self.target.entries.get(&(table, index)).copied()? & physical_mask;
            if table == 0 {
                return None;
            }
        }
        let leaf = self
            .target
            .entries
            .get(&(table, ((address >> 12) & 0x1ff) as usize))
            .copied()?;
        (leaf != 0).then_some((leaf & physical_mask, leaf & 0b10 != 0))
    }
}

#[test]
fn a_map_of_an_on_demand_object_publishes_no_leaf() {
    let mut fixture = Fixture::new();
    for page in 0..PAGES {
        assert_eq!(fixture.leaf(START + page * BASE_PAGE_SIZE), None);
        assert_eq!(fixture.leaf(ALIAS + page * BASE_PAGE_SIZE), None);
    }
    // A page committed before a later map still gets no leaf from the map:
    // only a touch publishes one, so a map never builds a table for it.
    fixture.change(ALIAS, SPAN, None).unwrap();
    fixture.commit(2);
    fixture.map(ALIAS).unwrap();
    assert_eq!(fixture.leaf(ALIAS + 2 * BASE_PAGE_SIZE), None);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_touch_publishes_one_leaf_and_a_second_touch_finds_it() {
    let mut fixture = Fixture::new();
    // A touch of a page with no frame is refused: commit comes first.
    assert_eq!(
        fixture.touch(START),
        Err(X86AddressSpacePublishError::FrameRole(
            FrameRoleError::Absent
        ))
    );
    let frame = fixture.commit(0);
    // No table exists yet: the touch builds a PDPT, a PD and a PT, and
    // after it the rest of the object needs none.
    assert_eq!(fixture.table_cost(START), 3);
    assert_eq!(fixture.touch(START), Ok(true));
    assert_eq!(fixture.leaf(START), Some((frame, true)));
    assert_eq!(fixture.table_cost(ALIAS), 0);
    // The alias shares the frame but not the leaf.
    assert_eq!(fixture.leaf(ALIAS), None);
    assert_eq!(fixture.touch(START), Ok(false), "a spurious second touch");
    assert_eq!(fixture.touch(ALIAS), Ok(true));
    assert_eq!(fixture.leaf(ALIAS), Some((frame, true)));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn unmapping_an_untouched_alias_skips_its_absent_leaves() {
    // Review D1: a page committed through one mapping has no leaf in the
    // other, and unmapping the other must not fail on it.
    let mut fixture = Fixture::new();
    let frame = fixture.commit(1);
    fixture.touch(START + BASE_PAGE_SIZE).unwrap();
    assert_eq!(fixture.change(ALIAS, SPAN, None), Ok(()));
    assert_eq!(fixture.leaf(START + BASE_PAGE_SIZE), Some((frame, true)));
    assert_eq!(fixture.region.mappings().iter().flatten().count(), 1);
    // Then the touched mapping: its one leaf goes, the rest were absent.
    assert_eq!(fixture.change(START, SPAN, None), Ok(()));
    assert_eq!(fixture.leaf(START + BASE_PAGE_SIZE), None);
    assert_eq!(fixture.region.mappings().iter().flatten().count(), 0);
    assert_eq!(fixture.objects.active_lease_count(), 0);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn protect_changes_present_leaves_and_skips_absent_ones() {
    let mut fixture = Fixture::new();
    let frame = fixture.commit(0);
    fixture.commit(3);
    fixture.touch(START).unwrap();
    // Read-only over both mappings: the touched leaf loses write; page 3,
    // committed but never touched here, and the alias stay absent.
    assert_eq!(
        fixture.change(START, 2 * SPAN, Some(Protection::READ)),
        Ok(())
    );
    assert_eq!(fixture.leaf(START), Some((frame, false)));
    assert_eq!(fixture.leaf(START + 3 * BASE_PAGE_SIZE), None);
    assert_eq!(fixture.leaf(ALIAS), None);
    // A later touch takes the mapping's current protection.
    assert_eq!(fixture.touch(ALIAS), Ok(true));
    assert_eq!(fixture.leaf(ALIAS), Some((frame, false)));
    // And back to read-write, then teardown of everything.
    assert_eq!(
        fixture.change(START, 2 * SPAN, Some(Protection::READ_WRITE)),
        Ok(())
    );
    assert_eq!(fixture.leaf(START), Some((frame, true)));
    assert_eq!(fixture.leaf(ALIAS), Some((frame, true)));
    assert_eq!(fixture.change(START, 2 * SPAN, None), Ok(()));
    assert!(fixture.leaf(START).is_none() && fixture.leaf(ALIAS).is_none());
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_leaf_that_maps_another_frame_is_refused() {
    let mut fixture = Fixture::new();
    fixture.commit(0);
    let other = fixture.commit(1);
    fixture.touch(START + BASE_PAGE_SIZE).unwrap();
    // Forge page 0's leaf to name page 1's frame: neither a touch nor an
    // unmap may take it as page 0's.
    let leaf_table = {
        let physical_mask = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);
        let mut table = fixture.root.physical_start();
        for level in (1..=3).rev() {
            let index = ((START >> (12 + level * 9)) & 0x1ff) as usize;
            table = fixture.target.entries[&(table, index)] & physical_mask;
        }
        table
    };
    let forged = fixture.target.entries[&(
        leaf_table,
        ((START + BASE_PAGE_SIZE) >> 12) as usize & 0x1ff,
    )];
    fixture
        .target
        .entries
        .insert((leaf_table, (START >> 12) as usize & 0x1ff), forged);
    assert_eq!(fixture.leaf(START).map(|(frame, _)| frame), Some(other));
    assert_eq!(
        fixture.touch(START),
        Err(X86AddressSpacePublishError::Map(MapError::FrameMismatch))
    );
    assert_eq!(
        fixture.change(START, SPAN, None),
        Err(X86AddressSpacePublishError::Map(MapError::FrameMismatch))
    );
}

/// Review M6-3: a leaf already present counts as this touch's only when it
/// is exactly the leaf a publish would write, with the accessed and dirty
/// bits the CPU sets ignored. A served fault was a not-present one, so then
/// the retry succeeds; a leaf that grants less is refused, not retried.
#[test]
fn a_present_leaf_is_the_touch_only_if_it_grants_the_mapping() {
    const ACCESSED_DIRTY: u64 = (1 << 5) | (1 << 6);
    const WRITABLE: u64 = 1 << 1;
    let mut fixture = Fixture::new();
    fixture.commit(0);
    fixture.touch(START).unwrap();
    let leaf_table = {
        let physical_mask = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);
        let mut table = fixture.root.physical_start();
        for level in (1..=3).rev() {
            let index = ((START >> (12 + level * 9)) & 0x1ff) as usize;
            table = fixture.target.entries[&(table, index)] & physical_mask;
        }
        table
    };
    let key = (leaf_table, (START >> 12) as usize & 0x1ff);
    let published = fixture.target.entries[&key];
    fixture
        .target
        .entries
        .insert(key, published | ACCESSED_DIRTY);
    assert_eq!(fixture.touch(START), Ok(false));
    // The same frame, read-only, under a read-write mapping.
    fixture.target.entries.insert(key, published & !WRITABLE);
    assert_eq!(
        fixture.touch(START),
        Err(X86AddressSpacePublishError::Map(MapError::FrameMismatch))
    );
    fixture.target.entries.insert(key, published);
    assert_eq!(fixture.touch(START), Ok(false));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// §8.6 / §8.11: two Processes map one object. Tearing one down (teardown
/// unmaps each mapping, as `unmap_inactive_userspace` does) removes only its
/// own leaves; the other keeps its leaves and the object keeps its frames.
#[test]
fn tearing_down_one_process_leaves_the_others_leaves_and_the_frames() {
    let mut fixture = Fixture::new();
    fixture.add_process();
    let shared = fixture.commit(0);
    let mine = fixture.commit(1);
    let theirs = fixture.commit(2);
    // Page 0 touched in both; page 1 only here; page 2 only there.
    fixture.touch(START).unwrap();
    fixture.touch(ALIAS + BASE_PAGE_SIZE).unwrap();
    fixture.swap_process();
    fixture.touch(START).unwrap();
    fixture.touch(START + 2 * BASE_PAGE_SIZE).unwrap();
    fixture.swap_process();
    assert_eq!(fixture.leaf(START + 2 * BASE_PAGE_SIZE), None);

    let frames = fixture.roles.on_demand_frames(fixture.backing).unwrap();
    // Teardown of this Process, mapping by mapping.
    assert_eq!(fixture.change(START, SPAN, None), Ok(()));
    assert_eq!(fixture.change(ALIAS, SPAN, None), Ok(()));
    assert_eq!(fixture.leaf(START), None);
    assert_eq!(fixture.leaf(ALIAS + BASE_PAGE_SIZE), None);
    assert_eq!(fixture.objects.active_lease_count(), 2);
    assert_eq!(fixture.roles.on_demand_frames(fixture.backing), Ok(frames));

    fixture.swap_process();
    assert_eq!(fixture.leaf(START), Some((shared, true)));
    assert_eq!(
        fixture.leaf(START + 2 * BASE_PAGE_SIZE),
        Some((theirs, true))
    );
    // A page the torn-down Process touched is committed, not mapped, here.
    assert_eq!(fixture.leaf(START + BASE_PAGE_SIZE), None);
    assert_eq!(fixture.touch(START + BASE_PAGE_SIZE), Ok(true));
    assert_eq!(fixture.leaf(START + BASE_PAGE_SIZE), Some((mine, true)));
    assert_eq!(fixture.change(START, 2 * SPAN, None), Ok(()));
    assert_eq!(fixture.leaf(START), None);
    assert_eq!(fixture.objects.active_lease_count(), 0);
    assert_eq!(fixture.roles.on_demand_frames(fixture.backing), Ok(frames));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// Touches every page at `START` and page 1 at `ALIAS`: five present
/// leaves, more than one batch's four, so a change over both mappings
/// publishes in two batches. Returns the four frames.
fn touch_two_batches(fixture: &mut Fixture) -> [u64; 4] {
    let frames = [0, 1, 2, 3].map(|page| fixture.commit(page));
    for page in 0..PAGES {
        fixture.touch(START + page * BASE_PAGE_SIZE).unwrap();
    }
    fixture.touch(ALIAS + BASE_PAGE_SIZE).unwrap();
    frames
}

/// §8.6 / §8.11: an unmap over both mappings whose second batch fails is
/// undone. The undo publishes no on-demand leaf (§8.6), so the pages of the
/// undone batch are mapped again but absent until touched again; the failed
/// batch changed nothing. No frame is lost either way.
#[test]
fn an_undone_unmap_of_two_mappings_leaves_touched_pages_to_be_touched_again() {
    let mut fixture = Fixture::new();
    let frames = touch_two_batches(&mut fixture);
    let committed = fixture.roles.on_demand_frames(fixture.backing).unwrap();
    fixture.target.fail_apply_at = Some(fixture.target.apply_count + 2);
    assert!(fixture.change(START, 2 * SPAN, None).is_err());
    fixture.target.fail_apply_at = None;
    assert_eq!(fixture.region.mappings().iter().flatten().count(), 2);
    assert_eq!(fixture.objects.active_lease_count(), 2);
    assert_eq!(
        fixture.leaf(ALIAS + BASE_PAGE_SIZE),
        Some((frames[1], true))
    );
    for page in 0..PAGES {
        let address = START + page * BASE_PAGE_SIZE;
        assert_eq!(fixture.leaf(address), None);
        assert_eq!(fixture.touch(address), Ok(true));
        assert_eq!(fixture.leaf(address), Some((frames[page as usize], true)));
    }
    assert_eq!(
        fixture.roles.on_demand_frames(fixture.backing),
        Ok(committed)
    );
    assert_eq!(fixture.change(START, 2 * SPAN, None), Ok(()));
    assert_eq!(fixture.objects.active_lease_count(), 0);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// §8.6 / §8.11: a protect over both mappings whose second batch fails is
/// undone: the first batch's present leaves get their write back, the
/// failed batch's never lost it, and absent pages stay absent.
#[test]
fn an_undone_protect_of_two_mappings_restores_present_leaves() {
    let mut fixture = Fixture::new();
    let frames = touch_two_batches(&mut fixture);
    fixture.target.fail_apply_at = Some(fixture.target.apply_count + 2);
    assert!(
        fixture
            .change(START, 2 * SPAN, Some(Protection::READ))
            .is_err()
    );
    fixture.target.fail_apply_at = None;
    for page in 0..PAGES {
        assert_eq!(
            fixture.leaf(START + page * BASE_PAGE_SIZE),
            Some((frames[page as usize], true))
        );
    }
    assert_eq!(
        fixture.leaf(ALIAS + BASE_PAGE_SIZE),
        Some((frames[1], true))
    );
    assert_eq!(fixture.leaf(ALIAS), None);
    // A touch after the undo takes the restored protection.
    assert_eq!(fixture.touch(ALIAS), Ok(true));
    assert_eq!(fixture.leaf(ALIAS), Some((frames[0], true)));
    assert_eq!(fixture.change(START, 2 * SPAN, None), Ok(()));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// DW2 §5.3a's question (reviewed 2026-11-13: safe by construction): a
/// root never links a table another root's owner holds. A touch in one
/// Process offered only the other's table candidates is refused, and
/// nothing is published.
#[test]
fn a_root_refuses_another_owners_table_candidates() {
    let mut fixture = Fixture::new();
    fixture.add_process();
    fixture.commit(0);
    let other = fixture.other.as_mut().unwrap();
    core::mem::swap(&mut fixture.candidates, &mut other.2);
    assert!(fixture.touch(START).is_err());
    assert_eq!(fixture.leaf(START), None);
    let other = fixture.other.as_mut().unwrap();
    core::mem::swap(&mut fixture.candidates, &mut other.2);
    assert_eq!(fixture.touch(START), Ok(true));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// The same question, for an entry already in place: a PML4 entry planted
/// to name the other Process's PDPT is refused, not followed, even by the
/// read-only walk that finds an already-present leaf (it found the other
/// Process's leaf and called the touch served before this was checked).
#[test]
fn a_root_refuses_an_entry_naming_another_owners_table() {
    let mut fixture = Fixture::new();
    fixture.add_process();
    let frame = fixture.commit(0);
    fixture.swap_process();
    fixture.touch(START).unwrap();
    let index = ((START >> 39) & 0x1ff) as usize;
    let foreign = fixture.target.entries[&(fixture.root.physical_start(), index)];
    fixture.swap_process();
    fixture
        .target
        .entries
        .insert((fixture.root.physical_start(), index), foreign);
    assert!(matches!(
        fixture.touch(START),
        Err(X86AddressSpacePublishError::Journal(_))
    ));
    // The other Process's leaf is untouched.
    fixture.swap_process();
    assert_eq!(fixture.leaf(START), Some((frame, true)));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}
