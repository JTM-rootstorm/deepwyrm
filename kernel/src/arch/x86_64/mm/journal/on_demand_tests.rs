//! DW2 M6 §8.6: an on-demand page committed in its object may have a leaf
//! in one mapping and none in another. Unmap, protect and teardown take
//! each address space's leaves as they are, and a touch publishes one leaf.

use super::super::super::MapError;
use super::*;
use crate::memory::address_region::{AddressRegion, AddressSpaceTransactionError, Mapping};
use crate::memory::frame_roles::IndexMemory;
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::memory::usercopy::{UserPinError, UserPinTracker};
use crate::object::InternalRef;
use std::boxed::Box;
use std::collections::BTreeSet;
use std::sync::Mutex;

/// Two mappings of one four-page object, side by side under one PT.
const START: u64 = 0x40_0000;
const PAGES: u64 = 4;
const SPAN: u64 = PAGES * BASE_PAGE_SIZE;
const ALIAS: u64 = START + SPAN;

type Publisher<'a, T = FakeTarget> = X86AddressSpacePublisher<'a, T, 4, 64, 3, 32, 4>;

/// The pin tracker a touch's target is wrapped over, as the live target is.
type Pins = UserPinTracker<4>;
/// The live target's shape over the fake one.
type Tracked<'a> = PinTrackedTarget<'a, FakeTarget, 4>;

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
    /// The object's own reference; tests drop it or make it a handle.
    owner: Option<InternalRef>,
    region: AddressRegion<2>,
    spaces: AddressSpaceAuthority<2, 2>,
    target: FakeTarget,
    /// The protection `map` maps with.
    protection: Protection,
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
        Self::with_protection(Protection::READ_WRITE, Protection::READ_WRITE)
    }

    /// As [`Fixture::new`], for an object whose protection ceiling is
    /// `ceiling`, mapped twice with `protection`.
    #[allow(
        unsafe_code,
        reason = "the host model attests synthetic frame zeroing and root ownership"
    )]
    fn with_protection(ceiling: Protection, protection: Protection) -> Self {
        let mut roles = synthetic_frame_role_manager::<4, 64>(0x1000, 32);
        roles.set_index_memory(Box::leak(Box::<Model>::default()));
        let (root, page_tables, candidates) = new_root(&mut roles);
        let grant = roles.allocate_on_demand_backing(PAGES).unwrap();
        let backing = grant.identity();
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut objects = MemoryObjectAuthority::<1, 4>::new();
        objects
            .grant_backing(&creation, grant, SPAN, MemoryObjectKind::OnDemand, ceiling)
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
            owner: Some(owner),
            region,
            spaces,
            target: FakeTarget::default(),
            protection,
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
    fn publisher<'a, T: AtomicPageTableTarget<Error: core::fmt::Debug>>(
        roles: &'a mut FrameRoleManager<4, 64>,
        root: TableIdentity,
        page_tables: &'a PageTableRoot,
        candidates: &'a mut [Option<TableCandidateGrant>; 3],
        region: &AddressRegion<2>,
        target: &'a mut T,
    ) -> Publisher<'a, T> {
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
            self.owner.as_ref().expect("an owner to map through"),
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        );
        let authorization = self
            .region
            .authorize_map(&self.objects, resolved, self.protection)
            .unwrap();
        match self.region.map(
            &mut self.objects,
            &mut self.registry,
            &mut publisher,
            at,
            authorization,
            0,
            SPAN,
            self.protection,
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
            Ok(releases) => {
                // A host target publishes no shootdown.
                drop(releases.settle_locally(&mut self.registry));
                Ok(())
            }
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

    /// The mapping covering `address`.
    fn mapping_at(&self, address: u64) -> Mapping {
        self.region
            .mappings()
            .iter()
            .flatten()
            .copied()
            .find(|mapping| {
                mapping.virtual_start() <= address
                    && address < mapping.virtual_start() + mapping.byte_len()
            })
            .expect("a mapping covers the touch")
    }

    /// Runs `touch` with this fixture's fake target wrapped in a pin-tracked
    /// target over `pins`, as the live target is, and puts it back.
    fn with_pins<R>(
        &mut self,
        pins: &Pins,
        touch: impl FnOnce(&mut Self, &mut Tracked<'_>) -> R,
    ) -> R {
        let mut tracked = PinTrackedTarget {
            scratch: core::mem::take(&mut self.target),
            pins,
            address_space: self.region.address_space_key(),
            span: None,
        };
        let result = touch(self, &mut tracked);
        assert!(tracked.span.is_none(), "a touch left a mutation span held");
        self.target = tracked.scratch;
        result
    }

    /// A serve's touch at `address` through the journal, as the serve made
    /// it before DW2 §13.16 part e1: the table count, then the commit of
    /// object page `commit` if any, then, when no table is missing, the
    /// journal's publish of the leaf. The target is pin-tracked over `pins`.
    fn touch_through_journal(&mut self, address: u64, commit: Option<u64>, pins: &Pins) -> Touch {
        let mapping = self.mapping_at(address);
        self.with_pins(pins, |fixture, target| {
            let tables = Self::publisher(
                &mut fixture.roles,
                fixture.root,
                &fixture.page_tables,
                &mut fixture.candidates,
                &fixture.region,
                target,
            )
            .touch_table_cost(address);
            if let Some(page) = commit {
                fixture.commit(page);
            }
            let published = (tables == Ok(0)).then(|| {
                Self::publisher(
                    &mut fixture.roles,
                    fixture.root,
                    &fixture.page_tables,
                    &mut fixture.candidates,
                    &fixture.region,
                    target,
                )
                .publish_touched_leaf(&mapping, address)
            });
            (tables, published)
        })
    }

    /// The same touch through one walk and one write (DW2 §13.16 part e1):
    /// find, the commit through the same publisher, write.
    fn touch_through_find(&mut self, address: u64, commit: Option<u64>, pins: &Pins) -> Touch {
        let mapping = self.mapping_at(address);
        let backing = self.backing;
        self.with_pins(pins, |fixture, target| {
            let mut publisher = Self::publisher(
                &mut fixture.roles,
                fixture.root,
                &fixture.page_tables,
                &mut fixture.candidates,
                &fixture.region,
                target,
            );
            let found = publisher.find_touched_leaf(&mapping, address);
            if let Some(page) = commit {
                publisher.commit_on_demand_page(backing, page).unwrap();
            }
            match found {
                Ok(TouchedLeaf::Found(place)) => (Ok(0), Some(publisher.write_touched_leaf(place))),
                Ok(TouchedLeaf::MissingTables(tables)) => (Ok(tables), None),
                Err(error) => (Err(error), None),
            }
        })
    }

    /// The same touch with the commit made through the place (DW2 §13.18
    /// part f1): find, `commit_touched_page`, write, the write taking the
    /// frame from the place. Where the serve commits (`commit` is the
    /// touched page), the limit is unbounded; where it does not, the limit
    /// is zero, so a committed page still gives the place its frame and an
    /// uncommitted one is left to the write's resolve. With no place, the
    /// commit is made as the other paths make it.
    fn touch_through_place(&mut self, address: u64, commit: Option<u64>, pins: &Pins) -> Touch {
        let mapping = self.mapping_at(address);
        let backing = self.backing;
        self.with_pins(pins, |fixture, target| {
            let mut publisher = Self::publisher(
                &mut fixture.roles,
                fixture.root,
                &fixture.page_tables,
                &mut fixture.candidates,
                &fixture.region,
                target,
            );
            match publisher.find_touched_leaf(&mapping, address) {
                Ok(TouchedLeaf::Found(mut place)) => {
                    let limit = match commit {
                        Some(page) => {
                            assert_eq!(page, (address - mapping.virtual_start()) / BASE_PAGE_SIZE);
                            u64::MAX
                        }
                        None => 0,
                    };
                    publisher.commit_touched_page(&mut place, limit).unwrap();
                    (Ok(0), Some(publisher.write_touched_leaf(place)))
                }
                found => {
                    if let Some(page) = commit {
                        publisher.commit_on_demand_page(backing, page).unwrap();
                    }
                    match found {
                        Ok(TouchedLeaf::MissingTables(tables)) => (Ok(tables), None),
                        Err(error) => (Err(error), None),
                        Ok(TouchedLeaf::Found(_)) => unreachable!(),
                    }
                }
            }
        })
    }

    /// Publishes the leaf a touch at `address` needs.
    fn touch(&mut self, address: u64) -> Result<bool, X86AddressSpacePublishError<()>> {
        let mapping = self.mapping_at(address);
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

/// A serve's touch: the table count (or the walk's error) and, when no
/// table was missing, the leaf's publish.
type Touch = (
    Result<usize, X86AddressSpacePublishError<PinTrackedError<()>>>,
    Option<Result<bool, X86AddressSpacePublishError<PinTrackedError<()>>>>,
);

const ACCESSED_DIRTY: u64 = (1 << 5) | (1 << 6);
const USER_BIT: u64 = 1 << 2;
const WRITABLE_BIT: u64 = 1 << 1;
const NO_EXECUTE_BIT: u64 = 1 << 63;

/// The entry on `address`'s path at `level` (3 the PML4's, 0 the leaf), as
/// (table, index) in the fake target.
fn entry_key(fixture: &Fixture, address: u64, level: usize) -> (u64, usize) {
    let physical_mask = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);
    let mut table = fixture.root.physical_start();
    for walked in (level + 1..=3).rev() {
        let index = ((address >> (12 + walked * 9)) & 0x1ff) as usize;
        table = fixture.target.entries[&(table, index)] & physical_mask;
    }
    (table, ((address >> (12 + level * 9)) & 0x1ff) as usize)
}

/// Every table on `START`'s path exists: page 1 is committed and touched.
fn with_tables(mut fixture: Fixture) -> Fixture {
    fixture.commit(1);
    fixture.touch(START + BASE_PAGE_SIZE).unwrap();
    fixture
}

/// DW2 §13.16 part e1: builds two fixtures with `make`, touches `address`
/// in one through the journal and in the other through one walk and one
/// write, committing object page `commit` between the walk and the publish,
/// and checks that both give the same results and leave every page-table
/// entry the same, bit for bit. The walk and write make at most one store
/// and no invalidation. A third fixture is touched with the commit made
/// through the place and the frame taken from it (DW2 §13.18 part f1), and
/// is held to the same. Returns the result and the second fixture.
fn touch_both_ways(
    make: impl Fn() -> Fixture,
    address: u64,
    commit: Option<u64>,
) -> (Touch, Fixture) {
    touch_both_ways_holding(make, address, commit, hold_nothing)
}

/// Anything a test holds on a pin tracker while a touch runs, released when
/// it is dropped.
trait Held {}
impl<T> Held for T {}

/// What a touch runs beside: nothing held.
fn hold_nothing<'p>(_: &Fixture, _: &'p Pins) -> Box<dyn Held + 'p> {
    Box::new(())
}

/// As [`touch_both_ways`], with each fixture's target pin-tracked over its
/// own tracker, on which `hold` holds something for the touch's length.
fn touch_both_ways_holding(
    make: impl Fn() -> Fixture,
    address: u64,
    commit: Option<u64>,
    hold: for<'p> fn(&Fixture, &'p Pins) -> Box<dyn Held + 'p>,
) -> (Touch, Fixture) {
    let mut journal = make();
    let mut direct = make();
    let mut placed = make();
    assert_eq!(direct.target.entries, journal.target.entries);
    assert_eq!(placed.target.entries, journal.target.entries);
    let journal_pins = Pins::new();
    let direct_pins = Pins::new();
    let placed_pins = Pins::new();
    let through_journal = {
        let _held = hold(&journal, &journal_pins);
        journal.touch_through_journal(address, commit, &journal_pins)
    };
    let applied = direct.target.applied.len();
    let invalidated = direct.target.invalidated.len();
    let through_find = {
        let _held = hold(&direct, &direct_pins);
        direct.touch_through_find(address, commit, &direct_pins)
    };
    assert_eq!(through_find, through_journal);
    assert_eq!(direct.target.entries, journal.target.entries);
    let stores = direct.target.applied.len() - applied;
    assert_eq!(
        stores,
        usize::from(through_find.1 == Some(Ok(true))),
        "one store exactly when a leaf is published"
    );
    assert_eq!(direct.target.invalidated.len(), invalidated);
    assert_eq!(
        direct.roles.check_invariants(),
        journal.roles.check_invariants()
    );
    // DW2 §13.18 part f1: the third way, the frame from the commit through
    // the place, gives the same results and the same entries, bit for bit.
    let applied = placed.target.applied.len();
    let invalidated = placed.target.invalidated.len();
    let through_place = {
        let _held = hold(&placed, &placed_pins);
        placed.touch_through_place(address, commit, &placed_pins)
    };
    assert_eq!(through_place, through_journal);
    assert_eq!(placed.target.entries, journal.target.entries);
    assert_eq!(
        placed.target.applied.len() - applied,
        usize::from(through_place.1 == Some(Ok(true))),
        "one store exactly when a leaf is published"
    );
    assert_eq!(placed.target.invalidated.len(), invalidated);
    assert_eq!(
        placed.roles.check_invariants(),
        journal.roles.check_invariants()
    );
    assert_eq!(
        placed.roles.available_frames(),
        direct.roles.available_frames()
    );
    assert_eq!(
        placed.roles.on_demand_frames(placed.backing),
        direct.roles.on_demand_frames(direct.backing)
    );
    (through_find, direct)
}

#[test]
fn one_walk_and_one_store_publish_an_empty_leaf_as_the_journal_does() {
    // The page committed in the serve's hold, after the walk.
    let (result, fixture) = touch_both_ways(|| with_tables(Fixture::new()), START, Some(0));
    assert_eq!(result, (Ok(0), Some(Ok(true))));
    let page_one = fixture.leaf(START + BASE_PAGE_SIZE).unwrap().0;
    assert!(matches!(fixture.leaf(START), Some((frame, true)) if frame != page_one));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
    // The page committed before: nothing to commit in the serve.
    let (result, fixture) = touch_both_ways(
        || {
            let mut fixture = with_tables(Fixture::new());
            fixture.commit(0);
            fixture
        },
        START,
        None,
    );
    assert_eq!(result, (Ok(0), Some(Ok(true))));
    assert!(fixture.leaf(START).is_some());
    // A spurious second touch finds it through either path.
    let (result, _) = touch_both_ways(
        || {
            let mut fixture = with_tables(Fixture::new());
            fixture.commit(0);
            assert_eq!(
                fixture.touch_through_find(START, None, &Pins::new()),
                (Ok(0), Some(Ok(true)))
            );
            fixture
        },
        START,
        None,
    );
    assert_eq!(result, (Ok(0), Some(Ok(false))));
}

#[test]
fn one_walk_finds_the_same_leaf_already_present() {
    let present = || {
        let mut fixture = with_tables(Fixture::new());
        fixture.commit(0);
        fixture.touch(START).unwrap();
        fixture
    };
    let (result, _) = touch_both_ways(present, START, None);
    assert_eq!(result, (Ok(0), Some(Ok(false))));
    // The accessed and dirty bits the CPU sets are not a difference.
    let (result, _) = touch_both_ways(
        || {
            let mut fixture = present();
            let key = entry_key(&fixture, START, 0);
            *fixture.target.entries.get_mut(&key).unwrap() |= ACCESSED_DIRTY;
            fixture
        },
        START,
        None,
    );
    assert_eq!(result, (Ok(0), Some(Ok(false))));
}

const ADDRESS_MASK: u64 = ((1_u64 << 40) - 1) & !(BASE_PAGE_SIZE - 1);

/// Builds a fixture with every table, pages 0 and 1 committed and touched,
/// and the leaf at `at` replaced by `forge(page 0's leaf, page 1's leaf,
/// the root's frame)`.
fn forged(at: u64, forge: fn(u64, u64, u64) -> u64) -> Fixture {
    let mut fixture = with_tables(Fixture::new());
    fixture.commit(0);
    fixture.touch(START).unwrap();
    let page_zero = fixture.target.entries[&entry_key(&fixture, START, 0)];
    let page_one = fixture.target.entries[&entry_key(&fixture, START + BASE_PAGE_SIZE, 0)];
    let root = fixture.root.physical_start();
    let key = entry_key(&fixture, at, 0);
    fixture
        .target
        .entries
        .insert(key, forge(page_zero, page_one, root));
    fixture
}

#[test]
fn one_walk_refuses_a_present_leaf_of_another_frame_or_permissions() {
    const MISMATCH: Touch = (
        Ok(0),
        Some(Err(X86AddressSpacePublishError::Map(
            MapError::FrameMismatch,
        ))),
    );
    // A frame of no backing (the root's), with the leaf's own flags.
    let (result, _) = touch_both_ways(
        || {
            forged(START, |page_zero, _, root| {
                (page_zero & !ADDRESS_MASK) | root
            })
        },
        START,
        None,
    );
    assert_eq!(result, MISMATCH);
    // The backing's own frame, but its page at another offset (page 1's).
    let (result, _) = touch_both_ways(|| forged(START, |_, page_one, _| page_one), START, None);
    assert_eq!(result, MISMATCH);
    // The right frame without write, under a read-write mapping.
    let (result, _) = touch_both_ways(
        || forged(START, |page_zero, _, _| page_zero & !WRITABLE_BIT),
        START,
        None,
    );
    assert_eq!(result, MISMATCH);
    // The right frame, executable, under a mapping that is not.
    let (result, _) = touch_both_ways(
        || forged(START, |page_zero, _, _| page_zero & !NO_EXECUTE_BIT),
        START,
        None,
    );
    assert_eq!(result, MISMATCH);
    // Page 2, committed in the serve's hold, could not have had a leaf: a
    // leaf already there is another frame's (the serve panics on it).
    let at = START + 2 * BASE_PAGE_SIZE;
    let (result, _) = touch_both_ways(|| forged(at, |_, page_one, _| page_one), at, Some(2));
    assert_eq!(result, MISMATCH);
}

#[test]
fn one_walk_refuses_a_page_with_no_frame() {
    let (result, fixture) = touch_both_ways(|| with_tables(Fixture::new()), START, None);
    assert_eq!(
        result,
        (
            Ok(0),
            Some(Err(X86AddressSpacePublishError::FrameRole(
                FrameRoleError::Absent
            )))
        )
    );
    assert_eq!(fixture.leaf(START), None);
}

#[test]
fn one_walk_counts_the_tables_missing_at_each_level() {
    // No table at all: the PDPT, the PD and the PT.
    let (result, _) = touch_both_ways(Fixture::new, START, Some(0));
    assert_eq!(result, (Ok(3), None));
    // The entry naming the PT, the PD or the PDPT emptied.
    for (level, missing) in [(1, 1), (2, 2), (3, 3)] {
        let (result, _) = touch_both_ways(
            || {
                let mut fixture = with_tables(Fixture::new());
                let key = entry_key(&fixture, START, level);
                fixture.target.entries.insert(key, 0);
                fixture
            },
            START,
            Some(0),
        );
        assert_eq!(result, (Ok(missing), None), "level {level}");
    }
}

#[test]
fn one_walk_refuses_an_ancestor_without_the_user_bit() {
    for level in 1..=3 {
        let (result, fixture) = touch_both_ways(
            || {
                let mut fixture = with_tables(Fixture::new());
                let key = entry_key(&fixture, START, level);
                *fixture.target.entries.get_mut(&key).unwrap() &= !USER_BIT;
                fixture
            },
            START,
            Some(0),
        );
        assert_eq!(
            result,
            (
                Err(X86AddressSpacePublishError::Map(MapError::InvalidPath)),
                None
            ),
            "level {level}"
        );
        assert_eq!(fixture.leaf(START), None);
    }
}

/// §5.3a: a path through another Process's PDPT. The other's leaf for page
/// 0 is present and is this page's; for page 1 it is empty.
fn through_another_roots_table() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.add_process();
    fixture.commit(0);
    fixture.commit(1);
    fixture.swap_process();
    fixture.touch(START).unwrap();
    let key = entry_key(&fixture, START, 3);
    let foreign = fixture.target.entries[&key];
    fixture.swap_process();
    fixture
        .target
        .entries
        .insert((fixture.root.physical_start(), key.1), foreign);
    fixture
}

#[test]
fn one_walk_refuses_a_path_through_another_roots_table() {
    let (result, _) = touch_both_ways(through_another_roots_table, START, None);
    assert!(matches!(
        result,
        (
            Ok(0),
            Some(Err(X86AddressSpacePublishError::Journal(
                OwnedPageTableJournalError::FrameRole(_)
            )))
        )
    ));
    let (result, mut fixture) =
        touch_both_ways(through_another_roots_table, START + BASE_PAGE_SIZE, None);
    assert_eq!(
        result,
        (
            Ok(0),
            Some(Err(X86AddressSpacePublishError::Map(
                MapError::TableClaimRejected
            )))
        )
    );
    // Nothing was written in the other Process's tables.
    fixture.swap_process();
    assert_eq!(fixture.leaf(START + BASE_PAGE_SIZE), None);
}

#[test]
fn one_walk_writes_the_leaf_each_protection_needs() {
    for (ceiling, protection) in [
        (Protection::READ_WRITE, Protection::READ),
        (Protection::READ_WRITE, Protection::READ_WRITE),
        (Protection::READ_EXECUTE, Protection::READ_EXECUTE),
    ] {
        let (result, fixture) = touch_both_ways(
            || with_tables(Fixture::with_protection(ceiling, protection)),
            START,
            Some(0),
        );
        assert_eq!(result, (Ok(0), Some(Ok(true))), "{protection:?}");
        let leaf = fixture.target.entries[&entry_key(&fixture, START, 0)];
        assert_eq!(leaf & WRITABLE_BIT != 0, protection.writable());
        assert_eq!(leaf & NO_EXECUTE_BIT == 0, protection.executable());
        assert_eq!(leaf & USER_BIT, USER_BIT);
    }
}

/// A readable word at `address`, for a user pin.
fn word(address: u64) -> UserRange {
    UserRange::new(
        UserAddressSpace::x86_64_four_level(BASE_PAGE_SIZE).unwrap(),
        address,
        4,
        4,
        UserAccess::READ,
        EmptyAddressRule::Reject,
    )
    .unwrap()
}

/// A user pin on a word of `START`'s page.
fn hold_pin<'p>(fixture: &Fixture, pins: &'p Pins) -> Box<dyn Held + 'p> {
    Box::new(
        pins.pin_owned(fixture.region.address_space_key(), word(START + 8))
            .unwrap(),
    )
}

/// Another mutation's permit, over page 3 of the same mapping.
fn hold_mutation<'p>(fixture: &Fixture, pins: &'p Pins) -> Box<dyn Held + 'p> {
    Box::new(
        pins.begin_mutation(
            fixture.region.address_space_key(),
            START + 3 * BASE_PAGE_SIZE,
            BASE_PAGE_SIZE,
        )
        .unwrap(),
    )
}

/// The address space reserved for teardown.
fn hold_teardown<'p>(fixture: &Fixture, pins: &'p Pins) -> Box<dyn Held + 'p> {
    Box::new(
        pins.reserve_teardown(fixture.region.address_space_key())
            .unwrap(),
    )
}

/// The journal's `apply` reserves the page it publishes against user pins,
/// another mutation and a teardown reservation; the one store reserves the
/// same page and is refused with the same error, writing nothing.
#[test]
fn one_store_is_refused_where_the_journal_reserves_its_page() {
    const REFUSED: Touch = (
        Ok(0),
        Some(Err(X86AddressSpacePublishError::Journal(
            OwnedPageTableJournalError::Target(PinTrackedError::Pin(UserPinError::Conflict)),
        ))),
    );
    for hold in [hold_pin, hold_mutation, hold_teardown] {
        // The page committed in the serve's hold, and before it.
        for (commit, committed) in [(Some(0), false), (None, true)] {
            let (result, fixture) = touch_both_ways_holding(
                || {
                    let mut fixture = with_tables(Fixture::new());
                    if committed {
                        fixture.commit(0);
                    }
                    fixture
                },
                START,
                commit,
                hold,
            );
            assert_eq!(result, REFUSED);
            assert_eq!(fixture.leaf(START), None);
        }
    }
    // An already-present leaf reserves nothing, in either path.
    let (result, _) = touch_both_ways_holding(
        || {
            let mut fixture = with_tables(Fixture::new());
            fixture.commit(0);
            fixture.touch(START).unwrap();
            fixture
        },
        START,
        None,
        hold_pin,
    );
    assert_eq!(result, (Ok(0), Some(Ok(false))));
}

#[test]
fn one_store_releases_its_page_after_writing() {
    let mut fixture = with_tables(Fixture::new());
    let pins = Pins::new();
    assert_eq!(
        fixture.touch_through_find(START, Some(0), &pins),
        (Ok(0), Some(Ok(true)))
    );
    let space = fixture.region.address_space_key();
    drop(pins.begin_mutation(space, START, BASE_PAGE_SIZE).unwrap());
    let pin = pins.pin_owned(space, word(START + 8)).unwrap();
    pins.release_owned(space, pin).unwrap();
}

/// DW2 §13.18 part f1: a commit through the place over its limit takes
/// nothing and leaves the place as `find_touched_leaf` made it, so the
/// write resolves the page as before and refuses it uncommitted.
#[test]
fn a_commit_through_the_place_over_its_limit_leaves_the_write_to_resolve() {
    let mut fixture = with_tables(Fixture::new());
    let mapping = fixture.mapping_at(START);
    let free = fixture.roles.available_frames();
    let pins = Pins::new();
    let result = fixture.with_pins(&pins, |fixture, target| {
        let mut publisher = Fixture::publisher(
            &mut fixture.roles,
            fixture.root,
            &fixture.page_tables,
            &mut fixture.candidates,
            &fixture.region,
            target,
        );
        let Ok(TouchedLeaf::Found(mut place)) = publisher.find_touched_leaf(&mapping, START) else {
            panic!("every table exists");
        };
        // Page 0 takes one frame (the backing's root is its leaf node).
        assert_eq!(publisher.commit_touched_page(&mut place, 0), Ok(None));
        publisher.write_touched_leaf(place)
    });
    assert_eq!(
        result,
        Err(X86AddressSpacePublishError::FrameRole(
            FrameRoleError::Absent
        ))
    );
    assert_eq!(fixture.roles.available_frames(), free);
    assert_eq!(fixture.leaf(START), None);
    // The same place within one frame commits it and writes its leaf.
    assert_eq!(
        fixture.touch_through_place(START, Some(0), &pins),
        (Ok(0), Some(Ok(true)))
    );
    assert_eq!(fixture.roles.available_frames(), free - 1);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// A commit through a place whose mapping names no page of itself at the
/// place's address is `InvalidMapping` with nothing taken: an object offset
/// that overflows, one that is not a page's, and an address past the
/// mapping's end.
#[test]
fn a_commit_through_the_place_refuses_a_page_its_mapping_cannot_name() {
    let mut fixture = with_tables(Fixture::new());
    let mapping = fixture.mapping_at(START);
    let overflow = mapping.with_object_offset_for_test(!(BASE_PAGE_SIZE - 1));
    let unaligned = mapping.with_object_offset_for_test(1);
    let free = fixture.roles.available_frames();
    let frames = fixture.roles.on_demand_frames(fixture.backing);
    let pins = Pins::new();
    for (mapping, address) in [
        (overflow, START + BASE_PAGE_SIZE),
        (unaligned, START),
        (mapping, ALIAS),
    ] {
        let committed = fixture.with_pins(&pins, |fixture, target| {
            let mut publisher = Fixture::publisher(
                &mut fixture.roles,
                fixture.root,
                &fixture.page_tables,
                &mut fixture.candidates,
                &fixture.region,
                target,
            );
            let Ok(TouchedLeaf::Found(mut place)) = publisher.find_touched_leaf(&mapping, address)
            else {
                panic!("every table exists");
            };
            let committed = publisher.commit_touched_page(&mut place, u64::MAX);
            // Nor does the write publish anything for it.
            assert!(publisher.write_touched_leaf(place).is_err());
            committed
        });
        assert_eq!(
            committed,
            Err(X86AddressSpacePublishError::InvalidMapping),
            "{address:#x}"
        );
        assert_eq!(fixture.roles.available_frames(), free);
        assert_eq!(fixture.roles.on_demand_frames(fixture.backing), frames);
    }
    assert_eq!(fixture.leaf(START), None);
    assert_eq!(fixture.leaf(ALIAS), None);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

/// Part e1's path through another root's table, with the page committed in
/// the serve's hold through the place: the commit is made and the write is
/// refused, as the journal path refuses it after its commit.
#[test]
fn a_frame_from_the_place_is_still_refused_through_another_roots_table() {
    let at = START + 2 * BASE_PAGE_SIZE;
    let (result, mut fixture) = touch_both_ways(through_another_roots_table, at, Some(2));
    assert_eq!(
        result,
        (
            Ok(0),
            Some(Err(X86AddressSpacePublishError::Map(
                MapError::TableClaimRejected
            )))
        )
    );
    // The commit was made: page 2 costs nothing now.
    assert_eq!(
        fixture.roles.on_demand_commit_cost(fixture.backing, 2),
        Ok(0)
    );
    fixture.swap_process();
    assert_eq!(fixture.leaf(at), None);
}

/// A path that names one table twice: the PD's entry for `START` names the
/// PD itself. Each way refuses the touch alike, and the frame from the
/// place changes nothing of it.
#[test]
fn a_path_that_revisits_a_table_is_refused_each_way() {
    let revisiting = || {
        let mut fixture = with_tables(Fixture::new());
        let key = entry_key(&fixture, START, 1);
        let entry = fixture.target.entries[&key];
        fixture
            .target
            .entries
            .insert(key, (entry & !ADDRESS_MASK) | key.0);
        fixture
    };
    for commit in [Some(0), None] {
        let (result, _) = touch_both_ways(
            || {
                let mut fixture = revisiting();
                if commit.is_none() {
                    fixture.commit(0);
                }
                fixture
            },
            START,
            commit,
        );
        assert_eq!(
            result,
            (
                Ok(0),
                Some(Err(X86AddressSpacePublishError::Map(MapError::InvalidPath)))
            ),
            "{commit:?}"
        );
    }
}

#[path = "release_tests.rs"]
mod release_tests;
