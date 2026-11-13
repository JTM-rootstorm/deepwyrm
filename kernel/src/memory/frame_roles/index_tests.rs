extern crate std;

use super::super::super::physical::PhysicalAddressLimit;
use super::*;
use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

const PAGE: u64 = BASE_PAGE_SIZE;
/// What a page that was never zeroed reads as.
const GARBAGE: u64 = 0xdead_beef_0000_0001;
type Manager = FrameRoleManager<8, 64>;

/// Physical memory as the index sees it: a page reads as garbage until it
/// is zeroed, so a node linked before zeroing would decode as an entry.
#[derive(Default)]
struct Model {
    zeroed: Mutex<BTreeSet<u64>>,
    entries: Mutex<BTreeMap<(u64, usize), u64>>,
    /// Zeroing this page fails.
    fail_zero: Mutex<Option<u64>>,
}

impl IndexMemory for Model {
    fn read(&self, node: u64, entry: usize) -> u64 {
        if let Some(value) = self.entries.lock().unwrap().get(&(node, entry)) {
            return *value;
        }
        if self.zeroed.lock().unwrap().contains(&node) {
            0
        } else {
            GARBAGE
        }
    }

    #[allow(
        unsafe_code,
        reason = "the model implements the trait's unsafe methods"
    )]
    unsafe fn write(&self, node: u64, entry: usize, value: u64) {
        assert!(
            self.zeroed.lock().unwrap().contains(&node),
            "an entry is written only into a zeroed node"
        );
        self.entries.lock().unwrap().insert((node, entry), value);
    }

    #[allow(
        unsafe_code,
        reason = "the model implements the trait's unsafe methods"
    )]
    unsafe fn zero(&self, page: u64) -> bool {
        if *self.fail_zero.lock().unwrap() == Some(page) {
            return false;
        }
        self.entries
            .lock()
            .unwrap()
            .retain(|(node, _), _| *node != page);
        self.zeroed.lock().unwrap().insert(page);
        true
    }
}

fn manager(page_count: u64) -> (Manager, &'static Model) {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(PAGE, page_count, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    let mut roles = Manager::new(allocator).unwrap();
    let model: &'static Model = Box::leak(Box::default());
    roles.set_index_memory(model);
    (roles, model)
}

fn page(roles: &Manager, grant: &ObjectBackingGrant, index: u64) -> Result<u64, FrameRoleError> {
    roles
        .resolve_object_page(grant.identity(), index * PAGE, true)
        .map(|segment| segment.physical_start)
}

const THREE_LEVELS: u64 = 512 * 512 + 1;

#[test]
fn a_new_backing_is_one_root_and_every_page_absent() {
    let (mut roles, _) = manager(16);
    let before = roles.available_frames();
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    assert_eq!(grant.kind(), ObjectBackingKind::OnDemand);
    assert_eq!(grant.byte_len(), THREE_LEVELS * PAGE);
    assert_eq!(roles.available_frames(), before - 1);
    assert_eq!(roles.on_demand_frames(grant.identity()), Ok(1));
    assert!(roles.is_on_demand(grant.identity()));
    for index in [0, 511, 512, THREE_LEVELS - 1] {
        assert_eq!(page(&roles, &grant, index), Err(FrameRoleError::Absent));
    }
    // A page past the object is not absent: it is not there at all.
    assert_eq!(
        page(&roles, &grant, THREE_LEVELS),
        Err(FrameRoleError::WrongRole)
    );
    roles.check_invariants().unwrap();
}

#[test]
fn sizes_are_bounded_by_four_levels() {
    let (mut roles, _) = manager(16);
    assert!(roles.allocate_on_demand_backing(0).is_err());
    assert!(
        roles
            .allocate_on_demand_backing(INDEX_MAX_PAGES + 1)
            .is_err()
    );
    let largest = roles.allocate_on_demand_backing(INDEX_MAX_PAGES).unwrap();
    assert_eq!(roles.on_demand_commit_cost(largest.identity(), 0), Ok(4));
    let small = roles.allocate_on_demand_backing(1).unwrap();
    assert_eq!(roles.on_demand_commit_cost(small.identity(), 0), Ok(1));
}

#[test]
fn a_commit_takes_the_nodes_its_path_lacks_and_costs_what_it_said() {
    let (mut roles, model) = manager(32);
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    let backing = grant.identity();
    let cost = roles.on_demand_commit_cost(backing, 600).unwrap();
    assert_eq!(cost, 3, "two nodes and the page");
    let before = roles.available_frames();
    let commit = roles.commit_on_demand_page(backing, 600).unwrap();
    assert_eq!(commit.frames, cost);
    assert_eq!(roles.available_frames(), before - cost);
    assert_eq!(page(&roles, &grant, 600), Ok(commit.physical_start));
    assert!(
        model
            .zeroed
            .lock()
            .unwrap()
            .contains(&commit.physical_start)
    );

    // Committed already: free, and the same frame.
    assert_eq!(roles.on_demand_commit_cost(backing, 600), Ok(0));
    assert_eq!(
        roles.commit_on_demand_page(backing, 600),
        Ok(OnDemandCommit {
            physical_start: commit.physical_start,
            frames: 0
        })
    );
    // A neighbour shares the leaf node; another leaf needs its own.
    assert_eq!(roles.on_demand_commit_cost(backing, 601), Ok(1));
    assert_eq!(roles.on_demand_commit_cost(backing, 0), Ok(2));
    assert_eq!(
        roles.on_demand_commit_cost(backing, THREE_LEVELS - 1),
        Ok(3)
    );
    for index in [601, 0, THREE_LEVELS - 1] {
        let cost = roles.on_demand_commit_cost(backing, index).unwrap();
        assert_eq!(
            roles.commit_on_demand_page(backing, index).unwrap().frames,
            cost
        );
    }
    assert_eq!(page(&roles, &grant, 602), Err(FrameRoleError::Absent));
    // Root, 3 level-1 nodes... : root + (node 0 + leaves 0 and 1) + (node
    // 1 + its leaf) + 4 pages.
    assert_eq!(roles.on_demand_frames(backing), Ok(1 + 3 + 2 + 4));
    roles.check_invariants().unwrap();

    // A cursor resolves through the index too.
    let mut cursor = BackingCursor::new(backing);
    assert_eq!(
        roles
            .resolve_at(&mut cursor, 601 * PAGE, true)
            .map(|s| s.byte_len),
        Ok(PAGE)
    );
    assert_eq!(
        roles.resolve_at(&mut cursor, 5 * PAGE, false),
        Err(FrameRoleError::Absent)
    );
}

#[test]
fn a_commit_that_runs_out_of_frames_changes_nothing() {
    let (mut roles, _) = manager(3);
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    // Two frames left; the commit needs three.
    assert_eq!(roles.available_frames(), 2);
    assert!(matches!(
        roles.commit_on_demand_page(grant.identity(), 7),
        Err(FrameRoleError::Physical(_))
    ));
    assert_eq!(roles.available_frames(), 2);
    assert_eq!(page(&roles, &grant, 7), Err(FrameRoleError::Absent));
    assert_eq!(roles.on_demand_frames(grant.identity()), Ok(1));
    roles.check_invariants().unwrap();
}

#[test]
fn a_frame_that_fails_to_zero_changes_nothing() {
    let (mut roles, model) = manager(8);
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    // The allocator hands out the lowest page next; fail the second frame.
    let second = grant.physical_start() + 2 * PAGE;
    *model.fail_zero.lock().unwrap() = Some(second);
    let before = roles.available_frames();
    assert_eq!(
        roles.commit_on_demand_page(grant.identity(), 7),
        Err(FrameRoleError::InitializationFailed)
    );
    assert_eq!(roles.available_frames(), before);
    assert_eq!(page(&roles, &grant, 7), Err(FrameRoleError::Absent));
    roles.check_invariants().unwrap();
    *model.fail_zero.lock().unwrap() = None;
    assert_eq!(
        roles
            .commit_on_demand_page(grant.identity(), 7)
            .unwrap()
            .frames,
        3
    );
}

#[test]
#[allow(unsafe_code, reason = "the test corrupts the model's node pages")]
fn a_foreign_or_misplaced_entry_is_refused() {
    let (mut roles, model) = manager(16);
    let one = roles.allocate_on_demand_backing(512).unwrap();
    let two = roles.allocate_on_demand_backing(512).unwrap();
    roles.commit_on_demand_page(one.identity(), 3).unwrap();
    let foreign = roles.commit_on_demand_page(two.identity(), 4).unwrap();
    let raw = model.read(two.physical_start(), 4);
    assert_ne!(raw, 0);
    assert_eq!(page(&roles, &two, 4), Ok(foreign.physical_start));

    // Another backing's page named from this one's root.
    // SAFETY: the model's pages are plain memory.
    unsafe { model.write(one.physical_start(), 9, raw) };
    assert_eq!(page(&roles, &one, 9), Err(FrameRoleError::WrongRole));
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    // The right backing's page at the wrong place.
    let own = model.read(one.physical_start(), 3);
    // SAFETY: as above.
    unsafe { model.write(one.physical_start(), 9, own) };
    assert_eq!(page(&roles, &one, 9), Err(FrameRoleError::WrongRole));
    // Release refuses a tree it cannot check, and keeps the grant.
    let root = one.physical_start();
    let refused = roles.cancel_object_backing(one).unwrap_err();
    assert_eq!(refused.error(), FrameRoleError::WrongRole);
    // SAFETY: as above.
    unsafe { model.write(root, 9, 0) };
    roles.cancel_object_backing(refused.into_grant()).unwrap();
    roles.check_invariants().unwrap();
}

#[test]
fn release_frees_every_page_and_node() {
    let (mut roles, _) = manager(32);
    let initial = roles.available_frames();
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    let backing = grant.identity();
    for index in [0, 1, 513, 512 * 512, THREE_LEVELS - 1] {
        roles.commit_on_demand_page(backing, index).unwrap();
    }
    assert!(roles.available_frames() < initial);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert!(!roles.is_on_demand(backing));
    assert!(roles.on_demand_frames(backing).is_err());
    roles.check_invariants().unwrap();
}

#[test]
fn an_on_demand_backing_needs_its_memory_access() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(PAGE, 4, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    let mut roles = Manager::new(allocator).unwrap();
    assert!(roles.allocate_on_demand_backing(1).is_err());
    assert_eq!(roles.available_frames(), 4);
}
