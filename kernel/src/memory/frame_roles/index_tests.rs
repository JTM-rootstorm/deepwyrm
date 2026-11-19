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

/// The pages of a three-level index whose commits need one, two and three
/// frames after page 600 is committed: a neighbour in its leaf, a page under
/// a fresh leaf node, and a page under a fresh node above that.
const ONE_TWO_THREE: [(u64, u64); 3] = [(601, 1), (0, 2), (THREE_LEVELS - 1, 3)];

/// DW2 §13.18 part f1: a commit within a limit at or above its cost commits
/// exactly what the unlimited commit does, in a second manager made the
/// same way.
#[test]
fn a_commit_within_its_cost_commits_what_the_full_commit_does() {
    for slack in [0, 1, 1000, u64::MAX - 3] {
        let (mut within, _) = manager(32);
        let (mut full, _) = manager(32);
        let grant = within.allocate_on_demand_backing(THREE_LEVELS).unwrap();
        let other = full.allocate_on_demand_backing(THREE_LEVELS).unwrap();
        assert_eq!(grant.physical_start(), other.physical_start());
        within.commit_on_demand_page(grant.identity(), 600).unwrap();
        full.commit_on_demand_page(other.identity(), 600).unwrap();
        for (index, cost) in ONE_TWO_THREE {
            assert_eq!(
                within.on_demand_commit_cost(grant.identity(), index),
                Ok(cost)
            );
            let commit = within
                .commit_on_demand_page_within(grant.identity(), index, cost + slack)
                .unwrap()
                .unwrap();
            let expected = full.commit_on_demand_page(other.identity(), index).unwrap();
            assert_eq!(commit, expected, "page {index}, slack {slack}");
            assert_eq!(commit.frames, cost);
            assert_eq!(page(&within, &grant, index), Ok(commit.physical_start));
            assert_eq!(within.available_frames(), full.available_frames());
        }
        within.check_invariants().unwrap();
    }
}

/// One below the cost takes nothing and changes nothing: the free frames,
/// the cost and a following full commit are as if it had not been asked.
#[test]
fn a_commit_one_below_its_cost_takes_nothing() {
    let (mut roles, _) = manager(32);
    let (mut untouched, _) = manager(32);
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    let other = untouched.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    roles.commit_on_demand_page(grant.identity(), 600).unwrap();
    untouched
        .commit_on_demand_page(other.identity(), 600)
        .unwrap();
    for (index, cost) in ONE_TWO_THREE {
        let free = roles.available_frames();
        assert_eq!(
            roles.commit_on_demand_page_within(grant.identity(), index, cost - 1),
            Ok(None),
            "page {index}"
        );
        assert_eq!(roles.available_frames(), free);
        assert_eq!(page(&roles, &grant, index), Err(FrameRoleError::Absent));
        assert_eq!(
            roles.on_demand_commit_cost(grant.identity(), index),
            Ok(cost)
        );
        roles.check_invariants().unwrap();
        assert_eq!(
            roles.commit_on_demand_page(grant.identity(), index),
            untouched.commit_on_demand_page(other.identity(), index)
        );
        assert_eq!(roles.available_frames(), untouched.available_frames());
    }
}

/// A committed page is its frame and no frames, even for a limit of zero.
#[test]
fn a_committed_page_is_its_frame_within_any_limit() {
    let (mut roles, _) = manager(32);
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    let backing = grant.identity();
    let commit = roles.commit_on_demand_page(backing, 600).unwrap();
    let free = roles.available_frames();
    for limit in [0, 1, u64::MAX] {
        assert_eq!(
            roles.commit_on_demand_page_within(backing, 600, limit),
            Ok(Some(OnDemandCommit {
                physical_start: commit.physical_start,
                frames: 0
            }))
        );
    }
    assert_eq!(roles.available_frames(), free);
    // A page past the object is refused as the full commit refuses it,
    // whatever the limit.
    for limit in [0, u64::MAX] {
        assert_eq!(
            roles.commit_on_demand_page_within(backing, THREE_LEVELS, limit),
            Err(FrameRoleError::WrongRole)
        );
    }
    assert_eq!(
        roles.commit_on_demand_page(backing, THREE_LEVELS),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(roles.available_frames(), free);
    roles.check_invariants().unwrap();
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

/// §8.11 R1: a commit step admits a range's cost once, so that cost must be
/// exactly what committing its pages in order takes, each missing node
/// counted once though several pages share it.
#[test]
fn a_range_costs_what_committing_its_pages_in_order_takes() {
    let (mut roles, _) = manager(64);
    let grant = roles.allocate_on_demand_backing(INDEX_MAX_PAGES).unwrap();
    let backing = grant.identity();
    roles.commit_on_demand_page(backing, 5).unwrap();
    // Within one leaf around a committed page; across a leaf node's edge;
    // across a height-2 node's edge; an empty range; all committed.
    for (first, count) in [(0, 10), (509, 6), ((1 << 18) - 2, 4), (100, 0), (2, 6)] {
        let cost = roles
            .on_demand_commit_range_cost(backing, first, count)
            .unwrap();
        let before = roles.available_frames();
        let taken: u64 = (first..first + count)
            .map(|page| roles.commit_on_demand_page(backing, page).unwrap().frames)
            .sum();
        assert_eq!(cost, taken, "pages {first}..+{count}");
        assert_eq!(roles.available_frames(), before - taken);
    }
    // A prefix costs its own share only: under the existing height-3 node,
    // a new height-2 node and leaf, then the pages.
    assert_eq!(
        roles.on_demand_commit_range_cost(backing, 1 << 20, 3),
        Ok(3 + 2)
    );
    assert_eq!(
        roles.on_demand_commit_range_cost(backing, 1 << 20, 1),
        Ok(1 + 2)
    );
    roles.check_invariants().unwrap();
}

/// Finalizes `backing` in steps of `budget` entries (DW2 §10.12 item 2),
/// checking the role table after every step: each step frees what it says,
/// visits no more than its budget plus a cascade of node frees, and the
/// frames left are the root once the cursor reaches the end. Returns the
/// steps taken.
fn release_in_steps(roles: &mut Manager, grant: &ObjectBackingGrant, budget: u64) -> u64 {
    let backing = grant.identity();
    let pages = grant.byte_len() / PAGE;
    let mut cursor = 0;
    let mut steps = 0;
    while cursor < pages {
        let before = roles.available_frames();
        let held = roles.on_demand_frames(backing).unwrap();
        let (next, freed, visited) = roles.release_index_step(backing, cursor, budget).unwrap();
        assert!(next > cursor || cursor == pages, "a step makes progress");
        assert!(visited < budget + u64::from(INDEX_MAX_LEVELS));
        assert_eq!(roles.available_frames(), before + freed);
        assert_eq!(roles.on_demand_frames(backing).unwrap(), held - freed);
        roles.check_invariants().unwrap();
        cursor = next;
        steps += 1;
    }
    assert_eq!(
        roles.on_demand_frames(backing),
        Ok(1),
        "only the root is left"
    );
    steps
}

#[test]
fn a_stepped_release_frees_pages_and_nodes_whatever_the_budget() {
    for budget in [1, 2, 3, 5, 512] {
        let (mut roles, _) = manager(32);
        let initial = roles.available_frames();
        let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
        // The last page sits in a level-1 node and a leaf whose spans run
        // past the object's end.
        for index in [0, 1, 511, 513, 512 * 512 - 1, 512 * 512, THREE_LEVELS - 1] {
            roles
                .commit_on_demand_page(grant.identity(), index)
                .unwrap();
        }
        release_in_steps(&mut roles, &grant, budget);
        roles.cancel_object_backing(grant).unwrap();
        assert_eq!(roles.available_frames(), initial, "budget {budget}");
        roles.check_invariants().unwrap();
    }
}

#[test]
fn a_last_leaf_cut_short_by_the_object_is_freed() {
    // Two levels, the second leaf covering only 88 pages.
    let (mut roles, _) = manager(16);
    let initial = roles.available_frames();
    let grant = roles.allocate_on_demand_backing(600).unwrap();
    for index in [0, 599] {
        roles
            .commit_on_demand_page(grant.identity(), index)
            .unwrap();
    }
    release_in_steps(&mut roles, &grant, 2);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
}

#[test]
fn a_step_that_ends_at_a_node_s_end_frees_that_node() {
    let (mut roles, _) = manager(16);
    let grant = roles.allocate_on_demand_backing(2048).unwrap();
    let backing = grant.identity();
    for index in [510, 511, 1024] {
        roles.commit_on_demand_page(backing, index).unwrap();
    }
    // Root, two leaves and three pages.
    assert_eq!(roles.on_demand_frames(backing), Ok(6));
    // From page 509: its absent entry, 510, 511. The budget is spent at
    // the leaf's end, and the leaf goes with it.
    let (cursor, freed, visited) = roles.release_index_step(backing, 509, 3).unwrap();
    assert_eq!((cursor, freed, visited), (512, 3, 4));
    assert_eq!(roles.on_demand_frames(backing), Ok(3));
    roles.check_invariants().unwrap();
    release_in_steps(&mut roles, &grant, 3);
}

#[test]
fn one_and_four_level_indexes_release_in_steps() {
    let (mut roles, _) = manager(16);
    let initial = roles.available_frames();
    let small = roles.allocate_on_demand_backing(512).unwrap();
    for index in [0, 7, 511] {
        roles
            .commit_on_demand_page(small.identity(), index)
            .unwrap();
    }
    // Each absent page of a leaf is one entry visited.
    assert_eq!(release_in_steps(&mut roles, &small, 2), 256);
    roles.cancel_object_backing(small).unwrap();
    let largest = roles.allocate_on_demand_backing(INDEX_MAX_PAGES).unwrap();
    for index in [0, INDEX_MAX_PAGES - 1] {
        roles
            .commit_on_demand_page(largest.identity(), index)
            .unwrap();
    }
    release_in_steps(&mut roles, &largest, 4);
    roles.cancel_object_backing(largest).unwrap();
    assert_eq!(roles.available_frames(), initial);
}

#[test]
fn nodes_left_empty_by_a_decommit_are_freed() {
    let (mut roles, _) = manager(16);
    let initial = roles.available_frames();
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    let backing = grant.identity();
    roles.commit_on_demand_page(backing, 700).unwrap();
    roles
        .decommit_on_demand_range(backing, 0, THREE_LEVELS, 4096)
        .unwrap();
    // Two nodes and the root, no pages.
    assert_eq!(roles.on_demand_frames(backing), Ok(3));
    release_in_steps(&mut roles, &grant, 1);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
}

/// DW2 §12.6 item 2: the root and each entry are read through
/// `index_root_at` and `index_entry_at`, and keep every error of the full
/// record read: foreign, stale, the wrong role, a node where a page is
/// due and the reverse, and an entry of more than one page.
#[test]
#[allow(
    unsafe_code,
    reason = "the test corrupts the model's node pages and attests a zeroed backing"
)]
fn the_index_readers_keep_their_errors() {
    let (mut roles, model) = manager(32);
    // Two levels: the root and one leaf node per 512 pages.
    let grant = roles.allocate_on_demand_backing(513).unwrap();
    let backing = grant.identity();
    let head = backing.0;
    roles.commit_on_demand_page(backing, 0).unwrap();
    let root = grant.physical_start();
    let node_raw = model.read(root, 0);
    let node = roles
        .record(FrameRoleIdentity {
            domain: roles.domain,
            raw: node_raw,
        })
        .unwrap();
    let page_raw = model.read(node.range.start, 0);

    // The root: foreign, a chain backing, a node and a page are not roots.
    let foreign = BackingIdentity(FrameRoleIdentity {
        domain: roles.domain + 1,
        raw: head.raw,
    });
    assert_eq!(
        roles.on_demand_frames(foreign),
        Err(FrameRoleError::ForeignManager)
    );
    assert!(!roles.is_on_demand(foreign));
    let allocation = roles.allocate_backing(1).unwrap();
    // SAFETY: the host model never dereferences the synthetic run.
    let chain = unsafe { roles.assume_backing_zeroed(allocation) }.unwrap();
    for not_a_root in [chain.identity().0.raw, node_raw, page_raw] {
        let identity = BackingIdentity(FrameRoleIdentity {
            domain: roles.domain,
            raw: not_a_root,
        });
        assert_eq!(
            roles.on_demand_frames(identity),
            Err(FrameRoleError::WrongRole)
        );
        assert_eq!(
            roles.commit_on_demand_page(identity, 0),
            Err(FrameRoleError::WrongRole)
        );
        assert_eq!(
            roles.commit_on_demand_page_within(identity, 0, 0),
            Err(FrameRoleError::WrongRole)
        );
        assert!(!roles.is_on_demand(identity));
    }
    // An on-demand root is not a chain.
    assert_eq!(
        roles.object_segments(backing, 0, PAGE, false).err(),
        Some(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.release_chain(head, ChainState::Backing, 513, 1),
        Err(FrameRoleError::WrongRole)
    );

    // Entries: a page where a node is due, a node where a page is due, a
    // live run of another role, a stale identity, and a page of two
    // frames at the right place.
    // SAFETY: the model's pages are plain memory.
    unsafe { model.write(root, 1, page_raw) };
    assert_eq!(page(&roles, &grant, 512), Err(FrameRoleError::WrongRole));
    // SAFETY: as above.
    unsafe { model.write(root, 1, 0) };
    // SAFETY: as above.
    unsafe { model.write(node.range.start, 1, node_raw) };
    assert_eq!(page(&roles, &grant, 1), Err(FrameRoleError::WrongRole));
    // SAFETY: as above.
    unsafe { model.write(node.range.start, 1, chain.identity().0.raw) };
    assert_eq!(page(&roles, &grant, 1), Err(FrameRoleError::WrongRole));
    let gone = roles.allocate(1).unwrap();
    let gone_raw = gone.identity.raw;
    roles.cancel_allocation(gone).unwrap();
    // SAFETY: as above.
    unsafe { model.write(node.range.start, 1, gone_raw) };
    assert_eq!(page(&roles, &grant, 1), Err(FrameRoleError::InvalidGrant));
    let (slot, generation) = roles.next_slot().unwrap();
    let wide = roles.allocator.allocate_run(2).unwrap();
    let wide_identity = roles.identity(slot, generation).unwrap();
    roles.occupy(
        slot,
        generation,
        RoleRecord {
            range: wide,
            role: FrameRole::ObjectPage(IndexEntryLink {
                owner: head.raw,
                place: 1,
            }),
        },
    );
    // SAFETY: as above.
    unsafe { model.write(node.range.start, 1, wide_identity.raw) };
    assert_eq!(page(&roles, &grant, 1), Err(FrameRoleError::WrongRole));
    // Restored, the index reads and frees whole.
    // SAFETY: as above.
    unsafe { model.write(node.range.start, 1, 0) };
    assert_eq!(page(&roles, &grant, 0), Ok(model_page(&roles, page_raw)));
    roles.allocator.free_run(wide).unwrap();
    roles.vacate(slot);
    roles.check_invariants().unwrap();
    roles.cancel_object_backing(grant).unwrap();
    roles.cancel_object_backing(chain).unwrap();
    roles.check_invariants().unwrap();
}

/// The physical page the committed page `raw` holds.
fn model_page(roles: &Manager, raw: u64) -> u64 {
    roles
        .record(FrameRoleIdentity {
            domain: roles.domain,
            raw,
        })
        .unwrap()
        .range
        .start
}

/// `model`, with node page `node` zeroed and entries `[3, 9)` written one
/// at a time as `0x77`, so a run's writes land among others.
fn run_model(node: u64) -> Model {
    let model = Model::default();
    #[allow(unsafe_code, reason = "the test owns its model's pages")]
    // SAFETY: the model is the test's own; nothing else names its pages.
    unsafe {
        assert!(model.zero(node));
        for entry in 3..9 {
            model.write(node, entry, 0x77);
        }
    }
    model
}

#[test]
fn a_run_writes_what_its_entries_written_one_at_a_time_write() {
    let node = 5 * PAGE;
    for (first, count) in [(0, 1), (4, 3), (7, 0), (100, 312), (500, 12), (0, 512)] {
        let by_run = run_model(node);
        let by_entry = run_model(node);
        #[allow(unsafe_code, reason = "the test owns its model's pages")]
        // SAFETY: the models are the test's own; the run lies in the node.
        unsafe {
            by_run.write_run(node, first, count, 0x1234);
            for entry in first..first + count {
                by_entry.write(node, entry, 0x1234);
            }
        }
        assert_eq!(
            *by_run.entries.lock().unwrap(),
            *by_entry.entries.lock().unwrap(),
            "run of {count} from entry {first}"
        );
        for entry in 0..INDEX_FANOUT as usize {
            let expected = if (first..first + count).contains(&entry) {
                0x1234
            } else if (3..9).contains(&entry) {
                0x77
            } else {
                0
            };
            assert_eq!(by_run.read(node, entry), expected, "entry {entry}");
        }
    }
}

#[test]
#[should_panic(expected = "an index run lies in its node")]
fn a_run_past_its_nodes_end_panics() {
    let node = 5 * PAGE;
    let model = run_model(node);
    #[allow(unsafe_code, reason = "the test owns its model's pages")]
    // SAFETY: the model is the test's own; the run is refused before any
    // write.
    unsafe {
        model.write_run(node, 500, 13, 1)
    };
}
