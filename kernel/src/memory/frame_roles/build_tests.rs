//! An eager backing allocated, and abandoned, in steps (DW2 §12.11 part
//! 2): the first hold, the building steps' budgets and splits, a failing
//! run, and abandonment at each stage.

extern crate std;

use super::super::super::physical::PhysicalAddressLimit;
use super::*;
use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::vec::Vec;

const PAGE: u64 = BASE_PAGE_SIZE;
/// What a node page that was never zeroed reads as.
const GARBAGE: u64 = 0xdead_beef_0000_0001;

/// Index memory that counts zeroings and can fail one.
#[derive(Default)]
struct Model {
    zeroed: Mutex<BTreeSet<u64>>,
    entries: Mutex<BTreeMap<(u64, usize), u64>>,
    zeroes: AtomicU64,
    /// The zeroing, counted from 0, that fails.
    fail_zero_at: Mutex<Option<u64>>,
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
        let call = self.zeroes.fetch_add(1, Ordering::Relaxed);
        if *self.fail_zero_at.lock().unwrap() == Some(call) {
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

impl Model {
    /// Fails the zeroing `ahead` zeroings from now (0: the next).
    fn fail_in(&self, ahead: u64) {
        *self.fail_zero_at.lock().unwrap() = Some(self.zeroes.load(Ordering::Relaxed) + ahead);
    }

    fn fail_none(&self) {
        *self.fail_zero_at.lock().unwrap() = None;
    }

    fn entries(&self) -> BTreeMap<(u64, usize), u64> {
        self.entries.lock().unwrap().clone()
    }
}

type Small = FrameRoleManager<48, 640>;

/// A range-allocator manager of `page_count` pages, its index memory set.
fn small(page_count: u64) -> (Small, &'static Model) {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(PAGE, page_count, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    let mut roles = FrameRoleManager::new(allocator).unwrap();
    let model: &'static Model = Box::leak(Box::default());
    roles.set_index_memory(model);
    (roles, model)
}

/// A manager whose free memory is holes of the given page counts, in
/// address order, each followed by one held page; the rest is held.
fn holed(sizes: &[u64]) -> (Small, &'static Model, Vec<AllocationGrant>) {
    let (mut roles, model) = small(sizes.iter().map(|size| size + 1).sum::<u64>() + 8);
    let mut held = Vec::new();
    let mut gaps = Vec::new();
    for &size in sizes {
        gaps.push(roles.allocate(size).unwrap());
        held.push(roles.allocate(1).unwrap());
    }
    held.push(roles.allocate(roles.available_frames()).unwrap());
    for gap in gaps {
        roles.cancel_allocation(gap).unwrap();
    }
    (roles, model, held)
}

type Grown = FrameRoleManager<8, 64>;

/// A grown manager (the buddy allocator) over two ranges of `pages` pages,
/// with every other page held: no free block is longer than a page.
fn fragmented(pages: u64) -> (Grown, Vec<AllocationGrant>) {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidates = [
        PageRange::from_page_count(3 * PAGE, pages, limit).unwrap(),
        PageRange::from_page_count((pages + 100) * PAGE, pages, limit).unwrap(),
    ];
    let allocator = PhysicalFrameAllocator::from_candidates(&candidates, limit, []).unwrap();
    let mut roles = Grown::new(allocator).unwrap();
    test_support::grow_in_leaked_runs(&mut roles, 2);
    roles.set_index_memory(Box::leak(Box::<Model>::default()));
    let mut all = Vec::new();
    while let Ok(grant) = roles.allocate(1) {
        all.push(grant);
    }
    all.sort_by_key(|grant| grant.physical_start());
    let mut held = Vec::new();
    for (index, grant) in all.into_iter().enumerate() {
        if index % 2 == 0 {
            roles.cancel_allocation(grant).unwrap();
        } else {
            held.push(grant);
        }
    }
    assert_eq!(roles.largest_free_pages(), 1);
    (roles, held)
}

#[allow(
    unsafe_code,
    reason = "the host model never dereferences synthetic physical memory"
)]
fn zeroed<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    allocation: BackingAllocation,
) -> ObjectBackingGrant {
    assert!(roles.zero_backing_pages(&allocation, 0, allocation.pages(), &mut |_| true));
    // SAFETY: the host model never dereferences the synthetic runs.
    unsafe { roles.assume_backing_zeroed(allocation) }.unwrap()
}

/// The runs the index rooted at `root` names, as (first object page,
/// pages), in object order, from their `ObjectPage` records.
fn layout<const R: usize, const S: usize>(
    roles: &FrameRoleManager<R, S>,
    root: FrameRoleIdentity,
) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = roles
        .slot_views()
        .filter_map(|(_, view)| match view.record {
            Some(RoleRecord {
                range,
                role: FrameRole::ObjectPage(link),
            }) if link.owner == root.raw => Some((link.place, range.page_count())),
            _ => None,
        })
        .collect();
    runs.sort_unstable();
    runs
}

/// The run lengths a remainder of `chain` (in chain order) and then
/// allocator runs of `fresh` pages give, by the rule: the tail first,
/// whole if at most `RUN_CAP` pages, else its last `RUN_CAP` pages.
fn rule_layout(chain: &[u64], fresh: &[u64]) -> Vec<u64> {
    let mut chain = chain.to_vec();
    let mut runs = Vec::new();
    while let Some(tail) = chain.pop() {
        if tail > RUN_CAP {
            runs.push(RUN_CAP);
            chain.push(tail - RUN_CAP);
        } else {
            runs.push(tail);
        }
    }
    runs.extend_from_slice(fresh);
    runs
}

/// The (pages linked, runs linked) after each step the rule gives for
/// runs of `lengths`: a step stops once it has linked `BUILD_STEP_RUNS`
/// runs or `BUILD_STEP_PAGES` pages.
fn rule_steps(lengths: &[u64]) -> Vec<(u64, u64)> {
    let mut steps = Vec::new();
    let (mut linked, mut runs) = (0, 0);
    let (mut step_runs, mut step_pages) = (0, 0);
    for &length in lengths {
        linked += length;
        runs += 1;
        step_runs += 1;
        step_pages += length;
        if step_runs >= BUILD_STEP_RUNS || step_pages >= BUILD_STEP_PAGES {
            steps.push((linked, runs));
            (step_runs, step_pages) = (0, 0);
        }
    }
    if step_runs != 0 {
        steps.push((linked, runs));
    }
    steps
}

/// What a failed run must leave as it was.
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    available: u64,
    linked: u64,
    runs: u64,
    remainder: Option<(FrameRoleIdentity, u64, u64)>,
    layout: Vec<(u64, u64)>,
    entries: BTreeMap<(u64, usize), u64>,
    free: Vec<PageRange>,
}

fn snapshot(roles: &Small, model: &Model, allocation: &BackingAllocation) -> Snapshot {
    Snapshot {
        available: roles.available_frames(),
        linked: allocation.linked,
        runs: allocation.runs,
        remainder: allocation
            .remainder
            .as_ref()
            .map(|remainder| (remainder.head, remainder.pages, remainder.runs)),
        layout: layout(roles, allocation.head),
        entries: model.entries(),
        free: roles.allocator.boot_free_ranges().to_vec(),
    }
}

/// Every lookup, zeroing, release step and on-demand entry point refuses
/// the unfinished index `root`.
fn refused<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    allocation: &BackingAllocation,
) {
    let root = BackingIdentity(allocation.head);
    for page in [0, allocation.pages() - 1] {
        assert_eq!(
            roles.resolve_object_page(root, page * PAGE, false),
            Err(FrameRoleError::WrongRole)
        );
    }
    assert!(roles.validate_object_range(root, 0, PAGE, false).is_err());
    assert!(!roles.is_on_demand(root));
    assert_eq!(
        roles.commit_on_demand_page(root, 0),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.on_demand_commit_cost(root, 0),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.on_demand_commit_range_cost(root, 0, 1),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.decommit_on_demand_range(root, 0, 1, 8),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(roles.on_demand_frames(root), Err(FrameRoleError::WrongRole));
    assert!(roles.release_index_step(root, 0, 8).is_err());
}

#[test]
fn sixteen_runs_are_a_chain_after_the_first_hold_and_seventeen_build() {
    let (mut roles, _, _held) = holed(&[1; 20]);
    let initial = roles.available_frames();

    let allocation = roles.begin_backing(16).unwrap();
    assert!(!allocation.indexed && allocation.is_complete());
    assert_eq!(allocation.run_count(), 16);
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_backing_allocation(allocation).unwrap();
    assert_eq!(roles.available_frames(), initial);

    let allocation = roles.begin_backing(17).unwrap();
    assert!(allocation.indexed && !allocation.is_complete());
    // Sixteen runs, as a chain, and the root.
    assert_eq!(allocation.run_count(), 16);
    assert_eq!((allocation.linked, allocation.runs), (0, 0));
    assert_eq!(roles.available_frames(), initial - 17);
    assert_eq!(
        roles.role(allocation.head),
        Ok(FrameRoleKind::BackingAllocated)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    refused(&mut roles, &allocation);
    // Neither zeroed nor made a backing while it is being built.
    assert!(!roles.zero_backing_pages(&allocation, 0, 1, &mut |_| true));
    #[allow(unsafe_code, reason = "the refusal touches no memory")]
    // SAFETY: refused before anything is assumed.
    let refusal = unsafe { roles.assume_backing_zeroed(allocation) }.unwrap_err();
    let mut allocation = refusal.into_grant();

    // One run linked: still building, still refused.
    roles.extend_backing_runs(&mut allocation, 1).unwrap();
    assert_eq!((allocation.linked, allocation.runs), (1, 1));
    assert!(!allocation.is_complete());
    assert_eq!(roles.check_invariants(), Ok(()));
    refused(&mut roles, &allocation);

    // The rest in one step: complete, and not resolved until zeroed.
    roles.extend_backing(&mut allocation).unwrap();
    assert!(allocation.is_complete());
    assert_eq!(allocation.run_count(), 17);
    // The runs and the root.
    assert_eq!(roles.available_frames(), initial - 18);
    assert_eq!(roles.check_invariants(), Ok(()));
    let root = BackingIdentity(allocation.head);
    assert_eq!(
        roles.resolve_object_page(root, 0, false),
        Err(FrameRoleError::WrongRole)
    );
    let grant = zeroed(&mut roles, allocation);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    let frames: BTreeSet<u64> = (0..17)
        .map(|page| {
            roles
                .resolve_object_page(grant.identity(), page * PAGE, false)
                .unwrap()
                .physical_start
        })
        .collect();
    assert_eq!(frames.len(), 17, "every page a distinct frame");
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_step_links_at_most_512_runs() {
    let (mut roles, _held) = fragmented(2200);
    let initial = roles.available_frames();
    let pages = 1100;
    let mut allocation = roles.begin_backing(pages).unwrap();
    let mut steps = Vec::new();
    while !allocation.is_complete() {
        roles.extend_backing(&mut allocation).unwrap();
        assert_eq!(roles.check_invariants(), Ok(()));
        steps.push((allocation.linked, allocation.runs));
    }
    // One-page runs: the first hold's 16, then the allocator's.
    assert_eq!(steps, rule_steps(&[1; 1100]));
    assert_eq!(steps, [(512, 512), (1024, 1024), (1100, 1100)]);
    let grant = zeroed(&mut roles, allocation);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_step_stops_at_its_page_limit_splitting_long_runs_from_their_end() {
    // The first hold takes the 80,000-page hole and 15 of the 5,000s, the
    // 16th holding the root, the leaves and the last 3,000 pages.
    let mut sizes = std::vec![5000; 16];
    sizes.push(80_000);
    let (mut roles, _, _held) = holed(&sizes);
    let initial = roles.available_frames();
    let pages = 80_000 + 15 * 5000 + 3000;
    let mut allocation = roles.begin_backing(pages).unwrap();
    let mut chain = std::vec![80_000];
    chain.extend([5000; 15]);
    assert_eq!(allocation.run_count(), 16);
    let lengths = rule_layout(&chain, &[3000]);
    let mut steps = Vec::new();
    while !allocation.is_complete() {
        roles.extend_backing(&mut allocation).unwrap();
        assert_eq!(roles.check_invariants(), Ok(()));
        steps.push((allocation.linked, allocation.runs));
    }
    assert_eq!(steps, rule_steps(&lengths));
    // The first step stops at the run that takes it to its page limit.
    assert!(steps.len() > 2);
    assert!(steps[0].0 >= BUILD_STEP_PAGES && steps[0].1 < BUILD_STEP_RUNS);
    assert!(steps[0].0 - lengths[steps[0].1 as usize - 1] < BUILD_STEP_PAGES);
    let mut place = 0;
    let expected: Vec<(u64, u64)> = lengths
        .iter()
        .map(|&length| {
            place += length;
            (place - length, length)
        })
        .collect();
    assert_eq!(layout(&roles, allocation.head), expected);
    // The root and a leaf per 512 pages.
    assert_eq!(
        roles.available_frames(),
        initial - pages - 1 - pages.div_ceil(512)
    );
    let grant = zeroed(&mut roles, allocation);
    let frames: BTreeSet<u64> = (0..pages)
        .step_by(7)
        .map(|page| {
            roles
                .resolve_object_page(grant.identity(), page * PAGE, false)
                .unwrap()
                .physical_start
        })
        .collect();
    assert_eq!(frames.len() as u64, pages.div_ceil(7));
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn each_run_linked_leaves_the_remainder_a_whole_chain() {
    // The first hold takes 4,500, 4,200 and 14 single pages; the root,
    // the leaves and the last 6 pages come from the other single pages.
    let mut sizes = std::vec![4500, 4200];
    sizes.extend([1; 40]);
    let (mut roles, model, _held) = holed(&sizes);
    let initial = roles.available_frames();
    let pages = 4500 + 4200 + 14 + 6;
    let mut allocation = roles.begin_backing(pages).unwrap();
    let index = EagerIndex {
        memory: model,
        root: allocation.head,
        node: roles
            .index_root(allocation.head, RootUse::Any)
            .unwrap()
            .0
            .start,
        levels: 2,
    };
    let mut chain = std::vec![4500, 4200];
    chain.extend([1; 14]);
    let lengths = rule_layout(&chain, &[1; 6]);
    let mut splits = 0;
    // All but the last run one at a time; the step that links the last
    // completes the root.
    let (last, lengths) = lengths.split_last().unwrap();
    for &length in lengths {
        let tail = allocation
            .remainder
            .as_ref()
            .map(|remainder| roles.remainder_tail(remainder).unwrap().1.range);
        assert_eq!(roles.link_one_run(&index, &mut allocation), Ok(length));
        assert_eq!(roles.check_invariants(), Ok(()));
        match &allocation.remainder {
            Some(remainder) => {
                assert_eq!(
                    roles.chain_totals(remainder.head, ChainState::Allocated),
                    Ok((remainder.pages, remainder.runs))
                );
                assert_eq!(remainder.pages + allocation.linked, 4500 + 4200 + 14);
                // A split tail keeps its start and its place in the chain.
                let after = roles.remainder_tail(remainder).unwrap().1.range;
                if tail.is_some_and(|tail| tail.start == after.start) {
                    assert_eq!(after.end, tail.unwrap().end - length * PAGE);
                    splits += 1;
                }
            }
            None => assert!(allocation.linked >= 4500 + 4200 + 14),
        }
    }
    assert_eq!(splits, 2, "each of the two long runs split once");
    assert_eq!(allocation.linked, pages - last);
    roles.extend_backing(&mut allocation).unwrap();
    assert!(allocation.is_complete());
    let grant = zeroed(&mut roles, allocation);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
}

#[test]
fn a_node_or_a_run_failing_leaves_the_index_as_it_was_before_that_run() {
    // The first hold takes 5,000 and 15 single pages, and the root another;
    // linked from the tail, the 15 single pages lie in leaf 0, and the
    // 5,000's last 4,096 pages, at page 15, need leaves 1 to 8.
    let mut sizes = std::vec![5000];
    sizes.extend([1; 31]);
    let (mut roles, model, _held) = holed(&sizes);
    let initial = roles.available_frames();
    let mut allocation = roles.begin_backing(5020).unwrap();
    let index = EagerIndex {
        memory: model,
        root: allocation.head,
        node: roles
            .index_root(allocation.head, RootUse::Any)
            .unwrap()
            .0
            .start,
        levels: 2,
    };
    for _ in 0..15 {
        roles.link_one_run(&index, &mut allocation).unwrap();
    }
    let before = snapshot(&roles, model, &allocation);
    for position in 0..8 {
        model.fail_in(position);
        assert_eq!(
            roles.link_one_run(&index, &mut allocation),
            Err(FrameRoleError::InitializationFailed),
            "node {position}"
        );
        model.fail_none();
        assert_eq!(snapshot(&roles, model, &allocation), before);
        assert_eq!(roles.check_invariants(), Ok(()));
    }
    // Out of role slots for the split's own record, after its nodes.
    let free_slots = roles.free_slot_count;
    roles.free_slot_count = 8;
    assert_eq!(
        roles.link_one_run(&index, &mut allocation),
        Err(FrameRoleError::Capacity)
    );
    roles.free_slot_count = free_slots;
    assert_eq!(snapshot(&roles, model, &allocation), before);
    assert_eq!(roles.check_invariants(), Ok(()));
    assert_eq!(roles.link_one_run(&index, &mut allocation), Ok(RUN_CAP));
    // A failed step leaves the allocation to abandon whole.
    model.fail_in(0);
    assert_eq!(
        roles.extend_backing(&mut allocation),
        Err(FrameRoleError::InitializationFailed)
    );
    model.fail_none();
    let owed = roles.abandon_backing(allocation).expect("runs are linked");
    assert_eq!(owed.pages(), 15 + RUN_CAP);
    free_owed(&mut roles, owed, 64);
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_fresh_run_that_fails_is_freed_and_one_that_cannot_be_taken_changes_nothing() {
    // Sixteen runs of 320 pages fill leaves 0 to 9 exactly; the next run,
    // from the seventeenth hole, starts leaf 10 at page 5,120.
    let mut sizes = std::vec![1; 20];
    sizes.extend([320; 17]);
    let (mut roles, model, _held) = holed(&sizes);
    let mut allocation = roles.begin_backing(16 * 320 + 200).unwrap();
    let index = EagerIndex {
        memory: model,
        root: allocation.head,
        node: roles
            .index_root(allocation.head, RootUse::Any)
            .unwrap()
            .0
            .start,
        levels: 2,
    };
    // A remainder run whole whose leaf fails stays in the remainder.
    assert_eq!(roles.link_one_run(&index, &mut allocation), Ok(320));
    let before = snapshot(&roles, model, &allocation);
    model.fail_in(0);
    assert_eq!(
        roles.link_one_run(&index, &mut allocation),
        Err(FrameRoleError::InitializationFailed)
    );
    model.fail_none();
    assert_eq!(snapshot(&roles, model, &allocation), before);
    for _ in 1..16 {
        assert_eq!(roles.link_one_run(&index, &mut allocation), Ok(320));
    }
    assert!(allocation.remainder.is_none());
    // A fresh run whose leaf fails is given back.
    let before = snapshot(&roles, model, &allocation);
    model.fail_in(0);
    assert_eq!(
        roles.link_one_run(&index, &mut allocation),
        Err(FrameRoleError::InitializationFailed)
    );
    model.fail_none();
    assert_eq!(snapshot(&roles, model, &allocation), before);
    assert_eq!(roles.check_invariants(), Ok(()));
    // No frame for a fresh run: nothing changes.
    let mut taken = Vec::new();
    while let Ok(grant) = roles.allocate(1) {
        taken.push(grant);
    }
    let before = snapshot(&roles, model, &allocation);
    assert_eq!(
        roles.link_one_run(&index, &mut allocation),
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::NoFramesAvailable
        ))
    );
    assert_eq!(snapshot(&roles, model, &allocation), before);
    for grant in taken {
        roles.cancel_allocation(grant).unwrap();
    }
    roles.extend_backing(&mut allocation).unwrap();
    assert!(allocation.is_complete());
    assert_eq!(layout(&roles, allocation.head).last(), Some(&(5120, 200)));
    roles.cancel_backing_allocation(allocation).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

/// Frees `owed` in release steps of `budget`, checking the manager after
/// each, then its root, which is refused while entries remain. Returns the
/// run pages the steps freed.
fn free_owed(roles: &mut Small, owed: OwedBacking, budget: u64) -> u64 {
    let backing = owed.identity();
    let pages = owed.pages();
    let owed = roles
        .release_owed_backing(owed)
        .expect_err("a root with entries below it is not freed")
        .into_grant();
    let mut cursor = 0;
    let mut freed = 0;
    while cursor < pages {
        let (next, step_freed, _) = roles.release_index_step(backing, cursor, budget).unwrap();
        assert!(next > cursor, "a step makes progress");
        assert_eq!(roles.check_invariants(), Ok(()));
        assert_eq!(
            roles.resolve_object_page(backing, (pages - 1) * PAGE, false),
            Err(FrameRoleError::WrongRole)
        );
        cursor = next;
        freed += step_freed;
    }
    assert_eq!(freed, pages, "each run's pages once");
    roles.release_owed_backing(owed).unwrap();
    freed
}

#[test]
fn an_allocation_abandoned_at_each_stage_owes_only_what_is_linked() {
    let mut sizes = std::vec![1; 30];
    sizes.extend([300; 18]);
    for stage in 0..5 {
        let (mut roles, _, _held) = holed(&sizes);
        let initial = roles.available_frames();
        let owed = match stage {
            // A chain: freed at once.
            0 => {
                let allocation = roles.begin_backing(16 * 300).unwrap();
                assert!(!allocation.indexed);
                roles.abandon_backing(allocation)
            }
            // Building, nothing linked: its remainder and root freed.
            1 => {
                let allocation = roles.begin_backing(17 * 300).unwrap();
                roles.abandon_backing(allocation)
            }
            // Building, five runs linked: owed, the rest freed.
            2 => {
                let mut allocation = roles.begin_backing(17 * 300).unwrap();
                roles.extend_backing_runs(&mut allocation, 5).unwrap();
                let owed = roles.abandon_backing(allocation);
                assert_eq!(owed.as_ref().map(OwedBacking::pages), Some(5 * 300));
                owed
            }
            // Complete and not zeroed: owed whole.
            3 => {
                let allocation = roles.allocate_backing(17 * 300).unwrap();
                let owed = roles.abandon_backing(allocation);
                assert_eq!(owed.as_ref().map(OwedBacking::pages), Some(17 * 300));
                owed
            }
            // A zeroed backing rolled back: owed whole; a chain is freed.
            _ => {
                let allocation = roles.allocate_backing(300).unwrap();
                let chain = zeroed(&mut roles, allocation);
                assert_eq!(roles.abandon_object_backing(chain), None);
                let allocation = roles.allocate_backing(17 * 300).unwrap();
                let grant = zeroed(&mut roles, allocation);
                let owed = roles.abandon_object_backing(grant);
                assert_eq!(owed.as_ref().map(OwedBacking::pages), Some(17 * 300));
                owed
            }
        };
        assert_eq!(roles.check_invariants(), Ok(()), "stage {stage}");
        match owed {
            None => assert!(stage < 2, "stage {stage}"),
            Some(owed) => {
                assert!(stage >= 2);
                // Being freed: nothing resolves it, nothing commits to it.
                assert_eq!(
                    roles.resolve_object_page(owed.identity(), 0, false),
                    Err(FrameRoleError::WrongRole)
                );
                assert!(!roles.is_on_demand(owed.identity()));
                assert_eq!(
                    roles.role(owed.identity().0),
                    Ok(FrameRoleKind::ObjectBacking(
                        ObjectBackingKind::AllocatorIndexed
                    ))
                );
                let pages = owed.pages();
                assert_eq!(free_owed(&mut roles, owed, 7), pages);
            }
        }
        assert_eq!(roles.available_frames(), initial, "stage {stage}");
        assert_eq!(roles.check_invariants(), Ok(()));
    }
}
