//! Eager backings held as an index (DW2 §12.10 part 2): conversion,
//! lookup, zeroing, stepped release, and the on-demand entry points that
//! must refuse them.

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

/// Index memory that counts reads and zeroes, and can fail one zeroing.
#[derive(Default)]
struct Model {
    zeroed: Mutex<BTreeSet<u64>>,
    entries: Mutex<BTreeMap<(u64, usize), u64>>,
    reads: AtomicU64,
    zeroes: AtomicU64,
    /// The zeroing, counted from 0, that fails.
    fail_zero_at: Mutex<Option<u64>>,
}

impl IndexMemory for Model {
    fn read(&self, node: u64, entry: usize) -> u64 {
        self.reads.fetch_add(1, Ordering::Relaxed);
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
    fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

fn model() -> &'static Model {
    Box::leak(Box::default())
}

// ---- A range-allocator manager with holes of chosen sizes. ----

type Small = FrameRoleManager<48, 160>;

/// A manager of `page_count` pages, its index memory set.
fn small(page_count: u64) -> (Small, &'static Model) {
    sized(page_count)
}

fn sized<const S: usize>(page_count: u64) -> (FrameRoleManager<48, S>, &'static Model) {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(PAGE, page_count, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    let mut roles = FrameRoleManager::new(allocator).unwrap();
    let model = model();
    roles.set_index_memory(model);
    (roles, model)
}

/// Leaves free holes of the given page counts, in address order, separated
/// by one held page each, and holds the rest.
fn holes<const S: usize>(
    roles: &mut FrameRoleManager<48, S>,
    sizes: &[u64],
) -> Vec<AllocationGrant> {
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
    held
}

// ---- A grown manager (the buddy allocator) fragmented into pages. ----

type Grown = FrameRoleManager<8, 64>;

/// A grown manager over two ranges of `pages` pages each, its index memory
/// set, with every other allocator page held so that no free block is
/// longer than a page. Returns the pages held.
fn fragmented(pages: u64) -> (Grown, &'static Model, Vec<AllocationGrant>) {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidates = [
        PageRange::from_page_count(3 * PAGE, pages, limit).unwrap(),
        PageRange::from_page_count((pages + 100) * PAGE, pages, limit).unwrap(),
    ];
    let allocator = PhysicalFrameAllocator::from_candidates(&candidates, limit, []).unwrap();
    let mut roles = Grown::new(allocator).unwrap();
    test_support::grow_in_leaked_runs(&mut roles, 2);
    let model = model();
    roles.set_index_memory(model);
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
    (roles, model, held)
}

#[allow(
    unsafe_code,
    reason = "the host model never dereferences synthetic physical memory"
)]
fn zeroed<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    allocation: BackingAllocation,
) -> ObjectBackingGrant {
    // SAFETY: the host model never dereferences the synthetic runs.
    unsafe { roles.assume_backing_zeroed(allocation) }.unwrap()
}

fn backing<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    pages: u64,
) -> ObjectBackingGrant {
    let allocation = roles.allocate_backing(pages).unwrap();
    zeroed(roles, allocation)
}

fn resolve<const R: usize, const S: usize>(
    roles: &FrameRoleManager<R, S>,
    backing: BackingIdentity,
    page: u64,
) -> Result<u64, FrameRoleError> {
    roles
        .resolve_object_page(backing, page * PAGE, true)
        .map(|segment| segment.physical_start)
}

/// The frame of every page of a `pages`-page backing made as a chain from
/// the manager's present state, which is restored afterwards.
fn chain_frames<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    model: &'static Model,
    pages: u64,
) -> Vec<u64> {
    roles.index_memory = None;
    let grant = backing(roles, pages);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorOwned);
    let mut cursor = BackingCursor::new(grant.identity());
    let frames = (0..pages)
        .map(|page| {
            roles
                .resolve_at(&mut cursor, page * PAGE, true)
                .unwrap()
                .physical_start
        })
        .collect();
    roles.cancel_object_backing(grant).unwrap();
    roles.set_index_memory(model);
    frames
}

/// The runs of a backing made as a chain from the manager's present state,
/// as (first object page, pages); the state is restored afterwards.
fn chain_runs<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    model: &'static Model,
    pages: u64,
) -> Vec<(u64, u64)> {
    roles.index_memory = None;
    let grant = backing(roles, pages);
    let runs = roles
        .object_segments(grant.identity(), 0, grant.byte_len(), true)
        .unwrap()
        .map(|segment| (segment.object_offset / PAGE, segment.byte_len / PAGE))
        .collect();
    roles.cancel_object_backing(grant).unwrap();
    roles.set_index_memory(model);
    runs
}

/// A `pages`-page backing allocated as a chain, the frame of each of its
/// pages read from that chain, and then converted as `allocate_backing`
/// converts it and zeroed: the same allocation before and after.
fn converted<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    model: &'static Model,
    pages: u64,
) -> (Vec<u64>, ObjectBackingGrant) {
    roles.index_memory = None;
    let chain = roles.allocate_backing(pages).unwrap();
    assert!(!chain.indexed);
    let frames = roles
        .backing_allocation_segments(&chain)
        .unwrap()
        .flat_map(|segment| {
            (0..segment.byte_len / PAGE).map(move |page| segment.physical_start + page * PAGE)
        })
        .collect();
    roles.set_index_memory(model);
    let root = roles.index_allocation(chain.head, pages).unwrap().unwrap();
    let allocation = BackingAllocation {
        head: root,
        indexed: true,
        ..chain
    };
    (frames, zeroed(roles, allocation))
}

#[test]
fn an_indexed_backing_resolves_every_page_to_its_chain_s_frame_in_two_node_reads() {
    let (mut roles, model, _held) = fragmented(4400);
    let pages = 3000;
    let before = roles.available_frames();
    let (frames, grant) = converted(&mut roles, model, pages);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    assert_eq!(grant.run_count(), pages, "thousands of one-page runs");
    assert_eq!(grant.byte_len(), pages * PAGE);
    // The root and six leaves.
    assert_eq!(roles.available_frames(), before - pages - 7);
    assert_eq!(roles.check_invariants(), Ok(()));
    for (page, frame) in frames.iter().enumerate() {
        let reads = model.reads();
        assert_eq!(resolve(&roles, grant.identity(), page as u64), Ok(*frame));
        assert_eq!(model.reads() - reads, 2, "page {page}");
    }
    // Every DMA and mapping lookup goes through the same cursor entry.
    let mut cursor = BackingCursor::new(grant.identity());
    assert_eq!(
        roles.object_page(&mut cursor, 1234 * PAGE, true),
        Some(frames[1234])
    );
    assert!(!roles.is_on_demand(grant.identity()));
    assert_eq!(
        roles.validate_object_range(grant.identity(), 0, pages * PAGE, true),
        Ok(())
    );
    assert_eq!(
        roles.validate_object_range(grant.identity(), PAGE, pages * PAGE, true),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        resolve(&roles, grant.identity(), pages),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.resolve_object_page(grant.identity(), PAGE + 1, true),
        Err(FrameRoleError::WrongRole)
    );
    // A foreign manager's identity is refused.
    let (other, _) = small(64);
    assert!(resolve(&other, grant.identity(), 0).is_err());

    let identity = grant.identity();
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), before);
    assert_eq!(roles.check_invariants(), Ok(()));
    // Stale once freed.
    assert!(resolve(&roles, identity, 0).is_err());
    assert!(
        roles
            .validate_object_range(identity, 0, PAGE, false)
            .is_err()
    );
}

#[test]
fn seventeen_runs_resolve_in_one_node_read_and_runs_of_many_pages_at_their_offset() {
    let (mut roles, model) = small(1024);
    let mut sizes = std::vec![300, 120, 9, 3];
    sizes.extend([1; 14]);
    let _held = holes(&mut roles, &sizes);
    let pages = sizes.iter().sum::<u64>() - 1;
    let runs = chain_runs(&mut roles, model, pages);
    assert_eq!(runs.len(), 17);
    // The range allocator gives the same runs again from the same state.
    let frames = chain_frames(&mut roles, model, pages);
    let grant = backing(&mut roles, pages);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    assert_eq!(grant.run_count(), 17);
    assert_eq!(roles.check_invariants(), Ok(()));
    for (page, frame) in frames.iter().enumerate() {
        let reads = model.reads();
        assert_eq!(resolve(&roles, grant.identity(), page as u64), Ok(*frame));
        assert_eq!(model.reads() - reads, 1, "the root is the leaf");
    }
    // Pages inside a run lie at their offset in it.
    assert_eq!(frames[299], frames[0] + 299 * PAGE);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_three_level_index_resolves_every_page_in_three_node_reads() {
    // 17 holes of 16,500 pages: the backing takes 16 whole and part of the
    // last, whose rest holds the root, 2 middle nodes and 516 leaves.
    let (mut roles, model) = sized::<640>(17 * 16_501 + 64);
    let _held = holes(&mut roles, &[16_500; 17]);
    let pages = 16 * 16_500 + 100;
    assert!(pages > 512 * 512);
    let frames = chain_frames(&mut roles, model, pages);
    let before = roles.available_frames();
    let grant = backing(&mut roles, pages);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    assert_eq!(grant.run_count(), 17);
    assert_eq!(roles.available_frames(), before - pages - 1 - 2 - 516);
    assert_eq!(roles.check_invariants(), Ok(()));
    for page in (0..pages).step_by(97).chain([pages - 1, 16_499, 16_500]) {
        let reads = model.reads();
        assert_eq!(
            resolve(&roles, grant.identity(), page),
            Ok(frames[page as usize])
        );
        assert_eq!(model.reads() - reads, 3, "page {page}");
    }
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), before);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn sixteen_runs_stay_a_chain_and_seventeen_become_an_index() {
    let (mut roles, _) = small(256);
    let _held = holes(&mut roles, &[1; 18]);
    let initial = roles.available_frames();

    let allocation = roles.allocate_backing(16).unwrap();
    assert!(!allocation.indexed);
    assert_eq!(allocation.run_count(), 16);
    let chain = zeroed(&mut roles, allocation);
    assert_eq!(chain.kind(), ObjectBackingKind::AllocatorOwned);
    assert_eq!(
        roles
            .object_segments(chain.identity(), 0, chain.byte_len(), true)
            .unwrap()
            .count(),
        16
    );
    assert_eq!(roles.available_frames(), initial - 16);
    roles.cancel_object_backing(chain).unwrap();

    let allocation = roles.allocate_backing(17).unwrap();
    assert!(allocation.indexed);
    assert_eq!(allocation.run_count(), 17);
    // The runs and the root: the last free page.
    assert_eq!(roles.available_frames(), 0);
    let record = roles.record(allocation.head).unwrap();
    assert_eq!(record.role.kind(), FrameRoleKind::BackingAllocated);
    assert_eq!(roles.check_invariants(), Ok(()));
    let index = zeroed(&mut roles, allocation);
    assert_eq!(index.kind(), ObjectBackingKind::AllocatorIndexed);
    assert_eq!(
        roles.role(index.identity().0),
        Ok(FrameRoleKind::ObjectBacking(
            ObjectBackingKind::AllocatorIndexed
        ))
    );
    // Not a chain: the chain paths refuse it.
    assert!(
        roles
            .object_segments(index.identity(), 0, PAGE, true)
            .is_err()
    );
    // Every run is reached from the index, none from a chain.
    let mut runs = 0;
    for (_, view) in roles.slot_views() {
        match view.record.map(|record| record.role) {
            Some(FrameRole::BackingAllocated(_) | FrameRole::ObjectBacking(_)) => {
                panic!("a run was left on the chain")
            }
            Some(FrameRole::ObjectPage(link)) => {
                assert_eq!(link.owner, index.identity().0.raw);
                runs += 1;
            }
            _ => {}
        }
    }
    assert_eq!(runs, 17);
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(index).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_node_allocation_failing_at_each_position_frees_everything() {
    let (mut roles, model, _held) = fragmented(2200);
    let pages = 1200;
    let before = roles.available_frames();
    let blocks: Vec<_> = roles.allocator.free_blocks().collect();
    // The root and three leaves.
    let frames = 4;
    for position in 0..frames {
        let start = model.zeroes.load(Ordering::Relaxed);
        *model.fail_zero_at.lock().unwrap() = Some(start + position);
        assert_eq!(
            roles.allocate_backing(pages),
            Err(FrameRoleError::InitializationFailed),
            "position {position}"
        );
        assert_eq!(roles.available_frames(), before);
        assert_eq!(roles.allocator.free_blocks().collect::<Vec<_>>(), blocks);
        assert_eq!(roles.check_invariants(), Ok(()));
    }
    // Out of role slots taking a node: the same.
    let free_slots = roles.free_slot_count;
    roles.free_slot_count = usize::try_from(pages).unwrap() + 2;
    assert_eq!(roles.allocate_backing(pages), Err(FrameRoleError::Capacity));
    assert_eq!(roles.available_frames(), before);
    roles.free_slot_count = free_slots;
    assert_eq!(roles.check_invariants(), Ok(()));

    let start = model.zeroes.load(Ordering::Relaxed);
    *model.fail_zero_at.lock().unwrap() = Some(start + frames);
    let grant = backing(&mut roles, pages);
    assert_eq!(roles.available_frames(), before - pages - frames);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.allocator.free_blocks().collect::<Vec<_>>(), blocks);
}

#[test]
fn with_no_index_memory_a_backing_of_many_runs_stays_a_chain() {
    let (mut roles, _, _held) = fragmented(400);
    roles.index_memory = None;
    let grant = backing(&mut roles, 100);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorOwned);
    assert_eq!(grant.run_count(), 100);
    assert_eq!(
        roles
            .object_segments(grant.identity(), 0, grant.byte_len(), true)
            .unwrap()
            .count(),
        100
    );
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn zeroing_by_ranges_inside_runs_zeroes_each_page_once_and_only_then_resolves() {
    let (mut roles, model) = small(2048);
    let mut sizes = std::vec![700, 300, 9, 3];
    sizes.extend([1; 20]);
    let _held = holes(&mut roles, &sizes);
    // 17 runs, and the root and three leaves from the holes left.
    let pages = 1025;
    let frames = chain_frames(&mut roles, model, pages);
    let allocation = roles.allocate_backing(pages).unwrap();
    assert!(allocation.indexed);
    let root = BackingIdentity(allocation.head);
    // Not yet zeroed: nobody resolves it, and it is not on demand.
    assert_eq!(resolve(&roles, root, 0), Err(FrameRoleError::WrongRole));
    assert!(roles.validate_object_range(root, 0, PAGE, false).is_err());
    assert!(!roles.is_on_demand(root));
    assert!(roles.release_index_step(root, 0, 4).is_err());

    let mut seen = Vec::new();
    let mut first = 0;
    for count in [5, 600, 1, 101, 2, 310, 1].iter().cycle() {
        if first == pages {
            break;
        }
        let count = (*count).min(pages - first);
        assert!(
            roles.zero_backing_pages(&allocation, first, count, &mut |page| {
                seen.push(page);
                true
            })
        );
        first += count;
    }
    assert_eq!(seen, frames, "each page once, in object order");
    assert!(!roles.zero_backing_pages(&allocation, pages - 1, 2, &mut |_| true));
    assert!(!roles.zero_backing_pages(&allocation, 3, 4, &mut |_| false));
    let grant = zeroed(&mut roles, allocation);
    for (page, frame) in frames.iter().enumerate() {
        assert_eq!(resolve(&roles, grant.identity(), page as u64), Ok(*frame));
    }
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_failed_zeroing_cancels_an_indexed_allocation_whole() {
    let (mut roles, _) = small(256);
    let _held = holes(&mut roles, &[1; 20]);
    let initial = roles.available_frames();
    let free = roles.allocator.boot_free_ranges().to_vec();
    let mut calls = 0;
    // SAFETY: the zeroing closure fails on its fifth page.
    #[allow(unsafe_code, reason = "the test's zeroing touches no memory")]
    let result = unsafe {
        roles.allocate_zeroed_backing(18, &mut |_| {
            calls += 1;
            calls != 5
        })
    };
    assert_eq!(result, Err(FrameRoleError::InitializationFailed));
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.allocator.boot_free_ranges(), free.as_slice());
    assert_eq!(roles.check_invariants(), Ok(()));
    // SAFETY: as above, zeroing every page.
    #[allow(unsafe_code, reason = "the test's zeroing touches no memory")]
    let grant = unsafe { roles.allocate_zeroed_backing(18, &mut |_| true) }.unwrap();
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
}

/// Releases `grant` in steps of `budget` entries, checking the manager
/// after each, and completes it. Returns the run pages freed and the step
/// ends, as (cursor, whether it lay inside a run).
fn release_in_steps<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    grant: ObjectBackingGrant,
    runs: &[(u64, u64)],
    budget: u64,
) -> (u64, Vec<u64>) {
    let backing = grant.identity();
    let pages = grant.byte_len() / PAGE;
    let mut cursor = 0;
    let mut freed_pages = 0;
    let mut ends = Vec::new();
    while cursor < pages {
        let before = roles.available_frames();
        let (next, freed, visited) = roles.release_index_step(backing, cursor, budget).unwrap();
        assert!(next > cursor, "a step makes progress");
        assert!(visited < budget + u64::from(INDEX_MAX_LEVELS));
        // What came back is the run pages counted and any nodes.
        let back = roles.available_frames() - before;
        assert!(back >= freed && back - freed <= u64::from(INDEX_MAX_LEVELS) * visited);
        assert_eq!(roles.check_invariants(), Ok(()));
        // A backing being freed resolves for nobody, its pages past the
        // cursor included.
        for page in [next, next + 1, pages - 1] {
            if (next..pages).contains(&page) {
                assert_eq!(
                    resolve(roles, backing, page),
                    Err(FrameRoleError::WrongRole),
                    "page {page}"
                );
            }
        }
        freed_pages += freed;
        cursor = next;
        ends.push(next);
    }
    let _ = runs;
    roles.cancel_object_backing(grant).unwrap();
    (freed_pages, ends)
}

#[test]
fn a_stepped_release_frees_every_run_and_node_across_runs_and_leaves() {
    // Runs of 700 pages (across a leaf boundary), 300 (inside a leaf),
    // smaller ones, and single pages in the last leaf.
    let mut sizes = std::vec![700, 300, 9, 3, 2];
    sizes.extend([1; 16]);
    // 17 runs, and the root and three leaves from the last four holes.
    let pages = 1026;
    for budget in [1, 2, 3, 7, 64, 4096] {
        let (mut roles, model) = small(2048);
        let _held = holes(&mut roles, &sizes);
        let initial = roles.available_frames();
        let free = roles.allocator.boot_free_ranges().to_vec();
        let runs = chain_runs(&mut roles, model, pages);
        assert_eq!(runs[0], (0, 700));
        assert_eq!(runs[1], (700, 300));
        let grant = backing(&mut roles, pages);
        assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
        let (freed, ends) = release_in_steps(&mut roles, grant, &runs, budget);
        assert_eq!(freed, pages, "budget {budget}: each run's pages once");
        assert_eq!(roles.available_frames(), initial);
        assert_eq!(roles.allocator.boot_free_ranges(), free.as_slice());
        assert_eq!(roles.check_invariants(), Ok(()));
        if budget <= 3 {
            let inside_run = |end: &u64| {
                runs.iter()
                    .any(|(first, n)| first < end && *end < first + n)
            };
            assert!(ends.iter().any(inside_run), "a step ended inside a run");
            assert!(
                ends.iter()
                    .any(|end| end % INDEX_FANOUT != 0 && *end < pages),
                "a step ended inside a leaf"
            );
        }
    }
}

#[test]
fn a_stepped_release_of_thousands_of_runs_on_the_buddy_allocator_returns_every_page() {
    let (mut roles, model, _held) = fragmented(2200);
    let initial = roles.available_frames();
    let blocks: Vec<_> = roles.allocator.free_blocks().collect();
    let pages = 2100;
    let runs = chain_runs(&mut roles, model, pages);
    let grant = backing(&mut roles, pages);
    let backing = grant.identity();
    let mut cursor = 0;
    let mut freed_pages = 0;
    while cursor < pages {
        let (next, freed, _) = roles.release_index_step(backing, cursor, 100).unwrap();
        freed_pages += freed;
        cursor = next;
    }
    assert_eq!(freed_pages, pages);
    assert_eq!(roles.check_invariants(), Ok(()));
    let _ = runs;
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.allocator.free_blocks().collect::<Vec<_>>(), blocks);
}

#[test]
fn every_on_demand_entry_point_refuses_an_eager_root() {
    let (mut roles, _) = small(256);
    let _held = holes(&mut roles, &[1; 20]);
    let allocation = roles.allocate_backing(18).unwrap();
    assert!(allocation.indexed);
    let allocated = BackingIdentity(allocation.head);
    let check = |roles: &mut Small, backing: BackingIdentity| {
        assert!(!roles.is_on_demand(backing));
        assert_eq!(
            roles.commit_on_demand_page(backing, 0),
            Err(FrameRoleError::WrongRole)
        );
        assert_eq!(
            roles.on_demand_commit_cost(backing, 0),
            Err(FrameRoleError::WrongRole)
        );
        assert_eq!(
            roles.on_demand_commit_range_cost(backing, 0, 1),
            Err(FrameRoleError::WrongRole)
        );
        assert_eq!(
            roles.on_demand_commit_range_cost(backing, 0, 0),
            Err(FrameRoleError::WrongRole)
        );
        assert_eq!(
            roles.decommit_on_demand_range(backing, 0, 18, 64),
            Err(FrameRoleError::WrongRole)
        );
        assert_eq!(
            roles.on_demand_frames(backing),
            Err(FrameRoleError::WrongRole)
        );
    };
    check(&mut roles, allocated);
    let grant = zeroed(&mut roles, allocation);
    check(&mut roles, grant.identity());
    // Nothing above changed it.
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();
}

#[test]
fn an_on_demand_root_still_refuses_a_multi_page_entry_an_eager_root_takes() {
    let (mut roles, model) = small(64);
    let grant = roles.allocate_on_demand_backing(8).unwrap();
    let root = grant.identity();
    // A two-page run claiming page 2 of the on-demand backing.
    let run = roles.allocate(2).unwrap();
    let slot = roles.slot(run.identity).unwrap();
    roles.replace_record(
        slot,
        RoleRecord {
            range: run.range,
            role: FrameRole::ObjectPage(IndexEntryLink {
                owner: root.0.raw,
                place: 2,
            }),
        },
    );
    #[allow(unsafe_code, reason = "the test owns the model's node")]
    // SAFETY: the model's root node, which the test owns.
    unsafe {
        model.write(grant.physical_start(), 2, run.identity.raw)
    };
    assert_eq!(resolve(&roles, root, 2), Err(FrameRoleError::WrongRole));
    assert_eq!(
        roles.commit_on_demand_page(root, 2),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    // Under the same root made eager, the run holds pages 2 and 3, and a
    // page of the root without an entry is refused, not absent.
    let (range, link) = roles.index_root(root.0, RootUse::Any).unwrap();
    roles.replace_record(
        roles.slot(root.0).unwrap(),
        RoleRecord {
            range,
            role: FrameRole::IndexRoot(IndexRootLink {
                state: IndexRootState::Eager,
                ..link
            }),
        },
    );
    assert_eq!(resolve(&roles, root, 2), Ok(run.range.start));
    assert_eq!(resolve(&roles, root, 3), Err(FrameRoleError::WrongRole));
    assert_eq!(resolve(&roles, root, 0), Err(FrameRoleError::WrongRole));
}

#[test]
fn a_gap_or_a_misplaced_entry_in_an_eager_index_fails_the_invariants() {
    let (mut roles, model) = small(256);
    let _held = holes(&mut roles, &[4; 20]);
    // 17 runs of four pages; the root is the leaf.
    let grant = backing(&mut roles, 68);
    assert_eq!(grant.run_count(), 17);
    assert_eq!(roles.check_invariants(), Ok(()));
    let root = grant.physical_start();
    let write = |entry: usize, value: u64| {
        #[allow(unsafe_code, reason = "the test owns the model's node")]
        // SAFETY: the model's root node, which the test owns.
        unsafe {
            model.write(root, entry, value)
        };
    };
    let first = model.read(root, 0);
    let second = model.read(root, 4);
    assert_ne!(first, second);
    // A gap inside a run, then between runs.
    for page in [5, 8] {
        let raw = model.read(root, page);
        write(page, 0);
        assert_eq!(
            roles.check_invariants(),
            Err(FrameRoleError::InvariantViolation),
            "page {page}"
        );
        assert_eq!(
            resolve(&roles, grant.identity(), page as u64),
            Err(FrameRoleError::WrongRole)
        );
        write(page, raw);
        assert_eq!(roles.check_invariants(), Ok(()));
    }
    // The first two entries of the first run cleared, as a release step
    // that ended inside the run would leave them: the run is still reached
    // from page 2, but an `Eager` root that no release has stepped must
    // start at page 0.
    let cleared: Vec<u64> = (0..2).map(|page| model.read(root, page)).collect();
    for page in 0..2 {
        write(page, 0);
    }
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    for (page, raw) in cleared.into_iter().enumerate() {
        write(page, raw);
    }
    assert_eq!(roles.check_invariants(), Ok(()));
    // A page naming a run before it, or after it, that does not hold it.
    let raw = model.read(root, 9);
    for wrong in [first, second, model.read(root, 12)] {
        write(9, wrong);
        assert_eq!(
            roles.check_invariants(),
            Err(FrameRoleError::InvariantViolation)
        );
        assert_eq!(
            resolve(&roles, grant.identity(), 9),
            Err(FrameRoleError::WrongRole)
        );
    }
    write(9, raw);
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();
}

#[test]
fn a_backing_being_freed_resolves_for_nobody_and_stays_whole_mid_release() {
    let (mut roles, model) = small(2048);
    let mut sizes = std::vec![700, 300, 9, 3, 2];
    sizes.extend([1; 16]);
    let _held = holes(&mut roles, &sizes);
    let initial = roles.available_frames();
    let pages = 1026;
    let grant = backing(&mut roles, pages);
    let backing = grant.identity();
    let _ = model;
    assert!(resolve(&roles, backing, 1000).is_ok());
    // One step: past the 700-page run's first leaf.
    let (cursor, _, _) = roles.release_index_step(backing, 0, 1).unwrap();
    assert_eq!(cursor, 512);
    assert_eq!(
        roles.role(backing.0),
        Ok(FrameRoleKind::ObjectBacking(
            ObjectBackingKind::AllocatorIndexed
        ))
    );
    for page in [cursor, 700, 1000, pages - 1] {
        assert_eq!(
            resolve(&roles, backing, page),
            Err(FrameRoleError::WrongRole),
            "page {page}"
        );
    }
    assert_eq!(
        roles.validate_object_range(backing, cursor * PAGE, PAGE, false),
        Err(FrameRoleError::WrongRole)
    );
    assert!(!roles.is_on_demand(backing));
    assert_eq!(
        roles.commit_on_demand_page(backing, cursor),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.on_demand_commit_cost(backing, cursor),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.on_demand_commit_range_cost(backing, cursor, 1),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.decommit_on_demand_range(backing, cursor, pages, 64),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.on_demand_frames(backing),
        Err(FrameRoleError::WrongRole)
    );
    // Its entries start past page 0 inside a run, and it is whole.
    assert_eq!(roles.check_invariants(), Ok(()));
    // Later steps take it; the final release frees the root.
    let mut cursor = cursor;
    while cursor < pages {
        cursor = roles.release_index_step(backing, cursor, 5).unwrap().0;
        assert_eq!(roles.check_invariants(), Ok(()));
    }
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_never_stepped_eager_backing_cancels_whole() {
    let (mut roles, _) = small(2048);
    let mut sizes = std::vec![700, 300, 9, 3, 2];
    sizes.extend([1; 16]);
    let _held = holes(&mut roles, &sizes);
    let initial = roles.available_frames();
    let free = roles.allocator.boot_free_ranges().to_vec();
    let grant = backing(&mut roles, 1026);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.allocator.boot_free_ranges(), free.as_slice());
    assert_eq!(roles.check_invariants(), Ok(()));
}

/// Releases a `pages`-page eager backing laid out as `runs` (first page,
/// pages) in steps of `budget`, checking each step's visits and cursor
/// against what it freed. Returns each step's (cursor, freed, visited).
fn release_counting<const R: usize, const S: usize>(
    roles: &mut FrameRoleManager<R, S>,
    grant: ObjectBackingGrant,
    runs: &[(u64, u64)],
    budget: u64,
) -> Vec<(u64, u64, u64)> {
    let backing = grant.identity();
    let pages = grant.byte_len() / PAGE;
    let mut cursor = 0;
    let mut released = 0;
    let mut steps = Vec::new();
    while cursor < pages {
        let (next, freed, visited) = roles.release_index_step(backing, cursor, budget).unwrap();
        assert!(next > cursor, "a step makes progress");
        if next < pages {
            assert!(
                visited >= budget,
                "budget {budget}: a step short of the end used its budget"
            );
        }
        assert!(visited < budget + u64::from(INDEX_MAX_LEVELS));
        released += freed;
        // The cursor is past only what was released, and the start of a
        // run still live across it.
        let live = runs
            .iter()
            .find(|(first, count)| *first < next && next < first + count);
        assert_eq!(
            released,
            live.map_or(next, |(first, _)| *first),
            "budget {budget}"
        );
        steps.push((next, freed, visited));
        cursor = next;
    }
    assert_eq!(released, pages);
    roles.cancel_object_backing(grant).unwrap();
    steps
}

#[test]
fn a_release_step_counts_a_visit_per_leaf_passed_and_freed_and_per_entry_cleared() {
    // Runs: 5,300 pages (leaves 0 to 9 whole, ending 180 pages into leaf
    // 10), 300 pages (inside leaf 10), then 16 one-page runs: 5,616 pages,
    // 18 runs, two levels with 11 leaves. Twelve more one-page holes hold
    // the root and the leaves.
    let mut sizes = std::vec![5300, 300];
    sizes.extend([1; 28]);
    let pages = 5616;
    for (budget, first) in [
        // 10 leaves passed (1 visit each) and freed by the cascade (1 each),
        // then the 180 entries of leaf 10 cleared (1 each) and the run
        // freed: 20 + 180 = 200 visits, exactly the budget.
        (200, (5300, 5300, 200)),
        // As above (200), then the 300-page run's entries cleared (300),
        // then 12 one-page runs (1 each) reach the budget: 512 visits,
        // cursor 5,612, 5,612 pages freed.
        (512, (5612, 5612, 512)),
        // Leaf 0 passed (1), its cascade (1), leaf 1 passed (1), its
        // cascade (1), leaf 2 passed (1): 5 visits, cursor at 1,536 and
        // the step ends after leaf 2's cascade (1), 6 visits, nothing freed.
        (5, (1536, 0, 6)),
    ] {
        let (mut roles, model) = small(8192);
        let _held = holes(&mut roles, &sizes);
        let initial = roles.available_frames();
        let runs = chain_runs(&mut roles, model, pages);
        assert_eq!(runs.len(), 18);
        assert_eq!(&runs[..2], &[(0, 5300), (5300, 300)]);
        let grant = backing(&mut roles, pages);
        assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
        let steps = release_counting(&mut roles, grant, &runs, budget);
        assert_eq!(steps[0], first, "budget {budget}");
        assert_eq!(roles.available_frames(), initial);
        assert_eq!(roles.check_invariants(), Ok(()));
    }
}
