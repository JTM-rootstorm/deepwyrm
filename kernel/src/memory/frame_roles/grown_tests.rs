//! Chains and on-demand indexes on a grown manager, whose allocator is the
//! buddy allocator (DW2 large-memory plan, M7 §12.2, test 4). Every
//! assertion holds for either allocator: none depends on which frames come
//! first.

extern crate std;

use super::super::physical::PhysicalAddressLimit;
use super::*;
use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::vec::Vec;

const PAGE: u64 = BASE_PAGE_SIZE;
const THREE_LEVELS: u64 = 512 * 512 + 1;
type Manager = FrameRoleManager<8, 64>;

/// Index memory that zeroes on request and never fails.
#[derive(Default)]
struct Model {
    entries: Mutex<BTreeMap<(u64, usize), u64>>,
}

impl IndexMemory for Model {
    fn read(&self, node: u64, entry: usize) -> u64 {
        self.entries
            .lock()
            .unwrap()
            .get(&(node, entry))
            .copied()
            .unwrap_or(0)
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
        true
    }
}

/// A manager over three initial ranges, grown from three staged runs in a
/// leaked buffer, with index memory set.
fn grown() -> Manager {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidates = [
        PageRange::from_page_count(3 * PAGE, 700, limit).unwrap(),
        PageRange::from_page_count(1029 * PAGE, 1000, limit).unwrap(),
        PageRange::from_page_count(4096 * PAGE, 600, limit).unwrap(),
    ];
    let allocator = PhysicalFrameAllocator::from_candidates(&candidates, limit, []).unwrap();
    let mut roles = Manager::new(allocator).unwrap();
    let (_, runs) = test_support::grow_in_leaked_runs(&mut roles, 3);
    assert_eq!(runs.len(), 3);
    let model: &'static Model = Box::leak(Box::default());
    roles.set_index_memory(model);
    assert_eq!(roles.check_invariants(), Ok(()));
    roles
}

#[allow(
    unsafe_code,
    reason = "the host model never dereferences synthetic physical memory"
)]
fn backing(roles: &mut Manager, page_count: u64) -> ObjectBackingGrant {
    let allocation = roles.allocate_backing(page_count).unwrap();
    // SAFETY: the host model never dereferences the synthetic runs.
    unsafe { roles.assume_backing_zeroed(allocation) }.unwrap()
}

fn free_blocks(roles: &Manager) -> Vec<(u64, u32)> {
    roles.allocator.free_blocks().collect()
}

fn in_allocator_ram(roles: &Manager, physical: u64) -> bool {
    roles
        .allocator_ranges()
        .any(|range| range.contains(physical) && range.contains(physical + PAGE - 1))
}

/// Leaves every other single page free, so no free piece is longer than a
/// page, and returns the pages held.
fn fragment(roles: &mut Manager) -> Vec<AllocationGrant> {
    let mut pages = Vec::new();
    while let Ok(grant) = roles.allocate(1) {
        pages.push(grant);
    }
    pages.sort_by_key(|grant| grant.physical_start());
    let mut held = Vec::new();
    for (index, grant) in pages.into_iter().enumerate() {
        if index % 2 == 0 {
            roles.cancel_allocation(grant).unwrap();
        } else {
            held.push(grant);
        }
    }
    held
}

#[test]
fn a_grown_backing_resolves_every_page_to_distinct_allocator_frames_and_cancels_whole() {
    let mut roles = grown();
    let before = roles.available_frames();
    let blocks = free_blocks(&roles);
    // A run held elsewhere splits the free memory first.
    let held = roles.allocate(37).unwrap();
    let grant = backing(&mut roles, 300);
    assert_eq!(roles.available_frames(), before - 37 - 300);
    assert_eq!(roles.check_invariants(), Ok(()));

    let mut cursor = BackingCursor::new(grant.identity());
    let mut frames = BTreeSet::new();
    for page in 0..300 {
        let resolved = roles.resolve_at(&mut cursor, page * PAGE, true).unwrap();
        assert_eq!(resolved.byte_len, PAGE);
        assert!(in_allocator_ram(&roles, resolved.physical_start));
        assert!(!held.range.overlaps(PageRange {
            start: resolved.physical_start,
            end: resolved.physical_start + PAGE,
        }));
        assert!(frames.insert(resolved.physical_start), "page {page}");
    }
    assert_eq!(
        roles.resolve_at(&mut cursor, 300 * PAGE, false).err(),
        Some(FrameRoleError::WrongRole)
    );

    roles.cancel_object_backing(grant).unwrap();
    roles.cancel_allocation(held).unwrap();
    assert_eq!(roles.available_frames(), before);
    assert_eq!(free_blocks(&roles), blocks);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_request_larger_than_the_largest_free_block_takes_runs_that_never_grow() {
    let mut roles = grown();
    let before = roles.available_frames();
    let blocks = free_blocks(&roles);
    let largest = roles.largest_free_pages();
    let wanted = largest + largest / 2 + 3;
    assert!(wanted < before);
    let grant = backing(&mut roles, wanted);
    assert!(grant.run_count() >= 2);
    assert_eq!(grant.byte_len(), wanted * PAGE);
    let pieces: Vec<_> = roles
        .object_segments(grant.identity(), 0, grant.byte_len(), true)
        .unwrap()
        .collect();
    assert_eq!(pieces.len() as u64, grant.run_count());
    let mut offset = 0;
    for pair in pieces.windows(2) {
        assert!(pair[1].byte_len <= pair[0].byte_len, "{pieces:?}");
    }
    for piece in &pieces {
        assert_eq!(piece.object_offset, offset);
        assert!(piece.byte_len <= largest * PAGE);
        offset += piece.byte_len;
    }
    assert_eq!(offset, wanted * PAGE);
    assert_eq!(roles.available_frames(), before - wanted);
    assert_eq!(roles.check_invariants(), Ok(()));

    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), before);
    assert_eq!(free_blocks(&roles), blocks);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn running_out_of_memory_mid_backing_frees_every_run_taken() {
    let mut roles = grown();
    let held = fragment(&mut roles);
    let before = roles.available_frames();
    let blocks = free_blocks(&roles);
    assert_eq!(roles.largest_free_pages(), 1);
    assert_eq!(roles.check_invariants(), Ok(()));
    assert_eq!(
        roles.allocate_backing(before + 1),
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::NoFramesAvailable
        ))
    );
    assert_eq!(roles.available_frames(), before);
    assert_eq!(free_blocks(&roles), blocks);
    assert_eq!(roles.check_invariants(), Ok(()));

    // Held as an index (more than 16 runs), the same memory has no room
    // for its nodes: the allocation fails and frees all it took (DW2
    // §12.10 part 2 item 4).
    assert_eq!(
        roles.allocate_backing(before),
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::NoFramesAvailable
        ))
    );
    assert_eq!(roles.available_frames(), before);
    assert_eq!(free_blocks(&roles), blocks);
    assert_eq!(roles.check_invariants(), Ok(()));

    // Without index memory, the same memory is still usable whole, one
    // page per run.
    roles.index_memory = None;
    let grant = backing(&mut roles, before);
    assert_eq!(grant.run_count(), before);
    assert_eq!(roles.available_frames(), 0);
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();
    for grant in held {
        roles.cancel_allocation(grant).unwrap();
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn an_on_demand_backing_commits_scattered_pages_and_a_stepped_release_returns_them() {
    let mut roles = grown();
    let initial = roles.available_frames();
    let blocks = free_blocks(&roles);
    let grant = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    let backing = grant.identity();
    let committed = [
        0,
        1,
        511,
        513,
        4000,
        100_000,
        512 * 512 - 1,
        THREE_LEVELS - 1,
    ];
    for page in committed {
        roles.commit_on_demand_page(backing, page).unwrap();
        assert_eq!(roles.check_invariants(), Ok(()));
    }
    let mut frames: BTreeSet<u64> = BTreeSet::new();
    for page in committed {
        let physical = roles
            .resolve_object_page(backing, page * PAGE, true)
            .unwrap()
            .physical_start;
        assert!(in_allocator_ram(&roles, physical));
        assert!(frames.insert(physical), "page {page}");
    }
    let held = roles.on_demand_frames(backing).unwrap();
    assert_eq!(roles.available_frames(), initial - held);

    let pages = grant.byte_len() / PAGE;
    let mut cursor = 0;
    while cursor < pages {
        let before = roles.available_frames();
        let (next, freed, _) = roles.release_index_step(backing, cursor, 3).unwrap();
        assert!(next > cursor, "a step makes progress");
        assert_eq!(roles.available_frames(), before + freed);
        assert_eq!(roles.check_invariants(), Ok(()));
        cursor = next;
    }
    assert_eq!(
        roles.on_demand_frames(backing),
        Ok(1),
        "only the root is left"
    );
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(free_blocks(&roles), blocks);
    assert_eq!(roles.check_invariants(), Ok(()));
}
