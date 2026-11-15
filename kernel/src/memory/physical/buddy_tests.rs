//! The buddy allocator, driven through `PhysicalFrameAllocator` after
//! `adopt_buddy` (DW2 large-memory plan, M7 §12.2, tests 1 and 2).

extern crate std;

use super::*;
use std::{boxed::Box, vec, vec::Vec};

const PAGE: u64 = BASE_PAGE_SIZE;
type Allocator = PhysicalFrameAllocator<16>;

fn limit() -> PhysicalAddressLimit {
    PhysicalAddressLimit::new(1_u64 << 40).unwrap()
}

/// `count` pages from page `first`.
fn pages(first: u64, count: u64) -> PageRange {
    PageRange {
        start: first * PAGE,
        end: (first + count) * PAGE,
    }
}

/// A boot-phase allocator over `(first page, page count)` candidates.
fn boot(ranges: &[(u64, u64)]) -> Allocator {
    let candidates: Vec<_> = ranges
        .iter()
        .map(|(first, count)| pages(*first, *count))
        .collect();
    Allocator::from_candidates(&candidates, limit(), []).unwrap()
}

/// Leaked storage of the given lengths, filled with garbage `adopt_buddy`
/// must overwrite.
fn storage(tags: usize, links: usize, bases: usize) -> BuddyStorage {
    BuddyStorage {
        tags: Box::leak(vec![0xa5_u8; tags].into_boxed_slice()),
        links: Box::leak(vec![FreeLink { next: 7, prev: 9 }; links].into_boxed_slice()),
        bases: Box::leak(vec![u64::MAX; bases].into_boxed_slice()),
    }
}

fn storage_for(allocator: &Allocator) -> BuddyStorage {
    let frames = usize::try_from(allocator.initial_frames()).unwrap();
    storage(frames, frames, allocator.initial_range_count())
}

fn adopt(allocator: &mut Allocator) {
    let storage = storage_for(allocator);
    assert!(allocator.adopt_buddy(storage).is_ok());
    assert_eq!(allocator.check_buddy(), Ok(()));
}

fn adopted(ranges: &[(u64, u64)]) -> Allocator {
    let mut allocator = boot(ranges);
    adopt(&mut allocator);
    allocator
}

/// The free blocks as (first page, order), in address order.
fn blocks(allocator: &Allocator) -> Vec<(u64, u32)> {
    allocator
        .free_blocks()
        .map(|(start, order)| (start / PAGE, order))
        .collect()
}

fn page_list(range: PageRange) -> (u64, u64) {
    (range.start / PAGE, range.page_count())
}

#[test]
fn seeding_turns_unaligned_ranges_into_maximal_aligned_blocks() {
    let allocator = adopted(&[(3, 13), (37, 20)]);
    assert_eq!(
        blocks(&allocator),
        [
            (3, 0),
            (4, 2),
            (8, 3),
            (37, 0),
            (38, 1),
            (40, 3),
            (48, 3),
            (56, 0)
        ]
    );
    assert_eq!(allocator.available_frames(), 33);
    assert_eq!(allocator.largest_free_pages(), 8);
}

#[test]
fn seeding_takes_the_boot_free_list_not_the_initial_ranges() {
    let mut allocator = boot(&[(4, 12)]);
    let held = allocator.allocate_run(3).unwrap();
    assert_eq!(page_list(held), (4, 3));
    adopt(&mut allocator);
    assert_eq!(blocks(&allocator), [(7, 0), (8, 3)]);
    assert_eq!(allocator.available_frames(), 9);
    // What the boot phase handed out frees into the buddy allocator.
    allocator.free_run(held).unwrap();
    assert_eq!(blocks(&allocator), [(4, 2), (8, 3)]);
    assert_eq!(allocator.check_buddy(), Ok(()));
}

#[test]
fn adoption_refuses_wrong_storage_and_a_second_adoption() {
    let mut allocator = boot(&[(8, 8), (32, 16)]);
    let frames = 24;
    for (tags, links, bases) in [
        (frames - 1, frames, 2),
        (frames, frames + 1, 2),
        (frames + 1, frames + 1, 2),
        (frames, frames, 1),
        (frames, frames, 3),
    ] {
        assert!(allocator.adopt_buddy(storage(tags, links, bases)).is_err());
        assert_eq!(blocks(&allocator), []);
        assert_eq!(allocator.available_frames(), 24);
        // Still the boot phase: first fit.
        let run = allocator.allocate_run(1).unwrap();
        assert_eq!(page_list(run), (8, 1));
        allocator.free_run(run).unwrap();
    }
    adopt(&mut allocator);
    assert!(allocator.adopt_buddy(storage_for(&allocator)).is_err());
    assert_eq!(blocks(&allocator), [(8, 3), (32, 4)]);
}

#[test]
fn storage_is_refused_at_u32_max_pages() {
    let limit = PhysicalAddressLimit::new(1_u64 << 52).unwrap();
    let largest = u64::from(u32::MAX) - 1;
    for (count, accepted) in [(largest, true), (largest + 1, false)] {
        let candidate = PageRange::from_page_count(PAGE, count, limit).unwrap();
        let allocator = Allocator::from_candidates(&[candidate], limit, []).unwrap();
        let count = usize::try_from(count).unwrap();
        assert_eq!(allocator.accepts_buddy_storage(count, count, 1), accepted);
    }
}

#[test]
fn an_allocation_keeps_its_exact_length_and_returns_the_tail() {
    let mut allocator = adopted(&[(64, 64)]);
    assert_eq!(blocks(&allocator), [(64, 6)]);
    let run = allocator.allocate_run(5).unwrap();
    assert_eq!(page_list(run), (64, 5));
    assert_eq!(
        blocks(&allocator),
        [(69, 0), (70, 1), (72, 3), (80, 4), (96, 5)]
    );
    assert_eq!(allocator.available_frames(), 59);
    assert_eq!(allocator.largest_free_pages(), 32);
    assert_eq!(allocator.check_buddy(), Ok(()));

    // The smallest sufficient block: 3 pages come from the 8-page block.
    let small = allocator.allocate_run(3).unwrap();
    assert_eq!(page_list(small), (72, 3));
    assert_eq!(
        blocks(&allocator),
        [(69, 0), (70, 1), (75, 0), (76, 2), (80, 4), (96, 5)]
    );
    assert_eq!(allocator.available_frames(), 56);
    assert_eq!(allocator.check_buddy(), Ok(()));

    allocator.free_run(run).unwrap();
    allocator.free_run(small).unwrap();
    assert_eq!(blocks(&allocator), [(64, 6)]);
    assert_eq!(allocator.available_frames(), 64);
    assert_eq!(allocator.largest_free_pages(), 64);
    assert_eq!(allocator.check_buddy(), Ok(()));
}

#[test]
fn freeing_everything_in_another_order_restores_the_seeded_blocks() {
    let mut allocator = adopted(&[(3, 61), (100, 77), (300, 40)]);
    let seeded = blocks(&allocator);
    let total = allocator.available_frames();
    let sizes = [1, 3, 7, 2, 5, 16, 1, 9, 4];
    let mut runs = Vec::new();
    for size in sizes.iter().cycle() {
        match allocator.allocate_run(*size) {
            Ok(run) => runs.push(run),
            Err(PhysicalMemoryError::NoFramesAvailable) if *size == 1 => break,
            Err(error) => assert_eq!(error, PhysicalMemoryError::NoFramesAvailable),
        }
        assert_eq!(allocator.check_buddy(), Ok(()));
    }
    assert_eq!(allocator.available_frames(), 0);
    let held: u64 = runs.iter().map(|run| run.page_count()).sum();
    assert_eq!(held, total);
    // Odd positions first, then even ones backwards.
    let mut order: Vec<_> = (1..runs.len()).step_by(2).collect();
    order.extend((0..runs.len()).step_by(2).rev());
    for index in order {
        allocator.free_run(runs[index]).unwrap();
        assert_eq!(allocator.check_buddy(), Ok(()));
    }
    assert_eq!(blocks(&allocator), seeded);
    assert_eq!(allocator.available_frames(), total);
}

#[test]
fn double_frees_are_refused_and_change_nothing() {
    let mut allocator = adopted(&[(64, 64)]);
    let whole = allocator.allocate_run(64).unwrap();
    assert_eq!(page_list(whole), (64, 64));
    allocator.free_run(pages(72, 4)).unwrap();
    assert_eq!(blocks(&allocator), [(72, 2)]);
    for (first, count) in [
        // The same block again.
        (72, 4),
        // A page inside a free block.
        (73, 1),
        (74, 2),
        // A range containing a free block.
        (70, 10),
        (64, 64),
        // A range ending inside a free block.
        (70, 3),
    ] {
        assert_eq!(
            allocator.free_run(pages(first, count)),
            Err(PhysicalMemoryError::DoubleFree),
            "pages {first}..+{count}"
        );
        assert_eq!(blocks(&allocator), [(72, 2)]);
        assert_eq!(allocator.available_frames(), 4);
        assert_eq!(allocator.check_buddy(), Ok(()));
        assert!(allocator.overlaps_free(pages(first, count)));
    }
    assert!(!allocator.overlaps_free(pages(64, 8)));
    assert!(!allocator.overlaps_free(pages(76, 52)));
    allocator.free_run(pages(64, 8)).unwrap();
    allocator.free_run(pages(76, 52)).unwrap();
    assert_eq!(blocks(&allocator), [(64, 6)]);
}

#[test]
fn frees_outside_or_across_initial_ranges_are_invalid_frames() {
    let mut allocator = adopted(&[(16, 16), (40, 8)]);
    let first = allocator.allocate_run(16).unwrap();
    let second = allocator.allocate_run(8).unwrap();
    assert_eq!(page_list(first), (16, 16));
    assert_eq!(page_list(second), (40, 8));
    for (start, count) in [(10, 2), (30, 12), (32, 8), (47, 2), (48, 1), (0, 1)] {
        assert_eq!(
            allocator.free_run(pages(start, count)),
            Err(PhysicalMemoryError::InvalidFrame),
            "pages {start}..+{count}"
        );
    }
    assert_eq!(
        allocator.free_run(PageRange {
            start: 16 * PAGE,
            end: 16 * PAGE + 1
        }),
        Err(PhysicalMemoryError::InvalidPageRange)
    );
    assert_eq!(
        allocator.free_run(pages(1 << 28, 1)),
        Err(PhysicalMemoryError::OutsidePhysicalLimit)
    );
    assert_eq!(allocator.available_frames(), 0);
    assert_eq!(blocks(&allocator), []);
    assert_eq!(allocator.check_buddy(), Ok(()));
}

#[test]
fn blocks_never_merge_across_initial_ranges() {
    // Page 20 is the position after page 11: a merge that ignored the
    // range would pair the block at 8 with the one at 20.
    let mut allocator = adopted(&[(8, 4), (20, 4)]);
    assert_eq!(blocks(&allocator), [(8, 2), (20, 2)]);
    let one = allocator.allocate_run(4).unwrap();
    let other = allocator.allocate_run(4).unwrap();
    let (low, high) = if one.start < other.start {
        (one, other)
    } else {
        (other, one)
    };
    allocator.free_run(high).unwrap();
    allocator.free_run(low).unwrap();
    assert_eq!(blocks(&allocator), [(8, 2), (20, 2)]);
    assert_eq!(allocator.largest_free_pages(), 4);
    assert_eq!(allocator.check_buddy(), Ok(()));
    assert_eq!(
        allocator.allocate_run(8),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
}

#[test]
fn an_allocation_below_a_ceiling_takes_a_head_first_then_scans() {
    // The head of order 4 is the block at 32, the last seeded.
    let mut allocator = adopted(&[(16, 32)]);
    assert_eq!(blocks(&allocator), [(16, 4), (32, 4)]);
    let run = allocator.allocate_run_below(2, 40 * PAGE).unwrap();
    assert_eq!(page_list(run), (32, 2));
    assert_eq!(allocator.check_buddy(), Ok(()));

    // The head is above the ceiling; the scan finds the block at 16.
    let mut allocator = adopted(&[(16, 32)]);
    let run = allocator.allocate_run_below(4, 24 * PAGE).unwrap();
    assert_eq!(page_list(run), (16, 4));
    assert_eq!(blocks(&allocator), [(20, 2), (24, 3), (32, 4)]);
    assert_eq!(allocator.available_frames(), 28);
    assert_eq!(allocator.check_buddy(), Ok(()));

    // Below 22 only a block of 2 pages is free: 3 pages are refused, with
    // nothing changed. A non-page-aligned ceiling keeps whole pages below.
    for (count, ceiling) in [(3, 22 * PAGE), (2, 22 * PAGE - 1), (1, 16 * PAGE)] {
        let before = blocks(&allocator);
        assert_eq!(
            allocator.allocate_run_below(count, ceiling),
            Err(PhysicalMemoryError::NoFramesAvailable)
        );
        assert_eq!(blocks(&allocator), before);
        assert_eq!(allocator.available_frames(), 28);
        assert_eq!(allocator.check_buddy(), Ok(()));
    }
    let run = allocator.allocate_run_below(2, 22 * PAGE).unwrap();
    assert_eq!(page_list(run), (20, 2));
    // A ceiling above the physical limit is bounded by it.
    let run = allocator.allocate_run_below(1, u64::MAX).unwrap();
    assert!(run.end <= limit().exclusive());
    assert_eq!(allocator.check_buddy(), Ok(()));
}

#[test]
fn single_pages_exhaust_exactly_the_initial_frames() {
    let mut allocator = adopted(&[(3, 100), (200, 57), (400, 33)]);
    let mut count = 0_u64;
    while allocator.allocate_run(1).is_ok() {
        count += 1;
    }
    assert_eq!(count, allocator.initial_frames());
    assert_eq!(allocator.available_frames(), 0);
    assert_eq!(allocator.largest_free_pages(), 0);
    assert_eq!(
        allocator.allocate_run(1),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
    assert_eq!(
        allocator.allocate_run_below(1, u64::MAX),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
    assert_eq!(allocator.check_buddy(), Ok(()));
}

#[test]
fn page_positions_are_the_same_before_and_after_adoption() {
    let ranges = [(3, 100), (200, 57), (400, 33)];
    let before = boot(&ranges);
    let after = adopted(&ranges);
    let mut addresses = vec![0, PAGE, 2 * PAGE, u64::MAX, 1 << 40];
    for (first, count) in ranges {
        for page in [
            first - 1,
            first,
            first + 1,
            first + count - 1,
            first + count,
        ] {
            addresses.push(page * PAGE);
            addresses.push(page * PAGE + 123);
        }
    }
    for address in addresses {
        assert_eq!(
            before.page_position(address),
            after.page_position(address),
            "address {address:#x}"
        );
    }
    assert_eq!(after.page_position(3 * PAGE), Some(0));
    assert_eq!(after.page_position(200 * PAGE), Some(100));
    assert_eq!(after.page_position(432 * PAGE + 5), Some(189));
    assert_eq!(after.page_position(433 * PAGE), None);
}

/// A fixed-seed linear congruential generator (Knuth's MMIX constants).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Which pages are free, by page number, and which initial range each page
/// belongs to.
struct Model {
    free: Vec<bool>,
    ranges: Vec<(u64, u64)>,
}

impl Model {
    fn free_pages(&self) -> u64 {
        self.free.iter().filter(|free| **free).count() as u64
    }

    fn block_free(&self, first: u64, order: u32) -> bool {
        (first..first + (1 << order)).all(|page| self.free[page as usize])
    }

    /// Aligned blocks of 2^`order` pages, inside one initial range, all free.
    fn free_aligned(&self, order: u32) -> impl Iterator<Item = u64> + '_ {
        self.ranges.iter().flat_map(move |(first, count)| {
            let size = 1_u64 << order;
            let start = first.next_multiple_of(size);
            (start..)
                .step_by(size as usize)
                .take_while(move |page| page + size <= first + count)
                .filter(move |page| self.block_free(*page, order))
        })
    }

    /// The largest aligned free block inside one initial range, from each
    /// maximal free interval.
    fn largest_aligned(&self) -> u64 {
        let mut largest = 0;
        for (first, count) in &self.ranges {
            let end = first + count;
            let mut page = *first;
            while page < end {
                if !self.free[page as usize] {
                    page += 1;
                    continue;
                }
                let start = page;
                while page < end && self.free[page as usize] {
                    page += 1;
                }
                let fits = (0..=12)
                    .rev()
                    .map(|order| 1_u64 << order)
                    .find(|size| start.next_multiple_of(*size) + size <= page)
                    .unwrap_or(0);
                largest = largest.max(fits);
            }
        }
        largest
    }

    fn set(&mut self, run: PageRange, free: bool) {
        for page in run.start / PAGE..run.end / PAGE {
            assert_ne!(self.free[page as usize], free, "page {page}");
            self.free[page as usize] = free;
        }
    }

    fn inside_one_range(&self, run: PageRange) -> bool {
        self.ranges
            .iter()
            .any(|(first, count)| pages(*first, *count).contains(run))
    }
}

#[test]
fn a_model_of_mixed_allocations_and_frees_agrees_with_the_buddy_allocator() {
    let ranges = [(3, 1500), (2053, 2500), (8192, 1800)];
    let mut allocator = adopted(&ranges);
    let mut model = Model {
        free: vec![false; 10_000],
        ranges: ranges.to_vec(),
    };
    for (first, count) in ranges {
        model.set(pages(first, count), true);
    }
    let mut random = Lcg(0x05ee_d0dd_5b0d_d1e5);
    let mut live: Vec<PageRange> = Vec::new();
    let (mut allocated, mut refused, mut freed) = (0, 0, 0);
    for step in 0..4000 {
        let choice = random.below(100);
        if choice < 55 || live.is_empty() {
            let count = match random.below(10) {
                0 => 1 + random.below(400),
                1..=3 => 1 + random.below(40),
                _ => 1 + random.below(4),
            };
            let below = (45..55).contains(&choice);
            let ceiling = (random.below(10_000) + 1) * PAGE - random.below(2) * 7;
            let result = if below {
                allocator.allocate_run_below(count, ceiling)
            } else {
                allocator.allocate_run(count)
            };
            match result {
                Ok(run) => {
                    assert_eq!(run.page_count(), count, "step {step}");
                    assert!(model.inside_one_range(run), "step {step}");
                    assert!(!below || run.end <= ceiling, "step {step}");
                    // No returned run overlaps a live one: every page was free.
                    model.set(run, false);
                    live.push(run);
                    allocated += 1;
                }
                Err(error) => {
                    assert_eq!(error, PhysicalMemoryError::NoFramesAvailable);
                    let order = count.next_power_of_two().trailing_zeros();
                    let found = model
                        .free_aligned(order)
                        .find(|first| !below || (first + count) * PAGE <= ceiling);
                    assert_eq!(found, None, "step {step}: a free block was missed");
                    refused += 1;
                }
            }
        } else if choice < 92 {
            let index = random.below(live.len() as u64) as usize;
            let run = live.swap_remove(index);
            allocator.free_run(run).unwrap();
            model.set(run, true);
            freed += 1;
        } else {
            // A free overlapping a free page is refused and changes nothing.
            let free_pages: Vec<u64> = (0..model.free.len() as u64)
                .filter(|page| model.free[*page as usize])
                .collect();
            if let Some(page) =
                free_pages.get(random.below(free_pages.len().max(1) as u64) as usize)
            {
                let before = blocks(&allocator);
                let run = pages(*page, 1);
                assert_eq!(
                    allocator.free_run(run),
                    Err(PhysicalMemoryError::DoubleFree)
                );
                assert_eq!(blocks(&allocator), before);
            }
        }
        assert_eq!(allocator.check_buddy(), Ok(()), "step {step}");
        assert_eq!(
            allocator.available_frames(),
            model.free_pages(),
            "step {step}"
        );
        assert_eq!(
            allocator.largest_free_pages(),
            model.largest_aligned(),
            "step {step}"
        );
    }
    assert!(allocated > 1000 && refused > 10 && freed > 1000);
    for run in live {
        allocator.free_run(run).unwrap();
    }
    assert_eq!(allocator.available_frames(), allocator.initial_frames());
    assert_eq!(allocator.check_buddy(), Ok(()));
}
