use super::*;

const LIMIT: PhysicalAddressLimit = PhysicalAddressLimit {
    exclusive: 0x20_000,
};

fn range(start: u64, len: u64) -> PhysicalRange {
    PhysicalRange::new(start, len).unwrap()
}

#[test]
fn page_cover_checks_overflow_and_limit() {
    assert_eq!(
        PageRange::cover(range(0x1fff, 2), LIMIT),
        Ok(PageRange {
            start: 0x1000,
            end: 0x3000
        })
    );
    assert_eq!(
        PageRange::cover(range(0x1f_fff, 2), LIMIT),
        Err(PhysicalMemoryError::OutsidePhysicalLimit)
    );
    assert_eq!(
        PhysicalRange::new(u64::MAX, 1),
        Err(PhysicalRangeError::AddressOverflow)
    );
    assert_eq!(
        PhysicalAddressLimit::from_address_bits(40),
        Ok(PhysicalAddressLimit::new(1_u64 << 40).unwrap())
    );
    assert_eq!(
        PhysicalAddressLimit::from_address_bits(53),
        Err(PhysicalRangeError::InvalidAddressLimit)
    );
    assert_eq!(
        PhysicalAddressLimit::new(0x3000),
        Err(PhysicalRangeError::InvalidAddressLimit)
    );
}

#[test]
fn allocator_reserves_page_zero_and_rejects_invalid_frees() {
    let candidates = [PageRange {
        start: 0,
        end: 0x10_000,
    }];
    let mut allocator =
        PhysicalFrameAllocator::<4>::from_candidates(&candidates, LIMIT, [range(0x3000, 0x1000)])
            .unwrap();
    assert_eq!(allocator.available_frames(), 14);

    let frame = allocator.allocate_frame().unwrap();
    assert_eq!(frame.physical_start(), 0x1000);
    assert_eq!(allocator.free_frame(frame), Ok(()));
    assert_eq!(
        allocator.free_frame(frame),
        Err(PhysicalMemoryError::DoubleFree)
    );
    assert_eq!(
        allocator.free_frame(PhysicalFrame {
            physical_start: 0x3000
        }),
        Err(PhysicalMemoryError::InvalidFrame)
    );
}

#[test]
fn allocator_repeatedly_reports_oom_after_exhaustion() {
    let candidates = [PageRange {
        start: 0x1000,
        end: 0x2000,
    }];
    let mut allocator =
        PhysicalFrameAllocator::<1>::from_candidates(&candidates, LIMIT, []).unwrap();
    assert_eq!(allocator.allocate_frame().unwrap().physical_start(), 0x1000);
    assert_eq!(
        allocator.allocate_frame(),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
    assert_eq!(
        allocator.allocate_frame(),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
}

#[test]
fn low_ceiling_allocation_is_lowest_fit_and_never_crosses_the_ceiling() {
    let limit = PhysicalAddressLimit::new(1_u64 << 24).unwrap();
    let candidates = [
        PageRange {
            start: 0,
            end: 0x5000,
        },
        PageRange {
            start: 0x9000,
            end: 0x14_000,
        },
    ];
    let mut allocator =
        PhysicalFrameAllocator::<2>::from_candidates(&candidates, limit, []).unwrap();

    // Page zero is reserved, so this demonstrates that a low-memory caller
    // gets a nonzero page without assuming a fixed address.
    let first = allocator.allocate_run_below(2, 0x10_0000).unwrap();
    assert_eq!(
        first,
        PageRange {
            start: 0x1000,
            end: 0x3000
        }
    );
    assert!(first.end <= 0x10_0000);

    // The remaining low fragment is too short. The later range wins only
    // after the earlier candidate cannot satisfy the requested run.
    let second = allocator.allocate_run_below(3, 0x11_000).unwrap();
    assert_eq!(
        second,
        PageRange {
            start: 0x9000,
            end: 0xc000
        }
    );
    assert!(second.end <= 0x11_000);
}

#[test]
fn low_ceiling_rejection_is_failure_atomic_for_fragmented_ranges() {
    let limit = PhysicalAddressLimit::new(1_u64 << 24).unwrap();
    let candidates = [
        PageRange {
            start: 0x1000,
            end: 0x3000,
        },
        PageRange {
            start: 0x5000,
            end: 0x8000,
        },
    ];
    let mut allocator =
        PhysicalFrameAllocator::<2>::from_candidates(&candidates, limit, []).unwrap();
    let available = allocator.available_frames();

    assert_eq!(
        allocator.allocate_run_below(2, 0x2000),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
    assert_eq!(allocator.available_frames(), available);

    // A non-page-aligned ceiling cannot permit a page which would cross it.
    assert_eq!(
        allocator.allocate_run_below(1, 0x1fff),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
    assert_eq!(allocator.available_frames(), available);

    // The rejected requests did not disturb the original lowest-fit result.
    assert_eq!(
        allocator.allocate_run(1),
        Ok(PageRange {
            start: 0x1000,
            end: 0x2000,
        })
    );
}

#[test]
fn allocator_rejects_invalid_candidate_ranges() {
    for candidate in [
        PageRange {
            start: 0x3000,
            end: 0x2000,
        },
        PageRange {
            start: 1,
            end: 0x1000,
        },
        PageRange {
            start: 0x1000,
            end: 0x1001,
        },
    ] {
        assert!(matches!(
            PhysicalFrameAllocator::<1>::from_candidates(&[candidate], LIMIT, []),
            Err(PhysicalMemoryError::InvalidPageRange)
        ));
    }
    let at_limit = [PageRange {
        start: LIMIT.exclusive(),
        end: LIMIT.exclusive(),
    }];
    assert!(matches!(
        PhysicalFrameAllocator::<1>::from_candidates(&at_limit, LIMIT, []),
        Err(PhysicalMemoryError::InvalidPageRange)
    ));
    let outside = [PageRange {
        start: LIMIT.exclusive() - BASE_PAGE_SIZE,
        end: LIMIT.exclusive() + BASE_PAGE_SIZE,
    }];
    assert!(matches!(
        PhysicalFrameAllocator::<1>::from_candidates(&outside, LIMIT, []),
        Err(PhysicalMemoryError::OutsidePhysicalLimit)
    ));
}

/// Fills a range with `runs` single-frame runs and frees every other one,
/// leaving `runs / 2` live runs each followed by a hole, plus the free tail:
/// one free range more than the live runs, the worst case.
fn fragment<const RANGE_CAPACITY: usize>(
    allocator: &mut PhysicalFrameAllocator<RANGE_CAPACITY>,
    runs: usize,
) -> Result<(), PhysicalMemoryError> {
    let mut frames = [PhysicalFrame { physical_start: 0 }; 16];
    for frame in frames.iter_mut().take(runs) {
        *frame = allocator.allocate_frame()?;
    }
    for frame in frames.iter().take(runs).step_by(2) {
        allocator.free_frame(*frame)?;
    }
    Ok(())
}

#[test]
fn the_free_range_bound_holds_at_its_worst_case() {
    // One candidate, no reservations, four live runs: at most five ranges.
    let candidates = [PageRange {
        start: 0x1000,
        end: 0x10_000,
    }];
    const BOUND: usize = free_range_bound(1, 0, 4);
    let mut allocator =
        PhysicalFrameAllocator::<BOUND>::from_candidates(&candidates, LIMIT, []).unwrap();
    assert_eq!(fragment(&mut allocator, 8), Ok(()));
    assert_eq!(allocator.free_len, BOUND);
    assert_eq!(allocator.available_frames(), 15 - 4);

    // One range slot fewer, and the last free of the same pattern is refused.
    let mut short =
        PhysicalFrameAllocator::<{ BOUND - 1 }>::from_candidates(&candidates, LIMIT, []).unwrap();
    assert_eq!(
        fragment(&mut short, 8),
        Err(PhysicalMemoryError::CapacityExceeded)
    );
}

#[test]
fn the_free_range_bound_counts_reservations_that_split_ranges() {
    // Two candidates, each split by a reservation strictly inside it, and
    // page zero trimmed from the first without splitting it.
    let candidates = [
        PageRange {
            start: 0,
            end: 0x8000,
        },
        PageRange {
            start: 0x10_000,
            end: 0x18_000,
        },
    ];
    let reservations = [range(0x3000, 0x1000), range(0x13_000, 0x1000)];
    const BOUND: usize = free_range_bound(2, 2, 0);
    let allocator =
        PhysicalFrameAllocator::<BOUND>::from_candidates(&candidates, LIMIT, reservations).unwrap();
    assert_eq!(allocator.initial_len, BOUND);
    assert_eq!(allocator.available_frames(), 7 + 8 - 2);
    assert!(matches!(
        PhysicalFrameAllocator::<{ BOUND - 1 }>::from_candidates(&candidates, LIMIT, reservations),
        Err(PhysicalMemoryError::CapacityExceeded)
    ));
}

mod aligned {
    //! The boot phase's aligned allocation (DW2 M7 §12.9 item 3).

    extern crate std;

    use super::*;
    use std::{boxed::Box, vec, vec::Vec};

    const PAGE: u64 = BASE_PAGE_SIZE;
    type Allocator = PhysicalFrameAllocator<64>;

    fn limit() -> PhysicalAddressLimit {
        PhysicalAddressLimit::new(1_u64 << 40).unwrap()
    }

    /// A fixed-seed xorshift generator.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    /// Up to eight disjoint candidate ranges at random page offsets and
    /// lengths, some with 2 MiB-aligned interiors.
    fn generated_map(rng: &mut Rng) -> Allocator {
        let mut candidates = Vec::new();
        let mut next = 1 + rng.below(600);
        for _ in 0..1 + rng.below(8) {
            let longest = if rng.below(3) == 0 { 2600 } else { 700 };
            let pages = 1 + rng.below(longest);
            candidates.push(PageRange {
                start: next * PAGE,
                end: (next + pages) * PAGE,
            });
            next += pages + 1 + rng.below(900);
        }
        PhysicalFrameAllocator::from_candidates(&candidates, limit(), []).unwrap()
    }

    /// The longest aligned interior of any free range, in pages, rounded
    /// down to a multiple of `align`: what the allocation must take from.
    fn longest_aligned(allocator: &Allocator, align: u64) -> u64 {
        allocator
            .boot_free_ranges()
            .iter()
            .map(|range| {
                let start = range.start.next_multiple_of(align * PAGE);
                range.end.saturating_sub(start) / PAGE / align * align
            })
            .max()
            .unwrap_or(0)
    }

    /// The boot free list is sorted, disjoint, non-empty and inside the
    /// initial ranges, and no free range touches a live run.
    fn check(allocator: &Allocator, live: &[PageRange]) {
        let free = allocator.boot_free_ranges();
        for pair in free.windows(2) {
            assert!(pair[0].end < pair[1].start, "{pair:?}");
        }
        for range in free {
            assert!(range.start < range.end);
            assert!(allocator.contains_initial(*range));
            assert!(live.iter().all(|run| !run.overlaps(*range)));
        }
        for run in live {
            assert!(allocator.contains_initial(*run));
        }
        let held: u64 = live.iter().map(|run| run.page_count()).sum();
        assert_eq!(
            allocator.available_frames() + held,
            allocator.initial_frames()
        );
    }

    #[test]
    fn aligned_runs_start_aligned_fit_the_request_and_conserve_pages() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut aligned_runs = 0;
        let mut middle_runs = 0;
        for _ in 0..300 {
            let mut allocator = generated_map(&mut rng);
            let mut live = Vec::new();
            for _ in 0..12 {
                let align = [1, 2, 8, 512][rng.below(4) as usize];
                let extra = rng.below(2) * rng.below(align);
                let max = align * (1 + rng.below(6)) + extra;
                let longest = longest_aligned(&allocator, align);
                let before = allocator.available_frames();
                match allocator.allocate_largest_aligned(max, align) {
                    Ok(run) => {
                        let pages = run.page_count();
                        assert!(run.start.is_multiple_of(align * PAGE), "{run:?} {align}");
                        assert!(pages <= max && pages <= longest);
                        assert_eq!(pages, longest.min(max));
                        if max.is_multiple_of(align) {
                            assert!(pages.is_multiple_of(align));
                        }
                        assert_eq!(allocator.available_frames(), before - pages);
                        if align > 1 {
                            aligned_runs += 1;
                        }
                        if !allocator
                            .boot_free_ranges()
                            .iter()
                            .all(|free| free.end != run.start)
                        {
                            middle_runs += 1;
                        }
                        live.push(run);
                    }
                    Err(error) => {
                        assert_eq!(error, PhysicalMemoryError::NoFramesAvailable);
                        assert_eq!(longest, 0);
                        assert_eq!(allocator.available_frames(), before);
                    }
                }
                check(&allocator, &live);
            }
            // Freed in any order, the free list is the initial ranges again.
            while !live.is_empty() {
                let run = live.remove(rng.below(live.len() as u64) as usize);
                allocator.free_run(run).unwrap();
                check(&allocator, &live);
            }
            assert_eq!(
                allocator.boot_free_ranges(),
                &allocator.initial[..allocator.initial_len]
            );
        }
        assert!(aligned_runs > 300 && middle_runs > 100);
    }

    #[test]
    fn an_aligned_run_from_the_middle_of_a_range_splits_it() {
        // Pages 1 to 1999: the 2 MiB-aligned interior starts at page 512.
        let candidates = [PageRange {
            start: PAGE,
            end: 2000 * PAGE,
        }];
        let mut allocator = Allocator::from_candidates(&candidates, limit(), []).unwrap();
        let run = allocator.allocate_largest_aligned(4096, 512).unwrap();
        assert_eq!(
            run,
            PageRange {
                start: 512 * PAGE,
                end: 1536 * PAGE
            }
        );
        assert_eq!(
            allocator.boot_free_ranges(),
            &[
                PageRange {
                    start: PAGE,
                    end: 512 * PAGE
                },
                PageRange {
                    start: 1536 * PAGE,
                    end: 2000 * PAGE
                },
            ]
        );
        // Nothing aligned to 2 MiB is left; any page alignment takes the
        // largest range from its start.
        assert_eq!(
            allocator.allocate_largest_aligned(512, 512),
            Err(PhysicalMemoryError::NoFramesAvailable)
        );
        assert_eq!(
            allocator.allocate_largest_aligned(10_000, 1),
            Ok(PageRange {
                start: PAGE,
                end: 512 * PAGE
            })
        );
        assert_eq!(
            allocator.allocate_largest_aligned(0, 1),
            Err(PhysicalMemoryError::InvalidPageRange)
        );
        assert_eq!(
            allocator.allocate_largest_aligned(1, 0),
            Err(PhysicalMemoryError::InvalidPageRange)
        );
    }

    #[test]
    fn a_split_with_no_free_range_slot_left_is_refused_and_changes_nothing() {
        let candidates = [PageRange {
            start: PAGE,
            end: 2000 * PAGE,
        }];
        let mut allocator =
            PhysicalFrameAllocator::<1>::from_candidates(&candidates, limit(), []).unwrap();
        assert_eq!(
            allocator.allocate_largest_aligned(512, 512),
            Err(PhysicalMemoryError::CapacityExceeded)
        );
        assert_eq!(allocator.boot_free_ranges(), &candidates);
        // A run at the range's start needs no new slot.
        assert!(allocator.allocate_largest_aligned(512, 1).is_ok());
    }

    #[test]
    fn the_aligned_allocation_is_refused_after_growth() {
        let candidates = [PageRange {
            start: PAGE,
            end: 2000 * PAGE,
        }];
        let mut allocator = Allocator::from_candidates(&candidates, limit(), []).unwrap();
        let frames = usize::try_from(allocator.initial_frames()).unwrap();
        let storage = BuddyStorage {
            tags: Box::leak(vec![0_u8; frames].into_boxed_slice()),
            links: Box::leak(vec![FreeLink::EMPTY; frames].into_boxed_slice()),
            bases: Box::leak(vec![0_u64; allocator.initial_range_count()].into_boxed_slice()),
            hints: Box::leak(vec![0_u32; allocator.range_hint_count()].into_boxed_slice()),
        };
        assert!(allocator.adopt_buddy(storage).is_ok());
        let available = allocator.available_frames();
        assert_eq!(
            allocator.allocate_largest_aligned(512, 512),
            Err(PhysicalMemoryError::InvalidPageRange)
        );
        assert_eq!(allocator.available_frames(), available);
        assert_eq!(allocator.check_buddy(), Ok(()));
    }
}
