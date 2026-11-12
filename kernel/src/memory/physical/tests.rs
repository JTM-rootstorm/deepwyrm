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
