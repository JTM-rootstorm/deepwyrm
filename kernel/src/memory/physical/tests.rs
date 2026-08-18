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
