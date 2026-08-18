use super::*;
use crate::memory::frame_roles::{KernelImageSegment, synthetic_frame_role_manager};

fn limit() -> PhysicalAddressLimit {
    PhysicalAddressLimit::new(0x20_000).unwrap()
}

fn range(start: u64) -> PhysicalRange {
    PhysicalRange::new(start, 0x1000).unwrap()
}

fn kernel_ranges() -> [PhysicalRange; 3] {
    [range(0x2000), range(0x3000), range(0x4000)]
}

fn reserved_kernel_map() -> SanitizedBootMap {
    sanitize_records(
        &[
            record(0x1000, 2, DW_BOOT_MEMORY_KIND_RESERVED, 0),
            record(0x3000, 4, DW_BOOT_MEMORY_KIND_RESERVED, 0),
            record(0x10_000, 8, DW_BOOT_MEMORY_KIND_USABLE, 0),
        ],
        limit(),
    )
    .unwrap()
}

fn record(
    physical_start: u64,
    page_count: u64,
    kind: deepwyrm_abi::DwBootMemoryKind,
    firmware_attributes: u64,
) -> DwBootMemoryRangeV1 {
    DwBootMemoryRangeV1 {
        physical_start,
        page_count,
        kind,
        firmware_attributes,
        ..DwBootMemoryRangeV1::default()
    }
}

fn usable_map() -> SanitizedBootMap {
    let mut map = SanitizedBootMap::empty(limit());
    map.usable[0] = SanitizedUsableRange {
        pages: PageRange {
            start: 0,
            end: 0x10_000,
        },
        firmware_attributes: 0x8,
    };
    map.usable_len = 1;
    map
}

#[test]
fn every_reservation_kind_is_subtracted_before_frames_become_free() {
    let map = usable_map();
    let reservations = [
        BootstrapReservation {
            kind: BootstrapReservationKind::BootInfo,
            range: range(0x1000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::MemoryMapTable,
            range: range(0x2000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::ModuleTable,
            range: range(0x3000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::ModuleData { index: 0 },
            range: range(0x4000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::CommandLine,
            range: range(0x5000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::Entropy,
            range: range(0x6000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::FramebufferPixels,
            range: range(0x7000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::AcpiRsdpMaximumExtent,
            range: range(0x8000),
        },
        BootstrapReservation {
            kind: BootstrapReservationKind::PagingTableFrame { index: 0 },
            range: range(0x9000),
        },
    ];
    let mut allocator = initialize_frame_allocator::<16>(&map, &reservations).unwrap();
    assert_eq!(allocator.available_frames(), 6);
    for page in 10_u64..=15 {
        assert_eq!(
            allocator.allocate_frame().unwrap().physical_start(),
            page * 0x1000
        );
    }
    assert_eq!(
        allocator.allocate_frame(),
        Err(PhysicalMemoryError::NoFramesAvailable)
    );
}

#[test]
fn sanitization_keeps_only_usable_and_preserves_opaque_attributes() {
    let map = sanitize_records(
        &[
            record(0x1000, 1, DW_BOOT_MEMORY_KIND_USABLE, 0x8),
            record(0x2000, 1, DW_BOOT_MEMORY_KIND_USABLE, 0x8),
            record(
                0x3000,
                1,
                DW_BOOT_MEMORY_KIND_RESERVED,
                0x8000_0000_0000_0000,
            ),
        ],
        limit(),
    )
    .unwrap();
    assert_eq!(map.usable_range_count(), 1);
    let usable = map.usable_range(0).unwrap();
    assert_eq!(
        usable.physical_range(),
        PhysicalRange::new(0x1000, 0x2000).unwrap()
    );
    assert_eq!(usable.firmware_attributes(), 0x8);
}

#[test]
fn every_enumerated_handoff_kind_requires_complete_nonusable_coverage() {
    let covered = [
        record(0x1000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
        record(0x2000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
    ];
    let handoff = PhysicalRange::new(0x1800, 0x1000).unwrap();
    for kind in [
        BootstrapReservationKind::BootInfo,
        BootstrapReservationKind::MemoryMapTable,
        BootstrapReservationKind::ModuleTable,
        BootstrapReservationKind::ModuleData { index: 0 },
        BootstrapReservationKind::CommandLine,
        BootstrapReservationKind::Entropy,
        BootstrapReservationKind::FramebufferPixels,
        BootstrapReservationKind::AcpiRsdpMaximumExtent,
        BootstrapReservationKind::PagingTableFrame { index: 0 },
    ] {
        assert_eq!(
            require_nonusable_coverage(&covered, handoff, kind, limit()),
            Ok(())
        );
    }
}

#[test]
fn handoff_coverage_rejects_gaps_and_any_usable_overlap() {
    let handoff = PhysicalRange::new(0x1800, 0x1800).unwrap();
    let gap = [
        record(0x1000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
        record(0x3000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
    ];
    assert_eq!(
        require_nonusable_coverage(&gap, handoff, BootstrapReservationKind::BootInfo, limit(),),
        Err(BootMapError::HandoffRangeUncovered {
            kind: BootstrapReservationKind::BootInfo,
        })
    );

    let usable_overlap = [
        record(0x1000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
        record(0x2000, 1, DW_BOOT_MEMORY_KIND_USABLE, 0),
    ];
    assert_eq!(
        require_nonusable_coverage(
            &usable_overlap,
            handoff,
            BootstrapReservationKind::ModuleData { index: 1 },
            limit(),
        ),
        Err(BootMapError::HandoffRangeUsable {
            kind: BootstrapReservationKind::ModuleData { index: 1 },
        })
    );
}

#[test]
fn paging_table_frames_require_exact_reserved_map_coverage() {
    let frame = PhysicalRange::new(0x2000, u64::from(DW_BOOT_BASE_PAGE_SIZE)).unwrap();
    let kind = BootstrapReservationKind::PagingTableFrame { index: 7 };
    let reserved = [record(0x2000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0)];
    assert_eq!(
        require_reserved_coverage(&reserved, frame, kind, limit()),
        Ok(())
    );

    let usable = [record(0x2000, 1, DW_BOOT_MEMORY_KIND_USABLE, 0)];
    assert_eq!(
        require_reserved_coverage(&usable, frame, kind, limit()),
        Err(BootMapError::HandoffRangeNotReserved { kind })
    );

    let mmio = [record(0x2000, 1, DW_BOOT_MEMORY_KIND_MMIO, 0)];
    assert_eq!(
        require_reserved_coverage(&mmio, frame, kind, limit()),
        Err(BootMapError::HandoffRangeNotReserved { kind })
    );

    let outside = [record(0x1000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0)];
    assert_eq!(
        require_reserved_coverage(&outside, frame, kind, limit()),
        Err(BootMapError::HandoffRangeUncovered { kind })
    );
}

#[test]
fn kernel_image_requires_complete_exact_reserved_coverage() {
    let map = reserved_kernel_map();
    assert_eq!(
        BootstrapMemoryWitness::new(&map, &[]).validate_kernel_image_ranges(&kernel_ranges()),
        Ok(())
    );

    let mmio = sanitize_records(
        &[
            record(0x2000, 1, DW_BOOT_MEMORY_KIND_MMIO, 0),
            record(0x3000, 2, DW_BOOT_MEMORY_KIND_RESERVED, 0),
        ],
        limit(),
    )
    .unwrap();
    assert_eq!(
        BootstrapMemoryWitness::new(&mmio, &[]).validate_kernel_image_ranges(&kernel_ranges()),
        Err(KernelImageBoundaryError::NotReserved { range_index: 0 })
    );

    let gap = sanitize_records(
        &[
            record(0x1000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
            record(0x3000, 4, DW_BOOT_MEMORY_KIND_RESERVED, 0),
        ],
        limit(),
    )
    .unwrap();
    let spanning_gap = [
        PhysicalRange::new(0x1000, 0x3000).unwrap(),
        range(0x5000),
        range(0x6000),
    ];
    assert_eq!(
        BootstrapMemoryWitness::new(&gap, &[]).validate_kernel_image_ranges(&spanning_gap),
        Err(KernelImageBoundaryError::Uncovered { range_index: 0 })
    );
}

#[test]
fn sanitizer_rejects_unknown_memory_kind_before_witness_issuance() {
    assert!(matches!(
        sanitize_records(
            &[record(
                0x1000,
                1,
                deepwyrm_abi::DwBootMemoryKind(u32::MAX),
                0,
            )],
            limit(),
        ),
        Err(BootMapError::UnknownMemoryKind)
    ));
}

#[test]
fn every_bootstrap_reservation_kind_blocks_kernel_image_aliasing() {
    let map = reserved_kernel_map();
    for kind in [
        BootstrapReservationKind::BootInfo,
        BootstrapReservationKind::MemoryMapTable,
        BootstrapReservationKind::ModuleTable,
        BootstrapReservationKind::ModuleData { index: 0 },
        BootstrapReservationKind::CommandLine,
        BootstrapReservationKind::Entropy,
        BootstrapReservationKind::FramebufferPixels,
        BootstrapReservationKind::AcpiRsdpMaximumExtent,
        BootstrapReservationKind::PagingTableFrame { index: 0 },
    ] {
        let reservations = [BootstrapReservation {
            kind,
            range: PhysicalRange::new(0x2800, 0x100).unwrap(),
        }];
        assert_eq!(
            BootstrapMemoryWitness::new(&map, &reservations)
                .validate_kernel_image_ranges(&kernel_ranges()),
            Err(KernelImageBoundaryError::BootstrapReservationOverlap {
                range_index: 0,
                reservation: kind,
            })
        );
    }
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic host roles prove rejected boot provenance has no publication side effect"
)]
fn rejected_kernel_boundary_leaves_allocator_and_roles_unchanged() {
    let map = reserved_kernel_map();
    let reservations = [BootstrapReservation {
        kind: BootstrapReservationKind::BootInfo,
        range: range(0x2000),
    }];
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x10_000, 8);
    let available = roles.available_frames();
    assert_eq!(
        BootstrapMemoryWitness::new(&map, &reservations)
            .validate_kernel_image_ranges(&kernel_ranges()),
        Err(KernelImageBoundaryError::BootstrapReservationOverlap {
            range_index: 0,
            reservation: BootstrapReservationKind::BootInfo,
        })
    );
    assert_eq!(roles.available_frames(), available);
    assert_eq!(roles.check_invariants(), Ok(()));

    let declarations = [
        (kernel_ranges()[0], KernelImageSegment::Text),
        (kernel_ranges()[1], KernelImageSegment::ReadOnlyData),
        (kernel_ranges()[2], KernelImageSegment::WritableData),
    ];
    let staged = unsafe { roles.stage_kernel_image_roles(declarations) }
        .expect("rejected boundary must not have published a role");
    let _published = roles.publish_staged_kernel_image(staged);
    for (range, segment) in declarations {
        assert_eq!(
            roles.validate_kernel_image_page(range.physical_start(), segment),
            Ok(())
        );
    }
    assert_eq!(roles.available_frames(), available);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn sanitization_rejects_unsorted_overlapping_and_out_of_limit_records() {
    assert!(matches!(
        sanitize_records(
            &[
                record(0x3000, 1, DW_BOOT_MEMORY_KIND_USABLE, 0),
                record(0x1000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
            ],
            limit(),
        ),
        Err(BootMapError::UnsortedInput)
    ));
    assert!(matches!(
        sanitize_records(
            &[
                record(0x1000, 2, DW_BOOT_MEMORY_KIND_USABLE, 0),
                record(0x2000, 1, DW_BOOT_MEMORY_KIND_RESERVED, 0),
            ],
            limit(),
        ),
        Err(BootMapError::OverlappingInput)
    ));
    assert!(matches!(
        sanitize_records(
            &[record(0x1f000, 2, DW_BOOT_MEMORY_KIND_USABLE, 0)],
            limit(),
        ),
        Err(BootMapError::Physical(
            PhysicalMemoryError::OutsidePhysicalLimit
        ))
    ));
}
