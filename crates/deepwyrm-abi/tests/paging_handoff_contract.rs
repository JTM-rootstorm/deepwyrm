use core::mem::{align_of, offset_of, size_of};

use deepwyrm_abi::{
    DW_BOOT_MODULE_FLAG_READ_ONLY, DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
    DW_BOOT_MODULE_V1_SIZE, DW_BOOT_MODULE_V1_VERSION,
    DW_BOOT_X86_64_PAGING_HANDOFF_FLAGS_SUPPORTED_MASK,
    DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION, DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_PHYSICAL_ADDRESS_WIDTH,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_PHYSICAL_ADDRESS_WIDTH,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT, DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
    DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS, DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE,
    DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION, DwBootModuleFlags, DwBootModuleKind, DwBootModuleV1,
    DwBootX86_64PagingHandoffFlags, DwBootX86_64PagingHandoffV1,
};

const BASE_PAGE_SIZE: u64 = 4_096;

fn valid_header() -> DwBootX86_64PagingHandoffV1 {
    DwBootX86_64PagingHandoffV1 {
        size: DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE,
        version: DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION,
        flags: DW_BOOT_X86_64_PAGING_HANDOFF_FLAGS_SUPPORTED_MASK,
        physical_address_width: 52,
        cr3_root_physical: 0x1000,
        table_frames_offset: DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
        table_frame_count: DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT,
        table_frame_stride: DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
        total_byte_len: DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
            + DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT
                * DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
        paging_layout_version: DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION,
        reserved0: 0,
        temporary_virtual_address: DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
        pml4_index: DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
        pdpt_index: DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX,
        pd_index: DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
        pt_index: DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
        temporary_pdpt_frame_physical: 0x2000,
        temporary_pd_frame_physical: 0x3000,
        temporary_pt_frame_physical: 0x4000,
        reserved: [0; 3],
    }
}

fn valid_module(header: &DwBootX86_64PagingHandoffV1) -> DwBootModuleV1 {
    DwBootModuleV1 {
        size: DW_BOOT_MODULE_V1_SIZE,
        version: DW_BOOT_MODULE_V1_VERSION,
        kind: DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
        flags: DW_BOOT_MODULE_FLAG_READ_ONLY,
        physical_start: 0x8000,
        byte_len: u64::from(header.total_byte_len),
        reserved: [0; 4],
    }
}

fn derived_index(virtual_address: u64, shift: u32) -> u16 {
    ((virtual_address >> shift) & 0x1ff) as u16
}

// This schema-level model checks typed contract relationships. The kernel's
// BootInfo intake separately performs the hostile-byte, one-snapshot parse.
fn validate_carrier_model(
    modules: &[DwBootModuleV1],
    header: &DwBootX86_64PagingHandoffV1,
    frames: &[u64],
) -> Result<(), &'static str> {
    let mut carriers = modules
        .iter()
        .filter(|module| module.kind == DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1);
    let module = carriers.next().ok_or("missing carrier")?;
    if carriers.next().is_some() {
        return Err("duplicate carrier");
    }
    if module.flags != DW_BOOT_MODULE_FLAG_READ_ONLY {
        return Err("carrier flags");
    }
    if module.physical_start % BASE_PAGE_SIZE != 0 {
        return Err("carrier alignment");
    }
    if header.size != DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE
        || header.version != DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION
        || header.flags != DW_BOOT_X86_64_PAGING_HANDOFF_FLAGS_SUPPORTED_MASK
        || header.paging_layout_version != DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION
        || header.reserved0 != 0
        || header.reserved != [0; 3]
    {
        return Err("fixed header");
    }
    if !(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_PHYSICAL_ADDRESS_WIDTH
        ..=DW_BOOT_X86_64_PAGING_HANDOFF_MAX_PHYSICAL_ADDRESS_WIDTH)
        .contains(&header.physical_address_width)
    {
        return Err("physical width");
    }
    if header.table_frames_offset != DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
        || header.table_frame_stride != DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE
        || !(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT
            ..=DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT)
            .contains(&header.table_frame_count)
        || usize::try_from(header.table_frame_count).ok() != Some(frames.len())
    {
        return Err("list shape");
    }
    let exact_extent = header
        .table_frame_count
        .checked_mul(header.table_frame_stride)
        .and_then(|list_len| header.table_frames_offset.checked_add(list_len))
        .ok_or("extent overflow")?;
    if header.total_byte_len != exact_extent
        || header.total_byte_len > DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN
        || module.byte_len != u64::from(exact_extent)
    {
        return Err("extent mismatch");
    }
    if header.temporary_virtual_address != DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS
        || header.pml4_index != derived_index(header.temporary_virtual_address, 39)
        || header.pdpt_index != derived_index(header.temporary_virtual_address, 30)
        || header.pd_index != derived_index(header.temporary_virtual_address, 21)
        || header.pt_index != derived_index(header.temporary_virtual_address, 12)
    {
        return Err("temporary path");
    }

    let required_frames = [
        header.cr3_root_physical,
        header.temporary_pdpt_frame_physical,
        header.temporary_pd_frame_physical,
        header.temporary_pt_frame_physical,
    ];
    for (index, frame) in required_frames.iter().enumerate() {
        if required_frames[..index].contains(frame) {
            return Err("cyclic temporary path");
        }
    }
    if frames.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("unsorted frame list");
    }
    let physical_limit = 1_u64
        .checked_shl(header.physical_address_width)
        .ok_or("physical width shift")?;
    if frames
        .iter()
        .any(|frame| *frame == 0 || frame % BASE_PAGE_SIZE != 0 || *frame >= physical_limit)
    {
        return Err("invalid frame address");
    }
    if required_frames
        .iter()
        .any(|required| !frames.contains(required))
    {
        return Err("missing required frame");
    }
    Ok(())
}

#[test]
fn paging_handoff_layout_and_constants_are_exact() {
    assert_eq!(size_of::<DwBootX86_64PagingHandoffV1>(), 112);
    assert_eq!(align_of::<DwBootX86_64PagingHandoffV1>(), 8);
    assert_eq!(DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE, 112);
    assert_eq!(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET, 112);
    assert_eq!(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE, 8);
    assert_eq!(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT, 4);
    assert_eq!(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT, 256);
    assert_eq!(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN, 2_160);
    assert_eq!(
        offset_of!(DwBootX86_64PagingHandoffV1, cr3_root_physical),
        16
    );
    assert_eq!(
        offset_of!(DwBootX86_64PagingHandoffV1, table_frames_offset),
        24
    );
    assert_eq!(offset_of!(DwBootX86_64PagingHandoffV1, total_byte_len), 36);
    assert_eq!(
        offset_of!(DwBootX86_64PagingHandoffV1, temporary_virtual_address),
        48
    );
    assert_eq!(offset_of!(DwBootX86_64PagingHandoffV1, pml4_index), 56);
    assert_eq!(
        offset_of!(DwBootX86_64PagingHandoffV1, temporary_pdpt_frame_physical),
        64
    );
    assert_eq!(offset_of!(DwBootX86_64PagingHandoffV1, reserved), 88);

    let temporary = DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS;
    assert_eq!(temporary, 0xffff_ff00_0000_0000);
    assert_eq!(derived_index(temporary, 39), 510);
    assert_eq!(derived_index(temporary, 30), 0);
    assert_eq!(derived_index(temporary, 21), 0);
    assert_eq!(derived_index(temporary, 12), 0);
}

#[test]
fn valid_minimum_and_maximum_carriers_are_accepted() {
    let minimum_header = valid_header();
    let minimum_module = valid_module(&minimum_header);
    assert_eq!(
        validate_carrier_model(
            &[minimum_module],
            &minimum_header,
            &[0x1000, 0x2000, 0x3000, 0x4000]
        ),
        Ok(())
    );

    let maximum_frames = (1..=DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT)
        .map(|index| u64::from(index) * BASE_PAGE_SIZE)
        .collect::<Vec<_>>();
    let mut maximum_header = valid_header();
    maximum_header.table_frame_count = DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT;
    maximum_header.total_byte_len = DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN;
    let maximum_module = valid_module(&maximum_header);
    assert_eq!(
        validate_carrier_model(&[maximum_module], &maximum_header, &maximum_frames),
        Ok(())
    );
}

#[test]
fn malformed_headers_and_extents_fail_closed() {
    let frames = [0x1000, 0x2000, 0x3000, 0x4000];
    let valid = valid_header();

    for malformed in [
        DwBootX86_64PagingHandoffV1 { size: 0, ..valid },
        DwBootX86_64PagingHandoffV1 {
            version: 0,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            flags: DwBootX86_64PagingHandoffFlags(1),
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            physical_address_width: 53,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            cr3_root_physical: 0x1001,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            table_frames_offset: 120,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            table_frame_count: 3,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            table_frame_stride: 16,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            total_byte_len: 143,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            paging_layout_version: 1,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            reserved0: 1,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            temporary_virtual_address: 0,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            pml4_index: 0,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            temporary_pdpt_frame_physical: 0x1000,
            ..valid
        },
        DwBootX86_64PagingHandoffV1 {
            reserved: [0, 1, 0],
            ..valid
        },
    ] {
        let module = valid_module(&malformed);
        assert!(validate_carrier_model(&[module], &malformed, &frames).is_err());
    }
}

#[test]
fn malformed_module_sets_and_frame_lists_fail_closed() {
    let header = valid_header();
    let module = valid_module(&header);
    let unrelated = DwBootModuleV1 {
        kind: DwBootModuleKind(99),
        ..module
    };
    assert!(
        validate_carrier_model(&[unrelated], &header, &[0x1000, 0x2000, 0x3000, 0x4000]).is_err()
    );
    assert!(
        validate_carrier_model(
            &[module, module],
            &header,
            &[0x1000, 0x2000, 0x3000, 0x4000]
        )
        .is_err()
    );
    let writable = DwBootModuleV1 {
        flags: DwBootModuleFlags(DW_BOOT_MODULE_FLAG_READ_ONLY.0 | 2),
        ..module
    };
    assert!(
        validate_carrier_model(&[writable], &header, &[0x1000, 0x2000, 0x3000, 0x4000]).is_err()
    );
    let wrong_extent = DwBootModuleV1 {
        byte_len: module.byte_len + 8,
        ..module
    };
    assert!(
        validate_carrier_model(&[wrong_extent], &header, &[0x1000, 0x2000, 0x3000, 0x4000])
            .is_err()
    );

    for malformed_frames in [
        [0x1000, 0x3000, 0x2000, 0x4000],
        [0x1000, 0x2000, 0x2000, 0x4000],
        [0x1000, 0x2000, 0x3000, 0x4001],
        [0x1000, 0x2000, 0x3000, 0x5000],
    ] {
        assert!(validate_carrier_model(&[module], &header, &malformed_frames).is_err());
    }
}

#[test]
fn generated_rust_c_and_docs_preserve_internal_carrier_semantics() {
    let artifacts = [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../abi/generated/deepwyrm_abi.rs"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../abi/generated/deepwyrm_abi.h"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../abi/generated/ABI.md"
        )),
    ];
    let markers = [
        "Exactly one READ_ONLY kernel-internal DwBootX86_64PagingHandoffV1 carrier",
        "must never be transferred to userspace",
        "strictly ascending and unique",
        "enumerates every current transition page-table frame exactly once with no data frames",
        "low 12 bits zero",
        "must be exactly equal",
    ];

    for artifact in artifacts {
        for marker in markers {
            assert!(
                artifact.contains(marker),
                "generated paging-handoff artifact is missing marker: {marker}"
            );
        }
    }
}
