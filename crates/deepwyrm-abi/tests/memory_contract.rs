use core::mem::{align_of, offset_of, size_of};

use deepwyrm_abi::{
    DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
    DW_ADDRESS_REGION_MAP_FLAG_FIXED, DW_ADDRESS_REGION_MAP_FLAGS_SUPPORTED_MASK,
    DW_BASE_PAGE_SIZE, DW_BOOT_BASE_PAGE_SIZE, DW_MEMORY_OBJECT_CREATE_FLAGS_SUPPORTED_MASK,
    DW_MEMORY_PROTECTION_EXECUTE, DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_SUPPORTED_MASK,
    DW_MEMORY_PROTECTION_WRITE, DwAddressRegionMapArgsV1,
};

#[allow(dead_code)]
mod generated_wrapper_metadata {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../abi/generated/syscall_wrappers.rs"
    ));
}

#[test]
fn memory_flag_namespaces_are_narrow_and_explicit() {
    assert_eq!(DW_BASE_PAGE_SIZE, 4_096);
    assert_eq!(DW_BASE_PAGE_SIZE, DW_BOOT_BASE_PAGE_SIZE);
    let protections = [
        DW_MEMORY_PROTECTION_READ.0,
        DW_MEMORY_PROTECTION_WRITE.0,
        DW_MEMORY_PROTECTION_EXECUTE.0,
    ];
    assert!(protections.iter().all(|value| value.is_power_of_two()));
    assert_eq!(
        DW_MEMORY_PROTECTION_SUPPORTED_MASK.0,
        protections.into_iter().fold(0, |mask, value| mask | value)
    );
    assert_eq!(DW_MEMORY_OBJECT_CREATE_FLAGS_SUPPORTED_MASK.0, 0);
    assert_eq!(
        DW_ADDRESS_REGION_MAP_FLAGS_SUPPORTED_MASK,
        DW_ADDRESS_REGION_MAP_FLAG_FIXED
    );
}

#[test]
fn map_args_v1_has_the_generated_fixed_width_layout() {
    assert_eq!(DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION, 1);
    assert_eq!(DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, 72);
    assert_eq!(size_of::<DwAddressRegionMapArgsV1>(), 72);
    assert_eq!(align_of::<DwAddressRegionMapArgsV1>(), 8);
    assert_eq!(
        offset_of!(DwAddressRegionMapArgsV1, memory_object_offset),
        8
    );
    assert_eq!(offset_of!(DwAddressRegionMapArgsV1, byte_len), 16);
    assert_eq!(offset_of!(DwAddressRegionMapArgsV1, requested_address), 24);
    assert_eq!(offset_of!(DwAddressRegionMapArgsV1, protections), 32);
    assert_eq!(offset_of!(DwAddressRegionMapArgsV1, flags), 36);
    assert_eq!(offset_of!(DwAddressRegionMapArgsV1, reserved), 40);
}

#[test]
fn map_metadata_requires_the_unconditional_rights_baseline() {
    let memory_object = generated_wrapper_metadata::DW_SYSCALL_ARGUMENT_METADATA
        .iter()
        .find(|argument| argument.syscall_number == 0x0002_0010 && argument.name == "memory_object")
        .expect("address_region_map memory_object metadata must exist");

    assert_eq!(memory_object.required_object_type, "MEMORY_OBJECT");
    assert_eq!(memory_object.required_rights, "MAP+READ");
}

#[test]
fn logical_size_and_page_rounded_mapping_capacity_remain_distinct() {
    let page_size = u64::from(DW_BASE_PAGE_SIZE);
    let logical_size = page_size + 1;
    let mapping_capacity = logical_size
        .checked_add(page_size - 1)
        .map(|value| value & !(page_size - 1))
        .expect("test logical size must round without overflow");

    assert_eq!(mapping_capacity, page_size * 2);
    assert!(logical_size < mapping_capacity);
    assert_eq!(mapping_capacity + page_size, page_size * 3);

    let generated_artifacts = [
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
    let required_markers = [
        "Exact logical content byte size",
        "checked align_up(logical byte_size, DW_BASE_PAGE_SIZE) mappable capacity",
        "hardware-addressable padding",
        "zero-initialized before first publication",
        "never contains unrelated data",
        "may be shared or modified subject to mapping protections",
        "parse or use object content only through exact logical byte_size",
    ];

    for artifact in generated_artifacts {
        for marker in required_markers {
            assert!(
                artifact.contains(marker),
                "generated ABI artifact is missing logical-size marker: {marker}"
            );
        }
    }
}
