use core::mem::{offset_of, size_of};

use deepwyrm_abi::{
    DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, DW_BOOT_DEVICE_RESOURCE_V1_SIZE,
    DW_BOOT_DEVICE_RESOURCE_V1_VERSION, DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    DW_BOOT_DEVICE_TABLE_MAX_RESOURCES, DW_BOOT_DEVICE_TABLE_RECORD_STRIDE,
    DW_BOOT_DEVICE_TABLE_V1_SIZE, DW_BOOT_DEVICE_TABLE_V1_VERSION,
    DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DwBootDeviceResourceV1,
    DwBootDeviceTableV1,
};

#[test]
fn d1_boot_device_carrier_identities_and_layouts_are_exact() {
    assert_eq!(DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1.0, 4);
    assert_eq!(DW_BOOT_DEVICE_TABLE_V1_VERSION, 1);
    assert_eq!(DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK, 0);
    assert_eq!(DW_BOOT_DEVICE_TABLE_MAX_RESOURCES, 8);
    assert_eq!(DW_BOOT_DEVICE_TABLE_RECORD_STRIDE, 48);
    assert_eq!(DW_BOOT_DEVICE_RESOURCE_V1_VERSION, 1);
    assert_eq!(DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, 0);
    assert_eq!(DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT.0, 1);

    assert_eq!(size_of::<DwBootDeviceTableV1>(), 32);
    assert_eq!(DW_BOOT_DEVICE_TABLE_V1_SIZE, 32);
    assert_eq!(offset_of!(DwBootDeviceTableV1, resource_count), 8);
    assert_eq!(offset_of!(DwBootDeviceTableV1, flags), 12);
    assert_eq!(offset_of!(DwBootDeviceTableV1, record_stride), 16);
    assert_eq!(offset_of!(DwBootDeviceTableV1, reserved0), 20);
    assert_eq!(offset_of!(DwBootDeviceTableV1, total_byte_len), 24);

    assert_eq!(size_of::<DwBootDeviceResourceV1>(), 48);
    assert_eq!(DW_BOOT_DEVICE_RESOURCE_V1_SIZE, 48);
    assert_eq!(offset_of!(DwBootDeviceResourceV1, kind), 8);
    assert_eq!(offset_of!(DwBootDeviceResourceV1, resource_id), 16);
    assert_eq!(
        offset_of!(DwBootDeviceResourceV1, device_correlation_id),
        24
    );
    assert_eq!(offset_of!(DwBootDeviceResourceV1, pio_base), 32);
    assert_eq!(offset_of!(DwBootDeviceResourceV1, pio_length), 34);
    assert_eq!(offset_of!(DwBootDeviceResourceV1, interrupt_source), 36);
    assert_eq!(offset_of!(DwBootDeviceResourceV1, reserved), 40);
}
