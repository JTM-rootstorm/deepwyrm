use core::mem::{offset_of, size_of};

use deepwyrm_abi::{
    DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, DW_BOOT_DEVICE_RESOURCE_V2_SIZE,
    DW_BOOT_DEVICE_RESOURCE_V2_VERSION, DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    DW_BOOT_DEVICE_TABLE_MAX_RESOURCES, DW_BOOT_DEVICE_TABLE_RECORD_STRIDE,
    DW_BOOT_DEVICE_TABLE_V2_SIZE, DW_BOOT_DEVICE_TABLE_V2_VERSION,
    DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1, DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DwBootDeviceResourceV2,
    DwBootDeviceTableV2,
};

#[test]
fn d1_boot_device_carrier_identities_and_layouts_are_exact() {
    assert_eq!(DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1.0, 4);
    assert_eq!(DW_BOOT_DEVICE_TABLE_V2_VERSION, 2);
    assert_eq!(DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK, 0);
    assert_eq!(DW_BOOT_DEVICE_TABLE_MAX_RESOURCES, 8);
    assert_eq!(DW_BOOT_DEVICE_TABLE_RECORD_STRIDE, 64);
    assert_eq!(DW_BOOT_DEVICE_RESOURCE_V2_VERSION, 2);
    assert_eq!(DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, 0);
    assert_eq!(DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT.0, 1);
    assert_eq!(DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION.0, 2);

    assert_eq!(size_of::<DwBootDeviceTableV2>(), 32);
    assert_eq!(DW_BOOT_DEVICE_TABLE_V2_SIZE, 32);
    assert_eq!(offset_of!(DwBootDeviceTableV2, resource_count), 8);
    assert_eq!(offset_of!(DwBootDeviceTableV2, flags), 12);
    assert_eq!(offset_of!(DwBootDeviceTableV2, record_stride), 16);
    assert_eq!(offset_of!(DwBootDeviceTableV2, reserved0), 20);
    assert_eq!(offset_of!(DwBootDeviceTableV2, total_byte_len), 24);

    assert_eq!(size_of::<DwBootDeviceResourceV2>(), 64);
    assert_eq!(DW_BOOT_DEVICE_RESOURCE_V2_SIZE, 64);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, kind), 8);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, resource_id), 16);
    assert_eq!(
        offset_of!(DwBootDeviceResourceV2, device_correlation_id),
        24
    );
    assert_eq!(offset_of!(DwBootDeviceResourceV2, pio_base), 32);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, pio_length), 34);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, interrupt_source), 36);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, pci_address), 40);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, pci_ids), 44);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, reserved0), 48);
    assert_eq!(offset_of!(DwBootDeviceResourceV2, reserved1), 56);
}
