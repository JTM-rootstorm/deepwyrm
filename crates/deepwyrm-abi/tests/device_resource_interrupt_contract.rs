use core::mem::{offset_of, size_of};

use deepwyrm_abi::{
    DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT, DW_DEVICE_RESOURCE_INFO_FLAGS_SUPPORTED_MASK,
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_INTERRUPT_INFO_FLAG_COALESCED, DW_INTERRUPT_INFO_FLAGS_SUPPORTED_MASK,
    DW_INTERRUPT_INFO_V1_SIZE, DW_INTERRUPT_INFO_V1_VERSION, DW_INTERRUPT_STATE_ARMED,
    DW_INTERRUPT_STATE_FINALIZING, DW_INTERRUPT_STATE_PENDING,
    DW_OBJECT_COMPATIBLE_RIGHTS_DEVICE_RESOURCE, DW_OBJECT_COMPATIBLE_RIGHTS_INTERRUPT,
    DW_OBJECT_COMPATIBLE_RIGHTS_TASK_GROUP, DW_OBJECT_COMPATIBLE_SIGNALS_INTERRUPT,
    DW_OBJECT_INFO_DEVICE_RESOURCE_V1, DW_OBJECT_INFO_INTERRUPT_V1, DW_OBJECT_TYPE_DEVICE_RESOURCE,
    DW_OBJECT_TYPE_EXCEPTION, DW_OBJECT_TYPE_INTERRUPT, DW_RIGHT_DUPLICATE, DW_RIGHT_RESOURCE,
    DW_RIGHTS_KNOWN_MASK, DW_SIGNAL_SIGNALED, DW_SYSCALL_DEVICE_PIO_READ,
    DW_SYSCALL_DEVICE_PIO_WRITE, DW_SYSCALL_DEVICE_RESOURCE_CLAIM, DW_SYSCALL_INTERRUPT_ACK,
    DW_SYSCALL_INTERRUPT_CREATE, DwDeviceResourceInfoV1, DwInterruptInfoV1, DwKnownSyscall,
    DwSyscallImplementationPhase, dw_object_compatible_rights, dw_object_compatible_signals,
    dw_rights_are_known,
};

#[test]
fn d1_activates_only_the_reached_objects_rights_signals_and_feature_identity() {
    assert_eq!(DW_OBJECT_TYPE_INTERRUPT.0, 16);
    assert_eq!(DW_OBJECT_TYPE_DEVICE_RESOURCE.0, 17);
    assert_eq!(DW_RIGHT_RESOURCE.0, 0x400);
    assert_eq!(DW_RIGHTS_KNOWN_MASK.0, 0x7ff);
    assert!(dw_rights_are_known(DW_RIGHT_RESOURCE));

    assert_eq!(DW_OBJECT_COMPATIBLE_RIGHTS_TASK_GROUP.0, 0x7c0);
    assert_eq!(DW_OBJECT_COMPATIBLE_RIGHTS_DEVICE_RESOURCE.0, 0x3c3);
    assert_eq!(DW_OBJECT_COMPATIBLE_RIGHTS_INTERRUPT.0, 0x390);
    assert_eq!(
        DW_OBJECT_COMPATIBLE_RIGHTS_INTERRUPT.0 & DW_RIGHT_DUPLICATE.0,
        0
    );
    assert_eq!(
        dw_object_compatible_rights(DW_OBJECT_TYPE_INTERRUPT),
        DW_OBJECT_COMPATIBLE_RIGHTS_INTERRUPT
    );
    assert_eq!(
        dw_object_compatible_rights(DW_OBJECT_TYPE_DEVICE_RESOURCE),
        DW_OBJECT_COMPATIBLE_RIGHTS_DEVICE_RESOURCE
    );
    assert_eq!(dw_object_compatible_rights(DW_OBJECT_TYPE_EXCEPTION).0, 0);

    assert_eq!(DW_OBJECT_COMPATIBLE_SIGNALS_INTERRUPT, DW_SIGNAL_SIGNALED);
    assert_eq!(
        dw_object_compatible_signals(DW_OBJECT_TYPE_INTERRUPT),
        DW_SIGNAL_SIGNALED
    );
    assert_eq!(DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT, 1);
}

#[test]
fn d1_object_info_topics_states_flags_and_layouts_are_exact() {
    assert_eq!(DW_OBJECT_INFO_DEVICE_RESOURCE_V1, 0x0003_0001);
    assert_eq!(DW_OBJECT_INFO_INTERRUPT_V1, 0x0003_0002);
    assert_eq!(DW_DEVICE_RESOURCE_INFO_V1_VERSION, 1);
    assert_eq!(DW_DEVICE_RESOURCE_INFO_FLAGS_SUPPORTED_MASK, 0);
    assert_eq!(DW_INTERRUPT_INFO_V1_VERSION, 1);
    assert_eq!(DW_INTERRUPT_STATE_ARMED.0, 1);
    assert_eq!(DW_INTERRUPT_STATE_PENDING.0, 2);
    assert_eq!(DW_INTERRUPT_STATE_FINALIZING.0, 3);
    assert_eq!(DW_INTERRUPT_INFO_FLAG_COALESCED.0, 1);
    assert_eq!(
        DW_INTERRUPT_INFO_FLAGS_SUPPORTED_MASK,
        DW_INTERRUPT_INFO_FLAG_COALESCED
    );

    assert_eq!(size_of::<DwDeviceResourceInfoV1>(), 48);
    assert_eq!(DW_DEVICE_RESOURCE_INFO_V1_SIZE, 48);
    assert_eq!(offset_of!(DwDeviceResourceInfoV1, kind), 8);
    assert_eq!(offset_of!(DwDeviceResourceInfoV1, resource_id), 16);
    assert_eq!(offset_of!(DwDeviceResourceInfoV1, lease_generation), 24);
    assert_eq!(offset_of!(DwDeviceResourceInfoV1, pio_base), 32);
    assert_eq!(offset_of!(DwDeviceResourceInfoV1, interrupt_source), 36);
    assert_eq!(offset_of!(DwDeviceResourceInfoV1, reserved), 40);

    assert_eq!(size_of::<DwInterruptInfoV1>(), 64);
    assert_eq!(DW_INTERRUPT_INFO_V1_SIZE, 64);
    assert_eq!(offset_of!(DwInterruptInfoV1, source), 8);
    assert_eq!(offset_of!(DwInterruptInfoV1, state), 12);
    assert_eq!(offset_of!(DwInterruptInfoV1, object_generation), 16);
    assert_eq!(offset_of!(DwInterruptInfoV1, binding_generation), 24);
    assert_eq!(offset_of!(DwInterruptInfoV1, parent_resource_id), 32);
    assert_eq!(offset_of!(DwInterruptInfoV1, parent_lease_generation), 40);
    assert_eq!(offset_of!(DwInterruptInfoV1, flags), 48);
    assert_eq!(offset_of!(DwInterruptInfoV1, reserved), 56);
}

#[test]
fn d1_device_syscall_namespace_is_exact_and_staged_after_dw0() {
    for (known, id, arguments) in [
        (
            DwKnownSyscall::DeviceResourceClaim,
            DW_SYSCALL_DEVICE_RESOURCE_CLAIM,
            4,
        ),
        (DwKnownSyscall::DevicePioRead, DW_SYSCALL_DEVICE_PIO_READ, 4),
        (
            DwKnownSyscall::DevicePioWrite,
            DW_SYSCALL_DEVICE_PIO_WRITE,
            4,
        ),
        (
            DwKnownSyscall::InterruptCreate,
            DW_SYSCALL_INTERRUPT_CREATE,
            3,
        ),
        (DwKnownSyscall::InterruptAck, DW_SYSCALL_INTERRUPT_ACK, 1),
    ] {
        assert_eq!(DwKnownSyscall::from_id(id), Some(known));
        assert_eq!(known.id(), id);
        assert_eq!(known.argument_count(), arguments);
        assert_eq!(
            known.implementation_phase(),
            DwSyscallImplementationPhase::Dw1D
        );
        assert!(
            !known
                .implementation_phase()
                .is_active_through(DwSyscallImplementationPhase::Dw0H)
        );
    }

    assert_eq!(DW_SYSCALL_DEVICE_RESOURCE_CLAIM.0, 0x0006_0001);
    assert_eq!(DW_SYSCALL_DEVICE_PIO_READ.0, 0x0006_0002);
    assert_eq!(DW_SYSCALL_DEVICE_PIO_WRITE.0, 0x0006_0003);
    assert_eq!(DW_SYSCALL_INTERRUPT_CREATE.0, 0x0006_0010);
    assert_eq!(DW_SYSCALL_INTERRUPT_ACK.0, 0x0006_0011);
}
