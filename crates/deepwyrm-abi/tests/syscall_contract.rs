use deepwyrm_abi::{
    DW_SYSCALL_DEVICE_RESOURCE_CLAIM, DW_SYSCALL_HANDLE_CLOSE, DW_SYSCALL_INTERRUPT_ACK,
    DW_SYSCALL_PROCESS_CREATE, DW_SYSCALL_PROCESS_EXIT, DW_SYSCALL_PROCESS_TERMINATE,
    DW_SYSCALL_TASK_GROUP_CREATE, DW_SYSCALL_TASK_GROUP_TERMINATE, DW_SYSCALL_THREAD_CREATE,
    DW_SYSCALL_THREAD_EXIT, DW_SYSCALL_THREAD_START, DW_SYSCALL_THREAD_TERMINATE, DwKnownSyscall,
    DwSyscallId, DwSyscallImplementationPhase,
};

#[allow(dead_code)]
mod wrapper_metadata {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../abi/generated/syscall_wrappers.rs"
    ));
}

#[test]
fn string_free_kernel_dispatch_decodes_ids_and_phases() {
    assert_eq!(
        DwKnownSyscall::from_id(DW_SYSCALL_TASK_GROUP_CREATE),
        Some(DwKnownSyscall::TaskGroupCreate)
    );
    assert_eq!(
        DwKnownSyscall::from_id(DW_SYSCALL_HANDLE_CLOSE),
        Some(DwKnownSyscall::HandleClose)
    );
    assert_eq!(DwKnownSyscall::from_id(DwSyscallId(0x1234_5678)), None);
    assert_eq!(
        DwKnownSyscall::ProcessCreate.implementation_phase(),
        DwSyscallImplementationPhase::Dw0F
    );
    assert!(
        DwKnownSyscall::ThreadStart
            .implementation_phase()
            .is_active_through(DwSyscallImplementationPhase::Dw0E)
    );
    assert!(
        !DwKnownSyscall::ProcessCreate
            .implementation_phase()
            .is_active_through(DwSyscallImplementationPhase::Dw0E)
    );
    assert_eq!(DwKnownSyscall::ThreadStart.id(), DW_SYSCALL_THREAD_START);
    assert_eq!(DwKnownSyscall::ThreadStart.argument_count(), 2);
    assert_eq!(
        DwKnownSyscall::ProcessCreate.id(),
        DW_SYSCALL_PROCESS_CREATE
    );
    assert_eq!(
        DwKnownSyscall::DeviceResourceClaim.implementation_phase(),
        DwSyscallImplementationPhase::Dw1D
    );
    assert!(
        !DwKnownSyscall::DeviceResourceClaim
            .implementation_phase()
            .is_active_through(DwSyscallImplementationPhase::Dw0H)
    );
}

#[test]
fn wrapper_metadata_locks_e_argument_registers_and_authority() {
    let parent = wrapper_metadata::DW_SYSCALL_ARGUMENT_METADATA
        .iter()
        .find(|argument| {
            argument.syscall_number == DW_SYSCALL_TASK_GROUP_CREATE.0 && argument.name == "parent"
        })
        .unwrap();
    assert_eq!(parent.index, 0);
    assert_eq!(parent.register, "RDI");
    assert_eq!(parent.abi_type, "DwHandle");
    assert_eq!(parent.required_object_type, "TASK_GROUP");
    assert_eq!(parent.required_rights, "MODIFY");

    let start_size = wrapper_metadata::DW_SYSCALL_ARGUMENT_METADATA
        .iter()
        .find(|argument| {
            argument.syscall_number == DW_SYSCALL_THREAD_START.0 && argument.name == "args_size"
        })
        .unwrap();
    assert_eq!(start_size.index, 1);
    assert_eq!(start_size.register, "RSI");
    assert_eq!(start_size.abi_type, "u64");

    let claim_domain = wrapper_metadata::DW_SYSCALL_ARGUMENT_METADATA
        .iter()
        .find(|argument| {
            argument.syscall_number == DW_SYSCALL_DEVICE_RESOURCE_CLAIM.0
                && argument.name == "resource_domain"
        })
        .unwrap();
    assert_eq!(claim_domain.index, 0);
    assert_eq!(claim_domain.required_object_type, "TASK_GROUP");
    assert_eq!(claim_domain.required_rights, "RESOURCE");

    let interrupt = wrapper_metadata::DW_SYSCALL_ARGUMENT_METADATA
        .iter()
        .find(|argument| {
            argument.syscall_number == DW_SYSCALL_INTERRUPT_ACK.0 && argument.name == "interrupt"
        })
        .unwrap();
    assert_eq!(interrupt.required_object_type, "INTERRUPT");
    assert_eq!(interrupt.required_rights, "MODIFY");
}

#[test]
fn e_task_syscall_numbers_remain_canonical() {
    for (actual, expected) in [
        (DW_SYSCALL_TASK_GROUP_CREATE.0, 0x0001_0001),
        (DW_SYSCALL_TASK_GROUP_TERMINATE.0, 0x0001_0002),
        (DW_SYSCALL_PROCESS_CREATE.0, 0x0001_0010),
        (DW_SYSCALL_PROCESS_EXIT.0, 0x0001_0011),
        (DW_SYSCALL_PROCESS_TERMINATE.0, 0x0001_0012),
        (DW_SYSCALL_THREAD_CREATE.0, 0x0001_0020),
        (DW_SYSCALL_THREAD_START.0, 0x0001_0021),
        (DW_SYSCALL_THREAD_EXIT.0, 0x0001_0022),
        (DW_SYSCALL_THREAD_TERMINATE.0, 0x0001_0023),
    ] {
        assert_eq!(actual, expected);
    }
}

#[test]
fn no_std_boundary_includes_only_string_free_dispatch_material() {
    let crate_source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(crate_source.contains("syscall_kernel.rs"));
    assert!(!crate_source.contains("syscall_dispatch.rs"));
    assert!(!crate_source.contains("syscall_wrappers.rs"));
}
