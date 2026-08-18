use deepwyrm_abi::{
    DW_SYSCALL_HANDLE_CLOSE, DW_SYSCALL_PROCESS_CREATE, DW_SYSCALL_TASK_GROUP_CREATE,
    DW_SYSCALL_THREAD_START, DwKnownSyscall, DwSyscallId, DwSyscallImplementationPhase,
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
}
