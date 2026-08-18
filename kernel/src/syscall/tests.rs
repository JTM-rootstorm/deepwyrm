use deepwyrm_abi::{
    DW_STATUS_NOT_SUPPORTED, DW_SYSCALL_ABI_GET_INFO, DW_SYSCALL_ADDRESS_REGION_MAP,
    DW_SYSCALL_CHANNEL_CREATE, DW_SYSCALL_HANDLE_CLOSE, DW_SYSCALL_PROCESS_CREATE,
    DW_SYSCALL_PROCESS_EXIT, DW_SYSCALL_TASK_GROUP_CREATE, DW_SYSCALL_THREAD_START, DwKnownSyscall,
    DwSyscallId,
};

use super::{RawSyscallArguments, decode};

const ARGUMENTS: RawSyscallArguments =
    RawSyscallArguments::new([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

#[test]
fn schema_known_syscalls_through_e_decode_without_private_number_tables() {
    for (id, expected) in [
        (DW_SYSCALL_ABI_GET_INFO, DwKnownSyscall::AbiGetInfo),
        (DW_SYSCALL_HANDLE_CLOSE, DwKnownSyscall::HandleClose),
        (
            DW_SYSCALL_ADDRESS_REGION_MAP,
            DwKnownSyscall::AddressRegionMap,
        ),
        (
            DW_SYSCALL_TASK_GROUP_CREATE,
            DwKnownSyscall::TaskGroupCreate,
        ),
        (DW_SYSCALL_PROCESS_EXIT, DwKnownSyscall::ProcessExit),
        (DW_SYSCALL_THREAD_START, DwKnownSyscall::ThreadStart),
    ] {
        let decoded = decode(id, ARGUMENTS).unwrap();
        assert_eq!(decoded.identity(), expected);
        assert_eq!(decoded.arguments().as_array(), ARGUMENTS.as_array());
    }
}

#[test]
fn unknown_and_post_e_syscalls_fail_with_not_supported() {
    for id in [
        DwSyscallId(0),
        DwSyscallId(0x1234_5678),
        DwSyscallId(0xffff_0000),
        DW_SYSCALL_PROCESS_CREATE,
        DW_SYSCALL_CHANNEL_CREATE,
    ] {
        assert_eq!(decode(id, ARGUMENTS), Err(DW_STATUS_NOT_SUPPORTED));
    }
}

#[test]
fn raw_arguments_preserve_all_six_abi_slots_without_interpretation() {
    for (index, expected) in ARGUMENTS.as_array().into_iter().enumerate() {
        assert_eq!(ARGUMENTS.get(index), Some(expected));
    }
    assert_eq!(ARGUMENTS.get(6), None);
    assert_eq!(ARGUMENTS.get(usize::MAX), None);
}
