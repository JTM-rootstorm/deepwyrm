extern crate std;

use super::*;

fn args(values: [u64; 6]) -> RawSyscallArguments {
    RawSyscallArguments::new(values)
}

#[test]
fn every_schema_active_through_f_has_a_typed_request() {
    let active = [
        DwKnownSyscall::AbiGetInfo,
        DwKnownSyscall::HandleClose,
        DwKnownSyscall::HandleDuplicate,
        DwKnownSyscall::ObjectGetInfoV1,
        DwKnownSyscall::TaskGroupCreate,
        DwKnownSyscall::TaskGroupTerminate,
        DwKnownSyscall::ProcessExit,
        DwKnownSyscall::ProcessTerminate,
        DwKnownSyscall::ThreadCreate,
        DwKnownSyscall::ThreadStart,
        DwKnownSyscall::ThreadExit,
        DwKnownSyscall::ThreadTerminate,
        DwKnownSyscall::MemoryObjectCreate,
        DwKnownSyscall::AddressRegionMap,
        DwKnownSyscall::AddressRegionUnmap,
        DwKnownSyscall::AddressRegionProtect,
        DwKnownSyscall::ProcessCreate,
        DwKnownSyscall::ChannelCreate,
        DwKnownSyscall::ChannelSend,
        DwKnownSyscall::ChannelReceive,
        DwKnownSyscall::WaitOne,
        DwKnownSyscall::WaitMany,
        DwKnownSyscall::EventCreate,
        DwKnownSyscall::EventSignal,
        DwKnownSyscall::AtomicWait32,
        DwKnownSyscall::AtomicWake,
        DwKnownSyscall::ClockGet,
        DwKnownSyscall::TimerCreate,
        DwKnownSyscall::TimerSet,
        DwKnownSyscall::TimerCancel,
    ];
    for syscall in active {
        assert!(
            decode_native(syscall.id(), args([0; 6])).is_ok(),
            "missing typed F request for {syscall:?}"
        );
    }
}

#[test]
fn unknown_syscalls_remain_not_supported() {
    assert_eq!(
        decode_native(DwSyscallId(0xffff_fffe), args([0; 6])),
        Err(DW_STATUS_NOT_SUPPORTED)
    );
}

#[test]
fn narrow_scalar_arguments_reject_nonzero_upper_bits() {
    assert_eq!(
        decode_native(
            DwKnownSyscall::ProcessExit.id(),
            args([u64::from(u32::MAX) + 1, 0, 0, 0, 0, 0]),
        ),
        Err(DW_STATUS_INVALID_ARGUMENT)
    );
}
#[test]
fn typed_requests_preserve_raw_register_order() {
    assert_eq!(
        decode_native(
            DwKnownSyscall::AddressRegionProtect.id(),
            args([11, 22, 33, 4, 0, 0]),
        ),
        Ok(NativeSyscallRequest::AddressRegionProtect {
            address_region: DwHandle(11),
            address: DwUserAddress(22),
            byte_len: 33,
            protections: 4,
        })
    );
}

#[test]
fn f_typed_requests_preserve_register_widths_and_order() {
    assert_eq!(
        decode_native(
            DwKnownSyscall::ChannelSend.id(),
            args([11, 22, 33, 44, 5, 66]),
        ),
        Ok(NativeSyscallRequest::ChannelSend {
            channel: DwHandle(11),
            bytes: DwUserAddress(22),
            byte_len: 33,
            transfers: DwUserAddress(44),
            transfer_count: 5,
            flags: 66,
        })
    );
    assert_eq!(
        decode_native(
            DwKnownSyscall::WaitMany.id(),
            args([0x1000, 7, 0, 99, 0x2000, 0]),
        ),
        Ok(NativeSyscallRequest::WaitMany {
            items: DwUserAddress(0x1000),
            item_count: 7,
            mode: 0,
            deadline: DwDeadline(99),
            out_result: DwUserAddress(0x2000),
        })
    );
    assert_eq!(
        decode_native(DwKnownSyscall::ClockGet.id(), args([3, 0x3000, 0, 0, 0, 0]),),
        Ok(NativeSyscallRequest::ClockGet {
            clock_id: DwClockId(3),
            out_nanoseconds: DwUserAddress(0x3000),
        })
    );
}

#[test]
fn f_narrow_scalars_reject_upper_bits_before_handler_dispatch() {
    let over = u64::from(u32::MAX) + 1;
    for (syscall, arguments) in [
        (DwKnownSyscall::ChannelSend, [1, 2, over, 4, 0, 0]),
        (DwKnownSyscall::WaitMany, [1, over, 0, 0, 0, 0]),
        (DwKnownSyscall::AtomicWake, [1, over, 0, 0, 0, 0]),
        (DwKnownSyscall::ClockGet, [over, 0, 0, 0, 0, 0]),
    ] {
        assert_eq!(
            decode_native(syscall.id(), args(arguments)),
            Err(DW_STATUS_INVALID_ARGUMENT),
            "{syscall:?} accepted non-u32 scalar bits"
        );
    }
}

struct RecordingHandler {
    last: Option<NativeSyscallRequest>,
}

impl NativeSyscallHandler for RecordingHandler {
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        self.last = Some(request);
        NativeSyscallResult {
            status: deepwyrm_abi::DW_STATUS_SUCCESS,
            control: SyscallControl::ReturnToCaller,
        }
    }
}

#[test]
fn dispatch_routes_typed_requests_and_handles_decode_failures_locally() {
    let mut handler = RecordingHandler { last: None };
    let success = dispatch_native(
        &mut handler,
        DwKnownSyscall::HandleClose.id(),
        args([0x55, 0, 0, 0, 0, 0]),
    );
    assert_eq!(success.status, deepwyrm_abi::DW_STATUS_SUCCESS);
    assert_eq!(
        handler.last,
        Some(NativeSyscallRequest::HandleClose {
            handle: DwHandle(0x55)
        })
    );
    handler.last = None;
    let rejected = dispatch_native(&mut handler, DwSyscallId(0xffff_fffe), args([0; 6]));
    assert_eq!(rejected.status, DW_STATUS_NOT_SUPPORTED);
    assert_eq!(rejected.control, SyscallControl::ReturnToCaller);
    assert_eq!(handler.last, None);
}

struct FrameRuntime {
    handled: usize,
    executable: bool,
    writable_stack: bool,
}

impl NativeSyscallHandler for FrameRuntime {
    fn handle(&mut self, _request: NativeSyscallRequest) -> NativeSyscallResult {
        self.handled += 1;
        NativeSyscallResult::returning(deepwyrm_abi::DW_STATUS_SUCCESS)
    }
}

impl crate::arch::x86_64::syscall::UserReturnMappingValidation for FrameRuntime {
    fn executable_at(&mut self, _instruction_pointer: u64) -> bool {
        self.executable
    }

    fn writable_byte_below(&mut self, _stack_pointer: u64) -> bool {
        self.writable_stack
    }
}
impl NativeSyscallFrameRuntime for FrameRuntime {
    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        frame.authorize_return(current_binding_generation, self)
    }

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) -> ! {
        panic!("invalid synthetic return: {error:?}")
    }

    fn reschedule(&mut self) -> ! {
        panic!("unexpected synthetic reschedule")
    }
}

#[test]
fn frame_dispatch_sets_status_then_authorizes_exact_return() {
    let mut runtime = FrameRuntime {
        handled: 0,
        executable: true,
        writable_stack: true,
    };
    let mut frame = crate::arch::x86_64::syscall::RawSyscallFrame::synthetic(
        u64::from(DwKnownSyscall::HandleClose.id().0),
        [0x77, 0, 0, 0, 0, 0],
        0x4000,
        0x8000,
        u64::MAX,
        9,
    );
    dispatch_frame(&mut runtime, &mut frame, 9);
    assert_eq!(runtime.handled, 1);
    assert_eq!(frame.test_status_bits(), 0);
    assert_eq!(frame.test_return_authorized(), 1);
}

#[test]
fn frame_dispatch_fails_stopped_when_binding_generation_changes() {
    let mut runtime = FrameRuntime {
        handled: 0,
        executable: true,
        writable_stack: true,
    };
    let mut frame = crate::arch::x86_64::syscall::RawSyscallFrame::synthetic(
        u64::from(DwKnownSyscall::HandleClose.id().0),
        [0x77, 0, 0, 0, 0, 0],
        0x4000,
        0x8000,
        0x202,
        9,
    );
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch_frame(&mut runtime, &mut frame, 10);
    }));
    assert!(failed.is_err());
    assert_eq!(runtime.handled, 1);
    assert_eq!(frame.test_return_authorized(), 0);
}
