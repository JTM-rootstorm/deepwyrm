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
fn d1_device_syscalls_remain_inactive_before_runtime_implementation() {
    for syscall in [
        DwKnownSyscall::DeviceResourceClaim,
        DwKnownSyscall::DevicePioRead,
        DwKnownSyscall::DevicePioWrite,
        DwKnownSyscall::InterruptCreate,
        DwKnownSyscall::InterruptAck,
    ] {
        assert_eq!(
            decode_native(syscall.id(), args([0; 6])),
            Err(DW_STATUS_NOT_SUPPORTED)
        );
    }
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
            DwKnownSyscall::ProcessCreate.id(),
            args([0x11, 88, 0x2200, 64, 0, 0]),
        ),
        Ok(NativeSyscallRequest::ProcessCreate {
            args: DwUserAddress(0x11),
            args_size: 88,
            out_result: DwUserAddress(0x2200),
            result_size: 64,
        })
    );
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
    invalid_return: Option<crate::arch::x86_64::syscall::UserReturnError>,
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
#[allow(
    unsafe_code,
    reason = "the host fixture implements the runtime suspension boundary without producing a live plan"
)]
impl NativeSyscallFrameRuntime for FrameRuntime {
    #[cfg(deepwyrm_dw1b_evidence)]
    fn intercept_dw1b_evidence_raw(
        &mut self,
        _arguments: RawSyscallArguments,
    ) -> NativeSyscallResult {
        panic!("host frame fixture must not intercept selector-26 evidence")
    }

    #[cfg(deepwyrm_wyr1b_evidence)]
    fn intercept_wyr1b_evidence_raw(
        &mut self,
        _arguments: RawSyscallArguments,
    ) -> NativeSyscallResult {
        panic!("host frame fixture must not intercept selector-27 evidence")
    }

    #[cfg(deepwyrm_wyr1_evidence)]
    fn intercept_wyr1_evidence_raw(
        &mut self,
        _arguments: RawSyscallArguments,
    ) -> NativeSyscallResult {
        panic!("host frame fixture must not intercept selector-25 evidence")
    }

    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        frame.authorize_return(current_binding_generation, self)
    }

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) {
        assert!(self.invalid_return.replace(error).is_none());
    }

    fn user_exception(&mut self, _record: crate::arch::x86_64::exceptions::UserExceptionRecord) {
        panic!("unexpected synthetic user exception")
    }

    fn terminate_current(&mut self) -> ! {
        panic!("unexpected synthetic termination")
    }

    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        panic!("unexpected synthetic fresh-thread entry")
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeSuspendPlan<'owner> {
        panic!("unexpected synthetic suspension")
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeIdleSuspendPoll<'owner> {
        panic!("unexpected synthetic idle suspension")
    }

    fn resume_suspended(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeResumeOutcome {
        panic!("unexpected synthetic resume")
    }
}

#[test]
fn frame_dispatch_sets_status_then_authorizes_exact_return() {
    let mut runtime = FrameRuntime {
        handled: 0,
        executable: true,
        writable_stack: true,
        invalid_return: None,
    };
    let mut frame = crate::arch::x86_64::syscall::RawSyscallFrame::synthetic(
        u64::from(DwKnownSyscall::HandleClose.id().0),
        [0x77, 0, 0, 0, 0, 0],
        0x4000,
        0x8000,
        u64::MAX,
        9,
    );
    assert_eq!(
        dispatch_frame(&mut runtime, &mut frame, 9),
        SyscallControl::ReturnToCaller
    );
    assert_eq!(runtime.handled, 1);
    assert_eq!(frame.test_status_bits(), 0);
    assert_eq!(frame.test_return_authorized(), 1);
}

#[test]
fn frame_dispatch_turns_invalid_return_into_terminal_control_without_panicking() {
    let mut runtime = FrameRuntime {
        handled: 0,
        executable: true,
        writable_stack: true,
        invalid_return: None,
    };
    let mut frame = crate::arch::x86_64::syscall::RawSyscallFrame::synthetic(
        u64::from(DwKnownSyscall::HandleClose.id().0),
        [0x77, 0, 0, 0, 0, 0],
        0x4000,
        0x8000,
        0x202,
        9,
    );
    assert_eq!(
        dispatch_frame(&mut runtime, &mut frame, 10),
        SyscallControl::TerminateCurrent
    );
    assert_eq!(runtime.handled, 1);
    assert_eq!(frame.test_return_authorized(), 0);
    assert_eq!(
        runtime.invalid_return,
        Some(crate::arch::x86_64::syscall::UserReturnError::BindingChanged)
    );
}

struct SuspendingRuntime;

impl NativeSyscallHandler for SuspendingRuntime {
    fn handle(&mut self, _request: NativeSyscallRequest) -> NativeSyscallResult {
        NativeSyscallResult {
            status: deepwyrm_abi::DW_STATUS_SUCCESS,
            control: SyscallControl::SuspendCurrent,
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the host fixture implements the runtime suspension boundary without producing a live plan"
)]
impl NativeSyscallFrameRuntime for SuspendingRuntime {
    #[cfg(deepwyrm_dw1b_evidence)]
    fn intercept_dw1b_evidence_raw(
        &mut self,
        _arguments: RawSyscallArguments,
    ) -> NativeSyscallResult {
        panic!("suspending host fixture must not intercept selector-26 evidence")
    }

    #[cfg(deepwyrm_wyr1b_evidence)]
    fn intercept_wyr1b_evidence_raw(
        &mut self,
        _arguments: RawSyscallArguments,
    ) -> NativeSyscallResult {
        panic!("suspending host fixture must not intercept selector-27 evidence")
    }

    #[cfg(deepwyrm_wyr1_evidence)]
    fn intercept_wyr1_evidence_raw(
        &mut self,
        _arguments: RawSyscallArguments,
    ) -> NativeSyscallResult {
        panic!("suspending host fixture must not intercept selector-25 evidence")
    }

    fn authorize_return(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        _current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        panic!("suspended dispatch must not authorize before resume")
    }

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) {
        panic!("unexpected invalid suspended return: {error:?}")
    }

    fn user_exception(&mut self, _record: crate::arch::x86_64::exceptions::UserExceptionRecord) {
        panic!("unexpected suspended user exception")
    }

    fn terminate_current(&mut self) -> ! {
        panic!("suspended dispatch must not terminate")
    }

    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        panic!("direct dispatch test never launches a fresh Thread")
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeSuspendPlan<'owner> {
        panic!("direct dispatch test stops before trampoline suspension")
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeIdleSuspendPoll<'owner> {
        panic!("direct dispatch test never enters idle suspension")
    }

    fn resume_suspended(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeResumeOutcome {
        panic!("direct dispatch test never resumes")
    }
}

#[test]
fn suspended_dispatch_returns_control_without_authorizing_the_user_frame() {
    let mut runtime = SuspendingRuntime;
    let mut frame = crate::arch::x86_64::syscall::RawSyscallFrame::synthetic(
        u64::from(DwKnownSyscall::HandleClose.id().0),
        [0x55, 0, 0, 0, 0, 0],
        0x4000,
        0x8000,
        0x202,
        3,
    );
    assert_eq!(
        dispatch_frame(&mut runtime, &mut frame, 3),
        SyscallControl::SuspendCurrent
    );
    assert_eq!(frame.test_status_bits(), 0);
    assert_eq!(frame.test_return_authorized(), 0);
}
