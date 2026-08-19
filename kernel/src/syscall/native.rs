use deepwyrm_abi::{
    DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NOT_SUPPORTED, DwClockId, DwDeadline, DwHandle,
    DwKnownSyscall, DwRights, DwSignals, DwStatus, DwSyscallId, DwTerminationReason, DwUserAddress,
};

use super::{DecodedSyscall, RawSyscallArguments, decode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeSyscallRequest {
    AbiGetInfo {
        out_info: DwUserAddress,
        out_size: u64,
        out_required_size: DwUserAddress,
    },
    HandleClose {
        handle: DwHandle,
    },
    HandleDuplicate {
        handle: DwHandle,
        requested_rights: DwRights,
        out_handle: DwUserAddress,
    },
    ObjectGetInfoV1 {
        handle: DwHandle,
        topic: u32,
        out_info: DwUserAddress,
        out_size: u64,
        out_required_size: DwUserAddress,
    },
    TaskGroupCreate {
        parent: DwHandle,
        requested_rights: DwRights,
        out_handle: DwUserAddress,
    },
    TaskGroupTerminate {
        task_group: DwHandle,
        reason: DwTerminationReason,
    },
    ProcessCreate {
        args: DwUserAddress,
        args_size: u64,
        out_result: DwUserAddress,
        result_size: u64,
    },
    ProcessExit {
        exit_code: u32,
    },
    ProcessTerminate {
        process: DwHandle,
        reason: DwTerminationReason,
        code: u32,
    },
    ThreadCreate {
        process: DwHandle,
        requested_rights: DwRights,
        out_thread: DwUserAddress,
    },
    ThreadStart {
        args: DwUserAddress,
        args_size: u64,
    },
    ThreadExit {
        exit_code: u32,
    },
    ThreadTerminate {
        thread: DwHandle,
        reason: DwTerminationReason,
        code: u32,
    },
    MemoryObjectCreate {
        byte_len: u64,
        flags: u32,
        requested_rights: DwRights,
        out_handle: DwUserAddress,
    },
    AddressRegionMap {
        address_region: DwHandle,
        memory_object: DwHandle,
        args: DwUserAddress,
        args_size: u64,
        out_address: DwUserAddress,
    },
    AddressRegionUnmap {
        address_region: DwHandle,
        address: DwUserAddress,
        byte_len: u64,
    },
    AddressRegionProtect {
        address_region: DwHandle,
        address: DwUserAddress,
        byte_len: u64,
        protections: u32,
    },
    ChannelCreate {
        requested_rights: DwRights,
        out_endpoint0: DwUserAddress,
        out_endpoint1: DwUserAddress,
    },
    ChannelSend {
        channel: DwHandle,
        bytes: DwUserAddress,
        byte_len: u32,
        transfers: DwUserAddress,
        transfer_count: u32,
        flags: u64,
    },
    ChannelReceive {
        channel: DwHandle,
        out_bytes: DwUserAddress,
        byte_capacity: u32,
        out_handles: DwUserAddress,
        handle_capacity: u32,
        out_result: DwUserAddress,
    },
    WaitOne {
        handle: DwHandle,
        signals: DwSignals,
        deadline: DwDeadline,
        out_result: DwUserAddress,
    },
    WaitMany {
        items: DwUserAddress,
        item_count: u32,
        mode: u32,
        deadline: DwDeadline,
        out_result: DwUserAddress,
    },
    EventCreate {
        requested_rights: DwRights,
        out_event: DwUserAddress,
    },
    EventSignal {
        event: DwHandle,
        clear_mask: DwSignals,
        set_mask: DwSignals,
    },
    AtomicWait32 {
        address: DwUserAddress,
        expected: u32,
        deadline: DwDeadline,
    },
    AtomicWake {
        address: DwUserAddress,
        count: u32,
        out_woken: DwUserAddress,
    },
    ClockGet {
        clock_id: DwClockId,
        out_nanoseconds: DwUserAddress,
    },
    TimerCreate {
        requested_rights: DwRights,
        out_timer: DwUserAddress,
    },
    TimerSet {
        timer: DwHandle,
        deadline: DwDeadline,
    },
    TimerCancel {
        timer: DwHandle,
    },
}

fn u32_arg(value: u64) -> Result<u32, DwStatus> {
    u32::try_from(value).map_err(|_| DW_STATUS_INVALID_ARGUMENT)
}

pub(crate) fn decode_native(
    id: DwSyscallId,
    arguments: RawSyscallArguments,
) -> Result<NativeSyscallRequest, DwStatus> {
    decode(id, arguments).and_then(decode_decoded)
}

fn decode_decoded(decoded: DecodedSyscall) -> Result<NativeSyscallRequest, DwStatus> {
    let a = decoded.arguments().as_array();
    let request = match decoded.identity() {
        DwKnownSyscall::AbiGetInfo => NativeSyscallRequest::AbiGetInfo {
            out_info: DwUserAddress(a[0]),
            out_size: a[1],
            out_required_size: DwUserAddress(a[2]),
        },
        DwKnownSyscall::HandleClose => NativeSyscallRequest::HandleClose {
            handle: DwHandle(a[0]),
        },
        DwKnownSyscall::HandleDuplicate => NativeSyscallRequest::HandleDuplicate {
            handle: DwHandle(a[0]),
            requested_rights: DwRights(a[1]),
            out_handle: DwUserAddress(a[2]),
        },
        DwKnownSyscall::ObjectGetInfoV1 => NativeSyscallRequest::ObjectGetInfoV1 {
            handle: DwHandle(a[0]),
            topic: u32_arg(a[1])?,
            out_info: DwUserAddress(a[2]),
            out_size: a[3],
            out_required_size: DwUserAddress(a[4]),
        },
        DwKnownSyscall::TaskGroupCreate => NativeSyscallRequest::TaskGroupCreate {
            parent: DwHandle(a[0]),
            requested_rights: DwRights(a[1]),
            out_handle: DwUserAddress(a[2]),
        },
        DwKnownSyscall::TaskGroupTerminate => NativeSyscallRequest::TaskGroupTerminate {
            task_group: DwHandle(a[0]),
            reason: DwTerminationReason(u32_arg(a[1])?),
        },
        DwKnownSyscall::ProcessExit => NativeSyscallRequest::ProcessExit {
            exit_code: u32_arg(a[0])?,
        },
        DwKnownSyscall::ProcessTerminate => NativeSyscallRequest::ProcessTerminate {
            process: DwHandle(a[0]),
            reason: DwTerminationReason(u32_arg(a[1])?),
            code: u32_arg(a[2])?,
        },
        DwKnownSyscall::ThreadCreate => NativeSyscallRequest::ThreadCreate {
            process: DwHandle(a[0]),
            requested_rights: DwRights(a[1]),
            out_thread: DwUserAddress(a[2]),
        },
        DwKnownSyscall::ThreadStart => NativeSyscallRequest::ThreadStart {
            args: DwUserAddress(a[0]),
            args_size: a[1],
        },
        DwKnownSyscall::ThreadExit => NativeSyscallRequest::ThreadExit {
            exit_code: u32_arg(a[0])?,
        },
        DwKnownSyscall::ThreadTerminate => NativeSyscallRequest::ThreadTerminate {
            thread: DwHandle(a[0]),
            reason: DwTerminationReason(u32_arg(a[1])?),
            code: u32_arg(a[2])?,
        },
        DwKnownSyscall::MemoryObjectCreate => NativeSyscallRequest::MemoryObjectCreate {
            byte_len: a[0],
            flags: u32_arg(a[1])?,
            requested_rights: DwRights(a[2]),
            out_handle: DwUserAddress(a[3]),
        },
        DwKnownSyscall::AddressRegionMap => NativeSyscallRequest::AddressRegionMap {
            address_region: DwHandle(a[0]),
            memory_object: DwHandle(a[1]),
            args: DwUserAddress(a[2]),
            args_size: a[3],
            out_address: DwUserAddress(a[4]),
        },
        DwKnownSyscall::AddressRegionUnmap => NativeSyscallRequest::AddressRegionUnmap {
            address_region: DwHandle(a[0]),
            address: DwUserAddress(a[1]),
            byte_len: a[2],
        },
        DwKnownSyscall::AddressRegionProtect => NativeSyscallRequest::AddressRegionProtect {
            address_region: DwHandle(a[0]),
            address: DwUserAddress(a[1]),
            byte_len: a[2],
            protections: u32_arg(a[3])?,
        },
        DwKnownSyscall::ProcessCreate => NativeSyscallRequest::ProcessCreate {
            args: DwUserAddress(a[0]),
            args_size: a[1],
            out_result: DwUserAddress(a[2]),
            result_size: a[3],
        },
        DwKnownSyscall::ChannelCreate => NativeSyscallRequest::ChannelCreate {
            requested_rights: DwRights(a[0]),
            out_endpoint0: DwUserAddress(a[1]),
            out_endpoint1: DwUserAddress(a[2]),
        },
        DwKnownSyscall::ChannelSend => NativeSyscallRequest::ChannelSend {
            channel: DwHandle(a[0]),
            bytes: DwUserAddress(a[1]),
            byte_len: u32_arg(a[2])?,
            transfers: DwUserAddress(a[3]),
            transfer_count: u32_arg(a[4])?,
            flags: a[5],
        },
        DwKnownSyscall::ChannelReceive => NativeSyscallRequest::ChannelReceive {
            channel: DwHandle(a[0]),
            out_bytes: DwUserAddress(a[1]),
            byte_capacity: u32_arg(a[2])?,
            out_handles: DwUserAddress(a[3]),
            handle_capacity: u32_arg(a[4])?,
            out_result: DwUserAddress(a[5]),
        },
        DwKnownSyscall::WaitOne => NativeSyscallRequest::WaitOne {
            handle: DwHandle(a[0]),
            signals: DwSignals(a[1]),
            deadline: DwDeadline(a[2]),
            out_result: DwUserAddress(a[3]),
        },
        DwKnownSyscall::WaitMany => NativeSyscallRequest::WaitMany {
            items: DwUserAddress(a[0]),
            item_count: u32_arg(a[1])?,
            mode: u32_arg(a[2])?,
            deadline: DwDeadline(a[3]),
            out_result: DwUserAddress(a[4]),
        },
        DwKnownSyscall::EventCreate => NativeSyscallRequest::EventCreate {
            requested_rights: DwRights(a[0]),
            out_event: DwUserAddress(a[1]),
        },
        DwKnownSyscall::EventSignal => NativeSyscallRequest::EventSignal {
            event: DwHandle(a[0]),
            clear_mask: DwSignals(a[1]),
            set_mask: DwSignals(a[2]),
        },
        DwKnownSyscall::AtomicWait32 => NativeSyscallRequest::AtomicWait32 {
            address: DwUserAddress(a[0]),
            expected: u32_arg(a[1])?,
            deadline: DwDeadline(a[2]),
        },
        DwKnownSyscall::AtomicWake => NativeSyscallRequest::AtomicWake {
            address: DwUserAddress(a[0]),
            count: u32_arg(a[1])?,
            out_woken: DwUserAddress(a[2]),
        },
        DwKnownSyscall::ClockGet => NativeSyscallRequest::ClockGet {
            clock_id: DwClockId(u32_arg(a[0])?),
            out_nanoseconds: DwUserAddress(a[1]),
        },
        DwKnownSyscall::TimerCreate => NativeSyscallRequest::TimerCreate {
            requested_rights: DwRights(a[0]),
            out_timer: DwUserAddress(a[1]),
        },
        DwKnownSyscall::TimerSet => NativeSyscallRequest::TimerSet {
            timer: DwHandle(a[0]),
            deadline: DwDeadline(a[1]),
        },
        DwKnownSyscall::TimerCancel => NativeSyscallRequest::TimerCancel {
            timer: DwHandle(a[0]),
        },
    };
    Ok(request)
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallControl {
    ReturnToCaller,
    TerminateCurrent,
    SuspendCurrent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeSyscallResult {
    pub(crate) status: DwStatus,
    pub(crate) control: SyscallControl,
}

impl NativeSyscallResult {
    pub(crate) const fn returning(status: DwStatus) -> Self {
        Self {
            status,
            control: SyscallControl::ReturnToCaller,
        }
    }
}

pub(crate) trait NativeSyscallHandler {
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult;
}

pub(crate) fn dispatch_native<H: NativeSyscallHandler>(
    handler: &mut H,
    id: DwSyscallId,
    arguments: RawSyscallArguments,
) -> NativeSyscallResult {
    match decode_native(id, arguments) {
        Ok(request) => handler.handle(request),
        Err(status) => NativeSyscallResult::returning(status),
    }
}

pub(crate) trait NativeSyscallServices {
    fn abi_get_info(
        &mut self,
        out_info: DwUserAddress,
        out_size: u64,
        out_required_size: DwUserAddress,
    ) -> NativeSyscallResult;
    fn handle_close(&mut self, handle: DwHandle) -> NativeSyscallResult;
    fn handle_duplicate(
        &mut self,
        handle: DwHandle,
        requested_rights: DwRights,
        out_handle: DwUserAddress,
    ) -> NativeSyscallResult;
    fn object_get_info_v1(
        &mut self,
        handle: DwHandle,
        topic: u32,
        out_info: DwUserAddress,
        out_size: u64,
        out_required_size: DwUserAddress,
    ) -> NativeSyscallResult;
    fn task_group_create(
        &mut self,
        parent: DwHandle,
        requested_rights: DwRights,
        out_handle: DwUserAddress,
    ) -> NativeSyscallResult;
    fn task_group_terminate(
        &mut self,
        task_group: DwHandle,
        reason: DwTerminationReason,
    ) -> NativeSyscallResult;
    fn process_exit(&mut self, exit_code: u32) -> NativeSyscallResult;
    fn process_terminate(
        &mut self,
        process: DwHandle,
        reason: DwTerminationReason,
        code: u32,
    ) -> NativeSyscallResult;
    fn thread_create(
        &mut self,
        process: DwHandle,
        requested_rights: DwRights,
        out_thread: DwUserAddress,
    ) -> NativeSyscallResult;
    fn thread_start(&mut self, args: DwUserAddress, args_size: u64) -> NativeSyscallResult;
    fn thread_exit(&mut self, exit_code: u32) -> NativeSyscallResult;
    fn thread_terminate(
        &mut self,
        thread: DwHandle,
        reason: DwTerminationReason,
        code: u32,
    ) -> NativeSyscallResult;
    fn memory_object_create(
        &mut self,
        byte_len: u64,
        flags: u32,
        requested_rights: DwRights,
        out_handle: DwUserAddress,
    ) -> NativeSyscallResult;
    fn address_region_map(
        &mut self,
        address_region: DwHandle,
        memory_object: DwHandle,
        args: DwUserAddress,
        args_size: u64,
        out_address: DwUserAddress,
    ) -> NativeSyscallResult;
    fn address_region_unmap(
        &mut self,
        address_region: DwHandle,
        address: DwUserAddress,
        byte_len: u64,
    ) -> NativeSyscallResult;
    fn address_region_protect(
        &mut self,
        address_region: DwHandle,
        address: DwUserAddress,
        byte_len: u64,
        protections: u32,
    ) -> NativeSyscallResult;
    fn process_create(
        &mut self,
        _args: DwUserAddress,
        _args_size: u64,
        _out_result: DwUserAddress,
        _result_size: u64,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn channel_create(
        &mut self,
        _requested_rights: DwRights,
        _out_endpoint0: DwUserAddress,
        _out_endpoint1: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn channel_send(
        &mut self,
        _channel: DwHandle,
        _bytes: DwUserAddress,
        _byte_len: u32,
        _transfers: DwUserAddress,
        _transfer_count: u32,
        _flags: u64,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn channel_receive(
        &mut self,
        _channel: DwHandle,
        _out_bytes: DwUserAddress,
        _byte_capacity: u32,
        _out_handles: DwUserAddress,
        _handle_capacity: u32,
        _out_result: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn wait_one(
        &mut self,
        _handle: DwHandle,
        _signals: DwSignals,
        _deadline: DwDeadline,
        _out_result: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn wait_many(
        &mut self,
        _items: DwUserAddress,
        _item_count: u32,
        _mode: u32,
        _deadline: DwDeadline,
        _out_result: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn event_create(
        &mut self,
        _requested_rights: DwRights,
        _out_event: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn event_signal(
        &mut self,
        _event: DwHandle,
        _clear_mask: DwSignals,
        _set_mask: DwSignals,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn atomic_wait32(
        &mut self,
        _address: DwUserAddress,
        _expected: u32,
        _deadline: DwDeadline,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn atomic_wake(
        &mut self,
        _address: DwUserAddress,
        _count: u32,
        _out_woken: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn clock_get(
        &mut self,
        _clock_id: DwClockId,
        _out_nanoseconds: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn timer_create(
        &mut self,
        _requested_rights: DwRights,
        _out_timer: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn timer_set(&mut self, _timer: DwHandle, _deadline: DwDeadline) -> NativeSyscallResult {
        unsupported_f()
    }
    fn timer_cancel(&mut self, _timer: DwHandle) -> NativeSyscallResult {
        unsupported_f()
    }
}

const fn unsupported_f() -> NativeSyscallResult {
    NativeSyscallResult::returning(DW_STATUS_NOT_SUPPORTED)
}

impl<T: NativeSyscallServices> NativeSyscallHandler for T {
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        match request {
            NativeSyscallRequest::AbiGetInfo {
                out_info,
                out_size,
                out_required_size,
            } => self.abi_get_info(out_info, out_size, out_required_size),
            NativeSyscallRequest::HandleClose { handle } => self.handle_close(handle),
            NativeSyscallRequest::HandleDuplicate {
                handle,
                requested_rights,
                out_handle,
            } => self.handle_duplicate(handle, requested_rights, out_handle),
            NativeSyscallRequest::ObjectGetInfoV1 {
                handle,
                topic,
                out_info,
                out_size,
                out_required_size,
            } => self.object_get_info_v1(handle, topic, out_info, out_size, out_required_size),
            NativeSyscallRequest::TaskGroupCreate {
                parent,
                requested_rights,
                out_handle,
            } => self.task_group_create(parent, requested_rights, out_handle),
            NativeSyscallRequest::TaskGroupTerminate { task_group, reason } => {
                self.task_group_terminate(task_group, reason)
            }
            NativeSyscallRequest::ProcessExit { exit_code } => self.process_exit(exit_code),
            NativeSyscallRequest::ProcessTerminate {
                process,
                reason,
                code,
            } => self.process_terminate(process, reason, code),
            NativeSyscallRequest::ThreadCreate {
                process,
                requested_rights,
                out_thread,
            } => self.thread_create(process, requested_rights, out_thread),
            NativeSyscallRequest::ThreadStart { args, args_size } => {
                self.thread_start(args, args_size)
            }
            NativeSyscallRequest::ThreadExit { exit_code } => self.thread_exit(exit_code),
            NativeSyscallRequest::ThreadTerminate {
                thread,
                reason,
                code,
            } => self.thread_terminate(thread, reason, code),
            NativeSyscallRequest::MemoryObjectCreate {
                byte_len,
                flags,
                requested_rights,
                out_handle,
            } => self.memory_object_create(byte_len, flags, requested_rights, out_handle),
            NativeSyscallRequest::AddressRegionMap {
                address_region,
                memory_object,
                args,
                args_size,
                out_address,
            } => {
                self.address_region_map(address_region, memory_object, args, args_size, out_address)
            }
            NativeSyscallRequest::AddressRegionUnmap {
                address_region,
                address,
                byte_len,
            } => self.address_region_unmap(address_region, address, byte_len),
            NativeSyscallRequest::AddressRegionProtect {
                address_region,
                address,
                byte_len,
                protections,
            } => self.address_region_protect(address_region, address, byte_len, protections),
            NativeSyscallRequest::ProcessCreate {
                args,
                args_size,
                out_result,
                result_size,
            } => self.process_create(args, args_size, out_result, result_size),
            NativeSyscallRequest::ChannelCreate {
                requested_rights,
                out_endpoint0,
                out_endpoint1,
            } => self.channel_create(requested_rights, out_endpoint0, out_endpoint1),
            NativeSyscallRequest::ChannelSend {
                channel,
                bytes,
                byte_len,
                transfers,
                transfer_count,
                flags,
            } => self.channel_send(channel, bytes, byte_len, transfers, transfer_count, flags),
            NativeSyscallRequest::ChannelReceive {
                channel,
                out_bytes,
                byte_capacity,
                out_handles,
                handle_capacity,
                out_result,
            } => self.channel_receive(
                channel,
                out_bytes,
                byte_capacity,
                out_handles,
                handle_capacity,
                out_result,
            ),
            NativeSyscallRequest::WaitOne {
                handle,
                signals,
                deadline,
                out_result,
            } => self.wait_one(handle, signals, deadline, out_result),
            NativeSyscallRequest::WaitMany {
                items,
                item_count,
                mode,
                deadline,
                out_result,
            } => self.wait_many(items, item_count, mode, deadline, out_result),
            NativeSyscallRequest::EventCreate {
                requested_rights,
                out_event,
            } => self.event_create(requested_rights, out_event),
            NativeSyscallRequest::EventSignal {
                event,
                clear_mask,
                set_mask,
            } => self.event_signal(event, clear_mask, set_mask),
            NativeSyscallRequest::AtomicWait32 {
                address,
                expected,
                deadline,
            } => self.atomic_wait32(address, expected, deadline),
            NativeSyscallRequest::AtomicWake {
                address,
                count,
                out_woken,
            } => self.atomic_wake(address, count, out_woken),
            NativeSyscallRequest::ClockGet {
                clock_id,
                out_nanoseconds,
            } => self.clock_get(clock_id, out_nanoseconds),
            NativeSyscallRequest::TimerCreate {
                requested_rights,
                out_timer,
            } => self.timer_create(requested_rights, out_timer),
            NativeSyscallRequest::TimerSet { timer, deadline } => self.timer_set(timer, deadline),
            NativeSyscallRequest::TimerCancel { timer } => self.timer_cancel(timer),
        }
    }
}

pub(crate) trait NativeSyscallFrameRuntime: NativeSyscallHandler {
    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError>;

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) -> !;

    fn terminate_current(&mut self) -> !;

    fn prepare_suspend(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::arch::x86_64::context::KernelSwitchPlan;

    fn resume_suspended(&mut self, frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame);
}

pub(crate) fn dispatch_frame<R: NativeSyscallFrameRuntime>(
    runtime: &mut R,
    frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    current_binding_generation: u64,
) -> SyscallControl {
    let result = match frame.request() {
        Some((id, arguments)) => dispatch_native(runtime, id, arguments),
        None => NativeSyscallResult::returning(DW_STATUS_INVALID_ARGUMENT),
    };
    frame.set_status(result.status);
    if result.control == SyscallControl::ReturnToCaller
        && let Err(error) = runtime.authorize_return(frame, current_binding_generation)
    {
        runtime.invalid_return(error);
    }
    result.control
}
