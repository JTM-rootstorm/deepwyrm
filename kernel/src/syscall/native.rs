use deepwyrm_abi::{
    DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NOT_SUPPORTED, DwHandle, DwKnownSyscall, DwRights,
    DwStatus, DwSyscallId, DwTerminationReason, DwUserAddress,
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
        DwKnownSyscall::ProcessCreate
        | DwKnownSyscall::ChannelCreate
        | DwKnownSyscall::ChannelSend
        | DwKnownSyscall::ChannelReceive
        | DwKnownSyscall::WaitOne
        | DwKnownSyscall::WaitMany
        | DwKnownSyscall::EventCreate
        | DwKnownSyscall::EventSignal
        | DwKnownSyscall::AtomicWait32
        | DwKnownSyscall::AtomicWake
        | DwKnownSyscall::ClockGet
        | DwKnownSyscall::TimerCreate
        | DwKnownSyscall::TimerSet
        | DwKnownSyscall::TimerCancel => return Err(DW_STATUS_NOT_SUPPORTED),
    };
    Ok(request)
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallControl {
    ReturnToCaller,
    Reschedule,
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

    fn reschedule(&mut self) -> !;
}

pub(crate) fn dispatch_frame<R: NativeSyscallFrameRuntime>(
    runtime: &mut R,
    frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    current_binding_generation: u64,
) {
    let result = match frame.request() {
        Some((id, arguments)) => dispatch_native(runtime, id, arguments),
        None => NativeSyscallResult::returning(DW_STATUS_INVALID_ARGUMENT),
    };
    frame.set_status(result.status);
    match result.control {
        SyscallControl::ReturnToCaller => {
            if let Err(error) = runtime.authorize_return(frame, current_binding_generation) {
                runtime.invalid_return(error);
            }
        }
        SyscallControl::Reschedule => runtime.reschedule(),
    }
}
