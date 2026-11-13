use deepwyrm_abi::{
    DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS, DwClockId, DwDeadline,
    DwHandle, DwKnownSyscall, DwRights, DwSignals, DwStatus, DwSyscallId, DwTerminationReason,
    DwUserAddress,
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
    TaskGroupLimit {
        task_group: DwHandle,
        class: u32,
        limit: u32,
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
    ThreadSetFsBase {
        fs_base: u64,
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
    MemoryObjectCommit {
        memory_object: DwHandle,
        offset: u64,
        byte_len: u64,
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
    DeviceResourceClaim {
        resource_domain: DwHandle,
        resource_id: u64,
        requested_rights: DwRights,
        out_resource: DwUserAddress,
    },
    DevicePioRead {
        resource: DwHandle,
        offset: u32,
        width: u32,
        out_value: DwUserAddress,
    },
    DevicePioWrite {
        resource: DwHandle,
        offset: u32,
        width: u32,
        value: u32,
    },
    DevicePciConfigRead {
        resource: DwHandle,
        offset: u32,
        width: u32,
        out_value: DwUserAddress,
    },
    DevicePciCommand {
        resource: DwHandle,
        memory_space: u32,
        bus_master: u32,
    },
    DeviceMmioObjectCreate {
        resource: DwHandle,
        bar: u32,
        requested_rights: DwRights,
        out_memory_object: DwUserAddress,
    },
    DmaMap {
        resource: DwHandle,
        memory_object: DwHandle,
        offset: u64,
        byte_len: u64,
        access: u32,
        out_iova: DwUserAddress,
    },
    DmaUnmap {
        resource: DwHandle,
        iova: u64,
        byte_len: u64,
    },
    InterruptCreate {
        resource: DwHandle,
        requested_rights: DwRights,
        out_interrupt: DwUserAddress,
    },
    InterruptAck {
        interrupt: DwHandle,
    },
}

/// One user buffer a syscall copies in or out (DW2 M6 §8.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserBuffer {
    pub(crate) address: u64,
    pub(crate) byte_len: u64,
    /// The syscall writes it.
    pub(crate) write: bool,
}

impl NativeSyscallRequest {
    /// The user buffers this request copies, as its arguments declare them,
    /// so on-demand pages under them can be filled in before any copy (DW2
    /// M6 §8.6). Every request is listed, so a new syscall must say. Each
    /// length is capped at the most the syscall ever copies, so a caller's
    /// length cannot make the fill-in walk more than that (review M6-2).
    pub(crate) fn user_buffers(&self) -> [Option<UserBuffer>; 3] {
        use deepwyrm_abi::{
            DW_ABI_INFO_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_CHANNEL_MAX_HANDLES,
            DW_CHANNEL_MAX_PAYLOAD, DW_CHANNEL_RECEIVE_RESULT_V1_SIZE, DW_HANDLE_TRANSFER_V1_SIZE,
            DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE,
            DW_RECEIVED_HANDLE_INFO_V1_SIZE, DW_THREAD_START_ARGS_V1_SIZE, DW_WAIT_ITEM_V1_SIZE,
            DW_WAIT_MANY_MAX_ITEMS, DW_WAIT_RESULT_V1_SIZE,
        };
        const INFO_MAX: u64 = {
            let object = super::abi_bytes::MAX_OBJECT_INFO_BYTES as u64;
            let abi = DW_ABI_INFO_V1_SIZE as u64;
            if object > abi { object } else { abi }
        };
        let out = |address: DwUserAddress, byte_len: u64| {
            Some(UserBuffer {
                address: address.0,
                byte_len,
                write: true,
            })
        };
        let input = |address: DwUserAddress, byte_len: u64| {
            Some(UserBuffer {
                address: address.0,
                byte_len,
                write: false,
            })
        };
        let records = |count: u32, max: u32, size: u32| u64::from(count.min(max)) * u64::from(size);
        let capped = |len: u64, max: u32| len.min(u64::from(max));
        match *self {
            Self::AbiGetInfo {
                out_info,
                out_size,
                out_required_size,
            }
            | Self::ObjectGetInfoV1 {
                out_info,
                out_size,
                out_required_size,
                ..
            } => [
                out(out_info, out_size.min(INFO_MAX)),
                out(out_required_size, 8),
                None,
            ],
            Self::HandleDuplicate { out_handle, .. }
            | Self::TaskGroupCreate { out_handle, .. }
            | Self::MemoryObjectCreate { out_handle, .. } => [out(out_handle, 8), None, None],
            Self::ThreadCreate { out_thread, .. } => [out(out_thread, 8), None, None],
            Self::EventCreate { out_event, .. } => [out(out_event, 8), None, None],
            Self::TimerCreate { out_timer, .. } => [out(out_timer, 8), None, None],
            Self::ClockGet {
                out_nanoseconds, ..
            } => [out(out_nanoseconds, 8), None, None],
            Self::DeviceResourceClaim { out_resource, .. } => [out(out_resource, 8), None, None],
            Self::DeviceMmioObjectCreate {
                out_memory_object, ..
            } => [out(out_memory_object, 8), None, None],
            Self::DmaMap { out_iova, .. } => [out(out_iova, 8), None, None],
            Self::InterruptCreate { out_interrupt, .. } => [out(out_interrupt, 8), None, None],
            Self::DevicePioRead { out_value, .. } | Self::DevicePciConfigRead { out_value, .. } => {
                [out(out_value, 4), None, None]
            }
            Self::ProcessCreate {
                args,
                args_size,
                out_result,
                result_size,
            } => [
                input(args, capped(args_size, DW_PROCESS_CREATE_ARGS_V1_SIZE)),
                out(
                    out_result,
                    capped(result_size, DW_PROCESS_CREATE_RESULT_V1_SIZE),
                ),
                None,
            ],
            Self::ThreadStart { args, args_size } => [
                input(args, capped(args_size, DW_THREAD_START_ARGS_V1_SIZE)),
                None,
                None,
            ],
            Self::AddressRegionMap {
                args,
                args_size,
                out_address,
                ..
            } => [
                input(args, capped(args_size, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE)),
                out(out_address, 8),
                None,
            ],
            Self::ChannelCreate {
                out_endpoint0,
                out_endpoint1,
                ..
            } => [out(out_endpoint0, 8), out(out_endpoint1, 8), None],
            Self::ChannelSend {
                bytes,
                byte_len,
                transfers,
                transfer_count,
                ..
            } => [
                input(bytes, capped(u64::from(byte_len), DW_CHANNEL_MAX_PAYLOAD)),
                input(
                    transfers,
                    records(
                        transfer_count,
                        DW_CHANNEL_MAX_HANDLES,
                        DW_HANDLE_TRANSFER_V1_SIZE,
                    ),
                ),
                None,
            ],
            Self::ChannelReceive {
                out_bytes,
                byte_capacity,
                out_handles,
                handle_capacity,
                out_result,
                ..
            } => [
                out(
                    out_bytes,
                    capped(u64::from(byte_capacity), DW_CHANNEL_MAX_PAYLOAD),
                ),
                out(
                    out_handles,
                    records(
                        handle_capacity,
                        DW_CHANNEL_MAX_HANDLES,
                        DW_RECEIVED_HANDLE_INFO_V1_SIZE,
                    ),
                ),
                out(out_result, u64::from(DW_CHANNEL_RECEIVE_RESULT_V1_SIZE)),
            ],
            Self::WaitOne { out_result, .. } => [
                out(out_result, u64::from(DW_WAIT_RESULT_V1_SIZE)),
                None,
                None,
            ],
            Self::WaitMany {
                items,
                item_count,
                out_result,
                ..
            } => [
                input(
                    items,
                    records(item_count, DW_WAIT_MANY_MAX_ITEMS, DW_WAIT_ITEM_V1_SIZE),
                ),
                out(out_result, u64::from(DW_WAIT_RESULT_V1_SIZE)),
                None,
            ],
            Self::AtomicWait32 { address, .. } => [input(address, 4), None, None],
            Self::AtomicWake {
                address, out_woken, ..
            } => [input(address, 4), out(out_woken, 4), None],
            // Unmap and protect name a target range, not a buffer they copy.
            Self::HandleClose { .. }
            | Self::TaskGroupTerminate { .. }
            | Self::TaskGroupLimit { .. }
            | Self::ProcessExit { .. }
            | Self::ProcessTerminate { .. }
            | Self::ThreadSetFsBase { .. }
            | Self::ThreadExit { .. }
            | Self::ThreadTerminate { .. }
            | Self::MemoryObjectCommit { .. }
            | Self::AddressRegionUnmap { .. }
            | Self::AddressRegionProtect { .. }
            | Self::EventSignal { .. }
            | Self::TimerSet { .. }
            | Self::TimerCancel { .. }
            | Self::DevicePioWrite { .. }
            | Self::DevicePciCommand { .. }
            | Self::DmaUnmap { .. }
            | Self::InterruptAck { .. } => [None, None, None],
        }
    }
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
        DwKnownSyscall::TaskGroupLimit => NativeSyscallRequest::TaskGroupLimit {
            task_group: DwHandle(a[0]),
            class: u32_arg(a[1])?,
            limit: u32_arg(a[2])?,
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
        DwKnownSyscall::ThreadSetFsBase => NativeSyscallRequest::ThreadSetFsBase { fs_base: a[0] },
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
        DwKnownSyscall::MemoryObjectCommit => NativeSyscallRequest::MemoryObjectCommit {
            memory_object: DwHandle(a[0]),
            offset: a[1],
            byte_len: a[2],
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
        DwKnownSyscall::DeviceResourceClaim => NativeSyscallRequest::DeviceResourceClaim {
            resource_domain: DwHandle(a[0]),
            resource_id: a[1],
            requested_rights: DwRights(a[2]),
            out_resource: DwUserAddress(a[3]),
        },
        DwKnownSyscall::DevicePioRead => NativeSyscallRequest::DevicePioRead {
            resource: DwHandle(a[0]),
            offset: u32_arg(a[1])?,
            width: u32_arg(a[2])?,
            out_value: DwUserAddress(a[3]),
        },
        DwKnownSyscall::DevicePioWrite => NativeSyscallRequest::DevicePioWrite {
            resource: DwHandle(a[0]),
            offset: u32_arg(a[1])?,
            width: u32_arg(a[2])?,
            value: u32_arg(a[3])?,
        },
        DwKnownSyscall::DevicePciConfigRead => NativeSyscallRequest::DevicePciConfigRead {
            resource: DwHandle(a[0]),
            offset: u32_arg(a[1])?,
            width: u32_arg(a[2])?,
            out_value: DwUserAddress(a[3]),
        },
        DwKnownSyscall::DevicePciCommand => NativeSyscallRequest::DevicePciCommand {
            resource: DwHandle(a[0]),
            memory_space: u32_arg(a[1])?,
            bus_master: u32_arg(a[2])?,
        },
        DwKnownSyscall::DeviceMmioObjectCreate => NativeSyscallRequest::DeviceMmioObjectCreate {
            resource: DwHandle(a[0]),
            bar: u32_arg(a[1])?,
            requested_rights: DwRights(a[2]),
            out_memory_object: DwUserAddress(a[3]),
        },
        DwKnownSyscall::DmaMap => NativeSyscallRequest::DmaMap {
            resource: DwHandle(a[0]),
            memory_object: DwHandle(a[1]),
            offset: a[2],
            byte_len: a[3],
            access: u32_arg(a[4])?,
            out_iova: DwUserAddress(a[5]),
        },
        DwKnownSyscall::DmaUnmap => NativeSyscallRequest::DmaUnmap {
            resource: DwHandle(a[0]),
            iova: a[1],
            byte_len: a[2],
        },
        DwKnownSyscall::InterruptCreate => NativeSyscallRequest::InterruptCreate {
            resource: DwHandle(a[0]),
            requested_rights: DwRights(a[1]),
            out_interrupt: DwUserAddress(a[2]),
        },
        DwKnownSyscall::InterruptAck => NativeSyscallRequest::InterruptAck {
            interrupt: DwHandle(a[0]),
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
    CompleteRemoteStop,
    ServiceRendezvous,
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

/// Proof that a runtime published its final releases: its cleanup queue was
/// drained, so peer signals, waiter wakes and payload reclamation from this
/// syscall are visible before userspace resumes (S2K D5, TSV row 76).
///
/// Neither `Clone` nor `Copy`: one drain proves one return.
#[must_use = "a drain proof exists to admit one return to userspace"]
pub(crate) struct FinalizersDrained {
    _private: (),
}

impl FinalizersDrained {
    /// # Safety
    ///
    /// The caller's finalizer drain has just completed: its cleanup queue is
    /// empty and no deferred parent release remains.
    #[allow(
        unsafe_code,
        reason = "the unchecked constructor states a runtime queue fact no type here can see"
    )]
    pub(crate) const unsafe fn assume() -> Self {
        Self { _private: () }
    }
}

/// A syscall result a runtime may hand back to its dispatcher. A
/// `ReturnToCaller` result exists only with a `FinalizersDrained` proof, so a
/// runtime cannot resume userspace with its final releases still queued.
pub(crate) struct ReturnReady {
    result: NativeSyscallResult,
}

impl ReturnReady {
    /// Any result, returning to the caller or not, with the drain proof.
    pub(crate) const fn drained(result: NativeSyscallResult, _drained: FinalizersDrained) -> Self {
        Self { result }
    }

    /// A result that does not return to the caller needs no proof. A
    /// `ReturnToCaller` result comes back unchanged, still owing one.
    pub(crate) fn without_return(result: NativeSyscallResult) -> Result<Self, NativeSyscallResult> {
        if result.control == SyscallControl::ReturnToCaller {
            Err(result)
        } else {
            Ok(Self { result })
        }
    }

    /// A Stop reached the runtime at a safe point: the dispatcher services the
    /// rendezvous and never returns this result to the caller.
    pub(crate) const fn service_rendezvous() -> Self {
        Self {
            result: NativeSyscallResult {
                status: DW_STATUS_SUCCESS,
                control: SyscallControl::ServiceRendezvous,
            },
        }
    }

    /// A termination published remote Stops. The dispatcher completes them
    /// before anything returns, and that completion owes its own proof.
    pub(crate) const fn complete_remote_stop() -> Self {
        Self {
            result: NativeSyscallResult {
                status: DW_STATUS_SUCCESS,
                control: SyscallControl::CompleteRemoteStop,
            },
        }
    }

    pub(crate) const fn into_result(self) -> NativeSyscallResult {
        self.result
    }
}

pub(crate) fn dispatch_native<H: NativeSyscallHandler>(
    handler: &mut H,
    id: DwSyscallId,
    arguments: RawSyscallArguments,
) -> NativeSyscallResult {
    let result = match decode_native(id, arguments) {
        Ok(request) => handler.handle(request),
        Err(status) => NativeSyscallResult::returning(status),
    };
    crate::task::drain_runnable_work_notifications();
    result
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
    /// `task_group_limit`. The live runtime serves it through the F-service
    /// dispatch; a runtime without TaskGroup limits refuses it.
    fn task_group_limit(
        &mut self,
        _task_group: DwHandle,
        _class: u32,
        _limit: u32,
    ) -> NativeSyscallResult {
        NativeSyscallResult::returning(deepwyrm_abi::DW_STATUS_NOT_SUPPORTED)
    }
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
    /// `memory_object_commit` (DW2 M6 §8.2). The live runtime serves it
    /// through its CPU-local facade, in steps.
    fn memory_object_commit(
        &mut self,
        _memory_object: DwHandle,
        _offset: u64,
        _byte_len: u64,
    ) -> NativeSyscallResult {
        NativeSyscallResult::returning(deepwyrm_abi::DW_STATUS_NOT_SUPPORTED)
    }
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
    fn device_resource_claim(
        &mut self,
        _resource_domain: DwHandle,
        _resource_id: u64,
        _requested_rights: DwRights,
        _out_resource: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn device_pio_read(
        &mut self,
        _resource: DwHandle,
        _offset: u32,
        _width: u32,
        _out_value: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn device_pio_write(
        &mut self,
        _resource: DwHandle,
        _offset: u32,
        _width: u32,
        _value: u32,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn device_pci_config_read(
        &mut self,
        _resource: DwHandle,
        _offset: u32,
        _width: u32,
        _out_value: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn device_pci_command(
        &mut self,
        _resource: DwHandle,
        _memory_space: u32,
        _bus_master: u32,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn device_mmio_object_create(
        &mut self,
        _resource: DwHandle,
        _bar: u32,
        _requested_rights: DwRights,
        _out_memory_object: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    #[allow(clippy::too_many_arguments)]
    fn dma_map(
        &mut self,
        _resource: DwHandle,
        _memory_object: DwHandle,
        _offset: u64,
        _byte_len: u64,
        _access: u32,
        _out_iova: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn dma_unmap(
        &mut self,
        _resource: DwHandle,
        _iova: u64,
        _byte_len: u64,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn interrupt_create(
        &mut self,
        _resource: DwHandle,
        _requested_rights: DwRights,
        _out_interrupt: DwUserAddress,
    ) -> NativeSyscallResult {
        unsupported_f()
    }
    fn interrupt_ack(&mut self, _interrupt: DwHandle) -> NativeSyscallResult {
        unsupported_f()
    }
    fn thread_set_fs_base(&mut self, _fs_base: u64) -> NativeSyscallResult {
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
            NativeSyscallRequest::TaskGroupLimit {
                task_group,
                class,
                limit,
            } => self.task_group_limit(task_group, class, limit),
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
            NativeSyscallRequest::ThreadSetFsBase { fs_base } => self.thread_set_fs_base(fs_base),
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
            NativeSyscallRequest::MemoryObjectCommit {
                memory_object,
                offset,
                byte_len,
            } => self.memory_object_commit(memory_object, offset, byte_len),
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
            NativeSyscallRequest::DeviceResourceClaim {
                resource_domain,
                resource_id,
                requested_rights,
                out_resource,
            } => self.device_resource_claim(
                resource_domain,
                resource_id,
                requested_rights,
                out_resource,
            ),
            NativeSyscallRequest::DevicePioRead {
                resource,
                offset,
                width,
                out_value,
            } => self.device_pio_read(resource, offset, width, out_value),
            NativeSyscallRequest::DevicePioWrite {
                resource,
                offset,
                width,
                value,
            } => self.device_pio_write(resource, offset, width, value),
            NativeSyscallRequest::DevicePciConfigRead {
                resource,
                offset,
                width,
                out_value,
            } => self.device_pci_config_read(resource, offset, width, out_value),
            NativeSyscallRequest::DevicePciCommand {
                resource,
                memory_space,
                bus_master,
            } => self.device_pci_command(resource, memory_space, bus_master),
            NativeSyscallRequest::DeviceMmioObjectCreate {
                resource,
                bar,
                requested_rights,
                out_memory_object,
            } => self.device_mmio_object_create(resource, bar, requested_rights, out_memory_object),
            NativeSyscallRequest::DmaMap {
                resource,
                memory_object,
                offset,
                byte_len,
                access,
                out_iova,
            } => self.dma_map(resource, memory_object, offset, byte_len, access, out_iova),
            NativeSyscallRequest::DmaUnmap {
                resource,
                iova,
                byte_len,
            } => self.dma_unmap(resource, iova, byte_len),
            NativeSyscallRequest::InterruptCreate {
                resource,
                requested_rights,
                out_interrupt,
            } => self.interrupt_create(resource, requested_rights, out_interrupt),
            NativeSyscallRequest::InterruptAck { interrupt } => self.interrupt_ack(interrupt),
        }
    }
}

#[must_use = "suspend plans must be consumed by the raw syscall runtime"]
pub(crate) enum NativeSuspendPlan<'owner> {
    Switch(crate::arch::x86_64::context::KernelSwitchPlan<'owner>),
    IdleCurrent,
}

#[must_use = "idle suspension polls must either continue idling, resume the waiter, or switch to newly runnable work"]
pub(crate) enum NativeIdleSuspendPoll<'owner> {
    Continue,
    ResumeCurrent,
    Switch(crate::arch::x86_64::context::KernelSwitchPlan<'owner>),
}

#[must_use = "a resumed syscall either owns a live current Thread or must service the published rendezvous"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeResumeOutcome {
    Resumed,
    ServiceRendezvous,
    TerminateCurrent,
}

#[must_use = "a DW1-B safe-boundary decision must return or immediately consume its switch plan"]
pub(crate) enum NativePreemptionPlan<'owner> {
    Return,
    Switch(crate::arch::x86_64::context::KernelSwitchPlan<'owner>),
}

/// A divergent entry's handle on this CPU's carrier ([DIVERGENT] in
/// `syscall/live.rs`, closing the former [CARRIER] gap (1), S2K-6).
///
/// A divergent entry never returns, so a `&mut self` receiver would leave a
/// function-argument reference, protected for the callee's whole run, in a
/// frame that is abandoned rather than returned from; the carrier's later
/// reborrows through its published pointer would then conflict with that
/// protector under Stacked and Tree Borrows. This handle carries the same
/// unique borrow as a raw pointer, which passing neither retags nor
/// protects. The entry borrows the carrier from it (`get`) for ordinary,
/// returning work, and a divergent boundary accepts only the
/// `CarrierRelease` that consuming the handle (`release`) yields. So a
/// divergence can only happen in a frame that holds the handle by value,
/// never inside a method that received the carrier as `&mut self`: such a
/// method has no handle to release, and none can be made from a reference.
/// Neither `Clone` nor `Copy`.
pub(crate) struct DivergentCarrier<'a, R> {
    carrier: core::ptr::NonNull<R>,
    _borrow: core::marker::PhantomData<&'a mut R>,
}

/// A carrier that certifies itself guard-free, for `DivergentCarrier::release`.
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
pub(crate) trait GuardFreeSource {
    fn guard_free(&mut self) -> crate::arch::x86_64::syscall::GuardFree<'_>;
}

impl<'a, R> DivergentCarrier<'a, R> {
    /// # Safety
    ///
    /// `carrier` is this CPU's published carrier, valid for `'a`, and no
    /// reference to it is live in any frame that will resume.
    #[allow(
        unsafe_code,
        reason = "the unchecked constructor states a published-carrier fact no type here can see"
    )]
    pub(crate) const unsafe fn published(carrier: core::ptr::NonNull<R>) -> Self {
        Self {
            carrier,
            _borrow: core::marker::PhantomData,
        }
    }

    /// The carrier, for returning work while the entry keeps the handle.
    #[allow(
        unsafe_code,
        reason = "the handle carries a unique borrow for 'a by construction"
    )]
    pub(crate) fn get(&mut self) -> &mut R {
        // SAFETY: `published`'s caller vouched for a unique borrow for `'a`; this reborrow is
        // bounded by the handle's own `&mut` borrow, so it cannot outlive or alias another.
        unsafe { self.carrier.as_mut() }
    }

    /// Consumes the handle for the one divergent boundary that ends the entry.
    #[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
    #[allow(
        unsafe_code,
        reason = "consuming the handle is what certifies no carrier reference survives"
    )]
    pub(crate) fn release(self) -> crate::arch::x86_64::syscall::CarrierRelease<'a>
    where
        R: GuardFreeSource,
    {
        // SAFETY: as in `get`, a unique borrow for `'a`, taken once here as the handle is consumed.
        let carrier: &'a mut R = unsafe { &mut *self.carrier.as_ptr() };
        // SAFETY: the handle is consumed, so this frame holds no other reference to the carrier
        // and every earlier `get` borrow has ended; `published`'s caller vouched that no frame
        // that resumes holds one.
        unsafe { crate::arch::x86_64::syscall::CarrierRelease::new(carrier.guard_free()) }
    }
}

/// One CPU's quantum-expiry publisher. Expiry is published from the timer
/// interrupt and from synchronous quantum cancellation, both of which can run
/// while this CPU's runtime is borrowed by a suspended frame that will resume
/// (a facade method in its idle STI window, or draining a cancellation). The
/// publisher is therefore its own per-CPU object, published beside the runtime
/// and never the runtime itself, so publication reborrows nothing that frame
/// holds ([CARRIER] gap 2 in `syscall/live.rs`, closed by S2K-6).
pub(crate) trait NativeQuantumExpiry {
    fn publish_quantum_expiry(
        &mut self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<bool, crate::task::SchedulerError>;
}

/// The publisher of a runtime that arms no quantum: every expiry is stale.
/// Zero-sized, so its binding needs no storage.
pub(crate) struct NoQuantumExpiry;

impl NativeQuantumExpiry for NoQuantumExpiry {
    fn publish_quantum_expiry(
        &mut self,
        _ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<bool, crate::task::SchedulerError> {
        Ok(false)
    }
}

/// What the runtime did with a CPL3 page fault (DW2 M6 §8.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserPageFaultOutcome {
    /// A frame was committed or a leaf published: return and retry.
    Served,
    /// Another touch published exactly this page's leaf after the fault: retry.
    AlreadyPresent,
    /// Not an on-demand page this access may touch: today's terminal fault.
    Unserved,
    /// An on-demand page that could not be given a frame: the process ends
    /// with `DW_TERMINATION_RESOURCE_POLICY`, and a syscall's fill-in fails
    /// with this status (`NO_RESOURCES` for quota, `NO_MEMORY` for frames).
    Exhausted(DwStatus),
    /// The runtime could not reach a safe point: poll for a stop and retry.
    Retry,
}

#[allow(
    unsafe_code,
    reason = "plan-producing runtime methods carry physical-current and fixed-entry obligations that safe Rust cannot encode"
)]
pub(crate) trait NativeSyscallFrameRuntime: NativeSyscallHandler {
    /// This runtime's per-CPU quantum-expiry publisher, a separate object from
    /// the runtime itself (see [`NativeQuantumExpiry`]).
    type QuantumExpiry: NativeQuantumExpiry;

    /// Samples a new dispatch budget only inside synchronized preparation,
    /// immediately before scheduler preparation. The sampler must not acquire
    /// runtime authority; it runs while that guard is held by the live carrier.
    fn prepare_quantum(
        &mut self,
        _sample_now_ns: impl FnOnce() -> u64,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, crate::task::SchedulerError> {
        panic!("native runtime does not admit DW1-B quantum arming")
    }

    fn has_reschedule_request(&mut self) -> bool {
        false
    }

    fn authorize_timer_return(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawCpl3TimerReturnFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        panic!("native runtime does not admit asynchronous CPL3 return")
    }

    /// Produces a guard-free switch plan from an exact pending scheduler
    /// request. The caller must consume it immediately.
    ///
    /// # Safety
    ///
    /// The caller must be the raw timer/syscall safe-boundary trampoline on
    /// the current Thread's bound kernel stack.
    unsafe fn prepare_preemption<'owner>(&'owner mut self) -> NativePreemptionPlan<'owner> {
        panic!("native runtime does not admit DW1-B preemption")
    }

    fn resume_timer_preemption(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawCpl3TimerReturnFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        panic!("native runtime does not admit timer-preempted continuation resume")
    }

    fn resume_syscall_preemption(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        panic!("native runtime does not admit syscall-return preemption resume")
    }

    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError>;

    /// Converts a rejected user return into terminal state for the current
    /// Process. The raw trampoline performs the divergent reaper-stack handoff
    /// after this method returns.
    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError);

    /// Converts a structured CPL3 exception into terminal state for the
    /// current Process. The exception trampoline performs the divergent
    /// reaper-stack handoff after this method returns.
    fn user_exception(&mut self, record: crate::arch::x86_64::exceptions::UserExceptionRecord);

    /// Ends the current Process for a fault on an on-demand page that could
    /// not be given a frame, with `DW_TERMINATION_RESOURCE_POLICY` (DW2 M6
    /// §8.2). A runtime without on-demand objects never stages one.
    fn user_resource_fault(
        &mut self,
        record: crate::arch::x86_64::exceptions::UserExceptionRecord,
    ) {
        self.user_exception(record);
    }

    /// Serves a CPL3 page fault at `cr2` with error code `error` if it lies
    /// on an on-demand page the faulting access may touch (DW2 M6 §8.5). A
    /// runtime without on-demand objects serves none.
    fn serve_user_page_fault(&mut self, _cr2: u64, _error: u64) -> UserPageFaultOutcome {
        UserPageFaultOutcome::Unserved
    }

    fn terminate_current(this: DivergentCarrier<'_, Self>) -> !
    where
        Self: Sized;

    /// Enters userspace for the scheduler-selected Thread whose kernel
    /// continuation slot is still zero. Called only from the fixed trusted
    /// first-run kernel continuation after the context-switch boundary has
    /// already bound that Thread's owned kernel stack.
    fn enter_scheduled_fresh_thread(this: DivergentCarrier<'_, Self>) -> !
    where
        Self: Sized;

    /// Acquires work for a CPU that entered the live runtime from its private
    /// AP bootstrap stack rather than from an existing Thread continuation.
    /// Implementations must remain cooperative: an idle CPU may claim Runnable
    /// work, but this entry does not displace a Running Thread.
    fn enter_idle_scheduler(_this: DivergentCarrier<'_, Self>) -> !
    where
        Self: Sized,
    {
        panic!("native runtime does not admit idle-CPU scheduler entry")
    }

    /// Begins accounting only after the architecture has successfully
    /// published this CPU's exact HALTED generation.
    fn publish_scheduler_idle(
        &mut self,
        _started_at_ns: u64,
    ) -> Result<crate::task::SchedulerIdleAccountingToken, crate::task::SchedulerError> {
        panic!("native runtime does not admit scheduler idle accounting")
    }

    /// Closes the matching scheduler idle interval after the architecture has
    /// completed the exact HALTED generation that returned from `hlt`.
    fn finish_scheduler_idle(
        &mut self,
        _token: crate::task::SchedulerIdleAccountingToken,
        _finished_at_ns: u64,
    ) -> Result<(), crate::task::SchedulerError> {
        panic!("native runtime does not admit scheduler idle accounting")
    }

    /// Completes an initiator-side remote-stop wait after the raw trampoline
    /// has closed its usercopy window. Implementations must not retain a
    /// shared runtime guard while publishing, waiting for, or consuming the
    /// exact-safe acknowledgement.
    fn complete_remote_stop(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        _current_binding_generation: u64,
    ) -> SyscallControl {
        panic!("native runtime has no pending remote stop")
    }

    /// Returns a plan branded by the stationary execution owner borrowed from
    /// this runtime. The raw trampoline must consume it immediately.
    ///
    /// # Safety
    ///
    /// The caller must be the raw syscall trampoline running on the kernel
    /// stack named by the pending scheduling decision. The implementation must
    /// pass that physical-current fact and only the architecture-owned fixed
    /// first-run entry through every lower plan-producing facade.
    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeSuspendPlan<'owner>;

    /// Propagates the same owner brand through the idle IRQ polling facade.
    ///
    /// # Safety
    ///
    /// The caller must still be running the physically active suspended
    /// continuation, even if its logical Thread became runnable while idle.
    /// The implementation must preserve that carrier identity and the fixed
    /// architecture-owned first-run entry through every lower facade.
    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeIdleSuspendPoll<'owner>;

    /// Resumes a logically selected suspended Thread while holding the
    /// runtime's scheduler authority. An already-published local terminal
    /// owner retains its suspended claim for reaper abandonment. Otherwise,
    /// implementations must acknowledge physical arrival and poll the
    /// authoritative rendezvous mailbox before consulting resumable task
    /// state; a published Stop wins that edge and returns to the trampoline.
    fn resume_suspended(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> NativeResumeOutcome;
}

/// Private carrier seam for a CPL3-origin e1 return gate.
///
/// The hard IRQ itself only latches work.  If the pre-IRET gate observes an
/// exact Stop/HoldSafe notification, it pivots to the CPU-private rendezvous
/// reaper and calls this divergent method with the staged request; it may not
/// return to the interrupted user context.
pub(crate) trait NativeRendezvousRuntime {
    fn rendezvous_stop(
        this: DivergentCarrier<'_, Self>,
        request: crate::arch::x86_64::rendezvous::StopRequest,
        reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> !
    where
        Self: Sized;
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
        return SyscallControl::TerminateCurrent;
    }
    result.control
}
