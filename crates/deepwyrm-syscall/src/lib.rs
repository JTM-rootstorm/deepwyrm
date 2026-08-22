//! Freestanding x86_64 bindings for the native Deepwyrm syscall ABI.
//!
//! This crate owns the guest-side raw `SYSCALL` boundary.  It deliberately
//! exposes native status values, handles, and generated ABI records directly:
//! it does not provide libc, errno, POSIX, or file-descriptor compatibility.
//! Every syscall ID and record comes from [`deepwyrm_abi`], which is generated
//! from Deepwyrm's canonical ABI schema.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::global_asm;

pub use deepwyrm_abi::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("deepwyrm-syscall currently supports only x86_64 guests");

// This is the generated, audited SysV-to-Deepwyrm register shuffle.  Keeping
// it in the ABI output prevents guest users from reproducing the convention.
global_asm!(
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../abi/generated/syscall_veneer_x86_64.S"
    )),
    options(att_syntax)
);

unsafe extern "C" {
    /// Invoke the generated raw six-argument syscall veneer.
    ///
    /// The assembly owns the register convention; callers must supply only
    /// generated syscall IDs and ABI scalar values.  The typed wrappers below
    /// keep references alive for the complete kernel call and are the public
    /// guest API.
    fn dw_syscall6(
        number: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> i64;
}

#[inline]
fn status_from_raw(value: i64) -> DwStatus {
    DwStatus(value as i32)
}

/// Invoke one generated syscall ID with six already-encoded ABI arguments.
///
/// # Safety
///
/// Each scalar must satisfy the selected syscall's generated ABI contract.
/// Any argument encoding a userspace address must remain valid, correctly
/// aligned for the selected record, and accessible with the required
/// direction for the entire kernel call.  Public wrappers should be preferred.
#[inline]
unsafe fn syscall6(
    number: DwSyscallId,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> DwStatus {
    // SAFETY: this is the single guest raw-call boundary.  The generated
    // veneer has the declared SysV signature and performs no pointer access.
    status_from_raw(unsafe { dw_syscall6(number.0.into(), arg0, arg1, arg2, arg3, arg4, arg5) })
}

#[inline]
fn input_address<T: ?Sized>(value: &T) -> u64 {
    core::ptr::from_ref(value).cast::<()>() as u64
}

#[inline]
fn output_address<T: ?Sized>(value: &mut T) -> u64 {
    core::ptr::from_mut(value).cast::<()>() as u64
}

#[inline]
fn input_slice_address<T>(value: &[T]) -> u64 {
    if value.is_empty() {
        0
    } else {
        input_address(value)
    }
}

#[inline]
fn output_slice_address<T>(value: &mut [T]) -> u64 {
    if value.is_empty() {
        0
    } else {
        output_address(value)
    }
}

#[inline]
fn u32_len(length: usize) -> Result<u32, DwStatus> {
    u32::try_from(length).map_err(|_| DW_STATUS_INVALID_ARGUMENT)
}

/// Close one caller-local native handle.
#[inline]
pub fn handle_close(handle: DwHandle) -> DwStatus {
    // SAFETY: `handle` is a generated scalar ABI argument.
    unsafe { syscall6(DW_SYSCALL_HANDLE_CLOSE, handle.0, 0, 0, 0, 0, 0) }
}

/// Duplicate one handle with an explicit nonzero rights subset.
#[inline]
pub fn handle_duplicate(
    handle: DwHandle,
    requested_rights: DwRights,
    out_handle: &mut DwHandle,
) -> DwStatus {
    // SAFETY: the generated scalar arguments are copied by value and the
    // output reference remains uniquely borrowed for the complete call.
    unsafe {
        syscall6(
            DW_SYSCALL_HANDLE_DUPLICATE,
            handle.0,
            requested_rights.0,
            output_address(out_handle),
            0,
            0,
            0,
        )
    }
}

#[inline]
fn object_get_info_v1<T>(
    handle: DwHandle,
    topic: u32,
    out_info: &mut T,
    out_required_size: &mut u64,
) -> DwStatus {
    let out_size = core::mem::size_of::<T>() as u64;
    // SAFETY: both mutable references remain live and uniquely borrowed for
    // this call.  Their sizes and topic are selected by the typed wrappers.
    unsafe {
        syscall6(
            DW_SYSCALL_OBJECT_GET_INFO_V1,
            handle.0,
            u64::from(topic),
            output_address(out_info),
            out_size,
            output_address(out_required_size),
            0,
        )
    }
}

/// Query generated basic object type and rights metadata for one handle.
#[inline]
pub fn object_get_basic_info_v1(
    handle: DwHandle,
    out_info: &mut DwObjectInfoV1,
    out_required_size: &mut u64,
) -> DwStatus {
    object_get_info_v1(handle, DW_OBJECT_INFO_BASIC_V1, out_info, out_required_size)
}

/// Query the exact generated logical byte size of a MemoryObject handle.
#[inline]
pub fn object_get_memory_object_info_v1(
    handle: DwHandle,
    out_info: &mut DwMemoryObjectInfoV1,
    out_required_size: &mut u64,
) -> DwStatus {
    object_get_info_v1(
        handle,
        DW_OBJECT_INFO_MEMORY_OBJECT_V1,
        out_info,
        out_required_size,
    )
}

/// Query generated Process or Thread lifecycle and termination state.
#[inline]
pub fn object_get_task_state_v1(
    handle: DwHandle,
    out_info: &mut DwTaskTerminationInfoV1,
    out_required_size: &mut u64,
) -> DwStatus {
    object_get_info_v1(
        handle,
        DW_OBJECT_INFO_TASK_STATE_V1,
        out_info,
        out_required_size,
    )
}

/// Transactionally create a child Process and install its bootstrap Channel.
#[inline]
pub fn process_create(
    args: &DwProcessCreateArgsV1,
    out_result: &mut DwProcessCreateResultV1,
) -> DwStatus {
    // SAFETY: both generated records remain borrowed for the complete call and
    // their exact generated sizes are supplied to the kernel.
    unsafe {
        syscall6(
            DW_SYSCALL_PROCESS_CREATE,
            input_address(args),
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            output_address(out_result),
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            0,
            0,
        )
    }
}

/// Request normal termination of the calling process with a native exit code.
#[inline]
pub fn process_exit(exit_code: u32) -> DwStatus {
    // SAFETY: `exit_code` is a generated scalar ABI argument.
    unsafe { syscall6(DW_SYSCALL_PROCESS_EXIT, u64::from(exit_code), 0, 0, 0, 0, 0) }
}

/// Explicitly terminate one Process through held `MODIFY` authority.
#[inline]
pub fn process_terminate(process: DwHandle, reason: DwTerminationReason, code: u32) -> DwStatus {
    // SAFETY: all arguments are generated scalar ABI values.
    unsafe {
        syscall6(
            DW_SYSCALL_PROCESS_TERMINATE,
            process.0,
            u64::from(reason.0),
            u64::from(code),
            0,
            0,
            0,
        )
    }
}

/// Create one Thread in a child Process in `CREATED` state.
#[inline]
pub fn thread_create(
    process: DwHandle,
    requested_rights: DwRights,
    out_thread: &mut DwHandle,
) -> DwStatus {
    // SAFETY: generated scalars are copied and the output handle remains
    // uniquely borrowed for the complete call.
    unsafe {
        syscall6(
            DW_SYSCALL_THREAD_CREATE,
            process.0,
            requested_rights.0,
            output_address(out_thread),
            0,
            0,
            0,
        )
    }
}

/// Start one created Thread with exact generated V1 register state.
#[inline]
pub fn thread_start(args: &DwThreadStartArgsV1) -> DwStatus {
    // SAFETY: the generated record remains immutably borrowed for the call and
    // its exact generated size is supplied.
    unsafe {
        syscall6(
            DW_SYSCALL_THREAD_START,
            input_address(args),
            u64::from(DW_THREAD_START_ARGS_V1_SIZE),
            0,
            0,
            0,
            0,
        )
    }
}

/// Request normal termination of the calling thread with a native exit code.
#[inline]
pub fn thread_exit(exit_code: u32) -> DwStatus {
    // SAFETY: `exit_code` is a generated scalar ABI argument.
    unsafe { syscall6(DW_SYSCALL_THREAD_EXIT, u64::from(exit_code), 0, 0, 0, 0, 0) }
}

/// Explicitly terminate one Thread through held `MODIFY` authority.
#[inline]
pub fn thread_terminate(thread: DwHandle, reason: DwTerminationReason, code: u32) -> DwStatus {
    // SAFETY: all arguments are generated scalar ABI values.
    unsafe {
        syscall6(
            DW_SYSCALL_THREAD_TERMINATE,
            thread.0,
            u64::from(reason.0),
            u64::from(code),
            0,
            0,
            0,
        )
    }
}

/// Create one zero-filled page-backed MemoryObject.
#[inline]
pub fn memory_object_create(
    byte_len: DwSize,
    flags: DwMemoryObjectCreateFlags,
    requested_rights: DwRights,
    out_handle: &mut DwHandle,
) -> DwStatus {
    // SAFETY: generated scalars are copied and the output remains uniquely
    // borrowed for the complete call.
    unsafe {
        syscall6(
            DW_SYSCALL_MEMORY_OBJECT_CREATE,
            byte_len.0,
            u64::from(flags.0),
            requested_rights.0,
            output_address(out_handle),
            0,
            0,
        )
    }
}

/// Atomically send one native Channel datagram and optional moved handles.
#[inline]
pub fn channel_send(
    channel: DwHandle,
    bytes: &[u8],
    transfers: &[DwHandleTransferV1],
    flags: u64,
) -> DwStatus {
    let Ok(byte_len) = u32_len(bytes.len()) else {
        return DW_STATUS_INVALID_ARGUMENT;
    };
    let Ok(transfer_count) = u32_len(transfers.len()) else {
        return DW_STATUS_INVALID_ARGUMENT;
    };
    // SAFETY: the borrowed slices remain live and immutable for the call; the
    // generated records establish the transfer layout.
    unsafe {
        syscall6(
            DW_SYSCALL_CHANNEL_SEND,
            channel.0,
            input_slice_address(bytes),
            u64::from(byte_len),
            input_slice_address(transfers),
            u64::from(transfer_count),
            flags,
        )
    }
}

/// Receive one native Channel datagram into caller-owned ABI buffers.
#[inline]
pub fn channel_receive(
    channel: DwHandle,
    out_bytes: &mut [u8],
    out_handles: &mut [DwReceivedHandleInfoV1],
    out_result: &mut DwChannelReceiveResultV1,
) -> DwStatus {
    let Ok(byte_capacity) = u32_len(out_bytes.len()) else {
        return DW_STATUS_INVALID_ARGUMENT;
    };
    let Ok(handle_capacity) = u32_len(out_handles.len()) else {
        return DW_STATUS_INVALID_ARGUMENT;
    };
    // SAFETY: each mutable slice and output record remains uniquely borrowed
    // for the call and uses a generated record layout.
    unsafe {
        syscall6(
            DW_SYSCALL_CHANNEL_RECEIVE,
            channel.0,
            output_slice_address(out_bytes),
            u64::from(byte_capacity),
            output_slice_address(out_handles),
            u64::from(handle_capacity),
            output_address(out_result),
        )
    }
}

/// Map one generated MemoryObject range into a generated AddressRegion.
#[inline]
pub fn address_region_map(
    address_region: DwHandle,
    memory_object: DwHandle,
    args: &DwAddressRegionMapArgsV1,
    out_address: &mut DwUserAddress,
) -> DwStatus {
    // SAFETY: the references remain valid for the call and the argument size
    // comes from the generated ABI definition rather than a copied layout.
    unsafe {
        syscall6(
            DW_SYSCALL_ADDRESS_REGION_MAP,
            address_region.0,
            memory_object.0,
            input_address(args),
            u64::from(DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE),
            output_address(out_address),
            0,
        )
    }
}

/// Remove one fully mapped native AddressRegion range.
#[inline]
pub fn address_region_unmap(
    address_region: DwHandle,
    address: DwUserAddress,
    byte_len: DwSize,
) -> DwStatus {
    // SAFETY: every argument is a generated scalar ABI value.
    unsafe {
        syscall6(
            DW_SYSCALL_ADDRESS_REGION_UNMAP,
            address_region.0,
            address.0,
            byte_len.0,
            0,
            0,
            0,
        )
    }
}

/// Change one fully mapped AddressRegion range without exceeding its ceiling.
#[inline]
pub fn address_region_protect(
    address_region: DwHandle,
    address: DwUserAddress,
    byte_len: DwSize,
    protections: DwMemoryProtection,
) -> DwStatus {
    // SAFETY: every argument is a generated scalar ABI value.
    unsafe {
        syscall6(
            DW_SYSCALL_ADDRESS_REGION_PROTECT,
            address_region.0,
            address.0,
            byte_len.0,
            u64::from(protections.0),
            0,
            0,
        )
    }
}

/// Create one connected Channel pair with a shared requested rights mask.
#[inline]
pub fn channel_create(
    requested_rights: DwRights,
    out_endpoint0: &mut DwHandle,
    out_endpoint1: &mut DwHandle,
) -> DwStatus {
    // SAFETY: both output handles remain disjoint and uniquely borrowed for the
    // complete call.
    unsafe {
        syscall6(
            DW_SYSCALL_CHANNEL_CREATE,
            requested_rights.0,
            output_address(out_endpoint0),
            output_address(out_endpoint1),
            0,
            0,
            0,
        )
    }
}

/// Wait for one generated signal mask on one waitable handle.
#[inline]
pub fn wait_one(
    handle: DwHandle,
    signals: DwSignals,
    deadline: DwDeadline,
    out_result: &mut DwWaitResultV1,
) -> DwStatus {
    // SAFETY: generated scalars are copied and the output remains uniquely
    // borrowed for the complete call.
    unsafe {
        syscall6(
            DW_SYSCALL_WAIT_ONE,
            handle.0,
            signals.0,
            deadline.0,
            output_address(out_result),
            0,
            0,
        )
    }
}

/// Wait-any over a bounded caller-owned generated item slice.
#[inline]
pub fn wait_many(
    items: &[DwWaitItemV1],
    mode: u32,
    deadline: DwDeadline,
    out_result: &mut DwWaitResultV1,
) -> DwStatus {
    let Ok(item_count) = u32_len(items.len()) else {
        return DW_STATUS_INVALID_ARGUMENT;
    };
    // SAFETY: the item slice remains immutably borrowed and the output remains
    // uniquely borrowed for the complete call.
    unsafe {
        syscall6(
            DW_SYSCALL_WAIT_MANY,
            input_slice_address(items),
            u64::from(item_count),
            u64::from(mode),
            deadline.0,
            output_address(out_result),
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_channel_slices_use_null_abi_addresses() {
        assert_eq!(input_slice_address::<u8>(&[]), 0);
        assert_eq!(input_slice_address::<DwHandleTransferV1>(&[]), 0);
        assert_eq!(output_slice_address::<u8>(&mut []), 0);
        assert_eq!(output_slice_address::<DwReceivedHandleInfoV1>(&mut []), 0);
    }

    #[test]
    fn nonempty_channel_slices_preserve_data_addresses() {
        let bytes = [90_u8; 1];
        let transfers = [DwHandleTransferV1::default(); 1];
        let mut out_bytes = [0_u8; 1];
        let mut out_handles = [DwReceivedHandleInfoV1::default(); 1];

        assert_eq!(input_slice_address(&bytes), bytes.as_ptr() as u64);
        assert_eq!(input_slice_address(&transfers), transfers.as_ptr() as u64);
        assert_eq!(
            output_slice_address(&mut out_bytes),
            out_bytes.as_mut_ptr() as u64
        );
        assert_eq!(
            output_slice_address(&mut out_handles),
            out_handles.as_mut_ptr() as u64
        );
    }
}
