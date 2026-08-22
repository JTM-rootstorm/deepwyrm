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
fn u32_len(length: usize) -> Result<u32, DwStatus> {
    u32::try_from(length).map_err(|_| DW_STATUS_INVALID_ARGUMENT)
}

/// Close one caller-local native handle.
#[inline]
pub fn handle_close(handle: DwHandle) -> DwStatus {
    // SAFETY: `handle` is a generated scalar ABI argument.
    unsafe { syscall6(DW_SYSCALL_HANDLE_CLOSE, handle.0, 0, 0, 0, 0, 0) }
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

/// Request normal termination of the calling process with a native exit code.
#[inline]
pub fn process_exit(exit_code: u32) -> DwStatus {
    // SAFETY: `exit_code` is a generated scalar ABI argument.
    unsafe { syscall6(DW_SYSCALL_PROCESS_EXIT, u64::from(exit_code), 0, 0, 0, 0, 0) }
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
            input_address(bytes),
            u64::from(byte_len),
            input_address(transfers),
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
            output_address(out_bytes),
            u64::from(byte_capacity),
            output_address(out_handles),
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
