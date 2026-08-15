//! Raw x86_64 loader-to-Rust entry boundary.
//!
//! The assembly shim normalizes the small portion of machine state required
//! by Rust, switches away from the loader transition stack, and then calls
//! this System V boundary. BootInfo intake and all later initialization are
//! owned by the architecture-independent kernel entry path.

/// Receives the identity-mapped physical address of `DwBootInfoV1` from the
/// assembly shim and transfers control to the kernel entry path.
///
/// This symbol is internal to the kernel ELF and is not part of the userspace
/// ABI. It must remain System V compatible with `entry.S`.
#[allow(
    unsafe_code,
    reason = "fixed symbol required by the audited x86_64 assembly entry boundary"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_kernel_rust_entry(boot_info_physical: u64) -> ! {
    crate::kernel_main(boot_info_physical)
}
