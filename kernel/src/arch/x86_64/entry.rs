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
    // SAFETY: the assembly shim established CPL0, the kernel-owned stack, and
    // IF=0. This is the first Rust architecture action and precedes descriptor
    // installation, BootInfo reads, and transition-paging attestation.
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    unsafe {
        normalize_dw0_c_cpu_state();
    }
    crate::kernel_main(boot_info_physical)
}

/// Establishes the consumer-owned DW0-C supervisor-access profile.
///
/// Wyrmroot preserves unrelated incoming CR4/RFLAGS state and does not promise
/// SMAP or AC clear. Deepwyrm therefore clears exactly CR4.SMAP and RFLAGS.AC
/// before any C1/C2 assumption while retaining every other bit, including IF.
/// Later live observations fail closed if either bit drifts back.
///
/// # Safety
///
/// The caller must execute at CPL0 on a live writable stack before any
/// concurrent CPU or interrupt path can observe or mutate this bootstrap CPU
/// state. The caller must not depend on supervisor access to user mappings.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[inline(never)]
#[allow(
    unsafe_code,
    reason = "one balanced bootstrap assembly block normalizes only CR4.SMAP and saved RFLAGS.AC"
)]
unsafe fn normalize_dw0_c_cpu_state() {
    // SAFETY: the entry shim supplies CPL0, a writable kernel stack, IF=0, and
    // sole-BSP execution. PUSHFQ/POPFQ are balanced. BTR changes temporary
    // arithmetic flags, but POPFQ restores the saved incoming word after only
    // AC is cleared. No `nomem`/`readonly` option is used: the compiler must
    // account for the explicit stack memory traffic and CR4 state change.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "mov {scratch}, cr4",
            "btr {scratch}, 21",
            "mov cr4, {scratch}",
            "btr qword ptr [rsp], 18",
            "popfq",
            scratch = lateout(reg) _,
        );
    }
}
