//! Deepwyrm kernel crate boundary.
//!
//! The portable boot-intake model remains host-testable. Freestanding x86_64
//! entry installs the kernel's own diagnostic and descriptor state before it
//! validates the loader-owned handoff.

#![no_std]
#![deny(unsafe_code)]

pub mod arch;
pub mod boot;
pub mod debug;
pub mod interrupt;

#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use boot::BootInfoByteReader;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const MAX_X86_PHYSICAL_ADDRESS_EXCLUSIVE: u64 = 1_u64 << 52;

/// Transfers from the raw architecture entry into validated DW0-B bring-up.
///
/// This symbol is architecture-internal. The loader enters through
/// `_dw_kernel_entry`, never by calling this Rust function directly.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "raw entry establishes the single-BSP descriptor-install preconditions"
)]
pub(crate) fn kernel_main(boot_info_physical: u64) -> ! {
    // SAFETY: the raw entry shim has already switched to the kernel-owned
    // stack and enforces the reconciled single-BSP, IF-clear entry contract.
    if let Err(error) = unsafe { arch::x86_64::install_early_descriptors() } {
        panic!("failed to install early x86_64 descriptors: {error:?}");
    }

    let reader = IdentityMappedBootInfoReader;
    let _boot_info = boot::validate_boot_info(&reader, boot_info_physical)
        .unwrap_or_else(|error| panic!("invalid DwBootInfoV1 handoff: {error:?}"));

    #[cfg(feature = "test-support")]
    match test_support::BUILD_GUEST_TEST {
        test_support::BuildGuestTest::BootHandoffPass => test_support::complete_pass(0),
        test_support::BuildGuestTest::ExceptionFailPath => {
            test_support::trigger_expected_invalid_opcode()
        }
        test_support::BuildGuestTest::PanicPath => panic!("DW0-B panic-path guest test"),
    }

    #[cfg(not(feature = "test-support"))]
    {
        let _ = debug::emit_early_record(
            debug::DiagnosticLevel::Info,
            "boot",
            "validated DwBootInfoV1 handoff",
        );
        halt_bootstrap_cpu()
    }
}

/// Reads the loader's temporary identity mappings under
/// `DW_BOOT_X86_64_ENTRY_V1`.
///
/// Construction is private to [`kernel_main`]. The loader contract guarantees
/// that BootInfo and each referenced handoff range remain mapped and immutable
/// until Deepwyrm replaces the transition page tables.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct IdentityMappedBootInfoReader;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl BootInfoByteReader for IdentityMappedBootInfoReader {
    #[allow(
        unsafe_code,
        reason = "audited identity-mapped physical handoff copy boundary"
    )]
    fn read_exact(&self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        if destination.is_empty() {
            return Ok(());
        }
        let byte_len = u64::try_from(destination.len()).map_err(|_| ())?;
        let physical_end = physical_start.checked_add(byte_len).ok_or(())?;
        if physical_start == 0 || physical_end > MAX_X86_PHYSICAL_ADDRESS_EXCLUSIVE {
            return Err(());
        }
        let source = usize::try_from(physical_start).map_err(|_| ())? as *const u8;

        // SAFETY: the private reader is used only during the locked loader
        // handoff lifetime. The source is a checked physical range below the
        // maximum x86_64 physical-address width and is identity-mapped and
        // immutable by contract. The destination is a live Rust slice on the
        // disjoint higher-half kernel stack.
        unsafe {
            core::ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), destination.len());
        }
        Ok(())
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    debug::handle_early_panic(info)
}

#[cfg(all(
    not(feature = "test-support"),
    target_os = "none",
    target_arch = "x86_64"
))]
#[allow(
    unsafe_code,
    reason = "terminal DW0-B bootstrap endpoint keeps interrupts disabled"
)]
fn halt_bootstrap_cpu() -> ! {
    loop {
        // SAFETY: DW0-B has no scheduler or later initialization to resume.
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
