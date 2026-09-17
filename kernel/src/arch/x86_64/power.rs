//! Production platform power-off.
//!
//! The terminal path of a production boot used to emit its completion record
//! and then halt forever, while every instrumented build ended its run through
//! the `test-support` `isa-debug-exit` transport. That asymmetry meant a
//! production image could describe why it had finished but could not act on it:
//! the machine stayed up with nothing left to run, and anything watching the
//! domain rather than the guest never observed an end.
//!
//! This module closes that gap with the architectural mechanism rather than a
//! test device. The values come from firmware via [`crate::arch::x86_64::acpi`]
//! and were authorized against the locked q35 profile at boot.

use crate::arch::x86_64::acpi::sleep;
use crate::arch::x86_64::io_port::X86PortIo;

/// Request ACPI S5 soft-off, then halt.
///
/// On conforming firmware the machine powers off inside the PM1a control write
/// and the halt loop is never reached. The loop is the honest fallback for
/// firmware that declines, for a boot where S5 discovery failed, and for the
/// window between the write and the platform acting on it -- in every one of
/// those cases the behaviour is exactly what production did before, so this can
/// only ever end a boot that would otherwise have hung.
#[allow(
    unsafe_code,
    reason = "the terminal path has no runnable work; halting with interrupts enabled is the pre-existing production behaviour this extends"
)]
pub(crate) fn soft_off_then_halt() -> ! {
    match sleep::authorized_soft_off() {
        Some(command) => sleep::request_soft_off(&mut X86PortIo, command),
        None => {
            let _ = crate::debug::emit_early_record(
                crate::debug::DiagnosticLevel::Warn,
                "power",
                "ACPI S5 soft-off unavailable; halting instead",
            );
        }
    }
    loop {
        // SAFETY: nothing remains runnable on this CPU. Keeping the interrupt
        // shadow matches the halt loop this replaced, so a platform that acts
        // on the S5 write asynchronously still gets serviced.
        unsafe {
            core::arch::asm!("sti", "hlt", options(nomem, nostack));
        }
    }
}
