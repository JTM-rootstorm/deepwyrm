//! Narrow x86_64 QEMU test-exit primitives.

use core::arch::asm;

use crate::debug::emit_early_raw_record;

use super::{
    identity::{completion_record, exception_outcome, expects_invalid_opcode},
    protocol::{COMPLETION_RECORD_LEN, CompletionOutcome},
    transport::{CompletionTransport, DebugExitValue, complete},
};

/// Test-only I/O port configured by the centralized QEMU runner.
const QEMU_DEBUG_EXIT_PORT: u16 = 0x00f4;

/// Completion transport for the centralized x86_64 QEMU guest-test profile.
///
/// Construction is unsafe so ordinary test-feature code cannot silently assert
/// that the QEMU-only I/O device is present on an arbitrary machine.
struct QemuCompletionTransport {
    _private: (),
}

impl QemuCompletionTransport {
    /// Establish the QEMU-only completion transport.
    ///
    /// # Safety
    ///
    /// The caller must prove that this test kernel is running under the
    /// centralized QEMU profile with `isa-debug-exit` configured at
    /// [`QEMU_DEBUG_EXIT_PORT`].
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction proves the test-only QEMU device precondition"
    )]
    const unsafe fn new() -> Self {
        Self { _private: () }
    }
}

impl CompletionTransport for QemuCompletionTransport {
    fn write_serial_record(&mut self, record: &[u8; COMPLETION_RECORD_LEN]) {
        // The host requires both the serial record and matching process status;
        // a serial failure therefore becomes infrastructure failure, never PASS.
        let _ = emit_early_raw_record(record);
    }

    #[allow(
        unsafe_code,
        reason = "transport construction established the QEMU port precondition"
    )]
    fn write_debug_exit(&mut self, value: DebugExitValue) {
        // SAFETY: this type can only be constructed after the caller proves the
        // centralized QEMU debug-exit device is present.
        unsafe { write_qemu_debug_exit(value) }
    }

    fn halt(&mut self) -> ! {
        halt_after_completion()
    }
}

/// Emit the build-selected test's PASS terminal record and stop.
pub(crate) fn complete_pass(detail: u32) -> ! {
    complete_known_outcome(CompletionOutcome::Pass, detail)
}

/// Emit the build-selected test's FAIL terminal record and stop.
pub(crate) fn complete_fail(detail: u32) -> ! {
    complete_known_outcome(CompletionOutcome::Fail, detail)
}

/// Emit the build-selected test's PANIC terminal record and stop.
pub(crate) fn complete_panic(detail: u32) -> ! {
    complete_known_outcome(CompletionOutcome::Panic, detail)
}

/// Classify an early exception for the selected guest test and stop.
///
/// Only the deliberately induced invalid-opcode exception in the dedicated
/// negative test is FAIL. Every unexpected exception is PANIC.
pub(crate) fn complete_exception_vector(vector: u8) -> ! {
    let detail = u32::from(vector);
    match exception_outcome(vector) {
        CompletionOutcome::Fail => complete_fail(detail),
        CompletionOutcome::Panic => complete_panic(detail),
        CompletionOutcome::Pass => unreachable!("exceptions cannot classify as PASS"),
    }
}

/// Deliberately raise #UD for the dedicated negative guest test.
///
/// The compile-time selector gate runs before the instruction so no other test
/// image can accidentally reinterpret a real invalid opcode as expected FAIL.
#[allow(
    unsafe_code,
    reason = "the dedicated negative guest test intentionally executes one UD2"
)]
pub(crate) fn trigger_expected_invalid_opcode() -> ! {
    assert!(
        expects_invalid_opcode(),
        "UD2 trigger is restricted to exception-fail-path"
    );
    // SAFETY: the compile-time identity above confines this instruction to the
    // dedicated #UD test after the IDT and terminal exception path are active.
    unsafe {
        asm!("ud2", options(noreturn, nomem, nostack));
    }
}

#[allow(
    unsafe_code,
    reason = "compile-time test identity confines construction to the QEMU test image"
)]
fn complete_known_outcome(outcome: CompletionOutcome, detail: u32) -> ! {
    // SAFETY: this function exists only in an x86_64-none `test-support` build
    // whose compile-time selector was resolved by the central QEMU harness
    // build path. Such artifacts are not production or physical-hardware images.
    let mut transport = unsafe { QemuCompletionTransport::new() };
    complete(&mut transport, completion_record(outcome, detail))
}

/// Write one outcome-only value to QEMU's test exit device.
///
/// # Safety
///
/// The caller must prove this is a test kernel running under the centralized
/// QEMU profile with `isa-debug-exit` configured at [`QEMU_DEBUG_EXIT_PORT`].
/// Executing this on unverified physical hardware could address an unrelated
/// I/O device.
#[allow(unsafe_code, reason = "test-only x86 QEMU debug-exit port boundary")]
unsafe fn write_qemu_debug_exit(value: DebugExitValue) {
    // SAFETY: The caller establishes that the test-only QEMU port is present.
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") QEMU_DEBUG_EXIT_PORT,
            in("eax") value.raw(),
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Halt permanently after a terminal test result if QEMU did not exit.
#[allow(
    unsafe_code,
    reason = "test-only x86 terminal halt instruction boundary"
)]
fn halt_after_completion() -> ! {
    loop {
        // SAFETY: This terminal test-only path intentionally disables maskable
        // interrupts and halts; it never returns to normal kernel execution.
        unsafe {
            asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
