//! Narrow x86_64 QEMU test-exit primitives.

#![allow(
    unsafe_code,
    reason = "target-only test completion, fixed fault probes, and QEMU exit I/O are confined to this module"
)]

use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::arch::x86_64::exceptions::{EarlyException, ExceptionVector};
use crate::debug::emit_early_raw_record;

use super::{
    identity::{
        ExpectedPageFaultFacts, ExpectedPageFaultKind, completion_record, exception_outcome,
        expected_fault_selector, expected_page_fault_matches, expects_invalid_opcode,
    },
    protocol::{COMPLETION_RECORD_LEN, CompletionOutcome},
    transport::{CompletionTransport, DebugExitValue, complete},
};

/// Test-only I/O port configured by the centralized QEMU runner.
const QEMU_DEBUG_EXIT_PORT: u16 = 0x00f4;

const EXPECTED_FAULT_EMPTY: u8 = 0;
const EXPECTED_FAULT_WRITING: u8 = 1;
const EXPECTED_FAULT_ARMED: u8 = 2;
const EXPECTED_FAULT_CONSUMED: u8 = 3;

static EXPECTED_FAULT_STATE: AtomicU8 = AtomicU8::new(EXPECTED_FAULT_EMPTY);
static EXPECTED_FAULT_ADDRESS: AtomicU64 = AtomicU64::new(0);
static EXPECTED_FAULT_RIP: AtomicU64 = AtomicU64::new(0);
static EXPECTED_FAULT_ERROR: AtomicU64 = AtomicU64::new(0);
static EXPECTED_FAULT_PROCESSOR: AtomicU8 = AtomicU8::new(0);

core::arch::global_asm!(
    r#"
    .pushsection .text.deepwyrm_test_faults,"ax",@progbits
    .p2align 4
    .globl dw_test_unmapped_read
    .type dw_test_unmapped_read,@function
dw_test_unmapped_read:
    .globl dw_test_unmapped_read_site
dw_test_unmapped_read_site:
    mov rax, qword ptr [rdi]
    ret
    .size dw_test_unmapped_read, .-dw_test_unmapped_read

    .p2align 4
    .globl dw_test_write_protected
    .type dw_test_write_protected,@function
dw_test_write_protected:
    .globl dw_test_write_protected_site
dw_test_write_protected_site:
    mov qword ptr [rdi], rsi
    ret
    .size dw_test_write_protected, .-dw_test_write_protected
    .popsection
"#
);

#[allow(
    unsafe_code,
    reason = "symbols are defined by the adjacent test-only global assembly"
)]
unsafe extern "sysv64" {
    fn dw_test_unmapped_read(address: u64);
    static dw_test_unmapped_read_site: u8;
    fn dw_test_write_protected(address: u64, value: u64);
    static dw_test_write_protected_site: u8;
}

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
pub(crate) fn complete_exception(exception: EarlyException) -> ! {
    let vector = exception.vector.vector();
    let detail = u32::from(vector);
    if matches!(exception.vector, ExceptionVector::PageFault)
        && EXPECTED_FAULT_STATE.load(Ordering::Acquire) == EXPECTED_FAULT_ARMED
    {
        if live_expected_page_fault_matches(exception)
            && EXPECTED_FAULT_STATE
                .compare_exchange(
                    EXPECTED_FAULT_ARMED,
                    EXPECTED_FAULT_CONSUMED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            complete_pass(0x5046_4f4b)
        }
        complete_panic(0x5046_4241)
    }
    match exception_outcome(vector) {
        CompletionOutcome::Fail => complete_fail(detail),
        CompletionOutcome::Panic => complete_panic(detail),
        CompletionOutcome::Pass => unreachable!("exceptions cannot classify as PASS"),
    }
}

fn live_expected_page_fault_matches(exception: EarlyException) -> bool {
    let processor = observed_processor_id();
    expected_page_fault_matches(
        exception,
        ExpectedPageFaultFacts {
            address: EXPECTED_FAULT_ADDRESS.load(Ordering::Relaxed),
            instruction_pointer: EXPECTED_FAULT_RIP.load(Ordering::Relaxed),
            error_code: EXPECTED_FAULT_ERROR.load(Ordering::Relaxed),
            processor_id: EXPECTED_FAULT_PROCESSOR.load(Ordering::Relaxed),
        },
        processor,
    )
}

#[allow(
    unsafe_code,
    reason = "the target-only CPUID observation binds an expected terminal fault to the current BSP"
)]
fn observed_processor_id() -> u8 {
    core::arch::x86_64::__cpuid(1).ebx.wrapping_shr(24) as u8
}

/// Performs one bounded alias-coherency observation in the C2 CPU profile.
///
/// # Safety
///
/// `writer` and `reader` must name live, naturally aligned, writable user
/// mappings retained under exclusive address-space mutation authority for the
/// complete call. Both mappings must cover at least eight bytes. C2 must have
/// reobserved CR4.SMAP clear and RFLAGS.AC clear before activating this root.
pub(crate) unsafe fn write_then_read_user_alias(writer: u64, reader: u64, value: u64) -> bool {
    let observed = unsafe {
        core::ptr::write_volatile(writer as *mut u64, value);
        core::ptr::read_volatile(reader as *const u64)
    };
    observed == value
}

/// Reads one naturally aligned user word in the accepted C2 CPU profile.
///
/// # Safety
///
/// `address` must name a live, naturally aligned, readable user mapping held
/// stable under exclusive address-space mutation authority for this call. C2
/// must have reobserved CR4.SMAP clear and RFLAGS.AC clear before activation.
pub(crate) unsafe fn read_user_alias_word(address: u64) -> u64 {
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

fn arm_expected_page_fault(address: u64, kind: ExpectedPageFaultKind) -> Result<(), ()> {
    let (required_selector, error) = expected_fault_selector(kind);
    let rip = match kind {
        ExpectedPageFaultKind::UnmappedSupervisorRead => {
            core::ptr::addr_of!(dw_test_unmapped_read_site) as u64
        }
        ExpectedPageFaultKind::WriteProtectedSupervisorWrite => {
            core::ptr::addr_of!(dw_test_write_protected_site) as u64
        }
    };
    if super::BUILD_GUEST_TEST != required_selector
        || EXPECTED_FAULT_STATE
            .compare_exchange(
                EXPECTED_FAULT_EMPTY,
                EXPECTED_FAULT_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        return Err(());
    }
    EXPECTED_FAULT_ADDRESS.store(address, Ordering::Relaxed);
    EXPECTED_FAULT_RIP.store(rip, Ordering::Relaxed);
    EXPECTED_FAULT_ERROR.store(error, Ordering::Relaxed);
    EXPECTED_FAULT_PROCESSOR.store(observed_processor_id(), Ordering::Relaxed);
    EXPECTED_FAULT_STATE.store(EXPECTED_FAULT_ARMED, Ordering::Release);
    Ok(())
}

/// Arms and executes one exact selector-bound terminal page-fault probe.
/// Falling through the faulting instruction is an explicit test failure.
#[allow(
    unsafe_code,
    reason = "the one-shot expectation fixes the exact assembly site and address before executing the deliberate fault"
)]
pub(crate) fn expect_terminal_page_fault(address: u64, kind: ExpectedPageFaultKind) -> ! {
    if arm_expected_page_fault(address, kind).is_err() {
        complete_fail(0x5046_4152)
    }
    unsafe {
        match kind {
            ExpectedPageFaultKind::UnmappedSupervisorRead => dw_test_unmapped_read(address),
            ExpectedPageFaultKind::WriteProtectedSupervisorWrite => {
                dw_test_write_protected(address, 0x4457_3043_3357_5021)
            }
        }
    }
    complete_fail(0x5046_464c)
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
