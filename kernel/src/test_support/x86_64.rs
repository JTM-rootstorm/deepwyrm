//! Narrow x86_64 QEMU test-exit primitives.

#![allow(
    unsafe_code,
    reason = "target-only test completion, fixed fault probes, and QEMU exit I/O are confined to this module"
)]

use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::arch::x86_64::exceptions::{EarlyException, ExceptionVector};
#[cfg(any(
    deepwyrm_i1_evidence,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_dw1e_evidence,
    deepwyrm_wyr1c_evidence,
    deepwyrm_wyr1d_evidence,
    deepwyrm_wyr1e_evidence,
    deepwyrm_r1_evidence,
))]
use crate::debug::TestSerialTransaction;
#[cfg(any(
    deepwyrm_i1_evidence,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_dw1e_evidence,
    deepwyrm_wyr1c_evidence,
    deepwyrm_wyr1d_evidence,
    deepwyrm_wyr1e_evidence,
    deepwyrm_r1_evidence,
))]
use crate::debug::begin_test_serial_transaction;
use crate::debug::emit_early_raw_record;

#[cfg(deepwyrm_dw1e_evidence)]
use super::DW1E_E3A_READY_LEN;
#[cfg(deepwyrm_dw1c_evidence)]
use super::Dw1cEvidenceFlushPermit;
#[cfg(deepwyrm_dw1d_evidence)]
use super::Dw1dEvidenceFlushPermit;
#[cfg(all(deepwyrm_dw1e_evidence, deepwyrm_dw1e_e3b_full))]
use super::Dw1eEvidenceFullPermit;
#[cfg(all(deepwyrm_dw1e_evidence, not(deepwyrm_dw1e_e3b_full)))]
use super::Dw1eEvidencePartialPermit;
#[cfg(deepwyrm_wyr1c_evidence)]
use super::Wyr1cEvidenceFlushError;
#[cfg(deepwyrm_wyr1d_evidence)]
use super::Wyr1dEvidenceFlushError;
#[cfg(deepwyrm_wyr1e_evidence)]
use super::Wyr1eEvidenceFlushError;
#[cfg(deepwyrm_dw1b_evidence)]
use super::dw1b_evidence::Dw1bEvidenceFlushPermit;
#[cfg(deepwyrm_i1_evidence)]
use super::{EvidenceFlushError, I1_EVIDENCE};
#[cfg(deepwyrm_wrcap_relay)]
use super::{WRCAP_RELAY, WrcapFlushError};
#[cfg(deepwyrm_wyr1_evidence)]
use super::{Wyr1EvidenceFlushError, wyr1_evidence::Wyr1EvidenceFlushPermit};
#[cfg(deepwyrm_wyr1b_evidence)]
use super::{Wyr1bEvidenceFlushError, wyr1b_evidence::Wyr1bEvidenceFlushPermit};
use super::{
    identity::{
        ExpectedPageFaultFacts, ExpectedPageFaultKind, completion_record, exception_outcome,
        expected_fault_selector, expected_page_fault_matches, expects_invalid_opcode,
    },
    protocol::{COMPLETION_RECORD_LEN, CompletionOutcome},
    transport::{CompletionTransport, CompletionTransportError, DebugExitValue, complete},
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

#[cfg(deepwyrm_dw1c_evidence)]
const DW1C_TERMINAL_SUCCESS: u8 = 1;
#[cfg(deepwyrm_dw1c_evidence)]
const DW1C_TERMINAL_FAILURE: u8 = 2;
#[cfg(deepwyrm_dw1c_evidence)]
static DW1C_TERMINAL_OWNER: AtomicU8 = AtomicU8::new(0);
#[cfg(deepwyrm_dw1d_evidence)]
const DW1D_TERMINAL_SUCCESS: u8 = 1;
#[cfg(deepwyrm_dw1d_evidence)]
const DW1D_TERMINAL_FAILURE: u8 = 2;
#[cfg(deepwyrm_dw1d_evidence)]
static DW1D_TERMINAL_OWNER: AtomicU8 = AtomicU8::new(0);
#[cfg(deepwyrm_dw1e_evidence)]
const DW1E_TERMINAL_SUCCESS: u8 = 1;
#[cfg(deepwyrm_dw1e_evidence)]
const DW1E_TERMINAL_FAILURE: u8 = 2;
#[cfg(deepwyrm_dw1e_evidence)]
static DW1E_TERMINAL_OWNER: super::Dw1eTerminalArbiter = super::Dw1eTerminalArbiter::new();
#[cfg(deepwyrm_wyr1c_evidence)]
const WYR1C_TERMINAL_SUCCESS: u8 = 1;
#[cfg(deepwyrm_wyr1c_evidence)]
static WYR1C_TERMINAL_OWNER: AtomicU8 = AtomicU8::new(0);
#[cfg(deepwyrm_wyr1d_evidence)]
const WYR1D_TERMINAL_SUCCESS: u8 = 1;
#[cfg(deepwyrm_wyr1d_evidence)]
static WYR1D_TERMINAL_OWNER: AtomicU8 = AtomicU8::new(0);
#[cfg(deepwyrm_wyr1e_evidence)]
const WYR1E_TERMINAL_SUCCESS: u8 = 1;
#[cfg(deepwyrm_wyr1e_evidence)]
static WYR1E_TERMINAL_OWNER: AtomicU8 = AtomicU8::new(0);
#[cfg(deepwyrm_r1_evidence)]
const R1_TERMINAL_SUCCESS: u8 = 1;
#[cfg(deepwyrm_r1_evidence)]
static R1_TERMINAL_OWNER: AtomicU8 = AtomicU8::new(0);

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
    #[cfg(any(
        deepwyrm_i1_evidence,
        deepwyrm_wrcap_relay,
        deepwyrm_wyr1_evidence,
        deepwyrm_dw1b_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_dw1c_evidence,
        deepwyrm_dw1d_evidence,
        deepwyrm_dw1e_evidence,
        deepwyrm_wyr1c_evidence,
        deepwyrm_wyr1d_evidence,
        deepwyrm_wyr1e_evidence,
        deepwyrm_r1_evidence,
    ))]
    transaction: Option<TestSerialTransaction>,
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
        Self {
            _private: (),
            #[cfg(any(
                deepwyrm_i1_evidence,
                deepwyrm_wrcap_relay,
                deepwyrm_wyr1_evidence,
                deepwyrm_dw1b_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_dw1c_evidence,
                deepwyrm_dw1d_evidence,
                deepwyrm_dw1e_evidence,
                deepwyrm_wyr1c_evidence,
                deepwyrm_wyr1d_evidence,
                deepwyrm_wyr1e_evidence,
                deepwyrm_r1_evidence,
            ))]
            transaction: None,
        }
    }
}

impl CompletionTransport for QemuCompletionTransport {
    fn write_serial_record(
        &mut self,
        record: &[u8; COMPLETION_RECORD_LEN],
    ) -> Result<(), CompletionTransportError> {
        // The host requires both the serial record and matching process status;
        // a serial failure therefore becomes infrastructure failure, never PASS.
        #[cfg(any(
            deepwyrm_i1_evidence,
            deepwyrm_wrcap_relay,
            deepwyrm_wyr1_evidence,
            deepwyrm_dw1b_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_dw1c_evidence,
            deepwyrm_dw1d_evidence,
            deepwyrm_dw1e_evidence,
            deepwyrm_wyr1c_evidence,
            deepwyrm_wyr1d_evidence,
            deepwyrm_wyr1e_evidence,
            deepwyrm_r1_evidence,
        ))]
        if let Some(transaction) = self.transaction.as_mut() {
            return transaction
                .write_terminal(record)
                .map_err(|_| CompletionTransportError::Serial);
        }
        emit_early_raw_record(record).map_err(|_| CompletionTransportError::Serial)
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

/// Flush selector 26's fixed evidence record and append its PASS terminal in
/// one exclusive serial transaction before issuing debug-exit.
#[cfg(deepwyrm_dw1b_evidence)]
pub(crate) fn complete_dw1b_evidence(permit: Dw1bEvidenceFlushPermit) -> ! {
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(mut transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    if transaction.write_evidence(permit.record()).is_err() {
        halt_after_completion()
    }
    transport.transaction = Some(transaction);
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

/// Flush selector-25's preserved transcript and append its PASS terminal in
/// the same exclusive COM1 transaction before issuing debug-exit.
#[cfg(deepwyrm_wyr1_evidence)]
pub(crate) fn complete_wyr1_evidence(permit: Wyr1EvidenceFlushPermit<'_>) -> ! {
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let outcome = match begin_test_serial_transaction() {
        Ok(transaction) => {
            transport.transaction = Some(transaction);
            match permit.flush(|record| {
                transport
                    .transaction
                    .as_mut()
                    .expect("WYR1EVID1 reporter owns its serial transaction")
                    .write_evidence(record)
                    .map_err(|_| Wyr1EvidenceFlushError::Transport)
            }) {
                Ok(()) => (CompletionOutcome::Pass, 0),
                Err(error) => (CompletionOutcome::Fail, wyr1_failure_detail(error)),
            }
        }
        Err(_) => halt_after_completion(),
    };
    complete(&mut transport, completion_record(outcome.0, outcome.1))
}

/// Flush selector 27's exact WRB1 transcript and append PASS in the same
/// exclusive COM1 transaction before issuing debug-exit.
#[cfg(deepwyrm_wyr1b_evidence)]
pub(crate) fn complete_wyr1b_evidence(permit: Wyr1bEvidenceFlushPermit<'_>) -> ! {
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let outcome = match begin_test_serial_transaction() {
        Ok(transaction) => {
            transport.transaction = Some(transaction);
            match permit.flush(|record| {
                transport
                    .transaction
                    .as_mut()
                    .expect("WRB1 reporter owns its serial transaction")
                    .write_evidence(record)
                    .map_err(|_| Wyr1bEvidenceFlushError::Transport)
            }) {
                Ok(()) => (CompletionOutcome::Pass, 0),
                Err(error) => (CompletionOutcome::Fail, wyr1b_failure_detail(error)),
            }
        }
        Err(_) => halt_after_completion(),
    };
    complete(&mut transport, completion_record(outcome.0, outcome.1))
}

/// Selector 28 owns one uninterrupted transaction: all 46 kernel-authored
/// DW1C records, then canonical DWTEST1 28/0, then the matching debug exit.
#[cfg(deepwyrm_dw1c_evidence)]
pub(crate) fn complete_dw1c_evidence(permit: Dw1cEvidenceFlushPermit<'_>) -> ! {
    if !claim_dw1c_terminal(DW1C_TERMINAL_SUCCESS) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush(|record| {
            transport
                .transaction
                .as_mut()
                .expect("DW1C owns serial transaction")
                .write_evidence(record)
                .map_err(|_| ())
        })
        .is_err()
    {
        // A transmitted prefix cannot be rolled back. Never append a terminal
        // that could make a partial certificate look like a coherent failure
        // transaction; the host records the bounded serial and timeout.
        halt_after_completion()
    }
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

/// Selector 30 owns one uninterrupted transaction: all 40 authenticated D6
/// records, canonical DWTEST1 30/0, and the matching debug exit.
#[cfg(deepwyrm_dw1d_evidence)]
pub(crate) fn complete_dw1d_evidence(permit: Dw1dEvidenceFlushPermit<'_>) -> ! {
    if !claim_dw1d_terminal(DW1D_TERMINAL_SUCCESS) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush(|record| {
            transport
                .transaction
                .as_mut()
                .expect("DWD6E1 owns serial transaction")
                .write_evidence(record)
                .map_err(|_| ())
        })
        .is_err()
    {
        halt_after_completion()
    }
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

/// Publish the E3A operational readiness marker after action 3 commits. This
/// is deliberately outside both DWE3E1 and DWTEST1 and carries no acceptance
/// meaning.
#[cfg(deepwyrm_dw1e_evidence)]
pub(crate) fn emit_dw1e_e3a_ready(marker: &[u8; DW1E_E3A_READY_LEN]) -> Result<(), ()> {
    let mut transaction = begin_test_serial_transaction().map_err(|_| ())?;
    transaction.write_evidence(marker).map_err(|_| ())
}

/// Emit one selector-32 nonclaim readiness trigger immediately. The three
/// triggers are outside the final contiguous WRD1/DWTEST1 certificate.
#[cfg(deepwyrm_wyr1d_evidence)]
pub(crate) fn emit_wyr1d_ready(
    marker: &[u8; super::wyr1d_evidence::WYR1D_READY_RECORD_LEN],
) -> Result<(), ()> {
    let mut transaction = begin_test_serial_transaction().map_err(|_| ())?;
    transaction.write_evidence(marker).map_err(|_| ())
}

/// E3A's host-extraction gate emits only records 0 through 8. It returns after
/// the partial transcript so the production driver can finish draining the
/// queued WRST response to physical COM2. It never emits a selector PASS or
/// writes the QEMU debug-exit device.
#[cfg(all(deepwyrm_dw1e_evidence, not(deepwyrm_dw1e_e3b_full)))]
pub(crate) fn flush_dw1e_e3a_partial(permit: Dw1eEvidencePartialPermit<'_>) {
    let Ok(mut transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    if permit
        .flush(|record| transaction.write_evidence(record).map_err(|_| ()))
        .is_err()
    {
        halt_after_completion()
    }
}

/// Selector 31 owns one uninterrupted transaction: all 26 DWE3E1 records,
/// canonical `DWTEST1 31 0`, and the matching debug exit.
#[cfg(all(deepwyrm_dw1e_evidence, deepwyrm_dw1e_e3b_full))]
pub(crate) fn complete_dw1e_evidence(permit: Dw1eEvidenceFullPermit<'_>) -> ! {
    if !claim_dw1e_terminal(DW1E_TERMINAL_SUCCESS) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush(|record| {
            transport
                .transaction
                .as_mut()
                .expect("DWE3E1 owns serial transaction")
                .write_evidence(record)
                .map_err(|_| ())
        })
        .is_err()
    {
        halt_after_completion()
    }
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

/// Selector 29 owns one uninterrupted transaction: all WRC6 records,
/// canonical DWTEST1 29/0, and the matching debug exit.
#[cfg(deepwyrm_wyr1c_evidence)]
pub(crate) fn complete_wyr1c_evidence(
    permit: super::wyr1c_evidence::Wyr1cEvidenceFlushPermit<'_>,
) -> ! {
    if !claim_wyr1c_terminal(WYR1C_TERMINAL_SUCCESS) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush(|record| {
            transport
                .transaction
                .as_mut()
                .expect("WRC6 owns serial transaction")
                .write_evidence(record)
                .map_err(|_| Wyr1cEvidenceFlushError::Transport)
        })
        .is_err()
    {
        halt_after_completion()
    }
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

/// Selector 32 owns one uninterrupted transaction: all 12 WRD1 records,
/// canonical DWTEST1 32/0, and the matching debug exit.
#[cfg(deepwyrm_wyr1d_evidence)]
pub(crate) fn complete_wyr1d_evidence(
    permit: super::wyr1d_evidence::Wyr1dEvidenceFlushPermit<'_>,
) -> ! {
    if !claim_wyr1d_terminal(WYR1D_TERMINAL_SUCCESS) {
        halt_after_completion()
    }
    // SAFETY: this function exists only in the centrally selected
    // `native-console-streams` QEMU test image. Its verified handoff profile
    // supplies `isa-debug-exit`; it is not a production or physical image.
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush(|record| {
            transport
                .transaction
                .as_mut()
                .expect("WRD1 owns serial transaction")
                .write_evidence(record)
                .map_err(|_| Wyr1dEvidenceFlushError::Transport)
        })
        .is_err()
    {
        halt_after_completion()
    }
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

/// Selector 33 owns one uninterrupted transaction: the complete bounded WRE1
/// certificate, canonical DWTEST1 33/0, and the matching debug exit.
#[cfg(deepwyrm_wyr1e_evidence)]
pub(crate) fn complete_wyr1e_evidence(
    permit: super::wyr1e_evidence::Wyr1eEvidenceFlushPermit<'_>,
) -> ! {
    if !claim_wyr1e_terminal(WYR1E_TERMINAL_SUCCESS) {
        halt_after_completion()
    }
    // SAFETY: this function exists only in the centrally selected
    // `interactive-wyrmsh` QEMU test image. Its verified handoff profile
    // supplies `isa-debug-exit`; it is not a production or physical image.
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush(|record| {
            transport
                .transaction
                .as_mut()
                .expect("WRE1 owns serial transaction")
                .write_evidence(record)
                .map_err(|_| Wyr1eEvidenceFlushError::Transport)
        })
        .is_err()
    {
        halt_after_completion()
    }
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

/// Reset-card-R1 terminal certificate. The sole terminal owner flushes the
/// bounded `R1SP` transcript over the COM1 test transaction and then completes,
/// which is how the probe's per-step outcomes reach the host: card R1's product
/// omits the userspace UART driver and consoled, not the kernel's own COM1
/// diagnostic path.
#[cfg(deepwyrm_r1_evidence)]
pub(crate) fn complete_r1_evidence(permit: super::r1_evidence::R1EvidenceFlushPermit<'_>) -> ! {
    use super::r1_evidence::R1EvidenceFlushError;

    if !claim_r1_terminal(R1_TERMINAL_SUCCESS) {
        halt_after_completion()
    }
    // SAFETY: this function exists only in the centrally selected
    // `dynamic-launch-saturation` QEMU test image. Its verified handoff profile
    // supplies `isa-debug-exit`; it is not a production or physical image.
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush(|record| {
            transport
                .transaction
                .as_mut()
                .expect("R1SP owns serial transaction")
                .write_evidence(record)
                .map_err(|_| R1EvidenceFlushError::Transport)
        })
        .is_err()
    {
        // An incomplete or refused transcript must not be reported as a pass:
        // halt without a completion record so the run reads as a timeout rather
        // than a false certificate.
        halt_after_completion()
    }
    complete(
        &mut transport,
        completion_record(CompletionOutcome::Pass, 0),
    )
}

#[cfg(deepwyrm_r1_evidence)]
fn claim_r1_terminal(owner: u8) -> bool {
    R1_TERMINAL_OWNER
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(deepwyrm_dw1c_evidence)]
fn claim_dw1c_terminal(owner: u8) -> bool {
    claim_dw1c_terminal_on(&DW1C_TERMINAL_OWNER, owner)
}

#[cfg(deepwyrm_dw1d_evidence)]
fn claim_dw1d_terminal(owner: u8) -> bool {
    DW1D_TERMINAL_OWNER
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(deepwyrm_dw1e_evidence)]
fn claim_dw1e_terminal(owner: u8) -> bool {
    DW1E_TERMINAL_OWNER.claim(owner)
}

#[cfg(deepwyrm_wyr1c_evidence)]
fn claim_wyr1c_terminal(owner: u8) -> bool {
    WYR1C_TERMINAL_OWNER
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(deepwyrm_wyr1d_evidence)]
fn claim_wyr1d_terminal(owner: u8) -> bool {
    WYR1D_TERMINAL_OWNER
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(deepwyrm_wyr1e_evidence)]
fn claim_wyr1e_terminal(owner: u8) -> bool {
    WYR1E_TERMINAL_OWNER
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(any(test, deepwyrm_dw1c_evidence))]
fn claim_dw1c_terminal_on(state: &AtomicU8, owner: u8) -> bool {
    state
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(deepwyrm_dw1c_evidence)]
fn complete_dw1c_failure_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    if !claim_dw1c_terminal(DW1C_TERMINAL_FAILURE) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_dw1d_evidence)]
fn complete_dw1d_failure_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    if !claim_dw1d_terminal(DW1D_TERMINAL_FAILURE) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_dw1e_evidence)]
fn complete_dw1e_failure_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    if !claim_dw1e_terminal(DW1E_TERMINAL_FAILURE) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_wyr1c_evidence)]
fn complete_wyr1c_failure_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    if !claim_wyr1c_terminal(2) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_wyr1d_evidence)]
fn complete_wyr1d_failure_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    if !claim_wyr1d_terminal(2) {
        halt_after_completion()
    }
    // SAFETY: this function exists only in the centrally selected
    // `native-console-streams` QEMU test image. Its verified handoff profile
    // supplies `isa-debug-exit`; it is not a production or physical image.
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_wyr1e_evidence)]
fn complete_wyr1e_failure_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    if !claim_wyr1e_terminal(2) {
        halt_after_completion()
    }
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    complete(&mut transport, completion_record(outcome, detail))
}

/// Selector-25's sole kernel terminal for failures and panics. One atomic
/// claimant owns the accepted evidence prefix, DWTEST1, and debug-exit as one
/// transaction.
#[cfg(deepwyrm_wyr1_evidence)]
fn complete_wyr1_evidence_kernel_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    let Some(permit) = super::WYR1_EVIDENCE.claim_failure() else {
        halt_after_completion()
    };
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush_prefix(|record| {
            transport
                .transaction
                .as_mut()
                .expect("WYR1EVID1 failure owns its serial transaction")
                .write_evidence(record)
                .map_err(|_| Wyr1EvidenceFlushError::Transport)
        })
        .is_err()
    {
        halt_after_completion()
    }
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_wyr1b_evidence)]
fn complete_wyr1b_evidence_kernel_terminal(outcome: CompletionOutcome, detail: u32) -> ! {
    debug_assert!(outcome != CompletionOutcome::Pass);
    let Some(permit) = super::WYR1B_EVIDENCE.claim_failure() else {
        halt_after_completion()
    };
    let mut transport = unsafe { QemuCompletionTransport::new() };
    let Ok(transaction) = begin_test_serial_transaction() else {
        halt_after_completion()
    };
    transport.transaction = Some(transaction);
    if permit
        .flush_prefix(|record| {
            transport
                .transaction
                .as_mut()
                .expect("WRB1 failure owns its serial transaction")
                .write_evidence(record)
                .map_err(|_| Wyr1bEvidenceFlushError::Transport)
        })
        .is_err()
    {
        halt_after_completion()
    }
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_wyr1_evidence)]
fn wyr1_failure_detail(error: Wyr1EvidenceFlushError) -> u32 {
    match error {
        Wyr1EvidenceFlushError::Incomplete => 0x2510_f001,
        Wyr1EvidenceFlushError::Early => 0x2510_f002,
        Wyr1EvidenceFlushError::Retirement => 0x2510_f003,
        Wyr1EvidenceFlushError::WrongReporter => 0x2510_f004,
        Wyr1EvidenceFlushError::Malformed => 0x2510_f005,
        Wyr1EvidenceFlushError::OutOfOrder => 0x2510_f006,
        Wyr1EvidenceFlushError::Full => 0x2510_f007,
        Wyr1EvidenceFlushError::DuplicateTerminal => 0x2510_f008,
        Wyr1EvidenceFlushError::ReporterClaimed => 0x2510_f009,
        Wyr1EvidenceFlushError::Busy => 0x2510_f00a,
        Wyr1EvidenceFlushError::Transport => 0x2510_f00b,
    }
}

#[cfg(deepwyrm_wyr1b_evidence)]
fn wyr1b_failure_detail(error: Wyr1bEvidenceFlushError) -> u32 {
    match error {
        Wyr1bEvidenceFlushError::Incomplete => 0x2710_f001,
        Wyr1bEvidenceFlushError::Early => 0x2710_f002,
        Wyr1bEvidenceFlushError::Retirement => 0x2710_f003,
        Wyr1bEvidenceFlushError::WrongReporter => 0x2710_f004,
        Wyr1bEvidenceFlushError::Malformed => 0x2710_f005,
        Wyr1bEvidenceFlushError::OutOfOrder => 0x2710_f006,
        Wyr1bEvidenceFlushError::Full => 0x2710_f007,
        Wyr1bEvidenceFlushError::DuplicateTerminal => 0x2710_f008,
        Wyr1bEvidenceFlushError::ReporterClaimed => 0x2710_f009,
        Wyr1bEvidenceFlushError::Busy => 0x2710_f00a,
        Wyr1bEvidenceFlushError::Transport => 0x2710_f00b,
        Wyr1bEvidenceFlushError::StartupMissing => 0x2710_f00c,
        Wyr1bEvidenceFlushError::StartupDuplicate => 0x2710_f00d,
        Wyr1bEvidenceFlushError::StartupRoot => 0x2710_f00e,
        Wyr1bEvidenceFlushError::StartupEntry => 0x2710_f00f,
        Wyr1bEvidenceFlushError::StartupStackPointer => 0x2710_f010,
        Wyr1bEvidenceFlushError::StartupStackMapping => 0x2710_f011,
        Wyr1bEvidenceFlushError::StartupStackProtection => 0x2710_f012,
        Wyr1bEvidenceFlushError::StartupGuard => 0x2710_f013,
    }
}

/// Emit the build-selected test's PASS terminal record and stop.
pub(crate) fn complete_pass(detail: u32) -> ! {
    #[cfg(deepwyrm_dw1c_evidence)]
    {
        let _ = detail;
        complete_dw1c_failure_terminal(CompletionOutcome::Fail, 0x2810_ffff)
    }
    #[cfg(deepwyrm_dw1d_evidence)]
    {
        let _ = detail;
        complete_dw1d_failure_terminal(CompletionOutcome::Fail, 0x3010_ffff)
    }
    #[cfg(deepwyrm_dw1e_evidence)]
    {
        let _ = detail;
        complete_dw1e_failure_terminal(CompletionOutcome::Fail, 0x3110_ffff)
    }
    #[cfg(deepwyrm_wyr1c_evidence)]
    {
        let _ = detail;
        complete_wyr1c_failure_terminal(CompletionOutcome::Fail, 0x2910_ffff)
    }
    #[cfg(deepwyrm_wyr1d_evidence)]
    {
        let _ = detail;
        complete_wyr1d_failure_terminal(CompletionOutcome::Fail, 0x3210_ffff)
    }
    #[cfg(deepwyrm_wyr1e_evidence)]
    {
        let _ = detail;
        complete_wyr1e_failure_terminal(CompletionOutcome::Fail, 0x3310_ffff)
    }
    #[cfg(deepwyrm_wyr1_evidence)]
    {
        let _ = detail;
        complete_wyr1_evidence_kernel_terminal(CompletionOutcome::Fail, 0x2510_ffff)
    }
    #[cfg(deepwyrm_dw1b_evidence)]
    {
        let _ = detail;
        complete_known_outcome(CompletionOutcome::Fail, 0x2610_ffff)
    }
    #[cfg(deepwyrm_wyr1b_evidence)]
    {
        let _ = detail;
        complete_wyr1b_evidence_kernel_terminal(CompletionOutcome::Fail, 0x2710_ffff)
    }
    #[cfg(not(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_dw1b_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_dw1c_evidence,
        deepwyrm_dw1d_evidence,
        deepwyrm_dw1e_evidence,
        deepwyrm_wyr1c_evidence,
        deepwyrm_wyr1d_evidence,
        deepwyrm_wyr1e_evidence,
    )))]
    complete_known_outcome(CompletionOutcome::Pass, detail)
}

/// Emit the build-selected test's FAIL terminal record and stop.
pub(crate) fn complete_fail(detail: u32) -> ! {
    #[cfg(deepwyrm_dw1c_evidence)]
    {
        complete_dw1c_failure_terminal(CompletionOutcome::Fail, detail)
    }
    #[cfg(deepwyrm_dw1d_evidence)]
    {
        complete_dw1d_failure_terminal(CompletionOutcome::Fail, detail)
    }
    #[cfg(deepwyrm_dw1e_evidence)]
    {
        complete_dw1e_failure_terminal(CompletionOutcome::Fail, detail)
    }
    #[cfg(deepwyrm_wyr1c_evidence)]
    {
        complete_wyr1c_failure_terminal(CompletionOutcome::Fail, detail)
    }
    #[cfg(deepwyrm_wyr1d_evidence)]
    {
        complete_wyr1d_failure_terminal(CompletionOutcome::Fail, detail)
    }
    #[cfg(deepwyrm_wyr1e_evidence)]
    {
        complete_wyr1e_failure_terminal(CompletionOutcome::Fail, detail)
    }
    #[cfg(deepwyrm_wyr1_evidence)]
    {
        complete_wyr1_evidence_kernel_terminal(CompletionOutcome::Fail, detail)
    }
    #[cfg(not(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_dw1c_evidence,
        deepwyrm_dw1d_evidence,
        deepwyrm_dw1e_evidence,
        deepwyrm_wyr1c_evidence,
        deepwyrm_wyr1d_evidence,
        deepwyrm_wyr1e_evidence,
    )))]
    {
        #[cfg(deepwyrm_wyr1b_evidence)]
        complete_wyr1b_evidence_kernel_terminal(CompletionOutcome::Fail, detail);
        #[cfg(not(deepwyrm_wyr1b_evidence))]
        complete_known_outcome(CompletionOutcome::Fail, detail)
    }
}

/// Emit the build-selected test's PANIC terminal record and stop.
pub(crate) fn complete_panic(detail: u32) -> ! {
    #[cfg(deepwyrm_dw1c_evidence)]
    {
        complete_dw1c_failure_terminal(CompletionOutcome::Panic, detail)
    }
    #[cfg(deepwyrm_dw1d_evidence)]
    {
        complete_dw1d_failure_terminal(CompletionOutcome::Panic, detail)
    }
    #[cfg(deepwyrm_dw1e_evidence)]
    {
        complete_dw1e_failure_terminal(CompletionOutcome::Panic, detail)
    }
    #[cfg(deepwyrm_wyr1c_evidence)]
    {
        complete_wyr1c_failure_terminal(CompletionOutcome::Panic, detail)
    }
    #[cfg(deepwyrm_wyr1d_evidence)]
    {
        complete_wyr1d_failure_terminal(CompletionOutcome::Panic, detail)
    }
    #[cfg(deepwyrm_wyr1e_evidence)]
    {
        complete_wyr1e_failure_terminal(CompletionOutcome::Panic, detail)
    }
    #[cfg(deepwyrm_wyr1_evidence)]
    {
        complete_wyr1_evidence_kernel_terminal(CompletionOutcome::Panic, detail)
    }
    #[cfg(not(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_dw1c_evidence,
        deepwyrm_dw1d_evidence,
        deepwyrm_dw1e_evidence,
        deepwyrm_wyr1c_evidence,
        deepwyrm_wyr1d_evidence,
        deepwyrm_wyr1e_evidence,
    )))]
    {
        #[cfg(deepwyrm_wyr1b_evidence)]
        complete_wyr1b_evidence_kernel_terminal(CompletionOutcome::Panic, detail);
        #[cfg(not(deepwyrm_wyr1b_evidence))]
        complete_known_outcome(CompletionOutcome::Panic, detail)
    }
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
#[cfg(not(any(
    deepwyrm_wyr1_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_wyr1c_evidence,
    deepwyrm_wyr1d_evidence,
    deepwyrm_wyr1e_evidence,
)))]
fn complete_known_outcome(outcome: CompletionOutcome, detail: u32) -> ! {
    // SAFETY: this function exists only in an x86_64-none `test-support` build
    // whose compile-time selector was resolved by the central QEMU harness
    // build path. Such artifacts are not production or physical-hardware images.
    #[cfg(deepwyrm_i1_evidence)]
    let permit = match I1_EVIDENCE.finalize_running_invariant() {
        Ok(permit) => permit,
        // A competing terminal path already owns the I1 transcript. It alone
        // may write COM1 or debug-exit; losers simply stop.
        Err(_) => halt_after_completion(),
    };
    #[cfg(deepwyrm_wrcap_relay)]
    let permit = match WRCAP_RELAY.claim_reporter() {
        Ok(permit) => permit,
        // One reporter owns the WRCAP1 + DWTEST1 serial transaction. A
        // competing terminal path must not append a second transcript.
        Err(_) => halt_after_completion(),
    };
    let mut transport = unsafe { QemuCompletionTransport::new() };
    #[cfg(any(deepwyrm_i1_evidence, deepwyrm_wrcap_relay))]
    let (outcome, detail) = match begin_test_serial_transaction() {
        Ok(transaction) => {
            transport.transaction = Some(transaction);
            #[cfg(deepwyrm_i1_evidence)]
            match permit.flush(|record| {
                transport
                    .transaction
                    .as_mut()
                    .expect("I1 reporter owns its serial transaction")
                    .write_evidence(record)
                    .map_err(|_| EvidenceFlushError::Transport)
            }) {
                Ok(()) => (outcome, detail),
                Err(error) => (CompletionOutcome::Fail, evidence_failure_detail(error)),
            }
            #[cfg(deepwyrm_wrcap_relay)]
            match permit.flush(|record| {
                transport
                    .transaction
                    .as_mut()
                    .expect("WRCAP1 reporter owns its serial transaction")
                    .write_evidence(record)
                    .map_err(|_| WrcapFlushError::Transport)
            }) {
                Ok(()) => (outcome, detail),
                Err(error) => wrcap_flush_failure(outcome, detail, error),
            }
        }
        Err(_) => halt_after_completion(),
    };
    complete(&mut transport, completion_record(outcome, detail))
}

#[cfg(deepwyrm_wrcap_relay)]
fn wrcap_flush_failure(
    outcome: CompletionOutcome,
    detail: u32,
    error: WrcapFlushError,
) -> (CompletionOutcome, u32) {
    if outcome == CompletionOutcome::Pass {
        (CompletionOutcome::Fail, wrcap_failure_detail(error))
    } else {
        // A missing transcript is a consequence when the primordial process
        // failed before evidence publication. Preserve that first exact
        // application or kernel failure instead of replacing it with the
        // secondary incomplete-relay diagnosis.
        (outcome, detail)
    }
}

#[cfg(deepwyrm_wrcap_relay)]
fn wrcap_failure_detail(error: WrcapFlushError) -> u32 {
    match error {
        WrcapFlushError::Incomplete => 0x240a_f001,
        WrcapFlushError::Malformed => 0x240a_f002,
        WrcapFlushError::OutOfOrder => 0x240a_f003,
        WrcapFlushError::Extra => 0x240a_f004,
        WrcapFlushError::Receive => 0x240a_f005,
        WrcapFlushError::ReporterClaimed => 0x240a_f006,
        WrcapFlushError::Busy => 0x240a_f007,
        WrcapFlushError::Transport => 0x240a_f008,
    }
}

#[cfg(deepwyrm_i1_evidence)]
fn evidence_failure_detail(error: EvidenceFlushError) -> u32 {
    match error {
        EvidenceFlushError::NotFinalized => 0x4931_0001,
        EvidenceFlushError::NotReady => 0x4931_0002,
        EvidenceFlushError::Overflow => 0x4931_0003,
        EvidenceFlushError::Malformed => 0x4931_0004,
        EvidenceFlushError::Invariant => 0x4931_0500 | super::i1_runtime_missing_mask(),
        EvidenceFlushError::FinalizationClosed => 0x4931_0006,
        EvidenceFlushError::ReporterClaimed => 0x4931_0007,
        EvidenceFlushError::Transport => 0x4931_0008,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dw1c_terminal_arbitration_has_one_success_or_failure_winner() {
        let success_first = AtomicU8::new(0);
        assert!(claim_dw1c_terminal_on(&success_first, 1));
        assert!(!claim_dw1c_terminal_on(&success_first, 2));
        assert_eq!(success_first.load(Ordering::Acquire), 1);

        let failure_first = AtomicU8::new(0);
        assert!(claim_dw1c_terminal_on(&failure_first, 2));
        assert!(!claim_dw1c_terminal_on(&failure_first, 1));
        assert_eq!(failure_first.load(Ordering::Acquire), 2);
    }
}
