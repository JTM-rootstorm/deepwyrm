//! Reset-card R1 relay for Wyrmroot's dynamic-launch saturation probe.
//!
//! `DW1_WYR1_RUNTIME_RESET_IMPLEMENTATION_PLAN.md` card R1A needs the probe's
//! per-step outcomes to leave the guest, and card R1's product deliberately
//! omits the UART driver and consoled, so no userspace serial path exists. This
//! is the selector-private relay that carries them instead.
//!
//! The collector validates only bounded `R1SP` transport: exact length, magic
//! and version, the configured build nonce, a consecutive one-based sequence,
//! single permanent-reporter custody, one terminal record, and the capacity
//! bound. What a step *means* stays a Wyrmroot and host-decoder
//! responsibility, exactly as the selector-33 relay divides it. This private
//! operation is absent from the public ABI and from generated ABI decode.
//!
//! Reporter custody is permanent system-init, matching every other selector.
//! The probe is a dynamically launched client: it sends bounded records to its
//! parent over its ordinary bootstrap channel and permanent init relays them,
//! so no launched child is granted a private kernel operation.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only relay")
)]
// The collector has no target caller yet: the primordial runtime's
// `intercept_r1_evidence_raw` implementation and the terminal reporter arrive
// with card R1's product. The contract is already pinned from both sides by
// these tests and by Wyrmroot's `r1-saturation` record encoder tests.
#![cfg_attr(
    target_os = "none",
    allow(
        dead_code,
        reason = "the primordial intercept and terminal reporter arrive with R1's product"
    )
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::sync::SpinMutex;
use crate::task::ProcessKey;

pub(crate) const R1_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff22;
pub(crate) const R1_EVIDENCE_RECORD_LEN: usize = 64;
pub(crate) const R1_EVIDENCE_RECORD_CAPACITY: usize = 64;

const MAGIC: [u8; 4] = *b"R1SP";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;

/// Record kinds. `STEP` carries one observed scenario step; `FAILED` carries the
/// first failure classification; `TERMINAL` closes the stream exactly once.
const RECORD_STEP: u32 = 1;
const RECORD_FAILED: u32 = 2;
const RECORD_TERMINAL: u32 = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R1EvidenceError {
    /// Submitted before the reporter was established.
    Early,
    /// A Process other than the established reporter submitted a record.
    WrongReporter,
    /// Transport, length, magic, version, or a reserved field is wrong.
    Malformed,
    /// The record's build nonce is not the configured one.
    WrongNonce,
    /// The sequence is not the next consecutive one-based value.
    OutOfOrder,
    /// A record arrived after the terminal record.
    AfterTerminal,
    /// A second terminal record arrived.
    DuplicateTerminal,
    /// The bounded buffer is full.
    Full,
    /// A second Process attempted to claim reporter custody.
    ReporterClaimed,
    /// A `STEP` or `FAILED` record arrived with no preceding failure context, or
    /// a `FAILED` record arrived twice.
    Framing,
}

const STATE_UNSET: u8 = 0;
const STATE_READY: u8 = 1;

/// One validated record plus the sequence it occupied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R1EvidenceRecord {
    pub(crate) sequence: u64,
    pub(crate) bytes: [u8; R1_EVIDENCE_RECORD_LEN],
}

struct R1EvidenceState {
    nonce: u64,
    reporter: Option<ProcessKey>,
    next_sequence: u64,
    terminal_seen: bool,
    failure_seen: bool,
    len: usize,
    records: [Option<R1EvidenceRecord>; R1_EVIDENCE_RECORD_CAPACITY],
}

impl R1EvidenceState {
    const fn new() -> Self {
        Self {
            nonce: 0,
            reporter: None,
            next_sequence: 1,
            terminal_seen: false,
            failure_seen: false,
            len: 0,
            records: [None; R1_EVIDENCE_RECORD_CAPACITY],
        }
    }
}

/// Selector-private collector. One instance per booted kernel.
pub(crate) struct R1EvidenceCollector {
    state: SpinMutex<R1EvidenceState>,
    configured: AtomicU8,
}

fn read_u16(bytes: &[u8; R1_EVIDENCE_RECORD_LEN], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8; R1_EVIDENCE_RECORD_LEN], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8; R1_EVIDENCE_RECORD_LEN], offset: usize) -> u64 {
    let mut word = [0_u8; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(word)
}

impl R1EvidenceCollector {
    pub(crate) const fn new() -> Self {
        Self {
            state: SpinMutex::new(R1EvidenceState::new()),
            configured: AtomicU8::new(STATE_UNSET),
        }
    }

    /// Installs the configured build nonce exactly once. A zero nonce is
    /// refused so an unconfigured product cannot silently accept records.
    pub(crate) fn configure(&self, nonce: u64) -> Result<(), R1EvidenceError> {
        if nonce == 0 {
            return Err(R1EvidenceError::Malformed);
        }
        let mut state = self.state.lock();
        if self.configured.load(Ordering::Acquire) != STATE_UNSET {
            return Err(R1EvidenceError::ReporterClaimed);
        }
        state.nonce = nonce;
        self.configured.store(STATE_READY, Ordering::Release);
        Ok(())
    }

    /// Claims reporter custody for permanent system-init exactly once.
    pub(crate) fn claim_reporter(&self, process: ProcessKey) -> Result<(), R1EvidenceError> {
        if self.configured.load(Ordering::Acquire) != STATE_READY {
            return Err(R1EvidenceError::Early);
        }
        let mut state = self.state.lock();
        if state.reporter.is_some() {
            return Err(R1EvidenceError::ReporterClaimed);
        }
        state.reporter = Some(process);
        Ok(())
    }

    /// Validates and retains one record submitted by the established reporter.
    pub(crate) fn submit(
        &self,
        reporter: ProcessKey,
        bytes: &[u8; R1_EVIDENCE_RECORD_LEN],
    ) -> Result<u64, R1EvidenceError> {
        if self.configured.load(Ordering::Acquire) != STATE_READY {
            return Err(R1EvidenceError::Early);
        }
        let mut state = self.state.lock();
        if state.reporter != Some(reporter) {
            return Err(R1EvidenceError::WrongReporter);
        }
        if state.terminal_seen {
            return Err(R1EvidenceError::AfterTerminal);
        }
        if bytes[0..4] != MAGIC
            || read_u16(bytes, 4) != MAJOR
            || read_u16(bytes, 6) != MINOR
            || read_u32(bytes, 12) as usize != R1_EVIDENCE_RECORD_LEN
            || read_u32(bytes, 60) != 0
        {
            return Err(R1EvidenceError::Malformed);
        }
        if read_u64(bytes, 24) != state.nonce {
            return Err(R1EvidenceError::WrongNonce);
        }
        let sequence = read_u64(bytes, 16);
        if sequence != state.next_sequence {
            return Err(R1EvidenceError::OutOfOrder);
        }
        let kind = read_u32(bytes, 8);
        match kind {
            RECORD_STEP => {
                if state.failure_seen {
                    // A failed probe stops; further steps would misreport it.
                    return Err(R1EvidenceError::Framing);
                }
            }
            RECORD_FAILED => {
                if state.failure_seen {
                    return Err(R1EvidenceError::Framing);
                }
            }
            RECORD_TERMINAL => {}
            _ => return Err(R1EvidenceError::Malformed),
        }
        if state.len >= R1_EVIDENCE_RECORD_CAPACITY {
            return Err(R1EvidenceError::Full);
        }
        let slot = state.len;
        state.records[slot] = Some(R1EvidenceRecord {
            sequence,
            bytes: *bytes,
        });
        state.len = slot + 1;
        state.next_sequence = sequence.checked_add(1).ok_or(R1EvidenceError::OutOfOrder)?;
        match kind {
            RECORD_FAILED => state.failure_seen = true,
            RECORD_TERMINAL => state.terminal_seen = true,
            _ => {}
        }
        Ok(sequence)
    }

    pub(crate) fn len(&self) -> usize {
        self.state.lock().len
    }

    pub(crate) fn terminal_seen(&self) -> bool {
        self.state.lock().terminal_seen
    }

    pub(crate) fn record(&self, index: usize) -> Option<R1EvidenceRecord> {
        let state = self.state.lock();
        if index >= state.len {
            return None;
        }
        state.records[index]
    }
}

#[cfg(test)]
mod tests;
