//! Selector-25-only relay for Wyrmroot-owned WYR1EVID1 evidence.
//!
//! This is a fixed-capacity acceptance transport, not a public syscall or a
//! kernel interpretation of Wyrmroot supervision policy. The kernel validates
//! canonical framing and scenario termination, then preserves every accepted
//! line byte-for-byte for one exclusive terminal COM1 transaction.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only relay")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::sync::SpinMutex;
use crate::task::ProcessKey;

pub(crate) const WYR1_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff19;
pub(crate) const WYR1_EVIDENCE_RECORD_LEN: usize = 114;
pub(crate) const WYR1_EVIDENCE_RECORD_CAPACITY: usize = 32;
const CHECKSUM_OFFSET: usize = 105;
const TERMINAL_KIND: u8 = 0xff;
const EMPTY_RECORD: [u8; WYR1_EVIDENCE_RECORD_LEN] = [0; WYR1_EVIDENCE_RECORD_LEN];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Normal,
    DegradedRecovery,
}

impl Scenario {
    const fn code(self) -> u8 {
        match self {
            Self::Normal => 1,
            Self::DegradedRecovery => 2,
        }
    }
}

#[cfg(not(test))]
const fn build_scenario() -> Scenario {
    const VALUE: &str = env!(
        "DEEPWYRM_WYR1_EVIDENCE_SCENARIO",
        "selector 25 requires its build-owned evidence scenario"
    );
    if string_equals(VALUE, "normal") {
        Scenario::Normal
    } else if string_equals(VALUE, "degraded_recovery") {
        Scenario::DegradedRecovery
    } else {
        panic!("invalid build-owned WYR1 evidence scenario")
    }
}

#[cfg(test)]
const fn build_scenario() -> Scenario {
    Scenario::Normal
}

const fn string_equals(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wyr1EvidenceError {
    Early,
    Retirement,
    WrongReporter,
    Malformed,
    OutOfOrder,
    Full,
    DuplicateTerminal,
    ReporterClaimed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wyr1EvidenceFlushError {
    Incomplete,
    Early,
    Retirement,
    WrongReporter,
    Malformed,
    OutOfOrder,
    Full,
    DuplicateTerminal,
    ReporterClaimed,
    Busy,
    Transport,
}

pub(crate) enum Wyr1EvidenceSubmit<'a> {
    Accepted,
    Terminal(Wyr1EvidenceFlushPermit<'a>),
}

/// Kernel-owned retirement facts required before selector 25 can expose its
/// reporter. The primordial architecture root is deliberately distinguished:
/// its user mappings and root-region authority are retired, while its private
/// bootstrap PML4 remains reserved as kernel-owned architecture storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Wyr1RetirementFacts {
    pub(crate) process_quiesced: bool,
    pub(crate) root_region_retired: bool,
    pub(crate) monitor_and_kernel_peer_released: bool,
    pub(crate) finalizers_drained: bool,
    pub(crate) private_primordial_pml4_retained: bool,
}

impl Wyr1RetirementFacts {
    const fn complete(self) -> bool {
        self.process_quiesced
            && self.root_region_retired
            && self.monitor_and_kernel_peer_released
            && self.finalizers_drained
            && self.private_primordial_pml4_retained
    }
}

struct Transcript {
    records: [[u8; WYR1_EVIDENCE_RECORD_LEN]; WYR1_EVIDENCE_RECORD_CAPACITY],
    count: usize,
    reporter: Option<ProcessKey>,
    retired: bool,
    terminal: bool,
    failure: Option<Wyr1EvidenceError>,
}

impl Transcript {
    const fn new() -> Self {
        Self {
            records: [EMPTY_RECORD; WYR1_EVIDENCE_RECORD_CAPACITY],
            count: 0,
            reporter: None,
            retired: false,
            terminal: false,
            failure: None,
        }
    }

    fn latch(&mut self, error: Wyr1EvidenceError) -> Wyr1EvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

/// Fixed-capacity selector-local WYR1EVID1 transcript and reporter binding.
pub(crate) struct Wyr1EvidenceCollector {
    transcript: SpinMutex<Transcript>,
    terminal_claimed: AtomicU8,
}

impl Wyr1EvidenceCollector {
    pub(crate) const fn new() -> Self {
        Self {
            transcript: SpinMutex::new(Transcript::new()),
            terminal_claimed: AtomicU8::new(0),
        }
    }

    /// Bind the sole reporter only after the kernel has verified and retired
    /// the primordial bootstrap. Failure is latched rather than weakened into
    /// permission for a later process to claim the relay.
    pub(crate) fn bind_reporter_after_retirement(
        &self,
        reporter: ProcessKey,
        facts: Wyr1RetirementFacts,
    ) -> Result<(), Wyr1EvidenceError> {
        let mut transcript = self.transcript.lock();
        if !facts.complete() || transcript.retired || transcript.reporter.is_some() {
            return Err(transcript.latch(Wyr1EvidenceError::Retirement));
        }
        if transcript.failure.is_some() {
            return Err(transcript.failure.expect("latched failure"));
        }
        transcript.reporter = Some(reporter);
        transcript.retired = true;
        Ok(())
    }

    /// Authorize the exact bound reporter before any user memory is touched.
    /// [`submit`](Self::submit) repeats these checks at commit time.
    pub(crate) fn authorize_submission(
        &self,
        process: ProcessKey,
    ) -> Result<(), Wyr1EvidenceError> {
        let mut transcript = self.transcript.lock();
        if !transcript.retired {
            return Err(transcript.latch(Wyr1EvidenceError::Early));
        }
        if transcript.reporter != Some(process) {
            return Err(transcript.latch(Wyr1EvidenceError::WrongReporter));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        if transcript.terminal {
            return Err(transcript.latch(Wyr1EvidenceError::DuplicateTerminal));
        }
        if transcript.count == WYR1_EVIDENCE_RECORD_CAPACITY {
            return Err(transcript.latch(Wyr1EvidenceError::Full));
        }
        Ok(())
    }

    /// Validate and preserve one exact reporter submission.
    pub(crate) fn submit(
        &self,
        process: ProcessKey,
        record: &[u8; WYR1_EVIDENCE_RECORD_LEN],
    ) -> Result<Wyr1EvidenceSubmit<'_>, Wyr1EvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)?;
        let terminal = match validate_record(record, transcript.count as u32, build_scenario()) {
            Ok(terminal) => terminal,
            Err(error) => return Err(transcript.latch(error)),
        };
        if terminal {
            self.terminal_claimed
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| transcript.latch(Wyr1EvidenceError::ReporterClaimed))?;
        }
        let index = transcript.count;
        transcript.records[index] = *record;
        transcript.count += 1;
        if terminal {
            transcript.terminal = true;
            drop(transcript);
            Ok(Wyr1EvidenceSubmit::Terminal(Wyr1EvidenceFlushPermit {
                collector: self,
            }))
        } else {
            drop(transcript);
            Ok(Wyr1EvidenceSubmit::Accepted)
        }
    }

    /// Claim the selector's only terminal path for a kernel-detected failure.
    pub(crate) fn claim_failure(&self) -> Option<Wyr1EvidenceFailurePermit<'_>> {
        self.terminal_claimed
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Wyr1EvidenceFailurePermit { collector: self })
    }
}

fn authorize_locked(
    transcript: &mut Transcript,
    process: ProcessKey,
) -> Result<(), Wyr1EvidenceError> {
    if !transcript.retired {
        return Err(transcript.latch(Wyr1EvidenceError::Early));
    }
    if transcript.reporter != Some(process) {
        return Err(transcript.latch(Wyr1EvidenceError::WrongReporter));
    }
    if let Some(error) = transcript.failure {
        return Err(error);
    }
    if transcript.terminal {
        return Err(transcript.latch(Wyr1EvidenceError::DuplicateTerminal));
    }
    if transcript.count == WYR1_EVIDENCE_RECORD_CAPACITY {
        return Err(transcript.latch(Wyr1EvidenceError::Full));
    }
    Ok(())
}

#[must_use]
pub(crate) struct Wyr1EvidenceFlushPermit<'a> {
    collector: &'a Wyr1EvidenceCollector,
}

#[must_use]
pub(crate) struct Wyr1EvidenceFailurePermit<'a> {
    collector: &'a Wyr1EvidenceCollector,
}

impl Wyr1EvidenceFailurePermit<'_> {
    /// Emit the already-accepted prefix. Failure paths intentionally do not
    /// require a terminal evidence record; the following DWTEST1 FAIL is the
    /// authoritative finite terminal.
    pub(crate) fn flush_prefix(
        self,
        mut emit: impl FnMut(&[u8; WYR1_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1EvidenceFlushError>,
    ) -> Result<(), Wyr1EvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1EvidenceFlushError::Busy)?;
        for record in &transcript.records[..transcript.count] {
            emit(record)?;
        }
        Ok(())
    }
}

impl Wyr1EvidenceFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; WYR1_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1EvidenceFlushError>,
    ) -> Result<(), Wyr1EvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1EvidenceFlushError::Busy)?;
        if let Some(error) = transcript.failure {
            return Err(flush_error(error));
        }
        if !transcript.retired || !transcript.terminal || transcript.count == 0 {
            return Err(Wyr1EvidenceFlushError::Incomplete);
        }
        let records = transcript.records;
        let count = transcript.count;
        drop(transcript);
        for record in &records[..count] {
            emit(record)?;
        }
        Ok(())
    }
}

const fn flush_error(error: Wyr1EvidenceError) -> Wyr1EvidenceFlushError {
    match error {
        Wyr1EvidenceError::Early => Wyr1EvidenceFlushError::Early,
        Wyr1EvidenceError::Retirement => Wyr1EvidenceFlushError::Retirement,
        Wyr1EvidenceError::WrongReporter => Wyr1EvidenceFlushError::WrongReporter,
        Wyr1EvidenceError::Malformed => Wyr1EvidenceFlushError::Malformed,
        Wyr1EvidenceError::OutOfOrder => Wyr1EvidenceFlushError::OutOfOrder,
        Wyr1EvidenceError::Full => Wyr1EvidenceFlushError::Full,
        Wyr1EvidenceError::DuplicateTerminal => Wyr1EvidenceFlushError::DuplicateTerminal,
        Wyr1EvidenceError::ReporterClaimed => Wyr1EvidenceFlushError::ReporterClaimed,
    }
}

fn validate_record(
    record: &[u8; WYR1_EVIDENCE_RECORD_LEN],
    expected_sequence: u32,
    scenario: Scenario,
) -> Result<bool, Wyr1EvidenceError> {
    if &record[0..9] != b"WYR1EVID1"
        || record[9] != b'|'
        || &record[10..12] != b"01"
        || record[12] != b'|'
        || record[29] != b'|'
        || record[38] != b'|'
        || record[41] != b'|'
        || record[44] != b'|'
        || record[53] != b'|'
        || record[70] != b'|'
        || record[87] != b'|'
        || record[104] != b'|'
        || record[113] != b'\n'
    {
        return Err(Wyr1EvidenceError::Malformed);
    }
    for range in [
        13..29,
        30..38,
        39..41,
        42..44,
        45..53,
        54..70,
        71..87,
        88..104,
        105..113,
    ] {
        if !record[range].iter().copied().all(is_upper_hex) {
            return Err(Wyr1EvidenceError::Malformed);
        }
    }
    if record[13..29] != *build_nonce().as_bytes() {
        return Err(Wyr1EvidenceError::Malformed);
    }
    let sequence = parse_hex_u32(&record[30..38]).ok_or(Wyr1EvidenceError::Malformed)?;
    let kind = parse_hex_u8(&record[39..41]).ok_or(Wyr1EvidenceError::Malformed)?;
    let record_scenario = parse_hex_u8(&record[42..44]).ok_or(Wyr1EvidenceError::Malformed)?;
    let role = parse_hex_u32(&record[45..53]).ok_or(Wyr1EvidenceError::Malformed)?;
    let generation = parse_hex_u64(&record[54..70]).ok_or(Wyr1EvidenceError::Malformed)?;
    let transaction = parse_hex_u64(&record[71..87]).ok_or(Wyr1EvidenceError::Malformed)?;
    let value = parse_hex_u64(&record[88..104]).ok_or(Wyr1EvidenceError::Malformed)?;
    let checksum =
        parse_hex_u32(&record[CHECKSUM_OFFSET..113]).ok_or(Wyr1EvidenceError::Malformed)?;
    if sequence != expected_sequence {
        return Err(Wyr1EvidenceError::OutOfOrder);
    }
    if record_scenario != scenario.code() || checksum != fnv1a32(&record[..CHECKSUM_OFFSET]) {
        return Err(Wyr1EvidenceError::Malformed);
    }
    match kind {
        0x01 if role != 0 && generation != 0 && transaction != 0 && value == 0 => Ok(false),
        0x02 if role != 0 && generation != 0 && transaction != 0 => Ok(false),
        0x03 if role != 0 && generation != 0 && transaction != 0 && value > generation => Ok(false),
        0x04 if role != 0 && generation != 0 && transaction != 0 && value != 0 => Ok(false),
        TERMINAL_KIND if role == 0 && generation == 0 && transaction == 0 && value == 0 => Ok(true),
        _ => Err(Wyr1EvidenceError::Malformed),
    }
}

#[cfg(not(test))]
const fn build_nonce() -> &'static str {
    env!(
        "DEEPWYRM_WYR1_EVIDENCE_NONCE",
        "selector 25 requires its build-owned evidence nonce"
    )
}

#[cfg(test)]
const fn build_nonce() -> &'static str {
    "0123456789ABCDEF"
}

const fn is_upper_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'F')
}

fn parse_hex_u8(bytes: &[u8]) -> Option<u8> {
    u8::try_from(parse_hex_u64(bytes)?).ok()
}

fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    u32::try_from(parse_hex_u64(bytes)?).ok()
}

fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    Some(value)
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut checksum = 0x811c_9dc5_u32;
    for byte in bytes {
        checksum ^= u32::from(*byte);
        checksum = checksum.wrapping_mul(0x0100_0193);
    }
    checksum
}

pub(crate) static WYR1_EVIDENCE: Wyr1EvidenceCollector = Wyr1EvidenceCollector::new();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::DW_OBJECT_TYPE_PROCESS;

    const RETIRED: Wyr1RetirementFacts = Wyr1RetirementFacts {
        process_quiesced: true,
        root_region_retired: true,
        monitor_and_kernel_peer_released: true,
        finalizers_drained: true,
        private_primordial_pml4_retained: true,
    };

    fn process_key() -> ProcessKey {
        let mut registry = ObjectRegistry::<1>::new();
        let process = registry
            .create(DW_OBJECT_TYPE_PROCESS)
            .expect("test Process object creation");
        ProcessKey::from_object_id(process.id())
    }

    fn write_hex(mut value: u64, output: &mut [u8]) {
        for byte in output.iter_mut().rev() {
            let digit = (value & 0xf) as u8;
            *byte = if digit < 10 {
                b'0' + digit
            } else {
                b'A' + digit - 10
            };
            value >>= 4;
        }
        assert_eq!(value, 0);
    }

    fn record(
        sequence: u32,
        kind: u8,
        role: u32,
        generation: u64,
        transaction: u64,
        value: u64,
    ) -> [u8; WYR1_EVIDENCE_RECORD_LEN] {
        let mut record = [b'0'; WYR1_EVIDENCE_RECORD_LEN];
        record[0..9].copy_from_slice(b"WYR1EVID1");
        for delimiter in [9, 12, 29, 38, 41, 44, 53, 70, 87, 104] {
            record[delimiter] = b'|';
        }
        record[10..12].copy_from_slice(b"01");
        record[13..29].copy_from_slice(build_nonce().as_bytes());
        write_hex(u64::from(sequence), &mut record[30..38]);
        write_hex(u64::from(kind), &mut record[39..41]);
        write_hex(u64::from(build_scenario().code()), &mut record[42..44]);
        write_hex(u64::from(role), &mut record[45..53]);
        write_hex(generation, &mut record[54..70]);
        write_hex(transaction, &mut record[71..87]);
        write_hex(value, &mut record[88..104]);
        let checksum = fnv1a32(&record[..CHECKSUM_OFFSET]);
        write_hex(u64::from(checksum), &mut record[105..113]);
        record[113] = b'\n';
        record
    }

    #[test]
    fn exact_records_are_preserved_through_terminal() {
        let collector = Wyr1EvidenceCollector::new();
        let reporter = process_key();
        collector
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        let ready = record(0, 1, 1, 1, 17, 0);
        assert!(matches!(
            collector.submit(reporter, &ready),
            Ok(Wyr1EvidenceSubmit::Accepted)
        ));
        let terminal = record(1, 0xff, 0, 0, 0, 0);
        let Ok(Wyr1EvidenceSubmit::Terminal(permit)) = collector.submit(reporter, &terminal) else {
            panic!("terminal permit")
        };
        let mut observed = [[0; WYR1_EVIDENCE_RECORD_LEN]; 2];
        let mut count = 0;
        permit
            .flush(|record| {
                observed[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(observed, [ready, terminal]);
    }

    #[test]
    fn early_wrong_duplicate_and_malformed_facts_latch() {
        let reporter = process_key();
        let other = process_key();
        let early = Wyr1EvidenceCollector::new();
        assert!(matches!(
            early.submit(reporter, &record(0, 1, 1, 1, 1, 0)),
            Err(Wyr1EvidenceError::Early)
        ));

        let wrong = Wyr1EvidenceCollector::new();
        wrong
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        assert!(matches!(
            wrong.submit(other, &record(0, 1, 1, 1, 1, 0)),
            Err(Wyr1EvidenceError::WrongReporter)
        ));

        let malformed = Wyr1EvidenceCollector::new();
        malformed
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        let mut bad = record(0, 1, 1, 1, 1, 0);
        bad[105] ^= 1;
        assert!(matches!(
            malformed.submit(reporter, &bad),
            Err(Wyr1EvidenceError::Malformed)
        ));
    }

    #[test]
    fn every_retirement_fact_is_required_before_enablement() {
        let reporter = process_key();
        for facts in [
            Wyr1RetirementFacts {
                process_quiesced: false,
                ..RETIRED
            },
            Wyr1RetirementFacts {
                root_region_retired: false,
                ..RETIRED
            },
            Wyr1RetirementFacts {
                monitor_and_kernel_peer_released: false,
                ..RETIRED
            },
            Wyr1RetirementFacts {
                finalizers_drained: false,
                ..RETIRED
            },
            Wyr1RetirementFacts {
                private_primordial_pml4_retained: false,
                ..RETIRED
            },
        ] {
            let collector = Wyr1EvidenceCollector::new();
            assert_eq!(
                collector.bind_reporter_after_retirement(reporter, facts),
                Err(Wyr1EvidenceError::Retirement)
            );
        }
    }

    #[test]
    fn authorization_rejects_early_and_wrong_reporters_before_record_access() {
        let reporter = process_key();
        let wrong = process_key();
        let early = Wyr1EvidenceCollector::new();
        assert_eq!(
            early.authorize_submission(reporter),
            Err(Wyr1EvidenceError::Early)
        );
        let collector = Wyr1EvidenceCollector::new();
        collector
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        assert_eq!(
            collector.authorize_submission(wrong),
            Err(Wyr1EvidenceError::WrongReporter)
        );
    }

    #[test]
    fn transcript_accepts_exactly_32_records_and_rejects_record_33() {
        let reporter = process_key();
        let collector = Wyr1EvidenceCollector::new();
        collector
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        for sequence in 0..31 {
            assert!(matches!(
                collector.submit(reporter, &record(sequence, 1, 1, 1, 1, 0)),
                Ok(Wyr1EvidenceSubmit::Accepted)
            ));
        }
        let Ok(Wyr1EvidenceSubmit::Terminal(permit)) =
            collector.submit(reporter, &record(31, 0xff, 0, 0, 0, 0))
        else {
            panic!("record 32 must be the accepted terminal")
        };
        let mut count = 0;
        permit
            .flush(|_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 32);

        let full = Wyr1EvidenceCollector::new();
        full.bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        for sequence in 0..32 {
            assert!(matches!(
                full.submit(reporter, &record(sequence, 1, 1, 1, 1, 0)),
                Ok(Wyr1EvidenceSubmit::Accepted)
            ));
        }
        assert_eq!(
            full.authorize_submission(reporter),
            Err(Wyr1EvidenceError::Full)
        );
    }

    #[test]
    fn sequence_duplicate_terminal_and_terminal_claim_are_exclusive() {
        let reporter = process_key();
        let out_of_order = Wyr1EvidenceCollector::new();
        out_of_order
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        assert!(matches!(
            out_of_order.submit(reporter, &record(1, 1, 1, 1, 1, 0)),
            Err(Wyr1EvidenceError::OutOfOrder)
        ));

        let terminal = Wyr1EvidenceCollector::new();
        terminal
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        let Ok(Wyr1EvidenceSubmit::Terminal(_permit)) =
            terminal.submit(reporter, &record(0, 0xff, 0, 0, 0, 0))
        else {
            panic!("first terminal must claim completion")
        };
        assert!(matches!(
            terminal.submit(reporter, &record(1, 0xff, 0, 0, 0, 0)),
            Err(Wyr1EvidenceError::DuplicateTerminal)
        ));
        assert!(terminal.claim_failure().is_none());

        let failure = Wyr1EvidenceCollector::new();
        assert!(failure.claim_failure().is_some());
        assert!(failure.claim_failure().is_none());
    }
}
