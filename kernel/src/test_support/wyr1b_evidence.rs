//! Selector-27-only relay for Wyrmroot-owned WRB1 evidence.
//!
//! This fixed-capacity collector validates the canonical record framing,
//! build-bound nonce, and exact event order. It does not interpret registry or
//! launch policy and is not part of Deepwyrm's public ABI.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only relay")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::sync::SpinMutex;
use crate::task::ProcessKey;

pub(crate) const WYR1B_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1b;
pub(crate) const WYR1B_EVIDENCE_RECORD_LEN: usize = 96;
pub(crate) const WYR1B_EVIDENCE_RECORD_CAPACITY: usize = 14;
const CHECKSUM_OFFSET: usize = 88;
const TERMINAL_EVENT: u8 = 0xff;
const EMPTY_RECORD: [u8; WYR1B_EVIDENCE_RECORD_LEN] = [0; WYR1B_EVIDENCE_RECORD_LEN];
const EXPECTED_EVENTS: [u8; WYR1B_EVIDENCE_RECORD_CAPACITY] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, TERMINAL_EVENT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wyr1bEvidenceError {
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
pub(crate) enum Wyr1bEvidenceFlushError {
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

pub(crate) enum Wyr1bEvidenceSubmit<'a> {
    Accepted,
    Terminal(Wyr1bEvidenceFlushPermit<'a>),
}

/// Kernel-owned facts required before the permanent controller may report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Wyr1bRetirementFacts {
    pub(crate) process_quiesced: bool,
    pub(crate) root_region_retired: bool,
    pub(crate) monitor_and_kernel_peer_released: bool,
    pub(crate) finalizers_drained: bool,
    pub(crate) private_primordial_pml4_retained: bool,
}

impl Wyr1bRetirementFacts {
    const fn complete(self) -> bool {
        self.process_quiesced
            && self.root_region_retired
            && self.monitor_and_kernel_peer_released
            && self.finalizers_drained
            && self.private_primordial_pml4_retained
    }
}

struct Transcript {
    records: [[u8; WYR1B_EVIDENCE_RECORD_LEN]; WYR1B_EVIDENCE_RECORD_CAPACITY],
    count: usize,
    reporter: Option<ProcessKey>,
    retired: bool,
    terminal: bool,
    failure: Option<Wyr1bEvidenceError>,
}

impl Transcript {
    const fn new() -> Self {
        Self {
            records: [EMPTY_RECORD; WYR1B_EVIDENCE_RECORD_CAPACITY],
            count: 0,
            reporter: None,
            retired: false,
            terminal: false,
            failure: None,
        }
    }

    fn latch(&mut self, error: Wyr1bEvidenceError) -> Wyr1bEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

/// Fixed-capacity selector-local WRB1 transcript and reporter binding.
pub(crate) struct Wyr1bEvidenceCollector {
    transcript: SpinMutex<Transcript>,
    terminal_claimed: AtomicU8,
    nonce: u64,
}

impl Wyr1bEvidenceCollector {
    pub(crate) const fn new(nonce: u64) -> Self {
        assert!(nonce != 0, "selector-27 evidence nonce must be nonzero");
        Self {
            transcript: SpinMutex::new(Transcript::new()),
            terminal_claimed: AtomicU8::new(0),
            nonce,
        }
    }

    pub(crate) fn bind_reporter_after_retirement(
        &self,
        reporter: ProcessKey,
        facts: Wyr1bRetirementFacts,
    ) -> Result<(), Wyr1bEvidenceError> {
        let mut transcript = self.transcript.lock();
        if !facts.complete() || transcript.retired || transcript.reporter.is_some() {
            return Err(transcript.latch(Wyr1bEvidenceError::Retirement));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        transcript.reporter = Some(reporter);
        transcript.retired = true;
        Ok(())
    }

    /// Check reporter authority before any userspace address is accessed.
    pub(crate) fn authorize_submission(
        &self,
        process: ProcessKey,
    ) -> Result<(), Wyr1bEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)
    }

    pub(crate) fn submit(
        &self,
        process: ProcessKey,
        record: &[u8; WYR1B_EVIDENCE_RECORD_LEN],
    ) -> Result<Wyr1bEvidenceSubmit<'_>, Wyr1bEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)?;
        let terminal = match validate_record(record, transcript.count, self.nonce) {
            Ok(terminal) => terminal,
            Err(error) => return Err(transcript.latch(error)),
        };
        if terminal {
            self.terminal_claimed
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| transcript.latch(Wyr1bEvidenceError::ReporterClaimed))?;
        }
        let index = transcript.count;
        transcript.records[index] = *record;
        transcript.count += 1;
        if terminal {
            transcript.terminal = true;
            drop(transcript);
            Ok(Wyr1bEvidenceSubmit::Terminal(Wyr1bEvidenceFlushPermit {
                collector: self,
            }))
        } else {
            Ok(Wyr1bEvidenceSubmit::Accepted)
        }
    }

    pub(crate) fn claim_failure(&self) -> Option<Wyr1bEvidenceFailurePermit<'_>> {
        self.terminal_claimed
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Wyr1bEvidenceFailurePermit { collector: self })
    }
}

fn authorize_locked(
    transcript: &mut Transcript,
    process: ProcessKey,
) -> Result<(), Wyr1bEvidenceError> {
    if !transcript.retired {
        return Err(transcript.latch(Wyr1bEvidenceError::Early));
    }
    if transcript.reporter != Some(process) {
        return Err(transcript.latch(Wyr1bEvidenceError::WrongReporter));
    }
    if let Some(error) = transcript.failure {
        return Err(error);
    }
    if transcript.terminal {
        return Err(transcript.latch(Wyr1bEvidenceError::DuplicateTerminal));
    }
    if transcript.count == WYR1B_EVIDENCE_RECORD_CAPACITY {
        return Err(transcript.latch(Wyr1bEvidenceError::Full));
    }
    Ok(())
}

#[must_use]
pub(crate) struct Wyr1bEvidenceFlushPermit<'a> {
    collector: &'a Wyr1bEvidenceCollector,
}

#[must_use]
pub(crate) struct Wyr1bEvidenceFailurePermit<'a> {
    collector: &'a Wyr1bEvidenceCollector,
}

impl Wyr1bEvidenceFailurePermit<'_> {
    pub(crate) fn flush_prefix(
        self,
        mut emit: impl FnMut(&[u8; WYR1B_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1bEvidenceFlushError>,
    ) -> Result<(), Wyr1bEvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1bEvidenceFlushError::Busy)?;
        for record in &transcript.records[..transcript.count] {
            emit(record)?;
        }
        Ok(())
    }
}

impl Wyr1bEvidenceFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; WYR1B_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1bEvidenceFlushError>,
    ) -> Result<(), Wyr1bEvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1bEvidenceFlushError::Busy)?;
        if let Some(error) = transcript.failure {
            return Err(flush_error(error));
        }
        if !transcript.retired
            || !transcript.terminal
            || transcript.count != WYR1B_EVIDENCE_RECORD_CAPACITY
        {
            return Err(Wyr1bEvidenceFlushError::Incomplete);
        }
        let records = transcript.records;
        drop(transcript);
        for record in &records {
            emit(record)?;
        }
        Ok(())
    }
}

const fn flush_error(error: Wyr1bEvidenceError) -> Wyr1bEvidenceFlushError {
    match error {
        Wyr1bEvidenceError::Early => Wyr1bEvidenceFlushError::Early,
        Wyr1bEvidenceError::Retirement => Wyr1bEvidenceFlushError::Retirement,
        Wyr1bEvidenceError::WrongReporter => Wyr1bEvidenceFlushError::WrongReporter,
        Wyr1bEvidenceError::Malformed => Wyr1bEvidenceFlushError::Malformed,
        Wyr1bEvidenceError::OutOfOrder => Wyr1bEvidenceFlushError::OutOfOrder,
        Wyr1bEvidenceError::Full => Wyr1bEvidenceFlushError::Full,
        Wyr1bEvidenceError::DuplicateTerminal => Wyr1bEvidenceFlushError::DuplicateTerminal,
        Wyr1bEvidenceError::ReporterClaimed => Wyr1bEvidenceFlushError::ReporterClaimed,
    }
}

fn validate_record(
    record: &[u8; WYR1B_EVIDENCE_RECORD_LEN],
    expected_sequence: usize,
    nonce: u64,
) -> Result<bool, Wyr1bEvidenceError> {
    if &record[..4] != b"WRB1"
        || record[4] != b'|'
        || &record[5..7] != b"01"
        || record[7] != b'|'
        || record[24] != b'|'
        || record[33] != b'|'
        || record[36] != b'|'
        || record[53] != b'|'
        || record[70] != b'|'
        || record[87] != b'|'
    {
        return Err(Wyr1bEvidenceError::Malformed);
    }
    for range in [8..24, 25..33, 34..36, 37..53, 54..70, 71..87, 88..96] {
        if !record[range].iter().copied().all(is_upper_hex) {
            return Err(Wyr1bEvidenceError::Malformed);
        }
    }
    let record_nonce = parse_hex_u64(&record[8..24]).ok_or(Wyr1bEvidenceError::Malformed)?;
    let sequence = parse_hex_u64(&record[25..33]).ok_or(Wyr1bEvidenceError::Malformed)?;
    let event = parse_hex_u8(&record[34..36]).ok_or(Wyr1bEvidenceError::Malformed)?;
    let subject = parse_hex_u64(&record[37..53]).ok_or(Wyr1bEvidenceError::Malformed)?;
    let generation = parse_hex_u64(&record[54..70]).ok_or(Wyr1bEvidenceError::Malformed)?;
    let value = parse_hex_u64(&record[71..87]).ok_or(Wyr1bEvidenceError::Malformed)?;
    let checksum =
        parse_hex_u32(&record[CHECKSUM_OFFSET..]).ok_or(Wyr1bEvidenceError::Malformed)?;
    if sequence != expected_sequence as u64 || event != EXPECTED_EVENTS[expected_sequence] {
        return Err(Wyr1bEvidenceError::OutOfOrder);
    }
    if record_nonce != nonce || checksum != fnv1a32(&record[..CHECKSUM_OFFSET]) {
        return Err(Wyr1bEvidenceError::Malformed);
    }
    let terminal = event == TERMINAL_EVENT;
    if terminal != (subject == 0 && generation == 0 && value == 0)
        || (!terminal && (subject == 0 || generation == 0))
    {
        return Err(Wyr1bEvidenceError::Malformed);
    }
    Ok(terminal)
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
    bytes.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

const fn parse_build_nonce(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() == 16,
        "selector-27 nonce must contain 16 digits"
    );
    let mut parsed = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("selector-27 nonce must be uppercase hexadecimal"),
        };
        parsed = (parsed << 4) | digit as u64;
        index += 1;
    }
    assert!(parsed != 0, "selector-27 nonce must be nonzero");
    parsed
}

#[cfg(deepwyrm_wyr1b_evidence)]
pub(crate) static WYR1B_EVIDENCE: Wyr1bEvidenceCollector =
    Wyr1bEvidenceCollector::new(parse_build_nonce(env!("DEEPWYRM_WYR1B_EVIDENCE_NONCE")));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::DW_OBJECT_TYPE_PROCESS;

    const NONCE: u64 = 0x0123_4567_89ab_cdef;
    const RETIRED: Wyr1bRetirementFacts = Wyr1bRetirementFacts {
        process_quiesced: true,
        root_region_retired: true,
        monitor_and_kernel_peer_released: true,
        finalizers_drained: true,
        private_primordial_pml4_retained: true,
    };

    fn process_key() -> ProcessKey {
        let mut registry = ObjectRegistry::<1>::new();
        let process = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        ProcessKey::from_object_id(process.id())
    }

    fn put_hex(output: &mut [u8], value: u64) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let width = output.len();
        for (index, byte) in output.iter_mut().enumerate() {
            let shift = (width - index - 1) * 4;
            *byte = HEX[((value >> shift) & 0xf) as usize];
        }
    }

    fn record(sequence: usize, event: u8) -> [u8; WYR1B_EVIDENCE_RECORD_LEN] {
        let terminal = event == TERMINAL_EVENT;
        let mut record = [b'|'; WYR1B_EVIDENCE_RECORD_LEN];
        record[..4].copy_from_slice(b"WRB1");
        put_hex(&mut record[5..7], 1);
        put_hex(&mut record[8..24], NONCE);
        put_hex(&mut record[25..33], sequence as u64);
        put_hex(&mut record[34..36], u64::from(event));
        put_hex(&mut record[37..53], if terminal { 0 } else { 1 });
        put_hex(&mut record[54..70], if terminal { 0 } else { 1 });
        put_hex(&mut record[71..87], 0);
        let checksum = fnv1a32(&record[..CHECKSUM_OFFSET]);
        put_hex(&mut record[CHECKSUM_OFFSET..], u64::from(checksum));
        record
    }

    #[test]
    fn exact_fourteen_record_transcript_is_preserved() {
        let collector = Wyr1bEvidenceCollector::new(NONCE);
        let reporter = process_key();
        collector
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        for (sequence, event) in EXPECTED_EVENTS.into_iter().enumerate() {
            let submission = collector
                .submit(reporter, &record(sequence, event))
                .unwrap();
            if sequence + 1 == WYR1B_EVIDENCE_RECORD_CAPACITY {
                let Wyr1bEvidenceSubmit::Terminal(permit) = submission else {
                    panic!("terminal record must claim the transcript")
                };
                let mut count = 0;
                permit
                    .flush(|_| {
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(count, WYR1B_EVIDENCE_RECORD_CAPACITY);
            } else {
                assert!(matches!(submission, Wyr1bEvidenceSubmit::Accepted));
            }
        }
    }

    #[test]
    fn malformed_order_reporter_and_duplicate_fail_closed() {
        let reporter = process_key();
        let other = process_key();

        let wrong = Wyr1bEvidenceCollector::new(NONCE);
        wrong
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        assert!(matches!(
            wrong.submit(other, &record(0, 1)),
            Err(Wyr1bEvidenceError::WrongReporter)
        ));

        let order = Wyr1bEvidenceCollector::new(NONCE);
        order
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        assert!(matches!(
            order.submit(reporter, &record(0, 2)),
            Err(Wyr1bEvidenceError::OutOfOrder)
        ));

        let malformed = Wyr1bEvidenceCollector::new(NONCE);
        malformed
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        let mut bad = record(0, 1);
        bad[95] ^= 1;
        assert!(matches!(
            malformed.submit(reporter, &bad),
            Err(Wyr1bEvidenceError::Malformed)
        ));

        let terminal = Wyr1bEvidenceCollector::new(NONCE);
        terminal
            .bind_reporter_after_retirement(reporter, RETIRED)
            .unwrap();
        for (sequence, event) in EXPECTED_EVENTS.into_iter().enumerate() {
            let _ = terminal.submit(reporter, &record(sequence, event)).unwrap();
        }
        assert_eq!(
            terminal.authorize_submission(reporter),
            Err(Wyr1bEvidenceError::DuplicateTerminal)
        );
        assert!(terminal.claim_failure().is_none());
    }

    #[test]
    fn every_retirement_fact_and_early_submission_are_rejected() {
        let reporter = process_key();
        let early = Wyr1bEvidenceCollector::new(NONCE);
        assert_eq!(
            early.authorize_submission(reporter),
            Err(Wyr1bEvidenceError::Early)
        );
        for facts in [
            Wyr1bRetirementFacts {
                process_quiesced: false,
                ..RETIRED
            },
            Wyr1bRetirementFacts {
                root_region_retired: false,
                ..RETIRED
            },
            Wyr1bRetirementFacts {
                monitor_and_kernel_peer_released: false,
                ..RETIRED
            },
            Wyr1bRetirementFacts {
                finalizers_drained: false,
                ..RETIRED
            },
            Wyr1bRetirementFacts {
                private_primordial_pml4_retained: false,
                ..RETIRED
            },
        ] {
            let collector = Wyr1bEvidenceCollector::new(NONCE);
            assert_eq!(
                collector.bind_reporter_after_retirement(reporter, facts),
                Err(Wyr1bEvidenceError::Retirement)
            );
        }
    }
}
