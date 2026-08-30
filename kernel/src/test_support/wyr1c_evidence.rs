//! Selector-29-only relay for Wyrmroot's device-coordinator restart evidence.
//!
//! The collector owns only bounded framing, nonce binding, ordered events, and
//! reporter custody.  DeviceResource/Interrupt rights, generations, and
//! restart joins remain Wyrmroot facts; no physical IRQ or PIO operation is
//! performed here and this operation is absent from the public ABI.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only relay")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::memory::address_region::AddressRegionObjectKey;
use crate::sync::SpinMutex;
use crate::task::{ProcessKey, ThreadKey};

use super::wyr1b_evidence::{Wyr1bReporterStartFacts, Wyr1bRetirementFacts};

pub(crate) const WYR1C_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1e;
pub(crate) const WYR1C_EVIDENCE_RECORD_LEN: usize = 113;
pub(crate) const WYR1C_EVIDENCE_RECORD_CAPACITY: usize = 27;
pub(crate) const WYR1C_EVIDENCE_EVENT_COUNT: usize = 26;
pub(crate) const WYR1C_EVIDENCE_TERMINAL_EVENT: u8 = 0xff;
const CHECKSUM_OFFSET: usize = 105;
const EMPTY_RECORD: [u8; WYR1C_EVIDENCE_RECORD_LEN] = [0; WYR1C_EVIDENCE_RECORD_LEN];
const EXPECTED_EVENTS: [u8; WYR1C_EVIDENCE_RECORD_CAPACITY] = [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    WYR1C_EVIDENCE_TERMINAL_EVENT,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wyr1cEvidenceError {
    Early,
    Retirement,
    WrongReporter,
    Malformed,
    OutOfOrder,
    Full,
    DuplicateTerminal,
    ReporterClaimed,
    StartupMissing,
    StartupDuplicate,
    StartupRoot,
    StartupEntry,
    StartupStackPointer,
    StartupStackMapping,
    StartupStackProtection,
    StartupGuard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wyr1cEvidenceFlushError {
    Incomplete,
    Early,
    Retirement,
    WrongReporter,
    Malformed,
    OutOfOrder,
    Full,
    DuplicateTerminal,
    ReporterClaimed,
    StartupMissing,
    StartupDuplicate,
    StartupRoot,
    StartupEntry,
    StartupStackPointer,
    StartupStackMapping,
    StartupStackProtection,
    StartupGuard,
    Busy,
    Transport,
}

pub(crate) enum Wyr1cEvidenceSubmit<'a> {
    Accepted,
    Terminal(Wyr1cEvidenceFlushPermit<'a>),
}

/// One opaque Wyrmroot identity tuple carried by each ordered event.
/// Deepwyrm preserves these fields but deliberately does not interpret them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Wyr1cEvidenceFields {
    pub(crate) lease: u64,
    pub(crate) binding: u64,
    pub(crate) value: u64,
    pub(crate) auxiliary: u64,
}

struct Transcript {
    records: [[u8; WYR1C_EVIDENCE_RECORD_LEN]; WYR1C_EVIDENCE_RECORD_CAPACITY],
    count: usize,
    startup: Option<Wyr1bReporterStartFacts>,
    reporter: Option<ProcessKey>,
    retired: bool,
    terminal: bool,
    failure: Option<Wyr1cEvidenceError>,
}

impl Transcript {
    const fn new() -> Self {
        Self {
            records: [EMPTY_RECORD; WYR1C_EVIDENCE_RECORD_CAPACITY],
            count: 0,
            startup: None,
            reporter: None,
            retired: false,
            terminal: false,
            failure: None,
        }
    }

    fn latch(&mut self, error: Wyr1cEvidenceError) -> Wyr1cEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

/// Fixed-capacity selector-local WRC6 transcript and one-shot reporter bind.
pub(crate) struct Wyr1cEvidenceCollector {
    transcript: SpinMutex<Transcript>,
    terminal_claimed: AtomicU8,
    nonce: u64,
}

impl Wyr1cEvidenceCollector {
    pub(crate) const fn new(nonce: u64) -> Self {
        assert!(nonce != 0, "selector-29 evidence nonce must be nonzero");
        Self {
            transcript: SpinMutex::new(Transcript::new()),
            terminal_claimed: AtomicU8::new(0),
            nonce,
        }
    }

    pub(crate) fn observe_reporter_start(
        &self,
        facts: Wyr1bReporterStartFacts,
    ) -> Result<(), Wyr1cEvidenceError> {
        let mut transcript = self.transcript.lock();
        if transcript.startup.is_some() {
            return Err(transcript.latch(Wyr1cEvidenceError::StartupDuplicate));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        facts
            .validate()
            .map_err(|error| transcript.latch(map_startup_error(error)))?;
        transcript.startup = Some(facts);
        Ok(())
    }

    pub(crate) fn bind_reporter_after_retirement(
        &self,
        reporter: ProcessKey,
        reporter_thread: ThreadKey,
        reporter_root: AddressRegionObjectKey,
        facts: Wyr1bRetirementFacts,
    ) -> Result<(), Wyr1cEvidenceError> {
        let mut transcript = self.transcript.lock();
        if !facts.complete() || transcript.retired || transcript.reporter.is_some() {
            return Err(transcript.latch(Wyr1cEvidenceError::Retirement));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        let Some(startup) = transcript.startup else {
            return Err(transcript.latch(Wyr1cEvidenceError::StartupMissing));
        };
        if startup.reporter_process != reporter
            || startup.reporter_thread != reporter_thread
            || startup.reporter_root != reporter_root
        {
            return Err(transcript.latch(Wyr1cEvidenceError::StartupRoot));
        }
        transcript.reporter = Some(reporter);
        transcript.retired = true;
        Ok(())
    }

    /// Authority is checked before the raw syscall performs any usercopy.
    pub(crate) fn authorize_submission(
        &self,
        process: ProcessKey,
    ) -> Result<(), Wyr1cEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)
    }

    pub(crate) fn submit(
        &self,
        process: ProcessKey,
        record: &[u8; WYR1C_EVIDENCE_RECORD_LEN],
    ) -> Result<Wyr1cEvidenceSubmit<'_>, Wyr1cEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)?;
        let terminal = match validate_record(record, transcript.count, self.nonce) {
            Ok(terminal) => terminal,
            Err(error) => return Err(transcript.latch(error)),
        };
        if terminal {
            self.terminal_claimed
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| transcript.latch(Wyr1cEvidenceError::ReporterClaimed))?;
        }
        let index = transcript.count;
        transcript.records[index] = *record;
        transcript.count += 1;
        if terminal {
            transcript.terminal = true;
            drop(transcript);
            Ok(Wyr1cEvidenceSubmit::Terminal(Wyr1cEvidenceFlushPermit {
                collector: self,
            }))
        } else {
            Ok(Wyr1cEvidenceSubmit::Accepted)
        }
    }

    pub(crate) fn claim_failure(&self) -> Option<Wyr1cEvidenceFailurePermit<'_>> {
        self.terminal_claimed
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Wyr1cEvidenceFailurePermit { collector: self })
    }
}

fn authorize_locked(
    transcript: &mut Transcript,
    process: ProcessKey,
) -> Result<(), Wyr1cEvidenceError> {
    if !transcript.retired {
        return Err(transcript.latch(Wyr1cEvidenceError::Early));
    }
    if transcript.reporter != Some(process) {
        return Err(transcript.latch(Wyr1cEvidenceError::WrongReporter));
    }
    if let Some(error) = transcript.failure {
        return Err(error);
    }
    if transcript.terminal {
        return Err(transcript.latch(Wyr1cEvidenceError::DuplicateTerminal));
    }
    if transcript.count == WYR1C_EVIDENCE_RECORD_CAPACITY {
        return Err(transcript.latch(Wyr1cEvidenceError::Full));
    }
    Ok(())
}

#[must_use]
pub(crate) struct Wyr1cEvidenceFlushPermit<'a> {
    collector: &'a Wyr1cEvidenceCollector,
}

#[must_use]
pub(crate) struct Wyr1cEvidenceFailurePermit<'a> {
    collector: &'a Wyr1cEvidenceCollector,
}

impl Wyr1cEvidenceFailurePermit<'_> {
    pub(crate) fn flush_prefix(
        self,
        mut emit: impl FnMut(&[u8; WYR1C_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1cEvidenceFlushError>,
    ) -> Result<(), Wyr1cEvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1cEvidenceFlushError::Busy)?;
        for record in &transcript.records[..transcript.count] {
            emit(record)?;
        }
        Ok(())
    }
}

impl Wyr1cEvidenceFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; WYR1C_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1cEvidenceFlushError>,
    ) -> Result<(), Wyr1cEvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1cEvidenceFlushError::Busy)?;
        if transcript.failure.is_some()
            || !transcript.retired
            || !transcript.terminal
            || transcript.count != WYR1C_EVIDENCE_RECORD_CAPACITY
        {
            return Err(Wyr1cEvidenceFlushError::Incomplete);
        }
        let records = transcript.records;
        drop(transcript);
        for record in &records {
            emit(record)?;
        }
        Ok(())
    }
}

fn map_startup_error(error: super::wyr1b_evidence::Wyr1bEvidenceError) -> Wyr1cEvidenceError {
    use super::wyr1b_evidence::Wyr1bEvidenceError;
    match error {
        Wyr1bEvidenceError::StartupMissing => Wyr1cEvidenceError::StartupMissing,
        Wyr1bEvidenceError::StartupDuplicate => Wyr1cEvidenceError::StartupDuplicate,
        Wyr1bEvidenceError::StartupRoot => Wyr1cEvidenceError::StartupRoot,
        Wyr1bEvidenceError::StartupEntry => Wyr1cEvidenceError::StartupEntry,
        Wyr1bEvidenceError::StartupStackPointer => Wyr1cEvidenceError::StartupStackPointer,
        Wyr1bEvidenceError::StartupStackMapping => Wyr1cEvidenceError::StartupStackMapping,
        Wyr1bEvidenceError::StartupStackProtection => Wyr1cEvidenceError::StartupStackProtection,
        Wyr1bEvidenceError::StartupGuard => Wyr1cEvidenceError::StartupGuard,
        _ => Wyr1cEvidenceError::Malformed,
    }
}

fn validate_record(
    record: &[u8; WYR1C_EVIDENCE_RECORD_LEN],
    expected_sequence: usize,
    nonce: u64,
) -> Result<bool, Wyr1cEvidenceError> {
    if &record[..4] != b"WRC6"
        || record[4] != b'|'
        || &record[5..7] != b"01"
        || record[7] != b'|'
        || record[24] != b'|'
        || record[33] != b'|'
        || record[36] != b'|'
        || record[53] != b'|'
        || record[70] != b'|'
        || record[87] != b'|'
        || record[104] != b'|'
    {
        return Err(Wyr1cEvidenceError::Malformed);
    }
    for range in [
        8..24,
        25..33,
        34..36,
        37..53,
        54..70,
        71..87,
        88..104,
        105..113,
    ] {
        if !record[range].iter().copied().all(is_upper_hex) {
            return Err(Wyr1cEvidenceError::Malformed);
        }
    }
    let record_nonce = parse_hex_u64(&record[8..24]).ok_or(Wyr1cEvidenceError::Malformed)?;
    let sequence = parse_hex_u64(&record[25..33]).ok_or(Wyr1cEvidenceError::Malformed)?;
    let event = parse_hex_u8(&record[34..36]).ok_or(Wyr1cEvidenceError::Malformed)?;
    let lease = parse_hex_u64(&record[37..53]).ok_or(Wyr1cEvidenceError::Malformed)?;
    let binding = parse_hex_u64(&record[54..70]).ok_or(Wyr1cEvidenceError::Malformed)?;
    let value = parse_hex_u64(&record[71..87]).ok_or(Wyr1cEvidenceError::Malformed)?;
    let auxiliary = parse_hex_u64(&record[88..104]).ok_or(Wyr1cEvidenceError::Malformed)?;
    let checksum =
        parse_hex_u32(&record[CHECKSUM_OFFSET..]).ok_or(Wyr1cEvidenceError::Malformed)?;
    if sequence != expected_sequence as u64 || event != EXPECTED_EVENTS[expected_sequence] {
        return Err(Wyr1cEvidenceError::OutOfOrder);
    }
    if record_nonce != nonce || checksum != fnv1a32(&record[..CHECKSUM_OFFSET]) {
        return Err(Wyr1cEvidenceError::Malformed);
    }
    let terminal = event == WYR1C_EVIDENCE_TERMINAL_EVENT;
    if terminal != (lease == 0 && binding == 0 && value == 0 && auxiliary == 0)
        || (!terminal && lease == 0)
    {
        return Err(Wyr1cEvidenceError::Malformed);
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
        "selector-29 nonce must contain 16 digits"
    );
    let mut parsed = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("selector-29 nonce must be uppercase hexadecimal"),
        };
        parsed = (parsed << 4) | digit as u64;
        index += 1;
    }
    assert!(parsed != 0, "selector-29 nonce must be nonzero");
    parsed
}

#[cfg(deepwyrm_wyr1c_evidence)]
pub(crate) static WYR1C_EVIDENCE: Wyr1cEvidenceCollector =
    Wyr1cEvidenceCollector::new(parse_build_nonce(env!("DEEPWYRM_WYR1C_EVIDENCE_NONCE")));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD,
    };

    const NONCE: u64 = 0x0123_4567_89ab_cdef;
    const RETIRED: Wyr1bRetirementFacts = Wyr1bRetirementFacts {
        process_quiesced: true,
        root_region_retired: true,
        monitor_and_kernel_peer_released: true,
        finalizers_drained: true,
        private_primordial_pml4_retained: true,
    };

    fn subject() -> (ProcessKey, ThreadKey, AddressRegionObjectKey) {
        let mut registry = ObjectRegistry::<3>::new();
        let process = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let thread = registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
        let root = registry.create(DW_OBJECT_TYPE_ADDRESS_REGION).unwrap();
        (
            ProcessKey::from_object_id(process.id()),
            ThreadKey::from_object_id(thread.id()),
            AddressRegionObjectKey::from_object_id(root.id()),
        )
    }

    fn arm(
        collector: &Wyr1cEvidenceCollector,
        reporter: ProcessKey,
        thread: ThreadKey,
        root: AddressRegionObjectKey,
    ) {
        let facts = Wyr1bReporterStartFacts {
            reporter_process: reporter,
            reporter_thread: thread,
            reporter_root: root,
            root_owned_by_reporter: true,
            entry_point: 0x20_0000,
            entry_mapping_bound: true,
            stack_pointer: super::super::wyr1b_evidence::WYR1B_SYSTEM_INIT_STACK_POINTER,
            stack_mapping_start: super::super::wyr1b_evidence::WYR1B_SYSTEM_INIT_STACK_BOTTOM,
            stack_mapping_bytes: super::super::wyr1b_evidence::WYR1B_SYSTEM_INIT_STACK_BYTES,
            stack_mapping_rw_nx: true,
            guard_absent: true,
        };
        collector.observe_reporter_start(facts).unwrap();
        collector
            .bind_reporter_after_retirement(reporter, thread, root, RETIRED)
            .unwrap();
    }

    fn put_hex(output: &mut [u8], value: u64) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let width = output.len();
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = HEX[((value >> ((width - index - 1) * 4)) & 0xf) as usize];
        }
    }

    fn record(sequence: usize, event: u8) -> [u8; WYR1C_EVIDENCE_RECORD_LEN] {
        let terminal = event == WYR1C_EVIDENCE_TERMINAL_EVENT;
        let mut record = [b'|'; WYR1C_EVIDENCE_RECORD_LEN];
        record[..4].copy_from_slice(b"WRC6");
        record[5..7].copy_from_slice(b"01");
        put_hex(&mut record[8..24], NONCE);
        put_hex(&mut record[25..33], sequence as u64);
        put_hex(&mut record[34..36], u64::from(event));
        put_hex(&mut record[37..53], if terminal { 0 } else { 1 });
        put_hex(
            &mut record[54..70],
            if terminal { 0 } else { sequence as u64 + 1 },
        );
        put_hex(&mut record[71..87], if terminal { 0 } else { 2 });
        put_hex(&mut record[88..104], if terminal { 0 } else { 3 });
        let checksum = fnv1a32(&record[..CHECKSUM_OFFSET]);
        put_hex(&mut record[CHECKSUM_OFFSET..], u64::from(checksum));
        record
    }

    #[test]
    fn exact_ordered_transcript_flushes_atomically() {
        let collector = Wyr1cEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        for (sequence, event) in EXPECTED_EVENTS.into_iter().enumerate() {
            let submission = collector
                .submit(reporter, &record(sequence, event))
                .unwrap();
            if sequence + 1 == WYR1C_EVIDENCE_RECORD_CAPACITY {
                let Wyr1cEvidenceSubmit::Terminal(permit) = submission else {
                    panic!("terminal record must claim the transcript")
                };
                let mut count = 0;
                permit
                    .flush(|_| {
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(count, WYR1C_EVIDENCE_RECORD_CAPACITY);
            } else {
                assert!(matches!(submission, Wyr1cEvidenceSubmit::Accepted));
            }
        }
    }

    #[test]
    fn authority_order_checksum_and_generation_fields_fail_closed() {
        let (reporter, thread, root) = subject();
        let early = Wyr1cEvidenceCollector::new(NONCE);
        assert_eq!(
            early.authorize_submission(reporter),
            Err(Wyr1cEvidenceError::Early)
        );
        let wrong = Wyr1cEvidenceCollector::new(NONCE);
        arm(&wrong, reporter, thread, root);
        let other = subject().0;
        assert!(matches!(
            wrong.submit(other, &record(0, 1)),
            Err(Wyr1cEvidenceError::WrongReporter)
        ));
        let order = Wyr1cEvidenceCollector::new(NONCE);
        arm(&order, reporter, thread, root);
        assert!(matches!(
            order.submit(reporter, &record(0, 2)),
            Err(Wyr1cEvidenceError::OutOfOrder)
        ));
        let malformed = Wyr1cEvidenceCollector::new(NONCE);
        arm(&malformed, reporter, thread, root);
        let mut bad = record(0, 1);
        bad[112] ^= 1;
        assert!(matches!(
            malformed.submit(reporter, &bad),
            Err(Wyr1cEvidenceError::Malformed)
        ));
    }
}
