//! Selector-32-only relay for Wyrmroot's native console-stream evidence.
//!
//! The collector owns the frozen WRD1 framing, nonce, order, generation
//! relations, and permanent-reporter custody. Raw COM2 bytes and all
//! userspace lifecycle facts remain Wyrmroot-owned; this private operation is
//! absent from the public ABI.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only relay")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::memory::address_region::AddressRegionObjectKey;
use crate::sync::SpinMutex;
use crate::task::{ProcessKey, ThreadKey};

use super::wyr1b_evidence::{Wyr1bReporterStartFacts, Wyr1bRetirementFacts};

pub(crate) const WYR1D_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff20;
pub(crate) const WYR1D_EVIDENCE_RECORD_LEN: usize = 192;
pub(crate) const WYR1D_EVIDENCE_RECORD_CAPACITY: usize = 12;
pub(crate) const WYR1D_READY_RECORD_LEN: usize = 178;
const EMPTY_RECORD: [u8; WYR1D_EVIDENCE_RECORD_LEN] = [0; WYR1D_EVIDENCE_RECORD_LEN];
const MAX_RAW_COMMITTED_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wyr1dEvidenceError {
    Early,
    Retirement,
    WrongReporter,
    Malformed,
    WrongNonce,
    OutOfOrder,
    Relation,
    ReadinessOrder,
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
pub(crate) enum Wyr1dEvidenceFlushError {
    Incomplete,
    Busy,
    Transport,
}

pub(crate) enum Wyr1dEvidenceSubmit<'a> {
    Accepted,
    Terminal(Wyr1dEvidenceFlushPermit<'a>),
}

struct Transcript {
    records: [[u8; WYR1D_EVIDENCE_RECORD_LEN]; WYR1D_EVIDENCE_RECORD_CAPACITY],
    count: usize,
    startup: Option<Wyr1bReporterStartFacts>,
    reporter: Option<ProcessKey>,
    retired: bool,
    terminal: bool,
    readiness: [Option<CurrentTuple>; 3],
    readiness_count: usize,
    failure: Option<Wyr1dEvidenceError>,
}

impl Transcript {
    const fn new() -> Self {
        Self {
            records: [EMPTY_RECORD; WYR1D_EVIDENCE_RECORD_CAPACITY],
            count: 0,
            startup: None,
            reporter: None,
            retired: false,
            terminal: false,
            readiness: [None; 3],
            readiness_count: 0,
            failure: None,
        }
    }

    fn latch(&mut self, error: Wyr1dEvidenceError) -> Wyr1dEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

/// Fixed-capacity selector-local WRD1 transcript and one-shot reporter bind.
pub(crate) struct Wyr1dEvidenceCollector {
    transcript: SpinMutex<Transcript>,
    terminal_claimed: AtomicU8,
    nonce: u64,
}

impl Wyr1dEvidenceCollector {
    pub(crate) const fn new(nonce: u64) -> Self {
        assert!(nonce != 0, "selector-32 evidence nonce must be nonzero");
        Self {
            transcript: SpinMutex::new(Transcript::new()),
            terminal_claimed: AtomicU8::new(0),
            nonce,
        }
    }

    pub(crate) fn observe_reporter_start(
        &self,
        facts: Wyr1bReporterStartFacts,
    ) -> Result<(), Wyr1dEvidenceError> {
        let mut transcript = self.transcript.lock();
        if transcript.startup.is_some() {
            return Err(transcript.latch(Wyr1dEvidenceError::StartupDuplicate));
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
    ) -> Result<(), Wyr1dEvidenceError> {
        let mut transcript = self.transcript.lock();
        if !facts.complete() || transcript.retired || transcript.reporter.is_some() {
            return Err(transcript.latch(Wyr1dEvidenceError::Retirement));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        let Some(startup) = transcript.startup else {
            return Err(transcript.latch(Wyr1dEvidenceError::StartupMissing));
        };
        if startup.reporter_process != reporter
            || startup.reporter_thread != reporter_thread
            || startup.reporter_root != reporter_root
        {
            return Err(transcript.latch(Wyr1dEvidenceError::StartupRoot));
        }
        transcript.reporter = Some(reporter);
        transcript.retired = true;
        Ok(())
    }

    /// Authority is checked before the raw syscall performs any usercopy.
    pub(crate) fn authorize_submission(
        &self,
        process: ProcessKey,
    ) -> Result<(), Wyr1dEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)
    }

    pub(crate) fn submit(
        &self,
        process: ProcessKey,
        record: &[u8; WYR1D_EVIDENCE_RECORD_LEN],
    ) -> Result<Wyr1dEvidenceSubmit<'_>, Wyr1dEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)?;
        if let Err(error) = validate_record(
            record,
            &transcript.records,
            &transcript.readiness,
            transcript.count,
            self.nonce,
        ) {
            return Err(transcript.latch(error));
        }
        let terminal = transcript.count + 1 == WYR1D_EVIDENCE_RECORD_CAPACITY;
        if terminal {
            self.terminal_claimed
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| transcript.latch(Wyr1dEvidenceError::ReporterClaimed))?;
        }
        let index = transcript.count;
        transcript.records[index] = *record;
        transcript.count += 1;
        if terminal {
            transcript.terminal = true;
            drop(transcript);
            Ok(Wyr1dEvidenceSubmit::Terminal(Wyr1dEvidenceFlushPermit {
                collector: self,
            }))
        } else {
            Ok(Wyr1dEvidenceSubmit::Accepted)
        }
    }

    pub(crate) fn submit_readiness(
        &self,
        process: ProcessKey,
        record: &[u8; WYR1D_READY_RECORD_LEN],
    ) -> Result<(), Wyr1dEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)?;
        let expected_record_count = [2, 9, 11]
            .get(transcript.readiness_count)
            .copied()
            .ok_or_else(|| transcript.latch(Wyr1dEvidenceError::ReadinessOrder))?;
        if transcript.count != expected_record_count {
            return Err(transcript.latch(Wyr1dEvidenceError::ReadinessOrder));
        }
        let readiness =
            decode_readiness(record, self.nonce).map_err(|error| transcript.latch(error))?;
        let joined = match transcript.readiness_count {
            0 => decode_record(&transcript.records[1])
                .is_ok_and(|attached| require_prefix(readiness, attached.current, 7).is_ok()),
            1 => decode_record(&transcript.records[8])
                .is_ok_and(|replacement| readiness == replacement.current),
            2 => decode_record(&transcript.records[10])
                .is_ok_and(|replacement| readiness == replacement.current),
            _ => false,
        };
        if !joined {
            return Err(transcript.latch(Wyr1dEvidenceError::Relation));
        }
        let index = transcript.readiness_count;
        transcript.readiness[index] = Some(readiness);
        transcript.readiness_count += 1;
        Ok(())
    }
}

fn authorize_locked(
    transcript: &mut Transcript,
    process: ProcessKey,
) -> Result<(), Wyr1dEvidenceError> {
    if !transcript.retired {
        return Err(transcript.latch(Wyr1dEvidenceError::Early));
    }
    if transcript.reporter != Some(process) {
        return Err(transcript.latch(Wyr1dEvidenceError::WrongReporter));
    }
    if let Some(error) = transcript.failure {
        return Err(error);
    }
    if transcript.terminal {
        return Err(transcript.latch(Wyr1dEvidenceError::DuplicateTerminal));
    }
    if transcript.count == WYR1D_EVIDENCE_RECORD_CAPACITY {
        return Err(transcript.latch(Wyr1dEvidenceError::Full));
    }
    Ok(())
}

#[must_use]
pub(crate) struct Wyr1dEvidenceFlushPermit<'a> {
    collector: &'a Wyr1dEvidenceCollector,
}

impl Wyr1dEvidenceFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; WYR1D_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1dEvidenceFlushError>,
    ) -> Result<(), Wyr1dEvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1dEvidenceFlushError::Busy)?;
        if transcript.failure.is_some()
            || !transcript.retired
            || !transcript.terminal
            || transcript.count != WYR1D_EVIDENCE_RECORD_CAPACITY
            || transcript.readiness_count != 3
        {
            return Err(Wyr1dEvidenceFlushError::Incomplete);
        }
        let records = transcript.records;
        drop(transcript);
        for record in &records {
            emit(record)?;
        }
        Ok(())
    }
}

fn map_startup_error(error: super::wyr1b_evidence::Wyr1bEvidenceError) -> Wyr1dEvidenceError {
    use super::wyr1b_evidence::Wyr1bEvidenceError;
    match error {
        Wyr1bEvidenceError::StartupMissing => Wyr1dEvidenceError::StartupMissing,
        Wyr1bEvidenceError::StartupDuplicate => Wyr1dEvidenceError::StartupDuplicate,
        Wyr1bEvidenceError::StartupRoot => Wyr1dEvidenceError::StartupRoot,
        Wyr1bEvidenceError::StartupEntry => Wyr1dEvidenceError::StartupEntry,
        Wyr1bEvidenceError::StartupStackPointer => Wyr1dEvidenceError::StartupStackPointer,
        Wyr1bEvidenceError::StartupStackMapping => Wyr1dEvidenceError::StartupStackMapping,
        Wyr1bEvidenceError::StartupStackProtection => Wyr1dEvidenceError::StartupStackProtection,
        Wyr1bEvidenceError::StartupGuard => Wyr1dEvidenceError::StartupGuard,
        _ => Wyr1dEvidenceError::Malformed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CurrentTuple {
    role: u64,
    bundle: u64,
    attempt: u64,
    endpoint_id: u64,
    endpoint_generation: u64,
    operation: u64,
    stream: u64,
    console: u64,
    child: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreviousTuple {
    bundle: u64,
    attempt: u64,
    endpoint_id: u64,
    endpoint_generation: u64,
    operation: u64,
    stream: u64,
    console: u64,
    child: u64,
}

impl PreviousTuple {
    const fn is_zero(self) -> bool {
        self.bundle == 0
            && self.attempt == 0
            && self.endpoint_id == 0
            && self.endpoint_generation == 0
            && self.operation == 0
            && self.stream == 0
            && self.console == 0
            && self.child == 0
    }

    const fn matches_current(self, current: CurrentTuple) -> bool {
        self.bundle == current.bundle
            && self.attempt == current.attempt
            && self.endpoint_id == current.endpoint_id
            && self.endpoint_generation == current.endpoint_generation
            && self.operation == current.operation
            && self.stream == current.stream
            && self.console == current.console
            && self.child == current.child
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedRecord {
    record_type: u32,
    sequence: u64,
    nonce: u64,
    current: CurrentTuple,
    previous: PreviousTuple,
    value: u64,
}

fn validate_record(
    record: &[u8; WYR1D_EVIDENCE_RECORD_LEN],
    records: &[[u8; WYR1D_EVIDENCE_RECORD_LEN]; WYR1D_EVIDENCE_RECORD_CAPACITY],
    readiness: &[Option<CurrentTuple>; 3],
    expected_index: usize,
    nonce: u64,
) -> Result<(), Wyr1dEvidenceError> {
    let decoded = decode_record(record)?;
    let expected = u64::try_from(expected_index + 1).map_err(|_| Wyr1dEvidenceError::OutOfOrder)?;
    if decoded.sequence != expected || u64::from(decoded.record_type) != expected {
        return Err(Wyr1dEvidenceError::OutOfOrder);
    }
    if decoded.nonce != nonce {
        return Err(Wyr1dEvidenceError::WrongNonce);
    }

    let previous_record = |index: usize| decode_record(&records[index]);
    match decoded.record_type {
        1 => require_initial_shape(decoded, 6, false),
        2 => {
            require_initial_shape(decoded, 7, false)?;
            require_prefix(decoded.current, previous_record(0)?.current, 6)
        }
        3 | 4 => {
            require_initial_shape(decoded, 7, true)?;
            if readiness[0].is_none() {
                return Err(Wyr1dEvidenceError::ReadinessOrder);
            }
            if decoded.value > MAX_RAW_COMMITTED_BYTES {
                return Err(Wyr1dEvidenceError::Relation);
            }
            require_prefix(decoded.current, previous_record(1)?.current, 7)
        }
        5 => {
            require_initial_shape(decoded, 8, false)?;
            require_prefix(decoded.current, previous_record(3)?.current, 7)?;
            require_prefix(
                decoded.current,
                readiness[0].ok_or(Wyr1dEvidenceError::ReadinessOrder)?,
                8,
            )
        }
        6 => {
            require_initial_shape(decoded, 9, false)?;
            require_prefix(decoded.current, previous_record(4)?.current, 8)?;
            if Some(decoded.current) != readiness[0] {
                return Err(Wyr1dEvidenceError::Relation);
            }
            Ok(())
        }
        7 | 8 => {
            require_initial_shape(decoded, 9, true)?;
            if decoded.current != previous_record(5)?.current
                || decoded.value != expected_observation_value(decoded.record_type, decoded)
            {
                return Err(Wyr1dEvidenceError::Relation);
            }
            Ok(())
        }
        9 => {
            require_replacement_shape(decoded)?;
            let old = previous_record(7)?.current;
            if !decoded.previous.matches_current(old)
                || decoded.current.role != old.role
                || decoded.current.bundle != old.bundle
                || decoded.current.attempt <= old.attempt
                || (
                    decoded.current.endpoint_id,
                    decoded.current.endpoint_generation,
                ) == (old.endpoint_id, old.endpoint_generation)
                || decoded.current.operation <= old.operation
                || decoded.current.stream <= old.stream
                || decoded.current.console <= old.console
                || decoded.current.child <= old.child
            {
                return Err(Wyr1dEvidenceError::Relation);
            }
            Ok(())
        }
        10 => {
            require_initial_shape(decoded, 9, true)?;
            if Some(decoded.current) != readiness[1]
                || decoded.current != previous_record(8)?.current
                || decoded.value != expected_observation_value(decoded.record_type, decoded)
            {
                return Err(Wyr1dEvidenceError::Relation);
            }
            Ok(())
        }
        11 => {
            require_replacement_shape(decoded)?;
            let old = previous_record(9)?.current;
            if !decoded.previous.matches_current(old)
                || decoded.current.role != old.role
                || decoded.current.bundle != old.bundle
                || decoded.current.attempt != old.attempt
                || decoded.current.endpoint_id != old.endpoint_id
                || decoded.current.endpoint_generation != old.endpoint_generation
                || decoded.current.stream != old.stream
                || decoded.current.console != old.console
                || decoded.current.operation != old.operation
                || decoded.current.child <= old.child
            {
                return Err(Wyr1dEvidenceError::Relation);
            }
            Ok(())
        }
        12 => {
            require_initial_shape(decoded, 9, true)?;
            if Some(decoded.current) != readiness[2]
                || decoded.current != previous_record(10)?.current
                || decoded.value != expected_observation_value(decoded.record_type, decoded)
            {
                return Err(Wyr1dEvidenceError::Relation);
            }
            Ok(())
        }
        _ => Err(Wyr1dEvidenceError::OutOfOrder),
    }
}

fn decode_readiness(
    record: &[u8; WYR1D_READY_RECORD_LEN],
    expected_nonce: u64,
) -> Result<CurrentTuple, Wyr1dEvidenceError> {
    if &record[..8] != b"D5READY|" || record[177] != b'\n' {
        return Err(Wyr1dEvidenceError::Malformed);
    }
    for separator in [24, 41, 58, 75, 92, 109, 126, 143, 160] {
        if record[separator] != b'|' {
            return Err(Wyr1dEvidenceError::Malformed);
        }
    }
    let ranges = [
        8..24,
        25..41,
        42..58,
        59..75,
        76..92,
        93..109,
        110..126,
        127..143,
        144..160,
        161..177,
    ];
    let mut fields = [0_u64; 10];
    for (index, range) in ranges.into_iter().enumerate() {
        fields[index] = parse_upper_hex_u64(&record[range])?;
        if fields[index] == 0 {
            return Err(Wyr1dEvidenceError::Relation);
        }
    }
    if fields[0] != expected_nonce {
        return Err(Wyr1dEvidenceError::WrongNonce);
    }
    Ok(CurrentTuple {
        role: fields[1],
        bundle: fields[2],
        attempt: fields[3],
        endpoint_id: fields[4],
        endpoint_generation: fields[5],
        operation: fields[6],
        stream: fields[7],
        console: fields[8],
        child: fields[9],
    })
}

fn parse_upper_hex_u64(bytes: &[u8]) -> Result<u64, Wyr1dEvidenceError> {
    let mut value = 0_u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(Wyr1dEvidenceError::Malformed),
        };
        value = value
            .checked_mul(16)
            .and_then(|current| current.checked_add(digit))
            .ok_or(Wyr1dEvidenceError::Malformed)?;
    }
    Ok(value)
}

fn require_initial_shape(
    record: DecodedRecord,
    nonzero_current_fields: usize,
    value_nonzero: bool,
) -> Result<(), Wyr1dEvidenceError> {
    let fields = current_fields(record.current);
    if fields[..nonzero_current_fields].contains(&0)
        || fields[nonzero_current_fields..]
            .iter()
            .any(|field| *field != 0)
        || !record.previous.is_zero()
        || (value_nonzero == (record.value == 0))
    {
        return Err(Wyr1dEvidenceError::Relation);
    }
    Ok(())
}

fn require_replacement_shape(record: DecodedRecord) -> Result<(), Wyr1dEvidenceError> {
    if current_fields(record.current).contains(&0)
        || previous_fields(record.previous).contains(&0)
        || record.value != 0
    {
        return Err(Wyr1dEvidenceError::Relation);
    }
    Ok(())
}

fn require_prefix(
    current: CurrentTuple,
    expected: CurrentTuple,
    fields: usize,
) -> Result<(), Wyr1dEvidenceError> {
    if current_fields(current)[..fields] != current_fields(expected)[..fields] {
        return Err(Wyr1dEvidenceError::Relation);
    }
    Ok(())
}

const fn current_fields(current: CurrentTuple) -> [u64; 9] {
    [
        current.role,
        current.bundle,
        current.attempt,
        current.endpoint_id,
        current.endpoint_generation,
        current.operation,
        current.stream,
        current.console,
        current.child,
    ]
}

const fn previous_fields(previous: PreviousTuple) -> [u64; 8] {
    [
        previous.bundle,
        previous.attempt,
        previous.endpoint_id,
        previous.endpoint_generation,
        previous.operation,
        previous.stream,
        previous.console,
        previous.child,
    ]
}

fn decode_record(
    record: &[u8; WYR1D_EVIDENCE_RECORD_LEN],
) -> Result<DecodedRecord, Wyr1dEvidenceError> {
    if &record[0..4] != b"WRD1"
        || read_u16(record, 4) != 1
        || read_u16(record, 6) != 0
        || read_u32(record, 12) != 0
        || read_u32(record, 16) != WYR1D_EVIDENCE_RECORD_LEN as u32
        || read_u32(record, 20) != 0
        || read_u64(record, 184) != 0
    {
        return Err(Wyr1dEvidenceError::Malformed);
    }
    Ok(DecodedRecord {
        record_type: read_u32(record, 8),
        sequence: read_u64(record, 24),
        nonce: read_u64(record, 32),
        current: CurrentTuple {
            role: read_u64(record, 40),
            bundle: read_u64(record, 48),
            attempt: read_u64(record, 56),
            endpoint_id: read_u64(record, 64),
            endpoint_generation: read_u64(record, 72),
            operation: read_u64(record, 80),
            stream: read_u64(record, 88),
            console: read_u64(record, 96),
            child: read_u64(record, 104),
        },
        previous: PreviousTuple {
            bundle: read_u64(record, 112),
            attempt: read_u64(record, 120),
            endpoint_id: read_u64(record, 128),
            endpoint_generation: read_u64(record, 136),
            operation: read_u64(record, 144),
            stream: read_u64(record, 152),
            console: read_u64(record, 160),
            child: read_u64(record, 168),
        },
        value: read_u64(record, 176),
    })
}

fn expected_observation_value(record_type: u32, record: DecodedRecord) -> u64 {
    let (leg, stderr) = match record_type {
        7 => (1, false),
        8 => (2, true),
        10 => (3, false),
        12 => (4, false),
        _ => unreachable!("only observation records have response hashes"),
    };
    let challenge = challenge(record.nonce, leg, record.current);
    let mut response = [0_u8; 23];
    let prefix: &[u8] = if stderr { b"err " } else { b"pong " };
    response[..prefix.len()].copy_from_slice(prefix);
    write_upper_hex_u64(&mut response[prefix.len()..prefix.len() + 16], challenge);
    response[prefix.len() + 16..prefix.len() + 18].copy_from_slice(b"\r\n");
    fnv1a64(&response[..prefix.len() + 18])
}

fn challenge(nonce: u64, leg: u64, current: CurrentTuple) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for value in [
        nonce,
        32,
        leg,
        current.bundle,
        current.attempt,
        current.stream,
        current.console,
        current.child,
    ] {
        hash = fnv1a64_continue(hash, &value.to_le_bytes());
    }
    hash
}

fn write_upper_hex_u64(output: &mut [u8], value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = HEX[((value >> ((15 - index) * 4)) & 0xf) as usize];
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_continue(0xcbf2_9ce4_8422_2325, bytes)
}

fn fnv1a64_continue(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn read_u16(record: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        record[offset..offset + 2]
            .try_into()
            .expect("fixed WRD1 u16"),
    )
}

fn read_u32(record: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        record[offset..offset + 4]
            .try_into()
            .expect("fixed WRD1 u32"),
    )
}

fn read_u64(record: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        record[offset..offset + 8]
            .try_into()
            .expect("fixed WRD1 u64"),
    )
}

const fn parse_build_nonce(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() == 16,
        "selector-32 nonce must contain 16 digits"
    );
    let mut parsed = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("selector-32 nonce must be uppercase hexadecimal"),
        };
        parsed = (parsed << 4) | digit as u64;
        index += 1;
    }
    assert!(parsed != 0, "selector-32 nonce must be nonzero");
    parsed
}

#[cfg(deepwyrm_wyr1d_evidence)]
pub(crate) static WYR1D_EVIDENCE: Wyr1dEvidenceCollector =
    Wyr1dEvidenceCollector::new(parse_build_nonce(env!("DEEPWYRM_WYR1D_EVIDENCE_NONCE")));

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
        collector: &Wyr1dEvidenceCollector,
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

    fn write_u16(record: &mut [u8], offset: usize, value: u16) {
        record[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(record: &mut [u8], offset: usize, value: u32) {
        record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(record: &mut [u8], offset: usize, value: u64) {
        record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn encode(
        sequence: u64,
        current: CurrentTuple,
        previous: PreviousTuple,
        value: u64,
    ) -> [u8; 192] {
        let mut record = [0_u8; 192];
        record[..4].copy_from_slice(b"WRD1");
        write_u16(&mut record, 4, 1);
        write_u32(&mut record, 8, sequence as u32);
        write_u32(&mut record, 16, 192);
        write_u64(&mut record, 24, sequence);
        write_u64(&mut record, 32, NONCE);
        for (offset, field) in current_fields(current).into_iter().enumerate() {
            write_u64(&mut record, 40 + offset * 8, field);
        }
        for (offset, field) in previous_fields(previous).into_iter().enumerate() {
            write_u64(&mut record, 112 + offset * 8, field);
        }
        write_u64(&mut record, 176, value);
        record
    }

    fn readiness(current: CurrentTuple) -> [u8; WYR1D_READY_RECORD_LEN] {
        let mut record = [b'|'; WYR1D_READY_RECORD_LEN];
        record[..8].copy_from_slice(b"D5READY|");
        let fields = [
            NONCE,
            current.role,
            current.bundle,
            current.attempt,
            current.endpoint_id,
            current.endpoint_generation,
            current.operation,
            current.stream,
            current.console,
            current.child,
        ];
        let starts = [8, 25, 42, 59, 76, 93, 110, 127, 144, 161];
        for (start, value) in starts.into_iter().zip(fields) {
            write_upper_hex_u64(&mut record[start..start + 16], value);
        }
        record[177] = b'\n';
        record
    }

    fn transcript() -> [[u8; 192]; 12] {
        let zero = PreviousTuple {
            bundle: 0,
            attempt: 0,
            endpoint_id: 0,
            endpoint_generation: 0,
            operation: 0,
            stream: 0,
            console: 0,
            child: 0,
        };
        let base = CurrentTuple {
            role: 1,
            bundle: 10,
            attempt: 20,
            endpoint_id: 30,
            endpoint_generation: 1,
            operation: 50,
            stream: 60,
            console: 70,
            child: 80,
        };
        let ready = CurrentTuple {
            stream: 0,
            console: 0,
            child: 0,
            ..base
        };
        let stream = CurrentTuple {
            console: 0,
            child: 0,
            ..base
        };
        let console = CurrentTuple { child: 0, ..base };
        let driver2 = CurrentTuple {
            attempt: 21,
            endpoint_id: 31,
            endpoint_generation: 1,
            operation: 51,
            stream: 61,
            console: 71,
            child: 81,
            ..base
        };
        let child3 = CurrentTuple {
            child: 82,
            ..driver2
        };
        let mut records = [EMPTY_RECORD; 12];
        records[0] = encode(1, ready, zero, 0);
        records[1] = encode(2, stream, zero, 0);
        records[2] = encode(3, stream, zero, 23);
        records[3] = encode(4, stream, zero, 23);
        records[4] = encode(5, console, zero, 0);
        records[5] = encode(6, base, zero, 0);
        let observation = |sequence, current| {
            let mut record = encode(sequence, current, zero, 1);
            let decoded = decode_record(&record).unwrap();
            write_u64(
                &mut record,
                176,
                expected_observation_value(sequence as u32, decoded),
            );
            record
        };
        records[6] = observation(7, base);
        records[7] = observation(8, base);
        records[8] = encode(
            9,
            driver2,
            PreviousTuple {
                bundle: base.bundle,
                attempt: base.attempt,
                endpoint_id: base.endpoint_id,
                endpoint_generation: base.endpoint_generation,
                operation: base.operation,
                stream: base.stream,
                console: base.console,
                child: base.child,
            },
            0,
        );
        records[9] = observation(10, driver2);
        records[10] = encode(
            11,
            child3,
            PreviousTuple {
                bundle: driver2.bundle,
                attempt: driver2.attempt,
                endpoint_id: driver2.endpoint_id,
                endpoint_generation: driver2.endpoint_generation,
                operation: driver2.operation,
                stream: driver2.stream,
                console: driver2.console,
                child: driver2.child,
            },
            0,
        );
        records[11] = observation(12, child3);
        records
    }

    #[test]
    fn exact_ordered_generation_chain_flushes_all_twelve_records() {
        let collector = Wyr1dEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        let records = transcript();
        for (index, record) in records.iter().enumerate() {
            if index == 2 {
                collector
                    .submit_readiness(
                        reporter,
                        &readiness(decode_record(&records[5]).unwrap().current),
                    )
                    .unwrap();
            } else if index == 9 {
                collector
                    .submit_readiness(
                        reporter,
                        &readiness(decode_record(&records[8]).unwrap().current),
                    )
                    .unwrap();
            } else if index == 11 {
                collector
                    .submit_readiness(
                        reporter,
                        &readiness(decode_record(&records[10]).unwrap().current),
                    )
                    .unwrap();
            }
            let submission = collector.submit(reporter, record).unwrap();
            if index == 11 {
                let Wyr1dEvidenceSubmit::Terminal(permit) = submission else {
                    panic!("twelfth record must claim the transcript")
                };
                let mut count = 0;
                permit
                    .flush(|_| {
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(count, 12);
            } else {
                assert!(matches!(submission, Wyr1dEvidenceSubmit::Accepted));
            }
        }
    }

    #[test]
    fn driver_replacement_preserves_lease_and_requires_fresh_monotonic_join() {
        let records = transcript();
        let old = decode_record(&records[7]).unwrap().current;
        let replacement = decode_record(&records[8]).unwrap().current;
        assert_eq!(replacement.bundle, old.bundle);
        assert_eq!(replacement.endpoint_generation, 1);
        assert_eq!(replacement.endpoint_generation, old.endpoint_generation);
        assert_ne!(replacement.endpoint_id, old.endpoint_id);
        assert!(validate_record(&records[8], &records, &[None; 3], 8, NONCE).is_ok());

        // A different scalar is insufficient if an ordered identity regresses.
        for (offset, value) in [
            (48, old.bundle + 1),
            (56, old.attempt),
            (56, old.attempt - 1),
            (64, old.endpoint_id),
            (80, old.operation),
            (80, old.operation - 1),
            (88, old.stream),
            (88, old.stream - 1),
            (96, old.console),
            (96, old.console - 1),
            (104, old.child),
            (104, old.child - 1),
        ] {
            let mut invalid = records[8];
            write_u64(&mut invalid, offset, value);
            assert_eq!(
                validate_record(&invalid, &records, &[None; 3], 8, NONCE),
                Err(Wyr1dEvidenceError::Relation),
                "replacement field at {offset} accepted {value}"
            );
        }
    }

    #[test]
    fn child_replacement_preserves_the_raw_attach_transaction() {
        let records = transcript();
        let old = decode_record(&records[9]).unwrap().current;
        let replacement = decode_record(&records[10]).unwrap().current;
        assert_eq!(replacement.operation, old.operation);
        assert!(replacement.child > old.child);
        assert!(validate_record(&records[10], &records, &[None; 3], 10, NONCE).is_ok());

        for (offset, value) in [
            (80, old.operation + 1),
            (80, old.operation - 1),
            (104, old.child),
            (104, old.child - 1),
        ] {
            let mut invalid = records[10];
            write_u64(&mut invalid, offset, value);
            assert_eq!(
                validate_record(&invalid, &records, &[None; 3], 10, NONCE),
                Err(Wyr1dEvidenceError::Relation),
                "child replacement field at {offset} accepted {value}"
            );
        }
    }

    #[test]
    fn authority_nonce_order_and_generation_relations_fail_closed() {
        let (reporter, thread, root) = subject();
        let early = Wyr1dEvidenceCollector::new(NONCE);
        assert_eq!(
            early.authorize_submission(reporter),
            Err(Wyr1dEvidenceError::Early)
        );

        let wrong = Wyr1dEvidenceCollector::new(NONCE);
        arm(&wrong, reporter, thread, root);
        assert!(matches!(
            wrong.submit(subject().0, &transcript()[0]),
            Err(Wyr1dEvidenceError::WrongReporter)
        ));

        let nonce = Wyr1dEvidenceCollector::new(NONCE + 1);
        arm(&nonce, reporter, thread, root);
        assert!(matches!(
            nonce.submit(reporter, &transcript()[0]),
            Err(Wyr1dEvidenceError::WrongNonce)
        ));

        let order = Wyr1dEvidenceCollector::new(NONCE);
        arm(&order, reporter, thread, root);
        assert!(matches!(
            order.submit(reporter, &transcript()[1]),
            Err(Wyr1dEvidenceError::OutOfOrder)
        ));

        let relation = Wyr1dEvidenceCollector::new(NONCE);
        arm(&relation, reporter, thread, root);
        let mut records = transcript();
        for (index, record) in records[..8].iter().enumerate() {
            if index == 2 {
                relation
                    .submit_readiness(
                        reporter,
                        &readiness(decode_record(&records[5]).unwrap().current),
                    )
                    .unwrap();
            }
            assert!(matches!(
                relation.submit(reporter, record),
                Ok(Wyr1dEvidenceSubmit::Accepted)
            ));
        }
        write_u64(&mut records[8], 152, 999);
        assert!(matches!(
            relation.submit(reporter, &records[8]),
            Err(Wyr1dEvidenceError::Relation)
        ));
    }

    #[test]
    fn observation_hash_and_reserved_fields_are_exact() {
        let (reporter, thread, root) = subject();
        let hash = Wyr1dEvidenceCollector::new(NONCE);
        arm(&hash, reporter, thread, root);
        let mut records = transcript();
        for (index, record) in records[..6].iter().enumerate() {
            if index == 2 {
                hash.submit_readiness(
                    reporter,
                    &readiness(decode_record(&records[5]).unwrap().current),
                )
                .unwrap();
            }
            hash.submit(reporter, record).unwrap();
        }
        records[6][176] ^= 1;
        assert!(matches!(
            hash.submit(reporter, &records[6]),
            Err(Wyr1dEvidenceError::Relation)
        ));

        let malformed = Wyr1dEvidenceCollector::new(NONCE);
        arm(&malformed, reporter, thread, root);
        let mut first = transcript()[0];
        first[184] = 1;
        assert!(matches!(
            malformed.submit(reporter, &first),
            Err(Wyr1dEvidenceError::Malformed)
        ));
    }

    #[test]
    fn readiness_grammar_phase_and_tuple_are_exact() {
        let (reporter, thread, root) = subject();
        let collector = Wyr1dEvidenceCollector::new(NONCE);
        arm(&collector, reporter, thread, root);
        let records = transcript();
        collector.submit(reporter, &records[0]).unwrap();
        let initial = readiness(decode_record(&records[5]).unwrap().current);
        assert!(matches!(
            collector.submit_readiness(reporter, &initial),
            Err(Wyr1dEvidenceError::ReadinessOrder)
        ));

        let collector = Wyr1dEvidenceCollector::new(NONCE);
        arm(&collector, reporter, thread, root);
        collector.submit(reporter, &records[0]).unwrap();
        collector.submit(reporter, &records[1]).unwrap();
        let mut malformed = initial;
        malformed[8] = b'a';
        assert!(matches!(
            collector.submit_readiness(reporter, &malformed),
            Err(Wyr1dEvidenceError::Malformed)
        ));
    }
}
