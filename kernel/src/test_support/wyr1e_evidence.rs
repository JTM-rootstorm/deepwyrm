//! Selector-33-only relay for Wyrmroot's interactive-shell evidence.
//!
//! The collector validates only bounded WRE1 transport, the build nonce,
//! stable current-shell identity, lifecycle framing, and permanent-reporter
//! custody. ShellJobs meanings and application policy remain Wyrmroot and
//! host-decoder responsibilities. This private operation is absent from the
//! public ABI.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only relay")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::memory::address_region::AddressRegionObjectKey;
use crate::sync::SpinMutex;
use crate::task::{ProcessKey, ThreadKey};

use super::wyr1b_evidence::{Wyr1bReporterStartFacts, Wyr1bRetirementFacts};

pub(crate) const WYR1E_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff21;
pub(crate) const WYR1E_EVIDENCE_RECORD_LEN: usize = 192;
pub(crate) const WYR1E_EVIDENCE_RECORD_CAPACITY: usize = 128;
const EMPTY_RECORD: [u8; WYR1E_EVIDENCE_RECORD_LEN] = [0; WYR1E_EVIDENCE_RECORD_LEN];
const RECORD_SHELL_READY: u32 = 1;
const RECORD_SHELLJOBS_TRANSACTION: u32 = 2;
const RECORD_SHELL_EXITED: u32 = 3;
const RECORD_TERMINAL: u32 = 255;
const E8_UP_RECORDS: usize = 33;
const E8_SMP_RECORDS: usize = 69;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceVersion {
    V1_0,
    V1_1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Wyr1eEvidenceError {
    Early,
    Retirement,
    WrongReporter,
    Malformed,
    WrongNonce,
    OutOfOrder,
    Relation,
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
pub(crate) enum Wyr1eEvidenceFlushError {
    Incomplete,
    Busy,
    Transport,
}

pub(crate) enum Wyr1eEvidenceSubmit<'a> {
    Accepted,
    Terminal(Wyr1eEvidenceFlushPermit<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShellTuple([u64; 10]);

impl ShellTuple {
    fn all_nonzero(self) -> bool {
        !self.0.contains(&0)
    }
}

struct Transcript {
    records: [[u8; WYR1E_EVIDENCE_RECORD_LEN]; WYR1E_EVIDENCE_RECORD_CAPACITY],
    count: usize,
    startup: Option<Wyr1bReporterStartFacts>,
    reporter: Option<ProcessKey>,
    shell: Option<ShellTuple>,
    retired: bool,
    shell_exited: bool,
    previous_shell: Option<ShellTuple>,
    stage: u32,
    epoch_transactions: usize,
    last_transaction: u64,
    trigger_launch_transaction: u64,
    trigger_job: u64,
    ready_aux0: u64,
    ready_aux1: u64,
    ready_values: [u64; 3],
    stage4_profile: u8,
    terminal: bool,
    failure: Option<Wyr1eEvidenceError>,
}

impl Transcript {
    const fn new() -> Self {
        Self {
            records: [EMPTY_RECORD; WYR1E_EVIDENCE_RECORD_CAPACITY],
            count: 0,
            startup: None,
            reporter: None,
            shell: None,
            retired: false,
            shell_exited: false,
            previous_shell: None,
            stage: 0,
            epoch_transactions: 0,
            last_transaction: 0,
            trigger_launch_transaction: 0,
            trigger_job: 0,
            ready_aux0: 0,
            ready_aux1: 0,
            ready_values: [0; 3],
            stage4_profile: 0,
            terminal: false,
            failure: None,
        }
    }

    fn latch(&mut self, error: Wyr1eEvidenceError) -> Wyr1eEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

/// Fixed-capacity selector-local WRE1 transcript and one-shot reporter bind.
pub(crate) struct Wyr1eEvidenceCollector {
    transcript: SpinMutex<Transcript>,
    terminal_claimed: AtomicU8,
    nonce: u64,
    version: EvidenceVersion,
}

impl Wyr1eEvidenceCollector {
    pub(crate) const fn new(nonce: u64) -> Self {
        assert!(nonce != 0, "selector-33 evidence nonce must be nonzero");
        Self {
            transcript: SpinMutex::new(Transcript::new()),
            terminal_claimed: AtomicU8::new(0),
            nonce,
            version: EvidenceVersion::V1_0,
        }
    }

    const fn new_v1_1(nonce: u64) -> Self {
        assert!(nonce != 0, "selector-33 E8 evidence nonce must be nonzero");
        Self {
            transcript: SpinMutex::new(Transcript::new()),
            terminal_claimed: AtomicU8::new(0),
            nonce,
            version: EvidenceVersion::V1_1,
        }
    }

    pub(crate) fn observe_reporter_start(
        &self,
        facts: Wyr1bReporterStartFacts,
    ) -> Result<(), Wyr1eEvidenceError> {
        let mut transcript = self.transcript.lock();
        if transcript.startup.is_some() {
            return Err(transcript.latch(Wyr1eEvidenceError::StartupDuplicate));
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
    ) -> Result<(), Wyr1eEvidenceError> {
        let mut transcript = self.transcript.lock();
        if !facts.complete() || transcript.retired || transcript.reporter.is_some() {
            return Err(transcript.latch(Wyr1eEvidenceError::Retirement));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        let Some(startup) = transcript.startup else {
            return Err(transcript.latch(Wyr1eEvidenceError::StartupMissing));
        };
        if startup.reporter_process != reporter
            || startup.reporter_thread != reporter_thread
            || startup.reporter_root != reporter_root
        {
            return Err(transcript.latch(Wyr1eEvidenceError::StartupRoot));
        }
        transcript.reporter = Some(reporter);
        transcript.retired = true;
        Ok(())
    }

    /// Authority is checked before the raw syscall performs any usercopy.
    pub(crate) fn authorize_submission(
        &self,
        process: ProcessKey,
    ) -> Result<(), Wyr1eEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)
    }

    /// Rechecks reporter authority after usercopy and commits one exact record.
    pub(crate) fn submit(
        &self,
        process: ProcessKey,
        record: &[u8; WYR1E_EVIDENCE_RECORD_LEN],
    ) -> Result<Wyr1eEvidenceSubmit<'_>, Wyr1eEvidenceError> {
        let mut transcript = self.transcript.lock();
        authorize_locked(&mut transcript, process)?;
        let decoded =
            decode_record(record, self.version).map_err(|error| transcript.latch(error))?;
        if let Err(error) = validate_record(&transcript, decoded, self.nonce, self.version) {
            return Err(transcript.latch(error));
        }
        if decoded.record_type != RECORD_TERMINAL
            && transcript.count + 1 == WYR1E_EVIDENCE_RECORD_CAPACITY
        {
            return Err(transcript.latch(Wyr1eEvidenceError::Full));
        }
        if decoded.record_type == RECORD_TERMINAL {
            self.terminal_claimed
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| transcript.latch(Wyr1eEvidenceError::ReporterClaimed))?;
        }
        commit_record(&mut transcript, decoded, self.version);
        let index = transcript.count;
        transcript.records[index] = *record;
        transcript.count += 1;
        if decoded.record_type == RECORD_TERMINAL {
            transcript.terminal = true;
            drop(transcript);
            Ok(Wyr1eEvidenceSubmit::Terminal(Wyr1eEvidenceFlushPermit {
                collector: self,
            }))
        } else {
            Ok(Wyr1eEvidenceSubmit::Accepted)
        }
    }
}

fn authorize_locked(
    transcript: &mut Transcript,
    process: ProcessKey,
) -> Result<(), Wyr1eEvidenceError> {
    if !transcript.retired {
        return Err(transcript.latch(Wyr1eEvidenceError::Early));
    }
    if transcript.reporter != Some(process) {
        return Err(transcript.latch(Wyr1eEvidenceError::WrongReporter));
    }
    if let Some(error) = transcript.failure {
        return Err(error);
    }
    if transcript.terminal {
        return Err(transcript.latch(Wyr1eEvidenceError::DuplicateTerminal));
    }
    if transcript.count == WYR1E_EVIDENCE_RECORD_CAPACITY {
        return Err(transcript.latch(Wyr1eEvidenceError::Full));
    }
    Ok(())
}

#[must_use]
pub(crate) struct Wyr1eEvidenceFlushPermit<'a> {
    collector: &'a Wyr1eEvidenceCollector,
}

impl Wyr1eEvidenceFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; WYR1E_EVIDENCE_RECORD_LEN]) -> Result<(), Wyr1eEvidenceFlushError>,
    ) -> Result<(), Wyr1eEvidenceFlushError> {
        let transcript = self
            .collector
            .transcript
            .try_lock()
            .ok_or(Wyr1eEvidenceFlushError::Busy)?;
        if transcript.failure.is_some()
            || !transcript.retired
            || !transcript.shell_exited
            || !transcript.terminal
            || transcript.count < 3
            || transcript.count > WYR1E_EVIDENCE_RECORD_CAPACITY
        {
            return Err(Wyr1eEvidenceFlushError::Incomplete);
        }
        // The 24 KiB bounded transcript remains in static storage. Holding the
        // selector-terminal lock avoids a kernel-stack copy while the sole
        // terminal owner emits the final certificate.
        for record in &transcript.records[..transcript.count] {
            emit(record)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DecodedRecord {
    record_type: u32,
    sequence: u64,
    nonce: u64,
    shell: ShellTuple,
    operation_transaction: u64,
    operation_job: u64,
    message_kind: u32,
    outcome_class: u32,
    values: [u64; 3],
    digest: [u8; 32],
}

fn validate_record(
    transcript: &Transcript,
    record: DecodedRecord,
    nonce: u64,
    version: EvidenceVersion,
) -> Result<(), Wyr1eEvidenceError> {
    let expected_sequence =
        u64::try_from(transcript.count + 1).map_err(|_| Wyr1eEvidenceError::OutOfOrder)?;
    if record.sequence != expected_sequence {
        return Err(Wyr1eEvidenceError::OutOfOrder);
    }
    if record.nonce != nonce {
        return Err(Wyr1eEvidenceError::WrongNonce);
    }
    if !record.shell.all_nonzero() {
        return Err(Wyr1eEvidenceError::Relation);
    }

    return match version {
        EvidenceVersion::V1_0 => validate_v1_0_record(transcript, record),
        EvidenceVersion::V1_1 => validate_v1_1_record(transcript, record),
    };
}

fn validate_v1_0_record(
    transcript: &Transcript,
    record: DecodedRecord,
) -> Result<(), Wyr1eEvidenceError> {
    if transcript
        .shell
        .is_some_and(|expected| expected != record.shell)
    {
        return Err(Wyr1eEvidenceError::Relation);
    }

    let semantic_zero = record.operation_transaction == 0
        && record.operation_job == 0
        && record.message_kind == 0
        && record.outcome_class == 0
        && record.values == [0; 3]
        && record.digest == [0; 32];
    match record.record_type {
        RECORD_SHELL_READY if transcript.count == 0 => {
            if record.operation_transaction != 0
                || record.operation_job != 0
                || record.message_kind != 0
                || record.outcome_class != 0
                || record.digest != [0; 32]
                || record.values.contains(&0)
            {
                return Err(Wyr1eEvidenceError::Relation);
            }
        }
        RECORD_SHELLJOBS_TRANSACTION if transcript.count != 0 && !transcript.shell_exited => {
            if record.operation_transaction == 0
                || !matches!(record.message_kind, 1 | 5 | 7 | 9 | 13)
                || record.digest == [0; 32]
            {
                return Err(Wyr1eEvidenceError::Relation);
            }
        }
        RECORD_SHELL_EXITED if transcript.count != 0 && !transcript.shell_exited => {
            if record.operation_transaction == 0
                || record.operation_job != record.shell.0[4]
                || record.message_kind != 13
                || record.outcome_class != 1
                || record.values != [0; 3]
                || record.digest == [0; 32]
            {
                return Err(Wyr1eEvidenceError::Relation);
            }
        }
        RECORD_TERMINAL if transcript.shell_exited && semantic_zero => {}
        RECORD_TERMINAL if transcript.terminal => {
            return Err(Wyr1eEvidenceError::DuplicateTerminal);
        }
        _ => return Err(Wyr1eEvidenceError::OutOfOrder),
    }
    Ok(())
}

fn validate_v1_1_record(
    transcript: &Transcript,
    record: DecodedRecord,
) -> Result<(), Wyr1eEvidenceError> {
    let semantic_zero = record.operation_transaction == 0
        && record.operation_job == 0
        && record.message_kind == 0
        && record.outcome_class == 0
        && record.values == [0; 3]
        && record.digest == [0; 32];
    match record.record_type {
        RECORD_SHELL_READY => validate_v1_1_ready(transcript, record),
        RECORD_SHELLJOBS_TRANSACTION => validate_v1_1_transaction(transcript, record),
        RECORD_SHELL_EXITED => validate_v1_1_retired(transcript, record),
        RECORD_TERMINAL if transcript.terminal => Err(Wyr1eEvidenceError::DuplicateTerminal),
        RECORD_TERMINAL
            if transcript.stage == 4
                && transcript.shell.is_none()
                && transcript.shell_exited
                && transcript.previous_shell == Some(record.shell)
                && semantic_zero
                && matches!(transcript.count + 1, E8_UP_RECORDS | E8_SMP_RECORDS) =>
        {
            Ok(())
        }
        _ => Err(Wyr1eEvidenceError::OutOfOrder),
    }
}

fn validate_v1_1_ready(
    transcript: &Transcript,
    record: DecodedRecord,
) -> Result<(), Wyr1eEvidenceError> {
    let expected_stage = transcript
        .stage
        .checked_add(1)
        .ok_or(Wyr1eEvidenceError::OutOfOrder)?;
    if transcript.shell.is_some()
        || expected_stage > 4
        || record.message_kind != expected_stage
        || record.operation_transaction == 0
        || record.operation_job == 0
        || record.outcome_class != 0
        || record.values.contains(&0)
        || record.digest == [0; 32]
    {
        return Err(Wyr1eEvidenceError::Relation);
    }
    let Some(previous) = transcript.previous_shell else {
        return if expected_stage == 1 {
            Ok(())
        } else {
            Err(Wyr1eEvidenceError::OutOfOrder)
        };
    };
    let old = previous.0;
    let new = record.shell.0;
    let common_fresh = new[3] != old[3]
        && new[4] != old[4]
        && (new[6], new[7]) != (old[6], old[7])
        && (new[8], new[9]) != (old[8], old[9]);
    let relation = match expected_stage {
        2 => {
            new[0] == old[0]
                && new[1] != old[1]
                && new[2] != old[2]
                && new[5] == old[5]
                && common_fresh
                && record.operation_transaction == transcript.ready_aux0
                && record.operation_job == transcript.ready_aux1
                && record.values == transcript.ready_values
        }
        3 => {
            new[5] == old[5]
                && common_fresh
                && record.operation_transaction != transcript.ready_aux0
                && record.operation_job != transcript.ready_aux1
                && record.values[0] != transcript.ready_values[0]
                && record.values[1] != transcript.ready_values[1]
        }
        4 => {
            new[5] != old[5]
                && common_fresh
                && record.operation_transaction != transcript.ready_aux0
                && record.operation_job != transcript.ready_aux1
                && record.values[0] != transcript.ready_values[0]
        }
        _ => false,
    };
    if relation {
        Ok(())
    } else {
        Err(Wyr1eEvidenceError::Relation)
    }
}

fn validate_v1_1_transaction(
    transcript: &Transcript,
    record: DecodedRecord,
) -> Result<(), Wyr1eEvidenceError> {
    let Some(shell) = transcript.shell else {
        return Err(Wyr1eEvidenceError::OutOfOrder);
    };
    if record.shell != shell
        || !transaction_kind_matches(
            transcript.stage,
            transcript.epoch_transactions,
            record.message_kind,
            transcript.stage4_profile,
        )
        || record.operation_transaction == 0
        || record.operation_transaction <= transcript.last_transaction
        || record.digest == [0; 32]
    {
        return Err(Wyr1eEvidenceError::Relation);
    }
    if matches!(transcript.stage, 2 | 3) && record.operation_job == 0 {
        return Err(Wyr1eEvidenceError::Relation);
    }
    Ok(())
}

fn validate_v1_1_retired(
    transcript: &Transcript,
    record: DecodedRecord,
) -> Result<(), Wyr1eEvidenceError> {
    let Some(shell) = transcript.shell else {
        return Err(Wyr1eEvidenceError::OutOfOrder);
    };
    if record.shell != shell
        || record.message_kind != transcript.stage
        || !epoch_transaction_count_complete(transcript.stage, transcript.epoch_transactions)
        || record.digest == [0; 32]
    {
        return Err(Wyr1eEvidenceError::Relation);
    }
    match transcript.stage {
        1 | 4 => {
            if record.operation_transaction == 0
                || record.operation_job != shell.0[4]
                || record.outcome_class != 1
                || record.values != [0; 3]
            {
                return Err(Wyr1eEvidenceError::Relation);
            }
        }
        2 | 3 => {
            let trigger_wait_transaction = transcript
                .trigger_launch_transaction
                .checked_add(1)
                .ok_or(Wyr1eEvidenceError::Relation)?;
            if record.operation_transaction != trigger_wait_transaction
                || record.operation_job != transcript.trigger_job
                || !forced_retirement_result(record.outcome_class, record.values)
            {
                return Err(Wyr1eEvidenceError::Relation);
            }
        }
        _ => return Err(Wyr1eEvidenceError::OutOfOrder),
    }
    Ok(())
}

fn forced_retirement_result(outcome: u32, values: [u64; 3]) -> bool {
    (outcome == 5 && values == [0; 3])
        || (outcome == 1
            && matches!(values[0], 0x5745_0104 | 0x5745_0106)
            && values[1] == 0
            && values[2] == 0)
}

const S1_KINDS: [u32; 18] = [13, 1, 5, 9, 1, 1, 1, 5, 9, 1, 5, 9, 1, 13, 7, 5, 9, 13];
const TRIGGER_KINDS: [u32; 1] = [1];
const S4_UP_KINDS: [u32; 4] = [1, 5, 9, 13];
const S4_SMP_KINDS: [u32; 40] = [
    1, 1, 1, 1, 1, 1, 13, 1, 5, 9, 13, 1, 5, 9, 13, 1, 5, 9, 7, 7, 7, 7, 7, 7, 5, 9, 5, 9, 5, 9, 5,
    9, 5, 9, 5, 9, 1, 5, 9, 13,
];
const _: () = assert!(
    1 + S1_KINDS.len() + 1 + 2 * (1 + TRIGGER_KINDS.len() + 1) + 1 + S4_UP_KINDS.len() + 1 + 1
        == E8_UP_RECORDS
);
const _: () = assert!(
    1 + S1_KINDS.len() + 1 + 2 * (1 + TRIGGER_KINDS.len() + 1) + 1 + S4_SMP_KINDS.len() + 1 + 1
        == E8_SMP_RECORDS
);

fn transaction_kind_matches(stage: u32, index: usize, kind: u32, stage4_profile: u8) -> bool {
    match stage {
        1 => S1_KINDS.get(index) == Some(&kind),
        2 | 3 => TRIGGER_KINDS.get(index) == Some(&kind),
        4 if stage4_profile == 1 => S4_UP_KINDS.get(index) == Some(&kind),
        4 if stage4_profile == 2 => S4_SMP_KINDS.get(index) == Some(&kind),
        4 => S4_UP_KINDS.get(index) == Some(&kind) || S4_SMP_KINDS.get(index) == Some(&kind),
        _ => false,
    }
}

fn epoch_transaction_count_complete(stage: u32, count: usize) -> bool {
    match stage {
        1 => count == S1_KINDS.len(),
        2 | 3 => count == TRIGGER_KINDS.len(),
        4 => count == S4_UP_KINDS.len() || count == S4_SMP_KINDS.len(),
        _ => false,
    }
}

fn commit_record(transcript: &mut Transcript, record: DecodedRecord, version: EvidenceVersion) {
    if version == EvidenceVersion::V1_0 {
        if transcript.shell.is_none() {
            transcript.shell = Some(record.shell);
        }
        if record.record_type == RECORD_SHELL_EXITED {
            transcript.shell_exited = true;
        }
        return;
    }
    match record.record_type {
        RECORD_SHELL_READY => {
            transcript.shell = Some(record.shell);
            transcript.stage = record.message_kind;
            transcript.epoch_transactions = 0;
            transcript.last_transaction = 0;
            transcript.trigger_launch_transaction = 0;
            transcript.trigger_job = 0;
            transcript.ready_aux0 = record.operation_transaction;
            transcript.ready_aux1 = record.operation_job;
            transcript.ready_values = record.values;
            transcript.stage4_profile = 0;
        }
        RECORD_SHELLJOBS_TRANSACTION => {
            if transcript.stage == 4 && transcript.epoch_transactions == 1 {
                transcript.stage4_profile = if record.message_kind == 5 { 1 } else { 2 };
            }
            transcript.epoch_transactions += 1;
            transcript.last_transaction = record.operation_transaction;
            if matches!(transcript.stage, 2 | 3) {
                transcript.trigger_launch_transaction = record.operation_transaction;
                transcript.trigger_job = record.operation_job;
            }
        }
        RECORD_SHELL_EXITED => {
            transcript.previous_shell = transcript.shell.take();
            transcript.shell_exited = transcript.stage == 4;
        }
        RECORD_TERMINAL => {}
        _ => unreachable!("validated WRE1 record type"),
    }
}

fn decode_record(
    record: &[u8; WYR1E_EVIDENCE_RECORD_LEN],
    version: EvidenceVersion,
) -> Result<DecodedRecord, Wyr1eEvidenceError> {
    let expected_minor = match version {
        EvidenceVersion::V1_0 => 0,
        EvidenceVersion::V1_1 => 1,
    };
    if &record[0..4] != b"WRE1"
        || read_u16(record, 4) != 1
        || read_u16(record, 6) != expected_minor
        || read_u32(record, 12) != WYR1E_EVIDENCE_RECORD_LEN as u32
    {
        return Err(Wyr1eEvidenceError::Malformed);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&record[160..192]);
    Ok(DecodedRecord {
        record_type: read_u32(record, 8),
        sequence: read_u64(record, 16),
        nonce: read_u64(record, 24),
        shell: ShellTuple([
            read_u64(record, 32),
            read_u64(record, 40),
            read_u64(record, 48),
            read_u64(record, 56),
            read_u64(record, 64),
            read_u64(record, 72),
            read_u64(record, 80),
            read_u64(record, 88),
            read_u64(record, 96),
            read_u64(record, 104),
        ]),
        operation_transaction: read_u64(record, 112),
        operation_job: read_u64(record, 120),
        message_kind: read_u32(record, 128),
        outcome_class: read_u32(record, 132),
        values: [
            read_u64(record, 136),
            read_u64(record, 144),
            read_u64(record, 152),
        ],
        digest,
    })
}

fn map_startup_error(error: super::wyr1b_evidence::Wyr1bEvidenceError) -> Wyr1eEvidenceError {
    use super::wyr1b_evidence::Wyr1bEvidenceError;
    match error {
        Wyr1bEvidenceError::StartupMissing => Wyr1eEvidenceError::StartupMissing,
        Wyr1bEvidenceError::StartupDuplicate => Wyr1eEvidenceError::StartupDuplicate,
        Wyr1bEvidenceError::StartupRoot => Wyr1eEvidenceError::StartupRoot,
        Wyr1bEvidenceError::StartupEntry => Wyr1eEvidenceError::StartupEntry,
        Wyr1bEvidenceError::StartupStackPointer => Wyr1eEvidenceError::StartupStackPointer,
        Wyr1bEvidenceError::StartupStackMapping => Wyr1eEvidenceError::StartupStackMapping,
        Wyr1bEvidenceError::StartupStackProtection => Wyr1eEvidenceError::StartupStackProtection,
        Wyr1bEvidenceError::StartupGuard => Wyr1eEvidenceError::StartupGuard,
        _ => Wyr1eEvidenceError::Malformed,
    }
}

fn read_u16(record: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        record[offset..offset + 2]
            .try_into()
            .expect("fixed WRE1 u16"),
    )
}

fn read_u32(record: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        record[offset..offset + 4]
            .try_into()
            .expect("fixed WRE1 u32"),
    )
}

fn read_u64(record: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        record[offset..offset + 8]
            .try_into()
            .expect("fixed WRE1 u64"),
    )
}

const fn parse_build_nonce(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() == 16,
        "selector-33 nonce must contain 16 digits"
    );
    let mut parsed = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("selector-33 nonce must be uppercase hexadecimal"),
        };
        parsed = (parsed << 4) | digit as u64;
        index += 1;
    }
    assert!(parsed != 0, "selector-33 nonce must be nonzero");
    parsed
}

#[cfg(all(deepwyrm_wyr1e_evidence, not(deepwyrm_wyr1e8_evidence)))]
pub(crate) static WYR1E_EVIDENCE: Wyr1eEvidenceCollector =
    Wyr1eEvidenceCollector::new(parse_build_nonce(env!("DEEPWYRM_WYR1E7_EVIDENCE_NONCE")));
#[cfg(deepwyrm_wyr1e8_evidence)]
pub(crate) static WYR1E_EVIDENCE: Wyr1eEvidenceCollector =
    Wyr1eEvidenceCollector::new_v1_1(parse_build_nonce(env!("DEEPWYRM_WYR1E8_EVIDENCE_NONCE")));

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
        collector: &Wyr1eEvidenceCollector,
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

    fn encode(record_type: u32, sequence: u64) -> [u8; WYR1E_EVIDENCE_RECORD_LEN] {
        let mut record = [0_u8; WYR1E_EVIDENCE_RECORD_LEN];
        record[..4].copy_from_slice(b"WRE1");
        write_u16(&mut record, 4, 1);
        write_u32(&mut record, 8, record_type);
        write_u32(&mut record, 12, WYR1E_EVIDENCE_RECORD_LEN as u32);
        write_u64(&mut record, 16, sequence);
        write_u64(&mut record, 24, NONCE);
        for index in 0..10 {
            write_u64(&mut record, 32 + index * 8, index as u64 + 1);
        }
        match record_type {
            RECORD_SHELL_READY => {
                write_u64(&mut record, 136, 1);
                write_u64(&mut record, 144, 2);
                write_u64(&mut record, 152, 3);
            }
            RECORD_SHELLJOBS_TRANSACTION => {
                write_u64(&mut record, 112, sequence + 100);
                write_u32(&mut record, 128, 5);
                record[160] = 1;
            }
            RECORD_SHELL_EXITED => {
                write_u64(&mut record, 112, sequence + 100);
                write_u64(&mut record, 120, 5);
                write_u32(&mut record, 128, 13);
                write_u32(&mut record, 132, 1);
                record[160] = 1;
            }
            RECORD_TERMINAL => {}
            _ => {}
        }
        record
    }

    fn encode_e8(
        record_type: u32,
        sequence: u64,
        shell: [u64; 10],
        aux0: u64,
        aux1: u64,
        kind: u32,
        outcome: u32,
        values: [u64; 3],
    ) -> [u8; WYR1E_EVIDENCE_RECORD_LEN] {
        let mut record = [0_u8; WYR1E_EVIDENCE_RECORD_LEN];
        record[..4].copy_from_slice(b"WRE1");
        write_u16(&mut record, 4, 1);
        write_u16(&mut record, 6, 1);
        write_u32(&mut record, 8, record_type);
        write_u32(&mut record, 12, WYR1E_EVIDENCE_RECORD_LEN as u32);
        write_u64(&mut record, 16, sequence);
        write_u64(&mut record, 24, NONCE);
        for (index, value) in shell.into_iter().enumerate() {
            write_u64(&mut record, 32 + index * 8, value);
        }
        write_u64(&mut record, 112, aux0);
        write_u64(&mut record, 120, aux1);
        write_u32(&mut record, 128, kind);
        write_u32(&mut record, 132, outcome);
        for (index, value) in values.into_iter().enumerate() {
            write_u64(&mut record, 136 + index * 8, value);
        }
        if record_type != RECORD_TERMINAL {
            record[160] = 1;
        }
        record
    }

    fn submit_e8_profile(collector: &Wyr1eEvidenceCollector, reporter: ProcessKey, smp: bool) {
        let shells = [
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            [1, 12, 13, 14, 15, 6, 17, 18, 19, 20],
            [21, 22, 23, 24, 25, 6, 27, 28, 29, 30],
            [31, 32, 33, 34, 35, 36, 37, 38, 39, 40],
        ];
        let ready_aux = [(41, 42), (41, 42), (51, 52), (61, 62)];
        let ready_values = [[71, 72, 73], [71, 72, 73], [81, 82, 83], [91, 82, 83]];
        let mut sequence = 1_u64;
        for stage in 1..=4_u32 {
            let index = (stage - 1) as usize;
            collector
                .submit(
                    reporter,
                    &encode_e8(
                        RECORD_SHELL_READY,
                        sequence,
                        shells[index],
                        ready_aux[index].0,
                        ready_aux[index].1,
                        stage,
                        0,
                        ready_values[index],
                    ),
                )
                .unwrap();
            sequence += 1;
            let kinds: &[u32] = match stage {
                1 => &S1_KINDS,
                2 | 3 => &TRIGGER_KINDS,
                4 if smp => &S4_SMP_KINDS,
                4 => &S4_UP_KINDS,
                _ => unreachable!(),
            };
            let mut launch = (0_u64, 0_u64);
            for (transaction_index, kind) in kinds.iter().copied().enumerate() {
                let transaction = transaction_index as u64 + 101;
                let job = if kind == 1 { transaction + 1000 } else { 0 };
                if matches!(stage, 2 | 3) {
                    launch = (transaction, job);
                }
                collector
                    .submit(
                        reporter,
                        &encode_e8(
                            RECORD_SHELLJOBS_TRANSACTION,
                            sequence,
                            shells[index],
                            transaction,
                            job,
                            kind,
                            0,
                            [0; 3],
                        ),
                    )
                    .unwrap();
                sequence += 1;
            }
            let (aux0, aux1, outcome, values) = if matches!(stage, 2 | 3) {
                (launch.0 + 1, launch.1, 1, [0x5745_0106, 0, 0])
            } else {
                (900 + stage as u64, shells[index][4], 1, [0; 3])
            };
            collector
                .submit(
                    reporter,
                    &encode_e8(
                        RECORD_SHELL_EXITED,
                        sequence,
                        shells[index],
                        aux0,
                        aux1,
                        stage,
                        outcome,
                        values,
                    ),
                )
                .unwrap();
            sequence += 1;
        }
        let Wyr1eEvidenceSubmit::Terminal(permit) = collector
            .submit(
                reporter,
                &encode_e8(RECORD_TERMINAL, sequence, shells[3], 0, 0, 0, 0, [0; 3]),
            )
            .unwrap()
        else {
            panic!("E8 terminal must return flush permit")
        };
        let mut emitted = 0;
        permit
            .flush(|_| {
                emitted += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(emitted, if smp { E8_SMP_RECORDS } else { E8_UP_RECORDS });
    }

    fn collector_after_stage1() -> (Wyr1eEvidenceCollector, ProcessKey, [u64; 10]) {
        let collector = Wyr1eEvidenceCollector::new_v1_1(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        let first_shell = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut sequence = 1_u64;
        collector
            .submit(
                reporter,
                &encode_e8(
                    RECORD_SHELL_READY,
                    sequence,
                    first_shell,
                    41,
                    42,
                    1,
                    0,
                    [71, 72, 73],
                ),
            )
            .unwrap();
        sequence += 1;
        for (transaction_index, kind) in S1_KINDS.into_iter().enumerate() {
            collector
                .submit(
                    reporter,
                    &encode_e8(
                        RECORD_SHELLJOBS_TRANSACTION,
                        sequence,
                        first_shell,
                        transaction_index as u64 + 101,
                        0,
                        kind,
                        0,
                        [0; 3],
                    ),
                )
                .unwrap();
            sequence += 1;
        }
        collector
            .submit(
                reporter,
                &encode_e8(
                    RECORD_SHELL_EXITED,
                    sequence,
                    first_shell,
                    901,
                    first_shell[4],
                    1,
                    1,
                    [0; 3],
                ),
            )
            .unwrap();
        (collector, reporter, first_shell)
    }

    fn collector_at_stage2_trigger(
        trigger_launch_transaction: u64,
    ) -> (Wyr1eEvidenceCollector, ProcessKey, [u64; 10]) {
        let (collector, reporter, _) = collector_after_stage1();
        let second_shell = [1, 12, 13, 14, 15, 6, 17, 18, 19, 20];
        collector
            .submit(
                reporter,
                &encode_e8(
                    RECORD_SHELL_READY,
                    21,
                    second_shell,
                    41,
                    42,
                    2,
                    0,
                    [71, 72, 73],
                ),
            )
            .unwrap();
        collector
            .submit(
                reporter,
                &encode_e8(
                    RECORD_SHELLJOBS_TRANSACTION,
                    22,
                    second_shell,
                    trigger_launch_transaction,
                    1_101,
                    1,
                    0,
                    [0; 3],
                ),
            )
            .unwrap();
        (collector, reporter, second_shell)
    }

    #[test]
    fn e8_exact_up_and_smp_lifecycles_flush() {
        for smp in [false, true] {
            let collector = Wyr1eEvidenceCollector::new_v1_1(NONCE);
            let (reporter, thread, root) = subject();
            arm(&collector, reporter, thread, root);
            submit_e8_profile(&collector, reporter, smp);
        }
    }

    #[test]
    fn e8_forced_retirement_results_are_exact_and_priority_complete() {
        assert!(forced_retirement_result(1, [0x5745_0104, 0, 0]));
        assert!(forced_retirement_result(1, [0x5745_0106, 0, 0]));
        assert!(forced_retirement_result(5, [0; 3]));
        for rejected in [
            (1, [0x5745_0105, 0, 0]),
            (1, [0x5745_0104, 1, 0]),
            (2, [0; 3]),
            (5, [1, 0, 0]),
        ] {
            assert!(!forced_retirement_result(rejected.0, rejected.1));
        }
    }

    #[test]
    fn e8_forced_retirement_wait_is_exact_checked_successor() {
        for (launch_transaction, wait_transaction, accepted) in [
            (101, 102, true),
            (101, 103, false),
            (u64::MAX, u64::MAX, false),
        ] {
            let (collector, reporter, shell) = collector_at_stage2_trigger(launch_transaction);
            let result = collector.submit(
                reporter,
                &encode_e8(
                    RECORD_SHELL_EXITED,
                    23,
                    shell,
                    wait_transaction,
                    1_101,
                    2,
                    1,
                    [0x5745_0106, 0, 0],
                ),
            );
            if accepted {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.err(), Some(Wyr1eEvidenceError::Relation));
            }
        }
    }

    #[test]
    fn e8_clean_replacement_requires_fresh_status_and_shell_generations() {
        for reused_index in [1, 2] {
            let (collector, reporter, old_shell) = collector_after_stage1();
            let mut new_shell = [1, 12, 13, 14, 15, 6, 17, 18, 19, 20];
            new_shell[reused_index] = old_shell[reused_index];
            let ready = encode_e8(
                RECORD_SHELL_READY,
                21,
                new_shell,
                41,
                42,
                2,
                0,
                [71, 72, 73],
            );
            assert_eq!(
                collector.submit(reporter, &ready).err(),
                Some(Wyr1eEvidenceError::Relation)
            );
        }
    }

    #[test]
    fn e8_minor_and_exact_transaction_order_fail_closed() {
        let collector = Wyr1eEvidenceCollector::new_v1_1(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        let shell = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut old_minor = encode_e8(RECORD_SHELL_READY, 1, shell, 11, 12, 1, 0, [13, 14, 15]);
        write_u16(&mut old_minor, 6, 0);
        assert_eq!(
            collector.submit(reporter, &old_minor).err(),
            Some(Wyr1eEvidenceError::Malformed)
        );

        let collector = Wyr1eEvidenceCollector::new_v1_1(NONCE);
        arm(&collector, reporter, thread, root);
        collector
            .submit(
                reporter,
                &encode_e8(RECORD_SHELL_READY, 1, shell, 11, 12, 1, 0, [13, 14, 15]),
            )
            .unwrap();
        let wrong_first = encode_e8(RECORD_SHELLJOBS_TRANSACTION, 2, shell, 21, 0, 1, 0, [0; 3]);
        assert_eq!(
            collector.submit(reporter, &wrong_first).err(),
            Some(Wyr1eEvidenceError::Relation)
        );
    }

    #[test]
    fn exact_lifecycle_flushes_complete_certificate() {
        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        for sequence in 1..=3 {
            let kind = [
                RECORD_SHELL_READY,
                RECORD_SHELLJOBS_TRANSACTION,
                RECORD_SHELL_EXITED,
            ][(sequence - 1) as usize];
            assert!(matches!(
                collector.submit(reporter, &encode(kind, sequence)).unwrap(),
                Wyr1eEvidenceSubmit::Accepted
            ));
        }
        let Wyr1eEvidenceSubmit::Terminal(permit) = collector
            .submit(reporter, &encode(RECORD_TERMINAL, 4))
            .unwrap()
        else {
            panic!("terminal record must return the flush permit")
        };
        let mut emitted = 0;
        permit
            .flush(|_| {
                emitted += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(emitted, 4);
    }

    #[test]
    fn reporter_retirement_and_post_usercopy_recheck_are_fail_closed() {
        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        assert_eq!(
            collector.authorize_submission(reporter),
            Err(Wyr1eEvidenceError::Early)
        );

        let collector = Wyr1eEvidenceCollector::new(NONCE);
        arm(&collector, reporter, thread, root);
        let (other, _, _) = subject();
        assert_eq!(
            collector.authorize_submission(other),
            Err(Wyr1eEvidenceError::WrongReporter)
        );
    }

    #[test]
    fn framing_nonce_sequence_tuple_and_lifecycle_mutations_latch() {
        for mutation in 0..7 {
            let collector = Wyr1eEvidenceCollector::new(NONCE);
            let (reporter, thread, root) = subject();
            arm(&collector, reporter, thread, root);
            let mut record = encode(RECORD_SHELL_READY, 1);
            match mutation {
                0 => record[0] = b'X',
                1 => write_u64(&mut record, 24, NONCE + 1),
                2 => write_u64(&mut record, 16, 2),
                3 => write_u64(&mut record, 32, 0),
                4 => write_u64(&mut record, 112, 1),
                5 => write_u32(&mut record, 8, RECORD_TERMINAL),
                6 => write_u64(&mut record, 136, 0),
                _ => unreachable!(),
            }
            assert!(collector.submit(reporter, &record).is_err());
            assert!(
                collector
                    .submit(reporter, &encode(RECORD_SHELL_READY, 1))
                    .is_err()
            );
        }

        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        collector
            .submit(reporter, &encode(RECORD_SHELL_READY, 1))
            .unwrap();
        let mut changed = encode(RECORD_SHELLJOBS_TRANSACTION, 2);
        write_u64(&mut changed, 104, 99);
        assert_eq!(
            collector.submit(reporter, &changed).err(),
            Some(Wyr1eEvidenceError::Relation)
        );
    }

    #[test]
    fn capacity_reserves_the_last_slot_for_terminal() {
        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        collector
            .submit(reporter, &encode(RECORD_SHELL_READY, 1))
            .unwrap();
        for sequence in 2..WYR1E_EVIDENCE_RECORD_CAPACITY as u64 {
            collector
                .submit(reporter, &encode(RECORD_SHELLJOBS_TRANSACTION, sequence))
                .unwrap();
        }
        assert_eq!(
            collector
                .submit(
                    reporter,
                    &encode(RECORD_SHELL_EXITED, WYR1E_EVIDENCE_RECORD_CAPACITY as u64)
                )
                .err(),
            Some(Wyr1eEvidenceError::Full)
        );
    }

    #[test]
    fn terminal_is_unique_last_and_immediately_follows_shell_exit() {
        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        collector
            .submit(reporter, &encode(RECORD_SHELL_READY, 1))
            .unwrap();
        assert_eq!(
            collector
                .submit(reporter, &encode(RECORD_TERMINAL, 2))
                .err(),
            Some(Wyr1eEvidenceError::OutOfOrder)
        );
    }

    #[test]
    fn type_shapes_check_request_kind_without_interpreting_transaction_outcome() {
        for message_kind in [1, 5, 7, 9, 13] {
            let collector = Wyr1eEvidenceCollector::new(NONCE);
            let (reporter, thread, root) = subject();
            arm(&collector, reporter, thread, root);
            collector
                .submit(reporter, &encode(RECORD_SHELL_READY, 1))
                .unwrap();
            let mut transaction = encode(RECORD_SHELLJOBS_TRANSACTION, 2);
            write_u32(&mut transaction, 128, message_kind);
            collector.submit(reporter, &transaction).unwrap();
        }

        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        collector
            .submit(reporter, &encode(RECORD_SHELL_READY, 1))
            .unwrap();

        let mut opaque = encode(RECORD_SHELLJOBS_TRANSACTION, 2);
        write_u32(&mut opaque, 128, 13);
        write_u32(&mut opaque, 132, 0xdead_beef);
        write_u64(&mut opaque, 120, 0);
        write_u64(&mut opaque, 136, u64::MAX);
        collector.submit(reporter, &opaque).unwrap();

        let mut unknown_kind = encode(RECORD_SHELLJOBS_TRANSACTION, 3);
        write_u32(&mut unknown_kind, 128, 0xfeed_beef);
        assert_eq!(
            collector.submit(reporter, &unknown_kind).err(),
            Some(Wyr1eEvidenceError::Relation)
        );

        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        collector
            .submit(reporter, &encode(RECORD_SHELL_READY, 1))
            .unwrap();
        let mut exited = encode(RECORD_SHELL_EXITED, 2);
        write_u32(&mut exited, 128, 12);
        assert_eq!(
            collector.submit(reporter, &exited).err(),
            Some(Wyr1eEvidenceError::Relation)
        );
    }

    #[test]
    fn transport_failure_stops_flush_and_terminal_cannot_repeat() {
        let collector = Wyr1eEvidenceCollector::new(NONCE);
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
        collector
            .submit(reporter, &encode(RECORD_SHELL_READY, 1))
            .unwrap();
        collector
            .submit(reporter, &encode(RECORD_SHELL_EXITED, 2))
            .unwrap();
        let Wyr1eEvidenceSubmit::Terminal(permit) = collector
            .submit(reporter, &encode(RECORD_TERMINAL, 3))
            .unwrap()
        else {
            panic!("terminal record must return the flush permit")
        };
        let mut emitted = 0;
        assert_eq!(
            permit.flush(|_| {
                emitted += 1;
                if emitted == 2 {
                    Err(Wyr1eEvidenceFlushError::Transport)
                } else {
                    Ok(())
                }
            }),
            Err(Wyr1eEvidenceFlushError::Transport)
        );
        assert_eq!(emitted, 2);
        assert_eq!(
            collector
                .submit(reporter, &encode(RECORD_TERMINAL, 4))
                .err(),
            Some(Wyr1eEvidenceError::DuplicateTerminal)
        );
    }
}
