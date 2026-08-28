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

use crate::memory::address_region::AddressRegionObjectKey;
use crate::sync::SpinMutex;
use crate::task::{ProcessKey, ThreadKey};

pub(crate) const WYR1B_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1b;
pub(crate) const WYR1B_EVIDENCE_RECORD_LEN: usize = 96;
pub(crate) const WYR1B_EVIDENCE_RECORD_CAPACITY: usize = 14;
// Private selector-27 mirror of Wyrmroot's fixed legacy-v1 system-init child
// geometry. This test invariant is separate from Deepwyrm's primordial
// bootstrap stack: system-init remains 128 KiB while Deepwyrm's independently
// owned primordial stack is 256 KiB after the DW1-C functional-first revision.
pub(crate) const WYR1B_SYSTEM_INIT_STACK_TOP: u64 = 0x0000_7fff_ffff_0000;
pub(crate) const WYR1B_SYSTEM_INIT_STACK_BYTES: u64 = 128 * 1024;
pub(crate) const WYR1B_SYSTEM_INIT_STACK_BOTTOM: u64 =
    WYR1B_SYSTEM_INIT_STACK_TOP - WYR1B_SYSTEM_INIT_STACK_BYTES;
pub(crate) const WYR1B_SYSTEM_INIT_STACK_POINTER: u64 = WYR1B_SYSTEM_INIT_STACK_TOP - 4096;
pub(crate) const WYR1B_SYSTEM_INIT_GUARD_START: u64 = WYR1B_SYSTEM_INIT_STACK_BOTTOM - 4096;
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

/// Selector-local facts captured from the exact first Thread started in the
/// primordial child that becomes the permanent controller. These are private
/// kernel/test identities, not a Wyrmroot or Deepwyrm ABI record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Wyr1bReporterStartFacts {
    pub(crate) reporter_process: ProcessKey,
    pub(crate) reporter_thread: ThreadKey,
    pub(crate) reporter_root: AddressRegionObjectKey,
    pub(crate) root_owned_by_reporter: bool,
    pub(crate) entry_point: u64,
    pub(crate) entry_mapping_bound: bool,
    pub(crate) stack_pointer: u64,
    pub(crate) stack_mapping_start: u64,
    pub(crate) stack_mapping_bytes: u64,
    pub(crate) stack_mapping_rw_nx: bool,
    pub(crate) guard_absent: bool,
}

impl Wyr1bReporterStartFacts {
    const fn validate(self) -> Result<(), Wyr1bEvidenceError> {
        if !self.root_owned_by_reporter {
            return Err(Wyr1bEvidenceError::StartupRoot);
        }
        if self.entry_point == 0 || !self.entry_mapping_bound {
            return Err(Wyr1bEvidenceError::StartupEntry);
        }
        if self.stack_pointer != WYR1B_SYSTEM_INIT_STACK_POINTER {
            return Err(Wyr1bEvidenceError::StartupStackPointer);
        }
        if self.stack_mapping_start != WYR1B_SYSTEM_INIT_STACK_BOTTOM
            || self.stack_mapping_bytes != WYR1B_SYSTEM_INIT_STACK_BYTES
        {
            return Err(Wyr1bEvidenceError::StartupStackMapping);
        }
        if !self.stack_mapping_rw_nx {
            return Err(Wyr1bEvidenceError::StartupStackProtection);
        }
        if !self.guard_absent {
            return Err(Wyr1bEvidenceError::StartupGuard);
        }
        Ok(())
    }
}

struct Transcript {
    records: [[u8; WYR1B_EVIDENCE_RECORD_LEN]; WYR1B_EVIDENCE_RECORD_CAPACITY],
    count: usize,
    startup: Option<Wyr1bReporterStartFacts>,
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
            startup: None,
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

    pub(crate) fn observe_reporter_start(
        &self,
        facts: Wyr1bReporterStartFacts,
    ) -> Result<(), Wyr1bEvidenceError> {
        let mut transcript = self.transcript.lock();
        if transcript.startup.is_some() {
            return Err(transcript.latch(Wyr1bEvidenceError::StartupDuplicate));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        if let Err(error) = facts.validate() {
            return Err(transcript.latch(error));
        }
        transcript.startup = Some(facts);
        Ok(())
    }

    pub(crate) fn bind_reporter_after_retirement(
        &self,
        reporter: ProcessKey,
        reporter_thread: ThreadKey,
        reporter_root: AddressRegionObjectKey,
        facts: Wyr1bRetirementFacts,
    ) -> Result<(), Wyr1bEvidenceError> {
        let mut transcript = self.transcript.lock();
        if !facts.complete() || transcript.retired || transcript.reporter.is_some() {
            return Err(transcript.latch(Wyr1bEvidenceError::Retirement));
        }
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        let Some(startup) = transcript.startup else {
            return Err(transcript.latch(Wyr1bEvidenceError::StartupMissing));
        };
        if startup.reporter_process != reporter
            || startup.reporter_thread != reporter_thread
            || startup.reporter_root != reporter_root
        {
            return Err(transcript.latch(Wyr1bEvidenceError::StartupRoot));
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
        Wyr1bEvidenceError::StartupMissing => Wyr1bEvidenceFlushError::StartupMissing,
        Wyr1bEvidenceError::StartupDuplicate => Wyr1bEvidenceFlushError::StartupDuplicate,
        Wyr1bEvidenceError::StartupRoot => Wyr1bEvidenceFlushError::StartupRoot,
        Wyr1bEvidenceError::StartupEntry => Wyr1bEvidenceFlushError::StartupEntry,
        Wyr1bEvidenceError::StartupStackPointer => Wyr1bEvidenceFlushError::StartupStackPointer,
        Wyr1bEvidenceError::StartupStackMapping => Wyr1bEvidenceFlushError::StartupStackMapping,
        Wyr1bEvidenceError::StartupStackProtection => {
            Wyr1bEvidenceFlushError::StartupStackProtection
        }
        Wyr1bEvidenceError::StartupGuard => Wyr1bEvidenceFlushError::StartupGuard,
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

    fn process_key() -> ProcessKey {
        subject().0
    }

    fn valid_start(
        reporter_process: ProcessKey,
        reporter_thread: ThreadKey,
        reporter_root: AddressRegionObjectKey,
    ) -> Wyr1bReporterStartFacts {
        Wyr1bReporterStartFacts {
            reporter_process,
            reporter_thread,
            reporter_root,
            root_owned_by_reporter: true,
            entry_point: 0x20_0000,
            entry_mapping_bound: true,
            stack_pointer: WYR1B_SYSTEM_INIT_STACK_POINTER,
            stack_mapping_start: WYR1B_SYSTEM_INIT_STACK_BOTTOM,
            stack_mapping_bytes: WYR1B_SYSTEM_INIT_STACK_BYTES,
            stack_mapping_rw_nx: true,
            guard_absent: true,
        }
    }

    fn arm(
        collector: &Wyr1bEvidenceCollector,
        reporter: ProcessKey,
        thread: ThreadKey,
        root: AddressRegionObjectKey,
    ) {
        collector
            .observe_reporter_start(valid_start(reporter, thread, root))
            .unwrap();
        collector
            .bind_reporter_after_retirement(reporter, thread, root, RETIRED)
            .unwrap();
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
        let (reporter, thread, root) = subject();
        arm(&collector, reporter, thread, root);
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
        let (reporter, thread, root) = subject();
        let other = process_key();

        let wrong = Wyr1bEvidenceCollector::new(NONCE);
        arm(&wrong, reporter, thread, root);
        assert!(matches!(
            wrong.submit(other, &record(0, 1)),
            Err(Wyr1bEvidenceError::WrongReporter)
        ));

        let order = Wyr1bEvidenceCollector::new(NONCE);
        arm(&order, reporter, thread, root);
        assert!(matches!(
            order.submit(reporter, &record(0, 2)),
            Err(Wyr1bEvidenceError::OutOfOrder)
        ));

        let malformed = Wyr1bEvidenceCollector::new(NONCE);
        arm(&malformed, reporter, thread, root);
        let mut bad = record(0, 1);
        bad[95] ^= 1;
        assert!(matches!(
            malformed.submit(reporter, &bad),
            Err(Wyr1bEvidenceError::Malformed)
        ));

        let terminal = Wyr1bEvidenceCollector::new(NONCE);
        arm(&terminal, reporter, thread, root);
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
        let (reporter, thread, root) = subject();
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
                collector.bind_reporter_after_retirement(reporter, thread, root, facts),
                Err(Wyr1bEvidenceError::Retirement)
            );
        }
    }

    #[test]
    fn reporter_start_facts_bind_exact_root_stack_and_guard() {
        let (reporter, thread, root) = subject();
        let collector = Wyr1bEvidenceCollector::new(NONCE);
        assert_eq!(
            collector.bind_reporter_after_retirement(reporter, thread, root, RETIRED),
            Err(Wyr1bEvidenceError::StartupMissing)
        );

        for (facts, expected) in [
            (
                Wyr1bReporterStartFacts {
                    root_owned_by_reporter: false,
                    ..valid_start(reporter, thread, root)
                },
                Wyr1bEvidenceError::StartupRoot,
            ),
            (
                Wyr1bReporterStartFacts {
                    entry_mapping_bound: false,
                    ..valid_start(reporter, thread, root)
                },
                Wyr1bEvidenceError::StartupEntry,
            ),
            (
                Wyr1bReporterStartFacts {
                    stack_pointer: WYR1B_SYSTEM_INIT_STACK_POINTER - 16,
                    ..valid_start(reporter, thread, root)
                },
                Wyr1bEvidenceError::StartupStackPointer,
            ),
            (
                Wyr1bReporterStartFacts {
                    stack_mapping_bytes: WYR1B_SYSTEM_INIT_STACK_BYTES + 4096,
                    ..valid_start(reporter, thread, root)
                },
                Wyr1bEvidenceError::StartupStackMapping,
            ),
            (
                Wyr1bReporterStartFacts {
                    stack_mapping_rw_nx: false,
                    ..valid_start(reporter, thread, root)
                },
                Wyr1bEvidenceError::StartupStackProtection,
            ),
            (
                Wyr1bReporterStartFacts {
                    guard_absent: false,
                    ..valid_start(reporter, thread, root)
                },
                Wyr1bEvidenceError::StartupGuard,
            ),
        ] {
            let malformed = Wyr1bEvidenceCollector::new(NONCE);
            assert_eq!(malformed.observe_reporter_start(facts), Err(expected));
            assert_eq!(malformed.observe_reporter_start(facts), Err(expected));
        }

        let valid = Wyr1bEvidenceCollector::new(NONCE);
        valid
            .observe_reporter_start(valid_start(reporter, thread, root))
            .unwrap();
        assert_eq!(
            valid.observe_reporter_start(valid_start(reporter, thread, root)),
            Err(Wyr1bEvidenceError::StartupDuplicate)
        );

        let mismatched_root = Wyr1bEvidenceCollector::new(NONCE);
        mismatched_root
            .observe_reporter_start(valid_start(reporter, thread, root))
            .unwrap();
        assert_eq!(
            mismatched_root.bind_reporter_after_retirement(reporter, thread, subject().2, RETIRED),
            Err(Wyr1bEvidenceError::StartupRoot)
        );

        let mismatched_thread = Wyr1bEvidenceCollector::new(NONCE);
        mismatched_thread
            .observe_reporter_start(valid_start(reporter, thread, root))
            .unwrap();
        assert_eq!(
            mismatched_thread.bind_reporter_after_retirement(reporter, subject().1, root, RETIRED,),
            Err(Wyr1bEvidenceError::StartupRoot)
        );
    }
}
