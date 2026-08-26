//! Selector-26-only kernel evidence for one-CPU normal preemption.
//!
//! The raw submission operation, scheduler facts, and `DWPRE1` record are test
//! harness internals. None of this module is part of Deepwyrm's public ABI.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only collector")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::sync::SpinMutex;
use crate::task::{ProcessKey, SchedulerCounters, ThreadKey};

pub(crate) const DW1B_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1a;
pub(crate) const DW1B_EVIDENCE_RECORD_LEN: usize = 122;
pub(crate) const DW1B_EXCHANGE_COUNT: u64 = 8;
pub(crate) const DW1B_REQUIRED_FACTS: u32 = 0x0000_00ff;
const MAX_QUANTUM_EXPIRATIONS: u64 = 256;

const FACT_IDENTITIES_BOUND: u32 = 1 << 0;
const FACT_HOG_RUNNING: u32 = 1 << 1;
const FACT_HOG_PREEMPTED: u32 = 1 << 2;
const FACT_PROGRESS_COMPLETE: u32 = 1 << 3;
const FACT_HELLO_COMPLETE: u32 = 1 << 4;
const FACT_HOG_REAPED: u32 = 1 << 5;
const FACT_PRIMORDIAL_NORMAL: u32 = 1 << 6;
const FACT_ACCOUNTING_SOUND: u32 = 1 << 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1bRawOperation {
    Arm {
        hog_handle: u64,
        progress_handle: u64,
    },
    Progress {
        exchange_count: u64,
        digest: u64,
    },
}

impl Dw1bRawOperation {
    pub(crate) fn decode(values: [u64; 6]) -> Result<Self, Dw1bEvidenceError> {
        match values {
            [1, hog_handle, progress_handle, DW1B_EXCHANGE_COUNT, 0, 0] => Ok(Self::Arm {
                hog_handle,
                progress_handle,
            }),
            [2, exchange_count, digest, 0, 0, 0] => Ok(Self::Progress {
                exchange_count,
                digest,
            }),
            _ => Err(Dw1bEvidenceError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Dw1bSubjects {
    pub(crate) reporter_process: ProcessKey,
    pub(crate) reporter_thread: ThreadKey,
    pub(crate) hog_process: ProcessKey,
    pub(crate) hog_thread: ThreadKey,
    pub(crate) progress_process: ProcessKey,
    pub(crate) progress_thread: ThreadKey,
}

impl Dw1bSubjects {
    pub(crate) fn distinct(self) -> bool {
        self.reporter_process != self.hog_process
            && self.reporter_process != self.progress_process
            && self.hog_process != self.progress_process
            && self.reporter_thread != self.hog_thread
            && self.reporter_thread != self.progress_thread
            && self.hog_thread != self.progress_thread
    }
}

pub(crate) fn exact_single_thread<const N: usize>(
    threads: [Option<ThreadKey>; N],
) -> Option<ThreadKey> {
    let mut selected = None;
    for thread in threads.into_iter().flatten() {
        if selected.replace(thread).is_some() {
            return None;
        }
    }
    selected
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1bEvidenceError {
    Malformed,
    OutOfOrder,
    WrongReporter,
    WrongSubject,
    DuplicateReap,
    Incomplete,
    CounterRegression,
    CounterRelation,
    AccountingOverflow,
    TerminalClaimed,
}

#[derive(Clone, Copy)]
struct EvidenceState {
    subjects: Option<Dw1bSubjects>,
    baseline: SchedulerCounters,
    facts: u32,
    progress_submitted: bool,
    failure: Option<Dw1bEvidenceError>,
    complete: bool,
}

impl EvidenceState {
    const fn new() -> Self {
        Self {
            subjects: None,
            baseline: SchedulerCounters {
                current_runnable: 0,
                context_switches: 0,
                quantum_expirations: 0,
                involuntary_preemptions: 0,
                voluntary_blocks: 0,
                voluntary_yields: 0,
                wakeups: 0,
                steals_in: 0,
                steals_out: 0,
                migrations_in: 0,
                migrations_out: 0,
                idle_entries: 0,
                idle_time_ns: 0,
                longest_ready_delay_ns: 0,
                overflow_fault: false,
            },
            facts: 0,
            progress_submitted: false,
            failure: None,
            complete: false,
        }
    }

    fn latch(&mut self, error: Dw1bEvidenceError) -> Dw1bEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

pub(crate) struct Dw1bEvidenceCollector {
    state: SpinMutex<EvidenceState>,
    nonce: u64,
    expected_digest: u64,
    terminal_claimed: AtomicU8,
}

impl Dw1bEvidenceCollector {
    pub(crate) const fn new(nonce: u64, expected_digest: u64) -> Self {
        Self {
            state: SpinMutex::new(EvidenceState::new()),
            nonce,
            expected_digest,
            terminal_claimed: AtomicU8::new(0),
        }
    }

    pub(crate) fn arm(
        &self,
        subjects: Dw1bSubjects,
        baseline: SchedulerCounters,
    ) -> Result<(), Dw1bEvidenceError> {
        let mut state = self.state.lock();
        if state.subjects.is_some() || state.complete || state.progress_submitted {
            return Err(state.latch(Dw1bEvidenceError::OutOfOrder));
        }
        if !subjects.distinct() {
            return Err(state.latch(Dw1bEvidenceError::WrongSubject));
        }
        if baseline.overflow_fault {
            return Err(state.latch(Dw1bEvidenceError::AccountingOverflow));
        }
        state.subjects = Some(subjects);
        state.baseline = baseline;
        state.facts = FACT_IDENTITIES_BOUND;
        Ok(())
    }

    /// Records only a physically completed involuntary switch. The caller owns
    /// the scheduler's exact outgoing claim and the selected incoming Thread.
    pub(crate) fn observe_completed_preemption(
        &self,
        outgoing: ThreadKey,
        incoming: ThreadKey,
    ) -> Result<(), Dw1bEvidenceError> {
        let mut state = self.state.lock();
        let Some(subjects) = state.subjects else {
            return Ok(());
        };
        if outgoing != subjects.hog_thread {
            return Ok(());
        }
        if incoming == subjects.hog_thread {
            return Err(state.latch(Dw1bEvidenceError::WrongSubject));
        }
        state.facts |= FACT_HOG_RUNNING | FACT_HOG_PREEMPTED;
        Ok(())
    }

    pub(crate) fn progress(
        &self,
        reporter: ProcessKey,
        exchange_count: u64,
        digest: u64,
    ) -> Result<(), Dw1bEvidenceError> {
        let mut state = self.state.lock();
        let Some(subjects) = state.subjects else {
            return Err(state.latch(Dw1bEvidenceError::OutOfOrder));
        };
        if reporter != subjects.progress_process {
            return Err(state.latch(Dw1bEvidenceError::WrongReporter));
        }
        if state.progress_submitted || state.complete {
            return Err(state.latch(Dw1bEvidenceError::OutOfOrder));
        }
        if exchange_count != DW1B_EXCHANGE_COUNT || digest != self.expected_digest {
            return Err(state.latch(Dw1bEvidenceError::Malformed));
        }
        state.progress_submitted = true;
        state.facts |= FACT_PROGRESS_COMPLETE;
        Ok(())
    }

    pub(crate) fn observe_reaped_process(
        &self,
        process: ProcessKey,
    ) -> Result<(), Dw1bEvidenceError> {
        let mut state = self.state.lock();
        let Some(subjects) = state.subjects else {
            return Ok(());
        };
        if process != subjects.hog_process {
            return Ok(());
        }
        if state.facts & FACT_HOG_REAPED != 0 {
            return Err(state.latch(Dw1bEvidenceError::DuplicateReap));
        }
        state.facts |= FACT_HOG_REAPED;
        Ok(())
    }

    pub(crate) fn finish(
        &self,
        final_counters: SchedulerCounters,
        primordial_normal: bool,
    ) -> Result<Dw1bEvidenceFlushPermit, Dw1bEvidenceError> {
        let mut state = self.state.lock();
        if state.complete {
            return Err(state.latch(Dw1bEvidenceError::TerminalClaimed));
        }
        if let Some(error) = state.failure {
            return Err(error);
        }
        if state.subjects.is_none() || !state.progress_submitted {
            return Err(state.latch(Dw1bEvidenceError::Incomplete));
        }
        if primordial_normal {
            state.facts |= FACT_HELLO_COMPLETE | FACT_PRIMORDIAL_NORMAL;
        }
        if state.baseline.overflow_fault || final_counters.overflow_fault {
            return Err(state.latch(Dw1bEvidenceError::AccountingOverflow));
        }
        state.facts |= FACT_ACCOUNTING_SOUND;

        let quantum_expirations = delta(
            final_counters.quantum_expirations,
            state.baseline.quantum_expirations,
        )
        .ok_or_else(|| state.latch(Dw1bEvidenceError::CounterRegression))?;
        let involuntary_preemptions = delta(
            final_counters.involuntary_preemptions,
            state.baseline.involuntary_preemptions,
        )
        .ok_or_else(|| state.latch(Dw1bEvidenceError::CounterRegression))?;
        let context_switches = delta(
            final_counters.context_switches,
            state.baseline.context_switches,
        )
        .ok_or_else(|| state.latch(Dw1bEvidenceError::CounterRegression))?;
        let wakeups = delta(final_counters.wakeups, state.baseline.wakeups)
            .ok_or_else(|| state.latch(Dw1bEvidenceError::CounterRegression))?;

        if state.facts != DW1B_REQUIRED_FACTS
            || involuntary_preemptions == 0
            || involuntary_preemptions > quantum_expirations
            || quantum_expirations > MAX_QUANTUM_EXPIRATIONS
            || context_switches < involuntary_preemptions
            || wakeups < DW1B_EXCHANGE_COUNT
        {
            return Err(state.latch(Dw1bEvidenceError::CounterRelation));
        }
        self.terminal_claimed
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| state.latch(Dw1bEvidenceError::TerminalClaimed))?;
        let record = encode_record(
            self.nonce,
            quantum_expirations,
            involuntary_preemptions,
            context_switches,
            wakeups,
            state.facts,
        );
        state.complete = true;
        Ok(Dw1bEvidenceFlushPermit { record })
    }
}

const fn delta(final_value: u64, baseline: u64) -> Option<u64> {
    final_value.checked_sub(baseline)
}

#[must_use]
pub(crate) struct Dw1bEvidenceFlushPermit {
    record: [u8; DW1B_EVIDENCE_RECORD_LEN],
}

impl Dw1bEvidenceFlushPermit {
    pub(crate) const fn record(&self) -> &[u8; DW1B_EVIDENCE_RECORD_LEN] {
        &self.record
    }
}

fn encode_record(
    nonce: u64,
    quantum_expirations: u64,
    involuntary_preemptions: u64,
    context_switches: u64,
    wakeups: u64,
    facts: u32,
) -> [u8; DW1B_EVIDENCE_RECORD_LEN] {
    let mut record = [b'|'; DW1B_EVIDENCE_RECORD_LEN];
    record[0..6].copy_from_slice(b"DWPRE1");
    put_hex(&mut record[7..9], 1);
    put_hex(&mut record[10..26], nonce);
    put_hex(&mut record[27..35], 0);
    put_hex(&mut record[36..52], quantum_expirations);
    put_hex(&mut record[53..69], involuntary_preemptions);
    put_hex(&mut record[70..86], context_switches);
    put_hex(&mut record[87..103], wakeups);
    put_hex(&mut record[104..112], u64::from(facts));
    let checksum = fnv1a32(&record[..113]);
    put_hex(&mut record[113..121], u64::from(checksum));
    record[121] = b'\n';
    record
}

fn put_hex(output: &mut [u8], value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let width = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        let shift = (width - index - 1) * 4;
        *byte = HEX[((value >> shift) & 0xf) as usize];
    }
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

const fn parse_hex_u64(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() == 16,
        "selector-26 build hex must contain 16 digits"
    );
    let mut parsed = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("selector-26 build hex must be uppercase"),
        };
        parsed = (parsed << 4) | digit as u64;
        index += 1;
    }
    assert!(parsed != 0, "selector-26 build hex must be nonzero");
    parsed
}

#[cfg(deepwyrm_dw1b_evidence)]
pub(crate) static DW1B_EVIDENCE: Dw1bEvidenceCollector = Dw1bEvidenceCollector::new(
    parse_hex_u64(env!("DEEPWYRM_DW1B_EVIDENCE_NONCE")),
    parse_hex_u64(env!("DEEPWYRM_DW1B_CHALLENGE_DIGEST")),
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use crate::task::TaskAuthority;

    type Tasks = TaskAuthority<2, 3, 3, 2>;

    fn subject(
        tasks: &mut Tasks,
        registry: &mut ObjectRegistry<16>,
        root: &crate::object::InternalRef,
    ) -> (ProcessKey, ThreadKey) {
        let (process, process_handle) = tasks.create_process(registry, root).unwrap();
        let process_pin = registry
            .retain_internal_from_handle(&process_handle)
            .unwrap();
        let (thread, thread_handle) = tasks.create_thread(registry, &process_pin).unwrap();
        assert!(registry.release_internal(process_pin).unwrap().is_none());
        core::mem::forget(process_handle);
        core::mem::forget(thread_handle);
        (process, thread)
    }

    fn subjects() -> Dw1bSubjects {
        let mut registry = ObjectRegistry::<16>::new();
        let mut tasks = Tasks::new();
        let (_, root) = tasks.create_root_group(&mut registry).unwrap();
        let (reporter_process, reporter_thread) = subject(&mut tasks, &mut registry, &root);
        let (hog_process, hog_thread) = subject(&mut tasks, &mut registry, &root);
        let (progress_process, progress_thread) = subject(&mut tasks, &mut registry, &root);
        core::mem::forget(root);
        Dw1bSubjects {
            reporter_process,
            reporter_thread,
            hog_process,
            hog_thread,
            progress_process,
            progress_thread,
        }
    }

    fn final_counters() -> SchedulerCounters {
        SchedulerCounters {
            context_switches: 9,
            quantum_expirations: 3,
            involuntary_preemptions: 2,
            wakeups: 8,
            ..SchedulerCounters::default()
        }
    }

    #[test]
    fn exact_workload_and_scheduler_facts_encode_one_record() {
        let subjects = subjects();
        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        collector
            .observe_completed_preemption(subjects.hog_thread, subjects.progress_thread)
            .unwrap();
        collector.progress(subjects.progress_process, 8, 2).unwrap();
        collector
            .observe_reaped_process(subjects.hog_process)
            .unwrap();
        let permit = collector.finish(final_counters(), true).unwrap();
        let record = permit.record();
        assert_eq!(
            record,
            b"DWPRE1|01|0000000000000001|00000000|0000000000000003|0000000000000002|0000000000000009|0000000000000008|000000FF|4C376D36\n"
        );
        let checksum = core::str::from_utf8(&record[113..121]).unwrap();
        assert_eq!(
            u32::from_str_radix(checksum, 16).unwrap(),
            fnv1a32(&record[..113])
        );
    }

    #[test]
    fn repeated_exact_hog_preemptions_are_idempotent_but_self_switch_is_rejected() {
        let subjects = subjects();
        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        collector
            .observe_completed_preemption(subjects.hog_thread, subjects.progress_thread)
            .unwrap();
        collector
            .observe_completed_preemption(subjects.hog_thread, subjects.reporter_thread)
            .unwrap();

        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        assert_eq!(
            collector.observe_completed_preemption(subjects.hog_thread, subjects.hog_thread),
            Err(Dw1bEvidenceError::WrongSubject)
        );
    }

    #[test]
    fn aggregate_counters_cannot_replace_exact_hog_preemption() {
        let subjects = subjects();
        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        collector.progress(subjects.progress_process, 8, 2).unwrap();
        collector
            .observe_reaped_process(subjects.hog_process)
            .unwrap();
        assert!(matches!(
            collector.finish(final_counters(), true),
            Err(Dw1bEvidenceError::CounterRelation)
        ));
    }

    #[test]
    fn operations_are_ordered_once_only_and_reporter_bound() {
        let subjects = subjects();
        let collector = Dw1bEvidenceCollector::new(1, 2);
        assert_eq!(
            collector.progress(subjects.progress_process, 8, 2),
            Err(Dw1bEvidenceError::OutOfOrder)
        );

        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        assert_eq!(
            collector.progress(subjects.reporter_process, 8, 2),
            Err(Dw1bEvidenceError::WrongReporter)
        );
        assert_eq!(
            collector.progress(subjects.progress_process, 7, 2),
            Err(Dw1bEvidenceError::Malformed)
        );

        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        assert_eq!(
            collector.arm(subjects, SchedulerCounters::default()),
            Err(Dw1bEvidenceError::OutOfOrder)
        );

        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        collector.progress(subjects.progress_process, 8, 2).unwrap();
        assert_eq!(
            collector.progress(subjects.progress_process, 8, 2),
            Err(Dw1bEvidenceError::OutOfOrder)
        );
        collector
            .observe_reaped_process(subjects.hog_process)
            .unwrap();
        assert_eq!(
            collector.observe_reaped_process(subjects.hog_process),
            Err(Dw1bEvidenceError::DuplicateReap)
        );
    }

    #[test]
    fn bounded_counter_relations_are_enforced() {
        let subjects = subjects();
        let collector = Dw1bEvidenceCollector::new(1, 2);
        collector
            .arm(subjects, SchedulerCounters::default())
            .unwrap();
        collector
            .observe_completed_preemption(subjects.hog_thread, subjects.progress_thread)
            .unwrap();
        collector.progress(subjects.progress_process, 8, 2).unwrap();
        collector
            .observe_reaped_process(subjects.hog_process)
            .unwrap();
        let mut counters = final_counters();
        counters.quantum_expirations = 257;
        assert!(matches!(
            collector.finish(counters, true),
            Err(Dw1bEvidenceError::CounterRelation)
        ));
    }

    #[test]
    fn counter_regression_overflow_and_false_completion_are_rejected() {
        fn prepared(subjects: Dw1bSubjects) -> Dw1bEvidenceCollector {
            let collector = Dw1bEvidenceCollector::new(1, 2);
            let baseline = SchedulerCounters {
                context_switches: 10,
                quantum_expirations: 10,
                involuntary_preemptions: 10,
                wakeups: 10,
                ..SchedulerCounters::default()
            };
            collector.arm(subjects, baseline).unwrap();
            collector
                .observe_completed_preemption(subjects.hog_thread, subjects.progress_thread)
                .unwrap();
            collector.progress(subjects.progress_process, 8, 2).unwrap();
            collector
                .observe_reaped_process(subjects.hog_process)
                .unwrap();
            collector
        }

        let subjects = subjects();
        assert!(matches!(
            prepared(subjects).finish(SchedulerCounters::default(), true),
            Err(Dw1bEvidenceError::CounterRegression)
        ));
        let mut overflow = SchedulerCounters::default();
        overflow.overflow_fault = true;
        assert!(matches!(
            prepared(subjects).finish(overflow, true),
            Err(Dw1bEvidenceError::AccountingOverflow)
        ));
        let final_counters = SchedulerCounters {
            context_switches: 19,
            quantum_expirations: 13,
            involuntary_preemptions: 12,
            wakeups: 18,
            ..SchedulerCounters::default()
        };
        assert!(matches!(
            prepared(subjects).finish(final_counters, false),
            Err(Dw1bEvidenceError::CounterRelation)
        ));
    }

    #[test]
    fn raw_operation_shapes_reject_every_unowned_argument() {
        assert_eq!(
            Dw1bRawOperation::decode([1, 10, 11, 8, 0, 0]),
            Ok(Dw1bRawOperation::Arm {
                hog_handle: 10,
                progress_handle: 11,
            })
        );
        assert_eq!(
            Dw1bRawOperation::decode([2, 8, 0x1234, 0, 0, 0]),
            Ok(Dw1bRawOperation::Progress {
                exchange_count: 8,
                digest: 0x1234,
            })
        );
        for malformed in [
            [0, 10, 11, 8, 0, 0],
            [1, 10, 11, 7, 0, 0],
            [1, 10, 11, 8, 1, 0],
            [1, 10, 11, 8, 0, 1],
            [2, 8, 0x1234, 1, 0, 0],
            [2, 8, 0x1234, 0, 1, 0],
            [2, 8, 0x1234, 0, 0, 1],
        ] {
            assert_eq!(
                Dw1bRawOperation::decode(malformed),
                Err(Dw1bEvidenceError::Malformed)
            );
        }
    }

    #[test]
    fn subject_thread_cardinality_is_exactly_one() {
        let subjects = subjects();
        assert_eq!(
            exact_single_thread([Some(subjects.hog_thread), None]),
            Some(subjects.hog_thread)
        );
        assert_eq!(exact_single_thread([None, None]), None);
        assert_eq!(
            exact_single_thread([Some(subjects.hog_thread), Some(subjects.progress_thread)]),
            None
        );
    }
}
