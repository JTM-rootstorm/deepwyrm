use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) use crate::cpu::CpuIndex as SchedulerCpuId;
use crate::sync::IrqSpinMutex;

use super::ThreadKey;

#[path = "scheduler/carrier_admission.rs"]
mod carrier_admission;
use carrier_admission::CarrierAdmissionState;
pub(crate) use carrier_admission::{
    CarrierAdmissionError, CarrierAdmissionLifecycle, CarrierAdmissionSnapshot,
    CarrierAdmissionTicket, CarrierDeadlineState, CarrierResourceTuple, CarrierRuntimeState,
};

static NEXT_SCHEDULER_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// DW0-H's bounded logical scheduler-CPU namespace.
///
/// This is an internal ownership identity, not a userspace ABI value.  The
/// canonical SMP profile has exactly four CPUs, so accepting a fifth owner is
/// an explicit error rather than silently aliasing or dropping it.
pub(crate) const H2_SCHEDULER_CPU_CAPACITY: usize = crate::cpu::CPU_CAPACITY;

fn mint_scheduler_domain() -> u64 {
    NEXT_SCHEDULER_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .expect("scheduler domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerError {
    Capacity,
    DuplicateThread,
    ForeignReservation,
    StaleReservation,
    ForeignBlockToken,
    StaleBlockToken,
    CurrentThreadRunning,
    NotScheduled,
    NotRunning,
    WrongCpu,
    ForeignExecutionClaim,
    StaleExecutionClaim,
    TokenExhausted,
    BlockPreparationActive,
    SwitchPending,
    ContinuationOwned,
    AccountingOverflow,
    AccountingUnderflow,
    TimeRegression,
    IdleAccountingActive,
    CarrierUnavailable,
    StaleIdleAccounting,
    QuantumUnavailable,
    StaleQuantum,
    PreemptionDisabled,
    PreemptionDepthOverflow,
    PreemptionDepthUnderflow,
}

/// Fixed DW1 normal-class quantum. This is internal policy, not ABI.
pub(crate) const DEFAULT_NORMAL_QUANTUM_NS: u64 = 5_000_000;

/// Exact identity of one CPU-local scheduler deadline source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerQuantumTicket {
    domain: u64,
    cpu: SchedulerCpuId,
    thread: ThreadKey,
    execution_generation: u64,
    source_arm_generation: u64,
    deadline_ns: u64,
}

impl SchedulerQuantumTicket {
    pub(crate) const fn cpu(self) -> SchedulerCpuId {
        self.cpu
    }

    pub(crate) const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub(crate) const fn execution_generation(self) -> u64 {
        self.execution_generation
    }

    pub(crate) const fn source_arm_generation(self) -> u64 {
        self.source_arm_generation
    }

    pub(crate) const fn deadline_ns(self) -> u64 {
        self.deadline_ns
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerPreemptionDecision {
    /// The exact request remains pending until the checked depth reaches zero.
    Deferred,
    /// The request was consumed, but no eligible local peer existed.
    RetainCurrent,
    /// The outgoing continuation must be saved before the decision completes.
    Switch {
        decision: ScheduleDecision,
        outgoing: SchedulerExecutionClaim,
    },
}

/// Exact internal snapshot consumed by selector-26 evidence integration after
/// its cross-repository wire is frozen. This is kernel-private and not ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerPreemptionSnapshot {
    pub(crate) running: Option<SchedulerExecutionClaim>,
    pub(crate) quantum: Option<SchedulerQuantumTicket>,
    pub(crate) request: Option<SchedulerQuantumTicket>,
    pub(crate) preemption_disable_depth: u32,
    pub(crate) counters: SchedulerCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerThreadState {
    Reserved,
    Runnable,
    Running,
    Blocked,
}

/// Exact ownership of one nonzero Thread execution claim on one CPU.
///
/// The generation changes each time Runnable work is claimed. H2-D can carry
/// this opaque key through a stop request/acknowledgement without confusing a
/// later execution of the same Thread on the same CPU for the original claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerExecutionClaim {
    domain: u64,
    cpu: SchedulerCpuId,
    thread: ThreadKey,
    generation: u64,
}

impl SchedulerExecutionClaim {
    pub(crate) const fn cpu(self) -> SchedulerCpuId {
        self.cpu
    }

    pub(crate) const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockWakeKey {
    domain: u64,
    token: u64,
    thread: ThreadKey,
    cpu: SchedulerCpuId,
    execution_generation: u64,
}

impl BlockWakeKey {
    pub(crate) const fn token(self) -> u64 {
        self.token
    }

    pub(crate) const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub(crate) const fn execution_generation(self) -> u64 {
        self.execution_generation
    }
}

#[must_use = "prepared block ownership must be committed only after wait/deadline registration or explicitly cancelled"]
#[derive(Debug)]
pub(crate) struct BlockReservation {
    key: BlockWakeKey,
}

impl BlockReservation {
    pub(crate) const fn wake_key(&self) -> BlockWakeKey {
        self.key
    }
}

#[derive(Debug)]
pub(crate) struct BlockReservationFailure {
    error: SchedulerError,
    reservation: BlockReservation,
}

impl BlockReservationFailure {
    pub(crate) const fn error(&self) -> SchedulerError {
        self.error
    }

    pub(crate) fn into_reservation(self) -> BlockReservation {
        self.reservation
    }
}

#[must_use = "blocked scheduler ownership must be transferred to a waiter registration or explicitly woken"]
#[derive(Debug)]
pub(crate) struct BlockToken {
    key: BlockWakeKey,
}

impl BlockToken {
    pub(crate) const fn wake_key(&self) -> BlockWakeKey {
        self.key
    }

    pub(crate) const fn into_wake_key(self) -> BlockWakeKey {
        self.key
    }
}

#[must_use = "scheduler reservations must be committed or cancelled"]
#[derive(Debug)]
pub(crate) struct SchedulerReservation {
    domain: u64,
    token: u64,
    thread: ThreadKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleDecision {
    pub(crate) previous: Option<ThreadKey>,
    pub(crate) current: Option<ThreadKey>,
    pub(crate) cancelled_quantum: Option<SchedulerQuantumTicket>,
}

/// Scheduler-authoritative ownership published before an architecture wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RunnablePublication {
    target: SchedulerCpuId,
    continuation_bound: bool,
}

/// Exact successful blocked-to-Runnable wake publication. The wake generation
/// is scheduler-owned and advances only with this committed transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerWakePublication {
    runnable: RunnablePublication,
    source: SchedulerCpuId,
    generation: u64,
}

impl SchedulerWakePublication {
    pub(crate) const fn target(self) -> SchedulerCpuId {
        self.runnable.target()
    }

    pub(crate) const fn source(self) -> SchedulerCpuId {
        self.source
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn wake_affinity(self) -> Option<SchedulerCpuId> {
        self.runnable.wake_affinity()
    }
}

/// Exact successful continuation-release commit returned after scheduler
/// authority has been dropped. Selector-private evidence consumes the
/// generation only outside the scheduler lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerCompletedSwitch {
    runnable_publication: Option<RunnablePublication>,
    generation: u64,
    involuntary_preemption: bool,
}

impl SchedulerCompletedSwitch {
    pub(crate) const fn runnable_publication(self) -> Option<RunnablePublication> {
        self.runnable_publication
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn involuntary_preemption(self) -> bool {
        self.involuntary_preemption
    }
}

/// Exact identity of the most recently committed idle-steal migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerMigrationRecord {
    pub(crate) thread: ThreadKey,
    pub(crate) execution_generation: u64,
    pub(crate) source: SchedulerCpuId,
    pub(crate) target: SchedulerCpuId,
    pub(crate) generation: u64,
    pub(crate) enqueue_generation: u64,
}

/// A migration has changed queue placement but has not yet crossed the
/// fallible dispatch-accounting/claim boundary.  Keeping the exact prior
/// values makes an idle steal one transaction rather than a visible partial
/// scheduler mutation.
#[derive(Clone, Copy)]
struct PendingMigration {
    record: SchedulerMigrationRecord,
    index: usize,
    prior_entry: QueueEntry,
    prior_accounting: SchedulerAccounting,
    prior_last_migration: Option<SchedulerMigrationRecord>,
    prior_next_generation: u64,
}

/// Scheduler dispatch result that carries an exact committed migration to the
/// execution facade without enlarging the common scheduling decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerDispatch {
    decision: ScheduleDecision,
    migration: Option<SchedulerMigrationRecord>,
}

impl SchedulerDispatch {
    pub(crate) const fn decision(self) -> ScheduleDecision {
        self.decision
    }

    pub(crate) const fn migration(self) -> Option<SchedulerMigrationRecord> {
        self.migration
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerIdleDispatch {
    decision: IdleScheduleDecision,
    migration: Option<SchedulerMigrationRecord>,
}

impl SchedulerIdleDispatch {
    pub(crate) const fn decision(self) -> IdleScheduleDecision {
        self.decision
    }

    pub(crate) const fn migration(self) -> Option<SchedulerMigrationRecord> {
        self.migration
    }
}

/// Selector-private migration exclusions use the same fixed reason ordering
/// as the DW1-A contract. They are absent from ordinary production kernels.
#[cfg(any(test, deepwyrm_dw1c_evidence))]
#[allow(
    dead_code,
    reason = "the fixed rejection code set is validated across phased selector fixtures"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SchedulerMigrationRejectionReason {
    Running = 0x01,
    BlockPreparing = 0x02,
    ContinuationBound = 0x03,
    ExecutionPinned = 0x04,
    ScratchPinned = 0x05,
    RootSwitching = 0x06,
    StopPending = 0x07,
    RendezvousPending = 0x08,
    Terminal = 0x09,
    NotRevalidatable = 0x0a,
}

#[cfg(any(test, deepwyrm_dw1c_evidence))]
impl SchedulerMigrationRejectionReason {
    pub(crate) const fn code(self) -> u8 {
        self as u8
    }
}

#[cfg(any(test, deepwyrm_dw1c_evidence))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerMigrationRejection {
    pub(crate) thread: ThreadKey,
    pub(crate) execution_generation: u64,
    pub(crate) cpu: SchedulerCpuId,
    pub(crate) reason: SchedulerMigrationRejectionReason,
}

impl RunnablePublication {
    pub(crate) const fn target(self) -> SchedulerCpuId {
        self.target
    }

    pub(crate) const fn wake_affinity(self) -> Option<SchedulerCpuId> {
        if self.continuation_bound {
            Some(self.target)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdleScheduleDecision {
    ContinueIdle,
    ResumeCurrent,
    Switch(ScheduleDecision),
}

#[derive(Debug)]
pub(crate) struct SchedulerReservationFailure {
    error: SchedulerError,
    reservation: SchedulerReservation,
}

impl SchedulerReservationFailure {
    pub(crate) const fn error(&self) -> SchedulerError {
        self.error
    }

    pub(crate) fn into_reservation(self) -> SchedulerReservation {
        self.reservation
    }
}

#[derive(Clone, Copy)]
struct QueueEntry {
    thread: ThreadKey,
    state: SchedulerThreadState,
    token: u64,
    started_execution_generation: u64,
    block_cpu: Option<SchedulerCpuId>,
    block_execution_generation: u64,
    continuation_cpu: Option<SchedulerCpuId>,
    continuation_generation: u64,
    target_cpu: SchedulerCpuId,
    last_cpu: Option<SchedulerCpuId>,
    eligibility_mask: u64,
    enqueue_generation: u64,
    migration_generation: u64,
    migration_eligibility_generation: u64,
    #[cfg(any(test, deepwyrm_dw1c_evidence))]
    migration_exclusion: Option<SchedulerMigrationRejectionReason>,
    ready_at_ns: Option<u64>,
}

const SCHEDULER_TRACE_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerTraceKind {
    Runnable,
    Dispatch,
    Yield,
    Block,
    Wake,
    Retire,
    RemoteStop,
    IdleBegin,
    IdleEnd,
    QuantumArm,
    QuantumExpire,
    Preempt,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerTraceRecord {
    pub(crate) kind: SchedulerTraceKind,
    pub(crate) cpu: SchedulerCpuId,
    pub(crate) thread: Option<ThreadKey>,
    pub(crate) generation: u64,
    pub(crate) at_ns: u64,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct SchedulerTrace {
    records: [Option<SchedulerTraceRecord>; SCHEDULER_TRACE_CAPACITY],
    next: usize,
    len: usize,
}

#[cfg(test)]
impl SchedulerTrace {
    const fn new() -> Self {
        Self {
            records: [None; SCHEDULER_TRACE_CAPACITY],
            next: 0,
            len: 0,
        }
    }

    fn push(&mut self, record: SchedulerTraceRecord) {
        debug_assert_ne!(record.generation, 0);
        self.records[self.next] = Some(record);
        self.next = (self.next + 1) % SCHEDULER_TRACE_CAPACITY;
        self.len = self.len.saturating_add(1).min(SCHEDULER_TRACE_CAPACITY);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerIdleAccountingToken {
    domain: u64,
    cpu: SchedulerCpuId,
    generation: u64,
    started_at_ns: u64,
}

/// Bounded internal DW1-A telemetry for one logical CPU.
///
/// `current_runnable` counts entries owned by this CPU's logical FIFO. Steal
/// and migration counters advance together for the single C3 idle-migration
/// transition; all fields remain checked and fail-stop on overflow.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SchedulerCounters {
    pub(crate) current_runnable: u64,
    pub(crate) context_switches: u64,
    pub(crate) quantum_expirations: u64,
    pub(crate) involuntary_preemptions: u64,
    pub(crate) voluntary_blocks: u64,
    pub(crate) voluntary_yields: u64,
    pub(crate) wakeups: u64,
    pub(crate) steals_in: u64,
    pub(crate) steals_out: u64,
    pub(crate) migrations_in: u64,
    pub(crate) migrations_out: u64,
    pub(crate) idle_entries: u64,
    pub(crate) idle_time_ns: u64,
    pub(crate) longest_ready_delay_ns: u64,
    pub(crate) overflow_fault: bool,
}

#[derive(Clone, Copy)]
enum SchedulerEvent {
    ContextSwitch,
    VoluntaryBlock,
    VoluntaryYield,
    Wakeup,
    IdleEntry,
    QuantumExpiration,
    InvoluntaryPreemption,
    StealIn,
    StealOut,
    MigrationIn,
    MigrationOut,
}

impl SchedulerCounters {
    fn increment(&mut self, event: SchedulerEvent) -> Result<(), SchedulerError> {
        let counter = match event {
            SchedulerEvent::ContextSwitch => &mut self.context_switches,
            SchedulerEvent::VoluntaryBlock => &mut self.voluntary_blocks,
            SchedulerEvent::VoluntaryYield => &mut self.voluntary_yields,
            SchedulerEvent::Wakeup => &mut self.wakeups,
            SchedulerEvent::IdleEntry => &mut self.idle_entries,
            SchedulerEvent::QuantumExpiration => &mut self.quantum_expirations,
            SchedulerEvent::InvoluntaryPreemption => &mut self.involuntary_preemptions,
            SchedulerEvent::StealIn => &mut self.steals_in,
            SchedulerEvent::StealOut => &mut self.steals_out,
            SchedulerEvent::MigrationIn => &mut self.migrations_in,
            SchedulerEvent::MigrationOut => &mut self.migrations_out,
        };
        let Some(next) = counter.checked_add(1) else {
            self.overflow_fault = true;
            return Err(SchedulerError::AccountingOverflow);
        };
        *counter = next;
        Ok(())
    }

    fn increment_runnable(&mut self) -> Result<(), SchedulerError> {
        let Some(next) = self.current_runnable.checked_add(1) else {
            self.overflow_fault = true;
            return Err(SchedulerError::AccountingOverflow);
        };
        self.current_runnable = next;
        Ok(())
    }

    fn decrement_runnable(&mut self) -> Result<(), SchedulerError> {
        let Some(next) = self.current_runnable.checked_sub(1) else {
            return Err(SchedulerError::AccountingUnderflow);
        };
        self.current_runnable = next;
        Ok(())
    }

    fn record_idle_time(&mut self, elapsed_ns: u64) -> Result<(), SchedulerError> {
        let Some(next) = self.idle_time_ns.checked_add(elapsed_ns) else {
            self.overflow_fault = true;
            return Err(SchedulerError::AccountingOverflow);
        };
        self.idle_time_ns = next;
        Ok(())
    }

    fn observe_ready_delay(
        &mut self,
        ready_at_ns: u64,
        dispatch_at_ns: u64,
    ) -> Result<(), SchedulerError> {
        let delay = dispatch_at_ns
            .checked_sub(ready_at_ns)
            .ok_or(SchedulerError::TimeRegression)?;
        self.longest_ready_delay_ns = self.longest_ready_delay_ns.max(delay);
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct SchedulerAccounting {
    cpu: [SchedulerCounters; H2_SCHEDULER_CPU_CAPACITY],
}

impl SchedulerAccounting {
    fn counters_mut(&mut self, cpu: SchedulerCpuId) -> &mut SchedulerCounters {
        &mut self.cpu[cpu.index()]
    }

    fn increment(
        &mut self,
        cpu: SchedulerCpuId,
        event: SchedulerEvent,
    ) -> Result<(), SchedulerError> {
        self.counters_mut(cpu).increment(event)
    }

    fn increment_runnable(&mut self, cpu: SchedulerCpuId) -> Result<(), SchedulerError> {
        self.counters_mut(cpu).increment_runnable()
    }

    fn decrement_runnable(&mut self, cpu: SchedulerCpuId) -> Result<(), SchedulerError> {
        self.counters_mut(cpu).decrement_runnable()
    }

    fn observe_ready_delay(
        &mut self,
        dispatch_cpu: SchedulerCpuId,
        ready_at_ns: Option<u64>,
        dispatch_at_ns: Option<u64>,
    ) -> Result<(), SchedulerError> {
        match (ready_at_ns, dispatch_at_ns) {
            (Some(ready_at_ns), Some(dispatch_at_ns)) => self
                .counters_mut(dispatch_cpu)
                .observe_ready_delay(ready_at_ns, dispatch_at_ns),
            _ => Ok(()),
        }
    }

    fn retain_faults_from(&mut self, attempted: Self) {
        for (current, attempted) in self.cpu.iter_mut().zip(attempted.cpu) {
            current.overflow_fault |= attempted.overflow_fault;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RunningClaim {
    thread: ThreadKey,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuspendedPublication {
    Queued,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SuspendedContinuation {
    thread: ThreadKey,
    generation: u64,
    publication: SuspendedPublication,
    involuntary_preemption: bool,
}

struct SchedulerState<const CAPACITY: usize> {
    domain: u64,
    next_token: u64,
    next_execution_generation: u64,
    next_enqueue_generation: u64,
    next_migration_generation: u64,
    next_migration_eligibility_generation: u64,
    next_idle_generation: u64,
    next_wake_generation: u64,
    next_completed_switch_generation: u64,
    next_quantum_generation: [u64; H2_SCHEDULER_CPU_CAPACITY],
    queue: [Option<QueueEntry>; CAPACITY],
    len: usize,
    running: [Option<RunningClaim>; H2_SCHEDULER_CPU_CAPACITY],
    pending_block: [Option<BlockWakeKey>; H2_SCHEDULER_CPU_CAPACITY],
    suspended: [Option<SuspendedContinuation>; H2_SCHEDULER_CPU_CAPACITY],
    accounting: SchedulerAccounting,
    active_idle: [Option<SchedulerIdleAccountingToken>; H2_SCHEDULER_CPU_CAPACITY],
    instrumentation_now_ns: [Option<u64>; H2_SCHEDULER_CPU_CAPACITY],
    instrumentation_global_now_ns: Option<u64>,
    quantum: [Option<SchedulerQuantumTicket>; H2_SCHEDULER_CPU_CAPACITY],
    need_resched: [Option<SchedulerQuantumTicket>; H2_SCHEDULER_CPU_CAPACITY],
    preemption_disable_depth: [u32; H2_SCHEDULER_CPU_CAPACITY],
    last_migration: Option<SchedulerMigrationRecord>,
    carrier_admission: CarrierAdmissionState,
    #[cfg(test)]
    trace: SchedulerTrace,
}

impl<const CAPACITY: usize> SchedulerState<CAPACITY> {
    fn new() -> Self {
        Self {
            domain: mint_scheduler_domain(),
            next_token: 1,
            next_execution_generation: 1,
            next_enqueue_generation: 1,
            next_migration_generation: 1,
            next_migration_eligibility_generation: 1,
            next_idle_generation: 1,
            next_wake_generation: 1,
            next_completed_switch_generation: 1,
            next_quantum_generation: [1; H2_SCHEDULER_CPU_CAPACITY],
            queue: [None; CAPACITY],
            len: 0,
            running: [None; H2_SCHEDULER_CPU_CAPACITY],
            pending_block: [None; H2_SCHEDULER_CPU_CAPACITY],
            suspended: [None; H2_SCHEDULER_CPU_CAPACITY],
            accounting: SchedulerAccounting::default(),
            active_idle: [None; H2_SCHEDULER_CPU_CAPACITY],
            instrumentation_now_ns: [None; H2_SCHEDULER_CPU_CAPACITY],
            instrumentation_global_now_ns: None,
            quantum: [None; H2_SCHEDULER_CPU_CAPACITY],
            need_resched: [None; H2_SCHEDULER_CPU_CAPACITY],
            preemption_disable_depth: [0; H2_SCHEDULER_CPU_CAPACITY],
            last_migration: None,
            carrier_admission: CarrierAdmissionState::new(),
            #[cfg(test)]
            trace: SchedulerTrace::new(),
        }
    }

    fn contains(&self, thread: ThreadKey) -> bool {
        self.running
            .iter()
            .flatten()
            .any(|claim| claim.thread == thread)
            || self.queue[..self.len]
                .iter()
                .flatten()
                .any(|entry| entry.thread == thread)
    }

    fn reject_accounting(&mut self, attempted: SchedulerAccounting, error: SchedulerError) {
        match error {
            SchedulerError::AccountingOverflow | SchedulerError::AccountingUnderflow => {
                self.accounting.retain_faults_from(attempted);
            }
            SchedulerError::TimeRegression => {}
            _ => panic!("unexpected scheduler telemetry rejection: {error:?}"),
        }
        #[cfg(not(test))]
        panic!("scheduler accounting invariant failed: {error:?}");
    }

    fn assert_invariants(&self) {
        if let Err(error) = self.check_invariants() {
            panic!("scheduler invariant failed: {error:?}");
        }
    }

    fn record_trace(
        &mut self,
        kind: SchedulerTraceKind,
        cpu: SchedulerCpuId,
        thread: Option<ThreadKey>,
        generation: u64,
    ) {
        #[cfg(test)]
        {
            if let Some(at_ns) = self.instrumentation_now_ns[cpu.index()] {
                self.trace.push(SchedulerTraceRecord {
                    kind,
                    cpu,
                    thread,
                    generation,
                    at_ns,
                });
            }
        }
        #[cfg(not(test))]
        let _ = (kind, cpu, thread, generation);
    }

    fn execution_generation_available(&self) -> bool {
        self.next_execution_generation
            .checked_add(1)
            .is_some_and(|next| next != 0)
    }

    fn push(&mut self, entry: QueueEntry) -> Result<(), SchedulerError> {
        if self.len == CAPACITY {
            return Err(SchedulerError::Capacity);
        }
        if self.queue[..self.len]
            .iter()
            .flatten()
            .any(|queued| queued.thread == entry.thread)
        {
            return Err(SchedulerError::DuplicateThread);
        }
        self.queue[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    fn remove_index(&mut self, index: usize) -> QueueEntry {
        debug_assert!(index < self.len);
        let removed = self.queue[index]
            .take()
            .expect("scheduler removal index is occupied");
        for current in index..self.len.saturating_sub(1) {
            self.queue[current] = self.queue[current + 1].take();
        }
        self.len -= 1;
        self.queue[self.len] = None;
        removed
    }

    fn schedulable_mask(&self) -> u64 {
        if self.carrier_admission.enforced {
            self.carrier_admission.schedulable_mask
        } else {
            (1_u64 << H2_SCHEDULER_CPU_CAPACITY) - 1
        }
    }

    fn cpu_admissible(&self, cpu: SchedulerCpuId, eligibility_mask: u64) -> bool {
        let bit = 1_u64 << cpu.index();
        self.schedulable_mask() & eligibility_mask & bit != 0
    }

    fn select_placement(
        &self,
        entry: QueueEntry,
        requester: SchedulerCpuId,
    ) -> Option<SchedulerCpuId> {
        if let Some(continuation_cpu) = entry.continuation_cpu {
            return self
                .cpu_admissible(continuation_cpu, entry.eligibility_mask)
                .then_some(continuation_cpu);
        }
        entry
            .last_cpu
            .filter(|cpu| self.cpu_admissible(*cpu, entry.eligibility_mask))
            .or_else(|| {
                self.cpu_admissible(requester, entry.eligibility_mask)
                    .then_some(requester)
            })
            .or_else(|| {
                (0..H2_SCHEDULER_CPU_CAPACITY)
                    .filter_map(SchedulerCpuId::new)
                    .find(|cpu| self.cpu_admissible(*cpu, entry.eligibility_mask))
            })
    }

    fn first_local_runnable_index(&self, cpu: SchedulerCpuId) -> Option<usize> {
        self.queue[..self.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && entry.continuation_cpu.is_none()
            })
        })
    }

    /// Revalidates every migration exclusion represented by scheduler state.
    /// Root/scratch execution pins and rendezvous ownership are confined to a
    /// Running or suspended generation, so the exact disjointness checks here
    /// reject those states without acquiring their separate authorities.
    fn entry_migratable(
        &self,
        entry: QueueEntry,
        victim: SchedulerCpuId,
        target: SchedulerCpuId,
    ) -> bool {
        self.entry_migratable_without_external_exclusion(entry, victim, target) && {
            #[cfg(any(test, deepwyrm_dw1c_evidence))]
            {
                entry.migration_exclusion.is_none()
            }
            #[cfg(not(any(test, deepwyrm_dw1c_evidence)))]
            {
                true
            }
        }
    }

    fn entry_migratable_without_external_exclusion(
        &self,
        entry: QueueEntry,
        victim: SchedulerCpuId,
        target: SchedulerCpuId,
    ) -> bool {
        entry.state == SchedulerThreadState::Runnable
            && entry.target_cpu == victim
            && entry.token == 0
            && entry.block_cpu.is_none()
            && entry.block_execution_generation == 0
            && entry.continuation_cpu.is_none()
            && entry.continuation_generation == 0
            && entry.migration_eligibility_generation != 0
            && self.cpu_admissible(target, entry.eligibility_mask)
            && !self
                .running
                .iter()
                .flatten()
                .any(|claim| claim.thread == entry.thread)
            && !self
                .pending_block
                .iter()
                .flatten()
                .any(|pending| pending.thread == entry.thread)
            && !self
                .suspended
                .iter()
                .flatten()
                .any(|suspended| suspended.thread == entry.thread)
    }

    fn claim_first_runnable_on(
        &mut self,
        cpu: SchedulerCpuId,
    ) -> Result<Option<RunningClaim>, SchedulerError> {
        let Some(index) = self.first_local_runnable_index(cpu) else {
            return Ok(None);
        };
        let entry = self.remove_index(index);
        let generation = if entry.started_execution_generation != 0 {
            entry.started_execution_generation
        } else {
            self.mint_execution_generation()?
        };
        Ok(Some(RunningClaim {
            thread: entry.thread,
            generation,
        }))
    }

    fn claim_first_runnable_for_idle(
        &mut self,
        cpu: SchedulerCpuId,
        suspended: SuspendedContinuation,
    ) -> Result<Option<RunningClaim>, SchedulerError> {
        let Some(index) = self.queue[..self.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && (entry.continuation_cpu.is_none() || entry.continuation_cpu == Some(cpu))
            })
        }) else {
            return Ok(None);
        };
        let entry = self.queue[index].expect("runnable claim index is occupied");
        let generation = if entry.continuation_cpu == Some(cpu) {
            if entry.thread != suspended.thread
                || entry.continuation_generation != suspended.generation
            {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            suspended.generation
        } else if entry.started_execution_generation != 0 {
            entry.started_execution_generation
        } else {
            self.mint_execution_generation()?
        };
        let entry = self.remove_index(index);
        Ok(Some(RunningClaim {
            thread: entry.thread,
            generation,
        }))
    }

    fn steal_oldest_for(
        &mut self,
        target: SchedulerCpuId,
    ) -> Result<Option<PendingMigration>, SchedulerError> {
        let mask = self.schedulable_mask();
        for offset in 1..H2_SCHEDULER_CPU_CAPACITY {
            let victim_index = (target.index() + offset) % H2_SCHEDULER_CPU_CAPACITY;
            if mask & (1_u64 << victim_index) == 0 {
                continue;
            }
            let victim = SchedulerCpuId::new(victim_index).expect("bounded scheduler CPU index");
            let Some(index) = self.queue[..self.len].iter().position(|entry| {
                entry.is_some_and(|entry| self.entry_migratable(entry, victim, target))
            }) else {
                continue;
            };

            let generation = self.next_migration_generation;
            let next_generation = generation
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(SchedulerError::TokenExhausted)?;
            let mut accounting = self.accounting;
            let result = accounting
                .decrement_runnable(victim)
                .and_then(|()| accounting.increment_runnable(target))
                .and_then(|()| accounting.increment(victim, SchedulerEvent::StealOut))
                .and_then(|()| accounting.increment(target, SchedulerEvent::StealIn))
                .and_then(|()| accounting.increment(victim, SchedulerEvent::MigrationOut))
                .and_then(|()| accounting.increment(target, SchedulerEvent::MigrationIn));
            if let Err(error) = result {
                self.reject_accounting(accounting, error);
                return Err(error);
            }
            let prior_entry = self.queue[index].expect("validated migration source remains queued");
            let entry = self.queue[index]
                .as_mut()
                .expect("validated migration source remains queued");
            entry.target_cpu = target;
            entry.migration_generation = generation;
            let migration = SchedulerMigrationRecord {
                thread: entry.thread,
                execution_generation: entry.started_execution_generation,
                source: victim,
                target,
                generation,
                enqueue_generation: entry.enqueue_generation,
            };
            let pending = PendingMigration {
                record: migration,
                index,
                prior_entry,
                prior_accounting: self.accounting,
                prior_last_migration: self.last_migration,
                prior_next_generation: self.next_migration_generation,
            };
            self.last_migration = Some(migration);
            self.next_migration_generation = next_generation;
            self.accounting = accounting;
            return Ok(Some(pending));
        }
        Ok(None)
    }

    fn rollback_pending_migration(&mut self, pending: PendingMigration) {
        let current =
            self.queue[pending.index].expect("post-steal rollback retains its queued candidate");
        assert_eq!(current.thread, pending.record.thread);
        assert_eq!(current.target_cpu, pending.record.target);
        assert_eq!(current.migration_generation, pending.record.generation);
        self.queue[pending.index] = Some(pending.prior_entry);
        self.accounting = pending.prior_accounting;
        self.last_migration = pending.prior_last_migration;
        self.next_migration_generation = pending.prior_next_generation;
    }

    fn running_cpu(&self, thread: ThreadKey) -> Option<SchedulerCpuId> {
        self.running
            .iter()
            .position(|current| current.is_some_and(|claim| claim.thread == thread))
            .and_then(SchedulerCpuId::new)
    }

    fn mint_execution_generation(&mut self) -> Result<u64, SchedulerError> {
        let generation = self.next_execution_generation;
        self.next_execution_generation = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        Ok(generation)
    }

    fn mint_migration_eligibility_generation(&mut self) -> Result<u64, SchedulerError> {
        let generation = self.next_migration_eligibility_generation;
        self.next_migration_eligibility_generation = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        Ok(generation)
    }

    fn checked_completed_switch_generation(&self) -> Result<(u64, u64), SchedulerError> {
        let generation = self.next_completed_switch_generation;
        if generation == 0 {
            return Err(SchedulerError::TokenExhausted);
        }
        let next = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        Ok((generation, next))
    }

    fn checked_wake_generation(&self) -> Result<(u64, u64), SchedulerError> {
        let generation = self.next_wake_generation;
        if generation == 0 {
            return Err(SchedulerError::TokenExhausted);
        }
        let next = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        Ok((generation, next))
    }

    fn clear_preemption_on(&mut self, cpu: SchedulerCpuId) -> Option<SchedulerQuantumTicket> {
        let cancelled = self.quantum[cpu.index()].take();
        self.need_resched[cpu.index()] = None;
        cancelled
    }

    fn mint_quantum_on(
        &mut self,
        cpu: SchedulerCpuId,
        claim: RunningClaim,
        now_ns: u64,
    ) -> Result<SchedulerQuantumTicket, SchedulerError> {
        let deadline_ns = now_ns
            .checked_add(DEFAULT_NORMAL_QUANTUM_NS)
            .ok_or(SchedulerError::TokenExhausted)?;
        let source_arm_generation = self.next_quantum_generation[cpu.index()];
        self.next_quantum_generation[cpu.index()] = source_arm_generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let ticket = SchedulerQuantumTicket {
            domain: self.domain,
            cpu,
            thread: claim.thread,
            execution_generation: claim.generation,
            source_arm_generation,
            deadline_ns,
        };
        self.quantum[cpu.index()] = Some(ticket);
        self.record_trace(
            SchedulerTraceKind::QuantumArm,
            cpu,
            Some(claim.thread),
            source_arm_generation,
        );
        Ok(ticket)
    }

    fn check_invariants(&self) -> Result<(), SchedulerError> {
        if self.accounting.cpu.iter().any(|cpu| cpu.overflow_fault) {
            return Err(SchedulerError::AccountingOverflow);
        }
        if self.next_completed_switch_generation == 0 {
            return Err(SchedulerError::TokenExhausted);
        }
        if self.next_wake_generation == 0 {
            return Err(SchedulerError::TokenExhausted);
        }
        if self.len > CAPACITY || self.queue[self.len..].iter().any(Option::is_some) {
            return Err(SchedulerError::Capacity);
        }
        for (cpu_index, pending) in self.pending_block.iter().copied().enumerate() {
            if let Some(pending) = pending {
                let cpu = SchedulerCpuId::new(cpu_index).expect("bounded scheduler CPU index");
                if pending.cpu != cpu
                    || !self.running[cpu_index].is_some_and(|claim| {
                        claim.thread == pending.thread
                            && claim.generation == pending.execution_generation
                    })
                    || pending.execution_generation == 0
                {
                    return Err(SchedulerError::StaleBlockToken);
                }
            }
        }
        for (cpu_index, current) in self.running.iter().copied().enumerate() {
            if let Some(current) = current
                && (current.generation == 0
                    || self.running[..cpu_index]
                        .iter()
                        .flatten()
                        .any(|prior| prior.thread == current.thread)
                    || self.queue[..self.len]
                        .iter()
                        .flatten()
                        .any(|entry| entry.thread == current.thread))
            {
                return Err(SchedulerError::DuplicateThread);
            }
        }
        for cpu_index in 0..H2_SCHEDULER_CPU_CAPACITY {
            let cpu = SchedulerCpuId::new(cpu_index).expect("bounded scheduler CPU index");
            let current = self.running[cpu_index];
            for ticket in [self.quantum[cpu_index], self.need_resched[cpu_index]]
                .into_iter()
                .flatten()
            {
                if ticket.domain != self.domain
                    || ticket.cpu != cpu
                    || ticket.execution_generation == 0
                    || ticket.source_arm_generation == 0
                    || ticket.deadline_ns == 0
                    || !current.is_some_and(|claim| {
                        claim.thread == ticket.thread
                            && claim.generation == ticket.execution_generation
                    })
                {
                    return Err(SchedulerError::StaleQuantum);
                }
            }
        }
        for (cpu_index, suspended) in self.suspended.iter().copied().enumerate() {
            let Some(suspended) = suspended else {
                continue;
            };
            if self.suspended[..cpu_index]
                .iter()
                .flatten()
                .any(|prior| prior.thread == suspended.thread)
                || suspended.generation == 0
                || self
                    .running
                    .iter()
                    .flatten()
                    .any(|claim| claim.thread == suspended.thread)
            {
                return Err(SchedulerError::DuplicateThread);
            }
            let cpu = SchedulerCpuId::new(cpu_index).expect("bounded scheduler CPU index");
            let queued_owner = self.queue[..self.len]
                .iter()
                .flatten()
                .find(|entry| entry.thread == suspended.thread)
                .map(|entry| (entry.continuation_cpu, entry.continuation_generation));
            match suspended.publication {
                SuspendedPublication::Queued
                    if queued_owner != Some((Some(cpu), suspended.generation)) =>
                {
                    return Err(SchedulerError::ContinuationOwned);
                }
                SuspendedPublication::Retired if queued_owner.is_some() => {
                    return Err(SchedulerError::ContinuationOwned);
                }
                _ => {}
            }
        }
        for (index, entry) in self.queue[..self.len].iter().enumerate() {
            let Some(entry) = entry else {
                return Err(SchedulerError::NotScheduled);
            };
            if matches!(
                entry.state,
                SchedulerThreadState::Reserved | SchedulerThreadState::Blocked
            ) && entry.token == 0
            {
                return Err(SchedulerError::StaleReservation);
            }
            if entry.state == SchedulerThreadState::Runnable && entry.token != 0 {
                return Err(SchedulerError::StaleReservation);
            }
            if (entry.state == SchedulerThreadState::Runnable) != (entry.enqueue_generation != 0) {
                return Err(SchedulerError::StaleReservation);
            }
            if entry.state == SchedulerThreadState::Blocked
                && (entry.block_cpu.is_none() || entry.block_execution_generation == 0)
            {
                return Err(SchedulerError::StaleBlockToken);
            }
            if entry.state != SchedulerThreadState::Blocked
                && (entry.block_cpu.is_some() || entry.block_execution_generation != 0)
            {
                return Err(SchedulerError::StaleBlockToken);
            }
            if entry.continuation_cpu.is_some()
                && !self.suspended.iter().flatten().any(|suspended| {
                    suspended.thread == entry.thread
                        && suspended.publication == SuspendedPublication::Queued
                })
            {
                return Err(SchedulerError::ContinuationOwned);
            }
            if entry.continuation_cpu.is_some() != (entry.continuation_generation != 0) {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            if entry.state == SchedulerThreadState::Runnable
                && entry.continuation_cpu.is_none()
                && entry.migration_eligibility_generation == 0
            {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            if self
                .running
                .iter()
                .flatten()
                .any(|claim| claim.thread == entry.thread)
                || self.queue[..index]
                    .iter()
                    .flatten()
                    .any(|prior| prior.thread == entry.thread)
            {
                return Err(SchedulerError::DuplicateThread);
            }
        }
        for cpu_index in 0..H2_SCHEDULER_CPU_CAPACITY {
            let cpu = SchedulerCpuId::new(cpu_index).expect("bounded scheduler CPU index");
            let runnable = self.queue[..self.len]
                .iter()
                .flatten()
                .filter(|entry| {
                    entry.state == SchedulerThreadState::Runnable && entry.target_cpu == cpu
                })
                .count() as u64;
            if self.accounting.cpu[cpu_index].current_runnable != runnable {
                return Err(SchedulerError::AccountingUnderflow);
            }
            if self.active_idle[cpu_index].is_some() && self.running[cpu_index].is_some() {
                return Err(SchedulerError::IdleAccountingActive);
            }
        }
        Ok(())
    }
}

/// Deterministic non-preemptive scheduler with four bounded CPU owners.
///
/// The private spin lock never escapes a method call. Callers therefore cannot
/// nest scheduler ownership around task finalization or process handle-table
/// work.  Releasing this lock from [`Self::complete_switch_on`] is also the
/// continuation-publication Release edge: another CPU must acquire this lock
/// to make that queued continuation eligible and claim it.
pub(crate) struct CooperativeScheduler<const CAPACITY: usize> {
    state: IrqSpinMutex<SchedulerState<CAPACITY>>,
}

impl<const CAPACITY: usize> CooperativeScheduler<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            state: IrqSpinMutex::new(SchedulerState::new()),
        }
    }

    pub(crate) fn reserve(
        &self,
        thread: ThreadKey,
    ) -> Result<SchedulerReservation, SchedulerError> {
        let mut state = self.state.lock();
        if state.contains(thread) {
            return Err(SchedulerError::DuplicateThread);
        }
        if state.len + state.running.iter().flatten().count() >= CAPACITY {
            return Err(SchedulerError::Capacity);
        }
        let token = state.next_token;
        let next_token = token
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let domain = state.domain;
        state.push(QueueEntry {
            thread,
            state: SchedulerThreadState::Reserved,
            token,
            started_execution_generation: 0,
            block_cpu: None,
            block_execution_generation: 0,
            continuation_cpu: None,
            continuation_generation: 0,
            target_cpu: SchedulerCpuId::BOOTSTRAP,
            last_cpu: None,
            eligibility_mask: (1_u64 << H2_SCHEDULER_CPU_CAPACITY) - 1,
            enqueue_generation: 0,
            migration_generation: 0,
            migration_eligibility_generation: 0,
            #[cfg(any(test, deepwyrm_dw1c_evidence))]
            migration_exclusion: None,
            ready_at_ns: None,
        })?;
        state.next_token = next_token;
        state.assert_invariants();
        Ok(SchedulerReservation {
            domain,
            token,
            thread,
        })
    }

    pub(crate) fn commit(
        &self,
        reservation: SchedulerReservation,
    ) -> Result<RunnablePublication, SchedulerReservationFailure> {
        self.commit_on(SchedulerCpuId::BOOTSTRAP, reservation)
    }

    pub(crate) fn commit_on(
        &self,
        requester: SchedulerCpuId,
        reservation: SchedulerReservation,
    ) -> Result<RunnablePublication, SchedulerReservationFailure> {
        let mut state = self.state.lock();
        if reservation.domain != state.domain {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::ForeignReservation,
                reservation,
            });
        }

        let Some(index) = state.queue[..state.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.thread == reservation.thread && entry.token == reservation.token
            })
        }) else {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::StaleReservation,
                reservation,
            });
        };
        if state.queue[index].is_none_or(|entry| entry.state != SchedulerThreadState::Reserved) {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::StaleReservation,
                reservation,
            });
        }
        let started_execution_generation = match state.mint_execution_generation() {
            Ok(generation) => generation,
            Err(error) => return Err(SchedulerReservationFailure { error, reservation }),
        };
        let enqueue_generation = state.next_enqueue_generation;
        let next_enqueue_generation = enqueue_generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerReservationFailure {
                error: SchedulerError::TokenExhausted,
                reservation: SchedulerReservation {
                    domain: reservation.domain,
                    token: reservation.token,
                    thread: reservation.thread,
                },
            })?;
        let reserved = state.queue[index].expect("validated scheduler reservation remains queued");
        let Some(target) = state.select_placement(reserved, requester) else {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::CarrierUnavailable,
                reservation,
            });
        };
        let eligibility_generation = state.next_migration_eligibility_generation;
        let next_eligibility_generation = eligibility_generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerReservationFailure {
                error: SchedulerError::TokenExhausted,
                reservation: SchedulerReservation {
                    domain: reservation.domain,
                    token: reservation.token,
                    thread: reservation.thread,
                },
            })?;
        let mut accounting = state.accounting;
        if let Err(error) = accounting.increment_runnable(target) {
            state.reject_accounting(accounting, error);
            return Err(SchedulerReservationFailure { error, reservation });
        }
        let ready_at_ns = state.instrumentation_global_now_ns;
        let entry = state.queue[index]
            .as_mut()
            .expect("validated scheduler reservation remains queued");
        entry.state = SchedulerThreadState::Runnable;
        entry.token = 0;
        entry.started_execution_generation = started_execution_generation;
        entry.target_cpu = target;
        entry.enqueue_generation = enqueue_generation;
        entry.migration_eligibility_generation = eligibility_generation;
        entry.ready_at_ns = ready_at_ns;
        state.next_enqueue_generation = next_enqueue_generation;
        state.next_migration_eligibility_generation = next_eligibility_generation;
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::Runnable,
            target,
            Some(reservation.thread),
            enqueue_generation,
        );
        state.assert_invariants();
        Ok(RunnablePublication {
            target,
            continuation_bound: false,
        })
    }

    pub(crate) fn cancel(
        &self,
        reservation: SchedulerReservation,
    ) -> Result<(), SchedulerReservationFailure> {
        let mut state = self.state.lock();
        if reservation.domain != state.domain {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::ForeignReservation,
                reservation,
            });
        }
        let Some(index) = state.queue[..state.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.thread == reservation.thread
                    && entry.token == reservation.token
                    && entry.state == SchedulerThreadState::Reserved
            })
        }) else {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::StaleReservation,
                reservation,
            });
        };
        state.remove_index(index);
        state.assert_invariants();
        Ok(())
    }

    /// Atomically claims the oldest local Runnable Thread, stealing at most
    /// one oldest eligible entry through one bounded cyclic victim scan.
    pub(crate) fn schedule_next_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> Result<ScheduleDecision, SchedulerError> {
        self.schedule_next_on_with_migration(cpu)
            .map(SchedulerDispatch::decision)
    }

    pub(crate) fn schedule_next_on_with_migration(
        &self,
        cpu: SchedulerCpuId,
    ) -> Result<SchedulerDispatch, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if state.carrier_admission.enforced
            && state.carrier_admission.schedulable_mask & (1_u64 << cpu_index) == 0
        {
            return Err(SchedulerError::CarrierUnavailable);
        }
        if state.running[cpu_index].is_some() {
            return Err(SchedulerError::CurrentThreadRunning);
        }
        if state.suspended[cpu_index].is_some() {
            return Err(SchedulerError::SwitchPending);
        }
        if state.active_idle[cpu_index].is_some() {
            return Err(SchedulerError::IdleAccountingActive);
        }
        let pending_migration = if state.first_local_runnable_index(cpu).is_none() {
            state.steal_oldest_for(cpu)?
        } else {
            None
        };
        let next_entry = state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && entry.continuation_cpu.is_none()
            })
            .copied();
        let mut accounting = state.accounting;
        let accounting_result = if let Some(entry) = next_entry {
            accounting
                .decrement_runnable(entry.target_cpu)
                .and_then(|()| {
                    accounting.observe_ready_delay(
                        cpu,
                        entry.ready_at_ns,
                        state.instrumentation_global_now_ns,
                    )
                })
                .and_then(|()| accounting.increment(cpu, SchedulerEvent::ContextSwitch))
        } else {
            Ok(())
        };
        if let Err(error) = accounting_result {
            if let Some(pending) = pending_migration {
                state.rollback_pending_migration(pending);
            }
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        let current = match state.claim_first_runnable_on(cpu) {
            Ok(current) => current,
            Err(error) => {
                if let Some(pending) = pending_migration {
                    state.rollback_pending_migration(pending);
                }
                return Err(error);
            }
        };
        state.running[cpu_index] = current;
        state.accounting = accounting;
        if let Some(current) = current {
            state.record_trace(
                SchedulerTraceKind::Dispatch,
                cpu,
                Some(current.thread),
                current.generation,
            );
        }
        state.assert_invariants();
        Ok(SchedulerDispatch {
            decision: ScheduleDecision {
                previous: None,
                current: current.map(|claim| claim.thread),
                cancelled_quantum: None,
            },
            migration: pending_migration.map(|pending| pending.record),
        })
    }

    pub(crate) fn yield_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        let Some(previous_claim) = state.running[cpu_index] else {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        };
        if previous_claim.thread != thread {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        }
        if state.pending_block[cpu_index].is_some() {
            return Err(SchedulerError::BlockPreparationActive);
        }
        if state.suspended[cpu_index].is_some() {
            return Err(SchedulerError::SwitchPending);
        }
        let next_entry = state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && entry.continuation_cpu.is_none()
            })
            .copied();
        let mut accounting = state.accounting;
        let Some(next_entry) = next_entry else {
            if let Err(error) = accounting.increment(cpu, SchedulerEvent::VoluntaryYield) {
                state.reject_accounting(accounting, error);
                return Err(error);
            }
            state.accounting = accounting;
            state.assert_invariants();
            return Ok(ScheduleDecision {
                previous: Some(thread),
                current: Some(thread),
                cancelled_quantum: None,
            });
        };
        let enqueue_generation = state.next_enqueue_generation;
        let next_enqueue_generation = enqueue_generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let accounting_result = accounting
            .decrement_runnable(next_entry.target_cpu)
            .and_then(|()| {
                accounting.observe_ready_delay(
                    cpu,
                    next_entry.ready_at_ns,
                    state.instrumentation_global_now_ns,
                )
            })
            .and_then(|()| accounting.increment_runnable(cpu))
            .and_then(|()| accounting.increment(cpu, SchedulerEvent::VoluntaryYield))
            .and_then(|()| accounting.increment(cpu, SchedulerEvent::ContextSwitch));
        if let Err(error) = accounting_result {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        let next = state
            .claim_first_runnable_on(cpu)?
            .expect("validated Runnable entry remains claimable");
        let cancelled_quantum = state.clear_preemption_on(cpu);
        state.running[cpu_index] = Some(next);
        let ready_at_ns = state.instrumentation_global_now_ns;
        state
            .push(QueueEntry {
                thread,
                state: SchedulerThreadState::Runnable,
                token: 0,
                started_execution_generation: 0,
                block_cpu: None,
                block_execution_generation: 0,
                continuation_cpu: Some(cpu),
                continuation_generation: previous_claim.generation,
                target_cpu: cpu,
                last_cpu: Some(cpu),
                eligibility_mask: (1_u64 << H2_SCHEDULER_CPU_CAPACITY) - 1,
                enqueue_generation,
                migration_generation: 0,
                migration_eligibility_generation: 0,
                #[cfg(any(test, deepwyrm_dw1c_evidence))]
                migration_exclusion: None,
                ready_at_ns,
            })
            .expect("replacing one Running Thread preserves scheduler capacity");
        state.suspended[cpu_index] = Some(SuspendedContinuation {
            thread,
            generation: previous_claim.generation,
            publication: SuspendedPublication::Queued,
            involuntary_preemption: false,
        });
        state.next_enqueue_generation = next_enqueue_generation;
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::Yield,
            cpu,
            Some(thread),
            previous_claim.generation,
        );
        state.assert_invariants();
        Ok(ScheduleDecision {
            previous: Some(thread),
            current: Some(next.thread),
            cancelled_quantum,
        })
    }

    /// Test-only forced replacement used to exercise stale-ticket rejection.
    #[cfg(test)]
    pub(crate) fn prepare_quantum_on(
        &self,
        cpu: SchedulerCpuId,
        now_ns: u64,
    ) -> Result<SchedulerQuantumTicket, SchedulerError> {
        let mut state = self.state.lock();
        let claim = state.running[cpu.index()].ok_or(SchedulerError::NotRunning)?;
        if state.suspended[cpu.index()].is_some() || state.pending_block[cpu.index()].is_some() {
            return Err(SchedulerError::QuantumUnavailable);
        }
        let ticket = state.mint_quantum_on(cpu, claim, now_ns)?;
        state.need_resched[cpu.index()] = None;
        state.assert_invariants();
        Ok(ticket)
    }

    /// Preserves an existing exact CPU-local budget across syscall entry/return and
    /// mints only when the selected execution genuinely has no quantum.
    pub(crate) fn prepare_quantum_if_needed_on(
        &self,
        cpu: SchedulerCpuId,
        now_ns: u64,
    ) -> Result<Option<SchedulerQuantumTicket>, SchedulerError> {
        let mut state = self.state.lock();
        let claim = state.running[cpu.index()].ok_or(SchedulerError::NotRunning)?;
        if state.suspended[cpu.index()].is_some()
            || state.pending_block[cpu.index()].is_some()
            || state.need_resched[cpu.index()].is_some()
        {
            return Err(SchedulerError::QuantumUnavailable);
        }
        if state.quantum[cpu.index()].is_some() {
            state.assert_invariants();
            return Ok(None);
        }
        let ticket = state.mint_quantum_on(cpu, claim, now_ns)?;
        state.assert_invariants();
        Ok(Some(ticket))
    }

    /// Publishes a coalescing request only for the still-current exact ticket.
    /// A late physical vector is a harmless rescan and cannot mutate a later
    /// dispatch or clear its source.
    pub(crate) fn publish_quantum_expiry(
        &self,
        ticket: SchedulerQuantumTicket,
    ) -> Result<bool, SchedulerError> {
        let mut state = self.state.lock();
        if ticket.domain != state.domain {
            return Ok(false);
        }
        let cpu_index = ticket.cpu.index();
        if state.quantum[cpu_index] != Some(ticket)
            || !state.running[cpu_index].is_some_and(|claim| {
                claim.thread == ticket.thread && claim.generation == ticket.execution_generation
            })
        {
            return Ok(false);
        }
        let mut accounting = state.accounting;
        if let Err(error) = accounting.increment(ticket.cpu, SchedulerEvent::QuantumExpiration) {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        state.quantum[cpu_index] = None;
        match state.need_resched[cpu_index] {
            None => state.need_resched[cpu_index] = Some(ticket),
            Some(current) if current == ticket => {}
            Some(_) => {
                state.assert_invariants();
                return Err(SchedulerError::StaleQuantum);
            }
        }
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::QuantumExpire,
            ticket.cpu,
            Some(ticket.thread),
            ticket.source_arm_generation,
        );
        state.assert_invariants();
        Ok(true)
    }

    pub(crate) fn has_reschedule_request_on(&self, cpu: SchedulerCpuId) -> bool {
        self.state.lock().need_resched[cpu.index()].is_some()
    }

    pub(crate) fn preemption_snapshot_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> SchedulerPreemptionSnapshot {
        let state = self.state.lock();
        SchedulerPreemptionSnapshot {
            running: state.running[cpu.index()].map(|claim| SchedulerExecutionClaim {
                domain: state.domain,
                cpu,
                thread: claim.thread,
                generation: claim.generation,
            }),
            quantum: state.quantum[cpu.index()],
            request: state.need_resched[cpu.index()],
            preemption_disable_depth: state.preemption_disable_depth[cpu.index()],
            counters: state.accounting.cpu[cpu.index()],
        }
    }

    pub(crate) fn preemption_disable_on(&self, cpu: SchedulerCpuId) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        state.preemption_disable_depth[cpu.index()] = state.preemption_disable_depth[cpu.index()]
            .checked_add(1)
            .ok_or(SchedulerError::PreemptionDepthOverflow)?;
        state.assert_invariants();
        Ok(())
    }

    pub(crate) fn preemption_enable_on(&self, cpu: SchedulerCpuId) -> Result<bool, SchedulerError> {
        let mut state = self.state.lock();
        state.preemption_disable_depth[cpu.index()] = state.preemption_disable_depth[cpu.index()]
            .checked_sub(1)
            .ok_or(SchedulerError::PreemptionDepthUnderflow)?;
        let ready = state.preemption_disable_depth[cpu.index()] == 0
            && state.need_resched[cpu.index()].is_some();
        state.assert_invariants();
        Ok(ready)
    }

    /// Consumes the current CPU's exact request at a guard-free CPL3 return boundary.
    /// The outgoing Thread is placed at the FIFO tail only when a local peer
    /// can be claimed in the same scheduler transaction.
    pub(crate) fn preempt_current_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> Result<SchedulerPreemptionDecision, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        let request = state.need_resched[cpu_index].ok_or(SchedulerError::StaleQuantum)?;
        let current = state.running[cpu_index].ok_or(SchedulerError::NotRunning)?;
        if current.thread != request.thread || current.generation != request.execution_generation {
            state.need_resched[cpu_index] = None;
            state.assert_invariants();
            return Err(SchedulerError::StaleQuantum);
        }
        if state.preemption_disable_depth[cpu_index] != 0
            || state.pending_block[cpu_index].is_some()
            || state.suspended[cpu_index].is_some()
        {
            return Ok(SchedulerPreemptionDecision::Deferred);
        }
        let Some(next_entry) = state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && entry.continuation_cpu.is_none()
            })
            .copied()
        else {
            state.need_resched[cpu_index] = None;
            state.assert_invariants();
            return Ok(SchedulerPreemptionDecision::RetainCurrent);
        };

        let enqueue_generation = state.next_enqueue_generation;
        let next_enqueue_generation = enqueue_generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let mut accounting = state.accounting;
        let accounting_result = accounting
            .decrement_runnable(next_entry.target_cpu)
            .and_then(|()| {
                accounting.observe_ready_delay(
                    cpu,
                    next_entry.ready_at_ns,
                    state.instrumentation_global_now_ns,
                )
            })
            .and_then(|()| accounting.increment_runnable(cpu))
            .and_then(|()| accounting.increment(cpu, SchedulerEvent::ContextSwitch));
        if let Err(error) = accounting_result {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        let next = state
            .claim_first_runnable_on(cpu)?
            .expect("validated normal Runnable peer remains claimable");
        state.running[cpu_index] = Some(next);
        let ready_at_ns = state.instrumentation_global_now_ns;
        state
            .push(QueueEntry {
                thread: current.thread,
                state: SchedulerThreadState::Runnable,
                token: 0,
                started_execution_generation: 0,
                block_cpu: None,
                block_execution_generation: 0,
                continuation_cpu: Some(cpu),
                continuation_generation: current.generation,
                target_cpu: cpu,
                last_cpu: Some(cpu),
                eligibility_mask: (1_u64 << H2_SCHEDULER_CPU_CAPACITY) - 1,
                enqueue_generation,
                migration_generation: 0,
                migration_eligibility_generation: 0,
                #[cfg(any(test, deepwyrm_dw1c_evidence))]
                migration_exclusion: None,
                ready_at_ns,
            })
            .expect("replacing one Running Thread preserves scheduler capacity");
        state.suspended[cpu_index] = Some(SuspendedContinuation {
            thread: current.thread,
            generation: current.generation,
            publication: SuspendedPublication::Queued,
            involuntary_preemption: true,
        });
        state.next_enqueue_generation = next_enqueue_generation;
        state.need_resched[cpu_index] = None;
        state.quantum[cpu_index] = None;
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::Preempt,
            cpu,
            Some(current.thread),
            request.source_arm_generation,
        );
        state.assert_invariants();
        Ok(SchedulerPreemptionDecision::Switch {
            decision: ScheduleDecision {
                previous: Some(current.thread),
                current: Some(next.thread),
                cancelled_quantum: None,
            },
            outgoing: SchedulerExecutionClaim {
                domain: state.domain,
                cpu,
                thread: current.thread,
                generation: current.generation,
            },
        })
    }

    pub(crate) fn prepare_block_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<BlockReservation, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        let Some(running_claim) = state.running[cpu_index] else {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        };
        if running_claim.thread != thread {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        }
        if state.suspended[cpu_index].is_some() {
            return Err(SchedulerError::SwitchPending);
        }
        if state.pending_block[cpu_index].is_some() {
            return Err(SchedulerError::BlockPreparationActive);
        }
        let token = state.next_token;
        state.next_token = state
            .next_token
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let key = BlockWakeKey {
            domain: state.domain,
            token,
            thread,
            cpu,
            execution_generation: running_claim.generation,
        };
        state.pending_block[cpu_index] = Some(key);
        state.assert_invariants();
        Ok(BlockReservation { key })
    }

    pub(crate) fn cancel_block_on(
        &self,
        cpu: SchedulerCpuId,
        reservation: BlockReservation,
    ) -> Result<(), BlockReservationFailure> {
        let mut state = self.state.lock();
        if reservation.key.domain != state.domain {
            return Err(BlockReservationFailure {
                error: SchedulerError::ForeignBlockToken,
                reservation,
            });
        }
        if reservation.key.cpu != cpu || state.pending_block[cpu.index()] != Some(reservation.key) {
            return Err(BlockReservationFailure {
                error: SchedulerError::StaleBlockToken,
                reservation,
            });
        }
        state.pending_block[cpu.index()] = None;
        state.assert_invariants();
        Ok(())
    }

    pub(crate) fn commit_block_on(
        &self,
        cpu: SchedulerCpuId,
        reservation: BlockReservation,
    ) -> Result<ScheduleDecision, BlockReservationFailure> {
        let mut state = self.state.lock();
        if reservation.key.domain != state.domain {
            return Err(BlockReservationFailure {
                error: SchedulerError::ForeignBlockToken,
                reservation,
            });
        }
        let cpu_index = cpu.index();
        if reservation.key.cpu != cpu
            || state.pending_block[cpu_index] != Some(reservation.key)
            || !state.running[cpu_index].is_some_and(|claim| {
                claim.thread == reservation.key.thread
                    && claim.generation == reservation.key.execution_generation
            })
            || state.suspended[cpu_index].is_some()
        {
            return Err(BlockReservationFailure {
                error: SchedulerError::StaleBlockToken,
                reservation,
            });
        }
        let next_entry = state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && entry.continuation_cpu.is_none()
            })
            .copied();
        let mut accounting = state.accounting;
        let mut accounting_result = accounting.increment(cpu, SchedulerEvent::VoluntaryBlock);
        if let Some(entry) = next_entry {
            accounting_result = accounting_result
                .and_then(|()| accounting.decrement_runnable(entry.target_cpu))
                .and_then(|()| {
                    accounting.observe_ready_delay(
                        cpu,
                        entry.ready_at_ns,
                        state.instrumentation_global_now_ns,
                    )
                });
        }
        accounting_result = accounting_result
            .and_then(|()| accounting.increment(cpu, SchedulerEvent::ContextSwitch));
        if let Err(error) = accounting_result {
            state.reject_accounting(accounting, error);
            return Err(BlockReservationFailure { error, reservation });
        }
        let current = match state.claim_first_runnable_on(cpu) {
            Ok(current) => current,
            Err(error) => return Err(BlockReservationFailure { error, reservation }),
        };
        state.pending_block[cpu_index] = None;
        let cancelled_quantum = state.clear_preemption_on(cpu);
        state.running[cpu_index] = None;
        state
            .push(QueueEntry {
                thread: reservation.key.thread,
                state: SchedulerThreadState::Blocked,
                token: reservation.key.token,
                started_execution_generation: 0,
                block_cpu: Some(cpu),
                block_execution_generation: reservation.key.execution_generation,
                continuation_cpu: Some(cpu),
                continuation_generation: reservation.key.execution_generation,
                target_cpu: cpu,
                last_cpu: Some(cpu),
                eligibility_mask: (1_u64 << H2_SCHEDULER_CPU_CAPACITY) - 1,
                enqueue_generation: 0,
                migration_generation: 0,
                migration_eligibility_generation: 0,
                #[cfg(any(test, deepwyrm_dw1c_evidence))]
                migration_exclusion: None,
                ready_at_ns: None,
            })
            .expect("moving one Running Thread to the queue preserves scheduler capacity");
        state.running[cpu_index] = current;
        state.suspended[cpu_index] = Some(SuspendedContinuation {
            thread: reservation.key.thread,
            generation: reservation.key.execution_generation,
            publication: SuspendedPublication::Queued,
            involuntary_preemption: false,
        });
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::Block,
            cpu,
            Some(reservation.key.thread),
            reservation.key.execution_generation,
        );
        state.assert_invariants();
        Ok(ScheduleDecision {
            previous: Some(reservation.key.thread),
            current: current.map(|claim| claim.thread),
            cancelled_quantum,
        })
    }

    pub(crate) fn block_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<(BlockToken, ScheduleDecision), SchedulerError> {
        let reservation = self.prepare_block_current_on(cpu, thread)?;
        let key = reservation.wake_key();
        match self.commit_block_on(cpu, reservation) {
            Ok(decision) => Ok((BlockToken { key }, decision)),
            Err(failure) => Err(failure.error()),
        }
    }

    /// Makes one exact blocked generation Runnable and reports whether its
    /// physically suspended continuation is still owned by one CPU. The
    /// caller must direct any idle-wake notification to that CPU until switch
    /// completion releases the continuation for ordinary FIFO acquisition.
    pub(crate) fn wake_with_affinity(
        &self,
        key: BlockWakeKey,
    ) -> Result<Option<SchedulerCpuId>, SchedulerError> {
        self.wake_on(key.cpu, key)
            .map(SchedulerWakePublication::wake_affinity)
    }

    pub(crate) fn wake_on(
        &self,
        requester: SchedulerCpuId,
        key: BlockWakeKey,
    ) -> Result<SchedulerWakePublication, SchedulerError> {
        let mut state = self.state.lock();
        if key.domain != state.domain {
            return Err(SchedulerError::ForeignBlockToken);
        }
        let Some(index) = state.queue[..state.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.thread == key.thread
                    && entry.token == key.token
                    && entry.block_cpu == Some(key.cpu)
                    && entry.block_execution_generation == key.execution_generation
                    && entry.state == SchedulerThreadState::Blocked
            })
        }) else {
            return Err(SchedulerError::StaleBlockToken);
        };
        let blocked = state.queue[index].expect("validated blocked scheduler entry remains queued");
        let Some(target) = state.select_placement(blocked, requester) else {
            return Err(SchedulerError::CarrierUnavailable);
        };
        let (wake_generation, next_wake_generation) = state.checked_wake_generation()?;
        let eligibility = if blocked.continuation_cpu.is_none() {
            let generation = state.next_migration_eligibility_generation;
            let next = generation
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(SchedulerError::TokenExhausted)?;
            Some((generation, next))
        } else {
            None
        };
        let mut accounting = state.accounting;
        let enqueue_generation = state.next_enqueue_generation;
        let next_enqueue_generation = enqueue_generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let accounting_result = accounting
            .increment_runnable(target)
            .and_then(|()| accounting.increment(requester, SchedulerEvent::Wakeup));
        if let Err(error) = accounting_result {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        let ready_at_ns = state.instrumentation_global_now_ns;
        let entry = state.queue[index]
            .as_mut()
            .expect("validated blocked scheduler entry remains queued");
        entry.state = SchedulerThreadState::Runnable;
        entry.token = 0;
        entry.started_execution_generation = key.execution_generation;
        entry.block_cpu = None;
        entry.block_execution_generation = 0;
        entry.target_cpu = target;
        entry.enqueue_generation = enqueue_generation;
        entry.migration_eligibility_generation = eligibility.map_or(0, |value| value.0);
        entry.ready_at_ns = ready_at_ns;
        state.next_enqueue_generation = next_enqueue_generation;
        if let Some((_, next)) = eligibility {
            state.next_migration_eligibility_generation = next;
        }
        state.next_wake_generation = next_wake_generation;
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::Wake,
            requester,
            Some(key.thread),
            key.execution_generation,
        );
        state.assert_invariants();
        Ok(SchedulerWakePublication {
            runnable: RunnablePublication {
                target,
                continuation_bound: blocked.continuation_cpu.is_some(),
            },
            source: requester,
            generation: wake_generation,
        })
    }

    pub(crate) fn wake(&self, key: BlockWakeKey) -> Result<(), SchedulerError> {
        self.wake_with_affinity(key).map(|_| ())
    }

    /// Validates that a deferred wake key belongs to this scheduler and names
    /// an already-issued generation without changing any scheduling state.
    ///
    /// Completed and terminally retired generations deliberately remain valid
    /// here: their durable wait registrations are the proof that the exact key
    /// once existed. Any still-live use of the token must retain the same Thread
    /// association.
    pub(crate) fn validate_issued_wake_key(&self, key: BlockWakeKey) -> Result<(), SchedulerError> {
        let state = self.state.lock();
        if key.domain != state.domain {
            return Err(SchedulerError::ForeignBlockToken);
        }
        if key.token == 0 || key.token >= state.next_token {
            return Err(SchedulerError::StaleBlockToken);
        }
        if state
            .pending_block
            .iter()
            .flatten()
            .any(|pending| pending.token == key.token && *pending != key)
            || state.queue[..state.len].iter().flatten().any(|entry| {
                entry.token == key.token
                    && (entry.thread != key.thread
                        || entry.state != SchedulerThreadState::Blocked
                        || entry.block_cpu != Some(key.cpu)
                        || entry.block_execution_generation != key.execution_generation)
            })
        {
            return Err(SchedulerError::StaleBlockToken);
        }
        Ok(())
    }

    /// Selects work after an IRQ while the CPU is physically executing a
    /// blocked syscall continuation on `suspended`'s kernel stack.
    ///
    /// The logical scheduler has no current Thread in this state. If the
    /// suspended Thread itself is selected, the caller may resume in place. If
    /// another Runnable Thread wins FIFO order, the returned decision names the
    /// physically-active suspended continuation as `previous` so the execution
    /// owner can save it before switching away.
    pub(crate) fn schedule_from_idle_on(
        &self,
        cpu: SchedulerCpuId,
        suspended: ThreadKey,
    ) -> Result<IdleScheduleDecision, SchedulerError> {
        self.schedule_from_idle_on_with_migration(cpu, suspended)
            .map(SchedulerIdleDispatch::decision)
    }

    pub(crate) fn schedule_from_idle_on_with_migration(
        &self,
        cpu: SchedulerCpuId,
        suspended: ThreadKey,
    ) -> Result<SchedulerIdleDispatch, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if state.carrier_admission.enforced
            && state.carrier_admission.schedulable_mask & (1_u64 << cpu_index) == 0
        {
            return Err(SchedulerError::CarrierUnavailable);
        }
        if state.running[cpu_index].is_some() {
            return Err(SchedulerError::CurrentThreadRunning);
        }
        if state.active_idle[cpu_index].is_some() {
            return Err(SchedulerError::IdleAccountingActive);
        }
        let Some(suspended_claim) = state.suspended[cpu_index] else {
            return Err(SchedulerError::ContinuationOwned);
        };
        if suspended_claim.thread != suspended
            || suspended_claim.publication != SuspendedPublication::Queued
        {
            return Err(SchedulerError::ContinuationOwned);
        }
        let local_runnable = state.queue[..state.len].iter().any(|entry| {
            entry.is_some_and(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && (entry.continuation_cpu.is_none() || entry.continuation_cpu == Some(cpu))
            })
        });
        let pending_migration = if !local_runnable {
            state.steal_oldest_for(cpu)?
        } else {
            None
        };
        let next_entry = state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && entry.target_cpu == cpu
                    && (entry.continuation_cpu.is_none() || entry.continuation_cpu == Some(cpu))
            })
            .copied();
        let mut accounting = state.accounting;
        let Some(next_entry) = next_entry else {
            if let Some(pending) = pending_migration {
                state.rollback_pending_migration(pending);
            }
            state.assert_invariants();
            return Ok(SchedulerIdleDispatch {
                decision: IdleScheduleDecision::ContinueIdle,
                migration: None,
            });
        };
        let mut accounting_result = accounting
            .decrement_runnable(next_entry.target_cpu)
            .and_then(|()| {
                accounting.observe_ready_delay(
                    cpu,
                    next_entry.ready_at_ns,
                    state.instrumentation_global_now_ns,
                )
            });
        if next_entry.thread != suspended {
            accounting_result = accounting_result
                .and_then(|()| accounting.increment(cpu, SchedulerEvent::ContextSwitch));
        }
        if let Err(error) = accounting_result {
            if let Some(pending) = pending_migration {
                state.rollback_pending_migration(pending);
            }
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        let next = match state.claim_first_runnable_for_idle(cpu, suspended_claim) {
            Ok(Some(next)) => next,
            Ok(None) => panic!("validated Runnable entry became unclaimable from idle"),
            Err(error) => {
                if let Some(pending) = pending_migration {
                    state.rollback_pending_migration(pending);
                }
                return Err(error);
            }
        };
        state.running[cpu_index] = Some(next);
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::Dispatch,
            cpu,
            Some(next.thread),
            next.generation,
        );
        if next.thread == suspended {
            state.suspended[cpu_index] = None;
            state.assert_invariants();
            Ok(SchedulerIdleDispatch {
                decision: IdleScheduleDecision::ResumeCurrent,
                migration: pending_migration.map(|pending| pending.record),
            })
        } else {
            state.assert_invariants();
            Ok(SchedulerIdleDispatch {
                decision: IdleScheduleDecision::Switch(ScheduleDecision {
                    previous: Some(suspended),
                    current: Some(next.thread),
                    cancelled_quantum: None,
                }),
                migration: pending_migration.map(|pending| pending.record),
            })
        }
    }

    /// Publishes that `cpu` has saved or abandoned its outgoing continuation.
    ///
    /// The architecture switch path writes the outgoing saved RSP before this
    /// call. Dropping the scheduler lock is a Release operation; a contender
    /// must subsequently acquire the same lock before it can claim the now
    /// unowned Runnable Thread and Acquire-load its continuation slot.
    pub(crate) fn complete_switch_on(
        &self,
        claim: SchedulerExecutionClaim,
    ) -> Result<(), SchedulerError> {
        self.complete_switch_on_with_runnable_publication(claim)
            .map(|_| ())
    }

    /// Releases an exact saved continuation and reports whether doing so made
    /// queued Runnable work eligible for acquisition by any idle CPU.
    pub(crate) fn complete_switch_on_with_runnable_publication(
        &self,
        claim: SchedulerExecutionClaim,
    ) -> Result<SchedulerCompletedSwitch, SchedulerError> {
        let mut state = self.state.lock();
        if claim.domain != state.domain {
            return Err(SchedulerError::ForeignExecutionClaim);
        }
        if claim.generation == 0 {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let cpu_index = claim.cpu.index();
        let Some(suspended) = state.suspended[cpu_index] else {
            return Err(SchedulerError::StaleExecutionClaim);
        };
        if suspended.thread != claim.thread || suspended.generation != claim.generation {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let (completed_switch_generation, next_completed_switch_generation) =
            state.checked_completed_switch_generation()?;
        let published_runnable = if suspended.publication == SuspendedPublication::Queued {
            let Some(index) = state.queue[..state.len]
                .iter()
                .position(|entry| entry.is_some_and(|entry| entry.thread == claim.thread))
            else {
                return Err(SchedulerError::NotScheduled);
            };
            let queued = state.queue[index].expect("suspended queue entry remains present");
            let eligibility_generation = if queued.state == SchedulerThreadState::Runnable {
                state.mint_migration_eligibility_generation()?
            } else {
                0
            };
            let entry = state.queue[index]
                .as_mut()
                .expect("suspended queue entry remains present");
            if entry.continuation_cpu != Some(claim.cpu)
                || entry.continuation_generation != claim.generation
            {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            let publication =
                (entry.state == SchedulerThreadState::Runnable).then_some(RunnablePublication {
                    target: entry.target_cpu,
                    continuation_bound: false,
                });
            entry.continuation_cpu = None;
            entry.continuation_generation = 0;
            entry.migration_eligibility_generation = eligibility_generation;
            publication
        } else {
            None
        };
        if suspended.involuntary_preemption {
            let mut accounting = state.accounting;
            if let Err(error) =
                accounting.increment(claim.cpu, SchedulerEvent::InvoluntaryPreemption)
            {
                state.reject_accounting(accounting, error);
                return Err(error);
            }
            state.accounting = accounting;
        }
        state.next_completed_switch_generation = next_completed_switch_generation;
        state.suspended[cpu_index] = None;
        state.assert_invariants();
        Ok(SchedulerCompletedSwitch {
            runnable_publication: published_runnable,
            generation: completed_switch_generation,
            involuntary_preemption: suspended.involuntary_preemption,
        })
    }

    pub(crate) fn retire_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if let Some(running_cpu) = state.running_cpu(thread) {
            if running_cpu != cpu {
                return Err(SchedulerError::WrongCpu);
            }
            if state.suspended[cpu_index].is_some() {
                return Err(SchedulerError::SwitchPending);
            }
            let outgoing = state.running[cpu_index].expect("running CPU retains its exact claim");
            let next_entry = state.queue[..state.len]
                .iter()
                .flatten()
                .find(|entry| {
                    entry.state == SchedulerThreadState::Runnable
                        && entry.target_cpu == cpu
                        && entry.continuation_cpu.is_none()
                })
                .copied();
            let mut accounting = state.accounting;
            let mut accounting_result = accounting.increment(cpu, SchedulerEvent::ContextSwitch);
            if let Some(entry) = next_entry {
                accounting_result = accounting_result
                    .and_then(|()| accounting.decrement_runnable(entry.target_cpu))
                    .and_then(|()| {
                        accounting.observe_ready_delay(
                            cpu,
                            entry.ready_at_ns,
                            state.instrumentation_global_now_ns,
                        )
                    });
            }
            if let Err(error) = accounting_result {
                state.reject_accounting(accounting, error);
                return Err(error);
            }
            let current = state.claim_first_runnable_on(cpu)?;
            if state.pending_block[cpu_index].is_some_and(|pending| pending.thread == thread) {
                state.pending_block[cpu_index] = None;
            }
            let cancelled_quantum = state.clear_preemption_on(cpu);
            state.running[cpu_index] = None;
            state.running[cpu_index] = current;
            state.suspended[cpu_index] = Some(SuspendedContinuation {
                thread,
                generation: outgoing.generation,
                publication: SuspendedPublication::Retired,
                involuntary_preemption: false,
            });
            state.accounting = accounting;
            state.record_trace(
                SchedulerTraceKind::Retire,
                cpu,
                Some(thread),
                outgoing.generation,
            );
            if let Some(current) = current {
                state.record_trace(
                    SchedulerTraceKind::Dispatch,
                    cpu,
                    Some(current.thread),
                    current.generation,
                );
            }
            state.assert_invariants();
            return Ok(ScheduleDecision {
                previous: Some(thread),
                current: current.map(|claim| claim.thread),
                cancelled_quantum,
            });
        }
        if let Some(owner_cpu) = state
            .suspended
            .iter()
            .position(|suspended| suspended.is_some_and(|owner| owner.thread == thread))
            .and_then(SchedulerCpuId::new)
        {
            if owner_cpu != cpu {
                return Err(SchedulerError::WrongCpu);
            }
            let Some(index) = state.queue[..state.len]
                .iter()
                .position(|entry| entry.is_some_and(|entry| entry.thread == thread))
            else {
                return Err(SchedulerError::NotScheduled);
            };
            let removed = state.queue[index].expect("suspended scheduler entry remains queued");
            let next_entry = state.queue[..state.len]
                .iter()
                .enumerate()
                .filter(|(candidate_index, _)| *candidate_index != index)
                .filter_map(|(_, entry)| *entry)
                .find(|entry| {
                    entry.state == SchedulerThreadState::Runnable
                        && entry.target_cpu == cpu
                        && entry.continuation_cpu.is_none()
                });
            let will_claim = state.running[cpu_index].is_none() && next_entry.is_some();
            if will_claim && !state.execution_generation_available() {
                return Err(SchedulerError::TokenExhausted);
            }
            let mut accounting = state.accounting;
            let mut accounting_result = Ok(());
            if removed.state == SchedulerThreadState::Runnable {
                accounting_result = accounting.decrement_runnable(removed.target_cpu);
            }
            if let Some(entry) = next_entry.filter(|_| will_claim) {
                accounting_result = accounting_result
                    .and_then(|()| accounting.decrement_runnable(entry.target_cpu))
                    .and_then(|()| {
                        accounting.observe_ready_delay(
                            cpu,
                            entry.ready_at_ns,
                            state.instrumentation_global_now_ns,
                        )
                    })
                    .and_then(|()| accounting.increment(cpu, SchedulerEvent::ContextSwitch));
            }
            if let Err(error) = accounting_result {
                state.reject_accounting(accounting, error);
                return Err(error);
            }
            state.remove_index(index);
            let suspended_generation = state.suspended[cpu_index]
                .expect("suspended Thread retains its exact claim")
                .generation;
            state.suspended[cpu_index] = Some(SuspendedContinuation {
                thread,
                generation: suspended_generation,
                publication: SuspendedPublication::Retired,
                involuntary_preemption: false,
            });
            if state.running[cpu_index].is_none() {
                state.running[cpu_index] = state.claim_first_runnable_on(cpu)?;
            }
            state.accounting = accounting;
            state.record_trace(
                SchedulerTraceKind::Retire,
                cpu,
                Some(thread),
                suspended_generation,
            );
            state.assert_invariants();
            return Ok(ScheduleDecision {
                previous: Some(thread),
                current: state.running[cpu_index].map(|claim| claim.thread),
                cancelled_quantum: None,
            });
        }
        let Some(index) = state.queue[..state.len]
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.thread == thread))
        else {
            return Err(SchedulerError::NotScheduled);
        };
        if state.queue[index].is_some_and(|entry| entry.continuation_cpu.is_some()) {
            return Err(SchedulerError::ContinuationOwned);
        }
        let removed = state.queue[index].expect("validated scheduler entry remains queued");
        let mut accounting = state.accounting;
        if removed.state == SchedulerThreadState::Runnable
            && let Err(error) = accounting.decrement_runnable(removed.target_cpu)
        {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        state.remove_index(index);
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::Retire,
            cpu,
            Some(thread),
            removed.enqueue_generation.max(removed.token),
        );
        state.assert_invariants();
        Ok(ScheduleDecision {
            previous: state.running[cpu_index].map(|claim| claim.thread),
            current: state.running[cpu_index].map(|claim| claim.thread),
            cancelled_quantum: None,
        })
    }

    /// Removes one exact remote Running claim without selecting replacement
    /// work. This is the scheduler half of an e1 stop safe point: the target
    /// CPU has already prevented user return, and its CPU-private reaper path
    /// must complete or abandon the retained continuation before any later
    /// carrier work is admitted on that CPU.
    pub(crate) fn stop_running_claim_on(
        &self,
        claim: SchedulerExecutionClaim,
    ) -> Result<Option<SchedulerQuantumTicket>, SchedulerError> {
        let mut state = self.state.lock();
        if claim.domain != state.domain {
            return Err(SchedulerError::ForeignExecutionClaim);
        }
        if claim.generation == 0 {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let cpu_index = claim.cpu.index();
        let Some(running) = state.running[cpu_index] else {
            return Err(SchedulerError::StaleExecutionClaim);
        };
        if running.thread != claim.thread || running.generation != claim.generation {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        if state.suspended[cpu_index].is_some() {
            return Err(SchedulerError::SwitchPending);
        }
        let mut accounting = state.accounting;
        if let Err(error) = accounting.increment(claim.cpu, SchedulerEvent::ContextSwitch) {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        if state.pending_block[cpu_index].is_some_and(|pending| pending.thread == claim.thread) {
            state.pending_block[cpu_index] = None;
        }
        let cancelled_quantum = state.clear_preemption_on(claim.cpu);
        state.running[cpu_index] = None;
        state.suspended[cpu_index] = Some(SuspendedContinuation {
            thread: claim.thread,
            generation: claim.generation,
            publication: SuspendedPublication::Retired,
            involuntary_preemption: false,
        });
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::RemoteStop,
            claim.cpu,
            Some(claim.thread),
            claim.generation,
        );
        state.assert_invariants();
        Ok(cancelled_quantum)
    }

    /// Retires the exact blocked continuation that is still physically active
    /// on `claim.cpu`. This is the e1 delivery-after-block case: the logical
    /// Running claim was already exchanged for a generation-bound suspended
    /// continuation, so treating it as a fresh Running claim would either
    /// stop the wrong generation or panic before the safe-point ACK.
    pub(crate) fn stop_suspended_claim_on(
        &self,
        claim: SchedulerExecutionClaim,
    ) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        if claim.domain != state.domain || claim.generation == 0 {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let cpu_index = claim.cpu.index();
        let Some(suspended) = state.suspended[cpu_index] else {
            return Err(SchedulerError::StaleExecutionClaim);
        };
        if suspended.thread != claim.thread
            || suspended.generation != claim.generation
            || suspended.publication != SuspendedPublication::Queued
        {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let Some(index) = state.queue[..state.len]
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.thread == claim.thread))
        else {
            return Err(SchedulerError::NotScheduled);
        };
        let entry = state.queue[index].expect("queued suspended continuation disappeared");
        if entry.continuation_cpu != Some(claim.cpu)
            || entry.continuation_generation != claim.generation
        {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let mut accounting = state.accounting;
        if entry.state == SchedulerThreadState::Runnable
            && let Err(error) = accounting.decrement_runnable(entry.target_cpu)
        {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        state.remove_index(index);
        state.suspended[cpu_index] = Some(SuspendedContinuation {
            thread: claim.thread,
            generation: claim.generation,
            publication: SuspendedPublication::Retired,
            involuntary_preemption: false,
        });
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::RemoteStop,
            claim.cpu,
            Some(claim.thread),
            claim.generation,
        );
        state.assert_invariants();
        Ok(())
    }

    pub(crate) fn state(&self, thread: ThreadKey) -> Option<SchedulerThreadState> {
        let state = self.state.lock();
        if state
            .running
            .iter()
            .flatten()
            .any(|claim| claim.thread == thread)
        {
            return Some(SchedulerThreadState::Running);
        }
        state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| entry.thread == thread)
            .map(|entry| entry.state)
    }

    /// Internal start identity for a committed-but-not-yet-first-dispatched
    /// Thread. It is intentionally not an ABI query.
    pub(crate) fn runnable_start_generation(&self, thread: ThreadKey) -> Option<u64> {
        let state = self.state.lock();
        state.queue[..state.len].iter().flatten().find_map(|entry| {
            (entry.thread == thread
                && entry.state == SchedulerThreadState::Runnable
                && entry.started_execution_generation != 0)
                .then_some(entry.started_execution_generation)
        })
    }

    /// Selector-private exact identity resolver used while ARM inspects a
    /// started actor. The scheduler lock joins Running, queued Runnable, and
    /// Blocked/suspended ownership without exposing this identity as ABI.
    #[cfg(any(test, deepwyrm_dw1c_evidence))]
    pub(crate) fn current_execution_generation(&self, thread: ThreadKey) -> Option<u64> {
        let state = self.state.lock();
        if let Some(claim) = state
            .running
            .iter()
            .flatten()
            .find(|claim| claim.thread == thread)
        {
            return Some(claim.generation);
        }
        let entry = state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| entry.thread == thread);
        match entry {
            Some(entry)
                if entry.state == SchedulerThreadState::Runnable
                    && entry.started_execution_generation != 0 =>
            {
                Some(entry.started_execution_generation)
            }
            Some(entry)
                if entry.state == SchedulerThreadState::Runnable
                    && entry.continuation_generation != 0 =>
            {
                Some(entry.continuation_generation)
            }
            Some(entry)
                if entry.state == SchedulerThreadState::Blocked
                    && entry.block_execution_generation != 0 =>
            {
                Some(entry.block_execution_generation)
            }
            _ => state
                .suspended
                .iter()
                .flatten()
                .find(|claim| claim.thread == thread)
                .map(|claim| claim.generation),
        }
    }

    #[cfg(test)]
    pub(crate) fn check_invariants(&self) -> Result<(), SchedulerError> {
        self.state.lock().check_invariants()
    }

    #[cfg(test)]
    pub(crate) fn counters_on(&self, cpu: SchedulerCpuId) -> SchedulerCounters {
        self.state.lock().accounting.cpu[cpu.index()]
    }

    #[cfg(test)]
    pub(crate) fn last_migration(&self) -> Option<SchedulerMigrationRecord> {
        self.state.lock().last_migration
    }

    #[cfg(any(test, deepwyrm_dw1c_evidence))]
    pub(crate) fn set_migration_exclusion(
        &self,
        thread: ThreadKey,
        execution_generation: u64,
        exclusion: SchedulerMigrationRejectionReason,
    ) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        let len = state.len;
        let Some(entry) = state.queue[..len]
            .iter_mut()
            .flatten()
            .find(|entry| entry.thread == thread)
        else {
            return Err(SchedulerError::NotScheduled);
        };
        if execution_generation == 0
            || entry.state != SchedulerThreadState::Runnable
            || entry.started_execution_generation != execution_generation
            || entry.migration_exclusion.is_some()
        {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        entry.migration_exclusion = Some(exclusion);
        state.assert_invariants();
        Ok(())
    }

    #[cfg(any(test, deepwyrm_dw1c_evidence))]
    /// Performs one selector-private migration attempt through the same locked
    /// candidate revalidation used by idle stealing.  A rejected attempt never
    /// changes queue placement, accounting, or migration generations.
    pub(crate) fn attempt_migration_revalidation_on(
        &self,
        target: SchedulerCpuId,
        thread: ThreadKey,
        execution_generation: u64,
    ) -> Result<SchedulerMigrationRejection, SchedulerError> {
        let state = self.state.lock();
        let Some(entry) = state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| entry.thread == thread)
        else {
            return Err(SchedulerError::NotScheduled);
        };
        if execution_generation == 0 || entry.started_execution_generation != execution_generation {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let victim = entry.target_cpu;
        if victim == target
            || !state.entry_migratable_without_external_exclusion(*entry, victim, target)
        {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        // `steal_oldest_for` calls the same predicate while holding this lock;
        // the test-only exclusion makes this exact candidate reject at its
        // final external-authority revalidation rather than moving it.
        let reason = entry
            .migration_exclusion
            .ok_or(SchedulerError::StaleExecutionClaim)?;
        if state.entry_migratable(*entry, victim, target) {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        Ok(SchedulerMigrationRejection {
            thread,
            execution_generation,
            cpu: target,
            reason,
        })
    }

    #[cfg(any(test, deepwyrm_dw1c_evidence))]
    pub(crate) fn clear_migration_exclusion(
        &self,
        thread: ThreadKey,
        execution_generation: u64,
        exclusion: SchedulerMigrationRejectionReason,
    ) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        let len = state.len;
        let Some(entry) = state.queue[..len]
            .iter_mut()
            .flatten()
            .find(|entry| entry.thread == thread)
        else {
            return Err(SchedulerError::NotScheduled);
        };
        if entry.state != SchedulerThreadState::Runnable
            || entry.started_execution_generation != execution_generation
            || entry.migration_exclusion != Some(exclusion)
        {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        entry.migration_exclusion = None;
        state.assert_invariants();
        Ok(())
    }

    /// Supplies a sampled monotonic-active timestamp for the immediately
    /// following instrumented scheduler transition. Sampling remains outside
    /// scheduler authority; regression is rejected before publication.
    pub(crate) fn observe_instrumentation_time_on(
        &self,
        cpu: SchedulerCpuId,
        now_ns: u64,
    ) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if state.instrumentation_now_ns[cpu_index].is_some_and(|previous| now_ns < previous) {
            return Err(SchedulerError::TimeRegression);
        }
        state.instrumentation_now_ns[cpu_index] = Some(now_ns);
        state.instrumentation_global_now_ns = Some(
            state
                .instrumentation_global_now_ns
                .map_or(now_ns, |global| global.max(now_ns)),
        );
        state.assert_invariants();
        Ok(())
    }

    /// Records an idle interval only after the architecture idle publisher has
    /// committed its exact generation. A scheduler rescan must never call this
    /// method merely because it observed no work.
    pub(crate) fn publish_idle_on(
        &self,
        cpu: SchedulerCpuId,
        started_at_ns: u64,
    ) -> Result<SchedulerIdleAccountingToken, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if state.running[cpu_index].is_some() {
            return Err(SchedulerError::CurrentThreadRunning);
        }
        if state.active_idle[cpu_index].is_some() {
            return Err(SchedulerError::IdleAccountingActive);
        }
        if state.instrumentation_now_ns[cpu_index].is_some_and(|previous| started_at_ns < previous)
        {
            return Err(SchedulerError::TimeRegression);
        }
        let generation = state.next_idle_generation;
        let next_generation = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let mut accounting = state.accounting;
        if let Err(error) = accounting.increment(cpu, SchedulerEvent::IdleEntry) {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        let token = SchedulerIdleAccountingToken {
            domain: state.domain,
            cpu,
            generation,
            started_at_ns,
        };
        state.next_idle_generation = next_generation;
        state.active_idle[cpu_index] = Some(token);
        state.instrumentation_now_ns[cpu_index] = Some(started_at_ns);
        state.instrumentation_global_now_ns = Some(
            state
                .instrumentation_global_now_ns
                .map_or(started_at_ns, |global| global.max(started_at_ns)),
        );
        state.accounting = accounting;
        state.record_trace(SchedulerTraceKind::IdleBegin, cpu, None, generation);
        state.assert_invariants();
        Ok(token)
    }

    /// Completes the exact architecture-published idle generation and charges
    /// its checked monotonic-active duration once.
    pub(crate) fn finish_idle_on(
        &self,
        token: SchedulerIdleAccountingToken,
        finished_at_ns: u64,
    ) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        if token.domain != state.domain
            || token.generation == 0
            || state.active_idle[token.cpu.index()] != Some(token)
        {
            return Err(SchedulerError::StaleIdleAccounting);
        }
        let cpu_index = token.cpu.index();
        if state.instrumentation_now_ns[cpu_index].is_some_and(|previous| finished_at_ns < previous)
        {
            return Err(SchedulerError::TimeRegression);
        }
        let elapsed_ns = finished_at_ns
            .checked_sub(token.started_at_ns)
            .ok_or(SchedulerError::TimeRegression)?;
        let mut accounting = state.accounting;
        if let Err(error) = accounting
            .counters_mut(token.cpu)
            .record_idle_time(elapsed_ns)
        {
            state.reject_accounting(accounting, error);
            return Err(error);
        }
        state.active_idle[cpu_index] = None;
        state.instrumentation_now_ns[cpu_index] = Some(finished_at_ns);
        state.instrumentation_global_now_ns = Some(
            state
                .instrumentation_global_now_ns
                .map_or(finished_at_ns, |global| global.max(finished_at_ns)),
        );
        state.accounting = accounting;
        state.record_trace(
            SchedulerTraceKind::IdleEnd,
            token.cpu,
            None,
            token.generation,
        );
        state.assert_invariants();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn trace_snapshot(
        &self,
    ) -> (
        [Option<SchedulerTraceRecord>; SCHEDULER_TRACE_CAPACITY],
        usize,
        usize,
    ) {
        let trace = self.state.lock().trace;
        (trace.records, trace.next, trace.len)
    }

    pub(crate) fn current_on(&self, cpu: SchedulerCpuId) -> Option<ThreadKey> {
        self.state.lock().running[cpu.index()].map(|claim| claim.thread)
    }

    pub(crate) fn running_cpu(&self, thread: ThreadKey) -> Option<SchedulerCpuId> {
        self.state.lock().running_cpu(thread)
    }

    pub(crate) fn running_claim_on(&self, cpu: SchedulerCpuId) -> Option<SchedulerExecutionClaim> {
        let state = self.state.lock();
        let claim = state.running[cpu.index()]?;
        Some(SchedulerExecutionClaim {
            domain: state.domain,
            cpu,
            thread: claim.thread,
            generation: claim.generation,
        })
    }

    pub(crate) fn suspended_claim_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> Option<SchedulerExecutionClaim> {
        let state = self.state.lock();
        let claim = state.suspended[cpu.index()]?;
        Some(SchedulerExecutionClaim {
            domain: state.domain,
            cpu,
            thread: claim.thread,
            generation: claim.generation,
        })
    }

    pub(crate) fn suspended_cpu(&self, thread: ThreadKey) -> Option<SchedulerCpuId> {
        self.state
            .lock()
            .suspended
            .iter()
            .position(|suspended| suspended.is_some_and(|owner| owner.thread == thread))
            .and_then(SchedulerCpuId::new)
    }

    pub(crate) fn validate_switch_on(
        &self,
        cpu: SchedulerCpuId,
        decision: ScheduleDecision,
    ) -> Result<(), SchedulerError> {
        let state = self.state.lock();
        let previous = decision.previous.ok_or(SchedulerError::NotRunning)?;
        let current = decision.current.ok_or(SchedulerError::NotRunning)?;
        if !state.running[cpu.index()].is_some_and(|claim| claim.thread == current) {
            return if state.running_cpu(current).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        }
        if state.suspended[cpu.index()].is_none_or(|owner| owner.thread != previous) {
            return Err(SchedulerError::ContinuationOwned);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn suspended_on(&self, cpu: SchedulerCpuId) -> Option<ThreadKey> {
        self.state.lock().suspended[cpu.index()].map(|suspended| suspended.thread)
    }

    // Temporary BSP adapters keep the pre-H2 target callers buildable while
    // the root integration lane migrates physical-current call sites.  They
    // must not be used after APs enter shared scheduling.
    pub(crate) fn schedule_next(&self) -> Result<ScheduleDecision, SchedulerError> {
        if let Some(suspended) = self.suspended_on_cpu(SchedulerCpuId::BOOTSTRAP) {
            return match self.schedule_from_idle(suspended)? {
                IdleScheduleDecision::ContinueIdle => Ok(ScheduleDecision {
                    previous: Some(suspended),
                    current: None,
                    cancelled_quantum: None,
                }),
                IdleScheduleDecision::ResumeCurrent => Ok(ScheduleDecision {
                    previous: Some(suspended),
                    current: Some(suspended),
                    cancelled_quantum: None,
                }),
                IdleScheduleDecision::Switch(decision) => Ok(decision),
            };
        }
        self.schedule_next_on(SchedulerCpuId::BOOTSTRAP)
    }

    pub(crate) fn yield_current(
        &self,
        thread: ThreadKey,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let decision = self.yield_current_on(SchedulerCpuId::BOOTSTRAP, thread)?;
        self.complete_bsp_model_switch(decision)?;
        Ok(decision)
    }

    pub(crate) fn prepare_block_current(
        &self,
        thread: ThreadKey,
    ) -> Result<BlockReservation, SchedulerError> {
        self.prepare_block_current_on(SchedulerCpuId::BOOTSTRAP, thread)
    }

    pub(crate) fn cancel_block(
        &self,
        reservation: BlockReservation,
    ) -> Result<(), BlockReservationFailure> {
        self.cancel_block_on(reservation.key.cpu, reservation)
    }

    pub(crate) fn commit_block(
        &self,
        reservation: BlockReservation,
    ) -> Result<ScheduleDecision, BlockReservationFailure> {
        let cpu = reservation.key.cpu;
        let decision = self.commit_block_on(cpu, reservation)?;
        if decision.current.is_some() {
            let claim = self
                .suspended_claim_on(cpu)
                .expect("block decision retains its outgoing execution claim");
            debug_assert_eq!(decision.previous, Some(claim.thread()));
            self.complete_switch_on(claim)
                .expect("BSP model switch completion follows a valid block decision");
        }
        Ok(decision)
    }

    pub(crate) fn block_current(
        &self,
        thread: ThreadKey,
    ) -> Result<(BlockToken, ScheduleDecision), SchedulerError> {
        let reservation = self.prepare_block_current(thread)?;
        let key = reservation.wake_key();
        match self.commit_block(reservation) {
            Ok(decision) => Ok((BlockToken { key }, decision)),
            Err(failure) => Err(failure.error()),
        }
    }

    pub(crate) fn schedule_from_idle(
        &self,
        suspended: ThreadKey,
    ) -> Result<IdleScheduleDecision, SchedulerError> {
        let decision = self.schedule_from_idle_on(SchedulerCpuId::BOOTSTRAP, suspended)?;
        if let IdleScheduleDecision::Switch(decision) = decision {
            self.complete_bsp_model_switch(decision)?;
        }
        Ok(decision)
    }

    pub(crate) fn retire(&self, thread: ThreadKey) -> Result<ScheduleDecision, SchedulerError> {
        if self
            .running_cpu(thread)
            .is_some_and(|cpu| cpu != SchedulerCpuId::BOOTSTRAP)
        {
            return Err(SchedulerError::WrongCpu);
        }
        let decision = self.retire_on(SchedulerCpuId::BOOTSTRAP, thread)?;
        self.complete_bsp_model_switch(decision)?;
        Ok(decision)
    }

    pub(crate) fn current(&self) -> Option<ThreadKey> {
        self.current_on(SchedulerCpuId::BOOTSTRAP)
    }

    fn complete_bsp_model_switch(&self, decision: ScheduleDecision) -> Result<(), SchedulerError> {
        if let Some(previous) = decision.previous
            && decision.previous != decision.current
        {
            let claim = self
                .suspended_claim_on(SchedulerCpuId::BOOTSTRAP)
                .ok_or(SchedulerError::StaleExecutionClaim)?;
            if claim.thread() != previous {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            self.complete_switch_on(claim)?;
        }
        Ok(())
    }

    fn suspended_on_cpu(&self, cpu: SchedulerCpuId) -> Option<ThreadKey> {
        self.state.lock().suspended[cpu.index()].map(|suspended| suspended.thread)
    }
}

#[cfg(test)]
#[path = "scheduler/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "scheduler/normal_policy_model.rs"]
mod normal_policy_model;
