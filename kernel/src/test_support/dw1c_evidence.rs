//! Selector-28-only kernel-owned DW1C evidence collector.
//!
//! This is deliberately not a scheduler ABI.  The only userspace input is a
//! ten-entry ARM table and five bounded progress acknowledgements; all facts
//! which make the transcript meaningful are captured by selector-local kernel
//! hooks.  Production builds never compile this module.

#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::ipc::ChannelEndpointKey;
use crate::object::ObjectId;
use crate::sync::SpinMutex;
use crate::task::{Dw1cFinalSchedulerSnapshot, ProcessKey, ThreadKey};
use deepwyrm_abi::DW_SIGNAL_WRITABLE;

pub(crate) const DW1C_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1c;
pub(crate) const DW1C_EVIDENCE_RECORD_LEN: usize = 96;
pub(crate) const DW1C_EVIDENCE_RECORD_CAPACITY: usize = 46;
#[cfg(test)]
const EMPTY: [u8; DW1C_EVIDENCE_RECORD_LEN] = [0; DW1C_EVIDENCE_RECORD_LEN];
pub(crate) const DW1C_ACTOR_COUNT: usize = 10;
pub(crate) const DW1C_ARM_BYTES: usize = DW1C_ACTOR_COUNT * 24;
pub(crate) const DW1C_ARM_TIMEOUT_SECONDS: u64 = 240;
pub(crate) const DW1C_ARM_TIMEOUT_NS: u64 =
    match DW1C_ARM_TIMEOUT_SECONDS.checked_mul(1_000_000_000) {
        Some(timeout_ns) => timeout_ns,
        None => panic!("DW1C ARM timeout does not fit nanoseconds"),
    };
/// A selector-private workload count is bounded to prevent a malformed raw
/// request from turning a progress acknowledgement into an unbounded value.
pub(crate) const DW1C_PROGRESS_MAX: u64 = u32::MAX as u64;
pub(crate) const DW1C_PROGRESS_MASK: u8 = 0x1f;
pub(crate) const DW1C_MIGRATION_REJECT_EXECUTION_PINNED: u8 = 0x04;
const DW1C_WAKE_GENERATION_MAX: u64 = 0x0000_ffff_ffff_ffff;
const DW1C_LIFECYCLE_ACTOR_FIRST: usize = 8;
const TERMINAL_EVENT: u8 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1cEvidenceError {
    Early,
    WrongReporter,
    Malformed,
    Duplicate,
    Full,
    Incomplete,
    Contradiction,
    WrongDigest,
    WrongActor,
    WrongGeneration,
    MissingKernelFact,
    TimeRegression,
    DeadlineExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Dw1cActor {
    pub(crate) token: u8,
    pub(crate) role: u8,
    pub(crate) process: ProcessKey,
    pub(crate) thread: ThreadKey,
    pub(crate) execution_generation: u64,
}

/// One private fixed-transcript payload. These values are retained exactly at
/// the commit point; serialization never synthesizes a relation later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Dw1cRecordPayload {
    pub(crate) subject: u64,
    pub(crate) generation: u64,
    pub(crate) value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProspectiveActor {
    process: ProcessKey,
    process_generation: u64,
    thread: Option<ThreadKey>,
    start_generation: Option<u64>,
    wait_generation: Option<u64>,
    process_ambiguous: bool,
    thread_ambiguous: bool,
    start_ambiguous: bool,
    wait_ambiguous: bool,
}

impl ProspectiveActor {
    const fn new(process: ProcessKey, process_generation: u64) -> Self {
        Self {
            process,
            process_generation,
            thread: None,
            start_generation: None,
            wait_generation: None,
            process_ambiguous: false,
            thread_ambiguous: false,
            start_ambiguous: false,
            wait_ambiguous: false,
        }
    }

    fn exact_started_identity(self, actor: Dw1cActor) -> bool {
        !self.process_ambiguous
            && !self.thread_ambiguous
            && !self.start_ambiguous
            && self.process == actor.process
            && self.thread == Some(actor.thread)
            && self.start_generation == Some(actor.execution_generation)
    }

    fn exact_pending_wait(self, actor: Dw1cActor) -> bool {
        self.exact_started_identity(actor)
            && !self.wait_ambiguous
            && self.wait_generation == Some(actor.execution_generation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Dw1cKernelFacts {
    /// One bit for each CPU 0..3 after ordinary scheduler admission.
    pub(crate) cpu_ready: u8,
    /// One bit for each CPU after a bound actor has held its Running claim.
    pub(crate) run: u8,
    /// One bit for each CPU after a matching local quantum expiry.
    pub(crate) quantum: u8,
    /// One bit for each CPU after the matching completed involuntary switch.
    pub(crate) preempt: u8,
    /// One bit for each remote-wake target CPU.
    pub(crate) remote_wake: u8,
    pub(crate) steal_migrate: bool,
    pub(crate) migration_reject_execution_pinned: bool,
    pub(crate) race_matrix: u8,
    pub(crate) lifecycle: u8,
    pub(crate) bootstrap_normal: bool,
    pub(crate) accounting_sound: bool,
    pub(crate) ready_delay_ns: u64,
}

impl Dw1cKernelFacts {
    const fn complete(self) -> bool {
        self.cpu_ready == 0x0f
            && self.run == 0x0f
            && self.quantum == 0x0f
            && self.preempt == 0x0f
            && self.remote_wake == 0x0f
            && self.steal_migrate
            && self.migration_reject_execution_pinned
            && self.race_matrix == DW1C_PROGRESS_MASK
            && self.lifecycle == 0x03
            && self.bootstrap_normal
            && self.accounting_sound
    }
}

struct State {
    installed: bool,
    reporter: Option<(ProcessKey, ThreadKey)>,
    prospective: [Option<ProspectiveActor>; DW1C_ACTOR_COUNT],
    actors: [Option<Dw1cActor>; DW1C_ACTOR_COUNT],
    progress: [u64; 5],
    arm_timeout_seconds: u64,
    arm_started_ns: Option<u64>,
    workload_complete: bool,
    cpu_ready_payload: [Option<Dw1cRecordPayload>; 4],
    run_payload: [Option<Dw1cRecordPayload>; 4],
    quantum_payload: [Option<Dw1cRecordPayload>; 4],
    preempt_payload: [Option<Dw1cRecordPayload>; 4],
    remote_wake_payload: [Option<Dw1cRecordPayload>; 4],
    steal_migrate_payload: Option<Dw1cRecordPayload>,
    migration_reject_payload: Option<Dw1cRecordPayload>,
    race_matrix_payload: Option<Dw1cRecordPayload>,
    exit_payload: [Option<Dw1cRecordPayload>; 2],
    reap_payload: [Option<Dw1cRecordPayload>; 2],
    lifecycle_process_generation: [Option<u64>; 2],
    ready_delay_payload: Option<Dw1cRecordPayload>,
    bootstrap_normal_payload: Option<Dw1cRecordPayload>,
    accounting_sound_payload: Option<Dw1cRecordPayload>,
    next_primordial_completion_token: u64,
    token6_wait_joined: bool,
    token6_wake_seen: bool,
    token6_wake_identity: Option<(u8, u8, u64, u64)>,
    token6_run_seen: bool,
    cpu_chain: [CpuChain; 4],
    arm_boundary_quantum_allowed: [bool; 4],
    token8_pending_expiry: Option<(u8, u64, u64)>,
    token8_terminal: Option<(u8, u64, u64)>,
    token7: Option<Token7Flight>,
    facts: Dw1cKernelFacts,
    terminal: bool,
    failure: Option<Dw1cEvidenceError>,
}

/// One bounded, not-yet-committed per-CPU transcript candidate. The public
/// selector transcript is filled only when an exact completed switch joins a
/// RUN and its published quantum expiry. Incomplete or surplus live activity
/// therefore cannot occupy one of the fixed evidence records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CpuChain {
    Empty,
    Run {
        token: u8,
        execution_generation: u64,
        serializable: bool,
    },
    Quantum {
        token: u8,
        execution_generation: u64,
        source_arm_generation: u64,
        serializable: bool,
    },
}

/// The selector-owned Channel is deliberately bound only after ARM, from the
/// exact token-7 caller's first failed capacity reservation.  The raw ARM
/// table names actors, not arbitrary object IDs, so retaining this small
/// generation-safe join avoids adding a selector ABI object-id encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Token7Flight {
    endpoint: ChannelEndpointKey,
    peer: ObjectId,
    wake_token: Option<u64>,
    blocked_execution_generation: Option<u64>,
    blocked: bool,
    wake_seen: bool,
    run_seen: bool,
}

impl State {
    const fn new() -> Self {
        Self {
            installed: false,
            reporter: None,
            prospective: [None; DW1C_ACTOR_COUNT],
            actors: [None; DW1C_ACTOR_COUNT],
            progress: [0; 5],
            arm_timeout_seconds: 0,
            arm_started_ns: None,
            workload_complete: false,
            cpu_ready_payload: [None; 4],
            run_payload: [None; 4],
            quantum_payload: [None; 4],
            preempt_payload: [None; 4],
            remote_wake_payload: [None; 4],
            steal_migrate_payload: None,
            migration_reject_payload: None,
            race_matrix_payload: None,
            exit_payload: [None; 2],
            reap_payload: [None; 2],
            lifecycle_process_generation: [None; 2],
            ready_delay_payload: None,
            bootstrap_normal_payload: None,
            accounting_sound_payload: None,
            next_primordial_completion_token: 1,
            token6_wait_joined: false,
            token6_wake_seen: false,
            token6_wake_identity: None,
            token6_run_seen: false,
            cpu_chain: [CpuChain::Empty; 4],
            arm_boundary_quantum_allowed: [false; 4],
            token8_pending_expiry: None,
            token8_terminal: None,
            token7: None,
            facts: Dw1cKernelFacts {
                cpu_ready: 0,
                run: 0,
                quantum: 0,
                preempt: 0,
                remote_wake: 0,
                steal_migrate: false,
                migration_reject_execution_pinned: false,
                race_matrix: 0,
                lifecycle: 0,
                bootstrap_normal: false,
                accounting_sound: false,
                ready_delay_ns: 0,
            },
            terminal: false,
            failure: None,
        }
    }
    fn latch(&mut self, error: Dw1cEvidenceError) -> Dw1cEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }

    fn scheduler_observation_closed(&self) -> bool {
        self.failure.is_some() || self.terminal
    }
}

/// Fixed selector-private collector.  It retains identity values, never task
/// object pins, so the two lifecycle actors may still exit and reap normally.
pub(crate) struct Dw1cEvidenceCollector {
    state: SpinMutex<State>,
    nonce: u64,
    digest: u64,
    terminal: AtomicU8,
}

pub(crate) fn decode_arm_entries(
    bytes: &[u8; DW1C_ARM_BYTES],
) -> Result<[(u64, u64, u64); DW1C_ACTOR_COUNT], Dw1cEvidenceError> {
    let mut entries = [(0, 0, 0); DW1C_ACTOR_COUNT];
    let mut index = 0;
    while index < DW1C_ACTOR_COUNT {
        let offset = index * 24;
        let read =
            |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed ARM slice"));
        entries[index] = (read(offset), read(offset + 8), read(offset + 16));
        index += 1;
    }
    Ok(entries)
}

impl Dw1cEvidenceCollector {
    pub(crate) const fn new(nonce: u64, digest: u64) -> Self {
        assert!(
            nonce != 0 && digest != 0,
            "DW1C build bindings must be nonzero"
        );
        Self {
            state: SpinMutex::new(State::new()),
            nonce,
            digest,
            terminal: AtomicU8::new(0),
        }
    }

    /// Installed before the selector's controller is allowed to return to
    /// userspace. CPU admission is the one pre-install relation because all
    /// carriers become scheduler-capable before the first selector process can
    /// install workload observation. A second installation is terminal.
    pub(crate) fn install(&self) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.installed || state.failure.is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        state.installed = true;
        Ok(())
    }

    /// Retains a bounded prospective Process identity only after selector
    /// installation. Capacity overflow is ignored here and therefore fails
    /// closed later if ARM names an identity whose CREATE fact was not kept.
    pub(crate) fn observe_process_create(
        &self,
        process: ProcessKey,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !state.installed {
            return Ok(());
        }
        let bound_actor = state
            .actors
            .iter()
            .flatten()
            .any(|actor| actor.process == process);
        if let Some(prospective) = state
            .prospective
            .iter_mut()
            .flatten()
            .find(|prospective| prospective.process == process)
        {
            if bound_actor {
                return Err(state.latch(Dw1cEvidenceError::Duplicate));
            }
            prospective.process_ambiguous = true;
            return Ok(());
        }
        let Some(slot) = state.prospective.iter_mut().find(|slot| slot.is_none()) else {
            return Ok(());
        };
        let generation = process.object_id().generation();
        if generation == 0 {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        *slot = Some(ProspectiveActor::new(process, generation));
        Ok(())
    }

    /// Joins a committed Thread CREATE to an already observed Process. A
    /// second Thread does not poison unrelated work globally, but makes that
    /// Process ineligible for exact selector ARM binding.
    pub(crate) fn observe_thread_create(
        &self,
        process: ProcessKey,
        thread: ThreadKey,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !state.installed {
            return Ok(());
        }
        if state.reporter.is_some() {
            // ARM authenticates one exact Thread per actor Process; it does
            // not prohibit that Process from creating unrelated Threads.
            return Ok(());
        }
        let Some(prospective) = state
            .prospective
            .iter_mut()
            .flatten()
            .find(|prospective| prospective.process == process)
        else {
            return Ok(());
        };
        if prospective.thread.is_some() {
            prospective.thread_ambiguous = true;
        } else {
            prospective.thread = Some(thread);
        }
        Ok(())
    }

    /// Retains the exact scheduler-owned generation only after START has
    /// committed. Unknown production Threads remain invisible to the selector.
    pub(crate) fn observe_thread_start(
        &self,
        process: ProcessKey,
        thread: ThreadKey,
        execution_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !state.installed {
            return Ok(());
        }
        if state.reporter.is_some() {
            if let Some(actor) = state
                .actors
                .iter()
                .flatten()
                .find(|actor| actor.process == process)
            {
                if actor.thread != thread {
                    return Ok(());
                }
                let error = if actor.thread == thread
                    && actor.execution_generation == execution_generation
                {
                    Dw1cEvidenceError::Duplicate
                } else {
                    Dw1cEvidenceError::WrongGeneration
                };
                return Err(state.latch(error));
            }
            return Ok(());
        }
        let Some(prospective) = state
            .prospective
            .iter_mut()
            .flatten()
            .find(|prospective| prospective.process == process)
        else {
            return Ok(());
        };
        if prospective.thread != Some(thread)
            || execution_generation == 0
            || prospective.start_generation.is_some()
        {
            prospective.start_ambiguous = true;
        } else {
            prospective.start_generation = Some(execution_generation);
        }
        Ok(())
    }

    /// Remembers a committed pre-ARM Blocked claim. The identity is retained
    /// without a task pin, so ARM can later prove token 6 names that existing
    /// GO wait rather than a userspace-supplied generation.
    pub(crate) fn observe_bound_wait_claim(
        &self,
        thread: ThreadKey,
        execution_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !state.installed {
            return Ok(());
        }
        if state.reporter.is_some() {
            return Ok(());
        }
        let Some(prospective) = state
            .prospective
            .iter_mut()
            .flatten()
            .find(|prospective| prospective.thread == Some(thread))
        else {
            return Ok(());
        };
        if prospective.start_generation != Some(execution_generation)
            || prospective.wait_generation.is_some()
        {
            prospective.wait_ambiguous = true;
        } else {
            prospective.wait_generation = Some(execution_generation);
        }
        Ok(())
    }

    pub(crate) fn arm(
        &self,
        reporter: (ProcessKey, ThreadKey),
        product_execution_generation: u64,
        actors: [Dw1cActor; DW1C_ACTOR_COUNT],
        arm_started_ns: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.failure.is_some() || state.reporter.is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        if product_execution_generation == 0 {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        for (index, actor) in actors.iter().enumerate() {
            if actor.token as usize != index + 1
                || actor.role as usize != index + 1
                || actor.process == reporter.0
                || actor.thread == reporter.1
                || actor.execution_generation == 0
                || actors[..index]
                    .iter()
                    .any(|prior| prior.process == actor.process || prior.thread == actor.thread)
            {
                return Err(state.latch(Dw1cEvidenceError::Malformed));
            }
        }
        let token6 = actors[5];
        let token6_wait_joined = state
            .prospective
            .iter()
            .flatten()
            .any(|prospective| prospective.exact_pending_wait(token6));
        if !token6_wait_joined {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        let mut lifecycle_generations = [None; 2];
        for (lifecycle_index, actor) in actors[DW1C_LIFECYCLE_ACTOR_FIRST..]
            .iter()
            .copied()
            .enumerate()
        {
            let Some(prospective) = state
                .prospective
                .iter()
                .flatten()
                .find(|prospective| prospective.exact_started_identity(actor))
            else {
                return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
            };
            lifecycle_generations[lifecycle_index] = Some(prospective.process_generation);
        }
        state.reporter = Some(reporter);
        state.arm_timeout_seconds = DW1C_ARM_TIMEOUT_SECONDS;
        state.arm_started_ns = Some(arm_started_ns);
        state.token6_wait_joined = token6_wait_joined;
        state.lifecycle_process_generation = lifecycle_generations;
        state.arm_boundary_quantum_allowed = [true; 4];
        for (slot, actor) in state.actors.iter_mut().zip(actors) {
            *slot = Some(actor);
        }
        Ok(())
    }

    /// Concrete scheduler commit-point callbacks. Only an ARM-bound execution
    /// identity may fill a fixed witness. Scheduler-validated later activity
    /// is consumed through a non-serializing chain regardless of whether that
    /// CPU's fixed slot is already complete. The scheduler keeps its lock;
    /// this collector takes its own bounded lock only after the scheduler
    /// transition has committed.
    /// Scheduler-facing variant: a scheduler owns only the exact Thread and
    /// execution claim.  The collector resolves that tuple against its ARM
    /// table, preserving Process ownership inside the test-private boundary.
    pub(crate) fn observe_running_claim(
        &self,
        cpu: u8,
        thread: ThreadKey,
        generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_claim(cpu, thread, generation, u64::from(cpu), 0)
    }

    /// Execution hooks use this to filter global scheduler activity. Direct
    /// actor-specific observer calls deliberately reject unknown subjects.
    pub(crate) fn tracks_thread(&self, thread: ThreadKey) -> bool {
        let state = self.state.lock();
        state.installed
            && !state.scheduler_observation_closed()
            && actor_thread_known(&state, thread)
    }

    /// Global IPC activity is intentionally filtered before the strict
    /// token-7 observers below.  Only the exact post-ARM actor may bind or
    /// advance the selector-owned Channel flight.
    pub(crate) fn tracks_token7_actor(&self, process: ProcessKey, thread: ThreadKey) -> bool {
        let state = self.state.lock();
        state.installed
            && !state.scheduler_observation_closed()
            && state
                .actors
                .get(6)
                .and_then(|actor| *actor)
                .is_some_and(|actor| actor.process == process && actor.thread == thread)
    }

    pub(crate) fn tracks_token7_thread(&self, thread: ThreadKey) -> bool {
        let state = self.state.lock();
        state.installed
            && !state.scheduler_observation_closed()
            && state
                .actors
                .get(6)
                .and_then(|actor| *actor)
                .is_some_and(|actor| actor.thread == thread)
    }

    /// Binds the selector-owned endpoint on the exact token-7 Process/Thread
    /// first post-ARM send that fails solely because its peer queue is full.
    /// The caller has already released Channel and object-authority pins.
    pub(crate) fn observe_token7_full_send(
        &self,
        process: ProcessKey,
        thread: ThreadKey,
        endpoint: ChannelEndpointKey,
        peer: ObjectId,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !state.installed || state.reporter.is_none() {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if !state
            .actors
            .get(6)
            .and_then(|actor| *actor)
            .is_some_and(|actor| actor.process == process && actor.thread == thread)
        {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        if endpoint.object_id() == peer {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if state.token7.is_some() {
            // The hook observes every capacity failure made by token 7. The
            // first one binds the private flight; retries and unrelated later
            // full Channels are ordinary userspace activity.
            return Ok(());
        }
        state.token7 = Some(Token7Flight {
            endpoint,
            peer,
            wake_token: None,
            blocked_execution_generation: None,
            blocked: false,
            wake_seen: false,
            run_seen: false,
        });
        Ok(())
    }

    /// Records the scheduler-committed blocked state for the one registered,
    /// exact-WRITABLE wait on token 7's bound endpoint.  `begin_registered_wait`
    /// calls this only after both WaitSet registration and scheduler block
    /// commit have completed.
    pub(crate) fn observe_token7_writable_block(
        &self,
        thread: ThreadKey,
        generation: u64,
        endpoint: ChannelEndpointKey,
        wake_token: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        let Some(actor) = state.actors.get(6).and_then(|actor| *actor) else {
            return Err(state.latch(Dw1cEvidenceError::Early));
        };
        if actor.thread != thread || generation == 0 {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        let Some(flight) = state.token7.as_mut() else {
            return Ok(());
        };
        if flight.endpoint != endpoint || flight.run_seen {
            return Ok(());
        }
        if wake_token == 0 {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if flight.blocked
            || flight.wake_token.is_some()
            || flight.blocked_execution_generation.is_some()
        {
            if flight.blocked_execution_generation == Some(generation)
                && flight.wake_token == Some(wake_token)
            {
                return Ok(());
            }
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
        flight.wake_token = Some(wake_token);
        flight.blocked_execution_generation = Some(generation);
        flight.blocked = true;
        Ok(())
    }

    /// Records only a capacity-producing receive on token 7's exact peer,
    /// after it won the exact blocked-operation generation and scheduler wake
    /// mutation succeeded.  A close, an unrelated peer, signal, or wake key
    /// cannot advance this join.
    pub(crate) fn observe_token7_peer_drain_wake(
        &self,
        thread: ThreadKey,
        generation: u64,
        drained_peer: ChannelEndpointKey,
        wake_token: u64,
        observed: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        let Some(actor) = state.actors.get(6).and_then(|actor| *actor) else {
            return Err(state.latch(Dw1cEvidenceError::Early));
        };
        if actor.thread != thread || generation == 0 {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        let Some(flight) = state.token7.as_mut() else {
            return Ok(());
        };
        if flight.run_seen
            || flight.peer != drained_peer.object_id()
            || flight.wake_token != Some(wake_token)
            || flight.blocked_execution_generation != Some(generation)
        {
            return Ok(());
        }
        if !flight.blocked || observed & DW_SIGNAL_WRITABLE.0 == 0 || flight.wake_seen {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
        flight.wake_seen = true;
        Ok(())
    }

    pub(crate) fn observe_quantum_claim(
        &self,
        cpu: u8,
        thread: ThreadKey,
        generation: u64,
        source_arm_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_claim(cpu, thread, generation, source_arm_generation, 1)
    }

    pub(crate) fn observe_preemption_claim(
        &self,
        cpu: u8,
        thread: ThreadKey,
        generation: u64,
        completed_switch_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_claim(cpu, thread, generation, completed_switch_generation, 2)
    }

    /// Consumes one scheduler-published expiry that a committed non-preemptive
    /// transition superseded. This closes only the live CPU chain; an already
    /// selected fixed witness remains immutable.
    pub(crate) fn observe_consumed_quantum_claim(
        &self,
        cpu: u8,
        thread: ThreadKey,
        generation: u64,
        source_arm_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        let token = actor_token_for_thread(&state, thread)
            .ok_or_else(|| state.latch(Dw1cEvidenceError::WrongActor))?;
        consume_published_quantum(&mut state, cpu, token, generation, source_arm_generation)
    }

    pub(crate) fn observe_remote_wake_claim(
        &self,
        source_cpu: u8,
        target_cpu: u8,
        thread: ThreadKey,
        generation: u64,
        wake_generation: u64,
    ) -> Result<Option<u8>, Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.scheduler_observation_closed() {
            return Ok(None);
        }
        let bit = cpu_bit(target_cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        if cpu_bit(source_cpu).is_none()
            || wake_generation == 0
            || wake_generation > DW1C_WAKE_GENERATION_MAX
        {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        let token = actor_token_for_thread(&state, thread)
            .expect("known remote-wake thread retains its selector token");
        let exact_bound_generation = actor_thread_bound(&state, thread, generation);
        if token == 8 && state.token8_terminal.is_some() {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
        // The scheduler may publish many independent actor wakes to the same
        // CPU, and a requester may wake an actor locally.  Those are valid
        // scheduler transitions, while the fixed transcript retains only the
        // first distinct remote relation for each target CPU.  Token 6's race
        // join remains independent of whether its wake owns that record slot.
        if source_cpu == target_cpu {
            if !exact_bound_generation {
                return Ok(None);
            }
            return observe_token6_wake(
                &mut state,
                token,
                (source_cpu, target_cpu, generation, wake_generation),
            )
            .map(|observed| observed.then_some(token));
        }
        let index = usize::from(target_cpu);
        let target_occupied = match (
            state.facts.remote_wake & bit != 0,
            state.remote_wake_payload[index],
        ) {
            (true, Some(_)) => true,
            (false, None) => false,
            _ => return Err(state.latch(Dw1cEvidenceError::Contradiction)),
        };
        let value = u64::from(target_cpu) | (u64::from(source_cpu) << 8) | (wake_generation << 16);
        let payload = Dw1cRecordPayload {
            subject: u64::from(token),
            generation,
            value,
        };
        if let Some(existing) = state
            .remote_wake_payload
            .iter()
            .flatten()
            .find(|existing| existing.value >> 16 == wake_generation)
        {
            let error = if *existing == payload {
                Dw1cEvidenceError::Duplicate
            } else {
                Dw1cEvidenceError::Contradiction
            };
            return Err(state.latch(error));
        }
        if !exact_bound_generation {
            return Ok(None);
        }
        let token6_observed = if exact_bound_generation {
            observe_token6_wake(
                &mut state,
                token,
                (source_cpu, target_cpu, generation, wake_generation),
            )?
        } else {
            false
        };
        if target_occupied {
            return Ok(token6_observed.then_some(token));
        }
        state.remote_wake_payload[index] = Some(payload);
        state.facts.remote_wake |= bit;
        Ok((token != 6 || token6_observed).then_some(token))
    }

    pub(crate) fn observe_steal_migration_claim(
        &self,
        source_cpu: u8,
        target_cpu: u8,
        thread: ThreadKey,
        execution_generation: u64,
        migration_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        if source_cpu == target_cpu
            || cpu_bit(source_cpu).is_none()
            || cpu_bit(target_cpu).is_none()
            || migration_generation == 0
        {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        let token = actor_token_for_thread(&state, thread)
            .expect("known migration thread retains its selector token");
        if token == 8 && state.token8_terminal.is_some() {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
        let payload = Dw1cRecordPayload {
            subject: u64::from(token),
            generation: migration_generation,
            value: u64::from(target_cpu) | (u64::from(source_cpu) << 8),
        };
        match (state.facts.steal_migrate, state.steal_migrate_payload) {
            (true, Some(existing)) => {
                if existing == payload {
                    return Err(state.latch(Dw1cEvidenceError::Duplicate));
                }
                if existing.generation == migration_generation {
                    return Err(state.latch(Dw1cEvidenceError::Contradiction));
                }
                return Ok(());
            }
            (false, None) => {}
            _ => return Err(state.latch(Dw1cEvidenceError::Contradiction)),
        }
        if !actor_thread_bound(&state, thread, execution_generation) {
            // A valid later continuation may migrate before the one fixed ARM
            // witness has been selected. It is non-serializing surplus.
            return Ok(());
        }
        state.steal_migrate_payload = Some(payload);
        state.facts.steal_migrate = true;
        Ok(())
    }

    pub(crate) fn observe_migration_rejection_claim(
        &self,
        cpu: u8,
        thread: ThreadKey,
        execution_generation: u64,
        reason: u8,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        let token = actor_token_for_thread(&state, thread)
            .expect("known migration-rejection thread retains its selector token");
        if token != 6 || cpu_bit(cpu).is_none() || reason != DW1C_MIGRATION_REJECT_EXECUTION_PINNED
        {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        let payload = Dw1cRecordPayload {
            subject: u64::from(token),
            generation: execution_generation,
            value: u64::from(cpu) | (u64::from(reason) << 8),
        };
        match (
            state.facts.migration_reject_execution_pinned,
            state.migration_reject_payload,
        ) {
            (true, Some(existing)) if existing == payload => {
                return Err(state.latch(Dw1cEvidenceError::Duplicate));
            }
            (true, Some(existing)) if existing.generation == execution_generation => {
                return Err(state.latch(Dw1cEvidenceError::Contradiction));
            }
            (true, Some(_)) if execution_generation != 0 => return Ok(()),
            (false, None) => {}
            _ => return Err(state.latch(Dw1cEvidenceError::Contradiction)),
        }
        if !actor_thread_bound(&state, thread, execution_generation) {
            return if execution_generation == 0 {
                Err(state.latch(Dw1cEvidenceError::WrongGeneration))
            } else {
                Ok(())
            };
        }
        state.migration_reject_payload = Some(payload);
        state.facts.migration_reject_execution_pinned = true;
        Ok(())
    }

    /// Consumes any tracked actor's already-published expiry after terminal
    /// retirement commits. Token 8 additionally selects the special terminal
    /// race witness. `absent_after_commit` is sampled while the retirement is
    /// still exact; later token-8 RUN/requeue observations are contradictions.
    pub(crate) fn observe_terminal_preemption_claim(
        &self,
        cpu: u8,
        thread: ThreadKey,
        generation: u64,
        source_arm_generation: u64,
        absent_after_commit: bool,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        let token = actor_token_for_thread(&state, thread)
            .expect("known terminal-preemption Thread retains its selector token");
        if cpu_bit(cpu).is_none() {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if !absent_after_commit {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
        consume_published_quantum(&mut state, cpu, token, generation, source_arm_generation)?;
        if token != 8 {
            return Ok(());
        }
        if state.token8_terminal.is_some() {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
        state.token8_terminal = Some((cpu, generation, source_arm_generation));
        state.facts.race_matrix |= 1 << 2;
        Ok(())
    }

    /// Records the normal Process-exit commit for lifecycle actors only. The
    /// terminal execution generation is sampled from the live claim before
    /// TaskAuthority commits, then joined here immediately after that commit.
    /// The authoritative caller has already proven that the current Thread
    /// belongs to this Process; it need not be the Thread originally bound by
    /// ARM because a valid multi-Thread Process may exit from another member.
    pub(crate) fn observe_process_exit(
        &self,
        process: ProcessKey,
        _thread: ThreadKey,
        terminal_thread_generation: u64,
        code: u32,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !state.installed {
            return Ok(());
        }
        let Some(actor) = state
            .actors
            .iter()
            .flatten()
            .copied()
            .find(|actor| actor.process == process)
        else {
            return Ok(());
        };
        if actor.token < 9 {
            return Ok(());
        }
        if actor.token > 10 || code != 0 {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if terminal_thread_generation == 0 {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        let index = usize::from(actor.token - 9);
        if state.exit_payload[index].is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        state.exit_payload[index] = Some(Dw1cRecordPayload {
            subject: u64::from(actor.token),
            generation: terminal_thread_generation,
            value: 0,
        });
        if state.exit_payload.iter().all(Option::is_some) {
            state.facts.lifecycle |= 0x01;
        }
        Ok(())
    }

    /// Records one final root retirement only after teardown and finalizer
    /// drain. Process generation is checked against the private CREATE/ARM
    /// bind. Each reap requires that same actor's exit. Observation order is
    /// independent of fixed EXIT(9,10), REAP(9,10) serialization.
    pub(crate) fn observe_process_reap(
        &self,
        process: ProcessKey,
        process_generation: u64,
        count: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !state.installed {
            return Ok(());
        }
        let Some(actor) = state
            .actors
            .iter()
            .flatten()
            .copied()
            .find(|actor| actor.process == process)
        else {
            return Ok(());
        };
        if actor.token < 9 {
            return Ok(());
        }
        if actor.token > 10 || count != 1 {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if process.object_id().generation() != process_generation {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        let index = usize::from(actor.token - 9);
        if state.reap_payload[index].is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        if state.exit_payload[index].is_none() {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        if state.lifecycle_process_generation[index] != Some(process_generation) {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        state.reap_payload[index] = Some(Dw1cRecordPayload {
            subject: u64::from(actor.token),
            generation: process_generation,
            value: count,
        });
        if state.reap_payload.iter().all(Option::is_some) {
            state.facts.lifecycle |= 0x02;
            state.facts.race_matrix |= 1 << 3;
        }
        Ok(())
    }

    pub(crate) fn observe_cpu_ready_payload(
        &self,
        cpu: u8,
        subject: u64,
        generation: u64,
        value: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        let index = usize::from(cpu);
        let bit = cpu_bit(cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
        if subject == 0 || generation == 0 || value == 0 || state.cpu_ready_payload[index].is_some()
        {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        state.cpu_ready_payload[index] = Some(Dw1cRecordPayload {
            subject,
            generation,
            value,
        });
        state.facts.cpu_ready |= bit;
        Ok(())
    }

    fn observe_cpu_claim(
        &self,
        cpu: u8,
        thread: ThreadKey,
        generation: u64,
        value: u64,
        kind: u8,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        let exact_bound_generation = actor_thread_bound(&state, thread, generation);
        let known_token = actor_token_for_thread(&state, thread)
            .expect("known CPU-claim thread retains its selector token");
        if kind == 0 && known_token == 7 && !exact_bound_generation {
            if let Some(flight) = state.token7.as_mut() {
                if flight.blocked_execution_generation == Some(generation) {
                    if !flight.blocked || !flight.wake_seen || flight.wake_token.is_none() {
                        return Err(state.latch(Dw1cEvidenceError::Contradiction));
                    }
                    flight.run_seen = true;
                    update_race_bit_one(&mut state);
                    return Ok(());
                }
            }
        }
        let token = actor_token_for_claim(&state, thread, generation)
            .or_else(|| (generation != 0).then_some(known_token));
        let Some(token) = token else {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        };
        retain_cpu_payload(
            &mut state,
            cpu,
            token,
            generation,
            value,
            kind,
            exact_bound_generation,
        )
    }

    pub(crate) fn progress(
        &self,
        caller: ProcessKey,
        token: u64,
        count: u64,
        digest: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        let index = token
            .checked_sub(1)
            .filter(|index| *index < 5)
            .ok_or_else(|| state.latch(Dw1cEvidenceError::WrongActor))?
            as usize;
        if digest != self.digest {
            return Err(state.latch(Dw1cEvidenceError::WrongDigest));
        }
        let Some(actor) = state.actors[index] else {
            return Err(state.latch(Dw1cEvidenceError::Early));
        };
        if caller != actor.process {
            return Err(state.latch(Dw1cEvidenceError::WrongReporter));
        }
        if count == 0 || count > DW1C_PROGRESS_MAX || state.progress[index] != 0 {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        state.progress[index] = count;
        update_race_bit_zero(&mut state);
        Ok(())
    }

    /// Accepts userspace's one correlation-only workload completion. This
    /// never claims terminal authority and cannot serialize or debug-exit.
    pub(crate) fn workload_complete(
        &self,
        caller: ProcessKey,
        mask: u64,
        digest: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.scheduler_observation_closed() {
            return Ok(());
        }
        if state.reporter.map(|reporter| reporter.0) != Some(caller) {
            return Err(state.latch(Dw1cEvidenceError::WrongReporter));
        }
        if state.arm_timeout_seconds != DW1C_ARM_TIMEOUT_SECONDS {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if state.workload_complete || state.terminal {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        if digest != self.digest {
            return Err(state.latch(Dw1cEvidenceError::WrongDigest));
        }
        if mask != u64::from(DW1C_PROGRESS_MASK) {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if state.progress.contains(&0) {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        state.workload_complete = true;
        Ok(())
    }

    /// Joins the genuine normal primordial completion to the already accepted
    /// workload and one exact scheduler snapshot. Only this path may claim the
    /// terminal flush permit.
    pub(crate) fn final_normal_completion(
        &self,
        completed_at_ns: u64,
        product_execution_generation: u64,
        snapshot: Dw1cFinalSchedulerSnapshot,
    ) -> Result<Dw1cEvidenceFlushPermit<'_>, Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if let Some(error) = state.failure {
            return Err(error);
        }
        if state.terminal {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        if !state.workload_complete {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        let Some(started_at_ns) = state.arm_started_ns else {
            return Err(state.latch(Dw1cEvidenceError::Early));
        };
        let elapsed_ns = match completed_at_ns.checked_sub(started_at_ns) {
            Some(elapsed_ns) => elapsed_ns,
            None => return Err(state.latch(Dw1cEvidenceError::TimeRegression)),
        };
        if elapsed_ns > DW1C_ARM_TIMEOUT_NS {
            return Err(state.latch(Dw1cEvidenceError::DeadlineExceeded));
        }
        if product_execution_generation == 0 {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        if snapshot.token() == 0
            || snapshot.generation() == 0
            || snapshot.accounting_mask() != 0x3f
            || state.facts.cpu_ready != 0x0f
            || state.facts.run != 0x0f
            || state.facts.quantum != 0x0f
            || state.facts.preempt != 0x0f
            || state.facts.remote_wake != 0x0f
            || !state.facts.steal_migrate
            || !state.facts.migration_reject_execution_pinned
            || state.facts.race_matrix != 0x0f
            || state.facts.lifecycle != 0x03
            || state.facts.bootstrap_normal
            || state.facts.accounting_sound
            || state.facts.ready_delay_ns != 0
            || state.race_matrix_payload.is_some()
            || state.ready_delay_payload.is_some()
            || state.bootstrap_normal_payload.is_some()
            || state.accounting_sound_payload.is_some()
        {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        let Some(token8) = state.actors[7] else {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        };
        let completion_token = state.next_primordial_completion_token;
        let Some(next_completion_token) = completion_token.checked_add(1).filter(|next| *next != 0)
        else {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        };
        if completion_token == 0 {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        state.race_matrix_payload = Some(Dw1cRecordPayload {
            subject: 8,
            generation: token8.execution_generation,
            value: u64::from(DW1C_PROGRESS_MASK),
        });
        // Records 42 and 44 share this selector-local scheduler-snapshot
        // identity. It is deliberately not an actor token or generation.
        state.ready_delay_payload = Some(Dw1cRecordPayload {
            subject: snapshot.token(),
            generation: snapshot.generation(),
            value: snapshot.max_ready_delay_ns(),
        });
        state.bootstrap_normal_payload = Some(Dw1cRecordPayload {
            subject: completion_token,
            generation: product_execution_generation,
            value: 0,
        });
        state.accounting_sound_payload = Some(Dw1cRecordPayload {
            subject: snapshot.token(),
            generation: snapshot.generation(),
            value: u64::from(snapshot.accounting_mask()),
        });
        state.next_primordial_completion_token = next_completion_token;
        state.facts.race_matrix |= 1 << 4;
        state.facts.ready_delay_ns = snapshot.max_ready_delay_ns();
        state.facts.bootstrap_normal = true;
        state.facts.accounting_sound = true;
        if !state.facts.complete() {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        for sequence in 0..DW1C_EVIDENCE_RECORD_CAPACITY {
            if payload_for(sequence, &state).is_err() {
                return Err(state.latch(Dw1cEvidenceError::Incomplete));
            }
        }
        if self
            .terminal
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
            || state.terminal
        {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        state.terminal = true;
        Ok(Dw1cEvidenceFlushPermit { collector: self })
    }

    fn flush(
        &self,
        write: impl FnMut(&[u8; DW1C_EVIDENCE_RECORD_LEN]) -> Result<(), ()>,
    ) -> Result<(), Dw1cEvidenceError> {
        let state = self.state.lock();
        if state.failure.is_some()
            || !state.workload_complete
            || !state.terminal
            || !state.facts.complete()
        {
            return Err(Dw1cEvidenceError::Incomplete);
        }
        let mut write = write;
        for sequence in 0..DW1C_EVIDENCE_RECORD_CAPACITY {
            let payload = payload_for(sequence, &state)?;
            let record = encode_record(self.nonce, sequence as u32, event_for(sequence), payload);
            write(&record).map_err(|_| Dw1cEvidenceError::Full)?;
        }
        Ok(())
    }
}

fn cpu_bit(cpu: u8) -> Option<u8> {
    (cpu < 4).then(|| 1_u8 << cpu)
}

fn observe_token6_wake(
    state: &mut State,
    token: u8,
    identity: (u8, u8, u64, u64),
) -> Result<bool, Dw1cEvidenceError> {
    if token != 6 {
        return Ok(false);
    }
    if !state.token6_wait_joined {
        return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
    }
    if let Some(existing) = state.token6_wake_identity {
        return if existing == identity {
            Err(state.latch(Dw1cEvidenceError::Duplicate))
        } else {
            Ok(false)
        };
    }
    state.token6_wake_seen = true;
    state.token6_wake_identity = Some(identity);
    update_race_bit_zero(state);
    Ok(true)
}

fn consume_published_quantum(
    state: &mut State,
    cpu: u8,
    token: u8,
    execution_generation: u64,
    source_arm_generation: u64,
) -> Result<(), Dw1cEvidenceError> {
    cpu_bit(cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
    if execution_generation == 0 || source_arm_generation == 0 {
        return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
    }
    let index = usize::from(cpu);
    if !matches!(
        state.cpu_chain[index],
        CpuChain::Quantum {
            token: quantum_token,
            execution_generation: quantum_generation,
            source_arm_generation: quantum_source,
            ..
        } if quantum_token == token
            && quantum_generation == execution_generation
            && quantum_source == source_arm_generation
    ) {
        return Err(state.latch(Dw1cEvidenceError::Contradiction));
    }
    if token == 8
        && state.token8_pending_expiry != Some((cpu, execution_generation, source_arm_generation))
    {
        return Err(state.latch(Dw1cEvidenceError::Contradiction));
    }
    state.cpu_chain[index] = CpuChain::Empty;
    if token == 8 {
        state.token8_pending_expiry = None;
    }
    Ok(())
}

fn retain_cpu_payload(
    state: &mut State,
    cpu: u8,
    token: u8,
    execution_generation: u64,
    value: u64,
    kind: u8,
    exact_bound_generation: bool,
) -> Result<(), Dw1cEvidenceError> {
    cpu_bit(cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
    let index = usize::from(cpu);
    if kind > 2 || (kind == 0 && value != u64::from(cpu)) || (kind != 0 && value == 0) {
        return Err(state.latch(Dw1cEvidenceError::Malformed));
    }
    if kind == 0 && exact_bound_generation {
        if token == 6 && !state.token6_wake_seen {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        if token == 7 && state.token7.is_some_and(|flight| !flight.wake_seen) {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
    }
    retain_cpu_chain(
        state,
        cpu,
        index,
        token,
        execution_generation,
        value,
        kind,
        exact_bound_generation,
    )?;
    if kind == 0 && token == 6 && exact_bound_generation {
        state.token6_run_seen = true;
        update_race_bit_zero(state);
    }
    if kind == 0 && token == 7 && exact_bound_generation {
        if let Some(flight) = state.token7.as_mut() {
            // Token 7 may execute normally before its selector-owned
            // backpressure transaction begins. Only a RUN after the exact
            // wake joins bit 1.
            flight.run_seen = true;
            update_race_bit_one(state);
        }
    }
    Ok(())
}

fn retain_cpu_chain(
    state: &mut State,
    cpu: u8,
    index: usize,
    token: u8,
    execution_generation: u64,
    value: u64,
    kind: u8,
    exact_bound_generation: bool,
) -> Result<(), Dw1cEvidenceError> {
    let payload = Dw1cRecordPayload {
        subject: u64::from(token),
        generation: execution_generation,
        value,
    };
    if token == 8 && state.token8_terminal.is_some() {
        return Err(state.latch(Dw1cEvidenceError::Contradiction));
    }
    match kind {
        0 => {
            match state.cpu_chain[index] {
                CpuChain::Run {
                    token: run_token,
                    execution_generation: run_generation,
                    ..
                } if run_token == token && run_generation == execution_generation => {
                    return Ok(());
                }
                CpuChain::Quantum { .. } => {
                    return Err(state.latch(Dw1cEvidenceError::Contradiction));
                }
                CpuChain::Empty | CpuChain::Run { .. } => {}
            }
            state.arm_boundary_quantum_allowed[index] = false;
            state.cpu_chain[index] = CpuChain::Run {
                token,
                execution_generation,
                serializable: exact_bound_generation,
            };
        }
        1 => {
            if state.quantum_payload[index] == Some(payload) {
                return Err(state.latch(Dw1cEvidenceError::Duplicate));
            }
            if state.quantum_payload[index].is_some_and(|committed| committed.value == value) {
                return Err(state.latch(Dw1cEvidenceError::Contradiction));
            }
            let serializable = match state.cpu_chain[index] {
                CpuChain::Run {
                    token: run_token,
                    execution_generation: run_generation,
                    serializable,
                } if run_token == token && run_generation == execution_generation => serializable,
                CpuChain::Quantum {
                    token: quantum_token,
                    execution_generation: quantum_generation,
                    source_arm_generation,
                    ..
                } if quantum_token == token
                    && quantum_generation == execution_generation
                    && source_arm_generation == value =>
                {
                    return Err(state.latch(Dw1cEvidenceError::Duplicate));
                }
                CpuChain::Quantum {
                    token: quantum_token,
                    execution_generation: quantum_generation,
                    serializable,
                    ..
                } if quantum_token == token && quantum_generation == execution_generation => {
                    serializable
                }
                CpuChain::Empty if state.arm_boundary_quantum_allowed[index] => {
                    // ARM binds actors while the other CPUs continue running.
                    // A tracked actor may therefore already own this CPU, or
                    // may dispatch between its generation sample and the ARM
                    // commit, before the collector can observe a separate RUN
                    // callback. A successfully published quantum ticket is
                    // scheduler-authoritative proof of that exact current
                    // Thread/generation. Admit this only once per CPU at the
                    // ARM boundary; later missing-RUN transitions stay strict.
                    exact_bound_generation
                }
                CpuChain::Empty if state.run_payload[index].is_some() => false,
                CpuChain::Empty => {
                    return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
                }
                _ => return Err(state.latch(Dw1cEvidenceError::Contradiction)),
            };
            if token == 8 {
                if state.token8_pending_expiry.is_some_and(
                    |(pending_cpu, pending_generation, _)| {
                        pending_cpu != cpu || pending_generation != execution_generation
                    },
                ) {
                    return Err(state.latch(Dw1cEvidenceError::Contradiction));
                }
            }
            state.cpu_chain[index] = CpuChain::Quantum {
                token,
                execution_generation,
                source_arm_generation: value,
                serializable,
            };
            state.arm_boundary_quantum_allowed[index] = false;
            if token == 8 {
                state.token8_pending_expiry = Some((cpu, execution_generation, value));
            }
        }
        _ => {
            if state.preempt_payload[index] == Some(payload) {
                return Err(state.latch(Dw1cEvidenceError::Duplicate));
            }
            if state
                .preempt_payload
                .iter()
                .flatten()
                .any(|committed| committed.value == value)
            {
                return Err(state.latch(Dw1cEvidenceError::Contradiction));
            }
            let CpuChain::Quantum {
                token: quantum_token,
                execution_generation: quantum_generation,
                source_arm_generation,
                serializable,
            } = state.cpu_chain[index]
            else {
                return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
            };
            if quantum_token != token || quantum_generation != execution_generation {
                return Err(state.latch(Dw1cEvidenceError::Contradiction));
            }
            if token == 8
                && state.token8_pending_expiry
                    == Some((cpu, execution_generation, source_arm_generation))
            {
                state.token8_pending_expiry = None;
            }
            state.cpu_chain[index] = CpuChain::Empty;
            if !serializable {
                return Ok(());
            }
            let identity_already_committed = state.run_payload.iter().flatten().any(|committed| {
                committed.subject == u64::from(token)
                    && committed.generation == execution_generation
            });
            if state.run_payload[index].is_some() || identity_already_committed {
                return Ok(());
            }
            let bit = 1_u8 << cpu;
            state.run_payload[index] = Some(Dw1cRecordPayload {
                subject: u64::from(token),
                generation: execution_generation,
                value: u64::from(cpu),
            });
            state.quantum_payload[index] = Some(Dw1cRecordPayload {
                subject: u64::from(token),
                generation: execution_generation,
                value: source_arm_generation,
            });
            state.preempt_payload[index] = Some(payload);
            state.facts.run |= bit;
            state.facts.quantum |= bit;
            state.facts.preempt |= bit;
        }
    }
    Ok(())
}

fn update_race_bit_zero(state: &mut State) {
    if state.token6_wait_joined
        && state.token6_wake_seen
        && state.token6_run_seen
        && state.progress.iter().any(|count| *count != 0)
    {
        state.facts.race_matrix |= 1;
    }
}

fn update_race_bit_one(state: &mut State) {
    if state.token7.is_some_and(|flight| {
        flight.blocked && flight.wake_seen && flight.run_seen && flight.wake_token.is_some()
    }) {
        state.facts.race_matrix |= 1 << 1;
    }
}

fn actor_thread_bound(state: &State, thread: ThreadKey, generation: u64) -> bool {
    actor_token_for_claim(state, thread, generation).is_some()
}

fn actor_token_for_claim(state: &State, thread: ThreadKey, generation: u64) -> Option<u8> {
    if generation == 0 {
        return None;
    }
    state
        .actors
        .iter()
        .flatten()
        .find(|actor| actor.thread == thread && actor.execution_generation == generation)
        .map(|actor| actor.token)
}
fn actor_token_for_thread(state: &State, thread: ThreadKey) -> Option<u8> {
    state
        .actors
        .iter()
        .flatten()
        .find(|actor| actor.thread == thread)
        .map(|actor| actor.token)
}
fn actor_thread_known(state: &State, thread: ThreadKey) -> bool {
    state
        .actors
        .iter()
        .flatten()
        .any(|actor| actor.thread == thread)
}

pub(crate) struct Dw1cEvidenceFlushPermit<'a> {
    collector: &'a Dw1cEvidenceCollector,
}
impl Dw1cEvidenceFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        write: impl FnMut(&[u8; DW1C_EVIDENCE_RECORD_LEN]) -> Result<(), ()>,
    ) -> Result<(), Dw1cEvidenceError> {
        self.collector.flush(write)
    }
}

const fn event_for(sequence: usize) -> u8 {
    match sequence {
        0..=3 => 1,
        4..=13 => 2,
        14..=17 => 3,
        18..=21 => 4,
        22..=25 => 5,
        26..=30 => 6,
        31..=34 => 7,
        35 => 8,
        36 => 9,
        37 => 10,
        38..=39 => 11,
        40..=41 => 12,
        42 => 13,
        43 => 14,
        44 => 15,
        45 => TERMINAL_EVENT,
        _ => 0,
    }
}

fn payload_for(sequence: usize, state: &State) -> Result<Dw1cRecordPayload, Dw1cEvidenceError> {
    let payload = match sequence {
        0..=3 => state.cpu_ready_payload[sequence],
        4..=13 => state.actors[sequence - 4].map(|actor| Dw1cRecordPayload {
            subject: u64::from(actor.token),
            generation: actor.execution_generation,
            value: u64::from(actor.role),
        }),
        14..=17 => state.run_payload[sequence - 14],
        18..=21 => state.quantum_payload[sequence - 18],
        22..=25 => state.preempt_payload[sequence - 22],
        26..=30 => {
            let index = sequence - 26;
            state.actors[index].and_then(|actor| {
                (state.progress[index] != 0).then_some(Dw1cRecordPayload {
                    subject: u64::from(actor.token),
                    generation: actor.execution_generation,
                    value: state.progress[index],
                })
            })
        }
        31..=34 => state.remote_wake_payload[sequence - 31],
        35 => state.steal_migrate_payload,
        36 => state.migration_reject_payload,
        37 => state.race_matrix_payload,
        38..=39 => state.exit_payload[sequence - 38],
        40..=41 => state.reap_payload[sequence - 40],
        42 => state.ready_delay_payload,
        43 => state.bootstrap_normal_payload,
        44 => state.accounting_sound_payload,
        45 => Some(Dw1cRecordPayload {
            subject: 0,
            generation: 0,
            value: 0,
        }),
        _ => None,
    };
    payload.ok_or(Dw1cEvidenceError::Incomplete)
}

fn encode_record(
    nonce: u64,
    sequence: u32,
    event: u8,
    payload: Dw1cRecordPayload,
) -> [u8; DW1C_EVIDENCE_RECORD_LEN] {
    let mut out = [b'0'; DW1C_EVIDENCE_RECORD_LEN];
    out[..8].copy_from_slice(b"DW1C|01|");
    put_hex(&mut out[8..24], nonce);
    out[24] = b'|';
    put_hex(&mut out[25..33], u64::from(sequence));
    out[33] = b'|';
    put_hex(&mut out[34..36], u64::from(event));
    out[36] = b'|';
    put_hex(&mut out[37..53], payload.subject);
    out[53] = b'|';
    put_hex(&mut out[54..70], payload.generation);
    out[70] = b'|';
    put_hex(&mut out[71..87], payload.value);
    out[87] = b'|';
    let checksum = fnv1a(&out[..88]);
    put_hex(&mut out[88..96], u64::from(checksum));
    out
}
fn put_hex(out: &mut [u8], mut value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in out.iter_mut().rev() {
        *byte = HEX[(value & 15) as usize];
        value >>= 4;
    }
}
const fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    let mut i = 0;
    while i < bytes.len() {
        hash = (hash ^ bytes[i] as u32).wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}
const fn parse_hex(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 16);
    let mut parsed = 0;
    let mut i = 0;
    while i < 16 {
        let digit = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'A'..=b'F' => bytes[i] - b'A' + 10,
            _ => panic!("uppercase hex required"),
        };
        parsed = (parsed << 4) | digit as u64;
        i += 1;
    }
    assert!(parsed != 0);
    parsed
}

#[cfg(deepwyrm_dw1c_evidence)]
pub(crate) static DW1C_EVIDENCE: Dw1cEvidenceCollector = Dw1cEvidenceCollector::new(
    parse_hex(env!("DEEPWYRM_DW1C_EVIDENCE_NONCE")),
    parse_hex(env!("DEEPWYRM_DW1C_PROGRESS_DIGEST")),
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::{DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD};
    fn actor(n: u8) -> Dw1cActor {
        let mut r = ObjectRegistry::<2>::new();
        let p = ProcessKey::from_object_id(r.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let t = ThreadKey::from_object_id(r.create(DW_OBJECT_TYPE_THREAD).unwrap().id());
        Dw1cActor {
            token: n,
            role: n,
            process: p,
            thread: t,
            execution_generation: u64::from(n),
        }
    }

    fn distinct_actor_set() -> ((ProcessKey, ThreadKey), [Dw1cActor; DW1C_ACTOR_COUNT]) {
        let mut registry = ObjectRegistry::<24>::new();
        let reporter_process =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let reporter_thread =
            ThreadKey::from_object_id(registry.create(DW_OBJECT_TYPE_THREAD).unwrap().id());
        let actors = core::array::from_fn(|index| {
            let token = u8::try_from(index + 1).unwrap();
            Dw1cActor {
                token,
                role: token,
                process: ProcessKey::from_object_id(
                    registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id(),
                ),
                thread: ThreadKey::from_object_id(
                    registry.create(DW_OBJECT_TYPE_THREAD).unwrap().id(),
                ),
                execution_generation: u64::from(token),
            }
        });
        ((reporter_process, reporter_thread), actors)
    }

    fn observe_prospective_actors(
        collector: &Dw1cEvidenceCollector,
        actors: &[Dw1cActor; DW1C_ACTOR_COUNT],
    ) {
        for actor in actors {
            collector.observe_process_create(actor.process).unwrap();
            collector
                .observe_thread_create(actor.process, actor.thread)
                .unwrap();
            collector
                .observe_thread_start(actor.process, actor.thread, actor.execution_generation)
                .unwrap();
        }
        let token6 = actors[5];
        collector
            .observe_bound_wait_claim(token6.thread, token6.execution_generation)
            .unwrap();
    }

    fn armed_collector() -> (Dw1cEvidenceCollector, [Dw1cActor; DW1C_ACTOR_COUNT]) {
        let (reporter, actors) = distinct_actor_set();
        let collector = Dw1cEvidenceCollector::new(1, 2);
        collector.install().unwrap();
        observe_prospective_actors(&collector, &actors);
        collector.arm(reporter, 0xa1, actors, 100).unwrap();
        (collector, actors)
    }

    fn complete_cpu_chain(
        collector: &Dw1cEvidenceCollector,
        cpu: u8,
        actor: Dw1cActor,
        source_arm_generation: u64,
        completed_switch_generation: u64,
    ) {
        collector
            .observe_running_claim(cpu, actor.thread, actor.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(
                cpu,
                actor.thread,
                actor.execution_generation,
                source_arm_generation,
            )
            .unwrap();
        collector
            .observe_preemption_claim(
                cpu,
                actor.thread,
                actor.execution_generation,
                completed_switch_generation,
            )
            .unwrap();
    }

    fn consume_arm_boundary_quantum(
        collector: &Dw1cEvidenceCollector,
        cpu: u8,
        actor: Dw1cActor,
        source_arm_generation: u64,
    ) {
        collector
            .observe_quantum_claim(
                cpu,
                actor.thread,
                actor.execution_generation,
                source_arm_generation,
            )
            .unwrap();
        collector
            .observe_consumed_quantum_claim(
                cpu,
                actor.thread,
                actor.execution_generation,
                source_arm_generation,
            )
            .unwrap();
    }

    fn channel_endpoints() -> (ChannelEndpointKey, ChannelEndpointKey) {
        let mut registry = ObjectRegistry::<2>::new();
        let endpoint = ChannelEndpointKey::from_object_id(
            registry.create(DW_OBJECT_TYPE_CHANNEL).unwrap().id(),
        );
        let peer = ChannelEndpointKey::from_object_id(
            registry.create(DW_OBJECT_TYPE_CHANNEL).unwrap().id(),
        );
        (endpoint, peer)
    }

    fn token7_full_blocked(
        collector: &Dw1cEvidenceCollector,
        actors: &[Dw1cActor; DW1C_ACTOR_COUNT],
        endpoint: ChannelEndpointKey,
        peer: ChannelEndpointKey,
    ) {
        let token7 = actors[6];
        collector
            .observe_token7_full_send(token7.process, token7.thread, endpoint, peer.object_id())
            .unwrap();
        collector
            .observe_token7_writable_block(
                token7.thread,
                token7.execution_generation,
                endpoint,
                0x71,
            )
            .unwrap();
    }

    fn decoded_payload(record: &[u8; DW1C_EVIDENCE_RECORD_LEN]) -> Dw1cRecordPayload {
        let read = |range: core::ops::Range<usize>| {
            u64::from_str_radix(core::str::from_utf8(&record[range]).unwrap(), 16).unwrap()
        };
        Dw1cRecordPayload {
            subject: read(37..53),
            generation: read(54..70),
            value: read(71..87),
        }
    }

    fn completion_ready_collector() -> (Dw1cEvidenceCollector, [Dw1cActor; DW1C_ACTOR_COUNT]) {
        let (collector, actors) = armed_collector();
        let reporter = collector.state.lock().reporter.unwrap().0;
        {
            let mut state = collector.state.lock();
            state.progress = [11, 12, 13, 14, 15];
            for cpu in 0..4 {
                let actor = actors[cpu];
                let payload = Dw1cRecordPayload {
                    subject: u64::from(actor.token),
                    generation: actor.execution_generation,
                    value: cpu as u64,
                };
                state.cpu_ready_payload[cpu] = Some(Dw1cRecordPayload {
                    subject: 0x100 + cpu as u64,
                    generation: 0x200 + cpu as u64,
                    value: 0x300 + cpu as u64,
                });
                state.run_payload[cpu] = Some(payload);
                state.quantum_payload[cpu] = Some(Dw1cRecordPayload {
                    value: 0x400 + cpu as u64,
                    ..payload
                });
                state.preempt_payload[cpu] = Some(Dw1cRecordPayload {
                    value: 0x500 + cpu as u64,
                    ..payload
                });
                state.remote_wake_payload[cpu] = Some(Dw1cRecordPayload {
                    value: cpu as u64 | (((cpu + 1) % 4) as u64) << 8 | (1_u64 << 16),
                    ..payload
                });
            }
            state.steal_migrate_payload = Some(Dw1cRecordPayload {
                subject: 5,
                generation: 0x8000,
                value: 0x0203,
            });
            state.migration_reject_payload = Some(Dw1cRecordPayload {
                subject: 6,
                generation: actors[5].execution_generation,
                value: 1 | (u64::from(DW1C_MIGRATION_REJECT_EXECUTION_PINNED) << 8),
            });
            for index in 0..2 {
                let actor = actors[index + 8];
                state.exit_payload[index] = Some(Dw1cRecordPayload {
                    subject: u64::from(actor.token),
                    generation: actor.execution_generation,
                    value: 0,
                });
                state.reap_payload[index] = Some(Dw1cRecordPayload {
                    subject: u64::from(actor.token),
                    generation: actor.process.object_id().generation(),
                    value: 1,
                });
            }
            state.facts = Dw1cKernelFacts {
                cpu_ready: 0x0f,
                run: 0x0f,
                quantum: 0x0f,
                preempt: 0x0f,
                remote_wake: 0x0f,
                steal_migrate: true,
                migration_reject_execution_pinned: true,
                race_matrix: 0x0f,
                lifecycle: 0x03,
                bootstrap_normal: false,
                accounting_sound: false,
                ready_delay_ns: 0,
            };
        }
        collector
            .workload_complete(reporter, u64::from(DW1C_PROGRESS_MASK), 2)
            .unwrap();
        (collector, actors)
    }

    fn fixed_payload_snapshot(
        state: &State,
    ) -> [Option<Dw1cRecordPayload>; DW1C_EVIDENCE_RECORD_CAPACITY] {
        core::array::from_fn(|sequence| payload_for(sequence, state).ok())
    }

    fn private_join_snapshot(
        state: &State,
    ) -> (
        bool,
        bool,
        Option<(u8, u8, u64, u64)>,
        bool,
        [CpuChain; 4],
        Option<(u8, u64, u64)>,
        Option<(u8, u64, u64)>,
        Option<Token7Flight>,
    ) {
        (
            state.token6_wait_joined,
            state.token6_wake_seen,
            state.token6_wake_identity,
            state.token6_run_seen,
            state.cpu_chain,
            state.token8_pending_expiry,
            state.token8_terminal,
            state.token7,
        )
    }

    const fn final_snapshot(max_ready_delay_ns: u64) -> Dw1cFinalSchedulerSnapshot {
        Dw1cFinalSchedulerSnapshot::for_test(0x91, 0x92, max_ready_delay_ns, 0x3f)
    }

    #[test]
    fn fixed_stream_is_46_records_of_96_bytes() {
        let a = encode_record(
            1,
            45,
            TERMINAL_EVENT,
            Dw1cRecordPayload {
                subject: 0,
                generation: 0,
                value: 0,
            },
        );
        assert_eq!(a.len(), 96);
        assert_eq!(&a[..8], b"DW1C|01|");
        assert_eq!(event_for(45), TERMINAL_EVENT);
        assert_eq!(
            decoded_payload(&a),
            Dw1cRecordPayload {
                subject: 0,
                generation: 0,
                value: 0,
            }
        );
    }

    #[test]
    fn source_contract_keeps_raw_op3_nonterminal_and_flushes_only_normal_completion() {
        let source = include_str!("../arch/x86_64/mm/activation/primordial.rs");
        let scheduler_source = include_str!("../task/scheduler.rs");
        let execution_source = include_str!("../task/execution.rs");
        let collector_source = include_str!("dw1c_evidence.rs");
        let raw = source
            .split("fn intercept_dw1c_evidence_raw(")
            .nth(1)
            .unwrap()
            .split("fn authorize_return(")
            .next()
            .unwrap();
        assert!(raw.contains(".workload_complete(self.process, values[1], values[2])"));
        assert!(!raw.contains("complete_dw1c_evidence"));
        assert!(!raw.contains("final_normal_completion"));
        assert!(
            raw.find("crate::time::monotonic_now()")
                < raw.find("let phase = self.reserve_runtime_phase()")
        );
        assert!(raw.contains(".running_claim_on(self.cpu)"));
        assert!(raw.contains("product_execution_generation,"));
        assert!(scheduler_source.contains(
            "scheduler-snapshot identities for DW1-C records 42 and 44, not actor tokens"
        ));
        assert!(
            collector_source
                .contains("Records 42 and 44 share this selector-local scheduler-snapshot")
        );
        let retained = execution_source
            .split("fn observe_retained_current_published_expiry(")
            .nth(1)
            .unwrap()
            .split("fn observe_terminal_after_expiry_ticket(")
            .next()
            .unwrap();
        assert!(
            retained.find("self.observe_consumed_published_expiry(Some(ticket))")
                < retained.find(".observe_running_claim(")
        );
        let preempt = execution_source
            .split("pub(crate) fn preempt_current_on(")
            .nth(1)
            .unwrap()
            .split("pub(crate) fn preemption_disable_on(")
            .next()
            .unwrap();
        assert!(
            preempt.contains(
                "self.observe_retained_current_published_expiry(consumed_published_expiry)"
            )
        );

        assert_eq!(
            source.matches("complete_primordial_launch(self);").count(),
            2
        );
        assert_eq!(source.matches(".final_normal_completion(").count(), 2);
        assert_eq!(
            source
                .matches("crate::test_support::complete_dw1c_evidence(permit)")
                .count(),
            2
        );
        for completion in source.split("complete_primordial_launch(self);").skip(1) {
            let hook = completion
                .split("#[cfg(all(feature = \"test-support\", deepwyrm_dw1b_evidence))]")
                .next()
                .unwrap();
            let normal = hook.find("if completion.is_err()").unwrap();
            let time = hook.find("crate::time::monotonic_now()").unwrap();
            let snapshot = hook.find(".dw1c_final_scheduler_snapshot()").unwrap();
            let join = hook.find(".final_normal_completion(").unwrap();
            let flush = hook
                .find("crate::test_support::complete_dw1c_evidence(permit)")
                .unwrap();
            assert!(normal < time && time < snapshot && snapshot < join && join < flush);
        }
    }

    #[test]
    fn workload_complete_is_one_time_correlation_and_never_flushes() {
        let (early, _) = armed_collector();
        let early_reporter = early.state.lock().reporter.unwrap().0;
        assert_eq!(
            early.workload_complete(early_reporter, u64::from(DW1C_PROGRESS_MASK), 2),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
        let mut writes = 0;
        assert_eq!(
            early.flush(|_| {
                writes += 1;
                Ok(())
            }),
            Err(Dw1cEvidenceError::Incomplete)
        );
        assert_eq!(writes, 0);

        let (replay, _) = completion_ready_collector();
        let reporter = replay.state.lock().reporter.unwrap().0;
        assert_eq!(replay.terminal.load(Ordering::Acquire), 0);
        assert_eq!(
            replay.workload_complete(reporter, u64::from(DW1C_PROGRESS_MASK), 2),
            Err(Dw1cEvidenceError::Duplicate)
        );
        assert_eq!(replay.terminal.load(Ordering::Acquire), 0);
    }

    #[test]
    fn bounded_completion_accepts_exact_limit_and_rejects_one_ns_over_or_regression() {
        let (exact, _) = completion_ready_collector();
        assert!(
            exact
                .final_normal_completion(100 + DW1C_ARM_TIMEOUT_NS, 0xa1, final_snapshot(9))
                .is_ok()
        );
        assert_eq!(exact.state.lock().facts.race_matrix, DW1C_PROGRESS_MASK);

        let (over, _) = completion_ready_collector();
        assert!(matches!(
            over.final_normal_completion(101 + DW1C_ARM_TIMEOUT_NS, 0xa1, final_snapshot(9)),
            Err(Dw1cEvidenceError::DeadlineExceeded)
        ));
        assert_eq!(over.terminal.load(Ordering::Acquire), 0);

        let (regression, _) = completion_ready_collector();
        assert!(matches!(
            regression.final_normal_completion(99, 0xa1, final_snapshot(9)),
            Err(Dw1cEvidenceError::TimeRegression)
        ));
        assert_eq!(regression.terminal.load(Ordering::Acquire), 0);

        let (later_product_generation, _) = completion_ready_collector();
        assert!(
            later_product_generation
                .final_normal_completion(100 + DW1C_ARM_TIMEOUT_NS, 0xa2, final_snapshot(9))
                .is_ok()
        );

        let (zero_product_generation, _) = completion_ready_collector();
        assert!(matches!(
            zero_product_generation.final_normal_completion(
                100 + DW1C_ARM_TIMEOUT_NS,
                0,
                final_snapshot(9),
            ),
            Err(Dw1cEvidenceError::WrongGeneration)
        ));
        assert_eq!(zero_product_generation.terminal.load(Ordering::Acquire), 0);
    }

    #[test]
    fn final_completion_requires_every_kernel_fact_and_each_preexisting_race_bit() {
        for missing in 0..13 {
            let (collector, _) = completion_ready_collector();
            {
                let mut state = collector.state.lock();
                match missing {
                    0 => state.facts.cpu_ready &= !1,
                    1 => state.facts.run &= !1,
                    2 => state.facts.quantum &= !1,
                    3 => state.facts.preempt &= !1,
                    4 => state.facts.remote_wake &= !1,
                    5 => state.facts.steal_migrate = false,
                    6 => state.facts.migration_reject_execution_pinned = false,
                    7..=10 => state.facts.race_matrix &= !(1 << (missing - 7)),
                    11 => state.facts.lifecycle &= !1,
                    12 => state.facts.lifecycle &= !2,
                    _ => unreachable!(),
                }
            }
            assert!(matches!(
                collector.final_normal_completion(101, 0xa1, final_snapshot(9)),
                Err(Dw1cEvidenceError::MissingKernelFact)
            ));
            assert_eq!(collector.terminal.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn final_flush_decodes_all_46_exact_stored_payloads() {
        let (collector, actors) = completion_ready_collector();
        let permit = collector
            .final_normal_completion(100 + DW1C_ARM_TIMEOUT_NS, 0xa1, final_snapshot(0x99))
            .unwrap();
        let expected: [Dw1cRecordPayload; DW1C_EVIDENCE_RECORD_CAPACITY] = {
            let state = collector.state.lock();
            core::array::from_fn(|sequence| payload_for(sequence, &state).unwrap())
        };
        let mut records = [EMPTY; DW1C_EVIDENCE_RECORD_CAPACITY];
        let mut record_count = 0;
        permit
            .flush(|record| {
                records[record_count] = *record;
                record_count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(record_count, DW1C_EVIDENCE_RECORD_CAPACITY);
        for (sequence, record) in records.iter().enumerate() {
            assert_eq!(
                decoded_payload(record),
                expected[sequence],
                "sequence {sequence}"
            );
            assert_eq!(
                u8::from_str_radix(core::str::from_utf8(&record[34..36]).unwrap(), 16).unwrap(),
                event_for(sequence),
                "event sequence {sequence}"
            );
        }
        assert_eq!(
            expected[37],
            Dw1cRecordPayload {
                subject: 8,
                generation: actors[7].execution_generation,
                value: 0x1f,
            }
        );
        assert_eq!(
            expected[42],
            Dw1cRecordPayload {
                subject: 0x91,
                generation: 0x92,
                value: 0x99,
            }
        );
        assert_eq!(
            expected[43],
            Dw1cRecordPayload {
                subject: 1,
                generation: 0xa1,
                value: 0,
            }
        );
        assert_eq!(
            expected[44],
            Dw1cRecordPayload {
                subject: 0x91,
                generation: 0x92,
                value: 0x3f,
            }
        );
        assert_eq!(expected[42].subject, expected[44].subject);
        assert_eq!(expected[42].generation, expected[44].generation);
        assert!(!(1..=u64::try_from(DW1C_ACTOR_COUNT).unwrap()).contains(&expected[42].subject));
        assert_eq!(
            expected[45],
            Dw1cRecordPayload {
                subject: 0,
                generation: 0,
                value: 0,
            }
        );
    }

    #[test]
    fn post_workload_scheduler_surplus_preserves_the_fixed_certificate_and_flushes() {
        let (collector, actors) = completion_ready_collector();
        {
            let mut state = collector.state.lock();
            state.exit_payload = [None; 2];
            state.reap_payload = [None; 2];
            state.facts.lifecycle = 0;
            state.facts.race_matrix &= !(1 << 3);
        }
        let before = {
            let state = collector.state.lock();
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
                state.facts,
                state.progress,
                state.workload_complete,
            )
        };

        let later_generation = actors[3].execution_generation + 0x100;
        collector
            .observe_running_claim(0, actors[3].thread, later_generation)
            .unwrap();
        collector
            .observe_quantum_claim(0, actors[3].thread, later_generation, 0x9001)
            .unwrap();
        collector
            .observe_preemption_claim(0, actors[3].thread, later_generation, 0x9002)
            .unwrap();
        assert_eq!(
            collector.observe_remote_wake_claim(
                2,
                0,
                actors[4].thread,
                actors[4].execution_generation + 0x100,
                0x9003,
            ),
            Ok(None)
        );
        collector
            .observe_steal_migration_claim(0, 2, actors[3].thread, 0, 0x9004)
            .unwrap();
        collector
            .observe_migration_rejection_claim(
                2,
                actors[5].thread,
                actors[5].execution_generation + 0x100,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
                state.facts,
                state.progress,
                state.workload_complete,
            ),
            before
        );
        assert_eq!(state.cpu_chain[0], CpuChain::Empty);
        assert_eq!(state.failure, None);
        drop(state);

        for actor in &actors[8..] {
            collector
                .observe_process_exit(actor.process, actor.thread, actor.execution_generation, 0)
                .unwrap();
        }
        for actor in &actors[8..] {
            collector
                .observe_process_reap(actor.process, actor.process.object_id().generation(), 1)
                .unwrap();
        }

        let permit = collector
            .final_normal_completion(101, 0xa1, final_snapshot(9))
            .unwrap();
        let mut records = 0;
        permit
            .flush(|_| {
                records += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(records, DW1C_EVIDENCE_RECORD_CAPACITY);
    }

    #[test]
    fn terminal_seal_makes_all_observer_callbacks_inert() {
        let (collector, actors) = completion_ready_collector();
        let permit = collector
            .final_normal_completion(101, 0xa1, final_snapshot(9))
            .unwrap();
        let before = {
            let state = collector.state.lock();
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
                state.facts,
                state.progress,
                state.workload_complete,
                state.failure,
            )
        };
        let (endpoint, peer) = channel_endpoints();
        assert!(!collector.tracks_thread(actors[0].thread));
        assert!(!collector.tracks_token7_actor(actors[6].process, actors[6].thread));
        assert!(!collector.tracks_token7_thread(actors[6].thread));
        assert_eq!(collector.observe_process_create(actors[0].process), Ok(()));
        assert_eq!(
            collector.observe_thread_create(actors[0].process, actors[0].thread),
            Ok(())
        );
        assert_eq!(
            collector.observe_thread_start(
                actors[0].process,
                actors[0].thread,
                actors[0].execution_generation,
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_bound_wait_claim(actors[5].thread, actors[5].execution_generation),
            Ok(())
        );
        assert_eq!(
            collector.observe_token7_full_send(
                actors[6].process,
                actors[6].thread,
                endpoint,
                peer.object_id(),
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_token7_writable_block(
                actors[6].thread,
                actors[6].execution_generation,
                endpoint,
                0x71,
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_token7_peer_drain_wake(
                actors[6].thread,
                actors[6].execution_generation,
                peer,
                0x71,
                DW_SIGNAL_WRITABLE.0,
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_running_claim(0, actors[0].thread, actors[0].execution_generation,),
            Ok(())
        );
        assert_eq!(
            collector.observe_quantum_claim(0, actors[0].thread, actors[0].execution_generation, 1),
            Ok(())
        );
        assert_eq!(
            collector.observe_preemption_claim(
                0,
                actors[0].thread,
                actors[0].execution_generation,
                1,
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_remote_wake_claim(
                1,
                0,
                actors[0].thread,
                actors[0].execution_generation,
                0x9101,
            ),
            Ok(None)
        );
        assert_eq!(
            collector.observe_steal_migration_claim(0, 1, actors[0].thread, 0, 0x9102),
            Ok(())
        );
        assert_eq!(
            collector.observe_migration_rejection_claim(
                1,
                actors[5].thread,
                actors[5].execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_terminal_preemption_claim(
                0,
                actors[7].thread,
                actors[7].execution_generation,
                1,
                false,
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_process_exit(
                actors[8].process,
                actors[8].thread,
                actors[8].execution_generation,
                1,
            ),
            Ok(())
        );
        assert_eq!(
            collector.observe_process_reap(actors[8].process, 0, 0),
            Ok(())
        );
        assert_eq!(collector.observe_cpu_ready_payload(0, 1, 1, 1), Ok(()));
        assert_eq!(
            collector.progress(actors[0].process, 1, 999, collector.digest),
            Ok(())
        );
        let reporter = collector.state.lock().reporter.unwrap().0;
        assert_eq!(
            collector.workload_complete(reporter, u64::from(DW1C_PROGRESS_MASK), collector.digest,),
            Ok(())
        );
        let state = collector.state.lock();
        assert_eq!(
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
                state.facts,
                state.progress,
                state.workload_complete,
                state.failure,
            ),
            before
        );
        assert!(state.terminal);
        drop(state);

        let mut records = 0;
        permit
            .flush(|_| {
                records += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(records, DW1C_EVIDENCE_RECORD_CAPACITY);
    }
    #[test]
    fn arm_rejects_duplicate_subjects() {
        let c = Dw1cEvidenceCollector::new(1, 2);
        c.install().unwrap();
        let actors = [
            actor(1),
            actor(2),
            actor(3),
            actor(4),
            actor(5),
            actor(6),
            actor(7),
            actor(8),
            actor(9),
            actor(10),
        ];
        assert!(
            c.arm((actors[0].process, actors[0].thread), 0xa1, actors, 100,)
                .is_err()
        );
    }

    #[test]
    fn arm_rejects_one_thread_claimed_by_distinct_actor_processes() {
        let (reporter, mut actors) = distinct_actor_set();
        let collector = Dw1cEvidenceCollector::new(1, 2);
        collector.install().unwrap();
        observe_prospective_actors(&collector, &actors);
        actors[1].thread = actors[0].thread;

        assert_eq!(
            collector.arm(reporter, 0xa1, actors, 100),
            Err(Dw1cEvidenceError::Malformed)
        );
    }

    #[test]
    fn arm_rejects_zero_product_execution_generation_without_binding() {
        let (reporter, actors) = distinct_actor_set();
        let collector = Dw1cEvidenceCollector::new(1, 2);
        collector.install().unwrap();
        observe_prospective_actors(&collector, &actors);

        assert_eq!(
            collector.arm(reporter, 0, actors, 100),
            Err(Dw1cEvidenceError::WrongGeneration)
        );
        let state = collector.state.lock();
        assert_eq!(state.reporter, None);
    }

    #[test]
    fn preinstall_lifecycle_and_wait_observations_cannot_satisfy_arm() {
        let (reporter, actors) = distinct_actor_set();
        let collector = Dw1cEvidenceCollector::new(1, 2);
        for actor in actors {
            collector.observe_process_create(actor.process).unwrap();
            collector
                .observe_thread_create(actor.process, actor.thread)
                .unwrap();
            collector
                .observe_thread_start(actor.process, actor.thread, actor.execution_generation)
                .unwrap();
        }
        collector
            .observe_bound_wait_claim(actors[5].thread, actors[5].execution_generation)
            .unwrap();
        collector.install().unwrap();

        assert_eq!(
            collector.arm(reporter, 0xa1, actors, 100),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
        assert!(
            collector
                .state
                .lock()
                .prospective
                .iter()
                .all(Option::is_none)
        );
    }

    #[test]
    fn preinstall_cpu_admission_is_retained_without_admitting_actor_facts() {
        let (reporter, actors) = distinct_actor_set();
        let collector = Dw1cEvidenceCollector::new(1, 2);
        for cpu in 0_u8..4 {
            collector
                .observe_cpu_ready_payload(
                    cpu,
                    0x1000 + u64::from(cpu),
                    0x2000 + u64::from(cpu),
                    0x3000 + u64::from(cpu),
                )
                .unwrap();
        }
        collector.observe_process_create(actors[0].process).unwrap();
        collector
            .observe_thread_create(actors[0].process, actors[0].thread)
            .unwrap();
        collector
            .observe_thread_start(
                actors[0].process,
                actors[0].thread,
                actors[0].execution_generation,
            )
            .unwrap();

        collector.install().unwrap();
        let state = collector.state.lock();
        assert_eq!(state.facts.cpu_ready, 0x0f);
        assert!(state.cpu_ready_payload.iter().all(Option::is_some));
        assert!(state.prospective.iter().all(Option::is_none));
        drop(state);
        assert_eq!(
            collector.arm(reporter, 0xa1, actors, 100),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
    }

    #[test]
    fn arm_requires_exact_lifecycle_create_start_and_token6_pending_wait() {
        let (reporter, actors) = distinct_actor_set();
        let missing_create = Dw1cEvidenceCollector::new(1, 2);
        missing_create.install().unwrap();
        for (index, actor) in actors.iter().copied().enumerate() {
            if index != 8 {
                missing_create
                    .observe_process_create(actor.process)
                    .unwrap();
                missing_create
                    .observe_thread_create(actor.process, actor.thread)
                    .unwrap();
                missing_create
                    .observe_thread_start(actor.process, actor.thread, actor.execution_generation)
                    .unwrap();
            }
        }
        missing_create
            .observe_bound_wait_claim(actors[5].thread, actors[5].execution_generation)
            .unwrap();
        assert_eq!(
            missing_create.arm(reporter, 0xa1, actors, 100),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );

        let (reporter, actors) = distinct_actor_set();
        let missing_start = Dw1cEvidenceCollector::new(1, 2);
        missing_start.install().unwrap();
        for (index, actor) in actors.iter().copied().enumerate() {
            missing_start.observe_process_create(actor.process).unwrap();
            missing_start
                .observe_thread_create(actor.process, actor.thread)
                .unwrap();
            if index != 9 {
                missing_start
                    .observe_thread_start(actor.process, actor.thread, actor.execution_generation)
                    .unwrap();
            }
        }
        missing_start
            .observe_bound_wait_claim(actors[5].thread, actors[5].execution_generation)
            .unwrap();
        assert_eq!(
            missing_start.arm(reporter, 0xa1, actors, 100),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );

        let (reporter, actors) = distinct_actor_set();
        let stale_wait = Dw1cEvidenceCollector::new(1, 2);
        stale_wait.install().unwrap();
        for actor in actors {
            stale_wait.observe_process_create(actor.process).unwrap();
            stale_wait
                .observe_thread_create(actor.process, actor.thread)
                .unwrap();
            stale_wait
                .observe_thread_start(actor.process, actor.thread, actor.execution_generation)
                .unwrap();
        }
        stale_wait
            .observe_bound_wait_claim(actors[5].thread, actors[5].execution_generation + 1)
            .unwrap();
        assert_eq!(
            stale_wait.arm(reporter, 0xa1, actors, 100),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
    }

    #[test]
    fn duplicate_prospective_transitions_fail_only_if_arm_names_that_identity() {
        let (reporter, actors) = distinct_actor_set();
        let collector = Dw1cEvidenceCollector::new(1, 2);
        collector.install().unwrap();
        observe_prospective_actors(&collector, &actors);
        collector
            .observe_thread_start(
                actors[8].process,
                actors[8].thread,
                actors[8].execution_generation,
            )
            .unwrap();
        assert_eq!(
            collector.arm(reporter, 0xa1, actors, 100),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );

        let (reporter, actors) = distinct_actor_set();
        let unrelated = Dw1cEvidenceCollector::new(1, 2);
        unrelated.install().unwrap();
        observe_prospective_actors(&unrelated, &actors);
        let mut registry = ObjectRegistry::<2>::new();
        let process =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let thread =
            ThreadKey::from_object_id(registry.create(DW_OBJECT_TYPE_THREAD).unwrap().id());
        unrelated.observe_thread_create(process, thread).unwrap();
        unrelated.observe_thread_start(process, thread, 99).unwrap();
        unrelated.observe_bound_wait_claim(thread, 99).unwrap();
        unrelated.arm(reporter, 0xa1, actors, 100).unwrap();
        assert_eq!(unrelated.state.lock().failure, None);
        assert_eq!(
            unrelated.observe_thread_create(actors[0].process, thread),
            Ok(())
        );
        unrelated
            .observe_thread_start(actors[0].process, thread, 100)
            .unwrap();
        assert_eq!(unrelated.state.lock().failure, None);
    }

    #[test]
    fn direct_actor_observers_latch_unknown_or_unjoined_identities() {
        let (collector, _actors) = armed_collector();
        let mut registry = ObjectRegistry::<2>::new();
        let unknown =
            ThreadKey::from_object_id(registry.create(DW_OBJECT_TYPE_THREAD).unwrap().id());
        assert!(!collector.tracks_thread(unknown));
        assert_eq!(
            collector.observe_running_claim(0, unknown, 1),
            Err(Dw1cEvidenceError::WrongActor)
        );
        assert_eq!(
            collector.state.lock().failure,
            Some(Dw1cEvidenceError::WrongActor)
        );

        let (collector, actors) = armed_collector();
        let actor = actors[0];
        assert!(collector.tracks_thread(actor.thread));
        consume_arm_boundary_quantum(&collector, 0, actor, 6);
        assert_eq!(
            collector.observe_quantum_claim(0, actor.thread, actor.execution_generation + 1, 7),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
        assert_eq!(
            collector.state.lock().failure,
            Some(Dw1cEvidenceError::MissingKernelFact)
        );
    }

    #[test]
    fn token8_terminal_preemption_requires_matching_expiry_and_forbids_later_run() {
        let (missing_expiry, actors) = armed_collector();
        let token8 = actors[7];
        assert_eq!(
            missing_expiry.observe_terminal_preemption_claim(
                2,
                token8.thread,
                token8.execution_generation,
                0x88,
                true,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );

        let (collector, actors) = armed_collector();
        let token8 = actors[7];
        collector
            .observe_running_claim(2, token8.thread, token8.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, token8.execution_generation, 0x88)
            .unwrap();
        assert_eq!(
            collector.observe_terminal_preemption_claim(
                2,
                token8.thread,
                token8.execution_generation,
                0x89,
                true,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );

        let (collector, actors) = armed_collector();
        let token8 = actors[7];
        collector
            .observe_running_claim(2, token8.thread, token8.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, token8.execution_generation, 0x88)
            .unwrap();
        collector
            .observe_terminal_preemption_claim(
                2,
                token8.thread,
                token8.execution_generation,
                0x88,
                true,
            )
            .unwrap();
        assert_eq!(collector.state.lock().facts.race_matrix & (1 << 2), 1 << 2);
        assert_eq!(
            collector.observe_running_claim(2, token8.thread, token8.execution_generation),
            Err(Dw1cEvidenceError::Contradiction)
        );
    }

    #[test]
    fn consumed_published_expiry_clears_live_chain_without_selecting_terminal_witness() {
        let (collector, actors) = armed_collector();
        let actor = actors[0];
        collector
            .observe_running_claim(1, actor.thread, actor.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(1, actor.thread, actor.execution_generation, 0x81)
            .unwrap();
        collector
            .observe_consumed_quantum_claim(1, actor.thread, actor.execution_generation, 0x81)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.cpu_chain[1], CpuChain::Empty);
        assert_eq!(state.token8_pending_expiry, None);
        assert_eq!(state.token8_terminal, None);
        assert_eq!(state.facts.race_matrix & (1 << 2), 0);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn retained_current_republishes_run_before_the_rearmed_quantum() {
        let (collector, actors) = armed_collector();
        let actor = actors[2];

        collector
            .observe_quantum_claim(2, actor.thread, actor.execution_generation, 0x81)
            .unwrap();
        collector
            .observe_consumed_quantum_claim(2, actor.thread, actor.execution_generation, 0x81)
            .unwrap();
        collector
            .observe_running_claim(2, actor.thread, actor.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, actor.thread, actor.execution_generation, 0x82)
            .unwrap();
        collector
            .observe_preemption_claim(2, actor.thread, actor.execution_generation, 0x182)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(
            state.run_payload[2].unwrap().subject,
            u64::from(actor.token)
        );
        assert_eq!(state.quantum_payload[2].unwrap().value, 0x82);
        assert_eq!(state.preempt_payload[2].unwrap().value, 0x182);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn retained_current_republishes_a_nonserializing_later_generation() {
        let (collector, actors) = armed_collector();
        let actor = actors[3];
        let later_generation = actor.execution_generation + 0x100;

        collector
            .observe_quantum_claim(3, actor.thread, later_generation, 0x91)
            .unwrap();
        collector
            .observe_consumed_quantum_claim(3, actor.thread, later_generation, 0x91)
            .unwrap();
        collector
            .observe_running_claim(3, actor.thread, later_generation)
            .unwrap();
        collector
            .observe_quantum_claim(3, actor.thread, later_generation, 0x92)
            .unwrap();
        collector
            .observe_preemption_claim(3, actor.thread, later_generation, 0x192)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.cpu_chain[3], CpuChain::Empty);
        assert_eq!(state.run_payload[3], None);
        assert_eq!(state.quantum_payload[3], None);
        assert_eq!(state.preempt_payload[3], None);
        assert_eq!(state.facts.run & 0x08, 0);
        assert_eq!(state.facts.quantum & 0x08, 0);
        assert_eq!(state.facts.preempt & 0x08, 0);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn ordinary_actor_terminal_expiry_is_valid_cleanup_not_token8_evidence() {
        let (collector, actors) = armed_collector();
        let actor = actors[0];
        collector
            .observe_running_claim(1, actor.thread, actor.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(1, actor.thread, actor.execution_generation, 0x82)
            .unwrap();
        collector
            .observe_terminal_preemption_claim(
                1,
                actor.thread,
                actor.execution_generation,
                0x82,
                true,
            )
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.cpu_chain[1], CpuChain::Empty);
        assert_eq!(state.token8_terminal, None);
        assert_eq!(state.facts.race_matrix & (1 << 2), 0);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn token8_later_expiry_replaces_a_consumed_nonterminal_candidate() {
        let (collector, actors) = armed_collector();
        let token8 = actors[7];
        collector
            .observe_running_claim(2, token8.thread, token8.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, token8.execution_generation, 0x81)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, token8.execution_generation, 0x82)
            .unwrap();
        collector
            .observe_terminal_preemption_claim(
                2,
                token8.thread,
                token8.execution_generation,
                0x82,
                true,
            )
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.token8_pending_expiry, None);
        assert_eq!(
            state.token8_terminal,
            Some((2, token8.execution_generation, 0x82))
        );
        assert_eq!(state.facts.race_matrix & (1 << 2), 1 << 2);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn token8_later_generation_expiry_can_win_the_private_terminal_join() {
        let (collector, actors) = armed_collector();
        let token8 = actors[7];
        let later_generation = token8.execution_generation + 0x100;
        collector
            .observe_running_claim(2, token8.thread, later_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, later_generation, 0x184)
            .unwrap();
        collector
            .observe_terminal_preemption_claim(2, token8.thread, later_generation, 0x184, true)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.token8_pending_expiry, None);
        assert_eq!(state.token8_terminal, Some((2, later_generation, 0x184)));
        assert_eq!(state.cpu_chain[2], CpuChain::Empty);
        assert_eq!(state.run_payload[2], None);
        assert_eq!(state.quantum_payload[2], None);
        assert_eq!(state.preempt_payload[2], None);
        assert_eq!(state.facts.race_matrix & (1 << 2), 1 << 2);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn run_after_quantum_latches_without_mutating_the_pending_chain_or_races() {
        let (collector, actors) = armed_collector();
        let token8 = actors[7];
        collector
            .observe_running_claim(2, token8.thread, token8.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, token8.execution_generation, 0x83)
            .unwrap();

        assert_eq!(
            collector.observe_running_claim(2, actors[0].thread, actors[0].execution_generation,),
            Err(Dw1cEvidenceError::Contradiction)
        );
        let state = collector.state.lock();
        assert_eq!(
            state.cpu_chain[2],
            CpuChain::Quantum {
                token: token8.token,
                execution_generation: token8.execution_generation,
                source_arm_generation: 0x83,
                serializable: true,
            }
        );
        assert_eq!(
            state.token8_pending_expiry,
            Some((2, token8.execution_generation, 0x83))
        );
        assert_eq!(state.run_payload[2], None);
        assert_eq!(state.quantum_payload[2], None);
        assert_eq!(state.preempt_payload[2], None);
        assert_eq!(state.facts.race_matrix, 0);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Contradiction));
    }

    #[test]
    fn token7_full_registered_writable_peer_drain_wake_then_run_sets_only_bit_one() {
        let (collector, actors) = armed_collector();
        let token7 = actors[6];
        let (endpoint, peer) = channel_endpoints();
        token7_full_blocked(&collector, &actors, endpoint, peer);
        collector
            .observe_token7_peer_drain_wake(
                token7.thread,
                token7.execution_generation,
                peer,
                0x71,
                DW_SIGNAL_WRITABLE.0,
            )
            .unwrap();
        collector
            .observe_running_claim(0, token7.thread, token7.execution_generation)
            .unwrap();
        collector
            .observe_running_claim(0, token7.thread, token7.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(0, token7.thread, token7.execution_generation, 0x72)
            .unwrap();
        collector
            .observe_preemption_claim(0, token7.thread, token7.execution_generation, 0x73)
            .unwrap();
        let state = collector.state.lock();
        assert_eq!(state.facts.race_matrix & (1 << 1), 1 << 1);
        assert_eq!(state.run_payload[0].unwrap().subject, 7);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn token7_later_block_generation_advances_only_its_private_join() {
        let (collector, actors) = armed_collector();
        let token7 = actors[6];
        let later_generation = token7.execution_generation + 0x100;
        let (endpoint, peer) = channel_endpoints();
        collector
            .observe_token7_full_send(token7.process, token7.thread, endpoint, peer.object_id())
            .unwrap();
        collector
            .observe_token7_writable_block(token7.thread, later_generation, endpoint, 0x171)
            .unwrap();
        collector
            .observe_token7_peer_drain_wake(
                token7.thread,
                later_generation,
                peer,
                0x171,
                DW_SIGNAL_WRITABLE.0,
            )
            .unwrap();
        collector
            .observe_running_claim(0, token7.thread, later_generation)
            .unwrap();
        collector
            .observe_running_claim(0, token7.thread, later_generation)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.facts.race_matrix & (1 << 1), 1 << 1);
        assert_eq!(state.cpu_chain[0], CpuChain::Empty);
        assert_eq!(state.run_payload[0], None);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn token7_ignores_unbound_or_unrelated_wait_activity() {
        let (no_full, actors) = armed_collector();
        let token7 = actors[6];
        let (endpoint, _peer) = channel_endpoints();
        no_full
            .observe_token7_writable_block(
                token7.thread,
                token7.execution_generation,
                endpoint,
                0x71,
            )
            .unwrap();
        assert_eq!(no_full.state.lock().failure, None);

        let (ready, actors) = armed_collector();
        let token7 = actors[6];
        let (endpoint, peer) = channel_endpoints();
        ready
            .observe_token7_full_send(token7.process, token7.thread, endpoint, peer.object_id())
            .unwrap();
        ready
            .observe_token7_peer_drain_wake(
                token7.thread,
                token7.execution_generation,
                peer,
                0x71,
                DW_SIGNAL_WRITABLE.0,
            )
            .unwrap();
        assert_eq!(ready.state.lock().failure, None);
    }

    #[test]
    fn token7_ignores_unrelated_wakes_but_rejects_selected_wake_without_writable() {
        let (wrong_peer, actors) = armed_collector();
        let token7 = actors[6];
        let (endpoint, peer) = channel_endpoints();
        let (_other_endpoint, other_peer) = channel_endpoints();
        token7_full_blocked(&wrong_peer, &actors, endpoint, peer);
        wrong_peer
            .observe_token7_peer_drain_wake(
                token7.thread,
                token7.execution_generation,
                other_peer,
                0x71,
                DW_SIGNAL_WRITABLE.0,
            )
            .unwrap();
        assert_eq!(wrong_peer.state.lock().failure, None);

        let (wrong_signals, actors) = armed_collector();
        let token7 = actors[6];
        let (endpoint, peer) = channel_endpoints();
        token7_full_blocked(&wrong_signals, &actors, endpoint, peer);
        wrong_signals
            .observe_token7_peer_drain_wake(
                token7.thread,
                token7.execution_generation,
                peer,
                0x72,
                DW_SIGNAL_WRITABLE.0,
            )
            .unwrap();
        assert_eq!(wrong_signals.state.lock().failure, None);

        let (missing_writable, actors) = armed_collector();
        let token7 = actors[6];
        let (endpoint, peer) = channel_endpoints();
        token7_full_blocked(&missing_writable, &actors, endpoint, peer);
        assert_eq!(
            missing_writable.observe_token7_peer_drain_wake(
                token7.thread,
                token7.execution_generation,
                peer,
                0x71,
                0,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );

        let (run_first, actors) = armed_collector();
        let token7 = actors[6];
        let (endpoint, peer) = channel_endpoints();
        token7_full_blocked(&run_first, &actors, endpoint, peer);
        assert_eq!(
            run_first.observe_running_claim(0, token7.thread, token7.execution_generation),
            Err(Dw1cEvidenceError::Contradiction)
        );
    }

    #[test]
    fn interleaved_lifecycle_observation_retains_grouped_ordered_payloads() {
        let (collector, actors) = armed_collector();
        let token9 = actors[8];
        let token10 = actors[9];
        collector
            .observe_process_exit(
                token9.process,
                token9.thread,
                token9.execution_generation,
                0,
            )
            .unwrap();
        collector
            .observe_process_reap(token9.process, token9.process.object_id().generation(), 1)
            .unwrap();
        collector
            .observe_process_exit(
                token10.process,
                token10.thread,
                token10.execution_generation,
                0,
            )
            .unwrap();
        collector
            .observe_process_reap(token10.process, token10.process.object_id().generation(), 1)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.facts.lifecycle, 0x03);
        assert_eq!(state.facts.race_matrix & (1 << 3), 1 << 3);
        assert_eq!(payload_for(38, &state).unwrap().subject, 9);
        assert_eq!(
            payload_for(38, &state).unwrap().generation,
            token9.execution_generation
        );
        assert_eq!(payload_for(39, &state).unwrap().subject, 10);
        assert_eq!(
            payload_for(40, &state).unwrap().generation,
            token9.process.object_id().generation()
        );
        assert_eq!(payload_for(40, &state).unwrap().value, 1);
        assert_eq!(payload_for(41, &state).unwrap().subject, 10);
    }

    #[test]
    fn lifecycle_accepts_concurrent_order_and_terminal_thread_generation() {
        let (out_of_order, actors) = armed_collector();
        out_of_order
            .observe_process_exit(
                actors[9].process,
                actors[9].thread,
                actors[9].execution_generation,
                0,
            )
            .unwrap();
        out_of_order
            .observe_process_exit(
                actors[8].process,
                actors[8].thread,
                actors[8].execution_generation,
                0,
            )
            .unwrap();
        assert_eq!(out_of_order.state.lock().facts.lifecycle & 0x01, 0x01);

        let (later_terminal, actors) = armed_collector();
        let terminal_generation = actors[8].execution_generation + 1;
        later_terminal
            .observe_process_exit(actors[8].process, actors[8].thread, terminal_generation, 0)
            .unwrap();
        assert_eq!(
            later_terminal.state.lock().exit_payload[0]
                .unwrap()
                .generation,
            terminal_generation
        );

        let (zero_generation, actors) = armed_collector();
        assert_eq!(
            zero_generation.observe_process_exit(actors[8].process, actors[8].thread, 0, 0),
            Err(Dw1cEvidenceError::WrongGeneration)
        );

        let (alternate_terminal_thread, actors) = armed_collector();
        alternate_terminal_thread
            .observe_process_exit(
                actors[8].process,
                actors[7].thread,
                actors[8].execution_generation + 2,
                0,
            )
            .unwrap();
        assert_eq!(
            alternate_terminal_thread.state.lock().exit_payload[0]
                .unwrap()
                .generation,
            actors[8].execution_generation + 2
        );

        let (duplicate, actors) = armed_collector();
        duplicate
            .observe_process_exit(
                actors[8].process,
                actors[8].thread,
                actors[8].execution_generation,
                0,
            )
            .unwrap();
        assert_eq!(
            duplicate.observe_process_exit(
                actors[8].process,
                actors[8].thread,
                actors[8].execution_generation,
                0,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );

        let (early_reap, actors) = armed_collector();
        assert_eq!(
            early_reap.observe_process_reap(
                actors[8].process,
                actors[8].process.object_id().generation(),
                1,
            ),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );

        let (bad_count, actors) = armed_collector();
        assert_eq!(
            bad_count.observe_process_reap(
                actors[8].process,
                actors[8].process.object_id().generation(),
                2,
            ),
            Err(Dw1cEvidenceError::Malformed)
        );

        let (bad_code, actors) = armed_collector();
        assert_eq!(
            bad_code.observe_process_exit(
                actors[8].process,
                actors[8].thread,
                actors[8].execution_generation,
                1,
            ),
            Err(Dw1cEvidenceError::Malformed)
        );

        let (reap_out_of_order, actors) = armed_collector();
        for actor in actors[8..].iter().copied() {
            reap_out_of_order
                .observe_process_exit(actor.process, actor.thread, actor.execution_generation, 0)
                .unwrap();
        }
        reap_out_of_order
            .observe_process_reap(
                actors[9].process,
                actors[9].process.object_id().generation(),
                1,
            )
            .unwrap();
        reap_out_of_order
            .observe_process_reap(
                actors[8].process,
                actors[8].process.object_id().generation(),
                1,
            )
            .unwrap();
        assert_eq!(reap_out_of_order.state.lock().facts.lifecycle, 0x03);

        let (stale_reap, actors) = armed_collector();
        for actor in actors[8..].iter().copied() {
            stale_reap
                .observe_process_exit(actor.process, actor.thread, actor.execution_generation, 0)
                .unwrap();
        }
        assert_eq!(
            stale_reap.observe_process_reap(
                actors[8].process,
                actors[8].process.object_id().generation() + 1,
                1,
            ),
            Err(Dw1cEvidenceError::WrongGeneration)
        );

        let (duplicate_reap, actors) = armed_collector();
        for actor in actors[8..].iter().copied() {
            duplicate_reap
                .observe_process_exit(actor.process, actor.thread, actor.execution_generation, 0)
                .unwrap();
        }
        duplicate_reap
            .observe_process_reap(
                actors[8].process,
                actors[8].process.object_id().generation(),
                1,
            )
            .unwrap();
        assert_eq!(
            duplicate_reap.observe_process_reap(
                actors[8].process,
                actors[8].process.object_id().generation(),
                1,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );
    }

    #[test]
    fn pending_wait_wake_run_and_independent_progress_form_race_zero() {
        let (collector, actors) = armed_collector();
        let token6 = actors[5];
        collector.progress(actors[0].process, 1, 7, 2).unwrap();
        collector
            .observe_remote_wake_claim(1, 0, token6.thread, token6.execution_generation, 3)
            .unwrap();
        collector
            .observe_running_claim(0, token6.thread, token6.execution_generation)
            .unwrap();
        let state = collector.state.lock();
        assert!(state.token6_wait_joined);
        assert!(state.token6_wake_seen);
        assert!(state.token6_run_seen);
        assert_eq!(state.facts.race_matrix & 1, 1);
    }

    #[test]
    fn run_quantum_and_preempt_retain_exact_joined_payloads() {
        let (collector, actors) = armed_collector();
        let actor = actors[3];

        collector
            .observe_running_claim(2, actor.thread, actor.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, actor.thread, actor.execution_generation, 0x1234)
            .unwrap();
        collector
            .observe_preemption_claim(2, actor.thread, actor.execution_generation, 0x5678)
            .unwrap();

        let state = collector.state.lock();
        let identity = (u64::from(actor.token), actor.execution_generation);
        assert_eq!(
            state.run_payload[2].map(|payload| (
                payload.subject,
                payload.generation,
                payload.value
            )),
            Some((identity.0, identity.1, 2))
        );
        assert_eq!(
            state.quantum_payload[2].map(|payload| (
                payload.subject,
                payload.generation,
                payload.value
            )),
            Some((identity.0, identity.1, 0x1234))
        );
        assert_eq!(
            state.preempt_payload[2].map(|payload| (
                payload.subject,
                payload.generation,
                payload.value
            )),
            Some((identity.0, identity.1, 0x5678))
        );
        assert_eq!(state.facts.run & 0x04, 0x04);
        assert_eq!(state.facts.quantum & 0x04, 0x04);
        assert_eq!(state.facts.preempt & 0x04, 0x04);
    }

    #[test]
    fn cpu_transcript_selects_one_complete_chain_and_ignores_later_valid_surplus() {
        let (collector, actors) = armed_collector();
        complete_cpu_chain(&collector, 0, actors[0], 0x11, 0x101);
        let retained = {
            let state = collector.state.lock();
            (
                state.run_payload[0],
                state.quantum_payload[0],
                state.preempt_payload[0],
            )
        };

        complete_cpu_chain(&collector, 0, actors[1], 0x12, 0x102);
        let state = collector.state.lock();
        assert_eq!(
            (
                state.run_payload[0],
                state.quantum_payload[0],
                state.preempt_payload[0],
            ),
            retained
        );
        assert_eq!(state.cpu_chain[0], CpuChain::Empty);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn completed_cpu_accepts_later_generation_surplus_without_an_observed_run() {
        let (collector, actors) = armed_collector();
        complete_cpu_chain(&collector, 0, actors[0], 0x13, 0x103);
        let later_execution_generation = actors[0].execution_generation + 0x100;
        let retained = {
            let state = collector.state.lock();
            (
                state.run_payload[0],
                state.quantum_payload[0],
                state.preempt_payload[0],
            )
        };

        collector
            .observe_quantum_claim(0, actors[0].thread, later_execution_generation, 0x14)
            .unwrap();
        collector
            .observe_preemption_claim(0, actors[0].thread, later_execution_generation, 0x104)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(
            (
                state.run_payload[0],
                state.quantum_payload[0],
                state.preempt_payload[0],
            ),
            retained
        );
        assert_eq!(state.cpu_chain[0], CpuChain::Empty);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn first_post_arm_quantum_joins_a_preexisting_running_actor_once() {
        let (collector, actors) = armed_collector();
        let actor = actors[2];

        collector
            .observe_quantum_claim(2, actor.thread, actor.execution_generation, 0x15)
            .unwrap();
        assert_eq!(
            collector.state.lock().cpu_chain[2],
            CpuChain::Quantum {
                token: actor.token,
                execution_generation: actor.execution_generation,
                source_arm_generation: 0x15,
                serializable: true,
            }
        );
        collector
            .observe_preemption_claim(2, actor.thread, actor.execution_generation, 0x105)
            .unwrap();
        let state = collector.state.lock();
        assert_eq!(
            state.run_payload[2],
            Some(Dw1cRecordPayload {
                subject: u64::from(actor.token),
                generation: actor.execution_generation,
                value: 2,
            })
        );
        assert_eq!(state.failure, None);
        drop(state);

        let (one_shot, actors) = armed_collector();
        let actor = actors[2];
        consume_arm_boundary_quantum(&one_shot, 2, actor, 0x15);
        let later_generation = actor.execution_generation + 0x100;
        assert_eq!(
            one_shot.observe_quantum_claim(2, actor.thread, later_generation, 0x16),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
        assert_eq!(
            one_shot.state.lock().failure,
            Some(Dw1cEvidenceError::MissingKernelFact)
        );
    }

    #[test]
    fn incomplete_cpu_consumes_later_generation_chain_without_filling_fixed_records() {
        let (collector, actors) = armed_collector();
        let actor = actors[3];
        let later_generation = actor.execution_generation + 0x100;

        collector
            .observe_running_claim(2, actor.thread, later_generation)
            .unwrap();
        assert_eq!(
            collector.state.lock().cpu_chain[2],
            CpuChain::Run {
                token: actor.token,
                execution_generation: later_generation,
                serializable: false,
            }
        );
        collector
            .observe_quantum_claim(2, actor.thread, later_generation, 0x15)
            .unwrap();
        assert_eq!(
            collector.state.lock().cpu_chain[2],
            CpuChain::Quantum {
                token: actor.token,
                execution_generation: later_generation,
                source_arm_generation: 0x15,
                serializable: false,
            }
        );
        collector
            .observe_preemption_claim(2, actor.thread, later_generation, 0x105)
            .unwrap();

        {
            let state = collector.state.lock();
            assert_eq!(state.cpu_chain[2], CpuChain::Empty);
            assert_eq!(state.run_payload[2], None);
            assert_eq!(state.quantum_payload[2], None);
            assert_eq!(state.preempt_payload[2], None);
            assert_eq!(state.facts.run & 0x04, 0);
            assert_eq!(state.facts.quantum & 0x04, 0);
            assert_eq!(state.facts.preempt & 0x04, 0);
            assert_eq!(state.failure, None);
        }

        complete_cpu_chain(&collector, 2, actor, 0x16, 0x106);
        let state = collector.state.lock();
        assert_eq!(
            state.run_payload[2].unwrap().subject,
            u64::from(actor.token)
        );
        assert_eq!(
            state.run_payload[2].unwrap().generation,
            actor.execution_generation
        );
        assert_eq!(state.failure, None);
    }

    #[test]
    fn later_scheduler_surplus_does_not_advance_private_token6_or_token7_joins() {
        let (collector, actors) = armed_collector();
        for (cpu, actor, quantum, preempt) in
            [(0, actors[5], 0x61, 0x601), (1, actors[6], 0x71, 0x701)]
        {
            let later_generation = actor.execution_generation + 0x100;
            collector
                .observe_running_claim(cpu, actor.thread, later_generation)
                .unwrap();
            collector
                .observe_quantum_claim(cpu, actor.thread, later_generation, quantum)
                .unwrap();
            collector
                .observe_preemption_claim(cpu, actor.thread, later_generation, preempt)
                .unwrap();
        }

        let state = collector.state.lock();
        assert!(!state.token6_wake_seen);
        assert!(!state.token6_run_seen);
        assert_eq!(state.token7, None);
        assert_eq!(state.cpu_chain, [CpuChain::Empty; 4]);
        assert_eq!(state.run_payload, [None; 4]);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn later_run_replaces_an_incomplete_candidate_and_latest_quantum_arm_wins() {
        let (collector, actors) = armed_collector();
        collector
            .observe_running_claim(1, actors[0].thread, actors[0].execution_generation)
            .unwrap();
        collector
            .observe_running_claim(1, actors[1].thread, actors[1].execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(1, actors[1].thread, actors[1].execution_generation, 0x21)
            .unwrap();
        collector
            .observe_quantum_claim(1, actors[1].thread, actors[1].execution_generation, 0x22)
            .unwrap();
        collector
            .observe_preemption_claim(1, actors[1].thread, actors[1].execution_generation, 0x201)
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(state.run_payload[1].unwrap().subject, 2);
        assert_eq!(state.quantum_payload[1].unwrap().value, 0x22);
        assert_eq!(state.preempt_payload[1].unwrap().value, 0x201);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn duplicate_cpu_identity_on_another_cpu_is_surplus_until_a_distinct_chain_completes() {
        let (collector, actors) = armed_collector();
        complete_cpu_chain(&collector, 0, actors[0], 0x31, 0x301);
        complete_cpu_chain(&collector, 1, actors[0], 0x32, 0x302);
        {
            let state = collector.state.lock();
            assert_eq!(state.run_payload[1], None);
            assert_eq!(state.quantum_payload[1], None);
            assert_eq!(state.preempt_payload[1], None);
            assert_eq!(state.cpu_chain[1], CpuChain::Empty);
            assert_eq!(state.failure, None);
        }

        complete_cpu_chain(&collector, 1, actors[1], 0x33, 0x303);
        let state = collector.state.lock();
        assert_eq!(state.run_payload[1].unwrap().subject, 2);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn retained_cpu_generations_reject_exact_replay_and_conflicting_reuse() {
        let (duplicate_quantum, actors) = armed_collector();
        complete_cpu_chain(&duplicate_quantum, 0, actors[0], 0x41, 0x401);
        assert_eq!(
            duplicate_quantum.observe_quantum_claim(
                0,
                actors[0].thread,
                actors[0].execution_generation,
                0x41,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );
        assert_eq!(
            duplicate_quantum.state.lock().quantum_payload[0]
                .unwrap()
                .value,
            0x41
        );

        let (reused_arm, actors) = armed_collector();
        complete_cpu_chain(&reused_arm, 0, actors[0], 0x42, 0x402);
        reused_arm
            .observe_running_claim(0, actors[1].thread, actors[1].execution_generation)
            .unwrap();
        assert_eq!(
            reused_arm.observe_quantum_claim(
                0,
                actors[1].thread,
                actors[1].execution_generation,
                0x42,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );
        let state = reused_arm.state.lock();
        assert_eq!(state.quantum_payload[0].unwrap().subject, 1);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Contradiction));
    }

    #[test]
    fn token8_expiry_terminal_join_is_independent_of_the_canonical_cpu_chain() {
        let (collector, actors) = armed_collector();
        complete_cpu_chain(&collector, 2, actors[0], 0x51, 0x501);
        let canonical = {
            let state = collector.state.lock();
            (
                state.run_payload[2],
                state.quantum_payload[2],
                state.preempt_payload[2],
            )
        };
        let token8 = actors[7];
        collector
            .observe_running_claim(2, token8.thread, token8.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, token8.execution_generation, 0x52)
            .unwrap();
        collector
            .observe_terminal_preemption_claim(
                2,
                token8.thread,
                token8.execution_generation,
                0x52,
                true,
            )
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(
            (
                state.run_payload[2],
                state.quantum_payload[2],
                state.preempt_payload[2],
            ),
            canonical
        );
        assert_eq!(state.cpu_chain[2], CpuChain::Empty);
        assert_eq!(state.token8_pending_expiry, None);
        assert_eq!(state.facts.race_matrix & (1 << 2), 1 << 2);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn later_generation_token8_cpu_surplus_cannot_poison_the_terminal_join() {
        let (collector, actors) = armed_collector();
        complete_cpu_chain(&collector, 2, actors[0], 0x51, 0x501);
        let token8 = actors[7];
        let later_generation = token8.execution_generation + 0x100;
        collector
            .observe_quantum_claim(2, token8.thread, later_generation, 0x52)
            .unwrap();
        collector
            .observe_preemption_claim(2, token8.thread, later_generation, 0x502)
            .unwrap();
        assert_eq!(collector.state.lock().token8_pending_expiry, None);

        collector
            .observe_running_claim(2, token8.thread, token8.execution_generation)
            .unwrap();
        collector
            .observe_quantum_claim(2, token8.thread, token8.execution_generation, 0x53)
            .unwrap();
        collector
            .observe_terminal_preemption_claim(
                2,
                token8.thread,
                token8.execution_generation,
                0x53,
                true,
            )
            .unwrap();
        let state = collector.state.lock();
        assert_eq!(state.token8_pending_expiry, None);
        assert_eq!(state.facts.race_matrix & (1 << 2), 1 << 2);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn repeated_run_is_idempotent_but_unjoined_relations_latch() {
        let (repeated, actors) = armed_collector();
        let actor = actors[0];
        repeated
            .observe_running_claim(0, actor.thread, actor.execution_generation)
            .unwrap();
        assert_eq!(
            repeated.observe_running_claim(0, actor.thread, actor.execution_generation),
            Ok(())
        );
        let state = repeated.state.lock();
        assert_eq!(
            state.cpu_chain[0],
            CpuChain::Run {
                token: actor.token,
                execution_generation: actor.execution_generation,
                serializable: true,
            }
        );
        assert_eq!(state.run_payload[0], None);
        assert_eq!(state.failure, None);
        drop(state);

        let (unjoined, actors) = armed_collector();
        let actor = actors[1];
        consume_arm_boundary_quantum(&unjoined, 1, actor, 8);
        assert_eq!(
            unjoined.observe_quantum_claim(1, actor.thread, actor.execution_generation + 1, 9,),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
        let state = unjoined.state.lock();
        assert_eq!(state.facts.quantum, 0);
        assert_eq!(state.quantum_payload[1], None);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::MissingKernelFact));
    }

    #[test]
    fn preempt_requires_the_same_exact_actor_as_the_cpu_quantum() {
        let (missing, actors) = armed_collector();
        assert_eq!(
            missing.observe_preemption_claim(
                1,
                actors[0].thread,
                actors[0].execution_generation,
                7,
            ),
            Err(Dw1cEvidenceError::MissingKernelFact)
        );
        assert_eq!(missing.state.lock().preempt_payload[1], None);

        let (mismatch, actors) = armed_collector();
        mismatch
            .observe_running_claim(1, actors[0].thread, actors[0].execution_generation)
            .unwrap();
        mismatch
            .observe_quantum_claim(1, actors[0].thread, actors[0].execution_generation, 6)
            .unwrap();
        assert_eq!(
            mismatch.observe_preemption_claim(
                1,
                actors[1].thread,
                actors[1].execution_generation,
                8,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );
        let state = mismatch.state.lock();
        assert_eq!(state.facts.preempt, 0);
        assert_eq!(state.preempt_payload[1], None);
        drop(state);

        let (replay, actors) = armed_collector();
        complete_cpu_chain(&replay, 1, actors[0], 6, 7);
        let retained = {
            let state = replay.state.lock();
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
            )
        };
        assert_eq!(
            replay
                .observe_preemption_claim(1, actors[0].thread, actors[0].execution_generation, 7,),
            Err(Dw1cEvidenceError::Duplicate)
        );
        let state = replay.state.lock();
        assert_eq!(
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
            ),
            retained
        );
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Duplicate));
        drop(state);

        let (reused_switch, actors) = armed_collector();
        complete_cpu_chain(&reused_switch, 1, actors[0], 6, 7);
        reused_switch
            .observe_running_claim(2, actors[1].thread, actors[1].execution_generation)
            .unwrap();
        reused_switch
            .observe_quantum_claim(2, actors[1].thread, actors[1].execution_generation, 8)
            .unwrap();
        let retained = {
            let state = reused_switch.state.lock();
            fixed_payload_snapshot(&state)
        };
        assert_eq!(
            reused_switch.observe_preemption_claim(
                2,
                actors[1].thread,
                actors[1].execution_generation,
                7,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );
        let state = reused_switch.state.lock();
        assert_eq!(fixed_payload_snapshot(&state), retained);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Contradiction));
    }

    #[test]
    fn remote_wake_migration_and_rejection_retain_exact_payloads() {
        let (collector, actors) = armed_collector();
        let remote = actors[4];
        assert_eq!(
            collector
                .observe_remote_wake_claim(
                    3,
                    1,
                    remote.thread,
                    remote.execution_generation,
                    0x1234_5678,
                )
                .unwrap(),
            Some(remote.token)
        );
        collector
            .observe_steal_migration_claim(1, 2, remote.thread, remote.execution_generation, 0x9988)
            .unwrap();
        let pinned = actors[5];
        collector
            .observe_migration_rejection_claim(
                3,
                pinned.thread,
                pinned.execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();

        let state = collector.state.lock();
        assert_eq!(
            state.remote_wake_payload[1],
            Some(Dw1cRecordPayload {
                subject: u64::from(remote.token),
                generation: remote.execution_generation,
                value: 1 | (3 << 8) | (0x1234_5678 << 16),
            })
        );
        assert_eq!(
            state.steal_migrate_payload,
            Some(Dw1cRecordPayload {
                subject: u64::from(remote.token),
                generation: 0x9988,
                value: 2 | (1 << 8),
            })
        );
        assert_eq!(
            state.migration_reject_payload,
            Some(Dw1cRecordPayload {
                subject: 6,
                generation: pinned.execution_generation,
                value: 3 | (u64::from(DW1C_MIGRATION_REJECT_EXECUTION_PINNED) << 8),
            })
        );
    }

    #[test]
    fn selected_token6_wake_and_rejection_accept_later_distinct_surplus() {
        let (collector, actors) = armed_collector();
        let token6 = actors[5];
        assert_eq!(
            collector.observe_remote_wake_claim(
                1,
                0,
                token6.thread,
                token6.execution_generation,
                7,
            ),
            Ok(Some(6))
        );
        collector
            .observe_migration_rejection_claim(
                1,
                token6.thread,
                token6.execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();
        let retained_rejection = collector.state.lock().migration_reject_payload;

        assert_eq!(
            collector.observe_remote_wake_claim(
                2,
                1,
                token6.thread,
                token6.execution_generation,
                8,
            ),
            Ok(None)
        );
        collector
            .observe_migration_rejection_claim(
                2,
                token6.thread,
                token6.execution_generation + 0x100,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();
        let state = collector.state.lock();
        assert_eq!(state.migration_reject_payload, retained_rejection);
        assert_eq!(state.failure, None);
        drop(state);

        let (replay, actors) = armed_collector();
        let token6 = actors[5];
        replay
            .observe_remote_wake_claim(1, 0, token6.thread, token6.execution_generation, 7)
            .unwrap();
        assert_eq!(
            replay.observe_remote_wake_claim(1, 0, token6.thread, token6.execution_generation, 7,),
            Err(Dw1cEvidenceError::Duplicate)
        );

        let (rejection_replay, actors) = armed_collector();
        let token6 = actors[5];
        rejection_replay
            .observe_migration_rejection_claim(
                1,
                token6.thread,
                token6.execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();
        let retained = {
            let state = rejection_replay.state.lock();
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
            )
        };
        assert_eq!(
            rejection_replay.observe_migration_rejection_claim(
                1,
                token6.thread,
                token6.execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );
        let state = rejection_replay.state.lock();
        assert_eq!(
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
            ),
            retained
        );
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Duplicate));
        drop(state);

        let (rejection_reuse, actors) = armed_collector();
        let token6 = actors[5];
        rejection_reuse
            .observe_migration_rejection_claim(
                1,
                token6.thread,
                token6.execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();
        let retained = {
            let state = rejection_reuse.state.lock();
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
            )
        };
        assert_eq!(
            rejection_reuse.observe_migration_rejection_claim(
                2,
                token6.thread,
                token6.execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );
        let state = rejection_reuse.state.lock();
        assert_eq!(
            (
                fixed_payload_snapshot(&state),
                private_join_snapshot(&state),
            ),
            retained
        );
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Contradiction));
    }

    #[test]
    fn later_surplus_and_overflowed_migration_relations_do_not_replace_payloads() {
        let (later, actors) = armed_collector();
        assert_eq!(
            later.observe_remote_wake_claim(
                0,
                1,
                actors[0].thread,
                actors[0].execution_generation + 1,
                7,
            ),
            Ok(None)
        );
        let state = later.state.lock();
        assert_eq!(state.remote_wake_payload[1], None);
        assert_eq!(state.failure, None);
        drop(state);

        let (overflow, actors) = armed_collector();
        assert_eq!(
            overflow.observe_remote_wake_claim(
                0,
                1,
                actors[0].thread,
                actors[0].execution_generation,
                DW1C_WAKE_GENERATION_MAX + 1,
            ),
            Err(Dw1cEvidenceError::Malformed)
        );
        assert_eq!(overflow.state.lock().remote_wake_payload[1], None);

        let (surplus, actors) = armed_collector();
        let actor = actors[0];
        surplus
            .observe_remote_wake_claim(0, 1, actor.thread, actor.execution_generation, 7)
            .unwrap();
        assert_eq!(
            surplus.observe_remote_wake_claim(
                2,
                1,
                actors[1].thread,
                actors[1].execution_generation,
                8,
            ),
            Ok(None)
        );
        assert_eq!(
            surplus.observe_remote_wake_claim(
                1,
                1,
                actors[2].thread,
                actors[2].execution_generation,
                9,
            ),
            Ok(None)
        );
        let state = surplus.state.lock();
        assert_eq!(state.remote_wake_payload[1].unwrap().value, 1 | (7 << 16));
        assert_eq!(state.failure, None);
        drop(state);

        let (occupied_later_generation, actors) = armed_collector();
        let first = actors[0];
        occupied_later_generation
            .observe_remote_wake_claim(0, 1, first.thread, first.execution_generation, 7)
            .unwrap();
        assert_eq!(
            occupied_later_generation.observe_remote_wake_claim(
                2,
                1,
                actors[1].thread,
                actors[1].execution_generation + 1,
                8,
            ),
            Ok(None)
        );
        let state = occupied_later_generation.state.lock();
        assert_eq!(state.remote_wake_payload[1].unwrap().subject, 1);
        assert_eq!(state.failure, None);
        drop(state);

        let (occupied_malformed, actors) = armed_collector();
        let first = actors[0];
        occupied_malformed
            .observe_remote_wake_claim(0, 1, first.thread, first.execution_generation, 7)
            .unwrap();
        assert_eq!(
            occupied_malformed.observe_remote_wake_claim(
                4,
                1,
                actors[1].thread,
                actors[1].execution_generation,
                8,
            ),
            Err(Dw1cEvidenceError::Malformed)
        );
        let state = occupied_malformed.state.lock();
        assert_eq!(state.remote_wake_payload[1].unwrap().subject, 1);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Malformed));
        drop(state);

        let (reused_generation, actors) = armed_collector();
        let first = actors[0];
        reused_generation
            .observe_remote_wake_claim(0, 1, first.thread, first.execution_generation, 7)
            .unwrap();
        assert_eq!(
            reused_generation.observe_remote_wake_claim(
                2,
                1,
                actors[1].thread,
                actors[1].execution_generation,
                7,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );
        let state = reused_generation.state.lock();
        assert_eq!(state.remote_wake_payload[1].unwrap().subject, 1);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Contradiction));
        drop(state);

        let (token6_surplus, actors) = armed_collector();
        let first = actors[0];
        token6_surplus
            .observe_remote_wake_claim(0, 1, first.thread, first.execution_generation, 7)
            .unwrap();
        let token6 = actors[5];
        assert_eq!(
            token6_surplus.observe_remote_wake_claim(
                2,
                1,
                token6.thread,
                token6.execution_generation,
                8,
            ),
            Ok(Some(6))
        );
        let state = token6_surplus.state.lock();
        assert!(state.token6_wake_seen);
        assert_eq!(state.remote_wake_payload[1].unwrap().subject, 1);
        assert_eq!(state.failure, None);
        drop(state);
        assert_eq!(
            token6_surplus.observe_remote_wake_claim(
                3,
                2,
                token6.thread,
                token6.execution_generation,
                9,
            ),
            Ok(None)
        );
        assert_eq!(token6_surplus.state.lock().failure, None);

        let (exact_duplicate, actors) = armed_collector();
        let actor = actors[0];
        exact_duplicate
            .observe_remote_wake_claim(0, 1, actor.thread, actor.execution_generation, 7)
            .unwrap();
        assert_eq!(
            exact_duplicate.observe_remote_wake_claim(
                0,
                1,
                actor.thread,
                actor.execution_generation,
                7,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );

        let (local_token6, actors) = armed_collector();
        let token6 = actors[5];
        assert_eq!(
            local_token6.observe_remote_wake_claim(
                2,
                2,
                token6.thread,
                token6.execution_generation,
                10,
            ),
            Ok(Some(6))
        );
        let state = local_token6.state.lock();
        assert!(state.token6_wake_seen);
        assert_eq!(state.facts.remote_wake, 0);
        assert_eq!(state.remote_wake_payload, [None; 4]);
        assert_eq!(state.failure, None);
        drop(state);

        let (later_migration, actors) = armed_collector();
        assert_eq!(
            later_migration.observe_steal_migration_claim(
                1,
                2,
                actors[2].thread,
                actors[2].execution_generation + 1,
                9,
            ),
            Ok(())
        );
        let state = later_migration.state.lock();
        assert_eq!(state.steal_migrate_payload, None);
        assert_eq!(state.failure, None);
        drop(state);

        let (later_rejection, actors) = armed_collector();
        let token6 = actors[5];
        later_rejection
            .observe_migration_rejection_claim(
                1,
                token6.thread,
                token6.execution_generation + 1,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();
        let state = later_rejection.state.lock();
        assert_eq!(state.migration_reject_payload, None);
        assert_eq!(state.failure, None);
        drop(state);

        let (surplus_migration, actors) = armed_collector();
        surplus_migration
            .observe_steal_migration_claim(
                1,
                2,
                actors[2].thread,
                actors[2].execution_generation,
                9,
            )
            .unwrap();
        assert_eq!(
            surplus_migration.observe_steal_migration_claim(
                2,
                3,
                actors[3].thread,
                actors[3].execution_generation,
                10,
            ),
            Ok(())
        );
        assert_eq!(
            surplus_migration
                .state
                .lock()
                .steal_migrate_payload
                .unwrap()
                .generation,
            9
        );
        assert_eq!(surplus_migration.state.lock().failure, None);

        let (duplicate_migration, actors) = armed_collector();
        let actor = actors[2];
        duplicate_migration
            .observe_steal_migration_claim(1, 2, actor.thread, actor.execution_generation, 9)
            .unwrap();
        let retained = duplicate_migration
            .state
            .lock()
            .steal_migrate_payload
            .unwrap();
        assert_eq!(
            duplicate_migration.observe_steal_migration_claim(
                1,
                2,
                actor.thread,
                actor.execution_generation,
                9,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );
        let state = duplicate_migration.state.lock();
        assert_eq!(state.steal_migrate_payload, Some(retained));
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Duplicate));
        drop(state);

        let (reused_migration_generation, actors) = armed_collector();
        reused_migration_generation
            .observe_steal_migration_claim(
                1,
                2,
                actors[2].thread,
                actors[2].execution_generation,
                9,
            )
            .unwrap();
        let retained = reused_migration_generation
            .state
            .lock()
            .steal_migrate_payload
            .unwrap();
        assert_eq!(
            reused_migration_generation.observe_steal_migration_claim(
                2,
                3,
                actors[3].thread,
                actors[3].execution_generation,
                9,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );
        let state = reused_migration_generation.state.lock();
        assert_eq!(state.steal_migrate_payload, Some(retained));
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Contradiction));
        drop(state);

        let (occupied_continuation_migration, actors) = armed_collector();
        occupied_continuation_migration
            .observe_steal_migration_claim(
                1,
                2,
                actors[2].thread,
                actors[2].execution_generation,
                9,
            )
            .unwrap();
        let retained = occupied_continuation_migration
            .state
            .lock()
            .steal_migrate_payload
            .unwrap();
        assert_eq!(
            occupied_continuation_migration.observe_steal_migration_claim(
                2,
                3,
                actors[3].thread,
                0,
                10,
            ),
            Ok(())
        );
        let state = occupied_continuation_migration.state.lock();
        assert_eq!(state.steal_migrate_payload, Some(retained));
        assert_eq!(state.failure, None);
        drop(state);

        let (occupied_malformed_migration, actors) = armed_collector();
        occupied_malformed_migration
            .observe_steal_migration_claim(
                1,
                2,
                actors[2].thread,
                actors[2].execution_generation,
                9,
            )
            .unwrap();
        let retained = occupied_malformed_migration
            .state
            .lock()
            .steal_migrate_payload
            .unwrap();
        assert_eq!(
            occupied_malformed_migration.observe_steal_migration_claim(
                3,
                3,
                actors[3].thread,
                actors[3].execution_generation,
                10,
            ),
            Err(Dw1cEvidenceError::Malformed)
        );
        let state = occupied_malformed_migration.state.lock();
        assert_eq!(state.steal_migrate_payload, Some(retained));
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Malformed));
        drop(state);

        let (wrong_rejection, actors) = armed_collector();
        assert_eq!(
            wrong_rejection.observe_migration_rejection_claim(
                0,
                actors[4].thread,
                actors[4].execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            ),
            Err(Dw1cEvidenceError::Malformed)
        );
        assert_eq!(wrong_rejection.state.lock().migration_reject_payload, None);
    }

    #[test]
    fn implemented_fixed_stream_records_decode_exact_retained_values() {
        let (collector, actors) = armed_collector();
        for cpu in 0_u8..4 {
            collector
                .observe_cpu_ready_payload(
                    cpu,
                    0x1000 + u64::from(cpu),
                    0x2000 + u64::from(cpu),
                    0x3000 + u64::from(cpu),
                )
                .unwrap();
            let actor = actors[usize::from(cpu)];
            collector
                .observe_running_claim(cpu, actor.thread, actor.execution_generation)
                .unwrap();
            collector
                .observe_quantum_claim(
                    cpu,
                    actor.thread,
                    actor.execution_generation,
                    0x4000 + u64::from(cpu),
                )
                .unwrap();
            collector
                .observe_preemption_claim(
                    cpu,
                    actor.thread,
                    actor.execution_generation,
                    0x5000 + u64::from(cpu),
                )
                .unwrap();
            let wake_actor = actors[usize::from(cpu) + 4];
            collector
                .observe_remote_wake_claim(
                    (cpu + 1) % 4,
                    cpu,
                    wake_actor.thread,
                    wake_actor.execution_generation,
                    0x6000 + u64::from(cpu),
                )
                .unwrap();
        }
        for (index, actor) in actors[..5].iter().copied().enumerate() {
            collector
                .progress(
                    actor.process,
                    u64::from(actor.token),
                    0x7000 + index as u64,
                    2,
                )
                .unwrap();
        }
        collector
            .observe_steal_migration_claim(
                2,
                3,
                actors[4].thread,
                actors[4].execution_generation,
                0x8000,
            )
            .unwrap();
        collector
            .observe_migration_rejection_claim(
                1,
                actors[5].thread,
                actors[5].execution_generation,
                DW1C_MIGRATION_REJECT_EXECUTION_PINNED,
            )
            .unwrap();
        for actor in actors[8..].iter().copied() {
            collector
                .observe_process_exit(actor.process, actor.thread, actor.execution_generation, 0)
                .unwrap();
        }
        for actor in actors[8..].iter().copied() {
            collector
                .observe_process_reap(actor.process, actor.process.object_id().generation(), 1)
                .unwrap();
        }

        let state = collector.state.lock();
        for sequence in 0..=36 {
            let expected = payload_for(sequence, &state).unwrap();
            let record = encode_record(1, sequence as u32, event_for(sequence), expected);
            assert_eq!(decoded_payload(&record), expected, "sequence {sequence}");
        }
        assert_eq!(payload_for(37, &state), Err(Dw1cEvidenceError::Incomplete));
        for sequence in 38..=41 {
            let expected = payload_for(sequence, &state).unwrap();
            let record = encode_record(1, sequence as u32, event_for(sequence), expected);
            assert_eq!(decoded_payload(&record), expected, "sequence {sequence}");
        }
        assert_eq!(payload_for(45, &state).unwrap().generation, 0);
    }

    #[test]
    fn final_completion_fails_before_terminal_claim_when_later_payload_families_are_missing() {
        let (collector, actors) = armed_collector();
        let reporter = collector.state.lock().reporter.unwrap();
        {
            let mut state = collector.state.lock();
            state.progress = [1, 2, 3, 4, 5];
            for cpu in 0..4 {
                let actor = actors[cpu];
                let payload = Dw1cRecordPayload {
                    subject: u64::from(actor.token),
                    generation: actor.execution_generation,
                    value: cpu as u64,
                };
                state.cpu_ready_payload[cpu] = Some(Dw1cRecordPayload {
                    subject: 0x100 + cpu as u64,
                    generation: 0x200 + cpu as u64,
                    value: 0x300 + cpu as u64,
                });
                state.run_payload[cpu] = Some(payload);
                state.quantum_payload[cpu] = Some(Dw1cRecordPayload {
                    value: 0x400 + cpu as u64,
                    ..payload
                });
                state.preempt_payload[cpu] = Some(Dw1cRecordPayload {
                    value: 0x500 + cpu as u64,
                    ..payload
                });
                state.remote_wake_payload[cpu] = Some(Dw1cRecordPayload {
                    value: cpu as u64 | (((cpu + 1) % 4) as u64) << 8 | (1_u64 << 16),
                    ..payload
                });
            }
            state.steal_migrate_payload = Some(Dw1cRecordPayload {
                subject: 5,
                generation: 1,
                value: 0x0102,
            });
            state.migration_reject_payload = Some(Dw1cRecordPayload {
                subject: 6,
                generation: actors[5].execution_generation,
                value: 1 | (u64::from(DW1C_MIGRATION_REJECT_EXECUTION_PINNED) << 8),
            });
            state.facts = Dw1cKernelFacts {
                cpu_ready: 0x0f,
                run: 0x0f,
                quantum: 0x0f,
                preempt: 0x0f,
                remote_wake: 0x0f,
                steal_migrate: true,
                migration_reject_execution_pinned: true,
                race_matrix: 0x0f,
                lifecycle: 0x03,
                bootstrap_normal: false,
                accounting_sound: false,
                ready_delay_ns: 0,
            };
        }

        assert!(!collector.state.lock().facts.complete());
        collector
            .workload_complete(reporter.0, u64::from(DW1C_PROGRESS_MASK), 2)
            .unwrap();
        assert!(matches!(
            collector.final_normal_completion(
                101,
                0xa1,
                Dw1cFinalSchedulerSnapshot::for_test(1, 1, 1, 0x3f),
            ),
            Err(Dw1cEvidenceError::Incomplete)
        ));
        assert_eq!(collector.terminal.load(Ordering::Acquire), 0);
        let state = collector.state.lock();
        assert!(!state.terminal);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Incomplete));
    }
}
