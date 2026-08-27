//! Selector-28-only kernel-owned DW1C evidence collector.
//!
//! This is deliberately not a scheduler ABI.  The only userspace input is a
//! ten-entry ARM table and five bounded progress acknowledgements; all facts
//! which make the transcript meaningful are captured by selector-local kernel
//! hooks.  Production builds never compile this module.

#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::sync::SpinMutex;
use crate::task::{ProcessKey, ThreadKey};

pub(crate) const DW1C_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1c;
pub(crate) const DW1C_EVIDENCE_RECORD_LEN: usize = 96;
pub(crate) const DW1C_EVIDENCE_RECORD_CAPACITY: usize = 46;
pub(crate) const DW1C_ACTOR_COUNT: usize = 10;
pub(crate) const DW1C_ARM_BYTES: usize = DW1C_ACTOR_COUNT * 24;
pub(crate) const DW1C_ARM_TIMEOUT_SECONDS: u64 = 240;
/// A selector-private workload count is bounded to prevent a malformed raw
/// request from turning a progress acknowledgement into an unbounded value.
pub(crate) const DW1C_PROGRESS_MAX: u64 = u32::MAX as u64;
pub(crate) const DW1C_PROGRESS_MASK: u8 = 0x1f;
pub(crate) const DW1C_MIGRATION_REJECT_EXECUTION_PINNED: u8 = 0x04;
const DW1C_WAKE_GENERATION_MAX: u64 = 0x0000_ffff_ffff_ffff;
const DW1C_LIFECYCLE_ACTOR_FIRST: usize = 8;
const TERMINAL_EVENT: u8 = 0xff;
const EMPTY: [u8; DW1C_EVIDENCE_RECORD_LEN] = [0; DW1C_EVIDENCE_RECORD_LEN];

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
    cpu_ready_payload: [Option<Dw1cRecordPayload>; 4],
    run_payload: [Option<Dw1cRecordPayload>; 4],
    quantum_payload: [Option<Dw1cRecordPayload>; 4],
    preempt_payload: [Option<Dw1cRecordPayload>; 4],
    remote_wake_payload: [Option<Dw1cRecordPayload>; 4],
    steal_migrate_payload: Option<Dw1cRecordPayload>,
    migration_reject_payload: Option<Dw1cRecordPayload>,
    exit_payload: [Option<Dw1cRecordPayload>; 2],
    reap_payload: [Option<Dw1cRecordPayload>; 2],
    lifecycle_process_generation: [Option<u64>; 2],
    token6_wait_joined: bool,
    token6_wake_seen: bool,
    token6_run_seen: bool,
    facts: Dw1cKernelFacts,
    terminal: bool,
    failure: Option<Dw1cEvidenceError>,
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
            cpu_ready_payload: [None; 4],
            run_payload: [None; 4],
            quantum_payload: [None; 4],
            preempt_payload: [None; 4],
            remote_wake_payload: [None; 4],
            steal_migrate_payload: None,
            migration_reject_payload: None,
            exit_payload: [None; 2],
            reap_payload: [None; 2],
            lifecycle_process_generation: [None; 2],
            token6_wait_joined: false,
            token6_wake_seen: false,
            token6_run_seen: false,
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
    /// userspace.  No callback accepts a pre-install relation, and a second
    /// installation is a terminal selector failure.
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
        if !state.installed {
            return Ok(());
        }
        if state.reporter.is_some() {
            if state
                .actors
                .iter()
                .flatten()
                .any(|actor| actor.process == process)
            {
                return Err(state.latch(Dw1cEvidenceError::Contradiction));
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
        actors: [Dw1cActor; DW1C_ACTOR_COUNT],
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.failure.is_some() || state.reporter.is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        for (index, actor) in actors.iter().enumerate() {
            if actor.token as usize != index + 1
                || actor.role as usize != index + 1
                || actor.process == reporter.0
                || actor.execution_generation == 0
                || actors[..index]
                    .iter()
                    .any(|prior| prior.process == actor.process)
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
        state.token6_wait_joined = token6_wait_joined;
        state.lifecycle_process_generation = lifecycle_generations;
        for (slot, actor) in state.actors.iter_mut().zip(actors) {
            *slot = Some(actor);
        }
        Ok(())
    }

    /// Hooks are supplied by the kernel scheduler, never by raw userspace data.
    pub(crate) fn observe_kernel_facts(
        &self,
        facts: Dw1cKernelFacts,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed || state.reporter.is_none() || state.terminal {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if state.facts.cpu_ready & !facts.cpu_ready != 0
            || state.facts.run & !facts.run != 0
            || state.facts.quantum & !facts.quantum != 0
            || state.facts.preempt & !facts.preempt != 0
            || state.facts.remote_wake & !facts.remote_wake != 0
            || state.facts.race_matrix & !facts.race_matrix != 0
        {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
        state.facts = facts;
        Ok(())
    }

    /// Concrete scheduler commit-point callbacks.  They accept only a bound
    /// `(ProcessKey, ThreadKey, execution_generation)` tuple and latch on an
    /// unbound/stale subject or a repeated per-CPU fact.  The scheduler keeps
    /// its lock; this collector takes its own bounded lock only after the
    /// scheduler transition has committed.
    pub(crate) fn observe_running(
        &self,
        cpu: u8,
        process: ProcessKey,
        thread: ThreadKey,
        generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_actor(cpu, process, thread, generation, u64::from(cpu), 0)
    }

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
        state.installed && actor_thread_known(&state, thread)
    }

    pub(crate) fn observe_quantum_expiry(
        &self,
        cpu: u8,
        process: ProcessKey,
        thread: ThreadKey,
        generation: u64,
        source_arm_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_actor(cpu, process, thread, generation, source_arm_generation, 1)
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

    pub(crate) fn observe_preemption(
        &self,
        cpu: u8,
        process: ProcessKey,
        thread: ThreadKey,
        generation: u64,
        completed_switch_generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_actor(
            cpu,
            process,
            thread,
            generation,
            completed_switch_generation,
            2,
        )
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

    pub(crate) fn observe_remote_wake_claim(
        &self,
        source_cpu: u8,
        target_cpu: u8,
        thread: ThreadKey,
        generation: u64,
        wake_generation: u64,
    ) -> Result<Option<u8>, Dw1cEvidenceError> {
        let mut state = self.state.lock();
        let bit = cpu_bit(target_cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
        if !state.installed {
            return Err(state.latch(Dw1cEvidenceError::Early));
        }
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        if !actor_thread_bound(&state, thread, generation) {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        if source_cpu == target_cpu
            || cpu_bit(source_cpu).is_none()
            || wake_generation == 0
            || wake_generation > DW1C_WAKE_GENERATION_MAX
        {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        let index = usize::from(target_cpu);
        if state.facts.remote_wake & bit != 0 || state.remote_wake_payload[index].is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        let token = actor_token_for_claim(&state, thread, generation)
            .expect("bound remote wake retains its selector token");
        if token == 6 && (!state.token6_wait_joined || state.token6_wake_seen) {
            let error = if state.token6_wake_seen {
                Dw1cEvidenceError::Duplicate
            } else {
                Dw1cEvidenceError::MissingKernelFact
            };
            return Err(state.latch(error));
        }
        let value = u64::from(target_cpu) | (u64::from(source_cpu) << 8) | (wake_generation << 16);
        state.remote_wake_payload[index] = Some(Dw1cRecordPayload {
            subject: u64::from(token),
            generation,
            value,
        });
        state.facts.remote_wake |= bit;
        if token == 6 {
            state.token6_wake_seen = true;
            update_race_bit_zero(&mut state);
        }
        Ok(Some(token))
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
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        if !actor_thread_bound(&state, thread, execution_generation) {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        if source_cpu == target_cpu
            || cpu_bit(source_cpu).is_none()
            || cpu_bit(target_cpu).is_none()
            || migration_generation == 0
        {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if state.facts.steal_migrate || state.steal_migrate_payload.is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        let token = actor_token_for_claim(&state, thread, execution_generation)
            .expect("bound migration retains its selector token");
        state.steal_migrate_payload = Some(Dw1cRecordPayload {
            subject: u64::from(token),
            generation: migration_generation,
            value: u64::from(target_cpu) | (u64::from(source_cpu) << 8),
        });
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
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        let Some(token) = actor_token_for_claim(&state, thread, execution_generation) else {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        };
        if token != 6 || cpu_bit(cpu).is_none() || reason != DW1C_MIGRATION_REJECT_EXECUTION_PINNED
        {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if state.facts.migration_reject_execution_pinned || state.migration_reject_payload.is_some()
        {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        state.migration_reject_payload = Some(Dw1cRecordPayload {
            subject: u64::from(token),
            generation: execution_generation,
            value: u64::from(cpu) | (u64::from(reason) << 8),
        });
        state.facts.migration_reject_execution_pinned = true;
        Ok(())
    }

    /// Records the normal Process-exit commit for lifecycle actors only. The
    /// terminal execution generation is sampled from the live claim before
    /// TaskAuthority commits, then joined here immediately after that commit.
    pub(crate) fn observe_process_exit(
        &self,
        process: ProcessKey,
        thread: ThreadKey,
        terminal_thread_generation: u64,
        code: u32,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
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
        if actor.thread != thread
            || actor.execution_generation != terminal_thread_generation
            || terminal_thread_generation == 0
        {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        let index = usize::from(actor.token - 9);
        if state.exit_payload[index].is_some() {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        let expected = state
            .exit_payload
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| state.latch(Dw1cEvidenceError::Duplicate))?;
        if index != expected {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
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
    /// bind, and the stream order is EXIT(9,10) then REAP(9,10).
    pub(crate) fn observe_process_reap(
        &self,
        process: ProcessKey,
        process_generation: u64,
        count: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
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
        if state.exit_payload.iter().any(Option::is_none) {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        }
        let expected = state
            .reap_payload
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| state.latch(Dw1cEvidenceError::Duplicate))?;
        if index != expected {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
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

    pub(crate) fn observe_cpu_ready(&self, cpu: u8) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        let bit = cpu_bit(cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
        if !state.installed || state.facts.cpu_ready & bit != 0 {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        state.facts.cpu_ready |= bit;
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
        let index = usize::from(cpu);
        let bit = cpu_bit(cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
        if !state.installed
            || subject == 0
            || generation == 0
            || value == 0
            || state.cpu_ready_payload[index].is_some()
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

    fn observe_cpu_actor(
        &self,
        cpu: u8,
        process: ProcessKey,
        thread: ThreadKey,
        generation: u64,
        value: u64,
        kind: u8,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if !state.installed || !actor_bound(&state, process, thread, generation) {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        retain_cpu_payload(&mut state, cpu, thread, generation, value, kind)
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
        if !actor_thread_known(&state, thread) {
            return Err(state.latch(Dw1cEvidenceError::WrongActor));
        }
        if !actor_thread_bound(&state, thread, generation) {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        retain_cpu_payload(&mut state, cpu, thread, generation, value, kind)
    }

    pub(crate) fn progress(
        &self,
        caller: ProcessKey,
        token: u64,
        count: u64,
        digest: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
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

    pub(crate) fn complete(
        &self,
        caller: ProcessKey,
        mask: u64,
        digest: u64,
    ) -> Result<Dw1cEvidenceFlushPermit<'_>, Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if let Some(error) = state.failure {
            return Err(error);
        }
        if state.reporter.map(|reporter| reporter.0) != Some(caller) {
            return Err(state.latch(Dw1cEvidenceError::WrongReporter));
        }
        if state.arm_timeout_seconds != DW1C_ARM_TIMEOUT_SECONDS {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        if mask != u64::from(DW1C_PROGRESS_MASK)
            || digest != self.digest
            || state.progress.iter().any(|count| *count == 0)
        {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
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

    pub(crate) fn flush(
        &self,
        write: impl FnMut(&[u8; DW1C_EVIDENCE_RECORD_LEN]) -> Result<(), ()>,
    ) -> Result<(), Dw1cEvidenceError> {
        let state = self.state.lock();
        if state.failure.is_some() || !state.terminal || !state.facts.complete() {
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

fn retain_cpu_payload(
    state: &mut State,
    cpu: u8,
    thread: ThreadKey,
    execution_generation: u64,
    value: u64,
    kind: u8,
) -> Result<(), Dw1cEvidenceError> {
    let bit = cpu_bit(cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
    let index = usize::from(cpu);
    if kind > 2 || (kind == 0 && value != u64::from(cpu)) || (kind != 0 && value == 0) {
        return Err(state.latch(Dw1cEvidenceError::Malformed));
    }
    let token = state
        .actors
        .iter()
        .flatten()
        .find(|actor| actor.thread == thread && actor.execution_generation == execution_generation)
        .expect("bound actor retains its selector token")
        .token;
    if kind == 0 && token == 6 && !state.token6_wake_seen {
        return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
    }
    let payload = Dw1cRecordPayload {
        subject: u64::from(token),
        generation: execution_generation,
        value,
    };
    if kind == 2 {
        let Some(quantum) = state.quantum_payload[index] else {
            return Err(state.latch(Dw1cEvidenceError::MissingKernelFact));
        };
        if quantum.subject != payload.subject || quantum.generation != payload.generation {
            return Err(state.latch(Dw1cEvidenceError::Contradiction));
        }
    }
    let duplicate = match kind {
        0 => state.facts.run & bit != 0 || state.run_payload[index].is_some(),
        1 => state.facts.quantum & bit != 0 || state.quantum_payload[index].is_some(),
        _ => state.facts.preempt & bit != 0 || state.preempt_payload[index].is_some(),
    };
    if duplicate {
        return Err(state.latch(Dw1cEvidenceError::Duplicate));
    }
    match kind {
        0 => {
            state.facts.run |= bit;
            state.run_payload[index] = Some(payload);
            if token == 6 {
                state.token6_run_seen = true;
                update_race_bit_zero(state);
            }
        }
        1 => {
            state.facts.quantum |= bit;
            state.quantum_payload[index] = Some(payload);
        }
        _ => {
            state.facts.preempt |= bit;
            state.preempt_payload[index] = Some(payload);
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

fn actor_bound(state: &State, process: ProcessKey, thread: ThreadKey, generation: u64) -> bool {
    generation != 0
        && state.actors.iter().flatten().any(|actor| {
            actor.process == process
                && actor.thread == thread
                && actor.execution_generation == generation
        })
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
        38..=39 => state.exit_payload[sequence - 38],
        40..=41 => state.reap_payload[sequence - 40],
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
    use deepwyrm_abi::{DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD};
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
        collector.arm(reporter, actors).unwrap();
        (collector, actors)
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
            c.arm((actors[0].process, actors[0].thread), actors)
                .is_err()
        );
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
            collector.arm(reporter, actors),
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
            missing_create.arm(reporter, actors),
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
            missing_start.arm(reporter, actors),
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
            stale_wait.arm(reporter, actors),
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
            collector.arm(reporter, actors),
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
        unrelated.arm(reporter, actors).unwrap();
        assert_eq!(unrelated.state.lock().failure, None);
        assert_eq!(
            unrelated.observe_thread_create(actors[0].process, thread),
            Err(Dw1cEvidenceError::Contradiction)
        );
    }

    #[test]
    fn direct_actor_observers_latch_unknown_or_stale_identities() {
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
        assert_eq!(
            collector.observe_quantum_claim(0, actor.thread, actor.execution_generation + 1, 7),
            Err(Dw1cEvidenceError::WrongGeneration)
        );
        assert_eq!(
            collector.state.lock().failure,
            Some(Dw1cEvidenceError::WrongGeneration)
        );
    }

    #[test]
    fn lifecycle_exit_and_reap_retain_exact_ordered_payloads() {
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
            .observe_process_exit(
                token10.process,
                token10.thread,
                token10.execution_generation,
                0,
            )
            .unwrap();
        collector
            .observe_process_reap(token9.process, token9.process.object_id().generation(), 1)
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
    fn lifecycle_rejects_stale_duplicate_and_out_of_order_terminal_facts() {
        let (out_of_order, actors) = armed_collector();
        assert_eq!(
            out_of_order.observe_process_exit(
                actors[9].process,
                actors[9].thread,
                actors[9].execution_generation,
                0,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );

        let (stale, actors) = armed_collector();
        assert_eq!(
            stale.observe_process_exit(
                actors[8].process,
                actors[8].thread,
                actors[8].execution_generation + 1,
                0,
            ),
            Err(Dw1cEvidenceError::WrongGeneration)
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
        assert_eq!(
            reap_out_of_order.observe_process_reap(
                actors[9].process,
                actors[9].process.object_id().generation(),
                1,
            ),
            Err(Dw1cEvidenceError::Contradiction)
        );

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
    fn duplicate_and_stale_cpu_relations_latch_without_replacing_payload() {
        let (duplicate, actors) = armed_collector();
        let actor = actors[0];
        duplicate
            .observe_running_claim(0, actor.thread, actor.execution_generation)
            .unwrap();
        assert_eq!(
            duplicate.observe_running_claim(0, actor.thread, actor.execution_generation),
            Err(Dw1cEvidenceError::Duplicate)
        );
        let state = duplicate.state.lock();
        assert_eq!(state.run_payload[0].unwrap().value, 0);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Duplicate));
        drop(state);

        let (stale, actors) = armed_collector();
        let actor = actors[1];
        assert_eq!(
            stale.observe_quantum_claim(1, actor.thread, actor.execution_generation + 1, 9,),
            Err(Dw1cEvidenceError::WrongGeneration)
        );
        let state = stale.state.lock();
        assert_eq!(state.facts.quantum, 0);
        assert_eq!(state.quantum_payload[1], None);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::WrongGeneration));
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
    fn stale_duplicate_and_overflowed_migration_relations_do_not_replace_payloads() {
        let (stale, actors) = armed_collector();
        assert_eq!(
            stale.observe_remote_wake_claim(
                0,
                1,
                actors[0].thread,
                actors[0].execution_generation + 1,
                7,
            ),
            Err(Dw1cEvidenceError::WrongGeneration)
        );
        assert_eq!(stale.state.lock().remote_wake_payload[1], None);

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

        let (duplicate, actors) = armed_collector();
        let actor = actors[0];
        duplicate
            .observe_remote_wake_claim(0, 1, actor.thread, actor.execution_generation, 7)
            .unwrap();
        assert_eq!(
            duplicate.observe_remote_wake_claim(
                2,
                1,
                actors[1].thread,
                actors[1].execution_generation,
                8,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );
        let state = duplicate.state.lock();
        assert_eq!(state.remote_wake_payload[1].unwrap().value, 1 | (7 << 16));
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Duplicate));
        drop(state);

        let (stale_migration, actors) = armed_collector();
        assert_eq!(
            stale_migration.observe_steal_migration_claim(
                1,
                2,
                actors[2].thread,
                actors[2].execution_generation + 1,
                9,
            ),
            Err(Dw1cEvidenceError::WrongGeneration)
        );
        assert_eq!(stale_migration.state.lock().steal_migrate_payload, None);

        let (duplicate_migration, actors) = armed_collector();
        duplicate_migration
            .observe_steal_migration_claim(
                1,
                2,
                actors[2].thread,
                actors[2].execution_generation,
                9,
            )
            .unwrap();
        assert_eq!(
            duplicate_migration.observe_steal_migration_claim(
                2,
                3,
                actors[3].thread,
                actors[3].execution_generation,
                10,
            ),
            Err(Dw1cEvidenceError::Duplicate)
        );
        assert_eq!(
            duplicate_migration
                .state
                .lock()
                .steal_migrate_payload
                .unwrap()
                .generation,
            9
        );

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
    fn complete_fails_before_terminal_claim_when_later_payload_families_are_missing() {
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
                race_matrix: DW1C_PROGRESS_MASK,
                lifecycle: 0x03,
                bootstrap_normal: true,
                accounting_sound: true,
                ready_delay_ns: 1,
            };
        }

        assert!(collector.state.lock().facts.complete());
        assert!(matches!(
            collector.complete(reporter.0, u64::from(DW1C_PROGRESS_MASK), 2),
            Err(Dw1cEvidenceError::Incomplete)
        ));
        assert_eq!(collector.terminal.load(Ordering::Acquire), 0);
        let state = collector.state.lock();
        assert!(!state.terminal);
        assert_eq!(state.failure, Some(Dw1cEvidenceError::Incomplete));
    }
}
