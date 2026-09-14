//! Allocation-free host model for the frozen DW1 normal scheduling policy.
//!
//! This is deliberately test-only. It exercises the future DW1-B/C policy
//! contract without changing the live cooperative scheduler or claiming that
//! timer-driven preemption and AP carrier execution exist.

const CPU_COUNT: usize = 4;
const TASK_CAPACITY: usize = 8;
const DEFAULT_QUANTUM_NS: u64 = 5_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskId {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RunToken {
    task: TaskId,
    cpu: usize,
    execution_generation: u64,
    arm_generation: u64,
    deadline_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WakeToken {
    task: TaskId,
    block_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelError {
    Capacity,
    Duplicate,
    Missing,
    Stale,
    OfflineCpu,
    IneligibleCpu,
    CpuBusy,
    NotRunning,
    BlockPreparing,
    NotBlocked,
    Terminal,
    MigrationRejected,
    RemoteStopPending,
    Overflow,
    TimeRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskState {
    Empty,
    Runnable { cpu: usize, enqueue_generation: u64 },
    Running { token: RunToken },
    BlockPreparing { token: RunToken },
    Blocked { block_generation: u64 },
    Terminal,
}

#[derive(Clone, Copy, Debug)]
struct TaskRecord {
    id: Option<TaskId>,
    state: TaskState,
    eligibility: u8,
    last_cpu: Option<usize>,
    continuation_cpu: Option<usize>,
    execution_pins: u8,
    scratch_pins: u8,
    root_switch: bool,
    remote_stop: bool,
    rendezvous_pending: bool,
    migration_generation: u64,
}

impl TaskRecord {
    const EMPTY: Self = Self {
        id: None,
        state: TaskState::Empty,
        eligibility: 0,
        last_cpu: None,
        continuation_cpu: None,
        execution_pins: 0,
        scratch_pins: 0,
        root_switch: false,
        remote_stop: false,
        rendezvous_pending: false,
        migration_generation: 0,
    };

    fn migratable(self) -> bool {
        matches!(self.state, TaskState::Runnable { .. })
            && self.continuation_cpu.is_none()
            && self.execution_pins == 0
            && self.scratch_pins == 0
            && !self.root_switch
            && !self.remote_stop
            && !self.rendezvous_pending
    }
}

#[derive(Clone, Copy)]
struct Queue {
    entries: [Option<TaskId>; TASK_CAPACITY],
    len: usize,
}

impl Queue {
    const EMPTY: Self = Self {
        entries: [None; TASK_CAPACITY],
        len: 0,
    };

    fn push(&mut self, task: TaskId) -> Result<(), ModelError> {
        if self.len == TASK_CAPACITY {
            return Err(ModelError::Capacity);
        }
        if self.entries[..self.len].contains(&Some(task)) {
            return Err(ModelError::Duplicate);
        }
        self.entries[self.len] = Some(task);
        self.len += 1;
        Ok(())
    }

    fn remove(&mut self, index: usize) -> TaskId {
        let task = self.entries[index].take().expect("occupied queue index");
        for cursor in index..self.len - 1 {
            self.entries[cursor] = self.entries[cursor + 1].take();
        }
        self.len -= 1;
        self.entries[self.len] = None;
        task
    }

    fn position(&self, task: TaskId) -> Option<usize> {
        self.entries[..self.len]
            .iter()
            .position(|entry| *entry == Some(task))
    }
}

struct NormalPolicyModel {
    online: u8,
    tasks: [TaskRecord; TASK_CAPACITY],
    queues: [Queue; CPU_COUNT],
    running: [Option<RunToken>; CPU_COUNT],
    next_execution: u64,
    next_enqueue: u64,
    next_arm: [u64; CPU_COUNT],
    next_block: u64,
    quantum_expirations: u64,
    quanta_served: [u64; TASK_CAPACITY],
    recovery_offers: u64,
    recovery_refusals: u64,
    rebalance_pulls: u64,
    now_ns: u64,
    overflow_fault: bool,
}

impl NormalPolicyModel {
    fn new(online: u8) -> Self {
        Self {
            online: online & 0b1111,
            tasks: [TaskRecord::EMPTY; TASK_CAPACITY],
            queues: [Queue::EMPTY; CPU_COUNT],
            running: [None; CPU_COUNT],
            next_execution: 1,
            next_enqueue: 1,
            next_arm: [1; CPU_COUNT],
            next_block: 1,
            quantum_expirations: 0,
            quanta_served: [0; TASK_CAPACITY],
            recovery_offers: 0,
            recovery_refusals: 0,
            rebalance_pulls: 0,
            now_ns: 0,
            overflow_fault: false,
        }
    }

    fn mint(counter: &mut u64) -> Result<u64, ModelError> {
        let value = *counter;
        *counter = value
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(ModelError::Overflow)?;
        Ok(value)
    }

    fn validate_cpu(&self, cpu: usize) -> Result<(), ModelError> {
        if cpu >= CPU_COUNT || self.online & (1 << cpu) == 0 {
            Err(ModelError::OfflineCpu)
        } else {
            Ok(())
        }
    }

    fn record(&self, task: TaskId) -> Result<&TaskRecord, ModelError> {
        let record = self.tasks.get(task.slot).ok_or(ModelError::Missing)?;
        if record.id != Some(task) {
            return Err(if record.id.is_some() {
                ModelError::Stale
            } else {
                ModelError::Missing
            });
        }
        Ok(record)
    }

    fn record_mut(&mut self, task: TaskId) -> Result<&mut TaskRecord, ModelError> {
        let record = self.tasks.get_mut(task.slot).ok_or(ModelError::Missing)?;
        if record.id != Some(task) {
            return Err(if record.id.is_some() {
                ModelError::Stale
            } else {
                ModelError::Missing
            });
        }
        Ok(record)
    }

    fn eligible(&self, task: TaskId, cpu: usize) -> bool {
        self.record(task)
            .is_ok_and(|record| record.eligibility & (1 << cpu) != 0)
    }

    fn placement(&self, task: TaskId, requester: usize) -> Result<usize, ModelError> {
        self.validate_cpu(requester)?;
        let record = self.record(task)?;
        let usable = record.eligibility & self.online;
        if usable == 0 {
            return Err(ModelError::IneligibleCpu);
        }
        if let Some(cpu) = record.continuation_cpu {
            return if usable & (1 << cpu) != 0 {
                Ok(cpu)
            } else {
                Err(ModelError::IneligibleCpu)
            };
        }
        let retained = record.last_cpu.filter(|cpu| usable & (1 << cpu) != 0);
        let requested = (usable & (1 << requester) != 0).then_some(requester);
        let admissible = || (0..CPU_COUNT).filter(|cpu| usable & (1 << cpu) != 0);
        // R4B: the frozen order holds while some admissible CPU can still reach
        // idle, because §5 stealing recovers what it does. Once none can, it
        // recovers nothing, so the least-loaded CPU wins and the frozen order
        // only breaks the tie.
        if admissible().any(|cpu| self.runnable_depth(cpu) == 0) {
            return retained
                .or(requested)
                .or_else(|| admissible().next())
                .ok_or(ModelError::IneligibleCpu);
        }
        let shallowest = admissible()
            .min_by_key(|cpu| (self.runnable_depth(*cpu), *cpu))
            .ok_or(ModelError::IneligibleCpu)?;
        let least = self.runnable_depth(shallowest);
        Ok(retained
            .filter(|cpu| self.runnable_depth(*cpu) == least)
            .or(requested.filter(|cpu| self.runnable_depth(*cpu) == least))
            .unwrap_or(shallowest))
    }

    fn add(
        &mut self,
        task: TaskId,
        eligibility: u8,
        requester: usize,
    ) -> Result<usize, ModelError> {
        if task.generation == 0 || task.slot >= TASK_CAPACITY {
            return Err(ModelError::Missing);
        }
        if self.tasks[task.slot].id.is_some() {
            return Err(ModelError::Duplicate);
        }
        self.tasks[task.slot] = TaskRecord {
            id: Some(task),
            eligibility,
            ..TaskRecord::EMPTY
        };
        let cpu = match self.placement(task, requester) {
            Ok(cpu) => cpu,
            Err(error) => {
                self.tasks[task.slot] = TaskRecord::EMPTY;
                return Err(error);
            }
        };
        let generation = match Self::mint(&mut self.next_enqueue) {
            Ok(generation) => generation,
            Err(error) => {
                self.tasks[task.slot] = TaskRecord::EMPTY;
                return Err(error);
            }
        };
        self.queues[cpu].push(task)?;
        self.tasks[task.slot].state = TaskState::Runnable {
            cpu,
            enqueue_generation: generation,
        };
        self.check()?;
        Ok(cpu)
    }

    fn dispatch(&mut self, cpu: usize, now_ns: u64) -> Result<Option<RunToken>, ModelError> {
        self.validate_cpu(cpu)?;
        if self.running[cpu].is_some() {
            return Err(ModelError::CpuBusy);
        }
        let Some(index) = (0..self.queues[cpu].len).find(|index| {
            self.queues[cpu].entries[*index].is_some_and(|task| self.eligible(task, cpu))
        }) else {
            return Ok(None);
        };
        let deadline_ns = now_ns
            .checked_add(DEFAULT_QUANTUM_NS)
            .ok_or(ModelError::Overflow)?;
        let execution_generation = Self::mint(&mut self.next_execution)?;
        let arm_generation = Self::mint(&mut self.next_arm[cpu])?;
        let task = self.queues[cpu].remove(index);
        let token = RunToken {
            task,
            cpu,
            execution_generation,
            arm_generation,
            deadline_ns,
        };
        self.running[cpu] = Some(token);
        let record = self.record_mut(task)?;
        record.state = TaskState::Running { token };
        record.last_cpu = Some(cpu);
        self.quanta_served[task.slot] = self.quanta_served[task.slot]
            .checked_add(1)
            .ok_or(ModelError::Overflow)?;
        self.check()?;
        Ok(Some(token))
    }

    fn expire(&mut self, token: RunToken, now_ns: u64) -> Result<RunToken, ModelError> {
        if self.running.get(token.cpu).copied().flatten() != Some(token) {
            return Err(ModelError::Stale);
        }
        if now_ns < token.deadline_ns {
            return Err(ModelError::TimeRegression);
        }
        if matches!(
            self.record(token.task)?.state,
            TaskState::BlockPreparing { .. }
        ) {
            return Err(ModelError::BlockPreparing);
        }
        if self.record(token.task)?.remote_stop || self.record(token.task)?.rendezvous_pending {
            return Err(ModelError::RemoteStopPending);
        }
        self.quantum_expirations = self.quantum_expirations.checked_add(1).ok_or_else(|| {
            self.overflow_fault = true;
            ModelError::Overflow
        })?;
        if self.queues[token.cpu].len != 0 {
            self.running[token.cpu] = None;
            let enqueue_generation = Self::mint(&mut self.next_enqueue)?;
            self.queues[token.cpu].push(token.task)?;
            self.record_mut(token.task)?.state = TaskState::Runnable {
                cpu: token.cpu,
                enqueue_generation,
            };
            let next = self.dispatch(token.cpu, now_ns)?.expect("peer exists");
            self.check()?;
            Ok(next)
        } else {
            let deadline_ns = now_ns
                .checked_add(DEFAULT_QUANTUM_NS)
                .ok_or(ModelError::Overflow)?;
            let arm_generation = Self::mint(&mut self.next_arm[token.cpu])?;
            let replacement = RunToken {
                arm_generation,
                deadline_ns,
                ..token
            };
            self.running[token.cpu] = Some(replacement);
            self.record_mut(token.task)?.state = TaskState::Running { token: replacement };
            self.quanta_served[token.task.slot] = self.quanta_served[token.task.slot]
                .checked_add(1)
                .ok_or(ModelError::Overflow)?;
            self.check()?;
            Ok(replacement)
        }
    }

    fn prepare_block(&mut self, token: RunToken) -> Result<(), ModelError> {
        if self.running.get(token.cpu).copied().flatten() != Some(token) {
            return Err(ModelError::Stale);
        }
        self.record_mut(token.task)?.state = TaskState::BlockPreparing { token };
        self.check()
    }

    fn cancel_block(&mut self, token: RunToken) -> Result<(), ModelError> {
        if !matches!(self.record(token.task)?.state, TaskState::BlockPreparing { token: current } if current == token)
        {
            return Err(ModelError::Stale);
        }
        self.record_mut(token.task)?.state = TaskState::Running { token };
        self.check()
    }

    fn commit_block(&mut self, token: RunToken) -> Result<WakeToken, ModelError> {
        if self.running.get(token.cpu).copied().flatten() != Some(token)
            || !matches!(self.record(token.task)?.state, TaskState::BlockPreparing { token: current } if current == token)
        {
            return Err(ModelError::Stale);
        }
        let block_generation = Self::mint(&mut self.next_block)?;
        self.running[token.cpu] = None;
        self.record_mut(token.task)?.state = TaskState::Blocked { block_generation };
        self.check()?;
        Ok(WakeToken {
            task: token.task,
            block_generation,
        })
    }

    fn wake(&mut self, token: WakeToken, requester: usize) -> Result<usize, ModelError> {
        match self.record(token.task)?.state {
            TaskState::Blocked { block_generation }
                if block_generation == token.block_generation => {}
            TaskState::Terminal => return Err(ModelError::Terminal),
            TaskState::Blocked { .. } => return Err(ModelError::Stale),
            _ => return Err(ModelError::NotBlocked),
        }
        let cpu = self.placement(token.task, requester)?;
        let enqueue_generation = Self::mint(&mut self.next_enqueue)?;
        self.queues[cpu].push(token.task)?;
        self.record_mut(token.task)?.state = TaskState::Runnable {
            cpu,
            enqueue_generation,
        };
        self.check()?;
        Ok(cpu)
    }

    fn terminate(&mut self, task: TaskId) -> Result<(), ModelError> {
        let state = self.record(task)?.state;
        match state {
            TaskState::Runnable { cpu, .. } => {
                let index = self.queues[cpu].position(task).ok_or(ModelError::Missing)?;
                self.queues[cpu].remove(index);
            }
            TaskState::Running { token } | TaskState::BlockPreparing { token } => {
                self.running[token.cpu] = None;
            }
            TaskState::Blocked { .. } => {}
            TaskState::Terminal => return Err(ModelError::Terminal),
            TaskState::Empty => return Err(ModelError::Missing),
        }
        self.record_mut(task)?.state = TaskState::Terminal;
        self.check()
    }

    fn migrate(&mut self, task: TaskId, target: usize) -> Result<(), ModelError> {
        self.validate_cpu(target)?;
        let record = *self.record(task)?;
        let TaskState::Runnable {
            cpu: source,
            enqueue_generation,
        } = record.state
        else {
            return Err(ModelError::MigrationRejected);
        };
        if !record.migratable() {
            return Err(ModelError::MigrationRejected);
        }
        if record.eligibility & (1 << target) == 0 {
            return Err(ModelError::IneligibleCpu);
        }
        if source == target {
            return Ok(());
        }
        let next_migration = record
            .migration_generation
            .checked_add(1)
            .filter(|value| *value != 0)
            .ok_or(ModelError::Overflow)?;
        let index = self.queues[source]
            .position(task)
            .ok_or(ModelError::Missing)?;
        self.queues[target].push(task)?;
        self.queues[source].remove(index);
        let record = self.record_mut(task)?;
        record.state = TaskState::Runnable {
            cpu: target,
            enqueue_generation,
        };
        record.migration_generation = next_migration;
        self.check()
    }

    fn steal_idle(&mut self, idle: usize) -> Result<Option<TaskId>, ModelError> {
        self.validate_cpu(idle)?;
        if self.running[idle].is_some() || self.queues[idle].len != 0 {
            return Err(ModelError::CpuBusy);
        }
        for offset in 1..CPU_COUNT {
            let victim = (idle + offset) % CPU_COUNT;
            if self.online & (1 << victim) == 0 {
                continue;
            }
            for index in 0..self.queues[victim].len {
                let task = self.queues[victim].entries[index].expect("bounded queue entry");
                if self.eligible(task, idle) && self.record(task)?.migratable() {
                    self.migrate(task, idle)?;
                    return Ok(Some(task));
                }
            }
        }
        Ok(None)
    }

    /// Runnable weight a CPU is carrying: its queued entries plus the entry it
    /// is running. This is the load quantity the frozen placement order in
    /// `DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md` §4 never consults.
    fn runnable_depth(&self, cpu: usize) -> usize {
        self.queues[cpu].len + usize::from(self.running[cpu].is_some())
    }

    /// True when no online CPU can reach the idle path, which is the only
    /// condition under which contract §5 stealing runs.
    fn every_cpu_is_busy(&self) -> bool {
        (0..CPU_COUNT)
            .filter(|cpu| self.online & (1 << cpu) != 0)
            .all(|cpu| self.running[cpu].is_some())
    }

    fn quanta_served(&self, task: TaskId) -> u64 {
        self.quanta_served[task.slot]
    }

    /// One scheduling tick across every online CPU, in the order the frozen
    /// policy describes: a busy CPU expires its quantum, an idle CPU rescans
    /// locally, then performs one bounded victim scan, then dispatches.
    ///
    /// Every CPU is offered the load-recovery point once per tick whether or
    /// not it is busy, and a refusal is counted rather than skipped. The driver
    /// therefore does not itself decide that a busy CPU cannot recover load --
    /// `steal_idle` does, which is what R4C has to change.
    fn advance_one_quantum(&mut self) -> Result<(), ModelError> {
        self.now_ns = self
            .now_ns
            .checked_add(DEFAULT_QUANTUM_NS)
            .ok_or(ModelError::Overflow)?;
        let now_ns = self.now_ns;
        for cpu in 0..CPU_COUNT {
            if self.online & (1 << cpu) == 0 {
                continue;
            }
            // R4C first: quantum expiry is the recovery point a saturated CPU
            // actually reaches, and a pulled entry must be selectable by the
            // rotation that follows.
            self.rebalance_pull(cpu)?;
            if let Some(token) = self.running[cpu] {
                self.expire(token, now_ns)?;
            }
            self.recovery_offers = self
                .recovery_offers
                .checked_add(1)
                .ok_or(ModelError::Overflow)?;
            match self.steal_idle(cpu) {
                Ok(_) => {}
                Err(ModelError::CpuBusy) => {
                    self.recovery_refusals = self
                        .recovery_refusals
                        .checked_add(1)
                        .ok_or(ModelError::Overflow)?;
                }
                Err(error) => return Err(error),
            }
            if self.running[cpu].is_none() {
                self.dispatch(cpu, now_ns)?;
            }
        }
        Ok(())
    }

    fn run_for(&mut self, quanta: u64) -> Result<(), ModelError> {
        for _ in 0..quanta {
            self.advance_one_quantum()?;
        }
        Ok(())
    }

    /// R4C: bounded load recovery for a CPU that is not idle, offered at
    /// quantum expiry. Moves at most one entry, and only from a victim carrying
    /// at least two more, so a move that would merely swap the imbalance is
    /// refused and the mechanism converges.
    fn rebalance_pull(&mut self, target: usize) -> Result<Option<TaskId>, ModelError> {
        self.validate_cpu(target)?;
        // Production reaches this only from quantum expiry, so only from a CPU
        // that is running something. An idle CPU's recovery is §5 stealing,
        // which has no depth threshold to satisfy.
        if self.running[target].is_none() {
            return Ok(None);
        }
        let threshold = self.runnable_depth(target) + 2;
        for offset in 1..CPU_COUNT {
            let victim = (target + offset) % CPU_COUNT;
            if self.online & (1 << victim) == 0 || self.runnable_depth(victim) < threshold {
                continue;
            }
            for index in 0..self.queues[victim].len {
                let task = self.queues[victim].entries[index].expect("bounded queue entry");
                if self.eligible(task, target) && self.record(task)?.migratable() {
                    self.migrate(task, target)?;
                    self.rebalance_pulls = self
                        .rebalance_pulls
                        .checked_add(1)
                        .ok_or(ModelError::Overflow)?;
                    return Ok(Some(task));
                }
            }
        }
        Ok(None)
    }

    fn check(&self) -> Result<(), ModelError> {
        if self.overflow_fault {
            return Err(ModelError::Overflow);
        }
        for cpu in 0..CPU_COUNT {
            if self.running[cpu].is_some() && self.online & (1 << cpu) == 0 {
                return Err(ModelError::OfflineCpu);
            }
            for index in 0..self.queues[cpu].len {
                let task = self.queues[cpu].entries[index].ok_or(ModelError::Missing)?;
                if self.queues[cpu].entries[..index].contains(&Some(task))
                    || self
                        .running
                        .iter()
                        .flatten()
                        .any(|token| token.task == task)
                    || !matches!(self.record(task)?.state, TaskState::Runnable { cpu: owner, .. } if owner == cpu)
                {
                    return Err(ModelError::Duplicate);
                }
            }
        }
        for (cpu, token) in self.running.iter().copied().enumerate() {
            if let Some(token) = token
                && (token.cpu != cpu
                    || self.running[..cpu]
                        .iter()
                        .flatten()
                        .any(|prior| prior.task == token.task)
                    || !matches!(self.record(token.task)?.state, TaskState::Running { token: current } | TaskState::BlockPreparing { token: current } if current == token))
            {
                return Err(ModelError::Duplicate);
            }
        }
        Ok(())
    }
}

fn task(slot: usize, generation: u64) -> TaskId {
    TaskId { slot, generation }
}

#[test]
fn fifo_round_robin_and_deterministic_placement() {
    let mut model = NormalPolicyModel::new(0b1111);
    assert_eq!(model.add(task(0, 1), 0b1111, 2), Ok(2));
    assert_eq!(model.add(task(1, 1), 0b1111, 2), Ok(2));
    let first = model.dispatch(2, 0).unwrap().unwrap();
    assert_eq!(first.task, task(0, 1));
    let second = model.expire(first, DEFAULT_QUANTUM_NS).unwrap();
    assert_eq!(second.task, task(1, 1));
    let third = model.expire(second, DEFAULT_QUANTUM_NS * 2).unwrap();
    assert_eq!(third.task, task(0, 1));

    model.prepare_block(third).unwrap();
    let wake = model.commit_block(third).unwrap();
    assert_eq!(
        model.wake(wake, 3),
        Ok(2),
        "last eligible CPU wins wake placement"
    );
}

#[test]
fn placement_eligibility_offline_and_bounded_cyclic_steal() {
    let mut model = NormalPolicyModel::new(0b1011);
    assert_eq!(
        model.add(task(0, 1), 0b0100, 0),
        Err(ModelError::IneligibleCpu)
    );
    assert_eq!(
        model.add(task(0, 2), 0b1010, 0),
        Ok(1),
        "lowest online eligible CPU wins"
    );
    assert_eq!(model.add(task(1, 1), 0b1011, 1), Ok(1));
    assert_eq!(model.steal_idle(3), Ok(Some(task(0, 2))));
    assert_eq!(model.dispatch(2, 0), Err(ModelError::OfflineCpu));
    assert_eq!(model.check(), Ok(()));
}

#[test]
fn migration_is_transactional_and_rejects_every_frozen_guard() {
    let mut model = NormalPolicyModel::new(0b1111);
    model.add(task(0, 1), 0b1111, 0).unwrap();
    model.tasks[0].execution_pins = 1;
    assert_eq!(
        model.migrate(task(0, 1), 1),
        Err(ModelError::MigrationRejected)
    );
    assert_eq!(model.queues[0].position(task(0, 1)), Some(0));
    model.tasks[0].execution_pins = 0;
    model.tasks[0].scratch_pins = 1;
    assert_eq!(
        model.migrate(task(0, 1), 1),
        Err(ModelError::MigrationRejected)
    );
    assert_eq!(model.queues[0].position(task(0, 1)), Some(0));
    model.tasks[0].scratch_pins = 0;
    model.tasks[0].root_switch = true;
    assert_eq!(
        model.migrate(task(0, 1), 1),
        Err(ModelError::MigrationRejected)
    );
    model.tasks[0].root_switch = false;
    model.tasks[0].continuation_cpu = Some(0);
    assert_eq!(
        model.migrate(task(0, 1), 1),
        Err(ModelError::MigrationRejected)
    );
    model.tasks[0].continuation_cpu = None;
    model.tasks[0].remote_stop = true;
    assert_eq!(
        model.migrate(task(0, 1), 1),
        Err(ModelError::MigrationRejected)
    );
    model.tasks[0].remote_stop = false;
    model.tasks[0].rendezvous_pending = true;
    assert_eq!(
        model.migrate(task(0, 1), 1),
        Err(ModelError::MigrationRejected)
    );
    assert_eq!(model.queues[0].position(task(0, 1)), Some(0));
    model.tasks[0].rendezvous_pending = false;
    model.migrate(task(0, 1), 1).unwrap();
    assert_eq!(model.tasks[0].migration_generation, 1);
    assert_eq!(model.check(), Ok(()));
}

#[test]
fn stale_quantum_wake_and_generation_reuse_cannot_mutate_replacement() {
    let mut model = NormalPolicyModel::new(1);
    model.add(task(0, 1), 1, 0).unwrap();
    let run = model.dispatch(0, 0).unwrap().unwrap();
    model.prepare_block(run).unwrap();
    assert_eq!(
        model.expire(run, DEFAULT_QUANTUM_NS),
        Err(ModelError::BlockPreparing)
    );
    let wake = model.commit_block(run).unwrap();
    model.terminate(task(0, 1)).unwrap();
    assert_eq!(model.wake(wake, 0), Err(ModelError::Terminal));
    assert_eq!(
        model.expire(run, DEFAULT_QUANTUM_NS),
        Err(ModelError::Stale)
    );

    model.tasks[0] = TaskRecord::EMPTY;
    model.add(task(0, 2), 1, 0).unwrap();
    assert_eq!(model.wake(wake, 0), Err(ModelError::Stale));
    assert_eq!(model.migrate(task(0, 1), 0), Err(ModelError::Stale));
    assert!(matches!(model.tasks[0].state, TaskState::Runnable { .. }));
    assert_eq!(model.check(), Ok(()));
}

#[test]
fn remote_stop_and_rendezvous_pending_defer_expiry_without_mutating_the_running_token() {
    let mut model = NormalPolicyModel::new(1);
    model.add(task(0, 1), 1, 0).unwrap();
    let running = model.dispatch(0, 0).unwrap().unwrap();
    model.tasks[0].remote_stop = true;
    assert_eq!(
        model.expire(running, DEFAULT_QUANTUM_NS),
        Err(ModelError::RemoteStopPending)
    );
    assert_eq!(model.running[0], Some(running));
    model.tasks[0].remote_stop = false;
    model.tasks[0].rendezvous_pending = true;
    assert_eq!(
        model.expire(running, DEFAULT_QUANTUM_NS),
        Err(ModelError::RemoteStopPending)
    );
    assert_eq!(model.running[0], Some(running));
    model.tasks[0].rendezvous_pending = false;
    assert_eq!(
        model.expire(running, DEFAULT_QUANTUM_NS).unwrap().task,
        task(0, 1)
    );
    assert_eq!(model.check(), Ok(()));
}

#[test]
fn terminal_wins_block_and_quantum_competition_exactly_once() {
    let mut model = NormalPolicyModel::new(1);
    model.add(task(0, 1), 1, 0).unwrap();
    let run = model.dispatch(0, 0).unwrap().unwrap();
    model.prepare_block(run).unwrap();
    model.terminate(task(0, 1)).unwrap();
    assert_eq!(model.cancel_block(run), Err(ModelError::Stale));
    assert_eq!(model.commit_block(run), Err(ModelError::Stale));
    assert_eq!(
        model.expire(run, DEFAULT_QUANTUM_NS),
        Err(ModelError::Stale)
    );
    assert_eq!(model.terminate(task(0, 1)), Err(ModelError::Terminal));
    assert_eq!(model.check(), Ok(()));
}

#[test]
fn checked_quantum_generation_and_deadline_overflow_leave_ownership_unchanged() {
    let mut model = NormalPolicyModel::new(1);
    model.add(task(0, 1), 1, 0).unwrap();
    assert_eq!(model.dispatch(0, u64::MAX), Err(ModelError::Overflow));
    assert!(model.running[0].is_none());
    assert_eq!(model.queues[0].position(task(0, 1)), Some(0));

    model.next_execution = u64::MAX;
    assert_eq!(model.dispatch(0, 0), Err(ModelError::Overflow));
    assert!(model.running[0].is_none());
    assert_eq!(model.queues[0].position(task(0, 1)), Some(0));
}

#[test]
fn fixed_seed_transition_trace_preserves_unique_running_and_queued_identity() {
    let mut model = NormalPolicyModel::new(0b1111);
    for slot in 0..TASK_CAPACITY {
        model.add(task(slot, 1), 0b1111, slot % CPU_COUNT).unwrap();
        model.check().unwrap();
    }
    let mut runs = [None; CPU_COUNT];
    for (cpu, run) in runs.iter_mut().enumerate() {
        *run = model.dispatch(cpu, 0).unwrap();
        model.check().unwrap();
    }
    for step in 1..=32u64 {
        let cpu = (step as usize) % CPU_COUNT;
        if let Some(run) = runs[cpu] {
            runs[cpu] = Some(model.expire(run, step * DEFAULT_QUANTUM_NS).unwrap());
        }
        model.check().unwrap();
    }
    assert_eq!(model.quantum_expirations, 32);
}

// ---------------------------------------------------------------------------
// R4A/R4B: saturation liveness.
//
// `DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md` §5 claims that "under bounded
// runnable load, repeated local dispatch and bounded idle stealing must ensure
// every continuously eligible normal Thread eventually runs". R4A measured that
// claim against the shape R1 ran in the VM -- four continuously runnable hogs on
// four CPUs, plus further threads created from one launching CPU while every CPU
// is busy -- and found it true and weaker than this reset needs: every thread
// ran, and no thread's share ever converged toward its peers'.
//
// R4B amended §4 so that placement consults load exactly where idle stealing
// cannot recover it. These tests now state the amended policy. Two of them
// remain R4C oracles: an imbalance that placement never caused is still
// permanent, and must be inverted rather than deleted when R4C lands.

/// Share spread a balanced placement leaves: with every thread continuously
/// runnable and equally eligible, each receives the same number of quanta.
const BALANCED_SHARE_SPREAD: u64 = 1;

/// Four hogs launched from CPU 0, then spread one per CPU by the idle path.
/// After this the model is saturated: no CPU can reach idle again.
fn saturated_four_cpu_model() -> NormalPolicyModel {
    let mut model = NormalPolicyModel::new(0b1111);
    for slot in 0..CPU_COUNT {
        assert_eq!(
            model.add(task(slot, 1), 0b1111, 0),
            Ok(0),
            "CPUs can still idle, so the frozen order sends every launch to the launching CPU"
        );
    }
    model.advance_one_quantum().unwrap();
    for cpu in 0..CPU_COUNT {
        assert_eq!(
            model.runnable_depth(cpu),
            1,
            "idle stealing spreads the launch pile while CPUs are still idle"
        );
    }
    assert!(model.every_cpu_is_busy());
    model
}

/// Adds further continuously runnable threads from CPU 0, returning where each
/// was placed.
fn add_from_the_launching_cpu(
    model: &mut NormalPolicyModel,
    slots: core::ops::Range<usize>,
) -> [Option<usize>; TASK_CAPACITY] {
    let mut placed = [None; TASK_CAPACITY];
    for slot in slots {
        placed[slot] = Some(model.add(task(slot, 1), 0b1111, 0).expect("admissible launch"));
    }
    placed
}

/// Quanta served over a window, bounded across the threads that were live for
/// it. A terminated slot serves none and would otherwise floor the minimum.
fn served_bounds(model: &NormalPolicyModel, baseline: [u64; TASK_CAPACITY]) -> (u64, u64) {
    let mut min = u64::MAX;
    let mut max = 0;
    for slot in 0..TASK_CAPACITY {
        if !matches!(
            model.tasks[slot].state,
            TaskState::Runnable { .. } | TaskState::Running { .. }
        ) {
            continue;
        }
        let served = model.quanta_served[slot] - baseline[slot];
        min = min.min(served);
        max = max.max(served);
    }
    assert_ne!(min, u64::MAX, "the window had at least one live thread");
    (min, max)
}

#[test]
fn placement_while_a_cpu_can_still_idle_keeps_the_frozen_order() {
    let mut model = NormalPolicyModel::new(0b1111);
    assert_eq!(model.add(task(0, 1), 0b1111, 0), Ok(0));
    assert_eq!(
        model.add(task(1, 1), 0b1111, 0),
        Ok(0),
        "the requesting CPU still wins while an idle peer can steal the excess"
    );
    assert_eq!(model.runnable_depth(0), 2);
    assert_eq!(model.runnable_depth(1), 0);
    model.advance_one_quantum().unwrap();
    assert_eq!(
        (model.runnable_depth(0), model.runnable_depth(1)),
        (1, 1),
        "and the idle path recovers it, which is why R4B left this case alone"
    );
}

#[test]
fn placement_under_full_load_spreads_across_the_least_loaded_cpus() {
    let mut model = saturated_four_cpu_model();
    let placed = add_from_the_launching_cpu(&mut model, CPU_COUNT..TASK_CAPACITY);
    assert_eq!(
        placed[CPU_COUNT],
        Some(0),
        "the requesting CPU still breaks a tie among equally loaded peers"
    );
    for cpu in 0..CPU_COUNT {
        assert_eq!(
            model.runnable_depth(cpu),
            TASK_CAPACITY / CPU_COUNT,
            "no CPU absorbs work its peers are equally eligible to run"
        );
    }
}

#[test]
fn a_wake_under_full_load_leaves_the_deepest_queue() {
    let mut model = saturated_four_cpu_model();
    for slot in CPU_COUNT..TASK_CAPACITY - 1 {
        assert_eq!(
            model.add(task(slot, 1), 0b0001, 0),
            Ok(0),
            "eligibility, not placement, deepens CPU 0"
        );
    }
    let running = model.running[0].expect("the launching CPU is busy");
    model.prepare_block(running).unwrap();
    let wake = model.commit_block(running).unwrap();
    let placed = model.wake(wake, CPU_COUNT - 1).expect("admissible wake");
    assert_ne!(
        placed, 0,
        "retention yields once the last CPU is the deepest queue"
    );
    assert!(
        model.runnable_depth(placed) < model.runnable_depth(0),
        "a woken thread no longer rejoins the queue it would wait longest in"
    );
}

#[test]
fn quantum_expiry_rotates_a_saturated_queue_in_fifo_age_order() {
    let mut model = saturated_four_cpu_model();
    add_from_the_launching_cpu(&mut model, CPU_COUNT..TASK_CAPACITY);
    let depth = model.runnable_depth(0);
    assert!(depth > 1, "CPU 0 carries a queue to rotate");
    let mut observed = [None; TASK_CAPACITY];
    for step in 0..depth {
        observed[step] = model.running[0].map(|token| token.task);
        model.advance_one_quantum().unwrap();
    }
    for step in 0..depth {
        assert!(observed[step].is_some(), "CPU 0 never idles");
        for earlier in 0..step {
            assert_ne!(
                observed[step], observed[earlier],
                "each local peer runs once before any repeat"
            );
        }
    }
    assert_eq!(
        model.running[0].map(|token| token.task),
        observed[0],
        "the rotation returns to its oldest entry after exactly one pass"
    );
}

#[test]
fn every_thread_gets_an_equal_share_once_placement_can_balance_it() {
    let mut model = saturated_four_cpu_model();
    add_from_the_launching_cpu(&mut model, CPU_COUNT..TASK_CAPACITY);
    let baseline = model.quanta_served;
    model.run_for(100).unwrap();

    let (min, max) = served_bounds(&model, baseline);
    assert_eq!(
        (min, max),
        (50, 50),
        "eight threads across four CPUs each take half a CPU"
    );
    assert_eq!(
        max / min,
        BALANCED_SHARE_SPREAD,
        "R4B closes the share spread R4A measured at 5:1"
    );
}

/// Depths of `3,1,1,1` with no CPU able to reach idle: three threads launched
/// from CPU 0 while its peers are still idle, then one thread each on the peers.
/// R4B's load rule does not apply to those launches, because CPUs 1 to 3 could
/// still idle at the time, so this is an imbalance placement cannot prevent.
///
/// Six threads on four CPUs: `2,2,1,1` is the best reachable shape and `3,1,1,1`
/// is strictly worse. R4B's commit message offered `2,1,1,1` as the R4C case,
/// which was wrong -- five threads on four CPUs cannot do better than one CPU
/// carrying two, so that spread was optimal granularity rather than a defect,
/// and the tests asserting it were not oracles for anything.
fn imbalanced_busy_model() -> NormalPolicyModel {
    let mut model = NormalPolicyModel::new(0b1111);
    for slot in 0..3 {
        assert_eq!(model.add(task(slot, 1), 0b1111, 0), Ok(0));
    }
    model.dispatch(0, 0).unwrap().expect("CPU 0 has work");
    for cpu in 1..CPU_COUNT {
        assert_eq!(model.add(task(2 + cpu, 1), 0b1111, cpu), Ok(cpu));
        model.dispatch(cpu, 0).unwrap().expect("each peer has work");
    }
    assert_eq!(model.runnable_depth(0), 3);
    for cpu in 1..CPU_COUNT {
        assert_eq!(model.runnable_depth(cpu), 1);
    }
    assert!(model.every_cpu_is_busy());
    model
}

#[test]
fn idle_stealing_alone_still_cannot_reach_a_busy_imbalance() {
    let mut model = imbalanced_busy_model();
    for cpu in 0..CPU_COUNT {
        assert_eq!(
            model.steal_idle(cpu),
            Err(ModelError::CpuBusy),
            "§5 load recovery is still gated on an idleness that never arrives"
        );
    }
}

#[test]
fn rebalancing_repairs_an_imbalance_placement_could_not_prevent() {
    let mut model = imbalanced_busy_model();
    model.run_for(1).unwrap();
    let mut depths = [0; CPU_COUNT];
    for (cpu, depth) in depths.iter_mut().enumerate() {
        *depth = model.runnable_depth(cpu);
    }
    depths.sort_unstable();
    assert_eq!(
        depths,
        [1, 1, 2, 2],
        "one bounded pull reaches the best shape six threads admit on four CPUs"
    );
    assert!(model.every_cpu_is_busy());
}

#[test]
fn rebalancing_stops_once_no_move_improves_the_spread() {
    let mut model = imbalanced_busy_model();
    model.run_for(64).unwrap();
    assert_eq!(
        model.rebalance_pulls, 1,
        "a repair, not a rotation: one improving move, then quiet"
    );

    let baseline = model.quanta_served;
    model.run_for(100).unwrap();
    let (min, max) = served_bounds(&model, baseline);
    assert_eq!(
        (min, max),
        (50, 100),
        "the two CPUs carrying a pair give each half, the sole occupants give all"
    );
    assert_eq!(
        max / min,
        2,
        "six threads on four CPUs cannot be equal; R4C reaches the spread they admit, \
         down from the 3:1 the unrepaired imbalance held"
    );
}

#[test]
fn an_already_optimal_spread_is_left_alone() {
    let mut model = saturated_four_cpu_model();
    add_from_the_launching_cpu(&mut model, CPU_COUNT..TASK_CAPACITY - 3);
    model.run_for(64).unwrap();
    assert_eq!(
        model.rebalance_pulls, 0,
        "five threads on four CPUs are already as even as they can be"
    );
}

// ---------------------------------------------------------------------------
// R4D: entrants against no-yield workloads.
//
// The hogs in this model never yield and never block -- the model has no
// voluntary yield at all -- so every switch below is involuntary. What R4D
// validates is that a thread arriving into that workload still runs, and runs
// soon: a newly created one, and one woken by a deadline.
//
// Deadline wakes matter on their own because §11 makes CPU 0 the sole live
// timer and wait-service owner, so every deadline wake is requested from CPU 0.
// Under the unqualified §4 order, a waiter whose last CPU was also CPU 0 --
// which is the common case, since it blocked there -- returned to CPU 0 however
// loaded it was, and so did the next, and the next.

/// Three threads that ran on CPU 0 and blocked there, as a deadline waiter
/// does, with four no-yield hogs then saturating every CPU.
fn deadline_waiters_then_saturation() -> (NormalPolicyModel, [WakeToken; 3]) {
    let mut model = NormalPolicyModel::new(0b1111);
    for slot in 0..3 {
        assert_eq!(model.add(task(slot, 1), 0b1111, 0), Ok(0));
    }
    let mut wakes = [None; 3];
    for wake in wakes.iter_mut() {
        let running = model.dispatch(0, 0).unwrap().expect("a waiter to run");
        model.prepare_block(running).unwrap();
        *wake = Some(model.commit_block(running).unwrap());
    }
    for slot in 0..3 {
        assert_eq!(
            model.tasks[slot].last_cpu,
            Some(0),
            "a waiter blocks on the CPU it ran on, which is the timer owner"
        );
    }

    for slot in 3..3 + CPU_COUNT {
        model.add(task(slot, 1), 0b1111, 0).unwrap();
    }
    model.advance_one_quantum().unwrap();
    assert!(model.every_cpu_is_busy());
    for cpu in 0..CPU_COUNT {
        assert_eq!(model.runnable_depth(cpu), 1, "one hog per CPU");
    }
    (model, wakes.map(|wake| wake.expect("blocked waiter")))
}

#[test]
fn a_thread_created_under_saturation_runs_at_the_first_expiry_of_its_cpu() {
    let mut model = saturated_four_cpu_model();
    // One thread per CPU, all created from CPU 0, the launching CPU.
    for cpu in 0..CPU_COUNT {
        assert_eq!(
            model.add(task(CPU_COUNT + cpu, 1), 0b1111, 0),
            Ok(cpu),
            "no entrant queues behind another while a peer carries less"
        );
    }
    model.advance_one_quantum().unwrap();
    for cpu in 0..CPU_COUNT {
        assert_eq!(
            model.quanta_served(task(CPU_COUNT + cpu, 1)),
            1,
            "no hog yielded or blocked, and every entrant still ran"
        );
    }
    for slot in 0..CPU_COUNT {
        assert!(
            matches!(
                model.tasks[slot].state,
                TaskState::Runnable { .. } | TaskState::Running { .. }
            ),
            "every hog is still continuously runnable"
        );
    }
}

#[test]
fn deadline_wakes_all_requested_from_cpu0_do_not_pile_onto_it() {
    let (mut model, wakes) = deadline_waiters_then_saturation();
    let mut placed = [0; 3];
    for (slot, wake) in wakes.into_iter().enumerate() {
        placed[slot] = model.wake(wake, 0).expect("admissible deadline wake");
    }
    assert_eq!(
        placed,
        [0, 1, 2],
        "the first waiter is retained on the timer owner; the rest are not"
    );
    assert_eq!(model.runnable_depth(0), 2);
}

#[test]
fn every_deadline_waiter_runs_at_the_first_expiry_after_its_wake() {
    let (mut model, wakes) = deadline_waiters_then_saturation();
    for wake in wakes {
        model.wake(wake, 0).expect("admissible deadline wake");
    }
    let baseline = model.quanta_served;
    model.advance_one_quantum().unwrap();
    for slot in 0..3 {
        assert_eq!(
            model.quanta_served(task(slot, 1)) - baseline[slot],
            1,
            "waiter {slot} ran one quantum after its wake, against no-yield hogs"
        );
    }
}
