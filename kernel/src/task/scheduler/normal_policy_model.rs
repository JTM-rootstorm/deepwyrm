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
    root_switch: bool,
    remote_stop: bool,
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
        root_switch: false,
        remote_stop: false,
        migration_generation: 0,
    };

    fn migratable(self) -> bool {
        matches!(self.state, TaskState::Runnable { .. })
            && self.continuation_cpu.is_none()
            && self.execution_pins == 0
            && !self.root_switch
            && !self.remote_stop
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
        if let Some(cpu) = record.last_cpu.filter(|cpu| usable & (1 << cpu) != 0) {
            return Ok(cpu);
        }
        if usable & (1 << requester) != 0 {
            return Ok(requester);
        }
        (0..CPU_COUNT)
            .find(|cpu| usable & (1 << cpu) != 0)
            .ok_or(ModelError::IneligibleCpu)
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
            self.check()?;
            Ok(replacement)
        }
    }

    fn prepare_block(&mut self, token: RunToken) -> Result<(), ModelError> {
        if self.running.get(token.cpu).copied().flatten() != Some(token) {
            return Err(ModelError::Stale);
        }
        self.record_mut(token.task)?.state = TaskState::BlockPreparing { token };
        Ok(())
    }

    fn cancel_block(&mut self, token: RunToken) -> Result<(), ModelError> {
        if !matches!(self.record(token.task)?.state, TaskState::BlockPreparing { token: current } if current == token)
        {
            return Err(ModelError::Stale);
        }
        self.record_mut(token.task)?.state = TaskState::Running { token };
        Ok(())
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
    assert!(matches!(model.tasks[0].state, TaskState::Runnable { .. }));
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
