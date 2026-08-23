//! Deterministic H3-C host stress model for ownership-sensitive concurrency.
//!
//! The production scheduler remains crate-private, so this integration test
//! keeps its own deliberately small reference model.  It drives the same
//! ownership boundaries under a reproducible interleaving: per-CPU execution,
//! handle permits, blocking/wake keys, timer delivery, close, and terminal
//! object reuse.  Every operation validates the model immediately; failures
//! retain the seed and operation index needed to replay them.

use std::fmt::{self, Display};
use std::path::PathBuf;

const CPUS: usize = 4;
const THREAD_SLOTS: usize = 8;
const HANDLE_SLOTS: usize = 8;
const MESSAGE_CAPACITY: usize = 4;
const OPERATIONS_PER_SEED: usize = 1_024;
const SEEDS: [u64; 4] = [
    0x4d32_7a91_c0de_0001,
    0x4d32_7a91_c0de_0002,
    0x4d32_7a91_c0de_0003,
    0x4d32_7a91_c0de_0004,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadId {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutionClaim {
    thread: ThreadId,
    cpu: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WakeKey {
    thread: ThreadId,
    cpu: usize,
    execution_generation: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandlePermit {
    slot: usize,
    generation: u64,
    thread: ThreadId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadState {
    Runnable,
    Running(ExecutionClaim),
    Blocked(WakeKey),
    Retired,
}

#[derive(Clone, Copy, Debug)]
struct ThreadSlot {
    generation: u64,
    state: ThreadState,
}

#[derive(Clone, Copy, Debug)]
struct HandleSlot {
    generation: u64,
    permit: Option<HandlePermit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResultKind {
    Applied,
    StaleRejected,
    Noop,
}

impl Display for ResultKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied => formatter.write_str("applied"),
            Self::StaleRejected => formatter.write_str("stale-rejected"),
            Self::Noop => formatter.write_str("noop"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Schedule { cpu: usize },
    Yield { cpu: usize },
    Wait { cpu: usize },
    Wake { history: usize },
    TimerFire { history: usize },
    Send { handle: usize },
    Receive { handle: usize },
    Close { handle: usize },
    Reopen { thread_slot: usize },
    Terminate { thread_slot: usize },
    Recreate { thread_slot: usize },
}

impl Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schedule { cpu } => write!(formatter, "schedule(cpu={cpu})"),
            Self::Yield { cpu } => write!(formatter, "yield(cpu={cpu})"),
            Self::Wait { cpu } => write!(formatter, "wait(cpu={cpu})"),
            Self::Wake { history } => write!(formatter, "wake(history={history})"),
            Self::TimerFire { history } => write!(formatter, "timer-fire(history={history})"),
            Self::Send { handle } => write!(formatter, "send(handle={handle})"),
            Self::Receive { handle } => write!(formatter, "receive(handle={handle})"),
            Self::Close { handle } => write!(formatter, "close(handle={handle})"),
            Self::Reopen { thread_slot } => write!(formatter, "reopen(thread={thread_slot})"),
            Self::Terminate { thread_slot } => write!(formatter, "terminate(thread={thread_slot})"),
            Self::Recreate { thread_slot } => write!(formatter, "recreate(thread={thread_slot})"),
        }
    }
}

struct Model {
    threads: [ThreadSlot; THREAD_SLOTS],
    running: [Option<ExecutionClaim>; CPUS],
    handles: [HandleSlot; HANDLE_SLOTS],
    next_execution_generation: u64,
    next_wake_generation: u64,
    messages: usize,
    wake_history: Vec<WakeKey>,
}

impl Model {
    fn new() -> Self {
        let threads = std::array::from_fn(|_| ThreadSlot {
            generation: 1,
            state: ThreadState::Runnable,
        });
        let handles = std::array::from_fn(|slot| HandleSlot {
            generation: (slot as u64) + 1,
            permit: None,
        });
        let mut model = Self {
            threads,
            running: [None; CPUS],
            handles,
            next_execution_generation: 1,
            next_wake_generation: 1,
            messages: 0,
            wake_history: Vec::new(),
        };
        for slot in 0..THREAD_SLOTS.min(HANDLE_SLOTS) {
            assert_eq!(model.reopen(slot), ResultKind::Applied);
        }
        model
    }

    fn thread_id(&self, slot: usize) -> ThreadId {
        ThreadId {
            slot,
            generation: self.threads[slot].generation,
        }
    }

    fn thread_slot(&self, id: ThreadId) -> Option<usize> {
        self.threads
            .get(id.slot)
            .filter(|entry| entry.generation == id.generation)
            .map(|_| id.slot)
    }

    fn mint_execution_generation(&mut self) -> u64 {
        let value = self.next_execution_generation;
        self.next_execution_generation = self
            .next_execution_generation
            .checked_add(1)
            .expect("H3-C reference execution generation must not wrap");
        value
    }

    fn mint_wake_generation(&mut self) -> u64 {
        let value = self.next_wake_generation;
        self.next_wake_generation = self
            .next_wake_generation
            .checked_add(1)
            .expect("H3-C reference wake generation must not wrap");
        value
    }

    fn schedule(&mut self, cpu: usize) -> ResultKind {
        if self.running[cpu].is_some() {
            return ResultKind::Noop;
        }
        let Some(slot) = self
            .threads
            .iter()
            .position(|entry| entry.state == ThreadState::Runnable)
        else {
            return ResultKind::Noop;
        };
        let claim = ExecutionClaim {
            thread: self.thread_id(slot),
            cpu,
            generation: self.mint_execution_generation(),
        };
        self.threads[slot].state = ThreadState::Running(claim);
        self.running[cpu] = Some(claim);
        ResultKind::Applied
    }

    fn yield_current(&mut self, cpu: usize) -> ResultKind {
        let Some(claim) = self.running[cpu] else {
            return ResultKind::Noop;
        };
        let Some(slot) = self.thread_slot(claim.thread) else {
            return ResultKind::StaleRejected;
        };
        if self.threads[slot].state != ThreadState::Running(claim) {
            return ResultKind::StaleRejected;
        }
        self.threads[slot].state = ThreadState::Runnable;
        self.running[cpu] = None;
        ResultKind::Applied
    }

    fn begin_wait(&mut self, cpu: usize) -> ResultKind {
        let Some(claim) = self.running[cpu] else {
            return ResultKind::Noop;
        };
        let Some(slot) = self.thread_slot(claim.thread) else {
            return ResultKind::StaleRejected;
        };
        if self.threads[slot].state != ThreadState::Running(claim) {
            return ResultKind::StaleRejected;
        }
        let key = WakeKey {
            thread: claim.thread,
            cpu,
            execution_generation: claim.generation,
            generation: self.mint_wake_generation(),
        };
        self.threads[slot].state = ThreadState::Blocked(key);
        self.running[cpu] = None;
        self.wake_history.push(key);
        ResultKind::Applied
    }

    fn wake(&mut self, key: WakeKey) -> ResultKind {
        let Some(slot) = self.thread_slot(key.thread) else {
            return ResultKind::StaleRejected;
        };
        if self.threads[slot].state != ThreadState::Blocked(key) {
            return ResultKind::StaleRejected;
        }
        self.threads[slot].state = ThreadState::Runnable;
        ResultKind::Applied
    }

    fn permit_is_live(&self, permit: HandlePermit) -> bool {
        self.handles.get(permit.slot).is_some_and(|slot| {
            slot.generation == permit.generation
                && slot.permit == Some(permit)
                && self.thread_slot(permit.thread).is_some_and(|thread_slot| {
                    self.threads[thread_slot].state != ThreadState::Retired
                })
        })
    }

    fn use_handle(&self, handle: usize) -> Option<HandlePermit> {
        self.handles
            .get(handle)
            .and_then(|slot| slot.permit)
            .filter(|permit| self.permit_is_live(*permit))
    }

    fn send(&mut self, handle: usize) -> ResultKind {
        if self.messages == MESSAGE_CAPACITY {
            return ResultKind::Noop;
        }
        if self.use_handle(handle).is_none() {
            return ResultKind::StaleRejected;
        }
        self.messages += 1;
        ResultKind::Applied
    }

    fn receive(&mut self, handle: usize) -> ResultKind {
        if self.use_handle(handle).is_none() {
            return ResultKind::StaleRejected;
        }
        if self.messages == 0 {
            return ResultKind::Noop;
        }
        self.messages -= 1;
        ResultKind::Applied
    }

    fn close(&mut self, handle: usize) -> ResultKind {
        let Some(slot) = self.handles.get_mut(handle) else {
            return ResultKind::StaleRejected;
        };
        let Some(permit) = slot.permit else {
            return ResultKind::StaleRejected;
        };
        if slot.generation != permit.generation {
            return ResultKind::StaleRejected;
        }
        slot.permit = None;
        ResultKind::Applied
    }

    fn reopen(&mut self, thread_slot: usize) -> ResultKind {
        if self.threads[thread_slot].state == ThreadState::Retired {
            return ResultKind::StaleRejected;
        }
        let Some(handle_slot) = self.handles.iter().position(|slot| slot.permit.is_none()) else {
            return ResultKind::Noop;
        };
        let thread = self.thread_id(thread_slot);
        let slot = &mut self.handles[handle_slot];
        slot.generation = slot
            .generation
            .checked_add(1)
            .expect("H3-C reference permit generation must not wrap");
        let permit = HandlePermit {
            slot: handle_slot,
            generation: slot.generation,
            thread,
        };
        slot.permit = Some(permit);
        ResultKind::Applied
    }

    fn terminate(&mut self, thread_slot: usize) -> ResultKind {
        if self.threads[thread_slot].state == ThreadState::Retired {
            return ResultKind::StaleRejected;
        }
        let id = self.thread_id(thread_slot);
        if let ThreadState::Running(claim) = self.threads[thread_slot].state {
            self.running[claim.cpu] = None;
        }
        self.threads[thread_slot].state = ThreadState::Retired;
        for slot in &mut self.handles {
            if slot.permit.is_some_and(|permit| permit.thread == id) {
                slot.permit = None;
            }
        }
        ResultKind::Applied
    }

    fn recreate(&mut self, thread_slot: usize) -> ResultKind {
        if self.threads[thread_slot].state != ThreadState::Retired {
            return ResultKind::Noop;
        }
        self.threads[thread_slot].generation = self.threads[thread_slot]
            .generation
            .checked_add(1)
            .expect("H3-C reference object generation must not wrap");
        self.threads[thread_slot].state = ThreadState::Runnable;
        ResultKind::Applied
    }

    fn apply(&mut self, operation: Operation) -> ResultKind {
        match operation {
            Operation::Schedule { cpu } => self.schedule(cpu),
            Operation::Yield { cpu } => self.yield_current(cpu),
            Operation::Wait { cpu } => self.begin_wait(cpu),
            Operation::Wake { history } | Operation::TimerFire { history } => self
                .wake_history
                .get(history % self.wake_history.len().max(1))
                .copied()
                .map_or(ResultKind::Noop, |key| self.wake(key)),
            Operation::Send { handle } => self.send(handle),
            Operation::Receive { handle } => self.receive(handle),
            Operation::Close { handle } => self.close(handle),
            Operation::Reopen { thread_slot } => self.reopen(thread_slot),
            Operation::Terminate { thread_slot } => self.terminate(thread_slot),
            Operation::Recreate { thread_slot } => self.recreate(thread_slot),
        }
    }

    fn assert_invariants(&self, seed: u64, operation_index: usize, operation: Operation) {
        assert!(
            self.messages <= MESSAGE_CAPACITY,
            "seed={seed:#018x} operation={operation_index} {operation}: message bound exceeded"
        );

        for (cpu, claim) in self.running.iter().enumerate() {
            if let Some(claim) = claim {
                assert_eq!(
                    claim.cpu, cpu,
                    "seed={seed:#018x} operation={operation_index} {operation}: CPU carrier mismatch"
                );
                let slot = self
                    .thread_slot(claim.thread)
                    .unwrap_or_else(|| panic!(
                        "seed={seed:#018x} operation={operation_index} {operation}: running stale thread id"
                    ));
                assert_eq!(
                    self.threads[slot].state,
                    ThreadState::Running(*claim),
                    "seed={seed:#018x} operation={operation_index} {operation}: running claim not owned by thread"
                );
            }
        }

        for (slot, thread) in self.threads.iter().enumerate() {
            match thread.state {
                ThreadState::Running(claim) => {
                    assert_eq!(
                        self.running[claim.cpu],
                        Some(claim),
                        "seed={seed:#018x} operation={operation_index} {operation}: thread {slot} has no matching CPU owner"
                    );
                }
                ThreadState::Blocked(key) => {
                    assert_ne!(
                        key.generation, 0,
                        "seed={seed:#018x} operation={operation_index} {operation}: blocked key generation is zero"
                    );
                    assert_ne!(
                        key.execution_generation, 0,
                        "seed={seed:#018x} operation={operation_index} {operation}: blocked execution generation is zero"
                    );
                    assert!(
                        !self
                            .running
                            .iter()
                            .flatten()
                            .any(|claim| claim.thread == key.thread),
                        "seed={seed:#018x} operation={operation_index} {operation}: blocked thread {slot} is still running"
                    );
                }
                ThreadState::Runnable | ThreadState::Retired => {}
            }
        }

        for (index, slot) in self.handles.iter().enumerate() {
            assert_ne!(
                slot.generation, 0,
                "seed={seed:#018x} operation={operation_index} {operation}: handle {index} generation is zero"
            );
            if let Some(permit) = slot.permit {
                assert_eq!(
                    permit.slot, index,
                    "seed={seed:#018x} operation={operation_index} {operation}: permit carries wrong slot"
                );
                assert_eq!(
                    permit.generation, slot.generation,
                    "seed={seed:#018x} operation={operation_index} {operation}: permit carries stale generation"
                );
                let thread_slot = self.thread_slot(permit.thread).unwrap_or_else(|| panic!(
                    "seed={seed:#018x} operation={operation_index} {operation}: permit retains stale object identity"
                ));
                assert_ne!(
                    self.threads[thread_slot].state,
                    ThreadState::Retired,
                    "seed={seed:#018x} operation={operation_index} {operation}: permit retains terminated object"
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ScheduleRng(u64);

impl ScheduleRng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bounded(&mut self, upper: usize) -> usize {
        (self.next() as usize) % upper
    }

    fn operation(&mut self) -> Operation {
        match self.bounded(11) {
            0 => Operation::Schedule {
                cpu: self.bounded(CPUS),
            },
            1 => Operation::Yield {
                cpu: self.bounded(CPUS),
            },
            2 => Operation::Wait {
                cpu: self.bounded(CPUS),
            },
            3 => Operation::Wake {
                history: self.bounded(THREAD_SLOTS * 4),
            },
            4 => Operation::TimerFire {
                history: self.bounded(THREAD_SLOTS * 4),
            },
            5 => Operation::Send {
                handle: self.bounded(HANDLE_SLOTS),
            },
            6 => Operation::Receive {
                handle: self.bounded(HANDLE_SLOTS),
            },
            7 => Operation::Close {
                handle: self.bounded(HANDLE_SLOTS),
            },
            8 => Operation::Reopen {
                thread_slot: self.bounded(THREAD_SLOTS),
            },
            9 => Operation::Terminate {
                thread_slot: self.bounded(THREAD_SLOTS),
            },
            _ => Operation::Recreate {
                thread_slot: self.bounded(THREAD_SLOTS),
            },
        }
    }
}

#[test]
fn h3c_deterministic_multicpu_lifetime_stress_rejects_stale_generations() {
    let mut total_stale_rejections = 0;
    let mut total_waits = 0;
    let mut total_terminations = 0;

    for seed in SEEDS {
        let mut model = Model::new();
        let mut rng = ScheduleRng(seed);

        // Start four distinct logical CPU owners so later operations include
        // contested schedule, wait, timer and terminal paths from the outset.
        for cpu in 0..CPUS {
            let operation = Operation::Schedule { cpu };
            assert_eq!(model.apply(operation), ResultKind::Applied);
            model.assert_invariants(seed, cpu, operation);
        }

        for operation_index in 0..OPERATIONS_PER_SEED {
            let operation = rng.operation();
            let result = model.apply(operation);
            if result == ResultKind::StaleRejected {
                total_stale_rejections += 1;
            }
            if matches!(operation, Operation::Wait { .. }) && result == ResultKind::Applied {
                total_waits += 1;
            }
            if matches!(operation, Operation::Terminate { .. }) && result == ResultKind::Applied {
                total_terminations += 1;
            }
            model.assert_invariants(seed, operation_index, operation);
        }
    }

    assert!(
        total_stale_rejections > 100,
        "the schedule did not exercise enough stale close/wake/handle paths: {total_stale_rejections}"
    );
    assert!(
        total_waits > 10,
        "the schedule did not exercise waits: {total_waits}"
    );
    assert!(
        total_terminations > 10,
        "the schedule did not exercise terminal cleanup: {total_terminations}"
    );
}

#[test]
fn h3c_scheduler_source_keeps_per_cpu_and_generation_contracts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/task/scheduler.rs"))
        .expect("read scheduler source for H3-C contract test");

    for required in [
        "H2_SCHEDULER_CPU_CAPACITY: usize = 4",
        "running: [Option<RunningClaim>; H2_SCHEDULER_CPU_CAPACITY]",
        "pending_block: [Option<BlockWakeKey>; H2_SCHEDULER_CPU_CAPACITY]",
        "suspended: [Option<SuspendedContinuation>; H2_SCHEDULER_CPU_CAPACITY]",
        "execution_generation: u64",
        "fn wake(&self, key: BlockWakeKey)",
        "SchedulerError::StaleBlockToken",
        "SchedulerError::StaleExecutionClaim",
        "fn retire_on(",
        "fn complete_switch_on(",
    ] {
        assert!(
            source.contains(required),
            "H3-C scheduler contract omitted {required}"
        );
    }
    assert!(source.contains("entry.thread == key.thread"));
    assert!(source.contains("entry.token == key.token"));
    assert!(source.contains("entry.block_cpu == Some(key.cpu)"));
    assert!(!source.contains("static mut"));
}
