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
    let cpu_source = std::fs::read_to_string(root.join("src/cpu.rs"))
        .expect("read canonical CPU identity source for H3-C contract test");

    assert!(cpu_source.contains("CPU_CAPACITY: usize = 4"));

    for required in [
        "H2_SCHEDULER_CPU_CAPACITY: usize = crate::cpu::CPU_CAPACITY",
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

// I2 extends the H3 model with the ownership edges that cannot be exercised
// by the existing scheduler-only reference state.  This remains a host model:
// the corresponding live evidence must come from the canonical four-vCPU
// guest selector after I1.
const I2_CPUS: usize = 4;
const I2_SPACES: usize = 3;
const I2_OBJECTS: usize = 3;
const I2_PROCESSES: usize = 8;
const I2_OPERATIONS_PER_SEED: usize = 768;
const I2_SEEDS: [u64; 4] = [
    0x4932_0000_cafe_0001,
    0x4932_0000_cafe_0002,
    0x4932_0000_cafe_0003,
    0x4932_0000_cafe_0004,
];
const PM_TIMER_MODULUS: u32 = 1 << 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2Result {
    Applied,
    Rejected,
    Noop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2MappingMutation {
    Map { object: usize, protection: u8 },
    Protect { protection: u8 },
    Unmap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct I2PendingMutation {
    generation: u64,
    mutation: I2MappingMutation,
    required_acks: u8,
    received_acks: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct I2Space {
    generation: u64,
    owner: Option<usize>,
    active: bool,
    mapping: Option<(usize, u8)>,
    mutation_generation: u64,
    pending: Option<I2PendingMutation>,
    resident: [bool; I2_CPUS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2ObjectState {
    Live,
    Finalized,
    Reclaimed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct I2Object {
    generation: u64,
    state: I2ObjectState,
    mappings: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct I2Process {
    generation: u64,
    parent: Option<usize>,
    active: bool,
    space: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct I2Cpu {
    space: Option<(usize, u64)>,
    idle: bool,
    wake_generation: u64,
    timer_generation: u64,
    timer_deadline: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
enum I2Operation {
    Enter {
        cpu: usize,
        space: usize,
    },
    Leave {
        cpu: usize,
    },
    Map {
        space: usize,
        object: usize,
        initiator: usize,
    },
    Protect {
        space: usize,
        protection: u8,
        initiator: usize,
    },
    Unmap {
        space: usize,
        initiator: usize,
    },
    Ack {
        space: usize,
        cpu: usize,
        generation: u64,
    },
    FinalizeObject {
        object: usize,
    },
    ReclaimObject {
        object: usize,
    },
    TearDown {
        space: usize,
    },
    CreateChild {
        parent: usize,
        slot: usize,
    },
    TrySiblingAuthority {
        caller: usize,
        target: usize,
    },
    ExitProcess {
        process: usize,
    },
    Idle {
        cpu: usize,
    },
    Wake {
        cpu: usize,
        generation: u64,
    },
    ArmTimer {
        cpu: usize,
        delta: u64,
    },
    FireTimer {
        cpu: usize,
        generation: u64,
    },
    Advance {
        delta: u64,
    },
}

impl Display for I2Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enter { cpu, space } => write!(formatter, "enter(cpu={cpu},space={space})"),
            Self::Leave { cpu } => write!(formatter, "leave(cpu={cpu})"),
            Self::Map {
                space,
                object,
                initiator,
            } => write!(
                formatter,
                "map(space={space},object={object},initiator={initiator})"
            ),
            Self::Protect {
                space,
                protection,
                initiator,
            } => {
                write!(
                    formatter,
                    "protect(space={space},protection={protection},initiator={initiator})"
                )
            }
            Self::Unmap { space, initiator } => {
                write!(formatter, "unmap(space={space},initiator={initiator})")
            }
            Self::Ack {
                space,
                cpu,
                generation,
            } => write!(
                formatter,
                "ack(space={space},cpu={cpu},generation={generation})"
            ),
            Self::FinalizeObject { object } => {
                write!(formatter, "finalize-object(object={object})")
            }
            Self::ReclaimObject { object } => write!(formatter, "reclaim-object(object={object})"),
            Self::TearDown { space } => write!(formatter, "teardown(space={space})"),
            Self::CreateChild { parent, slot } => {
                write!(formatter, "create-child(parent={parent},slot={slot})")
            }
            Self::TrySiblingAuthority { caller, target } => {
                write!(formatter, "try-authority(caller={caller},target={target})")
            }
            Self::ExitProcess { process } => write!(formatter, "exit-process(process={process})"),
            Self::Idle { cpu } => write!(formatter, "idle(cpu={cpu})"),
            Self::Wake { cpu, generation } => {
                write!(formatter, "wake(cpu={cpu},generation={generation})")
            }
            Self::ArmTimer { cpu, delta } => {
                write!(formatter, "arm-timer(cpu={cpu},delta={delta})")
            }
            Self::FireTimer { cpu, generation } => {
                write!(formatter, "fire-timer(cpu={cpu},generation={generation})")
            }
            Self::Advance { delta } => write!(formatter, "advance(delta={delta})"),
        }
    }
}

#[derive(Clone, Copy)]
struct I2Context {
    seed: u64,
    operation: usize,
    name: I2Operation,
}

impl I2Context {
    fn failure(self, stage: &str, message: &str) -> String {
        format!(
            "seed={:#018x} operation={} stage={} {} ({})",
            self.seed, self.operation, stage, self.name, message
        )
    }
}

struct I2Model {
    spaces: [I2Space; I2_SPACES],
    objects: [I2Object; I2_OBJECTS],
    processes: [I2Process; I2_PROCESSES],
    cpus: [I2Cpu; I2_CPUS],
    now: u64,
    pm_counter: u32,
    pm_extended: u64,
    pm_last_sample: u32,
    pm_wraps: u64,
}

impl I2Model {
    fn new() -> Self {
        let spaces = std::array::from_fn(|index| I2Space {
            generation: (index as u64) + 1,
            owner: (index == 0).then_some(0),
            active: true,
            mapping: None,
            mutation_generation: 1,
            pending: None,
            resident: [false; I2_CPUS],
        });
        let objects = std::array::from_fn(|index| I2Object {
            generation: (index as u64) + 1,
            state: I2ObjectState::Live,
            mappings: 0,
        });
        let mut processes = std::array::from_fn(|index| I2Process {
            generation: (index as u64) + 1,
            parent: None,
            active: false,
            space: index % I2_SPACES,
        });
        processes[0].active = true;
        Self {
            spaces,
            objects,
            processes,
            cpus: [I2Cpu {
                space: None,
                idle: true,
                wake_generation: 1,
                timer_generation: 1,
                timer_deadline: None,
            }; I2_CPUS],
            now: 0,
            pm_counter: PM_TIMER_MODULUS - 4,
            pm_extended: u64::from(PM_TIMER_MODULUS - 4),
            pm_last_sample: PM_TIMER_MODULUS - 4,
            pm_wraps: 0,
        }
    }

    fn mutation_mask(&self, space: usize, initiator: usize) -> u8 {
        self.spaces[space]
            .resident
            .iter()
            .enumerate()
            .filter_map(|(cpu, resident)| (*resident && cpu != initiator).then_some(1_u8 << cpu))
            .fold(0, |mask, bit| mask | bit)
    }

    fn begin_mutation(
        &mut self,
        space: usize,
        mutation: I2MappingMutation,
        initiator: usize,
    ) -> I2Result {
        if !self.spaces[space].active
            || self.spaces[space].owner.is_none()
            || self.spaces[space].pending.is_some()
        {
            return I2Result::Rejected;
        }
        if matches!(mutation, I2MappingMutation::Map { .. }) && self.spaces[space].mapping.is_some()
        {
            return I2Result::Rejected;
        }
        if let I2MappingMutation::Map { object, .. } = mutation
            && self.objects[object].state != I2ObjectState::Live
        {
            return I2Result::Rejected;
        }
        if matches!(
            mutation,
            I2MappingMutation::Protect { .. } | I2MappingMutation::Unmap
        ) && self.spaces[space].mapping.is_none()
        {
            return I2Result::Rejected;
        }
        let required_acks = self.mutation_mask(space, initiator);
        self.spaces[space].pending = Some(I2PendingMutation {
            generation: self.spaces[space].mutation_generation,
            mutation,
            required_acks,
            received_acks: 0,
        });
        if required_acks == 0 {
            self.commit_mutation(space);
        }
        I2Result::Applied
    }

    fn commit_mutation(&mut self, space: usize) {
        let pending = self.spaces[space]
            .pending
            .take()
            .expect("I2 mutation commit requires a pending mutation");
        match pending.mutation {
            I2MappingMutation::Map { object, protection } => {
                self.spaces[space].mapping = Some((object, protection));
                self.objects[object].mappings = self.objects[object]
                    .mappings
                    .checked_add(1)
                    .expect("I2 object mapping count must not wrap");
            }
            I2MappingMutation::Protect { protection } => {
                let mapping = self.spaces[space]
                    .mapping
                    .as_mut()
                    .expect("I2 protect commit requires a mapping");
                mapping.1 = protection;
            }
            I2MappingMutation::Unmap => {
                let (object, _) = self.spaces[space]
                    .mapping
                    .take()
                    .expect("I2 unmap commit requires a mapping");
                self.objects[object].mappings = self.objects[object]
                    .mappings
                    .checked_sub(1)
                    .expect("I2 object mapping count must not underflow");
            }
        }
        self.spaces[space].mutation_generation = self.spaces[space]
            .mutation_generation
            .checked_add(1)
            .expect("I2 mapping generation must not wrap");
    }

    fn acknowledge(&mut self, space: usize, cpu: usize, generation: u64) -> I2Result {
        let Some(mut pending) = self.spaces[space].pending else {
            return I2Result::Rejected;
        };
        if pending.generation != generation {
            return I2Result::Rejected;
        }
        if !self.spaces[space].resident[cpu] {
            return I2Result::Rejected;
        }
        let bit = 1_u8 << cpu;
        if pending.required_acks & bit == 0 || pending.received_acks & bit != 0 {
            return I2Result::Rejected;
        }
        pending.received_acks |= bit;
        let complete = pending.received_acks == pending.required_acks;
        self.spaces[space].pending = Some(pending);
        if complete {
            self.commit_mutation(space);
        }
        I2Result::Applied
    }

    fn enter(&mut self, cpu: usize, space: usize) -> I2Result {
        if !self.spaces[space].active
            || self.spaces[space].owner.is_none()
            || self.spaces[space].pending.is_some()
        {
            return I2Result::Rejected;
        }
        if self.cpus[cpu].space.is_some() {
            return I2Result::Noop;
        }
        self.cpus[cpu].space = Some((space, self.spaces[space].generation));
        self.cpus[cpu].idle = false;
        self.spaces[space].resident[cpu] = true;
        I2Result::Applied
    }

    fn leave(&mut self, cpu: usize) -> I2Result {
        let Some((space, generation)) = self.cpus[cpu].space.take() else {
            return I2Result::Noop;
        };
        if !self.spaces[space].active || self.spaces[space].generation != generation {
            return I2Result::Rejected;
        }
        if self.spaces[space].pending.is_some_and(|pending| {
            pending.required_acks & (1_u8 << cpu) != 0 && pending.received_acks & (1_u8 << cpu) == 0
        }) {
            self.cpus[cpu].space = Some((space, generation));
            return I2Result::Rejected;
        }
        self.spaces[space].resident[cpu] = false;
        I2Result::Applied
    }

    fn finalize_object(&mut self, object: usize) -> I2Result {
        if self.objects[object].state != I2ObjectState::Live
            || self.objects[object].mappings != 0
            || self.spaces.iter().any(|space| {
                space.pending.is_some_and(|pending| {
                    matches!(
                        pending.mutation,
                        I2MappingMutation::Map { object: pending_object, .. }
                            if pending_object == object
                    )
                })
            })
        {
            return I2Result::Rejected;
        }
        self.objects[object].state = I2ObjectState::Finalized;
        I2Result::Applied
    }

    fn reclaim_object(&mut self, object: usize) -> I2Result {
        if self.objects[object].state != I2ObjectState::Finalized {
            return I2Result::Rejected;
        }
        self.objects[object].state = I2ObjectState::Reclaimed;
        self.objects[object].generation = self.objects[object]
            .generation
            .checked_add(1)
            .expect("I2 object generation must not wrap");
        I2Result::Applied
    }

    fn teardown(&mut self, space: usize) -> I2Result {
        let record = &self.spaces[space];
        if !record.active
            || record.owner.is_some()
            || record.pending.is_some()
            || record.mapping.is_some()
        {
            return I2Result::Rejected;
        }
        if record.resident.iter().any(|resident| *resident) {
            return I2Result::Rejected;
        }
        self.spaces[space].active = false;
        self.spaces[space].generation = self.spaces[space]
            .generation
            .checked_add(1)
            .expect("I2 space generation must not wrap");
        I2Result::Applied
    }

    fn is_descendant(&self, ancestor: usize, candidate: usize) -> bool {
        let mut current = Some(candidate);
        while let Some(process) = current {
            if process == ancestor {
                return true;
            }
            current = self.processes[process].parent;
        }
        false
    }

    fn create_child(&mut self, parent: usize, slot: usize) -> I2Result {
        if !self.processes[parent].active || self.processes[slot].active || parent == slot {
            return I2Result::Rejected;
        }
        let Some(space) = self
            .spaces
            .iter()
            .position(|record| record.active && record.owner.is_none())
        else {
            return I2Result::Noop;
        };
        self.processes[slot].active = true;
        self.processes[slot].parent = Some(parent);
        self.processes[slot].space = space;
        self.processes[slot].generation = self.processes[slot]
            .generation
            .checked_add(1)
            .expect("I2 process generation must not wrap");
        self.spaces[space].owner = Some(slot);
        I2Result::Applied
    }

    fn try_sibling_authority(&self, caller: usize, target: usize) -> I2Result {
        if !self.processes[caller].active || !self.processes[target].active {
            return I2Result::Rejected;
        }
        if self.is_descendant(caller, target) {
            I2Result::Applied
        } else {
            I2Result::Rejected
        }
    }

    fn exit_process(&mut self, process: usize) -> I2Result {
        if !self.processes[process].active || process == 0 {
            return I2Result::Rejected;
        }
        for index in 0..I2_PROCESSES {
            if self.processes[index].active && self.is_descendant(process, index) {
                let space = self.processes[index].space;
                if self.spaces[space].resident.iter().any(|resident| *resident)
                    || self.spaces[space].mapping.is_some()
                    || self.spaces[space].pending.is_some()
                {
                    return I2Result::Rejected;
                }
            }
        }
        for index in 0..I2_PROCESSES {
            if self.processes[index].active && self.is_descendant(process, index) {
                self.spaces[self.processes[index].space].owner = None;
                self.processes[index].active = false;
            }
        }
        I2Result::Applied
    }

    fn idle(&mut self, cpu: usize) -> I2Result {
        if self.cpus[cpu].space.is_some() || self.cpus[cpu].idle {
            return I2Result::Noop;
        }
        self.cpus[cpu].idle = true;
        I2Result::Applied
    }

    fn wake(&mut self, cpu: usize, generation: u64) -> I2Result {
        if generation != self.cpus[cpu].wake_generation {
            return I2Result::Rejected;
        }
        self.cpus[cpu].wake_generation = self.cpus[cpu]
            .wake_generation
            .checked_add(1)
            .expect("I2 wake generation must not wrap");
        self.cpus[cpu].idle = false;
        I2Result::Applied
    }

    fn arm_timer(&mut self, cpu: usize, delta: u64) -> I2Result {
        self.cpus[cpu].timer_generation = self.cpus[cpu]
            .timer_generation
            .checked_add(1)
            .expect("I2 timer generation must not wrap");
        self.cpus[cpu].timer_deadline = Some(
            self.now
                .checked_add(delta)
                .expect("I2 timer deadline must not wrap"),
        );
        I2Result::Applied
    }

    fn fire_timer(&mut self, cpu: usize, generation: u64) -> I2Result {
        if generation != self.cpus[cpu].timer_generation {
            return I2Result::Rejected;
        }
        let Some(deadline) = self.cpus[cpu].timer_deadline else {
            return I2Result::Noop;
        };
        if self.now < deadline {
            return I2Result::Noop;
        }
        self.cpus[cpu].timer_deadline = None;
        self.cpus[cpu].idle = false;
        I2Result::Applied
    }

    fn advance(&mut self, delta: u64) -> I2Result {
        if delta >= u64::from(PM_TIMER_MODULUS) {
            return I2Result::Rejected;
        }
        self.now = self
            .now
            .checked_add(delta)
            .expect("I2 monotonic clock must not wrap");
        let previous_sample = self.pm_last_sample;
        let next_sample = (u64::from(previous_sample) + delta) % u64::from(PM_TIMER_MODULUS);
        let sampled_delta = if next_sample >= u64::from(previous_sample) {
            next_sample - u64::from(previous_sample)
        } else {
            self.pm_wraps = self
                .pm_wraps
                .checked_add(1)
                .expect("I2 PM wrap count must not wrap");
            u64::from(PM_TIMER_MODULUS) - u64::from(previous_sample) + next_sample
        };
        self.pm_extended = self
            .pm_extended
            .checked_add(sampled_delta)
            .expect("I2 PM extended counter must not wrap");
        self.pm_counter = next_sample as u32;
        self.pm_last_sample = self.pm_counter;
        I2Result::Applied
    }

    fn apply(&mut self, operation: I2Operation) -> I2Result {
        match operation {
            I2Operation::Enter { cpu, space } => self.enter(cpu, space),
            I2Operation::Leave { cpu } => self.leave(cpu),
            I2Operation::Map {
                space,
                object,
                initiator,
            } => self.begin_mutation(
                space,
                I2MappingMutation::Map {
                    object,
                    protection: 0b011,
                },
                initiator,
            ),
            I2Operation::Protect {
                space,
                protection,
                initiator,
            } => self.begin_mutation(space, I2MappingMutation::Protect { protection }, initiator),
            I2Operation::Unmap { space, initiator } => {
                self.begin_mutation(space, I2MappingMutation::Unmap, initiator)
            }
            I2Operation::Ack {
                space,
                cpu,
                generation,
            } => self.acknowledge(space, cpu, generation),
            I2Operation::FinalizeObject { object } => self.finalize_object(object),
            I2Operation::ReclaimObject { object } => self.reclaim_object(object),
            I2Operation::TearDown { space } => self.teardown(space),
            I2Operation::CreateChild { parent, slot } => self.create_child(parent, slot),
            I2Operation::TrySiblingAuthority { caller, target } => {
                self.try_sibling_authority(caller, target)
            }
            I2Operation::ExitProcess { process } => self.exit_process(process),
            I2Operation::Idle { cpu } => self.idle(cpu),
            I2Operation::Wake { cpu, generation } => self.wake(cpu, generation),
            I2Operation::ArmTimer { cpu, delta } => self.arm_timer(cpu, delta),
            I2Operation::FireTimer { cpu, generation } => self.fire_timer(cpu, generation),
            I2Operation::Advance { delta } => self.advance(delta),
        }
    }

    fn assert_invariants(&self, context: I2Context) {
        let fail = |stage: &str, message: &str| -> ! {
            panic!("{}", context.failure(stage, message));
        };

        for (cpu, state) in self.cpus.iter().enumerate() {
            if let Some((space, generation)) = state.space {
                if !self.spaces[space].active || self.spaces[space].generation != generation {
                    fail("residency", "CPU holds a stale address-space identity");
                }
                if !self.spaces[space].resident[cpu] {
                    fail("residency", "CPU carrier is not published in the space");
                }
                if state.idle {
                    fail("idle", "CPU is both resident and idle");
                }
            }
            if state.timer_generation == 0 || state.wake_generation == 0 {
                fail("timer", "CPU generation reached zero");
            }
        }

        for (space_index, space) in self.spaces.iter().enumerate() {
            let resident_count = space.resident.iter().filter(|resident| **resident).count();
            let published_count = self
                .cpus
                .iter()
                .filter(|cpu| {
                    cpu.space.is_some_and(|(space_id, generation)| {
                        space_id == space_index && generation == space.generation
                    })
                })
                .count();
            if resident_count != published_count {
                fail("residency", "resident CPU set disagrees with CPU carriers");
            }
            if let Some(pending) = space.pending {
                if pending.generation != space.mutation_generation {
                    fail(
                        "shootdown",
                        "pending acknowledgement targets the wrong mutation generation",
                    );
                }
                if pending.received_acks & !pending.required_acks != 0 {
                    fail("shootdown", "acknowledgement arrived for a nonresident CPU");
                }
                if pending.received_acks == pending.required_acks {
                    fail("shootdown", "completed shootdown remained published");
                }
            }
            if !space.active
                && (space.mapping.is_some()
                    || space.pending.is_some()
                    || space.resident.iter().any(|resident| *resident))
            {
                fail("teardown", "retired space retained live ownership");
            }
        }

        let mut mapping_counts = [0_u8; I2_OBJECTS];
        for space in &self.spaces {
            if let Some((object, _)) = space.mapping {
                mapping_counts[object] = mapping_counts[object]
                    .checked_add(1)
                    .unwrap_or_else(|| fail("memory-object", "mapping count overflowed"));
                if self.objects[object].state != I2ObjectState::Live {
                    fail("memory-object", "non-live object remains mapped");
                }
            }
            if let Some(I2PendingMutation {
                mutation: I2MappingMutation::Map { object, .. },
                ..
            }) = space.pending
                && self.objects[object].state != I2ObjectState::Live
            {
                fail("memory-object", "finalization raced a pending map");
            }
        }
        for (object, state) in self.objects.iter().enumerate() {
            if state.mappings != mapping_counts[object] {
                fail(
                    "memory-object",
                    "object mapping count disagrees with spaces",
                );
            }
            if state.state != I2ObjectState::Live && state.mappings != 0 {
                fail("memory-object", "finalized object still has mappings");
            }
        }

        for (process, record) in self.processes.iter().enumerate() {
            if record.active {
                if !self.spaces[record.space].active
                    || self.spaces[record.space].owner != Some(process)
                {
                    fail(
                        "subtree",
                        "active process does not own an active address space",
                    );
                }
                if let Some(parent) = record.parent
                    && (!self.processes[parent].active || parent == process)
                {
                    fail("subtree", "active process has an invalid parent");
                }
            }
            let mut current = record.parent;
            for _ in 0..I2_PROCESSES {
                if current == Some(process) {
                    fail("subtree", "process hierarchy contains a cycle");
                }
                current = current.and_then(|parent| self.processes[parent].parent);
            }
        }
        for (space, record) in self.spaces.iter().enumerate() {
            if let Some(owner) = record.owner
                && (!self.processes[owner].active || self.processes[owner].space != space)
            {
                fail("subtree", "address-space owner is stale or mismatched");
            }
        }

        if self.pm_counter >= PM_TIMER_MODULUS || self.pm_last_sample >= PM_TIMER_MODULUS {
            fail("pm-timer", "counter escaped the 24-bit hardware range");
        }
        if self.pm_counter != self.pm_last_sample {
            fail(
                "pm-timer",
                "stored PM counter differs from the last raw sample",
            );
        }
        let expected_extended = self
            .pm_wraps
            .checked_mul(u64::from(PM_TIMER_MODULUS))
            .and_then(|value| value.checked_add(u64::from(self.pm_counter)))
            .unwrap_or_else(|| fail("pm-timer", "extended counter overflowed"));
        if self.pm_extended != expected_extended {
            fail(
                "pm-timer",
                "maintenance extension disagrees with sampled counter",
            );
        }
    }
}

#[derive(Clone, Copy)]
struct I2Rng(u64);

impl I2Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bounded(&mut self, upper: usize) -> usize {
        (self.next() as usize) % upper
    }

    fn operation(&mut self, model: &I2Model) -> I2Operation {
        match self.bounded(18) {
            0 => I2Operation::Enter {
                cpu: self.bounded(I2_CPUS),
                space: self.bounded(I2_SPACES),
            },
            1 => I2Operation::Leave {
                cpu: self.bounded(I2_CPUS),
            },
            2 => I2Operation::Map {
                space: self.bounded(I2_SPACES),
                object: self.bounded(I2_OBJECTS),
                initiator: self.bounded(I2_CPUS),
            },
            3 => I2Operation::Protect {
                space: self.bounded(I2_SPACES),
                protection: 1 + self.bounded(7) as u8,
                initiator: self.bounded(I2_CPUS),
            },
            4 => I2Operation::Unmap {
                space: self.bounded(I2_SPACES),
                initiator: self.bounded(I2_CPUS),
            },
            5 | 6 => {
                let space = self.bounded(I2_SPACES);
                let generation = if self.next() & 1 == 0 {
                    model.spaces[space].mutation_generation
                } else {
                    model.spaces[space].mutation_generation.saturating_sub(1)
                };
                I2Operation::Ack {
                    space,
                    cpu: self.bounded(I2_CPUS),
                    generation,
                }
            }
            7 => I2Operation::FinalizeObject {
                object: self.bounded(I2_OBJECTS),
            },
            8 => I2Operation::ReclaimObject {
                object: self.bounded(I2_OBJECTS),
            },
            9 => I2Operation::TearDown {
                space: self.bounded(I2_SPACES),
            },
            10 => I2Operation::CreateChild {
                parent: self.bounded(I2_PROCESSES),
                slot: self.bounded(I2_PROCESSES),
            },
            11 => I2Operation::TrySiblingAuthority {
                caller: self.bounded(I2_PROCESSES),
                target: self.bounded(I2_PROCESSES),
            },
            12 => I2Operation::ExitProcess {
                process: 1 + self.bounded(I2_PROCESSES - 1),
            },
            13 => I2Operation::Idle {
                cpu: self.bounded(I2_CPUS),
            },
            14 => {
                let cpu = self.bounded(I2_CPUS);
                let generation = model.cpus[cpu].wake_generation;
                I2Operation::Wake { cpu, generation }
            }
            15 => I2Operation::ArmTimer {
                cpu: self.bounded(I2_CPUS),
                delta: 1 + self.next() % 31,
            },
            16 => {
                let cpu = self.bounded(I2_CPUS);
                let generation = model.cpus[cpu].timer_generation;
                I2Operation::FireTimer { cpu, generation }
            }
            _ => I2Operation::Advance {
                delta: 1 + self.next() % 0x20_0000,
            },
        }
    }
}

#[test]
fn i2_deterministic_mapping_authority_and_idle_stress_preserves_ownership() {
    for seed in I2_SEEDS {
        let mut model = I2Model::new();
        let mut rng = I2Rng(seed);
        let prefix = [
            I2Operation::Enter { cpu: 0, space: 0 },
            I2Operation::Enter { cpu: 1, space: 0 },
            I2Operation::Map {
                space: 0,
                object: 0,
                initiator: 0,
            },
            I2Operation::Ack {
                space: 0,
                cpu: 1,
                generation: 1,
            },
            I2Operation::Protect {
                space: 0,
                protection: 0b101,
                initiator: 0,
            },
            I2Operation::Ack {
                space: 0,
                cpu: 1,
                generation: 1,
            },
            I2Operation::Ack {
                space: 0,
                cpu: 1,
                generation: 2,
            },
            I2Operation::FinalizeObject { object: 0 },
            I2Operation::Unmap {
                space: 0,
                initiator: 0,
            },
            I2Operation::Ack {
                space: 0,
                cpu: 1,
                generation: 2,
            },
            I2Operation::Ack {
                space: 0,
                cpu: 1,
                generation: 3,
            },
            I2Operation::FinalizeObject { object: 0 },
            I2Operation::ReclaimObject { object: 0 },
            I2Operation::Leave { cpu: 0 },
            I2Operation::Leave { cpu: 1 },
            I2Operation::TearDown { space: 0 },
            I2Operation::CreateChild { parent: 0, slot: 1 },
            I2Operation::CreateChild { parent: 1, slot: 2 },
            I2Operation::TrySiblingAuthority {
                caller: 2,
                target: 1,
            },
            I2Operation::TrySiblingAuthority {
                caller: 1,
                target: 2,
            },
            I2Operation::TearDown { space: 1 },
            I2Operation::ExitProcess { process: 1 },
            I2Operation::TearDown { space: 1 },
            I2Operation::TearDown { space: 2 },
            I2Operation::Idle { cpu: 0 },
            I2Operation::Wake {
                cpu: 0,
                generation: 1,
            },
            I2Operation::Wake {
                cpu: 0,
                generation: 1,
            },
            I2Operation::ArmTimer { cpu: 0, delta: 7 },
            I2Operation::FireTimer {
                cpu: 0,
                generation: 1,
            },
            I2Operation::Advance { delta: 7 },
            I2Operation::FireTimer {
                cpu: 0,
                generation: 2,
            },
            I2Operation::Idle { cpu: 0 },
            I2Operation::Wake {
                cpu: 0,
                generation: 2,
            },
            I2Operation::ArmTimer { cpu: 0, delta: 3 },
            I2Operation::FireTimer {
                cpu: 0,
                generation: 2,
            },
            I2Operation::Advance { delta: 3 },
            I2Operation::FireTimer {
                cpu: 0,
                generation: 3,
            },
        ];
        for (operation_index, operation) in prefix.into_iter().enumerate() {
            let context = I2Context {
                seed,
                operation: operation_index,
                name: operation,
            };
            let result = model.apply(operation);
            let expected = match operation_index {
                5 | 7 | 9 | 15 | 18 | 20 | 26 | 28 | 34 => I2Result::Rejected,
                _ => I2Result::Applied,
            };
            assert_eq!(
                result,
                expected,
                "{} stage=expected-prefix",
                context.failure("expected-prefix", "operation result diverged")
            );
            assert!(
                matches!(
                    result,
                    I2Result::Applied | I2Result::Rejected | I2Result::Noop
                ),
                "{} stage=apply returned an unknown result",
                context.failure("apply", "invalid result")
            );
            model.assert_invariants(context);
            if operation_index == 6 {
                assert_eq!(
                    model.spaces[0].mapping,
                    Some((0, 0b101)),
                    "{} stage=protect-commit mapping protection was not published",
                    context.failure("protect-commit", "protection update missing")
                );
            }
        }

        let mut applied = 0_usize;
        let mut rejected = 0_usize;
        let mut noop = 0_usize;
        for operation_index in prefix.len()..(prefix.len() + I2_OPERATIONS_PER_SEED) {
            let operation = rng.operation(&model);
            let context = I2Context {
                seed,
                operation: operation_index,
                name: operation,
            };
            let result = model.apply(operation);
            match result {
                I2Result::Applied => applied += 1,
                I2Result::Rejected => rejected += 1,
                I2Result::Noop => noop += 1,
            }
            model.assert_invariants(context);
        }

        assert!(
            applied > 100,
            "seed={seed:#018x} operation={} stage=coverage applied outcomes were not exercised: {applied}",
            prefix.len() + I2_OPERATIONS_PER_SEED
        );
        assert!(
            rejected > 100,
            "seed={seed:#018x} operation={} stage=coverage rejected outcomes were not exercised: {rejected}",
            prefix.len() + I2_OPERATIONS_PER_SEED
        );
        assert!(
            noop > 10,
            "seed={seed:#018x} operation={} stage=coverage noop outcomes were not exercised: {noop}",
            prefix.len() + I2_OPERATIONS_PER_SEED
        );
        assert!(
            model.pm_wraps > 0,
            "seed={seed:#018x} operation={} stage=pm-timer no counter wrap was exercised",
            prefix.len() + I2_OPERATIONS_PER_SEED
        );
    }
}

// This companion oracle deliberately models the I2 operation *families* that
// are broader than the page-table model above.  It is intentionally bounded:
// the goal is deterministic ownership/lifetime coverage, not to pretend that
// a host test has established the live four-vCPU runtime contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2Family {
    Handle,
    Channel,
    Wait,
    Lifecycle,
    Mapping,
    MemoryObject,
    Subtree,
    IdleWakeTimer,
    Shootdown,
}

impl I2Family {
    const COUNT: usize = 9;

    const fn index(self) -> usize {
        match self {
            Self::Handle => 0,
            Self::Channel => 1,
            Self::Wait => 2,
            Self::Lifecycle => 3,
            Self::Mapping => 4,
            Self::MemoryObject => 5,
            Self::Subtree => 6,
            Self::IdleWakeTimer => 7,
            Self::Shootdown => 8,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Handle => "handle",
            Self::Channel => "channel",
            Self::Wait => "wait",
            Self::Lifecycle => "lifecycle",
            Self::Mapping => "mapping",
            Self::MemoryObject => "memory-object",
            Self::Subtree => "subtree",
            Self::IdleWakeTimer => "idle-wake-timer",
            Self::Shootdown => "shootdown",
        }
    }

    const ALL: [Self; Self::COUNT] = [
        Self::Handle,
        Self::Channel,
        Self::Wait,
        Self::Lifecycle,
        Self::Mapping,
        Self::MemoryObject,
        Self::Subtree,
        Self::IdleWakeTimer,
        Self::Shootdown,
    ];
}

#[derive(Default)]
struct I2Coverage {
    family: [usize; I2Family::COUNT],
    cpu: [usize; I2_CPUS],
}

impl I2Coverage {
    fn record(&mut self, family: I2Family, cpu: usize) {
        self.family[family.index()] += 1;
        self.cpu[cpu] += 1;
    }

    fn assert_complete(&self, seed: u64, operation: usize) {
        for family in I2Family::ALL {
            assert!(
                self.family[family.index()] > 0,
                "seed={seed:#018x} operation={operation} family={} stage=coverage family was not exercised",
                family.name(),
            );
        }
        for (cpu, count) in self.cpu.iter().enumerate() {
            assert!(
                *count > 0,
                "seed={seed:#018x} operation={operation} family=cpu-{cpu} stage=coverage CPU was not exercised",
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct I2OracleHandle {
    generation: u64,
    rights: u8,
    live: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2OracleThread {
    Created,
    Started,
    Exited,
    Excepted,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct I2OracleThreadSlot {
    generation: u64,
    state: I2OracleThread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2WaitCompletion {
    Signal,
    Timeout,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct I2OracleWait {
    token: u64,
    thread_generation: u64,
}

struct I2ProtocolOracle {
    handles: [I2OracleHandle; 3],
    messages: usize,
    peer_closed: bool,
    waits: [Option<I2OracleWait>; I2_CPUS],
    completed_waits: [Option<I2WaitCompletion>; I2_CPUS],
    next_wait: u64,
    threads: [I2OracleThreadSlot; I2_CPUS],
}

impl I2ProtocolOracle {
    fn new() -> Self {
        Self {
            handles: [
                I2OracleHandle {
                    generation: 1,
                    rights: 0b111,
                    live: true,
                },
                I2OracleHandle {
                    generation: 1,
                    rights: 0,
                    live: false,
                },
                I2OracleHandle {
                    generation: 1,
                    rights: 0b111,
                    live: true,
                },
            ],
            messages: 0,
            peer_closed: false,
            waits: [None; I2_CPUS],
            completed_waits: [None; I2_CPUS],
            next_wait: 1,
            threads: [I2OracleThreadSlot {
                generation: 1,
                state: I2OracleThread::Created,
            }; I2_CPUS],
        }
    }

    fn duplicate_reduced(&mut self, source: usize, destination: usize, rights: u8) -> bool {
        let source_handle = self.handles[source];
        if !source_handle.live || rights & !source_handle.rights != 0 {
            return false;
        }
        let destination_handle = &mut self.handles[destination];
        destination_handle.generation += 1;
        destination_handle.rights = rights;
        destination_handle.live = true;
        true
    }

    fn close(&mut self, handle: usize, generation: u64) -> bool {
        let entry = &mut self.handles[handle];
        if !entry.live || entry.generation != generation {
            return false;
        }
        entry.live = false;
        true
    }

    fn close_peer(&mut self, handle: usize, generation: u64) -> bool {
        if !self.close(handle, generation) {
            return false;
        }
        self.peer_closed = true;
        true
    }

    fn send_reason(&mut self, handle: usize, generation: u64) -> I2ChannelResult {
        let handle = self.handles[handle];
        if !handle.live || handle.generation != generation || handle.rights & 0b001 == 0 {
            return I2ChannelResult::StaleOrRights;
        }
        if self.peer_closed {
            return I2ChannelResult::PeerClosed;
        }
        if self.messages == MESSAGE_CAPACITY {
            return I2ChannelResult::Backpressure;
        }
        self.messages += 1;
        I2ChannelResult::Applied
    }

    fn send(&mut self, handle: usize, generation: u64) -> bool {
        self.send_reason(handle, generation) == I2ChannelResult::Applied
    }

    fn receive(&mut self, handle: usize, generation: u64) -> bool {
        let handle = self.handles[handle];
        if !handle.live || handle.generation != generation || handle.rights & 0b010 == 0 {
            return false;
        }
        if self.messages == 0 {
            return false;
        }
        self.messages -= 1;
        true
    }

    fn wait(&mut self, cpu: usize) -> I2OracleWait {
        if self.threads[cpu].state == I2OracleThread::Terminated {
            return I2OracleWait {
                token: 0,
                thread_generation: 0,
            };
        }
        let token = self.next_wait;
        self.next_wait += 1;
        let wait = I2OracleWait {
            token,
            thread_generation: self.threads[cpu].generation,
        };
        self.waits[cpu] = Some(wait);
        wait
    }

    fn finish_wait(&mut self, cpu: usize, wait: I2OracleWait, reason: I2WaitCompletion) -> bool {
        if wait.token == 0
            || self.waits[cpu] != Some(wait)
            || self.threads[cpu].generation != wait.thread_generation
            || self.threads[cpu].state == I2OracleThread::Terminated
        {
            return false;
        }
        self.waits[cpu] = None;
        self.completed_waits[cpu] = Some(reason);
        true
    }

    fn create(&mut self, cpu: usize) -> bool {
        if self.threads[cpu].state != I2OracleThread::Terminated {
            return false;
        }
        self.threads[cpu].generation += 1;
        self.threads[cpu].state = I2OracleThread::Created;
        true
    }

    fn start(&mut self, cpu: usize, generation: u64) -> bool {
        if self.threads[cpu].generation != generation
            || self.threads[cpu].state != I2OracleThread::Created
        {
            return false;
        }
        self.threads[cpu].state = I2OracleThread::Started;
        true
    }

    fn complete(&mut self, cpu: usize, generation: u64, state: I2OracleThread) -> bool {
        if !matches!(state, I2OracleThread::Exited | I2OracleThread::Excepted)
            || self.threads[cpu].generation != generation
            || self.threads[cpu].state != I2OracleThread::Started
        {
            return false;
        }
        self.threads[cpu].state = state;
        true
    }

    fn terminal_retire(&mut self, cpu: usize, generation: u64) -> bool {
        if self.threads[cpu].generation != generation
            || matches!(self.threads[cpu].state, I2OracleThread::Terminated)
        {
            return false;
        }
        self.threads[cpu].state = I2OracleThread::Terminated;
        self.waits[cpu] = None;
        self.completed_waits[cpu] = None;
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2ChannelResult {
    Applied,
    StaleOrRights,
    Backpressure,
    PeerClosed,
}

fn i2_oracle_assert(seed: u64, operation: usize, family: I2Family, stage: &str, condition: bool) {
    assert!(
        condition,
        "seed={seed:#018x} operation={operation} family={} stage={stage}",
        family.name(),
    );
}

fn i2_seeded_cpu_order(rng: &mut I2Rng) -> [usize; I2_CPUS] {
    let mut order = [0, 1, 2, 3];
    for index in (1..I2_CPUS).rev() {
        let swap = rng.bounded(index + 1);
        order.swap(index, swap);
    }
    order
}

#[test]
fn i2_deterministic_operation_family_oracle_is_bounded_and_complete() {
    let mut schedules = Vec::new();
    for seed in I2_SEEDS {
        let mut rng = I2Rng(seed);
        let cpu_order = i2_seeded_cpu_order(&mut rng);
        let initiator_order = i2_seeded_cpu_order(&mut rng);
        schedules.push((cpu_order, initiator_order));
        let mut coverage = I2Coverage::default();
        let mut protocol = I2ProtocolOracle::new();
        let mut operation = 0;
        let source_generation = protocol.handles[0].generation;

        // Duplicate with reduced rights, close, then reject the stale source.
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Handle,
            "duplicate-reduced",
            protocol.duplicate_reduced(0, 1, 0b011),
        );
        coverage.record(I2Family::Handle, 0);
        operation += 1;
        let duplicate_generation = protocol.handles[1].generation;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Handle,
            "close-source",
            protocol.close(0, source_generation),
        );
        coverage.record(I2Family::Handle, 1);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Handle,
            "stale-source-rejected",
            !protocol.close(0, source_generation),
        );
        coverage.record(I2Family::Handle, 2);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Handle,
            "reduced-rights",
            protocol.handles[1].rights == 0b011,
        );
        coverage.record(I2Family::Handle, 3);
        operation += 1;

        // Channel capacity and peer-close are distinct from local handle close.
        for cpu in cpu_order {
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Channel,
                "send",
                protocol.send(1, duplicate_generation),
            );
            coverage.record(I2Family::Channel, cpu);
            operation += 1;
        }
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Channel,
            "backpressure",
            protocol.send_reason(1, duplicate_generation) == I2ChannelResult::Backpressure,
        );
        coverage.record(I2Family::Channel, 0);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Channel,
            "receive",
            protocol.receive(1, duplicate_generation),
        );
        coverage.record(I2Family::Channel, 1);
        operation += 1;
        protocol.handles[1].rights = 0b001;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Channel,
            "rights-rejected-receive",
            !protocol.receive(1, duplicate_generation),
        );
        protocol.handles[1].rights = 0b011;
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Channel,
            "endpoint-close",
            protocol.close_peer(2, protocol.handles[2].generation),
        );
        coverage.record(I2Family::Channel, 2);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Channel,
            "live-peer-propagated-close",
            protocol.handles[1].live
                && protocol.send_reason(1, duplicate_generation) == I2ChannelResult::PeerClosed,
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Channel,
            "stale-receive-after-source-close",
            !protocol.receive(0, source_generation),
        );
        operation += 1;

        for cpu in cpu_order {
            let signal = protocol.wait(cpu);
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Wait,
                "signal",
                protocol.finish_wait(cpu, signal, I2WaitCompletion::Signal),
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Wait,
                "signal-race-rejected",
                !protocol.finish_wait(cpu, signal, I2WaitCompletion::Cancel),
            );
            coverage.record(I2Family::Wait, cpu);
            operation += 1;
            let timeout = protocol.wait(cpu);
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Wait,
                "timeout",
                protocol.finish_wait(cpu, timeout, I2WaitCompletion::Timeout),
            );
            operation += 1;
            let cancel = protocol.wait(cpu);
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Wait,
                "cancel",
                protocol.finish_wait(cpu, cancel, I2WaitCompletion::Cancel),
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Wait,
                "completion-reason",
                protocol.completed_waits[cpu] == Some(I2WaitCompletion::Cancel),
            );
            operation += 1;
        }
        let stale_wait = protocol.wait(0);
        let stale_generation = protocol.threads[0].generation;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Lifecycle,
            "terminal-wait-owner",
            protocol.terminal_retire(0, stale_generation),
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Wait,
            "terminal-retirement",
            !protocol.finish_wait(0, stale_wait, I2WaitCompletion::Signal),
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Lifecycle,
            "start-after-terminal",
            !protocol.start(0, stale_generation),
        );
        coverage.record(I2Family::Wait, 0);
        operation += 1;

        for cpu in cpu_order {
            // The earlier terminal-wait path may have retired this slot; this
            // is a fresh generation's create transition before start.
            if protocol.threads[cpu].state == I2OracleThread::Terminated {
                i2_oracle_assert(
                    seed,
                    operation,
                    I2Family::Lifecycle,
                    "create-after-terminal",
                    protocol.create(cpu),
                );
            }
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "create",
                protocol.threads[cpu].state == I2OracleThread::Created,
            );
            operation += 1;
            let generation = protocol.threads[cpu].generation;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "start",
                protocol.start(cpu, generation),
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "duplicate-start",
                !protocol.start(cpu, generation),
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "start",
                protocol.threads[cpu].state == I2OracleThread::Started,
            );
            coverage.record(I2Family::Lifecycle, cpu);
            operation += 1;
            let completion = if rng.next() & 1 == 0 {
                I2OracleThread::Exited
            } else {
                I2OracleThread::Excepted
            };
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "exit-or-exception",
                protocol.complete(cpu, generation, completion),
            );
            operation += 1;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "stale-generation-completion",
                !protocol.complete(cpu, generation.saturating_sub(1), completion),
            );
            operation += 1;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "terminate",
                protocol.terminal_retire(cpu, generation),
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "terminate",
                protocol.threads[cpu].state == I2OracleThread::Terminated,
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Lifecycle,
                "terminal-after-terminal",
                !protocol.terminal_retire(cpu, generation),
            );
            operation += 1;
        }

        // Keep the negative remote-ack paths in one small model so every
        // rejection is attributable to the pending exact generation, rather
        // than merely to an unrelated finished mutation.
        let mut ack_adversary = I2Model::new();
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "ack-adversary-enter-initiator",
            ack_adversary.enter(0, 0) == I2Result::Applied,
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "ack-adversary-enter-remote",
            ack_adversary.enter(1, 0) == I2Result::Applied,
        );
        let pending_generation = ack_adversary.spaces[0].mutation_generation;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "pending-map",
            ack_adversary.begin_mutation(
                0,
                I2MappingMutation::Map {
                    object: 0,
                    protection: 0b011,
                },
                0,
            ) == I2Result::Applied,
        );
        coverage.record(I2Family::Shootdown, 0);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "mutation-contention",
            ack_adversary.begin_mutation(
                0,
                I2MappingMutation::Map {
                    object: 2,
                    protection: 0b101,
                },
                0,
            ) == I2Result::Rejected,
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "nonresident-ack",
            ack_adversary.acknowledge(0, 2, pending_generation) == I2Result::Rejected,
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "leave-before-ack",
            ack_adversary.leave(1) == I2Result::Rejected,
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::MemoryObject,
            "finalize-refuses-pending-map",
            ack_adversary.finalize_object(0) == I2Result::Rejected,
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::MemoryObject,
            "reclaim-refuses-pending-map",
            ack_adversary.reclaim_object(0) == I2Result::Rejected,
        );
        ack_adversary.spaces[0].owner = None;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "teardown-refuses-pending-map",
            ack_adversary.teardown(0) == I2Result::Rejected,
        );
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "current-remote-ack",
            ack_adversary.acknowledge(0, 1, pending_generation) == I2Result::Applied,
        );
        coverage.record(I2Family::Shootdown, 1);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Shootdown,
            "duplicate-current-ack",
            ack_adversary.acknowledge(0, 1, pending_generation) == I2Result::Rejected,
        );

        // Four initiators mutate a space resident on all four CPUs.  Every
        // exact generation must acknowledge before map/protect/unmap commits;
        // the prior generation is rejected while the mutation is pending.
        let mut model = I2Model::new();
        for cpu in 0..I2_CPUS {
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Mapping,
                "enter",
                model.enter(cpu, 0) == I2Result::Applied,
            );
            coverage.record(I2Family::Mapping, cpu);
            operation += 1;
        }
        for initiator in initiator_order {
            let map_generation = model.spaces[0].mutation_generation;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Mapping,
                "map",
                model.begin_mutation(
                    0,
                    I2MappingMutation::Map {
                        object: 1,
                        protection: 0b011,
                    },
                    initiator,
                ) == I2Result::Applied,
            );
            coverage.record(I2Family::Mapping, initiator);
            operation += 1;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Shootdown,
                "stale-exact-generation-ack",
                model.acknowledge(
                    0,
                    (initiator + 1) % I2_CPUS,
                    map_generation.saturating_sub(1),
                ) == I2Result::Rejected,
            );
            coverage.record(I2Family::Shootdown, initiator);
            operation += 1;
            for cpu in 0..I2_CPUS {
                if cpu != initiator {
                    i2_oracle_assert(
                        seed,
                        operation,
                        I2Family::Shootdown,
                        "map-ack",
                        model.acknowledge(0, cpu, map_generation) == I2Result::Applied,
                    );
                    coverage.record(I2Family::Shootdown, cpu);
                    operation += 1;
                }
            }
            let protect_generation = model.spaces[0].mutation_generation;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Mapping,
                "protect",
                model.begin_mutation(
                    0,
                    I2MappingMutation::Protect { protection: 0b101 },
                    initiator,
                ) == I2Result::Applied,
            );
            operation += 1;
            for cpu in 0..I2_CPUS {
                if cpu != initiator {
                    i2_oracle_assert(
                        seed,
                        operation,
                        I2Family::Shootdown,
                        "protect-ack",
                        model.acknowledge(0, cpu, protect_generation) == I2Result::Applied,
                    );
                    operation += 1;
                }
            }
            let unmap_generation = model.spaces[0].mutation_generation;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::Mapping,
                "unmap",
                model.begin_mutation(0, I2MappingMutation::Unmap, initiator) == I2Result::Applied,
            );
            operation += 1;
            for cpu in 0..I2_CPUS {
                if cpu != initiator {
                    i2_oracle_assert(
                        seed,
                        operation,
                        I2Family::Shootdown,
                        "unmap-ack",
                        model.acknowledge(0, cpu, unmap_generation) == I2Result::Applied,
                    );
                    operation += 1;
                }
            }
        }
        i2_oracle_assert(
            seed,
            operation,
            I2Family::MemoryObject,
            "finalize",
            model.finalize_object(1) == I2Result::Applied,
        );
        coverage.record(I2Family::MemoryObject, 0);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::MemoryObject,
            "reclaim",
            model.reclaim_object(1) == I2Result::Applied,
        );
        coverage.record(I2Family::MemoryObject, 1);
        operation += 1;

        i2_oracle_assert(
            seed,
            operation,
            I2Family::Subtree,
            "create-child",
            model.create_child(0, 1) == I2Result::Applied,
        );
        coverage.record(I2Family::Subtree, 2);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Subtree,
            "reject-sibling-authority",
            model.try_sibling_authority(1, 0) == I2Result::Rejected,
        );
        coverage.record(I2Family::Subtree, 3);
        operation += 1;
        i2_oracle_assert(
            seed,
            operation,
            I2Family::Lifecycle,
            "process-exit",
            model.exit_process(1) == I2Result::Applied,
        );
        coverage.record(I2Family::Lifecycle, 1);
        operation += 1;

        for cpu in 0..I2_CPUS {
            i2_oracle_assert(
                seed,
                operation,
                I2Family::IdleWakeTimer,
                "leave",
                model.leave(cpu) == I2Result::Applied,
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::IdleWakeTimer,
                "idle",
                model.idle(cpu) == I2Result::Applied,
            );
            let wake_generation = model.cpus[cpu].wake_generation;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::IdleWakeTimer,
                "wake",
                model.wake(cpu, wake_generation) == I2Result::Applied,
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::IdleWakeTimer,
                "stale-wake",
                model.wake(cpu, wake_generation) == I2Result::Rejected,
            );
            i2_oracle_assert(
                seed,
                operation,
                I2Family::IdleWakeTimer,
                "arm-timer",
                model.arm_timer(cpu, 1) == I2Result::Applied,
            );
            let timer_generation = model.cpus[cpu].timer_generation;
            i2_oracle_assert(
                seed,
                operation,
                I2Family::IdleWakeTimer,
                "early-timer",
                model.fire_timer(cpu, timer_generation) == I2Result::Noop,
            );
            coverage.record(I2Family::IdleWakeTimer, cpu);
            operation += 1;
        }
        i2_oracle_assert(
            seed,
            operation,
            I2Family::IdleWakeTimer,
            "advance",
            model.advance(1) == I2Result::Applied,
        );
        for cpu in 0..I2_CPUS {
            i2_oracle_assert(
                seed,
                operation,
                I2Family::IdleWakeTimer,
                "fire-timer",
                model.fire_timer(cpu, model.cpus[cpu].timer_generation) == I2Result::Applied,
            );
            operation += 1;
        }
        model.assert_invariants(I2Context {
            seed,
            operation,
            name: I2Operation::Advance { delta: 0 },
        });
        coverage.assert_complete(seed, operation);
    }
    for (index, schedule) in schedules.iter().enumerate() {
        assert!(
            schedules[..index].iter().all(|prior| prior != schedule),
            "I2 seeded companion schedule duplicated at index={index}: {schedule:?}",
        );
    }
}
