//! Structured liveness snapshot for the DW1/WYR1 runtime reset (card R1B).
//!
//! `DW1_WYR1_RUNTIME_RESET_IMPLEMENTATION_PLAN.md` section 8.2 requires a
//! bounded snapshot that identifies current CPU/thread state, scheduler
//! placement, wait ownership and outstanding teardown work, and section 8.2
//! further requires that it be "obtainable without taking the monolithic
//! runtime lock being investigated". Section 13 makes a snapshot that depends
//! on the stalled authority a stop condition.
//!
//! Most of what the plan asks for already lives outside
//! `RuntimeAuthorityLock`: the scheduler, wait registry, blocked-operation
//! registry and live time state each carry their own `IrqSpinMutex` inside the
//! `&'static PrimordialRuntimeShared`. Three facts do not — the per-CPU current
//! Process, the per-CPU root/context identity, and outstanding termination
//! transactions all live in the carrier behind that lock, and the carrier
//! itself is pinned to the boot stack, so it has no statically known address a
//! debugger could reach either.
//!
//! This module closes both gaps without moving ownership:
//!
//! * [`publish_current`] mirrors the per-CPU identity facts into lock-free
//!   per-CPU cells as they are established, so a stalled guest can report them
//!   without acquiring the runtime authority; and
//! * [`publish_runtime_authority`] records the address of the live authority's
//!   ticket pair once, so host GDB over the QEMU gdbstub can read it directly
//!   from memory without executing guest code at all.
//!
//! The mirror is diagnostic state, never authority. Nothing reads it to make a
//! scheduling, capability, or lifetime decision, and a torn or stale cell can
//! only degrade a report. Publication is a short run of relaxed atomic stores
//! on paths that already own the facts being published.
//!
//! Cells use an odd-during-write sequence so a reader — guest or debugger —
//! can detect that it observed a publication in progress instead of silently
//! reporting a mixed identity.

// The read side has no guest caller by design: host GDB reads `LIVENESS`
// straight out of memory over the gdbstub, which is the whole point of a
// diagnostic that must work when the runtime authority is stalled. A selector's
// timeout path calls `emit_snapshot` once reset card R1's product exists.
#![cfg_attr(
    target_os = "none",
    allow(
        dead_code,
        reason = "host GDB consumes the read side without a guest call; R1's product wires emit_snapshot"
    )
)]

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::cpu::{CPU_CAPACITY, CpuIndex};

/// Sentinel for "no wake requested yet", distinct from CPU 0.
pub(crate) const NO_CPU: u32 = u32::MAX;

/// Last runtime event a CPU published. Ordinals are diagnostic only and are
/// not a stable ABI; the plan's section 8.2 snapshot is explicitly test-visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum LivenessEvent {
    None = 0,
    /// The carrier was re-seated onto this CPU by `switch_cpu_state`.
    CarrierSelected = 1,
    /// A return-time preemption decision was taken on this CPU.
    Preempted = 2,
    /// A quantum expiry was published for this CPU's current execution.
    QuantumExpired = 3,
    /// This CPU entered the idle scheduler.
    IdleEntered = 4,
    /// This CPU began a Process/TaskGroup/Thread termination transaction.
    TerminationPrepared = 5,
    /// A thread was dispatched onto this CPU.
    Dispatched = 6,
    /// The current thread blocked on this CPU.
    Blocked = 7,
    /// A blocked thread was woken with this CPU as the requester.
    Woken = 8,
    /// A fresh quantum was minted for this CPU's current execution.
    QuantumArmed = 9,
}

/// One CPU's mirrored identity. Every field is a diagnostic projection of state
/// owned elsewhere.
#[derive(Debug)]
struct PerCpuLiveness {
    /// Odd while a publication is in progress.
    sequence: AtomicU64,
    thread: AtomicU64,
    process: AtomicU64,
    root_key: AtomicU64,
    context_id: AtomicU64,
    stack_id: AtomicU64,
    event: AtomicU32,
    publications: AtomicU64,
    /// Scheduler-owned facts. Published separately from the carrier identity
    /// because the carrier does not hold them, and they are what turn "this
    /// thread is current" into "and here is why nothing else ran".
    execution_generation: AtomicU64,
    runnable_here: AtomicU32,
    queue_len: AtomicU32,
    reschedule_pending: AtomicU32,
    quantum_armed: AtomicU32,
    last_wake_target: AtomicU32,
}

impl PerCpuLiveness {
    const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            thread: AtomicU64::new(0),
            process: AtomicU64::new(0),
            root_key: AtomicU64::new(0),
            context_id: AtomicU64::new(0),
            stack_id: AtomicU64::new(0),
            event: AtomicU32::new(LivenessEvent::None as u32),
            publications: AtomicU64::new(0),
            execution_generation: AtomicU64::new(0),
            runnable_here: AtomicU32::new(0),
            queue_len: AtomicU32::new(0),
            reschedule_pending: AtomicU32::new(0),
            quantum_armed: AtomicU32::new(0),
            last_wake_target: AtomicU32::new(NO_CPU),
        }
    }
}

/// A consistent read of one CPU's mirrored identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuLivenessRecord {
    pub(crate) cpu: usize,
    pub(crate) thread: u64,
    pub(crate) process: u64,
    pub(crate) root_key: u64,
    pub(crate) context_id: u64,
    pub(crate) stack_id: u64,
    pub(crate) event: u32,
    pub(crate) publications: u64,
    pub(crate) execution_generation: u64,
    pub(crate) runnable_here: u32,
    pub(crate) queue_len: u32,
    pub(crate) reschedule_pending: bool,
    pub(crate) quantum_armed: bool,
    /// Target CPU of the most recent wake this CPU requested, or [`NO_CPU`].
    pub(crate) last_wake_target: u32,
    /// False when the reader could not obtain a stable sequence, so the fields
    /// above may mix two publications. A report must say so rather than
    /// presenting them as observed state.
    pub(crate) consistent: bool,
}

#[derive(Debug)]
struct LivenessSnapshot {
    cpus: [PerCpuLiveness; CPU_CAPACITY],
    /// Address of the live `RuntimeAuthorityLock`, for host GDB. Null until the
    /// primordial path publishes it.
    runtime_authority: AtomicPtr<()>,
}

impl LivenessSnapshot {
    const fn new() -> Self {
        Self {
            cpus: [
                PerCpuLiveness::new(),
                PerCpuLiveness::new(),
                PerCpuLiveness::new(),
                PerCpuLiveness::new(),
            ],
            runtime_authority: AtomicPtr::new(core::ptr::null_mut()),
        }
    }
}

const _: () = assert!(
    CPU_CAPACITY == 4,
    "liveness mirror initializer must cover every CPU slot"
);

/// The one diagnostic mirror. Host GDB resolves this symbol directly; see
/// `tools/gdb/r1-liveness.gdb`.
static LIVENESS: LivenessSnapshot = LivenessSnapshot::new();

/// Records the address of the live runtime authority exactly once.
///
/// The carrier is currently pinned to the boot stack, so this is the only way a
/// debugger can locate the lock's ticket pair. Reset card R2D removes the
/// boot-stack lifetime; this publication remains valid wherever the authority
/// ends up living.
///
/// `authority` is the address of the pair's first word, **not** the lock's base.
/// The lock is `repr(Rust)` and the compiler puts its value first, so a reader
/// given the base address reads carrier bytes and calls them a ticket pair --
/// which is what card R1's run 10 did. The caller asserts that the two words are
/// adjacent, so one read covers both.
pub(crate) fn publish_runtime_authority(authority: *const ()) {
    publish_runtime_authority_on(&LIVENESS, authority);
}

fn publish_runtime_authority_on(snapshot: &LivenessSnapshot, authority: *const ()) {
    snapshot
        .runtime_authority
        .store(authority.cast_mut(), Ordering::Release);
}

/// Returns the published runtime-authority address, or null if the primordial
/// path has not reached its publication point yet.
pub(crate) fn runtime_authority() -> *const () {
    runtime_authority_on(&LIVENESS)
}

fn runtime_authority_on(snapshot: &LivenessSnapshot) -> *const () {
    snapshot
        .runtime_authority
        .load(Ordering::Acquire)
        .cast_const()
}

/// Mirrors one CPU's current identity.
///
/// Callers pass diagnostic projections of identities they already hold; this
/// function performs no lookups and acquires nothing, so it is safe to call
/// from inside any authority, including with interrupts disabled.
#[allow(clippy::too_many_arguments, reason = "one mirrored fact per parameter")]
pub(crate) fn publish_current(
    cpu: CpuIndex,
    thread: u64,
    process: u64,
    root_key: u64,
    context_id: u64,
    stack_id: u64,
    event: LivenessEvent,
) {
    publish_current_on(
        &LIVENESS, cpu, thread, process, root_key, context_id, stack_id, event,
    );
}

#[allow(clippy::too_many_arguments, reason = "one mirrored fact per parameter")]
fn publish_current_on(
    snapshot: &LivenessSnapshot,
    cpu: CpuIndex,
    thread: u64,
    process: u64,
    root_key: u64,
    context_id: u64,
    stack_id: u64,
    event: LivenessEvent,
) {
    let cell = &snapshot.cpus[cpu.index()];
    let start = cell.sequence.load(Ordering::Relaxed).wrapping_add(1);
    cell.sequence.store(start, Ordering::Relaxed);
    cell.thread.store(thread, Ordering::Relaxed);
    cell.process.store(process, Ordering::Relaxed);
    cell.root_key.store(root_key, Ordering::Relaxed);
    cell.context_id.store(context_id, Ordering::Relaxed);
    cell.stack_id.store(stack_id, Ordering::Relaxed);
    cell.event.store(event as u32, Ordering::Relaxed);
    cell.publications.fetch_add(1, Ordering::Relaxed);
    cell.sequence
        .store(start.wrapping_add(1), Ordering::Release);
}

/// Mirrors the scheduler-owned facts for one CPU.
///
/// Published from inside the scheduler authority, which already holds them, so
/// this performs no lookups and acquires nothing. These are the fields that
/// distinguish "the supervisor is Runnable behind a no-yield hog on its own
/// CPU" from "the supervisor is blocked and nothing woke it", which is most of
/// what reset card R1's gate asks a failing run to answer.
pub(crate) fn publish_scheduler(
    cpu: CpuIndex,
    execution_generation: u64,
    runnable_here: u32,
    queue_len: u32,
    reschedule_pending: bool,
    quantum_armed: bool,
    event: LivenessEvent,
) {
    publish_scheduler_on(
        &LIVENESS,
        cpu,
        execution_generation,
        runnable_here,
        queue_len,
        reschedule_pending,
        quantum_armed,
        event,
    );
}

#[allow(clippy::too_many_arguments, reason = "one mirrored fact per parameter")]
fn publish_scheduler_on(
    snapshot: &LivenessSnapshot,
    cpu: CpuIndex,
    execution_generation: u64,
    runnable_here: u32,
    queue_len: u32,
    reschedule_pending: bool,
    quantum_armed: bool,
    event: LivenessEvent,
) {
    let cell = &snapshot.cpus[cpu.index()];
    cell.execution_generation
        .store(execution_generation, Ordering::Relaxed);
    cell.runnable_here.store(runnable_here, Ordering::Relaxed);
    cell.queue_len.store(queue_len, Ordering::Relaxed);
    cell.reschedule_pending
        .store(u32::from(reschedule_pending), Ordering::Relaxed);
    cell.quantum_armed
        .store(u32::from(quantum_armed), Ordering::Relaxed);
    cell.event.store(event as u32, Ordering::Relaxed);
}

/// Records where a wake this CPU requested was actually placed.
///
/// A wake that lands back on a saturated CPU is the sticky-placement failure
/// mode; recording the target makes that visible without inferring it.
pub(crate) fn publish_wake_target(requester: CpuIndex, target: CpuIndex) {
    publish_wake_target_on(&LIVENESS, requester, target);
}

fn publish_wake_target_on(snapshot: &LivenessSnapshot, requester: CpuIndex, target: CpuIndex) {
    snapshot.cpus[requester.index()]
        .last_wake_target
        .store(target.index() as u32, Ordering::Relaxed);
    snapshot.cpus[requester.index()]
        .event
        .store(LivenessEvent::Woken as u32, Ordering::Relaxed);
}

/// Records a runtime event for one CPU without disturbing its mirrored
/// identity. Used on paths that change scheduling state but not the current
/// thread, so a stall can still be attributed to its last transition.
pub(crate) fn note_event(cpu: CpuIndex, event: LivenessEvent) {
    note_event_on(&LIVENESS, cpu, event);
}

fn note_event_on(snapshot: &LivenessSnapshot, cpu: CpuIndex, event: LivenessEvent) {
    snapshot.cpus[cpu.index()]
        .event
        .store(event as u32, Ordering::Relaxed);
}

/// Reads one CPU's mirrored identity, retrying a bounded number of times when a
/// publication is in flight.
pub(crate) fn read_cpu(cpu: CpuIndex) -> CpuLivenessRecord {
    read_cpu_on(&LIVENESS, cpu)
}

fn read_cpu_on(snapshot: &LivenessSnapshot, cpu: CpuIndex) -> CpuLivenessRecord {
    const ATTEMPTS: usize = 8;
    let cell = &snapshot.cpus[cpu.index()];
    for _ in 0..ATTEMPTS {
        let before = cell.sequence.load(Ordering::Acquire);
        if !before.is_multiple_of(2) {
            continue;
        }
        let record = CpuLivenessRecord {
            cpu: cpu.index(),
            thread: cell.thread.load(Ordering::Relaxed),
            process: cell.process.load(Ordering::Relaxed),
            root_key: cell.root_key.load(Ordering::Relaxed),
            context_id: cell.context_id.load(Ordering::Relaxed),
            stack_id: cell.stack_id.load(Ordering::Relaxed),
            event: cell.event.load(Ordering::Relaxed),
            publications: cell.publications.load(Ordering::Relaxed),
            execution_generation: cell.execution_generation.load(Ordering::Relaxed),
            runnable_here: cell.runnable_here.load(Ordering::Relaxed),
            queue_len: cell.queue_len.load(Ordering::Relaxed),
            reschedule_pending: cell.reschedule_pending.load(Ordering::Relaxed) != 0,
            quantum_armed: cell.quantum_armed.load(Ordering::Relaxed) != 0,
            last_wake_target: cell.last_wake_target.load(Ordering::Relaxed),
            consistent: true,
        };
        if cell.sequence.load(Ordering::Acquire) == before {
            return record;
        }
    }
    CpuLivenessRecord {
        cpu: cpu.index(),
        thread: cell.thread.load(Ordering::Relaxed),
        process: cell.process.load(Ordering::Relaxed),
        root_key: cell.root_key.load(Ordering::Relaxed),
        context_id: cell.context_id.load(Ordering::Relaxed),
        stack_id: cell.stack_id.load(Ordering::Relaxed),
        event: cell.event.load(Ordering::Relaxed),
        publications: cell.publications.load(Ordering::Relaxed),
        execution_generation: cell.execution_generation.load(Ordering::Relaxed),
        runnable_here: cell.runnable_here.load(Ordering::Relaxed),
        queue_len: cell.queue_len.load(Ordering::Relaxed),
        reschedule_pending: cell.reschedule_pending.load(Ordering::Relaxed) != 0,
        quantum_armed: cell.quantum_armed.load(Ordering::Relaxed) != 0,
        last_wake_target: cell.last_wake_target.load(Ordering::Relaxed),
        consistent: false,
    }
}

/// Upper bound on one formatted snapshot: one authority line plus one line per
/// CPU slot, every field fixed-width.
pub(crate) const SNAPSHOT_MAX_BYTES: usize = 96 + CPU_CAPACITY * 288;

struct Cursor<'a> {
    bytes: &'a mut [u8],
    written: usize,
    overflowed: bool,
}

impl Cursor<'_> {
    fn literal(&mut self, text: &str) {
        let source = text.as_bytes();
        if self.written + source.len() > self.bytes.len() {
            self.overflowed = true;
            return;
        }
        self.bytes[self.written..self.written + source.len()].copy_from_slice(source);
        self.written += source.len();
    }

    fn hex64(&mut self, value: u64) {
        const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
        if self.written + 16 > self.bytes.len() {
            self.overflowed = true;
            return;
        }
        for shift in (0..16).rev() {
            let nibble = ((value >> (shift * 4)) & 0xF) as usize;
            self.bytes[self.written] = DIGITS[nibble];
            self.written += 1;
        }
    }

    fn decimal(&mut self, value: u64) {
        let mut scratch = [0_u8; 20];
        let mut length = 0;
        let mut remaining = value;
        loop {
            scratch[length] = b'0' + (remaining % 10) as u8;
            length += 1;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        if self.written + length > self.bytes.len() {
            self.overflowed = true;
            return;
        }
        for index in (0..length).rev() {
            self.bytes[self.written] = scratch[index];
            self.written += 1;
        }
    }
}

/// Formats the complete lock-free snapshot into `buffer`, returning the byte
/// count, or `None` when the buffer is smaller than [`SNAPSHOT_MAX_BYTES`].
///
/// Nothing here acquires the runtime authority, the scheduler, or any other
/// lock: every field is read from the mirror or from one atomic. The authority
/// address is reported rather than dereferenced, so host GDB can read the
/// ticket pair and the carrier behind it with full type information while the
/// guest stays out of the stalled lock entirely.
pub(crate) fn format_snapshot(buffer: &mut [u8]) -> Option<usize> {
    format_snapshot_on(&LIVENESS, buffer)
}

fn format_snapshot_on(snapshot: &LivenessSnapshot, buffer: &mut [u8]) -> Option<usize> {
    if buffer.len() < SNAPSHOT_MAX_BYTES {
        return None;
    }
    let mut cursor = Cursor {
        bytes: buffer,
        written: 0,
        overflowed: false,
    };
    cursor.literal("DWLIVE1|authority=");
    cursor.hex64(runtime_authority_on(snapshot) as u64);
    cursor.literal("|cpus=");
    cursor.decimal(CPU_CAPACITY as u64);
    cursor.literal("\r\n");
    for index in 0..CPU_CAPACITY {
        let Some(cpu) = CpuIndex::new(index) else {
            continue;
        };
        let record = read_cpu_on(snapshot, cpu);
        cursor.literal("DWLIVE1|cpu=");
        cursor.decimal(record.cpu as u64);
        cursor.literal(if record.consistent {
            "|read=stable"
        } else {
            "|read=TORN"
        });
        cursor.literal("|thread=");
        cursor.hex64(record.thread);
        cursor.literal("|process=");
        cursor.hex64(record.process);
        cursor.literal("|root=");
        cursor.hex64(record.root_key);
        cursor.literal("|context=");
        cursor.hex64(record.context_id);
        cursor.literal("|stack=");
        cursor.hex64(record.stack_id);
        cursor.literal("|event=");
        cursor.decimal(u64::from(record.event));
        cursor.literal("|publications=");
        cursor.decimal(record.publications);
        cursor.literal("|exec_gen=");
        cursor.decimal(record.execution_generation);
        cursor.literal("|runnable_here=");
        cursor.decimal(u64::from(record.runnable_here));
        cursor.literal("|queue=");
        cursor.decimal(u64::from(record.queue_len));
        cursor.literal(if record.reschedule_pending {
            "|resched=1"
        } else {
            "|resched=0"
        });
        cursor.literal(if record.quantum_armed {
            "|quantum=1"
        } else {
            "|quantum=0"
        });
        cursor.literal("|wake_target=");
        if record.last_wake_target == NO_CPU {
            cursor.literal("none");
        } else {
            cursor.decimal(u64::from(record.last_wake_target));
        }
        cursor.literal("\r\n");
    }
    if cursor.overflowed {
        return None;
    }
    Some(cursor.written)
}

/// Emits one formatted snapshot through the test-support COM1 seam.
///
/// This is the guest half of the R1B timeout trigger. It is deliberately
/// lock-free with respect to the runtime authority so it still reports when
/// that authority is the thing that has stalled.
#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
pub(crate) fn emit_snapshot() -> Result<(), super::SerialError> {
    let mut buffer = [0_u8; SNAPSHOT_MAX_BYTES];
    let Some(length) = format_snapshot(&mut buffer) else {
        return Err(super::SerialError::Busy);
    };
    super::emit_early_raw_record(&buffer[..length])
}

#[cfg(test)]
mod tests;
