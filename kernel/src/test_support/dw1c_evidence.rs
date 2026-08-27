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
pub(crate) const DW1C_PROGRESS_MASK: u8 = 0x1f;
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
    actors: [Option<Dw1cActor>; DW1C_ACTOR_COUNT],
    progress: [u64; 5],
    facts: Dw1cKernelFacts,
    terminal: bool,
    failure: Option<Dw1cEvidenceError>,
}

impl State {
    const fn new() -> Self {
        Self {
            installed: false,
            reporter: None,
            actors: [None; DW1C_ACTOR_COUNT],
            progress: [0; 5],
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
        state.reporter = Some(reporter);
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
        self.observe_cpu_actor(cpu, process, thread, generation, 0)
    }

    pub(crate) fn observe_quantum_expiry(
        &self,
        cpu: u8,
        process: ProcessKey,
        thread: ThreadKey,
        generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_actor(cpu, process, thread, generation, 1)
    }

    pub(crate) fn observe_preemption(
        &self,
        cpu: u8,
        process: ProcessKey,
        thread: ThreadKey,
        generation: u64,
    ) -> Result<(), Dw1cEvidenceError> {
        self.observe_cpu_actor(cpu, process, thread, generation, 2)
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

    fn observe_cpu_actor(
        &self,
        cpu: u8,
        process: ProcessKey,
        thread: ThreadKey,
        generation: u64,
        kind: u8,
    ) -> Result<(), Dw1cEvidenceError> {
        let mut state = self.state.lock();
        let bit = cpu_bit(cpu).ok_or_else(|| state.latch(Dw1cEvidenceError::Malformed))?;
        if !state.installed || !actor_bound(&state, process, thread, generation) {
            return Err(state.latch(Dw1cEvidenceError::WrongGeneration));
        }
        let destination = match kind {
            0 => &mut state.facts.run,
            1 => &mut state.facts.quantum,
            _ => &mut state.facts.preempt,
        };
        if *destination & bit != 0 {
            return Err(state.latch(Dw1cEvidenceError::Duplicate));
        }
        *destination |= bit;
        Ok(())
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
        if count == 0 || state.progress[index] != 0 {
            return Err(state.latch(Dw1cEvidenceError::Malformed));
        }
        state.progress[index] = count;
        Ok(())
    }

    pub(crate) fn complete(
        &self,
        caller: ProcessKey,
        mask: u64,
        digest: u64,
    ) -> Result<Dw1cEvidenceFlushPermit<'_>, Dw1cEvidenceError> {
        let mut state = self.state.lock();
        if state.reporter.map(|reporter| reporter.0) != Some(caller) {
            return Err(state.latch(Dw1cEvidenceError::WrongReporter));
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
        if !state.terminal || !state.facts.complete() {
            return Err(Dw1cEvidenceError::Incomplete);
        }
        let mut write = write;
        for sequence in 0..DW1C_EVIDENCE_RECORD_CAPACITY {
            let record = encode_record(self.nonce, sequence as u32, event_for(sequence));
            write(&record).map_err(|_| Dw1cEvidenceError::Full)?;
        }
        Ok(())
    }
}

fn cpu_bit(cpu: u8) -> Option<u8> {
    (cpu < 4).then(|| 1_u8 << cpu)
}
fn actor_bound(state: &State, process: ProcessKey, thread: ThreadKey, generation: u64) -> bool {
    generation != 0
        && state.actors.iter().flatten().any(|actor| {
            actor.process == process
                && actor.thread == thread
                && actor.execution_generation == generation
        })
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

fn encode_record(nonce: u64, sequence: u32, event: u8) -> [u8; DW1C_EVIDENCE_RECORD_LEN] {
    let mut out = [b'0'; DW1C_EVIDENCE_RECORD_LEN];
    out[..8].copy_from_slice(b"DW1C|01|");
    put_hex(&mut out[8..24], nonce);
    out[24] = b'|';
    put_hex(&mut out[25..33], u64::from(sequence));
    out[33] = b'|';
    put_hex(&mut out[34..36], u64::from(event));
    out[36] = b'|';
    put_hex(&mut out[37..53], 0);
    out[53] = b'|';
    put_hex(&mut out[54..70], 1);
    out[70] = b'|';
    put_hex(&mut out[71..87], 0);
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
    #[test]
    fn fixed_stream_is_46_records_of_96_bytes() {
        let a = encode_record(1, 45, TERMINAL_EVENT);
        assert_eq!(a.len(), 96);
        assert_eq!(&a[..8], b"DW1C|01|");
        assert_eq!(event_for(45), TERMINAL_EVENT);
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
}
