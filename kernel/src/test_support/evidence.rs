//! DW0-I1 SMP acceptance evidence, confined to the test-support build.
//!
//! CPUs reserve and publish fixed-size facts here; only the terminal reporter
//! serializes those facts to COM1.  Workers have no serial-port API. This module deliberately has no runtime
//! scenario hookup yet.

#![allow(
    dead_code,
    reason = "the target-only I1 hooks are intentionally unconnected until the runtime lane owns them"
)]

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

pub(crate) const I1_EVIDENCE_RECORD_LEN: usize = 85;
const MAX_EVENTS: usize = 64;
const SLOT_EMPTY: u8 = 0;
const SLOT_WRITING: u8 = 1;
const SLOT_READY: u8 = 2;
const STATE_COUNT_MASK: usize = 0xff;
const STATE_FAILURE: usize = 0x100;
const COLLECTING: usize = 0;
const CLOSING: usize = 1;
const FINALIZED: usize = 2;
const FAILURE_NONE: u8 = 0;
const FAILURE_OVERFLOW: u8 = 1;
const FAILURE_MALFORMED: u8 = 2;
const FAILURE_INVARIANT: u8 = 3;
const NONCE: u64 = parse_nonce(env!("DEEPWYRM_I1_EVIDENCE_NONCE"));

/// One of the host-validated DWEVID1 facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EvidenceKind {
    CpuOnline = 0x01,
    Cpl3Syscall = 0x02,
    ParentBlocked = 0x03,
    DescendantRunning = 0x04,
    RunningInvariant = 0x05,
    WakeSent = 0x06,
    WakeObserved = 0x07,
    ChildExit = 0x08,
    ChildCleanup = 0x09,
    TlbPublish = 0x0a,
    TlbAck = 0x0b,
    RendezvousAck = 0x0c,
    ReclaimAllowed = 0x0d,
}

/// Typed, pointer-free test evidence supplied by the later I1 runtime hooks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceEvent {
    kind: EvidenceKind,
    cpu: u8,
    token: u32,
    arg0: u32,
    arg1: u32,
}

impl EvidenceEvent {
    pub(crate) const fn cpu_online(cpu: u8, apic_id: u32) -> Self {
        Self {
            kind: EvidenceKind::CpuOnline,
            cpu,
            token: 0,
            arg0: apic_id,
            arg1: cpu as u32,
        }
    }

    pub(crate) const fn cpl3_syscall(
        cpu: u8,
        token: u32,
        syscall_class: u32,
        observed_count: u32,
    ) -> Self {
        Self {
            kind: EvidenceKind::Cpl3Syscall,
            cpu,
            token,
            arg0: syscall_class,
            arg1: observed_count,
        }
    }

    pub(crate) const fn parent_blocked(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::ParentBlocked,
            cpu,
            token,
            arg0: 0,
            arg1: 0,
        }
    }

    pub(crate) const fn descendant_running(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::DescendantRunning,
            cpu,
            token,
            arg0: 0,
            arg1: 0,
        }
    }

    pub(crate) const fn wake_sent(cpu: u8, token: u32, target_cpu: u8) -> Self {
        Self {
            kind: EvidenceKind::WakeSent,
            cpu,
            token,
            arg0: target_cpu as u32,
            arg1: 0,
        }
    }

    pub(crate) const fn wake_observed(cpu: u8, token: u32, source_cpu: u8) -> Self {
        Self {
            kind: EvidenceKind::WakeObserved,
            cpu,
            token,
            arg0: source_cpu as u32,
            arg1: 0,
        }
    }

    pub(crate) const fn child_exit(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::ChildExit,
            cpu,
            token,
            arg0: 0,
            arg1: 0,
        }
    }

    pub(crate) const fn child_cleanup(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::ChildCleanup,
            cpu,
            token,
            arg0: 0,
            arg1: 0,
        }
    }

    pub(crate) const fn tlb_publish(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::TlbPublish,
            cpu,
            token,
            arg0: 0x0000_000f,
            arg1: 0,
        }
    }

    pub(crate) const fn tlb_ack(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::TlbAck,
            cpu,
            token,
            arg0: 0x0000_000f,
            arg1: 0,
        }
    }

    pub(crate) const fn rendezvous_ack(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::RendezvousAck,
            cpu,
            token,
            arg0: 0x0000_000f,
            arg1: 0,
        }
    }

    pub(crate) const fn reclaim_allowed(cpu: u8, token: u32) -> Self {
        Self {
            kind: EvidenceKind::ReclaimAllowed,
            cpu,
            token,
            arg0: 0x0000_000f,
            arg1: 0x0000_000f,
        }
    }

    const fn running_invariant() -> Self {
        Self {
            kind: EvidenceKind::RunningInvariant,
            cpu: 0,
            token: 0,
            arg0: 0,
            arg1: 0,
        }
    }

    const fn valid(self) -> bool {
        if self.cpu > 3 {
            return false;
        }
        match self.kind {
            EvidenceKind::CpuOnline => self.token == 0 && self.arg1 == self.cpu as u32,
            EvidenceKind::RunningInvariant => {
                self.cpu == 0 && self.token == 0 && self.arg0 == 0 && self.arg1 == 0
            }
            EvidenceKind::Cpl3Syscall => self.token != 0,
            EvidenceKind::TlbPublish | EvidenceKind::TlbAck | EvidenceKind::RendezvousAck => {
                self.token != 0 && self.arg0 == 0x0000_000f && self.arg1 == 0
            }
            EvidenceKind::ReclaimAllowed => {
                self.token != 0 && self.arg0 == 0x0000_000f && self.arg1 == 0x0000_000f
            }
            EvidenceKind::WakeSent | EvidenceKind::WakeObserved => {
                self.token != 0 && self.arg0 <= 3 && self.arg1 == 0
            }
            EvidenceKind::ParentBlocked | EvidenceKind::DescendantRunning => {
                self.token != 0 && self.arg0 == 0 && self.arg1 == 0
            }
            _ => self.token != 0 && self.arg0 == 0 && self.arg1 == 0,
        }
    }
}

struct Slot {
    state: AtomicU8,
    kind: AtomicU8,
    cpu: AtomicU8,
    token: AtomicU32,
    arg0: AtomicU32,
    arg1: AtomicU32,
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(SLOT_EMPTY),
            kind: AtomicU8::new(0),
            cpu: AtomicU8::new(0),
            token: AtomicU32::new(0),
            arg0: AtomicU32::new(0),
            arg1: AtomicU32::new(0),
        }
    }
}

/// Terminal state reported by a failed collector flush.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceFlushError {
    NotFinalized,
    NotReady,
    Overflow,
    Malformed,
    Invariant,
    FinalizationClosed,
    ReporterClaimed,
    Transport,
}

/// Fixed, no-allocation DWEVID1 collector.  Each event field is atomic; no
/// shared mutable reference is manufactured while the four CPUs publish.
pub(crate) struct EvidenceCollector {
    state: AtomicUsize,
    reporter_claimed: AtomicU8,
    failure: AtomicU8,
    slots: [Slot; MAX_EVENTS],
}

impl EvidenceCollector {
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicUsize::new(pack_state(COLLECTING, 0)),
            reporter_claimed: AtomicU8::new(0),
            failure: AtomicU8::new(FAILURE_NONE),
            slots: [const { Slot::new() }; MAX_EVENTS],
        }
    }

    /// Record a scenario fact.  Calls after finalization or malformed facts
    /// latch terminal failure instead of silently changing the transcript.
    pub(crate) fn record(&self, event: EvidenceEvent) -> Result<(), EvidenceFlushError> {
        let sequence = self.reserve()?;
        if event.kind == EvidenceKind::RunningInvariant || !event.valid() {
            self.abort(sequence);
            return Err(EvidenceFlushError::Malformed);
        }
        self.publish(sequence, event);
        Ok(())
    }

    /// Seal collection and append the sole `RUNNING_INVARIANT` record.  This
    /// is the only API that can create that final evidence event.
    pub(crate) fn finalize_running_invariant(
        &self,
    ) -> Result<FinalizedEvidence<'_>, EvidenceFlushError> {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state_phase(state) != COLLECTING {
                return Err(EvidenceFlushError::FinalizationClosed);
            }
            let count = state_count(state);
            if self
                .state
                .compare_exchange(
                    state,
                    pack_state(CLOSING, count) | (state & STATE_FAILURE),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.publish(count, EvidenceEvent::running_invariant());
                self.state.store(
                    pack_state(FINALIZED, count + 1) | (state & STATE_FAILURE),
                    Ordering::Release,
                );
                return Ok(FinalizedEvidence { collector: self });
            }
        }
    }

    fn reserve(&self) -> Result<usize, EvidenceFlushError> {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state_phase(state) != COLLECTING {
                return Err(EvidenceFlushError::FinalizationClosed);
            }
            if state_has_failure(state) {
                return Err(EvidenceFlushError::Overflow);
            }
            let current = state_count(state);
            // Preserve the last fixed slot for finalization's invariant record.
            if current >= MAX_EVENTS - 1 {
                if self
                    .state
                    .compare_exchange_weak(
                        state,
                        state | STATE_FAILURE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Err(EvidenceFlushError::Overflow);
                }
                continue;
            }
            if self
                .state
                .compare_exchange_weak(
                    state,
                    pack_state(COLLECTING, current + 1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Ok(current);
            }
        }
    }

    fn publish(&self, sequence: usize, event: EvidenceEvent) {
        let slot = &self.slots[sequence];
        if slot
            .state
            .compare_exchange(
                SLOT_EMPTY,
                SLOT_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.latch(FAILURE_INVARIANT);
            return;
        }
        slot.kind.store(event.kind as u8, Ordering::Relaxed);
        slot.cpu.store(event.cpu, Ordering::Relaxed);
        slot.token.store(event.token, Ordering::Relaxed);
        slot.arg0.store(event.arg0, Ordering::Relaxed);
        slot.arg1.store(event.arg1, Ordering::Relaxed);
        slot.state.store(SLOT_READY, Ordering::Release);
    }

    fn abort(&self, sequence: usize) {
        let slot = &self.slots[sequence];
        if slot
            .state
            .compare_exchange(
                SLOT_EMPTY,
                SLOT_ABORTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.latch(FAILURE_INVARIANT);
        }
    }

    #[cfg(test)]
    fn reserve_paused_for_test(&self, event: EvidenceEvent) -> Result<usize, EvidenceFlushError> {
        let sequence = self.reserve()?;
        let slot = &self.slots[sequence];
        slot.state
            .compare_exchange(
                SLOT_EMPTY,
                SLOT_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| EvidenceFlushError::Invariant)?;
        slot.kind.store(event.kind as u8, Ordering::Relaxed);
        slot.cpu.store(event.cpu, Ordering::Relaxed);
        slot.token.store(event.token, Ordering::Relaxed);
        slot.arg0.store(event.arg0, Ordering::Relaxed);
        slot.arg1.store(event.arg1, Ordering::Relaxed);
        Ok(sequence)
    }

    #[cfg(test)]
    fn publish_paused_for_test(&self, sequence: usize) {
        self.slots[sequence]
            .state
            .store(SLOT_READY, Ordering::Release);
    }

    fn latch(&self, failure: u8) {
        let _ = self.failure.compare_exchange(
            FAILURE_NONE,
            failure,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    fn failure_result(&self) -> Result<(), EvidenceFlushError> {
        match self.failure.load(Ordering::Acquire) {
            FAILURE_NONE => Ok(()),
            FAILURE_OVERFLOW => Err(EvidenceFlushError::Overflow),
            FAILURE_MALFORMED => Err(EvidenceFlushError::Malformed),
            _ => Err(EvidenceFlushError::Invariant),
        }
    }

    fn semantic_valid(&self, count: usize) -> bool {
        if !(5..=MAX_EVENTS).contains(&count) {
            return false;
        }
        for later in 0..count {
            let event = self.read(later);
            for earlier in 0..later {
                if self.read(earlier) == event {
                    return false;
                }
            }
        }
        let mut online_cpus = 0_u8;
        let mut apic_ids = [0_u32; 4];
        for index in 0..4 {
            let event = self.read(index);
            if event.kind != EvidenceKind::CpuOnline
                || event.cpu > 3
                || online_cpus & (1 << event.cpu) != 0
            {
                return false;
            }
            for prior in &apic_ids[..index] {
                if *prior == event.arg0 {
                    return false;
                }
            }
            online_cpus |= 1 << event.cpu;
            apic_ids[index] = event.arg0;
        }
        if online_cpus != 0x0f || self.read(count - 1) != EvidenceEvent::running_invariant() {
            return false;
        }
        let facts = &self.slots[4..count - 1];
        let mut cpl3_cpus = 0_u8;
        let mut cpl3_tokens = [0_u32; MAX_EVENTS];
        let mut cpl3_count = 0;
        let mut parent = None;
        let mut descendant_running = false;
        let mut wake = None;
        let mut wake_observed = false;
        let mut child_exit = None;
        let mut child_cleanup = false;
        let mut tlb = None;
        let mut tlb_acks = 0_u8;
        let mut rendezvous_acks = 0_u8;
        let mut reclaim_allowed = false;
        for (relative, slot) in facts.iter().enumerate() {
            let event = read_slot(slot);
            match event.kind {
                EvidenceKind::CpuOnline | EvidenceKind::RunningInvariant => return false,
                EvidenceKind::Cpl3Syscall => {
                    cpl3_cpus |= 1 << event.cpu;
                    if !cpl3_tokens[..cpl3_count].contains(&event.token) {
                        cpl3_tokens[cpl3_count] = event.token;
                        cpl3_count += 1;
                    }
                }
                EvidenceKind::ParentBlocked => {
                    if parent.is_some() {
                        return false;
                    }
                    parent = Some((relative, event));
                }
                EvidenceKind::DescendantRunning => {
                    if descendant_running {
                        return false;
                    }
                    if !matches!(parent, Some((before, parent_event)) if before < relative && parent_event.token == event.token && parent_event.cpu != event.cpu)
                    {
                        return false;
                    }
                    descendant_running = true;
                }
                EvidenceKind::WakeSent => {
                    if wake.is_some() {
                        return false;
                    }
                    wake = Some((relative, event));
                }
                EvidenceKind::WakeObserved => {
                    if wake_observed {
                        return false;
                    }
                    if !matches!(wake, Some((before, sent)) if before < relative && sent.token == event.token && sent.cpu != event.cpu && sent.arg0 == event.cpu as u32 && event.arg0 == sent.cpu as u32)
                    {
                        return false;
                    }
                    wake_observed = true;
                }
                EvidenceKind::ChildExit => {
                    if child_exit.is_some() {
                        return false;
                    }
                    child_exit = Some((relative, event));
                }
                EvidenceKind::ChildCleanup => {
                    if child_cleanup {
                        return false;
                    }
                    if !matches!(child_exit, Some((before, exited)) if before < relative && exited.token == event.token && exited.cpu != event.cpu)
                    {
                        return false;
                    }
                    child_cleanup = true;
                }
                EvidenceKind::TlbPublish => {
                    if tlb.is_some() {
                        return false;
                    }
                    tlb = Some((relative, event));
                }
                EvidenceKind::TlbAck => {
                    if !matches!(tlb, Some((before, published)) if before < relative && published.token == event.token)
                        || tlb_acks & (1 << event.cpu) != 0
                    {
                        return false;
                    } else {
                        tlb_acks |= 1 << event.cpu;
                    }
                }
                EvidenceKind::RendezvousAck => {
                    if !matches!(tlb, Some((before, published)) if before < relative && published.token == event.token)
                        || rendezvous_acks & (1 << event.cpu) != 0
                    {
                        return false;
                    } else {
                        rendezvous_acks |= 1 << event.cpu;
                    }
                }
                EvidenceKind::ReclaimAllowed => {
                    if reclaim_allowed {
                        return false;
                    }
                    if !matches!(tlb, Some((before, published)) if before < relative && published.token == event.token)
                        || tlb_acks != 0x0f
                        || rendezvous_acks != 0x0f
                    {
                        return false;
                    }
                    reclaim_allowed = true;
                }
            }
        }
        cpl3_cpus.count_ones() >= 2
            && cpl3_count >= 2
            && parent.is_some()
            && descendant_running
            && wake.is_some()
            && wake_observed
            && child_exit.is_some()
            && child_cleanup
            && tlb.is_some()
            && tlb_acks == 0x0f
            && rendezvous_acks == 0x0f
            && reclaim_allowed
    }

    fn read(&self, index: usize) -> EvidenceEvent {
        read_slot(&self.slots[index])
    }
}

/// Move-only authorization for the one designated evidence reporter. Its
/// consuming flush claim prevents competing terminal paths from interleaving
/// DWEVID1 and DWTEST1 over COM1.
#[must_use]
pub(crate) struct FinalizedEvidence<'a> {
    collector: &'a EvidenceCollector,
}

impl FinalizedEvidence<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; I1_EVIDENCE_RECORD_LEN]) -> Result<(), EvidenceFlushError>,
    ) -> Result<(), EvidenceFlushError> {
        let collector = self.collector;
        if collector
            .reporter_claimed
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(EvidenceFlushError::ReporterClaimed);
        }
        let state = collector.state.load(Ordering::Acquire);
        if state_phase(state) != FINALIZED {
            return Err(EvidenceFlushError::NotFinalized);
        }
        let count = state_count(state);
        for sequence in 0..count {
            let mut spins = 0;
            while matches!(
                collector.slots[sequence].state.load(Ordering::Acquire),
                SLOT_EMPTY | SLOT_WRITING
            ) {
                if spins == MAX_PUBLICATION_SPINS {
                    return Err(EvidenceFlushError::NotReady);
                }
                spins += 1;
                core::hint::spin_loop();
            }
            match collector.slots[sequence].state.load(Ordering::Acquire) {
                SLOT_READY => {}
                SLOT_ABORTED => return Err(EvidenceFlushError::Malformed),
                SLOT_EMPTY | SLOT_WRITING => return Err(EvidenceFlushError::NotReady),
                _ => return Err(EvidenceFlushError::Invariant),
            }
        }
        if state_has_failure(state) {
            return Err(EvidenceFlushError::Overflow);
        }
        if !collector.semantic_valid(count) {
            collector.latch(FAILURE_INVARIANT);
            return Err(EvidenceFlushError::Invariant);
        }
        for sequence in 0..count {
            emit(&encode(sequence as u32, &collector.slots[sequence]))?;
        }
        Ok(())
    }
}

const MAX_PUBLICATION_SPINS: usize = 4096;
const SLOT_ABORTED: u8 = 3;
const fn pack_state(phase: usize, count: usize) -> usize {
    (phase << 9) | count
}
const fn state_phase(state: usize) -> usize {
    state >> 9
}
const fn state_count(state: usize) -> usize {
    state & STATE_COUNT_MASK
}
const fn state_has_failure(state: usize) -> bool {
    state & STATE_FAILURE != 0
}

/// The one build-selected collector; no public ABI or production state uses it.
pub(crate) static I1_EVIDENCE: EvidenceCollector = EvidenceCollector::new();

fn encode(sequence: u32, slot: &Slot) -> [u8; I1_EVIDENCE_RECORD_LEN] {
    let mut record = [0_u8; I1_EVIDENCE_RECORD_LEN];
    record[..7].copy_from_slice(b"DWEVID1");
    record[7] = b'|';
    record[8..10].copy_from_slice(b"01");
    record[10] = b'|';
    encode_hex_u64(NONCE, &mut record[11..27]);
    record[27] = b'|';
    encode_hex(sequence, &mut record[28..36]);
    record[36] = b'|';
    encode_hex(
        u32::from(slot.kind.load(Ordering::Relaxed)),
        &mut record[37..39],
    );
    record[39] = b'|';
    encode_hex(
        u32::from(slot.cpu.load(Ordering::Relaxed)),
        &mut record[40..48],
    );
    record[48] = b'|';
    encode_hex(slot.token.load(Ordering::Relaxed), &mut record[49..57]);
    record[57] = b'|';
    encode_hex(slot.arg0.load(Ordering::Relaxed), &mut record[58..66]);
    record[66] = b'|';
    encode_hex(slot.arg1.load(Ordering::Relaxed), &mut record[67..75]);
    record[75] = b'|';
    encode_hex(fnv1a32(&record[..76]), &mut record[76..84]);
    record[84] = b'\n';
    record
}

fn read_slot(slot: &Slot) -> EvidenceEvent {
    EvidenceEvent {
        kind: EvidenceKind::from_wire(slot.kind.load(Ordering::Relaxed))
            .expect("published evidence kind"),
        cpu: slot.cpu.load(Ordering::Relaxed),
        token: slot.token.load(Ordering::Relaxed),
        arg0: slot.arg0.load(Ordering::Relaxed),
        arg1: slot.arg1.load(Ordering::Relaxed),
    }
}

impl EvidenceKind {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::CpuOnline),
            2 => Some(Self::Cpl3Syscall),
            3 => Some(Self::ParentBlocked),
            4 => Some(Self::DescendantRunning),
            5 => Some(Self::RunningInvariant),
            6 => Some(Self::WakeSent),
            7 => Some(Self::WakeObserved),
            8 => Some(Self::ChildExit),
            9 => Some(Self::ChildCleanup),
            10 => Some(Self::TlbPublish),
            11 => Some(Self::TlbAck),
            12 => Some(Self::RendezvousAck),
            13 => Some(Self::ReclaimAllowed),
            _ => None,
        }
    }
}

fn encode_hex(value: u32, output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let width = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = HEX[((value >> ((width - index - 1) * 4)) & 15) as usize];
    }
}
fn encode_hex_u64(value: u64, output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let width = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = HEX[((value >> ((width - index - 1) * 4)) & 15) as usize];
    }
}
fn fnv1a32(input: &[u8]) -> u32 {
    input.iter().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}
const fn parse_nonce(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 16);
    let mut index = 0;
    let mut result = 0_u64;
    while index < 16 {
        let byte = bytes[index];
        let digit = if byte >= b'0' && byte <= b'9' {
            byte - b'0'
        } else if byte >= b'A' && byte <= b'F' {
            byte - b'A' + 10
        } else {
            panic!("I1 nonce must be uppercase hex")
        };
        result = (result << 4) | digit as u64;
        index += 1;
    }
    assert!(result != 0);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    fn decode_hex(input: &[u8]) -> Option<u32> {
        input.iter().try_fold(0_u32, |value, byte| {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return None,
            };
            value.checked_mul(16)?.checked_add(u32::from(digit))
        })
    }
    fn parse(record: &[u8]) -> bool {
        record.len() == 85
            && &record[..7] == b"DWEVID1"
            && record[7] == b'|'
            && record[10] == b'|'
            && record[27] == b'|'
            && record[36] == b'|'
            && record[39] == b'|'
            && record[48] == b'|'
            && record[57] == b'|'
            && record[66] == b'|'
            && record[75] == b'|'
            && record[84] == b'\n'
            && decode_hex(&record[76..84]) == Some(fnv1a32(&record[..76]))
    }
    fn complete_contract(collector: &EvidenceCollector) -> FinalizedEvidence<'_> {
        for cpu in 0..4 {
            collector
                .record(EvidenceEvent::cpu_online(cpu, 0x20 + u32::from(cpu)))
                .unwrap();
        }
        collector
            .record(EvidenceEvent::cpl3_syscall(0, 1, 1, 1))
            .unwrap();
        collector
            .record(EvidenceEvent::cpl3_syscall(1, 2, 1, 1))
            .unwrap();
        collector
            .record(EvidenceEvent::parent_blocked(0, 3))
            .unwrap();
        collector
            .record(EvidenceEvent::descendant_running(1, 3))
            .unwrap();
        collector.record(EvidenceEvent::wake_sent(1, 4, 2)).unwrap();
        collector
            .record(EvidenceEvent::wake_observed(2, 4, 1))
            .unwrap();
        collector.record(EvidenceEvent::child_exit(2, 5)).unwrap();
        collector
            .record(EvidenceEvent::child_cleanup(3, 5))
            .unwrap();
        collector.record(EvidenceEvent::tlb_publish(0, 6)).unwrap();
        for cpu in 0..4 {
            collector.record(EvidenceEvent::tlb_ack(cpu, 6)).unwrap();
        }
        for cpu in 0..4 {
            collector
                .record(EvidenceEvent::rendezvous_ack(cpu, 6))
                .unwrap();
        }
        collector
            .record(EvidenceEvent::reclaim_allowed(0, 6))
            .unwrap();
        collector.finalize_running_invariant().unwrap()
    }
    #[test]
    fn encoding_round_trips_exactly() {
        let collector = EvidenceCollector::new();
        let permit = complete_contract(&collector);
        let mut records = [[0; 85]; 32];
        let mut count = 0;
        permit
            .flush(|record| {
                records[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 23);
        assert!(records[..count].iter().all(|record| parse(record)));
        assert_eq!(&records[0][8..10], b"01");
        assert_eq!(&records[count - 1][37..39], b"05");
    }
    #[test]
    fn checksum_case_and_bounds_fail_closed() {
        let collector = EvidenceCollector::new();
        assert_eq!(
            collector.record(EvidenceEvent::wake_sent(4, 1, 0)),
            Err(EvidenceFlushError::Malformed)
        );
        let permit = collector.finalize_running_invariant().unwrap();
        assert_eq!(permit.flush(|_| Ok(())), Err(EvidenceFlushError::Malformed));
        let collector = EvidenceCollector::new();
        for index in 0..MAX_EVENTS - 1 {
            collector
                .record(EvidenceEvent::cpu_online((index % 4) as u8, index as u32))
                .unwrap();
        }
        assert_eq!(
            collector.record(EvidenceEvent::cpu_online(0, 99)),
            Err(EvidenceFlushError::Overflow)
        );
    }
    #[test]
    fn concurrent_reservations_publish_without_shared_mutation() {
        let collector = Arc::new(EvidenceCollector::new());
        for cpu in 0..4 {
            collector
                .record(EvidenceEvent::cpu_online(cpu, 0x20 + u32::from(cpu)))
                .unwrap();
        }
        let mut joins = Vec::new();
        for cpu in 0..4 {
            let collector = Arc::clone(&collector);
            joins.push(thread::spawn(move || {
                for token in 1..=8 {
                    collector
                        .record(EvidenceEvent::cpl3_syscall(cpu, token + 10, 1, 1))
                        .unwrap();
                }
            }));
        }
        for join in joins {
            join.join().unwrap();
        }
        let _permit = collector.finalize_running_invariant().unwrap();
    }
    #[test]
    fn only_finalization_emits_final_event() {
        let collector = EvidenceCollector::new();
        assert_eq!(
            collector.record(EvidenceEvent::running_invariant()),
            Err(EvidenceFlushError::Malformed)
        );
    }

    #[test]
    fn finalization_linearizes_a_paused_reservation_and_blocks_new_producers() {
        let collector = EvidenceCollector::new();
        let paused = collector
            .reserve_paused_for_test(EvidenceEvent::cpu_online(0, 0x20))
            .unwrap();
        assert_eq!(paused, 0);
        let permit = collector.finalize_running_invariant().unwrap();
        assert_eq!(collector.read(1), EvidenceEvent::running_invariant());
        assert!(matches!(
            collector.record(EvidenceEvent::cpu_online(1, 0x21)),
            Err(EvidenceFlushError::FinalizationClosed)
        ));
        collector.publish_paused_for_test(paused);
        assert_eq!(permit.flush(|_| Ok(())), Err(EvidenceFlushError::Invariant));
    }

    #[test]
    fn duplicate_finalization_and_reporter_claim_fail_closed() {
        let collector = EvidenceCollector::new();
        complete_contract_without_final(&collector);
        let permit = collector.finalize_running_invariant().unwrap();
        assert!(matches!(
            collector.finalize_running_invariant(),
            Err(EvidenceFlushError::FinalizationClosed)
        ));
        collector.reporter_claimed.store(1, Ordering::Release);
        assert_eq!(
            permit.flush(|_| Ok(())),
            Err(EvidenceFlushError::ReporterClaimed)
        );
    }

    #[test]
    fn transport_failure_and_duplicate_semantic_fact_never_flush() {
        let collector = EvidenceCollector::new();
        let permit = complete_contract(&collector);
        assert_eq!(
            permit.flush(|_| Err(EvidenceFlushError::Transport)),
            Err(EvidenceFlushError::Transport)
        );

        let collector = EvidenceCollector::new();
        complete_contract_without_final(&collector);
        collector
            .record(EvidenceEvent::parent_blocked(2, 7))
            .unwrap();
        let permit = collector.finalize_running_invariant().unwrap();
        assert_eq!(permit.flush(|_| Ok(())), Err(EvidenceFlushError::Invariant));
    }

    #[test]
    fn failure_reserved_before_close_is_in_the_final_terminal_decision() {
        let collector = EvidenceCollector::new();
        let sequence = collector.reserve().unwrap();
        let permit = collector.finalize_running_invariant().unwrap();
        collector.abort(sequence);
        assert_eq!(permit.flush(|_| Ok(())), Err(EvidenceFlushError::Malformed));
    }

    #[test]
    fn abandoned_inflight_writer_fails_boundedly_instead_of_spinning_forever() {
        let collector = EvidenceCollector::new();
        let _sequence = collector
            .reserve_paused_for_test(EvidenceEvent::cpu_online(0, 0x20))
            .unwrap();
        let permit = collector.finalize_running_invariant().unwrap();
        assert_eq!(permit.flush(|_| Ok(())), Err(EvidenceFlushError::NotReady));
    }

    #[test]
    fn pause_after_reserve_before_writing_fails_without_panicking_or_hanging() {
        let collector = EvidenceCollector::new();
        let sequence = collector.reserve().unwrap();
        assert_eq!(
            collector.slots[sequence].state.load(Ordering::Acquire),
            SLOT_EMPTY
        );
        let permit = collector.finalize_running_invariant().unwrap();
        assert_eq!(permit.flush(|_| Ok(())), Err(EvidenceFlushError::NotReady));
    }

    #[test]
    fn publication_crossing_reporter_wait_is_observed_before_snapshot() {
        let collector = EvidenceCollector::new();
        let sequence = collector
            .reserve_paused_for_test(EvidenceEvent::cpu_online(0, 0x20))
            .unwrap();
        let permit = collector.finalize_running_invariant().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| collector.publish_paused_for_test(sequence));
            assert_eq!(permit.flush(|_| Ok(())), Err(EvidenceFlushError::Invariant));
        });
    }

    fn complete_contract_without_final(collector: &EvidenceCollector) {
        for cpu in 0..4 {
            collector
                .record(EvidenceEvent::cpu_online(cpu, 0x20 + u32::from(cpu)))
                .unwrap();
        }
        collector
            .record(EvidenceEvent::cpl3_syscall(0, 1, 1, 1))
            .unwrap();
        collector
            .record(EvidenceEvent::cpl3_syscall(1, 2, 1, 1))
            .unwrap();
        collector
            .record(EvidenceEvent::parent_blocked(0, 3))
            .unwrap();
        collector
            .record(EvidenceEvent::descendant_running(1, 3))
            .unwrap();
        collector.record(EvidenceEvent::wake_sent(1, 4, 2)).unwrap();
        collector
            .record(EvidenceEvent::wake_observed(2, 4, 1))
            .unwrap();
        collector.record(EvidenceEvent::child_exit(2, 5)).unwrap();
        collector
            .record(EvidenceEvent::child_cleanup(3, 5))
            .unwrap();
        collector.record(EvidenceEvent::tlb_publish(0, 6)).unwrap();
        for cpu in 0..4 {
            collector.record(EvidenceEvent::tlb_ack(cpu, 6)).unwrap();
        }
        for cpu in 0..4 {
            collector
                .record(EvidenceEvent::rendezvous_ack(cpu, 6))
                .unwrap();
        }
        collector
            .record(EvidenceEvent::reclaim_allowed(0, 6))
            .unwrap();
    }
}
