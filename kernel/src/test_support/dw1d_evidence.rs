//! Selector-30-only DeviceResource/Interrupt lifecycle evidence.
//!
//! The raw authority protocol and `DWD6E1` records are test-product internals.
//! Public claim, PIO, Interrupt, wait, acknowledgement, finalization, and task
//! teardown mechanisms remain the sole source of lifecycle facts.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only collector")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use deepwyrm_abi::{DW_SIGNAL_SIGNALED, DW_STATUS_BAD_STATE};

use crate::device::InterruptBinding;
use crate::object::ObjectId;
use crate::sync::SpinMutex;
use crate::task::ProcessKey;

pub(crate) const DW1D_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1d;
pub(crate) const DW1D_EVIDENCE_RECORD_LEN: usize = 117;
pub(crate) const DW1D_EVIDENCE_RECORD_COUNT: usize = 40;

const ACTOR_KERNEL: u8 = 0;
const ACTOR_CONTROLLER: u8 = 1;
const ACTOR_FIRST_OWNER: u8 = 2;
const ACTOR_TRIGGER: u8 = 3;
const ACTOR_REPLACEMENT_OWNER: u8 = 4;

const EVENT_BOOT: u8 = 0x01;
const EVENT_ARM: u8 = 0x02;
const EVENT_DENIED: u8 = 0x03;
const EVENT_FIRST_CLAIM: u8 = 0x04;
const EVENT_PIO_SAVE: u8 = 0x05;
const EVENT_PIO_WRITE: u8 = 0x06;
const EVENT_PIO_READ: u8 = 0x07;
const EVENT_PIO_RESTORE: u8 = 0x08;
const EVENT_FIRST_BIND: u8 = 0x09;
const EVENT_WAIT_BLOCKED: u8 = 0x0a;
const EVENT_DELIVERED: u8 = 0x0b;
const EVENT_WAIT_WOKE: u8 = 0x0c;
const EVENT_ACKED: u8 = 0x0d;
const EVENT_ACK_RACE: u8 = 0x0e;
const EVENT_FIRST_INTERRUPT_FINAL: u8 = 0x0f;
const EVENT_FIRST_GRANT_RETURN: u8 = 0x10;
const EVENT_STALE_REJECTED: u8 = 0x11;
const EVENT_REPLACEMENT_CLAIM: u8 = 0x12;
const EVENT_REPLACEMENT_BIND: u8 = 0x13;
const EVENT_REPLACEMENT_INTERRUPT_FINAL: u8 = 0x14;
const EVENT_REPLACEMENT_REAP: u8 = 0x15;
const EVENT_ACCOUNTING: u8 = 0x16;
const EVENT_READY: u8 = 0x17;
const EVENT_TERMINAL: u8 = 0xff;

const EXPECTED_RESOURCE_ID: u64 = 1;
const EXPECTED_PIO_BASE: u16 = 0x02f8;
const EXPECTED_PIO_LENGTH: u16 = 8;
const EXPECTED_INTERRUPT_SOURCE: u32 = 3;
const EXPECTED_ACCOUNTING_MASK: u8 = 0x3f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1dRawOperation {
    Arm {
        owner_handle: u64,
        trigger_handle: u64,
    },
    Bind {
        interrupt_handle: u64,
        lease_generation: u64,
    },
    Deliver {
        sequence: u64,
    },
    Report {
        event: u8,
        value: u64,
        auxiliary: u64,
    },
}

impl Dw1dRawOperation {
    fn decode(values: [u64; 6], nonce: u64, challenge: u64) -> Result<Self, Dw1dEvidenceError> {
        match values {
            [
                1,
                owner_handle,
                trigger_handle,
                supplied_nonce,
                supplied_challenge,
                0,
            ] if supplied_nonce == nonce && supplied_challenge == challenge => Ok(Self::Arm {
                owner_handle,
                trigger_handle,
            }),
            [
                2,
                interrupt_handle,
                lease_generation,
                supplied_nonce,
                supplied_challenge,
                0,
            ] if lease_generation != 0
                && supplied_nonce == nonce
                && supplied_challenge == challenge =>
            {
                Ok(Self::Bind {
                    interrupt_handle,
                    lease_generation,
                })
            }
            [3, sequence, supplied_nonce, supplied_challenge, 0, 0]
                if sequence != 0 && supplied_nonce == nonce && supplied_challenge == challenge =>
            {
                Ok(Self::Deliver { sequence })
            }
            [
                4,
                event,
                value,
                auxiliary,
                supplied_nonce,
                supplied_challenge,
            ] if event <= u64::from(u8::MAX)
                && supplied_nonce == nonce
                && supplied_challenge == challenge =>
            {
                Ok(Self::Report {
                    event: event as u8,
                    value,
                    auxiliary,
                })
            }
            _ => Err(Dw1dEvidenceError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1dEvidenceError {
    Malformed,
    Early,
    OutOfOrder,
    WrongActor,
    WrongIdentity,
    WrongGeneration,
    WrongRelation,
    Duplicate,
    Incomplete,
    Full,
    TerminalClaimed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1dDeliverPlan {
    WaitRegistrationPending,
    Live(InterruptBinding),
    RacePermit,
    Stale(InterruptBinding),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1dAckPlan {
    Ordinary,
    InjectRace(InterruptBinding),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvidenceRecord {
    event: u8,
    actor: u8,
    lease: u64,
    binding: u64,
    value: u64,
    auxiliary: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundInterrupt {
    object: ObjectId,
    binding: InterruptBinding,
    lease: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockedWait {
    process: ProcessKey,
    interrupt: ObjectId,
    execution_generation: u64,
    token: u64,
}

#[derive(Clone, Copy)]
struct State {
    records: [Option<EvidenceRecord>; DW1D_EVIDENCE_RECORD_COUNT],
    record_count: usize,
    controller: Option<ProcessKey>,
    trigger: Option<ProcessKey>,
    first_owner: Option<ProcessKey>,
    replacement_owner: Option<ProcessKey>,
    first_resource: Option<(ObjectId, u64)>,
    replacement_resource: Option<(ObjectId, u64)>,
    first_interrupt: Option<BoundInterrupt>,
    replacement_interrupt: Option<BoundInterrupt>,
    saved_scratch: Option<u8>,
    completed_cycles: u8,
    blocked_wait: Option<BlockedWait>,
    delivered_sequence: Option<u64>,
    race_permit: bool,
    race_injected: bool,
    race_complete: bool,
    first_interrupt_final: bool,
    first_grant_return: bool,
    stale_rejected: bool,
    replacement_wait_cancelled: bool,
    replacement_interrupt_final: bool,
    replacement_reaped: bool,
    accounting_complete: bool,
    ready: bool,
    failure: Option<Dw1dEvidenceError>,
}

impl State {
    const fn new() -> Self {
        Self {
            records: [None; DW1D_EVIDENCE_RECORD_COUNT],
            record_count: 0,
            controller: None,
            trigger: None,
            first_owner: None,
            replacement_owner: None,
            first_resource: None,
            replacement_resource: None,
            first_interrupt: None,
            replacement_interrupt: None,
            saved_scratch: None,
            completed_cycles: 0,
            blocked_wait: None,
            delivered_sequence: None,
            race_permit: false,
            race_injected: false,
            race_complete: false,
            first_interrupt_final: false,
            first_grant_return: false,
            stale_rejected: false,
            replacement_wait_cancelled: false,
            replacement_interrupt_final: false,
            replacement_reaped: false,
            accounting_complete: false,
            ready: false,
            failure: None,
        }
    }

    fn latch(&mut self, error: Dw1dEvidenceError) -> Dw1dEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }

    fn push(
        &mut self,
        event: u8,
        actor: u8,
        lease: u64,
        binding: u64,
        value: u64,
        auxiliary: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        let Some(slot) = self.records.get_mut(self.record_count) else {
            return Err(self.latch(Dw1dEvidenceError::Full));
        };
        *slot = Some(EvidenceRecord {
            event,
            actor,
            lease,
            binding,
            value,
            auxiliary,
        });
        self.record_count += 1;
        Ok(())
    }
}

/// Fixed selector-private collector. It retains opaque identity words, never
/// object pins, and therefore cannot extend a Process, Interrupt, or grant.
pub(crate) struct Dw1dEvidenceCollector {
    state: SpinMutex<State>,
    nonce: u64,
    challenge: u64,
    terminal: AtomicU8,
}

impl Dw1dEvidenceCollector {
    pub(crate) const fn new(nonce: u64, challenge: u64) -> Self {
        assert!(nonce != 0 && challenge != 0);
        Self {
            state: SpinMutex::new(State::new()),
            nonce,
            challenge,
            terminal: AtomicU8::new(0),
        }
    }

    pub(crate) fn decode_raw(
        &self,
        values: [u64; 6],
    ) -> Result<Dw1dRawOperation, Dw1dEvidenceError> {
        Dw1dRawOperation::decode(values, self.nonce, self.challenge)
    }

    pub(crate) const fn challenge_byte(&self) -> u8 {
        self.challenge as u8
    }

    pub(crate) fn observe_boot(
        &self,
        resource_count: usize,
        resource_id: u64,
        pio_base: u16,
        pio_length: u16,
        interrupt_source: u32,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if state.record_count != 0 {
            return Err(state.latch(Dw1dEvidenceError::Duplicate));
        }
        if resource_count != 1
            || resource_id != EXPECTED_RESOURCE_ID
            || pio_base != EXPECTED_PIO_BASE
            || pio_length != EXPECTED_PIO_LENGTH
            || interrupt_source != EXPECTED_INTERRUPT_SOURCE
        {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        let packed = (1_u64 << 63)
            | (u64::from(pio_base) << 32)
            | (u64::from(pio_length) << 16)
            | u64::from(interrupt_source);
        state.push(EVENT_BOOT, ACTOR_KERNEL, 0, 0, resource_id, packed)
    }

    pub(crate) fn arm(
        &self,
        controller: ProcessKey,
        owner: ProcessKey,
        trigger: ProcessKey,
        owner_in_resource_domain: bool,
        trigger_outside_resource_domain: bool,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if state.failure.is_some() || state.record_count == 0 {
            return Err(state.latch(Dw1dEvidenceError::Early));
        }
        if !owner_in_resource_domain
            || !trigger_outside_resource_domain
            || controller == owner
            || controller == trigger
            || owner == trigger
        {
            return Err(state.latch(Dw1dEvidenceError::WrongActor));
        }
        match (state.controller, state.trigger, state.first_owner) {
            (None, None, None) => {
                state.controller = Some(controller);
                state.trigger = Some(trigger);
                state.first_owner = Some(owner);
                state.push(
                    EVENT_ARM,
                    ACTOR_CONTROLLER,
                    0,
                    0,
                    owner.object_id().evidence_identity(),
                    trigger.object_id().evidence_identity(),
                )
            }
            (Some(expected_controller), Some(expected_trigger), Some(first_owner)) => {
                if !state.stale_rejected
                    || state.replacement_owner.is_some()
                    || controller != expected_controller
                    || trigger != expected_trigger
                    || owner == first_owner
                {
                    return Err(state.latch(Dw1dEvidenceError::OutOfOrder));
                }
                state.replacement_owner = Some(owner);
                Ok(())
            }
            _ => Err(state.latch(Dw1dEvidenceError::OutOfOrder)),
        }
    }

    pub(crate) fn report(
        &self,
        caller: ProcessKey,
        event: u8,
        value: u64,
        auxiliary: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        match event {
            EVENT_DENIED => {
                if state.controller != Some(caller)
                    || state.first_resource.is_some()
                    || value != EXPECTED_RESOURCE_ID
                    || auxiliary != 0
                {
                    return Err(state.latch(Dw1dEvidenceError::WrongRelation));
                }
                state.push(EVENT_DENIED, ACTOR_CONTROLLER, 0, 0, value, auxiliary)?;
                Ok(())
            }
            EVENT_PIO_SAVE => {
                if state.first_owner != Some(caller)
                    || state.first_resource.is_none()
                    || state.saved_scratch.is_some()
                    || value > u64::from(u8::MAX)
                    || auxiliary != 7
                {
                    return Err(state.latch(Dw1dEvidenceError::WrongRelation));
                }
                state.saved_scratch = Some(value as u8);
                let (_object, lease) = state.first_resource.expect("first claim checked");
                state.push(EVENT_PIO_SAVE, ACTOR_FIRST_OWNER, lease, 0, value, 0)?;
                Ok(())
            }
            EVENT_PIO_WRITE | EVENT_PIO_READ => {
                let Some(saved) = state.saved_scratch else {
                    return Err(state.latch(Dw1dEvidenceError::Early));
                };
                if state.first_owner != Some(caller)
                    || state.first_interrupt.is_some()
                    || value != u64::from(self.challenge_byte())
                    || auxiliary != u64::from(saved)
                    || (event == EVENT_PIO_READ
                        && state.records[..state.record_count]
                            .iter()
                            .flatten()
                            .all(|record| record.event != EVENT_PIO_WRITE))
                {
                    return Err(state.latch(Dw1dEvidenceError::WrongRelation));
                }
                let (_object, lease) = state.first_resource.expect("first claim checked");
                state.push(event, ACTOR_FIRST_OWNER, lease, 0, value, 0)?;
                Ok(())
            }
            EVENT_PIO_RESTORE => {
                let Some(saved) = state.saved_scratch else {
                    return Err(state.latch(Dw1dEvidenceError::Early));
                };
                if state.first_owner != Some(caller)
                    || value != u64::from(saved)
                    || auxiliary != u64::from(self.challenge_byte())
                    || state.records[..state.record_count]
                        .iter()
                        .flatten()
                        .all(|record| record.event != EVENT_PIO_READ)
                {
                    return Err(state.latch(Dw1dEvidenceError::WrongRelation));
                }
                let (_object, lease) = state.first_resource.expect("first claim checked");
                state.push(EVENT_PIO_RESTORE, ACTOR_FIRST_OWNER, lease, 0, value, 0)?;
                Ok(())
            }
            EVENT_READY => {
                if state.controller != Some(caller)
                    || !state.accounting_complete
                    || state.ready
                    || value != 0
                    || auxiliary != 0
                {
                    return Err(state.latch(Dw1dEvidenceError::WrongRelation));
                }
                state.push(EVENT_READY, ACTOR_CONTROLLER, 0, 0, 0, 0)?;
                state.ready = true;
                Ok(())
            }
            _ => Err(state.latch(Dw1dEvidenceError::Malformed)),
        }
    }

    pub(crate) fn final_normal_completion(
        &self,
    ) -> Result<Dw1dEvidenceFlushPermit<'_>, Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if !state.ready || !state.accounting_complete || state.failure.is_some() {
            return Err(state.failure.unwrap_or(Dw1dEvidenceError::Incomplete));
        }
        state.push(EVENT_TERMINAL, ACTOR_KERNEL, 0, 0, 0, 0)?;
        if state.record_count != DW1D_EVIDENCE_RECORD_COUNT {
            return Err(state.latch(Dw1dEvidenceError::Incomplete));
        }
        self.terminal
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| state.latch(Dw1dEvidenceError::TerminalClaimed))?;
        Ok(Dw1dEvidenceFlushPermit { collector: self })
    }

    pub(crate) fn observe_claim(
        &self,
        process: ProcessKey,
        resource_id: u64,
        object: ObjectId,
        lease: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if resource_id != EXPECTED_RESOURCE_ID || lease == 0 {
            return Err(state.latch(Dw1dEvidenceError::WrongIdentity));
        }
        if state.first_owner == Some(process) && state.first_resource.is_none() {
            if state.records[..state.record_count]
                .iter()
                .flatten()
                .all(|record| record.event != EVENT_DENIED)
            {
                return Err(state.latch(Dw1dEvidenceError::Early));
            }
            state.first_resource = Some((object, lease));
            return state.push(
                EVENT_FIRST_CLAIM,
                ACTOR_FIRST_OWNER,
                lease,
                0,
                resource_id,
                0,
            );
        }
        if state.replacement_owner == Some(process) && state.replacement_resource.is_none() {
            let (_, first_lease) = state
                .first_resource
                .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
            if !state.stale_rejected || lease == first_lease {
                return Err(state.latch(Dw1dEvidenceError::WrongGeneration));
            }
            state.replacement_resource = Some((object, lease));
            return state.push(
                EVENT_REPLACEMENT_CLAIM,
                ACTOR_REPLACEMENT_OWNER,
                lease,
                0,
                resource_id,
                0,
            );
        }
        Err(state.latch(Dw1dEvidenceError::WrongActor))
    }

    pub(crate) fn bind(
        &self,
        process: ProcessKey,
        interrupt_object: ObjectId,
        binding: InterruptBinding,
        lease: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if binding.source() != EXPECTED_INTERRUPT_SOURCE || binding.generation() == 0 || lease == 0
        {
            return Err(state.latch(Dw1dEvidenceError::WrongIdentity));
        }
        let bound = BoundInterrupt {
            object: interrupt_object,
            binding,
            lease,
        };
        if state.first_owner == Some(process) && state.first_interrupt.is_none() {
            if state.first_resource.map(|(_, value)| value) != Some(lease)
                || state.records[..state.record_count]
                    .iter()
                    .flatten()
                    .all(|record| record.event != EVENT_PIO_RESTORE)
            {
                return Err(state.latch(Dw1dEvidenceError::OutOfOrder));
            }
            state.first_interrupt = Some(bound);
            return state.push(
                EVENT_FIRST_BIND,
                ACTOR_FIRST_OWNER,
                lease,
                binding.generation(),
                u64::from(binding.source()),
                0,
            );
        }
        if state.replacement_owner == Some(process) && state.replacement_interrupt.is_none() {
            let first = state
                .first_interrupt
                .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
            if state.replacement_resource.map(|(_, value)| value) != Some(lease)
                || binding.generation() == first.binding.generation()
            {
                return Err(state.latch(Dw1dEvidenceError::WrongGeneration));
            }
            state.replacement_interrupt = Some(bound);
            return state.push(
                EVENT_REPLACEMENT_BIND,
                ACTOR_REPLACEMENT_OWNER,
                lease,
                binding.generation(),
                u64::from(binding.source()),
                0,
            );
        }
        Err(state.latch(Dw1dEvidenceError::WrongActor))
    }

    pub(crate) fn observe_wait_blocked(
        &self,
        process: ProcessKey,
        interrupt: ObjectId,
        execution_generation: u64,
        token: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if execution_generation == 0 || token == 0 || state.blocked_wait.is_some() {
            return Err(state.latch(Dw1dEvidenceError::Duplicate));
        }
        let blocked = BlockedWait {
            process,
            interrupt,
            execution_generation,
            token,
        };
        if state.first_owner == Some(process)
            && state
                .first_interrupt
                .is_some_and(|bound| bound.object == interrupt)
            && state.completed_cycles < 5
        {
            let delivery_sequence = u64::from(state.completed_cycles) + 1;
            state.blocked_wait = Some(blocked);
            let bound = state.first_interrupt.expect("first binding checked");
            return state.push(
                EVENT_WAIT_BLOCKED,
                ACTOR_FIRST_OWNER,
                bound.lease,
                bound.binding.generation(),
                delivery_sequence,
                0,
            );
        }
        if state.replacement_owner == Some(process)
            && state
                .replacement_interrupt
                .is_some_and(|bound| bound.object == interrupt)
        {
            state.blocked_wait = Some(blocked);
            return Ok(());
        }
        Err(state.latch(Dw1dEvidenceError::WrongActor))
    }

    pub(crate) fn tracks_interrupt_wait(&self, process: ProcessKey, interrupt: ObjectId) -> bool {
        let state = self.state.lock();
        state.blocked_wait.is_none()
            && ((state.first_owner == Some(process)
                && state
                    .first_interrupt
                    .is_some_and(|bound| bound.object == interrupt)
                && state.completed_cycles < 5)
                || (state.replacement_owner == Some(process)
                    && state
                        .replacement_interrupt
                        .is_some_and(|bound| bound.object == interrupt)))
    }

    pub(crate) fn authorize_deliver(
        &self,
        process: ProcessKey,
        sequence: u64,
    ) -> Result<Dw1dDeliverPlan, Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if state.trigger != Some(process) {
            return Err(state.latch(Dw1dEvidenceError::WrongActor));
        }
        let first = state
            .first_interrupt
            .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
        match sequence {
            1..=5
                if sequence == u64::from(state.completed_cycles) + 1
                    && state.blocked_wait.is_none()
                    && state.delivered_sequence.is_none() =>
            {
                // The trigger can run after the owner has published its logical
                // wait intent but before the wait registry commit becomes
                // visible. Preserve the exact next sequence without consuming
                // or poisoning it; every other mismatch remains latching.
                Ok(Dw1dDeliverPlan::WaitRegistrationPending)
            }
            1..=5
                if sequence == u64::from(state.completed_cycles) + 1
                    && state.blocked_wait.is_some()
                    && state.delivered_sequence.is_none() =>
            {
                Ok(Dw1dDeliverPlan::Live(first.binding))
            }
            6 if state.completed_cycles == 5
                && state.blocked_wait.is_none()
                && state.delivered_sequence.is_none()
                && !state.race_complete =>
            {
                Ok(Dw1dDeliverPlan::Live(first.binding))
            }
            7 if state.delivered_sequence == Some(6)
                && !state.race_permit
                && !state.race_injected =>
            {
                state.race_permit = true;
                Ok(Dw1dDeliverPlan::RacePermit)
            }
            8 if state.first_grant_return && !state.stale_rejected => {
                Ok(Dw1dDeliverPlan::Stale(first.binding))
            }
            _ => Err(state.latch(Dw1dEvidenceError::OutOfOrder)),
        }
    }

    pub(crate) fn replacement_termination_ready(
        &self,
        controller: ProcessKey,
        target: ProcessKey,
    ) -> Result<bool, Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if state.controller != Some(controller) {
            return Err(state.latch(Dw1dEvidenceError::WrongActor));
        }
        if state.replacement_owner != Some(target) {
            return Err(state.latch(Dw1dEvidenceError::WrongActor));
        }
        let replacement = state
            .replacement_interrupt
            .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
        if !state.stale_rejected
            || state.replacement_resource.is_none()
            || state.replacement_wait_cancelled
            || state.replacement_interrupt_final
            || state.replacement_reaped
        {
            return Err(state.latch(Dw1dEvidenceError::OutOfOrder));
        }
        let Some(blocked) = state.blocked_wait else {
            // This exact replacement is admitted only after its real wait
            // registration exists. A retry before that point is transient and
            // leaves the evidence state untouched.
            return Ok(false);
        };
        if blocked.process != target || blocked.interrupt != replacement.object {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        Ok(true)
    }

    pub(crate) fn observe_delivery(
        &self,
        sequence: u64,
        binding: InterruptBinding,
        accepted: bool,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        let first = state
            .first_interrupt
            .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
        if !accepted || binding != first.binding || state.delivered_sequence.is_some() {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        match sequence {
            1..=5 if sequence == u64::from(state.completed_cycles) + 1 => {
                let _blocked = state
                    .blocked_wait
                    .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
                state.delivered_sequence = Some(sequence);
                state.push(
                    EVENT_DELIVERED,
                    ACTOR_TRIGGER,
                    first.lease,
                    first.binding.generation(),
                    sequence,
                    0,
                )
            }
            6 if state.completed_cycles == 5 => {
                state.delivered_sequence = Some(6);
                Ok(())
            }
            _ => Err(state.latch(Dw1dEvidenceError::OutOfOrder)),
        }
    }

    pub(crate) fn observe_wait_completion(
        &self,
        process: ProcessKey,
        execution_generation: u64,
        token: u64,
        observed: deepwyrm_abi::DwSignals,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        let blocked = state
            .blocked_wait
            .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
        if state.first_owner != Some(process)
            || blocked.process != process
            || blocked.execution_generation != execution_generation
            || blocked.token != token
            || observed != DW_SIGNAL_SIGNALED
            || state.delivered_sequence != Some(u64::from(state.completed_cycles) + 1)
        {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        let bound = state.first_interrupt.expect("first binding checked");
        let delivery_sequence = u64::from(state.completed_cycles) + 1;
        state.push(
            EVENT_WAIT_WOKE,
            ACTOR_FIRST_OWNER,
            bound.lease,
            bound.binding.generation(),
            delivery_sequence,
            0,
        )
    }

    pub(crate) fn tracks_wait_completion(
        &self,
        process: ProcessKey,
        execution_generation: u64,
        token: u64,
    ) -> bool {
        self.state.lock().blocked_wait.is_some_and(|blocked| {
            blocked.process == process
                && blocked.execution_generation == execution_generation
                && blocked.token == token
        })
    }

    pub(crate) fn ack_prepared(
        &self,
        process: ProcessKey,
        binding: InterruptBinding,
    ) -> Result<Dw1dAckPlan, Dw1dEvidenceError> {
        let mut state = self.state.lock();
        let first = state
            .first_interrupt
            .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
        if state.first_owner != Some(process) || binding != first.binding {
            return Err(state.latch(Dw1dEvidenceError::WrongActor));
        }
        if state.delivered_sequence == Some(u64::from(state.completed_cycles) + 1)
            && state.completed_cycles < 5
        {
            return Ok(Dw1dAckPlan::Ordinary);
        }
        if state.delivered_sequence == Some(6) && state.race_permit && !state.race_injected {
            state.race_permit = false;
            return Ok(Dw1dAckPlan::InjectRace(first.binding));
        }
        Err(state.latch(Dw1dEvidenceError::OutOfOrder))
    }

    pub(crate) fn observe_race_injected(
        &self,
        binding: InterruptBinding,
        accepted: bool,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if !accepted
            || state
                .first_interrupt
                .is_none_or(|first| first.binding != binding)
            || state.race_permit
            || state.race_injected
        {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        state.race_injected = true;
        Ok(())
    }

    pub(crate) fn observe_ack_complete(
        &self,
        process: ProcessKey,
        binding: InterruptBinding,
        pending: bool,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        let first = state
            .first_interrupt
            .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
        if state.first_owner != Some(process) || binding != first.binding {
            return Err(state.latch(Dw1dEvidenceError::WrongActor));
        }
        if state.completed_cycles < 5
            && state.delivered_sequence == Some(u64::from(state.completed_cycles) + 1)
            && !pending
        {
            let delivery_sequence = u64::from(state.completed_cycles) + 1;
            state.push(
                EVENT_ACKED,
                ACTOR_FIRST_OWNER,
                first.lease,
                first.binding.generation(),
                delivery_sequence,
                0,
            )?;
            state.completed_cycles += 1;
            state.blocked_wait = None;
            state.delivered_sequence = None;
            return Ok(());
        }
        if state.delivered_sequence == Some(6)
            && state.race_injected
            && !state.race_complete
            && pending
        {
            state.push(
                EVENT_ACK_RACE,
                ACTOR_TRIGGER,
                first.lease,
                first.binding.generation(),
                7,
                6,
            )?;
            state.race_complete = true;
            return Ok(());
        }
        Err(state.latch(Dw1dEvidenceError::WrongRelation))
    }

    pub(crate) fn observe_interrupt_finalized(
        &self,
        object: ObjectId,
        binding: InterruptBinding,
        lease: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if state.first_interrupt.is_some_and(|first| {
            first.object == object && first.binding == binding && first.lease == lease
        }) {
            if !state.race_complete || state.first_interrupt_final {
                return Err(state.latch(Dw1dEvidenceError::OutOfOrder));
            }
            state.first_interrupt_final = true;
            return state.push(
                EVENT_FIRST_INTERRUPT_FINAL,
                ACTOR_KERNEL,
                lease,
                binding.generation(),
                0,
                0,
            );
        }
        if state.replacement_interrupt.is_some_and(|replacement| {
            replacement.object == object
                && replacement.binding == binding
                && replacement.lease == lease
        }) {
            if !state.replacement_wait_cancelled || state.replacement_interrupt_final {
                return Err(state.latch(Dw1dEvidenceError::OutOfOrder));
            }
            state.replacement_interrupt_final = true;
            return state.push(
                EVENT_REPLACEMENT_INTERRUPT_FINAL,
                ACTOR_REPLACEMENT_OWNER,
                lease,
                binding.generation(),
                1,
                0,
            );
        }
        Ok(())
    }

    pub(crate) fn observe_grant_returned(
        &self,
        resource_id: u64,
        object: ObjectId,
        lease: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if state.first_resource == Some((object, lease)) {
            if !state.first_interrupt_final
                || state.first_grant_return
                || resource_id != EXPECTED_RESOURCE_ID
            {
                return Err(state.latch(Dw1dEvidenceError::OutOfOrder));
            }
            let binding = state
                .first_interrupt
                .expect("first binding exists before grant return")
                .binding
                .generation();
            state.first_grant_return = true;
            return state.push(EVENT_FIRST_GRANT_RETURN, ACTOR_KERNEL, lease, binding, 0, 0);
        }
        Ok(())
    }

    pub(crate) fn observe_stale_delivery(
        &self,
        process: ProcessKey,
        sequence: u64,
        binding: InterruptBinding,
        status: deepwyrm_abi::DwStatus,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        let first = state
            .first_interrupt
            .ok_or_else(|| state.latch(Dw1dEvidenceError::Early))?;
        if state.trigger != Some(process)
            || sequence != 8
            || binding != first.binding
            || status != DW_STATUS_BAD_STATE
            || !state.first_grant_return
            || state.stale_rejected
        {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        state.push(
            EVENT_STALE_REJECTED,
            ACTOR_TRIGGER,
            first.lease,
            first.binding.generation(),
            8,
            u64::from(status.0.unsigned_abs()),
        )?;
        state.stale_rejected = true;
        Ok(())
    }

    pub(crate) fn observe_terminal_wait_cancelled(
        &self,
        process: ProcessKey,
        execution_generation: u64,
        token: u64,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        let Some(blocked) = state.blocked_wait else {
            return Ok(());
        };
        if state.replacement_owner != Some(process) {
            return Ok(());
        }
        if blocked.process != process
            || blocked.execution_generation != execution_generation
            || blocked.token != token
            || state.replacement_wait_cancelled
        {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        state.replacement_wait_cancelled = true;
        Ok(())
    }

    pub(crate) fn observe_process_reaped(
        &self,
        process: ProcessKey,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if state.replacement_owner != Some(process) {
            return Ok(());
        }
        if !state.replacement_interrupt_final || state.replacement_reaped {
            return Err(state.latch(Dw1dEvidenceError::OutOfOrder));
        }
        let replacement = state
            .replacement_interrupt
            .expect("replacement binding exists before reap");
        state.push(
            EVENT_REPLACEMENT_REAP,
            ACTOR_KERNEL,
            replacement.lease,
            replacement.binding.generation(),
            1,
            0,
        )?;
        state.replacement_reaped = true;
        Ok(())
    }

    pub(crate) fn observe_accounting(
        &self,
        live_device_resources: usize,
        live_interrupts: usize,
        live_waits: usize,
        grant_available: bool,
        accounting_mask: u8,
    ) -> Result<(), Dw1dEvidenceError> {
        let mut state = self.state.lock();
        if !state.replacement_reaped
            || state.accounting_complete
            || live_device_resources != 0
            || live_interrupts != 0
            || live_waits != 0
            || !grant_available
            || accounting_mask != EXPECTED_ACCOUNTING_MASK
        {
            return Err(state.latch(Dw1dEvidenceError::WrongRelation));
        }
        let packed = (u64::try_from(live_device_resources).unwrap_or(u64::MAX) << 32)
            | (u64::try_from(live_interrupts).unwrap_or(u64::MAX) << 16)
            | u64::try_from(live_waits).unwrap_or(u64::MAX);
        state.push(
            EVENT_ACCOUNTING,
            ACTOR_KERNEL,
            0,
            0,
            packed,
            u64::from(accounting_mask),
        )?;
        state.accounting_complete = true;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Dw1dEvidenceFlushPermit<'a> {
    collector: &'a Dw1dEvidenceCollector,
}

impl core::fmt::Debug for Dw1dEvidenceFlushPermit<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Dw1dEvidenceFlushPermit")
    }
}

impl PartialEq for Dw1dEvidenceFlushPermit<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.collector, other.collector)
    }
}

impl Eq for Dw1dEvidenceFlushPermit<'_> {}

impl Dw1dEvidenceFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; DW1D_EVIDENCE_RECORD_LEN]) -> Result<(), ()>,
    ) -> Result<(), Dw1dEvidenceError> {
        let state = self.collector.state.lock();
        if !state.ready
            || state.failure.is_some()
            || state.record_count != DW1D_EVIDENCE_RECORD_COUNT
        {
            return Err(state.failure.unwrap_or(Dw1dEvidenceError::Incomplete));
        }
        for (sequence, record) in state.records.iter().enumerate() {
            let record = record.ok_or(Dw1dEvidenceError::Incomplete)?;
            emit(&encode_record(
                sequence as u32,
                record,
                self.collector.nonce,
            ))
            .map_err(|()| Dw1dEvidenceError::Incomplete)?;
        }
        Ok(())
    }
}

fn encode_record(
    sequence: u32,
    record: EvidenceRecord,
    nonce: u64,
) -> [u8; DW1D_EVIDENCE_RECORD_LEN] {
    let mut out = [b'0'; DW1D_EVIDENCE_RECORD_LEN];
    out[..6].copy_from_slice(b"DWD6E1");
    out[6] = b'|';
    put_hex(&mut out[7..15], u64::from(sequence));
    out[15] = b'|';
    put_hex(&mut out[16..18], u64::from(record.event));
    out[18] = b'|';
    put_hex(&mut out[19..21], u64::from(record.actor));
    out[21] = b'|';
    put_hex(&mut out[22..38], nonce);
    out[38] = b'|';
    put_hex(&mut out[39..55], record.lease);
    out[55] = b'|';
    put_hex(&mut out[56..72], record.binding);
    out[72] = b'|';
    put_hex(&mut out[73..89], record.value);
    out[89] = b'|';
    put_hex(&mut out[90..106], record.auxiliary);
    out[106] = b'|';
    let checksum = crc32(&out[..106]);
    put_hex(&mut out[107..115], u64::from(checksum));
    out[115] = b'\r';
    out[116] = b'\n';
    out
}

fn put_hex(out: &mut [u8], mut value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in out.iter_mut().rev() {
        *byte = HEX[(value & 0xf) as usize];
        value >>= 4;
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

const fn parse_hex(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 16);
    let mut parsed = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("uppercase hex required"),
        };
        parsed = (parsed << 4) | digit as u64;
        index += 1;
    }
    assert!(parsed != 0);
    parsed
}

#[cfg(deepwyrm_dw1d_evidence)]
pub(crate) static DW1D_EVIDENCE: Dw1dEvidenceCollector = Dw1dEvidenceCollector::new(
    parse_hex(env!("DEEPWYRM_DW1D_EVIDENCE_NONCE")),
    parse_hex(env!("DEEPWYRM_DW1D_EVIDENCE_CHALLENGE")),
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use crate::task::ProcessKey;
    use deepwyrm_abi::{DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_PROCESS};

    fn process(registry: &mut ObjectRegistry<16>) -> ProcessKey {
        ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id())
    }

    fn binding() -> InterruptBinding {
        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let generation = NEXT.fetch_add(1, Ordering::Relaxed);
        InterruptBinding::for_test(generation, EXPECTED_INTERRUPT_SOURCE, generation)
    }

    struct Fixture {
        collector: Dw1dEvidenceCollector,
        controller: ProcessKey,
        owner: ProcessKey,
        trigger: ProcessKey,
        replacement: ProcessKey,
        first_resource: ObjectId,
        replacement_resource: ObjectId,
        first_interrupt_object: ObjectId,
        first_binding: InterruptBinding,
        replacement_interrupt_object: ObjectId,
        replacement_binding: InterruptBinding,
    }

    fn first_bound_fixture() -> Fixture {
        let collector = Dw1dEvidenceCollector::new(0x1111, 0x2273);
        let mut registry = ObjectRegistry::<16>::new();
        let first_interrupt_object = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
        let replacement_interrupt_object = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
        let first_binding = binding();
        let replacement_binding = binding();
        let fixture = Fixture {
            collector,
            controller: process(&mut registry),
            owner: process(&mut registry),
            trigger: process(&mut registry),
            replacement: process(&mut registry),
            first_resource: registry
                .create(deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE)
                .unwrap()
                .id(),
            replacement_resource: registry
                .create(deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE)
                .unwrap()
                .id(),
            first_interrupt_object,
            first_binding,
            replacement_interrupt_object,
            replacement_binding,
        };
        fixture.collector.observe_boot(1, 1, 0x2f8, 8, 3).unwrap();
        fixture
            .collector
            .arm(
                fixture.controller,
                fixture.owner,
                fixture.trigger,
                true,
                true,
            )
            .unwrap();
        fixture
            .collector
            .report(fixture.controller, EVENT_DENIED, 1, 0)
            .unwrap();
        fixture
            .collector
            .observe_claim(fixture.owner, 1, fixture.first_resource, 1)
            .unwrap();
        fixture
            .collector
            .report(fixture.owner, EVENT_PIO_SAVE, 0x55, 7)
            .unwrap();
        fixture
            .collector
            .report(fixture.owner, EVENT_PIO_WRITE, 0x73, 0x55)
            .unwrap();
        fixture
            .collector
            .report(fixture.owner, EVENT_PIO_READ, 0x73, 0x55)
            .unwrap();
        fixture
            .collector
            .report(fixture.owner, EVENT_PIO_RESTORE, 0x55, 0x73)
            .unwrap();
        fixture
            .collector
            .bind(
                fixture.owner,
                fixture.first_interrupt_object,
                fixture.first_binding,
                1,
            )
            .unwrap();
        fixture
    }

    fn advance_to_replacement_bound(fixture: &Fixture) {
        for sequence in 1..=5 {
            fixture
                .collector
                .observe_wait_blocked(
                    fixture.owner,
                    fixture.first_interrupt_object,
                    sequence,
                    0x100 + sequence,
                )
                .unwrap();
            assert_eq!(
                fixture
                    .collector
                    .authorize_deliver(fixture.trigger, sequence),
                Ok(Dw1dDeliverPlan::Live(fixture.first_binding))
            );
            fixture
                .collector
                .observe_delivery(sequence, fixture.first_binding, true)
                .unwrap();
            fixture
                .collector
                .observe_wait_completion(
                    fixture.owner,
                    sequence,
                    0x100 + sequence,
                    DW_SIGNAL_SIGNALED,
                )
                .unwrap();
            assert_eq!(
                fixture
                    .collector
                    .ack_prepared(fixture.owner, fixture.first_binding),
                Ok(Dw1dAckPlan::Ordinary)
            );
            fixture
                .collector
                .observe_ack_complete(fixture.owner, fixture.first_binding, false)
                .unwrap();
        }
        assert_eq!(
            fixture.collector.authorize_deliver(fixture.trigger, 6),
            Ok(Dw1dDeliverPlan::Live(fixture.first_binding))
        );
        fixture
            .collector
            .observe_delivery(6, fixture.first_binding, true)
            .unwrap();
        assert_eq!(
            fixture.collector.authorize_deliver(fixture.trigger, 7),
            Ok(Dw1dDeliverPlan::RacePermit)
        );
        assert_eq!(
            fixture
                .collector
                .ack_prepared(fixture.owner, fixture.first_binding),
            Ok(Dw1dAckPlan::InjectRace(fixture.first_binding))
        );
        fixture
            .collector
            .observe_race_injected(fixture.first_binding, true)
            .unwrap();
        fixture
            .collector
            .observe_ack_complete(fixture.owner, fixture.first_binding, true)
            .unwrap();
        fixture
            .collector
            .observe_interrupt_finalized(fixture.first_interrupt_object, fixture.first_binding, 1)
            .unwrap();
        fixture
            .collector
            .observe_grant_returned(1, fixture.first_resource, 1)
            .unwrap();
        assert_eq!(
            fixture.collector.authorize_deliver(fixture.trigger, 8),
            Ok(Dw1dDeliverPlan::Stale(fixture.first_binding))
        );
        fixture
            .collector
            .observe_stale_delivery(
                fixture.trigger,
                8,
                fixture.first_binding,
                DW_STATUS_BAD_STATE,
            )
            .unwrap();
        fixture
            .collector
            .arm(
                fixture.controller,
                fixture.replacement,
                fixture.trigger,
                true,
                true,
            )
            .unwrap();
        fixture
            .collector
            .observe_claim(fixture.replacement, 1, fixture.replacement_resource, 2)
            .unwrap();
        fixture
            .collector
            .bind(
                fixture.replacement,
                fixture.replacement_interrupt_object,
                fixture.replacement_binding,
                2,
            )
            .unwrap();
    }

    #[test]
    fn raw_decode_accepts_only_exact_build_bindings_and_report_allowlist() {
        let collector = Dw1dEvidenceCollector::new(0x1111, 0x2222);
        assert_eq!(
            collector.decode_raw([3, 7, 0x1111, 0x2222, 0, 0]),
            Ok(Dw1dRawOperation::Deliver { sequence: 7 })
        );
        assert_eq!(
            collector.decode_raw([3, 7, 0x1111, 0x2223, 0, 0]),
            Err(Dw1dEvidenceError::Malformed)
        );
        assert_eq!(
            collector.decode_raw([4, 0x0a, 0, 0, 0x1111, 0x2222]),
            Ok(Dw1dRawOperation::Report {
                event: 0x0a,
                value: 0,
                auxiliary: 0,
            })
        );
    }

    #[test]
    fn record_is_exact_117_byte_crc32_crlf_shape() {
        let record = encode_record(
            0x12,
            EvidenceRecord {
                event: 0xff,
                actor: 0,
                lease: 1,
                binding: 2,
                value: 3,
                auxiliary: 4,
            },
            0x1234,
        );
        assert_eq!(record.len(), 117);
        assert_eq!(&record[..7], b"DWD6E1|");
        assert_eq!(&record[115..], b"\r\n");
        let expected = crc32(&record[..106]);
        let encoded = core::str::from_utf8(&record[107..115]).unwrap();
        assert_eq!(u32::from_str_radix(encoded, 16).unwrap(), expected);
    }

    #[test]
    fn premature_exact_delivery_is_retryable_without_poisoning_the_cycle() {
        let fixture = first_bound_fixture();
        assert_eq!(
            fixture.collector.authorize_deliver(fixture.trigger, 1),
            Ok(Dw1dDeliverPlan::WaitRegistrationPending)
        );
        fixture
            .collector
            .observe_wait_blocked(fixture.owner, fixture.first_interrupt_object, 1, 0x101)
            .unwrap();
        assert_eq!(
            fixture.collector.authorize_deliver(fixture.trigger, 1),
            Ok(Dw1dDeliverPlan::Live(fixture.first_binding))
        );
        fixture
            .collector
            .observe_delivery(1, fixture.first_binding, true)
            .unwrap();
        fixture
            .collector
            .observe_wait_completion(fixture.owner, 1, 0x101, DW_SIGNAL_SIGNALED)
            .unwrap();
        assert_eq!(
            fixture
                .collector
                .ack_prepared(fixture.owner, fixture.first_binding),
            Ok(Dw1dAckPlan::Ordinary)
        );
        fixture
            .collector
            .observe_ack_complete(fixture.owner, fixture.first_binding, false)
            .unwrap();
    }

    #[test]
    fn premature_delivery_exception_does_not_relax_wrong_sequence_fail_closed() {
        let fixture = first_bound_fixture();
        assert_eq!(
            fixture.collector.authorize_deliver(fixture.trigger, 2),
            Err(Dw1dEvidenceError::OutOfOrder)
        );
        assert_eq!(
            fixture.collector.state.lock().failure,
            Some(Dw1dEvidenceError::OutOfOrder)
        );
    }

    #[test]
    fn replacement_termination_waits_for_exact_registered_wait_without_poisoning() {
        let fixture = first_bound_fixture();
        advance_to_replacement_bound(&fixture);
        assert_eq!(
            fixture
                .collector
                .replacement_termination_ready(fixture.controller, fixture.replacement,),
            Ok(false)
        );
        fixture
            .collector
            .observe_wait_blocked(
                fixture.replacement,
                fixture.replacement_interrupt_object,
                9,
                0x209,
            )
            .unwrap();
        assert_eq!(
            fixture
                .collector
                .replacement_termination_ready(fixture.controller, fixture.replacement,),
            Ok(true)
        );

        let wrong_target = first_bound_fixture();
        advance_to_replacement_bound(&wrong_target);
        assert_eq!(
            wrong_target
                .collector
                .replacement_termination_ready(wrong_target.controller, wrong_target.owner),
            Err(Dw1dEvidenceError::WrongActor)
        );
        assert_eq!(
            wrong_target.collector.state.lock().failure,
            Some(Dw1dEvidenceError::WrongActor)
        );
    }

    #[test]
    fn source_gate_returns_would_block_before_real_process_termination_preparation() {
        let source = include_str!("../arch/x86_64/mm/activation/primordial.rs");
        let handler = source
            .split("impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler")
            .nth(1)
            .unwrap()
            .split("fn complete_remote_stop(")
            .next()
            .unwrap();
        let gate = handler
            .find("runtime.dw1d_replacement_termination_gate(process)")
            .unwrap();
        let retry = handler[gate..]
            .find("NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK)")
            .map(|offset| gate + offset)
            .unwrap();
        let preparation = handler.find("let prepared = match request").unwrap();
        assert!(gate < retry && retry < preparation);
    }

    #[test]
    fn source_contract_wires_d6_to_real_lifecycle_and_normal_terminal_paths() {
        let primordial = include_str!("../arch/x86_64/mm/activation/primordial.rs");
        let adapters = include_str!("../syscall/adapters.rs");
        let wait = include_str!("../wait/engine.rs");
        let finalizer = include_str!("../object/finalizer.rs");
        let native = include_str!("../syscall/native.rs");
        let terminal = include_str!("x86_64.rs");

        let raw = primordial
            .split("fn intercept_dw1d_evidence_raw(")
            .nth(1)
            .unwrap()
            .split("fn authorize_return(")
            .next()
            .unwrap();
        assert!(raw.contains("Dw1dDeliverPlan::WaitRegistrationPending => DW_STATUS_WOULD_BLOCK"));
        assert!(raw.contains(".binding_for_resolved(&resolved)"));
        assert!(raw.contains(".observe_stale_delivery("));
        assert!(!raw.contains("complete_dw1d_evidence"));

        let facade = primordial
            .split("fn intercept_dw1d_evidence_raw(")
            .nth(2)
            .unwrap()
            .split("fn complete_remote_stop(")
            .next()
            .unwrap();
        assert!(
            facade.find("with_synchronized_runtime_at_safe_point(")
                < facade.find("drain_runnable_work_notifications();")
        );
        assert!(primordial.contains("crate::syscall::interrupt_ack_dw1d("));
        assert!(primordial.contains(".observe_boot("));
        assert!(primordial.contains(".observe_process_reaped(process)"));
        let controller = primordial
            .split("fn dw1d_controller_authorized(&self) -> bool {")
            .nth(1)
            .unwrap()
            .split("fn dw1d_process_handle(")
            .next()
            .unwrap();
        assert!(controller.contains("self.process == self.primordial_process"));
        assert!(!controller.contains("evidence_init_process"));
        assert_eq!(primordial.matches(".final_normal_completion()").count(), 2);

        let ack = adapters
            .split("pub(crate) fn interrupt_ack_dw1d<")
            .nth(1)
            .unwrap()
            .split("fn interrupt_create_status(")
            .next()
            .unwrap();
        let prepared = ack.find("prepare_interrupt_ack(").unwrap();
        let authorized = ack.find(".ack_prepared(").unwrap();
        let injected = ack.find(".observe_race_injected(").unwrap();
        let completed = ack
            .find(".complete(registry, interrupts, platform)")
            .unwrap();
        let observed = ack.find(".observe_ack_complete(").unwrap();
        assert!(prepared < authorized && authorized < injected && injected < completed);
        assert!(completed < observed);

        assert!(wait.contains(".observe_wait_blocked("));
        assert!(wait.contains(".observe_wait_completion("));
        assert!(wait.contains(".observe_terminal_wait_cancelled("));
        assert!(finalizer.contains(".observe_interrupt_finalized("));
        assert!(finalizer.contains(".observe_grant_returned("));
        assert!(native.contains("runtime.intercept_dw1d_evidence_raw(arguments)"));
        assert!(terminal.contains("pub(crate) fn complete_dw1d_evidence("));
        assert!(terminal.contains("completion_record(CompletionOutcome::Pass, 0)"));
    }

    #[test]
    fn five_cycles_race_finalization_replacement_and_terminal_form_exact_stream() {
        let fixture = first_bound_fixture();
        advance_to_replacement_bound(&fixture);
        fixture
            .collector
            .observe_wait_blocked(
                fixture.replacement,
                fixture.replacement_interrupt_object,
                9,
                0x209,
            )
            .unwrap();
        fixture
            .collector
            .observe_terminal_wait_cancelled(fixture.replacement, 9, 0x209)
            .unwrap();
        fixture
            .collector
            .observe_interrupt_finalized(
                fixture.replacement_interrupt_object,
                fixture.replacement_binding,
                2,
            )
            .unwrap();
        fixture
            .collector
            .observe_process_reaped(fixture.replacement)
            .unwrap();
        fixture
            .collector
            .observe_accounting(0, 0, 0, true, 0x3f)
            .unwrap();
        fixture
            .collector
            .report(fixture.controller, EVENT_READY, 0, 0)
            .unwrap();
        let permit = fixture.collector.final_normal_completion().unwrap();
        let mut records = 0;
        permit
            .flush(|record| {
                assert_eq!(record.len(), 117);
                records += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(records, 40);
    }
}
