//! Selector-31-only q35 COM2 interrupt evidence.
//!
//! E3B extends the reached first challenge leg through exact U1 retirement,
//! fresh U2 replacement, and a saved-U1 delivery replay through the real
//! Interrupt classifier. The complete 26-record transcript is claimed and
//! emitted only after every relation is closed.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only collector")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use deepwyrm_abi::DW_SIGNAL_SIGNALED;

use crate::arch::x86_64::acpi::PlatformIrqRoute;
use crate::device::{
    InterruptBinding, InterruptDelivery, InterruptDeliveryDisposition, Q35InterruptCounterSnapshot,
};
use crate::object::ObjectId;
use crate::sync::IrqSpinMutex;
use crate::task::ProcessKey;

pub(crate) const DW1E_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1f;
pub(crate) const DW1E_EVIDENCE_RECORD_LEN: usize = 204;
pub(crate) const DW1E_EVIDENCE_RECORD_COUNT: usize = 26;
pub(crate) const DW1E_E3A_RECORD_COUNT: usize = 9;
pub(crate) const DW1E_E3A_READY_LEN: usize = 90;

const RAW_WORD_COUNT: usize = 6;
const RAW_ACTION_BIND_DRIVER: u64 = 1;
const RAW_ACTION_BIND_PROBE: u64 = 2;
const RAW_ACTION_ARM_CHALLENGE: u64 = 3;
const RAW_ACTION_REPORT: u64 = 4;

const ACTOR_KERNEL: u8 = 0;
const ACTOR_DRIVER: u8 = 1;
const ACTOR_PROBE: u8 = 2;
const ACTOR_CONTROLLER: u8 = 3;

const EVENT_ROUTE_DISCOVERED: u8 = 0x01;
const EVENT_U1_RESERVED: u8 = 0x02;
const EVENT_U1_COMMITTED: u8 = 0x03;
const EVENT_C1_PHYSICAL: u8 = 0x04;
const EVENT_C1_PENDING: u8 = 0x05;
const EVENT_C1_WAIT_WAKE: u8 = 0x06;
pub(crate) const EVENT_C1_UART_DRAIN: u8 = 0x07;
const EVENT_C1_ACK: u8 = 0x08;
pub(crate) const EVENT_C1_RESPONSE: u8 = 0x09;
pub(crate) const EVENT_U1_PEER_CLOSED: u8 = 0x0a;
const EVENT_U1_RETIRE_BEGIN: u8 = 0x0b;
const EVENT_U1_ROUTE_MASKED: u8 = 0x0c;
const EVENT_U1_HANDLER_QUIESCENT: u8 = 0x0d;
const EVENT_U1_LAPIC_CLEAR: u8 = 0x0e;
const EVENT_U1_RELEASED: u8 = 0x0f;
const EVENT_U2_RESERVED: u8 = 0x10;
const EVENT_U2_COMMITTED: u8 = 0x11;
const EVENT_C2_PHYSICAL: u8 = 0x12;
const EVENT_C2_PENDING: u8 = 0x13;
const EVENT_C2_WAIT_WAKE: u8 = 0x14;
pub(crate) const EVENT_C2_UART_DRAIN: u8 = 0x15;
const EVENT_C2_ACK: u8 = 0x16;
pub(crate) const EVENT_C2_RESPONSE: u8 = 0x17;
const EVENT_STALE_U1_REJECTED: u8 = 0x18;
const EVENT_ACCOUNTING: u8 = 0x19;
const EVENT_TERMINAL: u8 = 0xff;

pub(crate) struct Dw1eTerminalArbiter {
    owner: AtomicU8,
}

impl Dw1eTerminalArbiter {
    pub(crate) const fn new() -> Self {
        Self {
            owner: AtomicU8::new(0),
        }
    }

    pub(crate) fn claim(&self, owner: u8) -> bool {
        assert!(matches!(owner, 1 | 2));
        self.owner
            .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[cfg(test)]
    fn owner(&self) -> u8 {
        self.owner.load(Ordering::Acquire)
    }
}

// E3A consumes only the first nine entries. Keeping the complete contract
// order here prevents E3B from renumbering or repurposing the reserved tail.
const EVIDENCE_EVENT_ORDER: [u8; DW1E_EVIDENCE_RECORD_COUNT] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff,
];
const EVIDENCE_ACTOR_ORDER: [u8; DW1E_EVIDENCE_RECORD_COUNT] = [
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_DRIVER,
    ACTOR_KERNEL,
    ACTOR_PROBE,
    ACTOR_CONTROLLER,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_DRIVER,
    ACTOR_KERNEL,
    ACTOR_PROBE,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
    ACTOR_KERNEL,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1eRawOperation {
    BindDriver {
        interrupt_handle: u64,
        attempt_generation: u64,
    },
    BindProbe {
        probe_handle: u64,
    },
    ArmChallenge {
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_hash: u64,
    },
    Submit {
        event: u8,
        value: u64,
        auxiliary: u64,
    },
    TerminalClaim,
}

impl Dw1eRawOperation {
    fn decode(values: [u64; RAW_WORD_COUNT], nonce: u64) -> Result<Self, Dw1eEvidenceError> {
        match values {
            [
                RAW_ACTION_BIND_DRIVER,
                interrupt_handle,
                attempt_generation,
                supplied_nonce,
                0,
                0,
            ] if interrupt_handle != 0 && attempt_generation != 0 && supplied_nonce == nonce => {
                Ok(Self::BindDriver {
                    interrupt_handle,
                    attempt_generation,
                })
            }
            [RAW_ACTION_BIND_PROBE, probe_handle, supplied_nonce, 0, 0, 0]
                if probe_handle != 0 && supplied_nonce == nonce =>
            {
                Ok(Self::BindProbe { probe_handle })
            }
            [
                RAW_ACTION_ARM_CHALLENGE,
                stream_generation,
                challenge_generation,
                expected_length,
                expected_hash,
                supplied_nonce,
            ] if stream_generation != 0
                && challenge_generation != 0
                && expected_length != 0
                && expected_hash != 0
                && supplied_nonce == nonce =>
            {
                Ok(Self::ArmChallenge {
                    stream_generation,
                    challenge_generation,
                    expected_length,
                    expected_hash,
                })
            }
            [
                RAW_ACTION_REPORT,
                event,
                value,
                auxiliary,
                supplied_nonce,
                0,
            ] if matches!(event, 0x07 | 0x09 | 0x0a | 0x15 | 0x17)
                && value != 0
                && (event == 0x0a || auxiliary != 0)
                && (event != 0x0a || auxiliary == 0)
                && supplied_nonce == nonce =>
            {
                Ok(Self::Submit {
                    event: event as u8,
                    value,
                    auxiliary,
                })
            }
            [RAW_ACTION_REPORT, 0xff, 0, 0, supplied_nonce, 0] if supplied_nonce == nonce => {
                Ok(Self::TerminalClaim)
            }
            _ => Err(Dw1eEvidenceError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dw1eEvidenceError {
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
    PartialClaimed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Dw1eEvidenceRecord {
    pub(crate) event: u8,
    pub(crate) actor: u8,
    pub(crate) route_generation: u64,
    pub(crate) object_generation: u64,
    pub(crate) binding_generation: u64,
    pub(crate) lease_generation: u64,
    pub(crate) attempt_generation: u64,
    pub(crate) stream_generation: u64,
    pub(crate) challenge_generation: u64,
    pub(crate) value: u64,
    pub(crate) auxiliary: u64,
}

#[derive(Clone, Copy)]
struct BoundInterrupt {
    object: ObjectId,
    binding: InterruptBinding,
    lease_generation: u64,
}

#[derive(Clone, Copy)]
struct BlockedWait {
    process: ProcessKey,
    object: ObjectId,
    execution_generation: u64,
    token: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Challenge {
    stream_generation: u64,
    challenge_generation: u64,
    expected_length: u64,
    expected_hash: u64,
}

#[derive(Clone, Copy)]
struct State {
    records: [Option<Dw1eEvidenceRecord>; DW1E_EVIDENCE_RECORD_COUNT],
    record_count: usize,
    reserved: Option<InterruptBinding>,
    committed: Option<BoundInterrupt>,
    first_committed: Option<BoundInterrupt>,
    controller: Option<ProcessKey>,
    driver: Option<ProcessKey>,
    first_driver: Option<ProcessKey>,
    probe: Option<ProcessKey>,
    first_probe: Option<ProcessKey>,
    attempt_generation: u64,
    first_attempt_generation: u64,
    challenge: Option<Challenge>,
    first_challenge: Option<Challenge>,
    first_response: Option<(u64, u64)>,
    saved_u1_delivery: Option<InterruptDelivery>,
    terminal_claimed: bool,
    blocked_wait: Option<BlockedWait>,
    physical_delta: u8,
    delivery_delta: u8,
    repeat_delta: u8,
    wait_woke: bool,
    drain: Option<(u64, u64)>,
    acknowledgement_delta: u8,
    ack_complete: bool,
    response: Option<(u64, u64)>,
    pending_u1_retirement: [Option<Dw1eEvidenceRecord>; 5],
    failure: Option<Dw1eEvidenceError>,
}

impl State {
    const fn new() -> Self {
        Self {
            records: [None; DW1E_EVIDENCE_RECORD_COUNT],
            record_count: 0,
            reserved: None,
            committed: None,
            first_committed: None,
            controller: None,
            driver: None,
            first_driver: None,
            probe: None,
            first_probe: None,
            attempt_generation: 0,
            first_attempt_generation: 0,
            challenge: None,
            first_challenge: None,
            first_response: None,
            saved_u1_delivery: None,
            terminal_claimed: false,
            blocked_wait: None,
            physical_delta: 0,
            delivery_delta: 0,
            repeat_delta: 0,
            wait_woke: false,
            drain: None,
            acknowledgement_delta: 0,
            ack_complete: false,
            response: None,
            pending_u1_retirement: [None; 5],
            failure: None,
        }
    }

    fn latch(&mut self, error: Dw1eEvidenceError) -> Dw1eEvidenceError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }

    fn push(&mut self, record: Dw1eEvidenceRecord) -> Result<(), Dw1eEvidenceError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        let Some(slot) = self.records.get_mut(self.record_count) else {
            return Err(self.latch(Dw1eEvidenceError::Full));
        };
        *slot = Some(record);
        self.record_count += 1;
        Ok(())
    }
}

pub(crate) struct Dw1eEvidenceCollector {
    state: IrqSpinMutex<State>,
    nonce: u64,
    partial: AtomicU8,
}

impl Dw1eEvidenceCollector {
    pub(crate) const fn new(nonce: u64) -> Self {
        assert!(nonce != 0);
        Self {
            state: IrqSpinMutex::new(State::new()),
            nonce,
            partial: AtomicU8::new(0),
        }
    }

    pub(crate) fn decode_raw(
        &self,
        values: [u64; 6],
    ) -> Result<Dw1eRawOperation, Dw1eEvidenceError> {
        Dw1eRawOperation::decode(values, self.nonce)
    }

    /// E3A-only operational synchronization. This marker is deliberately not
    /// a DWE3E1 record and cannot satisfy selector acceptance.
    pub(crate) fn ready_marker(&self) -> Result<[u8; DW1E_E3A_READY_LEN], Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let challenge = state
            .challenge
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Early))?;
        Ok(encode_ready_marker(self.nonce, challenge))
    }

    pub(crate) fn observe_route(&self, route: PlatformIrqRoute) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.record_count != 0 {
            return Err(state.latch(Dw1eEvidenceError::Duplicate));
        }
        let value = u64::from(route.gsi())
            | (u64::from(route.vector()) << 32)
            | (u64::from(route.bsp_local_apic_id()) << 40);
        let controller = route.controller();
        let auxiliary = 3_u64
            | (1_u64 << 16)
            | (1_u64 << 18)
            | (u64::from(controller.id()) << 20)
            | (u64::from(controller.gsi_base()) << 28);
        state.push(zero_generation_record(
            EVENT_ROUTE_DISCOVERED,
            ACTOR_KERNEL,
            value,
            auxiliary,
        ))
    }

    pub(crate) fn observe_reserved(
        &self,
        binding: InterruptBinding,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let first = state.record_count == 1 && state.reserved.is_none();
        let replacement = state.record_count == 15
            && state.first_committed.is_some()
            && state
                .first_committed
                .is_some_and(|first| binding.generation() > first.binding.generation());
        if (!first && !replacement) || binding.source() != 3 || binding.generation() == 0 {
            return Err(state.latch(Dw1eEvidenceError::WrongIdentity));
        }
        if replacement && state.reserved == Some(binding) {
            return Err(state.latch(Dw1eEvidenceError::Duplicate));
        }
        state.reserved = Some(binding);
        Ok(())
    }

    pub(crate) fn observe_committed(
        &self,
        object: ObjectId,
        binding: InterruptBinding,
        lease_generation: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let first = state.record_count == 1 && state.committed.is_none();
        let replacement = state.record_count == 15
            && state.first_committed.is_some()
            && state.first_committed.is_some_and(|first| {
                binding.generation() > first.binding.generation()
                    && object.generation() != first.object.generation()
                    && lease_generation == first.lease_generation
            });
        if state.reserved != Some(binding)
            || (!first && !replacement)
            || object.generation() == 0
            || lease_generation == 0
        {
            return Err(state.latch(Dw1eEvidenceError::WrongGeneration));
        }
        state.committed = Some(BoundInterrupt {
            object,
            binding,
            lease_generation,
        });
        Ok(())
    }

    pub(crate) fn bind_driver(
        &self,
        driver: ProcessKey,
        object: ObjectId,
        binding: InterruptBinding,
        lease_generation: u64,
        attempt_generation: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let Some(committed) = state.committed else {
            return Err(state.latch(Dw1eEvidenceError::Early));
        };
        let first_leg = state.record_count == 1;
        let second_leg = state.record_count == 15
            && state.first_committed.is_some()
            && state.first_driver.is_some();
        if (!first_leg && !second_leg)
            || (first_leg && state.driver.is_some())
            || (second_leg && state.first_driver == Some(driver))
            || committed.object != object
            || committed.binding != binding
            || committed.lease_generation != lease_generation
            || attempt_generation == 0
            || (second_leg && attempt_generation <= state.first_attempt_generation)
        {
            return Err(state.latch(Dw1eEvidenceError::WrongGeneration));
        }
        state.driver = Some(driver);
        state.attempt_generation = attempt_generation;
        let (reserved_event, committed_event) = if first_leg {
            (EVENT_U1_RESERVED, EVENT_U1_COMMITTED)
        } else {
            (EVENT_U2_RESERVED, EVENT_U2_COMMITTED)
        };
        let reserved = tuple_record(
            reserved_event,
            ACTOR_KERNEL,
            committed,
            attempt_generation,
            None,
            0,
            0,
        );
        let committed_record = tuple_record(
            committed_event,
            ACTOR_KERNEL,
            committed,
            attempt_generation,
            None,
            0,
            0,
        );
        state.push(reserved)?;
        state.push(committed_record)
    }

    pub(crate) fn bind_probe(
        &self,
        controller: ProcessKey,
        probe: ProcessKey,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let first_leg = state.record_count == 3 && state.first_probe.is_none();
        let second_leg = state.record_count == 17
            && state.first_probe.is_some()
            && state.first_probe != Some(probe);
        if (!first_leg && !second_leg)
            || state.driver.is_none()
            || state.driver == Some(controller)
            || state.driver == Some(probe)
            || controller == probe
            || state.controller.is_some_and(|bound| bound != controller)
        {
            return Err(state.latch(Dw1eEvidenceError::WrongActor));
        }
        state.controller = Some(controller);
        state.probe = Some(probe);
        Ok(())
    }

    pub(crate) fn challenge_wait_target(
        &self,
    ) -> Result<(ProcessKey, ObjectId), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let Some(driver) = state.driver else {
            return Err(state.latch(Dw1eEvidenceError::Early));
        };
        let Some(committed) = state.committed else {
            return Err(state.latch(Dw1eEvidenceError::Early));
        };
        Ok((driver, committed.object))
    }

    pub(crate) fn arm_challenge(
        &self,
        caller: ProcessKey,
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_hash: u64,
        blocked_process: ProcessKey,
        blocked_object: ObjectId,
        execution_generation: u64,
        token: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.driver != Some(caller) && state.controller != Some(caller) {
            return Err(state.latch(Dw1eEvidenceError::WrongActor));
        }
        let first_leg = state.record_count == 3 && state.challenge.is_none();
        let second_leg = state.record_count == 17
            && state.first_challenge.is_some()
            && state.challenge == state.first_challenge;
        if state.probe.is_none() || (!first_leg && !second_leg) {
            return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
        }
        if state.driver != Some(blocked_process)
            || state
                .committed
                .is_none_or(|committed| committed.object != blocked_object)
            || (first_leg && state.blocked_wait.is_some())
            || execution_generation == 0
            || token == 0
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        if second_leg {
            let first = state
                .first_challenge
                .expect("second leg retains U1 challenge");
            if stream_generation <= first.stream_generation
                || challenge_generation <= first.challenge_generation
                || (expected_length == first.expected_length
                    && expected_hash == first.expected_hash)
            {
                return Err(state.latch(Dw1eEvidenceError::WrongGeneration));
            }
            state.physical_delta = 0;
            state.delivery_delta = 0;
            state.repeat_delta = 0;
            state.wait_woke = false;
            state.drain = None;
            state.acknowledgement_delta = 0;
            state.ack_complete = false;
            state.response = None;
        }
        state.challenge = Some(Challenge {
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        });
        state.blocked_wait = Some(BlockedWait {
            process: blocked_process,
            object: blocked_object,
            execution_generation,
            token,
        });
        Ok(())
    }

    pub(crate) fn observe_physical(
        &self,
        delivery: InterruptDelivery,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.challenge.is_none() {
            return Ok(());
        }
        let binding = delivery.binding_for_evidence();
        if state
            .committed
            .is_none_or(|committed| committed.binding != binding)
        {
            return Err(state.latch(Dw1eEvidenceError::WrongGeneration));
        }
        if state.first_committed.is_none() && state.saved_u1_delivery.is_none() {
            state.saved_u1_delivery = Some(delivery);
        }
        // A UART receive epoch can become quiescent before userspace queues
        // the deterministic response. Enabling THRI then begins another real
        // epoch on the same exact binding. Preserve the completed accounting
        // as the prior quiescent point, but reopen the per-leg interval so
        // transmit progress remains observable and acknowledgeable.
        if state.ack_complete {
            state.ack_complete = false;
        }
        state.physical_delta = state
            .physical_delta
            .checked_add(1)
            .filter(|value| *value != u8::MAX)
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Full))?;
        Ok(())
    }

    pub(crate) fn observe_delivery(
        &self,
        binding: InterruptBinding,
        disposition: InterruptDeliveryDisposition,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.challenge.is_none() {
            return Ok(());
        }
        if state
            .committed
            .is_none_or(|committed| committed.binding != binding)
            || state.delivery_delta >= state.physical_delta
            || matches!(disposition, InterruptDeliveryDisposition::Rejected)
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        state.delivery_delta = state
            .delivery_delta
            .checked_add(1)
            .filter(|value| *value != u8::MAX)
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Full))?;
        if matches!(
            disposition,
            InterruptDeliveryDisposition::CoalescedPending | InterruptDeliveryDisposition::AckRace
        ) {
            state.repeat_delta = state
                .repeat_delta
                .checked_add(1)
                .filter(|value| *value != u8::MAX)
                .ok_or_else(|| state.latch(Dw1eEvidenceError::Full))?;
        }
        Ok(())
    }

    pub(crate) fn tracks_interrupt_wait(&self, process: ProcessKey, object: ObjectId) -> bool {
        let state = self.state.lock();
        state.driver == Some(process)
            && state
                .committed
                .is_some_and(|committed| committed.object == object)
            && state.challenge.is_some()
            && state.blocked_wait.is_none()
            && !state.wait_woke
    }

    pub(crate) fn observe_wait_blocked(
        &self,
        process: ProcessKey,
        object: ObjectId,
        execution_generation: u64,
        token: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.driver != Some(process)
            || state
                .committed
                .is_none_or(|committed| committed.object != object)
            || state.challenge.is_none()
            || state.blocked_wait.is_some()
            || execution_generation == 0
            || token == 0
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        state.blocked_wait = Some(BlockedWait {
            process,
            object,
            execution_generation,
            token,
        });
        Ok(())
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

    pub(crate) fn observe_wait_completion(
        &self,
        process: ProcessKey,
        execution_generation: u64,
        token: u64,
        observed: deepwyrm_abi::DwSignals,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let Some(blocked) = state.blocked_wait else {
            return Err(state.latch(Dw1eEvidenceError::Early));
        };
        if blocked.process != process
            || state
                .committed
                .is_none_or(|committed| committed.object != blocked.object)
            || blocked.execution_generation != execution_generation
            || blocked.token != token
            || observed != DW_SIGNAL_SIGNALED
            || state.delivery_delta == 0
            || state.wait_woke
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        state.wait_woke = true;
        Ok(())
    }

    pub(crate) fn submit(
        &self,
        caller: ProcessKey,
        event: u8,
        value: u64,
        auxiliary: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        match event {
            EVENT_C1_UART_DRAIN | EVENT_C2_UART_DRAIN => {
                let Some(challenge) = state.challenge else {
                    return Err(state.latch(Dw1eEvidenceError::Early));
                };
                let expected_event = if state.record_count == 3 {
                    EVENT_C1_UART_DRAIN
                } else if state.record_count == 17 {
                    EVENT_C2_UART_DRAIN
                } else {
                    return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
                };
                if event != expected_event
                    || state.driver != Some(caller)
                    || !state.wait_woke
                    || state.drain.is_some()
                    || value != challenge.expected_length
                    || auxiliary != challenge.expected_hash
                {
                    return Err(state.latch(Dw1eEvidenceError::WrongRelation));
                }
                state.drain = Some((value, auxiliary));
                Ok(())
            }
            EVENT_C1_RESPONSE | EVENT_C2_RESPONSE => {
                #[cfg(not(deepwyrm_dw1e_e3b_full))]
                let response_requires_current_ack = !state.ack_complete;
                #[cfg(deepwyrm_dw1e_e3b_full)]
                let response_requires_current_ack = false;
                let expected_event = if state.record_count == 3 {
                    EVENT_C1_RESPONSE
                } else if state.record_count == 17 {
                    EVENT_C2_RESPONSE
                } else {
                    return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
                };
                if state.probe != Some(caller)
                    || event != expected_event
                    || !state.wait_woke
                    || state.drain.is_none()
                    || state.acknowledgement_delta == 0
                    || response_requires_current_ack
                    || state.response.is_some()
                    || value == 0
                    || auxiliary == 0
                    || (event == EVENT_C2_RESPONSE
                        && state.first_response == Some((value, auxiliary)))
                {
                    return Err(state.latch(Dw1eEvidenceError::WrongRelation));
                }
                // In E3B-full mode the probe queues its response to the driver
                // before it can report this relation. A response-TX interrupt
                // may therefore begin and clear `ack_complete` before the
                // probe runs again. Once the prior challenge wake, drain, and
                // acknowledgement establish causality, preserve the
                // actor-owned response independently of the current epoch.
                // E3A still materializes immediately below and therefore keeps
                // its original current-ack admission requirement. The E3B TEMT
                // barrier and `materialize_leg` still require the final exact
                // interrupt epoch to be acknowledged before acceptance.
                state.response = Some((value, auxiliary));
                #[cfg(not(deepwyrm_dw1e_e3b_full))]
                if event == EVENT_C1_RESPONSE {
                    materialize_leg(&mut state)?;
                }
                Ok(())
            }
            #[cfg(deepwyrm_dw1e_e3b_full)]
            EVENT_U1_PEER_CLOSED => {
                if state.record_count != 3 {
                    return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
                }
                let challenge = state
                    .challenge
                    .ok_or_else(|| state.latch(Dw1eEvidenceError::Early))?;
                if state.controller != Some(caller)
                    || value != challenge.stream_generation
                    || auxiliary != 0
                {
                    return Err(state.latch(Dw1eEvidenceError::WrongRelation));
                }
                materialize_leg(&mut state)?;
                assert_eq!(state.record_count, DW1E_E3A_RECORD_COUNT);
                let first = state
                    .first_committed
                    .expect("first-leg materialization retains its committed tuple");
                let challenge = state
                    .first_challenge
                    .expect("first-leg materialization retains its challenge tuple");
                let attempt_generation = state.first_attempt_generation;
                state.push(tuple_record(
                    EVENT_U1_PEER_CLOSED,
                    ACTOR_CONTROLLER,
                    first,
                    attempt_generation,
                    Some(challenge),
                    value,
                    0,
                ))?;
                materialize_pending_u1_retirement(&mut state)
            }
            _ => Err(state.latch(Dw1eEvidenceError::Malformed)),
        }
    }

    pub(crate) fn observe_ack(
        &self,
        process: ProcessKey,
        binding: InterruptBinding,
        still_pending: bool,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.driver != Some(process)
            || state
                .committed
                .is_none_or(|committed| committed.binding != binding)
            || state.drain.is_none()
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        state.acknowledgement_delta = state
            .acknowledgement_delta
            .checked_add(1)
            .filter(|value| *value != u8::MAX)
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Full))?;
        if !still_pending {
            if state.physical_delta == 0
                || state.delivery_delta != state.physical_delta
                || state.repeat_delta >= state.delivery_delta
                || state.acknowledgement_delta > state.delivery_delta
            {
                return Err(state.latch(Dw1eEvidenceError::WrongRelation));
            }
            state.ack_complete = true;
        }
        Ok(())
    }

    pub(crate) fn partial_permit(
        &self,
    ) -> Result<Dw1eEvidencePartialPermit<'_>, Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.failure.is_some() || state.record_count != DW1E_E3A_RECORD_COUNT {
            return Err(state.failure.unwrap_or(Dw1eEvidenceError::Incomplete));
        }
        self.partial
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| state.latch(Dw1eEvidenceError::PartialClaimed))?;
        Ok(Dw1eEvidencePartialPermit { collector: self })
    }

    pub(crate) fn observe_retire_begin(
        &self,
        binding: InterruptBinding,
    ) -> Result<(), Dw1eEvidenceError> {
        self.push_u1_retirement(EVENT_U1_RETIRE_BEGIN, binding, 0, 0, 10)
    }

    pub(crate) fn observe_route_masked(
        &self,
        binding: InterruptBinding,
        idle_reads: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        if !(1..=65_536).contains(&idle_reads) {
            let mut state = self.state.lock();
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        self.push_u1_retirement(EVENT_U1_ROUTE_MASKED, binding, 3, idle_reads, 11)
    }

    pub(crate) fn observe_handler_quiescent(
        &self,
        binding: InterruptBinding,
    ) -> Result<(), Dw1eEvidenceError> {
        self.push_u1_retirement(EVENT_U1_HANDLER_QUIESCENT, binding, 0, 0, 12)
    }

    pub(crate) fn observe_lapic_clear(
        &self,
        binding: InterruptBinding,
    ) -> Result<(), Dw1eEvidenceError> {
        self.push_u1_retirement(EVENT_U1_LAPIC_CLEAR, binding, 3, 0, 13)
    }

    pub(crate) fn observe_released(
        &self,
        binding: InterruptBinding,
    ) -> Result<(), Dw1eEvidenceError> {
        self.push_u1_retirement(EVENT_U1_RELEASED, binding, 1, 0, 14)
    }

    fn push_u1_retirement(
        &self,
        event: u8,
        binding: InterruptBinding,
        value: u64,
        auxiliary: u64,
        expected_count: usize,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if let Some(failure) = state.failure {
            return Err(failure);
        }
        if state.first_committed.is_none() {
            if state.record_count != 3 {
                return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
            }
            let Some(committed) = state.committed else {
                return Err(state.latch(Dw1eEvidenceError::Early));
            };
            let Some(challenge) = state.challenge else {
                return Err(state.latch(Dw1eEvidenceError::Early));
            };
            if binding != committed.binding {
                return Err(state.latch(Dw1eEvidenceError::WrongRelation));
            }
            let Some(index) = expected_count.checked_sub(10).filter(|index| *index < 5) else {
                return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
            };
            if state.pending_u1_retirement[..index]
                .iter()
                .any(Option::is_none)
            {
                return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
            }
            let record = tuple_record(
                event,
                ACTOR_KERNEL,
                committed,
                state.attempt_generation,
                Some(challenge),
                value,
                auxiliary,
            );
            return match state.pending_u1_retirement[index] {
                None => {
                    state.pending_u1_retirement[index] = Some(record);
                    Ok(())
                }
                Some(existing) if existing == record => Ok(()),
                Some(_) => Err(state.latch(Dw1eEvidenceError::WrongRelation)),
            };
        }
        let first = state
            .first_committed
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Early))?;
        let challenge = state
            .first_challenge
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Early))?;
        if binding != first.binding {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        if state.record_count > expected_count {
            let expected = tuple_record(
                event,
                ACTOR_KERNEL,
                first,
                state.first_attempt_generation,
                Some(challenge),
                value,
                auxiliary,
            );
            return if state.records[expected_count] == Some(expected) {
                Ok(())
            } else {
                Err(state.latch(Dw1eEvidenceError::WrongRelation))
            };
        }
        if state.record_count != expected_count {
            return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
        }
        let attempt_generation = state.first_attempt_generation;
        state.push(tuple_record(
            event,
            ACTOR_KERNEL,
            first,
            attempt_generation,
            Some(challenge),
            value,
            auxiliary,
        ))
    }

    pub(crate) fn prepare_terminal(
        &self,
        caller: ProcessKey,
    ) -> Result<(InterruptDelivery, InterruptBinding), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if let Some(failure) = state.failure {
            return Err(failure);
        }
        if state.terminal_claimed {
            return Err(state.latch(Dw1eEvidenceError::Duplicate));
        }
        if state.controller != Some(caller) {
            return Err(state.latch(Dw1eEvidenceError::WrongActor));
        }
        if state.record_count != 17 {
            return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
        }
        if state.response.is_none()
            || !state.wait_woke
            || state.drain.is_none()
            || !state.ack_complete
        {
            return Err(state.latch(Dw1eEvidenceError::Incomplete));
        }
        let delivery = state
            .saved_u1_delivery
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?;
        let current = state
            .committed
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?
            .binding;
        state.terminal_claimed = true;
        Ok((delivery, current))
    }

    pub(crate) fn pending_terminal(
        &self,
    ) -> Result<Option<(InterruptDelivery, InterruptBinding)>, Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if let Some(failure) = state.failure {
            return Err(failure);
        }
        if !state.terminal_claimed || state.record_count != 17 {
            return Ok(None);
        }
        let delivery = state
            .saved_u1_delivery
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?;
        let current = state
            .committed
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?
            .binding;
        Ok(Some((delivery, current)))
    }

    pub(crate) fn materialize_terminal(
        &self,
        current_u2: InterruptBinding,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if let Some(failure) = state.failure {
            return Err(failure);
        }
        if !state.terminal_claimed || state.record_count != 17 {
            return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
        }
        if state
            .committed
            .is_none_or(|committed| committed.binding != current_u2)
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        materialize_leg(&mut state)
    }

    pub(crate) fn complete_stale_and_accounting(
        &self,
        disposition: InterruptDeliveryDisposition,
        wake_count: usize,
        counters: Q35InterruptCounterSnapshot,
    ) -> Result<Dw1eEvidenceFullPermit<'_>, Dw1eEvidenceError> {
        let mut state = self.state.lock();
        let first = state
            .first_committed
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?;
        let current = state
            .committed
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?;
        let first_challenge = state
            .first_challenge
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?;
        let current_challenge = state
            .challenge
            .ok_or_else(|| state.latch(Dw1eEvidenceError::Incomplete))?;
        if state.record_count != 23
            || !state.terminal_claimed
            || disposition != InterruptDeliveryDisposition::Rejected
            || wake_count != 0
            || current.binding.generation() <= first.binding.generation()
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        let first_attempt_generation = state.first_attempt_generation;
        let current_attempt_generation = state.attempt_generation;
        let [
            Some(u1_physical),
            Some(u1_delivery),
            Some(u1_ack),
            Some(u2_physical),
            Some(u2_delivery),
            Some(u2_ack),
        ] = [
            state.records[3],
            state.records[4],
            state.records[7],
            state.records[17],
            state.records[18],
            state.records[21],
        ]
        else {
            return Err(state.latch(Dw1eEvidenceError::Incomplete));
        };
        let physical = u1_physical.value + u2_physical.value;
        let exact = u1_delivery.value + u2_delivery.value;
        let pending = u1_delivery.auxiliary + u2_delivery.auxiliary;
        let acknowledgements = u1_ack.value + u2_ack.value;
        if counters.physical_entries != physical
            || counters.exact_deliveries != exact
            || counters.pending_deliveries != pending
            || counters.acknowledgements != acknowledgements
        {
            return Err(state.latch(Dw1eEvidenceError::WrongRelation));
        }
        state.push(tuple_record(
            EVENT_STALE_U1_REJECTED,
            ACTOR_KERNEL,
            first,
            first_attempt_generation,
            Some(first_challenge),
            current.binding.generation(),
            current.object.generation(),
        ))?;
        let packed = pack_counters(counters)?;
        state.push(tuple_record(
            EVENT_ACCOUNTING,
            ACTOR_KERNEL,
            current,
            current_attempt_generation,
            Some(current_challenge),
            packed.0,
            packed.1,
        ))?;
        state.push(zero_generation_record(EVENT_TERMINAL, ACTOR_KERNEL, 0, 0))?;
        self.partial
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| state.latch(Dw1eEvidenceError::PartialClaimed))?;
        Ok(Dw1eEvidenceFullPermit { collector: self })
    }
}

fn encode_ready_marker(nonce: u64, challenge: Challenge) -> [u8; DW1E_E3A_READY_LEN] {
    let mut out = [b'0'; DW1E_E3A_READY_LEN];
    out[..9].copy_from_slice(b"DWE3READY");
    out[9] = b'|';
    out[10..12].copy_from_slice(b"01");
    out[12] = b'|';
    put_hex(&mut out[13..29], nonce);
    out[29] = b'|';
    put_hex(&mut out[30..46], challenge.stream_generation);
    out[46] = b'|';
    put_hex(&mut out[47..63], challenge.challenge_generation);
    out[63] = b'|';
    put_hex(&mut out[64..80], challenge.expected_hash);
    out[80] = b'|';
    let checksum = fnv1a32(&out[..81]);
    put_hex(&mut out[81..89], u64::from(checksum));
    out[89] = b'\n';
    out
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "the readiness parser is a host/model gate")
)]
pub(crate) fn parse_ready_marker(
    bytes: &[u8; DW1E_E3A_READY_LEN],
    expected_nonce: u64,
    expected_stream: u64,
    expected_challenge: u64,
    expected_payload_hash: u64,
) -> Result<(), Dw1eEvidenceError> {
    if &bytes[..9] != b"DWE3READY"
        || bytes[9] != b'|'
        || &bytes[10..12] != b"01"
        || bytes[12] != b'|'
        || bytes[29] != b'|'
        || bytes[46] != b'|'
        || bytes[63] != b'|'
        || bytes[80] != b'|'
        || bytes[89] != b'\n'
    {
        return Err(Dw1eEvidenceError::Malformed);
    }
    if parse_hex(&bytes[13..29])? != expected_nonce
        || parse_hex(&bytes[30..46])? != expected_stream
        || parse_hex(&bytes[47..63])? != expected_challenge
        || parse_hex(&bytes[64..80])? != expected_payload_hash
        || parse_hex(&bytes[81..89])? != u64::from(fnv1a32(&bytes[..81]))
    {
        return Err(Dw1eEvidenceError::WrongIdentity);
    }
    Ok(())
}

/// E3A host/model extraction gate. It validates exactly records 0 through 8
/// and deliberately has no terminal or PASS concept.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the partial transcript validator is a host/model gate"
    )
)]
pub(crate) fn validate_e3a_transcript(
    bytes: &[[u8; DW1E_EVIDENCE_RECORD_LEN]; DW1E_E3A_RECORD_COUNT],
    nonce: u64,
) -> Result<(), Dw1eEvidenceError> {
    let mut records = [zero_generation_record(0, 0, 0, 0); DW1E_E3A_RECORD_COUNT];
    for (sequence, encoded) in bytes.iter().enumerate() {
        records[sequence] = parse_record(encoded, nonce, sequence as u32)?;
    }
    for index in 0..DW1E_E3A_RECORD_COUNT {
        if records[index].event != EVIDENCE_EVENT_ORDER[index]
            || records[index].actor != EVIDENCE_ACTOR_ORDER[index]
        {
            return Err(Dw1eEvidenceError::OutOfOrder);
        }
    }
    let route = records[0];
    if route.route_generation != 0
        || route.object_generation != 0
        || route.binding_generation != 0
        || route.lease_generation != 0
        || route.attempt_generation != 0
        || route.stream_generation != 0
        || route.challenge_generation != 0
        || ((route.value >> 32) & 0xff) != 0x30
        || (route.value >> 48) != 0
        || (route.auxiliary & 0xffff) != 3
        || ((route.auxiliary >> 16) & 0x3) != 1
        || ((route.auxiliary >> 18) & 0x3) != 1
        || (route.auxiliary >> 60) != 0
    {
        return Err(Dw1eEvidenceError::WrongRelation);
    }
    let tuple = records[1];
    let committed = Dw1eEvidenceRecord {
        event: EVENT_U1_COMMITTED,
        ..tuple
    };
    if tuple.route_generation == 0
        || tuple.object_generation == 0
        || tuple.binding_generation == 0
        || tuple.lease_generation == 0
        || tuple.attempt_generation == 0
        || tuple.route_generation != tuple.binding_generation
        || tuple.stream_generation != 0
        || tuple.challenge_generation != 0
        || tuple.value != 0
        || tuple.auxiliary != 0
        || records[2] != committed
    {
        return Err(Dw1eEvidenceError::WrongGeneration);
    }
    for record in &records[3..] {
        if record.route_generation != tuple.route_generation
            || record.object_generation != tuple.object_generation
            || record.binding_generation != tuple.binding_generation
            || record.lease_generation != tuple.lease_generation
            || record.attempt_generation != tuple.attempt_generation
            || record.stream_generation == 0
            || record.challenge_generation == 0
            || record.stream_generation != records[3].stream_generation
            || record.challenge_generation != records[3].challenge_generation
        {
            return Err(Dw1eEvidenceError::WrongGeneration);
        }
    }
    if !(1..=254).contains(&records[3].value)
        || records[3].auxiliary != 0
        || records[4].value != records[3].value
        || records[4].auxiliary >= records[4].value
        || records[5].value != 1
        || records[5].auxiliary != 0
        || records[6].value == 0
        || records[6].auxiliary == 0
        || !(1..=records[4].value).contains(&records[7].value)
        || records[7].auxiliary != 0
        || records[8].value == 0
        || records[8].auxiliary == 0
    {
        return Err(Dw1eEvidenceError::WrongRelation);
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the complete transcript validator is a host/model gate"
    )
)]
pub(crate) fn validate_e3b_transcript(
    bytes: &[[u8; DW1E_EVIDENCE_RECORD_LEN]; DW1E_EVIDENCE_RECORD_COUNT],
    nonce: u64,
) -> Result<(), Dw1eEvidenceError> {
    let mut records = [zero_generation_record(0, 0, 0, 0); DW1E_EVIDENCE_RECORD_COUNT];
    for (sequence, encoded) in bytes.iter().enumerate() {
        records[sequence] = parse_record(encoded, nonce, sequence as u32)?;
        if records[sequence].event != EVIDENCE_EVENT_ORDER[sequence]
            || records[sequence].actor != EVIDENCE_ACTOR_ORDER[sequence]
        {
            return Err(Dw1eEvidenceError::OutOfOrder);
        }
    }
    let route = records[0];
    if route.route_generation != 0
        || route.object_generation != 0
        || route.binding_generation != 0
        || route.lease_generation != 0
        || route.attempt_generation != 0
        || route.stream_generation != 0
        || route.challenge_generation != 0
        || ((route.value >> 32) & 0xff) != 0x30
        || (route.value >> 48) != 0
        || (route.auxiliary & 0xffff) != 3
        || ((route.auxiliary >> 16) & 0x3) != 1
        || ((route.auxiliary >> 18) & 0x3) != 1
        || (route.auxiliary >> 60) != 0
    {
        return Err(Dw1eEvidenceError::WrongRelation);
    }
    let u1 = records[1];
    let u2 = records[15];
    if u1.route_generation == 0
        || u1.object_generation == 0
        || u1.binding_generation == 0
        || u1.lease_generation == 0
        || u1.attempt_generation == 0
        || u1.route_generation != u1.binding_generation
        || u2.route_generation <= u1.route_generation
        || u2.object_generation == u1.object_generation
        || u2.binding_generation <= u1.binding_generation
        || u2.route_generation != u2.binding_generation
        || u2.lease_generation != u1.lease_generation
        || u2.attempt_generation <= u1.attempt_generation
        || u1.stream_generation != 0
        || u1.challenge_generation != 0
        || u2.stream_generation != 0
        || u2.challenge_generation != 0
        || u1.value != 0
        || u1.auxiliary != 0
        || u2.value != 0
        || u2.auxiliary != 0
        || records[2]
            != (Dw1eEvidenceRecord {
                event: EVENT_U1_COMMITTED,
                ..u1
            })
        || records[16]
            != (Dw1eEvidenceRecord {
                event: EVENT_U2_COMMITTED,
                ..u2
            })
    {
        return Err(Dw1eEvidenceError::WrongGeneration);
    }
    let c1 = records[3];
    let c2 = records[17];
    if c1.stream_generation == 0
        || c1.challenge_generation == 0
        || c2.stream_generation <= c1.stream_generation
        || c2.challenge_generation <= c1.challenge_generation
    {
        return Err(Dw1eEvidenceError::WrongGeneration);
    }
    for record in &records[3..15] {
        validate_tuple(*record, u1, c1)?;
    }
    for record in &records[17..23] {
        validate_tuple(*record, u2, c2)?;
    }
    validate_tuple(records[23], u1, c1)?;
    validate_tuple(records[24], u2, c2)?;
    if records[9].value != c1.stream_generation
        || records[9].auxiliary != 0
        || records[10].value != 0
        || records[10].auxiliary != 0
        || records[11].value != 3
        || !(1..=65_536).contains(&records[11].auxiliary)
        || records[12].value != 0
        || records[12].auxiliary != 0
        || records[13].value != 3
        || records[13].auxiliary != 0
        || records[14].value != 1
        || records[14].auxiliary != 0
        || records[23].value != u2.binding_generation
        || records[23].auxiliary != u2.object_generation
    {
        return Err(Dw1eEvidenceError::WrongRelation);
    }
    for start in [3_usize, 17_usize] {
        let physical = records[start];
        let pending = records[start + 1];
        let wake = records[start + 2];
        let drain = records[start + 3];
        let ack = records[start + 4];
        let response = records[start + 5];
        if !(1..=254).contains(&physical.value)
            || physical.auxiliary != 0
            || pending.value != physical.value
            || pending.auxiliary >= pending.value
            || wake.value != 1
            || wake.auxiliary != 0
            || drain.value == 0
            || drain.auxiliary == 0
            || !(1..=pending.value).contains(&ack.value)
            || ack.auxiliary != 0
            || response.value == 0
            || response.auxiliary == 0
        {
            return Err(Dw1eEvidenceError::WrongRelation);
        }
    }
    if (records[6].value == records[20].value && records[6].auxiliary == records[20].auxiliary)
        || (records[8].value == records[22].value && records[8].auxiliary == records[22].auxiliary)
    {
        return Err(Dw1eEvidenceError::WrongRelation);
    }
    let packed = records[24].value;
    let count = |index: usize| (packed >> (index * 8)) & 0xff;
    if count(0) != records[3].value + records[17].value
        || count(1) != records[4].value + records[18].value
        || count(2) != records[4].auxiliary + records[18].auxiliary
        || count(3) != records[7].value + records[21].value
        || !(1..=254).contains(&count(4))
        || !(2..=254).contains(&count(5))
        || count(6) != 2
        || count(7) != 1
        || records[24].auxiliary != 1
        || records[25] != zero_generation_record(EVENT_TERMINAL, ACTOR_KERNEL, 0, 0)
    {
        return Err(Dw1eEvidenceError::WrongRelation);
    }
    Ok(())
}

fn validate_tuple(
    record: Dw1eEvidenceRecord,
    tuple: Dw1eEvidenceRecord,
    challenge: Dw1eEvidenceRecord,
) -> Result<(), Dw1eEvidenceError> {
    if record.route_generation != tuple.route_generation
        || record.object_generation != tuple.object_generation
        || record.binding_generation != tuple.binding_generation
        || record.lease_generation != tuple.lease_generation
        || record.attempt_generation != tuple.attempt_generation
        || record.stream_generation != challenge.stream_generation
        || record.challenge_generation != challenge.challenge_generation
    {
        return Err(Dw1eEvidenceError::WrongGeneration);
    }
    Ok(())
}

fn tuple_record(
    event: u8,
    actor: u8,
    committed: BoundInterrupt,
    attempt_generation: u64,
    challenge: Option<Challenge>,
    value: u64,
    auxiliary: u64,
) -> Dw1eEvidenceRecord {
    Dw1eEvidenceRecord {
        event,
        actor,
        route_generation: committed.binding.generation(),
        object_generation: committed.object.generation(),
        binding_generation: committed.binding.generation(),
        lease_generation: committed.lease_generation,
        attempt_generation,
        stream_generation: challenge.map_or(0, |challenge| challenge.stream_generation),
        challenge_generation: challenge.map_or(0, |challenge| challenge.challenge_generation),
        value,
        auxiliary,
    }
}

const fn zero_generation_record(
    event: u8,
    actor: u8,
    value: u64,
    auxiliary: u64,
) -> Dw1eEvidenceRecord {
    Dw1eEvidenceRecord {
        event,
        actor,
        route_generation: 0,
        object_generation: 0,
        binding_generation: 0,
        lease_generation: 0,
        attempt_generation: 0,
        stream_generation: 0,
        challenge_generation: 0,
        value,
        auxiliary,
    }
}

fn materialize_leg(state: &mut State) -> Result<(), Dw1eEvidenceError> {
    let committed = state.committed.ok_or(Dw1eEvidenceError::Incomplete)?;
    let challenge = state.challenge.ok_or(Dw1eEvidenceError::Incomplete)?;
    let drain = state.drain.ok_or(Dw1eEvidenceError::Incomplete)?;
    let response = state.response.ok_or(Dw1eEvidenceError::Incomplete)?;
    let first_leg = state.record_count == 3;
    let second_leg = state.record_count == 17;
    if (!first_leg && !second_leg) || !state.wait_woke || !state.ack_complete {
        return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
    }
    let (physical_event, pending_event, wake_event, drain_event, ack_event, response_event) =
        if first_leg {
            (
                EVENT_C1_PHYSICAL,
                EVENT_C1_PENDING,
                EVENT_C1_WAIT_WAKE,
                EVENT_C1_UART_DRAIN,
                EVENT_C1_ACK,
                EVENT_C1_RESPONSE,
            )
        } else {
            (
                EVENT_C2_PHYSICAL,
                EVENT_C2_PENDING,
                EVENT_C2_WAIT_WAKE,
                EVENT_C2_UART_DRAIN,
                EVENT_C2_ACK,
                EVENT_C2_RESPONSE,
            )
        };
    for record in [
        tuple_record(
            physical_event,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            u64::from(state.physical_delta),
            0,
        ),
        tuple_record(
            pending_event,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            u64::from(state.delivery_delta),
            u64::from(state.repeat_delta),
        ),
        tuple_record(
            wake_event,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            1,
            0,
        ),
        tuple_record(
            drain_event,
            ACTOR_DRIVER,
            committed,
            state.attempt_generation,
            Some(challenge),
            drain.0,
            drain.1,
        ),
        tuple_record(
            ack_event,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            u64::from(state.acknowledgement_delta),
            0,
        ),
        tuple_record(
            response_event,
            ACTOR_PROBE,
            committed,
            state.attempt_generation,
            Some(challenge),
            response.0,
            response.1,
        ),
    ] {
        state.push(record)?;
    }
    if first_leg {
        state.first_committed = Some(committed);
        state.first_driver = state.driver;
        state.first_probe = state.probe;
        state.first_attempt_generation = state.attempt_generation;
        state.first_challenge = Some(challenge);
        state.first_response = Some(response);
    }
    Ok(())
}

fn materialize_pending_u1_retirement(state: &mut State) -> Result<(), Dw1eEvidenceError> {
    for index in 0..state.pending_u1_retirement.len() {
        let Some(record) = state.pending_u1_retirement[index] else {
            break;
        };
        if state.record_count != 10 + index {
            return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
        }
        state.push(record)?;
        state.pending_u1_retirement[index] = None;
    }
    Ok(())
}

fn pack_counters(counters: Q35InterruptCounterSnapshot) -> Result<(u64, u64), Dw1eEvidenceError> {
    let values = [
        counters.physical_entries,
        counters.exact_deliveries,
        counters.pending_deliveries,
        counters.acknowledgements,
        counters.stale_orphans,
        counters.route_masks,
        counters.route_unmasks,
        counters.final_releases,
    ];
    if values.into_iter().any(|value| value >= 0xff)
        || counters.generation_replacements != 1
        || counters.physical_entries != counters.exact_deliveries
        || !(2..=254).contains(&counters.physical_entries)
        || counters.pending_deliveries > counters.physical_entries.saturating_sub(2)
        || !(2..=counters.physical_entries).contains(&counters.acknowledgements)
        || !(1..=254).contains(&counters.stale_orphans)
        || !(2..=254).contains(&counters.route_masks)
        || counters.route_unmasks != 2
        || counters.final_releases != 1
    {
        return Err(Dw1eEvidenceError::WrongRelation);
    }
    let packed = values
        .into_iter()
        .enumerate()
        .fold(0_u64, |packed, (index, value)| {
            packed | (value << (index * 8))
        });
    Ok((packed, counters.generation_replacements))
}

#[derive(Clone, Copy)]
pub(crate) struct Dw1eEvidencePartialPermit<'a> {
    collector: &'a Dw1eEvidenceCollector,
}

impl Dw1eEvidencePartialPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; DW1E_EVIDENCE_RECORD_LEN]) -> Result<(), ()>,
    ) -> Result<(), Dw1eEvidenceError> {
        let state = self.collector.state.lock();
        if state.failure.is_some() || state.record_count != DW1E_E3A_RECORD_COUNT {
            return Err(state.failure.unwrap_or(Dw1eEvidenceError::Incomplete));
        }
        for (sequence, record) in state.records[..DW1E_E3A_RECORD_COUNT].iter().enumerate() {
            let encoded = encode_record(
                u32::try_from(sequence).expect("E3 evidence sequence fits u32"),
                record.ok_or(Dw1eEvidenceError::Incomplete)?,
                self.collector.nonce,
            );
            emit(&encoded).map_err(|()| Dw1eEvidenceError::Incomplete)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Dw1eEvidenceFullPermit<'a> {
    collector: &'a Dw1eEvidenceCollector,
}

impl Dw1eEvidenceFullPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; DW1E_EVIDENCE_RECORD_LEN]) -> Result<(), ()>,
    ) -> Result<(), Dw1eEvidenceError> {
        let state = self.collector.state.lock();
        if state.failure.is_some() || state.record_count != DW1E_EVIDENCE_RECORD_COUNT {
            return Err(state.failure.unwrap_or(Dw1eEvidenceError::Incomplete));
        }
        for (sequence, record) in state.records.iter().enumerate() {
            let encoded = encode_record(
                u32::try_from(sequence).expect("E3 evidence sequence fits u32"),
                record.ok_or(Dw1eEvidenceError::Incomplete)?,
                self.collector.nonce,
            );
            emit(&encoded).map_err(|()| Dw1eEvidenceError::Incomplete)?;
        }
        Ok(())
    }
}

pub(crate) fn encode_record(
    sequence: u32,
    record: Dw1eEvidenceRecord,
    nonce: u64,
) -> [u8; DW1E_EVIDENCE_RECORD_LEN] {
    let mut out = [b'0'; DW1E_EVIDENCE_RECORD_LEN];
    out[..6].copy_from_slice(b"DWE3E1");
    for index in [
        6, 9, 26, 35, 38, 41, 58, 75, 92, 109, 126, 143, 160, 177, 194,
    ] {
        out[index] = b'|';
    }
    out[7..9].copy_from_slice(b"01");
    put_hex(&mut out[10..26], nonce);
    put_hex(&mut out[27..35], u64::from(sequence));
    put_hex(&mut out[36..38], u64::from(record.event));
    put_hex(&mut out[39..41], u64::from(record.actor));
    for (range, value) in [
        (42..58, record.route_generation),
        (59..75, record.object_generation),
        (76..92, record.binding_generation),
        (93..109, record.lease_generation),
        (110..126, record.attempt_generation),
        (127..143, record.stream_generation),
        (144..160, record.challenge_generation),
        (161..177, record.value),
        (178..194, record.auxiliary),
    ] {
        put_hex(&mut out[range], value);
    }
    let checksum = fnv1a32(&out[..195]);
    put_hex(&mut out[195..203], u64::from(checksum));
    out[203] = b'\n';
    out
}

pub(crate) fn parse_record(
    bytes: &[u8; DW1E_EVIDENCE_RECORD_LEN],
    expected_nonce: u64,
    expected_sequence: u32,
) -> Result<Dw1eEvidenceRecord, Dw1eEvidenceError> {
    if &bytes[..6] != b"DWE3E1"
        || &bytes[7..9] != b"01"
        || bytes[203] != b'\n'
        || [
            6, 9, 26, 35, 38, 41, 58, 75, 92, 109, 126, 143, 160, 177, 194,
        ]
        .into_iter()
        .any(|index| bytes[index] != b'|')
    {
        return Err(Dw1eEvidenceError::Malformed);
    }
    let nonce = parse_hex(&bytes[10..26])?;
    let sequence = parse_hex(&bytes[27..35])?;
    let checksum = parse_hex(&bytes[195..203])?;
    if nonce != expected_nonce
        || sequence != u64::from(expected_sequence)
        || checksum != u64::from(fnv1a32(&bytes[..195]))
    {
        return Err(Dw1eEvidenceError::WrongIdentity);
    }
    Ok(Dw1eEvidenceRecord {
        event: u8::try_from(parse_hex(&bytes[36..38])?)
            .map_err(|_| Dw1eEvidenceError::Malformed)?,
        actor: u8::try_from(parse_hex(&bytes[39..41])?)
            .map_err(|_| Dw1eEvidenceError::Malformed)?,
        route_generation: parse_hex(&bytes[42..58])?,
        object_generation: parse_hex(&bytes[59..75])?,
        binding_generation: parse_hex(&bytes[76..92])?,
        lease_generation: parse_hex(&bytes[93..109])?,
        attempt_generation: parse_hex(&bytes[110..126])?,
        stream_generation: parse_hex(&bytes[127..143])?,
        challenge_generation: parse_hex(&bytes[144..160])?,
        value: parse_hex(&bytes[161..177])?,
        auxiliary: parse_hex(&bytes[178..194])?,
    })
}

fn put_hex(out: &mut [u8], mut value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in out.iter_mut().rev() {
        *byte = HEX[(value & 0xf) as usize];
        value >>= 4;
    }
}

fn parse_hex(bytes: &[u8]) -> Result<u64, Dw1eEvidenceError> {
    let mut value = 0_u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(Dw1eEvidenceError::Malformed),
        };
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(u64::from(digit)))
            .ok_or(Dw1eEvidenceError::Malformed)?;
    }
    Ok(value)
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

const fn parse_nonce(value: &str) -> u64 {
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

#[cfg(deepwyrm_dw1e_evidence)]
pub(crate) static DW1E_EVIDENCE: Dw1eEvidenceCollector =
    Dw1eEvidenceCollector::new(parse_nonce(env!("DEEPWYRM_DW1E_EVIDENCE_NONCE")));

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::{DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_PROCESS};
    use std::sync::Barrier;

    fn sample_record() -> Dw1eEvidenceRecord {
        Dw1eEvidenceRecord {
            event: EVENT_C1_RESPONSE,
            actor: ACTOR_PROBE,
            route_generation: 1,
            object_generation: 2,
            binding_generation: 1,
            lease_generation: 3,
            attempt_generation: 4,
            stream_generation: 5,
            challenge_generation: 6,
            value: 7,
            auxiliary: 8,
        }
    }

    #[test]
    fn exact_record_layout_round_trips_and_rejects_case_or_checksum_drift() {
        let nonce = 0x1234_5678_9abc_def0;
        let encoded = encode_record(8, sample_record(), nonce);
        assert_eq!(encoded.len(), 204);
        assert_eq!(encoded[203], b'\n');
        assert_eq!(parse_record(&encoded, nonce, 8), Ok(sample_record()));

        let mut lowercase = encoded;
        lowercase[10] = b'a';
        assert_eq!(
            parse_record(&lowercase, nonce, 8),
            Err(Dw1eEvidenceError::Malformed)
        );
        let mut corrupt = encoded;
        corrupt[178] ^= 1;
        assert_eq!(
            parse_record(&corrupt, nonce, 8),
            Err(Dw1eEvidenceError::WrongIdentity)
        );
    }

    #[test]
    fn raw_protocol_is_exactly_four_actions_with_nonce_and_reserved_zeroes() {
        let collector = Dw1eEvidenceCollector::new(9);
        assert_eq!(RAW_WORD_COUNT, 6);
        assert_eq!(RAW_ACTION_BIND_DRIVER, 1);
        assert_eq!(RAW_ACTION_BIND_PROBE, 2);
        assert_eq!(RAW_ACTION_ARM_CHALLENGE, 3);
        assert_eq!(RAW_ACTION_REPORT, 4);
        assert_eq!(
            collector.decode_raw([1, 11, 12, 9, 0, 0]),
            Ok(Dw1eRawOperation::BindDriver {
                interrupt_handle: 11,
                attempt_generation: 12,
            })
        );
        assert_eq!(
            collector.decode_raw([2, 13, 9, 0, 0, 0]),
            Ok(Dw1eRawOperation::BindProbe { probe_handle: 13 })
        );
        assert_eq!(
            collector.decode_raw([3, 14, 15, 16, 17, 9]),
            Ok(Dw1eRawOperation::ArmChallenge {
                stream_generation: 14,
                challenge_generation: 15,
                expected_length: 16,
                expected_hash: 17,
            })
        );
        assert_eq!(
            collector.decode_raw([4, 7, 18, 19, 9, 0]),
            Ok(Dw1eRawOperation::Submit {
                event: 7,
                value: 18,
                auxiliary: 19,
            })
        );
        assert_eq!(
            collector.decode_raw([4, 0xff, 0, 0, 9, 0]),
            Ok(Dw1eRawOperation::TerminalClaim)
        );
        for (event, value, auxiliary) in [
            (EVENT_C1_UART_DRAIN, 18, 19),
            (EVENT_C1_RESPONSE, 18, 19),
            (EVENT_U1_PEER_CLOSED, 18, 0),
            (EVENT_C2_UART_DRAIN, 18, 19),
            (EVENT_C2_RESPONSE, 18, 19),
        ] {
            assert!(matches!(
                collector.decode_raw([4, u64::from(event), value, auxiliary, 9, 0]),
                Ok(Dw1eRawOperation::Submit { .. })
            ));
        }
        for malformed in [
            [0, 0, 0, 0, 0, 0],
            [1, 0, 12, 9, 0, 0],
            [1, 11, 0, 9, 0, 0],
            [1, 11, 12, 9, 1, 0],
            [2, 0, 9, 0, 0, 0],
            [2, 13, 0, 0, 0, 0],
            [2, 13, 9, 0, 0, 1],
            [3, 0, 15, 16, 17, 9],
            [3, 14, 0, 16, 17, 9],
            [3, 14, 15, 0, 17, 9],
            [3, 14, 15, 16, 0, 9],
            [4, 0, 18, 19, 9, 0],
            [4, 7, 0, 19, 9, 0],
            [4, 9, 18, 0, 9, 0],
            [4, 8, 18, 19, 9, 0],
            [4, 10, 18, 19, 9, 0],
            [4, 11, 18, 19, 9, 0],
            [4, 21, 18, 0, 9, 0],
            [4, 23, 18, 0, 9, 0],
            [4, 24, 18, 19, 9, 0],
            [4, 25, 18, 19, 9, 0],
            [4, 255, 18, 19, 9, 0],
            [4, 255, 1, 0, 9, 0],
            [4, 255, 0, 1, 9, 0],
            [4, 7, 18, 19, 8, 0],
            [4, 7, 18, 19, 9, 1],
            [5, 0, 0, 0, 9, 0],
        ] {
            assert_eq!(
                collector.decode_raw(malformed),
                Err(Dw1eEvidenceError::Malformed)
            );
        }
    }

    #[test]
    fn e3b_tail_keeps_the_frozen_event_and_actor_identities() {
        assert_eq!(EVIDENCE_EVENT_ORDER.len(), 26);
        assert_eq!(EVIDENCE_ACTOR_ORDER.len(), 26);
        assert_eq!(&EVIDENCE_EVENT_ORDER[..9], &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            &EVIDENCE_EVENT_ORDER[9..25],
            &[
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25
            ]
        );
        assert_eq!(EVIDENCE_EVENT_ORDER[25], 0xff);
        assert_eq!(EVIDENCE_ACTOR_ORDER[9], ACTOR_CONTROLLER);
        assert_eq!(EVIDENCE_ACTOR_ORDER[20], ACTOR_DRIVER);
        assert_eq!(EVIDENCE_ACTOR_ORDER[22], ACTOR_PROBE);
        assert_eq!(EVIDENCE_ACTOR_ORDER[25], ACTOR_KERNEL);
    }

    #[test]
    fn readiness_marker_is_nonce_bound_and_not_a_certificate_record() {
        let marker = encode_ready_marker(
            0x1234_5678_9abc_def0,
            Challenge {
                stream_generation: 3,
                challenge_generation: 4,
                expected_length: 5,
                expected_hash: 6,
            },
        );
        assert_eq!(
            parse_ready_marker(&marker, 0x1234_5678_9abc_def0, 3, 4, 6),
            Ok(())
        );
        assert_ne!(&marker[..6], b"DWE3E1");
        let mut corrupt = marker;
        corrupt[13] ^= 1;
        assert_eq!(
            parse_ready_marker(&corrupt, 0x1234_5678_9abc_def0, 3, 4, 6),
            Err(Dw1eEvidenceError::WrongIdentity)
        );
    }

    #[test]
    fn terminal_arbiter_success_first_blocks_failure_and_panic_racers() {
        let arbiter = Dw1eTerminalArbiter::new();
        let claimed = Barrier::new(2);
        std::thread::scope(|scope| {
            let success = scope.spawn(|| {
                assert!(arbiter.claim(1));
                claimed.wait();
            });
            claimed.wait();
            let failure = scope.spawn(|| arbiter.claim(2));
            let panic = scope.spawn(|| arbiter.claim(2));
            success.join().unwrap();
            assert!(!failure.join().unwrap());
            assert!(!panic.join().unwrap());
        });
        assert_eq!(arbiter.owner(), 1);
    }

    #[test]
    fn terminal_arbiter_failure_first_blocks_success_and_panic_racers() {
        let arbiter = Dw1eTerminalArbiter::new();
        let claimed = Barrier::new(2);
        std::thread::scope(|scope| {
            let failure = scope.spawn(|| {
                assert!(arbiter.claim(2));
                claimed.wait();
            });
            claimed.wait();
            let success = scope.spawn(|| arbiter.claim(1));
            let panic = scope.spawn(|| arbiter.claim(2));
            failure.join().unwrap();
            assert!(!success.join().unwrap());
            assert!(!panic.join().unwrap());
        });
        assert_eq!(arbiter.owner(), 2);
    }

    #[test]
    #[cfg(not(deepwyrm_dw1e_e3b_full))]
    fn e3a_response_materializes_and_extracts_exact_records_without_a_terminal() {
        let collector = Dw1eEvidenceCollector::new(0x1234);
        let route = PlatformIrqRoute::test_q35(
            crate::arch::x86_64::acpi::IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0),
            3,
            7,
        );
        collector.observe_route(route).unwrap();
        let binding = InterruptBinding::for_test(9, 3, 11);
        collector.observe_reserved(binding).unwrap();
        let mut registry = ObjectRegistry::<8>::new();
        let object = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
        let driver =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let probe =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let controller =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        collector.observe_committed(object, binding, 13).unwrap();
        collector
            .bind_driver(driver, object, binding, 13, 17)
            .unwrap();
        collector.bind_probe(controller, probe).unwrap();
        collector
            .arm_challenge(driver, 19, 23, 5, 29, driver, object, 31, 37)
            .unwrap();
        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        collector
            .observe_wait_completion(driver, 31, 37, DW_SIGNAL_SIGNALED)
            .unwrap();
        collector
            .submit(driver, EVENT_C1_UART_DRAIN, 5, 29)
            .unwrap();
        collector.observe_ack(driver, binding, false).unwrap();

        // The response itself is transmitted through one exact U1 THRI
        // epoch before the probe reports that it received the bytes.
        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        collector.observe_ack(driver, binding, false).unwrap();
        collector.submit(probe, EVENT_C1_RESPONSE, 7, 41).unwrap();

        let permit = collector.partial_permit().unwrap();
        let mut transcript = [[0_u8; DW1E_EVIDENCE_RECORD_LEN]; DW1E_E3A_RECORD_COUNT];
        let mut count = 0;
        permit
            .flush(|record| {
                transcript[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, DW1E_E3A_RECORD_COUNT);
        assert_eq!(validate_e3a_transcript(&transcript, 0x1234), Ok(()));
        assert!(matches!(
            collector.partial_permit(),
            Err(Dw1eEvidenceError::PartialClaimed)
        ));

        // E3A's immutable extraction remains tolerant of a late, exact THRI
        // completion in the still-live U1 generation.
        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        collector.observe_ack(driver, binding, false).unwrap();
        assert_eq!(
            collector.submit(controller, EVENT_U1_PEER_CLOSED, 19, 0),
            Err(Dw1eEvidenceError::Malformed)
        );
    }

    #[test]
    #[cfg(not(deepwyrm_dw1e_e3b_full))]
    fn e3a_response_still_requires_the_current_interrupt_ack() {
        let collector = Dw1eEvidenceCollector::new(0x1234);
        let route = PlatformIrqRoute::test_q35(
            crate::arch::x86_64::acpi::IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0),
            3,
            7,
        );
        collector.observe_route(route).unwrap();
        let binding = InterruptBinding::for_test(9, 3, 11);
        collector.observe_reserved(binding).unwrap();
        let mut registry = ObjectRegistry::<8>::new();
        let object = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
        let driver =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let probe =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let controller =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        collector.observe_committed(object, binding, 13).unwrap();
        collector
            .bind_driver(driver, object, binding, 13, 17)
            .unwrap();
        collector.bind_probe(controller, probe).unwrap();
        collector
            .arm_challenge(driver, 19, 23, 5, 29, driver, object, 31, 37)
            .unwrap();
        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        collector
            .observe_wait_completion(driver, 31, 37, DW_SIGNAL_SIGNALED)
            .unwrap();
        collector
            .submit(driver, EVENT_C1_UART_DRAIN, 5, 29)
            .unwrap();
        collector.observe_ack(driver, binding, false).unwrap();

        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        assert_eq!(
            collector.submit(probe, EVENT_C1_RESPONSE, 7, 41),
            Err(Dw1eEvidenceError::WrongRelation)
        );
    }

    #[test]
    #[cfg(deepwyrm_dw1e_e3b_full)]
    fn e3b_first_leg_materializes_only_at_the_peer_close_barrier() {
        let collector = Dw1eEvidenceCollector::new(0x1234);
        let route = PlatformIrqRoute::test_q35(
            crate::arch::x86_64::acpi::IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0),
            3,
            7,
        );
        collector.observe_route(route).unwrap();
        let binding = InterruptBinding::for_test(9, 3, 11);
        collector.observe_reserved(binding).unwrap();
        let mut registry = ObjectRegistry::<8>::new();
        let object = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
        let driver =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let probe =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let controller =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        collector.observe_committed(object, binding, 13).unwrap();
        collector
            .bind_driver(driver, object, binding, 13, 17)
            .unwrap();
        collector.bind_probe(controller, probe).unwrap();
        collector
            .arm_challenge(driver, 19, 23, 5, 29, driver, object, 31, 37)
            .unwrap();
        assert!(!collector.tracks_interrupt_wait(driver, object));
        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        collector
            .observe_wait_completion(driver, 31, 37, DW_SIGNAL_SIGNALED)
            .unwrap();
        assert!(!collector.tracks_interrupt_wait(driver, object));
        collector
            .submit(driver, EVENT_C1_UART_DRAIN, 5, 29)
            .unwrap();
        collector.observe_ack(driver, binding, false).unwrap();

        // The response is transmitted by the same UART after the receive
        // epoch's clean ack. A fresh THRI epoch must remain inside the exact
        // U1 generation instead of being misclassified as post-generation
        // traffic.
        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        collector.observe_ack(driver, binding, false).unwrap();
        collector.submit(probe, EVENT_C1_RESPONSE, 7, 41).unwrap();

        assert!(matches!(
            collector.partial_permit(),
            Err(Dw1eEvidenceError::Incomplete)
        ));

        // The probe response does not freeze the leg. A late valid transmit
        // interrupt and ack remain part of C1 until the controller's
        // peer-close/TEMT barrier materializes records 3 through 8.
        collector
            .observe_physical(InterruptDelivery::for_test(binding))
            .unwrap();
        collector
            .observe_delivery(binding, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        collector.observe_ack(driver, binding, false).unwrap();
        collector
            .submit(controller, EVENT_U1_PEER_CLOSED, 19, 0)
            .unwrap();

        let mut transcript = [[0_u8; DW1E_EVIDENCE_RECORD_LEN]; DW1E_E3A_RECORD_COUNT];
        let state = collector.state.lock();
        for (sequence, output) in transcript.iter_mut().enumerate() {
            *output = encode_record(sequence as u32, state.records[sequence].unwrap(), 0x1234);
        }
        drop(state);
        assert_eq!(validate_e3a_transcript(&transcript, 0x1234), Ok(()));
        assert!(matches!(
            collector.partial_permit(),
            Err(Dw1eEvidenceError::Incomplete)
        ));
    }

    #[test]
    #[cfg(deepwyrm_dw1e_e3b_full)]
    fn full_e3b_model_retires_replaces_and_rejects_saved_u1_delivery() {
        let collector = Dw1eEvidenceCollector::new(0x1234);
        let route = PlatformIrqRoute::test_q35(
            crate::arch::x86_64::acpi::IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0),
            3,
            7,
        );
        collector.observe_route(route).unwrap();
        let mut registry = ObjectRegistry::<16>::new();
        let first_creation = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap();
        let object1 = first_creation.id();
        registry.cancel_creation(first_creation).unwrap();
        let object2 = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
        let driver1 =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let driver2 =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let probe1 =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let probe2 =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let controller =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let binding1 = InterruptBinding::for_test(9, 3, 11);
        collector.observe_reserved(binding1).unwrap();
        collector.observe_committed(object1, binding1, 13).unwrap();
        collector
            .bind_driver(driver1, object1, binding1, 13, 17)
            .unwrap();
        collector.bind_probe(controller, probe1).unwrap();
        collector
            .arm_challenge(driver1, 19, 23, 5, 29, driver1, object1, 31, 37)
            .unwrap();
        for _ in 0..2 {
            collector
                .observe_physical(InterruptDelivery::for_test(binding1))
                .unwrap();
            collector
                .observe_delivery(binding1, InterruptDeliveryDisposition::FirstPending)
                .unwrap();
            if !collector.state.lock().wait_woke {
                collector
                    .observe_wait_completion(driver1, 31, 37, DW_SIGNAL_SIGNALED)
                    .unwrap();
                collector
                    .submit(driver1, EVENT_C1_UART_DRAIN, 5, 29)
                    .unwrap();
            }
            collector.observe_ack(driver1, binding1, false).unwrap();
        }
        collector
            .observe_physical(InterruptDelivery::for_test(binding1))
            .unwrap();
        collector
            .observe_delivery(binding1, InterruptDeliveryDisposition::FirstPending)
            .unwrap();
        // Kernel finalization may complete before the controller observes the
        // response and peer-close, and before the last IRQ acknowledgement
        // settles. Preserve the facts while retaining the canonical transcript.
        collector.observe_retire_begin(binding1).unwrap();
        collector.observe_route_masked(binding1, 3).unwrap();
        collector.observe_handler_quiescent(binding1).unwrap();
        collector.observe_lapic_clear(binding1).unwrap();
        collector.observe_released(binding1).unwrap();
        assert_eq!(collector.state.lock().record_count, 3);
        collector.observe_ack(driver1, binding1, false).unwrap();
        collector.submit(probe1, EVENT_C1_RESPONSE, 7, 41).unwrap();
        collector
            .submit(controller, EVENT_U1_PEER_CLOSED, 19, 0)
            .unwrap();
        assert_eq!(collector.state.lock().record_count, 15);

        let binding2 = InterruptBinding::for_test(9, 3, 12);
        collector.observe_reserved(binding2).unwrap();
        collector.observe_committed(object2, binding2, 13).unwrap();
        collector
            .bind_driver(driver2, object2, binding2, 13, 18)
            .unwrap();
        collector.bind_probe(controller, probe2).unwrap();
        collector
            .arm_challenge(driver2, 20, 24, 6, 30, driver2, object2, 32, 38)
            .unwrap();
        for epoch in 0..2 {
            collector
                .observe_physical(InterruptDelivery::for_test(binding2))
                .unwrap();
            collector
                .observe_delivery(binding2, InterruptDeliveryDisposition::FirstPending)
                .unwrap();
            if !collector.state.lock().wait_woke {
                collector
                    .observe_wait_completion(driver2, 32, 38, DW_SIGNAL_SIGNALED)
                    .unwrap();
                collector
                    .submit(driver2, EVENT_C2_UART_DRAIN, 6, 30)
                    .unwrap();
            }
            if epoch == 1 {
                // The response relation races with the response-TX interrupt:
                // admit it while the latest physical epoch is not yet acked,
                // then let the terminal/TEMT join enforce exact completion.
                assert!(!collector.state.lock().ack_complete);
                collector.submit(probe2, EVENT_C2_RESPONSE, 8, 42).unwrap();
            }
            collector.observe_ack(driver2, binding2, false).unwrap();
        }
        let claim_ready = Barrier::new(2);
        let allow_claim_return = Barrier::new(2);
        let (saved, current) = std::thread::scope(|scope| {
            let claim = scope.spawn(|| {
                let prepared = collector.prepare_terminal(controller).unwrap();
                claim_ready.wait();
                allow_claim_return.wait();
                prepared
            });
            claim_ready.wait();
            assert_eq!(collector.state.lock().record_count, 17);
            collector
                .observe_physical(InterruptDelivery::for_test(binding2))
                .unwrap();
            collector
                .observe_delivery(binding2, InterruptDeliveryDisposition::FirstPending)
                .unwrap();
            collector.observe_ack(driver2, binding2, false).unwrap();
            allow_claim_return.wait();
            claim.join().unwrap()
        });
        assert_eq!(saved, InterruptDelivery::for_test(binding1));
        assert_eq!(current, binding2);
        assert_eq!(
            collector.pending_terminal().unwrap(),
            Some((saved, current))
        );
        collector.materialize_terminal(current).unwrap();
        assert_eq!(collector.pending_terminal().unwrap(), None);
        let permit = collector
            .complete_stale_and_accounting(
                InterruptDeliveryDisposition::Rejected,
                0,
                Q35InterruptCounterSnapshot {
                    physical_entries: 6,
                    exact_deliveries: 6,
                    pending_deliveries: 0,
                    acknowledgements: 6,
                    stale_orphans: 1,
                    route_masks: 4,
                    route_unmasks: 2,
                    final_releases: 1,
                    generation_replacements: 1,
                },
            )
            .unwrap();
        let mut transcript = [[0_u8; DW1E_EVIDENCE_RECORD_LEN]; DW1E_EVIDENCE_RECORD_COUNT];
        let mut count = 0;
        permit
            .flush(|record| {
                transcript[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 26);
        assert_eq!(validate_e3b_transcript(&transcript, 0x1234), Ok(()));
        assert_eq!(
            collector.prepare_terminal(controller),
            Err(Dw1eEvidenceError::Duplicate)
        );

        let mut stale = transcript;
        stale[23] = encode_record(
            23,
            Dw1eEvidenceRecord {
                value: binding1.generation(),
                ..parse_record(&stale[23], 0x1234, 23).unwrap()
            },
            0x1234,
        );
        assert_eq!(
            validate_e3b_transcript(&stale, 0x1234),
            Err(Dw1eEvidenceError::WrongRelation)
        );
    }

    #[test]
    #[cfg(deepwyrm_dw1e_e3b_full)]
    fn probe_response_requires_prior_challenge_progress() {
        let collector = Dw1eEvidenceCollector::new(0x1234);
        let route = PlatformIrqRoute::test_q35(
            crate::arch::x86_64::acpi::IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0),
            3,
            7,
        );
        collector.observe_route(route).unwrap();
        let binding = InterruptBinding::for_test(9, 3, 11);
        collector.observe_reserved(binding).unwrap();
        let mut registry = ObjectRegistry::<8>::new();
        let object = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
        let driver =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let probe =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        let controller =
            ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
        collector.observe_committed(object, binding, 13).unwrap();
        collector
            .bind_driver(driver, object, binding, 13, 17)
            .unwrap();
        collector.bind_probe(controller, probe).unwrap();
        collector
            .arm_challenge(driver, 19, 23, 5, 29, driver, object, 31, 37)
            .unwrap();

        assert_eq!(
            collector.submit(probe, EVENT_C1_RESPONSE, 7, 41),
            Err(Dw1eEvidenceError::WrongRelation)
        );
    }

    #[test]
    #[cfg(deepwyrm_dw1e_e3b_full)]
    fn terminal_claim_requires_the_bound_controller_and_complete_c2() {
        fn collector_bound_through_u1() -> (Dw1eEvidenceCollector, ProcessKey, ProcessKey) {
            let collector = Dw1eEvidenceCollector::new(0x1234);
            let route = PlatformIrqRoute::test_q35(
                crate::arch::x86_64::acpi::IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0),
                3,
                7,
            );
            collector.observe_route(route).unwrap();
            let binding = InterruptBinding::for_test(9, 3, 11);
            collector.observe_reserved(binding).unwrap();
            let mut registry = ObjectRegistry::<8>::new();
            let object = registry.create(DW_OBJECT_TYPE_INTERRUPT).unwrap().id();
            let driver =
                ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
            let probe =
                ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
            let controller =
                ProcessKey::from_object_id(registry.create(DW_OBJECT_TYPE_PROCESS).unwrap().id());
            collector.observe_committed(object, binding, 13).unwrap();
            collector
                .bind_driver(driver, object, binding, 13, 17)
                .unwrap();
            collector.bind_probe(controller, probe).unwrap();
            (collector, controller, probe)
        }

        let (early, controller, _) = collector_bound_through_u1();
        assert_eq!(
            early.prepare_terminal(controller),
            Err(Dw1eEvidenceError::OutOfOrder)
        );

        let (wrong_actor, _, probe) = collector_bound_through_u1();
        assert_eq!(
            wrong_actor.prepare_terminal(probe),
            Err(Dw1eEvidenceError::WrongActor)
        );
    }

    #[test]
    fn selector_private_raw_id_and_e3a_partial_path_cannot_be_public_acceptance() {
        let schema = include_str!("../../../abi/schema/syscalls.toml");
        let generated = include_str!("../../../abi/generated/syscall_kernel.rs");
        for public_surface in [schema, generated] {
            assert!(!public_surface.contains("ffff_ff1f"));
            assert!(!public_surface.contains("FFFFFF1F"));
            assert!(!public_surface.contains("4294967071"));
        }

        let terminal = include_str!("x86_64.rs");
        let partial = terminal
            .split("pub(crate) fn flush_dw1e_e3a_partial(")
            .nth(1)
            .unwrap()
            .split("/// Selector 31 owns")
            .next()
            .unwrap();
        assert!(!partial.contains("completion_record"));
        assert!(!partial.contains("write_debug_exit"));
        assert!(!partial.contains("DebugExitValue::PASS"));
        assert!(!partial.contains("Dw1eEvidencePartialPermit<'_>) -> !"));
        assert!(!partial.trim_end().ends_with("halt_after_completion()\n}"));

        let runtime = include_str!("../arch/x86_64/mm/activation/primordial.rs");
        let response_branch = runtime
            .split("Dw1eRawOperation::Submit {")
            .nth(1)
            .unwrap()
            .split("Dw1eRawOperation::TerminalClaim =>")
            .next()
            .unwrap();
        let commit = response_branch
            .find("self.commit_runtime_phase(phase);")
            .unwrap();
        let returning = response_branch
            .find("NativeSyscallResult::returning(DW_STATUS_SUCCESS)")
            .unwrap();
        assert!(commit < returning);
        assert_eq!(
            response_branch
                .matches("self.commit_runtime_phase(phase);")
                .count(),
            2
        );
        assert!(response_branch.contains("#[cfg(not(deepwyrm_dw1e_e3b_full))]"));
        assert!(response_branch.contains("event == crate::test_support::EVENT_C1_RESPONSE"));
        assert!(response_branch.contains("DW1E_EVIDENCE.partial_permit()"));
        assert!(response_branch.contains("flush_dw1e_e3a_partial(permit)"));
        assert!(!response_branch.contains("complete_dw1e_evidence"));
        assert!(!response_branch.contains("deliver_classified"));
        assert!(!response_branch.contains("complete_pass"));
        assert!(!response_branch.contains("write_debug_exit"));
        assert!(
            terminal
                .contains("complete_dw1e_failure_terminal(CompletionOutcome::Fail, 0x3110_ffff)")
        );

        let build = include_str!("../../build.rs");
        assert!(build.contains("cargo:rerun-if-env-changed=DEEPWYRM_DW1E_E3B_FULL"));
        assert!(build.contains("cargo:rustc-check-cfg=cfg(deepwyrm_dw1e_e3b_full)"));
        assert!(build.contains("cargo:rustc-cfg=deepwyrm_dw1e_e3b_full"));
        assert!(build.contains("Some(\"1\") if selected => Ok(true)"));
    }

    #[test]
    fn e3b_source_contract_joins_retirement_replay_and_atomic_terminal_seams() {
        let collector = include_str!("dw1e_evidence.rs");
        let peer_close = collector
            .split("EVENT_U1_PEER_CLOSED =>")
            .nth(1)
            .unwrap()
            .split("_ => Err(state.latch(Dw1eEvidenceError::Malformed))")
            .next()
            .unwrap();
        let controller_auth = peer_close.find("state.controller != Some(caller)").unwrap();
        let materialize = peer_close.find("materialize_leg(&mut state)?").unwrap();
        assert!(controller_auth < materialize);

        let platform = include_str!("../device/q35_interrupt.rs");
        let retirement_begin = platform
            .split("fn begin_retirement_exact(")
            .nth(1)
            .unwrap()
            .split("fn counter_snapshot_locked(")
            .next()
            .unwrap();
        assert_eq!(
            retirement_begin
                .matches("observe_retire_begin(binding)")
                .count(),
            1
        );
        let retirement = platform
            .split("pub(crate) fn try_finish_retirement(")
            .nth(1)
            .unwrap()
            .split("fn begin_handler(")
            .next()
            .unwrap();
        for observation in [
            "observe_route_masked(binding, proof.reads)",
            "observe_handler_quiescent(binding)",
            "observe_lapic_clear(binding)",
            "observe_released(binding)",
        ] {
            assert_eq!(retirement.matches(observation).count(), 1);
        }
        let first_idle = retirement
            .find("if let Some(proof) = first_idle_proof")
            .unwrap();
        let masked = retirement
            .find("observe_route_masked(binding, proof.reads)")
            .unwrap();
        let quiescent = retirement
            .find("observe_handler_quiescent(binding)")
            .unwrap();
        let bsp_clear = retirement.find("bsp_vector_clear()").unwrap();
        let lapic_clear = retirement.find("observe_lapic_clear(binding)").unwrap();
        let release = retirement.find(".release(binding.generation())").unwrap();
        let released = retirement.find("observe_released(binding)").unwrap();
        assert!(first_idle < masked);
        assert!(masked < quiescent);
        assert!(quiescent < bsp_clear);
        assert!(bsp_clear < lapic_clear);
        assert!(lapic_clear < release);
        assert!(release < released);

        let interrupts = include_str!("../device/interrupt.rs");
        let finalization = interrupts
            .split("impl<const INTERRUPTS: usize> InterruptFinalizer")
            .nth(1)
            .unwrap()
            .split("fn retry_deferred_finalization(")
            .next()
            .unwrap();
        let platform_retiring = finalization
            .find("platform.begin_retirement(binding);")
            .unwrap();
        let typed_finalizing = finalization
            .find("interrupt.state = InterruptState::Finalizing;")
            .unwrap();
        let finish_retirement = finalization
            .find("platform.retire_source(binding)")
            .unwrap();
        assert!(platform_retiring < typed_finalizing);
        assert!(typed_finalizing < finish_retirement);

        let runtime = include_str!("../arch/x86_64/mm/activation/primordial.rs");
        let terminal = runtime
            .split("Dw1eRawOperation::TerminalClaim =>")
            .nth(1)
            .unwrap()
            .split("fn authorize_return(")
            .next()
            .unwrap();
        let saved = terminal.find(".prepare_terminal(self.process)").unwrap();
        let freeze = terminal
            .find(".try_freeze_dw1e_terminal(stale, current)")
            .unwrap();
        let freeze_helper = runtime
            .split("fn try_freeze_dw1e_terminal(")
            .nth(1)
            .unwrap()
            .split("fn service_pending_dw1e_terminal(")
            .next()
            .unwrap();
        let materialize = freeze_helper
            .find(".materialize_terminal(current)")
            .unwrap();
        let classified = freeze_helper.find(".deliver_classified(saved_u1,").unwrap();
        let zero_wake = freeze_helper.find("!wakes.is_empty()").unwrap();
        let accounting = terminal.find(".complete_stale_and_accounting(").unwrap();
        assert!(saved < freeze);
        assert!(materialize < classified);
        assert!(classified < zero_wake);
        assert!(freeze < accounting);
        assert!(!freeze_helper.contains("complete_irq_signal_wakes"));
        assert!(!terminal.contains("counter_snapshot()"));
        assert!(!terminal.contains("record_stale_delivery_replay"));
        assert!(!terminal.contains("InterruptDelivery::for_test"));

        let safe_point = runtime
            .split("fn with_synchronized_runtime_at_safe_point<T>(")
            .nth(1)
            .unwrap()
            .split("fn enter_ap_kernel_root_detached(")
            .next()
            .unwrap();
        let bsp_guard = safe_point
            .find("self.cpu == crate::cpu::CpuIndex::BOOTSTRAP")
            .unwrap();
        let pending_terminal = safe_point.find("service_pending_dw1e_terminal()").unwrap();
        assert!(bsp_guard < pending_terminal);

        let completion = include_str!("x86_64.rs");
        let full = completion
            .split("pub(crate) fn complete_dw1e_evidence(")
            .nth(1)
            .unwrap();
        let transaction = full.find("begin_test_serial_transaction()").unwrap();
        let transcript = full.find("permit\n        .flush").unwrap();
        let pass = full
            .find("completion_record(CompletionOutcome::Pass, 0)")
            .unwrap();
        assert!(transaction < transcript);
        assert!(transcript < pass);

        assert!(completion.contains("static DW1E_TERMINAL_OWNER: super::Dw1eTerminalArbiter ="));
        assert!(full.contains("claim_dw1e_terminal(DW1E_TERMINAL_SUCCESS)"));
        let failure = completion
            .split("fn complete_dw1e_failure_terminal(")
            .nth(1)
            .unwrap()
            .split("#[cfg(deepwyrm_wyr1c_evidence)]")
            .next()
            .unwrap();
        assert!(failure.contains("claim_dw1e_terminal(DW1E_TERMINAL_FAILURE)"));
        let fail_dispatch = completion
            .split("pub(crate) fn complete_fail(")
            .nth(1)
            .unwrap()
            .split("pub(crate) fn complete_panic(")
            .next()
            .unwrap();
        let panic_dispatch = completion
            .split("pub(crate) fn complete_panic(")
            .nth(1)
            .unwrap();
        assert!(
            fail_dispatch
                .contains("complete_dw1e_failure_terminal(CompletionOutcome::Fail, detail)")
        );
        assert!(
            panic_dispatch
                .contains("complete_dw1e_failure_terminal(CompletionOutcome::Panic, detail)")
        );
    }
}
