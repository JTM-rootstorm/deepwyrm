//! Selector-31-only q35 COM2 interrupt evidence.
//!
//! E3A deliberately closes only the first challenge leg. The collector keeps
//! the complete 26-record shape reserved for E3B, but its partial permit emits
//! records 0 through 8 and never emits a `DWTEST1` PASS terminal.

#![cfg_attr(
    not(target_os = "none"),
    allow(dead_code, reason = "host tests exercise the target-only collector")
)]

use core::sync::atomic::{AtomicU8, Ordering};

use deepwyrm_abi::DW_SIGNAL_SIGNALED;

use crate::arch::x86_64::acpi::PlatformIrqRoute;
use crate::device::{InterruptBinding, InterruptDeliveryDisposition};
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
    BindProbe,
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
            [RAW_ACTION_BIND_PROBE, supplied_nonce, 0, 0, 0, 0] if supplied_nonce == nonce => {
                Ok(Self::BindProbe)
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
            ] if matches!(event, 0x07 | 0x09)
                && value != 0
                && auxiliary != 0
                && supplied_nonce == nonce =>
            {
                Ok(Self::Submit {
                    event: event as u8,
                    value,
                    auxiliary,
                })
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

#[derive(Clone, Copy)]
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
    controller: Option<ProcessKey>,
    driver: Option<ProcessKey>,
    probe: Option<ProcessKey>,
    attempt_generation: u64,
    challenge: Option<Challenge>,
    blocked_wait: Option<BlockedWait>,
    physical_delta: u8,
    delivery_delta: u8,
    repeat_delta: u8,
    wait_woke: bool,
    drain: Option<(u64, u64)>,
    acknowledgement_delta: u8,
    ack_complete: bool,
    response: Option<(u64, u64)>,
    failure: Option<Dw1eEvidenceError>,
}

impl State {
    const fn new() -> Self {
        Self {
            records: [None; DW1E_EVIDENCE_RECORD_COUNT],
            record_count: 0,
            reserved: None,
            committed: None,
            controller: None,
            driver: None,
            probe: None,
            attempt_generation: 0,
            challenge: None,
            blocked_wait: None,
            physical_delta: 0,
            delivery_delta: 0,
            repeat_delta: 0,
            wait_woke: false,
            drain: None,
            acknowledgement_delta: 0,
            ack_complete: false,
            response: None,
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
        if state.record_count != 1 || binding.source() != 3 || binding.generation() == 0 {
            return Err(state.latch(Dw1eEvidenceError::WrongIdentity));
        }
        if state.reserved.replace(binding).is_some() {
            return Err(state.latch(Dw1eEvidenceError::Duplicate));
        }
        Ok(())
    }

    pub(crate) fn observe_committed(
        &self,
        object: ObjectId,
        binding: InterruptBinding,
        lease_generation: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.reserved != Some(binding)
            || state.committed.is_some()
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
        if state.driver.is_some()
            || committed.object != object
            || committed.binding != binding
            || committed.lease_generation != lease_generation
            || attempt_generation == 0
        {
            return Err(state.latch(Dw1eEvidenceError::WrongGeneration));
        }
        state.driver = Some(driver);
        state.attempt_generation = attempt_generation;
        let reserved = tuple_record(
            EVENT_U1_RESERVED,
            ACTOR_KERNEL,
            committed,
            attempt_generation,
            None,
            0,
            0,
        );
        let committed_record = tuple_record(
            EVENT_U1_COMMITTED,
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
        if state.driver.is_none() || controller == probe || state.probe.is_some() {
            return Err(state.latch(Dw1eEvidenceError::WrongActor));
        }
        state.controller = Some(controller);
        state.probe = Some(probe);
        Ok(())
    }

    pub(crate) fn arm_challenge(
        &self,
        caller: ProcessKey,
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_hash: u64,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.driver != Some(caller) && state.controller != Some(caller) {
            return Err(state.latch(Dw1eEvidenceError::WrongActor));
        }
        if state.probe.is_none() || state.challenge.is_some() || state.record_count != 3 {
            return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
        }
        state.challenge = Some(Challenge {
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        });
        Ok(())
    }

    pub(crate) fn observe_physical(
        &self,
        binding: InterruptBinding,
    ) -> Result<(), Dw1eEvidenceError> {
        let mut state = self.state.lock();
        if state.challenge.is_none() {
            return Ok(());
        }
        if state
            .committed
            .is_none_or(|committed| committed.binding != binding)
            || state.ack_complete
        {
            return Err(state.latch(Dw1eEvidenceError::WrongGeneration));
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
            EVENT_C1_UART_DRAIN => {
                let Some(challenge) = state.challenge else {
                    return Err(state.latch(Dw1eEvidenceError::Early));
                };
                if state.driver != Some(caller)
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
            EVENT_C1_RESPONSE => {
                if state.probe != Some(caller)
                    || !state.ack_complete
                    || state.response.is_some()
                    || value == 0
                    || auxiliary == 0
                {
                    return Err(state.latch(Dw1eEvidenceError::WrongRelation));
                }
                state.response = Some((value, auxiliary));
                materialize_e3a(&mut state)
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
            || state.ack_complete
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

fn materialize_e3a(state: &mut State) -> Result<(), Dw1eEvidenceError> {
    let committed = state.committed.ok_or(Dw1eEvidenceError::Incomplete)?;
    let challenge = state.challenge.ok_or(Dw1eEvidenceError::Incomplete)?;
    let drain = state.drain.ok_or(Dw1eEvidenceError::Incomplete)?;
    let response = state.response.ok_or(Dw1eEvidenceError::Incomplete)?;
    if state.record_count != 3 || !state.wait_woke || !state.ack_complete {
        return Err(state.latch(Dw1eEvidenceError::OutOfOrder));
    }
    for record in [
        tuple_record(
            EVENT_C1_PHYSICAL,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            u64::from(state.physical_delta),
            0,
        ),
        tuple_record(
            EVENT_C1_PENDING,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            u64::from(state.delivery_delta),
            u64::from(state.repeat_delta),
        ),
        tuple_record(
            EVENT_C1_WAIT_WAKE,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            1,
            0,
        ),
        tuple_record(
            EVENT_C1_UART_DRAIN,
            ACTOR_DRIVER,
            committed,
            state.attempt_generation,
            Some(challenge),
            drain.0,
            drain.1,
        ),
        tuple_record(
            EVENT_C1_ACK,
            ACTOR_KERNEL,
            committed,
            state.attempt_generation,
            Some(challenge),
            u64::from(state.acknowledgement_delta),
            0,
        ),
        tuple_record(
            EVENT_C1_RESPONSE,
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
    Ok(())
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
    use super::*;
    use crate::object::ObjectRegistry;
    use deepwyrm_abi::{DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_PROCESS};

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
            collector.decode_raw([2, 9, 0, 0, 0, 0]),
            Ok(Dw1eRawOperation::BindProbe)
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
        for malformed in [
            [0, 0, 0, 0, 0, 0],
            [1, 0, 12, 9, 0, 0],
            [1, 11, 0, 9, 0, 0],
            [1, 11, 12, 9, 1, 0],
            [2, 0, 0, 0, 0, 0],
            [2, 9, 0, 0, 0, 1],
            [3, 0, 15, 16, 17, 9],
            [3, 14, 0, 16, 17, 9],
            [3, 14, 15, 0, 17, 9],
            [3, 14, 15, 16, 0, 9],
            [4, 0, 18, 19, 9, 0],
            [4, 7, 0, 19, 9, 0],
            [4, 9, 18, 0, 9, 0],
            [4, 8, 18, 19, 9, 0],
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
    fn first_leg_model_extracts_exact_records_without_a_terminal() {
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
        collector.arm_challenge(driver, 19, 23, 5, 29).unwrap();
        collector
            .observe_wait_blocked(driver, object, 31, 37)
            .unwrap();
        collector.observe_physical(binding).unwrap();
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
            .split("/// Selector 29")
            .next()
            .unwrap();
        assert!(!partial.contains("completion_record"));
        assert!(!partial.contains("write_debug_exit"));
        assert!(!partial.contains("DebugExitValue::PASS"));
        assert!(terminal.contains("complete_known_outcome(CompletionOutcome::Fail, 0x3110_ffff)"));
    }
}
