//! DW0-F5 bounded Channel endpoint and byte-datagram foundation.
//!
//! Generic object lifetime remains owned by `ObjectRegistry`. This module owns
//! only typed endpoint side leases, pair generations, bounded datagram queues,
//! transfer-token ownership, readiness, and peer-close state.

use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::{
    DW_CHANNEL_MAX_PAYLOAD, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_WAIT, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DwSignals, dw_signals_are_compatible,
};

use crate::handle::{HandleTransferBatch, ResolvedHandle};
use crate::object::{
    CreationRef, FinalRelease, HandleRef, InternalRef, ObjectId, ObjectRegistry,
    ObjectRegistryError,
};
use crate::sync::SpinMutex;
use crate::task::{BlockWakeKey, ThreadKey};
use crate::wait::{WaitRegistry, WakeBatch};

static NEXT_CHANNEL_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_channel_domain() -> u64 {
    NEXT_CHANNEL_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |domain| {
            domain.checked_add(1).filter(|next| *next != 0)
        })
        .expect("channel-authority domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChannelError {
    Capacity,
    InvalidArgument,
    InvalidEndpoint,
    StalePair,
    WouldBlock,
    /// The shared payload pool had no free slot, which is **not** the same
    /// condition as the peer's queue being full.
    ///
    /// Card R1 could not tell which of the two refused a report send, because
    /// both arrived as `WouldBlock`. They call for different responses: a full
    /// peer queue clears when that peer receives, while pool exhaustion clears
    /// when *any* channel in the system releases a slot. The pool is one
    /// `static` of `PAYLOAD_POOL_SLOTS` entries shared by every pair, and each
    /// entry is `DW_CHANNEL_MAX_PAYLOAD` (64 KiB) wide, so it cannot simply be
    /// sized to cover every queueable datagram: selector 34's geometry alone
    /// admits 24 pairs x 2 queues x 2 depth = 96, which at 64 KiB a slot would be
    /// 6 MiB of static memory against the 1 MiB the pool costs today.
    ///
    /// This maps to the same ABI status as `WouldBlock` deliberately. Splitting
    /// it at the ABI is a separate, deliberate decision; splitting it inside the
    /// kernel is what lets a diagnosis name the resource that ran out.
    PayloadExhausted,
    PeerClosed,
    BufferTooSmall,
    AccessDenied,
    FinalizationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChannelCreateError {
    Registry(ObjectRegistryError),
    Channel(ChannelError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChannelEndpointKey(ObjectId);

impl ChannelEndpointKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }

    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChannelPairKey {
    domain: u64,
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelSide {
    Zero,
    One,
}

impl ChannelSide {
    const fn index(self) -> usize {
        match self {
            Self::Zero => 0,
            Self::One => 1,
        }
    }

    const fn peer(self) -> Self {
        match self {
            Self::Zero => Self::One,
            Self::One => Self::Zero,
        }
    }
}

#[derive(Debug)]
struct ChannelSideLease {
    pair: ChannelPairKey,
    side: ChannelSide,
}

struct EndpointRecord {
    object: ObjectId,
    lease: ChannelSideLease,
}

const PAYLOAD_POOL_SLOTS: usize = 16;
const PAYLOAD_BYTES: usize = DW_CHANNEL_MAX_PAYLOAD as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadToken {
    slot: u8,
    generation: u32,
}

#[derive(Clone, Copy)]
struct PayloadSlot {
    generation: u32,
    in_use: bool,
    bytes: [u8; PAYLOAD_BYTES],
}

#[allow(
    clippy::large_const_arrays,
    reason = "Copied const initializer for the statically allocated payload pool."
)]
const EMPTY_PAYLOAD_SLOT: PayloadSlot = PayloadSlot {
    generation: 0,
    in_use: false,
    bytes: [0; PAYLOAD_BYTES],
};

struct PayloadPool {
    slots: SpinMutex<[PayloadSlot; PAYLOAD_POOL_SLOTS]>,
}

impl PayloadPool {
    const fn new() -> Self {
        Self {
            slots: SpinMutex::new([EMPTY_PAYLOAD_SLOT; PAYLOAD_POOL_SLOTS]),
        }
    }

    fn allocate(&self, payload: &[u8]) -> Result<Option<PayloadToken>, ChannelError> {
        if payload.is_empty() {
            return Ok(None);
        }
        let mut slots = self.slots.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.in_use {
                continue;
            }
            let Some(generation) = slot
                .generation
                .checked_add(1)
                .filter(|generation| *generation != 0)
            else {
                continue;
            };
            slot.generation = generation;
            slot.bytes[..payload.len()].copy_from_slice(payload);
            slot.in_use = true;
            return Ok(Some(PayloadToken {
                slot: u8::try_from(index).expect("payload pool fits u8 token"),
                generation,
            }));
        }
        Err(ChannelError::PayloadExhausted)
    }

    fn copy_and_release(&self, token: PayloadToken, byte_len: usize, output: &mut [u8]) {
        let mut slots = self.slots.lock();
        let slot = slots
            .get_mut(usize::from(token.slot))
            .expect("queued payload token slot remains in range");
        assert!(
            slot.in_use && slot.generation == token.generation,
            "queued payload token became stale before receive"
        );
        output[..byte_len].copy_from_slice(&slot.bytes[..byte_len]);
        slot.in_use = false;
    }

    fn release(&self, token: PayloadToken) {
        let mut slots = self.slots.lock();
        let slot = slots
            .get_mut(usize::from(token.slot))
            .expect("queued payload token slot remains in range");
        assert!(
            slot.in_use && slot.generation == token.generation,
            "queued payload token became stale before queue drain"
        );
        slot.in_use = false;
    }
}

static PAYLOAD_POOL: PayloadPool = PayloadPool::new();

struct QueuedMessage {
    byte_len: u32,
    payload: Option<PayloadToken>,
    transfers: HandleTransferBatch,
}

struct ByteQueue<const DEPTH: usize> {
    descriptors: [Option<QueuedMessage>; DEPTH],
    head: usize,
    len: usize,
    send_reservations: [Option<u64>; DEPTH],
    next_send_generation: u64,
    receive_reservation: Option<u64>,
    next_receive_generation: u64,
}

impl<const DEPTH: usize> ByteQueue<DEPTH> {
    fn new() -> Self {
        Self {
            descriptors: core::array::from_fn(|_| None),
            head: 0,
            len: 0,
            send_reservations: [None; DEPTH],
            next_send_generation: 0,
            receive_reservation: None,
            next_receive_generation: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn reserved_send_count(&self) -> usize {
        self.send_reservations.iter().flatten().count()
    }

    fn has_minimal_capacity(&self) -> bool {
        self.len + self.reserved_send_count() < DEPTH
    }

    fn can_admit(&self) -> bool {
        self.has_minimal_capacity()
    }

    fn head(&self) -> Option<&QueuedMessage> {
        self.descriptors[self.head].as_ref()
    }

    fn reserve_send(&mut self) -> Result<u64, ChannelError> {
        if !self.can_admit() {
            return Err(ChannelError::WouldBlock);
        }
        let generation = self
            .next_send_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ChannelError::Capacity)?;
        let slot = self
            .send_reservations
            .iter_mut()
            .find(|reservation| reservation.is_none())
            .ok_or(ChannelError::WouldBlock)?;
        self.next_send_generation = generation;
        *slot = Some(generation);
        Ok(generation)
    }

    fn cancel_send(&mut self, generation: u64) -> Result<(), ChannelError> {
        let reservation = self
            .send_reservations
            .iter_mut()
            .find(|reservation| **reservation == Some(generation))
            .ok_or(ChannelError::StalePair)?;
        *reservation = None;
        Ok(())
    }

    fn commit_send(&mut self, generation: u64, message: QueuedMessage) {
        self.cancel_send(generation).unwrap_or_else(|error| {
            panic!("reserved Channel descriptor vanished before commit: {error:?}")
        });
        assert!(
            self.len < DEPTH,
            "reserved Channel descriptor capacity drifted"
        );
        let tail = (self.head + self.len) % DEPTH;
        self.descriptors[tail] = Some(message);
        self.len += 1;
    }

    fn reserve_head(&mut self) -> Result<(u64, ChannelMessageInfo), ChannelError> {
        let message = self.head().ok_or(ChannelError::WouldBlock)?;
        let info = ChannelMessageInfo {
            required_bytes: message.byte_len,
            required_handles: u32::try_from(message.transfers.len())
                .expect("Channel transfer count fits generated u32 limit"),
        };
        if self.receive_reservation.is_some() {
            return Err(ChannelError::WouldBlock);
        }
        let generation = self
            .next_receive_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ChannelError::Capacity)?;
        self.next_receive_generation = generation;
        self.receive_reservation = Some(generation);
        Ok((generation, info))
    }

    fn cancel_receive(&mut self, generation: u64) -> Result<(), ChannelError> {
        if self.receive_reservation != Some(generation) {
            return Err(ChannelError::StalePair);
        }
        self.receive_reservation = None;
        Ok(())
    }

    fn pop_reserved(&mut self, generation: u64) -> Result<QueuedMessage, ChannelError> {
        self.cancel_receive(generation)?;
        let message = self.descriptors[self.head]
            .take()
            .ok_or(ChannelError::StalePair)?;
        self.head = (self.head + 1) % DEPTH;
        self.len -= 1;
        Ok(message)
    }

    fn pop(&mut self) -> Option<QueuedMessage> {
        assert!(
            self.receive_reservation.is_none(),
            "Channel queue drain overlapped an active receive reservation"
        );
        let message = self.descriptors[self.head].take()?;
        self.head = (self.head + 1) % DEPTH;
        self.len -= 1;
        Some(message)
    }

    fn drain_transfers(&mut self) -> [Option<HandleTransferBatch>; DEPTH] {
        let mut transfers = core::array::from_fn(|_| None);
        let mut transfer_count = 0;
        while let Some(message) = self.pop() {
            if let Some(token) = message.payload {
                PAYLOAD_POOL.release(token);
            }
            if !message.transfers.is_empty() {
                transfers[transfer_count] = Some(message.transfers);
                transfer_count += 1;
            }
        }
        self.send_reservations.fill(None);
        self.head = 0;
        transfers
    }
}

struct PairRecord<const DEPTH: usize> {
    endpoints: [Option<EndpointRecord>; 2],
    inbound: [ByteQueue<DEPTH>; 2],
}

impl<const DEPTH: usize> PairRecord<DEPTH> {
    fn new() -> Self {
        Self {
            endpoints: core::array::from_fn(|_| None),
            inbound: core::array::from_fn(|_| ByteQueue::new()),
        }
    }
}

struct PairSlot<const DEPTH: usize> {
    generation: u32,
    pair: Option<PairRecord<DEPTH>>,
}

#[must_use = "typed Channel bindings must be sealed by ObjectRegistry before publication"]
pub(crate) struct ChannelPayloadBinding {
    creation: CreationRef,
}

impl ChannelPayloadBinding {
    pub(crate) fn into_creation(self) -> CreationRef {
        self.creation
    }
}

#[must_use = "typed Channel cleanup must be consumed by ObjectRegistry"]
pub(crate) struct ChannelPayloadCleanup {
    final_release: FinalRelease,
}

impl ChannelPayloadCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

pub(crate) struct ChannelFinalization<const DEPTH: usize, const WAITERS: usize> {
    final_release: FinalRelease,
    wakes: WakeBatch<WAITERS>,
    drained_transfers: [Option<HandleTransferBatch>; DEPTH],
}

#[must_use = "Channel send reservations must commit a complete datagram or be cancelled"]
pub(crate) struct ChannelSendReservation {
    pair: ChannelPairKey,
    side: ChannelSide,
    generation: u64,
    byte_len: u32,
    payload: Option<PayloadToken>,
}

#[must_use = "received Channel transfer tokens must be published or released"]
pub(crate) struct ChannelReceivedMessage<const WAITERS: usize> {
    byte_len: usize,
    transfers: HandleTransferBatch,
    wakes: WakeBatch<WAITERS>,
}

impl<const WAITERS: usize> ChannelReceivedMessage<WAITERS> {
    pub(crate) fn into_parts(self) -> (usize, HandleTransferBatch, WakeBatch<WAITERS>) {
        (self.byte_len, self.transfers, self.wakes)
    }
}

#[must_use = "Channel finalization effects contain typed final releases that must be routed"]
pub(crate) struct ChannelCompletion<const OBJECTS: usize, const WAITERS: usize> {
    wakes: WakeBatch<WAITERS>,
    final_releases: [Option<FinalRelease>; OBJECTS],
}

impl<const OBJECTS: usize, const WAITERS: usize> ChannelCompletion<OBJECTS, WAITERS> {
    pub(crate) fn into_parts(self) -> (WakeBatch<WAITERS>, [Option<FinalRelease>; OBJECTS]) {
        (self.wakes, self.final_releases)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChannelMessageInfo {
    pub(crate) required_bytes: u32,
    pub(crate) required_handles: u32,
}

#[must_use = "Channel receive reservations must be committed or cancelled"]
#[derive(Debug)]
pub(crate) struct ChannelReceiveReservation {
    pair: ChannelPairKey,
    side: ChannelSide,
    generation: u64,
    info: ChannelMessageInfo,
}

impl ChannelReceiveReservation {
    pub(crate) const fn info(&self) -> ChannelMessageInfo {
        self.info
    }
}

#[must_use = "ready Channel pins and registrations must be released by the blocking operation owner"]
pub(crate) enum ChannelWaitOutcome {
    Ready {
        observed: DwSignals,
        pin: InternalRef,
    },
    Registered(crate::wait::WaitRegistration),
}

#[derive(Debug)]
pub(crate) struct ChannelWaitFailure {
    pub(crate) error: ChannelError,
    pub(crate) pin: InternalRef,
}

pub(crate) struct ChannelAuthority<const PAIRS: usize, const DEPTH: usize> {
    domain: u64,
    pairs: SpinMutex<[PairSlot<DEPTH>; PAIRS]>,
}

impl<const PAIRS: usize, const DEPTH: usize> ChannelAuthority<PAIRS, DEPTH> {
    pub(crate) fn new() -> Self {
        assert!(PAIRS > 0, "Channel pair pool must be nonempty");
        assert!(DEPTH > 0, "Channel queue depth must be nonzero");
        Self {
            domain: mint_channel_domain(),
            pairs: SpinMutex::new(core::array::from_fn(|_| PairSlot {
                generation: 0,
                pair: None,
            })),
        }
    }

    fn reserve_pair(&self) -> Result<ChannelPairKey, ChannelError> {
        let mut slots = self.pairs.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.pair.is_some() {
                continue;
            }
            let Some(generation) = slot
                .generation
                .checked_add(1)
                .filter(|generation| *generation != 0)
            else {
                continue;
            };
            let slot_index = u16::try_from(index).map_err(|_| ChannelError::Capacity)?;
            slot.generation = generation;
            slot.pair = Some(PairRecord::new());
            return Ok(ChannelPairKey {
                domain: self.domain,
                slot: slot_index,
                generation,
            });
        }
        Err(ChannelError::Capacity)
    }

    fn cancel_empty_pair(&self, key: ChannelPairKey) {
        let mut slots = self.pairs.lock();
        let slot = slots
            .get_mut(usize::from(key.slot))
            .expect("reserved Channel pair slot remains in range");
        assert_eq!(key.domain, self.domain, "foreign Channel pair rollback");
        assert_eq!(
            slot.generation, key.generation,
            "stale Channel pair rollback"
        );
        let pair = slot
            .pair
            .as_ref()
            .expect("reserved Channel pair remains live");
        assert!(pair.endpoints.iter().all(Option::is_none));
        assert!(pair.inbound.iter().all(ByteQueue::is_empty));
        slot.pair = None;
    }

    fn bind_pair(
        &self,
        key: ChannelPairKey,
        first: CreationRef,
        second: CreationRef,
    ) -> Result<[ChannelPayloadBinding; 2], ChannelError> {
        if first.object_type() != DW_OBJECT_TYPE_CHANNEL
            || second.object_type() != DW_OBJECT_TYPE_CHANNEL
        {
            return Err(ChannelError::InvalidEndpoint);
        }
        let mut slots = self.pairs.lock();
        let slot = slots
            .get_mut(usize::from(key.slot))
            .ok_or(ChannelError::StalePair)?;
        if key.domain != self.domain || slot.generation != key.generation {
            return Err(ChannelError::StalePair);
        }
        let pair = slot.pair.as_mut().ok_or(ChannelError::StalePair)?;
        if pair.endpoints.iter().any(Option::is_some) {
            return Err(ChannelError::StalePair);
        }
        pair.endpoints[0] = Some(EndpointRecord {
            object: first.id(),
            lease: ChannelSideLease {
                pair: key,
                side: ChannelSide::Zero,
            },
        });
        pair.endpoints[1] = Some(EndpointRecord {
            object: second.id(),
            lease: ChannelSideLease {
                pair: key,
                side: ChannelSide::One,
            },
        });
        Ok([
            ChannelPayloadBinding { creation: first },
            ChannelPayloadBinding { creation: second },
        ])
    }

    pub(crate) fn create_pair<const OBJECTS: usize>(
        &self,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> Result<([ChannelEndpointKey; 2], [HandleRef; 2]), ChannelCreateError> {
        let pair = self.reserve_pair().map_err(ChannelCreateError::Channel)?;
        let first = match registry.create(DW_OBJECT_TYPE_CHANNEL) {
            Ok(first) => first,
            Err(error) => {
                self.cancel_empty_pair(pair);
                return Err(ChannelCreateError::Registry(error));
            }
        };
        let second = match registry.create(DW_OBJECT_TYPE_CHANNEL) {
            Ok(second) => second,
            Err(error) => {
                registry.cancel_creation(first).unwrap_or_else(|failure| {
                    panic!(
                        "Channel first-object rollback drifted: {:?}",
                        failure.error()
                    )
                });
                self.cancel_empty_pair(pair);
                return Err(ChannelCreateError::Registry(error));
            }
        };
        let first_key = ChannelEndpointKey(first.id());
        let second_key = ChannelEndpointKey(second.id());
        let bindings = self
            .bind_pair(pair, first, second)
            .unwrap_or_else(|error| panic!("reserved Channel pair binding drifted: {error:?}"));
        let [first_binding, second_binding] = bindings;
        let first_bound = registry
            .finish_payload_binding(first_binding)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh Channel endpoint-0 binding rejected: {:?}",
                    failure.error()
                )
            });
        let second_bound = registry
            .finish_payload_binding(second_binding)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh Channel endpoint-1 binding rejected: {:?}",
                    failure.error()
                )
            });
        let first_handle = registry
            .bound_into_handle(first_bound)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh Channel endpoint-0 handle conversion failed: {:?}",
                    failure.error()
                )
            });
        let second_handle = registry
            .bound_into_handle(second_bound)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh Channel endpoint-1 handle conversion failed: {:?}",
                    failure.error()
                )
            });
        Ok(([first_key, second_key], [first_handle, second_handle]))
    }

    fn locate<'a>(
        &'a self,
        slots: &'a [PairSlot<DEPTH>; PAIRS],
        key: ChannelEndpointKey,
    ) -> Result<(usize, ChannelSide), ChannelError> {
        for (slot_index, slot) in slots.iter().enumerate() {
            let Some(pair) = slot.pair.as_ref() else {
                continue;
            };
            for side in [ChannelSide::Zero, ChannelSide::One] {
                let Some(endpoint) = pair.endpoints[side.index()].as_ref() else {
                    continue;
                };
                if endpoint.object == key.object_id() {
                    let lease = &endpoint.lease;
                    if lease.pair.domain != self.domain
                        || lease.pair.slot as usize != slot_index
                        || lease.pair.generation != slot.generation
                        || lease.side != side
                    {
                        return Err(ChannelError::StalePair);
                    }
                    return Ok((slot_index, side));
                }
            }
        }
        Err(ChannelError::InvalidEndpoint)
    }

    fn signals_for_pair(
        pair: &PairRecord<DEPTH>,
        side: ChannelSide,
    ) -> Result<DwSignals, ChannelError> {
        if pair.endpoints[side.index()].is_none() {
            return Err(ChannelError::InvalidEndpoint);
        }
        let peer = side.peer();
        let peer_open = pair.endpoints[peer.index()].is_some();
        let mut signals = 0_u64;
        if !pair.inbound[side.index()].is_empty() {
            signals |= DW_SIGNAL_READABLE.0;
        }
        if peer_open && pair.inbound[peer.index()].has_minimal_capacity() {
            signals |= DW_SIGNAL_WRITABLE.0;
        }
        if !peer_open {
            signals |= DW_SIGNAL_PEER_CLOSED.0;
        }
        Ok(DwSignals(signals))
    }

    pub(crate) fn current_signals(
        &self,
        key: ChannelEndpointKey,
    ) -> Result<DwSignals, ChannelError> {
        let slots = self.pairs.lock();
        let (slot_index, side) = self.locate(&slots, key)?;
        let pair = slots[slot_index]
            .pair
            .as_ref()
            .ok_or(ChannelError::StalePair)?;
        Self::signals_for_pair(pair, side)
    }

    fn collect_changed<const WAITERS: usize>(
        pair: &PairRecord<DEPTH>,
        waits: &WaitRegistry<WAITERS>,
        first: ChannelSide,
        second: ChannelSide,
    ) -> Result<WakeBatch<WAITERS>, ChannelError> {
        let mut wakes = WakeBatch::empty();
        for side in [first, second] {
            let Some(endpoint) = pair.endpoints[side.index()].as_ref() else {
                continue;
            };
            let observed = Self::signals_for_pair(pair, side)?;
            wakes.append(waits.take_ready(endpoint.object, observed));
        }
        Ok(wakes)
    }

    pub(crate) fn peer_object(
        &self,
        endpoint: ChannelEndpointKey,
    ) -> Result<ObjectId, ChannelError> {
        let slots = self.pairs.lock();
        let (slot_index, side) = self.locate(&slots, endpoint)?;
        let pair = slots[slot_index]
            .pair
            .as_ref()
            .ok_or(ChannelError::StalePair)?;
        pair.endpoints[side.peer().index()]
            .as_ref()
            .map(|peer| peer.object)
            .ok_or(ChannelError::PeerClosed)
    }

    fn transfer_closes_queue_cycle<I>(
        &self,
        slots: &[PairSlot<DEPTH>; PAIRS],
        destination: ObjectId,
        transferred_channels: I,
    ) -> Result<bool, ChannelError>
    where
        I: IntoIterator<Item = ObjectId>,
    {
        let mut pending = [0_u8; PAIRS];
        let mut visited = [0_u8; PAIRS];
        for object in transferred_channels {
            if object == destination {
                return Ok(true);
            }
            let (slot, side) = self
                .locate(slots, ChannelEndpointKey(object))
                .map_err(|_| ChannelError::StalePair)?;
            pending[slot] |= 1 << side.index();
        }

        loop {
            let mut next = None;
            for slot in 0..PAIRS {
                for side in [ChannelSide::Zero, ChannelSide::One] {
                    let side_bit = 1 << side.index();
                    if pending[slot] & side_bit != 0 {
                        pending[slot] &= !side_bit;
                        if visited[slot] & side_bit == 0 {
                            visited[slot] |= side_bit;
                            next = Some((slot, side));
                            break;
                        }
                    }
                }
                if next.is_some() {
                    break;
                }
            }
            let Some((slot, side)) = next else {
                return Ok(false);
            };
            let pair = slots[slot].pair.as_ref().ok_or(ChannelError::StalePair)?;
            let endpoint = pair.endpoints[side.index()]
                .as_ref()
                .ok_or(ChannelError::StalePair)?;
            if endpoint.object == destination {
                return Ok(true);
            }
            for message in pair.inbound[side.index()].descriptors.iter().flatten() {
                for object in message.transfers.objects_of_type(DW_OBJECT_TYPE_CHANNEL) {
                    if object == destination {
                        return Ok(true);
                    }
                    let (next_slot, next_side) = self
                        .locate(slots, ChannelEndpointKey(object))
                        .map_err(|_| ChannelError::StalePair)?;
                    let side_bit = 1 << next_side.index();
                    if visited[next_slot] & side_bit == 0 {
                        pending[next_slot] |= side_bit;
                    }
                }
            }
        }
    }

    pub(crate) fn transfer_would_close_queue_cycle<I>(
        &self,
        endpoint: ChannelEndpointKey,
        transferred_channels: I,
    ) -> Result<bool, ChannelError>
    where
        I: IntoIterator<Item = ObjectId>,
    {
        let slots = self.pairs.lock();
        let (slot, side) = self.locate(&slots, endpoint)?;
        let pair = slots[slot].pair.as_ref().ok_or(ChannelError::StalePair)?;
        let destination = pair.endpoints[side.peer().index()]
            .as_ref()
            .map(|peer| peer.object)
            .ok_or(ChannelError::PeerClosed)?;
        self.transfer_closes_queue_cycle(&slots, destination, transferred_channels)
    }

    pub(crate) fn reserve_send(
        &self,
        endpoint: ChannelEndpointKey,
        payload: &[u8],
    ) -> Result<ChannelSendReservation, ChannelError> {
        if payload.len() > DW_CHANNEL_MAX_PAYLOAD as usize {
            return Err(ChannelError::InvalidArgument);
        }
        let mut slots = self.pairs.lock();
        let (slot_index, side) = self.locate(&slots, endpoint)?;
        let slot = &mut slots[slot_index];
        let pair = slot.pair.as_mut().ok_or(ChannelError::StalePair)?;
        let peer = side.peer();
        if pair.endpoints[peer.index()].is_none() {
            return Err(ChannelError::PeerClosed);
        }
        let generation = pair.inbound[peer.index()].reserve_send()?;
        let payload_token = match PAYLOAD_POOL.allocate(payload) {
            Ok(token) => token,
            Err(error) => {
                pair.inbound[peer.index()]
                    .cancel_send(generation)
                    .expect("fresh Channel send reservation cancels exactly");
                return Err(error);
            }
        };
        Ok(ChannelSendReservation {
            pair: ChannelPairKey {
                domain: self.domain,
                slot: u16::try_from(slot_index).map_err(|_| ChannelError::Capacity)?,
                generation: slot.generation,
            },
            side,
            generation,
            byte_len: u32::try_from(payload.len())
                .expect("Channel payload fits generated u32 limit"),
            payload: payload_token,
        })
    }

    pub(crate) fn cancel_send(
        &self,
        reservation: ChannelSendReservation,
    ) -> Result<(), ChannelError> {
        let ChannelSendReservation {
            pair: pair_key,
            side,
            generation,
            byte_len: _,
            payload,
        } = reservation;
        let mut result = Ok(());
        {
            let mut slots = self.pairs.lock();
            if pair_key.domain != self.domain {
                result = Err(ChannelError::StalePair);
            } else if let Some(slot) = slots.get_mut(usize::from(pair_key.slot)) {
                if slot.generation != pair_key.generation {
                    result = Err(ChannelError::StalePair);
                } else if let Some(pair) = slot.pair.as_mut() {
                    if pair.inbound[side.peer().index()]
                        .cancel_send(generation)
                        .is_err()
                    {
                        result = Err(ChannelError::StalePair);
                    }
                } else {
                    result = Err(ChannelError::StalePair);
                }
            } else {
                result = Err(ChannelError::StalePair);
            }
        }
        if let Some(token) = payload {
            PAYLOAD_POOL.release(token);
        }
        result
    }

    #[allow(
        clippy::result_large_err,
        reason = "F6 send failure must return the exact bounded move-only transfer batch for rollback without allocation"
    )]
    pub(crate) fn commit_send<const WAITERS: usize>(
        &self,
        reservation: ChannelSendReservation,
        transfers: HandleTransferBatch,
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<WakeBatch<WAITERS>, (ChannelError, HandleTransferBatch)> {
        let ChannelSendReservation {
            pair: pair_key,
            side,
            generation,
            byte_len,
            payload,
        } = reservation;
        let mut slots = self.pairs.lock();
        if pair_key.domain != self.domain {
            if let Some(token) = payload {
                PAYLOAD_POOL.release(token);
            }
            return Err((ChannelError::StalePair, transfers));
        }
        let slot_index = usize::from(pair_key.slot);
        let Some(slot) = slots.get(slot_index) else {
            if let Some(token) = payload {
                PAYLOAD_POOL.release(token);
            }
            return Err((ChannelError::StalePair, transfers));
        };
        if slot.generation != pair_key.generation {
            if let Some(token) = payload {
                PAYLOAD_POOL.release(token);
            }
            return Err((ChannelError::StalePair, transfers));
        }
        let Some(pair) = slot.pair.as_ref() else {
            if let Some(token) = payload {
                PAYLOAD_POOL.release(token);
            }
            return Err((ChannelError::StalePair, transfers));
        };
        if pair.endpoints[side.index()].is_none() {
            let pair = slots[slot_index]
                .pair
                .as_mut()
                .expect("validated Channel pair remains live");
            let _ = pair.inbound[side.peer().index()].cancel_send(generation);
            if let Some(token) = payload {
                PAYLOAD_POOL.release(token);
            }
            return Err((ChannelError::InvalidEndpoint, transfers));
        }
        let peer = side.peer();
        if pair.endpoints[peer.index()].is_none() {
            let pair = slots[slot_index]
                .pair
                .as_mut()
                .expect("validated Channel pair remains live");
            let _ = pair.inbound[peer.index()].cancel_send(generation);
            if let Some(token) = payload {
                PAYLOAD_POOL.release(token);
            }
            return Err((ChannelError::PeerClosed, transfers));
        }
        let destination = pair.endpoints[peer.index()]
            .as_ref()
            .expect("validated Channel peer remains live")
            .object;
        match self.transfer_closes_queue_cycle(
            &slots,
            destination,
            transfers.objects_of_type(DW_OBJECT_TYPE_CHANNEL),
        ) {
            Ok(false) => {}
            Ok(true) => {
                let pair = slots[slot_index]
                    .pair
                    .as_mut()
                    .expect("validated Channel pair remains live");
                let _ = pair.inbound[peer.index()].cancel_send(generation);
                if let Some(token) = payload {
                    PAYLOAD_POOL.release(token);
                }
                return Err((ChannelError::InvalidArgument, transfers));
            }
            Err(error) => {
                let pair = slots[slot_index]
                    .pair
                    .as_mut()
                    .expect("validated Channel pair remains live");
                let _ = pair.inbound[peer.index()].cancel_send(generation);
                if let Some(token) = payload {
                    PAYLOAD_POOL.release(token);
                }
                return Err((error, transfers));
            }
        }
        let pair = slots[slot_index]
            .pair
            .as_mut()
            .expect("validated Channel pair remains live");
        pair.inbound[peer.index()].commit_send(
            generation,
            QueuedMessage {
                byte_len,
                payload,
                transfers,
            },
        );
        Ok(
            Self::collect_changed(pair, waits, peer, side).unwrap_or_else(|error| {
                panic!("committed Channel send signal collection drifted: {error:?}")
            }),
        )
    }

    pub(crate) fn send<const WAITERS: usize>(
        &self,
        endpoint: ChannelEndpointKey,
        payload: &[u8],
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<WakeBatch<WAITERS>, ChannelError> {
        let reservation = self.reserve_send(endpoint, payload)?;
        match self.commit_send(reservation, HandleTransferBatch::empty(), waits) {
            Ok(wakes) => Ok(wakes),
            Err((error, transfers)) => {
                debug_assert!(transfers.is_empty());
                Err(error)
            }
        }
    }

    pub(crate) fn peek_receive(
        &self,
        endpoint: ChannelEndpointKey,
    ) -> Result<ChannelMessageInfo, ChannelError> {
        let slots = self.pairs.lock();
        let (slot_index, side) = self.locate(&slots, endpoint)?;
        let pair = slots[slot_index]
            .pair
            .as_ref()
            .ok_or(ChannelError::StalePair)?;
        if let Some(message) = pair.inbound[side.index()].head() {
            return Ok(ChannelMessageInfo {
                required_bytes: message.byte_len,
                required_handles: u32::try_from(message.transfers.len())
                    .expect("Channel transfer count fits generated u32 limit"),
            });
        }
        if pair.endpoints[side.peer().index()].is_none() {
            Err(ChannelError::PeerClosed)
        } else {
            Err(ChannelError::WouldBlock)
        }
    }

    pub(crate) fn reserve_receive(
        &self,
        endpoint: ChannelEndpointKey,
    ) -> Result<ChannelReceiveReservation, ChannelError> {
        let mut slots = self.pairs.lock();
        let (slot_index, side) = self.locate(&slots, endpoint)?;
        let slot = &mut slots[slot_index];
        let pair = slot.pair.as_mut().ok_or(ChannelError::StalePair)?;
        if pair.inbound[side.index()].is_empty() {
            return if pair.endpoints[side.peer().index()].is_none() {
                Err(ChannelError::PeerClosed)
            } else {
                Err(ChannelError::WouldBlock)
            };
        }
        let (generation, info) = pair.inbound[side.index()].reserve_head()?;
        Ok(ChannelReceiveReservation {
            pair: ChannelPairKey {
                domain: self.domain,
                slot: u16::try_from(slot_index).map_err(|_| ChannelError::Capacity)?,
                generation: slot.generation,
            },
            side,
            generation,
            info,
        })
    }

    pub(crate) fn cancel_receive(
        &self,
        reservation: ChannelReceiveReservation,
    ) -> Result<(), ChannelError> {
        let mut slots = self.pairs.lock();
        if reservation.pair.domain != self.domain {
            return Err(ChannelError::StalePair);
        }
        let slot = slots
            .get_mut(usize::from(reservation.pair.slot))
            .ok_or(ChannelError::StalePair)?;
        if slot.generation != reservation.pair.generation {
            return Err(ChannelError::StalePair);
        }
        let pair = slot.pair.as_mut().ok_or(ChannelError::StalePair)?;
        pair.inbound[reservation.side.index()].cancel_receive(reservation.generation)
    }

    pub(crate) fn receive_reserved<const WAITERS: usize>(
        &self,
        reservation: ChannelReceiveReservation,
        output: &mut [u8],
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<ChannelReceivedMessage<WAITERS>, ChannelError> {
        let mut slots = self.pairs.lock();
        if reservation.pair.domain != self.domain {
            return Err(ChannelError::StalePair);
        }
        let slot = slots
            .get_mut(usize::from(reservation.pair.slot))
            .ok_or(ChannelError::StalePair)?;
        if slot.generation != reservation.pair.generation {
            return Err(ChannelError::StalePair);
        }
        let pair = slot.pair.as_mut().ok_or(ChannelError::StalePair)?;
        if pair.endpoints[reservation.side.index()].is_none() {
            return Err(ChannelError::InvalidEndpoint);
        }
        let required = reservation.info.required_bytes as usize;
        if output.len() < required {
            pair.inbound[reservation.side.index()].cancel_receive(reservation.generation)?;
            return Err(ChannelError::BufferTooSmall);
        }
        let message =
            pair.inbound[reservation.side.index()].pop_reserved(reservation.generation)?;
        debug_assert_eq!(message.byte_len, reservation.info.required_bytes);
        debug_assert_eq!(
            message.transfers.len(),
            reservation.info.required_handles as usize
        );
        if let Some(token) = message.payload {
            PAYLOAD_POOL.copy_and_release(token, required, output);
        }
        let wakes = Self::collect_changed(pair, waits, reservation.side.peer(), reservation.side)?;
        Ok(ChannelReceivedMessage {
            byte_len: required,
            transfers: message.transfers,
            wakes,
        })
    }

    pub(crate) fn receive_into<const WAITERS: usize>(
        &self,
        endpoint: ChannelEndpointKey,
        output: &mut [u8],
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<(usize, WakeBatch<WAITERS>), ChannelError> {
        let reservation = self.reserve_receive(endpoint)?;
        let info = reservation.info();
        if info.required_handles != 0 {
            self.cancel_receive(reservation)?;
            return Err(ChannelError::InvalidArgument);
        }
        if output.len() < info.required_bytes as usize {
            self.cancel_receive(reservation)?;
            return Err(ChannelError::BufferTooSmall);
        }
        let received = self.receive_reserved(reservation, output, waits)?;
        let (bytes, transfers, wakes) = received.into_parts();
        debug_assert!(transfers.is_empty());
        Ok((bytes, wakes))
    }

    pub(crate) fn register_wait<const WAITERS: usize>(
        &self,
        waits: &WaitRegistry<WAITERS>,
        target: ResolvedHandle,
        desired: DwSignals,
        item_index: u32,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<ChannelWaitOutcome, ChannelWaitFailure> {
        if target.object_type() != DW_OBJECT_TYPE_CHANNEL {
            return Err(ChannelWaitFailure {
                error: ChannelError::InvalidEndpoint,
                pin: target.into_internal(),
            });
        }
        if target.rights().0 & DW_RIGHT_WAIT.0 != DW_RIGHT_WAIT.0 {
            return Err(ChannelWaitFailure {
                error: ChannelError::AccessDenied,
                pin: target.into_internal(),
            });
        }
        if desired.0 == 0 || !dw_signals_are_compatible(target.object_type(), desired) {
            return Err(ChannelWaitFailure {
                error: ChannelError::InvalidArgument,
                pin: target.into_internal(),
            });
        }
        let slots = self.pairs.lock();
        let key = ChannelEndpointKey(target.object_id());
        let (slot_index, side) = match self.locate(&slots, key) {
            Ok(value) => value,
            Err(error) => {
                return Err(ChannelWaitFailure {
                    error,
                    pin: target.into_internal(),
                });
            }
        };
        let pair = match slots[slot_index].pair.as_ref() {
            Some(pair) => pair,
            None => {
                return Err(ChannelWaitFailure {
                    error: ChannelError::StalePair,
                    pin: target.into_internal(),
                });
            }
        };
        let observed = match Self::signals_for_pair(pair, side) {
            Ok(observed) => observed,
            Err(error) => {
                return Err(ChannelWaitFailure {
                    error,
                    pin: target.into_internal(),
                });
            }
        };
        if observed.0 & desired.0 != 0 {
            return Ok(ChannelWaitOutcome::Ready {
                observed,
                pin: target.into_internal(),
            });
        }
        match waits.register(target.into_internal(), desired, item_index, thread, wake) {
            Ok(registration) => Ok(ChannelWaitOutcome::Registered(registration)),
            Err(failure) => Err(ChannelWaitFailure {
                error: match failure.error() {
                    crate::wait::WaitError::Capacity => ChannelError::Capacity,
                    crate::wait::WaitError::AccessDenied => ChannelError::AccessDenied,
                    crate::wait::WaitError::InvalidSignals => ChannelError::InvalidArgument,
                    _ => ChannelError::StalePair,
                },
                pin: failure.into_pin(),
            }),
        }
    }

    pub(crate) fn take_finalization<const WAITERS: usize>(
        &self,
        final_release: FinalRelease,
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<ChannelFinalization<DEPTH, WAITERS>, (ChannelError, FinalRelease)> {
        if final_release.object_type() != DW_OBJECT_TYPE_CHANNEL {
            return Err((ChannelError::FinalizationMismatch, final_release));
        }
        let mut slots = self.pairs.lock();
        let key = ChannelEndpointKey(final_release.id());
        let (slot_index, side) = match self.locate(&slots, key) {
            Ok(value) => value,
            Err(error) => return Err((error, final_release)),
        };
        let slot = &mut slots[slot_index];
        let pair = match slot.pair.as_mut() {
            Some(pair) => pair,
            None => return Err((ChannelError::StalePair, final_release)),
        };
        let endpoint = pair.endpoints[side.index()]
            .take()
            .expect("located Channel endpoint remains live");
        if endpoint.lease.pair.domain != self.domain
            || endpoint.lease.pair.slot as usize != slot_index
            || endpoint.lease.pair.generation != slot.generation
            || endpoint.lease.side != side
        {
            return Err((ChannelError::StalePair, final_release));
        }
        let drained_transfers = pair.inbound[side.index()].drain_transfers();
        let mut wakes = WakeBatch::empty();
        let peer = side.peer();
        if let Some(peer_endpoint) = pair.endpoints[peer.index()].as_ref() {
            let observed = Self::signals_for_pair(pair, peer)
                .unwrap_or_else(|error| panic!("surviving Channel peer signal drifted: {error:?}"));
            wakes.append(waits.take_ready(peer_endpoint.object, observed));
        }
        if pair.endpoints.iter().all(Option::is_none) {
            debug_assert!(pair.inbound.iter().all(ByteQueue::is_empty));
            slot.pair = None;
        }
        Ok(ChannelFinalization {
            final_release,
            wakes,
            drained_transfers,
        })
    }

    #[cfg(test)]
    fn test_pair_key(&self, endpoint: ChannelEndpointKey) -> Result<ChannelPairKey, ChannelError> {
        let slots = self.pairs.lock();
        let (slot_index, side) = self.locate(&slots, endpoint)?;
        Ok(slots[slot_index]
            .pair
            .as_ref()
            .and_then(|pair| pair.endpoints[side.index()].as_ref())
            .expect("located endpoint exists")
            .lease
            .pair)
    }

    #[cfg(test)]
    fn test_pair_key_is_live(&self, key: ChannelPairKey) -> bool {
        if key.domain != self.domain {
            return false;
        }
        self.pairs
            .lock()
            .get(usize::from(key.slot))
            .is_some_and(|slot| slot.generation == key.generation && slot.pair.is_some())
    }

    #[cfg(test)]
    fn test_set_pair_generation(&self, slot: usize, generation: u32) {
        let mut slots = self.pairs.lock();
        let slot = slots
            .get_mut(slot)
            .expect("test pair slot remains in range");
        assert!(slot.pair.is_none(), "test only mutates a vacant pair slot");
        slot.generation = generation;
    }
}

pub(crate) fn complete_channel_finalization<
    const OBJECTS: usize,
    const DEPTH: usize,
    const WAITERS: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: ChannelFinalization<DEPTH, WAITERS>,
) -> ChannelCompletion<OBJECTS, WAITERS> {
    let ChannelFinalization {
        final_release,
        wakes,
        drained_transfers,
    } = finalization;
    registry
        .complete_payload_finalization(ChannelPayloadCleanup { final_release })
        .unwrap_or_else(|failure| {
            panic!(
                "generic Channel finalization became invalid after typed cleanup: {:?}",
                failure.error()
            )
        });

    let mut final_releases = core::array::from_fn(|_| None);
    let mut final_release_count = 0;
    for transfers in drained_transfers.into_iter().flatten() {
        for release in transfers.release(registry).into_iter().flatten() {
            assert!(
                final_release_count < OBJECTS,
                "Channel teardown produced more final releases than registry capacity"
            );
            final_releases[final_release_count] = Some(release);
            final_release_count += 1;
        }
    }
    ChannelCompletion {
        wakes,
        final_releases,
    }
}

#[cfg(test)]
mod tests;
