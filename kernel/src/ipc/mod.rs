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
    /// The shared large payload class had no free slot, which is **not** the
    /// same condition as the peer's queue being full.
    ///
    /// Card R1 could not tell which of the two refused a report send, because
    /// both arrived as `WouldBlock`. They call for different responses: a full
    /// peer queue clears when that peer receives, while pool exhaustion clears
    /// when *any* channel in the system releases a large slot.
    ///
    /// Only a payload above `SMALL_PAYLOAD_BYTES` can meet this: smaller ones
    /// are stored in their queue's own slots (`ChannelSmallPayloads`). The
    /// large class is one `static` of `PAYLOAD_POOL_SLOTS` entries shared by
    /// every pair, and each entry is `DW_CHANNEL_MAX_PAYLOAD` (64 KiB) wide, so
    /// it cannot simply be sized to cover every queueable datagram: the
    /// production geometry admits 96 pairs x 2 queues x 2 depth = 384, which at
    /// 64 KiB a slot would be 24 MiB of static memory against the 1 MiB the
    /// pool costs today.
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

/// The bound of the small size class: a payload of at most this many bytes is
/// stored in its destination queue's own small slots and never competes with
/// another channel for storage.
///
/// Every non-empty send used to take one of sixteen slots of
/// `DW_CHANNEL_MAX_PAYLOAD`, so a 64-byte record reserved 64 KiB. The pool was
/// therefore exhausted by *count*, not by bytes, and one busy channel could deny
/// an unrelated one: card R1's probe was refused at its report-send site while
/// the pool held a megabyte for sixteen tiny records.
///
/// 1 KiB is chosen against real payloads, not by round number: an `R1SP` record
/// is 64 bytes and the launch/job frame is 416. A send larger than this takes a
/// slot of the shared large class, which is still exhaustible (see
/// [`ChannelError::PayloadExhausted`]).
const SMALL_PAYLOAD_BYTES: usize = 1024;

#[derive(Clone, Copy)]
struct SmallPayloadSlot {
    generation: u64,
    in_use: bool,
    bytes: [u8; SMALL_PAYLOAD_BYTES],
}

const EMPTY_SMALL_PAYLOAD_SLOT: SmallPayloadSlot = SmallPayloadSlot {
    generation: 0,
    in_use: false,
    bytes: [0; SMALL_PAYLOAD_BYTES],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SmallPayloadToken {
    index: usize,
    generation: u64,
}

/// Small-class payload storage for one `ChannelAuthority<PAIRS, DEPTH>`.
///
/// The storage is positional: every queue of every pair owns exactly `DEPTH`
/// small slots, so the class is `PAIRS * 2 * DEPTH` slots *by type* and cannot
/// be configured apart from the authority it serves (an earlier global pool was
/// sized against a literal pair count and silently fell behind the production
/// geometry). A queue admits at most `DEPTH` reservations plus queued
/// datagrams, each holds at most one small slot of that queue, and every path
/// that retires a reservation or a datagram frees its slot under the same
/// `pairs` lock. A send that passed queue admission therefore always finds a
/// free small slot: small traffic is never refused for payload storage, and one
/// channel cannot deny another.
///
/// This is a separate object with a `const` constructor, rather than a field
/// built by `ChannelAuthority::new`, so that it lives in a `static`. At the
/// production geometry it is roughly 400 KiB, which must never be materialized
/// on a kernel stack on its way into the runtime storage.
///
/// Lock order: `ChannelAuthority::pairs`, then this store.
pub(crate) struct ChannelSmallPayloads<const PAIRS: usize, const DEPTH: usize> {
    slots: SpinMutex<[[[SmallPayloadSlot; DEPTH]; 2]; PAIRS]>,
}

impl<const PAIRS: usize, const DEPTH: usize> ChannelSmallPayloads<PAIRS, DEPTH> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: SpinMutex::new([[[EMPTY_SMALL_PAYLOAD_SLOT; DEPTH]; 2]; PAIRS]),
        }
    }

    /// Stores `payload` in a free slot of one queue, or reports that all
    /// `DEPTH` of that queue's slots are held.
    fn allocate(
        &self,
        pair_slot: usize,
        queue: ChannelSide,
        payload: &[u8],
    ) -> Option<SmallPayloadToken> {
        let mut slots = self.slots.lock();
        for (index, slot) in slots[pair_slot][queue.index()].iter_mut().enumerate() {
            if slot.in_use {
                continue;
            }
            // A u64 generation cannot wrap in the life of a kernel; a slot that
            // somehow did is skipped rather than reused ambiguously.
            let Some(generation) = slot.generation.checked_add(1) else {
                continue;
            };
            slot.generation = generation;
            slot.bytes[..payload.len()].copy_from_slice(payload);
            slot.in_use = true;
            return Some(SmallPayloadToken { index, generation });
        }
        None
    }

    fn copy_and_release(
        &self,
        pair_slot: usize,
        queue: ChannelSide,
        token: SmallPayloadToken,
        byte_len: usize,
        output: &mut [u8],
    ) {
        let mut slots = self.slots.lock();
        let slot = &mut slots[pair_slot][queue.index()][token.index];
        assert!(
            slot.in_use && slot.generation == token.generation,
            "queued small payload token became stale before receive"
        );
        output[..byte_len].copy_from_slice(&slot.bytes[..byte_len]);
        slot.in_use = false;
    }

    /// Frees the slot a token names. A token whose queue was drained since it
    /// was issued (its endpoint was finalized under an outstanding send
    /// reservation) no longer owns anything; the generation tells, and such a
    /// release does nothing.
    fn release(&self, pair_slot: usize, queue: ChannelSide, token: SmallPayloadToken) {
        let mut slots = self.slots.lock();
        if let Some(slot) = slots
            .get_mut(pair_slot)
            .and_then(|pair| pair[queue.index()].get_mut(token.index))
            && slot.in_use
            && slot.generation == token.generation
        {
            slot.in_use = false;
        }
    }

    /// Frees every slot of one queue. Draining a queue discards its datagrams
    /// and its send reservations together, so nothing may keep a slot of it.
    fn reset_queue(&self, pair_slot: usize, queue: ChannelSide) {
        let mut slots = self.slots.lock();
        for slot in &mut slots[pair_slot][queue.index()] {
            slot.in_use = false;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LargePayloadToken {
    slot: u8,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadToken {
    Small(SmallPayloadToken),
    Large(LargePayloadToken),
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

/// The large size class: `PAYLOAD_POOL_SLOTS` slots of `DW_CHANNEL_MAX_PAYLOAD`
/// shared by every channel of every authority, for payloads above
/// `SMALL_PAYLOAD_BYTES`. Unlike the small class it can be exhausted, and one
/// channel's large traffic can then refuse another's.
struct LargePayloadPool {
    slots: SpinMutex<[PayloadSlot; PAYLOAD_POOL_SLOTS]>,
}

impl LargePayloadPool {
    const fn new() -> Self {
        Self {
            slots: SpinMutex::new([EMPTY_PAYLOAD_SLOT; PAYLOAD_POOL_SLOTS]),
        }
    }

    fn allocate(&self, payload: &[u8]) -> Result<LargePayloadToken, ChannelError> {
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
            return Ok(LargePayloadToken {
                slot: u8::try_from(index).expect("payload pool fits u8 token"),
                generation,
            });
        }
        crate::debug::liveness::note_channel_refusal(
            crate::debug::liveness::ChannelRefusal::PayloadExhausted,
        );
        Err(ChannelError::PayloadExhausted)
    }

    fn copy_and_release(&self, token: LargePayloadToken, byte_len: usize, output: &mut [u8]) {
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

    fn release(&self, token: LargePayloadToken) {
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

static LARGE_PAYLOAD_POOL: LargePayloadPool = LargePayloadPool::new();

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
            crate::debug::liveness::note_channel_refusal(
                crate::debug::liveness::ChannelRefusal::QueueFull,
            );
            return Err(ChannelError::WouldBlock);
        }
        let generation = self
            .next_send_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ChannelError::Capacity)?;
        let Some(slot) = self
            .send_reservations
            .iter_mut()
            .find(|reservation| reservation.is_none())
        else {
            crate::debug::liveness::note_channel_refusal(
                crate::debug::liveness::ChannelRefusal::QueueFull,
            );
            return Err(ChannelError::WouldBlock);
        };
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
            // The caller resets this queue's small slots as a whole.
            if let Some(PayloadToken::Large(token)) = message.payload {
                LARGE_PAYLOAD_POOL.release(token);
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

pub(crate) struct ChannelFinalization<const DEPTH: usize> {
    final_release: FinalRelease,
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
    Ready { pin: InternalRef },
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
    /// Typed by the same `PAIRS` and `DEPTH`, so the small class always covers
    /// every datagram this authority's queues can hold.
    small: &'static ChannelSmallPayloads<PAIRS, DEPTH>,
}

impl<const PAIRS: usize, const DEPTH: usize> ChannelAuthority<PAIRS, DEPTH> {
    /// Builds an authority over its small-payload storage. The storage must be
    /// dedicated to this authority: its slots are addressed by pair slot.
    pub(crate) fn with_small_payloads(small: &'static ChannelSmallPayloads<PAIRS, DEPTH>) -> Self {
        assert!(PAIRS > 0, "Channel pair pool must be nonempty");
        assert!(DEPTH > 0, "Channel queue depth must be nonzero");
        Self {
            small,
            domain: mint_channel_domain(),
            pairs: SpinMutex::new(core::array::from_fn(|_| PairSlot {
                generation: 0,
                pair: None,
            })),
        }
    }

    /// Stores a datagram's bytes for a send that already holds a reservation in
    /// `queue` of `pair_slot`. An empty payload takes no storage; one within the
    /// small bound takes one of that queue's own slots, which the reservation
    /// guarantees is free; a larger one competes for the shared large class.
    fn store_payload(
        &self,
        pair_slot: usize,
        queue: ChannelSide,
        payload: &[u8],
    ) -> Result<Option<PayloadToken>, ChannelError> {
        if payload.is_empty() {
            return Ok(None);
        }
        if payload.len() <= SMALL_PAYLOAD_BYTES {
            let small = self.small.allocate(pair_slot, queue, payload);
            debug_assert!(
                small.is_some(),
                "a reserved Channel send found none of its queue's small slots free"
            );
            if let Some(token) = small {
                return Ok(Some(PayloadToken::Small(token)));
            }
            // Unreachable while the reservation invariant holds. Falling back
            // keeps a broken invariant a refusal at worst, never a panic.
        }
        LARGE_PAYLOAD_POOL
            .allocate(payload)
            .map(|token| Some(PayloadToken::Large(token)))
    }

    /// Frees the storage of a send reservation of this authority's `queue`.
    fn release_payload(&self, pair_slot: usize, queue: ChannelSide, payload: Option<PayloadToken>) {
        match payload {
            Some(PayloadToken::Small(token)) => self.small.release(pair_slot, queue, token),
            Some(PayloadToken::Large(token)) => LARGE_PAYLOAD_POOL.release(token),
            None => {}
        }
    }

    /// Frees what can be freed of a reservation another authority issued: the
    /// large class is global, while a small slot belongs to that authority's
    /// storage, where it stays paired with the queue reservation this one
    /// cannot cancel either.
    fn release_foreign_payload(payload: Option<PayloadToken>) {
        if let Some(PayloadToken::Large(token)) = payload {
            LARGE_PAYLOAD_POOL.release(token);
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
        let payload_token = match self.store_payload(slot_index, peer, payload) {
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
            // Inside the lock, so the queue slot and the payload slot of one
            // reservation are never seen free separately.
            if pair_key.domain == self.domain {
                self.release_payload(usize::from(pair_key.slot), side.peer(), payload);
            } else {
                Self::release_foreign_payload(payload);
            }
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
            Self::release_foreign_payload(payload);
            return Err((ChannelError::StalePair, transfers));
        }
        let slot_index = usize::from(pair_key.slot);
        let Some(slot) = slots.get(slot_index) else {
            self.release_payload(slot_index, side.peer(), payload);
            return Err((ChannelError::StalePair, transfers));
        };
        if slot.generation != pair_key.generation {
            self.release_payload(slot_index, side.peer(), payload);
            return Err((ChannelError::StalePair, transfers));
        }
        let Some(pair) = slot.pair.as_ref() else {
            self.release_payload(slot_index, side.peer(), payload);
            return Err((ChannelError::StalePair, transfers));
        };
        if pair.endpoints[side.index()].is_none() {
            let pair = slots[slot_index]
                .pair
                .as_mut()
                .expect("validated Channel pair remains live");
            let _ = pair.inbound[side.peer().index()].cancel_send(generation);
            self.release_payload(slot_index, side.peer(), payload);
            return Err((ChannelError::InvalidEndpoint, transfers));
        }
        let peer = side.peer();
        if pair.endpoints[peer.index()].is_none() {
            let pair = slots[slot_index]
                .pair
                .as_mut()
                .expect("validated Channel pair remains live");
            let _ = pair.inbound[peer.index()].cancel_send(generation);
            self.release_payload(slot_index, side.peer(), payload);
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
                self.release_payload(slot_index, peer, payload);
                return Err((ChannelError::InvalidArgument, transfers));
            }
            Err(error) => {
                let pair = slots[slot_index]
                    .pair
                    .as_mut()
                    .expect("validated Channel pair remains live");
                let _ = pair.inbound[peer.index()].cancel_send(generation);
                self.release_payload(slot_index, peer, payload);
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

    #[cfg(test)]
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

    #[cfg(test)]
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
        match message.payload {
            Some(PayloadToken::Small(token)) => self.small.copy_and_release(
                usize::from(reservation.pair.slot),
                reservation.side,
                token,
                required,
                output,
            ),
            Some(PayloadToken::Large(token)) => {
                LARGE_PAYLOAD_POOL.copy_and_release(token, required, output);
            }
            None => {}
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
        wakes: &mut WakeBatch<WAITERS>,
    ) -> Result<ChannelFinalization<DEPTH>, (ChannelError, FinalRelease)> {
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
        self.small.reset_queue(slot_index, side);
        let peer = side.peer();
        if let Some(peer_endpoint) = pair.endpoints[peer.index()].as_ref() {
            let observed = Self::signals_for_pair(pair, peer)
                .unwrap_or_else(|error| panic!("surviving Channel peer signal drifted: {error:?}"));
            waits.take_ready_into(peer_endpoint.object, observed, wakes);
        }
        if pair.endpoints.iter().all(Option::is_none) {
            debug_assert!(pair.inbound.iter().all(ByteQueue::is_empty));
            slot.pair = None;
        }
        Ok(ChannelFinalization {
            final_release,
            drained_transfers,
        })
    }

    /// Host tests build many short-lived authorities; each gets its own leaked
    /// small-payload storage instead of a hand-written `static`.
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        extern crate std;
        Self::with_small_payloads(std::boxed::Box::leak(std::boxed::Box::new(
            ChannelSmallPayloads::new(),
        )))
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

/// Completes a Channel endpoint's generic finalization, then releases the
/// handles still queued toward it, giving each final release they produce to
/// `final_release_sink` (rather than collecting them in a registry-sized
/// array, DW2 plan §10.2 item 2).
pub(crate) fn complete_channel_finalization<const OBJECTS: usize, const DEPTH: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: ChannelFinalization<DEPTH>,
    mut final_release_sink: impl FnMut(FinalRelease),
) {
    let ChannelFinalization {
        final_release,
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

    for transfers in drained_transfers.into_iter().flatten() {
        for release in transfers.release(registry).into_iter().flatten() {
            final_release_sink(release);
        }
    }
}

#[cfg(test)]
mod test_vec {
    extern crate std;
    pub(crate) use std::vec::Vec;
}

/// Test convenience: completes a Channel finalization and collects the final
/// releases the drained transfers produce.
#[cfg(test)]
pub(crate) fn collect_channel_releases<const OBJECTS: usize, const DEPTH: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: ChannelFinalization<DEPTH>,
) -> test_vec::Vec<Option<FinalRelease>> {
    let mut releases = test_vec::Vec::new();
    complete_channel_finalization(registry, finalization, |release| {
        releases.push(Some(release));
    });
    releases
}

#[cfg(test)]
mod tests;
