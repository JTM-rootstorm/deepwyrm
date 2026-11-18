//! Generic DW0-D kernel-object identity and strong-lifetime registry.
//!
//! `ObjectId` is identity only. Strong lifetime authority is represented by
//! move-only reference tokens that can be minted or transformed only here.

use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) mod charge;
#[cfg(deepwyrm_integrated)]
mod finalizer;
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live facade queues teardowns")
)]
pub(crate) mod slot_queue;
#[cfg(deepwyrm_integrated)]
#[allow(
    unused_imports,
    reason = "DW0-E2 exports the typed finalizer router ahead of E5 close/teardown consumers"
)]
pub(crate) use finalizer::PayloadFinalizer;

use deepwyrm_abi::{DW_OBJECT_TYPE_MEMORY_OBJECT, DwObjectType, dw_object_compatible_rights};

static NEXT_REGISTRY_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_registry_domain() -> u64 {
    NEXT_REGISTRY_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |domain| {
            domain.checked_add(1).filter(|next| *next != 0)
        })
        .expect("object-registry domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectId {
    domain: u64,
    raw: u64,
}
impl ObjectId {
    const fn new(domain: u64, raw: u64) -> Self {
        Self { domain, raw }
    }

    pub(crate) const fn generation(self) -> u64 {
        self.raw >> 32
    }

    /// Registry-local identity word for diagnostic reporting only.
    ///
    /// Reset card R1B mirrors this into the lock-free liveness snapshot so a
    /// stalled runtime can name its current Process/Thread without acquiring
    /// the authority under investigation. Equality and every authority check
    /// continue to use the complete private domain-plus-raw identity; this
    /// projection is never an authority token and is never compared to decide
    /// access. The selected runtimes have one registry domain.
    pub(crate) const fn diagnostic_identity(self) -> u64 {
        self.raw
    }

    /// Stable registry-local identity word used only by fixed test evidence.
    /// Equality and authority checks continue to use the complete private
    /// domain-plus-raw identity; the selected D6 runtime has one registry.
    #[cfg(test)]
    pub(crate) const fn evidence_identity(self) -> u64 {
        self.raw
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectRegistryError {
    InvalidObjectType,
    Capacity,
    ForeignReference,
    StaleReference,
    ObjectTypeMismatch,
    ReferenceCountExhausted,
    ReferenceCountUnderflow,
    NotFinalizing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceKind {
    Handle,
    Internal,
}
#[must_use = "creation references must be installed, converted, or released"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CreationRef {
    id: ObjectId,
    object_type: DwObjectType,
}

impl CreationRef {
    pub(crate) const fn id(&self) -> ObjectId {
        self.id
    }

    pub(crate) const fn object_type(&self) -> DwObjectType {
        self.object_type
    }
}

#[must_use = "bound creations must become a first handle/internal owner or be rolled back through typed payload cleanup"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BoundCreation {
    reference: CreationRef,
}

impl BoundCreation {
    #[cfg_attr(
        deepwyrm_production_product,
        allow(
            dead_code,
            reason = "used by host tests and by the compile-fail UI contracts, which build this file without cfg(test)"
        )
    )]
    pub(crate) const fn id(&self) -> ObjectId {
        self.reference.id()
    }
    #[cfg_attr(
        deepwyrm_production_product,
        allow(
            dead_code,
            reason = "used by host tests and by the compile-fail UI contracts, which build this file without cfg(test)"
        )
    )]
    pub(crate) const fn object_type(&self) -> DwObjectType {
        self.reference.object_type()
    }
}

mod payload_binding_seal {
    use super::CreationRef;
    pub trait Sealed {
        fn into_creation(self) -> CreationRef;
    }
}

pub(crate) trait PayloadBindingProof: payload_binding_seal::Sealed {}

mod payload_cleanup_seal {
    use super::FinalRelease;
    pub trait Sealed {
        fn into_final_release(self) -> FinalRelease;
    }
}

pub(crate) trait PayloadCleanupProof: payload_cleanup_seal::Sealed {}

#[must_use = "handle references own one generic object lifetime reference"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HandleRef {
    id: ObjectId,
    object_type: DwObjectType,
}
impl HandleRef {
    pub(crate) const fn id(&self) -> ObjectId {
        self.id
    }

    pub(crate) const fn object_type(&self) -> DwObjectType {
        self.object_type
    }
}

#[must_use = "internal references own one generic object lifetime reference"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InternalRef {
    id: ObjectId,
    object_type: DwObjectType,
}

impl InternalRef {
    pub(crate) const fn id(&self) -> ObjectId {
        self.id
    }

    pub(crate) const fn object_type(&self) -> DwObjectType {
        self.object_type
    }
}
#[must_use = "final-release authority must complete subsystem cleanup"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FinalRelease {
    id: ObjectId,
    object_type: DwObjectType,
}

impl FinalRelease {
    pub(crate) const fn id(&self) -> ObjectId {
        self.id
    }

    pub(crate) const fn object_type(&self) -> DwObjectType {
        self.object_type
    }

    #[cfg(test)]
    pub(crate) const fn duplicate_for_negative_test(&self) -> Self {
        Self {
            id: self.id,
            object_type: self.object_type,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReferenceError<T> {
    error: ObjectRegistryError,
    reference: T,
}

impl<T> ReferenceError<T> {
    pub(crate) const fn error(&self) -> ObjectRegistryError {
        self.error
    }

    pub(crate) fn into_reference(self) -> T {
        self.reference
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveObject {
    object_type: DwObjectType,
    handle_refs: u32,
    internal_refs: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Vacant,
    Live(LiveObject),
    Finalizing(DwObjectType),
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectSlot {
    generation: u32,
    state: SlotState,
}

const EMPTY_SLOT: ObjectSlot = ObjectSlot {
    generation: 0,
    state: SlotState::Vacant,
};
/// Page reservations the registry holds at once: each held by a Thread for
/// its create in flight, or by an owed backing for the frames it holds
/// until freed (DW2 §12.11 part 2 item 8). At least the kernel's
/// thread-stack capacity, which bounds live threads (asserted in `lib.rs`).
/// Keyed by thread, not CPU, since a create can yield between reserving and
/// creating and resume elsewhere (DW2 M5 §10.8 D1). Owed backings hold
/// slots too, so a create can find every slot held: it is then refused.
pub(crate) const RESERVATION_THREADS: usize = 64;

/// What holds a page reservation (DW2 §12.11 part 2 item 8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReservationHolder {
    /// A Thread's create in flight.
    Thread(ObjectId),
    /// An owed backing, by its root's raw identity: the frames of an
    /// abandoned create, charged until freed.
    OwedBacking(u64),
}

pub(crate) struct ObjectRegistry<const CAPACITY: usize> {
    domain: u64,
    slots: [ObjectSlot; CAPACITY],
    /// Per slot, the limited TaskGroups its creator was charged to.
    tags: [charge::ChargeTag; CAPACITY],
    /// Per slot, its weight under the page class: the pages of a RAM-backed
    /// MemoryObject, zero for everything else. Reset with the tag.
    pages: [u64; CAPACITY],
    /// Per creating thread, pages a MemoryObjectCreate admitted before
    /// allocating its frames outside the global lock, charged to its tag
    /// until the hold that creates the object (DW2 §7.3 R7). Concurrent
    /// creates see each other's, so they cannot together allocate past a
    /// limit. A create abandoned with frames still held passes its
    /// reservation to its owed backing, which keeps it until they are freed
    /// (DW2 §12.11 part 2 item 8).
    reserved: [Option<(ReservationHolder, charge::ChargeTag, u64)>; RESERVATION_THREADS],
    /// Per slot, for the group that holds it, the pages charged to it: the
    /// weights of the live and finalizing slots whose tag names it, and the
    /// reservations whose tag names it (DW2 §13.12 part a). Every write
    /// goes through [`Self::change_usage`]; zeroed when the slot is
    /// released, so whatever holds the slot next starts from zero.
    usage_pages: [u64; CAPACITY],
    /// Per slot, for the group that holds it, the live and finalizing
    /// objects of each object class charged to it.
    usage_objects: [[u16; charge::OBJECT_CLASSES]; CAPACITY],
    /// The part of `usage_pages` held by finalizing objects and by owed
    /// backings' reservations: freed by owed work, not by a live owner.
    finalizing_pages: [u64; CAPACITY],
    /// The part of `usage_objects` that is finalizing.
    finalizing_objects: [[u16; charge::OBJECT_CLASSES]; CAPACITY],
    /// MemoryObject slots whose last handle is gone while internal
    /// references remain, noted at each such release for the release-on-
    /// unmap step (DW2 §10.9 item 4). A slot is queued at most once: its
    /// flag is set on push and cleared only when its entry is popped, so
    /// the ring cannot overflow whatever finalizes or reuses the slot
    /// meanwhile. A popped slot is judged by whatever occupies it then.
    notices: [u32; CAPACITY],
    notice_head: usize,
    notice_len: usize,
    notice_queued: [bool; CAPACITY],
    /// TaskGroups whose kept usage was compared with the scan as their slot
    /// was released, and the figures that differed then (DW2 §13.12 part
    /// a): the groups that end before power-off are checked too.
    ended_groups: usize,
    ended_mismatches: usize,
}

impl<const CAPACITY: usize> ObjectRegistry<CAPACITY> {
    pub(crate) fn new() -> Self {
        const {
            assert!(
                CAPACITY <= u16::MAX as usize,
                "a group's object counts fit u16 only while the registry does"
            );
        }
        Self {
            domain: mint_registry_domain(),
            slots: [EMPTY_SLOT; CAPACITY],
            tags: [charge::ChargeTag::EMPTY; CAPACITY],
            pages: [0; CAPACITY],
            reserved: [None; RESERVATION_THREADS],
            usage_pages: [0; CAPACITY],
            usage_objects: [[0; charge::OBJECT_CLASSES]; CAPACITY],
            finalizing_pages: [0; CAPACITY],
            finalizing_objects: [[0; charge::OBJECT_CLASSES]; CAPACITY],
            notices: [0; CAPACITY],
            notice_head: 0,
            notice_len: 0,
            notice_queued: [false; CAPACITY],
            ended_groups: 0,
            ended_mismatches: 0,
        }
    }

    fn push_notice(&mut self, slot: usize) {
        if self.notice_queued[slot] {
            return;
        }
        assert!(
            self.notice_len < CAPACITY,
            "a deduplicated notice ring cannot overflow"
        );
        self.notices[(self.notice_head + self.notice_len) % CAPACITY] =
            u32::try_from(slot).expect("registry slots fit u32");
        self.notice_len += 1;
        self.notice_queued[slot] = true;
    }

    /// Whether any release-on-unmap notice is queued (DW2 §10.9 item 4).
    pub(crate) fn memory_notices_pending(&self) -> bool {
        self.notice_len != 0
    }

    /// Pops the oldest MemoryObject release notice: `None` when there is
    /// none, `Some(None)` when its slot no longer holds a live MemoryObject,
    /// else that object.
    pub(crate) fn pop_memory_notice(&mut self) -> Option<Option<ObjectId>> {
        if self.notice_len == 0 {
            return None;
        }
        let slot = self.notices[self.notice_head] as usize;
        self.notice_head = (self.notice_head + 1) % CAPACITY;
        self.notice_len -= 1;
        self.notice_queued[slot] = false;
        let entry = self.slots[slot];
        Some(match entry.state {
            SlotState::Live(live) if live.object_type == DW_OBJECT_TYPE_MEMORY_OBJECT => {
                encode_object_id(slot, entry.generation).map(|raw| ObjectId::new(self.domain, raw))
            }
            SlotState::Vacant
            | SlotState::Live(_)
            | SlotState::Finalizing(_)
            | SlotState::Retired => None,
        })
    }

    /// Queues `id` again, for a release that needs more steps. Does nothing
    /// for a stale identity.
    pub(crate) fn requeue_memory_notice(&mut self, id: ObjectId) {
        if self.live_reference_counts(id).is_some()
            && let Ok(slot) = self.reference_slot(id)
        {
            self.push_notice(slot);
        }
    }

    /// A live object's handle and internal reference counts; `None` unless
    /// `id` names a `Live` slot of its generation.
    pub(crate) fn live_reference_counts(&self, id: ObjectId) -> Option<(u32, u32)> {
        let slot = self.reference_slot(id).ok()?;
        let (_, generation) = decode_object_id(id.raw)?;
        let entry = &self.slots[slot];
        if entry.generation != generation {
            return None;
        }
        match entry.state {
            SlotState::Live(live) => Some((live.handle_refs, live.internal_refs)),
            SlotState::Vacant | SlotState::Finalizing(_) | SlotState::Retired => None,
        }
    }

    /// Charges `pages` to `tag` for `thread`'s create in flight, replacing
    /// any reservation that thread held. `false` when every slot is held by
    /// another thread or by an owed backing: the create is then refused.
    #[must_use]
    pub(crate) fn reserve_pages(
        &mut self,
        thread: ObjectId,
        tag: charge::ChargeTag,
        pages: u64,
    ) -> bool {
        self.release_reserved_pages(thread);
        self.reserve_for(ReservationHolder::Thread(thread), tag, pages)
    }

    /// Ends `thread`'s reservation, if it holds one. An owed backing's,
    /// even one re-keyed from this thread, is not touched.
    pub(crate) fn release_reserved_pages(&mut self, thread: ObjectId) {
        self.end_reservation(ReservationHolder::Thread(thread));
    }

    /// Passes `thread`'s reservation, in place with its slot and tag, to
    /// the owed backing `backing` (a root's raw identity), now charged
    /// `pages`: the frames of `thread`'s abandoned create (DW2 §12.11 part
    /// 2 item 8). `false` if `thread` holds none.
    #[must_use]
    pub(crate) fn rekey_reservation_to_owed_backing(
        &mut self,
        thread: ObjectId,
        backing: u64,
        pages: u64,
    ) -> bool {
        match self
            .reserved
            .iter_mut()
            .flatten()
            .find(|(holder, _, _)| *holder == ReservationHolder::Thread(thread))
        {
            Some(reservation) => {
                let (_, tag, held) = *reservation;
                reservation.0 = ReservationHolder::OwedBacking(backing);
                reservation.2 = pages;
                let operation = "rekey_reservation_to_owed_backing";
                self.change_usage(
                    tag,
                    Direction::Remove,
                    None,
                    held,
                    Figures::Usage,
                    operation,
                );
                self.change_usage(
                    tag,
                    Direction::Add,
                    None,
                    pages,
                    Figures::UsageAndFinalizing,
                    operation,
                );
                true
            }
            None => false,
        }
    }

    /// Charges `pages` to `tag` for the owed backing `backing` when the
    /// Thread whose create held its frames no longer holds a reservation
    /// in this hold (a create rolled back). The frames are already held,
    /// so no limit refuses it; `false` only when no slot is free.
    #[must_use]
    pub(crate) fn reserve_owed_backing_pages(
        &mut self,
        backing: u64,
        tag: charge::ChargeTag,
        pages: u64,
    ) -> bool {
        self.reserve_for(ReservationHolder::OwedBacking(backing), tag, pages)
    }

    /// Lowers the owed backing `backing`'s reservation by `pages` its
    /// release freed. Refuses one it does not hold, or a reservation
    /// smaller than `pages`.
    pub(crate) fn lower_owed_backing_pages(
        &mut self,
        backing: u64,
        pages: u64,
    ) -> Result<(), ObjectRegistryError> {
        let reservation = self
            .reserved
            .iter_mut()
            .flatten()
            .find(|(holder, _, _)| *holder == ReservationHolder::OwedBacking(backing))
            .ok_or(ObjectRegistryError::StaleReference)?;
        reservation.2 = reservation
            .2
            .checked_sub(pages)
            .ok_or(ObjectRegistryError::ReferenceCountUnderflow)?;
        let tag = reservation.1;
        self.change_usage(
            tag,
            Direction::Remove,
            None,
            pages,
            Figures::UsageAndFinalizing,
            "lower_owed_backing_pages",
        );
        Ok(())
    }

    /// Ends the owed backing `backing`'s reservation once its root is
    /// freed.
    pub(crate) fn end_owed_backing_reservation(&mut self, backing: u64) {
        self.end_reservation(ReservationHolder::OwedBacking(backing));
    }

    fn reserve_for(
        &mut self,
        holder: ReservationHolder,
        tag: charge::ChargeTag,
        pages: u64,
    ) -> bool {
        match self.reserved.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some((holder, tag, pages));
                self.change_usage(
                    tag,
                    Direction::Add,
                    None,
                    pages,
                    reservation_figures(holder),
                    "reserve",
                );
                true
            }
            None => false,
        }
    }

    fn end_reservation(&mut self, holder: ReservationHolder) {
        for index in 0..RESERVATION_THREADS {
            let Some((owner, tag, pages)) = self.reserved[index] else {
                continue;
            };
            if owner == holder {
                self.reserved[index] = None;
                self.change_usage(
                    tag,
                    Direction::Remove,
                    None,
                    pages,
                    reservation_figures(owner),
                    "end_reservation",
                );
            }
        }
    }

    /// The slot `group` holds now: `None` when the identity is of another
    /// registry, out of range, of an older generation, or its slot is
    /// vacant or retired.
    fn held_group_slot(&self, group: ObjectId) -> Option<usize> {
        let slot = self.reference_slot(group).ok()?;
        let (_, generation) = decode_object_id(group.raw)?;
        let entry = &self.slots[slot];
        (entry.generation == generation
            && matches!(entry.state, SlotState::Live(_) | SlotState::Finalizing(_)))
        .then_some(slot)
    }

    /// The one rule for every write of usage (DW2 §13.12 part a): one
    /// object of `class` (if any) and `pages` pages are added to or removed
    /// from `figures` of each group `tag` names, at that group's slot,
    /// only while the slot holds that group; a group gone changes nothing.
    /// A group named twice is changed once, as a scan counts it once. An
    /// overflow or underflow is a bookkeeping bug and panics naming
    /// `operation`.
    fn change_usage(
        &mut self,
        tag: charge::ChargeTag,
        direction: Direction,
        class: Option<usize>,
        pages: u64,
        figures: Figures,
        operation: &'static str,
    ) {
        if class.is_none() && pages == 0 {
            return;
        }
        for (index, group) in tag.groups().enumerate() {
            if tag.groups().take(index).any(|earlier| earlier == group) {
                continue;
            }
            let Some(slot) = self.held_group_slot(group) else {
                continue;
            };
            if figures != Figures::Finalizing {
                apply_usage_change(
                    &mut self.usage_pages[slot],
                    &mut self.usage_objects[slot],
                    direction,
                    class,
                    pages,
                    operation,
                    "usage",
                );
            }
            if figures != Figures::Usage {
                apply_usage_change(
                    &mut self.finalizing_pages[slot],
                    &mut self.finalizing_objects[slot],
                    direction,
                    class,
                    pages,
                    operation,
                    "finalizing",
                );
            }
        }
    }

    /// The object class of the object in `slot`, live or finalizing.
    fn slot_class(&self, slot: usize) -> Option<usize> {
        match self.slots[slot].state {
            SlotState::Live(live) => charge::object_class(live.object_type),
            SlotState::Finalizing(object_type) => charge::object_class(object_type),
            SlotState::Vacant | SlotState::Retired => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_slot_generations(&self) -> [u32; CAPACITY] {
        core::array::from_fn(|slot| self.slots[slot].generation)
    }

    /// Every slot's generation, state and reference counts, for tests that
    /// prove an operation left the registry exactly as it found it.
    #[cfg(test)]
    pub(crate) fn test_snapshot(&self) -> impl PartialEq + core::fmt::Debug + use<CAPACITY> {
        self.slots
    }

    pub(crate) fn create(
        &mut self,
        object_type: DwObjectType,
    ) -> Result<CreationRef, ObjectRegistryError> {
        if dw_object_compatible_rights(object_type).0 == 0 {
            return Err(ObjectRegistryError::InvalidObjectType);
        }

        for slot in 0..CAPACITY {
            if !matches!(self.slots[slot].state, SlotState::Vacant) {
                continue;
            }
            let Some(generation) = next_generation(self.slots[slot].generation) else {
                self.slots[slot].state = SlotState::Retired;
                continue;
            };
            let Some(raw) = encode_object_id(slot, generation) else {
                self.slots[slot].state = SlotState::Retired;
                continue;
            };
            self.tags[slot] = charge::ChargeTag::EMPTY;
            self.pages[slot] = 0;
            self.slots[slot] = ObjectSlot {
                generation,
                state: SlotState::Live(LiveObject {
                    object_type,
                    handle_refs: 0,
                    internal_refs: 1,
                }),
            };
            return Ok(CreationRef {
                id: ObjectId::new(self.domain, raw),
                object_type,
            });
        }

        Err(ObjectRegistryError::Capacity)
    }
    /// Records the quota charge of a live object just created for a process
    /// (F4 DW1-F4-M1). The tag lives exactly as long as the slot does.
    pub(crate) fn set_charge_tag(
        &mut self,
        id: ObjectId,
        tag: charge::ChargeTag,
    ) -> Result<(), ObjectRegistryError> {
        let slot = self.reference_slot(id)?;
        let generation = decode_object_id(id.raw)
            .ok_or(ObjectRegistryError::StaleReference)?
            .1;
        if self.slots[slot].generation != generation
            || !matches!(self.slots[slot].state, SlotState::Live(_))
        {
            return Err(ObjectRegistryError::StaleReference);
        }
        let class = self.slot_class(slot);
        let pages = self.pages[slot];
        let old = self.tags[slot];
        self.change_usage(
            old,
            Direction::Remove,
            class,
            pages,
            Figures::Usage,
            "set_charge_tag",
        );
        self.tags[slot] = tag;
        self.change_usage(
            tag,
            Direction::Add,
            class,
            pages,
            Figures::Usage,
            "set_charge_tag",
        );
        Ok(())
    }

    /// Records a live object's weight under the page class (D6). Like the
    /// tag, it lives exactly as long as the slot.
    pub(crate) fn set_charge_pages(
        &mut self,
        id: ObjectId,
        pages: u64,
    ) -> Result<(), ObjectRegistryError> {
        let slot = self.reference_slot(id)?;
        let generation = decode_object_id(id.raw)
            .ok_or(ObjectRegistryError::StaleReference)?
            .1;
        if self.slots[slot].generation != generation
            || !matches!(self.slots[slot].state, SlotState::Live(_))
        {
            return Err(ObjectRegistryError::StaleReference);
        }
        let old = self.pages[slot];
        self.pages[slot] = pages;
        let (direction, difference) = if pages >= old {
            (Direction::Add, pages - old)
        } else {
            (Direction::Remove, old - pages)
        };
        self.change_usage(
            self.tags[slot],
            direction,
            None,
            difference,
            Figures::Usage,
            "set_charge_pages",
        );
        Ok(())
    }

    /// Lowers a finalizing object's weight by `frames` as a stepped
    /// finalization frees them (DW2 §10.12 item 3), so its groups' usage
    /// falls step by step. Refuses a slot that is not finalizing that
    /// object, or a weight smaller than `frames`.
    pub(crate) fn lower_finalizing_charge_pages(
        &mut self,
        id: ObjectId,
        frames: u64,
    ) -> Result<(), ObjectRegistryError> {
        let slot = self.reference_slot(id)?;
        let generation = decode_object_id(id.raw)
            .ok_or(ObjectRegistryError::StaleReference)?
            .1;
        if self.slots[slot].generation != generation
            || !matches!(self.slots[slot].state, SlotState::Finalizing(_))
        {
            return Err(ObjectRegistryError::NotFinalizing);
        }
        self.pages[slot] = self.pages[slot]
            .checked_sub(frames)
            .ok_or(ObjectRegistryError::ReferenceCountUnderflow)?;
        self.change_usage(
            self.tags[slot],
            Direction::Remove,
            None,
            frames,
            Figures::UsageAndFinalizing,
            "lower_finalizing_charge_pages",
        );
        Ok(())
    }

    /// A live object's charge: the tag it was created with and its weight
    /// under the page class.
    pub(crate) fn charge(
        &self,
        id: ObjectId,
    ) -> Result<(charge::ChargeTag, u64), ObjectRegistryError> {
        let slot = self.reference_slot(id)?;
        let generation = decode_object_id(id.raw)
            .ok_or(ObjectRegistryError::StaleReference)?
            .1;
        if self.slots[slot].generation != generation
            || !matches!(self.slots[slot].state, SlotState::Live(_))
        {
            return Err(ObjectRegistryError::StaleReference);
        }
        Ok((self.tags[slot], self.pages[slot]))
    }

    /// Pages charged to `group`: of its live and finalizing objects and its
    /// reservations. A finalizing MemoryObject still holds its frames, so
    /// it still counts. Zero once `group` no longer holds its slot.
    pub(crate) fn charged_pages(&self, group: ObjectId) -> usize {
        #[cfg(test)]
        self.assert_group_matches_scan(group);
        let pages = self
            .held_group_slot(group)
            .map_or(0, |slot| self.usage_pages[slot]);
        usize::try_from(pages).unwrap_or(usize::MAX)
    }

    /// Live and finalizing objects of `class` charged to `group`. Zero once
    /// `group` no longer holds its slot.
    pub(crate) fn charged(&self, group: ObjectId, class: usize) -> usize {
        #[cfg(test)]
        self.assert_group_matches_scan(group);
        self.held_group_slot(group)
            .and_then(|slot| self.usage_objects[slot].get(class))
            .map_or(0, |&count| usize::from(count))
    }

    /// The part of [`Self::charged_pages`] held by `group`'s finalizing
    /// objects and owed backings: pages owed work will free.
    pub(crate) fn finalizing_pages_of(&self, group: ObjectId) -> u64 {
        self.held_group_slot(group)
            .map_or(0, |slot| self.finalizing_pages[slot])
    }

    /// The part of [`Self::charged`] that is finalizing.
    pub(crate) fn finalizing_objects_of(&self, group: ObjectId, class: usize) -> usize {
        self.held_group_slot(group)
            .and_then(|slot| self.finalizing_objects[slot].get(class))
            .map_or(0, |&count| usize::from(count))
    }

    /// For every slot holding a live TaskGroup (with `every_live`, every
    /// live slot), compares the four kept figures with the same figures
    /// found by scanning the slots and reservations, calling `mismatch`
    /// with the group, the figure, the class (for an object count), the
    /// kept value and the scanned value for each that differs. Returns how
    /// many slots it compared. Its scans are not counted as admission's.
    fn compare_usage(
        &self,
        every_live: bool,
        mut mismatch: impl FnMut(ObjectId, &'static str, Option<usize>, u64, u64),
    ) -> usize {
        let mut compared = 0;
        for slot in 0..CAPACITY {
            let entry = self.slots[slot];
            let SlotState::Live(live) = entry.state else {
                continue;
            };
            if !every_live && live.object_type != deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP {
                continue;
            }
            let Some(raw) = encode_object_id(slot, entry.generation) else {
                continue;
            };
            self.compare_slot_usage(slot, ObjectId::new(self.domain, raw), &mut mismatch);
            compared += 1;
        }
        compared
    }

    fn compare_slot_usage(
        &self,
        slot: usize,
        group: ObjectId,
        mismatch: &mut impl FnMut(ObjectId, &'static str, Option<usize>, u64, u64),
    ) {
        let widen = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        let scanned = widen(self.charged_pages_by_scan(group));
        if self.usage_pages[slot] != scanned {
            mismatch(group, "usage pages", None, self.usage_pages[slot], scanned);
        }
        let (finalizing_pages, finalizing_objects) = self.finalizing_by_scan(group);
        let kept = self.finalizing_pages_of(group);
        if kept != finalizing_pages {
            mismatch(group, "finalizing pages", None, kept, finalizing_pages);
        }
        for (class, &finalizing) in finalizing_objects.iter().enumerate() {
            let kept = u64::from(self.usage_objects[slot][class]);
            let scanned = widen(self.charged_by_scan(group, class));
            if kept != scanned {
                mismatch(group, "usage objects", Some(class), kept, scanned);
            }
            let kept = widen(self.finalizing_objects_of(group, class));
            let scanned = widen(finalizing);
            if kept != scanned {
                mismatch(group, "finalizing objects", Some(class), kept, scanned);
            }
        }
    }

    /// The kernel's check of kept usage (DW2 §13.12 part a): every live
    /// TaskGroup's four figures against a scan now, with those compared as
    /// each ended TaskGroup's slot was released. Returns the groups
    /// compared and the figures that differed; the step report's last hold
    /// prints it.
    pub(crate) fn usage_mismatches(&self) -> (usize, usize) {
        let mut mismatches = 0usize;
        let groups = self.compare_usage(false, |_, _, _, _, _| {
            mismatches = mismatches.saturating_add(1);
        });
        (
            groups.saturating_add(self.ended_groups),
            mismatches.saturating_add(self.ended_mismatches),
        )
    }

    /// Panics, naming the group, the figure and both values, if any live
    /// slot's kept usage differs from a scan.
    #[cfg(test)]
    pub(crate) fn assert_usage_matches_scan(&self) {
        self.compare_usage(true, usage_mismatch_panic);
    }

    /// As [`Self::assert_usage_matches_scan`], for `group` alone, if it
    /// holds its slot.
    #[cfg(test)]
    fn assert_group_matches_scan(&self, group: ObjectId) {
        if let Some(slot) = self.held_group_slot(group) {
            self.compare_slot_usage(slot, group, &mut usage_mismatch_panic);
        }
    }

    /// Pages charged to `group`, found by scanning the slots and the
    /// reservations: what [`Self::charged_pages`] keeps, for the checks.
    fn charged_pages_by_scan(&self, group: ObjectId) -> usize {
        self.slots
            .iter()
            .zip(&self.tags)
            .zip(&self.pages)
            .filter(|((slot, tag), _)| {
                matches!(slot.state, SlotState::Live(_) | SlotState::Finalizing(_))
                    && tag.names(group)
            })
            .fold(0usize, |total, (_, &pages)| {
                total.saturating_add(usize::try_from(pages).unwrap_or(usize::MAX))
            })
            .saturating_add(
                self.reserved
                    .iter()
                    .flatten()
                    .filter(|(_, tag, _)| tag.names(group))
                    .fold(0usize, |total, &(_, _, pages)| {
                        total.saturating_add(usize::try_from(pages).unwrap_or(usize::MAX))
                    }),
            )
    }

    /// Live and finalizing objects of `class` charged to `group`, found by
    /// scanning the slots: what [`Self::charged`] keeps, for the checks.
    fn charged_by_scan(&self, group: ObjectId, class: usize) -> usize {
        self.slots
            .iter()
            .zip(&self.tags)
            .filter(|(slot, tag)| {
                let object_type = match slot.state {
                    SlotState::Live(live) => live.object_type,
                    SlotState::Finalizing(object_type) => object_type,
                    SlotState::Vacant | SlotState::Retired => return false,
                };
                charge::object_class(object_type) == Some(class) && tag.names(group)
            })
            .count()
    }

    /// The finalizing part of `group`'s usage, found by scanning: the
    /// weights of finalizing slots whose tag names it with the owed
    /// backings' reservations whose tag names it, and the finalizing
    /// objects of each class. What [`Self::finalizing_pages_of`] and
    /// [`Self::finalizing_objects_of`] keep, for the checks.
    fn finalizing_by_scan(&self, group: ObjectId) -> (u64, [usize; charge::OBJECT_CLASSES]) {
        let mut pages = 0u64;
        let mut objects = [0usize; charge::OBJECT_CLASSES];
        for slot in 0..CAPACITY {
            let SlotState::Finalizing(object_type) = self.slots[slot].state else {
                continue;
            };
            if !self.tags[slot].names(group) {
                continue;
            }
            pages = pages.saturating_add(self.pages[slot]);
            if let Some(class) = charge::object_class(object_type) {
                objects[class] += 1;
            }
        }
        for &(holder, tag, held) in self.reserved.iter().flatten() {
            if matches!(holder, ReservationHolder::OwedBacking(_)) && tag.names(group) {
                pages = pages.saturating_add(held);
            }
        }
        (pages, objects)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn creation_into_handle(
        &mut self,
        reference: CreationRef,
    ) -> Result<HandleRef, ReferenceError<CreationRef>> {
        if let Err(error) = self.transition_reference(
            reference.id,
            reference.object_type,
            ReferenceKind::Internal,
            ReferenceKind::Handle,
        ) {
            return Err(ReferenceError { error, reference });
        }
        Ok(HandleRef {
            id: reference.id,
            object_type: reference.object_type,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn creation_into_internal(
        &self,
        reference: CreationRef,
    ) -> Result<InternalRef, ReferenceError<CreationRef>> {
        if let Err(error) =
            self.validate_reference(reference.id, reference.object_type, ReferenceKind::Internal)
        {
            return Err(ReferenceError { error, reference });
        }
        Ok(InternalRef {
            id: reference.id,
            object_type: reference.object_type,
        })
    }

    pub(crate) fn finish_payload_binding<P: PayloadBindingProof>(
        &self,
        proof: P,
    ) -> Result<BoundCreation, ReferenceError<CreationRef>> {
        let reference = payload_binding_seal::Sealed::into_creation(proof);
        if let Err(error) =
            self.validate_reference(reference.id, reference.object_type, ReferenceKind::Internal)
        {
            return Err(ReferenceError { error, reference });
        }
        Ok(BoundCreation { reference })
    }

    pub(crate) fn retain_handle_from_bound(
        &mut self,
        bound: &BoundCreation,
    ) -> Result<HandleRef, ObjectRegistryError> {
        self.retain_reference(
            bound.reference.id,
            bound.reference.object_type,
            ReferenceKind::Internal,
            ReferenceKind::Handle,
        )?;
        Ok(HandleRef {
            id: bound.reference.id,
            object_type: bound.reference.object_type,
        })
    }

    pub(crate) fn bound_into_handle(
        &mut self,
        bound: BoundCreation,
    ) -> Result<HandleRef, ReferenceError<BoundCreation>> {
        let BoundCreation { reference } = bound;
        if let Err(error) = self.transition_reference(
            reference.id,
            reference.object_type,
            ReferenceKind::Internal,
            ReferenceKind::Handle,
        ) {
            return Err(ReferenceError {
                error,
                reference: BoundCreation { reference },
            });
        }
        Ok(HandleRef {
            id: reference.id,
            object_type: reference.object_type,
        })
    }

    pub(crate) fn bound_into_internal(
        &self,
        bound: BoundCreation,
    ) -> Result<InternalRef, ReferenceError<BoundCreation>> {
        let BoundCreation { reference } = bound;
        if let Err(error) =
            self.validate_reference(reference.id, reference.object_type, ReferenceKind::Internal)
        {
            return Err(ReferenceError {
                error,
                reference: BoundCreation { reference },
            });
        }
        Ok(InternalRef {
            id: reference.id,
            object_type: reference.object_type,
        })
    }

    #[cfg_attr(
        deepwyrm_production_product,
        allow(
            dead_code,
            reason = "used by host tests and by the compile-fail UI contracts, which build this file without cfg(test)"
        )
    )]
    pub(crate) fn handle_into_internal(
        &mut self,
        reference: HandleRef,
    ) -> Result<InternalRef, ReferenceError<HandleRef>> {
        if let Err(error) = self.transition_reference(
            reference.id,
            reference.object_type,
            ReferenceKind::Handle,
            ReferenceKind::Internal,
        ) {
            return Err(ReferenceError { error, reference });
        }
        Ok(InternalRef {
            id: reference.id,
            object_type: reference.object_type,
        })
    }

    pub(crate) fn internal_into_handle(
        &mut self,
        reference: InternalRef,
    ) -> Result<HandleRef, ReferenceError<InternalRef>> {
        if let Err(error) = self.transition_reference(
            reference.id,
            reference.object_type,
            ReferenceKind::Internal,
            ReferenceKind::Handle,
        ) {
            return Err(ReferenceError { error, reference });
        }
        Ok(HandleRef {
            id: reference.id,
            object_type: reference.object_type,
        })
    }

    pub(crate) fn retain_handle(
        &mut self,
        source: &HandleRef,
    ) -> Result<HandleRef, ObjectRegistryError> {
        self.retain_reference(
            source.id,
            source.object_type,
            ReferenceKind::Handle,
            ReferenceKind::Handle,
        )?;
        Ok(HandleRef {
            id: source.id,
            object_type: source.object_type,
        })
    }

    pub(crate) fn retain_internal_from_handle(
        &mut self,
        source: &HandleRef,
    ) -> Result<InternalRef, ObjectRegistryError> {
        self.retain_reference(
            source.id,
            source.object_type,
            ReferenceKind::Handle,
            ReferenceKind::Internal,
        )?;
        Ok(InternalRef {
            id: source.id,
            object_type: source.object_type,
        })
    }
    pub(crate) fn retain_internal(
        &mut self,
        source: &InternalRef,
    ) -> Result<InternalRef, ObjectRegistryError> {
        self.retain_reference(
            source.id,
            source.object_type,
            ReferenceKind::Internal,
            ReferenceKind::Internal,
        )?;
        Ok(InternalRef {
            id: source.id,
            object_type: source.object_type,
        })
    }

    pub(crate) fn cancel_creation(
        &mut self,
        reference: CreationRef,
    ) -> Result<(), ReferenceError<CreationRef>> {
        let id = reference.id;
        let object_type = reference.object_type;
        let final_release = match self.release_reference(id, object_type, ReferenceKind::Internal) {
            Ok(Some(final_release)) => final_release,
            Ok(None) => unreachable!("unpublished creation owns exactly one internal reference"),
            Err(error) => return Err(ReferenceError { error, reference }),
        };
        if let Err(error) = self.complete_finalization_inner(&final_release) {
            panic!("unbound creation cancellation failed after final release: {error:?}");
        }
        Ok(())
    }

    #[cfg_attr(
        deepwyrm_production_product,
        allow(
            dead_code,
            reason = "used by host tests and by the compile-fail UI contracts, which build this file without cfg(test)"
        )
    )]
    pub(crate) fn release_creation(
        &mut self,
        reference: CreationRef,
    ) -> Result<Option<FinalRelease>, ReferenceError<CreationRef>> {
        match self.release_reference(reference.id, reference.object_type, ReferenceKind::Internal) {
            Ok(final_release) => Ok(final_release),
            Err(error) => Err(ReferenceError { error, reference }),
        }
    }

    pub(crate) fn release_handle(
        &mut self,
        reference: HandleRef,
    ) -> Result<Option<FinalRelease>, ReferenceError<HandleRef>> {
        match self.release_reference(reference.id, reference.object_type, ReferenceKind::Handle) {
            Ok(final_release) => Ok(final_release),
            Err(error) => Err(ReferenceError { error, reference }),
        }
    }

    pub(crate) fn release_internal(
        &mut self,
        reference: InternalRef,
    ) -> Result<Option<FinalRelease>, ReferenceError<InternalRef>> {
        match self.release_reference(reference.id, reference.object_type, ReferenceKind::Internal) {
            Ok(final_release) => Ok(final_release),
            Err(error) => Err(ReferenceError { error, reference }),
        }
    }

    pub(crate) fn complete_payload_finalization<P: PayloadCleanupProof>(
        &mut self,
        proof: P,
    ) -> Result<(), ReferenceError<FinalRelease>> {
        let final_release = payload_cleanup_seal::Sealed::into_final_release(proof);
        if let Err(error) = self.complete_finalization_inner(&final_release) {
            return Err(ReferenceError {
                error,
                reference: final_release,
            });
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn complete_finalization(
        &mut self,
        final_release: FinalRelease,
    ) -> Result<(), ReferenceError<FinalRelease>> {
        let result = self.complete_finalization_inner(&final_release);
        if let Err(error) = result {
            return Err(ReferenceError {
                error,
                reference: final_release,
            });
        }
        Ok(())
    }

    fn complete_finalization_inner(
        &mut self,
        final_release: &FinalRelease,
    ) -> Result<(), ObjectRegistryError> {
        let slot = self.reference_slot(final_release.id)?;
        let entry = &mut self.slots[slot];
        if entry.generation != decode_object_id(final_release.id.raw).unwrap().1 {
            return Err(ObjectRegistryError::StaleReference);
        }
        match entry.state {
            SlotState::Finalizing(object_type) if object_type == final_release.object_type => {}
            SlotState::Finalizing(_) => return Err(ObjectRegistryError::ObjectTypeMismatch),
            _ => return Err(ObjectRegistryError::NotFinalizing),
        }

        // A TaskGroup ends: its figures are compared with the scan one last
        // time before they are zeroed, counted, not asserted, so the
        // report says what was found.
        if final_release.object_type == deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP {
            let mut mismatches = 0usize;
            self.compare_slot_usage(slot, final_release.id, &mut |_, _, _, _, _| {
                mismatches = mismatches.saturating_add(1);
            });
            self.ended_groups = self.ended_groups.saturating_add(1);
            self.ended_mismatches = self.ended_mismatches.saturating_add(mismatches);
        }
        // A finalizing slot is released: its object and its remaining
        // weight leave its groups' usage and their finalizing part.
        self.change_usage(
            self.tags[slot],
            Direction::Remove,
            self.slot_class(slot),
            self.pages[slot],
            Figures::UsageAndFinalizing,
            "release",
        );
        let entry = &mut self.slots[slot];
        entry.state = if next_generation(entry.generation).is_some() {
            SlotState::Vacant
        } else {
            SlotState::Retired
        };
        // Whatever the slot held, a group's figures end with it.
        self.usage_pages[slot] = 0;
        self.usage_objects[slot] = [0; charge::OBJECT_CLASSES];
        self.finalizing_pages[slot] = 0;
        self.finalizing_objects[slot] = [0; charge::OBJECT_CLASSES];
        Ok(())
    }
    fn validate_reference(
        &self,
        id: ObjectId,
        object_type: DwObjectType,
        kind: ReferenceKind,
    ) -> Result<(), ObjectRegistryError> {
        let slot = self.reference_slot(id)?;
        let (_, generation) =
            decode_object_id(id.raw).ok_or(ObjectRegistryError::StaleReference)?;
        let entry = &self.slots[slot];
        if entry.generation != generation {
            return Err(ObjectRegistryError::StaleReference);
        }
        let SlotState::Live(live) = entry.state else {
            return Err(ObjectRegistryError::StaleReference);
        };
        if live.object_type != object_type {
            return Err(ObjectRegistryError::ObjectTypeMismatch);
        }
        let count = match kind {
            ReferenceKind::Handle => live.handle_refs,
            ReferenceKind::Internal => live.internal_refs,
        };
        if count == 0 {
            return Err(ObjectRegistryError::ReferenceCountUnderflow);
        }
        Ok(())
    }
    fn retain_reference(
        &mut self,
        id: ObjectId,
        object_type: DwObjectType,
        source_kind: ReferenceKind,
        retained_kind: ReferenceKind,
    ) -> Result<(), ObjectRegistryError> {
        self.validate_reference(id, object_type, source_kind)?;
        let slot = self.reference_slot(id)?;
        let SlotState::Live(live) = &mut self.slots[slot].state else {
            return Err(ObjectRegistryError::StaleReference);
        };
        let counter = match retained_kind {
            ReferenceKind::Handle => &mut live.handle_refs,
            ReferenceKind::Internal => &mut live.internal_refs,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(ObjectRegistryError::ReferenceCountExhausted)?;
        Ok(())
    }

    fn transition_reference(
        &mut self,
        id: ObjectId,
        object_type: DwObjectType,
        from: ReferenceKind,
        to: ReferenceKind,
    ) -> Result<(), ObjectRegistryError> {
        self.validate_reference(id, object_type, from)?;
        if from == to {
            return Ok(());
        }
        let slot = self.reference_slot(id)?;
        let SlotState::Live(live) = &mut self.slots[slot].state else {
            return Err(ObjectRegistryError::StaleReference);
        };
        match (from, to) {
            (ReferenceKind::Handle, ReferenceKind::Internal) => {
                let next = live
                    .internal_refs
                    .checked_add(1)
                    .ok_or(ObjectRegistryError::ReferenceCountExhausted)?;
                live.handle_refs = live
                    .handle_refs
                    .checked_sub(1)
                    .ok_or(ObjectRegistryError::ReferenceCountUnderflow)?;
                live.internal_refs = next;
            }
            (ReferenceKind::Internal, ReferenceKind::Handle) => {
                let next = live
                    .handle_refs
                    .checked_add(1)
                    .ok_or(ObjectRegistryError::ReferenceCountExhausted)?;
                live.internal_refs = live
                    .internal_refs
                    .checked_sub(1)
                    .ok_or(ObjectRegistryError::ReferenceCountUnderflow)?;
                live.handle_refs = next;
            }
            _ => unreachable!("equal reference kinds returned before transition"),
        }
        Ok(())
    }

    fn release_reference(
        &mut self,
        id: ObjectId,
        object_type: DwObjectType,
        kind: ReferenceKind,
    ) -> Result<Option<FinalRelease>, ObjectRegistryError> {
        self.validate_reference(id, object_type, kind)?;
        let slot = self.reference_slot(id)?;
        let becomes_final = {
            let SlotState::Live(live) = &mut self.slots[slot].state else {
                return Err(ObjectRegistryError::StaleReference);
            };
            let counter = match kind {
                ReferenceKind::Handle => &mut live.handle_refs,
                ReferenceKind::Internal => &mut live.internal_refs,
            };
            *counter = counter
                .checked_sub(1)
                .ok_or(ObjectRegistryError::ReferenceCountUnderflow)?;
            u64::from(live.handle_refs) + u64::from(live.internal_refs) == 0
        };
        if becomes_final {
            self.slots[slot].state = SlotState::Finalizing(object_type);
            // Its object and its weight stay in its groups' usage, now as
            // finalizing.
            self.change_usage(
                self.tags[slot],
                Direction::Add,
                charge::object_class(object_type),
                self.pages[slot],
                Figures::Finalizing,
                "release to finalizing",
            );
            return Ok(Some(FinalRelease { id, object_type }));
        }
        // A MemoryObject left with internal references and no handle may
        // have unmapped pages to release (DW2 §10.9 item 4): a handle
        // close, a DMA unmap, or a held lease pin released on its
        // shootdown's settlement.
        if object_type == DW_OBJECT_TYPE_MEMORY_OBJECT
            && matches!(self.slots[slot].state, SlotState::Live(live) if live.handle_refs == 0)
        {
            self.push_notice(slot);
        }
        Ok(None)
    }

    /// The pool slot `id` names, for tables indexed by slot; `None` for an
    /// identity of another registry or out of range. Says nothing about
    /// whether the slot still holds `id`.
    pub(crate) fn slot_of(&self, id: ObjectId) -> Option<usize> {
        self.reference_slot(id).ok()
    }

    fn reference_slot(&self, id: ObjectId) -> Result<usize, ObjectRegistryError> {
        if id.domain != self.domain {
            return Err(ObjectRegistryError::ForeignReference);
        }
        let (slot, _) = decode_object_id(id.raw).ok_or(ObjectRegistryError::StaleReference)?;
        self.slots
            .get(slot)
            .map(|_| slot)
            .ok_or(ObjectRegistryError::StaleReference)
    }
}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::memory::object::MemoryObjectBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::memory::object::MemoryObjectBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::memory::object::MemoryObjectCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::memory::object::MemoryObjectCleanup {}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::task::TaskPayloadBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::task::TaskPayloadBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::task::TaskPayloadCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::task::TaskPayloadCleanup {}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::memory::address_region::AddressRegionPayloadBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::memory::address_region::AddressRegionPayloadBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::memory::address_region::AddressRegionPayloadCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::memory::address_region::AddressRegionPayloadCleanup {}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::wait::EventPayloadBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::wait::EventPayloadBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::wait::EventPayloadCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::wait::EventPayloadCleanup {}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::device::InterruptPayloadBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::device::InterruptPayloadBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::device::InterruptCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::device::InterruptCleanup {}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::time::TimerPayloadBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::time::TimerPayloadBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::time::TimerPayloadCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::time::TimerPayloadCleanup {}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::device::DeviceResourceBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::device::DeviceResourceBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::device::DeviceResourceCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::device::DeviceResourceCleanup {}

#[cfg(deepwyrm_integrated)]
impl payload_binding_seal::Sealed for crate::ipc::ChannelPayloadBinding {
    fn into_creation(self) -> CreationRef {
        self.into_creation()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadBindingProof for crate::ipc::ChannelPayloadBinding {}

#[cfg(deepwyrm_integrated)]
impl payload_cleanup_seal::Sealed for crate::ipc::ChannelPayloadCleanup {
    fn into_final_release(self) -> FinalRelease {
        self.into_final_release()
    }
}
#[cfg(deepwyrm_integrated)]
impl PayloadCleanupProof for crate::ipc::ChannelPayloadCleanup {}

/// Whether a usage change adds or removes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Add,
    Remove,
}

/// Which of a group's figures a usage change applies to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Figures {
    /// Its usage only: a live object or a create's reservation.
    Usage,
    /// Only the finalizing part: an object passing from live to finalizing.
    Finalizing,
    /// Both: what is finalizing, or an owed backing's reservation.
    UsageAndFinalizing,
}

/// A reservation counts in its groups' usage; an owed backing's, whose
/// frames owed steps free, also in their finalizing part.
const fn reservation_figures(holder: ReservationHolder) -> Figures {
    match holder {
        ReservationHolder::Thread(_) => Figures::Usage,
        ReservationHolder::OwedBacking(_) => Figures::UsageAndFinalizing,
    }
}

/// Applies one usage change to one group's pages and object counts.
fn apply_usage_change(
    pages_entry: &mut u64,
    objects_entry: &mut [u16; charge::OBJECT_CLASSES],
    direction: Direction,
    class: Option<usize>,
    pages: u64,
    operation: &'static str,
    figure: &'static str,
) {
    let held = *pages_entry;
    *pages_entry = match direction {
        Direction::Add => held.checked_add(pages),
        Direction::Remove => held.checked_sub(pages),
    }
    .unwrap_or_else(|| {
        panic!("{operation}: a group's {figure} pages {held} cannot {direction:?} {pages}")
    });
    if let Some(class) = class {
        let count = &mut objects_entry[class];
        let held = *count;
        *count = match direction {
            Direction::Add => held.checked_add(1),
            Direction::Remove => held.checked_sub(1),
        }
        .unwrap_or_else(|| {
            panic!("{operation}: a group's {figure} objects of class {class} ({held}) cannot {direction:?} one")
        });
    }
}

#[cfg(test)]
fn usage_mismatch_panic(
    group: ObjectId,
    figure: &'static str,
    class: Option<usize>,
    kept: u64,
    scanned: u64,
) {
    panic!("group {group:?}: {figure} (class {class:?}) is kept as {kept} but scans as {scanned}");
}

fn next_generation(generation: u32) -> Option<u32> {
    generation.checked_add(1).filter(|next| *next != 0)
}

fn encode_object_id(slot: usize, generation: u32) -> Option<u64> {
    let slot = u32::try_from(slot.checked_add(1)?).ok()?;
    (generation != 0).then_some((u64::from(generation) << 32) | u64::from(slot))
}

fn decode_object_id(raw: u64) -> Option<(usize, u32)> {
    let generation = (raw >> 32) as u32;
    let slot = u32::try_from(raw & u64::from(u32::MAX))
        .ok()?
        .checked_sub(1)?;
    (generation != 0).then_some((usize::try_from(slot).ok()?, generation))
}

#[cfg(test)]
mod tests;
