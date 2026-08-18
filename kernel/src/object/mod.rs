//! Generic DW0-D kernel-object identity and strong-lifetime registry.
//!
//! `ObjectId` is identity only. Strong lifetime authority is represented by
//! move-only reference tokens that can be minted or transformed only here.

use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::{DwObjectType, dw_object_compatible_rights};

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
pub(crate) struct ObjectRegistry<const CAPACITY: usize> {
    domain: u64,
    slots: [ObjectSlot; CAPACITY],
}

impl<const CAPACITY: usize> ObjectRegistry<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_registry_domain(),
            slots: [EMPTY_SLOT; CAPACITY],
        }
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

        entry.state = if next_generation(entry.generation).is_some() {
            SlotState::Vacant
        } else {
            SlotState::Retired
        };
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
            return Ok(Some(FinalRelease { id, object_type }));
        }
        Ok(None)
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
mod tests {
    extern crate std;

    use deepwyrm_abi::{
        DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_NONE,
        DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP,
    };

    use super::*;

    fn counts<const CAPACITY: usize>(
        registry: &ObjectRegistry<CAPACITY>,
        id: ObjectId,
    ) -> (u32, u32) {
        let slot = registry.reference_slot(id).unwrap();
        match registry.slots[slot].state {
            SlotState::Live(live) => (live.handle_refs, live.internal_refs),
            other => panic!("expected live object, got {other:?}"),
        }
    }

    fn finish<const CAPACITY: usize>(
        registry: &mut ObjectRegistry<CAPACITY>,
        final_release: FinalRelease,
    ) {
        registry.complete_finalization(final_release).unwrap();
    }

    #[test]
    fn create_rejects_nonlive_types_and_honors_fixed_capacity() {
        let mut registry = ObjectRegistry::<1>::new();
        assert_eq!(
            registry.create(DW_OBJECT_TYPE_NONE),
            Err(ObjectRegistryError::InvalidObjectType)
        );
        assert_eq!(
            registry.create(DW_OBJECT_TYPE_INTERRUPT),
            Err(ObjectRegistryError::InvalidObjectType)
        );
        assert_eq!(
            registry.create(DwObjectType(0xfeed)),
            Err(ObjectRegistryError::InvalidObjectType)
        );
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        assert_eq!(counts(&registry, creation.id()), (0, 1));
        assert_eq!(
            registry.create(DW_OBJECT_TYPE_PROCESS),
            Err(ObjectRegistryError::Capacity)
        );

        let final_release = registry.release_creation(creation).unwrap().unwrap();
        finish(&mut registry, final_release);
    }

    #[test]
    fn reference_classes_transition_and_retain_exactly() {
        let mut registry = ObjectRegistry::<2>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let id = creation.id();
        assert_eq!(counts(&registry, id), (0, 1));

        let handle0 = registry.creation_into_handle(creation).unwrap();
        assert_eq!(counts(&registry, id), (1, 0));
        let handle1 = registry.retain_handle(&handle0).unwrap();
        assert_eq!(counts(&registry, id), (2, 0));
        let internal0 = registry.retain_internal_from_handle(&handle0).unwrap();
        assert_eq!(counts(&registry, id), (2, 1));
        let internal1 = registry.retain_internal(&internal0).unwrap();
        assert_eq!(counts(&registry, id), (2, 2));

        let internal2 = registry.handle_into_internal(handle1).unwrap();
        assert_eq!(counts(&registry, id), (1, 3));
        let handle1 = registry.internal_into_handle(internal2).unwrap();
        assert_eq!(counts(&registry, id), (2, 2));

        assert!(registry.release_internal(internal0).unwrap().is_none());
        assert!(registry.release_internal(internal1).unwrap().is_none());
        assert!(registry.release_handle(handle1).unwrap().is_none());
        let final_release = registry.release_handle(handle0).unwrap().unwrap();
        assert_eq!(final_release.id(), id);
        assert_eq!(final_release.object_type(), DW_OBJECT_TYPE_MEMORY_OBJECT);
        finish(&mut registry, final_release);
    }

    #[test]
    fn finalizing_slot_is_not_reused_until_cleanup_completes() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let old_id = creation.id();
        let handle = registry.creation_into_handle(creation).unwrap();
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let stale = HandleRef {
            id: old_id,
            object_type: DW_OBJECT_TYPE_PROCESS,
        };
        assert_eq!(
            registry.retain_handle(&stale),
            Err(ObjectRegistryError::StaleReference)
        );

        assert_eq!(
            registry.create(DW_OBJECT_TYPE_PROCESS),
            Err(ObjectRegistryError::Capacity)
        );
        finish(&mut registry, final_release);

        let replacement = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        assert_ne!(replacement.id(), old_id);
        let final_release = registry.release_creation(replacement).unwrap().unwrap();
        finish(&mut registry, final_release);
    }

    #[test]
    fn foreign_registry_rejects_and_returns_consumed_reference() {
        let mut owner = ObjectRegistry::<1>::new();
        let mut foreign = ObjectRegistry::<1>::new();
        let creation = owner.create(DW_OBJECT_TYPE_TASK_GROUP).unwrap();
        let id = creation.id();

        let error = foreign.creation_into_handle(creation).unwrap_err();
        assert_eq!(error.error(), ObjectRegistryError::ForeignReference);
        let creation = error.into_reference();
        assert_eq!(creation.id(), id);

        let handle = owner.creation_into_handle(creation).unwrap();
        let final_release = owner.release_handle(handle).unwrap().unwrap();
        finish(&mut owner, final_release);
    }

    #[test]
    fn stale_identity_cannot_be_promoted_after_slot_reuse() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let old_id = creation.id();
        let handle = registry.creation_into_handle(creation).unwrap();
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish(&mut registry, final_release);

        let replacement = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let stale = HandleRef {
            id: old_id,
            object_type: DW_OBJECT_TYPE_PROCESS,
        };
        assert_eq!(
            registry.retain_handle(&stale),
            Err(ObjectRegistryError::StaleReference)
        );

        let final_release = registry.release_creation(replacement).unwrap().unwrap();
        finish(&mut registry, final_release);
    }

    #[test]
    fn forged_wrong_class_or_type_fails_closed_without_count_change() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let id = creation.id();
        let handle = registry.creation_into_handle(creation).unwrap();

        let fake_internal = InternalRef {
            id,
            object_type: DW_OBJECT_TYPE_PROCESS,
        };
        let error = registry.release_internal(fake_internal).unwrap_err();
        assert_eq!(error.error(), ObjectRegistryError::ReferenceCountUnderflow);
        let _ = error.into_reference();
        assert_eq!(counts(&registry, id), (1, 0));

        let wrong_type = HandleRef {
            id,
            object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
        };
        assert_eq!(
            registry.retain_handle(&wrong_type),
            Err(ObjectRegistryError::ObjectTypeMismatch)
        );
        assert_eq!(counts(&registry, id), (1, 0));

        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish(&mut registry, final_release);
    }

    #[test]
    fn both_reference_counters_fail_before_overflow() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let id = creation.id();
        let handle = registry.creation_into_handle(creation).unwrap();
        let slot = registry.reference_slot(id).unwrap();

        let SlotState::Live(live) = &mut registry.slots[slot].state else {
            unreachable!();
        };
        live.handle_refs = u32::MAX;
        assert_eq!(
            registry.retain_handle(&handle),
            Err(ObjectRegistryError::ReferenceCountExhausted)
        );
        let SlotState::Live(live) = &mut registry.slots[slot].state else {
            unreachable!();
        };
        assert_eq!(live.handle_refs, u32::MAX);
        live.handle_refs = 1;

        let internal = registry.retain_internal_from_handle(&handle).unwrap();
        let SlotState::Live(live) = &mut registry.slots[slot].state else {
            unreachable!();
        };
        live.internal_refs = u32::MAX;
        assert_eq!(
            registry.retain_internal_from_handle(&handle),
            Err(ObjectRegistryError::ReferenceCountExhausted)
        );
        let SlotState::Live(live) = &mut registry.slots[slot].state else {
            unreachable!();
        };
        assert_eq!(live.internal_refs, u32::MAX);
        live.internal_refs = 1;

        assert!(registry.release_internal(internal).unwrap().is_none());
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish(&mut registry, final_release);
    }

    #[test]
    fn generation_exhaustion_permanently_retires_the_slot() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let mut final_release = registry.release_creation(creation).unwrap().unwrap();
        let slot = registry.reference_slot(final_release.id()).unwrap();
        registry.slots[slot].generation = u32::MAX;
        final_release.id.raw = encode_object_id(slot, u32::MAX).unwrap();
        finish(&mut registry, final_release);

        assert_eq!(registry.slots[slot].state, SlotState::Retired);
        assert_eq!(
            registry.create(DW_OBJECT_TYPE_PROCESS),
            Err(ObjectRegistryError::Capacity)
        );
    }

    #[test]
    fn final_release_can_complete_only_once() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let final_release = registry.release_creation(creation).unwrap().unwrap();
        let id = final_release.id();
        let object_type = final_release.object_type();
        finish(&mut registry, final_release);

        let duplicate = FinalRelease { id, object_type };
        let error = registry.complete_finalization(duplicate).unwrap_err();
        assert_eq!(error.error(), ObjectRegistryError::NotFinalizing);
        let _ = error.into_reference();
    }

    #[test]
    fn creation_can_become_an_explicit_internal_owner() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let id = creation.id();
        let internal = registry.creation_into_internal(creation).unwrap();
        assert_eq!(counts(&registry, id), (0, 1));
        let final_release = registry.release_internal(internal).unwrap().unwrap();
        finish(&mut registry, final_release);
    }

    #[test]
    fn zero_capacity_registry_fails_closed() {
        let mut registry = ObjectRegistry::<0>::new();
        assert_eq!(
            registry.create(DW_OBJECT_TYPE_PROCESS),
            Err(ObjectRegistryError::Capacity)
        );
    }
}
