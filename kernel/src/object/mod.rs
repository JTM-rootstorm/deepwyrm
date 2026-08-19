//! Generic DW0-D kernel-object identity and strong-lifetime registry.
//!
//! `ObjectId` is identity only. Strong lifetime authority is represented by
//! move-only reference tokens that can be minted or transformed only here.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(deepwyrm_integrated)]
mod finalizer;
#[cfg(deepwyrm_integrated)]
#[allow(
    unused_imports,
    reason = "DW0-E2 exports the typed finalizer router ahead of E5 close/teardown consumers"
)]
pub(crate) use finalizer::PayloadFinalizer;

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

#[must_use = "bound creations must become a first handle/internal owner or be rolled back through typed payload cleanup"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BoundCreation {
    reference: CreationRef,
}

impl BoundCreation {
    pub(crate) const fn id(&self) -> ObjectId {
        self.reference.id()
    }
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

    #[cfg(test)]
    pub(crate) fn test_slot_generations(&self) -> [u32; CAPACITY] {
        core::array::from_fn(|slot| self.slots[slot].generation)
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
