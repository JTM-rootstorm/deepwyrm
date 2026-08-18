use deepwyrm_abi::{
    DW_HANDLE_INVALID, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DwHandle, DwObjectType, DwRights,
};

use crate::object::{
    FinalRelease, HandleRef, InternalRef, ObjectId, ObjectRegistry, ObjectRegistryError,
};

use super::rights::{
    RightsValidationError, require_held, require_subset, validate_compatible,
    validate_requested_syntax, validate_required_syntax,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleTableError {
    InvalidHandle,
    InvalidRights,
    WrongObjectType,
    AccessDenied,
    Capacity,
    ReferenceCapacity,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AcceptedObjectTypes<'a> {
    Any,
    One(DwObjectType),
    Set(&'a [DwObjectType]),
}
impl AcceptedObjectTypes<'_> {
    fn accepts(self, object_type: DwObjectType) -> bool {
        match self {
            Self::Any => true,
            Self::One(expected) => expected == object_type,
            Self::Set(expected) => expected.contains(&object_type),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BasicHandleInfo {
    pub(crate) object_type: DwObjectType,
    pub(crate) rights: DwRights,
}

#[must_use = "resolved handles own one internal object reference"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResolvedHandle {
    reference: InternalRef,
    rights: DwRights,
}

impl ResolvedHandle {
    pub(crate) const fn object_type(&self) -> DwObjectType {
        self.reference.object_type()
    }

    pub(crate) const fn object_id(&self) -> ObjectId {
        self.reference.id()
    }

    pub(crate) const fn rights(&self) -> DwRights {
        self.rights
    }
    pub(crate) fn into_internal(self) -> InternalRef {
        self.reference
    }

    pub(crate) const fn basic_info(&self) -> BasicHandleInfo {
        BasicHandleInfo {
            object_type: self.reference.object_type(),
            rights: self.rights,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InstallError {
    error: HandleTableError,
    reference: HandleRef,
}

impl InstallError {
    pub(crate) const fn error(&self) -> HandleTableError {
        self.error
    }

    pub(crate) fn into_reference(self) -> HandleRef {
        self.reference
    }
}

#[must_use = "drained final-release tokens require subsystem cleanup"]
pub(crate) struct DrainResult<const CAPACITY: usize> {
    final_releases: [Option<FinalRelease>; CAPACITY],
    final_release_count: usize,
}
impl<const CAPACITY: usize> DrainResult<CAPACITY> {
    pub(crate) const fn final_release_count(&self) -> usize {
        self.final_release_count
    }

    pub(crate) fn into_final_releases(self) -> [Option<FinalRelease>; CAPACITY] {
        self.final_releases
    }
}

struct HandleEntry {
    reference: HandleRef,
    rights: DwRights,
}

struct HandleSlot {
    generation: u32,
    retired: bool,
    entry: Option<HandleEntry>,
}

#[derive(Clone, Copy)]
struct Reservation {
    slot: usize,
    generation: u32,
    handle: DwHandle,
}

#[must_use = "handle tables with live entries must be explicitly drained before teardown"]
pub(crate) struct HandleTable<const CAPACITY: usize> {
    slots: [HandleSlot; CAPACITY],
    live_count: usize,
}
impl<const CAPACITY: usize> HandleTable<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| HandleSlot {
                generation: 0,
                retired: false,
                entry: None,
            }),
            live_count: 0,
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.live_count
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.live_count == 0
    }

    pub(crate) fn install(
        &mut self,
        reference: HandleRef,
        rights: DwRights,
    ) -> Result<DwHandle, InstallError> {
        if let Err(error) = validate_requested_syntax(rights)
            .and_then(|_| validate_compatible(reference.object_type(), rights))
        {
            return Err(InstallError {
                error: rights_error(error),
                reference,
            });
        }
        let reservation = match self.reserve_slot() {
            Ok(reservation) => reservation,
            Err(error) => return Err(InstallError { error, reference }),
        };
        self.publish(reservation, HandleEntry { reference, rights });
        Ok(reservation.handle)
    }

    pub(crate) fn lookup<const OBJECTS: usize>(
        &self,
        registry: &mut ObjectRegistry<OBJECTS>,
        handle: DwHandle,
        accepted: AcceptedObjectTypes<'_>,
        required_rights: DwRights,
    ) -> Result<ResolvedHandle, HandleTableError> {
        validate_required_syntax(required_rights).map_err(rights_error)?;
        let entry = self.resolve_entry(handle)?;
        let object_type = entry.reference.object_type();
        if !accepted.accepts(object_type) {
            return Err(HandleTableError::WrongObjectType);
        }
        validate_compatible(object_type, required_rights).map_err(rights_error)?;
        require_held(entry.rights, required_rights).map_err(rights_error)?;
        let reference = registry
            .retain_internal_from_handle(&entry.reference)
            .map_err(retain_error)?;
        Ok(ResolvedHandle {
            reference,
            rights: entry.rights,
        })
    }

    pub(crate) fn inspect_basic(
        &self,
        handle: DwHandle,
    ) -> Result<BasicHandleInfo, HandleTableError> {
        let entry = self.resolve_entry(handle)?;
        require_held(entry.rights, DW_RIGHT_INSPECT).map_err(rights_error)?;
        Ok(BasicHandleInfo {
            object_type: entry.reference.object_type(),
            rights: entry.rights,
        })
    }

    pub(crate) fn close<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        handle: DwHandle,
    ) -> Result<Option<FinalRelease>, HandleTableError> {
        let slot = self.resolve_slot(handle)?;
        let entry = self.slots[slot]
            .entry
            .take()
            .expect("resolved handle slot has a live entry");
        self.live_count = self
            .live_count
            .checked_sub(1)
            .expect("live handle count underflow after resolved close");
        if next_generation(self.slots[slot].generation).is_none() {
            self.slots[slot].retired = true;
        }
        match registry.release_handle(entry.reference) {
            Ok(final_release) => Ok(final_release),
            Err(failure) => panic!(
                "handle table/object registry invariant violated on close: {:?}",
                failure.error()
            ),
        }
    }

    pub(crate) fn duplicate<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        source: DwHandle,
        requested_rights: DwRights,
    ) -> Result<DwHandle, HandleTableError> {
        validate_requested_syntax(requested_rights).map_err(rights_error)?;
        let source_slot = self.resolve_slot(source)?;
        let (object_type, held_rights) = {
            let entry = self.slots[source_slot]
                .entry
                .as_ref()
                .expect("resolved source handle has a live entry");
            (entry.reference.object_type(), entry.rights)
        };
        validate_compatible(object_type, requested_rights).map_err(rights_error)?;
        require_held(held_rights, DW_RIGHT_DUPLICATE).map_err(rights_error)?;
        require_subset(held_rights, requested_rights).map_err(rights_error)?;

        let reservation = self.reserve_slot()?;
        let retained = {
            let entry = self.slots[source_slot]
                .entry
                .as_ref()
                .expect("resolved source handle remains live during exclusive duplicate");
            registry
                .retain_handle(&entry.reference)
                .map_err(retain_error)?
        };
        self.publish(
            reservation,
            HandleEntry {
                reference: retained,
                rights: requested_rights,
            },
        );
        Ok(reservation.handle)
    }

    pub(crate) fn drain<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> DrainResult<CAPACITY> {
        let mut final_releases = core::array::from_fn(|_| None);
        let mut final_release_count = 0;
        for slot in 0..CAPACITY {
            let Some(entry) = self.slots[slot].entry.take() else {
                continue;
            };
            self.live_count = self
                .live_count
                .checked_sub(1)
                .expect("live handle count underflow during drain");
            if next_generation(self.slots[slot].generation).is_none() {
                self.slots[slot].retired = true;
            }
            match registry.release_handle(entry.reference) {
                Ok(Some(final_release)) => {
                    final_releases[final_release_count] = Some(final_release);
                    final_release_count += 1;
                }
                Ok(None) => {}
                Err(failure) => panic!(
                    "handle table/object registry invariant violated during drain: {:?}",
                    failure.error()
                ),
            }
        }
        debug_assert_eq!(self.live_count, 0);
        DrainResult {
            final_releases,
            final_release_count,
        }
    }

    fn reserve_slot(&mut self) -> Result<Reservation, HandleTableError> {
        for slot in 0..CAPACITY {
            if self.slots[slot].retired || self.slots[slot].entry.is_some() {
                continue;
            }
            let Some(generation) = next_generation(self.slots[slot].generation) else {
                self.slots[slot].retired = true;
                continue;
            };
            let Some(handle) = encode_handle(slot, generation) else {
                self.slots[slot].retired = true;
                continue;
            };
            return Ok(Reservation {
                slot,
                generation,
                handle,
            });
        }
        Err(HandleTableError::Capacity)
    }

    fn publish(&mut self, reservation: Reservation, entry: HandleEntry) {
        let slot = &mut self.slots[reservation.slot];
        assert!(
            !slot.retired,
            "reserved handle slot retired before publication"
        );
        assert!(
            slot.entry.is_none(),
            "reserved handle slot became live before publication"
        );
        slot.generation = reservation.generation;
        slot.entry = Some(entry);
        self.live_count = self
            .live_count
            .checked_add(1)
            .expect("live handle count exceeds table capacity");
    }

    fn resolve_entry(&self, handle: DwHandle) -> Result<&HandleEntry, HandleTableError> {
        let slot = self.resolve_slot(handle)?;
        Ok(self.slots[slot]
            .entry
            .as_ref()
            .expect("resolved handle slot has a live entry"))
    }

    fn resolve_slot(&self, handle: DwHandle) -> Result<usize, HandleTableError> {
        if handle == DW_HANDLE_INVALID {
            return Err(HandleTableError::InvalidHandle);
        }
        let (slot, generation) = decode_handle(handle).ok_or(HandleTableError::InvalidHandle)?;
        let entry = self
            .slots
            .get(slot)
            .ok_or(HandleTableError::InvalidHandle)?;
        if entry.retired || entry.generation != generation || entry.entry.is_none() {
            return Err(HandleTableError::InvalidHandle);
        }
        Ok(slot)
    }
}

impl<const CAPACITY: usize> Drop for HandleTable<CAPACITY> {
    fn drop(&mut self) {
        assert!(
            self.live_count == 0 && self.slots.iter().all(|slot| slot.entry.is_none()),
            "live HandleTable dropped without explicit close/drain"
        );
    }
}

fn next_generation(generation: u32) -> Option<u32> {
    generation.checked_add(1).filter(|next| *next != 0)
}

fn encode_handle(slot: usize, generation: u32) -> Option<DwHandle> {
    let slot = u32::try_from(slot.checked_add(1)?).ok()?;
    (generation != 0).then_some(DwHandle((u64::from(generation) << 32) | u64::from(slot)))
}

fn decode_handle(handle: DwHandle) -> Option<(usize, u32)> {
    let generation = (handle.0 >> 32) as u32;
    let slot = u32::try_from(handle.0 & u64::from(u32::MAX))
        .ok()?
        .checked_sub(1)?;
    (generation != 0).then_some((usize::try_from(slot).ok()?, generation))
}

fn rights_error(error: RightsValidationError) -> HandleTableError {
    match error {
        RightsValidationError::Zero
        | RightsValidationError::Unknown
        | RightsValidationError::Incompatible => HandleTableError::InvalidRights,
        RightsValidationError::Missing | RightsValidationError::Escalation => {
            HandleTableError::AccessDenied
        }
    }
}

fn retain_error(error: ObjectRegistryError) -> HandleTableError {
    match error {
        ObjectRegistryError::ReferenceCountExhausted => HandleTableError::ReferenceCapacity,
        other => panic!("handle table/object registry retain invariant violated: {other:?}"),
    }
}

#[cfg(test)]
mod tests;
