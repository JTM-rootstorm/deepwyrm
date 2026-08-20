use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::{
    DW_CHANNEL_MAX_HANDLES, DW_HANDLE_INVALID, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT,
    DW_RIGHT_TRANSFER, DwHandle, DwObjectType, DwRights,
};

static NEXT_HANDLE_TABLE_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_handle_table_domain() -> u64 {
    NEXT_HANDLE_TABLE_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |domain| {
            domain.checked_add(1).filter(|next| *next != 0)
        })
        .expect("handle-table domain space exhausted")
}

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

    pub(crate) fn retain<const OBJECTS: usize>(
        &self,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> Result<Self, HandleTableError> {
        let reference = registry
            .retain_internal(&self.reference)
            .map_err(retain_error)?;
        Ok(Self {
            reference,
            rights: self.rights,
        })
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
    prior_generation: u32,
    generation: u32,
    handle: DwHandle,
}

#[must_use = "reserved handle pairs must be published exactly once or deliberately discarded before any intervening table mutation"]
pub(crate) struct HandlePairReservation {
    domain: u64,
    object_type: DwObjectType,
    rights: DwRights,
    first: Reservation,
    second: Reservation,
}

pub(crate) const HANDLE_TRANSFER_LIMIT: usize = DW_CHANNEL_MAX_HANDLES as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HandleMoveRequest {
    pub(crate) handle: DwHandle,
    pub(crate) requested_rights: DwRights,
}

#[derive(Clone, Copy)]
struct PreparedMoveEntry {
    slot: usize,
    handle: DwHandle,
    object: ObjectId,
    object_type: DwObjectType,
    source_rights: DwRights,
    requested_rights: DwRights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleMovePrepareError {
    DuplicateSource,
    Table(HandleTableError),
}

#[must_use = "prepared handle moves must be extracted only after Channel resources are reserved"]
pub(crate) struct PreparedHandleMoveBatch<'a, const CAPACITY: usize> {
    table: &'a mut HandleTable<CAPACITY>,
    entries: [Option<PreparedMoveEntry>; HANDLE_TRANSFER_LIMIT],
    len: usize,
}

#[must_use = "extracted source handles must be finalized after send commit or rolled back after send failure"]
pub(crate) struct HandleMoveRollback<'a, const CAPACITY: usize> {
    table: &'a mut HandleTable<CAPACITY>,
    entries: [Option<PreparedMoveEntry>; HANDLE_TRANSFER_LIMIT],
    len: usize,
    completed: bool,
}

#[must_use = "queued transfer tokens own generic handle references until receive publication or queue teardown"]
pub(crate) struct HandleTransferToken {
    reference: HandleRef,
    source_rights: DwRights,
    requested_rights: DwRights,
}

#[must_use = "transfer batches must move into a Channel, destination HandleTable, or teardown release path"]
pub(crate) struct HandleTransferBatch {
    entries: [Option<HandleTransferToken>; HANDLE_TRANSFER_LIMIT],
    len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublishedHandleInfo {
    pub(crate) handle: DwHandle,
    pub(crate) rights: DwRights,
    pub(crate) object_type: DwObjectType,
}

#[must_use = "destination handle reservations must publish the complete received transfer batch or be discarded before queue consumption"]
pub(crate) struct HandleBatchReservation<'a, const CAPACITY: usize> {
    table: &'a mut HandleTable<CAPACITY>,
    reservations: [Option<Reservation>; HANDLE_TRANSFER_LIMIT],
    len: usize,
}

#[must_use = "handle tables with live entries must be explicitly drained before teardown"]
pub(crate) struct HandleTable<const CAPACITY: usize> {
    domain: u64,
    slots: [HandleSlot; CAPACITY],
    live_count: usize,
}
impl<const CAPACITY: usize> HandleTable<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_handle_table_domain(),
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

    pub(crate) fn prepare_move_batch(
        &mut self,
        requests: &[HandleMoveRequest],
    ) -> Result<PreparedHandleMoveBatch<'_, CAPACITY>, HandleMovePrepareError> {
        assert!(
            requests.len() <= HANDLE_TRANSFER_LIMIT,
            "Channel transfer request exceeds generated ABI maximum"
        );
        for left in 0..requests.len() {
            for right in left + 1..requests.len() {
                if requests[left].handle == requests[right].handle {
                    return Err(HandleMovePrepareError::DuplicateSource);
                }
            }
        }

        let mut entries = [None; HANDLE_TRANSFER_LIMIT];
        for (index, request) in requests.iter().copied().enumerate() {
            let slot = self
                .resolve_slot(request.handle)
                .map_err(HandleMovePrepareError::Table)?;
            let entry = self.slots[slot]
                .entry
                .as_ref()
                .expect("resolved transfer source remains live");
            require_held(entry.rights, DW_RIGHT_TRANSFER)
                .map_err(|error| HandleMovePrepareError::Table(rights_error(error)))?;
            validate_requested_syntax(request.requested_rights)
                .map_err(|error| HandleMovePrepareError::Table(rights_error(error)))?;
            validate_compatible(entry.reference.object_type(), request.requested_rights)
                .map_err(|error| HandleMovePrepareError::Table(rights_error(error)))?;
            require_subset(entry.rights, request.requested_rights)
                .map_err(|error| HandleMovePrepareError::Table(rights_error(error)))?;
            entries[index] = Some(PreparedMoveEntry {
                slot,
                handle: request.handle,
                object: entry.reference.id(),
                object_type: entry.reference.object_type(),
                source_rights: entry.rights,
                requested_rights: request.requested_rights,
            });
        }

        Ok(PreparedHandleMoveBatch {
            table: self,
            entries,
            len: requests.len(),
        })
    }

    pub(crate) fn reserve_transfer_batch(
        &mut self,
        count: usize,
    ) -> Result<HandleBatchReservation<'_, CAPACITY>, HandleTableError> {
        assert!(
            count <= HANDLE_TRANSFER_LIMIT,
            "Channel receive handle count exceeds generated ABI maximum"
        );
        let mut reservations: [Option<Reservation>; HANDLE_TRANSFER_LIMIT] =
            [None; HANDLE_TRANSFER_LIMIT];
        for index in 0..count {
            let mut found = None;
            for slot in 0..CAPACITY {
                if reservations[..index]
                    .iter()
                    .flatten()
                    .any(|reservation| reservation.slot == slot)
                    || self.slots[slot].retired
                    || self.slots[slot].entry.is_some()
                {
                    continue;
                }
                let prior_generation = self.slots[slot].generation;
                let Some(generation) = next_generation(prior_generation) else {
                    self.slots[slot].retired = true;
                    continue;
                };
                let Some(handle) = encode_handle(slot, generation) else {
                    self.slots[slot].retired = true;
                    continue;
                };
                found = Some(Reservation {
                    slot,
                    prior_generation,
                    generation,
                    handle,
                });
                break;
            }
            reservations[index] = Some(found.ok_or(HandleTableError::Capacity)?);
        }
        Ok(HandleBatchReservation {
            table: self,
            reservations,
            len: count,
        })
    }

    /// Reserves two caller-local slots without publishing either handle.
    ///
    /// The caller must retain exclusive logical ownership of this HandleTable
    /// until `publish_reserved_pair` consumes the token. The reservation itself
    /// does not mutate slot generations, so abandoning it before publication is
    /// rollback-free.
    pub(crate) fn reserve_pair(
        &mut self,
        object_type: DwObjectType,
        rights: DwRights,
    ) -> Result<HandlePairReservation, HandleTableError> {
        validate_requested_syntax(rights).map_err(rights_error)?;
        validate_compatible(object_type, rights).map_err(rights_error)?;
        let first = self.reserve_slot_excluding(None)?;
        let second = self.reserve_slot_excluding(Some(first.slot))?;
        Ok(HandlePairReservation {
            domain: self.domain,
            object_type,
            rights,
            first,
            second,
        })
    }

    /// Atomically publishes both references into a previously reserved pair.
    ///
    /// Any reservation/table drift is a kernel ownership bug rather than a
    /// recoverable userspace condition.
    pub(crate) fn publish_reserved_pair(
        &mut self,
        reservation: HandlePairReservation,
        first: HandleRef,
        second: HandleRef,
    ) -> [DwHandle; 2] {
        assert_eq!(
            reservation.domain, self.domain,
            "foreign handle-pair reservation"
        );
        assert_eq!(
            first.object_type(),
            reservation.object_type,
            "first reserved handle type drift"
        );
        assert_eq!(
            second.object_type(),
            reservation.object_type,
            "second reserved handle type drift"
        );
        self.assert_reservation_fresh(reservation.first);
        self.assert_reservation_fresh(reservation.second);
        let handles = [reservation.first.handle, reservation.second.handle];
        self.publish(
            reservation.first,
            HandleEntry {
                reference: first,
                rights: reservation.rights,
            },
        );
        self.publish(
            reservation.second,
            HandleEntry {
                reference: second,
                rights: reservation.rights,
            },
        );
        handles
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
        self.reserve_slot_excluding(None)
    }

    fn reserve_slot_excluding(
        &mut self,
        excluded: Option<usize>,
    ) -> Result<Reservation, HandleTableError> {
        for slot in 0..CAPACITY {
            if excluded == Some(slot)
                || self.slots[slot].retired
                || self.slots[slot].entry.is_some()
            {
                continue;
            }
            let prior_generation = self.slots[slot].generation;
            let Some(generation) = next_generation(prior_generation) else {
                self.slots[slot].retired = true;
                continue;
            };
            let Some(handle) = encode_handle(slot, generation) else {
                self.slots[slot].retired = true;
                continue;
            };
            return Ok(Reservation {
                slot,
                prior_generation,
                generation,
                handle,
            });
        }
        Err(HandleTableError::Capacity)
    }

    fn assert_reservation_fresh(&self, reservation: Reservation) {
        let slot = &self.slots[reservation.slot];
        assert!(
            !slot.retired
                && slot.entry.is_none()
                && slot.generation == reservation.prior_generation,
            "reserved handle slot changed before pair publication"
        );
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

impl<'a, const CAPACITY: usize> PreparedHandleMoveBatch<'a, CAPACITY> {
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn contains_object(&self, object: ObjectId) -> bool {
        self.entries[..self.len]
            .iter()
            .flatten()
            .any(|entry| entry.object == object)
    }

    pub(crate) fn extract(self) -> (HandleMoveRollback<'a, CAPACITY>, HandleTransferBatch) {
        let Self {
            table,
            entries,
            len,
        } = self;
        let mut transfers = HandleTransferBatch::empty();
        for (index, prepared) in entries[..len].iter().flatten().copied().enumerate() {
            assert_eq!(
                table.resolve_slot(prepared.handle),
                Ok(prepared.slot),
                "prepared transfer source changed under exclusive table ownership"
            );
            let entry = table.slots[prepared.slot]
                .entry
                .take()
                .expect("prepared transfer source remains live until extraction");
            assert_eq!(entry.reference.id(), prepared.object);
            assert_eq!(entry.reference.object_type(), prepared.object_type);
            assert_eq!(entry.rights, prepared.source_rights);
            table.live_count = table
                .live_count
                .checked_sub(1)
                .expect("live handle count underflow during transfer extraction");
            transfers.entries[index] = Some(HandleTransferToken {
                reference: entry.reference,
                source_rights: entry.rights,
                requested_rights: prepared.requested_rights,
            });
            transfers.len += 1;
        }
        (
            HandleMoveRollback {
                table,
                entries,
                len,
                completed: false,
            },
            transfers,
        )
    }
}

impl<const CAPACITY: usize> HandleMoveRollback<'_, CAPACITY> {
    pub(crate) fn finish(mut self) {
        for prepared in self.entries[..self.len].iter().flatten().copied() {
            let slot = &mut self.table.slots[prepared.slot];
            assert!(
                slot.entry.is_none() && slot.generation == (prepared.handle.0 >> 32) as u32,
                "committed transfer source slot drifted before invalidation finish"
            );
            if next_generation(slot.generation).is_none() {
                slot.retired = true;
            }
        }
        self.completed = true;
    }

    pub(crate) fn rollback(mut self, mut transfers: HandleTransferBatch) {
        assert_eq!(
            transfers.len, self.len,
            "transfer rollback batch length drift"
        );
        for (index, prepared) in self.entries[..self.len]
            .iter()
            .flatten()
            .copied()
            .enumerate()
        {
            let token = transfers.entries[index]
                .take()
                .expect("transfer rollback retains every extracted token");
            assert_eq!(token.reference.id(), prepared.object);
            assert_eq!(token.reference.object_type(), prepared.object_type);
            assert_eq!(token.source_rights, prepared.source_rights);
            assert_eq!(token.requested_rights, prepared.requested_rights);
            let slot = &mut self.table.slots[prepared.slot];
            assert!(
                !slot.retired
                    && slot.entry.is_none()
                    && slot.generation == (prepared.handle.0 >> 32) as u32,
                "transfer rollback source slot drifted"
            );
            slot.entry = Some(HandleEntry {
                reference: token.reference,
                rights: token.source_rights,
            });
            self.table.live_count = self
                .table
                .live_count
                .checked_add(1)
                .expect("live handle count overflow during transfer rollback");
        }
        self.completed = true;
    }
}

impl<const CAPACITY: usize> Drop for HandleMoveRollback<'_, CAPACITY> {
    fn drop(&mut self) {
        assert!(
            self.completed,
            "extracted handle move dropped without commit finish or rollback"
        );
    }
}

impl HandleTransferToken {
    pub(crate) const fn object_id(&self) -> ObjectId {
        self.reference.id()
    }

    pub(crate) const fn object_type(&self) -> DwObjectType {
        self.reference.object_type()
    }

    pub(crate) const fn rights(&self) -> DwRights {
        self.requested_rights
    }
}

impl HandleTransferBatch {
    pub(crate) fn empty() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn release<const OBJECTS: usize>(
        mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> [Option<FinalRelease>; HANDLE_TRANSFER_LIMIT] {
        let mut releases = core::array::from_fn(|_| None);
        for (release, entry) in releases
            .iter_mut()
            .zip(self.entries.iter_mut())
            .take(self.len)
        {
            let token = entry
                .take()
                .expect("transfer release batch retains every live token");
            *release = registry
                .release_handle(token.reference)
                .unwrap_or_else(|failure| {
                    panic!(
                        "queued transfer reference release drifted: {:?}",
                        failure.error()
                    )
                });
        }
        self.len = 0;
        releases
    }
}

impl<'a, const CAPACITY: usize> HandleBatchReservation<'a, CAPACITY> {
    pub(crate) fn publish(
        self,
        mut transfers: HandleTransferBatch,
    ) -> [Option<PublishedHandleInfo>; HANDLE_TRANSFER_LIMIT] {
        assert_eq!(
            transfers.len, self.len,
            "received transfer count drifted after destination reservation"
        );
        let Self {
            table,
            reservations,
            len,
        } = self;
        let mut published = [None; HANDLE_TRANSFER_LIMIT];
        for index in 0..len {
            let reservation = reservations[index]
                .expect("destination reservation exists for every received token");
            table.assert_reservation_fresh(reservation);
            let token = transfers.entries[index]
                .take()
                .expect("received transfer batch retains every token");
            let info = PublishedHandleInfo {
                handle: reservation.handle,
                rights: token.requested_rights,
                object_type: token.reference.object_type(),
            };
            table.publish(
                reservation,
                HandleEntry {
                    reference: token.reference,
                    rights: token.requested_rights,
                },
            );
            published[index] = Some(info);
        }
        published
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
