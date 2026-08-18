//! Fixed-capacity, authority-owned `MemoryObject` backing and mapping leases.
//!
//! This is deliberately below handles and syscalls. The only construction
//! boundary consumes a typed frame-role grant; consumers receive opaque object
//! keys and short-lived mapping leases rather than physical addresses or
//! independently constructible backing metadata.

#![allow(
    dead_code,
    reason = "DW0-C establishes this authority model before the later page-table and syscall integration supplies production callers"
)]

use super::address_region::{AddressSpaceKey, RegionKey, mint_authority_domain};
use crate::memory::frame_roles::{
    BackingIdentity, FrameRoleManager, ObjectBackingGrant, ObjectBackingKind,
};
use crate::object::{CreationRef, FinalRelease, ObjectId, ObjectRegistry};
use deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT;

/// The DW0 base page size.
pub(crate) const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryObjectError {
    Empty,
    Unaligned,
    Overflow,
    BackingTooSmall,
    Capacity,
    InvalidObjectKey,
    InvalidLease,
    ForeignLease,
    DuplicateLease,
    LeaseCapacity,
    GenerationExhausted,
    InvalidProtection,
    UnsupportedProtection,
    ProtectionCeiling,
    WritableExecutableAlias,
    BackingKind,
    ObjectIdentity,
    FinalizationMismatch,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectCreateError {
    error: MemoryObjectError,
    backing: ObjectBackingGrant,
}

impl MemoryObjectCreateError {
    pub(crate) const fn error(&self) -> MemoryObjectError {
        self.error
    }

    pub(crate) fn into_backing(self) -> ObjectBackingGrant {
        self.backing
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectFinalizationError {
    error: MemoryObjectError,
    final_release: FinalRelease,
}

impl MemoryObjectFinalizationError {
    pub(crate) const fn error(&self) -> MemoryObjectError {
        self.error
    }

    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

#[must_use = "memory finalization must reclaim or deliberately retire its typed backing"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectFinalization {
    final_release: FinalRelease,
    backing: ObjectBackingGrant,
    kind: MemoryObjectKind,
}

impl MemoryObjectFinalization {
    pub(crate) const fn kind(&self) -> MemoryObjectKind {
        self.kind
    }

    pub(crate) fn into_parts(self) -> (FinalRelease, ObjectBackingGrant) {
        (self.final_release, self.backing)
    }
}

pub(crate) fn complete_memory_finalization<
    const REGISTRY_OBJECTS: usize,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    finalization: MemoryObjectFinalization,
) {
    let kind = finalization.kind;
    let (final_release, backing) = finalization.into_parts();
    match (kind, backing.kind()) {
        (MemoryObjectKind::PageBacked, ObjectBackingKind::AllocatorOwned) => {
            if let Err(error) = roles.cancel_object_backing(backing) {
                panic!(
                    "allocator-backed MemoryObject finalization lost typed backing authority: {error:?}"
                );
            }
        }
        (MemoryObjectKind::ImmutableBootModule, ObjectBackingKind::ImmutableModule { .. }) => {
            // External immutable module pages are deliberately not returned to
            // the dynamic allocator. Consuming the typed grant retires only
            // the logical MemoryObject payload.
            let _retired_immutable_backing = backing;
        }
        _ => panic!("MemoryObject payload/backing kind diverged before finalization"),
    }
    if let Err(error) = registry.complete_finalization(final_release) {
        panic!("generic MemoryObject finalization became invalid after backing cleanup: {error:?}");
    }
}

/// A permission set used both as an object-wide protection ceiling and as one
/// effective mapping protection. A ceiling may include both write and execute
/// so a single object can make an explicit RW -> RX transition, but every
/// effective mapping must remain readable and non-WX.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryProtection(u8);

impl MemoryProtection {
    pub(crate) const READ: Self = Self(1);
    pub(crate) const WRITE: Self = Self(2);
    pub(crate) const EXECUTE: Self = Self(4);
    pub(crate) const READ_WRITE: Self = Self(3);
    pub(crate) const READ_EXECUTE: Self = Self(5);
    pub(crate) const READ_WRITE_EXECUTE: Self = Self(7);

    pub(crate) const fn ceiling(bits: u8) -> Result<Self, MemoryObjectError> {
        if bits == 0 || bits & !0x7 != 0 || bits & Self::READ.0 == 0 {
            return Err(MemoryObjectError::InvalidProtection);
        }
        Ok(Self(bits))
    }

    pub(crate) const fn mapping(bits: u8) -> Result<Self, MemoryObjectError> {
        if bits == Self::WRITE.0 || bits == Self::EXECUTE.0 {
            return Err(MemoryObjectError::UnsupportedProtection);
        }
        let protection = match Self::ceiling(bits) {
            Ok(protection) => protection,
            Err(error) => return Err(error),
        };
        if protection.0 & Self::WRITE.0 != 0 && protection.0 & Self::EXECUTE.0 != 0 {
            return Err(MemoryObjectError::InvalidProtection);
        }
        Ok(protection)
    }

    pub(crate) const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub(crate) const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn writable(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }

    pub(crate) const fn executable(self) -> bool {
        self.0 & Self::EXECUTE.0 != 0
    }
}

/// Backing category used for policy validation only; Deepwyrm does not inspect
/// an immutable boot module as a filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryObjectKind {
    PageBacked,
    #[allow(
        dead_code,
        reason = "bootfs integration constructs immutable module objects after the DW0-C model gate"
    )]
    ImmutableBootModule,
}

/// Opaque authority-issued identity for one page-backed object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectKey {
    object: Option<ObjectId>,
}

impl MemoryObjectKey {
    pub(super) const EMPTY: Self = Self { object: None };

    pub(crate) const fn object_id(self) -> Option<ObjectId> {
        self.object
    }
}

/// Opaque authority-issued identity for one committed mapping lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MappingLease {
    domain: u64,
    raw: u64,
}

impl MappingLease {
    pub(super) const EMPTY: Self = Self { domain: 0, raw: 0 };
}

/// Opaque proof that the future handle-rights seam validated MAP + READ and
/// any requested WRITE/EXECUTE authority for exactly one MemoryObject.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MapAuthorization {
    object: MemoryObjectKey,
    address_space: AddressSpaceKey,
    region: RegionKey,
    ceiling: MemoryProtection,
}

impl MapAuthorization {
    pub(super) fn capture(
        self,
        address_space: AddressSpaceKey,
        region: RegionKey,
    ) -> Result<CapturedMappingAuthority, MemoryObjectError> {
        if self.address_space != address_space || self.region != region {
            return Err(MemoryObjectError::ForeignLease);
        }
        Ok(CapturedMappingAuthority {
            object: self.object,
            ceiling: self.ceiling,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CapturedMappingAuthority {
    object: MemoryObjectKey,
    ceiling: MemoryProtection,
}

impl CapturedMappingAuthority {
    pub(super) const EMPTY: Self = Self {
        object: MemoryObjectKey::EMPTY,
        ceiling: MemoryProtection::READ,
    };
    pub(super) const fn object(self) -> MemoryObjectKey {
        self.object
    }
    const fn ceiling(self) -> MemoryProtection {
        self.ceiling
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectInfo {
    logical_byte_len: u64,
    rounded_byte_len: u64,
    kind: MemoryObjectKind,
    protection_ceiling: MemoryProtection,
}

impl MemoryObjectInfo {
    pub(crate) const fn logical_byte_len(self) -> u64 {
        self.logical_byte_len
    }

    pub(crate) const fn rounded_byte_len(self) -> u64 {
        self.rounded_byte_len
    }

    pub(crate) const fn kind(self) -> MemoryObjectKind {
        self.kind
    }

    #[allow(
        dead_code,
        reason = "callers use the object ceiling to audit authority before constructing a mapping request"
    )]
    pub(crate) const fn protection_ceiling(self) -> MemoryProtection {
        self.protection_ceiling
    }
}

/// A page-aligned portion of an object backing. This remains metadata; no
/// dereferenceable pointer or allocator capability leaves this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectRange {
    backing: BackingIdentity,
    physical_start: u64,
    object_offset: u64,
    byte_len: u64,
}

impl MemoryObjectRange {
    pub(super) const EMPTY: Self = Self {
        backing: BackingIdentity::EMPTY,
        physical_start: 0,
        object_offset: 0,
        byte_len: 0,
    };

    #[allow(
        dead_code,
        reason = "the page-table publisher needs physical backing metadata without exposing allocator authority"
    )]
    pub(crate) const fn physical_start(self) -> u64 {
        self.physical_start
    }

    pub(crate) const fn backing_identity(self) -> BackingIdentity {
        self.backing
    }

    pub(crate) const fn object_offset(self) -> u64 {
        self.object_offset
    }

    #[allow(
        dead_code,
        reason = "the page-table publisher needs the validated range length without exposing allocator authority"
    )]
    pub(crate) const fn byte_len(self) -> u64 {
        self.byte_len
    }
}

/// A requested lease in a prospective replacement batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LeaseRequest {
    address_space: AddressSpaceKey,
    region: RegionKey,
    mapping_authority: CapturedMappingAuthority,
    object_offset: u64,
    byte_len: u64,
    protection: MemoryProtection,
}

impl LeaseRequest {
    pub(super) const EMPTY: Self = Self {
        address_space: AddressSpaceKey::EMPTY,
        region: RegionKey::EMPTY,
        mapping_authority: CapturedMappingAuthority::EMPTY,
        object_offset: 0,
        byte_len: 0,
        protection: MemoryProtection::READ,
    };

    pub(super) const fn new(
        address_space: AddressSpaceKey,
        region: RegionKey,
        mapping_authority: CapturedMappingAuthority,
        object_offset: u64,
        byte_len: u64,
        protection: MemoryProtection,
    ) -> Self {
        Self {
            address_space,
            region,
            mapping_authority,
            object_offset,
            byte_len,
            protection,
        }
    }
}

/// A newly allocated lease paired with the exact validated backing range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LeaseTicket {
    lease: MappingLease,
    object: MemoryObjectKey,
    range: MemoryObjectRange,
    protection: MemoryProtection,
    mapping_authority: CapturedMappingAuthority,
}

impl LeaseTicket {
    pub(super) const fn lease(self) -> MappingLease {
        self.lease
    }

    pub(super) const fn object(self) -> MemoryObjectKey {
        self.object
    }

    pub(super) const fn range(self) -> MemoryObjectRange {
        self.range
    }

    pub(super) const fn protection(self) -> MemoryProtection {
        self.protection
    }

    pub(super) const fn mapping_authority(self) -> CapturedMappingAuthority {
        self.mapping_authority
    }
}

#[derive(Clone, Copy)]
struct ObjectRecord {
    object: ObjectId,
    backing: BackingIdentity,
    physical_start: u64,
    logical_byte_len: u64,
    rounded_byte_len: u64,
    kind: MemoryObjectKind,
    protection_ceiling: MemoryProtection,
}

#[derive(Clone, Copy)]
struct ObjectSlot {
    record: Option<ObjectRecord>,
}

const EMPTY_OBJECT_SLOT: ObjectSlot = ObjectSlot { record: None };

#[derive(Clone, Copy)]
struct LeaseRecord {
    address_space: AddressSpaceKey,
    region: RegionKey,
    object_slot: usize,
    #[allow(
        dead_code,
        reason = "retained for lease provenance when the page-table publisher gains invalidation auditing"
    )]
    range: MemoryObjectRange,
    protection: MemoryProtection,
    #[allow(
        dead_code,
        reason = "retained source authority prevents future replacement paths from widening a lease"
    )]
    mapping_authority: CapturedMappingAuthority,
}

#[derive(Clone, Copy)]
struct LeaseSlot {
    generation: u32,
    record: Option<LeaseRecord>,
}

const EMPTY_LEASE_SLOT: LeaseSlot = LeaseSlot {
    generation: 0,
    record: None,
};

#[derive(Clone, Copy)]
struct PendingLease {
    slot: usize,
    generation: u32,
    record: LeaseRecord,
}

const EMPTY_PENDING: PendingLease = PendingLease {
    slot: 0,
    generation: 0,
    record: LeaseRecord {
        address_space: AddressSpaceKey::EMPTY,
        region: RegionKey::EMPTY,
        object_slot: 0,
        range: MemoryObjectRange {
            backing: BackingIdentity::EMPTY,
            physical_start: 0,
            object_offset: 0,
            byte_len: 0,
        },
        protection: MemoryProtection::READ,
        mapping_authority: CapturedMappingAuthority::EMPTY,
    },
};

/// Fixed-capacity authority over objects and their active mapping leases.
///
/// Every map/protect/unmap replacement is prepared while this authority is
/// mutably borrowed. The prepared batch exposes only tickets and can commit
/// only after its address-space publisher reports an atomic PTE replacement.
pub(crate) struct MemoryObjectAuthority<const OBJECTS: usize, const LEASES: usize> {
    domain: u64,
    objects: [ObjectSlot; OBJECTS],
    backings: [Option<ObjectBackingGrant>; OBJECTS],
    leases: [LeaseSlot; LEASES],
}

impl<const OBJECTS: usize, const LEASES: usize> MemoryObjectAuthority<OBJECTS, LEASES> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_authority_domain(),
            objects: [EMPTY_OBJECT_SLOT; OBJECTS],
            backings: core::array::from_fn(|_| None),
            leases: [EMPTY_LEASE_SLOT; LEASES],
        }
    }

    /// Consumes a frame-role grant, binding its exclusive backing identity to
    /// one object. A failed creation returns the grant for caller rollback.
    pub(crate) fn grant_backing(
        &mut self,
        reference: &CreationRef,
        backing: ObjectBackingGrant,
        logical_byte_len: u64,
        kind: MemoryObjectKind,
        protection_ceiling: MemoryProtection,
    ) -> Result<MemoryObjectKey, MemoryObjectCreateError> {
        let validated = self.validate_backing(
            reference,
            &backing,
            logical_byte_len,
            kind,
            protection_ceiling,
        );
        let (slot, rounded_byte_len) = match validated {
            Ok(validated) => validated,
            Err(error) => return Err(MemoryObjectCreateError { error, backing }),
        };
        let physical_start = backing.physical_start();
        let object = reference.id();
        self.objects[slot] = ObjectSlot {
            record: Some(ObjectRecord {
                object,
                backing: backing.identity(),
                physical_start,
                logical_byte_len,
                rounded_byte_len,
                kind,
                protection_ceiling,
            }),
        };
        self.backings[slot] = Some(backing);
        Ok(MemoryObjectKey {
            object: Some(object),
        })
    }

    fn validate_backing(
        &self,
        reference: &CreationRef,
        backing: &ObjectBackingGrant,
        logical_byte_len: u64,
        kind: MemoryObjectKind,
        protection_ceiling: MemoryProtection,
    ) -> Result<(usize, u64), MemoryObjectError> {
        if reference.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
            return Err(MemoryObjectError::ObjectIdentity);
        }
        let object = reference.id();
        if self
            .objects
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| record.object == object)
        {
            return Err(MemoryObjectError::ObjectIdentity);
        }
        let physical_start = backing.physical_start();
        let backing_len = backing.byte_len();
        if backing_len == 0 || logical_byte_len == 0 {
            return Err(MemoryObjectError::Empty);
        }
        if !physical_start.is_multiple_of(PAGE_SIZE) || !backing_len.is_multiple_of(PAGE_SIZE) {
            return Err(MemoryObjectError::Unaligned);
        }
        if physical_start.checked_add(backing_len).is_none() {
            return Err(MemoryObjectError::Overflow);
        }
        MemoryProtection::ceiling(protection_ceiling.0)?;
        let rounded_byte_len = round_up_to_page(logical_byte_len)?;
        if rounded_byte_len > backing_len {
            return Err(MemoryObjectError::BackingTooSmall);
        }
        if !matches!(
            (kind, backing.kind()),
            (
                MemoryObjectKind::PageBacked,
                ObjectBackingKind::AllocatorOwned
            ) | (
                MemoryObjectKind::ImmutableBootModule,
                ObjectBackingKind::ImmutableModule { .. }
            )
        ) {
            return Err(MemoryObjectError::BackingKind);
        }
        if matches!(kind, MemoryObjectKind::ImmutableBootModule) && protection_ceiling.writable() {
            return Err(MemoryObjectError::ProtectionCeiling);
        }
        let slot = self
            .objects
            .iter()
            .zip(self.backings.iter())
            .position(|(slot, backing)| slot.record.is_none() && backing.is_none())
            .ok_or(MemoryObjectError::Capacity)?;
        Ok((slot, rounded_byte_len))
    }

    pub(crate) fn object_info(
        &self,
        object: MemoryObjectKey,
    ) -> Result<MemoryObjectInfo, MemoryObjectError> {
        let record = self.object_record(object)?;
        Ok(MemoryObjectInfo {
            logical_byte_len: record.logical_byte_len,
            rounded_byte_len: record.rounded_byte_len,
            kind: record.kind,
            protection_ceiling: record.protection_ceiling,
        })
    }

    pub(crate) fn take_finalization(
        &mut self,
        final_release: FinalRelease,
    ) -> Result<MemoryObjectFinalization, MemoryObjectFinalizationError> {
        if final_release.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
            return Err(MemoryObjectFinalizationError {
                error: MemoryObjectError::FinalizationMismatch,
                final_release,
            });
        }
        let object = final_release.id();
        let Some(slot) = self
            .objects
            .iter()
            .position(|slot| slot.record.is_some_and(|record| record.object == object))
        else {
            return Err(MemoryObjectFinalizationError {
                error: MemoryObjectError::FinalizationMismatch,
                final_release,
            });
        };
        let record = self.objects[slot]
            .record
            .take()
            .expect("finalization lookup found a payload record");
        let backing = self.backings[slot]
            .take()
            .expect("memory payload lost its typed backing authority");
        Ok(MemoryObjectFinalization {
            final_release,
            backing,
            kind: record.kind,
        })
    }

    /// Issues an opaque mapping authority after the future handle layer has
    /// validated the exact native rights for `object`.
    ///
    /// # Safety
    ///
    /// The caller must have validated MAP + READ for `object`, plus WRITE
    /// and/or EXECUTE exactly when present in `ceiling`, from a live
    /// rights-bearing handle. DW0-C has no handle table yet, so this narrow
    /// seam is the only construction path and deliberately remains unsafe.
    #[allow(
        unsafe_code,
        reason = "the future rights-validation seam is the sole authority source until DW0-D handles exist"
    )]
    pub(super) unsafe fn issue_map_authorization(
        &self,
        object: MemoryObjectKey,
        address_space: AddressSpaceKey,
        region: RegionKey,
        ceiling: MemoryProtection,
    ) -> Result<MapAuthorization, MemoryObjectError> {
        let record = self.object_record(object)?;
        MemoryProtection::ceiling(ceiling.bits())?;
        if !record.protection_ceiling.contains(ceiling) {
            return Err(MemoryObjectError::ProtectionCeiling);
        }
        if !address_space.same_domain(region) {
            return Err(MemoryObjectError::ForeignLease);
        }
        Ok(MapAuthorization {
            object,
            address_space,
            region,
            ceiling,
        })
    }

    pub(crate) const fn active_lease_count(&self) -> usize {
        let mut count = 0;
        let mut index = 0;
        while index < LEASES {
            if self.leases[index].record.is_some() {
                count += 1;
            }
            index += 1;
        }
        count
    }

    /// Validates a complete replacement while retaining mutable authority.
    /// Dropping the returned batch releases no resource; `commit` is the only
    /// mutation point and is intentionally infallible after publication.
    pub(super) fn prepare_replace<const BATCH: usize>(
        &mut self,
        address_space: AddressSpaceKey,
        region: RegionKey,
        released: &[MappingLease],
        requested: &[LeaseRequest],
    ) -> Result<PreparedReplace<'_, OBJECTS, LEASES, BATCH>, MemoryObjectError> {
        if !address_space.same_domain(region) {
            return Err(MemoryObjectError::ForeignLease);
        }
        if released.is_empty() && requested.is_empty() {
            return Err(MemoryObjectError::Empty);
        }
        if released.len() > BATCH || requested.len() > BATCH {
            return Err(MemoryObjectError::LeaseCapacity);
        }
        let mut release_slots = [usize::MAX; BATCH];
        for (position, lease) in released.iter().copied().enumerate() {
            let slot = self.lease_slot(lease)?;
            let record = self.leases[slot]
                .record
                .expect("validated lease slot has a record");
            if record.address_space != address_space || record.region != region {
                return Err(MemoryObjectError::ForeignLease);
            }
            if release_slots[..position].contains(&slot) {
                return Err(MemoryObjectError::DuplicateLease);
            }
            release_slots[position] = slot;
        }

        let mut writable = [false; OBJECTS];
        let mut executable = [false; OBJECTS];
        for (slot, lease) in self.leases.iter().enumerate() {
            let Some(record) = lease.record else {
                continue;
            };
            if release_slots[..released.len()].contains(&slot) {
                continue;
            }
            writable[record.object_slot] |= record.protection.writable();
            executable[record.object_slot] |= record.protection.executable();
        }

        let reusable_slots = self
            .leases
            .iter()
            .enumerate()
            .filter(|(slot, lease)| {
                lease.record.is_none() || release_slots[..released.len()].contains(slot)
            })
            .count();
        if requested.len() > reusable_slots {
            return Err(MemoryObjectError::LeaseCapacity);
        }

        let mut pending = [EMPTY_PENDING; BATCH];
        let mut tickets = [None; BATCH];
        let mut candidate_cursor = 0;
        for (position, request) in requested.iter().copied().enumerate() {
            if request.address_space != address_space || request.region != region {
                return Err(MemoryObjectError::ForeignLease);
            }
            let object_key = request.mapping_authority.object();
            let object_slot = self.object_slot(object_key)?;
            let object = self.objects[object_slot]
                .record
                .expect("validated object slot has a record");
            MemoryProtection::mapping(request.protection.0)?;
            MemoryProtection::ceiling(request.mapping_authority.ceiling().0)?;
            if !object
                .protection_ceiling
                .contains(request.mapping_authority.ceiling())
                || !request
                    .mapping_authority
                    .ceiling()
                    .contains(request.protection)
            {
                return Err(MemoryObjectError::ProtectionCeiling);
            }
            if matches!(object.kind, MemoryObjectKind::ImmutableBootModule)
                && request.protection.writable()
            {
                return Err(MemoryObjectError::ProtectionCeiling);
            }
            let range = object_range(object, request.object_offset, request.byte_len)?;
            if (request.protection.writable() && executable[object_slot])
                || (request.protection.executable() && writable[object_slot])
            {
                return Err(MemoryObjectError::WritableExecutableAlias);
            }
            writable[object_slot] |= request.protection.writable();
            executable[object_slot] |= request.protection.executable();

            let slot = loop {
                let slot = candidate_cursor;
                candidate_cursor += 1;
                if self.leases[slot].record.is_none()
                    || release_slots[..released.len()].contains(&slot)
                {
                    break slot;
                }
            };
            let generation = next_generation(self.leases[slot].generation)?;
            let lease = MappingLease {
                domain: self.domain,
                raw: encode_raw_key(slot, generation),
            };
            let record = LeaseRecord {
                address_space,
                region,
                object_slot,
                range,
                protection: request.protection,
                mapping_authority: request.mapping_authority,
            };
            pending[position] = PendingLease {
                slot,
                generation,
                record,
            };
            tickets[position] = Some(LeaseTicket {
                lease,
                object: object_key,
                range,
                protection: request.protection,
                mapping_authority: request.mapping_authority,
            });
        }
        Ok(PreparedReplace {
            authority: self,
            released: release_slots,
            released_len: released.len(),
            pending,
            pending_len: requested.len(),
            tickets,
        })
    }

    fn object_slot(&self, object: MemoryObjectKey) -> Result<usize, MemoryObjectError> {
        let object = object.object.ok_or(MemoryObjectError::InvalidObjectKey)?;
        self.objects
            .iter()
            .position(|slot| slot.record.is_some_and(|record| record.object == object))
            .ok_or(MemoryObjectError::InvalidObjectKey)
    }

    fn object_record(&self, object: MemoryObjectKey) -> Result<ObjectRecord, MemoryObjectError> {
        let slot = self.object_slot(object)?;
        Ok(self.objects[slot]
            .record
            .expect("validated object slot has a record"))
    }

    fn lease_slot(&self, lease: MappingLease) -> Result<usize, MemoryObjectError> {
        if lease.domain != self.domain {
            return Err(MemoryObjectError::InvalidLease);
        }
        let (slot, generation) =
            decode_raw_key(lease.raw).ok_or(MemoryObjectError::InvalidLease)?;
        let entry = self
            .leases
            .get(slot)
            .ok_or(MemoryObjectError::InvalidLease)?;
        if entry.generation != generation || entry.record.is_none() {
            return Err(MemoryObjectError::InvalidLease);
        }
        Ok(slot)
    }
}

/// A validated replacement batch held under an exclusive authority borrow.
pub(super) struct PreparedReplace<'a, const OBJECTS: usize, const LEASES: usize, const BATCH: usize>
{
    authority: &'a mut MemoryObjectAuthority<OBJECTS, LEASES>,
    released: [usize; BATCH],
    released_len: usize,
    pending: [PendingLease; BATCH],
    pending_len: usize,
    tickets: [Option<LeaseTicket>; BATCH],
}

impl<const OBJECTS: usize, const LEASES: usize, const BATCH: usize>
    PreparedReplace<'_, OBJECTS, LEASES, BATCH>
{
    pub(super) fn tickets(&self) -> &[Option<LeaseTicket>] {
        &self.tickets[..self.pending_len]
    }

    /// Commits only after the caller's address-space publisher has atomically
    /// accepted the corresponding PTE replacement. This has no fallible work:
    /// it clears released leases and installs the already-validated tickets.
    pub(super) fn commit(mut self) {
        for slot in self.released[..self.released_len].iter().copied() {
            self.authority.leases[slot].record = None;
        }
        for pending in self.pending[..self.pending_len].iter().copied() {
            self.authority.leases[pending.slot] = LeaseSlot {
                generation: pending.generation,
                record: Some(pending.record),
            };
        }
        self.released_len = 0;
        self.pending_len = 0;
    }
}

fn round_up_to_page(byte_len: u64) -> Result<u64, MemoryObjectError> {
    byte_len
        .checked_add(PAGE_SIZE - 1)
        .ok_or(MemoryObjectError::Overflow)
        .map(|value| value / PAGE_SIZE * PAGE_SIZE)
}

fn object_range(
    object: ObjectRecord,
    object_offset: u64,
    byte_len: u64,
) -> Result<MemoryObjectRange, MemoryObjectError> {
    if byte_len == 0 {
        return Err(MemoryObjectError::Empty);
    }
    if !object_offset.is_multiple_of(PAGE_SIZE) || !byte_len.is_multiple_of(PAGE_SIZE) {
        return Err(MemoryObjectError::Unaligned);
    }
    let end = object_offset
        .checked_add(byte_len)
        .ok_or(MemoryObjectError::Overflow)?;
    if end > object.rounded_byte_len {
        return Err(MemoryObjectError::BackingTooSmall);
    }
    let physical_start = object
        .physical_start
        .checked_add(object_offset)
        .ok_or(MemoryObjectError::Overflow)?;
    Ok(MemoryObjectRange {
        backing: object.backing,
        physical_start,
        object_offset,
        byte_len,
    })
}

fn next_generation(generation: u32) -> Result<u32, MemoryObjectError> {
    generation
        .checked_add(1)
        .filter(|next| *next != 0)
        .ok_or(MemoryObjectError::GenerationExhausted)
}

fn encode_raw_key(slot: usize, generation: u32) -> u64 {
    (u64::from(generation) << 32) | u64::try_from(slot + 1).expect("slot fits u64")
}

fn decode_raw_key(raw: u64) -> Option<(usize, u32)> {
    let generation = (raw >> 32) as u32;
    let slot = usize::try_from((raw & u64::from(u32::MAX)).checked_sub(1)?).ok()?;
    (generation != 0).then_some((slot, generation))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::address_region::AddressSpaceAuthority;
    use super::*;
    use crate::object::ObjectRegistry;
    use std::boxed::Box;

    fn grant<const OBJECTS: usize, const LEASES: usize>(
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<OBJECTS>,
        logical_byte_len: u64,
        ceiling: MemoryProtection,
    ) -> (MemoryObjectKey, CreationRef) {
        let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x20_000, 4);
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let key = authority
            .grant_backing(
                &creation,
                backing,
                logical_byte_len,
                MemoryObjectKind::PageBacked,
                ceiling,
            )
            .unwrap();
        (key, creation)
    }

    #[allow(
        unsafe_code,
        reason = "tests stand in for the future handle-rights validation seam"
    )]
    fn mapping<const OBJECTS: usize, const LEASES: usize>(
        authority: &MemoryObjectAuthority<OBJECTS, LEASES>,
        object: MemoryObjectKey,
        ceiling: MemoryProtection,
    ) -> CapturedMappingAuthority {
        let _ = authority;
        CapturedMappingAuthority { object, ceiling }
    }

    #[allow(
        unsafe_code,
        reason = "test-local address-space registries satisfy the unique-root authority contract"
    )]
    fn ids() -> (AddressSpaceKey, RegionKey) {
        // SAFETY: this test-local registry uniquely owns its synthetic root.
        // Leaking it makes the registry outlive every returned identity.
        let spaces = Box::leak(Box::new(unsafe { AddressSpaceAuthority::<1, 1>::new() }));
        let space = spaces.create_address_space().unwrap();
        let region = spaces
            .create_region::<1>(space, PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        (space, region.region_key())
    }

    #[test]
    fn allocator_grant_preserves_exact_and_rounded_lengths() {
        let mut registry = ObjectRegistry::<2>::new();
        let mut authority = MemoryObjectAuthority::<2, 4>::new();
        let (key, _creation) = grant(
            &mut authority,
            &mut registry,
            PAGE_SIZE + 1,
            MemoryProtection::READ_WRITE_EXECUTE,
        );
        let info = authority.object_info(key).unwrap();
        assert_eq!(info.logical_byte_len(), PAGE_SIZE + 1);
        assert_eq!(info.rounded_byte_len(), PAGE_SIZE * 2);
        assert_eq!(info.kind(), MemoryObjectKind::PageBacked);
    }

    #[test]
    fn typed_backing_identity_is_retained_and_failed_creation_returns_the_grant() {
        let mut registry = ObjectRegistry::<2>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut authority = MemoryObjectAuthority::<2, 2>::new();
        let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x20_000, 1);
        let expected_identity = backing.identity();
        let error = authority
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE * 2,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ_WRITE,
            )
            .unwrap_err();
        assert_eq!(error.error(), MemoryObjectError::BackingTooSmall);

        let backing = error.into_backing();
        assert_eq!(backing.identity(), expected_identity);
        let key = authority
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ_WRITE,
            )
            .unwrap();
        assert_eq!(
            authority.object_record(key).unwrap().backing,
            expected_identity
        );
    }

    #[test]
    fn immutable_module_grant_rejects_role_confusion_and_writable_ceiling() {
        let mut registry = ObjectRegistry::<2>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut authority = MemoryObjectAuthority::<2, 2>::new();
        let backing =
            crate::memory::frame_roles::synthetic_immutable_module_backing(0x30_000, 1, 9);
        let error = authority
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ,
            )
            .unwrap_err();
        assert_eq!(error.error(), MemoryObjectError::BackingKind);

        let error = authority
            .grant_backing(
                &creation,
                error.into_backing(),
                PAGE_SIZE,
                MemoryObjectKind::ImmutableBootModule,
                MemoryProtection::READ_WRITE,
            )
            .unwrap_err();
        assert_eq!(error.error(), MemoryObjectError::ProtectionCeiling);

        let key = authority
            .grant_backing(
                &creation,
                error.into_backing(),
                PAGE_SIZE,
                MemoryObjectKind::ImmutableBootModule,
                MemoryProtection::READ,
            )
            .unwrap();
        assert_eq!(
            authority.object_info(key).unwrap().kind(),
            MemoryObjectKind::ImmutableBootModule
        );
    }

    #[test]
    fn final_page_tail_is_mapping_capacity_but_not_logical_object_size() {
        let (space, region) = ids();
        let mut registry = ObjectRegistry::<2>::new();
        let mut authority = MemoryObjectAuthority::<2, 4>::new();
        let (key, _creation) = grant(
            &mut authority,
            &mut registry,
            PAGE_SIZE + 1,
            MemoryProtection::READ_WRITE,
        );
        let info = authority.object_info(key).unwrap();
        assert_eq!(info.logical_byte_len(), PAGE_SIZE + 1);
        assert_eq!(info.rounded_byte_len(), PAGE_SIZE * 2);
        let token = mapping(&authority, key, MemoryProtection::READ_WRITE);
        authority
            .prepare_replace::<1>(
                space,
                region,
                &[],
                &[LeaseRequest::new(
                    space,
                    region,
                    token,
                    PAGE_SIZE,
                    PAGE_SIZE,
                    MemoryProtection::READ,
                )],
            )
            .unwrap()
            .commit();
        assert_eq!(authority.active_lease_count(), 1);
    }

    #[test]
    fn replacement_rejects_bad_ranges_and_wx_aliases_without_commit() {
        let (space, region) = ids();
        let mut registry = ObjectRegistry::<2>::new();
        let mut authority = MemoryObjectAuthority::<2, 4>::new();
        let (key, _creation) = grant(
            &mut authority,
            &mut registry,
            PAGE_SIZE * 2,
            MemoryProtection::READ_WRITE_EXECUTE,
        );
        let read = mapping(&authority, key, MemoryProtection::READ);
        let read_write = mapping(&authority, key, MemoryProtection::READ_WRITE);
        let read_write_execute = mapping(&authority, key, MemoryProtection::READ_WRITE_EXECUTE);
        assert!(matches!(
            authority.prepare_replace::<2>(
                space,
                region,
                &[],
                &[LeaseRequest::new(
                    space,
                    region,
                    read,
                    1,
                    PAGE_SIZE,
                    MemoryProtection::READ,
                )],
            ),
            Err(MemoryObjectError::Unaligned)
        ));
        let prepared = authority
            .prepare_replace::<2>(
                space,
                region,
                &[],
                &[LeaseRequest::new(
                    space,
                    region,
                    read_write,
                    0,
                    PAGE_SIZE,
                    MemoryProtection::READ_WRITE,
                )],
            )
            .unwrap();
        prepared.commit();
        assert_eq!(authority.active_lease_count(), 1);
        assert!(matches!(
            authority.prepare_replace::<2>(
                space,
                region,
                &[],
                &[LeaseRequest::new(
                    space,
                    region,
                    read_write_execute,
                    PAGE_SIZE,
                    PAGE_SIZE,
                    MemoryProtection::READ_EXECUTE,
                )],
            ),
            Err(MemoryObjectError::WritableExecutableAlias)
        ));
        assert_eq!(authority.active_lease_count(), 1);
    }

    #[test]
    fn protection_ceiling_is_captured_per_object() {
        let (space, region) = ids();
        let mut registry = ObjectRegistry::<2>::new();
        let mut authority = MemoryObjectAuthority::<2, 2>::new();
        let (key, _creation) = grant(
            &mut authority,
            &mut registry,
            PAGE_SIZE,
            MemoryProtection::READ_WRITE,
        );
        let read_write = mapping(&authority, key, MemoryProtection::READ_WRITE);
        assert!(matches!(
            authority.prepare_replace::<1>(
                space,
                region,
                &[],
                &[LeaseRequest::new(
                    space,
                    region,
                    read_write,
                    0,
                    PAGE_SIZE,
                    MemoryProtection::READ_EXECUTE,
                )],
            ),
            Err(MemoryObjectError::ProtectionCeiling)
        ));
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "test manager models complete physical zeroing before typed backing assignment"
    )]
    fn allocator_backing_is_reclaimed_only_through_typed_finalization() {
        let mut roles =
            crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
        let allocation = roles.allocate(1).unwrap();
        let physical_start = allocation.physical_start();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let backing = roles.assign_object_backing(zeroed).unwrap();

        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        let key = authority
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ_WRITE,
            )
            .unwrap();
        let final_release = registry.release_creation(creation).unwrap().unwrap();
        let finalization = authority.take_finalization(final_release).unwrap();
        assert_eq!(
            authority.object_info(key),
            Err(MemoryObjectError::InvalidObjectKey)
        );
        complete_memory_finalization(&mut registry, &mut roles, finalization);

        let recycled = roles.allocate(1).unwrap();
        assert_eq!(recycled.physical_start(), physical_start);
    }

    #[test]
    fn immutable_backing_retires_logically_without_allocator_reclamation() {
        let mut roles =
            crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 2);
        let backing =
            crate::memory::frame_roles::synthetic_immutable_module_backing(0x80_000, 1, 7);
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        authority
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::ImmutableBootModule,
                MemoryProtection::READ,
            )
            .unwrap();
        let final_release = registry.release_creation(creation).unwrap().unwrap();
        let finalization = authority.take_finalization(final_release).unwrap();
        complete_memory_finalization(&mut registry, &mut roles, finalization);

        assert!(registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).is_ok());
        assert_eq!(roles.allocate(2).unwrap().byte_len(), PAGE_SIZE * 2);
    }

    #[test]
    fn wrong_final_release_cannot_consume_memory_payload() {
        use deepwyrm_abi::DW_OBJECT_TYPE_EVENT;

        let mut registry = ObjectRegistry::<2>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let event = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x20_000, 1);
        let key = authority
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ,
            )
            .unwrap();
        let event_final = registry.release_creation(event).unwrap().unwrap();
        let error = authority.take_finalization(event_final).unwrap_err();
        assert_eq!(error.error(), MemoryObjectError::FinalizationMismatch);
        let event_final = error.into_final_release();
        registry.complete_finalization(event_final).unwrap();
        assert!(authority.object_info(key).is_ok());
    }

    #[test]
    fn empty_replacements_and_sentinels_never_enter_lease_transitions() {
        let (space, region) = ids();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        assert!(matches!(
            authority.prepare_replace::<1>(space, region, &[], &[]),
            Err(MemoryObjectError::Empty)
        ));
        assert!(matches!(
            authority.prepare_replace::<1>(space, region, &[], &[LeaseRequest::EMPTY]),
            Err(MemoryObjectError::ForeignLease)
        ));
        assert!(matches!(
            authority.prepare_replace::<1>(AddressSpaceKey::EMPTY, RegionKey::EMPTY, &[], &[],),
            Err(MemoryObjectError::ForeignLease)
        ));
        assert_eq!(authority.active_lease_count(), 0);
    }
}
