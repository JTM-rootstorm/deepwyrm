//! Fixed-capacity, authority-owned `MemoryObject` backing and mapping leases.
//!
//! This is deliberately below handles and syscalls. The only construction
//! boundary consumes a typed frame-role grant; consumers receive opaque object
//! keys and short-lived mapping leases rather than physical addresses or
//! independently constructible backing metadata.

#![allow(
    dead_code,
    reason = "DW0-C/D4 expose memory-object and lease authority ahead of DW0-D5/E service and syscall consumers"
)]

use super::address_region::{AddressSpaceKey, RegionKey, mint_authority_domain};
use crate::handle::ResolvedHandle;
use crate::memory::frame_roles::{
    BackingIdentity, FrameRoleManager, ObjectBackingGrant, ObjectBackingKind,
};
use crate::object::{CreationRef, FinalRelease, InternalRef, ObjectId, ObjectRegistry};
use deepwyrm_abi::{
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_EXECUTE, DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_WRITE,
};

#[path = "object/lease.rs"]
mod lease;

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
    ObjectReference,
    InsufficientRights,
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
pub(crate) struct MemoryObjectBindError {
    error: MemoryObjectError,
    creation: CreationRef,
    backing: ObjectBackingGrant,
}

impl MemoryObjectBindError {
    pub(crate) const fn error(&self) -> MemoryObjectError {
        self.error
    }
    pub(crate) fn into_parts(self) -> (CreationRef, ObjectBackingGrant) {
        (self.creation, self.backing)
    }
}

#[must_use = "a bound MemoryObject payload must be sealed by ObjectRegistry before publication"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectBinding {
    creation: CreationRef,
    key: MemoryObjectKey,
}

impl MemoryObjectBinding {
    pub(crate) const fn key(&self) -> MemoryObjectKey {
        self.key
    }
    pub(crate) fn into_creation(self) -> CreationRef {
        self.creation
    }
}

#[must_use = "authorization failure returns a live lookup pin that must be released or reused"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MapAuthorizationCreateError {
    error: MemoryObjectError,
    resolved: ResolvedHandle,
}

impl MapAuthorizationCreateError {
    pub(crate) const fn error(&self) -> MemoryObjectError {
        self.error
    }

    pub(crate) fn into_resolved(self) -> ResolvedHandle {
        self.resolved
    }

    pub(crate) fn release<const REGISTRY_OBJECTS: usize>(
        self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    ) -> (MemoryObjectError, MappingFinalReleases<REGISTRY_OBJECTS>) {
        let error = self.error;
        let pin = self.resolved.into_internal();
        let mut final_releases = MappingFinalReleases::empty();
        release_internal_pin(registry, pin, &mut final_releases);
        (error, final_releases)
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

#[must_use = "typed MemoryObject cleanup must be consumed by the generic object registry"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MemoryObjectCleanup {
    final_release: FinalRelease,
}

impl MemoryObjectCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
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
    let cleanup = MemoryObjectCleanup { final_release };
    if let Err(error) = registry.complete_payload_finalization(cleanup) {
        panic!(
            "generic MemoryObject finalization became invalid after typed backing cleanup: {error:?}"
        );
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

/// Opaque one-shot proof produced by consuming a D3-resolved MemoryObject
/// handle with MAP + READ and any requested WRITE/EXECUTE authority.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MapAuthorization {
    object: MemoryObjectKey,
    address_space: AddressSpaceKey,
    region: RegionKey,
    ceiling: MemoryProtection,
    pin: InternalRef,
}

impl MapAuthorization {
    pub(super) fn capture(
        &self,
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

    fn object_id(&self) -> ObjectId {
        self.pin.id()
    }

    pub(super) fn release<const REGISTRY_OBJECTS: usize>(
        self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    ) -> MappingFinalReleases<REGISTRY_OBJECTS> {
        let mut final_releases = MappingFinalReleases::empty();
        release_map_authorization(registry, self, &mut final_releases);
        final_releases
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

#[must_use = "mapping reference releases may contain final MemoryObject cleanup authority"]
#[derive(Debug)]
pub(crate) struct MappingFinalReleases<const CAPACITY: usize> {
    items: [Option<FinalRelease>; CAPACITY],
    count: usize,
}

impl<const CAPACITY: usize> MappingFinalReleases<CAPACITY> {
    pub(crate) fn empty() -> Self {
        Self {
            items: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn push(&mut self, release: FinalRelease) {
        assert!(
            self.count < CAPACITY,
            "mapping final-release batch overflow"
        );
        self.items[self.count] = Some(release);
        self.count += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.count
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(crate) fn into_items(self) -> [Option<FinalRelease>; CAPACITY] {
        self.items
    }
}

#[derive(Debug)]
pub(super) struct PrepareReplaceError<const CAPACITY: usize> {
    error: MemoryObjectError,
    final_releases: MappingFinalReleases<CAPACITY>,
}

impl<const CAPACITY: usize> PrepareReplaceError<CAPACITY> {
    pub(super) const fn error(&self) -> MemoryObjectError {
        self.error
    }

    pub(super) fn into_final_releases(self) -> MappingFinalReleases<CAPACITY> {
        self.final_releases
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
struct LeaseMetadata {
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

struct LeaseRecord {
    metadata: LeaseMetadata,
    pin: InternalRef,
}

struct LeaseSlot {
    generation: u32,
    record: Option<LeaseRecord>,
}

#[derive(Clone, Copy)]
enum ExistingPinSource {
    Released(usize),
    Authorization,
}

#[derive(Clone, Copy)]
enum PendingPinSource {
    Released(usize),
    Authorization,
    Extra(usize),
}

#[derive(Clone, Copy)]
struct PendingLease {
    slot: usize,
    generation: u32,
    metadata: LeaseMetadata,
    pin_source: PendingPinSource,
}

struct ReplacePlan<const BATCH: usize> {
    released: [usize; BATCH],
    released_len: usize,
    pending: [Option<PendingLease>; BATCH],
    pending_len: usize,
    tickets: [Option<LeaseTicket>; BATCH],
    extra_sources: [Option<ExistingPinSource>; BATCH],
    extra_len: usize,
}

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
            leases: core::array::from_fn(|_| LeaseSlot {
                generation: 0,
                record: None,
            }),
        }
    }

    /// Production binding path. Consumes the sole unpublished generic creation
    /// authority and typed backing, then returns the only proof from which the
    /// generic registry may publish a first owner.
    pub(crate) fn bind_backing(
        &mut self,
        creation: CreationRef,
        backing: ObjectBackingGrant,
        logical_byte_len: u64,
        kind: MemoryObjectKind,
        protection_ceiling: MemoryProtection,
    ) -> Result<MemoryObjectBinding, MemoryObjectBindError> {
        let validated = self.validate_backing(
            &creation,
            &backing,
            logical_byte_len,
            kind,
            protection_ceiling,
        );
        let (slot, rounded_byte_len) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                return Err(MemoryObjectBindError {
                    error,
                    creation,
                    backing,
                });
            }
        };
        let key = self.install_backing(
            slot,
            creation.id(),
            backing,
            logical_byte_len,
            rounded_byte_len,
            kind,
            protection_ceiling,
        );
        Ok(MemoryObjectBinding { creation, key })
    }

    /// Test-support compatibility path. Production payload-bearing construction
    /// must use `bind_backing`, which consumes CreationRef.
    #[cfg(any(test, feature = "test-support"))]
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
        Ok(self.install_backing(
            slot,
            reference.id(),
            backing,
            logical_byte_len,
            rounded_byte_len,
            kind,
            protection_ceiling,
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "typed backing installation keeps object identity, exact/rounded extent, kind, and protection ceiling explicit"
    )]
    fn install_backing(
        &mut self,
        slot: usize,
        object: ObjectId,
        backing: ObjectBackingGrant,
        logical_byte_len: u64,
        rounded_byte_len: u64,
        kind: MemoryObjectKind,
        protection_ceiling: MemoryProtection,
    ) -> MemoryObjectKey {
        let physical_start = backing.physical_start();
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
        MemoryObjectKey {
            object: Some(object),
        }
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

    pub(crate) fn object_info_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<MemoryObjectInfo, MemoryObjectError> {
        if resolved.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
            return Err(MemoryObjectError::ObjectReference);
        }
        self.object_info(MemoryObjectKey {
            object: Some(resolved.object_id()),
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

    /// Consumes one D3 lookup pin into a region-bound mapping authorization.
    ///
    /// The resolved handle itself is the pre-publication strong reference. No
    /// second retain occurs here: successful validation moves that exact pin
    /// into `MapAuthorization`, while every failure returns the still-live
    /// `ResolvedHandle` unchanged to its caller.
    pub(crate) fn issue_map_authorization(
        &self,
        resolved: ResolvedHandle,
        address_space: AddressSpaceKey,
        region: RegionKey,
        ceiling: MemoryProtection,
    ) -> Result<MapAuthorization, MapAuthorizationCreateError> {
        if let Err(error) = MemoryProtection::ceiling(ceiling.bits()) {
            return Err(MapAuthorizationCreateError { error, resolved });
        }
        if resolved.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
            return Err(MapAuthorizationCreateError {
                error: MemoryObjectError::ObjectReference,
                resolved,
            });
        }

        let mut required = DW_RIGHT_MAP.0 | DW_RIGHT_READ.0;
        if ceiling.writable() {
            required |= DW_RIGHT_WRITE.0;
        }
        if ceiling.executable() {
            required |= DW_RIGHT_EXECUTE.0;
        }
        if resolved.rights().0 & required != required {
            return Err(MapAuthorizationCreateError {
                error: MemoryObjectError::InsufficientRights,
                resolved,
            });
        }

        let object = MemoryObjectKey {
            object: Some(resolved.object_id()),
        };
        let record = match self.object_record(object) {
            Ok(record) => record,
            Err(error) => return Err(MapAuthorizationCreateError { error, resolved }),
        };
        if !record.protection_ceiling.contains(ceiling) {
            return Err(MapAuthorizationCreateError {
                error: MemoryObjectError::ProtectionCeiling,
                resolved,
            });
        }
        if !address_space.same_domain(region) {
            return Err(MapAuthorizationCreateError {
                error: MemoryObjectError::ForeignLease,
                resolved,
            });
        }

        let pin = resolved.into_internal();
        Ok(MapAuthorization {
            object,
            address_space,
            region,
            ceiling,
            pin,
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

    /// Prepares one mapping replacement without changing committed leases.
    ///
    /// Existing released-lease pins remain installed until publication succeeds.
    /// The optional authorization contributes exactly one already-retained pin;
    /// only positive per-object lease-count deltas retain additional pins.
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

fn release_internal_pin<const REGISTRY_OBJECTS: usize>(
    registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    pin: InternalRef,
    final_releases: &mut MappingFinalReleases<REGISTRY_OBJECTS>,
) {
    match registry.release_internal(pin) {
        Ok(Some(final_release)) => final_releases.push(final_release),
        Ok(None) => {}
        Err(error) => panic!("mapping pin release violated generic object invariants: {error:?}"),
    }
}

fn release_map_authorization<const REGISTRY_OBJECTS: usize>(
    registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    authorization: MapAuthorization,
    final_releases: &mut MappingFinalReleases<REGISTRY_OBJECTS>,
) {
    release_internal_pin(registry, authorization.pin, final_releases);
}

/// A validated replacement batch held under exclusive memory/registry borrows.
pub(super) struct PreparedReplace<
    'a,
    const OBJECTS: usize,
    const LEASES: usize,
    const BATCH: usize,
    const REGISTRY_OBJECTS: usize,
> {
    authority: &'a mut MemoryObjectAuthority<OBJECTS, LEASES>,
    registry: &'a mut ObjectRegistry<REGISTRY_OBJECTS>,
    plan: ReplacePlan<BATCH>,
    extra_pins: [Option<InternalRef>; BATCH],
    authorization: Option<MapAuthorization>,
    finished: bool,
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
#[allow(
    clippy::err_expect,
    reason = "prepared mapping transactions intentionally omit Debug; negative tests must consume errors without widening that authority surface"
)]
#[path = "object/tests.rs"]
mod tests;
