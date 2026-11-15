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
use crate::object::{CreationRef, FinalRelease, HandleRef, InternalRef, ObjectId, ObjectRegistry};
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
    ) -> (MemoryObjectError, MappingFinalReleases) {
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
    /// DeviceMmio only: the DeviceResource the BAR belongs to, kept alive for
    /// as long as this object (and so any mapping of it) exists.
    parent: Option<InternalRef>,
}

impl MemoryObjectFinalization {
    pub(crate) const fn kind(&self) -> MemoryObjectKind {
        self.kind
    }

    pub(crate) fn into_parts(self) -> (FinalRelease, ObjectBackingGrant) {
        assert!(
            self.parent.is_none(),
            "a DeviceMmio MemoryObject must finalize through complete_memory_finalization"
        );
        (self.final_release, self.backing)
    }

    pub(crate) const fn backing_physical_start(&self) -> u64 {
        self.backing.physical_start()
    }
}

/// Splits a transaction-cancelled page-backed object into its generic cleanup
/// proof and typed backing. The integrated caller completes registry cleanup.
pub(crate) fn into_page_backed_cancellation_parts(
    finalization: MemoryObjectFinalization,
) -> (MemoryObjectCleanup, ObjectBackingGrant) {
    assert_eq!(
        finalization.kind(),
        MemoryObjectKind::PageBacked,
        "primordial cancellation only recycles allocator-backed objects"
    );
    let (final_release, backing) = finalization.into_parts();
    (MemoryObjectCleanup { final_release }, backing)
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

#[cfg(deepwyrm_integrated)]
#[must_use = "a DeviceMmio object's parent release must be finalized, not dropped"]
pub(crate) fn complete_memory_finalization<
    const REGISTRY_OBJECTS: usize,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    finalization: MemoryObjectFinalization,
) -> Option<FinalRelease> {
    let MemoryObjectFinalization {
        final_release,
        backing,
        kind,
        parent,
    } = finalization;
    assert_eq!(
        parent.is_some(),
        kind == MemoryObjectKind::DeviceMmio,
        "exactly the DeviceMmio objects hold a parent reference"
    );
    let mut parent_release = None;
    match (kind, backing.kind()) {
        (MemoryObjectKind::PageBacked, ObjectBackingKind::AllocatorOwned)
        | (MemoryObjectKind::OnDemand, ObjectBackingKind::OnDemand) => {
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
        (MemoryObjectKind::DeviceMmio, ObjectBackingKind::DeviceMmio) => {
            // The BAR's role is permanent; the grant goes back to the probe
            // table so a later object can be made over the same BAR. Only
            // then is the DeviceResource let go, so a new lease never sees a
            // BAR that an older object still names.
            crate::device::pci::PCI_FUNCTIONS.return_bar_backing(backing);
            let parent =
                parent.expect("a DeviceMmio MemoryObject lost its DeviceResource reference");
            parent_release = registry.release_internal(parent).unwrap_or_else(|failure| {
                panic!(
                    "DeviceMmio finalization lost its DeviceResource reference: {:?}",
                    failure.error()
                )
            });
        }
        _ => panic!("MemoryObject payload/backing kind diverged before finalization"),
    }
    let cleanup = MemoryObjectCleanup { final_release };
    if let Err(error) = registry.complete_payload_finalization(cleanup) {
        panic!(
            "generic MemoryObject finalization became invalid after typed backing cleanup: {error:?}"
        );
    }
    parent_release
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
    /// One whole PCI memory BAR (storage K3).
    DeviceMmio,
    /// Allocator RAM given page by page on first touch (DW2 M6 §8.3).
    OnDemand,
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
    ) -> MappingFinalReleases {
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

/// The most mappings one replace transaction may hold on either side: the
/// largest per-region slot count any build may select.
pub(crate) const MAX_MAPPING_BATCH: usize = 64;

/// One replace transaction drops at most its released leases' pins, its
/// surplus pins and its authorization: `2 * BATCH + 1`. Sizing the batch by
/// the transaction rather than by the object registry keeps every frame that
/// carries one small (it was 640 entries, several copies per frame; DW2 plan
/// §10.2 item 2).
pub(crate) const MAPPING_FINAL_RELEASE_CAPACITY: usize = 2 * MAX_MAPPING_BATCH + 1;

/// The pins of the leases a committed replace took out of the page tables.
///
/// Each pin keeps its object alive, so its frames stay allocated, until every
/// CPU has acknowledged the removal: acknowledgement precedes reclamation
/// (H0 §12.6). Releasing a pin at commit, before the shootdown settled, let
/// another holder's last release finalize the object and free frames a remote
/// TLB still mapped (DW2 §10.9 review, finding F1). Family G hands these to
/// [`crate::syscall::HeldReleases`], which releases them on the settlement;
/// a path where no other CPU can hold the translation releases them at once
/// with [`MappingFinalReleases::settle_locally`]. Dropping a non-empty set
/// fails stop.
#[must_use = "unmapped lease pins are released only after their removal is acknowledged"]
#[derive(Debug)]
pub(crate) struct UnmappedLeasePins {
    pins: [Option<InternalRef>; MAX_MAPPING_BATCH],
    count: usize,
}

impl UnmappedLeasePins {
    pub(crate) fn empty() -> Self {
        Self {
            pins: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn push(&mut self, pin: InternalRef) {
        assert!(
            self.count < MAX_MAPPING_BATCH,
            "unmapped lease pin batch overflow"
        );
        self.pins[self.count] = Some(pin);
        self.count += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.count
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Moves every pin of `other` into this set.
    pub(crate) fn absorb(&mut self, other: &mut Self) {
        for pin in other.take_all() {
            self.push(pin);
        }
    }

    fn take_all(&mut self) -> impl Iterator<Item = InternalRef> + '_ {
        self.count = 0;
        self.pins.iter_mut().filter_map(Option::take)
    }

    /// Releases every pin, handing each final release to `sink`. The caller
    /// guarantees no CPU can still hold a translation of the removed leases.
    pub(crate) fn release<const REGISTRY_OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        mut sink: impl FnMut(FinalRelease),
    ) {
        for pin in self.take_all() {
            match registry.release_internal(pin) {
                Ok(Some(final_release)) => sink(final_release),
                Ok(None) => {}
                Err(error) => {
                    panic!(
                        "unmapped lease pin release violated generic object invariants: {error:?}"
                    )
                }
            }
        }
    }
}

impl Drop for UnmappedLeasePins {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            extern crate std;
            // A failing host test unwinds through its pins; a second panic
            // would abort the whole test binary.
            if std::thread::panicking() {
                return;
            }
        }
        if self.count != 0 {
            // The pins are leaked with the panic: their objects stay alive,
            // which is the safe side of the failure.
            panic!("unmapped lease pins were dropped before their removal was acknowledged");
        }
    }
}

#[must_use = "mapping reference releases may contain final MemoryObject cleanup authority"]
#[derive(Debug)]
pub(crate) struct MappingFinalReleases {
    items: [Option<FinalRelease>; MAPPING_FINAL_RELEASE_CAPACITY],
    count: usize,
    unmapped: UnmappedLeasePins,
}

impl MappingFinalReleases {
    pub(crate) fn empty() -> Self {
        Self {
            items: core::array::from_fn(|_| None),
            count: 0,
            unmapped: UnmappedLeasePins::empty(),
        }
    }

    fn push_unmapped(&mut self, pin: InternalRef) {
        self.unmapped.push(pin);
    }

    /// Releases the unmapped lease pins now, into this batch. Only for a path
    /// where no other CPU can hold a translation of the removed range: the
    /// teardown of a quiesced Process no CPU is resident on, a rollback of
    /// mappings no CPU has entered, or a host model that publishes no
    /// shootdown. The batch keeps its `2 * BATCH + 1` bound: these pins were
    /// part of it before they were held.
    pub(crate) fn settle_locally<const REGISTRY_OBJECTS: usize>(
        mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    ) -> Self {
        let mut unmapped = core::mem::replace(&mut self.unmapped, UnmappedLeasePins::empty());
        unmapped.release(registry, |release| self.push(release));
        self
    }

    /// The final releases and the unmapped lease pins, apart.
    pub(crate) fn into_parts(
        self,
    ) -> (
        [Option<FinalRelease>; MAPPING_FINAL_RELEASE_CAPACITY],
        UnmappedLeasePins,
    ) {
        (self.items, self.unmapped)
    }

    fn push(&mut self, release: FinalRelease) {
        assert!(
            self.count < MAPPING_FINAL_RELEASE_CAPACITY,
            "mapping final-release batch overflow"
        );
        self.items[self.count] = Some(release);
        self.count += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.count
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0 && self.unmapped.is_empty()
    }

    /// The final releases. Fails stop if unmapped lease pins remain: those
    /// go through [`Self::into_parts`] or [`Self::settle_locally`] first.
    pub(crate) fn into_items(self) -> [Option<FinalRelease>; MAPPING_FINAL_RELEASE_CAPACITY] {
        let (items, unmapped) = self.into_parts();
        drop(unmapped);
        items
    }
}

#[derive(Debug)]
pub(super) struct PrepareReplaceError {
    error: MemoryObjectError,
    final_releases: MappingFinalReleases,
}

impl PrepareReplaceError {
    pub(super) const fn error(&self) -> MemoryObjectError {
        self.error
    }

    pub(super) fn into_final_releases(self) -> MappingFinalReleases {
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
    object_offset: u64,
    byte_len: u64,
    /// Device registers: mapped strong-uncacheable (PCD|PWT).
    uncached: bool,
}

impl MemoryObjectRange {
    pub(super) const EMPTY: Self = Self {
        backing: BackingIdentity::EMPTY,
        object_offset: 0,
        byte_len: 0,
        uncached: false,
    };

    #[cfg(test)]
    pub(super) const fn for_test(object_offset: u64, byte_len: u64) -> Self {
        Self {
            object_offset,
            byte_len,
            ..Self::EMPTY
        }
    }

    pub(crate) const fn backing_identity(self) -> BackingIdentity {
        self.backing
    }

    pub(crate) const fn uncached(self) -> bool {
        self.uncached
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
    logical_byte_len: u64,
    rounded_byte_len: u64,
    kind: MemoryObjectKind,
    protection_ceiling: MemoryProtection,
    /// On demand: the hull `[first, end)` of object pages whose
    /// translations transactions removed and no release has examined yet
    /// (DW2 §10.9 item 2). Gone with the record at finalization.
    released: Option<(u64, u64)>,
}

#[derive(Clone, Copy)]
struct ObjectSlot {
    record: Option<ObjectRecord>,
}

const EMPTY_OBJECT_SLOT: ObjectSlot = ObjectSlot { record: None };

/// On-demand MemoryObjects with a live payload record, across every
/// authority. While it is zero no user buffer can lie on an on-demand page,
/// so a syscall skips its fill-in phase without taking a lock (DW2 M6 §8.6).
pub(crate) static LIVE_ON_DEMAND_OBJECTS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

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

/// One replace transaction's plan. The caller owns it and lends it to
/// [`MemoryObjectAuthority::prepare_replace`] for the transaction's life, so
/// the plan is built in place and never copied between frames: at 64 slots it
/// is about 19.5 KB (DW2 plan §10.2 item 2).
pub(crate) struct ReplacePlan<const BATCH: usize> {
    released: [usize; BATCH],
    released_len: usize,
    pending: [Option<PendingLease>; BATCH],
    pending_len: usize,
    tickets: [Option<LeaseTicket>; BATCH],
    extra_sources: [Option<ExistingPinSource>; BATCH],
    extra_len: usize,
    /// Per on-demand object losing translations: its slot and the hull of
    /// the removed object pages, widened into its record at commit.
    removed: [Option<(usize, u64, u64)>; BATCH],
    removed_len: usize,
}

impl<const BATCH: usize> ReplacePlan<BATCH> {
    pub(crate) const fn new() -> Self {
        Self {
            released: [usize::MAX; BATCH],
            released_len: 0,
            pending: [None; BATCH],
            pending_len: 0,
            tickets: [None; BATCH],
            extra_sources: [None; BATCH],
            extra_len: 0,
            removed: [None; BATCH],
            removed_len: 0,
        }
    }
}

/// Index entries one release step may visit (DW2 §10.9 items 5, 8).
pub(crate) const RELEASE_STEP_ENTRIES: u64 = 4096;

/// What one release step did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseStep {
    /// Nothing to release, or the object may not release now.
    Idle,
    /// The hull is done.
    Done { freed: u64 },
    /// Hull remains: queue the object again.
    More { freed: u64 },
}

/// Live lease records of a lease table.
trait LeaseRecords<'a> {
    fn flatten_records(self) -> impl Iterator<Item = &'a LeaseRecord>;
}

impl<'a, I: Iterator<Item = &'a LeaseSlot>> LeaseRecords<'a> for I {
    fn flatten_records(self) -> impl Iterator<Item = &'a LeaseRecord> {
        self.filter_map(|lease| lease.record.as_ref())
    }
}

/// Object pages `[first_page, end_page)` of `object` whose (virtual address,
/// object offset) translations a transaction removes and none of its new
/// mappings reproduces (DW2 §10.9 item 1). The region computes them; it
/// alone knows each mapping's virtual address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemovedRange {
    pub(super) object: MemoryObjectKey,
    pub(super) first_page: u64,
    pub(super) end_page: u64,
}

impl RemovedRange {
    pub(crate) const EMPTY: Self = Self {
        object: MemoryObjectKey::EMPTY,
        first_page: 0,
        end_page: 0,
    };

    pub(crate) const fn new(object: MemoryObjectKey, first_page: u64, end_page: u64) -> Self {
        Self {
            object,
            first_page,
            end_page,
        }
    }
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
    /// DeviceMmio objects' DeviceResource references, by object slot.
    parents: [Option<InternalRef>; OBJECTS],
    leases: [LeaseSlot; LEASES],
    /// On-demand objects whose finalization is owed and done in steps
    /// (DW2 §10.12), each holding the slot it sits in until it completes,
    /// so the queue is bounded by the slots and a slot is not reused while
    /// its frames are held.
    owed: [Option<OwedFinalization>; OBJECTS],
    /// The owed slots, oldest first: a ring of `owed_len` from `owed_head`.
    owed_order: [usize; OBJECTS],
    owed_head: usize,
    owed_len: usize,
}

/// A finalization owed in steps, and how far its index has been freed.
struct OwedFinalization {
    finalization: MemoryObjectFinalization,
    cursor: u64,
}

impl<const OBJECTS: usize, const LEASES: usize> MemoryObjectAuthority<OBJECTS, LEASES> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_authority_domain(),
            objects: [EMPTY_OBJECT_SLOT; OBJECTS],
            backings: core::array::from_fn(|_| None),
            parents: core::array::from_fn(|_| None),
            leases: core::array::from_fn(|_| LeaseSlot {
                generation: 0,
                record: None,
            }),
            owed: core::array::from_fn(|_| None),
            owed_order: [0; OBJECTS],
            owed_head: 0,
            owed_len: 0,
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

    /// Binds one whole-BAR DeviceMmio object. `parent` is the DeviceResource
    /// lookup pin, kept until the object finalizes. The ceiling is read/write:
    /// device registers are never executable.
    pub(crate) fn bind_device_mmio(
        &mut self,
        creation: CreationRef,
        backing: ObjectBackingGrant,
        parent: InternalRef,
    ) -> Result<MemoryObjectBinding, (MemoryObjectBindError, InternalRef)> {
        if parent.object_type() != deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE {
            return Err((
                MemoryObjectBindError {
                    error: MemoryObjectError::ObjectReference,
                    creation,
                    backing,
                },
                parent,
            ));
        }
        let byte_len = backing.byte_len();
        let slot = match self.bind_backing(
            creation,
            backing,
            byte_len,
            MemoryObjectKind::DeviceMmio,
            MemoryProtection::READ_WRITE,
        ) {
            Ok(binding) => binding,
            Err(error) => return Err((error, parent)),
        };
        let index = self
            .objects
            .iter()
            .position(|object| {
                object
                    .record
                    .is_some_and(|record| Some(record.object) == slot.key.object)
            })
            .expect("a fresh DeviceMmio binding has a slot");
        self.parents[index] = Some(parent);
        Ok(slot)
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
        self.objects[slot] = ObjectSlot {
            record: Some(ObjectRecord {
                object,
                backing: backing.identity(),
                logical_byte_len,
                rounded_byte_len,
                kind,
                protection_ceiling,
                released: None,
            }),
        };
        self.backings[slot] = Some(backing);
        if kind == MemoryObjectKind::OnDemand {
            LIVE_ON_DEMAND_OBJECTS.fetch_add(1, core::sync::atomic::Ordering::Release);
        }
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
        // The role manager made the grant: its runs are page-aligned and in
        // range, and its length is whole pages.
        let backing_len = backing.byte_len();
        if backing_len == 0 || logical_byte_len == 0 {
            return Err(MemoryObjectError::Empty);
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
            ) | (MemoryObjectKind::DeviceMmio, ObjectBackingKind::DeviceMmio)
                | (MemoryObjectKind::OnDemand, ObjectBackingKind::OnDemand)
        ) {
            return Err(MemoryObjectError::BackingKind);
        }
        if matches!(kind, MemoryObjectKind::ImmutableBootModule) && protection_ceiling.writable() {
            return Err(MemoryObjectError::ProtectionCeiling);
        }
        // Device registers are never code, and their exact size is the BAR's.
        if matches!(kind, MemoryObjectKind::DeviceMmio)
            && (protection_ceiling.executable() || logical_byte_len != backing_len)
        {
            return Err(MemoryObjectError::ProtectionCeiling);
        }
        let slot = self
            .objects
            .iter()
            .zip(self.backings.iter())
            .zip(self.owed.iter())
            .position(|((slot, backing), owed)| {
                slot.record.is_none() && backing.is_none() && owed.is_none()
            })
            .ok_or(MemoryObjectError::Capacity)?;
        Ok((slot, rounded_byte_len))
    }

    /// Whether the live object `object` is on demand (DW2 M6).
    pub(crate) fn object_is_on_demand(&self, object: ObjectId) -> bool {
        self.object_record(MemoryObjectKey {
            object: Some(object),
        })
        .is_ok_and(|record| record.kind == MemoryObjectKind::OnDemand)
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

    /// Returns writable page backing for a kernel factory that still owns the
    /// corresponding HandleRef. This deliberately does not accept an ObjectId
    /// or synthesize a MemoryObjectKey, preserving the key as authority-issued.
    pub(crate) fn backing_for_population(
        &self,
        reference: &HandleRef,
    ) -> Result<&ObjectBackingGrant, MemoryObjectError> {
        if reference.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
            return Err(MemoryObjectError::ObjectReference);
        }
        let object_id = reference.id();
        let slot = self
            .objects
            .iter()
            .position(|slot| slot.record.is_some_and(|record| record.object == object_id))
            .ok_or(MemoryObjectError::InvalidObjectKey)?;
        let record = self.objects[slot]
            .record
            .ok_or(MemoryObjectError::InvalidObjectKey)?;
        if record.kind != MemoryObjectKind::PageBacked {
            return Err(MemoryObjectError::BackingKind);
        }
        if !record.protection_ceiling.writable() {
            return Err(MemoryObjectError::ProtectionCeiling);
        }
        self.backings[slot]
            .as_ref()
            .ok_or(MemoryObjectError::InvalidObjectKey)
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

    /// The backing `memory_object_commit` fills in over `[offset, offset +
    /// byte_len)`, after checking the range lies in the object: `None` for an
    /// object that is not on demand, whose pages all have frames (DW2 M6
    /// §8.2).
    pub(crate) fn commit_range(
        &self,
        resolved: &ResolvedHandle,
        offset: u64,
        byte_len: u64,
    ) -> Result<Option<BackingIdentity>, MemoryObjectError> {
        if resolved.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
            return Err(MemoryObjectError::ObjectReference);
        }
        let record = self.object_record(MemoryObjectKey {
            object: Some(resolved.object_id()),
        })?;
        let range = object_range(record, offset, byte_len)?;
        Ok((record.kind == MemoryObjectKind::OnDemand).then_some(range.backing))
    }

    /// The validated range `[offset, offset + byte_len)` of a page-backed
    /// object a DMA mapping may name (storage K4). The caller resolves its
    /// pages through the role manager; they may lie in several runs (DW2 M3). Device-MMIO and boot-module
    /// objects are refused with `BackingKind`; a device-writable mapping needs
    /// a writable object.
    pub(crate) fn dma_physical_range(
        &self,
        resolved: &ResolvedHandle,
        offset: u64,
        byte_len: u64,
        device_writes: bool,
    ) -> Result<MemoryObjectRange, MemoryObjectError> {
        if resolved.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
            return Err(MemoryObjectError::ObjectReference);
        }
        let record = self.object_record(MemoryObjectKey {
            object: Some(resolved.object_id()),
        })?;
        if !matches!(
            record.kind,
            MemoryObjectKind::PageBacked | MemoryObjectKind::OnDemand
        ) {
            return Err(MemoryObjectError::BackingKind);
        }
        if device_writes && !record.protection_ceiling.writable() {
            return Err(MemoryObjectError::ProtectionCeiling);
        }
        object_range(record, offset, byte_len)
    }

    /// Whether any finalization is owed (DW2 §10.12).
    pub(crate) fn finalization_owed(&self) -> bool {
        self.owed_len != 0
    }

    /// Queues an on-demand object's finalization to be done in steps (DW2
    /// §10.12 item 1), in a free slot (the one `take_finalization` just
    /// emptied, at least, is free); any other kind is returned to be
    /// completed at once.
    pub(crate) fn defer_finalization(
        &mut self,
        finalization: MemoryObjectFinalization,
    ) -> Option<MemoryObjectFinalization> {
        if finalization.kind != MemoryObjectKind::OnDemand
            || finalization.backing.kind() != ObjectBackingKind::OnDemand
        {
            return Some(finalization);
        }
        let slot = self
            .objects
            .iter()
            .zip(self.backings.iter())
            .zip(self.owed.iter())
            .position(|((slot, backing), owed)| {
                slot.record.is_none() && backing.is_none() && owed.is_none()
            })
            .expect("the slot a finalization was taken from is free");
        self.owed[slot] = Some(OwedFinalization {
            finalization,
            cursor: 0,
        });
        assert!(self.owed_len < OBJECTS, "one owed entry per slot");
        self.owed_order[(self.owed_head + self.owed_len) % OBJECTS] = slot;
        self.owed_len += 1;
        None
    }

    /// One step of the owed finalizations (DW2 §10.12 item 2), oldest
    /// first: at most `budget` index entries are visited, the budget left
    /// by an object that completes going on to the next (step-6 review R3),
    /// less the root's entries its completion reads.
    /// Each step lowers the object's weight by the frames it freed; an
    /// object whose index is empty is completed. `true` if any remain.
    #[cfg(deepwyrm_integrated)]
    pub(crate) fn finalize_owed_step<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        budget: u64,
    ) -> bool {
        self.finalize_owed_step_observed(registry, roles, budget, |_, _, _| {})
    }

    /// The owed slots, oldest first (DW2 §10.19 revision 2: the step report
    /// keys its record of each queued object by its slot).
    pub(crate) fn owed_slots(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.owed_len).map(|index| self.owed_order[(self.owed_head + index) % OBJECTS])
    }

    /// [`Self::finalize_owed_step`], telling `observe` of each object it
    /// worked on: its slot, the frames this step freed of it, and whether
    /// it completed. Only reported; the step is the same.
    #[cfg(deepwyrm_integrated)]
    pub(crate) fn finalize_owed_step_observed<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        budget: u64,
        mut observe: impl FnMut(usize, u64, bool),
    ) -> bool {
        let mut left = budget;
        while left != 0 && self.owed_len != 0 {
            let slot = self.owed_order[self.owed_head];
            let owed = self.owed[slot]
                .as_mut()
                .expect("a queued owed slot holds its finalization");
            let backing = owed.finalization.backing.identity();
            let pages = owed.finalization.backing.byte_len() / PAGE_SIZE;
            let (cursor, freed, visited) = roles
                .release_index_step(backing, owed.cursor, left)
                .unwrap_or_else(|error| panic!("an owed index did not free: {error:?}"));
            owed.cursor = cursor;
            if freed != 0 {
                registry
                    .lower_finalizing_charge_pages(owed.finalization.final_release.id(), freed)
                    .unwrap_or_else(|error| {
                        panic!("an owed object's weight did not fall: {error:?}")
                    });
            }
            left = left.saturating_sub(visited.max(1));
            observe(slot, freed, cursor >= pages);
            if cursor < pages {
                break;
            }
            let owed = self.owed[slot]
                .take()
                .expect("a queued owed slot holds its finalization");
            self.owed_head = (self.owed_head + 1) % OBJECTS;
            self.owed_len -= 1;
            let parent = complete_memory_finalization(registry, roles, owed.finalization);
            assert!(parent.is_none(), "an on-demand object has no parent");
            // Completion re-reads the root's entries to check the index
            // empty before freeing it: charged in full (second security
            // pass D-2).
            left = left.saturating_sub(crate::memory::frame_roles::INDEX_FANOUT);
        }
        self.owed_len != 0
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
        if record.kind == MemoryObjectKind::OnDemand {
            LIVE_ON_DEMAND_OBJECTS.fetch_sub(1, core::sync::atomic::Ordering::Release);
        }
        Ok(MemoryObjectFinalization {
            final_release,
            backing,
            kind: record.kind,
            parent: self.parents[slot].take(),
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

    /// One step of releasing an on-demand object's unmapped pages (DW2
    /// §10.9 item 5). Runs under T and P where the cleanup queue drains,
    /// after its pops. The object must be `Live` in the registry, have no
    /// handle and no internal reference beyond its live leases' pins: then
    /// no removal of its translations is unacknowledged and nothing but a
    /// live lease can reach its pages. Frees up to [`RELEASE_STEP_ENTRIES`]
    /// index entries' worth of committed pages in its hull that no live
    /// lease covers, lowering its charge by the pages freed.
    pub(crate) fn release_unmapped_step<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        object: ObjectId,
    ) -> ReleaseStep {
        self.release_unmapped_step_within(registry, roles, object, RELEASE_STEP_ENTRIES)
    }

    /// [`Self::release_unmapped_step`] with an entry budget of `budget`.
    pub(crate) fn release_unmapped_step_within<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        object: ObjectId,
        budget: u64,
    ) -> ReleaseStep {
        let Some(slot) = self
            .objects
            .iter()
            .position(|slot| slot.record.is_some_and(|record| record.object == object))
        else {
            return ReleaseStep::Idle;
        };
        let record = self.objects[slot]
            .record
            .expect("found object slot has a record");
        let (MemoryObjectKind::OnDemand, Some((first, end))) = (record.kind, record.released)
        else {
            return ReleaseStep::Idle;
        };
        let Some((handles, internal)) = registry.live_reference_counts(object) else {
            return ReleaseStep::Idle;
        };
        let leases = self
            .leases
            .iter()
            .flatten_records()
            .filter(|lease| lease.metadata.object_slot == slot)
            .count();
        if handles != 0 || usize::try_from(internal).ok() != Some(leases) {
            return ReleaseStep::Idle;
        }
        let mut cursor = first;
        let mut visited = 0_u64;
        let mut freed = 0_u64;
        while cursor < end && visited < budget {
            let Some((low, high)) = self.next_uncovered(slot, cursor, end) else {
                cursor = end;
                break;
            };
            let (next, pages, entries) = roles
                .decommit_on_demand_range(record.backing, low, high, budget - visited)
                .unwrap_or_else(|error| {
                    panic!("a live on-demand object's index failed to release: {error:?}")
                });
            freed += pages;
            visited += entries;
            cursor = next;
            if entries == 0 {
                break;
            }
        }
        if freed != 0 {
            let (_, weight) = registry
                .charge(object)
                .unwrap_or_else(|error| panic!("a live object lost its charge: {error:?}"));
            let weight = weight
                .checked_sub(freed)
                .expect("an object's weight counts every page it committed");
            registry
                .set_charge_pages(object, weight)
                .unwrap_or_else(|error| panic!("a live object rejected its weight: {error:?}"));
        }
        let record = self.objects[slot]
            .record
            .as_mut()
            .expect("found object slot has a record");
        if cursor >= end {
            record.released = None;
            ReleaseStep::Done { freed }
        } else {
            record.released = Some((cursor, end));
            ReleaseStep::More { freed }
        }
    }

    /// The first run `[low, high)` of object pages at or after `from` and
    /// before `end` that no live lease of the object at `slot` covers.
    fn next_uncovered(&self, slot: usize, from: u64, end: u64) -> Option<(u64, u64)> {
        let covers = || {
            self.leases
                .iter()
                .flatten_records()
                .filter(move |lease| lease.metadata.object_slot == slot)
                .map(|lease| {
                    let first = lease.metadata.range.object_offset / PAGE_SIZE;
                    (first, first + lease.metadata.range.byte_len / PAGE_SIZE)
                })
        };
        let mut low = from;
        while let Some((_, cover_end)) =
            covers().find(|&(cover_first, cover_end)| cover_first <= low && low < cover_end)
        {
            low = cover_end;
        }
        if low >= end {
            return None;
        }
        let high = covers()
            .map(|(cover_first, _)| cover_first)
            .filter(|&cover_first| cover_first > low)
            .fold(end, u64::min);
        Some((low, high))
    }

    #[cfg(test)]
    pub(crate) fn released_hull(&self, object: ObjectId) -> Option<(u64, u64)> {
        self.objects
            .iter()
            .find_map(|slot| slot.record.filter(|record| record.object == object))
            .and_then(|record| record.released)
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
    final_releases: &mut MappingFinalReleases,
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
    final_releases: &mut MappingFinalReleases,
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
    plan: &'a mut ReplacePlan<BATCH>,
    extra_pins: [Option<InternalRef>; BATCH],
    /// One per on-demand object losing translations with no removed lease
    /// pin held for it, held to settlement (DW2 §10.9 item 3, review B-1).
    coverage_pins: [Option<InternalRef>; BATCH],
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
    Ok(MemoryObjectRange {
        backing: object.backing,
        object_offset,
        byte_len,
        uncached: matches!(object.kind, MemoryObjectKind::DeviceMmio),
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
