//! Atomic `AddressRegion` model and address-space publication boundary.
//!
//! The region never changes its model or authority leases until an injected
//! publisher atomically accepts the same full replacement for page tables.

#![allow(
    dead_code,
    reason = "DW0-C/D4 expose the atomic region model ahead of later process/syscall production consumers"
)]

use super::object::{
    CapturedMappingAuthority, LeaseRequest, MapAuthorization, MapAuthorizationCreateError,
    MappingFinalReleases, MappingLease, MemoryObjectAuthority, MemoryObjectError, MemoryObjectKey,
    MemoryObjectRange, MemoryProtection, PAGE_SIZE,
};
use crate::handle::ResolvedHandle;
use crate::object::ObjectRegistry;
use core::sync::atomic::{AtomicU64, Ordering};

#[path = "address_region/authority.rs"]
mod authority;
#[path = "address_region/region.rs"]
mod region;

const USER_CANONICAL_END: u64 = 0x0000_8000_0000_0000;
const EMPTY_LEASE: MappingLease = MappingLease::EMPTY;

pub(crate) type Protection = MemoryProtection;

/// Opaque authority-issued identity for one page-table root/address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AddressSpaceKey {
    domain: u64,
    raw: u64,
}

impl AddressSpaceKey {
    pub(super) const EMPTY: Self = Self { domain: 0, raw: 0 };
    pub(crate) const fn same_domain(self, region: RegionKey) -> bool {
        self.domain != 0 && self.domain == region.domain
    }
}

/// Opaque authority-issued identity for a region within one address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegionKey {
    domain: u64,
    raw: u64,
}

impl RegionKey {
    pub(super) const EMPTY: Self = Self { domain: 0, raw: 0 };
}

static NEXT_AUTHORITY_DOMAIN: AtomicU64 = AtomicU64::new(1);

pub(super) fn mint_authority_domain() -> u64 {
    NEXT_AUTHORITY_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |domain| {
            domain.checked_add(1).filter(|next| *next != 0)
        })
        .expect("authority-domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressRegionError {
    Empty,
    Unaligned,
    Overflow,
    OutsideRegion,
    PageZero,
    Overlap,
    Unmapped,
    NoSpace,
    Capacity,
    LiveMappings,
    LiveRegions,
    PublisherIdentity,
    InvalidProtection,
    UnsupportedProtection,
    Object(MemoryObjectError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressSpaceTransactionError<E> {
    Model(AddressRegionError),
    Publish(E),
}

#[derive(Debug)]
pub(crate) struct AddressSpaceTransactionFailure<E, const FINALIZERS: usize> {
    error: AddressSpaceTransactionError<E>,
    final_releases: MappingFinalReleases<FINALIZERS>,
}

impl<E, const FINALIZERS: usize> AddressSpaceTransactionFailure<E, FINALIZERS> {
    pub(crate) const fn error(&self) -> &AddressSpaceTransactionError<E> {
        &self.error
    }

    pub(crate) fn into_final_releases(self) -> MappingFinalReleases<FINALIZERS> {
        self.final_releases
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AddressSpaceTransactionError<E>,
        MappingFinalReleases<FINALIZERS>,
    ) {
        (self.error, self.final_releases)
    }
}

#[derive(Clone, Copy)]
struct AddressSpaceSlot {
    generation: u32,
    active: bool,
}

const EMPTY_ADDRESS_SPACE_SLOT: AddressSpaceSlot = AddressSpaceSlot {
    generation: 0,
    active: false,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegionRecord {
    address_space_slot: usize,
    start: u64,
    byte_len: u64,
}

#[derive(Clone, Copy)]
struct RegionSlot {
    generation: u32,
    record: Option<RegionRecord>,
}

const EMPTY_REGION_SLOT: RegionSlot = RegionSlot {
    generation: 0,
    record: None,
};

/// Owns address-space and sibling-region identity. A key represents the
/// architecture root selected for an address space; consumers cannot build or
/// retarget one from raw integers.
pub(crate) struct AddressSpaceAuthority<const SPACES: usize, const REGIONS: usize> {
    domain: u64,
    spaces: [AddressSpaceSlot; SPACES],
    regions: [RegionSlot; REGIONS],
}

/// One committed virtual mapping. The lease is opaque and proves that this
/// mapping participated in the authority's object-wide W/X accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mapping {
    address_space: AddressSpaceKey,
    region: RegionKey,
    virtual_start: u64,
    byte_len: u64,
    object: MemoryObjectKey,
    backing: MemoryObjectRange,
    protection: Protection,
    mapping_authority: CapturedMappingAuthority,
    lease: MappingLease,
}

impl Mapping {
    pub(crate) const fn address_space(&self) -> AddressSpaceKey {
        self.address_space
    }

    pub(crate) const fn region(&self) -> RegionKey {
        self.region
    }

    #[allow(
        dead_code,
        reason = "the architecture publisher consumes virtual starts when it materializes page-table entries"
    )]
    pub(crate) const fn virtual_start(&self) -> u64 {
        self.virtual_start
    }

    pub(crate) const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    #[allow(
        dead_code,
        reason = "the architecture publisher consumes allocator-owned backing metadata when it materializes page-table entries"
    )]
    pub(crate) const fn backing(&self) -> MemoryObjectRange {
        self.backing
    }

    pub(crate) const fn protection(&self) -> Protection {
        self.protection
    }

    #[allow(
        dead_code,
        reason = "the architecture publisher uses the opaque lease for publication and invalidation provenance"
    )]
    pub(super) const fn lease(&self) -> MappingLease {
        self.lease
    }

    const fn end(self) -> u64 {
        self.virtual_start + self.byte_len
    }

    const fn spec(self) -> MappingSpec {
        MappingSpec {
            address_space: self.address_space,
            region: self.region,
            virtual_start: self.virtual_start,
            byte_len: self.byte_len,
            object: self.object,
            object_offset: self.backing.object_offset(),
            protection: self.protection,
            mapping_authority: self.mapping_authority,
        }
    }
}

#[derive(Clone, Copy)]
struct MappingSpec {
    address_space: AddressSpaceKey,
    region: RegionKey,
    virtual_start: u64,
    byte_len: u64,
    object: MemoryObjectKey,
    object_offset: u64,
    protection: Protection,
    mapping_authority: CapturedMappingAuthority,
}

impl MappingSpec {
    const fn end(self) -> u64 {
        self.virtual_start + self.byte_len
    }

    fn slice(
        self,
        start: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<Self, AddressRegionError> {
        let virtual_offset = start
            .checked_sub(self.virtual_start)
            .ok_or(AddressRegionError::Overflow)?;
        let object_offset = self
            .object_offset
            .checked_add(virtual_offset)
            .ok_or(AddressRegionError::Overflow)?;
        Ok(Self {
            address_space: self.address_space,
            region: self.region,
            virtual_start: start,
            byte_len,
            object: self.object,
            object_offset,
            protection,
            mapping_authority: self.mapping_authority,
        })
    }
}

fn next_generation(generation: u32) -> Result<u32, AddressRegionError> {
    generation
        .checked_add(1)
        .filter(|next| *next != 0)
        .ok_or(AddressRegionError::Capacity)
}

fn encode_key(slot: usize, generation: u32) -> u64 {
    (u64::from(generation) << 32) | u64::try_from(slot + 1).expect("slot fits u64")
}

fn decode_key(raw: u64) -> Option<(usize, u32)> {
    let generation = (raw >> 32) as u32;
    let slot = usize::try_from((raw & u64::from(u32::MAX)).checked_sub(1)?).ok()?;
    (generation != 0).then_some((slot, generation))
}

const EMPTY_MAPPING: Mapping = Mapping {
    address_space: AddressSpaceKey::EMPTY,
    region: RegionKey::EMPTY,
    virtual_start: 0,
    byte_len: 0,
    object: MemoryObjectKey::EMPTY,
    backing: MemoryObjectRange::EMPTY,
    protection: Protection::READ,
    mapping_authority: CapturedMappingAuthority::EMPTY,
    lease: EMPTY_LEASE,
};

pub(crate) mod publisher_seal {
    pub trait Sealed {}
}

/// The sole page-table seam used by this model.
///
/// Implementations must serialize the address-space root and either publish
/// exactly `after` in place of `before` (including all PTE invalidations) or
/// leave every PTE unchanged. A returned error is a pre-commit failure.
///
/// # Safety
///
/// The implementation must own the exact architecture root denoted by
/// `address_space`, reject every other root/region pair, and make the full
/// replacement atomic with respect to its page tables and invalidations.
#[allow(
    unsafe_code,
    reason = "page-table-root identity is an architecture invariant Rust cannot prove"
)]
pub(crate) unsafe trait AddressSpacePublisher: publisher_seal::Sealed {
    type Error;

    /// Returns the exact root identity this publisher controls.
    fn address_space_key(&self) -> AddressSpaceKey;

    /// Atomically publishes this region's mappings only when both supplied
    /// identities match the root and region the publisher owns.
    fn publish_replace(
        &mut self,
        address_space: AddressSpaceKey,
        region: RegionKey,
        before: &[Mapping],
        after: &[Mapping],
    ) -> Result<(), Self::Error>;
}

/// Fixed-capacity model for one lower-canonical user address region.
pub(crate) struct AddressRegion<const SLOTS: usize> {
    address_space: AddressSpaceKey,
    region: RegionKey,
    start: u64,
    byte_len: u64,
    mappings: [Option<Mapping>; SLOTS],
}

fn push_spec<const SLOTS: usize>(
    staged: &mut [Option<MappingSpec>; SLOTS],
    length: &mut usize,
    mapping: MappingSpec,
) -> Result<(), AddressRegionError> {
    if *length == SLOTS {
        return Err(AddressRegionError::Capacity);
    }
    staged[*length] = Some(mapping);
    *length += 1;
    Ok(())
}

const fn intersects_specs(left: MappingSpec, right: MappingSpec) -> bool {
    left.virtual_start < right.end() && right.virtual_start < left.end()
}

fn model_failure<E, const FINALIZERS: usize>(
    error: AddressRegionError,
) -> AddressSpaceTransactionFailure<E, FINALIZERS> {
    AddressSpaceTransactionFailure {
        error: AddressSpaceTransactionError::Model(error),
        final_releases: MappingFinalReleases::empty(),
    }
}

fn authorization_failure<E, const REGISTRY_OBJECTS: usize>(
    registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    authorization: MapAuthorization,
    error: AddressRegionError,
) -> AddressSpaceTransactionFailure<E, REGISTRY_OBJECTS> {
    AddressSpaceTransactionFailure {
        error: AddressSpaceTransactionError::Model(error),
        final_releases: authorization.release(registry),
    }
}

const fn protection_error(error: MemoryObjectError) -> AddressRegionError {
    match error {
        MemoryObjectError::UnsupportedProtection => AddressRegionError::UnsupportedProtection,
        _ => AddressRegionError::InvalidProtection,
    }
}

#[cfg(deepwyrm_integrated)]
#[path = "address_region/object_adapter.rs"]
mod object_adapter;
#[cfg(deepwyrm_integrated)]
#[allow(
    unused_imports,
    reason = "DW0-E2 exports the typed AddressRegion adapter ahead of E5 syscall consumers"
)]
pub(crate) use object_adapter::{
    AddressRegionObjectAuthority, AddressRegionObjectError, AddressRegionObjectKey,
    AddressRegionPayloadBinding, AddressRegionPayloadCleanup, complete_address_region_finalization,
};

#[cfg(test)]
#[allow(
    clippy::err_expect,
    reason = "prepared mapping transactions intentionally omit Debug; negative tests must consume errors without widening that authority surface"
)]
#[path = "address_region/tests.rs"]
mod tests;
