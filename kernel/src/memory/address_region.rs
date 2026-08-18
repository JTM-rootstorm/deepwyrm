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

#[derive(Clone, Copy)]
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

impl<const SPACES: usize, const REGIONS: usize> AddressSpaceAuthority<SPACES, REGIONS> {
    /// Creates a root/region registry with a process-lifetime-unique domain.
    ///
    /// # Safety
    ///
    /// The caller must install this as the sole registry for every
    /// architecture page-table root registered through it, must never
    /// register the same root through another authority, and must retain this
    /// authority for at least as long as every region and publisher identity
    /// it issues. Target integration confines this boundary to the global
    /// address-space owner.
    #[allow(
        unsafe_code,
        reason = "physical page-table-root uniqueness and registry lifetime are architecture facts"
    )]
    pub(crate) unsafe fn new() -> Self {
        Self {
            domain: mint_authority_domain(),
            spaces: [EMPTY_ADDRESS_SPACE_SLOT; SPACES],
            regions: [EMPTY_REGION_SLOT; REGIONS],
        }
    }

    /// Registers one architecture-owned page-table root identity.
    pub(crate) fn create_address_space(&mut self) -> Result<AddressSpaceKey, AddressRegionError> {
        let slot = self
            .spaces
            .iter()
            .position(|space| !space.active)
            .ok_or(AddressRegionError::Capacity)?;
        let generation = next_generation(self.spaces[slot].generation)?;
        self.spaces[slot] = AddressSpaceSlot {
            generation,
            active: true,
        };
        Ok(AddressSpaceKey {
            domain: self.domain,
            raw: encode_key(slot, generation),
        })
    }

    /// Creates one nonoverlapping sibling region in `address_space`.
    pub(crate) fn create_region<const SLOTS: usize>(
        &mut self,
        address_space: AddressSpaceKey,
        start: u64,
        byte_len: u64,
    ) -> Result<AddressRegion<SLOTS>, AddressRegionError> {
        let address_space_slot = self.address_space_slot(address_space)?;
        AddressRegion::<SLOTS>::validate_region_interval(start, byte_len)?;
        let end = start
            .checked_add(byte_len)
            .ok_or(AddressRegionError::Overflow)?;
        if self
            .regions
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| {
                record.address_space_slot == address_space_slot
                    && start < record.start + record.byte_len
                    && record.start < end
            })
        {
            return Err(AddressRegionError::Overlap);
        }
        let slot = self
            .regions
            .iter()
            .position(|region| region.record.is_none())
            .ok_or(AddressRegionError::Capacity)?;
        let generation = next_generation(self.regions[slot].generation)?;
        self.regions[slot] = RegionSlot {
            generation,
            record: Some(RegionRecord {
                address_space_slot,
                start,
                byte_len,
            }),
        };
        Ok(AddressRegion::new(
            address_space,
            RegionKey {
                domain: self.domain,
                raw: encode_key(slot, generation),
            },
            start,
            byte_len,
        ))
    }

    fn address_space_slot(&self, key: AddressSpaceKey) -> Result<usize, AddressRegionError> {
        if key.domain == 0 || key.domain != self.domain {
            return Err(AddressRegionError::OutsideRegion);
        }
        let (slot, generation) = decode_key(key.raw).ok_or(AddressRegionError::OutsideRegion)?;
        let entry = self
            .spaces
            .get(slot)
            .ok_or(AddressRegionError::OutsideRegion)?;
        if !entry.active || entry.generation != generation {
            return Err(AddressRegionError::OutsideRegion);
        }
        Ok(slot)
    }
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

impl<const SLOTS: usize> AddressRegion<SLOTS> {
    pub(crate) const fn address_space_key(&self) -> AddressSpaceKey {
        self.address_space
    }

    pub(crate) const fn region_key(&self) -> RegionKey {
        self.region
    }
    const fn new(
        address_space: AddressSpaceKey,
        region: RegionKey,
        start: u64,
        byte_len: u64,
    ) -> Self {
        Self {
            address_space,
            region,
            start,
            byte_len,
            mappings: [None; SLOTS],
        }
    }

    const fn validate_region_interval(start: u64, byte_len: u64) -> Result<(), AddressRegionError> {
        if byte_len == 0 {
            return Err(AddressRegionError::Empty);
        }
        if start == 0 {
            return Err(AddressRegionError::PageZero);
        }
        if !start.is_multiple_of(PAGE_SIZE) || !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(AddressRegionError::Unaligned);
        }
        let end = match start.checked_add(byte_len) {
            Some(end) => end,
            None => return Err(AddressRegionError::Overflow),
        };
        if start >= USER_CANONICAL_END || end > USER_CANONICAL_END {
            return Err(AddressRegionError::OutsideRegion);
        }
        Ok(())
    }

    pub(crate) const fn mappings(&self) -> &[Option<Mapping>; SLOTS] {
        &self.mappings
    }

    /// Consumes one D3-resolved handle into a one-shot authorization bound to
    /// this exact region. The lookup pin becomes the mapping pre-publication
    /// lifetime owner; validation failure returns the resolved handle intact.
    pub(crate) fn authorize_map<const OBJECTS: usize, const LEASES: usize>(
        &self,
        authority: &MemoryObjectAuthority<OBJECTS, LEASES>,
        resolved: ResolvedHandle,
        ceiling: Protection,
    ) -> Result<MapAuthorization, MapAuthorizationCreateError> {
        authority.issue_map_authorization(resolved, self.address_space, self.region, ceiling)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the mapping contract keeps virtual address, backing range, effective protection, and captured source ceiling explicit at the authority boundary"
    )]
    pub(crate) fn map<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        virtual_start: u64,
        authorization: MapAuthorization,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let mapping_authority = match authorization.capture(self.address_space, self.region) {
            Ok(authority) => authority,
            Err(error) => {
                return Err(authorization_failure(
                    registry,
                    authorization,
                    AddressRegionError::Object(error),
                ));
            }
        };
        if let Err(error) = self.validate_interval(virtual_start, byte_len) {
            return Err(authorization_failure(registry, authorization, error));
        }
        if let Err(error) = MemoryProtection::mapping(protection.bits()) {
            return Err(authorization_failure(
                registry,
                authorization,
                protection_error(error),
            ));
        }
        let mut staged = self.current_specs();
        let length = self.mapping_count();
        if length == SLOTS {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Capacity,
            ));
        }
        let candidate = MappingSpec {
            address_space: self.address_space,
            region: self.region,
            virtual_start,
            byte_len,
            object: mapping_authority.object(),
            object_offset,
            protection,
            mapping_authority,
        };
        if staged[..length]
            .iter()
            .flatten()
            .any(|current| intersects_specs(*current, candidate))
        {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Overlap,
            ));
        }
        staged[length] = Some(candidate);
        self.commit_specs(
            authority,
            registry,
            publisher,
            &staged,
            length + 1,
            Some(authorization),
        )
    }

    /// Maps at the lowest available page-aligned address in this region.
    ///
    /// This is the `flags = 0` allocator-chosen placement path. It advances
    /// only past existing mappings, so it considers no more than `SLOTS`
    /// occupied intervals and never searches page-by-page.
    #[allow(
        clippy::too_many_arguments,
        reason = "the allocator-chosen variant intentionally mirrors the explicit fixed-map authority contract"
    )]
    pub(crate) fn map_anywhere<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        authorization: MapAuthorization,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<
        (u64, MappingFinalReleases<REGISTRY_OBJECTS>),
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        if byte_len == 0 {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Empty,
            ));
        }
        if !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Unaligned,
            ));
        }
        if let Err(error) = MemoryProtection::mapping(protection.bits()) {
            return Err(authorization_failure(
                registry,
                authorization,
                protection_error(error),
            ));
        }
        let region_end = match self.start.checked_add(self.byte_len) {
            Some(end) => end,
            None => {
                return Err(authorization_failure(
                    registry,
                    authorization,
                    AddressRegionError::Overflow,
                ));
            }
        };
        let mut candidate = self.start;
        for _ in 0..SLOTS {
            let candidate_end = match candidate.checked_add(byte_len) {
                Some(end) => end,
                None => {
                    return Err(authorization_failure(
                        registry,
                        authorization,
                        AddressRegionError::NoSpace,
                    ));
                }
            };
            if candidate_end > region_end {
                return Err(authorization_failure(
                    registry,
                    authorization,
                    AddressRegionError::NoSpace,
                ));
            }

            let mut next_candidate = candidate;
            for mapping in self.mappings.iter().flatten().copied() {
                if candidate < mapping.end() && mapping.virtual_start < candidate_end {
                    next_candidate = next_candidate.max(mapping.end());
                }
            }
            if next_candidate == candidate {
                let final_releases = self.map(
                    authority,
                    registry,
                    publisher,
                    candidate,
                    authorization,
                    object_offset,
                    byte_len,
                    protection,
                )?;
                return Ok((candidate, final_releases));
            }
            candidate = next_candidate;
        }
        Err(authorization_failure(
            registry,
            authorization,
            AddressRegionError::NoSpace,
        ))
    }

    pub(crate) fn unmap<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        start: u64,
        byte_len: u64,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let end = self
            .checked_interval_end(start, byte_len)
            .map_err(model_failure)?;
        self.require_covered(start, end).map_err(model_failure)?;
        self.rebuild(authority, registry, publisher, start, end, None)
    }

    pub(crate) fn protect<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        start: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        MemoryProtection::mapping(protection.bits())
            .map_err(|error| model_failure(protection_error(error)))?;
        let end = self
            .checked_interval_end(start, byte_len)
            .map_err(model_failure)?;
        self.require_covered(start, end).map_err(model_failure)?;
        self.rebuild(authority, registry, publisher, start, end, Some(protection))
    }

    fn rebuild<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        start: u64,
        end: u64,
        replacement_protection: Option<Protection>,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let mut staged = [None; SLOTS];
        let mut staged_len = 0;
        for mapping in self.mappings.iter().flatten().copied() {
            let spec = mapping.spec();
            if spec.end() <= start || spec.virtual_start >= end {
                push_spec(&mut staged, &mut staged_len, spec).map_err(model_failure)?;
                continue;
            }
            if spec.virtual_start < start {
                let slice = spec
                    .slice(
                        spec.virtual_start,
                        start - spec.virtual_start,
                        spec.protection,
                    )
                    .map_err(model_failure)?;
                push_spec(&mut staged, &mut staged_len, slice).map_err(model_failure)?;
            }
            let overlap_start = spec.virtual_start.max(start);
            let overlap_end = spec.end().min(end);
            if let Some(protection) = replacement_protection {
                let slice = spec
                    .slice(overlap_start, overlap_end - overlap_start, protection)
                    .map_err(model_failure)?;
                push_spec(&mut staged, &mut staged_len, slice).map_err(model_failure)?;
            }
            if spec.end() > end {
                let slice = spec
                    .slice(end, spec.end() - end, spec.protection)
                    .map_err(model_failure)?;
                push_spec(&mut staged, &mut staged_len, slice).map_err(model_failure)?;
            }
        }
        self.commit_specs(authority, registry, publisher, &staged, staged_len, None)
    }

    fn commit_specs<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        specs: &[Option<MappingSpec>; SLOTS],
        spec_len: usize,
        authorization: Option<MapAuthorization>,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let old_len = self.mapping_count();
        let mut released = [EMPTY_LEASE; SLOTS];
        let mut old = [EMPTY_MAPPING; SLOTS];
        for (index, mapping) in self.mappings.iter().flatten().copied().enumerate() {
            released[index] = mapping.lease;
            old[index] = mapping;
        }
        let mut requests = [LeaseRequest::EMPTY; SLOTS];
        for (index, spec) in specs[..spec_len].iter().flatten().copied().enumerate() {
            requests[index] = LeaseRequest::new(
                spec.address_space,
                spec.region,
                spec.mapping_authority,
                spec.object_offset,
                spec.byte_len,
                spec.protection,
            );
        }
        let prepared = match authority.prepare_replace::<SLOTS, REGISTRY_OBJECTS>(
            registry,
            self.address_space,
            self.region,
            &released[..old_len],
            &requests[..spec_len],
            authorization,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                let model_error = error.error();
                return Err(AddressSpaceTransactionFailure {
                    error: AddressSpaceTransactionError::Model(AddressRegionError::Object(
                        model_error,
                    )),
                    final_releases: error.into_final_releases(),
                });
            }
        };
        let mut next_dense = [EMPTY_MAPPING; SLOTS];
        let mut next = [None; SLOTS];
        for (index, (spec, ticket)) in specs[..spec_len]
            .iter()
            .flatten()
            .copied()
            .zip(prepared.tickets().iter().flatten().copied())
            .enumerate()
        {
            let mapping = Mapping {
                address_space: spec.address_space,
                region: spec.region,
                virtual_start: spec.virtual_start,
                byte_len: spec.byte_len,
                object: ticket.object(),
                backing: ticket.range(),
                protection: ticket.protection(),
                mapping_authority: ticket.mapping_authority(),
                lease: ticket.lease(),
            };
            next_dense[index] = mapping;
            next[index] = Some(mapping);
        }
        if publisher.address_space_key() != self.address_space {
            let final_releases = prepared.rollback();
            return Err(AddressSpaceTransactionFailure {
                error: AddressSpaceTransactionError::Model(AddressRegionError::PublisherIdentity),
                final_releases,
            });
        }
        if let Err(error) = publisher.publish_replace(
            self.address_space,
            self.region,
            &old[..old_len],
            &next_dense[..spec_len],
        ) {
            let final_releases = prepared.rollback();
            return Err(AddressSpaceTransactionFailure {
                error: AddressSpaceTransactionError::Publish(error),
                final_releases,
            });
        }

        // Publication succeeded. From this point the reference transaction is
        // infallible except for fail-stop invariant corruption.
        self.mappings = next;
        Ok(prepared.commit())
    }

    fn mapping_count(&self) -> usize {
        self.mappings.iter().flatten().count()
    }

    fn current_specs(&self) -> [Option<MappingSpec>; SLOTS] {
        let mut specs = [None; SLOTS];
        for (index, mapping) in self.mappings.iter().flatten().copied().enumerate() {
            specs[index] = Some(mapping.spec());
        }
        specs
    }

    fn checked_interval_end(&self, start: u64, byte_len: u64) -> Result<u64, AddressRegionError> {
        self.validate_interval(start, byte_len)?;
        start
            .checked_add(byte_len)
            .ok_or(AddressRegionError::Overflow)
    }

    fn validate_interval(&self, start: u64, byte_len: u64) -> Result<(), AddressRegionError> {
        if byte_len == 0 {
            return Err(AddressRegionError::Empty);
        }
        if start == 0 {
            return Err(AddressRegionError::PageZero);
        }
        if !start.is_multiple_of(PAGE_SIZE) || !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(AddressRegionError::Unaligned);
        }
        let end = start
            .checked_add(byte_len)
            .ok_or(AddressRegionError::Overflow)?;
        let region_end = self
            .start
            .checked_add(self.byte_len)
            .ok_or(AddressRegionError::Overflow)?;
        if start < self.start || end > region_end || end > USER_CANONICAL_END {
            return Err(AddressRegionError::OutsideRegion);
        }
        Ok(())
    }

    fn require_covered(&self, start: u64, end: u64) -> Result<(), AddressRegionError> {
        let mut cursor = start;
        while cursor < end {
            let mapping = self
                .mappings
                .iter()
                .flatten()
                .find(|mapping| mapping.virtual_start <= cursor && cursor < mapping.end())
                .ok_or(AddressRegionError::Unmapped)?;
            cursor = mapping.end().min(end);
        }
        Ok(())
    }
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

#[cfg(test)]
#[allow(
    clippy::err_expect,
    reason = "prepared mapping transactions intentionally omit Debug; negative tests must consume errors without widening that authority surface"
)]
#[path = "address_region/tests.rs"]
mod tests;
