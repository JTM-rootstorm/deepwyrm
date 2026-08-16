//! Atomic `AddressRegion` model and address-space publication boundary.
//!
//! The region never changes its model or authority leases until an injected
//! publisher atomically accepts the same full replacement for page tables.

#![allow(
    dead_code,
    reason = "DW0-C exposes this model to the architecture publisher before page-table integration wires its production callers"
)]

use super::object::{
    CapturedMappingAuthority, LeaseRequest, MapAuthorization, MappingLease, MemoryObjectAuthority,
    MemoryObjectError, MemoryObjectKey, MemoryObjectRange, MemoryProtection, PAGE_SIZE,
};
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

    /// Issues a one-shot map authorization bound to this exact region.
    ///
    /// # Safety
    ///
    /// The caller must have validated MAP + READ for `object`, plus WRITE
    /// and/or EXECUTE exactly when present in `ceiling`, from a currently live
    /// rights-bearing handle. The authorization is consumed by one map
    /// attempt; only a successfully committed mapping retains its private
    /// captured ceiling after the source handle closes.
    #[allow(
        unsafe_code,
        reason = "this is the narrow future handle-rights validation seam for region-bound map authority"
    )]
    pub(crate) unsafe fn authorize_map<const OBJECTS: usize, const LEASES: usize>(
        &self,
        authority: &MemoryObjectAuthority<OBJECTS, LEASES>,
        object: MemoryObjectKey,
        ceiling: Protection,
    ) -> Result<MapAuthorization, MemoryObjectError> {
        // SAFETY: this function carries the same live-handle rights contract
        // while supplying the region identities callers cannot forge.
        unsafe {
            authority.issue_map_authorization(object, self.address_space, self.region, ceiling)
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the mapping contract keeps virtual address, backing range, effective protection, and captured source ceiling explicit at the authority boundary"
    )]
    pub(crate) fn map<const OBJECTS: usize, const LEASES: usize, P: AddressSpacePublisher>(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        publisher: &mut P,
        virtual_start: u64,
        authorization: MapAuthorization,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<(), AddressSpaceTransactionError<P::Error>> {
        let mapping_authority = authorization
            .capture(self.address_space, self.region)
            .map_err(|error| {
                AddressSpaceTransactionError::Model(AddressRegionError::Object(error))
            })?;
        self.validate_interval(virtual_start, byte_len)
            .map_err(AddressSpaceTransactionError::Model)?;
        MemoryProtection::mapping(protection.bits())
            .map_err(|error| AddressSpaceTransactionError::Model(protection_error(error)))?;
        let mut staged = self.current_specs();
        let length = self.mapping_count();
        if length == SLOTS {
            return Err(AddressSpaceTransactionError::Model(
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
            return Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Overlap,
            ));
        }
        staged[length] = Some(candidate);
        self.commit_specs(authority, publisher, &staged, length + 1)
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
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        publisher: &mut P,
        authorization: MapAuthorization,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<u64, AddressSpaceTransactionError<P::Error>> {
        if byte_len == 0 {
            return Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Empty,
            ));
        }
        if !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Unaligned,
            ));
        }
        MemoryProtection::mapping(protection.bits())
            .map_err(|error| AddressSpaceTransactionError::Model(protection_error(error)))?;

        let region_end =
            self.start
                .checked_add(self.byte_len)
                .ok_or(AddressSpaceTransactionError::Model(
                    AddressRegionError::Overflow,
                ))?;
        let mut candidate = self.start;
        for _ in 0..SLOTS {
            let candidate_end =
                candidate
                    .checked_add(byte_len)
                    .ok_or(AddressSpaceTransactionError::Model(
                        AddressRegionError::NoSpace,
                    ))?;
            if candidate_end > region_end {
                return Err(AddressSpaceTransactionError::Model(
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
                self.map(
                    authority,
                    publisher,
                    candidate,
                    authorization,
                    object_offset,
                    byte_len,
                    protection,
                )?;
                return Ok(candidate);
            }
            candidate = next_candidate;
        }
        Err(AddressSpaceTransactionError::Model(
            AddressRegionError::NoSpace,
        ))
    }

    pub(crate) fn unmap<const OBJECTS: usize, const LEASES: usize, P: AddressSpacePublisher>(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        publisher: &mut P,
        start: u64,
        byte_len: u64,
    ) -> Result<(), AddressSpaceTransactionError<P::Error>> {
        let end = self
            .checked_interval_end(start, byte_len)
            .map_err(AddressSpaceTransactionError::Model)?;
        self.require_covered(start, end)
            .map_err(AddressSpaceTransactionError::Model)?;
        self.rebuild(authority, publisher, start, end, None)
    }

    pub(crate) fn protect<const OBJECTS: usize, const LEASES: usize, P: AddressSpacePublisher>(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        publisher: &mut P,
        start: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<(), AddressSpaceTransactionError<P::Error>> {
        MemoryProtection::mapping(protection.bits())
            .map_err(|error| AddressSpaceTransactionError::Model(protection_error(error)))?;
        let end = self
            .checked_interval_end(start, byte_len)
            .map_err(AddressSpaceTransactionError::Model)?;
        self.require_covered(start, end)
            .map_err(AddressSpaceTransactionError::Model)?;
        self.rebuild(authority, publisher, start, end, Some(protection))
    }

    fn rebuild<const OBJECTS: usize, const LEASES: usize, P: AddressSpacePublisher>(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        publisher: &mut P,
        start: u64,
        end: u64,
        replacement_protection: Option<Protection>,
    ) -> Result<(), AddressSpaceTransactionError<P::Error>> {
        let mut staged = [None; SLOTS];
        let mut staged_len = 0;
        for mapping in self.mappings.iter().flatten().copied() {
            let spec = mapping.spec();
            if spec.end() <= start || spec.virtual_start >= end {
                push_spec(&mut staged, &mut staged_len, spec)
                    .map_err(AddressSpaceTransactionError::Model)?;
                continue;
            }
            if spec.virtual_start < start {
                push_spec(
                    &mut staged,
                    &mut staged_len,
                    spec.slice(
                        spec.virtual_start,
                        start - spec.virtual_start,
                        spec.protection,
                    )
                    .map_err(AddressSpaceTransactionError::Model)?,
                )
                .map_err(AddressSpaceTransactionError::Model)?;
            }
            let overlap_start = spec.virtual_start.max(start);
            let overlap_end = spec.end().min(end);
            if let Some(protection) = replacement_protection {
                push_spec(
                    &mut staged,
                    &mut staged_len,
                    spec.slice(overlap_start, overlap_end - overlap_start, protection)
                        .map_err(AddressSpaceTransactionError::Model)?,
                )
                .map_err(AddressSpaceTransactionError::Model)?;
            }
            if spec.end() > end {
                push_spec(
                    &mut staged,
                    &mut staged_len,
                    spec.slice(end, spec.end() - end, spec.protection)
                        .map_err(AddressSpaceTransactionError::Model)?,
                )
                .map_err(AddressSpaceTransactionError::Model)?;
            }
        }
        self.commit_specs(authority, publisher, &staged, staged_len)
    }

    fn commit_specs<const OBJECTS: usize, const LEASES: usize, P: AddressSpacePublisher>(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        publisher: &mut P,
        specs: &[Option<MappingSpec>; SLOTS],
        spec_len: usize,
    ) -> Result<(), AddressSpaceTransactionError<P::Error>> {
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

        let prepared = authority
            .prepare_replace::<SLOTS>(
                self.address_space,
                self.region,
                &released[..old_len],
                &requests[..spec_len],
            )
            .map_err(|error| {
                AddressSpaceTransactionError::Model(AddressRegionError::Object(error))
            })?;
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
            return Err(AddressSpaceTransactionError::Model(
                AddressRegionError::PublisherIdentity,
            ));
        }
        publisher
            .publish_replace(
                self.address_space,
                self.region,
                &old[..old_len],
                &next_dense[..spec_len],
            )
            .map_err(AddressSpaceTransactionError::Publish)?;

        // Both writes are infallible and happen while `self` and `authority`
        // are exclusively borrowed; a publisher error above has returned with
        // all three layers unchanged.
        self.mappings = next;
        prepared.commit();
        Ok(())
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

const fn protection_error(error: MemoryObjectError) -> AddressRegionError {
    match error {
        MemoryObjectError::UnsupportedProtection => AddressRegionError::UnsupportedProtection,
        _ => AddressRegionError::InvalidProtection,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::object::MemoryObjectKind;
    use super::*;
    use std::boxed::Box;

    struct FakePublisher {
        address_space: AddressSpaceKey,
        calls: usize,
        fail: bool,
        last_before: usize,
        last_after: usize,
    }

    impl FakePublisher {
        fn for_region<const SLOTS: usize>(region: &AddressRegion<SLOTS>) -> Self {
            Self {
                address_space: region.address_space,
                calls: 0,
                fail: false,
                last_before: 0,
                last_after: 0,
            }
        }
    }

    impl publisher_seal::Sealed for FakePublisher {}

    #[allow(
        unsafe_code,
        reason = "the synthetic publisher preserves the supplied root identity"
    )]
    unsafe impl AddressSpacePublisher for FakePublisher {
        type Error = ();

        fn address_space_key(&self) -> AddressSpaceKey {
            self.address_space
        }

        fn publish_replace(
            &mut self,
            address_space: AddressSpaceKey,
            _region: RegionKey,
            before: &[Mapping],
            after: &[Mapping],
        ) -> Result<(), Self::Error> {
            if address_space != self.address_space {
                return Err(());
            }
            self.calls += 1;
            self.last_before = before.len();
            self.last_after = after.len();
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    fn object<const OBJECTS: usize, const LEASES: usize>(
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        ceiling: Protection,
    ) -> MemoryObjectKey {
        object_at(authority, 0x20_000, ceiling)
    }

    fn object_at<const OBJECTS: usize, const LEASES: usize>(
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        physical_start: u64,
        ceiling: Protection,
    ) -> MemoryObjectKey {
        let backing = crate::memory::frame_roles::synthetic_allocator_backing(physical_start, 8);
        authority
            .grant_backing(
                backing,
                PAGE_SIZE * 8,
                MemoryObjectKind::PageBacked,
                ceiling,
            )
            .unwrap()
    }

    #[allow(
        unsafe_code,
        reason = "tests stand in for the future handle-rights validation seam"
    )]
    fn authorization<const OBJECTS: usize, const LEASES: usize, const SLOTS: usize>(
        authority: &MemoryObjectAuthority<OBJECTS, LEASES>,
        object: MemoryObjectKey,
        region: &AddressRegion<SLOTS>,
        ceiling: Protection,
    ) -> MapAuthorization {
        // SAFETY: each test explicitly selects the exercised MAP+READ/W/X authority.
        unsafe { region.authorize_map(authority, object, ceiling).unwrap() }
    }

    #[allow(
        unsafe_code,
        reason = "test-local registries uniquely own their synthetic address-space roots"
    )]
    fn space_authority<const SPACES: usize, const REGIONS: usize>()
    -> AddressSpaceAuthority<SPACES, REGIONS> {
        // SAFETY: each returned test registry is the only issuer for its
        // synthetic roots and remains live while its regions are created.
        unsafe { AddressSpaceAuthority::new() }
    }

    fn region<const SLOTS: usize>(start: u64, byte_len: u64) -> AddressRegion<SLOTS> {
        let spaces = Box::leak(Box::new(space_authority::<1, 1>()));
        let space = spaces.create_address_space().unwrap();
        spaces.create_region(space, start, byte_len).unwrap()
    }

    #[test]
    fn rejects_page_zero_and_upper_canonical_regions() {
        assert!(matches!(
            AddressRegion::<2>::validate_region_interval(0, PAGE_SIZE),
            Err(AddressRegionError::PageZero)
        ));
        assert!(matches!(
            AddressRegion::<2>::validate_region_interval(
                USER_CANONICAL_END - PAGE_SIZE,
                PAGE_SIZE * 2
            ),
            Err(AddressRegionError::OutsideRegion)
        ));
        assert_eq!(
            MemoryProtection::mapping(Protection::WRITE.bits()),
            Err(MemoryObjectError::UnsupportedProtection)
        );
        assert_eq!(
            MemoryProtection::mapping(Protection::EXECUTE.bits()),
            Err(MemoryObjectError::UnsupportedProtection)
        );
    }

    #[test]
    fn replacement_publishes_model_and_lease_together() {
        let mut authority = MemoryObjectAuthority::<2, 8>::new();
        let object = object(&mut authority, Protection::READ_WRITE_EXECUTE);
        let mut region = region::<4>(PAGE_SIZE, PAGE_SIZE * 8);
        let token = authorization(&authority, object, &region, Protection::READ_WRITE_EXECUTE);
        let mut publisher = FakePublisher::for_region(&region);
        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                token,
                0,
                PAGE_SIZE * 2,
                Protection::READ_WRITE,
            )
            .unwrap();
        assert_eq!(publisher.last_before, 0);
        assert_eq!(publisher.last_after, 1);
        assert_eq!(authority.active_lease_count(), 1);
        region
            .protect(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                PAGE_SIZE * 2,
                Protection::READ_EXECUTE,
            )
            .unwrap();
        assert_eq!(
            region.mappings()[0].unwrap().protection(),
            Protection::READ_EXECUTE
        );
        assert_eq!(authority.active_lease_count(), 1);
    }

    #[test]
    fn mapping_authority_is_captured_across_protect_and_split_replacements() {
        let mut authority = MemoryObjectAuthority::<2, 8>::new();
        let object = object(&mut authority, Protection::READ_WRITE_EXECUTE);
        let mut region = region::<4>(PAGE_SIZE, PAGE_SIZE * 8);
        let read = authorization(&authority, object, &region, Protection::READ);
        let mut publisher = FakePublisher::for_region(&region);

        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                read,
                0,
                PAGE_SIZE,
                Protection::READ,
            )
            .unwrap();
        assert!(matches!(
            region.protect(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                PAGE_SIZE,
                Protection::READ_WRITE,
            ),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Object(MemoryObjectError::ProtectionCeiling)
            ))
        ));
        region
            .unmap(&mut authority, &mut publisher, PAGE_SIZE, PAGE_SIZE)
            .unwrap();

        let read_write = authorization(&authority, object, &region, Protection::READ_WRITE);
        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                read_write,
                0,
                PAGE_SIZE,
                Protection::READ,
            )
            .unwrap();
        let read_execute = authorization(&authority, object, &region, Protection::READ_EXECUTE);
        region
            .protect(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                PAGE_SIZE,
                Protection::READ_WRITE,
            )
            .unwrap();
        region
            .unmap(&mut authority, &mut publisher, PAGE_SIZE, PAGE_SIZE)
            .unwrap();

        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                read_execute,
                0,
                PAGE_SIZE,
                Protection::READ,
            )
            .unwrap();
        region
            .protect(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                PAGE_SIZE,
                Protection::READ_EXECUTE,
            )
            .unwrap();
    }

    #[test]
    fn object_wide_wx_aliases_and_publisher_failures_are_rejected_without_mutation() {
        let mut authority = MemoryObjectAuthority::<2, 8>::new();
        let object = object(&mut authority, Protection::READ_WRITE_EXECUTE);
        let mut first = region::<2>(PAGE_SIZE, PAGE_SIZE * 4);
        let read_write = authorization(&authority, object, &first, Protection::READ_WRITE);
        let mut publisher = FakePublisher::for_region(&first);
        first
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                read_write,
                0,
                PAGE_SIZE,
                Protection::READ_WRITE,
            )
            .unwrap();
        let mut second = region::<2>(PAGE_SIZE * 5, PAGE_SIZE * 2);
        let read_execute = authorization(&authority, object, &second, Protection::READ_EXECUTE);
        let mut second_publisher = FakePublisher::for_region(&second);
        assert!(matches!(
            second.map(
                &mut authority,
                &mut second_publisher,
                PAGE_SIZE * 5,
                read_execute,
                PAGE_SIZE,
                PAGE_SIZE,
                Protection::READ_EXECUTE,
            ),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Object(MemoryObjectError::WritableExecutableAlias)
            ))
        ));
        assert_eq!(authority.active_lease_count(), 1);

        let mut failed = region::<2>(PAGE_SIZE * 8, PAGE_SIZE * 2);
        let read_write_execute =
            authorization(&authority, object, &failed, Protection::READ_WRITE_EXECUTE);
        let mut failed_publisher = FakePublisher::for_region(&failed);
        failed_publisher.fail = true;
        assert_eq!(
            failed.map(
                &mut authority,
                &mut failed_publisher,
                PAGE_SIZE * 8,
                read_write_execute,
                PAGE_SIZE * 2,
                PAGE_SIZE,
                Protection::READ,
            ),
            Err(AddressSpaceTransactionError::Publish(()))
        );
        assert!(failed.mappings().iter().all(Option::is_none));
        assert_eq!(authority.active_lease_count(), 1);

        let retry = authorization(&authority, object, &failed, Protection::READ_WRITE_EXECUTE);
        failed_publisher.fail = false;
        failed
            .map(
                &mut authority,
                &mut failed_publisher,
                PAGE_SIZE * 8,
                retry,
                PAGE_SIZE * 2,
                PAGE_SIZE,
                Protection::READ,
            )
            .unwrap();
        assert_eq!(failed_publisher.calls, 2);
        assert_eq!(failed.mappings().iter().flatten().count(), 1);
        assert_eq!(authority.active_lease_count(), 2);
    }

    #[test]
    fn partial_unmap_needs_split_capacity_and_rolls_back_before_publication() {
        let mut authority = MemoryObjectAuthority::<2, 4>::new();
        let object = object(&mut authority, Protection::READ_WRITE);
        let mut region = region::<1>(PAGE_SIZE, PAGE_SIZE * 4);
        let read_write = authorization(&authority, object, &region, Protection::READ_WRITE);
        let mut publisher = FakePublisher::for_region(&region);
        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                read_write,
                0,
                PAGE_SIZE * 3,
                Protection::READ,
            )
            .unwrap();
        let calls_before = publisher.calls;
        assert_eq!(
            region.unmap(&mut authority, &mut publisher, PAGE_SIZE * 2, PAGE_SIZE),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Capacity
            ))
        );
        assert_eq!(publisher.calls, calls_before);
        assert_eq!(region.mappings()[0].unwrap().byte_len(), PAGE_SIZE * 3);
        assert_eq!(authority.active_lease_count(), 1);
    }

    #[test]
    fn map_anywhere_uses_first_fit_and_reports_fragmented_exhaustion() {
        let mut authority = MemoryObjectAuthority::<2, 8>::new();
        let object = object(&mut authority, Protection::READ_WRITE);
        let mut region = region::<4>(PAGE_SIZE, PAGE_SIZE * 4);
        let mut publisher = FakePublisher::for_region(&region);

        for virtual_start in [PAGE_SIZE, PAGE_SIZE * 3] {
            let read_write = authorization(&authority, object, &region, Protection::READ_WRITE);
            region
                .map(
                    &mut authority,
                    &mut publisher,
                    virtual_start,
                    read_write,
                    0,
                    PAGE_SIZE,
                    Protection::READ,
                )
                .unwrap();
        }
        let anywhere = authorization(&authority, object, &region, Protection::READ_WRITE);
        assert_eq!(
            region
                .map_anywhere(
                    &mut authority,
                    &mut publisher,
                    anywhere,
                    0,
                    PAGE_SIZE,
                    Protection::READ,
                )
                .unwrap(),
            PAGE_SIZE * 2
        );
        let last_fixed = authorization(&authority, object, &region, Protection::READ_WRITE);
        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE * 4,
                last_fixed,
                0,
                PAGE_SIZE,
                Protection::READ,
            )
            .unwrap();
        let exhausted = authorization(&authority, object, &region, Protection::READ_WRITE);
        assert!(matches!(
            region.map_anywhere(
                &mut authority,
                &mut publisher,
                exhausted,
                0,
                PAGE_SIZE,
                Protection::READ,
            ),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::NoSpace
            ))
        ));
    }

    #[test]
    fn space_region_and_lease_identities_reject_swaps_overlaps_and_stale_releases() {
        let mut spaces = space_authority::<2, 3>();
        let first_space = spaces.create_address_space().unwrap();
        let recreated_space = {
            let mut transient = space_authority::<1, 1>();
            transient.create_address_space().unwrap()
        };
        let mut other_registry = space_authority::<1, 1>();
        let other_space = other_registry.create_address_space().unwrap();
        assert_ne!(first_space, recreated_space);
        assert_ne!(first_space, other_space);
        let second_space = spaces.create_address_space().unwrap();
        let mut first: AddressRegion<2> = spaces
            .create_region(first_space, PAGE_SIZE, PAGE_SIZE * 2)
            .unwrap();
        assert!(matches!(
            spaces.create_region::<2>(first_space, PAGE_SIZE * 2, PAGE_SIZE),
            Err(AddressRegionError::Overlap)
        ));
        let second: AddressRegion<2> = spaces
            .create_region(first_space, PAGE_SIZE * 4, PAGE_SIZE * 2)
            .unwrap();

        let mut objects = MemoryObjectAuthority::<1, 4>::new();
        let object = object(&mut objects, Protection::READ_WRITE_EXECUTE);
        let read = authorization(&objects, object, &first, Protection::READ);
        let mut swapped_publisher = FakePublisher {
            address_space: second_space,
            calls: 0,
            fail: false,
            last_before: 0,
            last_after: 0,
        };
        assert!(matches!(
            first.map(
                &mut objects,
                &mut swapped_publisher,
                PAGE_SIZE,
                read,
                0,
                PAGE_SIZE,
                Protection::READ,
            ),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::PublisherIdentity
            ))
        ));
        assert_eq!(swapped_publisher.calls, 0);

        let mut publisher = FakePublisher::for_region(&first);
        let read = authorization(&objects, object, &first, Protection::READ);
        first
            .map(
                &mut objects,
                &mut publisher,
                PAGE_SIZE,
                read,
                0,
                PAGE_SIZE,
                Protection::READ,
            )
            .unwrap();
        let stale_lease = first.mappings()[0].unwrap().lease();
        assert!(matches!(
            objects.prepare_replace::<2>(first_space, second.region, &[stale_lease], &[]),
            Err(MemoryObjectError::ForeignLease)
        ));
        first
            .protect(
                &mut objects,
                &mut publisher,
                PAGE_SIZE,
                PAGE_SIZE,
                Protection::READ,
            )
            .unwrap();
        assert!(matches!(
            objects.prepare_replace::<2>(first_space, first.region, &[stale_lease], &[]),
            Err(MemoryObjectError::InvalidLease)
        ));
    }

    #[test]
    fn object_authorizations_cannot_replay_across_authority_domains() {
        let mut spaces = space_authority::<1, 1>();
        let space = spaces.create_address_space().unwrap();
        let mut region: AddressRegion<1> =
            spaces.create_region(space, PAGE_SIZE, PAGE_SIZE).unwrap();
        let mut first = MemoryObjectAuthority::<1, 1>::new();
        let first_object = object_at(&mut first, 0x20_000, Protection::READ);
        let authorization = authorization(&first, first_object, &region, Protection::READ);

        let mut second = MemoryObjectAuthority::<1, 1>::new();
        let second_object = object_at(&mut second, 0x40_000, Protection::READ);
        assert_ne!(first_object, second_object);
        let mut publisher = FakePublisher::for_region(&region);
        assert!(matches!(
            region.map(
                &mut second,
                &mut publisher,
                PAGE_SIZE,
                authorization,
                0,
                PAGE_SIZE,
                Protection::READ,
            ),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Object(MemoryObjectError::InvalidObjectKey)
            ))
        ));
        assert_eq!(publisher.calls, 0);
        assert_eq!(second.active_lease_count(), 0);
    }
}
