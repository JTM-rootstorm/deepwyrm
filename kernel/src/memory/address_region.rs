//! Atomic `AddressRegion` model and address-space publication boundary.
//!
//! The region never changes its model or authority leases until an injected
//! publisher atomically accepts the same full replacement for page tables.

#![allow(
    dead_code,
    reason = "DW0-C exposes this model to the architecture publisher before page-table integration wires its production callers"
)]

use super::object::{
    LeaseRequest, MappingLease, MemoryObjectAuthority, MemoryObjectError, MemoryObjectKey,
    MemoryObjectRange, MemoryProtection, PAGE_SIZE,
};

const USER_CANONICAL_END: u64 = 0x0000_8000_0000_0000;
const EMPTY_LEASE: MappingLease = MappingLease::EMPTY;

pub(crate) type Protection = MemoryProtection;

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
    InvalidProtection,
    UnsupportedProtection,
    Object(MemoryObjectError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressSpaceTransactionError<E> {
    Model(AddressRegionError),
    Publish(E),
}

/// One committed virtual mapping. The lease is opaque and proves that this
/// mapping participated in the authority's object-wide W/X accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mapping {
    virtual_start: u64,
    byte_len: u64,
    object: MemoryObjectKey,
    backing: MemoryObjectRange,
    protection: Protection,
    captured_ceiling: Protection,
    lease: MappingLease,
}

impl Mapping {
    #[allow(
        dead_code,
        reason = "the architecture publisher consumes virtual starts when it materializes page-table entries"
    )]
    pub(crate) const fn virtual_start(self) -> u64 {
        self.virtual_start
    }

    pub(crate) const fn byte_len(self) -> u64 {
        self.byte_len
    }

    #[allow(
        dead_code,
        reason = "the architecture publisher consumes allocator-owned backing metadata when it materializes page-table entries"
    )]
    pub(crate) const fn backing(self) -> MemoryObjectRange {
        self.backing
    }

    pub(crate) const fn protection(self) -> Protection {
        self.protection
    }

    #[allow(
        dead_code,
        reason = "the architecture publisher uses the opaque lease for publication and invalidation provenance"
    )]
    pub(crate) const fn lease(self) -> MappingLease {
        self.lease
    }

    const fn end(self) -> u64 {
        self.virtual_start + self.byte_len
    }

    const fn spec(self) -> MappingSpec {
        MappingSpec {
            virtual_start: self.virtual_start,
            byte_len: self.byte_len,
            object: self.object,
            object_offset: self.backing.object_offset(),
            protection: self.protection,
            captured_ceiling: self.captured_ceiling,
        }
    }
}

#[derive(Clone, Copy)]
struct MappingSpec {
    virtual_start: u64,
    byte_len: u64,
    object: MemoryObjectKey,
    object_offset: u64,
    protection: Protection,
    captured_ceiling: Protection,
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
            virtual_start: start,
            byte_len,
            object: self.object,
            object_offset,
            protection,
            captured_ceiling: self.captured_ceiling,
        })
    }
}

const EMPTY_MAPPING: Mapping = Mapping {
    virtual_start: 0,
    byte_len: 0,
    object: MemoryObjectKey::EMPTY,
    backing: MemoryObjectRange::EMPTY,
    protection: Protection::READ,
    captured_ceiling: Protection::READ,
    lease: EMPTY_LEASE,
};

/// The sole page-table seam used by this model.
///
/// Implementations must serialize the address-space root and either publish
/// exactly `after` in place of `before` (including all PTE invalidations) or
/// leave every PTE unchanged. A returned error is a pre-commit failure.
pub(crate) trait AddressSpacePublisher {
    type Error;

    fn publish_replace(&mut self, before: &[Mapping], after: &[Mapping])
    -> Result<(), Self::Error>;
}

/// Fixed-capacity model for one lower-canonical user address region.
pub(crate) struct AddressRegion<const SLOTS: usize> {
    start: u64,
    byte_len: u64,
    mappings: [Option<Mapping>; SLOTS],
}

impl<const SLOTS: usize> AddressRegion<SLOTS> {
    pub(crate) const fn new(start: u64, byte_len: u64) -> Result<Self, AddressRegionError> {
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
        Ok(Self {
            start,
            byte_len,
            mappings: [None; SLOTS],
        })
    }

    pub(crate) const fn mappings(&self) -> &[Option<Mapping>; SLOTS] {
        &self.mappings
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
        object: MemoryObjectKey,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
        source_ceiling: Protection,
    ) -> Result<(), AddressSpaceTransactionError<P::Error>> {
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
            virtual_start,
            byte_len,
            object,
            object_offset,
            protection,
            captured_ceiling: source_ceiling,
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
        object: MemoryObjectKey,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
        source_ceiling: Protection,
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
                    object,
                    object_offset,
                    byte_len,
                    protection,
                    source_ceiling,
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
                spec.object,
                spec.object_offset,
                spec.byte_len,
                spec.protection,
                spec.captured_ceiling,
            );
        }

        let prepared = authority
            .prepare_replace::<SLOTS>(&released[..old_len], &requests[..spec_len])
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
                virtual_start: spec.virtual_start,
                byte_len: spec.byte_len,
                object: ticket.object(),
                backing: ticket.range(),
                protection: ticket.protection(),
                captured_ceiling: ticket.captured_ceiling(),
                lease: ticket.lease(),
            };
            next_dense[index] = mapping;
            next[index] = Some(mapping);
        }
        publisher
            .publish_replace(&old[..old_len], &next_dense[..spec_len])
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
    use super::super::object::MemoryObjectKind;
    use super::*;

    #[derive(Default)]
    struct FakePublisher {
        calls: usize,
        fail: bool,
        last_before: usize,
        last_after: usize,
    }

    impl AddressSpacePublisher for FakePublisher {
        type Error = ();

        fn publish_replace(
            &mut self,
            before: &[Mapping],
            after: &[Mapping],
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            self.last_before = before.len();
            self.last_after = after.len();
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    #[allow(
        unsafe_code,
        reason = "tests exercise the allocator-owned backing grant boundary with synthetic frames"
    )]
    fn object<const OBJECTS: usize, const LEASES: usize>(
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        ceiling: Protection,
    ) -> MemoryObjectKey {
        // SAFETY: synthetic frames are metadata only and have no aliases in this test.
        unsafe {
            authority
                .grant_allocator_backing(
                    0x20_000,
                    PAGE_SIZE * 8,
                    PAGE_SIZE * 8,
                    MemoryObjectKind::PageBacked,
                    ceiling,
                )
                .unwrap()
        }
    }

    #[test]
    fn rejects_page_zero_and_upper_canonical_regions() {
        assert!(matches!(
            AddressRegion::<2>::new(0, PAGE_SIZE),
            Err(AddressRegionError::PageZero)
        ));
        assert!(matches!(
            AddressRegion::<2>::new(USER_CANONICAL_END - PAGE_SIZE, PAGE_SIZE * 2),
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
        let mut publisher = FakePublisher::default();
        let mut region = AddressRegion::<4>::new(PAGE_SIZE, PAGE_SIZE * 8).unwrap();
        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                object,
                0,
                PAGE_SIZE * 2,
                Protection::READ_WRITE,
                Protection::READ_WRITE_EXECUTE,
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
    fn source_ceiling_is_captured_across_protect_and_split_replacements() {
        let mut authority = MemoryObjectAuthority::<2, 8>::new();
        let object = object(&mut authority, Protection::READ_WRITE_EXECUTE);
        let mut publisher = FakePublisher::default();
        let mut region = AddressRegion::<4>::new(PAGE_SIZE, PAGE_SIZE * 8).unwrap();

        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                object,
                0,
                PAGE_SIZE,
                Protection::READ,
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

        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                object,
                0,
                PAGE_SIZE,
                Protection::READ,
                Protection::READ_WRITE,
            )
            .unwrap();
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
                object,
                0,
                PAGE_SIZE,
                Protection::READ,
                Protection::READ_EXECUTE,
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
        let mut publisher = FakePublisher::default();
        let mut first = AddressRegion::<2>::new(PAGE_SIZE, PAGE_SIZE * 4).unwrap();
        first
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                object,
                0,
                PAGE_SIZE,
                Protection::READ_WRITE,
                Protection::READ_WRITE_EXECUTE,
            )
            .unwrap();
        let mut second = AddressRegion::<2>::new(PAGE_SIZE, PAGE_SIZE * 4).unwrap();
        assert!(matches!(
            second.map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                object,
                PAGE_SIZE,
                PAGE_SIZE,
                Protection::READ_EXECUTE,
                Protection::READ_WRITE_EXECUTE,
            ),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::Object(MemoryObjectError::WritableExecutableAlias)
            ))
        ));
        assert_eq!(authority.active_lease_count(), 1);

        let mut failed = AddressRegion::<2>::new(PAGE_SIZE * 5, PAGE_SIZE * 2).unwrap();
        publisher.fail = true;
        assert_eq!(
            failed.map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE * 5,
                object,
                PAGE_SIZE * 2,
                PAGE_SIZE,
                Protection::READ,
                Protection::READ_WRITE_EXECUTE,
            ),
            Err(AddressSpaceTransactionError::Publish(()))
        );
        assert!(failed.mappings().iter().all(Option::is_none));
        assert_eq!(authority.active_lease_count(), 1);
    }

    #[test]
    fn partial_unmap_needs_split_capacity_and_rolls_back_before_publication() {
        let mut authority = MemoryObjectAuthority::<2, 4>::new();
        let object = object(&mut authority, Protection::READ_WRITE);
        let mut publisher = FakePublisher::default();
        let mut region = AddressRegion::<1>::new(PAGE_SIZE, PAGE_SIZE * 4).unwrap();
        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE,
                object,
                0,
                PAGE_SIZE * 3,
                Protection::READ,
                Protection::READ_WRITE,
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
        let mut publisher = FakePublisher::default();
        let mut region = AddressRegion::<4>::new(PAGE_SIZE, PAGE_SIZE * 4).unwrap();

        for virtual_start in [PAGE_SIZE, PAGE_SIZE * 3] {
            region
                .map(
                    &mut authority,
                    &mut publisher,
                    virtual_start,
                    object,
                    0,
                    PAGE_SIZE,
                    Protection::READ,
                    Protection::READ_WRITE,
                )
                .unwrap();
        }
        assert_eq!(
            region
                .map_anywhere(
                    &mut authority,
                    &mut publisher,
                    object,
                    0,
                    PAGE_SIZE,
                    Protection::READ,
                    Protection::READ_WRITE,
                )
                .unwrap(),
            PAGE_SIZE * 2
        );
        region
            .map(
                &mut authority,
                &mut publisher,
                PAGE_SIZE * 4,
                object,
                0,
                PAGE_SIZE,
                Protection::READ,
                Protection::READ_WRITE,
            )
            .unwrap();
        assert!(matches!(
            region.map_anywhere(
                &mut authority,
                &mut publisher,
                object,
                0,
                PAGE_SIZE,
                Protection::READ,
                Protection::READ_WRITE,
            ),
            Err(AddressSpaceTransactionError::Model(
                AddressRegionError::NoSpace
            ))
        ));
    }
}
