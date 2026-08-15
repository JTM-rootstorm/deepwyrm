//! Fixed-capacity, authority-owned `MemoryObject` backing and mapping leases.
//!
//! This is deliberately below handles and syscalls. The only construction
//! boundary is an allocator-owned unsafe backing grant; consumers receive
//! opaque object keys and short-lived mapping leases rather than physical
//! addresses or independently constructible backing metadata.

#![allow(
    dead_code,
    reason = "DW0-C establishes this authority model before the later page-table and syscall integration supplies production callers"
)]

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
    DuplicateLease,
    LeaseCapacity,
    GenerationExhausted,
    InvalidProtection,
    UnsupportedProtection,
    ProtectionCeiling,
    WritableExecutableAlias,
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
pub(crate) struct MemoryObjectKey(u64);

impl MemoryObjectKey {
    pub(crate) const EMPTY: Self = Self(0);
}

/// Opaque authority-issued identity for one committed mapping lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MappingLease(u64);

impl MappingLease {
    pub(crate) const EMPTY: Self = Self(0);
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
    physical_start: u64,
    object_offset: u64,
    byte_len: u64,
}

impl MemoryObjectRange {
    pub(crate) const EMPTY: Self = Self {
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
pub(crate) struct LeaseRequest {
    object: MemoryObjectKey,
    object_offset: u64,
    byte_len: u64,
    protection: MemoryProtection,
    captured_ceiling: MemoryProtection,
}

impl LeaseRequest {
    pub(crate) const EMPTY: Self = Self {
        object: MemoryObjectKey(0),
        object_offset: 0,
        byte_len: 0,
        protection: MemoryProtection::READ,
        captured_ceiling: MemoryProtection::READ,
    };

    pub(crate) const fn new(
        object: MemoryObjectKey,
        object_offset: u64,
        byte_len: u64,
        protection: MemoryProtection,
        captured_ceiling: MemoryProtection,
    ) -> Self {
        Self {
            object,
            object_offset,
            byte_len,
            protection,
            captured_ceiling,
        }
    }
}

/// A newly allocated lease paired with the exact validated backing range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeaseTicket {
    lease: MappingLease,
    object: MemoryObjectKey,
    range: MemoryObjectRange,
    protection: MemoryProtection,
    captured_ceiling: MemoryProtection,
}

impl LeaseTicket {
    pub(crate) const fn lease(self) -> MappingLease {
        self.lease
    }

    pub(crate) const fn object(self) -> MemoryObjectKey {
        self.object
    }

    pub(crate) const fn range(self) -> MemoryObjectRange {
        self.range
    }

    pub(crate) const fn protection(self) -> MemoryProtection {
        self.protection
    }

    pub(crate) const fn captured_ceiling(self) -> MemoryProtection {
        self.captured_ceiling
    }
}

#[derive(Clone, Copy)]
struct ObjectRecord {
    physical_start: u64,
    logical_byte_len: u64,
    rounded_byte_len: u64,
    kind: MemoryObjectKind,
    protection_ceiling: MemoryProtection,
}

#[derive(Clone, Copy)]
struct ObjectSlot {
    generation: u32,
    record: Option<ObjectRecord>,
}

const EMPTY_OBJECT_SLOT: ObjectSlot = ObjectSlot {
    generation: 0,
    record: None,
};

#[derive(Clone, Copy)]
struct LeaseRecord {
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
    captured_ceiling: MemoryProtection,
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
        object_slot: 0,
        range: MemoryObjectRange {
            physical_start: 0,
            object_offset: 0,
            byte_len: 0,
        },
        protection: MemoryProtection::READ,
        captured_ceiling: MemoryProtection::READ,
    },
};

/// Fixed-capacity authority over objects and their active mapping leases.
///
/// Every map/protect/unmap replacement is prepared while this authority is
/// mutably borrowed. The prepared batch exposes only tickets and can commit
/// only after its address-space publisher reports an atomic PTE replacement.
pub(crate) struct MemoryObjectAuthority<const OBJECTS: usize, const LEASES: usize> {
    objects: [ObjectSlot; OBJECTS],
    leases: [LeaseSlot; LEASES],
}

impl<const OBJECTS: usize, const LEASES: usize> MemoryObjectAuthority<OBJECTS, LEASES> {
    pub(crate) const fn new() -> Self {
        Self {
            objects: [EMPTY_OBJECT_SLOT; OBJECTS],
            leases: [EMPTY_LEASE_SLOT; LEASES],
        }
    }

    /// Grants allocator-owned backing to this authority.
    ///
    /// # Safety
    ///
    /// The caller must prove the allocator exclusively owns the aligned,
    /// nonempty page covering `[physical_start, physical_start + backing_len)`;
    /// it must not be a page table, loader-temporary range, or a frame already
    /// granted to another object. Every byte that a rounded mapping can expose,
    /// including tail bytes beyond `logical_byte_len`, must already be
    /// initialized; anonymous backing and immutable-module tail padding must be
    /// zeroed. The allocator must retain that ownership until this authority's
    /// object lifecycle says it may reclaim the frames.
    #[allow(
        unsafe_code,
        reason = "this explicit boundary records allocator ownership transfer without dereferencing the backing"
    )]
    pub(crate) unsafe fn grant_allocator_backing(
        &mut self,
        physical_start: u64,
        backing_len: u64,
        logical_byte_len: u64,
        kind: MemoryObjectKind,
        protection_ceiling: MemoryProtection,
    ) -> Result<MemoryObjectKey, MemoryObjectError> {
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
        if matches!(kind, MemoryObjectKind::ImmutableBootModule) && protection_ceiling.writable() {
            return Err(MemoryObjectError::ProtectionCeiling);
        }
        let slot = self
            .objects
            .iter()
            .position(|slot| slot.record.is_none())
            .ok_or(MemoryObjectError::Capacity)?;
        let generation = next_generation(self.objects[slot].generation)?;
        self.objects[slot] = ObjectSlot {
            generation,
            record: Some(ObjectRecord {
                physical_start,
                logical_byte_len,
                rounded_byte_len,
                kind,
                protection_ceiling,
            }),
        };
        Ok(MemoryObjectKey(encode_raw_key(slot, generation)))
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
    pub(crate) fn prepare_replace<const BATCH: usize>(
        &mut self,
        released: &[MappingLease],
        requested: &[LeaseRequest],
    ) -> Result<PreparedReplace<'_, OBJECTS, LEASES, BATCH>, MemoryObjectError> {
        if released.len() > BATCH || requested.len() > BATCH {
            return Err(MemoryObjectError::LeaseCapacity);
        }
        let mut release_slots = [usize::MAX; BATCH];
        for (position, lease) in released.iter().copied().enumerate() {
            let slot = self.lease_slot(lease)?;
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
            let object_slot = self.object_slot(request.object)?;
            let object = self.objects[object_slot]
                .record
                .expect("validated object slot has a record");
            MemoryProtection::mapping(request.protection.0)?;
            MemoryProtection::ceiling(request.captured_ceiling.0)?;
            if !object.protection_ceiling.contains(request.captured_ceiling)
                || !request.captured_ceiling.contains(request.protection)
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
            let lease = MappingLease(encode_raw_key(slot, generation));
            let record = LeaseRecord {
                object_slot,
                range,
                protection: request.protection,
                captured_ceiling: request.captured_ceiling,
            };
            pending[position] = PendingLease {
                slot,
                generation,
                record,
            };
            tickets[position] = Some(LeaseTicket {
                lease,
                object: request.object,
                range,
                protection: request.protection,
                captured_ceiling: request.captured_ceiling,
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
        let (slot, generation) =
            decode_raw_key(object.0).ok_or(MemoryObjectError::InvalidObjectKey)?;
        let entry = self
            .objects
            .get(slot)
            .ok_or(MemoryObjectError::InvalidObjectKey)?;
        if entry.generation != generation || entry.record.is_none() {
            return Err(MemoryObjectError::InvalidObjectKey);
        }
        Ok(slot)
    }

    fn object_record(&self, object: MemoryObjectKey) -> Result<ObjectRecord, MemoryObjectError> {
        let slot = self.object_slot(object)?;
        Ok(self.objects[slot]
            .record
            .expect("validated object slot has a record"))
    }

    fn lease_slot(&self, lease: MappingLease) -> Result<usize, MemoryObjectError> {
        let (slot, generation) = decode_raw_key(lease.0).ok_or(MemoryObjectError::InvalidLease)?;
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
pub(crate) struct PreparedReplace<'a, const OBJECTS: usize, const LEASES: usize, const BATCH: usize>
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
    pub(crate) fn tickets(&self) -> &[Option<LeaseTicket>] {
        &self.tickets[..self.pending_len]
    }

    /// Commits only after the caller's address-space publisher has atomically
    /// accepted the corresponding PTE replacement. This has no fallible work:
    /// it clears released leases and installs the already-validated tickets.
    pub(crate) fn commit(mut self) {
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
    use super::*;

    #[allow(
        unsafe_code,
        reason = "tests exercise the explicit allocator-owned grant boundary with synthetic frames"
    )]
    fn grant<const OBJECTS: usize, const LEASES: usize>(
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        logical_byte_len: u64,
        ceiling: MemoryProtection,
    ) -> MemoryObjectKey {
        // SAFETY: synthetic test frames are not dereferenced or shared.
        unsafe {
            authority
                .grant_allocator_backing(
                    0x20_000,
                    PAGE_SIZE * 4,
                    logical_byte_len,
                    MemoryObjectKind::PageBacked,
                    ceiling,
                )
                .unwrap()
        }
    }

    #[test]
    fn allocator_grant_preserves_exact_and_rounded_lengths() {
        let mut authority = MemoryObjectAuthority::<2, 4>::new();
        let key = grant(
            &mut authority,
            PAGE_SIZE + 1,
            MemoryProtection::READ_WRITE_EXECUTE,
        );
        let info = authority.object_info(key).unwrap();
        assert_eq!(info.logical_byte_len(), PAGE_SIZE + 1);
        assert_eq!(info.rounded_byte_len(), PAGE_SIZE * 2);
        assert_eq!(info.kind(), MemoryObjectKind::PageBacked);
    }

    #[test]
    fn replacement_rejects_bad_ranges_and_wx_aliases_without_commit() {
        let mut authority = MemoryObjectAuthority::<2, 4>::new();
        let key = grant(
            &mut authority,
            PAGE_SIZE * 2,
            MemoryProtection::READ_WRITE_EXECUTE,
        );
        assert!(matches!(
            authority.prepare_replace::<2>(
                &[],
                &[LeaseRequest::new(
                    key,
                    1,
                    PAGE_SIZE,
                    MemoryProtection::READ,
                    MemoryProtection::READ,
                )],
            ),
            Err(MemoryObjectError::Unaligned)
        ));
        let prepared = authority
            .prepare_replace::<2>(
                &[],
                &[LeaseRequest::new(
                    key,
                    0,
                    PAGE_SIZE,
                    MemoryProtection::READ_WRITE,
                    MemoryProtection::READ_WRITE,
                )],
            )
            .unwrap();
        prepared.commit();
        assert_eq!(authority.active_lease_count(), 1);
        assert!(matches!(
            authority.prepare_replace::<2>(
                &[],
                &[LeaseRequest::new(
                    key,
                    PAGE_SIZE,
                    PAGE_SIZE,
                    MemoryProtection::READ_EXECUTE,
                    MemoryProtection::READ_WRITE_EXECUTE,
                )],
            ),
            Err(MemoryObjectError::WritableExecutableAlias)
        ));
        assert_eq!(authority.active_lease_count(), 1);
    }

    #[test]
    fn protection_ceiling_is_captured_per_object() {
        let mut authority = MemoryObjectAuthority::<2, 2>::new();
        let key = grant(&mut authority, PAGE_SIZE, MemoryProtection::READ_WRITE);
        assert!(matches!(
            authority.prepare_replace::<1>(
                &[],
                &[LeaseRequest::new(
                    key,
                    0,
                    PAGE_SIZE,
                    MemoryProtection::READ_EXECUTE,
                    MemoryProtection::READ_WRITE,
                )],
            ),
            Err(MemoryObjectError::ProtectionCeiling)
        ));
    }
}
