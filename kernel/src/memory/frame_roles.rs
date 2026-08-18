//! Authoritative physical-frame ownership and role transitions.
//!
//! The range allocator is deliberately kept as a mechanism below this module.
//! Every allocation made available to the rest of the kernel is represented by
//! one generation-stamped, non-copy grant and one nonoverlapping registry
//! record. Raw physical addresses are metadata, never ownership authority.

#![allow(
    dead_code,
    reason = "DW0-C establishes typed frame ownership before the architecture publisher consumes it"
)]

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::boot_map::BootstrapMemoryWitness;
use super::boot_map::{BootMapError, BootstrapReservation, SanitizedBootMap};
use super::physical::{
    BASE_PAGE_SIZE, PageRange, PhysicalFrameAllocator, PhysicalMemoryError, PhysicalRange,
};

#[path = "frame_roles/manager.rs"]
mod manager;
#[cfg(test)]
#[path = "frame_roles/test_support.rs"]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::{
    synthetic_allocator_backing, synthetic_frame_role_manager, synthetic_immutable_module_backing,
};

static NEXT_MANAGER_DOMAIN: AtomicU64 = AtomicU64::new(1);
static FRAME_ROLE_MANAGER_CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameRoleError {
    Physical(PhysicalMemoryError),
    Capacity,
    GenerationExhausted,
    ManagerDomainExhausted,
    ForeignManager,
    InvalidGrant,
    WrongRole,
    Overlap,
    ExternalAllocatorOverlap,
    DynamicOutsideAllocator,
    InvalidTableOwner,
    InvalidTableParent,
    DuplicateTableRoot,
    ReadOnlyBacking,
    InvariantViolation,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct GrantTransitionError<G> {
    error: FrameRoleError,
    grant: G,
}

impl<G> GrantTransitionError<G> {
    const fn new(error: FrameRoleError, grant: G) -> Self {
        Self { error, grant }
    }

    pub(crate) const fn error(&self) -> FrameRoleError {
        self.error
    }

    pub(crate) fn into_grant(self) -> G {
        self.grant
    }
}

impl From<PhysicalMemoryError> for FrameRoleError {
    fn from(error: PhysicalMemoryError) -> Self {
        Self::Physical(error)
    }
}

fn claim_manager(claimed: &AtomicBool) -> Result<(), FrameRoleInitializationError> {
    claimed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| FrameRoleInitializationError::AlreadyInitialized)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameRoleInitializationError {
    BootMap(BootMapError),
    AlreadyInitialized,
    Role(FrameRoleError),
}

/// Opaque observation identity. It can query a role, but cannot mutate or free
/// it without the corresponding non-copy grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameRoleIdentity {
    domain: u64,
    raw: u64,
}

impl FrameRoleIdentity {
    const EMPTY: Self = Self { domain: 0, raw: 0 };
}

/// Opaque identity retained by `MemoryObject` mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackingIdentity(FrameRoleIdentity);

impl BackingIdentity {
    pub(crate) const EMPTY: Self = Self(FrameRoleIdentity::EMPTY);
}

/// One frame-role namespace for an architecture address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TableOwnerKey {
    domain: u64,
    raw: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TableLevel {
    Pml4,
    Pdpt,
    Pd,
    Pt,
}

impl TableLevel {
    pub(crate) const fn child(self) -> Option<Self> {
        match self {
            Self::Pml4 => Some(Self::Pdpt),
            Self::Pdpt => Some(Self::Pd),
            Self::Pd => Some(Self::Pt),
            Self::Pt => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TableIdentity {
    role: FrameRoleIdentity,
    owner: TableOwnerKey,
    level: TableLevel,
    physical_start: u64,
}

impl TableIdentity {
    pub(crate) const fn physical_start(self) -> u64 {
        self.physical_start
    }

    pub(crate) const fn owner(self) -> TableOwnerKey {
        self.owner
    }

    pub(crate) const fn level(self) -> TableLevel {
        self.level
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectBackingKind {
    AllocatorOwned,
    ImmutableModule { module_index: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelImageSegment {
    Text,
    ReadOnlyData,
    WritableData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExternalFrameRole {
    TransitionTable { table_index: u32 },
    KernelImage { segment: KernelImageSegment },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameRoleKind {
    AllocatedUninitialized,
    Zeroed,
    ObjectBacking(ObjectBackingKind),
    TableCandidate {
        owner: TableOwnerKey,
        level: TableLevel,
    },
    PageTable {
        owner: TableOwnerKey,
        level: TableLevel,
    },
    External(ExternalFrameRole),
    ExternalImmutableModule {
        module_index: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameRole {
    AllocatedUninitialized,
    Zeroed,
    ObjectBacking(ObjectBackingKind),
    TableCandidate {
        owner: TableOwnerKey,
        level: TableLevel,
    },
    PageTable {
        owner: TableOwnerKey,
        level: TableLevel,
        parent: Option<FrameRoleIdentity>,
    },
    External(ExternalFrameRole),
    ExternalImmutableModule {
        module_index: u32,
    },
}

impl FrameRole {
    const fn is_dynamic(self) -> bool {
        !matches!(
            self,
            Self::External(_) | Self::ExternalImmutableModule { .. }
        )
    }

    const fn kind(self) -> FrameRoleKind {
        match self {
            Self::AllocatedUninitialized => FrameRoleKind::AllocatedUninitialized,
            Self::Zeroed => FrameRoleKind::Zeroed,
            Self::ObjectBacking(kind) => FrameRoleKind::ObjectBacking(kind),
            Self::TableCandidate { owner, level } => FrameRoleKind::TableCandidate { owner, level },
            Self::PageTable {
                owner,
                level,
                parent: _,
            } => FrameRoleKind::PageTable { owner, level },
            Self::External(role) => FrameRoleKind::External(role),
            Self::ExternalImmutableModule { module_index } => {
                FrameRoleKind::ExternalImmutableModule { module_index }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RoleRecord {
    range: PageRange,
    role: FrameRole,
}

#[derive(Clone, Copy)]
struct RoleSlot {
    generation: u32,
    record: Option<RoleRecord>,
}

const EMPTY_ROLE_SLOT: RoleSlot = RoleSlot {
    generation: 0,
    record: None,
};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AllocationGrant {
    identity: FrameRoleIdentity,
    range: PageRange,
}

impl AllocationGrant {
    pub(crate) const fn physical_start(&self) -> u64 {
        self.range.start
    }

    pub(crate) const fn byte_len(&self) -> u64 {
        self.range.end - self.range.start
    }
}

/// Linear record of the exact loader transition-table set imported after
/// live graph attestation. Keeping this token alive prevents later bootstrap
/// code from treating those frames as anonymous external memory.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TransitionTableRoleSet<const CAPACITY: usize> {
    _domain: u64,
    count: usize,
    _capacity: core::marker::PhantomData<[(); CAPACITY]>,
}

impl<const CAPACITY: usize> TransitionTableRoleSet<CAPACITY> {
    pub(crate) const fn len(&self) -> usize {
        self.count
    }
}

/// Fully validated but unpublished role assignment for the three linker
/// kernel segments retained by the first Deep-owned root.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct StagedKernelImageRoles {
    domain: u64,
    ranges: [PageRange; 3],
    segments: [KernelImageSegment; 3],
    slots: [usize; 3],
    generations: [u32; 3],
    identities: [FrameRoleIdentity; 3],
}

impl StagedKernelImageRoles {
    pub(crate) fn validate_page(
        &self,
        physical_start: u64,
        segment: KernelImageSegment,
    ) -> Result<(), FrameRoleError> {
        let index = self
            .segments
            .iter()
            .position(|candidate| *candidate == segment)
            .ok_or(FrameRoleError::WrongRole)?;
        if !(self.ranges[index].start <= physical_start
            && physical_start < self.ranges[index].end
            && physical_start.is_multiple_of(BASE_PAGE_SIZE))
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct KernelImageRoleSet {
    _identities: [FrameRoleIdentity; 3],
    ranges: [PageRange; 3],
    segments: [KernelImageSegment; 3],
}

impl KernelImageRoleSet {
    pub(crate) fn validate_page(
        &self,
        physical_start: u64,
        segment: KernelImageSegment,
    ) -> Result<(), FrameRoleError> {
        let index = self
            .segments
            .iter()
            .position(|candidate| *candidate == segment)
            .ok_or(FrameRoleError::WrongRole)?;
        if !(self.ranges[index].start <= physical_start
            && physical_start < self.ranges[index].end
            && physical_start.is_multiple_of(BASE_PAGE_SIZE))
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ZeroedGrant {
    identity: FrameRoleIdentity,
    range: PageRange,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObjectBackingGrant {
    identity: BackingIdentity,
    range: PageRange,
    kind: ObjectBackingKind,
}

impl ObjectBackingGrant {
    pub(crate) const fn identity(&self) -> BackingIdentity {
        self.identity
    }

    pub(crate) const fn physical_start(&self) -> u64 {
        self.range.start
    }

    pub(crate) const fn byte_len(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub(crate) const fn kind(&self) -> ObjectBackingKind {
        self.kind
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TableCandidateGrant {
    identity: FrameRoleIdentity,
    range: PageRange,
    owner: TableOwnerKey,
    level: TableLevel,
}

pub(crate) enum TableCommitParent<'a> {
    Committed(TableIdentity),
    Candidate(&'a TableCandidateGrant),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct StagedTableCommit {
    grant: TableCandidateGrant,
    slot: usize,
    parent: Option<FrameRoleIdentity>,
}

impl TableCandidateGrant {
    pub(crate) const fn physical_start(&self) -> u64 {
        self.range.start
    }

    pub(crate) const fn owner(&self) -> TableOwnerKey {
        self.owner
    }

    pub(crate) const fn level(&self) -> TableLevel {
        self.level
    }
}

impl StagedTableCommit {
    pub(crate) const fn candidate(&self) -> &TableCandidateGrant {
        &self.grant
    }

    pub(crate) fn into_candidate(self) -> TableCandidateGrant {
        self.grant
    }
}

/// The sole dynamic allocator and physical-role registry.
pub(crate) struct FrameRoleManager<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    domain: u64,
    allocator: PhysicalFrameAllocator<RANGE_CAPACITY>,
    roles: [RoleSlot; ROLE_CAPACITY],
    next_table_owner: u64,
}

#[cfg(test)]
#[path = "frame_roles/tests.rs"]
mod tests;
