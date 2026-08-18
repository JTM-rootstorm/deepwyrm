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

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn new(allocator: PhysicalFrameAllocator<RANGE_CAPACITY>) -> Result<Self, FrameRoleError> {
        let domain = NEXT_MANAGER_DOMAIN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| FrameRoleError::ManagerDomainExhausted)?;
        Ok(Self {
            domain,
            allocator,
            roles: [EMPTY_ROLE_SLOT; ROLE_CAPACITY],
            next_table_owner: 1,
        })
    }

    /// Creates the kernel's sole dynamic frame owner from a consumed map.
    ///
    /// Validation and allocator construction complete before the global
    /// one-shot claim. Once claimed, initialization is terminal even if the
    /// subsequent manager-domain allocation fails.
    ///
    /// # Safety
    ///
    /// The caller must be the sole boot-memory owner, must not have created or
    /// retained any other allocator over the handoff's usable ranges, and must
    /// retain the returned manager for the lifetime of all issued grants.
    #[allow(
        unsafe_code,
        reason = "boot ownership uniqueness cannot be derived from a repeatable sanitized-map value alone"
    )]
    pub(crate) unsafe fn from_boot_map(
        map: SanitizedBootMap,
        reservations: &[BootstrapReservation],
    ) -> Result<Self, FrameRoleInitializationError> {
        let allocator = super::boot_map::initialize_frame_allocator(&map, reservations)
            .map_err(FrameRoleInitializationError::BootMap)?;
        claim_manager(&FRAME_ROLE_MANAGER_CLAIMED)?;
        Self::new(allocator).map_err(FrameRoleInitializationError::Role)
    }

    /// Initializes the sole manager directly in caller-owned static storage,
    /// avoiding a large bootstrap-stack temporary.
    ///
    /// # Safety
    ///
    /// In addition to [`Self::from_boot_map`]'s ownership contract, `slot`
    /// must be unique, uninitialized storage which remains alive for every
    /// grant and active paging session issued by the returned manager.
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    #[allow(
        unsafe_code,
        reason = "one-shot bootstrap constructs the large role registry directly in static storage"
    )]
    pub(crate) unsafe fn from_boot_map_in<'a>(
        slot: &'a mut MaybeUninit<Self>,
        map: &'a SanitizedBootMap,
        reservations: &'a [BootstrapReservation],
    ) -> Result<(&'a mut Self, BootstrapMemoryWitness<'a>), FrameRoleInitializationError> {
        let destination = slot.as_mut_ptr();
        let allocator_slot = unsafe {
            &mut *core::ptr::addr_of_mut!((*destination).allocator)
                .cast::<MaybeUninit<PhysicalFrameAllocator<RANGE_CAPACITY>>>()
        };
        unsafe {
            super::boot_map::initialize_frame_allocator_in(allocator_slot, map, reservations)
        }
        .map_err(FrameRoleInitializationError::BootMap)?;
        claim_manager(&FRAME_ROLE_MANAGER_CLAIMED)?;
        let domain = NEXT_MANAGER_DOMAIN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| {
                FrameRoleInitializationError::Role(FrameRoleError::ManagerDomainExhausted)
            })?;
        unsafe {
            core::ptr::addr_of_mut!((*destination).domain).write(domain);
            let roles = core::ptr::addr_of_mut!((*destination).roles).cast::<RoleSlot>();
            for index in 0..ROLE_CAPACITY {
                roles.add(index).write(EMPTY_ROLE_SLOT);
            }
            core::ptr::addr_of_mut!((*destination).next_table_owner).write(1);
            Ok((
                &mut *destination,
                BootstrapMemoryWitness::new(map, reservations),
            ))
        }
    }

    pub(crate) fn allocate(&mut self, page_count: u64) -> Result<AllocationGrant, FrameRoleError> {
        let (slot, generation) = self.next_slot()?;
        let identity = self.identity(slot, generation)?;
        let range = self.allocator.allocate_run(page_count)?;
        self.roles[slot] = RoleSlot {
            generation,
            record: Some(RoleRecord {
                range,
                role: FrameRole::AllocatedUninitialized,
            }),
        };
        Ok(AllocationGrant { identity, range })
    }

    /// Revalidates a live allocation grant before architecture code mutates
    /// its physical contents.
    pub(crate) fn validate_allocation(
        &self,
        grant: &AllocationGrant,
    ) -> Result<(), FrameRoleError> {
        let record = self.record(grant.identity)?;
        if record.range != grant.range || record.role != FrameRole::AllocatedUninitialized {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }

    /// Attests that architecture-owned access initialized every byte in the
    /// allocation to zero.
    ///
    /// # Safety
    ///
    /// The caller must have exclusively zeroed the complete physical run and
    /// completed any cache maintenance required before returning the grant.
    #[allow(
        unsafe_code,
        reason = "physical zeroing is an architecture access fact represented by a typed state transition"
    )]
    pub(crate) unsafe fn assume_zeroed(
        &mut self,
        grant: AllocationGrant,
    ) -> Result<ZeroedGrant, GrantTransitionError<AllocationGrant>> {
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::AllocatedUninitialized,
            FrameRole::Zeroed,
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(ZeroedGrant {
            identity: grant.identity,
            range: grant.range,
        })
    }

    pub(crate) fn assign_object_backing(
        &mut self,
        grant: ZeroedGrant,
    ) -> Result<ObjectBackingGrant, GrantTransitionError<ZeroedGrant>> {
        let kind = ObjectBackingKind::AllocatorOwned;
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::Zeroed,
            FrameRole::ObjectBacking(kind),
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(ObjectBackingGrant {
            identity: BackingIdentity(grant.identity),
            range: grant.range,
            kind,
        })
    }

    pub(crate) fn create_table_owner(&mut self) -> Result<TableOwnerKey, FrameRoleError> {
        let raw = self.next_table_owner;
        self.next_table_owner = raw
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(FrameRoleError::InvalidTableOwner)?;
        Ok(TableOwnerKey {
            domain: self.domain,
            raw,
        })
    }

    pub(crate) fn prepare_table(
        &mut self,
        grant: ZeroedGrant,
        owner: TableOwnerKey,
        level: TableLevel,
    ) -> Result<TableCandidateGrant, GrantTransitionError<ZeroedGrant>> {
        if let Err(error) = self.validate_owner(owner) {
            return Err(GrantTransitionError::new(error, grant));
        }
        if grant.range.page_count() != 1 {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::Zeroed,
            FrameRole::TableCandidate { owner, level },
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(TableCandidateGrant {
            identity: grant.identity,
            range: grant.range,
            owner,
            level,
        })
    }

    pub(crate) fn commit_table(
        &mut self,
        grant: TableCandidateGrant,
        parent: Option<TableIdentity>,
    ) -> Result<TableIdentity, GrantTransitionError<TableCandidateGrant>> {
        let parent = parent.map(TableCommitParent::Committed);
        let staged = self.stage_table_commit(grant, parent)?;
        Ok(self.publish_staged_table(staged))
    }

    pub(crate) fn stage_table_commit(
        &self,
        grant: TableCandidateGrant,
        parent: Option<TableCommitParent<'_>>,
    ) -> Result<StagedTableCommit, GrantTransitionError<TableCandidateGrant>> {
        if let Err(error) = self.validate_owner(grant.owner) {
            return Err(GrantTransitionError::new(error, grant));
        }
        let slot = match self.slot(grant.identity) {
            Ok(slot) => slot,
            Err(error) => return Err(GrantTransitionError::new(error, grant)),
        };
        if self.roles[slot].record
            != Some(RoleRecord {
                range: grant.range,
                role: FrameRole::TableCandidate {
                    owner: grant.owner,
                    level: grant.level,
                },
            })
        {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        if grant.level == TableLevel::Pml4
            && self
                .roles
                .iter()
                .enumerate()
                .filter(|(other_slot, _)| *other_slot != slot)
                .filter_map(|(_, slot)| slot.record)
                .any(|record| {
                    matches!(
                        record.role,
                        FrameRole::PageTable {
                            owner,
                            level: TableLevel::Pml4,
                            ..
                        } | FrameRole::TableCandidate {
                            owner,
                            level: TableLevel::Pml4,
                        } if owner == grant.owner
                    )
                })
        {
            return Err(GrantTransitionError::new(
                FrameRoleError::DuplicateTableRoot,
                grant,
            ));
        }
        let parent_role = match (grant.level, parent) {
            (TableLevel::Pml4, None) => None,
            (TableLevel::Pml4, Some(_)) | (_, None) => {
                return Err(GrantTransitionError::new(
                    FrameRoleError::InvalidTableParent,
                    grant,
                ));
            }
            (level, Some(TableCommitParent::Committed(parent))) => {
                if self.validate_table_identity(parent).is_err()
                    || parent.owner != grant.owner
                    || parent.level.child() != Some(level)
                {
                    return Err(GrantTransitionError::new(
                        FrameRoleError::InvalidTableParent,
                        grant,
                    ));
                }
                Some(parent.role)
            }
            (level, Some(TableCommitParent::Candidate(parent))) => {
                let record = match self.record(parent.identity) {
                    Ok(record) => record,
                    Err(_) => {
                        return Err(GrantTransitionError::new(
                            FrameRoleError::InvalidTableParent,
                            grant,
                        ));
                    }
                };
                if record.range != parent.range
                    || record.role
                        != (FrameRole::TableCandidate {
                            owner: parent.owner,
                            level: parent.level,
                        })
                    || parent.owner != grant.owner
                    || parent.level.child() != Some(level)
                {
                    return Err(GrantTransitionError::new(
                        FrameRoleError::InvalidTableParent,
                        grant,
                    ));
                }
                Some(parent.identity)
            }
        };
        Ok(StagedTableCommit {
            grant,
            slot,
            parent: parent_role,
        })
    }

    pub(crate) fn publish_staged_table(&mut self, staged: StagedTableCommit) -> TableIdentity {
        assert_eq!(
            self.validate_staged_table(&staged),
            Ok(()),
            "staged table commit became invalid before publication"
        );
        let grant = staged.grant;
        self.roles[staged.slot].record = Some(RoleRecord {
            range: grant.range,
            role: FrameRole::PageTable {
                owner: grant.owner,
                level: grant.level,
                parent: staged.parent,
            },
        });
        TableIdentity {
            role: grant.identity,
            owner: grant.owner,
            level: grant.level,
            physical_start: grant.range.start,
        }
    }

    pub(crate) fn cancel_staged_table(
        &mut self,
        staged: StagedTableCommit,
    ) -> Result<(), GrantTransitionError<TableCandidateGrant>> {
        self.cancel_table_candidate(staged.grant)
    }

    pub(crate) fn validate_table_identity(
        &self,
        table: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        let record = self.record(table.role)?;
        if record.range.start != table.physical_start
            || record.range.page_count() != 1
            || record.role
                != (FrameRole::PageTable {
                    owner: table.owner,
                    level: table.level,
                    parent: match record.role {
                        FrameRole::PageTable { parent, .. } => parent,
                        _ => None,
                    },
                })
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }

    pub(crate) fn table_identity(
        &self,
        owner: TableOwnerKey,
        level: TableLevel,
        physical_start: u64,
    ) -> Result<TableIdentity, FrameRoleError> {
        self.validate_owner(owner)?;
        let (slot, _) = self
            .roles
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| entry.record.map(|record| (slot, record)))
            .find(|(_, record)| {
                record.range.start == physical_start
                    && record.range.page_count() == 1
                    && matches!(
                        record.role,
                        FrameRole::PageTable {
                            owner: record_owner,
                            level: record_level,
                            ..
                        } if record_owner == owner && record_level == level
                    )
            })
            .ok_or(FrameRoleError::WrongRole)?;
        Ok(TableIdentity {
            role: self.identity(slot, self.roles[slot].generation)?,
            owner,
            level,
            physical_start,
        })
    }

    pub(crate) fn validate_table_child(
        &self,
        parent: TableIdentity,
        child: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        self.validate_table_identity(parent)?;
        self.validate_table_identity(child)?;
        if parent.owner != child.owner || parent.level.child() != Some(child.level) {
            return Err(FrameRoleError::InvalidTableParent);
        }
        let child_record = self.record(child.role)?;
        if !matches!(
            child_record.role,
            FrameRole::PageTable {
                parent: Some(parent_role),
                ..
            } if parent_role == parent.role
        ) {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(())
    }

    /// Imports one transition-table or kernel-image range which has already
    /// been excluded from the allocator.
    ///
    /// # Safety
    ///
    /// The caller must have validated the range's boot provenance, role, and
    /// lifetime against the copied handoff and live architecture state.
    #[allow(
        unsafe_code,
        reason = "external boot provenance cannot be derived from allocator state alone"
    )]
    pub(crate) unsafe fn import_external(
        &mut self,
        range: PhysicalRange,
        role: ExternalFrameRole,
    ) -> Result<FrameRoleIdentity, FrameRoleError> {
        let pages = self.validate_external_page_range(range)?;
        let identity = self.insert_role(pages, FrameRole::External(role))?;
        Ok(identity)
    }

    /// Validates the exact three kernel image ranges and reserves registry
    /// slots without changing role state. The caller retains an unchanged
    /// manager on every error.
    ///
    /// # Safety
    ///
    /// The supplied ranges and segment labels must come from the live-attested
    /// loader root and exact linker bounds, with firmware already exited and
    /// the physical storage retained through the pending CR3 switch.
    #[allow(
        unsafe_code,
        reason = "kernel image provenance is established by the live transition graph"
    )]
    pub(crate) unsafe fn stage_kernel_image_roles(
        &self,
        declarations: [(PhysicalRange, KernelImageSegment); 3],
    ) -> Result<StagedKernelImageRoles, FrameRoleError> {
        let mut ranges = [PageRange::empty(); 3];
        let mut segments = [KernelImageSegment::Text; 3];
        for (index, (range, segment)) in declarations.into_iter().enumerate() {
            if segments[..index].contains(&segment) {
                return Err(FrameRoleError::WrongRole);
            }
            ranges[index] = self.validate_external_page_range(range)?;
            segments[index] = segment;
            if ranges[..index]
                .iter()
                .any(|existing| existing.overlaps(ranges[index]))
            {
                return Err(FrameRoleError::Overlap);
            }
        }
        if !segments.contains(&KernelImageSegment::Text)
            || !segments.contains(&KernelImageSegment::ReadOnlyData)
            || !segments.contains(&KernelImageSegment::WritableData)
        {
            return Err(FrameRoleError::WrongRole);
        }

        let mut slots = [usize::MAX; 3];
        let mut generations = [0_u32; 3];
        let mut identities = [FrameRoleIdentity::EMPTY; 3];
        let mut selected = 0;
        for (slot, role) in self.roles.iter().enumerate() {
            if role.record.is_some() {
                continue;
            }
            let generation = role
                .generation
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(FrameRoleError::GenerationExhausted)?;
            slots[selected] = slot;
            generations[selected] = generation;
            identities[selected] = self.identity(slot, generation)?;
            selected += 1;
            if selected == 3 {
                break;
            }
        }
        if selected != 3 {
            return Err(FrameRoleError::Capacity);
        }
        Ok(StagedKernelImageRoles {
            domain: self.domain,
            ranges,
            segments,
            slots,
            generations,
            identities,
        })
    }

    /// Publishes a previously staged image-role set. The exclusive manager
    /// borrow prevents intervening mutation, so this phase is infallible.
    pub(crate) fn publish_staged_kernel_image(
        &mut self,
        staged: StagedKernelImageRoles,
    ) -> KernelImageRoleSet {
        assert_eq!(
            staged.domain, self.domain,
            "staged kernel image roles belong to another manager"
        );
        assert!(
            staged.segments.contains(&KernelImageSegment::Text)
                && staged.segments.contains(&KernelImageSegment::ReadOnlyData)
                && staged.segments.contains(&KernelImageSegment::WritableData),
            "staged kernel image segment set changed before publication"
        );
        for index in 0..3 {
            assert!(
                staged.slots[index] < ROLE_CAPACITY
                    && !staged.slots[..index].contains(&staged.slots[index])
                    && !staged.ranges[..index]
                        .iter()
                        .any(|range| range.overlaps(staged.ranges[index]))
                    && self.validate_external_pages(staged.ranges[index]).is_ok()
                    && self.identity(staged.slots[index], staged.generations[index])
                        == Ok(staged.identities[index])
                    && staged.identities[index].domain == self.domain
                    && self.roles[staged.slots[index]].record.is_none()
                    && self.roles[staged.slots[index]]
                        .generation
                        .checked_add(1)
                        .is_some_and(|generation| generation == staged.generations[index]),
                "staged kernel image role changed before publication"
            );
        }
        for index in 0..3 {
            self.roles[staged.slots[index]] = RoleSlot {
                generation: staged.generations[index],
                record: Some(RoleRecord {
                    range: staged.ranges[index],
                    role: FrameRole::External(ExternalFrameRole::KernelImage {
                        segment: staged.segments[index],
                    }),
                }),
            };
        }
        KernelImageRoleSet {
            _identities: staged.identities,
            ranges: staged.ranges,
            segments: staged.segments,
        }
    }

    /// Atomically imports the complete live-attested transition-table set.
    ///
    /// Every range, overlap, capacity, generation, and identity check finishes
    /// before the first registry slot changes. Failure therefore imports none
    /// of the supplied frames.
    ///
    /// # Safety
    ///
    /// The caller must have consumed a one-shot live transition attestation
    /// proving that `frames` is the exact, strictly ascending set of retained
    /// loader table frames for the current root. The accepted loader contract
    /// supplies their boot provenance and allocator exclusion.
    #[allow(
        unsafe_code,
        reason = "external transition-table provenance is established by the one-shot architecture attestation"
    )]
    pub(crate) unsafe fn import_transition_tables<const CAPACITY: usize>(
        &mut self,
        frames: &[u64],
    ) -> Result<TransitionTableRoleSet<CAPACITY>, FrameRoleError> {
        if frames.is_empty() || frames.len() > CAPACITY {
            return Err(FrameRoleError::Capacity);
        }

        let mut ranges = [PageRange::empty(); CAPACITY];
        let mut slots = [usize::MAX; CAPACITY];
        let mut generations = [0_u32; CAPACITY];
        let mut table_indices = [0_u32; CAPACITY];

        for (index, &frame) in frames.iter().enumerate() {
            if index != 0 && frames[index - 1] >= frame {
                return Err(FrameRoleError::Overlap);
            }
            let range = PageRange::from_page_count(frame, 1, self.allocator.physical_limit())?;
            ranges[index] = self.validate_external_pages(range)?;
            table_indices[index] = u32::try_from(index).map_err(|_| FrameRoleError::Capacity)?;
        }

        let mut selected = 0;
        for (slot, role) in self.roles.iter().enumerate() {
            if role.record.is_some() {
                continue;
            }
            let generation = role
                .generation
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(FrameRoleError::GenerationExhausted)?;
            slots[selected] = slot;
            generations[selected] = generation;
            selected += 1;
            if selected == frames.len() {
                break;
            }
        }
        if selected != frames.len() {
            return Err(FrameRoleError::Capacity);
        }

        for index in 0..frames.len() {
            self.roles[slots[index]] = RoleSlot {
                generation: generations[index],
                record: Some(RoleRecord {
                    range: ranges[index],
                    role: FrameRole::External(ExternalFrameRole::TransitionTable {
                        table_index: table_indices[index],
                    }),
                }),
            };
        }
        Ok(TransitionTableRoleSet {
            _domain: self.domain,
            count: frames.len(),
            _capacity: core::marker::PhantomData,
        })
    }

    /// Imports immutable module pages as typed read-only object backing.
    ///
    /// # Safety
    ///
    /// The caller must have validated the module reservation, immutable
    /// lifetime, initialized tail bytes, and exclusion from allocator ranges.
    #[allow(
        unsafe_code,
        reason = "immutable boot-module provenance is established by the boot handoff boundary"
    )]
    pub(crate) unsafe fn import_immutable_module(
        &mut self,
        range: PhysicalRange,
        module_index: u32,
    ) -> Result<ObjectBackingGrant, FrameRoleError> {
        let pages = self.validate_immutable_module_range(range)?;
        let identity =
            self.insert_role(pages, FrameRole::ExternalImmutableModule { module_index })?;
        Ok(ObjectBackingGrant {
            identity: BackingIdentity(identity),
            range: pages,
            kind: ObjectBackingKind::ImmutableModule { module_index },
        })
    }

    pub(crate) fn cancel_allocation(
        &mut self,
        grant: AllocationGrant,
    ) -> Result<(), GrantTransitionError<AllocationGrant>> {
        if let Err(error) = self.cancel(
            grant.identity,
            grant.range,
            FrameRole::AllocatedUninitialized,
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    pub(crate) fn cancel_zeroed(
        &mut self,
        grant: ZeroedGrant,
    ) -> Result<(), GrantTransitionError<ZeroedGrant>> {
        if let Err(error) = self.cancel(grant.identity, grant.range, FrameRole::Zeroed) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    pub(crate) fn cancel_object_backing(
        &mut self,
        grant: ObjectBackingGrant,
    ) -> Result<(), GrantTransitionError<ObjectBackingGrant>> {
        let result = match grant.kind {
            ObjectBackingKind::AllocatorOwned => self.cancel(
                grant.identity.0,
                grant.range,
                FrameRole::ObjectBacking(grant.kind),
            ),
            ObjectBackingKind::ImmutableModule { .. } => Err(FrameRoleError::WrongRole),
        };
        if let Err(error) = result {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    pub(crate) fn cancel_table_candidate(
        &mut self,
        grant: TableCandidateGrant,
    ) -> Result<(), GrantTransitionError<TableCandidateGrant>> {
        if let Err(error) = self.cancel(
            grant.identity,
            grant.range,
            FrameRole::TableCandidate {
                owner: grant.owner,
                level: grant.level,
            },
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    pub(crate) fn validate_object_backing(
        &self,
        backing: BackingIdentity,
        physical_start: u64,
        byte_len: u64,
        writable: bool,
    ) -> Result<(), FrameRoleError> {
        let range = PageRange::from_page_count(
            physical_start,
            byte_len
                .checked_div(BASE_PAGE_SIZE)
                .filter(|_| byte_len.is_multiple_of(BASE_PAGE_SIZE))
                .ok_or(FrameRoleError::WrongRole)?,
            self.allocator.physical_limit(),
        )?;
        let record = self.record(backing.0)?;
        if !record.range.contains(range) {
            return Err(FrameRoleError::WrongRole);
        }
        match record.role {
            FrameRole::ObjectBacking(ObjectBackingKind::AllocatorOwned) => Ok(()),
            FrameRole::ExternalImmutableModule { .. } if writable => {
                Err(FrameRoleError::ReadOnlyBacking)
            }
            FrameRole::ExternalImmutableModule { .. } => Ok(()),
            _ => Err(FrameRoleError::WrongRole),
        }
    }

    /// Confirms that one exact base page belongs to the boot-authenticated
    /// kernel image segment whose permissions C2 is about to retain.
    pub(crate) fn validate_kernel_image_page(
        &self,
        physical_start: u64,
        segment: KernelImageSegment,
    ) -> Result<(), FrameRoleError> {
        let page = PageRange::from_page_count(physical_start, 1, self.allocator.physical_limit())?;
        self.roles
            .iter()
            .filter_map(|slot| slot.record)
            .find(|record| record.range.contains(page))
            .filter(|record| {
                record.role == FrameRole::External(ExternalFrameRole::KernelImage { segment })
            })
            .map(|_| ())
            .ok_or(FrameRoleError::WrongRole)
    }

    pub(crate) fn role(
        &self,
        identity: FrameRoleIdentity,
    ) -> Result<FrameRoleKind, FrameRoleError> {
        Ok(self.record(identity)?.role.kind())
    }

    pub(crate) fn available_frames(&self) -> u64 {
        self.allocator.available_frames()
    }

    pub(crate) fn check_invariants(&self) -> Result<(), FrameRoleError> {
        let mut dynamic_pages = 0_u64;
        for (left_index, left) in self.roles.iter().enumerate() {
            let Some(left) = left.record else {
                continue;
            };
            for right in self.roles[left_index + 1..]
                .iter()
                .filter_map(|slot| slot.record)
            {
                if left.range.overlaps(right.range) {
                    return Err(FrameRoleError::InvariantViolation);
                }
            }
            if left.role.is_dynamic() {
                if !self.allocator.contains_initial(left.range)
                    || self.allocator.overlaps_free(left.range)
                {
                    return Err(FrameRoleError::InvariantViolation);
                }
                dynamic_pages = dynamic_pages
                    .checked_add(left.range.page_count())
                    .ok_or(FrameRoleError::InvariantViolation)?;
            } else if self.allocator.overlaps_initial(left.range) {
                return Err(FrameRoleError::InvariantViolation);
            }
        }
        if self.allocator.available_frames().checked_add(dynamic_pages)
            != Some(self.allocator.initial_frames())
        {
            return Err(FrameRoleError::InvariantViolation);
        }
        Ok(())
    }

    fn transition(
        &mut self,
        identity: FrameRoleIdentity,
        range: PageRange,
        expected: FrameRole,
        replacement: FrameRole,
    ) -> Result<(), FrameRoleError> {
        let slot = self.slot(identity)?;
        let record = self.roles[slot]
            .record
            .ok_or(FrameRoleError::InvalidGrant)?;
        if record.range != range || record.role != expected {
            return Err(FrameRoleError::WrongRole);
        }
        self.roles[slot].record = Some(RoleRecord {
            range,
            role: replacement,
        });
        Ok(())
    }

    fn cancel(
        &mut self,
        identity: FrameRoleIdentity,
        range: PageRange,
        expected: FrameRole,
    ) -> Result<(), FrameRoleError> {
        let slot = self.slot(identity)?;
        let record = self.roles[slot]
            .record
            .ok_or(FrameRoleError::InvalidGrant)?;
        if record.range != range || record.role != expected || !record.role.is_dynamic() {
            return Err(FrameRoleError::WrongRole);
        }
        self.allocator.free_run(range)?;
        self.roles[slot].record = None;
        Ok(())
    }

    fn validate_external_page_range(
        &self,
        range: PhysicalRange,
    ) -> Result<PageRange, FrameRoleError> {
        if !range.physical_start().is_multiple_of(BASE_PAGE_SIZE)
            || !range.byte_len().is_multiple_of(BASE_PAGE_SIZE)
        {
            return Err(FrameRoleError::Physical(
                PhysicalMemoryError::InvalidPageRange,
            ));
        }
        let pages = PageRange::from_page_count(
            range.physical_start(),
            range.byte_len() / BASE_PAGE_SIZE,
            self.allocator.physical_limit(),
        )?;
        self.validate_external_pages(pages)
    }

    fn validate_immutable_module_range(
        &self,
        range: PhysicalRange,
    ) -> Result<PageRange, FrameRoleError> {
        if !range.physical_start().is_multiple_of(BASE_PAGE_SIZE) {
            return Err(FrameRoleError::Physical(
                PhysicalMemoryError::InvalidPageRange,
            ));
        }
        let pages = PageRange::cover(range, self.allocator.physical_limit())?;
        self.validate_external_pages(pages)
    }

    fn validate_external_pages(&self, pages: PageRange) -> Result<PageRange, FrameRoleError> {
        if self.allocator.overlaps_initial(pages) {
            return Err(FrameRoleError::ExternalAllocatorOverlap);
        }
        if self
            .roles
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| record.range.overlaps(pages))
        {
            return Err(FrameRoleError::Overlap);
        }
        Ok(pages)
    }

    fn insert_role(
        &mut self,
        range: PageRange,
        role: FrameRole,
    ) -> Result<FrameRoleIdentity, FrameRoleError> {
        if self
            .roles
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| record.range.overlaps(range))
        {
            return Err(FrameRoleError::Overlap);
        }
        let (slot, generation) = self.next_slot()?;
        let identity = self.identity(slot, generation)?;
        self.roles[slot] = RoleSlot {
            generation,
            record: Some(RoleRecord { range, role }),
        };
        Ok(identity)
    }

    fn next_slot(&self) -> Result<(usize, u32), FrameRoleError> {
        let slot = self
            .roles
            .iter()
            .position(|slot| slot.record.is_none())
            .ok_or(FrameRoleError::Capacity)?;
        let generation = self.roles[slot]
            .generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(FrameRoleError::GenerationExhausted)?;
        Ok((slot, generation))
    }

    fn identity(&self, slot: usize, generation: u32) -> Result<FrameRoleIdentity, FrameRoleError> {
        let slot = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .ok_or(FrameRoleError::Capacity)?;
        Ok(FrameRoleIdentity {
            domain: self.domain,
            raw: (u64::from(generation) << 32) | u64::from(slot),
        })
    }

    fn slot(&self, identity: FrameRoleIdentity) -> Result<usize, FrameRoleError> {
        if identity.domain != self.domain {
            return Err(FrameRoleError::ForeignManager);
        }
        let generation = (identity.raw >> 32) as u32;
        let slot = usize::try_from(
            (identity.raw as u32)
                .checked_sub(1)
                .ok_or(FrameRoleError::InvalidGrant)?,
        )
        .map_err(|_| FrameRoleError::InvalidGrant)?;
        let entry = self.roles.get(slot).ok_or(FrameRoleError::InvalidGrant)?;
        if generation == 0 || entry.generation != generation || entry.record.is_none() {
            return Err(FrameRoleError::InvalidGrant);
        }
        Ok(slot)
    }

    fn record(&self, identity: FrameRoleIdentity) -> Result<RoleRecord, FrameRoleError> {
        let slot = self.slot(identity)?;
        self.roles[slot].record.ok_or(FrameRoleError::InvalidGrant)
    }

    fn validate_owner(&self, owner: TableOwnerKey) -> Result<(), FrameRoleError> {
        if owner.domain != self.domain || owner.raw == 0 || owner.raw >= self.next_table_owner {
            return Err(FrameRoleError::InvalidTableOwner);
        }
        Ok(())
    }

    fn validate_staged_table(&self, staged: &StagedTableCommit) -> Result<(), FrameRoleError> {
        let grant = &staged.grant;
        self.validate_owner(grant.owner)?;
        if self.slot(grant.identity)? != staged.slot
            || self.roles[staged.slot].record
                != Some(RoleRecord {
                    range: grant.range,
                    role: FrameRole::TableCandidate {
                        owner: grant.owner,
                        level: grant.level,
                    },
                })
        {
            return Err(FrameRoleError::InvalidGrant);
        }

        match (grant.level, staged.parent) {
            (TableLevel::Pml4, None) => {
                if self
                    .roles
                    .iter()
                    .enumerate()
                    .filter(|(slot, _)| *slot != staged.slot)
                    .filter_map(|(_, slot)| slot.record)
                    .any(|record| {
                        matches!(
                            record.role,
                            FrameRole::PageTable {
                                owner,
                                level: TableLevel::Pml4,
                                ..
                            } | FrameRole::TableCandidate {
                                owner,
                                level: TableLevel::Pml4,
                            } if owner == grant.owner
                        )
                    })
                {
                    return Err(FrameRoleError::DuplicateTableRoot);
                }
            }
            (TableLevel::Pml4, Some(_)) | (_, None) => {
                return Err(FrameRoleError::InvalidTableParent);
            }
            (level, Some(parent)) => {
                if parent == grant.identity {
                    return Err(FrameRoleError::InvalidTableParent);
                }
                let parent = self.record(parent)?;
                let valid_parent = match parent.role {
                    FrameRole::PageTable {
                        owner,
                        level: parent_level,
                        ..
                    } => owner == grant.owner && parent_level.child() == Some(level),
                    _ => false,
                };
                if !valid_parent {
                    return Err(FrameRoleError::InvalidTableParent);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "the synthetic model helper attests zeroing without dereferencing physical memory"
)]
pub(crate) fn synthetic_allocator_backing(
    physical_start: u64,
    page_count: u64,
) -> ObjectBackingGrant {
    use super::physical::PhysicalAddressLimit;

    let limit = PhysicalAddressLimit::new(1_u64 << 40).expect("test physical limit is valid");
    let candidate = PageRange::from_page_count(physical_start, page_count, limit)
        .expect("test backing range is valid");
    let allocator = PhysicalFrameAllocator::<1>::from_candidates(&[candidate], limit, [])
        .expect("test allocator initializes");
    let mut roles =
        FrameRoleManager::<1, 1>::new(allocator).expect("test role manager initializes");
    let allocation = roles.allocate(page_count).expect("test backing allocates");
    // SAFETY: host model tests never dereference synthetic physical memory;
    // the helper exists only to exercise typed ownership consumption.
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.expect("test backing is zeroed");
    roles
        .assign_object_backing(zeroed)
        .expect("test object backing role commits")
}

#[cfg(test)]
pub(crate) fn synthetic_frame_role_manager<
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    physical_start: u64,
    page_count: u64,
) -> FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY> {
    use super::physical::PhysicalAddressLimit;

    let limit = PhysicalAddressLimit::new(1_u64 << 40).expect("test physical limit is valid");
    let candidate = PageRange::from_page_count(physical_start, page_count, limit)
        .expect("test allocator range is valid");
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, [])
        .expect("test allocator initializes");
    FrameRoleManager::new(allocator).expect("test role manager initializes")
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "the synthetic model helper supplies immutable boot provenance without physical access"
)]
pub(crate) fn synthetic_immutable_module_backing(
    physical_start: u64,
    page_count: u64,
    module_index: u32,
) -> ObjectBackingGrant {
    use super::physical::PhysicalAddressLimit;

    let limit = PhysicalAddressLimit::new(1_u64 << 40).expect("test physical limit is valid");
    let candidate = PageRange::from_page_count(BASE_PAGE_SIZE, 1, limit)
        .expect("test allocator range is valid");
    let allocator = PhysicalFrameAllocator::<1>::from_candidates(&[candidate], limit, [])
        .expect("test allocator initializes");
    let mut roles =
        FrameRoleManager::<1, 1>::new(allocator).expect("test role manager initializes");
    let byte_len = page_count
        .checked_mul(BASE_PAGE_SIZE)
        .expect("test module length is valid");
    let range = PhysicalRange::new(physical_start, byte_len).expect("test module range is valid");
    // SAFETY: this is a metadata-only host model with disjoint synthetic
    // immutable-module provenance.
    unsafe { roles.import_immutable_module(range, module_index) }
        .expect("test immutable module role commits")
}

#[cfg(test)]
#[path = "frame_roles/tests.rs"]
mod tests;
