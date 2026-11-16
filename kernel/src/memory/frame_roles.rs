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
use super::growable::GrowableStore;
use super::physical::{
    BASE_PAGE_SIZE, BuddyStorage, FreeLink, PageRange, PhysicalFrameAllocator, PhysicalMemoryError,
    PhysicalRange,
};

#[path = "frame_roles/chain.rs"]
mod chain;
#[path = "frame_roles/index.rs"]
mod index;
#[path = "frame_roles/manager.rs"]
mod manager;
#[path = "frame_roles/slot.rs"]
mod slot;
use chain::ChainState;
#[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
pub(crate) use index::OnDemandCommit;
pub(crate) use index::{INDEX_FANOUT, INDEX_MAX_PAGES, IndexMemory};
use index::{IndexEntryLink, IndexRootLink};
#[cfg(test)]
#[path = "frame_roles/test_support.rs"]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::{
    synthetic_allocator_backing, synthetic_device_mmio_backing, synthetic_frame_role_manager,
    synthetic_immutable_module_backing,
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
    /// The caller could not initialize a page of a new backing.
    InitializationFailed,
    /// The page lies in an on-demand backing but has no frame yet (DW2 M6
    /// §8.3).
    Absent,
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

/// Move-only role-manager proof that one committed PML4 has no owned child
/// tables at the preflight point. Architecture teardown retains the exclusive
/// manager borrow, retires residency, then consumes this proof exactly once.
#[must_use = "an empty-root proof must be consumed only after architecture retirement"]
pub(crate) struct EmptyTableRootGrant {
    root: TableIdentity,
}

/// Move-only preflight state for one exact owned page-table hierarchy.
///
/// Architecture teardown observes every reachable low-half table top-down.
/// The role manager marks each observed slot with this proof's epoch, so a
/// slot seen twice is an alias, and counts them; no array sized by the role
/// table is needed (DW2 M2 §5.3). The proof is bound to the manager's role
/// version: any role change in between invalidates it.
#[must_use = "an empty hierarchy candidate must be finished or abandoned"]
pub(crate) struct EmptyTableHierarchyCandidate {
    root: TableIdentity,
    epoch: u64,
    version: u64,
    observed: u32,
}

/// Move-only proof that every committed table owned by one PML4 was observed
/// in an empty, exact-parent architecture walk: the observed count equals the
/// root's count of committed descendant tables.
#[must_use = "an empty hierarchy proof must be consumed only after architecture retirement"]
pub(crate) struct EmptyTableHierarchyGrant {
    root: TableIdentity,
    epoch: u64,
    version: u64,
    remaining: u32,
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
    ImmutableModule {
        module_index: u32,
    },
    /// One admitted PCI memory BAR: device registers outside the allocator,
    /// never RAM, mapped uncached and never executable.
    DeviceMmio,
    /// Allocator pages given on first touch through a per-object index
    /// (DW2 M6 §8.3).
    OnDemand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelImageSegment {
    Text,
    ReadOnlyData,
    WritableData,
}

/// Architecture-owned dynamic storage whose contents are initialized outside
/// the generic object and page-table pipelines and then retained for the
/// kernel lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArchitectureBootstrapKind {
    /// The single low physical page containing the x86 AP startup image.
    X86ApTrampoline,
    /// One frame of the Intel VT-d table pool: the root table, the bus-0
    /// context table, or a second-level table of some function's DMA domain.
    /// The pool keeps its frames for the life of the machine and reaches
    /// them through the direct map, flushing each line it touches.
    X86VtdTable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExternalFrameRole {
    TransitionTable { table_index: u32 },
    KernelImage { segment: KernelImageSegment },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameRoleKind {
    /// A fresh run whose contents are whatever its last owner left: freed
    /// page tables keep their entries (DW2 M2 §5.3). Every consumer zeroes
    /// or fully writes it before use.
    AllocatedUninitialized,
    Zeroed,
    /// One run of a backing allocated but not yet zeroed (DW2 M3).
    BackingAllocated,
    ObjectBacking(ObjectBackingKind),
    ArchitectureBootstrap(ArchitectureBootstrapKind),
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
    ExternalDeviceMmio,
    /// The run holding the grown role table itself (DW2 M2 §5.3).
    RoleTableStorage,
    /// A node of an on-demand backing's index below its root (DW2 M6).
    BackingIndexNode,
    /// A committed page of an on-demand backing (DW2 M6).
    OnDemandPage,
}

/// Where one run sits in an allocator-owned object backing (DW2 M3 §6.2).
/// Identities are raw values in this manager's domain; `next` is zero on
/// the last run. The head run has `head` equal to its own identity and
/// `object_page` zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChainLink {
    head: u64,
    object_page: u64,
    next: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameRole {
    AllocatedUninitialized,
    Zeroed,
    /// One run of a backing allocated but not yet zeroed.
    BackingAllocated(ChainLink),
    /// One run of an allocator-owned object backing.
    ObjectBacking(ChainLink),
    ArchitectureBootstrap(ArchitectureBootstrapKind),
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
    ExternalDeviceMmio,
    RoleTableStorage,
    /// The root node of an on-demand backing: the backing's identity.
    IndexRoot(IndexRootLink),
    /// A node of an on-demand backing's index below its root.
    IndexNode(IndexEntryLink),
    /// A committed page of an on-demand backing.
    ObjectPage(IndexEntryLink),
}

impl FrameRole {
    const fn is_dynamic(self) -> bool {
        !matches!(
            self,
            Self::External(_) | Self::ExternalImmutableModule { .. } | Self::ExternalDeviceMmio
        )
    }

    const fn kind(self) -> FrameRoleKind {
        match self {
            Self::AllocatedUninitialized => FrameRoleKind::AllocatedUninitialized,
            Self::Zeroed => FrameRoleKind::Zeroed,
            Self::BackingAllocated(_) => FrameRoleKind::BackingAllocated,
            Self::ObjectBacking(_) => {
                FrameRoleKind::ObjectBacking(ObjectBackingKind::AllocatorOwned)
            }
            Self::ArchitectureBootstrap(kind) => FrameRoleKind::ArchitectureBootstrap(kind),
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
            Self::ExternalDeviceMmio => FrameRoleKind::ExternalDeviceMmio,
            Self::RoleTableStorage => FrameRoleKind::RoleTableStorage,
            Self::IndexRoot(_) => FrameRoleKind::ObjectBacking(ObjectBackingKind::OnDemand),
            Self::IndexNode(_) => FrameRoleKind::BackingIndexNode,
            Self::ObjectPage(_) => FrameRoleKind::OnDemandPage,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RoleRecord {
    range: PageRange,
    role: FrameRole,
}

/// One slot as stored (DW2 §12.3): 48 bytes. Only the accessors in
/// `frame_roles/slot.rs` read or write its fields; the rest of the manager
/// works with the [`SlotView`] they unpack and the [`RoleRecord`] they pack.
#[derive(Clone, Copy)]
#[repr(C)]
struct RoleSlot {
    generation: u32,
    /// The run's pages; 0 if the slot is free.
    pages: u32,
    /// The run's physical start; in a free slot, the next free slot plus one
    /// (0 = none).
    start: u64,
    role: StoredRole,
}

/// A role as stored: 32 bytes. Identities and owners are raw values in this
/// manager's domain. The proof mark and the table count live in the two
/// committed-table variants, the only roles that use them.
#[derive(Clone, Copy)]
enum StoredRole {
    Free,
    AllocatedUninitialized,
    Zeroed,
    BackingAllocated(ChainLink),
    ObjectBacking(ChainLink),
    ArchitectureBootstrap(ArchitectureBootstrapKind),
    /// A PML4 candidate; `next_root` is the next slot of the root list plus
    /// one (0 = none).
    RootCandidate {
        owner: u64,
        next_root: u32,
    },
    TableCandidate {
        owner: u64,
        level: TableLevel,
    },
    /// A committed PML4.
    Root {
        owner: u64,
        mark: u64,
        tables: u32,
        next_root: u32,
    },
    /// A committed table below a PML4; `parent` is its parent's raw identity.
    PageTable {
        owner: u64,
        parent: u64,
        mark: u64,
        tables: u32,
        level: TableLevel,
    },
    External(ExternalFrameRole),
    ExternalImmutableModule {
        module_index: u32,
    },
    ExternalDeviceMmio,
    RoleTableStorage,
    IndexRoot(IndexRootLink),
    IndexNode(IndexEntryLink),
    ObjectPage(IndexEntryLink),
}

const _: () = assert!(core::mem::size_of::<RoleSlot>() == 48);
const _: () = assert!(core::mem::size_of::<StoredRole>() == 32);

const EMPTY_ROLE_SLOT: RoleSlot = RoleSlot {
    generation: 0,
    pages: 0,
    start: 0,
    role: StoredRole::Free,
};

/// One slot unpacked into the types the manager's logic works with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SlotView {
    generation: u32,
    record: Option<RoleRecord>,
    /// On a committed table: the epoch of the last empty-hierarchy proof
    /// that observed it. Zero on any other slot.
    mark: u64,
    /// On a committed PML4: how many committed tables below it its owner
    /// has. On any other committed table: how many committed child tables
    /// name it as their parent (DW2 §10.14 revision 2 item 2), so a table
    /// can be freed alone only once none does. Zero on any other slot.
    tables: u32,
}

/// What a committed table's slot says about it: the questions the page
/// walk and the empty-hierarchy proof ask, read without building a
/// [`FrameRole`]. Owners and parents are raw values in this manager's
/// domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TableFacts {
    start: u64,
    owner: u64,
    level: TableLevel,
    /// The parent's raw identity; 0 on a PML4.
    parent: u64,
    mark: u64,
    tables: u32,
}

/// Which kind of backing head a slot holds: the one question the object
/// paths ask of a head before they walk it (DW2 §12.6), read without
/// building a [`FrameRole`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeadKind {
    ObjectBacking,
    BackingAllocated,
    DeviceMmio,
    ImmutableModule,
    IndexRoot,
    /// Every other role, and a free slot.
    Other,
}

/// What a slot that can be a run of a chain says about it (DW2 §12.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChainFacts {
    range: PageRange,
    source: ChainSource,
}

/// The role a chain run holds: a run of an allocator-owned chain with its
/// link, or an external backing, which is a chain of its one run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainSource {
    /// `BackingAllocated`.
    Allocated(ChainLink),
    /// `ObjectBacking`.
    Backing(ChainLink),
    /// `ExternalImmutableModule`.
    Module,
    /// `ExternalDeviceMmio`.
    Device,
}

/// What a slot holding an index node or a committed on-demand page says
/// about it (DW2 §12.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndexEntryFacts {
    range: PageRange,
    /// True for an index node, false for a committed page.
    node: bool,
    link: IndexEntryLink,
}

/// Allocator pages per role slot the grown table adds beyond the boot table:
/// one per page, so slots cannot run out before pages do, since every run
/// takes one slot and at least one page (DW2 M3 §6.7).
const GROWN_SLOT_PAGES: u64 = 1;

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

/// Linear ownership of one fully initialized architecture bootstrap range.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ArchitectureBootstrapGrant {
    identity: FrameRoleIdentity,
    range: PageRange,
    kind: ArchitectureBootstrapKind,
}

impl ArchitectureBootstrapGrant {
    pub(crate) const fn physical_start(&self) -> u64 {
        self.range.start
    }

    pub(crate) const fn byte_len(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub(crate) const fn kind(&self) -> ArchitectureBootstrapKind {
        self.kind
    }
}

/// Move-only ownership of one object backing: for allocator-owned memory,
/// a chain of runs named by its head run (DW2 M3 §6.2).
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObjectBackingGrant {
    identity: BackingIdentity,
    /// The head run.
    range: PageRange,
    kind: ObjectBackingKind,
    pages: u64,
    runs: u64,
}

impl ObjectBackingGrant {
    pub(crate) const fn identity(&self) -> BackingIdentity {
        self.identity
    }

    /// The head run's start; the whole backing only when it is one run.
    pub(crate) const fn physical_start(&self) -> u64 {
        self.range.start
    }

    /// The whole backing's length.
    pub(crate) const fn byte_len(&self) -> u64 {
        self.pages * BASE_PAGE_SIZE
    }

    pub(crate) const fn run_count(&self) -> u64 {
        self.runs
    }

    pub(crate) const fn kind(&self) -> ObjectBackingKind {
        self.kind
    }
}

/// Move-only ownership of a backing's runs before they are zeroed: the
/// chain [`FrameRoleManager::allocate_backing`] made (DW2 M3 §6.3).
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a backing allocation must be zeroed into a backing or cancelled"]
pub(crate) struct BackingAllocation {
    head: FrameRoleIdentity,
    pages: u64,
    runs: u64,
}

impl BackingAllocation {
    /// The pages allocated.
    pub(crate) const fn pages(&self) -> u64 {
        self.pages
    }

    pub(crate) const fn byte_len(&self) -> u64 {
        self.pages * BASE_PAGE_SIZE
    }

    pub(crate) const fn run_count(&self) -> u64 {
        self.runs
    }
}

/// A place in one backing's chain, kept by a caller that resolves pages in
/// order so each page costs one step instead of a walk from the head (DW2
/// M3 §6.2). It holds no borrow and grants nothing: every step revalidates
/// the run it names, and a stale place restarts from the head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackingCursor {
    head: FrameRoleIdentity,
    run: FrameRoleIdentity,
    run_page: u64,
}

impl BackingCursor {
    pub(crate) const fn new(backing: BackingIdentity) -> Self {
        Self {
            head: backing.0,
            run: backing.0,
            run_page: 0,
        }
    }

    /// The backing this cursor walks.
    pub(crate) const fn backing(&self) -> BackingIdentity {
        BackingIdentity(self.head)
    }

    /// This cursor if it walks `backing`, else a new one at its head.
    pub(crate) fn for_backing(cursor: Option<Self>, backing: BackingIdentity) -> Self {
        cursor
            .filter(|cursor| cursor.head == backing.0)
            .unwrap_or(Self::new(backing))
    }
}

/// One physically contiguous piece of an object range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectSegment {
    /// The run holding the piece.
    pub(crate) run: FrameRoleIdentity,
    pub(crate) object_offset: u64,
    pub(crate) physical_start: u64,
    pub(crate) byte_len: u64,
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
///
/// It starts with `ROLE_CAPACITY` slots and an allocator with `RANGE_CAPACITY`
/// free ranges, held inline. Once the direct map is active,
/// [`Self::adopt_storage`] moves the slots into one run of RAM sized from installed memory, adds an index from each allocator
/// page to the role starting there (DW2 large-memory plan, M2 §5.3), and
/// switches the allocator to a buddy allocator whose per-page metadata lives
/// in the same run (M7 §12.2).
pub(crate) struct FrameRoleManager<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    domain: u64,
    allocator: PhysicalFrameAllocator<RANGE_CAPACITY>,
    roles: GrowableStore<RoleSlot, ROLE_CAPACITY>,
    /// The first free slot plus one (0 = none): the head of the free list
    /// threaded through the free slots' `start`. A slot whose generation is
    /// spent is never returned to it.
    first_free: u32,
    /// The free list's length.
    free_slot_count: usize,
    /// The first slot of PML4 level (a candidate or a committed root) plus
    /// one (0 = none): the head of the root list threaded through those
    /// slots' stored roles.
    first_root: u32,
    /// After growth: for each allocator page, in initial-range order, one
    /// plus the slot of the dynamic role starting at that page, or zero.
    starts: Option<&'static mut [u32]>,
    next_table_owner: u64,
    next_epoch: u64,
    /// Changes whenever any role record changes; binds hierarchy proofs.
    version: u64,
    /// Access to on-demand index pages (DW2 M6 §8.3); none until set.
    index_memory: Option<&'static dyn IndexMemory>,
}

/// Where each part of the grown role table lies in its run, in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RoleTableLayout {
    slots: usize,
    starts_offset: usize,
    starts: usize,
    links_offset: usize,
    bases_offset: usize,
    bases: usize,
    hints_offset: usize,
    hints: usize,
    tags_offset: usize,
    bytes: u64,
}

impl RoleTableLayout {
    /// Pages the run needs.
    pub(crate) const fn page_count(&self) -> u64 {
        self.bytes.div_ceil(BASE_PAGE_SIZE)
    }

    /// Role slots the grown table holds.
    pub(crate) const fn slot_count(&self) -> usize {
        self.slots
    }
}

/// Resolves one page of an object backing to its physical address, for a
/// caller that maps pages one at a time onto another address space (DMA).
pub(crate) trait ObjectPages {
    /// The physical page at `object_offset` of the backing `cursor` walks,
    /// or `None` when the backing does not hold that page or refuses a
    /// writable use.
    fn object_page(
        &self,
        cursor: &mut BackingCursor,
        object_offset: u64,
        writable: bool,
    ) -> Option<u64>;
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> ObjectPages
    for FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn object_page(
        &self,
        cursor: &mut BackingCursor,
        object_offset: u64,
        writable: bool,
    ) -> Option<u64> {
        self.resolve_at(cursor, object_offset, writable)
            .ok()
            .map(|page| page.physical_start)
    }
}

#[cfg(test)]
#[path = "frame_roles/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "frame_roles/grown_tests.rs"]
mod grown_tests;

#[cfg(test)]
#[path = "frame_roles/slot_tests.rs"]
mod slot_tests;
