//! Linear activation of one validated, inactive Deepwyrm page-table root.
//!
//! Preparation is the only fallible phase. It retains both the live-transition
//! handoff and the target backend on failure. A prepared activation owns all
//! authority needed for one infallible CR3 publication, after which the
//! transition handoff is consumed and cannot be recovered.

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
use crate::memory::boot_map::{BootstrapMemoryWitness, KernelImageBoundaryError};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use crate::memory::frame_roles::TableOwnerKey;
use crate::memory::frame_roles::{
    FrameRoleError, FrameRoleManager, KernelImageRoleSet, KernelImageSegment,
    StagedKernelImageRoles, TableIdentity, TableLevel,
};
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
use crate::memory::physical::PhysicalRange;

use super::super::VirtualPage;
use super::super::journal::{
    AtomicPageTableTarget, JournalWrite, target_seal as journal_target_seal,
};
use super::super::{
    ACCESSED, AddressError, CACHE_DISABLE, DIRTY, FrameAddress, GLOBAL, HUGE, NO_EXECUTE,
    PAGE_SIZE, PERMITTED_ENTRY_FLAGS, PRESENT, PageTableRoot, PagingCapabilities, SOFTWARE_HIGH,
    SOFTWARE_LOW, USER, WRITABLE, WRITE_THROUGH,
};
use super::private::TransitionActivationHandoff;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::private::{
    LiveTransitionError, LiveTransitionMapper, TransitionActivationAccessError,
    TransitionZeroError, claim_live_transition_mapper,
};

const ENTRY_COUNT: usize = 512;
const MAX_DEEP_TABLE_FRAMES: usize = 256;
const ADDRESS_OFFSET_MASK: u64 = PAGE_SIZE - 1;
const HARDWARE_MUTABLE: u64 = ACCESSED | DIRTY;
const MIN_ACTIVATION_STACK_HEADROOM: u64 = PAGE_SIZE;
const DISALLOWED_COMMON: u64 =
    USER | WRITE_THROUGH | CACHE_DISABLE | HUGE | GLOBAL | SOFTWARE_LOW | SOFTWARE_HIGH;

#[derive(Clone, Copy)]
pub(super) struct DeepScratchBinding {
    window_page: u64,
    control_page: u64,
    pt: TableIdentity,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
struct BuildEdge {
    parent: TableIdentity,
    index: usize,
    child: TableIdentity,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct BuildWorkspace(core::cell::UnsafeCell<[Option<BuildEdge>; MAX_DEEP_TABLE_FRAMES]>);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl BuildWorkspace {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([None; MAX_DEEP_TABLE_FRAMES]))
    }
}

// SAFETY: the sole unsafe bootstrap activation session owns this workspace;
// APs are offline and C1's atomic claim excludes a second initializer.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one-shot BSP activation serializes the static graph-build workspace"
)]
unsafe impl Sync for BuildWorkspace {}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BUILD_WORKSPACE: BuildWorkspace = BuildWorkspace::new();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DeepRootBuildError {
    Capacity,
    InvalidKernelLayout,
    MappingMismatch,
    BootBoundary(KernelImageBoundaryError),
    FrameRole(FrameRoleError),
    Transition,
    Root(AddressError),
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct DeepRootBuildFailure {
    error: DeepRootBuildError,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl DeepRootBuildFailure {
    pub(crate) const fn error(&self) -> &DeepRootBuildError {
        &self.error
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActivationCpuState {
    processor_id: u8,
    physical_address_width: u8,
    current_root: FrameAddress,
    cpl: u8,
    paging_enabled: bool,
    long_mode_active: bool,
    four_level_paging: bool,
    no_execute_enabled: bool,
    write_protect_enabled: bool,
    interrupts_enabled: bool,
    pcid_enabled: bool,
    global_pages_enabled: bool,
    smap_enabled: bool,
    access_flag_set: bool,
    pat_supported: bool,
    pat_entry_zero: u8,
    stack_pointer: u64,
    code_selector: u16,
    gdt_base: u64,
    gdt_limit: u16,
    idt_base: u64,
    idt_limit: u16,
    task_register: u16,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ActivationPrepareError<E> {
    FrameRole(FrameRoleError),
    Root(AddressError),
    WrongProcessorState,
    WrongControlState,
    ActiveRootReused,
    InterruptsEnabled,
    PcidEnabled,
    GlobalPagesEnabled,
    Target(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SegmentKind {
    Text,
    ReadOnly,
    Writable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KernelSegment {
    start: u64,
    end: u64,
    kind: SegmentKind,
}

#[derive(Clone, Copy)]
struct ExecutionCarrierFacts {
    stack_bottom: u64,
    stack_top: u64,
    gdt_base: u64,
    gdt_limit: u16,
    idt_base: u64,
    idt_limit: u16,
    tss_base: u64,
    tss_limit: u16,
    code_selector: u16,
    task_register: u16,
}

impl KernelSegment {
    fn contains(self, page: u64) -> bool {
        page >= self.start && page < self.end
    }

    const fn expected_flags(self) -> u64 {
        match self.kind {
            SegmentKind::Text => PRESENT,
            SegmentKind::ReadOnly => PRESENT | NO_EXECUTE,
            SegmentKind::Writable => PRESENT | WRITABLE | NO_EXECUTE,
        }
    }

    const fn frame_role(self) -> KernelImageSegment {
        match self.kind {
            SegmentKind::Text => KernelImageSegment::Text,
            SegmentKind::ReadOnly => KernelImageSegment::ReadOnlyData,
            SegmentKind::Writable => KernelImageSegment::WritableData,
        }
    }
}

trait ActivationGraphAccess {
    type Error;

    fn read_transition(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error>;
    fn read_inactive(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
enum InactiveGraphError<E> {
    Access(E),
    FrameRole(FrameRoleError),
    Capacity,
    InvalidSegmentLayout,
    InvalidEntry,
    DuplicateOrCyclicTable,
    MissingSegmentPage,
    ExtraTable,
    ExtraLeaf,
    MappingMismatch,
    InvalidScratchPath,
}

#[derive(Clone, Copy)]
struct PendingTable {
    identity: TableIdentity,
    level: TableLevel,
    virtual_prefix: u64,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct GraphValidationWorkspace {
    pending: core::cell::UnsafeCell<[Option<PendingTable>; MAX_DEEP_TABLE_FRAMES]>,
    visited: core::cell::UnsafeCell<[u64; MAX_DEEP_TABLE_FRAMES]>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl GraphValidationWorkspace {
    const fn new() -> Self {
        Self {
            pending: core::cell::UnsafeCell::new([None; MAX_DEEP_TABLE_FRAMES]),
            visited: core::cell::UnsafeCell::new([0; MAX_DEEP_TABLE_FRAMES]),
        }
    }
}

// SAFETY: the one-shot activation target owns this workspace with APs offline
// and does not issue references beyond one preflight call.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one-shot BSP activation serializes the static graph-validation workspace"
)]
unsafe impl Sync for GraphValidationWorkspace {}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static GRAPH_VALIDATION_WORKSPACE: GraphValidationWorkspace = GraphValidationWorkspace::new();

fn table_level_depth(level: TableLevel) -> u8 {
    match level {
        TableLevel::Pml4 => 3,
        TableLevel::Pdpt => 2,
        TableLevel::Pd => 1,
        TableLevel::Pt => 0,
    }
}

fn entry_virtual_address(prefix: u64, index: usize, level: u8) -> u64 {
    let shift = 12 + u32::from(level) * 9;
    let address = prefix | ((index as u64) << shift);
    if address & (1_u64 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

fn physical_mask(capabilities: PagingCapabilities) -> u64 {
    (capabilities.physical_limit().exclusive() - 1) & !ADDRESS_OFFSET_MASK
}

fn validate_present_entry(
    entry: u64,
    capabilities: PagingCapabilities,
    leaf: bool,
) -> Result<FrameAddress, ()> {
    if entry & PRESENT == 0
        || entry & !PERMITTED_ENTRY_FLAGS & !physical_mask(capabilities) != 0
        || entry & DISALLOWED_COMMON != 0
        || (!leaf && entry & WRITABLE == 0)
    {
        return Err(());
    }
    let address = entry & physical_mask(capabilities);
    FrameAddress::new(address, capabilities.physical_limit()).map_err(|_| ())
}

fn segment_for_page(segments: &[KernelSegment; 3], page: u64) -> Option<KernelSegment> {
    segments
        .iter()
        .copied()
        .find(|segment| segment.contains(page))
}

fn subtree_is_required(
    virtual_prefix: u64,
    child_level: u8,
    segments: &[KernelSegment; 3],
    scratch_page: u64,
) -> bool {
    let shift = 12 + u32::from(child_level + 1) * 9;
    let key = virtual_prefix >> shift;
    scratch_page >> shift == key
        || segments.iter().any(|segment| {
            let start = segment.start >> shift;
            let end = (segment.end - 1) >> shift;
            key >= start && key <= end
        })
}

fn validate_segment_layout(
    segments: &[KernelSegment; 3],
    scratch: DeepScratchBinding,
) -> Result<(), InactiveGraphError<core::convert::Infallible>> {
    let scratch_page = scratch.window_page;
    if scratch_page & ADDRESS_OFFSET_MASK != 0
        || scratch_page < 0xffff_8000_0000_0000
        || scratch.control_page != scratch_page.checked_add(PAGE_SIZE).unwrap_or(0)
        || scratch.control_page >> 21 != scratch_page >> 21
        || segments.iter().any(|segment| {
            segment.start & ADDRESS_OFFSET_MASK != 0
                || segment.end & ADDRESS_OFFSET_MASK != 0
                || segment.start >= segment.end
                || segment.start < 0xffff_8000_0000_0000
                || segment.contains(scratch_page)
                || segment.contains(scratch.control_page)
        })
        || segments[0].end > segments[1].start
        || segments[1].end > segments[2].start
    {
        return Err(InactiveGraphError::InvalidSegmentLayout);
    }
    Ok(())
}

fn read_entry<A: ActivationGraphAccess>(
    access: &mut A,
    transition: bool,
    table: FrameAddress,
    index: usize,
) -> Result<u64, InactiveGraphError<A::Error>> {
    if transition {
        access.read_transition(table, index)
    } else {
        access.read_inactive(table, index)
    }
    .map_err(InactiveGraphError::Access)
}

fn resolve_leaf<A: ActivationGraphAccess>(
    access: &mut A,
    transition: bool,
    root: FrameAddress,
    page: u64,
    capabilities: PagingCapabilities,
) -> Result<u64, InactiveGraphError<A::Error>> {
    let mut table = root;
    for level in (0..=3).rev() {
        let index = ((page >> (12 + level * 9)) & 0x1ff) as usize;
        let entry = read_entry(access, transition, table, index)?;
        if entry & PRESENT == 0 {
            return Err(InactiveGraphError::MissingSegmentPage);
        }
        table = validate_present_entry(entry, capabilities, level == 0)
            .map_err(|_| InactiveGraphError::InvalidEntry)?;
        if level != 0
            && entry & !(physical_mask(capabilities) | HARDWARE_MUTABLE) != PRESENT | WRITABLE
        {
            return Err(InactiveGraphError::InvalidEntry);
        }
        if level == 0 {
            return Ok(entry);
        }
    }
    unreachable!("four-level walk always returns at the leaf")
}

fn validate_scratch_path<A: ActivationGraphAccess>(
    access: &mut A,
    root: FrameAddress,
    scratch: DeepScratchBinding,
    capabilities: PagingCapabilities,
) -> Result<(), InactiveGraphError<A::Error>> {
    let scratch_page = scratch.window_page;
    let mut table = root;
    for level in (1..=3).rev() {
        let index = ((scratch_page >> (12 + level * 9)) & 0x1ff) as usize;
        let entry = read_entry(access, false, table, index)?;
        table = validate_present_entry(entry, capabilities, false)
            .map_err(|_| InactiveGraphError::InvalidScratchPath)?;
        if entry & !(physical_mask(capabilities) | HARDWARE_MUTABLE) != PRESENT | WRITABLE {
            return Err(InactiveGraphError::InvalidScratchPath);
        }
    }
    let leaf_index = ((scratch_page >> 12) & 0x1ff) as usize;
    if read_entry(access, false, table, leaf_index)? != 0 {
        return Err(InactiveGraphError::InvalidScratchPath);
    }
    if table.address() != scratch.pt.physical_start() {
        return Err(InactiveGraphError::InvalidScratchPath);
    }
    let control_index = ((scratch.control_page >> 12) & 0x1ff) as usize;
    let control = read_entry(access, false, table, control_index)?;
    if control & physical_mask(capabilities) != scratch.pt.physical_start()
        || control & !(physical_mask(capabilities) | HARDWARE_MUTABLE)
            != PRESENT | WRITABLE | NO_EXECUTE
    {
        return Err(InactiveGraphError::InvalidScratchPath);
    }
    Ok(())
}

trait KernelPageRoleValidation {
    fn validate_kernel_page(
        &self,
        physical_start: u64,
        segment: KernelImageSegment,
    ) -> Result<(), FrameRoleError>;
}

impl KernelPageRoleValidation for StagedKernelImageRoles {
    fn validate_kernel_page(
        &self,
        physical_start: u64,
        segment: KernelImageSegment,
    ) -> Result<(), FrameRoleError> {
        self.validate_page(physical_start, segment)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl KernelPageRoleValidation for KernelImageRoleSet {
    fn validate_kernel_page(
        &self,
        physical_start: u64,
        segment: KernelImageSegment,
    ) -> Result<(), FrameRoleError> {
        self.validate_page(physical_start, segment)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the graph verifier keeps each independently authenticated root, role, layout, and workspace input explicit"
)]
fn validate_inactive_graph_with_workspace<
    A: ActivationGraphAccess,
    K: KernelPageRoleValidation,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    access: &mut A,
    roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    kernel_roles: &K,
    root: TableIdentity,
    transition_root: FrameAddress,
    scratch: DeepScratchBinding,
    segments: &[KernelSegment; 3],
    capabilities: PagingCapabilities,
    pending: &mut [Option<PendingTable>; MAX_DEEP_TABLE_FRAMES],
    visited: &mut [u64; MAX_DEEP_TABLE_FRAMES],
) -> Result<(), InactiveGraphError<A::Error>> {
    validate_segment_layout(segments, scratch).map_err(|error| match error {
        InactiveGraphError::InvalidSegmentLayout => InactiveGraphError::InvalidSegmentLayout,
        _ => unreachable!("layout validation has one error"),
    })?;
    let owner = root.owner();
    pending.fill(None);
    visited.fill(0);
    pending[0] = Some(PendingTable {
        identity: root,
        level: TableLevel::Pml4,
        virtual_prefix: 0,
    });
    let mut pending_count = 1;
    let mut cursor = 0;
    let mut visited_count = 0;

    while cursor < pending_count {
        let node = pending[cursor].expect("queued table entry is initialized");
        cursor += 1;
        let frame = FrameAddress::new(
            node.identity.physical_start(),
            capabilities.physical_limit(),
        )
        .map_err(|_| InactiveGraphError::InvalidEntry)?;
        if visited[..visited_count].contains(&frame.address()) {
            return Err(InactiveGraphError::DuplicateOrCyclicTable);
        }
        if visited_count == MAX_DEEP_TABLE_FRAMES {
            return Err(InactiveGraphError::Capacity);
        }
        visited[visited_count] = frame.address();
        visited_count += 1;
        let depth = table_level_depth(node.level);

        for index in 0..ENTRY_COUNT {
            let entry = read_entry(access, false, frame, index)?;
            if entry & PRESENT == 0 {
                if entry != 0 {
                    return Err(InactiveGraphError::InvalidEntry);
                }
                continue;
            }
            let mapped = validate_present_entry(entry, capabilities, depth == 0)
                .map_err(|_| InactiveGraphError::InvalidEntry)?;
            let virtual_page = entry_virtual_address(node.virtual_prefix, index, depth);
            if depth == 0 {
                if virtual_page == scratch.control_page {
                    if mapped.address() != scratch.pt.physical_start()
                        || entry & !(physical_mask(capabilities) | HARDWARE_MUTABLE)
                            != PRESENT | WRITABLE | NO_EXECUTE
                    {
                        return Err(InactiveGraphError::InvalidScratchPath);
                    }
                } else {
                    let segment = segment_for_page(segments, virtual_page)
                        .ok_or(InactiveGraphError::ExtraLeaf)?;
                    if entry & !physical_mask(capabilities) & !HARDWARE_MUTABLE
                        != segment.expected_flags()
                    {
                        return Err(InactiveGraphError::InvalidEntry);
                    }
                }
                continue;
            }
            if entry & !(physical_mask(capabilities) | HARDWARE_MUTABLE) != PRESENT | WRITABLE {
                return Err(InactiveGraphError::InvalidEntry);
            }
            let child_level = node.level.child().ok_or(InactiveGraphError::InvalidEntry)?;
            if !subtree_is_required(virtual_page, depth - 1, segments, scratch.window_page) {
                return Err(InactiveGraphError::ExtraTable);
            }
            let child = roles
                .table_identity(owner, child_level, mapped.address())
                .map_err(InactiveGraphError::FrameRole)?;
            roles
                .validate_table_child(node.identity, child)
                .map_err(InactiveGraphError::FrameRole)?;
            if pending_count == MAX_DEEP_TABLE_FRAMES {
                return Err(InactiveGraphError::Capacity);
            }
            pending[pending_count] = Some(PendingTable {
                identity: child,
                level: child_level,
                virtual_prefix: virtual_page,
            });
            pending_count += 1;
        }
    }

    validate_scratch_path(
        access,
        root_frame(root, capabilities)?,
        scratch,
        capabilities,
    )?;
    for segment in segments {
        let mut page = segment.start;
        while page < segment.end {
            let transition = resolve_leaf(access, true, transition_root, page, capabilities)?;
            let inactive = resolve_leaf(
                access,
                false,
                root_frame(root, capabilities)?,
                page,
                capabilities,
            )?;
            let expected = segment.expected_flags();
            if transition & !physical_mask(capabilities) & !HARDWARE_MUTABLE != expected
                || inactive & !physical_mask(capabilities) & !HARDWARE_MUTABLE != expected
                || transition & physical_mask(capabilities)
                    != inactive & physical_mask(capabilities)
            {
                return Err(InactiveGraphError::MappingMismatch);
            }
            kernel_roles
                .validate_kernel_page(inactive & physical_mask(capabilities), segment.frame_role())
                .map_err(InactiveGraphError::FrameRole)?;
            page += PAGE_SIZE;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "the host wrapper mirrors the production graph-verification boundary"
)]
fn validate_inactive_graph<
    A: ActivationGraphAccess,
    K: KernelPageRoleValidation,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    access: &mut A,
    roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    kernel_roles: &K,
    root: TableIdentity,
    transition_root: FrameAddress,
    scratch: DeepScratchBinding,
    segments: &[KernelSegment; 3],
    capabilities: PagingCapabilities,
) -> Result<(), InactiveGraphError<A::Error>> {
    let mut pending = [None; MAX_DEEP_TABLE_FRAMES];
    let mut visited = [0_u64; MAX_DEEP_TABLE_FRAMES];
    validate_inactive_graph_with_workspace(
        access,
        roles,
        kernel_roles,
        root,
        transition_root,
        scratch,
        segments,
        capabilities,
        &mut pending,
        &mut visited,
    )
}

fn root_frame<E>(
    root: TableIdentity,
    capabilities: PagingCapabilities,
) -> Result<FrameAddress, InactiveGraphError<E>> {
    FrameAddress::new(root.physical_start(), capabilities.physical_limit())
        .map_err(|_| InactiveGraphError::InvalidEntry)
}

struct InactiveDeepRoot {
    root: PageTableRoot,
    identity: TableIdentity,
}

/// Serialized authority for the exact inactive root built through the live C1
/// target. It owns the terminal transition handoff and exclusively borrows the
/// role registry, so no sibling can mutate roles or the graph between C2
/// preflight and activation.
pub(crate) struct InactiveRootAuthority<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
{
    handoff: TransitionActivationHandoff<'a>,
    root: PageTableRoot,
    identity: TableIdentity,
    scratch: DeepScratchBinding,
    kernel_roles: KernelImageRoleSet,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

impl<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>
{
    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free linear failure path must return the unique transition handoff and root authority"
    )]
    pub(super) fn bind(
        handoff: TransitionActivationHandoff<'a>,
        root: PageTableRoot,
        identity: TableIdentity,
        scratch: DeepScratchBinding,
        kernel_roles: KernelImageRoleSet,
        roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    ) -> Result<
        Self,
        (
            FrameRoleError,
            TransitionActivationHandoff<'a>,
            PageTableRoot,
        ),
    > {
        if root.frame().address() != identity.physical_start()
            || root.physical_limit().exclusive() == 0
            || identity.level() != TableLevel::Pml4
            || scratch.pt.level() != TableLevel::Pt
            || scratch.pt.owner() != identity.owner()
            || scratch.control_page != scratch.window_page + PAGE_SIZE
        {
            return Err((FrameRoleError::WrongRole, handoff, root));
        }
        if let Err(error) = roles.validate_table_identity(identity) {
            return Err((error, handoff, root));
        }
        if let Err(error) = roles.validate_table_identity(scratch.pt) {
            return Err((error, handoff, root));
        }
        Ok(Self {
            handoff,
            root,
            identity,
            scratch,
            kernel_roles,
            roles,
            _not_send_sync: core::marker::PhantomData,
        })
    }
}

impl InactiveDeepRoot {
    fn validate(
        root: &PageTableRoot,
        identity: TableIdentity,
        capabilities: PagingCapabilities,
        cpu: ActivationCpuState,
    ) -> Result<(), ActivationPrepareError<core::convert::Infallible>> {
        if identity.level() != TableLevel::Pml4
            || root.frame().address() != identity.physical_start()
            || root.physical_limit() != capabilities.physical_limit()
        {
            return Err(ActivationPrepareError::FrameRole(FrameRoleError::WrongRole));
        }
        if root.frame() == cpu.current_root {
            return Err(ActivationPrepareError::ActiveRootReused);
        }
        if cpu.cpl != 0 {
            return Err(ActivationPrepareError::WrongProcessorState);
        }
        if !cpu.paging_enabled
            || !cpu.long_mode_active
            || !cpu.four_level_paging
            || !cpu.no_execute_enabled
            || !cpu.write_protect_enabled
            || cpu.smap_enabled
            || cpu.access_flag_set
            || !cpu.pat_supported
            || cpu.pat_entry_zero != 6
            || Some(capabilities.physical_limit().exclusive())
                != 1_u64.checked_shl(u32::from(cpu.physical_address_width))
        {
            return Err(ActivationPrepareError::WrongControlState);
        }
        if cpu.interrupts_enabled {
            return Err(ActivationPrepareError::InterruptsEnabled);
        }
        if cpu.pcid_enabled {
            return Err(ActivationPrepareError::PcidEnabled);
        }
        if cpu.global_pages_enabled {
            return Err(ActivationPrepareError::GlobalPagesEnabled);
        }
        Ok(())
    }
}

mod target_seal {
    pub trait Sealed {}
}

/// Architecture backend for the single irreversible C2 publication step.
///
/// # Safety
///
/// Implementations must make `preflight` validate every condition needed to
/// continue executing through `activate`: the complete inactive graph, its
/// frame roles, the current instruction/control/stack mappings, and the
/// Deep-owned scratch path. Once `preflight` succeeds, `activate` must perform
/// exactly one CR3 write, perform no fallible operation, and return only after
/// the new root is usable. PCID and global pages remain disabled in DW0-C2.
#[allow(
    unsafe_code,
    reason = "exactly one architecture CR3 write is the audited C2 commit boundary"
)]
pub(crate) unsafe trait Cr3ActivationTarget<H>: target_seal::Sealed + Sized {
    type Error;
    type Active;

    fn observe(
        &mut self,
        handoff: &mut H,
    ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error>;

    fn preflight(
        &mut self,
        handoff: &mut H,
        root: &PageTableRoot,
        identity: TableIdentity,
    ) -> Result<(), Self::Error>;

    /// Performs the sole irreversible CR3 publication.
    ///
    /// # Safety
    ///
    /// The caller must have completed `preflight` on this exact backend and
    /// root without permitting intervening mutation or CPU-state drift.
    unsafe fn activate(self, handoff: H, root: FrameAddress) -> Self::Active;
}

pub(crate) struct PreparedActivation<H, T: Cr3ActivationTarget<H>> {
    handoff: H,
    target: T,
    inactive: InactiveDeepRoot,
}

pub(crate) struct ActivationPrepareFailure<H, T, E> {
    error: ActivationPrepareError<E>,
    handoff: H,
    target: T,
    root: PageTableRoot,
    identity: TableIdentity,
}

impl<H, T, E> ActivationPrepareFailure<H, T, E> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ActivationPrepareError<E>,
        H,
        T,
        PageTableRoot,
        TableIdentity,
    ) {
        (
            self.error,
            self.handoff,
            self.target,
            self.root,
            self.identity,
        )
    }
}

pub(crate) struct ActiveDeepPaging<A> {
    target: A,
    root: PageTableRoot,
    identity: TableIdentity,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LiveActivationError {
    WrongProcessorState,
    WrongControlState,
    Transition,
    Graph,
    InvalidKernelLayout,
    KernelRoles(FrameRoleError),
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct LiveCr3ActivationTarget<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    kernel_roles: Option<KernelImageRoleSet>,
    scratch: DeepScratchBinding,
    root_identity: Option<TableIdentity>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct LiveActivePagingTarget<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    _kernel_roles: KernelImageRoleSet,
    scratch: ActiveScratchTarget<LiveActiveScratchIo>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

struct ActiveScratchTarget<I> {
    scratch: DeepScratchBinding,
    io: I,
    poisoned: bool,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveActiveTargetError {
    Busy,
    InvalidIndex,
    ReservedScratchEntry,
}

trait ActiveScratchIo {
    fn load(&mut self, address: u64) -> u64;
    fn store(&mut self, address: u64, value: u64);
    fn compare_exchange(&mut self, address: u64, current: u64, new: u64) -> Result<(), u64>;
    fn invalidate(&mut self, virtual_address: u64);
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct LiveActiveScratchIo;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> target_seal::Sealed
    for LiveCr3ActivationTarget<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the authenticated control/window aliases provide aligned atomic PTE access and local invalidation"
)]
impl ActiveScratchIo for LiveActiveScratchIo {
    fn load(&mut self, address: u64) -> u64 {
        unsafe {
            (&*(address as *const core::sync::atomic::AtomicU64))
                .load(core::sync::atomic::Ordering::SeqCst)
        }
    }

    fn store(&mut self, address: u64, value: u64) {
        unsafe {
            (&*(address as *const core::sync::atomic::AtomicU64))
                .store(value, core::sync::atomic::Ordering::SeqCst);
        }
    }

    fn compare_exchange(&mut self, address: u64, current: u64, new: u64) -> Result<(), u64> {
        unsafe { &*(address as *const core::sync::atomic::AtomicU64) }
            .compare_exchange(
                current,
                new,
                core::sync::atomic::Ordering::SeqCst,
                core::sync::atomic::Ordering::SeqCst,
            )
            .map(|_| ())
    }

    fn invalidate(&mut self, virtual_address: u64) {
        unsafe {
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) virtual_address,
                options(nostack, preserves_flags),
            );
        }
    }
}

impl<I: ActiveScratchIo> journal_target_seal::Sealed for ActiveScratchTarget<I> {}

impl<I: ActiveScratchIo> ActiveScratchTarget<I> {
    fn scratch_leaf_index(&self) -> usize {
        ((self.scratch.window_page >> 12) & 0x1ff) as usize
    }

    fn scratch_control_index(&self) -> usize {
        ((self.scratch.control_page >> 12) & 0x1ff) as usize
    }

    fn scratch_leaf_address(&self) -> u64 {
        self.scratch.control_page + (self.scratch_leaf_index() as u64) * 8
    }

    fn restore_scratch_mapping(&mut self, installed: u64) {
        let leaf = self.scratch_leaf_address();
        let mut expected = installed;
        for _ in 0..3 {
            match self.io.compare_exchange(leaf, expected, 0) {
                Ok(()) => {
                    self.io.invalidate(self.scratch.window_page);
                    return;
                }
                Err(observed) if observed & !(ACCESSED | DIRTY) == installed => {
                    expected = observed;
                }
                Err(observed) => {
                    self.poisoned = true;
                    panic!("hostile active scratch leaf drift: observed {observed:#018x}");
                }
            }
        }
        self.poisoned = true;
        panic!("active scratch leaf did not converge after A/D drift");
    }

    #[allow(
        unsafe_code,
        reason = "the active Deep-owned scratch window performs bounded volatile table access and local invlpg"
    )]
    fn access_frame_entry(
        &mut self,
        frame: FrameAddress,
        index: usize,
        replacement: Option<u64>,
    ) -> Result<u64, LiveActiveTargetError> {
        assert!(!self.poisoned, "active Deep scratch mapper is poisoned");
        let (base, installed) = if frame.address() == self.scratch.pt.physical_start() {
            (self.scratch.control_page, None)
        } else {
            let installed = frame.address() | PRESENT | WRITABLE | NO_EXECUTE;
            let leaf = self.scratch_leaf_address();
            if self.io.compare_exchange(leaf, 0, installed).is_err() {
                return Err(LiveActiveTargetError::Busy);
            }
            self.io.invalidate(self.scratch.window_page);
            (self.scratch.window_page, Some(installed))
        };
        let address = base + (index as u64) * 8;
        let result = self.io.load(address);
        if let Some(value) = replacement {
            self.io.store(address, value);
        }
        let Some(installed) = installed else {
            return Ok(result);
        };
        self.restore_scratch_mapping(installed);
        Ok(result)
    }

    #[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
    fn zero_allocator_frame(&mut self, frame: FrameAddress) -> Result<(), LiveActiveTargetError> {
        assert!(!self.poisoned, "active Deep scratch mapper is poisoned");
        if frame.address() == self.scratch.pt.physical_start() {
            return Err(LiveActiveTargetError::ReservedScratchEntry);
        }
        let installed = frame.address() | PRESENT | WRITABLE | NO_EXECUTE;
        let leaf = self.scratch_leaf_address();
        if self.io.compare_exchange(leaf, 0, installed).is_err() {
            return Err(LiveActiveTargetError::Busy);
        }
        self.io.invalidate(self.scratch.window_page);
        for index in 0..ENTRY_COUNT {
            self.io
                .store(self.scratch.window_page + (index as u64) * 8, 0);
        }
        self.restore_scratch_mapping(installed);
        Ok(())
    }

    fn validate_location(
        &self,
        table: FrameAddress,
        index: usize,
    ) -> Result<(), LiveActiveTargetError> {
        if index >= ENTRY_COUNT {
            return Err(LiveActiveTargetError::InvalidIndex);
        }
        if table.address() == self.scratch.pt.physical_start()
            && (index == self.scratch_leaf_index() || index == self.scratch_control_index())
        {
            return Err(LiveActiveTargetError::ReservedScratchEntry);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "aligned active page-table entries are accessed atomically through the authenticated scratch mapping"
    )]
    fn read_location(
        &mut self,
        table: FrameAddress,
        index: usize,
    ) -> Result<u64, LiveActiveTargetError> {
        self.validate_location(table, index)?;
        self.access_frame_entry(table, index, None)
    }

    #[allow(
        unsafe_code,
        reason = "serialized journal publication stores one aligned PTE through the authenticated scratch mapping"
    )]
    fn write_location(
        &mut self,
        table: FrameAddress,
        index: usize,
        value: u64,
    ) -> Result<(), LiveActiveTargetError> {
        self.validate_location(table, index)?;
        self.access_frame_entry(table, index, Some(value))
            .map(|_| ())
    }
}

// SAFETY: this target is linear, root/role bound, and uses the authenticated
// Deep-owned control alias to preflight every access. After its first target
// entry write, any impossible scratch conflict is fail-stop rather than Err.
#[allow(
    unsafe_code,
    reason = "sealed active root publication implements the journal's exact all-or-fail-stop contract"
)]
unsafe impl<I: ActiveScratchIo> AtomicPageTableTarget for ActiveScratchTarget<I> {
    type Error = LiveActiveTargetError;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.read_location(table, index)
    }

    fn apply(
        &mut self,
        writes: &[JournalWrite],
        invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error> {
        for write in writes {
            self.validate_location(write.table(), write.index())?;
            let _ = self.read_location(write.table(), write.index())?;
        }
        if self.io.load(self.scratch_leaf_address()) != 0 {
            return Err(LiveActiveTargetError::Busy);
        }

        let mut wrote = false;
        for write in writes {
            if let Err(error) = self.write_location(write.table(), write.index(), write.value()) {
                if wrote {
                    panic!("active scratch access failed after page-table publication began");
                }
                return Err(error);
            }
            wrote = true;
        }
        for page in invalidations {
            self.io.invalidate(page.address());
        }
        Ok(())
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct LiveGraphAccess<'borrow, 'handoff>(&'borrow mut TransitionActivationHandoff<'handoff>);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl ActivationGraphAccess for LiveGraphAccess<'_, '_> {
    type Error = TransitionActivationAccessError;

    fn read_transition(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.0.read_transition_entry(table, index)
    }

    fn read_inactive(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.0
            .read_inactive_entry(table, index)
            .map_err(TransitionActivationAccessError::Scratch)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn page_aligned_end(end: u64) -> Option<u64> {
    end.checked_add(ADDRESS_OFFSET_MASK)
        .map(|value| value & !ADDRESS_OFFSET_MASK)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined kernel segment bounds are immutable activation facts"
)]
fn live_kernel_segments() -> Result<[KernelSegment; 3], LiveActivationError> {
    unsafe extern "C" {
        static __dw_text_start: u8;
        static __dw_text_end: u8;
        static __dw_rodata_start: u8;
        static __dw_rodata_end: u8;
        static __dw_data_start: u8;
        static __dw_data_end: u8;
    }
    let text_start = core::ptr::addr_of!(__dw_text_start) as u64;
    let text_end = page_aligned_end(core::ptr::addr_of!(__dw_text_end) as u64)
        .ok_or(LiveActivationError::InvalidKernelLayout)?;
    let rodata_start = core::ptr::addr_of!(__dw_rodata_start) as u64;
    let rodata_end = page_aligned_end(core::ptr::addr_of!(__dw_rodata_end) as u64)
        .ok_or(LiveActivationError::InvalidKernelLayout)?;
    let data_start = core::ptr::addr_of!(__dw_data_start) as u64;
    let data_end = page_aligned_end(core::ptr::addr_of!(__dw_data_end) as u64)
        .ok_or(LiveActivationError::InvalidKernelLayout)?;
    Ok([
        KernelSegment {
            start: text_start,
            end: text_end,
            kind: SegmentKind::Text,
        },
        KernelSegment {
            start: rodata_start,
            end: rodata_end,
            kind: SegmentKind::ReadOnly,
        },
        KernelSegment {
            start: data_start,
            end: data_end,
            kind: SegmentKind::Writable,
        },
    ])
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn allocate_owned_table<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mapper: &mut LiveTransitionMapper,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    owner: TableOwnerKey,
    level: TableLevel,
    parent: Option<TableIdentity>,
) -> Result<TableIdentity, DeepRootBuildError> {
    let allocation = roles.allocate(1).map_err(DeepRootBuildError::FrameRole)?;
    let zeroed = mapper
        .zero_allocation(roles, allocation)
        .map_err(|failure| {
            let error = match *failure.error() {
                TransitionZeroError::FrameRole(error) => DeepRootBuildError::FrameRole(error),
                TransitionZeroError::InvalidAllocation | TransitionZeroError::Scratch(_) => {
                    DeepRootBuildError::Transition
                }
            };
            let _retained_allocation = failure.into_grant();
            error
        })?;
    let candidate = roles
        .prepare_table(zeroed, owner, level)
        .map_err(|failure| failure.error())
        .map_err(DeepRootBuildError::FrameRole)?;
    roles
        .commit_table(candidate, parent)
        .map_err(|failure| failure.error())
        .map_err(DeepRootBuildError::FrameRole)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn ensure_leaf_table<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mapper: &mut LiveTransitionMapper,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    owner: TableOwnerKey,
    root: TableIdentity,
    page: u64,
    edges: &mut [Option<BuildEdge>; MAX_DEEP_TABLE_FRAMES],
    edge_count: &mut usize,
) -> Result<TableIdentity, DeepRootBuildError> {
    let mut parent = root;
    for level in (1..=3).rev() {
        let index = ((page >> (12 + level * 9)) & 0x1ff) as usize;
        if let Some(edge) = edges[..*edge_count]
            .iter()
            .flatten()
            .find(|edge| edge.parent == parent && edge.index == index)
            .copied()
        {
            parent = edge.child;
            continue;
        }
        if *edge_count == MAX_DEEP_TABLE_FRAMES - 1 {
            return Err(DeepRootBuildError::Capacity);
        }
        let child_level = parent
            .level()
            .child()
            .ok_or(DeepRootBuildError::MappingMismatch)?;
        let child = allocate_owned_table(mapper, roles, owner, child_level, Some(parent))?;
        mapper
            .write_owned_table_entry(
                roles,
                parent,
                index,
                child.physical_start() | PRESENT | WRITABLE,
            )
            .map_err(|_| DeepRootBuildError::Transition)?;
        edges[*edge_count] = Some(BuildEdge {
            parent,
            index,
            child,
        });
        *edge_count += 1;
        parent = child;
    }
    if parent.level() != TableLevel::Pt {
        return Err(DeepRootBuildError::MappingMismatch);
    }
    Ok(parent)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn map_owned_leaf<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mapper: &mut LiveTransitionMapper,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    owner: TableOwnerKey,
    root: TableIdentity,
    page: u64,
    leaf: u64,
    edges: &mut [Option<BuildEdge>; MAX_DEEP_TABLE_FRAMES],
    edge_count: &mut usize,
) -> Result<TableIdentity, DeepRootBuildError> {
    let pt = ensure_leaf_table(mapper, roles, owner, root, page, edges, edge_count)?;
    let index = ((page >> 12) & 0x1ff) as usize;
    if mapper
        .read_owned_table_entry(roles, pt, index)
        .map_err(|_| DeepRootBuildError::Transition)?
        != 0
    {
        return Err(DeepRootBuildError::MappingMismatch);
    }
    mapper
        .write_owned_table_entry(roles, pt, index, leaf)
        .map_err(|_| DeepRootBuildError::Transition)?;
    Ok(pt)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn derive_kernel_declarations_before_allocation(
    mapper: &mut LiveTransitionMapper,
    segments: &[KernelSegment; 3],
    capabilities: PagingCapabilities,
) -> Result<[(PhysicalRange, KernelImageSegment); 3], DeepRootBuildError> {
    let mut declarations = [
        (
            PhysicalRange::new(PAGE_SIZE, PAGE_SIZE).expect("placeholder range is valid"),
            KernelImageSegment::Text,
        ),
        (
            PhysicalRange::new(PAGE_SIZE, PAGE_SIZE).expect("placeholder range is valid"),
            KernelImageSegment::ReadOnlyData,
        ),
        (
            PhysicalRange::new(PAGE_SIZE, PAGE_SIZE).expect("placeholder range is valid"),
            KernelImageSegment::WritableData,
        ),
    ];
    for (index, segment) in segments.iter().copied().enumerate() {
        let first = mapper
            .resolve_transition_leaf(segment.start)
            .map_err(|_| DeepRootBuildError::Transition)?;
        if first & !physical_mask(capabilities) & !HARDWARE_MUTABLE != segment.expected_flags() {
            return Err(DeepRootBuildError::MappingMismatch);
        }
        let physical_start = first & physical_mask(capabilities);
        let mut page = segment
            .start
            .checked_add(PAGE_SIZE)
            .ok_or(DeepRootBuildError::InvalidKernelLayout)?;
        while page < segment.end {
            let leaf = mapper
                .resolve_transition_leaf(page)
                .map_err(|_| DeepRootBuildError::Transition)?;
            let offset = page - segment.start;
            let expected_physical = physical_start
                .checked_add(offset)
                .ok_or(DeepRootBuildError::InvalidKernelLayout)?;
            if leaf & !physical_mask(capabilities) & !HARDWARE_MUTABLE != segment.expected_flags()
                || leaf & physical_mask(capabilities) != expected_physical
            {
                return Err(DeepRootBuildError::MappingMismatch);
            }
            page = page
                .checked_add(PAGE_SIZE)
                .ok_or(DeepRootBuildError::InvalidKernelLayout)?;
        }
        declarations[index] = (
            PhysicalRange::new(physical_start, segment.end - segment.start)
                .map_err(|_| DeepRootBuildError::InvalidKernelLayout)?,
            segment.frame_role(),
        );
    }
    Ok(declarations)
}

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
fn validate_kernel_boot_boundary(
    witness: BootstrapMemoryWitness<'_>,
    declarations: &[(PhysicalRange, KernelImageSegment); 3],
) -> Result<(), KernelImageBoundaryError> {
    witness.validate_kernel_image_ranges(&declarations.map(|(range, _)| range))
}

/// Builds and serializes the exact first Deep-owned root through C1's linear
/// physical window. Any failure is terminal for the boot attempt: committed
/// table roles are deliberately not reclaimed in DW0-C.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the serialized builder transfers one fully typed inactive PML4 into PageTableRoot"
)]
fn build_and_bind_deep_root<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mut mapper: LiveTransitionMapper<'a>,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    memory_witness: BootstrapMemoryWitness<'_>,
) -> Result<InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>, DeepRootBuildFailure> {
    let result = (|| {
        let segments =
            live_kernel_segments().map_err(|_| DeepRootBuildError::InvalidKernelLayout)?;
        let capabilities = mapper.capabilities();
        if mapper.temporary_virtual_address() & ADDRESS_OFFSET_MASK != 0 {
            return Err(DeepRootBuildError::InvalidKernelLayout);
        }
        let declarations =
            derive_kernel_declarations_before_allocation(&mut mapper, &segments, capabilities)?;
        validate_kernel_boot_boundary(memory_witness, &declarations)
            .map_err(DeepRootBuildError::BootBoundary)?;
        // SAFETY: these exact page ranges were derived from the freshly
        // attested transition root and linker bounds, then proven fully
        // covered by normalized RESERVED records and disjoint from every
        // bootstrap reservation before any role publication or allocation.
        let staged_kernel_roles = unsafe { roles.stage_kernel_image_roles(declarations) }
            .map_err(DeepRootBuildError::FrameRole)?;
        let kernel_roles = roles.publish_staged_kernel_image(staged_kernel_roles);
        let owner = roles
            .create_table_owner()
            .map_err(DeepRootBuildError::FrameRole)?;
        let root_identity =
            allocate_owned_table(&mut mapper, roles, owner, TableLevel::Pml4, None)?;
        let edges = unsafe { &mut *BUILD_WORKSPACE.0.get() };
        for edge in edges.iter_mut() {
            *edge = None;
        }
        let mut edge_count = 0;

        for segment in segments {
            let mut page = segment.start;
            while page < segment.end {
                let transition_leaf = mapper
                    .resolve_transition_leaf(page)
                    .map_err(|_| DeepRootBuildError::Transition)?;
                if transition_leaf & !physical_mask(capabilities) & !HARDWARE_MUTABLE
                    != segment.expected_flags()
                {
                    return Err(DeepRootBuildError::MappingMismatch);
                }
                let physical = transition_leaf & physical_mask(capabilities);
                FrameAddress::new(physical, capabilities.physical_limit())
                    .map_err(DeepRootBuildError::Root)?;
                map_owned_leaf(
                    &mut mapper,
                    roles,
                    owner,
                    root_identity,
                    page,
                    physical | segment.expected_flags(),
                    edges,
                    &mut edge_count,
                )?;
                page = page
                    .checked_add(PAGE_SIZE)
                    .ok_or(DeepRootBuildError::InvalidKernelLayout)?;
            }
        }

        let window_page = mapper.temporary_virtual_address();
        let control_page = window_page
            .checked_add(PAGE_SIZE)
            .ok_or(DeepRootBuildError::InvalidKernelLayout)?;
        if ((window_page >> 12) & 0x1ff) == 0x1ff || window_page >> 21 != control_page >> 21 {
            return Err(DeepRootBuildError::InvalidKernelLayout);
        }
        let scratch_pt = ensure_leaf_table(
            &mut mapper,
            roles,
            owner,
            root_identity,
            window_page,
            edges,
            &mut edge_count,
        )?;
        let window_index = ((window_page >> 12) & 0x1ff) as usize;
        let control_index = ((control_page >> 12) & 0x1ff) as usize;
        if mapper
            .read_owned_table_entry(roles, scratch_pt, window_index)
            .map_err(|_| DeepRootBuildError::Transition)?
            != 0
            || mapper
                .read_owned_table_entry(roles, scratch_pt, control_index)
                .map_err(|_| DeepRootBuildError::Transition)?
                != 0
        {
            return Err(DeepRootBuildError::MappingMismatch);
        }
        mapper
            .write_owned_table_entry(
                roles,
                scratch_pt,
                control_index,
                scratch_pt.physical_start() | PRESENT | WRITABLE | NO_EXECUTE,
            )
            .map_err(|_| DeepRootBuildError::Transition)?;

        // SAFETY: every table is allocator-owned, fully zeroed, typed to this
        // one owner, and reachable only from the still-inactive root built by
        // this serialized C1 mapper.
        let root =
            unsafe { PageTableRoot::from_owned_root(root_identity.physical_start(), capabilities) }
                .map_err(DeepRootBuildError::Root)?;
        Ok((
            root,
            root_identity,
            DeepScratchBinding {
                window_page,
                control_page,
                pt: scratch_pt,
            },
            kernel_roles,
        ))
    })();

    let (root, identity, scratch, kernel_roles) = match result {
        Ok(parts) => parts,
        Err(error) => return Err(DeepRootBuildFailure { error }),
    };
    InactiveRootAuthority::bind(
        mapper.into_activation_handoff(),
        root,
        identity,
        scratch,
        kernel_roles,
        roles,
    )
    .map_err(|(error, _handoff, _)| DeepRootBuildFailure {
        error: DeepRootBuildError::FrameRole(error),
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "C2 reobserves privileged CPU state at the sealed one-shot boundary"
)]
unsafe fn observe_activation_cpu(
    capabilities: PagingCapabilities,
) -> Result<ActivationCpuState, LiveActivationError> {
    use core::arch::asm;
    use core::arch::x86_64::__cpuid;

    let maximum_basic = __cpuid(0).eax;
    let maximum_extended = __cpuid(0x8000_0000).eax;
    if maximum_basic < 1 || maximum_extended < 0x8000_0008 {
        return Err(LiveActivationError::WrongControlState);
    }
    let leaf_one = __cpuid(1);
    let pat_supported = leaf_one.edx & (1 << 16) != 0;
    let physical_address_width = (__cpuid(0x8000_0008).eax & 0xff) as u8;
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    let rflags: u64;
    let stack_pointer: u64;
    let cs: u16;
    let task_register: u16;
    let mut gdtr = [0_u8; 10];
    let mut idtr = [0_u8; 10];
    let efer_low: u32;
    let efer_high: u32;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
        asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        asm!("str {:x}", out(reg) task_register, options(nomem, nostack, preserves_flags));
        asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack, preserves_flags));
        asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") 0xc000_0080_u32,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags),
        );
    }
    let pat_entry_zero = if pat_supported {
        let pat_low: u32;
        let pat_high: u32;
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") 0x277_u32,
                out("eax") pat_low,
                out("edx") pat_high,
                options(nomem, nostack, preserves_flags),
            );
        }
        let _ = pat_high;
        pat_low as u8
    } else {
        0
    };
    let current_root = FrameAddress::new(cr3, capabilities.physical_limit())
        .map_err(|_| LiveActivationError::WrongControlState)?;
    let efer = u64::from(efer_low) | (u64::from(efer_high) << 32);
    let gdt_limit = u16::from_le_bytes(gdtr[..2].try_into().expect("GDTR limit is two bytes"));
    let gdt_base = u64::from_le_bytes(gdtr[2..].try_into().expect("GDTR base is eight bytes"));
    let idt_limit = u16::from_le_bytes(idtr[..2].try_into().expect("IDTR limit is two bytes"));
    let idt_base = u64::from_le_bytes(idtr[2..].try_into().expect("IDTR base is eight bytes"));
    Ok(ActivationCpuState {
        processor_id: (leaf_one.ebx >> 24) as u8,
        physical_address_width,
        current_root,
        cpl: (cs & 3) as u8,
        paging_enabled: cr0 & (1 << 31) != 0,
        long_mode_active: efer & (1 << 10) != 0,
        four_level_paging: cr4 & (1 << 12) == 0,
        no_execute_enabled: efer & (1 << 11) != 0,
        write_protect_enabled: cr0 & (1 << 16) != 0,
        interrupts_enabled: rflags & (1 << 9) != 0,
        pcid_enabled: cr4 & (1 << 17) != 0,
        global_pages_enabled: cr4 & (1 << 7) != 0,
        smap_enabled: cr4 & (1 << 21) != 0,
        access_flag_set: rflags & (1 << 18) != 0,
        pat_supported,
        pat_entry_zero,
        stack_pointer,
        code_selector: cs,
        gdt_base,
        gdt_limit,
        idt_base,
        idt_limit,
        task_register,
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn validate_execution_carriers(
    cpu: ActivationCpuState,
    segments: &[KernelSegment; 3],
) -> Result<(), LiveActivationError> {
    let descriptors = crate::arch::x86_64::early_descriptor_addresses()
        .ok_or(LiveActivationError::WrongControlState)?;
    let (stack_bottom, stack_top) = live_boot_stack_bounds()?;
    let facts = ExecutionCarrierFacts {
        stack_bottom,
        stack_top,
        gdt_base: descriptors.gdt,
        gdt_limit: descriptors.gdt_limit,
        idt_base: descriptors.idt,
        idt_limit: descriptors.idt_limit,
        tss_base: descriptors.tss,
        tss_limit: descriptors.tss_limit,
        code_selector: crate::arch::x86_64::gdt::KERNEL_CODE_SELECTOR.bits(),
        task_register: crate::arch::x86_64::gdt::KERNEL_TSS_SELECTOR.bits(),
    };
    if !execution_carriers_match(cpu, segments, facts) {
        return Err(LiveActivationError::WrongControlState);
    }
    Ok(())
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-owned boot-stack bounds are immutable activation facts"
)]
fn live_boot_stack_bounds() -> Result<(u64, u64), LiveActivationError> {
    unsafe extern "C" {
        static __dw_boot_stack_bottom: u8;
        static __dw_boot_stack_top: u8;
    }
    let bottom = core::ptr::addr_of!(__dw_boot_stack_bottom) as u64;
    let top = core::ptr::addr_of!(__dw_boot_stack_top) as u64;
    if bottom >= top || !bottom.is_multiple_of(PAGE_SIZE) {
        return Err(LiveActivationError::InvalidKernelLayout);
    }
    Ok((bottom, top))
}

fn range_is_retained_writable(writable: KernelSegment, start: u64, inclusive_limit: u16) -> bool {
    start
        .checked_add(u64::from(inclusive_limit) + 1)
        .is_some_and(|end| start >= writable.start && end <= writable.end && start < end)
}

fn execution_carriers_match(
    cpu: ActivationCpuState,
    segments: &[KernelSegment; 3],
    facts: ExecutionCarrierFacts,
) -> bool {
    let Some(writable) = segments
        .iter()
        .find(|segment| segment.kind == SegmentKind::Writable)
    else {
        return false;
    };
    let stack_has_headroom = cpu
        .stack_pointer
        .checked_sub(MIN_ACTIVATION_STACK_HEADROOM)
        .is_some_and(|lowest_push| lowest_push >= facts.stack_bottom)
        && cpu.stack_pointer <= facts.stack_top;
    stack_has_headroom
        && cpu.code_selector == facts.code_selector
        && cpu.gdt_base == facts.gdt_base
        && cpu.gdt_limit == facts.gdt_limit
        && cpu.idt_base == facts.idt_base
        && cpu.idt_limit == facts.idt_limit
        && cpu.task_register == facts.task_register
        && range_is_retained_writable(*writable, facts.gdt_base, facts.gdt_limit)
        && range_is_retained_writable(*writable, facts.idt_base, facts.idt_limit)
        && range_is_retained_writable(*writable, facts.tss_base, facts.tss_limit)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn validate_live_observation(
    cpu: ActivationCpuState,
    handoff: &TransitionActivationHandoff,
) -> Result<(), LiveActivationError> {
    if cpu.processor_id != handoff.processor_id() || cpu.cpl != 0 {
        return Err(LiveActivationError::WrongProcessorState);
    }
    if cpu.current_root != handoff.transition_root()
        || cpu.physical_address_width
            != handoff.capabilities().physical_limit().exclusive().ilog2() as u8
        || !cpu.paging_enabled
        || !cpu.long_mode_active
        || !cpu.four_level_paging
        || !cpu.no_execute_enabled
        || !cpu.write_protect_enabled
        || cpu.interrupts_enabled
        || cpu.pcid_enabled
        || cpu.global_pages_enabled
        || cpu.smap_enabled
        || cpu.access_flag_set
        || !cpu.pat_supported
        || cpu.pat_entry_zero != 6
    {
        return Err(LiveActivationError::WrongControlState);
    }
    Ok(())
}

// SAFETY: the implementation is sealed in the C1 transition authority module.
// It revalidates every recoverable fact before exposing a prepared typestate;
// its commit retires that authority before one CR3 write and has no post-write
// failure or destructor path.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "privileged observation and the sole CR3 write form the audited C2 boundary"
)]
unsafe impl<'a, 'handoff, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    Cr3ActivationTarget<TransitionActivationHandoff<'handoff>>
    for LiveCr3ActivationTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = LiveActivationError;
    type Active = LiveActivePagingTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>;

    fn observe(
        &mut self,
        handoff: &mut TransitionActivationHandoff,
    ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error> {
        let capabilities = handoff.capabilities();
        let cpu = unsafe { observe_activation_cpu(capabilities) }?;
        validate_live_observation(cpu, handoff)?;
        handoff
            .revalidate_temporary_path(cpu.current_root)
            .map_err(|_| LiveActivationError::Transition)?;
        Ok((cpu, capabilities))
    }

    fn preflight(
        &mut self,
        handoff: &mut TransitionActivationHandoff,
        root: &PageTableRoot,
        identity: TableIdentity,
    ) -> Result<(), Self::Error> {
        let kernel_roles = self
            .kernel_roles
            .as_ref()
            .ok_or(LiveActivationError::WrongControlState)?;
        let segments = live_kernel_segments()?;
        let carrier_cpu = unsafe { observe_activation_cpu(handoff.capabilities()) }?;
        validate_live_observation(carrier_cpu, handoff)?;
        validate_execution_carriers(carrier_cpu, &segments)?;
        let capabilities = handoff.capabilities();
        let transition_root = handoff.transition_root();
        let graph_pending = unsafe { &mut *GRAPH_VALIDATION_WORKSPACE.pending.get() };
        let graph_visited = unsafe { &mut *GRAPH_VALIDATION_WORKSPACE.visited.get() };
        validate_inactive_graph_with_workspace(
            &mut LiveGraphAccess(handoff),
            &*self.roles,
            kernel_roles,
            identity,
            transition_root,
            self.scratch,
            &segments,
            capabilities,
            graph_pending,
            graph_visited,
        )
        .map_err(|_| LiveActivationError::Graph)?;
        if root.frame().address() != identity.physical_start() {
            return Err(LiveActivationError::WrongControlState);
        }

        // This is the last recoverable observation after all scratch-window
        // reads. It proves the old root/path/empty leaf were restored before a
        // prepared activation can escape.
        let cpu = unsafe { observe_activation_cpu(capabilities) }?;
        validate_live_observation(cpu, handoff)?;
        validate_execution_carriers(cpu, &segments)?;
        handoff
            .revalidate_temporary_path(cpu.current_root)
            .map_err(|_| LiveActivationError::Transition)?;
        self.root_identity = Some(identity);
        Ok(())
    }

    unsafe fn activate(
        self,
        mut handoff: TransitionActivationHandoff,
        root: FrameAddress,
    ) -> Self::Active {
        // Final drift checks are deliberately fail-stop and occur before the
        // retirement CAS or irreversible CR3 write.
        let capabilities = handoff.capabilities();
        let cpu = unsafe { observe_activation_cpu(capabilities) }
            .expect("C2 CPU state drifted after successful preflight");
        validate_live_observation(cpu, &handoff)
            .expect("C2 processor/control state drifted after successful preflight");
        let segments = live_kernel_segments()
            .expect("C2 linker segment layout drifted after successful preflight");
        validate_execution_carriers(cpu, &segments)
            .expect("C2 stack or descriptor carrier drifted after successful preflight");
        handoff
            .revalidate_temporary_path(cpu.current_root)
            .expect("C2 transition path drifted after successful preflight");
        let kernel_roles = self
            .kernel_roles
            .expect("C2 kernel image roles were not published during preflight");
        let _root_identity = self
            .root_identity
            .expect("C2 root identity was not retained during preflight");
        handoff.retire_before_activation();
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) root.address(),
                options(nostack, preserves_flags),
            );
        }
        LiveActivePagingTarget {
            roles: self.roles,
            _kernel_roles: kernel_roles,
            scratch: ActiveScratchTarget {
                scratch: self.scratch,
                io: LiveActiveScratchIo,
                poisoned: false,
                _not_send_sync: core::marker::PhantomData,
            },
            _not_send_sync: core::marker::PhantomData,
        }
    }
}

impl<A> ActiveDeepPaging<A> {
    pub(crate) const fn root(&self) -> &PageTableRoot {
        &self.root
    }

    pub(crate) const fn identity(&self) -> TableIdentity {
        self.identity
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
struct ActiveRootTestAuthority<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    root: &'a PageTableRoot,
    identity: TableIdentity,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    scratch: &'a mut ActiveScratchTarget<LiveActiveScratchIo>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
struct ActiveWalk {
    entry: u64,
    physical_start: u64,
    user: bool,
    writable: bool,
    executable: bool,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveUserAccessError {
    MissingOrInvalid,
    Permission,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
struct ActiveUserPageAccess<'a, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    authority: &'a mut ActiveRootTestAuthority<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
struct PinnedActiveUserPages<'a, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    authority: &'a mut ActiveRootTestAuthority<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::memory::usercopy::UserPageAccess
    for ActiveUserPageAccess<'_, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = ActiveUserAccessError;
    type Pinned<'a>
        = PinnedActiveUserPages<'a, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
    where
        Self: 'a;

    fn pin(
        &mut self,
        _range: crate::memory::user_range::UserRange,
    ) -> Result<Self::Pinned<'_>, Self::Error> {
        Ok(PinnedActiveUserPages {
            authority: self.authority,
        })
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::memory::usercopy::PinnedUserPages
    for PinnedActiveUserPages<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = ActiveUserAccessError;

    fn preflight(
        &mut self,
        chunk: crate::memory::user_range::UserPageChunk,
    ) -> Result<(), Self::Error> {
        let walk = self
            .authority
            .walk_leaf(chunk.page_start())
            .map_err(|_| ActiveUserAccessError::MissingOrInvalid)?;
        if !walk.user
            || (chunk
                .access()
                .includes(crate::memory::user_range::UserAccess::WRITE)
                && !walk.writable)
            || (chunk
                .access()
                .includes(crate::memory::user_range::UserAccess::EXECUTE)
                && !walk.executable)
        {
            return Err(ActiveUserAccessError::Permission);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the pinned live-root walk proved every source page present and user-readable before this exact copy"
    )]
    fn read_exact(&mut self, range: crate::memory::user_range::UserRange, destination: &mut [u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                range.start() as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
    }

    #[allow(
        unsafe_code,
        reason = "the pinned live-root walk proved every destination page present and user-writable before this exact copy"
    )]
    fn write_exact(&mut self, range: crate::memory::user_range::UserRange, source: &[u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), range.start() as *mut u8, source.len());
        }
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    const TEST_REGION_START: u64 = 0x0000_0000_4000_0000;
    const TEST_REGION_PAGES: u64 = 16;
    const ALIAS_VALUE: u64 = 0x4457_3043_334d_454d;

    #[allow(
        unsafe_code,
        reason = "the active scratch mapper provides the physical zeroing fact consumed by the typed role transition"
    )]
    fn allocate_zeroed(&mut self) -> Result<(crate::memory::frame_roles::ZeroedGrant, u64), u32> {
        let allocation = self.roles.allocate(1).map_err(|_| 0x0101_u32)?;
        let physical_start = allocation.physical_start();
        self.roles
            .validate_allocation(&allocation)
            .map_err(|_| 0x0102_u32)?;
        let frame = FrameAddress::new(allocation.physical_start(), self.root.physical_limit())
            .map_err(|_| 0x0103_u32)?;
        self.scratch
            .zero_allocator_frame(frame)
            .map_err(|_| 0x0104_u32)?;
        // SAFETY: the exact live allocation was exclusively mapped through
        // the active Deep scratch window, every byte was zeroed, and the
        // window was removed and invalidated before this transition.
        unsafe { self.roles.assume_zeroed(allocation) }
            .map(|grant| (grant, physical_start))
            .map_err(|_| 0x0105_u32)
    }

    fn prepare_candidate(
        &mut self,
        level: TableLevel,
    ) -> Result<crate::memory::frame_roles::TableCandidateGrant, u32> {
        let (zeroed, _) = self.allocate_zeroed()?;
        self.roles
            .prepare_table(zeroed, self.identity.owner(), level)
            .map_err(|_| 0x0106_u32)
    }

    fn walk_leaf(&mut self, virtual_address: u64) -> Result<ActiveWalk, u32> {
        let page = VirtualPage::new(virtual_address).map_err(|_| 0x0201_u32)?;
        let user_half = page.is_user_half();
        let mut current = self.identity;
        let mut effective_user = true;
        let mut effective_writable = true;
        let mut effective_executable = true;
        for level in (1..=3).rev() {
            let entry = self
                .scratch
                .read_location(
                    FrameAddress::new(current.physical_start(), self.root.physical_limit())
                        .map_err(|_| 0x0202_u32)?,
                    page.index(level),
                )
                .map_err(|_| 0x0203_u32)?;
            if entry & PRESENT == 0 || entry & HUGE != 0 {
                return Err(0x0204);
            }
            effective_user &= entry & USER != 0;
            effective_writable &= entry & WRITABLE != 0;
            effective_executable &= entry & NO_EXECUTE == 0;
            let child_level = match level {
                3 => TableLevel::Pdpt,
                2 => TableLevel::Pd,
                1 => TableLevel::Pt,
                _ => unreachable!(),
            };
            let physical_start = entry & physical_mask(self.root.capabilities);
            let child = self
                .roles
                .table_identity(self.identity.owner(), child_level, physical_start)
                .map_err(|_| 0x0205_u32)?;
            self.roles
                .validate_table_child(current, child)
                .map_err(|_| 0x0206_u32)?;
            current = child;
        }
        let entry = self
            .scratch
            .read_location(
                FrameAddress::new(current.physical_start(), self.root.physical_limit())
                    .map_err(|_| 0x0207_u32)?,
                page.index(0),
            )
            .map_err(|_| 0x0208_u32)?;
        if entry & PRESENT == 0 || entry & HUGE != 0 {
            return Err(0x0209);
        }
        effective_user &= entry & USER != 0;
        effective_writable &= entry & WRITABLE != 0;
        effective_executable &= entry & NO_EXECUTE == 0;
        if effective_user != user_half {
            return Err(0x020a);
        }
        Ok(ActiveWalk {
            entry,
            physical_start: entry & physical_mask(self.root.capabilities),
            user: effective_user,
            writable: effective_writable,
            executable: effective_executable,
        })
    }

    #[allow(
        unsafe_code,
        reason = "the test-only authority created both model keys for this exact retained active root and uniquely borrowed scratch target"
    )]
    fn bind_test_publisher<'borrow>(
        &'borrow mut self,
        address_space: crate::memory::address_region::AddressSpaceKey,
        region: crate::memory::address_region::RegionKey,
        candidates: &'borrow mut [Option<crate::memory::frame_roles::TableCandidateGrant>; 3],
    ) -> Result<
        super::super::journal::X86AddressSpacePublisher<
            'borrow,
            ActiveScratchTarget<LiveActiveScratchIo>,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            3,
            4,
            1,
        >,
        u32,
    > {
        unsafe {
            super::super::journal::X86AddressSpacePublisher::new(
                address_space,
                region,
                self.root,
                self.identity,
                self.roles,
                self.scratch,
                candidates,
            )
        }
        .map_err(|_| 0x0405_u32)
    }

    fn model_has_exact_single_mapping(
        region: &crate::memory::address_region::AddressRegion<2>,
        objects: &crate::memory::object::MemoryObjectAuthority<1, 2>,
        virtual_start: u64,
        physical_start: u64,
        protection: crate::memory::object::MemoryProtection,
    ) -> bool {
        let mut mappings = region.mappings().iter().flatten();
        mappings.next().is_some_and(|mapping| {
            mapping.virtual_start() == virtual_start
                && mapping.byte_len() == PAGE_SIZE
                && mapping.backing().physical_start() == physical_start
                && mapping.protection() == protection
        }) && mappings.next().is_none()
            && objects.active_lease_count() == 1
    }

    fn model_has_exact_two_mappings(
        region: &crate::memory::address_region::AddressRegion<2>,
        objects: &crate::memory::object::MemoryObjectAuthority<1, 2>,
        first: (u64, crate::memory::object::MemoryProtection),
        second: (u64, crate::memory::object::MemoryProtection),
        physical_start: u64,
    ) -> bool {
        let mappings = region.mappings();
        let Some(first_mapping) = mappings[0] else {
            return false;
        };
        let Some(second_mapping) = mappings[1] else {
            return false;
        };
        first_mapping.virtual_start() == first.0
            && second_mapping.virtual_start() == second.0
            && first_mapping.byte_len() == PAGE_SIZE
            && second_mapping.byte_len() == PAGE_SIZE
            && first_mapping.backing().physical_start() == physical_start
            && second_mapping.backing().physical_start() == physical_start
            && first_mapping.protection() == first.1
            && second_mapping.protection() == second.1
            && mappings[2..].iter().all(Option::is_none)
            && objects.active_lease_count() == 2
    }

    #[allow(
        unsafe_code,
        reason = "the test-only authority locally supplies the future handle-rights proof and binds opaque model keys to this exact active root"
    )]
    fn run_mapped_case(&mut self, test: crate::test_support::BuildGuestTest) -> ! {
        use crate::memory::address_region::AddressSpaceAuthority;
        use crate::memory::object::{MemoryObjectAuthority, MemoryObjectKind, MemoryProtection};

        let first = Self::TEST_REGION_START;
        let (allocation, backing_physical) = self
            .allocate_zeroed()
            .unwrap_or_else(|detail| crate::test_support::complete_fail(detail));
        if backing_physical == first {
            crate::test_support::complete_fail(0x0400);
        }
        let backing = self
            .roles
            .assign_object_backing(allocation)
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0401));
        let mut objects = MemoryObjectAuthority::<1, 2>::new();
        let object = objects
            .grant_backing(
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ_WRITE_EXECUTE,
            )
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0402));

        let mut candidates = [
            Some(
                self.prepare_candidate(TableLevel::Pdpt)
                    .unwrap_or_else(|detail| crate::test_support::complete_fail(detail)),
            ),
            Some(
                self.prepare_candidate(TableLevel::Pd)
                    .unwrap_or_else(|detail| crate::test_support::complete_fail(detail)),
            ),
            Some(
                self.prepare_candidate(TableLevel::Pt)
                    .unwrap_or_else(|detail| crate::test_support::complete_fail(detail)),
            ),
        ];
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 2>::new() };
        let address_space = spaces
            .create_address_space()
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0403));
        let mut region = spaces
            .create_region::<2>(
                address_space,
                Self::TEST_REGION_START,
                Self::TEST_REGION_PAGES * PAGE_SIZE,
            )
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0404));

        // Keep every portable model authority and role-backed object in this
        // terminal frame. The closure may report a scenario result, but the
        // owners cannot be dropped while any published test mapping survives:
        // both completion paths below diverge before this scope can unwind.
        let result = (|| -> Result<(), u32> {
            let authorization = unsafe {
                region.authorize_map(&objects, object, MemoryProtection::READ_WRITE_EXECUTE)
            }
            .map_err(|_| 0x0406_u32)?;
            {
                let mut publisher =
                    self.bind_test_publisher(address_space, region.region_key(), &mut candidates)?;
                region
                    .map(
                        &mut objects,
                        &mut publisher,
                        first,
                        authorization,
                        0,
                        PAGE_SIZE,
                        MemoryProtection::READ_WRITE,
                    )
                    .map_err(|_| 0x0407_u32)?;
            }

            match test {
                crate::test_support::BuildGuestTest::MemoryMapping => (|| -> Result<(), u32> {
                    let walk = self.walk_leaf(first)?;
                    if walk.physical_start != backing_physical
                        || !walk.user
                        || !walk.writable
                        || walk.executable
                        || walk.entry & GLOBAL != 0
                        || !Self::model_has_exact_single_mapping(
                            &region,
                            &objects,
                            first,
                            backing_physical,
                            MemoryProtection::READ_WRITE,
                        )
                    {
                        return Err(0x0410);
                    }
                    self.write_then_read_alias(first, first)?;
                    Ok(())
                })(),
                crate::test_support::BuildGuestTest::MemoryUnmapping => (|| -> Result<(), u32> {
                    self.write_then_read_alias(first, first)?;
                    {
                        let mut publisher = self.bind_test_publisher(
                            address_space,
                            region.region_key(),
                            &mut candidates,
                        )?;
                        region
                            .unmap(&mut objects, &mut publisher, first, PAGE_SIZE)
                            .map_err(|_| 0x0420_u32)?;
                    }
                    if self.walk_leaf(first).is_ok()
                        || !region.mappings().iter().all(Option::is_none)
                        || objects.active_lease_count() != 0
                    {
                        return Err(0x0421);
                    }
                    crate::test_support::expect_terminal_page_fault(
                        first,
                        crate::test_support::ExpectedPageFaultKind::UnmappedSupervisorRead,
                    )
                })(),
                crate::test_support::BuildGuestTest::MemoryPermissions => {
                    (|| -> Result<(), u32> {
                        let initial = self.walk_leaf(first)?;
                        if initial.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ_WRITE,
                            )
                        {
                            return Err(0x042f);
                        }
                        self.write_then_read_alias(first, first)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .protect(
                                    &mut objects,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                )
                                .map_err(|_| 0x0430_u32)?;
                        }
                        let read_only = self.walk_leaf(first)?;
                        if !read_only.user
                            || read_only.writable
                            || read_only.executable
                            || read_only.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ,
                            )
                        {
                            return Err(0x0431);
                        }
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .protect(
                                    &mut objects,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_EXECUTE,
                                )
                                .map_err(|_| 0x0432_u32)?;
                        }
                        let executable = self.walk_leaf(first)?;
                        if !executable.user
                            || executable.writable
                            || !executable.executable
                            || executable.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ_EXECUTE,
                            )
                        {
                            return Err(0x0433);
                        }
                        let before = executable.entry;
                        let rejected = {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region.protect(
                                &mut objects,
                                &mut publisher,
                                first,
                                PAGE_SIZE,
                                MemoryProtection::READ_WRITE_EXECUTE,
                            )
                        };
                        let after_rejected = self.walk_leaf(first)?;
                        if rejected.is_ok()
                            || after_rejected.entry != before
                            || after_rejected.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ_EXECUTE,
                            )
                        {
                            return Err(0x0434);
                        }
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .protect(
                                    &mut objects,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                )
                                .map_err(|_| 0x0435_u32)?;
                        }
                        let read_only = self.walk_leaf(first)?;
                        if !read_only.user
                            || read_only.writable
                            || read_only.executable
                            || read_only.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ,
                            )
                        {
                            return Err(0x0436);
                        }
                        crate::test_support::expect_terminal_page_fault(
                            first,
                            crate::test_support::ExpectedPageFaultKind::WriteProtectedSupervisorWrite,
                        )
                    })()
                }
                crate::test_support::BuildGuestTest::MemoryInvalidPointer => {
                    (|| -> Result<(), u32> {
                        use crate::memory::user_range::{
                            EmptyAddressRule, UserAccess, UserAddressSpace, UserRange,
                            UserRangeError, X86_64_USER_END_EXCLUSIVE,
                        };
                        use crate::memory::usercopy::UserCopyError;

                        let user_space = UserAddressSpace::x86_64_four_level(PAGE_SIZE)
                            .map_err(|_| 0x0437_u32)?;
                        let original_entry = self.walk_leaf(first)?.entry;
                        let original_mappings = *region.mappings();
                        let original_leases = objects.active_lease_count();
                        for access in [UserAccess::READ, UserAccess::WRITE] {
                            if UserRange::new(user_space, 0, 1, 1, access, EmptyAddressRule::Reject)
                                != Err(UserRangeError::NullAddress)
                                || UserRange::new(
                                    user_space,
                                    X86_64_USER_END_EXCLUSIVE,
                                    1,
                                    1,
                                    access,
                                    EmptyAddressRule::Reject,
                                ) != Err(UserRangeError::OutsideUserAddressSpace)
                                || UserRange::new(
                                    user_space,
                                    0xffff_8000_0000_0000,
                                    1,
                                    1,
                                    access,
                                    EmptyAddressRule::Reject,
                                ) != Err(UserRangeError::OutsideUserAddressSpace)
                                || UserRange::new(
                                    user_space,
                                    u64::MAX - 3,
                                    8,
                                    1,
                                    access,
                                    EmptyAddressRule::Reject,
                                ) != Err(UserRangeError::AddressOverflow)
                            {
                                return Err(0x0438);
                            }
                        }
                        if self.walk_leaf(first)?.entry != original_entry
                            || *region.mappings() != original_mappings
                            || objects.active_lease_count() != original_leases
                        {
                            return Err(0x0439);
                        }

                        let probe = first + PAGE_SIZE - 8;
                        let crossing = first + PAGE_SIZE - 4;
                        self.write_then_read_alias(probe, probe)?;
                        if self.walk_leaf(first + PAGE_SIZE).is_ok() {
                            return Err(0x043a);
                        }
                        let read_crossing = UserRange::new(
                            user_space,
                            crossing,
                            8,
                            1,
                            UserAccess::READ,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x043b_u32)?;
                        let mut destination = [0xa5_u8; 8];
                        let destination_before = destination;
                        let mut scratch = [0x5a_u8; 8];
                        let read_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_from_user(
                                &mut access,
                                read_crossing,
                                &mut destination,
                                &mut scratch,
                            )
                        };
                        if !matches!(
                            read_result,
                            Err(UserCopyError::Access(
                                ActiveUserAccessError::MissingOrInvalid
                            ))
                        ) || destination != destination_before
                            || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x043c);
                        }

                        let write_crossing = UserRange::new(
                            user_space,
                            crossing,
                            8,
                            1,
                            UserAccess::WRITE,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x043d_u32)?;
                        let write_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_to_user(
                                &mut access,
                                write_crossing,
                                b"BADWRITE",
                            )
                        };
                        if !matches!(
                            write_result,
                            Err(UserCopyError::Access(
                                ActiveUserAccessError::MissingOrInvalid
                            ))
                        ) || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x043e);
                        }

                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .protect(
                                    &mut objects,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                )
                                .map_err(|_| 0x043f_u32)?;
                        }
                        let read_only = self.walk_leaf(first)?;
                        if !read_only.user || read_only.writable || read_only.executable {
                            return Err(0x0470);
                        }

                        destination.fill(0xa5);
                        scratch.fill(0x5a);
                        let read_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_from_user(
                                &mut access,
                                read_crossing,
                                &mut destination,
                                &mut scratch,
                            )
                        };
                        if !matches!(
                            read_result,
                            Err(UserCopyError::Access(
                                ActiveUserAccessError::MissingOrInvalid
                            ))
                        ) || destination != [0xa5_u8; 8]
                            || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x0471);
                        }

                        let read_exact = UserRange::new(
                            user_space,
                            probe,
                            8,
                            8,
                            UserAccess::READ,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x0472_u32)?;
                        destination.fill(0);
                        scratch.fill(0);
                        {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_from_user(
                                &mut access,
                                read_exact,
                                &mut destination,
                                &mut scratch,
                            )
                            .map_err(|_| 0x0473_u32)?;
                        }
                        if destination != Self::ALIAS_VALUE.to_ne_bytes() {
                            return Err(0x0474);
                        }

                        let write_exact = UserRange::new(
                            user_space,
                            probe,
                            8,
                            8,
                            UserAccess::WRITE,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x0475_u32)?;
                        let write_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_to_user(
                                &mut access,
                                write_exact,
                                b"BADWRITE",
                            )
                        };
                        if !matches!(
                            write_result,
                            Err(UserCopyError::Access(ActiveUserAccessError::Permission))
                        ) || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x0476);
                        }

                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .protect(
                                    &mut objects,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_WRITE,
                                )
                                .map_err(|_| 0x0477_u32)?;
                        }
                        let second = first + PAGE_SIZE;
                        if backing_physical == second {
                            return Err(0x0478);
                        }
                        let authorization = unsafe {
                            region.authorize_map(
                                &objects,
                                object,
                                MemoryProtection::READ_WRITE_EXECUTE,
                            )
                        }
                        .map_err(|_| 0x0479_u32)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .map(
                                    &mut objects,
                                    &mut publisher,
                                    second,
                                    authorization,
                                    0,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_WRITE,
                                )
                                .map_err(|_| 0x047a_u32)?;
                        }
                        self.write_then_read_alias(second, second)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .protect(
                                    &mut objects,
                                    &mut publisher,
                                    second,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                )
                                .map_err(|_| 0x047b_u32)?;
                        }
                        let first_walk = self.walk_leaf(first)?;
                        let second_walk = self.walk_leaf(second)?;
                        if !first_walk.user
                            || !first_walk.writable
                            || first_walk.executable
                            || !second_walk.user
                            || second_walk.writable
                            || second_walk.executable
                            || first_walk.physical_start != backing_physical
                            || second_walk.physical_start != backing_physical
                            || !Self::model_has_exact_two_mappings(
                                &region,
                                &objects,
                                (first, MemoryProtection::READ_WRITE),
                                (second, MemoryProtection::READ),
                                backing_physical,
                            )
                        {
                            return Err(0x047c);
                        }
                        let first_entry = first_walk.entry;
                        let second_entry = second_walk.entry;
                        let write_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_to_user(
                                &mut access,
                                write_crossing,
                                b"BADWRITE",
                            )
                        };
                        if !matches!(
                            write_result,
                            Err(UserCopyError::Access(ActiveUserAccessError::Permission))
                        ) || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                            || self.read_alias_word(second)? != Self::ALIAS_VALUE
                            || self.walk_leaf(first)?.entry != first_entry
                            || self.walk_leaf(second)?.entry != second_entry
                            || !Self::model_has_exact_two_mappings(
                                &region,
                                &objects,
                                (first, MemoryProtection::READ_WRITE),
                                (second, MemoryProtection::READ),
                                backing_physical,
                            )
                        {
                            return Err(0x047d);
                        }
                        Ok(())
                    })()
                }
                crate::test_support::BuildGuestTest::MemoryUserKernelIsolation => {
                    (|| -> Result<(), u32> {
                        use crate::memory::address_region::{
                            AddressRegionError, AddressSpaceTransactionError,
                        };

                        let user = self.walk_leaf(first)?;
                        let kernel_page = live_kernel_segments()
                            .map_err(|_| 0x0440_u32)?
                            .first()
                            .ok_or(0x0441_u32)?
                            .start;
                        let kernel = self.walk_leaf(kernel_page)?;
                        if !user.user || kernel.user {
                            return Err(0x0442);
                        }
                        if !matches!(
                            spaces.create_region::<1>(
                                address_space,
                                0xffff_8000_0000_0000,
                                PAGE_SIZE,
                            ),
                            Err(AddressRegionError::OutsideRegion)
                        ) {
                            return Err(0x0443);
                        }
                        if self.walk_leaf(0).is_ok() {
                            return Err(0x0444);
                        }
                        let mappings_before = *region.mappings();
                        let leases_before = objects.active_lease_count();
                        let first_before = self.walk_leaf(first)?.entry;
                        let authorization = unsafe {
                            region.authorize_map(
                                &objects,
                                object,
                                MemoryProtection::READ_WRITE_EXECUTE,
                            )
                        }
                        .map_err(|_| 0x0445_u32)?;
                        let rejected = {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region.map(
                                &mut objects,
                                &mut publisher,
                                0,
                                authorization,
                                0,
                                PAGE_SIZE,
                                MemoryProtection::READ_WRITE,
                            )
                        };
                        if !matches!(
                            rejected,
                            Err(AddressSpaceTransactionError::Model(
                                AddressRegionError::PageZero
                            ))
                        ) || self.walk_leaf(0).is_ok()
                            || self.walk_leaf(first)?.entry != first_before
                            || *region.mappings() != mappings_before
                            || objects.active_lease_count() != leases_before
                        {
                            return Err(0x0446);
                        }
                        Ok(())
                    })()
                }
                crate::test_support::BuildGuestTest::MemorySharedMemoryObject => {
                    (|| -> Result<(), u32> {
                        let second = first + PAGE_SIZE;
                        if backing_physical == second {
                            return Err(0x044f);
                        }
                        let authorization = unsafe {
                            region.authorize_map(
                                &objects,
                                object,
                                MemoryProtection::READ_WRITE_EXECUTE,
                            )
                        }
                        .map_err(|_| 0x0450_u32)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .map(
                                    &mut objects,
                                    &mut publisher,
                                    second,
                                    authorization,
                                    0,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_WRITE,
                                )
                                .map_err(|_| 0x0451_u32)?;
                        }
                        let first_walk = self.walk_leaf(first)?;
                        let second_walk = self.walk_leaf(second)?;
                        if first_walk.physical_start != backing_physical
                            || second_walk.physical_start != backing_physical
                            || !Self::model_has_exact_two_mappings(
                                &region,
                                &objects,
                                (first, MemoryProtection::READ_WRITE),
                                (second, MemoryProtection::READ_WRITE),
                                backing_physical,
                            )
                        {
                            return Err(0x0452);
                        }
                        self.write_then_read_alias(first, second)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region
                                .unmap(&mut objects, &mut publisher, first, PAGE_SIZE)
                                .map_err(|_| 0x0453_u32)?;
                        }
                        let retained = self.walk_leaf(second)?;
                        if self.walk_leaf(first).is_ok()
                            || retained.physical_start != backing_physical
                            || !retained.user
                            || !retained.writable
                            || retained.executable
                            || self.read_alias_word(second)? != Self::ALIAS_VALUE
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                second,
                                backing_physical,
                                MemoryProtection::READ_WRITE,
                            )
                        {
                            return Err(0x0454);
                        }
                        Ok(())
                    })()
                }
                _ => Err(0x04ff),
            }
        })();

        match result {
            Ok(()) => crate::test_support::complete_pass(0),
            Err(detail) => crate::test_support::complete_fail(detail),
        }
    }

    #[allow(
        unsafe_code,
        reason = "the bound live-root walks prove both exact user aliases writable while this authority excludes address-space mutation"
    )]
    fn write_then_read_alias(&mut self, writer: u64, reader: u64) -> Result<(), u32> {
        let writer_walk = self.walk_leaf(writer)?;
        let reader_walk = self.walk_leaf(reader)?;
        if !writer_walk.user
            || !writer_walk.writable
            || !reader_walk.user
            || !reader_walk.writable
            || !unsafe {
                crate::test_support::write_then_read_user_alias(writer, reader, Self::ALIAS_VALUE)
            }
        {
            return Err(0x0460);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the bound live-root walk proves this exact user word readable while the authority excludes address-space mutation"
    )]
    fn read_alias_word(&mut self, address: u64) -> Result<u64, u32> {
        let walk = self.walk_leaf(address)?;
        if !walk.user {
            return Err(0x0461);
        }
        Ok(unsafe { crate::test_support::read_user_alias_word(address) })
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>
{
    pub(crate) fn run_memory_foundation_test(
        mut self,
        test: crate::test_support::BuildGuestTest,
    ) -> ! {
        let authority = &mut ActiveRootTestAuthority {
            root: &self.root,
            identity: self.identity,
            roles: &mut *self.target.roles,
            scratch: &mut self.target.scratch,
            _not_send_sync: core::marker::PhantomData,
        };
        match test {
            test if test.is_memory_foundation() => authority.run_mapped_case(test),
            _ => crate::test_support::complete_fail(0x00ff),
        }
    }
}

#[cfg(all(
    feature = "test-support",
    target_os = "none",
    target_arch = "x86_64",
    deepwyrm_c3_one_shot_ui
))]
fn active_deep_paging_cannot_be_duplicated<
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'_, RANGE_CAPACITY, ROLE_CAPACITY>>,
    test: crate::test_support::BuildGuestTest,
) -> ! {
    let claimed = active;
    core::hint::black_box(&active);
    claimed.run_memory_foundation_test(test)
}

impl<H, T: Cr3ActivationTarget<H>> PreparedActivation<H, T> {
    /// Publishes the prepared root. There is deliberately no recoverable error
    /// path after the architecture backend begins the CR3 transition.
    #[allow(
        unsafe_code,
        reason = "the prepared typestate proves the backend preflight completed"
    )]
    pub(crate) fn activate(self) -> ActiveDeepPaging<T::Active> {
        let Self {
            handoff,
            target,
            inactive,
        } = self;
        let InactiveDeepRoot { root, identity } = inactive;
        // SAFETY: construction of `PreparedActivation` is private to the
        // successful preflight path and owns both backend and root linearly.
        let target = unsafe { target.activate(handoff, root.frame()) };
        ActiveDeepPaging {
            target,
            root,
            identity,
        }
    }
}

fn prepare_activation<H, T: Cr3ActivationTarget<H>>(
    mut handoff: H,
    mut target: T,
    root: PageTableRoot,
    identity: TableIdentity,
) -> Result<PreparedActivation<H, T>, ActivationPrepareFailure<H, T, T::Error>> {
    let (cpu, capabilities) = match target.observe(&mut handoff) {
        Ok(preflight) => preflight,
        Err(error) => {
            return Err(ActivationPrepareFailure {
                error: ActivationPrepareError::Target(error),
                handoff,
                target,
                root,
                identity,
            });
        }
    };
    if let Err(error) = InactiveDeepRoot::validate(&root, identity, capabilities, cpu) {
        let error = match error {
            ActivationPrepareError::FrameRole(error) => ActivationPrepareError::FrameRole(error),
            ActivationPrepareError::Root(error) => ActivationPrepareError::Root(error),
            ActivationPrepareError::WrongProcessorState => {
                ActivationPrepareError::WrongProcessorState
            }
            ActivationPrepareError::WrongControlState => ActivationPrepareError::WrongControlState,
            ActivationPrepareError::ActiveRootReused => ActivationPrepareError::ActiveRootReused,
            ActivationPrepareError::InterruptsEnabled => ActivationPrepareError::InterruptsEnabled,
            ActivationPrepareError::PcidEnabled => ActivationPrepareError::PcidEnabled,
            ActivationPrepareError::GlobalPagesEnabled => {
                ActivationPrepareError::GlobalPagesEnabled
            }
            ActivationPrepareError::Target(never) => match never {},
        };
        return Err(ActivationPrepareFailure {
            error,
            handoff,
            target,
            root,
            identity,
        });
    }
    let inactive = InactiveDeepRoot { root, identity };
    if let Err(error) = target.preflight(&mut handoff, &inactive.root, inactive.identity) {
        return Err(ActivationPrepareFailure {
            error: ActivationPrepareError::Target(error),
            handoff,
            target,
            root: inactive.root,
            identity: inactive.identity,
        });
    }
    Ok(PreparedActivation {
        handoff,
        target,
        inactive,
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct DeepActivationPrepareFailure<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    error: ActivationPrepareError<LiveActivationError>,
    authority: InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn prepare_deep_activation<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    authority: InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
) -> Result<
    PreparedActivation<
        TransitionActivationHandoff<'a>,
        LiveCr3ActivationTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    DeepActivationPrepareFailure<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
> {
    let InactiveRootAuthority {
        handoff,
        root,
        identity,
        scratch,
        kernel_roles,
        roles,
        _not_send_sync: _,
    } = authority;
    let target = LiveCr3ActivationTarget {
        roles,
        kernel_roles: Some(kernel_roles),
        scratch,
        root_identity: None,
        _not_send_sync: core::marker::PhantomData,
    };
    prepare_activation(handoff, target, root, identity).map_err(|failure| {
        let (error, handoff, target, root, identity) = failure.into_parts();
        DeepActivationPrepareFailure {
            error,
            authority: InactiveRootAuthority {
                handoff,
                root,
                identity,
                scratch: target.scratch,
                kernel_roles: target
                    .kernel_roles
                    .expect("preflight failure retains imported kernel roles"),
                roles: target.roles,
                _not_send_sync: core::marker::PhantomData,
            },
        }
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum BootstrapDeepPagingError {
    Transition(LiveTransitionError),
    Build(DeepRootBuildError),
    Prepare(ActivationPrepareError<LiveActivationError>),
}

/// Performs the complete one-shot early-bootstrap paging transition and
/// returns the only live Deep-owned paging session.
///
/// # Safety
///
/// The caller must own the sole boot-memory manager on the BSP with APs
/// offline, CPL0, and IF clear. From entry until return it must not move or
/// replace the current kernel stack, GDT, IDT, TSS, transition root, or any
/// referenced page-table storage. The accepted loader's C1 integrity contract
/// must remain valid until this function consumes it. Failure is terminal for
/// the boot attempt; no transition mapper or partially built root escapes.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one unsafe bootstrap session encloses C1 claim, inactive construction, carrier preflight, and the sole CR3 write"
)]
pub(crate) unsafe fn activate_bootstrap_deep_paging<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    handoff: &'a crate::boot::ValidatedPagingHandoff,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    memory_witness: BootstrapMemoryWitness<'_>,
) -> Result<
    ActiveDeepPaging<LiveActivePagingTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>>,
    BootstrapDeepPagingError,
> {
    // SAFETY: this facade's contract is exactly the stronger C1 ownership and
    // CPU-state contract required by the one-shot claim.
    let mapper = unsafe { claim_live_transition_mapper(handoff, roles) }
        .map_err(BootstrapDeepPagingError::Transition)?;
    let authority = build_and_bind_deep_root(mapper, roles, memory_witness)
        .map_err(|failure| BootstrapDeepPagingError::Build(failure.error))?;
    let prepared = prepare_deep_activation(authority).map_err(|failure| {
        let DeepActivationPrepareFailure {
            error,
            authority: _terminal_authority,
        } = failure;
        BootstrapDeepPagingError::Prepare(error)
    })?;
    Ok(prepared.activate())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::collections::BTreeMap;
    use std::{cell::RefCell, rc::Rc, vec::Vec};

    use crate::memory::frame_roles::{
        FrameRoleManager, TableOwnerKey, synthetic_frame_role_manager,
    };
    use crate::memory::physical::PhysicalRange;

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Preflight,
        Cr3Write(u64),
        TransitionRetired,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ScratchIoEvent {
        Load(u64),
        Store(u64, u64),
        CompareExchange {
            address: u64,
            current: u64,
            new: u64,
        },
        Invalidate(u64),
    }

    #[derive(Default)]
    struct FakeActiveScratchIo {
        memory: BTreeMap<u64, u64>,
        events: Vec<ScratchIoEvent>,
        install_attempts: usize,
        fail_install_attempt: Option<usize>,
    }

    impl ActiveScratchIo for FakeActiveScratchIo {
        fn load(&mut self, address: u64) -> u64 {
            self.events.push(ScratchIoEvent::Load(address));
            *self.memory.get(&address).unwrap_or(&0)
        }

        fn store(&mut self, address: u64, value: u64) {
            self.events.push(ScratchIoEvent::Store(address, value));
            self.memory.insert(address, value);
        }

        fn compare_exchange(&mut self, address: u64, current: u64, new: u64) -> Result<(), u64> {
            self.events.push(ScratchIoEvent::CompareExchange {
                address,
                current,
                new,
            });
            if new != 0 {
                self.install_attempts += 1;
                if self.fail_install_attempt == Some(self.install_attempts) {
                    return Err(0xfeed_0000);
                }
            }
            let observed = *self.memory.get(&address).unwrap_or(&0);
            if observed != current {
                return Err(observed);
            }
            self.memory.insert(address, new);
            Ok(())
        }

        fn invalidate(&mut self, virtual_address: u64) {
            self.events
                .push(ScratchIoEvent::Invalidate(virtual_address));
        }
    }

    struct FakeHandoff(Rc<RefCell<Vec<Event>>>);

    impl FakeHandoff {
        fn retire_before_activation(self) {
            self.0.borrow_mut().push(Event::TransitionRetired);
        }
    }

    struct FakeTarget(Rc<RefCell<Vec<Event>>>);

    impl target_seal::Sealed for FakeTarget {}

    // SAFETY: this host fake records the modeled single write and exposes no
    // architecture state; its preflight and activation are inseparable.
    #[allow(
        unsafe_code,
        reason = "host fake models the sealed single-write architecture backend"
    )]
    unsafe impl Cr3ActivationTarget<FakeHandoff> for FakeTarget {
        type Error = ();
        type Active = ();

        fn observe(
            &mut self,
            _handoff: &mut FakeHandoff,
        ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error> {
            let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
            let current_root = FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap();
            Ok((
                ActivationCpuState {
                    processor_id: 0,
                    physical_address_width: 40,
                    current_root,
                    cpl: 0,
                    paging_enabled: true,
                    long_mode_active: true,
                    four_level_paging: true,
                    no_execute_enabled: true,
                    write_protect_enabled: true,
                    interrupts_enabled: false,
                    pcid_enabled: false,
                    global_pages_enabled: false,
                    smap_enabled: false,
                    access_flag_set: false,
                    pat_supported: true,
                    pat_entry_zero: 6,
                    stack_pointer: 0,
                    code_selector: 0,
                    gdt_base: 0,
                    gdt_limit: 0,
                    idt_base: 0,
                    idt_limit: 0,
                    task_register: 0,
                },
                capabilities,
            ))
        }

        fn preflight(
            &mut self,
            _handoff: &mut FakeHandoff,
            _root: &PageTableRoot,
            _identity: TableIdentity,
        ) -> Result<(), Self::Error> {
            self.0.borrow_mut().push(Event::Preflight);
            Ok(())
        }

        unsafe fn activate(self, handoff: FakeHandoff, root: FrameAddress) -> Self::Active {
            handoff.retire_before_activation();
            self.0.borrow_mut().push(Event::Cr3Write(root.address()));
        }
    }

    struct InvalidCpuTarget;

    impl target_seal::Sealed for InvalidCpuTarget {}

    #[allow(
        unsafe_code,
        reason = "host fake supplies one rejected observation and has no commit path"
    )]
    unsafe impl Cr3ActivationTarget<FakeHandoff> for InvalidCpuTarget {
        type Error = ();
        type Active = ();

        fn observe(
            &mut self,
            _handoff: &mut FakeHandoff,
        ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error> {
            let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
            Ok((
                ActivationCpuState {
                    processor_id: 0,
                    physical_address_width: 40,
                    current_root: FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
                    cpl: 0,
                    paging_enabled: true,
                    long_mode_active: true,
                    four_level_paging: true,
                    no_execute_enabled: true,
                    write_protect_enabled: true,
                    interrupts_enabled: true,
                    pcid_enabled: false,
                    global_pages_enabled: false,
                    smap_enabled: false,
                    access_flag_set: false,
                    pat_supported: true,
                    pat_entry_zero: 6,
                    stack_pointer: 0,
                    code_selector: 0,
                    gdt_base: 0,
                    gdt_limit: 0,
                    idt_base: 0,
                    idt_limit: 0,
                    task_register: 0,
                },
                capabilities,
            ))
        }

        fn preflight(
            &mut self,
            _handoff: &mut FakeHandoff,
            _root: &PageTableRoot,
            _identity: TableIdentity,
        ) -> Result<(), Self::Error> {
            panic!("invalid CPU state must reject before target preflight")
        }

        unsafe fn activate(self, _handoff: FakeHandoff, _root: FrameAddress) -> Self::Active {
            panic!("invalid CPU state must never reach activation")
        }
    }

    #[derive(Default)]
    struct FakeGraphAccess {
        transition: BTreeMap<(u64, usize), u64>,
        inactive: BTreeMap<(u64, usize), u64>,
    }

    impl ActivationGraphAccess for FakeGraphAccess {
        type Error = ();

        fn read_transition(
            &mut self,
            table: FrameAddress,
            index: usize,
        ) -> Result<u64, Self::Error> {
            Ok(*self.transition.get(&(table.address(), index)).unwrap_or(&0))
        }

        fn read_inactive(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
            Ok(*self.inactive.get(&(table.address(), index)).unwrap_or(&0))
        }
    }

    fn page_index(page: u64, level: usize) -> usize {
        ((page >> (12 + level * 9)) & 0x1ff) as usize
    }

    #[allow(
        unsafe_code,
        reason = "synthetic host tables model completed physical zeroing"
    )]
    fn commit_table<const ROLE_CAPACITY: usize>(
        roles: &mut FrameRoleManager<1, ROLE_CAPACITY>,
        owner: TableOwnerKey,
        level: TableLevel,
        parent: Option<TableIdentity>,
    ) -> TableIdentity {
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let candidate = roles.prepare_table(zeroed, owner, level).unwrap();
        roles.commit_table(candidate, parent).unwrap()
    }

    fn add_path(entries: &mut BTreeMap<(u64, usize), u64>, page: u64, tables: [u64; 4], leaf: u64) {
        for level in (1..=3).rev() {
            entries.insert(
                (tables[3 - level], page_index(page, level)),
                tables[4 - level] | PRESENT | WRITABLE,
            );
        }
        if leaf != 0 {
            entries.insert((tables[3], page_index(page, 0)), leaf);
        }
    }

    const FIXTURE_TEXT: u64 = 0xffff_8000_0000_0000;
    const FIXTURE_RODATA: u64 = FIXTURE_TEXT + PAGE_SIZE;
    const FIXTURE_DATA: u64 = FIXTURE_RODATA + PAGE_SIZE;
    const FIXTURE_SCRATCH: u64 = 0xffff_ff00_0000_0000;

    struct GraphFixture {
        access: FakeGraphAccess,
        roles: FrameRoleManager<1, 16>,
        staged: StagedKernelImageRoles,
        root: TableIdentity,
        kernel_tables: [u64; 4],
        scratch_tables: [u64; 4],
        scratch_pt: TableIdentity,
        extra_pdpt: TableIdentity,
        transition_tables: [u64; 4],
        capabilities: PagingCapabilities,
        segments: [KernelSegment; 3],
    }

    impl GraphFixture {
        fn validate(&mut self) -> Result<(), InactiveGraphError<()>> {
            validate_inactive_graph(
                &mut self.access,
                &self.roles,
                &self.staged,
                self.root,
                FrameAddress::new(
                    self.transition_tables[0],
                    self.capabilities.physical_limit(),
                )
                .unwrap(),
                DeepScratchBinding {
                    window_page: FIXTURE_SCRATCH,
                    control_page: FIXTURE_SCRATCH + PAGE_SIZE,
                    pt: self.scratch_pt,
                },
                &self.segments,
                self.capabilities,
            )
        }
    }

    #[allow(
        unsafe_code,
        reason = "synthetic host graph models typed page-table and kernel-image provenance"
    )]
    fn graph_fixture() -> GraphFixture {
        let segments = [
            KernelSegment {
                start: FIXTURE_TEXT,
                end: FIXTURE_RODATA,
                kind: SegmentKind::Text,
            },
            KernelSegment {
                start: FIXTURE_RODATA,
                end: FIXTURE_DATA,
                kind: SegmentKind::ReadOnly,
            },
            KernelSegment {
                start: FIXTURE_DATA,
                end: FIXTURE_DATA + PAGE_SIZE,
                kind: SegmentKind::Writable,
            },
        ];
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        let mut roles = synthetic_frame_role_manager::<1, 16>(0x8000, 8);
        let owner = roles.create_table_owner().unwrap();
        let root = commit_table(&mut roles, owner, TableLevel::Pml4, None);
        let kernel_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
        let kernel_pd = commit_table(&mut roles, owner, TableLevel::Pd, Some(kernel_pdpt));
        let kernel_pt = commit_table(&mut roles, owner, TableLevel::Pt, Some(kernel_pd));
        let scratch_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
        let scratch_pd = commit_table(&mut roles, owner, TableLevel::Pd, Some(scratch_pdpt));
        let scratch_pt = commit_table(&mut roles, owner, TableLevel::Pt, Some(scratch_pd));
        let extra_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
        let kernel_tables = [
            root.physical_start(),
            kernel_pdpt.physical_start(),
            kernel_pd.physical_start(),
            kernel_pt.physical_start(),
        ];
        let scratch_tables = [
            root.physical_start(),
            scratch_pdpt.physical_start(),
            scratch_pd.physical_start(),
            scratch_pt.physical_start(),
        ];
        let transition_tables = [0x1000, 0x2000, 0x3000, 0x4000];
        let mut access = FakeGraphAccess::default();
        for (page, physical, flags) in [
            (FIXTURE_TEXT, 0x20_0000, PRESENT),
            (FIXTURE_RODATA, 0x21_0000, PRESENT | NO_EXECUTE),
            (FIXTURE_DATA, 0x22_0000, PRESENT | WRITABLE | NO_EXECUTE),
        ] {
            add_path(
                &mut access.transition,
                page,
                transition_tables,
                physical | flags,
            );
            add_path(&mut access.inactive, page, kernel_tables, physical | flags);
        }
        add_path(&mut access.inactive, FIXTURE_SCRATCH, scratch_tables, 0);
        access.inactive.insert(
            (
                scratch_pt.physical_start(),
                page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
            ),
            scratch_pt.physical_start() | PRESENT | WRITABLE | NO_EXECUTE,
        );
        let staged = unsafe {
            roles.stage_kernel_image_roles([
                (
                    PhysicalRange::new(0x20_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::Text,
                ),
                (
                    PhysicalRange::new(0x21_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::ReadOnlyData,
                ),
                (
                    PhysicalRange::new(0x22_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::WritableData,
                ),
            ])
        }
        .unwrap();
        GraphFixture {
            access,
            roles,
            staged,
            root,
            kernel_tables,
            scratch_tables,
            scratch_pt,
            extra_pdpt,
            transition_tables,
            capabilities,
            segments,
        }
    }

    fn fake_active_scratch(
        scratch_pt: TableIdentity,
        fail_install_attempt: Option<usize>,
    ) -> ActiveScratchTarget<FakeActiveScratchIo> {
        ActiveScratchTarget {
            scratch: DeepScratchBinding {
                window_page: FIXTURE_SCRATCH,
                control_page: FIXTURE_SCRATCH + PAGE_SIZE,
                pt: scratch_pt,
            },
            io: FakeActiveScratchIo {
                fail_install_attempt,
                ..FakeActiveScratchIo::default()
            },
            poisoned: false,
            _not_send_sync: core::marker::PhantomData,
        }
    }

    #[test]
    fn active_scratch_error_restores_private_leaf_without_owned_write_or_requested_invlpg() {
        let fixture = graph_fixture();
        let mut target = fake_active_scratch(fixture.scratch_pt, Some(2));
        let limit = fixture.capabilities.physical_limit();
        let writes = [
            JournalWrite::test_new(FrameAddress::new(0x90_000, limit).unwrap(), 7, 0x1111),
            JournalWrite::test_new(FrameAddress::new(0x91_000, limit).unwrap(), 8, 0x2222),
        ];
        let requested = VirtualPage::new(FIXTURE_TEXT).unwrap();
        assert_eq!(
            target.apply(&writes, &[requested]),
            Err(LiveActiveTargetError::Busy)
        );
        assert_eq!(
            target
                .io
                .memory
                .get(&target.scratch_leaf_address())
                .copied()
                .unwrap_or(0),
            0
        );
        assert!(
            target
                .io
                .events
                .iter()
                .all(|event| !matches!(event, ScratchIoEvent::Store(_, _))),
            "prepublication failure must not write an owned-root entry"
        );
        assert!(target.io.events.iter().all(|event| {
            !matches!(event, ScratchIoEvent::Invalidate(page) if *page == requested.address())
        }));
        assert!(target.io.events.iter().any(|event| {
            matches!(event, ScratchIoEvent::Invalidate(page) if *page == FIXTURE_SCRATCH)
        }));
    }

    #[test]
    fn active_scratch_reserves_window_and_control_entries_without_io() {
        let fixture = graph_fixture();
        let mut target = fake_active_scratch(fixture.scratch_pt, None);
        let table = FrameAddress::new(
            fixture.scratch_pt.physical_start(),
            fixture.capabilities.physical_limit(),
        )
        .unwrap();
        for index in [target.scratch_leaf_index(), target.scratch_control_index()] {
            assert_eq!(
                target.read_entry(table, index),
                Err(LiveActiveTargetError::ReservedScratchEntry)
            );
        }
        assert!(target.io.events.is_empty());
    }

    #[test]
    fn graph_rejects_kernel_permission_drift() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (fixture.kernel_tables[3], page_index(FIXTURE_TEXT, 0)),
            0x20_0000 | PRESENT | NO_EXECUTE,
        );
        assert_eq!(fixture.validate(), Err(InactiveGraphError::InvalidEntry));
    }

    #[test]
    fn graph_rejects_kernel_physical_mapping_drift() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (fixture.kernel_tables[3], page_index(FIXTURE_TEXT, 0)),
            0x23_0000 | PRESENT,
        );
        assert_eq!(fixture.validate(), Err(InactiveGraphError::MappingMismatch));
    }

    #[test]
    fn graph_rejects_occupied_deep_scratch_leaf() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (fixture.scratch_tables[3], page_index(FIXTURE_SCRATCH, 0)),
            0x24_0000 | PRESENT | WRITABLE | NO_EXECUTE,
        );
        assert_eq!(fixture.validate(), Err(InactiveGraphError::ExtraLeaf));
    }

    #[test]
    fn graph_rejects_missing_deep_scratch_path() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.remove(&(
            fixture.root.physical_start(),
            page_index(FIXTURE_SCRATCH, 3),
        ));
        assert_eq!(
            fixture.validate(),
            Err(InactiveGraphError::InvalidScratchPath)
        );
    }

    #[test]
    fn graph_rejects_missing_scratch_control_alias() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.remove(&(
            fixture.scratch_pt.physical_start(),
            page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
        ));
        assert_eq!(
            fixture.validate(),
            Err(InactiveGraphError::InvalidScratchPath)
        );
    }

    #[test]
    fn graph_rejects_wrong_scratch_control_frame() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (
                fixture.scratch_pt.physical_start(),
                page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
            ),
            fixture.kernel_tables[3] | PRESENT | WRITABLE | NO_EXECUTE,
        );
        assert_eq!(
            fixture.validate(),
            Err(InactiveGraphError::InvalidScratchPath)
        );
    }

    #[test]
    fn graph_rejects_scratch_control_permission_drift() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (
                fixture.scratch_pt.physical_start(),
                page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
            ),
            fixture.scratch_pt.physical_start() | PRESENT | WRITABLE,
        );
        assert_eq!(
            fixture.validate(),
            Err(InactiveGraphError::InvalidScratchPath)
        );
    }

    #[test]
    fn graph_rejects_second_scratch_control_alias() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (
                fixture.scratch_pt.physical_start(),
                page_index(FIXTURE_SCRATCH + 2 * PAGE_SIZE, 0),
            ),
            fixture.scratch_pt.physical_start() | PRESENT | WRITABLE | NO_EXECUTE,
        );
        assert_eq!(fixture.validate(), Err(InactiveGraphError::ExtraLeaf));
    }

    #[test]
    fn graph_rejects_wrong_table_role_or_parent_level() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (fixture.root.physical_start(), page_index(FIXTURE_TEXT, 3)),
            fixture.kernel_tables[2] | PRESENT | WRITABLE,
        );
        assert_eq!(
            fixture.validate(),
            Err(InactiveGraphError::FrameRole(FrameRoleError::WrongRole))
        );
    }

    #[test]
    fn graph_rejects_duplicate_or_cyclic_table_reachability() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (
                fixture.root.physical_start(),
                page_index(FIXTURE_SCRATCH, 3),
            ),
            fixture.kernel_tables[1] | PRESENT | WRITABLE,
        );
        assert_eq!(
            fixture.validate(),
            Err(InactiveGraphError::DuplicateOrCyclicTable)
        );
    }

    #[test]
    fn graph_rejects_extra_empty_lower_half_subtree() {
        let mut fixture = graph_fixture();
        fixture.access.inactive.insert(
            (fixture.root.physical_start(), 0),
            fixture.extra_pdpt.physical_start() | PRESENT | WRITABLE,
        );
        assert_eq!(fixture.validate(), Err(InactiveGraphError::ExtraTable));
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "synthetic host graph models a bounded hostile table fanout"
    )]
    fn graph_capacity_rejects_before_any_leaf_or_scratch_access() {
        const SPAN: u64 = 1_u64 << 39;
        const START: u64 = 0xffff_8000_0000_0000;
        const MID_ONE: u64 = START + 64 * SPAN;
        const MID_TWO: u64 = START + 128 * SPAN;
        const SCRATCH: u64 = START + 255 * SPAN;
        let segments = [
            KernelSegment {
                start: START,
                end: MID_ONE,
                kind: SegmentKind::Text,
            },
            KernelSegment {
                start: MID_ONE,
                end: MID_TWO,
                kind: SegmentKind::ReadOnly,
            },
            KernelSegment {
                start: MID_TWO,
                end: SCRATCH,
                kind: SegmentKind::Writable,
            },
        ];
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        let mut roles = synthetic_frame_role_manager::<1, 300>(0x8000, 257);
        let owner = roles.create_table_owner().unwrap();
        let root = commit_table(&mut roles, owner, TableLevel::Pml4, None);
        let mut access = FakeGraphAccess::default();
        for index in 0..256 {
            let child = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
            access.inactive.insert(
                (root.physical_start(), 256 + index),
                child.physical_start() | PRESENT | WRITABLE,
            );
        }
        let staged = unsafe {
            roles.stage_kernel_image_roles([
                (
                    PhysicalRange::new(0x20_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::Text,
                ),
                (
                    PhysicalRange::new(0x21_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::ReadOnlyData,
                ),
                (
                    PhysicalRange::new(0x22_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::WritableData,
                ),
            ])
        }
        .unwrap();
        assert_eq!(
            validate_inactive_graph(
                &mut access,
                &roles,
                &staged,
                root,
                FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
                DeepScratchBinding {
                    window_page: SCRATCH,
                    control_page: SCRATCH + PAGE_SIZE,
                    pt: root,
                },
                &segments,
                capabilities,
            ),
            Err(InactiveGraphError::Capacity)
        );
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "synthetic host role setup models completed physical zeroing"
    )]
    fn full_owned_graph_matches_transition_segments_and_empty_scratch() {
        const TEXT: u64 = 0xffff_8000_0000_0000;
        const RODATA: u64 = TEXT + PAGE_SIZE;
        const DATA: u64 = RODATA + PAGE_SIZE;
        const SCRATCH: u64 = 0xffff_ff00_0000_0000;
        let segments = [
            KernelSegment {
                start: TEXT,
                end: RODATA,
                kind: SegmentKind::Text,
            },
            KernelSegment {
                start: RODATA,
                end: DATA,
                kind: SegmentKind::ReadOnly,
            },
            KernelSegment {
                start: DATA,
                end: DATA + PAGE_SIZE,
                kind: SegmentKind::Writable,
            },
        ];
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        let mut roles = synthetic_frame_role_manager::<1, 16>(0x8000, 7);
        let owner = roles.create_table_owner().unwrap();
        let root = commit_table(&mut roles, owner, TableLevel::Pml4, None);
        let kernel_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
        let kernel_pd = commit_table(&mut roles, owner, TableLevel::Pd, Some(kernel_pdpt));
        let kernel_pt = commit_table(&mut roles, owner, TableLevel::Pt, Some(kernel_pd));
        let scratch_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
        let scratch_pd = commit_table(&mut roles, owner, TableLevel::Pd, Some(scratch_pdpt));
        let scratch_pt = commit_table(&mut roles, owner, TableLevel::Pt, Some(scratch_pd));
        let new_kernel = [
            root.physical_start(),
            kernel_pdpt.physical_start(),
            kernel_pd.physical_start(),
            kernel_pt.physical_start(),
        ];
        let new_scratch = [
            root.physical_start(),
            scratch_pdpt.physical_start(),
            scratch_pd.physical_start(),
            scratch_pt.physical_start(),
        ];
        let old = [0x1000, 0x2000, 0x3000, 0x4000];
        let mut access = FakeGraphAccess::default();
        for (page, physical, flags) in [
            (TEXT, 0x20_0000, PRESENT),
            (RODATA, 0x21_0000, PRESENT | NO_EXECUTE),
            (DATA, 0x22_0000, PRESENT | WRITABLE | NO_EXECUTE),
        ] {
            add_path(&mut access.transition, page, old, physical | flags);
            add_path(&mut access.inactive, page, new_kernel, physical | flags);
        }
        // SAFETY: the synthetic fixture supplies disjoint, page-exact boot
        // provenance solely to exercise C2 role authentication.
        let staged = unsafe {
            roles.stage_kernel_image_roles([
                (
                    PhysicalRange::new(0x20_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::Text,
                ),
                (
                    PhysicalRange::new(0x21_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::ReadOnlyData,
                ),
                (
                    PhysicalRange::new(0x22_0000, PAGE_SIZE).unwrap(),
                    KernelImageSegment::WritableData,
                ),
            ])
        }
        .unwrap();
        add_path(&mut access.inactive, SCRATCH, new_scratch, 0);
        access.inactive.insert(
            (
                scratch_pt.physical_start(),
                page_index(SCRATCH + PAGE_SIZE, 0),
            ),
            scratch_pt.physical_start() | PRESENT | WRITABLE | NO_EXECUTE,
        );

        assert_eq!(
            validate_inactive_graph(
                &mut access,
                &roles,
                &staged,
                root,
                FrameAddress::new(old[0], capabilities.physical_limit()).unwrap(),
                DeepScratchBinding {
                    window_page: SCRATCH,
                    control_page: SCRATCH + PAGE_SIZE,
                    pt: scratch_pt,
                },
                &segments,
                capabilities,
            ),
            Ok(())
        );
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "synthetic host role setup models completed physical zeroing"
    )]
    fn retirement_before_one_infallible_write() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 1);
        let allocation = roles.allocate(1).unwrap();
        // SAFETY: synthetic host frames are never dereferenced and the test
        // models the completed zeroing step explicitly.
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let owner = roles.create_table_owner().unwrap();
        let candidate = roles
            .prepare_table(zeroed, owner, TableLevel::Pml4)
            .unwrap();
        let identity = roles.commit_table(candidate, None).unwrap();
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        // SAFETY: the synthetic role manager authenticated this exact root.
        let root =
            unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }
                .unwrap();
        let prepared = prepare_activation(
            FakeHandoff(Rc::clone(&events)),
            FakeTarget(Rc::clone(&events)),
            root,
            identity,
        )
        .unwrap_or_else(|_| panic!("activation preparation succeeds"));
        let active = prepared.activate();

        assert_eq!(active.identity(), identity);
        assert_eq!(active.root().frame().address(), 0x8000);
        assert_eq!(
            events.borrow().as_slice(),
            &[
                Event::Preflight,
                Event::TransitionRetired,
                Event::Cr3Write(0x8000),
            ]
        );
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "synthetic host role setup models completed physical zeroing"
    )]
    fn cpu_rejection_returns_all_authority_with_zero_retire_or_write_events() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 1);
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let owner = roles.create_table_owner().unwrap();
        let candidate = roles
            .prepare_table(zeroed, owner, TableLevel::Pml4)
            .unwrap();
        let identity = roles.commit_table(candidate, None).unwrap();
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        let root =
            unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }
                .unwrap();

        let failure = match prepare_activation(
            FakeHandoff(Rc::clone(&events)),
            InvalidCpuTarget,
            root,
            identity,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("enabled interrupts reject before preflight"),
        };
        let (error, _handoff, _target, root, returned_identity) = failure.into_parts();
        assert_eq!(error, ActivationPrepareError::InterruptsEnabled);
        assert_eq!(root.frame().address(), identity.physical_start());
        assert_eq!(returned_identity, identity);
        assert!(events.borrow().is_empty());
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "synthetic host role setup models one inactive owned root for pure CPU-profile validation"
    )]
    fn accepted_cpu_profile_rejects_smap_or_initial_access_flag() {
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 1);
        let allocation = roles.allocate(1).unwrap();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let owner = roles.create_table_owner().unwrap();
        let candidate = roles
            .prepare_table(zeroed, owner, TableLevel::Pml4)
            .unwrap();
        let identity = roles.commit_table(candidate, None).unwrap();
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        let root =
            unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }
                .unwrap();
        let mut cpu = ActivationCpuState {
            processor_id: 0,
            physical_address_width: 40,
            current_root: FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
            cpl: 0,
            paging_enabled: true,
            long_mode_active: true,
            four_level_paging: true,
            no_execute_enabled: true,
            write_protect_enabled: true,
            interrupts_enabled: false,
            pcid_enabled: false,
            global_pages_enabled: false,
            smap_enabled: false,
            access_flag_set: false,
            pat_supported: true,
            pat_entry_zero: 6,
            stack_pointer: 0,
            code_selector: 0,
            gdt_base: 0,
            gdt_limit: 0,
            idt_base: 0,
            idt_limit: 0,
            task_register: 0,
        };
        assert!(InactiveDeepRoot::validate(&root, identity, capabilities, cpu).is_ok());

        cpu.smap_enabled = true;
        assert_eq!(
            InactiveDeepRoot::validate(&root, identity, capabilities, cpu),
            Err(ActivationPrepareError::WrongControlState)
        );
        cpu.smap_enabled = false;
        cpu.access_flag_set = true;
        assert_eq!(
            InactiveDeepRoot::validate(&root, identity, capabilities, cpu),
            Err(ActivationPrepareError::WrongControlState)
        );
    }

    #[test]
    fn stack_and_descriptor_carriers_reject_drift() {
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        let mut cpu = ActivationCpuState {
            processor_id: 0,
            physical_address_width: 40,
            current_root: FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
            cpl: 0,
            paging_enabled: true,
            long_mode_active: true,
            four_level_paging: true,
            no_execute_enabled: true,
            write_protect_enabled: true,
            interrupts_enabled: false,
            pcid_enabled: false,
            global_pages_enabled: false,
            smap_enabled: false,
            access_flag_set: false,
            pat_supported: true,
            pat_entry_zero: 6,
            stack_pointer: 0xffff_8000_0000_5800,
            code_selector: 0x08,
            gdt_base: 0xffff_8000_0000_2100,
            gdt_limit: 39,
            idt_base: 0xffff_8000_0000_2200,
            idt_limit: 0x0fff,
            task_register: 0x18,
        };
        let segments = [
            KernelSegment {
                start: 0xffff_8000_0000_0000,
                end: 0xffff_8000_0000_1000,
                kind: SegmentKind::Text,
            },
            KernelSegment {
                start: 0xffff_8000_0000_1000,
                end: 0xffff_8000_0000_2000,
                kind: SegmentKind::ReadOnly,
            },
            KernelSegment {
                start: 0xffff_8000_0000_2000,
                end: 0xffff_8000_0000_6000,
                kind: SegmentKind::Writable,
            },
        ];
        let facts = ExecutionCarrierFacts {
            stack_bottom: 0xffff_8000_0000_4000,
            stack_top: 0xffff_8000_0000_6000,
            gdt_base: cpu.gdt_base,
            gdt_limit: cpu.gdt_limit,
            idt_base: cpu.idt_base,
            idt_limit: cpu.idt_limit,
            tss_base: 0xffff_8000_0000_3300,
            tss_limit: 0x0067,
            code_selector: 0x08,
            task_register: 0x18,
        };
        assert!(execution_carriers_match(cpu, &segments, facts));

        cpu.stack_pointer = facts.stack_bottom + MIN_ACTIVATION_STACK_HEADROOM - 1;
        assert!(!execution_carriers_match(cpu, &segments, facts));
        cpu.stack_pointer = 0xffff_8000_0000_5800;
        cpu.code_selector = 0x10;
        assert!(!execution_carriers_match(cpu, &segments, facts));
        cpu.code_selector = facts.code_selector;
        cpu.gdt_base += PAGE_SIZE;
        assert!(!execution_carriers_match(cpu, &segments, facts));
        cpu.gdt_base = facts.gdt_base;
        cpu.gdt_limit += 1;
        assert!(!execution_carriers_match(cpu, &segments, facts));
        cpu.gdt_limit = facts.gdt_limit;
        cpu.idt_limit -= 1;
        assert!(!execution_carriers_match(cpu, &segments, facts));
        cpu.idt_limit = facts.idt_limit;
        cpu.task_register = 0;
        assert!(!execution_carriers_match(cpu, &segments, facts));

        cpu.task_register = facts.task_register;
        let crossing_idt = ExecutionCarrierFacts {
            idt_base: 0xffff_8000_0000_5800,
            ..facts
        };
        cpu.idt_base = crossing_idt.idt_base;
        assert!(!execution_carriers_match(cpu, &segments, crossing_idt));
    }
}
