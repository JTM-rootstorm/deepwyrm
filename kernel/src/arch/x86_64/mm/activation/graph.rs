use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SegmentKind {
    Text,
    ReadOnly,
    Writable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct KernelSegment {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) kind: SegmentKind,
}

#[derive(Clone, Copy)]
pub(super) struct ExecutionCarrierFacts {
    pub(super) stack_bottom: u64,
    pub(super) stack_top: u64,
    pub(super) gdt_base: u64,
    pub(super) gdt_limit: u16,
    pub(super) idt_base: u64,
    pub(super) idt_limit: u16,
    pub(super) tss_base: u64,
    pub(super) tss_limit: u16,
    pub(super) code_selector: u16,
    pub(super) task_register: u16,
    pub(super) ist: IstStackLayout,
    pub(super) installed_ist_tops: [u64; 3],
    pub(super) privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
    pub(super) installed_privilege_stack0: u64,
}

impl KernelSegment {
    pub(super) fn contains(self, page: u64) -> bool {
        page >= self.start && page < self.end
    }

    pub(super) const fn expected_flags(self) -> u64 {
        match self.kind {
            SegmentKind::Text => PRESENT,
            SegmentKind::ReadOnly => PRESENT | NO_EXECUTE,
            SegmentKind::Writable => PRESENT | WRITABLE | NO_EXECUTE,
        }
    }

    pub(super) const fn frame_role(self) -> KernelImageSegment {
        match self.kind {
            SegmentKind::Text => KernelImageSegment::Text,
            SegmentKind::ReadOnly => KernelImageSegment::ReadOnlyData,
            SegmentKind::Writable => KernelImageSegment::WritableData,
        }
    }
}

pub(super) trait ActivationGraphAccess {
    type Error;

    fn read_transition(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error>;
    fn read_inactive(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum InactiveGraphError<E> {
    Access(E),
    FrameRole(FrameRoleError),
    Capacity,
    InvalidSegmentLayout,
    InvalidEntry,
    DuplicateOrCyclicTable,
    MissingSegmentPage,
    MappedGuardPage,
    ExtraTable,
    ExtraLeaf,
    MappingMismatch,
    InvalidScratchPath,
}

#[derive(Clone, Copy)]
pub(super) struct PendingTable {
    identity: TableIdentity,
    level: TableLevel,
    virtual_prefix: u64,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(super) struct GraphValidationWorkspace {
    pub(super) pending: core::cell::UnsafeCell<[Option<PendingTable>; MAX_DEEP_TABLE_FRAMES]>,
    pub(super) visited: core::cell::UnsafeCell<[u64; MAX_DEEP_TABLE_FRAMES]>,
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
pub(super) static GRAPH_VALIDATION_WORKSPACE: GraphValidationWorkspace =
    GraphValidationWorkspace::new();

pub(super) fn table_level_depth(level: TableLevel) -> u8 {
    match level {
        TableLevel::Pml4 => 3,
        TableLevel::Pdpt => 2,
        TableLevel::Pd => 1,
        TableLevel::Pt => 0,
    }
}

pub(super) fn entry_virtual_address(prefix: u64, index: usize, level: u8) -> u64 {
    let shift = 12 + u32::from(level) * 9;
    let address = prefix | ((index as u64) << shift);
    if address & (1_u64 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

pub(super) fn physical_mask(capabilities: PagingCapabilities) -> u64 {
    (capabilities.physical_limit().exclusive() - 1) & !ADDRESS_OFFSET_MASK
}

pub(super) fn validate_present_entry(
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

pub(super) fn segment_for_page(segments: &[KernelSegment; 3], page: u64) -> Option<KernelSegment> {
    segments
        .iter()
        .copied()
        .find(|segment| segment.contains(page))
}

pub(super) fn is_ist_guard(ist: IstStackLayout, page: u64) -> bool {
    ist.stacks().iter().any(|stack| stack.guard_page == page)
}

pub(super) fn is_thread_stack_guard(
    thread_stacks: &[crate::memory::kernel_stack::KernelStackBounds],
    page: u64,
) -> bool {
    thread_stacks.iter().any(|stack| stack.guard_page == page)
}

pub(super) fn is_kernel_guard(
    ist: IstStackLayout,
    thread_stacks: &[crate::memory::kernel_stack::KernelStackBounds],
    privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
    page: u64,
) -> bool {
    is_ist_guard(ist, page)
        || is_thread_stack_guard(thread_stacks, page)
        || privilege_entry.guard_page == page
}

pub(super) fn validate_ist_layout(
    segments: &[KernelSegment; 3],
    scratch_window_page: u64,
    scratch_control_page: u64,
    ist: IstStackLayout,
) -> Result<(), InactiveGraphError<core::convert::Infallible>> {
    let Some(writable) = segments
        .iter()
        .copied()
        .find(|segment| segment.kind == SegmentKind::Writable)
    else {
        return Err(InactiveGraphError::InvalidSegmentLayout);
    };
    if !ist.has_exact_shape()
        || ist.stacks().iter().any(|stack| {
            !writable.contains(stack.guard_page)
                || stack.top > writable.end
                || stack.guard_page == scratch_window_page
                || stack.guard_page == scratch_control_page
                || (scratch_window_page >= stack.bottom && scratch_window_page < stack.top)
                || (scratch_control_page >= stack.bottom && scratch_control_page < stack.top)
        })
    {
        return Err(InactiveGraphError::InvalidSegmentLayout);
    }
    Ok(())
}

pub(super) fn validate_thread_stack_layout(
    segments: &[KernelSegment; 3],
    scratch_window_page: u64,
    scratch_control_page: u64,
    thread_stacks: &[crate::memory::kernel_stack::KernelStackBounds],
) -> Result<(), InactiveGraphError<core::convert::Infallible>> {
    let Some(writable) = segments
        .iter()
        .copied()
        .find(|segment| segment.kind == SegmentKind::Writable)
    else {
        return Err(InactiveGraphError::InvalidSegmentLayout);
    };
    for (index, stack) in thread_stacks.iter().copied().enumerate() {
        if stack.bottom.checked_sub(stack.guard_page)
            != Some(crate::memory::kernel_stack::E3_THREAD_STACK_GUARD_SIZE)
            || stack.byte_len() != crate::memory::kernel_stack::E3_THREAD_STACK_SIZE
            || !stack
                .guard_page
                .is_multiple_of(crate::memory::kernel_stack::E3_THREAD_STACK_ALIGNMENT)
            || !writable.contains(stack.guard_page)
            || stack.top > writable.end
            || (scratch_window_page >= stack.guard_page && scratch_window_page < stack.top)
            || (scratch_control_page >= stack.guard_page && scratch_control_page < stack.top)
            || thread_stacks[..index]
                .iter()
                .any(|prior| stack.guard_page < prior.top && prior.guard_page < stack.top)
        {
            return Err(InactiveGraphError::InvalidSegmentLayout);
        }
    }
    Ok(())
}

pub(super) fn validate_privilege_entry_stack_layout(
    segments: &[KernelSegment; 3],
    scratch_window_page: u64,
    scratch_control_page: u64,
    ist: IstStackLayout,
    privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
    thread_stacks: &[crate::memory::kernel_stack::KernelStackBounds],
) -> Result<(), InactiveGraphError<core::convert::Infallible>> {
    let Some(writable) = segments
        .iter()
        .copied()
        .find(|segment| segment.kind == SegmentKind::Writable)
    else {
        return Err(InactiveGraphError::InvalidSegmentLayout);
    };
    let overlaps_thread = thread_stacks.iter().any(|stack| {
        privilege_entry.guard_page < stack.top && stack.guard_page < privilege_entry.top
    });
    let overlaps_ist = ist.stacks().iter().any(|stack| {
        privilege_entry.guard_page < stack.top && stack.guard_page < privilege_entry.top
    });
    if privilege_entry
        .bottom
        .checked_sub(privilege_entry.guard_page)
        != Some(crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE)
        || privilege_entry.byte_len() != crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_SIZE
        || !privilege_entry
            .guard_page
            .is_multiple_of(crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT)
        || !writable.contains(privilege_entry.guard_page)
        || privilege_entry.top > writable.end
        || (scratch_window_page >= privilege_entry.guard_page
            && scratch_window_page < privilege_entry.top)
        || (scratch_control_page >= privilege_entry.guard_page
            && scratch_control_page < privilege_entry.top)
        || overlaps_thread
        || overlaps_ist
    {
        return Err(InactiveGraphError::InvalidSegmentLayout);
    }
    Ok(())
}

pub(super) fn subtree_is_required(
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

pub(super) fn validate_segment_layout(
    segments: &[KernelSegment; 3],
    scratch: DeepScratchBinding,
    ist: IstStackLayout,
    thread_stacks: &[crate::memory::kernel_stack::KernelStackBounds],
    privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
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
    validate_ist_layout(segments, scratch.window_page, scratch.control_page, ist)?;
    validate_thread_stack_layout(
        segments,
        scratch.window_page,
        scratch.control_page,
        thread_stacks,
    )?;
    validate_privilege_entry_stack_layout(
        segments,
        scratch.window_page,
        scratch.control_page,
        ist,
        privilege_entry,
        thread_stacks,
    )
}

pub(super) fn read_entry<A: ActivationGraphAccess>(
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

pub(super) fn resolve_optional_leaf<A: ActivationGraphAccess>(
    access: &mut A,
    transition: bool,
    root: FrameAddress,
    page: u64,
    capabilities: PagingCapabilities,
) -> Result<Option<u64>, InactiveGraphError<A::Error>> {
    let mut table = root;
    for level in (0..=3).rev() {
        let index = ((page >> (12 + level * 9)) & 0x1ff) as usize;
        let entry = read_entry(access, transition, table, index)?;
        if entry & PRESENT == 0 {
            if entry != 0 {
                return Err(InactiveGraphError::InvalidEntry);
            }
            return if level == 0 {
                Ok(None)
            } else {
                Err(InactiveGraphError::MissingSegmentPage)
            };
        }
        table = validate_present_entry(entry, capabilities, level == 0)
            .map_err(|_| InactiveGraphError::InvalidEntry)?;
        if level != 0
            && entry & !(physical_mask(capabilities) | HARDWARE_MUTABLE) != PRESENT | WRITABLE
        {
            return Err(InactiveGraphError::InvalidEntry);
        }
        if level == 0 {
            return Ok(Some(entry));
        }
    }
    unreachable!("four-level walk always returns at the leaf")
}

pub(super) fn resolve_leaf<A: ActivationGraphAccess>(
    access: &mut A,
    transition: bool,
    root: FrameAddress,
    page: u64,
    capabilities: PagingCapabilities,
) -> Result<u64, InactiveGraphError<A::Error>> {
    resolve_optional_leaf(access, transition, root, page, capabilities)?
        .ok_or(InactiveGraphError::MissingSegmentPage)
}

pub(super) fn validate_scratch_path<A: ActivationGraphAccess>(
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

pub(super) trait KernelPageRoleValidation {
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
pub(super) fn validate_inactive_graph_with_workspace<
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
    ist: IstStackLayout,
    thread_stacks: &[crate::memory::kernel_stack::KernelStackBounds],
    privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
    capabilities: PagingCapabilities,
    pending: &mut [Option<PendingTable>; MAX_DEEP_TABLE_FRAMES],
    visited: &mut [u64; MAX_DEEP_TABLE_FRAMES],
) -> Result<(), InactiveGraphError<A::Error>> {
    validate_segment_layout(segments, scratch, ist, thread_stacks, privilege_entry).map_err(
        |error| match error {
            InactiveGraphError::InvalidSegmentLayout => InactiveGraphError::InvalidSegmentLayout,
            _ => unreachable!("layout validation has one error"),
        },
    )?;
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
                    if is_kernel_guard(ist, thread_stacks, privilege_entry, virtual_page) {
                        return Err(InactiveGraphError::MappedGuardPage);
                    }
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
            let expected = segment.expected_flags();
            if transition & !physical_mask(capabilities) & !HARDWARE_MUTABLE != expected {
                return Err(InactiveGraphError::MappingMismatch);
            }
            let transition_physical = transition & physical_mask(capabilities);
            kernel_roles
                .validate_kernel_page(transition_physical, segment.frame_role())
                .map_err(InactiveGraphError::FrameRole)?;
            let inactive = resolve_optional_leaf(
                access,
                false,
                root_frame(root, capabilities)?,
                page,
                capabilities,
            )?;
            if is_kernel_guard(ist, thread_stacks, privilege_entry, page) {
                if inactive.is_some() {
                    return Err(InactiveGraphError::MappedGuardPage);
                }
            } else {
                let inactive = inactive.ok_or(InactiveGraphError::MissingSegmentPage)?;
                if inactive & !physical_mask(capabilities) & !HARDWARE_MUTABLE != expected
                    || inactive & physical_mask(capabilities) != transition_physical
                {
                    return Err(InactiveGraphError::MappingMismatch);
                }
            }
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
pub(super) fn validate_inactive_graph<
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
    ist: IstStackLayout,
    privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
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
        ist,
        &[],
        privilege_entry,
        capabilities,
        &mut pending,
        &mut visited,
    )
}

pub(super) fn root_frame<E>(
    root: TableIdentity,
    capabilities: PagingCapabilities,
) -> Result<FrameAddress, InactiveGraphError<E>> {
    FrameAddress::new(root.physical_start(), capabilities.physical_limit())
        .map_err(|_| InactiveGraphError::InvalidEntry)
}
