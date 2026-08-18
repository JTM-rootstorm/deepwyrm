#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
use super::*;

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
pub(super) fn build_and_bind_deep_root<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    mut mapper: LiveTransitionMapper<'a>,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    memory_witness: BootstrapMemoryWitness<'_>,
) -> Result<InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>, DeepRootBuildFailure> {
    let result = (|| {
        let segments =
            live_kernel_segments().map_err(|_| DeepRootBuildError::InvalidKernelLayout)?;
        let ist = crate::arch::x86_64::linked_ist_stack_layout()
            .map_err(|_| DeepRootBuildError::InvalidKernelLayout)?;
        let thread_stacks = crate::arch::x86_64::linked_thread_kernel_stack_layout()
            .map_err(|_| DeepRootBuildError::InvalidKernelLayout)?;
        let capabilities = mapper.capabilities();
        let window_page = mapper.temporary_virtual_address();
        let control_page = window_page
            .checked_add(PAGE_SIZE)
            .ok_or(DeepRootBuildError::InvalidKernelLayout)?;
        if window_page & ADDRESS_OFFSET_MASK != 0
            || ((window_page >> 12) & 0x1ff) == 0x1ff
            || window_page >> 21 != control_page >> 21
            || validate_ist_layout(&segments, window_page, control_page, ist).is_err()
            || validate_thread_stack_layout(&segments, window_page, control_page, &thread_stacks)
                .is_err()
        {
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
                if is_kernel_guard(ist, &thread_stacks, page) {
                    let guard_pt = ensure_leaf_table(
                        &mut mapper,
                        roles,
                        owner,
                        root_identity,
                        page,
                        edges,
                        &mut edge_count,
                    )?;
                    let guard_index = ((page >> 12) & 0x1ff) as usize;
                    if mapper
                        .read_owned_table_entry(roles, guard_pt, guard_index)
                        .map_err(|_| DeepRootBuildError::Transition)?
                        != 0
                    {
                        return Err(DeepRootBuildError::MappingMismatch);
                    }
                    page = page
                        .checked_add(PAGE_SIZE)
                        .ok_or(DeepRootBuildError::InvalidKernelLayout)?;
                    continue;
                }
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
