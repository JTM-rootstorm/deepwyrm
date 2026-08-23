use super::super::physical::PhysicalAddressLimit;
use super::*;

type TestManager = FrameRoleManager<2, 16>;

fn manager(physical_start: u64, page_count: u64) -> TestManager {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(physical_start, page_count, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    FrameRoleManager::new(allocator).unwrap()
}

#[allow(
    unsafe_code,
    reason = "the host model never dereferences synthetic physical memory"
)]
fn allocate_zeroed(roles: &mut TestManager, page_count: u64) -> ZeroedGrant {
    let allocation = roles.allocate(page_count).unwrap();
    // SAFETY: the host model never dereferences the synthetic physical run.
    unsafe { roles.assume_zeroed(allocation) }.unwrap()
}

#[test]
fn free_xor_owned_and_stale_generation_are_exact() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let initial = roles.available_frames();
    let allocation = roles.allocate(2).unwrap();
    let stale = allocation.identity;
    let stale_range = allocation.range;
    assert_eq!(roles.available_frames(), initial - 2);
    assert_eq!(roles.role(stale), Ok(FrameRoleKind::AllocatedUninitialized));
    assert_eq!(roles.check_invariants(), Ok(()));

    roles.cancel_allocation(allocation).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.role(stale), Err(FrameRoleError::InvalidGrant));

    let replacement = roles.allocate(2).unwrap();
    assert_ne!(replacement.identity, stale);
    assert_eq!(replacement.range.start, BASE_PAGE_SIZE);
    let stale_grant = AllocationGrant {
        identity: stale,
        range: stale_range,
    };
    let error = roles.cancel_allocation(stale_grant).unwrap_err();
    assert_eq!(error.error(), FrameRoleError::InvalidGrant);
    assert_eq!(roles.available_frames(), initial - 2);
    roles.cancel_allocation(replacement).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn foreign_manager_rejection_returns_the_live_grant() {
    let mut owner = manager(BASE_PAGE_SIZE, 2);
    let mut foreign = manager(BASE_PAGE_SIZE * 8, 2);
    let allocation = owner.allocate(1).unwrap();

    let error = foreign.cancel_allocation(allocation).unwrap_err();
    assert_eq!(error.error(), FrameRoleError::ForeignManager);
    let allocation = error.into_grant();
    owner.cancel_allocation(allocation).unwrap();
    assert_eq!(owner.available_frames(), 2);
    assert_eq!(owner.check_invariants(), Ok(()));
}

#[test]
fn low_ceiling_grant_is_exact_and_failed_selection_preserves_manager_state() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let initial = roles.available_frames();
    let ceiling = BASE_PAGE_SIZE * 3;

    let grant = roles.allocate_below(1, ceiling).unwrap();
    let stale = grant.identity;
    assert_eq!(grant.physical_start(), BASE_PAGE_SIZE);
    assert_eq!(grant.byte_len(), BASE_PAGE_SIZE);
    assert!(grant.physical_start() + grant.byte_len() <= ceiling);
    assert_eq!(roles.available_frames(), initial - 1);
    roles.validate_allocation(&grant).unwrap();

    let available = roles.available_frames();
    assert_eq!(
        roles.allocate_below(2, ceiling),
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::NoFramesAvailable
        ))
    );
    assert_eq!(roles.available_frames(), available);
    roles.validate_allocation(&grant).unwrap();

    roles.cancel_allocation(grant).unwrap();
    let replacement = roles.allocate_below(1, ceiling).unwrap();
    assert_eq!(replacement.physical_start(), BASE_PAGE_SIZE);
    assert_ne!(replacement.identity, stale);
    roles.cancel_allocation(replacement).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));

    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(BASE_PAGE_SIZE, 2, limit).unwrap();
    let allocator = PhysicalFrameAllocator::<2>::from_candidates(&[candidate], limit, []).unwrap();
    let mut capacity_limited = FrameRoleManager::<2, 1>::new(allocator).unwrap();
    let first = capacity_limited.allocate(1).unwrap();
    let available = capacity_limited.available_frames();
    assert_eq!(
        capacity_limited.allocate_below(1, BASE_PAGE_SIZE * 3),
        Err(FrameRoleError::Capacity)
    );
    assert_eq!(capacity_limited.available_frames(), available);
    capacity_limited.cancel_allocation(first).unwrap();
}

#[test]
fn singleton_claim_is_one_shot_without_global_test_interference() {
    let claimed = AtomicBool::new(false);
    assert_eq!(claim_manager(&claimed), Ok(()));
    assert_eq!(
        claim_manager(&claimed),
        Err(FrameRoleInitializationError::AlreadyInitialized)
    );
}

#[test]
fn table_role_matrix_recovers_candidates_and_keeps_attached_committed_tables() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let initial = roles.available_frames();
    let owner = roles.create_table_owner().unwrap();
    let other_owner = roles.create_table_owner().unwrap();

    let root = allocate_zeroed(&mut roles, 1);
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root_identity = root.identity;
    let root = roles.commit_table(root, None).unwrap();
    assert_eq!(
        roles.role(root_identity),
        Ok(FrameRoleKind::PageTable {
            owner,
            level: TableLevel::Pml4,
        })
    );

    let duplicate_root = allocate_zeroed(&mut roles, 1);
    let duplicate_root = roles
        .prepare_table(duplicate_root, owner, TableLevel::Pml4)
        .unwrap();
    let error = roles.commit_table(duplicate_root, None).unwrap_err();
    assert_eq!(error.error(), FrameRoleError::DuplicateTableRoot);
    roles.cancel_table_candidate(error.into_grant()).unwrap();

    let foreign_child = allocate_zeroed(&mut roles, 1);
    let foreign_child = roles
        .prepare_table(foreign_child, other_owner, TableLevel::Pdpt)
        .unwrap();
    let error = roles.commit_table(foreign_child, Some(root)).unwrap_err();
    assert_eq!(error.error(), FrameRoleError::InvalidTableParent);
    roles.cancel_table_candidate(error.into_grant()).unwrap();

    let wrong_level = allocate_zeroed(&mut roles, 1);
    let wrong_level = roles
        .prepare_table(wrong_level, owner, TableLevel::Pd)
        .unwrap();
    let error = roles.commit_table(wrong_level, Some(root)).unwrap_err();
    assert_eq!(error.error(), FrameRoleError::InvalidTableParent);
    roles.cancel_table_candidate(error.into_grant()).unwrap();

    let child = allocate_zeroed(&mut roles, 1);
    let child = roles.prepare_table(child, owner, TableLevel::Pdpt).unwrap();
    let child_identity = child.identity;
    let child = roles.commit_table(child, Some(root)).unwrap();
    assert_eq!(child.owner(), owner);
    assert_eq!(child.level(), TableLevel::Pdpt);
    assert_eq!(
        roles.role(child_identity),
        Ok(FrameRoleKind::PageTable {
            owner,
            level: TableLevel::Pdpt,
        })
    );

    assert_eq!(roles.available_frames(), initial - 2);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model treats the empty synthetic root as retired before consuming its reclaim proof"
)]
fn empty_committed_root_reclaim_returns_frames_and_rejects_attached_children() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let initial = roles.available_frames();
    let owner = roles.create_table_owner().unwrap();
    let root = allocate_zeroed(&mut roles, 1);
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    assert_eq!(roles.available_frames(), initial - 1);
    let empty = roles.prepare_empty_table_root(root).unwrap();
    unsafe { roles.reclaim_preflighted_empty_table_root(empty) };
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));

    let owner = roles.create_table_owner().unwrap();
    let root = allocate_zeroed(&mut roles, 1);
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let child = allocate_zeroed(&mut roles, 1);
    let child = roles.prepare_table(child, owner, TableLevel::Pdpt).unwrap();
    let _child = roles.commit_table(child, Some(root)).unwrap();
    assert_eq!(
        roles.prepare_empty_table_root(root).map(|_| ()),
        Err(FrameRoleError::InvalidTableParent)
    );
    assert_eq!(roles.available_frames(), initial - 2);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model treats the exact empty hierarchy as atomically disconnected and retired"
)]
fn exact_empty_hierarchy_proof_reclaims_descendants_bottom_up() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let initial = roles.available_frames();
    let owner = roles.create_table_owner().unwrap();

    let root = allocate_zeroed(&mut roles, 1);
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let pdpt = allocate_zeroed(&mut roles, 1);
    let pdpt = roles.prepare_table(pdpt, owner, TableLevel::Pdpt).unwrap();
    let pdpt = roles.commit_table(pdpt, Some(root)).unwrap();
    let pd = allocate_zeroed(&mut roles, 1);
    let pd = roles.prepare_table(pd, owner, TableLevel::Pd).unwrap();
    let pd = roles.commit_table(pd, Some(pdpt)).unwrap();
    let pt = allocate_zeroed(&mut roles, 1);
    let pt = roles.prepare_table(pt, owner, TableLevel::Pt).unwrap();
    let pt = roles.commit_table(pt, Some(pd)).unwrap();

    let mut incomplete = roles.begin_empty_table_hierarchy(root).unwrap();
    roles
        .observe_empty_table_child(&mut incomplete, root, pdpt)
        .unwrap();
    assert!(matches!(
        roles.finish_empty_table_hierarchy(incomplete),
        Err(FrameRoleError::InvalidTableParent)
    ));

    let mut hierarchy = roles.begin_empty_table_hierarchy(root).unwrap();
    roles
        .observe_empty_table_child(&mut hierarchy, root, pdpt)
        .unwrap();
    assert_eq!(
        roles.observe_empty_table_child(&mut hierarchy, root, pdpt),
        Err(FrameRoleError::InvalidTableParent)
    );
    roles
        .observe_empty_table_child(&mut hierarchy, pdpt, pd)
        .unwrap();
    roles
        .observe_empty_table_child(&mut hierarchy, pd, pt)
        .unwrap();
    let hierarchy = roles.finish_empty_table_hierarchy(hierarchy).unwrap();
    let empty_root = unsafe { roles.reclaim_preflighted_empty_table_hierarchy(hierarchy) };
    unsafe { roles.reclaim_preflighted_empty_table_root(empty_root) };

    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn staged_root_requires_a_unique_candidate_and_can_publish_after_rollback() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let owner = roles.create_table_owner().unwrap();
    let first = allocate_zeroed(&mut roles, 1);
    let first = roles.prepare_table(first, owner, TableLevel::Pml4).unwrap();
    let second = allocate_zeroed(&mut roles, 1);
    let second = roles
        .prepare_table(second, owner, TableLevel::Pml4)
        .unwrap();

    let rejected = roles.stage_table_commit(first, None).unwrap_err();
    assert_eq!(rejected.error(), FrameRoleError::DuplicateTableRoot);
    let first = rejected.into_grant();
    roles.cancel_table_candidate(second).unwrap();

    let staged = roles.stage_table_commit(first, None).unwrap();
    let root = roles.publish_staged_table(staged);
    assert_eq!(root.owner(), owner);
    assert_eq!(root.level(), TableLevel::Pml4);
    assert_eq!(roles.validate_table_identity(root), Ok(()));
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[should_panic(expected = "staged table commit became invalid before publication")]
fn staged_child_panics_closed_if_its_candidate_parent_is_cancelled() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let owner = roles.create_table_owner().unwrap();
    let parent = allocate_zeroed(&mut roles, 1);
    let parent = roles
        .prepare_table(parent, owner, TableLevel::Pdpt)
        .unwrap();
    let child = allocate_zeroed(&mut roles, 1);
    let child = roles.prepare_table(child, owner, TableLevel::Pd).unwrap();
    let staged = roles
        .stage_table_commit(child, Some(TableCommitParent::Candidate(&parent)))
        .unwrap();

    roles.cancel_table_candidate(parent).unwrap();
    let _ = roles.publish_staged_table(staged);
}

#[test]
#[should_panic(expected = "staged table commit became invalid before publication")]
fn staged_child_cannot_publish_before_its_candidate_parent() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let owner = roles.create_table_owner().unwrap();
    let parent = allocate_zeroed(&mut roles, 1);
    let parent = roles
        .prepare_table(parent, owner, TableLevel::Pdpt)
        .unwrap();
    let child = allocate_zeroed(&mut roles, 1);
    let child = roles.prepare_table(child, owner, TableLevel::Pd).unwrap();
    let staged = roles
        .stage_table_commit(child, Some(TableCommitParent::Candidate(&parent)))
        .unwrap();

    let _ = roles.publish_staged_table(staged);
}

#[test]
#[should_panic(expected = "staged table commit became invalid before publication")]
fn foreign_manager_cannot_publish_a_staged_table_token() {
    let mut owner = manager(BASE_PAGE_SIZE, 2);
    let owner_key = owner.create_table_owner().unwrap();
    let root = allocate_zeroed(&mut owner, 1);
    let root = owner
        .prepare_table(root, owner_key, TableLevel::Pml4)
        .unwrap();
    let staged = owner.stage_table_commit(root, None).unwrap();

    let mut foreign = manager(BASE_PAGE_SIZE * 8, 2);
    let _ = foreign.publish_staged_table(staged);
}

#[test]
fn rejected_multi_page_table_transition_returns_zeroed_grant_for_rollback() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let initial = roles.available_frames();
    let owner = roles.create_table_owner().unwrap();
    let zeroed = allocate_zeroed(&mut roles, 2);

    let error = roles
        .prepare_table(zeroed, owner, TableLevel::Pml4)
        .unwrap_err();
    assert_eq!(error.error(), FrameRoleError::WrongRole);
    roles.cancel_zeroed(error.into_grant()).unwrap();
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the synthetic test attests complete architecture initialization"
)]
fn architecture_bootstrap_grant_retains_exact_low_page_ownership() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let grant = roles.allocate_below(1, 0x10_0000).unwrap();
    let physical_start = grant.physical_start();
    let retained = unsafe {
        roles.assume_architecture_bootstrap_initialized(
            grant,
            ArchitectureBootstrapKind::X86ApTrampoline,
        )
    }
    .unwrap();

    assert_ne!(physical_start, 0);
    assert!(physical_start < 0x10_0000);
    assert_eq!(retained.physical_start(), physical_start);
    assert_eq!(retained.byte_len(), BASE_PAGE_SIZE);
    assert_eq!(retained.kind(), ArchitectureBootstrapKind::X86ApTrampoline);
    assert_eq!(roles.validate_architecture_bootstrap(&retained), Ok(()));
    assert_eq!(
        roles.role(retained.identity),
        Ok(FrameRoleKind::ArchitectureBootstrap(
            ArchitectureBootstrapKind::X86ApTrampoline
        ))
    );
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the test supplies synthetic boot-provenance attestations"
)]
fn external_roles_are_disjoint_and_immutable_backing_is_read_only() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let transition = PhysicalRange::new(0x20_000, BASE_PAGE_SIZE).unwrap();
    // SAFETY: the synthetic external range is disjoint from the allocator.
    let transition = unsafe {
        roles.import_external(
            transition,
            ExternalFrameRole::TransitionTable { table_index: 0 },
        )
    }
    .unwrap();
    assert_eq!(
        roles.role(transition),
        Ok(FrameRoleKind::External(
            ExternalFrameRole::TransitionTable { table_index: 0 }
        ))
    );

    let overlapping_external = PhysicalRange::new(0x20_000, BASE_PAGE_SIZE).unwrap();
    // SAFETY: this deliberately repeats validated synthetic provenance to
    // prove that the registry still rejects the overlapping role.
    assert_eq!(
        unsafe {
            roles.import_external(
                overlapping_external,
                ExternalFrameRole::KernelImage {
                    segment: KernelImageSegment::Text,
                },
            )
        },
        Err(FrameRoleError::Overlap)
    );

    let allocator_overlap = PhysicalRange::new(BASE_PAGE_SIZE, BASE_PAGE_SIZE).unwrap();
    // SAFETY: the intentionally conflicting input exercises the manager's
    // independent allocator-exclusion check.
    assert_eq!(
        unsafe {
            roles.import_external(
                allocator_overlap,
                ExternalFrameRole::KernelImage {
                    segment: KernelImageSegment::WritableData,
                },
            )
        },
        Err(FrameRoleError::ExternalAllocatorOverlap)
    );

    let unaligned = PhysicalRange::new(0x28_001, BASE_PAGE_SIZE).unwrap();
    // SAFETY: the deliberately unaligned synthetic input proves that an
    // external role cannot capture bytes before its stated provenance.
    assert_eq!(
        unsafe {
            roles.import_external(
                unaligned,
                ExternalFrameRole::KernelImage {
                    segment: KernelImageSegment::ReadOnlyData,
                },
            )
        },
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::InvalidPageRange
        ))
    );

    let unaligned_end = PhysicalRange::new(0x2c_000, BASE_PAGE_SIZE + 1).unwrap();
    // SAFETY: the deliberately non-page-sized synthetic input proves a
    // generic external role cannot capture an unattested trailing tail.
    assert_eq!(
        unsafe {
            roles.import_external(
                unaligned_end,
                ExternalFrameRole::KernelImage {
                    segment: KernelImageSegment::ReadOnlyData,
                },
            )
        },
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::InvalidPageRange
        ))
    );

    let module_range = PhysicalRange::new(0x24_000, BASE_PAGE_SIZE + 1).unwrap();
    // SAFETY: the synthetic immutable range is page-aligned, initialized,
    // and disjoint from both the allocator and transition role.
    let module = unsafe { roles.import_immutable_module(module_range, 7) }.unwrap();
    assert_eq!(module.byte_len(), BASE_PAGE_SIZE * 2);
    assert_eq!(
        roles.validate_object_backing(
            module.identity(),
            module.physical_start(),
            module.byte_len(),
            false,
        ),
        Ok(())
    );
    assert_eq!(
        roles.validate_object_backing(
            module.identity(),
            module.physical_start(),
            module.byte_len(),
            true,
        ),
        Err(FrameRoleError::ReadOnlyBacking)
    );
    let error = roles.cancel_object_backing(module).unwrap_err();
    assert_eq!(error.error(), FrameRoleError::WrongRole);
    assert!(matches!(
        error.into_grant().kind(),
        ObjectBackingKind::ImmutableModule { module_index: 7 }
    ));
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic ranges model live-attested linker segment provenance"
)]
fn kernel_image_roles_stage_atomically_and_reject_overlap() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let text = PhysicalRange::new(0x30_000, BASE_PAGE_SIZE).unwrap();
    let rodata = PhysicalRange::new(0x31_000, BASE_PAGE_SIZE).unwrap();
    let data = PhysicalRange::new(0x32_000, BASE_PAGE_SIZE).unwrap();
    let declarations = [
        (text, KernelImageSegment::Text),
        (rodata, KernelImageSegment::ReadOnlyData),
        (data, KernelImageSegment::WritableData),
    ];
    let staged = unsafe { roles.stage_kernel_image_roles(declarations) }.unwrap();

    assert_eq!(
        roles.validate_kernel_image_page(0x30_000, KernelImageSegment::Text),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.publish_staged_kernel_image(staged);
    assert_eq!(
        roles.validate_kernel_image_page(0x30_000, KernelImageSegment::Text),
        Ok(())
    );
    assert_eq!(roles.check_invariants(), Ok(()));

    let fresh = manager(BASE_PAGE_SIZE, 4);
    let overlapping = [
        (text, KernelImageSegment::Text),
        (text, KernelImageSegment::ReadOnlyData),
        (data, KernelImageSegment::WritableData),
    ];
    assert_eq!(
        unsafe { fresh.stage_kernel_image_roles(overlapping) },
        Err(FrameRoleError::Overlap)
    );
    assert_eq!(
        fresh.validate_kernel_image_page(0x30_000, KernelImageSegment::Text),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(fresh.check_invariants(), Ok(()));
}

#[test]
#[should_panic(expected = "staged kernel image roles belong to another manager")]
#[allow(
    unsafe_code,
    reason = "synthetic ranges model live-attested linker segment provenance"
)]
fn staged_kernel_image_roles_reject_a_foreign_manager() {
    let source = manager(BASE_PAGE_SIZE, 4);
    let mut foreign = manager(0x10_000, 4);
    let staged = unsafe {
        source.stage_kernel_image_roles([
            (
                PhysicalRange::new(0x30_000, BASE_PAGE_SIZE).unwrap(),
                KernelImageSegment::Text,
            ),
            (
                PhysicalRange::new(0x31_000, BASE_PAGE_SIZE).unwrap(),
                KernelImageSegment::ReadOnlyData,
            ),
            (
                PhysicalRange::new(0x32_000, BASE_PAGE_SIZE).unwrap(),
                KernelImageSegment::WritableData,
            ),
        ])
    }
    .unwrap();
    foreign.publish_staged_kernel_image(staged);
}

#[test]
#[should_panic(expected = "staged kernel image role changed before publication")]
#[allow(
    unsafe_code,
    reason = "synthetic overlap models hostile mutation between stage and publication"
)]
fn staged_kernel_image_roles_revalidate_intervening_overlap() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let declarations = [
        (
            PhysicalRange::new(0x30_000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::Text,
        ),
        (
            PhysicalRange::new(0x31_000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::ReadOnlyData,
        ),
        (
            PhysicalRange::new(0x32_000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::WritableData,
        ),
    ];
    let staged = unsafe { roles.stage_kernel_image_roles(declarations) }.unwrap();
    unsafe {
        roles
            .import_external(
                declarations[0].0,
                ExternalFrameRole::KernelImage {
                    segment: KernelImageSegment::Text,
                },
            )
            .unwrap();
    }
    roles.publish_staged_kernel_image(staged);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model supplies an exact synthetic live transition-table set"
)]
fn transition_table_set_import_is_atomic_and_exact() {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(BASE_PAGE_SIZE, 1, limit).unwrap();
    let allocator = PhysicalFrameAllocator::<1>::from_candidates(&[candidate], limit, []).unwrap();
    let mut capacity_limited = FrameRoleManager::<1, 1>::new(allocator).unwrap();

    // SAFETY: both synthetic external frames are page-aligned, retained,
    // strictly ordered, and disjoint from the allocator.
    assert_eq!(
        unsafe { capacity_limited.import_transition_tables::<4>(&[0x20_000, 0x21_000]) },
        Err(FrameRoleError::Capacity)
    );
    assert_eq!(capacity_limited.check_invariants(), Ok(()));

    // A successful import of the first frame proves the failed batch did
    // not partially consume the sole role slot.
    // SAFETY: this one-frame set has the same synthetic provenance.
    let imported = unsafe { capacity_limited.import_transition_tables::<4>(&[0x20_000]) }.unwrap();
    assert_eq!(imported.len(), 1);
    let record = capacity_limited
        .roles
        .iter()
        .filter_map(|slot| slot.record)
        .find(|record| record.range.start == 0x20_000)
        .unwrap();
    assert_eq!(
        record.role.kind(),
        FrameRoleKind::External(ExternalFrameRole::TransitionTable { table_index: 0 })
    );
    assert_eq!(capacity_limited.check_invariants(), Ok(()));

    let allocator = PhysicalFrameAllocator::<1>::from_candidates(&[candidate], limit, []).unwrap();
    let mut roles = FrameRoleManager::<1, 4>::new(allocator).unwrap();
    // SAFETY: the deliberately duplicated set exercises prepublication
    // rejection; no role may be installed.
    assert_eq!(
        unsafe { roles.import_transition_tables::<4>(&[0x30_000, 0x30_000]) },
        Err(FrameRoleError::Overlap)
    );
    // SAFETY: the corrected exact set is ordered and allocator-disjoint.
    let imported = unsafe { roles.import_transition_tables::<4>(&[0x30_000, 0x31_000]) }.unwrap();
    assert_eq!(imported.len(), 2);
    for index in 0..2 {
        let record = roles
            .roles
            .iter()
            .filter_map(|slot| slot.record)
            .find(|record| record.range.start == 0x30_000 + (index as u64) * BASE_PAGE_SIZE)
            .unwrap();
        assert_eq!(
            record.role.kind(),
            FrameRoleKind::External(ExternalFrameRole::TransitionTable {
                table_index: index as u32,
            })
        );
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn object_backing_identity_cannot_validate_a_table_role() {
    let mut roles = manager(BASE_PAGE_SIZE, 4);
    let owner = roles.create_table_owner().unwrap();
    let table = allocate_zeroed(&mut roles, 1);
    let table = roles.prepare_table(table, owner, TableLevel::Pml4).unwrap();
    let table = roles.commit_table(table, None).unwrap();
    let confused = BackingIdentity(table.role);

    assert_eq!(
        roles.validate_object_backing(confused, table.physical_start(), BASE_PAGE_SIZE, false,),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic malicious map classification exercises pre-allocation kernel exclusion"
)]
fn kernel_image_allocator_overlap_rejects_without_allocation() {
    let roles = manager(BASE_PAGE_SIZE, 8);
    let available = roles.available_frames();
    let declarations = [
        (
            PhysicalRange::new(BASE_PAGE_SIZE, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::Text,
        ),
        (
            PhysicalRange::new(0x20_000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::ReadOnlyData,
        ),
        (
            PhysicalRange::new(0x21_000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::WritableData,
        ),
    ];
    assert_eq!(
        unsafe { roles.stage_kernel_image_roles(declarations) },
        Err(FrameRoleError::ExternalAllocatorOverlap)
    );
    assert_eq!(roles.available_frames(), available);
    assert_eq!(roles.check_invariants(), Ok(()));
}
