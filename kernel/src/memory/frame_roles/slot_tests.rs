//! Behaviour of the stored role slot (DW2 §12.3): issue order, the free
//! list, the root list, packing, and the invariants that check them.

extern crate std;

use super::super::physical::PhysicalAddressLimit;
use super::*;
use std::{boxed::Box, vec, vec::Vec};

type TestManager = FrameRoleManager<8, 16>;

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

/// A leaked, 8-aligned buffer standing in for the grown table's run.
fn grown_run(bytes: u64) -> *mut u8 {
    let words = usize::try_from(bytes.div_ceil(8)).unwrap();
    Box::leak(vec![0_u64; words].into_boxed_slice())
        .as_mut_ptr()
        .cast()
}

/// Grows from one staged run, as the recorded issue order was taken.
fn grow(roles: &mut TestManager) -> (RoleTableLayout, usize) {
    let (layout, slots) = test_support::grow_in_leaked_runs(roles, 1);
    (layout, slots[0])
}

/// The three slots the kernel-image staging would occupy next.
#[allow(
    unsafe_code,
    reason = "the host model stages synthetic kernel-image ranges outside allocator RAM"
)]
fn staged_image_slots(roles: &TestManager) -> [usize; 3] {
    let declarations = [
        (
            PhysicalRange::new(0x1000_0000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::Text,
        ),
        (
            PhysicalRange::new(0x1000_1000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::ReadOnlyData,
        ),
        (
            PhysicalRange::new(0x1000_2000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::WritableData,
        ),
    ];
    // SAFETY: the ranges lie outside allocator RAM and are never published.
    unsafe { roles.stage_kernel_image_roles(declarations) }
        .unwrap()
        .slots
}

/// The slot an identity names.
fn slot_number(identity: FrameRoleIdentity) -> usize {
    (identity.raw as u32 - 1) as usize
}

/// Drives a scripted sequence of allocations, frees, a spent generation,
/// table commits, growth and more churn, and returns every slot number the
/// manager issued, in order.
fn issued_slots() -> Vec<usize> {
    let mut roles = manager(BASE_PAGE_SIZE, 512);
    let mut issued = Vec::new();
    let take = |roles: &mut TestManager, issued: &mut Vec<usize>| {
        let grant = roles.allocate(1).unwrap();
        issued.push(slot_number(grant.identity));
        grant
    };

    // Boot: five allocations, two freed out of order, three more.
    let mut held: Vec<AllocationGrant> = (0..5).map(|_| take(&mut roles, &mut issued)).collect();
    let third = held.remove(3);
    let first = held.remove(1);
    roles.cancel_allocation(third).unwrap();
    roles.cancel_allocation(first).unwrap();
    for _ in 0..3 {
        let grant = take(&mut roles, &mut issued);
        held.push(grant);
    }

    // A slot driven to its last generation is used once more, then retired.
    let spent = held.remove(0);
    let spent_slot = slot_number(spent.identity);
    roles.cancel_allocation(spent).unwrap();
    roles.test_set_generation(spent_slot, u32::MAX - 1);
    let last = take(&mut roles, &mut issued);
    roles.cancel_allocation(last).unwrap();
    let after = take(&mut roles, &mut issued);
    held.push(after);

    // A root and a child table; the candidate of a second child cancelled.
    let owner = roles.create_table_owner().unwrap();
    let root = allocate_zeroed(&mut roles, 1);
    issued.push(slot_number(root.identity));
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let child = allocate_zeroed(&mut roles, 1);
    issued.push(slot_number(child.identity));
    let child = roles.prepare_table(child, owner, TableLevel::Pdpt).unwrap();
    let _child = roles.commit_table(child, Some(root)).unwrap();
    let dropped = allocate_zeroed(&mut roles, 1);
    issued.push(slot_number(dropped.identity));
    let dropped = roles
        .prepare_table(dropped, owner, TableLevel::Pdpt)
        .unwrap();
    roles.cancel_table_candidate(dropped).unwrap();

    // The kernel-image staging's view of the next three slots.
    issued.extend(staged_image_slots(&roles));

    // Growth, then churn above and below the boot table.
    let (_, storage) = grow(&mut roles);
    issued.push(storage);
    let mut grown: Vec<AllocationGrant> = (0..6).map(|_| take(&mut roles, &mut issued)).collect();
    for index in [4, 1, 0] {
        let grant = grown.remove(index);
        roles.cancel_allocation(grant).unwrap();
    }
    let boot = held.remove(2);
    roles.cancel_allocation(boot).unwrap();
    for _ in 0..4 {
        let grant = take(&mut roles, &mut issued);
        grown.push(grant);
    }
    issued.extend(staged_image_slots(&roles));
    assert_eq!(roles.check_invariants(), Ok(()));
    issued
}

/// The numbers were recorded by running [`issued_slots`] on the code
/// before §12.3 (Deepwyrm `5417329`, with its free-slot stack).
#[test]
fn slots_are_issued_in_the_same_order_as_before() {
    assert_eq!(
        issued_slots(),
        [
            0, 1, 2, 3, 4, 1, 3, 5, 0, 6, 7, 8, 9, 9, 10, 11, 9, 16, 17, 18, 19, 20, 21, 1, 16, 17,
            20, 22, 23, 24,
        ]
    );
}

/// Occupies the next free slot with `record`, bypassing the allocator, and
/// returns the slot.
fn occupy_next(roles: &mut TestManager, record: RoleRecord) -> usize {
    let (slot, generation) = roles.next_slot().unwrap();
    roles.occupy(slot, generation, record);
    slot
}

fn pages(start: u64, count: u64) -> PageRange {
    PageRange {
        start,
        end: start + count * BASE_PAGE_SIZE,
    }
}

/// One role of every kind, with owners and parents of `roles`' domain and
/// links at their limits.
fn every_role(roles: &TestManager) -> [FrameRole; 21] {
    let owner = TableOwnerKey {
        domain: roles.domain,
        raw: u64::MAX,
    };
    let parent = roles.identity(9, u32::MAX).unwrap();
    let link = ChainLink {
        head: u64::MAX,
        object_page: u64::MAX - 1,
        next: u64::MAX - 2,
    };
    let entry = IndexEntryLink {
        owner: u64::MAX,
        place: u64::MAX - 1,
    };
    [
        FrameRole::AllocatedUninitialized,
        FrameRole::Zeroed,
        FrameRole::BackingAllocated(link),
        FrameRole::ObjectBacking(link),
        FrameRole::ArchitectureBootstrap(ArchitectureBootstrapKind::X86ApTrampoline),
        FrameRole::ArchitectureBootstrap(ArchitectureBootstrapKind::X86VtdTable),
        FrameRole::TableCandidate {
            owner,
            level: TableLevel::Pml4,
        },
        FrameRole::TableCandidate {
            owner,
            level: TableLevel::Pt,
        },
        FrameRole::PageTable {
            owner,
            level: TableLevel::Pml4,
            parent: None,
        },
        FrameRole::PageTable {
            owner,
            level: TableLevel::Pd,
            parent: Some(parent),
        },
        FrameRole::External(ExternalFrameRole::TransitionTable {
            table_index: u32::MAX,
        }),
        FrameRole::External(ExternalFrameRole::KernelImage {
            segment: KernelImageSegment::WritableData,
        }),
        FrameRole::ExternalImmutableModule {
            module_index: u32::MAX,
        },
        FrameRole::ExternalDeviceMmio,
        FrameRole::RoleTableStorage,
        FrameRole::IndexRoot(IndexRootLink {
            pages: u64::MAX,
            levels: 4,
            state: IndexRootState::OnDemand,
        }),
        FrameRole::IndexRoot(IndexRootLink {
            pages: u64::MAX,
            levels: 4,
            state: IndexRootState::EagerAllocated,
        }),
        FrameRole::IndexRoot(IndexRootLink {
            pages: 1,
            levels: 1,
            state: IndexRootState::Eager,
        }),
        FrameRole::IndexRoot(IndexRootLink {
            pages: 1 << 36,
            levels: 4,
            state: IndexRootState::EagerFreeing,
        }),
        FrameRole::IndexNode(entry),
        FrameRole::ObjectPage(entry),
    ]
}

#[test]
fn a_record_of_every_role_kind_survives_a_store_and_a_read() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let kinds = every_role(&roles);
    // One page, and the most a slot stores, at the top of a 52-bit space.
    let ranges = [
        pages(BASE_PAGE_SIZE, 1),
        pages(
            (1 << 52) - u64::from(u32::MAX) * BASE_PAGE_SIZE,
            u64::from(u32::MAX),
        ),
    ];
    for range in ranges {
        for role in kinds {
            let record = RoleRecord { range, role };
            let free = roles.free_slot_count;
            let slot = occupy_next(&mut roles, record);
            let view = roles.slot_view(slot);
            assert_eq!(view.record, Some(record));
            assert_eq!((view.mark, view.tables), (0, 0));
            assert_eq!(roles.free_slot_count, free - 1);
            // A replacement by itself is a read and a store again.
            roles.replace_record(slot, record);
            assert_eq!(roles.slot_view(slot).record, Some(record));
            roles.vacate(slot);
            assert_eq!(roles.slot_view(slot).record, None);
            assert_eq!(roles.free_slot_count, free);
            assert_eq!(roles.next_slot().unwrap().0, slot);
        }
    }
}

#[test]
#[should_panic(expected = "a stored run has at most u32::MAX pages")]
fn a_dynamic_role_longer_than_u32_max_pages_is_refused() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    occupy_next(
        &mut roles,
        RoleRecord {
            range: pages(1 << 40, u64::from(u32::MAX) + 1),
            role: FrameRole::Zeroed,
        },
    );
}

#[test]
#[should_panic(expected = "a stored table owner belongs to another manager")]
fn an_owner_of_another_manager_is_refused() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let owner = TableOwnerKey {
        domain: roles.domain + 1,
        raw: 1,
    };
    occupy_next(
        &mut roles,
        RoleRecord {
            range: pages(BASE_PAGE_SIZE, 1),
            role: FrameRole::TableCandidate {
                owner,
                level: TableLevel::Pd,
            },
        },
    );
}

#[test]
#[should_panic(expected = "a stored parent table belongs to another manager")]
fn a_parent_of_another_manager_is_refused() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let owner = roles.create_table_owner().unwrap();
    let parent = FrameRoleIdentity {
        domain: roles.domain + 1,
        raw: 1,
    };
    occupy_next(
        &mut roles,
        RoleRecord {
            range: pages(BASE_PAGE_SIZE, 1),
            role: FrameRole::PageTable {
                owner,
                level: TableLevel::Pdpt,
                parent: Some(parent),
            },
        },
    );
}

#[test]
#[should_panic(expected = "a stored PML4 has a parent table")]
fn a_pml4_with_a_parent_is_refused() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let owner = roles.create_table_owner().unwrap();
    let parent = roles.identity(3, 1).unwrap();
    occupy_next(
        &mut roles,
        RoleRecord {
            range: pages(BASE_PAGE_SIZE, 1),
            role: FrameRole::PageTable {
                owner,
                level: TableLevel::Pml4,
                parent: Some(parent),
            },
        },
    );
}

#[test]
#[should_panic(expected = "a stored table below a PML4 has no parent table")]
fn a_table_below_a_pml4_without_a_parent_is_refused() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let owner = roles.create_table_owner().unwrap();
    occupy_next(
        &mut roles,
        RoleRecord {
            range: pages(BASE_PAGE_SIZE, 1),
            role: FrameRole::PageTable {
                owner,
                level: TableLevel::Pt,
                parent: None,
            },
        },
    );
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model imports synthetic device ranges it never dereferences"
)]
fn an_external_role_longer_than_u32_max_pages_is_refused_with_capacity() {
    let limit = PhysicalAddressLimit::new(1_u64 << 52).unwrap();
    let candidate = PageRange::from_page_count(BASE_PAGE_SIZE, 8, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    let mut roles = TestManager::new(allocator).unwrap();
    let free = roles.free_slot_count;
    let longest = u64::from(u32::MAX) * BASE_PAGE_SIZE;
    let too_long = PhysicalRange::new(1 << 46, longest + BASE_PAGE_SIZE).unwrap();
    // SAFETY: a synthetic BAR outside allocator RAM, never dereferenced.
    let refused = unsafe { roles.import_device_mmio(too_long) };
    assert_eq!(refused, Err(FrameRoleError::Capacity));
    assert_eq!(roles.free_slot_count, free);
    assert_eq!(roles.check_invariants(), Ok(()));
    // SAFETY: as above.
    let longest =
        unsafe { roles.import_device_mmio(PhysicalRange::new(1 << 46, longest).unwrap()) }.unwrap();
    assert_eq!(longest.byte_len(), u64::from(u32::MAX) * BASE_PAGE_SIZE);
    assert_eq!(roles.free_slot_count, free - 1);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model stages synthetic kernel-image ranges outside allocator RAM"
)]
fn a_kernel_image_segment_longer_than_u32_max_pages_is_refused_with_capacity() {
    let limit = PhysicalAddressLimit::new(1_u64 << 52).unwrap();
    let candidate = PageRange::from_page_count(BASE_PAGE_SIZE, 8, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    let roles = TestManager::new(allocator).unwrap();
    let too_long = (u64::from(u32::MAX) + 1) * BASE_PAGE_SIZE;
    let declarations = [
        (
            PhysicalRange::new(1 << 46, too_long).unwrap(),
            KernelImageSegment::Text,
        ),
        (
            PhysicalRange::new(1 << 47, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::ReadOnlyData,
        ),
        (
            PhysicalRange::new((1 << 47) + BASE_PAGE_SIZE, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::WritableData,
        ),
    ];
    // SAFETY: synthetic ranges outside allocator RAM, never published.
    let refused = unsafe { roles.stage_kernel_image_roles(declarations) };
    assert_eq!(refused, Err(FrameRoleError::Capacity));
}

/// A committed PML4 and one child for a fresh owner.
fn root_with_child(roles: &mut TestManager) -> (TableIdentity, TableIdentity) {
    let owner = roles.create_table_owner().unwrap();
    let root = allocate_zeroed(roles, 1);
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let child = allocate_zeroed(roles, 1);
    let child = roles.prepare_table(child, owner, TableLevel::Pdpt).unwrap();
    let child = roles.commit_table(child, Some(root)).unwrap();
    (root, child)
}

#[test]
fn a_tables_mark_and_count_survive_a_change_from_table_to_table_and_are_zero_after_any_other() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let (root, child) = root_with_child(&mut roles);
    let slot = roles.slot(root.role).unwrap();
    let child_slot = roles.slot(child.role).unwrap();
    let proof = roles.begin_empty_table_hierarchy(root).unwrap();
    let epoch = proof.epoch;
    let view = roles.slot_view(slot);
    assert_eq!((view.mark, view.tables), (epoch, 1));

    // Table to table: the same table stored again, and as another committed
    // table of its owner; the mark and the count stay.
    let record = view.record.unwrap();
    roles.replace_record(slot, record);
    let view = roles.slot_view(slot);
    assert_eq!((view.mark, view.tables), (epoch, 1));
    let child_record = roles.slot_view(child_slot).record.unwrap();
    let as_child = RoleRecord {
        range: record.range,
        role: child_record.role,
    };
    roles.replace_record(slot, as_child);
    let view = roles.slot_view(slot);
    assert_eq!(view.record, Some(as_child));
    assert_eq!((view.mark, view.tables), (epoch, 1));
    roles.replace_record(slot, record);
    assert_eq!(
        (roles.slot_view(slot).mark, roles.slot_view(slot).tables),
        (epoch, 1)
    );

    // Any other role zeroes them, and they stay zero when it becomes a table
    // again.
    roles.replace_record(
        slot,
        RoleRecord {
            range: record.range,
            role: FrameRole::Zeroed,
        },
    );
    let view = roles.slot_view(slot);
    assert_eq!((view.mark, view.tables), (0, 0));
    roles.replace_record(slot, record);
    let view = roles.slot_view(slot);
    assert_eq!((view.mark, view.tables), (0, 0));

    // A vacated and reoccupied slot starts at zero.
    roles.set_mark(child_slot, epoch);
    roles.set_tables(child_slot, 3);
    assert_eq!(
        (
            roles.slot_view(child_slot).mark,
            roles.slot_view(child_slot).tables
        ),
        (epoch, 3)
    );
    roles.vacate(child_slot);
    let view = roles.slot_view(child_slot);
    assert_eq!((view.record, view.mark, view.tables), (None, 0, 0));
    roles.occupy(child_slot, view.generation + 1, child_record);
    let view = roles.slot_view(child_slot);
    assert_eq!((view.mark, view.tables), (0, 0));
}

#[test]
#[should_panic(expected = "only a committed table carries a proof mark")]
fn a_mark_on_a_slot_that_is_not_a_committed_table_panics() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let grant = roles.allocate(1).unwrap();
    roles.set_mark(slot_number(grant.identity), 1);
}

#[test]
#[should_panic(expected = "only a committed table carries a table count")]
fn a_count_on_a_slot_that_is_not_a_committed_table_panics() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let grant = roles.allocate(1).unwrap();
    roles.set_tables(slot_number(grant.identity), 1);
}

#[test]
fn a_spent_generation_retires_its_slot_and_the_free_list_skips_it() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let first = roles.allocate(1).unwrap();
    let kept = roles.allocate(1).unwrap();
    let spent = slot_number(first.identity);
    roles.cancel_allocation(first).unwrap();
    roles.test_set_generation(spent, u32::MAX - 1);
    let free = roles.free_slot_count;
    assert_eq!(roles.next_slot(), Ok((spent, u32::MAX)));

    let last = roles.allocate(1).unwrap();
    assert_eq!(slot_number(last.identity), spent);
    roles.cancel_allocation(last).unwrap();
    // The slot is free but on no list: one fewer free slot than before.
    assert_eq!(roles.free_slot_count, free - 1);
    assert_eq!(roles.slot_view(spent).record, None);
    assert_eq!(roles.slot_view(spent).generation, u32::MAX);
    for depth in 0..roles.free_slot_count {
        assert_ne!(roles.free_slot(depth).unwrap().0, spent);
    }
    assert_eq!(
        roles.free_slot(roles.free_slot_count),
        Err(FrameRoleError::Capacity)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    let next = roles.allocate(1).unwrap();
    assert_ne!(slot_number(next.identity), spent);
    roles.cancel_allocation(next).unwrap();
    roles.cancel_allocation(kept).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn the_kernel_image_staging_sees_the_three_next_slots_and_publication_takes_them() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let mut held: Vec<AllocationGrant> = (0..6).map(|_| roles.allocate(1).unwrap()).collect();
    let fifth = held.remove(4);
    let sixth = held.remove(4);
    let freed: Vec<usize> = [fifth, sixth]
        .into_iter()
        .map(|grant| {
            let slot = slot_number(grant.identity);
            roles.cancel_allocation(grant).unwrap();
            slot
        })
        .collect();
    // The last freed is at the head, then the one before, then the next
    // never-used boot slot.
    let expected = [freed[1], freed[0], 6];
    let declarations = [
        (
            PhysicalRange::new(0x1000_0000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::Text,
        ),
        (
            PhysicalRange::new(0x1000_1000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::ReadOnlyData,
        ),
        (
            PhysicalRange::new(0x1000_2000, BASE_PAGE_SIZE).unwrap(),
            KernelImageSegment::WritableData,
        ),
    ];
    #[allow(
        unsafe_code,
        reason = "the host model stages synthetic kernel-image ranges outside allocator RAM"
    )]
    // SAFETY: the ranges lie outside allocator RAM and are never dereferenced.
    let staged = unsafe { roles.stage_kernel_image_roles(declarations) }.unwrap();
    assert_eq!(staged.slots, expected);
    roles.publish_staged_kernel_image(staged);
    for (slot, (range, segment)) in expected.into_iter().zip(declarations) {
        assert_eq!(
            roles.slot_view(slot).record,
            Some(RoleRecord {
                range: PageRange::cover(range, roles.allocator.physical_limit()).unwrap(),
                role: FrameRole::External(ExternalFrameRole::KernelImage { segment }),
            })
        );
    }
    assert_eq!(roles.next_slot().unwrap().0, 7);
    assert_eq!(roles.check_invariants(), Ok(()));
}

/// A PML4 candidate for `owner`.
fn root_candidate(roles: &mut TestManager, owner: TableOwnerKey) -> TableCandidateGrant {
    let page = allocate_zeroed(roles, 1);
    roles.prepare_table(page, owner, TableLevel::Pml4).unwrap()
}

#[allow(
    unsafe_code,
    reason = "the host model reclaims an empty synthetic root it never dereferences"
)]
fn reclaim_root(roles: &mut TestManager, root: TableIdentity) {
    let grant = roles.prepare_empty_table_root(root).unwrap();
    // SAFETY: the synthetic root is empty and was never made resident.
    unsafe { roles.reclaim_preflighted_empty_table_root(grant) };
}

#[test]
fn a_second_pml4_for_an_owner_is_refused_while_the_first_lives_and_accepted_after_it_goes() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let owner = roles.create_table_owner().unwrap();
    let other = roles.create_table_owner().unwrap();
    let other_root = root_candidate(&mut roles, other);
    let other_root = roles.commit_table(other_root, None).unwrap();

    // The first is a candidate.
    let first = root_candidate(&mut roles, owner);
    let second = root_candidate(&mut roles, owner);
    let refused = roles.commit_table(second, None).unwrap_err();
    assert_eq!(refused.error(), FrameRoleError::DuplicateTableRoot);
    let second = refused.into_grant();
    // The first candidate cancelled, the second is accepted.
    roles.cancel_table_candidate(first).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
    let committed = roles.commit_table(second, None).unwrap();

    // The first is committed.
    let third = root_candidate(&mut roles, owner);
    let refused = roles.commit_table(third, None).unwrap_err();
    assert_eq!(refused.error(), FrameRoleError::DuplicateTableRoot);
    let third = refused.into_grant();
    reclaim_root(&mut roles, committed);
    assert_eq!(roles.check_invariants(), Ok(()));
    let third = roles.commit_table(third, None).unwrap();

    // The slot reclaimed is reused, as a root of the owner, without a
    // trace of its old place on the list.
    reclaim_root(&mut roles, third);
    let fourth = root_candidate(&mut roles, owner);
    assert_eq!(roles.check_invariants(), Ok(()));
    let fourth = roles.commit_table(fourth, None).unwrap();
    assert_eq!(roles.validate_table_identity(other_root), Ok(()));
    assert_eq!(roles.validate_table_identity(fourth), Ok(()));
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[should_panic(expected = "staged table commit became invalid before publication")]
fn a_staged_root_is_checked_against_the_root_list_again_at_publication() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let owner = roles.create_table_owner().unwrap();
    let staged = root_candidate(&mut roles, owner);
    let staged = roles.stage_table_commit(staged, None).unwrap();
    let _rival = root_candidate(&mut roles, owner);
    roles.publish_staged_table(staged);
}

#[test]
fn the_root_list_survives_growth() {
    let mut roles = manager(BASE_PAGE_SIZE, 512);
    let committed_owner = roles.create_table_owner().unwrap();
    let candidate_owner = roles.create_table_owner().unwrap();
    let committed = root_candidate(&mut roles, committed_owner);
    let committed = roles.commit_table(committed, None).unwrap();
    let candidate = root_candidate(&mut roles, candidate_owner);

    grow(&mut roles);
    assert_eq!(roles.check_invariants(), Ok(()));
    for owner in [committed_owner, candidate_owner] {
        let rival = root_candidate(&mut roles, owner);
        let refused = roles.commit_table(rival, None).unwrap_err();
        assert_eq!(refused.error(), FrameRoleError::DuplicateTableRoot);
        roles.cancel_table_candidate(refused.into_grant()).unwrap();
    }
    let fresh_owner = roles.create_table_owner().unwrap();
    let fresh = root_candidate(&mut roles, fresh_owner);
    roles.commit_table(fresh, None).unwrap();

    // Both pre-growth roots leave the list and their owners can start over.
    reclaim_root(&mut roles, committed);
    roles.cancel_table_candidate(candidate).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
    for owner in [committed_owner, candidate_owner] {
        let again = root_candidate(&mut roles, owner);
        roles.commit_table(again, None).unwrap();
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn check_invariants_fails_on_a_corrupted_free_list() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let head = roles.next_slot().unwrap().0;
    let second = roles.free_slot(1).unwrap().0;
    let third = roles.free_slot(2).unwrap().0;
    assert_eq!(roles.check_invariants(), Ok(()));

    // A cycle.
    roles.test_set_free_link(head, head as u64 + 1);
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    // A free slot skipped.
    roles.test_set_free_link(head, third as u64 + 1);
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    // A link to a live slot.
    roles.test_set_free_link(head, second as u64 + 1);
    assert_eq!(roles.check_invariants(), Ok(()));
    let live = roles.allocate(1).unwrap();
    let live_slot = slot_number(live.identity);
    let next = roles.next_slot().unwrap().0;
    roles.test_set_free_link(next, live_slot as u64 + 1);
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    roles.test_set_free_link(next, third as u64 + 1);
    assert_eq!(roles.check_invariants(), Ok(()));
    // A count that is not the list's length.
    roles.free_slot_count += 1;
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    roles.free_slot_count -= 1;
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn check_invariants_fails_on_a_corrupted_root_list() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let (first, _) = root_with_child(&mut roles);
    let (second, _) = root_with_child(&mut roles);
    let first = roles.slot(first.role).unwrap();
    let second = roles.slot(second.role).unwrap();
    assert_eq!(roles.first_root as usize, second + 1);
    assert_eq!(roles.check_invariants(), Ok(()));

    // A root dropped from the list.
    roles.test_set_root_link(second, 0);
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    // A cycle.
    roles.test_set_root_link(second, second as u32 + 1);
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    // A link to a slot that is not of PML4 level.
    let free = roles.next_slot().unwrap().0;
    roles.test_set_root_link(second, free as u32 + 1);
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    roles.test_set_root_link(second, first as u32 + 1);
    assert_eq!(roles.check_invariants(), Ok(()));
    // An empty list.
    roles.first_root = 0;
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
}

#[test]
fn check_invariants_fails_on_two_roots_of_one_owner() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let (first, _) = root_with_child(&mut roles);
    let owner = roles.create_table_owner().unwrap();
    let candidate = root_candidate(&mut roles, owner);
    let candidate = roles.slot(candidate.identity).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.test_set_root_owner(candidate, first.owner().raw);
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
}

#[test]
fn table_at_answers_only_for_a_committed_table() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let (root, child) = root_with_child(&mut roles);
    let root_slot = roles.slot(root.role).unwrap();
    let child_slot = roles.slot(child.role).unwrap();
    let proof = roles.begin_empty_table_hierarchy(root).unwrap();
    assert_eq!(
        roles.table_at(root_slot),
        Some(TableFacts {
            start: root.physical_start(),
            owner: root.owner().raw,
            level: TableLevel::Pml4,
            parent: 0,
            mark: proof.epoch,
            tables: 1,
        })
    );
    assert_eq!(
        roles.table_at(child_slot),
        Some(TableFacts {
            start: child.physical_start(),
            owner: child.owner().raw,
            level: TableLevel::Pdpt,
            parent: root.role.raw,
            mark: 0,
            tables: 0,
        })
    );

    // A free slot, a table candidate and every role that is not a committed
    // table say nothing.
    let free = roles.next_slot().unwrap().0;
    assert_eq!(roles.table_at(free), None);
    let owner = roles.create_table_owner().unwrap();
    for level in [TableLevel::Pml4, TableLevel::Pd] {
        let candidate = allocate_zeroed(&mut roles, 1);
        let candidate = roles.prepare_table(candidate, owner, level).unwrap();
        assert_eq!(
            roles.table_at(roles.slot(candidate.identity).unwrap()),
            None
        );
        roles.cancel_table_candidate(candidate).unwrap();
    }
    for role in every_role(&roles) {
        let record = RoleRecord {
            range: pages(1 << 40, 1),
            role,
        };
        let slot = occupy_next(&mut roles, record);
        let committed = matches!(role, FrameRole::PageTable { .. });
        assert_eq!(roles.table_at(slot).is_some(), committed, "{role:?}");
        roles.vacate(slot);
    }
}

#[test]
fn record_at_agrees_with_the_slot_view_for_every_role_kind() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let free = roles.next_slot().unwrap().0;
    assert_eq!(roles.record_at(free), None);
    assert_eq!(roles.record_at(free), roles.slot_view(free).record);
    for range in [
        pages(BASE_PAGE_SIZE, 1),
        pages(
            (1 << 52) - u64::from(u32::MAX) * BASE_PAGE_SIZE,
            u64::from(u32::MAX),
        ),
    ] {
        for role in every_role(&roles) {
            let record = RoleRecord { range, role };
            let slot = occupy_next(&mut roles, record);
            assert_eq!(roles.record_at(slot), Some(record));
            assert_eq!(roles.record_at(slot), roles.slot_view(slot).record);
            roles.vacate(slot);
        }
    }
}

#[test]
fn live_generation_is_none_for_a_free_and_a_retired_slot() {
    let mut roles = manager(BASE_PAGE_SIZE, 8);
    let never_used = roles.next_slot().unwrap().0;
    assert_eq!(roles.live_generation(never_used), None);
    let grant = roles.allocate(1).unwrap();
    let slot = slot_number(grant.identity);
    assert_eq!(roles.live_generation(slot), Some(1));
    roles.cancel_allocation(grant).unwrap();
    assert_eq!(roles.live_generation(slot), None);

    roles.test_set_generation(slot, u32::MAX - 1);
    let last = roles.allocate(1).unwrap();
    assert_eq!(slot_number(last.identity), slot);
    assert_eq!(roles.live_generation(slot), Some(u32::MAX));
    roles.cancel_allocation(last).unwrap();
    assert_eq!(roles.live_generation(slot), None);
    assert_eq!(roles.slot_view(slot).generation, u32::MAX);
    // Past the table.
    assert_eq!(roles.live_generation(roles.roles.len()), None);
}

/// The answers of the five narrow readers of DW2 §12.6, side by side.
type Readers = (
    Option<PageRange>,
    HeadKind,
    Option<ChainFacts>,
    Option<(PageRange, IndexRootLink)>,
    Option<IndexEntryFacts>,
);

/// What every narrow reader must answer for a slot whose record is
/// `record`, derived from the record alone.
fn expected_readers(record: Option<RoleRecord>) -> Readers {
    let Some(RoleRecord { range, role }) = record else {
        return (None, HeadKind::Other, None, None, None);
    };
    let chain = |source| Some(ChainFacts { range, source });
    let (head, chain, root, entry) = match role {
        FrameRole::ObjectBacking(link) => (
            HeadKind::ObjectBacking,
            chain(ChainSource::Backing(link)),
            None,
            None,
        ),
        FrameRole::BackingAllocated(link) => (
            HeadKind::BackingAllocated,
            chain(ChainSource::Allocated(link)),
            None,
            None,
        ),
        FrameRole::ExternalDeviceMmio => {
            (HeadKind::DeviceMmio, chain(ChainSource::Device), None, None)
        }
        FrameRole::ExternalImmutableModule { .. } => (
            HeadKind::ImmutableModule,
            chain(ChainSource::Module),
            None,
            None,
        ),
        FrameRole::IndexRoot(link) => (HeadKind::IndexRoot, None, Some((range, link)), None),
        FrameRole::IndexNode(link) => (
            HeadKind::Other,
            None,
            None,
            Some(IndexEntryFacts {
                range,
                node: true,
                link,
            }),
        ),
        FrameRole::ObjectPage(link) => (
            HeadKind::Other,
            None,
            None,
            Some(IndexEntryFacts {
                range,
                node: false,
                link,
            }),
        ),
        FrameRole::AllocatedUninitialized
        | FrameRole::Zeroed
        | FrameRole::ArchitectureBootstrap(_)
        | FrameRole::TableCandidate { .. }
        | FrameRole::PageTable { .. }
        | FrameRole::External(_)
        | FrameRole::RoleTableStorage => (HeadKind::Other, None, None, None),
    };
    (Some(range), head, chain, root, entry)
}

fn readers(roles: &TestManager, slot: usize) -> Readers {
    (
        roles.run_at(slot),
        roles.head_kind_at(slot),
        roles.chain_at(slot),
        roles.index_root_at(slot),
        roles.index_entry_at(slot),
    )
}

/// DW2 §12.6 item 1: each narrow reader answers exactly what `record_at`'s
/// record implies, for a slot of every role kind (PML4 candidates and
/// roots and tables below them included), a free slot and a retired one.
#[test]
fn the_narrow_readers_agree_with_record_at_for_every_role_kind_and_a_free_and_a_retired_slot() {
    let mut roles = manager(BASE_PAGE_SIZE, 64);
    let free = roles.next_slot().unwrap().0;
    assert_eq!(readers(&roles, free), expected_readers(None));
    assert_eq!(roles.record_at(free), None);

    // Every kind, at one page and at the most a slot stores.
    for range in [
        pages(BASE_PAGE_SIZE, 1),
        pages(
            (1 << 52) - u64::from(u32::MAX) * BASE_PAGE_SIZE,
            u64::from(u32::MAX),
        ),
    ] {
        for role in every_role(&roles) {
            let slot = occupy_next(&mut roles, RoleRecord { range, role });
            let record = roles.record_at(slot);
            assert_eq!(record, Some(RoleRecord { range, role }));
            assert_eq!(readers(&roles, slot), expected_readers(record), "{role:?}");
            roles.vacate(slot);
            assert_eq!(readers(&roles, slot), expected_readers(None), "{role:?}");
        }
    }

    // Committed tables reached the ordinary way, with a mark and a count.
    let (root, child) = root_with_child(&mut roles);
    let _proof = roles.begin_empty_table_hierarchy(root).unwrap();
    for identity in [root.role, child.role] {
        let slot = roles.slot(identity).unwrap();
        assert_eq!(
            readers(&roles, slot),
            expected_readers(roles.record_at(slot))
        );
    }

    // A retired slot: its last generation used, then vacated.
    let grant = roles.allocate(1).unwrap();
    let slot = slot_number(grant.identity);
    roles.cancel_allocation(grant).unwrap();
    roles.test_set_generation(slot, u32::MAX - 1);
    let last = roles.allocate(1).unwrap();
    assert_eq!(slot_number(last.identity), slot);
    assert_eq!(readers(&roles, slot).0, Some(last.range));
    roles.cancel_allocation(last).unwrap();
    assert_eq!(roles.slot_view(slot).generation, u32::MAX);
    assert_eq!(roles.record_at(slot), None);
    assert_eq!(readers(&roles, slot), expected_readers(None));
    assert_eq!(roles.check_invariants(), Ok(()));
}
