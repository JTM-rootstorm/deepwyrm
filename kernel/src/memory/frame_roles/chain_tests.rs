extern crate std;

use super::super::super::physical::PhysicalAddressLimit;
use super::*;
use std::vec::Vec;

const PAGE: u64 = BASE_PAGE_SIZE;
type Manager = FrameRoleManager<8, 32>;

fn manager(page_count: u64) -> Manager {
    let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
    let candidate = PageRange::from_page_count(PAGE, page_count, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    FrameRoleManager::new(allocator).unwrap()
}

#[allow(
    unsafe_code,
    reason = "the host model never dereferences synthetic physical memory"
)]
fn backing(roles: &mut Manager, page_count: u64) -> ObjectBackingGrant {
    let allocation = roles.allocate_backing(page_count).unwrap();
    // SAFETY: the host model never dereferences the synthetic runs.
    unsafe { roles.assume_backing_zeroed(allocation) }.unwrap()
}

/// Leaves free holes of the given page counts, in address order, separated
/// by one held page each, and returns the held pages.
fn fragment(roles: &mut Manager, holes: &[u64]) -> Vec<AllocationGrant> {
    let mut held = Vec::new();
    let mut gaps = Vec::new();
    for &hole in holes {
        gaps.push(roles.allocate(hole).unwrap());
        held.push(roles.allocate(1).unwrap());
    }
    held.push(roles.allocate(roles.available_frames()).unwrap());
    for gap in gaps {
        roles.cancel_allocation(gap).unwrap();
    }
    held
}

fn segments(roles: &Manager, grant: &ObjectBackingGrant) -> Vec<ObjectSegment> {
    roles
        .object_segments(grant.identity(), 0, grant.byte_len(), true)
        .unwrap()
        .collect()
}

#[test]
fn unfragmented_memory_gives_one_run_like_a_plain_allocation() {
    let mut roles = manager(16);
    let grant = backing(&mut roles, 4);
    assert_eq!(grant.run_count(), 1);
    assert_eq!(grant.byte_len(), 4 * PAGE);
    let pieces = segments(&roles, &grant);
    assert_eq!(pieces.len(), 1);
    assert_eq!(pieces[0].physical_start, grant.physical_start());
    assert_eq!(pieces[0].byte_len, 4 * PAGE);
    assert_eq!(
        roles.role(pieces[0].run),
        Ok(FrameRoleKind::ObjectBacking(
            ObjectBackingKind::AllocatorOwned
        ))
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), 16);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_request_larger_than_the_largest_hole_takes_the_largest_holes_first() {
    let mut roles = manager(64);
    let held = fragment(&mut roles, &[1, 3, 2]);
    assert_eq!(roles.available_frames(), 6);
    let grant = backing(&mut roles, 5);
    assert_eq!(
        grant.run_count(),
        2,
        "the 3-page hole, then the 2-page hole"
    );
    let pieces = segments(&roles, &grant);
    // Holes: page 1 (1 page), pages 3..6 (3), pages 7..9 (2), in frames
    // starting at page 1.
    assert_eq!(
        pieces
            .iter()
            .map(|piece| (piece.object_offset, piece.physical_start, piece.byte_len))
            .collect::<Vec<_>>(),
        [(0, 3 * PAGE, 3 * PAGE), (3 * PAGE, 7 * PAGE, 2 * PAGE)]
    );
    assert_eq!(roles.available_frames(), 1);
    assert_eq!(roles.check_invariants(), Ok(()));

    // Each page resolves to its run, sequential or not.
    for (page, physical) in [(0, 3), (2, 5), (3, 7), (4, 8)] {
        let resolved = roles
            .resolve_object_page(grant.identity(), page * PAGE, true)
            .unwrap();
        assert_eq!(resolved.physical_start, physical * PAGE);
        assert_eq!(resolved.byte_len, PAGE);
    }
    // A range crossing runs is clipped at both ends.
    let middle: Vec<_> = roles
        .object_segments(grant.identity(), 2 * PAGE, 2 * PAGE, false)
        .unwrap()
        .map(|piece| (piece.object_offset, piece.physical_start, piece.byte_len))
        .collect();
    assert_eq!(
        middle,
        [(2 * PAGE, 5 * PAGE, PAGE), (3 * PAGE, 7 * PAGE, PAGE)]
    );

    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), 6);
    for grant in held {
        roles.cancel_allocation(grant).unwrap();
    }
    assert_eq!(roles.available_frames(), 64);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_backing_may_use_every_free_page_in_one_page_runs() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[1, 1, 1, 1, 1, 1]);
    let grant = backing(&mut roles, 6);
    assert_eq!(grant.run_count(), 6);
    assert_eq!(roles.available_frames(), 0);
    let pieces = segments(&roles, &grant);
    assert_eq!(pieces.len(), 6);
    for (index, piece) in pieces.iter().enumerate() {
        assert_eq!(piece.object_offset, index as u64 * PAGE);
        assert_eq!(piece.physical_start, (1 + 2 * index as u64) * PAGE);
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn running_out_of_memory_frees_every_run_taken() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[2, 3]);
    let before = roles.available_frames();
    assert_eq!(
        roles.allocate_backing(before + 1),
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::NoFramesAvailable
        ))
    );
    assert_eq!(roles.available_frames(), before);
    assert_eq!(roles.check_invariants(), Ok(()));
    // The same memory is still usable whole.
    let grant = backing(&mut roles, before);
    assert_eq!(grant.run_count(), 2);
}

#[test]
fn running_out_of_role_slots_frees_every_run_taken() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[1, 1, 1, 1, 1]);
    let before = roles.available_frames();
    // Hide all but three free slots: a five-run request takes three runs,
    // then finds no slot.
    let free_slots = roles.free_slot_count;
    roles.free_slot_count = 3;
    assert_eq!(roles.allocate_backing(5), Err(FrameRoleError::Capacity));
    assert_eq!(roles.available_frames(), before);
    assert_eq!(roles.free_slot_count, 3);
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.free_slot_count = free_slots;
    assert_eq!(backing(&mut roles, 5).run_count(), 5);
}

#[test]
fn an_unzeroed_allocation_is_walked_for_zeroing_and_can_be_cancelled() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[2, 3]);
    let allocation = roles.allocate_backing(4).unwrap();
    assert_eq!(allocation.run_count(), 2);
    let pieces: Vec<_> = roles
        .backing_allocation_segments(&allocation)
        .unwrap()
        .map(|piece| (piece.physical_start, piece.byte_len))
        .collect();
    assert_eq!(pieces, [(4 * PAGE, 3 * PAGE), (PAGE, PAGE)]);
    // Unzeroed runs are not object backing yet.
    let head = BackingIdentity(allocation.head);
    assert_eq!(
        roles.object_segments(head, 0, PAGE, false).err(),
        Some(FrameRoleError::WrongRole)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_backing_allocation(allocation).unwrap();
    assert_eq!(roles.available_frames(), 5);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn only_the_head_names_a_backing_and_ranges_stay_inside_it() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[2, 3]);
    let grant = backing(&mut roles, 5);
    let pieces = segments(&roles, &grant);
    let second = BackingIdentity(pieces[1].run);
    assert_eq!(
        roles.object_segments(second, 0, PAGE, false).err(),
        Some(FrameRoleError::WrongRole)
    );
    let head = grant.identity();
    for (offset, len) in [
        (0, 0),
        (1, PAGE),
        (0, PAGE + 1),
        (0, 6 * PAGE),
        (5 * PAGE, PAGE),
    ] {
        assert_eq!(
            roles.object_segments(head, offset, len, false).err(),
            Some(FrameRoleError::WrongRole),
            "offset {offset} len {len}"
        );
    }
    assert_eq!(
        roles
            .object_segments(head, u64::MAX - PAGE + 1, PAGE, false)
            .err(),
        Some(FrameRoleError::WrongRole)
    );
}

#[test]
fn a_cancelled_backing_is_stale_and_a_mismatched_grant_comes_back() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[2, 3]);
    let grant = backing(&mut roles, 5);
    let identity = grant.identity();

    let forged = ObjectBackingGrant {
        pages: grant.pages - 1,
        ..ObjectBackingGrant { ..grant }
    };
    let failure = roles.cancel_object_backing(forged).unwrap_err();
    assert_eq!(failure.error(), FrameRoleError::WrongRole);
    let grant = ObjectBackingGrant {
        pages: 5,
        ..failure.into_grant()
    };
    assert_eq!(roles.check_invariants(), Ok(()));

    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(
        roles.object_segments(identity, 0, PAGE, false).err(),
        Some(FrameRoleError::InvalidGrant)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_single_run_backing_resolves_through_the_same_walk() {
    let mut roles = manager(16);
    let allocation = roles.allocate(2).unwrap();
    // SAFETY: the host model never dereferences the synthetic run.
    #[allow(unsafe_code, reason = "host model attests zeroing")]
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let grant = roles.assign_object_backing(zeroed).unwrap();
    assert_eq!(grant.run_count(), 1);
    let page = roles
        .resolve_object_page(grant.identity(), PAGE, true)
        .unwrap();
    assert_eq!(page.physical_start, grant.physical_start() + PAGE);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.available_frames(), 16);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(unsafe_code, reason = "metadata-only boot module and BAR imports")]
fn external_backings_are_one_run_and_a_module_is_read_only() {
    let mut roles = manager(16);
    let module = PhysicalRange::new(0x10_0000, 2 * PAGE).unwrap();
    // SAFETY: metadata-only host model with disjoint synthetic provenance.
    let module = unsafe { roles.import_immutable_module(module, 0) }.unwrap();
    assert_eq!(
        roles
            .object_segments(module.identity(), 0, PAGE, true)
            .err(),
        Some(FrameRoleError::ReadOnlyBacking)
    );
    let page = roles
        .resolve_object_page(module.identity(), PAGE, false)
        .unwrap();
    assert_eq!(page.physical_start, 0x10_0000 + PAGE);
    let bar = PhysicalRange::new(0x20_0000, PAGE).unwrap();
    // SAFETY: as above.
    let bar = unsafe { roles.import_device_mmio(bar) }.unwrap();
    assert_eq!(
        roles
            .resolve_object_page(bar.identity(), 0, true)
            .unwrap()
            .physical_start,
        0x20_0000
    );
    assert_eq!(
        roles
            .object_segments(bar.identity(), PAGE, PAGE, true)
            .err(),
        Some(FrameRoleError::WrongRole)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "the host model's zero callback touches no memory"
)]
fn the_shared_allocator_zeroes_every_page_once_and_rolls_back_a_failure() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[2, 3]);
    let mut zeroed = Vec::new();
    // SAFETY: the host model never dereferences the synthetic pages.
    let grant = unsafe {
        roles.allocate_zeroed_backing(4, &mut |page| {
            zeroed.push(page);
            true
        })
    }
    .unwrap();
    assert_eq!(grant.run_count(), 2);
    zeroed.sort_unstable();
    assert_eq!(zeroed, [PAGE, 4 * PAGE, 5 * PAGE, 6 * PAGE]);
    roles.cancel_object_backing(grant).unwrap();

    let before = roles.available_frames();
    let mut calls = 0;
    // SAFETY: as above.
    let failed = unsafe {
        roles.allocate_zeroed_backing(4, &mut |_| {
            calls += 1;
            calls < 3
        })
    };
    assert_eq!(failed, Err(FrameRoleError::InitializationFailed));
    assert_eq!(roles.available_frames(), before);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_cursor_follows_pages_forward_restarts_backward_and_names_its_run() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[1, 1, 1, 1, 1]);
    let grant = backing(&mut roles, 5);
    let expected = [PAGE, 3 * PAGE, 5 * PAGE, 7 * PAGE, 9 * PAGE];
    let mut cursor = BackingCursor::new(grant.identity());
    for (page, physical) in expected.iter().enumerate() {
        let resolved = roles
            .resolve_at(&mut cursor, page as u64 * PAGE, true)
            .unwrap();
        assert_eq!(resolved.physical_start, *physical);
        assert_eq!(
            cursor.run, resolved.run,
            "the cursor stays at the page's run"
        );
    }
    // Backward restarts from the head; past the end fails.
    assert_eq!(
        roles
            .resolve_at(&mut cursor, PAGE, false)
            .unwrap()
            .physical_start,
        3 * PAGE
    );
    assert_eq!(
        roles.resolve_at(&mut cursor, 5 * PAGE, false).err(),
        Some(FrameRoleError::WrongRole)
    );
    assert_eq!(
        roles.resolve_at(&mut cursor, PAGE + 1, false).err(),
        Some(FrameRoleError::WrongRole)
    );
}

#[test]
fn a_cursor_grants_nothing_once_its_backing_is_gone() {
    let mut roles = manager(64);
    let _held = fragment(&mut roles, &[1, 1, 1]);
    let grant = backing(&mut roles, 3);
    let identity = grant.identity();
    let mut cursor = BackingCursor::new(identity);
    roles.resolve_at(&mut cursor, 2 * PAGE, false).unwrap();
    roles.cancel_object_backing(grant).unwrap();
    // The same slots and frames come back as another backing.
    let other = backing(&mut roles, 3);
    assert_ne!(other.identity(), identity);
    assert_eq!(
        roles.resolve_at(&mut cursor, 2 * PAGE, false).err(),
        Some(FrameRoleError::InvalidGrant)
    );
    // A cursor for one backing does not resolve another's pages.
    let mut wrong = BackingCursor::new(identity);
    wrong.run = segments(&roles, &other)[1].run;
    wrong.run_page = 1;
    assert!(roles.resolve_at(&mut wrong, PAGE, false).is_err());
}
