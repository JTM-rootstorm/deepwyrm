//! A cursor's place in an index (DW2 §12.12 item 5a): resolving through a
//! remembered run or leaf gives what a walk gives, and a place that is
//! stale, foreign or in a root nothing resolves grants nothing.

extern crate std;

use super::indexed_tests::{Model, Small, backing, holes, index_runs, sized, small, zeroed};
use super::*;
use std::vec::Vec;

const PAGE: u64 = BASE_PAGE_SIZE;
const THREE_LEVELS: u64 = 512 * 512 + 1;
type Large = FrameRoleManager<48, 1024>;

/// `pages` in order, in reverse and in a fixed pseudo-random order.
fn orders(pages: &[u64]) -> [Vec<u64>; 3] {
    let forward = pages.to_vec();
    let mut reverse = forward.clone();
    reverse.reverse();
    let mut shuffled = forward.clone();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for index in (1..shuffled.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        shuffled.swap(index, (state % (index as u64 + 1)) as usize);
    }
    [forward, reverse, shuffled]
}

/// Resolves every page of each order with one cursor, each against a
/// fresh cursor's answer.
fn matches_fresh<const R: usize, const S: usize>(
    roles: &FrameRoleManager<R, S>,
    backing: BackingIdentity,
    pages: &[u64],
) {
    for order in orders(pages) {
        let mut cursor = BackingCursor::new(backing);
        for page in order {
            let fresh = roles.resolve_object_page(backing, page * PAGE, false);
            assert_eq!(
                roles.resolve_at(&mut cursor, page * PAGE, false),
                fresh,
                "page {page}"
            );
            assert_eq!(cursor.head, backing.0);
        }
    }
}

/// The identity of the committed page or run of `backing` that starts at
/// object page `place`, from the role records.
fn entry_identity<const R: usize, const S: usize>(
    roles: &FrameRoleManager<R, S>,
    backing: BackingIdentity,
    place: u64,
) -> FrameRoleIdentity {
    roles
        .slot_views()
        .find_map(|(slot, view)| match view.record {
            Some(RoleRecord {
                role: FrameRole::ObjectPage(link),
                ..
            }) if link.owner == backing.0.raw && link.place == place => {
                Some(roles.identity(slot, view.generation).unwrap())
            }
            _ => None,
        })
        .expect("the entry exists")
}

/// The identity of entry `entry` of the root of `backing`, of any state.
fn root_entry<const R: usize, const S: usize>(
    roles: &FrameRoleManager<R, S>,
    model: &Model,
    backing: BackingIdentity,
    entry: usize,
) -> FrameRoleIdentity {
    let (root, _) = roles.index_root(backing.0, RootUse::Any).unwrap();
    FrameRoleIdentity {
        domain: roles.domain,
        raw: model.read(root.start, entry),
    }
}

#[test]
fn a_cursor_resolves_what_a_fresh_cursor_does_in_on_demand_roots_of_one_to_three_levels() {
    // One level: the root is the leaf.
    let (mut roles, _) = sized::<1024>(4096);
    let one = roles.allocate_on_demand_backing(512).unwrap();
    for page in (0..512).step_by(3).chain([511]) {
        roles.commit_on_demand_page(one.identity(), page).unwrap();
    }
    matches_fresh(&roles, one.identity(), &(0..512).collect::<Vec<_>>());

    // Two levels, three leaves: the first dense, the second sparse, the
    // third never made.
    let two = roles.allocate_on_demand_backing(1500).unwrap();
    for page in (0..300).chain((600..1000).step_by(7)) {
        roles.commit_on_demand_page(two.identity(), page).unwrap();
    }
    matches_fresh(&roles, two.identity(), &(0..1500).collect::<Vec<_>>());

    // Three levels: pages under two level-1 nodes.
    let three = roles.allocate_on_demand_backing(THREE_LEVELS).unwrap();
    for page in (0..40)
        .chain(510..515)
        .chain((1000..1500).step_by(11))
        .chain([512 * 512 - 1, 512 * 512])
    {
        roles.commit_on_demand_page(three.identity(), page).unwrap();
    }
    matches_fresh(
        &roles,
        three.identity(),
        &(0..THREE_LEVELS).collect::<Vec<_>>(),
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    for grant in [one, two, three] {
        roles.cancel_object_backing(grant).unwrap();
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

/// Runs of 700 pages (across leaves 0 and 1), 300 (inside leaf 0),
/// smaller ones and single pages: 1,026 pages, two levels.
fn crossing(roles: &mut Small) -> (ObjectBackingGrant, Vec<AllocationGrant>) {
    let mut sizes = std::vec![700, 300, 9, 3, 2];
    sizes.extend([1; 16]);
    let held = holes(roles, &sizes);
    let grant = backing(roles, 1026);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    assert_eq!(
        &index_runs(roles, grant.identity())[14..],
        &[(25, 300), (325, 700), (1025, 1)]
    );
    (grant, held)
}

#[test]
fn a_cursor_resolves_what_a_fresh_cursor_does_in_an_eager_root_whose_runs_cross_leaves() {
    let (mut roles, _) = small(2048);
    let (grant, _held) = crossing(&mut roles);
    matches_fresh(&roles, grant.identity(), &(0..1026).collect::<Vec<_>>());
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();
}

#[test]
fn a_decommitted_page_is_absent_a_recommitted_one_is_the_new_frame_and_a_reused_slot_is_not_returned()
 {
    let (mut roles, _) = small(64);
    let grant = roles.allocate_on_demand_backing(1024).unwrap();
    let backing = grant.identity();
    let first = roles.commit_on_demand_page(backing, 5).unwrap();
    roles.commit_on_demand_page(backing, 6).unwrap();
    let mut cursor = BackingCursor::new(backing);
    let resolved = roles.resolve_at(&mut cursor, 5 * PAGE, false).unwrap();
    assert_eq!(resolved.physical_start, first.physical_start);

    // Decommitted after the cursor resolved it.
    assert_eq!(
        roles.decommit_on_demand_range(backing, 5, 6, 8),
        Ok((6, 1, 1))
    );
    let mut stale = cursor;
    assert_eq!(
        roles.resolve_at(&mut stale, 5 * PAGE, false),
        Err(FrameRoleError::Absent)
    );
    assert_eq!(roles.check_invariants(), Ok(()));

    // Committed again: the new frame, from the cursor as it was.
    let again = roles.commit_on_demand_page(backing, 5).unwrap();
    let mut stale = cursor;
    let segment = roles.resolve_at(&mut stale, 5 * PAGE, false).unwrap();
    assert_eq!(segment.physical_start, again.physical_start);
    assert_eq!(
        Ok(segment),
        roles.resolve_object_page(backing, 5 * PAGE, false)
    );
    assert_eq!(roles.check_invariants(), Ok(()));

    // Decommitted again, and its slot taken by another backing's page.
    let other = roles.allocate_on_demand_backing(1).unwrap();
    let mut cursor = BackingCursor::new(backing);
    let held = roles.resolve_at(&mut cursor, 5 * PAGE, false).unwrap();
    roles.decommit_on_demand_range(backing, 5, 6, 8).unwrap();
    let taken = roles.commit_on_demand_page(other.identity(), 0).unwrap();
    let reused = roles
        .resolve_object_page(other.identity(), 0, false)
        .unwrap()
        .run;
    assert_eq!(
        reused.raw as u32, held.run.raw as u32,
        "the other backing's page took the slot"
    );
    assert_ne!(reused, held.run);
    assert_eq!(
        roles.resolve_at(&mut cursor, 5 * PAGE, false),
        Err(FrameRoleError::Absent)
    );
    assert_eq!(cursor.run, backing.0, "the cursor holds no run");
    let mut stale = BackingCursor::with_place(backing, reused, 5, cursor.leaf, 0);
    assert_eq!(
        roles.resolve_at(&mut stale, 5 * PAGE, false),
        Err(FrameRoleError::Absent),
        "the page {:#x} is not returned",
        taken.physical_start
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(other).unwrap();
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_cursor_naming_another_backing_s_leaf_and_run_resolves_its_own_backing() {
    let (mut roles, model) = small(64);
    let one = roles.allocate_on_demand_backing(1024).unwrap();
    let two = roles.allocate_on_demand_backing(1024).unwrap();
    for page in [5, 6, 600] {
        roles.commit_on_demand_page(one.identity(), page).unwrap();
    }
    for page in [5, 601] {
        roles.commit_on_demand_page(two.identity(), page).unwrap();
    }
    let foreign_run = entry_identity(&roles, two.identity(), 5);
    let foreign_leaves = [
        root_entry(&roles, model, two.identity(), 0),
        root_entry(&roles, model, two.identity(), 1),
    ];
    // Page 5: the other backing's run holds it at the same place; page 6:
    // the other backing's leaf has no entry for it; pages 600 and 601: in
    // the other's second leaf, which has an entry for 601 only.
    for (page, leaf, leaf_first) in [
        (5, 0, 0),
        (6, 0, 0),
        (7, 0, 0),
        (600, 1, 512),
        (601, 1, 512),
    ] {
        let fresh = roles.resolve_object_page(one.identity(), page * PAGE, false);
        let mut cursor = BackingCursor::with_place(
            one.identity(),
            foreign_run,
            5,
            foreign_leaves[leaf],
            leaf_first,
        );
        assert_eq!(
            roles.resolve_at(&mut cursor, page * PAGE, false),
            fresh,
            "page {page}"
        );
        assert_ne!(cursor.run, foreign_run);
        assert!(!foreign_leaves.contains(&cursor.leaf));
        assert_eq!(roles.check_invariants(), Ok(()));
    }
    roles.cancel_object_backing(one).unwrap();
    roles.cancel_object_backing(two).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_place_in_an_eager_root_being_freed_built_or_not_yet_zeroed_is_refused() {
    // Being freed: a cursor at page 900, in the 700-page run and leaf 1.
    let (mut roles, model) = small(2048);
    let (grant, _held) = crossing(&mut roles);
    let backing = grant.identity();
    let mut cursor = BackingCursor::new(backing);
    roles.resolve_at(&mut cursor, 900 * PAGE, false).unwrap();
    assert_eq!(cursor.run, entry_identity(&roles, backing, 325));
    assert_eq!(cursor.leaf, root_entry(&roles, model, backing, 1));
    roles.release_index_step(backing, 0, 1).unwrap();
    for page in [900, 901, 600] {
        let mut kept = cursor;
        assert_eq!(
            roles.resolve_at(&mut kept, page * PAGE, false),
            Err(FrameRoleError::WrongRole),
            "page {page}"
        );
    }
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();

    // Not yet zeroed, then zeroed.
    let (mut roles, model) = small(2048);
    let (grant, _held) = crossing(&mut roles);
    roles.cancel_object_backing(grant).unwrap();
    let allocation = roles.allocate_backing(1026).unwrap();
    assert!(allocation.indexed && allocation.is_complete());
    let root = BackingIdentity(allocation.head);
    let place = |roles: &Small| {
        BackingCursor::with_place(
            root,
            entry_identity(roles, root, 325),
            325,
            root_entry(roles, model, root, 1),
            512,
        )
    };
    assert_eq!(
        roles.resolve_at(&mut place(&roles), 900 * PAGE, false),
        Err(FrameRoleError::WrongRole)
    );
    assert!(roles.zero_backing_pages(&allocation, 0, 1026, &mut |_| true));
    let grant = zeroed(&mut roles, allocation);
    let mut cursor = place(&roles);
    assert_eq!(
        roles.resolve_at(&mut cursor, 900 * PAGE, false),
        roles.resolve_object_page(root, 900 * PAGE, false)
    );
    assert_ne!(cursor.run, root.0);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn a_place_in_an_eager_root_being_built_is_refused() {
    let (mut roles, model) = small(2048);
    let mut sizes = std::vec![700, 300, 9, 3, 2];
    sizes.extend([1; 16]);
    let _held = holes(&mut roles, &sizes);
    let mut allocation = roles.begin_backing(1026).unwrap();
    assert!(allocation.indexed && !allocation.is_complete());
    roles.extend_backing_runs(&mut allocation, 1).unwrap();
    assert_eq!(allocation.linked, 1);
    let root = BackingIdentity(allocation.head);
    // The run linked at page 0, and the leaf holding it.
    let mut cursor = BackingCursor::with_place(
        root,
        entry_identity(&roles, root, 0),
        0,
        root_entry(&roles, model, root, 0),
        0,
    );
    assert_ne!(cursor.leaf.raw, 0);
    assert_eq!(
        roles.resolve_at(&mut cursor, 0, false),
        Err(FrameRoleError::WrongRole)
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    while !allocation.is_complete() {
        roles.extend_backing(&mut allocation).unwrap();
    }
    assert!(roles.zero_backing_pages(&allocation, 0, 1026, &mut |_| true));
    let grant = zeroed(&mut roles, allocation);
    roles.cancel_object_backing(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn the_pages_of_an_eager_run_after_its_first_read_no_node_and_a_leaf_s_pages_one_entry() {
    let (mut roles, model) = small(2048);
    let (grant, _held) = crossing(&mut roles);
    let backing = grant.identity();
    let mut cursor = BackingCursor::new(backing);
    let reads = model.reads();
    roles.resolve_at(&mut cursor, 325 * PAGE, false).unwrap();
    assert_eq!(model.reads() - reads, 2, "the walk");
    for page in 326..1025 {
        let fresh = roles.resolve_object_page(backing, page * PAGE, false);
        let reads = model.reads();
        assert_eq!(roles.resolve_at(&mut cursor, page * PAGE, false), fresh);
        assert_eq!(model.reads() - reads, 0, "page {page}");
    }
    roles.cancel_object_backing(grant).unwrap();

    // A two-level on-demand root: leaf 1 committed from 512 to 612.
    let on_demand = roles.allocate_on_demand_backing(1024).unwrap();
    let backing = on_demand.identity();
    for page in 512..613 {
        roles.commit_on_demand_page(backing, page).unwrap();
    }
    let mut cursor = BackingCursor::new(backing);
    let reads = model.reads();
    roles.resolve_at(&mut cursor, 512 * PAGE, false).unwrap();
    assert_eq!(model.reads() - reads, 2, "the walk");
    for page in 513..1024 {
        let fresh = roles.resolve_object_page(backing, page * PAGE, false);
        let reads = model.reads();
        assert_eq!(roles.resolve_at(&mut cursor, page * PAGE, false), fresh);
        assert_eq!(model.reads() - reads, 1, "page {page}");
    }
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(on_demand).unwrap();
}
