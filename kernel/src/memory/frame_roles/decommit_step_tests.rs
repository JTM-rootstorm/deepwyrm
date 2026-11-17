//! A decommit that walks once for a leaf (DW2 §12.12 item 5): one call of
//! budget `b` does what calls of budget 1 do until they have visited `b`,
//! and reads a leaf's parent entry a bounded number of times.

extern crate std;

use super::indexed_tests::{Model, sized};
use super::*;
use std::collections::BTreeMap;
use std::vec::Vec;

type Manager = FrameRoleManager<48, 2048>;

const PAGE: u64 = BASE_PAGE_SIZE;
const THREE_LEVELS: u64 = 512 * 512 + 1;

#[derive(Clone, Copy, Debug)]
enum Case {
    /// One level: the root is the leaf.
    OwnLeaf,
    /// Two levels, three leaves, the middle one never made.
    Sparse,
    /// Two levels, three leaves, every page committed.
    Dense,
    /// Three levels: a few pages far apart and one dense leaf.
    ThreeLevels,
}

const BUDGETS: [u64; 7] = [1, 2, 7, 511, 512, 513, 4096];

/// The pages of `case` and the pages committed in it.
fn layout(case: Case) -> (u64, Vec<u64>) {
    match case {
        Case::OwnLeaf => (512, [0, 1, 7, 200, 201, 202, 510, 511].to_vec()),
        Case::Sparse => (1536, [0, 7, 300, 511, 1024, 1100, 1101, 1535].to_vec()),
        Case::Dense => (1536, (0..1536).collect()),
        Case::ThreeLevels => {
            let mut committed = [3, 600, 1023, 512 * 512 - 1, 512 * 512].to_vec();
            committed.extend(1024..1536);
            (THREE_LEVELS, committed)
        }
    }
}

/// The ranges `[start, end)` decommitted in `case`: inside a leaf, from a
/// leaf start, to a leaf end, across two leaf ends, empty, and past the
/// object's end.
fn ranges(case: Case) -> Vec<(u64, u64)> {
    match case {
        Case::OwnLeaf => [
            (5, 300),
            (0, 200),
            (100, 512),
            (0, 512),
            (9, 9),
            (300, 4),
            (200, 900),
        ]
        .to_vec(),
        Case::Dense => [
            (5, 300),
            (512, 900),
            (100, 512),
            (300, 1100),
            (700, 700),
            (1400, 3000),
        ]
        .to_vec(),
        Case::Sparse => [
            (5, 300),
            (1030, 1500),
            (512, 900),
            (1024, 1536),
            (100, 512),
            (300, 1024),
            (300, 1100),
            (0, 1536),
            (700, 700),
            (900, 100),
            (1400, 3000),
        ]
        .to_vec(),
        Case::ThreeLevels => [
            (1030, 1500),
            (1024, 1300),
            (700, 1536),
            (400, 1100),
            (0, 2000),
            (1000, 1100),
            (800, 800),
            (262_000, THREE_LEVELS + 500),
        ]
        .to_vec(),
    }
}

/// A manager holding the on-demand backing of `case`, and its pages.
fn build(case: Case) -> (Manager, &'static Model, BackingIdentity, u64) {
    let (mut roles, model) = sized::<2048>(4096);
    let (pages, committed) = layout(case);
    let grant = roles.allocate_on_demand_backing(pages).unwrap();
    let backing = grant.identity();
    for page in committed {
        roles.commit_on_demand_page(backing, page).unwrap();
    }
    let (_, root) = roles.index_root(backing.0, RootUse::OnDemand).unwrap();
    let levels = match case {
        Case::OwnLeaf => 1,
        Case::Sparse | Case::Dense => 2,
        Case::ThreeLevels => 3,
    };
    assert_eq!(root.levels, levels, "{case:?}");
    assert_eq!(roles.check_invariants(), Ok(()));
    (roles, model, backing, pages)
}

/// The pages of `case` whose resolution is compared: every page, except
/// that a three-level backing is probed at every page of each leaf it ever
/// made and at the first page of every other leaf (the slot records and
/// index entries, compared whole, cover the rest).
fn probes(case: Case) -> Vec<u64> {
    let (pages, committed) = layout(case);
    if pages <= 4096 {
        return (0..pages).collect();
    }
    let made: Vec<u64> = committed.iter().map(|page| page / INDEX_FANOUT).collect();
    (0..pages)
        .filter(|page| page % INDEX_FANOUT == 0 || made.contains(&(page / INDEX_FANOUT)))
        .collect()
}

/// What each page of `probes` resolves to: its frame, or why it has none.
fn resolved(
    roles: &Manager,
    backing: BackingIdentity,
    probes: &[u64],
) -> Vec<Result<u64, FrameRoleError>> {
    let mut cursor = BackingCursor::new(backing);
    probes
        .iter()
        .map(|&page| {
            roles
                .resolve_at(&mut cursor, page * PAGE, false)
                .map(|segment| segment.physical_start)
        })
        .collect()
}

/// Everything a decommit changes: each slot's generation and record, every
/// index entry written, the frames free, and the frames the backing holds.
type State = (
    Vec<(u32, Option<RoleRecord>)>,
    BTreeMap<(u64, usize), u64>,
    u64,
    Result<u64, FrameRoleError>,
);

fn state(roles: &Manager, model: &Model, backing: BackingIdentity) -> State {
    (
        roles
            .slot_views()
            .map(|(_, view)| (view.generation, view.record))
            .collect(),
        model.written(),
        roles.available_frames(),
        roles.on_demand_frames(backing),
    )
}

/// For each range of `case` and each budget `b`: one call of budget `b`
/// gives the result, and leaves the state, that calls of budget 1 from
/// each returned cursor give until they have visited `b` entries or the
/// cursor reaches the end.
fn calls_of_budget_one_agree(case: Case) {
    let (pages, _) = layout(case);
    let probes = probes(case);
    for (start, end) in ranges(case) {
        let stop = end.min(pages);
        for budget in BUDGETS {
            let (mut one, one_model, backing, _) = build(case);
            let (mut many, many_model, many_backing, _) = build(case);
            assert_eq!(backing.0.raw, many_backing.0.raw);
            let what = std::format!("{case:?}, [{start}, {end}), budget {budget}");
            let called = one
                .decommit_on_demand_range(backing, start, end, budget)
                .unwrap();
            let mut repeated = (start, 0, 0);
            while repeated.0 < stop && repeated.2 < budget {
                let (next, freed, visited) = many
                    .decommit_on_demand_range(many_backing, repeated.0, end, 1)
                    .unwrap();
                assert_eq!(visited, 1, "{what}");
                repeated = (next, repeated.1 + freed, repeated.2 + visited);
            }
            assert_eq!(called, repeated, "{what}");
            assert_eq!(one.check_invariants(), Ok(()), "{what}");
            assert_eq!(many.check_invariants(), Ok(()), "{what}");
            assert_eq!(
                one.on_demand_frames(backing),
                many.on_demand_frames(many_backing),
                "{what}"
            );
            assert_eq!(
                state(&one, one_model, backing),
                state(&many, many_model, many_backing),
                "{what}"
            );
            assert!(
                resolved(&one, backing, &probes) == resolved(&many, many_backing, &probes),
                "{what}"
            );
        }
    }
}

#[test]
fn a_decommit_of_budget_b_in_a_root_that_is_its_own_leaf_does_what_calls_of_budget_one_do() {
    calls_of_budget_one_agree(Case::OwnLeaf);
}

#[test]
fn a_decommit_of_budget_b_in_sparse_leaves_does_what_calls_of_budget_one_do() {
    calls_of_budget_one_agree(Case::Sparse);
}

#[test]
fn a_decommit_of_budget_b_in_dense_leaves_does_what_calls_of_budget_one_do() {
    calls_of_budget_one_agree(Case::Dense);
}

#[test]
fn a_decommit_of_budget_b_in_three_levels_does_what_calls_of_budget_one_do() {
    calls_of_budget_one_agree(Case::ThreeLevels);
}

#[test]
fn decommitting_a_full_leaf_of_a_two_level_root_reads_its_parent_entry_a_bounded_number_of_times() {
    let (mut roles, model) = sized::<1024>(2048);
    let grant = roles.allocate_on_demand_backing(1024).unwrap();
    let backing = grant.identity();
    for page in 512..1024 {
        roles.commit_on_demand_page(backing, page).unwrap();
    }
    let root = grant.physical_start();
    let before = model.reads_of(root, 1);
    let reads = model.reads();
    assert_eq!(
        roles.decommit_on_demand_range(backing, 512, 1024, 600),
        Ok((1024, 512, 512))
    );
    // Once by the one walk, not once per page.
    assert!(model.reads_of(root, 1) - before <= 2);
    assert!(model.reads() - reads <= 512 + 2);
    // The root and the leaf, which stays.
    assert_eq!(roles.on_demand_frames(backing), Ok(2));
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();
}

#[test]
fn a_decommit_across_leaves_leaves_its_range_absent_and_the_pages_around_it_committed() {
    let (mut roles, _) = sized::<2048>(4096);
    let grant = roles.allocate_on_demand_backing(1536).unwrap();
    let backing = grant.identity();
    let mut frames = BTreeMap::new();
    for page in 290..1110 {
        let committed = roles.commit_on_demand_page(backing, page).unwrap();
        frames.insert(page, committed.physical_start);
    }
    assert_eq!(
        roles.decommit_on_demand_range(backing, 300, 1100, 4096),
        Ok((1100, 800, 800))
    );
    assert_eq!(roles.check_invariants(), Ok(()));
    for page in 290..1110 {
        let found = roles
            .resolve_object_page(backing, page * PAGE, false)
            .map(|segment| segment.physical_start);
        if (300..1100).contains(&page) {
            assert_eq!(found, Err(FrameRoleError::Absent), "page {page}");
        } else {
            assert_eq!(found, Ok(frames[&page]), "page {page}");
        }
    }
    roles.cancel_object_backing(grant).unwrap();
}
