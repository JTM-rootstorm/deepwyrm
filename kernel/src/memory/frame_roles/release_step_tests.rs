//! A release step that walks once for a leaf (DW2 §12.12 item 5b): one
//! step of budget `b` does what steps of budget 1 do until they have
//! visited `b`, and reads a leaf's parent entry a bounded number of times.

extern crate std;

use super::indexed_tests::{Model, backing, holes, index_runs, sized};
use super::*;
use std::collections::BTreeMap;
use std::vec::Vec;

type Manager = FrameRoleManager<48, 2048>;

#[derive(Clone, Copy, Debug)]
enum Case {
    /// Two levels, three leaves, the middle one never made.
    OnDemandSparse,
    /// Two levels, three leaves, every page committed.
    OnDemandDense,
    /// Eager, two levels: a 700-page run across leaves 0 and 1 and a
    /// 300-page run ending inside leaf 0.
    EagerCrossing,
    /// Eager, two levels: a run ending exactly at leaf 0's end.
    EagerLeafEnd,
    /// Eager, one level: the root is the leaf.
    EagerOwnLeaf,
}

const CASES: [Case; 5] = [
    Case::OnDemandSparse,
    Case::OnDemandDense,
    Case::EagerCrossing,
    Case::EagerLeafEnd,
    Case::EagerOwnLeaf,
];

/// Eager backings from holes of `sizes`: the runs, then single pages.
fn eager(roles: &mut Manager, sizes: &[u64], pages: u64) -> BackingIdentity {
    let mut all = sizes.to_vec();
    all.extend([1; 16]);
    core::mem::forget(holes(roles, &all));
    let grant = backing(roles, pages);
    assert_eq!(grant.kind(), ObjectBackingKind::AllocatorIndexed);
    grant.identity()
}

/// A 1,536-page on-demand backing with `committed` pages committed.
fn on_demand(roles: &mut Manager, committed: &[u64]) -> BackingIdentity {
    let grant = roles.allocate_on_demand_backing(1536).unwrap();
    for &page in committed {
        roles.commit_on_demand_page(grant.identity(), page).unwrap();
    }
    grant.identity()
}

/// A manager holding the backing of `case`, and its pages.
fn build(case: Case) -> (Manager, &'static Model, BackingIdentity, u64) {
    let (mut roles, model) = sized::<2048>(4096);
    let (backing, pages) = match case {
        Case::OnDemandSparse => (on_demand(&mut roles, &[0, 7, 511, 1100, 1535]), 1536),
        Case::OnDemandDense => (on_demand(&mut roles, &(0..1536).collect::<Vec<_>>()), 1536),
        Case::EagerCrossing => {
            let backing = eager(&mut roles, &[700, 300, 9, 3, 2], 1026);
            assert_eq!(
                &index_runs(&roles, backing)[14..],
                &[(25, 300), (325, 700), (1025, 1)]
            );
            (backing, 1026)
        }
        Case::EagerLeafEnd => {
            let backing = eager(&mut roles, &[187, 300, 9, 3, 2], 513);
            let runs = index_runs(&roles, backing);
            assert!(
                runs.iter()
                    .any(|(first, count)| *count > 1 && first + count == INDEX_FANOUT),
                "a run ends at leaf 0's end: {runs:?}"
            );
            (backing, 513)
        }
        Case::EagerOwnLeaf => {
            let backing = eager(&mut roles, &[300, 9, 3, 2], 327);
            let (_, root) = roles.index_root(backing.0, RootUse::Any).unwrap();
            assert_eq!(root.levels, 1);
            (backing, 327)
        }
    };
    assert_eq!(roles.check_invariants(), Ok(()));
    (roles, model, backing, pages)
}

/// Everything a release changes: each slot's generation and record, every
/// index entry written, the frames free, and what the root's index holds.
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
        roles.index_count(backing.0, RootUse::Any),
    )
}

#[test]
fn a_step_of_budget_b_does_what_steps_of_budget_one_do_until_they_have_visited_b() {
    for case in CASES {
        for warmup in [0, 3] {
            for budget in [1, 2, 3, 7, 300, 513, 1100] {
                let (mut one, one_model, backing, pages) = build(case);
                let (mut many, many_model, many_backing, _) = build(case);
                assert_eq!(backing.0.raw, many_backing.0.raw);
                // The same steps first, so the step starts mid-release.
                let mut cursor = 0;
                for _ in 0..warmup {
                    if cursor < pages {
                        let (next, _, _) = one.release_index_step(backing, cursor, 7).unwrap();
                        let same = many.release_index_step(many_backing, cursor, 7).unwrap();
                        assert_eq!(next, same.0);
                        cursor = next;
                    }
                }
                if cursor >= pages {
                    continue;
                }
                let stepped = one.release_index_step(backing, cursor, budget).unwrap();
                let mut repeated = (cursor, 0, 0);
                while repeated.0 < pages && repeated.2 < budget {
                    let (next, freed, visited) = many
                        .release_index_step(many_backing, repeated.0, 1)
                        .unwrap();
                    repeated = (next, repeated.1 + freed, repeated.2 + visited);
                }
                let what = std::format!("{case:?}, warm-up {warmup}, budget {budget}");
                assert_eq!(stepped, repeated, "{what}");
                assert_eq!(one.check_invariants(), Ok(()), "{what}");
                assert_eq!(many.check_invariants(), Ok(()), "{what}");
                assert_eq!(
                    state(&one, one_model, backing),
                    state(&many, many_model, many_backing),
                    "{what}"
                );
            }
        }
    }
}

#[test]
fn releasing_a_full_leaf_of_an_on_demand_root_reads_its_parent_entry_a_bounded_number_of_times() {
    let (mut roles, model) = sized::<1024>(2048);
    let grant = roles.allocate_on_demand_backing(1024).unwrap();
    let backing = grant.identity();
    for page in 512..1024 {
        roles.commit_on_demand_page(backing, page).unwrap();
    }
    let root = grant.physical_start();
    let before = model.reads_of(root, 1);
    let reads = model.reads();
    // The leaf's 512 pages, then the leaf itself.
    assert_eq!(
        roles.release_index_step(backing, 512, 600),
        Ok((1024, 513, 513))
    );
    // Once by the walk and once to free the leaf, not once per page.
    assert!(model.reads_of(root, 1) - before <= 2);
    assert!(model.reads() - reads <= 512 + 2);
    assert_eq!(roles.on_demand_frames(backing), Ok(1));
    assert_eq!(roles.check_invariants(), Ok(()));
    roles.cancel_object_backing(grant).unwrap();
}
