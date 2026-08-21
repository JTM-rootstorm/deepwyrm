use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Owner {
    MappingPin,
    PageTable,
    HandleTable,
    TaskState,
    Channel,
    Timer,
    WaitRegistry,
    Scheduler,
    ObjectRegistry,
    Finalizer,
}

const OWNERS: [Owner; 10] = [
    Owner::MappingPin,
    Owner::PageTable,
    Owner::HandleTable,
    Owner::TaskState,
    Owner::Channel,
    Owner::Timer,
    Owner::WaitRegistry,
    Owner::Scheduler,
    Owner::ObjectRegistry,
    Owner::Finalizer,
];

/// Directed edges model the only nested ownership directions permitted by the
/// F0 contract. Operations may avoid nesting and execute these owners
/// sequentially; they must never introduce an edge in the opposite direction.
const ALLOWED_NESTING: &[(Owner, Owner)] = &[
    (Owner::MappingPin, Owner::HandleTable),
    (Owner::PageTable, Owner::ObjectRegistry),
    (Owner::HandleTable, Owner::Channel),
    (Owner::HandleTable, Owner::Timer),
    (Owner::HandleTable, Owner::ObjectRegistry),
    (Owner::TaskState, Owner::ObjectRegistry),
    (Owner::Channel, Owner::WaitRegistry),
    (Owner::Channel, Owner::ObjectRegistry),
    (Owner::Timer, Owner::WaitRegistry),
    (Owner::Timer, Owner::ObjectRegistry),
    (Owner::WaitRegistry, Owner::Scheduler),
    (Owner::WaitRegistry, Owner::ObjectRegistry),
    (Owner::Scheduler, Owner::ObjectRegistry),
];

const FORBIDDEN_SIMULTANEOUS_OWNERSHIP: &[(Owner, Owner)] = &[
    (Owner::TaskState, Owner::HandleTable),
    (Owner::Finalizer, Owner::HandleTable),
    (Owner::Finalizer, Owner::TaskState),
    (Owner::Finalizer, Owner::Channel),
    (Owner::Finalizer, Owner::Timer),
    (Owner::Finalizer, Owner::WaitRegistry),
    (Owner::Finalizer, Owner::Scheduler),
    (Owner::Finalizer, Owner::PageTable),
];

#[test]
fn f11_f_owner_dependency_model_is_acyclic() {
    let mut incoming = BTreeMap::from_iter(OWNERS.map(|owner| (owner, 0_usize)));
    let mut outgoing = BTreeMap::from_iter(OWNERS.map(|owner| (owner, BTreeSet::<Owner>::new())));

    for &(outer, inner) in ALLOWED_NESTING {
        assert_ne!(outer, inner, "an owner cannot nest itself");
        assert!(
            outgoing.get_mut(&outer).unwrap().insert(inner),
            "duplicate ownership edge {outer:?} -> {inner:?}"
        );
        *incoming.get_mut(&inner).unwrap() += 1;
    }

    let mut ready = incoming
        .iter()
        .filter_map(|(&owner, &count)| (count == 0).then_some(owner))
        .collect::<BTreeSet<_>>();
    let mut visited = 0;
    while let Some(owner) = ready.pop_first() {
        visited += 1;
        for &inner in &outgoing[&owner] {
            let count = incoming.get_mut(&inner).unwrap();
            *count -= 1;
            if *count == 0 {
                ready.insert(inner);
            }
        }
    }

    assert_eq!(
        visited,
        OWNERS.len(),
        "F11 ownership dependencies contain a lock/finalizer cycle"
    );
}

#[test]
fn f11_forbidden_owner_pairs_have_no_nesting_path() {
    fn reachable(from: Owner, to: Owner) -> bool {
        let mut pending = BTreeSet::from([from]);
        let mut visited = BTreeSet::new();
        while let Some(owner) = pending.pop_first() {
            if owner == to {
                return true;
            }
            if visited.insert(owner) {
                pending.extend(ALLOWED_NESTING.iter().filter_map(|&(outer, inner)| {
                    (outer == owner).then_some(inner)
                }));
            }
        }
        false
    }

    for &(left, right) in FORBIDDEN_SIMULTANEOUS_OWNERSHIP {
        assert!(!reachable(left, right));
        assert!(!reachable(right, left));
    }

    assert!(
        ALLOWED_NESTING
            .iter()
            .all(|&(outer, inner)| outer != Owner::Finalizer && inner != Owner::Finalizer),
        "typed finalization must run only after every mutation owner is released"
    );
}
