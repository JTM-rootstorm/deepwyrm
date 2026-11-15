extern crate std;

use super::*;
use crate::object::{ObjectId, ObjectRegistry};
use crate::syscall::StagedStopCleanup;
use deepwyrm_abi::DW_OBJECT_TYPE_EVENT;
use std::vec::Vec;

const OBJECTS: usize = 8;
const CPUS: usize = 4;

fn release(registry: &mut ObjectRegistry<OBJECTS>) -> FinalRelease {
    let creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
    let reference = registry.creation_into_handle(creation).unwrap();
    registry
        .release_handle(reference)
        .unwrap()
        .expect("the only reference to a new object finalizes")
}

/// A drain of the shared queue: every release it pops is finalized, in
/// order, and recorded.
fn drain(
    registry: &mut ObjectRegistry<OBJECTS>,
    shared: &mut CleanupQueue<OBJECTS>,
    finalized: &mut Vec<ObjectId>,
) {
    while let Some(release) = shared.pop() {
        finalized.push(release.id());
        registry.complete_finalization(release).unwrap();
    }
}

/// One hold on `cpu` that pushed `pushed` and ends with `end`, as the
/// carrier ends it: settle the queues, drain if told to, and leave both
/// queues empty (the F-service queue is absorbed before, so it is empty).
fn end_hold(
    registry: &mut ObjectRegistry<OBJECTS>,
    shared: &mut CleanupQueue<OBJECTS>,
    outboxes: &mut CleanupOutboxes<OBJECTS, CPUS>,
    finalized: &mut Vec<ObjectId>,
    cpu: usize,
    end: HoldEnd,
) {
    if settle_hold_queues(end, cpu, shared, outboxes) {
        drain(registry, shared, finalized);
    }
    assert_hold_ended(shared.is_empty(), true);
}

#[test]
fn every_syscall_control_has_one_hold_end() {
    assert_eq!(
        hold_end_for(SyscallControl::ReturnToCaller),
        HoldEnd::Return
    );
    assert_eq!(
        hold_end_for(SyscallControl::TerminateCurrent),
        HoldEnd::Stage
    );
    assert_eq!(
        hold_end_for(SyscallControl::CompleteRemoteStop),
        HoldEnd::Stage
    );
    assert_eq!(
        hold_end_for(SyscallControl::ServiceRendezvous),
        HoldEnd::Drain
    );
    assert_eq!(hold_end_for(SyscallControl::SuspendCurrent), HoldEnd::Drain);
    assert_eq!(hold_end_for(SyscallControl::YieldCurrent), HoldEnd::Drain);
}

/// Revision 2 items 1–2: a hold that pushes and ends is drained or staged,
/// never left in the shared queue, whichever end it takes.
#[test]
fn a_hold_that_pushes_ends_drained_or_staged_never_in_the_shared_queue() {
    for end in [HoldEnd::Drain, HoldEnd::Stage, HoldEnd::Return] {
        let mut registry = ObjectRegistry::<OBJECTS>::new();
        let mut shared = CleanupQueue::<OBJECTS>::new();
        let mut outboxes = CleanupOutboxes::<OBJECTS, CPUS>::new();
        let mut finalized = Vec::new();
        let first = release(&mut registry);
        let second = release(&mut registry);
        let ids = [first.id(), second.id()];
        shared.push(first);
        shared.push(second);
        end_hold(
            &mut registry,
            &mut shared,
            &mut outboxes,
            &mut finalized,
            1,
            end,
        );
        assert!(shared.is_empty(), "{end:?}");
        match end {
            HoldEnd::Drain | HoldEnd::Return => {
                assert_eq!(finalized, ids, "{end:?}");
                assert_eq!(outboxes.staged(1), 0);
            }
            HoldEnd::Stage => {
                assert!(finalized.is_empty());
                assert_eq!(outboxes.staged(1), 2);
                // The CPU's next Return hold finalizes them, in order.
                end_hold(
                    &mut registry,
                    &mut shared,
                    &mut outboxes,
                    &mut finalized,
                    1,
                    HoldEnd::Return,
                );
                assert_eq!(finalized, ids);
                assert_eq!(outboxes.staged(1), 0);
            }
        }
    }
}

/// Revision 2 item 2 and review C2/D2: a remote-termination initiator's
/// prepare hold stages the target's releases; other CPUs' holds, which
/// drain, and the stopped CPU's precommit, which stages only its own
/// pushes, leave them alone; they finalize at the initiator's completion
/// hold, after the acknowledgement.
#[test]
fn initiator_releases_finalize_only_after_the_acknowledgements() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut shared = CleanupQueue::<OBJECTS>::new();
    let mut outboxes = CleanupOutboxes::<OBJECTS, CPUS>::new();
    let mut rendezvous = StagedStopCleanup::<OBJECTS>::new();
    let mut finalized = Vec::new();
    let initiator = 0;
    let stopped = 2;

    // The initiator's prepare hold: the target Process's releases.
    let target = [release(&mut registry), release(&mut registry)];
    let target_ids = [target[0].id(), target[1].id()];
    for release in target {
        shared.push(release);
    }
    let end = hold_end_for(SyscallControl::CompleteRemoteStop);
    end_hold(
        &mut registry,
        &mut shared,
        &mut outboxes,
        &mut finalized,
        initiator,
        end,
    );

    // Another CPU's syscall returns with a release of its own.
    let other = release(&mut registry);
    let other_id = other.id();
    shared.push(other);
    end_hold(
        &mut registry,
        &mut shared,
        &mut outboxes,
        &mut finalized,
        1,
        HoldEnd::Return,
    );
    assert_eq!(finalized, [other_id]);

    // The stopped CPU's precommit stages what it pushed itself, only.
    let own = release(&mut registry);
    let own_id = own.id();
    shared.push(own);
    assert_eq!(outboxes.staged(stopped), 0);
    rendezvous.stage(&mut shared, CPUS);
    assert_hold_ended(shared.is_empty(), true);
    // Its commit finds the shared queue empty, and acknowledges; its
    // post-ack continuation finalizes its own staged release.
    assert!(shared.is_empty());
    assert!(rendezvous.finish(&mut shared));
    drain(&mut registry, &mut shared, &mut finalized);
    assert_eq!(finalized, [other_id, own_id]);
    assert_eq!(outboxes.staged(initiator), 2);

    // The initiator's completion hold, after the acknowledgement.
    end_hold(
        &mut registry,
        &mut shared,
        &mut outboxes,
        &mut finalized,
        initiator,
        HoldEnd::Return,
    );
    assert_eq!(finalized, [other_id, own_id, target_ids[0], target_ids[1]]);
}

/// A termination whose initiator itself terminates (its completion returns
/// `TerminateCurrent`) keeps both holds' releases staged for the terminal
/// handoff's first hold.
#[test]
fn a_terminating_initiator_keeps_its_releases_for_the_terminal_handoff() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut shared = CleanupQueue::<OBJECTS>::new();
    let mut outboxes = CleanupOutboxes::<OBJECTS, CPUS>::new();
    let mut finalized = Vec::new();
    let prepared = release(&mut registry);
    let completed = release(&mut registry);
    let ids = [prepared.id(), completed.id()];
    shared.push(prepared);
    end_hold(
        &mut registry,
        &mut shared,
        &mut outboxes,
        &mut finalized,
        3,
        hold_end_for(SyscallControl::CompleteRemoteStop),
    );
    shared.push(completed);
    end_hold(
        &mut registry,
        &mut shared,
        &mut outboxes,
        &mut finalized,
        3,
        hold_end_for(SyscallControl::TerminateCurrent),
    );
    assert!(finalized.is_empty());
    assert_eq!(outboxes.staged(3), 2);
    // The terminal handoff's first hold.
    end_hold(
        &mut registry,
        &mut shared,
        &mut outboxes,
        &mut finalized,
        3,
        HoldEnd::Return,
    );
    assert_eq!(finalized, ids);
}

#[test]
fn releasing_one_cpus_outbox_keeps_every_other_cpus_in_order() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut shared = CleanupQueue::<OBJECTS>::new();
    let mut outboxes = CleanupOutboxes::<OBJECTS, CPUS>::new();
    let mut ids = Vec::new();
    for cpu in [0, 1, 0, 2, 1] {
        let release = release(&mut registry);
        ids.push((cpu, release.id()));
        shared.push(release);
        outboxes.stage(cpu, &mut shared);
    }
    assert_eq!([0, 1, 2, 3].map(|cpu| outboxes.staged(cpu)), [2, 2, 1, 0]);
    let mut finalized = Vec::new();
    for cpu in [1, 3, 0, 2] {
        outboxes.release(cpu, &mut shared);
        drain(&mut registry, &mut shared, &mut finalized);
        let expected: Vec<ObjectId> = ids
            .iter()
            .filter(|(owner, _)| *owner == cpu)
            .map(|(_, id)| *id)
            .collect();
        assert_eq!(finalized, expected, "CPU {cpu}");
        finalized.clear();
        assert_eq!(outboxes.staged(cpu), 0);
    }
}

#[test]
#[should_panic(
    expected = "a runtime hold ended with cleanup undrained (shared queue empty: false, \
                           F-service queue empty: true)"
)]
fn a_hold_ending_with_the_shared_queue_full_is_named() {
    assert_hold_ended(false, true);
}

#[test]
#[should_panic(expected = "F-service queue empty: false")]
fn a_hold_ending_with_the_service_queue_full_is_named() {
    assert_hold_ended(true, false);
}

/// DW2 §10.19 revision 3: a hold off the BSP wakes it when it turned the
/// idle BSP's "owed work I can step" from false to true: a queue taken from
/// empty that is still owed at the hold's end, or the bootstrap's root
/// retired with teardown owed. Never for the BSP's own holds.
#[test]
fn a_hold_wakes_the_bsp_only_for_owed_work_it_newly_made_steppable() {
    const BSP: usize = 0;
    let change = |queued_from_empty, owed_at_end| OwedQueueChange {
        queued_from_empty,
        owed_at_end,
    };
    let facts = |finalization, teardown, retired| OwedHoldFacts {
        finalization,
        teardown,
        bootstrap_retired_with_teardown_owed: retired,
    };
    let none = change(false, false);
    let new_owed = change(true, true);
    // Queued into an empty queue and finished within the hold.
    let done_within = change(true, false);
    // Queued into a non-empty queue: owed at the end, not newly.
    let already_owed = change(false, true);
    let wake = |queue, retirement| OwedWake { queue, retirement };
    for (cpu, facts, expected) in [
        (1, facts(none, none, false), wake(false, false)),
        (1, facts(new_owed, none, false), wake(true, false)),
        (2, facts(none, new_owed, false), wake(true, false)),
        (3, facts(new_owed, new_owed, false), wake(true, false)),
        (1, facts(done_within, none, false), wake(false, false)),
        (1, facts(none, done_within, false), wake(false, false)),
        (
            1,
            facts(already_owed, already_owed, false),
            wake(false, false),
        ),
        (2, facts(done_within, new_owed, false), wake(true, false)),
        (1, facts(none, none, true), wake(false, true)),
        (3, facts(new_owed, already_owed, true), wake(true, true)),
        // The BSP's own holds: never.
        (BSP, facts(new_owed, new_owed, true), wake(false, false)),
        (BSP, facts(new_owed, none, false), wake(false, false)),
        (BSP, facts(none, none, true), wake(false, false)),
    ] {
        let woken = owed_work_wake(cpu, BSP, facts);
        assert_eq!(woken, expected, "cpu {cpu}, {facts:?}");
        assert_eq!(woken.any(), expected.queue || expected.retirement);
    }
}
