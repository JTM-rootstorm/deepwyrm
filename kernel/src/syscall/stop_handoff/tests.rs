extern crate std;

use super::*;

fn running() -> StopHandoffFacts {
    StopHandoffFacts {
        suspended: false,
        running: true,
        other_running: false,
        physically_executes: true,
        terminal_owned: false,
        parked_call: false,
        outbox_staged: 0,
        control: WaitControlHandoff::Clear,
        owner: Err(FServiceOwnerError::Missing),
    }
}

fn suspended(control: WaitControlHandoff) -> StopHandoffFacts {
    StopHandoffFacts {
        suspended: true,
        running: false,
        control,
        owner: Ok(FServiceOperationOwner::GenericWait),
        ..running()
    }
}

fn panics(facts: StopHandoffFacts) -> std::string::String {
    let message = std::panic::catch_unwind(|| classify_stop_handoff(facts))
        .expect_err("these facts must not classify");
    message
        .downcast_ref::<std::string::String>()
        .cloned()
        .expect("a formatted panic")
}

/// Every state §10.15 lists, with revision 2's additions, and the stop's
/// actions in each.
#[test]
fn every_handoff_state_classifies_with_its_actions() {
    let plan = |state, suspended_claim, retire_control, transfer_service_cleanup| StopHandoffPlan {
        state,
        suspended_claim,
        retire_control,
        transfer_service_cleanup,
    };
    let cases = [
        (
            running(),
            plan(StopHandoffState::Running, false, false, false),
        ),
        (
            StopHandoffFacts {
                parked_call: true,
                ..running()
            },
            plan(StopHandoffState::RunningWithParkedCall, false, false, false),
        ),
        // D-B: resumed past its handoff with its operation unsettled; the
        // transfer follows the Thread's own owner, in the Running branch too.
        (
            StopHandoffFacts {
                owner: Ok(FServiceOperationOwner::AtomicWait),
                ..running()
            },
            plan(StopHandoffState::ResumedUnsettled, false, false, true),
        ),
        (
            suspended(WaitControlHandoff::Pending { replacement: false }),
            plan(
                StopHandoffState::Pending { replacement: false },
                true,
                true,
                true,
            ),
        ),
        (
            suspended(WaitControlHandoff::Pending { replacement: true }),
            plan(
                StopHandoffState::Pending { replacement: true },
                true,
                true,
                true,
            ),
        ),
        (
            StopHandoffFacts {
                other_running: true,
                ..suspended(WaitControlHandoff::Pending { replacement: false })
            },
            plan(
                StopHandoffState::Pending { replacement: true },
                true,
                true,
                true,
            ),
        ),
        (
            suspended(WaitControlHandoff::Idle),
            plan(StopHandoffState::Idle, true, true, true),
        ),
        (
            suspended(WaitControlHandoff::Resuming),
            plan(StopHandoffState::Resuming, true, true, true),
        ),
        // The live order: `ResumeCurrent` already made the claim Running.
        // The stop retires the control on the Running branch.
        (
            StopHandoffFacts {
                control: WaitControlHandoff::Resuming,
                owner: Ok(FServiceOperationOwner::GenericWait),
                ..running()
            },
            plan(StopHandoffState::Resuming, false, true, true),
        ),
        (
            StopHandoffFacts {
                control: WaitControlHandoff::Resuming,
                ..running()
            },
            plan(StopHandoffState::Resuming, false, true, false),
        ),
        // D-C: Clear with a suspended claim is a prepared switch, classified.
        (
            suspended(WaitControlHandoff::Clear),
            plan(StopHandoffState::SwitchPrepared, true, false, true),
        ),
        // The initiator already cleaned the operation: no transfer.
        (
            StopHandoffFacts {
                owner: Err(FServiceOwnerError::Missing),
                ..suspended(WaitControlHandoff::Idle)
            },
            plan(StopHandoffState::Idle, true, true, false),
        ),
    ];
    for (facts, expected) in cases {
        assert_eq!(classify_stop_handoff(facts), expected, "{facts:?}");
    }
}

/// The transfer is decided by the stopped Thread's own owner alone: another
/// Thread's operation (the global quiescence the old precommit read) does
/// not enter the facts at all, and the same facts give the same decision.
#[test]
fn the_transfer_predicate_is_the_stopped_threads_own_owner() {
    for owner in [
        Ok(FServiceOperationOwner::GenericWait),
        Ok(FServiceOperationOwner::AtomicWait),
        Err(FServiceOwnerError::Missing),
    ] {
        for facts in [running(), suspended(WaitControlHandoff::Idle)] {
            let plan = classify_stop_handoff(StopHandoffFacts { owner, ..facts });
            assert_eq!(plan.transfer_service_cleanup, owner.is_ok(), "{owner:?}");
        }
    }
}

#[test]
fn unclassifiable_handoffs_panic_naming_their_facts() {
    let terminal = panics(StopHandoffFacts {
        terminal_owned: true,
        ..running()
    });
    assert!(
        terminal.contains("a terminal handoff owns the continuation")
            && terminal.contains("terminal_owned: true"),
        "{terminal}"
    );
    let outbox = panics(StopHandoffFacts {
        outbox_staged: 2,
        ..suspended(WaitControlHandoff::Idle)
    });
    assert!(
        outbox.contains("the stopped CPU's cleanup outbox is not empty")
            && outbox.contains("outbox_staged: 2"),
        "{outbox}"
    );
    let ambiguous = panics(StopHandoffFacts {
        owner: Err(FServiceOwnerError::Ambiguous),
        ..running()
    });
    assert!(ambiguous.contains("ambiguous"), "{ambiguous}");
    for control in [
        WaitControlHandoff::Pending { replacement: false },
        WaitControlHandoff::Idle,
    ] {
        let message = panics(StopHandoffFacts {
            control,
            ..running()
        });
        assert!(
            message.contains("a Running claim with a suspension handoff in flight"),
            "{message}"
        );
    }
    let neither = panics(StopHandoffFacts {
        running: false,
        ..running()
    });
    assert!(neither.contains("neither claim"), "{neither}");
    let elsewhere = panics(StopHandoffFacts {
        physically_executes: false,
        ..suspended(WaitControlHandoff::Idle)
    });
    assert!(elsewhere.contains("does not execute"), "{elsewhere}");
}
