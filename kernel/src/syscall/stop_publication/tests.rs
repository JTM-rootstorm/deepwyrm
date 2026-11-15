extern crate std;

use super::*;

const TARGET: u32 = 1;
const OTHER: u32 = 2;
const PROCESS: u8 = 10;
const FOREIGN: u8 = 11;

fn claim(thread: u32, terminal: bool) -> Option<ClaimFact<u32>> {
    Some(ClaimFact { thread, terminal })
}

/// A CPU running the terminal Thread, able to take a Stop.
fn running() -> StopTargetFacts<u32, u8> {
    StopTargetFacts {
        suspended: None,
        running: claim(TARGET, true),
        control: WaitControlHandoff::Clear,
        last_scheduled: Some(TARGET),
        root_switch_flight: false,
        active_root: Some(PROCESS),
        mailbox_idle: true,
        deferred_current: false,
        pending_termination: false,
    }
}

/// A CPU whose terminal Thread holds the suspended claim with `control`,
/// and `running` as its Running claim.
fn suspended(
    control: WaitControlHandoff,
    running: Option<ClaimFact<u32>>,
) -> StopTargetFacts<u32, u8> {
    StopTargetFacts {
        suspended: claim(TARGET, true),
        running,
        control,
        ..self::running()
    }
}

fn decide(facts: StopTargetFacts<u32, u8>) -> Result<StopPublication, StopRefusal> {
    decide_stop_publication(facts, |thread| {
        assert_eq!(thread, TARGET, "only the Stop's claim is looked up");
        PROCESS
    })
}

const RUNNING: Result<StopPublication, StopRefusal> = Ok(StopPublication::Publish {
    claim: StopTarget::Running,
    retire_unentered: false,
});
const SUSPENDED: Result<StopPublication, StopRefusal> = Ok(StopPublication::Publish {
    claim: StopTarget::Suspended,
    retire_unentered: false,
});

/// The states a Stop may be published in, and what it names.
#[test]
fn a_stoppable_cpu_is_published_to() {
    assert_eq!(decide(running()), RUNNING);
    // A block committed, `prepare_suspend` not run: with or without its
    // replacement chosen (that replacement not terminal).
    for replacement in [false, true] {
        assert_eq!(
            decide(suspended(WaitControlHandoff::Pending { replacement }, None)),
            SUSPENDED
        );
    }
    assert_eq!(
        decide(suspended(
            WaitControlHandoff::Pending { replacement: true },
            claim(OTHER, false)
        )),
        SUSPENDED
    );
    assert_eq!(decide(suspended(WaitControlHandoff::Idle, None)), SUSPENDED);
    assert_eq!(
        decide(suspended(WaitControlHandoff::Resuming, None)),
        SUSPENDED
    );
    // Both claims terminal under a pending block: the Stop names the
    // physical one and the preparation retires the unentered replacement.
    assert_eq!(
        decide(StopTargetFacts {
            running: claim(OTHER, true),
            ..suspended(WaitControlHandoff::Pending { replacement: true }, None)
        }),
        Ok(StopPublication::Publish {
            claim: StopTarget::Suspended,
            retire_unentered: true,
        })
    );
    // A Running claim of the terminal Thread beside another Thread's
    // suspended claim names the Running one.
    assert_eq!(
        decide(StopTargetFacts {
            suspended: claim(OTHER, false),
            ..running()
        }),
        RUNNING
    );
}

/// No terminal claim on the CPU: nothing is published, whatever else holds.
#[test]
fn a_cpu_without_a_terminal_claim_is_left_alone() {
    let busy = StopTargetFacts {
        suspended: claim(OTHER, false),
        running: claim(OTHER + 1, false),
        last_scheduled: None,
        root_switch_flight: true,
        active_root: None,
        mailbox_idle: false,
        deferred_current: true,
        pending_termination: true,
        ..running()
    };
    assert_eq!(
        decide_stop_publication(busy, |_: u32| -> u8 { panic!("no owner is looked up") }),
        Ok(StopPublication::Nothing)
    );
}

/// Each refusal, alone: today's three (flight, `last_scheduled`, root) and
/// revision 2's (pending termination, prepared switch, mailbox, deferred
/// current).
#[test]
fn each_unstoppable_fact_refuses_alone() {
    let cases = [
        (
            StopTargetFacts {
                root_switch_flight: true,
                ..running()
            },
            StopRefusal::RootSwitchFlight,
        ),
        (
            StopTargetFacts {
                last_scheduled: Some(OTHER),
                ..running()
            },
            StopRefusal::NotLastScheduled,
        ),
        (
            StopTargetFacts {
                last_scheduled: None,
                ..running()
            },
            StopRefusal::NotLastScheduled,
        ),
        (
            StopTargetFacts {
                active_root: None,
                ..running()
            },
            StopRefusal::NoActiveRoot,
        ),
        (
            StopTargetFacts {
                active_root: Some(FOREIGN),
                ..running()
            },
            StopRefusal::ForeignRoot,
        ),
        // Audit D1: the CPU's own termination is between its prepare and
        // completion holds.
        (
            StopTargetFacts {
                pending_termination: true,
                ..running()
            },
            StopRefusal::PendingTermination,
        ),
        // Review DD4: an earlier Stop not yet reclaimed by its initiator.
        (
            StopTargetFacts {
                mailbox_idle: false,
                ..running()
            },
            StopRefusal::MailboxBusy,
        ),
        (
            StopTargetFacts {
                deferred_current: true,
                ..running()
            },
            StopRefusal::DeferredCurrent,
        ),
        // Audit R2: a switch prepared away from the terminal Thread, its
        // destination another Thread (read unfiltered) or none.
        (
            suspended(WaitControlHandoff::Clear, claim(OTHER, false)),
            StopRefusal::PreparedSwitch,
        ),
        (
            suspended(WaitControlHandoff::Clear, None),
            StopRefusal::PreparedSwitch,
        ),
        // The "both terminal" branch takes the same guard: with a Clear
        // control the replacement may already execute.
        (
            suspended(WaitControlHandoff::Clear, claim(OTHER, true)),
            StopRefusal::PreparedSwitch,
        ),
        (
            suspended(
                WaitControlHandoff::Pending { replacement: true },
                claim(TARGET, true),
            ),
            StopRefusal::OneThreadTwoClaims,
        ),
    ];
    for (facts, refusal) in cases {
        assert_eq!(decide(facts), Err(refusal), "{facts:?}");
    }
}

/// The refusals apply to a suspended Stop claim as to a Running one.
#[test]
fn a_suspended_claim_is_refused_for_the_same_facts() {
    let base = suspended(WaitControlHandoff::Idle, None);
    for (facts, refusal) in [
        (
            StopTargetFacts {
                pending_termination: true,
                ..base
            },
            StopRefusal::PendingTermination,
        ),
        (
            StopTargetFacts {
                mailbox_idle: false,
                ..base
            },
            StopRefusal::MailboxBusy,
        ),
        (
            StopTargetFacts {
                deferred_current: true,
                ..base
            },
            StopRefusal::DeferredCurrent,
        ),
        (
            StopTargetFacts {
                root_switch_flight: true,
                ..base
            },
            StopRefusal::RootSwitchFlight,
        ),
    ] {
        assert_eq!(decide(facts), Err(refusal), "{facts:?}");
    }
}
