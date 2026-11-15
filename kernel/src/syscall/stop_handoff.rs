//! A remote Stop's precommit, classified once (DW2 §10.15 revision 2 item 4;
//! step-6 design review §5b, D-B, D-C). Clear with a suspended claim (D-C) is
//! named and refused: it is a prepared switch whose destination already runs
//! on this CPU, and stopping there is not sound (audit R2).
//!
//! The panics below are invariants, not cases a Stop may meet (DW2 §10.16
//! revision 2 item 5). Publication refuses a CPU in any of those states
//! (`stop_publication`), and every hold that moves a CPU into one looks for
//! a Stop first and takes it instead (preemption and yield, `prepare_suspend`,
//! the idle poll, a termination's prepare hold on the syscall and the
//! exception path). So a Stop is published before the transition, and that
//! hold finds it, or after, and publication refuses it.
//!
//! The stopped CPU's precommit reads the facts a Thread's handoff into and
//! out of a suspension leaves behind (its suspended and Running claims, what
//! physically executes, its wait control, the stopped Thread's own F-service
//! operation owner) and names the one state they describe, or panics naming
//! every fact. What the stop does is then a function of that state: which
//! claim it retires, whether it retires the wait control (and so takes the
//! quantum cancellation a pending suspension carries), and whether it moves
//! the stopped Thread's service operation out before the commit.

use super::adapters::WaitControlHandoff;
use super::f_services::{FServiceOperationOwner, FServiceOwnerError};

/// This CPU's Running claim, compared with the Stop's exact claim on its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunningClaim {
    /// No Running claim.
    None,
    /// The Running claim is the Stop's.
    Stopped,
    /// The Running claim names another Thread: a replacement chosen by a
    /// block, not yet entered.
    Other,
}

/// Which of this CPU's claims is the Stop's. The precommit refuses a Stop
/// that matches neither (`StaleRequest`) and prefers the suspended claim, so
/// only these two can reach the classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopClaim {
    /// The suspended claim is the Stop's; `running` is the Running claim,
    /// observed independently.
    Suspended { running: RunningClaim },
    /// The Running claim is the Stop's and no suspended claim is.
    Running,
}

/// What the stopped CPU's precommit observes, after every rejectable
/// identity check has passed (those include that a suspended claim's
/// Thread is the one this CPU physically executes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopHandoffFacts {
    pub(crate) claim: StopClaim,
    /// A terminal handoff owns this CPU's continuation (deferred current).
    pub(crate) terminal_owned: bool,
    /// The stopped Thread has a call parked between steps.
    pub(crate) parked_call: bool,
    /// Releases staged in this CPU's cleanup outbox (revision 2 item 3).
    pub(crate) outbox_staged: usize,
    pub(crate) control: WaitControlHandoff,
    /// The stopped Thread's own F-service operation owner.
    pub(crate) owner: Result<FServiceOperationOwner, FServiceOwnerError>,
}

/// The states a Stop can meet a Thread in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopHandoffState {
    /// Running, with no suspension in flight.
    Running,
    /// Running, with a call parked between steps; termination's drain
    /// settles the record.
    RunningWithParkedCall,
    /// Resumed past its physical handoff, its operation not yet settled by
    /// the resume hold (D-B).
    ResumedUnsettled,
    /// Its block committed and `prepare_suspend` has not run (step-6 D-1).
    Pending { replacement: bool },
    /// Its suspension idles the CPU.
    Idle,
    /// Its idle poll found the winner, short of the resume's handoff. The
    /// scheduler has already turned the suspended claim into a Running one
    /// (`schedule_from_idle_on`), so this is met on the Running branch; a
    /// suspended claim with a resuming control is classified the same.
    Resuming,
}

/// What the stop does in a state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopHandoffPlan {
    pub(crate) state: StopHandoffState,
    /// The stop retires the suspended claim; otherwise the Running claim
    /// (and takes that claim's quantum cancellation).
    pub(crate) suspended_claim: bool,
    /// The stop retires the wait control, taking a pending suspension's
    /// quantum cancellation.
    pub(crate) retire_control: bool,
    /// The stopped Thread has an operation: the stop moves its cleanup out
    /// of the service registries before the commit, in either branch (D-B).
    pub(crate) transfer_service_cleanup: bool,
}

/// Classifies a precommit's facts, or panics naming them all.
#[track_caller]
pub(crate) fn classify_stop_handoff(facts: StopHandoffFacts) -> StopHandoffPlan {
    let unclassified = |why: &str| -> ! {
        panic!("remote stop precommit cannot classify its handoff ({why}): {facts:?}")
    };
    // Upheld by publication's deferred-current refusal.
    if facts.terminal_owned {
        unclassified("a terminal handoff owns the continuation");
    }
    // An outbox is staged only between a termination's prepare hold and its
    // completion hold, or by a Retry hold that pushed nothing. Publication
    // refuses a CPU that owns a pending termination (audit D1), and both
    // prepare holds look for a Stop before preparing.
    if facts.outbox_staged != 0 {
        unclassified("the stopped CPU's cleanup outbox is not empty");
    }
    let transfer_service_cleanup = match facts.owner {
        Ok(_) => true,
        Err(FServiceOwnerError::Missing) => false,
        Err(FServiceOwnerError::Ambiguous) => unclassified("the operation owner is ambiguous"),
    };
    let state = match facts.claim {
        StopClaim::Suspended {
            running: RunningClaim::Stopped,
        } => unclassified("both claims are the Stop's"),
        StopClaim::Suspended { running } => match facts.control {
            WaitControlHandoff::Pending { replacement } => StopHandoffState::Pending {
                replacement: replacement || running == RunningClaim::Other,
            },
            WaitControlHandoff::Idle => StopHandoffState::Idle,
            WaitControlHandoff::Resuming => StopHandoffState::Resuming,
            // A switch prepared away from the stopped Thread (by
            // `prepare_suspend`, a preemption, a yield or an idle poll) whose
            // destination has not reached its handoff: the destination
            // already runs on this CPU, and the reaper would resume it from
            // the continuation it saved when it last switched out, which its
            // run since has overwritten. Not sound to stop here (DW2 §10.15
            // audit R2). Unreachable: publication refuses this state, and
            // each of those four holds takes a Stop published before it
            // instead of preparing the switch (DW2 §10.16 revision 2).
            WaitControlHandoff::Clear => {
                unclassified("a prepared switch's outgoing Thread, its destination already running")
            }
        },
        StopClaim::Running => match (facts.control, transfer_service_cleanup, facts.parked_call) {
            (WaitControlHandoff::Clear, false, false) => StopHandoffState::Running,
            (WaitControlHandoff::Clear, false, true) => StopHandoffState::RunningWithParkedCall,
            (WaitControlHandoff::Clear, true, false) => StopHandoffState::ResumedUnsettled,
            (WaitControlHandoff::Clear, true, true) => {
                unclassified("a parked call beside an unsettled operation")
            }
            // The idle poll's `ResumeCurrent` gives the scheduler's suspended
            // claim back as a Running claim at once; the control stays
            // `Resuming` until the resume's handoff hold.
            (WaitControlHandoff::Resuming, _, false) => StopHandoffState::Resuming,
            (WaitControlHandoff::Resuming, _, true) => {
                unclassified("a parked call beside a resuming suspension")
            }
            (WaitControlHandoff::Pending { .. } | WaitControlHandoff::Idle, _, _) => {
                unclassified("a Running claim with a suspension handoff in flight")
            }
        },
    };
    StopHandoffPlan {
        state,
        suspended_claim: matches!(facts.claim, StopClaim::Suspended { .. }),
        retire_control: facts.control != WaitControlHandoff::Clear,
        transfer_service_cleanup,
    }
}

#[cfg(test)]
#[path = "stop_handoff/tests.rs"]
mod tests;
