//! A remote Stop's precommit, classified once (DW2 §10.15 revision 2 item 4;
//! step-6 design review §5b, D-B, D-C).
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

/// What the stopped CPU's precommit observes, after every rejectable
/// identity check has passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopHandoffFacts {
    /// The CPU's suspended claim is the Stop's exact claim.
    pub(crate) suspended: bool,
    /// The CPU's Running claim is the Stop's exact claim.
    pub(crate) running: bool,
    /// The CPU's Running claim names another Thread: a replacement chosen
    /// by a block, not yet entered.
    pub(crate) other_running: bool,
    /// This CPU physically executes the stopped Thread.
    pub(crate) physically_executes: bool,
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
    /// Its suspension's switch was prepared (by `prepare_suspend`, or by an
    /// idle poll that returned `Switch`) and has not completed: the control
    /// is clear and the suspended claim is still this CPU's (D-C).
    SwitchPrepared,
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
    if facts.terminal_owned {
        unclassified("a terminal handoff owns the continuation");
    }
    if facts.outbox_staged != 0 {
        unclassified("the stopped CPU's cleanup outbox is not empty");
    }
    let transfer_service_cleanup = match facts.owner {
        Ok(_) => true,
        Err(FServiceOwnerError::Missing) => false,
        Err(FServiceOwnerError::Ambiguous) => unclassified("the operation owner is ambiguous"),
    };
    let state = match (facts.suspended, facts.running) {
        (true, false) => {
            if !facts.physically_executes {
                unclassified("a suspended claim this CPU does not execute");
            }
            match facts.control {
                WaitControlHandoff::Pending { replacement } => StopHandoffState::Pending {
                    replacement: replacement || facts.other_running,
                },
                WaitControlHandoff::Idle => StopHandoffState::Idle,
                WaitControlHandoff::Resuming => StopHandoffState::Resuming,
                WaitControlHandoff::Clear => StopHandoffState::SwitchPrepared,
            }
        }
        (false, true) => match (facts.control, transfer_service_cleanup, facts.parked_call) {
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
            _ => unclassified("a Running claim with a suspension handoff in flight"),
        },
        (true, true) => unclassified("both claims are the Stop's"),
        (false, false) => unclassified("neither claim is the Stop's"),
    };
    StopHandoffPlan {
        state,
        suspended_claim: facts.suspended,
        retire_control: facts.control != WaitControlHandoff::Clear,
        transfer_service_cleanup,
    }
}

#[cfg(test)]
#[path = "stop_handoff/tests.rs"]
mod tests;
