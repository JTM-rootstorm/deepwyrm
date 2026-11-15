//! Whether a remote Stop may be published to a CPU, decided once, at
//! publication, under the runtime authority T (DW2 §10.16 revision 2 item 1).
//!
//! A terminal preparation publishes a Stop to every other CPU that holds a
//! claim of one of its terminal Threads. Some states of the target CPU cannot
//! take a Stop soundly; the stopped side then panics on them (a staged
//! outbox, a prepared switch: `stop_handoff`). This function refuses them
//! instead, before anything changes, and the initiator releases T, polls its
//! own mailbox and tries again: each refused state ends at a hold of the
//! target CPU's own, which that retry waits for.
//!
//! The function is pure over the target CPU's facts. Every fact is read under
//! T and is moved only under T (the claims, the wait control, the CPU's
//! runtime slot) or moves only towards publishable without it (a mailbox is
//! reclaimed to Idle by its initiator guard-free, and leaves Idle only by a
//! publication, which runs under T).

use super::adapters::WaitControlHandoff;

/// One of the target CPU's scheduler claims: its Thread, and whether that
/// Thread is one the termination makes terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClaimFact<T> {
    pub(crate) thread: T,
    pub(crate) terminal: bool,
}

/// The target CPU's facts, all read in the one hold that would publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopTargetFacts<T, P> {
    /// The CPU's suspended claim, whatever its Thread.
    pub(crate) suspended: Option<ClaimFact<T>>,
    /// The CPU's Running claim, whatever its Thread (unfiltered: a prepared
    /// switch's destination is not terminal).
    pub(crate) running: Option<ClaimFact<T>>,
    /// The CPU's wait control.
    pub(crate) control: WaitControlHandoff,
    /// The Thread the CPU last made current at its own safe point.
    pub(crate) last_scheduled: Option<T>,
    /// The CPU has a root switch in flight.
    pub(crate) root_switch_flight: bool,
    /// The Process of the CPU's active root, `None` when it has none.
    pub(crate) active_root: Option<P>,
    /// The CPU's rendezvous mailbox is Idle: no Stop requested, none
    /// acknowledged and not yet reclaimed by its initiator.
    pub(crate) mailbox_idle: bool,
    /// A terminal handoff owns the CPU's continuation.
    pub(crate) deferred_current: bool,
    /// The CPU owns a remote termination between its prepare hold and its
    /// completion hold.
    pub(crate) pending_termination: bool,
}

/// Which of the target CPU's claims the Stop names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopTarget {
    Suspended,
    Running,
}

/// What publication does for one CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopPublication {
    /// No terminal Thread holds a claim there: nothing to publish.
    Nothing,
    /// Publish a Stop naming `claim`. `retire_unentered`: the Running claim
    /// is a terminal Thread's replacement chosen by a block whose
    /// `prepare_suspend` has not run; the preparation retires it before it
    /// publishes.
    Publish {
        claim: StopTarget,
        retire_unentered: bool,
    },
}

/// Why a CPU cannot take a Stop now. Each state ends at a hold of the
/// target CPU's own, after which a retry decides again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopRefusal {
    /// Both claims name one Thread.
    OneThreadTwoClaims,
    /// The CPU has a root switch in flight.
    RootSwitchFlight,
    /// The CPU has not yet made the claim's Thread current at its own safe
    /// point (or made another since).
    NotLastScheduled,
    /// The CPU has no active root.
    NoActiveRoot,
    /// The CPU's active root is not the claim's Process.
    ForeignRoot,
    /// The CPU owns a pending remote termination (DW2 §10.15 audit D1).
    PendingTermination,
    /// A terminal handoff owns the CPU's continuation.
    DeferredCurrent,
    /// The CPU's mailbox is not Idle (§10.16 review DD4).
    MailboxBusy,
    /// The terminal Thread's suspended claim with a Clear control: a switch
    /// prepared away from it, whose destination may already execute (DW2
    /// §10.15 audit R2).
    PreparedSwitch,
    /// The terminal Thread's Running claim while the CPU still holds a
    /// suspended claim, whatever its control: a switch whose destination has
    /// not reached its handoff hold, so the stop's retirement of the Running
    /// claim would fail (`SwitchPending`). It ends at that hold (§10.16
    /// review of revision 2, F3).
    SwitchUnfinished,
}

/// Decides publication for one target CPU from its facts. `owner` gives a
/// terminal Thread's Process; it is called only for the Stop's claim.
pub(crate) fn decide_stop_publication<T: Copy + Eq, P: Copy + Eq>(
    facts: StopTargetFacts<T, P>,
    owner: impl FnOnce(T) -> P,
) -> Result<StopPublication, StopRefusal> {
    let terminal = |claim: Option<ClaimFact<T>>| claim.filter(|claim| claim.terminal);
    let (thread, claim, retire_unentered) =
        match (terminal(facts.suspended), terminal(facts.running)) {
            (None, None) => return Ok(StopPublication::Nothing),
            (Some(suspended), None) => (suspended.thread, StopTarget::Suspended, false),
            (None, Some(running)) => (running.thread, StopTarget::Running, false),
            // A committed block can expose the old suspended carrier and its
            // not-yet-entered replacement at once. The Stop names the
            // physical claim; the preparation retires the replacement. The
            // prepared-switch refusal below keeps this to a block whose
            // `prepare_suspend` has not run.
            (Some(physical), Some(logical)) => {
                if physical.thread == logical.thread {
                    return Err(StopRefusal::OneThreadTwoClaims);
                }
                (physical.thread, StopTarget::Suspended, true)
            }
        };
    if facts.root_switch_flight {
        return Err(StopRefusal::RootSwitchFlight);
    }
    if facts.last_scheduled != Some(thread) {
        return Err(StopRefusal::NotLastScheduled);
    }
    if facts.pending_termination {
        return Err(StopRefusal::PendingTermination);
    }
    if facts.deferred_current {
        return Err(StopRefusal::DeferredCurrent);
    }
    if !facts.mailbox_idle {
        return Err(StopRefusal::MailboxBusy);
    }
    if claim == StopTarget::Suspended && facts.control == WaitControlHandoff::Clear {
        return Err(StopRefusal::PreparedSwitch);
    }
    if claim == StopTarget::Running && facts.suspended.is_some() {
        return Err(StopRefusal::SwitchUnfinished);
    }
    let Some(root) = facts.active_root else {
        return Err(StopRefusal::NoActiveRoot);
    };
    if owner(thread) != root {
        return Err(StopRefusal::ForeignRoot);
    }
    Ok(StopPublication::Publish {
        claim,
        retire_unentered,
    })
}

/// The claim facts of `cpu`, read from the execution domain, the Running
/// claim unfiltered.
pub(crate) fn claim_facts<const EXECUTION: usize>(
    execution: &crate::task::ExecutionDomain<EXECUTION>,
    cpu: crate::cpu::CpuIndex,
    terminal_threads: &[Option<crate::task::ThreadKey>],
) -> (
    Option<ClaimFact<crate::task::ThreadKey>>,
    Option<ClaimFact<crate::task::ThreadKey>>,
) {
    let fact = |claim: crate::task::SchedulerExecutionClaim| ClaimFact {
        thread: claim.thread(),
        terminal: terminal_threads.contains(&Some(claim.thread())),
    };
    (
        execution.suspended_claim_on(cpu).map(fact),
        execution.running_claim_on(cpu).map(fact),
    )
}

#[cfg(test)]
#[path = "stop_publication/tests.rs"]
mod tests;
