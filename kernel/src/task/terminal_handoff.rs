//! Terminal-handoff decisions the target-only live runtime takes, kept here so
//! host models reach them (design §11.2.12).

/// Where a CPU goes after the terminal transition of the Thread it was running
/// (design §11.2.12 rule 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalHandoffRoute {
    /// Switch to this CPU's next runnable Thread.
    Successor,
    /// This Thread's own transition exited its Process: emit the retirement
    /// record, take the idle-path power-off decision, and tear the root down.
    RetireProcess,
    /// The Process is live, or another Thread's transition exited it: leave
    /// its root for the kernel root and idle, with no record.
    LeaveRoot,
}

/// Routes a terminal handoff. `exits_process` is the captured proof that this
/// Thread's transition took the Process pin
/// (`DeferredCurrentExecutionResources::exits_process`), never a re-read of the
/// Process's state: two CPUs can both see `EXITED` (a sibling's non-final exit,
/// then another Thread's ProcessExit, both before either handoff), and each
/// Process exit has exactly one owner.
pub(crate) const fn terminal_handoff_route(
    has_successor: bool,
    exits_process: bool,
) -> TerminalHandoffRoute {
    if has_successor {
        TerminalHandoffRoute::Successor
    } else if exits_process {
        TerminalHandoffRoute::RetireProcess
    } else {
        TerminalHandoffRoute::LeaveRoot
    }
}

/// What one teardown site does about an exited Process's root (design
/// §11.2.12 rule 3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExitedRootTeardown {
    /// Nothing is owed here: the Process is live, has not quiesced, or its
    /// root is already unbound.
    NotDue,
    /// Owed, but another CPU is still resident on the root. That resident
    /// tears it down when it leaves.
    LeftToResident,
    /// This site makes the last condition true and tears the root down.
    TearDown,
}

/// An exited Process's root is torn down by whichever site first finds it
/// exited, quiescent, still bound and with no CPU resident: the initiator
/// completing a remote termination (which supplies quiescence), or the last
/// resident CPU leaving at its terminal handoff (which supplies zero
/// residency). The check and the teardown run under T, and the teardown
/// unbinds the root the next check needs, so it happens exactly once.
/// `residents` counts CPUs other than the caller's; every caller has left the
/// root, or never entered it.
pub(crate) const fn exited_root_teardown(
    exited: bool,
    quiescent: bool,
    root_bound: bool,
    residents: usize,
) -> ExitedRootTeardown {
    if !exited || !quiescent || !root_bound {
        ExitedRootTeardown::NotDue
    } else if residents != 0 {
        ExitedRootTeardown::LeftToResident
    } else {
        ExitedRootTeardown::TearDown
    }
}

/// What a syscall safe point does with the hold it has just taken (DW2
/// §10.15 review Q3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SafePointEntry {
    /// A Stop is published for this CPU: the call ends at the trampoline.
    Stopped,
    /// This CPU's scheduler-current Thread is terminal but its Stop is not
    /// yet published: a termination's preparation and its publication
    /// straddle T. Release T and wait for the Stop.
    AwaitStopPublication,
    /// Neither: the hold's operation may run.
    Proceed,
}

/// Decides a safe point's hold from the two facts read under T in that same
/// hold. Every hold that runs a syscall's operation decides with both: a
/// hold that checked only for a Stop let an exited Thread whose Stop was not
/// yet published run its operation, and a resumed parked call then found its
/// record already settled by another CPU's drain (Q3).
pub(crate) const fn safe_point_entry(
    stop_published: bool,
    terminal_current: bool,
) -> SafePointEntry {
    if stop_published {
        SafePointEntry::Stopped
    } else if terminal_current {
        SafePointEntry::AwaitStopPublication
    } else {
        SafePointEntry::Proceed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_safe_point_proceeds_only_when_its_thread_is_neither_stopped_nor_terminal() {
        assert_eq!(safe_point_entry(true, true), SafePointEntry::Stopped);
        assert_eq!(safe_point_entry(true, false), SafePointEntry::Stopped);
        assert_eq!(
            safe_point_entry(false, true),
            SafePointEntry::AwaitStopPublication
        );
        assert_eq!(safe_point_entry(false, false), SafePointEntry::Proceed);
    }

    /// Q3's interleaving over the real parked-call table. CPU A's Thread
    /// parked a call and is resuming it; between A's root-synchronization
    /// hold and the hold that takes the record back, an initiator prepares
    /// the Thread's termination (the Thread is now ended, its Stop not yet
    /// published), and a third CPU's drain settles ended records. A's take
    /// hold must not proceed: under the old rule (a Stop check alone) it
    /// did, and found no record.
    #[test]
    fn a_resumed_parked_call_never_takes_a_record_a_drain_settled() {
        use crate::syscall::ParkedCalls;
        let mut objects = crate::object::ObjectRegistry::<2>::new();
        let creation = objects.create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD).unwrap();
        let thread = crate::task::ThreadKey::from_object_id(creation.id());
        let mut parked = ParkedCalls::<u8, 4>::new();
        parked.park(thread, 1);
        // The initiator's preparation: ended, Stop unpublished.
        let ended = true;
        let stop_published = false;
        // Another CPU's drain settles the record.
        assert_eq!(parked.take_ended(|_| ended), Some((thread, 1)));
        // A's hold decides before it takes the record.
        let entry = safe_point_entry(stop_published, ended);
        assert_ne!(entry, SafePointEntry::Proceed);
        // What the old rule would have done:
        let old_rule_proceeds = !stop_published;
        assert!(old_rule_proceeds && parked.take(thread).is_none());
    }

    /// Model (c): the decision table.
    #[test]
    fn exited_root_teardown_is_owed_only_when_all_four_conditions_hold() {
        for exited in [false, true] {
            for quiescent in [false, true] {
                for root_bound in [false, true] {
                    for residents in [0, 1, 2] {
                        let expected = match (exited && quiescent && root_bound, residents) {
                            (false, _) => ExitedRootTeardown::NotDue,
                            (true, 0) => ExitedRootTeardown::TearDown,
                            (true, _) => ExitedRootTeardown::LeftToResident,
                        };
                        assert_eq!(
                            exited_root_teardown(exited, quiescent, root_bound, residents),
                            expected,
                            "exited={exited} quiescent={quiescent} bound={root_bound} residents={residents}"
                        );
                    }
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// The initiator completes a remote termination: the Process exits
        /// and quiesces, and the initiator (on its own root) attempts the
        /// teardown.
        InitiatorCompletes,
        /// Resident CPU `n` (an exited sibling's) leaves the root at its
        /// terminal handoff and attempts the teardown.
        ResidentLeaves(usize),
    }

    /// Model (b): a multi-CPU ProcessTerminate while two exited siblings'
    /// CPUs are still resident on the root. In every interleaving of the
    /// initiator's completion with the two residents leaving, the root is
    /// torn down exactly once, by whichever step makes the last condition
    /// true, and never while a CPU is resident.
    #[test]
    fn every_interleaving_tears_an_exited_root_down_exactly_once() {
        let orders = [
            [
                Step::InitiatorCompletes,
                Step::ResidentLeaves(0),
                Step::ResidentLeaves(1),
            ],
            [
                Step::InitiatorCompletes,
                Step::ResidentLeaves(1),
                Step::ResidentLeaves(0),
            ],
            [
                Step::ResidentLeaves(0),
                Step::InitiatorCompletes,
                Step::ResidentLeaves(1),
            ],
            [
                Step::ResidentLeaves(1),
                Step::InitiatorCompletes,
                Step::ResidentLeaves(0),
            ],
            [
                Step::ResidentLeaves(0),
                Step::ResidentLeaves(1),
                Step::InitiatorCompletes,
            ],
            [
                Step::ResidentLeaves(1),
                Step::ResidentLeaves(0),
                Step::InitiatorCompletes,
            ],
        ];
        for order in orders {
            let mut exited_and_quiescent = false;
            let mut root_bound = true;
            let mut resident = [true, true];
            let mut teardowns = 0;
            for step in order {
                match step {
                    Step::InitiatorCompletes => exited_and_quiescent = true,
                    Step::ResidentLeaves(cpu) => resident[cpu] = false,
                }
                let residents = resident.iter().filter(|resident| **resident).count();
                match exited_root_teardown(
                    exited_and_quiescent,
                    exited_and_quiescent,
                    root_bound,
                    residents,
                ) {
                    ExitedRootTeardown::TearDown => {
                        assert_eq!(residents, 0, "{order:?}: torn down under a resident");
                        root_bound = false;
                        teardowns += 1;
                    }
                    ExitedRootTeardown::LeftToResident => assert_ne!(residents, 0),
                    ExitedRootTeardown::NotDue => {}
                }
            }
            assert_eq!(teardowns, 1, "{order:?}");
            assert!(!root_bound, "{order:?}: the root leaked");
        }
    }
}
