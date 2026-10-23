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
