//! How a hold of the runtime authority T ends (DW2 §10.15 revision 2, items
//! 1–3).
//!
//! A remote Stop's commit asserts the shared cleanup queue empty, and the
//! stopped CPU releases T between its precommit and its commit. So no hold
//! may end with the shared queue (or the F-service carrier's queue, which a
//! precommit absorbs) holding anything. A hold that pushed releases either
//! drains them before it ends, popping the cleanup queue only (no teardown,
//! release or finalize step), or, when they must not finalize yet, stages
//! them in its CPU's outbox, which only that CPU's terminal handoff or
//! termination completion moves back. The runtime guard checks the rule as
//! it releases T, so a path that skips it fails at the hold that caused it.
//!
//! The target-only carrier applies these; the decisions and the queue moves
//! are here, where the host builds them.

use super::adapters::CleanupQueue;
use super::native::SyscallControl;
use crate::object::FinalRelease;

/// What a hold does with its pushes as it ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HoldEnd {
    /// It returns to its caller: its CPU's outbox moves back into the shared
    /// queue first (a termination's completion), then the caller drains
    /// fully, as every syscall return does.
    Return,
    /// It drains the shared queue, popping only (revision 2 item 1).
    Drain,
    /// Its releases must not finalize yet: they move into its CPU's outbox
    /// (revision 2 item 2).
    Stage,
}

/// The end a syscall result's last hold takes. `TerminateCurrent` releases
/// may finalize what the CPU still runs on, and a remote-termination
/// initiator's (`CompleteRemoteStop`) must finalize only after the stops it
/// published are acknowledged: both stage. Every other control that does
/// not return drains.
pub(crate) const fn hold_end_for(control: SyscallControl) -> HoldEnd {
    match control {
        SyscallControl::ReturnToCaller => HoldEnd::Return,
        SyscallControl::TerminateCurrent | SyscallControl::CompleteRemoteStop => HoldEnd::Stage,
        SyscallControl::ServiceRendezvous
        | SyscallControl::SuspendCurrent
        | SyscallControl::YieldCurrent => HoldEnd::Drain,
    }
}

/// The rule every hold ends under, checked by the runtime guard as it
/// releases T: both queues empty. Panics naming the queue that is not.
#[track_caller]
pub(crate) fn assert_hold_ended(shared_empty: bool, services_empty: bool) {
    if !(shared_empty && services_empty) {
        panic!(
            "a runtime hold ended with cleanup undrained (shared queue empty: {shared_empty}, \
             F-service queue empty: {services_empty})"
        );
    }
}

/// Every CPU's outbox, in one store: releases staged by a hold that must not
/// finalize them yet, in the order staged, each tagged with its CPU. At most
/// one release exists per object, so `CAPACITY` (the registry's) bounds all
/// of them together.
pub(crate) struct CleanupOutboxes<const CAPACITY: usize, const CPUS: usize> {
    releases: [Option<FinalRelease>; CAPACITY],
    owners: [u8; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize, const CPUS: usize> CleanupOutboxes<CAPACITY, CPUS> {
    const CPUS_FIT: () = assert!(CPUS <= u8::MAX as usize);

    pub(crate) fn new() -> Self {
        let () = Self::CPUS_FIT;
        Self {
            releases: core::array::from_fn(|_| None),
            owners: [0; CAPACITY],
            len: 0,
        }
    }

    /// Moves everything in `from` into `cpu`'s outbox, in order.
    pub(crate) fn stage(&mut self, cpu: usize, from: &mut CleanupQueue<CAPACITY>) {
        assert!(cpu < CPUS, "a cleanup outbox CPU is out of range");
        while let Some(release) = from.pop() {
            assert!(
                self.len < CAPACITY,
                "cleanup outboxes exceeded ObjectRegistry capacity"
            );
            self.releases[self.len] = Some(release);
            self.owners[self.len] = cpu as u8;
            self.len += 1;
        }
    }

    /// How many releases `cpu`'s outbox holds.
    pub(crate) fn staged(&self, cpu: usize) -> usize {
        self.owners[..self.len]
            .iter()
            .filter(|owner| usize::from(**owner) == cpu)
            .count()
    }

    /// Moves `cpu`'s outbox into `into`, in the order staged, leaving every
    /// other CPU's where it is.
    pub(crate) fn release(&mut self, cpu: usize, into: &mut CleanupQueue<CAPACITY>) {
        let mut kept = 0;
        for index in 0..self.len {
            let release = self.releases[index].take();
            if usize::from(self.owners[index]) == cpu {
                into.push(release.expect("a staged release went missing"));
            } else {
                self.releases[kept] = release;
                self.owners[kept] = self.owners[index];
                kept += 1;
            }
        }
        self.len = kept;
    }
}

/// Moves a hold's queues for its end on `cpu`, before the caller drains:
/// `Stage` moves the shared queue into the CPU's outbox, `Return` moves the
/// outbox back into the shared queue, `Drain` moves nothing. The caller has
/// absorbed the F-service queue into `shared` first. Returns whether the
/// caller must drain `shared` before it releases T.
pub(crate) fn settle_hold_queues<const CAPACITY: usize, const CPUS: usize>(
    end: HoldEnd,
    cpu: usize,
    shared: &mut CleanupQueue<CAPACITY>,
    outboxes: &mut CleanupOutboxes<CAPACITY, CPUS>,
) -> bool {
    match end {
        HoldEnd::Stage => {
            outboxes.stage(cpu, shared);
            false
        }
        HoldEnd::Return => {
            outboxes.release(cpu, shared);
            true
        }
        HoldEnd::Drain => true,
    }
}

#[cfg(test)]
#[path = "hold_end/tests.rs"]
mod tests;
