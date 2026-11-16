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

/// How many steps of one kind of owed work a hold may take: one (DW2
/// §12.11 part 2 item 11). The first [`Self::take`] in a hold allows its
/// step and every later one refuses; the hold's end reads the count with
/// [`Self::end`], which starts the next hold afresh.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct HoldStepBudget {
    taken: bool,
}

impl HoldStepBudget {
    pub(crate) const fn new() -> Self {
        Self { taken: false }
    }

    /// Whether the hold may take a step now: `true` only the first time.
    pub(crate) const fn take(&mut self) -> bool {
        let allowed = !self.taken;
        self.taken = true;
        allowed
    }

    /// At the hold's end: how many steps it took through [`Self::take`]
    /// (0 or 1), and a fresh budget for the next hold.
    pub(crate) const fn end(&mut self) -> u32 {
        let steps = self.taken as u32;
        self.taken = false;
        steps
    }
}

/// What a hold did to one queue of owed work (DW2 §10.19 revision 3): it
/// queued into it while it was empty, and the queue was still non-empty
/// when the hold ended.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OwedQueueChange {
    pub(crate) queued_from_empty: bool,
    pub(crate) owed_at_end: bool,
}

/// What a hold did that can give an idle BSP owed work it can step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OwedHoldFacts {
    pub(crate) finalization: OwedQueueChange,
    pub(crate) teardown: OwedQueueChange,
    /// The bootstrap's root retired in the hold, with teardown owed at its
    /// end: from then on the BSP's idle visit can step it.
    pub(crate) bootstrap_retired_with_teardown_owed: bool,
}

/// Why a hold wakes the BSP for owed work, if it does.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OwedWake {
    /// A queue went from empty to non-empty and stayed so.
    pub(crate) queue: bool,
    /// The bootstrap's root retired with teardown owed.
    pub(crate) retirement: bool,
}

impl OwedWake {
    pub(crate) const fn any(self) -> bool {
        self.queue || self.retirement
    }
}

/// Whether a hold on `cpu` wakes the BSP as it ends (DW2 §10.19 revision
/// 3): whenever it turned the idle BSP's "is there owed work I can step"
/// from false to true. A queue that was already non-empty has woken the
/// BSP or will be seen at its own check; one emptied again within the hold
/// needs nobody; the BSP's own holds need no wake, since it checks before
/// it idles.
pub(crate) const fn owed_work_wake(cpu: usize, bsp: usize, facts: OwedHoldFacts) -> OwedWake {
    if cpu == bsp {
        return OwedWake {
            queue: false,
            retirement: false,
        };
    }
    let finalization = facts.finalization.queued_from_empty && facts.finalization.owed_at_end;
    let teardown = facts.teardown.queued_from_empty && facts.teardown.owed_at_end;
    OwedWake {
        queue: finalization || teardown,
        retirement: facts.bootstrap_retired_with_teardown_owed,
    }
}

/// Something a hold did that may give an idle BSP owed work to step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BspOwedEvent {
    /// Queued an owed finalization while none was owed.
    FinalizationFromEmpty,
    /// Queued an owed teardown while none was owed.
    TeardownFromEmpty,
    /// Retired the bootstrap's root.
    BootstrapRetired,
}

/// One CPU's owed-work wake state (DW2 §10.19 revision 3), as one byte the
/// carrier keeps per CPU: the events its current hold did, and a wake
/// decided at a hold's end and not yet sent. A hold marks events; its end
/// settles them into a wake or none; after the release the wake is taken
/// and sent, and put back if it could not be.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OwedHoldState(u8);

impl OwedHoldState {
    const FINALIZATION_FROM_EMPTY: u8 = 1 << 0;
    const TEARDOWN_FROM_EMPTY: u8 = 1 << 1;
    const BOOTSTRAP_RETIRED: u8 = 1 << 2;
    const EVENTS: u8 =
        Self::FINALIZATION_FROM_EMPTY | Self::TEARDOWN_FROM_EMPTY | Self::BOOTSTRAP_RETIRED;
    const WAKE_QUEUE: u8 = 1 << 3;
    const WAKE_RETIREMENT: u8 = 1 << 4;
    const WAKES: u8 = Self::WAKE_QUEUE | Self::WAKE_RETIREMENT;

    pub(crate) const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub(crate) const fn bits(self) -> u8 {
        self.0
    }

    const fn wake_bits(wake: OwedWake) -> u8 {
        (if wake.queue { Self::WAKE_QUEUE } else { 0 })
            | if wake.retirement {
                Self::WAKE_RETIREMENT
            } else {
                0
            }
    }

    /// The hold did `event`.
    pub(crate) const fn marked(self, event: BspOwedEvent) -> Self {
        let bit = match event {
            BspOwedEvent::FinalizationFromEmpty => Self::FINALIZATION_FROM_EMPTY,
            BspOwedEvent::TeardownFromEmpty => Self::TEARDOWN_FROM_EMPTY,
            BspOwedEvent::BootstrapRetired => Self::BOOTSTRAP_RETIRED,
        };
        Self(self.0 | bit)
    }

    /// At the hold's end on `cpu`, with what is owed then: its events become
    /// the wake to deliver ([`owed_work_wake`]), or none, and are cleared. A
    /// wake still pending from before is kept. With no event, unchanged.
    pub(crate) const fn settled(
        self,
        cpu: usize,
        bsp: usize,
        finalization_owed: bool,
        teardown_owed: bool,
    ) -> Self {
        let events = self.0 & Self::EVENTS;
        if events == 0 {
            return self;
        }
        let facts = OwedHoldFacts {
            finalization: OwedQueueChange {
                queued_from_empty: events & Self::FINALIZATION_FROM_EMPTY != 0,
                owed_at_end: finalization_owed,
            },
            teardown: OwedQueueChange {
                queued_from_empty: events & Self::TEARDOWN_FROM_EMPTY != 0,
                owed_at_end: teardown_owed,
            },
            bootstrap_retired_with_teardown_owed: events & Self::BOOTSTRAP_RETIRED != 0
                && teardown_owed,
        };
        let wake = owed_work_wake(cpu, bsp, facts);
        Self((self.0 & Self::WAKES) | Self::wake_bits(wake))
    }

    /// After the release: the wake to deliver, if any, and the state without
    /// it.
    pub(crate) const fn take_wake(self) -> (Self, Option<OwedWake>) {
        let wakes = self.0 & Self::WAKES;
        if wakes == 0 {
            return (self, None);
        }
        (
            Self(self.0 & !Self::WAKES),
            Some(OwedWake {
                queue: wakes & Self::WAKE_QUEUE != 0,
                retirement: wakes & Self::WAKE_RETIREMENT != 0,
            }),
        )
    }

    /// `wake` could not be sent: it is pending again, so this CPU's next
    /// hold end tries it again.
    pub(crate) const fn with_unsent(self, wake: OwedWake) -> Self {
        Self(self.0 | Self::wake_bits(wake))
    }
}

#[cfg(test)]
#[path = "hold_end/tests.rs"]
mod tests;
