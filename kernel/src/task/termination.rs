//! Persistent termination-transaction storage, reset card R5A.
//!
//! # Why this exists
//!
//! Termination currently materialises every effect before releasing any of
//! them. `TaskGroupTerminationEffects<64, 64, 64>` measures **365,064 bytes**,
//! and it is built in one frame, returned by value, moved again by
//! `into_processes()`, and passed by value across the syscall boundary. The
//! stack oracle measures the two terminate frames at **1,476,128 bytes** --
//! 4.04 times the value's own size, so about four simultaneous copies. (The
//! oracle asserts the aggregate, not the per-frame split, so the attribution to
//! individual moves follows from the signatures rather than from measurement.)
//!
//! Component sizes, measured on the host at card R5A:
//!
//! | Type | Bytes |
//! | --- | ---: |
//! | `FinalRelease` | 24 |
//! | `InternalRef` | 24 |
//! | `ThreadExecutionResources` | 16 |
//! | `DrainResult<64>` | 2,056 |
//! | `ExitPins<64>` | 3,624 |
//! | `ProcessExitEffects<64, 64>` | 5,680 |
//! | `TaskGroupTerminationEffects<64, 64, 64>` | 365,064 |
//!
//! R5's gate is that no hot syscall frame scales as
//! `process_capacity x handles_per_process`. A batch that size cannot be made
//! to fit by shrinking it; the shape has to change. This module is the storage
//! the changed shape needs, and R5C and R5D migrate onto it.
//!
//! # What replaces it
//!
//! A transaction holds a *window* of pending work rather than the whole effect
//! set: the subject it is tearing down, how far it has got, and at most
//! `TERMINATION_WORK_WINDOW` items awaiting release. A caller pushes work until
//! the window is full, drains it, releases what it drained, and continues. Peak
//! storage stops depending on `PROCESSES x HANDLES` and becomes
//! `SLOTS x WINDOW`, which is fixed at compile time and lives in static memory
//! rather than on a syscall stack.
//!
//! # Losing a finalizer is impossible here
//!
//! `FinalRelease` and `InternalRef` are obligations: dropping one leaks an
//! object reference. A slot therefore cannot be freed while it still holds
//! any, by either `commit` or `abandon` -- both refuse with
//! [`TerminationError::WindowNotEmpty`]. The only way out of a transaction is
//! to drain what it holds, which hands the obligations back to a caller that
//! can discharge them.
//!
//! R5A adds storage and changes no behaviour, so nothing calls this yet.
//!
//! # What R5B did not use this for
//!
//! R5B converted the Process handle drain to bounded steps without opening a
//! transaction here. What this arena adds over a plain loop is a record that
//! *survives* a boundary: a stage, a cursor, and obligations held across a
//! suspension. The Process handle drain suspends across nothing -- it runs to
//! completion inside one syscall, and its finalizers go straight to the
//! caller's `CleanupQueue` -- so routing it through a slot would have cost a
//! copy and a lock per window and bought no property the loop lacks. R5C's
//! per-Process progress across remote-stop acknowledgement and R5D's finalizer
//! traversal are the migrations this storage exists for.

#![allow(
    dead_code,
    reason = "R5C and R5D migrate the termination paths onto this storage"
)]

use super::{ProcessKey, TaskGroupKey, ThreadExecutionResources};
use crate::object::{FinalRelease, InternalRef};
use crate::sync::SpinMutex;

/// Items a single step may hold before the caller has to drain and release.
///
/// Thirty-two is one window, not a capacity bound on termination: a subject
/// with more effects than this simply takes more steps. It is sized so a step's
/// own working set stays small -- at 56 bytes an item the window is 1,792 bytes
/// -- while still amortising the lock acquisition over a useful batch.
pub(crate) const TERMINATION_WORK_WINDOW: usize = 32;

/// Concurrent termination transactions the arena can hold.
///
/// One per CPU actively stepping, plus one per CPU suspended mid-transaction
/// waiting to resume. A transaction outlives the syscall that opened it -- that
/// is the point of staged execution -- so the bound cannot be "one per CPU".
pub(crate) const TERMINATION_TRANSACTION_SLOTS: usize = crate::cpu::CPU_CAPACITY * 2;

const _: () = assert!(
    TERMINATION_TRANSACTION_SLOTS >= crate::cpu::CPU_CAPACITY * 2,
    "every CPU needs a stepping slot and a suspended slot"
);

/// What a transaction is tearing down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminationSubject {
    Process(ProcessKey),
    Group(TaskGroupKey),
}

/// How far a transaction has got. Advances only forward.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum TerminationStage {
    /// Draining the subject's handle tables into finalizers.
    DrainingHandles = 0,
    /// Releasing terminal thread execution pins.
    ReleasingThreadPins = 1,
    /// Releasing the process's own terminal pin.
    ReleasingProcessPins = 2,
    /// Completing object finalization for what was drained.
    Finalizing = 3,
    /// Every step observed; the transaction may be committed.
    Complete = 4,
}

/// One obligation awaiting release.
#[derive(Debug)]
pub(crate) enum TerminationWork {
    /// A drained handle's finalizer.
    FinalRelease(FinalRelease),
    /// A terminal thread pin, with the execution resources it retires.
    ThreadPin {
        pin: InternalRef,
        resources: Option<ThreadExecutionResources>,
    },
    /// The subject process's own terminal pin.
    ProcessPin(InternalRef),
}

/// How far through the subject's own structure a stage has read.
///
/// Separate from [`TerminationStage`]: the stage says which kind of work is
/// being produced, the cursor says where the next item comes from, so a stage
/// that cannot fit its work in one window resumes rather than restarts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TerminationCursor {
    pub(crate) process: usize,
    pub(crate) handle: usize,
    pub(crate) thread: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminationError {
    /// Every slot is occupied.
    Capacity,
    /// The token names a slot whose generation has moved on.
    Stale,
    /// The window is full; drain it before pushing more.
    WindowFull,
    /// The slot still holds obligations. Drain and release them first.
    WindowNotEmpty,
    /// A stage may not move backwards.
    StageRegression,
    /// The transaction has not reached `Complete`.
    Incomplete,
    /// A slot's generation counter is exhausted; it is retired rather than
    /// reused, because a reused generation cannot be told from a stale token.
    GenerationExhausted,
}

/// Exact identity of one open transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TerminationToken {
    slot: usize,
    generation: u64,
}

impl TerminationToken {
    pub(crate) const fn slot(self) -> usize {
        self.slot
    }
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

struct TerminationSlot {
    generation: u64,
    open: bool,
    subject: Option<TerminationSubject>,
    stage: TerminationStage,
    cursor: TerminationCursor,
    work: [Option<TerminationWork>; TERMINATION_WORK_WINDOW],
    head: usize,
    len: usize,
    retired: u64,
}

impl TerminationSlot {
    const fn new() -> Self {
        Self {
            generation: 0,
            open: false,
            subject: None,
            stage: TerminationStage::DrainingHandles,
            cursor: TerminationCursor {
                process: 0,
                handle: 0,
                thread: 0,
            },
            work: [const { None }; TERMINATION_WORK_WINDOW],
            head: 0,
            len: 0,
            retired: 0,
        }
    }

    fn validate(&self, token: TerminationToken) -> Result<(), TerminationError> {
        if self.open && self.generation == token.generation {
            Ok(())
        } else {
            Err(TerminationError::Stale)
        }
    }
}

pub(crate) struct TerminationArena {
    slots: SpinMutex<[TerminationSlot; TERMINATION_TRANSACTION_SLOTS]>,
}

impl TerminationArena {
    const fn new() -> Self {
        Self {
            slots: SpinMutex::new(
                [const { TerminationSlot::new() }; TERMINATION_TRANSACTION_SLOTS],
            ),
        }
    }

    /// Opens a transaction against `subject`.
    ///
    /// First-fit over the slots, with a fresh nonzero generation so a token
    /// from a previous occupant of the slot cannot validate.
    pub(crate) fn begin(
        &self,
        subject: TerminationSubject,
    ) -> Result<TerminationToken, TerminationError> {
        let mut slots = self.slots.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.open {
                continue;
            }
            let Some(generation) = slot
                .generation
                .checked_add(1)
                .filter(|generation| *generation != 0)
            else {
                // Retire the slot rather than wrap: a reused generation is
                // indistinguishable from a stale token.
                continue;
            };
            slot.generation = generation;
            slot.open = true;
            slot.subject = Some(subject);
            slot.stage = TerminationStage::DrainingHandles;
            slot.cursor = TerminationCursor::default();
            slot.head = 0;
            slot.len = 0;
            slot.retired = 0;
            return Ok(TerminationToken {
                slot: index,
                generation,
            });
        }
        Err(TerminationError::Capacity)
    }

    pub(crate) fn subject(
        &self,
        token: TerminationToken,
    ) -> Result<TerminationSubject, TerminationError> {
        let slots = self.slots.lock();
        let slot = slots.get(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        slot.subject.ok_or(TerminationError::Stale)
    }

    pub(crate) fn stage(
        &self,
        token: TerminationToken,
    ) -> Result<TerminationStage, TerminationError> {
        let slots = self.slots.lock();
        let slot = slots.get(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        Ok(slot.stage)
    }

    pub(crate) fn cursor(
        &self,
        token: TerminationToken,
    ) -> Result<TerminationCursor, TerminationError> {
        let slots = self.slots.lock();
        let slot = slots.get(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        Ok(slot.cursor)
    }

    pub(crate) fn set_cursor(
        &self,
        token: TerminationToken,
        cursor: TerminationCursor,
    ) -> Result<(), TerminationError> {
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        slot.cursor = cursor;
        Ok(())
    }

    /// Moves the transaction to a later stage. Never to an earlier one.
    pub(crate) fn advance(
        &self,
        token: TerminationToken,
        stage: TerminationStage,
    ) -> Result<(), TerminationError> {
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        if stage < slot.stage {
            return Err(TerminationError::StageRegression);
        }
        slot.stage = stage;
        Ok(())
    }

    /// Queues one obligation, refusing rather than overwriting when full.
    pub(crate) fn push(
        &self,
        token: TerminationToken,
        work: TerminationWork,
    ) -> Result<(), TerminationError> {
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        if slot.len == TERMINATION_WORK_WINDOW {
            return Err(TerminationError::WindowFull);
        }
        let index = (slot.head + slot.len) % TERMINATION_WORK_WINDOW;
        slot.work[index] = Some(work);
        slot.len += 1;
        Ok(())
    }

    /// Hands back up to `out.len()` queued obligations in push order.
    ///
    /// The caller owns what it receives and must discharge it; nothing is
    /// dropped inside the arena.
    pub(crate) fn drain_into(
        &self,
        token: TerminationToken,
        out: &mut [Option<TerminationWork>],
    ) -> Result<usize, TerminationError> {
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        let mut taken = 0;
        while taken < out.len() && slot.len != 0 {
            out[taken] = slot.work[slot.head].take();
            slot.head = (slot.head + 1) % TERMINATION_WORK_WINDOW;
            slot.len -= 1;
            slot.retired = slot
                .retired
                .checked_add(1)
                .ok_or(TerminationError::GenerationExhausted)?;
            taken += 1;
        }
        Ok(taken)
    }

    pub(crate) fn queued(&self, token: TerminationToken) -> Result<usize, TerminationError> {
        let slots = self.slots.lock();
        let slot = slots.get(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        Ok(slot.len)
    }

    /// Closes a completed transaction, returning how many obligations it
    /// handed back over its life.
    pub(crate) fn commit(&self, token: TerminationToken) -> Result<u64, TerminationError> {
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        if slot.stage != TerminationStage::Complete {
            return Err(TerminationError::Incomplete);
        }
        if slot.len != 0 {
            return Err(TerminationError::WindowNotEmpty);
        }
        let retired = slot.retired;
        slot.open = false;
        slot.subject = None;
        Ok(retired)
    }

    /// Closes an incomplete transaction. Refuses while it still holds
    /// obligations, for the same reason `commit` does.
    pub(crate) fn abandon(&self, token: TerminationToken) -> Result<u64, TerminationError> {
        let mut slots = self.slots.lock();
        let slot = slots.get_mut(token.slot).ok_or(TerminationError::Stale)?;
        slot.validate(token)?;
        if slot.len != 0 {
            return Err(TerminationError::WindowNotEmpty);
        }
        let retired = slot.retired;
        slot.open = false;
        slot.subject = None;
        Ok(retired)
    }
}

pub(crate) static TERMINATION_ARENA: TerminationArena = TerminationArena::new();

#[cfg(test)]
#[path = "termination/tests.rs"]
mod tests;
