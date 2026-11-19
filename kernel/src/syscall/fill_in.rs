//! A syscall's fill-in and a commit step, as decisions over plain values
//! (DW2 M6 §8.2, §8.6; DW2 §13.16 part e4).
//!
//! The live runtime supplies each decision's values through a small trait
//! under its hold of T (and P, for a commit step); the decision itself is
//! host-built, so the order of what a hold does is tested here, over
//! models, as the fault gate's is in `native`.
//!
//! - [`fill_in_range`] is one hold of a fill-in: it serves, as a user touch,
//!   every on-demand page of one step of a buffer.
//! - [`fill_in_buffers`] runs a request's user buffers through holds, one
//!   step safe point each, and says how the call ended.
//! - [`commit_step`] is one hold of `memory_object_commit` (and of
//!   `dma_map`'s fill-in): it admits the step's cost, or the longest start
//!   of the step the quota admits, and commits those pages.

use super::native::{UserBuffer, UserPageFaultOutcome};
use deepwyrm_abi::{DW_STATUS_BAD_STATE, DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES, DwStatus};

/// What one hold of a fill-in asks of the runtime (T held).
pub(crate) trait FillInHold {
    /// On the bootstrap CPU, drains pending timer expiries; nothing
    /// elsewhere.
    fn service_timer_expiries(&mut self);
    /// Whether the page at `address` lies in an on-demand mapping of the
    /// current Process.
    fn on_demand(&mut self, address: u64) -> bool;
    /// Serves `address` as a user touch (a write when `write`), opening no
    /// fault window. `owed` is asked only for `Exhausted`: whether owed work
    /// could admit the refusal.
    fn serve(&mut self, address: u64, write: bool) -> FillServe;
    /// Takes the hold's owed step.
    fn take_owed_step(&mut self);
}

/// What a fill-in's serve of one page did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FillServe {
    pub(crate) outcome: UserPageFaultOutcome,
    /// For `Exhausted` only: whether owed work could admit the refusal.
    pub(crate) owed: bool,
}

/// One hold of a fill-in (DW2 M6 §8.6): serves, as a user touch of the
/// access the syscall will make (a write when `write`), every on-demand
/// page under `[*next, end)` up to one step of `step_bytes`. Pages outside
/// on-demand mappings are left to the copy, which fails them as before.
///
/// `*next` moves past each page before it is looked at. A refusal
/// (`Exhausted`) that is not owed ends the call with its status, `*next`
/// past the refused page. One that is owed (DW2 §13.12 part b) sets `*next`
/// back to the refused page, takes the hold's owed step and returns
/// `Ok(())`: the page is served again after the next safe point.
pub(crate) fn fill_in_range(
    hold: &mut impl FillInHold,
    next: &mut u64,
    end: u64,
    write: bool,
    step_bytes: u64,
    page_size: u64,
) -> Result<(), DwStatus> {
    let step_end = end.min(next.saturating_add(step_bytes));
    while *next < step_end {
        let page = *next;
        *next = page.saturating_add(page_size);
        if !hold.on_demand(page) {
            continue;
        }
        let served = hold.serve(page, write);
        if let UserPageFaultOutcome::Exhausted(status) = served.outcome {
            if !served.owed {
                return Err(status);
            }
            *next = page;
            hold.take_owed_step();
            return Ok(());
        }
    }
    Ok(())
}

/// What one step safe point of a fill-in runs under its hold.
pub(crate) trait FillInStep {
    /// What the hold returns.
    type Output;
    /// Runs under `hold`, told whether the quantum ended (`yielding`).
    fn run(self, hold: &mut impl FillInHold, yielding: bool) -> Self::Output;
}

/// A fill-in's step safe points.
pub(crate) trait FillInRuntime {
    /// One step safe point (the live one is
    /// `at_step_safe_point(may_yield, StepCall::FillIn, …)`): `Err(())` on a
    /// Stop; else `step` runs under the hold and is told whether the
    /// quantum ended.
    fn step<S: FillInStep>(&mut self, may_yield: bool, step: S) -> Result<S::Output, ()>;
}

/// How a fill-in's buffers ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FillInEnd {
    /// A Stop ended the call.
    Stopped,
    /// The quantum ended: park with buffer `index` and page `next`.
    Parked { index: usize, next: u64 },
    /// A serve was refused and the refusal is not owed.
    Failed(DwStatus),
    /// Every buffer is filled in; `stepped` says whether any step ran in
    /// this call or resume.
    Done { stepped: bool },
}

/// A request's user buffers filled in from buffer `first` (from page
/// `resume_at` of it, when given), one [`fill_in_range`] per step safe
/// point (DW2 M6 §8.6, §10.8). A buffer that is absent, empty or whose
/// rounded end overflows is skipped: it is the copy's to refuse.
///
/// Each hold drains the bootstrap CPU's timer expiries first, then, if the
/// quantum ended, serves nothing and the call parks; else it serves one
/// step. The first safe point of a call or resume may not yield: a resumed
/// call always makes progress before it yields again.
pub(crate) fn fill_in_buffers<R: FillInRuntime>(
    runtime: &mut R,
    buffers: [Option<UserBuffer>; 3],
    first: usize,
    resume_at: Option<u64>,
    step_bytes: u64,
    page_size: u64,
) -> FillInEnd {
    let mut stepped = false;
    for (index, buffer) in buffers.into_iter().enumerate().skip(first) {
        let Some(buffer) = buffer else {
            continue;
        };
        if buffer.byte_len == 0 {
            continue;
        }
        // A buffer the copy cannot use is the copy's to refuse.
        let Some(end) = buffer
            .address
            .checked_add(buffer.byte_len)
            .and_then(|end| end.checked_add(page_size - 1))
            .map(|end| end & !(page_size - 1))
        else {
            continue;
        };
        let mut next = resume_at
            .filter(|_| index == first)
            .unwrap_or(buffer.address & !(page_size - 1));
        while next < end {
            let step = BufferStep {
                next: &mut next,
                end,
                write: buffer.write,
                step_bytes,
                page_size,
            };
            match runtime.step(stepped, step) {
                Err(()) => return FillInEnd::Stopped,
                Ok(None) => return FillInEnd::Parked { index, next },
                Ok(Some(Err(status))) => return FillInEnd::Failed(status),
                Ok(Some(Ok(()))) => stepped = true,
            }
        }
    }
    FillInEnd::Done { stepped }
}

/// One hold of a buffer's fill-in: the bootstrap CPU's timer expiries
/// first, then, unless the quantum ended (`None`), one step of the range.
struct BufferStep<'n> {
    next: &'n mut u64,
    end: u64,
    write: bool,
    step_bytes: u64,
    page_size: u64,
}

impl FillInStep for BufferStep<'_> {
    type Output = Option<Result<(), DwStatus>>;

    fn run(self, hold: &mut impl FillInHold, yielding: bool) -> Self::Output {
        hold.service_timer_expiries();
        if yielding {
            return None;
        }
        Some(fill_in_range(
            hold,
            self.next,
            self.end,
            self.write,
            self.step_bytes,
            self.page_size,
        ))
    }
}

/// How one commit step's hold ended (DW2 M6 §8.2, §13.12 part b).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitStep {
    /// The whole range is committed.
    Done,
    /// The step committed its pages; more remain.
    More,
    /// The step met a refusal owed work could admit and took the hold's
    /// owed step instead; it is taken again at the next safe point.
    Owed,
}

/// Why a page of a commit step could not be committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitRefusal {
    /// No frame could be taken (`NO_MEMORY`).
    NoMemory,
    /// Anything else (`BAD_STATE`).
    BadState,
}

/// Where a commit step is, for the step report's stamps (DW2 §13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitPoint {
    /// The admission began.
    AdmitBegan,
    /// The admission ended; the pages are taken next.
    AdmitEnded,
    /// The pages admitted are taken (or one failed).
    Taken,
}

/// What one commit step asks under T and P.
pub(crate) trait CommitStepHold {
    /// Frames committing the step's first `pages` pages would take.
    fn cost(&mut self, pages: u64) -> Result<u64, DwStatus>;
    /// Admits `cost` frames against the object's creator (not called for a
    /// cost of zero).
    fn admit(&mut self, cost: u64) -> Result<(), DwStatus>;
    /// Closes every fault window; how many it closed.
    fn close_all_windows(&mut self) -> usize;
    /// Whether a quota refusal of `cost` frames is owed (a dead job's
    /// teardown, or finalizing weight).
    fn quota_refusal_owed(&mut self, cost: u64) -> bool;
    /// Commits the step's page number `index` (0 is the step's first); the
    /// frames it took.
    fn commit(&mut self, index: u64) -> Result<u64, CommitRefusal>;
    /// Adds `frames` to the object's weight.
    fn record(&mut self, frames: u64);
    /// Whether a frame refusal (`NO_MEMORY`) is owed: any finalization or
    /// teardown is owed.
    fn memory_refusal_owed(&mut self) -> bool;
    /// The step reached `point` (the step report's stamps); nothing by
    /// default.
    fn stamp(&mut self, _point: CommitPoint) {}
}

/// One commit step of `count` pages from `*next` (DW2 M6 §8.4), the range
/// ending at `end`. The step's cost is admitted all at once or, past the
/// quota, the longest start of it that fits, so a commit still fills the
/// quota exactly: at most ten admissions for a 2 MiB step, not one a page
/// (§8.11 R1). A quota refusal first closes every fault window and admits
/// once more, so credit is never the reason a commit is refused (DW2
/// §13.16 part e3). The frames taken are recorded in the object's weight,
/// and stay so even after a failure.
///
/// A refusal owed work could admit is not returned (DW2 §13.12 part b):
/// when the whole step's admission is refused and the refusal is owed,
/// nothing is committed and `*next` stays; when a frame cannot be taken
/// (`NO_MEMORY`) while the refusal is owed, the pages committed before it
/// stay committed and recorded and `*next` is the page that failed. Either
/// is [`CommitStep::Owed`], and the caller takes the hold's owed step.
pub(crate) fn commit_step(
    hold: &mut impl CommitStepHold,
    next: &mut u64,
    end: u64,
    count: u64,
    page_size: u64,
) -> Result<CommitStep, DwStatus> {
    hold.stamp(CommitPoint::AdmitBegan);
    // The whole step first.
    let whole = {
        let cost = hold.cost(count)?;
        let admitted = if cost == 0 { Ok(()) } else { hold.admit(cost) };
        match admitted {
            Err(DW_STATUS_NO_RESOURCES) if hold.close_all_windows() != 0 => {
                hold.admit(cost).map(|()| cost)
            }
            admitted => admitted.map(|()| cost),
        }
    };
    let (admitted, cost, mut result) = match whole {
        Ok(cost) => (count, cost, Ok(())),
        Err(DW_STATUS_NO_RESOURCES) => {
            // Owed: owed work could admit the whole step, so nothing is
            // committed and the step is taken again after the owed step.
            let whole_cost = hold.cost(count)?;
            if hold.quota_refusal_owed(whole_cost) {
                return Ok(CommitStep::Owed);
            }
            // The longest start of the step the quota admits.
            let (mut fits, mut fits_cost, mut refused) = (0, 0, count);
            while refused - fits > 1 {
                let middle = fits + (refused - fits) / 2;
                let admitted = hold.cost(middle).and_then(|cost| {
                    if cost != 0 {
                        hold.admit(cost)?;
                    }
                    Ok(cost)
                });
                match admitted {
                    Ok(cost) => (fits, fits_cost) = (middle, cost),
                    Err(DW_STATUS_NO_RESOURCES) => refused = middle,
                    Err(status) => return Err(status),
                }
            }
            (fits, fits_cost, Err(DW_STATUS_NO_RESOURCES))
        }
        Err(status) => return Err(status),
    };
    hold.stamp(CommitPoint::AdmitEnded);
    let mut frames = 0;
    for index in 0..admitted {
        match hold.commit(index) {
            Ok(taken) => frames += taken,
            Err(refusal) => {
                result = Err(match refusal {
                    CommitRefusal::NoMemory => DW_STATUS_NO_MEMORY,
                    CommitRefusal::BadState => DW_STATUS_BAD_STATE,
                });
                break;
            }
        }
        *next += page_size;
    }
    hold.stamp(CommitPoint::Taken);
    // What was taken stays committed and charged, even after a failure.
    debug_assert!(frames <= cost, "a commit step took more than it admitted");
    if frames != 0 {
        hold.record(frames);
    }
    match result {
        Ok(()) if *next >= end => Ok(CommitStep::Done),
        Ok(()) => Ok(CommitStep::More),
        Err(DW_STATUS_NO_MEMORY) if hold.memory_refusal_owed() => Ok(CommitStep::Owed),
        Err(status) => Err(status),
    }
}

#[cfg(test)]
#[path = "fill_in/tests.rs"]
mod tests;
