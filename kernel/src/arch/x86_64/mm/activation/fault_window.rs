//! The fast serve's decision (DW2 §13.16 part e3): a first touch inside
//! this CPU's fault window, served with the paging lock P alone.
//!
//! [`serve_fast`] makes the nine steps of the design in order over
//! [`FastServePaging`], which the live runtime implements over its
//! guard-free session and the host tests implement over a model. It reads
//! nothing of the runtime authority's value: the window carries what was
//! read under T when it was opened, and the rest is asked under P (the
//! session, the leaf, the commit) or of the scheduler and this CPU's own
//! state.
//!
//! A decline before step 6 changes nothing; steps 5 and 6 are one commit
//! within the credit (DW2 §13.18 part f1), which declines with nothing
//! taken. From step 6 the frames a commit took are spent from the window's
//! credit whatever follows, so the object's weight stays the frames
//! committed plus the credit; a decline at step 7 or 8 is still correct,
//! because the serve under T finds the page committed (cost zero) and does
//! what it does today.

use crate::memory::address_region::{FaultWindow, Mapping};
use crate::task::{ProcessKey, ThreadKey};

/// The page-fault error code's write bit.
const WRITE: u64 = 1 << 1;
/// The page-fault error code's instruction-fetch bit.
const FETCH: u64 = 1 << 4;
const PAGE_MASK: u64 = !(crate::memory::physical::BASE_PAGE_SIZE - 1);

/// Why the fast serve left a fault to the serve under T, by step (DW2
/// §13.16's `fault-declines` line).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastDecline {
    /// Steps 1 and 2: no window, another Thread or root, no session, a
    /// Stop, a reschedule, the Thread not Running here, or (on the BSP) a
    /// timer expiry pending.
    Identity,
    /// Step 3: outside the window's mapping, or an access its protection
    /// refuses.
    Mapping,
    /// Step 4: a page table on the path is missing, or the walk failed.
    Tables,
    /// Step 5: the commit would take more than the credit, or its cost
    /// could not be asked.
    Credit,
    /// Step 6: the commit was refused (a frame could not be taken).
    Memory,
    /// Step 7: the leaf could not be written.
    Leaf,
    /// Step 8: the return is not authorised by present leaves alone.
    Return,
    /// Steps 5 and 6 of a shared serve (DW2 §15.2): the page has no frame,
    /// and a shared hold takes none. Nothing was written; the gate runs
    /// the exclusive fast serve in the same fault.
    NotCommitted,
}

/// What the fast serve did when it served (step 9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastServed {
    /// A frame was committed or the leaf written.
    Served,
    /// The leaf was already this page's, and nothing was committed.
    AlreadyPresent,
}

/// Where the fast serve is, for the step report's parts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastStamp {
    /// Steps 1 to 3 done, before the leaf's walk: the end of `check`.
    Checked,
    /// Steps 5 and 6 done (a committed page takes nothing): the end of
    /// `commit`.
    Committed,
    /// Step 7 done: the end of `tables`.
    Written,
}

/// What a commit within the credit did (steps 5 and 6, DW2 §13.18 part
/// f1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastCommit {
    /// The commit would take more than the limit; nothing was taken.
    Over,
    /// The cost could not be asked (not an on-demand page of this backing).
    Unaskable,
    /// A frame could not be taken.
    Refused,
    /// The page is committed; the frames this commit took (zero if it was).
    Done(u64),
    /// The page has no frame and none may be taken here: a shared serve's
    /// answer for a page not yet committed (DW2 §15.2).
    NotCommitted,
}

/// A shared serve's answer for a page with no frame, by the window's
/// credit (`limit`, DW2 §15.6): with none left the touch is past what a
/// commit ahead covered, and `Over` sends it straight to the serve under T
/// as the `Credit` decline, which commits the next range; with credit,
/// `NotCommitted`, and the exclusive serve commits it from that credit in
/// the same fault.
#[inline(always)]
pub(crate) const fn shared_uncommitted(limit: u64) -> FastCommit {
    if limit == 0 {
        FastCommit::Over
    } else {
        FastCommit::NotCommitted
    }
}

/// The publisher's side of steps 4 to 7, all under one borrow of the
/// session, so the leaf's place found in step 4 is written in step 7 by
/// the same publisher.
pub(crate) trait FastLeaf {
    /// Where the leaf is.
    type Place;
    /// Step 4: the leaf's place, or `None` when a table is missing or the
    /// walk failed.
    fn find(&mut self, mapping: &Mapping, address: u64) -> Option<Self::Place>;
    /// Steps 5 and 6: commits the place's page if it takes at most `limit`
    /// frames (DW2 §13.18 part f1).
    fn commit_within(&mut self, place: &mut Self::Place, limit: u64) -> FastCommit;
    /// Step 7: writes the leaf at `place`; `Some(true)` when it wrote,
    /// `Some(false)` when it was already this page's leaf, `None` when it
    /// could not.
    fn write(&mut self, place: Self::Place) -> Option<bool>;
    /// The serve reached `stamp` (the commit's and the leaf's ends).
    fn stamp(&mut self, _stamp: FastStamp) {}
}

/// Everything the fast serve asks, in P's hold, of this CPU and its paging.
pub(crate) trait FastServePaging<R: Copy> {
    /// The publisher of steps 4 to 7, borrowing the session.
    type Leaf<'a>: FastLeaf
    where
        Self: 'a;

    /// This CPU's window, copied.
    fn window(&self) -> Option<FaultWindow<R>>;
    /// The Thread physically executing on this CPU and its root-switch
    /// epoch, both owner-local.
    fn executing(&self) -> (Option<ThreadKey>, u64);
    /// Builds the session for `root` and `process`, revalidated against
    /// this CPU, CR3, the binding and residency; `false` on any mismatch.
    fn open_session(&mut self, root: R, process: ProcessKey) -> bool;
    /// Step 2: the scheduler runs `thread` here and it is Running, no
    /// reschedule is requested for this CPU, no Stop is requested, and on
    /// the BSP no timer expiry is pending.
    fn scheduler_allows(&mut self, thread: ThreadKey) -> bool;
    /// The publisher for `mapping`'s address space and region, or `None`
    /// if the session refuses it.
    fn leaf(&mut self, mapping: &Mapping) -> Option<Self::Leaf<'_>>;
    /// The window's credit falls by `frames`, which a commit took.
    fn spend(&mut self, frames: u64);
    /// Step 8: the frame's return, validated through present leaves alone.
    fn validate_return(&mut self) -> bool;
    /// The serve reached `stamp` (the end of the checks).
    fn stamp(&mut self, _stamp: FastStamp) {}
}

/// The fast serve of a CPL3 page fault at `cr2` with error code `error`
/// (DW2 §13.16 part e3, steps 1 to 9).
pub(crate) fn serve_fast<R: Copy, P: FastServePaging<R>>(
    paging: &mut P,
    cr2: u64,
    error: u64,
) -> Result<FastServed, FastDecline> {
    // 1. This CPU's window, for the Thread it physically executes, on the
    //    root it had then; and its session.
    let window = paging.window().ok_or(FastDecline::Identity)?;
    let (executing, epoch) = paging.executing();
    if executing != Some(window.thread()) || epoch != window.root_epoch() {
        return Err(FastDecline::Identity);
    }
    if !paging.open_session(window.root(), window.process()) {
        return Err(FastDecline::Identity);
    }
    // 2. The scheduler, the Stop mailbox and the BSP's timer expiries.
    if !paging.scheduler_allows(window.thread()) {
        return Err(FastDecline::Identity);
    }
    // 3. The address is in the window's mapping, and the access is one its
    //    protection allows.
    let mapping = window.mapping();
    let address = cr2 & PAGE_MASK;
    let protection = mapping.protection();
    if address < mapping.virtual_start()
        || address - mapping.virtual_start() >= mapping.byte_len()
        || (error & WRITE != 0 && !protection.writable())
        || (error & FETCH != 0 && !protection.executable())
    {
        return Err(FastDecline::Mapping);
    }
    paging.stamp(FastStamp::Checked);
    let (frames, written) = {
        let mut leaf = paging.leaf(&mapping).ok_or(FastDecline::Identity)?;
        // 4. The leaf's place.
        let mut place = leaf.find(&mapping, address).ok_or(FastDecline::Tables)?;
        // 5 and 6. The commit, within the credit, in one walk of the
        //    backing's index (DW2 §13.18 part f1). A committed page takes
        //    nothing.
        let frames = match leaf.commit_within(&mut place, window.credit()) {
            FastCommit::Done(frames) => frames,
            FastCommit::Over | FastCommit::Unaskable => return Err(FastDecline::Credit),
            FastCommit::Refused => return Err(FastDecline::Memory),
            FastCommit::NotCommitted => return Err(FastDecline::NotCommitted),
        };
        leaf.stamp(FastStamp::Committed);
        // 7. The leaf.
        let written = leaf.write(place);
        leaf.stamp(FastStamp::Written);
        (frames, written)
    };
    // Whatever follows, the credit falls by the frames taken.
    if frames != 0 {
        paging.spend(frames);
    }
    let published = written.ok_or(FastDecline::Leaf)?;
    // 8. The return, through present leaves only.
    if !paging.validate_return() {
        return Err(FastDecline::Return);
    }
    // 9.
    Ok(if published || frames != 0 {
        FastServed::Served
    } else {
        FastServed::AlreadyPresent
    })
}

/// Which fast serve answered a fault (DW2 §15.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastKind {
    /// The serve with P shared, of a page already committed.
    Shared,
    /// The serve with P exclusive, which may commit.
    Exclusive,
}

/// One CPU's owner-local memory of its last fast serve (DW2 §15.2): set
/// when that serve took no frame, so the next fault tries the shared serve
/// first. A wrong value costs one attempt: a shared serve of an uncommitted
/// page answers `NotCommitted` and the exclusive one runs in the same
/// fault.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SharedServeFlag {
    took_no_frame: bool,
}

impl SharedServeFlag {
    /// Clear: the next fault runs the exclusive fast serve.
    pub(crate) const fn new() -> Self {
        Self {
            took_no_frame: false,
        }
    }

    /// Whether the next fault tries the shared serve first.
    pub(crate) const fn tries_shared(self) -> bool {
        self.took_no_frame
    }

    /// This CPU's serve under T ran: it may have opened, replaced or closed
    /// this CPU's window, so the next fault runs the exclusive serve first.
    pub(crate) fn serve_under_t_ran(&mut self) {
        self.took_no_frame = false;
    }

    /// This CPU's serve under T committed ahead of a stream (DW2 §15.6): the
    /// next touches find their pages committed, so the next fault tries the
    /// shared serve first.
    pub(crate) fn serve_under_t_committed_ahead(&mut self) {
        self.took_no_frame = true;
    }
}

/// The gate's choice of fast serve for one fault (DW2 §15.2), over
/// `context`. With the flag set, `shared` runs first: its success is the
/// fault's; on `NotCommitted` the flag is cleared and `exclusive` runs in
/// the same fault; any other decline is the fault's, for the serve under
/// T. With the flag clear, `exclusive` runs, and its success sets the flag
/// when it took no frame (its `bool`). Returns the outcome and which serve
/// gave it.
pub(crate) fn serve_gated<C, T>(
    flag: &mut SharedServeFlag,
    context: &mut C,
    shared: impl FnOnce(&mut C) -> Result<T, FastDecline>,
    exclusive: impl FnOnce(&mut C) -> Result<(T, bool), FastDecline>,
) -> (Result<T, FastDecline>, FastKind) {
    if flag.took_no_frame {
        match shared(context) {
            Err(FastDecline::NotCommitted) => flag.took_no_frame = false,
            answered => return (answered, FastKind::Shared),
        }
    }
    let answered = exclusive(context).map(|(served, took_no_frame)| {
        flag.took_no_frame = took_no_frame;
        served
    });
    (answered, FastKind::Exclusive)
}

#[cfg(test)]
#[path = "fault_window_tests.rs"]
mod tests;
