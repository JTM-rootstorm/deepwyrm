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
//! A decline before step 6 changes nothing. From step 6 the frames a commit
//! took are spent from the window's credit whatever follows, so the
//! object's weight stays the frames committed plus the credit; a decline at
//! step 7 or 8 is still correct, because the serve under T finds the page
//! committed (cost zero) and does what it does today.

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
    /// Step 5: the commit would take more than the credit.
    Credit,
    /// Step 6: the commit was refused.
    Memory,
    /// Step 7: the leaf could not be written.
    Leaf,
    /// Step 8: the return is not authorised by present leaves alone.
    Return,
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
    /// Step 6 done (or skipped for a zero cost): the end of `commit`.
    Committed,
    /// Step 7 done: the end of `tables`.
    Written,
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
    /// Step 5: the frames committing the page at `address` would take, or
    /// `None` if it cannot be asked.
    fn cost(&mut self, mapping: &Mapping, address: u64) -> Option<u64>;
    /// Step 6: commits the page at `address`, returning the frames taken,
    /// or `None` when the commit is refused (and took nothing).
    fn commit(&mut self, mapping: &Mapping, address: u64) -> Option<u64>;
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
    let (cost, frames, written) = {
        let mut leaf = paging.leaf(&mapping).ok_or(FastDecline::Identity)?;
        // 4. The leaf's place.
        let place = leaf.find(&mapping, address).ok_or(FastDecline::Tables)?;
        // 5. The commit's cost is within the credit.
        let cost = leaf.cost(&mapping, address).ok_or(FastDecline::Credit)?;
        if cost > window.credit() {
            return Err(FastDecline::Credit);
        }
        // 6. The commit. A cost of zero commits nothing.
        let frames = if cost == 0 {
            0
        } else {
            leaf.commit(&mapping, address).ok_or(FastDecline::Memory)?
        };
        leaf.stamp(FastStamp::Committed);
        // 7. The leaf.
        let written = leaf.write(place);
        leaf.stamp(FastStamp::Written);
        (cost, frames, written)
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
    Ok(if published || cost != 0 {
        FastServed::Served
    } else {
        FastServed::AlreadyPresent
    })
}

#[cfg(test)]
#[path = "fault_window_tests.rs"]
mod tests;
