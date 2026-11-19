//! Fault windows (DW2 §13.16 part e3): a page charge admitted ahead, so a
//! first touch inside the window can be served under the paging lock P
//! alone, without the runtime authority T.
//!
//! The table lives in P's value, one slot per CPU. A window names the Thread
//! and the root it was opened for, a copy of the mapping record the touch
//! falls in, the MemoryObject that mapping maps, and its credit: frames
//! charged to that object's weight and not yet committed.
//!
//! The one invariant of the charge: an object's page weight is the frames
//! committed for it plus the credit of every window that names it. A
//! window's credit is created ([`FaultWindows::open`]) and destroyed
//! ([`FaultWindows::close`], [`FaultWindows::close_address_space`],
//! [`FaultWindows::close_all`]) only with T and P both held, the weight
//! changed through [`WindowCharges`] in the same hold. Under P alone it only
//! falls, by exactly the frames a commit took ([`FaultWindows::spend`],
//! and under T and P [`FaultWindows::spend_ahead`]).
//!
//! A stream (DW2 §15.6): a window records the page of its last serve under
//! T (`base`), the credit it had right after that open or top-up
//! (`granted`), and the end of what was last committed ahead for it
//! (`ahead_end`). The next serve under T for the same window starts a
//! stream when the window has committed nothing ahead and the page is
//! exactly `base + (granted - credit + 1)` pages: every frame spent since
//! was a touch and this touch is the next page. A window that has
//! committed ahead continues its stream at exactly `ahead_end`; a serve
//! inside `(base, ahead_end)` changes nothing about it; any other ends it,
//! and the window is a credit window again. A new or replaced window is
//! never a stream. Committing ahead converts credit into committed frames
//! one for one, so it changes no weight and the invariant above holds as
//! for a fast serve's commit.
//!
//! No mapping record of an address space changes while a window copied from
//! it exists: every function of the AddressRegion adapter that hands out a
//! mutable region or retires a root consumes a [`WindowsClosed`] for its
//! address space, and the only way to make one is to close that address
//! space's windows here.
//!
//! Architecture-independent and built on the host; the root identity a
//! window carries is a type parameter (x86_64 passes its `UserCopyRoot`).

use super::{AddressSpaceKey, Mapping, PAGE_SIZE};
use crate::object::ObjectId;
use crate::task::{ProcessKey, ThreadKey};

/// The most frames one window is charged ahead (DW2 §13.16): T is taken
/// about once in this many touches, and a group's usage stands above its
/// committed frames by at most this many for each CPU.
pub(crate) const FAULT_WINDOW_FRAMES: u64 = 64;

/// The registry's side of a window's charge: admission and the object's
/// page weight. Every change is checked; a change to an object that is not
/// live is a broken invariant and panics.
pub(crate) trait WindowCharges {
    /// Whether `frames` more pages of weight for `object` are admitted now.
    fn admit(&self, object: ObjectId, frames: u64) -> bool;
    /// Adds `frames` to `object`'s page weight.
    fn add(&mut self, object: ObjectId, frames: u64);
    /// Takes `frames` from `object`'s page weight.
    fn subtract(&mut self, object: ObjectId, frames: u64);
}

/// One CPU's fault window. Its credit is private to this module: it rises
/// only by an admission in [`FaultWindows::open`] and falls only by
/// [`FaultWindows::spend`] and the closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FaultWindow<R> {
    thread: ThreadKey,
    process: ProcessKey,
    root_epoch: u64,
    root: R,
    mapping: Mapping,
    object: ObjectId,
    credit: u64,
    /// The page of the last serve under T that opened or kept this window.
    base: u64,
    /// The credit right after that open or top-up, or after the last
    /// commit ahead.
    granted: u64,
    /// The end of what was last committed ahead for this window: the
    /// address of the first page it did not cover. `None` when the window
    /// is not a stream.
    ahead_end: Option<u64>,
}

/// What a serve under T at a page is to the window it keeps (DW2 §15.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamStep {
    /// The window committed nothing ahead, and this is the page after every
    /// frame spent since its last serve under T.
    Starts,
    /// The page is exactly where the last commit ahead ended.
    Continues,
    /// The page is inside the last commit ahead's range (a page table was
    /// missing there): nothing about the stream changes.
    Inside,
    /// Anywhere else: no stream, and any stream ends.
    Elsewhere,
}

/// The stream rule (DW2 §15.6) for a serve under T at page `page` that
/// keeps `window`, decided before its top-up. An overflow is no stream.
fn stream_step<R>(window: &FaultWindow<R>, page: u64) -> StreamStep {
    match window.ahead_end {
        Some(end) if page == end => StreamStep::Continues,
        Some(end) if window.base < page && page < end => StreamStep::Inside,
        Some(_) => StreamStep::Elsewhere,
        None => {
            let next = window
                .granted
                .checked_sub(window.credit)
                .and_then(|spent| spent.checked_add(1))
                .and_then(|pages| pages.checked_mul(PAGE_SIZE))
                .and_then(|bytes| window.base.checked_add(bytes));
            if next == Some(page) {
                StreamStep::Starts
            } else {
                StreamStep::Elsewhere
            }
        }
    }
}

impl<R: Copy> FaultWindow<R> {
    /// The Thread it was opened for.
    pub(crate) const fn thread(&self) -> ThreadKey {
        self.thread
    }

    /// That Thread's Process, copied under T at opening.
    pub(crate) const fn process(&self) -> ProcessKey {
        self.process
    }

    /// This CPU's root-switch epoch at opening.
    pub(crate) const fn root_epoch(&self) -> u64 {
        self.root_epoch
    }

    /// The root identity, copied as a guard-free usercopy copies it.
    pub(crate) const fn root(&self) -> R {
        self.root
    }

    /// The mapping record the opening touch fell in.
    pub(crate) const fn mapping(&self) -> Mapping {
        self.mapping
    }

    /// The MemoryObject the mapping maps.
    pub(crate) const fn object(&self) -> ObjectId {
        self.object
    }

    /// Frames charged to [`Self::object`] and not yet committed.
    pub(crate) const fn credit(&self) -> u64 {
        self.credit
    }

    /// The page of the last serve under T that opened or kept it.
    pub(crate) const fn base(&self) -> u64 {
        self.base
    }

    /// Its credit right after that open or top-up, or after the last
    /// commit ahead.
    pub(crate) const fn granted(&self) -> u64 {
        self.granted
    }

    /// The end of what was last committed ahead for it, while it is a
    /// stream (DW2 §15.6).
    pub(crate) const fn ahead_end(&self) -> Option<u64> {
        self.ahead_end
    }
}

/// What a serve under T and P found, for opening a window after it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WindowOpening<R> {
    pub(crate) thread: ThreadKey,
    pub(crate) process: ProcessKey,
    pub(crate) root_epoch: u64,
    pub(crate) root: R,
    pub(crate) mapping: Mapping,
    pub(crate) object: ObjectId,
    /// The address the serve touched.
    pub(crate) address: u64,
}

/// What [`FaultWindows::open`] did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WindowOpened {
    /// An admission stored a window or topped one up.
    pub(crate) opened: bool,
    /// The CPU's old window was closed.
    pub(crate) closed: bool,
    /// This serve starts or continues a stream (DW2 §15.6): the pages
    /// after it are to be committed ahead from the window's credit.
    pub(crate) ahead: bool,
}

/// Streams started and ended since the last [`FaultWindows::take_stream_changes`]
/// (DW2 §15.6, the `streams` line).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StreamChanges {
    /// Windows whose first commit ahead was recorded.
    pub(crate) started: u64,
    /// Streams ended by a serve under T elsewhere, or by their window
    /// closing or being replaced.
    pub(crate) ended: u64,
}

/// Proof that no fault window copied from `address_space`'s mapping records
/// exists. Made only by [`FaultWindows::close_address_space`], neither
/// `Copy` nor `Clone`, and consumed by value by every function that changes
/// a mapping record or retires a root. It is not to be stored: opening a
/// window needs T, so it stays true until the hold that made it ends.
#[must_use = "a WindowsClosed is consumed by the mapping change it was made for"]
#[derive(Debug)]
pub(crate) struct WindowsClosed {
    address_space: AddressSpaceKey,
    closed: usize,
}

impl WindowsClosed {
    /// The address space it was made for.
    pub(crate) const fn address_space(&self) -> AddressSpaceKey {
        self.address_space
    }

    /// The windows closed to make it.
    pub(crate) const fn closed(&self) -> usize {
        self.closed
    }

    /// Consumes the proof for a change to `address_space`, which it must
    /// name.
    pub(crate) fn consume_for(self, address_space: AddressSpaceKey) {
        assert_eq!(
            self.address_space, address_space,
            "a mapping change was given another address space's WindowsClosed"
        );
    }
}

/// The pages of `mapping` after the page holding `address`.
fn pages_after(mapping: &Mapping, address: u64) -> u64 {
    let page = address & !(PAGE_SIZE - 1);
    let end = mapping.virtual_start().saturating_add(mapping.byte_len());
    end.saturating_sub(page.saturating_add(PAGE_SIZE)) / PAGE_SIZE
}

/// One fault window slot per CPU, in P's value.
pub(crate) struct FaultWindows<R, const CPUS: usize> {
    slots: [Option<FaultWindow<R>>; CPUS],
    /// Stream changes not yet taken for the step report.
    streams: StreamChanges,
}

impl<R: Copy, const CPUS: usize> Default for FaultWindows<R, CPUS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Copy, const CPUS: usize> FaultWindows<R, CPUS> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { None }; CPUS],
            streams: StreamChanges {
                started: 0,
                ended: 0,
            },
        }
    }

    /// CPU slot `cpu`'s window, if it has one.
    pub(crate) fn window(&self, cpu: usize) -> Option<&FaultWindow<R>> {
        self.slots.get(cpu).and_then(Option::as_ref)
    }

    /// Every open window.
    pub(crate) fn windows(&self) -> impl Iterator<Item = &FaultWindow<R>> + '_ {
        self.slots.iter().flatten()
    }

    /// Under P alone: a commit for CPU `cpu`'s window took `frames`, which
    /// its credit had admitted. The credit falls by exactly that. A spend
    /// without a window, or above its credit, is a broken invariant.
    pub(crate) fn spend(&mut self, cpu: usize, frames: u64) {
        let window = self
            .slots
            .get_mut(cpu)
            .and_then(Option::as_mut)
            .unwrap_or_else(|| panic!("a fault window's commit had no window"));
        window.credit = window
            .credit
            .checked_sub(frames)
            .unwrap_or_else(|| panic!("a fault window's commit took more than its credit"));
    }

    /// Under T and P (DW2 §15.6): a commit ahead for CPU `cpu`'s window
    /// took `frames`, which its credit had admitted, and covered the pages
    /// up to `ahead_end`, the address of the first page it did not cover.
    /// The credit falls by exactly `frames`, as [`Self::spend`] (with its
    /// panics); the window records `ahead_end`, and its granted credit is
    /// what is left, so a later serve inside the range is not a start.
    pub(crate) fn spend_ahead(&mut self, cpu: usize, frames: u64, ahead_end: u64) {
        self.spend(cpu, frames);
        let window = self
            .slots
            .get_mut(cpu)
            .and_then(Option::as_mut)
            .unwrap_or_else(|| panic!("a fault window's commit had no window"));
        if window.ahead_end.is_none() {
            self.streams.started += 1;
        }
        window.ahead_end = Some(ahead_end);
        window.granted = window.credit;
    }

    /// The streams started and ended since the last call, and resets them.
    pub(crate) fn take_stream_changes(&mut self) -> StreamChanges {
        core::mem::take(&mut self.streams)
    }

    /// Under T and P, at the end of a serve that left `opening.address`
    /// present: the window for the rest of the mapping (DW2 §13.16).
    /// - A window of the same Thread, Process, object and mapping is kept,
    ///   its root identity refreshed, and topped up to `min(64, pages
    ///   after this one)` by the difference, if that difference is
    ///   admitted. Before the top-up the stream rule (DW2 §15.6) is asked:
    ///   [`WindowOpened::ahead`] when this serve starts or continues a
    ///   stream; a serve elsewhere ends one. Unless the page is inside the
    ///   last commit ahead's range, the window then records this page and
    ///   its credit after the top-up.
    /// - Any other window of this CPU is closed. Then, when the mapping has
    ///   pages after this one, `min(64, those pages)` frames are admitted
    ///   against the object and a window is stored only if that admission
    ///   succeeds. A new window is never a stream.
    pub(crate) fn open(
        &mut self,
        cpu: usize,
        opening: WindowOpening<R>,
        charges: &mut impl WindowCharges,
    ) -> WindowOpened {
        let mut opened = WindowOpened::default();
        let Some(slot) = self.slots.get_mut(cpu) else {
            return opened;
        };
        let target = FAULT_WINDOW_FRAMES.min(pages_after(&opening.mapping, opening.address));
        let page = opening.address & !(PAGE_SIZE - 1);
        if let Some(window) = slot.as_mut()
            && window.thread == opening.thread
            && window.process == opening.process
            && window.object == opening.object
            && window.mapping == opening.mapping
        {
            let step = stream_step(window, page);
            if step == StreamStep::Elsewhere && window.ahead_end.take().is_some() {
                self.streams.ended += 1;
            }
            opened.ahead = matches!(step, StreamStep::Starts | StreamStep::Continues);
            window.root = opening.root;
            window.root_epoch = opening.root_epoch;
            if target > window.credit {
                let difference = target - window.credit;
                if charges.admit(opening.object, difference) {
                    charges.add(opening.object, difference);
                    window.credit = target;
                    opened.opened = true;
                }
            }
            if step != StreamStep::Inside {
                window.base = page;
                window.granted = window.credit;
            }
            return opened;
        }
        if let Some(old) = slot.take() {
            if old.credit != 0 {
                charges.subtract(old.object, old.credit);
            }
            if old.ahead_end.is_some() {
                self.streams.ended += 1;
            }
            opened.closed = true;
        }
        if target != 0 && charges.admit(opening.object, target) {
            charges.add(opening.object, target);
            *slot = Some(FaultWindow {
                thread: opening.thread,
                process: opening.process,
                root_epoch: opening.root_epoch,
                root: opening.root,
                mapping: opening.mapping,
                object: opening.object,
                credit: target,
                base: page,
                granted: target,
                ahead_end: None,
            });
            opened.opened = true;
        }
        opened
    }

    fn close_slot(
        slot: &mut Option<FaultWindow<R>>,
        charges: &mut impl WindowCharges,
        streams: &mut StreamChanges,
    ) -> bool {
        let Some(window) = slot.take() else {
            return false;
        };
        if window.credit != 0 {
            charges.subtract(window.object, window.credit);
        }
        if window.ahead_end.is_some() {
            streams.ended += 1;
        }
        true
    }

    /// Under T and P: closes CPU `cpu`'s window, returning its credit to
    /// the object's weight. `true` if it had one.
    pub(crate) fn close(&mut self, cpu: usize, charges: &mut impl WindowCharges) -> bool {
        self.slots
            .get_mut(cpu)
            .is_some_and(|slot| Self::close_slot(slot, charges, &mut self.streams))
    }

    /// Under T and P: closes every CPU's window whose mapping is in
    /// `address_space`, and returns the proof that none is left.
    pub(crate) fn close_address_space(
        &mut self,
        address_space: AddressSpaceKey,
        charges: &mut impl WindowCharges,
    ) -> WindowsClosed {
        let mut closed = 0;
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|window| window.mapping.address_space() == address_space)
                && Self::close_slot(slot, charges, &mut self.streams)
            {
                closed += 1;
            }
        }
        WindowsClosed {
            address_space,
            closed,
        }
    }

    /// Under T and P: closes every window, before a quota refusal is
    /// decided, so credit is never the reason one is refused. Returns how
    /// many it closed.
    pub(crate) fn close_all(&mut self, charges: &mut impl WindowCharges) -> usize {
        self.slots
            .iter_mut()
            .filter(|slot| slot.is_some())
            .map(|slot| Self::close_slot(slot, charges, &mut self.streams))
            .filter(|closed| *closed)
            .count()
    }

    /// The credit of every window whose object `counts` toward a group: the
    /// part of that group's kept usage no frame stands behind.
    pub(crate) fn credit_toward(&self, mut counts: impl FnMut(ObjectId) -> bool) -> u64 {
        self.windows()
            .filter(|window| counts(window.object))
            .fold(0_u64, |total, window| {
                total
                    .checked_add(window.credit)
                    .unwrap_or_else(|| panic!("fault window credit overflowed"))
            })
    }
}

/// A group's usage as it would stand with every window closed: the kept
/// figure less the credit of the windows that count toward it (DW2 §13.16,
/// the reported usage). The kept figure counts every such credit, so it is
/// never below it.
pub(crate) fn usage_without_credit(kept: usize, credit: u64) -> usize {
    let credit = usize::try_from(credit).unwrap_or(usize::MAX);
    kept.checked_sub(credit)
        .unwrap_or_else(|| panic!("a group's usage did not count its windows' credit"))
}

/// The one way a test gets a [`WindowsClosed`]: an empty window table,
/// closed for `address_space`.
#[cfg(test)]
pub(crate) fn test_windows_closed(address_space: AddressSpaceKey) -> WindowsClosed {
    struct NoCharges;
    impl WindowCharges for NoCharges {
        fn admit(&self, _: ObjectId, _: u64) -> bool {
            false
        }
        fn add(&mut self, _: ObjectId, _: u64) {
            panic!("an empty window table charged nothing");
        }
        fn subtract(&mut self, _: ObjectId, _: u64) {
            panic!("an empty window table returned nothing");
        }
    }
    FaultWindows::<(), 1>::new().close_address_space(address_space, &mut NoCharges)
}

/// A mapping record for the window tests: `pages` pages from `start` in
/// `address_space`, with `protection`.
#[cfg(test)]
pub(crate) fn test_mapping(
    address_space: AddressSpaceKey,
    start: u64,
    pages: u64,
    protection: super::Protection,
) -> Mapping {
    Mapping {
        address_space,
        virtual_start: start,
        byte_len: pages * PAGE_SIZE,
        protection,
        ..super::EMPTY_MAPPING
    }
}

#[cfg(test)]
#[path = "fault_window_tests.rs"]
mod tests;
