extern crate std;

use super::*;
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

const PAGE: u64 = 4096;
/// A fill-in step of four pages, so a buffer of a few pages takes several
/// holds.
const STEP: u64 = 4 * PAGE;

// ---------------------------------------------------------------------------
// The fill-in's model.
// ---------------------------------------------------------------------------

/// What the fill-in's model saw, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Call {
    /// A safe point's hold began (`yielding`: the quantum had ended).
    Hold { yielding: bool },
    /// The bootstrap hold drained this many pending timer expiries.
    Drain(usize),
    /// The page at this address was served.
    Serve(u64),
    /// The hold took its owed step.
    Owed,
}

const SERVED: FillServe = FillServe {
    outcome: UserPageFaultOutcome::Served,
    owed: false,
};

const fn exhausted(status: DwStatus, owed: bool) -> FillServe {
    FillServe {
        outcome: UserPageFaultOutcome::Exhausted(status),
        owed,
    }
}

/// One hold of the fill-in: pages are on demand when they are in `pages`,
/// and each serve of a page takes the next of its outcomes (the last one
/// repeats).
#[derive(Default)]
struct Pages {
    /// The hold runs on the bootstrap CPU.
    bootstrap: bool,
    /// Timer expiries that arrived and were not yet drained.
    pending: usize,
    pages: BTreeMap<u64, Vec<FillServe>>,
    log: Vec<Call>,
}

impl Pages {
    fn bootstrap() -> Self {
        Self {
            bootstrap: true,
            ..Self::default()
        }
    }

    /// Pages `[first, first + count)` (page numbers) are on demand and
    /// served.
    fn with_served(mut self, first: u64, count: u64) -> Self {
        for page in first..first + count {
            self.pages.insert(page * PAGE, vec![SERVED]);
        }
        self
    }

    fn with_page(mut self, page: u64, serves: &[FillServe]) -> Self {
        self.pages.insert(page * PAGE, serves.to_vec());
        self
    }

    fn served(&self) -> Vec<u64> {
        self.log
            .iter()
            .filter_map(|call| match call {
                Call::Serve(address) => Some(address / PAGE),
                Call::Hold { .. } | Call::Drain(_) | Call::Owed => None,
            })
            .collect()
    }

    fn owed_steps(&self) -> usize {
        self.log.iter().filter(|call| **call == Call::Owed).count()
    }
}

impl FillInHold for Pages {
    fn service_timer_expiries(&mut self) {
        if self.bootstrap {
            self.log.push(Call::Drain(self.pending));
            self.pending = 0;
        }
    }

    fn on_demand(&mut self, address: u64) -> bool {
        self.pages.contains_key(&address)
    }

    fn serve(&mut self, address: u64, _write: bool) -> FillServe {
        self.log.push(Call::Serve(address));
        let serves = self.pages.get_mut(&address).expect("only on demand");
        if serves.len() > 1 {
            serves.remove(0)
        } else {
            serves[0]
        }
    }

    fn take_owed_step(&mut self) {
        self.log.push(Call::Owed);
    }
}

/// The fill-in's safe points over one [`Pages`]: an expiry arrives before
/// every safe point, a Stop comes at safe point `stop_at` and the quantum
/// has ended at each of `yield_at` (counted from 0 in this call).
#[derive(Default)]
struct Safepoints {
    hold: Pages,
    stop_at: Option<usize>,
    yield_at: Vec<usize>,
    safe_points: usize,
    may_yield: Vec<bool>,
}

impl Safepoints {
    fn new(hold: Pages) -> Self {
        Self {
            hold,
            ..Self::default()
        }
    }

    /// A new call or resume over the same pages and log.
    fn resume(&mut self) {
        self.stop_at = None;
        self.yield_at.clear();
        self.safe_points = 0;
        self.may_yield.clear();
    }
}

impl FillInRuntime for Safepoints {
    type Hold<'a> = Pages;

    fn step<T>(
        &mut self,
        may_yield: bool,
        operation: impl FnOnce(&mut Pages, bool) -> T,
    ) -> Result<T, ()> {
        let point = self.safe_points;
        self.safe_points += 1;
        self.may_yield.push(may_yield);
        self.hold.pending += 1;
        if self.stop_at == Some(point) {
            return Err(());
        }
        let yielding = may_yield && self.yield_at.contains(&point);
        self.hold.log.push(Call::Hold { yielding });
        Ok(operation(&mut self.hold, yielding))
    }
}

fn buffer(first_page: u64, pages: u64, write: bool) -> Option<UserBuffer> {
    Some(UserBuffer {
        address: first_page * PAGE,
        byte_len: pages * PAGE,
        write,
    })
}

fn fill(runtime: &mut Safepoints, buffers: [Option<UserBuffer>; 3]) -> FillInEnd {
    fill_in_buffers(runtime, buffers, 0, None, STEP, PAGE)
}

// ---------------------------------------------------------------------------
// fill_in_range
// ---------------------------------------------------------------------------

/// A spurious fault: a page whose leaf was already there (`AlreadyPresent`)
/// is passed over like one served or unserved; nothing is refused.
#[test]
fn a_spurious_fault_is_passed_over() {
    let unserved = FillServe {
        outcome: UserPageFaultOutcome::Unserved,
        owed: false,
    };
    let present = FillServe {
        outcome: UserPageFaultOutcome::AlreadyPresent,
        owed: false,
    };
    let mut hold = Pages::default()
        .with_page(0, &[present])
        .with_page(1, &[SERVED])
        .with_page(2, &[unserved])
        .with_page(3, &[present]);
    let mut next = 0;
    assert_eq!(
        fill_in_range(&mut hold, &mut next, 4 * PAGE, false, STEP, PAGE),
        Ok(())
    );
    assert_eq!(next, 4 * PAGE);
    assert_eq!(hold.served(), [0, 1, 2, 3]);
    assert_eq!(hold.owed_steps(), 0);
}

#[test]
fn pages_not_on_demand_are_never_served() {
    let mut hold = Pages::default()
        .with_page(1, &[SERVED])
        .with_page(3, &[SERVED]);
    let mut next = 0;
    assert_eq!(
        fill_in_range(&mut hold, &mut next, 4 * PAGE, true, STEP, PAGE),
        Ok(())
    );
    assert_eq!(next, 4 * PAGE);
    assert_eq!(hold.served(), [1, 3]);
}

#[test]
fn one_hold_serves_at_most_one_step() {
    let mut hold = Pages::default().with_served(0, 10);
    let mut next = 0;
    let end = 10 * PAGE;
    assert_eq!(
        fill_in_range(&mut hold, &mut next, end, false, STEP, PAGE),
        Ok(())
    );
    assert_eq!(next, STEP);
    assert_eq!(hold.served(), [0, 1, 2, 3]);
    assert_eq!(
        fill_in_range(&mut hold, &mut next, end, false, STEP, PAGE),
        Ok(())
    );
    assert_eq!(next, 2 * STEP);
    assert_eq!(hold.served(), [0, 1, 2, 3, 4, 5, 6, 7]);
    // The last step ends at the range's end.
    assert_eq!(
        fill_in_range(&mut hold, &mut next, end, false, STEP, PAGE),
        Ok(())
    );
    assert_eq!(next, end);
    assert_eq!(hold.served(), (0..10).collect::<Vec<_>>());
}

/// A refusal that is not owed, for each status a serve refuses with
/// (`NO_MEMORY` is what the live serve returns when a table candidate is
/// refused): the call ends there with the status, `*next` past the refused
/// page, and the pages after it in the step are not served.
#[test]
fn a_refusal_not_owed_ends_the_call() {
    for status in [DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES] {
        let mut hold = Pages::default()
            .with_served(0, 4)
            .with_page(1, &[exhausted(status, false)]);
        let mut next = 0;
        assert_eq!(
            fill_in_range(&mut hold, &mut next, 4 * PAGE, false, STEP, PAGE),
            Err(status)
        );
        assert_eq!(next, 2 * PAGE, "{status:?}");
        assert_eq!(hold.served(), [0, 1]);
        assert_eq!(hold.owed_steps(), 0);
    }
}

/// The same refusals owed: the hold takes exactly one owed step and
/// returns `Ok`, `*next` is the refused page again, and the next hold
/// serves that page first.
#[test]
fn an_owed_refusal_takes_the_owed_step_and_serves_the_page_again() {
    for status in [DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES] {
        let mut hold = Pages::default()
            .with_served(0, 4)
            .with_page(1, &[exhausted(status, true), SERVED]);
        let mut next = 0;
        assert_eq!(
            fill_in_range(&mut hold, &mut next, 4 * PAGE, false, STEP, PAGE),
            Ok(())
        );
        assert_eq!(next, PAGE, "{status:?}");
        assert_eq!(
            hold.log,
            [Call::Serve(0), Call::Serve(PAGE), Call::Owed],
            "{status:?}"
        );
        assert_eq!(
            fill_in_range(&mut hold, &mut next, 4 * PAGE, false, STEP, PAGE),
            Ok(())
        );
        assert_eq!(next, 4 * PAGE);
        assert_eq!(hold.served(), [0, 1, 1, 2, 3]);
        assert_eq!(hold.owed_steps(), 1);
    }
}

// ---------------------------------------------------------------------------
// fill_in_buffers
// ---------------------------------------------------------------------------

/// The log split into holds, each starting at its `Hold` entry.
fn holds(log: &[Call]) -> Vec<&[Call]> {
    let mut starts: Vec<usize> = log
        .iter()
        .enumerate()
        .filter_map(|(index, call)| matches!(call, Call::Hold { .. }).then_some(index))
        .collect();
    assert_eq!(starts.first(), Some(&0), "every call is in a hold");
    starts.push(log.len());
    starts
        .windows(2)
        .map(|pair| &log[pair[0]..pair[1]])
        .collect()
}

/// BSP timer expiries during a long fill-in: an expiry arrives before every
/// safe point, and every bootstrap hold drains what is pending before it
/// serves anything, a yielding hold too. On another CPU nothing is drained
/// and the fill-in is otherwise the same.
#[test]
fn bsp_timer_expiries_are_drained_in_every_hold_of_a_long_fill_in() {
    let pages = 4 * 5 + 2;
    let mut bsp = Safepoints::new(Pages::bootstrap().with_served(0, pages));
    bsp.yield_at = vec![3];
    let buffers = [buffer(0, pages, true), None, None];
    let FillInEnd::Parked { index, next } = fill(&mut bsp, buffers) else {
        panic!("the quantum ended at the fourth safe point");
    };
    bsp.resume();
    assert_eq!(
        fill_in_buffers(&mut bsp, buffers, index, Some(next), STEP, PAGE),
        FillInEnd::Done { stepped: true }
    );
    let log = bsp.hold.log.clone();
    let holds = holds(&log);
    // Six steps of four, four, four, (yield), four, four, two pages.
    assert_eq!(holds.len(), 7);
    for (number, hold) in holds.iter().enumerate() {
        let yielding = number == 3;
        assert_eq!(hold[0], Call::Hold { yielding }, "hold {number}");
        // One expiry arrived before this safe point and is drained first.
        assert_eq!(hold[1], Call::Drain(1), "hold {number}");
        let served = hold[2..].iter().all(|call| matches!(call, Call::Serve(_)));
        assert!(served, "hold {number}: {hold:?}");
        if yielding {
            assert_eq!(hold.len(), 2, "a yielding hold serves nothing");
        } else {
            assert!(hold.len() > 2, "hold {number} serves its step");
        }
    }
    assert_eq!(bsp.hold.pending, 0);
    assert_eq!(bsp.hold.served(), (0..pages).collect::<Vec<_>>());

    // The same fill-in on an application processor.
    let mut ap = Safepoints::new(Pages::default().with_served(0, pages));
    ap.yield_at = vec![3];
    let FillInEnd::Parked { index, next } = fill(&mut ap, buffers) else {
        panic!("the quantum ended at the fourth safe point");
    };
    ap.resume();
    assert_eq!(
        fill_in_buffers(&mut ap, buffers, index, Some(next), STEP, PAGE),
        FillInEnd::Done { stepped: true }
    );
    assert!(
        !ap.hold
            .log
            .iter()
            .any(|call| matches!(call, Call::Drain(_)))
    );
    assert_eq!(ap.hold.pending, 7);
    let without_drains: Vec<Call> = log
        .iter()
        .copied()
        .filter(|call| !matches!(call, Call::Drain(_)))
        .collect();
    assert_eq!(ap.hold.log, without_drains);
}

#[test]
fn absent_empty_and_overflowing_buffers_are_skipped() {
    let mut runtime = Safepoints::new(Pages::bootstrap().with_served(0, 4));
    let buffers = [
        None,
        Some(UserBuffer {
            address: 0,
            byte_len: 0,
            write: false,
        }),
        Some(UserBuffer {
            address: u64::MAX - 10,
            byte_len: 5,
            write: false,
        }),
    ];
    assert_eq!(
        fill(&mut runtime, buffers),
        FillInEnd::Done { stepped: false }
    );
    assert_eq!(runtime.safe_points, 0);
    assert!(runtime.hold.log.is_empty());
}

#[test]
fn three_buffers_are_filled_in_in_order() {
    let mut runtime = Safepoints::new(Pages::default().with_served(0, 64));
    // Unaligned buffers cover every page they touch.
    let buffers = [
        Some(UserBuffer {
            address: 20 * PAGE + 8,
            byte_len: PAGE,
            write: true,
        }),
        buffer(2, 5, false),
        Some(UserBuffer {
            address: 40 * PAGE + PAGE - 1,
            byte_len: 1,
            write: false,
        }),
    ];
    assert_eq!(
        fill(&mut runtime, buffers),
        FillInEnd::Done { stepped: true }
    );
    assert_eq!(runtime.hold.served(), [20, 21, 2, 3, 4, 5, 6, 40]);
    // One step for the first buffer, two for the second, one for the third.
    assert_eq!(runtime.may_yield, [false, true, true, true]);
}

#[test]
fn a_stop_at_any_safe_point_ends_the_call() {
    for stop_at in 0..3 {
        let mut runtime = Safepoints::new(Pages::default().with_served(0, 12));
        runtime.stop_at = Some(stop_at);
        assert_eq!(
            fill(&mut runtime, [buffer(0, 12, false), None, None]),
            FillInEnd::Stopped
        );
        // Each safe point before the Stop served one step.
        assert_eq!(
            runtime.hold.served(),
            (0..4 * stop_at as u64).collect::<Vec<_>>()
        );
    }
}

/// A call parked at any safe point and resumed from where it parked serves
/// every page once, in order: none twice, none skipped.
#[test]
fn a_parked_call_resumes_where_it_parked() {
    let buffers = [
        buffer(0, 6, false),
        buffer(10, 3, true),
        buffer(20, 9, false),
    ];
    let expected: Vec<u64> = (0..6).chain(10..13).chain(20..29).collect();
    for park_at in 1..6 {
        let mut runtime = Safepoints::new(Pages::default().with_served(0, 32));
        runtime.yield_at = vec![park_at];
        let FillInEnd::Parked { index, next } = fill(&mut runtime, buffers) else {
            panic!("the call parks at safe point {park_at}");
        };
        assert_eq!(runtime.may_yield.len(), park_at + 1);
        assert!(!runtime.may_yield[0], "the first safe point may not yield");
        assert!(runtime.may_yield[1..].iter().all(|may_yield| *may_yield));
        // The cursor names the buffer and the page the resumed call starts
        // from: the first page no hold served.
        let served = runtime.hold.served().len();
        assert_eq!(next / PAGE, expected[served], "park at {park_at}");
        let buffer = buffers[index].expect("a parked buffer");
        assert!(buffer.address <= next && next < buffer.address + buffer.byte_len);
        runtime.resume();
        assert_eq!(
            fill_in_buffers(&mut runtime, buffers, index, Some(next), STEP, PAGE),
            FillInEnd::Done { stepped: true }
        );
        assert!(
            !runtime.may_yield[0],
            "a resume's first safe point may not yield"
        );
        assert_eq!(runtime.hold.served(), expected, "park at {park_at}");
    }
}

#[test]
fn a_refusal_not_owed_fails_the_fill_in() {
    let mut runtime = Safepoints::new(
        Pages::default()
            .with_served(0, 8)
            .with_page(5, &[exhausted(DW_STATUS_NO_MEMORY, false)]),
    );
    assert_eq!(
        fill(
            &mut runtime,
            [buffer(0, 8, false), buffer(0, 8, false), None]
        ),
        FillInEnd::Failed(DW_STATUS_NO_MEMORY)
    );
    assert_eq!(runtime.hold.served(), [0, 1, 2, 3, 4, 5]);
}

#[test]
fn an_owed_refusal_steps_and_the_fill_in_goes_on() {
    let mut runtime = Safepoints::new(
        Pages::default()
            .with_served(0, 8)
            .with_page(5, &[exhausted(DW_STATUS_NO_RESOURCES, true), SERVED]),
    );
    assert_eq!(
        fill(&mut runtime, [buffer(0, 8, false), None, None]),
        FillInEnd::Done { stepped: true }
    );
    assert_eq!(runtime.hold.served(), [0, 1, 2, 3, 4, 5, 5, 6, 7]);
    assert_eq!(runtime.hold.owed_steps(), 1);
    // The owed step's hold counts as a step: the next safe point may yield.
    assert_eq!(runtime.may_yield, [false, true, true]);
}

#[test]
fn done_says_whether_a_step_ran() {
    // No on-demand page, but the buffer's steps still ran.
    let mut runtime = Safepoints::new(Pages::default());
    assert_eq!(
        fill(&mut runtime, [buffer(0, 2, false), None, None]),
        FillInEnd::Done { stepped: true }
    );
    let mut runtime = Safepoints::new(Pages::default());
    assert_eq!(
        fill(&mut runtime, [None, None, None]),
        FillInEnd::Done { stepped: false }
    );
    // A resume at a buffer's end runs no step.
    let mut runtime = Safepoints::new(Pages::default());
    assert_eq!(
        fill_in_buffers(
            &mut runtime,
            [buffer(0, 2, false), None, None],
            0,
            Some(2 * PAGE),
            STEP,
            PAGE
        ),
        FillInEnd::Done { stepped: false }
    );
}

// ---------------------------------------------------------------------------
// commit_step's model.
// ---------------------------------------------------------------------------

/// What the commit step's model saw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Asked {
    Admit(u64),
    Close,
    QuotaOwed(u64),
    Commit(u64),
    Record(u64),
    MemoryOwed,
}

/// An object whose creator has `quota` frames, of which `charged` are its
/// weight and `windows` are held by fault windows' credit. Each page not
/// yet committed costs `page_cost` frames; frames come from `supply`.
struct Object {
    quota: u64,
    charged: u64,
    windows: Vec<u64>,
    page_cost: u64,
    committed: Vec<bool>,
    supply: u64,
    bad_state_at: Option<u64>,
    quota_owed: bool,
    memory_owed: bool,
    /// The step's first page.
    first: u64,
    log: Vec<Asked>,
    stamps: Vec<CommitPoint>,
}

impl Object {
    fn new(pages: usize, quota: u64) -> Self {
        Self {
            quota,
            charged: 0,
            windows: Vec::new(),
            page_cost: 1,
            committed: vec![false; pages],
            supply: u64::MAX,
            bad_state_at: None,
            quota_owed: false,
            memory_owed: false,
            first: 0,
            log: Vec::new(),
            stamps: Vec::new(),
        }
    }

    fn committed_pages(&self) -> Vec<u64> {
        (0..self.committed.len() as u64)
            .filter(|page| self.committed[*page as usize])
            .collect()
    }

    fn admissions(&self) -> usize {
        self.log
            .iter()
            .filter(|asked| matches!(asked, Asked::Admit(_)))
            .count()
    }

    fn recorded(&self) -> Vec<u64> {
        self.log
            .iter()
            .filter_map(|asked| match asked {
                Asked::Record(frames) => Some(*frames),
                Asked::Admit(_)
                | Asked::Close
                | Asked::QuotaOwed(_)
                | Asked::Commit(_)
                | Asked::MemoryOwed => None,
            })
            .collect()
    }

    /// One step of at most `step_pages` from `*next` in a range of
    /// `[0, end)`.
    fn step(&mut self, next: &mut u64, end: u64, step_pages: u64) -> Result<CommitStep, DwStatus> {
        self.first = *next / PAGE;
        let step_end = end.min(next.saturating_add(step_pages * PAGE));
        let count = (step_end - *next) / PAGE;
        commit_step(self, next, end, count, PAGE)
    }
}

impl CommitStepHold for Object {
    fn cost(&mut self, pages: u64) -> Result<u64, DwStatus> {
        Ok((self.first..self.first + pages)
            .filter(|page| !self.committed[*page as usize])
            .count() as u64
            * self.page_cost)
    }

    fn admit(&mut self, cost: u64) -> Result<(), DwStatus> {
        assert_ne!(cost, 0, "a cost of zero is never admitted");
        self.log.push(Asked::Admit(cost));
        let held = self.charged + self.windows.iter().sum::<u64>();
        if held + cost <= self.quota {
            Ok(())
        } else {
            Err(DW_STATUS_NO_RESOURCES)
        }
    }

    fn close_all_windows(&mut self) -> usize {
        self.log.push(Asked::Close);
        let closed = self.windows.len();
        self.windows.clear();
        closed
    }

    fn quota_refusal_owed(&mut self, cost: u64) -> bool {
        self.log.push(Asked::QuotaOwed(cost));
        self.quota_owed
    }

    fn commit(&mut self, index: u64) -> Result<u64, CommitRefusal> {
        let page = self.first + index;
        self.log.push(Asked::Commit(page));
        if self.bad_state_at == Some(page) {
            return Err(CommitRefusal::BadState);
        }
        if self.committed[page as usize] {
            return Ok(0);
        }
        if self.supply < self.page_cost {
            return Err(CommitRefusal::NoMemory);
        }
        self.supply -= self.page_cost;
        self.committed[page as usize] = true;
        Ok(self.page_cost)
    }

    fn record(&mut self, frames: u64) {
        self.log.push(Asked::Record(frames));
        self.charged += frames;
    }

    fn memory_refusal_owed(&mut self) -> bool {
        self.log.push(Asked::MemoryOwed);
        self.memory_owed
    }

    fn stamp(&mut self, point: CommitPoint) {
        self.stamps.push(point);
    }
}

// ---------------------------------------------------------------------------
// commit_step
// ---------------------------------------------------------------------------

#[test]
fn whole_steps_are_admitted_until_the_range_is_done() {
    let mut object = Object::new(16, 64);
    object.page_cost = 2;
    let mut next = 0;
    let end = 10 * PAGE;
    assert_eq!(object.step(&mut next, end, 4), Ok(CommitStep::More));
    assert_eq!(next, 4 * PAGE);
    assert_eq!(object.step(&mut next, end, 4), Ok(CommitStep::More));
    assert_eq!(object.step(&mut next, end, 4), Ok(CommitStep::Done));
    assert_eq!(next, end);
    assert_eq!(object.committed_pages(), (0..10).collect::<Vec<_>>());
    // Each step's record is exactly the frames it took.
    assert_eq!(object.recorded(), [8, 8, 4]);
    assert_eq!(object.charged, 20);
    assert_eq!(object.admissions(), 3);
}

#[test]
fn a_step_of_committed_pages_asks_no_admission_and_records_nothing() {
    let mut object = Object::new(8, 0);
    object.committed[..4].fill(true);
    let mut next = 0;
    assert_eq!(object.step(&mut next, 4 * PAGE, 4), Ok(CommitStep::Done));
    assert_eq!(next, 4 * PAGE);
    assert_eq!(
        object.log,
        [
            Asked::Commit(0),
            Asked::Commit(1),
            Asked::Commit(2),
            Asked::Commit(3)
        ]
    );
}

#[test]
fn a_refusal_that_closing_the_windows_cures_is_admitted() {
    let mut object = Object::new(8, 8);
    object.windows = vec![3, 2];
    let mut next = 0;
    assert_eq!(object.step(&mut next, 8 * PAGE, 8), Ok(CommitStep::Done));
    assert_eq!(
        object.log[..3],
        [Asked::Admit(8), Asked::Close, Asked::Admit(8)]
    );
    assert_eq!(
        object
            .log
            .iter()
            .filter(|asked| **asked == Asked::Close)
            .count(),
        1
    );
    assert_eq!(object.committed_pages(), (0..8).collect::<Vec<_>>());
    assert_eq!(object.recorded(), [8]);
}

#[test]
fn an_owed_quota_refusal_commits_nothing() {
    let mut object = Object::new(8, 3);
    object.windows = vec![1];
    object.quota_owed = true;
    let mut next = 2 * PAGE;
    assert_eq!(object.step(&mut next, 8 * PAGE, 4), Ok(CommitStep::Owed));
    assert_eq!(next, 2 * PAGE);
    assert_eq!(
        object.log,
        [
            Asked::Admit(4),
            Asked::Close,
            Asked::Admit(4),
            Asked::QuotaOwed(4)
        ]
    );
    assert!(object.committed_pages().is_empty());
    assert_eq!(object.stamps, [CommitPoint::AdmitBegan]);
}

/// A quota refusal not owed commits the longest start of the step the
/// quota admits, filling it exactly, in at most ten admissions for a
/// 512-page step.
#[test]
fn a_refusal_not_owed_commits_the_longest_start_that_fits() {
    for quota in [0, 1, 2, 3, 100, 255, 256, 257, 510, 511] {
        let mut object = Object::new(512, quota);
        let mut next = 0;
        assert_eq!(
            object.step(&mut next, 512 * PAGE, 512),
            Err(DW_STATUS_NO_RESOURCES),
            "quota {quota}"
        );
        assert_eq!(object.committed_pages(), (0..quota).collect::<Vec<_>>());
        assert_eq!(next, quota * PAGE, "quota {quota}");
        assert_eq!(object.charged, quota, "the quota is filled exactly");
        assert!(
            object.admissions() <= 10,
            "quota {quota}: {}",
            object.admissions()
        );
        assert_eq!(
            object
                .log
                .iter()
                .filter(|a| **a == Asked::QuotaOwed(512))
                .count(),
            1
        );
        assert_eq!(
            object.stamps,
            [
                CommitPoint::AdmitBegan,
                CommitPoint::AdmitEnded,
                CommitPoint::Taken
            ]
        );
    }
    // With pages already committed in the step, the start that fits counts
    // only the ones still to commit.
    let mut object = Object::new(16, 3);
    object.committed[1] = true;
    object.committed[2] = true;
    object.charged = 0;
    let mut next = 0;
    assert_eq!(
        object.step(&mut next, 16 * PAGE, 16),
        Err(DW_STATUS_NO_RESOURCES)
    );
    assert_eq!(object.committed_pages(), [0, 1, 2, 3, 4]);
    assert_eq!(next, 5 * PAGE);
    assert_eq!(object.recorded(), [3]);
}

#[test]
fn a_frame_refused_mid_step_keeps_what_was_taken() {
    for owed in [false, true] {
        let mut object = Object::new(8, 64);
        object.supply = 3;
        object.memory_owed = owed;
        let mut next = 0;
        let expected = if owed {
            Ok(CommitStep::Owed)
        } else {
            Err(DW_STATUS_NO_MEMORY)
        };
        assert_eq!(object.step(&mut next, 8 * PAGE, 8), expected);
        assert_eq!(object.committed_pages(), [0, 1, 2]);
        assert_eq!(object.recorded(), [3]);
        // The page that failed is where the call goes on.
        assert_eq!(next, 3 * PAGE);
        assert_eq!(object.log.last(), Some(&Asked::MemoryOwed));
    }
}

#[test]
fn a_bad_state_mid_step_keeps_what_was_taken() {
    let mut object = Object::new(8, 64);
    object.bad_state_at = Some(2);
    object.memory_owed = true;
    let mut next = 0;
    assert_eq!(
        object.step(&mut next, 8 * PAGE, 8),
        Err(DW_STATUS_BAD_STATE)
    );
    assert_eq!(object.committed_pages(), [0, 1]);
    assert_eq!(object.recorded(), [2]);
    assert_eq!(next, 2 * PAGE);
    // Only a frame refusal asks whether it is owed.
    assert!(!object.log.contains(&Asked::MemoryOwed));
}

#[test]
fn a_step_that_reaches_its_end_is_stamped_in_order() {
    let mut object = Object::new(8, 64);
    let mut next = 0;
    assert_eq!(object.step(&mut next, 8 * PAGE, 4), Ok(CommitStep::More));
    assert_eq!(
        object.stamps,
        [
            CommitPoint::AdmitBegan,
            CommitPoint::AdmitEnded,
            CommitPoint::Taken
        ]
    );
    let mut object = Object::new(8, 64);
    object.supply = 1;
    let mut next = 0;
    assert_eq!(
        object.step(&mut next, 8 * PAGE, 4),
        Err(DW_STATUS_NO_MEMORY)
    );
    assert_eq!(
        object.stamps,
        [
            CommitPoint::AdmitBegan,
            CommitPoint::AdmitEnded,
            CommitPoint::Taken
        ]
    );
    // The early owed return is no sample.
    let mut object = Object::new(8, 0);
    object.quota_owed = true;
    let mut next = 0;
    assert_eq!(object.step(&mut next, 8 * PAGE, 4), Ok(CommitStep::Owed));
    assert_eq!(object.stamps, [CommitPoint::AdmitBegan]);
}
