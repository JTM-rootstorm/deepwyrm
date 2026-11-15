//! What calls in steps did during a boot, logged at power-off (DW2 M5
//! §10.5 probes 14 and 15).
//!
//! For each call in steps (map, unmap, protect, the fill-in, commit and a
//! create's zeroing) the kernel keeps:
//! - the longest time one step held its CPU, from the safe point that began
//!   it to the next (interrupts are off for a whole syscall, so this is time
//!   nothing else ran there);
//! - how many Stops a safe point took after the call had made a step since
//!   it started or resumed, which is a Stop that landed between steps rather
//!   than before the first;
//! - how many parked calls were settled because their Thread ended while
//!   parked (§10.8 item 5);
//! - per call, its longest step, its steps and their total time, which
//!   give the cost per step and so per page (§10.6 step 6, probe 14);
//! - the longest time queued teardown, and queued finalization, stayed owed
//!   without the queue emptying (§10.10 item 8, §10.12): an upper bound on
//!   how long one dead job's memory waits to be freed;
//! - for queued finalization (§10.19 revision 2): one object's longest wait
//!   from being queued to its completion, with the frames it freed; the
//!   longest gap between finalize steps while some is owed; and every
//!   finalize step, nested in a timed step or not, by what drained.
//!
//! Every count is a relaxed atomic. Nothing here decides anything; it only
//! reports. The finalization records are written only under the runtime
//! authority T (queueing and stepping both run in its holds), so each has
//! one writer at a time; they are read at power-off.

use core::sync::atomic::{AtomicU64, Ordering};

/// A call in steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepCall {
    Map = 0,
    Unmap = 1,
    Protect = 2,
    FillIn = 3,
    Commit = 4,
    Create = 5,
    /// A step of an exited Process's queued teardown (DW2 §10.10).
    Teardown = 6,
    /// A step of releasing a handle-less object's unmapped pages (§10.9).
    Release = 7,
    /// A step of the queued finalization of on-demand objects (§10.12).
    Finalize = 8,
}

const CALLS: usize = 9;
const NAMES: [&str; CALLS] = [
    "map", "unmap", "protect", "fill", "commit", "create", "teardown", "release", "finalize",
];
/// The low bits of the packed longest step hold the call.
const CALL_BITS: u32 = 4;
const _: () = assert!(CALLS <= 1 << CALL_BITS);

/// Queued work whose time owed is reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owed {
    Teardown = 0,
    Finalize = 1,
}

/// What drained when a finalize step ran (DW2 §10.19 revision 2 item 3):
/// the kind of entry this CPU last made, kept per CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DrainSource {
    /// The timer gate of a user-mode interrupt (only the BSP's drains).
    Gate = 0,
    /// A syscall, from its entry to its return.
    Syscall = 1,
    /// A user page fault.
    Fault = 2,
    /// An idle loop, or the poll of a CPU idling on a blocked Thread's root.
    Idle = 3,
    /// Anything else: the reapers, a fresh Thread's entry.
    Other = 4,
}

const SOURCES: usize = 5;

impl DrainSource {
    fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Gate,
            1 => Self::Syscall,
            2 => Self::Fault,
            3 => Self::Idle,
            _ => Self::Other,
        }
    }
}

/// When each owed finalization was queued and the frames its steps have
/// freed, by its owed slot (DW2 §10.19 revision 2 item 1). Bounded as the
/// owed queue is, one entry per slot.
pub(crate) struct OwedWaits<const SLOTS: usize> {
    /// When the slot's object was queued, in nanoseconds plus one; zero
    /// when nothing queued there is recorded.
    queued: [AtomicU64; SLOTS],
    freed: [AtomicU64; SLOTS],
}

impl<const SLOTS: usize> OwedWaits<SLOTS> {
    pub(crate) const fn new() -> Self {
        Self {
            queued: [const { AtomicU64::new(0) }; SLOTS],
            freed: [const { AtomicU64::new(0) }; SLOTS],
        }
    }

    /// An object was queued in `slot` at `now`.
    pub(crate) fn queued(&self, slot: usize, now: u64) {
        if let (Some(queued), Some(freed)) = (self.queued.get(slot), self.freed.get(slot)) {
            queued.store(now.saturating_add(1), Ordering::Relaxed);
            freed.store(0, Ordering::Relaxed);
        }
    }

    /// A step freed `frames` of `slot`'s object.
    pub(crate) fn freed(&self, slot: usize, frames: u64) {
        if let Some(freed) = self.freed.get(slot) {
            freed.fetch_add(frames, Ordering::Relaxed);
        }
    }

    /// `slot`'s object completed: when it was queued and the frames freed,
    /// if its queueing was recorded. The slot's record is cleared.
    pub(crate) fn completed(&self, slot: usize) -> Option<(u64, u64)> {
        let queued = self.queued.get(slot)?.swap(0, Ordering::Relaxed);
        let freed = self.freed.get(slot)?.swap(0, Ordering::Relaxed);
        (queued != 0).then(|| (queued - 1, freed))
    }
}

/// The report's state, for `CPUS` CPUs.
pub(crate) struct StepTally<const CPUS: usize> {
    /// When each CPU's current step began, in nanoseconds plus one; zero
    /// when none is being timed.
    started: [AtomicU64; CPUS],
    /// The longest step in nanoseconds, shifted left by [`CALL_BITS`], with
    /// its call in the low bits, so one `fetch_max` keeps both.
    longest: AtomicU64,
    stops: [AtomicU64; CALLS],
    ended: [AtomicU64; CALLS],
    /// Per call: its longest step, its steps and their total, in ns.
    call_longest: [AtomicU64; CALLS],
    call_steps: [AtomicU64; CALLS],
    call_total: [AtomicU64; CALLS],
    /// Per kind of owed work: since when it has been owed, plus one (zero
    /// when nothing is), and the longest stretch owed, in ns.
    owed_since: [AtomicU64; 2],
    owed_longest: [AtomicU64; 2],
    /// One object's longest wait from queued to completed, in ns, and the
    /// frames that object freed.
    finalize_wait_longest: AtomicU64,
    finalize_wait_pages: AtomicU64,
    /// Since when no finalize step has run while some is owed: the end of
    /// the last step, or a queueing into an empty queue, in ns plus one;
    /// zero while nothing is owed. And the longest such gap, in ns.
    finalize_gap_since: AtomicU64,
    finalize_gap_longest: AtomicU64,
    /// Finalize steps by what drained, counted whether or not they were
    /// nested in a timed step.
    finalize_steps: [AtomicU64; SOURCES],
}

impl<const CPUS: usize> StepTally<CPUS> {
    pub(crate) const fn new() -> Self {
        Self {
            started: [const { AtomicU64::new(0) }; CPUS],
            longest: AtomicU64::new(0),
            stops: [const { AtomicU64::new(0) }; CALLS],
            ended: [const { AtomicU64::new(0) }; CALLS],
            call_longest: [const { AtomicU64::new(0) }; CALLS],
            call_steps: [const { AtomicU64::new(0) }; CALLS],
            call_total: [const { AtomicU64::new(0) }; CALLS],
            owed_since: [const { AtomicU64::new(0) }; 2],
            owed_longest: [const { AtomicU64::new(0) }; 2],
            finalize_wait_longest: AtomicU64::new(0),
            finalize_wait_pages: AtomicU64::new(0),
            finalize_gap_since: AtomicU64::new(0),
            finalize_gap_longest: AtomicU64::new(0),
            finalize_steps: [const { AtomicU64::new(0) }; SOURCES],
        }
    }

    /// An object's finalization was queued at `now`, into a queue that was
    /// empty if `into_empty`: a gap begins there.
    pub(crate) fn finalize_queued(&self, into_empty: bool, now: u64) {
        if into_empty {
            let _ = self.finalize_gap_since.compare_exchange(
                0,
                now.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// A finalize step drained by `source` ran from `began` to `ended`; it
    /// ends the gap before it, and if finalization is still `owed` after
    /// it, the next gap begins at its end.
    pub(crate) fn finalize_stepped(&self, source: DrainSource, began: u64, ended: u64, owed: bool) {
        self.finalize_steps[source as usize].fetch_add(1, Ordering::Relaxed);
        let next = if owed { ended.saturating_add(1) } else { 0 };
        let since = self.finalize_gap_since.swap(next, Ordering::Relaxed);
        if since != 0 {
            self.finalize_gap_longest
                .fetch_max(began.saturating_sub(since - 1), Ordering::Relaxed);
        }
    }

    /// An object completed after waiting `wait` ns since it was queued,
    /// having freed `pages` frames. One writer at a time (T), so the pair
    /// is kept together.
    pub(crate) fn finalize_waited(&self, wait: u64, pages: u64) {
        if wait > self.finalize_wait_longest.load(Ordering::Relaxed) {
            self.finalize_wait_longest.store(wait, Ordering::Relaxed);
            self.finalize_wait_pages.store(pages, Ordering::Relaxed);
        }
    }

    /// Writes the finalization lines' bodies (§10.19 revision 2); a gap
    /// still open at `now` counts.
    pub(crate) fn write_finalize_lines(
        &self,
        now: Option<u64>,
        mut line: impl FnMut(core::fmt::Arguments<'_>),
    ) {
        line(format_args!(
            "finalize-wait-longest-us={} pages={}",
            self.finalize_wait_longest.load(Ordering::Relaxed) / 1000,
            self.finalize_wait_pages.load(Ordering::Relaxed)
        ));
        let since = self.finalize_gap_since.load(Ordering::Relaxed);
        let open = match now {
            Some(now) if since != 0 => now.saturating_sub(since - 1),
            _ => 0,
        };
        let gap = self.finalize_gap_longest.load(Ordering::Relaxed).max(open);
        line(format_args!("finalize-gap-longest-us={}", gap / 1000));
        let [gate, syscall, fault, idle, other] = [0, 1, 2, 3, 4]
            .map(|source: usize| self.finalize_steps[source].load(Ordering::Relaxed));
        line(format_args!(
            "finalize-steps gate={gate} syscall={syscall} fault={fault} idle={idle} other={other}"
        ));
    }

    /// Whether `cpu` is timing a step now.
    pub(crate) fn timing(&self, cpu: usize) -> bool {
        self.started
            .get(cpu)
            .is_some_and(|slot| slot.load(Ordering::Relaxed) != 0)
    }

    /// Whether `kind` of work is `owed` at `now`: a stretch begins when it
    /// becomes owed and is recorded when it no longer is.
    pub(crate) fn owed_at(&self, kind: Owed, owed: bool, now: u64) {
        let since = &self.owed_since[kind as usize];
        if owed {
            let _ = since.compare_exchange(
                0,
                now.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        } else {
            let began = since.swap(0, Ordering::Relaxed);
            if began != 0 {
                self.owed_longest[kind as usize]
                    .fetch_max(now.saturating_sub(began - 1), Ordering::Relaxed);
            }
        }
    }

    /// A step of a call begins on `cpu` at `now`.
    pub(crate) fn step_began(&self, cpu: usize, now: u64) {
        if let Some(slot) = self.started.get(cpu) {
            slot.store(now.saturating_add(1), Ordering::Relaxed);
        }
    }

    /// The step `cpu` was timing ends at `now`, at a safe point of `call`.
    /// Nothing is recorded if no step was being timed there.
    pub(crate) fn step_ended(&self, cpu: usize, call: StepCall, now: u64) {
        let Some(slot) = self.started.get(cpu) else {
            return;
        };
        let started = slot.swap(0, Ordering::Relaxed);
        if started == 0 {
            return;
        }
        let held = now.saturating_sub(started - 1).min(u64::MAX >> CALL_BITS);
        self.longest
            .fetch_max((held << CALL_BITS) | call as u64, Ordering::Relaxed);
        let call = call as usize;
        self.call_longest[call].fetch_max(held, Ordering::Relaxed);
        self.call_steps[call].fetch_add(1, Ordering::Relaxed);
        self.call_total[call].fetch_add(held, Ordering::Relaxed);
    }

    /// A Stop ended `call` at a safe point after it had made a step.
    pub(crate) fn stopped_between_steps(&self, call: StepCall) {
        self.stops[call as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// A parked `call` was settled because its Thread had ended.
    pub(crate) fn parked_call_ended(&self, call: StepCall) {
        self.ended[call as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The longest step, in nanoseconds, and its call; `None` before any.
    pub(crate) fn longest(&self) -> Option<(u64, &'static str)> {
        let packed = self.longest.load(Ordering::Relaxed);
        (packed != 0).then(|| {
            let call = (packed & ((1 << CALL_BITS) - 1)) as usize;
            (packed >> CALL_BITS, NAMES.get(call).copied().unwrap_or("?"))
        })
    }

    /// Writes the report lines' bodies, one call each.
    pub(crate) fn write_lines(&self, mut line: impl FnMut(core::fmt::Arguments<'_>)) {
        match self.longest() {
            Some((held, call)) => line(format_args!("longest-step-us={} call={call}", held / 1000)),
            None => line(format_args!("longest-step-us=0 call=none")),
        }
        let counts = |counts: &[AtomicU64; CALLS]| {
            let mut values = [0u64; CALLS];
            for (value, count) in values.iter_mut().zip(counts) {
                *value = count.load(Ordering::Relaxed);
            }
            values
        };
        let [map, unmap, protect, fill, commit, create, ..] = counts(&self.stops);
        line(format_args!(
            "stops-between-steps map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create}"
        ));
        let [map, unmap, protect, fill, commit, create, ..] = counts(&self.ended);
        line(format_args!(
            "parked-ended map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create}"
        ));
        let per_call = |line: &mut dyn FnMut(core::fmt::Arguments<'_>),
                        name: &str,
                        values: [u64; CALLS],
                        scale: u64| {
            let [
                map,
                unmap,
                protect,
                fill,
                commit,
                create,
                teardown,
                release,
                finalize,
            ] = values.map(|value| value / scale);
            line(format_args!(
                "{name} map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create} teardown={teardown} release={release} finalize={finalize}"
            ));
        };
        per_call(
            &mut line,
            "call-longest-us",
            counts(&self.call_longest),
            1000,
        );
        per_call(&mut line, "call-steps", counts(&self.call_steps), 1);
        per_call(&mut line, "call-total-us", counts(&self.call_total), 1000);
        let [teardown, finalize] =
            [0, 1].map(|kind| self.owed_longest[kind].load(Ordering::Relaxed) / 1000);
        line(format_args!(
            "owed-longest-us teardown={teardown} finalize={finalize}"
        ));
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live {
    use super::{DrainSource, StepCall, StepTally};
    use crate::cpu::CPU_CAPACITY;

    static TALLY: StepTally<CPU_CAPACITY> = StepTally::new();
    /// Per CPU, whether a queued teardown step may still run since the
    /// CPU last entered from user mode (DW2 §10.10 item 7): one step per
    /// syscall, timer interrupt, page fault or idle poll.
    static TEARDOWN_ALLOWED: [core::sync::atomic::AtomicBool; CPU_CAPACITY] =
        [const { core::sync::atomic::AtomicBool::new(false) }; CPU_CAPACITY];

    /// An entry from user mode (or an idle poll) on `cpu`: one teardown
    /// step may run before the next.
    pub(crate) fn allow_teardown_step(cpu: usize) {
        if let Some(slot) = TEARDOWN_ALLOWED.get(cpu) {
            slot.store(true, core::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Takes `cpu`'s one teardown step, if it has not been taken.
    pub(crate) fn take_teardown_step(cpu: usize) -> bool {
        TEARDOWN_ALLOWED
            .get(cpu)
            .is_some_and(|slot| slot.swap(false, core::sync::atomic::Ordering::Relaxed))
    }

    /// Per CPU, the kind of entry it last made (DW2 §10.19 revision 2 item
    /// 3), as a [`DrainSource`]. Written and read only on its own CPU.
    static DRAIN_SOURCE: [core::sync::atomic::AtomicU8; CPU_CAPACITY] =
        [const { core::sync::atomic::AtomicU8::new(DrainSource::Other as u8) }; CPU_CAPACITY];

    /// `cpu` is now draining as `source`.
    pub(crate) fn set_drain_source(cpu: usize, source: DrainSource) {
        if let Some(slot) = DRAIN_SOURCE.get(cpu) {
            slot.store(source as u8, core::sync::atomic::Ordering::Relaxed);
        }
    }

    fn drain_source(cpu: usize) -> DrainSource {
        DRAIN_SOURCE.get(cpu).map_or(DrainSource::Other, |slot| {
            DrainSource::from_index(slot.load(core::sync::atomic::Ordering::Relaxed))
        })
    }

    /// The report's clock: the kernel's monotonic nanoseconds.
    pub(crate) fn now() -> Option<u64> {
        crate::time::monotonic_now().ok()
    }

    /// An owed finalization was queued at `now` (see
    /// [`StepTally::finalize_queued`]).
    pub(crate) fn finalize_queued(into_empty: bool, now: u64) {
        TALLY.finalize_queued(into_empty, now);
    }

    /// A finalize step ran on `cpu` (see [`StepTally::finalize_stepped`]).
    pub(crate) fn finalize_stepped(cpu: usize, began: u64, ended: u64, owed: bool) {
        TALLY.finalize_stepped(drain_source(cpu), began, ended, owed);
    }

    /// An owed finalization completed (see [`StepTally::finalize_waited`]).
    pub(crate) fn finalize_waited(wait: u64, pages: u64) {
        TALLY.finalize_waited(wait, pages);
    }

    /// Times a step from here, for a loop whose first step has no safe point
    /// before it.
    pub(crate) fn step_began(cpu: usize) {
        if let Some(now) = now() {
            TALLY.step_began(cpu, now);
        }
    }

    /// At a safe point of `call` on `cpu`: ends the step being timed if the
    /// call `stepped`, and returns the time for [`after_safe_point`].
    pub(crate) fn at_safe_point(cpu: usize, call: StepCall, stepped: bool) -> Option<u64> {
        let now = now();
        if let Some(now) = now
            && stepped
        {
            TALLY.step_ended(cpu, call, now);
        }
        now
    }

    /// After that safe point: a Stop that ended a call that had stepped is
    /// counted, and a step about to run is timed.
    pub(crate) fn after_safe_point(
        cpu: usize,
        call: StepCall,
        stepped: bool,
        now: Option<u64>,
        stopped: bool,
        stepping: bool,
    ) {
        if stopped && stepped {
            TALLY.stopped_between_steps(call);
        }
        if let (Some(now), true) = (now, stepping) {
            TALLY.step_began(cpu, now);
        }
    }

    pub(crate) fn parked_call_ended(call: StepCall) {
        TALLY.parked_call_ended(call);
    }

    /// Times `step` on `cpu` as one step of `call`, unless a step is being
    /// timed there already: then it is part of that step's hold and is
    /// counted in it (step-6 review D4).
    pub(crate) fn timed_nested<T>(cpu: usize, call: StepCall, step: impl FnOnce() -> T) -> T {
        if TALLY.timing(cpu) {
            step()
        } else {
            timed(cpu, call, step)
        }
    }

    /// Whether `kind` of work is owed now (see [`StepTally::owed_at`]).
    pub(crate) fn owed(kind: super::Owed, owed: bool) {
        if let Some(now) = now() {
            TALLY.owed_at(kind, owed, now);
        }
    }

    /// Times `step` on `cpu` as one step of `call`.
    pub(crate) fn timed<T>(cpu: usize, call: StepCall, step: impl FnOnce() -> T) -> T {
        step_began(cpu);
        let result = step();
        if let Some(now) = now() {
            TALLY.step_ended(cpu, call, now);
        }
        result
    }

    pub(crate) fn report() {
        fn emit(arguments: core::fmt::Arguments<'_>) {
            let mut line = Line::new();
            let _ = core::fmt::Write::write_fmt(&mut line, arguments);
            if let Ok(message) = core::str::from_utf8(line.text()) {
                let _ = crate::debug::emit_early_record(
                    crate::debug::DiagnosticLevel::Info,
                    "steps",
                    message,
                );
            }
        }
        TALLY.write_lines(emit);
        TALLY.write_finalize_lines(now(), emit);
    }

    struct Line {
        bytes: [u8; 224],
        len: usize,
    }

    impl Line {
        const fn new() -> Self {
            Self {
                bytes: [0; 224],
                len: 0,
            }
        }

        fn text(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    impl core::fmt::Write for Line {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.len + text.len();
            let slot = self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?;
            slot.copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use live::{
    after_safe_point, allow_teardown_step, at_safe_point, finalize_queued, finalize_stepped,
    finalize_waited, now, owed, parked_call_ended, report, set_drain_source, step_began,
    take_teardown_step, timed, timed_nested,
};

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::String;
    use std::vec::Vec;

    fn lines(tally: &StepTally<2>) -> Vec<String> {
        let mut out = Vec::new();
        tally.write_lines(|arguments| out.push(std::fmt::format(arguments)));
        out
    }

    #[test]
    fn nothing_recorded_reports_zero() {
        let tally = StepTally::<2>::new();
        assert_eq!(
            lines(&tally),
            [
                "longest-step-us=0 call=none",
                "stops-between-steps map=0 unmap=0 protect=0 fill=0 commit=0 create=0",
                "parked-ended map=0 unmap=0 protect=0 fill=0 commit=0 create=0",
                "call-longest-us map=0 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0",
                "call-steps map=0 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0",
                "call-total-us map=0 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0",
                "owed-longest-us teardown=0 finalize=0",
            ]
        );
    }

    #[test]
    fn each_call_keeps_its_longest_step_its_steps_and_their_total() {
        let tally = StepTally::<2>::new();
        for (cpu, call, began, ended) in [
            (0, StepCall::Finalize, 0, 2_000_000),
            (1, StepCall::Finalize, 0, 3_000_000),
            (0, StepCall::Release, 5_000_000, 5_400_000),
            (1, StepCall::Map, 0, 9_000_000),
        ] {
            tally.step_began(cpu, began);
            tally.step_ended(cpu, call, ended);
        }
        assert_eq!(tally.longest(), Some((9_000_000, "map")));
        let lines = lines(&tally);
        assert_eq!(
            lines[3],
            "call-longest-us map=9000 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=400 finalize=3000"
        );
        assert_eq!(
            lines[4],
            "call-steps map=1 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=1 finalize=2"
        );
        assert_eq!(
            lines[5],
            "call-total-us map=9000 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=400 finalize=5000"
        );
    }

    #[test]
    fn the_longest_stretch_owed_is_kept_per_kind() {
        let tally = StepTally::<2>::new();
        // Owed from 1 ms; still owed at 2 ms; done at 4 ms.
        tally.owed_at(Owed::Teardown, true, 1_000_000);
        tally.owed_at(Owed::Teardown, true, 2_000_000);
        tally.owed_at(Owed::Teardown, false, 4_000_000);
        // A shorter stretch later keeps the longest.
        tally.owed_at(Owed::Teardown, true, 10_000_000);
        tally.owed_at(Owed::Teardown, false, 11_000_000);
        // Not owed, then owed from time zero and done.
        tally.owed_at(Owed::Finalize, false, 1);
        tally.owed_at(Owed::Finalize, true, 0);
        tally.owed_at(Owed::Finalize, false, 7_000_000);
        assert_eq!(
            lines(&tally)[6],
            "owed-longest-us teardown=3000 finalize=7000"
        );
    }

    #[test]
    fn a_cpu_is_timing_only_between_a_begin_and_its_end() {
        let tally = StepTally::<2>::new();
        assert!(!tally.timing(0));
        tally.step_began(0, 0);
        assert!(tally.timing(0) && !tally.timing(1));
        tally.step_ended(0, StepCall::Finalize, 10);
        assert!(!tally.timing(0));
        assert!(!tally.timing(9));
    }

    #[test]
    fn the_longest_step_on_any_cpu_is_kept_with_its_call() {
        let tally = StepTally::<2>::new();
        tally.step_began(0, 1_000);
        tally.step_began(1, 0);
        tally.step_ended(0, StepCall::Map, 5_001_000);
        tally.step_ended(1, StepCall::Create, 9_000_000);
        assert_eq!(tally.longest(), Some((9_000_000, "create")));
        tally.step_began(1, 0);
        tally.step_ended(1, StepCall::Teardown, 9_500_000);
        assert_eq!(tally.longest(), Some((9_500_000, "teardown")));
        // A shorter step later changes nothing.
        tally.step_began(0, 10_000_000);
        tally.step_ended(0, StepCall::Commit, 10_000_500);
        assert_eq!(tally.longest(), Some((9_500_000, "teardown")));
        assert_eq!(lines(&tally)[0], "longest-step-us=9500 call=teardown");
    }

    #[test]
    fn an_end_with_no_timed_step_records_nothing() {
        let tally = StepTally::<2>::new();
        tally.step_ended(0, StepCall::Map, 1_000_000);
        assert_eq!(tally.longest(), None);
        // A step began at time zero is still timed.
        tally.step_began(0, 0);
        tally.step_ended(0, StepCall::Unmap, 7_000);
        assert_eq!(tally.longest(), Some((7_000, "unmap")));
        // Each begin is ended once.
        tally.step_ended(0, StepCall::Map, 99_000_000);
        assert_eq!(tally.longest(), Some((7_000, "unmap")));
        // A CPU past the table is ignored.
        tally.step_began(5, 0);
        tally.step_ended(5, StepCall::Map, 99_000_000);
        assert_eq!(tally.longest(), Some((7_000, "unmap")));
    }

    fn finalize_lines(tally: &StepTally<2>, now: Option<u64>) -> Vec<String> {
        let mut out = Vec::new();
        tally.write_finalize_lines(now, |arguments| out.push(std::fmt::format(arguments)));
        out
    }

    /// The events the runtime reports for owed finalization, scripted: the
    /// tally and the per-slot record together, as `finalize_owed_step` and
    /// the cleanup drain use them.
    struct Script {
        tally: StepTally<2>,
        waits: OwedWaits<4>,
        queued: usize,
    }

    impl Script {
        fn new() -> Self {
            Self {
                tally: StepTally::new(),
                waits: OwedWaits::new(),
                queued: 0,
            }
        }

        fn queue(&mut self, slot: usize, now_us: u64) {
            let now = now_us * 1000;
            self.waits.queued(slot, now);
            self.tally.finalize_queued(self.queued == 0, now);
            self.queued += 1;
        }

        /// A step from `began_us` to `ended_us` that freed `freed` frames
        /// of each `(slot, frames, completed)`.
        fn step(
            &mut self,
            source: DrainSource,
            began_us: u64,
            ended_us: u64,
            freed: &[(usize, u64, bool)],
        ) {
            let ended = ended_us * 1000;
            let mut oldest: Option<(u64, u64)> = None;
            for &(slot, frames, completed) in freed {
                self.waits.freed(slot, frames);
                if completed {
                    self.queued -= 1;
                    if let Some((queued, pages)) = self.waits.completed(slot)
                        && oldest.is_none_or(|(first, _)| queued < first)
                    {
                        oldest = Some((queued, pages));
                    }
                }
            }
            if let Some((queued, pages)) = oldest {
                self.tally.finalize_waited(ended - queued, pages);
            }
            self.tally
                .finalize_stepped(source, began_us * 1000, ended, self.queued != 0);
        }
    }

    #[test]
    fn nothing_queued_reports_zero_finalization() {
        let tally = StepTally::<2>::new();
        assert_eq!(
            finalize_lines(&tally, Some(9_000_000)),
            [
                "finalize-wait-longest-us=0 pages=0",
                "finalize-gap-longest-us=0",
                "finalize-steps gate=0 syscall=0 fault=0 idle=0 other=0",
            ]
        );
    }

    #[test]
    fn an_object_queued_into_an_empty_queue_waits_for_its_first_step() {
        let mut script = Script::new();
        // Queued at 1 ms; nothing steps until 4 ms; done by 6 ms.
        script.queue(2, 1_000);
        script.step(DrainSource::Gate, 4_000, 4_500, &[(2, 512, false)]);
        script.step(DrainSource::Gate, 5_000, 6_000, &[(2, 100, true)]);
        assert_eq!(
            finalize_lines(&script.tally, Some(50_000_000)),
            [
                "finalize-wait-longest-us=5000 pages=612",
                // 3 ms before the first step; 0.5 ms between the steps.
                "finalize-gap-longest-us=3000",
                "finalize-steps gate=2 syscall=0 fault=0 idle=0 other=0",
            ]
        );
    }

    #[test]
    fn the_time_nothing_is_owed_is_no_gap() {
        let mut script = Script::new();
        script.queue(0, 0);
        script.step(DrainSource::Syscall, 1_000, 1_100, &[(0, 7, true)]);
        // Empty for 100 ms, then queued again and stepped 2 ms later.
        script.queue(0, 101_100);
        script.step(DrainSource::Idle, 103_100, 103_200, &[(0, 9, true)]);
        assert_eq!(
            finalize_lines(&script.tally, Some(200_000_000)),
            [
                "finalize-wait-longest-us=2100 pages=9",
                "finalize-gap-longest-us=2000",
                "finalize-steps gate=0 syscall=1 fault=0 idle=1 other=0",
            ]
        );
    }

    #[test]
    fn two_overlapping_objects_keep_the_longest_wait_with_its_pages() {
        let mut script = Script::new();
        script.queue(1, 0);
        script.queue(3, 2_000);
        // Queued into a non-empty queue: no gap begins at 2 ms.
        script.step(DrainSource::Fault, 3_000, 3_200, &[(1, 512, false)]);
        script.step(
            DrainSource::Gate,
            4_000,
            4_300,
            &[(1, 40, true), (3, 300, false)],
        );
        script.step(DrainSource::Gate, 4_500, 30_000, &[(3, 200, true)]);
        assert_eq!(
            finalize_lines(&script.tally, Some(90_000_000)),
            [
                // Slot 1 waited 4.3 ms for 552 frames; slot 3, 28 ms for 500.
                "finalize-wait-longest-us=28000 pages=500",
                "finalize-gap-longest-us=3000",
                "finalize-steps gate=2 syscall=0 fault=1 idle=0 other=0",
            ]
        );
    }

    #[test]
    fn a_gap_still_open_at_the_report_counts() {
        let mut script = Script::new();
        script.queue(0, 0);
        script.step(DrainSource::Other, 1_000, 2_000, &[(0, 512, false)]);
        // Still owed at 900 ms: the gap since 2 ms counts, the wait does not.
        assert_eq!(
            finalize_lines(&script.tally, Some(900_000_000)),
            [
                "finalize-wait-longest-us=0 pages=0",
                "finalize-gap-longest-us=898000",
                "finalize-steps gate=0 syscall=0 fault=0 idle=0 other=1",
            ]
        );
        // Without a clock at the report, only closed gaps.
        assert_eq!(
            finalize_lines(&script.tally, None)[1],
            "finalize-gap-longest-us=1000"
        );
    }

    #[test]
    fn a_completion_without_its_queueing_is_not_a_wait() {
        let waits = OwedWaits::<2>::new();
        waits.freed(1, 5);
        assert_eq!(waits.completed(1), None);
        // The record is cleared by the completion, and a slot past the
        // record is ignored.
        waits.queued(1, 10);
        waits.freed(1, 3);
        assert_eq!(waits.completed(1), Some((10, 3)));
        assert_eq!(waits.completed(1), None);
        waits.queued(7, 10);
        waits.freed(7, 3);
        assert_eq!(waits.completed(7), None);
    }

    #[test]
    fn stops_and_ended_parked_calls_are_counted_by_call() {
        let tally = StepTally::<2>::new();
        tally.stopped_between_steps(StepCall::Map);
        tally.stopped_between_steps(StepCall::Map);
        tally.stopped_between_steps(StepCall::Create);
        tally.parked_call_ended(StepCall::Commit);
        tally.parked_call_ended(StepCall::FillIn);
        let lines = lines(&tally);
        assert_eq!(
            lines[1],
            "stops-between-steps map=2 unmap=0 protect=0 fill=0 commit=0 create=1"
        );
        assert_eq!(
            lines[2],
            "parked-ended map=0 unmap=0 protect=0 fill=1 commit=1 create=0"
        );
    }
}
