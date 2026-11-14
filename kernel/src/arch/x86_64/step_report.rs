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
//!   how long one dead job's memory waits to be freed.
//!
//! Every count is a relaxed atomic. Nothing here decides anything; it only
//! reports.

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
        }
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
    use super::{StepCall, StepTally};
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

    fn now() -> Option<u64> {
        crate::time::monotonic_now().ok()
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
        TALLY.write_lines(|arguments| {
            let mut line = Line::new();
            let _ = core::fmt::Write::write_fmt(&mut line, arguments);
            if let Ok(message) = core::str::from_utf8(line.text()) {
                let _ = crate::debug::emit_early_record(
                    crate::debug::DiagnosticLevel::Info,
                    "steps",
                    message,
                );
            }
        });
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
    after_safe_point, allow_teardown_step, at_safe_point, owed, parked_call_ended, report,
    step_began, take_teardown_step, timed, timed_nested,
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
