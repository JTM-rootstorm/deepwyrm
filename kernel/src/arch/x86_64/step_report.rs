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
//!   parked (§10.8 item 5).
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
}

const CALLS: usize = 6;
const NAMES: [&str; CALLS] = ["map", "unmap", "protect", "fill", "commit", "create"];
/// The low bits of the packed longest step hold the call.
const CALL_BITS: u32 = 3;

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
}

impl<const CPUS: usize> StepTally<CPUS> {
    pub(crate) const fn new() -> Self {
        Self {
            started: [const { AtomicU64::new(0) }; CPUS],
            longest: AtomicU64::new(0),
            stops: [const { AtomicU64::new(0) }; CALLS],
            ended: [const { AtomicU64::new(0) }; CALLS],
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

    /// Writes the three report lines' bodies, one call each.
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
        let [map, unmap, protect, fill, commit, create] = counts(&self.stops);
        line(format_args!(
            "stops-between-steps map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create}"
        ));
        let [map, unmap, protect, fill, commit, create] = counts(&self.ended);
        line(format_args!(
            "parked-ended map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create}"
        ));
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live {
    use super::{StepCall, StepTally};
    use crate::cpu::CPU_CAPACITY;

    static TALLY: StepTally<CPU_CAPACITY> = StepTally::new();

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
        bytes: [u8; 112],
        len: usize,
    }

    impl Line {
        const fn new() -> Self {
            Self {
                bytes: [0; 112],
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
pub(crate) use live::{after_safe_point, at_safe_point, parked_call_ended, report, step_began};

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
            ]
        );
    }

    #[test]
    fn the_longest_step_on_any_cpu_is_kept_with_its_call() {
        let tally = StepTally::<2>::new();
        tally.step_began(0, 1_000);
        tally.step_began(1, 0);
        tally.step_ended(0, StepCall::Map, 5_001_000);
        tally.step_ended(1, StepCall::Create, 9_000_000);
        assert_eq!(tally.longest(), Some((9_000_000, "create")));
        // A shorter step later changes nothing.
        tally.step_began(0, 10_000_000);
        tally.step_ended(0, StepCall::Commit, 10_000_500);
        assert_eq!(tally.longest(), Some((9_000_000, "create")));
        assert_eq!(lines(&tally)[0], "longest-step-us=9000 call=create");
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
