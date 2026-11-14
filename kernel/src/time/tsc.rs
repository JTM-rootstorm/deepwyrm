//! Invariant-TSC clock source (root `OS_STACK_ARCHITECTURE_PLAN.md` L1).
//!
//! The ACPI PM timer stays the reference: the TSC's rate is calibrated against
//! it at boot, then checked against it over a second window, and the clock
//! moves to the TSC only when CPUID reports an invariant TSC and both windows
//! agree. Anything else keeps the PM timer. A TSC read is one instruction,
//! where the PM timer is a port read of about a microsecond, and the TSC never
//! wraps, so the clock no longer needs the PM timer's wrap maintenance.
//!
//! Readings stay monotonic: a reading below the last one returns the last one.
//! An invariant TSC runs at one rate in every power state; whether the CPUs'
//! counters agree with each other is not assumed, only clamped here, and is
//! measured per CPU by L3.

use deepwyrm_abi::DW_DEADLINE_INFINITE;

const NANOS_PER_SECOND: u128 = 1_000_000_000;
/// The rates the calibration accepts; outside them the measurement is wrong.
pub(crate) const MIN_TSC_HZ: u64 = 100_000_000;
pub(crate) const MAX_TSC_HZ: u64 = 20_000_000_000;
/// How far the check window may disagree with the calibrated rate. A PM-timer
/// read costs about a microsecond at each end of a 10 ms window, about 200 ppm
/// together; ten times that is still a clock good to 0.2%.
pub(crate) const MAX_DISAGREEMENT_PPM: u64 = 2_000;
/// The PM timer needed a sample every quarter wrap; the TSC does not wrap, so
/// its maintenance deadline only bounds how long the deadline hardware may
/// stay unarmed.
pub(crate) const TSC_MAINTENANCE_NANOSECONDS: u64 = 1_000_000_000;

/// The TSC rate measured over `ns_delta` nanoseconds of the reference clock,
/// or `None` when it is implausible.
pub(crate) fn calibrate(tsc_delta: u64, ns_delta: u64) -> Option<u64> {
    if ns_delta == 0 {
        return None;
    }
    let hz = u128::from(tsc_delta).checked_mul(NANOS_PER_SECOND)? / u128::from(ns_delta);
    u64::try_from(hz)
        .ok()
        .filter(|hz| (MIN_TSC_HZ..=MAX_TSC_HZ).contains(hz))
}

/// How far a second window's measured rate is from `hz`, in parts per
/// million, or `None` when that window is itself implausible.
pub(crate) fn disagreement_ppm(hz: u64, tsc_delta: u64, ns_delta: u64) -> Option<u64> {
    let measured = calibrate(tsc_delta, ns_delta)?;
    let difference = u128::from(measured.abs_diff(hz));
    u64::try_from(difference * 1_000_000 / u128::from(hz)).ok()
}

/// Whether CPUID's extended leaf 0x8000_0007 reports an invariant TSC, given
/// the highest extended leaf and that leaf's EDX.
pub(crate) const fn reports_invariant_tsc(max_extended_leaf: u32, leaf_8000_0007_edx: u32) -> bool {
    max_extended_leaf >= 0x8000_0007 && leaf_8000_0007_edx & (1 << 8) != 0
}

/// Which source the boot cross-check chose, and what it measured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TscVerdict {
    /// The calibrated rate, when the calibration window was plausible.
    pub(crate) hz: Option<u64>,
    /// The check window's disagreement, when both windows were plausible.
    pub(crate) disagreement_ppm: Option<u64>,
    pub(crate) invariant: bool,
}

impl TscVerdict {
    pub(crate) fn new(invariant: bool, calibration: (u64, u64), check: (u64, u64)) -> Self {
        let hz = calibrate(calibration.0, calibration.1);
        let disagreement_ppm = hz.and_then(|hz| disagreement_ppm(hz, check.0, check.1));
        Self {
            hz,
            disagreement_ppm,
            invariant,
        }
    }

    /// The rate to run the clock on, or `None` to stay on the PM timer.
    pub(crate) fn selected_hz(self) -> Option<u64> {
        match (self.invariant, self.hz, self.disagreement_ppm) {
            (true, Some(hz), Some(ppm)) if ppm <= MAX_DISAGREEMENT_PPM => Some(hz),
            _ => None,
        }
    }
}

/// Converts TSC readings to the monotonic clock, continuing from the PM-timer
/// reading taken beside `base_tsc`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TscClock {
    base_tsc: u64,
    base_ns: u64,
    hz: u64,
    last_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TscClockError {
    /// The clock would reach the infinite-deadline sentinel.
    NanosecondOverflow,
}

impl TscClock {
    pub(crate) const fn new(base_tsc: u64, base_ns: u64, hz: u64) -> Self {
        Self {
            base_tsc,
            base_ns,
            hz,
            last_ns: base_ns,
        }
    }

    /// Nanoseconds at TSC reading `tsc`, never below an earlier result.
    pub(crate) fn sample(&mut self, tsc: u64) -> Result<u64, TscClockError> {
        let elapsed = u128::from(tsc.saturating_sub(self.base_tsc));
        let since = elapsed * NANOS_PER_SECOND / u128::from(self.hz);
        let now = u64::try_from(since)
            .ok()
            .and_then(|since| self.base_ns.checked_add(since))
            .filter(|now| *now < DW_DEADLINE_INFINITE.0)
            .ok_or(TscClockError::NanosecondOverflow)?;
        self.last_ns = self.last_ns.max(now);
        Ok(self.last_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_measures_the_rate_and_refuses_implausible_ones() {
        // 30 million ticks in 10 ms: 3 GHz.
        assert_eq!(calibrate(30_000_000, 10_000_000), Some(3_000_000_000));
        assert_eq!(calibrate(30_000_000, 0), None);
        // 10 MHz and 40 GHz are not TSC rates.
        assert_eq!(calibrate(100_000, 10_000_000), None);
        assert_eq!(calibrate(400_000_000, 10_000_000), None);
        assert_eq!(calibrate(u64::MAX, 1), None);
    }

    #[test]
    fn only_an_invariant_tsc_whose_windows_agree_is_selected() {
        let agree = TscVerdict::new(true, (30_000_000, 10_000_000), (30_003_000, 10_000_000));
        assert_eq!(agree.disagreement_ppm, Some(100));
        assert_eq!(agree.selected_hz(), Some(3_000_000_000));

        let variant = TscVerdict {
            invariant: false,
            ..agree
        };
        assert_eq!(variant.selected_hz(), None);

        let drifting = TscVerdict::new(true, (30_000_000, 10_000_000), (30_090_000, 10_000_000));
        assert_eq!(drifting.disagreement_ppm, Some(3_000));
        assert_eq!(drifting.selected_hz(), None);

        let broken_check = TscVerdict::new(true, (30_000_000, 10_000_000), (0, 10_000_000));
        assert_eq!(broken_check.disagreement_ppm, None);
        assert_eq!(broken_check.selected_hz(), None);

        let broken_calibration = TscVerdict::new(true, (0, 10_000_000), (30_000_000, 10_000_000));
        assert_eq!(broken_calibration.hz, None);
        assert_eq!(broken_calibration.selected_hz(), None);
    }

    #[test]
    fn cpuid_reports_an_invariant_tsc_only_from_a_present_leaf_with_bit_8() {
        assert!(reports_invariant_tsc(0x8000_0008, 1 << 8));
        assert!(!reports_invariant_tsc(0x8000_0008, !(1 << 8)));
        assert!(!reports_invariant_tsc(0x8000_0006, 1 << 8));
    }

    #[test]
    fn the_clock_continues_from_its_base_and_never_runs_backwards() {
        let mut clock = TscClock::new(1_000, 5_000_000, 1_000_000_000);
        assert_eq!(clock.sample(1_000), Ok(5_000_000));
        assert_eq!(clock.sample(2_500), Ok(5_001_500));
        // Another CPU's counter behind this one's: the clock holds.
        assert_eq!(clock.sample(2_000), Ok(5_001_500));
        assert_eq!(clock.sample(500), Ok(5_001_500));
        assert_eq!(clock.sample(3_000), Ok(5_002_000));
    }

    #[test]
    fn the_clock_refuses_to_reach_the_infinite_sentinel() {
        let mut clock = TscClock::new(0, DW_DEADLINE_INFINITE.0 - 10, 1_000_000_000);
        assert_eq!(clock.sample(9), Ok(DW_DEADLINE_INFINITE.0 - 1));
        assert_eq!(clock.sample(10), Err(TscClockError::NanosecondOverflow));
        // 2^64 ticks at the slowest rate is past what nanoseconds can hold.
        let mut slow = TscClock::new(0, 0, MIN_TSC_HZ);
        assert_eq!(
            slow.sample(u64::MAX),
            Err(TscClockError::NanosecondOverflow)
        );
    }
}
