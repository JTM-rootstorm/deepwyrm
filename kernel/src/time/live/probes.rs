//! Target-only F3/F8 deadline and Timer evidence probes.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::task::BlockWakeKey;
use crate::time::{
    PmTimerWidth, TimerAuthority, TimerExpiryToken, complete_timer_finalization,
    ticks_to_nanoseconds,
};

use super::{
    DeadlineWakeTarget, INITIALIZED, INITIALIZING, LiveTimeError, LiveTimerDeadlineAuthority,
    TimerExpiryTarget, UNINITIALIZED, bind_deadline_wake_target, bind_timer_expiry_target,
    live_state, monotonic_now, register_deadline,
};

pub(crate) fn calibrated_apic_timer_hz() -> Option<u64> {
    live_state().map(|state| state.lock().apic_timer_hz)
}

struct ProbeWakeTarget {
    scheduler: crate::task::CooperativeScheduler<1>,
    failed: AtomicU8,
}

impl DeadlineWakeTarget for ProbeWakeTarget {
    fn wake_deadline(&self, key: BlockWakeKey) {
        if self.scheduler.wake(key).is_err() {
            self.failed.store(1, Ordering::Release);
        }
    }
}

struct ProbeStorage(UnsafeCell<MaybeUninit<ProbeWakeTarget>>);

impl ProbeStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "the one-shot F3 target probe publishes stationary scheduler state before IRQ delivery"
)]
unsafe impl Sync for ProbeStorage {}

static PROBE_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static PROBE_STORAGE: ProbeStorage = ProbeStorage::new();

fn probe_target() -> Result<&'static ProbeWakeTarget, LiveTimeError> {
    if PROBE_STATE
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(LiveTimeError::AlreadyInitialized);
    }
    #[allow(
        unsafe_code,
        reason = "the target probe has one-shot BSP ownership before the static scheduler becomes interrupt-visible"
    )]
    unsafe {
        (*PROBE_STORAGE.0.get()).write(ProbeWakeTarget {
            scheduler: crate::task::CooperativeScheduler::new(),
            failed: AtomicU8::new(0),
        });
    }
    PROBE_STATE.store(INITIALIZED, Ordering::Release);
    #[allow(
        unsafe_code,
        reason = "the published probe target remains stationary for the rest of the test boot"
    )]
    Ok(unsafe { &*(*PROBE_STORAGE.0.get()).as_ptr() })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct F3TargetProbe {
    pub(crate) before_ns: u64,
    pub(crate) after_ns: u64,
    pub(crate) apic_timer_hz: u64,
}

pub(crate) fn run_target_deadline_probe() -> Result<F3TargetProbe, LiveTimeError> {
    let target = probe_target()?;
    bind_deadline_wake_target(target)?;

    let mut registry = crate::object::ObjectRegistry::<2>::new();
    let creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD)
        .map_err(|_| LiveTimeError::Deadline)?;
    let thread = crate::task::ThreadKey::from_object_id(creation.id());
    registry
        .cancel_creation(creation)
        .map_err(|_| LiveTimeError::Deadline)?;
    let reservation = target
        .scheduler
        .reserve(thread)
        .map_err(|_| LiveTimeError::Deadline)?;
    target
        .scheduler
        .commit(reservation)
        .map_err(|_| LiveTimeError::Deadline)?;
    if target
        .scheduler
        .schedule_next()
        .map_err(|_| LiveTimeError::Deadline)?
        .current
        != Some(thread)
    {
        return Err(LiveTimeError::Deadline);
    }
    let (blocked, decision) = target
        .scheduler
        .block_current(thread)
        .map_err(|_| LiveTimeError::Deadline)?;
    if decision.current.is_some() {
        return Err(LiveTimeError::Deadline);
    }

    let before_ns = monotonic_now()?;
    let deadline_ns = before_ns
        .checked_add(20_000_000)
        .filter(|value| *value < deepwyrm_abi::DW_DEADLINE_INFINITE.0)
        .ok_or(LiveTimeError::Deadline)?;
    let _registration = match register_deadline(deadline_ns, blocked.into_wake_key()) {
        Ok(registration) => registration,
        Err(failure) => {
            let (error, wake) = failure.into_parts();
            let _ = target.scheduler.wake(wake);
            return Err(error);
        }
    };

    for _ in 0..8 {
        if target.scheduler.state(thread) == Some(crate::task::SchedulerThreadState::Runnable) {
            break;
        }
        wait_for_interrupt();
    }
    if target.failed.load(Ordering::Acquire) != 0
        || target.scheduler.state(thread) != Some(crate::task::SchedulerThreadState::Runnable)
    {
        return Err(LiveTimeError::Deadline);
    }
    let deadline_wake_ns = monotonic_now()?;
    if deadline_wake_ns < deadline_ns {
        return Err(LiveTimeError::Deadline);
    }

    // DB-01 regression: remain genuinely idle for at least two complete 24-bit
    // PM-timer wrap intervals. Quarter-wrap maintenance IRQs must keep extending
    // the same monotonic domain without clock_get/user-deadline traffic driving it.
    let long_idle_ns = ticks_to_nanoseconds(PmTimerWidth::Bits24.modulus())
        .map_err(|_| LiveTimeError::Clock)?
        .checked_mul(2)
        .ok_or(LiveTimeError::Clock)?;
    let long_idle_target = deadline_wake_ns
        .checked_add(long_idle_ns)
        .filter(|value| *value < deepwyrm_abi::DW_DEADLINE_INFINITE.0)
        .ok_or(LiveTimeError::Clock)?;
    let mut after_ns = deadline_wake_ns;
    for _ in 0..32 {
        if after_ns >= long_idle_target {
            break;
        }
        wait_for_interrupt();
        after_ns = monotonic_now()?;
    }
    if after_ns < long_idle_target {
        return Err(LiveTimeError::Clock);
    }

    Ok(F3TargetProbe {
        before_ns,
        after_ns,
        apic_timer_hz: calibrated_apic_timer_hz().ok_or(LiveTimeError::Calibration)?,
    })
}

struct TimerProbeTarget {
    timers: TimerAuthority<1>,
    waits: crate::wait::WaitRegistry<1>,
    fired: AtomicU8,
    failed: AtomicU8,
}

impl TimerExpiryTarget for TimerProbeTarget {
    fn expire_timer(&self, token: TimerExpiryToken) {
        match self.timers.expire(token, &self.waits) {
            Ok(wakes) => {
                let (wake_intents, pins) = wakes.into_parts();
                if wake_intents.into_iter().flatten().next().is_some()
                    || pins.into_iter().flatten().next().is_some()
                {
                    self.failed.store(1, Ordering::Release);
                    return;
                }
                self.fired.store(1, Ordering::Release);
            }
            Err(_) => self.failed.store(1, Ordering::Release),
        }
    }
}

struct TimerProbeStorage(UnsafeCell<MaybeUninit<TimerProbeTarget>>);

impl TimerProbeStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "the one-shot F8 target probe publishes stationary Timer/wait state before IRQ delivery"
)]
unsafe impl Sync for TimerProbeStorage {}

static TIMER_PROBE_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static TIMER_PROBE_STORAGE: TimerProbeStorage = TimerProbeStorage::new();

fn timer_probe_target() -> Result<&'static TimerProbeTarget, LiveTimeError> {
    if TIMER_PROBE_STATE
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(LiveTimeError::AlreadyInitialized);
    }
    #[allow(
        unsafe_code,
        reason = "the target probe has one-shot BSP ownership before the Timer authority becomes interrupt-visible"
    )]
    unsafe {
        (*TIMER_PROBE_STORAGE.0.get()).write(TimerProbeTarget {
            timers: TimerAuthority::new(),
            waits: crate::wait::WaitRegistry::new(),
            fired: AtomicU8::new(0),
            failed: AtomicU8::new(0),
        });
    }
    TIMER_PROBE_STATE.store(INITIALIZED, Ordering::Release);
    #[allow(
        unsafe_code,
        reason = "the published F8 Timer probe target remains stationary for the rest of the test boot"
    )]
    Ok(unsafe { &*(*TIMER_PROBE_STORAGE.0.get()).as_ptr() })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct F8TargetTimerProbe {
    pub(crate) before_ns: u64,
    pub(crate) deadline_ns: u64,
    pub(crate) after_ns: u64,
}

pub(crate) fn run_target_timer_probe() -> Result<F8TargetTimerProbe, LiveTimeError> {
    let target = timer_probe_target()?;
    bind_timer_expiry_target(target)?;

    let mut registry = crate::object::ObjectRegistry::<1>::new();
    let (key, handle) = target
        .timers
        .create_timer(&mut registry)
        .map_err(|_| LiveTimeError::Deadline)?;
    let before_ns = monotonic_now()?;
    let deadline_ns = before_ns
        .checked_add(20_000_000)
        .filter(|deadline| *deadline < deepwyrm_abi::DW_DEADLINE_INFINITE.0)
        .ok_or(LiveTimeError::Deadline)?;
    let mut deadlines = LiveTimerDeadlineAuthority;
    let wakes = target
        .timers
        .set(
            key,
            deepwyrm_abi::DwDeadline(deadline_ns),
            &mut deadlines,
            &target.waits,
        )
        .map_err(|_| LiveTimeError::Deadline)?;
    let (wake_intents, pins) = wakes.into_parts();
    if wake_intents.into_iter().flatten().next().is_some()
        || pins.into_iter().flatten().next().is_some()
    {
        return Err(LiveTimeError::Deadline);
    }

    for _ in 0..8 {
        if target.fired.load(Ordering::Acquire) != 0 {
            break;
        }
        wait_for_interrupt();
    }
    let after_ns = monotonic_now()?;
    if target.failed.load(Ordering::Acquire) != 0
        || target.fired.load(Ordering::Acquire) == 0
        || after_ns < deadline_ns
        || target
            .timers
            .current_signals(key)
            .map_err(|_| LiveTimeError::Deadline)?
            != deepwyrm_abi::DW_SIGNAL_SIGNALED
    {
        return Err(LiveTimeError::Deadline);
    }

    let final_release = registry
        .release_handle(handle)
        .map_err(|_| LiveTimeError::Deadline)?
        .ok_or(LiveTimeError::Deadline)?;
    let finalization = target
        .timers
        .take_finalization(final_release, &mut deadlines)
        .map_err(|_| LiveTimeError::Deadline)?;
    complete_timer_finalization(&mut registry, finalization);

    Ok(F8TargetTimerProbe {
        before_ns,
        deadline_ns,
        after_ns,
    })
}

#[allow(
    unsafe_code,
    reason = "STI;HLT is the F3 target proof's race-free sleeping wait; CLI restores the caller's IF-clear test state"
)]
fn wait_for_interrupt() {
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}
