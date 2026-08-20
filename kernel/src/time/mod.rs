//! DW0-F3 monotonic clock and finite-deadline foundation.
//!
//! ABI time is absolute nanoseconds. The reference x86_64 backend extends the
//! ACPI PM timer and uses a calibrated Local APIC one-shot only as the wakeup
//! source; timer objects and generic wait registration remain later F phases.

mod deadline;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live;
mod pm_timer;

#[allow(
    unused_imports,
    reason = "F3 deadline primitives are staged for F4/F8 consumers while model tests exercise them now"
)]
pub(crate) use deadline::{
    ApicOneShot, DEADLINE_QUEUE_CAPACITY, DeadlineClass, DeadlineQueue, DeadlineQueueError,
    DeadlineRegistration, apic_one_shot_for_delta, classify_deadline,
};
#[allow(
    unused_imports,
    reason = "F3 PM timer primitives are split between target service and host arithmetic tests"
)]
pub(crate) use pm_timer::{
    ACPI_PM_TIMER_HZ, MonotonicSample, PmTimerDescriptor, PmTimerError, PmTimerState, PmTimerWidth,
    ticks_to_nanoseconds,
};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unused_imports,
    reason = "F3 wake registration APIs are consumed by later wait/timer phases after the live backend is installed"
)]
pub(crate) use live::{
    DeadlineRegistrationFailure, DeadlineWakeTarget, LiveTimeError, bind_deadline_wake_target,
    initialize, monotonic_now, register_deadline,
};
#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
#[allow(
    unused_imports,
    reason = "F3 target probe result is consumed only by the selected guest evidence path"
)]
pub(crate) use live::{F3TargetProbe, calibrated_apic_timer_hz, run_target_deadline_probe};
