//! DW0-F3 monotonic clock and finite-deadline foundation.
//!
//! ABI time is absolute nanoseconds. The reference x86_64 backend extends the
//! ACPI PM timer and uses a calibrated Local APIC one-shot only as the wakeup
//! source; timer objects and generic wait registration remain later F phases.

mod arbiter;
mod deadline;
mod init_state;
#[allow(
    unused_imports,
    reason = "F8 Timer primitives are staged together before syscall/wait consumers are wired"
)]
pub(crate) use timer::{
    TimerAuthority, TimerCreateError, TimerDeadlineAuthority, TimerDeadlineError, TimerError,
    TimerExpiryToken, TimerKey, TimerPayloadBinding, TimerPayloadCleanup, TimerWaitFailure,
    TimerWaitOutcome, complete_timer_finalization,
};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live;
mod pm_timer;
mod service;
mod timer;

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
    reason = "target-only live time initialization consumes this state model"
)]
pub(crate) use init_state::TimeInitState;
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
    DeadlineRegistrationFailure, DeadlineWakeTarget, LiveTimeError, LiveTimerDeadlineAuthority,
    TimerExpiryTarget, ap_scheduler_timer_is_masked, arm_scheduler_quantum,
    bind_deadline_wake_target, bind_timer_expiry_target, bsp_local_apic_identity,
    busy_wait_nanoseconds, cancel_deadline, cancel_scheduler_quantum, initialize,
    initialize_ap_local_apic, monotonic_now, q35_bsp_vector_is_clear, q35_current_cpu_is_bsp,
    register_deadline, request_q35_bsp_retirement_check, send_bsp_ipi,
    service_current_rendezvous_latch, service_current_scheduler_quantum_deadline,
    timer_service_is_healthy,
};
#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
#[allow(
    unused_imports,
    reason = "F3 target probe result is consumed only by the selected guest evidence path"
)]
pub(crate) use live::{
    F3TargetProbe, F8TargetTimerProbe, calibrated_apic_timer_hz, run_target_deadline_probe,
    run_target_timer_probe,
};
