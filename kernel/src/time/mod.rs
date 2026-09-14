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
    initialize_ap_local_apic, monotonic_now, register_deadline, send_bsp_ipi,
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
#[cfg(all(target_os = "none", target_arch = "x86_64", deepwyrm_dw1e_platform))]
#[allow(
    unused_imports,
    reason = "DW1-E q35 runtime exports exist only in the selected platform product"
)]
pub(crate) use live::{
    complete_q35_bsp_retirement_check, notify_q35_bsp_retirement_check,
    pending_q35_bsp_retirement_check, publish_q35_bsp_retirement_check, q35_bsp_vector_is_clear,
    q35_current_cpu_is_bsp, request_q35_bsp_terminal_check,
};

/// Source contract for the one wake-delivery seam no host test can execute.
///
/// `live.rs` compiles only for the bare x86-64 target, so nothing here runs the
/// timer interrupt. What this gate can do is hold the ordering the interrupt
/// depends on: a wake resolved inside it stages a runnable-work notification,
/// and only `drain_runnable_work_notifications` turns that staging into the e1
/// IPI a halted CPU needs. The interrupt has no syscall or idle-poll return to
/// inherit a drain from, so it must perform its own, after the handlers. Reset
/// card R1C's 300-second stall was exactly this drain being absent.
#[cfg(test)]
mod live_wake_delivery_contract {
    const DISPATCH: &str = "pub(crate) extern \"sysv64\" fn dw_x86_64_timer_interrupt_dispatch()";
    const DRAIN: &str = "crate::task::drain_runnable_work_notifications();";

    fn dispatch_body() -> &'static str {
        let source = include_str!("live.rs");
        let start = source
            .find(DISPATCH)
            .expect("the live timer interrupt dispatch is still named as the assembly entry calls it");
        let body = &source[start..];
        let end = body
            .find("\nfn read_pm_timer(")
            .expect("the timer dispatch is still followed by read_pm_timer");
        &body[..end]
    }

    #[test]
    fn the_timer_interrupt_publishes_the_wakes_it_stages() {
        let body = dispatch_body();
        let drain = body
            .find(DRAIN)
            .expect("the timer interrupt must drain the runnable-work notifications it stages");
        assert_eq!(
            body.matches(DRAIN).count(),
            1,
            "one drain at the end of the dispatch covers every staging path inside it"
        );
        for handler in [
            "(binding.handler)(binding.context, key);",
            "(binding.handler)(binding.context, token);",
        ] {
            let invocation = body.split(handler).next().unwrap().len();
            assert!(
                invocation < drain,
                "the drain must follow {handler}, not precede it"
            );
        }
        let quantum = body
            .find("publish_current_quantum_expiry(ticket)")
            .expect("the dispatch still publishes a due scheduler quantum");
        assert!(
            quantum < drain,
            "the drain belongs at the end of the dispatch, after quantum publication"
        );
    }

    #[test]
    fn the_deadline_wake_target_does_not_drain_for_the_interrupt() {
        // The wake target runs inside the interrupt with the scheduler and
        // blocked-operation locks live. If a drain is ever added there instead,
        // this gate fails rather than letting an IPI be sent under those locks.
        let source = include_str!("live.rs");
        let target = source
            .split("pub(crate) trait DeadlineWakeTarget")
            .nth(1)
            .expect("the deadline wake-target trait still declares the interrupt callback");
        let trampoline = target
            .split("fn wake_binding()")
            .next()
            .expect("the wake trampoline still precedes the binding accessor");
        assert!(
            !trampoline.contains(DRAIN),
            "notification delivery belongs to the dispatch, outside the handler's locks"
        );
    }
}
