//! Minimal `crate::debug` for the compile-fail fixtures that build
//! `task/scheduler.rs` as a standalone crate.
//!
//! The scheduler mirrors its own facts into the reset-card-R1 liveness snapshot
//! (`mirror_liveness`, `wake_on`), which reaches `crate::debug::liveness`. A
//! fixture crate has no `debug` module, so every one of those calls raised
//! `E0433` and became the *first* error the harness saw -- masking the
//! move-only contract each fixture actually exists to prove.
//!
//! This carries no behaviour on purpose. The fixtures never run; they only have
//! to compile far enough for the expected `E0277` to be the first error.
pub(crate) mod liveness {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub(crate) enum LivenessEvent {
        Dispatched = 6,
        Blocked = 7,
        Woken = 8,
        QuantumArmed = 9,
    }

    pub(crate) fn publish_scheduler(
        _cpu: crate::cpu::CpuIndex,
        _execution_generation: u64,
        _runnable_here: u32,
        _queue_len: u32,
        _reschedule_pending: bool,
        _quantum_armed: bool,
        _event: LivenessEvent,
    ) {
    }

    pub(crate) fn publish_wake_target(_requester: crate::cpu::CpuIndex, _target: crate::cpu::CpuIndex) {}
}
