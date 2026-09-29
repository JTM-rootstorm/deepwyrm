//! Stationary runtime identity primitives for the serialized I1 carrier join.
//!
//! `RuntimePhaseReservation` carries a Thread and Process-root binding
//! generation across guard-free syscall work so the commit can revalidate
//! them. `StationaryGuardDepth` backs the primordial carrier's guard-free
//! boundary check; nothing raises its depth any more, and S2K-3 replaces it
//! with a compile-time token. The staged `RuntimeCore`/`PagingAuthority`
//! authorities were never instantiated outside their own tests; the S2K
//! design (`Plans/DW1_S2K_RUNTIME_AUTHORITY_DESIGN.md` §4.1) replaced them and
//! S2K-1 deleted them.

#![allow(
    dead_code,
    reason = "both types are consumed by target-only runtimes; the host build sees only their tests"
)]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::cpu::CpuIndex;
use crate::task::ThreadKey;

/// Per-CPU depth that guard-free boundaries assert is zero.
///
/// This is a contract aid, not a scheduler lock. Only the deleted
/// `RuntimeCore`/`PagingAuthority` guards ever raised it, so
/// [`StationaryGuardDepth::assert_clear_on`] cannot fail (S2K design §2.4
/// finding 1). S2K-3 removes it together with the primordial carrier's no-op
/// check, in favour of a compile-time guard-free token.
pub(crate) struct StationaryGuardDepth {
    state: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

impl StationaryGuardDepth {
    pub(crate) const fn new() -> Self {
        Self {
            state: [const { AtomicU8::new(0) }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
        }
    }

    fn slot(&self, cpu: CpuIndex) -> &AtomicU8 {
        self.state
            .get(cpu.index())
            .unwrap_or_else(|| panic!("CPU {} exceeds stationary guard slots", cpu.index()))
    }

    pub(crate) fn assert_clear_on(&self, cpu: CpuIndex) {
        assert_eq!(
            self.slot(cpu).load(Ordering::Acquire),
            0,
            "stationary authority guard crossed a forbidden runtime boundary on CPU {}",
            cpu.index()
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimePhaseError {
    ZeroRootGeneration,
    IdentityDrift,
}

/// Move-only identity witness carried across guard-free syscall work.
///
/// It contains no guard and borrows no stationary authority.  The later
/// prepare/commit adapters use it to prove that a usercopy/paging phase did
/// not resume under a different Thread or Process-root binding generation.
#[must_use = "a runtime phase must be revalidated or explicitly aborted"]
pub(crate) struct RuntimePhaseReservation {
    thread: ThreadKey,
    root_generation: u64,
    // A reservation is tied to the carrier that prepared it.  It is an
    // identity witness, not a transferable stationary-runtime capability.
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl RuntimePhaseReservation {
    pub(crate) fn new(thread: ThreadKey, root_generation: u64) -> Result<Self, RuntimePhaseError> {
        if root_generation == 0 {
            return Err(RuntimePhaseError::ZeroRootGeneration);
        }
        Ok(Self {
            thread,
            root_generation,
            _not_send_or_sync: PhantomData,
        })
    }

    pub(crate) fn revalidate(
        self,
        thread: ThreadKey,
        root_generation: u64,
    ) -> Result<(), RuntimePhaseError> {
        if self.thread != thread || self.root_generation != root_generation {
            return Err(RuntimePhaseError::IdentityDrift);
        }
        Ok(())
    }

    pub(crate) fn abort(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use crate::task::TaskAuthority;

    fn thread_fixture() -> ThreadKey {
        let mut registry = ObjectRegistry::<4>::new();
        let mut tasks = TaskAuthority::<1, 1, 2, 2>::new();
        let (_group, owner) = tasks.create_root_group(&mut registry).unwrap();
        let (_process, process) = tasks.create_process(&mut registry, &owner).unwrap();
        let process = registry.retain_internal_from_handle(&process).unwrap();
        let (thread, _handle) = tasks.create_thread(&mut registry, &process).unwrap();
        thread
    }

    #[test]
    fn phase_reservation_survives_a_guard_free_pause_but_rejects_root_drift() {
        static DEPTH: StationaryGuardDepth = StationaryGuardDepth::new();
        let thread = thread_fixture();
        let phase = RuntimePhaseReservation::new(thread, 7).unwrap();
        // Models usercopy/paging work between short core phases.
        DEPTH.assert_clear_on(CpuIndex::BOOTSTRAP);
        assert_eq!(
            phase.revalidate(thread, 8),
            Err(RuntimePhaseError::IdentityDrift)
        );
    }
}
