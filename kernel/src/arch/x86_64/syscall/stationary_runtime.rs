//! Stationary runtime identity primitives for the serialized I1 carrier join.
//!
//! `RuntimePhaseReservation` carries a Thread and Process-root binding
//! generation across guard-free syscall work so the commit can revalidate
//! them. The staged `RuntimeCore`/`PagingAuthority` authorities were never
//! instantiated outside their own tests, so their `StationaryGuardDepth` never
//! rose and its guard-free check could never fire. The S2K design
//! (`Plans/DW1_S2K_RUNTIME_AUTHORITY_DESIGN.md` §4.1) replaced them: S2K-1
//! deleted the authorities, and S2K-3 replaced the depth check with the
//! compile-time `GuardFree` token.

#![allow(
    dead_code,
    reason = "the reservation is consumed by target-only runtimes; the host build sees only its test"
)]

use core::marker::PhantomData;

use crate::task::ThreadKey;

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
        let thread = thread_fixture();
        let phase = RuntimePhaseReservation::new(thread, 7).unwrap();
        // Usercopy/paging work between short core phases would run here.
        assert_eq!(
            phase.revalidate(thread, 8),
            Err(RuntimePhaseError::IdentityDrift)
        );
    }
}
