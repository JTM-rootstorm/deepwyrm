//! Target-independent ownership model for per-CPU native-runtime carriers.
//!
//! Live x86_64 entry stores the erased carrier pointer and its monomorphized
//! callbacks separately. This model owns the one-shot identity claims that
//! make those pointers CPU-local: one slot has one carrier, and one carrier
//! address can never be published in two slots.

use crate::sync::SpinMutex;
use core::sync::atomic::{AtomicU8, Ordering};

const CARRIER_UNBOUND: u8 = 0;
const CARRIER_PARKED: u8 = 1;
const CARRIER_EXECUTING: u8 = 2;

/// The irreversible publication state for one fixed CPU carrier.
///
/// Binding a carrier only makes its identity visible to the CPU-local entry
/// machinery.  It does not authorize that CPU to execute shared scheduler or
/// userspace work.  A separate Release/Acquire transition is required after
/// the complete runtime join has published every dependent authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeCarrierLifecycle {
    Unbound,
    Parked,
    Executing,
}

pub(super) struct RuntimeCarrierLifecycles<const SLOTS: usize> {
    states: [AtomicU8; SLOTS],
}

impl<const SLOTS: usize> RuntimeCarrierLifecycles<SLOTS> {
    pub(super) const fn new() -> Self {
        Self {
            states: [const { AtomicU8::new(CARRIER_UNBOUND) }; SLOTS],
        }
    }

    pub(super) fn bind_parked(&self, cpu_index: usize) -> Result<(), RuntimeCarrierClaimError> {
        let state = self
            .states
            .get(cpu_index)
            .ok_or(RuntimeCarrierClaimError::InvalidSlot)?;
        state
            .compare_exchange(
                CARRIER_UNBOUND,
                CARRIER_PARKED,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| RuntimeCarrierClaimError::SlotAlreadyClaimed)
    }

    pub(super) fn release(&self, cpu_index: usize) -> Result<(), RuntimeCarrierClaimError> {
        let state = self
            .states
            .get(cpu_index)
            .ok_or(RuntimeCarrierClaimError::InvalidSlot)?;
        state
            .compare_exchange(
                CARRIER_PARKED,
                CARRIER_EXECUTING,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| RuntimeCarrierClaimError::SlotAlreadyClaimed)
    }

    pub(super) fn lifecycle(&self, cpu_index: usize) -> Option<RuntimeCarrierLifecycle> {
        match self.states.get(cpu_index)?.load(Ordering::Acquire) {
            CARRIER_UNBOUND => Some(RuntimeCarrierLifecycle::Unbound),
            CARRIER_PARKED => Some(RuntimeCarrierLifecycle::Parked),
            CARRIER_EXECUTING => Some(RuntimeCarrierLifecycle::Executing),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeCarrierClaimError {
    InvalidSlot,
    NullContext,
    SlotAlreadyClaimed,
    ContextAlreadyClaimed,
}

pub(super) struct RuntimeCarrierClaims<const SLOTS: usize> {
    // Publication is one-shot and never occurs on syscall dispatch. This
    // bounded lock therefore cannot span usercopy, blocking, a context switch,
    // terminal handoff, or any runtime callback.
    owners: SpinMutex<[usize; SLOTS]>,
}

impl<const SLOTS: usize> RuntimeCarrierClaims<SLOTS> {
    pub(super) const fn new() -> Self {
        Self {
            owners: SpinMutex::new([0; SLOTS]),
        }
    }

    pub(super) fn claim(
        &self,
        cpu_index: usize,
        context: *mut (),
    ) -> Result<(), RuntimeCarrierClaimError> {
        if context.is_null() {
            return Err(RuntimeCarrierClaimError::NullContext);
        }
        let address = context.addr();
        let mut owners = self.owners.lock();
        let Some(owner) = owners.get(cpu_index) else {
            return Err(RuntimeCarrierClaimError::InvalidSlot);
        };
        if *owner != 0 {
            return Err(RuntimeCarrierClaimError::SlotAlreadyClaimed);
        }
        if owners.contains(&address) {
            return Err(RuntimeCarrierClaimError::ContextAlreadyClaimed);
        }
        owners[cpu_index] = address;
        Ok(())
    }

    #[cfg(test)]
    fn owner(&self, cpu_index: usize) -> Option<usize> {
        self.owners
            .lock()
            .get(cpu_index)
            .copied()
            .filter(|owner| *owner != 0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    #[test]
    fn one_carrier_address_cannot_be_claimed_by_two_cpu_slots() {
        let claims = Arc::new(RuntimeCarrierClaims::<2>::new());
        let barrier = Arc::new(Barrier::new(3));
        let mut carrier = 0_u64;
        let address = (&mut carrier as *mut u64).cast::<()>().addr();
        let workers: std::vec::Vec<_> = (0..2)
            .map(|cpu_index| {
                let claims = Arc::clone(&claims);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    claims.claim(cpu_index, core::ptr::with_exposed_provenance_mut(address))
                })
            })
            .collect();
        barrier.wait();

        let results: std::vec::Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("claim worker completes"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    **result == Err(RuntimeCarrierClaimError::ContextAlreadyClaimed)
                })
                .count(),
            1
        );
    }

    #[test]
    fn distinct_cpu_slots_accept_only_distinct_carriers() {
        let claims = RuntimeCarrierClaims::<2>::new();
        let mut carrier0 = 0_u64;
        let mut carrier1 = 0_u64;
        let context0 = (&mut carrier0 as *mut u64).cast::<()>();
        let context1 = (&mut carrier1 as *mut u64).cast::<()>();

        assert_eq!(claims.claim(0, context0), Ok(()));
        assert_eq!(claims.claim(1, context1), Ok(()));
        assert_eq!(claims.owner(0), Some(context0.addr()));
        assert_eq!(claims.owner(1), Some(context1.addr()));
        assert_eq!(
            claims.claim(0, context1),
            Err(RuntimeCarrierClaimError::SlotAlreadyClaimed)
        );
    }

    #[test]
    fn invalid_or_null_publication_fails_closed() {
        let claims = RuntimeCarrierClaims::<1>::new();
        let mut carrier = 0_u64;
        assert_eq!(
            claims.claim(1, (&mut carrier as *mut u64).cast()),
            Err(RuntimeCarrierClaimError::InvalidSlot)
        );
        assert_eq!(
            claims.claim(0, core::ptr::null_mut()),
            Err(RuntimeCarrierClaimError::NullContext)
        );
    }

    #[test]
    fn bound_carrier_stays_parked_until_the_single_release_transition() {
        let lifecycle = RuntimeCarrierLifecycles::<2>::new();
        assert_eq!(
            lifecycle.lifecycle(0),
            Some(RuntimeCarrierLifecycle::Unbound)
        );
        assert_eq!(lifecycle.bind_parked(0), Ok(()));
        assert_eq!(
            lifecycle.lifecycle(0),
            Some(RuntimeCarrierLifecycle::Parked)
        );
        assert_eq!(lifecycle.release(0), Ok(()));
        assert_eq!(
            lifecycle.lifecycle(0),
            Some(RuntimeCarrierLifecycle::Executing)
        );
        assert_eq!(
            lifecycle.release(0),
            Err(RuntimeCarrierClaimError::SlotAlreadyClaimed)
        );
        assert_eq!(
            lifecycle.lifecycle(1),
            Some(RuntimeCarrierLifecycle::Unbound)
        );
    }

    #[test]
    fn two_cpu_slots_release_independent_dispatch_gates() {
        let claims = RuntimeCarrierClaims::<2>::new();
        let lifecycle = RuntimeCarrierLifecycles::<2>::new();
        let mut carrier0 = 0_u64;
        let mut carrier1 = 0_u64;

        assert_eq!(claims.claim(0, (&mut carrier0 as *mut u64).cast()), Ok(()));
        assert_eq!(claims.claim(1, (&mut carrier1 as *mut u64).cast()), Ok(()));
        assert_eq!(lifecycle.bind_parked(0), Ok(()));
        assert_eq!(lifecycle.bind_parked(1), Ok(()));

        assert_eq!(lifecycle.release(1), Ok(()));
        assert_eq!(
            lifecycle.lifecycle(0),
            Some(RuntimeCarrierLifecycle::Parked),
            "releasing slot one must not admit slot zero dispatch"
        );
        assert_eq!(
            lifecycle.lifecycle(1),
            Some(RuntimeCarrierLifecycle::Executing)
        );
        assert_eq!(lifecycle.release(0), Ok(()));
        assert_eq!(
            lifecycle.lifecycle(0),
            Some(RuntimeCarrierLifecycle::Executing)
        );
    }
}
