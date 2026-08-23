//! Stationary runtime ownership primitives for the serialized I1 carrier join.
//!
//! These types deliberately expose authority only through non-escaping
//! closures.  They make a coarse first split between stationary shared state
//! and per-CPU carrier state without permitting an IRQ-safe guard to survive
//! into usercopy, switching, idle, or a terminal handoff.

#![allow(
    dead_code,
    reason = "the staged stationary authority surface is target-built before the later split converts every long primordial adapter into prepare/commit phases"
)]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::cpu::CpuIndex;
use crate::sync::IrqSpinMutex;
use crate::task::ThreadKey;

/// Instrumented depth of the two stationary authority families.
///
/// This is a contract aid, not a scheduler lock.  A boundary that may block,
/// return to userspace, switch context, hand off to the reaper, or execute
/// `sti; hlt` must call [`StationaryGuardDepth::assert_clear_on`] before entering
/// its architecture-specific work.
pub(crate) struct StationaryGuardDepth {
    state: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct StationaryGuard<'a> {
    depth: &'a StationaryGuardDepth,
    cpu: CpuIndex,
    expected: u8,
    name: &'static str,
}

impl Drop for StationaryGuard<'_> {
    fn drop(&mut self) {
        assert_eq!(
            self.depth.slot(self.cpu).swap(0, Ordering::AcqRel),
            self.expected,
            "{} guard depth underflow",
            self.name
        );
    }
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

    fn enter_core(&self, cpu: CpuIndex) -> StationaryGuard<'_> {
        self.slot(cpu)
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|_| panic!("stationary authority nesting on CPU {}", cpu.index()));
        StationaryGuard {
            depth: self,
            cpu,
            expected: 1,
            name: "RuntimeCore",
        }
    }

    fn enter_paging(&self, cpu: CpuIndex) -> StationaryGuard<'_> {
        self.slot(cpu)
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|_| panic!("stationary authority nesting on CPU {}", cpu.index()));
        StationaryGuard {
            depth: self,
            cpu,
            expected: 2,
            name: "PagingAuthority",
        }
    }

    pub(crate) fn assert_clear_on(&self, cpu: CpuIndex) {
        assert_eq!(
            self.slot(cpu).load(Ordering::Acquire),
            0,
            "stationary authority guard crossed a forbidden runtime boundary on CPU {}",
            cpu.index()
        );
    }

    #[cfg(test)]
    fn state_on(&self, cpu: CpuIndex) -> u8 {
        self.slot(cpu).load(Ordering::Acquire)
    }
}

/// Coarse stationary ownership of the non-paging live runtime authorities.
///
/// The individual payloads remain intentionally opaque to callers: a caller
/// may perform only a short prepare or commit closure.  The closure result is
/// owned, so neither a lock guard nor a borrowed authority can escape.
pub(crate) struct RuntimeCore<REGISTRY, MEMORY, TASKS, SPACES, REGIONS> {
    state: IrqSpinMutex<RuntimeCoreState<REGISTRY, MEMORY, TASKS, SPACES, REGIONS>>,
    depth: &'static StationaryGuardDepth,
}

pub(crate) struct RuntimeCoreState<REGISTRY, MEMORY, TASKS, SPACES, REGIONS> {
    pub(crate) registry: REGISTRY,
    pub(crate) memory: MEMORY,
    #[allow(
        dead_code,
        reason = "the staged BSP migration reaches registry/memory first"
    )]
    pub(crate) tasks: TASKS,
    #[allow(
        dead_code,
        reason = "the staged BSP migration reaches registry/memory first"
    )]
    pub(crate) spaces: SPACES,
    #[allow(
        dead_code,
        reason = "the staged BSP migration reaches registry/memory first"
    )]
    pub(crate) regions: REGIONS,
}

impl<REGISTRY, MEMORY, TASKS, SPACES, REGIONS>
    RuntimeCore<REGISTRY, MEMORY, TASKS, SPACES, REGIONS>
{
    pub(crate) fn new(
        registry: REGISTRY,
        memory: MEMORY,
        tasks: TASKS,
        spaces: SPACES,
        regions: REGIONS,
        depth: &'static StationaryGuardDepth,
    ) -> Self {
        Self {
            state: IrqSpinMutex::new(RuntimeCoreState {
                registry,
                memory,
                tasks,
                spaces,
                regions,
            }),
            depth,
        }
    }

    pub(crate) fn prepare_on<R>(
        &self,
        cpu: CpuIndex,
        operation: impl FnOnce(&mut RuntimeCoreState<REGISTRY, MEMORY, TASKS, SPACES, REGIONS>) -> R,
    ) -> R {
        let guard = self.depth.enter_core(cpu);
        let result = {
            let mut state = self.state.lock();
            operation(&mut state)
        };
        drop(guard);
        result
    }

    #[allow(
        dead_code,
        reason = "the first BSP migration currently has prepare-only observations"
    )]
    pub(crate) fn commit_on<R>(
        &self,
        cpu: CpuIndex,
        operation: impl FnOnce(&mut RuntimeCoreState<REGISTRY, MEMORY, TASKS, SPACES, REGIONS>) -> R,
    ) -> R {
        self.prepare_on(cpu, operation)
    }
}

/// Coarse stationary paging authority.  The payload is the exact owner of
/// frame roles, root bindings, coherency, and scratch topology for a runtime
/// instance.  It uses the same non-nesting closure discipline as RuntimeCore.
pub(crate) struct PagingAuthority<PAGING> {
    state: IrqSpinMutex<PAGING>,
    depth: &'static StationaryGuardDepth,
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

impl<PAGING> PagingAuthority<PAGING> {
    pub(crate) fn new(state: PAGING, depth: &'static StationaryGuardDepth) -> Self {
        Self {
            state: IrqSpinMutex::new(state),
            depth,
        }
    }

    pub(crate) fn prepare_on<R>(
        &self,
        cpu: CpuIndex,
        operation: impl FnOnce(&mut PAGING) -> R,
    ) -> R {
        let guard = self.depth.enter_paging(cpu);
        let result = {
            let mut state = self.state.lock();
            operation(&mut state)
        };
        drop(guard);
        result
    }

    pub(crate) fn commit_on<R>(
        &self,
        cpu: CpuIndex,
        operation: impl FnOnce(&mut PAGING) -> R,
    ) -> R {
        self.prepare_on(cpu, operation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadServiceSlotError {
    AlreadyBound,
    Capacity,
    StaleLease,
}

struct ThreadServiceSlot<STATE> {
    key: ThreadKey,
    state: STATE,
}

/// Move-only exact-generation key for a thread's F-service continuation.
#[must_use = "a service lease must be consumed by a matching per-thread operation"]
pub(crate) struct ThreadServiceLease {
    key: ThreadKey,
}

/// Fixed service-continuation storage keyed by exact `ThreadKey` identity.
/// A service state follows its Thread across CPUs; no CPU carrier owns it.
pub(crate) struct ThreadServiceSlots<STATE, const SLOTS: usize> {
    slots: IrqSpinMutex<[Option<ThreadServiceSlot<STATE>>; SLOTS]>,
}

impl<STATE, const SLOTS: usize> ThreadServiceSlots<STATE, SLOTS> {
    pub(crate) fn new() -> Self {
        Self {
            slots: IrqSpinMutex::new(core::array::from_fn(|_| None)),
        }
    }

    pub(crate) fn bind(
        &self,
        key: ThreadKey,
        state: STATE,
    ) -> Result<ThreadServiceLease, ThreadServiceSlotError> {
        let mut slots = self.slots.lock();
        if slots.iter().flatten().any(|slot| slot.key == key) {
            return Err(ThreadServiceSlotError::AlreadyBound);
        }
        let slot = slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ThreadServiceSlotError::Capacity)?;
        *slot = Some(ThreadServiceSlot { key, state });
        Ok(ThreadServiceLease { key })
    }

    pub(crate) fn with_lease<R>(
        &self,
        lease: &ThreadServiceLease,
        operation: impl FnOnce(&mut STATE) -> R,
    ) -> Result<R, ThreadServiceSlotError> {
        let mut slots = self.slots.lock();
        let slot = slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.key == lease.key)
            .ok_or(ThreadServiceSlotError::StaleLease)?;
        Ok(operation(&mut slot.state))
    }

    pub(crate) fn release(
        &self,
        lease: ThreadServiceLease,
    ) -> Result<STATE, ThreadServiceSlotError> {
        let mut slots = self.slots.lock();
        let slot = slots
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|slot| slot.key == lease.key))
            .ok_or(ThreadServiceSlotError::StaleLease)?;
        Ok(slot
            .take()
            .expect("matching service slot remains initialized")
            .state)
    }
}

/// CPU-private carrier staging.  Each slot is independently IRQ-serialized;
/// callers cannot borrow the backing buffer without naming the exact CPU.
pub(crate) struct PerCpuStaging<const BYTES: usize, const CPUS: usize> {
    slots: [IrqSpinMutex<[u8; BYTES]>; CPUS],
}

impl<const BYTES: usize, const CPUS: usize> PerCpuStaging<BYTES, CPUS> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { IrqSpinMutex::new([0; BYTES]) }; CPUS],
        }
    }

    pub(crate) fn with_cpu<R>(
        &self,
        cpu: CpuIndex,
        operation: impl FnOnce(&mut [u8; BYTES]) -> R,
    ) -> Option<R> {
        let slot = self.slots.get(cpu.index())?;
        let mut slot = slot.lock();
        Some(operation(&mut slot))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

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
    fn stationary_authorities_do_not_leak_guards_across_boundaries() {
        static DEPTH: StationaryGuardDepth = StationaryGuardDepth::new();
        let cpu = CpuIndex::BOOTSTRAP;
        let core = RuntimeCore::new(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, &DEPTH);
        let paging = PagingAuthority::new(7_u8, &DEPTH);
        assert_eq!(
            core.prepare_on(cpu, |state| state.registry + state.memory),
            3
        );
        assert_eq!(
            paging.commit_on(cpu, |state| {
                *state += 1;
                *state
            }),
            8
        );
        DEPTH.assert_clear_on(cpu);
        assert_eq!(DEPTH.state_on(cpu), 0);
    }

    #[test]
    #[should_panic(expected = "stationary authority nesting on CPU 0")]
    fn stationary_authority_nesting_fails_closed() {
        static DEPTH: StationaryGuardDepth = StationaryGuardDepth::new();
        let core = RuntimeCore::new((), (), (), (), (), &DEPTH);
        let paging = PagingAuthority::new((), &DEPTH);
        core.prepare_on(CpuIndex::BOOTSTRAP, |_| {
            paging.prepare_on(CpuIndex::BOOTSTRAP, |_| ())
        });
    }

    #[test]
    fn stationary_authorities_allow_independent_cpu_phases() {
        static DEPTH: StationaryGuardDepth = StationaryGuardDepth::new();
        let core = RuntimeCore::new((), (), (), (), (), &DEPTH);
        let paging = PagingAuthority::new((), &DEPTH);
        let cpu0 = CpuIndex::BOOTSTRAP;
        let cpu1 = CpuIndex::new(1).unwrap();
        core.prepare_on(cpu0, |_| paging.prepare_on(cpu1, |_| ()));
        DEPTH.assert_clear_on(cpu0);
        DEPTH.assert_clear_on(cpu1);
    }

    #[test]
    fn stationary_guard_is_balanced_when_a_prepare_phase_panics() {
        static DEPTH: StationaryGuardDepth = StationaryGuardDepth::new();
        let core = RuntimeCore::new((), (), (), (), (), &DEPTH);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.prepare_on(CpuIndex::BOOTSTRAP, |_| panic!("model prepare failure"));
        }));
        assert!(result.is_err());
        DEPTH.assert_clear_on(CpuIndex::BOOTSTRAP);
    }

    #[test]
    fn exact_thread_service_lease_follows_a_thread_across_cpu_migration() {
        let slots = ThreadServiceSlots::<u32, 2>::new();
        let thread = thread_fixture();
        let lease = slots.bind(thread, 11).unwrap();
        assert_eq!(
            slots.with_lease(&lease, |state| {
                *state += 1;
                *state
            }),
            Ok(12)
        );
        assert_eq!(slots.release(lease), Ok(12));
    }

    #[test]
    fn stale_thread_service_lease_rejects_after_exact_release() {
        let slots = ThreadServiceSlots::<u32, 1>::new();
        let lease = slots.bind(thread_fixture(), 11).unwrap();
        let stale = ThreadServiceLease { key: lease.key };
        assert_eq!(slots.release(lease), Ok(11));
        assert_eq!(
            slots.with_lease(&stale, |_| ()),
            Err(ThreadServiceSlotError::StaleLease)
        );
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

    #[test]
    fn per_cpu_staging_is_distinct_and_cross_cpu_access_never_aliases() {
        let staging = PerCpuStaging::<4, 2>::new();
        let cpu0 = CpuIndex::BOOTSTRAP;
        let cpu1 = CpuIndex::new(1).unwrap();
        staging.with_cpu(cpu0, |bytes| bytes.copy_from_slice(&[1, 2, 3, 4]));
        staging.with_cpu(cpu1, |bytes| bytes.copy_from_slice(&[5, 6, 7, 8]));
        assert_eq!(staging.with_cpu(cpu0, |bytes| *bytes), Some([1, 2, 3, 4]));
        assert_eq!(staging.with_cpu(cpu1, |bytes| *bytes), Some([5, 6, 7, 8]));
    }
}
