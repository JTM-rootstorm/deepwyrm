//! Scheduler-owned publication gate for fixed native CPU carriers.
//!
//! CPU startup, native runtime binding, interrupt mailboxes, retained roots,
//! and deadline hardware are independent authorities.  None of their local
//! lifecycle states grants ordinary scheduler work.  This module joins their
//! immutable identities under the scheduler lock and publishes the one state
//! that does: [`CarrierAdmissionLifecycle::Schedulable`].

use super::{CooperativeScheduler, H2_SCHEDULER_CPU_CAPACITY, SchedulerCpuId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierAdmissionLifecycle {
    Unavailable,
    Preparing,
    CarrierReady,
    Schedulable,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierRuntimeState {
    /// CPU0's already-running primordial carrier.
    Running,
    /// An AP carrier is bound but cannot yet execute scheduler work.
    Parked,
    /// The native carrier and CPU lifecycle have both been released.
    Executing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierDeadlineState {
    /// CPU0 retains the existing bootstrap deadline arbiter.
    BootstrapArbiterReady,
    /// An AP's local scheduler timer remains masked throughout DW1-C1.
    ApSchedulerTimerMasked,
}

/// Immutable identities revalidated at both sides of AP carrier publication.
///
/// The repeated CPU identities are intentional. They keep one accidentally
/// shared descriptor, runtime, stack, root, scratch, or mailbox slot from
/// becoming accepted merely because the outer CPU index was correct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierResourceTuple {
    pub(crate) cpu: SchedulerCpuId,
    pub(crate) local_apic_id: u8,
    pub(crate) online_generation: u64,
    pub(crate) root_generation: u64,
    pub(crate) descriptor_cpu: SchedulerCpuId,
    pub(crate) runtime_cpu: SchedulerCpuId,
    pub(crate) entry_stack_cpu: SchedulerCpuId,
    pub(crate) reaper_stack_cpu: SchedulerCpuId,
    pub(crate) root_cpu: SchedulerCpuId,
    pub(crate) scratch_cpu: SchedulerCpuId,
    pub(crate) idle_mailbox_cpu: SchedulerCpuId,
    pub(crate) tlb_mailbox_cpu: SchedulerCpuId,
    pub(crate) deadline: CarrierDeadlineState,
}

impl CarrierResourceTuple {
    fn validates_fixed_ownership(self) -> bool {
        self.online_generation != 0
            && self.root_generation != 0
            && [
                self.descriptor_cpu,
                self.runtime_cpu,
                self.entry_stack_cpu,
                self.reaper_stack_cpu,
                self.root_cpu,
                self.scratch_cpu,
                self.idle_mailbox_cpu,
                self.tlb_mailbox_cpu,
            ]
            .into_iter()
            .all(|owner| owner == self.cpu)
            && match self.deadline {
                CarrierDeadlineState::BootstrapArbiterReady => {
                    self.cpu == SchedulerCpuId::BOOTSTRAP
                }
                CarrierDeadlineState::ApSchedulerTimerMasked => {
                    self.cpu != SchedulerCpuId::BOOTSTRAP
                }
            }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierAdmissionTicket {
    domain: u64,
    cpu: SchedulerCpuId,
    online_generation: u64,
    admission_generation: u64,
    scheduler_slot_generation: u64,
}

impl CarrierAdmissionTicket {
    pub(crate) const fn cpu(self) -> SchedulerCpuId {
        self.cpu
    }

    pub(crate) const fn admission_generation(self) -> u64 {
        self.admission_generation
    }

    pub(crate) const fn online_generation(self) -> u64 {
        self.online_generation
    }

    pub(crate) const fn scheduler_slot_generation(self) -> u64 {
        self.scheduler_slot_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierAdmissionSnapshot {
    pub(crate) lifecycle: CarrierAdmissionLifecycle,
    pub(crate) online_generation: u64,
    pub(crate) admission_generation: u64,
    pub(crate) scheduler_slot_generation: u64,
    pub(crate) idle_wake_ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierAdmissionError {
    InvalidTuple,
    WrongRuntimeState,
    WrongSchedulerState,
    StaleTicket,
    UnexpectedState,
    GenerationExhausted,
    IdleWakeUnavailable,
}

#[derive(Clone, Copy)]
struct CarrierAdmissionSlot {
    lifecycle: CarrierAdmissionLifecycle,
    resources: Option<CarrierResourceTuple>,
    online_generation: u64,
    admission_generation: u64,
    scheduler_slot_generation: u64,
    idle_wake_ready: bool,
}

impl CarrierAdmissionSlot {
    const fn new() -> Self {
        Self {
            lifecycle: CarrierAdmissionLifecycle::Unavailable,
            resources: None,
            online_generation: 0,
            admission_generation: 0,
            scheduler_slot_generation: 0,
            idle_wake_ready: false,
        }
    }

    fn snapshot(self) -> CarrierAdmissionSnapshot {
        CarrierAdmissionSnapshot {
            lifecycle: self.lifecycle,
            online_generation: self.online_generation,
            admission_generation: self.admission_generation,
            scheduler_slot_generation: self.scheduler_slot_generation,
            idle_wake_ready: self.idle_wake_ready,
        }
    }
}

pub(super) struct CarrierAdmissionState {
    next_admission_generation: u64,
    next_scheduler_slot_generation: u64,
    slots: [CarrierAdmissionSlot; H2_SCHEDULER_CPU_CAPACITY],
    pub(super) schedulable_mask: u64,
    pub(super) enforced: bool,
}

impl CarrierAdmissionState {
    pub(super) const fn new() -> Self {
        Self {
            next_admission_generation: 1,
            next_scheduler_slot_generation: 1,
            slots: [CarrierAdmissionSlot::new(); H2_SCHEDULER_CPU_CAPACITY],
            schedulable_mask: 0,
            enforced: false,
        }
    }

    fn mint_generations(&mut self) -> Result<(u64, u64), CarrierAdmissionError> {
        let admission = self.next_admission_generation;
        let scheduler_slot = self.next_scheduler_slot_generation;
        self.next_admission_generation = admission
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CarrierAdmissionError::GenerationExhausted)?;
        self.next_scheduler_slot_generation = scheduler_slot
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CarrierAdmissionError::GenerationExhausted)?;
        Ok((admission, scheduler_slot))
    }
}

impl<const CAPACITY: usize> CooperativeScheduler<CAPACITY> {
    /// Begins CPU0 normalization from its already-running primordial claim.
    /// CPU0 never enters the AP Parked/release loop.
    pub(crate) fn prepare_bootstrap_carrier(
        &self,
        resources: CarrierResourceTuple,
        runtime: CarrierRuntimeState,
    ) -> Result<CarrierAdmissionTicket, CarrierAdmissionError> {
        if resources.cpu != SchedulerCpuId::BOOTSTRAP || !resources.validates_fixed_ownership() {
            return Err(CarrierAdmissionError::InvalidTuple);
        }
        if runtime != CarrierRuntimeState::Running {
            return Err(CarrierAdmissionError::WrongRuntimeState);
        }
        let mut state = self.state.lock();
        let cpu = SchedulerCpuId::BOOTSTRAP;
        if state.running[cpu.index()].is_none()
            || state.suspended[cpu.index()].is_some()
            || state.pending_block[cpu.index()].is_some()
            || state.carrier_admission.slots[cpu.index()].lifecycle
                != CarrierAdmissionLifecycle::Unavailable
        {
            return Err(CarrierAdmissionError::WrongSchedulerState);
        }
        let domain = state.domain;
        let (admission_generation, scheduler_slot_generation) =
            state.carrier_admission.mint_generations()?;
        state.carrier_admission.slots[cpu.index()] = CarrierAdmissionSlot {
            lifecycle: CarrierAdmissionLifecycle::Preparing,
            resources: Some(resources),
            online_generation: resources.online_generation,
            admission_generation,
            scheduler_slot_generation,
            idle_wake_ready: false,
        };
        state.carrier_admission.enforced = true;
        Ok(CarrierAdmissionTicket {
            domain,
            cpu,
            online_generation: resources.online_generation,
            admission_generation,
            scheduler_slot_generation,
        })
    }

    pub(crate) fn publish_bootstrap_carrier_ready(
        &self,
        ticket: CarrierAdmissionTicket,
        resources: CarrierResourceTuple,
        runtime: CarrierRuntimeState,
    ) -> Result<(), CarrierAdmissionError> {
        if runtime != CarrierRuntimeState::Running {
            return Err(CarrierAdmissionError::WrongRuntimeState);
        }
        let mut state = self.state.lock();
        if !ticket_matches(&state, ticket) {
            return Err(CarrierAdmissionError::StaleTicket);
        }
        let cpu_index = ticket.cpu.index();
        let has_running_claim = state.running[cpu_index].is_some();
        let slot = &mut state.carrier_admission.slots[cpu_index];
        if ticket.cpu != SchedulerCpuId::BOOTSTRAP
            || !resources.validates_fixed_ownership()
            || slot.lifecycle != CarrierAdmissionLifecycle::Preparing
            || slot.resources != Some(resources)
            || !has_running_claim
        {
            slot.lifecycle = CarrierAdmissionLifecycle::Failed;
            return Err(CarrierAdmissionError::WrongSchedulerState);
        }
        slot.lifecycle = CarrierAdmissionLifecycle::CarrierReady;
        Ok(())
    }

    pub(crate) fn commit_bootstrap_schedulable(
        &self,
        ticket: CarrierAdmissionTicket,
        resources: CarrierResourceTuple,
    ) -> Result<(), CarrierAdmissionError> {
        let mut state = self.state.lock();
        if !ticket_matches(&state, ticket) {
            return Err(CarrierAdmissionError::StaleTicket);
        }
        let cpu_index = ticket.cpu.index();
        if ticket.cpu != SchedulerCpuId::BOOTSTRAP
            || state.carrier_admission.slots[cpu_index].lifecycle
                != CarrierAdmissionLifecycle::CarrierReady
            || state.carrier_admission.slots[cpu_index].resources != Some(resources)
            || state.running[cpu_index].is_none()
        {
            state.carrier_admission.slots[cpu_index].lifecycle = CarrierAdmissionLifecycle::Failed;
            return Err(CarrierAdmissionError::WrongSchedulerState);
        }
        state.carrier_admission.slots[cpu_index].idle_wake_ready = true;
        state.carrier_admission.slots[cpu_index].lifecycle = CarrierAdmissionLifecycle::Schedulable;
        state.carrier_admission.schedulable_mask |= 1_u64 << cpu_index;
        Ok(())
    }

    /// Publishes the BSP half of an AP admission while the carrier and CPU are
    /// still parked and its scheduler slot is empty.
    pub(crate) fn prepare_ap_carrier(
        &self,
        resources: CarrierResourceTuple,
        runtime: CarrierRuntimeState,
    ) -> Result<CarrierAdmissionTicket, CarrierAdmissionError> {
        if resources.cpu == SchedulerCpuId::BOOTSTRAP || !resources.validates_fixed_ownership() {
            return Err(CarrierAdmissionError::InvalidTuple);
        }
        if runtime != CarrierRuntimeState::Parked {
            return Err(CarrierAdmissionError::WrongRuntimeState);
        }
        let mut state = self.state.lock();
        let cpu = resources.cpu;
        if state.running[cpu.index()].is_some()
            || state.suspended[cpu.index()].is_some()
            || state.pending_block[cpu.index()].is_some()
            || state.active_idle[cpu.index()].is_some()
            || state.carrier_admission.slots[cpu.index()].lifecycle
                != CarrierAdmissionLifecycle::Unavailable
        {
            return Err(CarrierAdmissionError::WrongSchedulerState);
        }
        let domain = state.domain;
        let (admission_generation, scheduler_slot_generation) =
            state.carrier_admission.mint_generations()?;
        state.carrier_admission.slots[cpu.index()] = CarrierAdmissionSlot {
            lifecycle: CarrierAdmissionLifecycle::Preparing,
            resources: Some(resources),
            online_generation: resources.online_generation,
            admission_generation,
            scheduler_slot_generation,
            idle_wake_ready: false,
        };
        state.carrier_admission.enforced = true;
        Ok(CarrierAdmissionTicket {
            domain,
            cpu,
            online_generation: resources.online_generation,
            admission_generation,
            scheduler_slot_generation,
        })
    }

    /// AP-side acknowledgement after native runtime and CPU execution release.
    pub(crate) fn publish_ap_carrier_ready(
        &self,
        ticket: CarrierAdmissionTicket,
        resources: CarrierResourceTuple,
        runtime: CarrierRuntimeState,
    ) -> Result<(), CarrierAdmissionError> {
        let mut state = self.state.lock();
        if !ticket_matches(&state, ticket) {
            return Err(CarrierAdmissionError::StaleTicket);
        }
        let slot = &mut state.carrier_admission.slots[ticket.cpu.index()];
        if runtime != CarrierRuntimeState::Executing
            || !resources.validates_fixed_ownership()
            || slot.lifecycle != CarrierAdmissionLifecycle::Preparing
            || slot.resources != Some(resources)
        {
            slot.lifecycle = CarrierAdmissionLifecycle::Failed;
            return Err(if runtime != CarrierRuntimeState::Executing {
                CarrierAdmissionError::WrongRuntimeState
            } else {
                CarrierAdmissionError::UnexpectedState
            });
        }
        slot.lifecycle = CarrierAdmissionLifecycle::CarrierReady;
        Ok(())
    }

    /// Runs the one fallible idle-wake publication while admission authority is
    /// held. On success, the remaining mask/lifecycle writes are infallible.
    pub(crate) fn commit_ap_schedulable(
        &self,
        ticket: CarrierAdmissionTicket,
        resources: CarrierResourceTuple,
        enable_idle_wake: impl FnOnce() -> bool,
    ) -> Result<(), CarrierAdmissionError> {
        self.commit_ap_schedulable_inner(ticket, resources, enable_idle_wake, || {})
    }

    fn commit_ap_schedulable_inner(
        &self,
        ticket: CarrierAdmissionTicket,
        resources: CarrierResourceTuple,
        enable_idle_wake: impl FnOnce() -> bool,
        after_idle_wake: impl FnOnce(),
    ) -> Result<(), CarrierAdmissionError> {
        let mut state = self.state.lock();
        if !ticket_matches(&state, ticket) {
            return Err(CarrierAdmissionError::StaleTicket);
        }
        let cpu_index = ticket.cpu.index();
        let slot = state.carrier_admission.slots[cpu_index];
        if slot.lifecycle != CarrierAdmissionLifecycle::CarrierReady
            || slot.resources != Some(resources)
            || state.running[cpu_index].is_some()
            || state.suspended[cpu_index].is_some()
            || state.pending_block[cpu_index].is_some()
            || state.active_idle[cpu_index].is_some()
        {
            state.carrier_admission.slots[cpu_index].lifecycle = CarrierAdmissionLifecycle::Failed;
            return Err(CarrierAdmissionError::WrongSchedulerState);
        }
        if !enable_idle_wake() {
            state.carrier_admission.slots[cpu_index].lifecycle = CarrierAdmissionLifecycle::Failed;
            return Err(CarrierAdmissionError::IdleWakeUnavailable);
        }

        // Irreversible boundary: no fallible work may be added below this line.
        // The test-only probe immediately after the hardware publication can
        // only diverge, modeling the required fail-stop outcome at this exact
        // boundary; production supplies an infallible no-op.
        after_idle_wake();
        state.carrier_admission.slots[cpu_index].idle_wake_ready = true;
        state.carrier_admission.slots[cpu_index].lifecycle = CarrierAdmissionLifecycle::Schedulable;
        state.carrier_admission.schedulable_mask |= 1_u64 << cpu_index;
        Ok(())
    }

    pub(crate) fn carrier_admission_snapshot(
        &self,
        cpu: SchedulerCpuId,
    ) -> CarrierAdmissionSnapshot {
        self.state.lock().carrier_admission.slots[cpu.index()].snapshot()
    }

    pub(crate) fn carrier_ticket_is_schedulable(&self, ticket: CarrierAdmissionTicket) -> bool {
        let state = self.state.lock();
        ticket_matches(&state, ticket)
            && state.carrier_admission.slots[ticket.cpu.index()].lifecycle
                == CarrierAdmissionLifecycle::Schedulable
            && state.carrier_admission.slots[ticket.cpu.index()].idle_wake_ready
            && state.carrier_admission.schedulable_mask & (1_u64 << ticket.cpu.index()) != 0
    }

    pub(crate) fn carrier_accepts_runnable_target(&self, cpu: SchedulerCpuId) -> bool {
        let state = self.state.lock();
        state.carrier_admission.schedulable_mask & (1_u64 << cpu.index()) != 0
            && state.carrier_admission.slots[cpu.index()].lifecycle
                == CarrierAdmissionLifecycle::Schedulable
    }

    pub(crate) fn fail_carrier_admission(&self, cpu: SchedulerCpuId) {
        let mut state = self.state.lock();
        let slot = &mut state.carrier_admission.slots[cpu.index()];
        if slot.lifecycle == CarrierAdmissionLifecycle::Schedulable {
            panic!("schedulable carrier cannot return to precommit failure");
        }
        slot.lifecycle = CarrierAdmissionLifecycle::Failed;
        slot.idle_wake_ready = false;
        state.carrier_admission.schedulable_mask &= !(1_u64 << cpu.index());
        state.carrier_admission.enforced = true;
    }
}

fn ticket_matches<const CAPACITY: usize>(
    state: &super::SchedulerState<CAPACITY>,
    ticket: CarrierAdmissionTicket,
) -> bool {
    let slot = state.carrier_admission.slots[ticket.cpu.index()];
    ticket.domain == state.domain
        && ticket.online_generation == slot.online_generation
        && ticket.admission_generation == slot.admission_generation
        && ticket.scheduler_slot_generation == slot.scheduler_slot_generation
        && ticket.online_generation != 0
        && ticket.admission_generation != 0
        && ticket.scheduler_slot_generation != 0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::object::ObjectRegistry;
    use crate::task::ThreadKey;
    use deepwyrm_abi::DW_OBJECT_TYPE_THREAD;

    fn cpu(index: usize) -> SchedulerCpuId {
        SchedulerCpuId::new(index).expect("test CPU is inside the fixed scheduler bound")
    }

    fn resources(index: usize, runtime_generation: u64) -> CarrierResourceTuple {
        let owner = cpu(index);
        CarrierResourceTuple {
            cpu: owner,
            local_apic_id: u8::try_from(index + 2).unwrap(),
            online_generation: runtime_generation,
            root_generation: 0x100 + runtime_generation,
            descriptor_cpu: owner,
            runtime_cpu: owner,
            entry_stack_cpu: owner,
            reaper_stack_cpu: owner,
            root_cpu: owner,
            scratch_cpu: owner,
            idle_mailbox_cpu: owner,
            tlb_mailbox_cpu: owner,
            deadline: if index == 0 {
                CarrierDeadlineState::BootstrapArbiterReady
            } else {
                CarrierDeadlineState::ApSchedulerTimerMasked
            },
        }
    }

    fn schedule_bootstrap_thread(scheduler: &CooperativeScheduler<8>) -> ThreadKey {
        let mut registry = ObjectRegistry::<4>::new();
        let creation = registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
        let thread = ThreadKey::from_object_id(creation.id());
        registry.cancel_creation(creation).unwrap();
        let reservation = scheduler.reserve(thread).unwrap();
        scheduler.commit(reservation).unwrap();
        assert_eq!(
            scheduler.schedule_next_on(cpu(0)).unwrap().current,
            Some(thread)
        );
        thread
    }

    #[test]
    fn four_cpu_admission_requires_exact_carrier_ready_tuple() {
        let scheduler = CooperativeScheduler::<8>::new();
        let primordial = schedule_bootstrap_thread(&scheduler);
        let bootstrap = scheduler
            .prepare_bootstrap_carrier(resources(0, 1), CarrierRuntimeState::Running)
            .unwrap();
        assert_eq!(scheduler.current_on(cpu(0)), Some(primordial));
        assert_eq!(
            scheduler.carrier_admission_snapshot(cpu(0)).lifecycle,
            CarrierAdmissionLifecycle::Preparing
        );
        scheduler
            .publish_bootstrap_carrier_ready(
                bootstrap,
                resources(0, 1),
                CarrierRuntimeState::Running,
            )
            .unwrap();
        scheduler
            .commit_bootstrap_schedulable(bootstrap, resources(0, 1))
            .unwrap();
        assert!(scheduler.carrier_ticket_is_schedulable(bootstrap));

        let mut admission_generations = [bootstrap.admission_generation(); 4];
        let mut slot_generations = [bootstrap.scheduler_slot_generation(); 4];
        for index in 1..4 {
            let tuple = resources(index, u64::try_from(index + 1).unwrap());
            let ticket = scheduler
                .prepare_ap_carrier(tuple, CarrierRuntimeState::Parked)
                .unwrap();
            assert!(!scheduler.carrier_accepts_runnable_target(cpu(index)));
            scheduler
                .publish_ap_carrier_ready(ticket, tuple, CarrierRuntimeState::Executing)
                .unwrap();
            assert!(!scheduler.carrier_accepts_runnable_target(cpu(index)));
            scheduler
                .commit_ap_schedulable(ticket, tuple, || true)
                .unwrap();
            assert!(scheduler.carrier_ticket_is_schedulable(ticket));
            assert!(scheduler.carrier_accepts_runnable_target(cpu(index)));
            admission_generations[index] = ticket.admission_generation();
            slot_generations[index] = ticket.scheduler_slot_generation();
        }
        for index in 0..4 {
            assert_ne!(admission_generations[index], 0);
            assert_ne!(slot_generations[index], 0);
            assert!(!admission_generations[..index].contains(&admission_generations[index]));
            assert!(!slot_generations[..index].contains(&slot_generations[index]));
        }
    }

    #[test]
    fn cpu0_normalization_preserves_primordial_running_claim() {
        let scheduler = CooperativeScheduler::<8>::new();
        let primordial = schedule_bootstrap_thread(&scheduler);
        let before = scheduler.running_claim_on(cpu(0)).unwrap();
        let ticket = scheduler
            .prepare_bootstrap_carrier(resources(0, 7), CarrierRuntimeState::Running)
            .unwrap();
        assert_eq!(scheduler.running_claim_on(cpu(0)).unwrap(), before);
        scheduler
            .publish_bootstrap_carrier_ready(ticket, resources(0, 7), CarrierRuntimeState::Running)
            .unwrap();
        assert_eq!(scheduler.running_claim_on(cpu(0)).unwrap(), before);
        scheduler
            .commit_bootstrap_schedulable(ticket, resources(0, 7))
            .unwrap();
        let after = scheduler.running_claim_on(cpu(0)).unwrap();
        assert_eq!(before, after);
        assert_eq!(after.thread(), primordial);
        assert_eq!(
            scheduler.carrier_admission_snapshot(cpu(0)).lifecycle,
            CarrierAdmissionLifecycle::Schedulable
        );
    }

    #[test]
    fn publication_reordering_never_admits_an_ap() {
        let scheduler = CooperativeScheduler::<8>::new();
        let tuple = resources(1, 9);
        let ticket = scheduler
            .prepare_ap_carrier(tuple, CarrierRuntimeState::Parked)
            .unwrap();
        assert_eq!(
            scheduler.commit_ap_schedulable(ticket, tuple, || true),
            Err(CarrierAdmissionError::WrongSchedulerState)
        );
        assert_eq!(
            scheduler.carrier_admission_snapshot(cpu(1)).lifecycle,
            CarrierAdmissionLifecycle::Failed
        );
        assert!(!scheduler.carrier_accepts_runnable_target(cpu(1)));
    }

    #[test]
    fn stale_carrier_ready_or_online_generation_cannot_commit() {
        let scheduler = CooperativeScheduler::<8>::new();
        let tuple = resources(2, 11);
        let ticket = scheduler
            .prepare_ap_carrier(tuple, CarrierRuntimeState::Parked)
            .unwrap();
        let stale = CarrierAdmissionTicket {
            online_generation: ticket.online_generation - 1,
            ..ticket
        };
        assert_eq!(
            scheduler.publish_ap_carrier_ready(stale, tuple, CarrierRuntimeState::Executing),
            Err(CarrierAdmissionError::StaleTicket)
        );
        assert!(!scheduler.carrier_accepts_runnable_target(cpu(2)));
    }

    #[test]
    fn failed_idle_wake_publication_is_precommit_and_not_retryable() {
        let scheduler = CooperativeScheduler::<8>::new();
        let tuple = resources(3, 13);
        let ticket = scheduler
            .prepare_ap_carrier(tuple, CarrierRuntimeState::Parked)
            .unwrap();
        scheduler
            .publish_ap_carrier_ready(ticket, tuple, CarrierRuntimeState::Executing)
            .unwrap();
        assert_eq!(
            scheduler.commit_ap_schedulable(ticket, tuple, || false),
            Err(CarrierAdmissionError::IdleWakeUnavailable)
        );
        let snapshot = scheduler.carrier_admission_snapshot(cpu(3));
        assert_eq!(snapshot.lifecycle, CarrierAdmissionLifecycle::Failed);
        assert!(!snapshot.idle_wake_ready);
        assert!(!scheduler.carrier_accepts_runnable_target(cpu(3)));
        assert_eq!(
            scheduler.publish_ap_carrier_ready(ticket, tuple, CarrierRuntimeState::Executing),
            Err(CarrierAdmissionError::UnexpectedState)
        );
    }

    #[test]
    fn post_idle_wake_fault_is_fail_stop_before_scheduler_publication() {
        let scheduler = CooperativeScheduler::<8>::new();
        let tuple = resources(3, 15);
        let ticket = scheduler
            .prepare_ap_carrier(tuple, CarrierRuntimeState::Parked)
            .unwrap();
        scheduler
            .publish_ap_carrier_ready(ticket, tuple, CarrierRuntimeState::Executing)
            .unwrap();
        let fault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = scheduler.commit_ap_schedulable_inner(
                ticket,
                tuple,
                || true,
                || panic!("injected post-idle-enable fail-stop"),
            );
        }));
        assert!(fault.is_err());
        let snapshot = scheduler.carrier_admission_snapshot(cpu(3));
        assert_eq!(snapshot.lifecycle, CarrierAdmissionLifecycle::CarrierReady);
        assert!(!snapshot.idle_wake_ready);
        assert!(!scheduler.carrier_accepts_runnable_target(cpu(3)));
    }

    #[test]
    fn mismatched_private_resource_identity_is_rejected() {
        let scheduler = CooperativeScheduler::<8>::new();
        let mut tuple = resources(1, 17);
        tuple.reaper_stack_cpu = cpu(2);
        assert_eq!(
            scheduler.prepare_ap_carrier(tuple, CarrierRuntimeState::Parked),
            Err(CarrierAdmissionError::InvalidTuple)
        );
        assert_eq!(
            scheduler.carrier_admission_snapshot(cpu(1)).lifecycle,
            CarrierAdmissionLifecycle::Unavailable
        );
    }

    #[test]
    fn every_idle_dispatch_path_rejects_a_pre_schedulable_cpu() {
        let scheduler = CooperativeScheduler::<8>::new();
        let mut registry = ObjectRegistry::<4>::new();
        let creation = registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
        let suspended = ThreadKey::from_object_id(creation.id());
        registry.cancel_creation(creation).unwrap();
        scheduler
            .prepare_ap_carrier(resources(1, 19), CarrierRuntimeState::Parked)
            .unwrap();
        assert_eq!(
            scheduler.schedule_from_idle_on(cpu(1), suspended),
            Err(super::super::SchedulerError::CarrierUnavailable)
        );
        assert_eq!(
            scheduler.schedule_next_on(cpu(1)),
            Err(super::super::SchedulerError::CarrierUnavailable)
        );
    }

    #[test]
    fn live_precommit_failure_latches_before_a_ticket_exists() {
        let scheduler = CooperativeScheduler::<8>::new();
        scheduler.fail_carrier_admission(cpu(2));
        assert_eq!(
            scheduler.carrier_admission_snapshot(cpu(2)).lifecycle,
            CarrierAdmissionLifecycle::Failed
        );
        assert_eq!(
            scheduler.prepare_ap_carrier(resources(2, 23), CarrierRuntimeState::Parked),
            Err(CarrierAdmissionError::WrongSchedulerState)
        );
        assert!(!scheduler.carrier_accepts_runnable_target(cpu(2)));
    }
}
