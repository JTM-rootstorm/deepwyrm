//! Generation-bound idle publication and coalesced e1 wake selection for H4.
//!
//! This layer does not schedule. A CPU publishes `Preparing` before its final
//! scheduler rescan, commits `Halted` immediately before the architectural
//! `sti; hlt; cli`, and returns to `Active` after any interrupt. A Runnable
//! publisher only selects one already-idle eligible CPU and publishes the
//! existing rendezvous-mailbox `Wake` notification before sending e1.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::cpu::{CPU_CAPACITY, CpuIndex};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::rendezvous::{
    DeferredFailure, DeferredReclaim, ReclaimError, RemoteStopReclaimPermit, StopIdentity,
    StopPublishFailure,
};
use super::rendezvous::{
    ExactSafeWitness, MailboxNotification, RemoteStopError, RemoteStopSafePoint,
    RendezvousIpiLatches, RendezvousMailbox, StopRequest,
};

const CPU_UNAVAILABLE: u8 = 0;
const CPU_ACTIVE: u8 = 1;
const CPU_PREPARING: u8 = 2;
const CPU_HALTED: u8 = 3;

const fn cpu(index: usize) -> CpuIndex {
    match CpuIndex::new(index) {
        Some(cpu) => cpu,
        None => panic!("idle-wake CPU constant exceeds canonical capacity"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdleWakeError {
    Unavailable,
    AlreadyEnabled,
    NotActive,
    StalePreparation,
    RescanRequired,
    GenerationExhausted,
    TransportFaulted,
}

#[must_use = "an idle preparation must be cancelled after finding work or committed immediately before halt"]
#[derive(Debug)]
pub(crate) struct IdlePreparation {
    cpu: CpuIndex,
    generation: u64,
}

impl IdlePreparation {
    pub(crate) const fn cpu(&self) -> CpuIndex {
        self.cpu
    }
}

#[must_use = "a committed idle halt must be completed after the interrupt returns"]
#[derive(Debug)]
pub(crate) struct IdleHalt {
    cpu: CpuIndex,
    generation: u64,
}

#[must_use = "failed idle commit retains the preparation that must be cancelled"]
#[derive(Debug)]
pub(crate) struct IdleCommitFailure {
    error: IdleWakeError,
    preparation: IdlePreparation,
}

impl IdleCommitFailure {
    pub(crate) const fn error(&self) -> IdleWakeError {
        self.error
    }

    pub(crate) fn into_preparation(self) -> IdlePreparation {
        self.preparation
    }
}

#[derive(Debug)]
struct IdleCpuSlot {
    state: AtomicU8,
    next_generation: AtomicU64,
    generation: AtomicU64,
}

impl IdleCpuSlot {
    const fn unavailable() -> Self {
        Self {
            state: AtomicU8::new(CPU_UNAVAILABLE),
            next_generation: AtomicU64::new(1),
            generation: AtomicU64::new(0),
        }
    }

    fn mint_generation(&self) -> Result<u64, IdleWakeError> {
        self.next_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                generation.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| IdleWakeError::GenerationExhausted)
    }
}

/// Bounded idle state paired one-to-one with the reviewed rendezvous mailboxes.
pub(crate) struct IdleWakeSet {
    cpus: [IdleCpuSlot; CPU_CAPACITY],
    mailboxes: [RendezvousMailbox; CPU_CAPACITY],
    ipi_latches: RendezvousIpiLatches,
    faulted: AtomicBool,
}

impl IdleWakeSet {
    pub(crate) const fn new() -> Self {
        Self {
            cpus: [const { IdleCpuSlot::unavailable() }; CPU_CAPACITY],
            mailboxes: [
                RendezvousMailbox::for_cpu(cpu(0)),
                RendezvousMailbox::for_cpu(cpu(1)),
                RendezvousMailbox::for_cpu(cpu(2)),
                RendezvousMailbox::for_cpu(cpu(3)),
            ],
            ipi_latches: RendezvousIpiLatches::new(),
            faulted: AtomicBool::new(false),
        }
    }

    /// Makes one CPU eligible for idle wake targeting exactly once.
    pub(crate) fn enable(&self, cpu: CpuIndex) -> Result<(), IdleWakeError> {
        self.ensure_healthy()?;
        self.cpus[cpu.index()]
            .state
            .compare_exchange(
                CPU_UNAVAILABLE,
                CPU_ACTIVE,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| IdleWakeError::AlreadyEnabled)
    }

    /// Release-publishes intent to halt before the final scheduler rescan.
    pub(crate) fn prepare(&self, cpu: CpuIndex) -> Result<IdlePreparation, IdleWakeError> {
        self.ensure_healthy()?;
        let slot = &self.cpus[cpu.index()];
        slot.state
            .compare_exchange(
                CPU_ACTIVE,
                CPU_PREPARING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|observed| {
                if observed == CPU_UNAVAILABLE {
                    IdleWakeError::Unavailable
                } else {
                    IdleWakeError::NotActive
                }
            })?;
        let generation = match slot.mint_generation() {
            Ok(generation) => generation,
            Err(error) => {
                slot.state.store(CPU_ACTIVE, Ordering::Release);
                return Err(error);
            }
        };
        slot.generation.store(generation, Ordering::Relaxed);
        slot.state.store(CPU_PREPARING, Ordering::Release);
        Ok(IdlePreparation { cpu, generation })
    }

    /// Cancels idle publication after the scheduler rescan found work.
    pub(crate) fn cancel(&self, preparation: IdlePreparation) -> Result<(), IdleWakeError> {
        self.ensure_healthy()?;
        self.finish_transition(
            preparation.cpu,
            preparation.generation,
            CPU_PREPARING,
            CPU_ACTIVE,
        )
    }

    /// Commits the exact preparation immediately before `sti; hlt; cli`.
    pub(crate) fn commit(
        &self,
        preparation: IdlePreparation,
    ) -> Result<IdleHalt, IdleCommitFailure> {
        if let Err(error) = self.ensure_healthy() {
            return Err(IdleCommitFailure { error, preparation });
        }
        let cpu = preparation.cpu;
        let generation = preparation.generation;
        // An EOI-completed e1 may already have published its CPU-local latch
        // before we reach the architectural `sti; hlt`. Consume/rescan it in
        // the carrier path rather than entering HALTED and depending on a
        // second interrupt that need never arrive.
        if self.ipi_latches.is_pending(cpu) {
            return Err(IdleCommitFailure {
                error: IdleWakeError::RescanRequired,
                preparation,
            });
        }
        if let Err(error) = self.finish_transition(cpu, generation, CPU_PREPARING, CPU_HALTED) {
            return Err(IdleCommitFailure { error, preparation });
        }
        Ok(IdleHalt { cpu, generation })
    }

    /// Returns the executing CPU to Active after any interrupt wakes the halt.
    pub(crate) fn finish(&self, halt: IdleHalt) -> Result<(), IdleWakeError> {
        self.ensure_healthy()?;
        self.finish_transition(halt.cpu, halt.generation, CPU_HALTED, CPU_ACTIVE)
    }

    fn finish_transition(
        &self,
        cpu: CpuIndex,
        generation: u64,
        expected: u8,
        next: u8,
    ) -> Result<(), IdleWakeError> {
        let slot = &self.cpus[cpu.index()];
        if generation == 0 || slot.generation.load(Ordering::Acquire) != generation {
            return Err(IdleWakeError::StalePreparation);
        }
        slot.state
            .compare_exchange(expected, next, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| IdleWakeError::StalePreparation)
    }

    /// Selects one eligible idle CPU whose mailbox does not already hold Wake,
    /// and publishes Wake before the caller emits e1. The publisher is
    /// excluded: an interrupting publisher is already executing and will
    /// rescan before returning to halt. Skipping claimed mailboxes lets a
    /// bounded burst distribute rescans across all idle CPUs.
    pub(crate) fn publish_runnable(
        &self,
        publisher: CpuIndex,
    ) -> Result<Option<CpuIndex>, IdleWakeError> {
        self.ensure_healthy()?;
        for offset in 1..CPU_CAPACITY {
            let index = (publisher.index() + offset) % CPU_CAPACITY;
            let state = self.cpus[index].state.load(Ordering::Acquire);
            if matches!(state, CPU_PREPARING | CPU_HALTED)
                && self.mailboxes[index].try_publish_wake()
            {
                self.ensure_healthy()?;
                return Ok(CpuIndex::new(index));
            }
        }
        Ok(None)
    }

    /// Publishes Wake only to the CPU that still owns a Runnable Thread's
    /// physically suspended continuation. An active owner needs no IPI; an
    /// unavailable owner is a broken scheduler/carrier binding and fails
    /// closed rather than waking a non-owner that cannot claim the Thread.
    pub(crate) fn publish_affine_runnable(
        &self,
        publisher: CpuIndex,
        owner: CpuIndex,
    ) -> Result<Option<CpuIndex>, IdleWakeError> {
        self.ensure_healthy()?;
        if owner == publisher {
            return Ok(None);
        }
        match self.cpus[owner.index()].state.load(Ordering::Acquire) {
            CPU_PREPARING | CPU_HALTED => {
                self.mailboxes[owner.index()].publish_wake();
                self.ensure_healthy()?;
                Ok(Some(owner))
            }
            CPU_ACTIVE => Ok(None),
            _ => Err(IdleWakeError::Unavailable),
        }
    }

    /// Acquires the current CPU's rendezvous notification after architecture
    /// EOI. Wake never changes idle generation/state and therefore cannot make
    /// a stale e1 cancel a later preparation. Stop/HoldSafe remain pending in
    /// their owning mailbox protocol and are never acknowledged here.
    pub(crate) fn take_notification(
        &self,
        cpu: CpuIndex,
    ) -> Result<MailboxNotification, IdleWakeError> {
        self.ensure_healthy()?;
        let notification = self.mailboxes[cpu.index()].take_notification();
        self.ensure_healthy()?;
        Ok(notification)
    }

    /// Performs the only IRQ-side e1 state transition: a CPU-local atomic
    /// latch. The later carrier safe point consumes the mailbox under normal
    /// execution rules, never from the interrupt callback.
    pub(crate) fn latch_rendezvous_ipi(&self, cpu: CpuIndex) -> Result<(), IdleWakeError> {
        self.ensure_healthy()?;
        if self.cpus[cpu.index()].state.load(Ordering::Acquire) == CPU_UNAVAILABLE {
            return Err(IdleWakeError::Unavailable);
        }
        self.ipi_latches.latch(cpu);
        Ok(())
    }

    /// Consumes a post-EOI latch and then acquires the exact mailbox state at
    /// a carrier-owned safe point. A missed/late duplicate e1 is harmless:
    /// the mailbox stays authoritative and the latch coalesces only rescan.
    pub(crate) fn take_latched_notification(
        &self,
        cpu: CpuIndex,
    ) -> Result<MailboxNotification, IdleWakeError> {
        self.ensure_healthy()?;
        if !self.ipi_latches.take(cpu) {
            return Ok(MailboxNotification::None);
        }
        self.take_notification(cpu)
    }

    fn complete_stop_at_safe_point<T: RemoteStopSafePoint>(
        &self,
        cpu: CpuIndex,
        request: StopRequest,
        target: &mut T,
    ) -> Result<(), RemoteStopError> {
        if self.ensure_healthy().is_err()
            || self.cpus[cpu.index()].state.load(Ordering::Acquire) == CPU_UNAVAILABLE
        {
            return Err(RemoteStopError::StaleRequest);
        }
        self.mailboxes[cpu.index()].complete_stop_at_safe_point(request, target)
    }

    fn prepare_stop_at_safe_point<T: RemoteStopSafePoint>(
        &self,
        cpu: CpuIndex,
        request: StopRequest,
        target: &mut T,
    ) -> Result<ExactSafeWitness, RemoteStopError> {
        if self.ensure_healthy().is_err()
            || self.cpus[cpu.index()].state.load(Ordering::Acquire) == CPU_UNAVAILABLE
        {
            return Err(RemoteStopError::StaleRequest);
        }
        self.mailboxes[cpu.index()].prepare_stop_at_safe_point(request, target)
    }

    fn commit_prepared_stop_at_safe_point<T: RemoteStopSafePoint>(
        &self,
        cpu: CpuIndex,
        witness: ExactSafeWitness,
        target: &mut T,
    ) {
        self.mailboxes[cpu.index()].commit_prepared_stop_at_safe_point(witness, target);
    }

    pub(crate) fn fail_transport(&self) {
        self.faulted.store(true, Ordering::Release);
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), IdleWakeError> {
        if self.faulted.load(Ordering::Acquire) {
            Err(IdleWakeError::TransportFaulted)
        } else {
            Ok(())
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static LIVE_IDLE_WAKE: IdleWakeSet = IdleWakeSet::new();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn current_cpu() -> Result<CpuIndex, IdleWakeError> {
    super::syscall::current_cpu_index_for_diagnostics()
        .and_then(CpuIndex::new)
        .ok_or(IdleWakeError::Unavailable)
}

/// Enables idle-wake targeting only after the CPU has a scheduler-capable
/// execution carrier. H4 enables the BSP immediately; parked AP carriers stay
/// unavailable until H2's live shared-runtime join releases them.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn enable_live_cpu(cpu: CpuIndex) -> Result<(), IdleWakeError> {
    LIVE_IDLE_WAKE.enable(cpu)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn prepare_current_idle() -> Result<IdlePreparation, IdleWakeError> {
    LIVE_IDLE_WAKE.prepare(current_cpu()?)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn cancel_current_idle(preparation: IdlePreparation) -> Result<(), IdleWakeError> {
    if preparation.cpu() != current_cpu()? {
        return Err(IdleWakeError::StalePreparation);
    }
    LIVE_IDLE_WAKE.cancel(preparation)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn commit_current_idle(
    preparation: IdlePreparation,
) -> Result<IdleHalt, IdleCommitFailure> {
    let current = match current_cpu() {
        Ok(cpu) => cpu,
        Err(error) => return Err(IdleCommitFailure { error, preparation }),
    };
    if preparation.cpu() != current {
        return Err(IdleCommitFailure {
            error: IdleWakeError::StalePreparation,
            preparation,
        });
    }
    LIVE_IDLE_WAKE.commit(preparation)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn finish_current_idle(halt: IdleHalt) -> Result<(), IdleWakeError> {
    if halt.cpu != current_cpu()? {
        return Err(IdleWakeError::StalePreparation);
    }
    LIVE_IDLE_WAKE.finish(halt)
}

/// Publishes one coalesced e1 Wake to an eligible remote idle CPU. The
/// rendezvous mailbox is updated before transport send; a transport failure is
/// fail-stop because Runnable publication has already committed and cannot be
/// rolled back without violating the wait/start winner contract.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn notify_runnable_work(affinity: Option<CpuIndex>) {
    let Ok(publisher) = current_cpu() else {
        fail_transport_and_halt();
    };
    let target = match affinity {
        Some(owner) => LIVE_IDLE_WAKE.publish_affine_runnable(publisher, owner),
        None => LIVE_IDLE_WAKE.publish_runnable(publisher),
    };
    let Ok(target) = target else {
        fail_transport_and_halt();
    };
    let Some(target) = target else {
        return;
    };
    let registry = super::smp::live_cpu_registry();
    let Ok(snapshot) = registry.snapshot(target.index()) else {
        fail_transport_and_halt();
    };
    if super::ipi::send_live_ipi(
        snapshot.local_apic_id,
        super::ipi::LiveIpiVector::Rendezvous,
    )
    .is_err()
    {
        fail_transport_and_halt();
    }
    #[cfg(deepwyrm_i1_evidence)]
    crate::test_support::observe_i1_remote_wake_sent(publisher, target);
}

/// Release-publishes an exact Stop to one remote CPU before sending e1.
///
/// Publication failure returns the caller's linear resource. A transport
/// failure after publication is fail-stop because the target may still
/// observe the request and the deferred ownership may no longer be released.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn publish_live_remote_stop<R>(
    identity: StopIdentity,
    resource: R,
) -> Result<DeferredReclaim<R>, StopPublishFailure<R>> {
    let target = CpuIndex::new(identity.target_cpu())
        .unwrap_or_else(|| panic!("remote Stop identity names an invalid CPU"));
    assert_ne!(
        current_cpu().unwrap_or_else(|_| fail_transport_and_halt()),
        target,
        "remote Stop publisher targeted its own physical CPU"
    );
    LIVE_IDLE_WAKE
        .ensure_healthy()
        .unwrap_or_else(|_| fail_transport_and_halt());
    let snapshot = super::smp::live_cpu_registry()
        .snapshot(target.index())
        .unwrap_or_else(|_| panic!("remote Stop target is not in the live CPU registry"));
    assert_eq!(
        snapshot.online_generation,
        identity.cpu_online_generation(),
        "remote Stop target changed online generation before publication"
    );
    let deferred = LIVE_IDLE_WAKE.mailboxes[target.index()].publish_stop(identity, resource)?;
    if super::ipi::send_live_ipi(
        snapshot.local_apic_id,
        super::ipi::LiveIpiVector::Rendezvous,
    )
    .is_err()
    {
        LIVE_IDLE_WAKE.mailboxes[target.index()]
            .retain_after_failure(&deferred, DeferredFailure::Transport)
            .unwrap_or_else(|_| panic!("remote Stop transport failure lost mailbox ownership"));
        core::mem::forget(deferred);
        fail_transport_and_halt();
    }
    Ok(deferred)
}

/// Acquire-consumes one exact-safe acknowledgement before returning the
/// caller's deferred resource. The bounded failure path retains the mailbox
/// witness and fails stop; it never turns a timeout into permission to reclaim.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn await_live_remote_stop<R>(
    mut deferred: DeferredReclaim<R>,
) -> (R, RemoteStopReclaimPermit) {
    let identity = deferred.request().identity();
    let target = CpuIndex::new(identity.target_cpu())
        .unwrap_or_else(|| panic!("deferred remote Stop names an invalid CPU"));
    let mailbox = &LIVE_IDLE_WAKE.mailboxes[target.index()];
    for _ in 0..20_000_000_u32 {
        match mailbox.complete_reclaim(deferred) {
            Ok(resource) => {
                return (
                    resource,
                    RemoteStopReclaimPermit::from_acknowledgement(identity),
                );
            }
            Err(failure) if failure.error() == ReclaimError::AwaitingAcknowledgement => {
                deferred = failure.into_deferred();
                core::hint::spin_loop();
            }
            Err(failure) => {
                deferred = failure.into_deferred();
                core::mem::forget(deferred);
                fail_transport_and_halt();
            }
        }
    }
    mailbox
        .retain_after_failure(&deferred, DeferredFailure::Timeout)
        .unwrap_or_else(|_| panic!("remote Stop timeout lost mailbox ownership"));
    core::mem::forget(deferred);
    fail_transport_and_halt()
}

/// Bounded e1 receive callback: publish a CPU-local latch after EOI. It does
/// not take scheduler, mailbox, usercopy, timer, or finalization authority.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn latch_current_rendezvous_ipi() {
    let Ok(cpu) = current_cpu() else {
        fail_transport_and_halt();
    };
    LIVE_IDLE_WAKE
        .latch_rendezvous_ipi(cpu)
        .unwrap_or_else(|_| fail_transport_and_halt());
}

/// Carrier-side e1 safe point. The caller must rescan after `Wake`; `Stop`
/// and `HoldSafe` are deliberately returned to the live carrier join rather
/// than acknowledged from interrupt context.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn take_current_latched_notification() -> MailboxNotification {
    let Ok(cpu) = current_cpu() else {
        fail_transport_and_halt();
    };
    LIVE_IDLE_WAKE
        .take_latched_notification(cpu)
        .unwrap_or_else(|_| fail_transport_and_halt())
}

/// Publishes one coalesced BSP carrier wake before a private service emits e1.
/// The mailbox remains authoritative if the IPI is delayed until after the
/// next IF-clear carrier boundary.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn publish_bsp_service_wake() -> Result<(), IdleWakeError> {
    LIVE_IDLE_WAKE.ensure_healthy()?;
    LIVE_IDLE_WAKE.mailboxes[CpuIndex::BOOTSTRAP.index()].publish_wake();
    LIVE_IDLE_WAKE.ensure_healthy()
}

/// Acquires the current CPU's mailbox directly at a carrier-owned safe point.
/// This closes the syscall-entry race where e1 is pending in the local APIC
/// while IF is already clear: the mailbox publication remains authoritative
/// even though the interrupt callback has not yet published its rescan latch.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn take_current_notification_at_safe_point() -> MailboxNotification {
    let Ok(cpu) = current_cpu() else {
        fail_transport_and_halt();
    };
    LIVE_IDLE_WAKE
        .take_notification(cpu)
        .unwrap_or_else(|_| fail_transport_and_halt())
}

/// Completes an exact Stop/HoldSafe only from the current CPU's reaper/safe
/// point.  The mailbox remains stationary; the carrier supplies the unique
/// mutable transition authority after the hard IRQ has returned.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn complete_current_rendezvous_stop<T: RemoteStopSafePoint>(
    request: StopRequest,
    target: &mut T,
) -> Result<(), RemoteStopError> {
    let cpu = current_cpu().map_err(|_| RemoteStopError::WrongIdentity)?;
    LIVE_IDLE_WAKE
        .complete_stop_at_safe_point(cpu, request, target)
        .map_err(|_| RemoteStopError::StaleRequest)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn prepare_current_rendezvous_stop<T: RemoteStopSafePoint>(
    request: StopRequest,
    target: &mut T,
) -> Result<ExactSafeWitness, RemoteStopError> {
    let cpu = current_cpu().map_err(|_| RemoteStopError::WrongIdentity)?;
    LIVE_IDLE_WAKE
        .prepare_stop_at_safe_point(cpu, request, target)
        .map_err(|_| RemoteStopError::StaleRequest)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn commit_current_rendezvous_stop<T: RemoteStopSafePoint>(
    witness: ExactSafeWitness,
    target: &mut T,
) {
    let cpu = current_cpu().unwrap_or_else(|_| fail_transport_and_halt());
    LIVE_IDLE_WAKE.commit_prepared_stop_at_safe_point(cpu, witness, target);
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn live_idle_wake_is_healthy() -> bool {
    LIVE_IDLE_WAKE.ensure_healthy().is_ok()
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn live_idle_wake_is_enabled(cpu: CpuIndex) -> bool {
    LIVE_IDLE_WAKE.cpus[cpu.index()]
        .state
        .load(Ordering::Acquire)
        != CPU_UNAVAILABLE
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn fail_transport_and_halt() -> ! {
    LIVE_IDLE_WAKE.fail_transport();
    loop {
        #[allow(
            unsafe_code,
            reason = "a committed Runnable publication with failed idle-wake transport cannot safely resume"
        )]
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    #[test]
    fn wake_before_prepare_is_observed_by_the_scheduler_rescan_not_an_ipi() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(None));

        let preparation = idle.prepare(cpu(1)).unwrap();
        idle.cancel(preparation).unwrap();
        assert_eq!(
            idle.take_notification(cpu(1)),
            Ok(MailboxNotification::None)
        );
    }

    #[test]
    fn runnable_publisher_is_never_its_own_wake_target() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        let preparation = idle.prepare(cpu(0)).unwrap();
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(None));
        assert_eq!(idle.publish_affine_runnable(cpu(0), cpu(0)), Ok(None));
        assert_eq!(
            idle.take_notification(cpu(0)),
            Ok(MailboxNotification::None)
        );
        idle.cancel(preparation).unwrap();
    }

    #[test]
    fn affine_runnable_wakes_only_its_owner_among_multiple_idle_cpus() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        idle.enable(cpu(2)).unwrap();
        let non_owner = idle.prepare(cpu(1)).unwrap();
        let owner = idle.prepare(cpu(2)).unwrap();

        assert_eq!(
            idle.publish_affine_runnable(cpu(0), cpu(2)),
            Ok(Some(cpu(2)))
        );
        assert_eq!(
            idle.take_notification(cpu(1)),
            Ok(MailboxNotification::None)
        );
        assert_eq!(
            idle.take_notification(cpu(2)),
            Ok(MailboxNotification::Wake)
        );

        idle.cancel(non_owner).unwrap();
        idle.cancel(owner).unwrap();
    }

    #[test]
    fn wake_during_prepare_is_coalesced_and_survives_halt_commit() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        let preparation = idle.prepare(cpu(1)).unwrap();
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(None));
        let halt = idle.commit(preparation).unwrap();
        assert_eq!(
            idle.take_notification(cpu(1)),
            Ok(MailboxNotification::Wake)
        );
        assert_eq!(
            idle.take_notification(cpu(1)),
            Ok(MailboxNotification::None)
        );
        idle.finish(halt).unwrap();
    }

    #[test]
    fn generic_wake_burst_claims_distinct_idle_mailboxes() {
        let idle = IdleWakeSet::new();
        for target in 0..CPU_CAPACITY {
            idle.enable(cpu(target)).unwrap();
        }
        let cpu1 = idle.prepare(cpu(1)).unwrap();
        let cpu2 = idle.prepare(cpu(2)).unwrap();
        let cpu3 = idle.prepare(cpu(3)).unwrap();

        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(2))));
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(3))));
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(None));
        for target in 1..CPU_CAPACITY {
            assert_eq!(
                idle.take_notification(cpu(target)),
                Ok(MailboxNotification::Wake)
            );
        }

        idle.cancel(cpu1).unwrap();
        idle.cancel(cpu2).unwrap();
        idle.cancel(cpu3).unwrap();
    }

    #[test]
    fn post_eoi_latch_defers_wake_consumption_to_carrier_safe_point() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        let preparation = idle.prepare(cpu(1)).unwrap();
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
        let halt = idle.commit(preparation).unwrap();

        // The IRQ callback publishes only this bit. It does not take the
        // mailbox or make a scheduler decision.
        idle.latch_rendezvous_ipi(cpu(1)).unwrap();
        assert_eq!(
            idle.take_latched_notification(cpu(1)),
            Ok(MailboxNotification::Wake)
        );
        assert_eq!(
            idle.take_latched_notification(cpu(1)),
            Ok(MailboxNotification::None)
        );
        idle.finish(halt).unwrap();
    }

    #[test]
    fn preexisting_post_eoi_latch_requires_rescan_before_halt() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        let preparation = idle.prepare(cpu(1)).unwrap();
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
        // Model an e1 handler that completed EOI before this carrier reaches
        // its final `sti; hlt` commit.
        idle.latch_rendezvous_ipi(cpu(1)).unwrap();
        let failure = idle.commit(preparation).unwrap_err();
        assert_eq!(failure.error(), IdleWakeError::RescanRequired);
        assert_eq!(
            idle.take_latched_notification(cpu(1)),
            Ok(MailboxNotification::Wake)
        );
        idle.cancel(failure.into_preparation()).unwrap();
    }

    #[test]
    fn concurrent_wake_and_halt_transition_never_loses_the_notification() {
        let idle = Arc::new(IdleWakeSet::new());
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        for _ in 0..2_000 {
            let preparation = idle.prepare(cpu(1)).unwrap();
            let start = Arc::new(Barrier::new(2));
            let publisher_idle = Arc::clone(&idle);
            let publisher_start = Arc::clone(&start);
            let publisher = thread::spawn(move || {
                publisher_start.wait();
                publisher_idle.publish_runnable(cpu(0))
            });
            start.wait();
            let halt = idle.commit(preparation).unwrap();
            assert_eq!(publisher.join().unwrap(), Ok(Some(cpu(1))));
            assert_eq!(
                idle.take_notification(cpu(1)),
                Ok(MailboxNotification::Wake)
            );
            idle.finish(halt).unwrap();
        }
    }

    #[test]
    fn stale_preparation_cannot_cancel_a_later_generation() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(2)).unwrap();
        let first = idle.prepare(cpu(2)).unwrap();
        let first_generation = first.generation;
        idle.cancel(first).unwrap();
        let second = idle.prepare(cpu(2)).unwrap();
        assert_ne!(first_generation, second.generation);
        assert_eq!(
            idle.finish_transition(cpu(2), first_generation, CPU_PREPARING, CPU_ACTIVE),
            Err(IdleWakeError::StalePreparation)
        );
        idle.cancel(second).unwrap();
    }

    #[test]
    fn ambiguous_wake_transport_fault_survives_late_delivery() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        let preparation = idle.prepare(cpu(1)).unwrap();
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
        let halt = idle.commit(preparation).unwrap();
        idle.fail_transport();
        assert_eq!(
            idle.take_notification(cpu(1)),
            Err(IdleWakeError::TransportFaulted)
        );
        assert_eq!(
            idle.prepare(cpu(0)).unwrap_err(),
            IdleWakeError::TransportFaulted
        );
        assert_eq!(idle.finish(halt), Err(IdleWakeError::TransportFaulted));
    }

    #[test]
    fn concurrent_late_wake_delivery_cannot_clear_transport_fault() {
        for _ in 0..2_000 {
            let idle = Arc::new(IdleWakeSet::new());
            idle.enable(cpu(0)).unwrap();
            idle.enable(cpu(1)).unwrap();
            let preparation = idle.prepare(cpu(1)).unwrap();
            assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
            let _halt = idle.commit(preparation).unwrap();
            let start = Arc::new(Barrier::new(3));
            let receiver_idle = Arc::clone(&idle);
            let receiver_start = Arc::clone(&start);
            let receiver = thread::spawn(move || {
                receiver_start.wait();
                receiver_idle.take_notification(cpu(1))
            });
            let sender_idle = Arc::clone(&idle);
            let sender_start = Arc::clone(&start);
            let sender = thread::spawn(move || {
                sender_start.wait();
                sender_idle.fail_transport();
            });
            start.wait();
            sender.join().unwrap();
            let _possibly_consumed_before_fault = receiver.join().unwrap();
            assert_eq!(idle.ensure_healthy(), Err(IdleWakeError::TransportFaulted));
            assert_eq!(
                idle.take_notification(cpu(1)),
                Err(IdleWakeError::TransportFaulted)
            );
        }
    }
}
