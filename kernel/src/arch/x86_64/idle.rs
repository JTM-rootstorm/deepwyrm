//! Generation-bound idle publication and coalesced e1 wake selection for H4.
//!
//! This layer does not schedule. A CPU publishes `Preparing` before its final
//! scheduler rescan, commits `Halted` immediately before the architectural
//! `sti; hlt; cli`, and returns to `Active` after any interrupt. A Runnable
//! publisher only selects one already-idle eligible CPU and publishes the
//! existing rendezvous-mailbox `Wake` notification before sending e1.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::cpu::{CPU_CAPACITY, CpuIndex};

use super::rendezvous::{MailboxNotification, RendezvousMailbox};

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
    pub(crate) fn commit(&self, preparation: IdlePreparation) -> Result<IdleHalt, IdleWakeError> {
        self.ensure_healthy()?;
        let cpu = preparation.cpu;
        let generation = preparation.generation;
        self.finish_transition(cpu, generation, CPU_PREPARING, CPU_HALTED)?;
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

    /// Selects one eligible idle CPU and publishes a coalesced Wake before the
    /// caller emits e1. The publisher is excluded: an interrupting publisher
    /// is already executing and will rescan before returning to halt.
    pub(crate) fn publish_runnable(
        &self,
        publisher: CpuIndex,
    ) -> Result<Option<CpuIndex>, IdleWakeError> {
        self.ensure_healthy()?;
        for offset in 1..CPU_CAPACITY {
            let index = (publisher.index() + offset) % CPU_CAPACITY;
            let state = self.cpus[index].state.load(Ordering::Acquire);
            if matches!(state, CPU_PREPARING | CPU_HALTED) {
                self.mailboxes[index].publish_wake();
                self.ensure_healthy()?;
                return Ok(CpuIndex::new(index));
            }
        }
        Ok(None)
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
pub(crate) fn commit_current_idle(preparation: IdlePreparation) -> Result<IdleHalt, IdleWakeError> {
    if preparation.cpu() != current_cpu()? {
        return Err(IdleWakeError::StalePreparation);
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
pub(crate) fn notify_runnable_work() {
    let Ok(publisher) = current_cpu() else {
        fail_transport_and_halt();
    };
    let Ok(target) = LIVE_IDLE_WAKE.publish_runnable(publisher) else {
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
}

/// Consumes only the current CPU's coalesced Wake notification after EOI.
/// Stop and HoldSafe remain visible to their exact rendezvous owner.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn take_current_notification() -> MailboxNotification {
    let Ok(cpu) = current_cpu() else {
        fail_transport_and_halt();
    };
    LIVE_IDLE_WAKE
        .take_notification(cpu)
        .unwrap_or_else(|_| fail_transport_and_halt())
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn live_idle_wake_is_healthy() -> bool {
    LIVE_IDLE_WAKE.ensure_healthy().is_ok()
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
        idle.cancel(preparation).unwrap();
    }

    #[test]
    fn wake_during_prepare_is_coalesced_and_survives_halt_commit() {
        let idle = IdleWakeSet::new();
        idle.enable(cpu(0)).unwrap();
        idle.enable(cpu(1)).unwrap();
        let preparation = idle.prepare(cpu(1)).unwrap();
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
        assert_eq!(idle.publish_runnable(cpu(0)), Ok(Some(cpu(1))));
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
