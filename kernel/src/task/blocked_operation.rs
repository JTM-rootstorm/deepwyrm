use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::IrqSpinMutex;
use deepwyrm_abi::DwSignals;

use super::{
    BlockWakeKey, ProcessKey, ProcessOperationLease, ProcessQuiescenceProof, TaskAuthority,
    ThreadKey,
};

static NEXT_BLOCKED_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_domain() -> u64 {
    NEXT_BLOCKED_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .expect("blocked-operation domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockedOperationError {
    Capacity,
    DuplicateThread,
    ForeignReservation,
    StaleReservation,
    ProcessStillBlocked,
    WinnerMismatch,
    Task(super::TaskError),
    OperationLeaseRequired,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    entry: Option<Entry>,
}

#[derive(Clone, Copy)]
struct Entry {
    process: ProcessKey,
    thread: ThreadKey,
    wake: BlockWakeKey,
    winner: Option<BlockedOperationWinner>,
}

const EMPTY_SLOT: Slot = Slot {
    generation: 0,
    entry: None,
};

#[must_use = "blocked-operation reservations must be completed before execution resources are reclaimed"]
pub(crate) struct BlockedOperationReservation {
    domain: u64,
    slot: u16,
    generation: u32,
    process: ProcessKey,
    thread: ThreadKey,
    wake: BlockWakeKey,
}

#[must_use = "root retirement requires proof that the matching blocked-operation registry is drained"]
pub(crate) struct BlockedOperationsDrained {
    domain: u64,
    process: ProcessKey,
    task_domain: Option<u64>,
    task_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockedOperationWinner {
    Signal {
        item_index: u32,
        observed: DwSignals,
    },
    /// A userspace atomic-wait key was selected by `atomic_wake`.
    ///
    /// This is intentionally distinct from object-signal completion: atomic
    /// waiters return successfully without treating the userspace predicate as
    /// a kernel-managed signal state.
    AtomicWake,
    Timeout,
    Cancelled,
    Terminal,
}

pub(crate) struct BlockedOperationRegistry<const CAPACITY: usize> {
    domain: u64,
    slots: IrqSpinMutex<[Slot; CAPACITY]>,
}

impl<const CAPACITY: usize> BlockedOperationRegistry<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_domain(),
            slots: IrqSpinMutex::new([EMPTY_SLOT; CAPACITY]),
        }
    }

    fn reserve(
        &self,
        process: ProcessKey,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<BlockedOperationReservation, BlockedOperationError> {
        let mut slots = self.slots.lock();
        if slots
            .iter()
            .any(|slot| slot.entry.is_some_and(|entry| entry.thread == thread))
        {
            return Err(BlockedOperationError::DuplicateThread);
        }
        let (index, slot) = slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.entry.is_none() && slot.generation != u32::MAX)
            .ok_or(BlockedOperationError::Capacity)?;
        let generation = slot
            .generation
            .checked_add(1)
            .filter(|value| *value != 0)
            .ok_or(BlockedOperationError::Capacity)?;
        slot.generation = generation;
        slot.entry = Some(Entry {
            process,
            thread,
            wake,
            winner: None,
        });
        Ok(BlockedOperationReservation {
            domain: self.domain,
            slot: u16::try_from(index).map_err(|_| BlockedOperationError::Capacity)?,
            generation,
            process,
            thread,
            wake,
        })
    }

    fn complete(
        &self,
        reservation: BlockedOperationReservation,
    ) -> Result<(), BlockedOperationError> {
        if reservation.domain != self.domain {
            return Err(BlockedOperationError::ForeignReservation);
        }
        let mut slots = self.slots.lock();
        let slot = slots
            .get_mut(usize::from(reservation.slot))
            .ok_or(BlockedOperationError::StaleReservation)?;
        if slot.generation != reservation.generation
            || !slot.entry.is_some_and(|entry| {
                entry.process == reservation.process
                    && entry.thread == reservation.thread
                    && entry.wake == reservation.wake
            })
        {
            return Err(BlockedOperationError::StaleReservation);
        }
        slot.entry = None;
        Ok(())
    }

    /// Claims one terminal outcome for an exact scheduler block generation.
    ///
    /// Signal, timeout, cancellation, and terminal retirement all contend on
    /// this single ledger. The first claim wins; later contenders observe
    /// `Ok(false)` and must not wake the scheduler again.
    pub(crate) fn try_claim_winner(
        &self,
        wake: BlockWakeKey,
        winner: BlockedOperationWinner,
    ) -> Result<bool, BlockedOperationError> {
        let mut slots = self.slots.lock();
        let entry = slots
            .iter_mut()
            .filter_map(|slot| slot.entry.as_mut())
            .find(|entry| entry.wake == wake)
            .ok_or(BlockedOperationError::StaleReservation)?;
        if entry.winner.is_some() {
            return Ok(false);
        }
        entry.winner = Some(winner);
        Ok(true)
    }

    pub(crate) fn winner(
        &self,
        wake: BlockWakeKey,
    ) -> Result<Option<BlockedOperationWinner>, BlockedOperationError> {
        self.slots
            .lock()
            .iter()
            .filter_map(|slot| slot.entry.as_ref())
            .find(|entry| entry.wake == wake)
            .map(|entry| entry.winner)
            .ok_or(BlockedOperationError::StaleReservation)
    }

    pub(crate) fn has_thread(&self, thread: ThreadKey) -> bool {
        self.slots
            .lock()
            .iter()
            .any(|slot| slot.entry.is_some_and(|entry| entry.thread == thread))
    }

    fn drained_inner(
        &self,
        process: ProcessKey,
    ) -> Result<BlockedOperationsDrained, BlockedOperationError> {
        if self
            .slots
            .lock()
            .iter()
            .any(|slot| slot.entry.is_some_and(|entry| entry.process == process))
        {
            return Err(BlockedOperationError::ProcessStillBlocked);
        }
        Ok(BlockedOperationsDrained {
            domain: self.domain,
            process,
            task_domain: None,
            task_generation: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn drained(
        &self,
        process: ProcessKey,
    ) -> Result<BlockedOperationsDrained, BlockedOperationError> {
        self.drained_inner(process)
    }

    pub(crate) fn drained_after_quiesce<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        proof: &ProcessQuiescenceProof,
    ) -> Result<BlockedOperationsDrained, BlockedOperationError> {
        tasks
            .validate_process_quiescence(proof, proof.process)
            .map_err(BlockedOperationError::Task)?;
        let mut drained = self.drained_inner(proof.process)?;
        drained.task_domain = Some(proof.authority_domain);
        drained.task_generation = Some(proof.generation);
        Ok(drained)
    }

    fn validate_drained_inner(
        &self,
        proof: &BlockedOperationsDrained,
        process: ProcessKey,
    ) -> Result<(), BlockedOperationError> {
        if proof.domain != self.domain || proof.process != process {
            return Err(BlockedOperationError::ForeignReservation);
        }
        if self
            .slots
            .lock()
            .iter()
            .any(|slot| slot.entry.is_some_and(|entry| entry.process == process))
        {
            return Err(BlockedOperationError::ProcessStillBlocked);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validate_drained(
        &self,
        proof: &BlockedOperationsDrained,
        process: ProcessKey,
    ) -> Result<(), BlockedOperationError> {
        self.validate_drained_inner(proof, process)
    }

    pub(crate) fn validate_drained_after_quiesce<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        proof: &ProcessQuiescenceProof,
        drained: &BlockedOperationsDrained,
    ) -> Result<(), BlockedOperationError> {
        tasks
            .validate_process_quiescence(proof, proof.process)
            .map_err(BlockedOperationError::Task)?;
        if drained.task_domain != Some(proof.authority_domain)
            || drained.task_generation != Some(proof.generation)
        {
            return Err(BlockedOperationError::ForeignReservation);
        }
        self.validate_drained_inner(drained, proof.process)
    }
}

/// One move-only owner for every resource that survives a blocking suspension.
///
/// `RESOURCES` is the syscall-specific bundle containing user/mapping pins, wait
/// registration, deadline registration, uncommitted output authority, and root
/// lifetime pin. F4/F7/F9 must place all such resources in this bundle rather
/// than publishing independent cleanup paths.
#[must_use = "a blocked operation must complete exactly once before its kernel stack can be reclaimed"]
pub(crate) struct BlockedOperation<RESOURCES> {
    reservation: Option<BlockedOperationReservation>,
    resources: Option<RESOURCES>,
    process_lease: Option<ProcessOperationLease>,
}

impl<RESOURCES> BlockedOperation<RESOURCES> {
    #[cfg(test)]
    pub(crate) fn publish<const CAPACITY: usize>(
        registry: &BlockedOperationRegistry<CAPACITY>,
        process: ProcessKey,
        thread: ThreadKey,
        wake: BlockWakeKey,
        resources: RESOURCES,
    ) -> Result<Self, (BlockedOperationError, RESOURCES)> {
        match registry.reserve(process, thread, wake) {
            Ok(reservation) => Ok(Self {
                reservation: Some(reservation),
                resources: Some(resources),
                process_lease: None,
            }),
            Err(error) => Err((error, resources)),
        }
    }

    /// Acquires and retains process-operation authority across block
    /// publication. No TaskAuthority borrow or registry lock survives return.
    pub(crate) fn publish_for_process<
        const CAPACITY: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        registry: &BlockedOperationRegistry<CAPACITY>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        process: ProcessKey,
        thread: ThreadKey,
        wake: BlockWakeKey,
        resources: RESOURCES,
    ) -> Result<Self, (BlockedOperationError, RESOURCES)> {
        let lease = match tasks.acquire_process_operation(process) {
            Ok(lease) => lease,
            Err(error) => return Err((BlockedOperationError::Task(error), resources)),
        };
        Self::publish_with_process_lease(registry, tasks, lease, process, thread, wake, resources)
    }

    /// Publishes a block using authority acquired after any user access and
    /// before process-owned setup. The lease moves into the durable operation
    /// owner on success and is released on every publication failure.
    pub(crate) fn publish_with_process_lease<
        const CAPACITY: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        registry: &BlockedOperationRegistry<CAPACITY>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        lease: ProcessOperationLease,
        process: ProcessKey,
        thread: ThreadKey,
        wake: BlockWakeKey,
        resources: RESOURCES,
    ) -> Result<Self, (BlockedOperationError, RESOURCES)> {
        if let Err(error) = tasks.validate_process_operation(&lease, process) {
            tasks
                .release_process_operation(lease)
                .unwrap_or_else(|(release_error, _)| {
                    panic!("invalid block lease could not be released: {release_error:?}")
                });
            return Err((BlockedOperationError::Task(error), resources));
        }
        match registry.reserve(process, thread, wake) {
            Ok(reservation) => Ok(Self {
                reservation: Some(reservation),
                resources: Some(resources),
                process_lease: Some(lease),
            }),
            Err(error) => {
                tasks
                    .release_process_operation(lease)
                    .unwrap_or_else(|(task_error, _)| {
                        panic!("failed block publication leaked operation lease: {task_error:?}")
                    });
                Err((error, resources))
            }
        }
    }

    pub(crate) fn wake_key(&self) -> BlockWakeKey {
        self.reservation
            .as_ref()
            .expect("blocked operation is live")
            .wake
    }

    #[cfg(test)]
    pub(crate) const fn has_process_lease(&self) -> bool {
        self.process_lease.is_some()
    }

    #[cfg(test)]
    pub(crate) fn complete_with<const CAPACITY: usize, RESULT>(
        self,
        registry: &BlockedOperationRegistry<CAPACITY>,
        _winner: BlockedOperationWinner,
        cleanup: impl FnOnce(RESOURCES) -> RESULT,
    ) -> Result<RESULT, BlockedOperationError> {
        if self.process_lease.is_some() {
            return Err(BlockedOperationError::OperationLeaseRequired);
        }
        self.complete_inner(registry, _winner, cleanup)
    }

    pub(crate) fn complete_for_process<
        const CAPACITY: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        RESULT,
    >(
        mut self,
        registry: &BlockedOperationRegistry<CAPACITY>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        winner: BlockedOperationWinner,
        cleanup: impl FnOnce(RESOURCES) -> RESULT,
    ) -> Result<RESULT, BlockedOperationError> {
        let lease = self
            .process_lease
            .take()
            .ok_or(BlockedOperationError::OperationLeaseRequired)?;
        let result = self.complete_inner(registry, winner, cleanup)?;
        tasks
            .release_process_operation(lease)
            .map_err(|(error, _)| BlockedOperationError::Task(error))?;
        Ok(result)
    }

    fn complete_inner<const CAPACITY: usize, RESULT>(
        mut self,
        registry: &BlockedOperationRegistry<CAPACITY>,
        winner: BlockedOperationWinner,
        cleanup: impl FnOnce(RESOURCES) -> RESULT,
    ) -> Result<RESULT, BlockedOperationError> {
        let reservation = self
            .reservation
            .as_ref()
            .expect("blocked operation reservation is live");
        let claimed = registry.try_claim_winner(reservation.wake, winner)?;
        if !claimed && registry.winner(reservation.wake)? != Some(winner) {
            return Err(BlockedOperationError::WinnerMismatch);
        }
        let resources = self
            .resources
            .take()
            .expect("blocked operation resources are live");
        let result = cleanup(resources);
        let reservation = self
            .reservation
            .take()
            .expect("blocked operation reservation is live");
        registry.complete(reservation)?;
        Ok(result)
    }
}

impl<RESOURCES> Drop for BlockedOperation<RESOURCES> {
    fn drop(&mut self) {
        assert!(
            self.reservation.is_none() && self.resources.is_none(),
            "live blocked operation dropped without signal/timeout/cancel/terminal completion"
        );
        assert!(
            self.process_lease.is_none(),
            "live blocked operation dropped with a process-operation lease"
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
    use crate::memory::usercopy::{UserPinError, UserPinTracker};
    use crate::object::ObjectRegistry;
    use crate::task::{
        CooperativeScheduler, ProcessGateError, ProcessLifecycleState, TaskAuthority,
    };
    use deepwyrm_abi::{DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD};

    fn keys() -> (ProcessKey, ThreadKey, BlockWakeKey) {
        let mut objects = ObjectRegistry::<4>::new();
        let process = objects.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let thread = objects.create(DW_OBJECT_TYPE_THREAD).unwrap();
        let process_key = ProcessKey::from_object_id(process.id());
        let thread_key = ThreadKey::from_object_id(thread.id());
        objects.cancel_creation(process).unwrap();
        objects.cancel_creation(thread).unwrap();
        let scheduler = CooperativeScheduler::<1>::new();
        let reservation = scheduler.reserve(thread_key).unwrap();
        scheduler.commit(reservation).unwrap();
        scheduler.schedule_next().unwrap();
        let (blocked, _) = scheduler.block_current(thread_key).unwrap();
        (process_key, thread_key, blocked.into_wake_key())
    }

    #[test]
    fn terminal_cleanup_precedes_drained_root_proof() {
        let (process, thread, wake) = keys();
        let registry = BlockedOperationRegistry::<2>::new();
        let operation = BlockedOperation::publish(&registry, process, thread, wake, 7_u64).unwrap();
        assert_eq!(
            registry.drained(process).err(),
            Some(BlockedOperationError::ProcessStillBlocked)
        );
        let result = operation
            .complete_with(&registry, BlockedOperationWinner::Terminal, |resource| {
                resource + 1
            })
            .unwrap();
        assert_eq!(result, 8);
        let proof = registry.drained(process).unwrap();
        assert!(registry.validate_drained(&proof, process).is_ok());
    }

    #[test]
    fn block_publication_lease_closes_before_quiesced_drain_proof() {
        let mut objects = ObjectRegistry::<8>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let (_root, root_owner) = tasks.create_root_group(&mut objects).unwrap();
        let (process, process_handle) = tasks.create_process(&mut objects, &root_owner).unwrap();
        let process_pin = objects
            .retain_internal_from_handle(&process_handle)
            .unwrap();
        let (thread, _thread_handle) = tasks.create_thread(&mut objects, &process_pin).unwrap();
        assert!(objects.release_internal(process_pin).unwrap().is_none());

        let scheduler = CooperativeScheduler::<1>::new();
        scheduler
            .commit(scheduler.reserve(thread).unwrap())
            .unwrap();
        scheduler.schedule_next().unwrap();
        let (blocked, _) = scheduler.block_current(thread).unwrap();
        let wake = blocked.into_wake_key();
        let registry = BlockedOperationRegistry::<1>::new();
        let operation = BlockedOperation::publish_for_process(
            &registry, &mut tasks, process, thread, wake, 0x55_u64,
        )
        .unwrap();

        assert_eq!(
            tasks.begin_process_quiesce(process),
            Err(ProcessGateError::OperationsInFlight)
        );
        assert_eq!(
            tasks.process_lifecycle(process),
            Ok(ProcessLifecycleState::Quiescing)
        );
        assert_eq!(
            registry.drained(process).err(),
            Some(BlockedOperationError::ProcessStillBlocked)
        );
        assert_eq!(
            operation
                .complete_for_process(
                    &registry,
                    &mut tasks,
                    BlockedOperationWinner::Terminal,
                    |resource| resource + 1,
                )
                .unwrap(),
            0x56
        );
        let proof = tasks.begin_process_quiesce(process).unwrap();
        let drained = registry.drained_after_quiesce(&tasks, &proof).unwrap();
        assert!(
            registry
                .validate_drained_after_quiesce(&tasks, &proof, &drained)
                .is_ok()
        );
    }

    #[test]
    fn signal_timeout_and_cancel_completion_each_release_the_exact_generation() {
        for winner in [
            BlockedOperationWinner::Signal {
                item_index: 0,
                observed: DwSignals(1),
            },
            BlockedOperationWinner::Timeout,
            BlockedOperationWinner::Cancelled,
        ] {
            let (process, thread, wake) = keys();
            let registry = BlockedOperationRegistry::<1>::new();
            let operation =
                BlockedOperation::publish(&registry, process, thread, wake, ()).unwrap();
            operation.complete_with(&registry, winner, |_| ()).unwrap();
            assert!(!registry.has_thread(thread));
            assert!(registry.drained(process).is_ok());
        }
    }

    #[test]
    fn blocked_operation_holds_mapping_pin_until_terminal_cleanup() {
        let (process, thread, wake) = keys();
        let registry = BlockedOperationRegistry::<1>::new();
        let pins = UserPinTracker::<1>::new();
        let space = UserAddressSpace::new(0x1000, 0x10_000, 0x1000).unwrap();
        let range = UserRange::new(
            space,
            0x2000,
            0x1000,
            1,
            UserAccess::WRITE,
            EmptyAddressRule::Reject,
        )
        .unwrap();
        let address_space = crate::memory::address_region::AddressSpaceKey::for_test(1, 1);
        let pin = pins.pin(address_space, range).unwrap();
        let operation = match BlockedOperation::publish(&registry, process, thread, wake, pin) {
            Ok(operation) => operation,
            Err((error, _pin)) => panic!("blocked-operation publication failed: {error:?}"),
        };
        assert_eq!(
            pins.begin_mutation(address_space, 0x2000, 0x1000).err(),
            Some(UserPinError::Conflict)
        );
        operation
            .complete_with(&registry, BlockedOperationWinner::Terminal, drop)
            .unwrap();
        let permit = pins.begin_mutation(address_space, 0x2000, 0x1000).unwrap();
        drop(permit);
    }

    #[test]
    fn capacity_failure_returns_unpublished_resources_without_stranding_state() {
        let (process, first_thread, first_wake) = keys();
        let (_, second_thread, second_wake) = keys();
        let registry = BlockedOperationRegistry::<1>::new();
        let first =
            BlockedOperation::publish(&registry, process, first_thread, first_wake, 0x11_u64)
                .unwrap();
        let (error, resource) = match BlockedOperation::publish(
            &registry,
            process,
            second_thread,
            second_wake,
            0x22_u64,
        ) {
            Ok(_) => panic!("capacity-one registry accepted a second live operation"),
            Err(failure) => failure,
        };
        assert_eq!(error, BlockedOperationError::Capacity);
        assert_eq!(resource, 0x22);
        assert!(!registry.has_thread(second_thread));
        first
            .complete_with(&registry, BlockedOperationWinner::Terminal, |_| ())
            .unwrap();
        assert!(registry.drained(process).is_ok());
    }

    #[test]
    fn exhausted_empty_slot_is_skipped_without_wedging_remaining_capacity() {
        let (process, thread, wake) = keys();
        let registry = BlockedOperationRegistry::<2>::new();
        registry.slots.lock()[0].generation = u32::MAX;

        let operation = BlockedOperation::publish(&registry, process, thread, wake, ()).unwrap();
        assert_eq!(
            operation
                .reservation
                .as_ref()
                .expect("published operation owns a reservation")
                .slot,
            1
        );
        operation
            .complete_with(&registry, BlockedOperationWinner::Terminal, |_| ())
            .unwrap();
        assert!(registry.drained(process).is_ok());
    }

    #[test]
    fn exact_block_generation_accepts_only_one_winner() {
        let (process, thread, wake) = keys();
        let registry = BlockedOperationRegistry::<1>::new();
        let operation = BlockedOperation::publish(&registry, process, thread, wake, ()).unwrap();
        let signal = BlockedOperationWinner::Signal {
            item_index: 3,
            observed: DwSignals(0x55),
        };
        assert_eq!(registry.try_claim_winner(wake, signal), Ok(true));
        assert_eq!(registry.winner(wake), Ok(Some(signal)));
        assert_eq!(
            registry.try_claim_winner(wake, BlockedOperationWinner::Timeout),
            Ok(false)
        );
        assert_eq!(operation.complete_with(&registry, signal, |_| ()), Ok(()));
    }

    #[test]
    fn h4_cross_cpu_signal_timeout_race_has_one_exact_winner() {
        for iteration in 0..2_000 {
            let (process, thread_key, wake) = keys();
            let registry = Arc::new(BlockedOperationRegistry::<1>::new());
            let operation =
                BlockedOperation::publish(&registry, process, thread_key, wake, iteration).unwrap();
            let signal = BlockedOperationWinner::Signal {
                item_index: 2,
                observed: DwSignals(0x40),
            };
            let start = Arc::new(Barrier::new(3));
            let signal_registry = Arc::clone(&registry);
            let signal_start = Arc::clone(&start);
            let signal_worker = thread::spawn(move || {
                signal_start.wait();
                signal_registry.try_claim_winner(wake, signal)
            });
            let timeout_registry = Arc::clone(&registry);
            let timeout_start = Arc::clone(&start);
            let timeout_worker = thread::spawn(move || {
                timeout_start.wait();
                timeout_registry.try_claim_winner(wake, BlockedOperationWinner::Timeout)
            });
            start.wait();
            let signal_won = signal_worker.join().unwrap().unwrap();
            let timeout_won = timeout_worker.join().unwrap().unwrap();
            assert_ne!(signal_won, timeout_won, "iteration={iteration}");
            let winner = registry.winner(wake).unwrap().unwrap();
            assert_eq!(
                winner,
                if signal_won {
                    signal
                } else {
                    BlockedOperationWinner::Timeout
                }
            );
            assert_eq!(
                operation.complete_with(&registry, winner, core::convert::identity),
                Ok(iteration)
            );
            assert!(!registry.has_thread(thread_key));
        }
    }

    #[test]
    fn preclaimed_signal_completes_with_exact_observation() {
        let (process, thread, wake) = keys();
        let registry = BlockedOperationRegistry::<1>::new();
        let operation = BlockedOperation::publish(&registry, process, thread, wake, 9_u32).unwrap();
        let winner = BlockedOperationWinner::Signal {
            item_index: 1,
            observed: DwSignals(0x20),
        };
        assert_eq!(registry.try_claim_winner(wake, winner), Ok(true));
        assert_eq!(
            operation.complete_with(&registry, winner, |value| value + 1),
            Ok(10)
        );
        assert!(!registry.has_thread(thread));
    }
}
