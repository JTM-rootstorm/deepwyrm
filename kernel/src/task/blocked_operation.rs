use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::IrqSpinMutex;
use deepwyrm_abi::DwSignals;

use super::{BlockWakeKey, ProcessKey, ThreadKey};

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockedOperationWinner {
    Signal {
        item_index: u32,
        observed: DwSignals,
    },
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
            .find(|(_, slot)| slot.entry.is_none())
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

    pub(crate) fn drained(
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
        })
    }

    pub(crate) fn validate_drained(
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
}

impl<RESOURCES> BlockedOperation<RESOURCES> {
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
            }),
            Err(error) => Err((error, resources)),
        }
    }

    pub(crate) fn wake_key(&self) -> BlockWakeKey {
        self.reservation
            .as_ref()
            .expect("blocked operation is live")
            .wake
    }

    pub(crate) fn complete_with<const CAPACITY: usize, RESULT>(
        mut self,
        registry: &BlockedOperationRegistry<CAPACITY>,
        _winner: BlockedOperationWinner,
        cleanup: impl FnOnce(RESOURCES) -> RESULT,
    ) -> Result<RESULT, BlockedOperationError> {
        let reservation = self
            .reservation
            .as_ref()
            .expect("blocked operation reservation is live");
        let claimed = registry.try_claim_winner(reservation.wake, _winner)?;
        if !claimed && registry.winner(reservation.wake)? != Some(_winner) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
    use crate::memory::usercopy::{UserPinError, UserPinTracker};
    use crate::object::ObjectRegistry;
    use crate::task::CooperativeScheduler;
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
        let pin = pins.pin(range).unwrap();
        let operation = match BlockedOperation::publish(&registry, process, thread, wake, pin) {
            Ok(operation) => operation,
            Err((error, _pin)) => panic!("blocked-operation publication failed: {error:?}"),
        };
        assert_eq!(
            pins.begin_mutation(0x2000, 0x1000).err(),
            Some(UserPinError::Conflict)
        );
        operation
            .complete_with(&registry, BlockedOperationWinner::Terminal, drop)
            .unwrap();
        let permit = pins.begin_mutation(0x2000, 0x1000).unwrap();
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
