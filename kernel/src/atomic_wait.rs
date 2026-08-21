//! Bounded stable-key registration for DW0-F9 atomic wait/wake.
//!
//! This module owns the address-independent wait-key index only.  A blocked
//! waiter remains durably owned by [`AtomicWaitOperation`]; the shared
//! `BlockedOperationRegistry` remains the sole winner ledger for every exact
//! scheduler block generation.

use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::DW_ATOMIC_WAKE_ALL;

pub(crate) use crate::memory::address_region::AtomicWaitKey;
use crate::sync::IrqSpinMutex;
use crate::task::{
    BlockWakeKey, BlockedOperation, BlockedOperationError, BlockedOperationRegistry,
    BlockedOperationWinner, ExecutionDomain, ProcessKey, ScheduleDecision, SchedulerError,
    ThreadKey,
};
use crate::time::DeadlineRegistration;
use crate::wait::engine::{WaitDeadline, WaitDeadlineAuthority, WaitDeadlineError};

static NEXT_ATOMIC_WAIT_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_domain() -> u64 {
    NEXT_ATOMIC_WAIT_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .expect("atomic-wait registry domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicWaitError {
    Capacity,
    DuplicateThread,
    ForeignRegistration,
    StaleRegistration,
    Blocked(BlockedOperationError),
}

#[derive(Clone, Copy)]
struct AtomicWaitEntry {
    key: AtomicWaitKey,
    wake: BlockWakeKey,
    sequence: u64,
}

#[derive(Clone, Copy)]
struct AtomicWaitSlot {
    generation: u32,
    entry: Option<AtomicWaitEntry>,
}

const EMPTY_SLOT: AtomicWaitSlot = AtomicWaitSlot {
    generation: 0,
    entry: None,
};

/// Exact, generation-protected ownership of one atomic-key registration.
///
/// This is a lightweight identity token, not the pin that keeps the referenced
/// userspace word alive.  The matching [`AtomicWaitOperation`] owns that pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AtomicWaitRegistration {
    domain: u64,
    slot: u16,
    generation: u32,
    key: AtomicWaitKey,
    wake: BlockWakeKey,
}

impl AtomicWaitRegistration {
    pub(crate) const fn key(self) -> AtomicWaitKey {
        self.key
    }

    pub(crate) const fn wake_key(self) -> BlockWakeKey {
        self.wake
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicWaitRegisterOutcome {
    Mismatch { observed: u32 },
    Registered(AtomicWaitRegistration),
}

/// Bounded set of exact scheduler generations selected by one `atomic_wake`.
///
/// Callers must issue the scheduler wake only after the registry lock is
/// released by consuming this batch.
#[must_use = "atomic wake batches must be dispatched after registration arbitration"]
pub(crate) struct AtomicWakeBatch<const CAPACITY: usize> {
    wakes: [Option<BlockWakeKey>; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> AtomicWakeBatch<CAPACITY> {
    const fn empty() -> Self {
        Self {
            wakes: [None; CAPACITY],
            len: 0,
        }
    }

    fn push(&mut self, wake: BlockWakeKey) {
        assert!(self.len < CAPACITY, "atomic wake batch overflow");
        self.wakes[self.len] = Some(wake);
        self.len += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn into_wakes(self) -> [Option<BlockWakeKey>; CAPACITY] {
        self.wakes
    }
}

/// Per-key registration index for `atomic_wait32`.
///
/// `observe` and `register_if_expected` execute their load closure while the
/// same IRQ-safe index lock used by `claim_wake` is held.  The F9 adapter must
/// call the first for the initial comparison and the second after it has
/// prepared the scheduler block, thereby closing compare/register lost wakes.
pub(crate) struct AtomicWaitRegistry<const CAPACITY: usize> {
    domain: u64,
    next_sequence: AtomicU64,
    slots: IrqSpinMutex<[AtomicWaitSlot; CAPACITY]>,
}

impl<const CAPACITY: usize> AtomicWaitRegistry<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_domain(),
            next_sequence: AtomicU64::new(1),
            slots: IrqSpinMutex::new([EMPTY_SLOT; CAPACITY]),
        }
    }

    /// Evaluates a pinned aligned word load under the atomic-key barrier.
    pub(crate) fn observe(&self, load: impl FnOnce() -> u32) -> u32 {
        let _slots = self.slots.lock();
        load()
    }

    /// Rechecks a pinned aligned word and publishes a waiter atomically with
    /// respect to `atomic_wake` for all keys in this bounded registry.
    pub(crate) fn register_if_expected(
        &self,
        key: AtomicWaitKey,
        wake: BlockWakeKey,
        expected: u32,
        load: impl FnOnce() -> u32,
    ) -> Result<AtomicWaitRegisterOutcome, AtomicWaitError> {
        let mut slots = self.slots.lock();
        let observed = load();
        if observed != expected {
            return Ok(AtomicWaitRegisterOutcome::Mismatch { observed });
        }
        let (index, slot) = slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.entry.is_none())
            .ok_or(AtomicWaitError::Capacity)?;
        let generation = slot
            .generation
            .checked_add(1)
            .filter(|value| *value != 0)
            .ok_or(AtomicWaitError::Capacity)?;
        let sequence = self
            .next_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| AtomicWaitError::Capacity)?;
        let slot_index = u16::try_from(index).map_err(|_| AtomicWaitError::Capacity)?;
        slot.generation = generation;
        slot.entry = Some(AtomicWaitEntry {
            key,
            wake,
            sequence,
        });
        Ok(AtomicWaitRegisterOutcome::Registered(
            AtomicWaitRegistration {
                domain: self.domain,
                slot: slot_index,
                generation,
                key,
                wake,
            },
        ))
    }

    /// Removes this exact registration when it still remains in the index.
    ///
    /// `Ok(false)` is normal after `atomic_wake` or timeout/terminal cleanup
    /// has already selected the same block generation.
    pub(crate) fn cancel_if_live(
        &self,
        registration: AtomicWaitRegistration,
    ) -> Result<bool, AtomicWaitError> {
        if registration.domain != self.domain {
            return Err(AtomicWaitError::ForeignRegistration);
        }
        let mut slots = self.slots.lock();
        let slot = slots
            .get_mut(usize::from(registration.slot))
            .ok_or(AtomicWaitError::StaleRegistration)?;
        if slot.generation < registration.generation {
            return Err(AtomicWaitError::StaleRegistration);
        }
        if slot.generation > registration.generation || slot.entry.is_none() {
            return Ok(false);
        }
        if !slot
            .entry
            .is_some_and(|entry| entry.key == registration.key && entry.wake == registration.wake)
        {
            return Err(AtomicWaitError::StaleRegistration);
        }
        slot.entry = None;
        Ok(true)
    }

    /// Claims and removes up to `count` keyed registrations in FIFO order.
    ///
    /// Each selected entry first claims `AtomicWake` in the shared blocked
    /// operation ledger.  Entries whose timeout/terminal winner already exists
    /// are discarded from this index and do not consume the requested wake
    /// count.  Callers dispatch the returned scheduler wake keys after this
    /// method returns and the index lock has been released.
    pub(crate) fn claim_wake<const BLOCKED: usize>(
        &self,
        key: AtomicWaitKey,
        count: u32,
        blocked: &BlockedOperationRegistry<BLOCKED>,
    ) -> Result<AtomicWakeBatch<CAPACITY>, AtomicWaitError> {
        let limit = if count == DW_ATOMIC_WAKE_ALL {
            CAPACITY
        } else {
            usize::try_from(count).expect("u32 fits usize on supported targets")
        };
        let mut batch = AtomicWakeBatch::empty();
        if limit == 0 {
            return Ok(batch);
        }

        let mut slots = self.slots.lock();
        while batch.len < limit {
            let Some(index) = oldest_keyed_slot(&slots, key) else {
                break;
            };
            let entry = slots[index]
                .entry
                .expect("oldest keyed atomic wait slot remains live");
            match blocked.try_claim_winner(entry.wake, BlockedOperationWinner::AtomicWake) {
                Ok(true) => {
                    slots[index].entry = None;
                    batch.push(entry.wake);
                }
                Ok(false) | Err(BlockedOperationError::StaleReservation) => {
                    // The operation already has a non-atomic terminal winner,
                    // or its owner was completed before this stale index entry
                    // was encountered.  In either case it is no longer
                    // eligible and must not obstruct later FIFO candidates.
                    slots[index].entry = None;
                }
                Err(error) => return Err(AtomicWaitError::Blocked(error)),
            }
        }
        Ok(batch)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.slots.lock().iter().all(|slot| slot.entry.is_none())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots
            .lock()
            .iter()
            .filter(|slot| slot.entry.is_some())
            .count()
    }
}

fn oldest_keyed_slot<const CAPACITY: usize>(
    slots: &[AtomicWaitSlot; CAPACITY],
    key: AtomicWaitKey,
) -> Option<usize> {
    slots
        .iter()
        .enumerate()
        .filter_map(|(index, slot)| {
            slot.entry
                .filter(|entry| entry.key == key)
                .map(|entry| (index, entry.sequence))
        })
        .min_by_key(|(_, sequence)| *sequence)
        .map(|(index, _)| index)
}

/// Durable owner for every resource that survives an `atomic_wait32` block.
///
/// `PIN` is the resolver-issued mapping/backing pin and must keep the selected
/// word stable until resume or terminal disposal.  Its registration and finite
/// deadline are returned only by exact winner completion.
#[must_use = "atomic wait resources must be resumed or terminally discarded"]
pub(crate) struct AtomicWaitOperation<PIN> {
    process: ProcessKey,
    thread: ThreadKey,
    blocked: BlockedOperation<()>,
    pin: PIN,
    registration: AtomicWaitRegistration,
    deadline: Option<DeadlineRegistration>,
}

impl<PIN> AtomicWaitOperation<PIN> {
    pub(crate) fn new(
        process: ProcessKey,
        thread: ThreadKey,
        blocked: BlockedOperation<()>,
        pin: PIN,
        registration: AtomicWaitRegistration,
        deadline: Option<DeadlineRegistration>,
    ) -> Self {
        Self {
            process,
            thread,
            blocked,
            pin,
            registration,
            deadline,
        }
    }

    pub(crate) const fn process(&self) -> ProcessKey {
        self.process
    }

    pub(crate) const fn thread(&self) -> ThreadKey {
        self.thread
    }

    pub(crate) fn wake_key(&self) -> BlockWakeKey {
        self.blocked.wake_key()
    }

    pub(crate) const fn registration(&self) -> AtomicWaitRegistration {
        self.registration
    }

    pub(crate) fn winner<const BLOCKED: usize>(
        &self,
        blocked: &BlockedOperationRegistry<BLOCKED>,
    ) -> Result<Option<BlockedOperationWinner>, BlockedOperationError> {
        blocked.winner(self.wake_key())
    }

    pub(crate) fn complete<const BLOCKED: usize>(
        self,
        blocked_registry: &BlockedOperationRegistry<BLOCKED>,
        winner: BlockedOperationWinner,
    ) -> Result<(PIN, AtomicWaitRegistration, Option<DeadlineRegistration>), BlockedOperationError>
    {
        let Self {
            process: _,
            thread: _,
            blocked,
            pin,
            registration,
            deadline,
        } = self;
        blocked.complete_with(blocked_registry, winner, |()| ())?;
        Ok((pin, registration, deadline))
    }

    pub(crate) fn complete_terminal<const BLOCKED: usize>(
        self,
        blocked_registry: &BlockedOperationRegistry<BLOCKED>,
    ) -> Result<(PIN, AtomicWaitRegistration, Option<DeadlineRegistration>), BlockedOperationError>
    {
        let wake = self.wake_key();
        let winner = match blocked_registry.winner(wake)? {
            Some(winner) => winner,
            None => {
                assert!(
                    blocked_registry.try_claim_winner(wake, BlockedOperationWinner::Terminal)?,
                    "fresh terminal atomic wait claim unexpectedly lost"
                );
                BlockedOperationWinner::Terminal
            }
        };
        self.complete(blocked_registry, winner)
    }
}

/// Thread-context operation owner for F9 suspended syscalls.
pub(crate) struct AtomicWaitOperationRegistry<PIN, const CAPACITY: usize> {
    entries: [Option<AtomicWaitOperation<PIN>>; CAPACITY],
}

impl<PIN, const CAPACITY: usize> AtomicWaitOperationRegistry<PIN, CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
        }
    }

    pub(crate) fn publish(
        &mut self,
        operation: &mut Option<AtomicWaitOperation<PIN>>,
    ) -> Result<(), AtomicWaitError> {
        let candidate = operation
            .as_ref()
            .expect("atomic wait operation publication requires a live candidate");
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.thread == candidate.thread)
        {
            return Err(AtomicWaitError::DuplicateThread);
        }
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return Err(AtomicWaitError::Capacity);
        };
        *slot = operation.take();
        Ok(())
    }

    pub(crate) fn take_wake(
        &mut self,
        wake: BlockWakeKey,
    ) -> Result<AtomicWaitOperation<PIN>, AtomicWaitError> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|entry| entry.wake_key() == wake))
            .ok_or(AtomicWaitError::StaleRegistration)?;
        Ok(slot
            .take()
            .expect("located atomic wait operation remains present"))
    }

    pub(crate) fn take_thread(&mut self, thread: ThreadKey) -> Option<AtomicWaitOperation<PIN>> {
        self.entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|entry| entry.thread == thread))
            .and_then(Option::take)
    }

    pub(crate) fn wake_key_for_thread(&self, thread: ThreadKey) -> Option<BlockWakeKey> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.thread == thread)
            .map(AtomicWaitOperation::wake_key)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }
}

impl<PIN, const CAPACITY: usize> Drop for AtomicWaitOperationRegistry<PIN, CAPACITY> {
    fn drop(&mut self) {
        assert!(
            self.entries.iter().all(Option::is_none),
            "live suspended atomic wait resources dropped without resume/terminal cleanup"
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicWaitBeginError {
    Registry(AtomicWaitError),
    Scheduler(SchedulerError),
    Blocked(BlockedOperationError),
    Deadline(WaitDeadlineError),
}

#[must_use = "atomic-wait begin failures return the still-owned word pin"]
pub(crate) struct AtomicWaitBeginFailure<PIN> {
    pub(crate) error: AtomicWaitBeginError,
    pub(crate) pin: PIN,
}

#[must_use = "atomic-wait outcomes either return the word pin or transfer it to a suspended operation"]
pub(crate) enum AtomicWaitBegin<PIN> {
    Mismatch(PIN),
    TimedOut(PIN),
    Ready(PIN),
    Suspended {
        wake: BlockWakeKey,
        decision: ScheduleDecision,
    },
}

fn cancel_deadline(
    authority: &mut Option<&mut dyn WaitDeadlineAuthority>,
    registration: Option<DeadlineRegistration>,
) -> Result<(), WaitDeadlineError> {
    let Some(registration) = registration else {
        return Ok(());
    };
    let Some(authority) = authority.as_mut() else {
        return Err(WaitDeadlineError::Fault);
    };
    (**authority).cancel_wait_deadline(registration)
}

/// Runs the F9 compare/prepare/register/recheck transaction.
///
/// `load` must perform an aligned atomic load through `pin`. The initial load
/// and the registration recheck both execute under the registry barrier used
/// by `atomic_wake`; no registry lock crosses scheduler publication.
#[allow(
    clippy::too_many_arguments,
    reason = "the wait transaction keeps predicate, deadline, scheduler, registry, operation, process, thread, and pinned-load authorities explicit"
)]
pub(crate) fn begin_atomic_wait<PIN, const WAITERS: usize, const EXECUTION: usize>(
    pin: PIN,
    key: AtomicWaitKey,
    expected: u32,
    deadline: WaitDeadline,
    registry: &AtomicWaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut AtomicWaitOperationRegistry<PIN, EXECUTION>,
    mut deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    process: ProcessKey,
    thread: ThreadKey,
    mut load: impl FnMut(&PIN) -> u32,
) -> Result<AtomicWaitBegin<PIN>, AtomicWaitBeginFailure<PIN>> {
    if registry.observe(|| load(&pin)) != expected {
        return Ok(AtomicWaitBegin::Mismatch(pin));
    }
    if deadline == WaitDeadline::Now {
        return Ok(AtomicWaitBegin::TimedOut(pin));
    }

    let block = match execution.prepare_block_current(thread) {
        Ok(block) => block,
        Err(error) => {
            return Err(AtomicWaitBeginFailure {
                error: AtomicWaitBeginError::Scheduler(error),
                pin,
            });
        }
    };
    let wake = block.wake_key();
    let blocked = match BlockedOperation::publish(
        execution.blocked_operations(),
        process,
        thread,
        wake,
        (),
    ) {
        Ok(blocked) => blocked,
        Err((error, ())) => {
            execution
                .cancel_block(block)
                .expect("fresh F9 block reservation remains cancellable");
            return Err(AtomicWaitBeginFailure {
                error: AtomicWaitBeginError::Blocked(error),
                pin,
            });
        }
    };

    let deadline_registration = match deadline {
        WaitDeadline::Now => unreachable!("NOW returned before F9 block preparation"),
        WaitDeadline::Infinite => None,
        WaitDeadline::Finite(deadline_ns) => {
            let Some(authority) = deadline_authority.as_mut() else {
                blocked
                    .complete_with(
                        execution.blocked_operations(),
                        BlockedOperationWinner::Cancelled,
                        |()| (),
                    )
                    .expect("F9 missing-deadline cleanup remains exact");
                execution
                    .cancel_block(block)
                    .expect("F9 missing-deadline block remains cancellable");
                return Err(AtomicWaitBeginFailure {
                    error: AtomicWaitBeginError::Deadline(WaitDeadlineError::Fault),
                    pin,
                });
            };
            match (**authority).register_wait_deadline(deadline_ns, wake) {
                Ok(registration) => Some(registration),
                Err(WaitDeadlineError::Expired) => {
                    blocked
                        .complete_with(
                            execution.blocked_operations(),
                            BlockedOperationWinner::Timeout,
                            |()| (),
                        )
                        .expect("F9 expired deadline cleanup remains exact");
                    execution
                        .cancel_block(block)
                        .expect("F9 expired-deadline block remains cancellable");
                    return Ok(AtomicWaitBegin::TimedOut(pin));
                }
                Err(error) => {
                    blocked
                        .complete_with(
                            execution.blocked_operations(),
                            BlockedOperationWinner::Cancelled,
                            |()| (),
                        )
                        .expect("F9 deadline failure cleanup remains exact");
                    execution
                        .cancel_block(block)
                        .expect("F9 deadline-failure block remains cancellable");
                    return Err(AtomicWaitBeginFailure {
                        error: AtomicWaitBeginError::Deadline(error),
                        pin,
                    });
                }
            }
        }
    };

    let registration = match registry.register_if_expected(key, wake, expected, || load(&pin)) {
        Ok(AtomicWaitRegisterOutcome::Registered(registration)) => registration,
        Ok(AtomicWaitRegisterOutcome::Mismatch { .. }) => {
            blocked
                .complete_with(
                    execution.blocked_operations(),
                    BlockedOperationWinner::Cancelled,
                    |()| (),
                )
                .expect("F9 reread mismatch cleanup remains exact");
            cancel_deadline(&mut deadline_authority, deadline_registration)
                .expect("F9 reread mismatch deadline remains cancellable");
            execution
                .cancel_block(block)
                .expect("F9 reread mismatch block remains cancellable");
            return Ok(AtomicWaitBegin::Mismatch(pin));
        }
        Err(error) => {
            blocked
                .complete_with(
                    execution.blocked_operations(),
                    BlockedOperationWinner::Cancelled,
                    |()| (),
                )
                .expect("F9 registration failure cleanup remains exact");
            cancel_deadline(&mut deadline_authority, deadline_registration)
                .expect("F9 registration failure deadline remains cancellable");
            execution
                .cancel_block(block)
                .expect("F9 registration failure block remains cancellable");
            return Err(AtomicWaitBeginFailure {
                error: AtomicWaitBeginError::Registry(error),
                pin,
            });
        }
    };

    let mut operation = Some(AtomicWaitOperation::new(
        process,
        thread,
        blocked,
        pin,
        registration,
        deadline_registration,
    ));
    if let Err(error) = operations.publish(&mut operation) {
        registry
            .cancel_if_live(registration)
            .expect("fresh F9 registration remains cancellable");
        let operation = operation
            .take()
            .expect("failed F9 operation publication remains caller-owned");
        let (pin, _, deadline) = operation
            .complete(
                execution.blocked_operations(),
                BlockedOperationWinner::Cancelled,
            )
            .expect("unpublished F9 operation cleanup remains exact");
        cancel_deadline(&mut deadline_authority, deadline)
            .expect("unpublished F9 deadline remains cancellable");
        execution
            .cancel_block(block)
            .expect("unpublished F9 block remains cancellable");
        return Err(AtomicWaitBeginFailure {
            error: AtomicWaitBeginError::Registry(error),
            pin,
        });
    }

    match execution.blocked_operations().winner(wake) {
        Ok(None) => {
            let decision = execution
                .commit_block(block)
                .expect("registered F9 block commit remains valid");
            Ok(AtomicWaitBegin::Suspended { wake, decision })
        }
        Ok(Some(
            winner @ (BlockedOperationWinner::AtomicWake | BlockedOperationWinner::Timeout),
        )) => {
            let operation = operations
                .take_wake(wake)
                .expect("pre-block F9 winner retains operation ownership");
            registry
                .cancel_if_live(operation.registration())
                .expect("pre-block F9 registration cleanup remains exact");
            let (pin, _, deadline) = operation
                .complete(execution.blocked_operations(), winner)
                .expect("pre-block F9 completion remains exact");
            cancel_deadline(&mut deadline_authority, deadline)
                .expect("pre-block F9 deadline remains cancellable");
            execution
                .cancel_block(block)
                .expect("pre-block F9 reservation remains cancellable");
            if winner == BlockedOperationWinner::AtomicWake {
                Ok(AtomicWaitBegin::Ready(pin))
            } else {
                Ok(AtomicWaitBegin::TimedOut(pin))
            }
        }
        Ok(Some(other)) => panic!("unexpected F9 winner before block commit: {other:?}"),
        Err(error) => panic!("fresh F9 blocked-operation ledger disappeared: {error:?}"),
    }
}

pub(crate) fn finish_atomic_wait<PIN, const WAITERS: usize, const EXECUTION: usize>(
    registry: &AtomicWaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut AtomicWaitOperationRegistry<PIN, EXECUTION>,
    mut deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    wake: BlockWakeKey,
) -> Result<(PIN, BlockedOperationWinner), AtomicWaitBeginError> {
    let operation = operations
        .take_wake(wake)
        .map_err(AtomicWaitBeginError::Registry)?;
    let winner = operation
        .winner(execution.blocked_operations())
        .map_err(AtomicWaitBeginError::Blocked)?
        .ok_or(AtomicWaitBeginError::Blocked(
            BlockedOperationError::WinnerMismatch,
        ))?;
    registry
        .cancel_if_live(operation.registration())
        .map_err(AtomicWaitBeginError::Registry)?;
    let (pin, _, deadline) = operation
        .complete(execution.blocked_operations(), winner)
        .map_err(AtomicWaitBeginError::Blocked)?;
    cancel_deadline(&mut deadline_authority, deadline).map_err(AtomicWaitBeginError::Deadline)?;
    Ok((pin, winner))
}

pub(crate) fn finish_terminal_atomic_wait<PIN, const WAITERS: usize, const EXECUTION: usize>(
    registry: &AtomicWaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut AtomicWaitOperationRegistry<PIN, EXECUTION>,
    mut deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    thread: ThreadKey,
) -> Result<Option<PIN>, AtomicWaitBeginError> {
    let Some(operation) = operations.take_thread(thread) else {
        return Ok(None);
    };
    registry
        .cancel_if_live(operation.registration())
        .map_err(AtomicWaitBeginError::Registry)?;
    let (pin, _, deadline) = operation
        .complete_terminal(execution.blocked_operations())
        .map_err(AtomicWaitBeginError::Blocked)?;
    cancel_deadline(&mut deadline_authority, deadline).map_err(AtomicWaitBeginError::Deadline)?;
    Ok(Some(pin))
}

pub(crate) fn wake_atomic_waiters<const WAITERS: usize, const EXECUTION: usize>(
    registry: &AtomicWaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    key: AtomicWaitKey,
    count: u32,
) -> Result<u32, AtomicWaitBeginError> {
    let batch = registry
        .claim_wake(key, count, execution.blocked_operations())
        .map_err(AtomicWaitBeginError::Registry)?;
    let woken = u32::try_from(batch.len()).expect("atomic waiter capacity fits u32");
    for wake in batch.into_wakes().into_iter().flatten() {
        match execution.wake(wake) {
            Ok(()) | Err(SchedulerError::StaleBlockToken) => {}
            Err(error) => return Err(AtomicWaitBeginError::Scheduler(error)),
        }
    }
    Ok(woken)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::memory::kernel_stack::KernelStackBounds;
    use crate::object::ObjectRegistry;
    use crate::task::{
        CooperativeScheduler, SchedulerThreadState, TaskAuthority, ThreadStartState,
    };
    use core::cell::Cell;
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD,
    };

    type TestKeys<const CAPACITY: usize> = (
        ProcessKey,
        [ThreadKey; CAPACITY],
        [BlockWakeKey; CAPACITY],
        [BlockedOperation<()>; CAPACITY],
        BlockedOperationRegistry<CAPACITY>,
        AtomicWaitKey,
    );

    fn keys<const CAPACITY: usize>() -> TestKeys<CAPACITY> {
        let mut objects = ObjectRegistry::<16>::new();
        let process = objects.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let memory = objects.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let process_key = ProcessKey::from_object_id(process.id());
        let key = AtomicWaitKey::new(memory.id(), 0x400);
        objects.cancel_creation(process).unwrap();
        objects.cancel_creation(memory).unwrap();

        let threads = core::array::from_fn(|_| {
            let thread = objects.create(DW_OBJECT_TYPE_THREAD).unwrap();
            let key = ThreadKey::from_object_id(thread.id());
            objects.cancel_creation(thread).unwrap();
            key
        });
        let scheduler = CooperativeScheduler::<CAPACITY>::new();
        for thread in threads {
            let reservation = scheduler.reserve(thread).unwrap();
            scheduler.commit(reservation).unwrap();
        }
        let mut decision = scheduler.schedule_next().unwrap();
        let wakes = core::array::from_fn(|index| {
            assert_eq!(decision.current, Some(threads[index]));
            let (block, next) = scheduler.block_current(threads[index]).unwrap();
            decision = next;
            block.into_wake_key()
        });
        let blocked_registry = BlockedOperationRegistry::<CAPACITY>::new();
        let blocked = core::array::from_fn(|index| {
            BlockedOperation::publish(
                &blocked_registry,
                process_key,
                threads[index],
                wakes[index],
                (),
            )
            .unwrap()
        });
        (process_key, threads, wakes, blocked, blocked_registry, key)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AtomicTraceState {
        Fresh,
        Mismatch,
        Registered,
        Winner(BlockedOperationWinner),
        Completed,
    }

    #[derive(Clone, Copy, Debug)]
    struct AtomicTraceWaiter {
        state: AtomicTraceState,
        registration: Option<AtomicWaitRegistration>,
        sequence: Option<u64>,
        live: bool,
    }

    impl AtomicTraceWaiter {
        const FRESH: Self = Self {
            state: AtomicTraceState::Fresh,
            registration: None,
            sequence: None,
            live: false,
        };
    }

    #[derive(Clone, Copy, Debug)]
    enum AtomicTraceAction {
        Register { waiter: usize, matches: bool },
        Wake { count: u32 },
        Timeout { waiter: usize },
        Terminal { waiter: usize },
        Complete { waiter: usize },
    }

    fn next_atomic_trace_word(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(3_037_000_493);
        *state
    }

    #[test]
    fn fixed_seed_atomic_wait_transactions_preserve_fifo_winners_and_copy_registrations() {
        const OPERATIONS: usize = 9;
        const WAIT_SLOTS: usize = 4;

        for seed in [0x3d7c_9a11_44e2_b5f8_u64, 0xca71_6e5d_80f4_2219] {
            let mut random = seed;
            let (_process, _threads, wakes, blocked, ledger, key) = keys::<OPERATIONS>();
            let registry = AtomicWaitRegistry::<WAIT_SLOTS>::new();
            let mut operations = blocked.map(Some);
            let mut model = [AtomicTraceWaiter::FRESH; OPERATIONS];
            let mut next_sequence = 0_u64;

            for step in 0..80 {
                let action = match step {
                    // Prefix: timeout wins before a bounded wake, which must
                    // skip it and wake the next FIFO candidate instead.
                    0 => AtomicTraceAction::Register {
                        waiter: 0,
                        matches: true,
                    },
                    1 => AtomicTraceAction::Register {
                        waiter: 1,
                        matches: true,
                    },
                    2 => AtomicTraceAction::Timeout { waiter: 0 },
                    3 => AtomicTraceAction::Wake { count: 1 },
                    // A terminal winner keeps ownership until the exact
                    // completion path returns its Copy registration.
                    4 => AtomicTraceAction::Register {
                        waiter: 2,
                        matches: true,
                    },
                    5 => AtomicTraceAction::Terminal { waiter: 2 },
                    6 => AtomicTraceAction::Complete { waiter: 2 },
                    7 => AtomicTraceAction::Wake {
                        count: DW_ATOMIC_WAKE_ALL,
                    },
                    // Predicate recheck mismatch must never publish a slot.
                    8 => AtomicTraceAction::Register {
                        waiter: 3,
                        matches: false,
                    },
                    // Fill all bounded slots, demonstrate capacity, then free
                    // two FIFO registrations and retry the rejected waiter.
                    9 => AtomicTraceAction::Register {
                        waiter: 4,
                        matches: true,
                    },
                    10 => AtomicTraceAction::Register {
                        waiter: 5,
                        matches: true,
                    },
                    11 => AtomicTraceAction::Register {
                        waiter: 6,
                        matches: true,
                    },
                    12 => AtomicTraceAction::Register {
                        waiter: 7,
                        matches: true,
                    },
                    13 => AtomicTraceAction::Register {
                        waiter: 8,
                        matches: true,
                    },
                    14 => AtomicTraceAction::Wake { count: 2 },
                    15 => AtomicTraceAction::Register {
                        waiter: 8,
                        matches: true,
                    },
                    _ => match next_atomic_trace_word(&mut random) % 5 {
                        0 => AtomicTraceAction::Register {
                            waiter: usize::try_from(
                                next_atomic_trace_word(&mut random) % OPERATIONS as u64,
                            )
                            .unwrap(),
                            matches: next_atomic_trace_word(&mut random) & 1 == 0,
                        },
                        1 => AtomicTraceAction::Wake {
                            count: match next_atomic_trace_word(&mut random) % 3 {
                                0 => 0,
                                1 => 1,
                                _ => DW_ATOMIC_WAKE_ALL,
                            },
                        },
                        2 => AtomicTraceAction::Timeout {
                            waiter: usize::try_from(
                                next_atomic_trace_word(&mut random) % OPERATIONS as u64,
                            )
                            .unwrap(),
                        },
                        3 => AtomicTraceAction::Terminal {
                            waiter: usize::try_from(
                                next_atomic_trace_word(&mut random) % OPERATIONS as u64,
                            )
                            .unwrap(),
                        },
                        _ => AtomicTraceAction::Complete {
                            waiter: usize::try_from(
                                next_atomic_trace_word(&mut random) % OPERATIONS as u64,
                            )
                            .unwrap(),
                        },
                    },
                };
                let context = std::format!("seed={seed:#018x} step={step} action={action:?}");

                match action {
                    AtomicTraceAction::Register { waiter, matches } => {
                        if model[waiter].state == AtomicTraceState::Fresh {
                            assert_eq!(registry.observe(|| 7), 7, "{context}");
                            let result =
                                registry.register_if_expected(key, wakes[waiter], 7, || {
                                    if matches { 7 } else { 8 }
                                });
                            match result {
                                Ok(AtomicWaitRegisterOutcome::Registered(registration)) => {
                                    assert!(matches, "{context}: mismatched predicate registered");
                                    assert!(
                                        model.iter().filter(|waiter| waiter.live).count()
                                            < WAIT_SLOTS,
                                        "{context}: registration exceeded bounded capacity"
                                    );
                                    // AtomicWaitRegistration is Copy identity
                                    // only. Cleanup ownership remains in the
                                    // move-only AtomicWaitOperation below.
                                    let copied_registration = registration;
                                    assert_eq!(copied_registration, registration, "{context}");
                                    model[waiter].state = AtomicTraceState::Registered;
                                    model[waiter].registration = Some(registration);
                                    model[waiter].sequence = Some(next_sequence);
                                    model[waiter].live = true;
                                    next_sequence += 1;
                                }
                                Ok(AtomicWaitRegisterOutcome::Mismatch { observed }) => {
                                    assert!(!matches, "{context}: matching predicate mismatched");
                                    assert_eq!(observed, 8, "{context}");
                                    model[waiter].state = AtomicTraceState::Mismatch;
                                }
                                Err(AtomicWaitError::Capacity) => {
                                    assert!(matches, "{context}: mismatch must precede capacity");
                                    assert_eq!(
                                        model.iter().filter(|waiter| waiter.live).count(),
                                        WAIT_SLOTS,
                                        "{context}: capacity failure without a full index"
                                    );
                                }
                                other => {
                                    panic!("{context}: unexpected registration outcome: {other:?}")
                                }
                            }
                        }
                    }
                    AtomicTraceAction::Wake { count } => {
                        let limit = if count == DW_ATOMIC_WAKE_ALL {
                            WAIT_SLOTS
                        } else {
                            usize::try_from(count).unwrap()
                        };
                        let mut expected = [None; WAIT_SLOTS];
                        let mut selected = 0;
                        while selected < limit {
                            let candidate = (0..OPERATIONS)
                                .filter(|&waiter| model[waiter].live)
                                .min_by_key(|&waiter| model[waiter].sequence.unwrap());
                            let Some(waiter) = candidate else {
                                break;
                            };
                            match model[waiter].state {
                                AtomicTraceState::Registered => {
                                    model[waiter].state = AtomicTraceState::Winner(
                                        BlockedOperationWinner::AtomicWake,
                                    );
                                    model[waiter].live = false;
                                    expected[selected] = Some(wakes[waiter]);
                                    selected += 1;
                                }
                                AtomicTraceState::Winner(_) => {
                                    // A timeout/terminal winner is stale index
                                    // state and must not consume wake budget.
                                    model[waiter].live = false;
                                }
                                state => {
                                    panic!("{context}: live waiter has invalid state {state:?}")
                                }
                            }
                        }
                        let batch = registry.claim_wake(key, count, &ledger).unwrap();
                        assert_eq!(batch.into_wakes(), expected, "{context}");
                    }
                    AtomicTraceAction::Timeout { waiter } => {
                        if model[waiter].state == AtomicTraceState::Registered {
                            assert!(
                                ledger
                                    .try_claim_winner(
                                        wakes[waiter],
                                        BlockedOperationWinner::Timeout
                                    )
                                    .unwrap(),
                                "{context}"
                            );
                            model[waiter].state =
                                AtomicTraceState::Winner(BlockedOperationWinner::Timeout);
                        }
                    }
                    AtomicTraceAction::Terminal { waiter } => match model[waiter].state {
                        AtomicTraceState::Fresh
                        | AtomicTraceState::Mismatch
                        | AtomicTraceState::Registered => {
                            assert!(
                                ledger
                                    .try_claim_winner(
                                        wakes[waiter],
                                        BlockedOperationWinner::Terminal
                                    )
                                    .unwrap(),
                                "{context}"
                            );
                            model[waiter].state =
                                AtomicTraceState::Winner(BlockedOperationWinner::Terminal);
                        }
                        AtomicTraceState::Winner(_) | AtomicTraceState::Completed => {}
                    },
                    AtomicTraceAction::Complete { waiter } => {
                        if let AtomicTraceState::Winner(winner) = model[waiter].state {
                            if let Some(registration) = model[waiter].registration {
                                assert_eq!(
                                    registry.cancel_if_live(registration).unwrap(),
                                    model[waiter].live,
                                    "{context}: cleanup must consume exactly its live registration"
                                );
                                model[waiter].live = false;
                            }
                            operations[waiter]
                                .take()
                                .expect("model completion retains its owning operation")
                                .complete_with(&ledger, winner, |()| ())
                                .unwrap();
                            model[waiter].state = AtomicTraceState::Completed;
                        }
                    }
                }

                assert_eq!(
                    registry.len(),
                    model.iter().filter(|waiter| waiter.live).count(),
                    "{context}: registry/model liveness diverged"
                );
            }

            for waiter in 0..OPERATIONS {
                let Some(operation) = operations[waiter].take() else {
                    assert_eq!(model[waiter].state, AtomicTraceState::Completed);
                    continue;
                };
                let winner = match model[waiter].state {
                    AtomicTraceState::Winner(winner) => winner,
                    AtomicTraceState::Fresh
                    | AtomicTraceState::Mismatch
                    | AtomicTraceState::Registered => {
                        assert!(
                            ledger
                                .try_claim_winner(wakes[waiter], BlockedOperationWinner::Cancelled)
                                .unwrap(),
                            "seed={seed:#018x}: final cleanup lost an unclaimed waiter"
                        );
                        BlockedOperationWinner::Cancelled
                    }
                    AtomicTraceState::Completed => {
                        unreachable!("completed operation remained owned")
                    }
                };
                if let Some(registration) = model[waiter].registration {
                    assert_eq!(
                        registry.cancel_if_live(registration).unwrap(),
                        model[waiter].live,
                        "seed={seed:#018x}: final cleanup registration mismatch for waiter {waiter}"
                    );
                    model[waiter].live = false;
                }
                operation.complete_with(&ledger, winner, |()| ()).unwrap();
                model[waiter].state = AtomicTraceState::Completed;
            }
            assert_eq!(
                registry.len(),
                0,
                "seed={seed:#018x}: terminal cleanup leaked index state"
            );
        }
    }

    #[test]
    fn keyed_wake_is_fifo_and_bounded() {
        let (_process, _threads, wakes, blocked, ledger, key) = keys::<3>();
        let registry = AtomicWaitRegistry::<3>::new();
        for wake in wakes {
            assert!(matches!(
                registry.register_if_expected(key, wake, 7, || 7).unwrap(),
                AtomicWaitRegisterOutcome::Registered(_)
            ));
        }

        let first = registry.claim_wake(key, 2, &ledger).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first.into_wakes(), [Some(wakes[0]), Some(wakes[1]), None]);
        assert_eq!(
            ledger.winner(wakes[0]),
            Ok(Some(BlockedOperationWinner::AtomicWake))
        );
        assert_eq!(
            ledger.winner(wakes[1]),
            Ok(Some(BlockedOperationWinner::AtomicWake))
        );
        assert_eq!(registry.len(), 1);

        let second = registry
            .claim_wake(key, DW_ATOMIC_WAKE_ALL, &ledger)
            .unwrap();
        assert_eq!(second.into_wakes(), [Some(wakes[2]), None, None]);
        assert_eq!(registry.len(), 0);

        for operation in blocked {
            operation
                .complete_with(&ledger, BlockedOperationWinner::AtomicWake, |()| ())
                .unwrap();
        }
    }

    #[test]
    fn recheck_mismatch_never_publishes_a_waiter() {
        let (_process, _threads, wakes, blocked, ledger, key) = keys::<1>();
        let registry = AtomicWaitRegistry::<1>::new();
        assert_eq!(registry.observe(|| 9), 9);
        assert_eq!(
            registry
                .register_if_expected(key, wakes[0], 9, || 10)
                .unwrap(),
            AtomicWaitRegisterOutcome::Mismatch { observed: 10 }
        );
        assert_eq!(registry.len(), 0);
        let [blocked] = blocked;
        blocked
            .complete_with(&ledger, BlockedOperationWinner::Cancelled, |()| ())
            .unwrap();
    }

    #[test]
    fn preclaimed_timeout_does_not_consume_wake_count() {
        let (_process, _threads, wakes, blocked, ledger, key) = keys::<2>();
        let registry = AtomicWaitRegistry::<2>::new();
        let first = match registry
            .register_if_expected(key, wakes[0], 1, || 1)
            .unwrap()
        {
            AtomicWaitRegisterOutcome::Registered(registration) => registration,
            AtomicWaitRegisterOutcome::Mismatch { .. } => panic!("test word must match"),
        };
        let second = match registry
            .register_if_expected(key, wakes[1], 1, || 1)
            .unwrap()
        {
            AtomicWaitRegisterOutcome::Registered(registration) => registration,
            AtomicWaitRegisterOutcome::Mismatch { .. } => panic!("test word must match"),
        };
        assert!(
            ledger
                .try_claim_winner(wakes[0], BlockedOperationWinner::Timeout)
                .unwrap()
        );

        let batch = registry.claim_wake(key, 1, &ledger).unwrap();
        assert_eq!(batch.into_wakes(), [Some(wakes[1]), None]);
        assert!(!registry.cancel_if_live(first).unwrap());
        assert!(!registry.cancel_if_live(second).unwrap());

        let [first_blocked, second_blocked] = blocked;
        first_blocked
            .complete_with(&ledger, BlockedOperationWinner::Timeout, |()| ())
            .unwrap();
        second_blocked
            .complete_with(&ledger, BlockedOperationWinner::AtomicWake, |()| ())
            .unwrap();
    }

    #[test]
    fn terminal_operation_cleanup_returns_pin_registration_and_deadline_once() {
        let (process, threads, wakes, blocked, ledger, key) = keys::<1>();
        let registrations = AtomicWaitRegistry::<1>::new();
        let registration = match registrations
            .register_if_expected(key, wakes[0], 0, || 0)
            .unwrap()
        {
            AtomicWaitRegisterOutcome::Registered(registration) => registration,
            AtomicWaitRegisterOutcome::Mismatch { .. } => panic!("test word must match"),
        };
        let mut operations = AtomicWaitOperationRegistry::<u32, 1>::new();
        let mut operation = Some(AtomicWaitOperation::new(
            process,
            threads[0],
            blocked.into_iter().next().unwrap(),
            0x55,
            registration,
            None,
        ));
        operations.publish(&mut operation).unwrap();
        assert!(operation.is_none());
        let operation = operations.take_thread(threads[0]).unwrap();
        let (pin, returned_registration, deadline) = operation.complete_terminal(&ledger).unwrap();
        assert_eq!(pin, 0x55);
        assert_eq!(returned_registration, registration);
        assert!(deadline.is_none());
        assert!(registrations.cancel_if_live(registration).unwrap());
    }

    fn running_fixture() -> (ExecutionDomain<1>, ProcessKey, ThreadKey, AtomicWaitKey) {
        let mut objects = ObjectRegistry::<8>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 2>::new();
        let (_root, root_owner) = tasks.create_root_group(&mut objects).unwrap();
        let (process, process_handle) = tasks.create_process(&mut objects, &root_owner).unwrap();
        assert!(objects.release_internal(root_owner).unwrap().is_none());
        let process_owner = objects
            .retain_internal_from_handle(&process_handle)
            .unwrap();
        let (thread, thread_handle) = tasks.create_thread(&mut objects, &process_owner).unwrap();
        assert!(objects.release_internal(process_owner).unwrap().is_none());
        assert!(objects.release_handle(process_handle).unwrap().is_none());
        assert!(objects.release_handle(thread_handle).unwrap().is_none());
        let memory = objects.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let key = AtomicWaitKey::new(memory.id(), 0x80);
        objects.cancel_creation(memory).unwrap();

        let stack = KernelStackBounds::new(
            0xffff_9400_0000_0000,
            0xffff_9400_0000_1000,
            0xffff_9400_0001_1000,
        )
        .unwrap();
        let execution = ExecutionDomain::<1>::new([stack]).unwrap();
        execution
            .start_thread(
                &mut tasks,
                thread,
                ThreadStartState::from_validated_user_state(
                    0x0000_0000_4000_0000,
                    0x0000_0000_5000_0000,
                    0,
                    0,
                ),
            )
            .unwrap();
        assert_eq!(execution.schedule_next().unwrap().current, Some(thread));
        (execution, process, thread, key)
    }

    struct ExpiredDeadline;

    impl WaitDeadlineAuthority for ExpiredDeadline {
        fn register_wait_deadline(
            &mut self,
            _deadline_ns: u64,
            _wake: BlockWakeKey,
        ) -> Result<DeadlineRegistration, WaitDeadlineError> {
            Err(WaitDeadlineError::Expired)
        }

        fn cancel_wait_deadline(
            &mut self,
            _registration: DeadlineRegistration,
        ) -> Result<(), WaitDeadlineError> {
            panic!("expired deadline never publishes a registration")
        }
    }

    #[test]
    fn initial_mismatch_precedes_now_deadline() {
        let (execution, process, thread, key) = running_fixture();
        let registrations = AtomicWaitRegistry::<1>::new();
        let mut operations = AtomicWaitOperationRegistry::<u32, 1>::new();
        let outcome = begin_atomic_wait(
            0x55,
            key,
            7,
            WaitDeadline::Now,
            &registrations,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            |_| 6,
        )
        .unwrap_or_else(|failure| panic!("mismatch begin failed: {:?}", failure.error));
        assert!(matches!(outcome, AtomicWaitBegin::Mismatch(0x55)));
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Running)
        );
        assert_eq!(registrations.len(), 0);
        assert_eq!(operations.len(), 0);
    }

    #[test]
    fn initial_mismatch_precedes_an_already_expired_finite_deadline() {
        let (execution, process, thread, key) = running_fixture();
        let registrations = AtomicWaitRegistry::<1>::new();
        let mut operations = AtomicWaitOperationRegistry::<u32, 1>::new();
        let mut deadlines = ExpiredDeadline;
        let outcome = begin_atomic_wait(
            0x56,
            key,
            7,
            WaitDeadline::Finite(10),
            &registrations,
            &execution,
            &mut operations,
            Some(&mut deadlines),
            process,
            thread,
            |_| 6,
        )
        .unwrap_or_else(|failure| panic!("mismatch begin failed: {:?}", failure.error));
        assert!(matches!(outcome, AtomicWaitBegin::Mismatch(0x56)));
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Running)
        );
        assert_eq!(registrations.len(), 0);
        assert_eq!(operations.len(), 0);
    }

    #[test]
    fn under_barrier_reread_mismatch_returns_without_registration() {
        let (execution, process, thread, key) = running_fixture();
        let registrations = AtomicWaitRegistry::<1>::new();
        let mut operations = AtomicWaitOperationRegistry::<u32, 1>::new();
        let loads = Cell::new(0_u32);
        let outcome = begin_atomic_wait(
            0x66,
            key,
            7,
            WaitDeadline::Infinite,
            &registrations,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            |_| {
                let load = loads.get();
                loads.set(load + 1);
                if load == 0 { 7 } else { 8 }
            },
        )
        .unwrap_or_else(|failure| panic!("reread begin failed: {:?}", failure.error));
        assert!(matches!(outcome, AtomicWaitBegin::Mismatch(0x66)));
        assert_eq!(loads.get(), 2);
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Running)
        );
        assert_eq!(registrations.len(), 0);
        assert_eq!(operations.len(), 0);
    }

    #[test]
    fn equal_word_with_expired_finite_deadline_times_out_cleanly() {
        let (execution, process, thread, key) = running_fixture();
        let registrations = AtomicWaitRegistry::<1>::new();
        let mut operations = AtomicWaitOperationRegistry::<u32, 1>::new();
        let mut deadlines = ExpiredDeadline;
        let outcome = begin_atomic_wait(
            0x77,
            key,
            7,
            WaitDeadline::Finite(10),
            &registrations,
            &execution,
            &mut operations,
            Some(&mut deadlines),
            process,
            thread,
            |_| 7,
        )
        .unwrap_or_else(|failure| panic!("expired begin failed: {:?}", failure.error));
        assert!(matches!(outcome, AtomicWaitBegin::TimedOut(0x77)));
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Running)
        );
        assert_eq!(registrations.len(), 0);
        assert_eq!(operations.len(), 0);
    }

    #[test]
    fn zero_count_wake_claims_nothing() {
        let (_process, _threads, wakes, blocked, ledger, key) = keys::<1>();
        let registry = AtomicWaitRegistry::<1>::new();
        let registration = match registry
            .register_if_expected(key, wakes[0], 1, || 1)
            .unwrap()
        {
            AtomicWaitRegisterOutcome::Registered(registration) => registration,
            AtomicWaitRegisterOutcome::Mismatch { .. } => panic!("test word must match"),
        };
        let batch = registry.claim_wake(key, 0, &ledger).unwrap();
        assert_eq!(batch.len(), 0);
        assert!(registry.cancel_if_live(registration).unwrap());
        let [blocked] = blocked;
        blocked
            .complete_with(&ledger, BlockedOperationWinner::Cancelled, |()| ())
            .unwrap();
    }

    #[test]
    fn atomic_wake_and_timeout_accept_exactly_one_winner() {
        let (_process, _threads, wakes, blocked, ledger, key) = keys::<1>();
        let registry = AtomicWaitRegistry::<1>::new();
        let registration = match registry
            .register_if_expected(key, wakes[0], 1, || 1)
            .unwrap()
        {
            AtomicWaitRegisterOutcome::Registered(registration) => registration,
            AtomicWaitRegisterOutcome::Mismatch { .. } => panic!("test word must match"),
        };
        let batch = registry.claim_wake(key, 1, &ledger).unwrap();
        assert_eq!(batch.into_wakes(), [Some(wakes[0])]);
        assert!(
            !ledger
                .try_claim_winner(wakes[0], BlockedOperationWinner::Timeout)
                .unwrap()
        );
        assert!(!registry.cancel_if_live(registration).unwrap());
        let [blocked] = blocked;
        blocked
            .complete_with(&ledger, BlockedOperationWinner::AtomicWake, |()| ())
            .unwrap();
    }

    #[test]
    fn aliases_share_keys_but_unrelated_and_stale_generations_do_not() {
        let mut objects = ObjectRegistry::<2>::new();
        let first = objects.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let first_id = first.id();
        objects.cancel_creation(first).unwrap();
        let replacement = objects.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let replacement_id = replacement.id();
        let unrelated = objects.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();

        let alias_a = AtomicWaitKey::new(replacement_id, 0x44);
        let alias_b = AtomicWaitKey::new(replacement_id, 0x44);
        assert_eq!(alias_a, alias_b);
        assert_ne!(AtomicWaitKey::new(first_id, 0x44), alias_a);
        assert_ne!(AtomicWaitKey::new(unrelated.id(), 0x44), alias_a);
        assert_ne!(AtomicWaitKey::new(replacement_id, 0x48), alias_a);

        objects.cancel_creation(replacement).unwrap();
        objects.cancel_creation(unrelated).unwrap();
    }
}
