use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::IrqSpinMutex;

use super::ThreadKey;

static NEXT_SCHEDULER_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// DW0-H's bounded logical scheduler-CPU namespace.
///
/// This is an internal ownership identity, not a userspace ABI value.  The
/// canonical SMP profile has exactly four CPUs, so accepting a fifth owner is
/// an explicit error rather than silently aliasing or dropping it.
pub(crate) const H2_SCHEDULER_CPU_CAPACITY: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerCpuId(u8);

impl SchedulerCpuId {
    pub(crate) const BOOTSTRAP: Self = Self(0);

    pub(crate) const fn new(index: usize) -> Option<Self> {
        if index < H2_SCHEDULER_CPU_CAPACITY {
            Some(Self(index as u8))
        } else {
            None
        }
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

fn mint_scheduler_domain() -> u64 {
    NEXT_SCHEDULER_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .expect("scheduler domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerError {
    Capacity,
    DuplicateThread,
    ForeignReservation,
    StaleReservation,
    ForeignBlockToken,
    StaleBlockToken,
    CurrentThreadRunning,
    NotScheduled,
    NotRunning,
    WrongCpu,
    ForeignExecutionClaim,
    StaleExecutionClaim,
    TokenExhausted,
    BlockPreparationActive,
    SwitchPending,
    ContinuationOwned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerThreadState {
    Reserved,
    Runnable,
    Running,
    Blocked,
}

/// Exact ownership of one nonzero Thread execution claim on one CPU.
///
/// The generation changes each time Runnable work is claimed. H2-D can carry
/// this opaque key through a stop request/acknowledgement without confusing a
/// later execution of the same Thread on the same CPU for the original claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerExecutionClaim {
    domain: u64,
    cpu: SchedulerCpuId,
    thread: ThreadKey,
    generation: u64,
}

impl SchedulerExecutionClaim {
    pub(crate) const fn cpu(self) -> SchedulerCpuId {
        self.cpu
    }

    pub(crate) const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockWakeKey {
    domain: u64,
    token: u64,
    thread: ThreadKey,
    cpu: SchedulerCpuId,
    execution_generation: u64,
}

#[must_use = "prepared block ownership must be committed only after wait/deadline registration or explicitly cancelled"]
#[derive(Debug)]
pub(crate) struct BlockReservation {
    key: BlockWakeKey,
}

impl BlockReservation {
    pub(crate) const fn wake_key(&self) -> BlockWakeKey {
        self.key
    }
}

#[derive(Debug)]
pub(crate) struct BlockReservationFailure {
    error: SchedulerError,
    reservation: BlockReservation,
}

impl BlockReservationFailure {
    pub(crate) const fn error(&self) -> SchedulerError {
        self.error
    }

    pub(crate) fn into_reservation(self) -> BlockReservation {
        self.reservation
    }
}

#[must_use = "blocked scheduler ownership must be transferred to a waiter registration or explicitly woken"]
#[derive(Debug)]
pub(crate) struct BlockToken {
    key: BlockWakeKey,
}

impl BlockToken {
    pub(crate) const fn wake_key(&self) -> BlockWakeKey {
        self.key
    }

    pub(crate) const fn into_wake_key(self) -> BlockWakeKey {
        self.key
    }
}

#[must_use = "scheduler reservations must be committed or cancelled"]
#[derive(Debug)]
pub(crate) struct SchedulerReservation {
    domain: u64,
    token: u64,
    thread: ThreadKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleDecision {
    pub(crate) previous: Option<ThreadKey>,
    pub(crate) current: Option<ThreadKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdleScheduleDecision {
    ContinueIdle,
    ResumeCurrent,
    Switch(ScheduleDecision),
}

#[derive(Debug)]
pub(crate) struct SchedulerReservationFailure {
    error: SchedulerError,
    reservation: SchedulerReservation,
}

impl SchedulerReservationFailure {
    pub(crate) const fn error(&self) -> SchedulerError {
        self.error
    }

    pub(crate) fn into_reservation(self) -> SchedulerReservation {
        self.reservation
    }
}

#[derive(Clone, Copy)]
struct QueueEntry {
    thread: ThreadKey,
    state: SchedulerThreadState,
    token: u64,
    block_cpu: Option<SchedulerCpuId>,
    block_execution_generation: u64,
    continuation_cpu: Option<SchedulerCpuId>,
    continuation_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RunningClaim {
    thread: ThreadKey,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuspendedPublication {
    Queued,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SuspendedContinuation {
    thread: ThreadKey,
    generation: u64,
    publication: SuspendedPublication,
}

struct SchedulerState<const CAPACITY: usize> {
    domain: u64,
    next_token: u64,
    next_execution_generation: u64,
    queue: [Option<QueueEntry>; CAPACITY],
    len: usize,
    running: [Option<RunningClaim>; H2_SCHEDULER_CPU_CAPACITY],
    pending_block: [Option<BlockWakeKey>; H2_SCHEDULER_CPU_CAPACITY],
    suspended: [Option<SuspendedContinuation>; H2_SCHEDULER_CPU_CAPACITY],
}

impl<const CAPACITY: usize> SchedulerState<CAPACITY> {
    fn new() -> Self {
        Self {
            domain: mint_scheduler_domain(),
            next_token: 1,
            next_execution_generation: 1,
            queue: [None; CAPACITY],
            len: 0,
            running: [None; H2_SCHEDULER_CPU_CAPACITY],
            pending_block: [None; H2_SCHEDULER_CPU_CAPACITY],
            suspended: [None; H2_SCHEDULER_CPU_CAPACITY],
        }
    }

    fn contains(&self, thread: ThreadKey) -> bool {
        self.running
            .iter()
            .flatten()
            .any(|claim| claim.thread == thread)
            || self.queue[..self.len]
                .iter()
                .flatten()
                .any(|entry| entry.thread == thread)
    }

    fn push(&mut self, entry: QueueEntry) -> Result<(), SchedulerError> {
        if self.len == CAPACITY {
            return Err(SchedulerError::Capacity);
        }
        self.queue[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    fn remove_index(&mut self, index: usize) -> QueueEntry {
        let removed = self.queue[index]
            .take()
            .expect("scheduler removal index is occupied");
        for current in index..self.len.saturating_sub(1) {
            self.queue[current] = self.queue[current + 1].take();
        }
        self.len -= 1;
        self.queue[self.len] = None;
        removed
    }

    fn claim_first_runnable(&mut self) -> Result<Option<RunningClaim>, SchedulerError> {
        let Some(index) = self.queue[..self.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.state == SchedulerThreadState::Runnable && entry.continuation_cpu.is_none()
            })
        }) else {
            return Ok(None);
        };
        let generation = self.mint_execution_generation()?;
        let entry = self.remove_index(index);
        Ok(Some(RunningClaim {
            thread: entry.thread,
            generation,
        }))
    }

    fn claim_first_runnable_for_idle(
        &mut self,
        cpu: SchedulerCpuId,
        suspended: SuspendedContinuation,
    ) -> Result<Option<RunningClaim>, SchedulerError> {
        let Some(index) = self.queue[..self.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.state == SchedulerThreadState::Runnable
                    && (entry.continuation_cpu.is_none() || entry.continuation_cpu == Some(cpu))
            })
        }) else {
            return Ok(None);
        };
        let entry = self.queue[index].expect("runnable claim index is occupied");
        let generation = if entry.continuation_cpu == Some(cpu) {
            if entry.thread != suspended.thread
                || entry.continuation_generation != suspended.generation
            {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            suspended.generation
        } else {
            self.mint_execution_generation()?
        };
        let entry = self.remove_index(index);
        Ok(Some(RunningClaim {
            thread: entry.thread,
            generation,
        }))
    }

    fn running_cpu(&self, thread: ThreadKey) -> Option<SchedulerCpuId> {
        self.running
            .iter()
            .position(|current| current.is_some_and(|claim| claim.thread == thread))
            .and_then(SchedulerCpuId::new)
    }

    fn mint_execution_generation(&mut self) -> Result<u64, SchedulerError> {
        let generation = self.next_execution_generation;
        self.next_execution_generation = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        Ok(generation)
    }

    fn check_invariants(&self) -> Result<(), SchedulerError> {
        if self.len > CAPACITY || self.queue[self.len..].iter().any(Option::is_some) {
            return Err(SchedulerError::Capacity);
        }
        for (cpu_index, pending) in self.pending_block.iter().copied().enumerate() {
            if let Some(pending) = pending {
                let cpu = SchedulerCpuId::new(cpu_index).expect("bounded scheduler CPU index");
                if pending.cpu != cpu
                    || !self.running[cpu_index].is_some_and(|claim| {
                        claim.thread == pending.thread
                            && claim.generation == pending.execution_generation
                    })
                    || pending.execution_generation == 0
                {
                    return Err(SchedulerError::StaleBlockToken);
                }
            }
        }
        for (cpu_index, current) in self.running.iter().copied().enumerate() {
            if let Some(current) = current
                && (current.generation == 0
                    || self.running[..cpu_index]
                        .iter()
                        .flatten()
                        .any(|prior| prior.thread == current.thread)
                    || self.queue[..self.len]
                        .iter()
                        .flatten()
                        .any(|entry| entry.thread == current.thread))
            {
                return Err(SchedulerError::DuplicateThread);
            }
        }
        for (cpu_index, suspended) in self.suspended.iter().copied().enumerate() {
            let Some(suspended) = suspended else {
                continue;
            };
            if self.suspended[..cpu_index]
                .iter()
                .flatten()
                .any(|prior| prior.thread == suspended.thread)
                || suspended.generation == 0
                || self
                    .running
                    .iter()
                    .flatten()
                    .any(|claim| claim.thread == suspended.thread)
            {
                return Err(SchedulerError::DuplicateThread);
            }
            let cpu = SchedulerCpuId::new(cpu_index).expect("bounded scheduler CPU index");
            let queued_owner = self.queue[..self.len]
                .iter()
                .flatten()
                .find(|entry| entry.thread == suspended.thread)
                .map(|entry| (entry.continuation_cpu, entry.continuation_generation));
            match suspended.publication {
                SuspendedPublication::Queued
                    if queued_owner != Some((Some(cpu), suspended.generation)) =>
                {
                    return Err(SchedulerError::ContinuationOwned);
                }
                SuspendedPublication::Retired if queued_owner.is_some() => {
                    return Err(SchedulerError::ContinuationOwned);
                }
                _ => {}
            }
        }
        for (index, entry) in self.queue[..self.len].iter().enumerate() {
            let Some(entry) = entry else {
                return Err(SchedulerError::NotScheduled);
            };
            if matches!(
                entry.state,
                SchedulerThreadState::Reserved | SchedulerThreadState::Blocked
            ) && entry.token == 0
            {
                return Err(SchedulerError::StaleReservation);
            }
            if entry.state == SchedulerThreadState::Runnable && entry.token != 0 {
                return Err(SchedulerError::StaleReservation);
            }
            if entry.state == SchedulerThreadState::Blocked
                && (entry.block_cpu.is_none() || entry.block_execution_generation == 0)
            {
                return Err(SchedulerError::StaleBlockToken);
            }
            if entry.state != SchedulerThreadState::Blocked
                && (entry.block_cpu.is_some() || entry.block_execution_generation != 0)
            {
                return Err(SchedulerError::StaleBlockToken);
            }
            if entry.continuation_cpu.is_some()
                && !self.suspended.iter().flatten().any(|suspended| {
                    suspended.thread == entry.thread
                        && suspended.publication == SuspendedPublication::Queued
                })
            {
                return Err(SchedulerError::ContinuationOwned);
            }
            if entry.continuation_cpu.is_some() != (entry.continuation_generation != 0) {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            if self
                .running
                .iter()
                .flatten()
                .any(|claim| claim.thread == entry.thread)
                || self.queue[..index]
                    .iter()
                    .flatten()
                    .any(|prior| prior.thread == entry.thread)
            {
                return Err(SchedulerError::DuplicateThread);
            }
        }
        Ok(())
    }
}

/// Deterministic non-preemptive scheduler with four bounded CPU owners.
///
/// The private spin lock never escapes a method call. Callers therefore cannot
/// nest scheduler ownership around task finalization or process handle-table
/// work.  Releasing this lock from [`Self::complete_switch_on`] is also the
/// continuation-publication Release edge: another CPU must acquire this lock
/// to make that queued continuation eligible and claim it.
pub(crate) struct CooperativeScheduler<const CAPACITY: usize> {
    state: IrqSpinMutex<SchedulerState<CAPACITY>>,
}

impl<const CAPACITY: usize> CooperativeScheduler<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            state: IrqSpinMutex::new(SchedulerState::new()),
        }
    }

    pub(crate) fn reserve(
        &self,
        thread: ThreadKey,
    ) -> Result<SchedulerReservation, SchedulerError> {
        let mut state = self.state.lock();
        if state.contains(thread) {
            return Err(SchedulerError::DuplicateThread);
        }
        if state.len + state.running.iter().flatten().count() >= CAPACITY {
            return Err(SchedulerError::Capacity);
        }
        let token = state.next_token;
        state.next_token = state
            .next_token
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let domain = state.domain;
        state.push(QueueEntry {
            thread,
            state: SchedulerThreadState::Reserved,
            token,
            block_cpu: None,
            block_execution_generation: 0,
            continuation_cpu: None,
            continuation_generation: 0,
        })?;
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(SchedulerReservation {
            domain,
            token,
            thread,
        })
    }

    pub(crate) fn commit(
        &self,
        reservation: SchedulerReservation,
    ) -> Result<(), SchedulerReservationFailure> {
        let mut state = self.state.lock();
        if reservation.domain != state.domain {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::ForeignReservation,
                reservation,
            });
        }

        let len = state.len;
        let Some(entry) = state.queue[..len]
            .iter_mut()
            .flatten()
            .find(|entry| entry.thread == reservation.thread && entry.token == reservation.token)
        else {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::StaleReservation,
                reservation,
            });
        };
        if entry.state != SchedulerThreadState::Reserved {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::StaleReservation,
                reservation,
            });
        }
        entry.state = SchedulerThreadState::Runnable;
        entry.token = 0;
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(())
    }

    pub(crate) fn cancel(
        &self,
        reservation: SchedulerReservation,
    ) -> Result<(), SchedulerReservationFailure> {
        let mut state = self.state.lock();
        if reservation.domain != state.domain {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::ForeignReservation,
                reservation,
            });
        }
        let Some(index) = state.queue[..state.len].iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.thread == reservation.thread
                    && entry.token == reservation.token
                    && entry.state == SchedulerThreadState::Reserved
            })
        }) else {
            return Err(SchedulerReservationFailure {
                error: SchedulerError::StaleReservation,
                reservation,
            });
        };
        state.remove_index(index);
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(())
    }

    /// Atomically claims the oldest unowned Runnable Thread for `cpu`.
    pub(crate) fn schedule_next_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if state.running[cpu_index].is_some() {
            return Err(SchedulerError::CurrentThreadRunning);
        }
        if state.suspended[cpu_index].is_some() {
            return Err(SchedulerError::SwitchPending);
        }
        let current = state.claim_first_runnable()?;
        state.running[cpu_index] = current;
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(ScheduleDecision {
            previous: None,
            current: current.map(|claim| claim.thread),
        })
    }

    pub(crate) fn yield_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        let Some(previous_claim) = state.running[cpu_index] else {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        };
        if previous_claim.thread != thread {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        }
        if state.pending_block[cpu_index].is_some() {
            return Err(SchedulerError::BlockPreparationActive);
        }
        if state.suspended[cpu_index].is_some() {
            return Err(SchedulerError::SwitchPending);
        }
        let Some(next) = state.claim_first_runnable()? else {
            return Ok(ScheduleDecision {
                previous: Some(thread),
                current: Some(thread),
            });
        };
        state.running[cpu_index] = Some(next);
        state
            .push(QueueEntry {
                thread,
                state: SchedulerThreadState::Runnable,
                token: 0,
                block_cpu: None,
                block_execution_generation: 0,
                continuation_cpu: Some(cpu),
                continuation_generation: previous_claim.generation,
            })
            .expect("replacing one Running Thread preserves scheduler capacity");
        state.suspended[cpu_index] = Some(SuspendedContinuation {
            thread,
            generation: previous_claim.generation,
            publication: SuspendedPublication::Queued,
        });
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(ScheduleDecision {
            previous: Some(thread),
            current: Some(next.thread),
        })
    }

    pub(crate) fn prepare_block_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<BlockReservation, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        let Some(running_claim) = state.running[cpu_index] else {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        };
        if running_claim.thread != thread {
            return if state.running_cpu(thread).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        }
        if state.suspended[cpu_index].is_some() {
            return Err(SchedulerError::SwitchPending);
        }
        if state.pending_block[cpu_index].is_some() {
            return Err(SchedulerError::BlockPreparationActive);
        }
        let token = state.next_token;
        state.next_token = state
            .next_token
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(SchedulerError::TokenExhausted)?;
        let key = BlockWakeKey {
            domain: state.domain,
            token,
            thread,
            cpu,
            execution_generation: running_claim.generation,
        };
        state.pending_block[cpu_index] = Some(key);
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(BlockReservation { key })
    }

    pub(crate) fn cancel_block_on(
        &self,
        cpu: SchedulerCpuId,
        reservation: BlockReservation,
    ) -> Result<(), BlockReservationFailure> {
        let mut state = self.state.lock();
        if reservation.key.domain != state.domain {
            return Err(BlockReservationFailure {
                error: SchedulerError::ForeignBlockToken,
                reservation,
            });
        }
        if reservation.key.cpu != cpu || state.pending_block[cpu.index()] != Some(reservation.key) {
            return Err(BlockReservationFailure {
                error: SchedulerError::StaleBlockToken,
                reservation,
            });
        }
        state.pending_block[cpu.index()] = None;
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(())
    }

    pub(crate) fn commit_block_on(
        &self,
        cpu: SchedulerCpuId,
        reservation: BlockReservation,
    ) -> Result<ScheduleDecision, BlockReservationFailure> {
        let mut state = self.state.lock();
        if reservation.key.domain != state.domain {
            return Err(BlockReservationFailure {
                error: SchedulerError::ForeignBlockToken,
                reservation,
            });
        }
        let cpu_index = cpu.index();
        if reservation.key.cpu != cpu
            || state.pending_block[cpu_index] != Some(reservation.key)
            || !state.running[cpu_index].is_some_and(|claim| {
                claim.thread == reservation.key.thread
                    && claim.generation == reservation.key.execution_generation
            })
            || state.suspended[cpu_index].is_some()
        {
            return Err(BlockReservationFailure {
                error: SchedulerError::StaleBlockToken,
                reservation,
            });
        }
        let current = match state.claim_first_runnable() {
            Ok(current) => current,
            Err(error) => return Err(BlockReservationFailure { error, reservation }),
        };
        state.pending_block[cpu_index] = None;
        state.running[cpu_index] = None;
        state
            .push(QueueEntry {
                thread: reservation.key.thread,
                state: SchedulerThreadState::Blocked,
                token: reservation.key.token,
                block_cpu: Some(cpu),
                block_execution_generation: reservation.key.execution_generation,
                continuation_cpu: Some(cpu),
                continuation_generation: reservation.key.execution_generation,
            })
            .expect("moving one Running Thread to the queue preserves scheduler capacity");
        state.running[cpu_index] = current;
        state.suspended[cpu_index] = Some(SuspendedContinuation {
            thread: reservation.key.thread,
            generation: reservation.key.execution_generation,
            publication: SuspendedPublication::Queued,
        });
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(ScheduleDecision {
            previous: Some(reservation.key.thread),
            current: current.map(|claim| claim.thread),
        })
    }

    pub(crate) fn block_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<(BlockToken, ScheduleDecision), SchedulerError> {
        let reservation = self.prepare_block_current_on(cpu, thread)?;
        let key = reservation.wake_key();
        match self.commit_block_on(cpu, reservation) {
            Ok(decision) => Ok((BlockToken { key }, decision)),
            Err(failure) => Err(failure.error()),
        }
    }

    pub(crate) fn wake(&self, key: BlockWakeKey) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        if key.domain != state.domain {
            return Err(SchedulerError::ForeignBlockToken);
        }
        let len = state.len;
        let Some(entry) = state.queue[..len].iter_mut().flatten().find(|entry| {
            entry.thread == key.thread
                && entry.token == key.token
                && entry.block_cpu == Some(key.cpu)
                && entry.block_execution_generation == key.execution_generation
                && entry.state == SchedulerThreadState::Blocked
        }) else {
            return Err(SchedulerError::StaleBlockToken);
        };
        entry.state = SchedulerThreadState::Runnable;
        entry.token = 0;
        entry.block_cpu = None;
        entry.block_execution_generation = 0;
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(())
    }

    /// Validates that a deferred wake key belongs to this scheduler and names
    /// an already-issued generation without changing any scheduling state.
    ///
    /// Completed and terminally retired generations deliberately remain valid
    /// here: their durable wait registrations are the proof that the exact key
    /// once existed. Any still-live use of the token must retain the same Thread
    /// association.
    pub(crate) fn validate_issued_wake_key(&self, key: BlockWakeKey) -> Result<(), SchedulerError> {
        let state = self.state.lock();
        if key.domain != state.domain {
            return Err(SchedulerError::ForeignBlockToken);
        }
        if key.token == 0 || key.token >= state.next_token {
            return Err(SchedulerError::StaleBlockToken);
        }
        if state
            .pending_block
            .iter()
            .flatten()
            .any(|pending| pending.token == key.token && *pending != key)
            || state.queue[..state.len].iter().flatten().any(|entry| {
                entry.token == key.token
                    && (entry.thread != key.thread
                        || entry.state != SchedulerThreadState::Blocked
                        || entry.block_cpu != Some(key.cpu)
                        || entry.block_execution_generation != key.execution_generation)
            })
        {
            return Err(SchedulerError::StaleBlockToken);
        }
        Ok(())
    }

    /// Selects work after an IRQ while the CPU is physically executing a
    /// blocked syscall continuation on `suspended`'s kernel stack.
    ///
    /// The logical scheduler has no current Thread in this state. If the
    /// suspended Thread itself is selected, the caller may resume in place. If
    /// another Runnable Thread wins FIFO order, the returned decision names the
    /// physically-active suspended continuation as `previous` so the execution
    /// owner can save it before switching away.
    pub(crate) fn schedule_from_idle_on(
        &self,
        cpu: SchedulerCpuId,
        suspended: ThreadKey,
    ) -> Result<IdleScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if state.running[cpu_index].is_some() {
            return Err(SchedulerError::CurrentThreadRunning);
        }
        let Some(suspended_claim) = state.suspended[cpu_index] else {
            return Err(SchedulerError::ContinuationOwned);
        };
        if suspended_claim.thread != suspended
            || suspended_claim.publication != SuspendedPublication::Queued
        {
            return Err(SchedulerError::ContinuationOwned);
        }
        let Some(next) = state.claim_first_runnable_for_idle(cpu, suspended_claim)? else {
            debug_assert_eq!(state.check_invariants(), Ok(()));
            return Ok(IdleScheduleDecision::ContinueIdle);
        };
        state.running[cpu_index] = Some(next);
        if next.thread == suspended {
            state.suspended[cpu_index] = None;
            debug_assert_eq!(state.check_invariants(), Ok(()));
            Ok(IdleScheduleDecision::ResumeCurrent)
        } else {
            debug_assert_eq!(state.check_invariants(), Ok(()));
            Ok(IdleScheduleDecision::Switch(ScheduleDecision {
                previous: Some(suspended),
                current: Some(next.thread),
            }))
        }
    }

    /// Publishes that `cpu` has saved or abandoned its outgoing continuation.
    ///
    /// The architecture switch path writes the outgoing saved RSP before this
    /// call. Dropping the scheduler lock is a Release operation; a contender
    /// must subsequently acquire the same lock before it can claim the now
    /// unowned Runnable Thread and Acquire-load its continuation slot.
    pub(crate) fn complete_switch_on(
        &self,
        claim: SchedulerExecutionClaim,
    ) -> Result<(), SchedulerError> {
        let mut state = self.state.lock();
        if claim.domain != state.domain {
            return Err(SchedulerError::ForeignExecutionClaim);
        }
        if claim.generation == 0 {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        let cpu_index = claim.cpu.index();
        let Some(suspended) = state.suspended[cpu_index] else {
            return Err(SchedulerError::StaleExecutionClaim);
        };
        if suspended.thread != claim.thread || suspended.generation != claim.generation {
            return Err(SchedulerError::StaleExecutionClaim);
        }
        if suspended.publication == SuspendedPublication::Queued {
            let len = state.len;
            let Some(entry) = state.queue[..len]
                .iter_mut()
                .flatten()
                .find(|entry| entry.thread == claim.thread)
            else {
                return Err(SchedulerError::NotScheduled);
            };
            if entry.continuation_cpu != Some(claim.cpu)
                || entry.continuation_generation != claim.generation
            {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            entry.continuation_cpu = None;
            entry.continuation_generation = 0;
        }
        state.suspended[cpu_index] = None;
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(())
    }

    pub(crate) fn retire_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        let cpu_index = cpu.index();
        if let Some(running_cpu) = state.running_cpu(thread) {
            if running_cpu != cpu {
                return Err(SchedulerError::WrongCpu);
            }
            if state.suspended[cpu_index].is_some() {
                return Err(SchedulerError::SwitchPending);
            }
            if state.pending_block[cpu_index].is_some_and(|pending| pending.thread == thread) {
                state.pending_block[cpu_index] = None;
            }
            let outgoing = state.running[cpu_index].expect("running CPU retains its exact claim");
            let current = state.claim_first_runnable()?;
            state.running[cpu_index] = None;
            state.running[cpu_index] = current;
            state.suspended[cpu_index] = Some(SuspendedContinuation {
                thread,
                generation: outgoing.generation,
                publication: SuspendedPublication::Retired,
            });
            debug_assert_eq!(state.check_invariants(), Ok(()));
            return Ok(ScheduleDecision {
                previous: Some(thread),
                current: current.map(|claim| claim.thread),
            });
        }
        if let Some(owner_cpu) = state
            .suspended
            .iter()
            .position(|suspended| suspended.is_some_and(|owner| owner.thread == thread))
            .and_then(SchedulerCpuId::new)
        {
            if owner_cpu != cpu {
                return Err(SchedulerError::WrongCpu);
            }
            let Some(index) = state.queue[..state.len]
                .iter()
                .position(|entry| entry.is_some_and(|entry| entry.thread == thread))
            else {
                return Err(SchedulerError::NotScheduled);
            };
            state.remove_index(index);
            let suspended_generation = state.suspended[cpu_index]
                .expect("suspended Thread retains its exact claim")
                .generation;
            state.suspended[cpu_index] = Some(SuspendedContinuation {
                thread,
                generation: suspended_generation,
                publication: SuspendedPublication::Retired,
            });
            if state.running[cpu_index].is_none() {
                state.running[cpu_index] = state.claim_first_runnable()?;
            }
            debug_assert_eq!(state.check_invariants(), Ok(()));
            return Ok(ScheduleDecision {
                previous: Some(thread),
                current: state.running[cpu_index].map(|claim| claim.thread),
            });
        }
        let Some(index) = state.queue[..state.len]
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.thread == thread))
        else {
            return Err(SchedulerError::NotScheduled);
        };
        if state.queue[index].is_some_and(|entry| entry.continuation_cpu.is_some()) {
            return Err(SchedulerError::ContinuationOwned);
        }
        state.remove_index(index);
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(ScheduleDecision {
            previous: state.running[cpu_index].map(|claim| claim.thread),
            current: state.running[cpu_index].map(|claim| claim.thread),
        })
    }

    pub(crate) fn state(&self, thread: ThreadKey) -> Option<SchedulerThreadState> {
        let state = self.state.lock();
        if state
            .running
            .iter()
            .flatten()
            .any(|claim| claim.thread == thread)
        {
            return Some(SchedulerThreadState::Running);
        }
        state.queue[..state.len]
            .iter()
            .flatten()
            .find(|entry| entry.thread == thread)
            .map(|entry| entry.state)
    }

    #[cfg(test)]
    pub(crate) fn check_invariants(&self) -> Result<(), SchedulerError> {
        self.state.lock().check_invariants()
    }

    pub(crate) fn current_on(&self, cpu: SchedulerCpuId) -> Option<ThreadKey> {
        self.state.lock().running[cpu.index()].map(|claim| claim.thread)
    }

    pub(crate) fn running_cpu(&self, thread: ThreadKey) -> Option<SchedulerCpuId> {
        self.state.lock().running_cpu(thread)
    }

    pub(crate) fn running_claim_on(&self, cpu: SchedulerCpuId) -> Option<SchedulerExecutionClaim> {
        let state = self.state.lock();
        let claim = state.running[cpu.index()]?;
        Some(SchedulerExecutionClaim {
            domain: state.domain,
            cpu,
            thread: claim.thread,
            generation: claim.generation,
        })
    }

    pub(crate) fn suspended_claim_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> Option<SchedulerExecutionClaim> {
        let state = self.state.lock();
        let claim = state.suspended[cpu.index()]?;
        Some(SchedulerExecutionClaim {
            domain: state.domain,
            cpu,
            thread: claim.thread,
            generation: claim.generation,
        })
    }

    pub(crate) fn suspended_cpu(&self, thread: ThreadKey) -> Option<SchedulerCpuId> {
        self.state
            .lock()
            .suspended
            .iter()
            .position(|suspended| suspended.is_some_and(|owner| owner.thread == thread))
            .and_then(SchedulerCpuId::new)
    }

    pub(crate) fn validate_switch_on(
        &self,
        cpu: SchedulerCpuId,
        decision: ScheduleDecision,
    ) -> Result<(), SchedulerError> {
        let state = self.state.lock();
        let previous = decision.previous.ok_or(SchedulerError::NotRunning)?;
        let current = decision.current.ok_or(SchedulerError::NotRunning)?;
        if !state.running[cpu.index()].is_some_and(|claim| claim.thread == current) {
            return if state.running_cpu(current).is_some() {
                Err(SchedulerError::WrongCpu)
            } else {
                Err(SchedulerError::NotRunning)
            };
        }
        if state.suspended[cpu.index()].is_none_or(|owner| owner.thread != previous) {
            return Err(SchedulerError::ContinuationOwned);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn suspended_on(&self, cpu: SchedulerCpuId) -> Option<ThreadKey> {
        self.state.lock().suspended[cpu.index()].map(|suspended| suspended.thread)
    }

    // Temporary BSP adapters keep the pre-H2 target callers buildable while
    // the root integration lane migrates physical-current call sites.  They
    // must not be used after APs enter shared scheduling.
    pub(crate) fn schedule_next(&self) -> Result<ScheduleDecision, SchedulerError> {
        if let Some(suspended) = self.suspended_on_cpu(SchedulerCpuId::BOOTSTRAP) {
            return match self.schedule_from_idle(suspended)? {
                IdleScheduleDecision::ContinueIdle => Ok(ScheduleDecision {
                    previous: Some(suspended),
                    current: None,
                }),
                IdleScheduleDecision::ResumeCurrent => Ok(ScheduleDecision {
                    previous: Some(suspended),
                    current: Some(suspended),
                }),
                IdleScheduleDecision::Switch(decision) => Ok(decision),
            };
        }
        self.schedule_next_on(SchedulerCpuId::BOOTSTRAP)
    }

    pub(crate) fn yield_current(
        &self,
        thread: ThreadKey,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let decision = self.yield_current_on(SchedulerCpuId::BOOTSTRAP, thread)?;
        self.complete_bsp_model_switch(decision)?;
        Ok(decision)
    }

    pub(crate) fn prepare_block_current(
        &self,
        thread: ThreadKey,
    ) -> Result<BlockReservation, SchedulerError> {
        self.prepare_block_current_on(SchedulerCpuId::BOOTSTRAP, thread)
    }

    pub(crate) fn cancel_block(
        &self,
        reservation: BlockReservation,
    ) -> Result<(), BlockReservationFailure> {
        self.cancel_block_on(reservation.key.cpu, reservation)
    }

    pub(crate) fn commit_block(
        &self,
        reservation: BlockReservation,
    ) -> Result<ScheduleDecision, BlockReservationFailure> {
        let cpu = reservation.key.cpu;
        let decision = self.commit_block_on(cpu, reservation)?;
        if decision.current.is_some() {
            let claim = self
                .suspended_claim_on(cpu)
                .expect("block decision retains its outgoing execution claim");
            debug_assert_eq!(decision.previous, Some(claim.thread()));
            self.complete_switch_on(claim)
                .expect("BSP model switch completion follows a valid block decision");
        }
        Ok(decision)
    }

    pub(crate) fn block_current(
        &self,
        thread: ThreadKey,
    ) -> Result<(BlockToken, ScheduleDecision), SchedulerError> {
        let reservation = self.prepare_block_current(thread)?;
        let key = reservation.wake_key();
        match self.commit_block(reservation) {
            Ok(decision) => Ok((BlockToken { key }, decision)),
            Err(failure) => Err(failure.error()),
        }
    }

    pub(crate) fn schedule_from_idle(
        &self,
        suspended: ThreadKey,
    ) -> Result<IdleScheduleDecision, SchedulerError> {
        let decision = self.schedule_from_idle_on(SchedulerCpuId::BOOTSTRAP, suspended)?;
        if let IdleScheduleDecision::Switch(decision) = decision {
            self.complete_bsp_model_switch(decision)?;
        }
        Ok(decision)
    }

    pub(crate) fn retire(&self, thread: ThreadKey) -> Result<ScheduleDecision, SchedulerError> {
        if self
            .running_cpu(thread)
            .is_some_and(|cpu| cpu != SchedulerCpuId::BOOTSTRAP)
        {
            return Err(SchedulerError::WrongCpu);
        }
        let decision = self.retire_on(SchedulerCpuId::BOOTSTRAP, thread)?;
        self.complete_bsp_model_switch(decision)?;
        Ok(decision)
    }

    pub(crate) fn current(&self) -> Option<ThreadKey> {
        self.current_on(SchedulerCpuId::BOOTSTRAP)
    }

    fn complete_bsp_model_switch(&self, decision: ScheduleDecision) -> Result<(), SchedulerError> {
        if let Some(previous) = decision.previous
            && decision.previous != decision.current
        {
            let claim = self
                .suspended_claim_on(SchedulerCpuId::BOOTSTRAP)
                .ok_or(SchedulerError::StaleExecutionClaim)?;
            if claim.thread() != previous {
                return Err(SchedulerError::StaleExecutionClaim);
            }
            self.complete_switch_on(claim)?;
        }
        Ok(())
    }

    fn suspended_on_cpu(&self, cpu: SchedulerCpuId) -> Option<ThreadKey> {
        self.state.lock().suspended[cpu.index()].map(|suspended| suspended.thread)
    }
}

#[cfg(test)]
#[path = "scheduler/tests.rs"]
mod tests;
