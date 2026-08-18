use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::SpinMutex;

use super::ThreadKey;

static NEXT_SCHEDULER_DOMAIN: AtomicU64 = AtomicU64::new(1);

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
    CurrentThreadRunning,
    NotScheduled,
    NotRunning,
    TokenExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerThreadState {
    Reserved,
    Runnable,
    Running,
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
}

struct SchedulerState<const CAPACITY: usize> {
    domain: u64,
    next_token: u64,
    queue: [Option<QueueEntry>; CAPACITY],
    len: usize,
    current: Option<ThreadKey>,
}

impl<const CAPACITY: usize> SchedulerState<CAPACITY> {
    fn new() -> Self {
        Self {
            domain: mint_scheduler_domain(),
            next_token: 1,
            queue: [None; CAPACITY],
            len: 0,
            current: None,
        }
    }

    fn contains(&self, thread: ThreadKey) -> bool {
        self.current == Some(thread)
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

    fn pop_first_runnable(&mut self) -> Option<ThreadKey> {
        let index = self.queue[..self.len].iter().position(|entry| {
            entry.is_some_and(|entry| entry.state == SchedulerThreadState::Runnable)
        })?;
        Some(self.remove_index(index).thread)
    }

    fn check_invariants(&self) -> Result<(), SchedulerError> {
        if self.len > CAPACITY || self.queue[self.len..].iter().any(Option::is_some) {
            return Err(SchedulerError::Capacity);
        }
        for (index, entry) in self.queue[..self.len].iter().enumerate() {
            let Some(entry) = entry else {
                return Err(SchedulerError::NotScheduled);
            };
            if self.current == Some(entry.thread)
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

/// Deterministic non-preemptive BSP scheduler.
///
/// The private spin lock never escapes a method call. Callers therefore cannot
/// nest scheduler ownership around task finalization or process handle-table work.
pub(crate) struct CooperativeScheduler<const CAPACITY: usize> {
    state: SpinMutex<SchedulerState<CAPACITY>>,
}

impl<const CAPACITY: usize> CooperativeScheduler<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            state: SpinMutex::new(SchedulerState::new()),
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
        if state.len + usize::from(state.current.is_some()) >= CAPACITY {
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

    pub(crate) fn schedule_next(&self) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        if state.current.is_some() {
            return Err(SchedulerError::CurrentThreadRunning);
        }
        let current = state.pop_first_runnable();
        state.current = current;
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(ScheduleDecision {
            previous: None,
            current,
        })
    }

    pub(crate) fn yield_current(
        &self,
        thread: ThreadKey,
    ) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        if state.current != Some(thread) {
            return Err(SchedulerError::NotRunning);
        }
        let Some(next) = state.pop_first_runnable() else {
            return Ok(ScheduleDecision {
                previous: Some(thread),
                current: Some(thread),
            });
        };
        state.push(QueueEntry {
            thread,
            state: SchedulerThreadState::Runnable,
            token: 0,
        })?;
        state.current = Some(next);
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(ScheduleDecision {
            previous: Some(thread),
            current: Some(next),
        })
    }

    pub(crate) fn retire(&self, thread: ThreadKey) -> Result<ScheduleDecision, SchedulerError> {
        let mut state = self.state.lock();
        let previous = state.current;
        if state.current == Some(thread) {
            state.current = state.pop_first_runnable();
            debug_assert_eq!(state.check_invariants(), Ok(()));
            return Ok(ScheduleDecision {
                previous,
                current: state.current,
            });
        }
        let Some(index) = state.queue[..state.len]
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.thread == thread))
        else {
            return Err(SchedulerError::NotScheduled);
        };
        state.remove_index(index);
        debug_assert_eq!(state.check_invariants(), Ok(()));
        Ok(ScheduleDecision {
            previous,
            current: state.current,
        })
    }

    pub(crate) fn state(&self, thread: ThreadKey) -> Option<SchedulerThreadState> {
        let state = self.state.lock();
        if state.current == Some(thread) {
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

    #[cfg(test)]
    pub(crate) fn current(&self) -> Option<ThreadKey> {
        self.state.lock().current
    }
}

#[cfg(test)]
#[path = "scheduler/tests.rs"]
mod tests;
