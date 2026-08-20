use crate::task::{
    BlockWakeKey, BlockedOperation, BlockedOperationError, BlockedOperationRegistry,
    BlockedOperationWinner, ProcessKey, ThreadKey,
};
use crate::time::DeadlineRegistration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitOperationError {
    Capacity,
    DuplicateThread,
    StaleWake,
}

/// One durable owner for every resource that survives a suspended wait syscall.
///
/// The embedded `BlockedOperation<()>` owns the exact winner-ledger reservation.
/// Output mapping stability and finite-deadline ownership live beside it so
/// resume and terminal teardown cannot accidentally split cleanup authority.
#[must_use = "suspended wait resources must be resumed or terminally discarded"]
pub(crate) struct WaitOperation<OUTPUT> {
    process: ProcessKey,
    thread: ThreadKey,
    blocked: BlockedOperation<()>,
    output: OUTPUT,
    deadline: Option<DeadlineRegistration>,
}

impl<OUTPUT> WaitOperation<OUTPUT> {
    pub(crate) fn new(
        process: ProcessKey,
        thread: ThreadKey,
        blocked: BlockedOperation<()>,
        output: OUTPUT,
        deadline: Option<DeadlineRegistration>,
    ) -> Self {
        Self {
            process,
            thread,
            blocked,
            output,
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

    pub(crate) fn winner<const CAPACITY: usize>(
        &self,
        blocked: &BlockedOperationRegistry<CAPACITY>,
    ) -> Result<Option<BlockedOperationWinner>, BlockedOperationError> {
        blocked.winner(self.wake_key())
    }

    pub(crate) fn complete<const CAPACITY: usize>(
        self,
        blocked_registry: &BlockedOperationRegistry<CAPACITY>,
        winner: BlockedOperationWinner,
    ) -> Result<(OUTPUT, Option<DeadlineRegistration>), BlockedOperationError> {
        let Self {
            process: _,
            thread: _,
            blocked,
            output,
            deadline,
        } = self;
        blocked.complete_with(blocked_registry, winner, |()| ())?;
        Ok((output, deadline))
    }
}

/// Thread-context owner for resources that must survive a blocked syscall.
///
/// IRQ and typed signal paths deliberately do not touch this registry. They
/// claim the matching `BlockedOperationRegistry` winner and wake only the exact
/// scheduler generation. Resume or terminal task teardown later consumes this
/// record and performs heavyweight wait/output/deadline cleanup.
pub(crate) struct WaitOperationRegistry<OUTPUT, const CAPACITY: usize> {
    entries: [Option<WaitOperation<OUTPUT>>; CAPACITY],
}

impl<OUTPUT, const CAPACITY: usize> WaitOperationRegistry<OUTPUT, CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
        }
    }

    pub(crate) fn publish(
        &mut self,
        operation: &mut Option<WaitOperation<OUTPUT>>,
    ) -> Result<(), WaitOperationError> {
        let candidate = operation
            .as_ref()
            .expect("wait-operation publication requires a live candidate");
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.thread == candidate.thread)
        {
            return Err(WaitOperationError::DuplicateThread);
        }
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return Err(WaitOperationError::Capacity);
        };
        *slot = operation.take();
        Ok(())
    }

    pub(crate) fn take_wake(
        &mut self,
        wake: BlockWakeKey,
    ) -> Result<WaitOperation<OUTPUT>, WaitOperationError> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|entry| entry.wake_key() == wake))
            .ok_or(WaitOperationError::StaleWake)?;
        Ok(slot.take().expect("located wait operation remains present"))
    }

    pub(crate) fn take_thread(&mut self, thread: ThreadKey) -> Option<WaitOperation<OUTPUT>> {
        self.entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|entry| entry.thread == thread))
            .and_then(Option::take)
    }

    pub(crate) fn contains_thread(&self, thread: ThreadKey) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|entry| entry.thread == thread)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }
}

impl<OUTPUT, const CAPACITY: usize> Drop for WaitOperationRegistry<OUTPUT, CAPACITY> {
    fn drop(&mut self) {
        assert!(
            self.entries.iter().all(Option::is_none),
            "live suspended wait resources dropped without resume/terminal cleanup"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use crate::task::{BlockedOperationRegistry, CooperativeScheduler};
    use deepwyrm_abi::{DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD};

    fn keys() -> (
        ProcessKey,
        ThreadKey,
        BlockWakeKey,
        BlockedOperation<()>,
        BlockedOperationRegistry<1>,
    ) {
        let mut objects = ObjectRegistry::<2>::new();
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
        let block = scheduler.prepare_block_current(thread_key).unwrap();
        let wake = block.wake_key();
        scheduler.cancel_block(block).unwrap();
        let blocked_registry = BlockedOperationRegistry::<1>::new();
        let blocked =
            BlockedOperation::publish(&blocked_registry, process_key, thread_key, wake, ())
                .unwrap();
        (process_key, thread_key, wake, blocked, blocked_registry)
    }

    #[test]
    fn operation_registry_is_thread_unique_and_wake_exact() {
        let (process, thread, wake, blocked, blocked_registry) = keys();
        let mut registry = WaitOperationRegistry::<u32, 1>::new();
        let mut first = Some(WaitOperation::new(process, thread, blocked, 7, None));
        registry
            .publish(&mut first)
            .unwrap_or_else(|_| panic!("first wait operation publishes"));
        assert!(first.is_none());
        assert_eq!(registry.len(), 1);

        // A second operation for the same Thread is rejected without losing its
        // embedded blocked-operation owner. Its separate winner ledger is kept
        // live here so the rejected owner can be deliberately completed.
        let second_registry = BlockedOperationRegistry::<1>::new();
        let second_blocked =
            BlockedOperation::publish(&second_registry, process, thread, wake, ()).unwrap();
        let mut rejected = Some(WaitOperation::new(process, thread, second_blocked, 9, None));
        assert_eq!(
            registry.publish(&mut rejected),
            Err(WaitOperationError::DuplicateThread)
        );
        let (rejected_output, rejected_deadline) = rejected
            .take()
            .expect("rejected wait operation remains caller-owned")
            .complete(&second_registry, BlockedOperationWinner::Cancelled)
            .unwrap();
        assert_eq!(rejected_output, 9);
        assert!(rejected_deadline.is_none());

        let operation = registry.take_wake(wake).unwrap();
        assert_eq!(operation.process(), process);
        assert_eq!(operation.thread(), thread);
        assert_eq!(operation.wake_key(), wake);
        let (output, deadline) = operation
            .complete(&blocked_registry, BlockedOperationWinner::Cancelled)
            .unwrap();
        assert_eq!(output, 7);
        assert!(deadline.is_none());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn terminal_take_consumes_exact_thread_resources() {
        let (process, thread, wake, blocked, blocked_registry) = keys();
        let mut registry = WaitOperationRegistry::<u32, 2>::new();
        let mut operation = Some(WaitOperation::new(process, thread, blocked, 11, None));
        registry
            .publish(&mut operation)
            .unwrap_or_else(|_| panic!("wait operation publishes"));
        assert!(operation.is_none());
        let operation = registry.take_thread(thread).unwrap();
        assert_eq!(operation.wake_key(), wake);
        assert!(!registry.contains_thread(thread));
        let (output, deadline) = operation
            .complete(&blocked_registry, BlockedOperationWinner::Terminal)
            .unwrap();
        assert_eq!(output, 11);
        assert!(deadline.is_none());
    }
}
