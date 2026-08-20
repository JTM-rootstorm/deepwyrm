use deepwyrm_abi::{
    DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD,
    DW_RIGHT_WAIT, DW_WAIT_MANY_MAX_ITEMS, DwSignals, DwWaitItemV1,
};

use crate::handle::{AcceptedObjectTypes, HandleTableError, ResolvedHandle};
use crate::ipc::{ChannelAuthority, ChannelError, ChannelWaitOutcome};
use crate::object::ObjectRegistry;
use crate::task::{
    BlockWakeKey, BlockedOperation, BlockedOperationError, BlockedOperationWinner, ExecutionDomain,
    ProcessKey, ScheduleDecision, SchedulerError, TaskAuthority, TaskError, ThreadKey,
};
use crate::time::DeadlineRegistration;

use super::operation::{WaitOperation, WaitOperationError, WaitOperationRegistry};
use super::{
    EventAuthority, EventWaitOutcome, WaitError, WaitRegistry, WakeBatch, current_signals_for,
    validate_wait_signals,
};

pub(crate) const WAIT_SET_LIMIT: usize = DW_WAIT_MANY_MAX_ITEMS as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitSelection {
    pub(crate) index: u32,
    pub(crate) observed: DwSignals,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitSetError {
    Task(TaskError),
    Handle(HandleTableError),
    Wait(WaitError),
    Channel(ChannelError),
    StateDrift,
}

pub(crate) struct WaitSources<
    'a,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
> {
    pub(crate) tasks: &'a TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    pub(crate) events: &'a EventAuthority<EVENTS>,
    pub(crate) channels: &'a ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    pub(crate) waits: &'a WaitRegistry<WAITERS>,
}

struct ResolvedWaitItem {
    target: ResolvedHandle,
    desired: DwSignals,
    item_index: u32,
}

#[must_use = "resolved wait pins must be released or transferred into registrations"]
pub(crate) struct ResolvedWaitSet {
    items: [Option<ResolvedWaitItem>; WAIT_SET_LIMIT],
    len: usize,
}

impl ResolvedWaitSet {
    pub(crate) fn resolve<
        const OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        registry: &mut ObjectRegistry<OBJECTS>,
        process: ProcessKey,
        requests: &[DwWaitItemV1],
    ) -> Result<Self, WaitSetError> {
        assert!(requests.len() <= WAIT_SET_LIMIT);
        let table = tasks.process_handles(process).map_err(WaitSetError::Task)?;
        let mut items = core::array::from_fn(|_| None);
        let mut len = 0;
        for (index, request) in requests.iter().copied().enumerate() {
            let target = match table.lookup(
                registry,
                request.handle,
                AcceptedObjectTypes::Any,
                DW_RIGHT_WAIT,
            ) {
                Ok(target) => target,
                Err(error) => {
                    release_items(registry, &mut items, len);
                    return Err(WaitSetError::Handle(error));
                }
            };
            if let Err(error) = validate_wait_signals(target.object_type(), request.signals) {
                release_internal_exact(registry, target.into_internal());
                release_items(registry, &mut items, len);
                return Err(WaitSetError::Wait(error));
            }
            items[index] = Some(ResolvedWaitItem {
                target,
                desired: request.signals,
                item_index: u32::try_from(index).expect("wait-many index fits generated u32 limit"),
            });
            len += 1;
        }
        Ok(Self { items, len })
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn select_ready<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EVENTS: usize,
        const CHANNEL_PAIRS: usize,
        const CHANNEL_DEPTH: usize,
        const WAITERS: usize,
    >(
        &self,
        sources: &WaitSources<
            '_,
            GROUPS,
            PROCESSES,
            THREADS,
            HANDLES,
            EVENTS,
            CHANNEL_PAIRS,
            CHANNEL_DEPTH,
            WAITERS,
        >,
    ) -> Result<Option<WaitSelection>, WaitSetError> {
        for item in self.items[..self.len].iter().flatten() {
            let observed = current_signals_for(
                sources.tasks,
                sources.events,
                sources.channels,
                &item.target,
            )
            .map_err(WaitSetError::Wait)?;
            if observed.0 & item.desired.0 != 0 {
                return Ok(Some(WaitSelection {
                    index: item.item_index,
                    observed,
                }));
            }
        }
        Ok(None)
    }

    fn register_generation<
        const OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EVENTS: usize,
        const CHANNEL_PAIRS: usize,
        const CHANNEL_DEPTH: usize,
        const WAITERS: usize,
    >(
        &self,
        registry: &mut ObjectRegistry<OBJECTS>,
        sources: &WaitSources<
            '_,
            GROUPS,
            PROCESSES,
            THREADS,
            HANDLES,
            EVENTS,
            CHANNEL_PAIRS,
            CHANNEL_DEPTH,
            WAITERS,
        >,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<Option<WaitSelection>, WaitSetError> {
        for item in self.items[..self.len].iter().flatten() {
            let retained = match item.target.retain(registry) {
                Ok(retained) => retained,
                Err(error) => {
                    release_cancelled_generation(registry, sources.waits.cancel_generation(wake));
                    return Err(WaitSetError::Handle(error));
                }
            };
            match register_one(
                sources,
                retained,
                item.desired,
                item.item_index,
                thread,
                wake,
            ) {
                Ok(RegisterOutcome::Registered) => {}
                Ok(RegisterOutcome::Ready(pin)) => {
                    release_internal_exact(registry, pin);
                    release_cancelled_generation(registry, sources.waits.cancel_generation(wake));
                    return self
                        .select_ready(sources)?
                        .ok_or(WaitSetError::StateDrift)
                        .map(Some);
                }
                Err((error, pin)) => {
                    release_internal_exact(registry, pin);
                    release_cancelled_generation(registry, sources.waits.cancel_generation(wake));
                    return Err(error);
                }
            }
        }

        match self.select_ready(sources) {
            Ok(Some(selection)) => {
                release_cancelled_generation(registry, sources.waits.cancel_generation(wake));
                Ok(Some(selection))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                release_cancelled_generation(registry, sources.waits.cancel_generation(wake));
                Err(error)
            }
        }
    }

    pub(crate) fn release<const OBJECTS: usize>(mut self, registry: &mut ObjectRegistry<OBJECTS>) {
        release_items(registry, &mut self.items, self.len);
        self.len = 0;
    }
}

enum RegisterOutcome {
    Ready(crate::object::InternalRef),
    Registered,
}

fn register_one<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
>(
    sources: &WaitSources<
        '_,
        GROUPS,
        PROCESSES,
        THREADS,
        HANDLES,
        EVENTS,
        CHANNEL_PAIRS,
        CHANNEL_DEPTH,
        WAITERS,
    >,
    target: ResolvedHandle,
    desired: DwSignals,
    item_index: u32,
    thread: ThreadKey,
    wake: BlockWakeKey,
) -> Result<RegisterOutcome, (WaitSetError, crate::object::InternalRef)> {
    match target.object_type() {
        DW_OBJECT_TYPE_EVENT => match sources.events.register_wait(
            sources.waits,
            target,
            desired,
            item_index,
            thread,
            wake,
        ) {
            Ok(EventWaitOutcome::Ready { pin, .. }) => Ok(RegisterOutcome::Ready(pin)),
            Ok(EventWaitOutcome::Registered(_registration)) => Ok(RegisterOutcome::Registered),
            Err(failure) => Err((WaitSetError::Wait(failure.error), failure.pin)),
        },
        DW_OBJECT_TYPE_CHANNEL => match sources.channels.register_wait(
            sources.waits,
            target,
            desired,
            item_index,
            thread,
            wake,
        ) {
            Ok(ChannelWaitOutcome::Ready { pin, .. }) => Ok(RegisterOutcome::Ready(pin)),
            Ok(ChannelWaitOutcome::Registered(_registration)) => Ok(RegisterOutcome::Registered),
            Err(failure) => Err((WaitSetError::Channel(failure.error), failure.pin)),
        },
        DW_OBJECT_TYPE_PROCESS | DW_OBJECT_TYPE_THREAD => {
            let observed =
                match current_signals_for(sources.tasks, sources.events, sources.channels, &target)
                {
                    Ok(observed) => observed,
                    Err(error) => {
                        return Err((WaitSetError::Wait(error), target.into_internal()));
                    }
                };
            if observed.0 & desired.0 != 0 {
                return Ok(RegisterOutcome::Ready(target.into_internal()));
            }
            match sources
                .waits
                .register(target.into_internal(), desired, item_index, thread, wake)
            {
                Ok(_registration) => Ok(RegisterOutcome::Registered),
                Err(failure) => Err((WaitSetError::Wait(failure.error()), failure.into_pin())),
            }
        }
        _ => Err((
            WaitSetError::Wait(WaitError::UnsupportedSource),
            target.into_internal(),
        )),
    }
}

fn release_items<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    items: &mut [Option<ResolvedWaitItem>; WAIT_SET_LIMIT],
    len: usize,
) {
    for item in &mut items[..len] {
        if let Some(item) = item.take() {
            release_internal_exact(registry, item.target.into_internal());
        }
    }
}

fn release_internal_exact<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    pin: crate::object::InternalRef,
) {
    assert!(
        registry.release_internal(pin).unwrap().is_none(),
        "wait setup pin unexpectedly became the final generic reference"
    );
}

fn release_cancelled_generation<const OBJECTS: usize, const WAITERS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    batch: WakeBatch<WAITERS>,
) {
    let (wakes, pins) = batch.into_parts();
    assert!(wakes.into_iter().flatten().next().is_none());
    for pin in pins.into_iter().flatten() {
        release_internal_exact(registry, pin);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitBeginError {
    Set(WaitSetError),
    Scheduler(SchedulerError),
    Blocked(BlockedOperationError),
    Operation(WaitOperationError),
}

pub(crate) enum WaitBeginOutcome<OUTPUT> {
    Ready {
        output: OUTPUT,
        deadline: Option<DeadlineRegistration>,
        selection: WaitSelection,
    },
    Suspended {
        wake: BlockWakeKey,
        decision: ScheduleDecision,
    },
}

pub(crate) struct WaitBeginFailure<OUTPUT> {
    pub(crate) error: WaitBeginError,
    pub(crate) output: OUTPUT,
    pub(crate) deadline: Option<DeadlineRegistration>,
}

pub(crate) struct WaitBeginContext<
    'a,
    OUTPUT,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
> {
    pub(crate) registry: &'a mut ObjectRegistry<OBJECTS>,
    pub(crate) sources: WaitSources<
        'a,
        GROUPS,
        PROCESSES,
        THREADS,
        HANDLES,
        EVENTS,
        CHANNEL_PAIRS,
        CHANNEL_DEPTH,
        WAITERS,
    >,
    pub(crate) execution: &'a ExecutionDomain<EXECUTION>,
    pub(crate) operations: &'a mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    pub(crate) process: ProcessKey,
    pub(crate) thread: ThreadKey,
}

pub(crate) fn begin_registered_wait<
    OUTPUT,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    set: ResolvedWaitSet,
    output: OUTPUT,
    deadline: Option<DeadlineRegistration>,
    context: WaitBeginContext<
        '_,
        OUTPUT,
        OBJECTS,
        GROUPS,
        PROCESSES,
        THREADS,
        HANDLES,
        EVENTS,
        CHANNEL_PAIRS,
        CHANNEL_DEPTH,
        WAITERS,
        EXECUTION,
    >,
) -> Result<WaitBeginOutcome<OUTPUT>, WaitBeginFailure<OUTPUT>> {
    let WaitBeginContext {
        registry,
        sources,
        execution,
        operations,
        process,
        thread,
    } = context;
    let block = match execution.prepare_block_current(thread) {
        Ok(block) => block,
        Err(error) => {
            set.release(registry);
            return Err(WaitBeginFailure {
                error: WaitBeginError::Scheduler(error),
                output,
                deadline,
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
            execution.cancel_block(block).unwrap_or_else(|failure| {
                panic!(
                    "fresh F7 block preparation failed rollback: {:?}",
                    failure.error()
                )
            });
            set.release(registry);
            return Err(WaitBeginFailure {
                error: WaitBeginError::Blocked(error),
                output,
                deadline,
            });
        }
    };
    let mut operation = Some(WaitOperation::new(
        process, thread, blocked, output, deadline,
    ));
    if let Err(error) = operations.publish(&mut operation) {
        let operation = operation
            .take()
            .expect("failed wait-operation publication remains caller-owned");
        let (output, deadline) = operation
            .complete(
                execution.blocked_operations(),
                BlockedOperationWinner::Cancelled,
            )
            .unwrap_or_else(|failure| {
                panic!("unpublished F7 operation cleanup drifted: {failure:?}")
            });
        execution.cancel_block(block).unwrap_or_else(|failure| {
            panic!(
                "fresh F7 block preparation failed rollback: {:?}",
                failure.error()
            )
        });
        set.release(registry);
        return Err(WaitBeginFailure {
            error: WaitBeginError::Operation(error),
            output,
            deadline,
        });
    }
    debug_assert!(operation.is_none());

    match set.register_generation(registry, &sources, thread, wake) {
        Ok(Some(selection)) => {
            let operation = operations
                .take_wake(wake)
                .expect("fresh F7 wait operation remains live");
            let (output, deadline) = operation
                .complete(
                    execution.blocked_operations(),
                    BlockedOperationWinner::Cancelled,
                )
                .unwrap_or_else(|failure| {
                    panic!("F7 ready rollback completion drifted: {failure:?}")
                });
            execution.cancel_block(block).unwrap_or_else(|failure| {
                panic!(
                    "F7 ready rollback block cancellation drifted: {:?}",
                    failure.error()
                )
            });
            set.release(registry);
            Ok(WaitBeginOutcome::Ready {
                output,
                deadline,
                selection,
            })
        }
        Ok(None) => {
            set.release(registry);
            let decision = execution.commit_block(block).unwrap_or_else(|failure| {
                panic!("F7 registered block commit drifted: {:?}", failure.error())
            });
            Ok(WaitBeginOutcome::Suspended { wake, decision })
        }
        Err(error) => {
            let operation = operations
                .take_wake(wake)
                .expect("fresh F7 wait operation remains live");
            let (output, deadline) = operation
                .complete(
                    execution.blocked_operations(),
                    BlockedOperationWinner::Cancelled,
                )
                .unwrap_or_else(|failure| {
                    panic!("F7 failed publication cleanup drifted: {failure:?}")
                });
            execution.cancel_block(block).unwrap_or_else(|failure| {
                panic!(
                    "F7 failed publication block cancellation drifted: {:?}",
                    failure.error()
                )
            });
            set.release(registry);
            Err(WaitBeginFailure {
                error: WaitBeginError::Set(error),
                output,
                deadline,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_abi::{DW_OBJECT_TYPE_EVENT, DW_SIGNAL_SIGNALED, dw_object_compatible_rights};

    use crate::memory::kernel_stack::KernelStackBounds;
    use crate::task::{SchedulerThreadState, ThreadStartState};
    use crate::wait::operation::WaitOperationRegistry;

    type Registry = ObjectRegistry<16>;
    type Tasks = TaskAuthority<1, 1, 1, 8>;
    type Events = EventAuthority<4>;
    type Channels = ChannelAuthority<1, 2>;
    type Waits = WaitRegistry<8>;
    type Execution = ExecutionDomain<1>;

    fn running_fixture() -> (Registry, Tasks, Execution, ProcessKey, ThreadKey) {
        let mut registry = Registry::new();
        let mut tasks = Tasks::new();
        let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
        let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
        assert!(registry.release_internal(root_owner).unwrap().is_none());
        let process_owner = registry
            .retain_internal_from_handle(&process_handle)
            .unwrap();
        let (thread, thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
        assert!(registry.release_internal(process_owner).unwrap().is_none());
        assert!(registry.release_handle(process_handle).unwrap().is_none());
        assert!(registry.release_handle(thread_handle).unwrap().is_none());

        let stack = KernelStackBounds::new(
            0xffff_9300_0000_0000,
            0xffff_9300_0000_1000,
            0xffff_9300_0001_1000,
        )
        .unwrap();
        let execution = Execution::new([stack]).unwrap();
        execution
            .start_thread(
                &mut tasks,
                thread,
                ThreadStartState::from_validated_user_state(
                    0x0000_0000_4000_0000,
                    0x0000_0000_5000_0000,
                    1,
                    2,
                ),
            )
            .unwrap();
        assert_eq!(execution.schedule_next().unwrap().current, Some(thread));
        (registry, tasks, execution, process, thread)
    }

    fn install_event(
        registry: &mut Registry,
        tasks: &mut Tasks,
        events: &Events,
        process: ProcessKey,
    ) -> (super::super::EventKey, deepwyrm_abi::DwHandle) {
        let (key, reference) = events.create_event(registry).unwrap();
        let handle = tasks
            .process_handles_mut(process)
            .unwrap()
            .install(reference, dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT))
            .unwrap();
        (key, handle)
    }

    fn close_event(
        registry: &mut Registry,
        tasks: &mut Tasks,
        events: &Events,
        process: ProcessKey,
        handle: deepwyrm_abi::DwHandle,
    ) {
        let release = tasks
            .process_handles_mut(process)
            .unwrap()
            .close(registry, handle)
            .unwrap()
            .unwrap();
        let finalization = events.take_finalization(release).unwrap();
        super::super::complete_event_finalization(registry, finalization);
    }

    #[test]
    fn ready_scan_chooses_lowest_input_index_deterministically() {
        let (mut registry, mut tasks, _execution, process, _thread) = running_fixture();
        let events = Events::new();
        let channels = Channels::new();
        let waits = Waits::new();
        let (first_key, first) = install_event(&mut registry, &mut tasks, &events, process);
        let (second_key, second) = install_event(&mut registry, &mut tasks, &events, process);
        assert_eq!(
            events
                .signal(first_key, DwSignals(0), DW_SIGNAL_SIGNALED, &waits)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            events
                .signal(second_key, DwSignals(0), DW_SIGNAL_SIGNALED, &waits)
                .unwrap()
                .len(),
            0
        );
        let requests = [
            DwWaitItemV1 {
                handle: second,
                signals: DW_SIGNAL_SIGNALED,
            },
            DwWaitItemV1 {
                handle: first,
                signals: DW_SIGNAL_SIGNALED,
            },
        ];
        let set = ResolvedWaitSet::resolve(&tasks, &mut registry, process, &requests).unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(
            set.select_ready(&WaitSources {
                tasks: &tasks,
                events: &events,
                channels: &channels,
                waits: &waits
            })
            .unwrap(),
            Some(WaitSelection {
                index: 0,
                observed: DW_SIGNAL_SIGNALED,
            })
        );
        set.release(&mut registry);
        close_event(&mut registry, &mut tasks, &events, process, first);
        close_event(&mut registry, &mut tasks, &events, process, second);
    }

    #[test]
    fn registration_barrier_returns_ready_without_blocking_if_source_flips() {
        let (mut registry, mut tasks, execution, process, thread) = running_fixture();
        let events = Events::new();
        let channels = Channels::new();
        let waits = Waits::new();
        let (event_key, event) = install_event(&mut registry, &mut tasks, &events, process);
        let requests = [DwWaitItemV1 {
            handle: event,
            signals: DW_SIGNAL_SIGNALED,
        }];
        let set = ResolvedWaitSet::resolve(&tasks, &mut registry, process, &requests).unwrap();
        assert_eq!(
            set.select_ready(&WaitSources {
                tasks: &tasks,
                events: &events,
                channels: &channels,
                waits: &waits
            })
            .unwrap(),
            None
        );

        // Simulate a transition after the caller's initial scan but before
        // source registration. register_wait's source lock must catch it.
        assert_eq!(
            events
                .signal(event_key, DwSignals(0), DW_SIGNAL_SIGNALED, &waits)
                .unwrap()
                .len(),
            0
        );
        let mut operations = WaitOperationRegistry::<u32, 1>::new();
        match begin_registered_wait(
            set,
            0x55,
            None,
            WaitBeginContext {
                registry: &mut registry,
                sources: WaitSources {
                    tasks: &tasks,
                    events: &events,
                    channels: &channels,
                    waits: &waits,
                },
                execution: &execution,
                operations: &mut operations,
                process,
                thread,
            },
        )
        .unwrap_or_else(|failure| panic!("wait begin failed: {:?}", failure.error))
        {
            WaitBeginOutcome::Ready {
                output,
                deadline,
                selection,
            } => {
                assert_eq!(output, 0x55);
                assert!(deadline.is_none());
                assert_eq!(selection.index, 0);
                assert_eq!(selection.observed, DW_SIGNAL_SIGNALED);
            }
            WaitBeginOutcome::Suspended { .. } => panic!("ready registration barrier blocked"),
        }
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Running)
        );
        assert_eq!(operations.len(), 0);
        assert_eq!(waits.len(), 0);
        close_event(&mut registry, &mut tasks, &events, process, event);
    }

    #[test]
    fn registered_wait_commits_block_then_signal_completes_exact_generation() {
        let (mut registry, mut tasks, execution, process, thread) = running_fixture();
        let events = Events::new();
        let channels = Channels::new();
        let waits = Waits::new();
        let (event_key, event) = install_event(&mut registry, &mut tasks, &events, process);
        let requests = [DwWaitItemV1 {
            handle: event,
            signals: DW_SIGNAL_SIGNALED,
        }];
        let set = ResolvedWaitSet::resolve(&tasks, &mut registry, process, &requests).unwrap();
        assert_eq!(
            set.select_ready(&WaitSources {
                tasks: &tasks,
                events: &events,
                channels: &channels,
                waits: &waits
            })
            .unwrap(),
            None
        );
        let mut operations = WaitOperationRegistry::<u32, 1>::new();
        let wake = match begin_registered_wait(
            set,
            0x77,
            None,
            WaitBeginContext {
                registry: &mut registry,
                sources: WaitSources {
                    tasks: &tasks,
                    events: &events,
                    channels: &channels,
                    waits: &waits,
                },
                execution: &execution,
                operations: &mut operations,
                process,
                thread,
            },
        )
        .unwrap_or_else(|failure| panic!("wait begin failed: {:?}", failure.error))
        {
            WaitBeginOutcome::Suspended { wake, decision } => {
                assert_eq!(decision.previous, Some(thread));
                assert_eq!(decision.current, None);
                wake
            }
            WaitBeginOutcome::Ready { .. } => panic!("unsignaled Event did not block"),
        };
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Blocked)
        );
        assert_eq!(waits.len(), 1);
        assert!(operations.contains_thread(thread));

        let batch = events
            .signal(event_key, DwSignals(0), DW_SIGNAL_SIGNALED, &waits)
            .unwrap();
        let (wakes, pins) = batch.into_parts();
        let mut selected = None;
        for intent in wakes.into_iter().flatten() {
            let winner = BlockedOperationWinner::Signal {
                item_index: intent.item_index(),
                observed: intent.observed(),
            };
            assert!(
                execution
                    .blocked_operations()
                    .try_claim_winner(intent.wake_key(), winner)
                    .unwrap()
            );
            execution.wake(intent.wake_key()).unwrap();
            selected = Some(winner);
        }
        for pin in pins.into_iter().flatten() {
            assert!(registry.release_internal(pin).unwrap().is_none());
        }
        let winner = selected.expect("Event signal produced one wake");
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Runnable)
        );
        let operation = operations.take_wake(wake).unwrap();
        assert_eq!(
            operation.winner(execution.blocked_operations()).unwrap(),
            Some(winner)
        );
        let (output, deadline) = operation
            .complete(execution.blocked_operations(), winner)
            .unwrap();
        assert_eq!(output, 0x77);
        assert!(deadline.is_none());
        assert_eq!(operations.len(), 0);
        assert_eq!(execution.schedule_next().unwrap().current, Some(thread));
        close_event(&mut registry, &mut tasks, &events, process, event);
    }
}
