//! Fixed-capacity DW0-E task payload and lifetime authority.
//!
//! `ObjectRegistry` remains the sole strong-liveness authority. This module
//! owns TaskGroup/Process/Thread payload state and consumes typed parent pins;
//! it never maintains an independent reference count.

use deepwyrm_abi::{
    DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP, DW_OBJECT_TYPE_THREAD,
    DW_TASK_STATE_CREATED, DW_TASK_STATE_EXITED, DW_TASK_STATE_RUNNING,
    DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_AUTHORIZED, DW_TERMINATION_NORMAL_EXIT,
    DwExceptionType, DwTaskState, DwTaskTerminationInfoV1, DwTerminationReason,
};

use crate::handle::{DrainResult, HandleTable};
use crate::object::{
    CreationRef, FinalRelease, HandleRef, InternalRef, ObjectId, ObjectRegistry,
    ObjectRegistryError,
};

mod authority;
mod execution;
mod scheduler;
#[allow(
    unused_imports,
    reason = "E3 execution resources are consumed by E4 context entry and E5 task syscall integration"
)]
pub(crate) use execution::{
    E3_INITIAL_USER_RFLAGS, ExecutionDomain, ExecutionResourceError, FpSimdPolicy,
    GeneralPurposeRegisters, KernelStackBounds, RetiredExitPins, SavedThreadContext,
    StartThreadError, UserTlsPolicy,
};
#[allow(
    unused_imports,
    reason = "E3 scheduler surface is consumed by the execution coordinator added in this phase"
)]
pub(crate) use scheduler::{
    CooperativeScheduler, ScheduleDecision, SchedulerError, SchedulerReservation,
    SchedulerReservationFailure, SchedulerThreadState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskError {
    Capacity,
    InvalidParent,
    ParentTerminating,
    InvalidTask,
    BadState,
    WrongObjectType,
    Reference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskGroupState {
    Active,
    Terminating,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskGroupKey(ObjectId);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessKey(ObjectId);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadKey(ObjectId);

impl TaskGroupKey {
    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}
impl ProcessKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }
    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}
impl ThreadKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }

    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelStackId(u64);
impl KernelStackId {
    pub(in crate::task) const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub(in crate::task) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadContextId(u64);
impl ThreadContextId {
    pub(in crate::task) const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub(in crate::task) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadStartState {
    entry: u64,
    stack_pointer: u64,
    argument0: u64,
    argument1: u64,
}

impl ThreadStartState {
    pub(crate) const fn from_validated_user_state(
        entry: u64,
        stack_pointer: u64,
        argument0: u64,
        argument1: u64,
    ) -> Self {
        Self {
            entry,
            stack_pointer,
            argument0,
            argument1,
        }
    }

    pub(crate) const fn entry(self) -> u64 {
        self.entry
    }
    pub(crate) const fn stack_pointer(self) -> u64 {
        self.stack_pointer
    }
    pub(crate) const fn argument0(self) -> u64 {
        self.argument0
    }
    pub(crate) const fn argument1(self) -> u64 {
        self.argument1
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ThreadExecutionResources {
    pub(in crate::task) kernel_stack: KernelStackId,
    pub(in crate::task) context: ThreadContextId,
}

impl ThreadExecutionResources {
    pub(crate) const fn kernel_stack(&self) -> KernelStackId {
        self.kernel_stack
    }
    pub(crate) const fn context(&self) -> ThreadContextId {
        self.context
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminationRecord {
    reason: DwTerminationReason,
    application_code: u32,
    exception_type: DwExceptionType,
    detail: u32,
    fault_address: u64,
}

impl TerminationRecord {
    const fn normal(code: u32) -> Self {
        Self {
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code: code,
            exception_type: DwExceptionType(0),
            detail: 0,
            fault_address: 0,
        }
    }

    const fn authorized(detail: u32) -> Self {
        Self {
            reason: DW_TERMINATION_AUTHORIZED,
            application_code: 0,
            exception_type: DwExceptionType(0),
            detail,
            fault_address: 0,
        }
    }

    const fn task_group_teardown() -> Self {
        Self {
            reason: deepwyrm_abi::DW_TERMINATION_TASK_GROUP_TEARDOWN,
            application_code: 0,
            exception_type: DwExceptionType(0),
            detail: 0,
            fault_address: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskStateRecord {
    state: DwTaskState,
    termination: Option<TerminationRecord>,
}

impl TaskStateRecord {
    const fn created() -> Self {
        Self {
            state: DW_TASK_STATE_CREATED,
            termination: None,
        }
    }

    fn mark_running(&mut self) -> Result<(), TaskError> {
        if self.state != DW_TASK_STATE_CREATED {
            return Err(TaskError::BadState);
        }
        self.state = DW_TASK_STATE_RUNNING;
        Ok(())
    }

    fn terminate(&mut self, termination: TerminationRecord) -> Result<(), TaskError> {
        if self.state == DW_TASK_STATE_EXITED {
            return Err(TaskError::BadState);
        }
        self.state = DW_TASK_STATE_EXITED;
        self.termination = Some(termination);
        Ok(())
    }

    fn abi(self) -> DwTaskTerminationInfoV1 {
        let termination = self.termination.unwrap_or(TerminationRecord {
            reason: DwTerminationReason(0),
            application_code: 0,
            exception_type: DwExceptionType(0),
            detail: 0,
            fault_address: 0,
        });
        DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            state: self.state,
            reason: termination.reason,
            application_code: termination.application_code,
            exception_type: termination.exception_type,
            detail: termination.detail,
            reserved0: 0,
            fault_address: termination.fault_address,
            reserved: [0; 3],
        }
    }
}

struct TaskGroupRecord<const GROUPS: usize, const PROCESSES: usize> {
    object: ObjectId,
    parent: Option<InternalRef>,
    state: TaskGroupState,
    child_groups: [Option<ObjectId>; GROUPS],
    processes: [Option<ObjectId>; PROCESSES],
}

struct ProcessRecord<const THREADS: usize, const HANDLES: usize> {
    object: ObjectId,
    parent: InternalRef,
    state: TaskStateRecord,
    execution_pin: Option<InternalRef>,
    root_region: Option<ObjectId>,
    threads: [Option<ObjectId>; THREADS],
    handles: HandleTable<HANDLES>,
}

struct ThreadRecord {
    object: ObjectId,
    parent: InternalRef,
    state: TaskStateRecord,
    execution_pin: Option<InternalRef>,
    start: Option<ThreadStartState>,
    kernel_stack: Option<KernelStackId>,
    context: Option<ThreadContextId>,
}

#[must_use = "task payload bindings must be sealed by ObjectRegistry before first publication"]
pub(crate) enum TaskPayloadBinding {
    TaskGroup {
        creation: CreationRef,
        key: TaskGroupKey,
    },
    Process {
        creation: CreationRef,
        key: ProcessKey,
    },
    Thread {
        creation: CreationRef,
        key: ThreadKey,
    },
}

impl TaskPayloadBinding {
    pub(crate) const fn task_group_key(&self) -> Option<TaskGroupKey> {
        match self {
            Self::TaskGroup { key, .. } => Some(*key),
            _ => None,
        }
    }
    pub(crate) const fn process_key(&self) -> Option<ProcessKey> {
        match self {
            Self::Process { key, .. } => Some(*key),
            _ => None,
        }
    }
    pub(crate) const fn thread_key(&self) -> Option<ThreadKey> {
        match self {
            Self::Thread { key, .. } => Some(*key),
            _ => None,
        }
    }
    pub(crate) fn into_creation(self) -> CreationRef {
        match self {
            Self::TaskGroup { creation, .. }
            | Self::Process { creation, .. }
            | Self::Thread { creation, .. } => creation,
        }
    }
}

#[must_use = "typed task cleanup must be consumed by ObjectRegistry"]
pub(crate) struct TaskPayloadCleanup {
    final_release: FinalRelease,
}
impl TaskPayloadCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

pub(crate) struct TaskFinalization {
    final_release: FinalRelease,
    parent: Option<InternalRef>,
}

#[must_use = "terminal execution pins must be released only after the task is no longer runnable"]
pub(crate) struct ExitPins<const THREADS: usize> {
    process: Option<InternalRef>,
    threads: [Option<InternalRef>; THREADS],
    resources: [Option<ThreadExecutionResources>; THREADS],
    count: usize,
}

impl<const THREADS: usize> ExitPins<THREADS> {
    fn empty() -> Self {
        Self {
            process: None,
            threads: core::array::from_fn(|_| None),
            resources: core::array::from_fn(|_| None),
            count: 0,
        }
    }
    fn push_thread(&mut self, pin: InternalRef, resources: Option<ThreadExecutionResources>) {
        assert!(self.count < THREADS, "terminal thread pin batch overflow");
        self.threads[self.count] = Some(pin);
        self.resources[self.count] = resources;
        self.count += 1;
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<InternalRef>,
        [Option<InternalRef>; THREADS],
        [Option<ThreadExecutionResources>; THREADS],
    ) {
        (self.process, self.threads, self.resources)
    }
}

pub(crate) struct ProcessExitEffects<const HANDLES: usize, const THREADS: usize> {
    pub(crate) drained: DrainResult<HANDLES>,
    pub(crate) pins: ExitPins<THREADS>,
}

pub(crate) struct TaskAuthority<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
> {
    groups: [Option<TaskGroupRecord<GROUPS, PROCESSES>>; GROUPS],
    processes: [Option<ProcessRecord<THREADS, HANDLES>>; PROCESSES],
    threads: [Option<ThreadRecord>; THREADS],
}

#[cfg(deepwyrm_integrated)]
pub(crate) fn complete_task_finalization<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: TaskFinalization,
) -> Option<FinalRelease> {
    let TaskFinalization {
        final_release,
        parent,
    } = finalization;
    let parent_final = parent.and_then(|pin| {
        registry.release_internal(pin).unwrap_or_else(|failure| {
            panic!(
                "task parent pin release violated object invariants: {:?}",
                failure.error()
            )
        })
    });
    if let Err(failure) =
        registry.complete_payload_finalization(TaskPayloadCleanup { final_release })
    {
        panic!(
            "generic task finalization became invalid after typed payload cleanup: {:?}",
            failure.error()
        );
    }
    parent_final
}

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(crate) struct TaskFinalizationError {
    error: TaskError,
    final_release: FinalRelease,
}
impl TaskFinalizationError {
    pub(crate) const fn error(&self) -> TaskError {
        self.error
    }
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskCreateError {
    Registry(ObjectRegistryError),
    Task(TaskError),
}

#[must_use = "TaskGroup teardown effects contain handle finalizers and execution pins to release outside task ownership"]
pub(crate) struct TaskGroupTerminationEffects<
    const PROCESSES: usize,
    const HANDLES: usize,
    const THREADS: usize,
> {
    processes: [Option<ProcessExitEffects<HANDLES, THREADS>>; PROCESSES],
    count: usize,
}

impl<const PROCESSES: usize, const HANDLES: usize, const THREADS: usize>
    TaskGroupTerminationEffects<PROCESSES, HANDLES, THREADS>
{
    fn empty() -> Self {
        Self {
            processes: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn push(&mut self, effects: ProcessExitEffects<HANDLES, THREADS>) {
        assert!(
            self.count < PROCESSES,
            "TaskGroup process-effect batch overflow"
        );
        self.processes[self.count] = Some(effects);
        self.count += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.count
    }

    pub(crate) fn into_processes(
        self,
    ) -> [Option<ProcessExitEffects<HANDLES, THREADS>>; PROCESSES] {
        self.processes
    }
}
