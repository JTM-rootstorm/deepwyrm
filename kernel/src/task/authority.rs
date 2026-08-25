use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_TASK_OPERATION_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_task_operation_domain() -> u64 {
    NEXT_TASK_OPERATION_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .expect("task operation domain space exhausted")
}

impl<const GROUPS: usize, const PROCESSES: usize, const THREADS: usize, const HANDLES: usize>
    TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>
{
    pub(crate) fn new() -> Self {
        Self {
            operation_domain: mint_task_operation_domain(),
            groups: core::array::from_fn(|_| None),
            processes: core::array::from_fn(|_| None),
            threads: core::array::from_fn(|_| None),
        }
    }

    pub(crate) fn bind_root_group(
        &mut self,
        creation: CreationRef,
    ) -> Result<TaskPayloadBinding, (TaskError, CreationRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_TASK_GROUP {
            return Err((TaskError::WrongObjectType, creation));
        }
        let slot = match self.groups.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => return Err((TaskError::Capacity, creation)),
        };
        let key = TaskGroupKey(creation.id());
        self.groups[slot] = Some(TaskGroupRecord {
            object: creation.id(),
            parent: None,
            state: TaskGroupState::Active,
            child_groups: [None; GROUPS],
            processes: [None; PROCESSES],
            reserved_processes: [None; PROCESSES],
        });
        Ok(TaskPayloadBinding::TaskGroup { creation, key })
    }

    pub(crate) fn bind_child_group(
        &mut self,
        creation: CreationRef,
        parent: InternalRef,
    ) -> Result<TaskPayloadBinding, (TaskError, CreationRef, InternalRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_TASK_GROUP
            || parent.object_type() != DW_OBJECT_TYPE_TASK_GROUP
        {
            return Err((TaskError::WrongObjectType, creation, parent));
        }
        let parent_slot = match self.group_slot(TaskGroupKey(parent.id())) {
            Ok(slot) => slot,
            Err(error) => return Err((error, creation, parent)),
        };
        if self.groups[parent_slot]
            .as_ref()
            .expect("validated group slot")
            .state
            != TaskGroupState::Active
        {
            return Err((TaskError::ParentTerminating, creation, parent));
        }
        let child_index = match self.groups[parent_slot]
            .as_ref()
            .expect("validated group slot")
            .child_groups
            .iter()
            .position(Option::is_none)
        {
            Some(index) => index,
            None => return Err((TaskError::Capacity, creation, parent)),
        };
        let slot = match self.groups.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => return Err((TaskError::Capacity, creation, parent)),
        };
        let key = TaskGroupKey(creation.id());
        self.groups[parent_slot]
            .as_mut()
            .expect("validated group slot")
            .child_groups[child_index] = Some(creation.id());
        self.groups[slot] = Some(TaskGroupRecord {
            object: creation.id(),
            parent: Some(parent),
            state: TaskGroupState::Active,
            child_groups: [None; GROUPS],
            processes: [None; PROCESSES],
            reserved_processes: [None; PROCESSES],
        });
        Ok(TaskPayloadBinding::TaskGroup { creation, key })
    }

    fn bind_prepared_process(
        &mut self,
        creation: CreationRef,
        parent: InternalRef,
    ) -> Result<TaskPayloadBinding, (TaskError, CreationRef, InternalRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_PROCESS
            || parent.object_type() != DW_OBJECT_TYPE_TASK_GROUP
        {
            return Err((TaskError::WrongObjectType, creation, parent));
        }
        let parent_slot = match self.group_slot(TaskGroupKey(parent.id())) {
            Ok(slot) => slot,
            Err(error) => return Err((error, creation, parent)),
        };
        if self.groups[parent_slot]
            .as_ref()
            .expect("validated group slot")
            .state
            != TaskGroupState::Active
        {
            return Err((TaskError::ParentTerminating, creation, parent));
        }
        let child_index = match self.groups[parent_slot]
            .as_ref()
            .expect("validated group slot")
            .processes
            .iter()
            .zip(
                self.groups[parent_slot]
                    .as_ref()
                    .expect("validated group slot")
                    .reserved_processes
                    .iter(),
            )
            .position(|(published, reserved)| published.is_none() && reserved.is_none())
        {
            Some(index) => index,
            None => return Err((TaskError::Capacity, creation, parent)),
        };
        let slot = match self.processes.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => return Err((TaskError::Capacity, creation, parent)),
        };
        let key = ProcessKey(creation.id());
        self.groups[parent_slot]
            .as_mut()
            .expect("validated group slot")
            .reserved_processes[child_index] = Some(creation.id());
        self.processes[slot] = Some(ProcessRecord {
            object: creation.id(),
            parent,
            state: TaskStateRecord::created(),
            execution_pin: None,
            root_region: None,
            root_region_reserved: false,
            hierarchy: ProcessHierarchyState::Reserved(child_index),
            threads: [None; THREADS],
            handles: HandleTable::new(),
            operations: ProcessOperationState::accepting(),
        });
        Ok(TaskPayloadBinding::Process { creation, key })
    }

    pub(crate) fn bind_thread(
        &mut self,
        creation: CreationRef,
        parent: InternalRef,
    ) -> Result<TaskPayloadBinding, (TaskError, CreationRef, InternalRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_THREAD
            || parent.object_type() != DW_OBJECT_TYPE_PROCESS
        {
            return Err((TaskError::WrongObjectType, creation, parent));
        }
        let process_slot = match self.process_slot(ProcessKey(parent.id())) {
            Ok(slot) => slot,
            Err(error) => return Err((error, creation, parent)),
        };
        let process = self.processes[process_slot]
            .as_mut()
            .expect("validated process slot");
        if process.operations.phase != ProcessLifecycleState::AcceptingOperations {
            return Err((TaskError::BadState, creation, parent));
        }
        let child_index = match process.threads.iter().position(Option::is_none) {
            Some(index) => index,
            None => return Err((TaskError::Capacity, creation, parent)),
        };
        let slot = match self.threads.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => return Err((TaskError::Capacity, creation, parent)),
        };
        let key = ThreadKey(creation.id());
        process.threads[child_index] = Some(creation.id());
        self.threads[slot] = Some(ThreadRecord {
            object: creation.id(),
            parent,
            state: TaskStateRecord::created(),
            execution_pin: None,
            start: None,
            kernel_stack: None,
            context: None,
        });
        Ok(TaskPayloadBinding::Thread { creation, key })
    }

    pub(crate) fn attach_process_execution_pin(
        &mut self,
        key: ProcessKey,
        pin: InternalRef,
    ) -> Result<(), TaskError> {
        if pin.id() != key.0 || pin.object_type() != DW_OBJECT_TYPE_PROCESS {
            return Err(TaskError::Reference);
        }
        let process = self.process_mut(key)?;
        if process.execution_pin.is_some() {
            return Err(TaskError::BadState);
        }
        process.execution_pin = Some(pin);
        Ok(())
    }

    fn commit_prepared_process(&mut self, key: ProcessKey) {
        let (parent, reservation) = {
            let process = self
                .process(key)
                .expect("prepared Process record remains live until commit");
            assert_eq!(
                process.state.state, DW_TASK_STATE_CREATED,
                "prepared Process state changed before hierarchy commit"
            );
            match process.hierarchy {
                ProcessHierarchyState::Reserved(slot) => (TaskGroupKey(process.parent.id()), slot),
                ProcessHierarchyState::Attached(_) => {
                    panic!("prepared Process hierarchy committed twice")
                }
            }
        };
        let parent_slot = self
            .group_slot(parent)
            .expect("prepared Process parent remains live until commit");
        let group = self.groups[parent_slot]
            .as_mut()
            .expect("prepared Process parent group record remains live");
        assert_eq!(
            group.state,
            TaskGroupState::Active,
            "prepared Process parent state changed before no-fail commit"
        );
        assert_eq!(
            group.processes[reservation], None,
            "prepared Process reserved hierarchy slot was published early"
        );
        assert_eq!(
            group.reserved_processes[reservation],
            Some(key.object_id()),
            "prepared Process hierarchy reservation identity drifted"
        );
        group.reserved_processes[reservation] = None;
        group.processes[reservation] = Some(key.object_id());
        self.process_mut(key)
            .expect("prepared Process record remains live through commit")
            .hierarchy = ProcessHierarchyState::Attached(reservation);
    }

    fn take_prepared_process_execution(&mut self, key: ProcessKey) -> InternalRef {
        let process = self
            .process_mut(key)
            .expect("prepared Process record remains live until cancellation");
        assert_eq!(
            process.state.state, DW_TASK_STATE_CREATED,
            "prepared Process state changed before cancellation"
        );
        assert!(
            process.root_region.is_none(),
            "prepared Process cancellation requires root-region cancellation first"
        );
        assert!(
            process.threads.iter().all(Option::is_none),
            "prepared Process cancellation cannot retain child Threads"
        );
        assert!(
            process.handles.is_empty(),
            "prepared Process cancellation cannot retain child Handles"
        );
        assert!(
            matches!(process.hierarchy, ProcessHierarchyState::Reserved(_)),
            "published Process cannot use prepared cancellation"
        );
        process
            .execution_pin
            .take()
            .expect("prepared Process retains its execution pin")
    }

    pub(crate) fn reserve_root_region_attachment(
        &mut self,
        key: ProcessKey,
    ) -> Result<PreparedRootRegionAttachment, TaskError> {
        let process = self.process_mut(key)?;
        if process.state.state != DW_TASK_STATE_CREATED
            || process.operations.phase != ProcessLifecycleState::AcceptingOperations
            || process.root_region.is_some()
            || process.root_region_reserved
        {
            return Err(TaskError::BadState);
        }
        process.root_region_reserved = true;
        Ok(PreparedRootRegionAttachment {
            process: key,
            completed: false,
        })
    }

    fn commit_prepared_root_region_attachment(&mut self, key: ProcessKey, object: ObjectId) {
        let process = self
            .process_mut(key)
            .expect("prepared Process record remains live for root attachment");
        assert_eq!(
            process.state.state, DW_TASK_STATE_CREATED,
            "prepared root attachment changed Process state before commit"
        );
        assert!(
            process.root_region.is_none() && process.root_region_reserved,
            "prepared root attachment reservation drifted before commit"
        );
        process.root_region = Some(object);
        process.root_region_reserved = false;
    }

    fn cancel_prepared_root_region_attachment(&mut self, key: ProcessKey) {
        let process = self
            .process_mut(key)
            .expect("prepared Process record remains live for root cancellation");
        assert_eq!(
            process.state.state, DW_TASK_STATE_CREATED,
            "prepared root attachment changed Process state before cancellation"
        );
        assert!(
            process.root_region.is_none() && process.root_region_reserved,
            "prepared root attachment reservation drifted before cancellation"
        );
        process.root_region_reserved = false;
    }

    pub(crate) fn attach_thread_execution_pin(
        &mut self,
        key: ThreadKey,
        pin: InternalRef,
    ) -> Result<(), TaskError> {
        if pin.id() != key.0 || pin.object_type() != DW_OBJECT_TYPE_THREAD {
            return Err(TaskError::Reference);
        }
        let thread = self.thread_mut(key)?;
        if thread.execution_pin.is_some() {
            return Err(TaskError::BadState);
        }
        thread.execution_pin = Some(pin);
        Ok(())
    }

    pub(crate) fn process_handles(
        &self,
        key: ProcessKey,
    ) -> Result<&HandleTable<HANDLES>, TaskError> {
        Ok(&self.process(key)?.handles)
    }

    pub(crate) fn process_handles_mut(
        &mut self,
        key: ProcessKey,
    ) -> Result<&mut HandleTable<HANDLES>, TaskError> {
        let process = self.process_mut(key)?;
        if process.operations.phase != ProcessLifecycleState::AcceptingOperations {
            return Err(TaskError::BadState);
        }
        Ok(&mut process.handles)
    }

    pub(crate) fn process_handles_mut_for_operation(
        &mut self,
        lease: &ProcessOperationLease,
        key: ProcessKey,
    ) -> Result<&mut HandleTable<HANDLES>, TaskError> {
        self.validate_process_operation(lease, key)?;
        Ok(&mut self.process_mut(key)?.handles)
    }

    pub(crate) fn process_handle_count(&self, key: ProcessKey) -> Result<usize, TaskError> {
        Ok(self.process(key)?.handles.len())
    }

    pub(crate) fn thread_process(&self, key: ThreadKey) -> Result<ProcessKey, TaskError> {
        Ok(ProcessKey(self.thread(key)?.parent.id()))
    }

    pub(crate) fn drain_exited_process_handles<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        key: ProcessKey,
    ) -> Result<DrainResult<HANDLES>, TaskError> {
        if self.process(key)?.state.state != DW_TASK_STATE_EXITED {
            return Err(TaskError::BadState);
        }
        self.drain_process_handles(registry, key)
    }

    fn drain_process_handles<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        key: ProcessKey,
    ) -> Result<DrainResult<HANDLES>, TaskError> {
        Ok(self.process_mut(key)?.handles.drain(registry))
    }

    pub(crate) fn attach_root_region(
        &mut self,
        key: ProcessKey,
        object: ObjectId,
    ) -> Result<(), TaskError> {
        let process = self.process_mut(key)?;
        if process.state.state != DW_TASK_STATE_CREATED
            || process.operations.phase != ProcessLifecycleState::AcceptingOperations
            || process.root_region.is_some()
            || process.root_region_reserved
        {
            return Err(TaskError::BadState);
        }
        process.root_region = Some(object);
        Ok(())
    }

    pub(crate) fn rollback_root_region_attachment(
        &mut self,
        key: ProcessKey,
        object: ObjectId,
    ) -> Result<(), TaskError> {
        let process = self.process_mut(key)?;
        if process.state.state != DW_TASK_STATE_CREATED
            || process.root_region != Some(object)
            || process.root_region_reserved
        {
            return Err(TaskError::BadState);
        }
        process.root_region = None;
        Ok(())
    }

    pub(crate) fn take_exited_root_region(
        &mut self,
        key: ProcessKey,
    ) -> Result<Option<ObjectId>, TaskError> {
        let process = self.process_mut(key)?;
        if process.state.state != DW_TASK_STATE_EXITED {
            return Err(TaskError::BadState);
        }
        Ok(process.root_region.take())
    }

    pub(crate) fn root_region(&self, key: ProcessKey) -> Result<Option<ObjectId>, TaskError> {
        Ok(self.process(key)?.root_region)
    }

    pub(crate) fn process_info(
        &self,
        key: ProcessKey,
    ) -> Result<DwTaskTerminationInfoV1, TaskError> {
        Ok(self.process(key)?.state.abi())
    }

    pub(crate) fn process_lifecycle(
        &self,
        key: ProcessKey,
    ) -> Result<ProcessLifecycleState, TaskError> {
        Ok(self.process(key)?.operations.phase)
    }

    pub(crate) fn process_thread_keys(
        &self,
        key: ProcessKey,
    ) -> Result<[Option<ThreadKey>; THREADS], TaskError> {
        let threads = self.process(key)?.threads;
        Ok(threads.map(|thread| thread.map(ThreadKey)))
    }

    /// Acquires move-only authority for setup or publication associated with a
    /// live Process. New leases are rejected as soon as quiescing begins.
    pub(crate) fn acquire_process_operation(
        &mut self,
        key: ProcessKey,
    ) -> Result<ProcessOperationLease, TaskError> {
        let authority_domain = self.operation_domain;
        let process = self.process_mut(key)?;
        if process.operations.phase != ProcessLifecycleState::AcceptingOperations {
            return Err(TaskError::BadState);
        }
        process.operations.active = process
            .operations
            .active
            .checked_add(1)
            .ok_or(TaskError::Capacity)?;
        Ok(ProcessOperationLease {
            authority_domain,
            process: key,
            generation: process.operations.generation,
            completed: false,
        })
    }

    pub(crate) fn validate_process_operation(
        &self,
        lease: &ProcessOperationLease,
        key: ProcessKey,
    ) -> Result<(), TaskError> {
        let process = self.process(key)?;
        if lease.completed
            || lease.authority_domain != self.operation_domain
            || lease.process != key
            || lease.generation != process.operations.generation
            || process.operations.phase == ProcessLifecycleState::Exited
            || process.operations.active == 0
        {
            return Err(TaskError::Reference);
        }
        Ok(())
    }

    pub(crate) fn release_process_operation(
        &mut self,
        mut lease: ProcessOperationLease,
    ) -> Result<(), (TaskError, ProcessOperationLease)> {
        let authority_domain = self.operation_domain;
        let process = match self.process_mut(lease.process) {
            Ok(process) => process,
            Err(error) => return Err((error, lease)),
        };
        if lease.completed
            || lease.authority_domain != authority_domain
            || lease.generation != process.operations.generation
            || process.operations.phase == ProcessLifecycleState::Exited
            || process.operations.active == 0
        {
            return Err((TaskError::Reference, lease));
        }
        process.operations.active -= 1;
        lease.completed = true;
        Ok(())
    }

    /// Closes the operation gate. A retry returns proof once all leases that
    /// predate the close have been released.
    pub(crate) fn begin_process_quiesce(
        &mut self,
        key: ProcessKey,
    ) -> Result<ProcessQuiescenceProof, ProcessGateError> {
        let authority_domain = self.operation_domain;
        let process = self.process_mut(key).map_err(ProcessGateError::Task)?;
        match process.operations.phase {
            ProcessLifecycleState::AcceptingOperations => {
                process.operations.phase = ProcessLifecycleState::Quiescing;
            }
            ProcessLifecycleState::Quiescing => {}
            ProcessLifecycleState::Exited => {
                return Err(ProcessGateError::Task(TaskError::BadState));
            }
        }
        if process.operations.active != 0 {
            return Err(ProcessGateError::OperationsInFlight);
        }
        Ok(ProcessQuiescenceProof {
            authority_domain,
            process: key,
            generation: process.operations.generation,
        })
    }

    pub(crate) fn process_quiescence_proof(
        &self,
        key: ProcessKey,
    ) -> Result<ProcessQuiescenceProof, TaskError> {
        let process = self.process(key)?;
        if process.operations.phase == ProcessLifecycleState::AcceptingOperations
            || process.operations.active != 0
        {
            return Err(TaskError::BadState);
        }
        Ok(ProcessQuiescenceProof {
            authority_domain: self.operation_domain,
            process: key,
            generation: process.operations.generation,
        })
    }

    pub(crate) fn validate_process_quiescence(
        &self,
        proof: &ProcessQuiescenceProof,
        key: ProcessKey,
    ) -> Result<(), TaskError> {
        let process = self.process(key)?;
        if proof.authority_domain != self.operation_domain
            || proof.process != key
            || proof.generation != process.operations.generation
            || process.operations.phase == ProcessLifecycleState::AcceptingOperations
            || process.operations.active != 0
        {
            return Err(TaskError::Reference);
        }
        Ok(())
    }

    fn finish_process_exit(
        &mut self,
        proof: &ProcessQuiescenceProof,
        termination: TerminationRecord,
    ) -> Result<(), TaskError> {
        self.validate_process_quiescence(proof, proof.process)?;
        let process = self.process_mut(proof.process)?;
        if process.operations.phase != ProcessLifecycleState::Quiescing {
            return Err(TaskError::BadState);
        }
        if process.operations.pending_termination != Some(termination) {
            return Err(TaskError::BadState);
        }
        process.state.terminate(termination)?;
        process.operations.phase = ProcessLifecycleState::Exited;
        Ok(())
    }

    fn begin_process_termination(
        &mut self,
        key: ProcessKey,
        termination: TerminationRecord,
    ) -> Result<ProcessQuiescenceProof, ProcessGateError> {
        {
            let process = self.process_mut(key).map_err(ProcessGateError::Task)?;
            match process.operations.pending_termination {
                None => process.operations.pending_termination = Some(termination),
                Some(selected) if selected == termination => {}
                Some(_) => return Err(ProcessGateError::Task(TaskError::BadState)),
            }
        }
        self.begin_process_quiesce(key)
    }

    pub(crate) fn thread_info(&self, key: ThreadKey) -> Result<DwTaskTerminationInfoV1, TaskError> {
        Ok(self.thread(key)?.state.abi())
    }

    pub(crate) fn group_state(&self, key: TaskGroupKey) -> Result<TaskGroupState, TaskError> {
        let slot = self.group_slot(key)?;
        Ok(self.groups[slot]
            .as_ref()
            .expect("validated group slot")
            .state)
    }

    fn group_subtree_slots(&self, key: TaskGroupKey) -> Result<[bool; GROUPS], TaskError> {
        let root_slot = self.group_slot(key)?;
        let mut selected = [false; GROUPS];
        selected[root_slot] = true;
        for _ in 0..GROUPS {
            let mut changed = false;
            for slot in 0..GROUPS {
                if selected[slot] {
                    continue;
                }
                let Some(record) = self.groups[slot].as_ref() else {
                    continue;
                };
                let Some(parent) = record.parent.as_ref() else {
                    continue;
                };
                let parent_slot = self.group_slot(TaskGroupKey(parent.id()))?;
                if selected[parent_slot] {
                    selected[slot] = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Ok(selected)
    }

    #[cfg(test)]
    pub(crate) fn configure_thread_start(
        &mut self,
        key: ThreadKey,
        start: ThreadStartState,
    ) -> Result<(), TaskError> {
        let thread = self.thread_mut(key)?;
        if thread.state.state != DW_TASK_STATE_CREATED || thread.start.is_some() {
            return Err(TaskError::BadState);
        }
        thread.start = Some(start);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn attach_thread_execution_resources(
        &mut self,
        key: ThreadKey,
        resources: ThreadExecutionResources,
    ) -> Result<(), TaskError> {
        let thread = self.thread_mut(key)?;
        if thread.state.state != DW_TASK_STATE_CREATED
            || thread.kernel_stack.is_some()
            || thread.context.is_some()
        {
            return Err(TaskError::BadState);
        }
        thread.kernel_stack = Some(resources.kernel_stack);
        thread.context = Some(resources.context);
        Ok(())
    }

    pub(crate) fn thread_start_state(
        &self,
        key: ThreadKey,
    ) -> Result<Option<ThreadStartState>, TaskError> {
        Ok(self.thread(key)?.start)
    }

    pub(crate) fn thread_execution_resources(
        &self,
        key: ThreadKey,
    ) -> Result<Option<(KernelStackId, ThreadContextId)>, TaskError> {
        let thread = self.thread(key)?;
        match (thread.kernel_stack, thread.context) {
            (Some(kernel_stack), Some(context)) => Ok(Some((kernel_stack, context))),
            (None, None) => Ok(None),
            _ => panic!("Thread payload contains a partial execution-resource identity"),
        }
    }
    pub(crate) fn prepare_thread_execution(
        &mut self,
        key: ThreadKey,
        start: ThreadStartState,
        resources: ThreadExecutionResources,
    ) -> Result<(), TaskError> {
        let thread_slot = self.thread_slot(key)?;
        let process_key = ProcessKey(
            self.threads[thread_slot]
                .as_ref()
                .expect("validated thread slot")
                .parent
                .id(),
        );
        if self.process(process_key)?.operations.phase != ProcessLifecycleState::AcceptingOperations
        {
            return Err(TaskError::BadState);
        }
        let thread = self.threads[thread_slot]
            .as_mut()
            .expect("validated thread slot");
        if thread.state.state != DW_TASK_STATE_CREATED
            || thread.start.is_some()
            || thread.kernel_stack.is_some()
            || thread.context.is_some()
        {
            return Err(TaskError::BadState);
        }
        thread.start = Some(start);
        thread.kernel_stack = Some(resources.kernel_stack());
        thread.context = Some(resources.context());
        Ok(())
    }

    pub(crate) fn rollback_thread_execution(
        &mut self,
        key: ThreadKey,
    ) -> Result<ThreadExecutionResources, TaskError> {
        let thread = self.thread_mut(key)?;
        if thread.state.state != DW_TASK_STATE_CREATED || thread.start.is_none() {
            return Err(TaskError::BadState);
        }
        let (Some(kernel_stack), Some(context)) =
            (thread.kernel_stack.take(), thread.context.take())
        else {
            panic!("prepared Thread lost one execution-resource identity")
        };
        thread.start = None;
        Ok(ThreadExecutionResources {
            kernel_stack,
            context,
        })
    }

    pub(crate) fn start_thread(&mut self, key: ThreadKey) -> Result<(), TaskError> {
        let thread_slot = self.thread_slot(key)?;
        let process_key = ProcessKey(
            self.threads[thread_slot]
                .as_ref()
                .expect("validated thread slot")
                .parent
                .id(),
        );
        let process_slot = self.process_slot(process_key)?;
        if self.processes[process_slot]
            .as_ref()
            .expect("validated process slot")
            .operations
            .phase
            != ProcessLifecycleState::AcceptingOperations
        {
            return Err(TaskError::BadState);
        }
        let thread = self.threads[thread_slot]
            .as_mut()
            .expect("validated thread slot");
        if thread.start.is_none() || thread.kernel_stack.is_none() || thread.context.is_none() {
            return Err(TaskError::BadState);
        }
        thread.state.mark_running()?;
        let process = self.processes[process_slot]
            .as_mut()
            .expect("validated process slot");
        if process.state.state == DW_TASK_STATE_CREATED {
            process.state.mark_running()?;
        }
        Ok(())
    }

    pub(crate) fn exit_thread(
        &mut self,
        key: ThreadKey,
        code: u32,
    ) -> Result<ExitPins<THREADS>, TaskError> {
        let thread_slot = self.thread_slot(key)?;
        if self.threads[thread_slot]
            .as_ref()
            .expect("validated thread slot")
            .state
            .state
            != DW_TASK_STATE_RUNNING
        {
            return Err(TaskError::BadState);
        }
        let process_key = ProcessKey(
            self.threads[thread_slot]
                .as_ref()
                .expect("validated thread slot")
                .parent
                .id(),
        );
        let exits_process = !self.process_has_other_live_threads(process_key, key)?;
        if !exits_process
            && self.process(process_key)?.operations.phase
                != ProcessLifecycleState::AcceptingOperations
        {
            return Err(TaskError::BadState);
        }
        let quiescence = if exits_process {
            Some(
                self.begin_process_termination(process_key, TerminationRecord::normal(code))
                    .map_err(|error| match error {
                        ProcessGateError::Task(error) => error,
                        ProcessGateError::OperationsInFlight => TaskError::BadState,
                    })?,
            )
        } else {
            None
        };
        let thread = self.threads[thread_slot]
            .as_mut()
            .expect("validated thread slot");
        thread.state.terminate(TerminationRecord::normal(code))?;
        let mut pins = ExitPins::empty();
        let resources = take_thread_execution_resources(thread);
        if let Some(pin) = thread.execution_pin.take() {
            pins.push_thread(pin, resources);
        } else {
            assert!(
                resources.is_none(),
                "Thread lost its execution pin before resource retirement"
            );
        }

        if let Some(proof) = quiescence {
            self.finish_process_exit(&proof, TerminationRecord::normal(code))?;
            pins.process = self.process_mut(process_key)?.execution_pin.take();
        }
        Ok(pins)
    }

    pub(crate) fn terminate_thread_authorized(
        &mut self,
        key: ThreadKey,
        detail: u32,
    ) -> Result<ExitPins<THREADS>, TaskError> {
        let thread_slot = self.thread_slot(key)?;
        let process_key = ProcessKey(
            self.threads[thread_slot]
                .as_ref()
                .expect("validated thread slot")
                .parent
                .id(),
        );
        let exits_process = !self.process_has_other_live_threads(process_key, key)?;
        if !exits_process
            && self.process(process_key)?.operations.phase
                != ProcessLifecycleState::AcceptingOperations
        {
            return Err(TaskError::BadState);
        }
        let quiescence = if exits_process {
            Some(
                self.begin_process_termination(process_key, TerminationRecord::authorized(detail))
                    .map_err(|error| match error {
                        ProcessGateError::Task(error) => error,
                        ProcessGateError::OperationsInFlight => TaskError::BadState,
                    })?,
            )
        } else {
            None
        };
        let thread = self.threads[thread_slot]
            .as_mut()
            .expect("validated thread slot");
        thread
            .state
            .terminate(TerminationRecord::authorized(detail))?;
        let mut pins = ExitPins::empty();
        let resources = take_thread_execution_resources(thread);
        if let Some(pin) = thread.execution_pin.take() {
            pins.push_thread(pin, resources);
        } else {
            assert!(
                resources.is_none(),
                "Thread lost its execution pin before resource retirement"
            );
        }
        if let Some(proof) = quiescence {
            self.finish_process_exit(&proof, TerminationRecord::authorized(detail))?;
            pins.process = self.process_mut(process_key)?.execution_pin.take();
        }
        Ok(pins)
    }

    pub(crate) fn exit_process<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        key: ProcessKey,
        calling_thread: ThreadKey,
        code: u32,
    ) -> Result<ProcessExitEffects<HANDLES, THREADS>, TaskError> {
        let normal = TerminationRecord::normal(code);
        let pins = self.terminate_process_common(
            key,
            normal,
            Some((calling_thread, normal)),
            TerminationRecord::authorized(0),
        )?;
        let drained = self.drain_process_handles(registry, key)?;
        Ok(ProcessExitEffects { drained, pins })
    }

    pub(crate) fn terminate_process_authorized<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        key: ProcessKey,
        detail: u32,
    ) -> Result<ProcessExitEffects<HANDLES, THREADS>, TaskError> {
        let pins = self.terminate_process_common(
            key,
            TerminationRecord::authorized(detail),
            None,
            TerminationRecord::authorized(0),
        )?;
        let drained = self.drain_process_handles(registry, key)?;
        Ok(ProcessExitEffects { drained, pins })
    }

    pub(crate) fn terminate_process_exception<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        key: ProcessKey,
        faulting_thread: ThreadKey,
        exception_type: DwExceptionType,
        detail: u32,
        fault_address: u64,
    ) -> Result<ProcessExitEffects<HANDLES, THREADS>, TaskError> {
        let fault = TerminationRecord {
            reason: deepwyrm_abi::DW_TERMINATION_UNHANDLED_EXCEPTION,
            application_code: 0,
            exception_type,
            detail,
            fault_address,
        };
        let pins = self.terminate_process_common(
            key,
            fault,
            Some((faulting_thread, fault)),
            TerminationRecord::authorized(0),
        )?;
        let drained = self.drain_process_handles(registry, key)?;
        Ok(ProcessExitEffects { drained, pins })
    }

    fn terminate_process_common(
        &mut self,
        key: ProcessKey,
        process_termination: TerminationRecord,
        primary: Option<(ThreadKey, TerminationRecord)>,
        sibling_termination: TerminationRecord,
    ) -> Result<ExitPins<THREADS>, TaskError> {
        let quiescence = self
            .begin_process_termination(key, process_termination)
            .map_err(|error| match error {
                ProcessGateError::Task(error) => error,
                ProcessGateError::OperationsInFlight => TaskError::OperationsInFlight,
            })?;
        let process_slot = self.process_slot(key)?;
        let thread_ids = self.processes[process_slot]
            .as_ref()
            .expect("validated process slot")
            .threads;
        let mut pins = ExitPins::empty();
        for object in thread_ids.into_iter().flatten() {
            let thread_key = ThreadKey(object);
            let thread_slot = self.thread_slot(thread_key)?;
            let thread = self.threads[thread_slot]
                .as_mut()
                .expect("validated thread slot");
            if thread.state.state == DW_TASK_STATE_EXITED {
                continue;
            }
            let termination = match primary {
                Some((primary_key, termination)) if primary_key == thread_key => termination,
                _ => sibling_termination,
            };
            thread.state.terminate(termination)?;
            let resources = take_thread_execution_resources(thread);
            if let Some(pin) = thread.execution_pin.take() {
                pins.push_thread(pin, resources);
            } else {
                assert!(
                    resources.is_none(),
                    "Thread lost its execution pin before resource retirement"
                );
            }
        }
        self.finish_process_exit(&quiescence, process_termination)?;
        pins.process = self.process_mut(key)?.execution_pin.take();
        Ok(pins)
    }

    pub(crate) fn take_finalization(
        &mut self,
        final_release: FinalRelease,
    ) -> Result<TaskFinalization, TaskFinalizationError> {
        let result = match final_release.object_type() {
            DW_OBJECT_TYPE_TASK_GROUP => self.take_group_finalization(&final_release),
            DW_OBJECT_TYPE_PROCESS => self.take_process_finalization(&final_release),
            DW_OBJECT_TYPE_THREAD => self.take_thread_finalization(&final_release),
            _ => Err(TaskError::WrongObjectType),
        };
        match result {
            Ok(parent) => Ok(TaskFinalization {
                final_release,
                parent,
            }),
            Err(error) => Err(TaskFinalizationError {
                error,
                final_release,
            }),
        }
    }

    fn take_group_finalization(
        &mut self,
        release: &FinalRelease,
    ) -> Result<Option<InternalRef>, TaskError> {
        let slot = self.group_slot(TaskGroupKey(release.id()))?;
        let record = self.groups[slot].take().expect("validated group slot");
        assert!(
            record.child_groups.iter().all(Option::is_none),
            "finalizing TaskGroup still names child groups"
        );
        assert!(
            record.processes.iter().all(Option::is_none),
            "finalizing TaskGroup still names processes"
        );
        assert!(
            record.reserved_processes.iter().all(Option::is_none),
            "finalizing TaskGroup still reserves unpublished processes"
        );
        if let Some(parent) = record.parent.as_ref() {
            let parent_slot = self.group_slot(TaskGroupKey(parent.id()))?;
            let parent_record = self.groups[parent_slot]
                .as_mut()
                .expect("live parent group");
            remove_child(&mut parent_record.child_groups, record.object)?;
        }
        Ok(record.parent)
    }

    fn take_process_finalization(
        &mut self,
        release: &FinalRelease,
    ) -> Result<Option<InternalRef>, TaskError> {
        let slot = self.process_slot(ProcessKey(release.id()))?;
        let record = self.processes[slot].take().expect("validated process slot");
        assert!(
            record.threads.iter().all(Option::is_none),
            "finalizing Process still names Thread payloads"
        );
        assert!(
            record.handles.is_empty(),
            "finalizing Process still owns live handles"
        );
        assert!(
            record.execution_pin.is_none(),
            "finalizing Process still owns execution authority"
        );
        assert!(
            record.root_region.is_none(),
            "finalizing Process still names a root AddressRegion"
        );
        assert!(
            !record.root_region_reserved,
            "finalizing Process still reserves a root AddressRegion"
        );
        assert!(
            record.operations.phase == ProcessLifecycleState::Exited
                || (matches!(record.hierarchy, ProcessHierarchyState::Reserved(_))
                    && record.operations.phase == ProcessLifecycleState::AcceptingOperations),
            "finalizing published Process whose lifecycle gate is not exited"
        );
        assert_eq!(
            record.operations.active, 0,
            "finalizing Process with active operation leases"
        );
        let parent_slot = self.group_slot(TaskGroupKey(record.parent.id()))?;
        let parent = self.groups[parent_slot]
            .as_mut()
            .expect("live parent group");
        match record.hierarchy {
            ProcessHierarchyState::Attached(slot) => {
                assert_eq!(
                    parent.processes[slot],
                    Some(record.object),
                    "published Process parent hierarchy identity drifted"
                );
                parent.processes[slot] = None;
            }
            ProcessHierarchyState::Reserved(slot) => {
                assert_eq!(
                    parent.reserved_processes[slot],
                    Some(record.object),
                    "prepared Process parent reservation identity drifted"
                );
                parent.reserved_processes[slot] = None;
            }
        }
        Ok(Some(record.parent))
    }

    fn take_thread_finalization(
        &mut self,
        release: &FinalRelease,
    ) -> Result<Option<InternalRef>, TaskError> {
        let slot = self.thread_slot(ThreadKey(release.id()))?;
        let record = self.threads[slot].take().expect("validated thread slot");
        assert!(
            record.execution_pin.is_none(),
            "finalizing Thread still owns execution authority"
        );
        assert!(
            record.kernel_stack.is_none() && record.context.is_none(),
            "finalizing Thread still owns execution resources"
        );
        let parent_slot = self.process_slot(ProcessKey(record.parent.id()))?;
        let parent = self.processes[parent_slot]
            .as_mut()
            .expect("live parent process");
        remove_child(&mut parent.threads, record.object)?;
        Ok(Some(record.parent))
    }

    fn group_slot(&self, key: TaskGroupKey) -> Result<usize, TaskError> {
        self.groups
            .iter()
            .position(|record| record.as_ref().is_some_and(|record| record.object == key.0))
            .ok_or(TaskError::InvalidTask)
    }
    fn process_slot(&self, key: ProcessKey) -> Result<usize, TaskError> {
        self.processes
            .iter()
            .position(|record| record.as_ref().is_some_and(|record| record.object == key.0))
            .ok_or(TaskError::InvalidTask)
    }
    fn thread_slot(&self, key: ThreadKey) -> Result<usize, TaskError> {
        self.threads
            .iter()
            .position(|record| record.as_ref().is_some_and(|record| record.object == key.0))
            .ok_or(TaskError::InvalidTask)
    }
    fn process(&self, key: ProcessKey) -> Result<&ProcessRecord<THREADS, HANDLES>, TaskError> {
        let slot = self.process_slot(key)?;
        Ok(self.processes[slot]
            .as_ref()
            .expect("validated process slot"))
    }
    fn process_mut(
        &mut self,
        key: ProcessKey,
    ) -> Result<&mut ProcessRecord<THREADS, HANDLES>, TaskError> {
        let slot = self.process_slot(key)?;
        Ok(self.processes[slot]
            .as_mut()
            .expect("validated process slot"))
    }
    fn thread(&self, key: ThreadKey) -> Result<&ThreadRecord, TaskError> {
        let slot = self.thread_slot(key)?;
        Ok(self.threads[slot].as_ref().expect("validated thread slot"))
    }
    fn thread_mut(&mut self, key: ThreadKey) -> Result<&mut ThreadRecord, TaskError> {
        let slot = self.thread_slot(key)?;
        Ok(self.threads[slot].as_mut().expect("validated thread slot"))
    }

    fn process_has_live_threads(&self, key: ProcessKey) -> Result<bool, TaskError> {
        let ids = self.process(key)?.threads;
        for object in ids.into_iter().flatten() {
            let thread = self.thread(ThreadKey(object))?;
            if thread.state.state != DW_TASK_STATE_EXITED {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn process_has_other_live_threads(
        &self,
        process: ProcessKey,
        excluded: ThreadKey,
    ) -> Result<bool, TaskError> {
        let ids = self.process(process)?.threads;
        for object in ids.into_iter().flatten() {
            let key = ThreadKey(object);
            if key != excluded && self.thread(key)?.state.state != DW_TASK_STATE_EXITED {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn take_thread_execution_resources(thread: &mut ThreadRecord) -> Option<ThreadExecutionResources> {
    match (thread.kernel_stack.take(), thread.context.take()) {
        (Some(kernel_stack), Some(context)) => Some(ThreadExecutionResources {
            kernel_stack,
            context,
        }),
        (None, None) => None,
        _ => panic!("Thread kernel-stack/context ownership diverged"),
    }
}

fn remove_child<const CAPACITY: usize>(
    items: &mut [Option<ObjectId>; CAPACITY],
    object: ObjectId,
) -> Result<(), TaskError> {
    let Some(slot) = items.iter().position(|item| *item == Some(object)) else {
        return Err(TaskError::InvalidParent);
    };
    items[slot] = None;
    Ok(())
}

impl<const GROUPS: usize, const PROCESSES: usize, const THREADS: usize, const HANDLES: usize>
    TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>
{
    pub(crate) fn create_root_group<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> Result<(TaskGroupKey, InternalRef), TaskCreateError> {
        let creation = registry
            .create(DW_OBJECT_TYPE_TASK_GROUP)
            .map_err(TaskCreateError::Registry)?;
        let binding = match self.bind_root_group(creation) {
            Ok(binding) => binding,
            Err((error, creation)) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "root-group rollback lost creation authority: {:?}",
                            failure.error()
                        )
                    });
                return Err(TaskCreateError::Task(error));
            }
        };
        let key = binding
            .task_group_key()
            .expect("root binding carries TaskGroup key");
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh root-group binding rejected by registry: {:?}",
                    failure.error()
                )
            });
        let owner = registry
            .bound_into_internal(bound)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh root-group owner conversion failed: {:?}",
                    failure.error()
                )
            });
        Ok((key, owner))
    }

    pub(crate) fn create_child_group<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        parent_owner: &InternalRef,
    ) -> Result<(TaskGroupKey, HandleRef), TaskCreateError> {
        let parent_key = TaskGroupKey(parent_owner.id());
        if self
            .group_state(parent_key)
            .map_err(TaskCreateError::Task)?
            != TaskGroupState::Active
        {
            return Err(TaskCreateError::Task(TaskError::ParentTerminating));
        }
        let parent = registry
            .retain_internal(parent_owner)
            .map_err(TaskCreateError::Registry)?;
        let creation = match registry.create(DW_OBJECT_TYPE_TASK_GROUP) {
            Ok(creation) => creation,
            Err(error) => {
                release_nonfinal_parent(registry, parent);
                return Err(TaskCreateError::Registry(error));
            }
        };
        let binding = match self.bind_child_group(creation, parent) {
            Ok(binding) => binding,
            Err((error, creation, parent)) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "child-group rollback lost creation authority: {:?}",
                            failure.error()
                        )
                    });
                release_nonfinal_parent(registry, parent);
                return Err(TaskCreateError::Task(error));
            }
        };
        let key = binding
            .task_group_key()
            .expect("child binding carries TaskGroup key");
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!("fresh child-group binding rejected: {:?}", failure.error())
            });
        let handle = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
            panic!(
                "fresh child-group handle conversion failed: {:?}",
                failure.error()
            )
        });
        Ok((key, handle))
    }

    pub(crate) fn prepare_process<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        parent_owner: &InternalRef,
    ) -> Result<PreparedProcess, TaskCreateError> {
        let parent = registry
            .retain_internal(parent_owner)
            .map_err(TaskCreateError::Registry)?;
        let creation = match registry.create(DW_OBJECT_TYPE_PROCESS) {
            Ok(creation) => creation,
            Err(error) => {
                release_nonfinal_parent(registry, parent);
                return Err(TaskCreateError::Registry(error));
            }
        };
        let binding = match self.bind_prepared_process(creation, parent) {
            Ok(binding) => binding,
            Err((error, creation, parent)) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "process rollback lost creation authority: {:?}",
                            failure.error()
                        )
                    });
                release_nonfinal_parent(registry, parent);
                return Err(TaskCreateError::Task(error));
            }
        };
        let key = binding
            .process_key()
            .expect("process binding carries Process key");
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!("fresh process binding rejected: {:?}", failure.error())
            });
        let handle = registry
            .retain_handle_from_bound(&bound)
            .unwrap_or_else(|error| panic!("fresh process handle retain failed: {error:?}"));
        let execution = registry
            .bound_into_internal(bound)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh process execution pin conversion failed: {:?}",
                    failure.error()
                )
            });
        self.attach_process_execution_pin(key, execution)
            .expect("fresh process accepts its execution pin");
        Ok(PreparedProcess {
            key,
            handle: Some(handle),
            completed: false,
        })
    }

    /// Retains the E factory's immediate-publication behavior for existing
    /// callers. F10 uses `prepare_process` directly to delay hierarchy
    /// publication until its all-or-nothing commit boundary.
    pub(crate) fn create_process<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        parent_owner: &InternalRef,
    ) -> Result<(ProcessKey, HandleRef), TaskCreateError> {
        self.prepare_process(registry, parent_owner)
            .map(|prepared| prepared.commit(self))
    }

    pub(crate) fn prepare_thread<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        parent_owner: &InternalRef,
    ) -> Result<PreparedThread, TaskCreateError> {
        let parent = registry
            .retain_internal(parent_owner)
            .map_err(TaskCreateError::Registry)?;
        let creation = match registry.create(DW_OBJECT_TYPE_THREAD) {
            Ok(creation) => creation,
            Err(error) => {
                release_nonfinal_parent(registry, parent);
                return Err(TaskCreateError::Registry(error));
            }
        };
        let binding = match self.bind_thread(creation, parent) {
            Ok(binding) => binding,
            Err((error, creation, parent)) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "thread rollback lost creation authority: {:?}",
                            failure.error()
                        )
                    });
                release_nonfinal_parent(registry, parent);
                return Err(TaskCreateError::Task(error));
            }
        };
        let key = binding
            .thread_key()
            .expect("thread binding carries Thread key");
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!("fresh thread binding rejected: {:?}", failure.error())
            });
        let handle = registry
            .retain_handle_from_bound(&bound)
            .unwrap_or_else(|error| panic!("fresh thread handle retain failed: {error:?}"));
        let execution = registry
            .bound_into_internal(bound)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh thread execution pin conversion failed: {:?}",
                    failure.error()
                )
            });
        self.attach_thread_execution_pin(key, execution)
            .expect("fresh thread accepts its execution pin");
        Ok(PreparedThread {
            key,
            handle: Some(handle),
            completed: false,
        })
    }

    /// Compatibility wrapper for ordinary E/F callers whose Process is
    /// already published. Primordial construction retains the prepared token
    /// until its wider transaction crosses the no-fail boundary.
    pub(crate) fn create_thread<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        parent_owner: &InternalRef,
    ) -> Result<(ThreadKey, HandleRef), TaskCreateError> {
        self.prepare_thread(registry, parent_owner)
            .map(PreparedThread::commit)
    }
}

impl PreparedThread {
    pub(crate) fn commit(mut self) -> (ThreadKey, HandleRef) {
        self.completed = true;
        (
            self.key,
            self.handle
                .take()
                .expect("prepared Thread commit retains its unpublished handle"),
        )
    }

    /// Cancels a CREATED Thread before its parent Process is published.
    pub(crate) fn cancel<
        const OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        mut self,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> Option<FinalRelease> {
        let thread = tasks
            .thread_mut(self.key)
            .expect("prepared Thread record remains live until cancellation");
        assert_eq!(
            thread.state.state, DW_TASK_STATE_CREATED,
            "running Thread cannot use prepared cancellation"
        );
        assert!(
            thread.start.is_none() && thread.kernel_stack.is_none() && thread.context.is_none(),
            "prepared Thread execution must be cancelled before payload cancellation"
        );
        let execution = thread
            .execution_pin
            .take()
            .expect("prepared Thread retains its execution pin");
        assert!(
            registry
                .release_internal(execution)
                .unwrap_or_else(|failure| {
                    panic!(
                        "prepared Thread execution-pin cancellation lost authority: {:?}",
                        failure.error()
                    )
                })
                .is_none(),
            "prepared Thread execution pin was unexpectedly final"
        );
        let final_release = registry
            .release_handle(
                self.handle
                    .take()
                    .expect("prepared Thread cancellation retains its handle"),
            )
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared Thread handle cancellation lost authority: {:?}",
                    failure.error()
                )
            })
            .expect("prepared Thread handle release must reach typed finalization");
        let finalization = tasks
            .take_finalization(final_release)
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared Thread typed cancellation diverged: {:?}",
                    failure.error()
                )
            });
        self.completed = true;
        complete_task_finalization(registry, finalization)
    }
}

impl PreparedProcess {
    /// Reserves the Process root-region attachment before HandleTable
    /// reservations are taken, without making a root region discoverable.
    pub(crate) fn reserve_root_region_attachment<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    ) -> Result<PreparedRootRegionAttachment, TaskError> {
        tasks.reserve_root_region_attachment(self.key)
    }

    /// Publishes the Process into its already-reserved parent hierarchy slot.
    ///
    /// This is intentionally infallible: all capacity and state checks belong
    /// to preparation, before F10 crosses its no-recoverable-failure boundary.
    pub(crate) fn commit<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        mut self,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    ) -> (ProcessKey, HandleRef) {
        tasks.commit_prepared_process(self.key);
        self.completed = true;
        (
            self.key,
            self.handle
                .take()
                .expect("prepared Process commit retains its unpublished handle"),
        )
    }

    /// Cancels an unpublished Process after every prepared child payload has
    /// been cancelled. Typed task cleanup happens before generic finalization,
    /// and the returned parent release remains for the caller's finalizer path.
    pub(crate) fn cancel<
        const OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        mut self,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> Option<FinalRelease> {
        let execution = tasks.take_prepared_process_execution(self.key);
        assert!(
            registry
                .release_internal(execution)
                .unwrap_or_else(|failure| {
                    panic!(
                        "prepared Process execution-pin cancellation lost authority: {:?}",
                        failure.error()
                    )
                })
                .is_none(),
            "prepared Process execution pin was unexpectedly final"
        );
        let final_release = registry
            .release_handle(
                self.handle
                    .take()
                    .expect("prepared Process cancellation retains its handle"),
            )
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared Process handle cancellation lost authority: {:?}",
                    failure.error()
                )
            })
            .expect("prepared Process handle release must reach typed finalization");
        let finalization = tasks
            .take_finalization(final_release)
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared Process typed cancellation diverged: {:?}",
                    failure.error()
                )
            });
        self.completed = true;
        complete_task_finalization(registry, finalization)
    }
}

impl PreparedRootRegionAttachment {
    pub(crate) fn process(&self) -> ProcessKey {
        self.process
    }

    pub(crate) fn commit<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        mut self,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        object: ObjectId,
    ) {
        tasks.commit_prepared_root_region_attachment(self.process, object);
        self.completed = true;
    }

    pub(crate) fn cancel<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        mut self,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    ) {
        tasks.cancel_prepared_root_region_attachment(self.process);
        self.completed = true;
    }
}

fn release_nonfinal_parent<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    parent: InternalRef,
) {
    match registry.release_internal(parent) {
        Ok(None) => {}
        Ok(Some(_)) => panic!("factory rollback unexpectedly finalized a still-borrowed parent"),
        Err(failure) => panic!(
            "factory rollback lost parent reference authority: {:?}",
            failure.error()
        ),
    }
}

impl<const GROUPS: usize, const PROCESSES: usize, const THREADS: usize, const HANDLES: usize>
    TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>
{
    pub(crate) fn terminate_group<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        key: TaskGroupKey,
    ) -> Result<TaskGroupTerminationEffects<PROCESSES, HANDLES, THREADS>, TaskError> {
        let root_slot = self.group_slot(key)?;
        if !matches!(
            self.groups[root_slot]
                .as_ref()
                .expect("validated group slot")
                .state,
            TaskGroupState::Active | TaskGroupState::Terminating
        ) {
            return Err(TaskError::BadState);
        }

        let selected = self.group_subtree_slots(key)?;

        for (slot, is_selected) in selected.iter().copied().enumerate() {
            if is_selected {
                self.groups[slot]
                    .as_mut()
                    .expect("selected group remains live")
                    .state = TaskGroupState::Terminating;
            }
        }

        let mut process_keys = [None; PROCESSES];
        let mut process_count = 0;
        for record in self.processes.iter().flatten() {
            if !matches!(record.hierarchy, ProcessHierarchyState::Attached(_)) {
                continue;
            }
            let parent_slot = self.group_slot(TaskGroupKey(record.parent.id()))?;
            if selected[parent_slot] {
                assert!(process_count < PROCESSES, "selected process list overflow");
                process_keys[process_count] = Some(ProcessKey(record.object));
                process_count += 1;
            }
        }

        let mut effects = TaskGroupTerminationEffects::empty();
        for process_key in process_keys.into_iter().flatten() {
            if self.process(process_key)?.state.state != DW_TASK_STATE_EXITED {
                self.begin_process_termination(
                    process_key,
                    TerminationRecord::task_group_teardown(),
                )
                .map_err(|error| match error {
                    ProcessGateError::Task(error) => error,
                    ProcessGateError::OperationsInFlight => TaskError::BadState,
                })?;
            }
        }
        for process_key in process_keys.into_iter().flatten() {
            if self.process(process_key)?.state.state == DW_TASK_STATE_EXITED {
                continue;
            }
            let pins = self.terminate_process_common(
                process_key,
                TerminationRecord::task_group_teardown(),
                None,
                TerminationRecord::task_group_teardown(),
            )?;
            let drained = self.drain_process_handles(registry, process_key)?;
            effects.push(process_key, ProcessExitEffects { drained, pins });
        }

        for (slot, is_selected) in selected.iter().copied().enumerate().rev() {
            if is_selected {
                self.groups[slot]
                    .as_mut()
                    .expect("selected group remains live")
                    .state = TaskGroupState::Terminated;
            }
        }
        Ok(effects)
    }
}
