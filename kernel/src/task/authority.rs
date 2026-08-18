use super::*;

impl<const GROUPS: usize, const PROCESSES: usize, const THREADS: usize, const HANDLES: usize>
    TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>
{
    pub(crate) fn new() -> Self {
        Self {
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
        });
        Ok(TaskPayloadBinding::TaskGroup { creation, key })
    }

    pub(crate) fn bind_process(
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
            .position(Option::is_none)
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
            .processes[child_index] = Some(creation.id());
        self.processes[slot] = Some(ProcessRecord {
            object: creation.id(),
            parent,
            state: TaskStateRecord::created(),
            execution_pin: None,
            root_region: None,
            threads: [None; THREADS],
            handles: HandleTable::new(),
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
        if process.state.state == DW_TASK_STATE_EXITED {
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

    pub(crate) fn process_handles_mut(
        &mut self,
        key: ProcessKey,
    ) -> Result<&mut HandleTable<HANDLES>, TaskError> {
        let process = self.process_mut(key)?;
        if process.state.state == DW_TASK_STATE_EXITED {
            return Err(TaskError::BadState);
        }
        Ok(&mut process.handles)
    }

    pub(crate) fn process_handle_count(&self, key: ProcessKey) -> Result<usize, TaskError> {
        Ok(self.process(key)?.handles.len())
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
        if process.state.state != DW_TASK_STATE_CREATED || process.root_region.is_some() {
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
        if process.state.state != DW_TASK_STATE_CREATED || process.root_region != Some(object) {
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
        if self.process(process_key)?.state.state == DW_TASK_STATE_EXITED {
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
            .state
            .state
            == DW_TASK_STATE_EXITED
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

        if !self.process_has_live_threads(process_key)? {
            let process = self.process_mut(process_key)?;
            process.state.terminate(TerminationRecord::normal(code))?;
            pins.process = process.execution_pin.take();
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
        if !self.process_has_live_threads(process_key)? {
            let process = self.process_mut(process_key)?;
            process
                .state
                .terminate(TerminationRecord::authorized(detail))?;
            pins.process = process.execution_pin.take();
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
        let process_slot = self.process_slot(key)?;
        if self.processes[process_slot]
            .as_ref()
            .expect("validated process slot")
            .state
            .state
            == DW_TASK_STATE_EXITED
        {
            return Err(TaskError::BadState);
        }
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
        let process = self.processes[process_slot]
            .as_mut()
            .expect("validated process slot");
        process.state.terminate(process_termination)?;
        pins.process = process.execution_pin.take();
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
        let parent_slot = self.group_slot(TaskGroupKey(record.parent.id()))?;
        let parent = self.groups[parent_slot]
            .as_mut()
            .expect("live parent group");
        remove_child(&mut parent.processes, record.object)?;
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

    pub(crate) fn create_process<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        parent_owner: &InternalRef,
    ) -> Result<(ProcessKey, HandleRef), TaskCreateError> {
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
        let binding = match self.bind_process(creation, parent) {
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
        Ok((key, handle))
    }

    pub(crate) fn create_thread<const OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        parent_owner: &InternalRef,
    ) -> Result<(ThreadKey, HandleRef), TaskCreateError> {
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
        Ok((key, handle))
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
        if self.groups[root_slot]
            .as_ref()
            .expect("validated group slot")
            .state
            != TaskGroupState::Active
        {
            return Err(TaskError::BadState);
        }

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
            let parent_slot = self.group_slot(TaskGroupKey(record.parent.id()))?;
            if selected[parent_slot] {
                assert!(process_count < PROCESSES, "selected process list overflow");
                process_keys[process_count] = Some(ProcessKey(record.object));
                process_count += 1;
            }
        }

        let mut effects = TaskGroupTerminationEffects::empty();
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
            effects.push(ProcessExitEffects { drained, pins });
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
