extern crate std;

use super::*;
use deepwyrm_abi::{
    DW_EXCEPTION_PAGE_FAULT, DW_OBJECT_TYPE_EVENT, DW_RIGHT_INSPECT, DW_TASK_STATE_CREATED,
    DW_TASK_STATE_EXITED, DW_TASK_STATE_RUNNING, DW_TERMINATION_AUTHORIZED,
    DW_TERMINATION_NORMAL_EXIT, DW_TERMINATION_TASK_GROUP_TEARDOWN,
    DW_TERMINATION_UNHANDLED_EXCEPTION,
};

const OBJECTS: usize = 16;
type Tasks = TaskAuthority<4, 4, 8, 4>;

fn release_pins(
    registry: &mut ObjectRegistry<OBJECTS>,
    pins: ExitPins<8>,
) -> [Option<FinalRelease>; 9] {
    let (process, threads, _resources) = pins.into_parts();
    let mut out = core::array::from_fn(|_| None);
    let mut next = 0;
    for pin in threads.into_iter().flatten().chain(process) {
        if let Some(release) = registry.release_internal(pin).unwrap() {
            out[next] = Some(release);
            next += 1;
        }
    }
    out
}

fn finish_task_release(
    tasks: &mut Tasks,
    registry: &mut ObjectRegistry<OBJECTS>,
    release: FinalRelease,
) {
    let mut pending = Some(release);
    while let Some(release) = pending.take() {
        let finalization = tasks.take_finalization(release).unwrap();
        pending = complete_task_finalization(registry, finalization);
    }
}

fn process_parent_pin(registry: &mut ObjectRegistry<OBJECTS>, process: &HandleRef) -> InternalRef {
    registry.retain_internal_from_handle(process).unwrap()
}

fn release_nonfinal_pin(registry: &mut ObjectRegistry<OBJECTS>, pin: InternalRef) {
    assert!(registry.release_internal(pin).unwrap().is_none());
}

fn prepare_thread(tasks: &mut Tasks, thread: ThreadKey, seed: u64) {
    let start = ThreadStartState::from_validated_user_state(
        0x0000_0000_4000_0000 + seed * 0x1000,
        0x0000_0000_5000_0000 + seed * 0x1000,
        seed,
        seed ^ 0x55aa,
    );
    tasks.configure_thread_start(thread, start).unwrap();
    tasks
        .attach_thread_execution_resources(
            thread,
            ThreadExecutionResources {
                kernel_stack: KernelStackId::new(seed + 1).unwrap(),
                context: ThreadContextId::new(seed + 0x100).unwrap(),
            },
        )
        .unwrap();
    assert_eq!(tasks.thread_start_state(thread), Ok(Some(start)));
}

#[test]
fn child_to_parent_lifetime_chain_finalizes_without_cycles() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let temporary_process_pin = process_parent_pin(&mut registry, &process_handle);
    let (thread, thread_handle) = tasks
        .create_thread(&mut registry, &temporary_process_pin)
        .unwrap();
    release_nonfinal_pin(&mut registry, temporary_process_pin);

    assert_eq!(tasks.group_state(root), Ok(TaskGroupState::Active));
    assert_eq!(
        tasks.process_info(process).unwrap().state,
        DW_TASK_STATE_CREATED
    );
    assert_eq!(
        tasks.thread_info(thread).unwrap().state,
        DW_TASK_STATE_CREATED
    );
    assert_eq!(tasks.start_thread(thread), Err(TaskError::BadState));
    prepare_thread(&mut tasks, thread, 1);
    tasks.start_thread(thread).unwrap();
    assert_eq!(
        tasks.process_info(process).unwrap().state,
        DW_TASK_STATE_RUNNING
    );
    assert_eq!(
        tasks.thread_info(thread).unwrap().state,
        DW_TASK_STATE_RUNNING
    );
    assert_eq!(tasks.start_thread(thread), Err(TaskError::BadState));

    let pins = tasks.exit_thread(thread, 0x1234_5678).unwrap();
    assert!(
        release_pins(&mut registry, pins)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );
    let thread_info = tasks.thread_info(thread).unwrap();
    assert_eq!(thread_info.state, DW_TASK_STATE_EXITED);
    assert_eq!(thread_info.reason, DW_TERMINATION_NORMAL_EXIT);
    assert_eq!(thread_info.application_code, 0x1234_5678);
    let process_info = tasks.process_info(process).unwrap();
    assert_eq!(process_info.state, DW_TASK_STATE_EXITED);
    assert_eq!(process_info.reason, DW_TERMINATION_NORMAL_EXIT);
    assert_eq!(process_info.application_code, 0x1234_5678);

    let thread_final = registry.release_handle(thread_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, thread_final);
    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, process_final);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);

    let (replacement_root, replacement_owner) = tasks.create_root_group(&mut registry).unwrap();
    assert_ne!(replacement_root, root);
    let replacement_final = registry
        .release_internal(replacement_owner)
        .unwrap()
        .unwrap();
    finish_task_release(&mut tasks, &mut registry, replacement_final);
}

#[test]
fn process_exit_drains_handles_and_records_per_thread_reason() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let temporary_process_pin = process_parent_pin(&mut registry, &process_handle);
    let (thread0, thread0_handle) = tasks
        .create_thread(&mut registry, &temporary_process_pin)
        .unwrap();
    let (thread1, thread1_handle) = tasks
        .create_thread(&mut registry, &temporary_process_pin)
        .unwrap();
    release_nonfinal_pin(&mut registry, temporary_process_pin);
    prepare_thread(&mut tasks, thread0, 2);
    prepare_thread(&mut tasks, thread1, 3);
    tasks.start_thread(thread0).unwrap();
    tasks.start_thread(thread1).unwrap();

    let event_creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
    let event_ref = registry.creation_into_handle(event_creation).unwrap();
    let event_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(event_ref, DW_RIGHT_INSPECT)
        .unwrap();
    assert_ne!(event_handle.0, 0);

    let effects = tasks
        .exit_process(&mut registry, process, thread0, 0x55aa)
        .unwrap();
    assert_eq!(effects.drained.final_release_count(), 1);
    let event_final = effects
        .drained
        .into_final_releases()
        .into_iter()
        .flatten()
        .next()
        .unwrap();
    registry.complete_finalization(event_final).unwrap();
    assert_eq!(tasks.process_handle_count(process), Ok(0));
    assert!(matches!(
        tasks.process_handles_mut(process),
        Err(TaskError::BadState)
    ));
    assert!(
        release_pins(&mut registry, effects.pins)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );

    let process_info = tasks.process_info(process).unwrap();
    assert_eq!(process_info.state, DW_TASK_STATE_EXITED);
    assert_eq!(process_info.reason, DW_TERMINATION_NORMAL_EXIT);
    assert_eq!(process_info.application_code, 0x55aa);
    let caller = tasks.thread_info(thread0).unwrap();
    assert_eq!(caller.reason, DW_TERMINATION_NORMAL_EXIT);
    assert_eq!(caller.application_code, 0x55aa);
    let sibling = tasks.thread_info(thread1).unwrap();
    assert_eq!(sibling.reason, DW_TERMINATION_AUTHORIZED);
    assert_eq!(sibling.application_code, 0);
    assert_eq!(sibling.detail, 0);
    assert!(matches!(
        tasks.exit_process(&mut registry, process, thread0, 1),
        Err(TaskError::BadState)
    ));

    for handle in [thread0_handle, thread1_handle] {
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, final_release);
    }
    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, process_final);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

#[test]
fn userspace_exception_is_process_fatal_and_siblings_do_not_claim_fault() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let temporary_process_pin = process_parent_pin(&mut registry, &process_handle);
    let (faulting, faulting_handle) = tasks
        .create_thread(&mut registry, &temporary_process_pin)
        .unwrap();
    let (sibling, sibling_handle) = tasks
        .create_thread(&mut registry, &temporary_process_pin)
        .unwrap();
    release_nonfinal_pin(&mut registry, temporary_process_pin);
    prepare_thread(&mut tasks, faulting, 4);
    prepare_thread(&mut tasks, sibling, 5);
    tasks.start_thread(faulting).unwrap();
    tasks.start_thread(sibling).unwrap();

    let effects = tasks
        .terminate_process_exception(
            &mut registry,
            process,
            faulting,
            DW_EXCEPTION_PAGE_FAULT,
            0x17,
            0x0000_0000_4141_5000,
        )
        .unwrap();
    assert_eq!(effects.drained.final_release_count(), 0);
    assert!(
        release_pins(&mut registry, effects.pins)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );

    for info in [
        tasks.process_info(process).unwrap(),
        tasks.thread_info(faulting).unwrap(),
    ] {
        assert_eq!(info.reason, DW_TERMINATION_UNHANDLED_EXCEPTION);
        assert_eq!(info.exception_type, DW_EXCEPTION_PAGE_FAULT);
        assert_eq!(info.detail, 0x17);
        assert_eq!(info.fault_address, 0x0000_0000_4141_5000);
    }
    let sibling_info = tasks.thread_info(sibling).unwrap();
    assert_eq!(sibling_info.reason, DW_TERMINATION_AUTHORIZED);
    assert_eq!(sibling_info.exception_type.0, 0);
    assert_eq!(sibling_info.fault_address, 0);

    for handle in [faulting_handle, sibling_handle] {
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, final_release);
    }
    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, process_final);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

#[test]
fn task_group_teardown_is_iterative_and_marks_all_live_descendants() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (child, child_handle) = tasks
        .create_child_group(&mut registry, &root_owner)
        .unwrap();
    let child_owner = registry.retain_internal_from_handle(&child_handle).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &child_owner).unwrap();
    release_nonfinal_pin(&mut registry, child_owner);
    let process_owner = process_parent_pin(&mut registry, &process_handle);
    let (thread, thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    release_nonfinal_pin(&mut registry, process_owner);
    prepare_thread(&mut tasks, thread, 6);
    tasks.start_thread(thread).unwrap();

    let effects = tasks.terminate_group(&mut registry, root).unwrap();
    assert_eq!(effects.len(), 1);
    for process_effect in effects.into_processes().into_iter().flatten() {
        assert_eq!(process_effect.drained.final_release_count(), 0);
        assert!(
            release_pins(&mut registry, process_effect.pins)
                .into_iter()
                .flatten()
                .next()
                .is_none()
        );
    }
    assert_eq!(tasks.group_state(root), Ok(TaskGroupState::Terminated));
    assert_eq!(tasks.group_state(child), Ok(TaskGroupState::Terminated));
    assert_eq!(
        tasks.process_info(process).unwrap().reason,
        DW_TERMINATION_TASK_GROUP_TEARDOWN
    );
    assert_eq!(
        tasks.thread_info(thread).unwrap().reason,
        DW_TERMINATION_TASK_GROUP_TEARDOWN
    );
    assert!(matches!(
        tasks.terminate_group(&mut registry, root),
        Err(TaskError::BadState)
    ));
    assert!(matches!(
        tasks.create_child_group(&mut registry, &root_owner),
        Err(TaskCreateError::Task(TaskError::ParentTerminating))
    ));

    let thread_final = registry.release_handle(thread_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, thread_final);
    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, process_final);
    let child_final = registry.release_handle(child_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, child_final);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

#[test]
fn failed_child_creation_rolls_back_generic_slot_and_parent_pin() {
    type TinyTasks = TaskAuthority<1, 1, 1, 1>;
    let mut registry = ObjectRegistry::<2>::new();
    let mut tasks = TinyTasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();

    assert!(matches!(
        tasks.create_child_group(&mut registry, &root_owner),
        Err(TaskCreateError::Task(TaskError::Capacity))
    ));
    assert_eq!(tasks.group_state(root), Ok(TaskGroupState::Active));

    let event = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
    registry.cancel_creation(event).unwrap();
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    let finalization = tasks.take_finalization(root_final).unwrap();
    assert!(complete_task_finalization(&mut registry, finalization).is_none());
}

#[test]
fn explicit_thread_termination_returns_execution_resources_and_closes_final_thread_process() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = process_parent_pin(&mut registry, &process_handle);
    let (thread, thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    release_nonfinal_pin(&mut registry, process_owner);
    prepare_thread(&mut tasks, thread, 9);
    tasks.start_thread(thread).unwrap();

    let pins = tasks.terminate_thread_authorized(thread, 0x88).unwrap();
    let (process_pin, thread_pins, resources) = pins.into_parts();
    let thread_pin = thread_pins.into_iter().flatten().next().unwrap();
    let resource = resources.into_iter().flatten().next().unwrap();
    assert_eq!(resource.kernel_stack, KernelStackId::new(10).unwrap());
    assert_eq!(resource.context, ThreadContextId::new(0x109).unwrap());
    assert!(registry.release_internal(thread_pin).unwrap().is_none());
    assert!(
        registry
            .release_internal(process_pin.unwrap())
            .unwrap()
            .is_none()
    );

    let thread_info = tasks.thread_info(thread).unwrap();
    assert_eq!(thread_info.reason, DW_TERMINATION_AUTHORIZED);
    assert_eq!(thread_info.detail, 0x88);
    let process_info = tasks.process_info(process).unwrap();
    assert_eq!(process_info.reason, DW_TERMINATION_AUTHORIZED);
    assert_eq!(process_info.detail, 0x88);
    assert!(matches!(
        tasks.terminate_thread_authorized(thread, 1),
        Err(TaskError::BadState)
    ));

    let thread_final = registry.release_handle(thread_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, thread_final);
    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, process_final);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}
