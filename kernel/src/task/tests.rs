extern crate std;

use super::*;
#[cfg(deepwyrm_wyr1_evidence)]
use deepwyrm_abi::DW_OBJECT_TYPE_ADDRESS_REGION;
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

#[cfg(deepwyrm_wyr1_evidence)]
fn wyr1_reporter_enablement_model(
    tasks: &Tasks,
    primordial: ProcessKey,
    reporter: ProcessKey,
) -> bool {
    reporter != primordial
        && tasks.process_quiescence_proof(primordial).is_ok()
        && tasks.root_region(primordial) == Ok(None)
        && tasks.process_lifecycle(reporter) == Ok(ProcessLifecycleState::AcceptingOperations)
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
                kernel_stack: KernelStackId::from_raw(seed + 1).unwrap(),
                context: ThreadContextId::from_raw(seed + 0x100).unwrap(),
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
fn resource_claim_membership_is_exact_or_descendant_not_ancestor_possession() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (domain, domain_handle) = tasks
        .create_child_group(&mut registry, &root_owner)
        .unwrap();
    let domain_parent = registry
        .retain_internal_from_handle(&domain_handle)
        .unwrap();
    let (attempt, attempt_handle) = tasks
        .create_child_group(&mut registry, &domain_parent)
        .unwrap();
    let attempt_parent = registry
        .retain_internal_from_handle(&attempt_handle)
        .unwrap();
    let (process, _process_handle) = tasks
        .create_process(&mut registry, &attempt_parent)
        .unwrap();

    let proof = tasks
        .prepare_resource_claim_membership(process, domain)
        .expect("descendant process belongs to exact resource domain");
    assert_eq!(tasks.validate_resource_claim_membership(&proof), Ok(()));
    let (unrelated, unrelated_owner) = tasks.create_root_group(&mut registry).unwrap();
    assert_eq!(
        tasks.prepare_resource_claim_membership(process, unrelated),
        Err(ResourceClaimMembershipError::AccessDenied)
    );
    assert_ne!(root, domain);
    assert_ne!(attempt, domain);
    drop(unrelated_owner);
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

    let effects = tasks.exit_process(process, thread0, 0x55aa).unwrap();
    let (releases, drained) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, process)
        .unwrap();
    assert_eq!(drained, 1);
    let event_final = releases.into_iter().flatten().next().unwrap();
    registry.complete_finalization(event_final).unwrap();
    assert_eq!(tasks.process_handle_count(process), Ok(0));
    assert!(matches!(
        tasks.process_handles_mut(process),
        Err(TaskError::BadState)
    ));
    assert!(
        release_pins(&mut registry, effects)
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
        tasks.exit_process(process, thread0, 1),
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
fn process_gate_selects_one_termination_and_drains_preexisting_operations() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();

    let lease = tasks.acquire_process_operation(process).unwrap();
    assert!(matches!(
        tasks.terminate_process_authorized(process, 0x11),
        Err(TaskError::OperationsInFlight)
    ));
    assert_eq!(
        tasks.process_lifecycle(process),
        Ok(ProcessLifecycleState::Quiescing)
    );
    assert_eq!(
        tasks.acquire_process_operation(process).err(),
        Some(TaskError::BadState)
    );
    assert!(tasks.validate_process_operation(&lease, process).is_ok());
    assert!(
        tasks
            .process_handles_mut_for_operation(&lease, process)
            .is_ok()
    );

    // A competing reason cannot replace the winner selected when the gate
    // first closed, either before or after the old operation drains.
    assert!(matches!(
        tasks.terminate_process_authorized(process, 0x22),
        Err(TaskError::BadState)
    ));
    tasks.release_process_operation(lease).unwrap();
    assert!(matches!(
        tasks.terminate_process_authorized(process, 0x22),
        Err(TaskError::BadState)
    ));
    let effects = tasks.terminate_process_authorized(process, 0x11).unwrap();
    assert_eq!(
        tasks.process_lifecycle(process),
        Ok(ProcessLifecycleState::Exited)
    );
    let proof = tasks.process_quiescence_proof(process).unwrap();
    assert!(tasks.validate_process_quiescence(&proof, process).is_ok());
    assert_eq!(tasks.process_info(process).unwrap().detail, 0x11);
    assert!(
        release_pins(&mut registry, effects)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );

    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, process_final);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

#[cfg(deepwyrm_wyr1_evidence)]
#[test]
fn wyr1_monitor_retains_exited_process_through_root_retirement_enablement_model() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root_group, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (primordial, process_monitor) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let (reporter, _reporter_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let root = registry.create(DW_OBJECT_TYPE_ADDRESS_REGION).unwrap();
    let root_object = root.id();
    let region_owner = registry.creation_into_internal(root).unwrap();
    tasks.attach_root_region(primordial, root_object).unwrap();

    assert!(!wyr1_reporter_enablement_model(
        &tasks, primordial, reporter
    ));

    let effects = tasks
        .terminate_process_authorized(primordial, 0x2510)
        .unwrap();
    let (process_pin, thread_pins, resources) = effects.into_parts();
    assert!(thread_pins.into_iter().all(|pin| pin.is_none()));
    assert!(resources.into_iter().all(|resource| resource.is_none()));
    assert!(
        registry
            .release_internal(process_pin.unwrap())
            .unwrap()
            .is_none()
    );
    assert!(!wyr1_reporter_enablement_model(
        &tasks, primordial, reporter
    ));

    assert_eq!(
        tasks.take_exited_root_region(primordial).unwrap(),
        Some(root_object)
    );
    assert!(tasks.process_quiescence_proof(primordial).is_ok());
    assert_eq!(ProcessKey::from_object_id(process_monitor.id()), primordial);
    assert_eq!(
        tasks.process_info(primordial).unwrap().state,
        DW_TASK_STATE_EXITED
    );
    assert!(wyr1_reporter_enablement_model(&tasks, primordial, reporter));

    assert!(registry.release_internal(region_owner).unwrap().is_some());
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
            process,
            faulting,
            DW_EXCEPTION_PAGE_FAULT,
            0x17,
            0x0000_0000_4141_5000,
        )
        .unwrap();
    let (_, drained) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, process)
        .unwrap();
    assert_eq!(drained, 0);
    assert!(
        release_pins(&mut registry, effects)
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

    let effects = tasks.terminate_group(root).unwrap();
    assert_eq!(effects.len(), 1);
    for process in effects.process_keys().into_iter().flatten() {
        let (_, drained) = tasks
            .drain_exited_process_handles_stepwise(&mut registry, process)
            .unwrap();
        assert_eq!(drained, 0);
        let pins = tasks.take_exited_process_exit_pins(process).unwrap();
        assert!(
            release_pins(&mut registry, pins)
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
        tasks.terminate_group(root),
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
fn task_group_termination_threads_exclude_retained_exited_descendants() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (target_group, target_group_handle) = tasks
        .create_child_group(&mut registry, &root_owner)
        .unwrap();
    let target_owner = registry
        .retain_internal_from_handle(&target_group_handle)
        .unwrap();

    let (exited_process, exited_process_handle) =
        tasks.create_process(&mut registry, &target_owner).unwrap();
    let exited_owner = process_parent_pin(&mut registry, &exited_process_handle);
    let (exited_thread, exited_thread_handle) =
        tasks.create_thread(&mut registry, &exited_owner).unwrap();
    release_nonfinal_pin(&mut registry, exited_owner);
    prepare_thread(&mut tasks, exited_thread, 7);
    tasks.start_thread(exited_thread).unwrap();
    let exited = tasks
        .exit_process(exited_process, exited_thread, 0)
        .unwrap();
    let (_, drained) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, exited_process)
        .unwrap();
    assert_eq!(drained, 0);
    assert!(
        release_pins(&mut registry, exited)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );

    let (live_process, live_process_handle) =
        tasks.create_process(&mut registry, &target_owner).unwrap();
    let live_owner = process_parent_pin(&mut registry, &live_process_handle);
    let (exited_sibling, exited_sibling_handle) =
        tasks.create_thread(&mut registry, &live_owner).unwrap();
    let (live_thread, live_thread_handle) =
        tasks.create_thread(&mut registry, &live_owner).unwrap();
    release_nonfinal_pin(&mut registry, live_owner);
    prepare_thread(&mut tasks, exited_sibling, 8);
    tasks.start_thread(exited_sibling).unwrap();
    prepare_thread(&mut tasks, live_thread, 9);
    tasks.start_thread(live_thread).unwrap();
    let exited_sibling_pins = tasks.exit_thread(exited_sibling, 7).unwrap();
    assert!(!exited_sibling_pins.exits_process());
    assert!(
        release_pins(&mut registry, exited_sibling_pins)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );
    release_nonfinal_pin(&mut registry, target_owner);

    assert_eq!(
        tasks.task_group_thread_keys(target_group).unwrap(),
        [
            Some(exited_thread),
            Some(exited_sibling),
            Some(live_thread),
            None,
            None,
            None,
            None,
            None
        ]
    );
    assert_eq!(
        tasks.process_thread_keys(live_process).unwrap(),
        [
            Some(exited_sibling),
            Some(live_thread),
            None,
            None,
            None,
            None,
            None,
            None
        ]
    );
    assert_eq!(
        tasks.process_termination_thread_keys(live_process).unwrap(),
        [Some(live_thread), None, None, None, None, None, None, None]
    );
    let termination_threads = tasks
        .task_group_termination_thread_keys(target_group)
        .unwrap();
    assert_eq!(
        termination_threads,
        [Some(live_thread), None, None, None, None, None, None, None]
    );

    let effects = tasks.terminate_group(target_group).unwrap();
    assert_eq!(effects.len(), 1);
    assert_eq!(
        effects.process_keys(),
        [Some(live_process), None, None, None]
    );
    assert_eq!(effects.thread_keys(), termination_threads);
    for process in effects.process_keys().into_iter().flatten() {
        let (_, drained) = tasks
            .drain_exited_process_handles_stepwise(&mut registry, process)
            .unwrap();
        assert_eq!(drained, 0);
        let pins = tasks.take_exited_process_exit_pins(process).unwrap();
        assert!(
            release_pins(&mut registry, pins)
                .into_iter()
                .flatten()
                .next()
                .is_none()
        );
    }

    for handle in [
        exited_thread_handle,
        exited_sibling_handle,
        live_thread_handle,
        exited_process_handle,
        live_process_handle,
        target_group_handle,
    ] {
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, final_release);
    }
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

#[test]
fn task_group_termination_threads_are_empty_when_all_descendants_exited() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (target_group, target_group_handle) = tasks
        .create_child_group(&mut registry, &root_owner)
        .unwrap();
    let target_owner = registry
        .retain_internal_from_handle(&target_group_handle)
        .unwrap();
    let (_nested_group, nested_group_handle) = tasks
        .create_child_group(&mut registry, &target_owner)
        .unwrap();
    release_nonfinal_pin(&mut registry, target_owner);
    let nested_owner = registry
        .retain_internal_from_handle(&nested_group_handle)
        .unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &nested_owner).unwrap();
    release_nonfinal_pin(&mut registry, nested_owner);
    let process_owner = process_parent_pin(&mut registry, &process_handle);
    let (thread, thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    release_nonfinal_pin(&mut registry, process_owner);
    prepare_thread(&mut tasks, thread, 9);
    tasks.start_thread(thread).unwrap();
    let exited = tasks.exit_process(process, thread, 0).unwrap();
    let (_, drained) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, process)
        .unwrap();
    assert_eq!(drained, 0);
    assert!(
        release_pins(&mut registry, exited)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );

    assert_eq!(
        tasks.task_group_thread_keys(target_group).unwrap(),
        [Some(thread), None, None, None, None, None, None, None]
    );
    assert_eq!(
        tasks
            .task_group_termination_thread_keys(target_group)
            .unwrap(),
        [None; 8]
    );
    let effects = tasks.terminate_group(target_group).unwrap();
    assert_eq!(effects.len(), 0);

    for handle in [
        thread_handle,
        process_handle,
        nested_group_handle,
        target_group_handle,
    ] {
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, final_release);
    }
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
fn prepared_process_is_hidden_from_group_teardown_and_cancels_afterwards() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let prepared = tasks.prepare_process(&mut registry, &root_owner).unwrap();
    let process = prepared.key();

    let root_slot = tasks
        .groups
        .iter()
        .position(|record| {
            record
                .as_ref()
                .is_some_and(|record| record.object == root.object_id())
        })
        .unwrap();
    let root_record = tasks.groups[root_slot].as_ref().unwrap();
    assert!(root_record.processes.iter().all(Option::is_none));
    assert!(
        root_record
            .reserved_processes
            .iter()
            .any(|object| *object == Some(process.object_id()))
    );

    let effects = tasks.terminate_group(root).unwrap();
    assert_eq!(effects.len(), 0);
    assert!(prepared.cancel(&mut tasks, &mut registry).is_none());

    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

#[test]
fn prepared_thread_cancel_removes_parent_attachment_and_recovers_capacity() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let prepared = tasks.prepare_thread(&mut registry, &process_owner).unwrap();
    let prepared_key = prepared.key();

    let process_record = tasks
        .processes
        .iter()
        .flatten()
        .find(|record| record.object == process.object_id())
        .unwrap();
    assert!(
        process_record
            .threads
            .iter()
            .any(|object| *object == Some(prepared_key.object_id()))
    );
    assert!(prepared.cancel(&mut tasks, &mut registry).is_none());
    let process_record = tasks
        .processes
        .iter()
        .flatten()
        .find(|record| record.object == process.object_id())
        .unwrap();
    assert!(process_record.threads.iter().all(Option::is_none));

    let replacement = tasks.prepare_thread(&mut registry, &process_owner).unwrap();
    assert_ne!(replacement.key(), prepared_key);
    assert!(replacement.cancel(&mut tasks, &mut registry).is_none());
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    let effects = tasks.terminate_process_authorized(process, 0).unwrap();
    let (_, drained) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, process)
        .unwrap();
    assert_eq!(drained, 0);
    assert!(
        release_pins(&mut registry, effects)
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );
    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, process_final);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
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
    assert_eq!(resource.kernel_stack, KernelStackId::from_raw(10).unwrap());
    assert_eq!(resource.context, ThreadContextId::from_raw(0x109).unwrap());
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

#[test]
fn process_owned_handle_tables_isolate_colliding_raw_handles() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process0, process0_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let (process1, process1_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();

    let event0_creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
    let event0_id = event0_creation.id();
    let event0_ref = registry.creation_into_handle(event0_creation).unwrap();
    let event1_creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
    let event1_id = event1_creation.id();
    let event1_ref = registry.creation_into_handle(event1_creation).unwrap();
    let handle0 = tasks
        .process_handles_mut(process0)
        .unwrap()
        .install(event0_ref, DW_RIGHT_INSPECT)
        .unwrap();
    let handle1 = tasks
        .process_handles_mut(process1)
        .unwrap()
        .install(event1_ref, DW_RIGHT_INSPECT)
        .unwrap();
    assert_eq!(handle0, handle1, "raw handles are process-local identities");

    let resolved0 = tasks
        .process_handles(process0)
        .unwrap()
        .lookup(
            &mut registry,
            handle0,
            crate::handle::AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    let resolved1 = tasks
        .process_handles(process1)
        .unwrap()
        .lookup(
            &mut registry,
            handle1,
            crate::handle::AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    assert_eq!(resolved0.object_id(), event0_id);
    assert_eq!(resolved1.object_id(), event1_id);
    assert_ne!(resolved0.object_id(), resolved1.object_id());
    release_nonfinal_pin(&mut registry, resolved0.into_internal());
    release_nonfinal_pin(&mut registry, resolved1.into_internal());

    let event0_final = tasks
        .process_handles_mut(process0)
        .unwrap()
        .close(&mut registry, handle0)
        .unwrap()
        .unwrap();
    registry.complete_finalization(event0_final).unwrap();
    let still_live = tasks
        .process_handles(process1)
        .unwrap()
        .lookup(
            &mut registry,
            handle1,
            crate::handle::AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    assert_eq!(still_live.object_id(), event1_id);
    release_nonfinal_pin(&mut registry, still_live.into_internal());
    let event1_final = tasks
        .process_handles_mut(process1)
        .unwrap()
        .close(&mut registry, handle1)
        .unwrap()
        .unwrap();
    registry.complete_finalization(event1_final).unwrap();

    for process in [process0, process1] {
        let effects = tasks.terminate_process_authorized(process, 0x61).unwrap();
        let (_, drained) = tasks
            .drain_exited_process_handles_stepwise(&mut registry, process)
            .unwrap();
        assert_eq!(drained, 0);
        assert!(
            release_pins(&mut registry, effects)
                .into_iter()
                .flatten()
                .next()
                .is_none()
        );
    }
    for handle in [process0_handle, process1_handle] {
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, final_release);
    }
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

#[test]
fn task_group_teardown_at_process_capacity_is_bounded() {
    type CapacityTasks = TaskAuthority<1, 4, 0, 1>;
    let mut registry = ObjectRegistry::<8>::new();
    let mut tasks = CapacityTasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let mut processes = std::vec::Vec::new();
    let mut handles = std::vec::Vec::new();
    for _ in 0..4 {
        let (process, handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
        processes.push(process);
        handles.push(handle);
    }
    assert!(matches!(
        tasks.create_process(&mut registry, &root_owner),
        Err(TaskCreateError::Task(TaskError::Capacity))
    ));

    let effects = tasks.terminate_group(root).unwrap();
    assert_eq!(effects.len(), 4);
    for process in effects.process_keys().into_iter().flatten() {
        let (_, drained) = tasks
            .drain_exited_process_handles_stepwise(&mut registry, process)
            .unwrap();
        assert_eq!(drained, 0);
        let (process_pin, thread_pins, resources) = tasks
            .take_exited_process_exit_pins(process)
            .unwrap()
            .into_parts();
        assert!(thread_pins.into_iter().next().is_none());
        assert!(resources.into_iter().next().is_none());
        assert!(
            registry
                .release_internal(process_pin.unwrap())
                .unwrap()
                .is_none()
        );
    }
    for process in processes {
        let info = tasks.process_info(process).unwrap();
        assert_eq!(info.state, DW_TASK_STATE_EXITED);
        assert_eq!(info.reason, DW_TERMINATION_TASK_GROUP_TEARDOWN);
    }
    for handle in handles {
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = tasks.take_finalization(final_release).unwrap();
        assert!(complete_task_finalization(&mut registry, finalization).is_none());
    }
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    let finalization = tasks.take_finalization(root_final).unwrap();
    assert!(complete_task_finalization(&mut registry, finalization).is_none());
}

#[test]
fn deterministic_start_close_terminate_finalize_interleavings_preserve_lifetime() {
    for close_before_start in [true, false] {
        let mut registry = ObjectRegistry::<OBJECTS>::new();
        let mut tasks = Tasks::new();
        let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
        let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
        let process_owner = process_parent_pin(&mut registry, &process_handle);
        let (thread, thread_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
        release_nonfinal_pin(&mut registry, process_owner);
        let thread_handle = tasks
            .process_handles_mut(process)
            .unwrap()
            .install(thread_ref, DW_RIGHT_INSPECT)
            .unwrap();

        if close_before_start {
            assert!(
                tasks
                    .process_handles_mut(process)
                    .unwrap()
                    .close(&mut registry, thread_handle)
                    .unwrap()
                    .is_none()
            );
        }
        prepare_thread(&mut tasks, thread, 0x30 + u64::from(close_before_start));
        tasks.start_thread(thread).unwrap();
        if !close_before_start {
            assert!(
                tasks
                    .process_handles_mut(process)
                    .unwrap()
                    .close(&mut registry, thread_handle)
                    .unwrap()
                    .is_none()
            );
        }

        let pins = tasks.terminate_thread_authorized(thread, 0x77).unwrap();
        let releases: std::vec::Vec<_> = release_pins(&mut registry, pins)
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(releases.len(), 1);
        assert_eq!(
            releases[0].object_type(),
            deepwyrm_abi::DW_OBJECT_TYPE_THREAD
        );
        finish_task_release(
            &mut tasks,
            &mut registry,
            releases.into_iter().next().unwrap(),
        );
        assert_eq!(tasks.thread_info(thread), Err(TaskError::InvalidTask));
        assert_eq!(tasks.start_thread(thread), Err(TaskError::InvalidTask));

        let process_final = registry.release_handle(process_handle).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, process_final);
        let root_final = registry.release_internal(root_owner).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, root_final);
    }
}

/// R5B: an exited Process's handles reach their finalizers across several
/// bounded steps, not in one `HANDLES`-wide array.
///
/// The table is filled to capacity and the window is narrower than it, so a
/// step that resumed from the wrong slot would either skip a finalizer -- the
/// count would fall short -- or revisit one, which the registry refuses.
#[test]
fn r5b_a_full_handle_table_drains_across_bounded_steps() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let temporary_process_pin = process_parent_pin(&mut registry, &process_handle);
    let (thread, _thread_handle) = tasks
        .create_thread(&mut registry, &temporary_process_pin)
        .unwrap();
    release_nonfinal_pin(&mut registry, temporary_process_pin);
    prepare_thread(&mut tasks, thread, 2);
    tasks.start_thread(thread).unwrap();

    for object_type in [
        DW_OBJECT_TYPE_EVENT,
        DW_OBJECT_TYPE_EVENT,
        DW_OBJECT_TYPE_EVENT,
        DW_OBJECT_TYPE_EVENT,
    ] {
        let creation = registry.create(object_type).unwrap();
        let reference = registry.creation_into_handle(creation).unwrap();
        tasks
            .process_handles_mut(process)
            .unwrap()
            .install(reference, DW_RIGHT_INSPECT)
            .unwrap();
    }
    assert_eq!(tasks.process_handle_count(process), Ok(4));

    // A live Process may not be drained: nothing in a cursor proves the subject
    // is terminal, so every step rechecks.
    let mut window: [Option<FinalRelease>; 2] = [None, None];
    assert_eq!(
        tasks
            .drain_exited_process_handle_window(&mut registry, process, 0, &mut window)
            .err(),
        Some(TaskError::BadState)
    );

    let pins = tasks.exit_process(process, thread, 0).unwrap();
    let (releases, drained) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, process)
        .unwrap();
    assert_eq!(drained, 4);
    assert_eq!(tasks.process_handle_count(process), Ok(0));
    for release in releases.into_iter().flatten() {
        registry.complete_finalization(release).unwrap();
    }
    for pin in release_pins(&mut registry, pins).into_iter().flatten() {
        registry.complete_finalization(pin).unwrap();
    }
    drop(root_owner);
}

/// Fixture for R5C: a root group holding one Process with one started Thread.
///
/// Returns the keys and the handles the caller must release.
fn one_process_group(
    tasks: &mut Tasks,
    registry: &mut ObjectRegistry<OBJECTS>,
) -> (
    TaskGroupKey,
    InternalRef,
    ProcessKey,
    ThreadKey,
    HandleRef,
    HandleRef,
) {
    let (root, root_owner) = tasks.create_root_group(registry).unwrap();
    let (process, process_handle) = tasks.create_process(registry, &root_owner).unwrap();
    let process_owner = process_parent_pin(registry, &process_handle);
    let (thread, thread_handle) = tasks.create_thread(registry, &process_owner).unwrap();
    release_nonfinal_pin(registry, process_owner);
    prepare_thread(tasks, thread, 9);
    tasks.start_thread(thread).unwrap();
    (
        root,
        root_owner,
        process,
        thread,
        process_handle,
        thread_handle,
    )
}

/// R5C: TaskGroup teardown leaves each Process's terminal execution pins in its
/// records, and the caller takes them one Process at a time.
///
/// This is the property that let the `[ProcessExitEffects; PROCESSES]` batch go.
/// A second take yields nothing, so the obligations are linear rather than
/// copied, and a Process that has not been torn down refuses to hand any over.
#[test]
fn r5c_group_teardown_leaves_each_processs_pins_for_the_caller_to_take() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner, process, thread, process_handle, thread_handle) =
        one_process_group(&mut tasks, &mut registry);

    // A live Process holds pins that are not the caller's to take.
    assert_eq!(
        tasks.take_exited_process_exit_pins(process).err(),
        Some(TaskError::BadState)
    );

    let teardown = tasks.terminate_group(root).unwrap();
    assert_eq!(teardown.process_keys()[0], Some(process));
    assert_eq!(teardown.thread_keys()[0], Some(thread));

    let pins = tasks.take_exited_process_exit_pins(process).unwrap();
    assert!(pins.exits_process());
    assert_eq!(pins.thread_keys()[0], Some(thread));

    // Taking again is empty rather than a second copy of the same obligations.
    let second = tasks.take_exited_process_exit_pins(process).unwrap();
    assert!(!second.exits_process());
    assert!(second.thread_keys().into_iter().all(|key| key.is_none()));

    for release in release_pins(&mut registry, pins).into_iter().flatten() {
        finish_task_release(&mut tasks, &mut registry, release);
    }
    for handle in [thread_handle, process_handle] {
        let release = registry.release_handle(handle).unwrap().unwrap();
        finish_task_release(&mut tasks, &mut registry, release);
    }
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}

/// R5C: a pin left waiting in a terminal record cannot be lost.
///
/// Deferring pin capture is safe because the pin is a real reference, not a
/// bookkeeping flag. While a terminal Process and Thread still hold theirs,
/// dropping every Handle to them finalizes nothing -- so a teardown that never
/// retires a Process strands that Process instead of leaking its execution
/// authority, and the objects are still there to be found.
#[test]
fn r5c_untaken_pins_keep_a_terminal_process_from_reaching_finalization() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner, process, thread, process_handle, thread_handle) =
        one_process_group(&mut tasks, &mut registry);
    let teardown = tasks.terminate_group(root).unwrap();
    assert_eq!(teardown.len(), 1);
    let (_, drained) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, process)
        .unwrap();
    assert_eq!(drained, 0);

    // Every Handle gone, both still pinned: nothing finalizes.
    assert!(registry.release_handle(thread_handle).unwrap().is_none());
    assert!(registry.release_handle(process_handle).unwrap().is_none());
    assert_eq!(
        tasks.thread_info(thread).unwrap().state,
        DW_TASK_STATE_EXITED
    );
    assert_eq!(
        tasks.process_info(process).unwrap().state,
        DW_TASK_STATE_EXITED
    );

    // Taking the pins is what lets finalization run.
    let pins = tasks.take_exited_process_exit_pins(process).unwrap();
    for release in release_pins(&mut registry, pins).into_iter().flatten() {
        finish_task_release(&mut tasks, &mut registry, release);
    }
    assert_eq!(tasks.process_info(process), Err(TaskError::InvalidTask));
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    finish_task_release(&mut tasks, &mut registry, root_final);
}
