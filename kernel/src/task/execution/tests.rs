extern crate std;

use super::*;
use crate::object::ObjectRegistry;
use crate::task::{
    BlockedOperation, BlockedOperationWinner, SchedulerThreadState, TaskAuthority, TaskError,
};
use deepwyrm_abi::{
    DW_EXCEPTION_PAGE_FAULT, DW_TASK_STATE_EXITED, DW_TASK_STATE_RUNNING,
    DW_TERMINATION_AUTHORIZED, DW_TERMINATION_UNHANDLED_EXCEPTION,
};
use std::sync::{Arc, Barrier};

const OBJECTS: usize = 16;
type Tasks = TaskAuthority<2, 2, 4, 4>;

fn stack_bounds<const N: usize>() -> [KernelStackBounds; N] {
    core::array::from_fn(|index| {
        let stride = 0x11_000_u64;
        let guard = 0xffff_9000_0000_0000 + u64::try_from(index).unwrap() * stride;
        KernelStackBounds::new(guard, guard + 0x1000, guard + stride).unwrap()
    })
}

fn start_state(seed: u64) -> ThreadStartState {
    ThreadStartState::from_validated_user_state(
        0x0000_0000_4000_0000 + seed * 0x1000,
        0x0000_0000_5000_0000 + seed * 0x1000,
        seed,
        seed + 1,
    )
}

fn one_thread_fixture() -> (
    ObjectRegistry<OBJECTS>,
    Tasks,
    ThreadKey,
    crate::object::HandleRef,
) {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (thread, thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    assert!(registry.release_handle(process_handle).unwrap().is_none());
    (registry, tasks, thread, thread_handle)
}

fn two_thread_process_fixture() -> (
    ObjectRegistry<OBJECTS>,
    Tasks,
    crate::object::InternalRef,
    crate::object::HandleRef,
    crate::task::ProcessKey,
    crate::task::ThreadKey,
    crate::object::HandleRef,
    crate::task::ThreadKey,
    crate::object::HandleRef,
) {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (current, current_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (replacement, replacement_handle) =
        tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    (
        registry,
        tasks,
        root_owner,
        process_handle,
        process,
        current,
        current_handle,
        replacement,
        replacement_handle,
    )
}

#[test]
fn initial_context_is_explicit_and_does_not_invent_tls_or_fp_state() {
    let start = start_state(7);
    let context = SavedThreadContext::initial(start);
    assert_eq!(context.gprs, GeneralPurposeRegisters::default());
    assert_eq!(context.user_rip, start.entry());
    assert_eq!(context.user_rsp, start.stack_pointer());
    assert_eq!(context.user_rflags, E3_INITIAL_USER_RFLAGS);
    assert_eq!(context.startup_arguments, [7, 8]);
    assert_eq!(context.tls_policy, UserTlsPolicy::DisabledKernelGsOnly);
    assert_eq!(context.fp_simd_policy, FpSimdPolicy::Unavailable);
}

#[test]
fn local_quantum_expiry_cannot_revive_a_normally_exited_thread() {
    let (
        mut registry,
        mut tasks,
        root_owner,
        process_handle,
        process,
        current,
        current_handle,
        replacement,
        replacement_handle,
    ) = two_thread_process_fixture();
    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    domain
        .start_thread(&mut tasks, current, start_state(80))
        .unwrap();
    domain
        .start_thread(&mut tasks, replacement, start_state(81))
        .unwrap();
    let cpu = SchedulerCpuId::BOOTSTRAP;
    assert_eq!(domain.schedule_next_on(cpu).unwrap().current, Some(current));
    let ticket = domain
        .prepare_quantum_if_needed_on(cpu, 1)
        .unwrap()
        .expect("current Thread receives one local quantum");

    let pins = tasks.exit_thread(current, 0x80).unwrap();
    assert_eq!(
        tasks.thread_info(current).unwrap().state,
        DW_TASK_STATE_EXITED
    );
    assert_eq!(
        tasks.process_info(process).unwrap().state,
        DW_TASK_STATE_RUNNING
    );

    // The timer event may win the race after task termination but before the
    // terminal scheduler retirement. Retirement must consume that exact
    // request and prevent a later stale event from changing ownership.
    assert!(domain.publish_quantum_expiry(ticket).unwrap());
    let (retired, deferred) = domain.retire_exit_pins_defer_current(pins, current);
    assert_eq!(domain.preemption_snapshot_on(cpu).quantum, None);
    assert_eq!(domain.preemption_snapshot_on(cpu).request, None);
    let deferred_pins = domain.reclaim_deferred_current(deferred);
    assert!(!domain.publish_quantum_expiry(ticket).unwrap());
    assert_eq!(domain.scheduler_state(current), None);
    assert_eq!(
        domain.scheduler_state(replacement),
        Some(SchedulerThreadState::Running)
    );
    assert!(matches!(
        tasks.exit_thread(current, 0x81),
        Err(TaskError::BadState)
    ));

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    for reference in [current_handle, replacement_handle, process_handle] {
        let _ = registry.release_handle(reference).unwrap();
    }
    let _ = registry.release_internal(root_owner).unwrap();
}

#[test]
fn authorized_process_termination_waits_for_exact_remote_stop_ack() {
    let (
        mut registry,
        mut tasks,
        root_owner,
        process_handle,
        process,
        current,
        current_handle,
        remote,
        remote_handle,
    ) = two_thread_process_fixture();
    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    let cpu0 = SchedulerCpuId::BOOTSTRAP;
    let cpu1 = SchedulerCpuId::new(1).unwrap();
    domain
        .start_thread_on(cpu0, &mut tasks, current, start_state(82))
        .unwrap();
    domain
        .start_thread_on(cpu1, &mut tasks, remote, start_state(83))
        .unwrap();
    assert_eq!(
        domain.schedule_next_on(cpu0).unwrap().current,
        Some(current)
    );
    assert_eq!(domain.schedule_next_on(cpu1).unwrap().current, Some(remote));
    let remote_claim = domain.running_claim_on(cpu1).unwrap();
    assert_eq!(domain.terminal_scheduler_current_on(&tasks, cpu1), Ok(None));

    let effects = tasks.terminate_process_authorized(process, 0x707).unwrap();
    assert_eq!(
        tasks.thread_info(current).unwrap().state,
        DW_TASK_STATE_EXITED
    );
    assert_eq!(
        tasks.thread_info(remote).unwrap().state,
        DW_TASK_STATE_EXITED
    );
    assert_eq!(
        tasks.process_info(process).unwrap().reason,
        DW_TERMINATION_AUTHORIZED
    );
    assert_eq!(
        domain.terminal_scheduler_current_on(&tasks, cpu0),
        Ok(Some(current))
    );
    assert_eq!(
        domain.terminal_scheduler_current_on(&tasks, cpu1),
        Ok(Some(remote))
    );

    // Authorized termination may not remove a remote Running owner directly:
    // the target CPU first abandons its exact generation, then acknowledges
    // that continuation before the terminal batch can reclaim it.
    assert_eq!(domain.stop_running_claim_on(remote_claim), Ok(None));
    let remote_suspended = domain.suspended_claim_on(cpu1).unwrap();
    assert_eq!(remote_suspended, remote_claim);
    domain.complete_switch_on(remote_suspended).unwrap();
    assert_eq!(domain.suspended_claim_on(cpu1), None);
    assert_eq!(domain.scheduler_state(remote), None);
    assert_eq!(domain.terminal_scheduler_current_on(&tasks, cpu1), Ok(None));

    let (retired, deferred) = domain.retire_exit_pins_defer_current_after_remote_stops_on(
        cpu0,
        effects,
        current,
        &[Some(remote)],
    );
    let deferred_pins = domain.reclaim_deferred_current_on(cpu0, deferred);
    assert_eq!(domain.scheduler_state(current), None);
    assert_eq!(domain.scheduler_state(remote), None);
    assert_eq!(
        domain.stop_running_claim_on(remote_claim),
        Err(SchedulerError::StaleExecutionClaim)
    );

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    for reference in [current_handle, remote_handle, process_handle] {
        let _ = registry.release_handle(reference).unwrap();
    }
    let _ = registry.release_internal(root_owner).unwrap();
}

#[test]
fn remote_stop_completion_retires_exact_suspended_physical_current() {
    let (
        mut registry,
        mut tasks,
        root_owner,
        process_handle,
        process,
        current,
        current_handle,
        remote,
        remote_handle,
    ) = two_thread_process_fixture();
    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    let cpu0 = SchedulerCpuId::BOOTSTRAP;
    let cpu1 = SchedulerCpuId::new(1).unwrap();
    domain
        .start_thread_on(cpu0, &mut tasks, current, start_state(84))
        .unwrap();
    domain
        .start_thread_on(cpu1, &mut tasks, remote, start_state(85))
        .unwrap();
    assert_eq!(
        domain.schedule_next_on(cpu0).unwrap().current,
        Some(current)
    );
    assert_eq!(domain.schedule_next_on(cpu1).unwrap().current, Some(remote));

    let effects = tasks.terminate_process_authorized(process, 0x708).unwrap();
    let current_claim = domain.running_claim_on(cpu0).unwrap();
    assert_eq!(domain.stop_running_claim_on(current_claim), Ok(None));
    assert_eq!(domain.running_claim_on(cpu0), None);
    assert_eq!(domain.suspended_claim_on(cpu0), Some(current_claim));

    let remote_claim = domain.running_claim_on(cpu1).unwrap();
    assert_eq!(domain.stop_running_claim_on(remote_claim), Ok(None));
    domain
        .complete_switch_on(domain.suspended_claim_on(cpu1).unwrap())
        .unwrap();

    let (retired, deferred) = domain.retire_exit_pins_defer_current_after_remote_stops_on(
        cpu0,
        effects,
        current,
        &[Some(remote)],
    );
    assert_eq!(domain.suspended_claim_on(cpu0).unwrap().thread(), current);
    let deferred_pins = domain.reclaim_deferred_current_on(cpu0, deferred);
    assert_eq!(domain.scheduler_state(current), None);
    assert_eq!(domain.scheduler_state(remote), None);

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    for reference in [current_handle, remote_handle, process_handle] {
        let _ = registry.release_handle(reference).unwrap();
    }
    let _ = registry.release_internal(root_owner).unwrap();
}

#[test]
fn remote_stop_completion_preserves_suspended_caller_with_logical_replacement() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (outgoing_process, outgoing_process_handle) =
        tasks.create_process(&mut registry, &root_owner).unwrap();
    let outgoing_owner = registry
        .retain_internal_from_handle(&outgoing_process_handle)
        .unwrap();
    let (outgoing, outgoing_handle) = tasks.create_thread(&mut registry, &outgoing_owner).unwrap();
    let (replacement_process, replacement_process_handle) =
        tasks.create_process(&mut registry, &root_owner).unwrap();
    let replacement_owner = registry
        .retain_internal_from_handle(&replacement_process_handle)
        .unwrap();
    let (replacement, replacement_handle) = tasks
        .create_thread(&mut registry, &replacement_owner)
        .unwrap();
    assert!(registry.release_internal(outgoing_owner).unwrap().is_none());
    assert!(
        registry
            .release_internal(replacement_owner)
            .unwrap()
            .is_none()
    );

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    let cpu0 = SchedulerCpuId::BOOTSTRAP;
    domain
        .start_thread_on(cpu0, &mut tasks, outgoing, start_state(86))
        .unwrap();
    domain
        .start_thread_on(cpu0, &mut tasks, replacement, start_state(87))
        .unwrap();
    assert_eq!(
        domain.schedule_next_on(cpu0).unwrap().current,
        Some(outgoing)
    );
    let (_block, decision) = domain.block_current_on(cpu0, outgoing).unwrap();
    assert_eq!(decision.current, Some(replacement));
    let suspended = domain.suspended_claim_on(cpu0).unwrap();
    assert_eq!(suspended.thread(), outgoing);
    assert_eq!(domain.running_claim_on(cpu0).unwrap().thread(), replacement);

    let effects = tasks
        .terminate_process_authorized(outgoing_process, 0x709)
        .unwrap();
    let (retired, deferred) =
        domain.retire_exit_pins_defer_current_after_remote_stops_on(cpu0, effects, outgoing, &[]);
    assert_eq!(domain.suspended_claim_on(cpu0), Some(suspended));
    assert_eq!(domain.running_claim_on(cpu0).unwrap().thread(), replacement);
    let deferred_pins = domain.reclaim_deferred_current_on(cpu0, deferred);
    assert_eq!(domain.suspended_claim_on(cpu0), None);
    assert_eq!(domain.running_claim_on(cpu0).unwrap().thread(), replacement);
    assert_eq!(domain.scheduler_state(outgoing), None);
    assert_eq!(
        domain.scheduler_state(replacement),
        Some(SchedulerThreadState::Running)
    );
    assert_eq!(
        tasks.process_info(replacement_process).unwrap().state,
        DW_TASK_STATE_RUNNING
    );

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    for reference in [
        outgoing_handle,
        outgoing_process_handle,
        replacement_handle,
        replacement_process_handle,
    ] {
        let _ = registry.release_handle(reference).unwrap();
    }
    let _ = registry.release_internal(root_owner).unwrap();
}

#[test]
fn stack_pool_rejects_overlap_and_stale_ids() {
    let valid = stack_bounds::<2>();
    let mut overlap = valid;
    overlap[1] = valid[0];
    assert!(matches!(
        KernelStackPool::new(overlap),
        Err(ExecutionResourceError::Overlap)
    ));

    let pool = KernelStackPool::new(valid).unwrap();
    let first = pool.allocate().unwrap();
    let second = pool.allocate().unwrap();
    assert_eq!(pool.allocate(), Err(ExecutionResourceError::Capacity));
    assert_ne!(pool.bounds(first).unwrap(), pool.bounds(second).unwrap());
    let retired = pool.reclaim(first).unwrap();
    assert_eq!(retired, valid[0]);
    assert_eq!(pool.bounds(first), Err(ExecutionResourceError::StaleId));
    let replacement = pool.allocate().unwrap();
    assert_ne!(first, replacement);
    assert_eq!(pool.reclaim(replacement).unwrap(), valid[0]);
    assert_eq!(pool.reclaim(second).unwrap(), valid[1]);
}

#[test]
fn context_pool_preserves_exact_saved_state_and_retires_generation() {
    let pool = ThreadContextPool::<1>::new();
    let first_context = SavedThreadContext::initial(start_state(1));
    let first = pool.allocate(first_context).unwrap();
    assert_eq!(pool.load(first), Ok(first_context));

    let mut updated = first_context;
    updated.gprs.rax = 0xfeed_face;
    pool.store(first, updated).unwrap();
    assert_eq!(pool.load(first), Ok(updated));
    assert_eq!(pool.reclaim(first), Ok(updated));
    assert_eq!(pool.load(first), Err(ExecutionResourceError::StaleId));

    let replacement = pool.allocate(first_context).unwrap();
    assert_ne!(first, replacement);
    assert_eq!(pool.reclaim(replacement), Ok(first_context));
}

#[test]
fn continuation_publication_has_one_release_winner_and_acquire_readers() {
    const WRITERS: usize = 8;

    let pool = Arc::new(KernelContinuationPool::<1>::new());
    let context = ThreadContextId::from_raw(encode_resource_id(0, 1).unwrap()).unwrap();
    let start = Arc::new(Barrier::new(WRITERS + 1));
    let mut workers = std::vec::Vec::new();
    for writer in 0..WRITERS {
        let pool = Arc::clone(&pool);
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            let candidate = 0x1000 + u64::try_from(writer).unwrap() * 0x10;
            start.wait();
            (candidate, pool.seed(context, candidate))
        }));
    }
    start.wait();

    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("continuation publisher completes"))
        .collect::<std::vec::Vec<_>>();
    let winners = results
        .iter()
        .filter(|(_, result)| result.is_ok())
        .collect::<std::vec::Vec<_>>();
    assert_eq!(winners.len(), 1);
    assert_eq!(pool.load(context), Ok(winners[0].0));
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| {
                *result == Err(ExecutionResourceError::ContinuationAlreadyInitialized)
            })
            .count(),
        WRITERS - 1
    );
}

#[test]
fn execution_domain_starts_schedules_and_reclaims_exact_thread_resources() {
    let (mut registry, mut tasks, thread, _thread_handle) = one_thread_fixture();
    let domain = ExecutionDomain::<1>::new(stack_bounds::<1>()).unwrap();
    let start = start_state(3);

    domain.start_thread(&mut tasks, thread, start).unwrap();
    assert_eq!(
        tasks.thread_info(thread).unwrap().state,
        DW_TASK_STATE_RUNNING
    );
    assert_eq!(
        domain.scheduler_state(thread),
        Some(super::super::SchedulerThreadState::Runnable)
    );
    let (stack, context) = tasks
        .thread_execution_resources(thread)
        .unwrap()
        .expect("started thread owns E3 resources");
    assert_eq!(domain.stack_bounds(stack).unwrap(), stack_bounds::<1>()[0]);
    assert_eq!(
        domain.load_context(context).unwrap(),
        SavedThreadContext::initial(start)
    );
    assert_eq!(domain.schedule_next().unwrap().current, Some(thread));

    let pins = tasks.exit_thread(thread, 0).unwrap();
    let (retired, deferred) = domain.retire_exit_pins_defer_current(pins, thread);
    assert_eq!(domain.scheduler_state(thread), None);
    assert!(domain.stack_bounds(stack).is_ok());
    assert!(domain.load_context(context).is_ok());
    let deferred_pins = domain.reclaim_deferred_current(deferred);
    assert_eq!(
        domain.stack_bounds(stack),
        Err(ExecutionResourceError::StaleId)
    );
    assert_eq!(
        domain.load_context(context),
        Err(ExecutionResourceError::StaleId)
    );
    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
}

#[test]
fn immediate_retirement_rejects_the_physical_current_thread_before_reclaim() {
    let (_registry, mut tasks, thread, _thread_handle) = one_thread_fixture();
    let domain = ExecutionDomain::<1>::new(stack_bounds::<1>()).unwrap();
    domain
        .start_thread(&mut tasks, thread, start_state(4))
        .unwrap();
    assert_eq!(domain.schedule_next().unwrap().current, Some(thread));
    let (stack, context) = tasks.thread_execution_resources(thread).unwrap().unwrap();

    let pins = tasks.exit_thread(thread, 0).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = domain.retire_exit_pins(pins);
    }));
    assert!(result.is_err());
    assert_eq!(
        domain.scheduler_state(thread),
        Some(super::super::SchedulerThreadState::Running)
    );
    assert!(domain.stack_bounds(stack).is_ok());
    assert!(domain.load_context(context).is_ok());
}

#[test]
fn current_terminal_resources_remain_allocated_until_linear_token_is_consumed() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_ref) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_ref).unwrap();
    let process_owner = registry.retain_internal_from_handle(&process_ref).unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (sibling, sibling_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    domain
        .start_thread(&mut tasks, current, start_state(1))
        .unwrap();
    domain
        .start_thread(&mut tasks, sibling, start_state(2))
        .unwrap();
    assert_eq!(domain.schedule_next().unwrap().current, Some(current));
    let (current_stack, current_context) =
        tasks.thread_execution_resources(current).unwrap().unwrap();
    let (sibling_stack, sibling_context) =
        tasks.thread_execution_resources(sibling).unwrap().unwrap();

    let effects = tasks.exit_process(process, current, 0).unwrap();
    let (retired, deferred) = domain.retire_exit_pins_defer_current(effects, current);

    assert_eq!(deferred.thread(), current);
    assert_eq!(domain.scheduler_state(current), None);
    assert_eq!(domain.scheduler_state(sibling), None);
    assert!(domain.stack_bounds(current_stack).is_ok());
    assert!(domain.load_context(current_context).is_ok());
    assert_eq!(
        domain.stack_bounds(sibling_stack),
        Err(ExecutionResourceError::StaleId)
    );
    assert_eq!(
        domain.load_context(sibling_context),
        Err(ExecutionResourceError::StaleId)
    );
    let replacement_stack = domain.stacks.allocate().unwrap();
    assert_eq!(
        domain.stacks.allocate(),
        Err(ExecutionResourceError::Capacity)
    );
    let replacement_context = domain
        .contexts
        .allocate(SavedThreadContext::initial(start_state(3)))
        .unwrap();
    assert_eq!(
        domain
            .contexts
            .allocate(SavedThreadContext::initial(start_state(4))),
        Err(ExecutionResourceError::Capacity)
    );

    let deferred_pins = domain.reclaim_deferred_current(deferred);
    assert_eq!(
        domain.stack_bounds(current_stack),
        Err(ExecutionResourceError::StaleId)
    );
    let post_reclaim_stack = domain.stacks.allocate().unwrap();
    let post_reclaim_context = domain
        .contexts
        .allocate(SavedThreadContext::initial(start_state(4)))
        .unwrap();
    domain.stacks.reclaim(replacement_stack).unwrap();
    domain.stacks.reclaim(post_reclaim_stack).unwrap();
    domain.contexts.reclaim(replacement_context).unwrap();
    domain.contexts.reclaim(post_reclaim_context).unwrap();
    assert_eq!(
        domain.load_context(current_context),
        Err(ExecutionResourceError::StaleId)
    );

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        let _ = registry.release_internal(pin).unwrap();
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        let _ = registry.release_internal(pin).unwrap();
    }
    for reference in [current_ref, sibling_ref, process_ref] {
        let _ = registry.release_handle(reference).unwrap();
    }
    let _ = registry.release_internal(root_ref).unwrap();
}

#[test]
fn failed_task_preparation_rolls_back_scheduler_stack_and_context_capacity() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let stale_creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD)
        .unwrap();
    let stale = ThreadKey::from_object_id(stale_creation.id());
    registry.cancel_creation(stale_creation).unwrap();
    let domain = ExecutionDomain::<1>::new(stack_bounds::<1>()).unwrap();

    assert_eq!(
        domain.start_thread(&mut tasks, stale, start_state(4)),
        Err(StartThreadError::Task(TaskError::InvalidTask))
    );
    assert_eq!(domain.scheduler_state(stale), None);

    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (thread, _thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    assert!(registry.release_handle(process_handle).unwrap().is_none());

    let prepared = domain
        .prepare_thread_start(&mut tasks, thread, start_state(5))
        .unwrap();
    assert_eq!(
        domain.scheduler_state(thread),
        Some(super::super::SchedulerThreadState::Reserved)
    );
    assert!(tasks.thread_execution_resources(thread).unwrap().is_some());
    prepared.cancel(&mut tasks);
    assert_eq!(domain.scheduler_state(thread), None);
    assert!(tasks.thread_execution_resources(thread).unwrap().is_none());

    domain
        .start_thread(&mut tasks, thread, start_state(6))
        .unwrap();
    assert_eq!(
        domain.scheduler_state(thread),
        Some(super::super::SchedulerThreadState::Runnable)
    );
}

#[test]
fn e3_execution_owners_are_send_sync_without_exporting_lock_guards() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CooperativeScheduler<4>>();
    assert_send_sync::<KernelStackPool<4>>();
    assert_send_sync::<ThreadContextPool<4>>();
    assert_send_sync::<ExecutionDomain<4>>();

    let sync_surface = include_str!("../../sync/mod.rs");
    assert!(!sync_surface.contains("SpinMutexGuard"));
}

#[test]
fn process_fatal_exception_defers_current_ownership_until_divergent_reclaim() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (faulting, faulting_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (sibling, sibling_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    let _ = (root, process_handle, faulting_handle, sibling_handle);

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    domain
        .start_thread(&mut tasks, faulting, start_state(10))
        .unwrap();
    domain
        .start_thread(&mut tasks, sibling, start_state(11))
        .unwrap();
    assert_eq!(domain.schedule_next().unwrap().current, Some(faulting));
    assert_eq!(
        domain.scheduler_state(sibling),
        Some(super::super::SchedulerThreadState::Runnable)
    );

    let (fault_stack, fault_context) = tasks.thread_execution_resources(faulting).unwrap().unwrap();
    let (sibling_stack, sibling_context) =
        tasks.thread_execution_resources(sibling).unwrap().unwrap();
    let effects = domain
        .terminate_process_exception(
            &mut tasks,
            &mut registry,
            process,
            faulting,
            super::super::TaskExceptionRecord::new(
                deepwyrm_abi::DW_EXCEPTION_PAGE_FAULT,
                0x44,
                0x5555,
            ),
        )
        .unwrap();
    let _drained = effects.drained;
    let retired = effects.pins;
    let deferred = effects.deferred_current;

    assert_eq!(domain.scheduler_state(faulting), None);
    assert_eq!(domain.scheduler_state(sibling), None);
    assert_eq!(deferred.thread(), faulting);
    assert!(domain.stack_bounds(fault_stack).is_ok());
    assert!(domain.load_context(fault_context).is_ok());
    assert_eq!(
        domain.stack_bounds(sibling_stack),
        Err(ExecutionResourceError::StaleId)
    );
    assert_eq!(
        domain.load_context(sibling_context),
        Err(ExecutionResourceError::StaleId)
    );

    let replacement_stack = domain.stacks.allocate().unwrap();
    assert_eq!(
        domain.stacks.allocate(),
        Err(ExecutionResourceError::Capacity)
    );
    let replacement_context = domain
        .contexts
        .allocate(SavedThreadContext::initial(start_state(12)))
        .unwrap();
    assert_eq!(
        domain
            .contexts
            .allocate(SavedThreadContext::initial(start_state(13))),
        Err(ExecutionResourceError::Capacity)
    );

    let deferred_pins = domain.reclaim_deferred_current(deferred);
    assert_eq!(
        domain.stack_bounds(fault_stack),
        Err(ExecutionResourceError::StaleId)
    );
    assert_eq!(
        domain.load_context(fault_context),
        Err(ExecutionResourceError::StaleId)
    );
    let post_reclaim_stack = domain.stacks.allocate().unwrap();
    let post_reclaim_context = domain
        .contexts
        .allocate(SavedThreadContext::initial(start_state(13)))
        .unwrap();
    domain.stacks.reclaim(replacement_stack).unwrap();
    domain.stacks.reclaim(post_reclaim_stack).unwrap();
    domain.contexts.reclaim(replacement_context).unwrap();
    domain.contexts.reclaim(post_reclaim_context).unwrap();

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
}

#[test]
fn ap_exception_retires_exact_cpu_generation_before_reclaim() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (faulting, faulting_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (sibling, sibling_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    let cpu = SchedulerCpuId::new(1).unwrap();
    domain
        .start_thread_on(cpu, &mut tasks, faulting, start_state(84))
        .unwrap();
    domain
        .start_thread_on(cpu, &mut tasks, sibling, start_state(85))
        .unwrap();
    assert_eq!(
        domain.schedule_next_on(cpu).unwrap().current,
        Some(faulting)
    );
    let faulting_claim = domain.running_claim_on(cpu).unwrap();

    let effects = tasks
        .terminate_process_exception(
            process,
            faulting,
            DW_EXCEPTION_PAGE_FAULT,
            0x84,
            0x0000_0000_4141_5000,
        )
        .unwrap();
    assert_eq!(
        tasks.process_info(process).unwrap().reason,
        DW_TERMINATION_UNHANDLED_EXCEPTION
    );
    assert_eq!(
        tasks.thread_info(faulting).unwrap().reason,
        DW_TERMINATION_UNHANDLED_EXCEPTION
    );
    assert_eq!(
        tasks.thread_info(sibling).unwrap().state,
        DW_TASK_STATE_EXITED
    );

    // AP exception handling must retire the exact physical owner before any
    // execution resources are reclaimed; the stale claim cannot stop or
    // revive a later generation.
    let (retired, deferred) = domain.retire_exit_pins_defer_current_on(cpu, effects, faulting);
    assert_eq!(deferred.thread(), faulting);
    assert_eq!(domain.suspended_claim_on(cpu).unwrap().thread(), faulting);
    let deferred_pins = domain.reclaim_deferred_current_on(cpu, deferred);
    assert_eq!(domain.suspended_claim_on(cpu), None);
    assert_eq!(domain.scheduler_state(faulting), None);
    assert_eq!(domain.scheduler_state(sibling), None);
    assert_eq!(
        domain.stop_running_claim_on(faulting_claim),
        Err(SchedulerError::StaleExecutionClaim)
    );

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    for reference in [faulting_handle, sibling_handle, process_handle] {
        let _ = registry.release_handle(reference).unwrap();
    }
}

#[test]
fn blocked_thread_retains_resources_until_terminal_retirement() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (blocked_thread, _blocked_handle) =
        tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (sibling, _sibling_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    domain
        .start_thread(&mut tasks, blocked_thread, start_state(20))
        .unwrap();
    domain
        .start_thread(&mut tasks, sibling, start_state(21))
        .unwrap();
    assert_eq!(
        domain.schedule_next().unwrap().current,
        Some(blocked_thread)
    );
    let (stack, context) = tasks
        .thread_execution_resources(blocked_thread)
        .unwrap()
        .unwrap();
    let saved = domain.load_context(context).unwrap();
    let (token, decision) = domain.block_current(blocked_thread).unwrap();
    assert_eq!(decision.current, Some(sibling));
    assert_eq!(
        domain.scheduler_state(blocked_thread),
        Some(super::super::SchedulerThreadState::Blocked)
    );
    assert_eq!(domain.stack_bounds(stack).unwrap(), stack_bounds::<2>()[0]);
    assert_eq!(domain.load_context(context).unwrap(), saved);

    let wake = token.into_wake_key();
    let pins = tasks.exit_thread(blocked_thread, 7).unwrap();
    let retired = domain.retire_exit_pins(pins);
    assert_eq!(domain.wake(wake), Err(SchedulerError::StaleBlockToken));
    assert_eq!(
        domain.stack_bounds(stack),
        Err(ExecutionResourceError::StaleId)
    );
    assert_eq!(
        domain.load_context(context),
        Err(ExecutionResourceError::StaleId)
    );
    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
}

#[test]
fn terminal_physical_claim_prefers_unpublished_suspended_generation_over_logical_replacement() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (outgoing, _outgoing_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (replacement, _replacement_handle) =
        tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    let cpu1 = crate::cpu::CpuIndex::new(1).unwrap();
    domain
        .start_thread_on(cpu1, &mut tasks, outgoing, start_state(61))
        .unwrap();
    domain
        .start_thread_on(cpu1, &mut tasks, replacement, start_state(62))
        .unwrap();
    assert_eq!(
        domain.schedule_next_on(cpu1).unwrap().current,
        Some(outgoing)
    );
    let (_block, decision) = domain.block_current_on(cpu1, outgoing).unwrap();
    assert_eq!(decision.current, Some(replacement));
    let suspended = domain.suspended_claim_on(cpu1).unwrap();
    let running = domain.running_claim_on(cpu1).unwrap();
    assert_eq!(suspended.thread(), outgoing);
    assert_eq!(running.thread(), replacement);
    assert_eq!(
        domain.terminal_physical_claim_on(cpu1, &[Some(outgoing), None]),
        Some(suspended)
    );
    assert_eq!(
        domain.terminal_physical_claim_on(cpu1, &[Some(replacement), None]),
        Some(running)
    );

    assert_eq!(domain.retire_unentered_running_claim_on(running), Ok(None));
    assert_eq!(domain.suspended_claim_on(cpu1), Some(suspended));
    assert_eq!(domain.running_claim_on(cpu1), None);
    assert_eq!(domain.scheduler_state(replacement), None);
    assert_eq!(
        domain.scheduler_state(outgoing),
        Some(super::super::SchedulerThreadState::Blocked)
    );
    assert_eq!(domain.scheduler.check_invariants(), Ok(()));
}

#[test]
fn destination_acknowledges_prior_suspension_before_terminal_process_retirement() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (outgoing, _outgoing_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (replacement, _replacement_handle) =
        tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    domain
        .start_thread(&mut tasks, outgoing, start_state(65))
        .unwrap();
    domain
        .start_thread(&mut tasks, replacement, start_state(66))
        .unwrap();
    let cpu0 = crate::cpu::CpuIndex::BOOTSTRAP;
    assert_eq!(
        domain.schedule_next_on(cpu0).unwrap().current,
        Some(outgoing)
    );
    let (_block, decision) = domain.block_current_on(cpu0, outgoing).unwrap();
    assert_eq!(decision.current, Some(replacement));

    let outgoing_claim = domain.suspended_claim_on(cpu0).unwrap();
    domain.complete_switch_on(outgoing_claim).unwrap();
    assert_eq!(domain.suspended_claim_on(cpu0), None);

    let effects = tasks.exit_process(process, replacement, 0).unwrap();
    let (retired, deferred) = domain.retire_exit_pins_defer_current_on(cpu0, effects, replacement);
    let terminal_claim = domain.suspended_claim_on(cpu0).unwrap();
    assert_eq!(terminal_claim.thread(), replacement);
    let deferred_pins = domain.reclaim_deferred_current_on(cpu0, deferred);
    assert_eq!(domain.suspended_claim_on(cpu0), None);

    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let mut deferred_pins = deferred_pins;
    while let Some(pin) = deferred_pins.pop() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
}

#[test]
#[allow(
    unsafe_code,
    reason = "the test owns both CPU0 stack carriers while reproducing a wake after logical block commit but before the physical switch"
)]
fn cpu_bound_blocking_switch_accepts_woken_outgoing_continuation() {
    extern crate std;
    #[repr(align(4096))]
    struct Region([u8; 0x12_000]);

    fn owned_bounds(region: &mut Region) -> KernelStackBounds {
        let guard = region.0.as_mut_ptr() as u64;
        KernelStackBounds::new(guard, guard + 0x1000, guard + 0x11_000).unwrap()
    }

    let mut outgoing_region = std::boxed::Box::new(Region([0; 0x12_000]));
    let mut replacement_region = std::boxed::Box::new(Region([0; 0x12_000]));
    let outgoing_bounds = owned_bounds(&mut outgoing_region);
    let replacement_bounds = owned_bounds(&mut replacement_region);

    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (outgoing, _outgoing_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (replacement, _replacement_handle) =
        tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new([outgoing_bounds, replacement_bounds]).unwrap();
    domain
        .start_thread(&mut tasks, outgoing, start_state(71))
        .unwrap();
    domain
        .start_thread(&mut tasks, replacement, start_state(72))
        .unwrap();
    let cpu0 = crate::cpu::CpuIndex::BOOTSTRAP;
    assert_eq!(
        domain.schedule_next_on(cpu0).unwrap().current,
        Some(outgoing)
    );

    let (block, decision) = domain.block_current_on(cpu0, outgoing).unwrap();
    assert_eq!(decision.current, Some(replacement));
    let suspended = domain.suspended_claim_on(cpu0).unwrap();
    assert_eq!(suspended.thread(), outgoing);

    domain.wake(block.into_wake_key()).unwrap();
    assert_eq!(
        domain.scheduler_state(outgoing),
        Some(crate::task::SchedulerThreadState::Runnable)
    );
    assert_eq!(domain.suspended_claim_on(cpu0), Some(suspended));

    let trusted_entry = 0xffff_8000_0012_3000;
    let plan =
        unsafe { domain.prepare_blocking_kernel_switch_on(&tasks, cpu0, decision, trusted_entry) }
            .unwrap();
    assert_eq!(plan.next_stack(), replacement_bounds);
    assert_eq!(plan.next_rsp() & 0xf, 8);
}

#[test]
fn continuation_seed_rejects_foreign_geometry_and_double_publication() {
    let (mut registry, mut tasks, thread, _thread_handle) = one_thread_fixture();
    let domain = ExecutionDomain::<1>::new(stack_bounds::<1>()).unwrap();
    domain
        .start_thread(&mut tasks, thread, start_state(30))
        .unwrap();
    let (stack, context) = tasks.thread_execution_resources(thread).unwrap().unwrap();
    let bounds = domain.stack_bounds(stack).unwrap();

    assert_eq!(
        domain.seed_test_kernel_continuation(stack, context, bounds.top - 56),
        Err(ExecutionResourceError::ContinuationOutsideStack)
    );
    assert_eq!(
        domain.seed_test_kernel_continuation(stack, context, bounds.bottom - 16),
        Err(ExecutionResourceError::ContinuationOutsideStack)
    );
    let saved_rsp = bounds.top - crate::arch::x86_64::context::KERNEL_CONTEXT_FRAME_BYTES;
    domain
        .seed_test_kernel_continuation(stack, context, saved_rsp)
        .unwrap();
    assert_eq!(domain.kernel_continuation_rsp(context), Ok(saved_rsp));
    assert_eq!(
        domain.seed_test_kernel_continuation(stack, context, saved_rsp),
        Err(ExecutionResourceError::ContinuationAlreadyInitialized)
    );
    let _ = &mut registry;
}

#[test]
#[allow(
    unsafe_code,
    reason = "the test keeps the execution domain stationary while each switch plan is inspected and dropped"
)]
fn switch_plan_requires_live_seeded_destination_continuation() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (first, _first_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (second, _second_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    domain
        .start_thread(&mut tasks, first, start_state(31))
        .unwrap();
    domain
        .start_thread(&mut tasks, second, start_state(32))
        .unwrap();
    assert_eq!(domain.schedule_next().unwrap().current, Some(first));
    let (second_stack, second_context) = tasks.thread_execution_resources(second).unwrap().unwrap();
    let (_blocked, decision) = domain.block_current(first).unwrap();
    assert_eq!(decision.current, Some(second));
    assert_eq!(
        unsafe { domain.prepare_kernel_switch(&tasks, decision) }.unwrap_err(),
        ExecutionSwitchError::Resource(ExecutionResourceError::ContinuationUnavailable)
    );

    let next_bounds = domain.stack_bounds(second_stack).unwrap();
    let next_rsp = next_bounds.top - crate::arch::x86_64::context::KERNEL_CONTEXT_FRAME_BYTES;
    domain
        .seed_test_kernel_continuation(second_stack, second_context, next_rsp)
        .unwrap();
    let plan = unsafe { domain.prepare_kernel_switch(&tasks, decision) }.unwrap();
    assert_eq!(plan.next_rsp(), next_rsp);
    assert_eq!(plan.next_stack(), next_bounds);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the test keeps the execution domain stationary while inspecting the idle switch plan"
)]
fn idle_switch_plan_can_save_a_woken_waiter_behind_an_earlier_fifo_winner() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (first, _first_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (waiter, _waiter_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new(stack_bounds::<2>()).unwrap();
    domain
        .start_thread(&mut tasks, first, start_state(41))
        .unwrap();
    domain
        .start_thread(&mut tasks, waiter, start_state(42))
        .unwrap();
    assert_eq!(domain.schedule_next().unwrap().current, Some(first));
    let (first_block, first_decision) = domain.block_current(first).unwrap();
    assert_eq!(first_decision.current, Some(waiter));
    let (waiter_block, waiter_decision) = domain.block_current(waiter).unwrap();
    assert_eq!(waiter_decision.current, None);

    // Both become Runnable while the CPU is still physically on waiter's
    // suspended kernel continuation; FIFO keeps `first` ahead of `waiter`.
    domain.wake(first_block.into_wake_key()).unwrap();
    domain.wake(waiter_block.into_wake_key()).unwrap();
    let idle = domain.schedule_from_idle(waiter).unwrap();
    let decision = match idle {
        crate::task::IdleScheduleDecision::Switch(decision) => decision,
        other => panic!("expected FIFO idle switch, got {other:?}"),
    };
    assert_eq!(decision.previous, Some(waiter));
    assert_eq!(decision.current, Some(first));
    assert_eq!(
        domain.scheduler_state(waiter),
        Some(crate::task::SchedulerThreadState::Runnable)
    );

    let (first_stack, first_context) = tasks.thread_execution_resources(first).unwrap().unwrap();
    let first_bounds = domain.stack_bounds(first_stack).unwrap();
    let first_rsp = first_bounds.top - crate::arch::x86_64::context::KERNEL_CONTEXT_FRAME_BYTES;
    domain
        .seed_test_kernel_continuation(first_stack, first_context, first_rsp)
        .unwrap();
    let plan = unsafe { domain.prepare_idle_kernel_switch(&tasks, decision) }.unwrap();
    assert_eq!(plan.next_stack(), first_bounds);
    assert_eq!(plan.next_rsp(), first_rsp);
}

#[test]
fn published_winner_between_check_and_commit_is_replayed_after_block_publication() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (thread, _thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<1>::new(stack_bounds::<1>()).unwrap();
    domain
        .start_thread(&mut tasks, thread, start_state(43))
        .unwrap();
    assert_eq!(domain.schedule_next().unwrap().current, Some(thread));

    let cpu = crate::cpu::CpuIndex::BOOTSTRAP;
    let block = domain.prepare_block_current_on(cpu, thread).unwrap();
    let wake = block.wake_key();
    let operation = BlockedOperation::publish_for_process(
        domain.blocked_operations(),
        &mut tasks,
        process,
        thread,
        wake,
        (),
    )
    .unwrap();
    assert_eq!(domain.blocked_operations().winner(wake), Ok(None));

    assert_eq!(
        domain
            .blocked_operations()
            .try_claim_winner(wake, BlockedOperationWinner::AtomicWake),
        Ok(true)
    );
    assert_eq!(domain.wake(wake), Err(SchedulerError::StaleBlockToken));

    let decision = domain.commit_published_block_on(cpu, block).unwrap();
    assert_eq!(decision.current, None);
    assert_eq!(
        domain.scheduler_state(thread),
        Some(crate::task::SchedulerThreadState::Runnable)
    );
    assert_eq!(
        domain.blocked_operations().winner(wake),
        Ok(Some(BlockedOperationWinner::AtomicWake))
    );
    operation
        .complete_for_process(
            domain.blocked_operations(),
            &mut tasks,
            BlockedOperationWinner::AtomicWake,
            |()| (),
        )
        .unwrap();
}

#[test]
#[allow(
    unsafe_code,
    reason = "the test gives the F7 fresh-thread planner two process-owned aligned stack carriers and inspects the exact destination first-run frame"
)]
fn blocking_switch_prepares_fresh_destination_without_seeding_suspended_slot() {
    extern crate std;
    #[repr(align(4096))]
    struct Region([u8; 0x12_000]);

    fn owned_bounds(region: &mut Region) -> KernelStackBounds {
        let guard = region.0.as_mut_ptr() as u64;
        KernelStackBounds::new(guard, guard + 0x1000, guard + 0x11_000).unwrap()
    }

    let mut first_region = std::boxed::Box::new(Region([0; 0x12_000]));
    let mut second_region = std::boxed::Box::new(Region([0; 0x12_000]));
    let first_bounds = owned_bounds(&mut first_region);
    let second_bounds = owned_bounds(&mut second_region);

    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (first, _first_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (second, _second_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let domain = ExecutionDomain::<2>::new([first_bounds, second_bounds]).unwrap();
    domain
        .start_thread(&mut tasks, first, start_state(51))
        .unwrap();
    domain
        .start_thread(&mut tasks, second, start_state(52))
        .unwrap();
    assert_eq!(domain.schedule_next().unwrap().current, Some(first));
    let (_second_stack, second_context) =
        tasks.thread_execution_resources(second).unwrap().unwrap();
    assert_eq!(domain.kernel_continuation_rsp(second_context), Ok(0));

    let (_blocked, decision) = domain.block_current(first).unwrap();
    assert_eq!(decision.current, Some(second));
    let trusted_entry = 0xffff_8000_0012_3000;
    let plan =
        unsafe { domain.prepare_blocking_kernel_switch(&tasks, decision, trusted_entry) }.unwrap();
    assert_eq!(plan.next_stack(), second_bounds);
    assert_eq!(plan.next_rsp() & 0xf, 8);
    assert!(
        crate::arch::x86_64::context::initial_saved_rsp_is_within_stack(
            second_bounds,
            plan.next_rsp()
        )
    );
    assert_eq!(domain.kernel_continuation_rsp(second_context), Ok(0));

    let frame = plan.next_rsp() as *const u64;
    unsafe {
        assert_eq!(
            frame.add(6).read(),
            crate::arch::x86_64::context::INITIAL_KERNEL_CONTINUATION_RFLAGS
        );
        assert_eq!(frame.add(7).read(), trusted_entry);
        assert_eq!(frame.add(8).read(), 0);
    }
}

/// R5D: abandoning a retired execution pin is a panic, not a silent leak.
///
/// `into_parts` could not enforce this -- it handed the two arrays out, and
/// dropping them was legal. Draining in place lets the record check itself, which
/// is worth more than the bytes the conversion saved.
#[test]
#[should_panic = "retired terminal execution pins dropped without release"]
fn r5d_a_retired_pin_cannot_be_abandoned() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let pins = RetiredExitPins::<1> {
        process: Some(root_owner),
        threads: [None],
        next: 0,
    };
    // `tasks` is forgotten rather than dropped so that nothing else panics
    // while unwinding, which would abort and hide which assertion this test is
    // about. The registry has no `Drop`, so neither forgetting nor dropping
    // it says anything; it simply falls out of scope.
    core::mem::forget(tasks);
    drop(pins);
}
