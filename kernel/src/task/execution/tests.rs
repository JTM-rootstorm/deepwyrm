extern crate std;

use super::*;
use crate::object::ObjectRegistry;
use crate::task::{TaskAuthority, TaskError};
use deepwyrm_abi::DW_TASK_STATE_RUNNING;

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
    let retired = domain.retire_exit_pins(pins);
    assert_eq!(domain.scheduler_state(thread), None);
    assert_eq!(
        domain.stack_bounds(stack),
        Err(ExecutionResourceError::StaleId)
    );
    assert_eq!(
        domain.load_context(context),
        Err(ExecutionResourceError::StaleId)
    );
    let (process_pin, thread_pins) = retired.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
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

    domain
        .start_thread(&mut tasks, thread, start_state(5))
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
fn process_fatal_exception_retires_running_and_runnable_execution_ownership() {
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

    assert_eq!(domain.scheduler_state(faulting), None);
    assert_eq!(domain.scheduler_state(sibling), None);
    for stack in [fault_stack, sibling_stack] {
        assert_eq!(
            domain.stack_bounds(stack),
            Err(ExecutionResourceError::StaleId)
        );
    }
    for context in [fault_context, sibling_context] {
        assert_eq!(
            domain.load_context(context),
            Err(ExecutionResourceError::StaleId)
        );
    }
    let (process_pin, thread_pins) = retired.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
}
