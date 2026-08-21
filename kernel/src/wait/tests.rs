use super::*;

use deepwyrm_abi::{
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_SIGNAL, DW_RIGHT_WAIT, DW_SIGNAL_READABLE,
};

use crate::handle::{AcceptedObjectTypes, HandleTable};
use crate::task::CooperativeScheduler;

fn make_thread_key<const OBJECTS: usize>(registry: &mut ObjectRegistry<OBJECTS>) -> ThreadKey {
    let creation = registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
    let key = ThreadKey::from_object_id(creation.id());
    registry.cancel_creation(creation).unwrap();
    key
}

fn blocked_key<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    scheduler: &CooperativeScheduler<2>,
) -> (ThreadKey, BlockWakeKey) {
    let thread = make_thread_key(registry);
    let reservation = scheduler.reserve(thread).unwrap();
    scheduler.commit(reservation).unwrap();
    scheduler.schedule_next().unwrap();
    let (blocked, _) = scheduler.block_current(thread).unwrap();
    (thread, blocked.into_wake_key())
}

#[test]
fn event_is_manual_reset_and_set_wakes_every_registered_waiter() {
    let mut registry = ObjectRegistry::<12>::new();
    let events = EventAuthority::<2>::new();
    let waits = WaitRegistry::<4>::new();
    let (event, handle) = events.create_event(&mut registry).unwrap();
    assert_eq!(events.current_signals(event).unwrap(), DwSignals(0));

    let mut table = HandleTable::<4>::new();
    let handle = table
        .install(
            handle,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
        )
        .unwrap();
    let scheduler = CooperativeScheduler::<2>::new();

    let first_thread = make_thread_key(&mut registry);
    let first_reservation = scheduler.reserve(first_thread).unwrap();
    scheduler.commit(first_reservation).unwrap();
    let second_thread = make_thread_key(&mut registry);
    let second_reservation = scheduler.reserve(second_thread).unwrap();
    scheduler.commit(second_reservation).unwrap();
    scheduler.schedule_next().unwrap();
    let (first_block, _) = scheduler.block_current(first_thread).unwrap();
    let (second_block, _) = scheduler.block_current(second_thread).unwrap();

    let first = table
        .lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    let second = table
        .lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert!(matches!(
        events
            .register_wait(
                &waits,
                first,
                DW_SIGNAL_SIGNALED,
                0,
                first_thread,
                first_block.into_wake_key(),
            )
            .unwrap(),
        EventWaitOutcome::Registered(_)
    ));
    assert!(matches!(
        events
            .register_wait(
                &waits,
                second,
                DW_SIGNAL_SIGNALED,
                1,
                second_thread,
                second_block.into_wake_key(),
            )
            .unwrap(),
        EventWaitOutcome::Registered(_)
    ));
    assert_eq!(waits.len(), 2);

    let wakes = events
        .signal(event, DwSignals(0), DW_SIGNAL_SIGNALED, &waits)
        .unwrap();
    assert_eq!(wakes.len(), 2);
    let (wake_intents, pins) = wakes.into_parts();
    for wake in wake_intents.into_iter().flatten() {
        assert_eq!(wake.observed(), DW_SIGNAL_SIGNALED);
        scheduler.wake(wake.wake_key()).unwrap();
    }
    for pin in pins.into_iter().flatten() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    assert_eq!(waits.len(), 0);
    assert_eq!(events.current_signals(event).unwrap(), DW_SIGNAL_SIGNALED);

    let cleared = events
        .signal(event, DW_SIGNAL_SIGNALED, DwSignals(0), &waits)
        .unwrap();
    assert_eq!(cleared.len(), 0);
    assert_eq!(events.current_signals(event).unwrap(), DwSignals(0));

    let final_release = table.close(&mut registry, handle).unwrap().unwrap();
    let finalization = events.take_finalization(final_release).unwrap();
    complete_event_finalization(&mut registry, finalization);
}

#[test]
fn already_signaled_event_returns_ready_without_publishing_registration() {
    let mut registry = ObjectRegistry::<8>::new();
    let events = EventAuthority::<1>::new();
    let waits = WaitRegistry::<1>::new();
    let (event, handle_ref) = events.create_event(&mut registry).unwrap();
    let mut table = HandleTable::<2>::new();
    let handle = table
        .install(
            handle_ref,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
        )
        .unwrap();
    let initial_wakes = events
        .signal(event, DwSignals(0), DW_SIGNAL_SIGNALED, &waits)
        .unwrap();
    assert_eq!(initial_wakes.len(), 0);

    let scheduler = CooperativeScheduler::<2>::new();
    let (thread, wake) = blocked_key(&mut registry, &scheduler);
    let target = table
        .lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    match events
        .register_wait(&waits, target, DW_SIGNAL_SIGNALED, 0, thread, wake)
        .unwrap()
    {
        EventWaitOutcome::Ready { observed, pin } => {
            assert_eq!(observed, DW_SIGNAL_SIGNALED);
            assert!(registry.release_internal(pin).unwrap().is_none());
        }
        EventWaitOutcome::Registered(_) => panic!("signaled Event unexpectedly blocked"),
    }
    assert_eq!(waits.len(), 0);
    let final_release = table.close(&mut registry, handle).unwrap().unwrap();
    let finalization = events.take_finalization(final_release).unwrap();
    complete_event_finalization(&mut registry, finalization);
}

#[test]
fn registration_pin_defers_event_finalization_until_cancelled() {
    let mut registry = ObjectRegistry::<8>::new();
    let events = EventAuthority::<1>::new();
    let waits = WaitRegistry::<1>::new();
    let (_event, handle_ref) = events.create_event(&mut registry).unwrap();
    let wait_pin = registry.retain_internal_from_handle(&handle_ref).unwrap();
    let scheduler = CooperativeScheduler::<2>::new();
    let (thread, wake) = blocked_key(&mut registry, &scheduler);
    let registration = waits
        .register(wait_pin, DW_SIGNAL_SIGNALED, 0, thread, wake)
        .unwrap();

    assert!(registry.release_handle(handle_ref).unwrap().is_none());
    let pin = waits.cancel(registration).unwrap();
    let final_release = registry.release_internal(pin).unwrap().unwrap();
    let finalization = events.take_finalization(final_release).unwrap();
    complete_event_finalization(&mut registry, finalization);
}

#[test]
fn exhausted_empty_registration_slot_is_skipped_without_wedging_capacity() {
    let mut registry = ObjectRegistry::<8>::new();
    let events = EventAuthority::<1>::new();
    let waits = WaitRegistry::<2>::new();
    waits.slots.lock()[0].generation = u32::MAX;
    let (_event, handle_ref) = events.create_event(&mut registry).unwrap();
    let wait_pin = registry.retain_internal_from_handle(&handle_ref).unwrap();
    let scheduler = CooperativeScheduler::<2>::new();
    let (thread, wake) = blocked_key(&mut registry, &scheduler);

    let registration = waits
        .register(wait_pin, DW_SIGNAL_SIGNALED, 0, thread, wake)
        .unwrap();
    assert_eq!(registration.slot, 1);
    let pin = waits.cancel(registration).unwrap();
    assert!(registry.release_internal(pin).unwrap().is_none());
    let final_release = registry.release_handle(handle_ref).unwrap().unwrap();
    let finalization = events.take_finalization(final_release).unwrap();
    complete_event_finalization(&mut registry, finalization);
}

#[test]
fn event_mask_validation_is_exact_and_idempotent() {
    assert_eq!(
        validate_event_signal_masks(DwSignals(0), DwSignals(0)),
        Err(WaitError::InvalidSignals)
    );
    assert_eq!(
        validate_event_signal_masks(DW_SIGNAL_SIGNALED, DW_SIGNAL_SIGNALED),
        Err(WaitError::InvalidSignals)
    );
    assert_eq!(
        validate_event_signal_masks(DW_SIGNAL_READABLE, DwSignals(0)),
        Err(WaitError::InvalidSignals)
    );
    assert!(validate_event_signal_masks(DwSignals(0), DW_SIGNAL_SIGNALED).is_ok());
    assert!(validate_event_signal_masks(DW_SIGNAL_SIGNALED, DwSignals(0)).is_ok());
}

#[test]
fn wait_signal_validation_uses_generated_object_compatibility() {
    assert_eq!(
        validate_wait_signals(DW_OBJECT_TYPE_EVENT, DwSignals(0)),
        Err(WaitError::InvalidSignals)
    );
    assert_eq!(
        validate_wait_signals(DW_OBJECT_TYPE_EVENT, DW_SIGNAL_READABLE),
        Err(WaitError::InvalidSignals)
    );
    assert!(validate_wait_signals(DW_OBJECT_TYPE_EVENT, DW_SIGNAL_SIGNALED).is_ok());
}

#[test]
fn handle_resolution_enforces_wait_signal_rights_and_object_type() {
    let mut registry = ObjectRegistry::<8>::new();
    let events = EventAuthority::<1>::new();
    let (_event, event_ref) = events.create_event(&mut registry).unwrap();
    let mut table = HandleTable::<3>::new();
    let signal_only = table.install(event_ref, DW_RIGHT_SIGNAL).unwrap();
    assert_eq!(
        table
            .lookup(
                &mut registry,
                signal_only,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
                DW_RIGHT_WAIT,
            )
            .unwrap_err(),
        crate::handle::HandleTableError::AccessDenied
    );
    let signal_target = table
        .lookup(
            &mut registry,
            signal_only,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_SIGNAL,
        )
        .unwrap();
    let scheduler = CooperativeScheduler::<2>::new();
    let (thread, wake) = blocked_key(&mut registry, &scheduler);
    let waits = WaitRegistry::<1>::new();
    let failure =
        match events.register_wait(&waits, signal_target, DW_SIGNAL_SIGNALED, 0, thread, wake) {
            Ok(_) => panic!("Event wait accepted a handle without WAIT rights"),
            Err(failure) => failure,
        };
    assert_eq!(failure.error, WaitError::AccessDenied);
    assert!(registry.release_internal(failure.pin).unwrap().is_none());

    let memory = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let memory_ref = registry.creation_into_handle(memory).unwrap();
    let memory_handle = table
        .install(
            memory_ref,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        )
        .unwrap();
    assert_eq!(
        table
            .lookup(
                &mut registry,
                memory_handle,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
                DW_RIGHT_SIGNAL,
            )
            .unwrap_err(),
        crate::handle::HandleTableError::WrongObjectType
    );
    let event_final = table.close(&mut registry, signal_only).unwrap().unwrap();
    let event_finalization = events.take_finalization(event_final).unwrap();
    complete_event_finalization(&mut registry, event_finalization);
    let memory_final = table.close(&mut registry, memory_handle).unwrap().unwrap();
    registry.complete_finalization(memory_final).unwrap();
}

#[test]
fn process_and_thread_exited_signals_are_observed_from_task_authority() {
    let mut registry = ObjectRegistry::<12>::new();
    let events = EventAuthority::<1>::new();
    let timers = crate::time::TimerAuthority::<1>::new();
    let channels = crate::ipc::ChannelAuthority::<1, 2>::new();
    let mut tasks = TaskAuthority::<1, 1, 1, 2>::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (thread, thread_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());

    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let thread_owner = registry
        .retain_internal_from_handle(&thread_handle)
        .unwrap();
    let process_target = crate::handle::resolve_test_internal_owner(
        &mut registry,
        &process_owner,
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_PROCESS),
    );
    let thread_target = crate::handle::resolve_test_internal_owner(
        &mut registry,
        &thread_owner,
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_THREAD),
    );
    assert_eq!(
        current_signals_for(&tasks, &events, &timers, &channels, &process_target).unwrap(),
        DwSignals(0)
    );
    assert_eq!(
        current_signals_for(&tasks, &events, &timers, &channels, &thread_target).unwrap(),
        DwSignals(0)
    );

    let exit_pins = tasks.terminate_thread_authorized(thread, 0x44).unwrap();
    assert_eq!(
        current_signals_for(&tasks, &events, &timers, &channels, &process_target).unwrap(),
        DW_SIGNAL_EXITED
    );
    assert_eq!(
        current_signals_for(&tasks, &events, &timers, &channels, &thread_target).unwrap(),
        DW_SIGNAL_EXITED
    );
    assert_eq!(process_target.object_id(), process.object_id());

    for pin in [
        process_target.into_internal(),
        thread_target.into_internal(),
    ] {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let (process_pin, thread_pins, resources) = exit_pins.into_parts();
    assert!(resources.into_iter().flatten().next().is_none());
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(thread_owner).unwrap().is_none());
}

#[test]
fn signal_wins_once_per_block_generation_and_consumes_sibling_registrations() {
    let mut registry = ObjectRegistry::<12>::new();
    let events = EventAuthority::<2>::new();
    let waits = WaitRegistry::<4>::new();
    let (first_event, first_ref) = events.create_event(&mut registry).unwrap();
    let (_second_event, second_ref) = events.create_event(&mut registry).unwrap();
    let mut table = HandleTable::<2>::new();
    let rights = deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT);
    let first_handle = table.install(first_ref, rights).unwrap();
    let second_handle = table.install(second_ref, rights).unwrap();

    let scheduler = CooperativeScheduler::<2>::new();
    let (thread, block_wake) = blocked_key(&mut registry, &scheduler);
    let first = table
        .lookup(
            &mut registry,
            first_handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    let second = table
        .lookup(
            &mut registry,
            second_handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    let _first_registration = match events
        .register_wait(&waits, first, DW_SIGNAL_SIGNALED, 5, thread, block_wake)
        .unwrap()
    {
        EventWaitOutcome::Registered(registration) => registration,
        EventWaitOutcome::Ready { .. } => panic!("unsignaled Event unexpectedly ready"),
    };
    let _second_registration = match events
        .register_wait(&waits, second, DW_SIGNAL_SIGNALED, 1, thread, block_wake)
        .unwrap()
    {
        EventWaitOutcome::Registered(registration) => registration,
        EventWaitOutcome::Ready { .. } => panic!("unsignaled Event unexpectedly ready"),
    };
    assert_eq!(waits.len(), 2);

    let batch = events
        .signal(first_event, DwSignals(0), DW_SIGNAL_SIGNALED, &waits)
        .unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.pin_len(), 2);
    assert_eq!(waits.len(), 0);
    let (wakes, pins) = batch.into_parts();
    let wake_intents: [Option<WakeIntent>; 4] = wakes;
    let wake = wake_intents.into_iter().flatten().next().unwrap();
    assert_eq!(wake.wake_key(), block_wake);
    assert_eq!(wake.observed(), DW_SIGNAL_SIGNALED);
    assert_eq!(wake.item_index(), 5);
    scheduler.wake(wake.wake_key()).unwrap();
    for pin in pins.into_iter().flatten() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }

    for handle in [first_handle, second_handle] {
        let final_release = table.close(&mut registry, handle).unwrap().unwrap();
        let finalization = events.take_finalization(final_release).unwrap();
        complete_event_finalization(&mut registry, finalization);
    }
}

#[test]
fn cancelling_block_generation_removes_all_siblings_without_wake() {
    let mut registry = ObjectRegistry::<8>::new();
    let events = EventAuthority::<1>::new();
    let waits = WaitRegistry::<4>::new();
    let (_event, handle_ref) = events.create_event(&mut registry).unwrap();
    let mut table = HandleTable::<1>::new();
    let handle = table
        .install(
            handle_ref,
            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
        )
        .unwrap();
    let scheduler = CooperativeScheduler::<2>::new();
    let (thread, wake) = blocked_key(&mut registry, &scheduler);
    for item_index in 0..2 {
        let target = table
            .lookup(
                &mut registry,
                handle,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
                DW_RIGHT_WAIT,
            )
            .unwrap();
        assert!(matches!(
            events
                .register_wait(&waits, target, DW_SIGNAL_SIGNALED, item_index, thread, wake,)
                .unwrap(),
            EventWaitOutcome::Registered(_)
        ));
    }
    assert_eq!(waits.len(), 2);
    let cancelled = waits.cancel_generation(wake);
    assert_eq!(cancelled.len(), 0);
    assert_eq!(cancelled.pin_len(), 2);
    assert_eq!(waits.len(), 0);
    let (_, pins) = cancelled.into_parts();
    for pin in pins.into_iter().flatten() {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let final_release = table.close(&mut registry, handle).unwrap().unwrap();
    complete_event_finalization(
        &mut registry,
        events.take_finalization(final_release).unwrap(),
    );
}
