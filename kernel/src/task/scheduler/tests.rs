extern crate std;

use super::*;
use crate::object::ObjectRegistry;
use deepwyrm_abi::DW_OBJECT_TYPE_THREAD;
use std::sync::Arc;
use std::thread;

fn thread_key(seed_registry: &mut ObjectRegistry<16>) -> ThreadKey {
    let creation = seed_registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
    let key = ThreadKey::from_object_id(creation.id());
    seed_registry.cancel_creation(creation).unwrap();
    key
}

#[test]
fn reservation_is_not_runnable_until_commit() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);

    let reservation = scheduler.reserve(thread).unwrap();
    assert_eq!(
        scheduler.state(thread),
        Some(SchedulerThreadState::Reserved)
    );
    assert_eq!(scheduler.schedule_next().unwrap().current, None);
    scheduler.commit(reservation).unwrap();
    assert_eq!(
        scheduler.state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(scheduler.schedule_next().unwrap().current, Some(thread));
    assert_eq!(scheduler.state(thread), Some(SchedulerThreadState::Running));
}

#[test]
fn fifo_yield_and_retire_keep_states_disjoint() {
    let scheduler = CooperativeScheduler::<4>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let a = thread_key(&mut registry);
    let b = thread_key(&mut registry);
    let c = thread_key(&mut registry);
    for key in [a, b, c] {
        let reservation = scheduler.reserve(key).unwrap();
        scheduler.commit(reservation).unwrap();
    }

    assert_eq!(scheduler.schedule_next().unwrap().current, Some(a));
    assert_eq!(scheduler.yield_current(a).unwrap().current, Some(b));
    assert_eq!(scheduler.state(a), Some(SchedulerThreadState::Runnable));
    assert_eq!(scheduler.state(b), Some(SchedulerThreadState::Running));
    assert_eq!(scheduler.retire(c).unwrap().current, Some(b));
    assert_eq!(scheduler.state(c), None);
    assert_eq!(scheduler.retire(b).unwrap().current, Some(a));
    assert_eq!(scheduler.current(), Some(a));
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn duplicate_capacity_and_foreign_reservations_fail_closed() {
    let first = CooperativeScheduler::<1>::new();
    let second = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let a = thread_key(&mut registry);
    let b = thread_key(&mut registry);

    let reservation = first.reserve(a).unwrap();
    assert_eq!(
        first.reserve(a).unwrap_err(),
        SchedulerError::DuplicateThread
    );
    assert_eq!(first.reserve(b).unwrap_err(), SchedulerError::Capacity);
    let failure = second.commit(reservation).unwrap_err();
    assert_eq!(failure.error(), SchedulerError::ForeignReservation);
    let reservation = failure.into_reservation();
    first.cancel(reservation).unwrap();

    let replacement = first.reserve(b).unwrap();
    first.cancel(replacement).unwrap();
    let replacement = first.reserve(a).unwrap();
    first.cancel(replacement).unwrap();
    assert_eq!(first.check_invariants(), Ok(()));
}

#[test]
fn cancelled_reservation_releases_capacity() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let a = thread_key(&mut registry);
    let b = thread_key(&mut registry);
    let reservation = scheduler.reserve(a).unwrap();
    scheduler.cancel(reservation).unwrap();
    assert_eq!(scheduler.state(a), None);
    let reservation = scheduler.reserve(b).unwrap();
    scheduler.commit(reservation).unwrap();
    assert_eq!(scheduler.state(b), Some(SchedulerThreadState::Runnable));
}

#[test]
fn concurrent_distinct_reservations_preserve_scheduler_invariants() {
    let scheduler = Arc::new(CooperativeScheduler::<4>::new());
    let mut registry = ObjectRegistry::<16>::new();
    let keys = core::array::from_fn::<_, 4, _>(|_| thread_key(&mut registry));
    let mut workers = std::vec::Vec::new();
    for key in keys {
        let scheduler = Arc::clone(&scheduler);
        workers.push(thread::spawn(move || {
            let reservation = scheduler.reserve(key).unwrap();
            scheduler.commit(reservation).unwrap();
        }));
    }
    for worker in workers {
        worker.join().expect("scheduler worker completes");
    }
    for key in keys {
        assert_eq!(scheduler.state(key), Some(SchedulerThreadState::Runnable));
    }
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn block_wake_generation_is_exact_and_fifo_is_preserved() {
    let scheduler = CooperativeScheduler::<3>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let a = thread_key(&mut registry);
    let b = thread_key(&mut registry);
    let c = thread_key(&mut registry);
    for key in [a, b, c] {
        let reservation = scheduler.reserve(key).unwrap();
        scheduler.commit(reservation).unwrap();
    }
    assert_eq!(scheduler.schedule_next().unwrap().current, Some(a));
    let (blocked, decision) = scheduler.block_current(a).unwrap();
    assert_eq!(decision.previous, Some(a));
    assert_eq!(decision.current, Some(b));
    assert_eq!(scheduler.state(a), Some(SchedulerThreadState::Blocked));
    let wake = blocked.wake_key();
    scheduler.wake(wake).unwrap();
    assert_eq!(scheduler.state(a), Some(SchedulerThreadState::Runnable));
    assert_eq!(scheduler.wake(wake), Err(SchedulerError::StaleBlockToken));
    assert_eq!(scheduler.yield_current(b).unwrap().current, Some(c));
    assert_eq!(scheduler.yield_current(c).unwrap().current, Some(a));
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn blocked_thread_can_be_retired_and_stale_wake_cannot_revive_it() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    let reservation = scheduler.reserve(thread).unwrap();
    scheduler.commit(reservation).unwrap();
    scheduler.schedule_next().unwrap();
    let (blocked, decision) = scheduler.block_current(thread).unwrap();
    assert_eq!(decision.current, None);
    let wake = blocked.into_wake_key();
    assert_eq!(scheduler.retire(thread).unwrap().current, None);
    assert_eq!(scheduler.state(thread), None);
    assert_eq!(scheduler.wake(wake), Err(SchedulerError::StaleBlockToken));
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn foreign_and_competing_wakes_fail_closed() {
    let first = Arc::new(CooperativeScheduler::<1>::new());
    let second = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    let reservation = first.reserve(thread).unwrap();
    first.commit(reservation).unwrap();
    first.schedule_next().unwrap();
    let (blocked, _) = first.block_current(thread).unwrap();
    let wake = blocked.into_wake_key();
    assert_eq!(second.wake(wake), Err(SchedulerError::ForeignBlockToken));

    let a = Arc::clone(&first);
    let b = Arc::clone(&first);
    let left = thread::spawn(move || a.wake(wake));
    let right = thread::spawn(move || b.wake(wake));
    let results = [left.join().unwrap(), right.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(SchedulerError::StaleBlockToken))
            .count(),
        1
    );
    assert_eq!(first.schedule_next().unwrap().current, Some(thread));
}
