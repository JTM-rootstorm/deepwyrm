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
