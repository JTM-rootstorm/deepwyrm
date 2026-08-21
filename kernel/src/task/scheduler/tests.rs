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

#[test]
fn prepared_block_keeps_thread_running_until_commit_and_cancel_is_exact() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    let reservation = scheduler.reserve(thread).unwrap();
    scheduler.commit(reservation).unwrap();
    assert_eq!(scheduler.schedule_next().unwrap().current, Some(thread));

    let block = scheduler.prepare_block_current(thread).unwrap();
    let wake = block.wake_key();
    assert_eq!(scheduler.state(thread), Some(SchedulerThreadState::Running));
    assert!(matches!(
        scheduler.prepare_block_current(thread),
        Err(SchedulerError::BlockPreparationActive)
    ));
    scheduler.cancel_block(block).unwrap();
    assert_eq!(scheduler.state(thread), Some(SchedulerThreadState::Running));
    assert_eq!(scheduler.wake(wake), Err(SchedulerError::StaleBlockToken));

    let block = scheduler.prepare_block_current(thread).unwrap();
    let wake = block.wake_key();
    let decision = scheduler.commit_block(block).unwrap();
    assert_eq!(decision.previous, Some(thread));
    assert_eq!(scheduler.state(thread), Some(SchedulerThreadState::Blocked));
    scheduler.wake(wake).unwrap();
    assert_eq!(
        scheduler.state(thread),
        Some(SchedulerThreadState::Runnable)
    );
}

#[test]
fn pending_block_preparation_is_retired_with_running_thread() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    let reservation = scheduler.reserve(thread).unwrap();
    scheduler.commit(reservation).unwrap();
    scheduler.schedule_next().unwrap();
    let block = scheduler.prepare_block_current(thread).unwrap();
    let wake = block.wake_key();
    let decision = scheduler.retire(thread).unwrap();
    assert_eq!(decision.previous, Some(thread));
    assert_eq!(decision.current, None);
    assert_eq!(scheduler.state(thread), None);
    assert_eq!(scheduler.wake(wake), Err(SchedulerError::StaleBlockToken));
}

#[test]
fn idle_scheduler_continues_then_resumes_exact_woken_waiter() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let waiter = thread_key(&mut registry);
    let reservation = scheduler.reserve(waiter).unwrap();
    scheduler.commit(reservation).unwrap();
    scheduler.schedule_next().unwrap();
    let (blocked, decision) = scheduler.block_current(waiter).unwrap();
    assert_eq!(decision.current, None);
    assert_eq!(
        scheduler.schedule_from_idle(waiter).unwrap(),
        IdleScheduleDecision::ContinueIdle
    );
    scheduler.wake(blocked.into_wake_key()).unwrap();
    assert_eq!(
        scheduler.schedule_from_idle(waiter).unwrap(),
        IdleScheduleDecision::ResumeCurrent
    );
    assert_eq!(scheduler.state(waiter), Some(SchedulerThreadState::Running));
}

#[test]
fn idle_scheduler_preserves_fifo_when_other_work_wakes_first() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let suspended = thread_key(&mut registry);
    for thread in [first, suspended] {
        let reservation = scheduler.reserve(thread).unwrap();
        scheduler.commit(reservation).unwrap();
    }
    scheduler.schedule_next().unwrap();
    let (first_block, decision) = scheduler.block_current(first).unwrap();
    assert_eq!(decision.current, Some(suspended));
    let (suspended_block, decision) = scheduler.block_current(suspended).unwrap();
    assert_eq!(decision.current, None);

    // Wake the first Thread before the physically-active suspended waiter.
    scheduler.wake(first_block.into_wake_key()).unwrap();
    assert_eq!(
        scheduler.schedule_from_idle(suspended).unwrap(),
        IdleScheduleDecision::Switch(ScheduleDecision {
            previous: Some(suspended),
            current: Some(first),
        })
    );
    assert_eq!(scheduler.state(first), Some(SchedulerThreadState::Running));
    assert_eq!(
        scheduler.state(suspended),
        Some(SchedulerThreadState::Blocked)
    );
    // Keep the token live in the model: it remains the exact later wake.
    assert!(suspended_block.wake_key().token != 0);
}

#[test]
fn dw0_f11_fixed_seed_scheduler_transaction_trace_preserves_queue_exclusivity() {
    const SEED: u64 = 0xd0f1_1000_u64;
    const CYCLES: usize = 6;

    macro_rules! assert_trace_model {
        ($scheduler:expr, $threads:expr, $expected:expr, $current:expr, $step:expr, $operation:expr) => {{
            assert_eq!(
                $scheduler.check_invariants(),
                Ok(()),
                "DW0-F11 seed={SEED:#x} step={} operation={}",
                $step,
                $operation,
            );
            assert_eq!(
                $scheduler.current(),
                $current,
                "DW0-F11 seed={SEED:#x} step={} operation={}",
                $step,
                $operation,
            );
            let expected_running = $expected
                .iter()
                .filter(|state| **state == Some(SchedulerThreadState::Running))
                .count();
            assert_eq!(
                expected_running,
                usize::from($current.is_some()),
                "DW0-F11 seed={SEED:#x} step={} operation={}",
                $step,
                $operation,
            );
            for (thread, expected_state) in $threads.iter().zip($expected.iter()) {
                assert_eq!(
                    $scheduler.state(*thread),
                    *expected_state,
                    "DW0-F11 seed={SEED:#x} step={} operation={} thread={thread:?}",
                    $step,
                    $operation,
                );
            }
        }};
    }

    let scheduler = CooperativeScheduler::<3>::new();
    let foreign_scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let threads = core::array::from_fn::<_, 3, _>(|_| thread_key(&mut registry));
    let foreign_thread = thread_key(&mut registry);
    let foreign_reservation = foreign_scheduler.reserve(foreign_thread).unwrap();
    foreign_scheduler.commit(foreign_reservation).unwrap();
    assert_eq!(
        foreign_scheduler.schedule_next().unwrap().current,
        Some(foreign_thread)
    );
    let (foreign_block, _) = foreign_scheduler.block_current(foreign_thread).unwrap();
    let foreign_wake = foreign_block.into_wake_key();

    let mut state = SEED;
    let mut step = 0;
    let mut covered = [false; 10];
    for _ in 0..CYCLES {
        // This deliberately small PRNG changes the participants each cycle while
        // retaining a replayable, bounded transition sequence.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let first = (state as usize) % threads.len();
        let second = (first + 1 + ((state >> 8) as usize % (threads.len() - 1))) % threads.len();
        let cancelled = 3 - first - second;
        let first_thread = threads[first];
        let second_thread = threads[second];
        let cancelled_thread = threads[cancelled];
        let mut expected = [None; 3];

        let cancelled_reservation = scheduler.reserve(cancelled_thread).unwrap();
        expected[cancelled] = Some(SchedulerThreadState::Reserved);
        covered[0] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            None::<ThreadKey>,
            step,
            "reserve-cancelled"
        );
        step += 1;

        scheduler.cancel(cancelled_reservation).unwrap();
        expected[cancelled] = None;
        covered[1] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            None::<ThreadKey>,
            step,
            "cancel-reservation"
        );
        step += 1;

        let first_reservation = scheduler.reserve(first_thread).unwrap();
        expected[first] = Some(SchedulerThreadState::Reserved);
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            None::<ThreadKey>,
            step,
            "reserve-first"
        );
        step += 1;

        scheduler.commit(first_reservation).unwrap();
        expected[first] = Some(SchedulerThreadState::Runnable);
        covered[0] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            None::<ThreadKey>,
            step,
            "commit-first"
        );
        step += 1;

        let second_reservation = scheduler.reserve(second_thread).unwrap();
        expected[second] = Some(SchedulerThreadState::Reserved);
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            None::<ThreadKey>,
            step,
            "reserve-second"
        );
        step += 1;

        scheduler.commit(second_reservation).unwrap();
        expected[second] = Some(SchedulerThreadState::Runnable);
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            None::<ThreadKey>,
            step,
            "commit-second"
        );
        step += 1;

        assert_eq!(
            scheduler.schedule_next().unwrap(),
            ScheduleDecision {
                previous: None,
                current: Some(first_thread),
            },
            "DW0-F11 seed={SEED:#x} step={step} operation=schedule"
        );
        expected[first] = Some(SchedulerThreadState::Running);
        covered[2] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(first_thread),
            step,
            "schedule"
        );
        step += 1;

        assert_eq!(
            scheduler.yield_current(first_thread).unwrap(),
            ScheduleDecision {
                previous: Some(first_thread),
                current: Some(second_thread),
            },
            "DW0-F11 seed={SEED:#x} step={step} operation=yield"
        );
        expected[first] = Some(SchedulerThreadState::Runnable);
        expected[second] = Some(SchedulerThreadState::Running);
        covered[3] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(second_thread),
            step,
            "yield"
        );
        step += 1;

        let cancelled_block = scheduler.prepare_block_current(second_thread).unwrap();
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(second_thread),
            step,
            "prepare-cancelled-block"
        );
        step += 1;

        scheduler.cancel_block(cancelled_block).unwrap();
        covered[4] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(second_thread),
            step,
            "cancel-block"
        );
        step += 1;

        let block = scheduler.prepare_block_current(second_thread).unwrap();
        let wake = block.wake_key();
        covered[4] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(second_thread),
            step,
            "prepare-block"
        );
        step += 1;

        assert_eq!(
            scheduler.commit_block(block).unwrap(),
            ScheduleDecision {
                previous: Some(second_thread),
                current: Some(first_thread),
            },
            "DW0-F11 seed={SEED:#x} step={step} operation=commit-block"
        );
        expected[first] = Some(SchedulerThreadState::Running);
        expected[second] = Some(SchedulerThreadState::Blocked);
        covered[5] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(first_thread),
            step,
            "commit-block"
        );
        step += 1;

        scheduler.wake(wake).unwrap();
        expected[second] = Some(SchedulerThreadState::Runnable);
        covered[6] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(first_thread),
            step,
            "exact-wake"
        );
        step += 1;

        assert_eq!(
            scheduler.wake(wake),
            Err(SchedulerError::StaleBlockToken),
            "DW0-F11 seed={SEED:#x} step={step} operation=stale-wake"
        );
        covered[7] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(first_thread),
            step,
            "stale-wake"
        );
        step += 1;

        assert_eq!(
            scheduler.wake(foreign_wake),
            Err(SchedulerError::ForeignBlockToken),
            "DW0-F11 seed={SEED:#x} step={step} operation=foreign-wake"
        );
        covered[8] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(first_thread),
            step,
            "foreign-wake"
        );
        step += 1;

        assert_eq!(
            scheduler.retire(second_thread).unwrap(),
            ScheduleDecision {
                previous: Some(first_thread),
                current: Some(first_thread),
            },
            "DW0-F11 seed={SEED:#x} step={step} operation=retire-runnable"
        );
        expected[second] = None;
        covered[9] = true;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            Some(first_thread),
            step,
            "retire-runnable"
        );
        step += 1;

        assert_eq!(
            scheduler.retire(first_thread).unwrap(),
            ScheduleDecision {
                previous: Some(first_thread),
                current: None,
            },
            "DW0-F11 seed={SEED:#x} step={step} operation=retire-running"
        );
        expected[first] = None;
        assert_trace_model!(
            scheduler,
            threads,
            expected,
            None::<ThreadKey>,
            step,
            "retire-running"
        );
        step += 1;
    }

    assert!(
        covered.into_iter().all(core::convert::identity),
        "DW0-F11 seed={SEED:#x} did not cover every scheduler transaction"
    );
}
