extern crate std;

use super::*;
use crate::object::ObjectRegistry;
use deepwyrm_abi::DW_OBJECT_TYPE_THREAD;
use std::sync::{Arc, Barrier};
use std::thread;

fn thread_key(seed_registry: &mut ObjectRegistry<16>) -> ThreadKey {
    let creation = seed_registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
    let key = ThreadKey::from_object_id(creation.id());
    seed_registry.cancel_creation(creation).unwrap();
    key
}

fn cpu(index: usize) -> SchedulerCpuId {
    SchedulerCpuId::new(index).expect("test CPU is inside the H2 bound")
}

#[test]
fn four_competing_cpus_claim_distinct_fifo_work_once() {
    let scheduler = Arc::new(CooperativeScheduler::<8>::new());
    let mut registry = ObjectRegistry::<16>::new();
    let keys = core::array::from_fn::<_, 8, _>(|_| thread_key(&mut registry));
    for key in keys {
        let reservation = scheduler.reserve(key).unwrap();
        scheduler.commit(reservation).unwrap();
    }

    let start = Arc::new(Barrier::new(H2_SCHEDULER_CPU_CAPACITY + 1));
    let mut workers = std::vec::Vec::new();
    for cpu_index in 0..H2_SCHEDULER_CPU_CAPACITY {
        let scheduler = Arc::clone(&scheduler);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            start.wait();
            (
                cpu_index,
                scheduler.schedule_next_on(cpu(cpu_index)).unwrap(),
            )
        }));
    }
    start.wait();

    let mut claimed = std::vec::Vec::new();
    for worker in workers {
        let (cpu_index, decision) = worker.join().expect("CPU claim worker completes");
        let current = decision.current.expect("each CPU claims queued work");
        assert!(
            !claimed.contains(&current),
            "a Thread was claimed by two CPUs"
        );
        claimed.push(current);
        assert_eq!(scheduler.current_on(cpu(cpu_index)), Some(current));
        assert_eq!(scheduler.running_cpu(current), Some(cpu(cpu_index)));
        let claim = scheduler
            .running_claim_on(cpu(cpu_index))
            .expect("Running ownership has an exact execution claim");
        assert_eq!(claim.thread(), current);
        assert_eq!(claim.cpu(), cpu(cpu_index));
        assert_ne!(claim.generation(), 0);
    }
    assert_eq!(claimed.len(), H2_SCHEDULER_CPU_CAPACITY);
    assert!(
        claimed
            .iter()
            .all(|thread| keys[..H2_SCHEDULER_CPU_CAPACITY].contains(thread))
    );
    for key in &keys[H2_SCHEDULER_CPU_CAPACITY..] {
        assert_eq!(scheduler.state(*key), Some(SchedulerThreadState::Runnable));
    }
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn one_cpu_and_one_thread_cannot_be_claimed_twice() {
    let scheduler = Arc::new(CooperativeScheduler::<2>::new());
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for key in [first, second] {
        let reservation = scheduler.reserve(key).unwrap();
        scheduler.commit(reservation).unwrap();
    }

    let start = Arc::new(Barrier::new(3));
    let mut workers = std::vec::Vec::new();
    for _ in 0..2 {
        let scheduler = Arc::clone(&scheduler);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            start.wait();
            scheduler.schedule_next_on(cpu(2))
        }));
    }
    start.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("same-CPU claimant completes"))
        .collect::<std::vec::Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(SchedulerError::CurrentThreadRunning))
            .count(),
        1
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn queued_and_running_threads_reject_duplicate_reservation() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let queued = thread_key(&mut registry);
    let running = thread_key(&mut registry);

    scheduler
        .commit(scheduler.reserve(queued).unwrap())
        .unwrap();
    assert_eq!(
        scheduler.reserve(queued).unwrap_err(),
        SchedulerError::DuplicateThread
    );
    scheduler
        .commit(scheduler.reserve(running).unwrap())
        .unwrap();
    assert_eq!(scheduler.schedule_next().unwrap().current, Some(queued));
    assert_eq!(
        scheduler.reserve(queued).unwrap_err(),
        SchedulerError::DuplicateThread
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn checked_accounting_freezes_overflow_and_rejects_bad_gauges_and_time() {
    let mut counters = SchedulerCounters {
        context_switches: u64::MAX,
        ..SchedulerCounters::default()
    };
    assert_eq!(
        counters.increment(SchedulerEvent::ContextSwitch),
        Err(SchedulerError::AccountingOverflow)
    );
    assert_eq!(counters.context_switches, u64::MAX);
    assert!(counters.overflow_fault);

    let mut gauge = SchedulerCounters::default();
    assert_eq!(
        gauge.decrement_runnable(),
        Err(SchedulerError::AccountingUnderflow)
    );
    assert_eq!(gauge.current_runnable, 0);
    gauge.current_runnable = u64::MAX;
    assert_eq!(
        gauge.increment_runnable(),
        Err(SchedulerError::AccountingOverflow)
    );
    assert_eq!(gauge.current_runnable, u64::MAX);

    let mut time = SchedulerCounters {
        idle_time_ns: u64::MAX - 2,
        ..SchedulerCounters::default()
    };
    assert_eq!(
        time.record_idle_time(3),
        Err(SchedulerError::AccountingOverflow)
    );
    assert_eq!(time.idle_time_ns, u64::MAX - 2);
    assert_eq!(
        time.observe_ready_delay(20, 19),
        Err(SchedulerError::TimeRegression)
    );
    assert_eq!(time.longest_ready_delay_ns, 0);
    time.observe_ready_delay(20, 27).unwrap();
    time.observe_ready_delay(25, 29).unwrap();
    assert_eq!(time.longest_ready_delay_ns, 7);
}

#[test]
fn dw1c_final_snapshot_is_one_lock_fresh_and_uses_maximum_cpu_ready_delay() {
    let scheduler = CooperativeScheduler::<4>::new();
    {
        let mut state = scheduler.state.lock();
        for (cpu, delay) in [7, 31, 19, 23].into_iter().enumerate() {
            state.accounting.cpu[cpu].longest_ready_delay_ns = delay;
        }
    }

    let first = scheduler.dw1c_final_snapshot().unwrap();
    assert_eq!(first.token(), 1);
    assert_eq!(first.generation(), 1);
    assert_eq!(first.max_ready_delay_ns(), 31);
    assert_eq!(first.accounting_mask(), 0x3f);
    let second = scheduler.dw1c_final_snapshot().unwrap();
    assert_eq!(second.token(), 2);
    assert_eq!(second.generation(), 2);

    let rollover = CooperativeScheduler::<1>::new();
    {
        let mut state = rollover.state.lock();
        state.next_final_snapshot_token = u64::MAX;
        state.next_final_snapshot_generation = 9;
    }
    assert_eq!(
        rollover.dw1c_final_snapshot(),
        Err(SchedulerError::TokenExhausted)
    );
    let state = rollover.state.lock();
    assert_eq!(state.next_final_snapshot_token, u64::MAX);
    assert_eq!(state.next_final_snapshot_generation, 9);
}

#[test]
fn dw1c_final_snapshot_rejects_sticky_accounting_and_time_faults() {
    let mut registry = ObjectRegistry::<16>::new();
    let scheduler = CooperativeScheduler::<1>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(thread).unwrap())
        .unwrap();
    {
        let mut state = scheduler.state.lock();
        state.accounting.cpu[0].current_runnable = 0;
    }
    assert_eq!(
        scheduler.retire(thread),
        Err(SchedulerError::AccountingUnderflow)
    );
    {
        let mut state = scheduler.state.lock();
        state.accounting.cpu[0].current_runnable = 1;
    }
    assert_eq!(
        scheduler.dw1c_final_snapshot(),
        Err(SchedulerError::AccountingUnderflow)
    );

    let time = CooperativeScheduler::<1>::new();
    time.observe_instrumentation_time_on(cpu(0), 10).unwrap();
    assert_eq!(
        time.observe_instrumentation_time_on(cpu(0), 9),
        Err(SchedulerError::TimeRegression)
    );
    assert_eq!(
        time.dw1c_final_snapshot(),
        Err(SchedulerError::TimeRegression)
    );

    let overflow = CooperativeScheduler::<1>::new();
    overflow.state.lock().accounting.cpu[0].overflow_fault = true;
    assert_eq!(
        overflow.dw1c_final_snapshot(),
        Err(SchedulerError::AccountingOverflow)
    );

    let inconsistent_gauge = CooperativeScheduler::<1>::new();
    inconsistent_gauge.state.lock().accounting.cpu[0].current_runnable = 1;
    assert_eq!(
        inconsistent_gauge.dw1c_final_snapshot(),
        Err(SchedulerError::AccountingUnderflow)
    );
}

#[test]
fn dw1c_final_snapshot_rejects_duplicate_and_terminal_scheduler_ownership() {
    let mut registry = ObjectRegistry::<16>::new();

    let duplicate_running = CooperativeScheduler::<2>::new();
    let running = thread_key(&mut registry);
    let claim = RunningClaim {
        thread: running,
        generation: 1,
    };
    {
        let mut state = duplicate_running.state.lock();
        state.running[0] = Some(claim);
        state.running[1] = Some(claim);
    }
    assert_eq!(
        duplicate_running.dw1c_final_snapshot(),
        Err(SchedulerError::DuplicateThread)
    );

    let running_and_queued = CooperativeScheduler::<2>::new();
    let both = thread_key(&mut registry);
    running_and_queued
        .commit(running_and_queued.reserve(both).unwrap())
        .unwrap();
    running_and_queued.state.lock().running[0] = Some(RunningClaim {
        thread: both,
        generation: 1,
    });
    assert_eq!(
        running_and_queued.dw1c_final_snapshot(),
        Err(SchedulerError::DuplicateThread)
    );

    let duplicate_queue = CooperativeScheduler::<2>::new();
    let queued = thread_key(&mut registry);
    duplicate_queue
        .commit(duplicate_queue.reserve(queued).unwrap())
        .unwrap();
    {
        let mut state = duplicate_queue.state.lock();
        state.queue[1] = state.queue[0];
        state.len = 2;
        state.accounting.cpu[0].current_runnable = 2;
    }
    assert_eq!(
        duplicate_queue.dw1c_final_snapshot(),
        Err(SchedulerError::DuplicateThread)
    );

    let terminal = CooperativeScheduler::<1>::new();
    let retired = thread_key(&mut registry);
    terminal.commit(terminal.reserve(retired).unwrap()).unwrap();
    terminal.state.lock().terminal_retired[0] = Some(retired);
    assert_eq!(
        terminal.dw1c_final_snapshot(),
        Err(SchedulerError::StaleExecutionClaim)
    );

    let terminal_suspended = CooperativeScheduler::<1>::new();
    let suspended = thread_key(&mut registry);
    {
        let mut state = terminal_suspended.state.lock();
        state.suspended[0] = Some(SuspendedContinuation {
            thread: suspended,
            generation: 1,
            publication: SuspendedPublication::Retired,
            involuntary_preemption: false,
        });
        state.terminal_retired[0] = Some(suspended);
    }
    assert_eq!(
        terminal_suspended.dw1c_final_snapshot(),
        Err(SchedulerError::StaleExecutionClaim)
    );
}

#[test]
fn accounting_failure_cannot_grant_running_ownership() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(thread).unwrap())
        .unwrap();
    {
        let mut state = scheduler.state.lock();
        state.accounting.cpu[1].context_switches = u64::MAX;
    }

    assert_eq!(
        scheduler.schedule_next_on(cpu(1)),
        Err(SchedulerError::AccountingOverflow)
    );
    assert_eq!(scheduler.current_on(cpu(1)), None);
    assert_eq!(
        scheduler.state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    let counters = scheduler.counters_on(cpu(1));
    assert_eq!(counters.context_switches, u64::MAX);
    assert!(counters.overflow_fault);
    assert_eq!(
        scheduler.check_invariants(),
        Err(SchedulerError::AccountingOverflow)
    );
    assert_eq!(
        scheduler.schedule_next_on(cpu(1)),
        Err(SchedulerError::AccountingOverflow)
    );
    assert_eq!(scheduler.current_on(cpu(1)), None);
}

#[test]
#[should_panic(expected = "scheduler invariant failed: AccountingUnderflow")]
fn invariant_reconciliation_is_fail_stop_in_all_build_modes() {
    let scheduler = CooperativeScheduler::<1>::new();
    scheduler.state.lock().accounting.cpu[0].current_runnable = 1;

    scheduler
        .observe_instrumentation_time_on(cpu(0), 1)
        .unwrap();
}

#[test]
fn idle_accounting_begins_only_after_publication_and_resume_is_not_a_switch() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let waiter = thread_key(&mut registry);

    scheduler
        .observe_instrumentation_time_on(cpu(0), 10)
        .unwrap();
    scheduler
        .commit(scheduler.reserve(waiter).unwrap())
        .unwrap();
    scheduler
        .observe_instrumentation_time_on(cpu(1), 20)
        .unwrap();
    scheduler.schedule_next_on(cpu(1)).unwrap();
    scheduler
        .observe_instrumentation_time_on(cpu(1), 30)
        .unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(1), waiter).unwrap();
    assert_eq!(decision.current, None);

    scheduler
        .observe_instrumentation_time_on(cpu(1), 40)
        .unwrap();
    assert_eq!(
        scheduler.schedule_from_idle_on(cpu(1), waiter),
        Ok(IdleScheduleDecision::ContinueIdle)
    );
    let before_publication = scheduler.counters_on(cpu(1));
    assert_eq!(before_publication.idle_entries, 0);
    assert_eq!(before_publication.idle_time_ns, 0);

    let idle = scheduler.publish_idle_on(cpu(1), 41).unwrap();
    assert_eq!(scheduler.counters_on(cpu(1)).idle_entries, 1);
    assert_eq!(
        scheduler.publish_idle_on(cpu(1), 42),
        Err(SchedulerError::IdleAccountingActive)
    );
    assert_eq!(
        scheduler.finish_idle_on(idle, 40),
        Err(SchedulerError::TimeRegression)
    );
    scheduler.finish_idle_on(idle, 51).unwrap();
    assert_eq!(
        scheduler.finish_idle_on(idle, 52),
        Err(SchedulerError::StaleIdleAccounting)
    );

    scheduler
        .observe_instrumentation_time_on(cpu(1), 60)
        .unwrap();
    scheduler.wake(blocked.into_wake_key()).unwrap();
    let switches_before_resume = scheduler.counters_on(cpu(1)).context_switches;
    scheduler
        .observe_instrumentation_time_on(cpu(1), 70)
        .unwrap();
    assert_eq!(
        scheduler.schedule_from_idle_on(cpu(1), waiter),
        Ok(IdleScheduleDecision::ResumeCurrent)
    );
    let counters = scheduler.counters_on(cpu(1));
    assert_eq!(counters.context_switches, switches_before_resume);
    assert_eq!(counters.idle_entries, 1);
    assert_eq!(counters.idle_time_ns, 10);
    assert_eq!(counters.longest_ready_delay_ns, 10);

    let (records, _, len) = scheduler.trace_snapshot();
    assert!(len >= 2);
    let mut idle_records = [None; 2];
    let mut idle_count = 0;
    for record in records.iter().flatten().filter(|record| {
        matches!(
            record.kind,
            SchedulerTraceKind::IdleBegin | SchedulerTraceKind::IdleEnd
        )
    }) {
        idle_records[idle_count] = Some(*record);
        idle_count += 1;
    }
    assert_eq!(idle_count, 2);
    let idle_begin = idle_records[0].unwrap();
    let idle_end = idle_records[1].unwrap();
    assert_ne!(idle_begin.generation, 0);
    assert_eq!(idle_begin.generation, idle_end.generation);
    assert_eq!(idle_begin.at_ns, 41);
    assert_eq!(idle_end.at_ns, 51);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn reordered_per_cpu_samples_preserve_idle_and_ready_delay_attribution() {
    let scheduler = CooperativeScheduler::<1>::new();
    let cpu0_idle = scheduler.publish_idle_on(cpu(0), 100).unwrap();
    let cpu1_idle = scheduler.publish_idle_on(cpu(1), 110).unwrap();

    scheduler.finish_idle_on(cpu0_idle, 105).unwrap();
    scheduler
        .observe_instrumentation_time_on(cpu(0), 106)
        .unwrap();
    scheduler.finish_idle_on(cpu1_idle, 115).unwrap();
    scheduler
        .observe_instrumentation_time_on(cpu(1), 116)
        .unwrap();
    assert_eq!(scheduler.counters_on(cpu(0)).idle_time_ns, 5);
    assert_eq!(scheduler.counters_on(cpu(1)).idle_time_ns, 5);
    assert_eq!(
        scheduler.observe_instrumentation_time_on(cpu(0), 104),
        Err(SchedulerError::TimeRegression)
    );

    let ready_scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let ready = thread_key(&mut registry);
    ready_scheduler
        .observe_instrumentation_time_on(cpu(0), 200)
        .unwrap();
    ready_scheduler
        .commit(ready_scheduler.reserve(ready).unwrap())
        .unwrap();
    ready_scheduler
        .observe_instrumentation_time_on(cpu(1), 199)
        .unwrap();
    assert_eq!(
        ready_scheduler.schedule_next_on(cpu(1)).unwrap().current,
        Some(ready)
    );
    assert_eq!(
        ready_scheduler.counters_on(cpu(1)).longest_ready_delay_ns,
        0
    );
    assert_eq!(ready_scheduler.counters_on(cpu(0)).current_runnable, 0);
    assert_eq!(ready_scheduler.check_invariants(), Ok(()));

    let same_cpu_scheduler = CooperativeScheduler::<1>::new();
    let same_cpu_ready = thread_key(&mut registry);
    same_cpu_scheduler
        .observe_instrumentation_time_on(cpu(0), 300)
        .unwrap();
    same_cpu_scheduler
        .commit(same_cpu_scheduler.reserve(same_cpu_ready).unwrap())
        .unwrap();
    {
        let mut state = same_cpu_scheduler.state.lock();
        state.instrumentation_now_ns[0] = Some(299);
        state.instrumentation_global_now_ns = Some(299);
    }
    assert_eq!(
        same_cpu_scheduler.schedule_next_on(cpu(0)),
        Err(SchedulerError::TimeRegression)
    );
    assert_eq!(
        same_cpu_scheduler.state(same_cpu_ready),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(same_cpu_scheduler.current_on(cpu(0)), None);
    assert_eq!(same_cpu_scheduler.counters_on(cpu(0)).current_runnable, 1);
    assert_eq!(same_cpu_scheduler.check_invariants(), Ok(()));
}

#[test]
fn trace_ring_is_fixed_capacity_and_every_record_is_generation_bound() {
    let scheduler = CooperativeScheduler::<1>::new();
    for generation in 0..(SCHEDULER_TRACE_CAPACITY + 8) {
        let start = (generation as u64) * 2;
        let idle = scheduler.publish_idle_on(cpu(2), start).unwrap();
        scheduler.finish_idle_on(idle, start + 1).unwrap();
    }
    let (records, _, len) = scheduler.trace_snapshot();
    assert_eq!(len, SCHEDULER_TRACE_CAPACITY);
    assert_eq!(records.iter().flatten().count(), SCHEDULER_TRACE_CAPACITY);
    assert!(
        records
            .iter()
            .flatten()
            .all(|record| record.generation != 0)
    );
}

#[test]
fn suspended_retire_generation_exhaustion_is_atomic_then_retryable() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let suspended = thread_key(&mut registry);
    let replacement = thread_key(&mut registry);

    scheduler
        .commit(scheduler.reserve(suspended).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(1)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(1), suspended).unwrap();
    assert_eq!(decision.current, None);
    scheduler.wake(blocked.into_wake_key()).unwrap();
    scheduler
        .commit_on(cpu(1), scheduler.reserve(replacement).unwrap())
        .unwrap();
    let before_cpu0 = scheduler.counters_on(cpu(0));
    let before_cpu1 = scheduler.counters_on(cpu(1));
    let suspended_claim = scheduler.suspended_claim_on(cpu(1)).unwrap();
    {
        let mut state = scheduler.state.lock();
        state.next_execution_generation = u64::MAX;
    }

    assert_eq!(
        scheduler.retire_on(cpu(1), suspended),
        Err(SchedulerError::TokenExhausted)
    );
    assert_eq!(
        scheduler.state(suspended),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(
        scheduler.state(replacement),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(scheduler.suspended_claim_on(cpu(1)), Some(suspended_claim));
    assert_eq!(scheduler.current_on(cpu(1)), None);
    assert_eq!(scheduler.counters_on(cpu(0)), before_cpu0);
    assert_eq!(scheduler.counters_on(cpu(1)), before_cpu1);
    assert_eq!(scheduler.check_invariants(), Ok(()));

    {
        let mut state = scheduler.state.lock();
        state.next_execution_generation = 100;
    }
    assert_eq!(
        scheduler.retire_on(cpu(1), suspended).unwrap().current,
        Some(replacement)
    );
    assert_eq!(scheduler.state(suspended), None);
    assert_eq!(scheduler.current_on(cpu(1)), Some(replacement));
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn remote_and_suspended_stop_accounting_preserves_exact_ownership() {
    let mut registry = ObjectRegistry::<16>::new();

    let running_scheduler = CooperativeScheduler::<1>::new();
    let running = thread_key(&mut registry);
    running_scheduler
        .commit(running_scheduler.reserve(running).unwrap())
        .unwrap();
    running_scheduler.schedule_next_on(cpu(1)).unwrap();
    let running_claim = running_scheduler.running_claim_on(cpu(1)).unwrap();
    running_scheduler
        .stop_running_claim_on(running_claim)
        .unwrap();
    assert_eq!(running_scheduler.current_on(cpu(1)), None);
    assert_eq!(running_scheduler.counters_on(cpu(1)).context_switches, 2);
    assert_eq!(running_scheduler.check_invariants(), Ok(()));

    let suspended_scheduler = CooperativeScheduler::<1>::new();
    let suspended = thread_key(&mut registry);
    suspended_scheduler
        .commit(suspended_scheduler.reserve(suspended).unwrap())
        .unwrap();
    suspended_scheduler.schedule_next_on(cpu(1)).unwrap();
    let (blocked, _) = suspended_scheduler
        .block_current_on(cpu(1), suspended)
        .unwrap();
    let suspended_claim = suspended_scheduler.suspended_claim_on(cpu(1)).unwrap();
    suspended_scheduler.wake(blocked.into_wake_key()).unwrap();
    suspended_scheduler
        .stop_suspended_claim_on(suspended_claim)
        .unwrap();
    assert_eq!(suspended_scheduler.state(suspended), None);
    let counters = suspended_scheduler.counters_on(cpu(1));
    assert_eq!(counters.current_runnable, 0);
    assert_eq!(counters.context_switches, 2);
    assert_eq!(suspended_scheduler.check_invariants(), Ok(()));
}

#[test]
fn cooperative_transitions_update_exact_cpu_accounting() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for thread in [first, second] {
        scheduler
            .commit_on(cpu(1), scheduler.reserve(thread).unwrap())
            .unwrap();
    }
    assert_eq!(scheduler.counters_on(cpu(1)).current_runnable, 2);

    scheduler.schedule_next_on(cpu(1)).unwrap();
    let first_claim = scheduler.running_claim_on(cpu(1)).unwrap();
    scheduler.yield_current_on(cpu(1), first).unwrap();
    scheduler.complete_switch_on(first_claim).unwrap();
    let second_claim = scheduler.running_claim_on(cpu(1)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(1), second).unwrap();
    assert_eq!(decision.current, Some(first));
    scheduler.wake(blocked.into_wake_key()).unwrap();
    scheduler.complete_switch_on(second_claim).unwrap();
    scheduler.retire_on(cpu(1), second).unwrap();
    scheduler.retire_on(cpu(1), first).unwrap();

    let bootstrap = scheduler.counters_on(cpu(0));
    assert_eq!(bootstrap.current_runnable, 0);
    let worker = scheduler.counters_on(cpu(1));
    assert_eq!(worker.current_runnable, 0);
    assert_eq!(worker.context_switches, 4);
    assert_eq!(worker.voluntary_yields, 1);
    assert_eq!(worker.voluntary_blocks, 1);
    assert_eq!(worker.wakeups, 1);
    assert!(!worker.overflow_fault);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn pending_blocks_are_cpu_local_and_reject_the_wrong_cpu() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for key in [first, second] {
        let reservation = scheduler.reserve(key).unwrap();
        scheduler.commit(reservation).unwrap();
    }
    scheduler.schedule_next_on(cpu(0)).unwrap();
    scheduler.schedule_next_on(cpu(1)).unwrap();
    let first_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    let second_claim = scheduler.running_claim_on(cpu(1)).unwrap();

    assert!(matches!(
        scheduler.prepare_block_current_on(cpu(1), first),
        Err(SchedulerError::WrongCpu)
    ));
    let first_block = scheduler.prepare_block_current_on(cpu(0), first).unwrap();
    let second_block = scheduler.prepare_block_current_on(cpu(1), second).unwrap();
    assert_eq!(
        first_block.wake_key().execution_generation,
        first_claim.generation()
    );
    assert_eq!(
        second_block.wake_key().execution_generation,
        second_claim.generation()
    );
    assert_eq!(
        scheduler.yield_current_on(cpu(0), first),
        Err(SchedulerError::BlockPreparationActive)
    );
    scheduler.cancel_block_on(cpu(0), first_block).unwrap();
    scheduler.cancel_block_on(cpu(1), second_block).unwrap();
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1b_quantum_identity_rejects_stale_replaced_and_cross_cpu_events() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let running = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(running).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(0)).unwrap();

    let first = scheduler.prepare_quantum_on(cpu(0), 10).unwrap();
    assert_eq!(first.deadline_ns(), 10 + DEFAULT_NORMAL_QUANTUM_NS);
    let replacement = scheduler.prepare_quantum_on(cpu(0), 20).unwrap();
    assert_ne!(
        first.source_arm_generation(),
        replacement.source_arm_generation()
    );
    assert_eq!(scheduler.publish_quantum_expiry(first), Ok(false));
    assert!(!scheduler.has_reschedule_request_on(cpu(0)));
    assert_eq!(scheduler.publish_quantum_expiry(replacement), Ok(true));
    assert!(scheduler.has_reschedule_request_on(cpu(0)));
    assert_eq!(scheduler.publish_quantum_expiry(replacement), Ok(false));
    assert_eq!(
        scheduler.prepare_quantum_on(cpu(1), 30),
        Err(SchedulerError::NotRunning)
    );
    assert_eq!(scheduler.counters_on(cpu(0)).quantum_expirations, 1);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c2_four_cpu_quantum_sources_arm_expire_cancel_and_rearm_independently() {
    let scheduler = CooperativeScheduler::<8>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let running = core::array::from_fn::<_, 4, _>(|cpu_index| {
        let thread = thread_key(&mut registry);
        scheduler
            .commit(scheduler.reserve(thread).unwrap())
            .unwrap();
        scheduler.schedule_next_on(cpu(cpu_index)).unwrap();
        thread
    });

    let first = core::array::from_fn::<_, 4, _>(|cpu_index| {
        scheduler
            .prepare_quantum_on(cpu(cpu_index), 100 + cpu_index as u64)
            .unwrap()
    });
    for (cpu_index, ticket) in first.into_iter().enumerate() {
        assert_eq!(ticket.cpu(), cpu(cpu_index));
        assert_eq!(ticket.source_arm_generation(), 1);
        assert_eq!(scheduler.publish_quantum_expiry(ticket), Ok(true));
        for other in 0..4 {
            assert_eq!(
                scheduler.has_reschedule_request_on(cpu(other)),
                other <= cpu_index
            );
        }
    }
    let replacements = core::array::from_fn::<_, 4, _>(|cpu_index| {
        assert_eq!(scheduler.counters_on(cpu(cpu_index)).quantum_expirations, 1);
        assert_eq!(
            scheduler.preempt_current_on(cpu(cpu_index)),
            Ok(SchedulerPreemptionDecision::RetainCurrent)
        );
        let replacement = scheduler
            .prepare_quantum_on(cpu(cpu_index), 1_000 + cpu_index as u64)
            .unwrap();
        assert_eq!(replacement.source_arm_generation(), 2);
        assert_eq!(
            scheduler.publish_quantum_expiry(first[cpu_index]),
            Ok(false)
        );
        assert_eq!(
            scheduler.preemption_snapshot_on(cpu(cpu_index)).quantum,
            Some(replacement)
        );
        replacement
    });

    for cpu_index in 0..4 {
        let peer = thread_key(&mut registry);
        scheduler
            .commit_on(cpu(cpu_index), scheduler.reserve(peer).unwrap())
            .unwrap();
    }
    for cpu_index in 0..4 {
        let decision = scheduler
            .yield_current_on(cpu(cpu_index), running[cpu_index])
            .unwrap();
        assert_eq!(decision.cancelled_quantum, Some(replacements[cpu_index]));
        assert_ne!(decision.current, Some(running[cpu_index]));
        scheduler
            .complete_switch_on(scheduler.suspended_claim_on(cpu(cpu_index)).unwrap())
            .unwrap();
        let rearmed = scheduler
            .prepare_quantum_if_needed_on(cpu(cpu_index), 10_000 + cpu_index as u64)
            .unwrap()
            .expect("replacement execution receives an independent fresh source");
        assert_eq!(rearmed.source_arm_generation(), 3);
        assert_eq!(
            scheduler.publish_quantum_expiry(replacements[cpu_index]),
            Ok(false)
        );
        assert_eq!(
            scheduler.preemption_snapshot_on(cpu(cpu_index)).quantum,
            Some(rearmed)
        );
    }
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c2_cross_cpu_ticket_identity_cannot_mutate_another_local_source() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    for cpu_index in 0..2 {
        let thread = thread_key(&mut registry);
        scheduler
            .commit(scheduler.reserve(thread).unwrap())
            .unwrap();
        scheduler.schedule_next_on(cpu(cpu_index)).unwrap();
    }
    let cpu0 = scheduler.prepare_quantum_on(cpu(0), 10).unwrap();
    let cpu1 = scheduler.prepare_quantum_on(cpu(1), 10).unwrap();
    assert_eq!(cpu0.source_arm_generation(), cpu1.source_arm_generation());

    let forged = SchedulerQuantumTicket {
        cpu: cpu(1),
        ..cpu0
    };
    assert_eq!(scheduler.publish_quantum_expiry(forged), Ok(false));
    assert_eq!(scheduler.preemption_snapshot_on(cpu(0)).quantum, Some(cpu0));
    assert_eq!(scheduler.preemption_snapshot_on(cpu(1)).quantum, Some(cpu1));
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1b_repeated_syscall_returns_preserve_budget_until_exact_expiry() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for thread in [first, second] {
        scheduler
            .commit(scheduler.reserve(thread).unwrap())
            .unwrap();
    }
    scheduler.schedule_next_on(cpu(0)).unwrap();

    let ticket = scheduler
        .prepare_quantum_if_needed_on(cpu(0), 100)
        .unwrap()
        .expect("initial CPL3 entry mints a budget");
    for syscall_return_ns in [101, 1_000, 1_000_000, ticket.deadline_ns() - 1] {
        assert_eq!(
            scheduler
                .prepare_quantum_if_needed_on(cpu(0), syscall_return_ns)
                .unwrap(),
            None,
            "a syscall return must preserve the running execution's exact budget"
        );
        assert_eq!(
            scheduler.preemption_snapshot_on(cpu(0)).quantum,
            Some(ticket)
        );
    }

    assert_eq!(scheduler.publish_quantum_expiry(ticket), Ok(true));
    assert_eq!(
        scheduler.prepare_quantum_if_needed_on(cpu(0), ticket.deadline_ns()),
        Err(SchedulerError::QuantumUnavailable),
        "a due request must survive return preparation"
    );
    let outgoing = scheduler.running_claim_on(cpu(0)).unwrap();
    assert!(matches!(
        scheduler.preempt_current_on(cpu(0)),
        Ok(SchedulerPreemptionDecision::Switch {
            decision: ScheduleDecision {
                previous: Some(previous),
                current: Some(current),
                cancelled_quantum: None,
            },
            outgoing: switched,
        }) if previous == first && current == second && switched == outgoing
    ));
    scheduler.complete_switch_on(outgoing).unwrap();

    let next = scheduler
        .prepare_quantum_if_needed_on(cpu(0), ticket.deadline_ns())
        .unwrap()
        .expect("the dispatched peer receives a new budget");
    assert_eq!(next.thread(), second);
    assert_ne!(next.source_arm_generation(), ticket.source_arm_generation());
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1b_no_peer_yield_preserves_budget_until_due_retain_consumes_it() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let running = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(running).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(0)).unwrap();
    let ticket = scheduler
        .prepare_quantum_if_needed_on(cpu(0), 100)
        .unwrap()
        .unwrap();

    assert_eq!(
        scheduler.yield_current_on(cpu(0), running).unwrap(),
        ScheduleDecision {
            previous: Some(running),
            current: Some(running),
            cancelled_quantum: None,
        }
    );
    assert_eq!(
        scheduler.preemption_snapshot_on(cpu(0)).quantum,
        Some(ticket)
    );

    assert_eq!(scheduler.publish_quantum_expiry(ticket), Ok(true));
    scheduler.yield_current_on(cpu(0), running).unwrap();
    assert_eq!(
        scheduler.preemption_snapshot_on(cpu(0)).request,
        Some(ticket),
        "a no-peer yield cannot erase an already-due exact request"
    );
    assert_eq!(
        scheduler.preempt_current_on(cpu(0)),
        Ok(SchedulerPreemptionDecision::RetainCurrent)
    );
    assert!(
        scheduler
            .prepare_quantum_if_needed_on(cpu(0), ticket.deadline_ns())
            .unwrap()
            .is_some(),
        "only due no-peer retention renews this running execution"
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1b_matching_expiry_rotates_fifo_and_retains_exact_continuation() {
    let scheduler = CooperativeScheduler::<3>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    let third = thread_key(&mut registry);
    for thread in [first, second, third] {
        scheduler
            .commit(scheduler.reserve(thread).unwrap())
            .unwrap();
    }
    assert_eq!(
        scheduler.schedule_next_on(cpu(0)).unwrap().current,
        Some(first)
    );
    let ticket = scheduler.prepare_quantum_on(cpu(0), 100).unwrap();
    assert_eq!(scheduler.publish_quantum_expiry(ticket), Ok(true));
    let outgoing = scheduler.running_claim_on(cpu(0)).unwrap();
    let decision = scheduler.preempt_current_on(cpu(0)).unwrap();
    assert_eq!(
        decision,
        SchedulerPreemptionDecision::Switch {
            decision: ScheduleDecision {
                previous: Some(first),
                current: Some(second),
                cancelled_quantum: None,
            },
            outgoing,
        }
    );
    assert_eq!(scheduler.suspended_claim_on(cpu(0)), Some(outgoing));
    assert_eq!(scheduler.current_on(cpu(0)), Some(second));
    assert_eq!(scheduler.counters_on(cpu(0)).involuntary_preemptions, 0);
    scheduler.complete_switch_on(outgoing).unwrap();
    assert_eq!(scheduler.counters_on(cpu(0)).involuntary_preemptions, 1);
    scheduler.yield_current_on(cpu(0), second).unwrap();
    assert_eq!(scheduler.current_on(cpu(0)), Some(third));
    let counters = scheduler.counters_on(cpu(0));
    assert_eq!(counters.quantum_expirations, 1);
    assert_eq!(counters.involuntary_preemptions, 1);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1b_no_peer_consumes_request_without_manufacturing_switch() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let running = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(running).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(0)).unwrap();
    let switches = scheduler.counters_on(cpu(0)).context_switches;
    let ticket = scheduler.prepare_quantum_on(cpu(0), 1).unwrap();
    scheduler.publish_quantum_expiry(ticket).unwrap();
    assert_eq!(
        scheduler.preempt_current_on(cpu(0)),
        Ok(SchedulerPreemptionDecision::RetainCurrent)
    );
    assert!(!scheduler.has_reschedule_request_on(cpu(0)));
    assert_eq!(scheduler.current_on(cpu(0)), Some(running));
    assert_eq!(scheduler.counters_on(cpu(0)).context_switches, switches);
    assert_eq!(scheduler.counters_on(cpu(0)).involuntary_preemptions, 0);
    assert!(scheduler.prepare_quantum_on(cpu(0), 2).is_ok());
}

#[test]
fn dw1b_checked_preemption_depth_defers_exact_request() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let running = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(running).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(0)).unwrap();
    scheduler.preemption_disable_on(cpu(0)).unwrap();
    let ticket = scheduler.prepare_quantum_on(cpu(0), 1).unwrap();
    scheduler.publish_quantum_expiry(ticket).unwrap();
    assert_eq!(
        scheduler.preempt_current_on(cpu(0)),
        Ok(SchedulerPreemptionDecision::Deferred)
    );
    assert!(scheduler.preemption_enable_on(cpu(0)).unwrap());
    assert_eq!(
        scheduler.preemption_enable_on(cpu(0)),
        Err(SchedulerError::PreemptionDepthUnderflow)
    );
}

#[test]
fn dw1b_block_commit_and_terminal_retirement_win_over_pending_expiry() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for thread in [first, second] {
        scheduler
            .commit(scheduler.reserve(thread).unwrap())
            .unwrap();
    }
    scheduler.schedule_next_on(cpu(0)).unwrap();
    let first_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    let ticket = scheduler.prepare_quantum_on(cpu(0), 1).unwrap();
    scheduler.publish_quantum_expiry(ticket).unwrap();
    let block = scheduler.prepare_block_current_on(cpu(0), first).unwrap();
    assert_eq!(
        scheduler.preempt_current_on(cpu(0)),
        Ok(SchedulerPreemptionDecision::Deferred)
    );
    let decision = scheduler.commit_block_on(cpu(0), block).unwrap();
    assert_eq!(decision.current, Some(second));
    assert!(!scheduler.has_reschedule_request_on(cpu(0)));
    assert_eq!(scheduler.publish_quantum_expiry(ticket), Ok(false));
    scheduler.complete_switch_on(first_claim).unwrap();

    let second_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    let ticket = scheduler.prepare_quantum_on(cpu(0), 2).unwrap();
    scheduler.publish_quantum_expiry(ticket).unwrap();
    assert_eq!(scheduler.retire_on(cpu(0), second).unwrap().current, None);
    assert!(!scheduler.has_reschedule_request_on(cpu(0)));
    assert_eq!(scheduler.publish_quantum_expiry(ticket), Ok(false));
    scheduler.complete_switch_on(second_claim).unwrap();
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1b_preemption_snapshot_is_exact_and_kernel_private() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let running = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(running).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(0)).unwrap();
    let claim = scheduler.running_claim_on(cpu(0));
    let ticket = scheduler.prepare_quantum_on(cpu(0), 10).unwrap();
    let armed = scheduler.preemption_snapshot_on(cpu(0));
    assert_eq!(armed.running, claim);
    assert_eq!(armed.quantum, Some(ticket));
    assert_eq!(armed.request, None);
    assert_eq!(armed.preemption_disable_depth, 0);

    scheduler.preemption_disable_on(cpu(0)).unwrap();
    scheduler.publish_quantum_expiry(ticket).unwrap();
    let expired = scheduler.preemption_snapshot_on(cpu(0));
    assert_eq!(expired.running, claim);
    assert_eq!(expired.quantum, None);
    assert_eq!(expired.request, Some(ticket));
    assert_eq!(expired.preemption_disable_depth, 1);
    assert_eq!(expired.counters.quantum_expirations, 1);
    assert_eq!(expired.counters.involuntary_preemptions, 0);
}

#[test]
fn suspended_waiter_is_not_migratable_until_release_acquire_handoff() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let waiter = thread_key(&mut registry);
    let reservation = scheduler.reserve(waiter).unwrap();
    scheduler.commit(reservation).unwrap();
    scheduler.schedule_next_on(cpu(0)).unwrap();
    let active_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(0), waiter).unwrap();
    assert_eq!(decision.current, None);
    assert_eq!(scheduler.suspended_on(cpu(0)), Some(waiter));
    assert_eq!(scheduler.suspended_claim_on(cpu(0)), Some(active_claim));

    scheduler.wake(blocked.into_wake_key()).unwrap();
    assert_eq!(scheduler.schedule_next_on(cpu(1)).unwrap().current, None);
    assert_eq!(scheduler.running_cpu(waiter), None);
    assert_eq!(
        scheduler.schedule_from_idle_on(cpu(0), waiter).unwrap(),
        IdleScheduleDecision::ResumeCurrent
    );
    assert_eq!(scheduler.running_cpu(waiter), Some(cpu(0)));
    assert_eq!(scheduler.running_claim_on(cpu(0)), Some(active_claim));
    assert_eq!(scheduler.suspended_on(cpu(0)), None);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn completed_switch_makes_outgoing_continuation_claimable_by_an_idle_cpu() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let outgoing = thread_key(&mut registry);
    let destination = thread_key(&mut registry);
    for key in [outgoing, destination] {
        let reservation = scheduler.reserve(key).unwrap();
        scheduler.commit_on(cpu(0), reservation).unwrap();
    }
    scheduler.schedule_next_on(cpu(0)).unwrap();
    let outgoing_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    let decision = scheduler.yield_current_on(cpu(0), outgoing).unwrap();
    assert_eq!(decision.current, Some(destination));
    assert_eq!(scheduler.suspended_on(cpu(0)), Some(outgoing));
    assert_eq!(scheduler.suspended_claim_on(cpu(0)), Some(outgoing_claim));
    assert_eq!(scheduler.schedule_next_on(cpu(1)).unwrap().current, None);

    // Models the post-assembly Release edge. The CPU-1 claim acquires the same
    // scheduler lock before it can observe the continuation as eligible.
    scheduler.complete_switch_on(outgoing_claim).unwrap();
    assert_eq!(
        scheduler.schedule_next_on(cpu(1)).unwrap().current,
        Some(outgoing)
    );
    assert_eq!(scheduler.running_cpu(outgoing), Some(cpu(1)));
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn stale_same_thread_same_cpu_switch_completion_cannot_clear_a_later_claim() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for key in [first, second] {
        let reservation = scheduler.reserve(key).unwrap();
        scheduler.commit(reservation).unwrap();
    }

    scheduler.schedule_next_on(cpu(0)).unwrap();
    let first_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    scheduler.yield_current_on(cpu(0), first).unwrap();
    assert_eq!(scheduler.suspended_claim_on(cpu(0)), Some(first_claim));
    scheduler.complete_switch_on(first_claim).unwrap();

    let second_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    scheduler.yield_current_on(cpu(0), second).unwrap();
    scheduler.complete_switch_on(second_claim).unwrap();

    let later_first_claim = scheduler.running_claim_on(cpu(0)).unwrap();
    assert_eq!(later_first_claim.thread(), first);
    assert_eq!(later_first_claim.cpu(), first_claim.cpu());
    assert_ne!(later_first_claim.generation(), first_claim.generation());
    scheduler.yield_current_on(cpu(0), first).unwrap();
    assert_eq!(
        scheduler.complete_switch_on(first_claim),
        Err(SchedulerError::StaleExecutionClaim)
    );
    assert_eq!(
        scheduler.suspended_claim_on(cpu(0)),
        Some(later_first_claim)
    );
    scheduler.complete_switch_on(later_first_claim).unwrap();
    assert_eq!(scheduler.check_invariants(), Ok(()));
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

    let ticket = scheduler.prepare_quantum_on(cpu(0), 10).unwrap();
    let block = scheduler.prepare_block_current(thread).unwrap();
    let wake = block.wake_key();
    let decision = scheduler.commit_block(block).unwrap();
    assert_eq!(decision.previous, Some(thread));
    assert_eq!(decision.cancelled_quantum, Some(ticket));
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
    let ticket = scheduler.prepare_quantum_on(cpu(0), 20).unwrap();
    let block = scheduler.prepare_block_current(thread).unwrap();
    let wake = block.wake_key();
    let decision = scheduler.retire(thread).unwrap();
    assert_eq!(decision.previous, Some(thread));
    assert_eq!(decision.current, None);
    assert_eq!(decision.cancelled_quantum, Some(ticket));
    assert_eq!(scheduler.state(thread), None);
    assert_eq!(scheduler.wake(wake), Err(SchedulerError::StaleBlockToken));
}

#[test]
fn remote_stop_removes_only_the_exact_running_claim_without_replacement() {
    let scheduler = CooperativeScheduler::<4>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let stopped = thread_key(&mut registry);
    let runnable = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(stopped).unwrap())
        .unwrap();
    scheduler
        .commit(scheduler.reserve(runnable).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(1)).unwrap();
    let claim = scheduler.running_claim_on(cpu(1)).unwrap();
    assert_eq!(claim.thread(), stopped);
    let ticket = scheduler.prepare_quantum_on(cpu(1), 30).unwrap();

    assert_eq!(scheduler.stop_running_claim_on(claim), Ok(Some(ticket)));
    assert_eq!(scheduler.current_on(cpu(1)), None);
    assert_eq!(scheduler.running_cpu(stopped), None);
    assert_eq!(scheduler.suspended_claim_on(cpu(1)), Some(claim));
    assert_eq!(scheduler.state(stopped), None);
    assert_eq!(
        scheduler.state(runnable),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(
        scheduler.stop_running_claim_on(claim),
        Err(SchedulerError::StaleExecutionClaim)
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn remote_stop_continuation_clears_the_retired_slot_before_replacement_schedule() {
    let scheduler = CooperativeScheduler::<4>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let stopped = thread_key(&mut registry);
    let runnable = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(stopped).unwrap())
        .unwrap();
    scheduler
        .commit(scheduler.reserve(runnable).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(1)).unwrap();
    let claim = scheduler.running_claim_on(cpu(1)).unwrap();

    scheduler.stop_running_claim_on(claim).unwrap();
    assert_eq!(
        scheduler.schedule_next_on(cpu(1)),
        Err(SchedulerError::SwitchPending)
    );
    // This is the post-ACK carrier-only action: it abandons the stopped
    // continuation without reintroducing its Running claim or reclaiming it.
    scheduler.complete_switch_on(claim).unwrap();
    assert_eq!(scheduler.suspended_claim_on(cpu(1)), None);
    assert_eq!(
        scheduler.schedule_next_on(cpu(1)).unwrap().current,
        Some(runnable)
    );
    assert_eq!(scheduler.running_cpu(stopped), None);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn remote_stop_after_block_retires_only_the_exact_suspended_generation() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let stopped = thread_key(&mut registry);
    scheduler
        .commit(scheduler.reserve(stopped).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(1)).unwrap();
    let (_block, _decision) = scheduler.block_current_on(cpu(1), stopped).unwrap();
    let claim = scheduler.suspended_claim_on(cpu(1)).unwrap();

    scheduler.stop_suspended_claim_on(claim).unwrap();
    assert_eq!(scheduler.suspended_claim_on(cpu(1)), Some(claim));
    assert_eq!(scheduler.state(stopped), None);
    assert_eq!(
        scheduler.stop_suspended_claim_on(claim),
        Err(SchedulerError::StaleExecutionClaim)
    );
    scheduler.complete_switch_on(claim).unwrap();
    assert_eq!(scheduler.suspended_claim_on(cpu(1)), None);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn h4_remote_wake_and_terminal_retirement_never_revive_the_thread() {
    let mut registry = ObjectRegistry::<16>::new();
    for iteration in 0..2_000 {
        let scheduler = Arc::new(CooperativeScheduler::<1>::new());
        let thread_key = thread_key(&mut registry);
        let reservation = scheduler.reserve(thread_key).unwrap();
        scheduler.commit(reservation).unwrap();
        scheduler.schedule_next_on(cpu(1)).unwrap();
        let (blocked, decision) = scheduler.block_current_on(cpu(1), thread_key).unwrap();
        assert_eq!(decision.current, None);
        let wake = blocked.into_wake_key();
        let suspended = scheduler.suspended_claim_on(cpu(1)).unwrap();
        let start = Arc::new(Barrier::new(3));

        let wake_scheduler = Arc::clone(&scheduler);
        let wake_start = Arc::clone(&start);
        let wake_worker = thread::spawn(move || {
            wake_start.wait();
            wake_scheduler.wake(wake)
        });
        let terminal_scheduler = Arc::clone(&scheduler);
        let terminal_start = Arc::clone(&start);
        let terminal_worker = thread::spawn(move || {
            terminal_start.wait();
            terminal_scheduler.retire_on(cpu(1), thread_key)
        });
        start.wait();

        let wake_result = wake_worker.join().unwrap();
        let terminal_result = terminal_worker.join().unwrap();
        assert!(
            matches!(wake_result, Ok(()) | Err(SchedulerError::StaleBlockToken)),
            "iteration={iteration} wake={wake_result:?}"
        );
        assert!(
            terminal_result.is_ok(),
            "iteration={iteration} terminal={terminal_result:?}"
        );
        assert_eq!(scheduler.state(thread_key), None, "iteration={iteration}");
        assert_eq!(
            scheduler.wake(wake),
            Err(SchedulerError::StaleBlockToken),
            "iteration={iteration}"
        );
        scheduler.complete_switch_on(suspended).unwrap();
        assert_eq!(scheduler.check_invariants(), Ok(()));
    }
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
fn wake_reports_exact_continuation_owner_until_switch_completion() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let blocked_thread = thread_key(&mut registry);
    let destination = thread_key(&mut registry);
    for thread in [blocked_thread, destination] {
        let reservation = scheduler.reserve(thread).unwrap();
        scheduler.commit_on(cpu(2), reservation).unwrap();
    }
    scheduler.schedule_next_on(cpu(2)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(2), blocked_thread).unwrap();
    assert_eq!(decision.current, Some(destination));
    let suspended = scheduler.suspended_claim_on(cpu(2)).unwrap();

    assert_eq!(
        scheduler
            .wake_with_affinity(blocked.into_wake_key())
            .unwrap(),
        Some(cpu(2))
    );
    assert_eq!(scheduler.schedule_next_on(cpu(3)).unwrap().current, None);
    assert_eq!(
        scheduler
            .complete_switch_on_with_runnable_publication(suspended)
            .unwrap()
            .runnable_publication()
            .expect("released Runnable reports its exact queue target")
            .target(),
        cpu(2)
    );
    assert_eq!(
        scheduler.schedule_next_on(cpu(3)).unwrap().current,
        Some(blocked_thread)
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn completed_switch_generation_is_exact_and_stale_completion_cannot_advance_it() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for thread in [first, second] {
        scheduler
            .commit_on(cpu(1), scheduler.reserve(thread).unwrap())
            .unwrap();
    }
    assert_eq!(
        scheduler.schedule_next_on(cpu(1)).unwrap().current,
        Some(first)
    );

    let first_ticket = scheduler.prepare_quantum_on(cpu(1), 1).unwrap();
    assert_eq!(scheduler.publish_quantum_expiry(first_ticket), Ok(true));
    let first_outgoing = match scheduler.preempt_current_on(cpu(1)).unwrap() {
        SchedulerPreemptionDecision::Switch { outgoing, .. } => outgoing,
        decision => panic!("exact expiry did not prepare a switch: {decision:?}"),
    };
    let first_completed = scheduler
        .complete_switch_on_with_runnable_publication(first_outgoing)
        .unwrap();
    assert_eq!(first_completed.generation(), 1);
    assert!(first_completed.involuntary_preemption());
    assert_eq!(
        scheduler.complete_switch_on_with_runnable_publication(first_outgoing),
        Err(SchedulerError::StaleExecutionClaim)
    );

    let second_ticket = scheduler.prepare_quantum_on(cpu(1), 2).unwrap();
    assert_eq!(scheduler.publish_quantum_expiry(second_ticket), Ok(true));
    let second_outgoing = match scheduler.preempt_current_on(cpu(1)).unwrap() {
        SchedulerPreemptionDecision::Switch { outgoing, .. } => outgoing,
        decision => panic!("replacement expiry did not prepare a switch: {decision:?}"),
    };
    let second_completed = scheduler
        .complete_switch_on_with_runnable_publication(second_outgoing)
        .unwrap();
    assert_eq!(second_completed.generation(), 2);
    assert!(second_completed.involuntary_preemption());
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn completed_switch_generation_rollover_is_atomic_and_retryable() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let first = thread_key(&mut registry);
    let second = thread_key(&mut registry);
    for thread in [first, second] {
        scheduler
            .commit_on(cpu(2), scheduler.reserve(thread).unwrap())
            .unwrap();
    }
    assert_eq!(
        scheduler.schedule_next_on(cpu(2)).unwrap().current,
        Some(first)
    );
    let ticket = scheduler.prepare_quantum_on(cpu(2), 1).unwrap();
    assert_eq!(scheduler.publish_quantum_expiry(ticket), Ok(true));
    let outgoing = match scheduler.preempt_current_on(cpu(2)).unwrap() {
        SchedulerPreemptionDecision::Switch { outgoing, .. } => outgoing,
        decision => panic!("exact expiry did not prepare a switch: {decision:?}"),
    };
    {
        scheduler.state.lock().next_completed_switch_generation = u64::MAX;
    }

    assert_eq!(
        scheduler.complete_switch_on_with_runnable_publication(outgoing),
        Err(SchedulerError::TokenExhausted)
    );
    assert_eq!(scheduler.suspended_claim_on(cpu(2)), Some(outgoing));
    assert_eq!(scheduler.current_on(cpu(2)), Some(second));
    assert_eq!(scheduler.check_invariants(), Ok(()));

    {
        scheduler.state.lock().next_completed_switch_generation = 0;
    }
    assert_eq!(
        scheduler.complete_switch_on_with_runnable_publication(outgoing),
        Err(SchedulerError::TokenExhausted)
    );
    assert_eq!(scheduler.suspended_claim_on(cpu(2)), Some(outgoing));

    {
        scheduler.state.lock().next_completed_switch_generation = 41;
    }
    let completed = scheduler
        .complete_switch_on_with_runnable_publication(outgoing)
        .unwrap();
    assert_eq!(completed.generation(), 41);
    assert!(completed.involuntary_preemption());
    assert_eq!(scheduler.suspended_claim_on(cpu(2)), None);
    assert_eq!(scheduler.check_invariants(), Ok(()));
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
            cancelled_quantum: None,
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
                cancelled_quantum: None,
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
                cancelled_quantum: None,
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
                cancelled_quantum: None,
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
                cancelled_quantum: None,
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
                cancelled_quantum: None,
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
    let counters = scheduler.counters_on(SchedulerCpuId::BOOTSTRAP);
    assert_eq!(counters.current_runnable, 0);
    assert_eq!(counters.context_switches, (CYCLES * 4) as u64);
    assert_eq!(counters.voluntary_yields, CYCLES as u64);
    assert_eq!(counters.voluntary_blocks, CYCLES as u64);
    assert_eq!(counters.wakeups, CYCLES as u64);
    assert!(!counters.overflow_fault);
}

#[test]
fn dw1c3_placement_uses_schedulable_requester_then_lowest_fallback() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    {
        let mut state = scheduler.state.lock();
        state.carrier_admission.enforced = true;
        state.carrier_admission.schedulable_mask = (1_u64 << 1) | (1_u64 << 3);
    }

    let fallback = thread_key(&mut registry);
    let fallback_publication = scheduler
        .commit_on(cpu(2), scheduler.reserve(fallback).unwrap())
        .unwrap();
    assert_eq!(fallback_publication.target(), cpu(1));

    let requested = thread_key(&mut registry);
    let requested_publication = scheduler
        .commit_on(cpu(3), scheduler.reserve(requested).unwrap())
        .unwrap();
    assert_eq!(requested_publication.target(), cpu(3));
    assert_eq!(
        scheduler.schedule_next_on(cpu(1)).unwrap().current,
        Some(fallback)
    );
    assert_eq!(
        scheduler.schedule_next_on(cpu(3)).unwrap().current,
        Some(requested)
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c3_released_blocked_thread_prefers_its_last_cpu() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(2), scheduler.reserve(thread).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(2)).unwrap();
    let running = scheduler.running_claim_on(cpu(2)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(2), thread).unwrap();
    let wake_key = blocked.wake_key();
    assert_eq!(decision.current, None);
    scheduler.complete_switch_on(running).unwrap();

    let publication = scheduler.wake_on(cpu(0), blocked.into_wake_key()).unwrap();
    assert_eq!(publication.source(), cpu(0));
    assert_eq!(publication.target(), cpu(2));
    assert_eq!(publication.generation(), 1);
    assert_eq!(publication.wake_affinity(), None);
    assert_eq!(
        scheduler.current_execution_generation(thread),
        Some(wake_key.execution_generation())
    );
    assert_eq!(
        scheduler.schedule_next_on(cpu(2)).unwrap().current,
        Some(thread)
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn wake_generation_is_exact_and_rollover_rejects_without_publication() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(2), scheduler.reserve(thread).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(2)).unwrap();
    let running = scheduler.running_claim_on(cpu(2)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(2), thread).unwrap();
    let key = blocked.wake_key();
    assert_eq!(decision.current, None);
    scheduler.complete_switch_on(running).unwrap();
    let accounting_before = scheduler.counters_on(cpu(2));

    scheduler.state.lock().next_wake_generation = u64::MAX;
    assert_eq!(
        scheduler.wake_on(cpu(0), key),
        Err(SchedulerError::TokenExhausted)
    );
    assert_eq!(scheduler.state(thread), Some(SchedulerThreadState::Blocked));
    assert_eq!(scheduler.counters_on(cpu(2)), accounting_before);
    assert_eq!(scheduler.state.lock().next_wake_generation, u64::MAX);

    scheduler.state.lock().next_wake_generation = 0;
    assert_eq!(
        scheduler.wake_on(cpu(0), key),
        Err(SchedulerError::TokenExhausted)
    );
    assert_eq!(scheduler.state(thread), Some(SchedulerThreadState::Blocked));

    scheduler.state.lock().next_wake_generation = 41;
    let publication = scheduler.wake_on(cpu(0), key).unwrap();
    assert_eq!(publication.source(), cpu(0));
    assert_eq!(publication.target(), cpu(2));
    assert_eq!(publication.generation(), 41);
    assert_eq!(scheduler.state.lock().next_wake_generation, 42);
    assert_eq!(
        scheduler.wake_on(cpu(0), key),
        Err(SchedulerError::StaleBlockToken)
    );
    assert_eq!(scheduler.state.lock().next_wake_generation, 42);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn current_execution_generation_joins_runnable_running_blocked_and_woken_states() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(1), scheduler.reserve(thread).unwrap())
        .unwrap();
    let generation = scheduler.runnable_start_generation(thread).unwrap();
    assert_eq!(
        scheduler.current_execution_generation(thread),
        Some(generation)
    );

    scheduler.schedule_next_on(cpu(1)).unwrap();
    assert_eq!(
        scheduler.current_execution_generation(thread),
        Some(generation)
    );
    let running = scheduler.running_claim_on(cpu(1)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(1), thread).unwrap();
    assert_eq!(decision.current, None);
    assert_eq!(
        scheduler.current_execution_generation(thread),
        Some(running.generation())
    );
    scheduler.complete_switch_on(running).unwrap();
    assert_eq!(
        scheduler.current_execution_generation(thread),
        Some(running.generation())
    );
    scheduler.wake_on(cpu(0), blocked.into_wake_key()).unwrap();
    assert_eq!(
        scheduler.current_execution_generation(thread),
        Some(running.generation())
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c3_unavailable_continuation_owner_never_falls_through_placement() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let blocked_thread = thread_key(&mut registry);
    let destination = thread_key(&mut registry);
    for thread in [blocked_thread, destination] {
        scheduler
            .commit_on(cpu(1), scheduler.reserve(thread).unwrap())
            .unwrap();
    }
    scheduler.schedule_next_on(cpu(1)).unwrap();
    let (blocked, decision) = scheduler.block_current_on(cpu(1), blocked_thread).unwrap();
    assert_eq!(decision.current, Some(destination));
    {
        let mut state = scheduler.state.lock();
        state.carrier_admission.enforced = true;
        state.carrier_admission.schedulable_mask = 1_u64 << 0;
    }

    assert_eq!(
        scheduler.wake_on(cpu(0), blocked.into_wake_key()),
        Err(SchedulerError::CarrierUnavailable)
    );
    assert_eq!(
        scheduler.state(blocked_thread),
        Some(SchedulerThreadState::Blocked)
    );
    assert_eq!(scheduler.running_cpu(blocked_thread), None);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c3_more_than_cpu_capacity_distributes_semantic_fifo_targets() {
    let scheduler = CooperativeScheduler::<8>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let mut threads = [None; 8];
    for (index, slot) in threads.iter_mut().enumerate() {
        let thread = thread_key(&mut registry);
        *slot = Some(thread);
        let target = cpu(index % H2_SCHEDULER_CPU_CAPACITY);
        let publication = scheduler
            .commit_on(target, scheduler.reserve(thread).unwrap())
            .unwrap();
        assert_eq!(publication.target(), target);
    }
    for (cpu_index, thread) in threads.iter().enumerate().take(H2_SCHEDULER_CPU_CAPACITY) {
        assert_eq!(scheduler.counters_on(cpu(cpu_index)).current_runnable, 2);
        assert_eq!(
            scheduler.schedule_next_on(cpu(cpu_index)).unwrap().current,
            *thread
        );
    }
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c3_idle_steal_is_cyclic_oldest_and_transactionally_accounted() {
    let scheduler = CooperativeScheduler::<3>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let oldest = thread_key(&mut registry);
    let same_victim_younger = thread_key(&mut registry);
    let later_victim = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(1), scheduler.reserve(oldest).unwrap())
        .unwrap();
    scheduler
        .commit_on(cpu(1), scheduler.reserve(same_victim_younger).unwrap())
        .unwrap();
    scheduler
        .commit_on(cpu(2), scheduler.reserve(later_victim).unwrap())
        .unwrap();

    let expected_execution_generation = scheduler.runnable_start_generation(oldest).unwrap();
    let dispatch = scheduler.schedule_next_on_with_migration(cpu(0)).unwrap();
    let decision = dispatch.decision();
    assert_eq!(decision.current, Some(oldest));
    let migration = dispatch
        .migration()
        .expect("idle dispatch carries its exact steal");
    assert_eq!(scheduler.last_migration(), Some(migration));
    assert_eq!(migration.thread, oldest);
    assert_eq!(
        migration.execution_generation,
        expected_execution_generation
    );
    assert_eq!(migration.source, cpu(1));
    assert_eq!(migration.target, cpu(0));
    assert_ne!(migration.generation, 0);
    assert_ne!(migration.enqueue_generation, 0);
    let source = scheduler.counters_on(cpu(1));
    let target = scheduler.counters_on(cpu(0));
    assert_eq!((source.steals_out, source.migrations_out), (1, 1));
    assert_eq!((target.steals_in, target.migrations_in), (1, 1));
    assert_eq!(source.current_runnable, 1);
    assert_eq!(target.current_runnable, 0);
    assert_eq!(scheduler.counters_on(cpu(2)).current_runnable, 1);

    let second_dispatch = scheduler.schedule_next_on_with_migration(cpu(3)).unwrap();
    assert_eq!(
        second_dispatch.decision().current,
        Some(same_victim_younger)
    );
    let second_migration = second_dispatch
        .migration()
        .expect("later idle dispatch carries a distinct exact steal");
    assert_eq!(second_migration.thread, same_victim_younger);
    assert_eq!(second_migration.source, cpu(1));
    assert_eq!(second_migration.target, cpu(3));
    assert_ne!(second_migration.generation, 0);
    assert_ne!(second_migration.generation, migration.generation);
    let source = scheduler.counters_on(cpu(1));
    let second_target = scheduler.counters_on(cpu(3));
    assert_eq!((source.steals_out, source.migrations_out), (2, 2));
    assert_eq!(
        (second_target.steals_in, second_target.migrations_in),
        (1, 1)
    );
    assert_eq!(source.current_runnable, 0);
    assert_eq!(second_target.current_runnable, 0);
    assert_eq!(scheduler.counters_on(cpu(2)).current_runnable, 1);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c3_migrated_ready_delay_is_charged_on_destination_dispatch() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .observe_instrumentation_time_on(cpu(1), 100)
        .unwrap();
    scheduler
        .commit_on(cpu(1), scheduler.reserve(thread).unwrap())
        .unwrap();
    scheduler
        .observe_instrumentation_time_on(cpu(0), 150)
        .unwrap();

    assert_eq!(
        scheduler.schedule_next_on(cpu(0)).unwrap().current,
        Some(thread)
    );
    assert_eq!(scheduler.counters_on(cpu(0)).longest_ready_delay_ns, 50);
    assert_eq!(scheduler.counters_on(cpu(1)).longest_ready_delay_ns, 0);
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c3_failed_migration_preserves_source_exactly_once() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(1), scheduler.reserve(thread).unwrap())
        .unwrap();
    let source_before = scheduler.counters_on(cpu(1));
    let target_before = scheduler.counters_on(cpu(0));
    scheduler.state.lock().next_migration_generation = u64::MAX;

    assert_eq!(
        scheduler.schedule_next_on(cpu(0)),
        Err(SchedulerError::TokenExhausted)
    );
    assert_eq!(
        scheduler.state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(scheduler.running_cpu(thread), None);
    assert_eq!(scheduler.counters_on(cpu(1)), source_before);
    assert_eq!(scheduler.counters_on(cpu(0)), target_before);
    assert_eq!(scheduler.last_migration(), None);
    assert_eq!(
        scheduler.schedule_next_on(cpu(1)).unwrap().current,
        Some(thread)
    );
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c3_post_steal_accounting_overflow_rolls_back_every_migration_field() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let thread = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(1), scheduler.reserve(thread).unwrap())
        .unwrap();
    let generation = scheduler.runnable_start_generation(thread).unwrap();
    let source_before = scheduler.counters_on(cpu(1));
    let target_before = scheduler.counters_on(cpu(0));
    let next_before = scheduler.state.lock().next_migration_generation;
    scheduler.state.lock().accounting.cpu[0].context_switches = u64::MAX;

    assert_eq!(
        scheduler.schedule_next_on_with_migration(cpu(0)),
        Err(SchedulerError::AccountingOverflow)
    );
    assert_eq!(scheduler.current_on(cpu(0)), None);
    assert_eq!(scheduler.running_cpu(thread), None);
    assert_eq!(
        scheduler.state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(
        scheduler.runnable_start_generation(thread),
        Some(generation)
    );
    assert_eq!(scheduler.counters_on(cpu(1)), source_before);
    assert_eq!(
        scheduler.counters_on(cpu(0)).current_runnable,
        target_before.current_runnable
    );
    assert_eq!(scheduler.last_migration(), None);
    assert_eq!(
        scheduler.state.lock().next_migration_generation,
        next_before
    );
}

#[test]
fn dw1c4_external_authority_exclusions_leave_the_source_queued() {
    for exclusion in [
        SchedulerMigrationRejectionReason::ExecutionPinned,
        SchedulerMigrationRejectionReason::ScratchPinned,
        SchedulerMigrationRejectionReason::RendezvousPending,
    ] {
        let scheduler = CooperativeScheduler::<1>::new();
        let mut registry = ObjectRegistry::<16>::new();
        let subject = thread_key(&mut registry);
        scheduler
            .commit_on(cpu(1), scheduler.reserve(subject).unwrap())
            .unwrap();
        let source_before = scheduler.counters_on(cpu(1));
        let target_before = scheduler.counters_on(cpu(0));
        let generation = scheduler.runnable_start_generation(subject).unwrap();
        scheduler
            .set_migration_exclusion(subject, generation, exclusion)
            .unwrap();

        assert_eq!(
            scheduler
                .attempt_migration_revalidation_on(cpu(0), subject, generation)
                .unwrap(),
            SchedulerMigrationRejection {
                thread: subject,
                execution_generation: generation,
                cpu: cpu(0),
                reason: exclusion,
            }
        );

        assert_eq!(scheduler.schedule_next_on(cpu(0)).unwrap().current, None);
        assert_eq!(
            scheduler.state(subject),
            Some(SchedulerThreadState::Runnable)
        );
        assert_eq!(scheduler.running_cpu(subject), None);
        assert_eq!(scheduler.counters_on(cpu(1)), source_before);
        assert_eq!(scheduler.counters_on(cpu(0)), target_before);
        assert_eq!(scheduler.last_migration(), None);
        scheduler
            .clear_migration_exclusion(subject, generation, exclusion)
            .unwrap();
        assert_eq!(scheduler.check_invariants(), Ok(()));
    }
}

#[test]
fn selector_migration_exclusion_set_probe_clear_is_generation_exact_and_retryable() {
    let scheduler = CooperativeScheduler::<1>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let subject = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(1), scheduler.reserve(subject).unwrap())
        .unwrap();
    let generation = scheduler.runnable_start_generation(subject).unwrap();
    let reason = SchedulerMigrationRejectionReason::ExecutionPinned;

    assert_eq!(
        scheduler.set_migration_exclusion(subject, generation + 1, reason),
        Err(SchedulerError::StaleExecutionClaim)
    );
    scheduler
        .set_migration_exclusion(subject, generation, reason)
        .unwrap();
    assert_eq!(
        scheduler.attempt_migration_revalidation_on(cpu(1), subject, generation),
        Err(SchedulerError::StaleExecutionClaim)
    );
    assert_eq!(
        scheduler.clear_migration_exclusion(
            subject,
            generation,
            SchedulerMigrationRejectionReason::ScratchPinned,
        ),
        Err(SchedulerError::StaleExecutionClaim)
    );
    assert_eq!(
        scheduler
            .attempt_migration_revalidation_on(cpu(0), subject, generation)
            .unwrap()
            .reason,
        reason
    );
    scheduler
        .clear_migration_exclusion(subject, generation, reason)
        .unwrap();
    let dispatch = scheduler.schedule_next_on_with_migration(cpu(0)).unwrap();
    let decision = dispatch.decision();
    assert_eq!(decision.current, Some(subject));
    assert!(dispatch.migration().is_some());
    assert_eq!(scheduler.check_invariants(), Ok(()));
}

#[test]
fn dw1c4_remote_stop_and_preemption_have_one_exact_winner_in_both_orders() {
    let mut registry = ObjectRegistry::<16>::new();

    let stop_first = CooperativeScheduler::<2>::new();
    let stopped = thread_key(&mut registry);
    let peer = thread_key(&mut registry);
    for thread in [stopped, peer] {
        stop_first
            .commit_on(cpu(0), stop_first.reserve(thread).unwrap())
            .unwrap();
    }
    stop_first.schedule_next_on(cpu(0)).unwrap();
    let claim = stop_first.running_claim_on(cpu(0)).unwrap();
    let ticket = stop_first.prepare_quantum_on(cpu(0), 10).unwrap();
    assert_eq!(stop_first.stop_running_claim_on(claim), Ok(Some(ticket)));
    assert_eq!(stop_first.publish_quantum_expiry(ticket), Ok(false));
    assert_eq!(
        stop_first.preempt_current_on(cpu(0)),
        Err(SchedulerError::StaleQuantum)
    );
    stop_first.complete_switch_on(claim).unwrap();
    assert_eq!(
        stop_first.schedule_next_on(cpu(0)).unwrap().current,
        Some(peer)
    );
    assert_eq!(stop_first.state(stopped), None);
    assert_eq!(stop_first.check_invariants(), Ok(()));

    let preempt_first = CooperativeScheduler::<2>::new();
    let outgoing = thread_key(&mut registry);
    let replacement = thread_key(&mut registry);
    for thread in [outgoing, replacement] {
        preempt_first
            .commit_on(cpu(0), preempt_first.reserve(thread).unwrap())
            .unwrap();
    }
    preempt_first.schedule_next_on(cpu(0)).unwrap();
    let ticket = preempt_first.prepare_quantum_on(cpu(0), 20).unwrap();
    assert_eq!(preempt_first.publish_quantum_expiry(ticket), Ok(true));
    let outgoing_claim = match preempt_first.preempt_current_on(cpu(0)).unwrap() {
        SchedulerPreemptionDecision::Switch { outgoing, .. } => outgoing,
        decision => panic!("expected exact preemptive switch, got {decision:?}"),
    };
    preempt_first
        .stop_suspended_claim_on(outgoing_claim)
        .unwrap();
    assert_eq!(preempt_first.publish_quantum_expiry(ticket), Ok(false));
    assert_eq!(preempt_first.state(outgoing), None);
    assert_eq!(preempt_first.current_on(cpu(0)), Some(replacement));
    preempt_first.complete_switch_on(outgoing_claim).unwrap();
    assert_eq!(preempt_first.check_invariants(), Ok(()));
}

#[test]
fn dw1c4_stale_timer_wake_and_migration_records_cannot_alias_reused_thread_keys() {
    let scheduler = CooperativeScheduler::<2>::new();
    let mut registry = ObjectRegistry::<16>::new();
    let retired = thread_key(&mut registry);
    scheduler
        .commit_on(cpu(1), scheduler.reserve(retired).unwrap())
        .unwrap();
    scheduler.schedule_next_on(cpu(1)).unwrap();
    let stale_timer = scheduler.prepare_quantum_on(cpu(1), 10).unwrap();
    let (blocked, _) = scheduler.block_current_on(cpu(1), retired).unwrap();
    let stale_wake = blocked.into_wake_key();
    scheduler.retire_on(cpu(1), retired).unwrap();
    scheduler
        .complete_switch_on(scheduler.suspended_claim_on(cpu(1)).unwrap())
        .unwrap();

    let generations_before_reuse = registry.test_slot_generations();
    let replacement = thread_key(&mut registry);
    let generations_after_reuse = registry.test_slot_generations();
    assert_ne!(
        replacement, retired,
        "ObjectRegistry generation reuse must change ThreadKey"
    );
    assert!(
        generations_before_reuse
            .iter()
            .zip(generations_after_reuse)
            .any(|(before, after)| after == before.checked_add(1).unwrap()),
        "replacement must advance one released ObjectRegistry slot generation"
    );
    scheduler
        .commit_on(cpu(1), scheduler.reserve(replacement).unwrap())
        .unwrap();
    let migrated = scheduler.schedule_next_on(cpu(0)).unwrap().current;
    assert_eq!(migrated, Some(replacement));
    let migration = scheduler.last_migration().unwrap();
    assert_eq!(migration.thread, replacement);
    assert_ne!(migration.thread, retired);
    assert_ne!(migration.generation, 0);
    assert_eq!(scheduler.publish_quantum_expiry(stale_timer), Ok(false));
    assert_eq!(
        scheduler.wake(stale_wake),
        Err(SchedulerError::StaleBlockToken)
    );
    assert_eq!(scheduler.current_on(cpu(0)), Some(replacement));
    assert_eq!(scheduler.check_invariants(), Ok(()));
}
