//! DW1-B logical deadline-source and physical-arm generation model.

use super::{ApicOneShot, DeadlineQueueError, apic_one_shot_for_delta};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LogicalDeadline<T: Copy + Eq> {
    pub(crate) generation: u64,
    pub(crate) deadline_ns: u64,
    pub(crate) payload: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineSourceError {
    InvalidGeneration,
    InvalidDeadline,
    GenerationRegression,
}

pub(crate) struct LocalDeadlineSource<T: Copy + Eq> {
    armed: Option<LogicalDeadline<T>>,
    last_generation: u64,
}

impl<T: Copy + Eq> LocalDeadlineSource<T> {
    pub(crate) const fn new() -> Self {
        Self {
            armed: None,
            last_generation: 0,
        }
    }

    pub(crate) const fn earliest(&self) -> Option<u64> {
        match self.armed {
            Some(deadline) => Some(deadline.deadline_ns),
            None => None,
        }
    }

    pub(crate) fn replace(
        &mut self,
        generation: u64,
        deadline_ns: u64,
        payload: T,
    ) -> Result<(), DeadlineSourceError> {
        if generation == 0 {
            return Err(DeadlineSourceError::InvalidGeneration);
        }
        if deadline_ns == 0 || deadline_ns == u64::MAX {
            return Err(DeadlineSourceError::InvalidDeadline);
        }
        if generation <= self.last_generation {
            return Err(DeadlineSourceError::GenerationRegression);
        }
        self.last_generation = generation;
        self.armed = Some(LogicalDeadline {
            generation,
            deadline_ns,
            payload,
        });
        Ok(())
    }

    pub(crate) fn cancel(&mut self, generation: u64, payload: T) -> bool {
        if self
            .armed
            .is_some_and(|armed| armed.generation == generation && armed.payload == payload)
        {
            self.armed = None;
            true
        } else {
            false
        }
    }

    pub(crate) fn take_due(&mut self, now_ns: u64) -> Option<T> {
        if self.armed.is_some_and(|armed| armed.deadline_ns <= now_ns) {
            self.armed.take().map(|armed| armed.payload)
        } else {
            None
        }
    }
}

pub(crate) const fn earliest_deadline(sources: [Option<u64>; 3], maintenance_deadline: u64) -> u64 {
    let mut earliest = maintenance_deadline;
    let mut index = 0;
    while index < sources.len() {
        if let Some(deadline) = sources[index]
            && deadline < earliest
        {
            earliest = deadline;
        }
        index += 1;
    }
    earliest
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HardwareArmIntent {
    pub(crate) generation: u64,
    pub(crate) source_revision: u64,
    pub(crate) deadline_ns: u64,
    pub(crate) shot: ApicOneShot,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HardwareStopIntent {
    pub(crate) generation: u64,
    pub(crate) source_revision: u64,
}

pub(crate) struct PhysicalArmSequence {
    next_generation: u64,
    desired_generation: u64,
    source_revision: u64,
}

impl PhysicalArmSequence {
    pub(crate) const fn initialized() -> Self {
        Self {
            next_generation: 2,
            desired_generation: 1,
            source_revision: 1,
        }
    }

    /// Invalidates every hardware intent prepared before an accepted logical
    /// source mutation, including a mutation that races LAPIC MMIO.
    pub(crate) fn source_mutated(&mut self) -> Result<(), DeadlineQueueError> {
        self.source_revision = self
            .source_revision
            .checked_add(1)
            .filter(|revision| *revision != 0)
            .ok_or(DeadlineQueueError::GenerationExhausted)?;
        Ok(())
    }

    pub(crate) fn prepare(
        &mut self,
        deadline_ns: u64,
        now_ns: u64,
        timer_hz: u64,
    ) -> Result<HardwareArmIntent, DeadlineQueueError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(DeadlineQueueError::GenerationExhausted)?;
        let shot = apic_one_shot_for_delta(deadline_ns.saturating_sub(now_ns), timer_hz)?;
        self.desired_generation = generation;
        Ok(HardwareArmIntent {
            generation,
            source_revision: self.source_revision,
            deadline_ns,
            shot,
        })
    }

    pub(crate) fn prepare_stop(&mut self) -> Result<HardwareStopIntent, DeadlineQueueError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(DeadlineQueueError::GenerationExhausted)?;
        self.desired_generation = generation;
        Ok(HardwareStopIntent {
            generation,
            source_revision: self.source_revision,
        })
    }

    pub(crate) const fn is_current(&self, intent: &HardwareArmIntent) -> bool {
        self.desired_generation == intent.generation
            && self.source_revision == intent.source_revision
    }

    pub(crate) const fn is_stop_current(&self, intent: &HardwareStopIntent) -> bool {
        self.desired_generation == intent.generation
            && self.source_revision == intent.source_revision
    }

    /// True when `intent` is still the desired arm and fires no later than
    /// every source now needs: `earliest_deadline_ns`, computed from the
    /// same clock sample `intent` was prepared with, is not earlier than the
    /// deadline `intent` was prepared for. Source changes that leave the
    /// earliest deadline where it was, or move it later, keep the arm.
    pub(crate) const fn still_covers(
        &self,
        intent: &HardwareArmIntent,
        earliest_deadline_ns: u64,
    ) -> bool {
        self.desired_generation == intent.generation && earliest_deadline_ns >= intent.deadline_ns
    }
}

/// Tries [`reconcile_hardware_arm`] makes before it defers.
pub(crate) const HARDWARE_ARM_TRIES: u32 = 8;

/// The operations [`reconcile_hardware_arm`] runs against one CPU's timer
/// sources and its one-shot timer.
pub(crate) trait HardwareArmPort {
    /// A prepared arm, carrying whatever the cover check needs.
    type Arm;
    type Error;

    /// Samples the clock and prepares an arm for the earliest deadline.
    fn prepare_arm(&mut self) -> Result<Self::Arm, Self::Error>;
    /// Programs the one-shot timer with `arm`.
    fn write_arm(&mut self, arm: &Self::Arm) -> Result<(), Self::Error>;
    /// Whether `arm` still fires no later than the sources need
    /// ([`PhysicalArmSequence::still_covers`]).
    fn arm_covers_sources(&mut self, arm: &Self::Arm) -> bool;
    /// Samples the clock and prepares an arm for that instant: the
    /// smallest count, which is no later than any deadline.
    fn prepare_immediate_arm(&mut self) -> Result<Self::Arm, Self::Error>;
}

/// How a successful [`reconcile_hardware_arm`] ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HardwareArmOutcome {
    /// An arm that covers the sources is in the timer; `lost_tries` tries
    /// before it were lost to an earlier deadline.
    Committed { lost_tries: u32 },
    /// Every try was lost; the timer holds the immediate arm, whose
    /// interrupt expires what is due and reconciles again.
    Deferred,
}

impl HardwareArmOutcome {
    pub(crate) const fn lost_tries(self) -> u32 {
        match self {
            Self::Committed { lost_tries } => lost_tries,
            Self::Deferred => HARDWARE_ARM_TRIES,
        }
    }

    pub(crate) const fn is_deferred(self) -> bool {
        match self {
            Self::Committed { .. } => false,
            Self::Deferred => true,
        }
    }
}

/// Programs the timer so it fires no later than every source needs.
///
/// Each try prepares an arm, writes it, and keeps it if it still covers the
/// sources. After [`HARDWARE_ARM_TRIES`] lost tries it writes the immediate
/// arm, which needs no recheck, and returns [`HardwareArmOutcome::Deferred`].
/// At most `HARDWARE_ARM_TRIES + 1` writes. Any preparation or write error
/// is returned at once.
pub(crate) fn reconcile_hardware_arm<P: HardwareArmPort>(
    port: &mut P,
) -> Result<HardwareArmOutcome, P::Error> {
    for lost_tries in 0..HARDWARE_ARM_TRIES {
        let arm = port.prepare_arm()?;
        port.write_arm(&arm)?;
        if port.arm_covers_sources(&arm) {
            return Ok(HardwareArmOutcome::Committed { lost_tries });
        }
    }
    let immediate = port.prepare_immediate_arm()?;
    port.write_arm(&immediate)?;
    Ok(HardwareArmOutcome::Deferred)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_quantum_arm_requires_rescheduling_before_an_ap_can_return_to_userspace() {
        use crate::cpu::CpuIndex;
        use crate::object::ObjectRegistry;
        use crate::task::{CooperativeScheduler, SchedulerPreemptionDecision, ThreadKey};
        use deepwyrm_abi::DW_OBJECT_TYPE_THREAD;

        for cpu_index in 0..4 {
            for peer_is_runnable in [false, true] {
                let cpu = CpuIndex::new(cpu_index).unwrap();
                let scheduler = CooperativeScheduler::<2>::new();
                let mut registry = ObjectRegistry::<16>::new();
                let mut new_thread = || {
                    let creation = registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
                    let key = ThreadKey::from_object_id(creation.id());
                    registry.cancel_creation(creation).unwrap();
                    key
                };
                let hog = new_thread();
                let peer = new_thread();
                scheduler
                    .commit_on(cpu, scheduler.reserve(hog).unwrap())
                    .unwrap();
                scheduler.schedule_next_on(cpu).unwrap();
                if peer_is_runnable {
                    scheduler
                        .commit_on(cpu, scheduler.reserve(peer).unwrap())
                        .unwrap();
                }

                let ticket = scheduler
                    .prepare_quantum_if_needed_on(cpu, 100)
                    .unwrap()
                    .unwrap();
                let mut source = LocalDeadlineSource::new();
                source
                    .replace(ticket.source_arm_generation(), ticket.deadline_ns(), ticket)
                    .unwrap();
                // A delay after minting can consume the entire quantum before
                // the first physical arm. AP reconciliation then stops the
                // timer and publishes this exact request synchronously.
                let now = ticket.deadline_ns() + 1;
                let expired = source.take_due(now).unwrap();
                assert_eq!(source.earliest(), None);
                assert_eq!(scheduler.publish_quantum_expiry(expired), Ok(true));
                assert!(scheduler.has_reschedule_request_on(cpu));

                // There is no remaining AP source and the hog makes no kernel
                // calls. Its return gate must consume this request now.
                match scheduler.preempt_current_on(cpu).unwrap() {
                    SchedulerPreemptionDecision::Switch { decision, outgoing } => {
                        assert!(peer_is_runnable);
                        assert_eq!(decision.current, Some(peer));
                        scheduler.complete_switch_on(outgoing).unwrap();
                    }
                    SchedulerPreemptionDecision::RetainCurrent { .. } => {
                        assert!(!peer_is_runnable);
                    }
                    SchedulerPreemptionDecision::Deferred => panic!("safe return was deferred"),
                }
                assert!(!scheduler.has_reschedule_request_on(cpu));
                let next = scheduler
                    .prepare_quantum_if_needed_on(cpu, now)
                    .unwrap()
                    .unwrap();
                assert_eq!(next.thread(), if peer_is_runnable { peer } else { hog });
                source
                    .replace(next.source_arm_generation(), next.deadline_ns(), next)
                    .unwrap();
                assert_eq!(source.take_due(now), None);
                assert_eq!(source.earliest(), Some(next.deadline_ns()));
                assert_eq!(scheduler.publish_quantum_expiry(expired), Ok(false));
                assert_eq!(scheduler.check_invariants(), Ok(()));
            }
        }
    }

    #[test]
    fn source_replace_cancel_and_due_are_exact_generation_operations() {
        let mut source = LocalDeadlineSource::new();
        assert_eq!(source.replace(1, 100, 7_u8), Ok(()));
        assert_eq!(
            source.replace(1, 200, 8),
            Err(DeadlineSourceError::GenerationRegression)
        );
        assert!(!source.cancel(1, 8));
        assert_eq!(source.take_due(99), None);
        assert_eq!(source.take_due(100), Some(7));
        assert_eq!(source.take_due(100), None);
        assert_eq!(
            source.replace(1, 150, 9),
            Err(DeadlineSourceError::GenerationRegression)
        );
        assert_eq!(source.replace(2, 200, 8), Ok(()));
        assert!(source.cancel(2, 8));
        assert_eq!(
            source.replace(2, 250, 9),
            Err(DeadlineSourceError::GenerationRegression)
        );
    }

    #[test]
    fn three_logical_sources_choose_earliest_and_equal_deadlines_stay_equal() {
        assert_eq!(earliest_deadline([Some(30), Some(20), Some(40)], 50), 20);
        assert_eq!(earliest_deadline([Some(20), Some(20), Some(20)], 50), 20);
        assert_eq!(earliest_deadline([None, None, None], 50), 50);
    }

    #[test]
    fn physical_reprogram_race_requires_the_newest_generation() {
        let mut arms = PhysicalArmSequence::initialized();
        let old = arms.prepare(1_000, 900, 1_000_000).unwrap();
        let new = arms.prepare(950, 900, 1_000_000).unwrap();
        assert!(!arms.is_current(&old));
        assert!(arms.is_current(&new));
        assert_ne!(old.generation, 0);
        assert_ne!(new.generation, 0);
        assert!(new.shot.initial_count <= old.shot.initial_count);
    }

    #[test]
    fn stop_intent_is_generation_bound_against_a_later_arm() {
        let mut arms = PhysicalArmSequence::initialized();
        let stop = arms.prepare_stop().unwrap();
        assert!(arms.is_stop_current(&stop));
        let arm = arms.prepare(1_000, 900, 1_000_000).unwrap();
        assert!(!arms.is_stop_current(&stop));
        assert!(arms.is_current(&arm));
    }

    #[test]
    fn logical_source_mutation_invalidates_an_inflight_physical_intent() {
        let mut source = LocalDeadlineSource::new();
        let mut arms = PhysicalArmSequence::initialized();
        source.replace(1, 1_000, 7_u8).unwrap();
        arms.source_mutated().unwrap();
        let stale = arms.prepare(1_000, 900, 1_000_000).unwrap();

        source.replace(2, 950, 8).unwrap();
        arms.source_mutated().unwrap();
        assert!(!arms.is_current(&stale));

        let current = arms.prepare(950, 900, 1_000_000).unwrap();
        assert!(arms.is_current(&current));
        assert_ne!(stale.source_revision, current.source_revision);
    }

    #[test]
    fn if_clear_expiry_and_late_vector_cannot_overwrite_the_next_budget() {
        let mut source = LocalDeadlineSource::new();
        let mut arms = PhysicalArmSequence::initialized();
        source.replace(41, 1_000, 7_u8).unwrap();
        arms.source_mutated().unwrap();
        let pending_expiry = arms.prepare(1_000, 900, 1_000_000).unwrap();

        assert_eq!(source.take_due(1_000), Some(7));
        arms.source_mutated().unwrap();
        assert!(!arms.is_current(&pending_expiry));

        source.replace(42, 6_000_000, 8).unwrap();
        arms.source_mutated().unwrap();
        let next_budget = arms.prepare(6_000_000, 1_000, 1_000_000).unwrap();
        assert!(arms.is_current(&next_budget));
        assert!(!source.cancel(41, 7), "late expiry identity is stale");
        assert_eq!(source.take_due(5_999_999), None);
        assert_eq!(source.take_due(6_000_000), Some(8));
    }

    #[test]
    fn dw1c2_four_cpu_quantum_sources_reconcile_without_cross_cpu_mutation() {
        let mut sources: [LocalDeadlineSource<(u8, u64)>; 4] =
            core::array::from_fn(|_| LocalDeadlineSource::new());
        let mut arms: [PhysicalArmSequence; 4] =
            core::array::from_fn(|_| PhysicalArmSequence::initialized());
        let mut first_intents: [Option<HardwareArmIntent>; 4] = core::array::from_fn(|_| None);

        for cpu in 0..4_u8 {
            let index = usize::from(cpu);
            sources[index]
                .replace(1, 1_000 + u64::from(cpu), (cpu, 1))
                .unwrap();
            arms[index].source_mutated().unwrap();
            first_intents[index] = Some(
                arms[index]
                    .prepare(1_000 + u64::from(cpu), 900, 1_000_000)
                    .unwrap(),
            );
        }

        assert_eq!(sources[2].take_due(1_002), Some((2, 1)));
        arms[2].source_mutated().unwrap();
        assert_eq!(sources[0].take_due(1_002), Some((0, 1)));
        assert_eq!(sources[1].take_due(1_002), Some((1, 1)));
        assert_eq!(sources[3].take_due(1_002), None);
        assert!(!sources[3].cancel(1, (2, 1)));
        assert_eq!(sources[3].earliest(), Some(1_003));

        assert!(sources[3].cancel(1, (3, 1)));
        arms[3].source_mutated().unwrap();
        let stopped = arms[3].prepare_stop().unwrap();
        assert!(arms[3].is_stop_current(&stopped));
        assert_eq!(sources[3].earliest(), None);
        sources[3].replace(2, 3_000, (3, 2)).unwrap();
        arms[3].source_mutated().unwrap();
        let rearmed = arms[3].prepare(3_000, 1_002, 1_000_000).unwrap();
        assert!(!arms[3].is_stop_current(&stopped));
        assert!(arms[3].is_current(&rearmed));
        assert_eq!(sources[3].take_due(3_000), Some((3, 2)));

        sources[2].replace(2, 2_000, (2, 2)).unwrap();
        arms[2].source_mutated().unwrap();
        let replacement = arms[2].prepare(2_000, 1_002, 1_000_000).unwrap();
        assert!(!arms[2].is_current(first_intents[2].as_ref().unwrap()));
        assert!(arms[2].is_current(&replacement));
        assert!(!sources[2].cancel(1, (2, 1)));
        assert_eq!(sources[2].take_due(1_999), None);
        assert_eq!(sources[2].take_due(2_000), Some((2, 2)));
    }

    #[test]
    fn hardware_count_conversion_is_checked_and_outward_rounded() {
        let mut arms = PhysicalArmSequence::initialized();
        assert_eq!(
            arms.prepare(10, 0, 0),
            Err(DeadlineQueueError::InvalidTimerRate)
        );
        let immediate = arms.prepare(10, 10, 1_000_000).unwrap();
        assert_eq!(immediate.shot.initial_count, 1);
        let bounded = arms.prepare(u64::MAX - 1, 0, u64::MAX).unwrap();
        assert_eq!(bounded.shot.initial_count, u32::MAX);
        assert!(!bounded.shot.reaches_deadline);
    }

    mod reconcile {
        extern crate std;

        use super::super::*;
        use crate::time::{DeadlineQueue, DeadlineRegistration};
        use std::vec::Vec;

        /// One count per nanosecond, so a shot's count is its delta.
        const HZ: u64 = 1_000_000_000;
        const MAINTENANCE_NS: u64 = 1_000_000;
        /// How far the clock moves between two samples.
        const CLOCK_STEP_NS: u64 = 100;

        /// The BSP's three sources and its arm sequence, mutated the way the
        /// live time state mutates them: every accepted change moves the
        /// source revision.
        struct Sources {
            waits: DeadlineQueue<16, u32>,
            timers: DeadlineQueue<16, u32>,
            quantum: LocalDeadlineSource<u32>,
            arms: PhysicalArmSequence,
            now_ns: u64,
        }

        impl Sources {
            fn new() -> Self {
                Self {
                    waits: DeadlineQueue::new(),
                    timers: DeadlineQueue::new(),
                    quantum: LocalDeadlineSource::new(),
                    arms: PhysicalArmSequence::initialized(),
                    now_ns: 1_000,
                }
            }

            fn earliest(&self) -> u64 {
                earliest_deadline(
                    [
                        self.waits.earliest(),
                        self.timers.earliest(),
                        self.quantum.earliest(),
                    ],
                    MAINTENANCE_NS,
                )
            }

            fn register_wait(&mut self, deadline_ns: u64) -> DeadlineRegistration {
                let registration = self.waits.register(deadline_ns, 0).unwrap();
                self.arms.source_mutated().unwrap();
                registration
            }

            fn cancel_wait(&mut self, registration: DeadlineRegistration) {
                self.waits.cancel(registration).unwrap();
                self.arms.source_mutated().unwrap();
            }

            fn register_timer(&mut self, deadline_ns: u64) -> DeadlineRegistration {
                let registration = self.timers.register(deadline_ns, 0).unwrap();
                self.arms.source_mutated().unwrap();
                registration
            }

            fn sample(&mut self) -> u64 {
                self.now_ns = self.now_ns.checked_add(CLOCK_STEP_NS).unwrap();
                self.now_ns
            }
        }

        struct TestArm {
            intent: HardwareArmIntent,
            sample_ns: u64,
        }

        #[derive(Debug, Eq, PartialEq)]
        enum TestError {
            Prepare,
            Write,
        }

        /// Drives the real arm sequence. `peer` runs inside every write's
        /// window, between the write and the cover check, with the index
        /// of that write.
        struct Port<F: FnMut(&mut Sources, usize)> {
            sources: Sources,
            peer: F,
            /// Initial count of every shot written, in order.
            writes: Vec<u32>,
            /// Whether the old revision compare would have kept each arm.
            revision_current: Vec<bool>,
            prepares: usize,
            write_attempts: usize,
            fail_prepare_at: Option<usize>,
            fail_write_at: Option<usize>,
        }

        impl<F: FnMut(&mut Sources, usize)> Port<F> {
            fn new(sources: Sources, peer: F) -> Self {
                Self {
                    sources,
                    peer,
                    writes: Vec::new(),
                    revision_current: Vec::new(),
                    prepares: 0,
                    write_attempts: 0,
                    fail_prepare_at: None,
                    fail_write_at: None,
                }
            }

            fn begin_prepare(&mut self) -> Result<u64, TestError> {
                let index = self.prepares;
                self.prepares += 1;
                if self.fail_prepare_at == Some(index) {
                    return Err(TestError::Prepare);
                }
                Ok(self.sources.sample())
            }
        }

        impl<F: FnMut(&mut Sources, usize)> HardwareArmPort for Port<F> {
            type Arm = TestArm;
            type Error = TestError;

            fn prepare_arm(&mut self) -> Result<TestArm, TestError> {
                let sample_ns = self.begin_prepare()?;
                let deadline_ns = self.sources.earliest();
                let intent = self
                    .sources
                    .arms
                    .prepare(deadline_ns, sample_ns, HZ)
                    .map_err(|_| TestError::Prepare)?;
                Ok(TestArm { intent, sample_ns })
            }

            fn write_arm(&mut self, arm: &TestArm) -> Result<(), TestError> {
                let index = self.write_attempts;
                self.write_attempts += 1;
                if self.fail_write_at == Some(index) {
                    return Err(TestError::Write);
                }
                self.writes.push(arm.intent.shot.initial_count);
                (self.peer)(&mut self.sources, index);
                Ok(())
            }

            fn arm_covers_sources(&mut self, arm: &TestArm) -> bool {
                // The maintenance deadline is fixed here, so the earliest
                // deadline from `arm.sample_ns` is the sources' earliest.
                assert!(arm.sample_ns <= self.sources.now_ns);
                self.revision_current
                    .push(self.sources.arms.is_current(&arm.intent));
                self.sources
                    .arms
                    .still_covers(&arm.intent, self.sources.earliest())
            }

            fn prepare_immediate_arm(&mut self) -> Result<TestArm, TestError> {
                let sample_ns = self.begin_prepare()?;
                let intent = self
                    .sources
                    .arms
                    .prepare(sample_ns, sample_ns, HZ)
                    .map_err(|_| TestError::Prepare)?;
                Ok(TestArm { intent, sample_ns })
            }
        }

        /// A peer that registers an earlier wait inside every window.
        fn earlier_every_window(sources: &mut Sources, index: usize) {
            let index = u64::try_from(index).unwrap();
            let _ = sources.register_wait(9_000 - 100 * index);
        }

        #[test]
        fn source_changes_that_leave_the_earliest_deadline_keep_the_first_arm() {
            let mut sources = Sources::new();
            let _ = sources.register_wait(10_000);
            let mut later = Some(sources.register_wait(50_000));
            let mut port = Port::new(sources, |sources, index| {
                let index = u64::try_from(index).unwrap();
                let next = sources.register_wait(60_000 + index);
                if let Some(previous) = later.replace(next) {
                    sources.cancel_wait(previous);
                }
            });

            assert_eq!(
                reconcile_hardware_arm(&mut port),
                Ok(HardwareArmOutcome::Committed { lost_tries: 0 })
            );
            assert_eq!(port.writes, [10_000 - 1_100]);
            // The revision moved inside the window: the revision compare
            // would have lost this try, and every later one.
            assert_eq!(port.revision_current, [false]);
        }

        #[test]
        fn an_earlier_deadline_registered_once_costs_one_retry() {
            let mut sources = Sources::new();
            let _ = sources.register_wait(10_000);
            let mut port = Port::new(sources, |sources, index| {
                if index == 0 {
                    let _ = sources.register_timer(5_000);
                }
            });

            assert_eq!(
                reconcile_hardware_arm(&mut port),
                Ok(HardwareArmOutcome::Committed { lost_tries: 1 })
            );
            assert_eq!(port.writes, [10_000 - 1_100, 5_000 - 1_200]);
            assert_eq!(
                HardwareArmOutcome::Committed { lost_tries: 1 }.lost_tries(),
                1
            );
        }

        #[test]
        fn an_earlier_deadline_in_every_window_defers_with_the_immediate_arm() {
            let mut sources = Sources::new();
            let _ = sources.register_wait(10_000);
            let mut port = Port::new(sources, earlier_every_window);

            let outcome = reconcile_hardware_arm(&mut port);
            assert_eq!(outcome, Ok(HardwareArmOutcome::Deferred));
            let outcome = outcome.unwrap();
            assert!(outcome.is_deferred());
            assert_eq!(outcome.lost_tries(), HARDWARE_ARM_TRIES);
            let tries = usize::try_from(HARDWARE_ARM_TRIES).unwrap();
            assert_eq!(port.writes.len(), tries + 1);
            assert_eq!(port.writes.last(), Some(&1));
            assert!(port.writes[..tries].iter().all(|count| *count > 1));
            assert_eq!(port.revision_current.len(), tries);
        }

        #[test]
        fn cancelling_the_earliest_deadline_keeps_the_early_arm() {
            let mut sources = Sources::new();
            let mut earliest = Some(sources.register_wait(10_000));
            let _ = sources.register_wait(20_000);
            let mut port = Port::new(sources, |sources, _| {
                if let Some(registration) = earliest.take() {
                    sources.cancel_wait(registration);
                }
            });

            assert_eq!(
                reconcile_hardware_arm(&mut port),
                Ok(HardwareArmOutcome::Committed { lost_tries: 0 })
            );
            assert_eq!(port.writes, [10_000 - 1_100]);
            assert_eq!(port.sources.earliest(), 20_000);
        }

        #[test]
        fn preparation_and_write_errors_are_returned_on_a_try_and_on_the_immediate_arm() {
            let tries = usize::try_from(HARDWARE_ARM_TRIES).unwrap();

            let mut sources = Sources::new();
            let _ = sources.register_wait(10_000);
            let mut port = Port::new(sources, |_, _| {});
            port.fail_prepare_at = Some(0);
            assert_eq!(reconcile_hardware_arm(&mut port), Err(TestError::Prepare));
            assert!(port.writes.is_empty());

            let mut sources = Sources::new();
            let _ = sources.register_wait(10_000);
            let mut port = Port::new(sources, |_, _| {});
            port.fail_write_at = Some(0);
            assert_eq!(reconcile_hardware_arm(&mut port), Err(TestError::Write));
            assert!(port.writes.is_empty());
            assert_eq!(port.prepares, 1);

            let mut sources = Sources::new();
            let _ = sources.register_wait(10_000);
            let mut port = Port::new(sources, earlier_every_window);
            port.fail_prepare_at = Some(tries);
            assert_eq!(reconcile_hardware_arm(&mut port), Err(TestError::Prepare));
            assert_eq!(port.writes.len(), tries);

            let mut sources = Sources::new();
            let _ = sources.register_wait(10_000);
            let mut port = Port::new(sources, earlier_every_window);
            port.fail_write_at = Some(tries);
            assert_eq!(reconcile_hardware_arm(&mut port), Err(TestError::Write));
            assert_eq!(port.writes.len(), tries);
            assert_eq!(port.prepares, tries + 1);
        }

        #[test]
        fn cover_check_needs_the_desired_generation_and_no_earlier_deadline() {
            let mut arms = PhysicalArmSequence::initialized();
            let intent = arms.prepare(1_000, 900, HZ).unwrap();
            assert!(arms.still_covers(&intent, 1_000));
            assert!(arms.still_covers(&intent, 1_500));
            assert!(!arms.still_covers(&intent, 999));
            arms.source_mutated().unwrap();
            assert!(!arms.is_current(&intent));
            assert!(arms.still_covers(&intent, 1_000));

            let newer = arms.prepare(2_000, 900, HZ).unwrap();
            assert!(!arms.still_covers(&intent, 1_000));
            assert!(!arms.still_covers(&intent, 5_000));
            assert!(arms.still_covers(&newer, 2_000));
        }
    }
}
