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

    pub(crate) const fn is_current(&self, intent: &HardwareArmIntent) -> bool {
        self.desired_generation == intent.generation
            && self.source_revision == intent.source_revision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
