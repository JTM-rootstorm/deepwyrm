use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::{DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DwDeadline};

use crate::task::BlockWakeKey;

pub(crate) const DEADLINE_QUEUE_CAPACITY: usize = 64;
const NANOS_PER_SECOND: u128 = 1_000_000_000;
static NEXT_DEADLINE_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_domain() -> u64 {
    NEXT_DEADLINE_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .expect("deadline domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineClass {
    Now,
    Finite(u64),
    Infinite,
}

pub(crate) const fn classify_deadline(deadline: DwDeadline) -> DeadlineClass {
    if deadline.0 == DW_DEADLINE_NOW.0 {
        DeadlineClass::Now
    } else if deadline.0 == DW_DEADLINE_INFINITE.0 {
        DeadlineClass::Infinite
    } else {
        DeadlineClass::Finite(deadline.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApicOneShot {
    pub(crate) initial_count: u32,
    pub(crate) reaches_deadline: bool,
}

pub(crate) fn apic_one_shot_for_delta(
    delta_ns: u64,
    timer_hz: u64,
) -> Result<ApicOneShot, DeadlineQueueError> {
    if timer_hz == 0 {
        return Err(DeadlineQueueError::InvalidTimerRate);
    }
    let numerator = u128::from(delta_ns)
        .checked_mul(u128::from(timer_hz))
        .ok_or(DeadlineQueueError::ArithmeticOverflow)?;
    let rounded = numerator
        .checked_add(NANOS_PER_SECOND - 1)
        .ok_or(DeadlineQueueError::ArithmeticOverflow)?
        / NANOS_PER_SECOND;
    let count = rounded.max(1);
    if count > u128::from(u32::MAX) {
        return Ok(ApicOneShot {
            initial_count: u32::MAX,
            reaches_deadline: false,
        });
    }
    Ok(ApicOneShot {
        initial_count: count as u32,
        reaches_deadline: true,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeadlineEntry {
    deadline_ns: u64,
    wake: BlockWakeKey,
}

#[derive(Clone, Copy)]
struct DeadlineSlot {
    generation: u32,
    entry: Option<DeadlineEntry>,
}

const EMPTY_SLOT: DeadlineSlot = DeadlineSlot {
    generation: 0,
    entry: None,
};

#[must_use = "deadline registrations must be cancelled or consumed by expiry"]
#[derive(Debug)]
pub(crate) struct DeadlineRegistration {
    domain: u64,
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineQueueError {
    Capacity,
    InvalidDeadline,
    ForeignRegistration,
    StaleRegistration,
    GenerationExhausted,
    InvalidTimerRate,
    ArithmeticOverflow,
}

pub(crate) struct DeadlineQueue<const CAPACITY: usize = DEADLINE_QUEUE_CAPACITY> {
    domain: u64,
    slots: [DeadlineSlot; CAPACITY],
}

impl<const CAPACITY: usize> DeadlineQueue<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_domain(),
            slots: [EMPTY_SLOT; CAPACITY],
        }
    }

    pub(crate) fn register(
        &mut self,
        deadline_ns: u64,
        wake: BlockWakeKey,
    ) -> Result<DeadlineRegistration, DeadlineQueueError> {
        if deadline_ns == DW_DEADLINE_NOW.0 || deadline_ns == DW_DEADLINE_INFINITE.0 {
            return Err(DeadlineQueueError::InvalidDeadline);
        }
        let (slot, entry) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.entry.is_none())
            .ok_or(DeadlineQueueError::Capacity)?;
        let slot = u16::try_from(slot).map_err(|_| DeadlineQueueError::Capacity)?;
        let generation = entry
            .generation
            .checked_add(1)
            .filter(|value| *value != 0)
            .ok_or(DeadlineQueueError::GenerationExhausted)?;
        entry.generation = generation;
        entry.entry = Some(DeadlineEntry { deadline_ns, wake });
        Ok(DeadlineRegistration {
            domain: self.domain,
            slot,
            generation,
        })
    }

    pub(crate) fn cancel(
        &mut self,
        registration: DeadlineRegistration,
    ) -> Result<BlockWakeKey, DeadlineQueueError> {
        if registration.domain != self.domain {
            return Err(DeadlineQueueError::ForeignRegistration);
        }
        let slot = self
            .slots
            .get_mut(usize::from(registration.slot))
            .ok_or(DeadlineQueueError::StaleRegistration)?;
        if slot.generation != registration.generation {
            return Err(DeadlineQueueError::StaleRegistration);
        }
        slot.entry
            .take()
            .map(|entry| entry.wake)
            .ok_or(DeadlineQueueError::StaleRegistration)
    }

    pub(crate) fn earliest(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|slot| slot.entry.map(|entry| entry.deadline_ns))
            .min()
    }

    pub(crate) fn expire(
        &mut self,
        now_ns: u64,
        output: &mut [Option<BlockWakeKey>; CAPACITY],
    ) -> usize {
        output.fill(None);
        let mut count = 0;
        for slot in &mut self.slots {
            if slot.entry.is_some_and(|entry| entry.deadline_ns <= now_ns) {
                let entry = slot.entry.take().expect("deadline entry was observed live");
                output[count] = Some(entry.wake);
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectRegistry;
    use crate::task::{CooperativeScheduler, ThreadKey};
    use deepwyrm_abi::DW_OBJECT_TYPE_THREAD;

    fn wake_key() -> BlockWakeKey {
        let mut registry = ObjectRegistry::<4>::new();
        let creation = registry.create(DW_OBJECT_TYPE_THREAD).unwrap();
        let thread = ThreadKey::from_object_id(creation.id());
        registry.cancel_creation(creation).unwrap();
        let scheduler = CooperativeScheduler::<1>::new();
        let reservation = scheduler.reserve(thread).unwrap();
        scheduler.commit(reservation).unwrap();
        assert_eq!(scheduler.schedule_next().unwrap().current, Some(thread));
        scheduler.block_current(thread).unwrap().0.into_wake_key()
    }

    #[test]
    fn deadline_classification_preserves_now_and_infinite_sentinels() {
        assert_eq!(classify_deadline(DW_DEADLINE_NOW), DeadlineClass::Now);
        assert_eq!(
            classify_deadline(DW_DEADLINE_INFINITE),
            DeadlineClass::Infinite
        );
        assert_eq!(classify_deadline(DwDeadline(9)), DeadlineClass::Finite(9));
    }

    #[test]
    fn queue_orders_expiry_and_cancel_is_generation_exact() {
        let mut queue = DeadlineQueue::<3>::new();
        let first = queue.register(30, wake_key()).unwrap();
        let _second = queue.register(10, wake_key()).unwrap();
        let _third = queue.register(20, wake_key()).unwrap();
        assert_eq!(queue.earliest(), Some(10));
        assert!(queue.register(40, wake_key()).is_err());
        queue.cancel(first).unwrap();
        let replacement = queue.register(40, wake_key()).unwrap();
        let mut expired = [None; 3];
        assert_eq!(queue.expire(20, &mut expired), 2);
        assert_eq!(queue.earliest(), Some(40));
        assert!(queue.cancel(replacement).is_ok());
    }

    #[test]
    fn lapic_programming_rounds_outward_and_handles_long_intervals() {
        let one = apic_one_shot_for_delta(1, 10_000_000).unwrap();
        assert_eq!(one.initial_count, 1);
        assert!(one.reaches_deadline);
        let exact = apic_one_shot_for_delta(1_000_000_000, 10_000_000).unwrap();
        assert_eq!(exact.initial_count, 10_000_000);
        let long = apic_one_shot_for_delta(u64::MAX - 1, 1_000_000_000).unwrap();
        assert_eq!(long.initial_count, u32::MAX);
        assert!(!long.reaches_deadline);
    }
}
