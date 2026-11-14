//! A FIFO of work owed to pool slots, each slot queued at most once (DW2
//! §10.10 item 1, the shape of §10.9's notice ring).
//!
//! A slot's flag is set when it is pushed and cleared only when its entry
//! is popped, so the ring never holds more entries than there are slots and
//! cannot overflow, whatever happens to the slot's occupant meanwhile. The
//! value pushed with a slot names its occupant then; pushing an already
//! queued slot replaces the value and keeps its place. A popped value may
//! be stale: the consumer revalidates it.

/// Up to `N` slots, each with a `T` naming what is owed.
pub(crate) struct SlotQueue<T: Copy, const N: usize> {
    ring: [u32; N],
    head: usize,
    len: usize,
    values: [Option<T>; N],
}

impl<T: Copy, const N: usize> SlotQueue<T, N> {
    pub(crate) const fn new() -> Self {
        Self {
            ring: [0; N],
            head: 0,
            len: 0,
            values: [None; N],
        }
    }

    /// Queues `slot` with `value`, at the tail unless it is already queued.
    /// A slot outside the pool is a caller bug.
    pub(crate) fn push(&mut self, slot: usize, value: T) {
        let queued = &mut self.values[slot];
        if queued.is_some() {
            *queued = Some(value);
            return;
        }
        *queued = Some(value);
        assert!(self.len < N, "a deduplicated slot queue cannot overflow");
        self.ring[(self.head + self.len) % N] = u32::try_from(slot).expect("pool slots fit u32");
        self.len += 1;
    }

    /// The oldest queued slot and its value.
    pub(crate) fn pop(&mut self) -> Option<(usize, T)> {
        if self.len == 0 {
            return None;
        }
        let slot = self.ring[self.head] as usize;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        let value = self.values[slot]
            .take()
            .expect("a queued slot holds its value until popped");
        Some((slot, value))
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_come_out_in_order_once_each() {
        let mut queue = SlotQueue::<u64, 4>::new();
        assert_eq!(queue.pop(), None);
        queue.push(2, 20);
        queue.push(0, 0);
        // Queued again: the value is replaced, the place kept.
        queue.push(2, 21);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), Some((2, 21)));
        assert_eq!(queue.pop(), Some((0, 0)));
        assert!(queue.is_empty());
    }

    #[test]
    fn a_popped_slot_requeued_goes_to_the_tail() {
        let mut queue = SlotQueue::<u64, 3>::new();
        queue.push(0, 1);
        queue.push(1, 2);
        let (slot, value) = queue.pop().unwrap();
        queue.push(slot, value);
        assert_eq!(queue.pop(), Some((1, 2)));
        assert_eq!(queue.pop(), Some((0, 1)));
    }

    #[test]
    fn every_slot_fits_and_the_ring_wraps() {
        let mut queue = SlotQueue::<usize, 3>::new();
        for round in 0..5 {
            for slot in 0..3 {
                queue.push(slot, slot + round);
                queue.push(slot, slot + round);
            }
            assert_eq!(queue.len(), 3);
            for slot in 0..3 {
                assert_eq!(queue.pop(), Some((slot, slot + round)));
            }
        }
        assert!(queue.is_empty());
    }
}
