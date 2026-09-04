//! Selector-32 wait registration capacity; this is not a public ABI quota.

// Registrations count items, including duplicate views of one endpoint, not
// blocked Threads. Consoled owns 9 items, or 10 with queued stdin; UART owns 3,
// devmgr 3, registryd at least 3, console-echo 1, and init's Timer 1.
// This is a demonstrated graph lower bound, not a maximum over all recovery
// interleavings. Keep useful headroom for the bounded product graph.
const REQUIRED_GRAPH_ITEMS: usize = 10 + 3 + 3 + 3 + 1 + 1;
pub(super) const WAITERS: usize = 32;
const _: () = assert!(WAITERS >= REQUIRED_GRAPH_ITEMS);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::object::{InternalRef, ObjectRegistry};
    use crate::task::{CooperativeScheduler, ThreadKey};
    use crate::wait::{WaitError, WaitRegistry};
    use deepwyrm_abi::{DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_THREAD, DW_SIGNAL_READABLE};

    // Exercise the real registration and generation-cancellation machinery.
    // Sources are inert Channel pins: readiness production and actor execution
    // belong to the paired live gate, not this capacity regression.
    fn exercise_graph<const CAPACITY: usize>(stdin_queued: bool) -> bool {
        let item_counts = [9 + usize::from(stdin_queued), 3, 3, 3, 1, 1];
        let expected_items: usize = item_counts.iter().sum();
        let mut objects = ObjectRegistry::<32>::new();
        let waits = WaitRegistry::<CAPACITY>::new();
        let scheduler = CooperativeScheduler::<6>::new();
        let mut sources = std::vec::Vec::new();
        let mut threads = std::vec::Vec::new();
        for count in item_counts {
            let thread = objects.create(DW_OBJECT_TYPE_THREAD).unwrap();
            let key = ThreadKey::from_object_id(thread.id());
            let reservation = scheduler.reserve(key).unwrap();
            scheduler.commit(reservation).unwrap();
            threads.push(thread);
            let actor_sources: std::vec::Vec<InternalRef> = (0..count)
                .map(|_| {
                    let creation = objects.create(DW_OBJECT_TYPE_CHANNEL).unwrap();
                    objects.creation_into_internal(creation).unwrap()
                })
                .collect();
            sources.push(actor_sources);
        }

        let mut complete = true;
        // Reuse the same registry and scheduler to catch leaked registrations
        // or object pins across successive wait generations.
        for _ in 0..3 {
            let mut generations = std::vec::Vec::new();
            let mut registered = 0;
            scheduler.schedule_next().unwrap();
            for (thread, actor_sources) in threads.iter().zip(&sources) {
                let key = ThreadKey::from_object_id(thread.id());
                let (blocked, _) = scheduler.block_current(key).unwrap();
                let wake = blocked.into_wake_key();
                let mut actor_registered = 0;
                for (index, source) in actor_sources.iter().enumerate() {
                    let pin = objects.retain_internal(source).unwrap();
                    match waits.register(pin, DW_SIGNAL_READABLE, index as u32, key, wake) {
                        Ok(_) => {
                            actor_registered += 1;
                            registered += 1;
                        }
                        Err(failure) => {
                            assert_eq!(failure.error(), WaitError::Capacity);
                            assert!(
                                objects
                                    .release_internal(failure.into_pin())
                                    .unwrap()
                                    .is_none()
                            );
                            complete = false;
                            break;
                        }
                    }
                }
                generations.push((wake, actor_registered));
            }
            assert_eq!(waits.len(), registered);
            assert_eq!(registered, expected_items.min(CAPACITY));
            let mut released = 0;
            for (wake, count) in generations {
                let cancelled = waits.cancel_generation(wake);
                assert_eq!(cancelled.len(), 0);
                assert_eq!(cancelled.pin_len(), count);
                let (_, pins) = cancelled.into_parts();
                for pin in pins.into_iter().flatten() {
                    assert!(objects.release_internal(pin).unwrap().is_none());
                    released += 1;
                }
                assert_eq!(waits.cancel_generation(wake).pin_len(), 0);
                scheduler.wake(wake).unwrap();
            }
            assert_eq!(released, registered);
            assert_eq!(waits.len(), 0);
        }
        // Final release must succeed for every source: a leaked registration
        // pin would leave an internal reference and fail this check.
        for source in sources.into_iter().flatten() {
            let final_release = objects.release_internal(source).unwrap().unwrap();
            objects.complete_finalization(final_release).unwrap();
        }
        for thread in threads {
            objects.cancel_creation(thread).unwrap();
        }
        complete
    }

    #[test]
    fn selector32_whole_wait_graph_exceeds_16_and_fits_with_cleanup() {
        for stdin_queued in [false, true] {
            assert!(!exercise_graph::<16>(stdin_queued));
            assert!(exercise_graph::<WAITERS>(stdin_queued));
        }
    }
}
