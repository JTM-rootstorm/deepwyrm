//! Selector-33 wait registration capacity; this is not a public ABI quota.

// Registrations count items, including duplicate views of one endpoint, not
// blocked Threads. The current interactive product has simultaneous actor
// maxima of: consoled 12, UART 3, devmgr 4, registryd 6, wyrmsh 7, and the
// system-init controller 7. This is a demonstrated product-graph bound, not a
// production-wide quota; retain headroom for scheduling overlap at cleanup.
const REQUIRED_GRAPH_ITEMS: usize = 12 + 3 + 4 + 6 + 7 + 7;
pub(super) const WAITERS: usize = 64;
const _: () = assert!(WAITERS >= REQUIRED_GRAPH_ITEMS);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::object::{InternalRef, ObjectRegistry};
    use crate::task::{CooperativeScheduler, ThreadKey};
    use crate::wait::{WaitError, WaitRegistry};
    use deepwyrm_abi::{DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_THREAD, DW_SIGNAL_READABLE};

    fn exercise_graph<const CAPACITY: usize>() -> bool {
        let item_counts = [12, 3, 4, 6, 7, 7];
        let expected_items: usize = item_counts.iter().sum();
        let mut objects = ObjectRegistry::<64>::new();
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
    fn selector33_whole_wait_graph_exceeds_32_and_fits_with_cleanup() {
        assert!(!exercise_graph::<32>());
        assert!(exercise_graph::<WAITERS>());
    }
}
