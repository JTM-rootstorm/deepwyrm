extern crate std;

use deepwyrm_abi::{
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_EXCEPTION, DW_OBJECT_TYPE_INTERRUPT,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_NONE, DW_OBJECT_TYPE_PROCESS,
    DW_OBJECT_TYPE_TASK_GROUP,
};

use super::*;

fn counts<const CAPACITY: usize>(registry: &ObjectRegistry<CAPACITY>, id: ObjectId) -> (u32, u32) {
    let slot = registry.reference_slot(id).unwrap();
    match registry.slots[slot].state {
        SlotState::Live(live) => (live.handle_refs, live.internal_refs),
        other => panic!("expected live object, got {other:?}"),
    }
}

/// Every live slot's kept usage against a scan (DW2 §13.12 part a).
fn check<const CAPACITY: usize>(registry: &ObjectRegistry<CAPACITY>) {
    registry.assert_usage_matches_scan();
}

fn finish<const CAPACITY: usize>(
    registry: &mut ObjectRegistry<CAPACITY>,
    final_release: FinalRelease,
) {
    registry.complete_finalization(final_release).unwrap();
}

#[test]
fn create_activates_only_schema_live_types_and_honors_fixed_capacity() {
    let mut registry = ObjectRegistry::<1>::new();
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_NONE),
        Err(ObjectRegistryError::InvalidObjectType)
    );
    check(&registry);
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_EXCEPTION),
        Err(ObjectRegistryError::InvalidObjectType)
    );
    check(&registry);
    assert_eq!(
        registry.create(DwObjectType(0xfeed)),
        Err(ObjectRegistryError::InvalidObjectType)
    );
    check(&registry);

    for object_type in [DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_DEVICE_RESOURCE] {
        let creation = registry.create(object_type).unwrap();
        check(&registry);
        assert_eq!(counts(&registry, creation.id()), (0, 1));
        let final_release = registry.release_creation(creation).unwrap().unwrap();
        check(&registry);
        finish(&mut registry, final_release);
        check(&registry);
    }

    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, creation.id()), (0, 1));
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );
    check(&registry);

    let final_release = registry.release_creation(creation).unwrap().unwrap();
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);
}

#[test]
fn reference_classes_transition_and_retain_exactly() {
    let mut registry = ObjectRegistry::<2>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    check(&registry);
    let id = creation.id();
    assert_eq!(counts(&registry, id), (0, 1));

    let handle0 = registry.creation_into_handle(creation).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, id), (1, 0));
    let handle1 = registry.retain_handle(&handle0).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, id), (2, 0));
    let internal0 = registry.retain_internal_from_handle(&handle0).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, id), (2, 1));
    let internal1 = registry.retain_internal(&internal0).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, id), (2, 2));

    let internal2 = registry.handle_into_internal(handle1).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, id), (1, 3));
    let handle1 = registry.internal_into_handle(internal2).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, id), (2, 2));

    assert!(registry.release_internal(internal0).unwrap().is_none());
    check(&registry);
    assert!(registry.release_internal(internal1).unwrap().is_none());
    check(&registry);
    assert!(registry.release_handle(handle1).unwrap().is_none());
    check(&registry);
    let final_release = registry.release_handle(handle0).unwrap().unwrap();
    check(&registry);
    assert_eq!(final_release.id(), id);
    assert_eq!(final_release.object_type(), DW_OBJECT_TYPE_MEMORY_OBJECT);
    finish(&mut registry, final_release);
    check(&registry);
}

#[test]
fn finalizing_slot_is_not_reused_until_cleanup_completes() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let old_id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();
    check(&registry);
    let final_release = registry.release_handle(handle).unwrap().unwrap();
    check(&registry);
    let stale = HandleRef {
        id: old_id,
        object_type: DW_OBJECT_TYPE_PROCESS,
    };
    assert_eq!(
        registry.retain_handle(&stale),
        Err(ObjectRegistryError::StaleReference)
    );
    check(&registry);

    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);

    let replacement = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    assert_ne!(replacement.id(), old_id);
    let final_release = registry.release_creation(replacement).unwrap().unwrap();
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);
}

#[test]
fn foreign_registry_rejects_and_returns_consumed_reference() {
    let mut owner = ObjectRegistry::<1>::new();
    let mut foreign = ObjectRegistry::<1>::new();
    let creation = owner.create(DW_OBJECT_TYPE_TASK_GROUP).unwrap();
    check(&owner);
    let id = creation.id();

    let error = foreign.creation_into_handle(creation).unwrap_err();
    check(&foreign);
    assert_eq!(error.error(), ObjectRegistryError::ForeignReference);
    let creation = error.into_reference();
    assert_eq!(creation.id(), id);

    let handle = owner.creation_into_handle(creation).unwrap();
    check(&owner);
    let final_release = owner.release_handle(handle).unwrap().unwrap();
    check(&owner);
    finish(&mut owner, final_release);
    check(&owner);
}

#[test]
fn stale_identity_cannot_be_promoted_after_slot_reuse() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let old_id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();
    check(&registry);
    let final_release = registry.release_handle(handle).unwrap().unwrap();
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);

    let replacement = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let stale = HandleRef {
        id: old_id,
        object_type: DW_OBJECT_TYPE_PROCESS,
    };
    assert_eq!(
        registry.retain_handle(&stale),
        Err(ObjectRegistryError::StaleReference)
    );
    check(&registry);

    let final_release = registry.release_creation(replacement).unwrap().unwrap();
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);
}

#[test]
fn forged_wrong_class_or_type_fails_closed_without_count_change() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();
    check(&registry);

    let fake_internal = InternalRef {
        id,
        object_type: DW_OBJECT_TYPE_PROCESS,
    };
    let error = registry.release_internal(fake_internal).unwrap_err();
    check(&registry);
    assert_eq!(error.error(), ObjectRegistryError::ReferenceCountUnderflow);
    let _ = error.into_reference();
    assert_eq!(counts(&registry, id), (1, 0));

    let wrong_type = HandleRef {
        id,
        object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
    };
    assert_eq!(
        registry.retain_handle(&wrong_type),
        Err(ObjectRegistryError::ObjectTypeMismatch)
    );
    check(&registry);
    assert_eq!(counts(&registry, id), (1, 0));

    let final_release = registry.release_handle(handle).unwrap().unwrap();
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);
}

#[test]
fn both_reference_counters_fail_before_overflow() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();
    check(&registry);
    let slot = registry.reference_slot(id).unwrap();

    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    live.handle_refs = u32::MAX;
    assert_eq!(
        registry.retain_handle(&handle),
        Err(ObjectRegistryError::ReferenceCountExhausted)
    );
    check(&registry);
    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    assert_eq!(live.handle_refs, u32::MAX);
    live.handle_refs = 1;

    let internal = registry.retain_internal_from_handle(&handle).unwrap();
    check(&registry);
    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    live.internal_refs = u32::MAX;
    assert_eq!(
        registry.retain_internal_from_handle(&handle),
        Err(ObjectRegistryError::ReferenceCountExhausted)
    );
    check(&registry);
    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    assert_eq!(live.internal_refs, u32::MAX);
    live.internal_refs = 1;

    assert!(registry.release_internal(internal).unwrap().is_none());
    check(&registry);
    let final_release = registry.release_handle(handle).unwrap().unwrap();
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);
}

#[test]
fn generation_exhaustion_permanently_retires_the_slot() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let mut final_release = registry.release_creation(creation).unwrap().unwrap();
    check(&registry);
    let slot = registry.reference_slot(final_release.id()).unwrap();
    registry.slots[slot].generation = u32::MAX;
    final_release.id.raw = encode_object_id(slot, u32::MAX).unwrap();
    finish(&mut registry, final_release);
    check(&registry);

    assert_eq!(registry.slots[slot].state, SlotState::Retired);
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );
    check(&registry);
}

#[test]
fn final_release_can_complete_only_once() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let final_release = registry.release_creation(creation).unwrap().unwrap();
    check(&registry);
    let id = final_release.id();
    let object_type = final_release.object_type();
    finish(&mut registry, final_release);
    check(&registry);

    let duplicate = FinalRelease { id, object_type };
    let error = registry.complete_finalization(duplicate).unwrap_err();
    check(&registry);
    assert_eq!(error.error(), ObjectRegistryError::NotFinalizing);
    let _ = error.into_reference();
}

#[test]
fn creation_can_become_an_explicit_internal_owner() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    check(&registry);
    let id = creation.id();
    let internal = registry.creation_into_internal(creation).unwrap();
    check(&registry);
    assert_eq!(counts(&registry, id), (0, 1));
    let final_release = registry.release_internal(internal).unwrap().unwrap();
    check(&registry);
    finish(&mut registry, final_release);
    check(&registry);
}

#[test]
fn zero_capacity_registry_fails_closed() {
    let mut registry = ObjectRegistry::<0>::new();
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );
    check(&registry);
}

#[test]
fn memory_release_notices_are_deduplicated_and_judge_the_slot_when_popped() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    check(&registry);
    let first = creation.id;
    let owner = registry.creation_into_internal(creation).unwrap();
    check(&registry);
    let lease = registry.retain_internal(&owner).unwrap();
    check(&registry);
    let device = registry.retain_internal(&owner).unwrap();
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), None);
    check(&registry);

    // Two releases that leave no handle: one notice.
    assert_eq!(registry.release_internal(device).unwrap(), None);
    check(&registry);
    assert_eq!(registry.release_internal(lease).unwrap(), None);
    check(&registry);
    // A final release notes nothing; the queued notice outlives the object
    // and its slot's reuse.
    let final_release = registry.release_internal(owner).unwrap().unwrap();
    check(&registry);
    registry.complete_finalization(final_release).unwrap();
    check(&registry);
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    check(&registry);
    let second = creation.id;
    assert_ne!(first, second);
    let owner = registry.creation_into_internal(creation).unwrap();
    check(&registry);
    let to_handle = registry.retain_internal(&owner).unwrap();
    check(&registry);
    let handle = registry.internal_into_handle(to_handle).unwrap();
    check(&registry);
    // The live notice is judged by the slot's new occupant.
    assert_eq!(registry.pop_memory_notice(), Some(Some(second)));
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), None);
    check(&registry);

    // With a handle open nothing is noted; closing it is.
    let extra = registry.retain_internal(&owner).unwrap();
    check(&registry);
    assert_eq!(registry.release_internal(extra).unwrap(), None);
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), None);
    check(&registry);
    assert_eq!(registry.release_handle(handle).unwrap(), None);
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), Some(Some(second)));
    check(&registry);

    // A requeue of a stale identity is ignored; of a live one, kept once.
    registry.requeue_memory_notice(first);
    check(&registry);
    registry.requeue_memory_notice(second);
    check(&registry);
    registry.requeue_memory_notice(second);
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), Some(Some(second)));
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), None);
    check(&registry);

    // A notice for a slot that no longer holds a MemoryObject pops empty.
    let lease = registry.retain_internal(&owner).unwrap();
    check(&registry);
    assert_eq!(registry.release_internal(lease).unwrap(), None);
    check(&registry);
    let final_release = registry.release_internal(owner).unwrap().unwrap();
    check(&registry);
    registry.complete_finalization(final_release).unwrap();
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), Some(None));
    check(&registry);
    assert_eq!(registry.pop_memory_notice(), None);
    check(&registry);
}

mod usage {
    //! Kept usage (DW2 §13.12 part a): each write changes the groups its
    //! tag names while they hold their slots, and the scan agrees.

    use std::vec::Vec;

    use deepwyrm_abi::{
        DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT, DW_OBJECT_TYPE_INTERRUPT,
        DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP,
        DW_OBJECT_TYPE_THREAD, DW_OBJECT_TYPE_TIMER,
    };

    use super::super::charge::{ChargeTag, MAX_LIMITED_ANCESTORS, OBJECT_CLASSES, object_class};
    use super::*;

    const MEMORY: usize = match object_class(DW_OBJECT_TYPE_MEMORY_OBJECT) {
        Some(class) => class,
        None => panic!("MemoryObject is a classed type"),
    };

    fn tag(groups: &[ObjectId]) -> ChargeTag {
        let mut tag = ChargeTag::EMPTY;
        for &group in groups {
            assert!(tag.push(group));
        }
        tag
    }

    /// A live object of `object_type` charged to `charge` with `pages`, as
    /// the create adapters leave one.
    fn charged<const CAPACITY: usize>(
        registry: &mut ObjectRegistry<CAPACITY>,
        object_type: DwObjectType,
        charge: ChargeTag,
        pages: u64,
    ) -> HandleRef {
        let creation = registry.create(object_type).unwrap();
        let handle = registry.creation_into_handle(creation).unwrap();
        registry.set_charge_tag(handle.id(), charge).unwrap();
        registry.set_charge_pages(handle.id(), pages).unwrap();
        check(registry);
        handle
    }

    fn group<const CAPACITY: usize>(
        registry: &mut ObjectRegistry<CAPACITY>,
        above: ChargeTag,
    ) -> HandleRef {
        charged(registry, DW_OBJECT_TYPE_TASK_GROUP, above, 0)
    }

    /// Closes `handle`, its last reference, and completes its release.
    fn close_and_release<const CAPACITY: usize>(
        registry: &mut ObjectRegistry<CAPACITY>,
        handle: HandleRef,
    ) {
        let last = registry.release_handle(handle).unwrap().unwrap();
        check(registry);
        registry.complete_finalization(last).unwrap();
        check(registry);
    }

    #[test]
    fn a_tag_naming_a_dead_group_changes_nothing() {
        let mut registry = ObjectRegistry::<8>::new();
        let parent = group(&mut registry, ChargeTag::EMPTY);
        let child = group(&mut registry, tag(&[parent.id()]));
        let both = tag(&[child.id(), parent.id()]);
        let object = charged(&mut registry, DW_OBJECT_TYPE_MEMORY_OBJECT, both, 7);
        assert_eq!(registry.charged_pages(child.id()), 7);
        assert_eq!(registry.charged(child.id(), MEMORY), 1);
        let child_id = child.id();
        close_and_release(&mut registry, child);
        assert_eq!(registry.charged_pages(child_id), 0);
        assert_eq!(registry.charged(child_id, MEMORY), 0);
        assert_eq!(registry.charged_pages(parent.id()), 7);

        // Every write through the dead group's tag reaches only the parent.
        registry.set_charge_pages(object.id(), 30).unwrap();
        assert!(registry.reserve_pages(object.id(), both, 5));
        let late = charged(&mut registry, DW_OBJECT_TYPE_CHANNEL, both, 0);
        check(&registry);
        assert_eq!(registry.charged_pages(child_id), 0);
        assert_eq!(registry.charged_pages(parent.id()), 35);
        assert_eq!(
            registry.charged(parent.id(), object_class(DW_OBJECT_TYPE_CHANNEL).unwrap()),
            1
        );
        registry.release_reserved_pages(object.id());
        close_and_release(&mut registry, object);
        close_and_release(&mut registry, late);
        // The child group itself, charged to the parent, left with its
        // slot's release; nothing is charged to the parent now.
        for class in 0..OBJECT_CLASSES {
            assert_eq!(registry.charged(parent.id(), class), 0);
        }
        assert_eq!(registry.charged_pages(parent.id()), 0);
        close_and_release(&mut registry, parent);
    }

    #[test]
    fn a_slot_reused_by_a_new_group_starts_at_zero() {
        let mut registry = ObjectRegistry::<2>::new();
        let old = group(&mut registry, ChargeTag::EMPTY);
        let old_id = old.id();
        let object = charged(
            &mut registry,
            DW_OBJECT_TYPE_MEMORY_OBJECT,
            tag(&[old_id]),
            9,
        );
        assert!(registry.reserve_owed_backing_pages(1, tag(&[old_id]), 4));
        assert_eq!(registry.charged_pages(old_id), 13);
        assert_eq!(registry.finalizing_pages_of(old_id), 4);
        close_and_release(&mut registry, old);
        check(&registry);

        let new = group(&mut registry, ChargeTag::EMPTY);
        let slot = registry.slot_of(new.id()).unwrap();
        assert_eq!(registry.slot_of(old_id), Some(slot));
        assert_ne!(new.id(), old_id);
        assert_eq!(registry.charged_pages(new.id()), 0);
        assert_eq!(registry.finalizing_pages_of(new.id()), 0);
        for class in 0..OBJECT_CLASSES {
            assert_eq!(registry.charged(new.id(), class), 0);
            assert_eq!(registry.finalizing_objects_of(new.id(), class), 0);
        }
        // The old group's object and backing leave without touching it.
        registry.lower_owed_backing_pages(1, 4).unwrap();
        registry.end_owed_backing_reservation(1);
        close_and_release(&mut registry, object);
        assert_eq!(registry.charged_pages(new.id()), 0);
        close_and_release(&mut registry, new);
    }

    #[test]
    fn finalizing_figures_rise_at_close_and_fall_with_each_step() {
        let mut registry = ObjectRegistry::<4>::new();
        let owner = group(&mut registry, ChargeTag::EMPTY);
        let charge = tag(&[owner.id()]);
        let object = charged(&mut registry, DW_OBJECT_TYPE_MEMORY_OBJECT, charge, 10);
        let id = object.id();
        assert_eq!(registry.finalizing_pages_of(owner.id()), 0);
        assert_eq!(registry.finalizing_objects_of(owner.id(), MEMORY), 0);

        let last = registry.release_handle(object).unwrap().unwrap();
        check(&registry);
        assert_eq!(registry.charged_pages(owner.id()), 10);
        assert_eq!(registry.charged(owner.id(), MEMORY), 1);
        assert_eq!(registry.finalizing_pages_of(owner.id()), 10);
        assert_eq!(registry.finalizing_objects_of(owner.id(), MEMORY), 1);

        for (step, left) in [(3, 7), (4, 3), (3, 0)] {
            registry.lower_finalizing_charge_pages(id, step).unwrap();
            check(&registry);
            assert_eq!(registry.charged_pages(owner.id()), left);
            assert_eq!(registry.finalizing_pages_of(owner.id()), left as u64);
            assert_eq!(registry.finalizing_objects_of(owner.id(), MEMORY), 1);
        }
        assert_eq!(
            registry.lower_finalizing_charge_pages(id, 1),
            Err(ObjectRegistryError::ReferenceCountUnderflow)
        );
        registry.complete_finalization(last).unwrap();
        check(&registry);
        assert_eq!(registry.charged(owner.id(), MEMORY), 0);
        assert_eq!(registry.finalizing_objects_of(owner.id(), MEMORY), 0);
        close_and_release(&mut registry, owner);
    }

    /// DW2 §13.19 item 1: whether a slot is free, and how many owed
    /// backings hold one, across a reservation, its passing to an owed
    /// backing, and the ends of both.
    #[test]
    fn reservation_slots_free_and_held_by_owed_backings_are_counted() {
        let mut registry = ObjectRegistry::<{ RESERVATION_THREADS + 1 }>::new();
        let owner = group(&mut registry, ChargeTag::EMPTY);
        let charge = tag(&[owner.id()]);
        let threads: Vec<_> = (0..RESERVATION_THREADS)
            .map(|_| charged(&mut registry, DW_OBJECT_TYPE_THREAD, ChargeTag::EMPTY, 0))
            .collect();
        assert!(registry.reservation_slot_free());
        assert_eq!(registry.owed_backing_reservations(), 0);

        // Every slot held by Threads' creates: none free, none owed.
        for thread in &threads {
            assert!(registry.reserve_pages(thread.id(), charge, 1));
        }
        check(&registry);
        assert!(!registry.reservation_slot_free());
        assert_eq!(registry.owed_backing_reservations(), 0);

        // Two passed to owed backings, in place: still none free.
        assert!(registry.rekey_reservation_to_owed_backing(threads[0].id(), 70, 1));
        assert!(registry.rekey_reservation_to_owed_backing(threads[1].id(), 71, 0));
        check(&registry);
        assert!(!registry.reservation_slot_free());
        assert_eq!(registry.owed_backing_reservations(), 2);

        // A Thread's create re-reserving keeps its one slot.
        assert!(registry.reserve_pages(threads[2].id(), charge, 3));
        assert!(!registry.reservation_slot_free());
        assert_eq!(registry.owed_backing_reservations(), 2);

        // One owed backing's reservation ends: a slot is free.
        registry.end_owed_backing_reservation(70);
        check(&registry);
        assert!(registry.reservation_slot_free());
        assert_eq!(registry.owed_backing_reservations(), 1);
        // A rolled-back create's backing takes it.
        assert!(registry.reserve_owed_backing_pages(72, charge, 1));
        assert!(!registry.reservation_slot_free());
        assert_eq!(registry.owed_backing_reservations(), 2);

        // A Thread's reservation ends: free again, owed unchanged.
        registry.release_reserved_pages(threads[3].id());
        assert!(registry.reservation_slot_free());
        assert_eq!(registry.owed_backing_reservations(), 2);

        registry.end_owed_backing_reservation(71);
        registry.end_owed_backing_reservation(72);
        for thread in &threads {
            registry.release_reserved_pages(thread.id());
        }
        check(&registry);
        assert_eq!(registry.owed_backing_reservations(), 0);
        assert_eq!(registry.charged_pages(owner.id()), 0);
        for thread in threads {
            close_and_release(&mut registry, thread);
        }
        close_and_release(&mut registry, owner);
    }

    #[test]
    fn an_owed_backing_s_reservation_is_finalizing_and_a_create_s_is_not() {
        let mut registry = ObjectRegistry::<4>::new();
        let owner = group(&mut registry, ChargeTag::EMPTY);
        let thread = charged(&mut registry, DW_OBJECT_TYPE_THREAD, ChargeTag::EMPTY, 0);
        let charge = tag(&[owner.id()]);

        assert!(registry.reserve_pages(thread.id(), charge, 12));
        check(&registry);
        assert_eq!(registry.charged_pages(owner.id()), 12);
        assert_eq!(registry.finalizing_pages_of(owner.id()), 0);

        // The create is abandoned with 8 frames held: its owed backing.
        assert!(registry.rekey_reservation_to_owed_backing(thread.id(), 50, 8));
        check(&registry);
        assert_eq!(registry.charged_pages(owner.id()), 8);
        assert_eq!(registry.finalizing_pages_of(owner.id()), 8);

        // One reserved directly, as a rolled-back create's.
        assert!(registry.reserve_owed_backing_pages(51, charge, 5));
        assert!(registry.reserve_pages(thread.id(), charge, 2));
        check(&registry);
        assert_eq!(registry.charged_pages(owner.id()), 15);
        assert_eq!(registry.finalizing_pages_of(owner.id()), 13);

        registry.lower_owed_backing_pages(50, 6).unwrap();
        check(&registry);
        assert_eq!(registry.finalizing_pages_of(owner.id()), 7);
        registry.release_reserved_pages(thread.id());
        check(&registry);
        assert_eq!(registry.charged_pages(owner.id()), 7);
        assert_eq!(registry.finalizing_pages_of(owner.id()), 7);
        registry.end_owed_backing_reservation(50);
        registry.end_owed_backing_reservation(51);
        check(&registry);
        assert_eq!(registry.charged_pages(owner.id()), 0);
        assert_eq!(registry.finalizing_pages_of(owner.id()), 0);
        close_and_release(&mut registry, thread);
        close_and_release(&mut registry, owner);
    }

    #[test]
    fn the_kernel_check_counts_groups_and_finds_a_wrong_figure() {
        let mut registry = ObjectRegistry::<4>::new();
        let owner = group(&mut registry, ChargeTag::EMPTY);
        let other = group(&mut registry, ChargeTag::EMPTY);
        let _object = charged(
            &mut registry,
            DW_OBJECT_TYPE_EVENT,
            tag(&[owner.id(), other.id()]),
            3,
        );
        assert_eq!(registry.usage_mismatches(), (2, 0));
        let slot = registry.slot_of(owner.id()).unwrap();
        registry.usage_pages[slot] += 1;
        registry.finalizing_objects[slot][MEMORY] = 1;
        assert_eq!(registry.usage_mismatches(), (2, 2));
    }

    #[test]
    fn a_group_that_ends_with_tagged_objects_alive_is_compared_at_its_end() {
        let mut registry = ObjectRegistry::<6>::new();
        let parent = group(&mut registry, ChargeTag::EMPTY);
        let child = group(&mut registry, tag(&[parent.id()]));
        let charge = tag(&[child.id(), parent.id()]);
        let object = charged(&mut registry, DW_OBJECT_TYPE_MEMORY_OBJECT, charge, 6);
        assert!(registry.reserve_owed_backing_pages(7, charge, 2));
        assert_eq!(registry.usage_mismatches(), (2, 0));
        close_and_release(&mut registry, child);
        assert_eq!((registry.ended_groups, registry.ended_mismatches), (1, 0));
        // One live group now, one compared at its end.
        assert_eq!(registry.usage_mismatches(), (2, 0));
        // An object that is not a group adds nothing when it ends.
        registry.end_owed_backing_reservation(7);
        close_and_release(&mut registry, object);
        assert_eq!((registry.ended_groups, registry.ended_mismatches), (1, 0));
        close_and_release(&mut registry, parent);
        assert_eq!(registry.usage_mismatches(), (2, 0));
    }

    #[test]
    fn a_figure_wrong_when_its_group_ends_is_counted_then() {
        let mut registry = ObjectRegistry::<4>::new();
        let owner = group(&mut registry, ChargeTag::EMPTY);
        let _object = charged(&mut registry, DW_OBJECT_TYPE_EVENT, tag(&[owner.id()]), 3);
        let slot = registry.slot_of(owner.id()).unwrap();
        registry.finalizing_pages[slot] = 5;
        registry.usage_objects[slot][MEMORY] = 2;
        let last = registry.release_handle(owner).unwrap().unwrap();
        registry.complete_finalization(last).unwrap();
        assert_eq!((registry.ended_groups, registry.ended_mismatches), (1, 2));
        assert_eq!(registry.usage_mismatches(), (1, 2));
        // The slot's entries were zeroed with it: nothing is left wrong.
        assert_eq!(registry.finalizing_pages[slot], 0);
        assert_eq!(registry.usage_objects[slot], [0; OBJECT_CLASSES]);
    }

    #[test]
    #[should_panic(expected = "release: a group's usage pages 0 cannot Remove 3")]
    fn a_figure_that_would_fall_below_zero_panics_naming_the_write() {
        let mut registry = ObjectRegistry::<4>::new();
        let owner = group(&mut registry, ChargeTag::EMPTY);
        let object = charged(&mut registry, DW_OBJECT_TYPE_EVENT, tag(&[owner.id()]), 3);
        let slot = registry.slot_of(owner.id()).unwrap();
        registry.usage_pages[slot] = 0;
        let last = registry.release_handle(object).unwrap().unwrap();
        let _ = registry.complete_finalization(last);
    }

    /// A small xorshift: the randomised test needs no external crate.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }

        fn pick<T>(&mut self, items: &[T]) -> Option<usize> {
            (!items.is_empty()).then(|| self.below(items.len()))
        }
    }

    const TYPES: [DwObjectType; 8] = [
        DW_OBJECT_TYPE_CHANNEL,
        DW_OBJECT_TYPE_EVENT,
        DW_OBJECT_TYPE_TIMER,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        DW_OBJECT_TYPE_THREAD,
        DW_OBJECT_TYPE_PROCESS,
        DW_OBJECT_TYPE_TASK_GROUP,
        DW_OBJECT_TYPE_INTERRUPT,
    ];

    /// Creates, charges, closes, stepped finalization, reservations made,
    /// moved to owed backings, lowered and ended, and groups dying with
    /// tagged objects left, in a seeded random order: after every step
    /// every live slot's kept figures equal the scan's.
    #[test]
    fn kept_usage_matches_the_scan_through_random_registry_operations() {
        for seed in [
            0x9e37_79b9_7f4a_7c15u64,
            0x0123_4567_89ab_cdef,
            0xdead_beef_cafe_f00d,
        ] {
            random_run(seed, 4_000);
        }
    }

    struct Live {
        handle: HandleRef,
        /// For a group: the tag its children are charged to.
        children: Option<ChargeTag>,
    }

    fn random_run(seed: u64, steps: usize) {
        let mut rng = XorShift(seed);
        let mut registry = ObjectRegistry::<48>::new();
        // Every tag a group ever handed out, kept after it dies.
        let mut tags: Vec<ChargeTag> = Vec::from([ChargeTag::EMPTY]);
        let mut live: Vec<Live> = Vec::new();
        let mut finalizing: Vec<(FinalRelease, u64)> = Vec::new();
        // Untagged Threads keying create reservations, and what each holds.
        let mut threads: Vec<(HandleRef, Option<u64>)> = Vec::new();
        for _ in 0..4 {
            let handle = charged(&mut registry, DW_OBJECT_TYPE_THREAD, ChargeTag::EMPTY, 0);
            threads.push((handle, None));
        }
        let mut owed: Vec<(u64, u64)> = Vec::new();
        let mut next_key = 1u64;
        let mut deepest = 0usize;
        // TaskGroup slots released, each compared at its end.
        let mut released = 0usize;

        for _ in 0..steps {
            match rng.below(17) {
                // A group, nested under a random live group or the root.
                0 | 1 => {
                    let groups: Vec<ChargeTag> =
                        live.iter().filter_map(|object| object.children).collect();
                    let above = match rng.pick(&groups) {
                        Some(index) if rng.below(8) != 0 => groups[index],
                        _ => ChargeTag::EMPTY,
                    };
                    let Ok(creation) = registry.create(DW_OBJECT_TYPE_TASK_GROUP) else {
                        continue;
                    };
                    let handle = registry.creation_into_handle(creation).unwrap();
                    registry.set_charge_tag(handle.id(), above).unwrap();
                    let mut children = above;
                    // A limited group joins its children's tag while it
                    // has room; an unlimited one does not.
                    if rng.below(4) != 0 && children.push(handle.id()) {
                        tags.push(children);
                    }
                    deepest = deepest.max(children.groups().count());
                    live.push(Live {
                        handle,
                        children: Some(children),
                    });
                }
                // An object charged to a tag, live or of dead groups.
                2 | 3 => {
                    let charge = tags[rng.below(tags.len())];
                    let object_type = TYPES[rng.below(TYPES.len())];
                    let Ok(creation) = registry.create(object_type) else {
                        continue;
                    };
                    let handle = registry.creation_into_handle(creation).unwrap();
                    registry.set_charge_tag(handle.id(), charge).unwrap();
                    if object_type == DW_OBJECT_TYPE_MEMORY_OBJECT {
                        registry
                            .set_charge_pages(handle.id(), rng.next() % 64)
                            .unwrap();
                    }
                    live.push(Live {
                        handle,
                        // An unlimited group: its children carry its tag.
                        children: (object_type == DW_OBJECT_TYPE_TASK_GROUP).then_some(charge),
                    });
                }
                // A weight raised (a commit) or lowered (a release on unmap).
                4 => {
                    let Some(index) = rng.pick(&live) else {
                        continue;
                    };
                    let id = live[index].handle.id();
                    let (_, pages) = registry.charge(id).unwrap();
                    let pages = if rng.below(2) == 0 {
                        pages + rng.next() % 32
                    } else {
                        pages - pages.min(rng.next() % 32)
                    };
                    registry.set_charge_pages(id, pages).unwrap();
                }
                // A close: the object, or a group with whatever it tags,
                // passes to finalizing.
                5 => {
                    let Some(index) = rng.pick(&live) else {
                        continue;
                    };
                    let Live { handle, .. } = live.swap_remove(index);
                    let (_, pages) = registry.charge(handle.id()).unwrap();
                    let last = registry.release_handle(handle).unwrap().unwrap();
                    finalizing.push((last, pages));
                }
                // An owed finalize step frees some frames.
                6 => {
                    let Some(index) = rng.pick(&finalizing) else {
                        continue;
                    };
                    let (last, left) = &mut finalizing[index];
                    let freed = (*left).min(1 + rng.next() % 16);
                    registry
                        .lower_finalizing_charge_pages(last.id(), freed)
                        .unwrap();
                    *left -= freed;
                }
                // A finalization completes and its slot is released.
                7 | 8 => {
                    let Some(index) = rng.pick(&finalizing) else {
                        continue;
                    };
                    let (last, _) = finalizing.swap_remove(index);
                    if last.object_type() == DW_OBJECT_TYPE_TASK_GROUP {
                        released += 1;
                    }
                    registry.complete_finalization(last).unwrap();
                }
                // A create reserves its pages (replacing what it held).
                9 => {
                    let index = rng.below(threads.len());
                    let pages = rng.next() % 40;
                    let charge = tags[rng.below(tags.len())];
                    let thread = threads[index].0.id();
                    if registry.reserve_pages(thread, charge, pages) {
                        threads[index].1 = Some(pages);
                    } else {
                        threads[index].1 = None;
                    }
                }
                // A create ends its reservation, or passes it to its owed
                // backing.
                10 => {
                    let index = rng.below(threads.len());
                    let thread = threads[index].0.id();
                    match (threads[index].1.take(), rng.below(2)) {
                        (Some(held), 0) => {
                            let pages = held.min(rng.next() % 40);
                            assert!(
                                registry.rekey_reservation_to_owed_backing(thread, next_key, pages)
                            );
                            owed.push((next_key, pages));
                            next_key += 1;
                        }
                        _ => registry.release_reserved_pages(thread),
                    }
                }
                // A rolled-back create's backing is reserved directly.
                11 => {
                    let charge = tags[rng.below(tags.len())];
                    let pages = rng.next() % 40;
                    if registry.reserve_owed_backing_pages(next_key, charge, pages) {
                        owed.push((next_key, pages));
                        next_key += 1;
                    }
                }
                // A live object charged to another tag, as a test fixture
                // does to an untagged Process.
                12 => {
                    let Some(index) = rng.pick(&live) else {
                        continue;
                    };
                    let charge = tags[rng.below(tags.len())];
                    registry
                        .set_charge_tag(live[index].handle.id(), charge)
                        .unwrap();
                }
                // A create charged and then cancelled before it is bound.
                13 => {
                    let charge = tags[rng.below(tags.len())];
                    let object_type = TYPES[rng.below(TYPES.len())];
                    let Ok(creation) = registry.create(object_type) else {
                        continue;
                    };
                    if object_type == DW_OBJECT_TYPE_TASK_GROUP {
                        released += 1;
                    }
                    registry.set_charge_tag(creation.id(), charge).unwrap();
                    registry
                        .set_charge_pages(creation.id(), rng.next() % 8)
                        .unwrap();
                    check(&registry);
                    registry.cancel_creation(creation).unwrap();
                }
                // An owed backing frees some runs, or its root.
                _ => {
                    let Some(index) = rng.pick(&owed) else {
                        continue;
                    };
                    let (key, left) = &mut owed[index];
                    let freed = (*left).min(rng.next() % 16);
                    registry.lower_owed_backing_pages(*key, freed).unwrap();
                    *left -= freed;
                    if *left == 0 || rng.below(3) == 0 {
                        let (key, _) = owed.swap_remove(index);
                        registry.end_owed_backing_reservation(key);
                    }
                }
            }
            check(&registry);
        }
        let groups = live
            .iter()
            .filter(|object| object.handle.object_type() == DW_OBJECT_TYPE_TASK_GROUP)
            .count();
        assert_eq!(registry.ended_mismatches, 0);
        assert_eq!(registry.ended_groups, released);
        assert!(released > 0, "the run ended groups");
        assert_eq!(registry.usage_mismatches(), (groups + released, 0));
        assert_eq!(
            deepest, MAX_LIMITED_ANCESTORS,
            "the run reached the deepest tag"
        );
    }
}
