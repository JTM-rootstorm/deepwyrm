extern crate std;

use deepwyrm_abi::{
    DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_NONE,
    DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP,
};

use super::*;

fn counts<const CAPACITY: usize>(registry: &ObjectRegistry<CAPACITY>, id: ObjectId) -> (u32, u32) {
    let slot = registry.reference_slot(id).unwrap();
    match registry.slots[slot].state {
        SlotState::Live(live) => (live.handle_refs, live.internal_refs),
        other => panic!("expected live object, got {other:?}"),
    }
}

fn finish<const CAPACITY: usize>(
    registry: &mut ObjectRegistry<CAPACITY>,
    final_release: FinalRelease,
) {
    registry.complete_finalization(final_release).unwrap();
}

#[test]
fn create_rejects_nonlive_types_and_honors_fixed_capacity() {
    let mut registry = ObjectRegistry::<1>::new();
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_NONE),
        Err(ObjectRegistryError::InvalidObjectType)
    );
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_INTERRUPT),
        Err(ObjectRegistryError::InvalidObjectType)
    );
    assert_eq!(
        registry.create(DwObjectType(0xfeed)),
        Err(ObjectRegistryError::InvalidObjectType)
    );
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    assert_eq!(counts(&registry, creation.id()), (0, 1));
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );

    let final_release = registry.release_creation(creation).unwrap().unwrap();
    finish(&mut registry, final_release);
}

#[test]
fn reference_classes_transition_and_retain_exactly() {
    let mut registry = ObjectRegistry::<2>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let id = creation.id();
    assert_eq!(counts(&registry, id), (0, 1));

    let handle0 = registry.creation_into_handle(creation).unwrap();
    assert_eq!(counts(&registry, id), (1, 0));
    let handle1 = registry.retain_handle(&handle0).unwrap();
    assert_eq!(counts(&registry, id), (2, 0));
    let internal0 = registry.retain_internal_from_handle(&handle0).unwrap();
    assert_eq!(counts(&registry, id), (2, 1));
    let internal1 = registry.retain_internal(&internal0).unwrap();
    assert_eq!(counts(&registry, id), (2, 2));

    let internal2 = registry.handle_into_internal(handle1).unwrap();
    assert_eq!(counts(&registry, id), (1, 3));
    let handle1 = registry.internal_into_handle(internal2).unwrap();
    assert_eq!(counts(&registry, id), (2, 2));

    assert!(registry.release_internal(internal0).unwrap().is_none());
    assert!(registry.release_internal(internal1).unwrap().is_none());
    assert!(registry.release_handle(handle1).unwrap().is_none());
    let final_release = registry.release_handle(handle0).unwrap().unwrap();
    assert_eq!(final_release.id(), id);
    assert_eq!(final_release.object_type(), DW_OBJECT_TYPE_MEMORY_OBJECT);
    finish(&mut registry, final_release);
}

#[test]
fn finalizing_slot_is_not_reused_until_cleanup_completes() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let old_id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();
    let final_release = registry.release_handle(handle).unwrap().unwrap();
    let stale = HandleRef {
        id: old_id,
        object_type: DW_OBJECT_TYPE_PROCESS,
    };
    assert_eq!(
        registry.retain_handle(&stale),
        Err(ObjectRegistryError::StaleReference)
    );

    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );
    finish(&mut registry, final_release);

    let replacement = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    assert_ne!(replacement.id(), old_id);
    let final_release = registry.release_creation(replacement).unwrap().unwrap();
    finish(&mut registry, final_release);
}

#[test]
fn foreign_registry_rejects_and_returns_consumed_reference() {
    let mut owner = ObjectRegistry::<1>::new();
    let mut foreign = ObjectRegistry::<1>::new();
    let creation = owner.create(DW_OBJECT_TYPE_TASK_GROUP).unwrap();
    let id = creation.id();

    let error = foreign.creation_into_handle(creation).unwrap_err();
    assert_eq!(error.error(), ObjectRegistryError::ForeignReference);
    let creation = error.into_reference();
    assert_eq!(creation.id(), id);

    let handle = owner.creation_into_handle(creation).unwrap();
    let final_release = owner.release_handle(handle).unwrap().unwrap();
    finish(&mut owner, final_release);
}

#[test]
fn stale_identity_cannot_be_promoted_after_slot_reuse() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let old_id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();
    let final_release = registry.release_handle(handle).unwrap().unwrap();
    finish(&mut registry, final_release);

    let replacement = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let stale = HandleRef {
        id: old_id,
        object_type: DW_OBJECT_TYPE_PROCESS,
    };
    assert_eq!(
        registry.retain_handle(&stale),
        Err(ObjectRegistryError::StaleReference)
    );

    let final_release = registry.release_creation(replacement).unwrap().unwrap();
    finish(&mut registry, final_release);
}

#[test]
fn forged_wrong_class_or_type_fails_closed_without_count_change() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();

    let fake_internal = InternalRef {
        id,
        object_type: DW_OBJECT_TYPE_PROCESS,
    };
    let error = registry.release_internal(fake_internal).unwrap_err();
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
    assert_eq!(counts(&registry, id), (1, 0));

    let final_release = registry.release_handle(handle).unwrap().unwrap();
    finish(&mut registry, final_release);
}

#[test]
fn both_reference_counters_fail_before_overflow() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let id = creation.id();
    let handle = registry.creation_into_handle(creation).unwrap();
    let slot = registry.reference_slot(id).unwrap();

    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    live.handle_refs = u32::MAX;
    assert_eq!(
        registry.retain_handle(&handle),
        Err(ObjectRegistryError::ReferenceCountExhausted)
    );
    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    assert_eq!(live.handle_refs, u32::MAX);
    live.handle_refs = 1;

    let internal = registry.retain_internal_from_handle(&handle).unwrap();
    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    live.internal_refs = u32::MAX;
    assert_eq!(
        registry.retain_internal_from_handle(&handle),
        Err(ObjectRegistryError::ReferenceCountExhausted)
    );
    let SlotState::Live(live) = &mut registry.slots[slot].state else {
        unreachable!();
    };
    assert_eq!(live.internal_refs, u32::MAX);
    live.internal_refs = 1;

    assert!(registry.release_internal(internal).unwrap().is_none());
    let final_release = registry.release_handle(handle).unwrap().unwrap();
    finish(&mut registry, final_release);
}

#[test]
fn generation_exhaustion_permanently_retires_the_slot() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let mut final_release = registry.release_creation(creation).unwrap().unwrap();
    let slot = registry.reference_slot(final_release.id()).unwrap();
    registry.slots[slot].generation = u32::MAX;
    final_release.id.raw = encode_object_id(slot, u32::MAX).unwrap();
    finish(&mut registry, final_release);

    assert_eq!(registry.slots[slot].state, SlotState::Retired);
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );
}

#[test]
fn final_release_can_complete_only_once() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let final_release = registry.release_creation(creation).unwrap().unwrap();
    let id = final_release.id();
    let object_type = final_release.object_type();
    finish(&mut registry, final_release);

    let duplicate = FinalRelease { id, object_type };
    let error = registry.complete_finalization(duplicate).unwrap_err();
    assert_eq!(error.error(), ObjectRegistryError::NotFinalizing);
    let _ = error.into_reference();
}

#[test]
fn creation_can_become_an_explicit_internal_owner() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let id = creation.id();
    let internal = registry.creation_into_internal(creation).unwrap();
    assert_eq!(counts(&registry, id), (0, 1));
    let final_release = registry.release_internal(internal).unwrap().unwrap();
    finish(&mut registry, final_release);
}

#[test]
fn zero_capacity_registry_fails_closed() {
    let mut registry = ObjectRegistry::<0>::new();
    assert_eq!(
        registry.create(DW_OBJECT_TYPE_PROCESS),
        Err(ObjectRegistryError::Capacity)
    );
}
