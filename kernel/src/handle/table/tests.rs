extern crate std;

use deepwyrm_abi::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP,
    DW_OBJECT_TYPE_THREAD, DW_OBJECT_TYPE_TIMER, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT,
    DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    dw_object_compatible_rights,
};

use super::*;

fn install_object<const OBJECTS: usize, const HANDLES: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    table: &mut HandleTable<HANDLES>,
    object_type: DwObjectType,
    rights: DwRights,
) -> DwHandle {
    let creation = registry.create(object_type).unwrap();
    let reference = registry.creation_into_handle(creation).unwrap();
    table.install(reference, rights).unwrap()
}

fn complete<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    final_release: Option<FinalRelease>,
) {
    if let Some(final_release) = final_release {
        registry.complete_finalization(final_release).unwrap();
    }
}

fn release_lookup<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    resolved: ResolvedHandle,
) -> Option<FinalRelease> {
    registry.release_internal(resolved.into_internal()).unwrap()
}

fn rights(bits: &[DwRights]) -> DwRights {
    DwRights(bits.iter().fold(0_u64, |mask, right| mask | right.0))
}

#[test]
fn every_live_object_type_installs_with_generated_compatible_rights() {
    let mut registry = ObjectRegistry::<8>::new();
    let mut table = HandleTable::<8>::new();
    for object_type in [
        DW_OBJECT_TYPE_TASK_GROUP,
        DW_OBJECT_TYPE_PROCESS,
        DW_OBJECT_TYPE_THREAD,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        DW_OBJECT_TYPE_ADDRESS_REGION,
        DW_OBJECT_TYPE_CHANNEL,
        DW_OBJECT_TYPE_EVENT,
        DW_OBJECT_TYPE_TIMER,
    ] {
        let compatible = dw_object_compatible_rights(object_type);
        let handle = install_object(&mut registry, &mut table, object_type, compatible);
        let info = table.inspect_basic(handle).unwrap();
        assert_eq!(info.object_type, object_type);
        assert_eq!(info.rights, compatible);
    }
    let drained = table.drain(&mut registry);
    assert_eq!(drained.final_release_count(), 8);
    for final_release in drained.into_final_releases().into_iter().flatten() {
        registry.complete_finalization(final_release).unwrap();
    }
}

#[test]
fn install_rejects_zero_unknown_and_incompatible_rights_without_losing_reference() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_TASK_GROUP).unwrap();
    let mut reference = registry.creation_into_handle(creation).unwrap();

    for invalid in [DwRights(0), DwRights(1_u64 << 63), DW_RIGHT_READ] {
        let failure = table.install(reference, invalid).unwrap_err();
        assert_eq!(failure.error(), HandleTableError::InvalidRights);
        reference = failure.into_reference();
        assert!(table.is_empty());
    }

    let valid = dw_object_compatible_rights(DW_OBJECT_TYPE_TASK_GROUP);
    let handle = table.install(reference, valid).unwrap();
    let final_release = table.close(&mut registry, handle).unwrap();
    complete(&mut registry, final_release);
}

#[test]
fn raw_handle_identity_is_table_local_and_may_collide() {
    let mut registry = ObjectRegistry::<2>::new();
    let mut first = HandleTable::<1>::new();
    let mut second = HandleTable::<1>::new();
    let first_handle = install_object(
        &mut registry,
        &mut first,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let second_handle = install_object(
        &mut registry,
        &mut second,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
    assert_eq!(first_handle, second_handle);
    assert_eq!(first_handle.0, (1_u64 << 32) | 1);
    assert_eq!(
        first.inspect_basic(first_handle).unwrap().object_type,
        DW_OBJECT_TYPE_MEMORY_OBJECT
    );
    assert_eq!(
        second.inspect_basic(second_handle).unwrap().object_type,
        DW_OBJECT_TYPE_EVENT
    );

    let first_final = first.close(&mut registry, first_handle).unwrap();
    let second_final = second.close(&mut registry, second_handle).unwrap();
    complete(&mut registry, first_final);
    complete(&mut registry, second_final);
}

#[test]
fn malformed_absent_and_stale_handles_fail_closed() {
    let mut registry = ObjectRegistry::<2>::new();
    let mut table = HandleTable::<2>::new();
    for invalid in [
        DW_HANDLE_INVALID,
        DwHandle(1),
        DwHandle(1_u64 << 32),
        DwHandle((1_u64 << 32) | 99),
        DwHandle(0x1234_5678_9abc_def0),
    ] {
        assert_eq!(
            table.inspect_basic(invalid),
            Err(HandleTableError::InvalidHandle)
        );
    }

    let handle = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let final_release = table.close(&mut registry, handle).unwrap();
    complete(&mut registry, final_release);
    assert_eq!(
        table.inspect_basic(handle),
        Err(HandleTableError::InvalidHandle)
    );

    let replacement = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
    assert_ne!(replacement, handle);
    assert_eq!(
        table.inspect_basic(handle),
        Err(HandleTableError::InvalidHandle)
    );
    assert_eq!(
        table.inspect_basic(replacement).unwrap().object_type,
        DW_OBJECT_TYPE_EVENT
    );
    let final_release = table.close(&mut registry, replacement).unwrap();
    complete(&mut registry, final_release);
}

#[test]
fn generation_exhaustion_retires_handle_slot_permanently() {
    let mut registry = ObjectRegistry::<2>::new();
    let mut table = HandleTable::<1>::new();
    table.slots[0].generation = u32::MAX - 1;
    let handle = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
    assert_eq!((handle.0 >> 32) as u32, u32::MAX);
    let final_release = table.close(&mut registry, handle).unwrap();
    complete(&mut registry, final_release);
    assert!(table.slots[0].retired);

    let creation = registry.create(DW_OBJECT_TYPE_TIMER).unwrap();
    let reference = registry.creation_into_handle(creation).unwrap();
    let failure = table
        .install(reference, dw_object_compatible_rights(DW_OBJECT_TYPE_TIMER))
        .unwrap_err();
    assert_eq!(failure.error(), HandleTableError::Capacity);
    let final_release = registry.release_handle(failure.into_reference()).unwrap();
    complete(&mut registry, final_release);
}

#[test]
fn lookup_checks_type_and_rights_then_holds_a_pin() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<1>::new();
    let held = rights(&[DW_RIGHT_READ, DW_RIGHT_MAP, DW_RIGHT_INSPECT]);
    let handle = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        held,
    );
    assert_eq!(
        table.lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_PROCESS),
            DW_RIGHT_READ,
        ),
        Err(HandleTableError::WrongObjectType)
    );
    assert_eq!(
        table.lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::Any,
            DW_RIGHT_WRITE,
        ),
        Err(HandleTableError::AccessDenied)
    );
    assert_eq!(
        table.lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::Any,
            DwRights(1_u64 << 63),
        ),
        Err(HandleTableError::InvalidRights)
    );
    let resolved = table
        .lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::Set(&[DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_MEMORY_OBJECT]),
            rights(&[DW_RIGHT_READ, DW_RIGHT_MAP]),
        )
        .unwrap();
    assert_eq!(resolved.object_type(), DW_OBJECT_TYPE_MEMORY_OBJECT);
    assert_eq!(resolved.rights(), held);
    assert_eq!(resolved.basic_info().rights, held);

    let close_result = table.close(&mut registry, handle).unwrap();
    assert!(close_result.is_none());
    let final_release = release_lookup(&mut registry, resolved);
    assert!(final_release.is_some());
    complete(&mut registry, final_release);
}

#[test]
fn basic_info_requires_inspect_without_creating_a_pin() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<1>::new();
    let held = rights(&[DW_RIGHT_READ, DW_RIGHT_MAP]);
    let handle = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        held,
    );
    assert_eq!(
        table.inspect_basic(handle),
        Err(HandleTableError::AccessDenied)
    );
    let final_release = table.close(&mut registry, handle).unwrap();
    complete(&mut registry, final_release);
}

#[test]
fn equal_and_reduced_duplicates_preserve_one_reference_per_entry() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<3>::new();
    let held = rights(&[
        DW_RIGHT_READ,
        DW_RIGHT_MAP,
        DW_RIGHT_DUPLICATE,
        DW_RIGHT_TRANSFER,
        DW_RIGHT_INSPECT,
    ]);
    let source = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        held,
    );
    let equal = table.duplicate(&mut registry, source, held).unwrap();
    let reduced_rights = rights(&[DW_RIGHT_READ, DW_RIGHT_MAP, DW_RIGHT_INSPECT]);
    let reduced = table
        .duplicate(&mut registry, source, reduced_rights)
        .unwrap();
    assert_eq!(table.inspect_basic(equal).unwrap().rights, held);
    assert_eq!(table.inspect_basic(reduced).unwrap().rights, reduced_rights);

    assert!(table.close(&mut registry, source).unwrap().is_none());
    assert!(table.close(&mut registry, equal).unwrap().is_none());
    let final_release = table.close(&mut registry, reduced).unwrap();
    assert!(final_release.is_some());
    complete(&mut registry, final_release);
}

#[test]
fn duplicate_validation_order_and_failures_leave_source_unchanged() {
    let mut registry = ObjectRegistry::<2>::new();
    let mut table = HandleTable::<3>::new();
    let stale = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
    let final_release = table.close(&mut registry, stale).unwrap();
    complete(&mut registry, final_release);
    assert_eq!(
        table.duplicate(&mut registry, stale, DW_RIGHT_READ),
        Err(HandleTableError::InvalidHandle)
    );
    assert_eq!(
        table.duplicate(&mut registry, stale, DwRights(1_u64 << 63)),
        Err(HandleTableError::InvalidRights)
    );

    let held = rights(&[
        DW_RIGHT_READ,
        DW_RIGHT_MAP,
        DW_RIGHT_DUPLICATE,
        DW_RIGHT_INSPECT,
    ]);
    let source = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        held,
    );
    for (requested, expected) in [
        (DwRights(0), HandleTableError::InvalidRights),
        (DwRights(1_u64 << 63), HandleTableError::InvalidRights),
        (DW_RIGHT_WAIT, HandleTableError::InvalidRights),
        (DW_RIGHT_WRITE, HandleTableError::AccessDenied),
    ] {
        let before = table.inspect_basic(source).unwrap();
        assert_eq!(
            table.duplicate(&mut registry, source, requested),
            Err(expected)
        );
        assert_eq!(table.inspect_basic(source).unwrap(), before);
        assert_eq!(table.len(), 1);
    }

    let no_duplicate = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        rights(&[DW_RIGHT_READ, DW_RIGHT_MAP, DW_RIGHT_INSPECT]),
    );
    assert_eq!(
        table.duplicate(&mut registry, no_duplicate, DW_RIGHT_READ),
        Err(HandleTableError::AccessDenied)
    );
    assert_eq!(table.len(), 2);

    let first_final = table.close(&mut registry, source).unwrap();
    let second_final = table.close(&mut registry, no_duplicate).unwrap();
    assert!(first_final.is_some());
    assert!(second_final.is_some());
    complete(&mut registry, first_final);
    complete(&mut registry, second_final);
}

#[test]
fn duplicate_capacity_failure_does_not_leak_a_reference() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<1>::new();
    let held = rights(&[
        DW_RIGHT_READ,
        DW_RIGHT_MAP,
        DW_RIGHT_DUPLICATE,
        DW_RIGHT_INSPECT,
    ]);
    let source = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        held,
    );
    assert_eq!(
        table.duplicate(&mut registry, source, DW_RIGHT_READ),
        Err(HandleTableError::Capacity)
    );
    assert_eq!(table.len(), 1);
    let final_release = table.close(&mut registry, source).unwrap();
    assert!(final_release.is_some());
    complete(&mut registry, final_release);
}

#[test]
fn install_capacity_failure_returns_the_unpublished_reference() {
    let mut registry = ObjectRegistry::<2>::new();
    let mut table = HandleTable::<1>::new();
    let first = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
    let creation = registry.create(DW_OBJECT_TYPE_TIMER).unwrap();
    let reference = registry.creation_into_handle(creation).unwrap();
    let failure = table
        .install(reference, dw_object_compatible_rights(DW_OBJECT_TYPE_TIMER))
        .unwrap_err();
    assert_eq!(failure.error(), HandleTableError::Capacity);
    let second_final = registry.release_handle(failure.into_reference()).unwrap();
    complete(&mut registry, second_final);
    let first_final = table.close(&mut registry, first).unwrap();
    complete(&mut registry, first_final);
}

#[test]
fn close_one_of_many_and_double_close_are_exact() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<2>::new();
    let held = rights(&[DW_RIGHT_READ, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT]);
    let first = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        held,
    );
    let second = table.duplicate(&mut registry, first, held).unwrap();
    assert!(table.close(&mut registry, first).unwrap().is_none());
    assert_eq!(
        table.close(&mut registry, first),
        Err(HandleTableError::InvalidHandle)
    );
    let final_release = table.close(&mut registry, second).unwrap();
    assert!(final_release.is_some());
    complete(&mut registry, final_release);
}

#[test]
#[should_panic(expected = "live HandleTable dropped without explicit close/drain")]
fn dropping_live_table_fails_stop() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<1>::new();
    let _handle = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
}

#[test]
fn drain_preserves_object_while_lookup_pin_is_live() {
    let mut registry = ObjectRegistry::<1>::new();
    let mut table = HandleTable::<1>::new();
    let handle = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        rights(&[DW_RIGHT_READ, DW_RIGHT_INSPECT]),
    );
    let resolved = table
        .lookup(
            &mut registry,
            handle,
            AcceptedObjectTypes::Any,
            DW_RIGHT_READ,
        )
        .unwrap();
    let drained = table.drain(&mut registry);
    assert_eq!(drained.final_release_count(), 0);
    let final_release = release_lookup(&mut registry, resolved);
    assert!(final_release.is_some());
    complete(&mut registry, final_release);
}

#[test]
fn drain_releases_each_entry_once_and_returns_finalizers() {
    let mut registry = ObjectRegistry::<2>::new();
    let mut table = HandleTable::<4>::new();
    let memory = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_MEMORY_OBJECT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let _duplicate = table
        .duplicate(
            &mut registry,
            memory,
            dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
        )
        .unwrap();
    let _event = install_object(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
    assert_eq!(table.len(), 3);
    let drained = table.drain(&mut registry);
    assert!(table.is_empty());
    assert_eq!(drained.final_release_count(), 2);
    assert_eq!(
        table.close(&mut registry, memory),
        Err(HandleTableError::InvalidHandle)
    );
    let mut completed = 0;
    for final_release in drained.into_final_releases().into_iter().flatten() {
        registry.complete_finalization(final_release).unwrap();
        completed += 1;
    }
    assert_eq!(completed, 2);
}
