//! Syscall-independent DW0-D handle and object-info service semantics.
//!
//! DW0-E may adapt these operations to userspace pointers and syscall return
//! conventions, but it must not duplicate their validation or authority rules.

use deepwyrm_abi::{
    DW_MEMORY_OBJECT_INFO_V1_SIZE, DW_OBJECT_INFO_BASIC_V1, DW_OBJECT_INFO_MEMORY_OBJECT_V1,
    DW_OBJECT_INFO_TASK_STATE_V1, DW_OBJECT_INFO_V1_SIZE, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD, DW_RIGHT_INSPECT, DW_STATUS_ACCESS_DENIED,
    DW_STATUS_BAD_HANDLE, DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NO_RESOURCES,
    DW_STATUS_NOT_SUPPORTED, DW_STATUS_WRONG_OBJECT_TYPE, DwHandle, DwMemoryObjectInfoV1,
    DwObjectInfoV1, DwRights, DwStatus,
};

use crate::memory::object::MemoryObjectAuthority;
use crate::object::{FinalRelease, ObjectRegistry};

use crate::handle::{AcceptedObjectTypes, HandleTable, HandleTableError, ResolvedHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectInfoResult {
    Basic(DwObjectInfoV1),
    MemoryObject(DwMemoryObjectInfoV1),
}

pub(crate) fn handle_close<const HANDLES: usize, const OBJECTS: usize>(
    table: &mut HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    handle: DwHandle,
) -> Result<Option<FinalRelease>, DwStatus> {
    table.close(registry, handle).map_err(table_status)
}

pub(crate) fn handle_duplicate<const HANDLES: usize, const OBJECTS: usize>(
    table: &mut HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    source: DwHandle,
    requested_rights: DwRights,
) -> Result<DwHandle, DwStatus> {
    table
        .duplicate(registry, source, requested_rights)
        .map_err(table_status)
}

pub(crate) fn object_get_info_v1<
    const HANDLES: usize,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
>(
    table: &HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    handle: DwHandle,
    topic: u32,
) -> Result<ObjectInfoResult, DwStatus> {
    let resolved = table
        .lookup(registry, handle, AcceptedObjectTypes::Any, DW_RIGHT_INSPECT)
        .map_err(table_status)?;

    let result = match topic {
        DW_OBJECT_INFO_BASIC_V1 => Ok(ObjectInfoResult::Basic(basic_info(&resolved))),
        DW_OBJECT_INFO_MEMORY_OBJECT_V1 => memory_info(memory, &resolved),
        DW_OBJECT_INFO_TASK_STATE_V1 => task_state_reserved(&resolved),
        _ => Err(DW_STATUS_NOT_SUPPORTED),
    };

    release_query_pin(registry, resolved);
    result
}

fn basic_info(resolved: &ResolvedHandle) -> DwObjectInfoV1 {
    DwObjectInfoV1 {
        size: DW_OBJECT_INFO_V1_SIZE,
        version: 1,
        object_type: resolved.object_type(),
        reserved0: 0,
        rights: resolved.rights(),
        reserved: [0; 4],
    }
}

fn memory_info<const MEMORY_OBJECTS: usize, const LEASES: usize>(
    memory: &MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    resolved: &ResolvedHandle,
) -> Result<ObjectInfoResult, DwStatus> {
    if resolved.object_type() != DW_OBJECT_TYPE_MEMORY_OBJECT {
        return Err(DW_STATUS_WRONG_OBJECT_TYPE);
    }
    let info = memory
        .object_info_for_resolved(resolved)
        .unwrap_or_else(|error| {
            panic!("live MemoryObject handle has no matching payload record: {error:?}")
        });
    Ok(ObjectInfoResult::MemoryObject(DwMemoryObjectInfoV1 {
        size: DW_MEMORY_OBJECT_INFO_V1_SIZE,
        version: 1,
        byte_size: info.logical_byte_len(),
        reserved: [0; 2],
    }))
}

fn task_state_reserved(resolved: &ResolvedHandle) -> Result<ObjectInfoResult, DwStatus> {
    if !matches!(
        resolved.object_type(),
        DW_OBJECT_TYPE_PROCESS | DW_OBJECT_TYPE_THREAD
    ) {
        return Err(DW_STATUS_WRONG_OBJECT_TYPE);
    }
    Err(DW_STATUS_NOT_SUPPORTED)
}

fn release_query_pin<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    resolved: ResolvedHandle,
) {
    match registry.release_internal(resolved.into_internal()) {
        Ok(None) => {}
        Ok(Some(_)) => panic!(
            "object-info lookup pin became final while its source handle remained table-owned"
        ),
        Err(error) => panic!(
            "object-info lookup pin violated generic object lifetime invariants: {:?}",
            error.error()
        ),
    }
}

fn table_status(error: HandleTableError) -> DwStatus {
    match error {
        HandleTableError::InvalidHandle => DW_STATUS_BAD_HANDLE,
        HandleTableError::InvalidRights => DW_STATUS_INVALID_ARGUMENT,
        HandleTableError::WrongObjectType => DW_STATUS_WRONG_OBJECT_TYPE,
        HandleTableError::AccessDenied => DW_STATUS_ACCESS_DENIED,
        HandleTableError::Capacity | HandleTableError::ReferenceCapacity => DW_STATUS_NO_RESOURCES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::object::{
        MemoryObjectKind, MemoryProtection, PAGE_SIZE, complete_memory_finalization,
    };
    use crate::object::ObjectRegistryError;
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_EVENT, DW_RIGHT_DUPLICATE, DW_RIGHT_READ, DW_RIGHT_WAIT,
        dw_object_compatible_rights,
    };

    fn install<const OBJECTS: usize, const HANDLES: usize>(
        registry: &mut ObjectRegistry<OBJECTS>,
        table: &mut HandleTable<HANDLES>,
        object_type: deepwyrm_abi::DwObjectType,
        rights: DwRights,
    ) -> DwHandle {
        let creation = registry.create(object_type).unwrap();
        let reference = registry.creation_into_handle(creation).unwrap();
        table.install(reference, rights).unwrap()
    }

    fn finish<const OBJECTS: usize>(
        registry: &mut ObjectRegistry<OBJECTS>,
        final_release: Option<FinalRelease>,
    ) {
        if let Some(final_release) = final_release {
            registry.complete_finalization(final_release).unwrap();
        }
    }

    fn close_and_finish<const OBJECTS: usize, const HANDLES: usize>(
        table: &mut HandleTable<HANDLES>,
        registry: &mut ObjectRegistry<OBJECTS>,
        handle: DwHandle,
    ) {
        let final_release = handle_close(table, registry, handle).unwrap();
        finish(registry, final_release);
    }
    fn rights(bits: &[DwRights]) -> DwRights {
        DwRights(bits.iter().fold(0_u64, |mask, right| mask | right.0))
    }

    #[test]
    fn close_returns_cleanup_authority_after_entry_invalidation() {
        let mut registry = ObjectRegistry::<1>::new();
        let mut table = HandleTable::<1>::new();
        let handle = install(
            &mut registry,
            &mut table,
            DW_OBJECT_TYPE_EVENT,
            dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
        );

        let final_release = handle_close(&mut table, &mut registry, handle)
            .unwrap()
            .expect("last handle returns final cleanup authority");
        assert_eq!(
            handle_close(&mut table, &mut registry, handle),
            Err(DW_STATUS_BAD_HANDLE)
        );
        assert_eq!(
            registry.create(DW_OBJECT_TYPE_EVENT),
            Err(ObjectRegistryError::Capacity),
            "finalizing slot is not reusable before cleanup"
        );
        registry.complete_finalization(final_release).unwrap();

        let replacement = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
        let final_release = registry.release_creation(replacement).unwrap();
        finish(&mut registry, final_release);
    }
    #[test]
    fn close_preserves_object_while_lookup_pin_is_live() {
        let mut registry = ObjectRegistry::<1>::new();
        let mut table = HandleTable::<1>::new();
        let handle = install(
            &mut registry,
            &mut table,
            DW_OBJECT_TYPE_EVENT,
            dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
        );
        let resolved = table
            .lookup(&mut registry, handle, AcceptedObjectTypes::Any, DwRights(0))
            .unwrap();

        assert!(
            handle_close(&mut table, &mut registry, handle)
                .unwrap()
                .is_none()
        );
        let final_release = registry
            .release_internal(resolved.into_internal())
            .unwrap()
            .expect("lookup pin becomes the final reference");
        registry.complete_finalization(final_release).unwrap();
    }

    #[test]
    fn duplicate_service_preserves_validation_order_and_capacity_rollback() {
        let mut registry = ObjectRegistry::<1>::new();
        let mut table = HandleTable::<1>::new();
        let stale = install(
            &mut registry,
            &mut table,
            DW_OBJECT_TYPE_EVENT,
            dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
        );
        close_and_finish(&mut table, &mut registry, stale);
        assert_eq!(
            handle_duplicate(&mut table, &mut registry, stale, DW_RIGHT_WAIT),
            Err(DW_STATUS_BAD_HANDLE)
        );
        assert_eq!(
            handle_duplicate(&mut table, &mut registry, stale, DwRights(1_u64 << 63)),
            Err(DW_STATUS_INVALID_ARGUMENT)
        );

        let held = rights(&[DW_RIGHT_WAIT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT]);
        let source = install(&mut registry, &mut table, DW_OBJECT_TYPE_EVENT, held);
        assert_eq!(
            handle_duplicate(&mut table, &mut registry, source, DW_RIGHT_WAIT),
            Err(DW_STATUS_NO_RESOURCES)
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.inspect_basic(source).unwrap().rights, held);
        close_and_finish(&mut table, &mut registry, source);

        let mut table = HandleTable::<2>::new();
        let source = install(&mut registry, &mut table, DW_OBJECT_TYPE_EVENT, held);
        let reduced_rights = rights(&[DW_RIGHT_WAIT, DW_RIGHT_INSPECT]);
        let duplicate =
            handle_duplicate(&mut table, &mut registry, source, reduced_rights).unwrap();
        assert_eq!(
            table.inspect_basic(duplicate).unwrap().rights,
            reduced_rights
        );
        assert!(
            handle_close(&mut table, &mut registry, source)
                .unwrap()
                .is_none()
        );
        close_and_finish(&mut table, &mut registry, duplicate);
    }

    #[test]
    fn duplicate_service_rejects_missing_delegation_right() {
        let mut registry = ObjectRegistry::<1>::new();
        let mut table = HandleTable::<2>::new();
        let held = rights(&[DW_RIGHT_WAIT, DW_RIGHT_INSPECT]);
        let source = install(&mut registry, &mut table, DW_OBJECT_TYPE_EVENT, held);
        assert_eq!(
            handle_duplicate(&mut table, &mut registry, source, DW_RIGHT_WAIT),
            Err(DW_STATUS_ACCESS_DENIED)
        );
        assert_eq!(table.len(), 1);
        close_and_finish(&mut table, &mut registry, source);
    }
    #[test]
    fn object_info_enforces_inspect_then_topic_and_type_order() {
        let memory = MemoryObjectAuthority::<0, 0>::new();
        let mut registry = ObjectRegistry::<3>::new();
        let mut table = HandleTable::<3>::new();

        let no_inspect = install(
            &mut registry,
            &mut table,
            DW_OBJECT_TYPE_EVENT,
            DW_RIGHT_WAIT,
        );
        assert_eq!(
            object_get_info_v1(&table, &mut registry, &memory, no_inspect, 0xffff_fffe),
            Err(DW_STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            object_get_info_v1(
                &table,
                &mut registry,
                &memory,
                no_inspect,
                DW_OBJECT_INFO_MEMORY_OBJECT_V1,
            ),
            Err(DW_STATUS_ACCESS_DENIED)
        );

        let inspected_rights = rights(&[DW_RIGHT_WAIT, DW_RIGHT_INSPECT]);
        let inspected = install(
            &mut registry,
            &mut table,
            DW_OBJECT_TYPE_EVENT,
            inspected_rights,
        );
        assert_eq!(
            object_get_info_v1(
                &table,
                &mut registry,
                &memory,
                DwHandle(0),
                DW_OBJECT_INFO_BASIC_V1,
            ),
            Err(DW_STATUS_BAD_HANDLE)
        );
        let basic = object_get_info_v1(
            &table,
            &mut registry,
            &memory,
            inspected,
            DW_OBJECT_INFO_BASIC_V1,
        )
        .unwrap();
        assert_eq!(
            basic,
            ObjectInfoResult::Basic(DwObjectInfoV1 {
                size: DW_OBJECT_INFO_V1_SIZE,
                version: 1,
                object_type: DW_OBJECT_TYPE_EVENT,
                reserved0: 0,
                rights: inspected_rights,
                reserved: [0; 4],
            })
        );
        assert_eq!(
            object_get_info_v1(&table, &mut registry, &memory, inspected, 0xffff_fffe),
            Err(DW_STATUS_NOT_SUPPORTED)
        );
        assert_eq!(
            object_get_info_v1(
                &table,
                &mut registry,
                &memory,
                inspected,
                DW_OBJECT_INFO_MEMORY_OBJECT_V1,
            ),
            Err(DW_STATUS_WRONG_OBJECT_TYPE)
        );
        assert_eq!(
            object_get_info_v1(
                &table,
                &mut registry,
                &memory,
                inspected,
                DW_OBJECT_INFO_TASK_STATE_V1,
            ),
            Err(DW_STATUS_WRONG_OBJECT_TYPE)
        );
        let process = install(
            &mut registry,
            &mut table,
            DW_OBJECT_TYPE_PROCESS,
            DW_RIGHT_INSPECT,
        );
        assert_eq!(
            object_get_info_v1(
                &table,
                &mut registry,
                &memory,
                process,
                DW_OBJECT_INFO_TASK_STATE_V1,
            ),
            Err(DW_STATUS_NOT_SUPPORTED),
            "D5 recognizes task-state type but does not fabricate DW0-E task state"
        );

        let first = handle_close(&mut table, &mut registry, no_inspect).unwrap();
        finish(&mut registry, first);
        let second = handle_close(&mut table, &mut registry, inspected).unwrap();
        finish(&mut registry, second);
        let third = handle_close(&mut table, &mut registry, process).unwrap();
        finish(&mut registry, third);
    }

    #[test]
    fn memory_object_info_reports_exact_logical_size() {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let backing =
            crate::memory::frame_roles::synthetic_immutable_module_backing(0x30_000, 2, 9);
        memory
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE + 1,
                MemoryObjectKind::ImmutableBootModule,
                MemoryProtection::READ,
            )
            .unwrap();
        let reference = registry.creation_into_handle(creation).unwrap();
        let held = rights(&[DW_RIGHT_READ, DW_RIGHT_INSPECT]);
        let mut table = HandleTable::<1>::new();
        let handle = table.install(reference, held).unwrap();

        assert_eq!(
            object_get_info_v1(
                &table,
                &mut registry,
                &memory,
                handle,
                DW_OBJECT_INFO_MEMORY_OBJECT_V1,
            )
            .unwrap(),
            ObjectInfoResult::MemoryObject(DwMemoryObjectInfoV1 {
                size: DW_MEMORY_OBJECT_INFO_V1_SIZE,
                version: 1,
                byte_size: PAGE_SIZE + 1,
                reserved: [0; 2],
            })
        );

        let final_release = handle_close(&mut table, &mut registry, handle)
            .unwrap()
            .expect("last MemoryObject handle yields cleanup authority");
        let finalization = memory.take_finalization(final_release).unwrap();
        let mut roles =
            crate::memory::frame_roles::synthetic_frame_role_manager::<1, 1>(0x80_000, 1);
        complete_memory_finalization(&mut registry, &mut roles, finalization);
    }
}
