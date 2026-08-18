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

use super::{AcceptedObjectTypes, HandleTable, HandleTableError, ResolvedHandle};

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
