//! Caller-local DW0-D handle table and generated-rights validation.

mod rights;
mod table;

#[allow(
    unused_imports,
    reason = "DW0-D4/D5 consume core table types while process ownership arrives in DW0-E"
)]
pub(crate) use table::{
    AcceptedObjectTypes, BasicHandleInfo, DrainResult, HandleTable, HandleTableError, InstallError,
    ResolvedHandle,
};

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn resolve_test_internal_owner<const OBJECTS: usize>(
    registry: &mut crate::object::ObjectRegistry<OBJECTS>,
    owner: &crate::object::InternalRef,
    rights: deepwyrm_abi::DwRights,
) -> ResolvedHandle {
    let retained = registry
        .retain_internal(owner)
        .expect("test owner remains a live generic object reference");
    let handle_ref = registry
        .internal_into_handle(retained)
        .expect("test owner can become a temporary handle reference");
    let mut table = HandleTable::<1>::new();
    let handle = table
        .install(handle_ref, rights)
        .expect("test handle rights are valid for the object");
    let resolved = table
        .lookup(
            registry,
            handle,
            AcceptedObjectTypes::Any,
            deepwyrm_abi::DwRights(0),
        )
        .expect("temporary test handle resolves");
    assert!(
        table.close(registry, handle).unwrap().is_none(),
        "resolved lookup pin and original owner keep the test object live"
    );
    resolved
}
