extern crate std;

use super::super::address_region::AddressSpaceAuthority;
use super::*;
use crate::handle::{AcceptedObjectTypes, HandleTable, HandleTableError};
use crate::object::ObjectRegistry;
use deepwyrm_abi::{DwHandle, DwRights};
use std::boxed::Box;

fn grant<const OBJECTS: usize, const LEASES: usize>(
    authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    logical_byte_len: u64,
    ceiling: MemoryProtection,
) -> (MemoryObjectKey, InternalRef) {
    let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x20_000, 4);
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let key = authority
        .grant_backing(
            &creation,
            backing,
            logical_byte_len,
            MemoryObjectKind::PageBacked,
            ceiling,
        )
        .unwrap();
    let owner = registry.creation_into_internal(creation).unwrap();
    (key, owner)
}

fn mapping<const OBJECTS: usize, const LEASES: usize>(
    authority: &MemoryObjectAuthority<OBJECTS, LEASES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    owner: &InternalRef,
    object: MemoryObjectKey,
    address_space: AddressSpaceKey,
    region: RegionKey,
    ceiling: MemoryProtection,
) -> (CapturedMappingAuthority, MapAuthorization) {
    assert_eq!(object.object_id(), Some(owner.id()));
    let resolved = crate::handle::resolve_test_internal_owner(
        registry,
        owner,
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let authorization = authority
        .issue_map_authorization(resolved, address_space, region, ceiling)
        .unwrap();
    let captured = authorization.capture(address_space, region).unwrap();
    (captured, authorization)
}

fn only_final<const CAPACITY: usize>(releases: MappingFinalReleases<CAPACITY>) -> FinalRelease {
    assert_eq!(releases.len(), 1);
    releases
        .into_items()
        .into_iter()
        .flatten()
        .next()
        .expect("one final release was reported")
}

#[allow(
    unsafe_code,
    reason = "test-local address-space registries satisfy the unique-root authority contract"
)]
fn ids() -> (AddressSpaceKey, RegionKey) {
    // SAFETY: this test-local registry uniquely owns its synthetic root.
    // Leaking it makes the registry outlive every returned identity.
    let spaces = Box::leak(Box::new(unsafe { AddressSpaceAuthority::<1, 1>::new() }));
    let space = spaces.create_address_space().unwrap();
    let region = spaces
        .create_region::<1>(space, PAGE_SIZE, PAGE_SIZE)
        .unwrap();
    (space, region.region_key())
}

#[allow(
    unsafe_code,
    reason = "the synthetic manager helper attests complete zeroing before typed backing assignment"
)]
fn handled_object<const HANDLES: usize>(
    rights: DwRights,
    ceiling: MemoryProtection,
) -> (
    crate::memory::frame_roles::FrameRoleManager<1, 8>,
    ObjectRegistry<2>,
    MemoryObjectAuthority<1, 4>,
    HandleTable<HANDLES>,
    MemoryObjectKey,
    DwHandle,
    u64,
) {
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
    let allocation = roles.allocate(1).unwrap();
    let physical_start = allocation.physical_start();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();

    let mut registry = ObjectRegistry::<2>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 4>::new();
    let key = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            ceiling,
        )
        .unwrap();
    let handle_ref = registry.creation_into_handle(creation).unwrap();
    let mut table = HandleTable::<HANDLES>::new();
    let handle = table.install(handle_ref, rights).unwrap();
    (
        roles,
        registry,
        authority,
        table,
        key,
        handle,
        physical_start,
    )
}

fn complete_memory_release(
    registry: &mut ObjectRegistry<2>,
    authority: &mut MemoryObjectAuthority<1, 4>,
    roles: &mut crate::memory::frame_roles::FrameRoleManager<1, 8>,
    final_release: FinalRelease,
) {
    let finalization = authority.take_finalization(final_release).unwrap();
    complete_memory_finalization(registry, roles, finalization);
}

#[test]
fn production_binding_consumes_creation_before_first_publication() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let id = creation.id();
    let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x30_000, 2);
    let mut authority = MemoryObjectAuthority::<1, 1>::new();

    let binding = authority
        .bind_backing(
            creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE,
        )
        .unwrap();
    assert_eq!(binding.key().object_id(), Some(id));

    let bound = registry.finish_payload_binding(binding).unwrap();
    assert_eq!(bound.id(), id);
    assert_eq!(bound.object_type(), DW_OBJECT_TYPE_MEMORY_OBJECT);
    let handle = registry.bound_into_handle(bound).unwrap();
    let final_release = registry.release_handle(handle).unwrap().unwrap();

    let finalization = authority.take_finalization(final_release).unwrap();
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x40_000, 2);
    // The synthetic backing above is not owned by this manager, so only prove
    // the typed payload extraction here; manager-backed cleanup is covered by
    // the existing finalization tests.
    let (release, _backing) = finalization.into_parts();
    registry.complete_finalization(release).unwrap();
    let _ = &mut roles;
}

#[test]
fn failed_production_binding_returns_creation_and_backing_for_rollback() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let id = creation.id();
    let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x50_000, 1);
    let mut authority = MemoryObjectAuthority::<1, 1>::new();

    let failure = authority
        .bind_backing(
            creation,
            backing,
            PAGE_SIZE * 2,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ,
        )
        .unwrap_err();
    assert_eq!(failure.error(), MemoryObjectError::BackingTooSmall);
    let (creation, _backing) = failure.into_parts();
    assert_eq!(creation.id(), id);
    let final_release = registry.release_creation(creation).unwrap().unwrap();
    registry.complete_finalization(final_release).unwrap();
}

#[test]
fn reduced_duplicate_cannot_widen_mapping_rights() {
    let full = deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT);
    let (mut roles, mut registry, mut authority, mut table, _key, source, physical_start) =
        handled_object::<2>(full, MemoryProtection::READ_WRITE_EXECUTE);
    let (space, region) = ids();

    let read_only = table
        .duplicate(&mut registry, source, DW_RIGHT_READ)
        .unwrap();
    let resolved = table
        .lookup(
            &mut registry,
            read_only,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_MEMORY_OBJECT),
            DwRights(0),
        )
        .unwrap();
    let failure = authority
        .issue_map_authorization(resolved, space, region, MemoryProtection::READ)
        .err()
        .expect("READ without MAP cannot authorize a mapping");
    assert_eq!(failure.error(), MemoryObjectError::InsufficientRights);
    let (error, releases) = failure.release(&mut registry);
    assert_eq!(error, MemoryObjectError::InsufficientRights);
    assert!(releases.is_empty());
    assert!(table.close(&mut registry, read_only).unwrap().is_none());

    let map_read = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0);
    let reduced = table.duplicate(&mut registry, source, map_read).unwrap();
    let resolved = table
        .lookup(
            &mut registry,
            reduced,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_MEMORY_OBJECT),
            DwRights(0),
        )
        .unwrap();
    let authorization = authority
        .issue_map_authorization(resolved, space, region, MemoryProtection::READ)
        .unwrap();
    assert!(authorization.release(&mut registry).is_empty());

    for ceiling in [MemoryProtection::READ_WRITE, MemoryProtection::READ_EXECUTE] {
        let resolved = table
            .lookup(
                &mut registry,
                reduced,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_MEMORY_OBJECT),
                DwRights(0),
            )
            .unwrap();
        let failure = authority
            .issue_map_authorization(resolved, space, region, ceiling)
            .err()
            .expect("reduced handle cannot widen mapping authority");
        assert_eq!(failure.error(), MemoryObjectError::InsufficientRights);
        let (_, releases) = failure.release(&mut registry);
        assert!(releases.is_empty());
    }
    assert!(table.close(&mut registry, reduced).unwrap().is_none());
    let final_release = table.close(&mut registry, source).unwrap().unwrap();
    complete_memory_release(&mut registry, &mut authority, &mut roles, final_release);
    assert_eq!(roles.allocate(1).unwrap().physical_start(), physical_start);
}

#[test]
fn resolved_lookup_survives_source_close_and_closed_handle_cannot_reauthorize() {
    let full = deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT);
    let (mut roles, mut registry, mut authority, mut table, _key, source, physical_start) =
        handled_object::<1>(full, MemoryProtection::READ_WRITE_EXECUTE);
    let (space, region) = ids();
    let resolved = table
        .lookup(
            &mut registry,
            source,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_MEMORY_OBJECT),
            DwRights(0),
        )
        .unwrap();
    assert!(table.close(&mut registry, source).unwrap().is_none());
    assert_eq!(
        table.lookup(&mut registry, source, AcceptedObjectTypes::Any, DwRights(0),),
        Err(HandleTableError::InvalidHandle)
    );
    let authorization = authority
        .issue_map_authorization(resolved, space, region, MemoryProtection::READ)
        .unwrap();
    let final_release = only_final(authorization.release(&mut registry));
    complete_memory_release(&mut registry, &mut authority, &mut roles, final_release);
    assert_eq!(roles.allocate(1).unwrap().physical_start(), physical_start);
}

#[test]
fn payload_ceiling_remains_below_broad_handle_rights() {
    let full = deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT);
    let (mut roles, mut registry, mut authority, mut table, _key, source, _) =
        handled_object::<1>(full, MemoryProtection::READ);
    let (space, region) = ids();
    let resolved = table
        .lookup(
            &mut registry,
            source,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_MEMORY_OBJECT),
            DwRights(0),
        )
        .unwrap();
    let failure = authority
        .issue_map_authorization(resolved, space, region, MemoryProtection::READ_WRITE)
        .err()
        .expect("payload ceiling must reject writable authorization");
    assert_eq!(failure.error(), MemoryObjectError::ProtectionCeiling);
    let (_, releases) = failure.release(&mut registry);
    assert!(releases.is_empty());
    let final_release = table.close(&mut registry, source).unwrap().unwrap();
    complete_memory_release(&mut registry, &mut authority, &mut roles, final_release);
}

#[test]
fn wrong_object_type_returns_resolved_pin_for_exact_release() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(deepwyrm_abi::DW_OBJECT_TYPE_EVENT).unwrap();
    let handle_ref = registry.creation_into_handle(creation).unwrap();
    let mut table = HandleTable::<1>::new();
    let event_rights =
        deepwyrm_abi::dw_object_compatible_rights(deepwyrm_abi::DW_OBJECT_TYPE_EVENT);
    let handle = table.install(handle_ref, event_rights).unwrap();
    let resolved = table
        .lookup(&mut registry, handle, AcceptedObjectTypes::Any, DwRights(0))
        .unwrap();
    let authority = MemoryObjectAuthority::<1, 1>::new();
    let (space, region) = ids();
    let failure = authority
        .issue_map_authorization(resolved, space, region, MemoryProtection::READ)
        .err()
        .expect("non-MemoryObject lookup cannot authorize a mapping");
    assert_eq!(failure.error(), MemoryObjectError::ObjectReference);
    let (_, releases) = failure.release(&mut registry);
    assert!(releases.is_empty());
    let final_release = table.close(&mut registry, handle).unwrap().unwrap();
    registry.complete_finalization(final_release).unwrap();
}

#[test]
fn allocator_grant_preserves_exact_and_rounded_lengths() {
    let mut registry = ObjectRegistry::<2>::new();
    let mut authority = MemoryObjectAuthority::<2, 4>::new();
    let (key, _owner) = grant(
        &mut authority,
        &mut registry,
        PAGE_SIZE + 1,
        MemoryProtection::READ_WRITE_EXECUTE,
    );
    let info = authority.object_info(key).unwrap();
    assert_eq!(info.logical_byte_len(), PAGE_SIZE + 1);
    assert_eq!(info.rounded_byte_len(), PAGE_SIZE * 2);
    assert_eq!(info.kind(), MemoryObjectKind::PageBacked);
}

#[test]
fn typed_backing_identity_is_retained_and_failed_creation_returns_the_grant() {
    let mut registry = ObjectRegistry::<2>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<2, 2>::new();
    let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x20_000, 1);
    let expected_identity = backing.identity();
    let error = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE * 2,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE,
        )
        .unwrap_err();
    assert_eq!(error.error(), MemoryObjectError::BackingTooSmall);

    let backing = error.into_backing();
    assert_eq!(backing.identity(), expected_identity);
    let key = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE,
        )
        .unwrap();
    assert_eq!(
        authority.object_record(key).unwrap().backing,
        expected_identity
    );
}

#[test]
fn immutable_module_grant_rejects_role_confusion_and_writable_ceiling() {
    let mut registry = ObjectRegistry::<2>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<2, 2>::new();
    let backing = crate::memory::frame_roles::synthetic_immutable_module_backing(0x30_000, 1, 9);
    let error = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ,
        )
        .unwrap_err();
    assert_eq!(error.error(), MemoryObjectError::BackingKind);

    let error = authority
        .grant_backing(
            &creation,
            error.into_backing(),
            PAGE_SIZE,
            MemoryObjectKind::ImmutableBootModule,
            MemoryProtection::READ_WRITE,
        )
        .unwrap_err();
    assert_eq!(error.error(), MemoryObjectError::ProtectionCeiling);

    let key = authority
        .grant_backing(
            &creation,
            error.into_backing(),
            PAGE_SIZE,
            MemoryObjectKind::ImmutableBootModule,
            MemoryProtection::READ,
        )
        .unwrap();
    assert_eq!(
        authority.object_info(key).unwrap().kind(),
        MemoryObjectKind::ImmutableBootModule
    );
}

#[test]
fn final_page_tail_is_mapping_capacity_but_not_logical_object_size() {
    let (space, region) = ids();
    let mut registry = ObjectRegistry::<2>::new();
    let mut authority = MemoryObjectAuthority::<2, 4>::new();
    let (key, owner) = grant(
        &mut authority,
        &mut registry,
        PAGE_SIZE + 1,
        MemoryProtection::READ_WRITE,
    );
    let info = authority.object_info(key).unwrap();
    assert_eq!(info.logical_byte_len(), PAGE_SIZE + 1);
    assert_eq!(info.rounded_byte_len(), PAGE_SIZE * 2);
    let (token, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ_WRITE,
    );
    let prepared = authority
        .prepare_replace::<1, 2>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                token,
                PAGE_SIZE,
                PAGE_SIZE,
                MemoryProtection::READ,
            )],
            Some(authorization),
        )
        .unwrap();
    assert!(prepared.commit().is_empty());
    assert_eq!(authority.active_lease_count(), 1);
}

#[test]
fn replacement_rejects_bad_ranges_and_wx_aliases_without_commit() {
    let (space, region) = ids();
    let mut registry = ObjectRegistry::<2>::new();
    let mut authority = MemoryObjectAuthority::<2, 4>::new();
    let (key, owner) = grant(
        &mut authority,
        &mut registry,
        PAGE_SIZE * 2,
        MemoryProtection::READ_WRITE_EXECUTE,
    );

    let (read, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ,
    );
    let error = authority
        .prepare_replace::<2, 2>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                read,
                1,
                PAGE_SIZE,
                MemoryProtection::READ,
            )],
            Some(authorization),
        )
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::Unaligned);
    assert!(error.into_final_releases().is_empty());

    let (read_write, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ_WRITE,
    );
    let prepared = authority
        .prepare_replace::<2, 2>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                read_write,
                0,
                PAGE_SIZE,
                MemoryProtection::READ_WRITE,
            )],
            Some(authorization),
        )
        .unwrap();
    assert!(prepared.commit().is_empty());
    assert_eq!(authority.active_lease_count(), 1);

    let (read_execute, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ_WRITE_EXECUTE,
    );
    let error = authority
        .prepare_replace::<2, 2>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                read_execute,
                PAGE_SIZE,
                PAGE_SIZE,
                MemoryProtection::READ_EXECUTE,
            )],
            Some(authorization),
        )
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::WritableExecutableAlias);
    assert!(error.into_final_releases().is_empty());
    assert_eq!(authority.active_lease_count(), 1);
}

#[test]
fn protection_ceiling_is_captured_per_object() {
    let (space, region) = ids();
    let mut registry = ObjectRegistry::<2>::new();
    let mut authority = MemoryObjectAuthority::<2, 2>::new();
    let (key, owner) = grant(
        &mut authority,
        &mut registry,
        PAGE_SIZE,
        MemoryProtection::READ_WRITE,
    );
    let (read_write, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ_WRITE,
    );
    let error = authority
        .prepare_replace::<1, 2>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                read_write,
                0,
                PAGE_SIZE,
                MemoryProtection::READ_EXECUTE,
            )],
            Some(authorization),
        )
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::ProtectionCeiling);
    assert!(error.into_final_releases().is_empty());
}

#[test]
#[allow(
    unsafe_code,
    reason = "the synthetic manager test attests complete zeroing before typed backing assignment"
)]
fn authorization_pin_transfers_to_lease_and_final_unmap_reclaims_backing() {
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
    let allocation = roles.allocate(1).unwrap();
    let physical_start = allocation.physical_start();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();

    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 2>::new();
    let key = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE,
        )
        .unwrap();
    let owner = registry.creation_into_internal(creation).unwrap();
    let (space, region) = ids();
    let (captured, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ_WRITE,
    );
    let prepared = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                captured,
                0,
                PAGE_SIZE,
                MemoryProtection::READ,
            )],
            Some(authorization),
        )
        .unwrap();
    let lease = prepared.tickets()[0].unwrap().lease();
    assert!(prepared.commit().is_empty());
    assert_eq!(authority.active_lease_count(), 1);

    assert!(registry.release_internal(owner).unwrap().is_none());
    let prepared = authority
        .prepare_replace::<1, 1>(&mut registry, space, region, &[lease], &[], None)
        .unwrap();
    let final_release = only_final(prepared.commit());
    let finalization = authority.take_finalization(final_release).unwrap();
    complete_memory_finalization(&mut registry, &mut roles, finalization);
    let recycled = roles.allocate(1).unwrap();
    assert_eq!(recycled.physical_start(), physical_start);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the synthetic manager test attests complete zeroing before typed backing assignment"
)]
fn failed_mapping_preparation_drops_last_authorization_pin() {
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
    let allocation = roles.allocate(1).unwrap();
    let physical_start = allocation.physical_start();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 1>::new();
    let key = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE,
        )
        .unwrap();
    let owner = registry.creation_into_internal(creation).unwrap();
    let (space, region) = ids();
    let (captured, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ_WRITE,
    );
    assert!(registry.release_internal(owner).unwrap().is_none());

    let error = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                captured,
                1,
                PAGE_SIZE,
                MemoryProtection::READ,
            )],
            Some(authorization),
        )
        .err()
        .expect("unaligned mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::Unaligned);
    let final_release = only_final(error.into_final_releases());
    let finalization = authority.take_finalization(final_release).unwrap();
    complete_memory_finalization(&mut registry, &mut roles, finalization);
    let recycled = roles.allocate(1).unwrap();
    assert_eq!(recycled.physical_start(), physical_start);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the synthetic manager test attests complete zeroing before typed backing assignment"
)]
fn mapping_split_retains_positive_delta_and_rollback_is_exact() {
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
    let allocation = roles.allocate(2).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 4>::new();
    let key = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE * 2,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE,
        )
        .unwrap();
    let owner = registry.creation_into_internal(creation).unwrap();
    let (space, region) = ids();
    let (captured, authorization) = mapping(
        &authority,
        &mut registry,
        &owner,
        key,
        space,
        region,
        MemoryProtection::READ_WRITE,
    );
    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::new(
                space,
                region,
                captured,
                0,
                PAGE_SIZE * 2,
                MemoryProtection::READ,
            )],
            Some(authorization),
        )
        .unwrap();
    let whole_lease = prepared.tickets()[0].unwrap().lease();
    assert!(prepared.commit().is_empty());
    assert_eq!(authority.active_lease_count(), 1);

    let split_requests = [
        LeaseRequest::new(
            space,
            region,
            captured,
            0,
            PAGE_SIZE,
            MemoryProtection::READ,
        ),
        LeaseRequest::new(
            space,
            region,
            captured,
            PAGE_SIZE,
            PAGE_SIZE,
            MemoryProtection::READ,
        ),
    ];
    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            space,
            region,
            &[whole_lease],
            &split_requests,
            None,
        )
        .unwrap();
    assert!(prepared.rollback().is_empty());
    assert_eq!(authority.active_lease_count(), 1);

    assert!(registry.release_internal(owner).unwrap().is_none());
    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            space,
            region,
            &[whole_lease],
            &split_requests,
            None,
        )
        .unwrap();
    let first_split = prepared.tickets()[0].unwrap().lease();
    let second_split = prepared.tickets()[1].unwrap().lease();
    assert!(prepared.commit().is_empty());
    assert_eq!(authority.active_lease_count(), 2);

    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            space,
            region,
            &[first_split, second_split],
            &[],
            None,
        )
        .unwrap();
    let final_release = only_final(prepared.commit());
    assert_eq!(authority.active_lease_count(), 0);
    let finalization = authority.take_finalization(final_release).unwrap();
    complete_memory_finalization(&mut registry, &mut roles, finalization);
    assert!(registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).is_ok());
}

#[test]
fn d6_handle_close_and_mapping_commit_interleavings_preserve_backing() {
    let full = deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT);

    for close_before_authorization in [false, true] {
        let (mut roles, mut registry, mut authority, mut table, _key, source, physical_start) =
            handled_object::<1>(full, MemoryProtection::READ_WRITE);
        let (space, region) = ids();
        let resolved = table
            .lookup(
                &mut registry,
                source,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_MEMORY_OBJECT),
                DwRights(0),
            )
            .unwrap();

        if close_before_authorization {
            assert!(table.close(&mut registry, source).unwrap().is_none());
        }
        let authorization = authority
            .issue_map_authorization(resolved, space, region, MemoryProtection::READ)
            .unwrap();
        let captured = authorization.capture(space, region).unwrap();
        let prepared = authority
            .prepare_replace::<1, 2>(
                &mut registry,
                space,
                region,
                &[],
                &[LeaseRequest::new(
                    space,
                    region,
                    captured,
                    0,
                    PAGE_SIZE,
                    MemoryProtection::READ,
                )],
                Some(authorization),
            )
            .unwrap();
        let lease = prepared.tickets()[0].unwrap().lease();
        assert!(prepared.commit().is_empty());
        assert_eq!(authority.active_lease_count(), 1);

        if !close_before_authorization {
            assert!(table.close(&mut registry, source).unwrap().is_none());
        }
        assert_eq!(
            table.lookup(&mut registry, source, AcceptedObjectTypes::Any, DwRights(0)),
            Err(HandleTableError::InvalidHandle)
        );

        let prepared = authority
            .prepare_replace::<1, 2>(&mut registry, space, region, &[lease], &[], None)
            .unwrap();
        let final_release = only_final(prepared.commit());
        complete_memory_release(&mut registry, &mut authority, &mut roles, final_release);
        assert_eq!(roles.allocate(1).unwrap().physical_start(), physical_start);
    }
}

#[test]
#[allow(
    unsafe_code,
    reason = "test manager models complete physical zeroing before typed backing assignment"
)]
fn allocator_backing_is_reclaimed_only_through_typed_finalization() {
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
    let allocation = roles.allocate(1).unwrap();
    let physical_start = allocation.physical_start();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();

    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 1>::new();
    let key = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE,
        )
        .unwrap();
    let final_release = registry.release_creation(creation).unwrap().unwrap();
    let finalization = authority.take_finalization(final_release).unwrap();
    assert_eq!(
        authority.object_info(key),
        Err(MemoryObjectError::InvalidObjectKey)
    );
    complete_memory_finalization(&mut registry, &mut roles, finalization);

    let recycled = roles.allocate(1).unwrap();
    assert_eq!(recycled.physical_start(), physical_start);
}

#[test]
fn immutable_backing_retires_logically_without_allocator_reclamation() {
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 2);
    let backing = crate::memory::frame_roles::synthetic_immutable_module_backing(0x80_000, 1, 7);
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 1>::new();
    authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::ImmutableBootModule,
            MemoryProtection::READ,
        )
        .unwrap();
    let final_release = registry.release_creation(creation).unwrap().unwrap();
    let finalization = authority.take_finalization(final_release).unwrap();
    complete_memory_finalization(&mut registry, &mut roles, finalization);

    assert!(registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).is_ok());
    assert_eq!(roles.allocate(2).unwrap().byte_len(), PAGE_SIZE * 2);
}

#[test]
fn wrong_final_release_cannot_consume_memory_payload() {
    use deepwyrm_abi::DW_OBJECT_TYPE_EVENT;

    let mut registry = ObjectRegistry::<2>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let event = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 1>::new();
    let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x20_000, 1);
    let key = authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ,
        )
        .unwrap();
    let event_final = registry.release_creation(event).unwrap().unwrap();
    let error = authority
        .take_finalization(event_final)
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::FinalizationMismatch);
    let event_final = error.into_final_release();
    registry.complete_finalization(event_final).unwrap();
    assert!(authority.object_info(key).is_ok());
}

#[test]
fn empty_replacements_and_sentinels_never_enter_lease_transitions() {
    let (space, region) = ids();
    let mut registry = ObjectRegistry::<1>::new();
    let mut authority = MemoryObjectAuthority::<1, 1>::new();

    let error = authority
        .prepare_replace::<1, 1>(&mut registry, space, region, &[], &[], None)
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::Empty);
    assert!(error.into_final_releases().is_empty());

    let error = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            space,
            region,
            &[],
            &[LeaseRequest::EMPTY],
            None,
        )
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::ForeignLease);
    assert!(error.into_final_releases().is_empty());

    let error = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            AddressSpaceKey::EMPTY,
            RegionKey::EMPTY,
            &[],
            &[],
            None,
        )
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::ForeignLease);
    assert!(error.into_final_releases().is_empty());
    assert_eq!(authority.active_lease_count(), 0);
}
