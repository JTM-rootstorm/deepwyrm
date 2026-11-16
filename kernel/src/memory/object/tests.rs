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

fn only_final(releases: MappingFinalReleases) -> FinalRelease {
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
    assert!(complete_memory_finalization(registry, roles, finalization).is_none());
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
fn kernel_population_requires_held_writable_page_backed_reference() {
    for (ceiling, expected) in [
        (MemoryProtection::READ_WRITE, Ok(())),
        (
            MemoryProtection::READ,
            Err(MemoryObjectError::ProtectionCeiling),
        ),
    ] {
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let backing = crate::memory::frame_roles::synthetic_allocator_backing(0x48_000, 1);
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        let binding = authority
            .bind_backing(
                creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                ceiling,
            )
            .unwrap();
        let bound = registry.finish_payload_binding(binding).unwrap();
        let handle = registry.bound_into_handle(bound).unwrap();

        assert_eq!(
            authority.backing_for_population(&handle).map(|_| ()),
            expected
        );

        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = authority.take_finalization(final_release).unwrap();
        let (release, _backing) = finalization.into_parts();
        registry.complete_finalization(release).unwrap();
    }
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
    let mut plan = ReplacePlan::<1>::new();
    let prepared = authority
        .prepare_replace::<1, 2>(
            &mut registry,
            &mut plan,
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
            &[],
            Some(authorization),
        )
        .unwrap();
    assert!(prepared.commit().settle_locally(&mut registry).is_empty());
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
    let mut plan = ReplacePlan::<2>::new();
    let error = authority
        .prepare_replace::<2, 2>(
            &mut registry,
            &mut plan,
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
            &[],
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
    let mut plan = ReplacePlan::<2>::new();
    let prepared = authority
        .prepare_replace::<2, 2>(
            &mut registry,
            &mut plan,
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
            &[],
            Some(authorization),
        )
        .unwrap();
    assert!(prepared.commit().settle_locally(&mut registry).is_empty());
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
    let mut plan = ReplacePlan::<2>::new();
    let error = authority
        .prepare_replace::<2, 2>(
            &mut registry,
            &mut plan,
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
            &[],
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
    let mut plan = ReplacePlan::<1>::new();
    let error = authority
        .prepare_replace::<1, 2>(
            &mut registry,
            &mut plan,
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
            &[],
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
    let mut plan = ReplacePlan::<1>::new();
    let prepared = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            &mut plan,
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
            &[],
            Some(authorization),
        )
        .unwrap();
    let lease = prepared.tickets()[0].unwrap().lease();
    assert!(prepared.commit().settle_locally(&mut registry).is_empty());
    assert_eq!(authority.active_lease_count(), 1);

    assert!(registry.release_internal(owner).unwrap().is_none());
    let mut plan = ReplacePlan::<1>::new();
    let prepared = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            &mut plan,
            space,
            region,
            &[lease],
            &[],
            &[],
            None,
        )
        .unwrap();
    let final_release = only_final(prepared.commit().settle_locally(&mut registry));
    let finalization = authority.take_finalization(final_release).unwrap();
    assert!(complete_memory_finalization(&mut registry, &mut roles, finalization).is_none());
    let recycled = roles.allocate(1).unwrap();
    assert_eq!(recycled.physical_start(), physical_start);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the synthetic manager test attests complete zeroing before typed backing assignment"
)]
fn exhausted_lease_slot_is_skipped_when_later_capacity_exists() {
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
    let allocation = roles.allocate(1).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let backing = roles.assign_object_backing(zeroed).unwrap();
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 2>::new();
    authority.leases[0].generation = u32::MAX;
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

    let mut plan = ReplacePlan::<1>::new();
    let prepared = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            &mut plan,
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
            &[],
            Some(authorization),
        )
        .unwrap();
    let lease = prepared.tickets()[0].unwrap().lease();
    assert_eq!(decode_raw_key(lease.raw).unwrap().0, 1);
    assert!(prepared.commit().settle_locally(&mut registry).is_empty());
    assert_eq!(authority.active_lease_count(), 1);
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

    let mut plan = ReplacePlan::<1>::new();
    let error = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            &mut plan,
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
            &[],
            Some(authorization),
        )
        .err()
        .expect("unaligned mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::Unaligned);
    let final_release = only_final(error.into_final_releases());
    let finalization = authority.take_finalization(final_release).unwrap();
    assert!(complete_memory_finalization(&mut registry, &mut roles, finalization).is_none());
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
    let mut plan = ReplacePlan::<2>::new();
    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            &mut plan,
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
            &[],
            Some(authorization),
        )
        .unwrap();
    let whole_lease = prepared.tickets()[0].unwrap().lease();
    assert!(prepared.commit().settle_locally(&mut registry).is_empty());
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
    let mut plan = ReplacePlan::<2>::new();
    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            &mut plan,
            space,
            region,
            &[whole_lease],
            &split_requests,
            &[],
            None,
        )
        .unwrap();
    assert!(prepared.rollback().is_empty());
    assert_eq!(authority.active_lease_count(), 1);

    assert!(registry.release_internal(owner).unwrap().is_none());
    let mut plan = ReplacePlan::<2>::new();
    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            &mut plan,
            space,
            region,
            &[whole_lease],
            &split_requests,
            &[],
            None,
        )
        .unwrap();
    let first_split = prepared.tickets()[0].unwrap().lease();
    let second_split = prepared.tickets()[1].unwrap().lease();
    assert!(prepared.commit().settle_locally(&mut registry).is_empty());
    assert_eq!(authority.active_lease_count(), 2);

    let mut plan = ReplacePlan::<2>::new();
    let prepared = authority
        .prepare_replace::<2, 1>(
            &mut registry,
            &mut plan,
            space,
            region,
            &[first_split, second_split],
            &[],
            &[],
            None,
        )
        .unwrap();
    let final_release = only_final(prepared.commit().settle_locally(&mut registry));
    assert_eq!(authority.active_lease_count(), 0);
    let finalization = authority.take_finalization(final_release).unwrap();
    assert!(complete_memory_finalization(&mut registry, &mut roles, finalization).is_none());
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
        let mut plan = ReplacePlan::<1>::new();
        let prepared = authority
            .prepare_replace::<1, 2>(
                &mut registry,
                &mut plan,
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
                &[],
                Some(authorization),
            )
            .unwrap();
        let lease = prepared.tickets()[0].unwrap().lease();
        assert!(prepared.commit().settle_locally(&mut registry).is_empty());
        assert_eq!(authority.active_lease_count(), 1);

        if !close_before_authorization {
            assert!(table.close(&mut registry, source).unwrap().is_none());
        }
        assert_eq!(
            table.lookup(&mut registry, source, AcceptedObjectTypes::Any, DwRights(0)),
            Err(HandleTableError::InvalidHandle)
        );

        let mut plan = ReplacePlan::<1>::new();
        let prepared = authority
            .prepare_replace::<1, 2>(
                &mut registry,
                &mut plan,
                space,
                region,
                &[lease],
                &[],
                &[],
                None,
            )
            .unwrap();
        let final_release = only_final(prepared.commit().settle_locally(&mut registry));
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
    assert!(complete_memory_finalization(&mut registry, &mut roles, finalization).is_none());

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
    assert!(complete_memory_finalization(&mut registry, &mut roles, finalization).is_none());

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

    let mut plan = ReplacePlan::<1>::new();
    let error = authority
        .prepare_replace::<1, 1>(&mut registry, &mut plan, space, region, &[], &[], &[], None)
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::Empty);
    assert!(error.into_final_releases().is_empty());

    let mut plan = ReplacePlan::<1>::new();
    let error = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            &mut plan,
            space,
            region,
            &[],
            &[LeaseRequest::EMPTY],
            &[],
            None,
        )
        .err()
        .expect("mapping preparation must fail");
    assert_eq!(error.error(), MemoryObjectError::ForeignLease);
    assert!(error.into_final_releases().is_empty());

    let mut plan = ReplacePlan::<1>::new();
    let error = authority
        .prepare_replace::<1, 1>(
            &mut registry,
            &mut plan,
            AddressSpaceKey::EMPTY,
            RegionKey::EMPTY,
            &[],
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

/// A DeviceResource object whose only reference is the returned pin.
fn device_resource_pin(registry: &mut ObjectRegistry<2>) -> InternalRef {
    let creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE)
        .unwrap();
    registry.creation_into_internal(creation).unwrap()
}

#[test]
fn device_mmio_objects_are_whole_bar_uncached_and_never_executable() {
    let mut registry = ObjectRegistry::<2>::new();
    let parent = device_resource_pin(&mut registry);
    let backing = crate::memory::frame_roles::synthetic_device_mmio_backing(0xe1_0000_0000, 2);
    let binding_backing = backing.identity();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<2, 1>::new();
    let binding = authority
        .bind_device_mmio(creation, backing, parent)
        .unwrap();
    let key = binding.key();
    let info = authority.object_info(key).unwrap();
    assert_eq!(info.kind, MemoryObjectKind::DeviceMmio);
    assert_eq!(info.logical_byte_len, 2 * PAGE_SIZE);
    assert_eq!(info.protection_ceiling, MemoryProtection::READ_WRITE);
    let record = authority.object_record(key).unwrap();
    let range = object_range(record, PAGE_SIZE, PAGE_SIZE).unwrap();
    assert!(range.uncached());
    assert_eq!(range.object_offset(), PAGE_SIZE);
    assert_eq!(range.backing_identity(), binding_backing);
    let _ = registry.finish_payload_binding(binding).unwrap();

    // The generic bind path refuses an executable ceiling or a partial BAR.
    let mut registry = ObjectRegistry::<2>::new();
    for (ceiling, logical) in [
        (MemoryProtection::READ_WRITE_EXECUTE, 2 * PAGE_SIZE),
        (MemoryProtection::READ_WRITE, PAGE_SIZE),
    ] {
        let backing = crate::memory::frame_roles::synthetic_device_mmio_backing(0xe2_0000_0000, 2);
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let error = authority
            .bind_backing(
                creation,
                backing,
                logical,
                MemoryObjectKind::DeviceMmio,
                ceiling,
            )
            .unwrap_err();
        assert_eq!(error.error(), MemoryObjectError::ProtectionCeiling);
        let (creation, _backing) = error.into_parts();
        registry.cancel_creation(creation).unwrap();
    }
}

#[test]
fn a_device_mmio_parent_must_be_a_device_resource() {
    let mut registry = ObjectRegistry::<2>::new();
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let event = registry.create(deepwyrm_abi::DW_OBJECT_TYPE_EVENT).unwrap();
    let wrong_parent = registry.creation_into_internal(event).unwrap();
    let backing = crate::memory::frame_roles::synthetic_device_mmio_backing(0xe3_0000_0000, 1);
    let mut authority = MemoryObjectAuthority::<1, 1>::new();
    let (error, parent) = authority
        .bind_device_mmio(creation, backing, wrong_parent)
        .unwrap_err();
    assert_eq!(error.error(), MemoryObjectError::ObjectReference);
    assert_eq!(parent.object_type(), deepwyrm_abi::DW_OBJECT_TYPE_EVENT);
    let (creation, _backing) = error.into_parts();
    registry.cancel_creation(creation).unwrap();
}

#[test]
fn device_mmio_finalization_returns_the_bar_then_releases_the_resource() {
    const RESOURCE_ID: u64 = 0x6b33_0001;
    const BAR: u64 = 0xe4_0000_0000;
    let mut roles = crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x10_000, 2);
    let mut registry = ObjectRegistry::<2>::new();
    let parent = device_resource_pin(&mut registry);
    let parent_id = parent.id();
    // Any identity serves as the holder here.
    crate::device::pci::PCI_FUNCTIONS.record_lent_for_test(RESOURCE_ID, BAR, parent_id);
    let backing = crate::memory::frame_roles::synthetic_device_mmio_backing(BAR, 1);
    let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut authority = MemoryObjectAuthority::<1, 1>::new();
    let binding = authority
        .bind_device_mmio(creation, backing, parent)
        .unwrap();
    let bound = registry.finish_payload_binding(binding).unwrap();
    let handle = registry.bound_into_handle(bound).unwrap();
    assert!(!crate::device::pci::PCI_FUNCTIONS.bar_is_available_for_test(RESOURCE_ID));

    let final_release = registry.release_handle(handle).unwrap().unwrap();
    let finalization = authority.take_finalization(final_release).unwrap();
    let parent_release = complete_memory_finalization(&mut registry, &mut roles, finalization)
        .expect("the DeviceMmio object held the resource's last reference");
    assert_eq!(parent_release.id(), parent_id);
    assert_eq!(
        parent_release.object_type(),
        deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE
    );
    assert!(crate::device::pci::PCI_FUNCTIONS.bar_is_available_for_test(RESOURCE_ID));
    // The memory object's slot is free again.
    assert!(registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).is_ok());
    let _ = parent_release;
}

/// DW2 §10.12: an on-demand object's finalization is owed and done in
/// steps, its weight falling with each, its slot held until it completes.
mod owed_finalization {
    use super::*;
    use crate::memory::frame_roles::{FrameRoleManager, IndexMemory, synthetic_frame_role_manager};
    use crate::object::charge::ChargeTag;
    use deepwyrm_abi::DW_OBJECT_TYPE_EVENT;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Model {
        zeroed: Mutex<BTreeSet<u64>>,
        entries: Mutex<BTreeMap<(u64, usize), u64>>,
    }

    impl IndexMemory for Model {
        fn read(&self, node: u64, entry: usize) -> u64 {
            let entries = self.entries.lock().unwrap();
            match entries.get(&(node, entry)) {
                Some(value) => *value,
                None if self.zeroed.lock().unwrap().contains(&node) => 0,
                None => panic!("an index node is read before it is zeroed"),
            }
        }

        #[allow(
            unsafe_code,
            reason = "the model implements the trait's unsafe methods"
        )]
        unsafe fn write(&self, node: u64, entry: usize, value: u64) {
            self.entries.lock().unwrap().insert((node, entry), value);
        }

        #[allow(
            unsafe_code,
            reason = "the model implements the trait's unsafe methods"
        )]
        unsafe fn zero(&self, page: u64) -> bool {
            self.entries
                .lock()
                .unwrap()
                .retain(|(node, _), _| *node != page);
            self.zeroed.lock().unwrap().insert(page);
            true
        }
    }

    type Roles = FrameRoleManager<4, 128>;

    fn roles() -> Roles {
        let mut roles = synthetic_frame_role_manager::<4, 128>(0x1000, 96);
        roles.set_index_memory(Box::leak(Box::<Model>::default()));
        roles
    }

    /// An on-demand object of `pages` pages with `committed` committed,
    /// charged to `group` for its frames, held by its returned owner.
    fn on_demand<const OBJECTS: usize, const REGISTRY: usize>(
        authority: &mut MemoryObjectAuthority<OBJECTS, 1>,
        registry: &mut ObjectRegistry<REGISTRY>,
        roles: &mut Roles,
        group: crate::object::ObjectId,
        pages: u64,
        committed: &[u64],
    ) -> Result<(InternalRef, u64), MemoryObjectError> {
        let backing = roles.allocate_on_demand_backing(pages).unwrap();
        for &page in committed {
            roles
                .commit_on_demand_page(backing.identity(), page)
                .unwrap();
        }
        let frames = roles.on_demand_frames(backing.identity()).unwrap();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        if let Err(error) = authority.grant_backing(
            &creation,
            backing,
            pages * PAGE_SIZE,
            MemoryObjectKind::OnDemand,
            MemoryProtection::READ_WRITE,
        ) {
            roles.cancel_object_backing(error.into_backing()).unwrap();
            registry.cancel_creation(creation).unwrap();
            return Err(MemoryObjectError::Capacity);
        }
        let owner = registry.creation_into_internal(creation).unwrap();
        let mut tag = ChargeTag::EMPTY;
        assert!(tag.push(group));
        registry.set_charge_tag(owner.id(), tag).unwrap();
        registry.set_charge_pages(owner.id(), frames).unwrap();
        Ok((owner, frames))
    }

    /// Releases `owner`, the object's last reference, as the cleanup
    /// drain's `finalize_one` does: the finalization is taken and owed.
    fn finalize<const OBJECTS: usize, const REGISTRY: usize>(
        authority: &mut MemoryObjectAuthority<OBJECTS, 1>,
        registry: &mut ObjectRegistry<REGISTRY>,
        owner: InternalRef,
    ) {
        let last = registry
            .release_internal(owner)
            .unwrap()
            .expect("the last reference");
        let finalization = authority.take_finalization(last).unwrap();
        assert!(authority.defer_finalization(finalization).is_none());
    }

    #[test]
    fn a_large_object_is_freed_in_steps_its_charge_falling_with_each() {
        let mut roles = roles();
        let initial = roles.available_frames();
        let mut registry = ObjectRegistry::<3>::new();
        let group = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
        let group_id = group.id();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        let committed: std::vec::Vec<u64> = (0..20).chain([1500, 2047]).collect();
        let (owner, frames) = on_demand(
            &mut authority,
            &mut registry,
            &mut roles,
            group_id,
            2048,
            &committed,
        )
        .unwrap();
        let object = owner.id();
        assert_eq!(registry.charged_pages(group_id), frames as usize);
        finalize(&mut authority, &mut registry, owner);
        assert!(authority.finalization_owed());
        // Still charged while its frames are held; unreachable meanwhile.
        assert_eq!(registry.charged_pages(group_id), frames as usize);
        assert!(registry.charge(object).is_err());
        assert!(!authority.object_is_on_demand(object));
        assert!(
            authority
                .object_info(MemoryObjectKey {
                    object: Some(object)
                })
                .is_err()
        );
        let mut steps = 0;
        let mut charged = frames as usize;
        loop {
            let held = roles.available_frames();
            let owed = authority.finalize_owed_step(&mut registry, &mut roles, 5);
            steps += 1;
            roles.check_invariants().unwrap();
            if !owed {
                break;
            }
            let freed = usize::try_from(roles.available_frames() - held).unwrap();
            assert!(freed != 0 || registry.charged_pages(group_id) == charged);
            assert_eq!(registry.charged_pages(group_id), charged - freed);
            charged -= freed;
        }
        assert!(steps > 3, "a large object takes several steps");
        assert_eq!(registry.charged_pages(group_id), 0);
        assert_eq!(roles.available_frames(), initial);
        // Its registry slot is free again.
        let reused = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        registry.cancel_creation(reused).unwrap();
        let _ = group;
    }

    #[test]
    fn a_releasing_slot_is_not_reused_until_its_object_completes() {
        let mut roles = roles();
        let mut registry = ObjectRegistry::<3>::new();
        let group = registry.create(DW_OBJECT_TYPE_EVENT).unwrap().id();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        let (owner, _) = on_demand(
            &mut authority,
            &mut registry,
            &mut roles,
            group,
            1024,
            &[0, 700],
        )
        .unwrap();
        finalize(&mut authority, &mut registry, owner);
        assert_eq!(
            on_demand(&mut authority, &mut registry, &mut roles, group, 1, &[]).err(),
            Some(MemoryObjectError::Capacity)
        );
        while authority.finalize_owed_step(&mut registry, &mut roles, 2) {}
        assert!(on_demand(&mut authority, &mut registry, &mut roles, group, 1, &[]).is_ok());
    }

    #[test]
    fn owed_objects_complete_oldest_first_sharing_one_step() {
        let mut roles = roles();
        let mut registry = ObjectRegistry::<4>::new();
        let group = registry.create(DW_OBJECT_TYPE_EVENT).unwrap().id();
        let mut authority = MemoryObjectAuthority::<2, 1>::new();
        let (first, _) = on_demand(
            &mut authority,
            &mut registry,
            &mut roles,
            group,
            600,
            &[0, 599],
        )
        .unwrap();
        let (second, _) =
            on_demand(&mut authority, &mut registry, &mut roles, group, 8, &[3]).unwrap();
        finalize(&mut authority, &mut registry, first);
        finalize(&mut authority, &mut registry, second);
        // A step too small for the first leaves the second untouched.
        assert!(authority.finalize_owed_step(&mut registry, &mut roles, 1));
        assert!(registry.charged_pages(group) >= 2);
        // A step with room for both, each completion counted as the root's
        // 512 entries it reads, completes both.
        assert!(!authority.finalize_owed_step(&mut registry, &mut roles, 2048));
        assert_eq!(registry.charged_pages(group), 0);
        roles.check_invariants().unwrap();
    }

    /// DW2 §10.19 revision 2: the step report sees each object a step works
    /// on by its owed slot, oldest first, with the frames freed and its
    /// completion; the frames it is told of are the frames that came back.
    #[test]
    fn a_step_reports_each_object_s_slot_frames_and_completion() {
        let mut roles = roles();
        let initial = roles.available_frames();
        let mut registry = ObjectRegistry::<4>::new();
        let group = registry.create(DW_OBJECT_TYPE_EVENT).unwrap().id();
        let mut authority = MemoryObjectAuthority::<2, 1>::new();
        let (first, first_frames) = on_demand(
            &mut authority,
            &mut registry,
            &mut roles,
            group,
            600,
            &[0, 599],
        )
        .unwrap();
        let (second, second_frames) =
            on_demand(&mut authority, &mut registry, &mut roles, group, 8, &[3]).unwrap();
        assert_eq!(authority.owed_slots().count(), 0);
        finalize(&mut authority, &mut registry, first);
        finalize(&mut authority, &mut registry, second);
        let slots: std::vec::Vec<usize> = authority.owed_slots().collect();
        assert_eq!(slots.len(), 2);
        assert_ne!(slots[0], slots[1]);
        let mut seen = std::vec::Vec::new();
        while authority.finalize_owed_step_observed(
            &mut registry,
            &mut roles,
            300,
            |slot, freed, completed| seen.push((slot, freed, completed)),
        ) {
            let left: std::vec::Vec<usize> = authority.owed_slots().collect();
            assert!(slots.ends_with(&left), "the oldest goes first");
        }
        assert_eq!(authority.owed_slots().count(), 0);
        for (index, frames) in [(0, first_frames), (1, second_frames)] {
            let mine: std::vec::Vec<_> = seen
                .iter()
                .filter(|(slot, _, _)| *slot == slots[index])
                .collect();
            let completions = mine.iter().filter(|(_, _, completed)| *completed).count();
            assert_eq!(completions, 1, "each completes once");
            assert!(mine.last().unwrap().2, "and last");
            // Every frame but the root, which completion frees.
            let freed: u64 = mine.iter().map(|(_, freed, _)| freed).sum();
            assert_eq!(freed, frames - 1);
        }
        assert_eq!(roles.available_frames(), initial);
        roles.check_invariants().unwrap();
    }

    /// Second security pass D-2: a completion reads the root's entries, so
    /// one step of the live budget completes one object, however small.
    #[test]
    fn a_completion_costs_its_root_s_entries() {
        let mut roles = roles();
        let mut registry = ObjectRegistry::<4>::new();
        let group = registry.create(DW_OBJECT_TYPE_EVENT).unwrap().id();
        let mut authority = MemoryObjectAuthority::<2, 1>::new();
        for _ in 0..2 {
            let (owner, _) =
                on_demand(&mut authority, &mut registry, &mut roles, group, 1, &[0]).unwrap();
            finalize(&mut authority, &mut registry, owner);
        }
        assert!(authority.finalize_owed_step(&mut registry, &mut roles, 512));
        assert_eq!(
            registry.charged_pages(group),
            2,
            "the second's root and page"
        );
        assert!(!authority.finalize_owed_step(&mut registry, &mut roles, 512));
        assert_eq!(registry.charged_pages(group), 0);
    }

    /// DW2 §12.10 part 2 items 6 and 8: a page-backed object whose backing
    /// is indexed is owed too, and each step lowers its charge, its pages,
    /// by the run pages it freed; its index nodes are not charged.
    #[test]
    #[allow(
        unsafe_code,
        reason = "the host model never dereferences synthetic physical memory"
    )]
    fn an_indexed_page_backed_object_is_freed_in_steps_its_charge_falling_by_run_pages() {
        let mut roles = synthetic_frame_role_manager::<64, 128>(0x1000, 96);
        roles.set_index_memory(Box::leak(Box::<Model>::default()));
        // Every other page held: 48 one-page holes.
        let mut gaps = std::vec::Vec::new();
        for _ in 0..48 {
            gaps.push(roles.allocate(1).unwrap());
            roles.allocate(1).unwrap();
        }
        for gap in gaps {
            roles.cancel_allocation(gap).unwrap();
        }
        let initial = roles.available_frames();
        let pages = 40;
        let allocation = roles.allocate_backing(pages).unwrap();
        // SAFETY: the host model never dereferences the synthetic runs.
        let backing = unsafe { roles.assume_backing_zeroed(allocation) }.unwrap();
        assert_eq!(backing.kind(), ObjectBackingKind::AllocatorIndexed);
        assert_eq!(backing.run_count(), pages);
        // The runs and the root.
        assert_eq!(roles.available_frames(), initial - pages - 1);

        let mut registry = ObjectRegistry::<3>::new();
        let group = registry.create(DW_OBJECT_TYPE_EVENT).unwrap().id();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        authority
            .grant_backing(
                &creation,
                backing,
                pages * PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ_WRITE,
            )
            .unwrap();
        let owner = registry.creation_into_internal(creation).unwrap();
        let mut tag = ChargeTag::EMPTY;
        assert!(tag.push(group));
        registry.set_charge_tag(owner.id(), tag).unwrap();
        registry.set_charge_pages(owner.id(), pages).unwrap();
        finalize(&mut authority, &mut registry, owner);
        assert!(authority.finalization_owed());
        assert_eq!(registry.charged_pages(group), pages as usize);

        let mut charged = pages as usize;
        let mut steps = 0;
        let mut freed_total = 0_u64;
        loop {
            let held = roles.available_frames();
            let owed = authority.finalize_owed_step_observed(
                &mut registry,
                &mut roles,
                5,
                |_, freed, _| freed_total += freed,
            );
            steps += 1;
            roles.check_invariants().unwrap();
            let back = usize::try_from(roles.available_frames() - held).unwrap();
            if !owed {
                // The completing step also frees the root, which was never
                // charged.
                assert_eq!(registry.charged_pages(group), 0);
                assert_eq!(back, charged + 1);
                break;
            }
            assert_eq!(registry.charged_pages(group), charged - back);
            charged -= back;
        }
        assert!(steps > 3, "the object takes several steps");
        assert_eq!(freed_total, pages);
        assert_eq!(roles.available_frames(), initial);
    }

    #[test]
    fn only_on_demand_objects_are_owed() {
        let mut registry = ObjectRegistry::<1>::new();
        let mut authority = MemoryObjectAuthority::<1, 1>::new();
        let (_, owner) = grant(
            &mut authority,
            &mut registry,
            PAGE_SIZE,
            MemoryProtection::READ_WRITE,
        );
        let last = registry.release_internal(owner).unwrap().unwrap();
        let finalization = authority.take_finalization(last).unwrap();
        let finalization = authority
            .defer_finalization(finalization)
            .expect("a page-backed object completes at once");
        assert!(!authority.finalization_owed());
        let (cleanup, _backing) = into_page_backed_cancellation_parts(finalization);
        let _ = registry.complete_payload_finalization(cleanup);
    }
}
