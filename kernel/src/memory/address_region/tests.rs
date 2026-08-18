extern crate std;

use super::super::object::MemoryObjectKind;
use super::*;
use crate::object::{InternalRef, ObjectRegistry};
use crate::task::{TaskAuthority, TaskError, complete_task_finalization};
use deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT;
use std::boxed::Box;
use std::ops::{Deref, DerefMut};

struct FakePublisher {
    address_space: AddressSpaceKey,
    calls: usize,
    fail: bool,
    last_before: usize,
    last_after: usize,
}

impl FakePublisher {
    fn for_region<const SLOTS: usize>(region: &AddressRegion<SLOTS>) -> Self {
        Self {
            address_space: region.address_space,
            calls: 0,
            fail: false,
            last_before: 0,
            last_after: 0,
        }
    }
}

impl publisher_seal::Sealed for FakePublisher {}

#[allow(
    unsafe_code,
    reason = "the synthetic publisher preserves the supplied root identity"
)]
unsafe impl AddressSpacePublisher for FakePublisher {
    type Error = ();

    fn address_space_key(&self) -> AddressSpaceKey {
        self.address_space
    }

    fn publish_replace(
        &mut self,
        address_space: AddressSpaceKey,
        _region: RegionKey,
        before: &[Mapping],
        after: &[Mapping],
    ) -> Result<(), Self::Error> {
        if address_space != self.address_space {
            return Err(());
        }
        self.calls += 1;
        self.last_before = before.len();
        self.last_after = after.len();
        if self.fail { Err(()) } else { Ok(()) }
    }
}

struct TestObjects<const OBJECTS: usize, const LEASES: usize> {
    registry: ObjectRegistry<OBJECTS>,
    authority: MemoryObjectAuthority<OBJECTS, LEASES>,
    owners: [Option<InternalRef>; OBJECTS],
}

impl<const OBJECTS: usize, const LEASES: usize> TestObjects<OBJECTS, LEASES> {
    fn new() -> Self {
        Self {
            registry: ObjectRegistry::new(),
            authority: MemoryObjectAuthority::new(),
            owners: core::array::from_fn(|_| None),
        }
    }

    fn insert_owner(&mut self, owner: InternalRef) {
        let slot = self
            .owners
            .iter()
            .position(Option::is_none)
            .expect("test object owner capacity matches payload capacity");
        self.owners[slot] = Some(owner);
    }

    fn split_mut(
        &mut self,
    ) -> (
        &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        &mut ObjectRegistry<OBJECTS>,
    ) {
        (&mut self.authority, &mut self.registry)
    }
}

impl<const OBJECTS: usize, const LEASES: usize> Deref for TestObjects<OBJECTS, LEASES> {
    type Target = MemoryObjectAuthority<OBJECTS, LEASES>;

    fn deref(&self) -> &Self::Target {
        &self.authority
    }
}

impl<const OBJECTS: usize, const LEASES: usize> DerefMut for TestObjects<OBJECTS, LEASES> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.authority
    }
}

fn object<const OBJECTS: usize, const LEASES: usize>(
    authority: &mut TestObjects<OBJECTS, LEASES>,
    ceiling: Protection,
) -> MemoryObjectKey {
    object_at(authority, 0x20_000, ceiling)
}

fn object_at<const OBJECTS: usize, const LEASES: usize>(
    authority: &mut TestObjects<OBJECTS, LEASES>,
    physical_start: u64,
    ceiling: Protection,
) -> MemoryObjectKey {
    let backing = crate::memory::frame_roles::synthetic_allocator_backing(physical_start, 8);
    let creation = authority
        .registry
        .create(DW_OBJECT_TYPE_MEMORY_OBJECT)
        .unwrap();
    let key = authority
        .authority
        .grant_backing(
            &creation,
            backing,
            PAGE_SIZE * 8,
            MemoryObjectKind::PageBacked,
            ceiling,
        )
        .unwrap();
    let owner = authority.registry.creation_into_internal(creation).unwrap();
    authority.insert_owner(owner);
    key
}

fn authorization<const OBJECTS: usize, const LEASES: usize, const SLOTS: usize>(
    objects: &mut TestObjects<OBJECTS, LEASES>,
    object: MemoryObjectKey,
    region: &AddressRegion<SLOTS>,
    ceiling: Protection,
) -> MapAuthorization {
    let object_id = object.object_id().expect("test MemoryObject key is live");
    let owner_slot = objects
        .owners
        .iter()
        .position(|owner| owner.as_ref().is_some_and(|owner| owner.id() == object_id))
        .expect("test MemoryObject has a generic owner");
    let TestObjects {
        registry,
        authority,
        owners,
    } = objects;
    let owner = owners[owner_slot].as_ref().unwrap();
    let resolved = crate::handle::resolve_test_internal_owner(
        registry,
        owner,
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    region.authorize_map(authority, resolved, ceiling).unwrap()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test adapter mirrors the explicit production map authority boundary while asserting no finalizer is discarded"
)]
fn test_map<
    const OBJECTS: usize,
    const LEASES: usize,
    const SLOTS: usize,
    P: AddressSpacePublisher,
>(
    region: &mut AddressRegion<SLOTS>,
    objects: &mut TestObjects<OBJECTS, LEASES>,
    publisher: &mut P,
    virtual_start: u64,
    authorization: MapAuthorization,
    object_offset: u64,
    byte_len: u64,
    protection: Protection,
) -> Result<(), AddressSpaceTransactionError<P::Error>> {
    let (authority, registry) = objects.split_mut();
    match region.map(
        authority,
        registry,
        publisher,
        virtual_start,
        authorization,
        object_offset,
        byte_len,
        protection,
    ) {
        Ok(final_releases) => {
            assert!(final_releases.is_empty());
            Ok(())
        }
        Err(failure) => {
            assert!(failure.final_releases.is_empty());
            Err(failure.error)
        }
    }
}

fn test_map_anywhere<
    const OBJECTS: usize,
    const LEASES: usize,
    const SLOTS: usize,
    P: AddressSpacePublisher,
>(
    region: &mut AddressRegion<SLOTS>,
    objects: &mut TestObjects<OBJECTS, LEASES>,
    publisher: &mut P,
    authorization: MapAuthorization,
    object_offset: u64,
    byte_len: u64,
    protection: Protection,
) -> Result<u64, AddressSpaceTransactionError<P::Error>> {
    let (authority, registry) = objects.split_mut();
    match region.map_anywhere(
        authority,
        registry,
        publisher,
        authorization,
        object_offset,
        byte_len,
        protection,
    ) {
        Ok((address, final_releases)) => {
            assert!(final_releases.is_empty());
            Ok(address)
        }
        Err(failure) => {
            assert!(failure.final_releases.is_empty());
            Err(failure.error)
        }
    }
}

fn test_unmap<
    const OBJECTS: usize,
    const LEASES: usize,
    const SLOTS: usize,
    P: AddressSpacePublisher,
>(
    region: &mut AddressRegion<SLOTS>,
    objects: &mut TestObjects<OBJECTS, LEASES>,
    publisher: &mut P,
    start: u64,
    byte_len: u64,
) -> Result<(), AddressSpaceTransactionError<P::Error>> {
    let (authority, registry) = objects.split_mut();
    match region.unmap(authority, registry, publisher, start, byte_len) {
        Ok(final_releases) => {
            assert!(final_releases.is_empty());
            Ok(())
        }
        Err(failure) => {
            assert!(failure.final_releases.is_empty());
            Err(failure.error)
        }
    }
}

fn test_protect<
    const OBJECTS: usize,
    const LEASES: usize,
    const SLOTS: usize,
    P: AddressSpacePublisher,
>(
    region: &mut AddressRegion<SLOTS>,
    objects: &mut TestObjects<OBJECTS, LEASES>,
    publisher: &mut P,
    start: u64,
    byte_len: u64,
    protection: Protection,
) -> Result<(), AddressSpaceTransactionError<P::Error>> {
    let (authority, registry) = objects.split_mut();
    match region.protect(authority, registry, publisher, start, byte_len, protection) {
        Ok(final_releases) => {
            assert!(final_releases.is_empty());
            Ok(())
        }
        Err(failure) => {
            assert!(failure.final_releases.is_empty());
            Err(failure.error)
        }
    }
}

#[allow(
    unsafe_code,
    reason = "test-local registries uniquely own their synthetic address-space roots"
)]
fn space_authority<const SPACES: usize, const REGIONS: usize>()
-> AddressSpaceAuthority<SPACES, REGIONS> {
    // SAFETY: each returned test registry is the only issuer for its
    // synthetic roots and remains live while its regions are created.
    unsafe { AddressSpaceAuthority::new() }
}

fn region<const SLOTS: usize>(start: u64, byte_len: u64) -> AddressRegion<SLOTS> {
    let spaces = Box::leak(Box::new(space_authority::<1, 1>()));
    let space = spaces.create_address_space().unwrap();
    spaces.create_region(space, start, byte_len).unwrap()
}

#[test]
fn rejects_page_zero_and_upper_canonical_regions() {
    assert!(matches!(
        AddressRegion::<2>::validate_region_interval(0, PAGE_SIZE),
        Err(AddressRegionError::PageZero)
    ));
    assert!(matches!(
        AddressRegion::<2>::validate_region_interval(USER_CANONICAL_END - PAGE_SIZE, PAGE_SIZE * 2),
        Err(AddressRegionError::OutsideRegion)
    ));
    assert_eq!(
        MemoryProtection::mapping(Protection::WRITE.bits()),
        Err(MemoryObjectError::UnsupportedProtection)
    );
    assert_eq!(
        MemoryProtection::mapping(Protection::EXECUTE.bits()),
        Err(MemoryObjectError::UnsupportedProtection)
    );
}

#[test]
fn replacement_publishes_model_and_lease_together() {
    let mut authority = TestObjects::<2, 8>::new();
    let object = object(&mut authority, Protection::READ_WRITE_EXECUTE);
    let mut region = region::<4>(PAGE_SIZE, PAGE_SIZE * 8);
    let token = authorization(
        &mut authority,
        object,
        &region,
        Protection::READ_WRITE_EXECUTE,
    );
    let mut publisher = FakePublisher::for_region(&region);
    test_map(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        token,
        0,
        PAGE_SIZE * 2,
        Protection::READ_WRITE,
    )
    .unwrap();
    assert_eq!(publisher.last_before, 0);
    assert_eq!(publisher.last_after, 1);
    assert_eq!(authority.active_lease_count(), 1);
    test_protect(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        PAGE_SIZE * 2,
        Protection::READ_EXECUTE,
    )
    .unwrap();
    assert_eq!(
        region.mappings()[0].unwrap().protection(),
        Protection::READ_EXECUTE
    );
    assert_eq!(authority.active_lease_count(), 1);
}

#[test]
fn mapping_authority_is_captured_across_protect_and_split_replacements() {
    let mut authority = TestObjects::<2, 8>::new();
    let object = object(&mut authority, Protection::READ_WRITE_EXECUTE);
    let mut region = region::<4>(PAGE_SIZE, PAGE_SIZE * 8);
    let read = authorization(&mut authority, object, &region, Protection::READ);
    let mut publisher = FakePublisher::for_region(&region);

    test_map(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        read,
        0,
        PAGE_SIZE,
        Protection::READ,
    )
    .unwrap();
    assert!(matches!(
        test_protect(
            &mut region,
            &mut authority,
            &mut publisher,
            PAGE_SIZE,
            PAGE_SIZE,
            Protection::READ_WRITE,
        ),
        Err(AddressSpaceTransactionError::Model(
            AddressRegionError::Object(MemoryObjectError::ProtectionCeiling)
        ))
    ));
    test_unmap(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        PAGE_SIZE,
    )
    .unwrap();

    let read_write = authorization(&mut authority, object, &region, Protection::READ_WRITE);
    test_map(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        read_write,
        0,
        PAGE_SIZE,
        Protection::READ,
    )
    .unwrap();
    let read_execute = authorization(&mut authority, object, &region, Protection::READ_EXECUTE);
    test_protect(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        PAGE_SIZE,
        Protection::READ_WRITE,
    )
    .unwrap();
    test_unmap(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        PAGE_SIZE,
    )
    .unwrap();

    test_map(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        read_execute,
        0,
        PAGE_SIZE,
        Protection::READ,
    )
    .unwrap();
    test_protect(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        PAGE_SIZE,
        Protection::READ_EXECUTE,
    )
    .unwrap();
}

#[test]
fn object_wide_wx_aliases_and_publisher_failures_are_rejected_without_mutation() {
    let mut authority = TestObjects::<2, 8>::new();
    let object = object(&mut authority, Protection::READ_WRITE_EXECUTE);
    let mut first = region::<2>(PAGE_SIZE, PAGE_SIZE * 4);
    let read_write = authorization(&mut authority, object, &first, Protection::READ_WRITE);
    let mut publisher = FakePublisher::for_region(&first);
    test_map(
        &mut first,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        read_write,
        0,
        PAGE_SIZE,
        Protection::READ_WRITE,
    )
    .unwrap();
    let mut second = region::<2>(PAGE_SIZE * 5, PAGE_SIZE * 2);
    let read_execute = authorization(&mut authority, object, &second, Protection::READ_EXECUTE);
    let mut second_publisher = FakePublisher::for_region(&second);
    assert!(matches!(
        test_map(
            &mut second,
            &mut authority,
            &mut second_publisher,
            PAGE_SIZE * 5,
            read_execute,
            PAGE_SIZE,
            PAGE_SIZE,
            Protection::READ_EXECUTE,
        ),
        Err(AddressSpaceTransactionError::Model(
            AddressRegionError::Object(MemoryObjectError::WritableExecutableAlias)
        ))
    ));
    assert_eq!(authority.active_lease_count(), 1);

    let mut failed = region::<2>(PAGE_SIZE * 8, PAGE_SIZE * 2);
    let read_write_execute = authorization(
        &mut authority,
        object,
        &failed,
        Protection::READ_WRITE_EXECUTE,
    );
    let mut failed_publisher = FakePublisher::for_region(&failed);
    failed_publisher.fail = true;
    assert_eq!(
        test_map(
            &mut failed,
            &mut authority,
            &mut failed_publisher,
            PAGE_SIZE * 8,
            read_write_execute,
            PAGE_SIZE * 2,
            PAGE_SIZE,
            Protection::READ,
        ),
        Err(AddressSpaceTransactionError::Publish(()))
    );
    assert!(failed.mappings().iter().all(Option::is_none));
    assert_eq!(authority.active_lease_count(), 1);

    let retry = authorization(
        &mut authority,
        object,
        &failed,
        Protection::READ_WRITE_EXECUTE,
    );
    failed_publisher.fail = false;
    test_map(
        &mut failed,
        &mut authority,
        &mut failed_publisher,
        PAGE_SIZE * 8,
        retry,
        PAGE_SIZE * 2,
        PAGE_SIZE,
        Protection::READ,
    )
    .unwrap();
    assert_eq!(failed_publisher.calls, 2);
    assert_eq!(failed.mappings().iter().flatten().count(), 1);
    assert_eq!(authority.active_lease_count(), 2);
}

#[test]
fn partial_unmap_needs_split_capacity_and_rolls_back_before_publication() {
    let mut authority = TestObjects::<2, 4>::new();
    let object = object(&mut authority, Protection::READ_WRITE);
    let mut region = region::<1>(PAGE_SIZE, PAGE_SIZE * 4);
    let read_write = authorization(&mut authority, object, &region, Protection::READ_WRITE);
    let mut publisher = FakePublisher::for_region(&region);
    test_map(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE,
        read_write,
        0,
        PAGE_SIZE * 3,
        Protection::READ,
    )
    .unwrap();
    let calls_before = publisher.calls;
    assert_eq!(
        test_unmap(
            &mut region,
            &mut authority,
            &mut publisher,
            PAGE_SIZE * 2,
            PAGE_SIZE
        ),
        Err(AddressSpaceTransactionError::Model(
            AddressRegionError::Capacity
        ))
    );
    assert_eq!(publisher.calls, calls_before);
    assert_eq!(region.mappings()[0].unwrap().byte_len(), PAGE_SIZE * 3);
    assert_eq!(authority.active_lease_count(), 1);
}

#[test]
fn map_anywhere_uses_first_fit_and_reports_fragmented_exhaustion() {
    let mut authority = TestObjects::<2, 8>::new();
    let object = object(&mut authority, Protection::READ_WRITE);
    let mut region = region::<4>(PAGE_SIZE, PAGE_SIZE * 4);
    let mut publisher = FakePublisher::for_region(&region);

    for virtual_start in [PAGE_SIZE, PAGE_SIZE * 3] {
        let read_write = authorization(&mut authority, object, &region, Protection::READ_WRITE);
        test_map(
            &mut region,
            &mut authority,
            &mut publisher,
            virtual_start,
            read_write,
            0,
            PAGE_SIZE,
            Protection::READ,
        )
        .unwrap();
    }
    let anywhere = authorization(&mut authority, object, &region, Protection::READ_WRITE);
    assert_eq!(
        test_map_anywhere(
            &mut region,
            &mut authority,
            &mut publisher,
            anywhere,
            0,
            PAGE_SIZE,
            Protection::READ,
        )
        .unwrap(),
        PAGE_SIZE * 2
    );
    let last_fixed = authorization(&mut authority, object, &region, Protection::READ_WRITE);
    test_map(
        &mut region,
        &mut authority,
        &mut publisher,
        PAGE_SIZE * 4,
        last_fixed,
        0,
        PAGE_SIZE,
        Protection::READ,
    )
    .unwrap();
    let exhausted = authorization(&mut authority, object, &region, Protection::READ_WRITE);
    assert!(matches!(
        test_map_anywhere(
            &mut region,
            &mut authority,
            &mut publisher,
            exhausted,
            0,
            PAGE_SIZE,
            Protection::READ,
        ),
        Err(AddressSpaceTransactionError::Model(
            AddressRegionError::NoSpace
        ))
    ));
}

#[test]
fn space_region_and_lease_identities_reject_swaps_overlaps_and_stale_releases() {
    let mut spaces = space_authority::<2, 3>();
    let first_space = spaces.create_address_space().unwrap();
    let recreated_space = {
        let mut transient = space_authority::<1, 1>();
        transient.create_address_space().unwrap()
    };
    let mut other_registry = space_authority::<1, 1>();
    let other_space = other_registry.create_address_space().unwrap();
    assert_ne!(first_space, recreated_space);
    assert_ne!(first_space, other_space);
    let second_space = spaces.create_address_space().unwrap();
    let mut first: AddressRegion<2> = spaces
        .create_region(first_space, PAGE_SIZE, PAGE_SIZE * 2)
        .unwrap();
    assert!(matches!(
        spaces.create_region::<2>(first_space, PAGE_SIZE * 2, PAGE_SIZE),
        Err(AddressRegionError::Overlap)
    ));
    let second: AddressRegion<2> = spaces
        .create_region(first_space, PAGE_SIZE * 4, PAGE_SIZE * 2)
        .unwrap();

    let mut objects = TestObjects::<1, 4>::new();
    let object = object(&mut objects, Protection::READ_WRITE_EXECUTE);
    let read = authorization(&mut objects, object, &first, Protection::READ);
    let mut swapped_publisher = FakePublisher {
        address_space: second_space,
        calls: 0,
        fail: false,
        last_before: 0,
        last_after: 0,
    };
    assert!(matches!(
        test_map(
            &mut first,
            &mut objects,
            &mut swapped_publisher,
            PAGE_SIZE,
            read,
            0,
            PAGE_SIZE,
            Protection::READ,
        ),
        Err(AddressSpaceTransactionError::Model(
            AddressRegionError::PublisherIdentity
        ))
    ));
    assert_eq!(swapped_publisher.calls, 0);

    let mut publisher = FakePublisher::for_region(&first);
    let read = authorization(&mut objects, object, &first, Protection::READ);
    test_map(
        &mut first,
        &mut objects,
        &mut publisher,
        PAGE_SIZE,
        read,
        0,
        PAGE_SIZE,
        Protection::READ,
    )
    .unwrap();
    let stale_lease = first.mappings()[0].unwrap().lease();
    let error = {
        let (authority, registry) = objects.split_mut();
        authority
            .prepare_replace::<2, 1>(
                registry,
                first_space,
                second.region,
                &[stale_lease],
                &[],
                None,
            )
            .err()
            .expect("foreign-region lease replacement must fail")
    };
    assert_eq!(error.error(), MemoryObjectError::ForeignLease);
    assert!(error.into_final_releases().is_empty());
    test_protect(
        &mut first,
        &mut objects,
        &mut publisher,
        PAGE_SIZE,
        PAGE_SIZE,
        Protection::READ,
    )
    .unwrap();
    let error = {
        let (authority, registry) = objects.split_mut();
        authority
            .prepare_replace::<2, 1>(
                registry,
                first_space,
                first.region,
                &[stale_lease],
                &[],
                None,
            )
            .err()
            .expect("stale lease replacement must fail")
    };
    assert_eq!(error.error(), MemoryObjectError::InvalidLease);
    assert!(error.into_final_releases().is_empty());
}

#[test]
fn object_authorizations_cannot_replay_across_authority_domains() {
    let mut spaces = space_authority::<1, 1>();
    let space = spaces.create_address_space().unwrap();
    let mut region: AddressRegion<1> = spaces.create_region(space, PAGE_SIZE, PAGE_SIZE).unwrap();

    let mut registry = ObjectRegistry::<2>::new();
    let first_creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut first = MemoryObjectAuthority::<1, 1>::new();
    let first_backing = crate::memory::frame_roles::synthetic_allocator_backing(0x20_000, 1);
    let first_object = first
        .grant_backing(
            &first_creation,
            first_backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            Protection::READ,
        )
        .unwrap();
    let first_owner = registry.creation_into_internal(first_creation).unwrap();
    assert_eq!(first_object.object_id(), Some(first_owner.id()));
    let resolved = crate::handle::resolve_test_internal_owner(
        &mut registry,
        &first_owner,
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let authorization = region
        .authorize_map(&first, resolved, Protection::READ)
        .unwrap();

    let second_creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
    let mut second = MemoryObjectAuthority::<1, 1>::new();
    let second_backing = crate::memory::frame_roles::synthetic_allocator_backing(0x40_000, 1);
    let second_object = second
        .grant_backing(
            &second_creation,
            second_backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            Protection::READ,
        )
        .unwrap();
    let _second_owner = registry.creation_into_internal(second_creation).unwrap();
    assert_ne!(first_object, second_object);

    let mut publisher = FakePublisher::for_region(&region);
    let failure = region
        .map(
            &mut second,
            &mut registry,
            &mut publisher,
            PAGE_SIZE,
            authorization,
            0,
            PAGE_SIZE,
            Protection::READ,
        )
        .unwrap_err();
    assert!(matches!(
        failure.error(),
        AddressSpaceTransactionError::Model(AddressRegionError::Object(
            MemoryObjectError::InvalidObjectKey
        ))
    ));
    assert!(failure.into_final_releases().is_empty());
    assert_eq!(publisher.calls, 0);
    assert_eq!(second.active_lease_count(), 0);
}

#[test]
#[allow(
    unsafe_code,
    reason = "test-local AddressSpaceAuthority uniquely owns its synthetic address-space identities"
)]
fn root_region_handle_close_preserves_address_space_until_process_exit() {
    type Tasks = TaskAuthority<2, 2, 2, 2>;
    let mut registry = ObjectRegistry::<8>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let mut spaces = unsafe { AddressSpaceAuthority::<2, 2>::new() };
    let mut regions = AddressRegionObjectAuthority::<2, 4>::new();

    let (region_key, region_handle): (AddressRegionObjectKey, _) = regions
        .create_root_region(
            &mut registry,
            &mut tasks,
            &mut spaces,
            process,
            &process_handle,
        )
        .unwrap();
    assert_eq!(
        tasks.root_region(process).unwrap(),
        Some(region_key.object_id())
    );
    assert_eq!(
        regions
            .region(region_key)
            .unwrap()
            .mappings()
            .iter()
            .flatten()
            .count(),
        0
    );
    assert!(registry.release_handle(region_handle).unwrap().is_none());
    assert!(matches!(
        regions.create_root_region(
            &mut registry,
            &mut tasks,
            &mut spaces,
            process,
            &process_handle
        ),
        Err(AddressRegionObjectError::Task(TaskError::BadState))
    ));

    let effects = tasks
        .terminate_process_authorized(&mut registry, process, 0x77)
        .unwrap();
    assert_eq!(effects.drained.final_release_count(), 0);
    let (process_pin, thread_pins) = effects.pins.into_parts();
    assert!(thread_pins.into_iter().flatten().next().is_none());
    assert!(
        registry
            .release_internal(process_pin.unwrap())
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        regions.region_mut_for_live_process(&tasks, region_key),
        Err(AddressRegionObjectError::Task(TaskError::BadState))
    ));

    let runtime_pin = regions.retire_exited_root(&mut tasks, process).unwrap();
    let region_final = registry.release_internal(runtime_pin).unwrap().unwrap();
    let finalization = regions
        .take_finalization(&mut spaces, region_final)
        .unwrap();
    assert!(complete_address_region_finalization(&mut registry, finalization).is_none());
    assert_eq!(tasks.root_region(process), Ok(None));

    let process_final = registry.release_handle(process_handle).unwrap().unwrap();
    let task_finalization = tasks.take_finalization(process_final).unwrap();
    assert!(complete_task_finalization(&mut registry, task_finalization).is_none());
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    let root_finalization = tasks.take_finalization(root_final).unwrap();
    assert!(complete_task_finalization(&mut registry, root_finalization).is_none());
}

#[test]
#[allow(
    unsafe_code,
    reason = "test-local AddressSpaceAuthority uniquely owns its synthetic address-space identities"
)]
fn address_space_identity_release_refuses_live_region_records() {
    let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
    let address_space = spaces.create_address_space().unwrap();
    let region = spaces
        .create_region::<1>(address_space, PAGE_SIZE, PAGE_SIZE)
        .unwrap();
    assert_eq!(
        spaces.release_address_space(address_space),
        Err(AddressRegionError::LiveRegions)
    );
    spaces.release_region(&region).unwrap();
    spaces.release_address_space(address_space).unwrap();
    assert_eq!(
        spaces.release_address_space(address_space),
        Err(AddressRegionError::OutsideRegion)
    );
}
