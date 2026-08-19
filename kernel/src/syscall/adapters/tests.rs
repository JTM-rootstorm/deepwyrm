use super::*;
use crate::memory::user_range::UserPageChunk;
use crate::memory::usercopy::PinnedUserPages;
use crate::object::ObjectRegistry;
use crate::task::TaskAuthority;
use deepwyrm_abi::{DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY};

const BASE: u64 = 0x4000;
const BYTES: usize = 4096;

struct FakeUserMemory {
    bytes: [u8; BYTES],
    deny_write: bool,
}

struct FakePinned<'a> {
    memory: &'a mut FakeUserMemory,
}

impl FakeUserMemory {
    fn new() -> Self {
        Self {
            bytes: [0; BYTES],
            deny_write: false,
        }
    }

    fn offset(address: u64, len: usize) -> usize {
        let offset = usize::try_from(address - BASE).unwrap();
        assert!(offset + len <= BYTES);
        offset
    }
}

impl UserPageAccess for FakeUserMemory {
    type Error = ();
    type Pinned<'a>
        = FakePinned<'a>
    where
        Self: 'a;

    fn pin(&mut self, _range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
        Ok(FakePinned { memory: self })
    }
}

impl PinnedUserPages for FakePinned<'_> {
    type Error = ();

    fn preflight(&mut self, chunk: UserPageChunk) -> Result<(), Self::Error> {
        if self.memory.deny_write && chunk.access().includes(UserAccess::WRITE) {
            return Err(());
        }
        let _ = FakeUserMemory::offset(chunk.address(), usize::try_from(chunk.byte_len()).unwrap());
        Ok(())
    }

    fn read_exact(&mut self, range: UserRange, destination: &mut [u8]) {
        let offset = FakeUserMemory::offset(range.start(), destination.len());
        destination.copy_from_slice(&self.memory.bytes[offset..offset + destination.len()]);
    }

    fn write_exact(&mut self, range: UserRange, source: &[u8]) {
        let offset = FakeUserMemory::offset(range.start(), source.len());
        self.memory.bytes[offset..offset + source.len()].copy_from_slice(source);
    }
}

fn u64_at(memory: &FakeUserMemory, address: u64) -> u64 {
    let offset = FakeUserMemory::offset(address, 8);
    u64::from_le_bytes(memory.bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn abi_get_info_reports_size_and_writes_only_after_pointer_validation() {
    let mut user = FakeUserMemory::new();
    assert_eq!(
        abi_get_info(
            &mut user,
            DwUserAddress(BASE + 0x100),
            8,
            DwUserAddress(BASE + 0x20),
        ),
        DW_STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(u64_at(&user, BASE + 0x20), u64::from(DW_ABI_INFO_V1_SIZE));
    assert_eq!(&user.bytes[0x100..0x140], &[0; 64]);

    user.deny_write = true;
    let before = user.bytes;
    assert_eq!(
        abi_get_info(
            &mut user,
            DwUserAddress(BASE + 0x100),
            64,
            DwUserAddress(BASE + 0x20),
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(user.bytes, before);
}

type Tasks = TaskAuthority<2, 2, 2, 8>;

fn process_fixture() -> (ObjectRegistry<16>, Tasks, ProcessKey, DwHandle) {
    let mut registry = ObjectRegistry::<16>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    let rights = DwRights(DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0);
    let handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(process_ref, rights)
        .unwrap();
    (registry, tasks, process, handle)
}

#[test]
fn duplicate_does_not_mutate_handle_table_until_output_is_preflighted() {
    let (mut registry, mut tasks, process, source) = process_fixture();
    let mut user = FakeUserMemory::new();
    user.deny_write = true;
    let before = tasks.process_handle_count(process).unwrap();
    assert_eq!(
        handle_duplicate(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            source,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x80),
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(tasks.process_handle_count(process).unwrap(), before);
    user.deny_write = false;
    assert_eq!(
        handle_duplicate(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            source,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x80),
        ),
        DW_STATUS_SUCCESS
    );
    let duplicate = DwHandle(u64_at(&user, BASE + 0x80));
    assert_ne!(duplicate.0, 0);
    assert_eq!(tasks.process_handle_count(process).unwrap(), before + 1);

    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        handle_close(&mut registry, &mut tasks, process, duplicate, &mut cleanup),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(&mut registry, &mut tasks, process, source, &mut cleanup),
        DW_STATUS_SUCCESS
    );
    assert_eq!(tasks.process_handle_count(process).unwrap(), 0);
}

struct TestBacking {
    roles: crate::memory::frame_roles::FrameRoleManager<1, 8>,
    allocations: usize,
}

impl TestBacking {
    fn new() -> Self {
        Self {
            roles: crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x20_000, 8),
            allocations: 0,
        }
    }
}

impl MemoryObjectBackingAccess for TestBacking {
    #[allow(
        unsafe_code,
        reason = "the host fixture models the production post-zeroing typed role transition"
    )]
    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<crate::memory::frame_roles::ObjectBackingGrant, DwStatus> {
        self.allocations += 1;
        let allocation = self
            .roles
            .allocate(page_count)
            .map_err(|_| deepwyrm_abi::DW_STATUS_NO_MEMORY)?;
        let zeroed = unsafe { self.roles.assume_zeroed(allocation) }.unwrap();
        self.roles
            .assign_object_backing(zeroed)
            .map_err(|_| deepwyrm_abi::DW_STATUS_NO_MEMORY)
    }

    fn rollback_object_backing(&mut self, backing: crate::memory::frame_roles::ObjectBackingGrant) {
        self.roles.cancel_object_backing(backing).unwrap();
    }
}

#[test]
fn memory_object_create_preflights_output_before_backing_allocation() {
    use deepwyrm_abi::{DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_WRITE};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let mut user = FakeUserMemory::new();
    let mut backing = TestBacking::new();
    let mut memory = MemoryObjectAuthority::<4, 4>::new();
    let rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0);
    let mut cleanup = CleanupQueue::<16>::new();

    user.deny_write = true;
    assert_eq!(
        memory_object_create(
            &mut user,
            &mut backing,
            &mut registry,
            &mut memory,
            &mut tasks,
            process,
            4096,
            0,
            rights,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(backing.allocations, 0);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 1);
    user.deny_write = false;
    assert_eq!(
        memory_object_create(
            &mut user,
            &mut backing,
            &mut registry,
            &mut memory,
            &mut tasks,
            process,
            4096,
            0,
            rights,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let memory_handle = DwHandle(u64_at(&user, BASE + 0x100));
    assert_ne!(memory_handle.0, 0);
    assert_eq!(backing.allocations, 1);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 2);

    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            memory_handle,
            &mut cleanup
        ),
        DW_STATUS_SUCCESS
    );
    for release in cleanup.into_releases().into_iter().flatten() {
        let finalization = memory.take_finalization(release).unwrap();
        crate::memory::object::complete_memory_finalization(
            &mut registry,
            &mut backing.roles,
            finalization,
        );
    }
    let mut final_cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut final_cleanup,
        ),
        DW_STATUS_SUCCESS
    );
}
struct FakePublisher {
    address_space: crate::memory::address_region::AddressSpaceKey,
    region: crate::memory::address_region::RegionKey,
    replacements: usize,
}

impl crate::memory::address_region::publisher_seal::Sealed for FakePublisher {}

#[allow(
    unsafe_code,
    reason = "the host fixture atomically accepts only its exact authority-issued address-space/region pair"
)]
unsafe impl crate::memory::address_region::AddressSpacePublisher for FakePublisher {
    type Error = ();

    fn address_space_key(&self) -> crate::memory::address_region::AddressSpaceKey {
        self.address_space
    }

    fn publish_replace(
        &mut self,
        address_space: crate::memory::address_region::AddressSpaceKey,
        region: crate::memory::address_region::RegionKey,
        _before: &[crate::memory::address_region::Mapping],
        _after: &[crate::memory::address_region::Mapping],
    ) -> Result<(), Self::Error> {
        assert_eq!(address_space, self.address_space);
        assert_eq!(region, self.region);
        self.replacements += 1;
        Ok(())
    }
}
#[allow(
    unsafe_code,
    reason = "test-local AddressSpaceAuthority uniquely owns its synthetic E5 address-space identities"
)]
fn region_fixture() -> (
    ObjectRegistry<24>,
    Tasks,
    ProcessKey,
    DwHandle,
    crate::memory::address_region::AddressSpaceAuthority<2, 2>,
    crate::memory::address_region::AddressRegionObjectAuthority<2, 8>,
    crate::memory::address_region::AddressRegionObjectKey,
    DwHandle,
) {
    use deepwyrm_abi::{DW_RIGHT_MAP, DW_RIGHT_MODIFY};

    let mut registry = ObjectRegistry::<24>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    let mut spaces = unsafe { crate::memory::address_region::AddressSpaceAuthority::<2, 2>::new() };
    let mut regions = crate::memory::address_region::AddressRegionObjectAuthority::<2, 8>::new();
    let (region_key, region_ref) = regions
        .create_root_region(
            &mut registry,
            &mut tasks,
            &mut spaces,
            process,
            &process_ref,
        )
        .unwrap();
    let process_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(
            process_ref,
            DwRights(DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0),
        )
        .unwrap();
    let region_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(region_ref, DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0))
        .unwrap();
    (
        registry,
        tasks,
        process,
        process_handle,
        spaces,
        regions,
        region_key,
        region_handle,
    )
}

fn write_map_args(memory: &mut FakeUserMemory, address: u64, protections: u32) {
    let offset = FakeUserMemory::offset(address, super::super::abi_bytes::ADDRESS_REGION_MAP_BYTES);
    let bytes =
        &mut memory.bytes[offset..offset + super::super::abi_bytes::ADDRESS_REGION_MAP_BYTES];
    bytes.fill(0);
    bytes[0..4].copy_from_slice(&deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE.to_le_bytes());
    bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&4096_u64.to_le_bytes());
    bytes[32..36].copy_from_slice(&protections.to_le_bytes());
}
#[test]
fn address_region_map_preflights_copyout_and_preserves_mapping_leases() {
    use deepwyrm_abi::{
        DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_MAP, DW_RIGHT_READ,
        DW_RIGHT_WRITE,
    };

    let (
        mut registry,
        mut tasks,
        process,
        process_handle,
        _spaces,
        mut regions,
        region_key,
        region_handle,
    ) = region_fixture();
    let mut user = FakeUserMemory::new();
    let mut backing = TestBacking::new();
    let mut memory = MemoryObjectAuthority::<4, 8>::new();
    let mut cleanup = CleanupQueue::<24>::new();
    let memory_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0);
    assert_eq!(
        memory_object_create(
            &mut user,
            &mut backing,
            &mut registry,
            &mut memory,
            &mut tasks,
            process,
            4096,
            0,
            memory_rights,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let memory_handle = DwHandle(u64_at(&user, BASE + 0x100));
    write_map_args(
        &mut user,
        BASE + 0x200,
        DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0,
    );
    let region_model = regions.region(region_key).unwrap();
    let mut publisher = FakePublisher {
        address_space: region_model.address_space_key(),
        region: region_model.region_key(),
        replacements: 0,
    };

    user.deny_write = true;
    assert_eq!(
        address_region_map(
            &mut user,
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            memory_handle,
            DwUserAddress(BASE + 0x200),
            u64::from(deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE),
            DwUserAddress(BASE + 0x300),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(publisher.replacements, 0);
    assert!(
        regions
            .region(region_key)
            .unwrap()
            .mappings()
            .iter()
            .all(Option::is_none)
    );
    user.deny_write = false;
    assert_eq!(
        address_region_map(
            &mut user,
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            memory_handle,
            DwUserAddress(BASE + 0x200),
            u64::from(deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE),
            DwUserAddress(BASE + 0x300),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let mapped = u64_at(&user, BASE + 0x300);
    assert_eq!(mapped, 4096);
    assert_eq!(publisher.replacements, 1);
    assert_eq!(
        regions
            .region(region_key)
            .unwrap()
            .mappings()
            .iter()
            .flatten()
            .count(),
        1
    );

    assert_eq!(
        address_region_protect(
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            DwUserAddress(mapped),
            4096,
            DW_MEMORY_PROTECTION_READ.0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(publisher.replacements, 2);
    assert_eq!(
        address_region_unmap(
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            DwUserAddress(mapped),
            4096,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(publisher.replacements, 3);
    assert!(
        regions
            .region(region_key)
            .unwrap()
            .mappings()
            .iter()
            .all(Option::is_none)
    );

    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            memory_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    for release in cleanup.into_releases().into_iter().flatten() {
        let finalization = memory.take_finalization(release).unwrap();
        crate::memory::object::complete_memory_finalization(
            &mut registry,
            &mut backing.roles,
            finalization,
        );
    }
    let mut final_cleanup = CleanupQueue::<24>::new();
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            region_handle,
            &mut final_cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut final_cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(tasks.process_handle_count(process).unwrap(), 0);
}
