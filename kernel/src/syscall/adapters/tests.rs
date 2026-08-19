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

fn test_stack_bounds<const N: usize>() -> [crate::memory::kernel_stack::KernelStackBounds; N] {
    core::array::from_fn(|index| {
        let stride = 0x11_000_u64;
        let guard = 0xffff_9100_0000_0000 + u64::try_from(index).unwrap() * stride;
        crate::memory::kernel_stack::KernelStackBounds::new(guard, guard + 0x1000, guard + stride)
            .unwrap()
    })
}

fn test_start(seed: u64) -> ThreadStartState {
    ThreadStartState::from_validated_user_state(
        0x0000_0000_4000_0000 + seed * 0x1000,
        0x0000_0000_5000_0000 + seed * 0x1000,
        seed,
        seed + 1,
    )
}

fn finish_task_cleanup<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut Tasks,
    cleanup: CleanupQueue<OBJECTS>,
) {
    for release in cleanup.into_releases().into_iter().flatten() {
        let mut pending = Some(release);
        while let Some(release) = pending.take() {
            let finalization = tasks.take_finalization(release).unwrap();
            pending = crate::task::complete_task_finalization(registry, finalization);
        }
    }
}

#[test]
fn invalid_task_creation_rights_do_not_burn_object_generations() {
    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let mut user = FakeUserMemory::new();
    let before = registry.test_slot_generations();
    let mut cleanup = CleanupQueue::<16>::new();

    assert_eq!(
        thread_create(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            DwRights(0),
            DwUserAddress(BASE + 0x180),
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(registry.test_slot_generations(), before);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 1);
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn self_thread_termination_with_live_sibling_never_returns_to_reclaimed_context() {
    use deepwyrm_abi::{DW_OBJECT_TYPE_PROCESS, DW_RIGHT_MODIFY, DW_TERMINATION_AUTHORIZED};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<2>::new(test_stack_bounds::<2>()).unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    let (sibling, sibling_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    let current_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(current_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let sibling_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(sibling_ref, DW_RIGHT_MODIFY)
        .unwrap();

    execution
        .start_thread(&mut tasks, current, test_start(1))
        .unwrap();
    execution
        .start_thread(&mut tasks, sibling, test_start(2))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));

    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            current_handle,
            DW_TERMINATION_AUTHORIZED,
            0x51,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::TerminateCurrent)
    );
    assert_eq!(execution.scheduler_state(current), None);
    assert_eq!(
        execution.scheduler_state(sibling),
        Some(SchedulerThreadState::Running)
    );
    assert_ne!(
        tasks.process_info(process).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_EXITED
    );

    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            sibling,
            sibling_handle,
            DW_TERMINATION_AUTHORIZED,
            0x52,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::TerminateCurrent)
    );
    assert_eq!(execution.scheduler_state(sibling), None);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 0);
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

struct ProcessBoundMappings {
    process: ProcessKey,
    executable: bool,
    writable_stack: bool,
}

impl crate::arch::x86_64::syscall::UserReturnMappingValidation for ProcessBoundMappings {
    fn executable_at(&mut self, _instruction_pointer: u64) -> bool {
        self.executable
    }

    fn writable_byte_below(&mut self, _stack_pointer: u64) -> bool {
        self.writable_stack
    }
}

impl crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation for ProcessBoundMappings {
    fn process_key(&self) -> ProcessKey {
        self.process
    }
}

fn write_thread_start_args(
    memory: &mut FakeUserMemory,
    address: u64,
    thread: DwHandle,
    entry: u64,
    stack_pointer: u64,
) {
    let offset = FakeUserMemory::offset(address, THREAD_START_BYTES);
    let bytes = &mut memory.bytes[offset..offset + THREAD_START_BYTES];
    bytes.fill(0);
    bytes[0..4].copy_from_slice(&(THREAD_START_BYTES as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&thread.0.to_le_bytes());
    bytes[16..24].copy_from_slice(&entry.to_le_bytes());
    bytes[24..32].copy_from_slice(&stack_pointer.to_le_bytes());
}

#[test]
fn thread_start_validates_the_target_process_address_space() {
    use deepwyrm_abi::DW_RIGHT_EXECUTE;

    let mut registry = ObjectRegistry::<24>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (caller, caller_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let (target, target_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let target_owner = registry.retain_internal_from_handle(&target_ref).unwrap();
    let (thread, thread_ref) = tasks.create_thread(&mut registry, &target_owner).unwrap();
    assert!(registry.release_internal(target_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    assert!(registry.release_handle(target_ref).unwrap().is_none());

    let caller_handle = tasks
        .process_handles_mut(caller)
        .unwrap()
        .install(caller_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let thread_handle = tasks
        .process_handles_mut(caller)
        .unwrap()
        .install(thread_ref, DW_RIGHT_EXECUTE)
        .unwrap();
    let mut user = FakeUserMemory::new();
    write_thread_start_args(
        &mut user,
        BASE + 0x280,
        thread_handle,
        0x4000_1000,
        0x5000_2000,
    );
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut cleanup = CleanupQueue::<24>::new();

    let mut wrong = ProcessBoundMappings {
        process: caller,
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        thread_start(
            &mut user,
            &mut wrong,
            &mut registry,
            &mut tasks,
            &execution,
            caller,
            DwUserAddress(BASE + 0x280),
            THREAD_START_BYTES as u64,
            &mut cleanup,
        ),
        DW_STATUS_BAD_STATE
    );
    assert_eq!(execution.scheduler_state(thread), None);
    assert_eq!(
        tasks.thread_info(thread).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );

    let mut correct = ProcessBoundMappings {
        process: target,
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        thread_start(
            &mut user,
            &mut correct,
            &mut registry,
            &mut tasks,
            &execution,
            caller,
            DwUserAddress(BASE + 0x280),
            THREAD_START_BYTES as u64,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(
        thread_start(
            &mut user,
            &mut correct,
            &mut registry,
            &mut tasks,
            &execution,
            caller,
            DwUserAddress(BASE + 0x280),
            THREAD_START_BYTES as u64,
            &mut cleanup,
        ),
        DW_STATUS_BAD_STATE
    );
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(execution.schedule_next().unwrap().current, Some(thread));
    let pins = tasks.exit_thread(thread, 0).unwrap();
    let retired = execution.retire_exit_pins(pins);
    let (process_pin, thread_pins) = retired.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        cleanup.push_optional(registry.release_internal(pin).unwrap());
    }
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            caller,
            thread_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            caller,
            caller_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
    assert_eq!(tasks.process_handle_count(caller).unwrap(), 0);
    assert_eq!(tasks.thread_process(thread), Err(TaskError::InvalidTask));
}

#[test]
fn task_create_output_preflight_precedes_generation_and_handle_mutation() {
    let mut registry = ObjectRegistry::<16>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let root_handle_owner = registry.retain_internal(&root_owner).unwrap();
    let root_handle_ref = registry.internal_into_handle(root_handle_owner).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let root_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(root_handle_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let process_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(process_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let before_generations = registry.test_slot_generations();
    let before_handles = tasks.process_handle_count(process).unwrap();
    let mut user = FakeUserMemory::new();
    user.deny_write = true;
    let mut cleanup = CleanupQueue::<16>::new();

    assert_eq!(
        task_group_create(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            root_handle,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(
        thread_create(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x180),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(registry.test_slot_generations(), before_generations);
    assert_eq!(tasks.process_handle_count(process).unwrap(), before_handles);

    for handle in [root_handle, process_handle] {
        assert_eq!(
            handle_close(&mut registry, &mut tasks, process, handle, &mut cleanup),
            DW_STATUS_SUCCESS
        );
    }
    let effects = tasks
        .terminate_process_authorized(&mut registry, process, 0x40)
        .unwrap();
    assert_eq!(effects.drained.final_release_count(), 0);
    let (process_pin, thread_pins, resources) = effects.pins.into_parts();
    assert!(thread_pins.into_iter().flatten().next().is_none());
    assert!(resources.into_iter().flatten().next().is_none());
    cleanup.push_optional(registry.release_internal(process_pin.unwrap()).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    let mut root_cleanup = CleanupQueue::<16>::new();
    root_cleanup.push(root_final);
    finish_task_cleanup(&mut registry, &mut tasks, root_cleanup);
}

#[test]
fn termination_rejects_reason_type_and_rights_before_target_mutation() {
    use deepwyrm_abi::{DW_OBJECT_TYPE_PROCESS, DW_TERMINATION_AUTHORIZED};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    let (target, target_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    let current_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(current_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let target_full = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(
            target_ref,
            DwRights(DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0),
        )
        .unwrap();
    let target_inspect = tasks
        .process_handles_mut(process)
        .unwrap()
        .duplicate(&mut registry, target_full, DW_RIGHT_INSPECT)
        .unwrap();

    execution
        .start_thread(&mut tasks, current, test_start(0x41))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));

    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            target_full,
            deepwyrm_abi::DwTerminationReason(u32::MAX),
            1,
            &mut cleanup,
        ),
        (DW_STATUS_INVALID_ARGUMENT, SyscallControl::ReturnToCaller)
    );
    assert_eq!(
        tasks.thread_info(target).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );
    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            process_handle,
            DW_TERMINATION_AUTHORIZED,
            2,
            &mut cleanup,
        ),
        (DW_STATUS_WRONG_OBJECT_TYPE, SyscallControl::ReturnToCaller)
    );
    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            target_inspect,
            DW_TERMINATION_AUTHORIZED,
            3,
            &mut cleanup,
        ),
        (DW_STATUS_ACCESS_DENIED, SyscallControl::ReturnToCaller)
    );
    assert_eq!(
        tasks.thread_info(target).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );
    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            target_full,
            DW_TERMINATION_AUTHORIZED,
            0x44,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::ReturnToCaller)
    );
    let target_info = tasks.thread_info(target).unwrap();
    assert_eq!(target_info.state, deepwyrm_abi::DW_TASK_STATE_EXITED);
    assert_eq!(target_info.reason, DW_TERMINATION_AUTHORIZED);
    assert_eq!(target_info.detail, 0x44);
    assert_eq!(
        execution.scheduler_state(current),
        Some(SchedulerThreadState::Running)
    );

    for handle in [target_full, target_inspect] {
        assert_eq!(
            handle_close(&mut registry, &mut tasks, process, handle, &mut cleanup),
            DW_STATUS_SUCCESS
        );
    }
    assert_eq!(
        thread_exit(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            0x55,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::TerminateCurrent)
    );
    assert_eq!(execution.scheduler_state(current), None);
    let _ = current_handle;
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}
