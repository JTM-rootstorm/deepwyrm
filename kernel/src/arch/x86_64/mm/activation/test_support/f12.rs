//! DW0-F12 target-only composed IPC/blocking userspace runtime.

use super::*;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::handle::AcceptedObjectTypes;
use crate::ipc::ChannelAuthority;
use crate::memory::address_region::{
    AddressRegionObjectAuthority, AddressRegionObjectKey, AddressSpaceAuthority,
};
use crate::memory::object::{
    MemoryObjectAuthority, MemoryObjectKey, MemoryObjectKind, MemoryProtection,
};
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::object::{HandleRef, InternalRef, ObjectRegistry};
use crate::syscall::native::{
    NativeSyscallFrameRuntime, NativeSyscallHandler, NativeSyscallRequest, NativeSyscallResult,
    SyscallControl,
};
use crate::syscall::{CleanupQueue, FServiceRoute, FServiceState, NativeWaitControl};
use crate::task::{ExecutionDomain, ProcessKey, SchedulerThreadState, TaskAuthority, ThreadKey};
use crate::time::TimerAuthority;
use crate::wait::{EventAuthority, WaitRegistry};
use deepwyrm_abi::{
    DW_CHANNEL_MAX_PAYLOAD, DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_OBJECT_TYPE_ADDRESS_REGION,
    DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_PROCESS, DW_RIGHT_MODIFY, DW_RIGHT_READ,
    DW_STATUS_BAD_HANDLE, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS, DW_TASK_STATE_CREATED,
    DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED, DW_TERMINATION_NORMAL_EXIT, DwUserAddress,
};

const REGISTRY_OBJECTS: usize = 24;
const MEMORY_OBJECTS: usize = 3;
const MEMORY_LEASES: usize = 3;
const TASK_GROUPS: usize = 1;
const PROCESSES: usize = 2;
const THREADS: usize = 2;
const HANDLES: usize = 16;
const SPACES: usize = 2;
const REGIONS: usize = 2;
const REGION_OBJECTS: usize = 2;
const REGION_SLOTS: usize = 3;
const CHANNEL_PAIRS: usize = 2;
const CHANNEL_DEPTH: usize = 2;
const EVENTS: usize = 1;
const TIMERS: usize = 1;
const WAITERS: usize = 4;
const EXECUTION_THREADS: usize = 2;
const F12_DETAIL_BASE: u32 = 0xf120_0000;
const SERVICE_ROLE: u64 = 0;
const PRODUCER_ROLE: u64 = 1;

type F12Registry = ObjectRegistry<REGISTRY_OBJECTS>;
type F12Memory = MemoryObjectAuthority<MEMORY_OBJECTS, MEMORY_LEASES>;
type F12Tasks = TaskAuthority<TASK_GROUPS, PROCESSES, THREADS, HANDLES>;
type F12Spaces = AddressSpaceAuthority<SPACES, REGIONS>;
type F12Regions = AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>;
type F12Channels = ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>;

const fn parse_decimal_u64(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(
        !bytes.is_empty(),
        "F12 address environment must not be empty"
    );
    let mut result = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(
            byte >= b'0' && byte <= b'9',
            "F12 address environment must be decimal"
        );
        let digit = (byte - b'0') as u64;
        assert!(
            result <= (u64::MAX - digit) / 10,
            "F12 address environment overflow"
        );
        result = result * 10 + digit;
        index += 1;
    }
    result
}

const F12_USER_ENTRY: u64 = parse_decimal_u64(env!("DEEPWYRM_F12_USER_ENTRY"));
const F12_USER_DATA: u64 = parse_decimal_u64(env!("DEEPWYRM_F12_USER_DATA"));
const F12_USER_STACK_BOTTOM: u64 = parse_decimal_u64(env!("DEEPWYRM_F12_USER_STACK_BOTTOM"));
const F12_USER_STACK_TOP: u64 = parse_decimal_u64(env!("DEEPWYRM_F12_USER_STACK_TOP"));
const F12_USER_SERVICE_STACK_TOP: u64 =
    parse_decimal_u64(env!("DEEPWYRM_F12_USER_SERVICE_STACK_TOP"));
const F12_USER_PRODUCER_STACK_TOP: u64 =
    parse_decimal_u64(env!("DEEPWYRM_F12_USER_PRODUCER_STACK_TOP"));

fn fail(detail: u32) -> ! {
    crate::test_support::complete_fail(F12_DETAIL_BASE | detail)
}

struct F12DeadlineWakeTarget {
    execution: ExecutionDomain<EXECUTION_THREADS>,
}

impl crate::time::DeadlineWakeTarget for F12DeadlineWakeTarget {
    fn wake_deadline(&self, key: crate::task::BlockWakeKey) {
        crate::wait::engine::claim_timeout_and_wake(&self.execution, key)
            .unwrap_or_else(|_| fail(0x01));
    }
}

struct F12ExecutionStorage(UnsafeCell<MaybeUninit<F12DeadlineWakeTarget>>);

impl F12ExecutionStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "one-shot F12 setup publishes stationary scheduler state before finite deadlines or CPL3 execution"
)]
unsafe impl Sync for F12ExecutionStorage {}

static F12_EXECUTION_STATE: AtomicU8 = AtomicU8::new(0);
static F12_EXECUTION_STORAGE: F12ExecutionStorage = F12ExecutionStorage::new();

struct F12ChannelStaging(UnsafeCell<[u8; DW_CHANNEL_MAX_PAYLOAD as usize]>);

#[allow(
    unsafe_code,
    reason = "the selector-13 boot lends this one-shot buffer only to its serialized syscall dispatcher"
)]
unsafe impl Sync for F12ChannelStaging {}

static F12_CHANNEL_STAGING_STATE: AtomicU8 = AtomicU8::new(0);
static F12_CHANNEL_STAGING: F12ChannelStaging =
    F12ChannelStaging(UnsafeCell::new([0; DW_CHANNEL_MAX_PAYLOAD as usize]));

#[allow(
    unsafe_code,
    reason = "one selector-13 runtime exclusively claims the stationary Channel staging buffer before CPL3"
)]
fn take_channel_staging() -> &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize] {
    F12_CHANNEL_STAGING_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|_| fail(0x05));
    unsafe { &mut *F12_CHANNEL_STAGING.0.get() }
}

#[allow(
    unsafe_code,
    reason = "the selector-13 boot owns one-shot publication of a stationary ExecutionDomain consumed by the timer IRQ and syscall runtime"
)]
fn publish_execution(
    bounds: [crate::memory::kernel_stack::KernelStackBounds; EXECUTION_THREADS],
) -> &'static ExecutionDomain<EXECUTION_THREADS> {
    F12_EXECUTION_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|_| fail(0x02));
    let execution = ExecutionDomain::new(bounds).unwrap_or_else(|_| fail(0x03));
    unsafe {
        (*F12_EXECUTION_STORAGE.0.get()).write(F12DeadlineWakeTarget { execution });
    }
    F12_EXECUTION_STATE.store(2, Ordering::Release);
    let target = unsafe { &*(*F12_EXECUTION_STORAGE.0.get()).as_ptr() };
    crate::time::bind_deadline_wake_target(target).unwrap_or_else(|_| fail(0x04));
    &target.execution
}

fn require_clean_mapping(
    result: Result<
        crate::memory::object::MappingFinalReleases<REGISTRY_OBJECTS>,
        crate::memory::address_region::AddressSpaceTransactionFailure<
            crate::arch::x86_64::mm::journal::X86AddressSpacePublishError<LiveActiveTargetError>,
            REGISTRY_OBJECTS,
        >,
    >,
    detail: u32,
) {
    match result {
        Ok(releases) if releases.is_empty() => {}
        Ok(_) => fail(detail + 7),
        Err(failure) => {
            let (error, _releases) = failure.into_parts();
            match error {
                crate::memory::address_region::AddressSpaceTransactionError::Model(_) => {
                    fail(detail)
                }
                crate::memory::address_region::AddressSpaceTransactionError::Publish(error) => {
                    use crate::arch::x86_64::mm::journal::X86AddressSpacePublishError;
                    match error {
                        X86AddressSpacePublishError::Identity => fail(detail + 1),
                        X86AddressSpacePublishError::InvalidMapping => fail(detail + 2),
                        X86AddressSpacePublishError::Capacity => fail(detail + 3),
                        X86AddressSpacePublishError::FrameRole(_) => fail(detail + 4),
                        X86AddressSpacePublishError::Map(_) => fail(detail + 5),
                        X86AddressSpacePublishError::Journal(_) => fail(detail + 6),
                    }
                }
            }
        }
    }
}

fn create_page_owner<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    registry: &mut F12Registry,
    memory: &mut F12Memory,
    detail: u32,
) -> (InternalRef, MemoryObjectKey) {
    let (zeroed, _) = setup.allocate_zeroed().unwrap_or_else(|_| fail(detail));
    let backing = setup
        .roles
        .assign_object_backing(zeroed)
        .unwrap_or_else(|_| fail(detail + 1));
    let creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT)
        .unwrap_or_else(|_| fail(detail + 2));
    let binding = memory
        .bind_backing(
            creation,
            backing,
            PAGE_SIZE,
            MemoryObjectKind::PageBacked,
            MemoryProtection::READ_WRITE_EXECUTE,
        )
        .unwrap_or_else(|_| fail(detail + 3));
    let key = binding.key();
    let bound = registry
        .finish_payload_binding(binding)
        .unwrap_or_else(|_| fail(detail + 4));
    (
        registry
            .bound_into_internal(bound)
            .unwrap_or_else(|_| fail(detail + 5)),
        key,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "F12 setup keeps exact mapping, backing, task, and page-table candidate authorities visible"
)]
fn map_page<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    registry: &mut F12Registry,
    memory: &mut F12Memory,
    tasks: &mut F12Tasks,
    process: ProcessKey,
    regions: &mut F12Regions,
    root_region: AddressRegionObjectKey,
    owner: &InternalRef,
    address: u64,
    authorization_ceiling: MemoryProtection,
    protection: MemoryProtection,
    candidates: &mut [Option<crate::memory::frame_roles::TableCandidateGrant>; 3],
    detail: u32,
) {
    let resolved = crate::handle::resolve_test_internal_owner(
        registry,
        owner,
        deepwyrm_abi::dw_object_compatible_rights(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let lease = tasks
        .acquire_process_operation(process)
        .unwrap_or_else(|_| fail(detail));
    let result = {
        let region = regions
            .region_mut_for_operation(tasks, &lease, root_region)
            .unwrap_or_else(|_| fail(detail));
        let authorization = memory
            .issue_map_authorization(
                resolved,
                region.address_space_key(),
                region.region_key(),
                authorization_ceiling,
            )
            .unwrap_or_else(|_| fail(detail + 1));
        let mut publisher = setup
            .bind_test_publisher(region.address_space_key(), region.region_key(), candidates)
            .unwrap_or_else(|_| fail(detail + 2));
        region.map(
            memory,
            registry,
            &mut publisher,
            address,
            authorization,
            0,
            PAGE_SIZE,
            protection,
        )
    };
    tasks
        .release_process_operation(lease)
        .unwrap_or_else(|_| fail(detail + 3));
    require_clean_mapping(result, detail + 3);
}

#[allow(
    clippy::too_many_arguments,
    reason = "F12 code sealing keeps the exact root region and active publisher explicit"
)]
fn protect_page<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    registry: &mut F12Registry,
    memory: &mut F12Memory,
    tasks: &mut F12Tasks,
    process: ProcessKey,
    regions: &mut F12Regions,
    root_region: AddressRegionObjectKey,
    address: u64,
    protection: MemoryProtection,
    candidates: &mut [Option<crate::memory::frame_roles::TableCandidateGrant>; 3],
    detail: u32,
) {
    let lease = tasks
        .acquire_process_operation(process)
        .unwrap_or_else(|_| fail(detail));
    let result = {
        let region = regions
            .region_mut_for_operation(tasks, &lease, root_region)
            .unwrap_or_else(|_| fail(detail));
        let mut publisher = setup
            .bind_test_publisher(region.address_space_key(), region.region_key(), candidates)
            .unwrap_or_else(|_| fail(detail + 1));
        region.protect(
            memory,
            registry,
            &mut publisher,
            address,
            PAGE_SIZE,
            protection,
        )
    };
    tasks
        .release_process_operation(lease)
        .unwrap_or_else(|_| fail(detail + 2));
    require_clean_mapping(result, detail + 2);
}

#[allow(
    unsafe_code,
    reason = "F12 test symbols delimit one linker-owned immutable userspace blob"
)]
fn embedded_user_blob() -> &'static [u8] {
    unsafe extern "C" {
        static __dw_test_f12_user_blob_start: u8;
        static __dw_test_f12_user_blob_end: u8;
    }
    let start = core::ptr::addr_of!(__dw_test_f12_user_blob_start) as usize;
    let end = core::ptr::addr_of!(__dw_test_f12_user_blob_end) as usize;
    let len = end.checked_sub(start).unwrap_or_else(|| fail(0x20));
    if len == 0 || len > usize::try_from(PAGE_SIZE).unwrap_or(4096) {
        fail(0x21);
    }
    unsafe { core::slice::from_raw_parts(start as *const u8, len) }
}

fn copy_user_blob<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
) {
    let blob = embedded_user_blob();
    let space = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap_or_else(|_| fail(0x22));
    let range = UserRange::new(
        space,
        F12_USER_ENTRY,
        u64::try_from(blob.len()).unwrap_or_else(|_| fail(0x23)),
        1,
        UserAccess::WRITE,
        EmptyAddressRule::Reject,
    )
    .unwrap_or_else(|_| fail(0x24));
    let mut access = ActiveUserPageAccess { authority: setup };
    crate::memory::usercopy::copy_to_user(&mut access, range, blob).unwrap_or_else(|_| fail(0x25));
}

fn publish_root_handle<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    root_handle: deepwyrm_abi::DwHandle,
) {
    let space = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap_or_else(|_| fail(0x2d));
    let range = UserRange::new(
        space,
        F12_USER_DATA,
        core::mem::size_of::<u64>() as u64,
        core::mem::align_of::<u64>() as u64,
        UserAccess::WRITE,
        EmptyAddressRule::Reject,
    )
    .unwrap_or_else(|_| fail(0x2e));
    let mut access = ActiveUserPageAccess { authority: setup };
    crate::memory::usercopy::copy_to_user(&mut access, range, &root_handle.0.to_le_bytes())
        .unwrap_or_else(|_| fail(0x2f));
}

fn validate_user_layout<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
) {
    let code = setup
        .walk_leaf(F12_USER_ENTRY)
        .unwrap_or_else(|_| fail(0x26));
    let data = setup
        .walk_leaf(F12_USER_DATA)
        .unwrap_or_else(|_| fail(0x27));
    let stack = setup
        .walk_leaf(F12_USER_STACK_BOTTOM)
        .unwrap_or_else(|_| fail(0x28));
    if !code.user || code.writable || !code.executable {
        fail(0x29);
    }
    if !data.user || !data.writable || data.executable {
        fail(0x2a);
    }
    if !stack.user || !stack.writable || stack.executable {
        fail(0x2b);
    }
    if F12_USER_SERVICE_STACK_TOP <= F12_USER_STACK_BOTTOM
        || F12_USER_PRODUCER_STACK_TOP > F12_USER_STACK_TOP
        || F12_USER_SERVICE_STACK_TOP >= F12_USER_PRODUCER_STACK_TOP
    {
        fail(0x2c);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct F12Scenario {
    service_phase: u8,
    producer_phase: u8,
    child: Option<ProcessKey>,
    child_root_retired: bool,
    exit_seen: bool,
}

impl F12Scenario {
    const fn new() -> Self {
        Self {
            service_phase: 0,
            producer_phase: 0,
            child: None,
            child_root_retired: false,
            exit_seen: false,
        }
    }
}

struct F12Runtime<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    active_root: ActiveRootSelection,
    registry: F12Registry,
    memory: F12Memory,
    tasks: F12Tasks,
    execution: &'static ExecutionDomain<EXECUTION_THREADS>,
    channels: F12Channels,
    events: EventAuthority<EVENTS>,
    timers: TimerAuthority<TIMERS>,
    waits: WaitRegistry<WAITERS>,
    services: FServiceState<
        super::super::user_access::OwnedLiveUserOutput,
        super::super::user_access::OwnedLiveAtomicU32,
        REGISTRY_OBJECTS,
        WAITERS,
        EXECUTION_THREADS,
    >,
    control: NativeWaitControl,
    channel_staging: &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize],
    spaces: F12Spaces,
    regions: F12Regions,
    root_region: AddressRegionObjectKey,
    root_region_ref: Option<HandleRef>,
    root_owner: Option<InternalRef>,
    process_ref: Option<HandleRef>,
    thread_refs: [Option<HandleRef>; EXECUTION_THREADS],
    memory_owners: [Option<InternalRef>; MEMORY_OBJECTS],
    memory_keys: [MemoryObjectKey; MEMORY_OBJECTS],
    process: ProcessKey,
    threads: [ThreadKey; EXECUTION_THREADS],
    stack_ids: [crate::task::KernelStackId; EXECUTION_THREADS],
    context_ids: [crate::task::ThreadContextId; EXECUTION_THREADS],
    deferred_current: Option<crate::task::DeferredCurrentExecutionResources>,
    cleanup: CleanupQueue<REGISTRY_OBJECTS>,
    scenario: F12Scenario,
}

#[allow(
    unsafe_code,
    reason = "F12 setup uniquely owns its synthetic address-space identity before CPL3 execution"
)]
fn build_runtime<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mut active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> F12Runtime<'roles, RANGE_CAPACITY, ROLE_CAPACITY> {
    let mut registry = F12Registry::new();
    let mut tasks = F12Tasks::new();
    let (_root, root_owner) = tasks
        .create_root_group(&mut registry)
        .unwrap_or_else(|_| fail(0x30));
    let root_handle_owner = registry
        .retain_internal(&root_owner)
        .unwrap_or_else(|_| fail(0x31));
    let root_handle_ref = registry
        .internal_into_handle(root_handle_owner)
        .unwrap_or_else(|_| fail(0x32));
    let (process, process_ref) = tasks
        .create_process(&mut registry, &root_owner)
        .unwrap_or_else(|_| fail(0x33));
    let root_handle = tasks
        .process_handles_mut(process)
        .unwrap_or_else(|_| fail(0x34))
        .install(root_handle_ref, DW_RIGHT_MODIFY)
        .unwrap_or_else(|_| fail(0x35));

    let mut spaces = unsafe { F12Spaces::new() };
    let mut regions = F12Regions::new();
    let (root_region, root_region_ref) = regions
        .create_root_region(
            &mut registry,
            &mut tasks,
            &mut spaces,
            process,
            &process_ref,
        )
        .unwrap_or_else(|_| fail(0x36));

    let process_owner = registry
        .retain_internal_from_handle(&process_ref)
        .unwrap_or_else(|_| fail(0x37));
    let (service, service_ref) = tasks
        .create_thread(&mut registry, &process_owner)
        .unwrap_or_else(|_| fail(0x38));
    let (producer, producer_ref) = tasks
        .create_thread(&mut registry, &process_owner)
        .unwrap_or_else(|_| fail(0x39));
    if registry
        .release_internal(process_owner)
        .unwrap_or_else(|_| fail(0x3a))
        .is_some()
    {
        fail(0x3b);
    }

    let mut memory = F12Memory::new();
    let mut scratch = active
        .target
        .current_scratch_target()
        .unwrap_or_else(|_| fail(0x3c));
    let mut setup = ActiveRootTestAuthority {
        root: &active.root,
        identity: active.identity,
        roles: &mut *active.target.roles,
        scratch: &mut scratch,
        _not_send_sync: core::marker::PhantomData,
    };
    if let Err(detail) = setup.validate_live_kernel_guard_layout() {
        fail(detail);
    }
    let (code_owner, code_key) = create_page_owner(&mut setup, &mut registry, &mut memory, 0x40);
    let (data_owner, data_key) = create_page_owner(&mut setup, &mut registry, &mut memory, 0x48);
    let (stack_owner, stack_key) = create_page_owner(&mut setup, &mut registry, &mut memory, 0x50);

    let mut candidates = [
        Some(
            setup
                .prepare_candidate(TableLevel::Pdpt)
                .unwrap_or_else(|_| fail(0x58)),
        ),
        Some(
            setup
                .prepare_candidate(TableLevel::Pd)
                .unwrap_or_else(|_| fail(0x59)),
        ),
        Some(
            setup
                .prepare_candidate(TableLevel::Pt)
                .unwrap_or_else(|_| fail(0x5a)),
        ),
    ];
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &mut tasks,
        process,
        &mut regions,
        root_region,
        &code_owner,
        F12_USER_ENTRY,
        MemoryProtection::READ_WRITE_EXECUTE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x60,
    );
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &mut tasks,
        process,
        &mut regions,
        root_region,
        &data_owner,
        F12_USER_DATA,
        MemoryProtection::READ_WRITE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x68,
    );
    if !candidates.iter().all(Option::is_none) {
        fail(0x70);
    }
    candidates[0] = Some(
        setup
            .prepare_candidate(TableLevel::Pt)
            .unwrap_or_else(|_| fail(0x71)),
    );
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &mut tasks,
        process,
        &mut regions,
        root_region,
        &stack_owner,
        F12_USER_STACK_BOTTOM,
        MemoryProtection::READ_WRITE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x72,
    );
    if !candidates.iter().all(Option::is_none) {
        fail(0x7a);
    }

    copy_user_blob(&mut setup);
    publish_root_handle(&mut setup, root_handle);
    protect_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &mut tasks,
        process,
        &mut regions,
        root_region,
        F12_USER_ENTRY,
        MemoryProtection::READ_EXECUTE,
        &mut candidates,
        0x7b,
    );
    validate_user_layout(&mut setup);
    drop(setup);
    let address_space = regions
        .region(root_region)
        .unwrap_or_else(|_| fail(0x7f))
        .address_space_key();
    active
        .bind_primordial_address_space(process, address_space)
        .unwrap_or_else(|_| fail(0x7f));
    let active_root = active
        .prepare_process_root_selection(crate::cpu::CpuIndex::BOOTSTRAP, process, address_space)
        .and_then(|prepared| {
            active
                .activate_process_root_selection(prepared, None)
                .map_err(|failure| failure.error())
        })
        .unwrap_or_else(|_| fail(0x7f));

    let stacks =
        crate::arch::x86_64::linked_thread_kernel_stack_layout().unwrap_or_else(|_| fail(0x80));
    let execution = publish_execution([stacks[0], stacks[1]]);
    execution
        .start_thread(
            &mut tasks,
            service,
            crate::task::ThreadStartState::from_validated_user_state(
                F12_USER_ENTRY,
                F12_USER_SERVICE_STACK_TOP,
                SERVICE_ROLE,
                root_handle.0,
            ),
        )
        .unwrap_or_else(|_| fail(0x81));
    execution
        .start_thread(
            &mut tasks,
            producer,
            crate::task::ThreadStartState::from_validated_user_state(
                F12_USER_ENTRY,
                F12_USER_PRODUCER_STACK_TOP,
                PRODUCER_ROLE,
                root_handle.0,
            ),
        )
        .unwrap_or_else(|_| fail(0x82));
    if execution
        .schedule_next()
        .unwrap_or_else(|_| fail(0x83))
        .current
        != Some(service)
    {
        fail(0x84);
    }

    let service_resources = tasks
        .thread_execution_resources(service)
        .unwrap_or_else(|_| fail(0x85))
        .unwrap_or_else(|| fail(0x86));
    let producer_resources = tasks
        .thread_execution_resources(producer)
        .unwrap_or_else(|_| fail(0x87))
        .unwrap_or_else(|| fail(0x88));

    F12Runtime {
        active,
        active_root,
        registry,
        memory,
        tasks,
        execution,
        channels: ChannelAuthority::new(),
        events: EventAuthority::new(),
        timers: TimerAuthority::new(),
        waits: WaitRegistry::new(),
        services: FServiceState::new(),
        control: NativeWaitControl::new(),
        channel_staging: take_channel_staging(),
        spaces,
        regions,
        root_region,
        root_region_ref: Some(root_region_ref),
        root_owner: Some(root_owner),
        process_ref: Some(process_ref),
        thread_refs: [Some(service_ref), Some(producer_ref)],
        memory_owners: [Some(code_owner), Some(data_owner), Some(stack_owner)],
        memory_keys: [code_key, data_key, stack_key],
        process,
        threads: [service, producer],
        stack_ids: [service_resources.0, producer_resources.0],
        context_ids: [service_resources.1, producer_resources.1],
        deferred_current: None,
        cleanup: CleanupQueue::new(),
        scenario: F12Scenario::new(),
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    F12Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn current_thread(&self) -> ThreadKey {
        if self.execution.scheduler_state(self.threads[0]) == Some(SchedulerThreadState::Running) {
            self.threads[0]
        } else if self.execution.scheduler_state(self.threads[1])
            == Some(SchedulerThreadState::Running)
        {
            self.threads[1]
        } else {
            fail(0x90)
        }
    }

    fn current_index(&self) -> usize {
        usize::from(self.current_thread() != self.threads[0])
    }

    fn absorb_service_cleanup(&mut self) {
        self.services.drain_cleanup_into(&mut self.cleanup);
    }

    fn read_user_bytes<const BYTES: usize>(&mut self, address: u64) -> [u8; BYTES] {
        let user = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap_or_else(|_| fail(0x91));
        let range = UserRange::new(
            user,
            address,
            BYTES as u64,
            1,
            UserAccess::READ,
            EmptyAddressRule::Reject,
        )
        .unwrap_or_else(|_| fail(0x92));
        let mut bytes = [0; BYTES];
        let mut scratch = [0; BYTES];
        let mut mappings = self
            .active
            .current_process_address_space(&self.active_root, self.process);
        crate::memory::usercopy::copy_from_user(&mut mappings, range, &mut bytes, &mut scratch)
            .unwrap_or_else(|_| fail(0x93));
        bytes
    }

    fn inspect_created_child(&mut self, out_result: DwUserAddress) {
        let result = self.read_user_bytes::<32>(out_result.0);
        if u32::from_le_bytes(result[0..4].try_into().unwrap_or_else(|_| fail(0x94)))
            != deepwyrm_abi::DW_PROCESS_CREATE_RESULT_V1_SIZE
            || u32::from_le_bytes(result[4..8].try_into().unwrap_or_else(|_| fail(0x94))) != 1
        {
            fail(0x95);
        }
        let raw = |offset: usize| {
            deepwyrm_abi::DwHandle(u64::from_le_bytes(
                result[offset..offset + 8]
                    .try_into()
                    .unwrap_or_else(|_| fail(0x94)),
            ))
        };
        let process_raw = raw(8);
        let root_raw = raw(16);
        let bootstrap_raw = raw(24);
        if process_raw.0 == 0 || root_raw.0 == 0 || bootstrap_raw.0 == 0 {
            fail(0x96);
        }

        let process_pin = self
            .tasks
            .process_handles(self.process)
            .unwrap_or_else(|_| fail(0x96))
            .lookup(
                &mut self.registry,
                process_raw,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_PROCESS),
                DW_RIGHT_MODIFY,
            )
            .unwrap_or_else(|_| fail(0x97));
        if process_pin.rights() != deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_PROCESS)
        {
            fail(0x98);
        }
        let child = ProcessKey::from_object_id(process_pin.object_id());
        if self
            .registry
            .release_internal(process_pin.into_internal())
            .unwrap_or_else(|_| fail(0x99))
            .is_some()
        {
            fail(0x9a);
        }

        let root_pin = self
            .tasks
            .process_handles(self.process)
            .unwrap_or_else(|_| fail(0x9b))
            .lookup(
                &mut self.registry,
                root_raw,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_ADDRESS_REGION),
                deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_ADDRESS_REGION),
            )
            .unwrap_or_else(|_| fail(0x9c));
        let child_root = self
            .tasks
            .root_region(child)
            .unwrap_or_else(|_| fail(0x9d))
            .unwrap_or_else(|| fail(0x9e));
        if root_pin.object_id() != child_root
            || root_pin.rights()
                != deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_ADDRESS_REGION)
        {
            fail(0x9f);
        }
        if self
            .registry
            .release_internal(root_pin.into_internal())
            .unwrap_or_else(|_| fail(0xa0))
            .is_some()
        {
            fail(0xa1);
        }

        if self
            .tasks
            .process_info(child)
            .unwrap_or_else(|_| fail(0xa2))
            .state
            != DW_TASK_STATE_CREATED
            || self
                .tasks
                .process_handle_count(child)
                .unwrap_or_else(|_| fail(0xa3))
                != 1
        {
            fail(0xa4);
        }
        let bootstrap_pin = self
            .tasks
            .process_handles(child)
            .unwrap_or_else(|_| fail(0xa5))
            .lookup(
                &mut self.registry,
                bootstrap_raw,
                AcceptedObjectTypes::One(DW_OBJECT_TYPE_CHANNEL),
                DW_RIGHT_READ,
            )
            .unwrap_or_else(|_| fail(0xa6));
        if bootstrap_pin.rights() != DW_RIGHT_READ {
            fail(0xa7);
        }
        if self
            .registry
            .release_internal(bootstrap_pin.into_internal())
            .unwrap_or_else(|_| fail(0xa8))
            .is_some()
        {
            fail(0xa9);
        }
        let child_region = self
            .regions
            .region(AddressRegionObjectKey::from_object_id(child_root))
            .unwrap_or_else(|_| fail(0xaa));
        if child_region.mappings().iter().any(Option::is_some) || self.scenario.child.is_some() {
            fail(0xab);
        }
        self.scenario.child = Some(child);
    }

    fn verify_request(&self, thread_index: usize, request: NativeSyscallRequest) {
        if thread_index == 0 {
            let valid = match (self.scenario.service_phase, request) {
                (0..=1, NativeSyscallRequest::ChannelCreate { .. })
                | (2, NativeSyscallRequest::EventCreate { .. })
                | (3, NativeSyscallRequest::HandleDuplicate { .. })
                | (4, NativeSyscallRequest::ClockGet { .. })
                | (7..=8, NativeSyscallRequest::ChannelReceive { .. })
                | (9, NativeSyscallRequest::AtomicWake { count: 1, .. })
                | (12, NativeSyscallRequest::ProcessCreate { .. })
                | (13, NativeSyscallRequest::HandleClose { .. })
                | (14 | 16, NativeSyscallRequest::ObjectGetInfoV1 { .. })
                | (
                    15,
                    NativeSyscallRequest::ProcessTerminate {
                        reason: DW_TERMINATION_AUTHORIZED,
                        code: 0,
                        ..
                    },
                )
                | (17, NativeSyscallRequest::ProcessExit { exit_code: 0 }) => true,
                (
                    5,
                    NativeSyscallRequest::WaitOne {
                        deadline: DW_DEADLINE_INFINITE,
                        ..
                    },
                ) => true,
                (10, NativeSyscallRequest::WaitOne { deadline, .. }) => {
                    deadline != DW_DEADLINE_NOW && deadline != DW_DEADLINE_INFINITE
                }
                _ => false,
            };
            if !valid {
                fail(0xac);
            }
        } else {
            let valid = match (self.scenario.producer_phase, request) {
                (0..=1, NativeSyscallRequest::ChannelSend { .. })
                | (4, NativeSyscallRequest::EventSignal { .. }) => true,
                (
                    2 | 5,
                    NativeSyscallRequest::AtomicWait32 {
                        expected: 0,
                        deadline: DW_DEADLINE_INFINITE,
                        ..
                    },
                ) => true,
                _ => false,
            };
            if !valid {
                fail(0xad);
            }
        }
    }

    fn record_result(
        &mut self,
        thread_index: usize,
        request: NativeSyscallRequest,
        result: NativeSyscallResult,
    ) {
        if thread_index == 0 {
            match self.scenario.service_phase {
                0..=4 | 7..=9 | 12 | 14 | 16
                    if result.status == DW_STATUS_SUCCESS
                        && result.control == SyscallControl::ReturnToCaller =>
                {
                    if let NativeSyscallRequest::ProcessCreate { out_result, .. } = request {
                        self.inspect_created_child(out_result);
                    }
                    self.scenario.service_phase += 1;
                }
                5 | 10
                    if result.status == DW_STATUS_SUCCESS
                        && result.control == SyscallControl::SuspendCurrent =>
                {
                    self.scenario.service_phase += 1;
                }
                13 if result.status == DW_STATUS_BAD_HANDLE
                    && result.control == SyscallControl::ReturnToCaller =>
                {
                    self.scenario.service_phase += 1;
                }
                15 if result.status == DW_STATUS_SUCCESS
                    && result.control == SyscallControl::ReturnToCaller =>
                {
                    self.scenario.service_phase += 1;
                }
                17 if result.status == DW_STATUS_SUCCESS
                    && result.control == SyscallControl::TerminateCurrent =>
                {
                    self.scenario.service_phase += 1;
                    self.scenario.exit_seen = true;
                }
                _ => fail(0xae),
            }
        } else {
            match self.scenario.producer_phase {
                0..=1 | 4
                    if result.status == DW_STATUS_SUCCESS
                        && result.control == SyscallControl::ReturnToCaller =>
                {
                    self.scenario.producer_phase += 1;
                }
                2 | 5
                    if result.status == DW_STATUS_SUCCESS
                        && result.control == SyscallControl::SuspendCurrent =>
                {
                    self.scenario.producer_phase += 1;
                }
                _ => fail(0xaf),
            }
        }
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler
    for F12Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        let thread = self.current_thread();
        let thread_index = self.current_index();
        self.verify_request(thread_index, request);

        let dispatch = {
            let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
            let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
            let mut user = self
                .active
                .current_process_address_space(&self.active_root, self.process);
            let root_generation = self.active_root.binding_generation();
            let prepared = self
                .services
                .prepare_dispatch(request, thread, root_generation)
                .unwrap_or_else(|_| fail(0xaf));
            self.services.dispatch_prepared(
                &mut self.control,
                prepared,
                &mut user,
                &mut self.registry,
                &mut self.tasks,
                self.execution,
                &self.channels,
                &self.events,
                &self.timers,
                None,
                &self.waits,
                &mut self.regions,
                &mut self.spaces,
                self.process,
                thread,
                crate::cpu::CpuIndex::BOOTSTRAP,
                root_generation,
                Some(&mut wait_deadlines),
                &mut timer_deadlines,
                &mut self.channel_staging[..],
                || crate::time::monotonic_now().map_err(|_| deepwyrm_abi::DW_STATUS_BAD_STATE),
            )
        };
        let (route, cleanup) = dispatch.into_parts();
        self.merge_cleanup(cleanup);

        let result = match route {
            FServiceRoute::Handled(result) => result,
            FServiceRoute::Fallthrough(request) => match request {
                NativeSyscallRequest::HandleClose { handle } => {
                    NativeSyscallResult::returning(crate::syscall::handle_close(
                        &mut self.registry,
                        &mut self.tasks,
                        self.process,
                        handle,
                        &mut self.cleanup,
                    ))
                }
                NativeSyscallRequest::HandleDuplicate {
                    handle,
                    requested_rights,
                    out_handle,
                } => {
                    let mut user = self
                        .active
                        .current_process_address_space(&self.active_root, self.process);
                    NativeSyscallResult::returning(crate::syscall::handle_duplicate(
                        &mut user,
                        &mut self.registry,
                        &mut self.tasks,
                        self.process,
                        handle,
                        requested_rights,
                        out_handle,
                    ))
                }
                NativeSyscallRequest::ObjectGetInfoV1 {
                    handle,
                    topic,
                    out_info,
                    out_size,
                    out_required_size,
                } => {
                    let mut user = self
                        .active
                        .current_process_address_space(&self.active_root, self.process);
                    NativeSyscallResult::returning(crate::syscall::object_get_info_v1(
                        &mut user,
                        &mut self.registry,
                        &self.memory,
                        &self.tasks,
                        self.process,
                        handle,
                        topic,
                        out_info,
                        out_size,
                        out_required_size,
                    ))
                }
                NativeSyscallRequest::ProcessTerminate {
                    process,
                    reason,
                    code,
                } => {
                    let pin = self
                        .tasks
                        .process_handles(self.process)
                        .unwrap_or_else(|_| fail(0xb0))
                        .lookup(
                            &mut self.registry,
                            process,
                            AcceptedObjectTypes::One(DW_OBJECT_TYPE_PROCESS),
                            DW_RIGHT_MODIFY,
                        )
                        .unwrap_or_else(|_| fail(0xb1));
                    let child = ProcessKey::from_object_id(pin.object_id());
                    if Some(child) != self.scenario.child
                        || self
                            .tasks
                            .process_info(child)
                            .unwrap_or_else(|_| fail(0xb2))
                            .state
                            != DW_TASK_STATE_CREATED
                    {
                        fail(0xb3);
                    }
                    if self
                        .registry
                        .release_internal(pin.into_internal())
                        .unwrap_or_else(|_| fail(0xb4))
                        .is_some()
                    {
                        fail(0xb5);
                    }

                    let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
                    let mut terminal = self.services.terminal_cleanup(
                        Some(&mut wait_deadlines),
                        |_| fail(0xb6),
                        |_| fail(0xb7),
                    );
                    let (status, control, deferred) = crate::syscall::process_terminate(
                        &mut self.registry,
                        &mut self.tasks,
                        self.execution,
                        &self.waits,
                        &mut terminal,
                        self.process,
                        thread,
                        process,
                        reason,
                        code,
                        &mut self.cleanup,
                    );
                    if deferred.is_some() {
                        fail(0xb7);
                    }
                    if status == DW_STATUS_SUCCESS {
                        let info = self
                            .tasks
                            .process_info(child)
                            .unwrap_or_else(|_| fail(0xb8));
                        if info.state != DW_TASK_STATE_EXITED
                            || info.reason != DW_TERMINATION_AUTHORIZED
                            || info.application_code != 0
                        {
                            fail(0xb9);
                        }
                        let proof = self
                            .tasks
                            .process_quiescence_proof(child)
                            .unwrap_or_else(|_| fail(0xba));
                        let drained = self
                            .execution
                            .blocked_operations_drained(&self.tasks, &proof)
                            .unwrap_or_else(|_| fail(0xba));
                        let root_pin = self
                            .regions
                            .retire_quiesced_root(
                                &mut self.tasks,
                                child,
                                &proof,
                                self.execution.blocked_operations(),
                                drained,
                            )
                            .unwrap_or_else(|_| fail(0xbb));
                        self.cleanup.push_optional(
                            self.registry
                                .release_internal(root_pin)
                                .unwrap_or_else(|_| fail(0xbc)),
                        );
                        self.scenario.child_root_retired = true;
                    }
                    NativeSyscallResult { status, control }
                }
                NativeSyscallRequest::ProcessExit { exit_code } => {
                    if self.scenario.producer_phase != 6 || !self.scenario.child_root_retired {
                        fail(0xbd);
                    }
                    let mut discarded = None;
                    let mut atomic_pin = None;
                    let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
                    let (status, control, deferred) = {
                        let mut terminal = self.services.terminal_cleanup(
                            Some(&mut wait_deadlines),
                            |output| {
                                if discarded.replace(output).is_some() {
                                    fail(0xbe);
                                }
                            },
                            |pin| {
                                if atomic_pin.replace(pin).is_some() {
                                    fail(0xbf);
                                }
                            },
                        );
                        crate::syscall::process_exit_on(
                            &mut self.registry,
                            &mut self.tasks,
                            self.execution,
                            &self.waits,
                            &mut terminal,
                            crate::cpu::CpuIndex::BOOTSTRAP,
                            self.process,
                            thread,
                            exit_code,
                            &mut self.cleanup,
                        )
                    };
                    if status == DW_STATUS_SUCCESS && control == SyscallControl::TerminateCurrent {
                        if self
                            .deferred_current
                            .replace(deferred.unwrap_or_else(|| fail(0xc2)))
                            .is_some()
                        {
                            fail(0xc2);
                        }
                    } else if deferred.is_some() {
                        fail(0xc2);
                    }
                    {
                        let mut user = self
                            .active
                            .current_process_address_space(&self.active_root, self.process);
                        if let Some(output) = discarded {
                            user.discard_owned_output(output)
                                .unwrap_or_else(|_| fail(0xc0));
                        }
                        if let Some(pin) = atomic_pin {
                            user.release_atomic_u32(pin).unwrap_or_else(|_| fail(0xc1));
                        } else if status == DW_STATUS_SUCCESS {
                            fail(0xc2);
                        }
                    }
                    self.absorb_service_cleanup();
                    NativeSyscallResult { status, control }
                }
                _ => NativeSyscallResult::returning(DW_STATUS_NOT_SUPPORTED),
            },
        };
        self.record_result(thread_index, request, result);
        result
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    F12Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn unmap_main_userspace(
        &mut self,
        proof: &crate::task::ProcessQuiescenceProof,
        drained: &crate::task::BlockedOperationsDrained,
    ) {
        self.execution
            .blocked_operations()
            .validate_drained_after_quiesce(&self.tasks, proof, drained)
            .unwrap_or_else(|_| fail(0xc3));
        let mut scratch = self
            .active
            .target
            .current_scratch_target()
            .unwrap_or_else(|_| fail(0xc4));
        let mut setup = ActiveRootTestAuthority {
            root: &self.active.root,
            identity: self.active.identity,
            roles: &mut *self.active.target.roles,
            scratch: &mut scratch,
            _not_send_sync: core::marker::PhantomData,
        };
        let mut candidates = [None, None, None];
        for (address, detail) in [
            (F12_USER_ENTRY, 0xc4),
            (F12_USER_DATA, 0xcc),
            (F12_USER_STACK_BOTTOM, 0xd4),
        ] {
            let region = self
                .regions
                .region_mut_for_quiesced_teardown(&self.tasks, proof, self.root_region)
                .unwrap_or_else(|_| fail(detail));
            let mut publisher = setup
                .bind_test_publisher(
                    region.address_space_key(),
                    region.region_key(),
                    &mut candidates,
                )
                .unwrap_or_else(|_| fail(detail + 1));
            require_clean_mapping(
                region.unmap(
                    &mut self.memory,
                    &mut self.registry,
                    &mut publisher,
                    address,
                    PAGE_SIZE,
                ),
                detail + 2,
            );
        }
        if self
            .regions
            .region(self.root_region)
            .unwrap_or_else(|_| fail(0xdc))
            .mappings()
            .iter()
            .any(Option::is_some)
            || setup.walk_leaf(F12_USER_ENTRY).is_ok()
            || setup.walk_leaf(F12_USER_DATA).is_ok()
            || setup.walk_leaf(F12_USER_STACK_BOTTOM).is_ok()
            || self.memory.active_lease_count() != 0
        {
            fail(0xdd);
        }
        for candidate in candidates.into_iter().flatten() {
            setup
                .roles
                .cancel_table_candidate(candidate)
                .unwrap_or_else(|_| fail(0xde));
        }
    }

    fn release_retained_references(&mut self) {
        for reference in self.thread_refs.iter_mut().filter_map(Option::take) {
            self.cleanup.push_optional(
                self.registry
                    .release_handle(reference)
                    .unwrap_or_else(|_| fail(0xdf)),
            );
        }
        if let Some(reference) = self.process_ref.take() {
            self.cleanup.push_optional(
                self.registry
                    .release_handle(reference)
                    .unwrap_or_else(|_| fail(0xe0)),
            );
        }
        if let Some(reference) = self.root_region_ref.take() {
            self.cleanup.push_optional(
                self.registry
                    .release_handle(reference)
                    .unwrap_or_else(|_| fail(0xe1)),
            );
        }
        for owner in self.memory_owners.iter_mut().filter_map(Option::take) {
            self.cleanup.push_optional(
                self.registry
                    .release_internal(owner)
                    .unwrap_or_else(|_| fail(0xe2)),
            );
        }
        if let Some(owner) = self.root_owner.take() {
            self.cleanup.push_optional(
                self.registry
                    .release_internal(owner)
                    .unwrap_or_else(|_| fail(0xe3)),
            );
        }
    }

    fn drain_finalizers(&mut self) {
        // The finalizer borrows the same authorities the queue lives beside, so
        // it is built per release rather than held across a snapshot of the
        // queue. That is what lets the queue stay where it is.
        while let Some(release) = self.cleanup.pop() {
            let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
            let mut finalizer = crate::object::PayloadFinalizer::new(
                &mut self.registry,
                &mut *self.active.target.roles,
                &mut self.memory,
                &self.events,
                &self.timers,
                &mut timer_deadlines,
                &self.channels,
                &self.waits,
                &mut self.tasks,
                &mut self.spaces,
                &mut self.regions,
            );
            let batch = finalizer.finalize_chain(release);
            let (wakes, pins) = batch.into_parts();
            if wakes.into_iter().flatten().next().is_some()
                || pins.into_iter().flatten().next().is_some()
            {
                fail(0xe4);
            }
        }
    }

    fn prove_registry_capacity(&mut self) {
        let mut probes: [Option<crate::object::CreationRef>; REGISTRY_OBJECTS] =
            core::array::from_fn(|_| None);
        for slot in &mut probes {
            *slot = Some(
                self.registry
                    .create(deepwyrm_abi::DW_OBJECT_TYPE_EVENT)
                    .unwrap_or_else(|_| fail(0xe5)),
            );
        }
        for probe in probes.into_iter().flatten() {
            self.registry
                .cancel_creation(probe)
                .unwrap_or_else(|_| fail(0xe6));
        }
    }

    fn finish_and_pass(&mut self) -> ! {
        if self.scenario
            != (F12Scenario {
                service_phase: 18,
                producer_phase: 6,
                child: self.scenario.child,
                child_root_retired: true,
                exit_seen: true,
            })
            || !self.services.is_quiescent()
            || !self.control.is_clear()
        {
            fail(0xe7);
        }
        let child = self.scenario.child.unwrap_or_else(|| fail(0xe8));
        let main = self
            .tasks
            .process_info(self.process)
            .unwrap_or_else(|_| fail(0xe9));
        let child_info = self
            .tasks
            .process_info(child)
            .unwrap_or_else(|_| fail(0xea));
        if main.state != DW_TASK_STATE_EXITED
            || main.reason != DW_TERMINATION_NORMAL_EXIT
            || main.application_code != 0
            || child_info.state != DW_TASK_STATE_EXITED
            || child_info.reason != DW_TERMINATION_AUTHORIZED
            || child_info.application_code != 0
            || self
                .tasks
                .root_region(child)
                .unwrap_or_else(|_| fail(0xeb))
                .is_some()
        {
            fail(0xec);
        }
        for (index, thread) in self.threads.into_iter().enumerate() {
            let info = self
                .tasks
                .thread_info(thread)
                .unwrap_or_else(|_| fail(0xed));
            let expected_reason = if index == 0 {
                DW_TERMINATION_NORMAL_EXIT
            } else {
                DW_TERMINATION_AUTHORIZED
            };
            if info.state != DW_TASK_STATE_EXITED
                || info.reason != expected_reason
                || info.application_code != 0
                || self.execution.scheduler_state(thread).is_some()
                || self.execution.stack_bounds(self.stack_ids[index]).is_ok()
                || self.execution.load_context(self.context_ids[index]).is_ok()
                || self.services.operation_owner(thread)
                    != Err(crate::syscall::FServiceOwnerError::Missing)
                || self.execution.blocked_operations().has_thread(thread)
            {
                fail(0xee);
            }
        }
        let proof = self
            .tasks
            .process_quiescence_proof(self.process)
            .unwrap_or_else(|_| fail(0xef));
        let drained = self
            .execution
            .blocked_operations_drained(&self.tasks, &proof)
            .unwrap_or_else(|_| fail(0xef));
        self.unmap_main_userspace(&proof, &drained);
        let root_pin = self
            .regions
            .retire_quiesced_root(
                &mut self.tasks,
                self.process,
                &proof,
                self.execution.blocked_operations(),
                drained,
            )
            .unwrap_or_else(|_| fail(0xf0));
        self.cleanup.push_optional(
            self.registry
                .release_internal(root_pin)
                .unwrap_or_else(|_| fail(0xf1)),
        );
        self.release_retained_references();
        self.drain_finalizers();
        if self.memory.active_lease_count() != 0
            || self
                .memory_keys
                .iter()
                .any(|key| self.memory.object_info(*key).is_ok())
            || self.tasks.process_info(self.process).is_ok()
            || self.tasks.process_info(child).is_ok()
            || self.tasks.thread_info(self.threads[0]).is_ok()
            || self.tasks.thread_info(self.threads[1]).is_ok()
            || self.regions.region(self.root_region).is_ok()
        {
            fail(0xf2);
        }
        if !self.cleanup.is_empty() {
            fail(0xf3);
        }
        self.prove_registry_capacity();
        crate::test_support::complete_pass(0)
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::native::NativeRendezvousRuntime
    for F12Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn rendezvous_stop(
        &mut self,
        _request: crate::arch::x86_64::rendezvous::StopRequest,
        _reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> ! {
        fail(0x1f12)
    }
}

#[allow(
    unsafe_code,
    reason = "the target runtime propagates the physical-current carrier and architecture-owned first-run entry"
)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallFrameRuntime
    for F12Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        let current = self.current_thread();
        if self.tasks.thread_process(current) != Ok(self.process)
            || self.execution.scheduler_state(current) != Some(SchedulerThreadState::Running)
        {
            return Err(crate::arch::x86_64::syscall::UserReturnError::BindingChanged);
        }
        let mut mappings = self
            .active
            .current_process_address_space(&self.active_root, self.process);
        frame.authorize_return(current_binding_generation, &mut mappings)
    }

    fn invalid_return(&mut self, _error: crate::arch::x86_64::syscall::UserReturnError) {
        fail(0xf4)
    }

    fn user_exception(&mut self, record: crate::arch::x86_64::exceptions::UserExceptionRecord) {
        fail(0x100 | (record.vector & 0x0f))
    }

    fn terminate_current(&mut self) -> ! {
        crate::syscall::complete_deferred_current_reclaim_on(
            &mut self.registry,
            self.execution,
            &self.waits,
            crate::cpu::CpuIndex::BOOTSTRAP,
            self.deferred_current.take().unwrap_or_else(|| fail(0xf4)),
            &mut self.cleanup,
        );
        self.finish_and_pass()
    }

    #[allow(
        unsafe_code,
        reason = "F12 enters the scheduler-selected producer through its validated bound context"
    )]
    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        if self.current_index() != 1
            || self.scenario.service_phase != 6
            || self.scenario.producer_phase != 0
        {
            fail(0xf5);
        }
        let context = self
            .execution
            .load_context(self.context_ids[1])
            .unwrap_or_else(|_| fail(0xf6));
        let stack = self
            .execution
            .stack_bounds(self.stack_ids[1])
            .unwrap_or_else(|_| fail(0xf7));
        let state = {
            let mut mappings = self
                .active
                .current_process_address_space(&self.active_root, self.process);
            crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
                .unwrap_or_else(|_| fail(0xf8))
        };
        unsafe { crate::arch::x86_64::syscall::enter_bound_validated_user(&state, stack) }
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan<'owner> {
        unsafe {
            self.services.prepare_suspend(
                &mut self.control,
                &self.tasks,
                self.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|_| fail(0xf9))
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'owner> {
        unsafe {
            self.services.poll_idle_suspend(
                &mut self.control,
                &self.tasks,
                self.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|_| fail(0xfa))
    }

    fn resume_suspended(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeResumeOutcome {
        let thread = self.current_thread();
        let index = self.current_index();
        let expected = if index == 0 {
            matches!(self.scenario.service_phase, 6 | 11)
                && self.services.operation_owner(thread)
                    == Ok(crate::syscall::FServiceOperationOwner::GenericWait)
        } else {
            self.scenario.producer_phase == 3
                && self.services.operation_owner(thread)
                    == Ok(crate::syscall::FServiceOperationOwner::AtomicWait)
        };
        if !expected {
            fail(0xfb);
        }
        let resumed = {
            let mut user = self
                .active
                .current_process_address_space(&self.active_root, self.process);
            let mut deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
            self.services.resume_suspended(
                &mut user,
                &mut self.registry,
                &mut self.tasks,
                &self.waits,
                self.execution,
                thread,
                Some(&mut deadlines),
            )
        }
        .unwrap_or_else(|_| fail(0xfc));
        let (status, cleanup) = resumed.into_parts();
        self.merge_cleanup(cleanup);
        if status != DW_STATUS_SUCCESS {
            fail(0xfd);
        }
        frame.set_status(status);
        if index == 0 {
            self.scenario.service_phase += 1;
        } else {
            self.scenario.producer_phase += 1;
        }
        crate::syscall::native::NativeResumeOutcome::Resumed
    }
}

fn unexpected_user_exception(record: crate::arch::x86_64::exceptions::UserExceptionRecord) -> ! {
    fail(0x100 | (record.vector & 0x0f))
}

#[allow(
    unsafe_code,
    reason = "F12 binds one stationary composed runtime and performs the audited initial CPL3 transition"
)]
fn enter_f12<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> ! {
    let mut runtime = build_runtime(active);
    let exception_binding =
        crate::arch::x86_64::syscall::bind_user_exception_handler(unexpected_user_exception)
            .unwrap_or_else(|_| fail(0x110));
    let context = runtime
        .execution
        .load_context(runtime.context_ids[0])
        .unwrap_or_else(|_| fail(0x111));
    let stack = runtime
        .execution
        .stack_bounds(runtime.stack_ids[0])
        .unwrap_or_else(|_| fail(0x112));
    let state = {
        let mut mappings = runtime
            .active
            .current_process_address_space(&runtime.active_root, runtime.process);
        crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
            .unwrap_or_else(|_| fail(0x113))
    };
    let mut runtime = core::pin::pin!(runtime);
    unsafe {
        crate::arch::x86_64::syscall::enter_native_syscall_runtime(
            runtime.as_mut(),
            &state,
            stack,
            &exception_binding,
        )
    }
}

pub(super) fn run_ipc_blocking_userspace_test<
    'roles,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    test: crate::test_support::BuildGuestTest,
) -> ! {
    match test {
        crate::test_support::BuildGuestTest::IpcBlockingSmoke => enter_f12(active),
        _ => fail(0xfe),
    }
}
