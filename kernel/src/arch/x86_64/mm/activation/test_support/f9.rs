//! DW0-F9 target-only two-Thread atomic wait/wake dispatch.

use super::*;

use crate::atomic_wait::{AtomicWaitOperationRegistry, AtomicWaitRegistry};
use crate::memory::address_region::{
    AddressRegionObjectAuthority, AddressRegionObjectKey, AddressSpaceAuthority,
};
use crate::memory::object::{MemoryObjectAuthority, MemoryObjectKind, MemoryProtection};
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::object::{HandleRef, InternalRef, ObjectRegistry};
use crate::syscall::CleanupQueue;
use crate::syscall::native::{
    NativeSyscallFrameRuntime, NativeSyscallHandler, NativeSyscallRequest, NativeSyscallResult,
    SyscallControl,
};
use crate::task::{ExecutionDomain, ProcessKey, SchedulerThreadState, TaskAuthority, ThreadKey};
use crate::wait::WaitRegistry;
use deepwyrm_abi::{
    DW_STATUS_BAD_ADDRESS, DW_STATUS_BAD_STATE, DW_STATUS_NO_RESOURCES, DW_STATUS_NOT_SUPPORTED,
    DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DW_TASK_STATE_EXITED,
    DW_TERMINATION_AUTHORIZED, DW_TERMINATION_NORMAL_EXIT, DwDeadline, DwStatus,
};

const REGISTRY_OBJECTS: usize = 10;
const MEMORY_OBJECTS: usize = 3;
const MEMORY_LEASES: usize = 3;
const F9_DETAIL_BASE: u32 = 0xf900_0000;
const WAITER_ROLE: u64 = 0;
const WAKER_ROLE: u64 = 1;

type F9Registry = ObjectRegistry<REGISTRY_OBJECTS>;
type F9Memory = MemoryObjectAuthority<MEMORY_OBJECTS, MEMORY_LEASES>;
type F9Tasks = TaskAuthority<1, 1, 2, 1>;
type F9Spaces = AddressSpaceAuthority<1, 1>;
type F9Regions = AddressRegionObjectAuthority<1, 3>;

const fn parse_decimal_u64(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(
        !bytes.is_empty(),
        "F9 address environment must not be empty"
    );
    let mut result = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(
            byte >= b'0' && byte <= b'9',
            "F9 address environment must be decimal"
        );
        let digit = (byte - b'0') as u64;
        assert!(
            result <= (u64::MAX - digit) / 10,
            "F9 address environment overflow"
        );
        result = result * 10 + digit;
        index += 1;
    }
    result
}

const F9_USER_ENTRY: u64 = parse_decimal_u64(env!("DEEPWYRM_F9_USER_ENTRY"));
const F9_USER_DATA: u64 = parse_decimal_u64(env!("DEEPWYRM_F9_USER_DATA"));
const F9_USER_STACK_BOTTOM: u64 = parse_decimal_u64(env!("DEEPWYRM_F9_USER_STACK_BOTTOM"));
const F9_USER_STACK_TOP: u64 = parse_decimal_u64(env!("DEEPWYRM_F9_USER_STACK_TOP"));
const F9_USER_WAITER_STACK_TOP: u64 = parse_decimal_u64(env!("DEEPWYRM_F9_USER_WAITER_STACK_TOP"));
const F9_USER_WAKER_STACK_TOP: u64 = parse_decimal_u64(env!("DEEPWYRM_F9_USER_WAKER_STACK_TOP"));

struct F9Runtime<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    registry: F9Registry,
    memory: F9Memory,
    tasks: F9Tasks,
    execution: ExecutionDomain<2>,
    waits: WaitRegistry<1>,
    atomic_waits: AtomicWaitRegistry<4>,
    atomic_operations: AtomicWaitOperationRegistry<super::super::OwnedLiveAtomicU32, 2>,
    _spaces: F9Spaces,
    regions: F9Regions,
    root_region: AddressRegionObjectKey,
    _root_region_ref: Option<HandleRef>,
    root_owner: Option<InternalRef>,
    process_ref: Option<HandleRef>,
    thread_refs: [Option<HandleRef>; 2],
    _memory_owners: [Option<InternalRef>; MEMORY_OBJECTS],
    process: ProcessKey,
    threads: [ThreadKey; 2],
    stack_ids: [crate::task::KernelStackId; 2],
    context_ids: [crate::task::ThreadContextId; 2],
    cleanup: CleanupQueue<REGISTRY_OBJECTS>,
    control: crate::syscall::NativeWaitControl,
    waiter_wait_seen: bool,
    wake_seen: bool,
    waker_wait_seen: bool,
    waiter_resumed: bool,
    exit_seen: bool,
}

fn fail(detail: u32) -> ! {
    crate::test_support::complete_fail(F9_DETAIL_BASE | detail)
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
    registry: &mut F9Registry,
    memory: &mut F9Memory,
    detail: u32,
) -> InternalRef {
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
    let bound = registry
        .finish_payload_binding(binding)
        .unwrap_or_else(|_| fail(detail + 4));
    registry
        .bound_into_internal(bound)
        .unwrap_or_else(|_| fail(detail + 5))
}

#[allow(
    clippy::too_many_arguments,
    reason = "F9 setup keeps the exact mapping, backing, and page-table candidate authorities visible"
)]
fn map_page<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    registry: &mut F9Registry,
    memory: &mut F9Memory,
    tasks: &F9Tasks,
    regions: &mut F9Regions,
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
    let region = regions
        .region_mut_for_live_process(tasks, root_region)
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
    require_clean_mapping(
        region.map(
            memory,
            registry,
            &mut publisher,
            address,
            authorization,
            0,
            PAGE_SIZE,
            protection,
        ),
        detail + 3,
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "F9 code sealing keeps the exact root region and active publisher explicit"
)]
fn protect_page<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    registry: &mut F9Registry,
    memory: &mut F9Memory,
    tasks: &F9Tasks,
    regions: &mut F9Regions,
    root_region: AddressRegionObjectKey,
    address: u64,
    protection: MemoryProtection,
    candidates: &mut [Option<crate::memory::frame_roles::TableCandidateGrant>; 3],
    detail: u32,
) {
    let region = regions
        .region_mut_for_live_process(tasks, root_region)
        .unwrap_or_else(|_| fail(detail));
    let mut publisher = setup
        .bind_test_publisher(region.address_space_key(), region.region_key(), candidates)
        .unwrap_or_else(|_| fail(detail + 1));
    require_clean_mapping(
        region.protect(
            memory,
            registry,
            &mut publisher,
            address,
            PAGE_SIZE,
            protection,
        ),
        detail + 2,
    );
}

#[allow(
    unsafe_code,
    reason = "F9 test symbols delimit one linker-owned immutable userspace blob"
)]
fn embedded_user_blob() -> &'static [u8] {
    unsafe extern "C" {
        static __dw_test_f9_user_blob_start: u8;
        static __dw_test_f9_user_blob_end: u8;
    }
    let start = core::ptr::addr_of!(__dw_test_f9_user_blob_start) as usize;
    let end = core::ptr::addr_of!(__dw_test_f9_user_blob_end) as usize;
    let len = end.checked_sub(start).unwrap_or_else(|| fail(0x30));
    if len == 0 || len > usize::try_from(PAGE_SIZE).unwrap_or(4096) {
        fail(0x31);
    }
    unsafe { core::slice::from_raw_parts(start as *const u8, len) }
}

fn copy_user_blob<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
) {
    let blob = embedded_user_blob();
    let space = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap_or_else(|_| fail(0x32));
    let range = UserRange::new(
        space,
        F9_USER_ENTRY,
        u64::try_from(blob.len()).unwrap_or_else(|_| fail(0x33)),
        1,
        UserAccess::WRITE,
        EmptyAddressRule::Reject,
    )
    .unwrap_or_else(|_| fail(0x34));
    let mut access = ActiveUserPageAccess { authority: setup };
    crate::memory::usercopy::copy_to_user(&mut access, range, blob).unwrap_or_else(|_| fail(0x35));
}

fn validate_user_layout<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
) {
    let code = setup
        .walk_leaf(F9_USER_ENTRY)
        .unwrap_or_else(|_| fail(0x36));
    let data = setup.walk_leaf(F9_USER_DATA).unwrap_or_else(|_| fail(0x37));
    let stack = setup
        .walk_leaf(F9_USER_STACK_BOTTOM)
        .unwrap_or_else(|_| fail(0x38));
    if !code.user || code.writable || !code.executable {
        fail(0x39);
    }
    if !data.user || !data.writable || data.executable {
        fail(0x3a);
    }
    if !stack.user || !stack.writable || stack.executable {
        fail(0x3b);
    }
    if F9_USER_WAITER_STACK_TOP <= F9_USER_STACK_BOTTOM
        || F9_USER_WAKER_STACK_TOP > F9_USER_STACK_TOP
        || F9_USER_WAITER_STACK_TOP >= F9_USER_WAKER_STACK_TOP
    {
        fail(0x3c);
    }
}

#[allow(
    unsafe_code,
    reason = "F9 setup uniquely owns its synthetic address-space identity before CPL3 execution"
)]
fn build_runtime<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mut active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> F9Runtime<'roles, RANGE_CAPACITY, ROLE_CAPACITY> {
    let mut registry = F9Registry::new();
    let mut tasks = F9Tasks::new();
    let (_root, root_owner) = tasks
        .create_root_group(&mut registry)
        .unwrap_or_else(|_| fail(0x40));
    let (process, process_ref) = tasks
        .create_process(&mut registry, &root_owner)
        .unwrap_or_else(|_| fail(0x41));

    let mut spaces = unsafe { F9Spaces::new() };
    let mut regions = F9Regions::new();
    let (root_region, root_region_ref) = regions
        .create_root_region(
            &mut registry,
            &mut tasks,
            &mut spaces,
            process,
            &process_ref,
        )
        .unwrap_or_else(|_| fail(0x42));

    let process_owner = registry
        .retain_internal_from_handle(&process_ref)
        .unwrap_or_else(|_| fail(0x43));
    let (waiter, waiter_ref) = tasks
        .create_thread(&mut registry, &process_owner)
        .unwrap_or_else(|_| fail(0x44));
    let (waker, waker_ref) = tasks
        .create_thread(&mut registry, &process_owner)
        .unwrap_or_else(|_| fail(0x45));
    if registry
        .release_internal(process_owner)
        .unwrap_or_else(|_| fail(0x46))
        .is_some()
    {
        fail(0x47);
    }

    let mut memory = F9Memory::new();
    let mut setup = ActiveRootTestAuthority {
        root: &active.root,
        identity: active.identity,
        roles: &mut *active.target.roles,
        scratch: &mut active.target.scratch,
        _not_send_sync: core::marker::PhantomData,
    };
    if let Err(detail) = setup.validate_live_kernel_guard_layout() {
        fail(detail);
    }
    let code_owner = create_page_owner(&mut setup, &mut registry, &mut memory, 0x50);
    let data_owner = create_page_owner(&mut setup, &mut registry, &mut memory, 0x58);
    let stack_owner = create_page_owner(&mut setup, &mut registry, &mut memory, 0x60);

    let mut candidates = [
        Some(
            setup
                .prepare_candidate(TableLevel::Pdpt)
                .unwrap_or_else(|_| fail(0x68)),
        ),
        Some(
            setup
                .prepare_candidate(TableLevel::Pd)
                .unwrap_or_else(|_| fail(0x69)),
        ),
        Some(
            setup
                .prepare_candidate(TableLevel::Pt)
                .unwrap_or_else(|_| fail(0x6a)),
        ),
    ];
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &tasks,
        &mut regions,
        root_region,
        &code_owner,
        F9_USER_ENTRY,
        MemoryProtection::READ_WRITE_EXECUTE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x70,
    );
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &tasks,
        &mut regions,
        root_region,
        &data_owner,
        F9_USER_DATA,
        MemoryProtection::READ_WRITE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x78,
    );
    if !candidates.iter().all(Option::is_none) {
        fail(0x80);
    }
    candidates[0] = Some(
        setup
            .prepare_candidate(TableLevel::Pt)
            .unwrap_or_else(|_| fail(0x81)),
    );
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &tasks,
        &mut regions,
        root_region,
        &stack_owner,
        F9_USER_STACK_BOTTOM,
        MemoryProtection::READ_WRITE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x82,
    );
    if !candidates.iter().all(Option::is_none) {
        fail(0x8a);
    }

    copy_user_blob(&mut setup);
    protect_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &tasks,
        &mut regions,
        root_region,
        F9_USER_ENTRY,
        MemoryProtection::READ_EXECUTE,
        &mut candidates,
        0x8b,
    );
    validate_user_layout(&mut setup);
    drop(setup);

    let stacks =
        crate::arch::x86_64::linked_thread_kernel_stack_layout().unwrap_or_else(|_| fail(0x90));
    let execution =
        ExecutionDomain::<2>::new([stacks[0], stacks[1]]).unwrap_or_else(|_| fail(0x91));
    execution
        .start_thread(
            &mut tasks,
            waiter,
            crate::task::ThreadStartState::from_validated_user_state(
                F9_USER_ENTRY,
                F9_USER_WAITER_STACK_TOP,
                WAITER_ROLE,
                0,
            ),
        )
        .unwrap_or_else(|_| fail(0x92));
    execution
        .start_thread(
            &mut tasks,
            waker,
            crate::task::ThreadStartState::from_validated_user_state(
                F9_USER_ENTRY,
                F9_USER_WAKER_STACK_TOP,
                WAKER_ROLE,
                0,
            ),
        )
        .unwrap_or_else(|_| fail(0x93));
    if execution
        .schedule_next()
        .unwrap_or_else(|_| fail(0x94))
        .current
        != Some(waiter)
    {
        fail(0x95);
    }

    let waiter_resources = tasks
        .thread_execution_resources(waiter)
        .unwrap_or_else(|_| fail(0x96))
        .unwrap_or_else(|| fail(0x97));
    let waker_resources = tasks
        .thread_execution_resources(waker)
        .unwrap_or_else(|_| fail(0x98))
        .unwrap_or_else(|| fail(0x99));

    F9Runtime {
        active,
        registry,
        memory,
        tasks,
        execution,
        waits: WaitRegistry::new(),
        atomic_waits: AtomicWaitRegistry::new(),
        atomic_operations: AtomicWaitOperationRegistry::new(),
        _spaces: spaces,
        regions,
        root_region,
        _root_region_ref: Some(root_region_ref),
        root_owner: Some(root_owner),
        process_ref: Some(process_ref),
        thread_refs: [Some(waiter_ref), Some(waker_ref)],
        _memory_owners: [Some(code_owner), Some(data_owner), Some(stack_owner)],
        process,
        threads: [waiter, waker],
        stack_ids: [waiter_resources.0, waker_resources.0],
        context_ids: [waiter_resources.1, waker_resources.1],
        cleanup: CleanupQueue::new(),
        control: crate::syscall::NativeWaitControl::new(),
        waiter_wait_seen: false,
        wake_seen: false,
        waker_wait_seen: false,
        waiter_resumed: false,
        exit_seen: false,
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    F9Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn current_thread(&self) -> ThreadKey {
        if self.execution.scheduler_state(self.threads[0]) == Some(SchedulerThreadState::Running) {
            self.threads[0]
        } else if self.execution.scheduler_state(self.threads[1])
            == Some(SchedulerThreadState::Running)
        {
            self.threads[1]
        } else {
            fail(0xa0)
        }
    }

    fn current_index(&self) -> usize {
        if self.current_thread() == self.threads[0] {
            0
        } else {
            1
        }
    }

    fn atomic_key(&self, address: u64) -> Result<crate::atomic_wait::AtomicWaitKey, DwStatus> {
        self.regions
            .resolve_atomic_wait_key_for_live_process(&self.tasks, self.process, address)
            .map_err(|_| DW_STATUS_BAD_ADDRESS)
    }

    fn release_atomic_pin(&mut self, pin: super::super::OwnedLiveAtomicU32) {
        self.active
            .current_process_address_space(self.process)
            .release_atomic_u32(pin)
            .unwrap_or_else(|_| fail(0xa1));
    }
}

fn wait_deadline(deadline: DwDeadline) -> crate::wait::engine::WaitDeadline {
    if deadline.0 == deepwyrm_abi::DW_DEADLINE_NOW.0 {
        crate::wait::engine::WaitDeadline::Now
    } else if deadline.0 == deepwyrm_abi::DW_DEADLINE_INFINITE.0 {
        crate::wait::engine::WaitDeadline::Infinite
    } else {
        crate::wait::engine::WaitDeadline::Finite(deadline.0)
    }
}

fn atomic_begin_error_status(error: crate::atomic_wait::AtomicWaitBeginError) -> DwStatus {
    use crate::atomic_wait::{AtomicWaitBeginError, AtomicWaitError};
    use crate::wait::engine::WaitDeadlineError;
    match error {
        AtomicWaitBeginError::Registry(AtomicWaitError::Capacity)
        | AtomicWaitBeginError::Deadline(WaitDeadlineError::Capacity) => DW_STATUS_NO_RESOURCES,
        AtomicWaitBeginError::Deadline(WaitDeadlineError::Expired) => DW_STATUS_TIMED_OUT,
        AtomicWaitBeginError::Registry(_)
        | AtomicWaitBeginError::Scheduler(_)
        | AtomicWaitBeginError::Blocked(_)
        | AtomicWaitBeginError::Deadline(WaitDeadlineError::Fault) => DW_STATUS_BAD_STATE,
    }
}

struct F9TerminalAtomicCleanup<'a, 'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
{
    active: &'a mut ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    atomic_waits: &'a AtomicWaitRegistry<4>,
    atomic_operations: &'a mut AtomicWaitOperationRegistry<super::super::OwnedLiveAtomicU32, 2>,
    process: ProcessKey,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::TerminalWaitCleanup<REGISTRY_OBJECTS, 1, 2>
    for F9TerminalAtomicCleanup<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn cleanup_terminal_wait(
        &mut self,
        _registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        _waits: &WaitRegistry<1>,
        execution: &ExecutionDomain<2>,
        thread: ThreadKey,
        _cleanup: &mut CleanupQueue<REGISTRY_OBJECTS>,
    ) {
        let mut deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let pin = crate::atomic_wait::finish_terminal_atomic_wait(
            self.atomic_waits,
            execution,
            self.atomic_operations,
            Some(&mut deadlines),
            thread,
        )
        .unwrap_or_else(|_| fail(0xa2));
        if let Some(pin) = pin {
            self.active
                .current_process_address_space(self.process)
                .release_atomic_u32(pin)
                .unwrap_or_else(|_| fail(0xa3));
        }
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler
    for F9Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        match request {
            NativeSyscallRequest::AtomicWait32 {
                address,
                expected,
                deadline,
            } => {
                let thread = self.current_thread();
                let pin = match self
                    .active
                    .current_process_address_space(self.process)
                    .pin_atomic_u32(address.0)
                {
                    Ok(pin) => pin,
                    Err(_) => return NativeSyscallResult::returning(DW_STATUS_BAD_ADDRESS),
                };
                let key = match self.atomic_key(address.0) {
                    Ok(key) => key,
                    Err(status) => {
                        self.release_atomic_pin(pin);
                        return NativeSyscallResult::returning(status);
                    }
                };
                let process = self.process;
                let active = &mut self.active;
                let mut deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
                let begin = crate::atomic_wait::begin_atomic_wait(
                    pin,
                    key,
                    expected,
                    wait_deadline(deadline),
                    &self.atomic_waits,
                    &self.execution,
                    &mut self.atomic_operations,
                    Some(&mut deadlines),
                    process,
                    thread,
                    |word| {
                        active
                            .current_process_address_space(process)
                            .load_atomic_u32_acquire(word)
                            .unwrap_or_else(|_| fail(0xa4))
                    },
                );
                match begin {
                    Ok(crate::atomic_wait::AtomicWaitBegin::Mismatch(pin)) => {
                        self.release_atomic_pin(pin);
                        NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK)
                    }
                    Ok(crate::atomic_wait::AtomicWaitBegin::TimedOut(pin)) => {
                        self.release_atomic_pin(pin);
                        NativeSyscallResult::returning(DW_STATUS_TIMED_OUT)
                    }
                    Ok(crate::atomic_wait::AtomicWaitBegin::Ready(pin)) => {
                        self.release_atomic_pin(pin);
                        NativeSyscallResult::returning(DW_STATUS_SUCCESS)
                    }
                    Ok(crate::atomic_wait::AtomicWaitBegin::Suspended { wake, decision }) => {
                        if thread == self.threads[0] {
                            if self.waiter_wait_seen {
                                fail(0xa5);
                            }
                            self.waiter_wait_seen = true;
                        } else {
                            if !self.wake_seen || self.waker_wait_seen {
                                fail(0xa6);
                            }
                            self.waker_wait_seen = true;
                        }
                        self.control
                            .accept(crate::syscall::WaitSyscallAction::Suspended(
                                crate::syscall::WaitSuspendState::new(wake, decision),
                            ))
                    }
                    Err(failure) => {
                        let status = atomic_begin_error_status(failure.error);
                        self.release_atomic_pin(failure.pin);
                        NativeSyscallResult::returning(status)
                    }
                }
            }
            NativeSyscallRequest::AtomicWake {
                address,
                count,
                out_woken,
            } => {
                if self.current_thread() != self.threads[1] || self.wake_seen {
                    fail(0xa7);
                }
                let process = self.process;
                let regions = &self.regions;
                let tasks = &self.tasks;
                let atomic_waits = &self.atomic_waits;
                let execution = &self.execution;
                let mut observed_woken = None;
                let mut user = self.active.current_process_address_space(process);
                let status = crate::syscall::atomic_wake_with(
                    &mut user,
                    address,
                    count,
                    out_woken,
                    |user, address| {
                        user.pin_atomic_u32(address.0)
                            .map_err(|_| DW_STATUS_BAD_ADDRESS)
                    },
                    |address, _pin| {
                        regions
                            .resolve_atomic_wait_key_for_live_process(tasks, process, address.0)
                            .map_err(|_| DW_STATUS_BAD_ADDRESS)
                    },
                    |user, pin| {
                        user.release_atomic_u32(pin).unwrap_or_else(|_| fail(0xa8));
                    },
                    |key, count| {
                        crate::atomic_wait::wake_atomic_waiters(atomic_waits, execution, key, count)
                            .map(|woken| {
                                observed_woken = Some(woken);
                                woken
                            })
                            .map_err(atomic_begin_error_status)
                    },
                );
                if status != DW_STATUS_SUCCESS {
                    return NativeSyscallResult::returning(status);
                }
                if observed_woken != Some(1) {
                    fail(0xac);
                }
                self.wake_seen = true;
                NativeSyscallResult::returning(DW_STATUS_SUCCESS)
            }
            NativeSyscallRequest::ProcessExit { exit_code } => {
                let current = self.current_thread();
                if current != self.threads[0]
                    || !self.waiter_resumed
                    || !self.waker_wait_seen
                    || self.exit_seen
                {
                    fail(0xad);
                }
                let mut terminal = F9TerminalAtomicCleanup {
                    active: &mut self.active,
                    atomic_waits: &self.atomic_waits,
                    atomic_operations: &mut self.atomic_operations,
                    process: self.process,
                };
                let (status, control) = crate::syscall::process_exit(
                    &mut self.registry,
                    &mut self.tasks,
                    &self.execution,
                    &self.waits,
                    &mut terminal,
                    self.process,
                    current,
                    exit_code,
                    &mut self.cleanup,
                );
                if status == DW_STATUS_SUCCESS && control == SyscallControl::TerminateCurrent {
                    self.exit_seen = true;
                }
                NativeSyscallResult { status, control }
            }
            _ => NativeSyscallResult::returning(DW_STATUS_NOT_SUPPORTED),
        }
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallFrameRuntime
    for F9Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
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
        let mut mappings = self.active.current_process_address_space(self.process);
        frame.authorize_return(current_binding_generation, &mut mappings)
    }

    fn invalid_return(&mut self, _error: crate::arch::x86_64::syscall::UserReturnError) -> ! {
        fail(0xb0)
    }

    fn terminate_current(&mut self) -> ! {
        if !self.waiter_wait_seen
            || !self.wake_seen
            || !self.waker_wait_seen
            || !self.waiter_resumed
            || !self.exit_seen
        {
            fail(0xb1);
        }
        let process = self
            .tasks
            .process_info(self.process)
            .unwrap_or_else(|_| fail(0xb2));
        if process.state != DW_TASK_STATE_EXITED
            || process.reason != DW_TERMINATION_NORMAL_EXIT
            || process.application_code != 0
        {
            fail(0xb3);
        }
        for (index, thread) in self.threads.into_iter().enumerate() {
            let info = self
                .tasks
                .thread_info(thread)
                .unwrap_or_else(|_| fail(0xb4));
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
                || self.atomic_operations.wake_key_for_thread(thread).is_some()
            {
                fail(0xb5);
            }
        }
        if self
            .execution
            .blocked_operations_drained(self.process)
            .is_err()
        {
            fail(0xb6);
        }
        let cleanup = core::mem::replace(&mut self.cleanup, CleanupQueue::new());
        if cleanup
            .into_releases()
            .into_iter()
            .flatten()
            .next()
            .is_some()
        {
            fail(0xb7);
        }
        crate::test_support::complete_pass(0)
    }

    #[allow(
        unsafe_code,
        reason = "F9 enters the scheduler-selected fresh Thread through its validated bound context"
    )]
    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        if self.current_index() != 1 || !self.waiter_wait_seen {
            fail(0xb8);
        }
        let context = self
            .execution
            .load_context(self.context_ids[1])
            .unwrap_or_else(|_| fail(0xb9));
        let stack = self
            .execution
            .stack_bounds(self.stack_ids[1])
            .unwrap_or_else(|_| fail(0xba));
        let state = {
            let mut mappings = self.active.current_process_address_space(self.process);
            crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
                .unwrap_or_else(|_| fail(0xbb))
        };
        unsafe { crate::arch::x86_64::syscall::enter_bound_validated_user(&state, stack) }
    }

    fn prepare_suspend(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan {
        self.control
            .prepare_suspend(
                &self.tasks,
                &self.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
            .unwrap_or_else(|_| fail(0xbc))
    }

    fn poll_idle_suspend(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeIdleSuspendPoll {
        self.control
            .poll_idle(
                &self.tasks,
                &self.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
            .unwrap_or_else(|_| fail(0xbd))
    }

    fn resume_suspended(&mut self, frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame) {
        let current = self.current_thread();
        if current != self.threads[0] || self.waiter_resumed {
            fail(0xbe);
        }
        let wake = self
            .atomic_operations
            .wake_key_for_thread(current)
            .unwrap_or_else(|| fail(0xbf));
        let mut deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (pin, winner) = crate::atomic_wait::finish_atomic_wait(
            &self.atomic_waits,
            &self.execution,
            &mut self.atomic_operations,
            Some(&mut deadlines),
            wake,
        )
        .unwrap_or_else(|_| fail(0xc0));
        self.release_atomic_pin(pin);
        match winner {
            crate::task::BlockedOperationWinner::AtomicWake => {
                frame.set_status(DW_STATUS_SUCCESS);
                self.waiter_resumed = true;
            }
            crate::task::BlockedOperationWinner::Timeout => {
                frame.set_status(DW_STATUS_TIMED_OUT);
            }
            _ => fail(0xc1),
        }
    }
}

fn unexpected_user_exception(record: crate::arch::x86_64::exceptions::UserExceptionRecord) -> ! {
    fail(0xe0 | (record.vector & 0x0f))
}

#[allow(
    unsafe_code,
    reason = "F9 binds one stationary two-Thread runtime and performs the audited initial CPL3 transition"
)]
fn enter_f9<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> ! {
    let mut runtime = build_runtime(active);
    let exception_binding =
        crate::arch::x86_64::syscall::bind_user_exception_handler(unexpected_user_exception)
            .unwrap_or_else(|_| fail(0xe1));
    let context = runtime
        .execution
        .load_context(runtime.context_ids[0])
        .unwrap_or_else(|_| fail(0xe2));
    let stack = runtime
        .execution
        .stack_bounds(runtime.stack_ids[0])
        .unwrap_or_else(|_| fail(0xe3));
    let state = {
        let mut mappings = runtime
            .active
            .current_process_address_space(runtime.process);
        crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
            .unwrap_or_else(|_| fail(0xe4))
    };
    let mut runtime = core::pin::pin!(runtime);
    let syscall_binding =
        crate::arch::x86_64::syscall::bind_native_syscall_runtime(runtime.as_mut())
            .unwrap_or_else(|_| fail(0xe5));
    unsafe {
        crate::arch::x86_64::syscall::enter_validated_user(
            &state,
            stack,
            &exception_binding,
            syscall_binding,
        )
    }
}

pub(super) fn run_atomic_wait_userspace_test<
    'roles,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    test: crate::test_support::BuildGuestTest,
) -> ! {
    match test {
        crate::test_support::BuildGuestTest::AtomicWaitWake => enter_f9(active),
        _ => fail(0xff),
    }
}
