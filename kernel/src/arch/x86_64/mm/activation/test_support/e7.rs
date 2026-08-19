use super::*;

use crate::memory::address_region::{AddressRegion, AddressSpaceAuthority};
use crate::memory::object::{MemoryObjectAuthority, MemoryObjectKind, MemoryProtection};
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::object::{HandleRef, InternalRef, ObjectRegistry};
use crate::syscall::CleanupQueue;
use crate::syscall::native::{
    NativeSyscallFrameRuntime, NativeSyscallHandler, NativeSyscallRequest, NativeSyscallResult,
    SyscallControl,
};
use crate::task::{ExecutionDomain, ProcessKey, SchedulerThreadState, TaskAuthority, ThreadKey};
use deepwyrm_abi::{
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS, DW_TASK_STATE_EXITED,
    DW_TERMINATION_NORMAL_EXIT,
};

const REGISTRY_OBJECTS: usize = 8;
const MEMORY_OBJECTS: usize = 3;
const MEMORY_LEASES: usize = 3;
const E7_DETAIL_BASE: u32 = 0xe700_0000;

type E7Registry = ObjectRegistry<REGISTRY_OBJECTS>;
type E7Memory = MemoryObjectAuthority<MEMORY_OBJECTS, MEMORY_LEASES>;
type E7Tasks = TaskAuthority<1, 1, 1, 1>;
type E7Spaces = AddressSpaceAuthority<1, 1>;
type E7Region = AddressRegion<3>;

struct E7SmokeRuntime<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    registry: E7Registry,
    memory: E7Memory,
    tasks: E7Tasks,
    execution: ExecutionDomain<1>,
    _spaces: E7Spaces,
    _region: E7Region,
    root_owner: Option<InternalRef>,
    process_ref: Option<HandleRef>,
    thread_ref: Option<HandleRef>,
    _memory_owners: [Option<InternalRef>; MEMORY_OBJECTS],
    process: ProcessKey,
    thread: ThreadKey,
    stack_id: crate::task::KernelStackId,
    context_id: crate::task::ThreadContextId,
    cleanup: CleanupQueue<REGISTRY_OBJECTS>,
    abi_seen: bool,
    exit_seen: bool,
}

fn fail(detail: u32) -> ! {
    crate::test_support::complete_fail(E7_DETAIL_BASE | detail)
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
    registry: &mut E7Registry,
    memory: &mut E7Memory,
    detail: u32,
) -> InternalRef {
    let (zeroed, _) = setup.allocate_zeroed().unwrap_or_else(|_| fail(detail));
    let backing = setup
        .roles
        .assign_object_backing(zeroed)
        .unwrap_or_else(|_| fail(detail + 1));
    let creation = registry
        .create(DW_OBJECT_TYPE_MEMORY_OBJECT)
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

fn map_page<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    registry: &mut E7Registry,
    memory: &mut E7Memory,
    region: &mut E7Region,
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
        deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
    );
    let authorization = memory
        .issue_map_authorization(
            resolved,
            region.address_space_key(),
            region.region_key(),
            authorization_ceiling,
        )
        .unwrap_or_else(|_| fail(detail));
    let mut publisher = setup
        .bind_test_publisher(region.address_space_key(), region.region_key(), candidates)
        .unwrap_or_else(|_| fail(detail + 1));
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
        detail + 2,
    );
}

fn protect_page<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    setup: &mut ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    registry: &mut E7Registry,
    memory: &mut E7Memory,
    region: &mut E7Region,
    address: u64,
    protection: MemoryProtection,
    candidates: &mut [Option<crate::memory::frame_roles::TableCandidateGrant>; 3],
    detail: u32,
) {
    let mut publisher = setup
        .bind_test_publisher(region.address_space_key(), region.region_key(), candidates)
        .unwrap_or_else(|_| fail(detail));
    require_clean_mapping(
        region.protect(
            memory,
            registry,
            &mut publisher,
            address,
            PAGE_SIZE,
            protection,
        ),
        detail + 1,
    );
}

#[allow(
    unsafe_code,
    reason = "linker-owned E7 test symbols delimit one immutable kernel-resident copy of the inspected userspace blob"
)]
fn embedded_user_blob() -> &'static [u8] {
    unsafe extern "C" {
        static __dw_test_e7_user_blob_start: u8;
        static __dw_test_e7_user_blob_end: u8;
    }
    let start = core::ptr::addr_of!(__dw_test_e7_user_blob_start) as usize;
    let end = core::ptr::addr_of!(__dw_test_e7_user_blob_end) as usize;
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
        crate::test_support::e7_user_entry(),
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
        .walk_leaf(crate::test_support::e7_user_entry())
        .unwrap_or_else(|_| fail(0x36));
    let data = setup
        .walk_leaf(crate::test_support::e7_user_data())
        .unwrap_or_else(|_| fail(0x37));
    let stack = setup
        .walk_leaf(crate::test_support::e7_user_stack_bottom())
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
}

#[allow(
    unsafe_code,
    reason = "E7 test setup uniquely owns its synthetic address-space identity before any CPL3 execution"
)]
fn build_smoke_runtime<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mut active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> E7SmokeRuntime<'roles, RANGE_CAPACITY, ROLE_CAPACITY> {
    let mut registry = E7Registry::new();
    let mut tasks = E7Tasks::new();
    let (_root, root_owner) = tasks
        .create_root_group(&mut registry)
        .unwrap_or_else(|_| fail(0x40));
    let (process, process_ref) = tasks
        .create_process(&mut registry, &root_owner)
        .unwrap_or_else(|_| fail(0x41));
    let process_owner = registry
        .retain_internal_from_handle(&process_ref)
        .unwrap_or_else(|_| fail(0x42));
    let (thread, thread_ref) = tasks
        .create_thread(&mut registry, &process_owner)
        .unwrap_or_else(|_| fail(0x43));
    if registry
        .release_internal(process_owner)
        .unwrap_or_else(|_| fail(0x44))
        .is_some()
    {
        fail(0x45);
    }

    let mut spaces = unsafe { E7Spaces::new() };
    let address_space = spaces.create_address_space().unwrap_or_else(|_| fail(0x46));
    let region_len = crate::test_support::e7_user_stack_top()
        .checked_sub(crate::test_support::e7_user_entry())
        .unwrap_or_else(|| fail(0x47));
    let mut region = spaces
        .create_region::<3>(
            address_space,
            crate::test_support::e7_user_entry(),
            region_len,
        )
        .unwrap_or_else(|_| fail(0x48));
    let mut memory = E7Memory::new();

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
        &mut region,
        &code_owner,
        crate::test_support::e7_user_entry(),
        MemoryProtection::READ_WRITE_EXECUTE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x70,
    );
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &mut region,
        &data_owner,
        crate::test_support::e7_user_data(),
        MemoryProtection::READ_WRITE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x74,
    );
    if !candidates.iter().all(Option::is_none) {
        fail(0x78);
    }
    candidates[0] = Some(
        setup
            .prepare_candidate(TableLevel::Pt)
            .unwrap_or_else(|_| fail(0x79)),
    );
    map_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &mut region,
        &stack_owner,
        crate::test_support::e7_user_stack_bottom(),
        MemoryProtection::READ_WRITE,
        MemoryProtection::READ_WRITE,
        &mut candidates,
        0x7a,
    );
    if !candidates.iter().all(Option::is_none) {
        fail(0x7e);
    }

    copy_user_blob(&mut setup);
    protect_page(
        &mut setup,
        &mut registry,
        &mut memory,
        &mut region,
        crate::test_support::e7_user_entry(),
        MemoryProtection::READ_EXECUTE,
        &mut candidates,
        0x80,
    );
    validate_user_layout(&mut setup);
    drop(setup);

    let stacks =
        crate::arch::x86_64::linked_thread_kernel_stack_layout().unwrap_or_else(|_| fail(0x84));
    let execution = ExecutionDomain::<1>::new([stacks[0]]).unwrap_or_else(|_| fail(0x85));
    let start = crate::task::ThreadStartState::from_validated_user_state(
        crate::test_support::e7_user_entry(),
        crate::test_support::e7_user_stack_top(),
        0,
        0,
    );
    execution
        .start_thread(&mut tasks, thread, start)
        .unwrap_or_else(|_| fail(0x86));
    if execution
        .schedule_next()
        .unwrap_or_else(|_| fail(0x87))
        .current
        != Some(thread)
    {
        fail(0x88);
    }
    let (stack_id, context_id) = tasks
        .thread_execution_resources(thread)
        .unwrap_or_else(|_| fail(0x89))
        .unwrap_or_else(|| fail(0x8a));

    E7SmokeRuntime {
        active,
        registry,
        memory,
        tasks,
        execution,
        _spaces: spaces,
        _region: region,
        root_owner: Some(root_owner),
        process_ref: Some(process_ref),
        thread_ref: Some(thread_ref),
        _memory_owners: [Some(code_owner), Some(data_owner), Some(stack_owner)],
        process,
        thread,
        stack_id,
        context_id,
        cleanup: CleanupQueue::new(),
        abi_seen: false,
        exit_seen: false,
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler
    for E7SmokeRuntime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        match request {
            NativeSyscallRequest::AbiGetInfo {
                out_info,
                out_size,
                out_required_size,
            } => {
                let status = {
                    let mut user = self.active.current_process_address_space(self.process);
                    crate::syscall::abi_get_info(&mut user, out_info, out_size, out_required_size)
                };
                if status == DW_STATUS_SUCCESS {
                    self.abi_seen = true;
                }
                NativeSyscallResult::returning(status)
            }
            NativeSyscallRequest::ProcessExit { exit_code } => {
                let (status, control) = crate::syscall::process_exit(
                    &mut self.registry,
                    &mut self.tasks,
                    &self.execution,
                    self.process,
                    self.thread,
                    exit_code,
                    &mut self.cleanup,
                );
                if status == DW_STATUS_SUCCESS && control == SyscallControl::Reschedule {
                    self.exit_seen = true;
                }
                NativeSyscallResult { status, control }
            }
            _ => NativeSyscallResult::returning(DW_STATUS_NOT_SUPPORTED),
        }
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallFrameRuntime
    for E7SmokeRuntime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if self.tasks.thread_process(self.thread) != Ok(self.process)
            || self.execution.scheduler_state(self.thread) != Some(SchedulerThreadState::Running)
        {
            return Err(crate::arch::x86_64::syscall::UserReturnError::BindingChanged);
        }
        let mut mappings = self.active.current_process_address_space(self.process);
        frame.authorize_return(current_binding_generation, &mut mappings)
    }

    fn invalid_return(&mut self, _error: crate::arch::x86_64::syscall::UserReturnError) -> ! {
        fail(0x90)
    }

    fn reschedule(&mut self) -> ! {
        if !self.abi_seen || !self.exit_seen {
            fail(0x91);
        }
        let process = self
            .tasks
            .process_info(self.process)
            .unwrap_or_else(|_| fail(0x92));
        let thread = self
            .tasks
            .thread_info(self.thread)
            .unwrap_or_else(|_| fail(0x93));
        if process.state != DW_TASK_STATE_EXITED
            || thread.state != DW_TASK_STATE_EXITED
            || process.reason != DW_TERMINATION_NORMAL_EXIT
            || thread.reason != DW_TERMINATION_NORMAL_EXIT
            || process.application_code != 0
            || thread.application_code != 0
        {
            fail(0x94);
        }
        if self.execution.scheduler_state(self.thread).is_some() {
            fail(0x95);
        }
        if self.execution.stack_bounds(self.stack_id).is_ok()
            || self.execution.load_context(self.context_id).is_ok()
        {
            fail(0x96);
        }
        let cleanup = core::mem::replace(&mut self.cleanup, CleanupQueue::new());
        if cleanup
            .into_releases()
            .into_iter()
            .flatten()
            .next()
            .is_some()
        {
            fail(0x97);
        }
        self.finalize_task_refs();
        crate::test_support::complete_pass(0)
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    E7SmokeRuntime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn finish_task_release(&mut self, release: crate::object::FinalRelease) {
        let mut pending = Some(release);
        while let Some(release) = pending.take() {
            let finalization = self
                .tasks
                .take_finalization(release)
                .unwrap_or_else(|_| fail(0x98));
            pending = crate::task::complete_task_finalization(&mut self.registry, finalization);
        }
    }

    fn finalize_task_refs(&mut self) {
        let thread = self.thread_ref.take().unwrap_or_else(|| fail(0x99));
        let thread_final = self
            .registry
            .release_handle(thread)
            .unwrap_or_else(|_| fail(0x9a))
            .unwrap_or_else(|| fail(0x9b));
        self.finish_task_release(thread_final);
        let process = self.process_ref.take().unwrap_or_else(|| fail(0x9c));
        let process_final = self
            .registry
            .release_handle(process)
            .unwrap_or_else(|_| fail(0x9d))
            .unwrap_or_else(|| fail(0x9e));
        self.finish_task_release(process_final);

        let root = self.root_owner.take().unwrap_or_else(|| fail(0x9f));
        let root_final = self
            .registry
            .release_internal(root)
            .unwrap_or_else(|_| fail(0xa0))
            .unwrap_or_else(|| fail(0xa1));
        self.finish_task_release(root_final);
    }
}

fn unexpected_user_exception(record: crate::arch::x86_64::exceptions::UserExceptionRecord) -> ! {
    fail(0xb0 | (record.vector & 0x0f))
}

#[allow(
    unsafe_code,
    reason = "E7 binds one stationary test runtime and performs the audited initial CPL3 IRET transition"
)]
fn enter_smoke<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> ! {
    let mut runtime = build_smoke_runtime(active);
    let exception_binding =
        crate::arch::x86_64::syscall::bind_user_exception_handler(unexpected_user_exception)
            .unwrap_or_else(|_| fail(0xb1));
    let syscall_binding =
        unsafe { crate::arch::x86_64::syscall::bind_native_syscall_runtime(&raw mut runtime) }
            .unwrap_or_else(|_| fail(0xb2));
    let context = runtime
        .execution
        .load_context(runtime.context_id)
        .unwrap_or_else(|_| fail(0xb3));
    let stack = runtime
        .execution
        .stack_bounds(runtime.stack_id)
        .unwrap_or_else(|_| fail(0xb4));
    let state = {
        let mut mappings = runtime
            .active
            .current_process_address_space(runtime.process);
        crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
            .unwrap_or_else(|error| match error {
                crate::arch::x86_64::syscall::UserReturnError::NonCanonicalUserAddress => {
                    fail(0xb5)
                }
                crate::arch::x86_64::syscall::UserReturnError::InstructionNotExecutable => {
                    fail(0xb6)
                }
                crate::arch::x86_64::syscall::UserReturnError::StackNotWritable => fail(0xb7),
                crate::arch::x86_64::syscall::UserReturnError::UnsupportedTlsPolicy => fail(0xb8),
                crate::arch::x86_64::syscall::UserReturnError::UnsupportedFpSimdPolicy => {
                    fail(0xb9)
                }
                crate::arch::x86_64::syscall::UserReturnError::BindingChanged => fail(0xba),
            })
    };
    unsafe {
        crate::arch::x86_64::syscall::enter_validated_user(
            &state,
            stack,
            &exception_binding,
            &syscall_binding,
        )
    }
}

pub(super) fn run_task_userspace_test<
    'roles,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    test: crate::test_support::BuildGuestTest,
) -> ! {
    match test {
        crate::test_support::BuildGuestTest::TaskSyscallSmoke => enter_smoke(active),
        _ => fail(0xff),
    }
}
