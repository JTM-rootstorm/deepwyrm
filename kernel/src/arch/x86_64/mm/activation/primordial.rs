//! Production DW0-G primordial process composition over the live x86_64 root.

#![allow(
    unsafe_code,
    reason = "the G3 live runtime owns bounded static publication, physical backing initialization, and the audited CPL3 transition"
)]

use super::*;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::boot::primordial::construction::authority::{
    AuthorityPrimordialBackend, AuthorityPrimordialMonitor, PrimordialPlatform,
};
use crate::boot::primordial::construction::{
    PrimordialCompletionBackend, PrimordialExitDisposition, complete_primordial_launch,
    construct_primordial,
};
use crate::ipc::ChannelAuthority;
use crate::memory::address_region::{
    AddressRegion, AddressRegionObjectAuthority, AddressSpaceAuthority, Protection,
};
use crate::memory::frame_roles::{ObjectBackingGrant, TableLevel};
use crate::memory::object::{MemoryObjectAuthority, MemoryProtection};
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::object::{HandleRef, InternalRef, ObjectRegistry};
use crate::syscall::native::{
    NativeSyscallFrameRuntime, NativeSyscallHandler, NativeSyscallRequest, NativeSyscallResult,
    SyscallControl,
};
use crate::syscall::{CleanupQueue, FServiceRoute, FServiceState};
use crate::task::{ExecutionDomain, ProcessKey, SchedulerThreadState, TaskAuthority, ThreadKey};
use crate::time::TimerAuthority;
use crate::wait::{EventAuthority, WaitRegistry};
use deepwyrm_abi::{
    DW_CHANNEL_MAX_PAYLOAD, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS, DW_TASK_STATE_EXITED,
    DW_TERMINATION_NORMAL_EXIT,
};

const MAX_BOOTFS_BYTES: usize = 32 * 1024 * 1024;
const REGISTRY_OBJECTS: usize = 32;
const MEMORY_OBJECTS: usize = 10;
const MEMORY_LEASES: usize = 10;
const CHANNEL_PAIRS: usize = 1;
const CHANNEL_DEPTH: usize = 2;
const WAITERS: usize = 4;
const TASK_GROUPS: usize = 1;
const PROCESSES: usize = 1;
const THREADS: usize = 1;
const HANDLES: usize = 8;
const SPACES: usize = 1;
const REGIONS: usize = 1;
const REGION_OBJECTS: usize = 1;
const REGION_SLOTS: usize = 10;
const EXECUTION_THREADS: usize = 1;
const EVENTS: usize = 1;
const TIMERS: usize = 1;

type Registry = ObjectRegistry<REGISTRY_OBJECTS>;
type Memory = MemoryObjectAuthority<MEMORY_OBJECTS, MEMORY_LEASES>;
type Channels = ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>;
type Tasks = TaskAuthority<TASK_GROUPS, PROCESSES, THREADS, HANDLES>;
type Spaces = AddressSpaceAuthority<SPACES, REGIONS>;
type Regions = AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>;

struct ByteStorage<const BYTES: usize>(UnsafeCell<MaybeUninit<[u8; BYTES]>>);

impl<const BYTES: usize> ByteStorage<BYTES> {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

// SAFETY: `kernel_main` is a one-shot BSP path and publishes no reference to
// either buffer before its exact module copy has completed.
unsafe impl<const BYTES: usize> Sync for ByteStorage<BYTES> {}

static BOOTSTRAP_BYTES: ByteStorage<{ crate::boot::primordial::MAX_PRIMORDIAL_ELF_BYTES }> =
    ByteStorage::new();
static BOOTFS_BYTES: ByteStorage<MAX_BOOTFS_BYTES> = ByteStorage::new();

struct ExecutionStorage(UnsafeCell<MaybeUninit<ExecutionDomain<EXECUTION_THREADS>>>);

impl ExecutionStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

// SAFETY: the one-shot BSP publishes the stationary execution domain before
// the first userspace transition and never mutates this storage again.
unsafe impl Sync for ExecutionStorage {}

static EXECUTION_STATE: AtomicU8 = AtomicU8::new(0);
static EXECUTION_STORAGE: ExecutionStorage = ExecutionStorage::new();

struct ChannelStaging(UnsafeCell<[u8; DW_CHANNEL_MAX_PAYLOAD as usize]>);

// SAFETY: the sole primordial syscall dispatcher claims this buffer before
// userspace starts and serializes every use through its pinned runtime.
unsafe impl Sync for ChannelStaging {}

static CHANNEL_STAGING_STATE: AtomicU8 = AtomicU8::new(0);
static CHANNEL_STAGING: ChannelStaging =
    ChannelStaging(UnsafeCell::new([0; DW_CHANNEL_MAX_PAYLOAD as usize]));

fn publish_execution() -> &'static ExecutionDomain<EXECUTION_THREADS> {
    EXECUTION_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|_| panic!("primordial execution domain was initialized twice"));
    let stacks = crate::arch::x86_64::linked_thread_kernel_stack_layout()
        .unwrap_or_else(|error| panic!("invalid primordial kernel stack layout: {error:?}"));
    let execution = ExecutionDomain::new([stacks[0]])
        .unwrap_or_else(|error| panic!("invalid primordial execution domain: {error:?}"));
    unsafe {
        (*EXECUTION_STORAGE.0.get()).write(execution);
    }
    EXECUTION_STATE.store(2, Ordering::Release);
    unsafe { &*(*EXECUTION_STORAGE.0.get()).as_ptr() }
}

fn take_channel_staging() -> &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize] {
    CHANNEL_STAGING_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|_| panic!("primordial Channel staging was claimed twice"));
    unsafe { &mut *CHANNEL_STAGING.0.get() }
}

struct LivePlatform<'a, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    active: &'a mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    LivePlatform<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn allocate(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, user_access::LiveUserAccessError> {
        let allocation = self
            .active
            .target
            .roles
            .allocate(page_count)
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        let physical_start = allocation.physical_start();
        let byte_len = allocation.byte_len();
        let mut offset = 0;
        while offset < byte_len {
            let frame =
                FrameAddress::new(physical_start + offset, self.active.root.physical_limit())
                    .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            if self
                .active
                .target
                .scratch
                .zero_allocator_frame(frame)
                .is_err()
            {
                self.active
                    .target
                    .roles
                    .cancel_allocation(allocation)
                    .unwrap_or_else(|_| panic!("primordial backing rollback lost allocation"));
                return Err(user_access::LiveUserAccessError::MissingOrInvalid);
            }
            offset += PAGE_SIZE;
        }
        let zeroed = unsafe { self.active.target.roles.assume_zeroed(allocation) }
            .unwrap_or_else(|_| panic!("primordial zeroed-backing transition drifted"));
        self.active
            .target
            .roles
            .assign_object_backing(zeroed)
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)
    }

    fn prepare_candidate(
        &mut self,
        level: TableLevel,
    ) -> Result<crate::memory::frame_roles::TableCandidateGrant, user_access::LiveUserAccessError>
    {
        let allocation = self
            .active
            .target
            .roles
            .allocate(1)
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        let frame = FrameAddress::new(
            allocation.physical_start(),
            self.active.root.physical_limit(),
        )
        .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        if self
            .active
            .target
            .scratch
            .zero_allocator_frame(frame)
            .is_err()
        {
            self.active
                .target
                .roles
                .cancel_allocation(allocation)
                .unwrap_or_else(|_| panic!("primordial table rollback lost allocation"));
            return Err(user_access::LiveUserAccessError::MissingOrInvalid);
        }
        let zeroed = unsafe { self.active.target.roles.assume_zeroed(allocation) }
            .unwrap_or_else(|_| panic!("primordial zeroed-table transition drifted"));
        self.active
            .target
            .roles
            .prepare_table(zeroed, self.active.identity.owner(), level)
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> PrimordialPlatform
    for LivePlatform<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = user_access::LiveUserAccessError;

    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, Self::Error> {
        self.allocate(page_count)
    }

    fn write_backing(
        &mut self,
        backing: &ObjectBackingGrant,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        if offset
            .checked_add(byte_len)
            .is_none_or(|end| end > backing.byte_len())
        {
            return Err(user_access::LiveUserAccessError::MissingOrInvalid);
        }
        let mut physical = backing.physical_start() + offset;
        let mut copied = 0_usize;
        while copied < bytes.len() {
            let page = physical & !(PAGE_SIZE - 1);
            let page_offset = (physical & (PAGE_SIZE - 1)) as usize;
            let take = (PAGE_SIZE as usize - page_offset).min(bytes.len() - copied);
            let frame = FrameAddress::new(page, self.active.root.physical_limit())
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            self.active
                .target
                .scratch
                .write_physical_bytes(frame, page_offset, &bytes[copied..copied + take])
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            physical += take as u64;
            copied += take;
        }
        Ok(())
    }

    fn recycle_backing(&mut self, backing: ObjectBackingGrant) {
        self.active
            .target
            .roles
            .cancel_object_backing(backing)
            .unwrap_or_else(|_| panic!("primordial backing rollback lost authority"));
    }

    fn map<const SLOTS: usize, const OBJECTS: usize, const LEASES: usize, const REGISTRY: usize>(
        &mut self,
        region: &mut AddressRegion<SLOTS>,
        memory: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY>,
        object: &HandleRef,
        rights: deepwyrm_abi::DwRights,
        virtual_start: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<(), Self::Error> {
        let mut candidates = [
            Some(self.prepare_candidate(TableLevel::Pdpt)?),
            Some(self.prepare_candidate(TableLevel::Pd)?),
            Some(self.prepare_candidate(TableLevel::Pt)?),
        ];
        let resolved =
            crate::handle::ResolvedHandle::from_kernel_reference(registry, object, rights)
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        let authorization = match memory.issue_map_authorization(
            resolved,
            region.address_space_key(),
            region.region_key(),
            protection,
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                let (_error, releases) = error.release(registry);
                assert!(releases.is_empty());
                return Err(user_access::LiveUserAccessError::MissingOrInvalid);
            }
        };
        let result = {
            let target = &mut self.active.target;
            let mut tracked = user_access::TrackedActiveTarget {
                scratch: &mut target.scratch,
                pins: &self.active.user_pins,
            };
            let mut publisher = unsafe {
                crate::arch::x86_64::mm::X86AddressSpacePublisher::<
                    _,
                    RANGE_CAPACITY,
                    ROLE_CAPACITY,
                    3,
                    4,
                    1,
                >::new(
                    region.address_space_key(),
                    region.region_key(),
                    &self.active.root,
                    self.active.identity,
                    target.roles,
                    &mut tracked,
                    &mut candidates,
                )
            }
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            region.map(
                memory,
                registry,
                &mut publisher,
                virtual_start,
                authorization,
                0,
                byte_len,
                protection,
            )
        };
        for candidate in candidates.into_iter().flatten() {
            self.active
                .target
                .roles
                .cancel_table_candidate(candidate)
                .unwrap_or_else(|_| panic!("primordial unused table rollback drifted"));
        }
        match result {
            Ok(releases) if releases.is_empty() => Ok(()),
            Ok(_) | Err(_) => Err(user_access::LiveUserAccessError::MissingOrInvalid),
        }
    }

    fn unmap<
        const SLOTS: usize,
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY: usize,
    >(
        &mut self,
        region: &mut AddressRegion<SLOTS>,
        memory: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY>,
        virtual_start: u64,
        byte_len: u64,
    ) {
        let mut candidates = [None, None, None];
        let result = {
            let target = &mut self.active.target;
            let mut tracked = user_access::TrackedActiveTarget {
                scratch: &mut target.scratch,
                pins: &self.active.user_pins,
            };
            let mut publisher = unsafe {
                crate::arch::x86_64::mm::X86AddressSpacePublisher::<
                    _,
                    RANGE_CAPACITY,
                    ROLE_CAPACITY,
                    3,
                    4,
                    1,
                >::new(
                    region.address_space_key(),
                    region.region_key(),
                    &self.active.root,
                    self.active.identity,
                    target.roles,
                    &mut tracked,
                    &mut candidates,
                )
            }
            .unwrap_or_else(|_| panic!("primordial rollback publisher unavailable"));
            region.unmap(memory, registry, &mut publisher, virtual_start, byte_len)
        };
        match result {
            Ok(releases) if releases.is_empty() => {}
            _ => panic!("primordial live mapping rollback diverged"),
        }
    }
}

struct Runtime<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    registry: Registry,
    memory: Memory,
    tasks: Tasks,
    execution: &'static ExecutionDomain<EXECUTION_THREADS>,
    channels: Channels,
    events: EventAuthority<EVENTS>,
    timers: TimerAuthority<TIMERS>,
    waits: WaitRegistry<WAITERS>,
    services: FServiceState<
        user_access::OwnedLiveUserOutput,
        user_access::OwnedLiveAtomicU32,
        REGISTRY_OBJECTS,
        WAITERS,
        EXECUTION_THREADS,
    >,
    channel_staging: &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize],
    spaces: Spaces,
    regions: Regions,
    process: ProcessKey,
    thread: ThreadKey,
    stack_id: crate::task::KernelStackId,
    context_id: crate::task::ThreadContextId,
    root_key: crate::memory::address_region::AddressRegionObjectKey,
    monitor: AuthorityPrimordialMonitor,
    _root_owner: Option<InternalRef>,
    deferred_current: Option<crate::task::DeferredCurrentExecutionResources>,
    cleanup: CleanupQueue<REGISTRY_OBJECTS>,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn merge_cleanup(&mut self, cleanup: CleanupQueue<REGISTRY_OBJECTS>) {
        for release in cleanup.into_releases().into_iter().flatten() {
            self.cleanup.push(release);
        }
    }
}

struct Completion<'a> {
    channels: &'a Channels,
    waits: &'a WaitRegistry<WAITERS>,
    tasks: &'a Tasks,
    execution: &'a ExecutionDomain<EXECUTION_THREADS>,
    services: &'a FServiceState<
        user_access::OwnedLiveUserOutput,
        user_access::OwnedLiveAtomicU32,
        REGISTRY_OBJECTS,
        WAITERS,
        EXECUTION_THREADS,
    >,
    monitor: &'a AuthorityPrimordialMonitor,
}

impl PrimordialCompletionBackend for Completion<'_> {
    type Error = ();

    fn receive_ready(&mut self, output: &mut [u8; 40]) -> Result<usize, Self::Error> {
        let (bytes, wakes) = self
            .channels
            .receive_into(self.monitor.channel_keys[0], output, self.waits)
            .map_err(|_| ())?;
        let (wake_intents, pins) = wakes.into_parts();
        if wake_intents.into_iter().flatten().next().is_some()
            || pins.into_iter().flatten().next().is_some()
        {
            return Err(());
        }
        Ok(bytes)
    }

    fn observe_exit(&mut self) -> Result<PrimordialExitDisposition, Self::Error> {
        let info = self
            .tasks
            .process_info(self.monitor.process_key)
            .map_err(|_| ())?;
        if info.state != DW_TASK_STATE_EXITED {
            return Err(());
        }
        if info.reason == DW_TERMINATION_NORMAL_EXIT {
            Ok(PrimordialExitDisposition::Normal(info.application_code))
        } else if info.reason == deepwyrm_abi::DW_TERMINATION_UNHANDLED_EXCEPTION {
            Ok(PrimordialExitDisposition::UnhandledException)
        } else {
            Ok(PrimordialExitDisposition::AuthorizedTermination)
        }
    }

    fn verify_quiescent(&mut self) -> Result<(), Self::Error> {
        if !self.services.is_quiescent()
            || self
                .execution
                .scheduler_state(self.monitor.thread_key)
                .is_some()
            || self
                .execution
                .blocked_operations()
                .has_thread(self.monitor.thread_key)
        {
            return Err(());
        }
        Ok(())
    }
}

#[allow(
    unsafe_code,
    reason = "the target runtime propagates the physical-current carrier and architecture-owned first-run entry"
)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallFrameRuntime
    for Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
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

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) -> ! {
        panic!("invalid primordial userspace return: {error:?}")
    }

    fn terminate_current(&mut self) -> ! {
        crate::syscall::complete_deferred_current_reclaim(
            &mut self.registry,
            self.execution,
            &self.waits,
            self.deferred_current
                .take()
                .unwrap_or_else(|| panic!("primordial exit omitted deferred resources")),
            &mut self.cleanup,
        );
        let mut completion = Completion {
            channels: &self.channels,
            waits: &self.waits,
            tasks: &self.tasks,
            execution: self.execution,
            services: &self.services,
            monitor: &self.monitor,
        };
        complete_primordial_launch(&mut completion)
            .unwrap_or_else(|error| panic!("primordial completion failed: {error:?}"));
        #[cfg(feature = "test-support")]
        crate::test_support::complete_pass(0);
        #[cfg(not(feature = "test-support"))]
        {
            let _ = crate::debug::emit_early_record(
                crate::debug::DiagnosticLevel::Info,
                "primordial",
                "Wyrmroot bootstrap completed normally",
            );
            loop {
                unsafe {
                    core::arch::asm!("sti", "hlt", options(nomem, nostack));
                }
            }
        }
    }

    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        panic!("single-thread primordial runtime selected an unexpected fresh Thread")
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan<'owner> {
        panic!("primordial bootstrap blocked despite its prepublished INIT")
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'owner> {
        panic!("primordial bootstrap reached an unexpected idle suspension")
    }

    fn resume_suspended(&mut self, _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame) {
        panic!("primordial bootstrap unexpectedly resumed a blocked syscall")
    }
}

fn copy_module<'a, const BYTES: usize, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'_, RANGE_CAPACITY, ROLE_CAPACITY>>,
    module: crate::boot::primordial::PrimordialModule,
    storage: &'a ByteStorage<BYTES>,
    label: &str,
) -> &'a [u8] {
    let byte_len = usize::try_from(module.range().byte_len())
        .unwrap_or_else(|_| panic!("{label} module length is not representable"));
    if byte_len == 0 || byte_len > BYTES {
        panic!("{label} module exceeds its bounded G3 intake buffer");
    }
    let destination = unsafe {
        core::slice::from_raw_parts_mut((*storage.0.get()).as_mut_ptr().cast::<u8>(), byte_len)
    };
    active
        .read_physical_bytes(module.range().physical_start(), destination)
        .unwrap_or_else(|error| panic!("could not copy {label} module: {error:?}"));
    destination
}

fn unexpected_user_exception(record: crate::arch::x86_64::exceptions::UserExceptionRecord) -> ! {
    panic!("primordial userspace exception: {record:?}")
}

#[allow(
    unsafe_code,
    reason = "G3 binds one stationary composed runtime and performs the audited initial CPL3 transition"
)]
pub(super) fn enter<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mut active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    modules: crate::boot::primordial::PrimordialBootModules,
) -> ! {
    let bootstrap = copy_module(
        &mut active,
        modules.bootstrap(),
        &BOOTSTRAP_BYTES,
        "bootstrap",
    );
    let bootfs = copy_module(&mut active, modules.bootfs(), &BOOTFS_BYTES, "bootfs");
    let plan = crate::boot::primordial::parse_primordial_elf(bootstrap)
        .unwrap_or_else(|error| panic!("invalid primordial bootstrap ELF: {error:?}"));

    let mut registry = Registry::new();
    let mut memory = Memory::new();
    let channels = Channels::new();
    let waits = WaitRegistry::new();
    let mut tasks = Tasks::new();
    let mut spaces = unsafe { Spaces::new() };
    let mut regions = Regions::new();
    let execution = publish_execution();
    let (_root_group, root_owner) = tasks
        .create_root_group(&mut registry)
        .unwrap_or_else(|error| panic!("could not create primordial root TaskGroup: {error:?}"));

    let monitor = {
        let mut platform = LivePlatform {
            active: &mut active,
        };
        let mut backend = AuthorityPrimordialBackend::new(
            &mut platform,
            &mut registry,
            &mut memory,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
            execution,
            &root_owner,
        );
        construct_primordial(&plan, bootstrap, bootfs, &mut backend, |_| false)
            .unwrap_or_else(|error| panic!("primordial construction failed: {error:?}"));
        backend.take_monitor()
    };
    if execution
        .schedule_next()
        .unwrap_or_else(|error| panic!("primordial scheduling failed: {error:?}"))
        .current
        != Some(monitor.thread_key)
    {
        panic!("primordial Thread was not the initial scheduling decision");
    }
    let (stack_id, context_id) = tasks
        .thread_execution_resources(monitor.thread_key)
        .unwrap_or_else(|error| panic!("primordial execution resources failed: {error:?}"))
        .unwrap_or_else(|| panic!("primordial Thread has no execution resources"));
    let process = monitor.process_key;
    let thread = monitor.thread_key;
    let root_key = monitor.root_key;
    let mut runtime = Runtime {
        active,
        registry,
        memory,
        tasks,
        execution,
        channels,
        events: EventAuthority::new(),
        timers: TimerAuthority::new(),
        waits,
        services: FServiceState::new(),
        channel_staging: take_channel_staging(),
        spaces,
        regions,
        process,
        thread,
        stack_id,
        context_id,
        root_key,
        monitor,
        _root_owner: Some(root_owner),
        deferred_current: None,
        cleanup: CleanupQueue::new(),
    };
    let exception_binding =
        crate::arch::x86_64::syscall::bind_user_exception_handler(unexpected_user_exception)
            .unwrap_or_else(|error| panic!("could not bind primordial exceptions: {error:?}"));
    let context = runtime
        .execution
        .load_context(runtime.context_id)
        .unwrap_or_else(|error| panic!("could not load primordial context: {error:?}"));
    let stack = runtime
        .execution
        .stack_bounds(runtime.stack_id)
        .unwrap_or_else(|error| panic!("could not load primordial kernel stack: {error:?}"));
    let state = {
        let mut mappings = runtime
            .active
            .current_process_address_space(runtime.process);
        crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
            .unwrap_or_else(|error| panic!("invalid primordial initial return: {error:?}"))
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

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler
    for Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        if self.execution.scheduler_state(self.thread) != Some(SchedulerThreadState::Running) {
            panic!("primordial syscall arrived without its running Thread");
        }
        let dispatch = {
            let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
            let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
            let mut user = self.active.current_process_address_space(self.process);
            self.services.dispatch(
                request,
                &mut user,
                &mut self.registry,
                &mut self.tasks,
                self.execution,
                &self.channels,
                &self.events,
                &self.timers,
                &self.waits,
                &mut self.regions,
                &mut self.spaces,
                self.process,
                self.thread,
                Some(&mut wait_deadlines),
                &mut timer_deadlines,
                &mut self.channel_staging[..],
                || crate::time::monotonic_now().map_err(|_| deepwyrm_abi::DW_STATUS_BAD_STATE),
            )
        };
        let (route, cleanup) = dispatch.into_parts();
        self.merge_cleanup(cleanup);
        match route {
            FServiceRoute::Handled(result) => result,
            FServiceRoute::Fallthrough(request) => self.handle_fallthrough(request),
        }
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    Runtime<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle_fallthrough(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        match request {
            NativeSyscallRequest::HandleClose { handle } => {
                NativeSyscallResult::returning(crate::syscall::handle_close(
                    &mut self.registry,
                    &mut self.tasks,
                    self.process,
                    handle,
                    &mut self.cleanup,
                ))
            }
            NativeSyscallRequest::ObjectGetInfoV1 {
                handle,
                topic,
                out_info,
                out_size,
                out_required_size,
            } => {
                let mut user = self.active.current_process_address_space(self.process);
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
            NativeSyscallRequest::AddressRegionMap {
                address_region,
                memory_object,
                args,
                args_size,
                out_address,
            } => NativeSyscallResult::returning(self.map_memory(
                address_region,
                memory_object,
                args,
                args_size,
                out_address,
            )),
            NativeSyscallRequest::AddressRegionUnmap {
                address_region,
                address,
                byte_len,
            } => {
                NativeSyscallResult::returning(self.unmap_memory(address_region, address, byte_len))
            }
            NativeSyscallRequest::ProcessExit { exit_code } => self.exit_process(exit_code),
            _ => NativeSyscallResult::returning(DW_STATUS_NOT_SUPPORTED),
        }
    }

    fn map_memory(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        memory_object: deepwyrm_abi::DwHandle,
        args_address: deepwyrm_abi::DwUserAddress,
        args_size: u64,
        out_address: deepwyrm_abi::DwUserAddress,
    ) -> deepwyrm_abi::DwStatus {
        let mut user = self.active.current_process_address_space(self.process);
        let args = match crate::syscall::decode_map_args(&mut user, args_address, args_size) {
            Ok(args) => args,
            Err(status) => return status,
        };
        let protection = match MemoryProtection::mapping(args.protections.0 as u8) {
            Ok(protection) => protection,
            Err(crate::memory::object::MemoryObjectError::UnsupportedProtection) => {
                return deepwyrm_abi::DW_STATUS_NOT_SUPPORTED;
            }
            Err(_) => return deepwyrm_abi::DW_STATUS_INVALID_ARGUMENT,
        };
        let output_range = match UserRange::new(
            UserAddressSpace::x86_64_four_level(PAGE_SIZE)
                .unwrap_or_else(|_| panic!("x86_64 userspace model unavailable")),
            out_address.0,
            8,
            8,
            UserAccess::WRITE,
            EmptyAddressRule::Reject,
        ) {
            Ok(range) => range,
            Err(_) => return deepwyrm_abi::DW_STATUS_BAD_ADDRESS,
        };
        let output = match user.preflight_owned_output(output_range) {
            Ok(output) => output,
            Err(_) => return deepwyrm_abi::DW_STATUS_BAD_ADDRESS,
        };
        let region = self
            .regions
            .region(self.root_key)
            .unwrap_or_else(|error| panic!("primordial root region unavailable: {error:?}"));
        let address_space_key = region.address_space_key();
        let region_key = region.region_key();
        let mut candidates = [
            Some(
                user.prepare_table_candidate(TableLevel::Pdpt)
                    .unwrap_or_else(|_| panic!("primordial map lacks a PDPT candidate")),
            ),
            Some(
                user.prepare_table_candidate(TableLevel::Pd)
                    .unwrap_or_else(|_| panic!("primordial map lacks a PD candidate")),
            ),
            Some(
                user.prepare_table_candidate(TableLevel::Pt)
                    .unwrap_or_else(|_| panic!("primordial map lacks a PT candidate")),
            ),
        ];
        let result = {
            let mut publisher = user
                .publisher::<3, 4, 1>(address_space_key, region_key, &mut candidates)
                .unwrap_or_else(|_| panic!("primordial map publisher unavailable"));
            crate::syscall::address_region_map_model(
                &mut publisher,
                &mut self.registry,
                &mut self.memory,
                &mut self.tasks,
                &mut self.regions,
                self.process,
                address_region,
                memory_object,
                args,
                protection,
                &mut self.cleanup,
            )
        };
        for candidate in candidates.into_iter().flatten() {
            user.recycle_table_candidate(candidate);
        }
        match result {
            Ok(address) => {
                user.commit_owned_output(output, &address.to_le_bytes())
                    .unwrap_or_else(|_| panic!("primordial map output pin drifted"));
                DW_STATUS_SUCCESS
            }
            Err(status) => {
                user.discard_owned_output(output)
                    .unwrap_or_else(|_| panic!("primordial map output pin drifted"));
                status
            }
        }
    }

    fn unmap_memory(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        address: deepwyrm_abi::DwUserAddress,
        byte_len: u64,
    ) -> deepwyrm_abi::DwStatus {
        let region = self
            .regions
            .region(self.root_key)
            .unwrap_or_else(|error| panic!("primordial root region unavailable: {error:?}"));
        let address_space_key = region.address_space_key();
        let region_key = region.region_key();
        let mut candidates = [None, None, None];
        let mut user = self.active.current_process_address_space(self.process);
        let mut publisher = user
            .publisher::<3, 4, 1>(address_space_key, region_key, &mut candidates)
            .unwrap_or_else(|_| panic!("primordial unmap publisher unavailable"));
        crate::syscall::address_region_unmap(
            &mut publisher,
            &mut self.registry,
            &mut self.memory,
            &mut self.tasks,
            &mut self.regions,
            self.process,
            address_region,
            address,
            byte_len,
            &mut self.cleanup,
        )
    }

    fn exit_process(&mut self, exit_code: u32) -> NativeSyscallResult {
        let mut discarded = None;
        let mut atomic_pin = None;
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded.replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pin.replace(pin).is_none());
                },
            );
            crate::syscall::process_exit(
                &mut self.registry,
                &mut self.tasks,
                self.execution,
                &self.waits,
                &mut terminal,
                self.process,
                self.thread,
                exit_code,
                &mut self.cleanup,
            )
        };
        if status == DW_STATUS_SUCCESS && control == SyscallControl::TerminateCurrent {
            self.deferred_current = Some(
                deferred.unwrap_or_else(|| panic!("primordial exit omitted deferred reclaim")),
            );
        } else {
            assert!(deferred.is_none());
        }
        let mut user = self.active.current_process_address_space(self.process);
        if let Some(output) = discarded {
            user.discard_owned_output(output)
                .unwrap_or_else(|_| panic!("primordial exit output pin drifted"));
        }
        if let Some(pin) = atomic_pin {
            user.release_atomic_u32(pin)
                .unwrap_or_else(|_| panic!("primordial exit atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
        NativeSyscallResult { status, control }
    }
}
