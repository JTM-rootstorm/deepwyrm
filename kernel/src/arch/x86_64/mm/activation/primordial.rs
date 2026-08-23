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
    PrimordialCompletionBackend, PrimordialExitDisposition, STACK_BYTES,
    complete_primordial_launch, construct_primordial,
};
use crate::ipc::ChannelAuthority;
use crate::memory::address_region::{
    AddressRegion, AddressRegionObjectAuthority, AddressSpaceAuthority, Protection,
};
use crate::memory::frame_roles::{ObjectBackingGrant, TableLevel};
use crate::memory::object::{MemoryObjectAuthority, MemoryProtection};
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::object::{HandleRef, InternalRef, ObjectRegistry};
use crate::sync::IrqSpinMutex;
#[cfg(feature = "test-support")]
use crate::syscall::FServiceOperationOwner;
use crate::syscall::native::{
    NativeSyscallFrameRuntime, NativeSyscallHandler, NativeSyscallRequest, NativeSyscallResult,
    SyscallControl,
};
use crate::syscall::{CleanupQueue, FServiceRoute, FServiceState, TerminalWaitCleanup};
use crate::task::{ExecutionDomain, ProcessKey, SchedulerThreadState, TaskAuthority, ThreadKey};
use crate::time::TimerAuthority;
use crate::wait::{EventAuthority, WaitRegistry};
use deepwyrm_abi::{
    DW_CHANNEL_MAX_PAYLOAD, DW_EXCEPTION_GENERAL_PROTECTION, DW_STATUS_BAD_STATE,
    DW_STATUS_NO_RESOURCES, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS, DW_TASK_STATE_EXITED,
    DW_TERMINATION_NORMAL_EXIT,
};

const MAX_BOOTFS_BYTES: usize = 32 * 1024 * 1024;
const REGISTRY_OBJECTS: usize = 32;
const MEMORY_OBJECTS: usize = 10;
const MEMORY_LEASES: usize = 10;
// I0 keeps the complete bootstrap -> init0 -> hello chain live while each
// parent performs bounded READY/exit supervision of its direct child.
const USERSPACE_CHAIN_PROCESSES: usize = 3;
const CHANNEL_PAIRS: usize = USERSPACE_CHAIN_PROCESSES;
const CHANNEL_DEPTH: usize = 2;
const WAITERS: usize = 4;
const TASK_GROUPS: usize = 1;
const PROCESSES: usize = USERSPACE_CHAIN_PROCESSES;
const THREADS: usize = USERSPACE_CHAIN_PROCESSES;
// Exact live bootstrap peak per Process: four inherited handles, one net
// ChannelCreate/rights-reduction result, Process+root, and Thread fill eight
// slots; the two reduced-right duplicates needed before the three-handle INIT
// move raise the pre-transfer peak to ten.
const INITIAL_BOOTSTRAP_HANDLES: usize = 4;
const CHANNEL_CREATE_REDUCE_NET_HANDLES: usize = 1;
const PROCESS_ROOT_HANDLES: usize = 2;
const THREAD_HANDLES: usize = 1;
const INIT_DUPLICATE_HANDLES: usize = 2;
const INIT_MOVED_HANDLES: usize = 3;
const BOOTSTRAP_HANDLE_PEAK: usize = INITIAL_BOOTSTRAP_HANDLES
    + CHANNEL_CREATE_REDUCE_NET_HANDLES
    + PROCESS_ROOT_HANDLES
    + THREAD_HANDLES
    + INIT_DUPLICATE_HANDLES;
const HANDLES: usize = BOOTSTRAP_HANDLE_PEAK;
const SPACES: usize = USERSPACE_CHAIN_PROCESSES;
const REGIONS: usize = USERSPACE_CHAIN_PROCESSES;
const REGION_OBJECTS: usize = USERSPACE_CHAIN_PROCESSES;
const REGION_SLOTS: usize = 10;
const EXECUTION_THREADS: usize = USERSPACE_CHAIN_PROCESSES;
const EVENTS: usize = 1;
const TIMERS: usize = 1;
// A bounded 16-page mapping can cross one boundary at each non-root level.
// Keep two candidates for PDPT, PD, and PT creation so the live publisher can
// construct both paths without depending on where the requested range lands.
const PRIMORDIAL_TABLE_CANDIDATES: usize = 6;
const PRIMORDIAL_MAX_MAPPING_PAGES: usize = (STACK_BYTES / PAGE_SIZE) as usize;
const PRIMORDIAL_JOURNAL_ENTRIES: usize =
    PRIMORDIAL_MAX_MAPPING_PAGES + PRIMORDIAL_TABLE_CANDIDATES;
const PRIMORDIAL_INVALIDATIONS: usize = PRIMORDIAL_MAX_MAPPING_PAGES;

// The native binding table and kernel-wide CPU identity must describe the
// same bounded carrier set; a capacity drift is a compile-time error.
const _: [(); crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] = [(); crate::cpu::CPU_CAPACITY];
const _: [(); PROCESSES] = [(); THREADS];
const _: [(); PROCESSES] = [(); CHANNEL_PAIRS];
const _: [(); PROCESSES] = [(); SPACES];
const _: [(); PROCESSES] = [(); REGIONS];
const _: [(); PROCESSES] = [(); REGION_OBJECTS];
const _: [(); PROCESSES] = [(); EXECUTION_THREADS];
const _: [(); 10] = [(); HANDLES];
const _: [(); 7] = [(); BOOTSTRAP_HANDLE_PEAK - INIT_MOVED_HANDLES];

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum G5PrimordialExpectation {
    Baseline,
    BlockingCleanup,
    UserException,
    InvalidReturn,
}

#[cfg(feature = "test-support")]
struct G5PrimordialProbe {
    expectation: G5PrimordialExpectation,
    valid: bool,
    generic_prepared_idle: bool,
    generic_poll_resumed: bool,
    generic_resumed_timed_out: bool,
    atomic_prepared_idle: bool,
    atomic_poll_resumed: bool,
    atomic_resumed_timed_out: bool,
    terminal_oracle_passed: bool,
    terminal_application_code: u32,
}

#[cfg(feature = "test-support")]
impl G5PrimordialProbe {
    fn for_build() -> Self {
        use crate::test_support::BuildGuestTest;

        let expectation = match crate::test_support::BUILD_GUEST_TEST {
            BuildGuestTest::PrimordialBootstrap => G5PrimordialExpectation::Baseline,
            BuildGuestTest::PrimordialBlockingCleanup => G5PrimordialExpectation::BlockingCleanup,
            BuildGuestTest::PrimordialUserException => G5PrimordialExpectation::UserException,
            BuildGuestTest::PrimordialInvalidReturn => G5PrimordialExpectation::InvalidReturn,
            _ => unreachable!("primordial runtime requires a primordial selector"),
        };
        Self {
            expectation,
            valid: true,
            generic_prepared_idle: false,
            generic_poll_resumed: false,
            generic_resumed_timed_out: false,
            atomic_prepared_idle: false,
            atomic_poll_resumed: false,
            atomic_resumed_timed_out: false,
            terminal_oracle_passed: false,
            terminal_application_code: 0,
        }
    }

    fn observe_prepare(
        &mut self,
        owner: Result<FServiceOperationOwner, crate::syscall::FServiceOwnerError>,
        idle_current: bool,
    ) {
        if self.expectation != G5PrimordialExpectation::BlockingCleanup {
            return;
        }
        match owner {
            Ok(FServiceOperationOwner::GenericWait) => {
                let ordered = !self.generic_prepared_idle
                    && !self.generic_poll_resumed
                    && !self.generic_resumed_timed_out
                    && !self.atomic_prepared_idle
                    && !self.atomic_poll_resumed
                    && !self.atomic_resumed_timed_out;
                self.valid &= idle_current && ordered;
                self.generic_prepared_idle = idle_current && ordered;
            }
            Ok(FServiceOperationOwner::AtomicWait) => {
                let ordered = self.generic_prepared_idle
                    && self.generic_poll_resumed
                    && self.generic_resumed_timed_out
                    && !self.atomic_prepared_idle
                    && !self.atomic_poll_resumed
                    && !self.atomic_resumed_timed_out;
                self.valid &= idle_current && ordered;
                self.atomic_prepared_idle = idle_current && ordered;
            }
            Err(_) => self.valid = false,
        }
    }

    fn observe_poll(
        &mut self,
        owner: Result<FServiceOperationOwner, crate::syscall::FServiceOwnerError>,
        resume_current: bool,
        switched: bool,
    ) {
        if self.expectation != G5PrimordialExpectation::BlockingCleanup {
            return;
        }
        match owner {
            Ok(FServiceOperationOwner::GenericWait) => {
                let ordered = self.generic_prepared_idle
                    && !self.generic_poll_resumed
                    && !self.generic_resumed_timed_out
                    && !self.atomic_prepared_idle;
                self.valid &= ordered && !switched;
                if resume_current && ordered {
                    self.generic_poll_resumed = true;
                }
            }
            Ok(FServiceOperationOwner::AtomicWait) => {
                let ordered = self.generic_resumed_timed_out
                    && self.atomic_prepared_idle
                    && !self.atomic_poll_resumed
                    && !self.atomic_resumed_timed_out;
                self.valid &= ordered && !switched;
                if resume_current && ordered {
                    self.atomic_poll_resumed = true;
                }
            }
            Err(_) => self.valid = false,
        }
    }

    fn observe_resume(
        &mut self,
        owner: Result<FServiceOperationOwner, crate::syscall::FServiceOwnerError>,
        status: deepwyrm_abi::DwStatus,
    ) {
        if self.expectation != G5PrimordialExpectation::BlockingCleanup {
            return;
        }
        match owner {
            Ok(FServiceOperationOwner::GenericWait) => {
                let ordered = self.generic_poll_resumed
                    && !self.generic_resumed_timed_out
                    && !self.atomic_prepared_idle;
                self.valid &= ordered && status == deepwyrm_abi::DW_STATUS_TIMED_OUT;
                self.generic_resumed_timed_out =
                    ordered && status == deepwyrm_abi::DW_STATUS_TIMED_OUT;
            }
            Ok(FServiceOperationOwner::AtomicWait) => {
                let ordered = self.generic_resumed_timed_out
                    && self.atomic_poll_resumed
                    && !self.atomic_resumed_timed_out;
                self.valid &= ordered && status == deepwyrm_abi::DW_STATUS_TIMED_OUT;
                self.atomic_resumed_timed_out =
                    ordered && status == deepwyrm_abi::DW_STATUS_TIMED_OUT;
            }
            Err(_) => self.valid = false,
        }
    }

    fn observe_terminal(&mut self, info: deepwyrm_abi::DwTaskTerminationInfoV1) {
        self.terminal_application_code = info.application_code;
        let (exception_type, detail) = match self.expectation {
            G5PrimordialExpectation::UserException => {
                (deepwyrm_abi::DW_EXCEPTION_ILLEGAL_INSTRUCTION, 6)
            }
            G5PrimordialExpectation::InvalidReturn => {
                (deepwyrm_abi::DW_EXCEPTION_GENERAL_PROTECTION, 1)
            }
            G5PrimordialExpectation::Baseline | G5PrimordialExpectation::BlockingCleanup => return,
        };
        self.terminal_oracle_passed = info
            == deepwyrm_abi::DwTaskTerminationInfoV1 {
                size: deepwyrm_abi::DW_TASK_TERMINATION_INFO_V1_SIZE,
                version: 1,
                state: deepwyrm_abi::DW_TASK_STATE_EXITED,
                reason: deepwyrm_abi::DW_TERMINATION_UNHANDLED_EXCEPTION,
                application_code: 0,
                exception_type,
                detail,
                reserved0: 0,
                fault_address: 0,
                reserved: [0; 3],
            };
    }

    fn accepts_completion(
        &self,
        completion: &Result<
            (),
            crate::boot::primordial::construction::PrimordialCompletionError<()>,
        >,
    ) -> bool {
        use crate::boot::primordial::construction::PrimordialCompletionError;

        match self.expectation {
            G5PrimordialExpectation::Baseline => completion == &Ok(()),
            G5PrimordialExpectation::BlockingCleanup => {
                self.valid
                    && self.generic_prepared_idle
                    && self.generic_poll_resumed
                    && self.generic_resumed_timed_out
                    && self.atomic_prepared_idle
                    && self.atomic_poll_resumed
                    && self.atomic_resumed_timed_out
                    && completion == &Ok(())
            }
            G5PrimordialExpectation::UserException | G5PrimordialExpectation::InvalidReturn => {
                self.terminal_oracle_passed
                    && completion == &Err(PrimordialCompletionError::UnhandledException)
            }
        }
    }

    fn failure_detail(
        &self,
        completion: &Result<
            (),
            crate::boot::primordial::construction::PrimordialCompletionError<()>,
        >,
    ) -> u32 {
        if self.terminal_application_code != 0 {
            return self.terminal_application_code;
        }
        match completion {
            Err(crate::boot::primordial::construction::PrimordialCompletionError::NonzeroExit(
                code,
            )) => *code,
            _ => 1,
        }
    }
}

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

/// Stationary authorities whose own bounded synchronization already permits
/// shared access without a broad native-runtime guard.
struct PrimordialRuntimeShared {
    execution: ExecutionDomain<EXECUTION_THREADS>,
    channels: Channels,
    events: EventAuthority<EVENTS>,
    timers: TimerAuthority<TIMERS>,
    waits: WaitRegistry<WAITERS>,
}

impl crate::time::DeadlineWakeTarget for PrimordialRuntimeShared {
    fn wake_deadline(&self, key: crate::task::BlockWakeKey) {
        crate::wait::engine::claim_timeout_and_wake(&self.execution, key)
            .unwrap_or_else(|error| panic!("primordial deadline wake drifted: {error:?}"));
    }
}

struct SharedRuntimeStorage(UnsafeCell<MaybeUninit<PrimordialRuntimeShared>>);

impl SharedRuntimeStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

// SAFETY: the one-shot BSP writes the complete shared object before Release
// publication. Every published field provides its own bounded synchronization;
// the storage cell itself is never mutably accessed again.
unsafe impl Sync for SharedRuntimeStorage {}

static SHARED_RUNTIME_STATE: AtomicU8 = AtomicU8::new(0);
static SHARED_RUNTIME_STORAGE: SharedRuntimeStorage = SharedRuntimeStorage::new();
static STATIONARY_GUARD_DEPTH: crate::arch::x86_64::syscall::StationaryGuardDepth =
    crate::arch::x86_64::syscall::StationaryGuardDepth::new();

/// Fixed CPU-local façade over the stationary runtime authorities.
///
/// It is bound before AP release but deliberately has no execution path until
/// the serialized H2 join can prove remote-stop and shootdown acknowledgements.
/// The syscall binding lifecycle, rather than a replaceable callback pointer,
/// is the one-way Parked -> Executing gate.
/// Fixed CPU-local carrier storage.  BSP currently enters through the richer
/// primordial adapter, while parked AP bindings dispatch directly to this
/// fail-closed carrier.  Both paths name the same one-per-slot stationary
/// storage entry; no AP can borrow BSP-local state.
struct PerCpuLiveCarrier {
    cpu: crate::cpu::CpuIndex,
    staging_slot: usize,
    local: IrqSpinMutex<PerCpuCarrierLocal>,
    _shared: &'static PrimordialRuntimeShared,
}

#[derive(Clone, Copy)]
struct PerCpuCarrierLocal {
    current_thread: Option<ThreadKey>,
    current_stack: Option<crate::task::KernelStackId>,
    current_context: Option<crate::task::ThreadContextId>,
    scratch_cpu: crate::cpu::CpuIndex,
    reaper_staged: bool,
}

impl PerCpuLiveCarrier {
    fn record_current(
        &self,
        thread: ThreadKey,
        stack: crate::task::KernelStackId,
        context: crate::task::ThreadContextId,
    ) {
        let mut local = self.local.lock();
        assert_eq!(local.scratch_cpu, self.cpu, "carrier scratch CPU drifted");
        assert!(
            !local.reaper_staged,
            "reaper-staged carrier cannot resume a Thread"
        );
        local.current_thread = Some(thread);
        local.current_stack = Some(stack);
        local.current_context = Some(context);
    }

    fn reject_entry(&self, operation: &'static str) -> ! {
        assert_eq!(
            self.staging_slot,
            self.cpu.index(),
            "carrier staging slot drifted"
        );
        panic!(
            "parked CPU {} reached forbidden native-runtime operation {operation}",
            self.cpu.index()
        )
    }
}

struct RuntimeCarrierStorage(
    UnsafeCell<[MaybeUninit<PerCpuLiveCarrier>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT]>,
);

impl RuntimeCarrierStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(
            [const { MaybeUninit::uninit() }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
        ))
    }
}

// SAFETY: the BSP initializes each discovered AP slot exactly once, publishes
// its address into that CPU's runtime binding, and never exposes the backing
// cell again. Parked carriers never return from a callback or touch shared
// mutable subsystem state.
unsafe impl Sync for RuntimeCarrierStorage {}

static RUNTIME_CARRIER_STATE: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { AtomicU8::new(0) }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static RUNTIME_CARRIER_STORAGE: RuntimeCarrierStorage = RuntimeCarrierStorage::new();

struct ChannelStaging(UnsafeCell<[u8; DW_CHANNEL_MAX_PAYLOAD as usize]>);

// SAFETY: one runtime CPU slot claims each buffer before userspace starts; no
// other carrier can receive the same buffer and each carrier serializes its
// own use while executing on that CPU.
unsafe impl Sync for ChannelStaging {}

static CHANNEL_STAGING_STATE: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { AtomicU8::new(0) }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static CHANNEL_STAGING: [ChannelStaging; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { ChannelStaging(UnsafeCell::new([0; DW_CHANNEL_MAX_PAYLOAD as usize])) };
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];

fn publish_runtime_shared() -> &'static PrimordialRuntimeShared {
    SHARED_RUNTIME_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|_| panic!("primordial shared runtime was initialized twice"));
    let stacks = crate::arch::x86_64::linked_thread_kernel_stack_layout()
        .unwrap_or_else(|error| panic!("invalid primordial kernel stack layout: {error:?}"));
    let execution =
        ExecutionDomain::<EXECUTION_THREADS>::new(core::array::from_fn(|index| stacks[index]))
            .unwrap_or_else(|error| panic!("invalid primordial execution domain: {error:?}"));
    unsafe {
        (*SHARED_RUNTIME_STORAGE.0.get()).write(PrimordialRuntimeShared {
            execution,
            channels: Channels::new(),
            events: EventAuthority::new(),
            timers: TimerAuthority::new(),
            waits: WaitRegistry::new(),
        });
    }
    SHARED_RUNTIME_STATE.store(2, Ordering::Release);
    let target = unsafe { &*(*SHARED_RUNTIME_STORAGE.0.get()).as_ptr() };
    crate::time::bind_deadline_wake_target(target)
        .unwrap_or_else(|error| panic!("could not bind primordial deadline wakes: {error:?}"));
    target
}

fn initialize_per_cpu_live_carriers(shared: &'static PrimordialRuntimeShared) {
    for cpu_index in 0..crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT {
        let cpu = crate::cpu::CpuIndex::new(cpu_index)
            .unwrap_or_else(|| panic!("CPU {cpu_index} exceeds the native carrier bound"));
        RUNTIME_CARRIER_STATE[cpu_index]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|_| panic!("CPU {cpu_index} native carrier was initialized twice"));
        unsafe {
            let slots = &mut *RUNTIME_CARRIER_STORAGE.0.get();
            slots[cpu_index].write(PerCpuLiveCarrier {
                cpu,
                staging_slot: cpu_index,
                local: IrqSpinMutex::new(PerCpuCarrierLocal {
                    current_thread: None,
                    current_stack: None,
                    current_context: None,
                    scratch_cpu: cpu,
                    reaper_staged: false,
                }),
                _shared: shared,
            });
        }
        RUNTIME_CARRIER_STATE[cpu_index].store(2, Ordering::Release);
    }
}

fn per_cpu_live_carrier(cpu: crate::cpu::CpuIndex) -> &'static PerCpuLiveCarrier {
    let index = cpu.index();
    if RUNTIME_CARRIER_STATE
        .get(index)
        .is_none_or(|state| state.load(Ordering::Acquire) != 2)
    {
        panic!("CPU {index} native carrier storage is unavailable");
    }
    unsafe { &*(*RUNTIME_CARRIER_STORAGE.0.get())[index].as_ptr() }
}

#[allow(
    unsafe_code,
    reason = "each parked AP receives exactly one one-shot binding to its own initialized carrier cell"
)]
unsafe fn pin_per_cpu_live_carrier(
    cpu: crate::cpu::CpuIndex,
) -> core::pin::Pin<&'static mut PerCpuLiveCarrier> {
    let index = cpu.index();
    if RUNTIME_CARRIER_STATE
        .get(index)
        .is_none_or(|state| state.load(Ordering::Acquire) != 2)
    {
        panic!("CPU {index} native carrier storage is unavailable");
    }
    let slots = unsafe { &mut *RUNTIME_CARRIER_STORAGE.0.get() };
    unsafe { core::pin::Pin::new_unchecked(&mut *slots[index].as_mut_ptr()) }
}

fn bind_parked_ap_runtime_carriers() {
    let registry = crate::arch::x86_64::smp::live_cpu_registry();
    for cpu_index in 1..registry.len() {
        let snapshot = registry
            .snapshot(cpu_index)
            .unwrap_or_else(|error| panic!("could not inspect AP {cpu_index}: {error:?}"));
        if snapshot.lifecycle != crate::arch::x86_64::smp::CpuLifecycle::Parked {
            panic!("AP {cpu_index} was not parked before native carrier binding");
        }
        let cpu = crate::cpu::CpuIndex::new(cpu_index)
            .unwrap_or_else(|| panic!("AP {cpu_index} exceeds the native carrier bound"));
        let carrier = unsafe { pin_per_cpu_live_carrier(cpu) };
        unsafe { crate::arch::x86_64::syscall::bind_native_runtime_carrier_for_slot(cpu, carrier) }
            .unwrap_or_else(|error| {
                panic!("could not bind AP {cpu_index} native carrier: {error:?}")
            });
    }
}

impl NativeSyscallHandler for PerCpuLiveCarrier {
    fn handle(&mut self, _request: NativeSyscallRequest) -> NativeSyscallResult {
        self.reject_entry("syscall dispatch")
    }
}

impl crate::syscall::native::NativeRendezvousRuntime for PerCpuLiveCarrier {
    fn rendezvous_stop(
        &mut self,
        _request: crate::arch::x86_64::rendezvous::StopRequest,
        _reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> ! {
        self.reject_entry("rendezvous stop reaper")
    }
}

#[allow(
    unsafe_code,
    reason = "the bound AP façade is deliberately fail-closed until the serialized scheduler/live runtime join releases it"
)]
impl NativeSyscallFrameRuntime for PerCpuLiveCarrier {
    fn authorize_return(
        &mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        _current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        self.reject_entry("user-return authorization")
    }

    fn invalid_return(&mut self, _error: crate::arch::x86_64::syscall::UserReturnError) {
        self.reject_entry("invalid user return")
    }

    fn user_exception(&mut self, _record: crate::arch::x86_64::exceptions::UserExceptionRecord) {
        self.reject_entry("userspace exception")
    }

    fn terminate_current(&mut self) -> ! {
        self.reject_entry("terminal reclaim")
    }

    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        self.reject_entry("fresh userspace entry")
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan<'owner> {
        self.reject_entry("suspend preparation")
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'owner> {
        self.reject_entry("idle-suspend polling")
    }

    fn resume_suspended(&mut self, _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame) {
        self.reject_entry("suspended syscall resume")
    }
}

fn take_channel_staging(cpu_index: usize) -> &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize] {
    let state = CHANNEL_STAGING_STATE
        .get(cpu_index)
        .unwrap_or_else(|| panic!("invalid primordial Channel staging CPU slot"));
    let staging = CHANNEL_STAGING
        .get(cpu_index)
        .unwrap_or_else(|| panic!("invalid primordial Channel staging CPU slot"));
    state
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|_| panic!("primordial Channel staging CPU slot was claimed twice"));
    unsafe { &mut *staging.0.get() }
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
        match self.active.target.roles.assign_object_backing(zeroed) {
            Ok(backing) => Ok(backing),
            Err(failure) => {
                self.active
                    .target
                    .roles
                    .cancel_zeroed(failure.into_grant())
                    .unwrap_or_else(|_| panic!("primordial zeroed-backing rollback drifted"));
                Err(user_access::LiveUserAccessError::MissingOrInvalid)
            }
        }
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
        match self
            .active
            .target
            .roles
            .prepare_table(zeroed, self.active.identity.owner(), level)
        {
            Ok(candidate) => Ok(candidate),
            Err(failure) => {
                self.active
                    .target
                    .roles
                    .cancel_zeroed(failure.into_grant())
                    .unwrap_or_else(|_| panic!("primordial zeroed-table rollback drifted"));
                Err(user_access::LiveUserAccessError::MissingOrInvalid)
            }
        }
    }

    fn unmap_committed<
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
    ) -> crate::memory::object::MappingFinalReleases<REGISTRY> {
        let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
        let result = {
            let target = &mut self.active.target;
            let mut tracked = user_access::TrackedActiveTarget {
                scratch: &mut target.scratch,
                pins: &self.active.user_pins,
                address_space: region.address_space_key(),
            };
            let mut publisher = unsafe {
                crate::arch::x86_64::mm::X86AddressSpacePublisher::<
                    _,
                    RANGE_CAPACITY,
                    ROLE_CAPACITY,
                    PRIMORDIAL_TABLE_CANDIDATES,
                    PRIMORDIAL_JOURNAL_ENTRIES,
                    PRIMORDIAL_INVALIDATIONS,
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
            .unwrap_or_else(|_| panic!("primordial teardown publisher unavailable"));
            region.unmap(memory, registry, &mut publisher, virtual_start, byte_len)
        };
        for candidate in candidates.into_iter().flatten() {
            self.active
                .target
                .roles
                .cancel_table_candidate(candidate)
                .unwrap_or_else(|_| panic!("primordial teardown table reclaim drifted"));
        }
        result.unwrap_or_else(|failure| {
            panic!(
                "primordial live mapping teardown diverged: {:?}",
                failure.error()
            )
        })
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
        let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
        let result = (|| {
            // At most two hierarchy paths are needed for the bounded initial
            // stack mapping: it may cross a PDPT, PD, and PT boundary.
            candidates[0] = Some(self.prepare_candidate(TableLevel::Pdpt)?);
            candidates[1] = Some(self.prepare_candidate(TableLevel::Pd)?);
            candidates[2] = Some(self.prepare_candidate(TableLevel::Pt)?);
            candidates[3] = Some(self.prepare_candidate(TableLevel::Pdpt)?);
            candidates[4] = Some(self.prepare_candidate(TableLevel::Pd)?);
            candidates[5] = Some(self.prepare_candidate(TableLevel::Pt)?);

            let target = &mut self.active.target;
            let mut tracked = user_access::TrackedActiveTarget {
                scratch: &mut target.scratch,
                pins: &self.active.user_pins,
                address_space: region.address_space_key(),
            };
            let mut publisher = unsafe {
                crate::arch::x86_64::mm::X86AddressSpacePublisher::<
                    _,
                    RANGE_CAPACITY,
                    ROLE_CAPACITY,
                    PRIMORDIAL_TABLE_CANDIDATES,
                    PRIMORDIAL_JOURNAL_ENTRIES,
                    PRIMORDIAL_INVALIDATIONS,
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
            match region.map(
                memory,
                registry,
                &mut publisher,
                virtual_start,
                authorization,
                0,
                byte_len,
                protection,
            ) {
                Ok(releases) => {
                    assert!(
                        releases.is_empty(),
                        "primordial map unexpectedly finalized live backing"
                    );
                    Ok(())
                }
                Err(failure) => {
                    let (error, releases) = failure.into_parts();
                    assert!(
                        releases.is_empty(),
                        "primordial map rollback unexpectedly finalized live backing"
                    );
                    match error {
                        crate::memory::address_region::AddressSpaceTransactionError::Model(
                            error,
                        ) => Err(user_access::LiveUserAccessError::MapModel(error)),
                        crate::memory::address_region::AddressSpaceTransactionError::Publish(
                            error,
                        ) => Err(user_access::LiveUserAccessError::MapPublish(error)),
                    }
                }
            }
        })();
        for candidate in candidates.into_iter().flatten() {
            self.active
                .target
                .roles
                .cancel_table_candidate(candidate)
                .unwrap_or_else(|_| panic!("primordial unused table rollback drifted"));
        }
        result
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
        assert!(
            self.unmap_committed(region, memory, registry, virtual_start, byte_len)
                .is_empty(),
            "primordial live mapping rollback finalized backing still owned by construction"
        );
    }
}

/// BSP execution carrier. Plain mutable authorities remain exclusively owned
/// here because their adapter surfaces do not yet provide transactional
/// interior synchronization. AP carriers cannot name or borrow this state.
enum CarrierActiveRoot {
    Process(super::ActiveRootSelection),
    StopPrecommitted(super::ActiveRootSelection),
    Kernel(super::ActiveKernelExecutionRoot),
    Transitioning,
}

impl CarrierActiveRoot {
    fn as_ref(&self) -> Option<&super::ActiveRootSelection> {
        match self {
            Self::Process(root) => Some(root),
            Self::StopPrecommitted(_) | Self::Kernel(_) | Self::Transitioning => None,
        }
    }

    fn take_process(&mut self) -> super::ActiveRootSelection {
        match core::mem::replace(self, Self::Transitioning) {
            Self::Process(root) => root,
            Self::StopPrecommitted(_) | Self::Kernel(_) | Self::Transitioning => {
                panic!("carrier has no active Process root")
            }
        }
    }
}

struct PrimordialRuntimeCarrier<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    cpu: crate::cpu::CpuIndex,
    local: &'static PerCpuLiveCarrier,
    active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    active_root: CarrierActiveRoot,
    stopping_claim: Option<crate::task::SchedulerExecutionClaim>,
    stopping_claim_was_suspended: bool,
    rendezvous_reaper: Option<crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry>,
    registry: Registry,
    memory: Memory,
    tasks: Tasks,
    shared: &'static PrimordialRuntimeShared,
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
    primordial_process: ProcessKey,
    primordial_root_key: crate::memory::address_region::AddressRegionObjectKey,
    primordial_address_space: crate::memory::address_region::AddressSpaceKey,
    channel_keys: [crate::ipc::ChannelEndpointKey; 2],
    kernel_peer: Option<HandleRef>,
    process_monitor: Option<HandleRef>,
    root_owner: Option<InternalRef>,
    deferred_current: Option<crate::task::DeferredCurrentExecutionResources>,
    cleanup: CleanupQueue<REGISTRY_OBJECTS>,
    // Pending final releases are moved before the irreversible stop commit.
    // They are drained only by the post-ack kernel-root continuation.
    rendezvous_cleanup: Option<CleanupQueue<REGISTRY_OBJECTS>>,
    #[cfg(feature = "test-support")]
    g5_probe: G5PrimordialProbe,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::MemoryObjectBackingAccess
    for user_access::LiveProcessAddressSpace<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, deepwyrm_abi::DwStatus> {
        user_access::LiveProcessAddressSpace::allocate_zeroed_backing(self, page_count)
            .map_err(|_| DW_STATUS_NO_RESOURCES)
    }

    fn rollback_object_backing(&mut self, backing: ObjectBackingGrant) {
        self.roles
            .cancel_object_backing(backing)
            .unwrap_or_else(|_| panic!("live MemoryObject backing rollback drifted"));
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> crate::syscall::ProcessRootReservation
    for user_access::LiveProcessAddressSpace<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn reserve_child_root(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), deepwyrm_abi::DwStatus> {
        self.reserve_child_address_space(process, address_space)
            .map_err(|error| match error {
                super::RootBindingError::Capacity
                | super::RootBindingError::FrameRole(
                    crate::memory::frame_roles::FrameRoleError::Capacity,
                ) => DW_STATUS_NO_RESOURCES,
                _ => DW_STATUS_BAD_STATE,
            })
    }

    fn rollback_empty_child_root(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) {
        self.rollback_empty_child_address_space(process, address_space)
            .unwrap_or_else(|error| panic!("empty child-root rollback drifted: {error:?}"));
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::ThreadStartMappingAccess
    for user_access::LiveProcessAddressSpace<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn select_process_for_return_validation(
        &mut self,
        process: ProcessKey,
    ) -> Result<(), deepwyrm_abi::DwStatus> {
        user_access::LiveProcessAddressSpace::select_process_for_return_validation(self, process)
            .map_err(|_| DW_STATUS_BAD_STATE)
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn reserve_runtime_phase(&self) -> crate::arch::x86_64::syscall::RuntimePhaseReservation {
        let root = self
            .active_root
            .as_ref()
            .unwrap_or_else(|| panic!("runtime phase requires an active Process root"));
        crate::arch::x86_64::syscall::RuntimePhaseReservation::new(
            self.thread,
            root.binding_generation(),
        )
        .unwrap_or_else(|_| panic!("runtime phase has an invalid exact root generation"))
    }

    fn commit_runtime_phase(&self, phase: crate::arch::x86_64::syscall::RuntimePhaseReservation) {
        let root = self
            .active_root
            .as_ref()
            .unwrap_or_else(|| panic!("runtime phase lost its active Process root"));
        phase
            .revalidate(self.thread, root.binding_generation())
            .unwrap_or_else(|_| panic!("runtime phase identity drifted across guard-free work"));
    }

    fn assert_guard_free_external_work(&self) {
        STATIONARY_GUARD_DEPTH.assert_clear_on(self.cpu);
    }

    fn synchronize_scheduler_current(&mut self) {
        assert_eq!(self.local.cpu, self.cpu, "BSP carrier storage CPU drifted");
        let thread = self
            .shared
            .execution
            .current_thread_on(self.cpu)
            .unwrap_or_else(|| panic!("runtime carrier has no scheduler-current Thread"));
        let process = self
            .tasks
            .thread_process(thread)
            .unwrap_or_else(|error| panic!("scheduler-current Thread lost its Process: {error:?}"));
        let root_object = self
            .tasks
            .root_region(process)
            .unwrap_or_else(|error| {
                panic!("scheduler-current Process root lookup failed: {error:?}")
            })
            .unwrap_or_else(|| panic!("scheduler-current Process has no root AddressRegion"));
        let root_key =
            crate::memory::address_region::AddressRegionObjectKey::from_object_id(root_object);
        let address_space = self
            .regions
            .region(root_key)
            .unwrap_or_else(|error| panic!("scheduler-current root is unavailable: {error:?}"))
            .address_space_key();
        let (stack_id, context_id) = self
            .tasks
            .thread_execution_resources(thread)
            .unwrap_or_else(|error| panic!("scheduler-current resources failed: {error:?}"))
            .unwrap_or_else(|| panic!("scheduler-current Thread has no execution resources"));
        if process == self.process
            && root_key == self.root_key
            && self
                .active_root
                .as_ref()
                .is_some_and(|root| root.selects_exact(self.cpu, process, address_space))
        {
            self.active
                .validate_current_process_root_selection(
                    self.active_root.as_ref().expect("active root"),
                    process,
                    address_space,
                )
                .unwrap_or_else(|error| {
                    panic!("retained scheduler-current root is not physically active: {error:?}")
                });
            // A sibling Thread in the same Process retains the unique root
            // selection token and changes only scheduler-owned execution
            // identity. Re-activating the same address space would violate
            // the residency protocol with AlreadyActive.
            self.thread = thread;
            self.stack_id = stack_id;
            self.context_id = context_id;
            self.local.record_current(thread, stack_id, context_id);
            return;
        }
        let prepared = self
            .active
            .prepare_process_root_selection(self.cpu, process, address_space)
            .unwrap_or_else(|error| panic!("could not prepare scheduler-current root: {error:?}"));
        let previous = core::mem::replace(&mut self.active_root, CarrierActiveRoot::Transitioning);
        let selected = match previous {
            CarrierActiveRoot::Process(previous) => match self
                .active
                .activate_process_root_selection(prepared, Some(previous))
            {
                Ok(selected) => selected,
                Err(failure) => {
                    let (error, prepared, previous) = failure.into_parts();
                    self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!("failed root selection could not be abandoned: {abandon:?}")
                        });
                    self.active_root = CarrierActiveRoot::Process(previous.unwrap_or_else(|| {
                        panic!("runtime carrier lost its Process root during activation rollback")
                    }));
                    panic!("could not activate scheduler-current root: {error:?}");
                }
            },
            CarrierActiveRoot::Kernel(previous) => match self
                .active
                .activate_from_kernel_execution_root(prepared, previous)
            {
                Ok(selected) => selected,
                Err(failure) => {
                    let (error, prepared, previous) = failure.into_parts();
                    self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!(
                                "failed kernel-root selection could not be abandoned: {abandon:?}"
                            )
                        });
                    self.active_root = CarrierActiveRoot::Kernel(previous);
                    panic!("could not activate scheduler-current root from kernel root: {error:?}");
                }
            },
            CarrierActiveRoot::StopPrecommitted(_) | CarrierActiveRoot::Transitioning => {
                panic!("runtime carrier has no stable root while selecting scheduler current")
            }
        };
        // Publish the carrier identity only after CR3/residency selection is
        // complete. No usercopy can observe a mixed Process/root tuple.
        self.process = process;
        self.thread = thread;
        self.root_key = root_key;
        self.stack_id = stack_id;
        self.context_id = context_id;
        self.active_root = CarrierActiveRoot::Process(selected);
        self.local.record_current(thread, stack_id, context_id);
    }

    fn merge_cleanup(&mut self, cleanup: CleanupQueue<REGISTRY_OBJECTS>) {
        for release in cleanup.into_releases().into_iter().flatten() {
            self.cleanup.push(release);
        }
    }

    fn stage_rendezvous_cleanup(&mut self) {
        assert!(
            self.rendezvous_cleanup.is_none(),
            "remote stop staged cleanup twice"
        );
        self.rendezvous_cleanup = Some(core::mem::replace(&mut self.cleanup, CleanupQueue::new()));
    }

    /// Moves a suspended F-service operation out of the stopped carrier before
    /// the Process root is released. e1 delivery after block commit has no
    /// Running claim, but it still owns exact wait/output/atomic cleanup that
    /// cannot be left to trip the post-commit quiescence check.
    fn transfer_suspended_service_cleanup_for_stop(&mut self) {
        if self.services.is_quiescent() {
            return;
        }
        let mut discarded = None;
        let mut atomic_pin = None;
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        {
            let mut terminal = self.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded.replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pin.replace(pin).is_none());
                },
            );
            terminal.cleanup_terminal_wait(
                &mut self.registry,
                &mut self.tasks,
                &self.shared.waits,
                &self.shared.execution,
                self.thread,
                &mut self.cleanup,
            );
        }
        let mut user = self.active.current_process_address_space(
            self.active_root.as_ref().expect("active Process root"),
            self.process,
        );
        if let Some(output) = discarded {
            user.discard_owned_output(output)
                .unwrap_or_else(|_| panic!("rendezvous suspended output pin drifted"));
        }
        if let Some(pin) = atomic_pin {
            user.release_atomic_u32(pin)
                .unwrap_or_else(|_| panic!("rendezvous suspended atomic pin drifted"));
        }
        self.merge_cleanup(self.services.take_cleanup());
    }

    fn drain_staged_rendezvous_cleanup(&mut self) {
        let cleanup = self
            .rendezvous_cleanup
            .take()
            .unwrap_or_else(|| panic!("post-ack carrier omitted staged cleanup"));
        self.merge_cleanup(cleanup);
        self.drain_finalizers()
            .unwrap_or_else(|_| panic!("post-ack rendezvous cleanup drifted"));
    }

    /// Continues only after the remote-stop mailbox Release acknowledgement.
    /// The stopped Thread remains deferred in the scheduler/reaper ownership
    /// graph; this carrier may select a different Runnable Thread or idle on
    /// its retained kernel root, but it must never consume the stopped IPI
    /// frame or reclaim resources still held by the initiator's exact ack.
    fn continue_after_rendezvous_stop(&mut self) -> ! {
        let stopped_claim = self
            .stopping_claim
            .take()
            .unwrap_or_else(|| panic!("rendezvous continuation lost its stopped claim"));
        // The exact-safe acknowledgement has already been Release-published.
        // We may now abandon the CPU-local retired continuation slot, but not
        // reclaim the stopped task/root/stack: that remains initiator-gated.
        self.shared
            .execution
            .complete_switch_on(stopped_claim)
            .unwrap_or_else(|error| {
                panic!("rendezvous continuation could not clear retired slot: {error:?}")
            });
        self.drain_staged_rendezvous_cleanup();
        let next = self.shared.execution.terminal_reaper_next_on(self.cpu);
        let Some(next) = next else {
            self.idle_after_rendezvous_stop()
        };
        self.enter_rendezvous_replacement(next)
    }

    /// Enters an exact Runnable replacement selected after the stopped frame
    /// has been irreversibly abandoned. This is also used by kernel-root idle
    /// after a late Wake; it never consumes or returns through that frame.
    fn enter_rendezvous_replacement(&mut self, next: ThreadKey) -> ! {
        let (stack_id, context_id) = self
            .tasks
            .thread_execution_resources(next)
            .unwrap_or_else(|error| panic!("rendezvous replacement resources failed: {error:?}"))
            .unwrap_or_else(|| panic!("rendezvous replacement Thread has no execution resources"));
        let stack = self
            .shared
            .execution
            .stack_bounds(stack_id)
            .unwrap_or_else(|error| panic!("rendezvous replacement stack failed: {error:?}"));
        let continuation = self
            .shared
            .execution
            .kernel_continuation_rsp(context_id)
            .unwrap_or_else(|error| {
                panic!("rendezvous replacement continuation failed: {error:?}")
            });
        // This switches Kernel -> Process exactly once if replacement work is
        // available. It performs no usercopy while the kernel-root state is
        // live and returns only after the target CR3 serialization.
        self.synchronize_scheduler_current();
        unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }.unwrap_or_else(
            |error| panic!("rendezvous replacement stack binding failed: {error:?}"),
        );
        let continuation = if continuation == 0 {
            unsafe {
                crate::arch::x86_64::context::prepare_initial_kernel_continuation(
                    stack,
                    crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
                )
            }
            .unwrap_or_else(|error| {
                panic!("rendezvous fresh continuation preparation failed: {error:?}")
            })
            .rsp()
        } else {
            continuation
        };
        crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(|error| {
            panic!("rendezvous replacement syscall boundary drifted: {error:?}")
        });
        unsafe { crate::arch::x86_64::context::abandon_to_kernel_continuation(continuation) }
    }

    fn idle_after_rendezvous_stop(&mut self) -> ! {
        assert!(matches!(self.active_root, CarrierActiveRoot::Kernel(_)));
        loop {
            let idle = crate::arch::x86_64::idle::prepare_current_idle().unwrap_or_else(|error| {
                panic!("rendezvous kernel-root idle preparation failed: {error:?}")
            });
            match crate::arch::x86_64::idle::commit_current_idle(idle) {
                Ok(halt) => {
                    #[allow(
                        unsafe_code,
                        reason = "the committed idle transition owns the CPU-local kernel-root carrier and brackets the only sti;hlt boundary"
                    )]
                    unsafe {
                        core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
                    }
                    crate::arch::x86_64::idle::finish_current_idle(halt).unwrap_or_else(|error| {
                        panic!("rendezvous kernel-root idle completion failed: {error:?}")
                    });
                    match crate::time::service_current_rendezvous_latch()
                        .unwrap_or_else(|_| panic!("rendezvous kernel-root idle latch failed"))
                    {
                        crate::arch::x86_64::rendezvous::MailboxNotification::None => {}
                        crate::arch::x86_64::rendezvous::MailboxNotification::Wake => {
                            if let Some(next) =
                                self.shared.execution.terminal_reaper_next_on(self.cpu)
                            {
                                self.enter_rendezvous_replacement(next);
                            }
                        }
                        crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {
                            // A late duplicate e1 observes the exact safe
                            // acknowledgement still held by its initiator.
                            // Stay on the kernel root and rescan; no stopped
                            // IPI frame exists to return through and no second
                            // acknowledgement may be published.
                        }
                        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_) => {
                            panic!("stopped kernel-root carrier received a second stop request")
                        }
                    }
                }
                Err(failure)
                    if failure.error()
                        == crate::arch::x86_64::idle::IdleWakeError::RescanRequired =>
                {
                    crate::arch::x86_64::idle::cancel_current_idle(failure.into_preparation())
                        .unwrap_or_else(|error| {
                            panic!("rendezvous kernel-root idle cancellation failed: {error:?}")
                        });
                    // An interrupt that completed EOI before the final idle
                    // commit must be consumed here. Merely cancelling leaves
                    // the latch set and turns every following commit into a
                    // permanent RescanRequired spin.
                    match crate::time::service_current_rendezvous_latch()
                        .unwrap_or_else(|_| panic!("rendezvous kernel-root rescan latch failed"))
                    {
                        crate::arch::x86_64::rendezvous::MailboxNotification::None => {}
                        crate::arch::x86_64::rendezvous::MailboxNotification::Wake => {
                            if let Some(next) =
                                self.shared.execution.terminal_reaper_next_on(self.cpu)
                            {
                                self.enter_rendezvous_replacement(next);
                            }
                        }
                        crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {}
                        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_) => {
                            panic!("stopped kernel-root carrier received a second stop request")
                        }
                    }
                }
                Err(failure) => panic!(
                    "rendezvous kernel-root idle commit failed: {:?}",
                    failure.error()
                ),
            }
        }
    }

    fn terminate_exception(&mut self, exception: crate::task::TaskExceptionRecord) {
        assert!(
            self.deferred_current.is_none(),
            "primordial runtime already owns deferred current resources"
        );
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
            crate::syscall::process_unhandled_exception(
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.process,
                self.thread,
                exception,
                &mut self.cleanup,
            )
        };
        assert_eq!(status, DW_STATUS_SUCCESS);
        assert_eq!(control, SyscallControl::TerminateCurrent);
        self.deferred_current =
            Some(deferred.expect("primordial exception omitted deferred current resources"));
        let mut user = self.active.current_process_address_space(
            self.active_root.as_ref().expect("active root"),
            self.process,
        );
        if let Some(output) = discarded {
            user.discard_owned_output(output)
                .unwrap_or_else(|_| panic!("primordial exception output pin drifted"));
        }
        if let Some(pin) = atomic_pin {
            user.release_atomic_u32(pin)
                .unwrap_or_else(|_| panic!("primordial exception atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
    }

    fn unmap_primordial_userspace(
        &mut self,
        proof: &crate::task::ProcessQuiescenceProof,
    ) -> Result<(), ()> {
        self.active
            .validate_current_process_root_selection(
                self.active_root.as_ref().ok_or(())?,
                self.primordial_process,
                self.primordial_address_space,
            )
            .map_err(|_| ())?;
        if self.process != self.primordial_process || self.root_key != self.primordial_root_key {
            return Err(());
        }
        loop {
            let mapping = self
                .regions
                .region(self.root_key)
                .map_err(|_| ())?
                .mappings()
                .iter()
                .flatten()
                .next()
                .copied();
            let Some(mapping) = mapping else {
                break;
            };
            let releases = {
                let region = self
                    .regions
                    .region_mut_for_quiesced_teardown(&self.tasks, proof, self.root_key)
                    .map_err(|_| ())?;
                let mut platform = LivePlatform {
                    active: &mut self.active,
                };
                platform.unmap_committed(
                    region,
                    &mut self.memory,
                    &mut self.registry,
                    mapping.virtual_start(),
                    mapping.byte_len(),
                )
            };
            for release in releases.into_items().into_iter().flatten() {
                self.cleanup.push(release);
            }
        }
        Ok(())
    }

    /// Removes every low-half mapping from an exited, noncurrent Process while
    /// the current Process retains the hardware-active CR3. Scratch publication
    /// is retargeted to the exited Process's exact bound root and restored
    /// before this single live session is dropped.
    fn unmap_inactive_userspace(
        &mut self,
        process: ProcessKey,
        root_key: crate::memory::address_region::AddressRegionObjectKey,
        proof: &crate::task::ProcessQuiescenceProof,
    ) -> Result<(), ()> {
        let current_process = self.active_root.as_ref().ok_or(())?.process();
        if process == current_process {
            return Err(());
        }
        let mut user = self
            .active
            .current_process_address_space(self.active_root.as_ref().ok_or(())?, current_process);
        user.select_process_for_return_validation(process)
            .map_err(|_| ())?;
        loop {
            let mapping = self
                .regions
                .region(root_key)
                .map_err(|_| ())?
                .mappings()
                .iter()
                .flatten()
                .next()
                .copied();
            let Some(mapping) = mapping else {
                break;
            };
            let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
            let releases = {
                let region = self
                    .regions
                    .region_mut_for_quiesced_teardown(&self.tasks, proof, root_key)
                    .map_err(|_| ())?;
                let mut publisher = user
                    .publisher::<
                        PRIMORDIAL_TABLE_CANDIDATES,
                        PRIMORDIAL_JOURNAL_ENTRIES,
                        PRIMORDIAL_INVALIDATIONS,
                    >(region.address_space_key(), region.region_key(), &mut candidates)
                    .map_err(|_| ())?;
                region
                    .unmap(
                        &mut self.memory,
                        &mut self.registry,
                        &mut publisher,
                        mapping.virtual_start(),
                        mapping.byte_len(),
                    )
                    .unwrap_or_else(|failure| {
                        panic!(
                            "inactive child mapping teardown diverged: {:?}",
                            failure.error()
                        )
                    })
            };
            for candidate in candidates.into_iter().flatten() {
                user.recycle_table_candidate(candidate);
            }
            for release in releases.into_items().into_iter().flatten() {
                self.cleanup.push(release);
            }
        }
        user.select_process_for_return_validation(current_process)
            .map_err(|_| ())?;
        Ok(())
    }

    fn finish_inactive_process_teardown(
        &mut self,
        process: ProcessKey,
        root_key: crate::memory::address_region::AddressRegionObjectKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), ()> {
        let proof = self
            .tasks
            .process_quiescence_proof(process)
            .map_err(|_| ())?;
        let drained = self
            .shared
            .execution
            .blocked_operations_drained(&self.tasks, &proof)
            .map_err(|_| ())?;
        self.unmap_inactive_userspace(process, root_key, &proof)?;
        if process != self.primordial_process {
            self.active
                .teardown_empty_child_address_space(process, address_space)
                .map_err(|_| ())?;
        }
        let root_pin = self
            .regions
            .retire_quiesced_root(
                &mut self.tasks,
                process,
                &proof,
                self.shared.execution.blocked_operations(),
                drained,
            )
            .map_err(|_| ())?;
        self.cleanup
            .push_optional(self.registry.release_internal(root_pin).map_err(|_| ())?);
        self.drain_finalizers()
    }

    fn release_terminal_authority(&mut self) -> Result<(), ()> {
        for reference in [self.kernel_peer.take(), self.process_monitor.take()]
            .into_iter()
            .flatten()
        {
            self.cleanup
                .push_optional(self.registry.release_handle(reference).map_err(|_| ())?);
        }
        let root_owner = self.root_owner.take().ok_or(())?;
        self.cleanup
            .push_optional(self.registry.release_internal(root_owner).map_err(|_| ())?);
        Ok(())
    }

    fn drain_finalizers(&mut self) -> Result<(), ()> {
        while !self.cleanup.is_empty() {
            let cleanup = core::mem::replace(&mut self.cleanup, CleanupQueue::new());
            for release in cleanup.into_releases().into_iter().flatten() {
                let batch = {
                    let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
                    let mut finalizer = crate::object::PayloadFinalizer::new(
                        &mut self.registry,
                        &mut *self.active.target.roles,
                        &mut self.memory,
                        &self.shared.events,
                        &self.shared.timers,
                        &mut timer_deadlines,
                        &self.shared.channels,
                        &self.shared.waits,
                        &mut self.tasks,
                        &mut self.spaces,
                        &mut self.regions,
                    );
                    finalizer.finalize_chain(release)
                };
                crate::syscall::complete_wait_wakes(
                    &mut self.registry,
                    &self.shared.execution,
                    batch,
                    &mut self.cleanup,
                );
            }
        }
        Ok(())
    }

    fn prove_registry_capacity(&mut self) -> Result<(), ()> {
        let mut probes: [Option<crate::object::CreationRef>; REGISTRY_OBJECTS] =
            core::array::from_fn(|_| None);
        for index in 0..REGISTRY_OBJECTS {
            match self.registry.create(deepwyrm_abi::DW_OBJECT_TYPE_EVENT) {
                Ok(probe) => probes[index] = Some(probe),
                Err(_) => {
                    for probe in probes.into_iter().flatten() {
                        self.registry.cancel_creation(probe).map_err(|_| ())?;
                    }
                    return Err(());
                }
            }
        }
        for probe in probes.into_iter().flatten() {
            self.registry.cancel_creation(probe).map_err(|_| ())?;
        }
        Ok(())
    }

    fn finish_terminal_teardown(&mut self) -> Result<(), ()> {
        if !self.services.is_quiescent()
            || self.shared.execution.scheduler_state(self.thread).is_some()
            || self
                .shared
                .execution
                .blocked_operations()
                .has_thread(self.thread)
        {
            return Err(());
        }
        let proof = self
            .tasks
            .process_quiescence_proof(self.process)
            .map_err(|_| ())?;
        let drained = self
            .shared
            .execution
            .blocked_operations_drained(&self.tasks, &proof)
            .map_err(|_| ())?;
        let address_space = self
            .regions
            .region(self.root_key)
            .map_err(|_| ())?
            .address_space_key();
        if self.process == self.primordial_process {
            self.unmap_primordial_userspace(&proof)?;
        } else {
            // The terminal child remains the physically active root when no
            // successor is runnable. Move the unique residency token to the
            // permanently retained primordial/kernel root before touching the
            // child's low half. The child is then noncurrent, so teardown can
            // use its exact scratch-selected publisher and finally reclaim its
            // owned PML4 without ever publishing through the primordial root.
            let prepared = self
                .active
                .prepare_process_root_selection(
                    self.cpu,
                    self.primordial_process,
                    self.primordial_address_space,
                )
                .map_err(|_| ())?;
            let previous = Some(self.active_root.take_process());
            let selected = match self
                .active
                .activate_process_root_selection(prepared, previous)
            {
                Ok(selected) => selected,
                Err(failure) => {
                    let (_error, prepared, previous) = failure.into_parts();
                    self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|error| {
                            panic!("terminal safe-root rollback drifted: {error:?}")
                        });
                    self.active_root = CarrierActiveRoot::Process(previous.unwrap_or_else(|| {
                        panic!("runtime carrier lost its Process root during activation rollback")
                    }));
                    return Err(());
                }
            };
            self.active_root = CarrierActiveRoot::Process(selected);
            self.unmap_inactive_userspace(self.process, self.root_key, &proof)?;
            self.active
                .teardown_empty_child_address_space(self.process, address_space)
                .map_err(|_| ())?;
        }
        if self.memory.active_lease_count() != 0 {
            return Err(());
        }
        let root_pin = self
            .regions
            .retire_quiesced_root(
                &mut self.tasks,
                self.process,
                &proof,
                self.shared.execution.blocked_operations(),
                drained,
            )
            .map_err(|_| ())?;
        self.cleanup
            .push_optional(self.registry.release_internal(root_pin).map_err(|_| ())?);
        self.release_terminal_authority()?;
        self.drain_finalizers()?;
        let trailing = core::mem::replace(&mut self.cleanup, CleanupQueue::new());
        if self.memory.active_lease_count() != 0
            || self.tasks.process_info(self.process).is_ok()
            || self.tasks.thread_info(self.thread).is_ok()
            || self.regions.region(self.root_key).is_ok()
            || trailing
                .into_releases()
                .into_iter()
                .flatten()
                .next()
                .is_some()
        {
            return Err(());
        }
        self.prove_registry_capacity()
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> PrimordialCompletionBackend
    for PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = ();

    fn receive_ready(&mut self, output: &mut [u8; 40]) -> Result<usize, Self::Error> {
        let (bytes, wakes) = self
            .shared
            .channels
            .receive_into(self.channel_keys[0], output, &self.shared.waits)
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
        let info = self.tasks.process_info(self.process).map_err(|_| ())?;
        #[cfg(feature = "test-support")]
        self.g5_probe.observe_terminal(info);
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
        self.finish_terminal_teardown()
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::arch::x86_64::rendezvous::RemoteStopSafePoint
    for PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn precommit_exact_stop(
        &mut self,
        identity: crate::arch::x86_64::rendezvous::StopIdentity,
        precommit: crate::arch::x86_64::rendezvous::ExactSafePrecommit,
    ) -> Result<
        crate::arch::x86_64::rendezvous::ExactSafeWitness,
        crate::arch::x86_64::rendezvous::RemoteStopError,
    > {
        // The IPI/reaper seam is an external, divergent boundary.  It must
        // never inherit a stationary authority guard from a preceding adapter
        // phase before it consumes the move-only reaper witness.
        self.assert_guard_free_external_work();
        if self.rendezvous_reaper.as_ref().is_none() {
            return Err(crate::arch::x86_64::rendezvous::RemoteStopError::UnsafePrecommit);
        }
        let registry = crate::arch::x86_64::smp::live_cpu_registry();
        let snapshot = registry
            .snapshot(self.cpu.index())
            .map_err(|_| crate::arch::x86_64::rendezvous::RemoteStopError::WrongIdentity)?;
        // An e1 Stop may arrive after the blocked syscall has committed its
        // exact Running generation into this CPU's suspended continuation.
        // Keep that case generation-bound; it is not a thread-only fallback.
        let (claim, was_suspended) = match self.shared.execution.running_claim_on(self.cpu) {
            Some(claim) => (claim, false),
            None => (
                self.shared
                    .execution
                    .suspended_claim_on(self.cpu)
                    .ok_or(crate::arch::x86_64::rendezvous::RemoteStopError::StaleRequest)?,
                true,
            ),
        };
        let root = self
            .active_root
            .as_ref()
            .ok_or(crate::arch::x86_64::rendezvous::RemoteStopError::UnsafePrecommit)?;
        if crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
            != Some(self.cpu.index())
            || identity.target_cpu() != self.cpu.index()
            || identity.cpu_online_generation() != snapshot.online_generation
            || identity.thread() != self.thread
            || identity.execution_generation() != claim.generation()
            || identity.root_binding_generation() != root.binding_generation()
            || claim.thread() != self.thread
            || self.shared.execution.current_thread_on(self.cpu) != Some(self.thread)
        {
            return Err(crate::arch::x86_64::rendezvous::RemoteStopError::WrongIdentity);
        }
        self.active
            .validate_current_process_root_selection(root, self.process, root.address_space())
            .map_err(|_| crate::arch::x86_64::rendezvous::RemoteStopError::WrongIdentity)?;
        if !matches!(self.active_root, CarrierActiveRoot::Process(_)) {
            return Err(crate::arch::x86_64::rendezvous::RemoteStopError::UnsafePrecommit);
        }
        let witness = precommit.verify(
            crate::arch::x86_64::rendezvous::SafePointPrecommitObservation {
                identity,
                // `reaper` is move-only evidence from the target-only seam;
                // it can be minted only after both facts were observed.
                cpu_private_safe_stack: true,
                user_access_disabled: true,
                // This method runs only from the divergent `-> !` rendezvous
                // callback; its caller has no route back to the IPI frame.
                user_return_prevented: true,
            },
        )?;
        // All rejectable identity/safe-point checks have passed. Move any
        // completed syscall releases out of the stopped carrier before the
        // reaper witness is consumed; only the post-ack continuation may
        // finalize them.
        if was_suspended {
            self.transfer_suspended_service_cleanup_for_stop();
        }
        self.stage_rendezvous_cleanup();
        let reaper = self
            .rendezvous_reaper
            .take()
            .expect("reaper witness disappeared after successful precommit");
        let previous = core::mem::replace(&mut self.active_root, CarrierActiveRoot::Transitioning);
        let CarrierActiveRoot::Process(root) = previous else {
            panic!("remote stop precommit lost the active Process root");
        };
        let _ = reaper;
        self.active_root = CarrierActiveRoot::StopPrecommitted(root);
        self.stopping_claim = Some(claim);
        self.stopping_claim_was_suspended = was_suspended;
        Ok(witness)
    }

    fn release_running_ownership(&mut self) {
        let claim = self
            .stopping_claim
            .take()
            .unwrap_or_else(|| panic!("remote stop commit omitted its exact Running claim"));
        if self.stopping_claim_was_suspended {
            self.shared
                .execution
                .stop_suspended_claim_on(claim)
                .unwrap_or_else(|error| {
                    panic!("remote stop suspended claim drifted after precommit: {error:?}")
                });
        } else {
            self.shared
                .execution
                .stop_running_claim_on(claim)
                .unwrap_or_else(|error| {
                    panic!("remote stop Running claim drifted after precommit: {error:?}")
                });
        }
        self.stopping_claim = Some(claim);
    }

    fn release_root_residency(&mut self) {
        let previous =
            match core::mem::replace(&mut self.active_root, CarrierActiveRoot::Transitioning) {
                CarrierActiveRoot::StopPrecommitted(root) => root,
                _ => panic!("remote stop root release without an exact Process selection"),
            };
        match self.active.enter_kernel_execution_root(previous) {
            Ok(kernel) => self.active_root = CarrierActiveRoot::Kernel(kernel),
            Err((error, recovered)) => {
                self.active_root = CarrierActiveRoot::StopPrecommitted(recovered);
                panic!("remote stop kernel-root handoff drifted after Running release: {error:?}");
            }
        }
    }

    fn deferred_cleanup_is_quiescent(&self) -> bool {
        self.cleanup.is_empty()
            && self.rendezvous_cleanup.is_some()
            && self.services.is_quiescent()
            && self.deferred_current.is_none()
            && self.shared.execution.running_claim_on(self.cpu).is_none()
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::native::NativeRendezvousRuntime
    for PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn rendezvous_stop(
        &mut self,
        request: crate::arch::x86_64::rendezvous::StopRequest,
        reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> ! {
        self.assert_guard_free_external_work();
        self.rendezvous_reaper = Some(reaper);
        crate::arch::x86_64::idle::complete_current_rendezvous_stop(request, self).unwrap_or_else(
            |error| panic!("remote rendezvous stop failed before commit: {error:?}"),
        );
        self.continue_after_rendezvous_stop()
    }
}

#[allow(
    unsafe_code,
    reason = "the target runtime propagates the physical-current carrier and architecture-owned first-run entry"
)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallFrameRuntime
    for PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if self.tasks.thread_process(self.thread) != Ok(self.process)
            || self.shared.execution.scheduler_state(self.thread)
                != Some(SchedulerThreadState::Running)
        {
            return Err(crate::arch::x86_64::syscall::UserReturnError::BindingChanged);
        }
        let mut mappings = self.active.current_process_address_space(
            self.active_root.as_ref().expect("active root"),
            self.process,
        );
        frame.authorize_return(current_binding_generation, &mut mappings)
    }

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) {
        self.terminate_exception(crate::task::TaskExceptionRecord::new(
            DW_EXCEPTION_GENERAL_PROTECTION,
            invalid_user_return_detail(error),
            0,
        ));
    }

    fn user_exception(&mut self, record: crate::arch::x86_64::exceptions::UserExceptionRecord) {
        self.terminate_exception(record.task_exception());
    }

    fn terminate_current(&mut self) -> ! {
        let retired_process = self.process;
        let retired_root_key = self.root_key;
        let retired_address_space = self
            .regions
            .region(retired_root_key)
            .unwrap_or_else(|error| panic!("terminal Process root disappeared: {error:?}"))
            .address_space_key();
        crate::syscall::complete_deferred_current_reclaim(
            &mut self.registry,
            &self.shared.execution,
            &self.shared.waits,
            self.deferred_current
                .take()
                .unwrap_or_else(|| panic!("primordial exit omitted deferred resources")),
            &mut self.cleanup,
        );
        let next = self.shared.execution.terminal_reaper_next_on(self.cpu);
        if let Some(next) = next {
            let (stack_id, context_id) = self
                .tasks
                .thread_execution_resources(next)
                .unwrap_or_else(|error| panic!("terminal next resources failed: {error:?}"))
                .unwrap_or_else(|| panic!("terminal next Thread has no execution resources"));
            let stack = self
                .shared
                .execution
                .stack_bounds(stack_id)
                .unwrap_or_else(|error| panic!("terminal next stack failed: {error:?}"));
            let continuation = self
                .shared
                .execution
                .kernel_continuation_rsp(context_id)
                .unwrap_or_else(|error| panic!("terminal next continuation failed: {error:?}"));
            self.synchronize_scheduler_current();
            if retired_process != self.process
                && self.tasks.process_quiescence_proof(retired_process).is_ok()
            {
                self.finish_inactive_process_teardown(
                    retired_process,
                    retired_root_key,
                    retired_address_space,
                )
                .unwrap_or_else(|_| panic!("inactive exited Process teardown drifted"));
            }
            unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                .unwrap_or_else(|error| panic!("terminal next stack binding failed: {error:?}"));
            let continuation = if continuation == 0 {
                unsafe {
                    crate::arch::x86_64::context::prepare_initial_kernel_continuation(
                        stack,
                        crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
                    )
                }
                .unwrap_or_else(|error| {
                    panic!("terminal fresh continuation preparation failed: {error:?}")
                })
                .rsp()
            } else {
                continuation
            };
            crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(
                |error| panic!("terminal next syscall boundary validation failed: {error:?}"),
            );
            unsafe { crate::arch::x86_64::context::abandon_to_kernel_continuation(continuation) }
        }
        let completion = complete_primordial_launch(self);
        #[cfg(feature = "test-support")]
        if self.g5_probe.accepts_completion(&completion) {
            crate::test_support::complete_pass(0)
        } else {
            crate::test_support::complete_fail(self.g5_probe.failure_detail(&completion))
        }
        #[cfg(not(feature = "test-support"))]
        {
            let (level, message) = match completion {
                Ok(()) => (
                    crate::debug::DiagnosticLevel::Info,
                    "Wyrmroot bootstrap completed normally",
                ),
                Err(crate::boot::primordial::construction::PrimordialCompletionError::UnhandledException) => (
                    crate::debug::DiagnosticLevel::Error,
                    "Wyrmroot bootstrap terminated after an unhandled userspace exception",
                ),
                Err(_) => (
                    crate::debug::DiagnosticLevel::Error,
                    "Wyrmroot bootstrap terminated with a structured completion failure",
                ),
            };
            let _ = crate::debug::emit_early_record(level, "primordial", message);
            loop {
                unsafe {
                    core::arch::asm!("sti", "hlt", options(nomem, nostack));
                }
            }
        }
    }

    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        self.synchronize_scheduler_current();
        let context = self
            .shared
            .execution
            .load_context(self.context_id)
            .unwrap_or_else(|error| panic!("could not load fresh Thread context: {error:?}"));
        let stack = self
            .shared
            .execution
            .stack_bounds(self.stack_id)
            .unwrap_or_else(|error| panic!("could not load fresh Thread stack: {error:?}"));
        let state = {
            let mut mappings = self.active.current_process_address_space(
                self.active_root.as_ref().expect("active root"),
                self.process,
            );
            crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
                .unwrap_or_else(|error| panic!("invalid fresh Thread return: {error:?}"))
        };
        unsafe { crate::arch::x86_64::syscall::enter_bound_validated_user(&state, stack) }
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan<'owner> {
        #[cfg(feature = "test-support")]
        let owner = self.services.operation_owner(self.thread);
        let plan = unsafe {
            self.services.prepare_suspend(
                &self.tasks,
                &self.shared.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|error| panic!("primordial suspend preparation drifted: {error:?}"));
        #[cfg(feature = "test-support")]
        self.g5_probe.observe_prepare(
            owner,
            matches!(
                &plan,
                crate::syscall::native::NativeSuspendPlan::IdleCurrent
            ),
        );
        plan
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'owner> {
        #[cfg(feature = "test-support")]
        let owner = self.services.operation_owner(self.thread);
        let poll = unsafe {
            self.services.poll_idle_suspend(
                &self.tasks,
                &self.shared.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|error| panic!("primordial idle-suspend poll drifted: {error:?}"));
        #[cfg(feature = "test-support")]
        self.g5_probe.observe_poll(
            owner,
            matches!(
                &poll,
                crate::syscall::native::NativeIdleSuspendPoll::ResumeCurrent
            ),
            matches!(
                &poll,
                crate::syscall::native::NativeIdleSuspendPoll::Switch(_)
            ),
        );
        poll
    }

    fn resume_suspended(&mut self, frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame) {
        self.synchronize_scheduler_current();
        #[cfg(feature = "test-support")]
        let owner = self.services.operation_owner(self.thread);
        let resumed = {
            let mut user = self.active.current_process_address_space(
                self.active_root.as_ref().expect("active root"),
                self.process,
            );
            let mut deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
            self.services.resume_suspended(
                &mut user,
                &mut self.registry,
                &mut self.tasks,
                &self.shared.waits,
                &self.shared.execution,
                self.thread,
                Some(&mut deadlines),
            )
        }
        .unwrap_or_else(|error| panic!("primordial suspended syscall resume drifted: {error:?}"));
        let (status, cleanup) = resumed.into_parts();
        self.merge_cleanup(cleanup);
        #[cfg(feature = "test-support")]
        self.g5_probe.observe_resume(owner, status);
        frame.set_status(status);
    }
}

const fn invalid_user_return_detail(error: crate::arch::x86_64::syscall::UserReturnError) -> u32 {
    use crate::arch::x86_64::syscall::UserReturnError;
    match error {
        UserReturnError::NonCanonicalUserAddress => 1,
        UserReturnError::InstructionNotExecutable => 2,
        UserReturnError::StackNotWritable => 3,
        UserReturnError::UnsupportedTlsPolicy => 4,
        UserReturnError::UnsupportedFpSimdPolicy => 5,
        UserReturnError::BindingChanged => 6,
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

#[allow(
    unsafe_code,
    reason = "G3 publishes stationary synchronized authorities, seals fail-closed AP carriers, and binds the BSP-exclusive carrier for audited initial CPL3 transition"
)]
pub(super) fn enter<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mut active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    modules: crate::boot::primordial::PrimordialBootModules,
) -> ! {
    let cpu_index = crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
        .unwrap_or_else(|| panic!("primordial runtime entered without an installed CPU slot"));
    if cpu_index != crate::cpu::CpuIndex::BOOTSTRAP.index() {
        panic!("primordial construction must remain on the bootstrap CPU");
    }
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
    let mut tasks = Tasks::new();
    let mut spaces = unsafe { Spaces::new() };
    let mut regions = Regions::new();
    let shared = publish_runtime_shared();
    initialize_per_cpu_live_carriers(shared);
    bind_parked_ap_runtime_carriers();
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
            &shared.channels,
            &shared.waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
            &shared.execution,
            &root_owner,
        );
        construct_primordial(&plan, bootstrap, bootfs, &mut backend, |_| false)
            .unwrap_or_else(|error| panic!("primordial construction failed: {error:?}"));
        backend.take_monitor()
    };
    let primordial_address_space = regions
        .region(monitor.root_key)
        .unwrap_or_else(|error| panic!("primordial root region unavailable: {error:?}"))
        .address_space_key();
    active
        .bind_primordial_address_space(monitor.process_key, primordial_address_space)
        .unwrap_or_else(|error| panic!("could not bind primordial architecture root: {error:?}"));
    active
        .reserve_kernel_execution_roots()
        .unwrap_or_else(|error| panic!("could not reserve CPU execution roots: {error:?}"));
    let initial_root = active
        .prepare_process_root_selection(
            crate::cpu::CpuIndex::BOOTSTRAP,
            monitor.process_key,
            primordial_address_space,
        )
        .and_then(|prepared| {
            active
                .activate_process_root_selection(prepared, None)
                .map_err(|failure| failure.error())
        })
        .unwrap_or_else(|error| panic!("could not publish primordial current root: {error:?}"));
    if shared
        .execution
        .schedule_next_on(crate::cpu::CpuIndex::BOOTSTRAP)
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
    let AuthorityPrimordialMonitor {
        kernel_peer,
        process: process_monitor,
        channel_keys,
        ..
    } = monitor;
    let mut runtime = PrimordialRuntimeCarrier {
        cpu: crate::cpu::CpuIndex::BOOTSTRAP,
        local: per_cpu_live_carrier(crate::cpu::CpuIndex::BOOTSTRAP),
        active,
        active_root: CarrierActiveRoot::Process(initial_root),
        stopping_claim: None,
        stopping_claim_was_suspended: false,
        rendezvous_reaper: None,
        registry,
        memory,
        tasks,
        shared,
        services: FServiceState::new(),
        channel_staging: take_channel_staging(cpu_index),
        spaces,
        regions,
        process,
        thread,
        stack_id,
        context_id,
        root_key,
        primordial_process: process,
        primordial_root_key: root_key,
        primordial_address_space,
        channel_keys,
        kernel_peer: Some(kernel_peer),
        process_monitor: Some(process_monitor),
        root_owner: Some(root_owner),
        deferred_current: None,
        cleanup: CleanupQueue::new(),
        rendezvous_cleanup: None,
        #[cfg(feature = "test-support")]
        g5_probe: G5PrimordialProbe::for_build(),
    };
    runtime
        .local
        .record_current(runtime.thread, runtime.stack_id, runtime.context_id);
    let exception_binding =
        crate::arch::x86_64::syscall::bind_native_runtime_user_exception_handler()
            .unwrap_or_else(|error| panic!("could not bind primordial exceptions: {error:?}"));
    let context = runtime
        .shared
        .execution
        .load_context(runtime.context_id)
        .unwrap_or_else(|error| panic!("could not load primordial context: {error:?}"));
    let stack = runtime
        .shared
        .execution
        .stack_bounds(runtime.stack_id)
        .unwrap_or_else(|error| panic!("could not load primordial kernel stack: {error:?}"));
    let state = {
        let mut mappings = runtime.active.current_process_address_space(
            runtime.active_root.as_ref().expect("active root"),
            runtime.process,
        );
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
    for PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        if self.shared.execution.scheduler_state(self.thread) != Some(SchedulerThreadState::Running)
        {
            panic!("primordial syscall arrived without its running Thread");
        }
        // This identity is deliberately detached from the carrier before any
        // usercopy or service dispatch.  The final check keeps a resumed
        // adapter from committing under a migrated Thread/root selection.
        let phase = self.reserve_runtime_phase();
        let result = match request {
            NativeSyscallRequest::ProcessCreate {
                args,
                args_size,
                out_result,
                result_size,
            } => {
                self.assert_guard_free_external_work();
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::process_create_with_root(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    &mut self.regions,
                    &mut self.spaces,
                    self.process,
                    args,
                    args_size,
                    out_result,
                    result_size,
                    &mut self.cleanup,
                ))
            }
            request => {
                self.assert_guard_free_external_work();
                let dispatch = {
                    let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
                    let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
                    let root_generation = self
                        .active_root
                        .as_ref()
                        .expect("active root")
                        .binding_generation();
                    let prepared = self
                        .services
                        .prepare_dispatch(request, self.thread, root_generation)
                        .unwrap_or_else(|_| {
                            panic!("F-service prepare has an invalid root identity")
                        });
                    let mut user = self.active.current_process_address_space(
                        self.active_root.as_ref().expect("active root"),
                        self.process,
                    );
                    self.services.dispatch_prepared(
                        prepared,
                        &mut user,
                        &mut self.registry,
                        &mut self.tasks,
                        &self.shared.execution,
                        &self.shared.channels,
                        &self.shared.events,
                        &self.shared.timers,
                        &self.shared.waits,
                        &mut self.regions,
                        &mut self.spaces,
                        self.process,
                        self.thread,
                        root_generation,
                        Some(&mut wait_deadlines),
                        &mut timer_deadlines,
                        &mut self.channel_staging[..],
                        || {
                            crate::time::monotonic_now()
                                .map_err(|_| deepwyrm_abi::DW_STATUS_BAD_STATE)
                        },
                    )
                };
                let (route, cleanup) = dispatch.into_parts();
                self.merge_cleanup(cleanup);
                match route {
                    FServiceRoute::Handled(result) => result,
                    FServiceRoute::Fallthrough(request) => self.handle_fallthrough(request),
                }
            }
        };
        self.commit_runtime_phase(phase);
        result
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle_fallthrough(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        self.assert_guard_free_external_work();
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
            NativeSyscallRequest::HandleDuplicate {
                handle,
                requested_rights,
                out_handle,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
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
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
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
            NativeSyscallRequest::ThreadCreate {
                process,
                requested_rights,
                out_thread,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::thread_create(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    self.process,
                    process,
                    requested_rights,
                    out_thread,
                    &mut self.cleanup,
                ))
            }
            NativeSyscallRequest::ThreadStart { args, args_size } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::thread_start_with_access(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.execution,
                    self.process,
                    args,
                    args_size,
                    &mut self.cleanup,
                ))
            }
            NativeSyscallRequest::ProcessTerminate {
                process,
                reason,
                code,
            } => self.terminate_process_handle(process, reason, code),
            NativeSyscallRequest::ThreadTerminate {
                thread,
                reason,
                code,
            } => self.terminate_thread_handle(thread, reason, code),
            NativeSyscallRequest::MemoryObjectCreate {
                byte_len,
                flags,
                requested_rights,
                out_handle,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::memory_object_create_owned(
                    &mut user,
                    &mut self.registry,
                    &mut self.memory,
                    &mut self.tasks,
                    self.process,
                    byte_len,
                    flags,
                    requested_rights,
                    out_handle,
                    &mut self.cleanup,
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
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
        let status = (|| {
            let mut user = self.active.current_process_address_space(
                self.active_root.as_ref().expect("active root"),
                self.process,
            );
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
            let prepared = match crate::syscall::prepare_address_region_mutation(
                &mut self.registry,
                &self.tasks,
                &self.regions,
                self.process,
                address_region,
                deepwyrm_abi::DwRights(
                    deepwyrm_abi::DW_RIGHT_MAP.0 | deepwyrm_abi::DW_RIGHT_MODIFY.0,
                ),
                &mut self.cleanup,
            ) {
                Ok(target) => target,
                Err(status) => {
                    user.discard_owned_output(output)
                        .unwrap_or_else(|_| panic!("primordial map output pin drifted"));
                    return status;
                }
            };
            let target = prepared.target();
            let caller_process = self.process;
            if user
                .select_process_for_return_validation(target.process)
                .is_err()
            {
                user.discard_owned_output(output)
                    .unwrap_or_else(|_| panic!("primordial map output pin drifted"));
                return DW_STATUS_BAD_STATE;
            }
            let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
            let result = (|| {
                candidates[0] = Some(
                    user.prepare_table_candidate(TableLevel::Pdpt)
                        .map_err(|_| DW_STATUS_NO_RESOURCES)?,
                );
                candidates[1] = Some(
                    user.prepare_table_candidate(TableLevel::Pd)
                        .map_err(|_| DW_STATUS_NO_RESOURCES)?,
                );
                candidates[2] = Some(
                    user.prepare_table_candidate(TableLevel::Pt)
                        .map_err(|_| DW_STATUS_NO_RESOURCES)?,
                );
                candidates[3] = Some(
                    user.prepare_table_candidate(TableLevel::Pdpt)
                        .map_err(|_| DW_STATUS_NO_RESOURCES)?,
                );
                candidates[4] = Some(
                    user.prepare_table_candidate(TableLevel::Pd)
                        .map_err(|_| DW_STATUS_NO_RESOURCES)?,
                );
                candidates[5] = Some(
                    user.prepare_table_candidate(TableLevel::Pt)
                        .map_err(|_| DW_STATUS_NO_RESOURCES)?,
                );
                let mut publisher = user
                .publisher::<
                    PRIMORDIAL_TABLE_CANDIDATES,
                    PRIMORDIAL_JOURNAL_ENTRIES,
                    PRIMORDIAL_INVALIDATIONS,
                >(target.address_space, target.region_key, &mut candidates)
                .map_err(|_| DW_STATUS_BAD_STATE)?;
                crate::syscall::address_region_map_prepared_model(
                    prepared,
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
            })();
            for candidate in candidates.into_iter().flatten() {
                user.recycle_table_candidate(candidate);
            }
            user.select_process_for_return_validation(caller_process)
                .unwrap_or_else(|error| {
                    panic!("primordial map caller-root restoration failed: {error:?}")
                });
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
        })();
        self.commit_runtime_phase(phase);
        status
    }

    fn unmap_memory(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        address: deepwyrm_abi::DwUserAddress,
        byte_len: u64,
    ) -> deepwyrm_abi::DwStatus {
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
        let status = (|| {
            let prepared = match crate::syscall::prepare_address_region_mutation(
                &mut self.registry,
                &self.tasks,
                &self.regions,
                self.process,
                address_region,
                deepwyrm_abi::DW_RIGHT_MODIFY,
                &mut self.cleanup,
            ) {
                Ok(target) => target,
                Err(status) => return status,
            };
            let target = prepared.target();
            let caller_process = self.process;
            let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
            let mut user = self.active.current_process_address_space(
                self.active_root.as_ref().expect("active root"),
                self.process,
            );
            if user
                .select_process_for_return_validation(target.process)
                .is_err()
            {
                return DW_STATUS_BAD_STATE;
            }
            let status = {
                let mut publisher = user
                .publisher::<
                    PRIMORDIAL_TABLE_CANDIDATES,
                    PRIMORDIAL_JOURNAL_ENTRIES,
                    PRIMORDIAL_INVALIDATIONS,
                >(target.address_space, target.region_key, &mut candidates)
                .unwrap_or_else(|_| panic!("primordial unmap publisher unavailable"));
                crate::syscall::address_region_unmap_prepared(
                    prepared,
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
            };
            for candidate in candidates.into_iter().flatten() {
                user.recycle_table_candidate(candidate);
            }
            user.select_process_for_return_validation(caller_process)
                .unwrap_or_else(|error| {
                    panic!("primordial unmap caller-root restoration failed: {error:?}")
                });
            status
        })();
        self.commit_runtime_phase(phase);
        status
    }

    fn exit_process(&mut self, exit_code: u32) -> NativeSyscallResult {
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
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
                &self.shared.execution,
                &self.shared.waits,
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
        let mut user = self.active.current_process_address_space(
            self.active_root.as_ref().expect("active root"),
            self.process,
        );
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
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn terminate_process_handle(
        &mut self,
        process: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
        code: u32,
    ) -> NativeSyscallResult {
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
        let mut discarded = None;
        let mut atomic_pin = None;
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| assert!(discarded.replace(output).is_none()),
                |pin| assert!(atomic_pin.replace(pin).is_none()),
            );
            crate::syscall::process_terminate(
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.process,
                self.thread,
                process,
                reason,
                code,
                &mut self.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pin, control, deferred);
        if status == DW_STATUS_SUCCESS && control == SyscallControl::ReturnToCaller {
            let target = crate::syscall::process_handle_target(
                &mut self.registry,
                &self.tasks,
                self.process,
                process,
                &mut self.cleanup,
            )
            .unwrap_or_else(|error| {
                panic!("terminated child Process handle lost identity: {error:?}")
            });
            if target != self.process {
                let root_object = self
                    .tasks
                    .root_region(target)
                    .unwrap_or_else(|error| {
                        panic!("terminated child root lookup failed: {error:?}")
                    })
                    .unwrap_or_else(|| panic!("terminated child has no root AddressRegion"));
                let root_key =
                    crate::memory::address_region::AddressRegionObjectKey::from_object_id(
                        root_object,
                    );
                let address_space = self
                    .regions
                    .region(root_key)
                    .unwrap_or_else(|error| panic!("terminated child root disappeared: {error:?}"))
                    .address_space_key();
                self.finish_inactive_process_teardown(target, root_key, address_space)
                    .unwrap_or_else(|_| panic!("terminated inactive child teardown drifted"));
            }
        }
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn terminate_thread_handle(
        &mut self,
        thread: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
        code: u32,
    ) -> NativeSyscallResult {
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
        let mut discarded = None;
        let mut atomic_pin = None;
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| assert!(discarded.replace(output).is_none()),
                |pin| assert!(atomic_pin.replace(pin).is_none()),
            );
            crate::syscall::thread_terminate(
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.process,
                self.thread,
                thread,
                reason,
                code,
                &mut self.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pin, control, deferred);
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn finish_terminal_adapter_resources(
        &mut self,
        discarded: Option<user_access::OwnedLiveUserOutput>,
        atomic_pin: Option<user_access::OwnedLiveAtomicU32>,
        control: SyscallControl,
        deferred: Option<crate::task::DeferredCurrentExecutionResources>,
    ) {
        if control == SyscallControl::TerminateCurrent {
            self.deferred_current = Some(
                deferred.unwrap_or_else(|| panic!("terminal adapter omitted deferred reclaim")),
            );
        } else {
            assert!(deferred.is_none());
        }
        let mut user = self.active.current_process_address_space(
            self.active_root.as_ref().expect("active root"),
            self.process,
        );
        if let Some(output) = discarded {
            user.discard_owned_output(output)
                .unwrap_or_else(|_| panic!("terminal adapter output pin drifted"));
        }
        if let Some(pin) = atomic_pin {
            user.release_atomic_u32(pin)
                .unwrap_or_else(|_| panic!("terminal adapter atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
    }
}
