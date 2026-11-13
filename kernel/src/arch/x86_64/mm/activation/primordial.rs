//! Production DW0-G primordial process composition over the live x86_64 root.

#![allow(
    unsafe_code,
    reason = "the G3 live runtime owns bounded static publication, physical backing initialization, and the audited CPL3 transition"
)]

use super::*;

use super::root_switch::{
    CarrierActiveRoot, ExecutedApKernelRootEntry, ExecutedSchedulerRootSwitch,
    ExecutedSchedulerRootSwitchKind, ExecutedStopRootSwitch, ExecutedTerminalKernelRootSwitch,
    ExecutedTerminalProcessRootSwitch, FailedApKernelRootEntry, FailedSchedulerRootSwitch,
    FailedSchedulerRootSwitchKind, FailedStopRootSwitch, FailedTerminalKernelRootSwitch,
    FailedTerminalProcessRootSwitch, PreparedApKernelRootEntry, PreparedSchedulerRootSwitch,
    PreparedSchedulerRootSwitchKind, PreparedStopRootSwitch, PreparedTerminalKernelRootSwitch,
    PreparedTerminalProcessRootSwitch, RootSwitchFlight, SchedulerRootIdentity,
};

use super::GuardFree;
use super::cpu_slots::{CpuOwner, CpuSlots, OtherCpus, RemotelyStaged};
use super::runtime_authority::{
    PagingAccess, PagingLock, RuntimeAuthorityGuard, RuntimeAuthorityHandle, RuntimeAuthorityLock,
    ShootdownInitiatorGuard, ShootdownInitiatorLock,
};
use crate::one_shot::init_fields;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::boot::primordial::construction::authority::{
    AuthorityPrimordialBackend, AuthorityPrimordialMonitor, PrimordialPlatform,
};
use crate::boot::primordial::construction::complete_primordial_launch;
use crate::boot::primordial::construction::{
    PrimordialCompletionBackend, PrimordialExitDisposition,
};
use crate::ipc::{ChannelAuthority, ChannelError};
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
    DivergentCarrier, NativeSyscallFrameRuntime, NativeSyscallHandler, NativeSyscallRequest,
    NativeSyscallResult, SyscallControl,
};
use crate::syscall::{
    CleanupQueue, FServiceRoute, FServiceState, NativeWaitControl, StagedStopCleanup,
    TerminalWaitCleanup,
};
use crate::task::{ExecutionDomain, ProcessKey, SchedulerThreadState, TaskAuthority, ThreadKey};
use crate::time::TimerAuthority;
use crate::wait::{EventAuthority, WaitRegistry};
use deepwyrm_abi::{
    DW_CHANNEL_MAX_PAYLOAD, DW_EXCEPTION_GENERAL_PROTECTION, DW_STATUS_BAD_STATE,
    DW_STATUS_NO_RESOURCES, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS, DW_STATUS_WOULD_BLOCK,
    DW_TASK_STATE_EXITED, DW_TERMINATION_NORMAL_EXIT,
};

const MAX_BOOTFS_BYTES: usize = 32 * 1024 * 1024;
#[cfg(not(deepwyrm_production_product))]
const REGISTRY_OBJECTS: usize = 32;
#[cfg(deepwyrm_production_product)]
const REGISTRY_OBJECTS: usize = super::production_resource_geometry::SELECTED.registry;
#[cfg(not(deepwyrm_production_product))]
const MEMORY_OBJECTS: usize = 10;
#[cfg(deepwyrm_production_product)]
const MEMORY_OBJECTS: usize = super::production_resource_geometry::SELECTED.memory;
#[cfg(not(deepwyrm_production_product))]
const MEMORY_LEASES: usize = 10;
#[cfg(deepwyrm_production_product)]
const MEMORY_LEASES: usize = super::production_resource_geometry::SELECTED.mappings;
// I0 keeps the complete bootstrap -> init0 -> hello chain live while each
// parent performs bounded READY/exit supervision of its direct child. The
// selector-24 controller adds exactly one temporary supervised child.
#[cfg(not(deepwyrm_production_product))]
const USERSPACE_CHAIN_PROCESSES: usize = 3;
#[cfg(deepwyrm_production_product)]
const USERSPACE_CHAIN_PROCESSES: usize = super::production_resource_geometry::SELECTED.identities;
#[cfg(not(deepwyrm_production_product))]
const CHANNEL_PAIRS: usize = USERSPACE_CHAIN_PROCESSES;
#[cfg(deepwyrm_production_product)]
const CHANNEL_PAIRS: usize = super::production_resource_geometry::SELECTED.channel_pairs;
const CHANNEL_DEPTH: usize = 2;
#[cfg(not(deepwyrm_production_product))]
const WAITERS: usize = 4;
#[cfg(deepwyrm_production_product)]
const WAITERS: usize = super::production_resource_geometry::SELECTED.waits;
#[cfg(not(deepwyrm_production_product))]
const TASK_GROUPS: usize = 1;
#[cfg(deepwyrm_production_product)]
const TASK_GROUPS: usize = super::production_resource_geometry::SELECTED.identities;
const PROCESSES: usize = USERSPACE_CHAIN_PROCESSES;
const THREADS: usize = USERSPACE_CHAIN_PROCESSES;
// The bootstrap handle deltas and peak live in `handle_capacity.rs`.
use super::handle_capacity::{BOOTSTRAP_HANDLE_PEAK, INIT_MOVED_HANDLES};
#[cfg(not(deepwyrm_production_product))]
const HANDLES: usize = BOOTSTRAP_HANDLE_PEAK;
#[cfg(deepwyrm_production_product)]
const HANDLES: usize = super::production_resource_geometry::SELECTED.handles;
const SPACES: usize = USERSPACE_CHAIN_PROCESSES;
const REGIONS: usize = USERSPACE_CHAIN_PROCESSES;
const REGION_OBJECTS: usize = USERSPACE_CHAIN_PROCESSES;
/// DW2 M5: 64 mapping slots per region (plan §10.2 item 2).
const REGION_SLOTS: usize = 64;
const EXECUTION_THREADS: usize = USERSPACE_CHAIN_PROCESSES;
// WYR1-F production is selected explicitly for the same reason selectors 33
// and 34 are: the freestanding product must not inherit the bootstrap-era DW0
// geometry merely because no evidence cfg named it. The same demand model
// drives the host fixtures and these target assertions.
#[cfg(deepwyrm_production_product)]
const _: () = {
    use super::production_resource_geometry::{Capacity, SELECTED, fits};
    assert!(HANDLES == SELECTED.handles);
    assert!(REGION_SLOTS == super::production_resource_geometry::JOB_REGION_MAPPINGS);
    assert!(MEMORY_OBJECTS == SELECTED.memory);
    assert!(MEMORY_LEASES == SELECTED.mappings);
    assert!(PROCESSES == SELECTED.identities);
    assert!(THREADS == SELECTED.identities);
    assert!(SPACES == SELECTED.identities);
    assert!(REGIONS == SELECTED.identities);
    assert!(REGION_OBJECTS == SELECTED.identities);
    assert!(TASK_GROUPS == SELECTED.identities);
    assert!(EXECUTION_THREADS == SELECTED.identities);
    assert!(REGISTRY_OBJECTS == SELECTED.registry);
    assert!(CHANNEL_PAIRS == SELECTED.channel_pairs);
    assert!(WAITERS == SELECTED.waits);
    assert!(TIMERS >= super::production_resource_geometry::TIMER_PEAK);
    assert!(EVENTS >= super::production_resource_geometry::EVENT_PEAK);
    assert!(REGION_SLOTS >= super::production_resource_geometry::REGION_MAPPING_PEAK);
    assert!(REGION_SLOTS <= super::production_resource_geometry::JOB_REGION_MAPPINGS);
    assert!(fits(Capacity {
        handles: HANDLES,
        memory: MEMORY_OBJECTS,
        mappings: MEMORY_LEASES,
        identities: PROCESSES,
        registry: REGISTRY_OBJECTS,
        channel_pairs: CHANNEL_PAIRS,
        waits: WAITERS,
        evidence: SELECTED.evidence,
    }));
};
const EVENTS: usize = 1;
#[cfg(not(deepwyrm_production_product))]
const TIMERS: usize = 1;
// Selector 31 overlaps system-init's resident control-tick Timer with one
// production UART driver's bounded TEMT-pacing Timer. Keep that exact
// product peak separate from the ordinary single-Timer geometry.
//
// F2A.2: the WYR1-F production product has the same overlap for the same
// reason -- it runs the real uart16550d against a real console -- and was
// getting the one-Timer geometry because no cfg marked it. That is the same
// silent inheritance the production ledger exists to stop, found by the
// ledger's own `TIMER_PEAK` rather than by a boot.
#[cfg(deepwyrm_production_product)]
const TIMERS: usize = 2;
// A bounded mapping can cross one boundary at each non-root level. Keep two
// candidates for PDPT, PD, and PT creation so the live publisher can construct
// both paths without depending on where the requested range lands. The I2
// bootfs needs a bounded 32-page window. The selector-24 WRCAP bootfs contains
// the controller plus its deterministic config and asset and is exactly 39
// pages after init0 termination-race reconciliation. The ordinary Wave 4
// bootfs is exactly 17 pages with its selector-specific init0 artifact.
//
// D7: one journal batch spans up to 16 MiB (`PRIMORDIAL_MAX_USER_MAPPING_PAGES`),
// which crosses up to nine PT, two PD and two PDPT boundaries. The pool holds
// sixteen; a map prepares only the candidates one batch of its length can
// need, so small maps still prepare six, and the publisher refills the pool
// between batches (DW2 M4).
pub(super) const PRIMORDIAL_TABLE_CANDIDATES: usize = 16;
// F3A.6y. This was a literal 17 -- "the ordinary Wave 4 bootfs is exactly 17
// pages", per the comment above, and true of the archive that was current when
// it was written. The WYR1-F production archive is 203 pages, so the mapping
// asked the publisher's invalidation array for 203 slots and got 17, which
// surfaced as an opaque `NO_RESOURCES` from the bootstrap's bootfs mapping and
// cost the F3A campaign eleven revisions to name (F3A.6x).
//
// Selector 34's arm below already said why, and fixed it for itself: "a
// guessed constant is what made an oversized archive surface as an opaque
// NO_RESOURCES ... instead of a build error." Four selector arms derive the
// ceiling from the producer's measured archive. Production, which is the
// absence of every selector, was never given the fix.
//
// `DEEPWYRM_BOOTFS_MAX_PAGES` is emitted by `build.rs` for every
// configuration: the producer's measurement when a producer built this kernel,
// and the historical Wave 4 value when nothing measured it, so a standalone
// `cargo build` is unchanged.
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_production_bootfs_pages();
const PRIMORDIAL_STACK_MAPPING_PAGES: usize =
    crate::boot::primordial::construction::STACK_BYTES as usize / 4096;
const _: () = assert!(crate::boot::primordial::construction::STACK_BYTES % 4096 == 0);
/// The most pages one journal batch of a user map, unmap or protect changes
/// (Deepwyrm D7): 16 MiB. A larger change is published in batches of this
/// size (DW2 M4), so this bounds static memory, not the size of a map. The
/// journal lives in static storage beneath P (`LiveJournalStorage`), not on
/// a kernel stack.
const PRIMORDIAL_MAX_USER_MAPPING_PAGES: usize = 4096;
// Mapping machinery must fit the selector-local bootfs ceiling, the
// independently owned primordial stack and the largest user mapping, without
// widening bootfs admission.
const PRIMORDIAL_MAX_MAPPING_PAGES: usize = {
    let mut pages = PRIMORDIAL_BOOTFS_MAX_PAGES;
    if PRIMORDIAL_STACK_MAPPING_PAGES > pages {
        pages = PRIMORDIAL_STACK_MAPPING_PAGES;
    }
    if PRIMORDIAL_MAX_USER_MAPPING_PAGES > pages {
        pages = PRIMORDIAL_MAX_USER_MAPPING_PAGES;
    }
    pages
};
// One leaf entry per page, plus the parent entries a mapping observes or
// writes: each table it creates, and each existing one it walks, at three
// levels.
pub(super) const PRIMORDIAL_JOURNAL_ENTRIES: usize =
    PRIMORDIAL_MAX_MAPPING_PAGES + 3 * PRIMORDIAL_TABLE_CANDIDATES;
pub(super) const PRIMORDIAL_INVALIDATIONS: usize = PRIMORDIAL_MAX_MAPPING_PAGES;

// The native binding table and kernel-wide CPU identity must describe the
// same bounded carrier set; a capacity drift is a compile-time error.
const _: [(); crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] = [(); crate::cpu::CPU_CAPACITY];
const _: [(); PROCESSES] = [(); THREADS];
#[cfg(not(deepwyrm_production_product))]
const _: [(); PROCESSES] = [(); CHANNEL_PAIRS];
const _: [(); PROCESSES] = [(); SPACES];
const _: [(); PROCESSES] = [(); REGIONS];
const _: [(); PROCESSES] = [(); REGION_OBJECTS];
const _: [(); PROCESSES] = [(); EXECUTION_THREADS];
#[cfg(not(deepwyrm_production_product))]
const _: [(); 10] = [(); HANDLES];
#[cfg(deepwyrm_production_product)]
const _: [(); 96] = [(); HANDLES];
#[cfg(deepwyrm_production_product)]
const _: [(); 2] = [(); TIMERS];
const _: [(); 7] = [(); BOOTSTRAP_HANDLE_PEAK - INIT_MOVED_HANDLES];

// Mirrors the production arm of `PRIMORDIAL_BOOTFS_MAX_PAGES` exactly. Without
// it this is dead code in every selector build, and a selector that reaches the
// const's arm without reaching this one is a compile error rather than a silent
// mismatch.
const fn parse_production_bootfs_pages() -> usize {
    let bytes = env!("DEEPWYRM_BOOTFS_MAX_PAGES").as_bytes();
    let mut value = 0_usize;
    let mut index = 0;
    assert!(!bytes.is_empty(), "production bootfs page ceiling is empty");
    while index < bytes.len() {
        assert!(
            bytes[index].is_ascii_digit(),
            "production bootfs page ceiling is not decimal"
        );
        value = value * 10 + (bytes[index] - b'0') as usize;
        index += 1;
    }
    assert!(
        value > 0 && value <= 8192,
        "production bootfs page ceiling is out of range"
    );
    value
}

type Registry = ObjectRegistry<REGISTRY_OBJECTS>;
type Memory = MemoryObjectAuthority<MEMORY_OBJECTS, MEMORY_LEASES>;
type Channels = ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>;
type Tasks = TaskAuthority<TASK_GROUPS, PROCESSES, THREADS, HANDLES>;
type Spaces = AddressSpaceAuthority<SPACES, REGIONS>;
type Regions = AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>;
#[cfg(deepwyrm_dw1e_platform)]
type RuntimeInterruptPlatform = crate::device::Q35InterruptPlatform;
#[cfg(not(deepwyrm_dw1e_platform))]
type RuntimeInterruptPlatform = crate::device::InterruptPlatformModel<8>;

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
    boot_resource_grants: crate::boot::BootResourceGrantAuthority,
    device_resources: crate::device::DeviceResourceAuthority<8>,
    interrupts: crate::device::InterruptAuthority<8>,
    interrupt_platform: RuntimeInterruptPlatform,
    events: EventAuthority<EVENTS>,
    timers: TimerAuthority<TIMERS>,
    timer_expiries:
        IrqSpinMutex<[Option<crate::time::TimerExpiryToken>; crate::time::DEADLINE_QUEUE_CAPACITY]>,
    waits: WaitRegistry<WAITERS>,
}

impl crate::time::DeadlineWakeTarget for PrimordialRuntimeShared {
    fn wake_deadline(&self, key: crate::task::BlockWakeKey) {
        crate::wait::engine::claim_timeout_and_wake(&self.execution, key)
            .unwrap_or_else(|error| panic!("primordial deadline wake drifted: {error:?}"));
    }
}

impl crate::time::TimerExpiryTarget for PrimordialRuntimeShared {
    fn expire_timer(&self, token: crate::time::TimerExpiryToken) {
        let mut pending = self.timer_expiries.lock();
        let slot = pending
            .iter_mut()
            .find(|slot| slot.is_none())
            .unwrap_or_else(|| panic!("primordial timer-expiry inbox exhausted"));
        *slot = Some(token);
    }
}

// Safety notes (S2K). Each SAFETY comment on an unsafe block below cites one of these shared
// justifications by its bracketed tag. Tags from `syscall/live.rs` ([CARRIER], [ENTRY-REF]) are
// defined there.
//
// [P-ONESHOT] Each static storage cell here (`SHARED_RUNTIME_STORAGE`) is written exactly once, on the BSP, by the caller that wins its
// state word's 0->1 exchange, and read only after that word's Release store of 2 is observed with
// Acquire. Nothing writes the cell again; later mutation goes through the synchronized types inside
// it.
//
// [P-PLAN] The `prepare_*_on` / `poll_*_on` scheduler and service facades are `unsafe` because they
// trust two facts the types cannot check: the CPU argument is the physically current CPU, running
// on the current Thread's bound kernel stack, and the entry is the fixed
// `first_run_thread_entry_rip`. The entry is always passed literally. A carrier is built for its
// facade's own CPU (`on`, S2K-6), and a facade is reached only through its own CPU's binding. The
// trait methods that lead here (`prepare_preemption`, `prepare_suspend`, `poll_idle_suspend`) are
// called only by the syscall trampoline and timer pre-IRET gate in `syscall/live.rs`, which meet
// their `# Safety`.
//
// [P-HANDOFF] Divergent handoffs (terminal reaper, rendezvous reaper, AP idle scheduler) run on a
// CPU-private stack with IF clear, never on the Thread stack they hand to. Each first rebinds the
// entry record to the next Thread's stack (`bind_current_thread_stack`), then either IRETs to a
// fresh Thread through `enter_bound_validated_user`, which rechecks that binding, or resumes the
// Thread's saved continuation with `abandon_to_kernel_continuation`. The handoff frame is abandoned
// and nothing refers into it afterwards. A fresh Thread (continuation 0) has never run, so nothing
// lives on its stack and building its first-run frame there is exclusive.
//
// [P-PUBLISHER] `LivePlatform` exists only while `enter` constructs the primordial Process.
// Construction maps and unmaps only in the primordial root region (`AuthorityPrimordialBackend`),
// whose address space `enter` then binds to this same `active.root`
// (`bind_primordial_address_space`). The roles and tracked target passed with it serialize that
// root, and `LivePlatform`'s `&mut active` excludes any other publisher for its lifetime.
//
// [P-FACADE] (F1, S2K) `enter` builds the facade array into its one-shot static storage
// (`PRIMORDIAL_FACADES`, S2K-4) and converts the storage's one `&'static mut`, once, into one raw
// base pointer; that reference is consumed there and never used again. Every later
// access to a facade, including its publication (`bind_runtime_carrier_facades` publishes
// `base.add(cpu)` itself), admission, the BSP's lock and release, and CPU0's entry
// (`enter_published_native_syscall_runtime`), goes through a pointer derived from that base.
// References are created only for one scoped use (a handle's `lock`) and never over a published
// facade while another CPU uses it. So no retag ever sits between a published pointer and its
// allocation, and the published addresses stay valid under Stacked and Tree Borrows.

/// The per-CPU runtime carrier facades, owned once for the kernel's lifetime
/// (S2K-4, reset R2D) and reached only through their published pointers
/// ([P-FACADE]).
static PRIMORDIAL_FACADES: crate::one_shot::OneShotStorage<
    [RuntimeCarrierFacade<
        'static,
        'static,
        { crate::BOOTSTRAP_FRAME_RANGE_CAPACITY },
        { crate::BOOTSTRAP_FRAME_ROLE_CAPACITY },
    >; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
> = crate::one_shot::OneShotStorage::new();

/// The per-CPU quantum-expiry publishers, owned once for the kernel's lifetime
/// beside the facades and reached only through their published pointers
/// ([P-FACADE]).
static PRIMORDIAL_QUANTUM_EXPIRY: crate::one_shot::OneShotStorage<
    [QuantumExpiryPublisher; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
> = crate::one_shot::OneShotStorage::new();

/// The primordial runtime's authority lock and the carrier it guards, owned
/// once for the kernel's lifetime (S2K-4, reset R2D).
static PRIMORDIAL_RUNTIME_AUTHORITY: crate::one_shot::OneShotStorage<
    RuntimeAuthorityLock<
        PrimordialRuntimeState<
            'static,
            { crate::BOOTSTRAP_FRAME_RANGE_CAPACITY },
            { crate::BOOTSTRAP_FRAME_ROLE_CAPACITY },
        >,
    >,
> = crate::one_shot::OneShotStorage::new();

/// The primordial runtime's paging authority, P, owned once for the kernel's
/// lifetime beside the runtime authority, T, and reached only beneath a T
/// guard (D1 commit 3, design §11.2.4).
static PRIMORDIAL_PAGING: crate::one_shot::OneShotStorage<
    PagingLock<super::PrimordialActivePaging>,
> = crate::one_shot::OneShotStorage::new();

/// The shootdown-initiator lock, S (D1 option B, design §11.2.9): one TLB
/// shootdown in flight system-wide. Taken beneath P, after T.
static PRIMORDIAL_SHOOTDOWN_INITIATOR: ShootdownInitiatorLock =
    ShootdownInitiatorLock::new(user_access::service_local_tlb_shootdown);

// Pin budget (D1 commit 6, design §11.2.3 family B). A family-B output pin
// now lives across a runtime-authority hold, one per CPU, while the CPU in
// the hold may hold up to three batch pins and a family-A copy holds one
// under P. Taking the coordinator's bound of three transient pins per CPU,
// the transient demand must fit the tracker. Suspended waits' owned pins
// come on top, at most one per Thread; that budget is reported with this
// commit rather than asserted (E8 and fairness select 64 Threads).
const _: () = assert!(
    super::E5_USER_PIN_CAPACITY >= 3 * crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT,
    "the user-pin tracker cannot hold every CPU's transient usercopy pins"
);

/// The paging authority P guards.
type RuntimePaging<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> =
    ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>;

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

/// CPU-local immutable identity over the stationary synchronized runtime.
struct PendingRemoteProcessTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedProcessTermination<THREADS>,
    deferred: [Option<crate::arch::x86_64::rendezvous::DeferredReclaim<()>>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct PendingRemoteTaskGroupTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedTaskGroupTermination<PROCESSES, THREADS>,
    deferred: [Option<crate::arch::x86_64::rendezvous::DeferredReclaim<()>>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct PendingRemoteThreadTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedThreadTermination<THREADS>,
    deferred: [Option<crate::arch::x86_64::rendezvous::DeferredReclaim<()>>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

enum PendingRemoteTermination {
    Process(PendingRemoteProcessTermination),
    TaskGroup(PendingRemoteTaskGroupTermination),
    Thread(PendingRemoteThreadTermination),
}

struct PreparedRemoteProcessTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedProcessTermination<THREADS>,
    identities: [Option<crate::arch::x86_64::rendezvous::StopIdentity>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct PreparedRemoteTaskGroupTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedTaskGroupTermination<PROCESSES, THREADS>,
    identities: [Option<crate::arch::x86_64::rendezvous::StopIdentity>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct PreparedRemoteThreadTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedThreadTermination<THREADS>,
    identities: [Option<crate::arch::x86_64::rendezvous::StopIdentity>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct TerminalStopPlan {
    identities: [Option<crate::arch::x86_64::rendezvous::StopIdentity>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    unentered: [Option<crate::task::SchedulerExecutionClaim>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

enum ProcessTerminationPreparation {
    Retry,
    Immediate(NativeSyscallResult),
    Remote(PreparedRemoteProcessTermination),
}

enum TaskGroupTerminationPreparation {
    Immediate(NativeSyscallResult),
    Remote(PreparedRemoteTaskGroupTermination),
}

enum ThreadTerminationPreparation {
    Immediate(NativeSyscallResult),
    Remote(PreparedRemoteThreadTermination),
}

/// Waits, guard-free, for every published remote Stop's exact
/// acknowledgement. The token keeps the wait out of any runtime-authority
/// guard: a stopped CPU acknowledges from its own safe point, which may need
/// that authority.
fn await_remote_stop_permits(
    deferred: [Option<crate::arch::x86_64::rendezvous::DeferredReclaim<()>>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    _guard_free: GuardFree<'_>,
) -> [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
    crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] {
    let mut permits = core::array::from_fn(|_| None);
    for (cpu_index, deferred) in deferred.into_iter().enumerate() {
        let Some(deferred) = deferred else {
            continue;
        };
        let ((), permit) = crate::arch::x86_64::idle::await_live_remote_stop(deferred);
        permits[cpu_index] = Some(permit);
    }
    permits
}

struct RuntimeCarrierFacade<
    'runtime,
    'roles,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    cpu: crate::cpu::CpuIndex,
    /// This CPU's only way to acquire the runtime authority.
    runtime: RuntimeAuthorityHandle<
        'runtime,
        PrimordialRuntimeState<'roles, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    shared: &'static PrimordialRuntimeShared,
    /// The paging lock P, which this CPU takes alone only for a guard-free
    /// usercopy (D1 commit 5); a carrier reaches it beneath its guard.
    paging: &'runtime PagingLock<RuntimePaging<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    /// This CPU's owner-local runtime facts, lent to its carrier for each
    /// guard hold (S2K-6, design §11.1).
    owned: CpuOwnedState,
    admission: Option<(
        crate::task::CarrierAdmissionTicket,
        crate::task::CarrierResourceTuple,
    )>,
    admission_entered: bool,
    pending_remote_termination: Option<PendingRemoteTermination>,
}

/// One CPU's quantum-expiry publisher (S2K-6, [CARRIER] gap 2 in
/// `syscall/live.rs`). Its own per-CPU object beside the facade, published
/// with the facade, so the timer interrupt and synchronous quantum
/// cancellation publish an expiry without reborrowing a facade that a
/// suspended frame on this CPU still holds.
///
/// It publishes without the runtime authority (D1 commit 2, design §11.2.4),
/// so nothing in interrupt context takes that lock. Publication is one
/// `CooperativeScheduler` operation under the scheduler's own
/// `IrqSpinMutex`. It writes only the publishing CPU's `quantum` and
/// `need_resched` slots, the event accounting, and the selector-28 fixture,
/// and it accepts only the ticket armed on that CPU for its exact running
/// claim. No runtime-guard holder depends on excluding it:
/// - on this CPU, a guard holder runs with IF clear and every synchronous
///   publication path runs guard-free, so the two never overlap;
/// - on another CPU, the guard-held scheduler operations that read this
///   CPU's slots (`stop_running_claim_on`,
///   `retire_unentered_running_claim_on`, the DW1-B counter snapshot) each
///   run under the scheduler lock. They take an armed quantum or a published
///   expiry, whichever they find. The selector-28 gate reports `Ready` only
///   after the last of publication's three steps.
struct QuantumExpiryPublisher {
    shared: &'static PrimordialRuntimeShared,
}

/// A family-G shootdown published in its syscall's first hold and awaited
/// after it, with neither T nor P held (D1 option B3, design §11.2.9): the
/// pending request, the driver that notified its targets, and S, released
/// only on its permit.
struct FamilyGShootdown {
    pending: crate::memory::address_region::PendingShootdown<{ crate::cpu::CPU_CAPACITY }>,
    driver: user_access::LiveTlbShootdownDriver,
    initiator: ShootdownInitiatorGuard<'static>,
}

/// `AddressRegionMap`'s input, copied in and validated, and its output,
/// pinned, with P alone before the first hold (D1 commit 9), or the status
/// the adapter's order fails it with.
type MapInput = Result<
    (
        deepwyrm_abi::DwAddressRegionMapArgsV1,
        MemoryProtection,
        user_access::OwnedLiveUserOutput,
    ),
    deepwyrm_abi::DwStatus,
>;

/// One step of an `AddressRegionMap` (DW2 M4b): its arguments, its
/// protection and the room its placement must find, or the status.
type MapStep = crate::syscall::MapStep<MemoryProtection>;

/// The largest step of a family-G call made in steps (DW2 M4b): one
/// journal batch, so a step holds the global locks for one batch.
const FAMILY_G_STEP_BYTES: u64 = PRIMORDIAL_MAX_USER_MAPPING_PAGES as u64 * PAGE_SIZE;
/// One hold of an on-demand commit (DW2 M6 §8.2, §8.11 R1): it zeroes every
/// frame it takes, so it is kept well below a family-G step.
const ON_DEMAND_COMMIT_STEP_BYTES: u64 = 2 * 1024 * 1024;

/// The first hold of a family-G syscall (D1 option B3).
#[must_use = "a family-G syscall leaves through ready_to_return, now or after its acknowledgement"]
enum FamilyGBegun {
    /// Settled in the first hold, and left through `ready_to_return`.
    Returned(crate::syscall::native::ReturnReady),
    /// An inner step of a call made in steps (DW2 M4b), settled in its
    /// first hold with its finalizers drained; the call goes on.
    Stepped {
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        status: deepwyrm_abi::DwStatus,
    },
    /// Published: the facade awaits the acknowledgement, releases S, and
    /// finishes in a last hold.
    Published {
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        status: deepwyrm_abi::DwStatus,
        shootdown: FamilyGShootdown,
    },
}

/// A resumed F operation's user effects, recorded under the runtime
/// authority and applied with P alone after it (D1 commit 8, design §11.2.3
/// family E). The output and the atomic word were pinned before the
/// operation suspended, so applying either cannot fail. Between the hold
/// and the application the Thread runs with IF clear and passes no safe
/// point, so no stop or teardown can take the pin first.
#[must_use = "a resumed wait's output settlement or pin release must be applied"]
struct ResumeSettlement {
    root: super::UserCopyRoot,
    process: ProcessKey,
    output: Option<(
        user_access::OwnedLiveUserOutput,
        crate::syscall::WaitResultBytes,
    )>,
    pin: Option<user_access::OwnedLiveAtomicU32>,
}

impl crate::syscall::native::NativeQuantumExpiry for QuantumExpiryPublisher {
    fn publish_quantum_expiry(
        &mut self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<bool, crate::task::SchedulerError> {
        self.shared.execution.publish_quantum_expiry(ticket)
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    RuntimeCarrierFacade<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn drain_quantum_cancellation_detached(&mut self) {
        let ticket = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            runtime.take_local_scheduler_quantum_cancellation()
        };
        let Some(ticket) = ticket else {
            return;
        };
        cancel_scheduler_quantum_guard_free(ticket, self.runtime.guard_free());
        let mut guard = self.runtime.lock();
        let runtime = guard.on(&mut self.owned);
        runtime.commit_local_scheduler_quantum_cancellation(ticket);
    }

    fn finish_scheduler_root_switch_detached(
        &mut self,
        prepared: Option<PreparedSchedulerRootSwitch>,
    ) {
        let Some(prepared) = prepared else {
            return;
        };
        let executed = match prepared.execute(self.runtime.guard_free()) {
            Ok(executed) => executed,
            Err(failure) => {
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on_root_switch_flight(&mut self.owned);
                let error = runtime.cancel_scheduler_root_switch(failure);
                panic!("detached scheduler root switch failed before CR3: {error:?}")
            }
        };
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on_root_switch_flight(&mut self.owned);
        runtime.commit_scheduler_root_switch(executed);
    }

    /// Reconciles the logical scheduler root after acknowledged remote Stops.
    /// The local syscall continuation may already be the exact unpublished
    /// suspended owner while its logical Running slot is empty or names a
    /// not-yet-entered replacement. The suspended physical claim is
    /// authoritative in either case, and its active Process root remains live
    /// until terminal retirement installs the divergent handoff token.
    fn synchronize_scheduler_current_after_remote_stops_detached(&mut self) {
        let prepared =
            {
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on(&mut self.owned);
                match runtime.core.shared.execution.suspended_claim_on(self.cpu) {
                    Some(suspended) => {
                        assert_eq!(
                            suspended.thread(),
                            runtime.own.scheduled().thread,
                            "remote-stop completion retained another physical scheduler claim"
                        );
                        assert!(
                            runtime.own.active_root.as_ref().is_some(),
                            "remote-stop completion lost the physical caller Process root"
                        );
                        None
                    }
                    None => match runtime
                        .core
                        .shared
                        .execution
                        .terminal_scheduler_current_on(&runtime.core.tasks, self.cpu)
                        .unwrap_or_else(|error| {
                            panic!("scheduler-current terminal state lookup failed: {error:?}")
                        }) {
                        Some(terminal) => {
                            assert_eq!(
                                terminal,
                                runtime.own.scheduled().thread,
                                "remote-stop completion found another terminal scheduler current"
                            );
                            let owner = runtime.core.tasks.thread_process(terminal).unwrap_or_else(
                                |error| {
                                    panic!("terminal scheduler-current lost its Process: {error:?}")
                                },
                            );
                            let active_root = runtime.own.active_root.as_ref().unwrap_or_else(|| {
                            panic!("remote-stop completion lost the terminal caller Process root")
                        });
                            assert_eq!(
                                active_root.process(),
                                owner,
                                "remote-stop completion retained another Process root"
                            );
                            None
                        }
                        None => runtime.prepare_scheduler_root_switch(),
                    },
                }
            };
        self.finish_scheduler_root_switch_detached(prepared);
    }

    /// Synchronizes the scheduler-current root without crossing an already
    /// published remote Stop. Terminal preparation deliberately moves a
    /// remote current's execution resources while retaining its scheduler
    /// claim until the target acknowledges that Stop. Preparation and mailbox
    /// publication straddle the shared runtime guard, so a target that enters
    /// that narrow gap waits for publication before root synchronization.
    fn synchronize_scheduler_current_at_safe_point_detached(&mut self) -> bool {
        let prepared = loop {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            if matches!(
                crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
                crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
            ) {
                return false;
            }
            if runtime
                .core
                .shared
                .execution
                .terminal_scheduler_current_on(&runtime.core.tasks, self.cpu)
                .unwrap_or_else(|error| {
                    panic!("scheduler-current terminal state lookup failed: {error:?}")
                })
                .is_some()
            {
                drop(guard);
                core::hint::spin_loop();
                continue;
            }
            break runtime.prepare_scheduler_root_switch();
        };
        let Some(prepared) = prepared else {
            return true;
        };
        let executed = match prepared.execute(self.runtime.guard_free()) {
            Ok(executed) => executed,
            Err(failure) => {
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on_root_switch_flight(&mut self.owned);
                let error = runtime.cancel_scheduler_root_switch(failure);
                panic!("detached scheduler root switch failed before CR3: {error:?}")
            }
        };
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on_root_switch_flight(&mut self.owned);
        runtime.commit_scheduler_root_switch(executed);
        !matches!(
            crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
        )
    }

    /// Family A (design §11.2.3, D1 commit 5): a syscall that needs no
    /// runtime authority, only its usercopy. The safe-point synchronization
    /// and one short guard hold run as for every syscall. That hold checks
    /// the running Thread, reserves the phase, and copies the CPU's root
    /// identity. The usercopy then runs with neither T nor P beneath it,
    /// taking P alone through a `GuardFree`, so H0 §12.8 holds by
    /// construction. A last hold commits the phase and leaves through
    /// `ready_to_return`. `None` for every other request.
    // Kept out of line so the ordinary syscall handler's frame, which the
    // stack oracles measure, does not absorb this family A path's locals.
    #[inline(never)]
    fn handle_guard_free_usercopy(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        if !matches!(
            request,
            NativeSyscallRequest::AbiGetInfo { .. } | NativeSyscallRequest::ClockGet { .. }
        ) {
            return None;
        }
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let result = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            NativeSyscallResult::returning(match request {
                NativeSyscallRequest::AbiGetInfo {
                    out_info,
                    out_size,
                    out_required_size,
                } => crate::syscall::abi_get_info_with_features(
                    &mut user,
                    out_info,
                    out_size,
                    out_required_size,
                    deepwyrm_abi::DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT,
                ),
                NativeSyscallRequest::ClockGet {
                    clock_id,
                    out_nanoseconds,
                } => crate::syscall::clock_get_with(&mut user, clock_id, out_nanoseconds, || {
                    crate::time::monotonic_now().map_err(|_| deepwyrm_abi::DW_STATUS_BAD_STATE)
                }),
                _ => unreachable!("guard-free usercopy classification drifted"),
            })
        };
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        runtime.commit_runtime_phase(phase);
        Some(Ok(runtime.ready_to_return(result)))
    }

    /// Family B (design §11.2.3, D1 commits 6 and 6b): a syscall whose only
    /// usercopy is fixed-size output, with at most an atomic pin besides.
    /// Its outputs are preflighted and pinned before the authority work, and
    /// written after it, with no runtime lock held for either.
    /// 1. As for family A, a first hold checks the Thread, reserves the
    ///    phase, and copies the root identity.
    /// 2. With P alone (`GuardFree`), every output range is pinned as an
    ///    owned output. `AtomicWake` pins its address first, and stops there
    ///    if that pin fails, as the adapter does.
    /// 3. A second hold runs the unchanged adapter sequence against a
    ///    `DeferredUserOutput`. It keeps its order of validation, then
    ///    preflight, then authority work, then commit, so statuses are
    ///    unchanged. The hold then commits the phase and leaves through
    ///    `ready_to_return`.
    /// 4. With P alone again, the atomic pin is released, and each recorded
    ///    output goes into its pinned output, which cannot fail. Every
    ///    output that was not written is discarded.
    /// `None` for every other request.
    // Kept out of line so the ordinary syscall handler's frame, which the
    // stack oracles measure, does not absorb this family B path's locals.
    #[inline(never)]
    fn handle_deferred_output(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let handle = |address| [Some((address, 8, 8)), None, None];
        let outputs: [Option<(deepwyrm_abi::DwUserAddress, usize, u64)>; 3] = match request {
            NativeSyscallRequest::HandleDuplicate { out_handle, .. }
            | NativeSyscallRequest::TaskGroupCreate { out_handle, .. } => handle(out_handle),
            NativeSyscallRequest::ThreadCreate { out_thread, .. } => handle(out_thread),
            NativeSyscallRequest::DeviceResourceClaim { out_resource, .. } => handle(out_resource),
            NativeSyscallRequest::DevicePioRead { out_value, .. }
            | NativeSyscallRequest::DevicePciConfigRead { out_value, .. } => {
                [Some((out_value, 4, 4)), None, None]
            }
            NativeSyscallRequest::InterruptCreate { out_interrupt, .. } => handle(out_interrupt),
            NativeSyscallRequest::DeviceMmioObjectCreate {
                out_memory_object, ..
            } => handle(out_memory_object),
            NativeSyscallRequest::DmaMap { out_iova, .. } => [Some((out_iova, 8, 8)), None, None],
            NativeSyscallRequest::EventCreate { out_event, .. } => handle(out_event),
            NativeSyscallRequest::TimerCreate { out_timer, .. } => handle(out_timer),
            NativeSyscallRequest::ChannelCreate {
                out_endpoint0,
                out_endpoint1,
                ..
            } => [
                Some((out_endpoint0, 8, 8)),
                Some((out_endpoint1, 8, 8)),
                None,
            ],
            NativeSyscallRequest::AtomicWake { out_woken, .. } => {
                [Some((out_woken, 4, 4)), None, None]
            }
            NativeSyscallRequest::MemoryObjectCreate { out_handle, .. } => handle(out_handle),
            _ => return None,
        };
        // MemoryObjectCreate's backing, allocated with P alone before the
        // hold, when its size is one the adapter can reach its allocation
        // with (D1 commit 6c).
        // An on-demand object's backing is its index root alone, charged
        // as one page (DW2 M6 §8.4).
        let (backing_pages, on_demand) = match request {
            NativeSyscallRequest::MemoryObjectCreate {
                byte_len, flags, ..
            } if byte_len != 0
                && byte_len.is_multiple_of(u64::from(deepwyrm_abi::DW_BASE_PAGE_SIZE)) =>
            {
                let pages = byte_len / u64::from(deepwyrm_abi::DW_BASE_PAGE_SIZE);
                match flags {
                    0 => (Some(pages), false),
                    flags
                        if flags == deepwyrm_abi::DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND.0
                            && pages <= crate::memory::frame_roles::INDEX_MAX_PAGES =>
                    {
                        (Some(pages), true)
                    }
                    _ => (None, false),
                }
            }
            _ => (None, false),
        };
        let cpu = self.cpu;
        let Ok(((phase, root, process), quota_allows)) = self
            .with_synchronized_runtime_at_safe_point(|runtime| {
                if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                    runtime.service_pending_timer_expiries_on_bootstrap();
                }
                let prepared = runtime.prepare_guard_free_usercopy();
                // Frames are allocated only for a request its quota admits
                // now; the adapter's admission under the next hold decides.
                // Admitted pages stay reserved until the final hold, so a
                // concurrent create cannot allocate past the limit (§7.3 R7).
                let allows = backing_pages.is_none_or(|pages| {
                    let process = runtime.own.scheduled().process;
                    crate::syscall::reserve_memory_object_pages(
                        &mut runtime.core.registry,
                        &runtime.core.tasks,
                        process,
                        if on_demand { 1 } else { pages },
                        cpu.index(),
                    )
                });
                (prepared, allows)
            })
        else {
            return Some(Err(()));
        };
        // Every range the adapter will preflight, or `None` if one cannot be
        // formed (the adapter then fails at that range, before any pin).
        let mut ranges = [None, None, None];
        let mut formed = true;
        for (index, output) in outputs.into_iter().enumerate() {
            if let Some((address, byte_len, alignment)) = output {
                match crate::syscall::output_range(address, byte_len, alignment) {
                    Ok(range) => ranges[index] = Some(range),
                    Err(_) => formed = false,
                }
            }
        }
        let (atomic_pin, pinned, backing) = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            let atomic_pin = match request {
                NativeSyscallRequest::AtomicWake { address, .. } => Some(
                    crate::syscall::FAtomicUserAccess::pin_atomic_u32(&mut user, address),
                ),
                _ => None,
            };
            let pinned = if !formed || matches!(atomic_pin, Some(Err(_))) {
                None
            } else {
                let mut owned = [None, None, None];
                let mut complete = true;
                for (index, range) in ranges.into_iter().enumerate() {
                    let Some(range) = range else {
                        continue;
                    };
                    match user.preflight_owned_output(range) {
                        Ok(output) => owned[index] = Some(output),
                        Err(_) => {
                            complete = false;
                            break;
                        }
                    }
                }
                if !complete {
                    for output in owned.into_iter().flatten() {
                        user.discard_owned_output(output)
                            .unwrap_or_else(|_| panic!("partial deferred output discard drifted"));
                    }
                    None
                } else {
                    Some(owned)
                }
            };
            let backing = match (backing_pages, &pinned) {
                // Refused by quota: no frames. Should the adapter admit after
                // all (usage fell in between), the request fails, not panics.
                (Some(_), Some(_)) if !quota_allows => {
                    Some(Err(deepwyrm_abi::DW_STATUS_NO_RESOURCES))
                }
                // An index root, zeroed as it is allocated (DW2 M6).
                (Some(page_count), Some(_)) if on_demand => Some(
                    user.allocate_on_demand_backing(page_count)
                        .map(EarlyBacking::Ready)
                        .map_err(|_| deepwyrm_abi::DW_STATUS_NO_RESOURCES),
                ),
                // Allocated here, zeroed below in steps (DW2 M4b).
                (Some(page_count), Some(_)) => Some(
                    user.allocate_backing(page_count)
                        .map(EarlyBacking::Unzeroed)
                        .map_err(|_| deepwyrm_abi::DW_STATUS_NO_RESOURCES),
                ),
                _ => None,
            };
            (atomic_pin, pinned, backing)
        };
        let backing = backing.map(|early| {
            early.and_then(|early| match early {
                EarlyBacking::Ready(grant) => Ok(grant),
                EarlyBacking::Unzeroed(allocation) => {
                    self.zero_backing_in_steps(root, process, allocation)
                }
            })
        });
        let pin_taken = matches!(atomic_pin, Some(Ok(_)));
        let mut deferred =
            crate::memory::usercopy::DeferredUserOutput::batch(pinned.as_ref().map(|_| ranges));
        let mut rollback = None;
        let (ready, released_pin) = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            // The adapter admits again, against the others' reservations.
            runtime.core.registry.release_reserved_pages(cpu.index());
            let (status, released_pin) = match (request, atomic_pin) {
                (NativeSyscallRequest::MemoryObjectCreate { .. }, None) => {
                    let mut access = crate::syscall::DeferredMemoryObjectAccess::new(
                        core::mem::replace(
                            &mut deferred,
                            crate::memory::usercopy::DeferredUserOutput::batch(None),
                        ),
                        backing_pages.unwrap_or(0),
                        backing,
                    );
                    let status = runtime.run_deferred_output_with(request, &mut access);
                    let (output, unused) = access.into_parts();
                    deferred = output;
                    rollback = unused;
                    (status, None)
                }
                (
                    NativeSyscallRequest::AtomicWake {
                        address,
                        count,
                        out_woken,
                    },
                    Some(atomic_pin),
                ) => runtime.run_deferred_atomic_wake(
                    &mut deferred,
                    atomic_pin,
                    address,
                    count,
                    out_woken,
                ),
                (request, None) => (runtime.run_deferred_output(request, &mut deferred), None),
                _ => unreachable!("deferred atomic pin classification drifted"),
            };
            runtime.commit_runtime_phase(phase);
            (
                runtime.ready_to_return(NativeSyscallResult::returning(status)),
                released_pin,
            )
        };
        assert_eq!(
            released_pin.is_some(),
            pin_taken,
            "a deferred atomic pin was not returned for release"
        );
        if released_pin.is_some() || pinned.is_some() || rollback.is_some() {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            if let Some(grant) = rollback {
                crate::syscall::MemoryObjectBackingAccess::rollback_object_backing(
                    &mut user, grant,
                );
            }
            if let Some(pin) = released_pin {
                crate::syscall::FAtomicUserAccess::release_atomic_u32(&mut user, pin);
            }
            for (index, output) in pinned.into_iter().flatten().enumerate() {
                let Some(output) = output else {
                    continue;
                };
                match deferred.written_at(index) {
                    Some(bytes) => user
                        .commit_owned_output(output, bytes)
                        .unwrap_or_else(|_| panic!("pinned deferred output commit drifted")),
                    None => user
                        .discard_owned_output(output)
                        .unwrap_or_else(|_| panic!("pinned deferred output discard drifted")),
                }
            }
        }
        Some(Ok(ready))
    }

    /// `ObjectGetInfoV1` (design §11.2.3 family B, D1 commit 6d). It is a
    /// read-only query whose info length is known only after the query.
    /// 1. A first hold as for family A.
    /// 2. With P alone, the required-size output is formed and pinned as an
    ///    owned output, its preflight coming first as in the adapter.
    /// 3. A second hold runs only the query.
    /// 4. With P alone again, the adapter's copy-out sequence runs: the
    ///    required size alone if the buffer is too small, otherwise the info
    ///    range's preflight and copy, then the required size.
    /// 5. A last hold commits the phase and leaves through `ready_to_return`.
    /// Statuses and their precedence are the adapter's. No usercopy runs
    /// under a runtime lock. `None` for every other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_object_info(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let NativeSyscallRequest::ObjectGetInfoV1 {
            handle,
            topic,
            out_info,
            out_size,
            out_required_size,
        } = request
        else {
            return None;
        };
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let required = crate::syscall::output_range(out_required_size, 8, 8).and_then(|range| {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            user.preflight_owned_output(range)
                .map_err(|_| deepwyrm_abi::DW_STATUS_BAD_ADDRESS)
        });
        let status = match required {
            Err(status) => status,
            Ok(required) => {
                let queried = {
                    let mut guard = self.runtime.lock();
                    let mut runtime = guard.on(&mut self.owned);
                    runtime.query_object_info(handle, topic)
                };
                let mut access = self.paging.guard_free_access(self.runtime.guard_free());
                let mut paging = access.lock();
                let mut user = paging
                    .guard_free_value()
                    .usercopy_process_address_space(root, process);
                match queried {
                    Err(status) => {
                        user.discard_owned_output(required)
                            .unwrap_or_else(|_| panic!("pinned info output discard drifted"));
                        status
                    }
                    Ok(mut encoded) => {
                        // DW2 M5: only the root TaskGroup's memory record
                        // carries free frames, read here under P.
                        if encoded.wants_free_pages() {
                            encoded.fill_free_pages(user.available_frames());
                        }
                        crate::syscall::object_get_info_v1_copy_out(
                            &mut user, required, &encoded, out_info, out_size,
                        )
                    }
                }
            }
        };
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        runtime.commit_runtime_phase(phase);
        Some(Ok(
            runtime.ready_to_return(NativeSyscallResult::returning(status))
        ))
    }

    /// `ChannelSend` (design §11.2.3 family D, D1 commit 7). It copies in
    /// before the authority work.
    /// 1. A first hold as for family A.
    /// 2. With P alone, `channel_send_snapshot` runs the adapter's first half:
    ///    argument validation, the transfer-record snapshot and its
    ///    validation, and the payload snapshot into this CPU's owner-local
    ///    Channel staging.
    /// 3. A second hold runs the second half (`channel_send_commit`), commits
    ///    the phase, and leaves through `ready_to_return`.
    /// The halves run in the adapter's order, so statuses and their
    /// precedence are unchanged. No usercopy runs under a runtime lock.
    /// `None` for every other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_channel_send(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let NativeSyscallRequest::ChannelSend {
            channel,
            bytes,
            byte_len,
            transfers,
            transfer_count,
            flags,
        } = request
        else {
            return None;
        };
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let snapshot = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            crate::syscall::channel_send_snapshot(
                &mut user,
                &mut self.owned.channel_staging[..],
                bytes,
                byte_len,
                transfers,
                transfer_count,
                flags,
            )
        };
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        let status = match snapshot {
            Err(status) => status,
            Ok(inputs) => runtime.commit_channel_send(&inputs, channel),
        };
        runtime.commit_runtime_phase(phase);
        Some(Ok(
            runtime.ready_to_return(NativeSyscallResult::returning(status))
        ))
    }

    /// `ChannelReceive` (design §11.2.3 family F and §11.2.8 decision 4, D1
    /// commit 7b): a two-phase reserve. It follows `channel_receive`'s order,
    /// split where it needs user memory.
    /// 1. A first hold as for family A.
    /// 2. With P alone: capacity validation and the result probe.
    /// 3. A second hold: handle resolution and the head reservation.
    /// 4. With P alone: the exact-size output ranges are formed and pinned as
    ///    owned outputs, all or nothing.
    /// 5. A third hold: the irreversible dequeue and handle publication, but
    ///    only if every pin succeeded. Otherwise the reservation is
    ///    cancelled (too small, or abandoned with the formation or pin
    ///    status). Then the phase is committed and the syscall leaves
    ///    through `ready_to_return`.
    /// 6. With P alone: the outputs are written into their pins.
    ///
    /// The reservation lives in this frame only. See
    /// `syscall::ChannelReceiveHold` for the abandonment invariant.
    /// `None` for every other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_channel_receive(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let NativeSyscallRequest::ChannelReceive {
            channel,
            out_bytes,
            byte_capacity,
            out_handles,
            handle_capacity,
            out_result,
        } = request
        else {
            return None;
        };
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let precheck = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            crate::syscall::channel_receive_precheck(
                &mut user,
                byte_capacity,
                handle_capacity,
                out_result,
            )
        };
        let held = match precheck {
            Err(status) => Err(status),
            Ok(()) => {
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on(&mut self.owned);
                runtime.reserve_channel_receive(channel)
            }
        };
        let hold = match held {
            Err(status) => {
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on(&mut self.owned);
                runtime.commit_runtime_phase(phase);
                return Some(Ok(
                    runtime.ready_to_return(NativeSyscallResult::returning(status))
                ));
            }
            Ok(hold) => hold,
        };
        // Form and pin every output, all or nothing, with P alone.
        let outputs = crate::syscall::channel_receive_output_ranges(
            hold.info(),
            byte_capacity,
            handle_capacity,
            out_bytes,
            out_handles,
            out_result,
        );
        let mut pins = [None, None, None];
        let pinned: Result<bool, deepwyrm_abi::DwStatus> = match outputs {
            Err(status) => Err(status),
            Ok(outputs) => {
                let mut access = self.paging.guard_free_access(self.runtime.guard_free());
                let mut paging = access.lock();
                let mut user = paging
                    .guard_free_value()
                    .usercopy_process_address_space(root, process);
                let (too_small, ranges) = match outputs {
                    crate::syscall::ChannelReceiveOutputs::TooSmall(range) => {
                        (true, [None, None, Some(range)])
                    }
                    crate::syscall::ChannelReceiveOutputs::Fits(ranges) => (
                        false,
                        ranges.map(|(range, len)| (len != 0).then_some(range)),
                    ),
                };
                let mut complete = true;
                for (index, range) in ranges.into_iter().enumerate() {
                    let Some(range) = range else {
                        continue;
                    };
                    match user.preflight_owned_output(range) {
                        Ok(output) => pins[index] = Some(output),
                        Err(_) => {
                            complete = false;
                            break;
                        }
                    }
                }
                if complete {
                    Ok(too_small)
                } else {
                    for output in pins.iter_mut().filter_map(Option::take) {
                        user.discard_owned_output(output)
                            .unwrap_or_else(|_| panic!("partial receive output discard drifted"));
                    }
                    Err(deepwyrm_abi::DW_STATUS_BAD_ADDRESS)
                }
            }
        };
        enum Written {
            Nothing,
            TooSmall([u8; deepwyrm_abi::DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize]),
            Received(crate::syscall::ChannelReceiveCopyOut),
        }
        let (ready, written) = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            let (status, written) = match pinned {
                Err(status) => (
                    runtime.abandon_channel_receive(hold, status),
                    Written::Nothing,
                ),
                Ok(true) => (
                    deepwyrm_abi::DW_STATUS_BUFFER_TOO_SMALL,
                    Written::TooSmall(runtime.channel_receive_too_small(hold)),
                ),
                Ok(false) => match runtime.commit_channel_receive(hold) {
                    Ok(copy) => (deepwyrm_abi::DW_STATUS_SUCCESS, Written::Received(copy)),
                    Err(status) => (status, Written::Nothing),
                },
            };
            runtime.commit_runtime_phase(phase);
            (
                runtime.ready_to_return(NativeSyscallResult::returning(status)),
                written,
            )
        };
        if pins.iter().any(Option::is_some) {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            for (index, output) in pins.into_iter().enumerate() {
                let Some(output) = output else {
                    continue;
                };
                let bytes = match &written {
                    Written::Nothing => None,
                    Written::TooSmall(result) => Some(&result[..]),
                    Written::Received(copy) => {
                        Some(copy.output(index, &self.owned.channel_staging[..]))
                    }
                };
                match bytes {
                    Some(bytes) => user
                        .commit_owned_output(output, bytes)
                        .unwrap_or_else(|_| panic!("pinned receive output commit drifted")),
                    None => user
                        .discard_owned_output(output)
                        .unwrap_or_else(|_| panic!("pinned receive output discard drifted")),
                }
            }
        }
        Some(Ok(ready))
    }

    /// `ProcessCreate` (design §11.2.3 family D, D1 commit 7c). It copies its
    /// input in and pins its output before the authority work, and writes
    /// the result after it.
    /// 1. A first hold as for family A.
    /// 2. With P alone, `process_create_input` copies and validates the
    ///    arguments and pins the result output.
    /// 3. A second hold runs the F10 transaction. The child's architecture
    ///    root is reserved through P beneath the guard, which is a page-table
    ///    mutation, not a usercopy. The output's commit or discard is
    ///    recorded. The hold then commits the phase and leaves through
    ///    `ready_to_return`.
    /// 4. With P alone, the recorded result goes into the pinned output, or
    ///    the output is discarded.
    /// Statuses and their precedence are the adapter's. `None` for every
    /// other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_process_create(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let NativeSyscallRequest::ProcessCreate {
            args,
            args_size,
            out_result,
            result_size,
        } = request
        else {
            return None;
        };
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let prepared = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            crate::syscall::process_create_input(
                &mut user,
                args,
                args_size,
                out_result,
                result_size,
            )
        };
        let (ready, pending) = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            let (status, pending) = runtime.run_process_create(prepared);
            runtime.commit_runtime_phase(phase);
            (
                runtime.ready_to_return(NativeSyscallResult::returning(status)),
                pending,
            )
        };
        if let Some((output, result)) = pending {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            match result {
                Some(result) => user
                    .commit_owned_output(output, &result)
                    .unwrap_or_else(|_| panic!("pinned ProcessCreate output commit drifted")),
                None => user
                    .discard_owned_output(output)
                    .unwrap_or_else(|_| panic!("pinned ProcessCreate output discard drifted")),
            }
        }
        Some(Ok(ready))
    }

    /// `WaitOne` and `WaitMany` (design §11.2.3 family E, D1 commit 8).
    /// 1. A first hold as for family A.
    /// 2. With P alone, `wait_one_input` or `wait_many_input` checks the
    ///    signals or snapshots the items, and pins the result output.
    /// 3. A second hold resolves the items, registers the waiter and decides
    ///    on suspension, then commits the phase and leaves through
    ///    `ready_to_return`. A suspended wait keeps its output in its wait
    ///    operation, for the resume to settle.
    /// 4. A returning wait's result goes into the pinned output with P
    ///    alone, or the output is discarded.
    /// Statuses and their precedence are the adapter's. `None` for every
    /// other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_wait(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        if !matches!(
            request,
            NativeSyscallRequest::WaitOne { .. } | NativeSyscallRequest::WaitMany { .. }
        ) {
            return None;
        }
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let prepared = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            match request {
                NativeSyscallRequest::WaitOne {
                    handle,
                    signals,
                    deadline,
                    out_result,
                } => {
                    crate::syscall::wait_one_input(&mut user, handle, signals, deadline, out_result)
                }
                NativeSyscallRequest::WaitMany {
                    items,
                    item_count,
                    mode,
                    deadline,
                    out_result,
                } => crate::syscall::wait_many_input(
                    &mut user, items, item_count, mode, deadline, out_result,
                ),
                _ => unreachable!("wait classification drifted"),
            }
        };
        let (ready, settlement) = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            let (result, settlement) = runtime.begin_wait(prepared);
            runtime.commit_runtime_phase(phase);
            (runtime.ready_to_return(result), settlement)
        };
        if let Some((output, result)) = settlement {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            match result {
                Some(result) => user
                    .commit_owned_output(output, &result)
                    .unwrap_or_else(|_| panic!("pinned wait output commit drifted")),
                None => user
                    .discard_owned_output(output)
                    .unwrap_or_else(|_| panic!("pinned wait output discard drifted")),
            }
        }
        Some(Ok(ready))
    }

    /// `AtomicWait32` (design §11.2.3 family E, D1 commit 8b), futex-style:
    /// the compare-load runs with no runtime lock held.
    /// 1. A first hold as for family A.
    /// 2. With P alone, the word is pinned and loaded for the early compare.
    /// 3. A second hold resolves the stable key, makes the early compare,
    ///    checks a `NOW` deadline, then prepares the block and registers the
    ///    waiter, which a wake from now on finds.
    /// 4. With P alone, the word is loaded again through the pin: the second
    ///    compare.
    /// 5. A third hold settles: a wake or deadline that already won is
    ///    honored, a mismatch cancels the registration, and otherwise the pin
    ///    moves into the suspended operation and the block commits. It then
    ///    commits the phase and leaves through `ready_to_return`, as the
    ///    second hold does when the wait returns before registering.
    /// 6. With P alone, a pin that did not move is released.
    /// Statuses and their precedence are the adapter's. `None` for every
    /// other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_atomic_wait(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let NativeSyscallRequest::AtomicWait32 {
            address,
            expected,
            deadline,
        } = request
        else {
            return None;
        };
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let pinned = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            crate::syscall::FAtomicUserAccess::pin_atomic_u32(&mut user, address).map(|pin| {
                let observed =
                    crate::syscall::FAtomicUserAccess::load_atomic_u32_acquire(&mut user, &pin);
                (pin, observed)
            })
        };
        enum Registered {
            Returned(
                crate::syscall::native::ReturnReady,
                Option<user_access::OwnedLiveAtomicU32>,
            ),
            Pending(
                crate::atomic_wait::PendingAtomicWait,
                user_access::OwnedLiveAtomicU32,
                crate::arch::x86_64::syscall::RuntimePhaseReservation,
            ),
        }
        let registered = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            match runtime.register_atomic_wait(pinned, address, expected, deadline) {
                Err((status, pin)) => {
                    runtime.commit_runtime_phase(phase);
                    Registered::Returned(
                        runtime.ready_to_return(NativeSyscallResult::returning(status)),
                        pin,
                    )
                }
                Ok((pending, pin)) => Registered::Pending(pending, pin, phase),
            }
        };
        let (ready, pin) = match registered {
            Registered::Returned(ready, pin) => (ready, pin),
            Registered::Pending(pending, pin, phase) => {
                // The registration is published, and was released with the
                // runtime authority. The fence orders it before this load,
                // so a waker whose store this load misses finds the waiter.
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                let matched = {
                    let mut access = self.paging.guard_free_access(self.runtime.guard_free());
                    let mut paging = access.lock();
                    let mut user = paging
                        .guard_free_value()
                        .usercopy_process_address_space(root, process);
                    crate::syscall::FAtomicUserAccess::load_atomic_u32_acquire(&mut user, &pin)
                        == expected
                };
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on(&mut self.owned);
                let (result, pin) = runtime.settle_atomic_wait(pending, pin, matched);
                runtime.commit_runtime_phase(phase);
                (runtime.ready_to_return(result), pin)
            }
        };
        if let Some(pin) = pin {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            crate::syscall::FAtomicUserAccess::release_atomic_u32(&mut user, pin);
        }
        Some(Ok(ready))
    }

    /// `ThreadStart` (design §11.2.3 family D, D1 commit 9).
    /// 1. A first hold as for family A.
    /// 2. With P alone, `thread_start_input` copies in and validates the
    ///    arguments.
    /// 3. A second hold resolves the Thread, walks RIP and RSP on a
    ///    return-validation session (no usercopy), starts it, commits the
    ///    phase and leaves through `ready_to_return`.
    /// Statuses and their precedence are the adapter's. `None` for every
    /// other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_thread_start(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let NativeSyscallRequest::ThreadStart { args, args_size } = request else {
            return None;
        };
        let cpu = self.cpu;
        let Ok((phase, root, process)) = self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.prepare_guard_free_usercopy()
        }) else {
            return Some(Err(()));
        };
        let input = {
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            crate::syscall::thread_start_input(&mut user, args, args_size)
        };
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        let status = runtime.run_thread_start(input);
        runtime.commit_runtime_phase(phase);
        Some(Ok(
            runtime.ready_to_return(NativeSyscallResult::returning(status))
        ))
    }

    /// `AddressRegionMap`, `AddressRegionUnmap` and `AddressRegionProtect`
    /// (design §11.2.3 family G and §11.2.9, D1 option B3).
    /// 1. A first hold, under T and then P: prepare, take S, publish the page
    ///    tables, commit the model and notify the targets, with every final
    ///    release held in the frame's `HeldReleases`. A mutation that leaves
    ///    nothing to acknowledge finishes here.
    /// 2. With neither T nor P held (`GuardFree`), wait for every
    ///    acknowledgement, servicing this CPU's mailbox, and mint the permit.
    /// 3. Release S on the permit.
    /// 4. A last hold merges the held releases on the permit, revalidates and
    ///    commits the phase, and leaves through `ready_to_return`, whose drain
    ///    therefore runs after the acknowledgement.
    /// `None` for every other request.
    // Kept out of line, like the other facade helpers, so the ordinary
    // handler's measured frame does not absorb it.
    #[inline(never)]
    fn handle_address_region_mutation(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        if !matches!(
            request,
            NativeSyscallRequest::AddressRegionMap { .. }
                | NativeSyscallRequest::AddressRegionUnmap { .. }
                | NativeSyscallRequest::AddressRegionProtect { .. }
        ) {
            return None;
        }
        // DW2 M4b: a call larger than one step runs as a chain of steps,
        // each a complete transaction through the holds below, with a safe
        // point between them; `RegionSteps` plans the chain.
        let mut steps = crate::syscall::RegionSteps::<MemoryProtection, REGION_SLOTS>::new(
            request,
            FAMILY_G_STEP_BYTES,
        );
        let mut output = None;
        let mut user = None;
        let mut previous = None;
        loop {
            let cpu = self.cpu;
            let snapshot_range = steps.snapshot_range();
            let previous_phase = previous.take();
            let Ok((phase, root, process, snapshot)) = self
                .with_synchronized_runtime_at_safe_point(|runtime| {
                    if let Some(phase) = previous_phase {
                        runtime.commit_runtime_phase(phase);
                    }
                    if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                        runtime.service_pending_timer_expiries_on_bootstrap();
                    }
                    let snapshot = snapshot_range
                        .map(|(region, start, end)| runtime.region_snapshot(region, start, end));
                    let (phase, root, process) = runtime.prepare_guard_free_usercopy();
                    (phase, root, process, snapshot)
                })
            else {
                // Stopped at a safe point. A call in steps keeps the steps
                // it made; a pinned map output is let go.
                self.settle_map_output(output.take(), user, None);
                return Some(Err(()));
            };
            let (root, process) = *user.get_or_insert((root, process));
            if let Some(snapshot) = snapshot {
                if let Err(status) = steps.set_snapshot(snapshot) {
                    // Refused as one call would be, before any step.
                    let ready = {
                        let mut guard = self.runtime.lock();
                        let mut runtime = guard.on(&mut self.owned);
                        runtime.return_from_steps(phase, status)
                    };
                    return Some(Ok(ready));
                }
            }
            // Map's arguments and output pin, with P alone (D1 commit 9).
            if steps.needs_map_input() {
                let NativeSyscallRequest::AddressRegionMap {
                    args,
                    args_size,
                    out_address,
                    ..
                } = request
                else {
                    unreachable!("only a map copies in arguments")
                };
                let mut access = self.paging.guard_free_access(self.runtime.guard_free());
                let mut paging = access.lock();
                let mut space = paging
                    .guard_free_value()
                    .usercopy_process_address_space(root, process);
                let input = map_input(&mut space, args, args_size, out_address);
                steps.set_map_input(input.map(|(args, protection, pinned)| {
                    output = Some(pinned);
                    (args, protection)
                }));
            }
            let step = steps.step();
            let mut held = crate::syscall::HeldReleases::new();
            let (begun, address) = {
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on(&mut self.owned);
                runtime.begin_address_region_mutation(
                    step.request,
                    step.map,
                    phase,
                    &mut held,
                    step.last,
                )
            };
            let finished = match begun {
                FamilyGBegun::Published {
                    phase,
                    status,
                    shootdown,
                } => {
                    let FamilyGShootdown {
                        pending,
                        mut driver,
                        initiator,
                    } = shootdown;
                    let permit = user_access::await_shootdown(
                        self.runtime.guard_free(),
                        pending,
                        &mut driver,
                    );
                    drop(driver);
                    let settlement = initiator.release(
                        crate::memory::address_region::ShootdownOutcome::Completed(permit),
                    );
                    let mut guard = self.runtime.lock();
                    let mut runtime = guard.on(&mut self.owned);
                    runtime.finish_address_region_mutation(
                        &mut held, settlement, phase, status, step.last,
                    )
                }
                settled => settled,
            };
            match finished {
                FamilyGBegun::Returned(ready) => {
                    self.settle_map_output(output.take(), user, address);
                    return Some(Ok(ready));
                }
                FamilyGBegun::Stepped { phase, status } => {
                    let Some(status) = steps.advance(status, address) else {
                        previous = Some(phase);
                        continue;
                    };
                    let ready = {
                        let mut guard = self.runtime.lock();
                        let mut runtime = guard.on(&mut self.owned);
                        runtime.return_from_steps(phase, status)
                    };
                    let address = if status == DW_STATUS_SUCCESS {
                        steps.address()
                    } else {
                        None
                    };
                    self.settle_map_output(output.take(), user, address);
                    return Some(Ok(ready));
                }
                FamilyGBegun::Published { .. } => {
                    unreachable!("a published step finishes in its last hold")
                }
            }
        }
    }

    /// A syscall's fill-in phase (DW2 M6 §8.6): before any copy, gives every
    /// on-demand page under the request's user buffers a frame and a leaf,
    /// and commits a `dma_map` range, a step per hold. `None` to go on to
    /// the syscall; `Some` when it ends here, with the fill-in's status or a
    /// stop. Nothing runs while no on-demand object exists.
    fn fill_in_user_buffers(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        if crate::memory::object::LIVE_ON_DEMAND_OBJECTS.load(core::sync::atomic::Ordering::Acquire)
            == 0
        {
            return None;
        }
        for buffer in request.user_buffers().into_iter().flatten() {
            if buffer.byte_len == 0 {
                continue;
            }
            // A buffer the copy cannot use is the copy's to refuse.
            let Some(end) = buffer
                .address
                .checked_add(buffer.byte_len)
                .and_then(|end| end.checked_add(PAGE_SIZE - 1))
                .map(|end| end & !(PAGE_SIZE - 1))
            else {
                continue;
            };
            let cpu = self.cpu;
            let mut next = buffer.address & !(PAGE_SIZE - 1);
            while next < end {
                match self.with_synchronized_runtime_at_safe_point(|runtime| {
                    if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                        runtime.service_pending_timer_expiries_on_bootstrap();
                    }
                    runtime.fill_in_user_range(&mut next, end, buffer.write)
                }) {
                    Err(()) => return Some(Err(())),
                    Ok(Err(status)) => return Some(self.return_status(status)),
                    Ok(Ok(())) => {}
                }
            }
        }
        // `dma_map` maps frames, not leaves: commit its range first (§8.6),
        // but only for a caller whose resource `dma_map` would accept and
        // who could map the object (review M6-1). Each step checks again.
        if let NativeSyscallRequest::DmaMap {
            resource,
            memory_object,
            offset,
            byte_len,
            access,
            ..
        } = request
        {
            let cpu = self.cpu;
            let mut next = offset;
            loop {
                match self.with_synchronized_runtime_at_safe_point(|runtime| {
                    if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                        runtime.service_pending_timer_expiries_on_bootstrap();
                    }
                    let process = runtime.own.scheduled().process;
                    let Some(required) = crate::syscall::dma_map_commit_rights(
                        &mut runtime.core.registry,
                        &mut runtime.core.tasks,
                        &runtime.core.shared.device_resources,
                        process,
                        resource,
                        access,
                    ) else {
                        return Ok(true);
                    };
                    runtime.commit_on_demand_step(
                        memory_object,
                        offset,
                        byte_len,
                        required,
                        &mut next,
                    )
                }) {
                    Err(()) => return Some(Err(())),
                    Ok(Ok(true)) => break,
                    Ok(Ok(false)) => {}
                    Ok(Err(
                        status @ (deepwyrm_abi::DW_STATUS_NO_RESOURCES
                        | deepwyrm_abi::DW_STATUS_NO_MEMORY),
                    )) => return Some(self.return_status(status)),
                    // The syscall reports a bad range or handle itself.
                    Ok(Err(_)) => break,
                }
            }
        }
        None
    }

    /// Ends a syscall with `status`.
    fn return_status(
        &mut self,
        status: deepwyrm_abi::DwStatus,
    ) -> Result<crate::syscall::native::ReturnReady, ()> {
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.ready_to_return(NativeSyscallResult::returning(status))
        })
    }

    /// `memory_object_commit` (DW2 M6 §8.2): commits the range a step of at
    /// most 2 MiB per hold of T and P, with a safe point between steps.
    /// Each step resolves the handle again. A failure returns at once; the
    /// pages committed before it stay committed and charged.
    fn handle_memory_object_commit(
        &mut self,
        request: NativeSyscallRequest,
    ) -> Option<Result<crate::syscall::native::ReturnReady, ()>> {
        let NativeSyscallRequest::MemoryObjectCommit {
            memory_object,
            offset,
            byte_len,
        } = request
        else {
            return None;
        };
        let cpu = self.cpu;
        let mut next = offset;
        loop {
            let step = self.with_synchronized_runtime_at_safe_point(|runtime| {
                if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                    runtime.service_pending_timer_expiries_on_bootstrap();
                }
                let result = runtime.commit_on_demand_step(
                    memory_object,
                    offset,
                    byte_len,
                    deepwyrm_abi::DW_RIGHT_MAP,
                    &mut next,
                );
                match result {
                    Ok(false) => None,
                    Ok(true) => Some(
                        runtime.ready_to_return(NativeSyscallResult::returning(DW_STATUS_SUCCESS)),
                    ),
                    Err(status) => {
                        Some(runtime.ready_to_return(NativeSyscallResult::returning(status)))
                    }
                }
            });
            match step {
                Err(()) => return Some(Err(())),
                Ok(Some(ready)) => return Some(Ok(ready)),
                Ok(None) => {}
            }
        }
    }

    /// Zeroes a new MemoryObject's backing one step at a time, taking P for
    /// each step and releasing it between them, then makes it the object's
    /// backing (DW2 M4b). Its frames are reachable only through
    /// `allocation`, held in this frame, so nothing touches them between
    /// steps. A page that fails frees the whole allocation.
    #[allow(
        unsafe_code,
        reason = "every page was zeroed by the steps before the allocation becomes a backing"
    )]
    fn zero_backing_in_steps(
        &mut self,
        root: super::UserCopyRoot,
        process: ProcessKey,
        allocation: crate::memory::frame_roles::BackingAllocation,
    ) -> Result<ObjectBackingGrant, deepwyrm_abi::DwStatus> {
        let step_pages = PRIMORDIAL_MAX_USER_MAPPING_PAGES as u64;
        let mut first = 0;
        let mut zeroed = true;
        while zeroed && first < allocation.pages() {
            let count = step_pages.min(allocation.pages() - first);
            let mut access = self.paging.guard_free_access(self.runtime.guard_free());
            let mut paging = access.lock();
            let mut user = paging
                .guard_free_value()
                .usercopy_process_address_space(root, process);
            zeroed = user.zero_backing_pages(&allocation, first, count);
            first += count;
        }
        let mut access = self.paging.guard_free_access(self.runtime.guard_free());
        let mut paging = access.lock();
        let mut user = paging
            .guard_free_value()
            .usercopy_process_address_space(root, process);
        if zeroed {
            // SAFETY: the loop zeroed every page of the allocation.
            Ok(unsafe { user.finish_zeroed_backing(allocation) })
        } else {
            user.cancel_backing(allocation);
            Err(deepwyrm_abi::DW_STATUS_NO_RESOURCES)
        }
    }

    /// Commits a map's address into its pinned output, or lets the output
    /// go (`None`), with P alone after the last hold.
    fn settle_map_output(
        &mut self,
        output: Option<user_access::OwnedLiveUserOutput>,
        user: Option<(super::UserCopyRoot, ProcessKey)>,
        address: Option<u64>,
    ) {
        let Some(output) = output else {
            return;
        };
        let (root, process) = user.expect("a pinned map output has its user root");
        let mut access = self.paging.guard_free_access(self.runtime.guard_free());
        let mut paging = access.lock();
        let mut space = paging
            .guard_free_value()
            .usercopy_process_address_space(root, process);
        match address {
            Some(address) => space
                .commit_owned_output(output, &address.to_le_bytes())
                .unwrap_or_else(|_| panic!("primordial map output pin drifted")),
            None => space
                .discard_owned_output(output)
                .unwrap_or_else(|_| panic!("primordial map output pin drifted")),
        }
    }

    /// Applies a resumed F operation's recorded user effects with P alone,
    /// after the hold that resumed it (D1 commit 8).
    #[inline(never)]
    fn apply_resume_settlement(&mut self, settlement: ResumeSettlement) {
        let ResumeSettlement {
            root,
            process,
            output,
            pin,
        } = settlement;
        if output.is_none() && pin.is_none() {
            return;
        }
        let mut access = self.paging.guard_free_access(self.runtime.guard_free());
        let mut paging = access.lock();
        let mut user = paging
            .guard_free_value()
            .usercopy_process_address_space(root, process);
        if let Some(pin) = pin {
            crate::syscall::FAtomicUserAccess::release_atomic_u32(&mut user, pin);
        }
        if let Some((output, result)) = output {
            match result {
                Some(result) => user
                    .commit_owned_output(output, &result)
                    .unwrap_or_else(|_| panic!("pinned resumed wait output commit drifted")),
                None => user
                    .discard_owned_output(output)
                    .unwrap_or_else(|_| panic!("pinned resumed wait output discard drifted")),
            }
        }
    }

    /// Runs one scheduler-current transaction under the same runtime guard as
    /// the final Stop arbitration. This closes both detached windows: a Stop
    /// published before root synchronization and one published after the CR3
    /// operation but before the caller reacquires runtime authority.
    // Inlined into each caller, as it was when the ordinary syscall path was its
    // only caller: the family-A and family-B helpers (D1 commits 5 and 6) add
    // instances, and an out-of-line instance would add a frame and a return
    // word to the ordinary syscall chain the stack oracles measure.
    #[inline(always)]
    fn with_synchronized_runtime_at_safe_point<T>(
        &mut self,
        operation: impl FnOnce(
            &mut PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>,
        ) -> T,
    ) -> Result<T, ()> {
        if !self.synchronize_scheduler_current_at_safe_point_detached() {
            return Err(());
        }
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        if matches!(
            crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
        ) {
            return Err(());
        }
        #[cfg(deepwyrm_dw1e_platform)]
        if self.cpu == crate::cpu::CpuIndex::BOOTSTRAP {
            runtime
                .service_q35_retirement_at_bsp_safe_point()
                .unwrap_or_else(|_| panic!("DW1-E2C deferred finalizer safe-point drifted"));
        }
        Ok(operation(&mut runtime))
    }

    #[cfg(deepwyrm_dw1e_platform)]
    fn service_q35_retirement_at_bsp_safe_point(&mut self) {
        if self.cpu != crate::cpu::CpuIndex::BOOTSTRAP {
            return;
        }
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        runtime
            .service_q35_retirement_at_bsp_safe_point()
            .unwrap_or_else(|_| panic!("DW1-E2C deferred finalizer safe-point drifted"));
    }

    /// Enters this AP's retained kernel root and returns the executing state
    /// that carries the proof, which its ready publication requires.
    fn enter_ap_kernel_root_detached(&mut self) -> crate::task::CarrierRuntimeState {
        let prepared = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            runtime.prepare_ap_kernel_root_entry()
        };
        let executed = match prepared.execute(self.runtime.guard_free()) {
            Ok(executed) => executed,
            Err(failure) => {
                let mut guard = self.runtime.lock();
                let mut runtime = guard.on_root_switch_flight(&mut self.owned);
                let error = runtime.cancel_ap_kernel_root_entry(failure);
                panic!("AP kernel-root entry failed before CR3: {error:?}")
            }
        };
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on_root_switch_flight(&mut self.owned);
        runtime.commit_ap_kernel_root_entry(executed)
    }

    fn terminate_exception_with_remote_stops(
        &mut self,
        exception: crate::task::TaskExceptionRecord,
    ) {
        assert!(
            self.pending_remote_termination.is_none(),
            "terminal exception crossed a pending remote termination"
        );
        if !self.synchronize_scheduler_current_at_safe_point_detached() {
            return;
        }
        let published = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(published);
        let pending = loop {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            match runtime.prepare_remote_process_exception(exception) {
                ProcessTerminationPreparation::Retry => {
                    drop(guard);
                    for _ in 0..64 {
                        core::hint::spin_loop();
                    }
                    continue;
                }
                ProcessTerminationPreparation::Immediate(result) => {
                    drop(guard);
                    self.drain_quantum_cancellation_detached();
                    assert_eq!(result.status, DW_STATUS_SUCCESS);
                    assert_eq!(result.control, SyscallControl::TerminateCurrent);
                    return;
                }
                ProcessTerminationPreparation::Remote(prepared) => {
                    let mut deferred = core::array::from_fn(|_| None);
                    for (cpu_index, identity) in prepared.identities.into_iter().enumerate() {
                        let Some(identity) = identity else {
                            continue;
                        };
                        deferred[cpu_index] = Some(
                            crate::arch::x86_64::idle::publish_live_remote_stop(identity, ())
                                .unwrap_or_else(|failure| {
                                    let error = failure.error();
                                    let _resource = failure.into_resource();
                                    panic!("exception remote-stop publication failed: {error:?}")
                                }),
                        );
                    }
                    break PendingRemoteProcessTermination {
                        phase: prepared.phase,
                        prepared: prepared.prepared,
                        deferred,
                    };
                }
            }
        };
        let permits = await_remote_stop_permits(pending.deferred, self.runtime.guard_free());
        self.synchronize_scheduler_current_after_remote_stops_detached();
        let result = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            runtime.complete_process_termination(pending.phase, pending.prepared, permits)
        };
        self.drain_quantum_cancellation_detached();
        assert_eq!(result.status, DW_STATUS_SUCCESS);
        assert_eq!(result.control, SyscallControl::TerminateCurrent);
    }
}

enum PreparedCarrierEntry {
    Fresh {
        state: crate::arch::x86_64::syscall::ValidatedUserReturn,
        stack: crate::memory::kernel_stack::KernelStackBounds,
    },
    Continuation {
        stack: crate::memory::kernel_stack::KernelStackBounds,
        rsp: u64,
    },
    Idle,
}

enum PreparedRendezvousNext {
    Scheduled {
        stack: crate::memory::kernel_stack::KernelStackBounds,
        continuation: u64,
    },
    Idle,
}

enum PreparedTerminalHandoff {
    Continuation(u64),
    IdleScheduler,
    /// Production only: nothing remains to run. The facade powers off after it
    /// drops the runtime guard, because the fallback halt loop enables
    /// interrupts (DW0-H §12.8; design §11.2.6).
    #[cfg(not(feature = "test-support"))]
    PowerOff,
}

struct TerminalRetirementState {
    retired_process: ProcessKey,
    retired_root_key: crate::memory::address_region::AddressRegionObjectKey,
    retired_address_space: crate::memory::address_region::AddressSpaceKey,
    /// This Thread's own transition exited the Process (design §11.2.12 rule
    /// 2), captured from the deferred bundle before its reclaim.
    exits_process: bool,
}

struct TerminalSuccessorState {
    retirement: TerminalRetirementState,
    stack: crate::memory::kernel_stack::KernelStackBounds,
    continuation: u64,
}

enum TerminalKernelContinuation {
    EnterPrimordialPublisher(TerminalRetirementState),
    FinishGenericChild(TerminalRetirementState),
    /// F3A.7k. Production's primordial retiring while other Processes live,
    /// with nothing runnable on its own CPU. The userspace half is already
    /// unmapped; the root is retired from the kernel root and the CPU idles.
    #[cfg(not(feature = "test-support"))]
    RetirePrimordialToIdle {
        retirement: TerminalRetirementState,
        proof: crate::task::ProcessQuiescenceProof,
        drained: crate::task::BlockedOperationsDrained,
    },
}

enum PreparedTerminalStep {
    SchedulerRoot {
        prepared: PreparedSchedulerRootSwitch,
        state: TerminalSuccessorState,
    },
    KernelRoot {
        prepared: PreparedTerminalKernelRootSwitch,
        continuation: TerminalKernelContinuation,
    },
    PrimordialRoot {
        prepared: PreparedTerminalProcessRootSwitch,
        retirement: TerminalRetirementState,
    },
    Final(PreparedTerminalHandoff),
}

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

fn publish_runtime_shared(
    boot_resource_grants: crate::boot::BootResourceGrants,
) -> &'static PrimordialRuntimeShared {
    SHARED_RUNTIME_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|_| panic!("primordial shared runtime was initialized twice"));
    let stacks = crate::arch::x86_64::linked_thread_kernel_stack_layout()
        .unwrap_or_else(|error| panic!("invalid primordial kernel stack layout: {error:?}"));
    let execution =
        ExecutionDomain::<EXECUTION_THREADS>::new(core::array::from_fn(|index| stacks[index]))
            .unwrap_or_else(|error| panic!("invalid primordial execution domain: {error:?}"));
    #[cfg(deepwyrm_dw1e_platform)]
    let q35_ioapic = crate::arch::x86_64::ioapic_live::q35_ioapic()
        .unwrap_or_else(|| panic!("DW1-E2C runtime requires the validated q35 IOAPIC owner"));
    #[cfg(deepwyrm_dw1e_platform)]
    let interrupt_platform = crate::device::Q35InterruptPlatform::new(q35_ioapic)
        .unwrap_or_else(|error| panic!("DW1-E2C q35 platform initialization failed: {error:?}"));
    #[cfg(not(deepwyrm_dw1e_platform))]
    let interrupt_platform = crate::device::InterruptPlatformModel::new();
    // SAFETY: [P-ONESHOT] the 0->1 exchange above admits exactly one writer, and nothing reads the
    // storage before the state-2 Release store below.
    unsafe {
        (*SHARED_RUNTIME_STORAGE.0.get()).write(PrimordialRuntimeShared {
            execution,
            channels: Channels::new(),
            boot_resource_grants: crate::boot::BootResourceGrantAuthority::new(
                boot_resource_grants,
            ),
            device_resources: crate::device::DeviceResourceAuthority::new(),
            interrupts: crate::device::InterruptAuthority::new(),
            interrupt_platform,
            events: EventAuthority::new(),
            timers: TimerAuthority::new(),
            timer_expiries: IrqSpinMutex::new([None; crate::time::DEADLINE_QUEUE_CAPACITY]),
            waits: WaitRegistry::new(),
        });
    }
    SHARED_RUNTIME_STATE.store(2, Ordering::Release);
    // SAFETY: [P-ONESHOT] this thread just wrote the storage, and it is never written again, so a
    // shared `'static` reference is valid for the rest of the kernel's life.
    let target = unsafe { &*(*SHARED_RUNTIME_STORAGE.0.get()).as_ptr() };
    #[cfg(deepwyrm_dw1e_platform)]
    crate::arch::x86_64::external_interrupt::bind_q35_external_interrupt_handler(target)
        .unwrap_or_else(|error| panic!("could not bind DW1-E2C q35 vector handler: {error:?}"));
    crate::time::bind_deadline_wake_target(target)
        .unwrap_or_else(|error| panic!("could not bind primordial deadline wakes: {error:?}"));
    crate::time::bind_timer_expiry_target(target)
        .unwrap_or_else(|error| panic!("could not bind primordial timer expiries: {error:?}"));
    target
}

#[cfg(deepwyrm_dw1e_platform)]
impl crate::arch::x86_64::external_interrupt::Q35ExternalInterruptHandler
    for PrimordialRuntimeShared
{
    fn handle_q35_com2_interrupt(
        &self,
    ) -> crate::arch::x86_64::external_interrupt::Q35ExternalInterruptCompletion {
        let generation = match self.interrupt_platform.snapshot_delivery() {
            crate::device::Q35DeliverySnapshot::Live {
                delivery,
                generation,
            } => {
                let (disposition, wakes) =
                    self.interrupts.deliver_classified(delivery, &self.waits);
                if matches!(
                    disposition,
                    crate::device::InterruptDeliveryDisposition::CoalescedPending
                        | crate::device::InterruptDeliveryDisposition::AckRace
                ) {
                    self.interrupt_platform.record_pending_delivery(generation);
                }
                crate::wait::complete_irq_signal_wakes(&self.execution, wakes);
                generation
            }
            crate::device::Q35DeliverySnapshot::Retiring { generation } => generation,
            crate::device::Q35DeliverySnapshot::Orphan => {
                return crate::arch::x86_64::external_interrupt::Q35ExternalInterruptCompletion::none();
            }
        };
        crate::arch::x86_64::external_interrupt::Q35ExternalInterruptCompletion::generation_bound(
            generation,
            complete_q35_handler_after_eoi,
        )
    }
}

#[cfg(deepwyrm_dw1e_platform)]
fn complete_q35_handler_after_eoi(generation: u64) {
    if SHARED_RUNTIME_STATE.load(Ordering::Acquire) != 2 {
        panic!("DW1-E2C handler completion preceded shared-runtime publication");
    }
    // SAFETY: [P-ONESHOT] state 2 was observed with Acquire above, pairing with
    // `publish_runtime_shared`'s Release store after its one write.
    let shared = unsafe { &*(*SHARED_RUNTIME_STORAGE.0.get()).as_ptr() };
    shared.interrupt_platform.complete_handler(generation);
}

fn bind_runtime_carrier_facades<
    'runtime,
    'roles,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    facades: core::ptr::NonNull<
        RuntimeCarrierFacade<'runtime, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    publishers: core::ptr::NonNull<QuantumExpiryPublisher>,
) -> usize {
    let registry = crate::arch::x86_64::smp::live_cpu_registry();
    let live_cpu_count = registry.len();
    assert!(
        (1..=crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT).contains(&live_cpu_count),
        "native runtime topology must fit the fixed carrier capacity"
    );
    for cpu_index in 0..live_cpu_count {
        let snapshot = registry
            .snapshot(cpu_index)
            .unwrap_or_else(|error| panic!("could not inspect CPU {cpu_index}: {error:?}"));
        let expected = crate::arch::x86_64::smp::runtime_pre_admission_lifecycle(cpu_index);
        if snapshot.lifecycle != expected {
            panic!("CPU {cpu_index} had the wrong lifecycle before native carrier binding");
        }
        let cpu = crate::cpu::CpuIndex::new(cpu_index)
            .unwrap_or_else(|| panic!("CPU {cpu_index} exceeds the native carrier bound"));
        // SAFETY: [P-FACADE] `cpu_index < live_cpu_count <= H1_RUNTIME_CPU_SLOT_COUNT`, so this is
        // an element of the permanent facade array, derived from its one base pointer.
        let carrier = unsafe { facades.add(cpu_index) };
        // SAFETY: [P-FACADE] as above, an element of the permanent publisher array.
        let publisher = unsafe { publishers.add(cpu_index) };
        // SAFETY: [P-FACADE] a field read through the element pointer; no reference to the facade.
        let shared = unsafe { (*carrier.as_ptr()).shared };
        if cpu_index == 0 {
            // SAFETY: [P-FACADE] the facade lives in permanent static storage, so it is
            // stationary for the kernel's life, and every later access uses this pointer's
            // provenance, which is the callee's contract.
            unsafe {
                crate::arch::x86_64::syscall::bind_running_native_runtime_carrier_for_slot(
                    cpu, carrier, publisher,
                )
            }
            .unwrap_or_else(|error| {
                shared.execution.fail_carrier_admission(cpu);
                panic!("could not bind CPU0 running native carrier: {error:?}")
            });
        } else {
            // SAFETY: [P-FACADE] as for CPU0 above; the AP is parked and cannot reach the carrier
            // callbacks during publication.
            unsafe {
                crate::arch::x86_64::syscall::bind_native_runtime_carrier_for_slot(
                    cpu, carrier, publisher,
                )
            }
            .unwrap_or_else(|error| {
                shared.execution.fail_carrier_admission(cpu);
                panic!("could not bind AP {cpu_index} native carrier: {error:?}")
            });
        }
    }
    live_cpu_count
}

fn carrier_resource_tuple<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    runtime: &PrimordialRuntimeCore<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    paging: &RuntimePaging<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    cpu: crate::cpu::CpuIndex,
    expected_cpu_lifecycle: crate::arch::x86_64::smp::CpuLifecycle,
    expected_runtime_lifecycle: crate::arch::x86_64::syscall::RuntimeCarrierLifecycle,
    expected_idle_wake_enabled: bool,
) -> crate::task::CarrierResourceTuple {
    let snapshot = crate::arch::x86_64::smp::live_cpu_registry()
        .snapshot(cpu.index())
        .unwrap_or_else(|_| {
            fail_live_carrier_admission(runtime.shared, cpu, "CPU registry unavailable")
        });
    if snapshot.lifecycle != expected_cpu_lifecycle
        || snapshot.online_generation == 0
        || crate::arch::x86_64::runtime_cpu_descriptor_lifecycle(cpu.index())
            != Some(crate::arch::x86_64::RuntimeCpuDescriptorLifecycle::Online)
        || crate::arch::x86_64::syscall::native_runtime_carrier_lifecycle(cpu)
            != Some(expected_runtime_lifecycle)
    {
        fail_live_carrier_admission(
            runtime.shared,
            cpu,
            "CPU lifecycle, descriptor, or runtime publication drifted",
        );
    }
    let stacks = crate::arch::x86_64::linked_runtime_cpu_stack_layout().unwrap_or_else(|_| {
        fail_live_carrier_admission(runtime.shared, cpu, "invalid runtime CPU stack layout")
    });
    let selected = stacks[cpu.index()];
    if selected.privilege_entry == selected.terminal_reaper
        || stacks[..cpu.index()].iter().any(|prior| {
            prior.privilege_entry == selected.privilege_entry
                || prior.terminal_reaper == selected.terminal_reaper
        })
    {
        fail_live_carrier_admission(runtime.shared, cpu, "CPU admission stacks are not private");
    }
    let root = paging.kernel_execution_root(cpu).unwrap_or_else(|_| {
        fail_live_carrier_admission(runtime.shared, cpu, "CPU retained root unavailable")
    });
    if root.cpu() != cpu || root.root_physical_start() == 0 {
        fail_live_carrier_admission(runtime.shared, cpu, "CPU retained root identity drifted");
    }
    if !paging.validates_cpu_scratch_binding(cpu)
        || !crate::arch::x86_64::ipi::live_ipi_transport_is_bound()
        || !crate::arch::x86_64::ipi::live_rendezvous_handler_is_bound()
        || !user_access::live_tlb_shootdown_is_ready()
        || crate::arch::x86_64::idle::live_idle_wake_is_enabled(cpu) != expected_idle_wake_enabled
        || (cpu == crate::cpu::CpuIndex::BOOTSTRAP && !crate::time::timer_service_is_healthy())
        || (cpu != crate::cpu::CpuIndex::BOOTSTRAP
            && !crate::time::ap_scheduler_timer_is_masked(cpu))
    {
        fail_live_carrier_admission(
            runtime.shared,
            cpu,
            "CPU scratch, e1/e2, idle-wake, or deadline admission drifted",
        );
    }
    crate::task::CarrierResourceTuple {
        cpu,
        local_apic_id: snapshot.local_apic_id,
        online_generation: snapshot.online_generation,
        root_generation: root.root_physical_start(),
        descriptor_cpu: cpu,
        runtime_cpu: cpu,
        entry_stack_cpu: cpu,
        reaper_stack_cpu: cpu,
        root_cpu: cpu,
        scratch_cpu: cpu,
        idle_mailbox_cpu: cpu,
        tlb_mailbox_cpu: cpu,
        deadline: if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
            crate::task::CarrierDeadlineState::BootstrapArbiterReady
        } else {
            crate::task::CarrierDeadlineState::ApSchedulerTimerMasked
        },
    }
}

/// Cancels this CPU's exact scheduler quantum, at the safe point after the
/// facade drops its guard. Cancellation can publish a due expiry
/// synchronously, which no longer takes the runtime authority (D1 commit 2).
/// The token records where this runs; it is no longer needed to avoid a
/// self-deadlock.
fn cancel_scheduler_quantum_guard_free(
    ticket: crate::task::SchedulerQuantumTicket,
    _guard_free: GuardFree<'_>,
) {
    crate::time::cancel_scheduler_quantum(ticket)
        .unwrap_or_else(|error| panic!("scheduler quantum cancellation failed: {error:?}"));
}

/// Halts the idle CPU until an interrupt, with IF set only inside the
/// window. No runtime lock may be held across `sti; hlt` (DW0-H §12.8):
/// the `GuardFree` token proves the caller holds none.
fn halt_for_interrupt(_guard_free: GuardFree<'_>) {
    // SAFETY: as at `wait_for_suspend_interrupt` in `syscall/live.rs`: CPL0 with IF clear, so
    // STI;HLT is race-free and CLI restores IF clear. Handlers run inside the window write memory
    // read after it, so the block omits `nomem` and is a compiler memory barrier.
    unsafe {
        core::arch::asm!("sti", "hlt", "cli", options(nostack));
    }
}

#[track_caller]
fn fail_live_carrier_admission(
    shared: &'static PrimordialRuntimeShared,
    cpu: crate::cpu::CpuIndex,
    reason: &'static str,
) -> ! {
    shared.execution.fail_carrier_admission(cpu);
    panic!("CPU {} carrier admission failed: {reason}", cpu.index());
}

/// Prepares every AP's admission. Runs after publication, so it reaches the
/// facades only through `enter`'s element pointers ([P-FACADE]).
fn prepare_runtime_carrier_admission<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    facades: core::ptr::NonNull<RuntimeCarrierFacade<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>>,
    live_cpu_count: usize,
) {
    // SAFETY: [P-FACADE] facade 0's handle, borrowed for this function only; the APs are parked,
    // and the loop below touches only their facades, not facade 0.
    let mut runtime = unsafe { (*facades.as_ptr()).runtime.lock() };
    for cpu_index in 1..live_cpu_count {
        // SAFETY: [P-FACADE] an element of the permanent facade array (`cpu_index` is below the live
        // count); its fields are read and written in place, without a reference to the facade.
        let facade = unsafe { facades.add(cpu_index) }.as_ptr();
        // SAFETY: [P-FACADE] as above.
        let (cpu, shared) = unsafe { ((*facade).cpu, (*facade).shared) };
        let (state, mut paging) = runtime.split_paging();
        let resources = carrier_resource_tuple(
            &state.core,
            &paging.lock(),
            cpu,
            crate::arch::x86_64::smp::CpuLifecycle::Parked,
            crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Parked,
            false,
        );
        let ticket = shared
            .execution
            .prepare_ap_carrier(resources, crate::task::CarrierRuntimeState::Parked)
            .unwrap_or_else(|error| {
                shared.execution.fail_carrier_admission(cpu);
                panic!("could not prepare AP {} admission: {error:?}", cpu.index())
            });
        // SAFETY: [P-FACADE] as above; this AP is still parked, so nothing else reads the field.
        unsafe { (*facade).admission = Some((ticket, resources)) };
    }
}

/// Admits CPU0. Runs after publication, so it reaches facade 0 only through
/// `enter`'s element pointer ([P-FACADE]).
fn normalize_bootstrap_carrier<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    facade: core::ptr::NonNull<RuntimeCarrierFacade<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>>,
) {
    let facade = facade.as_ptr();
    // SAFETY: [P-FACADE] field reads through facade 0's element pointer.
    let (cpu, shared) = unsafe { ((*facade).cpu, (*facade).shared) };
    let resources = {
        // SAFETY: [P-FACADE] facade 0's handle, borrowed for this block only.
        let mut runtime = unsafe { (*facade).runtime.lock() };
        let (state, mut paging) = runtime.split_paging();
        carrier_resource_tuple(
            &state.core,
            &paging.lock(),
            cpu,
            crate::arch::x86_64::smp::runtime_pre_admission_lifecycle(cpu.index()),
            crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing,
            true,
        )
    };
    if crate::arch::x86_64::syscall::native_runtime_carrier_lifecycle(cpu)
        != Some(crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing)
    {
        panic!("CPU0 running runtime carrier was not published");
    }
    let ticket = shared
        .execution
        .prepare_bootstrap_carrier(resources, crate::task::CarrierRuntimeState::Running)
        .unwrap_or_else(|error| {
            shared.execution.fail_carrier_admission(cpu);
            panic!("could not prepare CPU0 carrier: {error:?}")
        });
    shared
        .execution
        .publish_bootstrap_carrier_ready(
            ticket,
            resources,
            crate::task::CarrierRuntimeState::Running,
        )
        .unwrap_or_else(|error| {
            shared.execution.fail_carrier_admission(cpu);
            panic!("could not ready CPU0 carrier: {error:?}")
        });
    shared
        .execution
        .commit_bootstrap_schedulable(ticket, resources)
        .unwrap_or_else(|error| {
            shared.execution.fail_carrier_admission(cpu);
            panic!("could not commit CPU0 carrier: {error:?}")
        });
    // SAFETY: [P-FACADE] in-place field writes through facade 0's element pointer; CPU0 has not
    // entered its runtime yet, so nothing else reads them.
    unsafe {
        (*facade).admission = Some((ticket, resources));
        (*facade).admission_entered = true;
    }
}

fn release_runtime_carrier_facades<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    shared: &'static PrimordialRuntimeShared,
    runtime: &mut RuntimeAuthorityHandle<
        '_,
        PrimordialRuntimeState<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    admissions: [Option<(
        crate::task::CarrierAdmissionTicket,
        crate::task::CarrierResourceTuple,
    )>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
) {
    let registry = crate::arch::x86_64::smp::live_cpu_registry();
    for cpu_index in 1..registry.len() {
        let cpu = crate::cpu::CpuIndex::new(cpu_index)
            .unwrap_or_else(|| panic!("AP {cpu_index} exceeds the native carrier bound"));
        if crate::arch::x86_64::syscall::release_native_runtime_carrier_for_slot(cpu).is_err() {
            fail_live_carrier_admission(shared, cpu, "native runtime release failed");
        }
        if registry.begin_execution(cpu_index).is_err() {
            fail_live_carrier_admission(shared, cpu, "CPU execution release failed");
        }
        let (ticket, resources) = admissions[cpu_index]
            .unwrap_or_else(|| panic!("AP {cpu_index} omitted its admission ticket"));
        loop {
            let snapshot = shared.execution.carrier_admission_snapshot(cpu);
            if snapshot.lifecycle == crate::task::CarrierAdmissionLifecycle::CarrierReady
                && snapshot.admission_generation == ticket.admission_generation()
                && snapshot.scheduler_slot_generation == ticket.scheduler_slot_generation()
                && snapshot.online_generation == resources.online_generation
            {
                break;
            }
            if snapshot.lifecycle == crate::task::CarrierAdmissionLifecycle::Failed {
                panic!("AP {cpu_index} failed before scheduler admission");
            }
            core::hint::spin_loop();
        }
        let revalidated = {
            let mut runtime = runtime.lock();
            let (state, mut paging) = runtime.split_paging();
            carrier_resource_tuple(
                &state.core,
                &paging.lock(),
                cpu,
                crate::arch::x86_64::smp::CpuLifecycle::Executing,
                crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing,
                false,
            )
        };
        if revalidated != resources {
            fail_live_carrier_admission(shared, cpu, "final carrier tuple changed");
        }
        shared
            .execution
            .commit_ap_schedulable(ticket, resources, || {
                crate::arch::x86_64::idle::enable_live_cpu(cpu).is_ok()
            })
            .unwrap_or_else(|error| {
                panic!("could not commit AP {cpu_index} scheduler admission: {error:?}")
            });
    }
}

fn take_channel_staging(cpu_index: usize) -> &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize] {
    let state = CHANNEL_STAGING_STATE
        .get(cpu_index)
        .unwrap_or_else(|| panic!("invalid primordial Channel staging CPU slot"));
    let staging = CHANNEL_STAGING
        .get(cpu_index)
        .unwrap_or_else(|| panic!("invalid primordial Channel staging CPU slot"));
    if state
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        panic!("primordial Channel staging CPU slot was claimed twice");
    }
    // SAFETY: the 0->1 exchange above admits one claim per buffer, so this is the buffer's only
    // reference. Its CPU's owner-local state keeps it for the kernel's lifetime (S2K-6).
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
        let limit = self.active.root.physical_limit();
        let mut scratch = self
            .active
            .target
            .current_scratch_target()
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        let mut zero = |page: u64| {
            FrameAddress::new(page, limit)
                .is_ok_and(|frame| scratch.zero_allocator_frame(frame).is_ok())
        };
        // SAFETY: `zero` clears each page of the freshly granted, exclusively owned backing
        // through the scratch window (`zero_allocator_frame`), or fails; x86 caches are
        // coherent, so no maintenance is needed.
        unsafe {
            self.active
                .target
                .roles
                .allocate_zeroed_backing(page_count, &mut zero)
        }
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
        let mut scratch = self
            .active
            .target
            .current_scratch_target()
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        if scratch.zero_allocator_frame(frame).is_err() {
            self.active
                .target
                .roles
                .cancel_allocation(allocation)
                .unwrap_or_else(|_| panic!("primordial table rollback lost allocation"));
            return Err(user_access::LiveUserAccessError::MissingOrInvalid);
        }
        // SAFETY: the single page of this freshly granted, exclusively owned allocation was zeroed
        // above (`zero_allocator_frame`); x86 caches are coherent, so no maintenance is needed.
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
            let scratch = self
                .active
                .target
                .current_scratch_target()
                .unwrap_or_else(|error| {
                    panic!("primordial teardown scratch CPU failed: {error:?}")
                });
            let target = &mut self.active.target;
            let mut tracked = user_access::TrackedActiveTarget {
                scratch,
                pins: &self.active.user_pins,
                address_space: region.address_space_key(),
                span: None,
            };
            // SAFETY: [P-PUBLISHER] `region` is the primordial root region, whose address space is
            // `active.root`; `target.roles` and `tracked` serialize that root, and no other
            // publisher runs meanwhile.
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
                    &mut *self.active.journal,
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
        // The backing may be several runs (DW2 M3): each page is resolved
        // through its chain.
        let mut object_offset = offset;
        let mut copied = 0_usize;
        let mut cursor = crate::memory::frame_roles::BackingCursor::new(backing.identity());
        let mut scratch = self
            .active
            .target
            .current_scratch_target()
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        while copied < bytes.len() {
            let page_offset = (object_offset & (PAGE_SIZE - 1)) as usize;
            let take = (PAGE_SIZE as usize - page_offset).min(bytes.len() - copied);
            let page = self
                .active
                .target
                .roles
                .resolve_at(&mut cursor, object_offset & !(PAGE_SIZE - 1), true)
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            let frame = FrameAddress::new(page.physical_start, self.active.root.physical_limit())
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            scratch
                .write_physical_bytes(frame, page_offset, &bytes[copied..copied + take])
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            object_offset += take as u64;
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

            let scratch = self
                .active
                .target
                .current_scratch_target()
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            let target = &mut self.active.target;
            let mut tracked = user_access::TrackedActiveTarget {
                scratch,
                pins: &self.active.user_pins,
                address_space: region.address_space_key(),
                span: None,
            };
            // SAFETY: [P-PUBLISHER] `region` is the primordial root region, whose address space is
            // `active.root`; `target.roles` and `tracked` serialize that root, and no other
            // publisher runs meanwhile.
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
                    &mut *self.active.journal,
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

// The live-target bindings of the host-compiled root-switch transactions in
// `root_switch.rs`: each `execute` performs its CR3 effect through
// `LiveRootSwitchTarget`.
impl PreparedApKernelRootEntry {
    fn execute(
        self,
        guard_free: GuardFree<'_>,
    ) -> Result<ExecutedApKernelRootEntry, FailedApKernelRootEntry> {
        self.execute_on(&mut super::LiveRootSwitchTarget, guard_free)
    }
}

impl PreparedStopRootSwitch {
    fn execute(
        self,
        guard_free: GuardFree<'_>,
    ) -> Result<ExecutedStopRootSwitch, FailedStopRootSwitch> {
        self.execute_on(&mut super::LiveRootSwitchTarget, guard_free)
    }
}

impl PreparedTerminalKernelRootSwitch {
    fn execute(
        self,
        guard_free: GuardFree<'_>,
    ) -> Result<ExecutedTerminalKernelRootSwitch, FailedTerminalKernelRootSwitch> {
        self.execute_on(&mut super::LiveRootSwitchTarget, guard_free)
    }
}

impl PreparedTerminalProcessRootSwitch {
    fn execute(
        self,
        guard_free: GuardFree<'_>,
    ) -> Result<ExecutedTerminalProcessRootSwitch, FailedTerminalProcessRootSwitch> {
        self.execute_on(&mut super::LiveRootSwitchTarget, guard_free)
    }
}

impl PreparedSchedulerRootSwitch {
    fn execute(
        self,
        guard_free: GuardFree<'_>,
    ) -> Result<ExecutedSchedulerRootSwitch, FailedSchedulerRootSwitch> {
        self.execute_on(&mut super::LiveRootSwitchTarget, guard_free)
    }
}

/// One CPU's last scheduled identity: the Process, Thread, kernel stack,
/// context and Process root the scheduler last made current on it. Other CPUs
/// read it under the runtime authority (`terminal_stop_plan`). It is not what
/// physically executes there now; that is the owner-local
/// [`PhysicallyExecuting`], and neither is derived from the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScheduledIdentity {
    process: ProcessKey,
    thread: ThreadKey,
    stack_id: crate::task::KernelStackId,
    context_id: crate::task::ThreadContextId,
    root_key: crate::memory::address_region::AddressRegionObjectKey,
}

/// One CPU's runtime facts that other CPUs read under the runtime authority
/// (S2K-6, design §11.1). They live in the guarded `CpuSlots`, the single
/// source of each fact; only the owning CPU's carrier gets this slot mutably
/// (`CpuSlots::split`), and every other CPU reads it. The one remote write is
/// `RemotelyStaged::stage_remote`, a terminal preparation staging another
/// CPU's quantum cancellation.
struct CpuSharedState {
    /// `None` until this CPU's first scheduler synchronization: an empty slot
    /// reports no identity (design §2.4 finding 4).
    last_scheduled: Option<ScheduledIdentity>,
    active_root: CarrierActiveRoot,
    root_switch_flight: Option<RootSwitchFlight>,
    // Suspension handoff is physical-carrier state, unlike the durable wait
    // registries. One CPU must never consume another CPU's pending/idle
    // control decision even though both serialize the shared service owners.
    wait_control: NativeWaitControl,
    deferred_current: Option<crate::task::DeferredCurrentExecutionResources>,
    pending_quantum_cancellation: Option<crate::task::SchedulerQuantumTicket>,
    /// This CPU's exact claim while it is being remote-stopped, from its
    /// precommit until its post-acknowledgement continuation. Per CPU because
    /// one termination can stop several CPUs, each across two runtime holds.
    stopping_claim: Option<crate::task::SchedulerExecutionClaim>,
    stopping_claim_was_suspended: bool,
}

impl CpuSharedState {
    fn new() -> Self {
        Self {
            last_scheduled: None,
            active_root: CarrierActiveRoot::Unselected,
            root_switch_flight: None,
            wait_control: NativeWaitControl::new(),
            deferred_current: None,
            pending_quantum_cancellation: None,
            stopping_claim: None,
            stopping_claim_was_suspended: false,
        }
    }

    /// The last scheduled identity. Every carrier path that reads it runs
    /// after this CPU's first scheduler synchronization (or is the BSP, which
    /// starts with the primordial identity).
    #[track_caller]
    fn scheduled(&self) -> ScheduledIdentity {
        self.last_scheduled
            .unwrap_or_else(|| panic!("CPU carrier read its identity before scheduling one"))
    }
}

impl RemotelyStaged for CpuSharedState {
    type Staged = crate::task::SchedulerQuantumTicket;

    /// A terminal preparation retired another CPU's unentered logical
    /// replacement and stages its quantum cancellation, which that CPU takes
    /// and performs at its next safe point.
    fn stage_remote(&mut self, ticket: crate::task::SchedulerQuantumTicket) {
        assert!(
            self.pending_quantum_cancellation.replace(ticket).is_none(),
            "CPU already owns a pending quantum cancellation"
        );
    }
}

/// What physically executes on one CPU now: its current Thread, kernel stack
/// and context, all `None` while it idles. Distinct from the CPU's
/// [`ScheduledIdentity`], which keeps the last scheduled Thread after it stops
/// running; neither is derived from the other. Owner-local: only its CPU's
/// carrier touches it (S2K-6, design §11.1).
#[derive(Clone, Copy)]
struct PhysicallyExecuting {
    thread: Option<ThreadKey>,
    stack: Option<crate::task::KernelStackId>,
    context: Option<crate::task::ThreadContextId>,
}

impl PhysicallyExecuting {
    const fn idle() -> Self {
        Self {
            thread: None,
            stack: None,
            context: None,
        }
    }

    fn physically_executes(&self, thread: ThreadKey) -> bool {
        self.thread == Some(thread)
    }

    fn record_current(
        &mut self,
        thread: ThreadKey,
        stack: crate::task::KernelStackId,
        context: crate::task::ThreadContextId,
    ) {
        self.thread = Some(thread);
        self.stack = Some(stack);
        self.context = Some(context);
    }

    fn record_idle(&mut self) {
        *self = Self::idle();
    }
}

/// One CPU's owner-local runtime facts, held by its own facade and lent to
/// its carrier for each guard hold (S2K-6, design §11.1). No other CPU reads
/// them, so none of them is behind the runtime authority.
struct CpuOwnedState {
    /// This CPU's right to mutate its `CpuSharedState` slot.
    owner: CpuOwner,
    /// This CPU's Channel staging buffer, claimed once at construction.
    channel_staging: &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize],
    root_switch_epoch: u64,
    physically_executing: PhysicallyExecuting,
}

impl CpuOwnedState {
    fn new(owner: CpuOwner) -> Self {
        Self {
            channel_staging: take_channel_staging(owner.cpu().index()),
            owner,
            root_switch_epoch: 0,
            physically_executing: PhysicallyExecuting::idle(),
        }
    }
}

/// The runtime's CPU-independent authorities. Plain mutable authorities remain
/// exclusively owned here because their adapter surfaces do not yet provide
/// transactional interior synchronization.
struct PrimordialRuntimeCore<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    /// The paging authority's lock, P. Its value lives outside this lock's;
    /// only a carrier's `PagingAccess` takes it (D1 commit 3).
    paging: &'roles PagingLock<RuntimePaging<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    /// Set and consumed within one stopped CPU's precommit hold.
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
    spaces: Spaces,
    regions: Regions,
    primordial_process: ProcessKey,
    primordial_root_key: crate::memory::address_region::AddressRegionObjectKey,
    primordial_address_space: crate::memory::address_region::AddressSpaceKey,
    channel_keys: [crate::ipc::ChannelEndpointKey; 2],
    kernel_peer: Option<HandleRef>,
    process_monitor: Option<HandleRef>,
    root_owner: Option<InternalRef>,
    cleanup: CleanupQueue<REGISTRY_OBJECTS>,
    // Pending final releases are moved before the irreversible stop commit.
    // They are drained only by a post-ack kernel-root continuation, the last
    // one outstanding when several CPUs are stopped at once.
    rendezvous_cleanup: StagedStopCleanup<REGISTRY_OBJECTS>,
}

/// Everything the runtime authority guards: the core authorities and every
/// CPU's remotely read facts (S2K-6, design §11.1).
struct PrimordialRuntimeState<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    core: PrimordialRuntimeCore<'roles, RANGE_CAPACITY, ROLE_CAPACITY>,
    cpus: CpuSlots<CpuSharedState, { crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT }>,
}

impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeState<'roles, RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// One CPU's carrier for an ordinary guard hold: the core, that CPU's own
    /// slot (mutable only because `owned` holds its owner), every other CPU's
    /// slot read-only, and the CPU's owner-local facts. Refused while this
    /// CPU has a root-switch flight in progress, which only
    /// `on_root_switch_flight` may commit or cancel.
    #[track_caller]
    fn on_with<'a>(
        &'a mut self,
        owned: &'a mut CpuOwnedState,
        paging: PagingAccess<'a, RuntimePaging<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    ) -> PrimordialRuntimeCarrier<'a, 'roles, RANGE_CAPACITY, ROLE_CAPACITY> {
        let carrier = self.on_root_switch_flight_with(owned, paging);
        if carrier.own.root_switch_flight.is_some() {
            panic!("ordinary runtime carrier built during an in-flight root switch");
        }
        carrier
    }

    /// One CPU's carrier for the guard hold that commits or cancels its
    /// in-flight root switch; the commit or cancel checks the flight itself.
    fn on_root_switch_flight_with<'a>(
        &'a mut self,
        owned: &'a mut CpuOwnedState,
        paging: PagingAccess<'a, RuntimePaging<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    ) -> PrimordialRuntimeCarrier<'a, 'roles, RANGE_CAPACITY, ROLE_CAPACITY> {
        let (own, others) = self.cpus.split(&owned.owner);
        PrimordialRuntimeCarrier {
            core: &mut self.core,
            paging,
            own,
            others,
            owned,
        }
    }
}

/// A carrier is built only from a held runtime guard, which mints its
/// access to the paging lock beneath it (D1 commit 3).
impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    RuntimeAuthorityGuard<'_, PrimordialRuntimeState<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>
{
    /// The ordinary carrier for this hold.
    #[track_caller]
    fn on<'a>(
        &'a mut self,
        owned: &'a mut CpuOwnedState,
    ) -> PrimordialRuntimeCarrier<'a, 'roles, RANGE_CAPACITY, ROLE_CAPACITY> {
        let (state, paging) = self.split_paging();
        state.on_with(owned, paging)
    }

    /// The carrier for the hold that commits or cancels a root-switch flight.
    fn on_root_switch_flight<'a>(
        &'a mut self,
        owned: &'a mut CpuOwnedState,
    ) -> PrimordialRuntimeCarrier<'a, 'roles, RANGE_CAPACITY, ROLE_CAPACITY> {
        let (state, paging) = self.split_paging();
        state.on_root_switch_flight_with(owned, paging)
    }

    /// The guarded state and access to P beneath this guard, for the holds
    /// that need no carrier.
    fn split_paging(
        &mut self,
    ) -> (
        &mut PrimordialRuntimeState<'roles, RANGE_CAPACITY, ROLE_CAPACITY>,
        PagingAccess<'_, RuntimePaging<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    ) {
        let paging = self.core.paging;
        self.with_paging(paging)
    }
}

/// One CPU's runtime carrier for one guard hold (S2K-6, design §11.1). There is
/// no current CPU to switch: the carrier is built for one CPU, from the guard
/// and that CPU's owner-local state, and its own slot is the only one it can
/// mutate.
struct PrimordialRuntimeCarrier<'a, 'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
{
    core: &'a mut PrimordialRuntimeCore<'roles, RANGE_CAPACITY, ROLE_CAPACITY>,
    /// This hold's right to take P beneath its T guard.
    paging: PagingAccess<'a, RuntimePaging<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    own: &'a mut CpuSharedState,
    others: OtherCpus<'a, CpuSharedState>,
    owned: &'a mut CpuOwnedState,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// The CPU this carrier was built for: its owner's, by construction. There
    /// is no field to reselect (TSV row 85).
    const fn cpu(&self) -> crate::cpu::CpuIndex {
        self.owned.owner.cpu()
    }
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
    for user_access::PageTableMutationSession<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
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

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> crate::syscall::ThreadStartRetarget
    for user_access::ReturnValidationSession<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn retarget_for_thread_start(
        &mut self,
        process: ProcessKey,
    ) -> Result<(), deepwyrm_abi::DwStatus> {
        self.select_process_for_return_validation(process)
            .map_err(|_| DW_STATUS_BAD_STATE)
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
    PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// Records this CPU's last scheduled identity, the slot's single source,
    /// and mirrors it into the lock-free R1B liveness snapshot. The mirror is
    /// diagnostic only: nothing reads it to make a decision, and it exists so
    /// a stalled runtime can name each CPU's scheduled Process, Thread, root,
    /// context and stack without acquiring this authority. It names only this
    /// CPU's own identity, published when that identity is established.
    fn publish_last_scheduled(&mut self, identity: ScheduledIdentity) {
        self.own.last_scheduled = Some(identity);
        crate::debug::liveness::publish_current(
            self.cpu(),
            identity.thread.object_id().diagnostic_identity(),
            identity.process.object_id().diagnostic_identity(),
            identity.root_key.object_id().diagnostic_identity(),
            identity.context_id.diagnostic_identity(),
            identity.stack_id.diagnostic_identity(),
            crate::debug::liveness::LivenessEvent::CarrierSelected,
        );
    }

    fn begin_root_switch_flight(&mut self) -> RootSwitchFlight {
        let cpu = self.cpu();
        let epoch = &mut self.owned.root_switch_epoch;
        *epoch = epoch
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .unwrap_or_else(|| panic!("root-switch flight generation exhausted"));
        let flight = RootSwitchFlight {
            cpu,
            generation: *epoch,
        };
        if self.own.root_switch_flight.replace(flight).is_some() {
            panic!("CPU already owns an in-flight root switch");
        }
        flight
    }

    /// The commit or cancel of `flight` runs on the CPU that began it, against
    /// the transitioning slot that flight left.
    fn assert_root_switch_flight(&self, flight: RootSwitchFlight) {
        if flight.cpu != self.cpu() || self.own.root_switch_flight != Some(flight) {
            panic!("root-switch flight identity drifted before commit");
        }
        if !matches!(self.own.active_root, CarrierActiveRoot::Transitioning) {
            panic!("root-switch flight lost its transitioning carrier slot");
        }
    }

    fn finish_root_switch_flight(&mut self, flight: RootSwitchFlight) {
        if self.own.root_switch_flight != Some(flight) {
            panic!("root-switch flight identity drifted at commit");
        }
        self.own.root_switch_flight = None;
    }

    fn prepare_stop_root_switch(&mut self) -> PreparedStopRootSwitch {
        let previous =
            match core::mem::replace(&mut self.own.active_root, CarrierActiveRoot::Transitioning) {
                CarrierActiveRoot::StopPrecommitted(root) => root,
                _ => panic!("remote stop root switch omitted its precommitted Process root"),
            };
        let prepared = self
            .paging
            .lock()
            .prepare_kernel_execution_root_switch(previous)
            .unwrap_or_else(|(error, recovered)| {
                self.own.active_root = CarrierActiveRoot::StopPrecommitted(recovered);
                panic!("remote stop kernel-root preflight failed: {error:?}")
            });
        let flight = self.begin_root_switch_flight();
        PreparedStopRootSwitch::new(flight, prepared)
    }

    fn commit_stop_root_switch(&mut self, executed: ExecutedStopRootSwitch) {
        self.assert_root_switch_flight(executed.flight);
        let flight = executed.flight;
        let kernel = self
            .paging
            .lock()
            .commit_kernel_execution_root_switch(executed.into_executed());
        self.own.active_root = CarrierActiveRoot::Kernel(kernel);
        self.finish_root_switch_flight(flight);
    }

    fn cancel_stop_root_switch(
        &mut self,
        failure: FailedStopRootSwitch,
    ) -> super::RootBindingError {
        self.assert_root_switch_flight(failure.flight);
        let flight = failure.flight;
        let (error, previous) = failure.into_parts();
        self.own.active_root = CarrierActiveRoot::StopPrecommitted(previous);
        self.finish_root_switch_flight(flight);
        error
    }

    fn prepare_terminal_kernel_root_switch(&mut self) -> PreparedTerminalKernelRootSwitch {
        let previous = self.own.active_root.take_process();
        let prepared = self
            .paging
            .lock()
            .prepare_kernel_execution_root_switch(previous)
            .unwrap_or_else(|(error, recovered)| {
                self.own.active_root = CarrierActiveRoot::Process(recovered);
                panic!("terminal kernel-root preflight failed: {error:?}")
            });
        let flight = self.begin_root_switch_flight();
        PreparedTerminalKernelRootSwitch::new(flight, prepared)
    }

    fn commit_terminal_kernel_root_switch(&mut self, executed: ExecutedTerminalKernelRootSwitch) {
        self.assert_root_switch_flight(executed.flight);
        let flight = executed.flight;
        let kernel = self
            .paging
            .lock()
            .commit_kernel_execution_root_switch(executed.into_executed());
        self.own.active_root = CarrierActiveRoot::Kernel(kernel);
        self.finish_root_switch_flight(flight);
    }

    fn cancel_terminal_kernel_root_switch(
        &mut self,
        failure: FailedTerminalKernelRootSwitch,
    ) -> super::RootBindingError {
        self.assert_root_switch_flight(failure.flight);
        let flight = failure.flight;
        let (error, previous) = failure.into_parts();
        self.own.active_root = CarrierActiveRoot::Process(previous);
        self.finish_root_switch_flight(flight);
        error
    }

    fn prepare_terminal_primordial_root_switch(&mut self) -> PreparedTerminalProcessRootSwitch {
        let cpu = self.cpu();
        let prepared = self
            .paging
            .lock()
            .prepare_process_root_selection(
                cpu,
                self.core.primordial_process,
                self.core.primordial_address_space,
            )
            .unwrap_or_else(|error| {
                panic!("terminal idle publisher-root preparation failed: {error:?}")
            });
        let previous =
            match core::mem::replace(&mut self.own.active_root, CarrierActiveRoot::Transitioning) {
                CarrierActiveRoot::Kernel(root) => root,
                _ => panic!("terminal idle lost its kernel execution root"),
            };
        let prepared = self
            .paging
            .lock()
            .prepare_from_kernel_execution_root_switch(prepared, previous);
        let prepared = prepared.unwrap_or_else(|failure| {
            let (error, prepared, previous) = failure.into_parts();
            self.paging
                .lock()
                .abandon_process_root_selection(prepared)
                .unwrap_or_else(|abandon| {
                    panic!("terminal publisher-root abandonment failed: {abandon:?}")
                });
            self.own.active_root = CarrierActiveRoot::Kernel(previous);
            panic!("terminal publisher-root preflight failed: {error:?}")
        });
        let flight = self.begin_root_switch_flight();
        PreparedTerminalProcessRootSwitch::new(flight, prepared)
    }

    fn commit_terminal_primordial_root_switch(
        &mut self,
        executed: ExecutedTerminalProcessRootSwitch,
    ) {
        self.assert_root_switch_flight(executed.flight);
        let flight = executed.flight;
        let selected = self
            .paging
            .lock()
            .commit_from_kernel_execution_root_switch(executed.into_executed());
        self.own.active_root = CarrierActiveRoot::Process(selected);
        self.finish_root_switch_flight(flight);
    }

    fn cancel_terminal_primordial_root_switch(
        &mut self,
        failure: FailedTerminalProcessRootSwitch,
    ) -> super::RootBindingError {
        self.assert_root_switch_flight(failure.flight);
        let flight = failure.flight;
        let (error, prepared, previous) = failure.into_failure().into_parts();
        self.paging
            .lock()
            .abandon_process_root_selection(prepared)
            .unwrap_or_else(|abandon| {
                panic!("cancelled terminal publisher switch lost residency: {abandon:?}")
            });
        self.own.active_root = CarrierActiveRoot::Kernel(previous);
        self.finish_root_switch_flight(flight);
        error
    }

    fn prepare_ap_kernel_root_entry(&mut self) -> PreparedApKernelRootEntry {
        if self.cpu() == crate::cpu::CpuIndex::BOOTSTRAP
            || !matches!(self.own.active_root, CarrierActiveRoot::Unselected)
        {
            panic!("AP kernel-root entry requires an unselected AP carrier");
        }
        let cpu = self.cpu();
        let prepared = self
            .paging
            .lock()
            .prepare_ap_kernel_root_entry(cpu)
            .unwrap_or_else(|error| panic!("AP kernel-root entry preflight failed: {error:?}"));
        self.own.active_root = CarrierActiveRoot::Transitioning;
        let flight = self.begin_root_switch_flight();
        PreparedApKernelRootEntry::new(flight, prepared)
    }

    /// Commits the AP kernel-root entry and mints the executing state that
    /// proves it (TSV row 102): the only mint site.
    #[allow(
        unsafe_code,
        reason = "the kernel-root entry proof is minted only by its commit"
    )]
    fn commit_ap_kernel_root_entry(
        &mut self,
        executed: ExecutedApKernelRootEntry,
    ) -> crate::task::CarrierRuntimeState {
        self.assert_root_switch_flight(executed.flight);
        let flight = executed.flight;
        let kernel = self
            .paging
            .lock()
            .commit_ap_kernel_root_entry(executed.into_executed());
        self.own.active_root = CarrierActiveRoot::Kernel(kernel);
        self.finish_root_switch_flight(flight);
        // SAFETY: the `Executed` entry above exists only after its CR3 switch ran (`execute_on`),
        // and this CPU's carrier has just committed it as its active kernel root.
        unsafe { crate::task::CarrierRuntimeState::after_kernel_root_entry() }
    }

    fn cancel_ap_kernel_root_entry(
        &mut self,
        failure: FailedApKernelRootEntry,
    ) -> super::RootBindingError {
        self.assert_root_switch_flight(failure.flight);
        let flight = failure.flight;
        let (error, _prepared) = failure.into_parts();
        self.own.active_root = CarrierActiveRoot::Unselected;
        self.finish_root_switch_flight(flight);
        error
    }

    unsafe fn prepare_suspend_stationary(
        &mut self,
    ) -> crate::syscall::native::NativeSuspendPlan<'static> {
        #[cfg(feature = "test-support")]
        let owner = self
            .core
            .services
            .operation_owner(self.own.scheduled().thread);
        let cancelled_quantum = self.own.wait_control.pending_quantum_cancellation();
        self.stage_local_scheduler_quantum_cancellation(cancelled_quantum);
        let control = &mut self.own.wait_control;
        // SAFETY: [P-PLAN] forwarded: this `unsafe fn` has no `# Safety` section; its callers (the
        // `prepare_suspend` trait impls) supply the physically current `self.cpu()`, and the entry is
        // the fixed one.
        let plan = unsafe {
            self.core.services.prepare_suspend_on(
                control,
                self.owned.owner.cpu(),
                &self.core.tasks,
                &self.core.shared.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|error| panic!("primordial suspend preparation drifted: {error:?}"));
        plan
    }

    fn stage_local_scheduler_quantum_cancellation(
        &mut self,
        ticket: Option<crate::task::SchedulerQuantumTicket>,
    ) {
        let Some(ticket) = ticket else {
            return;
        };
        assert_eq!(ticket.cpu(), self.cpu(), "quantum cancellation changed CPU");
        assert!(
            self.own
                .pending_quantum_cancellation
                .replace(ticket)
                .is_none(),
            "CPU already owns a pending quantum cancellation"
        );
    }

    /// The one write to another CPU's slot (design §11.1): terminal
    /// preparation retired `cpu`'s unentered logical replacement, so `cpu`
    /// owns that replacement's quantum cancellation and performs it at its
    /// next safe point.
    fn stage_remote_scheduler_quantum_cancellation(
        &mut self,
        cpu: crate::cpu::CpuIndex,
        ticket: Option<crate::task::SchedulerQuantumTicket>,
    ) {
        let Some(ticket) = ticket else {
            return;
        };
        assert_eq!(ticket.cpu(), cpu, "quantum cancellation changed CPU");
        self.others.stage_remote(cpu, ticket);
    }

    fn take_local_scheduler_quantum_cancellation(
        &mut self,
    ) -> Option<crate::task::SchedulerQuantumTicket> {
        self.own.pending_quantum_cancellation.take()
    }

    fn commit_local_scheduler_quantum_cancellation(
        &self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) {
        assert_eq!(
            ticket.cpu(),
            self.cpu(),
            "quantum cancellation committed on another CPU"
        );
        assert!(
            self.own.pending_quantum_cancellation.is_none(),
            "a newer CPU-local cancellation overtook physical reconciliation"
        );
        assert_ne!(
            self.core
                .shared
                .execution
                .preemption_snapshot_on(self.cpu())
                .quantum,
            Some(ticket),
            "scheduler still owns the physically cancelled exact quantum"
        );
    }

    fn install_deferred_current(
        &mut self,
        deferred: crate::task::DeferredCurrentExecutionResources,
    ) {
        self.stage_local_scheduler_quantum_cancellation(deferred.cancelled_quantum());
        let slot = &mut self.own.deferred_current;
        assert!(slot.is_none(), "deferred current resources installed twice");
        *slot = Some(deferred);
    }

    /// # Safety
    ///
    /// Inherits `NativeRuntime::prepare_preemption`'s precondition: the caller
    /// must be the raw timer/syscall safe-boundary trampoline on the current
    /// Thread's bound kernel stack. The four callers in this file are those
    /// trait implementations; nothing else may reach it.
    unsafe fn prepare_preemption_stationary(
        &mut self,
    ) -> crate::syscall::native::NativePreemptionPlan<'static> {
        crate::debug::liveness::note_event(
            self.cpu(),
            crate::debug::liveness::LivenessEvent::Preempted,
        );
        match self
            .core
            .shared
            .execution
            .preempt_current_on(self.cpu())
            .unwrap_or_else(|error| panic!("DW1-B scheduler decision drifted: {error:?}"))
        {
            crate::task::SchedulerPreemptionDecision::Deferred => {
                panic!("DW1-B CPL3 return reached with preemption still disabled")
            }
            crate::task::SchedulerPreemptionDecision::RetainCurrent { .. } => {
                crate::syscall::native::NativePreemptionPlan::Return
            }
            crate::task::SchedulerPreemptionDecision::Switch { decision, outgoing } => {
                debug_assert_eq!(
                    self.core.shared.execution.suspended_claim_on(self.cpu()),
                    Some(outgoing)
                );
                // SAFETY: [P-PLAN] forwarded from this function's `# Safety`; `self.cpu()` is the
                // physically current CPU and the entry is the fixed `first_run_thread_entry_rip`.
                let plan = unsafe {
                    self.core
                        .shared
                        .execution
                        .prepare_preemptive_kernel_switch_on(
                            &self.core.tasks,
                            self.cpu(),
                            decision,
                            crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
                        )
                }
                .unwrap_or_else(|error| panic!("DW1-B switch preparation drifted: {error:?}"));
                crate::syscall::native::NativePreemptionPlan::Switch(plan)
            }
        }
    }

    /// # Safety
    ///
    /// The same precondition as `prepare_preemption_stationary` above.
    unsafe fn poll_idle_suspend_stationary(
        &mut self,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'static> {
        #[cfg(feature = "test-support")]
        let owner = self
            .core
            .services
            .operation_owner(self.own.scheduled().thread);
        let control = &mut self.own.wait_control;
        // SAFETY: [P-PLAN] forwarded from this function's `# Safety`; `self.cpu()` is the physically
        // current CPU and the entry is the fixed `first_run_thread_entry_rip`.
        let poll = unsafe {
            self.core.services.poll_idle_suspend_on(
                control,
                self.owned.owner.cpu(),
                &self.core.tasks,
                &self.core.shared.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|error| panic!("primordial idle-suspend poll drifted: {error:?}"));
        poll
    }

    fn prepare_fresh_user_entry_synchronized(
        &mut self,
    ) -> (
        crate::arch::x86_64::syscall::ValidatedUserReturn,
        crate::memory::kernel_stack::KernelStackBounds,
    ) {
        let context = self
            .core
            .shared
            .execution
            .load_context(self.own.scheduled().context_id)
            .unwrap_or_else(|error| panic!("could not load fresh Thread context: {error:?}"));
        let stack = self
            .core
            .shared
            .execution
            .stack_bounds(self.own.scheduled().stack_id)
            .unwrap_or_else(|error| panic!("could not load fresh Thread stack: {error:?}"));
        let state = {
            let regions = &self.core.regions;
            let memory = &self.core.memory;
            let demand = |process, address, execute| {
                regions.on_demand_return_allowed(process, address, execute, |object| {
                    memory.object_is_on_demand(object)
                })
            };
            let mut paging = self.paging.lock();
            let mut mappings = paging.return_validation_session(
                self.own.active_root.as_ref().expect("active root"),
                self.own.scheduled().process,
            );
            let mut mappings = OnDemandReturn {
                inner: &mut mappings,
                demand: &demand,
            };
            crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
                .unwrap_or_else(|error| panic!("invalid fresh Thread return: {error:?}"))
        };
        (state, stack)
    }

    fn prepare_terminal_retirement_state(&mut self) -> TerminalRetirementState {
        let retired_process = self.own.scheduled().process;
        let retired_root_key = self.own.scheduled().root_key;
        let retired_address_space = self
            .core
            .regions
            .region(retired_root_key)
            .unwrap_or_else(|error| panic!("terminal Process root disappeared: {error:?}"))
            .address_space_key();
        let deferred = self.own.deferred_current.take().unwrap_or_else(|| {
            if self
                .others
                .with_own(self.own)
                .any(|cpu| cpu.deferred_current.is_some())
            {
                panic!("terminal deferred resources migrated to another CPU")
            }
            if self
                .core
                .shared
                .execution
                .current_thread_on(self.cpu())
                .is_some()
            {
                panic!("terminal handoff retained a scheduler-current Thread")
            }
            if self
                .core
                .shared
                .execution
                .suspended_claim_on(self.cpu())
                .is_some()
            {
                panic!("terminal handoff retained a suspended claim without resources")
            }
            if self
                .core
                .shared
                .execution
                .running_claim_on(self.cpu())
                .is_some()
            {
                panic!("terminal handoff retained a Running claim without resources")
            }
            match self
                .core
                .shared
                .execution
                .scheduler_state(self.own.scheduled().thread)
            {
                Some(SchedulerThreadState::Reserved) => {
                    panic!("terminal handoff reached a reserved Thread without resources")
                }
                Some(SchedulerThreadState::Runnable) => {
                    panic!("terminal handoff reached a runnable Thread without resources")
                }
                Some(SchedulerThreadState::Running) => {
                    panic!("terminal handoff reached a Running Thread without resources")
                }
                Some(SchedulerThreadState::Blocked) => {
                    panic!("terminal handoff reached a blocked Thread without resources")
                }
                None => panic!("terminal handoff repeated after Thread retirement"),
            }
        });
        let exits_process = deferred.exits_process();
        crate::syscall::complete_deferred_current_reclaim_on(
            &mut self.core.registry,
            &self.core.shared.execution,
            &self.core.shared.waits,
            self.owned.owner.cpu(),
            deferred,
            &mut self.core.cleanup,
        );
        // Every terminal step below releases T before or across a guard-free
        // root switch, and a concurrent remote stop's commit requires the
        // shared queue empty (design §11.2.12 rule 4). The deferred reclaim
        // above can queue the Process's execution pin; the bound root region
        // still holds its parent reference, so the drain cannot finalize the
        // Process before its root retires.
        self.drain_finalizers()
            .unwrap_or_else(|_| panic!("terminal handoff could not drain its releases"));
        TerminalRetirementState {
            retired_process,
            retired_root_key,
            retired_address_space,
            exits_process,
        }
    }

    fn prepare_terminal_handoff_detached(&mut self) -> PreparedTerminalStep {
        let retirement = self.prepare_terminal_retirement_state();
        let next = self
            .core
            .shared
            .execution
            .terminal_reaper_next_on(self.cpu());
        let route = crate::task::terminal_handoff_route(next.is_some(), retirement.exits_process);
        if let Some(next) = next {
            assert_eq!(route, crate::task::TerminalHandoffRoute::Successor);
            let (stack_id, context_id) = self
                .core
                .tasks
                .thread_execution_resources(next)
                .unwrap_or_else(|error| panic!("terminal next resources failed: {error:?}"))
                .unwrap_or_else(|| panic!("terminal next Thread has no execution resources"));
            let stack = self
                .core
                .shared
                .execution
                .stack_bounds(stack_id)
                .unwrap_or_else(|error| panic!("terminal next stack failed: {error:?}"));
            let continuation = self
                .core
                .shared
                .execution
                .kernel_continuation_rsp(context_id)
                .unwrap_or_else(|error| panic!("terminal next continuation failed: {error:?}"));
            let state = TerminalSuccessorState {
                retirement,
                stack,
                continuation,
            };
            return match self.prepare_scheduler_root_switch() {
                Some(prepared) => PreparedTerminalStep::SchedulerRoot { prepared, state },
                None => PreparedTerminalStep::Final(self.finish_terminal_successor(state)),
            };
        }

        // Every arm below retires the Process: a retirement record, the
        // idle-path power-off decision, a root teardown. Only the Thread whose
        // own transition exited it takes them (design §11.2.12 rule 2). One
        // that left its Process live -- a non-final ThreadExit or a self
        // ThreadTerminate (§11.2.11) -- or whose Process another Thread's
        // transition exited, leaves the root for the kernel root and idles.
        if route == crate::task::TerminalHandoffRoute::LeaveRoot {
            // A non-owner of an exited child may be the last CPU resident on
            // its root, and then owes the teardown (§11.2.12 rule 3). Teardown
            // runs from a Process root, so it takes the owner's way out through
            // the primordial publisher root, without the record or the
            // power-off decision.
            let owes_teardown_attempt = retirement.retired_process != self.core.primordial_process
                && self
                    .core
                    .tasks
                    .process_info(retirement.retired_process)
                    .is_ok_and(|info| info.state == DW_TASK_STATE_EXITED);
            let continuation = if owes_teardown_attempt {
                TerminalKernelContinuation::EnterPrimordialPublisher(retirement)
            } else {
                TerminalKernelContinuation::FinishGenericChild(retirement)
            };
            let prepared = self.prepare_terminal_kernel_root_switch();
            return PreparedTerminalStep::KernelRoot {
                prepared,
                continuation,
            };
        }

        if retirement.retired_process != self.core.primordial_process {
            // F3A.7h. The one production record of a supervised process
            // ending. Every branch above that could say this is behind an
            // evidence cfg, so a production image reached its own shutdown
            // silently: the F3A.7g runs could see that the domain had not
            // powered off and could not see whether anything had exited.
            //
            // Emitted before the root switch, while this process's own
            // termination information is still readable, and ignored on
            // failure -- a busy COM1 must not change a retirement.
            #[cfg(not(feature = "test-support"))]
            if let Ok(info) = self.core.tasks.process_info(retirement.retired_process) {
                let primordial_live = matches!(
                    self.core.tasks.root_region(self.core.primordial_process),
                    Ok(Some(_))
                );
                let _ = crate::debug::emit_early_process_retirement_record(
                    info.application_code,
                    info.reason.0,
                    primordial_live,
                );
            }
            // F3A.7j. The primordial completion below is reached only when the
            // primordial Process is itself the last to exit. Under WYR1 it
            // never is: bootstrap hands off to permanent init and exits while
            // init is runnable, so its exit takes the successor path above,
            // and the Process that finally leaves the machine empty arrives
            // here. Idling then waits for nothing -- no Process remains to be
            // woken -- so F3A.7f's power-off was unreachable in production.
            // Asked only here, with nothing runnable on this CPU, and only of
            // Processes: one that still exists, in any state short of exited,
            // keeps the idle this path always took.
            #[cfg(not(feature = "test-support"))]
            if !self
                .core
                .tasks
                .any_process_unexited_except(retirement.retired_process)
            {
                let _ = crate::debug::emit_early_system_empty_record();
                return PreparedTerminalStep::Final(PreparedTerminalHandoff::PowerOff);
            }
            if crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
                != Some(self.cpu().index())
            {
                panic!("terminal idle facade resumed on another physical CPU")
            }
            if self
                .own
                .active_root
                .as_ref()
                .is_none_or(|previous| previous.cpu() != self.cpu())
            {
                panic!("terminal idle carrier retained another CPU's Process root")
            }
            let prepared = self.prepare_terminal_kernel_root_switch();
            return PreparedTerminalStep::KernelRoot {
                prepared,
                continuation: TerminalKernelContinuation::EnterPrimordialPublisher(retirement),
            };
        }

        // F3A.7k. Reaching here means the primordial is retiring with nothing
        // runnable on this CPU, which is completion only if it is also the
        // last Process. Under WYR1 on more than one CPU it is not: bootstrap
        // exits while init runs elsewhere, and the completion arm below found
        // the system not quiescent and -- since F3A.7f -- powered the machine
        // off mid-boot (F3A.7 q2, normal/smp). Retire it the way the
        // instrumented `RetireWyr1Primordial` does, without the evidence
        // reporter, and idle this CPU. The address space stays: it is the idle
        // carrier's publisher root, which `finish_quiesced_process_root_
        // retirement` never tears down for the primordial.
        #[cfg(not(feature = "test-support"))]
        if self
            .core
            .tasks
            .any_process_unexited_except(retirement.retired_process)
        {
            let proof = self
                .core
                .tasks
                .process_quiescence_proof(retirement.retired_process)
                .unwrap_or_else(|error| panic!("retiring primordial is not quiescent: {error:?}"));
            let drained = self
                .core
                .shared
                .execution
                .blocked_operations_drained(&self.core.tasks, &proof)
                .unwrap_or_else(|_| panic!("retiring primordial kept blocked operations"));
            self.unmap_primordial_userspace(&proof)
                .unwrap_or_else(|()| panic!("retiring primordial userspace unmap failed"));
            let prepared = self.prepare_terminal_kernel_root_switch();
            return PreparedTerminalStep::KernelRoot {
                prepared,
                continuation: TerminalKernelContinuation::RetirePrimordialToIdle {
                    retirement,
                    proof,
                    drained,
                },
            };
        }

        PreparedTerminalStep::Final(self.finish_primordial_terminal_handoff())
    }

    fn finish_terminal_successor(
        &mut self,
        state: TerminalSuccessorState,
    ) -> PreparedTerminalHandoff {
        if state.retirement.retired_process != self.own.scheduled().process {
            let _ = self.attempt_exited_root_teardown(state.retirement.retired_process);
        }
        // SAFETY: [P-HANDOFF] runs on this CPU's terminal reaper stack with IF clear, and holds no
        // entry-record reference; `state.stack` is the stack of the Thread resumed below.
        unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(state.stack) }
            .unwrap_or_else(|error| panic!("terminal next stack binding failed: {error:?}"));
        let continuation = if state.continuation == 0 {
            // SAFETY: [P-HANDOFF] continuation 0: the next Thread has never run, so its stack is
            // exclusively ours to build on, and the entry is the fixed
            // `first_run_thread_entry_rip`.
            unsafe {
                crate::arch::x86_64::context::prepare_initial_kernel_continuation(
                    state.stack,
                    crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
                )
            }
            .unwrap_or_else(|error| {
                panic!("terminal fresh continuation preparation failed: {error:?}")
            })
            .rsp()
        } else {
            state.continuation
        };
        crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(|error| {
            panic!("terminal next syscall boundary validation failed: {error:?}")
        });
        PreparedTerminalHandoff::Continuation(continuation)
    }

    fn continue_terminal_after_kernel_root(
        &mut self,
        continuation: TerminalKernelContinuation,
    ) -> PreparedTerminalStep {
        match continuation {
            TerminalKernelContinuation::EnterPrimordialPublisher(retirement) => {
                let prepared = self.prepare_terminal_primordial_root_switch();
                PreparedTerminalStep::PrimordialRoot {
                    prepared,
                    retirement,
                }
            }
            TerminalKernelContinuation::FinishGenericChild(retirement) => {
                let scheduled = self.own.scheduled();
                self.publish_last_scheduled(ScheduledIdentity {
                    process: self.core.primordial_process,
                    root_key: self.core.primordial_root_key,
                    ..scheduled
                });
                self.owned.physically_executing.record_idle();
                drop(retirement);
                PreparedTerminalStep::Final(PreparedTerminalHandoff::IdleScheduler)
            }
            #[cfg(not(feature = "test-support"))]
            TerminalKernelContinuation::RetirePrimordialToIdle {
                retirement,
                proof,
                drained,
            } => {
                self.finish_quiesced_process_root_retirement(
                    retirement.retired_process,
                    retirement.retired_address_space,
                    &proof,
                    drained,
                )
                .unwrap_or_else(|()| panic!("primordial root retirement failed"));
                self.owned.physically_executing.record_idle();
                PreparedTerminalStep::Final(PreparedTerminalHandoff::IdleScheduler)
            }
        }
    }

    fn continue_terminal_after_primordial_root(
        &mut self,
        retirement: TerminalRetirementState,
    ) -> PreparedTerminalStep {
        let _ = self.attempt_exited_root_teardown(retirement.retired_process);
        let prepared = self.prepare_terminal_kernel_root_switch();
        PreparedTerminalStep::KernelRoot {
            prepared,
            continuation: TerminalKernelContinuation::FinishGenericChild(retirement),
        }
    }

    fn finish_primordial_terminal_handoff(&mut self) -> PreparedTerminalHandoff {
        let completion = complete_primordial_launch(self);
        // Selector builds never run the primordial product.
        #[cfg(feature = "test-support")]
        unreachable!("selector builds do not run the primordial product: {completion:?}");
        #[cfg(not(feature = "test-support"))]
        {
            let record = crate::boot::primordial::construction::completion_record(&completion);
            let _ = crate::debug::emit_early_bootstrap_completion_record(
                record.level,
                record.cause,
                record.detail,
                record.exit.map(|exit| (exit.name(), exit.code())),
            );
            // Nothing remains runnable. Production used to halt here forever
            // while every instrumented build ended its domain through the
            // test-only debug-exit transport, so only an instrumented image
            // could finish a run. Power the platform off instead, once the
            // facade has dropped the guard; the fallback inside is the halt
            // loop this replaced.
            PreparedTerminalHandoff::PowerOff
        }
    }

    fn reserve_runtime_phase(&self) -> crate::arch::x86_64::syscall::RuntimePhaseReservation {
        let root = self
            .own
            .active_root
            .as_ref()
            .unwrap_or_else(|| panic!("runtime phase requires an active Process root"));
        crate::arch::x86_64::syscall::RuntimePhaseReservation::new(
            self.own.scheduled().thread,
            root.binding_generation(),
        )
        .unwrap_or_else(|_| panic!("runtime phase has an invalid exact root generation"))
    }

    fn commit_runtime_phase(&self, phase: crate::arch::x86_64::syscall::RuntimePhaseReservation) {
        let root = self
            .own
            .active_root
            .as_ref()
            .unwrap_or_else(|| panic!("runtime phase lost its active Process root"));
        phase
            .revalidate(self.own.scheduled().thread, root.binding_generation())
            .unwrap_or_else(|_| panic!("runtime phase identity drifted across guard-free work"));
    }

    #[track_caller]
    fn synchronize_scheduler_current(&mut self) {
        let Some(thread) = self.core.shared.execution.current_thread_on(self.cpu()) else {
            panic!("runtime carrier has no scheduler-current Thread");
        };
        let process = self
            .core
            .tasks
            .thread_process(thread)
            .unwrap_or_else(|error| panic!("scheduler-current Thread lost its Process: {error:?}"));
        let root_object = self
            .core
            .tasks
            .root_region(process)
            .unwrap_or_else(|error| {
                panic!("scheduler-current Process root lookup failed: {error:?}")
            })
            .unwrap_or_else(|| panic!("scheduler-current Process has no root AddressRegion"));
        let root_key =
            crate::memory::address_region::AddressRegionObjectKey::from_object_id(root_object);
        let address_space = self
            .core
            .regions
            .region(root_key)
            .unwrap_or_else(|error| panic!("scheduler-current root is unavailable: {error:?}"))
            .address_space_key();
        let (stack_id, context_id) = self
            .core
            .tasks
            .thread_execution_resources(thread)
            .unwrap_or_else(|error| panic!("scheduler-current resources failed: {error:?}"))
            .unwrap_or_else(|| panic!("scheduler-current Thread has no execution resources"));
        if self
            .own
            .active_root
            .as_ref()
            .is_some_and(|root| root.selects_exact(self.cpu(), process, address_space))
        {
            if let Err(error) = self.paging.lock().validate_current_process_root_selection(
                self.own.active_root.as_ref().expect("active root"),
                process,
                address_space,
            ) {
                match error {
                    super::RootBindingError::CpuMismatch => {
                        panic!("retained scheduler-current root names the wrong CPU")
                    }
                    super::RootBindingError::RootMismatch => {
                        panic!("retained scheduler-current root differs from hardware")
                    }
                    super::RootBindingError::Missing => {
                        panic!("retained scheduler-current root lost its binding")
                    }
                    super::RootBindingError::AlreadyActive
                    | super::RootBindingError::Resident
                    | super::RootBindingError::MutationInFlight => {
                        panic!("retained scheduler-current root has stale residency state")
                    }
                    _ => panic!("retained scheduler-current root validation failed"),
                }
            }
            // A sibling Thread, or a return to the root this CPU's slot
            // retains, keeps the unique root selection token and changes only the
            // scheduler-owned execution identity. Re-activating the same
            // address space would violate the residency protocol.
            self.publish_last_scheduled(ScheduledIdentity {
                process,
                thread,
                stack_id,
                context_id,
                root_key,
            });
            self.owned
                .physically_executing
                .record_current(thread, stack_id, context_id);
            return;
        }
        let cpu = self.cpu();
        let prepared = self
            .paging
            .lock()
            .prepare_process_root_selection(cpu, process, address_space)
            .unwrap_or_else(|error| panic!("could not prepare scheduler-current root: {error:?}"));
        let previous =
            core::mem::replace(&mut self.own.active_root, CarrierActiveRoot::Transitioning);
        let selected = match previous {
            CarrierActiveRoot::Unselected => {
                let activated = self
                    .paging
                    .lock()
                    .activate_process_root_selection(prepared, None);
                match activated {
                    Ok(selected) => selected,
                    Err(failure) => {
                        let (error, prepared, previous) = failure.into_parts();
                        debug_assert!(previous.is_none());
                        self.paging.lock()
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!("failed first root selection could not be abandoned: {abandon:?}")
                        });
                        self.own.active_root = CarrierActiveRoot::Unselected;
                        panic!("could not activate first scheduler-current root: {error:?}");
                    }
                }
            }
            CarrierActiveRoot::Process(previous) => {
                let activated = self
                    .paging
                    .lock()
                    .activate_process_root_selection(prepared, Some(previous));
                match activated {
                    Ok(selected) => selected,
                    Err(failure) => {
                        let (error, prepared, previous) = failure.into_parts();
                        self.paging
                            .lock()
                            .abandon_process_root_selection(prepared)
                            .unwrap_or_else(|abandon| {
                                panic!("failed root selection could not be abandoned: {abandon:?}")
                            });
                        self.own.active_root = CarrierActiveRoot::Process(previous.unwrap_or_else(|| {
                        panic!("runtime carrier lost its Process root during activation rollback")
                    }));
                        panic!("could not activate scheduler-current root: {error:?}");
                    }
                }
            }
            CarrierActiveRoot::Kernel(previous) => {
                let activated = self
                    .paging
                    .lock()
                    .activate_from_kernel_execution_root(prepared, previous);
                match activated {
                    Ok(selected) => selected,
                    Err(failure) => {
                        let (error, prepared, previous) = failure.into_parts();
                        self.paging
                        .lock()
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!(
                                "failed kernel-root selection could not be abandoned: {abandon:?}"
                            )
                        });
                        self.own.active_root = CarrierActiveRoot::Kernel(previous);
                        panic!(
                            "could not activate scheduler-current root from kernel root: {error:?}"
                        );
                    }
                }
            }
            CarrierActiveRoot::StopPrecommitted(_) | CarrierActiveRoot::Transitioning => {
                panic!("runtime carrier has no stable root while selecting scheduler current")
            }
        };
        // Publish the carrier identity only after CR3/residency selection is
        // complete. No usercopy can observe a mixed Process/root tuple.
        self.publish_last_scheduled(ScheduledIdentity {
            process,
            thread,
            stack_id,
            context_id,
            root_key,
        });
        self.own.active_root = CarrierActiveRoot::Process(selected);
        self.owned
            .physically_executing
            .record_current(thread, stack_id, context_id);
    }

    fn prepare_scheduler_root_switch(&mut self) -> Option<PreparedSchedulerRootSwitch> {
        let thread = self
            .core
            .shared
            .execution
            .current_thread_on(self.cpu())
            .unwrap_or_else(|| panic!("runtime carrier has no scheduler-current Thread"));
        let process = self
            .core
            .tasks
            .thread_process(thread)
            .unwrap_or_else(|error| panic!("scheduler-current Thread lost its Process: {error:?}"));
        let root_object = self
            .core
            .tasks
            .root_region(process)
            .unwrap_or_else(|error| {
                panic!("scheduler-current Process root lookup failed: {error:?}")
            })
            .unwrap_or_else(|| panic!("scheduler-current Process has no root AddressRegion"));
        let root_key =
            crate::memory::address_region::AddressRegionObjectKey::from_object_id(root_object);
        let address_space = self
            .core
            .regions
            .region(root_key)
            .unwrap_or_else(|error| panic!("scheduler-current root is unavailable: {error:?}"))
            .address_space_key();
        let (stack_id, context_id) = self
            .core
            .tasks
            .thread_execution_resources(thread)
            .unwrap_or_else(|error| panic!("scheduler-current resources failed: {error:?}"))
            .unwrap_or_else(|| panic!("scheduler-current Thread has no execution resources"));
        let identity = SchedulerRootIdentity {
            process,
            thread,
            root_key,
            stack_id,
            context_id,
        };
        if self
            .own
            .active_root
            .as_ref()
            .is_some_and(|root| root.selects_exact(self.cpu(), process, address_space))
        {
            self.paging
                .lock()
                .validate_current_process_root_selection(
                    self.own.active_root.as_ref().expect("active root"),
                    process,
                    address_space,
                )
                .unwrap_or_else(|error| {
                    panic!("retained scheduler-current root validation failed: {error:?}")
                });
            self.publish_scheduler_root_identity(identity);
            return None;
        }
        let cpu = self.cpu();
        let prepared = self
            .paging
            .lock()
            .prepare_process_root_selection(cpu, process, address_space)
            .unwrap_or_else(|error| panic!("could not prepare scheduler-current root: {error:?}"));
        let previous =
            core::mem::replace(&mut self.own.active_root, CarrierActiveRoot::Transitioning);
        let kind = match previous {
            CarrierActiveRoot::Unselected => ({
                let switched = self
                    .paging
                    .lock()
                    .prepare_process_root_switch(prepared, None);
                switched
            })
            .map(PreparedSchedulerRootSwitchKind::Process)
            .unwrap_or_else(|failure| {
                let (error, prepared, previous) = failure.into_parts();
                debug_assert!(previous.is_none());
                self.paging
                    .lock()
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("failed first root selection could not be abandoned: {abandon:?}")
                    });
                self.own.active_root = CarrierActiveRoot::Unselected;
                panic!("could not prepare first scheduler-current root switch: {error:?}");
            }),
            CarrierActiveRoot::Process(previous) => ({
                let switched = self
                    .paging
                    .lock()
                    .prepare_process_root_switch(prepared, Some(previous));
                switched
            })
            .map(PreparedSchedulerRootSwitchKind::Process)
            .unwrap_or_else(|failure| {
                let (error, prepared, previous) = failure.into_parts();
                self.paging
                    .lock()
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("failed root selection could not be abandoned: {abandon:?}")
                    });
                self.own.active_root = CarrierActiveRoot::Process(previous.unwrap_or_else(|| {
                    panic!("runtime carrier lost its Process root during switch preparation")
                }));
                panic!("could not prepare scheduler-current root switch: {error:?}");
            }),
            CarrierActiveRoot::Kernel(previous) => ({
                let switched = self
                    .paging
                    .lock()
                    .prepare_from_kernel_execution_root_switch(prepared, previous);
                switched
            })
            .map(PreparedSchedulerRootSwitchKind::FromKernel)
            .unwrap_or_else(|failure| {
                let (error, prepared, previous) = failure.into_parts();
                self.paging
                    .lock()
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("failed kernel-root selection could not be abandoned: {abandon:?}")
                    });
                self.own.active_root = CarrierActiveRoot::Kernel(previous);
                panic!("could not prepare scheduler-current switch from kernel root: {error:?}");
            }),
            CarrierActiveRoot::StopPrecommitted(_) | CarrierActiveRoot::Transitioning => {
                panic!("runtime carrier has no stable root while preparing scheduler current")
            }
        };
        let flight = self.begin_root_switch_flight();
        Some(PreparedSchedulerRootSwitch::new(flight, identity, kind))
    }

    fn commit_scheduler_root_switch(&mut self, executed: ExecutedSchedulerRootSwitch) {
        self.assert_root_switch_flight(executed.flight);
        let flight = executed.flight;
        let (identity, kind) = executed.into_parts();
        let selected = match kind {
            ExecutedSchedulerRootSwitchKind::Process(executed) => {
                self.paging.lock().commit_process_root_switch(executed)
            }
            ExecutedSchedulerRootSwitchKind::FromKernel(executed) => self
                .paging
                .lock()
                .commit_from_kernel_execution_root_switch(executed),
        };
        self.own.active_root = CarrierActiveRoot::Process(selected);
        self.publish_scheduler_root_identity(identity);
        self.finish_root_switch_flight(flight);
    }

    fn cancel_scheduler_root_switch(
        &mut self,
        failure: FailedSchedulerRootSwitch,
    ) -> super::RootBindingError {
        self.assert_root_switch_flight(failure.flight);
        let flight = failure.flight;
        let error = match failure.into_kind() {
            FailedSchedulerRootSwitchKind::Process(failure) => {
                let (error, prepared, previous) = failure.into_parts();
                self.paging
                    .lock()
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("cancelled Process root switch lost residency: {abandon:?}")
                    });
                self.own.active_root = previous
                    .map(CarrierActiveRoot::Process)
                    .unwrap_or(CarrierActiveRoot::Unselected);
                error
            }
            FailedSchedulerRootSwitchKind::FromKernel(failure) => {
                let (error, prepared, previous) = failure.into_parts();
                self.paging
                    .lock()
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("cancelled kernel-root switch lost residency: {abandon:?}")
                    });
                self.own.active_root = CarrierActiveRoot::Kernel(previous);
                error
            }
        };
        self.finish_root_switch_flight(flight);
        error
    }

    fn publish_scheduler_root_identity(&mut self, identity: SchedulerRootIdentity) {
        self.publish_last_scheduled(ScheduledIdentity {
            process: identity.process,
            thread: identity.thread,
            stack_id: identity.stack_id,
            context_id: identity.context_id,
            root_key: identity.root_key,
        });
        self.owned.physically_executing.record_current(
            identity.thread,
            identity.stack_id,
            identity.context_id,
        );
    }

    /// Publishes completion of the outgoing continuation only after this CPU
    /// has physically arrived on the selected destination stack.  Scheduler
    /// selection deliberately retains the suspended claim until this point so
    /// no other CPU can acquire a Runnable continuation before its saved RSP
    /// is visible.
    fn complete_physical_switch_handoff(&mut self) -> Option<crate::task::RunnablePublication> {
        if let Some(outgoing) = self.core.shared.execution.suspended_claim_on(self.cpu()) {
            let published = self
                .core
                .shared
                .execution
                .complete_switch_on(outgoing)
                .unwrap_or_else(|error| {
                    panic!("physical kernel switch completion drifted: {error:?}")
                });
            published
        } else {
            None
        }
    }

    fn merge_cleanup(&mut self, cleanup: &mut CleanupQueue<REGISTRY_OBJECTS>) {
        cleanup.drain_into(&mut self.core.cleanup);
    }

    /// Moves the F-service carrier's queued finalizers into this carrier's
    /// queue, without either queue leaving its owner.
    fn absorb_service_cleanup(&mut self) {
        self.core
            .services
            .drain_cleanup_into(&mut self.core.cleanup);
    }

    fn stage_rendezvous_cleanup(&mut self) {
        assert!(
            self.own.stopping_claim.is_none(),
            "remote stop staged cleanup twice on one CPU"
        );
        self.core.rendezvous_cleanup.stage(
            &mut self.core.cleanup,
            crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT,
        );
    }

    /// Moves a suspended F-service operation out of the stopped carrier before
    /// the Process root is released. e1 delivery after block commit has no
    /// Running claim, but it still owns exact wait/output/atomic cleanup that
    /// cannot be left to trip the post-commit quiescence check.
    fn transfer_suspended_service_cleanup_for_stop(&mut self) {
        if self.service_state_is_quiescent() {
            return;
        }
        let mut discarded = None;
        let mut atomic_pin = None;
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded.replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pin.replace(pin).is_none());
                },
            );
            terminal.cleanup_terminal_wait(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.waits,
                &self.core.shared.execution,
                self.own.scheduled().thread,
                &mut self.core.cleanup,
            );
        }
        {
            let mut paging = self.paging.lock();
            let mut user = paging.pin_settlement_session(
                self.own.active_root.as_ref().expect("active Process root"),
                self.own.scheduled().process,
            );
            if let Some(output) = discarded {
                user.discard_owned_output(output)
                    .unwrap_or_else(|_| panic!("rendezvous suspended output pin drifted"));
            }
            if let Some(pin) = atomic_pin {
                user.release_atomic_u32(pin)
                    .unwrap_or_else(|_| panic!("rendezvous suspended atomic pin drifted"));
            }
        }
        self.absorb_service_cleanup();
    }

    fn service_state_is_quiescent(&self) -> bool {
        self.core.services.is_quiescent()
            && self
                .others
                .with_own(self.own)
                .all(|cpu| cpu.wait_control.is_clear())
    }

    fn stopped_service_state_is_quiescent(&self) -> bool {
        matches!(
            self.core
                .services
                .operation_owner(self.own.scheduled().thread),
            Err(crate::syscall::FServiceOwnerError::Missing)
        ) && self.own.wait_control.is_clear()
    }

    fn drain_staged_rendezvous_cleanup(&mut self) {
        let _last = self.core.rendezvous_cleanup.finish(&mut self.core.cleanup);
        self.drain_finalizers()
            .unwrap_or_else(|_| panic!("post-ack rendezvous cleanup drifted"));
    }

    fn prepare_rendezvous_stop(
        &mut self,
        request: crate::arch::x86_64::rendezvous::StopRequest,
        reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> (
        crate::arch::x86_64::rendezvous::ExactSafeWitness,
        PreparedStopRootSwitch,
    ) {
        self.core.rendezvous_reaper = Some(reaper);
        let witness = crate::arch::x86_64::idle::prepare_current_rendezvous_stop(request, self)
            .unwrap_or_else(|error| {
                panic!("remote rendezvous stop failed before commit: {error:?}")
            });
        let root_switch = self.prepare_stop_root_switch();
        (witness, root_switch)
    }

    fn commit_rendezvous_stop(
        &mut self,
        witness: crate::arch::x86_64::rendezvous::ExactSafeWitness,
        root_switch: ExecutedStopRootSwitch,
    ) -> PreparedRendezvousNext {
        self.commit_stop_root_switch(root_switch);
        crate::arch::x86_64::idle::commit_current_rendezvous_stop(witness, self);
        self.prepare_after_rendezvous_stop()
    }

    /// Prepares the stopped CPU's next divergent entry as owned data. The
    /// caller must drop the coarse runtime guard before consuming the result.
    fn prepare_after_rendezvous_stop(&mut self) -> PreparedRendezvousNext {
        let stopped_claim = self
            .own
            .stopping_claim
            .take()
            .unwrap_or_else(|| panic!("rendezvous continuation lost its stopped claim"));
        // The exact-safe acknowledgement has already been Release-published.
        // We may now abandon the CPU-local retired continuation slot, but not
        // reclaim the stopped task/root/stack: that remains initiator-gated.
        self.core
            .shared
            .execution
            .complete_switch_on(stopped_claim)
            .unwrap_or_else(|error| {
                panic!("rendezvous continuation could not clear retired slot: {error:?}")
            });
        self.drain_staged_rendezvous_cleanup();
        let next = self
            .core
            .shared
            .execution
            .terminal_reaper_next_on(self.cpu());
        let Some(next) = next else {
            assert!(matches!(self.own.active_root, CarrierActiveRoot::Kernel(_)));
            return PreparedRendezvousNext::Idle;
        };
        let (stack_id, context_id) = self
            .core
            .tasks
            .thread_execution_resources(next)
            .unwrap_or_else(|error| panic!("rendezvous replacement resources failed: {error:?}"))
            .unwrap_or_else(|| panic!("rendezvous replacement Thread has no execution resources"));
        let stack = self
            .core
            .shared
            .execution
            .stack_bounds(stack_id)
            .unwrap_or_else(|error| panic!("rendezvous replacement stack failed: {error:?}"));
        let continuation = self
            .core
            .shared
            .execution
            .kernel_continuation_rsp(context_id)
            .unwrap_or_else(|error| {
                panic!("rendezvous replacement continuation failed: {error:?}")
            });
        PreparedRendezvousNext::Scheduled {
            stack,
            continuation,
        }
    }

    fn prepare_remote_process_exception(
        &mut self,
        exception: crate::task::TaskExceptionRecord,
    ) -> ProcessTerminationPreparation {
        let inspected_threads = crate::syscall::inspect_process_exit_threads(
            &self.core.tasks,
            self.own.scheduled().process,
        )
        .unwrap_or_else(|_| panic!("exception Process lost its Thread topology"));
        let plan = match self.terminal_stop_plan(&inspected_threads) {
            Ok(plan) => plan,
            Err(()) => return ProcessTerminationPreparation::Retry,
        };
        let phase = self.reserve_runtime_phase();
        let mut prepared = match self.prepare_process_exception_with_wait_cleanup(exception) {
            Ok(prepared) => prepared,
            Err(status) => {
                self.commit_runtime_phase(phase);
                return ProcessTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    status,
                ));
            }
        };
        assert_eq!(
            prepared.thread_keys(),
            inspected_threads,
            "exception terminal Thread set changed under runtime authority"
        );
        for thread in self
            .retire_unentered_terminal_replacements(plan.unentered)
            .into_iter()
            .flatten()
        {
            prepared.record_pre_retired(thread);
        }
        let identities = plan.identities;
        self.assert_terminal_stop_plan_unchanged(&inspected_threads, &identities);
        if identities.iter().all(Option::is_none) {
            return ProcessTerminationPreparation::Immediate(self.complete_process_termination(
                phase,
                prepared,
                core::array::from_fn(|_| None),
            ));
        }
        ProcessTerminationPreparation::Remote(PreparedRemoteProcessTermination {
            phase,
            prepared,
            identities,
        })
    }

    fn prepare_process_exception_with_wait_cleanup(
        &mut self,
        exception: crate::task::TaskExceptionRecord,
    ) -> Result<crate::syscall::PreparedProcessTermination<THREADS>, deepwyrm_abi::DwStatus> {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    *discarded
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("exception terminal output batch overflow") = Some(output);
                },
                |pin| {
                    *atomic_pins
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("exception terminal atomic-pin batch overflow") = Some(pin);
                },
            );
            crate::syscall::prepare_process_unhandled_exception(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.own.scheduled().process,
                self.own.scheduled().thread,
                exception,
                &mut self.core.cleanup,
            )
        };
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("exception terminal output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("exception terminal atomic pin drifted"));
        }
        self.absorb_service_cleanup();
        result
    }

    fn unmap_primordial_userspace(
        &mut self,
        proof: &crate::task::ProcessQuiescenceProof,
    ) -> Result<(), ()> {
        self.unmap_current_userspace(
            self.core.primordial_process,
            self.core.primordial_root_key,
            self.core.primordial_address_space,
            proof,
        )
    }

    fn unmap_current_userspace(
        &mut self,
        process: ProcessKey,
        root_key: crate::memory::address_region::AddressRegionObjectKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
        proof: &crate::task::ProcessQuiescenceProof,
    ) -> Result<(), ()> {
        self.paging
            .lock()
            .validate_current_process_root_selection(
                self.own.active_root.as_ref().ok_or(())?,
                process,
                address_space,
            )
            .map_err(|_| ())?;
        if self.own.scheduled().process != process || self.own.scheduled().root_key != root_key {
            return Err(());
        }
        let mut paging = self.paging.lock();
        let mut user =
            paging.page_table_mutation_session(self.own.active_root.as_ref().ok_or(())?, process);
        loop {
            let mapping = self
                .core
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
                    .core
                    .regions
                    .region_mut_for_quiesced_teardown(&self.core.tasks, proof, root_key)
                    .map_err(|_| ())?;
                let mut publisher = user
                    .publisher::<PRIMORDIAL_TABLE_CANDIDATES>(
                        region.address_space_key(),
                        region.region_key(),
                        &mut candidates,
                    )
                    .map_err(|_| ())?;
                region
                    .unmap(
                        &mut self.core.memory,
                        &mut self.core.registry,
                        &mut publisher,
                        mapping.virtual_start(),
                        mapping.byte_len(),
                    )
                    .unwrap_or_else(|failure| {
                        panic!(
                            "current process mapping teardown diverged: {:?}",
                            failure.error()
                        )
                    })
            };
            for candidate in candidates.into_iter().flatten() {
                user.recycle_table_candidate(candidate);
            }
            for release in releases.into_items().into_iter().flatten() {
                self.core.cleanup.push(release);
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
        let current_process = self.own.active_root.as_ref().ok_or(())?.process();
        if process == current_process {
            return Err(());
        }
        let mut paging = self.paging.lock();
        let mut user = paging
            .page_table_mutation_session(self.own.active_root.as_ref().ok_or(())?, current_process);
        user.select_process_for_return_validation(process)
            .map_err(|_| ())?;
        // Reviewed safe (DW2 §7.1 R2, 2026-11-13): every owned pin is drained
        // with its blocked operation or held by a CPU still resident on this
        // root, which the caller has ruled out. Checked here, before any
        // change, rather than failing partway through the unmaps below.
        let address_space = self
            .core
            .regions
            .region(root_key)
            .map_err(|_| ())?
            .address_space_key();
        assert!(
            !user.pins_hold_any(address_space),
            "an exited Process's address space still holds a user pin at teardown"
        );
        loop {
            let mapping = self
                .core
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
                    .core
                    .regions
                    .region_mut_for_quiesced_teardown(&self.core.tasks, proof, root_key)
                    .map_err(|_| ())?;
                let mut publisher = user
                    .publisher::<PRIMORDIAL_TABLE_CANDIDATES>(
                        region.address_space_key(),
                        region.region_key(),
                        &mut candidates,
                    )
                    .map_err(|_| ())?;
                region
                    .unmap(
                        &mut self.core.memory,
                        &mut self.core.registry,
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
                self.core.cleanup.push(release);
            }
        }
        user.select_process_for_return_validation(current_process)
            .map_err(|_| ())?;
        Ok(())
    }

    /// Design §11.2.12 rule 3: tears an exited Process's root down if this
    /// site is the one that makes all four conditions true -- exited,
    /// quiescent, root still bound, no CPU resident. Every caller has left the
    /// root or never entered it, so each resident counted is another CPU's,
    /// which tears the root down itself when it leaves. The primordial's
    /// address space stays as the idle carrier's publisher root, where idle
    /// CPUs reside; its residency does not hold back the primordial's root
    /// retirement, which `finish_quiesced_process_root_retirement` does
    /// without a teardown.
    // Kept out of line, with the teardown it calls, so the ordinary syscall
    // handler's measured frame does not absorb the remote completions'
    // teardown, and the DW1C terminal oracle can charge both frames.
    #[inline(never)]
    fn attempt_exited_root_teardown(
        &mut self,
        process: ProcessKey,
    ) -> crate::task::ExitedRootTeardown {
        let exited = self
            .core
            .tasks
            .process_info(process)
            .is_ok_and(|info| info.state == DW_TASK_STATE_EXITED);
        let quiescent = self.core.tasks.process_quiescence_proof(process).is_ok();
        // A finalized Process has no root left to tear down.
        let bound = self
            .core
            .tasks
            .root_region(process)
            .ok()
            .flatten()
            .map(|root_object| {
                let root_key =
                    crate::memory::address_region::AddressRegionObjectKey::from_object_id(
                        root_object,
                    );
                let address_space = self
                    .core
                    .regions
                    .region(root_key)
                    .unwrap_or_else(|error| panic!("exited Process root disappeared: {error:?}"))
                    .address_space_key();
                (root_key, address_space)
            });
        let residents = match bound {
            Some((_, address_space)) if process != self.core.primordial_process => self
                .paging
                .lock()
                .child_root_resident_count(process, address_space)
                .unwrap_or_else(|error| {
                    panic!("exited Process root residency query failed: {error:?}")
                }),
            _ => 0,
        };
        let decision =
            crate::task::exited_root_teardown(exited, quiescent, bound.is_some(), residents);
        if decision == crate::task::ExitedRootTeardown::TearDown {
            let (root_key, address_space) =
                bound.unwrap_or_else(|| panic!("an exited root teardown is owed only while bound"));
            self.finish_inactive_process_teardown(process, root_key, address_space)
                .unwrap_or_else(|_| panic!("exited Process root teardown drifted"));
        }
        decision
    }

    #[inline(never)]
    fn finish_inactive_process_teardown(
        &mut self,
        process: ProcessKey,
        root_key: crate::memory::address_region::AddressRegionObjectKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), ()> {
        let proof = self
            .core
            .tasks
            .process_quiescence_proof(process)
            .map_err(|_| ())?;
        let drained = self
            .core
            .shared
            .execution
            .blocked_operations_drained(&self.core.tasks, &proof)
            .map_err(|_| ())?;
        self.unmap_inactive_userspace(process, root_key, &proof)?;
        self.finish_quiesced_process_root_retirement(process, address_space, &proof, drained)?;
        Ok(())
    }

    /// Retires an exited child's empty root under the shootdown-initiator
    /// lock S (D1 option B4, design §11.2.9). S is taken beneath P before the
    /// teardown prepares, so the teardown waits for any family-G shootdown
    /// in flight, whose initiator holds S until its permit, instead of
    /// meeting `MutationInFlight`. A teardown publishes no remote request
    /// (it requires zero residents). S is released on its permit, or unused
    /// if it failed before its publication.
    fn teardown_child_root_under_initiator(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), super::RootBindingError> {
        let mut paging = self.paging.lock();
        let initiator = PRIMORDIAL_SHOOTDOWN_INITIATOR.acquire_beneath(&paging);
        match paging.teardown_empty_child_address_space(process, address_space) {
            Ok(permit) => {
                let _settled = initiator.release(
                    crate::memory::address_region::ShootdownOutcome::Completed(permit),
                );
                Ok(())
            }
            Err(error) => {
                initiator.release_unused();
                Err(error)
            }
        }
    }

    fn finish_quiesced_process_root_retirement(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
        proof: &crate::task::ProcessQuiescenceProof,
        drained: crate::task::BlockedOperationsDrained,
    ) -> Result<(), ()> {
        if process != self.core.primordial_process {
            self.teardown_child_root_under_initiator(process, address_space)
                .map_err(|_| ())?;
        }
        let root_pin = self
            .core
            .regions
            .retire_quiesced_root(
                &mut self.core.tasks,
                process,
                proof,
                self.core.shared.execution.blocked_operations(),
                drained,
            )
            .map_err(|_| ())?;
        self.core.cleanup.push_optional(
            self.core
                .registry
                .release_internal(root_pin)
                .map_err(|_| ())?,
        );
        self.drain_finalizers()?;
        Ok(())
    }

    fn release_terminal_authority(&mut self) -> Result<(), ()> {
        for reference in [
            self.core.kernel_peer.take(),
            self.core.process_monitor.take(),
        ]
        .into_iter()
        .flatten()
        {
            self.core.cleanup.push_optional(
                self.core
                    .registry
                    .release_handle(reference)
                    .map_err(|_| ())?,
            );
        }
        let root_owner = self.core.root_owner.take().ok_or(())?;
        self.core.cleanup.push_optional(
            self.core
                .registry
                .release_internal(root_owner)
                .map_err(|_| ())?,
        );
        Ok(())
    }

    #[cfg(deepwyrm_dw1e_platform)]
    fn retry_q35_finalizer_exact(
        &mut self,
        binding: crate::device::InterruptBinding,
    ) -> Result<(), ()> {
        let parent_release = {
            let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
            let mut paging = self.paging.lock();
            let mut finalizer = crate::object::PayloadFinalizer::new(
                &mut self.core.registry,
                &mut *paging.target.roles,
                &mut self.core.memory,
                &self.core.shared.events,
                &self.core.shared.timers,
                &mut timer_deadlines,
                &self.core.shared.channels,
                &self.core.shared.waits,
                &mut self.core.tasks,
                &mut self.core.spaces,
                &mut self.core.regions,
            )
            .with_device_resources(&self.core.shared.device_resources)
            .with_boot_resource_grants(&self.core.shared.boot_resource_grants)
            .with_interrupts(
                &self.core.shared.interrupts,
                &self.core.shared.interrupt_platform,
            );
            finalizer.retry_deferred_interrupt_exact(binding)
        };
        if let Some(parent_release) = parent_release {
            self.core.cleanup.push(parent_release);
            self.drain_finalizers()?;
        }
        Ok(())
    }

    #[cfg(deepwyrm_dw1e_platform)]
    fn service_q35_retirement_at_bsp_safe_point(&mut self) -> Result<(), ()> {
        if self.cpu() != crate::cpu::CpuIndex::BOOTSTRAP {
            return Ok(());
        }
        let pending = crate::time::pending_q35_bsp_retirement_check().map_err(|_| ())?;
        match pending {
            None => self.drain_finalizers(),
            Some(request) => match self
                .core
                .shared
                .interrupt_platform
                .retirement_request_status(request)
            {
                crate::device::Q35RetirementRequestStatus::Publishing => Ok(()),
                crate::device::Q35RetirementRequestStatus::Published(binding) => {
                    self.retry_q35_finalizer_exact(binding)
                }
                crate::device::Q35RetirementRequestStatus::Stale => {
                    crate::time::complete_q35_bsp_retirement_check(request).map_err(|_| ())
                }
            },
        }
    }

    fn drain_finalizers(&mut self) -> Result<(), ()> {
        loop {
            // Popping in place is what allows the cascade: finalizing one
            // release pushes its parents back onto this same queue, and they are
            // reached later in this loop rather than by a second pass over a
            // snapshot.
            while let Some(release) = self.core.cleanup.pop() {
                {
                    let batch = {
                        let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
                        let mut paging = self.paging.lock();
                        let mut finalizer = crate::object::PayloadFinalizer::new(
                            &mut self.core.registry,
                            &mut *paging.target.roles,
                            &mut self.core.memory,
                            &self.core.shared.events,
                            &self.core.shared.timers,
                            &mut timer_deadlines,
                            &self.core.shared.channels,
                            &self.core.shared.waits,
                            &mut self.core.tasks,
                            &mut self.core.spaces,
                            &mut self.core.regions,
                        )
                        .with_device_resources(&self.core.shared.device_resources)
                        .with_boot_resource_grants(&self.core.shared.boot_resource_grants)
                        .with_interrupts(
                            &self.core.shared.interrupts,
                            &self.core.shared.interrupt_platform,
                        );
                        finalizer.finalize_chain(release)
                    };
                    crate::syscall::complete_wait_wakes(
                        &mut self.core.registry,
                        &self.core.shared.execution,
                        batch,
                        &mut self.core.cleanup,
                    );
                }
            }
            let parent_release = {
                let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
                let mut paging = self.paging.lock();
                let mut finalizer = crate::object::PayloadFinalizer::new(
                    &mut self.core.registry,
                    &mut *paging.target.roles,
                    &mut self.core.memory,
                    &self.core.shared.events,
                    &self.core.shared.timers,
                    &mut timer_deadlines,
                    &self.core.shared.channels,
                    &self.core.shared.waits,
                    &mut self.core.tasks,
                    &mut self.core.spaces,
                    &mut self.core.regions,
                )
                .with_device_resources(&self.core.shared.device_resources)
                .with_boot_resource_grants(&self.core.shared.boot_resource_grants)
                .with_interrupts(
                    &self.core.shared.interrupts,
                    &self.core.shared.interrupt_platform,
                );
                finalizer.retry_deferred_interrupt()
            };
            let Some(parent_release) = parent_release else {
                break;
            };
            self.core.cleanup.push(parent_release);
        }
        Ok(())
    }

    fn service_pending_timer_expiries_on_bootstrap(&mut self) {
        assert_eq!(
            self.cpu(),
            crate::cpu::CpuIndex::BOOTSTRAP,
            "general Timer expiry service escaped CPU0 ownership"
        );
        let pending = {
            let mut inbox = self.core.shared.timer_expiries.lock();
            core::mem::replace(&mut *inbox, [None; crate::time::DEADLINE_QUEUE_CAPACITY])
        };
        for token in pending.into_iter().flatten() {
            let wakes = self
                .core
                .shared
                .timers
                .expire(token, &self.core.shared.waits)
                .unwrap_or_else(|error| panic!("primordial timer expiry drifted: {error:?}"));
            crate::syscall::complete_wait_wakes(
                &mut self.core.registry,
                &self.core.shared.execution,
                wakes,
                &mut self.core.cleanup,
            );
        }
        self.drain_finalizers()
            .unwrap_or_else(|_| panic!("timer expiry could not drain wake pins"));
    }

    fn prove_registry_capacity(&mut self) -> Result<(), ()> {
        let mut probes: [Option<crate::object::CreationRef>; REGISTRY_OBJECTS] =
            core::array::from_fn(|_| None);
        for index in 0..REGISTRY_OBJECTS {
            match self
                .core
                .registry
                .create(deepwyrm_abi::DW_OBJECT_TYPE_EVENT)
            {
                Ok(probe) => probes[index] = Some(probe),
                Err(_) => {
                    for probe in probes.into_iter().flatten() {
                        self.core.registry.cancel_creation(probe).map_err(|_| ())?;
                    }
                    return Err(());
                }
            }
        }
        for probe in probes.into_iter().flatten() {
            self.core.registry.cancel_creation(probe).map_err(|_| ())?;
        }
        Ok(())
    }

    fn finish_terminal_teardown(&mut self) -> Result<(), u32> {
        let service_residue = self.core.services.quiescence_residue();
        if service_residue != 0 {
            return Err(0x7000_0100_u32 | service_residue);
        }
        if let Some(cpu) = self
            .others
            .with_own(self.own)
            .position(|cpu| !cpu.wait_control.is_clear())
        {
            return Err(0x7000_0110_u32 | u32::try_from(cpu).unwrap_or(u32::MAX));
        }
        if self
            .core
            .shared
            .execution
            .scheduler_state(self.own.scheduled().thread)
            .is_some()
        {
            return Err(0x7000_0102_u32);
        }
        if self
            .core
            .shared
            .execution
            .blocked_operations()
            .has_thread(self.own.scheduled().thread)
        {
            return Err(0x7000_0103_u32);
        }
        let proof = self
            .core
            .tasks
            .process_quiescence_proof(self.own.scheduled().process)
            .map_err(|_| 0x7000_0002_u32)?;
        let drained = self
            .core
            .shared
            .execution
            .blocked_operations_drained(&self.core.tasks, &proof)
            .map_err(|_| 0x7000_0003_u32)?;
        let address_space = self
            .core
            .regions
            .region(self.own.scheduled().root_key)
            .map_err(|_| 0x7000_0004_u32)?
            .address_space_key();
        if self.own.scheduled().process == self.core.primordial_process {
            self.unmap_primordial_userspace(&proof)
                .map_err(|_| 0x7000_0005_u32)?;
        } else {
            // The terminal child remains the physically active root when no
            // successor is runnable. Move the unique residency token to the
            // permanently retained primordial/kernel root before touching the
            // child's low half. The child is then noncurrent, so teardown can
            // use its exact scratch-selected publisher and finally reclaim its
            // owned PML4 without ever publishing through the primordial root.
            let cpu = self.cpu();
            let prepared = self
                .paging
                .lock()
                .prepare_process_root_selection(
                    cpu,
                    self.core.primordial_process,
                    self.core.primordial_address_space,
                )
                .map_err(|_| 0x7000_0006_u32)?;
            let previous = Some(self.own.active_root.take_process());
            let activated = self
                .paging
                .lock()
                .activate_process_root_selection(prepared, previous);
            let selected = match activated {
                Ok(selected) => selected,
                Err(failure) => {
                    let (_error, prepared, previous) = failure.into_parts();
                    self.paging
                        .lock()
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|error| {
                            panic!("terminal safe-root rollback drifted: {error:?}")
                        });
                    self.own.active_root =
                        CarrierActiveRoot::Process(previous.unwrap_or_else(|| {
                            panic!(
                                "runtime carrier lost its Process root during activation rollback"
                            )
                        }));
                    return Err(0x7000_0007_u32);
                }
            };
            self.own.active_root = CarrierActiveRoot::Process(selected);
            self.unmap_inactive_userspace(
                self.own.scheduled().process,
                self.own.scheduled().root_key,
                &proof,
            )
            .map_err(|_| 0x7000_0008_u32)?;
            self.teardown_child_root_under_initiator(self.own.scheduled().process, address_space)
                .map_err(|_| 0x7000_0009_u32)?;
        }
        if self.core.memory.active_lease_count() != 0 {
            return Err(0x7000_000a_u32);
        }
        let root_pin = self
            .core
            .regions
            .retire_quiesced_root(
                &mut self.core.tasks,
                self.own.scheduled().process,
                &proof,
                self.core.shared.execution.blocked_operations(),
                drained,
            )
            .map_err(|_| 0x7000_000b_u32)?;
        self.core.cleanup.push_optional(
            self.core
                .registry
                .release_internal(root_pin)
                .map_err(|_| 0x7000_000c_u32)?,
        );
        self.release_terminal_authority()
            .map_err(|_| 0x7000_000d_u32)?;
        self.drain_finalizers().map_err(|_| 0x7000_000e_u32)?;
        if self.core.shared.boot_resource_grants.has_grants() {
            let owner = self
                .core
                .shared
                .boot_resource_grants
                .take_owner_if_all_grants_available()
                .map_err(|_| 0x7000_000e_u32)?;
            self.core.cleanup.push_optional(
                self.core
                    .registry
                    .release_internal(owner)
                    .map_err(|_| 0x7000_000e_u32)?,
            );
            self.drain_finalizers().map_err(|_| 0x7000_000e_u32)?;
        }
        if self.core.memory.active_lease_count() != 0
            || self
                .core
                .tasks
                .process_info(self.own.scheduled().process)
                .is_ok()
            || self
                .core
                .tasks
                .thread_info(self.own.scheduled().thread)
                .is_ok()
            || self
                .core
                .regions
                .region(self.own.scheduled().root_key)
                .is_ok()
            || !self.core.cleanup.is_empty()
        {
            return Err(0x7000_000f_u32);
        }
        self.prove_registry_capacity().map_err(|_| 0x7000_0010_u32)
    }
}

const fn primordial_channel_receive_error(error: ChannelError) -> u32 {
    match error {
        ChannelError::Capacity => 0x7100_0011,
        ChannelError::InvalidArgument => 0x7100_0012,
        ChannelError::InvalidEndpoint => 0x7100_0013,
        ChannelError::StalePair => 0x7100_0014,
        ChannelError::WouldBlock => 0x7100_0015,
        ChannelError::PeerClosed => 0x7100_0016,
        ChannelError::BufferTooSmall => 0x7100_0017,
        ChannelError::AccessDenied => 0x7100_0018,
        ChannelError::FinalizationMismatch => 0x7100_0019,
        // Its own code, not `WouldBlock`'s. This encoder exists so a primordial
        // receive failure names its cause, and "the shared payload pool was
        // empty" is a different cause from "the peer's queue was full".
        ChannelError::PayloadExhausted => 0x7100_001a,
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> PrimordialCompletionBackend
    for PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = u32;

    fn receive_ready(&mut self, output: &mut [u8; 40]) -> Result<usize, Self::Error> {
        let (bytes, wakes) = self
            .core
            .shared
            .channels
            .receive_into(self.core.channel_keys[0], output, &self.core.shared.waits)
            .map_err(primordial_channel_receive_error)?;
        let (wake_intents, pins) = wakes.into_parts();
        if wake_intents.into_iter().flatten().next().is_some()
            || pins.into_iter().flatten().next().is_some()
        {
            return Err(0x7100_0002_u32);
        }
        Ok(bytes)
    }

    fn observe_exit(&mut self) -> Result<PrimordialExitDisposition, Self::Error> {
        let info = self
            .core
            .tasks
            .process_info(self.own.scheduled().process)
            .map_err(|_| 0x7200_0001_u32)?;
        if info.state != DW_TASK_STATE_EXITED {
            return Err(0x7200_0002_u32);
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
    for PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
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
        if self.core.rendezvous_reaper.as_ref().is_none() {
            return Err(crate::arch::x86_64::rendezvous::RemoteStopError::UnsafePrecommit);
        }
        let registry = crate::arch::x86_64::smp::live_cpu_registry();
        let snapshot = registry
            .snapshot(self.cpu().index())
            .map_err(|_| crate::arch::x86_64::rendezvous::RemoteStopError::WrongIdentity)?;
        // An e1 Stop may arrive after the blocked syscall has committed its
        // exact Running generation into this CPU's suspended continuation.
        // Keep that case generation-bound; it is not a thread-only fallback.
        let suspended = self.core.shared.execution.suspended_claim_on(self.cpu());
        let running = self.core.shared.execution.running_claim_on(self.cpu());
        let matches_identity = |claim: crate::task::SchedulerExecutionClaim| {
            claim.thread() == identity.thread()
                && claim.generation() == identity.execution_generation()
        };
        let (claim, was_suspended) =
            if let Some(claim) = suspended.filter(|claim| matches_identity(*claim)) {
                (claim, true)
            } else if let Some(claim) = running.filter(|claim| matches_identity(*claim)) {
                (claim, false)
            } else {
                return Err(crate::arch::x86_64::rendezvous::RemoteStopError::StaleRequest);
            };
        let root = self
            .own
            .active_root
            .as_ref()
            .ok_or(crate::arch::x86_64::rendezvous::RemoteStopError::UnsafePrecommit)?;
        let scheduler_current_matches = !was_suspended
            && self.core.shared.execution.current_thread_on(self.cpu())
                == Some(self.own.scheduled().thread);
        // A block commit may have selected a logical replacement, but it has
        // not yet switched the physical carrier when this post-hlt e1 gate
        // runs. The CPU-private local record is the authoritative proof that
        // no replacement is executing on this stack/carrier.
        let suspended_carrier_matches = was_suspended
            && self
                .owned
                .physically_executing
                .physically_executes(self.own.scheduled().thread);
        if crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
            != Some(self.cpu().index())
            || identity.target_cpu() != self.cpu().index()
            || identity.cpu_online_generation() != snapshot.online_generation
            || identity.thread() != self.own.scheduled().thread
            || identity.execution_generation() != claim.generation()
            || identity.root_binding_generation() != root.binding_generation()
            || claim.thread() != self.own.scheduled().thread
            || !(scheduler_current_matches || suspended_carrier_matches)
        {
            return Err(crate::arch::x86_64::rendezvous::RemoteStopError::WrongIdentity);
        }
        self.paging
            .lock()
            .validate_current_process_root_selection(
                root,
                self.own.scheduled().process,
                root.address_space(),
            )
            .map_err(|_| crate::arch::x86_64::rendezvous::RemoteStopError::WrongIdentity)?;
        if !matches!(self.own.active_root, CarrierActiveRoot::Process(_)) {
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
            let thread = self.own.scheduled().thread;
            let control = &mut self.own.wait_control;
            self.core
                .services
                .retire_idle_control_for_stop(control, thread, claim.generation())
                .unwrap_or_else(|_| {
                    panic!("remote stop suspended idle control drifted before precommit")
                });
            self.transfer_suspended_service_cleanup_for_stop();
        }
        self.stage_rendezvous_cleanup();
        let reaper = self
            .core
            .rendezvous_reaper
            .take()
            .expect("reaper witness disappeared after successful precommit");
        let previous =
            core::mem::replace(&mut self.own.active_root, CarrierActiveRoot::Transitioning);
        let CarrierActiveRoot::Process(root) = previous else {
            panic!("remote stop precommit lost the active Process root");
        };
        let _ = reaper;
        self.own.active_root = CarrierActiveRoot::StopPrecommitted(root);
        self.own.stopping_claim = Some(claim);
        self.own.stopping_claim_was_suspended = was_suspended;
        Ok(witness)
    }

    fn release_running_ownership(&mut self) {
        let claim = self
            .own
            .stopping_claim
            .take()
            .unwrap_or_else(|| panic!("remote stop commit omitted its exact Running claim"));
        if self.own.stopping_claim_was_suspended {
            self.core
                .shared
                .execution
                .stop_suspended_claim_on(claim)
                .unwrap_or_else(|error| {
                    panic!("remote stop suspended claim drifted after precommit: {error:?}")
                });
        } else {
            let cancelled_quantum = self
                .core
                .shared
                .execution
                .stop_running_claim_on(claim)
                .unwrap_or_else(|error| {
                    panic!("remote stop Running claim drifted after precommit: {error:?}")
                });
            self.stage_local_scheduler_quantum_cancellation(cancelled_quantum);
        }
        self.own.stopping_claim = Some(claim);
    }

    fn release_root_residency(&mut self) {
        let previous =
            match core::mem::replace(&mut self.own.active_root, CarrierActiveRoot::Transitioning) {
                CarrierActiveRoot::StopPrecommitted(root) => root,
                _ => panic!("remote stop root release without an exact Process selection"),
            };
        match self.paging.lock().enter_kernel_execution_root(previous) {
            Ok(kernel) => self.own.active_root = CarrierActiveRoot::Kernel(kernel),
            Err((error, recovered)) => {
                self.own.active_root = CarrierActiveRoot::StopPrecommitted(recovered);
                panic!("remote stop kernel-root handoff drifted after Running release: {error:?}");
            }
        }
    }

    fn deferred_cleanup_is_quiescent(&self) -> bool {
        let stopped = self
            .own
            .stopping_claim
            .unwrap_or_else(|| panic!("remote stop cleanup omitted its exact stopped claim"));
        self.core.cleanup.is_empty()
            && self.core.rendezvous_cleanup.is_staged()
            && self.stopped_service_state_is_quiescent()
            && self.own.deferred_current.is_none()
            && self
                .core
                .shared
                .execution
                .running_claim_on(self.cpu())
                .is_none_or(|running| running.thread() != stopped.thread())
    }
}

#[allow(
    unsafe_code,
    reason = "the target runtime propagates the physical-current carrier and architecture-owned first-run entry"
)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn prepare_quantum(
        &mut self,
        sample_now_ns: impl FnOnce() -> u64,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, crate::task::SchedulerError> {
        // The facade already holds runtime authority. Finish the independent
        // clock sample before acquiring scheduler authority; component locks
        // remain sequential and no pre-runtime-lock sample spends this budget.
        let now_ns = sample_now_ns();
        self.core
            .shared
            .execution
            .prepare_quantum_if_needed_on(self.cpu(), now_ns)
    }

    fn has_reschedule_request(&mut self) -> bool {
        self.core
            .shared
            .execution
            .has_reschedule_request_on(self.cpu())
    }

    fn authorize_timer_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawCpl3TimerReturnFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if self.core.tasks.thread_process(self.own.scheduled().thread)
            != Ok(self.own.scheduled().process)
            || self.core.shared.execution.current_thread_on(self.cpu())
                != Some(self.own.scheduled().thread)
        {
            return Err(crate::arch::x86_64::syscall::UserReturnError::BindingChanged);
        }
        let regions = &self.core.regions;
        let memory = &self.core.memory;
        let demand = |process, address, execute| {
            regions.on_demand_return_allowed(process, address, execute, |object| {
                memory.object_is_on_demand(object)
            })
        };
        let mut paging = self.paging.lock();
        let mut mappings = paging.return_validation_session(
            self.own.active_root.as_ref().expect("active root"),
            self.own.scheduled().process,
        );
        frame.validate_and_sanitize(&mut OnDemandReturn {
            inner: &mut mappings,
            demand: &demand,
        })
    }

    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if self.core.tasks.thread_process(self.own.scheduled().thread)
            != Ok(self.own.scheduled().process)
            || self
                .core
                .shared
                .execution
                .scheduler_state(self.own.scheduled().thread)
                != Some(SchedulerThreadState::Running)
        {
            return Err(crate::arch::x86_64::syscall::UserReturnError::BindingChanged);
        }
        let regions = &self.core.regions;
        let memory = &self.core.memory;
        let demand = |process, address, execute| {
            regions.on_demand_return_allowed(process, address, execute, |object| {
                memory.object_is_on_demand(object)
            })
        };
        let mut paging = self.paging.lock();
        let mut mappings = paging.return_validation_session(
            self.own.active_root.as_ref().expect("active root"),
            self.own.scheduled().process,
        );
        frame.authorize_return(
            current_binding_generation,
            &mut OnDemandReturn {
                inner: &mut mappings,
                demand: &demand,
            },
        )?;
        drop(mappings);
        drop(paging);
        Ok(())
    }

    /// Resumes a suspended F operation under the runtime authority. Its user
    /// effects, the wait output's settlement or the atomic pin's release, are
    /// recorded, not applied: the caller applies them with P alone after the
    /// authority (D1 commit 8, design §11.2.3 family E).
    fn resume_suspended(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> ResumeSettlement {
        self.synchronize_scheduler_current();
        let publication = self.complete_physical_switch_handoff();
        crate::task::notify_completed_switch_runnable(publication);
        #[cfg(feature = "test-support")]
        let owner = self
            .core
            .services
            .operation_owner(self.own.scheduled().thread);
        let mut settlement = crate::syscall::DeferredWaitSettlement::new();
        let resumed = {
            let mut deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
            self.core.services.resume_suspended(
                &mut settlement,
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.waits,
                &self.core.shared.execution,
                self.own.scheduled().thread,
                Some(&mut deadlines),
            )
        }
        .unwrap_or_else(|error| panic!("primordial suspended syscall resume drifted: {error:?}"));
        let status = resumed.status();
        self.absorb_service_cleanup();
        frame.set_status(status);
        let (output, pin) = settlement.into_parts();
        ResumeSettlement {
            root: self
                .own
                .active_root
                .as_ref()
                .expect("active root")
                .usercopy_root(),
            process: self.own.scheduled().process,
            output,
            pin,
        }
    }
}

#[cfg(test)]
const fn primordial_receive_failure_tag(code: u32) -> u32 {
    match code {
        0x7100_0011 => 1,
        0x7100_0012 => 2,
        0x7100_0013 => 3,
        0x7100_0014 => 4,
        0x7100_0015 => 5,
        0x7100_0016 => 6,
        0x7100_0017 => 7,
        0x7100_0018 => 8,
        0x7100_0019 => 9,
        0x7100_0002 => 0xa,
        _ => 0xf,
    }
}

#[cfg(test)]
fn primordial_completion_case(
    error: crate::boot::primordial::construction::PrimordialCompletionError<u32>,
    terminal_info: Option<deepwyrm_abi::DwTaskTerminationInfoV1>,
) -> u32 {
    use crate::boot::primordial::construction::PrimordialCompletionError;

    // The canonical detail has only sixteen selector-local bits, so it cannot
    // retain both arbitrary u32 values losslessly. Receive failures use ETVV:
    // T is the exact bounded Channel/wake tag and VV is the most actionable
    // terminal category (including exact AF01_0002 versus bootstrap-family).
    // Other completion stages retain their existing stable low-byte detail.
    match error {
        PrimordialCompletionError::Receive(code, _) => {
            0xe000
                | (primordial_receive_failure_tag(code) << 8)
                | primordial_terminal_summary(terminal_info)
        }
        PrimordialCompletionError::MalformedReady(_) => 0xd200,
        PrimordialCompletionError::ObserveExit(code) => 0xd300 | (code & 0xff),
        PrimordialCompletionError::NonzeroExit(code) => 0xd400 | (code & 0xff),
        PrimordialCompletionError::UnhandledException => 0xd500,
        PrimordialCompletionError::AuthorizedTermination => 0xd600,
        PrimordialCompletionError::NotQuiescent(code, _) => 0xd700 | (code & 0xff),
    }
}

impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler
    for RuntimeCarrierFacade<'_, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        // Every result that returns to the caller leaves through the carrier's
        // `ready_to_return` under the guard that produced it, terminal results
        // included, so none resumes userspace with final releases still queued.
        let ready: crate::syscall::native::ReturnReady = 'handled: {
            if matches!(
                request,
                NativeSyscallRequest::ProcessExit { .. }
                    | NativeSyscallRequest::ProcessTerminate { .. }
                    | NativeSyscallRequest::TaskGroupTerminate { .. }
                    | NativeSyscallRequest::ThreadTerminate { .. }
            ) {
                assert!(
                    self.pending_remote_termination.is_none(),
                    "CPU-local carrier already owns a pending remote termination"
                );
                crate::debug::liveness::note_event(
                    self.cpu,
                    crate::debug::liveness::LivenessEvent::TerminationPrepared,
                );
                if !self.synchronize_scheduler_current_at_safe_point_detached() {
                    break 'handled crate::syscall::native::ReturnReady::service_rendezvous();
                }
                loop {
                    let mut guard = self.runtime.lock();
                    let mut runtime = guard.on(&mut self.owned);
                    if matches!(
                        crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
                        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
                    ) {
                        break 'handled crate::syscall::native::ReturnReady::service_rendezvous();
                    }
                    let prepared = match request {
                        NativeSyscallRequest::ProcessExit { exit_code } => {
                            match runtime.prepare_remote_process_exit(exit_code) {
                                ProcessTerminationPreparation::Retry => {
                                    drop(guard);
                                    for _ in 0..64 {
                                        core::hint::spin_loop();
                                    }
                                    continue;
                                }
                                ProcessTerminationPreparation::Immediate(result) => {
                                    let ready = runtime.ready_to_return(result);
                                    drop(guard);
                                    self.drain_quantum_cancellation_detached();
                                    break 'handled ready;
                                }
                                ProcessTerminationPreparation::Remote(prepared) => {
                                    let phase = prepared.phase;
                                    let identities = prepared.identities;
                                    let pending = PendingRemoteTermination::Process(
                                        PendingRemoteProcessTermination {
                                            phase,
                                            prepared: prepared.prepared,
                                            deferred: core::array::from_fn(|_| None),
                                        },
                                    );
                                    (identities, pending)
                                }
                            }
                        }
                        NativeSyscallRequest::ProcessTerminate {
                            process,
                            reason,
                            code,
                        } => {
                            match runtime.prepare_remote_process_termination(process, reason, code)
                            {
                                ProcessTerminationPreparation::Retry => {
                                    unreachable!(
                                        "external Process termination uses an ordinary retry status"
                                    )
                                }
                                ProcessTerminationPreparation::Immediate(result) => {
                                    let ready = runtime.ready_to_return(result);
                                    drop(guard);
                                    self.drain_quantum_cancellation_detached();
                                    break 'handled ready;
                                }
                                ProcessTerminationPreparation::Remote(prepared) => {
                                    let phase = prepared.phase;
                                    let identities = prepared.identities;
                                    let pending = PendingRemoteTermination::Process(
                                        PendingRemoteProcessTermination {
                                            phase,
                                            prepared: prepared.prepared,
                                            deferred: core::array::from_fn(|_| None),
                                        },
                                    );
                                    (identities, pending)
                                }
                            }
                        }
                        NativeSyscallRequest::TaskGroupTerminate { task_group, reason } => {
                            match runtime.prepare_remote_task_group_termination(task_group, reason)
                            {
                                TaskGroupTerminationPreparation::Immediate(result) => {
                                    let ready = runtime.ready_to_return(result);
                                    drop(guard);
                                    self.drain_quantum_cancellation_detached();
                                    break 'handled ready;
                                }
                                TaskGroupTerminationPreparation::Remote(prepared) => {
                                    let phase = prepared.phase;
                                    let identities = prepared.identities;
                                    let pending = PendingRemoteTermination::TaskGroup(
                                        PendingRemoteTaskGroupTermination {
                                            phase,
                                            prepared: prepared.prepared,
                                            deferred: core::array::from_fn(|_| None),
                                        },
                                    );
                                    (identities, pending)
                                }
                            }
                        }
                        NativeSyscallRequest::ThreadTerminate {
                            thread,
                            reason,
                            code,
                        } => {
                            match runtime.prepare_remote_thread_termination(thread, reason, code) {
                                ThreadTerminationPreparation::Immediate(result) => {
                                    let ready = runtime.ready_to_return(result);
                                    drop(guard);
                                    self.drain_quantum_cancellation_detached();
                                    break 'handled ready;
                                }
                                ThreadTerminationPreparation::Remote(prepared) => {
                                    let phase = prepared.phase;
                                    let identities = prepared.identities;
                                    let pending = PendingRemoteTermination::Thread(
                                        PendingRemoteThreadTermination {
                                            phase,
                                            prepared: prepared.prepared,
                                            deferred: core::array::from_fn(|_| None),
                                        },
                                    );
                                    (identities, pending)
                                }
                            }
                        }
                        _ => unreachable!("terminal request classification drifted"),
                    };
                    let (identities, mut pending) = prepared;
                    // Publish while the same authority guard still orders the terminal
                    // state transition. A target that was already in syscall entry
                    // must either finish its earlier guarded transaction or observe
                    // this Stop after acquiring it.
                    for (cpu_index, identity) in identities.into_iter().enumerate() {
                        let Some(identity) = identity else {
                            continue;
                        };
                        let deferred =
                            crate::arch::x86_64::idle::publish_live_remote_stop(identity, ())
                                .unwrap_or_else(|failure| {
                                    let error = failure.error();
                                    let _resource = failure.into_resource();
                                    panic!("remote-stop publication failed: {error:?}")
                                });
                        match &mut pending {
                            PendingRemoteTermination::Process(pending) => {
                                pending.deferred[cpu_index] = Some(deferred)
                            }
                            PendingRemoteTermination::TaskGroup(pending) => {
                                pending.deferred[cpu_index] = Some(deferred)
                            }
                            PendingRemoteTermination::Thread(pending) => {
                                pending.deferred[cpu_index] = Some(deferred)
                            }
                        }
                    }
                    self.pending_remote_termination = Some(pending);
                    break 'handled crate::syscall::native::ReturnReady::complete_remote_stop();
                }
            }
            let handled = match self
                .fill_in_user_buffers(request)
                .or_else(|| self.handle_guard_free_usercopy(request))
                .or_else(|| self.handle_deferred_output(request))
                .or_else(|| self.handle_object_info(request))
                .or_else(|| self.handle_channel_send(request))
                .or_else(|| self.handle_channel_receive(request))
                .or_else(|| self.handle_process_create(request))
                .or_else(|| self.handle_wait(request))
                .or_else(|| self.handle_atomic_wait(request))
                .or_else(|| self.handle_address_region_mutation(request))
                .or_else(|| self.handle_memory_object_commit(request))
                .or_else(|| self.handle_thread_start(request))
            {
                Some(handled) => handled,
                None => {
                    let cpu = self.cpu;
                    self.with_synchronized_runtime_at_safe_point(|runtime| {
                        if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                            runtime.service_pending_timer_expiries_on_bootstrap();
                        }
                        runtime.handle(request)
                    })
                }
            };
            let ready = match handled {
                Ok(ready) => ready,
                Err(()) => {
                    break 'handled crate::syscall::native::ReturnReady::service_rendezvous();
                }
            };
            crate::task::drain_runnable_work_notifications();
            self.drain_quantum_cancellation_detached();
            ready
        };
        ready.into_result()
    }
}

impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::native::NativeRendezvousRuntime
    for RuntimeCarrierFacade<'_, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn rendezvous_stop(
        this: DivergentCarrier<'_, Self>,
        request: crate::arch::x86_64::rendezvous::StopRequest,
        reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> ! {
        let mut carrier = this;
        let this = carrier.get();
        let (witness, root_switch) = {
            let mut guard = this.runtime.lock();
            let mut runtime = guard.on(&mut this.owned);
            runtime.prepare_rendezvous_stop(request, reaper)
        };
        let root_switch = match root_switch.execute(this.runtime.guard_free()) {
            Ok(executed) => executed,
            Err(failure) => {
                let mut guard = this.runtime.lock();
                let mut runtime = guard.on_root_switch_flight(&mut this.owned);
                let error = runtime.cancel_stop_root_switch(failure);
                panic!("detached remote-stop root switch failed before CR3: {error:?}")
            }
        };
        let next = {
            let mut guard = this.runtime.lock();
            let mut runtime = guard.on_root_switch_flight(&mut this.owned);
            runtime.commit_rendezvous_stop(witness, root_switch)
        };
        this.drain_quantum_cancellation_detached();
        let entry = match next {
            PreparedRendezvousNext::Idle => PreparedCarrierEntry::Idle,
            PreparedRendezvousNext::Scheduled {
                stack,
                continuation,
            } => {
                if !this.synchronize_scheduler_current_at_safe_point_detached() {
                    crate::arch::x86_64::syscall::handoff_current_rendezvous_from_carrier(
                        carrier.release(),
                    )
                }
                if continuation == 0 {
                    let (state, stack) = {
                        let mut guard = this.runtime.lock();
                        let mut runtime = guard.on(&mut this.owned);
                        runtime.prepare_fresh_user_entry_synchronized()
                    };
                    PreparedCarrierEntry::Fresh { state, stack }
                } else {
                    PreparedCarrierEntry::Continuation {
                        stack,
                        rsp: continuation,
                    }
                }
            }
        };
        match entry {
            PreparedCarrierEntry::Fresh { state, stack } => {
                // SAFETY: [P-HANDOFF] on this CPU's rendezvous reaper stack with IF clear; `stack`
                // is the scheduled Thread's, entered below.
                let bound =
                    unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                        .unwrap_or_else(|error| {
                            panic!("rendezvous fresh stack binding failed: {error:?}")
                        });
                // SAFETY: [P-HANDOFF] `state` was validated for the scheduled Thread's Process and
                // `bound` proves the binding just above; the callee rechecks both bindings.
                unsafe {
                    crate::arch::x86_64::syscall::enter_bound_validated_user(
                        &state,
                        bound,
                        carrier.release(),
                    )
                }
            }
            PreparedCarrierEntry::Continuation { stack, rsp } => {
                // SAFETY: [P-HANDOFF] on this CPU's rendezvous reaper stack with IF clear; `stack`
                // is the scheduled Thread's, resumed below.
                unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                    .unwrap_or_else(|error| {
                        panic!("rendezvous replacement stack binding failed: {error:?}")
                    });
                crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(
                    |error| panic!("rendezvous replacement boundary failed: {error:?}"),
                );
                // SAFETY: [P-HANDOFF] `rsp` is the scheduled Thread's saved continuation and its
                // stack is bound above; this reaper frame is abandoned.
                unsafe {
                    crate::arch::x86_64::context::abandon_to_kernel_continuation(
                        rsp,
                        carrier.release(),
                    )
                }
            }
            PreparedCarrierEntry::Idle => Self::enter_idle_scheduler(carrier),
        }
    }
}

#[allow(
    unsafe_code,
    reason = "CPU-local carrier callbacks serialize shared authorities and drop their coarse guard before every AP idle or userspace handoff"
)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::native::GuardFreeSource
    for RuntimeCarrierFacade<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn guard_free(&mut self) -> GuardFree<'_> {
        self.runtime.guard_free()
    }
}

impl<'runtime, 'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    NativeSyscallFrameRuntime
    for RuntimeCarrierFacade<'runtime, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type QuantumExpiry = QuantumExpiryPublisher;

    fn prepare_quantum(
        &mut self,
        sample_now_ns: impl FnOnce() -> u64,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, crate::task::SchedulerError> {
        match self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.prepare_quantum(sample_now_ns)
        }) {
            Ok(result) => result,
            Err(()) => Ok(None),
        }
    }

    fn has_reschedule_request(&mut self) -> bool {
        let cpu = self.cpu;
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            // A general Timer deadline publishes its completion token from the
            // Local APIC interrupt before the scheduler may return a woken
            // Thread to userspace. Drain that token at this carrier-owned safe
            // point so the Thread cannot close/rearm the Timer while its prior
            // completion remains buffered in the bounded IRQ inbox.
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.has_reschedule_request()
        })
        .unwrap_or(false)
    }

    fn authorize_timer_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawCpl3TimerReturnFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.authorize_timer_return(frame)
        })
        .unwrap_or(Ok(()))
    }

    unsafe fn prepare_preemption<'owner>(
        &'owner mut self,
    ) -> crate::syscall::native::NativePreemptionPlan<'owner> {
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        // SAFETY: forwards this trait method's `# Safety` to `prepare_preemption_stationary`;
        // the carrier was built for this facade's own CPU.
        unsafe { runtime.prepare_preemption_stationary() }
    }

    fn resume_timer_preemption(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawCpl3TimerReturnFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if !self.synchronize_scheduler_current_at_safe_point_detached() {
            return Ok(());
        }
        let publication = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(publication);
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        runtime.authorize_timer_return(frame)
    }

    fn resume_syscall_preemption(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if !self.synchronize_scheduler_current_at_safe_point_detached() {
            return Ok(());
        }
        let publication = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(publication);
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        let current_binding_generation = crate::arch::x86_64::syscall::current_binding_generation();
        frame.rebind_after_kernel_resume(current_binding_generation)?;
        runtime.authorize_return(frame, current_binding_generation)
    }

    fn complete_remote_stop(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> SyscallControl {
        let pending = self
            .pending_remote_termination
            .take()
            .unwrap_or_else(|| panic!("remote-stop control omitted its CPU-local termination"));
        let ready = match pending {
            PendingRemoteTermination::Process(pending) => {
                let permits =
                    await_remote_stop_permits(pending.deferred, self.runtime.guard_free());
                self.synchronize_scheduler_current_after_remote_stops_detached();
                {
                    let mut guard = self.runtime.lock();
                    let mut runtime = guard.on(&mut self.owned);
                    let result = runtime.complete_process_termination(
                        pending.phase,
                        pending.prepared,
                        permits,
                    );
                    runtime.ready_to_return(result)
                }
            }
            PendingRemoteTermination::TaskGroup(pending) => {
                let permits =
                    await_remote_stop_permits(pending.deferred, self.runtime.guard_free());
                self.synchronize_scheduler_current_after_remote_stops_detached();
                {
                    let mut guard = self.runtime.lock();
                    let mut runtime = guard.on(&mut self.owned);
                    let result = runtime.complete_task_group_termination(
                        pending.phase,
                        pending.prepared,
                        permits,
                    );
                    runtime.ready_to_return(result)
                }
            }
            PendingRemoteTermination::Thread(pending) => {
                let permits =
                    await_remote_stop_permits(pending.deferred, self.runtime.guard_free());
                self.synchronize_scheduler_current_after_remote_stops_detached();
                {
                    let mut guard = self.runtime.lock();
                    let mut runtime = guard.on(&mut self.owned);
                    let result = runtime.complete_thread_termination(
                        pending.phase,
                        pending.prepared,
                        permits,
                    );
                    runtime.ready_to_return(result)
                }
            }
        };
        self.drain_quantum_cancellation_detached();
        let result = ready.into_result();
        frame.set_status(result.status);
        if result.control == SyscallControl::ReturnToCaller
            && let Err(error) = self.authorize_return(frame, current_binding_generation)
        {
            self.invalid_return(error);
            return SyscallControl::TerminateCurrent;
        }
        result.control
    }

    fn authorize_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
        current_binding_generation: u64,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if matches!(
            crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
        ) {
            // The raw trampoline performs an authoritative post-dispatch
            // mailbox poll after dropping usercopy. It will diverge through
            // the rendezvous reaper, so no user-return authorization may be
            // minted from the terminal task state observed here.
            return Ok(());
        }
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.authorize_return(frame, current_binding_generation)
        })
        .unwrap_or(Ok(()))
    }

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) {
        self.terminate_exception_with_remote_stops(crate::task::TaskExceptionRecord::new(
            DW_EXCEPTION_GENERAL_PROTECTION,
            invalid_user_return_detail(error),
            0,
        ));
    }

    fn user_exception(&mut self, record: crate::arch::x86_64::exceptions::UserExceptionRecord) {
        self.terminate_exception_with_remote_stops(record.task_exception());
    }

    fn user_resource_fault(
        &mut self,
        record: crate::arch::x86_64::exceptions::UserExceptionRecord,
    ) {
        self.terminate_exception_with_remote_stops(record.task_exception().resource_policy());
    }

    fn serve_user_page_fault(
        &mut self,
        cr2: u64,
        error: u64,
    ) -> crate::syscall::native::UserPageFaultOutcome {
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.serve_user_page_fault(cr2, error)
        })
        .unwrap_or(crate::syscall::native::UserPageFaultOutcome::Retry)
    }

    fn terminate_current(this: DivergentCarrier<'_, Self>) -> ! {
        let mut carrier = this;
        let this = carrier.get();
        this.drain_quantum_cancellation_detached();
        let mut step = {
            let mut guard = this.runtime.lock();
            let mut runtime = guard.on(&mut this.owned);
            runtime.prepare_terminal_handoff_detached()
        };
        loop {
            step = match step {
                PreparedTerminalStep::SchedulerRoot { prepared, state } => {
                    let executed = match prepared.execute(this.runtime.guard_free()) {
                        Ok(executed) => executed,
                        Err(failure) => {
                            let mut guard = this.runtime.lock();
                            let mut runtime = guard.on_root_switch_flight(&mut this.owned);
                            let error = runtime.cancel_scheduler_root_switch(failure);
                            panic!("terminal scheduler root switch failed before CR3: {error:?}")
                        }
                    };
                    let mut guard = this.runtime.lock();
                    let mut runtime = guard.on_root_switch_flight(&mut this.owned);
                    runtime.commit_scheduler_root_switch(executed);
                    PreparedTerminalStep::Final(runtime.finish_terminal_successor(state))
                }
                PreparedTerminalStep::KernelRoot {
                    prepared,
                    continuation,
                } => {
                    let executed = match prepared.execute(this.runtime.guard_free()) {
                        Ok(executed) => executed,
                        Err(failure) => {
                            let mut guard = this.runtime.lock();
                            let mut runtime = guard.on_root_switch_flight(&mut this.owned);
                            let error = runtime.cancel_terminal_kernel_root_switch(failure);
                            panic!("terminal kernel-root switch failed before CR3: {error:?}")
                        }
                    };
                    let mut guard = this.runtime.lock();
                    let mut runtime = guard.on_root_switch_flight(&mut this.owned);
                    runtime.commit_terminal_kernel_root_switch(executed);
                    runtime.continue_terminal_after_kernel_root(continuation)
                }
                PreparedTerminalStep::PrimordialRoot {
                    prepared,
                    retirement,
                } => {
                    let executed = match prepared.execute(this.runtime.guard_free()) {
                        Ok(executed) => executed,
                        Err(failure) => {
                            let mut guard = this.runtime.lock();
                            let mut runtime = guard.on_root_switch_flight(&mut this.owned);
                            let error = runtime.cancel_terminal_primordial_root_switch(failure);
                            panic!("terminal publisher-root switch failed before CR3: {error:?}")
                        }
                    };
                    let mut guard = this.runtime.lock();
                    let mut runtime = guard.on_root_switch_flight(&mut this.owned);
                    runtime.commit_terminal_primordial_root_switch(executed);
                    runtime.continue_terminal_after_primordial_root(retirement)
                }
                PreparedTerminalStep::Final(handoff) => match handoff {
                    // SAFETY: [P-HANDOFF] `prepare_terminal_handoff` bound the next Thread's stack
                    // and returned its continuation (or built a fresh one there); this reaper frame
                    // is abandoned.
                    PreparedTerminalHandoff::Continuation(continuation) => unsafe {
                        crate::arch::x86_64::context::abandon_to_kernel_continuation(
                            continuation,
                            carrier.release(),
                        )
                    },
                    PreparedTerminalHandoff::IdleScheduler => {
                        crate::arch::x86_64::syscall::enter_bound_idle_scheduler(carrier.release())
                    }
                    #[cfg(not(feature = "test-support"))]
                    PreparedTerminalHandoff::PowerOff => {
                        crate::arch::x86_64::power::soft_off_then_halt(this.runtime.guard_free())
                    }
                },
            };
        }
    }

    fn enter_scheduled_fresh_thread(this: DivergentCarrier<'_, Self>) -> ! {
        let mut carrier = this;
        let this = carrier.get();
        if !this.synchronize_scheduler_current_at_safe_point_detached() {
            crate::arch::x86_64::syscall::handoff_current_rendezvous_from_carrier(carrier.release())
        }
        let publication = {
            let mut guard = this.runtime.lock();
            let mut runtime = guard.on(&mut this.owned);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(publication);
        let (state, stack) = {
            let mut guard = this.runtime.lock();
            let mut runtime = guard.on(&mut this.owned);
            runtime.prepare_fresh_user_entry_synchronized()
        };
        // The first-run switch bound `stack` before this frame existed; check that binding.
        let bound = crate::arch::x86_64::syscall::current_bound_kernel_stack(stack);
        // SAFETY: [P-HANDOFF] `state` was validated against the current Process and `bound`
        // proves the first-run switch's binding, which the callee rechecks. See its same-stack
        // note at `iret_validated_user`.
        unsafe {
            crate::arch::x86_64::syscall::enter_bound_validated_user(
                &state,
                bound,
                carrier.release(),
            )
        }
    }

    fn publish_scheduler_idle(
        &mut self,
        started_at_ns: u64,
    ) -> Result<crate::task::SchedulerIdleAccountingToken, crate::task::SchedulerError> {
        let runtime = self.runtime.lock();
        runtime
            .core
            .shared
            .execution
            .publish_idle_on(self.cpu, started_at_ns)
    }

    fn finish_scheduler_idle(
        &mut self,
        token: crate::task::SchedulerIdleAccountingToken,
        finished_at_ns: u64,
    ) -> Result<(), crate::task::SchedulerError> {
        let runtime = self.runtime.lock();
        runtime
            .core
            .shared
            .execution
            .finish_idle_on(token, finished_at_ns)
    }

    fn enter_idle_scheduler(this: DivergentCarrier<'_, Self>) -> ! {
        let mut carrier = this;
        let this = carrier.get();
        crate::debug::liveness::note_event(
            this.cpu,
            crate::debug::liveness::LivenessEvent::IdleEntered,
        );
        if !this.admission_entered {
            let (ticket, resources) = this
                .admission
                .unwrap_or_else(|| panic!("AP carrier omitted scheduler admission identity"));
            let executing = this.enter_ap_kernel_root_detached();
            if ticket.cpu() != this.cpu
                || crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
                    != Some(this.cpu.index())
                || crate::arch::x86_64::runtime_cpu_descriptor_lifecycle(this.cpu.index())
                    != Some(crate::arch::x86_64::RuntimeCpuDescriptorLifecycle::Online)
                || crate::arch::x86_64::syscall::native_runtime_carrier_lifecycle(this.cpu)
                    != Some(crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing)
                || !crate::arch::x86_64::ipi::live_ipi_transport_is_bound()
                || !crate::arch::x86_64::ipi::live_rendezvous_handler_is_bound()
                || !user_access::live_tlb_shootdown_is_ready()
                || crate::arch::x86_64::idle::live_idle_wake_is_enabled(this.cpu)
                || !crate::time::ap_scheduler_timer_is_masked(this.cpu)
            {
                fail_live_carrier_admission(
                    this.shared,
                    this.cpu,
                    "AP carrier admission revalidation failed",
                );
            }
            let snapshot = crate::arch::x86_64::smp::live_cpu_registry()
                .snapshot(this.cpu.index())
                .unwrap_or_else(|_| {
                    fail_live_carrier_admission(
                        this.shared,
                        this.cpu,
                        "AP registry revalidation failed",
                    )
                });
            if snapshot.lifecycle != crate::arch::x86_64::smp::CpuLifecycle::Executing
                || snapshot.local_apic_id != resources.local_apic_id
                || snapshot.online_generation != resources.online_generation
            {
                fail_live_carrier_admission(this.shared, this.cpu, "AP execution identity drifted");
            }
            let observed_resources = {
                let mut runtime = this.runtime.lock();
                let (state, mut paging) = runtime.split_paging();
                carrier_resource_tuple(
                    &state.core,
                    &paging.lock(),
                    this.cpu,
                    crate::arch::x86_64::smp::CpuLifecycle::Executing,
                    crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing,
                    false,
                )
            };
            if observed_resources != resources {
                fail_live_carrier_admission(
                    this.shared,
                    this.cpu,
                    "AP private carrier resources drifted",
                );
            }
            crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(|_| {
                fail_live_carrier_admission(
                    this.shared,
                    this.cpu,
                    "AP syscall boundary validation failed",
                )
            });
            this.shared
                .execution
                .publish_ap_carrier_ready(ticket, resources, executing)
                .unwrap_or_else(|error| {
                    this.shared.execution.fail_carrier_admission(this.cpu);
                    panic!(
                        "AP {} readiness publication failed: {error:?}",
                        this.cpu.index()
                    )
                });
            while !this.shared.execution.carrier_ticket_is_schedulable(ticket) {
                let observed = this.shared.execution.carrier_admission_snapshot(this.cpu);
                if observed.lifecycle == crate::task::CarrierAdmissionLifecycle::Failed {
                    panic!("AP {} admission failed", this.cpu.index());
                }
                core::hint::spin_loop();
            }
            this.admission_entered = true;
        }
        loop {
            enum Entry {
                Fresh {
                    state: crate::arch::x86_64::syscall::ValidatedUserReturn,
                    stack: crate::memory::kernel_stack::KernelStackBounds,
                },
                Continuation {
                    stack: crate::memory::kernel_stack::KernelStackBounds,
                    rsp: u64,
                },
            }

            let scheduled = {
                let mut guard = this.runtime.lock();
                let mut runtime = guard.on(&mut this.owned);
                // A Timer owned by a Thread running on an AP still expires on
                // the BSP's unified timer service.  CPU0 may have no current
                // Thread and remain in this kernel-root idle loop while that
                // AP continues creating timers, so the ordinary syscall and
                // suspended-Thread safe points are not sufficient consumers.
                // Drain before choosing the next runnable Thread; the
                // existing post-lock notification drain publishes any remote
                // wake without extending the shared authority critical path.
                if this.cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                    runtime.service_pending_timer_expiries_on_bootstrap();
                }
                runtime
                    .core
                    .shared
                    .execution
                    .schedule_next_on(this.cpu)
                    .unwrap_or_else(|error| panic!("AP scheduling failed: {error:?}"))
                    .current
            };
            crate::task::drain_runnable_work_notifications();
            // A `match`, not `Option::map`: the rendezvous handoff below diverges, and it must do
            // so in this entry's own frame, not inside a closure holding the carrier ([DIVERGENT]).
            let entry = match scheduled {
                None => None,
                Some(thread) => Some({
                    if !this.synchronize_scheduler_current_at_safe_point_detached() {
                        crate::arch::x86_64::syscall::handoff_current_rendezvous_from_carrier(
                            carrier.release(),
                        )
                    }
                    let mut guard = this.runtime.lock();
                    let mut runtime = guard.on(&mut this.owned);
                    let continuation = runtime
                        .core
                        .shared
                        .execution
                        .kernel_continuation_rsp(runtime.own.scheduled().context_id)
                        .unwrap_or_else(|error| {
                            panic!("AP continuation lookup failed for {thread:?}: {error:?}")
                        });
                    if continuation == 0 {
                        let (state, stack) = runtime.prepare_fresh_user_entry_synchronized();
                        Entry::Fresh { state, stack }
                    } else {
                        let stack = runtime
                            .core
                            .shared
                            .execution
                            .stack_bounds(runtime.own.scheduled().stack_id)
                            .unwrap_or_else(|error| panic!("AP stack lookup failed: {error:?}"));
                        Entry::Continuation {
                            stack,
                            rsp: continuation,
                        }
                    }
                }),
            };
            match entry {
                Some(Entry::Fresh { state, stack }) => {
                    // SAFETY: [P-HANDOFF] this idle loop runs on a CPU-private stack with IF clear;
                    // `stack` is the scheduled Thread's, entered below.
                    let bound =
                        unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                            .unwrap_or_else(|error| {
                                panic!("AP fresh stack binding failed: {error:?}")
                            });
                    // SAFETY: [P-HANDOFF] `state` was validated for the scheduled Thread's Process
                    // and `bound` proves the binding just above; the callee rechecks both.
                    unsafe {
                        crate::arch::x86_64::syscall::enter_bound_validated_user(
                            &state,
                            bound,
                            carrier.release(),
                        )
                    }
                }
                Some(Entry::Continuation { stack, rsp }) => {
                    // SAFETY: [P-HANDOFF] this idle loop runs on a CPU-private stack with IF clear;
                    // `stack` is the scheduled Thread's, resumed below.
                    unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                        .unwrap_or_else(|error| {
                            panic!("AP continuation stack binding failed: {error:?}")
                        });
                    crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(
                        |error| panic!("AP continuation syscall boundary failed: {error:?}"),
                    );
                    // SAFETY: [P-HANDOFF] `rsp` is the scheduled Thread's saved continuation and
                    // its stack is bound above; this idle frame is abandoned.
                    unsafe {
                        crate::arch::x86_64::context::abandon_to_kernel_continuation(
                            rsp,
                            carrier.release(),
                        )
                    }
                }
                None => {
                    let idle = crate::arch::x86_64::idle::prepare_current_idle()
                        .unwrap_or_else(|error| panic!("AP idle publication failed: {error:?}"));
                    let notification = match crate::arch::x86_64::idle::commit_current_idle(idle) {
                        Ok(halt) => {
                            let started_at_ns =
                                crate::time::monotonic_now().unwrap_or_else(|error| {
                                    panic!("AP idle start sample failed: {error:?}")
                                });
                            let idle_accounting = this
                                .publish_scheduler_idle(started_at_ns)
                                .unwrap_or_else(|error| {
                                    panic!("AP idle accounting publication failed: {error:?}")
                                });
                            halt_for_interrupt(this.runtime.guard_free());
                            crate::arch::x86_64::idle::finish_current_idle(halt).unwrap_or_else(
                                |error| panic!("AP idle completion failed: {error:?}"),
                            );
                            let finished_at_ns =
                                crate::time::monotonic_now().unwrap_or_else(|error| {
                                    panic!("AP idle finish sample failed: {error:?}")
                                });
                            this.finish_scheduler_idle(idle_accounting, finished_at_ns)
                                .unwrap_or_else(|error| {
                                    panic!("AP idle accounting completion failed: {error:?}")
                                });
                            crate::time::service_current_rendezvous_latch().unwrap_or_else(
                                |error| panic!("AP idle rendezvous service failed: {error:?}"),
                            )
                        }
                        Err(failure)
                            if failure.error()
                                == crate::arch::x86_64::idle::IdleWakeError::RescanRequired =>
                        {
                            crate::arch::x86_64::idle::cancel_current_idle(
                                failure.into_preparation(),
                            )
                            .unwrap_or_else(|error| {
                                panic!("AP idle rescan cancellation failed: {error:?}")
                            });
                            crate::time::service_current_rendezvous_latch().unwrap_or_else(
                                |error| panic!("AP idle rescan service failed: {error:?}"),
                            )
                        }
                        Err(failure) => {
                            panic!("AP idle commit failed: {:?}", failure.error())
                        }
                    };
                    match notification {
                        crate::arch::x86_64::rendezvous::MailboxNotification::None
                        | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {}
                        crate::arch::x86_64::rendezvous::MailboxNotification::Wake => {}
                        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_) => {
                            panic!("kernel-root idle carrier received an unexpected stop request")
                        }
                    }
                    #[cfg(deepwyrm_dw1e_platform)]
                    this.service_q35_retirement_at_bsp_safe_point();
                }
            }
        }
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan<'owner> {
        let plan = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            // SAFETY: forwards this trait method's `# Safety` to `prepare_suspend_stationary`;
            // the carrier was built for this facade's own CPU.
            unsafe { runtime.prepare_suspend_stationary() }
        };
        self.drain_quantum_cancellation_detached();
        plan
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'owner> {
        let poll = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            if self.cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
                #[cfg(deepwyrm_dw1e_platform)]
                runtime
                    .service_q35_retirement_at_bsp_safe_point()
                    .unwrap_or_else(|_| panic!("DW1-E2C deferred finalizer safe-point drifted"));
            }
            // SAFETY: forwards this trait method's `# Safety` to `poll_idle_suspend_stationary`;
            // the carrier was built for this facade's own CPU.
            unsafe { runtime.poll_idle_suspend_stationary() }
        };
        crate::task::drain_runnable_work_notifications();
        poll
    }

    fn resume_suspended(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeResumeOutcome {
        // A suspended continuation may resume after other CPUs held the
        // runtime authority; this CPU's own slot still holds its root token.
        // An already-published local terminal owner must retain its suspended
        // claim until the terminal reaper actually abandons this stack; every
        // resumable path acknowledges destination-stack arrival first.
        let terminal_current = {
            let mut guard = self.runtime.lock();
            let runtime = guard.on(&mut self.owned);
            let suspended_claim = runtime.core.shared.execution.suspended_claim_on(self.cpu);
            let terminal = match (suspended_claim, runtime.own.deferred_current.as_ref()) {
                (Some(suspended), Some(deferred)) => {
                    assert_eq!(
                        suspended.thread(),
                        runtime.own.scheduled().thread,
                        "terminal resume retained another physical scheduler claim"
                    );
                    assert_eq!(
                        suspended.thread(),
                        deferred.thread(),
                        "terminal resume deferred a different physical Thread"
                    );
                    true
                }
                _ => false,
            };
            if terminal {
                // The terminal reaper owns this continuation now; its idle
                // resume ends here, as it always did, short of a handoff.
                runtime.own.wait_control.finish_idle_resume();
            }
            terminal
        };
        if terminal_current {
            return crate::syscall::native::NativeResumeOutcome::TerminateCurrent;
        }
        if !self.synchronize_scheduler_current_at_safe_point_detached() {
            return crate::syscall::native::NativeResumeOutcome::ServiceRendezvous;
        }
        let publication = {
            let mut guard = self.runtime.lock();
            let mut runtime = guard.on(&mut self.owned);
            let publication = runtime.complete_physical_switch_handoff();
            // The continuation gave up its suspended claim at this handoff, so
            // its idle resume ends here: until now a remote stop could still
            // find it suspended, and its precommit retires a resuming control
            // exactly as an idle one.
            runtime.own.wait_control.finish_idle_resume();
            publication
        };
        crate::task::notify_completed_switch_runnable(publication);
        let mut guard = self.runtime.lock();
        let mut runtime = guard.on(&mut self.owned);
        let notification = crate::arch::x86_64::idle::take_current_notification_at_safe_point();
        if matches!(
            notification,
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
        ) {
            return crate::syscall::native::NativeResumeOutcome::ServiceRendezvous;
        }
        #[cfg(feature = "test-support")]
        let suspended_claim = runtime.core.shared.execution.suspended_claim_on(self.cpu);
        #[cfg(feature = "test-support")]
        if runtime
            .core
            .shared
            .execution
            .current_thread_on(self.cpu)
            .is_none()
        {
            let suspended = suspended_claim.is_some();
            match (notification, suspended) {
                (crate::arch::x86_64::rendezvous::MailboxNotification::None, false) => {
                    panic!("resume lost current without a mailbox notification or suspension")
                }
                (crate::arch::x86_64::rendezvous::MailboxNotification::None, true) => {
                    if runtime.own.wait_control.is_clear() {
                        match suspended_claim.and_then(|claim| {
                            runtime
                                .core
                                .shared
                                .execution
                                .scheduler_state(claim.thread())
                                .map(|state| (claim, state))
                        }) {
                            None if runtime.own.stopping_claim.is_some() => {
                                panic!("resume crossed an in-progress remote-stop carrier")
                            }
                            None if runtime.own.deferred_current.is_some() => {
                                panic!("resume crossed another local terminal carrier on this CPU")
                            }
                            None if suspended_claim.is_some_and(|claim| {
                                runtime
                                    .owned
                                    .physically_executing
                                    .physically_executes(claim.thread())
                            }) =>
                            {
                                panic!("resume physically executes its terminally retired carrier")
                            }
                            None => panic!("resume reached another terminally retired carrier"),
                            Some((_, crate::task::SchedulerThreadState::Blocked)) => {
                                panic!("resume reached a still-blocked switched carrier")
                            }
                            Some((_, crate::task::SchedulerThreadState::Runnable)) => {
                                panic!("resume reached an unclaimed runnable switched carrier")
                            }
                            Some((_, crate::task::SchedulerThreadState::Running)) => {
                                panic!("resume reached a suspension whose Thread runs elsewhere")
                            }
                            Some((_, crate::task::SchedulerThreadState::Reserved)) => {
                                panic!("resume reached a reserved switched carrier")
                            }
                        }
                    }
                    panic!("resume lost current while an idle suspension remained owned")
                }
                (crate::arch::x86_64::rendezvous::MailboxNotification::Wake, false) => {
                    panic!("resume lost current after consuming a wake")
                }
                (crate::arch::x86_64::rendezvous::MailboxNotification::Wake, true) => {
                    panic!("resume lost current after wake with a suspension still owned")
                }
                (crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_), false) => {
                    panic!("resume lost current behind a completed remote stop")
                }
                (crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_), true) => {
                    panic!("resume lost current behind remote stop with a suspension still owned")
                }
                (crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_), _) => {
                    unreachable!()
                }
            }
        }
        let settlement = runtime.resume_suspended(frame);
        drop(runtime);
        drop(guard);
        self.apply_resume_settlement(settlement);
        crate::syscall::native::NativeResumeOutcome::Resumed
    }
}

/// `AddressRegionMap`'s copy-in and output pin, in the adapter's order:
/// the arguments, their protection, then the output (D1 commit 9).
fn map_input<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    user: &mut user_access::LiveProcessAddressSpace<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>,
    args_address: deepwyrm_abi::DwUserAddress,
    args_size: u64,
    out_address: deepwyrm_abi::DwUserAddress,
) -> MapInput {
    let args = crate::syscall::decode_map_args(user, args_address, args_size)?;
    let protection = match MemoryProtection::mapping(args.protections.0 as u8) {
        Ok(protection) => protection,
        Err(crate::memory::object::MemoryObjectError::UnsupportedProtection) => {
            return Err(deepwyrm_abi::DW_STATUS_NOT_SUPPORTED);
        }
        Err(_) => return Err(deepwyrm_abi::DW_STATUS_INVALID_ARGUMENT),
    };
    let output_range = UserRange::new(
        UserAddressSpace::x86_64_four_level(PAGE_SIZE)
            .unwrap_or_else(|_| panic!("x86_64 userspace model unavailable")),
        out_address.0,
        8,
        8,
        UserAccess::WRITE,
        EmptyAddressRule::Reject,
    )
    .map_err(|_| deepwyrm_abi::DW_STATUS_BAD_ADDRESS)?;
    let output = user
        .preflight_owned_output(output_range)
        .map_err(|_| deepwyrm_abi::DW_STATUS_BAD_ADDRESS)?;
    Ok((args, protection, output))
}

const fn invalid_user_return_detail(error: crate::arch::x86_64::syscall::UserReturnError) -> u32 {
    use crate::arch::x86_64::syscall::UserReturnError;
    match error {
        UserReturnError::NonCanonicalUserAddress => 1,
        UserReturnError::InvalidSelector => 7,
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
    let start = storage.0.get().cast::<u8>();
    // SAFETY: exclusive: `enter` is the one-shot BSP path, calls this once per static and publishes
    // no reference to either buffer first. `byte_len <= BYTES` (checked above), and the prefix is
    // initialized through the raw pointer before any reference to it exists, so the slice covers
    // only initialized bytes of this `MaybeUninit` storage.
    let destination = unsafe {
        start.write_bytes(0, byte_len);
        core::slice::from_raw_parts_mut(start, byte_len)
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
pub(super) fn enter(
    mut active: super::PrimordialActivePaging,
    modules: crate::boot::primordial::PrimordialBootModules,
    boot_resource_grants: crate::boot::BootResourceGrants,
) -> ! {
    // The runtime is built over the one concrete, `'static` paging target, so its permanent
    // storage can be a static (S2K-4).
    const RANGE_CAPACITY: usize = crate::BOOTSTRAP_FRAME_RANGE_CAPACITY;
    const ROLE_CAPACITY: usize = crate::BOOTSTRAP_FRAME_ROLE_CAPACITY;
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
    // SAFETY: this is the only production `AddressSpaceAuthority`, so every root is registered
    // through it; it moves into the carrier, which lives in this never-returning frame.
    let mut spaces = unsafe { Spaces::new() };
    let mut regions = Regions::new();
    let shared = publish_runtime_shared(boot_resource_grants);
    let (_root_group, root_owner) = tasks
        .create_root_group(&mut registry)
        .unwrap_or_else(|error| panic!("could not create primordial root TaskGroup: {error:?}"));

    let resource_domain = if shared.boot_resource_grants.has_grants() {
        let (key, handle) = tasks
            .create_child_group(&mut registry, &root_owner)
            .unwrap_or_else(|error| {
                panic!("could not create boot resource-domain TaskGroup: {error:?}")
            });
        let owner = registry
            .retain_internal_from_handle(&handle)
            .unwrap_or_else(|error| {
                panic!("could not retain resource-domain ownership: {error:?}")
            });
        shared
            .boot_resource_grants
            .bind_owner(key, owner)
            .unwrap_or_else(|(error, _)| {
                panic!("could not bind boot resource-domain owner: {error:?}")
            });
        Some(handle)
    } else {
        None
    };

    let monitor = {
        let mut platform = LivePlatform {
            active: &mut active,
        };
        let mut backend = match resource_domain {
            Some(resource_domain) => AuthorityPrimordialBackend::new_with_resource_domain(
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
                resource_domain,
            ),
            None => AuthorityPrimordialBackend::new(
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
            ),
        };
        crate::boot::primordial::construction::construct_primordial_with_profile(
            &plan,
            bootstrap,
            bootfs,
            if shared.boot_resource_grants.has_grants() {
                crate::boot::primordial::construction::PrimordialInitProfile::ResourceDomain
            } else {
                crate::boot::primordial::construction::PrimordialInitProfile::Historical
            },
            &mut backend,
            |_| false,
        )
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
    // Every CPU's remotely read slot, and each slot's one owner, minted here once (S2K-6). Each
    // owner moves into its CPU's owner-local state, which its facade keeps.
    let mut cpus = CpuSlots::new(core::array::from_fn(|_| CpuSharedState::new()));
    let mut owned: [Option<CpuOwnedState>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] = cpus
        .mint_owners()
        .map(|owner| Some(CpuOwnedState::new(owner)));
    let mut bsp_owned = owned[crate::cpu::CpuIndex::BOOTSTRAP.index()]
        .take()
        .unwrap_or_else(|| panic!("no owner-local state for the BSP"));
    // The paging authority's lock, P, lives in its own permanent storage beside the runtime
    // authority's, outside the value T guards, and is reached only beneath a T guard (D1 commit 3).
    let paging: &'static PagingLock<RuntimePaging<'static, RANGE_CAPACITY, ROLE_CAPACITY>> =
        PRIMORDIAL_PAGING.init(PagingLock::new(
            active,
            user_access::service_local_tlb_shootdown,
        ));
    // Permanent storage (S2K-4, reset R2D): the lock and the carrier it guards live in one-shot
    // static storage for the kernel's lifetime, not on the boot stack. Built in place there (S2K
    // stage 4), so no whole-carrier temporary is materialized in this frame first.
    let runtime_ref: &'static RuntimeAuthorityLock<
        PrimordialRuntimeState<'static, RANGE_CAPACITY, ROLE_CAPACITY>,
    > = {
        // SAFETY: the storage's one pointer is valid for writes of the whole lock, whose own
        // fields `RuntimeAuthorityLock::init_in_place` writes; the two `init_fields!` write every
        // field of the state and of its core from exhaustive field lists, and nothing is read
        // before the storage is assumed initialized.
        unsafe {
            PRIMORDIAL_RUNTIME_AUTHORITY.init_in_place(|lock| {
                RuntimeAuthorityLock::init_in_place(
                    lock,
                    user_access::service_local_tlb_shootdown,
                    |state| {
                        init_fields!(
                            core::ptr::addr_of_mut!((*state).core),
                            PrimordialRuntimeCore {
                                paging: paging,
                                rendezvous_reaper: None,
                                registry: registry,
                                memory: memory,
                                tasks: tasks,
                                shared: shared,
                                services: (FServiceState::new()),
                                spaces: spaces,
                                regions: regions,
                                primordial_process: process,
                                primordial_root_key: root_key,
                                primordial_address_space: primordial_address_space,
                                channel_keys: channel_keys,
                                kernel_peer: (Some(kernel_peer)),
                                process_monitor: (Some(process_monitor)),
                                root_owner: (Some(root_owner)),
                                cleanup: (CleanupQueue::new()),
                                rendezvous_cleanup: (StagedStopCleanup::new()),
                            }
                        );
                        init_fields!(
                            state,
                            PrimordialRuntimeState {
                                core: in_place,
                                cpus: cpus,
                            }
                        );
                    },
                );
            })
        }
    };

    // Reset card R1B: record the live authority's ticket pair once so host GDB
    // over the QEMU gdbstub can read it without executing guest code. Since
    // S2K-4 (card R2D) the lock is a static, so this address is fixed for the
    // kernel's lifetime.
    //
    // The *ticket pair's* address, not the lock's. `RuntimeAuthorityLock` is
    // `repr(Rust)` and the compiler puts `value` first, so card R1's run 10 read
    // the sixteen bytes at the lock's base and got the leading bytes of the
    // carrier while labelling them a ticket pair. They were self-evidently wrong
    // -- a ticket lock cannot serve more tickets than it has issued -- but a
    // plausible-looking pair would have been reported as contention that was
    // never there. The pair is its own `repr(C)` struct, asserted adjacent by
    // `runtime_authority.rs`, so one read still covers both words.
    crate::debug::liveness::publish_runtime_authority(runtime_ref.ticket_pair_address());
    // One handle per CPU slot, minted once. Handle 0 serves this BSP path
    // until it moves into facade 0.
    let mut handles = runtime_ref
        .handles::<{ crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT }>()
        .into_iter();
    let mut bsp_handle = handles
        .next()
        .unwrap_or_else(|| panic!("no runtime authority handle for the BSP"));
    let (state, stack, exception_binding) = {
        let mut guard = bsp_handle.lock();
        let mut runtime = guard.on(&mut bsp_owned);
        // The BSP starts on the primordial Thread, under its Process root.
        runtime.own.active_root = CarrierActiveRoot::Process(initial_root);
        runtime.publish_last_scheduled(ScheduledIdentity {
            process,
            thread,
            stack_id,
            context_id,
            root_key,
        });
        runtime
            .owned
            .physically_executing
            .record_current(thread, stack_id, context_id);
        let exception_binding =
            crate::arch::x86_64::syscall::bind_native_runtime_user_exception_handler()
                .unwrap_or_else(|error| panic!("could not bind primordial exceptions: {error:?}"));
        let context = runtime
            .core
            .shared
            .execution
            .load_context(context_id)
            .unwrap_or_else(|error| panic!("could not load primordial context: {error:?}"));
        let stack = runtime
            .core
            .shared
            .execution
            .stack_bounds(stack_id)
            .unwrap_or_else(|error| panic!("could not load primordial kernel stack: {error:?}"));
        let state = {
            let mut paging = runtime.paging.lock();
            let mut mappings = paging.return_validation_session(
                runtime.own.active_root.as_ref().expect("active root"),
                process,
            );
            crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
                .unwrap_or_else(|error| panic!("invalid primordial initial return: {error:?}"))
        };
        (state, stack, exception_binding)
    };
    owned[crate::cpu::CpuIndex::BOOTSTRAP.index()] = Some(bsp_owned);
    let mut bsp_handle = Some(bsp_handle);
    let facades: [_; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
        core::array::from_fn(|cpu_index| RuntimeCarrierFacade {
            cpu: crate::cpu::CpuIndex::new(cpu_index)
                .unwrap_or_else(|| panic!("native carrier CPU {cpu_index} is out of range")),
            runtime: if cpu_index == 0 {
                bsp_handle.take()
            } else {
                handles.next()
            }
            .unwrap_or_else(|| panic!("no runtime authority handle for CPU {cpu_index}")),
            shared,
            paging,
            owned: owned[cpu_index]
                .take()
                .unwrap_or_else(|| panic!("no owner-local state for CPU {cpu_index}")),
            admission: None,
            admission_entered: false,
            pending_remote_termination: None,
        });
    // Permanent storage (S2K-4, reset R2D): the facade array lives in one-shot static storage for
    // the kernel's lifetime. [P-FACADE] Its one owner's reference is converted, here and once,
    // into the base pointer every later facade access derives from, and is never used again.
    let facades = core::ptr::NonNull::from(PRIMORDIAL_FACADES.init(facades))
        .cast::<RuntimeCarrierFacade<'static, 'static, RANGE_CAPACITY, ROLE_CAPACITY>>();
    // Each CPU's quantum-expiry publisher reaches only the stationary shared authorities.
    let publishers: [_; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
        core::array::from_fn(|_| QuantumExpiryPublisher { shared });
    // [P-FACADE] as for the facades: the publisher array's one owner's reference is converted
    // here, once, into the base pointer every later access derives from.
    let publishers = core::ptr::NonNull::from(PRIMORDIAL_QUANTUM_EXPIRY.init(publishers))
        .cast::<QuantumExpiryPublisher>();
    let live_cpu_count = bind_runtime_carrier_facades(facades, publishers);
    user_access::initialize_live_tlb_shootdown();
    prepare_runtime_carrier_admission(facades, live_cpu_count);
    normalize_bootstrap_carrier(facades);
    let admissions = core::array::from_fn(|cpu_index| {
        // SAFETY: [P-FACADE] field reads through element pointers of the facade array; every AP is
        // still parked and CPU0 is this CPU.
        unsafe { (*facades.add(cpu_index).as_ptr()).admission }
    });
    // SAFETY: [P-FACADE] facade 0's handle, borrowed for this call only; the released APs use only
    // their own facades.
    release_runtime_carrier_facades(
        shared,
        unsafe { &mut (*facades.as_ptr()).runtime },
        admissions,
    );
    // SAFETY: `state` was validated against the primordial mappings and `stack` is the primordial
    // Thread's own kernel stack; `facades` is facade 0's element pointer into its permanent storage,
    // the one CPU0 was published with ([P-FACADE]). That is the callee's `# Safety`.
    unsafe {
        crate::arch::x86_64::syscall::enter_published_native_syscall_runtime(
            facades,
            &state,
            stack,
            &exception_binding,
        )
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// Handles one ordinary syscall under the runtime guard. A result that
    /// returns to the caller is `ReturnReady` only with the proof that the
    /// final releases were published first (TSV row 76).
    fn handle(&mut self, request: NativeSyscallRequest) -> crate::syscall::native::ReturnReady {
        if self
            .core
            .shared
            .execution
            .scheduler_state(self.own.scheduled().thread)
            != Some(SchedulerThreadState::Running)
        {
            panic!("primordial syscall arrived without its running Thread");
        }
        // This identity is deliberately detached from the carrier before any
        // usercopy or service dispatch.  The final check keeps a resumed
        // adapter from committing under a migrated Thread/root selection.
        let phase = self.reserve_runtime_phase();
        let result = match request {
            NativeSyscallRequest::ProcessCreate { .. } => {
                unreachable!("ProcessCreate is served by the CPU-local facade (D1 commit 7c)")
            }
            NativeSyscallRequest::WaitOne { .. } | NativeSyscallRequest::WaitMany { .. } => {
                unreachable!(
                    "WaitOne and WaitMany are served by the CPU-local facade (D1 commit 8)"
                )
            }
            NativeSyscallRequest::AtomicWait32 { .. } => {
                unreachable!("AtomicWait32 is served by the CPU-local facade (D1 commit 8b)")
            }
            request => {
                let dispatch = {
                    let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
                    let mut timer_deadlines = crate::time::LiveTimerDeadlineAuthority;
                    let root_generation = self
                        .own
                        .active_root
                        .as_ref()
                        .expect("active root")
                        .binding_generation();
                    let prepared = self
                        .core
                        .services
                        .prepare_dispatch(request, self.own.scheduled().thread, root_generation)
                        .unwrap_or_else(|_| {
                            panic!("F-service prepare has an invalid root identity")
                        });
                    // Every copying F request is served by a facade helper
                    // first (D1 commit 9); the arms left here touch no user
                    // memory, so the dispatch gets no session.
                    let mut user = crate::syscall::UnreachableUserAccess::new();
                    let scheduled = self.own.scheduled();
                    self.core.services.dispatch_prepared(
                        &mut self.own.wait_control,
                        prepared,
                        &mut user,
                        &mut self.core.registry,
                        &mut self.core.tasks,
                        &self.core.shared.execution,
                        &self.core.shared.channels,
                        &self.core.shared.events,
                        &self.core.shared.timers,
                        Some(&self.core.shared.interrupts),
                        &self.core.shared.waits,
                        &mut self.core.regions,
                        &mut self.core.spaces,
                        scheduled.process,
                        scheduled.thread,
                        self.owned.owner.cpu(),
                        root_generation,
                        Some(&mut wait_deadlines),
                        &mut timer_deadlines,
                        &mut self.owned.channel_staging[..],
                        || {
                            crate::time::monotonic_now()
                                .map_err(|_| deepwyrm_abi::DW_STATUS_BAD_STATE)
                        },
                    )
                };
                let route = dispatch.into_route();
                self.absorb_service_cleanup();
                match route {
                    FServiceRoute::Handled(result) => result,
                    FServiceRoute::Fallthrough(request) => self.handle_fallthrough(request),
                }
            }
        };
        self.commit_runtime_phase(phase);
        self.ready_to_return(result)
    }

    /// The guarded half of a family-B syscall (D1 commit 6). This is the same
    /// adapter call as the ordinary dispatch, with the deferred output as its
    /// user access. The F-service creators queue their releases directly on
    /// the carrier's cleanup queue. The ordinary route reached the same queue
    /// through `absorb_service_cleanup`.
    fn run_deferred_output(
        &mut self,
        request: NativeSyscallRequest,
        user: &mut crate::memory::usercopy::DeferredUserOutput,
    ) -> deepwyrm_abi::DwStatus {
        let process = self.own.scheduled().process;
        match request {
            NativeSyscallRequest::HandleDuplicate {
                handle,
                requested_rights,
                out_handle,
            } => crate::syscall::handle_duplicate(
                user,
                &mut self.core.registry,
                &mut self.core.tasks,
                process,
                handle,
                requested_rights,
                out_handle,
            ),
            NativeSyscallRequest::TaskGroupCreate {
                parent,
                requested_rights,
                out_handle,
            } => crate::syscall::task_group_create(
                user,
                &mut self.core.registry,
                &mut self.core.tasks,
                process,
                parent,
                requested_rights,
                out_handle,
                &mut self.core.cleanup,
            ),
            NativeSyscallRequest::ThreadCreate {
                process: target,
                requested_rights,
                out_thread,
            } => crate::syscall::thread_create(
                user,
                &mut self.core.registry,
                &mut self.core.tasks,
                process,
                target,
                requested_rights,
                out_thread,
                &mut self.core.cleanup,
            ),
            NativeSyscallRequest::DeviceResourceClaim {
                resource_domain,
                resource_id,
                requested_rights,
                out_resource,
            } => crate::syscall::device_resource_claim(
                user,
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.boot_resource_grants,
                &self.core.shared.device_resources,
                process,
                resource_domain,
                resource_id,
                requested_rights,
                out_resource,
            ),
            NativeSyscallRequest::DevicePioRead {
                resource,
                offset,
                width,
                out_value,
            } => {
                let mut io = crate::arch::x86_64::io_port::X86PortIo;
                crate::syscall::device_pio_read(
                    user,
                    &mut self.core.registry,
                    &mut self.core.tasks,
                    &self.core.shared.device_resources,
                    &mut io,
                    process,
                    resource,
                    offset,
                    width,
                    out_value,
                )
            }
            NativeSyscallRequest::DeviceMmioObjectCreate {
                resource,
                bar,
                requested_rights,
                out_memory_object,
            } => crate::syscall::device_mmio_object_create(
                user,
                &mut self.core.registry,
                &mut self.core.memory,
                &mut self.core.tasks,
                &self.core.shared.device_resources,
                &mut crate::device::dma::live::LiveDmaService,
                process,
                resource,
                bar,
                requested_rights,
                out_memory_object,
                &mut self.core.cleanup,
            ),
            NativeSyscallRequest::DmaMap {
                resource,
                memory_object,
                offset,
                byte_len,
                access,
                out_iova,
            } => {
                // P is taken beneath T and before the DMA lock, which never
                // takes P; the role manager resolves each page of the range.
                let paging = self.paging.lock();
                crate::syscall::dma_map(
                    user,
                    &mut self.core.registry,
                    &self.core.memory,
                    &mut self.core.tasks,
                    &self.core.shared.device_resources,
                    &mut crate::device::dma::live::LiveDmaService,
                    &*paging.target.roles,
                    process,
                    resource,
                    memory_object,
                    offset,
                    byte_len,
                    access,
                    out_iova,
                    &mut self.core.cleanup,
                )
            }
            NativeSyscallRequest::DevicePciConfigRead {
                resource,
                offset,
                width,
                out_value,
            } => {
                let mut ports = crate::arch::x86_64::io_port::X86PortIo;
                let mut config = crate::arch::x86_64::pci_config::Mechanism1::new(&mut ports);
                crate::syscall::device_pci_config_read(
                    user,
                    &mut self.core.registry,
                    &mut self.core.tasks,
                    &self.core.shared.device_resources,
                    &mut config,
                    process,
                    resource,
                    offset,
                    width,
                    out_value,
                )
            }
            NativeSyscallRequest::InterruptCreate {
                resource,
                requested_rights,
                out_interrupt,
            } => crate::syscall::interrupt_create(
                user,
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.device_resources,
                &self.core.shared.interrupts,
                &self.core.shared.interrupt_platform,
                process,
                resource,
                requested_rights,
                out_interrupt,
            ),
            NativeSyscallRequest::EventCreate {
                requested_rights,
                out_event,
            } => crate::syscall::event_create(
                user,
                &mut self.core.registry,
                &self.core.shared.events,
                &mut self.core.tasks,
                process,
                requested_rights,
                out_event,
                &mut self.core.cleanup,
            ),
            NativeSyscallRequest::TimerCreate {
                requested_rights,
                out_timer,
            } => crate::syscall::timer_create(
                user,
                &mut self.core.registry,
                &self.core.shared.timers,
                &mut self.core.tasks,
                process,
                requested_rights,
                out_timer,
                &mut self.core.cleanup,
            ),
            NativeSyscallRequest::ChannelCreate {
                requested_rights,
                out_endpoint0,
                out_endpoint1,
            } => crate::syscall::channel_create(
                user,
                &mut self.core.registry,
                &self.core.shared.channels,
                &mut self.core.tasks,
                process,
                requested_rights,
                out_endpoint0,
                out_endpoint1,
            ),
            _ => unreachable!("deferred-output classification drifted"),
        }
    }

    /// The guarded half of a deferred `MemoryObjectCreate` (D1 commit 6c):
    /// the ordinary adapter call, with the early backing and output standing
    /// in for the user session.
    fn run_deferred_output_with(
        &mut self,
        request: NativeSyscallRequest,
        access: &mut crate::syscall::DeferredMemoryObjectAccess,
    ) -> deepwyrm_abi::DwStatus {
        let NativeSyscallRequest::MemoryObjectCreate {
            byte_len,
            flags,
            requested_rights,
            out_handle,
        } = request
        else {
            unreachable!("deferred MemoryObject classification drifted")
        };
        let process = self.own.scheduled().process;
        crate::syscall::memory_object_create_owned(
            access,
            &mut self.core.registry,
            &mut self.core.memory,
            &mut self.core.tasks,
            process,
            byte_len,
            flags,
            requested_rights,
            out_handle,
            &mut self.core.cleanup,
        )
    }

    /// The guarded half of `ObjectGetInfoV1` (D1 commit 6d): the read-only
    /// query, touching no user memory.
    fn query_object_info(
        &mut self,
        handle: deepwyrm_abi::DwHandle,
        topic: u32,
    ) -> Result<crate::syscall::EncodedObjectInfo, deepwyrm_abi::DwStatus> {
        crate::syscall::object_get_info_v1_query_with_device_objects(
            &mut self.core.registry,
            &self.core.memory,
            &self.core.tasks,
            &self.core.shared.device_resources,
            &self.core.shared.interrupts,
            self.own.scheduled().process,
            handle,
            topic,
        )
    }

    /// The guarded half of `ChannelSend` (D1 commit 7): the send commit over
    /// the payload already snapshotted into this CPU's Channel staging.
    fn commit_channel_send(
        &mut self,
        inputs: &crate::syscall::ChannelSendInputs,
        channel: deepwyrm_abi::DwHandle,
    ) -> deepwyrm_abi::DwStatus {
        let scheduled = self.own.scheduled();
        crate::syscall::channel_send_commit(
            inputs,
            &self.owned.channel_staging[..],
            &mut self.core.registry,
            &self.core.shared.channels,
            &self.core.shared.waits,
            &mut self.core.tasks,
            &self.core.shared.execution,
            scheduled.process,
            Some(scheduled.thread),
            channel,
            &mut self.core.cleanup,
        )
    }

    /// ChannelReceive's first guarded step (D1 commit 7b): resolve the
    /// endpoint and reserve its head message for this receiver.
    fn reserve_channel_receive(
        &mut self,
        channel: deepwyrm_abi::DwHandle,
    ) -> Result<crate::syscall::ChannelReceiveHold, deepwyrm_abi::DwStatus> {
        crate::syscall::channel_receive_reserve(
            &mut self.core.registry,
            &self.core.shared.channels,
            &self.core.tasks,
            self.own.scheduled().process,
            channel,
            &mut self.core.cleanup,
        )
    }

    /// Cancels a held receive whose outputs could not be formed or pinned.
    fn abandon_channel_receive(
        &mut self,
        hold: crate::syscall::ChannelReceiveHold,
        status: deepwyrm_abi::DwStatus,
    ) -> deepwyrm_abi::DwStatus {
        hold.abandon(
            status,
            &mut self.core.registry,
            &self.core.shared.channels,
            &mut self.core.cleanup,
        )
    }

    /// Cancels a held receive whose message does not fit.
    fn channel_receive_too_small(
        &mut self,
        hold: crate::syscall::ChannelReceiveHold,
    ) -> [u8; deepwyrm_abi::DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize] {
        hold.too_small(
            &mut self.core.registry,
            &self.core.shared.channels,
            &mut self.core.cleanup,
        )
    }

    /// Dequeues a held receive into this CPU's Channel staging, after every
    /// output is pinned.
    fn commit_channel_receive(
        &mut self,
        hold: crate::syscall::ChannelReceiveHold,
    ) -> Result<crate::syscall::ChannelReceiveCopyOut, deepwyrm_abi::DwStatus> {
        hold.commit(
            &mut self.owned.channel_staging[..],
            &mut self.core.registry,
            &self.core.shared.channels,
            &self.core.shared.waits,
            &mut self.core.tasks,
            &self.core.shared.execution,
            self.own.scheduled().process,
            &mut self.core.cleanup,
        )
    }

    /// The guarded half of `ProcessCreate` (D1 commit 7c): the selector
    /// evidence checks, then the F10 transaction over the prepared input.
    /// The child root is reserved through P beneath this guard, and the
    /// output's commit or discard is returned for the facade to carry out.
    #[allow(
        clippy::type_complexity,
        reason = "the pinned output and its optional result travel together"
    )]
    /// The first guarded half of `AtomicWait32` (D1 commit 8b).
    fn register_atomic_wait(
        &mut self,
        pinned: Result<(user_access::OwnedLiveAtomicU32, u32), deepwyrm_abi::DwStatus>,
        address: deepwyrm_abi::DwUserAddress,
        expected: u32,
        deadline: deepwyrm_abi::DwDeadline,
    ) -> crate::syscall::AtomicWaitHold<user_access::OwnedLiveAtomicU32> {
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let scheduled = self.own.scheduled();
        self.core.services.register_atomic_wait_pinned(
            pinned,
            &mut self.core.tasks,
            &self.core.shared.execution,
            &self.core.regions,
            scheduled.process,
            scheduled.thread,
            address,
            expected,
            deadline,
            self.owned.owner.cpu(),
            Some(&mut wait_deadlines),
        )
    }

    /// The second guarded half of `AtomicWait32` (D1 commit 8b).
    fn settle_atomic_wait(
        &mut self,
        pending: crate::atomic_wait::PendingAtomicWait,
        pin: user_access::OwnedLiveAtomicU32,
        matched: bool,
    ) -> (NativeSyscallResult, Option<user_access::OwnedLiveAtomicU32>) {
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let scheduled = self.own.scheduled();
        self.core.services.settle_atomic_wait_pinned(
            &mut self.own.wait_control,
            pending,
            pin,
            matched,
            &mut self.core.tasks,
            &self.core.shared.execution,
            self.owned.owner.cpu(),
            scheduled.process,
            scheduled.thread,
            Some(&mut wait_deadlines),
        )
    }

    /// The guarded half of `ThreadStart` (D1 commit 9): resolve, retarget a
    /// return-validation session, walk RIP and RSP, start the Thread. No
    /// usercopy; the arguments were copied in with P alone.
    fn run_thread_start(
        &mut self,
        args: Result<deepwyrm_abi::DwThreadStartArgsV1, deepwyrm_abi::DwStatus>,
    ) -> deepwyrm_abi::DwStatus {
        let status = {
            let mut paging = self.paging.lock();
            let mut validation = paging.return_validation_session(
                self.own.active_root.as_ref().expect("active root"),
                self.own.scheduled().process,
            );
            let regions = &self.core.regions;
            let memory = &self.core.memory;
            let demand = |process, address, execute| {
                regions.on_demand_return_allowed(process, address, execute, |object| {
                    memory.object_is_on_demand(object)
                })
            };
            crate::syscall::thread_start_prepared(
                args,
                &mut OnDemandReturn {
                    inner: &mut validation,
                    demand: &demand,
                },
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                self.own.scheduled().process,
                &mut self.core.cleanup,
            )
        };
        status
    }

    /// The guarded half of `WaitOne` and `WaitMany` (D1 commit 8): the
    /// same wait begin as the ordinary dispatch, over prepared input.
    fn begin_wait(
        &mut self,
        prepared: Result<
            crate::syscall::PreparedWait<user_access::OwnedLiveUserOutput>,
            deepwyrm_abi::DwStatus,
        >,
    ) -> (
        NativeSyscallResult,
        Option<(
            user_access::OwnedLiveUserOutput,
            crate::syscall::WaitResultBytes,
        )>,
    ) {
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(status) => return (NativeSyscallResult::returning(status), None),
        };
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let scheduled = self.own.scheduled();
        self.core.services.begin_prepared_wait(
            &mut self.own.wait_control,
            prepared,
            &mut self.core.registry,
            &mut self.core.tasks,
            &self.core.shared.events,
            &self.core.shared.timers,
            &self.core.shared.channels,
            Some(&self.core.shared.interrupts),
            &self.core.shared.waits,
            &self.core.shared.execution,
            Some(&mut wait_deadlines),
            self.owned.owner.cpu(),
            scheduled.process,
            scheduled.thread,
        )
    }

    fn run_process_create(
        &mut self,
        prepared: Result<
            crate::syscall::PreparedProcessCreate<user_access::OwnedLiveUserOutput>,
            deepwyrm_abi::DwStatus,
        >,
    ) -> (
        deepwyrm_abi::DwStatus,
        Option<(
            user_access::OwnedLiveUserOutput,
            Option<[u8; deepwyrm_abi::DW_PROCESS_CREATE_RESULT_V1_SIZE as usize]>,
        )>,
    ) {
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(status) => return (status, None),
        };
        let process = self.own.scheduled().process;
        let (status, pending) = {
            let mut paging = self.paging.lock();
            let mut session = paging.page_table_mutation_session(
                self.own.active_root.as_ref().expect("active root"),
                process,
            );
            let mut access = crate::syscall::DeferredProcessCreateAccess::new(&mut session);
            let status = crate::syscall::process_create_with_root_prepared(
                prepared,
                &mut access,
                &mut self.core.registry,
                &mut self.core.tasks,
                &mut self.core.regions,
                &mut self.core.spaces,
                process,
                &mut self.core.cleanup,
                |_child| {},
            );
            (status, access.into_pending())
        };
        (status, Some(pending))
    }

    /// The guarded half of a deferred `AtomicWake` (D1 commit 6b). The early
    /// atomic pin comes back for release after the hold.
    fn run_deferred_atomic_wake(
        &mut self,
        user: &mut crate::memory::usercopy::DeferredUserOutput,
        pinned: Result<user_access::OwnedLiveAtomicU32, deepwyrm_abi::DwStatus>,
        address: deepwyrm_abi::DwUserAddress,
        count: u32,
        out_woken: deepwyrm_abi::DwUserAddress,
    ) -> (
        deepwyrm_abi::DwStatus,
        Option<user_access::OwnedLiveAtomicU32>,
    ) {
        let process = self.own.scheduled().process;
        let (status, released) = self.core.services.dispatch_atomic_wake_pinned(
            user,
            pinned,
            &mut self.core.tasks,
            &self.core.shared.execution,
            &self.core.regions,
            process,
            address,
            count,
            out_woken,
        );
        (status, released)
    }

    /// The guarded half of a family-A syscall's preparation (D1 commit 5):
    /// the same running-Thread check and I1 observation as `handle`, the
    /// phase reservation, and a copy of this CPU's root identity for the
    /// usercopy that follows guard-free.
    fn prepare_guard_free_usercopy(
        &mut self,
    ) -> (
        crate::arch::x86_64::syscall::RuntimePhaseReservation,
        super::UserCopyRoot,
        ProcessKey,
    ) {
        if self
            .core
            .shared
            .execution
            .scheduler_state(self.own.scheduled().thread)
            != Some(SchedulerThreadState::Running)
        {
            panic!("primordial syscall arrived without its running Thread");
        }
        let phase = self.reserve_runtime_phase();
        let root = self
            .own
            .active_root
            .as_ref()
            .expect("active root")
            .usercopy_root();
        (phase, root, self.own.scheduled().process)
    }

    /// The only way a syscall result leaves the runtime guard for its
    /// dispatcher. A syscall return is the publication boundary for final
    /// handle releases: a result that returns to the caller first drains the
    /// carrier's cleanup queue, so no peer signal, waiter wake or payload
    /// reclamation stays parked there while userspace resumes (TSV row 76).
    fn ready_to_return(
        &mut self,
        result: NativeSyscallResult,
    ) -> crate::syscall::native::ReturnReady {
        match crate::syscall::native::ReturnReady::without_return(result) {
            Ok(ready) => ready,
            Err(result) => {
                crate::syscall::native::ReturnReady::drained(result, self.publish_final_releases())
            }
        }
    }

    /// Drains the finalizers and returns the proof a syscall return needs.
    #[allow(
        unsafe_code,
        reason = "the drain proof is minted only after the drain completed"
    )]
    fn publish_final_releases(&mut self) -> crate::syscall::native::FinalizersDrained {
        self.drain_finalizers()
            .unwrap_or_else(|_| panic!("normal syscall return could not drain finalizers"));
        // SAFETY: `drain_finalizers` returns `Ok` only after its loop emptied the cleanup queue
        // and found no deferred parent release to push.
        unsafe { crate::syscall::native::FinalizersDrained::assume() }
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeCarrier<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle_fallthrough(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        match request {
            NativeSyscallRequest::AbiGetInfo { .. } => {
                unreachable!("AbiGetInfo must be served guard-free by the CPU-local facade")
            }
            NativeSyscallRequest::HandleDuplicate { .. }
            | NativeSyscallRequest::TaskGroupCreate { .. }
            | NativeSyscallRequest::ThreadCreate { .. }
            | NativeSyscallRequest::DeviceResourceClaim { .. }
            | NativeSyscallRequest::DevicePioRead { .. }
            | NativeSyscallRequest::DevicePciConfigRead { .. }
            | NativeSyscallRequest::DeviceMmioObjectCreate { .. }
            | NativeSyscallRequest::DmaMap { .. }
            | NativeSyscallRequest::InterruptCreate { .. }
            | NativeSyscallRequest::MemoryObjectCreate { .. }
            | NativeSyscallRequest::ObjectGetInfoV1 { .. } => {
                unreachable!(
                    "family-B requests are served by the CPU-local facade's deferred output"
                )
            }
            NativeSyscallRequest::MemoryObjectCommit { .. } => {
                unreachable!("MemoryObjectCommit is served by the CPU-local facade in steps")
            }
            NativeSyscallRequest::HandleClose { handle } => {
                let status = crate::syscall::handle_close(
                    &mut self.core.registry,
                    &mut self.core.tasks,
                    self.own.scheduled().process,
                    handle,
                    &mut self.core.cleanup,
                );
                #[cfg(feature = "test-support")]
                if status == DW_STATUS_BAD_STATE {
                    panic!(
                        "running HandleClose caller has bad lifecycle: process={:?} thread={:?} lifecycle={:?}",
                        self.own.scheduled().process,
                        self.own.scheduled().thread,
                        self.core
                            .tasks
                            .process_lifecycle(self.own.scheduled().process),
                    );
                }
                NativeSyscallResult::returning(status)
            }
            NativeSyscallRequest::TaskGroupTerminate { .. } => {
                unreachable!("TaskGroupTerminate must be intercepted by the CPU-local facade")
            }
            NativeSyscallRequest::ThreadStart { .. } => {
                unreachable!("ThreadStart is served by the CPU-local facade (D1 commit 9)")
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
            NativeSyscallRequest::AddressRegionMap { .. }
            | NativeSyscallRequest::AddressRegionUnmap { .. }
            | NativeSyscallRequest::AddressRegionProtect { .. } => {
                unreachable!("family-G requests are served by the CPU-local facade (D1 option B3)")
            }
            NativeSyscallRequest::ProcessExit { exit_code } => self.exit_process(exit_code),
            NativeSyscallRequest::ThreadExit { exit_code } => self.exit_thread(exit_code),
            NativeSyscallRequest::ThreadSetFsBase { fs_base } => {
                if !crate::arch::x86_64::user_state::is_valid_user_fs_base(fs_base) {
                    return NativeSyscallResult::returning(
                        deepwyrm_abi::DW_STATUS_INVALID_ARGUMENT,
                    );
                }
                // SAFETY: the syscall runtime runs at CPL0 with IF clear on the CPU running the
                // calling Thread, and the value was just checked to be lower-half canonical. The
                // register is that Thread's own state from here on: `switch_kernel_context` saves
                // and restores it.
                unsafe { crate::arch::x86_64::user_state::write_current_fs_base(fs_base) };
                NativeSyscallResult::returning(DW_STATUS_SUCCESS)
            }
            NativeSyscallRequest::DevicePioWrite {
                resource,
                offset,
                width,
                value,
            } => {
                let mut io = crate::arch::x86_64::io_port::X86PortIo;
                NativeSyscallResult::returning(crate::syscall::device_pio_write(
                    &mut self.core.registry,
                    &mut self.core.tasks,
                    &self.core.shared.device_resources,
                    &mut io,
                    self.own.scheduled().process,
                    resource,
                    offset,
                    width,
                    value,
                ))
            }
            NativeSyscallRequest::DevicePciCommand {
                resource,
                memory_space,
                bus_master,
            } => {
                let mut ports = crate::arch::x86_64::io_port::X86PortIo;
                let mut config = crate::arch::x86_64::pci_config::Mechanism1::new(&mut ports);
                NativeSyscallResult::returning(crate::syscall::device_pci_command(
                    &mut self.core.registry,
                    &mut self.core.tasks,
                    &self.core.shared.device_resources,
                    &mut config,
                    &mut crate::device::dma::live::LiveDmaService,
                    self.own.scheduled().process,
                    resource,
                    memory_space,
                    bus_master,
                    crate::device::pci::dma_confined,
                    &mut self.core.cleanup,
                ))
            }
            NativeSyscallRequest::DmaUnmap {
                resource,
                iova,
                byte_len,
            } => NativeSyscallResult::returning(crate::syscall::dma_unmap(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.device_resources,
                &mut crate::device::dma::live::LiveDmaService,
                self.own.scheduled().process,
                resource,
                iova,
                byte_len,
                &mut self.core.cleanup,
            )),
            NativeSyscallRequest::InterruptAck { interrupt } => {
                NativeSyscallResult::returning(crate::syscall::interrupt_ack(
                    &mut self.core.registry,
                    &mut self.core.tasks,
                    &self.core.shared.interrupts,
                    &self.core.shared.interrupt_platform,
                    self.own.scheduled().process,
                    interrupt,
                    &mut self.core.cleanup,
                ))
            }
            _ => NativeSyscallResult::returning(DW_STATUS_NOT_SUPPORTED),
        }
    }

    /// The first hold of a family-G syscall (D1 option B3, design §11.2.9),
    /// after the facade's preparation hold reserved the phase and, for map,
    /// copied the arguments in and pinned the output with P alone (D1 commit
    /// 9): map, unmap or protect. A mutation whose shootdown is settled in this
    /// hold (nothing published, or no target left to acknowledge) has its
    /// releases merged, commits the phase and leaves through
    /// `ready_to_return`. A published one hands its pending shootdown, the
    /// held S and the phase to the facade, which waits with neither T nor P
    /// held.
    fn begin_address_region_mutation(
        &mut self,
        request: NativeSyscallRequest,
        map_input: Option<MapStep>,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        held: &mut crate::syscall::HeldReleases<REGISTRY_OBJECTS>,
        last: bool,
    ) -> (FamilyGBegun, Option<u64>) {
        let (status, shootdown, address) = match (request, map_input) {
            (
                NativeSyscallRequest::AddressRegionMap {
                    address_region,
                    memory_object,
                    ..
                },
                Some(input),
            ) => self.map_memory(address_region, memory_object, input, held),
            (
                NativeSyscallRequest::AddressRegionUnmap {
                    address_region,
                    address,
                    byte_len,
                },
                None,
            ) => {
                let (status, shootdown) =
                    self.unmap_memory(address_region, address, byte_len, held);
                (status, shootdown, None)
            }
            (
                NativeSyscallRequest::AddressRegionProtect {
                    address_region,
                    address,
                    byte_len,
                    protections,
                },
                None,
            ) => {
                let (status, shootdown) =
                    self.protect_memory(address_region, address, byte_len, protections, held);
                (status, shootdown, None)
            }
            _ => unreachable!("family-G classification drifted"),
        };
        let begun = match shootdown {
            None if last => {
                self.commit_runtime_phase(phase);
                FamilyGBegun::Returned(self.ready_to_return(NativeSyscallResult::returning(status)))
            }
            None => {
                self.drain_step_finalizers();
                FamilyGBegun::Stepped { phase, status }
            }
            Some(shootdown) => FamilyGBegun::Published {
                phase,
                status,
                shootdown,
            },
        };
        (begun, address)
    }

    /// Drains an inner step's finalizers (DW2 M4b), as a return would, so a
    /// call in steps never parks more than one step's releases.
    fn drain_step_finalizers(&mut self) {
        self.drain_finalizers()
            .unwrap_or_else(|_| panic!("a family-G step could not drain its finalizers"));
    }

    /// Returns a family-G call made in steps, after its last step (DW2 M4b).
    fn return_from_steps(
        &mut self,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        status: deepwyrm_abi::DwStatus,
    ) -> crate::syscall::native::ReturnReady {
        self.commit_runtime_phase(phase);
        self.ready_to_return(NativeSyscallResult::returning(status))
    }

    /// The whole-range checks and protection snapshot of an unmap or
    /// protect in steps, before its first step (DW2 M4b).
    fn region_snapshot(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        start: u64,
        end: u64,
    ) -> Result<[Option<(u64, u64, u32)>; REGION_SLOTS], deepwyrm_abi::DwStatus> {
        crate::syscall::address_region_range_snapshot(
            &mut self.core.registry,
            &self.core.tasks,
            &self.core.regions,
            self.own.scheduled().process,
            address_region,
            deepwyrm_abi::DW_RIGHT_MODIFY,
            start,
            end - start,
            &mut self.core.cleanup,
        )
    }

    /// The last hold of a published family-G syscall (D1 option B3): its
    /// held releases merge on the permit, after every acknowledgement, so
    /// `ready_to_return`'s drain reclaims them only then; the phase is
    /// revalidated and committed.
    fn finish_address_region_mutation(
        &mut self,
        held: &mut crate::syscall::HeldReleases<REGISTRY_OBJECTS>,
        settlement: crate::memory::address_region::ShootdownOutcome,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        status: deepwyrm_abi::DwStatus,
        last: bool,
    ) -> FamilyGBegun {
        held.merge(settlement, &mut self.core.cleanup);
        if !last {
            self.drain_step_finalizers();
            return FamilyGBegun::Stepped { phase, status };
        }
        self.commit_runtime_phase(phase);
        FamilyGBegun::Returned(self.ready_to_return(NativeSyscallResult::returning(status)))
    }

    /// Settles a family-G shootdown in its first hold when nothing is left to
    /// acknowledge, or hands it on (D1 option B3).
    fn settle_or_defer_shootdown<const CLEANUP: usize>(
        published: crate::memory::address_region::PublishedShootdown<{ crate::cpu::CPU_CAPACITY }>,
        initiator: ShootdownInitiatorGuard<'static>,
        driver: user_access::LiveTlbShootdownDriver,
        held: &mut crate::syscall::HeldReleases<REGISTRY_OBJECTS>,
        cleanup: &mut crate::syscall::CleanupQueue<CLEANUP>,
    ) -> Option<FamilyGShootdown> {
        match published {
            crate::memory::address_region::PublishedShootdown::Settled(settlement) => {
                let settlement = initiator.release(settlement);
                held.merge(settlement, cleanup);
                None
            }
            crate::memory::address_region::PublishedShootdown::Pending(pending) => {
                Some(FamilyGShootdown {
                    pending,
                    driver,
                    initiator,
                })
            }
        }
    }

    // Out of line (D1 option B2): its held releases stay out of the
    // ordinary handler's measured frame.
    #[inline(never)]
    /// Serves a CPL3 page fault at `cr2` on an on-demand page, under T and
    /// then P (DW2 M6 §8.5). In this one hold it finds the mapping, checks
    /// the access against its protection, admits the page and any index
    /// nodes against the object's creator and any page tables against this
    /// Process, commits the page, and publishes its one leaf here.
    fn serve_user_page_fault(
        &mut self,
        cr2: u64,
        error: u64,
    ) -> crate::syscall::native::UserPageFaultOutcome {
        use crate::memory::frame_roles::FrameRoleError;
        use crate::syscall::native::UserPageFaultOutcome as Outcome;
        const WRITE: u64 = 1 << 1;
        const FETCH: u64 = 1 << 4;
        let process = self.own.scheduled().process;
        let thread = self.own.scheduled().thread;
        if self.core.tasks.thread_process(thread) != Ok(process)
            || self.core.shared.execution.current_thread_on(self.cpu()) != Some(thread)
        {
            return Outcome::Unserved;
        }
        let address = cr2 & !(PAGE_SIZE - 1);
        let Ok(Some(mapping)) =
            self.core
                .regions
                .root_mapping_at(&self.core.tasks, process, address)
        else {
            return Outcome::Unserved;
        };
        let protection = mapping.protection();
        if (error & WRITE != 0 && !protection.writable())
            || (error & FETCH != 0 && !protection.executable())
        {
            return Outcome::Unserved;
        }
        let Some(object) = mapping.object_id() else {
            return Outcome::Unserved;
        };
        let backing = mapping.backing().backing_identity();
        let page =
            (address - mapping.virtual_start() + mapping.backing().object_offset()) / PAGE_SIZE;
        let mut paging = self.paging.lock();
        let mut session = paging.page_table_mutation_session(
            self.own.active_root.as_ref().expect("active root"),
            process,
        );
        if session
            .select_process_for_return_validation(process)
            .is_err()
        {
            return Outcome::Unserved;
        }
        // An eager backing has no commit cost to ask: its page faulting is
        // not one this serves.
        let Ok(cost) = session.on_demand_commit_cost(backing, page) else {
            return Outcome::Unserved;
        };
        let tables = {
            let mut empty: [Option<crate::memory::frame_roles::TableCandidateGrant>; 3] =
                [const { None }; 3];
            let Ok(mut publisher) =
                session.publisher::<3>(mapping.address_space(), mapping.region(), &mut empty)
            else {
                return Outcome::Unserved;
            };
            match publisher.touch_table_cost(address) {
                Ok(tables) => tables as u64,
                Err(_) => return Outcome::Unserved,
            }
        };
        // Admit both, together, before taking a frame (§8.4). Only a quota
        // refusal is exhaustion; the object and Process are live here.
        match crate::syscall::admit_charged_pages_together(
            &self.core.registry,
            &self.core.tasks,
            (object, cost),
            (process.object_id(), tables),
        ) {
            Ok(()) => {}
            Err(deepwyrm_abi::DW_STATUS_NO_RESOURCES) => {
                return Outcome::Exhausted(deepwyrm_abi::DW_STATUS_NO_RESOURCES);
            }
            Err(_) => return Outcome::Unserved,
        }
        if cost != 0 {
            match session.commit_on_demand_page(backing, page) {
                Ok(commit) => crate::syscall::record_charged_pages(
                    &mut self.core.registry,
                    object,
                    commit.frames,
                ),
                Err(
                    FrameRoleError::Physical(_)
                    | FrameRoleError::Capacity
                    | FrameRoleError::InitializationFailed,
                ) => return Outcome::Exhausted(deepwyrm_abi::DW_STATUS_NO_MEMORY),
                Err(_) => return Outcome::Unserved,
            }
        }
        // The levels missing are the lowest `tables` of PDPT, PD, PT.
        let mut candidates: [Option<crate::memory::frame_roles::TableCandidateGrant>; 3] =
            [const { None }; 3];
        let levels = [
            crate::memory::frame_roles::TableLevel::Pdpt,
            crate::memory::frame_roles::TableLevel::Pd,
            crate::memory::frame_roles::TableLevel::Pt,
        ];
        for (slot, level) in levels[3 - tables as usize..].iter().enumerate() {
            match session.prepare_table_candidate(*level) {
                Ok(candidate) => candidates[slot] = Some(candidate),
                Err(_) => {
                    for candidate in candidates.iter_mut().filter_map(Option::take) {
                        session.recycle_table_candidate(candidate);
                    }
                    return Outcome::Exhausted(deepwyrm_abi::DW_STATUS_NO_MEMORY);
                }
            }
        }
        let published = {
            let Ok(mut publisher) =
                session.publisher::<3>(mapping.address_space(), mapping.region(), &mut candidates)
            else {
                panic!("an on-demand fault's publisher was refused after its lookup");
            };
            publisher.publish_touched_leaf(&mapping, address)
        };
        // A leaf already present that is not exactly this page's leaf is not
        // a race this serves: the fault ends as before. Only a page
        // committed in this hold could not have had one.
        let published = match published {
            Ok(published) => published,
            Err(crate::arch::x86_64::mm::X86AddressSpacePublishError::Map(
                crate::arch::x86_64::mm::MapError::FrameMismatch,
            )) if cost == 0 => {
                for candidate in candidates.iter_mut().filter_map(Option::take) {
                    session.recycle_table_candidate(candidate);
                }
                return Outcome::Unserved;
            }
            Err(error) => panic!("an on-demand fault could not publish its leaf: {error:?}"),
        };
        let unused = candidates.iter().flatten().count() as u64;
        for candidate in candidates.iter_mut().filter_map(Option::take) {
            session.recycle_table_candidate(candidate);
        }
        let built = tables - unused;
        if built != 0 {
            crate::syscall::record_charged_pages(
                &mut self.core.registry,
                process.object_id(),
                built,
            );
        }
        if published || cost != 0 {
            Outcome::Served
        } else {
            Outcome::AlreadyPresent
        }
    }

    /// One hold of a syscall's fill-in phase (DW2 M6 §8.6): serves, as a
    /// user touch of the access the syscall will make, every on-demand page
    /// under `[*next, end)` up to one step's end, publishing its leaf here so
    /// the copy's page walk finds it. Pages outside on-demand mappings are
    /// left to the copy, which fails them as before.
    fn fill_in_user_range(
        &mut self,
        next: &mut u64,
        end: u64,
        write: bool,
    ) -> Result<(), deepwyrm_abi::DwStatus> {
        const USER: u64 = 1 << 2;
        const WRITE: u64 = 1 << 1;
        let process = self.own.scheduled().process;
        let step_end = end.min(next.saturating_add(FAMILY_G_STEP_BYTES));
        while *next < step_end {
            let page = *next;
            *next = page.saturating_add(PAGE_SIZE);
            let on_demand = match self
                .core
                .regions
                .root_mapping_at(&self.core.tasks, process, page)
            {
                Ok(Some(mapping)) => mapping
                    .object_id()
                    .is_some_and(|object| self.core.memory.object_is_on_demand(object)),
                _ => false,
            };
            if !on_demand {
                continue;
            }
            let error = USER | if write { WRITE } else { 0 };
            if let crate::syscall::native::UserPageFaultOutcome::Exhausted(status) =
                self.serve_user_page_fault(page, error)
            {
                return Err(status);
            }
        }
        Ok(())
    }

    /// One hold of `memory_object_commit` (and of `dma_map`'s fill-in):
    /// commits the pages from `*next` up to one commit step's end. The
    /// step's cost is admitted against the object's creator in this hold,
    /// all at once or, past the quota, the longest start of it that fits;
    /// the frames taken are charged to its weight (DW2 M6 §8.4). A step is
    /// at most 2 MiB, so a hold zeroes at most that and scans the registry
    /// at most ten times, not once a page (§8.11 R1). `Ok(true)` when the
    /// whole range is done.
    fn commit_on_demand_step(
        &mut self,
        memory_object: deepwyrm_abi::DwHandle,
        offset: u64,
        byte_len: u64,
        required: deepwyrm_abi::DwRights,
        next: &mut u64,
    ) -> Result<bool, deepwyrm_abi::DwStatus> {
        let process = self.own.scheduled().process;
        let Some((backing, object)) = crate::syscall::memory_object_commit_target(
            &mut self.core.registry,
            &mut self.core.tasks,
            &self.core.memory,
            process,
            memory_object,
            offset,
            byte_len,
            required,
        )?
        else {
            return Ok(true);
        };
        // The target checked the range lies in the object and is aligned.
        let page_size = u64::from(deepwyrm_abi::DW_BASE_PAGE_SIZE);
        let end = offset + byte_len;
        let step_end = end.min(next.saturating_add(ON_DEMAND_COMMIT_STEP_BYTES));
        let first = *next / page_size;
        let count = (step_end - *next) / page_size;
        let mut paging = self.paging.lock();
        let mut session = paging.page_table_mutation_session(
            self.own.active_root.as_ref().expect("active root"),
            process,
        );
        let registry = &self.core.registry;
        let tasks = &self.core.tasks;
        let admit = |pages: u64| -> Result<u64, deepwyrm_abi::DwStatus> {
            let cost = session
                .on_demand_commit_range_cost(backing, first, pages)
                .map_err(|_| DW_STATUS_BAD_STATE)?;
            if cost != 0 {
                crate::syscall::admit_charged_pages(registry, tasks, object, cost)?;
            }
            Ok(cost)
        };
        // The whole step, or else the longest start of it the quota admits,
        // so a commit still fills the quota exactly: at most ten admissions.
        let (admitted, cost, mut result) = match admit(count) {
            Ok(cost) => (count, cost, Ok(())),
            Err(deepwyrm_abi::DW_STATUS_NO_RESOURCES) => {
                let (mut fits, mut fits_cost, mut refused) = (0, 0, count);
                while refused - fits > 1 {
                    let middle = fits + (refused - fits) / 2;
                    match admit(middle) {
                        Ok(cost) => (fits, fits_cost) = (middle, cost),
                        Err(deepwyrm_abi::DW_STATUS_NO_RESOURCES) => refused = middle,
                        Err(status) => return Err(status),
                    }
                }
                (fits, fits_cost, Err(deepwyrm_abi::DW_STATUS_NO_RESOURCES))
            }
            Err(status) => return Err(status),
        };
        let mut frames = 0;
        for page in first..first + admitted {
            match session.commit_on_demand_page(backing, page) {
                Ok(commit) => frames += commit.frames,
                Err(error) => {
                    result = Err(match error {
                        crate::memory::frame_roles::FrameRoleError::Physical(_)
                        | crate::memory::frame_roles::FrameRoleError::Capacity
                        | crate::memory::frame_roles::FrameRoleError::InitializationFailed => {
                            deepwyrm_abi::DW_STATUS_NO_MEMORY
                        }
                        _ => DW_STATUS_BAD_STATE,
                    });
                    break;
                }
            }
            *next += page_size;
        }
        // What was taken stays committed and charged, even after a failure.
        debug_assert!(frames <= cost, "a commit step took more than it admitted");
        if frames != 0 {
            crate::syscall::record_charged_pages(&mut self.core.registry, object, frames);
        }
        result.map(|()| *next >= end)
    }

    fn map_memory(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        memory_object: deepwyrm_abi::DwHandle,
        input: MapStep,
        held: &mut crate::syscall::HeldReleases<REGISTRY_OBJECTS>,
    ) -> (
        deepwyrm_abi::DwStatus,
        Option<FamilyGShootdown>,
        Option<u64>,
    ) {
        let (args, protection, room) = match input {
            Ok(input) => input,
            Err(status) => return (status, None, None),
        };
        let mut shootdown = None;
        let result = (|| {
            let prepared = match crate::syscall::prepare_address_region_mutation(
                &mut self.core.registry,
                &self.core.tasks,
                &self.core.regions,
                self.own.scheduled().process,
                address_region,
                deepwyrm_abi::DwRights(
                    deepwyrm_abi::DW_RIGHT_MAP.0 | deepwyrm_abi::DW_RIGHT_MODIFY.0,
                ),
                &mut self.core.cleanup,
            ) {
                Ok(target) => target,
                Err(status) => return Err(status),
            };
            let target = prepared.target();
            let caller_process = self.own.scheduled().process;
            let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
            let result = {
                let mut paging = self.paging.lock();
                let mut session = paging.page_table_mutation_session(
                    self.own.active_root.as_ref().expect("active root"),
                    self.own.scheduled().process,
                );
                if session
                    .select_process_for_return_validation(target.process)
                    .is_err()
                {
                    Err(DW_STATUS_BAD_STATE)
                } else {
                    let result = (|| {
                        // As many tables as the mapping's length can need
                        // at each level (D7), never more than the pool.
                        // A larger map is published in batches, and the
                        // publisher refills this pool between them (DW2 M4).
                        let levels = crate::arch::x86_64::mm::table_candidates_for(
                            args.byte_len
                                .0
                                .min(PRIMORDIAL_MAX_USER_MAPPING_PAGES as u64 * 4096),
                            PRIMORDIAL_TABLE_CANDIDATES,
                        )
                        .ok_or(DW_STATUS_NO_RESOURCES)?;
                        let mut slot = 0;
                        for (level, count) in levels {
                            for _ in 0..count {
                                candidates[slot] = Some(
                                    session
                                        .prepare_table_candidate(level)
                                        .map_err(|_| DW_STATUS_NO_RESOURCES)?,
                                );
                                slot += 1;
                            }
                        }
                        let mut driver = user_access::LiveTlbShootdownDriver::current();
                        // S, beneath P, before the publisher's prepare_mutation (D1 option B1).
                        let initiator = PRIMORDIAL_SHOOTDOWN_INITIATOR.acquire_beneath(&session);
                        let (mut publisher, coherency) = match session
                            .publisher_with_coherency::<PRIMORDIAL_TABLE_CANDIDATES>(
                                target.address_space,
                                target.region_key,
                                &mut candidates,
                            ) {
                            Ok(parts) => parts,
                            Err(_) => {
                                initiator.release_unused();
                                return Err(DW_STATUS_BAD_STATE);
                            }
                        };
                        // SAFETY: the coherency domain lives in its root binding in the stationary
                        // primordial paging storage. A binding is removed only by a teardown,
                        // which takes S first (D1 option B4) and prepares one on the domain, which
                        // a published mutation refuses; S stays held until this shootdown's permit.
                        let mut publisher = unsafe {
                            crate::memory::address_region::CoherentAddressSpacePublisher::<
                                _,
                                _,
                                { crate::cpu::CPU_CAPACITY },
                                { user_access::LIVE_SHOOTDOWN_WAIT_STEPS },
                            >::new_deferred(
                                &mut publisher, coherency, &mut driver
                            )
                        };
                        let result = crate::syscall::address_region_map_prepared_model(
                            prepared,
                            &mut publisher,
                            &mut self.core.registry,
                            &mut self.core.memory,
                            &mut self.core.tasks,
                            &mut self.core.regions,
                            self.own.scheduled().process,
                            address_region,
                            memory_object,
                            args,
                            protection,
                            room,
                            held,
                        );
                        let published = publisher.finish_deferred();
                        shootdown = Self::settle_or_defer_shootdown(
                            published,
                            initiator,
                            driver,
                            held,
                            &mut self.core.cleanup,
                        );
                        result
                    })();
                    for candidate in candidates.into_iter().flatten() {
                        session.recycle_table_candidate(candidate);
                    }
                    session
                        .select_process_for_return_validation(caller_process)
                        .unwrap_or_else(|error| {
                            panic!("primordial map caller-root restoration failed: {error:?}")
                        });
                    result
                }
            };
            result
        })();
        match result {
            Ok(address) => (DW_STATUS_SUCCESS, shootdown, Some(address)),
            Err(status) => (status, shootdown, None),
        }
    }

    // Out of line (D1 option B2): its held releases stay out of the
    // ordinary handler's measured frame.
    #[inline(never)]
    fn unmap_memory(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        address: deepwyrm_abi::DwUserAddress,
        byte_len: u64,
        held: &mut crate::syscall::HeldReleases<REGISTRY_OBJECTS>,
    ) -> (deepwyrm_abi::DwStatus, Option<FamilyGShootdown>) {
        let prepared = match crate::syscall::prepare_address_region_mutation(
            &mut self.core.registry,
            &self.core.tasks,
            &self.core.regions,
            self.own.scheduled().process,
            address_region,
            deepwyrm_abi::DW_RIGHT_MODIFY,
            &mut self.core.cleanup,
        ) {
            Ok(target) => target,
            Err(status) => return (status, None),
        };
        let target = prepared.target();
        let caller_process = self.own.scheduled().process;
        let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
        let mut paging = self.paging.lock();
        let mut session = paging.page_table_mutation_session(
            self.own.active_root.as_ref().expect("active root"),
            self.own.scheduled().process,
        );
        if session
            .select_process_for_return_validation(target.process)
            .is_err()
        {
            return (DW_STATUS_BAD_STATE, None);
        }
        let (status, shootdown) = {
            let mut driver = user_access::LiveTlbShootdownDriver::current();
            // S, beneath P, before the publisher's prepare_mutation (D1 option B1).
            let initiator = PRIMORDIAL_SHOOTDOWN_INITIATOR.acquire_beneath(&session);
            let (mut publisher, coherency) = session
                .publisher_with_coherency::<PRIMORDIAL_TABLE_CANDIDATES>(
                    target.address_space,
                    target.region_key,
                    &mut candidates,
                )
                .unwrap_or_else(|_| panic!("primordial unmap publisher unavailable"));
            // SAFETY: as for `map_memory`: the coherency domain lives in its stationary root
            // binding until this shootdown's permit, which S, held until then, protects.
            let mut publisher = unsafe {
                crate::memory::address_region::CoherentAddressSpacePublisher::<
                    _,
                    _,
                    { crate::cpu::CPU_CAPACITY },
                    { user_access::LIVE_SHOOTDOWN_WAIT_STEPS },
                >::new_deferred(&mut publisher, coherency, &mut driver)
            };
            let status = crate::syscall::address_region_unmap_prepared(
                prepared,
                &mut publisher,
                &mut self.core.registry,
                &mut self.core.memory,
                &mut self.core.tasks,
                &mut self.core.regions,
                self.own.scheduled().process,
                address_region,
                address,
                byte_len,
                held,
            );
            let published = publisher.finish_deferred();
            let shootdown = Self::settle_or_defer_shootdown(
                published,
                initiator,
                driver,
                held,
                &mut self.core.cleanup,
            );
            (status, shootdown)
        };
        for candidate in candidates.into_iter().flatten() {
            session.recycle_table_candidate(candidate);
        }
        session
            .select_process_for_return_validation(caller_process)
            .unwrap_or_else(|error| {
                panic!("primordial unmap caller-root restoration failed: {error:?}")
            });
        (status, shootdown)
    }

    // Out of line (D1 option B2): its held releases stay out of the
    // ordinary handler's measured frame.
    #[inline(never)]
    fn protect_memory(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        address: deepwyrm_abi::DwUserAddress,
        byte_len: u64,
        protections: u32,
        held: &mut crate::syscall::HeldReleases<REGISTRY_OBJECTS>,
    ) -> (deepwyrm_abi::DwStatus, Option<FamilyGShootdown>) {
        let prepared = match crate::syscall::prepare_address_region_mutation(
            &mut self.core.registry,
            &self.core.tasks,
            &self.core.regions,
            self.own.scheduled().process,
            address_region,
            deepwyrm_abi::DW_RIGHT_MODIFY,
            &mut self.core.cleanup,
        ) {
            Ok(target) => target,
            Err(status) => return (status, None),
        };
        let target = prepared.target();
        let caller_process = self.own.scheduled().process;
        let mut candidates = [const { None }; PRIMORDIAL_TABLE_CANDIDATES];
        let mut paging = self.paging.lock();
        let mut session = paging.page_table_mutation_session(
            self.own.active_root.as_ref().expect("active root"),
            self.own.scheduled().process,
        );
        if session
            .select_process_for_return_validation(target.process)
            .is_err()
        {
            return (DW_STATUS_BAD_STATE, None);
        }
        let (status, shootdown) = {
            let mut driver = user_access::LiveTlbShootdownDriver::current();
            // S, beneath P, before the publisher's prepare_mutation (D1 option B1).
            let initiator = PRIMORDIAL_SHOOTDOWN_INITIATOR.acquire_beneath(&session);
            let (mut publisher, coherency) = session
                .publisher_with_coherency::<PRIMORDIAL_TABLE_CANDIDATES>(
                    target.address_space,
                    target.region_key,
                    &mut candidates,
                )
                .unwrap_or_else(|_| panic!("primordial protect publisher unavailable"));
            // SAFETY: as for `map_memory`: the coherency domain lives in its stationary root
            // binding until this shootdown's permit, which S, held until then, protects.
            let mut publisher = unsafe {
                crate::memory::address_region::CoherentAddressSpacePublisher::<
                    _,
                    _,
                    { crate::cpu::CPU_CAPACITY },
                    { user_access::LIVE_SHOOTDOWN_WAIT_STEPS },
                >::new_deferred(&mut publisher, coherency, &mut driver)
            };
            let status = crate::syscall::address_region_protect_prepared(
                prepared,
                &mut publisher,
                &mut self.core.registry,
                &mut self.core.memory,
                &mut self.core.tasks,
                &mut self.core.regions,
                self.own.scheduled().process,
                address_region,
                address,
                byte_len,
                protections,
                held,
            );
            let published = publisher.finish_deferred();
            let shootdown = Self::settle_or_defer_shootdown(
                published,
                initiator,
                driver,
                held,
                &mut self.core.cleanup,
            );
            (status, shootdown)
        };
        for candidate in candidates.into_iter().flatten() {
            session.recycle_table_candidate(candidate);
        }
        session
            .select_process_for_return_validation(caller_process)
            .unwrap_or_else(|error| {
                panic!("primordial protect caller-root restoration failed: {error:?}")
            });
        (status, shootdown)
    }

    fn exit_process(&mut self, exit_code: u32) -> NativeSyscallResult {
        let phase = self.reserve_runtime_phase();
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    *discarded
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process-exit terminal output batch overflow") = Some(output);
                },
                |pin| {
                    *atomic_pins
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process-exit terminal atomic-pin batch overflow") = Some(pin);
                },
            );
            crate::syscall::process_exit_on(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.owned.owner.cpu(),
                self.own.scheduled().process,
                self.own.scheduled().thread,
                exit_code,
                &mut self.core.cleanup,
            )
        };
        if status == DW_STATUS_SUCCESS && control == SyscallControl::TerminateCurrent {
            self.install_deferred_current(
                deferred.unwrap_or_else(|| panic!("primordial exit omitted deferred reclaim")),
            );
        } else {
            assert!(deferred.is_none());
        }
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("primordial exit output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("primordial exit atomic pin drifted"));
        }
        self.absorb_service_cleanup();
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    /// `ThreadExit` (design §11.2.11), in this one hold: only the caller
    /// becomes terminal, so no remote Stop is ever published. It reads no
    /// user memory; terminal pins settle on a narrow session.
    fn exit_thread(&mut self, exit_code: u32) -> NativeSyscallResult {
        let phase = self.reserve_runtime_phase();
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; 1] = [None];
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; 1] = [None];
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded[0].replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pins[0].replace(pin).is_none());
                },
            );
            crate::syscall::thread_exit_on(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.owned.owner.cpu(),
                self.own.scheduled().process,
                self.own.scheduled().thread,
                exit_code,
                &mut self.core.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn prepare_remote_process_exit(&mut self, exit_code: u32) -> ProcessTerminationPreparation {
        let inspected_threads = crate::syscall::inspect_process_exit_threads(
            &self.core.tasks,
            self.own.scheduled().process,
        )
        .unwrap_or_else(|_| panic!("exiting Process lost its Thread topology"));
        let plan = match self.terminal_stop_plan(&inspected_threads) {
            Ok(plan) => plan,
            Err(()) => return ProcessTerminationPreparation::Retry,
        };
        let phase = self.reserve_runtime_phase();
        let mut prepared = match self.prepare_process_exit_with_wait_cleanup(exit_code) {
            Ok(prepared) => prepared,
            Err(status) => {
                self.commit_runtime_phase(phase);
                return ProcessTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    status,
                ));
            }
        };
        assert_eq!(
            prepared.thread_keys(),
            inspected_threads,
            "ProcessExit terminal Thread set changed under runtime authority"
        );
        for thread in self
            .retire_unentered_terminal_replacements(plan.unentered)
            .into_iter()
            .flatten()
        {
            prepared.record_pre_retired(thread);
        }
        let identities = plan.identities;
        self.assert_terminal_stop_plan_unchanged(&inspected_threads, &identities);
        if identities.iter().all(Option::is_none) {
            return ProcessTerminationPreparation::Immediate(self.complete_process_termination(
                phase,
                prepared,
                core::array::from_fn(|_| None),
            ));
        }
        ProcessTerminationPreparation::Remote(PreparedRemoteProcessTermination {
            phase,
            prepared,
            identities,
        })
    }

    fn prepare_process_exit_with_wait_cleanup(
        &mut self,
        exit_code: u32,
    ) -> Result<crate::syscall::PreparedProcessTermination<THREADS>, deepwyrm_abi::DwStatus> {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    *discarded
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process-exit output batch overflow") = Some(output);
                },
                |pin| {
                    *atomic_pins
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process-exit atomic-pin batch overflow") = Some(pin);
                },
            );
            crate::syscall::prepare_process_exit(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.own.scheduled().process,
                self.own.scheduled().thread,
                exit_code,
                &mut self.core.cleanup,
            )
        };
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("process-exit output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("process-exit atomic pin drifted"));
        }
        self.absorb_service_cleanup();
        result
    }

    fn terminate_process_handle(
        &mut self,
        process: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
        code: u32,
    ) -> NativeSyscallResult {
        let phase = self.reserve_runtime_phase();
        let prepared =
            match self.prepare_process_termination_with_wait_cleanup(process, reason, code) {
                Ok(prepared) => prepared,
                Err(status) => {
                    let result = NativeSyscallResult::returning(status);
                    self.commit_runtime_phase(phase);
                    return result;
                }
            };
        self.complete_process_termination(phase, prepared, core::array::from_fn(|_| None))
    }

    fn prepare_remote_process_termination(
        &mut self,
        process: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
        code: u32,
    ) -> ProcessTerminationPreparation {
        let inspected_threads = match crate::syscall::inspect_process_termination_threads(
            &self.core.tasks,
            &self.core.shared.execution,
            self.own.scheduled().process,
            self.own.scheduled().thread,
            process,
            reason,
        ) {
            Ok(threads) => threads,
            Err(status) => {
                return ProcessTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    status,
                ));
            }
        };
        let plan = match self.terminal_stop_plan(&inspected_threads) {
            Ok(plan) => plan,
            Err(()) => {
                // A scheduler claim can name the next logical continuation
                // while its CPU still runs a prior rendezvous reaper under a
                // Kernel root. The ordinary retry boundary releases runtime
                // authority so that handoff can finish before we re-resolve
                // and reauthenticate the complete terminal operation.
                return ProcessTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    DW_STATUS_WOULD_BLOCK,
                ));
            }
        };
        let phase = self.reserve_runtime_phase();
        let mut prepared =
            match self.prepare_process_termination_with_wait_cleanup(process, reason, code) {
                Ok(prepared) => prepared,
                Err(status) => {
                    self.commit_runtime_phase(phase);
                    return ProcessTerminationPreparation::Immediate(
                        NativeSyscallResult::returning(status),
                    );
                }
            };
        assert_eq!(
            prepared.thread_keys(),
            inspected_threads,
            "Process terminal Thread set changed under runtime authority"
        );
        for thread in self
            .retire_unentered_terminal_replacements(plan.unentered)
            .into_iter()
            .flatten()
        {
            prepared.record_pre_retired(thread);
        }
        let identities = plan.identities;
        self.assert_terminal_stop_plan_unchanged(&inspected_threads, &identities);
        if identities.iter().all(Option::is_none) {
            return ProcessTerminationPreparation::Immediate(self.complete_process_termination(
                phase,
                prepared,
                core::array::from_fn(|_| None),
            ));
        }
        ProcessTerminationPreparation::Remote(PreparedRemoteProcessTermination {
            phase,
            prepared,
            identities,
        })
    }

    /// Classifies every remote scheduler claim against the carrier state that
    /// can actually accept an exact e1 Stop. A Running claim alone is only a
    /// logical scheduler choice: until the same Thread owns the physical
    /// carrier under a stable Process root, terminal preparation must retry
    /// without mutating task state.
    fn terminal_stop_plan<const TERMINAL_THREADS: usize>(
        &self,
        terminal_threads: &[Option<ThreadKey>; TERMINAL_THREADS],
    ) -> Result<TerminalStopPlan, ()> {
        let mut identities = core::array::from_fn(|_| None);
        let mut unentered = core::array::from_fn(|_| None);
        for (cpu_index, identity) in identities.iter_mut().enumerate() {
            let cpu = crate::cpu::CpuIndex::new(cpu_index)
                .unwrap_or_else(|| panic!("remote-stop CPU index is out of range"));
            if cpu == self.cpu() {
                continue;
            }
            let remote = self
                .others
                .get(cpu)
                .unwrap_or_else(|| panic!("remote-stop CPU has no runtime slot"));
            let suspended = self
                .core
                .shared
                .execution
                .suspended_claim_on(cpu)
                .filter(|claim| terminal_threads.contains(&Some(claim.thread())));
            let running = self
                .core
                .shared
                .execution
                .running_claim_on(cpu)
                .filter(|claim| terminal_threads.contains(&Some(claim.thread())));
            let claim = match (suspended, running) {
                (None, None) => continue,
                (Some(claim), None) | (None, Some(claim)) => claim,
                (Some(physical), Some(logical)) => {
                    // A committed switch can expose the old suspended carrier
                    // and its not-yet-entered logical replacement at once. The
                    // e1 request authenticates only the physical generation;
                    // successful terminal preparation retires the replacement
                    // transactionally before publishing that Stop.
                    if physical.thread() == logical.thread()
                        || remote.last_scheduled.map(|identity| identity.thread)
                            != Some(physical.thread())
                    {
                        return Err(());
                    }
                    unentered[cpu_index] = Some(logical);
                    physical
                }
            };
            if remote.root_switch_flight.is_some()
                || remote.last_scheduled.map(|identity| identity.thread) != Some(claim.thread())
            {
                return Err(());
            }
            let Some(root) = remote.active_root.as_ref() else {
                return Err(());
            };
            let owner = self
                .core
                .tasks
                .thread_process(claim.thread())
                .unwrap_or_else(|_| panic!("terminal Thread lost its Process owner"));
            if root.process() != owner {
                return Err(());
            }
            let snapshot = crate::arch::x86_64::smp::live_cpu_registry()
                .snapshot(cpu_index)
                .unwrap_or_else(|_| panic!("remote terminal owner is not online"));
            *identity = Some(
                root.stop_identity(snapshot.online_generation, claim)
                    .unwrap_or_else(|_| panic!("remote terminal identity is inconsistent")),
            );
        }
        Ok(TerminalStopPlan {
            identities,
            unentered,
        })
    }

    fn retire_unentered_terminal_replacements(
        &mut self,
        replacements: [Option<crate::task::SchedulerExecutionClaim>;
            crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    ) -> [Option<ThreadKey>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] {
        let mut retired = core::array::from_fn(|_| None);
        for (cpu_index, replacement) in replacements.into_iter().enumerate() {
            let Some(replacement) = replacement else {
                continue;
            };
            assert_eq!(
                replacement.cpu().index(),
                cpu_index,
                "terminal logical replacement changed CPU"
            );
            let cancelled_quantum = self
                .core
                .shared
                .execution
                .retire_unentered_running_claim_on(replacement)
                .unwrap_or_else(|error| {
                    panic!("terminal logical replacement drifted after preparation: {error:?}")
                });
            self.stage_remote_scheduler_quantum_cancellation(replacement.cpu(), cancelled_quantum);
            retired[cpu_index] = Some(replacement.thread());
        }
        retired
    }

    fn assert_terminal_stop_plan_unchanged<const TERMINAL_THREADS: usize>(
        &self,
        terminal_threads: &[Option<ThreadKey>; TERMINAL_THREADS],
        expected: &[Option<crate::arch::x86_64::rendezvous::StopIdentity>;
             crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    ) {
        let observed = self
            .terminal_stop_plan(terminal_threads)
            .unwrap_or_else(|()| panic!("terminal carrier plan changed during preparation"));
        assert_eq!(
            &observed.identities, expected,
            "terminal Stop identity changed during preparation"
        );
        assert!(
            observed.unentered.into_iter().all(|claim| claim.is_none()),
            "terminal logical replacement survived prepared retirement"
        );
    }

    fn prepare_process_termination_with_wait_cleanup(
        &mut self,
        process: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
        code: u32,
    ) -> Result<crate::syscall::PreparedProcessTermination<THREADS>, deepwyrm_abi::DwStatus> {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    *discarded
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process termination output batch overflow") = Some(output);
                },
                |pin| {
                    *atomic_pins
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process termination atomic-pin batch overflow") = Some(pin);
                },
            );
            crate::syscall::prepare_process_terminate(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.own.scheduled().process,
                self.own.scheduled().thread,
                process,
                reason,
                code,
                &mut self.core.cleanup,
            )
        };
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("process termination output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("process termination atomic pin drifted"));
        }
        self.absorb_service_cleanup();
        result
    }

    fn prepare_remote_task_group_termination(
        &mut self,
        task_group: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
    ) -> TaskGroupTerminationPreparation {
        let inspected_threads = match crate::syscall::inspect_task_group_termination_threads(
            &self.core.tasks,
            &self.core.shared.execution,
            self.own.scheduled().process,
            self.own.scheduled().thread,
            task_group,
            reason,
        ) {
            Ok(threads) => threads,
            Err(status) => {
                return TaskGroupTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    status,
                ));
            }
        };
        let plan = match self.terminal_stop_plan(&inspected_threads) {
            Ok(plan) => plan,
            Err(()) => {
                return TaskGroupTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    DW_STATUS_WOULD_BLOCK,
                ));
            }
        };
        let phase = self.reserve_runtime_phase();
        let mut prepared =
            match self.prepare_task_group_termination_with_wait_cleanup(task_group, reason) {
                Ok(prepared) => prepared,
                Err(status) => {
                    self.commit_runtime_phase(phase);
                    return TaskGroupTerminationPreparation::Immediate(
                        NativeSyscallResult::returning(status),
                    );
                }
            };
        assert_eq!(
            prepared.thread_keys(),
            inspected_threads,
            "TaskGroup terminal Thread set changed under runtime authority"
        );
        for thread in self
            .retire_unentered_terminal_replacements(plan.unentered)
            .into_iter()
            .flatten()
        {
            prepared.record_pre_retired(thread);
        }
        let identities = plan.identities;
        self.assert_terminal_stop_plan_unchanged(&inspected_threads, &identities);
        if identities.iter().all(Option::is_none) {
            return TaskGroupTerminationPreparation::Immediate(
                self.complete_task_group_termination(
                    phase,
                    prepared,
                    core::array::from_fn(|_| None),
                ),
            );
        }
        TaskGroupTerminationPreparation::Remote(PreparedRemoteTaskGroupTermination {
            phase,
            prepared,
            identities,
        })
    }

    fn prepare_task_group_termination_with_wait_cleanup(
        &mut self,
        task_group: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
    ) -> Result<
        crate::syscall::PreparedTaskGroupTermination<PROCESSES, THREADS>,
        deepwyrm_abi::DwStatus,
    > {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    *discarded
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("TaskGroup termination output batch overflow") = Some(output);
                },
                |pin| {
                    *atomic_pins
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("TaskGroup termination atomic-pin batch overflow") = Some(pin);
                },
            );
            crate::syscall::prepare_task_group_terminate(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.own.scheduled().process,
                self.own.scheduled().thread,
                task_group,
                reason,
                &mut self.core.cleanup,
            )
        };
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("TaskGroup termination output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("TaskGroup termination atomic pin drifted"));
        }
        self.absorb_service_cleanup();
        result
    }

    fn complete_task_group_termination(
        &mut self,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        prepared: crate::syscall::PreparedTaskGroupTermination<PROCESSES, THREADS>,
        permits: [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
            crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    ) -> NativeSyscallResult {
        let process_keys = prepared.process_keys();
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    *discarded
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("TaskGroup completion output batch overflow") = Some(output);
                },
                |pin| {
                    *atomic_pins
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("TaskGroup completion atomic-pin batch overflow") = Some(pin);
                },
            );
            crate::syscall::complete_prepared_task_group_termination_after_remote_stops_on(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.owned.owner.cpu(),
                self.own.scheduled().process,
                self.own.scheduled().thread,
                prepared,
                permits,
                &mut self.core.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        if status == DW_STATUS_SUCCESS {
            for target in process_keys.into_iter().flatten() {
                if target == self.own.scheduled().process {
                    continue;
                }
                // Design §11.2.12 rule 3: an exited sibling's CPU may still be
                // resident on the root; it then tears down when it leaves.
                let _ = self.attempt_exited_root_teardown(target);
            }
        }
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn complete_process_termination(
        &mut self,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        prepared: crate::syscall::PreparedProcessTermination<THREADS>,
        permits: [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
            crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    ) -> NativeSyscallResult {
        let target = prepared.target();
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    *discarded
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process completion output batch overflow") = Some(output);
                },
                |pin| {
                    *atomic_pins
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .expect("process completion atomic-pin batch overflow") = Some(pin);
                },
            );
            crate::syscall::complete_prepared_process_termination_after_remote_stops_on(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.owned.owner.cpu(),
                self.own.scheduled().process,
                self.own.scheduled().thread,
                prepared,
                permits,
                &mut self.core.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        if status == DW_STATUS_SUCCESS && control == SyscallControl::ReturnToCaller {
            if target != self.own.scheduled().process {
                // Design §11.2.12 rule 3: an exited sibling's CPU may still be
                // resident on the root; it then tears down when it leaves.
                let _ = self.attempt_exited_root_teardown(target);
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
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; 1] = [None];
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; 1] = [None];
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| discarded[0] = Some(output),
                |pin| atomic_pins[0] = Some(pin),
            );
            crate::syscall::thread_terminate(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.own.scheduled().process,
                self.own.scheduled().thread,
                thread,
                reason,
                code,
                &mut self.core.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn prepare_remote_thread_termination(
        &mut self,
        thread: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
        code: u32,
    ) -> ThreadTerminationPreparation {
        let inspected_threads = match crate::syscall::inspect_thread_termination_threads(
            &self.core.tasks,
            &self.core.shared.execution,
            self.own.scheduled().process,
            self.own.scheduled().thread,
            thread,
            reason,
        ) {
            Ok(threads) => threads,
            Err(status) => {
                return ThreadTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    status,
                ));
            }
        };
        let plan = match self.terminal_stop_plan(&inspected_threads) {
            Ok(plan) => plan,
            Err(()) => {
                return ThreadTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    DW_STATUS_WOULD_BLOCK,
                ));
            }
        };
        let phase = self.reserve_runtime_phase();
        let mut prepared =
            match self.prepare_thread_termination_with_wait_cleanup(thread, reason, code) {
                Ok(prepared) => prepared,
                Err(status) => {
                    self.commit_runtime_phase(phase);
                    return ThreadTerminationPreparation::Immediate(
                        NativeSyscallResult::returning(status),
                    );
                }
            };
        assert_eq!(
            prepared.thread_keys(),
            inspected_threads,
            "Thread terminal set changed under runtime authority"
        );
        for retired in self
            .retire_unentered_terminal_replacements(plan.unentered)
            .into_iter()
            .flatten()
        {
            prepared.record_pre_retired(retired);
        }
        let identities = plan.identities;
        self.assert_terminal_stop_plan_unchanged(&inspected_threads, &identities);
        if identities.iter().all(Option::is_none) {
            return ThreadTerminationPreparation::Immediate(self.complete_thread_termination(
                phase,
                prepared,
                core::array::from_fn(|_| None),
            ));
        }
        ThreadTerminationPreparation::Remote(PreparedRemoteThreadTermination {
            phase,
            prepared,
            identities,
        })
    }

    fn prepare_thread_termination_with_wait_cleanup(
        &mut self,
        thread: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
        code: u32,
    ) -> Result<crate::syscall::PreparedThreadTermination<THREADS>, deepwyrm_abi::DwStatus> {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; 1] = [None];
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; 1] = [None];
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded[0].replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pins[0].replace(pin).is_none());
                },
            );
            crate::syscall::prepare_thread_terminate(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.own.scheduled().process,
                self.own.scheduled().thread,
                thread,
                reason,
                code,
                &mut self.core.cleanup,
            )
        };
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("Thread termination output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("Thread termination atomic pin drifted"));
        }
        self.absorb_service_cleanup();
        result
    }

    fn complete_thread_termination(
        &mut self,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        prepared: crate::syscall::PreparedThreadTermination<THREADS>,
        permits: [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
            crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    ) -> NativeSyscallResult {
        let exited_process = prepared.exited_process();
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; 1] = [None];
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; 1] = [None];
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.core.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded[0].replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pins[0].replace(pin).is_none());
                },
            );
            crate::syscall::complete_prepared_thread_termination_after_remote_stops_on(
                &mut self.core.registry,
                &mut self.core.tasks,
                &self.core.shared.execution,
                &self.core.shared.waits,
                &mut terminal,
                self.owned.owner.cpu(),
                self.own.scheduled().process,
                self.own.scheduled().thread,
                prepared,
                permits,
                &mut self.core.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        if status == DW_STATUS_SUCCESS && control == SyscallControl::ReturnToCaller {
            if let Some(target) =
                exited_process.filter(|target| *target != self.own.scheduled().process)
            {
                // Design §11.2.12 rule 3: an exited sibling's CPU may still be
                // resident on the root; it then tears down when it leaves.
                let _ = self.attempt_exited_root_teardown(target);
            }
        }
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn finish_terminal_adapter_resources<const TERMINAL_RESOURCES: usize>(
        &mut self,
        discarded: [Option<user_access::OwnedLiveUserOutput>; TERMINAL_RESOURCES],
        atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; TERMINAL_RESOURCES],
        control: SyscallControl,
        deferred: Option<crate::task::DeferredCurrentExecutionResources>,
    ) {
        if control == SyscallControl::TerminateCurrent {
            self.install_deferred_current(
                deferred.unwrap_or_else(|| panic!("terminal adapter omitted deferred reclaim")),
            );
        } else {
            assert!(deferred.is_none());
        }
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("terminal adapter output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.paging.lock().user_pins)
                .unwrap_or_else(|_| panic!("terminal adapter atomic pin drifted"));
        }
        self.absorb_service_cleanup();
    }
}

/// A MemoryObjectCreate backing taken before the runtime hold: an eager
/// one still to be zeroed in steps, or an on-demand index root, ready.
enum EarlyBacking {
    Unzeroed(crate::memory::frame_roles::BackingAllocation),
    Ready(crate::memory::frame_roles::ObjectBackingGrant),
}

/// A return validator that also admits an absent leaf where the Process maps
/// an on-demand page with the protection the return needs (DW2 M6 §8.5,
/// review D6). The return then faults, and the fault gate serves it or ends
/// the Process with the fault's own cause. It reads only: nothing is
/// committed here.
struct OnDemandReturn<'v, M> {
    inner: &'v mut M,
    /// Whether `(process, address, execute)` is such a page.
    demand: &'v dyn Fn(ProcessKey, u64, bool) -> bool,
}

impl<M: crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation>
    crate::arch::x86_64::syscall::UserReturnMappingValidation for OnDemandReturn<'_, M>
{
    fn executable_at(&mut self, address: u64) -> bool {
        self.inner.executable_at(address) || (self.demand)(self.inner.process_key(), address, true)
    }

    fn writable_byte_below(&mut self, stack_pointer: u64) -> bool {
        self.inner.writable_byte_below(stack_pointer)
            || stack_pointer
                .checked_sub(1)
                .is_some_and(|address| (self.demand)(self.inner.process_key(), address, false))
    }
}

impl<M: crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation>
    crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation for OnDemandReturn<'_, M>
{
    fn process_key(&self) -> ProcessKey {
        self.inner.process_key()
    }
}

impl<M: crate::syscall::ThreadStartRetarget> crate::syscall::ThreadStartRetarget
    for OnDemandReturn<'_, M>
{
    fn retarget_for_thread_start(
        &mut self,
        process: ProcessKey,
    ) -> Result<(), deepwyrm_abi::DwStatus> {
        self.inner.retarget_for_thread_start(process)
    }
}
