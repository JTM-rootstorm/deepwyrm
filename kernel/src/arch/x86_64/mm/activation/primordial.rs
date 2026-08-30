//! Production DW0-G primordial process composition over the live x86_64 root.

#![allow(
    unsafe_code,
    reason = "the G3 live runtime owns bounded static publication, physical backing initialization, and the audited CPL3 transition"
)]

use super::*;

#[cfg(any(
    deepwyrm_wyr1_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_wyr1c_evidence
))]
use super::primordial_diagnostic::primordial_terminal_summary;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::boot::primordial::construction::authority::{
    AuthorityPrimordialBackend, AuthorityPrimordialMonitor, PrimordialPlatform,
};
#[cfg(not(any(deepwyrm_dw1d_evidence, deepwyrm_wyr1c_evidence)))]
use crate::boot::primordial::construction::complete_primordial_launch;
#[cfg(any(deepwyrm_dw1d_evidence, deepwyrm_wyr1c_evidence))]
use crate::boot::primordial::construction::complete_resource_primordial_launch;
#[cfg(any(deepwyrm_wyr1_evidence, deepwyrm_wyr1b_evidence))]
use crate::boot::primordial::construction::validate_primordial_retirement_facts;
#[cfg(deepwyrm_wyr1c_evidence)]
use crate::boot::primordial::construction::validate_resource_primordial_retirement_facts as validate_primordial_retirement_facts;
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
    NativeSyscallFrameRuntime, NativeSyscallHandler, NativeSyscallRequest, NativeSyscallResult,
    SyscallControl,
};
use crate::syscall::{
    CleanupQueue, FServiceRoute, FServiceState, NativeWaitControl, TerminalWaitCleanup,
};
#[cfg(any(
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_wyr1c_evidence,
    deepwyrm_dw1d_evidence
))]
use crate::task::ProcessLifecycleState;
use crate::task::{ExecutionDomain, ProcessKey, SchedulerThreadState, TaskAuthority, ThreadKey};
use crate::time::TimerAuthority;
use crate::wait::{EventAuthority, WaitRegistry};
use deepwyrm_abi::{
    DW_CHANNEL_MAX_PAYLOAD, DW_EXCEPTION_GENERAL_PROTECTION, DW_STATUS_BAD_STATE,
    DW_STATUS_NO_RESOURCES, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS, DW_STATUS_WOULD_BLOCK,
    DW_TASK_STATE_EXITED, DW_TERMINATION_NORMAL_EXIT,
};

const MAX_BOOTFS_BYTES: usize = 32 * 1024 * 1024;
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_wyr1c_evidence
)))]
const REGISTRY_OBJECTS: usize = 32;
#[cfg(deepwyrm_dw1c_evidence)]
const REGISTRY_OBJECTS: usize = 256;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const REGISTRY_OBJECTS: usize = 64;
// Selector 24 adds one bounded child-loader object set plus the controller's
// MemoryObject, Channel, Event, and Timer probes without taking I2's larger
// multi-process stress budget.
#[cfg(deepwyrm_wrcap_relay)]
const REGISTRY_OBJECTS: usize = 48;
// Selector 25's exact concurrent graph is primordial + init + two early
// roles.  Relative to the 32-object three-Process baseline, the fourth loader
// set contributes Process/root/Thread, three image MemoryObjects, and one
// Channel pair; three attempt TaskGroups and one control Timer keep the
// measured peak below this 48-object bound.
#[cfg(deepwyrm_wyr1_evidence)]
const REGISTRY_OBJECTS: usize = 48;
#[cfg(deepwyrm_dw1b_evidence)]
const REGISTRY_OBJECTS: usize = 64;
#[cfg(deepwyrm_wyr1b_evidence)]
const REGISTRY_OBJECTS: usize = 160;
#[cfg(deepwyrm_wyr1c_evidence)]
const REGISTRY_OBJECTS: usize = 160;
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_wyr1c_evidence
)))]
const MEMORY_OBJECTS: usize = 10;
#[cfg(deepwyrm_dw1c_evidence)]
const MEMORY_OBJECTS: usize = 40;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const MEMORY_OBJECTS: usize = 24;
// The selector-24 baseline owns eight bootfs/bootstrap/init0/controller
// objects. A worker adds two ELF segments plus its stack; the shared-memory
// case keeps one controller-owned probe object live at the same time.
#[cfg(deepwyrm_wrcap_relay)]
const MEMORY_OBJECTS: usize = 12;
// Four live images need the baseline bootfs plus three segments/stack objects
// per descendant: 10 for three Processes plus one three-object role image.
#[cfg(deepwyrm_wyr1_evidence)]
const MEMORY_OBJECTS: usize = 13;
#[cfg(deepwyrm_dw1b_evidence)]
const MEMORY_OBJECTS: usize = 16;
#[cfg(deepwyrm_wyr1b_evidence)]
const MEMORY_OBJECTS: usize = 28;
#[cfg(deepwyrm_wyr1c_evidence)]
const MEMORY_OBJECTS: usize = 28;
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_wyr1c_evidence
)))]
const MEMORY_LEASES: usize = 10;
#[cfg(deepwyrm_dw1c_evidence)]
const MEMORY_LEASES: usize = 40;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const MEMORY_LEASES: usize = 24;
// The shared-memory peak maps all twelve live objects and maps the probe once
// more into the worker, so it needs one additional mapping lease.
#[cfg(deepwyrm_wrcap_relay)]
const MEMORY_LEASES: usize = 13;
#[cfg(deepwyrm_wyr1_evidence)]
const MEMORY_LEASES: usize = 13;
#[cfg(deepwyrm_dw1b_evidence)]
const MEMORY_LEASES: usize = 16;
#[cfg(deepwyrm_wyr1b_evidence)]
const MEMORY_LEASES: usize = 28;
#[cfg(deepwyrm_wyr1c_evidence)]
const MEMORY_LEASES: usize = 28;
// I0 keeps the complete bootstrap -> init0 -> hello chain live while each
// parent performs bounded READY/exit supervision of its direct child. The
// selector-24 controller adds exactly one temporary supervised child.
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_wyr1c_evidence
)))]
const USERSPACE_CHAIN_PROCESSES: usize = 3;
// Selector 30 has three simultaneously live userspace Processes, but four
// lifetime-distinct generations: bootstrap, first owner, trigger, and the
// replacement owner.  The shared bounded geometry also sizes the scheduler's
// sticky terminal-retirement history, so it must retain all four identities.
#[cfg(deepwyrm_dw1d_evidence)]
const USERSPACE_CHAIN_PROCESSES: usize = 4;
// Primordial, controller, and the fixed ten workload actors.  This is test
// artifact geometry, not a production process limit.
#[cfg(deepwyrm_dw1c_evidence)]
const USERSPACE_CHAIN_PROCESSES: usize = 12;
#[cfg(deepwyrm_dw1c_evidence)]
const _: () = assert!(super::LIVE_ADDRESS_SPACE_CAPACITY >= USERSPACE_CHAIN_PROCESSES);
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const USERSPACE_CHAIN_PROCESSES: usize = 6;
#[cfg(deepwyrm_wrcap_relay)]
const USERSPACE_CHAIN_PROCESSES: usize = 4;
#[cfg(deepwyrm_wyr1_evidence)]
const USERSPACE_CHAIN_PROCESSES: usize = 4;
#[cfg(deepwyrm_dw1b_evidence)]
const USERSPACE_CHAIN_PROCESSES: usize = 5;
#[cfg(deepwyrm_wyr1b_evidence)]
const USERSPACE_CHAIN_PROCESSES: usize = 8;
#[cfg(deepwyrm_wyr1c_evidence)]
const USERSPACE_CHAIN_PROCESSES: usize = 8;
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_wyr1c_evidence
)))]
const CHANNEL_PAIRS: usize = USERSPACE_CHAIN_PROCESSES;
#[cfg(deepwyrm_dw1c_evidence)]
const CHANNEL_PAIRS: usize = 32;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const CHANNEL_PAIRS: usize = 8;
#[cfg(deepwyrm_wrcap_relay)]
const CHANNEL_PAIRS: usize = USERSPACE_CHAIN_PROCESSES;
#[cfg(deepwyrm_wyr1_evidence)]
const CHANNEL_PAIRS: usize = USERSPACE_CHAIN_PROCESSES;
#[cfg(deepwyrm_dw1b_evidence)]
const CHANNEL_PAIRS: usize = USERSPACE_CHAIN_PROCESSES;
#[cfg(deepwyrm_wyr1b_evidence)]
const CHANNEL_PAIRS: usize = 24;
#[cfg(deepwyrm_wyr1c_evidence)]
const CHANNEL_PAIRS: usize = 24;
const CHANNEL_DEPTH: usize = 2;
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_wyr1c_evidence
)))]
const WAITERS: usize = 4;
#[cfg(deepwyrm_dw1c_evidence)]
const WAITERS: usize = 24;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const WAITERS: usize = 12;
// Bootstrap supervises init0 and init0 supervises the controller while the
// controller supervises one worker. Each WAIT_ANY owns a Channel and Process
// registration, for an exact selector-24 peak of six.
#[cfg(deepwyrm_wrcap_relay)]
const WAITERS: usize = 6;
// Before primordial retires, its init READY wait overlaps init's one-at-a-time
// early-role READY wait: two registrations per WAIT_ANY, exact peak four.
#[cfg(deepwyrm_wyr1_evidence)]
const WAITERS: usize = 4;
#[cfg(deepwyrm_dw1b_evidence)]
const WAITERS: usize = 6;
#[cfg(deepwyrm_wyr1b_evidence)]
const WAITERS: usize = 16;
#[cfg(deepwyrm_wyr1c_evidence)]
const WAITERS: usize = 16;
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_wyr1c_evidence
)))]
const TASK_GROUPS: usize = 1;
#[cfg(deepwyrm_dw1c_evidence)]
const TASK_GROUPS: usize = 12;
// Root plus the exact boot-resource domain used by selector 30.
#[cfg(deepwyrm_dw1d_evidence)]
const TASK_GROUPS: usize = 2;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const TASK_GROUPS: usize = 4;
#[cfg(deepwyrm_wrcap_relay)]
const TASK_GROUPS: usize = 2;
// Root, init's delegated group, and one attempt group per two resident roles.
#[cfg(deepwyrm_wyr1_evidence)]
const TASK_GROUPS: usize = 4;
#[cfg(deepwyrm_dw1b_evidence)]
const TASK_GROUPS: usize = 1;
#[cfg(deepwyrm_wyr1b_evidence)]
const TASK_GROUPS: usize = 8;
#[cfg(deepwyrm_wyr1c_evidence)]
const TASK_GROUPS: usize = 8;
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
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_wyr1c_evidence
)))]
const HANDLES: usize = BOOTSTRAP_HANDLE_PEAK;
#[cfg(deepwyrm_dw1c_evidence)]
const HANDLES: usize = 64;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const HANDLES: usize = 16;
// Selector 24 retains the temporary child's TaskGroup handle while running the
// ordinary loader transaction, one above the ten-handle bootstrap peak.
#[cfg(deepwyrm_wrcap_relay)]
const HANDLES: usize = BOOTSTRAP_HANDLE_PEAK + 1;
// Init retains three supervision handles per resident role. While launching
// the second role, its four inherited handles + first role's three retained
// handles + the ordinary six-handle loader delta produce the exact peak 13.
#[cfg(deepwyrm_wyr1_evidence)]
const HANDLES: usize = BOOTSTRAP_HANDLE_PEAK + 3;
// Selector 30 receives the ordinary four bootstrap capabilities plus the
// boot-resource domain.  After the first owner exits, bootstrap retains the
// trigger's Process and launch Channel while the replacement owner loader
// holds its net Channel, Process+root, Thread, and resource-domain staging
// duplicate.  That exact replacement-launch peak is twelve handles.
#[cfg(deepwyrm_dw1d_evidence)]
const D6_INITIAL_HANDLES: usize = INITIAL_BOOTSTRAP_HANDLES + 1;
#[cfg(deepwyrm_dw1d_evidence)]
const D6_RETAINED_TRIGGER_HANDLES: usize = 2;
#[cfg(deepwyrm_dw1d_evidence)]
const D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES: usize = 1;
#[cfg(deepwyrm_dw1d_evidence)]
const D6_HANDLE_PEAK: usize = D6_INITIAL_HANDLES
    + D6_RETAINED_TRIGGER_HANDLES
    + CHANNEL_CREATE_REDUCE_NET_HANDLES
    + PROCESS_ROOT_HANDLES
    + THREAD_HANDLES
    + D6_RESOURCE_DOMAIN_DUPLICATE_HANDLES;
#[cfg(deepwyrm_dw1d_evidence)]
const HANDLES: usize = D6_HANDLE_PEAK;
#[cfg(deepwyrm_dw1b_evidence)]
const HANDLES: usize = 16;
#[cfg(deepwyrm_wyr1b_evidence)]
const HANDLES: usize = 32;
#[cfg(deepwyrm_wyr1c_evidence)]
const HANDLES: usize = 32;
const SPACES: usize = USERSPACE_CHAIN_PROCESSES;
const REGIONS: usize = USERSPACE_CHAIN_PROCESSES;
const REGION_OBJECTS: usize = USERSPACE_CHAIN_PROCESSES;
const REGION_SLOTS: usize = 10;
const EXECUTION_THREADS: usize = USERSPACE_CHAIN_PROCESSES;
#[cfg(not(deepwyrm_i2_stress))]
const EVENTS: usize = 1;
#[cfg(deepwyrm_i2_stress)]
const EVENTS: usize = 2;
#[cfg(not(deepwyrm_i2_stress))]
const TIMERS: usize = 1;
#[cfg(deepwyrm_i2_stress)]
const TIMERS: usize = 2;
// A bounded mapping can cross one boundary at each non-root level. Keep two
// candidates for PDPT, PD, and PT creation so the live publisher can construct
// both paths without depending on where the requested range lands. The I2
// bootfs needs a bounded 32-page window. The selector-24 WRCAP bootfs contains
// the controller plus its deterministic config and asset and is exactly 39
// pages after init0 termination-race reconciliation. The ordinary Wave 4
// bootfs is exactly 17 pages with its selector-specific init0 artifact.
const PRIMORDIAL_TABLE_CANDIDATES: usize = 6;
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_wyr1c_evidence
)))]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 17;
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 32;
#[cfg(deepwyrm_wrcap_relay)]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 39;
// Selector 25's accepted WYR1-A inputs were 170,496 and 169,896 bytes (42
// pages). The integrated WYR1-B regression inputs are 309,192 and 308,576
// bytes (76 pages), so the functional-first selector-local ceiling is 128
// pages. Deepwyrm owns this page ceiling and its rejection detail. Content
// hashes belong to receipt/root evidence recorded after the cross-repository
// source and media identities freeze; embedding them here would make the
// Deepwyrm revision recursively determine its own bootfs hash. This bound
// remains separate from the accepted WYR0 bounds and the 32 MiB loader intake.
#[cfg(deepwyrm_wyr1_evidence)]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 128;
#[cfg(deepwyrm_dw1b_evidence)]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_dw1b_bootfs_pages();
#[cfg(deepwyrm_wyr1b_evidence)]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_wyr1b_bootfs_pages();
#[cfg(deepwyrm_dw1c_evidence)]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_dw1c_bootfs_pages();
// Selector 29 consumes a frozen archive whose byte identity is recorded by
// Wyrmroot. Keep bounded functional headroom above selector 27 without
// widening the ordinary production profile or the 32 MiB loader intake.
#[cfg(deepwyrm_wyr1c_evidence)]
const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 256;
const PRIMORDIAL_STACK_MAPPING_PAGES: usize =
    crate::boot::primordial::construction::STACK_BYTES as usize / 4096;
const _: () = assert!(crate::boot::primordial::construction::STACK_BYTES % 4096 == 0);
// Mapping machinery must fit both the selector-local bootfs ceiling and the
// independently owned primordial stack without widening bootfs admission.
const PRIMORDIAL_MAX_MAPPING_PAGES: usize =
    if PRIMORDIAL_BOOTFS_MAX_PAGES > PRIMORDIAL_STACK_MAPPING_PAGES {
        PRIMORDIAL_BOOTFS_MAX_PAGES
    } else {
        PRIMORDIAL_STACK_MAPPING_PAGES
    };
const PRIMORDIAL_JOURNAL_ENTRIES: usize =
    PRIMORDIAL_MAX_MAPPING_PAGES + PRIMORDIAL_TABLE_CANDIDATES;
const PRIMORDIAL_INVALIDATIONS: usize = PRIMORDIAL_MAX_MAPPING_PAGES;

// The native binding table and kernel-wide CPU identity must describe the
// same bounded carrier set; a capacity drift is a compile-time error.
const _: [(); crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] = [(); crate::cpu::CPU_CAPACITY];
const _: [(); PROCESSES] = [(); THREADS];
#[cfg(all(
    not(deepwyrm_i2_stress),
    not(deepwyrm_wyr1b_evidence),
    not(deepwyrm_dw1c_evidence),
    not(deepwyrm_wyr1c_evidence)
))]
const _: [(); PROCESSES] = [(); CHANNEL_PAIRS];
const _: [(); PROCESSES] = [(); SPACES];
const _: [(); PROCESSES] = [(); REGIONS];
const _: [(); PROCESSES] = [(); REGION_OBJECTS];
const _: [(); PROCESSES] = [(); EXECUTION_THREADS];
#[cfg(not(any(
    deepwyrm_i2_stress,
    deepwyrm_wrcap_relay,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_wyr1c_evidence
)))]
const _: [(); 10] = [(); HANDLES];
#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]
const _: [(); 16] = [(); HANDLES];
#[cfg(deepwyrm_wrcap_relay)]
const _: [(); 11] = [(); HANDLES];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 13] = [(); HANDLES];
#[cfg(deepwyrm_dw1d_evidence)]
const _: [(); 12] = [(); HANDLES];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 4] = [(); USERSPACE_CHAIN_PROCESSES];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 4] = [(); CHANNEL_PAIRS];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 4] = [(); WAITERS];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 4] = [(); TASK_GROUPS];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 13] = [(); MEMORY_OBJECTS];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 13] = [(); MEMORY_LEASES];
#[cfg(deepwyrm_wyr1_evidence)]
const _: [(); 48] = [(); REGISTRY_OBJECTS];
#[cfg(deepwyrm_dw1b_evidence)]
const _: [(); 5] = [(); USERSPACE_CHAIN_PROCESSES];
#[cfg(deepwyrm_dw1b_evidence)]
const _: [(); 5] = [(); CHANNEL_PAIRS];
#[cfg(deepwyrm_dw1b_evidence)]
const _: [(); 16] = [(); HANDLES];
#[cfg(deepwyrm_dw1b_evidence)]
const _: [(); 16] = [(); MEMORY_OBJECTS];
#[cfg(deepwyrm_dw1b_evidence)]
const _: [(); 16] = [(); MEMORY_LEASES];
#[cfg(deepwyrm_dw1b_evidence)]
const _: [(); 64] = [(); REGISTRY_OBJECTS];
#[cfg(deepwyrm_wyr1b_evidence)]
const _: [(); 8] = [(); USERSPACE_CHAIN_PROCESSES];
#[cfg(deepwyrm_wyr1b_evidence)]
const _: [(); 24] = [(); CHANNEL_PAIRS];
#[cfg(deepwyrm_wyr1b_evidence)]
const _: [(); 32] = [(); HANDLES];
#[cfg(deepwyrm_wyr1b_evidence)]
const _: [(); 28] = [(); MEMORY_OBJECTS];
#[cfg(deepwyrm_wyr1b_evidence)]
const _: [(); 28] = [(); MEMORY_LEASES];
#[cfg(deepwyrm_wyr1b_evidence)]
const _: [(); 160] = [(); REGISTRY_OBJECTS];
#[cfg(deepwyrm_wyr1c_evidence)]
const _: [(); 8] = [(); USERSPACE_CHAIN_PROCESSES];
#[cfg(deepwyrm_wyr1c_evidence)]
const _: [(); 24] = [(); CHANNEL_PAIRS];
#[cfg(deepwyrm_wyr1c_evidence)]
const _: [(); 32] = [(); HANDLES];
#[cfg(deepwyrm_wyr1c_evidence)]
const _: [(); 28] = [(); MEMORY_OBJECTS];
#[cfg(deepwyrm_wyr1c_evidence)]
const _: [(); 28] = [(); MEMORY_LEASES];
#[cfg(deepwyrm_wyr1c_evidence)]
const _: [(); 160] = [(); REGISTRY_OBJECTS];
#[cfg(deepwyrm_dw1c_evidence)]
const _: [(); 12] = [(); USERSPACE_CHAIN_PROCESSES];
#[cfg(deepwyrm_dw1d_evidence)]
const _: [(); 4] = [(); USERSPACE_CHAIN_PROCESSES];
#[cfg(deepwyrm_dw1c_evidence)]
const _: [(); 32] = [(); CHANNEL_PAIRS];
#[cfg(deepwyrm_dw1c_evidence)]
const _: [(); 64] = [(); HANDLES];
#[cfg(deepwyrm_dw1c_evidence)]
const _: [(); 40] = [(); MEMORY_OBJECTS];
#[cfg(deepwyrm_dw1c_evidence)]
const _: [(); 40] = [(); MEMORY_LEASES];
#[cfg(deepwyrm_dw1c_evidence)]
const _: [(); 256] = [(); REGISTRY_OBJECTS];
const _: [(); 7] = [(); BOOTSTRAP_HANDLE_PEAK - INIT_MOVED_HANDLES];

#[cfg(deepwyrm_dw1b_evidence)]
const fn parse_dw1b_bootfs_pages() -> usize {
    let bytes = env!("DEEPWYRM_DW1B_BOOTFS_MAX_PAGES").as_bytes();
    let mut value = 0_usize;
    let mut index = 0;
    assert!(
        !bytes.is_empty(),
        "selector-26 bootfs page ceiling is empty"
    );
    while index < bytes.len() {
        assert!(
            bytes[index].is_ascii_digit(),
            "selector-26 bootfs page ceiling is not decimal"
        );
        value = value * 10 + (bytes[index] - b'0') as usize;
        index += 1;
    }
    assert!(
        value > 0 && value <= 8192,
        "selector-26 bootfs page ceiling is out of range"
    );
    value
}

#[cfg(deepwyrm_wyr1b_evidence)]
const fn parse_wyr1b_bootfs_pages() -> usize {
    let bytes = env!("DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES").as_bytes();
    let mut value = 0_usize;
    let mut index = 0;
    assert!(
        !bytes.is_empty(),
        "selector-27 bootfs page ceiling is empty"
    );
    while index < bytes.len() {
        assert!(
            bytes[index].is_ascii_digit(),
            "selector-27 bootfs page ceiling is not decimal"
        );
        value = value * 10 + (bytes[index] - b'0') as usize;
        index += 1;
    }
    assert!(
        value > 0 && value <= 8192,
        "selector-27 bootfs page ceiling is out of range"
    );
    value
}

#[cfg(deepwyrm_dw1c_evidence)]
const fn parse_dw1c_bootfs_pages() -> usize {
    let bytes = env!("DEEPWYRM_DW1C_BOOTFS_MAX_PAGES").as_bytes();
    let mut value = 0_usize;
    let mut index = 0;
    assert!(
        !bytes.is_empty(),
        "selector-28 bootfs page ceiling is empty"
    );
    while index < bytes.len() {
        assert!(
            bytes[index].is_ascii_digit(),
            "selector-28 bootfs page ceiling is not decimal"
        );
        value = value * 10 + (bytes[index] - b'0') as usize;
        index += 1;
    }
    assert!(
        value > 0 && value <= 8192,
        "selector-28 bootfs page ceiling is out of range"
    );
    value
}

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
    terminal_info: Option<deepwyrm_abi::DwTaskTerminationInfoV1>,
}

#[cfg(feature = "test-support")]
impl G5PrimordialProbe {
    fn for_build() -> Self {
        use crate::test_support::BuildGuestTest;

        let expectation = match crate::test_support::BUILD_GUEST_TEST {
            BuildGuestTest::PrimordialBootstrap => G5PrimordialExpectation::Baseline,
            BuildGuestTest::SmpRuntimeStress => G5PrimordialExpectation::Baseline,
            BuildGuestTest::SmpRuntimeAcceptance => G5PrimordialExpectation::Baseline,
            BuildGuestTest::NativeUserspaceCapability => G5PrimordialExpectation::Baseline,
            BuildGuestTest::PermanentSupervisorRrc => G5PrimordialExpectation::Baseline,
            BuildGuestTest::NormalPreemptionUp => G5PrimordialExpectation::Baseline,
            BuildGuestTest::NormalPreemptionSmp => G5PrimordialExpectation::Baseline,
            BuildGuestTest::BootstrapRegistryLaunch => G5PrimordialExpectation::Baseline,
            BuildGuestTest::DeviceCoordinatorRestart => G5PrimordialExpectation::Baseline,
            BuildGuestTest::DeviceResourceInterruptSynthetic => G5PrimordialExpectation::Baseline,
            BuildGuestTest::PrimordialBlockingCleanup => G5PrimordialExpectation::BlockingCleanup,
            BuildGuestTest::PrimordialUserException => G5PrimordialExpectation::UserException,
            BuildGuestTest::PrimordialInvalidReturn => G5PrimordialExpectation::InvalidReturn,
            BuildGuestTest::BootHandoffPass
            | BuildGuestTest::ExceptionFailPath
            | BuildGuestTest::PanicPath
            | BuildGuestTest::MemoryMapping
            | BuildGuestTest::MemoryUnmapping
            | BuildGuestTest::MemoryPermissions
            | BuildGuestTest::MemoryInvalidPointer
            | BuildGuestTest::MemoryUserKernelIsolation
            | BuildGuestTest::MemorySharedMemoryObject
            | BuildGuestTest::TaskSyscallSmoke
            | BuildGuestTest::TaskSyscallSanitize
            | BuildGuestTest::TaskUserException
            | BuildGuestTest::IpcBlockingSmoke
            | BuildGuestTest::AtomicWaitWake => {
                unreachable!("primordial runtime requires a primordial selector")
            }
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
            terminal_info: None,
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
        self.terminal_info = Some(info);
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
            crate::boot::primordial::construction::PrimordialCompletionError<u32>,
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
            crate::boot::primordial::construction::PrimordialCompletionError<u32>,
        >,
    ) -> u32 {
        if self.terminal_application_code != 0 {
            return self.terminal_application_code;
        }
        match completion {
            Err(crate::boot::primordial::construction::PrimordialCompletionError::Receive(
                detail,
            )) => *detail,
            Err(crate::boot::primordial::construction::PrimordialCompletionError::MalformedReady) => 3,
            Err(crate::boot::primordial::construction::PrimordialCompletionError::ObserveExit(
                detail,
            )) => *detail,
            Err(crate::boot::primordial::construction::PrimordialCompletionError::NonzeroExit(
                code,
            )) => *code,
            Err(crate::boot::primordial::construction::PrimordialCompletionError::UnhandledException) => 5,
            Err(crate::boot::primordial::construction::PrimordialCompletionError::AuthorizedTermination) => 6,
            Err(crate::boot::primordial::construction::PrimordialCompletionError::NotQuiescent(
                detail,
            )) => *detail,
            Ok(()) => 1,
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
    boot_resource_grants: crate::boot::BootResourceGrantAuthority,
    device_resources: crate::device::DeviceResourceAuthority<8>,
    interrupts: crate::device::InterruptAuthority<8>,
    interrupt_platform: crate::device::InterruptPlatformModel<8>,
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

/// Coarse DW0-H transaction boundary for the still-monolithic live authority
/// set. Per-CPU carrier state remains outside this lock; shared mutations are
/// serialized until the individual authorities grow narrower SMP adapters.
struct RuntimeAuthorityLock<T> {
    next_ticket: AtomicU64,
    serving: AtomicU64,
    value: UnsafeCell<T>,
}

impl<T> RuntimeAuthorityLock<T> {
    const fn new(value: T) -> Self {
        Self {
            next_ticket: AtomicU64::new(0),
            serving: AtomicU64::new(0),
            value: UnsafeCell::new(value),
        }
    }

    fn lock(&self) -> RuntimeAuthorityGuard<'_, T> {
        let mut observed = self.next_ticket.load(Ordering::Relaxed);
        let ticket = loop {
            if observed == u64::MAX {
                panic!("runtime authority ticket space exhausted");
            }
            match self.next_ticket.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(ticket) => break ticket,
                Err(current) => observed = current,
            }
        };
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        RuntimeAuthorityGuard {
            lock: self,
            ticket,
            owns_lock: true,
        }
    }
}

// SAFETY: `value` is initialized before any AP carrier is released, never
// moved afterward, and every access is serialized by the ticket pair. This is the
// explicit DW0-H bridge for authorities whose types intentionally do not claim
// `Send`/`Sync` independently.
unsafe impl<T> Sync for RuntimeAuthorityLock<T> {}

struct RuntimeAuthorityGuard<'a, T> {
    lock: &'a RuntimeAuthorityLock<T>,
    ticket: u64,
    owns_lock: bool,
}

impl<T> Deref for RuntimeAuthorityGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for RuntimeAuthorityGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for RuntimeAuthorityGuard<'_, T> {
    fn drop(&mut self) {
        if self.owns_lock {
            self.lock.serving.store(self.ticket + 1, Ordering::Release);
        }
    }
}

/// CPU-local immutable identity over the stationary synchronized runtime.
struct PendingRemoteProcessTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedProcessTermination<HANDLES, THREADS>,
    deferred: [Option<crate::arch::x86_64::rendezvous::DeferredReclaim<()>>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct PendingRemoteTaskGroupTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>,
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
    prepared: crate::syscall::PreparedProcessTermination<HANDLES, THREADS>,
    identities: [Option<crate::arch::x86_64::rendezvous::StopIdentity>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
}

struct PreparedRemoteTaskGroupTermination {
    phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
    prepared: crate::syscall::PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>,
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

fn await_remote_stop_permits(
    deferred: [Option<crate::arch::x86_64::rendezvous::DeferredReclaim<()>>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
) -> [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
    crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] {
    let mut permits = core::array::from_fn(|_| None);
    for (cpu_index, deferred) in deferred.into_iter().enumerate() {
        let Some(deferred) = deferred else {
            continue;
        };
        let ((), permit) = crate::arch::x86_64::idle::await_live_remote_stop(deferred);
        #[cfg(deepwyrm_i1_evidence)]
        crate::test_support::observe_i1_rendezvous_ack(
            crate::cpu::CpuIndex::new(permit.target_cpu())
                .unwrap_or_else(|| panic!("I1 stop permit names an invalid CPU")),
        );
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
    runtime: &'runtime RuntimeAuthorityLock<
        PrimordialRuntimeCarrier<'roles, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    shared: &'static PrimordialRuntimeShared,
    admission: Option<(
        crate::task::CarrierAdmissionTicket,
        crate::task::CarrierResourceTuple,
    )>,
    admission_entered: bool,
    pending_remote_termination: Option<PendingRemoteTermination>,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    RuntimeCarrierFacade<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn drain_quantum_cancellation_detached(&mut self) {
        let ticket = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.take_local_scheduler_quantum_cancellation()
        };
        let Some(ticket) = ticket else {
            return;
        };
        crate::time::cancel_scheduler_quantum(ticket)
            .unwrap_or_else(|error| panic!("scheduler quantum cancellation failed: {error:?}"));
        let mut runtime = self.runtime.lock();
        runtime.switch_cpu(self.cpu);
        runtime.commit_local_scheduler_quantum_cancellation(ticket);
    }

    fn synchronize_scheduler_current_detached(&mut self) {
        let prepared = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.prepare_scheduler_root_switch()
        };
        let Some(prepared) = prepared else {
            return;
        };
        let executed = match prepared.execute() {
            Ok(executed) => executed,
            Err(failure) => {
                let mut runtime = self.runtime.lock();
                let error = runtime.cancel_scheduler_root_switch(failure);
                panic!("detached scheduler root switch failed before CR3: {error:?}")
            }
        };
        let mut runtime = self.runtime.lock();
        runtime.commit_scheduler_root_switch(executed);
    }

    /// Synchronizes the scheduler-current root without crossing an already
    /// published remote Stop. Terminal preparation deliberately moves a
    /// remote current's execution resources while retaining its scheduler
    /// claim until the target acknowledges that Stop. Preparation and mailbox
    /// publication straddle the shared runtime guard, so a target that enters
    /// that narrow gap waits for publication before root synchronization.
    fn synchronize_scheduler_current_at_safe_point_detached(&mut self) -> bool {
        let prepared = loop {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            if matches!(
                crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
                crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
            ) {
                return false;
            }
            if runtime
                .shared
                .execution
                .terminal_stop_publication_pending_on(&runtime.tasks, self.cpu)
                .unwrap_or_else(|error| {
                    panic!("scheduler-current terminal state lookup failed: {error:?}")
                })
            {
                drop(runtime);
                core::hint::spin_loop();
                continue;
            }
            break runtime.prepare_scheduler_root_switch();
        };
        let Some(prepared) = prepared else {
            return true;
        };
        let executed = match prepared.execute() {
            Ok(executed) => executed,
            Err(failure) => {
                let mut runtime = self.runtime.lock();
                let error = runtime.cancel_scheduler_root_switch(failure);
                panic!("detached scheduler root switch failed before CR3: {error:?}")
            }
        };
        let mut runtime = self.runtime.lock();
        runtime.commit_scheduler_root_switch(executed);
        !matches!(
            crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
        )
    }

    /// Runs one scheduler-current transaction under the same runtime guard as
    /// the final Stop arbitration. This closes both detached windows: a Stop
    /// published before root synchronization and one published after the CR3
    /// operation but before the caller reacquires runtime authority.
    fn with_synchronized_runtime_at_safe_point<T>(
        &mut self,
        operation: impl FnOnce(&mut PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>) -> T,
    ) -> Result<T, ()> {
        if !self.synchronize_scheduler_current_at_safe_point_detached() {
            return Err(());
        }
        let mut runtime = self.runtime.lock();
        runtime.switch_cpu(self.cpu);
        if matches!(
            crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
        ) {
            return Err(());
        }
        Ok(operation(&mut runtime))
    }

    fn enter_ap_kernel_root_detached(&mut self) {
        let prepared = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.prepare_ap_kernel_root_entry()
        };
        let executed = match prepared.execute() {
            Ok(executed) => executed,
            Err(failure) => {
                let mut runtime = self.runtime.lock();
                let error = runtime.cancel_ap_kernel_root_entry(failure);
                panic!("AP kernel-root entry failed before CR3: {error:?}")
            }
        };
        let mut runtime = self.runtime.lock();
        runtime.commit_ap_kernel_root_entry(executed);
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
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(published);
        let pending = loop {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            match runtime.prepare_remote_process_exception(exception) {
                ProcessTerminationPreparation::Retry => {
                    drop(runtime);
                    for _ in 0..64 {
                        core::hint::spin_loop();
                    }
                    continue;
                }
                ProcessTerminationPreparation::Immediate(result) => {
                    drop(runtime);
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
        let permits = await_remote_stop_permits(pending.deferred);
        self.synchronize_scheduler_current_detached();
        let result = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
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
}

struct TerminalRetirementState {
    retired_process: ProcessKey,
    retired_root_key: crate::memory::address_region::AddressRegionObjectKey,
    retired_address_space: crate::memory::address_region::AddressSpaceKey,
    #[cfg(deepwyrm_dw1c_evidence)]
    product_execution_generation: u64,
    #[cfg(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_wyr1c_evidence
    ))]
    retiring_wyr1_primordial: bool,
    #[cfg(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_wyr1c_evidence
    ))]
    wyr1_primordial_teardown: Option<(
        crate::task::ProcessQuiescenceProof,
        crate::task::BlockedOperationsDrained,
    )>,
}

struct TerminalSuccessorState {
    retirement: TerminalRetirementState,
    stack: crate::memory::kernel_stack::KernelStackBounds,
    continuation: u64,
}

enum TerminalKernelContinuation {
    #[cfg(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_wyr1c_evidence
    ))]
    RetireWyr1Primordial(TerminalRetirementState),
    #[cfg(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_wyr1c_evidence
    ))]
    RetireWyr1Child {
        retirement: TerminalRetirementState,
        proof: crate::task::ProcessQuiescenceProof,
        drained: crate::task::BlockedOperationsDrained,
    },
    EnterPrimordialPublisher(TerminalRetirementState),
    FinishGenericChild(TerminalRetirementState),
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

/// Fixed CPU-local façade over the stationary runtime authorities.
///
/// The live runtime façades serialize shared authority access separately; this
/// object records only the physical execution identity that belongs to one CPU
/// and remains available to its divergent rendezvous/reaper path.
struct PerCpuLiveCarrier {
    cpu: crate::cpu::CpuIndex,
    local: IrqSpinMutex<PerCpuCarrierLocal>,
}

#[derive(Clone, Copy)]
struct PerCpuCarrierLocal {
    current_thread: Option<ThreadKey>,
    current_stack: Option<crate::task::KernelStackId>,
    current_context: Option<crate::task::ThreadContextId>,
    scratch_cpu: crate::cpu::CpuIndex,
}

impl PerCpuLiveCarrier {
    fn physically_executes(&self, thread: ThreadKey) -> bool {
        let local = self.local.lock();
        local.current_thread == Some(thread)
    }

    fn record_current(
        &self,
        thread: ThreadKey,
        stack: crate::task::KernelStackId,
        context: crate::task::ThreadContextId,
    ) {
        let mut local = self.local.lock();
        assert_eq!(local.scratch_cpu, self.cpu, "carrier scratch CPU drifted");
        local.current_thread = Some(thread);
        local.current_stack = Some(stack);
        local.current_context = Some(context);
    }

    fn record_idle(&self) {
        let mut local = self.local.lock();
        assert_eq!(local.scratch_cpu, self.cpu, "carrier scratch CPU drifted");
        local.current_thread = None;
        local.current_stack = None;
        local.current_context = None;
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

// SAFETY: the BSP initializes each fixed slot exactly once before any AP is
// released. Later access is through the slot's IRQ-serialized local record.
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
    unsafe {
        (*SHARED_RUNTIME_STORAGE.0.get()).write(PrimordialRuntimeShared {
            execution,
            channels: Channels::new(),
            boot_resource_grants: crate::boot::BootResourceGrantAuthority::new(
                boot_resource_grants,
            ),
            device_resources: crate::device::DeviceResourceAuthority::new(),
            interrupts: crate::device::InterruptAuthority::new(),
            interrupt_platform: crate::device::InterruptPlatformModel::new(),
            events: EventAuthority::new(),
            timers: TimerAuthority::new(),
            timer_expiries: IrqSpinMutex::new([None; crate::time::DEADLINE_QUEUE_CAPACITY]),
            waits: WaitRegistry::new(),
        });
    }
    SHARED_RUNTIME_STATE.store(2, Ordering::Release);
    let target = unsafe { &*(*SHARED_RUNTIME_STORAGE.0.get()).as_ptr() };
    crate::time::bind_deadline_wake_target(target)
        .unwrap_or_else(|error| panic!("could not bind primordial deadline wakes: {error:?}"));
    crate::time::bind_timer_expiry_target(target)
        .unwrap_or_else(|error| panic!("could not bind primordial timer expiries: {error:?}"));
    target
}

fn initialize_per_cpu_live_carriers() {
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
                local: IrqSpinMutex::new(PerCpuCarrierLocal {
                    current_thread: None,
                    current_stack: None,
                    current_context: None,
                    scratch_cpu: cpu,
                }),
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

fn bind_runtime_carrier_facades<
    'borrow,
    'runtime,
    'roles,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    facades: core::pin::Pin<
        &'borrow mut [RuntimeCarrierFacade<'runtime, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>;
                         crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    >,
) -> usize {
    let registry = crate::arch::x86_64::smp::live_cpu_registry();
    let live_cpu_count = registry.len();
    assert!(
        (1..=crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT).contains(&live_cpu_count),
        "native runtime topology must fit the fixed carrier capacity"
    );
    #[cfg(deepwyrm_dw1c_evidence)]
    assert_eq!(
        live_cpu_count,
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT,
        "DW1-C1 requires the exact four-CPU runtime topology"
    );
    let facades = unsafe { core::pin::Pin::get_unchecked_mut(facades) };
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
        let carrier = unsafe { core::pin::Pin::new_unchecked(&mut facades[cpu_index]) };
        if cpu_index == 0 {
            unsafe {
                crate::arch::x86_64::syscall::bind_running_native_runtime_carrier_for_slot(
                    cpu, carrier,
                )
            }
            .unwrap_or_else(|error| {
                facades[cpu_index]
                    .shared
                    .execution
                    .fail_carrier_admission(cpu);
                panic!("could not bind CPU0 running native carrier: {error:?}")
            });
        } else {
            unsafe {
                crate::arch::x86_64::syscall::bind_native_runtime_carrier_for_slot(cpu, carrier)
            }
            .unwrap_or_else(|error| {
                facades[cpu_index]
                    .shared
                    .execution
                    .fail_carrier_admission(cpu);
                panic!("could not bind AP {cpu_index} native carrier: {error:?}")
            });
        }
    }
    live_cpu_count
}

fn carrier_resource_tuple<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    runtime: &PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>,
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
    let root = runtime
        .active
        .kernel_execution_root(cpu)
        .unwrap_or_else(|_| {
            fail_live_carrier_admission(runtime.shared, cpu, "CPU retained root unavailable")
        });
    if root.cpu() != cpu || root.root_physical_start() == 0 {
        fail_live_carrier_admission(runtime.shared, cpu, "CPU retained root identity drifted");
    }
    if !runtime.active.validates_cpu_scratch_binding(cpu)
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

#[track_caller]
fn fail_live_carrier_admission(
    shared: &'static PrimordialRuntimeShared,
    cpu: crate::cpu::CpuIndex,
    reason: &'static str,
) -> ! {
    shared.execution.fail_carrier_admission(cpu);
    panic!("CPU {} carrier admission failed: {reason}", cpu.index());
}

fn prepare_runtime_carrier_admission<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    facades: &mut [RuntimeCarrierFacade<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>;
             crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    live_cpu_count: usize,
) {
    let runtime = facades[0].runtime.lock();
    for facade in facades[..live_cpu_count].iter_mut().skip(1) {
        let resources = carrier_resource_tuple(
            &runtime,
            facade.cpu,
            crate::arch::x86_64::smp::CpuLifecycle::Parked,
            crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Parked,
            false,
        );
        let ticket = facade
            .shared
            .execution
            .prepare_ap_carrier(resources, crate::task::CarrierRuntimeState::Parked)
            .unwrap_or_else(|error| {
                facade.shared.execution.fail_carrier_admission(facade.cpu);
                panic!(
                    "could not prepare AP {} admission: {error:?}",
                    facade.cpu.index()
                )
            });
        facade.admission = Some((ticket, resources));
    }
}

fn normalize_bootstrap_carrier<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    facade: &mut RuntimeCarrierFacade<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>,
) {
    let resources = {
        let runtime = facade.runtime.lock();
        carrier_resource_tuple(
            &runtime,
            facade.cpu,
            crate::arch::x86_64::smp::runtime_pre_admission_lifecycle(facade.cpu.index()),
            crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing,
            true,
        )
    };
    if crate::arch::x86_64::syscall::native_runtime_carrier_lifecycle(facade.cpu)
        != Some(crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing)
    {
        panic!("CPU0 running runtime carrier was not published");
    }
    let ticket = facade
        .shared
        .execution
        .prepare_bootstrap_carrier(resources, crate::task::CarrierRuntimeState::Running)
        .unwrap_or_else(|error| {
            facade.shared.execution.fail_carrier_admission(facade.cpu);
            panic!("could not prepare CPU0 carrier: {error:?}")
        });
    facade
        .shared
        .execution
        .publish_bootstrap_carrier_ready(
            ticket,
            resources,
            crate::task::CarrierRuntimeState::Running,
        )
        .unwrap_or_else(|error| {
            facade.shared.execution.fail_carrier_admission(facade.cpu);
            panic!("could not ready CPU0 carrier: {error:?}")
        });
    facade
        .shared
        .execution
        .commit_bootstrap_schedulable(ticket, resources)
        .unwrap_or_else(|error| {
            facade.shared.execution.fail_carrier_admission(facade.cpu);
            panic!("could not commit CPU0 carrier: {error:?}")
        });
    facade.admission = Some((ticket, resources));
    facade.admission_entered = true;
}

fn release_runtime_carrier_facades<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    shared: &'static PrimordialRuntimeShared,
    runtime: &RuntimeAuthorityLock<PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>>,
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
            let runtime = runtime.lock();
            carrier_resource_tuple(
                &runtime,
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
    take_channel_staging_once(cpu_index, false)
}

fn take_channel_staging_once(
    cpu_index: usize,
    permit_existing_claim: bool,
) -> &'static mut [u8; DW_CHANNEL_MAX_PAYLOAD as usize] {
    let state = CHANNEL_STAGING_STATE
        .get(cpu_index)
        .unwrap_or_else(|| panic!("invalid primordial Channel staging CPU slot"));
    let staging = CHANNEL_STAGING
        .get(cpu_index)
        .unwrap_or_else(|| panic!("invalid primordial Channel staging CPU slot"));
    if let Err(observed) = state.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
        if !permit_existing_claim || observed != 1 {
            panic!("primordial Channel staging CPU slot was claimed twice");
        }
    }
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
        let mut scratch = self
            .active
            .target
            .current_scratch_target()
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        let mut offset = 0;
        while offset < byte_len {
            let frame =
                FrameAddress::new(physical_start + offset, self.active.root.physical_limit())
                    .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            if scratch.zero_allocator_frame(frame).is_err() {
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
        let mut scratch = self
            .active
            .target
            .current_scratch_target()
            .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
        while copied < bytes.len() {
            let page = physical & !(PAGE_SIZE - 1);
            let page_offset = (physical & (PAGE_SIZE - 1)) as usize;
            let take = (PAGE_SIZE as usize - page_offset).min(bytes.len() - copied);
            let frame = FrameAddress::new(page, self.active.root.physical_limit())
                .map_err(|_| user_access::LiveUserAccessError::MissingOrInvalid)?;
            scratch
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
    Unselected,
    Process(super::ActiveRootSelection),
    StopPrecommitted(super::ActiveRootSelection),
    Kernel(super::ActiveKernelExecutionRoot),
    Transitioning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootSwitchFlight {
    cpu: crate::cpu::CpuIndex,
    generation: u64,
}

struct SchedulerRootIdentity {
    process: ProcessKey,
    thread: ThreadKey,
    root_key: crate::memory::address_region::AddressRegionObjectKey,
    stack_id: crate::task::KernelStackId,
    context_id: crate::task::ThreadContextId,
}

enum PreparedSchedulerRootSwitchKind {
    Process(super::PreparedProcessRootSwitch),
    FromKernel(super::PreparedKernelToProcessRootSwitch),
}

struct PreparedSchedulerRootSwitch {
    flight: RootSwitchFlight,
    identity: SchedulerRootIdentity,
    kind: PreparedSchedulerRootSwitchKind,
}

enum ExecutedSchedulerRootSwitchKind {
    Process(super::ExecutedProcessRootSwitch),
    FromKernel(super::ExecutedKernelToProcessRootSwitch),
}

struct ExecutedSchedulerRootSwitch {
    flight: RootSwitchFlight,
    identity: SchedulerRootIdentity,
    kind: ExecutedSchedulerRootSwitchKind,
}

enum FailedSchedulerRootSwitchKind {
    Process(super::RootSelectionFailure),
    FromKernel(super::KernelRootSelectionFailure),
}

struct FailedSchedulerRootSwitch {
    flight: RootSwitchFlight,
    kind: FailedSchedulerRootSwitchKind,
}

struct PreparedStopRootSwitch {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelExecutionRootSwitch,
}

struct ExecutedStopRootSwitch {
    flight: RootSwitchFlight,
    executed: super::ExecutedKernelExecutionRootSwitch,
}

struct FailedStopRootSwitch {
    flight: RootSwitchFlight,
    error: super::RootBindingError,
    previous: super::ActiveRootSelection,
}

struct PreparedTerminalKernelRootSwitch {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelExecutionRootSwitch,
}

struct ExecutedTerminalKernelRootSwitch {
    flight: RootSwitchFlight,
    executed: super::ExecutedKernelExecutionRootSwitch,
}

struct FailedTerminalKernelRootSwitch {
    flight: RootSwitchFlight,
    error: super::RootBindingError,
    previous: super::ActiveRootSelection,
}

struct PreparedTerminalProcessRootSwitch {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelToProcessRootSwitch,
}

struct ExecutedTerminalProcessRootSwitch {
    flight: RootSwitchFlight,
    executed: super::ExecutedKernelToProcessRootSwitch,
}

struct FailedTerminalProcessRootSwitch {
    flight: RootSwitchFlight,
    failure: super::KernelRootSelectionFailure,
}

struct PreparedApKernelRootEntry {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelRootEntry,
}

struct ExecutedApKernelRootEntry {
    flight: RootSwitchFlight,
    executed: super::ExecutedKernelRootEntry,
}

struct FailedApKernelRootEntry {
    flight: RootSwitchFlight,
    error: super::RootBindingError,
    prepared: super::PreparedKernelRootEntry,
}

impl PreparedApKernelRootEntry {
    fn execute(self) -> Result<ExecutedApKernelRootEntry, FailedApKernelRootEntry> {
        match self.prepared.execute(&mut super::LiveRootSwitchTarget) {
            Ok(executed) => Ok(ExecutedApKernelRootEntry {
                flight: self.flight,
                executed,
            }),
            Err((error, prepared)) => Err(FailedApKernelRootEntry {
                flight: self.flight,
                error,
                prepared,
            }),
        }
    }
}

impl PreparedStopRootSwitch {
    fn execute(self) -> Result<ExecutedStopRootSwitch, FailedStopRootSwitch> {
        match self.prepared.execute(&mut super::LiveRootSwitchTarget) {
            Ok(executed) => Ok(ExecutedStopRootSwitch {
                flight: self.flight,
                executed,
            }),
            Err((error, previous)) => Err(FailedStopRootSwitch {
                flight: self.flight,
                error,
                previous,
            }),
        }
    }
}

impl PreparedTerminalKernelRootSwitch {
    fn execute(self) -> Result<ExecutedTerminalKernelRootSwitch, FailedTerminalKernelRootSwitch> {
        match self.prepared.execute(&mut super::LiveRootSwitchTarget) {
            Ok(executed) => Ok(ExecutedTerminalKernelRootSwitch {
                flight: self.flight,
                executed,
            }),
            Err((error, previous)) => Err(FailedTerminalKernelRootSwitch {
                flight: self.flight,
                error,
                previous,
            }),
        }
    }
}

impl PreparedTerminalProcessRootSwitch {
    fn execute(self) -> Result<ExecutedTerminalProcessRootSwitch, FailedTerminalProcessRootSwitch> {
        match self.prepared.execute(&mut super::LiveRootSwitchTarget) {
            Ok(executed) => Ok(ExecutedTerminalProcessRootSwitch {
                flight: self.flight,
                executed,
            }),
            Err(failure) => Err(FailedTerminalProcessRootSwitch {
                flight: self.flight,
                failure,
            }),
        }
    }
}

impl PreparedSchedulerRootSwitch {
    fn execute(self) -> Result<ExecutedSchedulerRootSwitch, FailedSchedulerRootSwitch> {
        let kind = match self.kind {
            PreparedSchedulerRootSwitchKind::Process(prepared) => {
                match prepared.execute(&mut super::LiveRootSwitchTarget) {
                    Ok(executed) => ExecutedSchedulerRootSwitchKind::Process(executed),
                    Err(failure) => {
                        return Err(FailedSchedulerRootSwitch {
                            flight: self.flight,
                            kind: FailedSchedulerRootSwitchKind::Process(failure),
                        });
                    }
                }
            }
            PreparedSchedulerRootSwitchKind::FromKernel(prepared) => {
                match prepared.execute(&mut super::LiveRootSwitchTarget) {
                    Ok(executed) => ExecutedSchedulerRootSwitchKind::FromKernel(executed),
                    Err(failure) => {
                        return Err(FailedSchedulerRootSwitch {
                            flight: self.flight,
                            kind: FailedSchedulerRootSwitchKind::FromKernel(failure),
                        });
                    }
                }
            }
        };
        Ok(ExecutedSchedulerRootSwitch {
            flight: self.flight,
            identity: self.identity,
            kind,
        })
    }
}

impl CarrierActiveRoot {
    fn as_ref(&self) -> Option<&super::ActiveRootSelection> {
        match self {
            Self::Process(root) => Some(root),
            Self::Unselected
            | Self::StopPrecommitted(_)
            | Self::Kernel(_)
            | Self::Transitioning => None,
        }
    }

    fn take_process(&mut self) -> super::ActiveRootSelection {
        match core::mem::replace(self, Self::Transitioning) {
            Self::Process(root) => root,
            Self::Unselected
            | Self::StopPrecommitted(_)
            | Self::Kernel(_)
            | Self::Transitioning => {
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
    active_roots: [CarrierActiveRoot; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    root_switch_epochs: [u64; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    root_switch_flights: [Option<RootSwitchFlight>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cpu_processes: [Option<ProcessKey>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cpu_threads: [Option<ThreadKey>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cpu_stack_ids:
        [Option<crate::task::KernelStackId>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cpu_context_ids:
        [Option<crate::task::ThreadContextId>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cpu_root_keys: [Option<crate::memory::address_region::AddressRegionObjectKey>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    stopping_claim: Option<crate::task::SchedulerExecutionClaim>,
    stopping_claim_was_suspended: bool,
    #[cfg(deepwyrm_dw1b_evidence)]
    dw1b_preemption_outgoing: [Option<ThreadKey>; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    #[cfg(deepwyrm_dw1c_evidence)]
    dw1c_pending_detach: [Option<crate::task::Dw1cContinuationDetachRequest>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
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
    // Suspension handoff is physical-carrier state, unlike the durable wait
    // registries above. One CPU must never consume another CPU's pending/idle
    // control decision even though both serialize the shared service owners.
    wait_controls: [NativeWaitControl; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
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
    #[cfg(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_dw1b_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_dw1c_evidence,
        deepwyrm_wyr1c_evidence
    ))]
    evidence_init_process: Option<ProcessKey>,
    #[cfg(any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
    evidence_init_thread: Option<ThreadKey>,
    channel_keys: [crate::ipc::ChannelEndpointKey; 2],
    kernel_peer: Option<HandleRef>,
    process_monitor: Option<HandleRef>,
    root_owner: Option<InternalRef>,
    deferred_currents: [Option<crate::task::DeferredCurrentExecutionResources>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    pending_quantum_cancellations: [Option<crate::task::SchedulerQuantumTicket>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
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
    fn switch_cpu(&mut self, cpu: crate::cpu::CpuIndex) {
        if self.root_switch_flights[cpu.index()].is_some() {
            panic!("ordinary runtime selection targeted an in-flight root switch");
        }
        self.switch_cpu_state(cpu);
    }

    fn switch_cpu_state(&mut self, cpu: crate::cpu::CpuIndex) {
        if self.cpu != cpu {
            let previous = self.cpu.index();
            let outgoing = core::mem::replace(&mut self.active_root, CarrierActiveRoot::Unselected);
            let displaced = core::mem::replace(&mut self.active_roots[previous], outgoing);
            assert!(
                matches!(displaced, CarrierActiveRoot::Unselected),
                "active CPU slot already retained a root"
            );
            self.cpu_processes[previous] = Some(self.process);
            self.cpu_threads[previous] = Some(self.thread);
            self.cpu_stack_ids[previous] = Some(self.stack_id);
            self.cpu_context_ids[previous] = Some(self.context_id);
            self.cpu_root_keys[previous] = Some(self.root_key);
            self.cpu = cpu;
            let current = cpu.index();
            self.active_root = core::mem::replace(
                &mut self.active_roots[current],
                CarrierActiveRoot::Unselected,
            );
            self.local = per_cpu_live_carrier(cpu);
            if let Some(process) = self.cpu_processes[current] {
                self.process = process;
                self.thread = self.cpu_threads[current].expect("CPU state omitted Thread");
                self.stack_id = self.cpu_stack_ids[current].expect("CPU state omitted stack");
                self.context_id = self.cpu_context_ids[current].expect("CPU state omitted context");
                self.root_key = self.cpu_root_keys[current].expect("CPU state omitted root");
            }
            self.channel_staging = take_channel_staging_once(cpu.index(), true);
        }
    }

    fn begin_root_switch_flight(&mut self) -> RootSwitchFlight {
        let cpu = self.cpu;
        let slot = &mut self.root_switch_epochs[cpu.index()];
        *slot = slot
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .unwrap_or_else(|| panic!("root-switch flight generation exhausted"));
        let flight = RootSwitchFlight {
            cpu,
            generation: *slot,
        };
        if self.root_switch_flights[cpu.index()]
            .replace(flight)
            .is_some()
        {
            panic!("CPU already owns an in-flight root switch");
        }
        flight
    }

    fn select_root_switch_flight(&mut self, flight: RootSwitchFlight) {
        if self.root_switch_flights[flight.cpu.index()] != Some(flight) {
            panic!("root-switch flight identity drifted before commit");
        }
        self.switch_cpu_state(flight.cpu);
        if !matches!(self.active_root, CarrierActiveRoot::Transitioning) {
            panic!("root-switch flight lost its transitioning carrier slot");
        }
    }

    fn finish_root_switch_flight(&mut self, flight: RootSwitchFlight) {
        if self.root_switch_flights[flight.cpu.index()] != Some(flight) {
            panic!("root-switch flight identity drifted at commit");
        }
        self.root_switch_flights[flight.cpu.index()] = None;
    }

    fn prepare_stop_root_switch(&mut self) -> PreparedStopRootSwitch {
        let previous =
            match core::mem::replace(&mut self.active_root, CarrierActiveRoot::Transitioning) {
                CarrierActiveRoot::StopPrecommitted(root) => root,
                _ => panic!("remote stop root switch omitted its precommitted Process root"),
            };
        let prepared = self
            .active
            .prepare_kernel_execution_root_switch(previous)
            .unwrap_or_else(|(error, recovered)| {
                self.active_root = CarrierActiveRoot::StopPrecommitted(recovered);
                panic!("remote stop kernel-root preflight failed: {error:?}")
            });
        let flight = self.begin_root_switch_flight();
        PreparedStopRootSwitch { flight, prepared }
    }

    fn commit_stop_root_switch(&mut self, executed: ExecutedStopRootSwitch) {
        self.select_root_switch_flight(executed.flight);
        let kernel = self
            .active
            .commit_kernel_execution_root_switch(executed.executed);
        self.active_root = CarrierActiveRoot::Kernel(kernel);
        self.finish_root_switch_flight(executed.flight);
    }

    fn cancel_stop_root_switch(
        &mut self,
        failure: FailedStopRootSwitch,
    ) -> super::RootBindingError {
        self.select_root_switch_flight(failure.flight);
        self.active_root = CarrierActiveRoot::StopPrecommitted(failure.previous);
        self.finish_root_switch_flight(failure.flight);
        failure.error
    }

    fn prepare_terminal_kernel_root_switch(&mut self) -> PreparedTerminalKernelRootSwitch {
        let previous = self.active_root.take_process();
        let prepared = self
            .active
            .prepare_kernel_execution_root_switch(previous)
            .unwrap_or_else(|(error, recovered)| {
                self.active_root = CarrierActiveRoot::Process(recovered);
                panic!("terminal kernel-root preflight failed: {error:?}")
            });
        let flight = self.begin_root_switch_flight();
        PreparedTerminalKernelRootSwitch { flight, prepared }
    }

    fn commit_terminal_kernel_root_switch(&mut self, executed: ExecutedTerminalKernelRootSwitch) {
        self.select_root_switch_flight(executed.flight);
        let kernel = self
            .active
            .commit_kernel_execution_root_switch(executed.executed);
        self.active_root = CarrierActiveRoot::Kernel(kernel);
        self.finish_root_switch_flight(executed.flight);
    }

    fn cancel_terminal_kernel_root_switch(
        &mut self,
        failure: FailedTerminalKernelRootSwitch,
    ) -> super::RootBindingError {
        self.select_root_switch_flight(failure.flight);
        self.active_root = CarrierActiveRoot::Process(failure.previous);
        self.finish_root_switch_flight(failure.flight);
        failure.error
    }

    fn prepare_terminal_primordial_root_switch(&mut self) -> PreparedTerminalProcessRootSwitch {
        let prepared = self
            .active
            .prepare_process_root_selection(
                self.cpu,
                self.primordial_process,
                self.primordial_address_space,
            )
            .unwrap_or_else(|error| {
                panic!("terminal idle publisher-root preparation failed: {error:?}")
            });
        let previous =
            match core::mem::replace(&mut self.active_root, CarrierActiveRoot::Transitioning) {
                CarrierActiveRoot::Kernel(root) => root,
                _ => panic!("terminal idle lost its kernel execution root"),
            };
        let prepared = self
            .active
            .prepare_from_kernel_execution_root_switch(prepared, previous)
            .unwrap_or_else(|failure| {
                let (error, prepared, previous) = failure.into_parts();
                self.active
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("terminal publisher-root abandonment failed: {abandon:?}")
                    });
                self.active_root = CarrierActiveRoot::Kernel(previous);
                panic!("terminal publisher-root preflight failed: {error:?}")
            });
        let flight = self.begin_root_switch_flight();
        PreparedTerminalProcessRootSwitch { flight, prepared }
    }

    fn commit_terminal_primordial_root_switch(
        &mut self,
        executed: ExecutedTerminalProcessRootSwitch,
    ) {
        self.select_root_switch_flight(executed.flight);
        let selected = self
            .active
            .commit_from_kernel_execution_root_switch(executed.executed);
        self.active_root = CarrierActiveRoot::Process(selected);
        self.finish_root_switch_flight(executed.flight);
    }

    fn cancel_terminal_primordial_root_switch(
        &mut self,
        failure: FailedTerminalProcessRootSwitch,
    ) -> super::RootBindingError {
        self.select_root_switch_flight(failure.flight);
        let (error, prepared, previous) = failure.failure.into_parts();
        self.active
            .abandon_process_root_selection(prepared)
            .unwrap_or_else(|abandon| {
                panic!("cancelled terminal publisher switch lost residency: {abandon:?}")
            });
        self.active_root = CarrierActiveRoot::Kernel(previous);
        self.finish_root_switch_flight(failure.flight);
        error
    }

    fn prepare_ap_kernel_root_entry(&mut self) -> PreparedApKernelRootEntry {
        if self.cpu == crate::cpu::CpuIndex::BOOTSTRAP
            || !matches!(self.active_root, CarrierActiveRoot::Unselected)
        {
            panic!("AP kernel-root entry requires an unselected AP carrier");
        }
        let prepared = self
            .active
            .prepare_ap_kernel_root_entry(self.cpu)
            .unwrap_or_else(|error| panic!("AP kernel-root entry preflight failed: {error:?}"));
        self.active_root = CarrierActiveRoot::Transitioning;
        let flight = self.begin_root_switch_flight();
        PreparedApKernelRootEntry { flight, prepared }
    }

    fn commit_ap_kernel_root_entry(&mut self, executed: ExecutedApKernelRootEntry) {
        self.select_root_switch_flight(executed.flight);
        let kernel = self.active.commit_ap_kernel_root_entry(executed.executed);
        self.active_root = CarrierActiveRoot::Kernel(kernel);
        self.finish_root_switch_flight(executed.flight);
    }

    fn cancel_ap_kernel_root_entry(
        &mut self,
        failure: FailedApKernelRootEntry,
    ) -> super::RootBindingError {
        self.select_root_switch_flight(failure.flight);
        let _prepared = failure.prepared;
        self.active_root = CarrierActiveRoot::Unselected;
        self.finish_root_switch_flight(failure.flight);
        failure.error
    }

    #[track_caller]
    fn select_cpu(&mut self, cpu: crate::cpu::CpuIndex) {
        self.switch_cpu(cpu);
        self.synchronize_scheduler_current();
    }

    unsafe fn prepare_suspend_stationary(
        &mut self,
    ) -> crate::syscall::native::NativeSuspendPlan<'static> {
        #[cfg(feature = "test-support")]
        let owner = self.services.operation_owner(self.thread);
        let cancelled_quantum = self.wait_controls[self.cpu.index()].pending_quantum_cancellation();
        self.stage_local_scheduler_quantum_cancellation(cancelled_quantum);
        let control = &mut self.wait_controls[self.cpu.index()];
        #[cfg(deepwyrm_i1_evidence)]
        let pending_wake = control.pending_wake_key();
        let plan = unsafe {
            self.services.prepare_suspend_on(
                control,
                self.cpu,
                &self.tasks,
                &self.shared.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|error| panic!("primordial suspend preparation drifted: {error:?}"));
        #[cfg(deepwyrm_i1_evidence)]
        if let Some(wake) = pending_wake {
            crate::test_support::observe_i1_parent_blocked(self.cpu, wake);
        }
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

    fn stage_local_scheduler_quantum_cancellation(
        &mut self,
        ticket: Option<crate::task::SchedulerQuantumTicket>,
    ) {
        self.stage_scheduler_quantum_cancellation_on(self.cpu, ticket);
    }

    fn stage_scheduler_quantum_cancellation_on(
        &mut self,
        cpu: crate::cpu::CpuIndex,
        ticket: Option<crate::task::SchedulerQuantumTicket>,
    ) {
        let Some(ticket) = ticket else {
            return;
        };
        assert_eq!(ticket.cpu(), cpu, "quantum cancellation changed CPU");
        let slot = &mut self.pending_quantum_cancellations[cpu.index()];
        assert!(
            slot.is_none(),
            "CPU already owns a pending quantum cancellation"
        );
        *slot = Some(ticket);
    }

    fn take_local_scheduler_quantum_cancellation(
        &mut self,
    ) -> Option<crate::task::SchedulerQuantumTicket> {
        self.pending_quantum_cancellations[self.cpu.index()].take()
    }

    fn commit_local_scheduler_quantum_cancellation(
        &self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) {
        assert_eq!(
            ticket.cpu(),
            self.cpu,
            "quantum cancellation committed on another CPU"
        );
        assert!(
            self.pending_quantum_cancellations[self.cpu.index()].is_none(),
            "a newer CPU-local cancellation overtook physical reconciliation"
        );
        assert_ne!(
            self.shared
                .execution
                .preemption_snapshot_on(self.cpu)
                .quantum,
            Some(ticket),
            "scheduler still owns the physically cancelled exact quantum"
        );
    }

    fn execute_local_scheduler_quantum_cancellation(&mut self) {
        let Some(ticket) = self.take_local_scheduler_quantum_cancellation() else {
            return;
        };
        self.assert_guard_free_external_work();
        crate::time::cancel_scheduler_quantum(ticket)
            .unwrap_or_else(|error| panic!("scheduler quantum cancellation failed: {error:?}"));
        self.commit_local_scheduler_quantum_cancellation(ticket);
    }

    fn install_deferred_current(
        &mut self,
        deferred: crate::task::DeferredCurrentExecutionResources,
    ) {
        self.stage_local_scheduler_quantum_cancellation(deferred.cancelled_quantum());
        let slot = &mut self.deferred_currents[self.cpu.index()];
        assert!(slot.is_none(), "deferred current resources installed twice");
        *slot = Some(deferred);
    }

    unsafe fn prepare_preemption_stationary(
        &mut self,
    ) -> crate::syscall::native::NativePreemptionPlan<'static> {
        self.assert_guard_free_external_work();
        match self
            .shared
            .execution
            .preempt_current_on(self.cpu)
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
                    self.shared.execution.suspended_claim_on(self.cpu),
                    Some(outgoing)
                );
                let plan = unsafe {
                    self.shared.execution.prepare_preemptive_kernel_switch_on(
                        &self.tasks,
                        self.cpu,
                        decision,
                        crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
                    )
                }
                .unwrap_or_else(|error| panic!("DW1-B switch preparation drifted: {error:?}"));
                #[cfg(deepwyrm_dw1b_evidence)]
                {
                    let pending = &mut self.dw1b_preemption_outgoing[self.cpu.index()];
                    assert!(
                        pending.is_none(),
                        "selector-26 preemption attribution overlapped"
                    );
                    *pending = Some(outgoing.thread());
                }
                crate::syscall::native::NativePreemptionPlan::Switch(plan)
            }
        }
    }

    unsafe fn poll_idle_suspend_stationary(
        &mut self,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'static> {
        #[cfg(feature = "test-support")]
        let owner = self.services.operation_owner(self.thread);
        let control = &mut self.wait_controls[self.cpu.index()];
        let poll = unsafe {
            self.services.poll_idle_suspend_on(
                control,
                self.cpu,
                &self.tasks,
                &self.shared.execution,
                crate::arch::x86_64::syscall::first_run_thread_entry_rip(),
            )
        }
        .unwrap_or_else(|error| panic!("primordial idle-suspend poll drifted: {error:?}"));
        #[cfg(deepwyrm_dw1c_evidence)]
        if let crate::syscall::native::NativeIdleSuspendPoll::Detach { request, .. } = &poll {
            let slot = &mut self.dw1c_pending_detach[self.cpu.index()];
            assert!(slot.is_none(), "selector-28 idle detach overlapped");
            *slot = Some(*request);
        }
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

    fn prepare_fresh_user_entry(
        &mut self,
    ) -> (
        crate::arch::x86_64::syscall::ValidatedUserReturn,
        crate::memory::kernel_stack::KernelStackBounds,
    ) {
        self.synchronize_scheduler_current();
        self.prepare_fresh_user_entry_synchronized()
    }

    fn prepare_fresh_user_entry_synchronized(
        &mut self,
    ) -> (
        crate::arch::x86_64::syscall::ValidatedUserReturn,
        crate::memory::kernel_stack::KernelStackBounds,
    ) {
        #[cfg(deepwyrm_i1_evidence)]
        if self.process != self.primordial_process {
            crate::test_support::observe_i1_descendant_running(self.cpu);
        }
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
        (state, stack)
    }

    fn prepare_terminal_retirement_state(&mut self) -> TerminalRetirementState {
        let retired_process = self.process;
        let retired_root_key = self.root_key;
        let retired_address_space = self
            .regions
            .region(retired_root_key)
            .unwrap_or_else(|error| panic!("terminal Process root disappeared: {error:?}"))
            .address_space_key();
        let deferred = self.deferred_currents[self.cpu.index()]
            .take()
            .unwrap_or_else(|| {
                if self.deferred_currents.iter().any(Option::is_some) {
                    panic!("terminal deferred resources migrated to another CPU")
                }
                if self.shared.execution.current_thread_on(self.cpu).is_some() {
                    panic!("terminal handoff retained a scheduler-current Thread")
                }
                if self.shared.execution.suspended_claim_on(self.cpu).is_some() {
                    panic!("terminal handoff retained a suspended claim without resources")
                }
                if self.shared.execution.running_claim_on(self.cpu).is_some() {
                    panic!("terminal handoff retained a Running claim without resources")
                }
                match self.shared.execution.scheduler_state(self.thread) {
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
        #[cfg(deepwyrm_dw1c_evidence)]
        let product_execution_generation = deferred.execution_generation();
        crate::syscall::complete_deferred_current_reclaim_on(
            &mut self.registry,
            &self.shared.execution,
            &self.shared.waits,
            self.cpu,
            deferred,
            &mut self.cleanup,
        );
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        let retiring_wyr1_primordial = retired_process == self.primordial_process;
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        if retiring_wyr1_primordial && let Err(error) = validate_primordial_retirement_facts(self) {
            #[cfg(feature = "test-support")]
            let terminal_info = self.g5_probe.terminal_info;
            #[cfg(not(feature = "test-support"))]
            let terminal_info = None;
            crate::test_support::complete_fail(primordial_completion_detail(error, terminal_info))
        }
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        let wyr1_primordial_teardown = if retiring_wyr1_primordial {
            let proof = self
                .tasks
                .process_quiescence_proof(retired_process)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd009))
                });
            let drained = self
                .shared
                .execution
                .blocked_operations_drained(&self.tasks, &proof)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd00a))
                });
            self.unmap_primordial_userspace(&proof).unwrap_or_else(|_| {
                crate::test_support::complete_fail(supervisor_evidence_detail(0xd00b))
            });
            Some((proof, drained))
        } else {
            None
        };
        TerminalRetirementState {
            retired_process,
            retired_root_key,
            retired_address_space,
            #[cfg(deepwyrm_dw1c_evidence)]
            product_execution_generation,
            #[cfg(any(
                deepwyrm_wyr1_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_wyr1c_evidence
            ))]
            retiring_wyr1_primordial,
            #[cfg(any(
                deepwyrm_wyr1_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_wyr1c_evidence
            ))]
            wyr1_primordial_teardown,
        }
    }

    fn prepare_terminal_handoff_detached(&mut self) -> PreparedTerminalStep {
        let retirement = self.prepare_terminal_retirement_state();
        if let Some(next) = self.shared.execution.terminal_reaper_next_on(self.cpu) {
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

        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        if retirement.retiring_wyr1_primordial {
            let prepared = self.prepare_terminal_kernel_root_switch();
            return PreparedTerminalStep::KernelRoot {
                prepared,
                continuation: TerminalKernelContinuation::RetireWyr1Primordial(retirement),
            };
        }

        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        let primordial_retired = match self.tasks.root_region(self.primordial_process) {
            Ok(None) | Err(crate::task::TaskError::InvalidTask) => true,
            Ok(Some(_)) => false,
            Err(_) => crate::test_support::complete_fail(supervisor_evidence_detail(0xd00d)),
        };
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        if retirement.retired_process != self.primordial_process && primordial_retired {
            let retiring_reporter = self.evidence_init_process == Some(retirement.retired_process);
            if retiring_reporter {
                let info = self
                    .tasks
                    .process_info(retirement.retired_process)
                    .unwrap_or_else(|_| {
                        crate::test_support::complete_fail(supervisor_evidence_detail(0xd013))
                    });
                let detail = if info.application_code == 0 {
                    supervisor_evidence_detail(0xd014)
                } else {
                    info.application_code
                };
                crate::test_support::complete_fail(detail)
            }
            let proof = self
                .tasks
                .process_quiescence_proof(retirement.retired_process)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd00e))
                });
            let drained = self
                .shared
                .execution
                .blocked_operations_drained(&self.tasks, &proof)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd00f))
                });
            self.unmap_current_userspace(
                retirement.retired_process,
                retirement.retired_root_key,
                retirement.retired_address_space,
                &proof,
            )
            .unwrap_or_else(|_| {
                crate::test_support::complete_fail(supervisor_evidence_detail(0xd010))
            });
            let prepared = self.prepare_terminal_kernel_root_switch();
            return PreparedTerminalStep::KernelRoot {
                prepared,
                continuation: TerminalKernelContinuation::RetireWyr1Child {
                    retirement,
                    proof,
                    drained,
                },
            };
        }

        if retirement.retired_process != self.primordial_process {
            if crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
                != Some(self.cpu.index())
            {
                panic!("terminal idle facade resumed on another physical CPU")
            }
            if self
                .active_root
                .as_ref()
                .is_none_or(|previous| previous.cpu() != self.cpu)
            {
                panic!("terminal idle carrier retained another CPU's Process root")
            }
            let prepared = self.prepare_terminal_kernel_root_switch();
            return PreparedTerminalStep::KernelRoot {
                prepared,
                continuation: TerminalKernelContinuation::EnterPrimordialPublisher(retirement),
            };
        }

        PreparedTerminalStep::Final(self.finish_primordial_terminal_handoff(
            #[cfg(deepwyrm_dw1c_evidence)]
            retirement.product_execution_generation,
        ))
    }

    fn finish_terminal_successor(
        &mut self,
        state: TerminalSuccessorState,
    ) -> PreparedTerminalHandoff {
        if state.retirement.retired_process != self.process {
            #[cfg(any(
                deepwyrm_wyr1_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_wyr1c_evidence
            ))]
            if state.retirement.retiring_wyr1_primordial {
                let (proof, drained) =
                    state
                        .retirement
                        .wyr1_primordial_teardown
                        .unwrap_or_else(|| {
                            crate::test_support::complete_fail(supervisor_evidence_detail(0xd00c))
                        });
                self.finish_quiesced_process_root_retirement(
                    state.retirement.retired_process,
                    state.retirement.retired_address_space,
                    &proof,
                    drained,
                )
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd002))
                });
            } else if self
                .tasks
                .process_quiescence_proof(state.retirement.retired_process)
                .is_ok()
            {
                self.finish_inactive_process_teardown(
                    state.retirement.retired_process,
                    state.retirement.retired_root_key,
                    state.retirement.retired_address_space,
                )
                .unwrap_or_else(|_| panic!("inactive exited Process teardown drifted"));
            }
            #[cfg(not(any(
                deepwyrm_wyr1_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_wyr1c_evidence
            )))]
            if self
                .tasks
                .process_quiescence_proof(state.retirement.retired_process)
                .is_ok()
            {
                self.finish_inactive_process_teardown(
                    state.retirement.retired_process,
                    state.retirement.retired_root_key,
                    state.retirement.retired_address_space,
                )
                .unwrap_or_else(|_| panic!("inactive exited Process teardown drifted"));
            }
        }
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        if state.retirement.retiring_wyr1_primordial {
            self.enable_wyr1_reporter_after_retirement()
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd003))
                });
        }
        unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(state.stack) }
            .unwrap_or_else(|error| panic!("terminal next stack binding failed: {error:?}"));
        let continuation = if state.continuation == 0 {
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
            #[cfg(any(
                deepwyrm_wyr1_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_wyr1c_evidence
            ))]
            TerminalKernelContinuation::RetireWyr1Primordial(mut retirement) => {
                let (proof, drained) =
                    retirement
                        .wyr1_primordial_teardown
                        .take()
                        .unwrap_or_else(|| {
                            crate::test_support::complete_fail(supervisor_evidence_detail(0xd00c))
                        });
                self.finish_quiesced_process_root_retirement(
                    retirement.retired_process,
                    retirement.retired_address_space,
                    &proof,
                    drained,
                )
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd007))
                });
                self.enable_wyr1_reporter_after_retirement()
                    .unwrap_or_else(|_| {
                        crate::test_support::complete_fail(supervisor_evidence_detail(0xd008))
                    });
                self.local.record_idle();
                PreparedTerminalStep::Final(PreparedTerminalHandoff::IdleScheduler)
            }
            #[cfg(any(
                deepwyrm_wyr1_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_wyr1c_evidence
            ))]
            TerminalKernelContinuation::RetireWyr1Child {
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
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd012))
                });
                self.local.record_idle();
                PreparedTerminalStep::Final(PreparedTerminalHandoff::IdleScheduler)
            }
            TerminalKernelContinuation::EnterPrimordialPublisher(retirement) => {
                let prepared = self.prepare_terminal_primordial_root_switch();
                PreparedTerminalStep::PrimordialRoot {
                    prepared,
                    retirement,
                }
            }
            TerminalKernelContinuation::FinishGenericChild(retirement) => {
                self.process = self.primordial_process;
                self.root_key = self.primordial_root_key;
                self.local.record_idle();
                drop(retirement);
                PreparedTerminalStep::Final(PreparedTerminalHandoff::IdleScheduler)
            }
        }
    }

    fn continue_terminal_after_primordial_root(
        &mut self,
        retirement: TerminalRetirementState,
    ) -> PreparedTerminalStep {
        self.finish_inactive_process_teardown(
            retirement.retired_process,
            retirement.retired_root_key,
            retirement.retired_address_space,
        )
        .unwrap_or_else(|_| panic!("idle exited Process teardown drifted"));
        let prepared = self.prepare_terminal_kernel_root_switch();
        PreparedTerminalStep::KernelRoot {
            prepared,
            continuation: TerminalKernelContinuation::FinishGenericChild(retirement),
        }
    }

    fn finish_primordial_terminal_handoff(
        &mut self,
        #[cfg(deepwyrm_dw1c_evidence)] product_execution_generation: u64,
    ) -> PreparedTerminalHandoff {
        #[cfg(not(any(deepwyrm_dw1d_evidence, deepwyrm_wyr1c_evidence)))]
        let completion = complete_primordial_launch(self);
        #[cfg(any(deepwyrm_dw1d_evidence, deepwyrm_wyr1c_evidence))]
        let completion = complete_resource_primordial_launch(self);
        #[cfg(all(feature = "test-support", deepwyrm_dw1c_evidence))]
        {
            if completion.is_err() {
                crate::test_support::complete_fail(self.g5_probe.failure_detail(&completion))
            }
            let completed_at_ns = crate::time::monotonic_now()
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e018));
            let snapshot = self
                .shared
                .execution
                .dw1c_final_scheduler_snapshot()
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e019));
            let permit = crate::test_support::DW1C_EVIDENCE
                .final_normal_completion(completed_at_ns, product_execution_generation, snapshot)
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e01a));
            crate::test_support::complete_dw1c_evidence(permit)
        }
        #[cfg(all(feature = "test-support", deepwyrm_dw1b_evidence))]
        {
            let primordial_normal = self.g5_probe.accepts_completion(&completion);
            let counters = self
                .shared
                .execution
                .preemption_snapshot_on(crate::cpu::CpuIndex::BOOTSTRAP)
                .counters;
            match crate::test_support::DW1B_EVIDENCE.finish(counters, primordial_normal) {
                Ok(permit) => crate::test_support::complete_dw1b_evidence(permit),
                Err(error) => crate::test_support::complete_fail(dw1b_evidence_detail(error)),
            }
        }
        #[cfg(all(feature = "test-support", deepwyrm_dw1d_evidence))]
        {
            if completion.is_err() {
                crate::test_support::complete_fail(self.g5_probe.failure_detail(&completion))
            }
            let permit = crate::test_support::DW1D_EVIDENCE
                .final_normal_completion()
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e001));
            crate::test_support::complete_dw1d_evidence(permit)
        }
        #[cfg(all(feature = "test-support", deepwyrm_wyr1c_evidence))]
        {
            let detail = if self.g5_probe.accepts_completion(&completion) {
                supervisor_evidence_detail(0xd015)
            } else {
                self.g5_probe.failure_detail(&completion)
            };
            crate::test_support::complete_fail(detail)
        }
        #[cfg(all(
            feature = "test-support",
            not(any(
                deepwyrm_dw1b_evidence,
                deepwyrm_dw1c_evidence,
                deepwyrm_dw1d_evidence,
                deepwyrm_wyr1c_evidence
            ))
        ))]
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

    fn prepare_terminal_handoff(&mut self) -> PreparedTerminalHandoff {
        let retired_process = self.process;
        let retired_root_key = self.root_key;
        let retired_address_space = self
            .regions
            .region(retired_root_key)
            .unwrap_or_else(|error| panic!("terminal Process root disappeared: {error:?}"))
            .address_space_key();
        let deferred = self.deferred_currents[self.cpu.index()]
            .take()
            .unwrap_or_else(|| {
                if self.deferred_currents.iter().any(Option::is_some) {
                    panic!("terminal deferred resources migrated to another CPU")
                }
                if self.shared.execution.current_thread_on(self.cpu).is_some() {
                    panic!("terminal handoff retained a scheduler-current Thread")
                }
                if self.shared.execution.suspended_claim_on(self.cpu).is_some() {
                    panic!("terminal handoff retained a suspended claim without resources")
                }
                if self.shared.execution.running_claim_on(self.cpu).is_some() {
                    panic!("terminal handoff retained a Running claim without resources")
                }
                match self.shared.execution.scheduler_state(self.thread) {
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
        #[cfg(deepwyrm_dw1c_evidence)]
        let product_execution_generation = deferred.execution_generation();
        crate::syscall::complete_deferred_current_reclaim_on(
            &mut self.registry,
            &self.shared.execution,
            &self.shared.waits,
            self.cpu,
            deferred,
            &mut self.cleanup,
        );
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        let retiring_wyr1_primordial = retired_process == self.primordial_process;
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        if retiring_wyr1_primordial {
            if let Err(error) = validate_primordial_retirement_facts(self) {
                #[cfg(feature = "test-support")]
                let terminal_info = self.g5_probe.terminal_info;
                #[cfg(not(feature = "test-support"))]
                let terminal_info = None;
                crate::test_support::complete_fail(primordial_completion_detail(
                    error,
                    terminal_info,
                ))
            }
        }
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        let mut wyr1_primordial_teardown = if retiring_wyr1_primordial {
            // Primordial is still this CPU's hardware-active Process root.
            // Remove its low half through that exact publisher before choosing
            // either a userspace successor or the CPU-private kernel root.
            let proof = self
                .tasks
                .process_quiescence_proof(retired_process)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd009))
                });
            let drained = self
                .shared
                .execution
                .blocked_operations_drained(&self.tasks, &proof)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd00a))
                });
            self.unmap_primordial_userspace(&proof).unwrap_or_else(|_| {
                crate::test_support::complete_fail(supervisor_evidence_detail(0xd00b))
            });
            Some((proof, drained))
        } else {
            None
        };
        if let Some(next) = self.shared.execution.terminal_reaper_next_on(self.cpu) {
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
            if retired_process != self.process {
                #[cfg(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_wyr1c_evidence
                ))]
                if retiring_wyr1_primordial {
                    let (proof, drained) = wyr1_primordial_teardown.take().unwrap_or_else(|| {
                        crate::test_support::complete_fail(supervisor_evidence_detail(0xd00c))
                    });
                    self.finish_quiesced_process_root_retirement(
                        retired_process,
                        retired_address_space,
                        &proof,
                        drained,
                    )
                    .unwrap_or_else(|_| {
                        crate::test_support::complete_fail(supervisor_evidence_detail(0xd002))
                    });
                } else if self.tasks.process_quiescence_proof(retired_process).is_ok() {
                    self.finish_inactive_process_teardown(
                        retired_process,
                        retired_root_key,
                        retired_address_space,
                    )
                    .unwrap_or_else(|_| panic!("inactive exited Process teardown drifted"));
                }
                #[cfg(not(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_wyr1c_evidence
                )))]
                if self.tasks.process_quiescence_proof(retired_process).is_ok() {
                    self.finish_inactive_process_teardown(
                        retired_process,
                        retired_root_key,
                        retired_address_space,
                    )
                    .unwrap_or_else(|_| panic!("inactive exited Process teardown drifted"));
                }
            }
            #[cfg(any(
                deepwyrm_wyr1_evidence,
                deepwyrm_wyr1b_evidence,
                deepwyrm_wyr1c_evidence
            ))]
            if retiring_wyr1_primordial {
                self.enable_wyr1_reporter_after_retirement()
                    .unwrap_or_else(|_| {
                        crate::test_support::complete_fail(supervisor_evidence_detail(0xd003))
                    });
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
            return PreparedTerminalHandoff::Continuation(continuation);
        }

        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        if retiring_wyr1_primordial {
            // A permanent supervisor may already be Running on another CPU,
            // leaving no same-CPU successor. Primordial's low half is already
            // gone, so move to this CPU's private kernel root, retire the empty
            // primordial root, then leave the carrier idle without resurrecting
            // the bootstrap root.
            let previous = self.active_root.take_process();
            match self.active.enter_kernel_execution_root(previous) {
                Ok(kernel) => self.active_root = CarrierActiveRoot::Kernel(kernel),
                Err((error, recovered)) => {
                    self.active_root = CarrierActiveRoot::Process(recovered);
                    crate::test_support::complete_fail(match error {
                        super::RootBindingError::CpuMismatch => supervisor_evidence_detail(0xd004),
                        super::RootBindingError::RootMismatch => supervisor_evidence_detail(0xd005),
                        _ => supervisor_evidence_detail(0xd006),
                    })
                }
            }
            let (proof, drained) = wyr1_primordial_teardown.take().unwrap_or_else(|| {
                crate::test_support::complete_fail(supervisor_evidence_detail(0xd00c))
            });
            self.finish_quiesced_process_root_retirement(
                retired_process,
                retired_address_space,
                &proof,
                drained,
            )
            .unwrap_or_else(|_| {
                crate::test_support::complete_fail(supervisor_evidence_detail(0xd007))
            });
            self.enable_wyr1_reporter_after_retirement()
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd008))
                });
            self.local.record_idle();
            return PreparedTerminalHandoff::IdleScheduler;
        }

        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        let primordial_retired = match self.tasks.root_region(self.primordial_process) {
            Ok(None) | Err(crate::task::TaskError::InvalidTask) => true,
            Ok(Some(_)) => false,
            Err(_) => crate::test_support::complete_fail(supervisor_evidence_detail(0xd00d)),
        };
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        if retired_process != self.primordial_process && primordial_retired {
            // Once WYR1 has retired primordial, its retained boot-lifetime
            // PML4 is architecture-private state, not a Process publisher.
            // Tear down the current child through its own exact active root,
            // then enter the CPU-private kernel root before retiring the empty
            // child root and rescanning from ordinary idle.
            let retiring_reporter = self.evidence_init_process == Some(retired_process);
            if retiring_reporter {
                let info = self
                    .tasks
                    .process_info(retired_process)
                    .unwrap_or_else(|_| {
                        crate::test_support::complete_fail(supervisor_evidence_detail(0xd013))
                    });
                let detail = if info.application_code == 0 {
                    supervisor_evidence_detail(0xd014)
                } else {
                    info.application_code
                };
                crate::test_support::complete_fail(detail)
            }
            let proof = self
                .tasks
                .process_quiescence_proof(retired_process)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd00e))
                });
            let drained = self
                .shared
                .execution
                .blocked_operations_drained(&self.tasks, &proof)
                .unwrap_or_else(|_| {
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd00f))
                });
            self.unmap_current_userspace(
                retired_process,
                retired_root_key,
                retired_address_space,
                &proof,
            )
            .unwrap_or_else(|_| {
                crate::test_support::complete_fail(supervisor_evidence_detail(0xd010))
            });
            let previous = self.active_root.take_process();
            match self.active.enter_kernel_execution_root(previous) {
                Ok(kernel) => self.active_root = CarrierActiveRoot::Kernel(kernel),
                Err((_, recovered)) => {
                    self.active_root = CarrierActiveRoot::Process(recovered);
                    crate::test_support::complete_fail(supervisor_evidence_detail(0xd011))
                }
            }
            self.finish_quiesced_process_root_retirement(
                retired_process,
                retired_address_space,
                &proof,
                drained,
            )
            .unwrap_or_else(|_| {
                crate::test_support::complete_fail(supervisor_evidence_detail(0xd012))
            });
            self.local.record_idle();
            return PreparedTerminalHandoff::IdleScheduler;
        }

        if retired_process != self.primordial_process {
            if crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
                != Some(self.cpu.index())
            {
                panic!("terminal idle facade resumed on another physical CPU")
            }
            let previous = self.active_root.take_process();
            if previous.cpu() != self.cpu {
                panic!("terminal idle carrier retained another CPU's Process root")
            }
            match self.active.enter_kernel_execution_root(previous) {
                Ok(kernel) => self.active_root = CarrierActiveRoot::Kernel(kernel),
                Err((error, recovered)) => {
                    self.active_root = CarrierActiveRoot::Process(recovered);
                    match error {
                        super::RootBindingError::CpuMismatch => {
                            panic!("terminal idle kernel-root handoff used the wrong CPU")
                        }
                        super::RootBindingError::RootMismatch => {
                            panic!("terminal idle kernel-root handoff differed from hardware")
                        }
                        super::RootBindingError::Resident
                        | super::RootBindingError::AlreadyActive
                        | super::RootBindingError::MutationInFlight => {
                            panic!("terminal idle kernel-root handoff retained stale residency")
                        }
                        _ => panic!("terminal idle kernel-root handoff validation failed"),
                    }
                }
            }
            let prepared = self
                .active
                .prepare_process_root_selection(
                    self.cpu,
                    self.primordial_process,
                    self.primordial_address_space,
                )
                .unwrap_or_else(|error| {
                    panic!("terminal idle publisher-root preparation failed: {error:?}")
                });
            let previous =
                match core::mem::replace(&mut self.active_root, CarrierActiveRoot::Transitioning) {
                    CarrierActiveRoot::Kernel(root) => root,
                    _ => panic!("terminal idle lost its kernel execution root"),
                };
            let selected = self
                .active
                .activate_from_kernel_execution_root(prepared, previous)
                .unwrap_or_else(|failure| {
                    let (error, prepared, previous) = failure.into_parts();
                    self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!("terminal idle publisher-root abandonment failed: {abandon:?}")
                        });
                    self.active_root = CarrierActiveRoot::Kernel(previous);
                    panic!("terminal idle publisher-root activation failed: {error:?}")
                });
            self.active_root = CarrierActiveRoot::Process(selected);
            self.finish_inactive_process_teardown(
                retired_process,
                retired_root_key,
                retired_address_space,
            )
            .unwrap_or_else(|_| panic!("idle exited Process teardown drifted"));
            let previous = self.active_root.take_process();
            match self.active.enter_kernel_execution_root(previous) {
                Ok(kernel) => self.active_root = CarrierActiveRoot::Kernel(kernel),
                Err((error, recovered)) => {
                    self.active_root = CarrierActiveRoot::Process(recovered);
                    panic!("terminal idle publisher-root release failed: {error:?}");
                }
            }
            self.process = self.primordial_process;
            self.root_key = self.primordial_root_key;
            self.local.record_idle();
            return PreparedTerminalHandoff::IdleScheduler;
        }

        #[cfg(not(any(deepwyrm_dw1d_evidence, deepwyrm_wyr1c_evidence)))]
        let completion = complete_primordial_launch(self);
        #[cfg(any(deepwyrm_dw1d_evidence, deepwyrm_wyr1c_evidence))]
        let completion = complete_resource_primordial_launch(self);
        #[cfg(all(feature = "test-support", deepwyrm_dw1c_evidence))]
        {
            if completion.is_err() {
                crate::test_support::complete_fail(self.g5_probe.failure_detail(&completion))
            }
            let completed_at_ns = crate::time::monotonic_now()
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e018));
            let snapshot = self
                .shared
                .execution
                .dw1c_final_scheduler_snapshot()
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e019));
            let permit = crate::test_support::DW1C_EVIDENCE
                .final_normal_completion(completed_at_ns, product_execution_generation, snapshot)
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e01a));
            crate::test_support::complete_dw1c_evidence(permit)
        }
        #[cfg(all(feature = "test-support", deepwyrm_dw1b_evidence))]
        {
            let primordial_normal = self.g5_probe.accepts_completion(&completion);
            let counters = self
                .shared
                .execution
                .preemption_snapshot_on(crate::cpu::CpuIndex::BOOTSTRAP)
                .counters;
            match crate::test_support::DW1B_EVIDENCE.finish(counters, primordial_normal) {
                Ok(permit) => crate::test_support::complete_dw1b_evidence(permit),
                Err(error) => crate::test_support::complete_fail(dw1b_evidence_detail(error)),
            }
        }
        #[cfg(all(feature = "test-support", deepwyrm_dw1d_evidence))]
        {
            if completion.is_err() {
                crate::test_support::complete_fail(self.g5_probe.failure_detail(&completion))
            }
            let permit = crate::test_support::DW1D_EVIDENCE
                .final_normal_completion()
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e001));
            crate::test_support::complete_dw1d_evidence(permit)
        }
        #[cfg(all(feature = "test-support", deepwyrm_wyr1c_evidence))]
        {
            let detail = if self.g5_probe.accepts_completion(&completion) {
                supervisor_evidence_detail(0xd015)
            } else {
                self.g5_probe.failure_detail(&completion)
            };
            crate::test_support::complete_fail(detail)
        }
        #[cfg(all(
            feature = "test-support",
            not(any(
                deepwyrm_dw1b_evidence,
                deepwyrm_dw1c_evidence,
                deepwyrm_dw1d_evidence,
                deepwyrm_wyr1c_evidence
            ))
        ))]
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

    #[track_caller]
    fn synchronize_scheduler_current(&mut self) {
        assert_eq!(self.local.cpu, self.cpu, "BSP carrier storage CPU drifted");
        let Some(thread) = self.shared.execution.current_thread_on(self.cpu) else {
            panic!("runtime carrier has no scheduler-current Thread");
        };
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
        if self
            .active_root
            .as_ref()
            .is_some_and(|root| root.selects_exact(self.cpu, process, address_space))
        {
            if let Err(error) = self.active.validate_current_process_root_selection(
                self.active_root.as_ref().expect("active root"),
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
            // A sibling Thread or a return to this CPU's saved carrier slot
            // retains the unique root selection token and changes only the
            // scheduler-owned execution identity. Re-activating the same
            // address space would violate the residency protocol.
            self.process = process;
            self.thread = thread;
            self.root_key = root_key;
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
            CarrierActiveRoot::Unselected => {
                match self.active.activate_process_root_selection(prepared, None) {
                    Ok(selected) => selected,
                    Err(failure) => {
                        let (error, prepared, previous) = failure.into_parts();
                        debug_assert!(previous.is_none());
                        self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!("failed first root selection could not be abandoned: {abandon:?}")
                        });
                        self.active_root = CarrierActiveRoot::Unselected;
                        panic!("could not activate first scheduler-current root: {error:?}");
                    }
                }
            }
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

    fn prepare_scheduler_root_switch(&mut self) -> Option<PreparedSchedulerRootSwitch> {
        assert_eq!(self.local.cpu, self.cpu, "carrier storage CPU drifted");
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
        let identity = SchedulerRootIdentity {
            process,
            thread,
            root_key,
            stack_id,
            context_id,
        };
        if self
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
                    panic!("retained scheduler-current root validation failed: {error:?}")
                });
            self.publish_scheduler_root_identity(identity);
            return None;
        }
        let prepared = self
            .active
            .prepare_process_root_selection(self.cpu, process, address_space)
            .unwrap_or_else(|error| panic!("could not prepare scheduler-current root: {error:?}"));
        let previous = core::mem::replace(&mut self.active_root, CarrierActiveRoot::Transitioning);
        let kind = match previous {
            CarrierActiveRoot::Unselected => self
                .active
                .prepare_process_root_switch(prepared, None)
                .map(PreparedSchedulerRootSwitchKind::Process)
                .unwrap_or_else(|failure| {
                    let (error, prepared, previous) = failure.into_parts();
                    debug_assert!(previous.is_none());
                    self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!(
                                "failed first root selection could not be abandoned: {abandon:?}"
                            )
                        });
                    self.active_root = CarrierActiveRoot::Unselected;
                    panic!("could not prepare first scheduler-current root switch: {error:?}");
                }),
            CarrierActiveRoot::Process(previous) => self
                .active
                .prepare_process_root_switch(prepared, Some(previous))
                .map(PreparedSchedulerRootSwitchKind::Process)
                .unwrap_or_else(|failure| {
                    let (error, prepared, previous) = failure.into_parts();
                    self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!("failed root selection could not be abandoned: {abandon:?}")
                        });
                    self.active_root = CarrierActiveRoot::Process(previous.unwrap_or_else(|| {
                        panic!("runtime carrier lost its Process root during switch preparation")
                    }));
                    panic!("could not prepare scheduler-current root switch: {error:?}");
                }),
            CarrierActiveRoot::Kernel(previous) => self
                .active
                .prepare_from_kernel_execution_root_switch(prepared, previous)
                .map(PreparedSchedulerRootSwitchKind::FromKernel)
                .unwrap_or_else(|failure| {
                    let (error, prepared, previous) = failure.into_parts();
                    self.active
                        .abandon_process_root_selection(prepared)
                        .unwrap_or_else(|abandon| {
                            panic!(
                                "failed kernel-root selection could not be abandoned: {abandon:?}"
                            )
                        });
                    self.active_root = CarrierActiveRoot::Kernel(previous);
                    panic!(
                        "could not prepare scheduler-current switch from kernel root: {error:?}"
                    );
                }),
            CarrierActiveRoot::StopPrecommitted(_) | CarrierActiveRoot::Transitioning => {
                panic!("runtime carrier has no stable root while preparing scheduler current")
            }
        };
        let flight = self.begin_root_switch_flight();
        Some(PreparedSchedulerRootSwitch {
            flight,
            identity,
            kind,
        })
    }

    fn commit_scheduler_root_switch(&mut self, executed: ExecutedSchedulerRootSwitch) {
        self.select_root_switch_flight(executed.flight);
        let selected = match executed.kind {
            ExecutedSchedulerRootSwitchKind::Process(executed) => {
                self.active.commit_process_root_switch(executed)
            }
            ExecutedSchedulerRootSwitchKind::FromKernel(executed) => self
                .active
                .commit_from_kernel_execution_root_switch(executed),
        };
        self.active_root = CarrierActiveRoot::Process(selected);
        self.publish_scheduler_root_identity(executed.identity);
        self.finish_root_switch_flight(executed.flight);
    }

    fn cancel_scheduler_root_switch(
        &mut self,
        failure: FailedSchedulerRootSwitch,
    ) -> super::RootBindingError {
        self.select_root_switch_flight(failure.flight);
        let error = match failure.kind {
            FailedSchedulerRootSwitchKind::Process(failure) => {
                let (error, prepared, previous) = failure.into_parts();
                self.active
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("cancelled Process root switch lost residency: {abandon:?}")
                    });
                self.active_root = previous
                    .map(CarrierActiveRoot::Process)
                    .unwrap_or(CarrierActiveRoot::Unselected);
                error
            }
            FailedSchedulerRootSwitchKind::FromKernel(failure) => {
                let (error, prepared, previous) = failure.into_parts();
                self.active
                    .abandon_process_root_selection(prepared)
                    .unwrap_or_else(|abandon| {
                        panic!("cancelled kernel-root switch lost residency: {abandon:?}")
                    });
                self.active_root = CarrierActiveRoot::Kernel(previous);
                error
            }
        };
        self.finish_root_switch_flight(failure.flight);
        error
    }

    fn publish_scheduler_root_identity(&mut self, identity: SchedulerRootIdentity) {
        self.process = identity.process;
        self.thread = identity.thread;
        self.root_key = identity.root_key;
        self.stack_id = identity.stack_id;
        self.context_id = identity.context_id;
        self.local
            .record_current(identity.thread, identity.stack_id, identity.context_id);
    }

    /// Publishes completion of the outgoing continuation only after this CPU
    /// has physically arrived on the selected destination stack.  Scheduler
    /// selection deliberately retains the suspended claim until this point so
    /// no other CPU can acquire a Runnable continuation before its saved RSP
    /// is visible.
    fn complete_physical_switch_handoff(&mut self) -> Option<crate::task::RunnablePublication> {
        if let Some(outgoing) = self.shared.execution.suspended_claim_on(self.cpu) {
            let published = self
                .shared
                .execution
                .complete_switch_on(outgoing)
                .unwrap_or_else(|error| {
                    panic!("physical kernel switch completion drifted: {error:?}")
                });
            #[cfg(deepwyrm_dw1b_evidence)]
            if let Some(expected_outgoing) = self.dw1b_preemption_outgoing[self.cpu.index()].take()
            {
                assert_eq!(expected_outgoing, outgoing.thread());
                let incoming = self
                    .shared
                    .execution
                    .current_thread_on(self.cpu)
                    .unwrap_or_else(|| panic!("selector-26 preemption completed without incoming"));
                crate::test_support::DW1B_EVIDENCE
                    .observe_completed_preemption(expected_outgoing, incoming)
                    .unwrap_or_else(|error| {
                        crate::test_support::complete_fail(dw1b_evidence_detail(error))
                    });
            }
            published
        } else {
            None
        }
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
        if self.service_state_is_quiescent() {
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
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
    }

    fn service_state_is_quiescent(&self) -> bool {
        self.services.is_quiescent() && self.wait_controls.iter().all(NativeWaitControl::is_clear)
    }

    fn stopped_service_state_is_quiescent(&self) -> bool {
        matches!(
            self.services.operation_owner(self.thread),
            Err(crate::syscall::FServiceOwnerError::Missing)
        ) && self.wait_controls[self.cpu.index()].is_clear()
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

    fn prepare_rendezvous_stop(
        &mut self,
        request: crate::arch::x86_64::rendezvous::StopRequest,
        reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> (
        crate::arch::x86_64::rendezvous::ExactSafeWitness,
        PreparedStopRootSwitch,
    ) {
        self.assert_guard_free_external_work();
        self.rendezvous_reaper = Some(reaper);
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
            assert!(matches!(self.active_root, CarrierActiveRoot::Kernel(_)));
            return PreparedRendezvousNext::Idle;
        };
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
        PreparedRendezvousNext::Scheduled {
            stack,
            continuation,
        }
    }

    fn terminate_exception(&mut self, exception: crate::task::TaskExceptionRecord) {
        assert!(
            self.deferred_currents[self.cpu.index()].is_none(),
            "primordial runtime already owns deferred current resources"
        );
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.services.terminal_cleanup(
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
            crate::syscall::process_unhandled_exception_on(
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.cpu,
                self.process,
                self.thread,
                exception,
                &mut self.cleanup,
            )
        };
        assert_eq!(status, DW_STATUS_SUCCESS);
        assert_eq!(control, SyscallControl::TerminateCurrent);
        self.install_deferred_current(
            deferred.expect("primordial exception omitted deferred current resources"),
        );
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("primordial exception output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("primordial exception atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
    }

    fn prepare_remote_process_exception(
        &mut self,
        exception: crate::task::TaskExceptionRecord,
    ) -> ProcessTerminationPreparation {
        let inspected_threads = self
            .tasks
            .process_thread_keys(self.process)
            .unwrap_or_else(|_| panic!("exception Process lost its Thread topology"));
        let plan = match self.terminal_stop_plan(&inspected_threads) {
            Ok(plan) => plan,
            Err(()) => return ProcessTerminationPreparation::Retry,
        };
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
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
    ) -> Result<crate::syscall::PreparedProcessTermination<HANDLES, THREADS>, deepwyrm_abi::DwStatus>
    {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.services.terminal_cleanup(
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
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("exception terminal output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("exception terminal atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
        result
    }

    fn unmap_primordial_userspace(
        &mut self,
        proof: &crate::task::ProcessQuiescenceProof,
    ) -> Result<(), ()> {
        self.unmap_current_userspace(
            self.primordial_process,
            self.primordial_root_key,
            self.primordial_address_space,
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
        self.active
            .validate_current_process_root_selection(
                self.active_root.as_ref().ok_or(())?,
                process,
                address_space,
            )
            .map_err(|_| ())?;
        if self.process != process || self.root_key != root_key {
            return Err(());
        }
        let mut user = self
            .active
            .current_process_address_space(self.active_root.as_ref().ok_or(())?, process);
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
                            "current process mapping teardown diverged: {:?}",
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
        self.finish_quiesced_process_root_retirement(process, address_space, &proof, drained)?;
        #[cfg(deepwyrm_dw1b_evidence)]
        crate::test_support::DW1B_EVIDENCE
            .observe_reaped_process(process)
            .unwrap_or_else(|error| {
                crate::test_support::complete_fail(dw1b_evidence_detail(error))
            });
        Ok(())
    }

    fn finish_quiesced_process_root_retirement(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
        proof: &crate::task::ProcessQuiescenceProof,
        drained: crate::task::BlockedOperationsDrained,
    ) -> Result<(), ()> {
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
                proof,
                self.shared.execution.blocked_operations(),
                drained,
            )
            .map_err(|_| ())?;
        self.cleanup
            .push_optional(self.registry.release_internal(root_pin).map_err(|_| ())?);
        self.drain_finalizers()?;
        #[cfg(deepwyrm_dw1d_evidence)]
        crate::test_support::DW1D_EVIDENCE
            .observe_process_reaped(process)
            .unwrap_or_else(|error| {
                panic!("selector-30 Process reap observation failed: {error:?}")
            });
        #[cfg(deepwyrm_dw1c_evidence)]
        crate::test_support::DW1C_EVIDENCE
            .observe_process_reap(process, process.object_id().generation(), 1)
            .unwrap_or_else(|error| {
                panic!("selector-28 Process REAP observation failed: {error:?}")
            });
        Ok(())
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

    #[cfg(any(
        deepwyrm_wyr1_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_wyr1c_evidence
    ))]
    fn enable_wyr1_reporter_after_retirement(&mut self) -> Result<(), ()> {
        let reporter = self.evidence_init_process.ok_or(())?;
        #[cfg(any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
        let reporter_thread = self.evidence_init_thread.unwrap_or_else(|| {
            crate::test_support::complete_fail(wyr1b_submit_detail(
                crate::test_support::Wyr1bEvidenceError::StartupMissing,
            ))
        });
        #[cfg(any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
        let reporter_root = self
            .tasks
            .root_region(reporter)
            .unwrap_or_else(|_| {
                crate::test_support::complete_fail(wyr1b_submit_detail(
                    crate::test_support::Wyr1bEvidenceError::StartupRoot,
                ))
            })
            .map(crate::memory::address_region::AddressRegionObjectKey::from_object_id)
            .unwrap_or_else(|| {
                crate::test_support::complete_fail(wyr1b_submit_detail(
                    crate::test_support::Wyr1bEvidenceError::StartupRoot,
                ))
            });
        if reporter == self.primordial_process
            || self
                .tasks
                .process_quiescence_proof(self.primordial_process)
                .is_err()
            || self
                .tasks
                .root_region(self.primordial_process)
                .map_err(|_| ())?
                .is_some()
            || self.tasks.process_lifecycle(reporter)
                != Ok(ProcessLifecycleState::AcceptingOperations)
        {
            return Err(());
        }
        for reference in [self.kernel_peer.take(), self.process_monitor.take()]
            .into_iter()
            .flatten()
        {
            self.cleanup
                .push_optional(self.registry.release_handle(reference).map_err(|_| ())?);
        }
        self.drain_finalizers()?;
        #[cfg(deepwyrm_wyr1_evidence)]
        crate::test_support::WYR1_EVIDENCE
            .bind_reporter_after_retirement(
                reporter,
                crate::test_support::Wyr1RetirementFacts {
                    process_quiesced: true,
                    root_region_retired: true,
                    monitor_and_kernel_peer_released: self.kernel_peer.is_none()
                        && self.process_monitor.is_none(),
                    finalizers_drained: self.cleanup.is_empty(),
                    private_primordial_pml4_retained: true,
                },
            )
            .map_err(|_| ())?;
        #[cfg(deepwyrm_wyr1b_evidence)]
        crate::test_support::WYR1B_EVIDENCE
            .bind_reporter_after_retirement(
                reporter,
                reporter_thread,
                reporter_root,
                crate::test_support::Wyr1bRetirementFacts {
                    process_quiesced: true,
                    root_region_retired: true,
                    monitor_and_kernel_peer_released: self.kernel_peer.is_none()
                        && self.process_monitor.is_none(),
                    finalizers_drained: self.cleanup.is_empty(),
                    // The architecture owns the primordial bootstrap PML4 for
                    // the boot lifetime; all user mappings/root authority are
                    // gone, but this private table is intentionally retained.
                    private_primordial_pml4_retained: true,
                },
            )
            .unwrap_or_else(|error| crate::test_support::complete_fail(wyr1b_submit_detail(error)));
        #[cfg(deepwyrm_wyr1c_evidence)]
        crate::test_support::WYR1C_EVIDENCE
            .bind_reporter_after_retirement(
                reporter,
                reporter_thread,
                reporter_root,
                crate::test_support::Wyr1bRetirementFacts {
                    process_quiesced: true,
                    root_region_retired: true,
                    monitor_and_kernel_peer_released: self.kernel_peer.is_none()
                        && self.process_monitor.is_none(),
                    finalizers_drained: self.cleanup.is_empty(),
                    private_primordial_pml4_retained: true,
                },
            )
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x2910_e010));
        Ok(())
    }

    #[cfg(any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
    fn observe_wyr1b_system_init_start(
        &mut self,
    ) -> Result<(), crate::test_support::Wyr1bEvidenceError> {
        #[cfg(deepwyrm_wyr1b_evidence)]
        use crate::test_support::WYR1B_EVIDENCE;
        use crate::test_support::{
            WYR1B_SYSTEM_INIT_GUARD_START, WYR1B_SYSTEM_INIT_STACK_BOTTOM, Wyr1bEvidenceError,
            Wyr1bReporterStartFacts,
        };

        if self.evidence_init_thread.is_some() {
            return Ok(());
        }
        let Some(reporter_process) = self.evidence_init_process else {
            return Ok(());
        };
        let mut started = None;
        for thread in self
            .tasks
            .process_thread_keys(reporter_process)
            .map_err(|_| Wyr1bEvidenceError::StartupRoot)?
            .into_iter()
            .flatten()
        {
            let Some(start) = self
                .tasks
                .thread_start_state(thread)
                .map_err(|_| Wyr1bEvidenceError::StartupRoot)?
            else {
                continue;
            };
            if started.replace((thread, start)).is_some() {
                return Err(Wyr1bEvidenceError::StartupDuplicate);
            }
        }
        let Some((reporter_thread, start)) = started else {
            return Ok(());
        };
        let reporter_root = self
            .tasks
            .root_region(reporter_process)
            .map_err(|_| Wyr1bEvidenceError::StartupRoot)?
            .map(crate::memory::address_region::AddressRegionObjectKey::from_object_id)
            .ok_or(Wyr1bEvidenceError::StartupRoot)?;
        let root_owned_by_reporter =
            self.regions.region_process(reporter_root) == Ok(reporter_process);
        let region = self
            .regions
            .region(reporter_root)
            .map_err(|_| Wyr1bEvidenceError::StartupRoot)?;
        let mappings = region.mappings();
        let entry_mapping_bound = mappings.iter().flatten().any(|mapping| {
            mapping.virtual_start() <= start.entry()
                && mapping
                    .virtual_start()
                    .checked_add(mapping.byte_len())
                    .is_some_and(|end| start.entry() < end)
                && mapping.protection() == Protection::READ_EXECUTE
        });
        let stack_mapping = mappings.iter().flatten().find(|mapping| {
            mapping.virtual_start() < start.stack_pointer()
                && mapping
                    .virtual_start()
                    .checked_add(mapping.byte_len())
                    .is_some_and(|end| start.stack_pointer() <= end)
        });
        let (stack_mapping_start, stack_mapping_bytes, stack_mapping_rw_nx) = stack_mapping
            .map(|mapping| {
                (
                    mapping.virtual_start(),
                    mapping.byte_len(),
                    mapping.protection() == Protection::READ_WRITE,
                )
            })
            .unwrap_or((0, 0, false));
        let guard_absent = mappings.iter().flatten().all(|mapping| {
            mapping
                .virtual_start()
                .checked_add(mapping.byte_len())
                .is_some_and(|end| {
                    end <= WYR1B_SYSTEM_INIT_GUARD_START
                        || mapping.virtual_start() >= WYR1B_SYSTEM_INIT_STACK_BOTTOM
                })
        });
        let facts = Wyr1bReporterStartFacts {
            reporter_process,
            reporter_thread,
            reporter_root,
            root_owned_by_reporter,
            entry_point: start.entry(),
            entry_mapping_bound,
            stack_pointer: start.stack_pointer(),
            stack_mapping_start,
            stack_mapping_bytes,
            stack_mapping_rw_nx,
            guard_absent,
        };
        #[cfg(deepwyrm_wyr1b_evidence)]
        WYR1B_EVIDENCE.observe_reporter_start(facts)?;
        #[cfg(deepwyrm_wyr1c_evidence)]
        crate::test_support::WYR1C_EVIDENCE
            .observe_reporter_start(facts)
            .map_err(|_| Wyr1bEvidenceError::StartupRoot)?;
        self.evidence_init_thread = Some(reporter_thread);
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
                    )
                    .with_device_resources(&self.shared.device_resources)
                    .with_boot_resource_grants(&self.shared.boot_resource_grants)
                    .with_interrupts(&self.shared.interrupts, &self.shared.interrupt_platform);
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

    fn service_pending_timer_expiries_on_bootstrap(&mut self) {
        assert_eq!(
            self.cpu,
            crate::cpu::CpuIndex::BOOTSTRAP,
            "general Timer expiry service escaped CPU0 ownership"
        );
        let pending = {
            let mut inbox = self.shared.timer_expiries.lock();
            core::mem::replace(&mut *inbox, [None; crate::time::DEADLINE_QUEUE_CAPACITY])
        };
        for token in pending.into_iter().flatten() {
            let wakes = self
                .shared
                .timers
                .expire(token, &self.shared.waits)
                .unwrap_or_else(|error| panic!("primordial timer expiry drifted: {error:?}"));
            crate::syscall::complete_wait_wakes(
                &mut self.registry,
                &self.shared.execution,
                wakes,
                &mut self.cleanup,
            );
        }
        self.drain_finalizers()
            .unwrap_or_else(|_| panic!("timer expiry could not drain wake pins"));
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

    fn finish_terminal_teardown(&mut self) -> Result<(), u32> {
        let service_residue = self.services.quiescence_residue();
        if service_residue != 0 {
            return Err(0x7000_0100_u32 | service_residue);
        }
        if let Some(cpu) = self
            .wait_controls
            .iter()
            .position(|control| !control.is_clear())
        {
            return Err(0x7000_0110_u32 | u32::try_from(cpu).unwrap_or(u32::MAX));
        }
        if self.shared.execution.scheduler_state(self.thread).is_some() {
            return Err(0x7000_0102_u32);
        }
        if self
            .shared
            .execution
            .blocked_operations()
            .has_thread(self.thread)
        {
            return Err(0x7000_0103_u32);
        }
        let proof = self
            .tasks
            .process_quiescence_proof(self.process)
            .map_err(|_| 0x7000_0002_u32)?;
        let drained = self
            .shared
            .execution
            .blocked_operations_drained(&self.tasks, &proof)
            .map_err(|_| 0x7000_0003_u32)?;
        let address_space = self
            .regions
            .region(self.root_key)
            .map_err(|_| 0x7000_0004_u32)?
            .address_space_key();
        if self.process == self.primordial_process {
            self.unmap_primordial_userspace(&proof)
                .map_err(|_| 0x7000_0005_u32)?;
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
                .map_err(|_| 0x7000_0006_u32)?;
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
                    return Err(0x7000_0007_u32);
                }
            };
            self.active_root = CarrierActiveRoot::Process(selected);
            self.unmap_inactive_userspace(self.process, self.root_key, &proof)
                .map_err(|_| 0x7000_0008_u32)?;
            self.active
                .teardown_empty_child_address_space(self.process, address_space)
                .map_err(|_| 0x7000_0009_u32)?;
        }
        if self.memory.active_lease_count() != 0 {
            return Err(0x7000_000a_u32);
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
            .map_err(|_| 0x7000_000b_u32)?;
        self.cleanup.push_optional(
            self.registry
                .release_internal(root_pin)
                .map_err(|_| 0x7000_000c_u32)?,
        );
        self.release_terminal_authority()
            .map_err(|_| 0x7000_000d_u32)?;
        self.drain_finalizers().map_err(|_| 0x7000_000e_u32)?;
        if self.shared.boot_resource_grants.has_grants() {
            let owner = self
                .shared
                .boot_resource_grants
                .take_owner_if_all_grants_available()
                .map_err(|_| 0x7000_000e_u32)?;
            self.cleanup.push_optional(
                self.registry
                    .release_internal(owner)
                    .map_err(|_| 0x7000_000e_u32)?,
            );
            self.drain_finalizers().map_err(|_| 0x7000_000e_u32)?;
        }
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
            return Err(0x7000_000f_u32);
        }
        self.prove_registry_capacity().map_err(|_| 0x7000_0010_u32)
    }

    /// Selector-24-only join between the Wyrmroot controller and the host
    /// evidence parser. The kernel validates framing and preserves raw bytes;
    /// it does not originate or interpret capability facts.
    #[cfg(all(feature = "test-support", deepwyrm_wrcap_relay))]
    fn drain_wrcap_record(&mut self) {
        use crate::test_support::{WRCAP_RECORD_LEN, WRCAP_RELAY, WrcapDrainAction};

        let info = match self.shared.channels.peek_receive(self.channel_keys[0]) {
            Ok(info) => info,
            Err(ChannelError::WouldBlock) => return,
            Err(_) => {
                let _ = WRCAP_RELAY.reject_receive();
                return;
            }
        };
        match WRCAP_RELAY.drain_action(info.required_bytes, info.required_handles) {
            WrcapDrainAction::Drain => {}
            WrcapDrainAction::LeaveForReady => return,
            WrcapDrainAction::Reject => {
                let _ = WRCAP_RELAY.reject_receive();
                return;
            }
        }

        let mut record = [0_u8; WRCAP_RECORD_LEN];
        let (bytes, wakes) = match self.shared.channels.receive_into(
            self.channel_keys[0],
            &mut record,
            &self.shared.waits,
        ) {
            Ok(received) => received,
            Err(_) => {
                let _ = WRCAP_RELAY.reject_receive();
                return;
            }
        };
        crate::syscall::complete_wait_wakes(
            &mut self.registry,
            &self.shared.execution,
            wakes,
            &mut self.cleanup,
        );
        let _ = WRCAP_RELAY.record(&record[..bytes]);
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
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> PrimordialCompletionBackend
    for PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = u32;

    fn receive_ready(&mut self, output: &mut [u8; 40]) -> Result<usize, Self::Error> {
        let (bytes, wakes) = self
            .shared
            .channels
            .receive_into(self.channel_keys[0], output, &self.shared.waits)
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
            .tasks
            .process_info(self.process)
            .map_err(|_| 0x7200_0001_u32)?;
        #[cfg(feature = "test-support")]
        self.g5_probe.observe_terminal(info);
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
        let suspended = self.shared.execution.suspended_claim_on(self.cpu);
        let running = self.shared.execution.running_claim_on(self.cpu);
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
            .active_root
            .as_ref()
            .ok_or(crate::arch::x86_64::rendezvous::RemoteStopError::UnsafePrecommit)?;
        let scheduler_current_matches = !was_suspended
            && self.shared.execution.current_thread_on(self.cpu) == Some(self.thread);
        // A block commit may have selected a logical replacement, but it has
        // not yet switched the physical carrier when this post-hlt e1 gate
        // runs. The CPU-private local record is the authoritative proof that
        // no replacement is executing on this stack/carrier.
        let suspended_carrier_matches =
            was_suspended && self.local.physically_executes(self.thread);
        if crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
            != Some(self.cpu.index())
            || identity.target_cpu() != self.cpu.index()
            || identity.cpu_online_generation() != snapshot.online_generation
            || identity.thread() != self.thread
            || identity.execution_generation() != claim.generation()
            || identity.root_binding_generation() != root.binding_generation()
            || claim.thread() != self.thread
            || !(scheduler_current_matches || suspended_carrier_matches)
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
            let control = &mut self.wait_controls[self.cpu.index()];
            self.services
                .retire_idle_control_for_stop(control, self.thread, claim.generation())
                .unwrap_or_else(|_| {
                    panic!("remote stop suspended idle control drifted before precommit")
                });
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
            let cancelled_quantum = self
                .shared
                .execution
                .stop_running_claim_on(claim)
                .unwrap_or_else(|error| {
                    panic!("remote stop Running claim drifted after precommit: {error:?}")
                });
            self.stage_local_scheduler_quantum_cancellation(cancelled_quantum);
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
        let stopped = self
            .stopping_claim
            .unwrap_or_else(|| panic!("remote stop cleanup omitted its exact stopped claim"));
        self.cleanup.is_empty()
            && self.rendezvous_cleanup.is_some()
            && self.stopped_service_state_is_quiescent()
            && self.deferred_currents[self.cpu.index()].is_none()
            && self
                .shared
                .execution
                .running_claim_on(self.cpu)
                .is_none_or(|running| running.thread() != stopped.thread())
    }
}

#[allow(
    unsafe_code,
    reason = "the target runtime propagates the physical-current carrier and architecture-owned first-run entry"
)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallFrameRuntime
    for PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn publish_quantum_expiry(
        &mut self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<bool, crate::task::SchedulerError> {
        self.shared.execution.publish_quantum_expiry(ticket)
    }

    fn prepare_quantum(
        &mut self,
        now_ns: u64,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, crate::task::SchedulerError> {
        self.shared
            .execution
            .prepare_quantum_if_needed_on(self.cpu, now_ns)
    }

    fn has_reschedule_request(&mut self) -> bool {
        self.shared.execution.has_reschedule_request_on(self.cpu)
    }

    fn authorize_timer_return(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawCpl3TimerReturnFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        if self.tasks.thread_process(self.thread) != Ok(self.process)
            || self.shared.execution.current_thread_on(self.cpu) != Some(self.thread)
        {
            return Err(crate::arch::x86_64::syscall::UserReturnError::BindingChanged);
        }
        let mut mappings = self.active.current_process_address_space(
            self.active_root.as_ref().expect("active root"),
            self.process,
        );
        frame.validate_and_sanitize(&mut mappings)
    }

    unsafe fn prepare_preemption<'owner>(
        &'owner mut self,
    ) -> crate::syscall::native::NativePreemptionPlan<'owner> {
        unsafe { self.prepare_preemption_stationary() }
    }

    fn resume_timer_preemption(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawCpl3TimerReturnFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        self.synchronize_scheduler_current();
        let publication = self.complete_physical_switch_handoff();
        crate::task::notify_completed_switch_runnable(publication);
        self.authorize_timer_return(frame)
    }

    fn resume_syscall_preemption(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> Result<(), crate::arch::x86_64::syscall::UserReturnError> {
        self.synchronize_scheduler_current();
        let publication = self.complete_physical_switch_handoff();
        crate::task::notify_completed_switch_runnable(publication);
        let current_binding_generation = crate::arch::x86_64::syscall::current_binding_generation();
        frame.rebind_after_kernel_resume(current_binding_generation)?;
        self.authorize_return(frame, current_binding_generation)
    }

    #[cfg(deepwyrm_wyr1_evidence)]
    fn intercept_wyr1_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        use crate::test_support::{WYR1_EVIDENCE, WYR1_EVIDENCE_RECORD_LEN, Wyr1EvidenceSubmit};

        let values = arguments.as_array();
        if values[1] != WYR1_EVIDENCE_RECORD_LEN as u64
            || values[2..].iter().any(|value| *value != 0)
        {
            crate::test_support::complete_fail(0x2510_e001)
        }
        let phase = self.reserve_runtime_phase();
        WYR1_EVIDENCE
            .authorize_submission(self.process)
            .unwrap_or_else(|error| crate::test_support::complete_fail(wyr1_submit_detail(error)));
        let record = {
            let mut user = self.active.current_process_address_space(
                self.active_root.as_ref().expect("active root"),
                self.process,
            );
            match crate::syscall::copy_wyr1_evidence_input::<_, WYR1_EVIDENCE_RECORD_LEN>(
                &mut user,
                deepwyrm_abi::DwUserAddress(values[0]),
            ) {
                Ok(record) => record,
                Err(_) => crate::test_support::complete_fail(0x2510_e002),
            }
        };
        self.commit_runtime_phase(phase);
        match WYR1_EVIDENCE.submit(self.process, &record) {
            Ok(Wyr1EvidenceSubmit::Accepted) => NativeSyscallResult::returning(DW_STATUS_SUCCESS),
            Ok(Wyr1EvidenceSubmit::Terminal(permit)) => {
                crate::test_support::complete_wyr1_evidence(permit)
            }
            Err(error) => crate::test_support::complete_fail(wyr1_submit_detail(error)),
        }
    }

    #[cfg(deepwyrm_wyr1b_evidence)]
    fn intercept_wyr1b_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        use crate::test_support::{WYR1B_EVIDENCE, WYR1B_EVIDENCE_RECORD_LEN, Wyr1bEvidenceSubmit};

        let values = arguments.as_array();
        if values[1] != WYR1B_EVIDENCE_RECORD_LEN as u64
            || values[2..].iter().any(|value| *value != 0)
        {
            crate::test_support::complete_fail(0x2710_e001)
        }
        let phase = self.reserve_runtime_phase();
        WYR1B_EVIDENCE
            .authorize_submission(self.process)
            .unwrap_or_else(|error| crate::test_support::complete_fail(wyr1b_submit_detail(error)));
        let record = {
            let mut user = self.active.current_process_address_space(
                self.active_root.as_ref().expect("active root"),
                self.process,
            );
            match crate::syscall::copy_wyr1b_evidence_input::<_, WYR1B_EVIDENCE_RECORD_LEN>(
                &mut user,
                deepwyrm_abi::DwUserAddress(values[0]),
            ) {
                Ok(record) => record,
                Err(_) => crate::test_support::complete_fail(0x2710_e002),
            }
        };
        self.commit_runtime_phase(phase);
        match WYR1B_EVIDENCE.submit(self.process, &record) {
            Ok(Wyr1bEvidenceSubmit::Accepted) => NativeSyscallResult::returning(DW_STATUS_SUCCESS),
            Ok(Wyr1bEvidenceSubmit::Terminal(permit)) => {
                crate::test_support::complete_wyr1b_evidence(permit)
            }
            Err(error) => crate::test_support::complete_fail(wyr1b_submit_detail(error)),
        }
    }

    #[cfg(deepwyrm_wyr1c_evidence)]
    fn intercept_wyr1c_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        use crate::test_support::{WYR1C_EVIDENCE, WYR1C_EVIDENCE_RECORD_LEN, Wyr1cEvidenceSubmit};

        let values = arguments.as_array();
        if values[1] != WYR1C_EVIDENCE_RECORD_LEN as u64
            || values[2..].iter().any(|value| *value != 0)
        {
            crate::test_support::complete_fail(0x2910_e001)
        }
        let phase = self.reserve_runtime_phase();
        WYR1C_EVIDENCE
            .authorize_submission(self.process)
            .unwrap_or_else(|error| crate::test_support::complete_fail(wyr1c_submit_detail(error)));
        let record = {
            let mut user = self.active.current_process_address_space(
                self.active_root.as_ref().expect("active root"),
                self.process,
            );
            match crate::syscall::copy_wyr1c_evidence_input::<_, WYR1C_EVIDENCE_RECORD_LEN>(
                &mut user,
                deepwyrm_abi::DwUserAddress(values[0]),
            ) {
                Ok(record) => record,
                Err(_) => crate::test_support::complete_fail(0x2910_e002),
            }
        };
        self.commit_runtime_phase(phase);
        match WYR1C_EVIDENCE.submit(self.process, &record) {
            Ok(Wyr1cEvidenceSubmit::Accepted) => NativeSyscallResult::returning(DW_STATUS_SUCCESS),
            Ok(Wyr1cEvidenceSubmit::Terminal(permit)) => {
                crate::test_support::complete_wyr1c_evidence(permit)
            }
            Err(error) => crate::test_support::complete_fail(wyr1c_submit_detail(error)),
        }
    }

    #[cfg(deepwyrm_dw1b_evidence)]
    fn intercept_dw1b_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        use crate::test_support::{
            DW1B_EVIDENCE, Dw1bRawOperation, Dw1bSubjects, arm_thread_states_valid,
            exact_single_thread,
        };

        let operation = Dw1bRawOperation::decode(arguments.as_array())
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x2610_e001));
        let phase = self.reserve_runtime_phase();
        match operation {
            Dw1bRawOperation::Arm {
                hog_handle,
                progress_handle,
            } => {
                if self.cpu != crate::cpu::CpuIndex::BOOTSTRAP
                    || self.evidence_init_process != Some(self.process)
                    || self.shared.execution.current_thread_on(self.cpu) != Some(self.thread)
                    || self.tasks.thread_process(self.thread) != Ok(self.process)
                    || self.shared.execution.scheduler_state(self.thread)
                        != Some(SchedulerThreadState::Running)
                {
                    crate::test_support::complete_fail(0x2610_e002)
                }
                let handles = self
                    .tasks
                    .process_handles(self.process)
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2610_e003));
                let hog_process = handles
                    .process_target_for_dw1b_evidence(deepwyrm_abi::DwHandle(hog_handle))
                    .map(ProcessKey::from_object_id)
                    .unwrap_or_else(|| crate::test_support::complete_fail(0x2610_e004));
                let progress_process = handles
                    .process_target_for_dw1b_evidence(deepwyrm_abi::DwHandle(progress_handle))
                    .map(ProcessKey::from_object_id)
                    .unwrap_or_else(|| crate::test_support::complete_fail(0x2610_e005));
                if self.tasks.process_lifecycle(hog_process)
                    != Ok(ProcessLifecycleState::AcceptingOperations)
                    || self.tasks.process_lifecycle(progress_process)
                        != Ok(ProcessLifecycleState::AcceptingOperations)
                {
                    crate::test_support::complete_fail(0x2610_e006)
                }
                let hog_thread = exact_single_thread(
                    self.tasks
                        .process_thread_keys(hog_process)
                        .unwrap_or_else(|_| crate::test_support::complete_fail(0x2610_e007)),
                )
                .unwrap_or_else(|| crate::test_support::complete_fail(0x2610_e008));
                let progress_thread = exact_single_thread(
                    self.tasks
                        .process_thread_keys(progress_process)
                        .unwrap_or_else(|_| crate::test_support::complete_fail(0x2610_e009)),
                )
                .unwrap_or_else(|| crate::test_support::complete_fail(0x2610_e00a));
                if !arm_thread_states_valid(
                    self.shared.execution.scheduler_state(hog_thread),
                    self.shared.execution.scheduler_state(progress_thread),
                ) {
                    crate::test_support::complete_fail(0x2610_e00b)
                }
                let snapshot = self.shared.execution.preemption_snapshot_on(self.cpu);
                if snapshot.counters.overflow_fault
                    || snapshot.running.map(|claim| claim.thread()) != Some(self.thread)
                {
                    crate::test_support::complete_fail(0x2610_e00c)
                }
                DW1B_EVIDENCE
                    .arm(
                        Dw1bSubjects {
                            reporter_process: self.process,
                            reporter_thread: self.thread,
                            hog_process,
                            hog_thread,
                            progress_process,
                            progress_thread,
                        },
                        snapshot.counters,
                    )
                    .unwrap_or_else(|error| {
                        crate::test_support::complete_fail(dw1b_evidence_detail(error))
                    });
            }
            Dw1bRawOperation::Progress {
                exchange_count,
                digest,
            } => {
                DW1B_EVIDENCE
                    .progress(self.process, exchange_count, digest)
                    .unwrap_or_else(|error| {
                        crate::test_support::complete_fail(dw1b_evidence_detail(error))
                    });
            }
        }
        self.commit_runtime_phase(phase);
        NativeSyscallResult::returning(DW_STATUS_SUCCESS)
    }

    #[cfg(deepwyrm_dw1c_evidence)]
    fn intercept_dw1c_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        use crate::test_support::{
            DW1C_ARM_BYTES, DW1C_ARM_TIMEOUT_SECONDS, DW1C_EVIDENCE, DW1C_PROGRESS_MASK, Dw1cActor,
        };

        let values = arguments.as_array();
        let arm_started_ns = if values[0] == 1 {
            Some(
                crate::time::monotonic_now()
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e018)),
            )
        } else {
            None
        };
        let phase = self.reserve_runtime_phase();
        match values[0] {
            1 => {
                if !self.dw1c_controller_authorized()
                    || values[2] != 10
                    || values[3] != DW1C_ARM_TIMEOUT_SECONDS
                    || values[4] != 0
                    || values[5] != 0
                {
                    crate::test_support::complete_fail(0x2810_e001)
                }
                // Authority is checked before usercopy.  The copied handles are
                // inspected only; no handle/object reference is retained.
                let bytes = {
                    let mut user = self.active.current_process_address_space(
                        self.active_root.as_ref().expect("active root"),
                        self.process,
                    );
                    crate::syscall::copy_dw1c_evidence_input::<_, DW1C_ARM_BYTES>(
                        &mut user,
                        deepwyrm_abi::DwUserAddress(values[1]),
                    )
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e002))
                };
                if !self.dw1c_controller_authorized() {
                    crate::test_support::complete_fail(0x2810_e003)
                }
                let product_claim = self
                    .shared
                    .execution
                    .running_claim_on(self.cpu)
                    .filter(|claim| claim.thread() == self.thread)
                    .unwrap_or_else(|| crate::test_support::complete_fail(0x2810_e019));
                let product_execution_generation = product_claim.generation();
                let entries = crate::test_support::decode_dw1c_arm_entries(&bytes)
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e004));
                let handles = self
                    .tasks
                    .process_handles(self.process)
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e005));
                let actors = core::array::from_fn(|index| {
                    let (token, role, handle) = entries[index];
                    let expected = (index + 1) as u64;
                    if token != expected || role != expected {
                        crate::test_support::complete_fail(0x2810_e006)
                    }
                    let process = handles
                        .process_target_for_dw1c_evidence(deepwyrm_abi::DwHandle(handle))
                        .map(ProcessKey::from_object_id)
                        .unwrap_or_else(|| crate::test_support::complete_fail(0x2810_e016));
                    if self.tasks.process_lifecycle(process)
                        != Ok(ProcessLifecycleState::AcceptingOperations)
                    {
                        crate::test_support::complete_fail(0x2810_e007)
                    }
                    let threads = self
                        .tasks
                        .process_thread_keys(process)
                        .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e008));
                    let mut exact = None;
                    for thread in threads.into_iter().flatten() {
                        if exact.replace(thread).is_some() {
                            crate::test_support::complete_fail(0x2810_e009)
                        }
                    }
                    let thread =
                        exact.unwrap_or_else(|| crate::test_support::complete_fail(0x2810_e00a));
                    let generation = self
                        .shared
                        .execution
                        .current_execution_generation(thread)
                        .unwrap_or_else(|| crate::test_support::complete_fail(0x2810_e00b));
                    Dw1cActor {
                        token: token as u8,
                        role: role as u8,
                        process,
                        thread,
                        execution_generation: generation,
                    }
                });
                let fixture_actors =
                    core::array::from_fn(|index| crate::task::Dw1cSchedulerActorIdentity {
                        thread: actors[index].thread,
                        execution_generation: actors[index].execution_generation,
                    });
                match self
                    .shared
                    .execution
                    .install_dw1c_scheduler_fixture(product_claim, fixture_actors)
                {
                    Ok(()) => {}
                    Err(crate::task::SchedulerError::ContinuationOwned) => {
                        self.shared
                            .execution
                            .stage_dw1c_arm_retry_wake(fixture_actors);
                        self.commit_runtime_phase(phase);
                        return NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK);
                    }
                    Err(_) => crate::test_support::complete_fail(0x2810_e017),
                }
                DW1C_EVIDENCE
                    .arm(
                        (self.process, self.thread),
                        product_execution_generation,
                        actors,
                        arm_started_ns.expect("ARM sampled time before runtime authority"),
                    )
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e00c));
            }
            2 => {
                if values[4] != 0 || values[5] != 0 {
                    crate::test_support::complete_fail(0x2810_e010)
                }
                DW1C_EVIDENCE
                    .progress(self.process, values[1], values[2], values[3])
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e011));
            }
            3 => {
                if !self.dw1c_controller_authorized() || values[3..].iter().any(|value| *value != 0)
                {
                    crate::test_support::complete_fail(0x2810_e012)
                }
                if values[1] != u64::from(DW1C_PROGRESS_MASK) {
                    crate::test_support::complete_fail(0x2810_e013)
                }
                DW1C_EVIDENCE
                    .workload_complete(self.process, values[1], values[2])
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x2810_e014));
            }
            4 => {
                if !self.dw1c_controller_authorized() || values[1..].iter().any(|value| *value != 0)
                {
                    crate::test_support::complete_fail(0x2810_e01a)
                }
                if !self.shared.execution.dw1c_token2_relay_ready() {
                    self.commit_runtime_phase(phase);
                    return NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK);
                }
            }
            _ => crate::test_support::complete_fail(0x2810_e015),
        }
        self.commit_runtime_phase(phase);
        NativeSyscallResult::returning(DW_STATUS_SUCCESS)
    }

    #[cfg(deepwyrm_dw1d_evidence)]
    fn intercept_dw1d_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        use crate::test_support::{DW1D_EVIDENCE, Dw1dDeliverPlan, Dw1dRawOperation};

        let operation = DW1D_EVIDENCE
            .decode_raw(arguments.as_array())
            .unwrap_or_else(|error| crate::test_support::complete_fail(0x3010_e100 | error as u32));
        let phase = self.reserve_runtime_phase();
        let status = match operation {
            Dw1dRawOperation::Arm {
                owner_handle,
                trigger_handle,
            } => {
                if !self.dw1d_controller_authorized() {
                    crate::test_support::complete_fail(0x3010_e101)
                }
                let owner = self.dw1d_process_handle(owner_handle);
                let trigger = self.dw1d_process_handle(trigger_handle);
                if self.tasks.process_lifecycle(owner)
                    != Ok(ProcessLifecycleState::AcceptingOperations)
                    || self.tasks.process_lifecycle(trigger)
                        != Ok(ProcessLifecycleState::AcceptingOperations)
                {
                    crate::test_support::complete_fail(0x3010_e102)
                }
                let resource_domain = self
                    .shared
                    .boot_resource_grants
                    .owner_key()
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e103));
                let owner_in_resource_domain = self
                    .tasks
                    .prepare_resource_claim_membership(owner, resource_domain)
                    .is_ok();
                let trigger_outside_resource_domain = self
                    .tasks
                    .prepare_resource_claim_membership(trigger, resource_domain)
                    == Err(crate::task::ResourceClaimMembershipError::AccessDenied);
                DW1D_EVIDENCE
                    .arm(
                        self.process,
                        owner,
                        trigger,
                        owner_in_resource_domain,
                        trigger_outside_resource_domain,
                    )
                    .unwrap_or_else(|error| {
                        crate::test_support::complete_fail(0x3010_e110 | error as u32)
                    });
                DW_STATUS_SUCCESS
            }
            Dw1dRawOperation::Bind {
                interrupt_handle,
                lease_generation,
            } => {
                let resolved = self
                    .tasks
                    .process_handles(self.process)
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e120))
                    .lookup(
                        &mut self.registry,
                        deepwyrm_abi::DwHandle(interrupt_handle),
                        crate::handle::AcceptedObjectTypes::One(
                            deepwyrm_abi::DW_OBJECT_TYPE_INTERRUPT,
                        ),
                        deepwyrm_abi::DW_RIGHT_INSPECT,
                    )
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e121));
                let object = resolved.object_id();
                let info = crate::device::InterruptInfoProvider::object_info_for_resolved(
                    &self.shared.interrupts,
                    &resolved,
                )
                .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e122));
                let binding = self
                    .shared
                    .interrupts
                    .binding_for_resolved(&resolved)
                    .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e123));
                assert!(
                    self.registry
                        .release_internal(resolved.into_internal())
                        .unwrap_or_else(|failure| panic!(
                            "selector-30 BIND lookup release failed: {:?}",
                            failure.error()
                        ))
                        .is_none(),
                    "selector-30 BIND lookup unexpectedly finalized its object"
                );
                if info.source != 3
                    || info.parent_resource_id != 1
                    || info.parent_lease_generation != lease_generation
                    || info.binding_generation != binding.generation()
                {
                    crate::test_support::complete_fail(0x3010_e124)
                }
                DW1D_EVIDENCE
                    .bind(self.process, object, binding, lease_generation)
                    .unwrap_or_else(|error| {
                        crate::test_support::complete_fail(0x3010_e130 | error as u32)
                    });
                DW_STATUS_SUCCESS
            }
            Dw1dRawOperation::Deliver { sequence } => {
                match DW1D_EVIDENCE
                    .authorize_deliver(self.process, sequence)
                    .unwrap_or_else(|error| {
                        crate::test_support::complete_fail(0x3010_e140 | error as u32)
                    }) {
                    Dw1dDeliverPlan::WaitRegistrationPending => DW_STATUS_WOULD_BLOCK,
                    Dw1dDeliverPlan::Live(binding) => {
                        let delivery = self
                            .shared
                            .interrupt_platform
                            .prepare_delivery(binding)
                            .unwrap_or_else(|error| {
                                panic!("selector-30 live delivery preparation failed: {error:?}")
                            });
                        let (accepted, wakes) =
                            self.shared.interrupts.deliver(delivery, &self.shared.waits);
                        DW1D_EVIDENCE
                            .observe_delivery(sequence, binding, accepted)
                            .unwrap_or_else(|error| {
                                crate::test_support::complete_fail(0x3010_e150 | error as u32)
                            });
                        crate::syscall::complete_wait_wakes(
                            &mut self.registry,
                            &self.shared.execution,
                            wakes,
                            &mut self.cleanup,
                        );
                        DW_STATUS_SUCCESS
                    }
                    Dw1dDeliverPlan::RacePermit => DW_STATUS_SUCCESS,
                    Dw1dDeliverPlan::Stale(binding) => {
                        match self.shared.interrupt_platform.prepare_delivery(binding) {
                            Err(crate::device::InterruptPlatformError::StaleBinding) => {}
                            Err(error) => panic!(
                                "selector-30 stale delivery returned wrong platform error: {error:?}"
                            ),
                            Ok(_) => crate::test_support::complete_fail(0x3010_e160),
                        }
                        DW1D_EVIDENCE
                            .observe_stale_delivery(
                                self.process,
                                sequence,
                                binding,
                                DW_STATUS_BAD_STATE,
                            )
                            .unwrap_or_else(|error| {
                                crate::test_support::complete_fail(0x3010_e170 | error as u32)
                            });
                        DW_STATUS_BAD_STATE
                    }
                }
            }
            Dw1dRawOperation::Report {
                event,
                value,
                auxiliary,
            } => {
                if event == 0x17 {
                    if !self.services.is_quiescent()
                        || self.wait_controls.iter().any(|control| !control.is_clear())
                    {
                        crate::test_support::complete_fail(0x3010_e180)
                    }
                    let snapshot = self
                        .shared
                        .execution
                        .dw1c_final_scheduler_snapshot()
                        .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_e181));
                    let grant_available = self
                        .shared
                        .boot_resource_grants
                        .state_for(1)
                        .is_some_and(|(_, state)| {
                            state == crate::boot::BootResourceGrantState::Available
                        });
                    DW1D_EVIDENCE
                        .observe_accounting(
                            self.shared.device_resources.live_count(),
                            self.shared.interrupts.live_count(),
                            self.shared.waits.len(),
                            grant_available,
                            snapshot.accounting_mask(),
                        )
                        .unwrap_or_else(|error| {
                            crate::test_support::complete_fail(0x3010_e190 | error as u32)
                        });
                }
                DW1D_EVIDENCE
                    .report(self.process, event, value, auxiliary)
                    .unwrap_or_else(|error| {
                        crate::test_support::complete_fail(0x3010_e1a0 | error as u32)
                    });
                DW_STATUS_SUCCESS
            }
        };
        self.commit_runtime_phase(phase);
        NativeSyscallResult::returning(status)
    }

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
        frame.authorize_return(current_binding_generation, &mut mappings)?;
        drop(mappings);
        #[cfg(all(feature = "test-support", deepwyrm_wrcap_relay))]
        self.drain_wrcap_record();
        Ok(())
    }

    fn invalid_return(&mut self, error: crate::arch::x86_64::syscall::UserReturnError) {
        self.synchronize_scheduler_current();
        let publication = self.complete_physical_switch_handoff();
        crate::task::notify_completed_switch_runnable(publication);
        self.terminate_exception(crate::task::TaskExceptionRecord::new(
            DW_EXCEPTION_GENERAL_PROTECTION,
            invalid_user_return_detail(error),
            0,
        ));
    }

    fn user_exception(&mut self, record: crate::arch::x86_64::exceptions::UserExceptionRecord) {
        self.synchronize_scheduler_current();
        let publication = self.complete_physical_switch_handoff();
        crate::task::notify_completed_switch_runnable(publication);
        self.terminate_exception(record.task_exception());
    }

    fn terminate_current(&mut self) -> ! {
        self.execute_local_scheduler_quantum_cancellation();
        match self.prepare_terminal_handoff() {
            PreparedTerminalHandoff::Continuation(continuation) => unsafe {
                crate::arch::x86_64::context::abandon_to_kernel_continuation(continuation)
            },
            PreparedTerminalHandoff::IdleScheduler => {
                crate::arch::x86_64::syscall::enter_bound_idle_scheduler()
            }
        }
    }

    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        self.synchronize_scheduler_current();
        let publication = self.complete_physical_switch_handoff();
        crate::task::notify_completed_switch_runnable(publication);
        let (state, stack) = self.prepare_fresh_user_entry();
        unsafe { crate::arch::x86_64::syscall::enter_bound_validated_user(&state, stack) }
    }

    fn publish_scheduler_idle(
        &mut self,
        started_at_ns: u64,
    ) -> Result<crate::task::SchedulerIdleAccountingToken, crate::task::SchedulerError> {
        self.shared
            .execution
            .publish_idle_on(self.cpu, started_at_ns)
    }

    fn finish_scheduler_idle(
        &mut self,
        token: crate::task::SchedulerIdleAccountingToken,
        finished_at_ns: u64,
    ) -> Result<(), crate::task::SchedulerError> {
        self.shared.execution.finish_idle_on(token, finished_at_ns)
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan<'owner> {
        let plan = unsafe { self.prepare_suspend_stationary() };
        self.execute_local_scheduler_quantum_cancellation();
        plan
    }

    unsafe fn poll_idle_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeIdleSuspendPoll<'owner> {
        unsafe { self.poll_idle_suspend_stationary() }
    }

    fn resume_suspended(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeResumeOutcome {
        self.synchronize_scheduler_current();
        let publication = self.complete_physical_switch_handoff();
        crate::task::notify_completed_switch_runnable(publication);
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
        crate::syscall::native::NativeResumeOutcome::Resumed
    }
}

#[cfg(deepwyrm_wyr1_evidence)]
const fn wyr1_submit_detail(error: crate::test_support::Wyr1EvidenceError) -> u32 {
    use crate::test_support::Wyr1EvidenceError;
    match error {
        Wyr1EvidenceError::Early => 0x2510_e003,
        Wyr1EvidenceError::Retirement => 0x2510_e004,
        Wyr1EvidenceError::WrongReporter => 0x2510_e005,
        Wyr1EvidenceError::Malformed => 0x2510_e006,
        Wyr1EvidenceError::OutOfOrder => 0x2510_e007,
        Wyr1EvidenceError::Full => 0x2510_e008,
        Wyr1EvidenceError::DuplicateTerminal => 0x2510_e009,
        Wyr1EvidenceError::ReporterClaimed => 0x2510_e00a,
    }
}

#[cfg(any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
const fn wyr1b_submit_detail(error: crate::test_support::Wyr1bEvidenceError) -> u32 {
    use crate::test_support::Wyr1bEvidenceError;
    match error {
        Wyr1bEvidenceError::Early => 0x2710_e003,
        Wyr1bEvidenceError::Retirement => 0x2710_e004,
        Wyr1bEvidenceError::WrongReporter => 0x2710_e005,
        Wyr1bEvidenceError::Malformed => 0x2710_e006,
        Wyr1bEvidenceError::OutOfOrder => 0x2710_e007,
        Wyr1bEvidenceError::Full => 0x2710_e008,
        Wyr1bEvidenceError::DuplicateTerminal => 0x2710_e009,
        Wyr1bEvidenceError::ReporterClaimed => 0x2710_e00a,
        Wyr1bEvidenceError::StartupMissing => 0x2710_e00b,
        Wyr1bEvidenceError::StartupDuplicate => 0x2710_e00c,
        Wyr1bEvidenceError::StartupRoot => 0x2710_e00d,
        Wyr1bEvidenceError::StartupEntry => 0x2710_e00e,
        Wyr1bEvidenceError::StartupStackPointer => 0x2710_e00f,
        Wyr1bEvidenceError::StartupStackMapping => 0x2710_e010,
        Wyr1bEvidenceError::StartupStackProtection => 0x2710_e011,
        Wyr1bEvidenceError::StartupGuard => 0x2710_e012,
    }
}

#[cfg(deepwyrm_wyr1c_evidence)]
const fn wyr1c_submit_detail(error: crate::test_support::Wyr1cEvidenceError) -> u32 {
    use crate::test_support::Wyr1cEvidenceError;
    match error {
        Wyr1cEvidenceError::Early => 0x2910_e003,
        Wyr1cEvidenceError::Retirement => 0x2910_e004,
        Wyr1cEvidenceError::WrongReporter => 0x2910_e005,
        Wyr1cEvidenceError::Malformed => 0x2910_e006,
        Wyr1cEvidenceError::OutOfOrder => 0x2910_e007,
        Wyr1cEvidenceError::Full => 0x2910_e008,
        Wyr1cEvidenceError::DuplicateTerminal => 0x2910_e009,
        Wyr1cEvidenceError::ReporterClaimed => 0x2910_e00a,
        Wyr1cEvidenceError::StartupMissing => 0x2910_e00b,
        Wyr1cEvidenceError::StartupDuplicate => 0x2910_e00c,
        Wyr1cEvidenceError::StartupRoot => 0x2910_e00d,
        Wyr1cEvidenceError::StartupEntry => 0x2910_e00e,
        Wyr1cEvidenceError::StartupStackPointer => 0x2910_e00f,
        Wyr1cEvidenceError::StartupStackMapping => 0x2910_e010,
        Wyr1cEvidenceError::StartupStackProtection => 0x2910_e011,
        Wyr1cEvidenceError::StartupGuard => 0x2910_e012,
    }
}

#[cfg(deepwyrm_dw1b_evidence)]
const fn dw1b_evidence_detail(error: crate::test_support::Dw1bEvidenceError) -> u32 {
    use crate::test_support::Dw1bEvidenceError;
    match error {
        Dw1bEvidenceError::Malformed => 0x2610_f001,
        Dw1bEvidenceError::OutOfOrder => 0x2610_f002,
        Dw1bEvidenceError::WrongReporter => 0x2610_f003,
        Dw1bEvidenceError::WrongSubject => 0x2610_f004,
        Dw1bEvidenceError::DuplicateReap => 0x2610_f005,
        Dw1bEvidenceError::Incomplete => 0x2610_f006,
        Dw1bEvidenceError::CounterRegression => 0x2610_f007,
        Dw1bEvidenceError::CounterRelation => 0x2610_f008,
        Dw1bEvidenceError::AccountingOverflow => 0x2610_f009,
        Dw1bEvidenceError::TerminalClaimed => 0x2610_f00a,
    }
}

#[cfg(any(
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_wyr1c_evidence
))]
const fn evidence_process_create_detail(case: u32) -> u32 {
    #[cfg(deepwyrm_wyr1_evidence)]
    return 0x2510_c000 | case;
    #[cfg(deepwyrm_dw1b_evidence)]
    return 0x2610_c000 | case;
    #[cfg(deepwyrm_wyr1b_evidence)]
    return 0x2710_c000 | case;
    #[cfg(deepwyrm_dw1c_evidence)]
    return 0x2810_c000 | case;
    #[cfg(deepwyrm_dw1d_evidence)]
    return 0x3010_c000 | case;
    #[cfg(deepwyrm_wyr1c_evidence)]
    return 0x2910_c000 | case;
}

#[cfg(any(
    deepwyrm_wyr1_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_wyr1c_evidence
))]
const fn supervisor_evidence_detail(case: u32) -> u32 {
    #[cfg(deepwyrm_wyr1_evidence)]
    return 0x2510_0000 | case;
    #[cfg(deepwyrm_wyr1b_evidence)]
    return 0x2710_0000 | case;
    #[cfg(deepwyrm_wyr1c_evidence)]
    return 0x2910_0000 | case;
}

#[cfg(any(
    test,
    deepwyrm_wyr1_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_wyr1c_evidence
))]
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

#[cfg(any(
    test,
    deepwyrm_wyr1_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_wyr1c_evidence
))]
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
        PrimordialCompletionError::Receive(code) => {
            0xe000
                | (primordial_receive_failure_tag(code) << 8)
                | primordial_terminal_summary(terminal_info)
        }
        PrimordialCompletionError::MalformedReady => 0xd200,
        PrimordialCompletionError::ObserveExit(code) => 0xd300 | (code & 0xff),
        PrimordialCompletionError::NonzeroExit(code) => 0xd400 | (code & 0xff),
        PrimordialCompletionError::UnhandledException => 0xd500,
        PrimordialCompletionError::AuthorizedTermination => 0xd600,
        PrimordialCompletionError::NotQuiescent(code) => 0xd700 | (code & 0xff),
    }
}

#[cfg(any(
    deepwyrm_wyr1_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_wyr1c_evidence
))]
fn primordial_completion_detail(
    error: crate::boot::primordial::construction::PrimordialCompletionError<u32>,
    terminal_info: Option<deepwyrm_abi::DwTaskTerminationInfoV1>,
) -> u32 {
    supervisor_evidence_detail(primordial_completion_case(error, terminal_info))
}

impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler
    for RuntimeCarrierFacade<'_, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn handle(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
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
            if !self.synchronize_scheduler_current_at_safe_point_detached() {
                return NativeSyscallResult {
                    status: DW_STATUS_SUCCESS,
                    control: SyscallControl::ServiceRendezvous,
                };
            }
            loop {
                let mut runtime = self.runtime.lock();
                runtime.switch_cpu(self.cpu);
                if matches!(
                    crate::arch::x86_64::idle::take_current_notification_at_safe_point(),
                    crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
                ) {
                    return NativeSyscallResult {
                        status: DW_STATUS_SUCCESS,
                        control: SyscallControl::ServiceRendezvous,
                    };
                }
                #[cfg(deepwyrm_dw1c_evidence)]
                if let NativeSyscallRequest::ProcessTerminate { process, .. } = request
                    && let Some((_token8_thread, gate)) =
                        runtime.dw1c_process_termination_gate(process)
                    && gate == crate::task::Dw1cTerminalGate::AwaitingExpiry
                {
                    // Syscalls run with IF clear. Polling here would monopolize
                    // token 8's assigned CPU and prevent the very quantum expiry
                    // that opens this gate. Return through the ordinary syscall
                    // boundary so return-time preemption can dispatch token 8;
                    // the selector controller retries the complete operation.
                    return NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK);
                }
                #[cfg(deepwyrm_dw1d_evidence)]
                if let NativeSyscallRequest::ProcessTerminate { process, .. } = request
                    && let Some(ready) = runtime.dw1d_replacement_termination_gate(process)
                    && !ready
                {
                    // The controller can observe userspace's replacement-wait
                    // intent before the replacement commits its real wait.
                    // Leave the public termination operation untouched and
                    // return through the ordinary boundary so userspace can
                    // yield and retry after event 0A's registration exists.
                    return NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK);
                }
                let prepared = match request {
                    NativeSyscallRequest::ProcessExit { exit_code } => {
                        match runtime.prepare_remote_process_exit(exit_code) {
                            ProcessTerminationPreparation::Retry => {
                                drop(runtime);
                                for _ in 0..64 {
                                    core::hint::spin_loop();
                                }
                                continue;
                            }
                            ProcessTerminationPreparation::Immediate(result) => {
                                drop(runtime);
                                self.drain_quantum_cancellation_detached();
                                return result;
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
                    } => match runtime.prepare_remote_process_termination(process, reason, code) {
                        ProcessTerminationPreparation::Retry => {
                            unreachable!(
                                "external Process termination uses an ordinary retry status"
                            )
                        }
                        ProcessTerminationPreparation::Immediate(result) => {
                            drop(runtime);
                            self.drain_quantum_cancellation_detached();
                            return result;
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
                    },
                    NativeSyscallRequest::TaskGroupTerminate { task_group, reason } => {
                        match runtime.prepare_remote_task_group_termination(task_group, reason) {
                            TaskGroupTerminationPreparation::Immediate(result) => {
                                drop(runtime);
                                self.drain_quantum_cancellation_detached();
                                return result;
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
                    } => match runtime.prepare_remote_thread_termination(thread, reason, code) {
                        ThreadTerminationPreparation::Immediate(result) => {
                            drop(runtime);
                            self.drain_quantum_cancellation_detached();
                            return result;
                        }
                        ThreadTerminationPreparation::Remote(prepared) => {
                            let phase = prepared.phase;
                            let identities = prepared.identities;
                            let pending =
                                PendingRemoteTermination::Thread(PendingRemoteThreadTermination {
                                    phase,
                                    prepared: prepared.prepared,
                                    deferred: core::array::from_fn(|_| None),
                                });
                            (identities, pending)
                        }
                    },
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
                return NativeSyscallResult {
                    status: DW_STATUS_SUCCESS,
                    control: SyscallControl::CompleteRemoteStop,
                };
            }
        }
        let cpu = self.cpu;
        let result = match self.with_synchronized_runtime_at_safe_point(|runtime| {
            if cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            runtime.handle(request)
        }) {
            Ok(result) => result,
            Err(()) => {
                return NativeSyscallResult {
                    status: DW_STATUS_SUCCESS,
                    control: SyscallControl::ServiceRendezvous,
                };
            }
        };
        crate::task::drain_runnable_work_notifications();
        self.drain_quantum_cancellation_detached();
        result
    }
}

impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::syscall::native::NativeRendezvousRuntime
    for RuntimeCarrierFacade<'_, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn rendezvous_stop(
        &mut self,
        request: crate::arch::x86_64::rendezvous::StopRequest,
        reaper: crate::arch::x86_64::rendezvous::NativeRendezvousReaperEntry,
    ) -> ! {
        let (witness, root_switch) = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.prepare_rendezvous_stop(request, reaper)
        };
        let root_switch = match root_switch.execute() {
            Ok(executed) => executed,
            Err(failure) => {
                let mut runtime = self.runtime.lock();
                let error = runtime.cancel_stop_root_switch(failure);
                panic!("detached remote-stop root switch failed before CR3: {error:?}")
            }
        };
        let next = {
            let mut runtime = self.runtime.lock();
            runtime.commit_rendezvous_stop(witness, root_switch)
        };
        self.drain_quantum_cancellation_detached();
        let entry = match next {
            PreparedRendezvousNext::Idle => PreparedCarrierEntry::Idle,
            PreparedRendezvousNext::Scheduled {
                stack,
                continuation,
            } => {
                self.synchronize_scheduler_current_detached();
                if continuation == 0 {
                    let (state, stack) = {
                        let mut runtime = self.runtime.lock();
                        runtime.switch_cpu(self.cpu);
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
                unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                    .unwrap_or_else(|error| {
                        panic!("rendezvous fresh stack binding failed: {error:?}")
                    });
                unsafe { crate::arch::x86_64::syscall::enter_bound_validated_user(&state, stack) }
            }
            PreparedCarrierEntry::Continuation { stack, rsp } => {
                unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                    .unwrap_or_else(|error| {
                        panic!("rendezvous replacement stack binding failed: {error:?}")
                    });
                crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(
                    |error| panic!("rendezvous replacement boundary failed: {error:?}"),
                );
                unsafe { crate::arch::x86_64::context::abandon_to_kernel_continuation(rsp) }
            }
            PreparedCarrierEntry::Idle => self.enter_idle_scheduler(),
        }
    }
}

#[allow(
    unsafe_code,
    reason = "CPU-local carrier callbacks serialize shared authorities and drop their coarse guard before every AP idle or userspace handoff"
)]
impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallFrameRuntime
    for RuntimeCarrierFacade<'_, 'roles, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn publish_quantum_expiry(
        &mut self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<bool, crate::task::SchedulerError> {
        let published = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.shared.execution.publish_quantum_expiry(ticket)?
        };
        Ok(published)
    }

    fn prepare_quantum(
        &mut self,
        now_ns: u64,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, crate::task::SchedulerError> {
        match self
            .with_synchronized_runtime_at_safe_point(|runtime| runtime.prepare_quantum(now_ns))
        {
            Ok(result) => result,
            Err(()) => Ok(None),
        }
    }

    fn has_reschedule_request(&mut self) -> bool {
        self.with_synchronized_runtime_at_safe_point(|runtime| runtime.has_reschedule_request())
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
        let mut runtime = self.runtime.lock();
        runtime.switch_cpu(self.cpu);
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
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(publication);
        let mut runtime = self.runtime.lock();
        runtime.switch_cpu(self.cpu);
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
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(publication);
        let mut runtime = self.runtime.lock();
        runtime.switch_cpu(self.cpu);
        let current_binding_generation = crate::arch::x86_64::syscall::current_binding_generation();
        frame.rebind_after_kernel_resume(current_binding_generation)?;
        runtime.authorize_return(frame, current_binding_generation)
    }

    #[cfg(deepwyrm_wyr1_evidence)]
    fn intercept_wyr1_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.intercept_wyr1_evidence_raw(arguments)
        })
        .unwrap_or(NativeSyscallResult {
            status: DW_STATUS_SUCCESS,
            control: SyscallControl::ServiceRendezvous,
        })
    }

    #[cfg(deepwyrm_dw1b_evidence)]
    fn intercept_dw1b_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.intercept_dw1b_evidence_raw(arguments)
        })
        .unwrap_or(NativeSyscallResult {
            status: DW_STATUS_SUCCESS,
            control: SyscallControl::ServiceRendezvous,
        })
    }

    #[cfg(deepwyrm_wyr1b_evidence)]
    fn intercept_wyr1b_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        self.with_synchronized_runtime_at_safe_point(|runtime| {
            runtime.intercept_wyr1b_evidence_raw(arguments)
        })
        .unwrap_or(NativeSyscallResult {
            status: DW_STATUS_SUCCESS,
            control: SyscallControl::ServiceRendezvous,
        })
    }

    #[cfg(deepwyrm_wyr1c_evidence)]
    fn intercept_wyr1c_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        let result = self
            .with_synchronized_runtime_at_safe_point(|runtime| {
                runtime.intercept_wyr1c_evidence_raw(arguments)
            })
            .unwrap_or(NativeSyscallResult {
                status: DW_STATUS_SUCCESS,
                control: SyscallControl::ServiceRendezvous,
            });
        crate::task::drain_runnable_work_notifications();
        result
    }

    #[cfg(deepwyrm_dw1c_evidence)]
    fn intercept_dw1c_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        let result = self
            .with_synchronized_runtime_at_safe_point(|runtime| {
                runtime.intercept_dw1c_evidence_raw(arguments)
            })
            .unwrap_or(NativeSyscallResult {
                status: DW_STATUS_SUCCESS,
                control: SyscallControl::ServiceRendezvous,
            });
        // Selector-private raw calls bypass `dispatch_native`, so publish any
        // scheduler wake staged while the synchronized runtime was held only
        // after that authority has been released.
        crate::task::drain_runnable_work_notifications();
        result
    }

    #[cfg(deepwyrm_dw1d_evidence)]
    fn intercept_dw1d_evidence_raw(
        &mut self,
        arguments: crate::syscall::RawSyscallArguments,
    ) -> NativeSyscallResult {
        let result = self
            .with_synchronized_runtime_at_safe_point(|runtime| {
                runtime.intercept_dw1d_evidence_raw(arguments)
            })
            .unwrap_or(NativeSyscallResult {
                status: DW_STATUS_SUCCESS,
                control: SyscallControl::ServiceRendezvous,
            });
        // Selector-private delivery can publish waiter wakes while the
        // synchronized runtime is held. Notify CPUs only after releasing it.
        crate::task::drain_runnable_work_notifications();
        result
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
        let result = match pending {
            PendingRemoteTermination::Process(pending) => {
                let permits = await_remote_stop_permits(pending.deferred);
                self.synchronize_scheduler_current_detached();
                {
                    let mut runtime = self.runtime.lock();
                    runtime.switch_cpu(self.cpu);
                    runtime.complete_process_termination(pending.phase, pending.prepared, permits)
                }
            }
            PendingRemoteTermination::TaskGroup(pending) => {
                let permits = await_remote_stop_permits(pending.deferred);
                self.synchronize_scheduler_current_detached();
                {
                    let mut runtime = self.runtime.lock();
                    runtime.switch_cpu(self.cpu);
                    runtime.complete_task_group_termination(
                        pending.phase,
                        pending.prepared,
                        permits,
                    )
                }
            }
            PendingRemoteTermination::Thread(pending) => {
                let permits = await_remote_stop_permits(pending.deferred);
                self.synchronize_scheduler_current_detached();
                {
                    let mut runtime = self.runtime.lock();
                    runtime.switch_cpu(self.cpu);
                    runtime.complete_thread_termination(pending.phase, pending.prepared, permits)
                }
            }
        };
        self.drain_quantum_cancellation_detached();
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

    fn terminate_current(&mut self) -> ! {
        self.drain_quantum_cancellation_detached();
        let mut step = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.prepare_terminal_handoff_detached()
        };
        loop {
            step = match step {
                PreparedTerminalStep::SchedulerRoot { prepared, state } => {
                    let executed = match prepared.execute() {
                        Ok(executed) => executed,
                        Err(failure) => {
                            let mut runtime = self.runtime.lock();
                            let error = runtime.cancel_scheduler_root_switch(failure);
                            panic!("terminal scheduler root switch failed before CR3: {error:?}")
                        }
                    };
                    let mut runtime = self.runtime.lock();
                    runtime.commit_scheduler_root_switch(executed);
                    PreparedTerminalStep::Final(runtime.finish_terminal_successor(state))
                }
                PreparedTerminalStep::KernelRoot {
                    prepared,
                    continuation,
                } => {
                    let executed = match prepared.execute() {
                        Ok(executed) => executed,
                        Err(failure) => {
                            let mut runtime = self.runtime.lock();
                            let error = runtime.cancel_terminal_kernel_root_switch(failure);
                            panic!("terminal kernel-root switch failed before CR3: {error:?}")
                        }
                    };
                    let mut runtime = self.runtime.lock();
                    runtime.commit_terminal_kernel_root_switch(executed);
                    runtime.continue_terminal_after_kernel_root(continuation)
                }
                PreparedTerminalStep::PrimordialRoot {
                    prepared,
                    retirement,
                } => {
                    let executed = match prepared.execute() {
                        Ok(executed) => executed,
                        Err(failure) => {
                            let mut runtime = self.runtime.lock();
                            let error = runtime.cancel_terminal_primordial_root_switch(failure);
                            panic!("terminal publisher-root switch failed before CR3: {error:?}")
                        }
                    };
                    let mut runtime = self.runtime.lock();
                    runtime.commit_terminal_primordial_root_switch(executed);
                    runtime.continue_terminal_after_primordial_root(retirement)
                }
                PreparedTerminalStep::Final(handoff) => match handoff {
                    PreparedTerminalHandoff::Continuation(continuation) => unsafe {
                        crate::arch::x86_64::context::abandon_to_kernel_continuation(continuation)
                    },
                    PreparedTerminalHandoff::IdleScheduler => {
                        crate::arch::x86_64::syscall::enter_bound_idle_scheduler()
                    }
                },
            };
        }
    }

    fn enter_scheduled_fresh_thread(&mut self) -> ! {
        self.synchronize_scheduler_current_detached();
        let publication = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(publication);
        let (state, stack) = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.prepare_fresh_user_entry_synchronized()
        };
        unsafe { crate::arch::x86_64::syscall::enter_bound_validated_user(&state, stack) }
    }

    fn publish_scheduler_idle(
        &mut self,
        started_at_ns: u64,
    ) -> Result<crate::task::SchedulerIdleAccountingToken, crate::task::SchedulerError> {
        let runtime = self.runtime.lock();
        runtime
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
            .shared
            .execution
            .finish_idle_on(token, finished_at_ns)
    }

    fn enter_idle_scheduler(&mut self) -> ! {
        #[cfg(deepwyrm_dw1c_evidence)]
        {
            let pending = {
                let runtime = self.runtime.lock();
                runtime.dw1c_pending_detach[self.cpu.index()]
            };
            if let Some(request) = pending {
                let prepared = {
                    let mut runtime = self.runtime.lock();
                    runtime.switch_cpu(self.cpu);
                    runtime.prepare_terminal_kernel_root_switch()
                };
                let executed = match prepared.execute() {
                    Ok(executed) => executed,
                    Err(failure) => {
                        let mut runtime = self.runtime.lock();
                        let error = runtime.cancel_terminal_kernel_root_switch(failure);
                        panic!("selector-28 idle-detach root switch failed: {error:?}")
                    }
                };
                let publication = {
                    let mut runtime = self.runtime.lock();
                    // The executed flight is the authority that reselects its
                    // originating CPU. Ordinary selection is forbidden while
                    // that flight remains in progress.
                    runtime.commit_terminal_kernel_root_switch(executed);
                    let publication = runtime.complete_physical_switch_handoff();
                    runtime
                        .shared
                        .execution
                        .complete_dw1c_continuation_detach(request)
                        .unwrap_or_else(|error| {
                            panic!("selector-28 idle-detach completion drifted: {error:?}")
                        });
                    runtime.dw1c_pending_detach[self.cpu.index()] = None;
                    runtime.local.record_idle();
                    publication
                };
                crate::task::notify_completed_switch_runnable(publication);
            }
        }
        if !self.admission_entered {
            let (ticket, resources) = self
                .admission
                .unwrap_or_else(|| panic!("AP carrier omitted scheduler admission identity"));
            self.enter_ap_kernel_root_detached();
            if ticket.cpu() != self.cpu
                || crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
                    != Some(self.cpu.index())
                || crate::arch::x86_64::runtime_cpu_descriptor_lifecycle(self.cpu.index())
                    != Some(crate::arch::x86_64::RuntimeCpuDescriptorLifecycle::Online)
                || crate::arch::x86_64::syscall::native_runtime_carrier_lifecycle(self.cpu)
                    != Some(crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing)
                || !crate::arch::x86_64::ipi::live_ipi_transport_is_bound()
                || !crate::arch::x86_64::ipi::live_rendezvous_handler_is_bound()
                || !user_access::live_tlb_shootdown_is_ready()
                || crate::arch::x86_64::idle::live_idle_wake_is_enabled(self.cpu)
                || !crate::time::ap_scheduler_timer_is_masked(self.cpu)
            {
                fail_live_carrier_admission(
                    self.shared,
                    self.cpu,
                    "AP carrier admission revalidation failed",
                );
            }
            let snapshot = crate::arch::x86_64::smp::live_cpu_registry()
                .snapshot(self.cpu.index())
                .unwrap_or_else(|_| {
                    fail_live_carrier_admission(
                        self.shared,
                        self.cpu,
                        "AP registry revalidation failed",
                    )
                });
            if snapshot.lifecycle != crate::arch::x86_64::smp::CpuLifecycle::Executing
                || snapshot.local_apic_id != resources.local_apic_id
                || snapshot.online_generation != resources.online_generation
            {
                fail_live_carrier_admission(self.shared, self.cpu, "AP execution identity drifted");
            }
            let observed_resources = {
                let runtime = self.runtime.lock();
                carrier_resource_tuple(
                    &runtime,
                    self.cpu,
                    crate::arch::x86_64::smp::CpuLifecycle::Executing,
                    crate::arch::x86_64::syscall::RuntimeCarrierLifecycle::Executing,
                    false,
                )
            };
            if observed_resources != resources {
                fail_live_carrier_admission(
                    self.shared,
                    self.cpu,
                    "AP private carrier resources drifted",
                );
            }
            crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(|_| {
                fail_live_carrier_admission(
                    self.shared,
                    self.cpu,
                    "AP syscall boundary validation failed",
                )
            });
            self.shared
                .execution
                .publish_ap_carrier_ready(
                    ticket,
                    resources,
                    crate::task::CarrierRuntimeState::Executing,
                )
                .unwrap_or_else(|error| {
                    self.shared.execution.fail_carrier_admission(self.cpu);
                    panic!(
                        "AP {} readiness publication failed: {error:?}",
                        self.cpu.index()
                    )
                });
            while !self.shared.execution.carrier_ticket_is_schedulable(ticket) {
                let observed = self.shared.execution.carrier_admission_snapshot(self.cpu);
                if observed.lifecycle == crate::task::CarrierAdmissionLifecycle::Failed {
                    panic!("AP {} admission failed", self.cpu.index());
                }
                core::hint::spin_loop();
            }
            self.admission_entered = true;
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
                let runtime = self.runtime.lock();
                runtime
                    .shared
                    .execution
                    .schedule_next_on(self.cpu)
                    .unwrap_or_else(|error| panic!("AP scheduling failed: {error:?}"))
                    .current
            };
            crate::task::drain_runnable_work_notifications();
            let entry = scheduled.map(|thread| {
                self.synchronize_scheduler_current_detached();
                let mut runtime = self.runtime.lock();
                runtime.switch_cpu(self.cpu);
                let continuation = runtime
                    .shared
                    .execution
                    .kernel_continuation_rsp(runtime.context_id)
                    .unwrap_or_else(|error| {
                        panic!("AP continuation lookup failed for {thread:?}: {error:?}")
                    });
                if continuation == 0 {
                    let (state, stack) = runtime.prepare_fresh_user_entry_synchronized();
                    Entry::Fresh { state, stack }
                } else {
                    let stack = runtime
                        .shared
                        .execution
                        .stack_bounds(runtime.stack_id)
                        .unwrap_or_else(|error| panic!("AP stack lookup failed: {error:?}"));
                    Entry::Continuation {
                        stack,
                        rsp: continuation,
                    }
                }
            });
            match entry {
                Some(Entry::Fresh { state, stack }) => {
                    unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                        .unwrap_or_else(|error| panic!("AP fresh stack binding failed: {error:?}"));
                    unsafe {
                        crate::arch::x86_64::syscall::enter_bound_validated_user(&state, stack)
                    }
                }
                Some(Entry::Continuation { stack, rsp }) => {
                    unsafe { crate::arch::x86_64::syscall::bind_current_thread_stack(stack) }
                        .unwrap_or_else(|error| {
                            panic!("AP continuation stack binding failed: {error:?}")
                        });
                    crate::arch::x86_64::syscall::validate_live_syscall_boundary().unwrap_or_else(
                        |error| panic!("AP continuation syscall boundary failed: {error:?}"),
                    );
                    unsafe { crate::arch::x86_64::context::abandon_to_kernel_continuation(rsp) }
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
                            let idle_accounting = self
                                .publish_scheduler_idle(started_at_ns)
                                .unwrap_or_else(|error| {
                                    panic!("AP idle accounting publication failed: {error:?}")
                                });
                            unsafe {
                                core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
                            }
                            crate::arch::x86_64::idle::finish_current_idle(halt).unwrap_or_else(
                                |error| panic!("AP idle completion failed: {error:?}"),
                            );
                            let finished_at_ns =
                                crate::time::monotonic_now().unwrap_or_else(|error| {
                                    panic!("AP idle finish sample failed: {error:?}")
                                });
                            self.finish_scheduler_idle(idle_accounting, finished_at_ns)
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
                        crate::arch::x86_64::rendezvous::MailboxNotification::Wake => {
                            #[cfg(deepwyrm_i1_evidence)]
                            crate::test_support::observe_i1_remote_wake_received(self.cpu);
                        }
                        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_) => {
                            panic!("kernel-root idle carrier received an unexpected stop request")
                        }
                    }
                }
            }
        }
    }

    unsafe fn prepare_suspend<'owner>(
        &'owner mut self,
        _frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeSuspendPlan<'owner> {
        let plan = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
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
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            if self.cpu == crate::cpu::CpuIndex::BOOTSTRAP {
                runtime.service_pending_timer_expiries_on_bootstrap();
            }
            unsafe { runtime.poll_idle_suspend_stationary() }
        };
        crate::task::drain_runnable_work_notifications();
        poll
    }

    fn resume_suspended(
        &mut self,
        frame: &mut crate::arch::x86_64::syscall::RawSyscallFrame,
    ) -> crate::syscall::native::NativeResumeOutcome {
        // A suspended continuation may resume after another physical CPU used
        // the shared carrier. Restore this CPU's exact carrier/root token.
        // An already-published local terminal owner must retain its suspended
        // claim until the terminal reaper actually abandons this stack; every
        // resumable path acknowledges destination-stack arrival first.
        let terminal_current = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            let suspended_claim = runtime.shared.execution.suspended_claim_on(self.cpu);
            let no_current = runtime
                .shared
                .execution
                .current_thread_on(self.cpu)
                .is_none();
            match (
                no_current,
                suspended_claim,
                runtime.deferred_currents[self.cpu.index()].as_ref(),
            ) {
                (true, Some(suspended), Some(deferred)) => suspended.thread() == deferred.thread(),
                _ => false,
            }
        };
        if terminal_current {
            return crate::syscall::native::NativeResumeOutcome::TerminateCurrent;
        }
        if !self.synchronize_scheduler_current_at_safe_point_detached() {
            return crate::syscall::native::NativeResumeOutcome::ServiceRendezvous;
        }
        let publication = {
            let mut runtime = self.runtime.lock();
            runtime.switch_cpu(self.cpu);
            runtime.complete_physical_switch_handoff()
        };
        crate::task::notify_completed_switch_runnable(publication);
        let mut runtime = self.runtime.lock();
        runtime.switch_cpu(self.cpu);
        let notification = crate::arch::x86_64::idle::take_current_notification_at_safe_point();
        if matches!(
            notification,
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(_)
        ) {
            return crate::syscall::native::NativeResumeOutcome::ServiceRendezvous;
        }
        #[cfg(feature = "test-support")]
        let suspended_claim = runtime.shared.execution.suspended_claim_on(self.cpu);
        #[cfg(feature = "test-support")]
        if runtime
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
                    if runtime.wait_controls[self.cpu.index()].is_clear() {
                        match suspended_claim.and_then(|claim| {
                            runtime
                                .shared
                                .execution
                                .scheduler_state(claim.thread())
                                .map(|state| (claim, state))
                        }) {
                            None if runtime.stopping_claim.is_some() => {
                                panic!("resume crossed an in-progress remote-stop carrier")
                            }
                            None if runtime.deferred_currents[self.cpu.index()].is_some() => {
                                panic!("resume crossed another local terminal carrier on this CPU")
                            }
                            None if suspended_claim.is_some_and(|claim| {
                                runtime.local.physically_executes(claim.thread())
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
        runtime.resume_suspended(frame)
    }
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
    let destination = unsafe {
        core::slice::from_raw_parts_mut((*storage.0.get()).as_mut_ptr().cast::<u8>(), byte_len)
    };
    active
        .read_physical_bytes(module.range().physical_start(), destination)
        .unwrap_or_else(|error| panic!("could not copy {label} module: {error:?}"));
    destination
}

#[cfg(any(
    test,
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_dw1c_evidence,
    deepwyrm_dw1d_evidence,
    deepwyrm_wyr1c_evidence
))]
const fn integration_bootfs_page_count(byte_len: usize) -> Option<usize> {
    if byte_len == 0 {
        return None;
    }
    match byte_len.checked_add(4095) {
        Some(rounded) => Some(rounded / 4096),
        None => None,
    }
}

#[allow(
    unsafe_code,
    reason = "G3 publishes stationary synchronized authorities, seals fail-closed AP carriers, and binds the BSP-exclusive carrier for audited initial CPL3 transition"
)]
pub(super) fn enter<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    mut active: ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>,
    modules: crate::boot::primordial::PrimordialBootModules,
    boot_resource_grants: crate::boot::BootResourceGrants,
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
    #[cfg(deepwyrm_wyr1_evidence)]
    if !matches!(
        integration_bootfs_page_count(bootfs.len()),
        Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
    ) {
        crate::test_support::complete_fail(0x2510_b001)
    }
    #[cfg(deepwyrm_dw1b_evidence)]
    if !matches!(
        integration_bootfs_page_count(bootfs.len()),
        Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
    ) {
        crate::test_support::complete_fail(0x2610_b001)
    }
    #[cfg(deepwyrm_wyr1b_evidence)]
    if !matches!(
        integration_bootfs_page_count(bootfs.len()),
        Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
    ) {
        crate::test_support::complete_fail(0x2710_b001)
    }
    #[cfg(deepwyrm_dw1c_evidence)]
    if !matches!(
        integration_bootfs_page_count(bootfs.len()),
        Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
    ) {
        crate::test_support::complete_fail(0x2810_b001)
    }
    #[cfg(deepwyrm_dw1d_evidence)]
    if !matches!(
        integration_bootfs_page_count(bootfs.len()),
        Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
    ) {
        crate::test_support::complete_fail(0x3010_b001)
    }
    #[cfg(deepwyrm_wyr1c_evidence)]
    if !matches!(
        integration_bootfs_page_count(bootfs.len()),
        Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
    ) {
        crate::test_support::complete_fail(0x2910_b001)
    }
    let plan = crate::boot::primordial::parse_primordial_elf(bootstrap)
        .unwrap_or_else(|error| panic!("invalid primordial bootstrap ELF: {error:?}"));

    let mut registry = Registry::new();
    let mut memory = Memory::new();
    let mut tasks = Tasks::new();
    let mut spaces = unsafe { Spaces::new() };
    let mut regions = Regions::new();
    #[cfg(deepwyrm_dw1d_evidence)]
    {
        let grant = (boot_resource_grants.len() == 1)
            .then(|| boot_resource_grants.grant(0))
            .flatten()
            .unwrap_or_else(|| crate::test_support::complete_fail(0x3010_b002));
        let descriptor = grant.descriptor();
        if descriptor.kind != deepwyrm_abi::DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
        {
            crate::test_support::complete_fail(0x3010_b003)
        }
        crate::test_support::DW1D_EVIDENCE
            .observe_boot(
                boot_resource_grants.len(),
                descriptor.resource_id,
                descriptor.pio_base,
                descriptor.pio_length,
                descriptor.interrupt_source,
            )
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x3010_b004));
    }
    #[cfg(deepwyrm_wyr1c_evidence)]
    {
        let grant = (boot_resource_grants.len() == 1)
            .then(|| boot_resource_grants.grant(0))
            .flatten()
            .unwrap_or_else(|| crate::test_support::complete_fail(0x2910_b002));
        if grant.descriptor().kind
            != deepwyrm_abi::DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
        {
            crate::test_support::complete_fail(0x2910_b003)
        }
    }
    let shared = publish_runtime_shared(boot_resource_grants);
    initialize_per_cpu_live_carriers();
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
    let runtime = core::pin::pin!(RuntimeAuthorityLock::new(PrimordialRuntimeCarrier {
        cpu: crate::cpu::CpuIndex::BOOTSTRAP,
        local: per_cpu_live_carrier(crate::cpu::CpuIndex::BOOTSTRAP),
        active,
        active_root: CarrierActiveRoot::Process(initial_root),
        active_roots: core::array::from_fn(|_| CarrierActiveRoot::Unselected),
        root_switch_epochs: [0; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
        root_switch_flights: [None; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
        cpu_processes: core::array::from_fn(|_| None),
        cpu_threads: core::array::from_fn(|_| None),
        cpu_stack_ids: core::array::from_fn(|_| None),
        cpu_context_ids: core::array::from_fn(|_| None),
        cpu_root_keys: core::array::from_fn(|_| None),
        stopping_claim: None,
        stopping_claim_was_suspended: false,
        #[cfg(deepwyrm_dw1b_evidence)]
        dw1b_preemption_outgoing: core::array::from_fn(|_| None),
        #[cfg(deepwyrm_dw1c_evidence)]
        dw1c_pending_detach: core::array::from_fn(|_| None),
        rendezvous_reaper: None,
        registry,
        memory,
        tasks,
        shared,
        services: FServiceState::new(),
        wait_controls: core::array::from_fn(|_| NativeWaitControl::new()),
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
        #[cfg(any(
            deepwyrm_wyr1_evidence,
            deepwyrm_dw1b_evidence,
            deepwyrm_wyr1b_evidence,
            deepwyrm_dw1c_evidence,
            deepwyrm_wyr1c_evidence
        ))]
        evidence_init_process: None,
        #[cfg(any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
        evidence_init_thread: None,
        channel_keys,
        kernel_peer: Some(kernel_peer),
        process_monitor: Some(process_monitor),
        root_owner: Some(root_owner),
        deferred_currents: core::array::from_fn(|_| None),
        pending_quantum_cancellations: core::array::from_fn(|_| None),
        cleanup: CleanupQueue::new(),
        rendezvous_cleanup: None,
        #[cfg(feature = "test-support")]
        g5_probe: G5PrimordialProbe::for_build(),
    }));
    let runtime_ref = runtime.as_ref().get_ref();
    let (state, stack, exception_binding) = {
        let mut runtime = runtime_ref.lock();
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
            let PrimordialRuntimeCarrier {
                active,
                active_root,
                process,
                ..
            } = &mut *runtime;
            let mut mappings = active.current_process_address_space(
                active_root.as_ref().expect("active root"),
                *process,
            );
            crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, &mut mappings)
                .unwrap_or_else(|error| panic!("invalid primordial initial return: {error:?}"))
        };
        (state, stack, exception_binding)
    };
    let facades = core::array::from_fn(|cpu_index| RuntimeCarrierFacade {
        cpu: crate::cpu::CpuIndex::new(cpu_index)
            .unwrap_or_else(|| panic!("native carrier CPU {cpu_index} is out of range")),
        runtime: runtime_ref,
        shared,
        admission: None,
        admission_entered: false,
        pending_remote_termination: None,
    });
    let mut facades = core::pin::pin!(facades);
    let live_cpu_count = bind_runtime_carrier_facades(facades.as_mut());
    user_access::initialize_live_tlb_shootdown();
    let facades_mut = unsafe { core::pin::Pin::get_unchecked_mut(facades.as_mut()) };
    prepare_runtime_carrier_admission(facades_mut, live_cpu_count);
    normalize_bootstrap_carrier(&mut facades_mut[0]);
    let admissions = core::array::from_fn(|cpu_index| facades_mut[cpu_index].admission);
    let bsp_carrier = unsafe {
        let facade = &mut facades_mut[0];
        core::pin::Pin::new_unchecked(facade)
    };
    release_runtime_carrier_facades(shared, runtime_ref, admissions);
    unsafe {
        crate::arch::x86_64::syscall::enter_native_syscall_runtime(
            bsp_carrier,
            &state,
            stack,
            &exception_binding,
        )
    }
}

#[cfg(test)]
mod wyr1_capacity_tests {
    use super::*;

    #[test]
    fn integration_bootfs_measurement_accepts_selector_local_capacity_and_rejects_larger_inputs() {
        assert_eq!(integration_bootfs_page_count(0), None);
        assert_eq!(integration_bootfs_page_count(1), Some(1));
        assert_eq!(integration_bootfs_page_count(4096), Some(1));
        assert_eq!(integration_bootfs_page_count(4097), Some(2));
        assert_eq!(integration_bootfs_page_count(169_896), Some(42));
        assert_eq!(integration_bootfs_page_count(170_496), Some(42));
        assert_eq!(integration_bootfs_page_count(308_576), Some(76));
        assert_eq!(integration_bootfs_page_count(309_192), Some(76));
        assert_eq!(integration_bootfs_page_count(128 * 4096), Some(128));
        assert!(matches!(
            integration_bootfs_page_count(128 * 4096),
            Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
        ));
        assert_eq!(integration_bootfs_page_count(128 * 4096 + 1), Some(129));
        assert!(!matches!(
            integration_bootfs_page_count(128 * 4096 + 1),
            Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)
        ));
        assert_eq!(integration_bootfs_page_count(usize::MAX), None);
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
        #[cfg(deepwyrm_i1_evidence)]
        {
            let claim = self
                .shared
                .execution
                .running_claim_on(self.cpu)
                .unwrap_or_else(|| panic!("I1 syscall has no running execution claim"));
            crate::test_support::observe_i1_cpl3_syscall(self.cpu, claim.generation(), 1);
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
                #[cfg(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_dw1b_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_dw1c_evidence,
                    deepwyrm_wyr1c_evidence
                ))]
                let creating_evidence_init = self.process == self.primordial_process;
                #[cfg(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_dw1b_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_dw1c_evidence,
                    deepwyrm_wyr1c_evidence
                ))]
                if creating_evidence_init && self.evidence_init_process.is_some() {
                    crate::test_support::complete_fail(evidence_process_create_detail(1))
                }
                #[cfg(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_dw1b_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_dw1c_evidence,
                    deepwyrm_wyr1c_evidence
                ))]
                let mut committed_child = None;
                #[cfg(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_dw1b_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_dw1c_evidence,
                    deepwyrm_wyr1c_evidence
                ))]
                let status = crate::syscall::process_create_with_root_observed(
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
                    |child| {
                        committed_child = Some(child);
                        #[cfg(deepwyrm_dw1c_evidence)]
                        crate::test_support::DW1C_EVIDENCE
                            .observe_process_create(child)
                            .unwrap_or_else(|error| {
                                panic!("selector-28 Process CREATE observation failed: {error:?}")
                            });
                    },
                );
                #[cfg(not(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_dw1b_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_dw1c_evidence,
                    deepwyrm_wyr1c_evidence
                )))]
                let status = crate::syscall::process_create_with_root(
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
                );
                #[cfg(any(
                    deepwyrm_wyr1_evidence,
                    deepwyrm_dw1b_evidence,
                    deepwyrm_wyr1b_evidence,
                    deepwyrm_dw1c_evidence,
                    deepwyrm_wyr1c_evidence
                ))]
                if creating_evidence_init && status == DW_STATUS_SUCCESS {
                    self.evidence_init_process = Some(committed_child.unwrap_or_else(|| {
                        crate::test_support::complete_fail(evidence_process_create_detail(2))
                    }));
                }
                NativeSyscallResult::returning(status)
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
                        &mut self.wait_controls[self.cpu.index()],
                        prepared,
                        &mut user,
                        &mut self.registry,
                        &mut self.tasks,
                        &self.shared.execution,
                        &self.shared.channels,
                        &self.shared.events,
                        &self.shared.timers,
                        Some(&self.shared.interrupts),
                        &self.shared.waits,
                        &mut self.regions,
                        &mut self.spaces,
                        self.process,
                        self.thread,
                        self.cpu,
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
        if result.control == SyscallControl::ReturnToCaller {
            // A normal syscall return is the publication boundary for final
            // handle releases. Do not expose a successful close to userspace
            // while its peer signal, waiter wakes, or payload reclamation is
            // still parked in the carrier-local cleanup queue.
            self.drain_finalizers()
                .unwrap_or_else(|_| panic!("normal syscall return could not drain finalizers"));
        }
        result
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PrimordialRuntimeCarrier<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    #[cfg(deepwyrm_dw1c_evidence)]
    fn dw1c_controller_authorized(&self) -> bool {
        self.evidence_init_process == Some(self.process)
            && self.shared.execution.current_thread_on(self.cpu) == Some(self.thread)
            && self.tasks.thread_process(self.thread) == Ok(self.process)
            && self.shared.execution.scheduler_state(self.thread)
                == Some(SchedulerThreadState::Running)
    }

    #[cfg(deepwyrm_dw1d_evidence)]
    fn dw1d_controller_authorized(&self) -> bool {
        self.process == self.primordial_process
            && self.shared.execution.current_thread_on(self.cpu) == Some(self.thread)
            && self.tasks.thread_process(self.thread) == Ok(self.process)
            && self.shared.execution.scheduler_state(self.thread)
                == Some(SchedulerThreadState::Running)
    }

    #[cfg(deepwyrm_dw1d_evidence)]
    fn dw1d_process_handle(&self, handle: u64) -> ProcessKey {
        self.tasks
            .process_handles(self.process)
            .ok()
            .and_then(|handles| {
                handles.process_target_for_dw1d_evidence(deepwyrm_abi::DwHandle(handle))
            })
            .map(ProcessKey::from_object_id)
            .unwrap_or_else(|| crate::test_support::complete_fail(0x3010_e104))
    }

    #[cfg(deepwyrm_dw1d_evidence)]
    fn dw1d_replacement_termination_gate(&self, handle: deepwyrm_abi::DwHandle) -> Option<bool> {
        if !self.dw1d_controller_authorized() {
            return None;
        }
        let target = self
            .tasks
            .process_handles(self.process)
            .ok()
            .and_then(|handles| handles.process_target_for_dw1d_evidence(handle))
            .map(ProcessKey::from_object_id)
            .unwrap_or_else(|| crate::test_support::complete_fail(0x3010_e1b0));
        Some(
            crate::test_support::DW1D_EVIDENCE
                .replacement_termination_ready(self.process, target)
                .unwrap_or_else(|error| {
                    crate::test_support::complete_fail(0x3010_e1c0 | error as u32)
                }),
        )
    }

    #[cfg(deepwyrm_dw1c_evidence)]
    fn dw1c_process_termination_gate(
        &self,
        handle: deepwyrm_abi::DwHandle,
    ) -> Option<(ThreadKey, crate::task::Dw1cTerminalGate)> {
        if !self.dw1c_controller_authorized() {
            return None;
        }
        let process = self
            .tasks
            .process_handles(self.process)
            .ok()?
            .process_target_for_dw1c_evidence(handle)
            .map(ProcessKey::from_object_id)?;
        if self.tasks.process_lifecycle(process).ok()? != ProcessLifecycleState::AcceptingOperations
        {
            return None;
        }
        let mut exact = None;
        for thread in self
            .tasks
            .process_thread_keys(process)
            .ok()?
            .into_iter()
            .flatten()
        {
            if exact.replace(thread).is_some() {
                return None;
            }
        }
        let thread = exact?;
        let gate = self.shared.execution.dw1c_terminal_gate(thread);
        (gate != crate::task::Dw1cTerminalGate::NotFixture).then_some((thread, gate))
    }

    fn handle_fallthrough(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        self.assert_guard_free_external_work();
        match request {
            NativeSyscallRequest::AbiGetInfo {
                out_info,
                out_size,
                out_required_size,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::abi_get_info_with_features(
                    &mut user,
                    out_info,
                    out_size,
                    out_required_size,
                    deepwyrm_abi::DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT,
                ))
            }
            NativeSyscallRequest::HandleClose { handle } => {
                #[cfg(deepwyrm_i1_evidence)]
                let closed_process = self
                    .tasks
                    .process_handles(self.process)
                    .ok()
                    .and_then(|handles| handles.process_target_for_evidence(handle))
                    .map(crate::task::ProcessKey::from_object_id);
                let status = crate::syscall::handle_close(
                    &mut self.registry,
                    &mut self.tasks,
                    self.process,
                    handle,
                    &mut self.cleanup,
                );
                #[cfg(feature = "test-support")]
                if status == DW_STATUS_BAD_STATE {
                    panic!(
                        "running HandleClose caller has bad lifecycle: process={:?} thread={:?} lifecycle={:?}",
                        self.process,
                        self.thread,
                        self.tasks.process_lifecycle(self.process),
                    );
                }
                #[cfg(deepwyrm_i1_evidence)]
                if status == DW_STATUS_SUCCESS
                    && let Some(process) = closed_process
                {
                    crate::test_support::observe_i1_child_cleanup(process, self.cpu);
                    crate::test_support::observe_i1_reclaim_allowed(self.cpu);
                }
                NativeSyscallResult::returning(status)
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
                NativeSyscallResult::returning(
                    crate::syscall::object_get_info_v1_with_device_objects(
                        &mut user,
                        &mut self.registry,
                        &self.memory,
                        &self.tasks,
                        &self.shared.device_resources,
                        &self.shared.interrupts,
                        self.process,
                        handle,
                        topic,
                        out_info,
                        out_size,
                        out_required_size,
                    ),
                )
            }
            NativeSyscallRequest::TaskGroupCreate {
                parent,
                requested_rights,
                out_handle,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::task_group_create(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    self.process,
                    parent,
                    requested_rights,
                    out_handle,
                    &mut self.cleanup,
                ))
            }
            NativeSyscallRequest::TaskGroupTerminate { .. } => {
                unreachable!("TaskGroupTerminate must be intercepted by the CPU-local facade")
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
                let status = crate::syscall::thread_start_with_access(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.execution,
                    self.process,
                    args,
                    args_size,
                    &mut self.cleanup,
                );
                drop(user);
                #[cfg(any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
                if status == DW_STATUS_SUCCESS {
                    self.observe_wyr1b_system_init_start()
                        .unwrap_or_else(|error| {
                            crate::test_support::complete_fail(wyr1b_submit_detail(error))
                        });
                }
                #[cfg(deepwyrm_dw1c_evidence)]
                if status == DW_STATUS_SUCCESS
                    && self.process == self.primordial_process
                    && self.evidence_init_process.is_some()
                {
                    crate::test_support::DW1C_EVIDENCE
                        .install()
                        .unwrap_or_else(|error| {
                            crate::test_support::complete_fail(0x2810_c000 | error as u32)
                        });
                }
                NativeSyscallResult::returning(status)
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
            NativeSyscallRequest::AddressRegionProtect {
                address_region,
                address,
                byte_len,
                protections,
            } => NativeSyscallResult::returning(self.protect_memory(
                address_region,
                address,
                byte_len,
                protections,
            )),
            NativeSyscallRequest::ProcessExit { exit_code } => self.exit_process(exit_code),
            NativeSyscallRequest::DeviceResourceClaim {
                resource_domain,
                resource_id,
                requested_rights,
                out_resource,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::device_resource_claim(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.boot_resource_grants,
                    &self.shared.device_resources,
                    self.process,
                    resource_domain,
                    resource_id,
                    requested_rights,
                    out_resource,
                ))
            }
            NativeSyscallRequest::DevicePioRead {
                resource,
                offset,
                width,
                out_value,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                let mut io = crate::arch::x86_64::io_port::X86PortIo;
                NativeSyscallResult::returning(crate::syscall::device_pio_read(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.device_resources,
                    &mut io,
                    self.process,
                    resource,
                    offset,
                    width,
                    out_value,
                ))
            }
            NativeSyscallRequest::DevicePioWrite {
                resource,
                offset,
                width,
                value,
            } => {
                let mut io = crate::arch::x86_64::io_port::X86PortIo;
                NativeSyscallResult::returning(crate::syscall::device_pio_write(
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.device_resources,
                    &mut io,
                    self.process,
                    resource,
                    offset,
                    width,
                    value,
                ))
            }
            NativeSyscallRequest::InterruptCreate {
                resource,
                requested_rights,
                out_interrupt,
            } => {
                let mut user = self.active.current_process_address_space(
                    self.active_root.as_ref().expect("active root"),
                    self.process,
                );
                NativeSyscallResult::returning(crate::syscall::interrupt_create(
                    &mut user,
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.device_resources,
                    &self.shared.interrupts,
                    &self.shared.interrupt_platform,
                    self.process,
                    resource,
                    requested_rights,
                    out_interrupt,
                ))
            }
            NativeSyscallRequest::InterruptAck { interrupt } => {
                #[cfg(deepwyrm_dw1d_evidence)]
                return NativeSyscallResult::returning(crate::syscall::interrupt_ack_dw1d(
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.interrupts,
                    &self.shared.interrupt_platform,
                    &self.shared.waits,
                    &self.shared.execution,
                    self.process,
                    interrupt,
                    &mut self.cleanup,
                ));
                #[cfg(not(deepwyrm_dw1d_evidence))]
                NativeSyscallResult::returning(crate::syscall::interrupt_ack(
                    &mut self.registry,
                    &mut self.tasks,
                    &self.shared.interrupts,
                    &self.shared.interrupt_platform,
                    self.process,
                    interrupt,
                    &mut self.cleanup,
                ))
            }
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
                let mut shootdown = user_access::LiveTlbShootdownDriver::current();
                let (mut publisher, coherency) = user
                .publisher_with_coherency::<
                    PRIMORDIAL_TABLE_CANDIDATES,
                    PRIMORDIAL_JOURNAL_ENTRIES,
                    PRIMORDIAL_INVALIDATIONS,
                >(target.address_space, target.region_key, &mut candidates)
                .map_err(|_| DW_STATUS_BAD_STATE)?;
                let mut publisher =
                    crate::memory::address_region::CoherentAddressSpacePublisher::<
                        _,
                        _,
                        { crate::cpu::CPU_CAPACITY },
                        1_000_000,
                    >::new(&mut publisher, coherency, &mut shootdown);
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
                let mut shootdown = user_access::LiveTlbShootdownDriver::current();
                let (mut publisher, coherency) = user
                .publisher_with_coherency::<
                    PRIMORDIAL_TABLE_CANDIDATES,
                    PRIMORDIAL_JOURNAL_ENTRIES,
                    PRIMORDIAL_INVALIDATIONS,
                >(target.address_space, target.region_key, &mut candidates)
                .unwrap_or_else(|_| panic!("primordial unmap publisher unavailable"));
                let mut publisher =
                    crate::memory::address_region::CoherentAddressSpacePublisher::<
                        _,
                        _,
                        { crate::cpu::CPU_CAPACITY },
                        1_000_000,
                    >::new(&mut publisher, coherency, &mut shootdown);
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

    fn protect_memory(
        &mut self,
        address_region: deepwyrm_abi::DwHandle,
        address: deepwyrm_abi::DwUserAddress,
        byte_len: u64,
        protections: u32,
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
                let mut shootdown = user_access::LiveTlbShootdownDriver::current();
                let (mut publisher, coherency) = user
                    .publisher_with_coherency::<
                        PRIMORDIAL_TABLE_CANDIDATES,
                        PRIMORDIAL_JOURNAL_ENTRIES,
                        PRIMORDIAL_INVALIDATIONS,
                    >(target.address_space, target.region_key, &mut candidates)
                    .unwrap_or_else(|_| panic!("primordial protect publisher unavailable"));
                let mut publisher =
                    crate::memory::address_region::CoherentAddressSpacePublisher::<
                        _,
                        _,
                        { crate::cpu::CPU_CAPACITY },
                        1_000_000,
                    >::new(&mut publisher, coherency, &mut shootdown);
                crate::syscall::address_region_protect_prepared(
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
                    protections,
                    &mut self.cleanup,
                )
            };
            for candidate in candidates.into_iter().flatten() {
                user.recycle_table_candidate(candidate);
            }
            user.select_process_for_return_validation(caller_process)
                .unwrap_or_else(|error| {
                    panic!("primordial protect caller-root restoration failed: {error:?}")
                });
            status
        })();
        self.commit_runtime_phase(phase);
        status
    }

    fn exit_process(&mut self, exit_code: u32) -> NativeSyscallResult {
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
        #[cfg(deepwyrm_i1_evidence)]
        let exiting_claim = self.shared.execution.running_claim_on(self.cpu);
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.services.terminal_cleanup(
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
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.cpu,
                self.process,
                self.thread,
                exit_code,
                &mut self.cleanup,
            )
        };
        if status == DW_STATUS_SUCCESS && control == SyscallControl::TerminateCurrent {
            self.install_deferred_current(
                deferred.unwrap_or_else(|| panic!("primordial exit omitted deferred reclaim")),
            );
            #[cfg(deepwyrm_i1_evidence)]
            if self.process != self.primordial_process {
                let claim = exiting_claim
                    .unwrap_or_else(|| panic!("I1 child exit omitted its execution claim"));
                crate::test_support::observe_i1_child_exit(
                    self.process,
                    self.cpu,
                    claim.generation(),
                );
            }
        } else {
            assert!(deferred.is_none());
        }
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("primordial exit output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("primordial exit atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn prepare_remote_process_exit(&mut self, exit_code: u32) -> ProcessTerminationPreparation {
        let inspected_threads = self
            .tasks
            .process_thread_keys(self.process)
            .unwrap_or_else(|_| panic!("exiting Process lost its Thread topology"));
        let plan = match self.terminal_stop_plan(&inspected_threads) {
            Ok(plan) => plan,
            Err(()) => return ProcessTerminationPreparation::Retry,
        };
        let phase = self.reserve_runtime_phase();
        self.assert_guard_free_external_work();
        #[cfg(deepwyrm_i1_evidence)]
        let exiting_claim = self.shared.execution.running_claim_on(self.cpu);
        let mut prepared = match self.prepare_process_exit_with_wait_cleanup(exit_code) {
            Ok(prepared) => prepared,
            Err(status) => {
                self.commit_runtime_phase(phase);
                return ProcessTerminationPreparation::Immediate(NativeSyscallResult::returning(
                    status,
                ));
            }
        };
        #[cfg(deepwyrm_i1_evidence)]
        if self.process != self.primordial_process {
            let claim = exiting_claim
                .unwrap_or_else(|| panic!("I1 child exit omitted its execution claim"));
            crate::test_support::observe_i1_child_exit(self.process, self.cpu, claim.generation());
        }
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
    ) -> Result<crate::syscall::PreparedProcessTermination<HANDLES, THREADS>, deepwyrm_abi::DwStatus>
    {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.services.terminal_cleanup(
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
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("process-exit output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("process-exit atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
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
            &self.tasks,
            &self.shared.execution,
            self.process,
            self.thread,
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
        self.assert_guard_free_external_work();
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
        #[cfg(deepwyrm_i1_evidence)]
        {
            let mask = identities
                .iter()
                .enumerate()
                .fold(0_u32, |mask, (cpu, identity)| {
                    if identity.is_some() {
                        mask | (1_u32 << cpu)
                    } else {
                        mask
                    }
                });
            crate::test_support::observe_i1_rendezvous_targets(mask);
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
            if cpu == self.cpu {
                continue;
            }
            let suspended = self
                .shared
                .execution
                .suspended_claim_on(cpu)
                .filter(|claim| terminal_threads.contains(&Some(claim.thread())));
            let running = self
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
                        || self.cpu_threads[cpu_index] != Some(physical.thread())
                    {
                        return Err(());
                    }
                    unentered[cpu_index] = Some(logical);
                    physical
                }
            };
            if self.root_switch_flights[cpu_index].is_some()
                || self.cpu_threads[cpu_index] != Some(claim.thread())
            {
                return Err(());
            }
            let Some(root) = self.active_roots[cpu_index].as_ref() else {
                return Err(());
            };
            let owner = self
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
                .shared
                .execution
                .retire_unentered_running_claim_on(replacement)
                .unwrap_or_else(|error| {
                    panic!("terminal logical replacement drifted after preparation: {error:?}")
                });
            self.stage_scheduler_quantum_cancellation_on(replacement.cpu(), cancelled_quantum);
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
    ) -> Result<crate::syscall::PreparedProcessTermination<HANDLES, THREADS>, deepwyrm_abi::DwStatus>
    {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.services.terminal_cleanup(
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
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("process termination output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("process termination atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
        result
    }

    fn prepare_remote_task_group_termination(
        &mut self,
        task_group: deepwyrm_abi::DwHandle,
        reason: deepwyrm_abi::DwTerminationReason,
    ) -> TaskGroupTerminationPreparation {
        let inspected_threads = match crate::syscall::inspect_task_group_termination_threads(
            &self.tasks,
            &self.shared.execution,
            self.process,
            self.thread,
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
        self.assert_guard_free_external_work();
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
        crate::syscall::PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>,
        deepwyrm_abi::DwStatus,
    > {
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; THREADS] =
            core::array::from_fn(|_| None);
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; THREADS] =
            core::array::from_fn(|_| None);
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let result = {
            let mut terminal = self.services.terminal_cleanup(
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
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.process,
                self.thread,
                task_group,
                reason,
                &mut self.cleanup,
            )
        };
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("TaskGroup termination output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("TaskGroup termination atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
        result
    }

    fn complete_task_group_termination(
        &mut self,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        prepared: crate::syscall::PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>,
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
            let mut terminal = self.services.terminal_cleanup(
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
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.cpu,
                self.process,
                self.thread,
                prepared,
                permits,
                &mut self.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        if status == DW_STATUS_SUCCESS {
            for target in process_keys.into_iter().flatten() {
                if target == self.process {
                    continue;
                }
                let root_object = self
                    .tasks
                    .root_region(target)
                    .unwrap_or_else(|error| {
                        panic!("terminated TaskGroup child root lookup failed: {error:?}")
                    })
                    .unwrap_or_else(|| panic!("terminated TaskGroup child has no root region"));
                let root_key =
                    crate::memory::address_region::AddressRegionObjectKey::from_object_id(
                        root_object,
                    );
                let address_space = self
                    .regions
                    .region(root_key)
                    .unwrap_or_else(|error| {
                        panic!("terminated TaskGroup child root disappeared: {error:?}")
                    })
                    .address_space_key();
                self.finish_inactive_process_teardown(target, root_key, address_space)
                    .unwrap_or_else(|_| {
                        panic!("terminated TaskGroup inactive child teardown drifted")
                    });
            }
        }
        let result = NativeSyscallResult { status, control };
        self.commit_runtime_phase(phase);
        result
    }

    fn complete_process_termination(
        &mut self,
        phase: crate::arch::x86_64::syscall::RuntimePhaseReservation,
        prepared: crate::syscall::PreparedProcessTermination<HANDLES, THREADS>,
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
            let mut terminal = self.services.terminal_cleanup(
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
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.cpu,
                self.process,
                self.thread,
                prepared,
                permits,
                &mut self.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        if status == DW_STATUS_SUCCESS && control == SyscallControl::ReturnToCaller {
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
        let mut discarded: [Option<user_access::OwnedLiveUserOutput>; 1] = [None];
        let mut atomic_pins: [Option<user_access::OwnedLiveAtomicU32>; 1] = [None];
        let mut wait_deadlines = crate::wait::engine::LiveWaitDeadlineAuthority;
        let (status, control, deferred) = {
            let mut terminal = self.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| discarded[0] = Some(output),
                |pin| atomic_pins[0] = Some(pin),
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
            &self.tasks,
            &self.shared.execution,
            self.process,
            self.thread,
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
        self.assert_guard_free_external_work();
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
            let mut terminal = self.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded[0].replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pins[0].replace(pin).is_none());
                },
            );
            crate::syscall::prepare_thread_terminate(
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
        for output in discarded.into_iter().flatten() {
            output
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("Thread termination output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("Thread termination atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
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
            let mut terminal = self.services.terminal_cleanup(
                Some(&mut wait_deadlines),
                |output| {
                    assert!(discarded[0].replace(output).is_none());
                },
                |pin| {
                    assert!(atomic_pins[0].replace(pin).is_none());
                },
            );
            crate::syscall::complete_prepared_thread_termination_after_remote_stops_on(
                &mut self.registry,
                &mut self.tasks,
                &self.shared.execution,
                &self.shared.waits,
                &mut terminal,
                self.cpu,
                self.process,
                self.thread,
                prepared,
                permits,
                &mut self.cleanup,
            )
        };
        self.finish_terminal_adapter_resources(discarded, atomic_pins, control, deferred);
        if status == DW_STATUS_SUCCESS && control == SyscallControl::ReturnToCaller {
            if let Some(target) = exited_process.filter(|target| *target != self.process) {
                let root_object = self
                    .tasks
                    .root_region(target)
                    .unwrap_or_else(|error| {
                        panic!("final-Thread child root lookup failed: {error:?}")
                    })
                    .unwrap_or_else(|| panic!("final-Thread child has no root AddressRegion"));
                let root_key =
                    crate::memory::address_region::AddressRegionObjectKey::from_object_id(
                        root_object,
                    );
                let address_space = self
                    .regions
                    .region(root_key)
                    .unwrap_or_else(|error| {
                        panic!("final-Thread child root disappeared: {error:?}")
                    })
                    .address_space_key();
                self.finish_inactive_process_teardown(target, root_key, address_space)
                    .unwrap_or_else(|_| panic!("final-Thread inactive child teardown drifted"));
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
                .discard_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("terminal adapter output pin drifted"));
        }
        for pin in atomic_pins.into_iter().flatten() {
            pin.release_terminal(&self.active.user_pins)
                .unwrap_or_else(|_| panic!("terminal adapter atomic pin drifted"));
        }
        let cleanup = self.services.take_cleanup();
        self.merge_cleanup(cleanup);
    }
}
