//! Target-only per-CPU DW0-H1 SYSCALL installation and entry ownership.

use core::cell::UnsafeCell;
use core::convert::Infallible;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::memory::kernel_stack::KernelStackBounds;

use super::frame::{PerCpuEntryState, RawSyscallFrame, ValidatedUserReturn};
use super::msr::{
    CR0_TASK_SWITCHED, CR4_FSGSBASE, IA32_EFER, SyscallMsrAccess, SyscallMsrPlan,
    SyscallMsrPlanError, SyscallMsrProgramError, normalize_cr0_for_e5, normalize_cr4_for_e4,
    program_and_verify, verify,
};
use super::runtime_binding::{
    RuntimeCarrierClaimError, RuntimeCarrierClaims, RuntimeCarrierLifecycle,
    RuntimeCarrierLifecycles,
};

const INSTALL_UNSTARTED: u8 = 0;
const INSTALLING: u8 = 1;
const INSTALLED: u8 = 2;
const RFLAGS_IF: u64 = 1 << 9;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_SYSCALL_SYSRET: u32 = 1 << 11;
const RFLAGS_AC: u64 = 1 << 18;

/// A CPU-private native-dispatch window.  e1 may latch while this is held,
/// but no safe-point may consume Stop/HoldSafe until the dispatch has dropped
/// the guard and no adapter can still be in usercopy.
static NATIVE_USERCOPY_WINDOW: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { AtomicU8::new(0) }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];

#[must_use = "the native usercopy window must close before a carrier safe point"]
struct NativeUsercopyWindow {
    cpu_index: usize,
}

impl NativeUsercopyWindow {
    fn enter_current() -> Result<Self, ()> {
        let cpu_index = current_cpu_index_for_diagnostics().ok_or(())?;
        NATIVE_USERCOPY_WINDOW[cpu_index]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ())?;
        Ok(Self { cpu_index })
    }
}

impl Drop for NativeUsercopyWindow {
    fn drop(&mut self) {
        NATIVE_USERCOPY_WINDOW[self.cpu_index]
            .compare_exchange(1, 0, Ordering::Release, Ordering::Acquire)
            .unwrap_or_else(|_| panic!("native usercopy window state drifted"));
    }
}

struct EntryStateStorage(UnsafeCell<PerCpuEntryState>);

impl EntryStateStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(PerCpuEntryState::empty()))
    }
}

#[allow(
    unsafe_code,
    reason = "DW0-E4 BSP entry state is single-CPU and assembly/Rust access is serialized with IF clear"
)]
unsafe impl Sync for EntryStateStorage {}

struct PlanStorage(UnsafeCell<MaybeUninit<SyscallMsrPlan>>);

impl PlanStorage {
    const fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "the one-shot install state publishes the immutable expected MSR plan"
)]
unsafe impl Sync for PlanStorage {}

static INSTALL_STATE: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { AtomicU8::new(INSTALL_UNSTARTED) }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static ENTRY_STATE: [EntryStateStorage; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { EntryStateStorage::new() }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static EXPECTED_PLAN: [PlanStorage; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { PlanStorage::uninit() }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];

const ENTRY_STATE_TERMINAL_REAPER_INDEX: usize = 0;
const ENTRY_STATE_CPU_INDEX: usize = 1;

const RUNTIME_UNBOUND: u8 = 0;
const RUNTIME_BINDING: u8 = 1;
const RUNTIME_BOUND: u8 = 2;

pub(crate) type SyscallRuntimeHandler = unsafe fn(*mut (), &mut RawSyscallFrame);
type FreshThreadRuntimeHandler = unsafe fn(*mut ()) -> !;
type IdleSchedulerRuntimeHandler = unsafe fn(*mut ()) -> !;
type UserExceptionRuntimeHandler =
    unsafe fn(*mut (), crate::arch::x86_64::exceptions::UserExceptionRecord) -> !;
type RendezvousGateHandler = unsafe fn(*mut ()) -> u8;
type RendezvousReaperHandler = unsafe fn(*mut ()) -> !;
type QuantumExpiryHandler = unsafe fn(*mut (), crate::task::SchedulerQuantumTicket) -> bool;
type PrepareQuantumHandler = unsafe fn(*mut (), u64) -> Option<crate::task::SchedulerQuantumTicket>;
type TimerPreIretHandler = unsafe fn(*mut (), &mut super::frame::RawCpl3TimerReturnFrame);

#[derive(Clone, Copy)]
struct RuntimeBindingState {
    context: *mut (),
    handler: SyscallRuntimeHandler,
    fresh_thread_handler: FreshThreadRuntimeHandler,
    idle_scheduler_handler: IdleSchedulerRuntimeHandler,
    user_exception_handler: UserExceptionRuntimeHandler,
    rendezvous_gate_handler: RendezvousGateHandler,
    rendezvous_reaper_handler: RendezvousReaperHandler,
    quantum_expiry_handler: QuantumExpiryHandler,
    prepare_quantum_handler: PrepareQuantumHandler,
    timer_pre_iret_handler: TimerPreIretHandler,
}

struct RuntimeStorage(UnsafeCell<MaybeUninit<RuntimeBindingState>>);

impl RuntimeStorage {
    const fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "one CPU publishes each immutable carrier pointer/function pair before that slot's CPL3 entry and IF-clear dispatch only reads its own slot"
)]
unsafe impl Sync for RuntimeStorage {}

static RUNTIME_STATE: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { AtomicU8::new(RUNTIME_UNBOUND) }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static RUNTIME: [RuntimeStorage; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { RuntimeStorage::uninit() }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static RUNTIME_CARRIER_CLAIMS: RuntimeCarrierClaims<
    { crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT },
> = RuntimeCarrierClaims::new();
static RUNTIME_CARRIER_LIFECYCLES: RuntimeCarrierLifecycles<
    { crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT },
> = RuntimeCarrierLifecycles::new();

const TERMINAL_ACTION_EMPTY: u8 = 0;
const TERMINAL_ACTION_WRITING: u8 = 1;
const TERMINAL_ACTION_READY: u8 = 2;
const TERMINAL_ACTION_READING: u8 = 3;

#[derive(Clone, Copy)]
enum TerminalAction {
    CompleteCurrent,
    InvalidReturn(super::frame::UserReturnError),
    UserException(crate::arch::x86_64::exceptions::UserExceptionRecord),
}

const RENDEZVOUS_ACTION_EMPTY: u8 = 0;
const RENDEZVOUS_ACTION_WRITING: u8 = 1;
const RENDEZVOUS_ACTION_READY: u8 = 2;
const RENDEZVOUS_ACTION_READING: u8 = 3;

#[derive(Clone, Copy)]
struct RendezvousAction(crate::arch::x86_64::rendezvous::StopRequest);

struct RendezvousActionStorage(UnsafeCell<MaybeUninit<RendezvousAction>>);

impl RendezvousActionStorage {
    const fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "each GS-selected CPU owns its rendezvous-action slot and atomic state publishes the Copy request across the dedicated reaper pivot"
)]
unsafe impl Sync for RendezvousActionStorage {}

static RENDEZVOUS_ACTION_STATE: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { AtomicU8::new(RENDEZVOUS_ACTION_EMPTY) };
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static RENDEZVOUS_ACTION: [RendezvousActionStorage;
    crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { RendezvousActionStorage::uninit() }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];

struct TerminalActionStorage(UnsafeCell<MaybeUninit<TerminalAction>>);

impl TerminalActionStorage {
    const fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "each GS-selected CPU owns its terminal-action slot and atomic state publishes the staged Copy payload across the stack pivot"
)]
unsafe impl Sync for TerminalActionStorage {}

static TERMINAL_ACTION_STATE: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { AtomicU8::new(TERMINAL_ACTION_EMPTY) };
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];
static TERMINAL_ACTION: [TerminalActionStorage; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { TerminalActionStorage::uninit() }; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT];

struct NativeSyscallRuntimeEntry<
    'runtime,
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
> {
    runtime: Pin<&'runtime mut R>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallRuntimeBindError {
    AlreadyBound,
    BoundaryNotInstalled,
    ContextAlreadyBound,
    InvalidCpu,
    NullContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallInstallError {
    AlreadyInstallingOrInstalled,
    DescriptorState,
    UnsupportedCpu,
    InterruptsEnabled,
    FsgsbaseNotCleared,
    FpSimdPolicyNotEnforced,
    InvalidMsrPlan(SyscallMsrPlanError),
    MsrReadback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryBindingError {
    BoundaryNotInstalled,
    ForeignKernelStack,
    GenerationExhausted,
}

struct LiveMsrAccess;

#[allow(
    unsafe_code,
    reason = "the target-only MSR access implementation delegates to the audited RDMSR/WRMSR primitives"
)]
impl SyscallMsrAccess for LiveMsrAccess {
    type Error = Infallible;

    fn read(&mut self, msr: u32) -> Result<u64, Self::Error> {
        Ok(unsafe { read_msr(msr) })
    }

    fn write(&mut self, msr: u32, value: u64) -> Result<(), Self::Error> {
        unsafe { write_msr(msr, value) };
        Ok(())
    }
}

#[allow(
    unsafe_code,
    reason = "RDMSR is the audited E4 privileged MSR read boundary"
)]
unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[allow(
    unsafe_code,
    reason = "WRMSR is the audited E4 privileged MSR write boundary"
)]
unsafe fn write_msr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

#[allow(
    unsafe_code,
    reason = "CR0.TS makes the E3 unavailable FP/SIMD policy architectural before any CPL3 execution"
)]
unsafe fn enforce_live_fp_simd_unavailable() -> Result<(), SyscallInstallError> {
    let before: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) before,
            options(nomem, nostack, preserves_flags)
        );
    }
    let expected = normalize_cr0_for_e5(before);
    if before != expected {
        unsafe {
            core::arch::asm!(
                "mov cr0, {}",
                in(reg) expected,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    let observed: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) observed,
            options(nomem, nostack, preserves_flags)
        );
    }
    if observed != expected || observed & CR0_TASK_SWITCHED == 0 {
        return Err(SyscallInstallError::FpSimdPolicyNotEnforced);
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "IF-clear syscall entry checks that user FP/SIMD remains trapped before and after runtime dispatch"
)]
fn live_fp_simd_unavailable_is_enforced() -> bool {
    let cr0: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) cr0,
            options(nomem, nostack, preserves_flags)
        );
    }
    cr0 & CR0_TASK_SWITCHED != 0
}

#[allow(
    unsafe_code,
    reason = "CR4 normalization is part of the audited no-FSGSBASE E4 boundary"
)]
unsafe fn normalize_live_cr4() -> Result<(), SyscallInstallError> {
    let before: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) before,
            options(nomem, nostack, preserves_flags)
        );
    }
    let expected = normalize_cr4_for_e4(before);
    if before != expected {
        unsafe {
            core::arch::asm!(
                "mov cr4, {}",
                in(reg) expected,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    let observed: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) observed,
            options(nomem, nostack, preserves_flags)
        );
    }
    if observed & CR4_FSGSBASE != 0 || observed != expected {
        return Err(SyscallInstallError::FsgsbaseNotCleared);
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "RFLAGS/CS observation verifies the privileged IF-clear installation context"
)]
unsafe fn installation_cpu_state_is_valid() -> bool {
    let rflags: u64;
    let cs: u16;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) rflags,
            options(nomem, preserves_flags)
        );
        core::arch::asm!(
            "mov {:x}, cs",
            out(reg) cs,
            options(nomem, nostack, preserves_flags)
        );
    }
    cs & 3 == 0 && rflags & RFLAGS_IF == 0
}

fn cpu_supports_syscall() -> bool {
    use core::arch::x86_64::__cpuid;
    let maximum = __cpuid(0x8000_0000).eax;
    maximum >= CPUID_EXTENDED_FEATURES
        && __cpuid(CPUID_EXTENDED_FEATURES).edx & CPUID_SYSCALL_SYSRET != 0
}

fn entry_state_address(cpu_index: usize) -> Option<u64> {
    ENTRY_STATE.get(cpu_index).map(|state| state.0.get() as u64)
}

#[allow(
    unsafe_code,
    reason = "one-shot BSP initialization writes the supervisor-only GS entry record before publishing the swapgs MSR pair"
)]
unsafe fn initialize_entry_state(
    cpu_index: usize,
    entry_stack_top: u64,
    terminal_reaper_top: u64,
) -> Result<(), SyscallInstallError> {
    let state = ENTRY_STATE
        .get(cpu_index)
        .ok_or(SyscallInstallError::DescriptorState)?;
    unsafe {
        state.0.get().write(PerCpuEntryState {
            entry_stack_top,
            reserved: [terminal_reaper_top, cpu_index as u64],
            ..PerCpuEntryState::empty()
        });
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "installed-state Acquire publication makes the expected MSR plan immutable"
)]
unsafe fn expected_plan(cpu_index: usize) -> Option<SyscallMsrPlan> {
    let plan = EXPECTED_PLAN.get(cpu_index)?;
    Some(unsafe { (*plan.0.get()).assume_init() })
}

fn map_program_error(error: SyscallMsrProgramError<Infallible>) -> SyscallInstallError {
    match error {
        SyscallMsrProgramError::Access(never) => match never {},
        SyscallMsrProgramError::Readback { .. } => SyscallInstallError::MsrReadback,
    }
}

#[allow(
    unsafe_code,
    reason = "fixed assembly symbol address is the IA32_LSTAR target"
)]
fn syscall_entry_address() -> u64 {
    unsafe extern "C" {
        static dw_x86_64_syscall_entry: u8;
    }
    core::ptr::addr_of!(dw_x86_64_syscall_entry) as u64
}

fn cpu_index_for_entry_state_address(address: u64) -> Option<usize> {
    ENTRY_STATE
        .iter()
        .position(|state| state.0.get() as u64 == address)
}

/// Finds the current CPU's private entry record from the architectural GS
/// pair. Kernel-origin paths use IA32_GS_BASE; a CPL3 exception that has not
/// executed SWAPGS yet retains the same record in IA32_KERNEL_GS_BASE.
#[allow(
    unsafe_code,
    reason = "RDMSR reads the current CPU's architectural GS base pair without mutating it"
)]
fn current_cpu_index() -> Option<usize> {
    let gs_base = unsafe { read_msr(super::msr::IA32_GS_BASE) };
    cpu_index_for_entry_state_address(gs_base).or_else(|| {
        let kernel_gs_base = unsafe { read_msr(super::msr::IA32_KERNEL_GS_BASE) };
        cpu_index_for_entry_state_address(kernel_gs_base)
    })
}

/// Returns the installed logical CPU slot selected by the current
/// GS/KERNEL_GS_BASE entry-record identity.
///
/// Early bootstrap and malformed architectural state deliberately return
/// `None`; diagnostics must remain best-effort before the per-CPU boundary is
/// installed.
pub(crate) fn current_cpu_index_for_diagnostics() -> Option<usize> {
    let cpu_index = current_cpu_index()?;
    (INSTALL_STATE.get(cpu_index)?.load(Ordering::Acquire) == INSTALLED).then_some(cpu_index)
}

/// Resolves the exact CPU that is publishing scheduler work. CPU0 is accepted
/// without GS identity only before syscall-boundary installation has started;
/// once any live boundary exists, malformed current-CPU state fails closed.
pub(crate) fn current_cpu_index_for_scheduler_request() -> Option<usize> {
    current_cpu_index_for_diagnostics()
        .or_else(|| (INSTALL_STATE[0].load(Ordering::Acquire) == INSTALL_UNSTARTED).then_some(0))
}

/// Observes the carrier-local condition required before an e1 stop safe point:
/// native dispatch has released every usercopy-capable adapter borrow, and the
/// architectural AC flag remains clear.  This deliberately does not use
/// CR4.SMAP: DW0-C keeps SMAP disabled by contract.
pub(crate) fn current_native_usercopy_is_quiescent() -> bool {
    let Some(cpu_index) = current_cpu_index_for_diagnostics() else {
        return false;
    };
    let rflags: u64;
    #[allow(
        unsafe_code,
        reason = "PUSHFQ/POP observes the current CPU flag word without changing it"
    )]
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) rflags,
            options(nomem, preserves_flags)
        );
    }
    NATIVE_USERCOPY_WINDOW[cpu_index].load(Ordering::Acquire) == 0 && rflags & RFLAGS_AC == 0
}

/// Confirms that this CPU reached Rust through its own guarded rendezvous
/// reaper stack rather than the interrupted Thread or entry stack.
pub(crate) fn current_cpu_is_on_terminal_reaper_stack() -> bool {
    let Some(cpu_index) = current_cpu_index_for_diagnostics() else {
        return false;
    };
    let Some(state) = current_entry_state() else {
        return false;
    };
    let Ok(layouts) = crate::arch::x86_64::linked_runtime_cpu_stack_layout() else {
        return false;
    };
    let Some(stack) = layouts.get(cpu_index).map(|layout| layout.terminal_reaper) else {
        return false;
    };
    let stack_pointer: u64;
    #[allow(
        unsafe_code,
        reason = "the reaper proof observes the current stack pointer without changing execution state"
    )]
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }
    state.reserved[ENTRY_STATE_TERMINAL_REAPER_INDEX] == stack.top
        && stack_pointer >= stack.bottom
        && stack_pointer <= stack.top
}

#[allow(
    unsafe_code,
    reason = "the exact architectural GS base selects one release-published static per-CPU entry record"
)]
fn current_entry_state() -> Option<&'static PerCpuEntryState> {
    let cpu_index = current_cpu_index()?;
    let state = ENTRY_STATE.get(cpu_index)?;
    Some(unsafe { &*state.0.get() })
}

#[allow(
    unsafe_code,
    reason = "the current CPU exclusively updates its GS-selected entry record while IF remains clear"
)]
unsafe fn current_entry_state_mut() -> Option<(usize, &'static mut PerCpuEntryState)> {
    let cpu_index = current_cpu_index()?;
    let state = ENTRY_STATE.get(cpu_index)?;
    Some((cpu_index, unsafe { &mut *state.0.get() }))
}

/// Installs one runtime CPU's private DW0-H1 SYSCALL/GS boundary.
///
/// # Safety
///
/// Must run at CPL0 on `cpu_index` with IF clear after that CPU's private
/// runtime GDT/TSS/IDT is active. The selected entry record and MSR plan must
/// not have been initialized before.
#[allow(
    unsafe_code,
    reason = "H1 programs CPU-local CR4/MSRs and publishes the swapgs-protected private GS entry-state base"
)]
pub(crate) unsafe fn install_syscall_boundary_for_slot(
    cpu_index: usize,
    stacks: crate::arch::x86_64::RuntimeCpuStackLayout,
) -> Result<(), SyscallInstallError> {
    let install_state = INSTALL_STATE
        .get(cpu_index)
        .ok_or(SyscallInstallError::DescriptorState)?;
    if install_state
        .compare_exchange(
            INSTALL_UNSTARTED,
            INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(SyscallInstallError::AlreadyInstallingOrInstalled);
    }
    let result = (|| {
        if !unsafe { installation_cpu_state_is_valid() } {
            return Err(SyscallInstallError::InterruptsEnabled);
        }
        if crate::arch::x86_64::runtime_cpu_descriptor_lifecycle(cpu_index)
            != Some(crate::arch::x86_64::RuntimeCpuDescriptorLifecycle::DescriptorsActive)
        {
            return Err(SyscallInstallError::DescriptorState);
        }
        if !cpu_supports_syscall() {
            return Err(SyscallInstallError::UnsupportedCpu);
        }
        unsafe { enforce_live_fp_simd_unavailable()? };
        unsafe { normalize_live_cr4()? };
        unsafe {
            initialize_entry_state(
                cpu_index,
                stacks.privilege_entry.top,
                stacks.terminal_reaper.top,
            )?
        };

        let mut access = LiveMsrAccess;
        let current_efer = match access.read(IA32_EFER) {
            Ok(value) => value,
            Err(never) => match never {},
        };
        let entry_state_base =
            entry_state_address(cpu_index).ok_or(SyscallInstallError::DescriptorState)?;
        let plan = SyscallMsrPlan::new(current_efer, syscall_entry_address(), entry_state_base)
            .map_err(SyscallInstallError::InvalidMsrPlan)?;
        program_and_verify(&mut access, plan).map_err(map_program_error)?;
        let expected = EXPECTED_PLAN
            .get(cpu_index)
            .ok_or(SyscallInstallError::DescriptorState)?;
        unsafe { (*expected.0.get()).write(plan) };
        Ok(())
    })();

    match result {
        Ok(()) => {
            install_state.store(INSTALLED, Ordering::Release);
            Ok(())
        }
        Err(error) => {
            install_state.store(INSTALL_UNSTARTED, Ordering::Release);
            Err(error)
        }
    }
}

/// Installs the BSP's private runtime-slot-zero SYSCALL boundary.
///
/// # Safety
///
/// Must run on the BSP with IF clear after
/// `migrate_bsp_to_runtime_slot0_after_deep_paging`.
#[allow(
    unsafe_code,
    reason = "the BSP wrapper binds the already-active runtime slot zero to CPU-local SYSCALL MSRs"
)]
pub(crate) unsafe fn install_syscall_boundary() -> Result<(), SyscallInstallError> {
    let stacks = crate::arch::x86_64::runtime_cpu_stack_layout(0)
        .map_err(|_| SyscallInstallError::DescriptorState)?;
    unsafe { install_syscall_boundary_for_slot(0, stacks) }?;
    crate::arch::x86_64::publish_runtime_cpu_online(0)
        .map_err(|_| SyscallInstallError::DescriptorState)
}

#[allow(
    unsafe_code,
    reason = "live E4 revalidation reads CR4 and the one-shot published expected MSR plan"
)]
pub(crate) fn validate_live_syscall_boundary() -> Result<(), SyscallInstallError> {
    let cpu_index = current_cpu_index().ok_or(SyscallInstallError::DescriptorState)?;
    if INSTALL_STATE[cpu_index].load(Ordering::Acquire) != INSTALLED
        || crate::arch::x86_64::runtime_cpu_descriptor_lifecycle(cpu_index)
            != Some(crate::arch::x86_64::RuntimeCpuDescriptorLifecycle::Online)
    {
        return Err(SyscallInstallError::DescriptorState);
    }
    let cr4: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) cr4,
            options(nomem, nostack, preserves_flags)
        );
    }
    if cr4 & CR4_FSGSBASE != 0 {
        return Err(SyscallInstallError::FsgsbaseNotCleared);
    }
    if !live_fp_simd_unavailable_is_enforced() {
        return Err(SyscallInstallError::FpSimdPolicyNotEnforced);
    }
    let plan = unsafe { expected_plan(cpu_index) }.ok_or(SyscallInstallError::DescriptorState)?;
    verify(&mut LiveMsrAccess, plan).map_err(map_program_error)
}

#[allow(
    unsafe_code,
    reason = "the current CPU's scheduler linearization updates only its GS-selected assembly entry record with IF clear"
)]
pub(crate) unsafe fn bind_current_thread_stack(
    stack: KernelStackBounds,
) -> Result<u64, EntryBindingError> {
    let (cpu_index, state) =
        unsafe { current_entry_state_mut() }.ok_or(EntryBindingError::BoundaryNotInstalled)?;
    if INSTALL_STATE[cpu_index].load(Ordering::Acquire) != INSTALLED {
        return Err(EntryBindingError::BoundaryNotInstalled);
    }
    let linked = crate::arch::x86_64::linked_thread_kernel_stack_layout()
        .map_err(|_| EntryBindingError::ForeignKernelStack)?;
    if !linked.contains(&stack) {
        return Err(EntryBindingError::ForeignKernelStack);
    }
    let next = state
        .binding_generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(EntryBindingError::GenerationExhausted)?;
    state.current_kernel_stack_top = stack.top;
    state.binding_generation = next;
    Ok(next)
}

/// Binds a context-switch destination that is either an owned Thread stack or
/// this exact CPU's private bootstrap/idle carrier.  The latter is admitted
/// only for the selector-private blocked-continuation detach path.
#[cfg(deepwyrm_dw1c_evidence)]
#[allow(
    unsafe_code,
    reason = "the current CPU exclusively updates its GS-selected entry record while IF remains clear"
)]
fn bind_current_switch_stack(stack: KernelStackBounds) -> Result<u64, EntryBindingError> {
    let (cpu_index, state) =
        unsafe { current_entry_state_mut() }.ok_or(EntryBindingError::BoundaryNotInstalled)?;
    if INSTALL_STATE[cpu_index].load(Ordering::Acquire) != INSTALLED {
        return Err(EntryBindingError::BoundaryNotInstalled);
    }
    let thread_stack = crate::arch::x86_64::linked_thread_kernel_stack_layout()
        .map_err(|_| EntryBindingError::ForeignKernelStack)?
        .contains(&stack);
    let idle_stack = crate::arch::x86_64::linked_runtime_cpu_stack_layout()
        .map_err(|_| EntryBindingError::ForeignKernelStack)?
        .get(cpu_index)
        .is_some_and(|layout| layout.ap_bootstrap == stack);
    if !thread_stack && !idle_stack {
        return Err(EntryBindingError::ForeignKernelStack);
    }
    let next = state
        .binding_generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(EntryBindingError::GenerationExhausted)?;
    state.current_kernel_stack_top = stack.top;
    state.binding_generation = next;
    Ok(next)
}

/// Publishes a stationary carrier for an installed CPU while it remains parked
/// in CPL0.
///
/// This establishes the bounded per-CPU runtime identity before later H2
/// integration releases APs into scheduler work. It does not bind a Thread
/// stack or enter userspace.
///
/// # Safety
///
/// `runtime` must remain stationary for the full kernel lifetime. The caller
/// must prove that `cpu_index` cannot execute userspace or otherwise reach the
/// carrier callbacks during publication, and must never recover another
/// reference to its sealed static storage. Binding only publishes a `Parked`
/// lifecycle state; a later explicit release is required before dispatch can
/// observe the binding.
#[allow(
    unsafe_code,
    reason = "one-shot AP carrier binding erases a unique pinned static address only after the CPU-private boundary is installed"
)]
pub(crate) unsafe fn bind_native_runtime_carrier_for_slot<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    cpu_index: crate::cpu::CpuIndex,
    mut runtime: Pin<&mut R>,
) -> Result<(), SyscallRuntimeBindError> {
    let cpu_index = cpu_index.index();
    if INSTALL_STATE
        .get(cpu_index)
        .is_none_or(|state| state.load(Ordering::Acquire) != INSTALLED)
        || crate::arch::x86_64::runtime_cpu_descriptor_lifecycle(cpu_index)
            != Some(crate::arch::x86_64::RuntimeCpuDescriptorLifecycle::Online)
    {
        return Err(SyscallRuntimeBindError::BoundaryNotInstalled);
    }
    let context = unsafe { Pin::get_unchecked_mut(runtime.as_mut()) as *mut R };
    unsafe {
        publish_syscall_runtime(
            cpu_index,
            context.cast::<()>(),
            native_runtime_trampoline::<R>,
            native_runtime_fresh_thread::<R>,
            native_runtime_idle_scheduler::<R>,
            native_runtime_user_exception::<R>,
            native_runtime_rendezvous_gate::<R>,
            native_runtime_rendezvous_reaper::<R>,
            native_runtime_quantum_expiry::<R>,
            native_runtime_prepare_quantum::<R>,
            native_runtime_timer_pre_iret::<R>,
        )
    }?;
    RUNTIME_CARRIER_LIFECYCLES
        .bind_parked(cpu_index)
        .map_err(|_| SyscallRuntimeBindError::AlreadyBound)
}

/// Publishes CPU0's already-running native carrier without placing it in the
/// AP holding protocol. The two one-shot lifecycle stores are adjacent: CPU0
/// never waits in `Parked`, and scheduler normalization separately proves its
/// existing Running claim before AP release.
#[allow(
    unsafe_code,
    reason = "CPU0 uses the same stationary one-shot carrier publication as APs but has an already-running scheduler claim"
)]
pub(crate) unsafe fn bind_running_native_runtime_carrier_for_slot<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    cpu: crate::cpu::CpuIndex,
    runtime: Pin<&mut R>,
) -> Result<(), SyscallRuntimeBindError> {
    if cpu != crate::cpu::CpuIndex::BOOTSTRAP {
        return Err(SyscallRuntimeBindError::InvalidCpu);
    }
    unsafe { bind_native_runtime_carrier_for_slot(cpu, runtime) }?;
    release_native_runtime_carrier_for_slot(cpu)
}

/// Releases one already-bound carrier after the complete SMP runtime join.
///
/// This intentionally does not wake an AP, choose runnable work, or publish
/// scheduler ownership. The H2 join must establish remote-stop and TLB
/// acknowledgement before it invokes this final gate on a non-BSP CPU.
pub(crate) fn release_native_runtime_carrier_for_slot(
    cpu: crate::cpu::CpuIndex,
) -> Result<(), SyscallRuntimeBindError> {
    let cpu_index = cpu.index();
    if RUNTIME_STATE
        .get(cpu_index)
        .is_none_or(|state| state.load(Ordering::Acquire) != RUNTIME_BOUND)
    {
        return Err(SyscallRuntimeBindError::BoundaryNotInstalled);
    }
    RUNTIME_CARRIER_LIFECYCLES
        .release(cpu_index)
        .map_err(|_| SyscallRuntimeBindError::AlreadyBound)
}

pub(crate) fn native_runtime_carrier_lifecycle(
    cpu: crate::cpu::CpuIndex,
) -> Option<RuntimeCarrierLifecycle> {
    RUNTIME_CARRIER_LIFECYCLES.lifecycle(cpu.index())
}

#[allow(
    unsafe_code,
    reason = "SYSCALL dispatch reads the current CPU's private binding generation while FMASK keeps IF clear"
)]
pub(crate) fn current_binding_generation() -> u64 {
    current_entry_state().map_or(0, |state| state.binding_generation)
}

/// Publishes one CPU's private syscall execution carrier.
///
/// # Safety
///
/// The caller must keep `context` stationary and exclusively owned by
/// `cpu_index` for the full nonreturning lifetime of that CPU's private
/// native-runtime entry frame. Shared runtime state reachable through the
/// carrier must use its own bounded interior synchronization.
#[allow(
    unsafe_code,
    reason = "per-CPU one-shot publication stores a unique pinned carrier address plus its monomorphized dispatcher"
)]
unsafe fn publish_syscall_runtime(
    cpu_index: usize,
    context: *mut (),
    handler: SyscallRuntimeHandler,
    fresh_thread_handler: FreshThreadRuntimeHandler,
    idle_scheduler_handler: IdleSchedulerRuntimeHandler,
    user_exception_handler: UserExceptionRuntimeHandler,
    rendezvous_gate_handler: RendezvousGateHandler,
    rendezvous_reaper_handler: RendezvousReaperHandler,
    quantum_expiry_handler: QuantumExpiryHandler,
    prepare_quantum_handler: PrepareQuantumHandler,
    timer_pre_iret_handler: TimerPreIretHandler,
) -> Result<(), SyscallRuntimeBindError> {
    let state = RUNTIME_STATE
        .get(cpu_index)
        .ok_or(SyscallRuntimeBindError::InvalidCpu)?;
    let storage = RUNTIME
        .get(cpu_index)
        .ok_or(SyscallRuntimeBindError::InvalidCpu)?;
    if state
        .compare_exchange(
            RUNTIME_UNBOUND,
            RUNTIME_BINDING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(SyscallRuntimeBindError::AlreadyBound);
    }
    if let Err(error) = RUNTIME_CARRIER_CLAIMS.claim(cpu_index, context) {
        state.store(RUNTIME_UNBOUND, Ordering::Release);
        return Err(match error {
            RuntimeCarrierClaimError::InvalidSlot => SyscallRuntimeBindError::InvalidCpu,
            RuntimeCarrierClaimError::NullContext => SyscallRuntimeBindError::NullContext,
            RuntimeCarrierClaimError::SlotAlreadyClaimed => SyscallRuntimeBindError::AlreadyBound,
            RuntimeCarrierClaimError::ContextAlreadyClaimed => {
                SyscallRuntimeBindError::ContextAlreadyBound
            }
        });
    }
    unsafe {
        (*storage.0.get()).write(RuntimeBindingState {
            context,
            handler,
            fresh_thread_handler,
            idle_scheduler_handler,
            user_exception_handler,
            rendezvous_gate_handler,
            rendezvous_reaper_handler,
            quantum_expiry_handler,
            prepare_quantum_handler,
            timer_pre_iret_handler,
        });
    }
    state.store(RUNTIME_BOUND, Ordering::Release);
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Acquire observes only the current CPU's immutable one-shot carrier binding published before its CPL3 entry"
)]
fn runtime_binding() -> Option<RuntimeBindingState> {
    let cpu_index = current_cpu_index_for_diagnostics()?;
    if RUNTIME_STATE.get(cpu_index)?.load(Ordering::Acquire) != RUNTIME_BOUND {
        return None;
    }
    if RUNTIME_CARRIER_LIFECYCLES.lifecycle(cpu_index) != Some(RuntimeCarrierLifecycle::Executing) {
        return None;
    }
    let storage = RUNTIME.get(cpu_index)?;
    Some(unsafe { (*storage.0.get()).assume_init() })
}

/// Reacquires the erased runtime carrier published for the physical CPU on
/// which a suspended kernel continuation actually resumed. Kernel stack
/// continuations may migrate, so the raw pointer saved in the outgoing Rust
/// frame is not destination authority after a context switch returns.
fn current_runtime_context<R>() -> Option<*mut ()>
where
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
{
    let binding = runtime_binding()?;
    let expected = native_runtime_trampoline::<R> as SyscallRuntimeHandler as usize;
    (binding.handler as usize == expected).then_some(binding.context)
}

#[allow(
    unsafe_code,
    reason = "the CPU-private action slot is published before the divergent reaper consumes it"
)]
fn stage_rendezvous_action(action: RendezvousAction) -> Result<(), ()> {
    let cpu_index = current_cpu_index_for_diagnostics().ok_or(())?;
    let state = RENDEZVOUS_ACTION_STATE.get(cpu_index).ok_or(())?;
    let storage = RENDEZVOUS_ACTION.get(cpu_index).ok_or(())?;
    state
        .compare_exchange(
            RENDEZVOUS_ACTION_EMPTY,
            RENDEZVOUS_ACTION_WRITING,
            Ordering::Acquire,
            Ordering::Acquire,
        )
        .map_err(|_| ())?;
    unsafe { (*storage.0.get()).write(action) };
    state.store(RENDEZVOUS_ACTION_READY, Ordering::Release);
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "the CPU-private reaper acquires and consumes exactly one staged rendezvous action"
)]
fn take_rendezvous_action() -> Option<RendezvousAction> {
    let cpu_index = current_cpu_index_for_diagnostics()?;
    let state = RENDEZVOUS_ACTION_STATE.get(cpu_index)?;
    let storage = RENDEZVOUS_ACTION.get(cpu_index)?;
    state
        .compare_exchange(
            RENDEZVOUS_ACTION_READY,
            RENDEZVOUS_ACTION_READING,
            Ordering::Acquire,
            Ordering::Acquire,
        )
        .ok()?;
    let action = unsafe { (*storage.0.get()).assume_init_read() };
    state.store(RENDEZVOUS_ACTION_EMPTY, Ordering::Release);
    Some(action)
}

#[allow(
    unsafe_code,
    reason = "the IPI pre-IRET gate invokes only its immutable current-CPU carrier callback"
)]
unsafe fn native_runtime_rendezvous_gate<R: crate::syscall::native::NativeRendezvousRuntime>(
    context: *mut (),
) -> u8 {
    match crate::time::service_current_rendezvous_latch().unwrap_or_else(|_| halt_forever()) {
        crate::arch::x86_64::rendezvous::MailboxNotification::None
        | crate::arch::x86_64::rendezvous::MailboxNotification::Wake => 0,
        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
            stage_rendezvous_action(RendezvousAction(request)).unwrap_or_else(|_| halt_forever());
            // The assembly immediately pivots away from the interrupted IPI
            // frame; a nonzero result is never allowed to IRET to CPL3.
            let _ = context;
            1
        }
        // The exact request has already been acknowledged by a stopped
        // carrier and remains only to gate initiator reclaim. A replacement
        // carrier on this CPU must neither acknowledge it again nor inherit
        // the stopped IPI frame.
        crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => 0,
    }
}

#[allow(
    unsafe_code,
    reason = "the dedicated rendezvous reaper receives the immutable current-CPU carrier context"
)]
unsafe fn native_runtime_rendezvous_reaper<R: crate::syscall::native::NativeRendezvousRuntime>(
    context: *mut (),
) -> ! {
    let RendezvousAction(request) = take_rendezvous_action().unwrap_or_else(|| halt_forever());
    let reaper = crate::arch::x86_64::rendezvous::verify_native_rendezvous_reaper_entry()
        .unwrap_or_else(|| halt_forever());
    let runtime = unsafe { &mut *context.cast::<R>() };
    runtime.rendezvous_stop(request, reaper)
}

/// Abandons the current continuation for the separate e1 reaper seam.  The
/// staged request and immutable bound carrier are both selected by the current
/// CPU; unlike terminal syscall cleanup, no syscall terminal action crosses
/// this boundary.
#[allow(
    unsafe_code,
    reason = "the private ABI declaration and call enter the audited divergent e1 reaper pivot"
)]
fn handoff_to_rendezvous_reaper(context: *mut ()) -> ! {
    unsafe extern "sysv64" {
        fn dw_x86_64_rendezvous_reaper_handoff() -> !;
    }
    let _ = context;
    #[allow(
        unsafe_code,
        reason = "the audited assembly pivot selects the current CPU's private reaper stack and never returns"
    )]
    unsafe {
        dw_x86_64_rendezvous_reaper_handoff()
    }
}

/// Pivots a detached carrier entry onto the dedicated rendezvous reaper after
/// scheduler synchronization observes an exact remote Stop. Detached entries
/// have no syscall/timer frame to return through, so they must consume the
/// same stationary mailbox authority directly and abandon their carrier stack.
pub(crate) fn handoff_current_rendezvous_from_carrier() -> ! {
    match crate::arch::x86_64::idle::take_current_notification_at_safe_point() {
        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
            stage_rendezvous_action(RendezvousAction(request)).unwrap_or_else(|_| halt_forever());
            handoff_to_rendezvous_reaper(core::ptr::null_mut())
        }
        crate::arch::x86_64::rendezvous::MailboxNotification::None
        | crate::arch::x86_64::rendezvous::MailboxNotification::Wake
        | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => halt_forever(),
    }
}

/// Called by the CPL3-origin e1 assembly boundary after EOI/latch and before
/// GS restoration/IRET. Zero permits return; one enters the dedicated reaper.
#[allow(
    unsafe_code,
    reason = "the audited assembly gate calls this exact fixed symbol and immutable callback"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_x86_64_rendezvous_pre_iret_gate() -> u8 {
    let binding = runtime_binding().unwrap_or_else(|| halt_forever());
    unsafe { (binding.rendezvous_gate_handler)(binding.context) }
}

/// Diverges from the interrupted IPI frame onto the CPU-private reaper stack.
#[allow(
    unsafe_code,
    reason = "the audited assembly reaper calls this exact fixed symbol and immutable callback"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_x86_64_rendezvous_reaper() -> ! {
    let binding = runtime_binding().unwrap_or_else(|| halt_forever());
    unsafe { (binding.rendezvous_reaper_handler)(binding.context) }
}

#[allow(
    unsafe_code,
    reason = "the interrupt dispatcher invokes only the immutable CPU-local carrier callback with an exact scheduler ticket"
)]
unsafe fn native_runtime_quantum_expiry<R: crate::syscall::native::NativeSyscallFrameRuntime>(
    context: *mut (),
    ticket: crate::task::SchedulerQuantumTicket,
) -> bool {
    let runtime = unsafe { &mut *context.cast::<R>() };
    runtime
        .publish_quantum_expiry(ticket)
        .unwrap_or_else(|_| halt_forever())
}

#[allow(
    unsafe_code,
    reason = "the guard-free quantum-arm seam briefly reborrows the current CPU's unique carrier"
)]
unsafe fn native_runtime_prepare_quantum<R: crate::syscall::native::NativeSyscallFrameRuntime>(
    context: *mut (),
    now_ns: u64,
) -> Option<crate::task::SchedulerQuantumTicket> {
    let runtime = unsafe { &mut *context.cast::<R>() };
    runtime
        .prepare_quantum(now_ns)
        .unwrap_or_else(|_| halt_forever())
}

#[allow(
    unsafe_code,
    reason = "the immutable CPU-local binding pairs the exact ticket with its monomorphized runtime callback"
)]
pub(crate) fn publish_current_quantum_expiry(
    ticket: crate::task::SchedulerQuantumTicket,
) -> Result<bool, ()> {
    let binding = runtime_binding().ok_or(())?;
    Ok(unsafe { (binding.quantum_expiry_handler)(binding.context, ticket) })
}

/// Begins a fresh exact quantum only after all runtime/scheduler guards have
/// been released. The time service performs LAPIC MMIO through its own
/// guard-free prepare/program/revalidate sequence.
#[allow(
    unsafe_code,
    reason = "the immutable CPU-local binding briefly reborrows its unique carrier to mint one exact scheduler ticket"
)]
fn arm_current_normal_quantum() {
    let binding = runtime_binding().unwrap_or_else(|| halt_forever());
    let now_ns = crate::time::monotonic_now().unwrap_or_else(|_| halt_forever());
    if let Some(ticket) = unsafe { (binding.prepare_quantum_handler)(binding.context, now_ns) } {
        crate::time::arm_scheduler_quantum(ticket).unwrap_or_else(|_| halt_forever());
    }
}

fn poll_timer_return_stop(context: *mut ()) {
    match crate::arch::x86_64::idle::take_current_notification_at_safe_point() {
        crate::arch::x86_64::rendezvous::MailboxNotification::None
        | crate::arch::x86_64::rendezvous::MailboxNotification::Wake
        | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {}
        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
            stage_rendezvous_action(RendezvousAction(request)).unwrap_or_else(|_| halt_forever());
            handoff_to_rendezvous_reaper(context);
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the timer frame remains on the current Thread's bound stack while the lifetime-branded switch plan is consumed immediately"
)]
unsafe fn native_runtime_timer_pre_iret<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    mut context: *mut (),
    frame: &mut super::frame::RawCpl3TimerReturnFrame,
) {
    poll_timer_return_stop(context);
    validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
    {
        let runtime = unsafe { &mut *context.cast::<R>() };
        if let Err(error) = runtime.authorize_timer_return(frame) {
            invalid_bound_return::<R>(context, error);
        }
    }
    let has_request = {
        let runtime = unsafe { &mut *context.cast::<R>() };
        runtime.has_reschedule_request()
    };
    if has_request {
        let plan = {
            let runtime = unsafe { &mut *context.cast::<R>() };
            unsafe { runtime.prepare_preemption() }
        };
        match plan {
            crate::syscall::native::NativePreemptionPlan::Return => {}
            crate::syscall::native::NativePreemptionPlan::Switch(plan) => {
                switch_kernel_context(plan);
                context = current_runtime_context::<R>().unwrap_or_else(|| halt_forever());
                let runtime = unsafe { &mut *context.cast::<R>() };
                if let Err(error) = runtime.resume_timer_preemption(frame) {
                    invalid_bound_return::<R>(context, error);
                }
            }
        }
    }
    poll_timer_return_stop(context);
    arm_current_normal_quantum();
    poll_timer_return_stop(context);
}

/// Fixed assembly seam for CPL3-origin Local APIC timer return. Returning from
/// this function means the retained frame was revalidated for the exact
/// scheduler-current Thread and owns a fresh quantum source.
#[allow(
    unsafe_code,
    reason = "the audited assembly supplies the complete in-place 160-byte timer frame"
)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "sysv64" fn dw_x86_64_timer_pre_iret_gate(
    frame: *mut super::frame::RawCpl3TimerReturnFrame,
) {
    if frame.is_null() || (frame as usize) & 7 != 0 {
        halt_forever();
    }
    let binding = runtime_binding().unwrap_or_else(|| halt_forever());
    unsafe { (binding.timer_pre_iret_handler)(binding.context, &mut *frame) }
}

#[allow(
    unsafe_code,
    reason = "the current CPU exclusively stages one Copy terminal action before Release publication to its GS-selected reaper"
)]
fn stage_terminal_action(action: TerminalAction) -> Result<(), ()> {
    let cpu_index = current_cpu_index_for_diagnostics().ok_or(())?;
    let state = TERMINAL_ACTION_STATE.get(cpu_index).ok_or(())?;
    let storage = TERMINAL_ACTION.get(cpu_index).ok_or(())?;
    state
        .compare_exchange(
            TERMINAL_ACTION_EMPTY,
            TERMINAL_ACTION_WRITING,
            Ordering::Acquire,
            Ordering::Acquire,
        )
        .map_err(|_| ())?;
    unsafe { (*storage.0.get()).write(action) };
    state.store(TERMINAL_ACTION_READY, Ordering::Release);
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Acquire claims the current CPU's Copy terminal payload after the assembly stack pivot and no other CPU can select this GS-owned slot"
)]
fn take_terminal_action() -> Option<TerminalAction> {
    let cpu_index = current_cpu_index_for_diagnostics()?;
    let state = TERMINAL_ACTION_STATE.get(cpu_index)?;
    let storage = TERMINAL_ACTION.get(cpu_index)?;
    state
        .compare_exchange(
            TERMINAL_ACTION_READY,
            TERMINAL_ACTION_READING,
            Ordering::Acquire,
            Ordering::Acquire,
        )
        .ok()?;
    let action = unsafe { (*storage.0.get()).assume_init_read() };
    state.store(TERMINAL_ACTION_EMPTY, Ordering::Release);
    Some(action)
}

#[allow(
    unsafe_code,
    reason = "the private divergent entry retains this CPU's pinned carrier owner while the terminal action is staged without reborrowing it"
)]
fn invalid_bound_return<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    context: *mut (),
    error: super::frame::UserReturnError,
) -> ! {
    stage_terminal_action(TerminalAction::InvalidReturn(error)).unwrap_or_else(|_| halt_forever());
    handoff_to_terminal_reaper::<R>(context)
}

#[allow(
    unsafe_code,
    reason = "the exception callback stages a Copy record in CPU-local storage and abandons the faulting stack before runtime mutation"
)]
unsafe fn native_runtime_user_exception<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    context: *mut (),
    record: crate::arch::x86_64::exceptions::UserExceptionRecord,
) -> ! {
    stage_terminal_action(TerminalAction::UserException(record)).unwrap_or_else(|_| halt_forever());
    handoff_to_terminal_reaper::<R>(context)
}

#[allow(
    unsafe_code,
    reason = "the immutable runtime binding pairs its erased context with the monomorphized exception handler published before CPL3 entry"
)]
fn dispatch_bound_native_runtime_user_exception(
    record: crate::arch::x86_64::exceptions::UserExceptionRecord,
) -> ! {
    let Some(binding) = runtime_binding() else {
        halt_forever();
    };
    unsafe { (binding.user_exception_handler)(binding.context, record) }
}

/// Binds CPL3 exception dispatch to the current CPU's one-shot carrier identity
/// published by `enter_native_syscall_runtime` before userspace can execute.
pub(crate) fn bind_native_runtime_user_exception_handler() -> Result<
    crate::arch::x86_64::exceptions::UserExceptionBinding,
    crate::arch::x86_64::exceptions::UserExceptionBindError,
> {
    crate::arch::x86_64::exceptions::bind_user_exception_handler(
        dispatch_bound_native_runtime_user_exception,
    )
}

#[allow(
    unsafe_code,
    reason = "the fixed first-run entry reborrows only the current CPU's uniquely published carrier for one divergent fresh-Thread launch"
)]
unsafe fn native_runtime_fresh_thread<R: crate::syscall::native::NativeSyscallFrameRuntime>(
    context: *mut (),
) -> ! {
    let runtime = unsafe { &mut *context.cast::<R>() };
    runtime.enter_scheduled_fresh_thread()
}

#[allow(
    unsafe_code,
    reason = "the AP scheduler entry reborrows only its uniquely published CPU-local carrier"
)]
unsafe fn native_runtime_idle_scheduler<R: crate::syscall::native::NativeSyscallFrameRuntime>(
    context: *mut (),
) -> ! {
    let runtime = unsafe { &mut *context.cast::<R>() };
    runtime.enter_idle_scheduler()
}

#[allow(
    unsafe_code,
    reason = "the assembly handoff has abandoned the deferred Thread stack before the per-CPU staged terminal action mutates its uniquely bound carrier"
)]
unsafe extern "sysv64" fn native_runtime_terminal_reaper<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    context: *mut (),
) -> ! {
    let Some(action) = take_terminal_action() else {
        halt_forever();
    };
    let runtime = unsafe { &mut *context.cast::<R>() };
    match action {
        TerminalAction::CompleteCurrent => {}
        TerminalAction::InvalidReturn(error) => {
            runtime.invalid_return(error);
        }
        TerminalAction::UserException(record) => {
            runtime.user_exception(record);
        }
    }
    runtime.terminate_current()
}

#[allow(
    unsafe_code,
    reason = "the audited assembly boundary clears IF, switches to the guarded linker-owned reaper stack, and never returns to the deferred Thread stack"
)]
fn handoff_to_terminal_reaper<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    context: *mut (),
) -> ! {
    unsafe extern "sysv64" {
        fn dw_x86_64_terminal_reaper_handoff(
            context: *mut (),
            callback: unsafe extern "sysv64" fn(*mut ()) -> !,
        ) -> !;
    }
    let Some(state) = current_entry_state() else {
        halt_forever();
    };
    if state.reserved[ENTRY_STATE_TERMINAL_REAPER_INDEX] == 0
        || usize::try_from(state.reserved[ENTRY_STATE_CPU_INDEX])
            .ok()
            .and_then(|index| ENTRY_STATE.get(index))
            .is_none()
    {
        halt_forever();
    }
    unsafe { dw_x86_64_terminal_reaper_handoff(context, native_runtime_terminal_reaper::<R>) }
}

#[allow(
    unsafe_code,
    reason = "the current CPU's unique carrier is reborrowed only in bounded regions that do not span a kernel-context switch"
)]
unsafe fn native_runtime_trampoline<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    mut context: *mut (),
    frame: &mut RawSyscallFrame,
) {
    if !crate::time::timer_service_is_healthy()
        || !crate::arch::x86_64::idle::live_idle_wake_is_healthy()
    {
        halt_forever();
    }
    // The syscall gate entered with IF clear. A remote Stop may therefore be
    // published in the stationary mailbox while its e1 delivery is still
    // pending in the local APIC. Poll the authoritative mailbox before any
    // usercopy or syscall authority can observe terminal task state.
    match crate::arch::x86_64::idle::take_current_notification_at_safe_point() {
        crate::arch::x86_64::rendezvous::MailboxNotification::None
        | crate::arch::x86_64::rendezvous::MailboxNotification::Wake
        | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {}
        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
            stage_rendezvous_action(RendezvousAction(request)).unwrap_or_else(|_| halt_forever());
            handoff_to_rendezvous_reaper(context);
        }
    }
    let usercopy_window = NativeUsercopyWindow::enter_current().unwrap_or_else(|_| halt_forever());
    let control = {
        let runtime = unsafe { &mut *context.cast::<R>() };
        crate::syscall::native::dispatch_frame(runtime, frame, current_binding_generation())
    };
    // `dispatch_frame` may authorize a frame, but the raw assembly has not
    // returned to it yet. Dropping this guard makes that authorization
    // revocable by the following e1 safe point.
    drop(usercopy_window);
    // Recheck the authoritative mailbox after the guarded syscall/return
    // transaction. The initiator may have published terminal state and Stop
    // while this CPU was waiting to reacquire the shared runtime authority for
    // return authorization, before e1 could run with IF clear.
    match crate::arch::x86_64::idle::take_current_notification_at_safe_point() {
        crate::arch::x86_64::rendezvous::MailboxNotification::None
        | crate::arch::x86_64::rendezvous::MailboxNotification::Wake
        | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {}
        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
            stage_rendezvous_action(RendezvousAction(request)).unwrap_or_else(|_| halt_forever());
            handoff_to_rendezvous_reaper(context);
        }
    }
    match crate::time::service_current_rendezvous_latch().unwrap_or_else(|_| halt_forever()) {
        crate::arch::x86_64::rendezvous::MailboxNotification::None
        | crate::arch::x86_64::rendezvous::MailboxNotification::Wake => {}
        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
            stage_rendezvous_action(RendezvousAction(request)).unwrap_or_else(|_| halt_forever());
            handoff_to_rendezvous_reaper(context);
        }
        crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {}
    }
    if control == crate::syscall::native::SyscallControl::ServiceRendezvous {
        match crate::arch::x86_64::idle::take_current_notification_at_safe_point() {
            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
                stage_rendezvous_action(RendezvousAction(request))
                    .unwrap_or_else(|_| halt_forever());
                handoff_to_rendezvous_reaper(context);
            }
            crate::arch::x86_64::rendezvous::MailboxNotification::None
            | crate::arch::x86_64::rendezvous::MailboxNotification::Wake
            | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => halt_forever(),
        }
    }
    let control = if control == crate::syscall::native::SyscallControl::CompleteRemoteStop {
        let runtime = unsafe { &mut *context.cast::<R>() };
        runtime.complete_remote_stop(frame, current_binding_generation())
    } else {
        control
    };
    match control {
        crate::syscall::native::SyscallControl::ReturnToCaller => {}
        crate::syscall::native::SyscallControl::TerminateCurrent => {
            stage_terminal_action(TerminalAction::CompleteCurrent)
                .unwrap_or_else(|_| halt_forever());
            handoff_to_terminal_reaper::<R>(context)
        }
        crate::syscall::native::SyscallControl::SuspendCurrent => {
            let plan = {
                let runtime = unsafe { &mut *context.cast::<R>() };
                // SAFETY: the syscall assembly transferred this exact current
                // Thread frame to its bound kernel stack before entering the
                // trampoline; the runtime implementation is required to pass
                // only the fixed architecture-owned first-run entry.
                unsafe { runtime.prepare_suspend(frame) }
            };
            match plan {
                crate::syscall::native::NativeSuspendPlan::Switch(plan) => {
                    switch_kernel_context(plan);
                }
                crate::syscall::native::NativeSuspendPlan::IdleCurrent => {
                    loop {
                        let idle = crate::arch::x86_64::idle::prepare_current_idle()
                            .unwrap_or_else(|_| halt_forever());
                        let poll = {
                            let runtime = unsafe { &mut *context.cast::<R>() };
                            // SAFETY: this loop has not left the suspended current
                            // continuation; IRQ polling may change logical state but
                            // not the physically active kernel-stack carrier.
                            unsafe { runtime.poll_idle_suspend(frame) }
                        };
                        match poll {
                            crate::syscall::native::NativeIdleSuspendPoll::Continue => {
                                // SYSCALL FMASK keeps IF clear from the final
                                // scheduler rescan through this commit. The only
                                // re-enable is the atomic sti; hlt sequence below,
                                // so an e1 Wake cannot be consumed and lost in
                                // between publication and the architectural halt.
                                let idle_commit =
                                    crate::arch::x86_64::idle::commit_current_idle(idle);
                                let halt = match idle_commit {
                                    Ok(halt) => halt,
                                    Err(failure)
                                        if failure.error()
                                            == crate::arch::x86_64::idle::IdleWakeError::RescanRequired =>
                                    {
                                        // A rendezvous IRQ completed EOI before this
                                        // carrier reached `sti; hlt`. Consume its
                                        // latch and repeat the scheduler rescan; do
                                        // not sleep awaiting a second IPI.
                                        let preparation = failure.into_preparation();
                                        match crate::time::service_current_rendezvous_latch()
                                            .unwrap_or_else(|_| halt_forever())
                                        {
                                            crate::arch::x86_64::rendezvous::MailboxNotification::None
                                            | crate::arch::x86_64::rendezvous::MailboxNotification::Wake => {
                                                crate::arch::x86_64::idle::cancel_current_idle(
                                                    preparation,
                                                )
                                                .unwrap_or_else(|_| halt_forever());
                                                continue;
                                            }
                                            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
                                                crate::arch::x86_64::idle::cancel_current_idle(
                                                    preparation,
                                                )
                                                .unwrap_or_else(|_| halt_forever());
                                                stage_rendezvous_action(RendezvousAction(request))
                                                    .unwrap_or_else(|_| halt_forever());
                                                handoff_to_rendezvous_reaper(context);
                                            }
                                            crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {
                                                crate::arch::x86_64::idle::cancel_current_idle(
                                                    preparation,
                                                )
                                                .unwrap_or_else(|_| halt_forever());
                                                continue;
                                            }
                                        }
                                    }
                                    Err(_) => halt_forever(),
                                };
                                let idle_accounting = {
                                    let started_at_ns = crate::time::monotonic_now()
                                        .unwrap_or_else(|_| halt_forever());
                                    let runtime = unsafe { &mut *context.cast::<R>() };
                                    runtime
                                        .publish_scheduler_idle(started_at_ns)
                                        .unwrap_or_else(|_| halt_forever())
                                };
                                wait_for_suspend_interrupt();
                                // `hlt` returned with interrupts masked again.
                                // First complete the exact idle generation, then
                                // Acquire-consume its post-EOI latch before any
                                // scheduler poll or user-return work.
                                crate::arch::x86_64::idle::finish_current_idle(halt)
                                    .unwrap_or_else(|_| halt_forever());
                                let finished_at_ns =
                                    crate::time::monotonic_now().unwrap_or_else(|_| halt_forever());
                                {
                                    let runtime = unsafe { &mut *context.cast::<R>() };
                                    runtime
                                        .finish_scheduler_idle(idle_accounting, finished_at_ns)
                                        .unwrap_or_else(|_| halt_forever());
                                }
                                match crate::time::service_current_rendezvous_latch()
                                    .unwrap_or_else(|_| halt_forever())
                                {
                                crate::arch::x86_64::rendezvous::MailboxNotification::None
                                | crate::arch::x86_64::rendezvous::MailboxNotification::Wake => {}
                                crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
                                    stage_rendezvous_action(RendezvousAction(request))
                                        .unwrap_or_else(|_| halt_forever());
                                    handoff_to_rendezvous_reaper(context);
                                }
                                crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {}
                                }
                            }
                            crate::syscall::native::NativeIdleSuspendPoll::ResumeCurrent => {
                                crate::arch::x86_64::idle::cancel_current_idle(idle)
                                    .unwrap_or_else(|_| halt_forever());
                                break;
                            }
                            crate::syscall::native::NativeIdleSuspendPoll::Switch(plan) => {
                                crate::arch::x86_64::idle::cancel_current_idle(idle)
                                    .unwrap_or_else(|_| halt_forever());
                                switch_kernel_context(plan);
                                break;
                            }
                            #[cfg(deepwyrm_dw1c_evidence)]
                            crate::syscall::native::NativeIdleSuspendPoll::Detach {
                                plan, ..
                            } => {
                                crate::arch::x86_64::idle::cancel_current_idle(idle)
                                    .unwrap_or_else(|_| halt_forever());
                                switch_kernel_context(plan);
                                // The synthetic idle destination diverges, but
                                // this call returns later when the saved actor
                                // continuation is normally woken and resumed.
                                break;
                            }
                        }
                    }
                }
            }
            // `switch_kernel_context` returns on the destination CPU. The
            // outgoing stack frame still contains its source facade pointer;
            // reacquire the destination's one-shot published carrier before
            // any scheduler, terminal, mapping, or user-return operation.
            context = current_runtime_context::<R>().unwrap_or_else(|| halt_forever());
            let result = {
                let runtime = unsafe { &mut *context.cast::<R>() };
                match runtime.resume_suspended(frame) {
                    crate::syscall::native::NativeResumeOutcome::Resumed => {
                        let generation = current_binding_generation();
                        if let Err(error) = frame.rebind_after_kernel_resume(generation) {
                            invalid_bound_return::<R>(context, error);
                        }
                        runtime.authorize_return(frame, generation)
                    }
                    crate::syscall::native::NativeResumeOutcome::ServiceRendezvous => {
                        match crate::arch::x86_64::idle::take_current_notification_at_safe_point() {
                            crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => {
                                stage_rendezvous_action(RendezvousAction(request))
                                    .unwrap_or_else(|_| halt_forever());
                                handoff_to_rendezvous_reaper(context);
                            }
                            crate::arch::x86_64::rendezvous::MailboxNotification::None
                            | crate::arch::x86_64::rendezvous::MailboxNotification::Wake
                            | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {
                                halt_forever()
                            }
                        }
                    }
                    crate::syscall::native::NativeResumeOutcome::TerminateCurrent => {
                        stage_terminal_action(TerminalAction::CompleteCurrent)
                            .unwrap_or_else(|_| halt_forever());
                        handoff_to_terminal_reaper::<R>(context)
                    }
                }
            };
            if let Err(error) = result {
                invalid_bound_return::<R>(context, error);
            }
        }
        crate::syscall::native::SyscallControl::CompleteRemoteStop => halt_forever(),
        crate::syscall::native::SyscallControl::ServiceRendezvous => halt_forever(),
    }
    service_syscall_return_preemption::<R>(&mut context, frame);
}

#[allow(
    unsafe_code,
    reason = "the authorized raw syscall frame remains on its Thread-owned stack while an exact lifetime-branded preemption plan is consumed"
)]
fn service_syscall_return_preemption<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    context: &mut *mut (),
    frame: &mut RawSyscallFrame,
) {
    poll_timer_return_stop(*context);
    crate::time::service_current_scheduler_quantum_deadline().unwrap_or_else(|_| halt_forever());
    let has_request = {
        let runtime = unsafe { &mut *(*context).cast::<R>() };
        runtime.has_reschedule_request()
    };
    if has_request {
        let plan = {
            let runtime = unsafe { &mut *(*context).cast::<R>() };
            unsafe { runtime.prepare_preemption() }
        };
        if let crate::syscall::native::NativePreemptionPlan::Switch(plan) = plan {
            frame.revoke_authorized_return();
            switch_kernel_context(plan);
            *context = current_runtime_context::<R>().unwrap_or_else(|| halt_forever());
            let runtime = unsafe { &mut *(*context).cast::<R>() };
            if let Err(error) = runtime.resume_syscall_preemption(frame) {
                invalid_bound_return::<R>(*context, error);
            }
        }
    }
    poll_timer_return_stop(*context);
    arm_current_normal_quantum();
    poll_timer_return_stop(*context);
}

#[allow(
    unsafe_code,
    reason = "the lifetime-branded switch plan keeps execution-owner save storage stationary through immediate authenticated switch consumption"
)]
fn switch_kernel_context(plan: crate::arch::x86_64::context::KernelSwitchPlan<'_>) {
    #[cfg(deepwyrm_dw1c_evidence)]
    bind_current_switch_stack(plan.next_stack()).unwrap_or_else(|_| halt_forever());
    #[cfg(not(deepwyrm_dw1c_evidence))]
    unsafe { bind_current_thread_stack(plan.next_stack()) }.unwrap_or_else(|_| halt_forever());
    if !live_fp_simd_unavailable_is_enforced() {
        halt_forever();
    }
    unsafe { crate::arch::x86_64::context::execute_kernel_switch(plan) };
    if !live_fp_simd_unavailable_is_enforced() {
        halt_forever();
    }
}

#[allow(
    unsafe_code,
    reason = "STI immediately followed by HLT is the race-free x86 idle sequence; CLI restores the IF-clear syscall runtime before polling kernel state"
)]
fn wait_for_suspend_interrupt() {
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

/// Fixed trusted return target used by F7 synthetic first-run kernel frames.
/// The frame contains no erased runtime pointer; this symbol re-reads the
/// current CPU's one-shot immutable carrier binding and dispatches through its
/// monomorphized fresh-thread handler.
#[allow(
    unsafe_code,
    reason = "the one-shot runtime binding authenticates the erased context and fresh-thread function pointer before the divergent launch"
)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "sysv64" fn dw_x86_64_first_run_thread_entry() -> ! {
    validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
    if !crate::arch::x86_64::exceptions::user_exception_runtime_is_bound()
        || !live_fp_simd_unavailable_is_enforced()
    {
        halt_forever();
    }
    let Some(binding) = runtime_binding() else {
        halt_forever();
    };
    unsafe { (binding.fresh_thread_handler)(binding.context) }
}

/// Enters the bound cooperative scheduler from an AP's private bootstrap
/// stack. The AP carrier must already be released to `Executing`.
#[allow(
    unsafe_code,
    reason = "the immutable current-CPU binding pairs its carrier with the monomorphized divergent scheduler callback"
)]
pub(crate) fn enter_bound_idle_scheduler() -> ! {
    validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
    let binding = runtime_binding().unwrap_or_else(|| halt_forever());
    unsafe { (binding.idle_scheduler_handler)(binding.context) }
}

/// Fixed destination for a blocked-continuation detach.  The synthetic
/// context lands here on the CPU-private bootstrap stack before the bound
/// runtime releases scheduler ownership of the outgoing actor.
#[cfg(deepwyrm_dw1c_evidence)]
extern "sysv64" fn dw_x86_64_detached_idle_entry() -> ! {
    enter_bound_idle_scheduler()
}

#[cfg(deepwyrm_dw1c_evidence)]
pub(crate) fn detached_idle_entry_rip() -> u64 {
    dw_x86_64_detached_idle_entry as *const () as usize as u64
}

#[allow(
    dead_code,
    reason = "multi-thread F7/F12 runtimes use the first-run continuation; the single-thread G3 runtime does not"
)]
pub(crate) fn first_run_thread_entry_rip() -> u64 {
    dw_x86_64_first_run_thread_entry as *const () as usize as u64
}

#[allow(
    dead_code,
    unsafe_code,
    reason = "the private divergent entry retains the CPU-local pinned carrier owner for every dispatch through that slot's context/function pair"
)]
unsafe fn dispatch_bound_runtime(frame: &mut RawSyscallFrame) {
    let Some(binding) = runtime_binding() else {
        halt_forever();
    };
    unsafe { (binding.handler)(binding.context, frame) };
}

#[allow(
    dead_code,
    unsafe_code,
    reason = "F7 first-run entry checks the IF-clear BSP entry-state stack identity established by the context-switch boundary"
)]
fn current_kernel_stack_is(stack: KernelStackBounds) -> bool {
    current_entry_state().is_some_and(|state| state.current_kernel_stack_top == stack.top)
}

#[allow(
    dead_code,
    unsafe_code,
    reason = "F7 fresh-Thread launch reuses the already-installed exception/syscall runtimes and the stack binding established by the kernel context switch"
)]
pub(crate) unsafe fn enter_bound_validated_user(
    state: &ValidatedUserReturn,
    stack: KernelStackBounds,
) -> ! {
    validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
    if runtime_binding().is_none()
        || !crate::arch::x86_64::exceptions::user_exception_runtime_is_bound()
        || !current_kernel_stack_is(stack)
    {
        halt_forever();
    }
    unsafe { iret_validated_user(state) }
}

#[allow(
    unsafe_code,
    reason = "the caller has already validated user state and established the exact current kernel-stack/runtime ownership"
)]
unsafe fn iret_validated_user(state: &ValidatedUserReturn) -> ! {
    unsafe extern "sysv64" {
        fn dw_x86_64_iret_to_user(state: *const super::frame::RawUserReturnContext) -> !;
    }
    arm_current_normal_quantum();
    unsafe { dw_x86_64_iret_to_user(state.raw()) }
}

/// Publishes one stationary CPU-local execution carrier and enters CPL3 through
/// the validated IRETQ helper without returning its exclusive borrow to safe
/// Rust. A carrier address may be published for exactly one CPU slot.
///
/// # Safety
///
/// `stack` is the exact live E3 kernel-stack carrier of the selected Thread.
#[allow(
    unsafe_code,
    reason = "the divergent entry frame retains one CPU's pinned carrier borrow after unique per-CPU publication and transfers through audited IRETQ assembly"
)]
pub(crate) unsafe fn enter_native_syscall_runtime<
    'runtime,
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    runtime: Pin<&'runtime mut R>,
    state: &ValidatedUserReturn,
    stack: KernelStackBounds,
    exception_binding: &crate::arch::x86_64::exceptions::UserExceptionBinding,
) -> ! {
    let entry = NativeSyscallRuntimeEntry { runtime };
    unsafe { entry.enter(state, stack, exception_binding) }
}

impl<
    'runtime,
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
> NativeSyscallRuntimeEntry<'runtime, R>
{
    #[allow(
        unsafe_code,
        reason = "the private divergent entry owns one CPU's pinned carrier borrow for every path after unique per-CPU raw-pointer publication"
    )]
    unsafe fn enter(
        mut self,
        state: &ValidatedUserReturn,
        stack: KernelStackBounds,
        exception_binding: &crate::arch::x86_64::exceptions::UserExceptionBinding,
    ) -> ! {
        validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
        if !crate::arch::x86_64::exceptions::user_exception_binding_is_current(exception_binding) {
            halt_forever();
        }
        unsafe { bind_current_thread_stack(stack) }.unwrap_or_else(|_| halt_forever());
        // Reborrow the Pin so `self.runtime` remains owned by this nonreturning
        // frame after its address is erased into this CPU's immutable binding.
        let context = unsafe { Pin::get_unchecked_mut(self.runtime.as_mut()) as *mut R };
        let cpu_index = current_cpu_index_for_diagnostics().unwrap_or_else(|| halt_forever());
        if RUNTIME_STATE
            .get(cpu_index)
            .is_some_and(|slot| slot.load(Ordering::Acquire) == RUNTIME_UNBOUND)
        {
            unsafe {
                publish_syscall_runtime(
                    cpu_index,
                    context.cast::<()>(),
                    native_runtime_trampoline::<R>,
                    native_runtime_fresh_thread::<R>,
                    native_runtime_idle_scheduler::<R>,
                    native_runtime_user_exception::<R>,
                    native_runtime_rendezvous_gate::<R>,
                    native_runtime_rendezvous_reaper::<R>,
                    native_runtime_quantum_expiry::<R>,
                    native_runtime_prepare_quantum::<R>,
                    native_runtime_timer_pre_iret::<R>,
                )
            }
            .unwrap_or_else(|_| halt_forever());
            RUNTIME_CARRIER_LIFECYCLES
                .bind_parked(cpu_index)
                .unwrap_or_else(|_| halt_forever());
            let cpu = crate::cpu::CpuIndex::new(cpu_index).unwrap_or_else(|| halt_forever());
            release_native_runtime_carrier_for_slot(cpu).unwrap_or_else(|_| halt_forever());
        } else {
            let binding = RUNTIME
                .get(cpu_index)
                .filter(|_| {
                    RUNTIME_STATE[cpu_index].load(Ordering::Acquire) == RUNTIME_BOUND
                        && RUNTIME_CARRIER_LIFECYCLES.lifecycle(cpu_index)
                            == Some(RuntimeCarrierLifecycle::Executing)
                })
                .map(|storage| unsafe { (*storage.0.get()).assume_init() })
                .unwrap_or_else(|| halt_forever());
            if binding.context != context.cast::<()>()
                || binding.handler as usize != native_runtime_trampoline::<R> as *const () as usize
                || binding.idle_scheduler_handler as usize
                    != native_runtime_idle_scheduler::<R> as *const () as usize
            {
                halt_forever();
            }
        }
        unsafe { iret_validated_user(state) }
    }
}

#[allow(
    unsafe_code,
    reason = "fixed assembly symbol consumes only an assembly-built aligned raw syscall frame"
)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "sysv64" fn dw_x86_64_syscall_dispatch(frame: *mut RawSyscallFrame) {
    if frame.is_null() || (frame as usize) & 0xf != 0 {
        halt_forever();
    }
    let frame = unsafe { &mut *frame };
    if !frame.validates_entry()
        || frame.binding_generation() != current_binding_generation()
        || !live_fp_simd_unavailable_is_enforced()
    {
        halt_forever();
    }
    unsafe { dispatch_bound_runtime(frame) };
    if !live_fp_simd_unavailable_is_enforced() {
        halt_forever();
    }
    // A returning runtime handler must have authorized this exact frame after
    // current-Process mapping validation. Assembly fails stopped otherwise.
}

#[allow(
    unsafe_code,
    reason = "invalid E4 entry state is terminal with interrupts disabled"
)]
fn halt_forever() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
