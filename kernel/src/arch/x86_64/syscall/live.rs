//! Target-only per-CPU DW0-H1 SYSCALL installation and entry ownership.

use core::cell::UnsafeCell;
use core::convert::Infallible;
use core::mem::MaybeUninit;
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

// Safety notes (S2K). Each SAFETY comment on an unsafe block below cites one of these shared
// justifications by its bracketed tag.
//
// [ASM] Inline assembly here runs only in kernel code, at CPL0. CR0/CR4 moves, RDMSR/WRMSR of the
// SYSCALL and GS-base MSRs, PUSHFQ/POP, and copying RSP neither read nor write memory Rust can
// observe, so `nomem` is accurate for them. The STI;HLT;CLI idle window is the exception and
// omits `nomem`; see `wait_for_suspend_interrupt`. The kernel target (`x86_64-unknown-none`,
// `red_zone = false` in `kernel/arch/x86_64/layout.toml`) has no red zone, so PUSHFQ, and any
// interrupt taken inside a STI window, only write below RSP.
//
// [PER-CPU-SLOT] `ENTRY_STATE`, `EXPECTED_PLAN`, `RUNTIME`, `TERMINAL_ACTION` and
// `RENDEZVOUS_ACTION` are per-CPU `UnsafeCell` slots. A CPU selects a slot by `current_cpu_index`,
// i.e. by the GS / KERNEL_GS_BASE value that `install_syscall_boundary_for_slot` programmed to that
// slot's own `ENTRY_STATE` address, so a CPU only ever selects its own slot. Each slot's atomic
// state word orders it: the writer claims the word, writes, then stores the published state with
// Release; a reader observes that state with Acquire before reading.
//
// [ENTRY-REF] `current_entry_state` returns `&'static` and `current_entry_state_mut` returns
// `&'static mut` to the same per-CPU record. Neither lifetime is real. Soundness rests on every
// caller using the reference transiently and never across the two Rust writers
// (`bind_current_thread_stack`, `bind_current_switch_stack`), which holds for every caller in this
// file today, and on the assembly writing the record's staged-user fields only when no kernel
// frame on this CPU will use either reference again: SYSCALL entry from CPL3, and
// `dw_x86_64_iret_to_user`, which stages the IRET words there on its divergent path to CPL3. The
// S2K design should narrow these lifetimes.
//
// [CARRIER] A published context is the address of one pinned, stationary carrier `R`.
// `publish_syscall_runtime` writes it once per CPU slot, together with handlers monomorphized for
// that same `R`, so every cast back to `R` is to the right type, and `RUNTIME_CARRIER_CLAIMS`
// rejects publishing one address for two slots. Only the owning CPU dereferences it (via
// `runtime_binding`). Each `&mut *context` reborrow is scoped to one block that ends before any
// kernel-context switch, stack pivot or divergent handoff, and after a switch the context is
// re-read from the destination CPU's binding. The `bind_*` and `enter_native_syscall_runtime`
// callers owe the stationarity and no-other-reference contract.
//
// [CARRIER] model gap, UNVERIFIED (S2K). (1) Divergent carrier methods taking `&mut self`
// (`terminate_current`, `enter_idle_scheduler`, `rendezvous_stop`, or a detached caller reaching
// `handoff_current_rendezvous_from_carrier`) abandon frames that still hold a protected `&mut R`,
// and the carrier is later reborrowed through the published pointer. No abandoned frame resumes,
// but Stacked and Tree Borrows do not treat the protector as ended.
//
// [QUANTUM-EXPIRY] (closes the former gap (2), S2K-6) Quantum expiry is published from the timer
// interrupt and from synchronous quantum cancellation, both of which can run while a `&mut self`
// method of this CPU's carrier is suspended and will resume (the idle STI window; draining a
// cancellation). Its context is therefore not the carrier: each CPU publishes a separate
// `NativeQuantumExpiry` object with its binding (`quantum_expiry_context`), and only
// `native_runtime_quantum_expiry` reborrows it. No carrier frame holds a reference to it, and
// publication does not re-enter quantum expiry, so its reborrow never overlaps another.
//
// [GUARD-FREE] Crate-visible physical boundaries here (`enter_bound_validated_user`,
// `enter_bound_idle_scheduler`, `handoff_current_rendezvous_from_carrier`), and
// `context::abandon_to_kernel_continuation`, take a `GuardFree` token, so a carrier cannot reach
// them while it holds its runtime-authority guard. The private boundaries (`switch_kernel_context`,
// `handoff_to_rendezvous_reaper`, `handoff_to_terminal_reaper`) are guard-free by construction:
// only this file's trampolines call them, this file cannot name `RuntimeAuthorityGuard`
// (`pub(super)` in `mm::activation`), and no runtime trait method can return one.
//
// [FRAME] `dw_x86_64_syscall_dispatch` and `dw_x86_64_timer_pre_iret_gate` receive frame pointers
// from assembly (`syscall_entry.S`, `exceptions.S`). Rust checks them for null and alignment. That
// each points to one complete frame, owned by this entry and living on the current Thread's bound
// kernel stack, is the assembly's contract.

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
    /// Opens the window. Only after the entry's safe-point poll found no
    /// remote Stop: an adapter must never copy for a Thread already stopped.
    fn enter_current(_safe_point: super::SafePointClear) -> Result<Self, ()> {
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
type PrepareQuantumHandler = unsafe fn(*mut ()) -> Option<crate::task::SchedulerQuantumTicket>;
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
    /// This CPU's quantum-expiry publisher: a separate object from `context`
    /// (`NativeQuantumExpiry`), reached only by `quantum_expiry_handler`.
    quantum_expiry_context: *mut (),
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

/// The carrier a CPU enters with, held as the raw pointer every later access
/// uses (F1): no `&mut R` is retagged over it after publication.
struct NativeSyscallRuntimeEntry<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
> {
    runtime: core::ptr::NonNull<R>,
    /// The quantum-expiry publisher to bind when this entry publishes the
    /// runtime itself (the guest runtimes); `None` when its caller already
    /// published both (the primordial runtime).
    quantum_expiry: Option<core::ptr::NonNull<R::QuantumExpiry>>,
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
    /// The installing context was not ring 0.
    ///
    /// Distinct from `InterruptsEnabled`: that one is an atomicity failure,
    /// this one is an authority failure, and they were reported as the same
    /// value until the check was split.
    UnprivilegedContext,
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
        // SAFETY: [ASM] `LiveMsrAccess` is used only by `install_syscall_boundary_for_slot` and
        // `validate_live_syscall_boundary`, at CPL0 on a CPU with SYSCALL support, for the
        // architectural MSRs `SyscallMsrPlan` names.
        Ok(unsafe { read_msr(msr) })
    }

    fn write(&mut self, msr: u32, value: u64) -> Result<(), Self::Error> {
        // SAFETY: [ASM] only `program_and_verify` writes, inside
        // `install_syscall_boundary_for_slot` after CPL0 and IF-clear were checked; values come
        // from a `SyscallMsrPlan` whose addresses `SyscallMsrPlan::new` checked non-zero and
        // canonical.
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
    // SAFETY: [ASM] RDMSR of an MSR the caller guarantees exists (only the SYSCALL/GS-base set is
    // used); results come back in registers.
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
    // SAFETY: [ASM] WRMSR of an MSR and value the caller guarantees valid (see
    // `LiveMsrAccess::write`); no memory or stack access.
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
    // SAFETY: [ASM] side-effect-free CR0 read; the only caller has already checked CPL0.
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) before,
            options(nomem, nostack, preserves_flags)
        );
    }
    let expected = normalize_cr0_for_e5(before);
    if before != expected {
        // SAFETY: [ASM] sets only CR0.TS (`normalize_cr0_for_e5`). The kernel target is soft-float
        // (`-mno-sse` for C), so no kernel code executes an FP/SIMD instruction that TS would trap.
        unsafe {
            core::arch::asm!(
                "mov cr0, {}",
                in(reg) expected,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    let observed: u64;
    // SAFETY: [ASM] side-effect-free CR0 read, as above.
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
    // SAFETY: [ASM] side-effect-free CR0 read; every caller is kernel code at CPL0.
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
    // SAFETY: [ASM] side-effect-free CR4 read; the only caller has already checked CPL0.
    unsafe {
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) before,
            options(nomem, nostack, preserves_flags)
        );
    }
    let expected = normalize_cr4_for_e4(before);
    if before != expected {
        // SAFETY: [ASM] clears only CR4.FSGSBASE (`normalize_cr4_for_e4`); no kernel code uses
        // RD/WR{FS,GS}BASE, so disabling them breaks nothing Rust relies on.
        unsafe {
            core::arch::asm!(
                "mov cr4, {}",
                in(reg) expected,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    let observed: u64;
    // SAFETY: [ASM] side-effect-free CR4 read, as above.
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

/// Checks the two independent preconditions the installation context owes, and
/// reports which one failed.
///
/// They are separate obligations and are now reported separately. Ring 0 is an
/// *authority* precondition: only kernel context may install the syscall
/// boundary at all. IF-clear is an *atomicity* precondition: the CR4 and MSR
/// programming sequence that follows must not be interrupted partway. Nothing
/// about either implies the other.
///
/// This was one `bool`, and its only caller turned any failure into
/// `InterruptsEnabled`. A ring-3 caller therefore reported the one thing that
/// was not wrong, which is the cause erasure
/// `Plans/DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` exists to stop -- and it sat
/// on `install_syscall_boundary_for_slot`, where the authority half is the
/// security-relevant one. A single name over two invariants also means a later
/// edit to one half can drop the other without the name reading any
/// differently.
#[allow(
    unsafe_code,
    reason = "RFLAGS/CS observation verifies the privileged IF-clear installation context"
)]
unsafe fn verify_installation_cpu_state() -> Result<(), SyscallInstallError> {
    let rflags: u64;
    let cs: u16;
    // SAFETY: [ASM] PUSHFQ/POP writes only below RSP (no `nostack`, no red zone) and reading CS is
    // unprivileged; no Rust-visible memory is touched.
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
    if cs & 3 != 0 {
        return Err(SyscallInstallError::UnprivilegedContext);
    }
    if rflags & RFLAGS_IF != 0 {
        return Err(SyscallInstallError::InterruptsEnabled);
    }
    Ok(())
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
    // SAFETY: [PER-CPU-SLOT] the caller won this slot's UNSTARTED->INSTALLING exchange, so it is
    // the only writer, and it runs on this CPU with IF clear, so no entry through GS can read the
    // record mid-write. No reference to the record exists.
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
    // SAFETY: [PER-CPU-SLOT] callers first observe INSTALLED with Acquire;
    // `install_syscall_boundary_for_slot` stores it with Release only after writing this plan,
    // which is never rewritten. The plan is `Copy`.
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
    // SAFETY: [ASM] IA32_GS_BASE exists on every x86-64 CPU and reading it has no side effects.
    let gs_base = unsafe { read_msr(super::msr::IA32_GS_BASE) };
    cpu_index_for_entry_state_address(gs_base).or_else(|| {
        // SAFETY: [ASM] IA32_KERNEL_GS_BASE exists on every x86-64 CPU and reading it has no side
        // effects.
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
    // SAFETY: [ASM] PUSHFQ/POP writes only below RSP (no `nostack`, no red zone); no Rust-visible
    // memory is touched.
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
    // SAFETY: [ASM] copies RSP into a register; no memory or flags change.
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
    // SAFETY: [PER-CPU-SLOT] this CPU's own record, written before its GS base was programmed. See
    // [ENTRY-REF] for why the `'static` reference is only sound while callers keep it transient.
    Some(unsafe { &*state.0.get() })
}

#[allow(
    unsafe_code,
    reason = "the current CPU exclusively updates its GS-selected entry record while IF remains clear"
)]
unsafe fn current_entry_state_mut() -> Option<(usize, &'static mut PerCpuEntryState)> {
    let cpu_index = current_cpu_index()?;
    let state = ENTRY_STATE.get(cpu_index)?;
    // SAFETY: [PER-CPU-SLOT] this CPU's own record. See [ENTRY-REF]: both callers write two fields
    // and return, and no `current_entry_state` reference is live across them.
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
        // SAFETY: [ASM] the callee only observes RFLAGS and CS, which kernel code may always do.
        unsafe { verify_installation_cpu_state() }?;
        if crate::arch::x86_64::runtime_cpu_descriptor_lifecycle(cpu_index)
            != Some(crate::arch::x86_64::RuntimeCpuDescriptorLifecycle::DescriptorsActive)
        {
            return Err(SyscallInstallError::DescriptorState);
        }
        if !cpu_supports_syscall() {
            return Err(SyscallInstallError::UnsupportedCpu);
        }
        // SAFETY: CPL0 and IF clear were just checked, which is what the callee's CR0 write needs.
        unsafe { enforce_live_fp_simd_unavailable()? };
        // SAFETY: CPL0 and IF clear were just checked, which is what the callee's CR4 write needs.
        unsafe { normalize_live_cr4()? };
        // SAFETY: this call won the slot's UNSTARTED->INSTALLING exchange above, so it is the
        // record's only writer; see `initialize_entry_state`.
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
        // SAFETY: [PER-CPU-SLOT] the INSTALLING claim makes this the slot's only writer;
        // `expected_plan` readers wait for the INSTALLED Release store below.
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
    // SAFETY: forwarded from this function's `# Safety` (BSP, IF clear, slot 0 descriptors active
    // after `migrate_bsp_to_runtime_slot0_after_deep_paging`), which is what the callee requires.
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
    // SAFETY: [ASM] side-effect-free CR4 read; the slot is installed, so this is kernel code at
    // CPL0.
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
    // SAFETY: INSTALL_STATE for this slot was just observed INSTALLED with Acquire, which is what
    // `expected_plan` requires.
    let plan = unsafe { expected_plan(cpu_index) }.ok_or(SyscallInstallError::DescriptorState)?;
    verify(&mut LiveMsrAccess, plan).map_err(map_program_error)
}

#[allow(
    unsafe_code,
    reason = "the current CPU's scheduler linearization updates only its GS-selected assembly entry record with IF clear"
)]
pub(crate) unsafe fn bind_current_thread_stack(
    stack: KernelStackBounds,
) -> Result<super::BoundKernelStack, EntryBindingError> {
    let (cpu_index, state) =
        // SAFETY: [ENTRY-REF] the reference is used only inside this function and callers hold no
        // `current_entry_state` reference across the call; entry assembly writes the record only on
        // SYSCALL from CPL3.
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
    // SAFETY: the two stores above made `stack` this CPU's current kernel stack.
    Ok(unsafe { super::BoundKernelStack::assume(stack) })
}

/// Binds a context-switch destination that is either an owned Thread stack or
/// this exact CPU's private bootstrap/idle carrier.  The latter is admitted
/// only for the selector-private blocked-continuation detach path.
#[cfg(deepwyrm_dw1c_evidence)]
#[allow(
    unsafe_code,
    reason = "the current CPU exclusively updates its GS-selected entry record while IF remains clear"
)]
fn bind_current_switch_stack(
    stack: KernelStackBounds,
) -> Result<super::BoundKernelStack, EntryBindingError> {
    let (cpu_index, state) =
        // SAFETY: [ENTRY-REF] the reference is used only inside this function; the callers
        // (`switch_kernel_context`) run with IF clear and hold no other reference to the record.
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
    // SAFETY: the two stores above made `stack` this CPU's current kernel stack.
    Ok(unsafe { super::BoundKernelStack::assume(stack) })
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
/// `runtime` points to a live `R` that stays stationary for the full kernel
/// lifetime. From this call on, every access to it uses this pointer's
/// provenance (the pointer or one derived from it), and no reference derived
/// from it outlives one scoped use, so the published address is never
/// invalidated by a later retag (F1). The caller must prove that `cpu_index`
/// cannot execute userspace or otherwise reach the carrier callbacks during
/// publication. Binding only publishes a `Parked` lifecycle state; a later
/// explicit release is required before dispatch can observe the binding.
#[allow(
    unsafe_code,
    reason = "one-shot AP carrier binding erases a unique pinned static address only after the CPU-private boundary is installed"
)]
pub(crate) unsafe fn bind_native_runtime_carrier_for_slot<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    cpu_index: crate::cpu::CpuIndex,
    runtime: core::ptr::NonNull<R>,
    quantum_expiry: core::ptr::NonNull<R::QuantumExpiry>,
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
    // The caller's pointer itself is published: no reference is created here.
    let context = runtime.as_ptr();
    // SAFETY: [CARRIER] this function's `# Safety` supplies the callee's: a stationary carrier
    // owned by `cpu_index` and reached only through this pointer's provenance, with every handler
    // monomorphized for the same `R`.
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
            quantum_expiry.as_ptr().cast::<()>(),
            native_runtime_quantum_expiry::<R::QuantumExpiry>,
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
///
/// # Safety
///
/// As `bind_native_runtime_carrier_for_slot`.
#[allow(
    unsafe_code,
    reason = "CPU0 uses the same stationary one-shot carrier publication as APs but has an already-running scheduler claim"
)]
pub(crate) unsafe fn bind_running_native_runtime_carrier_for_slot<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    cpu: crate::cpu::CpuIndex,
    runtime: core::ptr::NonNull<R>,
    quantum_expiry: core::ptr::NonNull<R::QuantumExpiry>,
) -> Result<(), SyscallRuntimeBindError> {
    if cpu != crate::cpu::CpuIndex::BOOTSTRAP {
        return Err(SyscallRuntimeBindError::InvalidCpu);
    }
    // SAFETY: forwarded: this function's `# Safety` is `bind_native_runtime_carrier_for_slot`'s.
    unsafe { bind_native_runtime_carrier_for_slot(cpu, runtime, quantum_expiry) }?;
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
    quantum_expiry_context: *mut (),
    quantum_expiry_handler: QuantumExpiryHandler,
    prepare_quantum_handler: PrepareQuantumHandler,
    timer_pre_iret_handler: TimerPreIretHandler,
) -> Result<(), SyscallRuntimeBindError> {
    if quantum_expiry_context.is_null() {
        return Err(SyscallRuntimeBindError::NullContext);
    }
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
    // SAFETY: [PER-CPU-SLOT] the UNBOUND->BINDING exchange above makes this the slot's only writer,
    // and readers wait for the BOUND Release store below. BOUND is never undone, so the slot is
    // never rewritten.
    unsafe {
        (*storage.0.get()).write(RuntimeBindingState {
            context,
            handler,
            fresh_thread_handler,
            idle_scheduler_handler,
            user_exception_handler,
            rendezvous_gate_handler,
            rendezvous_reaper_handler,
            quantum_expiry_context,
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
    // SAFETY: [PER-CPU-SLOT] BOUND was loaded with Acquire, so `publish_syscall_runtime`'s one
    // write is visible and never changes; `RuntimeBindingState` is `Copy`.
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
    // SAFETY: [PER-CPU-SLOT] the EMPTY->WRITING exchange gives exclusive write access to this CPU's
    // slot; the READY Release store below publishes it.
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
    // SAFETY: [PER-CPU-SLOT] READY->READING (Acquire) pairs with `stage_rendezvous_action`'s READY
    // Release store, so the `Copy` payload is initialized; it is read once before the slot returns
    // to EMPTY.
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

/// The syscall entry's first safe point: the only place a `SafePointClear`
/// is minted, and so the only way to open the native usercopy window.
#[allow(
    unsafe_code,
    reason = "the proof is minted only from a mailbox observation that was not a Stop"
)]
fn poll_entry_safe_point()
-> Result<super::SafePointClear, crate::arch::x86_64::rendezvous::StopRequest> {
    match crate::arch::x86_64::idle::take_current_notification_at_safe_point() {
        crate::arch::x86_64::rendezvous::MailboxNotification::None
        | crate::arch::x86_64::rendezvous::MailboxNotification::Wake
        | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe(_) => {
            // SAFETY: the authoritative mailbox was just polled and held no Stop.
            Ok(unsafe { super::SafePointClear::assume() })
        }
        crate::arch::x86_64::rendezvous::MailboxNotification::Stop(request) => Err(request),
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
    // SAFETY: [CARRIER] `context` is this CPU's binding (`dw_x86_64_rendezvous_reaper`) and the
    // pivot abandoned the interrupted frame. A detached caller's abandoned `&mut self` is gap (1)
    // in [CARRIER].
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
    // SAFETY: the assembly (`syscall_entry.S`) clears IF, moves to this CPU's reaper stack and
    // never returns; every caller staged the rendezvous action first, and the reaper halts if none
    // is staged.
    unsafe {
        dw_x86_64_rendezvous_reaper_handoff()
    }
}

/// Pivots a detached carrier entry onto the dedicated rendezvous reaper after
/// scheduler synchronization observes an exact remote Stop. Detached entries
/// have no syscall/timer frame to return through, so they must consume the
/// same stationary mailbox authority directly and abandon their carrier stack.
///
/// Takes a `GuardFree` token: a carrier must drop its runtime-authority guard
/// before it abandons its stack for the reaper.
pub(crate) fn handoff_current_rendezvous_from_carrier(_guard_free: super::GuardFree<'_>) -> ! {
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
    // SAFETY: [CARRIER] `runtime_binding` returned this CPU's immutable binding; the handler is
    // `native_runtime_rendezvous_gate::<R>` for the `R` behind `context`.
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
    // SAFETY: [CARRIER] `runtime_binding` returned this CPU's immutable binding; the handler is
    // `native_runtime_rendezvous_reaper::<R>` for the `R` behind `context`.
    unsafe { (binding.rendezvous_reaper_handler)(binding.context) }
}

#[allow(
    unsafe_code,
    reason = "the interrupt dispatcher invokes only the immutable CPU-local carrier callback with an exact scheduler ticket"
)]
unsafe fn native_runtime_quantum_expiry<P: crate::syscall::native::NativeQuantumExpiry>(
    context: *mut (),
    ticket: crate::task::SchedulerQuantumTicket,
) -> bool {
    // SAFETY: [QUANTUM-EXPIRY] `context` is this CPU's publisher, bound with this handler
    // monomorphized for its `P`; no carrier frame holds a reference to it, and this is its only,
    // non-reentrant, reborrow.
    let publisher = unsafe { &mut *context.cast::<P>() };
    publisher
        .publish_quantum_expiry(ticket)
        .unwrap_or_else(|_| halt_forever())
}

#[allow(
    unsafe_code,
    reason = "the guard-free quantum-arm seam briefly reborrows the current CPU's unique carrier"
)]
unsafe fn native_runtime_prepare_quantum<R: crate::syscall::native::NativeSyscallFrameRuntime>(
    context: *mut (),
) -> Option<crate::task::SchedulerQuantumTicket> {
    // SAFETY: [CARRIER] reached only from `arm_current_normal_quantum`, whose callers hold no
    // reborrow of the carrier at that point; the reborrow ends with this function.
    let runtime = unsafe { &mut *context.cast::<R>() };
    runtime
        .prepare_quantum(|| crate::time::monotonic_now().unwrap_or_else(|_| halt_forever()))
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
    // SAFETY: this CPU's immutable binding pairs its quantum-expiry publisher with the matching
    // `native_runtime_quantum_expiry::<P>`, whose contract that publisher meets.
    Ok(unsafe { (binding.quantum_expiry_handler)(binding.quantum_expiry_context, ticket) })
}

/// Begins a fresh exact quantum only after all runtime/scheduler guards have
/// been released. The time service performs LAPIC MMIO through its own
/// guard-free prepare/program/revalidate sequence. A synchronous expiry is
/// returned to the caller; it must be consumed before returning to CPL3.
#[allow(
    unsafe_code,
    reason = "the immutable CPU-local binding briefly reborrows its unique carrier to mint one exact scheduler ticket"
)]
fn arm_current_normal_quantum() -> bool {
    let binding = runtime_binding().unwrap_or_else(|| halt_forever());
    // SAFETY: [CARRIER] this CPU's immutable binding; the handler is
    // `native_runtime_prepare_quantum::<R>`, and no carrier reborrow is live in the callers at this
    // point.
    if let Some(ticket) = unsafe { (binding.prepare_quantum_handler)(binding.context) } {
        return crate::time::arm_scheduler_quantum(ticket).unwrap_or_else(|_| halt_forever());
    }
    false
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
    loop {
        poll_timer_return_stop(context);
        validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
        {
            // SAFETY: [CARRIER] scoped reborrow of this CPU's carrier; the IRQ-origin gate has no
            // other Rust frame on this CPU that holds one.
            let runtime = unsafe { &mut *context.cast::<R>() };
            if let Err(error) = runtime.authorize_timer_return(frame) {
                invalid_bound_return::<R>(context, error);
            }
        }
        let has_request = {
            // SAFETY: [CARRIER] scoped reborrow of this CPU's carrier; the previous one has ended.
            let runtime = unsafe { &mut *context.cast::<R>() };
            runtime.has_reschedule_request()
        };
        if has_request {
            let plan = {
                // SAFETY: [CARRIER] scoped reborrow of this CPU's carrier; the previous one has
                // ended.
                let runtime = unsafe { &mut *context.cast::<R>() };
                // SAFETY: this is the timer safe-boundary gate on the current Thread's bound kernel
                // stack, which is the trait method's `# Safety`; the plan is consumed immediately
                // below.
                unsafe { runtime.prepare_preemption() }
            };
            match plan {
                crate::syscall::native::NativePreemptionPlan::Return => {}
                crate::syscall::native::NativePreemptionPlan::Switch(plan) => {
                    switch_kernel_context(plan);
                    context = current_runtime_context::<R>().unwrap_or_else(|| halt_forever());
                    // SAFETY: [CARRIER] `context` was just re-read from the destination CPU's
                    // binding after the switch.
                    let runtime = unsafe { &mut *context.cast::<R>() };
                    if let Err(error) = runtime.resume_timer_preemption(frame) {
                        invalid_bound_return::<R>(context, error);
                    }
                }
            }
        }
        poll_timer_return_stop(context);
        let expired_during_arm = arm_current_normal_quantum();
        poll_timer_return_stop(context);
        if !expired_during_arm {
            break;
        }
    }
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
    // SAFETY: [CARRIER] this CPU's immutable binding and its matching handler. [FRAME] the frame
    // was checked non-null and aligned above.
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
    // SAFETY: [PER-CPU-SLOT] the EMPTY->WRITING exchange gives exclusive write access to this CPU's
    // slot; the READY Release store below publishes it.
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
    // SAFETY: [PER-CPU-SLOT] READY->READING (Acquire) pairs with `stage_terminal_action`'s READY
    // Release store, so the `Copy` payload is initialized; it is read once before the slot returns
    // to EMPTY.
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
    // SAFETY: [CARRIER] this CPU's immutable binding; the handler is
    // `native_runtime_user_exception::<R>` for the `R` behind `context`. The CPL3 fault left no
    // Rust frame holding the carrier.
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
    // SAFETY: [CARRIER] reached only through `dw_x86_64_first_run_thread_entry` on a fresh Thread's
    // stack, so no other frame on this CPU holds a reborrow.
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
    // SAFETY: [CARRIER] reached only through `enter_bound_idle_scheduler`. Callers that are
    // themselves `&mut self` carrier methods abandon that frame; see gap (1) in [CARRIER].
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
    // SAFETY: [CARRIER] `context` is this CPU's binding, passed through the reaper handoff, which
    // abandoned the deferred Thread stack and every reborrow on it.
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
    // SAFETY: the reaper stack top was checked non-zero above; the assembly (`syscall_entry.S`)
    // clears IF, switches to it and calls the callback, which matches `R`. Callers staged the
    // action first.
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
    let safe_point = match poll_entry_safe_point() {
        Ok(clear) => clear,
        Err(request) => {
            stage_rendezvous_action(RendezvousAction(request)).unwrap_or_else(|_| halt_forever());
            handoff_to_rendezvous_reaper(context);
        }
    };
    let usercopy_window =
        NativeUsercopyWindow::enter_current(safe_point).unwrap_or_else(|_| halt_forever());
    let control = {
        // SAFETY: [CARRIER] first scoped reborrow in this trampoline; the SYSCALL entry left no
        // other Rust frame on this CPU holding one.
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
        // SAFETY: [CARRIER] scoped reborrow; the previous one has ended.
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
                // SAFETY: [CARRIER] scoped reborrow; the previous one has ended.
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
                            // SAFETY: [CARRIER] scoped reborrow inside the idle loop; no other
                            // reborrow is live.
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
                                    // SAFETY: [CARRIER] scoped reborrow; no other reborrow is live.
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
                                    // SAFETY: [CARRIER] scoped reborrow; no other reborrow is live.
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
                // SAFETY: [CARRIER] `context` was just re-read from the destination CPU's binding
                // after the switch.
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
    loop {
        poll_timer_return_stop(*context);
        crate::time::service_current_scheduler_quantum_deadline()
            .unwrap_or_else(|_| halt_forever());
        let has_request = {
            // SAFETY: [CARRIER] scoped reborrow; the trampoline holds no other one.
            let runtime = unsafe { &mut *(*context).cast::<R>() };
            runtime.has_reschedule_request()
        };
        if has_request {
            let plan = {
                // SAFETY: [CARRIER] scoped reborrow; the previous one has ended.
                let runtime = unsafe { &mut *(*context).cast::<R>() };
                // SAFETY: this is the syscall safe-boundary trampoline on the current Thread's
                // bound kernel stack, which is the trait method's `# Safety`; the plan is consumed
                // immediately below.
                unsafe { runtime.prepare_preemption() }
            };
            if let crate::syscall::native::NativePreemptionPlan::Switch(plan) = plan {
                frame.revoke_authorized_return();
                switch_kernel_context(plan);
                *context = current_runtime_context::<R>().unwrap_or_else(|| halt_forever());
                // SAFETY: [CARRIER] `*context` was just re-read from the destination CPU's binding
                // after the switch.
                let runtime = unsafe { &mut *(*context).cast::<R>() };
                if let Err(error) = runtime.resume_syscall_preemption(frame) {
                    invalid_bound_return::<R>(*context, error);
                }
            }
        }
        poll_timer_return_stop(*context);
        let expired_during_arm = arm_current_normal_quantum();
        poll_timer_return_stop(*context);
        if !expired_during_arm {
            break;
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the lifetime-branded switch plan keeps execution-owner save storage stationary through immediate authenticated switch consumption"
)]
fn switch_kernel_context(plan: crate::arch::x86_64::context::KernelSwitchPlan<'_>) {
    #[cfg(deepwyrm_dw1c_evidence)]
    bind_current_switch_stack(plan.next_stack()).unwrap_or_else(|_| halt_forever());
    #[cfg(not(deepwyrm_dw1c_evidence))]
    // SAFETY: [ENTRY-REF] callers (syscall trampoline, timer gate) run with IF clear and hold no
    // record reference; the stack bound is the one `execute_kernel_switch` below switches to.
    unsafe { bind_current_thread_stack(plan.next_stack()) }.unwrap_or_else(|_| halt_forever());
    if !live_fp_simd_unavailable_is_enforced() {
        halt_forever();
    }
    // SAFETY: the plan came from a runtime `prepare_*` method whose `# Safety` the caller met, and
    // is consumed immediately; the assembly also rejects a save frame outside `current_stack` with
    // `ud2`.
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
    // Handlers taken inside the STI window write memory the caller reads after it (wake latches,
    // mailboxes, timer state), so this block deliberately omits `nomem`: the compiler must treat
    // it as reading and writing memory, and may neither cache such a load across the halt nor sink
    // an earlier store below it. Linux's `safe_halt` carries a "memory" clobber for the same reason.
    // SAFETY: [ASM] CPL0 with IF clear (the syscall runtime's state), so STI's one-instruction
    // shadow makes STI;HLT race-free and CLI restores IF clear before kernel state is read.
    // `nostack` holds: the block pushes nothing, and a handler taken in the window writes only
    // below RSP.
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nostack)) };
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
    // SAFETY: [CARRIER] this CPU's immutable binding and its matching
    // `native_runtime_fresh_thread::<R>`, checked after the boundary and exception runtime were
    // validated above.
    unsafe { (binding.fresh_thread_handler)(binding.context) }
}

/// Enters the bound cooperative scheduler, abandoning the caller's frame. The
/// caller proves it holds no runtime-authority guard: a carrier with its
/// handle's token, and the two execution roots (AP bring-up and the detached
/// idle entry) with the token they mint at their root frame.
#[allow(
    unsafe_code,
    reason = "the immutable current-CPU binding pairs its carrier with the monomorphized divergent scheduler callback"
)]
pub(crate) fn enter_bound_idle_scheduler(_guard_free: super::GuardFree<'_>) -> ! {
    validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
    let binding = runtime_binding().unwrap_or_else(|| halt_forever());
    // SAFETY: [CARRIER] this CPU's immutable binding and its matching
    // `native_runtime_idle_scheduler::<R>`.
    unsafe { (binding.idle_scheduler_handler)(binding.context) }
}

/// Fixed destination for a blocked-continuation detach.  The synthetic
/// context lands here on the CPU-private bootstrap stack before the bound
/// runtime releases scheduler ownership of the outgoing actor.
#[cfg(deepwyrm_dw1c_evidence)]
#[allow(
    unsafe_code,
    reason = "the root frame of a fresh execution mints the only guard-free proof it can have"
)]
extern "sysv64" fn dw_x86_64_detached_idle_entry() -> ! {
    // SAFETY: this is the root Rust frame of a fresh execution: the detach's synthetic context
    // switches here on the CPU-private bootstrap stack, abandoning the frame that held the carrier.
    // No frame below this one exists, so no runtime-authority guard can be held.
    enter_bound_idle_scheduler(unsafe { super::GuardFree::assume() })
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
    // SAFETY: [CARRIER] this CPU's immutable binding and its matching trampoline; [FRAME] `frame`
    // is the caller's validated raw frame.
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

/// The proof for a binding a kernel context switch made: the first-run path
/// starts on the stack `switch_kernel_context` bound before the switch, in a
/// frame the proof could not cross. Halts if this CPU does not bind `stack`,
/// exactly as `enter_bound_validated_user` always has.
#[allow(
    unsafe_code,
    reason = "the token is minted only after the entry record was checked to bind the stack"
)]
pub(crate) fn current_bound_kernel_stack(stack: KernelStackBounds) -> super::BoundKernelStack {
    if !current_kernel_stack_is(stack) {
        halt_forever();
    }
    // SAFETY: the check above found this CPU's entry record binding `stack`.
    unsafe { super::BoundKernelStack::assume(stack) }
}

#[allow(
    dead_code,
    unsafe_code,
    reason = "F7 fresh-Thread launch reuses the already-installed exception/syscall runtimes and the stack binding established by the kernel context switch"
)]
pub(crate) unsafe fn enter_bound_validated_user(
    state: &ValidatedUserReturn,
    stack: super::BoundKernelStack,
    _guard_free: super::GuardFree<'_>,
) -> ! {
    validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
    // The token proves a binding happened; the check proves it is still the current one.
    if runtime_binding().is_none()
        || !crate::arch::x86_64::exceptions::user_exception_runtime_is_bound()
        || !current_kernel_stack_is(stack.stack())
    {
        halt_forever();
    }
    // SAFETY: the boundary, the runtime binding, the exception runtime and the stack binding were
    // all checked above; `state` is a `ValidatedUserReturn`, which `iret_validated_user` reads in
    // full before it writes the bound stack.
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
    // The assembly helper reads the whole context, then pivots from the bootstrap/idle/reaper
    // carrier (or, on the first-run path, from lower on the same stack) to the bound Thread stack
    // top and runs the ordinary pre-IRET gate there.
    // SAFETY: `state` is a `ValidatedUserReturn`, and the caller established the stack binding and
    // runtime ownership. The helper finishes every read of `*state` before its pivot and its first
    // stack write, so the frames it builds cannot clobber the context wherever it lives.
    unsafe { dw_x86_64_iret_to_user(state.raw()) }
}

/// Publishes one stationary CPU-local execution carrier and enters CPL3 through
/// the validated IRETQ helper without returning its exclusive borrow to safe
/// Rust. A carrier address may be published for exactly one CPU slot.
///
/// # Safety
///
/// `stack` is the exact live E3 kernel-stack carrier of the selected Thread.
// Only the E7, F9 and F12 guest runtimes pin a stack carrier and enter with it;
// the primordial runtime enters through `enter_published_native_syscall_runtime`.
#[cfg(any(deepwyrm_e7_guest, deepwyrm_f9_guest, deepwyrm_f12_guest))]
#[allow(
    unsafe_code,
    reason = "the divergent entry frame retains one CPU's pinned carrier borrow after unique per-CPU publication and transfers through audited IRETQ assembly"
)]
pub(crate) unsafe fn enter_native_syscall_runtime<
    'runtime,
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    runtime: core::pin::Pin<&'runtime mut R>,
    state: &ValidatedUserReturn,
    stack: KernelStackBounds,
    exception_binding: &crate::arch::x86_64::exceptions::UserExceptionBinding,
) -> ! {
    // SAFETY: the pointer is taken once from the pin, which is consumed here and never used again,
    // so every later access goes through it; nothing moves `R`.
    let runtime = core::ptr::NonNull::from(unsafe { core::pin::Pin::get_unchecked_mut(runtime) });
    // The guest runtimes arm no quantum: their publisher is zero-sized, so a dangling, aligned
    // pointer is a valid one, and no storage is needed.
    const {
        assert!(
            size_of::<R::QuantumExpiry>() == 0,
            "a guest runtime's quantum-expiry publisher must be zero-sized"
        );
    }
    let entry = NativeSyscallRuntimeEntry {
        runtime,
        quantum_expiry: Some(core::ptr::NonNull::dangling()),
    };
    // SAFETY: forwarded from this function's `# Safety`; `enter` performs the remaining binding
    // checks itself.
    unsafe { entry.enter(state, stack, exception_binding) }
}

/// Enters CPL3 on a carrier its caller already published with
/// `bind_running_native_runtime_carrier_for_slot`, through the same pointer,
/// so no reference is retagged over the published address (F1).
///
/// # Safety
///
/// `stack` is the exact live E3 kernel-stack carrier of the selected Thread,
/// and `runtime` is the pointer this CPU's carrier was published with, under
/// `bind_native_runtime_carrier_for_slot`'s `# Safety`.
#[allow(
    unsafe_code,
    reason = "the divergent entry keeps the published carrier pointer and transfers through audited IRETQ assembly"
)]
pub(crate) unsafe fn enter_published_native_syscall_runtime<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
>(
    runtime: core::ptr::NonNull<R>,
    state: &ValidatedUserReturn,
    stack: KernelStackBounds,
    exception_binding: &crate::arch::x86_64::exceptions::UserExceptionBinding,
) -> ! {
    let entry = NativeSyscallRuntimeEntry {
        runtime,
        quantum_expiry: None,
    };
    // SAFETY: forwarded from this function's `# Safety`; `enter` checks the pointer against the
    // published binding and halts on a mismatch.
    unsafe { entry.enter(state, stack, exception_binding) }
}

impl<
    R: crate::syscall::native::NativeSyscallFrameRuntime
        + crate::syscall::native::NativeRendezvousRuntime,
> NativeSyscallRuntimeEntry<R>
{
    #[allow(
        unsafe_code,
        reason = "the private divergent entry owns one CPU's pinned carrier borrow for every path after unique per-CPU raw-pointer publication"
    )]
    unsafe fn enter(
        self,
        state: &ValidatedUserReturn,
        stack: KernelStackBounds,
        exception_binding: &crate::arch::x86_64::exceptions::UserExceptionBinding,
    ) -> ! {
        validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
        if !crate::arch::x86_64::exceptions::user_exception_binding_is_current(exception_binding) {
            halt_forever();
        }
        // SAFETY: [ENTRY-REF] no record reference is live here; `stack` is the selected Thread's
        // live stack per this function's caller contract.
        unsafe { bind_current_thread_stack(stack) }.unwrap_or_else(|_| halt_forever());
        // The entry's pointer is the one published (or compared with the published binding): no
        // reference is created over the carrier here.
        let context = self.runtime.as_ptr();
        let cpu_index = current_cpu_index_for_diagnostics().unwrap_or_else(|| halt_forever());
        if RUNTIME_STATE
            .get(cpu_index)
            .is_some_and(|slot| slot.load(Ordering::Acquire) == RUNTIME_UNBOUND)
        {
            // SAFETY: [CARRIER] the entry's caller keeps the carrier stationary for the kernel's life
            // (a pin consumed by a never-returning frame, or a pointer published under
            // `bind_native_runtime_carrier_for_slot`'s contract), and every later use goes through
            // this pointer; it is owned by this CPU's slot.
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
                    self.quantum_expiry
                        .unwrap_or_else(|| halt_forever())
                        .as_ptr()
                        .cast::<()>(),
                    native_runtime_quantum_expiry::<R::QuantumExpiry>,
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
                // SAFETY: [PER-CPU-SLOT] the filter observed BOUND with Acquire, so the one-shot
                // binding is initialized and immutable; it is `Copy`.
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
        // SAFETY: the boundary was validated, `stack` was bound above per the caller's contract,
        // and `state` is a `ValidatedUserReturn`; the primordial caller keeps it on the boot stack,
        // off the bound stack.
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
    // SAFETY: [FRAME] checked non-null and 16-byte aligned above; the entry assembly passes its own
    // frame and keeps no other reference to it.
    let frame = unsafe { &mut *frame };
    if !frame.validates_entry()
        || frame.binding_generation() != current_binding_generation()
        || !live_fp_simd_unavailable_is_enforced()
    {
        halt_forever();
    }
    // SAFETY: the frame's entry signature and binding generation were validated above;
    // `dispatch_bound_runtime` halts if this CPU has no binding.
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
        // SAFETY: [ASM] CLI then HLT, with nothing after it; neither touches memory or the stack.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
