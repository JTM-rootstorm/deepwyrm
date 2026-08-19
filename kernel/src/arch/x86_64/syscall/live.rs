//! Target-only one-CPU DW0-E4 SYSCALL installation and entry ownership.

use core::cell::UnsafeCell;
use core::convert::Infallible;
use core::marker::PhantomData;
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

const INSTALL_UNSTARTED: u8 = 0;
const INSTALLING: u8 = 1;
const INSTALLED: u8 = 2;
const RFLAGS_IF: u64 = 1 << 9;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_SYSCALL_SYSRET: u32 = 1 << 11;

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

static INSTALL_STATE: AtomicU8 = AtomicU8::new(INSTALL_UNSTARTED);
static ENTRY_STATE: EntryStateStorage = EntryStateStorage::new();
static EXPECTED_PLAN: PlanStorage = PlanStorage::uninit();

const RUNTIME_UNBOUND: u8 = 0;
const RUNTIME_BINDING: u8 = 1;
const RUNTIME_BOUND: u8 = 2;

pub(crate) type SyscallRuntimeHandler = unsafe fn(*mut (), &mut RawSyscallFrame);

#[derive(Clone, Copy)]
struct RuntimeBindingState {
    context: *mut (),
    handler: SyscallRuntimeHandler,
}

struct RuntimeStorage(UnsafeCell<MaybeUninit<RuntimeBindingState>>);

impl RuntimeStorage {
    const fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "the BSP publishes one immutable runtime pointer/function pair before any CPL3 entry and IF-clear syscall dispatch only reads it"
)]
unsafe impl Sync for RuntimeStorage {}

static RUNTIME_STATE: AtomicU8 = AtomicU8::new(RUNTIME_UNBOUND);
static RUNTIME: RuntimeStorage = RuntimeStorage::uninit();

#[must_use = "CPL3 entry requires the exact one-shot pinned syscall runtime binding"]
pub(crate) struct SyscallRuntimeBinding<'runtime> {
    context: usize,
    handler: usize,
    _runtime: PhantomData<&'runtime mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallRuntimeBindError {
    AlreadyBound,
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

fn entry_state_address() -> u64 {
    ENTRY_STATE.0.get() as u64
}

#[allow(
    unsafe_code,
    reason = "one-shot BSP initialization writes the supervisor-only GS entry record before publishing the swapgs MSR pair"
)]
unsafe fn initialize_entry_state(entry_stack_top: u64) {
    unsafe {
        ENTRY_STATE.0.get().write(PerCpuEntryState {
            entry_stack_top,
            ..PerCpuEntryState::empty()
        });
    }
}

#[allow(
    unsafe_code,
    reason = "installed-state Acquire publication makes the expected MSR plan immutable"
)]
unsafe fn expected_plan() -> SyscallMsrPlan {
    unsafe { (*EXPECTED_PLAN.0.get()).assume_init() }
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

/// Installs the one-CPU DW0-E4 SYSCALL boundary.
///
/// # Safety
///
/// Must run at CPL0 on the BSP with IF clear after the final GDT/TSS is active.
#[allow(
    unsafe_code,
    reason = "E4 programs CR4 and architectural MSRs and publishes the swapgs-protected GS entry-state base"
)]
pub(crate) unsafe fn install_syscall_boundary() -> Result<(), SyscallInstallError> {
    if INSTALL_STATE
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
        let descriptors = crate::arch::x86_64::early_descriptor_addresses()
            .ok_or(SyscallInstallError::DescriptorState)?;
        let privilege = crate::arch::x86_64::linked_privilege_entry_stack_layout()
            .map_err(|_| SyscallInstallError::DescriptorState)?;
        if descriptors.privilege_stack0 != privilege.top {
            return Err(SyscallInstallError::DescriptorState);
        }
        if !cpu_supports_syscall() {
            return Err(SyscallInstallError::UnsupportedCpu);
        }
        unsafe { enforce_live_fp_simd_unavailable()? };
        unsafe { normalize_live_cr4()? };
        unsafe { initialize_entry_state(privilege.top) };

        let mut access = LiveMsrAccess;
        let current_efer = match access.read(IA32_EFER) {
            Ok(value) => value,
            Err(never) => match never {},
        };
        let plan =
            SyscallMsrPlan::new(current_efer, syscall_entry_address(), entry_state_address())
                .map_err(SyscallInstallError::InvalidMsrPlan)?;
        program_and_verify(&mut access, plan).map_err(map_program_error)?;
        unsafe { (*EXPECTED_PLAN.0.get()).write(plan) };
        Ok(())
    })();

    match result {
        Ok(()) => {
            INSTALL_STATE.store(INSTALLED, Ordering::Release);
            Ok(())
        }
        Err(error) => {
            INSTALL_STATE.store(INSTALL_UNSTARTED, Ordering::Release);
            Err(error)
        }
    }
}

#[allow(
    unsafe_code,
    reason = "live E4 revalidation reads CR4 and the one-shot published expected MSR plan"
)]
pub(crate) fn validate_live_syscall_boundary() -> Result<(), SyscallInstallError> {
    if INSTALL_STATE.load(Ordering::Acquire) != INSTALLED {
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
    let plan = unsafe { expected_plan() };
    verify(&mut LiveMsrAccess, plan).map_err(map_program_error)
}

#[allow(
    unsafe_code,
    reason = "BSP scheduler linearization updates the assembly-consumed current stack and generation with IF clear"
)]
pub(crate) unsafe fn bind_current_thread_stack(
    stack: KernelStackBounds,
) -> Result<u64, EntryBindingError> {
    if INSTALL_STATE.load(Ordering::Acquire) != INSTALLED {
        return Err(EntryBindingError::BoundaryNotInstalled);
    }
    let linked = crate::arch::x86_64::linked_thread_kernel_stack_layout()
        .map_err(|_| EntryBindingError::ForeignKernelStack)?;
    if !linked.contains(&stack) {
        return Err(EntryBindingError::ForeignKernelStack);
    }
    let state = unsafe { &mut *ENTRY_STATE.0.get() };
    let next = state
        .binding_generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(EntryBindingError::GenerationExhausted)?;
    state.current_kernel_stack_top = stack.top;
    state.binding_generation = next;
    Ok(next)
}

#[allow(
    unsafe_code,
    reason = "SYSCALL dispatch reads one BSP binding generation while FMASK keeps IF clear"
)]
pub(crate) fn current_binding_generation() -> u64 {
    unsafe { (*ENTRY_STATE.0.get()).binding_generation }
}

/// Publishes the single BSP syscall runtime identity used by the assembly boundary.
///
/// # Safety
///
/// The caller must keep `context` stationary and exclusively borrowed for the
/// lifetime represented by the returned higher-level binding.
#[allow(
    unsafe_code,
    reason = "one-shot publication stores the pinned runtime address plus its monomorphized dispatcher"
)]
unsafe fn publish_syscall_runtime(
    context: *mut (),
    handler: SyscallRuntimeHandler,
) -> Result<(usize, usize), SyscallRuntimeBindError> {
    if context.is_null() {
        return Err(SyscallRuntimeBindError::NullContext);
    }
    if RUNTIME_STATE
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
    unsafe {
        (*RUNTIME.0.get()).write(RuntimeBindingState { context, handler });
    }
    RUNTIME_STATE.store(RUNTIME_BOUND, Ordering::Release);
    Ok((context as usize, handler as usize))
}

#[allow(
    unsafe_code,
    reason = "Acquire observes the immutable one-shot runtime binding published before CPL3 entry"
)]
fn runtime_binding() -> Option<RuntimeBindingState> {
    if RUNTIME_STATE.load(Ordering::Acquire) != RUNTIME_BOUND {
        return None;
    }
    Some(unsafe { (*RUNTIME.0.get()).assume_init() })
}

pub(crate) fn syscall_runtime_binding_is_current(binding: &SyscallRuntimeBinding<'_>) -> bool {
    runtime_binding().is_some_and(|current| {
        current.context as usize == binding.context && current.handler as usize == binding.handler
    })
}

#[allow(
    unsafe_code,
    reason = "the branded one-shot binding guarantees the erased runtime pointer remains pinned and exclusive for this short reborrow"
)]
fn invalid_bound_return<R: crate::syscall::native::NativeSyscallFrameRuntime>(
    context: *mut (),
    error: super::frame::UserReturnError,
) -> ! {
    // SAFETY: each borrow is short-lived on the one-BSP runtime. No borrow of
    // `R` survives a kernel-context switch.
    let runtime = unsafe { &mut *context.cast::<R>() };
    runtime.invalid_return(error)
}

#[allow(
    unsafe_code,
    reason = "the pinned one-BSP runtime is reborrowed only in bounded regions that do not span a kernel-context switch"
)]
unsafe fn native_runtime_trampoline<R: crate::syscall::native::NativeSyscallFrameRuntime>(
    context: *mut (),
    frame: &mut RawSyscallFrame,
) {
    let control = {
        let runtime = unsafe { &mut *context.cast::<R>() };
        crate::syscall::native::dispatch_frame(runtime, frame, current_binding_generation())
    };
    match control {
        crate::syscall::native::SyscallControl::ReturnToCaller => {}
        crate::syscall::native::SyscallControl::TerminateCurrent => {
            let runtime = unsafe { &mut *context.cast::<R>() };
            runtime.terminate_current()
        }
        crate::syscall::native::SyscallControl::SuspendCurrent => {
            let plan = {
                let runtime = unsafe { &mut *context.cast::<R>() };
                runtime.prepare_suspend(frame)
            };
            unsafe { bind_current_thread_stack(plan.next_stack()) }
                .unwrap_or_else(|_| halt_forever());
            if !live_fp_simd_unavailable_is_enforced() {
                halt_forever();
            }
            unsafe { crate::arch::x86_64::context::execute_kernel_switch(plan) };
            if !live_fp_simd_unavailable_is_enforced() {
                halt_forever();
            }
            let generation = current_binding_generation();
            if let Err(error) = frame.rebind_after_kernel_resume(generation) {
                invalid_bound_return::<R>(context, error);
            }
            let result = {
                let runtime = unsafe { &mut *context.cast::<R>() };
                runtime.resume_suspended(frame);
                runtime.authorize_return(frame, generation)
            };
            if let Err(error) = result {
                invalid_bound_return::<R>(context, error);
            }
        }
    }
}

/// Binds one stationary typed runtime to the raw x86 syscall entry.
///
/// The returned lifetime brands the global raw pointer with the caller's
/// exclusive pinned borrow. Safe Rust cannot access or move the runtime again
/// while the binding remains live. `enter_validated_user` consumes that binding
/// and never returns, so the target runtime stays pinned for all later syscalls.
#[allow(
    unsafe_code,
    reason = "Pin supplies the stable runtime address and the returned lifetime-branded binding retains the exclusive borrow for divergent CPL3 execution"
)]
pub(crate) fn bind_native_syscall_runtime<
    'runtime,
    R: crate::syscall::native::NativeSyscallFrameRuntime,
>(
    runtime: Pin<&'runtime mut R>,
) -> Result<SyscallRuntimeBinding<'runtime>, SyscallRuntimeBindError> {
    // SAFETY: Pin guarantees the pointee cannot move for `'runtime`; the
    // returned binding carries the exclusive borrow for the same lifetime.
    let context = unsafe { Pin::get_unchecked_mut(runtime) as *mut R };
    let (context_identity, handler_identity) =
        unsafe { publish_syscall_runtime(context.cast::<()>(), native_runtime_trampoline::<R>) }?;
    Ok(SyscallRuntimeBinding {
        context: context_identity,
        handler: handler_identity,
        _runtime: PhantomData,
    })
}

#[allow(
    unsafe_code,
    reason = "the one-shot pinned binding guarantees the stored context/function pair remains valid for syscall dispatch"
)]
unsafe fn dispatch_bound_runtime(frame: &mut RawSyscallFrame) {
    let Some(binding) = runtime_binding() else {
        halt_forever();
    };
    unsafe { (binding.handler)(binding.context, frame) };
}

/// Enters CPL3 through the separately validated IRETQ helper.
///
/// # Safety
///
/// `stack` is the exact live E3 kernel-stack carrier of the selected Thread.
#[allow(
    unsafe_code,
    reason = "final E4 user transition binds the current stack and transfers to audited IRETQ assembly"
)]
pub(crate) unsafe fn enter_validated_user(
    state: &ValidatedUserReturn,
    stack: KernelStackBounds,
    exception_binding: &crate::arch::x86_64::exceptions::UserExceptionBinding,
    syscall_binding: SyscallRuntimeBinding<'_>,
) -> ! {
    validate_live_syscall_boundary().unwrap_or_else(|_| halt_forever());
    if !crate::arch::x86_64::exceptions::user_exception_binding_is_current(exception_binding) {
        halt_forever();
    }
    if !syscall_runtime_binding_is_current(&syscall_binding) {
        halt_forever();
    }
    unsafe { bind_current_thread_stack(stack) }.unwrap_or_else(|_| halt_forever());
    unsafe extern "sysv64" {
        fn dw_x86_64_iret_to_user(state: *const super::frame::RawUserReturnContext) -> !;
    }
    unsafe { dw_x86_64_iret_to_user(state.raw()) }
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
