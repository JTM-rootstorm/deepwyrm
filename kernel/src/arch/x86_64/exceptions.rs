//! Structured x86_64 exception-entry state.
//!
//! Kernel-origin and explicitly terminal architecture paths remain fail-stop.
//! DW0-E4 additionally normalizes CPL3 old-stack state and hands ordinary user
//! exceptions to a mandatory process-fatal task-runtime binding.

use deepwyrm_abi::{
    DW_EXCEPTION_BREAKPOINT, DW_EXCEPTION_DEBUG_TRAP, DW_EXCEPTION_DIVIDE_ERROR,
    DW_EXCEPTION_GENERAL_PROTECTION, DW_EXCEPTION_ILLEGAL_INSTRUCTION, DW_EXCEPTION_NONE,
    DW_EXCEPTION_PAGE_FAULT, DwExceptionType,
};

use crate::arch::x86_64::gdt::{KERNEL_CODE_SELECTOR, USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::interrupt::{VectorClass, classify_vector};

/// Number of architecturally allocated exception gates in the shared vector
/// policy. The corresponding handlers are indexed by their vector number.
pub const EXCEPTION_HANDLER_COUNT: usize = 32;

/// An x86_64 exception vector approved by the shared interrupt policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionVector {
    DivideError,
    Debug,
    NonMaskableInterrupt,
    Breakpoint,
    Overflow,
    BoundRangeExceeded,
    InvalidOpcode,
    DeviceNotAvailable,
    DoubleFault,
    CoprocessorSegmentOverrun,
    InvalidTss,
    SegmentNotPresent,
    StackSegmentFault,
    GeneralProtection,
    PageFault,
    Reserved(u8),
    X87FloatingPoint,
    AlignmentCheck,
    MachineCheck,
    SimdFloatingPoint,
    Virtualization,
    ControlProtection,
    HypervisorInjection,
    VmmCommunication,
    Security,
}

impl ExceptionVector {
    /// Converts a shared-policy exception vector into its architectural kind.
    pub const fn from_vector(vector: u8) -> Result<Self, ExceptionVectorError> {
        if !matches!(classify_vector(vector), VectorClass::Exception) {
            return Err(ExceptionVectorError::OutsideExceptionRange(vector));
        }

        Ok(match vector {
            0 => Self::DivideError,
            1 => Self::Debug,
            2 => Self::NonMaskableInterrupt,
            3 => Self::Breakpoint,
            4 => Self::Overflow,
            5 => Self::BoundRangeExceeded,
            6 => Self::InvalidOpcode,
            7 => Self::DeviceNotAvailable,
            8 => Self::DoubleFault,
            9 => Self::CoprocessorSegmentOverrun,
            10 => Self::InvalidTss,
            11 => Self::SegmentNotPresent,
            12 => Self::StackSegmentFault,
            13 => Self::GeneralProtection,
            14 => Self::PageFault,
            15 | 22..=27 | 31 => Self::Reserved(vector),
            16 => Self::X87FloatingPoint,
            17 => Self::AlignmentCheck,
            18 => Self::MachineCheck,
            19 => Self::SimdFloatingPoint,
            20 => Self::Virtualization,
            21 => Self::ControlProtection,
            28 => Self::HypervisorInjection,
            29 => Self::VmmCommunication,
            30 => Self::Security,
            _ => unreachable!(),
        })
    }

    /// Returns the vector number used to index a descriptor-table entry.
    #[must_use]
    pub const fn vector(self) -> u8 {
        match self {
            Self::DivideError => 0,
            Self::Debug => 1,
            Self::NonMaskableInterrupt => 2,
            Self::Breakpoint => 3,
            Self::Overflow => 4,
            Self::BoundRangeExceeded => 5,
            Self::InvalidOpcode => 6,
            Self::DeviceNotAvailable => 7,
            Self::DoubleFault => 8,
            Self::CoprocessorSegmentOverrun => 9,
            Self::InvalidTss => 10,
            Self::SegmentNotPresent => 11,
            Self::StackSegmentFault => 12,
            Self::GeneralProtection => 13,
            Self::PageFault => 14,
            Self::Reserved(vector) => vector,
            Self::X87FloatingPoint => 16,
            Self::AlignmentCheck => 17,
            Self::MachineCheck => 18,
            Self::SimdFloatingPoint => 19,
            Self::Virtualization => 20,
            Self::ControlProtection => 21,
            Self::HypervisorInjection => 28,
            Self::VmmCommunication => 29,
            Self::Security => 30,
        }
    }

    /// Indicates whether hardware pushes an error-code word for this vector.
    #[must_use]
    pub const fn pushes_error_code(self) -> bool {
        matches!(
            self,
            Self::DoubleFault
                | Self::InvalidTss
                | Self::SegmentNotPresent
                | Self::StackSegmentFault
                | Self::GeneralProtection
                | Self::PageFault
                | Self::AlignmentCheck
                | Self::ControlProtection
                | Self::VmmCommunication
                | Self::Security
        )
    }

    /// Maps exception kinds represented by the native ABI.
    ///
    /// This is classification only. DW0-B does not yet expose exception
    /// objects or delivery to userspace.
    #[must_use]
    pub const fn native_exception_type(self) -> Option<DwExceptionType> {
        match self {
            Self::PageFault => Some(DW_EXCEPTION_PAGE_FAULT),
            Self::InvalidOpcode => Some(DW_EXCEPTION_ILLEGAL_INSTRUCTION),
            Self::Breakpoint => Some(DW_EXCEPTION_BREAKPOINT),
            Self::DivideError => Some(DW_EXCEPTION_DIVIDE_ERROR),
            Self::GeneralProtection => Some(DW_EXCEPTION_GENERAL_PROTECTION),
            Self::Debug => Some(DW_EXCEPTION_DEBUG_TRAP),
            _ => None,
        }
    }

    /// Architecture paths that remain kernel-terminal even if interrupted CPL3.
    #[must_use]
    pub const fn is_always_terminal(self) -> bool {
        matches!(
            self,
            Self::NonMaskableInterrupt | Self::DoubleFault | Self::MachineCheck
        )
    }
}

/// Rejection of a vector not owned by the exception portion of the IDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionVectorError {
    OutsideExceptionRange(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExceptionOrigin {
    Kernel,
    User,
}

/// Architectural frame normalized by exception-entry assembly.
///
/// E4 assembly copies the optional old-stack pair into fixed fields. Kernel
/// origins expose `None`; CPL3 origins expose the exact hardware old RSP/SS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExceptionFrame {
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub rflags: u64,
    pub stack_pointer: Option<u64>,
    pub stack_segment: Option<u64>,
}

/// Structured early exception context handed to diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyException {
    pub vector: ExceptionVector,
    pub error_code: Option<u64>,
    pub frame: ExceptionFrame,
    /// The CR2 snapshot for a page fault, absent for all other exceptions.
    pub fault_address: Option<u64>,
}

impl EarlyException {
    /// Validates the normalized entry data against x86_64's error-code rules.
    pub const fn new(
        vector: ExceptionVector,
        error_code: Option<u64>,
        frame: ExceptionFrame,
        fault_address: Option<u64>,
    ) -> Result<Self, ExceptionFrameError> {
        if vector.pushes_error_code() != error_code.is_some() {
            return Err(ExceptionFrameError::UnexpectedErrorCode {
                vector,
                provided: error_code.is_some(),
            });
        }
        if matches!(vector, ExceptionVector::PageFault) != fault_address.is_some() {
            return Err(ExceptionFrameError::UnexpectedFaultAddress {
                vector,
                provided: fault_address.is_some(),
            });
        }
        if stack_pair_is_incomplete(frame) {
            return Err(ExceptionFrameError::IncompleteStackFrame);
        }
        Ok(Self {
            vector,
            error_code,
            frame,
            fault_address,
        })
    }

    /// Returns the decoded page-fault error word when this is a page fault.
    #[must_use]
    pub const fn page_fault_error(self) -> Option<PageFaultErrorCode> {
        match (self.vector, self.error_code) {
            (ExceptionVector::PageFault, Some(error)) => Some(PageFaultErrorCode(error)),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(any(test, target_os = "none")),
    allow(
        dead_code,
        reason = "E4 user exception state is host-tested before target/runtime consumption"
    )
)]
pub(crate) struct UserExceptionRecord {
    pub(crate) exception_type: DwExceptionType,
    pub(crate) vector: u32,
    pub(crate) detail: u32,
    pub(crate) reserved: u32,
    pub(crate) fault_address: u64,
    pub(crate) instruction_pointer: u64,
    pub(crate) stack_pointer: u64,
}

impl UserExceptionRecord {
    #[allow(
        dead_code,
        reason = "E4 exposes the architecture-neutral task handoff before the primordial runtime binds its handler"
    )]
    pub(crate) const fn task_exception(self) -> crate::task::TaskExceptionRecord {
        crate::task::TaskExceptionRecord::new(self.exception_type, self.detail, self.fault_address)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(any(test, target_os = "none")),
    allow(
        dead_code,
        reason = "E4 user exception state is host-tested before target/runtime consumption"
    )
)]
pub(crate) enum ExceptionDisposition {
    KernelTerminal(EarlyException),
    UserFatal(UserExceptionRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(any(test, target_os = "none")),
    allow(
        dead_code,
        reason = "E4 user exception state is host-tested before target/runtime consumption"
    )
)]
pub(crate) enum ExceptionDispositionError {
    RawFrame,
    Vector,
    NormalizedFrame,
}

#[cfg_attr(
    not(any(test, target_os = "none")),
    allow(
        dead_code,
        reason = "E4 user exception state is host-tested before target/runtime consumption"
    )
)]
pub(crate) fn classify_raw_exception(
    raw: RawExceptionContext,
) -> Result<ExceptionDisposition, ExceptionDispositionError> {
    if !raw.validates_architecture() {
        return Err(ExceptionDispositionError::RawFrame);
    }
    let vector_number = u8::try_from(raw.vector).map_err(|_| ExceptionDispositionError::Vector)?;
    let vector = ExceptionVector::from_vector(vector_number)
        .map_err(|_| ExceptionDispositionError::Vector)?;
    if raw.origin() == Some(ExceptionOrigin::User) && !vector.is_always_terminal() {
        let detail = if vector.pushes_error_code() {
            raw.raw_error_code as u32
        } else {
            u32::from(vector_number)
        };
        return Ok(ExceptionDisposition::UserFatal(UserExceptionRecord {
            exception_type: vector.native_exception_type().unwrap_or(DW_EXCEPTION_NONE),
            vector: u32::from(vector_number),
            detail,
            reserved: 0,
            fault_address: if matches!(vector, ExceptionVector::PageFault) {
                raw.cr2
            } else {
                0
            },
            instruction_pointer: raw.instruction_pointer,
            stack_pointer: raw.stack_pointer,
        }));
    }
    let frame = raw.frame().ok_or(ExceptionDispositionError::RawFrame)?;
    let error_code = vector.pushes_error_code().then_some(raw.raw_error_code);
    let fault_address = matches!(vector, ExceptionVector::PageFault).then_some(raw.cr2);
    let exception = EarlyException::new(vector, error_code, frame, fault_address)
        .map_err(|_| ExceptionDispositionError::NormalizedFrame)?;
    Ok(ExceptionDisposition::KernelTerminal(exception))
}

const fn stack_pair_is_incomplete(frame: ExceptionFrame) -> bool {
    frame.stack_pointer.is_some() != frame.stack_segment.is_some()
}

/// Rejection of malformed assembly-normalized exception state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionFrameError {
    UnexpectedErrorCode {
        vector: ExceptionVector,
        provided: bool,
    },
    UnexpectedFaultAddress {
        vector: ExceptionVector,
        provided: bool,
    },
    IncompleteStackFrame,
}

/// Decoded architectural page-fault error-code bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PageFaultErrorCode(u64);

impl PageFaultErrorCode {
    #[must_use]
    pub const fn was_present(self) -> bool {
        self.0 & (1 << 0) != 0
    }

    #[must_use]
    pub const fn was_write(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    #[must_use]
    pub const fn was_user_access(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    #[must_use]
    pub const fn reserved_bit_violation(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    #[must_use]
    pub const fn instruction_fetch(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    #[must_use]
    pub const fn protection_key(self) -> bool {
        self.0 & (1 << 5) != 0
    }

    #[must_use]
    pub const fn shadow_stack(self) -> bool {
        self.0 & (1 << 6) != 0
    }

    #[must_use]
    pub const fn sgx(self) -> bool {
        self.0 & (1 << 15) != 0
    }
}

/// The only early exception policy: report a complete record, then do not
/// resume the faulting execution context.
pub trait EarlyExceptionReporter {
    fn report_and_halt(&mut self, exception: EarlyException) -> !;
}

/// Reports an early exception through a policy supplied by the kernel entry
/// path. This remains distinct from later process exception delivery.
pub fn report_early_exception<R: EarlyExceptionReporter>(
    reporter: &mut R,
    exception: EarlyException,
) -> ! {
    reporter.report_and_halt(exception)
}

/// Register and processor-frame state normalized by `exceptions.S` before any
/// Rust call. This is an architecture-private, byte-defined assembly contract,
/// not a native ABI or a serializable record.
///
/// The terminal handlers never return, so assembly does not restore this
/// snapshot. Capturing it before Rust preserves evidence for bounded early
/// diagnostics and keeps later exception-policy work from depending on
/// clobbered calling-convention registers.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
pub(crate) struct RawExceptionContext {
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    cr2: u64,
    stack_pointer: u64,
    stack_segment: u64,
    rax: u64,
    vector: u64,
    raw_error_code: u64,
    instruction_pointer: u64,
    code_segment: u64,
    rflags: u64,
}

#[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
impl RawExceptionContext {
    fn origin(&self) -> Option<ExceptionOrigin> {
        if self.code_segment == u64::from(KERNEL_CODE_SELECTOR.bits()) {
            Some(ExceptionOrigin::Kernel)
        } else if self.code_segment == u64::from(USER_CODE_SELECTOR.bits()) {
            Some(ExceptionOrigin::User)
        } else {
            None
        }
    }

    fn validates_architecture(&self) -> bool {
        if self.vector > u64::from(u8::MAX)
            || !is_canonical_4_level(self.instruction_pointer)
            || self.rflags & (1 << 1) == 0
        {
            return false;
        }
        match self.origin() {
            Some(ExceptionOrigin::Kernel) => self.stack_pointer == 0 && self.stack_segment == 0,
            Some(ExceptionOrigin::User) => {
                self.stack_segment == u64::from(USER_DATA_SELECTOR.bits())
                    && is_lower_canonical_user(self.instruction_pointer)
            }
            None => false,
        }
    }

    fn frame(&self) -> Option<ExceptionFrame> {
        match self.origin()? {
            ExceptionOrigin::Kernel => Some(ExceptionFrame {
                instruction_pointer: self.instruction_pointer,
                code_segment: self.code_segment,
                rflags: self.rflags,
                stack_pointer: None,
                stack_segment: None,
            }),
            ExceptionOrigin::User => Some(ExceptionFrame {
                instruction_pointer: self.instruction_pointer,
                code_segment: self.code_segment,
                rflags: self.rflags,
                stack_pointer: Some(self.stack_pointer),
                stack_segment: Some(self.stack_segment),
            }),
        }
    }
}

#[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
const fn is_lower_canonical_user(address: u64) -> bool {
    address != 0 && address < 0x0000_8000_0000_0000
}

#[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
const fn is_canonical_4_level(address: u64) -> bool {
    let high = address >> 48;
    high == 0 || high == 0xffff
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct SerialEarlyExceptionReporter;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl EarlyExceptionReporter for SerialEarlyExceptionReporter {
    fn report_and_halt(&mut self, exception: EarlyException) -> ! {
        let _ = crate::debug::emit_early_panic_record(&crate::debug::PanicRecord {
            reason: exception_reason(exception.vector),
            cpu_id: None,
            instruction_pointer: Some(exception.frame.instruction_pointer),
            fault_address: exception.fault_address,
            backtrace_frames: &[],
        });
        #[cfg(feature = "test-support")]
        crate::test_support::complete_exception(exception);
        #[cfg(not(feature = "test-support"))]
        halt_forever()
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const fn exception_reason(vector: ExceptionVector) -> &'static str {
    match vector {
        ExceptionVector::DivideError => "x86 divide error",
        ExceptionVector::Debug => "x86 debug exception",
        ExceptionVector::NonMaskableInterrupt => "x86 non-maskable interrupt",
        ExceptionVector::Breakpoint => "x86 breakpoint",
        ExceptionVector::Overflow => "x86 overflow",
        ExceptionVector::BoundRangeExceeded => "x86 bound range exceeded",
        ExceptionVector::InvalidOpcode => "x86 invalid opcode",
        ExceptionVector::DeviceNotAvailable => "x86 device not available",
        ExceptionVector::DoubleFault => "x86 double fault",
        ExceptionVector::CoprocessorSegmentOverrun => "x86 coprocessor segment overrun",
        ExceptionVector::InvalidTss => "x86 invalid TSS",
        ExceptionVector::SegmentNotPresent => "x86 segment not present",
        ExceptionVector::StackSegmentFault => "x86 stack segment fault",
        ExceptionVector::GeneralProtection => "x86 general protection fault",
        ExceptionVector::PageFault => "x86 page fault",
        ExceptionVector::Reserved(_) => "x86 reserved exception vector",
        ExceptionVector::X87FloatingPoint => "x86 x87 floating point exception",
        ExceptionVector::AlignmentCheck => "x86 alignment check",
        ExceptionVector::MachineCheck => "x86 machine check",
        ExceptionVector::SimdFloatingPoint => "x86 SIMD floating point exception",
        ExceptionVector::Virtualization => "x86 virtualization exception",
        ExceptionVector::ControlProtection => "x86 control-protection exception",
        ExceptionVector::HypervisorInjection => "x86 hypervisor injection exception",
        ExceptionVector::VmmCommunication => "x86 VMM communication exception",
        ExceptionVector::Security => "x86 security exception",
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) type UserExceptionHandler = fn(UserExceptionRecord) -> !;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[must_use = "CPL3 entry requires a live E4 user-exception runtime binding"]
pub(crate) struct UserExceptionBinding {
    handler_address: usize,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserExceptionBindError {
    AlreadyBound,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static USER_EXCEPTION_HANDLER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn bind_user_exception_handler(
    handler: UserExceptionHandler,
) -> Result<UserExceptionBinding, UserExceptionBindError> {
    let address = handler as usize;
    USER_EXCEPTION_HANDLER
        .compare_exchange(
            0,
            address,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .map_err(|_| UserExceptionBindError::AlreadyBound)?;
    Ok(UserExceptionBinding {
        handler_address: address,
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn user_exception_binding_is_current(binding: &UserExceptionBinding) -> bool {
    binding.handler_address != 0
        && USER_EXCEPTION_HANDLER.load(core::sync::atomic::Ordering::Acquire)
            == binding.handler_address
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the one-shot atomic stores only a validated Rust function pointer supplied by bind_user_exception_handler"
)]
fn dispatch_bound_user_exception(record: UserExceptionRecord) -> ! {
    let address = USER_EXCEPTION_HANDLER.load(core::sync::atomic::Ordering::Acquire);
    if address == 0 {
        halt_forever();
    }
    assert_eq!(
        core::mem::size_of::<UserExceptionHandler>(),
        core::mem::size_of::<usize>(),
        "E4 user exception handler pointer width changed"
    );
    // SAFETY: the atomic is written only from an actual UserExceptionHandler
    // function pointer and never mutated after a successful bind.
    let handler: UserExceptionHandler = unsafe { core::mem::transmute(address) };
    handler(record)
}

/// Origin-aware exception dispatch target called by the audited E4 common
/// entry. Kernel-origin and architecturally terminal vectors preserve the
/// fail-stop reporter. Ordinary CPL3 exceptions become one structured record
/// handed to the bound task runtime and never resume the faulting context.
///
/// # Safety
///
/// Callers must supply a live, eight-byte-aligned `RawExceptionContext` built
/// exactly by the x86 exception assembly boundary.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "fixed symbol and raw frame read form the audited x86 exception assembly boundary"
)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "sysv64" fn dw_x86_64_exception_dispatch(
    raw_context: *const RawExceptionContext,
) -> ! {
    if raw_context.is_null() || (raw_context as usize) & 7 != 0 {
        halt_forever();
    }

    // SAFETY: exceptions.S constructs the exact fixed-width snapshot before
    // this call. The entry has IF clear and this function never resumes it.
    let raw_context = unsafe { raw_context.read() };
    match classify_raw_exception(raw_context) {
        Ok(ExceptionDisposition::KernelTerminal(exception)) => {
            report_early_exception(&mut SerialEarlyExceptionReporter, exception)
        }
        Ok(ExceptionDisposition::UserFatal(record)) => dispatch_bound_user_exception(record),
        Err(_) => halt_forever(),
    }
}

/// Terminal handler for the APIC error and spurious vectors. These vectors do
/// not use the exception frame convention and are never mistaken for native
/// process exceptions.
///
/// # Safety
///
/// Callers must supply a live, eight-byte-aligned `RawExceptionContext` built
/// exactly by the terminal APIC assembly boundary.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "fixed symbol required by the audited terminal interrupt assembly boundary"
)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "sysv64" fn dw_x86_64_terminal_interrupt_dispatch(
    raw_context: *const RawExceptionContext,
) -> ! {
    if raw_context.is_null() || (raw_context as usize) & 7 != 0 {
        halt_forever();
    }
    // SAFETY: the terminal APIC common stub uses the exact same normalized
    // context layout as the exception stubs before making this SysV call.
    let raw_context = unsafe { raw_context.read() };
    if !raw_context.validates_architecture() {
        halt_forever();
    }
    let reason = if raw_context.vector == u64::from(crate::interrupt::LOCAL_APIC_ERROR_VECTOR) {
        "local APIC error interrupt"
    } else if raw_context.vector == u64::from(crate::interrupt::LOCAL_APIC_SPURIOUS_VECTOR) {
        "local APIC spurious interrupt"
    } else {
        "unexpected terminal interrupt vector"
    };
    let _ = crate::debug::emit_early_panic_record(&crate::debug::PanicRecord {
        reason,
        cpu_id: None,
        instruction_pointer: None,
        fault_address: None,
        backtrace_frames: &[],
    });
    #[cfg(feature = "test-support")]
    crate::test_support::complete_panic(raw_context.vector as u32);
    #[cfg(not(feature = "test-support"))]
    halt_forever()
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "terminal x86 exception handling must stop the CPU with interrupts disabled"
)]
fn halt_forever() -> ! {
    loop {
        // SAFETY: terminal exception dispatch cannot return safely; disabling
        // maskable interrupts and halting avoids recursive execution.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

#[cfg(test)]
mod tests;
