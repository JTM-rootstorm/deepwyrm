//! Structured x86_64 early-exception state.
//!
//! This module describes data delivered by the exception-entry assembly
//! boundary. It deliberately does not prescribe recovery, scheduling, or
//! userspace exception delivery: before those facilities exist, an exception
//! reporter must fail stopped after recording the context.

use deepwyrm_abi::{
    DW_EXCEPTION_BREAKPOINT, DW_EXCEPTION_DEBUG_TRAP, DW_EXCEPTION_DIVIDE_ERROR,
    DW_EXCEPTION_GENERAL_PROTECTION, DW_EXCEPTION_ILLEGAL_INSTRUCTION, DW_EXCEPTION_PAGE_FAULT,
    DwExceptionType,
};

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
}

/// Rejection of a vector not owned by the exception portion of the IDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionVectorError {
    OutsideExceptionRange(u8),
}

/// Architectural frame normalized by exception-entry assembly.
///
/// DW0-B's terminal stubs deliberately do not consume optional old-stack
/// words: the emergency IDT has no IST while the final IDT does. Those tails
/// remain deferred until a distinct, table-specific frame contract exists.
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
    rax: u64,
    vector: u64,
    raw_error_code: u64,
    instruction_pointer: u64,
    code_segment: u64,
    rflags: u64,
}

#[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
impl RawExceptionContext {
    fn validates_architecture(&self) -> bool {
        self.vector <= u64::from(u8::MAX)
            && self.code_segment & 3 == 0
            && is_canonical_4_level(self.instruction_pointer)
            && self.rflags & (1 << 1) != 0
    }
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
        crate::test_support::complete_exception_vector(exception.vector.vector());
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

/// Terminal dispatch target called only by the audited `exceptions.S` common
/// entry. It has an explicit System V signature; it never treats an arbitrary
/// stack pointer as a Rust ABI argument and it never returns to an `iretq`.
///
/// # Safety
///
/// Callers must supply a live, eight-byte-aligned `RawExceptionContext` built
/// exactly by the terminal x86 exception assembly boundary.
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

    // SAFETY: `exceptions.S` saves every GPR plus CR2, vector/error words, and
    // the three mandatory processor-frame words before this explicit SysV
    // call. The exception path is terminal, so no asynchronous caller can
    // revoke the stack snapshot.
    let raw_context = unsafe { raw_context.read() };
    if !raw_context.validates_architecture() {
        halt_forever();
    }
    let Ok(vector_number) = u8::try_from(raw_context.vector) else {
        halt_forever();
    };
    let Ok(vector) = ExceptionVector::from_vector(vector_number) else {
        halt_forever();
    };
    let frame = ExceptionFrame {
        instruction_pointer: raw_context.instruction_pointer,
        code_segment: raw_context.code_segment,
        rflags: raw_context.rflags,
        stack_pointer: None,
        stack_segment: None,
    };
    let error_code = vector
        .pushes_error_code()
        .then_some(raw_context.raw_error_code);
    let fault_address = matches!(vector, ExceptionVector::PageFault).then_some(raw_context.cr2);
    let Ok(exception) = EarlyException::new(vector, error_code, frame, fault_address) else {
        halt_forever();
    };
    report_early_exception(&mut SerialEarlyExceptionReporter, exception)
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
mod tests {
    use super::*;
    use crate::interrupt::EXCEPTION_VECTOR_RANGE;

    const FRAME: ExceptionFrame = ExceptionFrame {
        instruction_pointer: 0xffff_ffff_8000_1000,
        code_segment: 0x08,
        rflags: 0x202,
        stack_pointer: None,
        stack_segment: None,
    };

    #[test]
    fn exception_vectors_follow_the_shared_vector_range() {
        assert_eq!(EXCEPTION_VECTOR_RANGE, 0x00..=0x1f);
        assert_eq!(
            ExceptionVector::from_vector(14),
            Ok(ExceptionVector::PageFault)
        );
        assert_eq!(
            ExceptionVector::from_vector(0x20),
            Err(ExceptionVectorError::OutsideExceptionRange(0x20))
        );
        assert_eq!(EXCEPTION_HANDLER_COUNT, 32);
    }

    #[test]
    fn error_code_and_cr2_rules_are_fail_closed() {
        assert!(
            EarlyException::new(ExceptionVector::PageFault, None, FRAME, Some(0x1000)).is_err()
        );
        assert!(EarlyException::new(ExceptionVector::InvalidOpcode, Some(0), FRAME, None).is_err());
        assert!(EarlyException::new(ExceptionVector::PageFault, Some(0), FRAME, None).is_err());
        assert!(
            EarlyException::new(ExceptionVector::PageFault, Some(0x7f), FRAME, Some(0x1000))
                .is_ok()
        );
    }

    #[test]
    fn stack_pair_must_be_complete() {
        let incomplete = ExceptionFrame {
            stack_pointer: Some(0x2000),
            ..FRAME
        };
        assert_eq!(
            EarlyException::new(ExceptionVector::Breakpoint, None, incomplete, None),
            Err(ExceptionFrameError::IncompleteStackFrame)
        );
    }

    #[test]
    fn page_fault_bits_are_preserved_without_reinterpreting_unknown_bits() {
        let exception = EarlyException::new(
            ExceptionVector::PageFault,
            Some(0x806f),
            FRAME,
            Some(0xdead_beef),
        )
        .unwrap();
        let error = exception.page_fault_error().unwrap();
        assert!(error.was_present());
        assert!(error.was_write());
        assert!(error.was_user_access());
        assert!(error.reserved_bit_violation());
        assert!(!error.instruction_fetch());
        assert!(error.protection_key());
        assert!(error.shadow_stack());
        assert!(error.sgx());
    }

    #[test]
    fn native_mapping_is_classification_not_delivery() {
        assert_eq!(
            ExceptionVector::PageFault.native_exception_type(),
            Some(DW_EXCEPTION_PAGE_FAULT)
        );
        assert_eq!(ExceptionVector::MachineCheck.native_exception_type(), None);
    }

    #[test]
    fn raw_context_has_the_assembly_defined_layout() {
        assert_eq!(core::mem::size_of::<RawExceptionContext>(), 168);
        assert_eq!(core::mem::align_of::<RawExceptionContext>(), 8);
        assert_eq!(core::mem::offset_of!(RawExceptionContext, rbx), 0);
        assert_eq!(core::mem::offset_of!(RawExceptionContext, cr2), 112);
        assert_eq!(core::mem::offset_of!(RawExceptionContext, rax), 120);
        assert_eq!(core::mem::offset_of!(RawExceptionContext, vector), 128);
        assert_eq!(
            core::mem::offset_of!(RawExceptionContext, instruction_pointer),
            144
        );
    }

    #[test]
    fn raw_context_validation_rejects_non_kernel_exception_state() {
        let valid = RawExceptionContext {
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            cr2: 0,
            rax: 0,
            vector: 14,
            raw_error_code: 0,
            instruction_pointer: 0xffff_ffff_8000_1000,
            code_segment: 0x08,
            rflags: 0x202,
        };
        assert!(valid.validates_architecture());
        let mut invalid = valid;
        invalid.code_segment = 0x1b;
        assert!(!invalid.validates_architecture());
        invalid = valid;
        invalid.instruction_pointer = 0x0001_0000_0000_0000;
        assert!(!invalid.validates_architecture());
        invalid = valid;
        invalid.rflags = 0;
        assert!(!invalid.validates_architecture());
    }
}
