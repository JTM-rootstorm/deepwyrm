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
    assert!(EarlyException::new(ExceptionVector::PageFault, None, FRAME, Some(0x1000)).is_err());
    assert!(EarlyException::new(ExceptionVector::InvalidOpcode, Some(0), FRAME, None).is_err());
    assert!(EarlyException::new(ExceptionVector::PageFault, Some(0), FRAME, None).is_err());
    assert!(
        EarlyException::new(ExceptionVector::PageFault, Some(0x7f), FRAME, Some(0x1000)).is_ok()
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
