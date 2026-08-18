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
fn raw_context_has_the_e4_fixed_assembly_layout() {
    assert_eq!(core::mem::size_of::<RawExceptionContext>(), 184);
    assert_eq!(core::mem::align_of::<RawExceptionContext>(), 8);
    assert_eq!(core::mem::offset_of!(RawExceptionContext, rbx), 0);
    assert_eq!(core::mem::offset_of!(RawExceptionContext, cr2), 112);
    assert_eq!(
        core::mem::offset_of!(RawExceptionContext, stack_pointer),
        120
    );
    assert_eq!(
        core::mem::offset_of!(RawExceptionContext, stack_segment),
        128
    );
    assert_eq!(core::mem::offset_of!(RawExceptionContext, rax), 136);
    assert_eq!(core::mem::offset_of!(RawExceptionContext, vector), 144);
    assert_eq!(
        core::mem::offset_of!(RawExceptionContext, raw_error_code),
        152
    );
    assert_eq!(
        core::mem::offset_of!(RawExceptionContext, instruction_pointer),
        160
    );
    assert_eq!(
        core::mem::offset_of!(RawExceptionContext, code_segment),
        168
    );
    assert_eq!(core::mem::offset_of!(RawExceptionContext, rflags), 176);
}

fn raw_kernel(vector: u64) -> RawExceptionContext {
    RawExceptionContext {
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
        stack_pointer: 0,
        stack_segment: 0,
        rax: 0,
        vector,
        raw_error_code: 0,
        instruction_pointer: 0xffff_ffff_8000_1000,
        code_segment: 0x08,
        rflags: 0x202,
    }
}

fn raw_user(vector: u64) -> RawExceptionContext {
    RawExceptionContext {
        instruction_pointer: 0x0000_0000_4000_1000,
        code_segment: 0x33,
        stack_pointer: 0x0000_0000_5000_2000,
        stack_segment: 0x2b,
        ..raw_kernel(vector)
    }
}

#[test]
fn raw_context_origin_validation_is_exact() {
    let valid = raw_kernel(14);
    assert!(valid.validates_architecture());
    assert_eq!(valid.origin(), Some(ExceptionOrigin::Kernel));

    let mut invalid = valid;
    invalid.code_segment = 0x1b;
    assert!(!invalid.validates_architecture());
    invalid = valid;
    invalid.stack_pointer = 1;
    assert!(!invalid.validates_architecture());
    invalid = valid;
    invalid.instruction_pointer = 0x0001_0000_0000_0000;
    assert!(!invalid.validates_architecture());
    invalid = valid;
    invalid.rflags = 0;
    assert!(!invalid.validates_architecture());

    let mut user = raw_user(14);
    assert!(user.validates_architecture());
    assert_eq!(user.origin(), Some(ExceptionOrigin::User));
    user.stack_segment = 0x23;
    assert!(!user.validates_architecture());
}

#[test]
fn user_page_fault_becomes_structured_process_fatal_record() {
    let mut raw = raw_user(14);
    raw.raw_error_code = 0x806f;
    raw.cr2 = 0xdead_beef;
    let ExceptionDisposition::UserFatal(record) = classify_raw_exception(raw).unwrap() else {
        panic!("CPL3 page fault was not classified as user-fatal");
    };
    assert_eq!(record.exception_type, DW_EXCEPTION_PAGE_FAULT);
    assert_eq!(record.vector, 14);
    assert_eq!(record.detail, 0x806f);
    assert_eq!(record.fault_address, 0xdead_beef);
    assert_eq!(record.instruction_pointer, 0x4000_1000);
    assert_eq!(record.stack_pointer, 0x5000_2000);
    let task = record.task_exception();
    assert_eq!(task.exception_type, DW_EXCEPTION_PAGE_FAULT);
    assert_eq!(task.detail, 0x806f);
    assert_eq!(task.fault_address, 0xdead_beef);
}

#[test]
fn unnumbered_user_exception_uses_none_plus_raw_vector_detail() {
    let raw = raw_user(7);
    let ExceptionDisposition::UserFatal(record) = classify_raw_exception(raw).unwrap() else {
        panic!("CPL3 #NM was not classified as user-fatal");
    };
    assert_eq!(record.exception_type, DW_EXCEPTION_NONE);
    assert_eq!(record.vector, 7);
    assert_eq!(record.detail, 7);
    assert_eq!(record.fault_address, 0);
}

#[test]
fn nmi_double_fault_and_machine_check_remain_architecture_terminal() {
    for vector in [2, 8, 18] {
        let mut raw = raw_user(vector);
        if vector == 8 {
            raw.raw_error_code = 0;
        }
        let ExceptionDisposition::KernelTerminal(exception) = classify_raw_exception(raw).unwrap()
        else {
            panic!("terminal vector {vector} became task-recoverable");
        };
        assert!(exception.vector.is_always_terminal());
        assert_eq!(exception.frame.stack_segment, Some(0x2b));
    }
}
