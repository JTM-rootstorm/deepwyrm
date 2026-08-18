use super::*;
use crate::arch::x86_64::exceptions::ExceptionFrame;
use crate::test_support::{DebugExitValue, expected_host_exit_status};

#[test]
fn embedded_identity_is_nonzero_and_panic_mapping_is_stable() {
    assert!(!BUILD_GUEST_TEST_SELECTOR.is_empty());
    assert_ne!(BUILD_GUEST_TEST_ID, 0);

    assert_eq!(BUILD_GUEST_TEST.expected_id(), BUILD_GUEST_TEST_ID);

    let cases = [
        (CompletionOutcome::Pass, DebugExitValue::PASS, 33),
        (CompletionOutcome::Fail, DebugExitValue::FAIL, 35),
        (CompletionOutcome::Panic, DebugExitValue::PANIC, 37),
    ];
    for (outcome, exit, host_status) in cases {
        let record = completion_record(outcome, 0x5041_4e49);
        assert_eq!(record.outcome, outcome);
        assert_eq!(record.test_id, BUILD_GUEST_TEST_ID);
        assert_eq!(record.detail, 0x5041_4e49);
        assert_eq!(DebugExitValue::from(record.outcome), exit);
        assert_eq!(expected_host_exit_status(exit), host_status);
    }
}

#[test]
fn all_nine_central_selectors_have_exact_kernel_identities() {
    let cases = [
        ("boot-handoff-pass", BuildGuestTest::BootHandoffPass, 1),
        ("exception-fail-path", BuildGuestTest::ExceptionFailPath, 2),
        ("panic-path", BuildGuestTest::PanicPath, 3),
        ("memory-mapping", BuildGuestTest::MemoryMapping, 4),
        ("memory-unmapping", BuildGuestTest::MemoryUnmapping, 5),
        ("memory-permissions", BuildGuestTest::MemoryPermissions, 6),
        (
            "memory-invalid-pointer",
            BuildGuestTest::MemoryInvalidPointer,
            7,
        ),
        (
            "memory-user-kernel-isolation",
            BuildGuestTest::MemoryUserKernelIsolation,
            8,
        ),
        (
            "memory-shared-memory-object",
            BuildGuestTest::MemorySharedMemoryObject,
            9,
        ),
    ];
    for (selector, identity, id) in cases {
        assert_eq!(parse_known_selector(selector), identity);
        assert_eq!(identity.expected_id(), id);
    }
}

#[test]
#[should_panic(expected = "unknown build-selected guest test")]
fn unknown_selector_has_no_kernel_identity() {
    let _ = parse_known_selector("arbitrary-runtime-test");
}

#[test]
fn only_expected_invalid_opcode_is_classified_as_fail() {
    assert_eq!(
        exception_outcome_for(BuildGuestTest::ExceptionFailPath, 6),
        CompletionOutcome::Fail
    );
    for (test, vector) in [
        (BuildGuestTest::ExceptionFailPath, 14),
        (BuildGuestTest::BootHandoffPass, 6),
        (BuildGuestTest::PanicPath, 6),
        (BuildGuestTest::MemoryMapping, 6),
        (BuildGuestTest::MemoryUnmapping, 6),
        (BuildGuestTest::MemoryPermissions, 6),
        (BuildGuestTest::MemoryInvalidPointer, 6),
        (BuildGuestTest::MemoryUserKernelIsolation, 6),
        (BuildGuestTest::MemorySharedMemoryObject, 6),
    ] {
        assert_eq!(
            exception_outcome_for(test, vector),
            CompletionOutcome::Panic
        );
    }
    assert_eq!(
        expects_invalid_opcode(),
        BUILD_GUEST_TEST == BuildGuestTest::ExceptionFailPath
    );
}

#[test]
fn invalid_opcode_trigger_is_gated_to_the_negative_test_selector() {
    assert!(invalid_opcode_trigger_allowed_for(
        BuildGuestTest::ExceptionFailPath
    ));
    assert!(!invalid_opcode_trigger_allowed_for(
        BuildGuestTest::BootHandoffPass
    ));
    assert!(!invalid_opcode_trigger_allowed_for(
        BuildGuestTest::PanicPath
    ));
}

#[test]
fn only_memory_selectors_enter_the_post_activation_dispatch() {
    for test in [
        BuildGuestTest::MemoryMapping,
        BuildGuestTest::MemoryUnmapping,
        BuildGuestTest::MemoryPermissions,
        BuildGuestTest::MemoryInvalidPointer,
        BuildGuestTest::MemoryUserKernelIsolation,
        BuildGuestTest::MemorySharedMemoryObject,
    ] {
        assert!(test.is_memory_foundation());
    }
    for test in [
        BuildGuestTest::BootHandoffPass,
        BuildGuestTest::ExceptionFailPath,
        BuildGuestTest::PanicPath,
    ] {
        assert!(!test.is_memory_foundation());
    }
}

#[test]
fn expected_page_fault_contract_checks_every_terminal_fact() {
    let expected = ExpectedPageFaultFacts {
        address: 0x4000_0000,
        instruction_pointer: 0xffff_ffff_8000_1234,
        error_code: 3,
        processor_id: 7,
    };
    let matching = EarlyException::new(
        ExceptionVector::PageFault,
        Some(3),
        ExceptionFrame {
            instruction_pointer: expected.instruction_pointer,
            code_segment: 8,
            rflags: 2,
            stack_pointer: None,
            stack_segment: None,
        },
        Some(expected.address),
    )
    .unwrap();
    assert!(expected_page_fault_matches(matching, expected, 7));

    let mut cases = [matching; 4];
    cases[0].fault_address = Some(expected.address + 8);
    cases[1].error_code = Some(1);
    cases[2].frame.instruction_pointer += 1;
    cases[3].vector = ExceptionVector::GeneralProtection;
    for mismatch in cases {
        assert!(!expected_page_fault_matches(mismatch, expected, 7));
    }
    assert!(!expected_page_fault_matches(matching, expected, 8));
    assert_eq!(
        expected_fault_selector(ExpectedPageFaultKind::UnmappedSupervisorRead),
        (BuildGuestTest::MemoryUnmapping, 0)
    );
    assert_eq!(
        expected_fault_selector(ExpectedPageFaultKind::WriteProtectedSupervisorWrite),
        (BuildGuestTest::MemoryPermissions, 3)
    );
}

#[test]
fn decimal_identity_parser_accepts_the_full_nonzero_u32_range() {
    assert_eq!(parse_nonzero_decimal_u32("1"), 1);
    assert_eq!(parse_nonzero_decimal_u32("4294967295"), u32::MAX);
}

#[test]
#[should_panic(expected = "guest-test ID must not be empty")]
fn decimal_identity_parser_rejects_empty_input() {
    let _ = parse_nonzero_decimal_u32("");
}

#[test]
#[should_panic(expected = "guest-test ID must be nonzero")]
fn decimal_identity_parser_rejects_zero() {
    let _ = parse_nonzero_decimal_u32("0");
}

#[test]
#[should_panic(expected = "guest-test ID must be decimal")]
fn decimal_identity_parser_rejects_non_decimal_input() {
    let _ = parse_nonzero_decimal_u32("1A");
}

#[test]
#[should_panic(expected = "guest-test ID exceeds u32")]
fn decimal_identity_parser_rejects_overflow() {
    let _ = parse_nonzero_decimal_u32("4294967296");
}
