//! Compile-time guest-test identity resolved by the central build tooling.

#![cfg_attr(
    not(target_os = "none"),
    allow(
        dead_code,
        reason = "host builds validate target-only guest identity helpers"
    )
)]

use super::protocol::{CompletionOutcome, CompletionRecord};
use crate::arch::x86_64::exceptions::{EarlyException, ExceptionVector};

/// Guest test selected and provenanced at kernel build time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuildGuestTest {
    BootHandoffPass,
    ExceptionFailPath,
    PanicPath,
    MemoryMapping,
    MemoryUnmapping,
    MemoryPermissions,
    MemoryInvalidPointer,
    MemoryUserKernelIsolation,
    MemorySharedMemoryObject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedPageFaultKind {
    UnmappedSupervisorRead,
    WriteProtectedSupervisorWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExpectedPageFaultFacts {
    pub(super) address: u64,
    pub(super) instruction_pointer: u64,
    pub(super) error_code: u64,
    pub(super) processor_id: u8,
}

pub(super) fn expected_page_fault_matches(
    exception: EarlyException,
    expected: ExpectedPageFaultFacts,
    observed_processor_id: u8,
) -> bool {
    exception.vector == ExceptionVector::PageFault
        && exception.fault_address == Some(expected.address)
        && exception.error_code == Some(expected.error_code)
        && exception.frame.instruction_pointer == expected.instruction_pointer
        && observed_processor_id == expected.processor_id
}

pub(super) const fn expected_fault_selector(kind: ExpectedPageFaultKind) -> (BuildGuestTest, u64) {
    match kind {
        ExpectedPageFaultKind::UnmappedSupervisorRead => (BuildGuestTest::MemoryUnmapping, 0),
        ExpectedPageFaultKind::WriteProtectedSupervisorWrite => {
            (BuildGuestTest::MemoryPermissions, 3)
        }
    }
}

const INVALID_OPCODE_VECTOR: u8 = 6;

impl BuildGuestTest {
    const fn expected_id(self) -> u32 {
        match self {
            Self::BootHandoffPass => 1,
            Self::ExceptionFailPath => 2,
            Self::PanicPath => 3,
            Self::MemoryMapping => 4,
            Self::MemoryUnmapping => 5,
            Self::MemoryPermissions => 6,
            Self::MemoryInvalidPointer => 7,
            Self::MemoryUserKernelIsolation => 8,
            Self::MemorySharedMemoryObject => 9,
        }
    }

    pub(crate) const fn is_memory_foundation(self) -> bool {
        matches!(
            self,
            Self::MemoryMapping
                | Self::MemoryUnmapping
                | Self::MemoryPermissions
                | Self::MemoryInvalidPointer
                | Self::MemoryUserKernelIsolation
                | Self::MemorySharedMemoryObject
        )
    }
}

/// Canonical selector embedded into this test kernel for provenance.
pub(crate) const BUILD_GUEST_TEST_SELECTOR: &str = env!(
    "DEEPWYRM_GUEST_TEST_SELECTOR",
    "test-support builds require a centrally validated guest-test selector"
);

/// Nonzero ID resolved from the central selector mapping by `kernel/build.rs`.
pub(crate) const BUILD_GUEST_TEST_ID: u32 = parse_nonzero_decimal_u32(env!(
    "DEEPWYRM_GUEST_TEST_ID",
    "kernel/build.rs must resolve the selected guest test to its canonical ID"
));

/// Known test identity corresponding to [`BUILD_GUEST_TEST_SELECTOR`].
pub(crate) const BUILD_GUEST_TEST: BuildGuestTest = parse_known_selector(BUILD_GUEST_TEST_SELECTOR);

const _: () = assert!(
    BUILD_GUEST_TEST_ID == BUILD_GUEST_TEST.expected_id(),
    "central guest-test selector ID differs from the kernel's known test identity"
);

pub(crate) const fn completion_record(outcome: CompletionOutcome, detail: u32) -> CompletionRecord {
    CompletionRecord {
        outcome,
        test_id: BUILD_GUEST_TEST_ID,
        detail,
    }
}

pub(crate) const fn exception_outcome(vector: u8) -> CompletionOutcome {
    exception_outcome_for(BUILD_GUEST_TEST, vector)
}

pub(crate) const fn expects_invalid_opcode() -> bool {
    invalid_opcode_trigger_allowed_for(BUILD_GUEST_TEST)
}

const fn invalid_opcode_trigger_allowed_for(test: BuildGuestTest) -> bool {
    matches!(test, BuildGuestTest::ExceptionFailPath)
}

const fn exception_outcome_for(test: BuildGuestTest, vector: u8) -> CompletionOutcome {
    if matches!(test, BuildGuestTest::ExceptionFailPath) && vector == INVALID_OPCODE_VECTOR {
        CompletionOutcome::Fail
    } else {
        CompletionOutcome::Panic
    }
}

const fn parse_known_selector(value: &str) -> BuildGuestTest {
    if string_equals(value, "boot-handoff-pass") {
        BuildGuestTest::BootHandoffPass
    } else if string_equals(value, "exception-fail-path") {
        BuildGuestTest::ExceptionFailPath
    } else if string_equals(value, "panic-path") {
        BuildGuestTest::PanicPath
    } else if string_equals(value, "memory-mapping") {
        BuildGuestTest::MemoryMapping
    } else if string_equals(value, "memory-unmapping") {
        BuildGuestTest::MemoryUnmapping
    } else if string_equals(value, "memory-permissions") {
        BuildGuestTest::MemoryPermissions
    } else if string_equals(value, "memory-invalid-pointer") {
        BuildGuestTest::MemoryInvalidPointer
    } else if string_equals(value, "memory-user-kernel-isolation") {
        BuildGuestTest::MemoryUserKernelIsolation
    } else if string_equals(value, "memory-shared-memory-object") {
        BuildGuestTest::MemorySharedMemoryObject
    } else {
        panic!("unknown build-selected guest test")
    }
}

const fn string_equals(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn parse_nonzero_decimal_u32(value: &str) -> u32 {
    let bytes = value.as_bytes();
    assert!(!bytes.is_empty(), "guest-test ID must not be empty");

    let mut result = 0_u32;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(
            byte >= b'0' && byte <= b'9',
            "guest-test ID must be decimal"
        );
        let digit = (byte - b'0') as u32;
        assert!(
            result <= (u32::MAX - digit) / 10,
            "guest-test ID exceeds u32"
        );
        result = result * 10 + digit;
        index += 1;
    }
    assert!(result != 0, "guest-test ID must be nonzero");
    result
}

#[cfg(test)]
mod tests {
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
}
