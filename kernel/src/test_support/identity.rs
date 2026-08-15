//! Compile-time guest-test identity resolved by the central build tooling.

#![cfg_attr(
    not(target_os = "none"),
    allow(
        dead_code,
        reason = "host builds validate target-only guest identity helpers"
    )
)]

use super::protocol::{CompletionOutcome, CompletionRecord};

/// Guest test selected and provenanced at kernel build time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BuildGuestTest {
    BootHandoffPass,
    ExceptionFailPath,
    PanicPath,
}

const INVALID_OPCODE_VECTOR: u8 = 6;

impl BuildGuestTest {
    const fn expected_id(self) -> u32 {
        match self {
            Self::BootHandoffPass => 1,
            Self::ExceptionFailPath => 2,
            Self::PanicPath => 3,
        }
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
    fn only_the_three_central_selectors_have_kernel_identities() {
        let cases = [
            ("boot-handoff-pass", BuildGuestTest::BootHandoffPass, 1),
            ("exception-fail-path", BuildGuestTest::ExceptionFailPath, 2),
            ("panic-path", BuildGuestTest::PanicPath, 3),
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
