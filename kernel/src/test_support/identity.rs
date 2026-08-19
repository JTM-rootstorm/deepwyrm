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
    TaskSyscallSmoke,
    TaskSyscallSanitize,
    TaskUserException,
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
            Self::TaskSyscallSmoke => 10,
            Self::TaskSyscallSanitize => 11,
            Self::TaskUserException => 12,
        }
    }

    pub(crate) const fn is_task_userspace(self) -> bool {
        matches!(
            self,
            Self::TaskSyscallSmoke | Self::TaskSyscallSanitize | Self::TaskUserException
        )
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
    } else if string_equals(value, "task-syscall-smoke") {
        BuildGuestTest::TaskSyscallSmoke
    } else if string_equals(value, "task-syscall-sanitize") {
        BuildGuestTest::TaskSyscallSanitize
    } else if string_equals(value, "task-user-exception") {
        BuildGuestTest::TaskUserException
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
mod tests;
