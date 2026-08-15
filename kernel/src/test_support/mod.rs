//! Test-build-only guest completion support.
//!
//! This module is compiled only when the kernel's `test-support` feature is
//! enabled. Its record, identifier, detail, and transport namespaces are test
//! harness internals, not Deepwyrm production ABI.

#![cfg(feature = "test-support")]

mod identity;
mod protocol;
mod transport;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod x86_64;

pub use protocol::{
    COMPLETION_RECORD_LEN, CompletionOutcome, CompletionParseError, CompletionRecord,
    EncodedCompletionRecord,
};
pub use transport::{
    CompletionTransport, DebugExitValue, complete, emit_completion, expected_host_exit_status,
};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::{
    complete_exception_vector, complete_panic, complete_pass, trigger_expected_invalid_opcode,
};

#[cfg(target_os = "none")]
pub(crate) use identity::{BUILD_GUEST_TEST, BuildGuestTest};
