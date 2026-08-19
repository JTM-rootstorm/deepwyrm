//! Test-build-only guest completion support.
//!
//! This module is compiled only when the kernel's `test-support` feature is
//! enabled. Its record, identifier, detail, and transport namespaces are test
//! harness internals, not Deepwyrm production ABI.

#![cfg(feature = "test-support")]

mod identity;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod memory;
mod protocol;
#[cfg(all(deepwyrm_e7_guest, target_arch = "x86_64", target_os = "none"))]
mod task;
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
    complete_exception, complete_fail, complete_panic, complete_pass, expect_terminal_page_fault,
    read_user_alias_word, trigger_expected_invalid_opcode, write_then_read_user_alias,
};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) use identity::ExpectedPageFaultKind;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) use memory::run_memory_guest_test;

#[cfg(all(deepwyrm_e7_guest, target_arch = "x86_64", target_os = "none"))]
pub(crate) use task::{
    e7_user_data, e7_user_entry, e7_user_stack_bottom, e7_user_stack_top, run_task_guest_test,
};

#[cfg(target_os = "none")]
pub(crate) use identity::{BUILD_GUEST_TEST, BuildGuestTest};
