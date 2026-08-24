//! Test-build-only guest completion support.
//!
//! This module is compiled only when the kernel's `test-support` feature is
//! enabled. Its record, identifier, detail, and transport namespaces are test
//! harness internals, not Deepwyrm production ABI.

#![cfg(feature = "test-support")]

#[cfg(deepwyrm_i1_evidence)]
mod evidence;
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

#[cfg(deepwyrm_i1_evidence)]
#[allow(
    unused_imports,
    reason = "the target-only scenario hooks consume these typed APIs in the I1 runtime lane"
)]
pub(crate) use evidence::{
    EvidenceEvent, EvidenceFlushError, EvidenceKind, I1_EVIDENCE, I1_EVIDENCE_RECORD_LEN,
    observe_child_cleanup as observe_i1_child_cleanup, observe_child_exit as observe_i1_child_exit,
    observe_cpl3_syscall as observe_i1_cpl3_syscall,
    observe_descendant_running as observe_i1_descendant_running,
    observe_parent_blocked as observe_i1_parent_blocked,
    observe_reclaim_allowed as observe_i1_reclaim_allowed,
    observe_remote_wake_received as observe_i1_remote_wake_received,
    observe_remote_wake_sent as observe_i1_remote_wake_sent,
    observe_rendezvous_ack as observe_i1_rendezvous_ack,
    observe_rendezvous_targets as observe_i1_rendezvous_targets,
    observe_tlb_ack as observe_i1_tlb_ack, observe_tlb_publish as observe_i1_tlb_publish,
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
