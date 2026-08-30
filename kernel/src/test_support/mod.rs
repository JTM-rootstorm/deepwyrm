//! Test-build-only guest completion support.
//!
//! This module is compiled only when the kernel's `test-support` feature is
//! enabled. Its record, identifier, detail, and transport namespaces are test
//! harness internals, not Deepwyrm production ABI.

#![cfg(feature = "test-support")]

#[cfg(any(
    all(deepwyrm_i1_evidence, deepwyrm_wrcap_relay),
    all(deepwyrm_i1_evidence, deepwyrm_wyr1_evidence),
    all(deepwyrm_wrcap_relay, deepwyrm_wyr1_evidence),
    all(deepwyrm_i1_evidence, deepwyrm_dw1b_evidence),
    all(deepwyrm_wrcap_relay, deepwyrm_dw1b_evidence),
    all(deepwyrm_wyr1_evidence, deepwyrm_dw1b_evidence),
    all(deepwyrm_dw1b_evidence, deepwyrm_dw1c_evidence),
    all(deepwyrm_wyr1b_evidence, deepwyrm_dw1c_evidence),
    all(deepwyrm_i1_evidence, deepwyrm_wyr1b_evidence),
    all(deepwyrm_wrcap_relay, deepwyrm_wyr1b_evidence),
    all(deepwyrm_wyr1_evidence, deepwyrm_wyr1b_evidence),
    all(deepwyrm_dw1b_evidence, deepwyrm_wyr1b_evidence),
    all(deepwyrm_dw1d_evidence, deepwyrm_i1_evidence),
    all(deepwyrm_dw1d_evidence, deepwyrm_wrcap_relay),
    all(deepwyrm_dw1d_evidence, deepwyrm_wyr1_evidence),
    all(deepwyrm_dw1d_evidence, deepwyrm_dw1b_evidence),
    all(deepwyrm_dw1d_evidence, deepwyrm_wyr1b_evidence),
    all(deepwyrm_dw1d_evidence, deepwyrm_dw1c_evidence),
    all(deepwyrm_wyr1c_evidence, deepwyrm_i1_evidence),
    all(deepwyrm_wyr1c_evidence, deepwyrm_wrcap_relay),
    all(deepwyrm_wyr1c_evidence, deepwyrm_wyr1_evidence),
    all(deepwyrm_wyr1c_evidence, deepwyrm_dw1b_evidence),
    all(deepwyrm_wyr1c_evidence, deepwyrm_wyr1b_evidence),
    all(deepwyrm_wyr1c_evidence, deepwyrm_dw1c_evidence),
    all(deepwyrm_wyr1c_evidence, deepwyrm_dw1d_evidence)
))]
compile_error!("selector-specific terminal reporters are selector-exclusive");

#[cfg(any(test, deepwyrm_dw1b_evidence))]
mod dw1b_evidence;
#[cfg(any(test, deepwyrm_dw1c_evidence))]
mod dw1c_evidence;
#[cfg(any(test, deepwyrm_dw1d_evidence))]
mod dw1d_evidence;
#[cfg(deepwyrm_i1_evidence)]
mod evidence;
mod identity;
#[cfg(all(deepwyrm_memory_guest, target_arch = "x86_64", target_os = "none"))]
mod memory;
mod protocol;
#[cfg(all(deepwyrm_e7_guest, target_arch = "x86_64", target_os = "none"))]
mod task;
mod transport;
#[cfg(any(test, deepwyrm_wrcap_relay))]
mod wrcap;
#[cfg(any(test, deepwyrm_wyr1_evidence))]
mod wyr1_evidence;
#[cfg(any(test, deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence))]
mod wyr1b_evidence;
#[cfg(any(test, deepwyrm_wyr1c_evidence))]
mod wyr1c_evidence;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod x86_64;

pub use protocol::{
    COMPLETION_RECORD_LEN, CompletionOutcome, CompletionParseError, CompletionRecord,
    EncodedCompletionRecord,
};
pub use transport::{
    CompletionTransport, DebugExitValue, complete, emit_completion, expected_host_exit_status,
};

#[cfg(deepwyrm_wrcap_relay)]
#[allow(
    unused_imports,
    reason = "the target-only primordial and terminal paths consume the WRCAP1 relay"
)]
pub(crate) use wrcap::{WRCAP_RECORD_LEN, WRCAP_RELAY, WrcapDrainAction, WrcapFlushError};

#[cfg(deepwyrm_dw1b_evidence)]
pub(crate) use dw1b_evidence::DW1B_EVIDENCE_RAW_SYSCALL;
#[cfg(deepwyrm_dw1c_evidence)]
pub(crate) use dw1c_evidence::DW1C_EVIDENCE_RAW_SYSCALL;
#[cfg(deepwyrm_dw1d_evidence)]
#[allow(
    unused_imports,
    reason = "selector-30 raw dispatch consumes this private ID only in the target runtime"
)]
pub(crate) use dw1d_evidence::DW1D_EVIDENCE_RAW_SYSCALL;
#[cfg(deepwyrm_dw1d_evidence)]
#[allow(
    unused_imports,
    reason = "selector-30 target-only lifecycle hooks consume this private surface"
)]
pub(crate) use dw1d_evidence::{
    DW1D_EVIDENCE, Dw1dAckPlan, Dw1dDeliverPlan, Dw1dEvidenceError, Dw1dEvidenceFlushPermit,
    Dw1dRawOperation,
};
#[cfg(deepwyrm_wyr1_evidence)]
pub(crate) use wyr1_evidence::WYR1_EVIDENCE_RAW_SYSCALL;
#[cfg(deepwyrm_wyr1b_evidence)]
pub(crate) use wyr1b_evidence::WYR1B_EVIDENCE_RAW_SYSCALL;
#[cfg(deepwyrm_wyr1c_evidence)]
pub(crate) use wyr1c_evidence::WYR1C_EVIDENCE_RAW_SYSCALL;

#[cfg(deepwyrm_dw1c_evidence)]
#[allow(
    unused_imports,
    reason = "selector-28 target-only raw dispatch and terminal transport consume this private surface"
)]
pub(crate) use dw1c_evidence::{
    DW1C_ACTOR_COUNT, DW1C_ARM_BYTES, DW1C_ARM_TIMEOUT_SECONDS, DW1C_EVIDENCE, DW1C_PROGRESS_MASK,
    Dw1cActor, Dw1cEvidenceError, Dw1cEvidenceFlushPermit,
    decode_arm_entries as decode_dw1c_arm_entries,
};

#[cfg(all(deepwyrm_dw1b_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use dw1b_evidence::{
    DW1B_EVIDENCE, Dw1bEvidenceError, Dw1bRawOperation, Dw1bSubjects, arm_thread_states_valid,
    exact_single_thread,
};

#[cfg(all(deepwyrm_wyr1_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use wyr1_evidence::{
    WYR1_EVIDENCE, WYR1_EVIDENCE_RECORD_LEN, Wyr1EvidenceError, Wyr1EvidenceFlushError,
    Wyr1EvidenceSubmit, Wyr1RetirementFacts,
};

#[cfg(all(
    any(deepwyrm_wyr1b_evidence, deepwyrm_wyr1c_evidence),
    target_arch = "x86_64",
    target_os = "none"
))]
pub(crate) use wyr1b_evidence::{
    WYR1B_EVIDENCE, WYR1B_EVIDENCE_RECORD_LEN, WYR1B_SYSTEM_INIT_GUARD_START,
    WYR1B_SYSTEM_INIT_STACK_BOTTOM, Wyr1bEvidenceError, Wyr1bEvidenceFlushError,
    Wyr1bEvidenceSubmit, Wyr1bReporterStartFacts, Wyr1bRetirementFacts,
};

#[cfg(all(deepwyrm_wyr1c_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use wyr1c_evidence::{
    WYR1C_EVIDENCE, WYR1C_EVIDENCE_RECORD_LEN, Wyr1cEvidenceError, Wyr1cEvidenceFlushError,
    Wyr1cEvidenceSubmit,
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
    runtime_missing_mask as i1_runtime_missing_mask,
};

#[cfg(all(deepwyrm_dw1b_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::complete_dw1b_evidence;
#[cfg(all(deepwyrm_dw1c_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::complete_dw1c_evidence;
#[cfg(all(deepwyrm_dw1d_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::complete_dw1d_evidence;
#[cfg(all(deepwyrm_wyr1_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::complete_wyr1_evidence;
#[cfg(all(deepwyrm_wyr1b_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::complete_wyr1b_evidence;
#[cfg(all(deepwyrm_wyr1c_evidence, target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::complete_wyr1c_evidence;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) use x86_64::{
    complete_exception, complete_fail, complete_panic, complete_pass, expect_terminal_page_fault,
    read_user_alias_word, trigger_expected_invalid_opcode, write_then_read_user_alias,
};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) use identity::ExpectedPageFaultKind;

#[cfg(all(deepwyrm_memory_guest, target_arch = "x86_64", target_os = "none"))]
pub(crate) use memory::run_memory_guest_test;

#[cfg(all(deepwyrm_e7_guest, target_arch = "x86_64", target_os = "none"))]
pub(crate) use task::{
    e7_user_data, e7_user_entry, e7_user_stack_bottom, e7_user_stack_top, run_task_guest_test,
};

#[cfg(target_os = "none")]
pub(crate) use identity::{BUILD_GUEST_TEST, BuildGuestTest};
