//! Phase-aware native syscall routing below the architecture entry boundary.
//!
//! DW0-F1 accepts a raw ABI syscall ID plus six already-captured scalar slots
//! and resolves schema-known operations active through DW0-F. F1 only exposes
//! typed requests for the new phase; subsystem handlers remain NOT_SUPPORTED
//! until their owning F implementation phase lands.

pub(crate) mod native;

mod abi_bytes;
mod adapters;
mod f_services;

#[allow(
    unused_imports,
    reason = "the shared F12 service composition is consumed by the target runtime lane"
)]
pub(crate) use f_services::{
    FAtomicUserAccess, FServiceDispatch, FServiceOperationOwner, FServiceOwnerError,
    FServiceResume, FServiceResumeError, FServiceRoute, FServiceState, FServiceTerminalCleanup,
};

#[cfg(deepwyrm_f9_guest)]
pub(crate) use adapters::atomic_wake_with;
#[cfg(all(deepwyrm_dw1c_evidence, target_os = "none", target_arch = "x86_64"))]
pub(crate) use adapters::copy_dw1c_evidence_input;
#[cfg(all(deepwyrm_wyr1_evidence, target_os = "none", target_arch = "x86_64"))]
pub(crate) use adapters::copy_wyr1_evidence_input;
#[cfg(all(deepwyrm_wyr1b_evidence, target_os = "none", target_arch = "x86_64"))]
pub(crate) use adapters::copy_wyr1b_evidence_input;
#[cfg(all(
    any(
        deepwyrm_wyr1_evidence,
        deepwyrm_dw1b_evidence,
        deepwyrm_wyr1b_evidence,
        deepwyrm_dw1c_evidence
    ),
    target_os = "none",
    target_arch = "x86_64"
))]
pub(crate) use adapters::process_create_with_root_observed;
#[allow(
    unused_imports,
    reason = "F7 native wait runtime ownership is consumed by the later freestanding F guest runtime"
)]
pub(crate) use adapters::{
    CleanupQueue, NativeWaitControl, TerminalWaitCleanup, WaitSuspendError, WaitSuspendState,
    WaitSyscallAction, WaitTerminalCleanup, resume_wait_thread_syscall, timer_cancel, timer_create,
    timer_set, wait_many_syscall, wait_one_syscall,
};

#[cfg(all(target_os = "none", target_arch = "x86_64", deepwyrm_e7_guest))]
pub(crate) use adapters::clock_get;
#[cfg(all(deepwyrm_f12_guest, not(deepwyrm_integrated)))]
pub(crate) use adapters::process_terminate;
#[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
#[allow(
    unused_imports,
    reason = "the integrated F12 target probe consumes the synchronous compatibility adapter only when test support is selected"
)]
pub(crate) use adapters::{
    MemoryObjectBackingAccess, ProcessRootReservation, ThreadStartMappingAccess,
    memory_object_create_owned, process_create_with_root, process_terminate, thread_create,
    thread_start_with_access, thread_terminate,
};
#[cfg(deepwyrm_e7_guest)]
pub(crate) use adapters::{NoTerminalWaitCleanup, abi_get_info};
#[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
pub(crate) use adapters::{
    PreparedProcessTermination, PreparedTaskGroupTermination, PreparedThreadTermination,
    address_region_map_prepared_model, address_region_protect_prepared,
    address_region_unmap_prepared, complete_deferred_current_reclaim_on,
    complete_prepared_process_termination_after_remote_stops_on,
    complete_prepared_task_group_termination_after_remote_stops_on,
    complete_prepared_thread_termination_after_remote_stops_on, complete_wait_wakes,
    decode_map_args, handle_close, handle_duplicate, object_get_info_v1,
    prepare_address_region_mutation, prepare_process_exit, prepare_process_terminate,
    prepare_process_unhandled_exception, prepare_task_group_terminate, prepare_thread_terminate,
    process_exit_on, process_unhandled_exception_on, task_group_create,
};
#[cfg(all(
    not(deepwyrm_integrated),
    any(deepwyrm_e7_guest, deepwyrm_f9_guest, deepwyrm_f12_guest)
))]
pub(crate) use adapters::{complete_deferred_current_reclaim_on, process_exit_on};
#[cfg(all(deepwyrm_f12_guest, not(deepwyrm_integrated)))]
pub(crate) use adapters::{handle_close, handle_duplicate, object_get_info_v1};

use deepwyrm_abi::{
    DW_STATUS_NOT_SUPPORTED, DwKnownSyscall, DwStatus, DwSyscallId, DwSyscallImplementationPhase,
};

const ACTIVE_PHASE: DwSyscallImplementationPhase = DwSyscallImplementationPhase::Dw0F;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawSyscallArguments([u64; 6]);

impl RawSyscallArguments {
    pub(crate) const fn new(arguments: [u64; 6]) -> Self {
        Self(arguments)
    }

    pub(crate) const fn get(self, index: usize) -> Option<u64> {
        if index < self.0.len() {
            Some(self.0[index])
        } else {
            None
        }
    }

    pub(crate) const fn as_array(self) -> [u64; 6] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DecodedSyscall {
    identity: DwKnownSyscall,
    arguments: RawSyscallArguments,
}

impl DecodedSyscall {
    pub(crate) const fn identity(self) -> DwKnownSyscall {
        self.identity
    }

    pub(crate) const fn arguments(self) -> RawSyscallArguments {
        self.arguments
    }
}

pub(crate) const fn decode(
    id: DwSyscallId,
    arguments: RawSyscallArguments,
) -> Result<DecodedSyscall, DwStatus> {
    let Some(identity) = DwKnownSyscall::from_id(id) else {
        return Err(DW_STATUS_NOT_SUPPORTED);
    };
    if !identity
        .implementation_phase()
        .is_active_through(ACTIVE_PHASE)
    {
        return Err(DW_STATUS_NOT_SUPPORTED);
    }
    Ok(DecodedSyscall {
        identity,
        arguments,
    })
}

#[cfg(test)]
mod tests;
