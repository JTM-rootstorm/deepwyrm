//! Move-only root-switch transactions of the primordial runtime carrier.
//!
//! Each switch is a flight: the carrier prepares a `Prepared*` value (with the
//! exact CPU/generation `RootSwitchFlight` it recorded), `execute_on` performs
//! the CR3 effect through a `RootSwitchTarget` and returns either an
//! `Executed*` value for the carrier's commit or a `Failed*` value for its
//! cancel. The types carry the ordering: a `Prepared*` is consumed by
//! `execute_on`, and only `execute_on` can produce an `Executed*` or `Failed*`,
//! because their payload fields are private to this module. The flight stays
//! readable for the carrier's identity checks.
//!
//! Split out of the target-only `primordial.rs` (S2K-2) and made generic over
//! `RootSwitchTarget`, so the host build compiles it and the compile-fail
//! cases in `kernel/tests/root_switch_ui.rs` can hold these properties
//! statically. `primordial.rs` binds the live target.

#![cfg_attr(
    test,
    allow(
        dead_code,
        reason = "the carrier that drives these transactions is target-only; host tests and the compile-fail cases exercise the types"
    )
)]

use super::RootSwitchTarget;
use crate::memory::address_region::AddressRegionObjectKey;
use crate::task::{KernelStackId, ProcessKey, ThreadContextId, ThreadKey};

/// The carrier's per-CPU root state.
pub(super) enum CarrierActiveRoot {
    Unselected,
    Process(super::ActiveRootSelection),
    StopPrecommitted(super::ActiveRootSelection),
    Kernel(super::ActiveKernelExecutionRoot),
    Transitioning,
}

impl CarrierActiveRoot {
    pub(super) fn as_ref(&self) -> Option<&super::ActiveRootSelection> {
        match self {
            Self::Process(root) => Some(root),
            Self::Unselected
            | Self::StopPrecommitted(_)
            | Self::Kernel(_)
            | Self::Transitioning => None,
        }
    }

    pub(super) fn take_process(&mut self) -> super::ActiveRootSelection {
        match core::mem::replace(self, Self::Transitioning) {
            Self::Process(root) => root,
            Self::Unselected
            | Self::StopPrecommitted(_)
            | Self::Kernel(_)
            | Self::Transitioning => {
                panic!("carrier has no active Process root")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootSwitchFlight {
    pub(super) cpu: crate::cpu::CpuIndex,
    pub(super) generation: u64,
}

pub(super) struct SchedulerRootIdentity {
    pub(super) process: ProcessKey,
    pub(super) thread: ThreadKey,
    pub(super) root_key: AddressRegionObjectKey,
    pub(super) stack_id: KernelStackId,
    pub(super) context_id: ThreadContextId,
}

pub(super) enum PreparedSchedulerRootSwitchKind {
    Process(super::PreparedProcessRootSwitch),
    FromKernel(super::PreparedKernelToProcessRootSwitch),
}

pub(super) struct PreparedSchedulerRootSwitch {
    flight: RootSwitchFlight,
    identity: SchedulerRootIdentity,
    kind: PreparedSchedulerRootSwitchKind,
}

pub(super) enum ExecutedSchedulerRootSwitchKind {
    Process(super::ExecutedProcessRootSwitch),
    FromKernel(super::ExecutedKernelToProcessRootSwitch),
}

pub(super) struct ExecutedSchedulerRootSwitch {
    pub(super) flight: RootSwitchFlight,
    identity: SchedulerRootIdentity,
    kind: ExecutedSchedulerRootSwitchKind,
}

pub(super) enum FailedSchedulerRootSwitchKind {
    Process(super::RootSelectionFailure),
    FromKernel(super::KernelRootSelectionFailure),
}

pub(super) struct FailedSchedulerRootSwitch {
    pub(super) flight: RootSwitchFlight,
    kind: FailedSchedulerRootSwitchKind,
}

pub(super) struct PreparedStopRootSwitch {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelExecutionRootSwitch,
}

pub(super) struct ExecutedStopRootSwitch {
    pub(super) flight: RootSwitchFlight,
    executed: super::ExecutedKernelExecutionRootSwitch,
}

pub(super) struct FailedStopRootSwitch {
    pub(super) flight: RootSwitchFlight,
    error: super::RootBindingError,
    previous: super::ActiveRootSelection,
}

pub(super) struct PreparedTerminalKernelRootSwitch {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelExecutionRootSwitch,
}

pub(super) struct ExecutedTerminalKernelRootSwitch {
    pub(super) flight: RootSwitchFlight,
    executed: super::ExecutedKernelExecutionRootSwitch,
}

pub(super) struct FailedTerminalKernelRootSwitch {
    pub(super) flight: RootSwitchFlight,
    error: super::RootBindingError,
    previous: super::ActiveRootSelection,
}

pub(super) struct PreparedTerminalProcessRootSwitch {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelToProcessRootSwitch,
}

pub(super) struct ExecutedTerminalProcessRootSwitch {
    pub(super) flight: RootSwitchFlight,
    executed: super::ExecutedKernelToProcessRootSwitch,
}

pub(super) struct FailedTerminalProcessRootSwitch {
    pub(super) flight: RootSwitchFlight,
    failure: super::KernelRootSelectionFailure,
}

pub(super) struct PreparedApKernelRootEntry {
    flight: RootSwitchFlight,
    prepared: super::PreparedKernelRootEntry,
}

pub(super) struct ExecutedApKernelRootEntry {
    pub(super) flight: RootSwitchFlight,
    executed: super::ExecutedKernelRootEntry,
}

pub(super) struct FailedApKernelRootEntry {
    pub(super) flight: RootSwitchFlight,
    error: super::RootBindingError,
    prepared: super::PreparedKernelRootEntry,
}

impl PreparedApKernelRootEntry {
    pub(super) fn new(flight: RootSwitchFlight, prepared: super::PreparedKernelRootEntry) -> Self {
        Self { flight, prepared }
    }

    pub(super) fn execute_on<T: RootSwitchTarget>(
        self,
        target: &mut T,
    ) -> Result<ExecutedApKernelRootEntry, FailedApKernelRootEntry> {
        match self.prepared.execute(target) {
            Ok(executed) => Ok(ExecutedApKernelRootEntry {
                flight: self.flight,
                executed,
            }),
            Err((error, prepared)) => Err(FailedApKernelRootEntry {
                flight: self.flight,
                error,
                prepared,
            }),
        }
    }
}

impl ExecutedApKernelRootEntry {
    pub(super) fn into_executed(self) -> super::ExecutedKernelRootEntry {
        self.executed
    }
}

impl FailedApKernelRootEntry {
    pub(super) fn into_parts(self) -> (super::RootBindingError, super::PreparedKernelRootEntry) {
        (self.error, self.prepared)
    }
}

impl PreparedStopRootSwitch {
    pub(super) fn new(
        flight: RootSwitchFlight,
        prepared: super::PreparedKernelExecutionRootSwitch,
    ) -> Self {
        Self { flight, prepared }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free failure path must return the move-only root owners unchanged"
    )]
    pub(super) fn execute_on<T: RootSwitchTarget>(
        self,
        target: &mut T,
    ) -> Result<ExecutedStopRootSwitch, FailedStopRootSwitch> {
        match self.prepared.execute(target) {
            Ok(executed) => Ok(ExecutedStopRootSwitch {
                flight: self.flight,
                executed,
            }),
            Err((error, previous)) => Err(FailedStopRootSwitch {
                flight: self.flight,
                error,
                previous,
            }),
        }
    }
}

impl ExecutedStopRootSwitch {
    pub(super) fn into_executed(self) -> super::ExecutedKernelExecutionRootSwitch {
        self.executed
    }
}

impl FailedStopRootSwitch {
    pub(super) fn into_parts(self) -> (super::RootBindingError, super::ActiveRootSelection) {
        (self.error, self.previous)
    }
}

impl PreparedTerminalKernelRootSwitch {
    pub(super) fn new(
        flight: RootSwitchFlight,
        prepared: super::PreparedKernelExecutionRootSwitch,
    ) -> Self {
        Self { flight, prepared }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free failure path must return the move-only root owners unchanged"
    )]
    pub(super) fn execute_on<T: RootSwitchTarget>(
        self,
        target: &mut T,
    ) -> Result<ExecutedTerminalKernelRootSwitch, FailedTerminalKernelRootSwitch> {
        match self.prepared.execute(target) {
            Ok(executed) => Ok(ExecutedTerminalKernelRootSwitch {
                flight: self.flight,
                executed,
            }),
            Err((error, previous)) => Err(FailedTerminalKernelRootSwitch {
                flight: self.flight,
                error,
                previous,
            }),
        }
    }
}

impl ExecutedTerminalKernelRootSwitch {
    pub(super) fn into_executed(self) -> super::ExecutedKernelExecutionRootSwitch {
        self.executed
    }
}

impl FailedTerminalKernelRootSwitch {
    pub(super) fn into_parts(self) -> (super::RootBindingError, super::ActiveRootSelection) {
        (self.error, self.previous)
    }
}

impl PreparedTerminalProcessRootSwitch {
    pub(super) fn new(
        flight: RootSwitchFlight,
        prepared: super::PreparedKernelToProcessRootSwitch,
    ) -> Self {
        Self { flight, prepared }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free failure path must return the move-only root owners unchanged"
    )]
    pub(super) fn execute_on<T: RootSwitchTarget>(
        self,
        target: &mut T,
    ) -> Result<ExecutedTerminalProcessRootSwitch, FailedTerminalProcessRootSwitch> {
        match self.prepared.execute(target) {
            Ok(executed) => Ok(ExecutedTerminalProcessRootSwitch {
                flight: self.flight,
                executed,
            }),
            Err(failure) => Err(FailedTerminalProcessRootSwitch {
                flight: self.flight,
                failure,
            }),
        }
    }
}

impl ExecutedTerminalProcessRootSwitch {
    pub(super) fn into_executed(self) -> super::ExecutedKernelToProcessRootSwitch {
        self.executed
    }
}

impl FailedTerminalProcessRootSwitch {
    pub(super) fn into_failure(self) -> super::KernelRootSelectionFailure {
        self.failure
    }
}

impl PreparedSchedulerRootSwitch {
    pub(super) fn new(
        flight: RootSwitchFlight,
        identity: SchedulerRootIdentity,
        kind: PreparedSchedulerRootSwitchKind,
    ) -> Self {
        Self {
            flight,
            identity,
            kind,
        }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free failure path must return the move-only root owners unchanged"
    )]
    pub(super) fn execute_on<T: RootSwitchTarget>(
        self,
        target: &mut T,
    ) -> Result<ExecutedSchedulerRootSwitch, FailedSchedulerRootSwitch> {
        let kind = match self.kind {
            PreparedSchedulerRootSwitchKind::Process(prepared) => match prepared.execute(target) {
                Ok(executed) => ExecutedSchedulerRootSwitchKind::Process(executed),
                Err(failure) => {
                    return Err(FailedSchedulerRootSwitch {
                        flight: self.flight,
                        kind: FailedSchedulerRootSwitchKind::Process(failure),
                    });
                }
            },
            PreparedSchedulerRootSwitchKind::FromKernel(prepared) => {
                match prepared.execute(target) {
                    Ok(executed) => ExecutedSchedulerRootSwitchKind::FromKernel(executed),
                    Err(failure) => {
                        return Err(FailedSchedulerRootSwitch {
                            flight: self.flight,
                            kind: FailedSchedulerRootSwitchKind::FromKernel(failure),
                        });
                    }
                }
            }
        };
        Ok(ExecutedSchedulerRootSwitch {
            flight: self.flight,
            identity: self.identity,
            kind,
        })
    }
}

impl ExecutedSchedulerRootSwitch {
    pub(super) fn into_parts(self) -> (SchedulerRootIdentity, ExecutedSchedulerRootSwitchKind) {
        (self.identity, self.kind)
    }
}

impl FailedSchedulerRootSwitch {
    pub(super) fn into_kind(self) -> FailedSchedulerRootSwitchKind {
        self.kind
    }
}
