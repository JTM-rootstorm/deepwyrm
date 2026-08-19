//! Phase-aware native syscall routing below the architecture entry boundary.
//!
//! DW0-E1 accepts a raw ABI syscall ID plus six already-captured scalar slots
//! and resolves only schema-known operations active through DW0-E. Handler
//! dispatch, usercopy, task ownership, and architecture register handling stay
//! in later E phases.

pub(crate) mod native;

mod abi_bytes;
mod adapters;

use deepwyrm_abi::{
    DW_STATUS_NOT_SUPPORTED, DwKnownSyscall, DwStatus, DwSyscallId, DwSyscallImplementationPhase,
};

const ACTIVE_PHASE: DwSyscallImplementationPhase = DwSyscallImplementationPhase::Dw0E;

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
