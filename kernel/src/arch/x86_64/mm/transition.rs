//! Live loader page-table attestation for the DW0-C1 transition window.
//!
//! Boot intake proves that the paging carrier is structurally well formed.
//! This module separately reconciles that copied declaration with CPU state
//! and the complete live four-level table graph before any temporary entry is
//! allowed to change.

#![allow(
    dead_code,
    reason = "DW0-C1 establishes the live transition boundary before C2 consumes its mapper"
)]

use super::{
    ACCESSED, CACHE_DISABLE, DIRTY, FrameAddress, GLOBAL, HUGE, NO_EXECUTE, PAGE_SIZE,
    PERMITTED_ENTRY_FLAGS, PRESENT, PagingCapabilities, SOFTWARE_HIGH, SOFTWARE_LOW, USER,
    WRITABLE, WRITE_THROUGH,
};
use crate::boot::ValidatedPagingHandoff;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use crate::memory::frame_roles::TableIdentity;
use crate::memory::frame_roles::{
    AllocationGrant, FrameRoleError, FrameRoleManager, TransitionTableRoleSet, ZeroedGrant,
};
use core::convert::Infallible;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};
use deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT;

mod private;

#[path = "activation.rs"]
mod activation;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use activation::LiveActivePagingTarget;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use activation::activate_bootstrap_deep_paging;
pub(crate) use activation::{
    ActivationCpuState, ActivationPrepareError, ActiveDeepPaging, Cr3ActivationTarget,
    InactiveRootAuthority, PreparedActivation,
};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use activation::{IstStackBounds, IstStackLayout};
pub(crate) use private::claim_live_transition_mapper;
#[allow(
    unused_imports,
    reason = "C1 facade error types precede their bootstrap and C2 consumers"
)]
pub(crate) use private::{
    LiveTransitionError, LiveTransitionMapper, TransitionActivationHandoff,
    TransitionAttestationError, TransitionScratchError, TransitionZeroError, TransitionZeroFailure,
};
