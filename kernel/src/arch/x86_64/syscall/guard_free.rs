//! The guard-free token (S2K-3).
//!
//! A physical boundary -- a CR3 root switch, a wait for a remote-stop
//! acknowledgement, a reaper handoff, an idle or user entry, abandoning to a
//! kernel continuation, or a kernel context switch -- must never run while
//! this CPU holds the primordial runtime authority guard (DW0-H §12.8,
//! DW1-C0 §6, reset plan §4.3). Every such boundary takes a `GuardFree`.
//!
//! The safe way to obtain one is `RuntimeAuthorityHandle::guard_free(&mut
//! self)`. The handle is the CPU's only way to lock, and a guard mutably
//! borrows it, so the borrow checker refuses to mint a token while that CPU's
//! guard is alive. Code that cannot hold a runtime-authority guard at all (a
//! runtime with no coarse lock, or a fresh bootstrap frame) uses the unsafe
//! `assume` and states why.
//!
//! Always compiled, so the runtime traits in `crate::syscall::native` can name
//! it in every build, and the compile-fail cases can include it.

use core::marker::PhantomData;

/// Proof that this CPU holds no runtime-authority guard for `'a`.
///
/// Zero-sized, neither `Clone` nor `Copy`, and neither `Send` nor `Sync`: a
/// token certifies the CPU and execution context that minted it and is
/// consumed by one boundary.
#[must_use = "a guard-free token exists to be passed to a physical boundary"]
pub(crate) struct GuardFree<'a> {
    _borrow: PhantomData<&'a mut ()>,
    _cpu_local: PhantomData<*mut ()>,
}

impl GuardFree<'_> {
    /// Mints a token without a handle.
    ///
    /// # Safety
    ///
    /// No runtime-authority guard is held by any frame of this CPU's current
    /// execution context, and none is acquired before the token is consumed.
    #[allow(
        unsafe_code,
        reason = "the unchecked constructor states a CPU-wide fact no type here can see"
    )]
    pub(crate) const unsafe fn assume() -> Self {
        Self {
            _borrow: PhantomData,
            _cpu_local: PhantomData,
        }
    }
}
