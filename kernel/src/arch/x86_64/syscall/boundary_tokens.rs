//! Proofs the CPL3 entry boundary takes (S2K-3).
//!
//! `BoundKernelStack`: the current CPU's entry record binds a Thread kernel
//! stack, so `enter_bound_validated_user` needs one where it used to trust
//! its callers' order. The live boundary mints it when it binds the stack
//! (`bind_current_thread_stack`) or when it re-checks a binding a kernel
//! context switch made (`current_bound_kernel_stack`).
//!
//! Only `core` and `KernelStackBounds`, so the compile-fail cases in
//! `kernel/tests/root_switch_ui.rs` build it on the host; the kernel compiles
//! it with the live boundary it serves.

use core::marker::PhantomData;

use crate::memory::kernel_stack::KernelStackBounds;

/// Proof that this CPU's entry record binds `stack` as its current kernel
/// stack. Neither `Clone` nor `Copy`, and neither `Send` nor `Sync`.
#[derive(Debug)]
pub(crate) struct BoundKernelStack {
    stack: KernelStackBounds,
    _cpu_local: PhantomData<*mut ()>,
}

impl BoundKernelStack {
    /// # Safety
    ///
    /// This CPU's entry record currently binds `stack` as its current kernel
    /// stack.
    #[allow(
        unsafe_code,
        reason = "the unchecked constructor states a per-CPU entry-record fact no type here can see"
    )]
    pub(crate) const unsafe fn assume(stack: KernelStackBounds) -> Self {
        Self {
            stack,
            _cpu_local: PhantomData,
        }
    }

    /// The bound stack.
    pub(crate) const fn stack(&self) -> KernelStackBounds {
        self.stack
    }
}
