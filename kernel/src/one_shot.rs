//! Static storage owned, once, for the kernel's lifetime.
//!
//! `OneShotStorage::take` hands the uninitialized storage to its one owner as
//! `&'static mut` and refuses every later call, so "this static is written by
//! one caller and then owned by it forever" is enforced, not argued at each
//! use. Boot data the frame-role manager borrows, and the primordial runtime's
//! permanent authority and carriers (S2K-4, reset R2D), live in such storage
//! instead of on the boot stack.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct OneShotStorage<T> {
    taken: AtomicBool,
    cell: UnsafeCell<MaybeUninit<T>>,
}

#[allow(
    unsafe_code,
    reason = "the storage hands its cell to exactly one owner, chosen by an atomic swap"
)]
// SAFETY: the only access is `take`, whose atomic swap admits exactly one caller, which receives
// the sole reference to the cell; no shared access to the contents is ever handed out through
// this type, so sharing `&OneShotStorage<T>` between CPUs shares nothing but the flag.
unsafe impl<T> Sync for OneShotStorage<T> {}

impl<T> OneShotStorage<T> {
    pub(crate) const fn new() -> Self {
        Self {
            taken: AtomicBool::new(false),
            cell: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// The uninitialized storage, for its one owner, for the kernel's
    /// lifetime. A second call panics.
    #[allow(
        unsafe_code,
        reason = "the swap proves this is the one caller, so the static cell's reference is unique"
    )]
    #[allow(
        clippy::mut_from_ref,
        reason = "the one-shot swap makes this the only reference ever created to the cell"
    )]
    pub(crate) fn take(&'static self) -> &'static mut MaybeUninit<T> {
        if self.taken.swap(true, Ordering::AcqRel) {
            panic!("one-shot static storage was taken twice");
        }
        // SAFETY: the swap above returned `false` exactly once for this static, so this is the only
        // reference ever created to the cell, and the cell lives for the kernel's lifetime.
        unsafe { &mut *self.cell.get() }
    }

    /// Moves `value` into the storage and returns its one owner's reference.
    #[allow(
        clippy::mut_from_ref,
        reason = "forwards `take`, whose one-shot swap makes the reference unique"
    )]
    pub(crate) fn init(&'static self, value: T) -> &'static mut T {
        self.take().write(value)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn the_storage_is_owned_once_for_the_kernel_lifetime() {
        static STORAGE: OneShotStorage<u64> = OneShotStorage::new();
        let owned: &'static mut u64 = STORAGE.init(7);
        *owned += 1;
        assert_eq!(*owned, 8);
        let again = std::panic::catch_unwind(|| {
            let _ = STORAGE.take();
        });
        assert!(again.is_err());
    }
}
