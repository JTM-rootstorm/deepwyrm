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

    /// Builds the value directly in the storage and returns its one owner's
    /// reference, so no whole-value temporary exists on the caller's stack
    /// (S2K stage 4: `init(value)` materialized the primordial carrier as a
    /// frame temporary before copying it in).
    ///
    /// # Safety
    ///
    /// `init` fully initializes the value behind the pointer before it
    /// returns, and reads nothing through it. Build it with [`init_fields!`],
    /// whose exhaustive field list makes "every field is written" a compile
    /// check, nesting another `init_fields!` for each field built in place.
    #[allow(
        unsafe_code,
        reason = "the caller's contract makes the storage initialized before it is assumed so"
    )]
    #[allow(
        clippy::mut_from_ref,
        reason = "forwards `take`, whose one-shot swap makes the reference unique"
    )]
    pub(crate) unsafe fn init_in_place(&'static self, init: impl FnOnce(*mut T)) -> &'static mut T {
        let slot = self.take();
        init(slot.as_mut_ptr());
        // SAFETY: `init` fully initialized the value and read nothing (this function's contract).
        unsafe { slot.assume_init_mut() }
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

/// Writes every field of the struct behind `$ptr` in place, from the field
/// list given, and fails to compile unless that list names every field.
///
/// Each `field: value` is written with `addr_of_mut!` and `ptr::write`, so no
/// reference to the uninitialized struct, and no whole-struct temporary, is
/// ever made. The exhaustiveness check is a struct pattern without `..`, in a
/// closure that is never called: a field added to the struct and not to the
/// list is a compile error here, not silently uninitialized memory (rustc
/// reports it at this macro as "pattern requires `..` due to inaccessible
/// fields", because the pattern's span is the macro's). A field
/// that is itself built in place is written by a nested `init_fields!` on its
/// own `addr_of_mut!` pointer and listed as `field: in_place`.
///
/// It expands to raw-pointer place expressions, so it compiles only inside an
/// `unsafe` block, whose SAFETY note states that `$ptr` is valid for writes of
/// the whole struct. This is the one place the in-place construction's
/// soundness lives.
macro_rules! init_fields {
    ($ptr:expr, $($struct:ident)::+ { $( $(#[$attr:meta])* $field:ident : $value:tt ),* $(,)? }) => {{
        let ptr = $ptr;
        $(
            $(#[$attr])*
            $crate::one_shot::init_fields!(@write ptr, $field, $value);
        )*
        // Never called: the pattern only checks the field list.
        let _exhaustive = || {
            let $($struct)::+ { $( $(#[$attr])* $field: _ ),* } = &*ptr;
        };
    }};
    (@write $ptr:ident, $field:ident, in_place) => {};
    (@write $ptr:ident, $field:ident, $value:tt) => {
        // The caller's pointer is valid for writes of the whole struct, so this field's place is
        // too; `write` stores without reading or dropping the uninitialized old value.
        core::ptr::addr_of_mut!((*$ptr).$field).write($value)
    };
}
pub(crate) use init_fields;

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

    #[derive(Debug, PartialEq)]
    struct Inner {
        left: [u8; 3],
        right: u64,
    }

    #[derive(Debug, PartialEq)]
    struct Outer {
        inner: Inner,
        flag: bool,
        name: Option<&'static str>,
    }

    /// The in-place builder writes every field, nested fields included, and
    /// the owner then reads the fully initialized value.
    #[test]
    fn a_value_built_in_place_is_fully_initialized() {
        static STORAGE: OneShotStorage<Outer> = OneShotStorage::new();
        #[allow(unsafe_code, reason = "the host model of the in-place builder")]
        // SAFETY: `init_fields!` writes every field of `Outer` and, nested, of `Inner`.
        let owned = unsafe {
            STORAGE.init_in_place(|outer| {
                init_fields!(
                    core::ptr::addr_of_mut!((*outer).inner),
                    Inner {
                        left: [1, 2, 3],
                        right: 9,
                    }
                );
                init_fields!(
                    outer,
                    Outer {
                        inner: in_place,
                        flag: true,
                        name: (Some("carrier")),
                    }
                );
            })
        };
        assert_eq!(
            *owned,
            Outer {
                inner: Inner {
                    left: [1, 2, 3],
                    right: 9
                },
                flag: true,
                name: Some("carrier"),
            }
        );
    }
}
