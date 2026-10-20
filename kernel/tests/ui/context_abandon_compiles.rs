#![no_std]
#![allow(dead_code)]

// Control case: the real abandon boundary type-checks with a token minted from
// a handle whose guard has been dropped.
include!("context_abandon_stub.rs");

use runtime_authority::RuntimeAuthorityHandle;

fn abandon_after_the_guard(handle: &mut RuntimeAuthorityHandle<'_, ()>) -> ! {
    drop(handle.lock());
    #[allow(unsafe_code, reason = "the fixture only type-checks the boundary")]
    unsafe {
        arch::x86_64::context::abandon_to_kernel_continuation(
            0x1000,
            arch::x86_64::syscall::CarrierRelease::new(handle.guard_free()),
        )
    }
}
