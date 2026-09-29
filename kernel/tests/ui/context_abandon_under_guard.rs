#![no_std]
#![allow(dead_code)]

include!("context_abandon_stub.rs");

use runtime_authority::RuntimeAuthorityHandle;

// The abandoned frame could never release a guard it holds.
fn abandon_under_the_guard(handle: &mut RuntimeAuthorityHandle<'_, ()>) -> ! {
    let _guard = handle.lock();
    #[allow(unsafe_code, reason = "the fixture only type-checks the boundary")]
    unsafe {
        arch::x86_64::context::abandon_to_kernel_continuation(0x1000, handle.guard_free())
    }
}
