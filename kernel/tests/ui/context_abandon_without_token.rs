#![no_std]
#![allow(dead_code)]

include!("context_abandon_stub.rs");

// No path abandons a frame without proving it holds no runtime guard.
fn abandon_without_proof() -> ! {
    #[allow(unsafe_code, reason = "the fixture only type-checks the boundary")]
    unsafe {
        arch::x86_64::context::abandon_to_kernel_continuation(0x1000)
    }
}
