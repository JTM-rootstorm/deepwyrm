#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::RuntimeAuthorityHandle;

// One handle per CPU: a copy would let one hold the guard while the other
// certifies the CPU guard-free.
pub(crate) fn duplicate(handle: &RuntimeAuthorityHandle<'_, u32>) {
    let _ = <RuntimeAuthorityHandle<'_, u32> as Clone>::clone(handle);
}
