#![no_std]

include!("runtime_authority_stub.rs");

// A token without a handle takes `unsafe` and a stated reason.
pub(crate) fn forge() -> GuardFree<'static> {
    GuardFree::assume()
}
