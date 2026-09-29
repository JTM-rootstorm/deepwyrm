#![no_std]

include!("runtime_authority_stub.rs");

// A token minted at an execution root is carried by value to its one
// boundary; it cannot be duplicated into a second.
pub(crate) fn duplicate(token: &GuardFree<'_>) {
    let _ = <GuardFree<'_> as Clone>::clone(token);
}
