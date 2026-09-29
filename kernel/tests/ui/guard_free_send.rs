#![no_std]

include!("runtime_authority_stub.rs");

fn require_send<T: Send>() {}

// A token certifies the CPU that minted it; it cannot travel to another.
pub(crate) fn token_is_not_send() {
    require_send::<GuardFree<'static>>();
}
