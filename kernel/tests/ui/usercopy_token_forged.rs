#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::GuardFreeValue;

// The usercopy token cannot be built by hand.
pub(crate) fn forge(value: &mut u64) -> GuardFreeValue<'_, u64> {
    GuardFreeValue { value }
}
