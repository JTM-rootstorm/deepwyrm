#![no_std]

include!("power_stub.rs");

// Powering off takes a guard-free token; nothing else stands in for it.
pub(crate) fn power_off_without_token() -> ! {
    power::soft_off_then_halt(())
}
