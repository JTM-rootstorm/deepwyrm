#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::RuntimeAuthorityLock;

fn consume(_token: GuardFree<'_>) {}

// S2K-6: a CPU's interrupt-context handle (its quantum-expiry publisher's)
// locks the runtime authority but can never certify the CPU guard-free.
pub(crate) fn prove_from_interrupt_handle(lock: &RuntimeAuthorityLock<u32>) {
    let [mut handle] = lock.interrupt_handles::<1>();
    consume(handle.guard_free());
}
