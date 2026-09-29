#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::RuntimeAuthorityLock;

fn consume(_token: GuardFree<'_>) {}

// No token while this CPU's guard is alive (the physical-boundary rule of
// DW0-H §12.8 and DW1-C0 §6).
pub(crate) fn prove_while_locked(lock: &RuntimeAuthorityLock<u32>) {
    let [mut handle] = lock.handles::<1>();
    let guard = handle.lock();
    consume(handle.guard_free());
    drop(guard);
}
