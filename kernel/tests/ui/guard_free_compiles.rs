#![no_std]

// Control case: a token can be minted once the guard is gone.
include!("runtime_authority_stub.rs");

use runtime_authority::RuntimeAuthorityLock;

fn consume(_token: GuardFree<'_>) {}

pub(crate) fn lock_then_prove(lock: &RuntimeAuthorityLock<u32>) {
    let [mut handle] = lock.handles::<1>();
    {
        let mut guard = handle.lock();
        *guard += 1;
    }
    consume(handle.guard_free());
}
