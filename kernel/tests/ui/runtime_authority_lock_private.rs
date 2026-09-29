#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::RuntimeAuthorityLock;

// Nothing locks the lock itself: only a CPU's handle can, so a guard always
// borrows that handle.
pub(crate) fn lock_directly(lock: &RuntimeAuthorityLock<u32>) {
    drop(lock.lock());
}
