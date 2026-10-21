#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::ShootdownInitiatorLock;

// S has no way in except beneath a witness that P is held.
pub(crate) fn initiate(initiator_lock: &ShootdownInitiatorLock) {
    initiator_lock.acquire_beneath(&()).release_unused();
}
