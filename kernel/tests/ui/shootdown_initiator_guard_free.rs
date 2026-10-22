#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock, ShootdownInitiatorLock};

// S is taken beneath P beneath T: a guard-free P does not witness it.
pub(crate) fn initiate_guard_free(
    lock: &RuntimeAuthorityLock<u32>,
    paging: &PagingLock<u64>,
    initiator_lock: &ShootdownInitiatorLock,
) {
    let [mut handle] = lock.handles::<1>();
    let mut access = paging.guard_free_access(handle.guard_free());
    let held = access.lock();
    initiator_lock.acquire_beneath(&held).release_unused();
}
