#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock, ShootdownInitiatorLock};

// S is released only by consuming a settlement of the shootdown it covered.
pub(crate) fn initiate(
    lock: &RuntimeAuthorityLock<u32>,
    paging: &PagingLock<u64>,
    initiator_lock: &ShootdownInitiatorLock,
) {
    let [mut handle] = lock.handles::<1>();
    let mut guard = handle.lock();
    let (_, mut access) = guard.with_paging(paging);
    let held = access.lock();
    let initiator = initiator_lock.acquire_beneath(&held);
    drop(held);
    initiator.release(5_u32);
}
