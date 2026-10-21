#![no_std]

// Control case (D1 option B1): S is taken beneath P beneath T, outlives both
// guards, and is released on a settlement.
include!("runtime_authority_stub.rs");

use runtime_authority::{
    PagingLock, RuntimeAuthorityLock, ShootdownInitiatorLock, ShootdownSettled,
};

pub(crate) struct Settled;
impl ShootdownSettled for Settled {}

pub(crate) fn initiate(
    lock: &RuntimeAuthorityLock<u32>,
    paging: &PagingLock<u64>,
    initiator_lock: &ShootdownInitiatorLock,
) {
    let [mut handle] = lock.handles::<1>();
    let initiator = {
        let mut guard = handle.lock();
        let (_, mut access) = guard.with_paging(paging);
        let held = access.lock();
        initiator_lock.acquire_beneath(&held)
    };
    let Settled = initiator.release(Settled);
}
