#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::{
    PagingLock, RuntimeAuthorityLock, ShootdownInitiatorLock, ShootdownSettled,
};

pub(crate) struct Settled;
impl ShootdownSettled for Settled {}

fn reclaim(_settled: Settled) {}

// The settlement gates reclamation. Once reclamation has consumed it, S can no
// longer be released: S cannot outlive its settlement.
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
    drop(guard);
    let settled = Settled;
    reclaim(settled);
    let _ = initiator.release(settled);
}
