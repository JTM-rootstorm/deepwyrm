#![no_std]

// Control case: P is taken beneath a held T guard and released before it.
include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock};

pub(crate) fn paging_beneath_guard(lock: &RuntimeAuthorityLock<u32>, paging: &PagingLock<u64>) {
    let [mut handle] = lock.handles::<1>();
    let mut guard = handle.lock();
    let (value, mut access) = guard.with_paging(paging);
    *value += 1;
    *access.lock() += 1;
    drop(guard);
}
