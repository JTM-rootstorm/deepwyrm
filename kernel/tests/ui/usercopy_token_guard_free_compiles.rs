#![no_std]

// Control case (D1 commit 9): P taken guard-free mints the value token that
// the usercopy session's constructor consumes.
include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock};

pub(crate) fn copy_guard_free(lock: &RuntimeAuthorityLock<u32>, paging: &PagingLock<u64>) {
    let [mut handle] = lock.handles::<1>();
    let mut access = paging.guard_free_access(handle.guard_free());
    let mut held = access.lock();
    *held.guard_free_value().into_inner() += 1;
}
