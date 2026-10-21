#![no_std]

// Control case: a guard-free usercopy takes P alone, and T only after it.
include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock};

pub(crate) fn usercopy_then_lock(lock: &RuntimeAuthorityLock<u32>, paging: &PagingLock<u64>) {
    let [mut handle] = lock.handles::<1>();
    {
        let mut access = paging.guard_free_access(handle.guard_free());
        *access.lock() += 1;
    }
    *handle.lock() += 1;
}
