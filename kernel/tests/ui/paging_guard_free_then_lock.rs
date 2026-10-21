#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock};

// P taken alone for a usercopy keeps the CPU's handle borrowed, so T cannot
// be taken after it (design §11.2.4: never P before T).
pub(crate) fn lock_during_usercopy(lock: &RuntimeAuthorityLock<u32>, paging: &PagingLock<u64>) {
    let [mut handle] = lock.handles::<1>();
    let mut access = paging.guard_free_access(handle.guard_free());
    let held = access.lock();
    *handle.lock() += 1;
    drop(held);
}
