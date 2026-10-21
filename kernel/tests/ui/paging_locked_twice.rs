#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock};

// One CPU cannot take P twice: the second acquisition would spin forever on
// its own guard.
pub(crate) fn paging_locked_twice(lock: &RuntimeAuthorityLock<u32>, paging: &PagingLock<u64>) {
    let [mut handle] = lock.handles::<1>();
    let mut guard = handle.lock();
    let (_value, mut access) = guard.with_paging(paging);
    let first = access.lock();
    let second = access.lock();
    drop(first);
    drop(second);
}
