#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock};

// P taken beneath a T guard mints no usercopy token: no usercopy under T.
pub(crate) fn copy_under_runtime(lock: &RuntimeAuthorityLock<u32>, paging: &PagingLock<u64>) {
    let [mut handle] = lock.handles::<1>();
    let mut guard = handle.lock();
    let (_, mut access) = guard.with_paging(paging);
    let mut held = access.lock();
    *held.guard_free_value().into_inner() += 1;
}
