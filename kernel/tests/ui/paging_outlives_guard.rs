#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::{PagingLock, RuntimeAuthorityLock};

// P cannot outlive the T guard beneath which it was taken, so no code holds P
// without T (design §11.2.4: T, then P, never P before T).
pub(crate) fn paging_outlives_guard(lock: &RuntimeAuthorityLock<u32>, paging: &PagingLock<u64>) {
    let [mut handle] = lock.handles::<1>();
    let mut guard = handle.lock();
    let (_value, mut access) = guard.with_paging(paging);
    let held = access.lock();
    drop(guard);
    drop(held);
}
