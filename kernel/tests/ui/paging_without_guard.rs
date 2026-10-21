#![no_std]

include!("runtime_authority_stub.rs");

use runtime_authority::PagingLock;

// P has no way in except beneath a T guard.
pub(crate) fn paging_without_guard(paging: &PagingLock<u64>) {
    drop(paging.acquire());
}
