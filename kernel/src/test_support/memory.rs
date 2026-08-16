//! Target-only DW0-C memory-foundation guest-test dispatch.
//!
//! The architecture session mints and consumes the bound live-root authority;
//! this module can choose a fixed scenario but cannot name a root, mapper, role
//! registry, or address-space identity independently.

use crate::arch::x86_64::mm::{ActiveDeepPaging, LiveActivePagingTarget};

use super::BUILD_GUEST_TEST;

pub(crate) fn run_memory_guest_test<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'_, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> ! {
    active.run_memory_foundation_test(BUILD_GUEST_TEST)
}
