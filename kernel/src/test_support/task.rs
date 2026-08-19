//! DW0-E7 target-only synthetic CPL3 task dispatch.

use crate::arch::x86_64::mm::{ActiveDeepPaging, LiveActivePagingTarget};

use super::{BUILD_GUEST_TEST, BuildGuestTest};

const fn parse_decimal_u64(value: &str) -> u64 {
    let bytes = value.as_bytes();
    assert!(
        !bytes.is_empty(),
        "E7 address environment must not be empty"
    );
    let mut result = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(
            byte >= b'0' && byte <= b'9',
            "E7 address environment must be decimal"
        );
        let digit = (byte - b'0') as u64;
        assert!(
            result <= (u64::MAX - digit) / 10,
            "E7 address environment overflow"
        );
        result = result * 10 + digit;
        index += 1;
    }
    result
}

const E7_USER_ENTRY: u64 = parse_decimal_u64(env!("DEEPWYRM_E7_USER_ENTRY"));
const E7_USER_DATA: u64 = parse_decimal_u64(env!("DEEPWYRM_E7_USER_DATA"));
const E7_USER_STACK_BOTTOM: u64 = parse_decimal_u64(env!("DEEPWYRM_E7_USER_STACK_BOTTOM"));
const E7_USER_STACK_TOP: u64 = parse_decimal_u64(env!("DEEPWYRM_E7_USER_STACK_TOP"));

pub(crate) const fn e7_user_entry() -> u64 {
    E7_USER_ENTRY
}
pub(crate) const fn e7_user_data() -> u64 {
    E7_USER_DATA
}
pub(crate) const fn e7_user_stack_bottom() -> u64 {
    E7_USER_STACK_BOTTOM
}
pub(crate) const fn e7_user_stack_top() -> u64 {
    E7_USER_STACK_TOP
}

pub(crate) fn run_task_guest_test<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'_, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> ! {
    match BUILD_GUEST_TEST {
        BuildGuestTest::TaskSyscallSmoke
        | BuildGuestTest::TaskSyscallSanitize
        | BuildGuestTest::TaskUserException => active.run_task_userspace_test(BUILD_GUEST_TEST),
        _ => super::complete_fail(0xe700_00fe),
    }
}
