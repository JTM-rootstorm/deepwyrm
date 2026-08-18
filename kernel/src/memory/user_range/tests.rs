use super::*;

const PAGE_SIZE: u64 = 4096;

fn space() -> UserAddressSpace {
    UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap()
}

fn range(start: u64, byte_len: u64) -> Result<UserRange, UserRangeError> {
    UserRange::new(
        space(),
        start,
        byte_len,
        1,
        UserAccess::READ,
        EmptyAddressRule::Reject,
    )
}

#[test]
fn rejects_page_zero_kernel_half_and_canonical_hole_edges() {
    assert_eq!(space().minimum_address(), PAGE_SIZE);
    assert_eq!(space().end_exclusive(), X86_64_USER_END_EXCLUSIVE);
    assert_eq!(space().page_size(), PAGE_SIZE);
    assert_eq!(
        UserAddressSpace::new(PAGE_SIZE, X86_64_USER_END_EXCLUSIVE + PAGE_SIZE, PAGE_SIZE,),
        Err(UserRangeError::InvalidAddressSpace)
    );
    assert_eq!(range(0, 1), Err(UserRangeError::NullAddress));
    assert_eq!(
        range(PAGE_SIZE - 1, 1),
        Err(UserRangeError::OutsideUserAddressSpace)
    );

    let last_user_byte = X86_64_USER_END_EXCLUSIVE - 1;
    assert_eq!(range(last_user_byte, 1).unwrap().start(), last_user_byte);
    assert_eq!(
        range(last_user_byte, 1).unwrap().end_exclusive(),
        X86_64_USER_END_EXCLUSIVE
    );
    assert_eq!(
        range(last_user_byte, 2),
        Err(UserRangeError::OutsideUserAddressSpace)
    );
    assert_eq!(
        range(X86_64_USER_END_EXCLUSIVE, 1),
        Err(UserRangeError::OutsideUserAddressSpace)
    );
    assert_eq!(
        range(0x0000_8000_0000_0001, 1),
        Err(UserRangeError::OutsideUserAddressSpace)
    );
    assert_eq!(
        range(0xffff_8000_0000_0000, 1),
        Err(UserRangeError::OutsideUserAddressSpace)
    );
    assert_eq!(range(u64::MAX, 2), Err(UserRangeError::AddressOverflow));
}

#[test]
fn zero_length_rules_are_explicit() {
    let make = |address, rule| UserRange::new(space(), address, 0, 8, UserAccess::WRITE, rule);
    assert_eq!(
        make(0, EmptyAddressRule::Reject),
        Err(UserRangeError::EmptyRange)
    );
    assert!(make(0, EmptyAddressRule::NullOnly).is_ok());
    assert_eq!(
        make(PAGE_SIZE, EmptyAddressRule::NullOnly),
        Err(UserRangeError::NullRequired)
    );
    assert_eq!(
        make(0, EmptyAddressRule::UserOnly),
        Err(UserRangeError::NullAddress)
    );
    assert!(make(PAGE_SIZE, EmptyAddressRule::UserOnly).is_ok());
    assert!(make(0, EmptyAddressRule::NullOrUser).is_ok());
    assert!(make(PAGE_SIZE, EmptyAddressRule::NullOrUser).is_ok());
    assert!(make(u64::MAX, EmptyAddressRule::Ignored).is_ok());
    assert_eq!(
        make(X86_64_USER_END_EXCLUSIVE, EmptyAddressRule::NullOrUser),
        Err(UserRangeError::OutsideUserAddressSpace)
    );
}

#[test]
fn checks_alignment_and_count_times_stride() {
    assert_eq!(
        UserRange::new(
            space(),
            PAGE_SIZE + 1,
            8,
            8,
            UserAccess::READ,
            EmptyAddressRule::Reject,
        ),
        Err(UserRangeError::InvalidAlignment)
    );
    assert_eq!(
        UserRange::from_count_stride(
            space(),
            PAGE_SIZE,
            1,
            0,
            1,
            UserAccess::READ,
            EmptyAddressRule::Reject,
        ),
        Err(UserRangeError::InvalidStride)
    );
    assert_eq!(
        UserRange::from_count_stride(
            space(),
            PAGE_SIZE,
            u64::MAX,
            2,
            1,
            UserAccess::READ,
            EmptyAddressRule::Reject,
        ),
        Err(UserRangeError::ByteLengthOverflow)
    );
}

#[test]
fn page_walk_splits_unaligned_cross_page_range() {
    let range = range(PAGE_SIZE + PAGE_SIZE - 3, 8).unwrap();
    let mut chunks = range.page_chunks();
    let first = chunks.next().unwrap();
    assert_eq!(first.page_start(), PAGE_SIZE);
    assert_eq!(first.address(), PAGE_SIZE * 2 - 3);
    assert_eq!(first.byte_len(), 3);
    let second = chunks.next().unwrap();
    assert_eq!(second.page_start(), PAGE_SIZE * 2);
    assert_eq!(second.address(), PAGE_SIZE * 2);
    assert_eq!(second.byte_len(), 5);
    assert_eq!(second.access(), UserAccess::READ);
    assert_eq!(chunks.next(), None);
}

#[test]
fn access_intents_do_not_imply_read() {
    assert!(!UserAccess::WRITE.includes(UserAccess::READ));
    assert!(!UserAccess::EXECUTE.includes(UserAccess::READ));
    assert!(UserAccess::READ_WRITE.includes(UserAccess::READ));
    assert!(UserAccess::READ_WRITE.includes(UserAccess::WRITE));
}
