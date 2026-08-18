//! Architecture-neutral geometry for bounded DW0-E kernel stack carriers.

pub(crate) const E3_BASE_PAGE_SIZE: u64 = 4096;
pub(crate) const E3_THREAD_STACK_COUNT: usize = 16;
pub(crate) const E3_THREAD_STACK_SIZE: u64 = 65_536;
pub(crate) const E3_THREAD_STACK_GUARD_SIZE: u64 = E3_BASE_PAGE_SIZE;
pub(crate) const E3_THREAD_STACK_ALIGNMENT: u64 = E3_BASE_PAGE_SIZE;
#[allow(
    dead_code,
    reason = "the stride is consumed by target linker-layout validation and host geometry tests"
)]
pub(crate) const E3_THREAD_STACK_STRIDE: u64 = E3_THREAD_STACK_GUARD_SIZE + E3_THREAD_STACK_SIZE;

pub(crate) const E4_PRIVILEGE_ENTRY_STACK_COUNT: usize = 1;
pub(crate) const E4_PRIVILEGE_ENTRY_STACK_SIZE: u64 = 16_384;
pub(crate) const E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE: u64 = E3_BASE_PAGE_SIZE;
pub(crate) const E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT: u64 = E3_BASE_PAGE_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelStackBounds {
    pub(crate) guard_page: u64,
    pub(crate) bottom: u64,
    pub(crate) top: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelStackLayoutError {
    InvalidLayout,
}

impl KernelStackBounds {
    pub(crate) const fn new(
        guard_page: u64,
        bottom: u64,
        top: u64,
    ) -> Result<Self, KernelStackLayoutError> {
        let Some(expected_bottom) = guard_page.checked_add(E3_THREAD_STACK_GUARD_SIZE) else {
            return Err(KernelStackLayoutError::InvalidLayout);
        };
        if guard_page == 0
            || !guard_page.is_multiple_of(E3_THREAD_STACK_ALIGNMENT)
            || bottom != expected_bottom
            || !bottom.is_multiple_of(E3_THREAD_STACK_ALIGNMENT)
            || top <= bottom
            || !top.is_multiple_of(E3_THREAD_STACK_ALIGNMENT)
            || !top.is_multiple_of(16)
        {
            return Err(KernelStackLayoutError::InvalidLayout);
        }
        Ok(Self {
            guard_page,
            bottom,
            top,
        })
    }

    pub(crate) const fn byte_len(self) -> u64 {
        self.top - self.bottom
    }
}

#[cfg(deepwyrm_integrated)]
const fn parse_decimal_u64(value: &str) -> u64 {
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut output = 0_u64;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(
            digit >= b'0' && digit <= b'9',
            "build-generated E3 layout value is not decimal"
        );
        output = output * 10 + (digit - b'0') as u64;
        index += 1;
    }
    output
}

#[cfg(deepwyrm_integrated)]
const _: () = {
    assert!(
        parse_decimal_u64(env!("DEEPWYRM_E3_THREAD_STACK_COUNT")) == E3_THREAD_STACK_COUNT as u64
    );
    assert!(parse_decimal_u64(env!("DEEPWYRM_E3_THREAD_STACK_SIZE")) == E3_THREAD_STACK_SIZE);
    assert!(
        parse_decimal_u64(env!("DEEPWYRM_E3_THREAD_STACK_GUARD_SIZE"))
            == E3_THREAD_STACK_GUARD_SIZE
    );
    assert!(
        parse_decimal_u64(env!("DEEPWYRM_E3_THREAD_STACK_ALIGNMENT")) == E3_THREAD_STACK_ALIGNMENT
    );
    assert!(
        parse_decimal_u64(env!("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_COUNT"))
            == E4_PRIVILEGE_ENTRY_STACK_COUNT as u64
    );
    assert!(
        parse_decimal_u64(env!("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_SIZE"))
            == E4_PRIVILEGE_ENTRY_STACK_SIZE
    );
    assert!(
        parse_decimal_u64(env!("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE"))
            == E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE
    );
    assert!(
        parse_decimal_u64(env!("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT"))
            == E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT
    );
};
