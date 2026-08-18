//! Checked userspace address ranges and page-walk metadata.
//!
//! This module validates only address arithmetic and the locked user/kernel
//! split. Whether pages are present and permit the requested access remains an
//! injected address-space responsibility in `usercopy`.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "DW0-C foundation is consumed by the pending address-space adapter"
    )
)]

/// Exclusive end of the lower canonical half under four-level x86_64 paging.
pub(crate) const X86_64_USER_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

/// Requested access to userspace memory.
///
/// These bits are kernel-internal validation metadata, not ABI mapping flags.
/// In particular, write and execute do not imply read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserAccess(u8);

impl UserAccess {
    pub(crate) const READ: Self = Self(1 << 0);
    pub(crate) const WRITE: Self = Self(1 << 1);
    pub(crate) const EXECUTE: Self = Self(1 << 2);
    pub(crate) const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);

    pub(crate) const fn includes(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// Explicit zero-length pointer policy selected by a syscall implementation.
///
/// No global ABI rule currently chooses among these cases. Requiring a caller
/// to name one prevents a generic helper from silently fossilizing a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmptyAddressRule {
    /// A zero byte length is invalid.
    Reject,
    /// Only address zero is accepted; no alignment check is performed.
    NullOnly,
    /// A nonzero, aligned address in the user range is required.
    UserOnly,
    /// Address zero or an aligned address in the user range is accepted.
    NullOrUser,
    /// The unused address scalar is ignored entirely.
    Ignored,
}

/// Numeric layout used to validate a process user address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserAddressSpace {
    minimum_address: u64,
    end_exclusive: u64,
    page_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserRangeError {
    InvalidAddressSpace,
    InvalidAlignment,
    InvalidStride,
    EmptyRange,
    NullRequired,
    NullAddress,
    OutsideUserAddressSpace,
    AddressOverflow,
    ByteLengthOverflow,
}

impl UserAddressSpace {
    /// Constructs a layout with page zero excluded from the valid user range.
    pub(crate) const fn new(
        minimum_address: u64,
        end_exclusive: u64,
        page_size: u64,
    ) -> Result<Self, UserRangeError> {
        if page_size == 0
            || !page_size.is_power_of_two()
            || minimum_address < page_size
            || minimum_address & (page_size - 1) != 0
            || end_exclusive & (page_size - 1) != 0
            || minimum_address >= end_exclusive
            || end_exclusive > X86_64_USER_END_EXCLUSIVE
        {
            return Err(UserRangeError::InvalidAddressSpace);
        }
        Ok(Self {
            minimum_address,
            end_exclusive,
            page_size,
        })
    }

    /// Constructs the locked four-level x86_64 lower-user-half layout.
    ///
    /// The caller supplies the canonical generated user page size rather than
    /// duplicating it in this architecture-neutral validation module.
    pub(crate) const fn x86_64_four_level(page_size: u64) -> Result<Self, UserRangeError> {
        Self::new(page_size, X86_64_USER_END_EXCLUSIVE, page_size)
    }

    pub(crate) const fn minimum_address(self) -> u64 {
        self.minimum_address
    }

    pub(crate) const fn end_exclusive(self) -> u64 {
        self.end_exclusive
    }

    pub(crate) const fn page_size(self) -> u64 {
        self.page_size
    }
}

/// A numerically checked userspace byte range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserRange {
    address_space: UserAddressSpace,
    start: u64,
    byte_len: u64,
    access: UserAccess,
}

impl UserRange {
    pub(crate) fn new(
        address_space: UserAddressSpace,
        start: u64,
        byte_len: u64,
        alignment: u64,
        access: UserAccess,
        empty_rule: EmptyAddressRule,
    ) -> Result<Self, UserRangeError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(UserRangeError::InvalidAlignment);
        }

        if byte_len == 0 {
            return Self::empty(address_space, start, alignment, access, empty_rule);
        }
        if start == 0 {
            return Err(UserRangeError::NullAddress);
        }
        if start & (alignment - 1) != 0 {
            return Err(UserRangeError::InvalidAlignment);
        }
        let end = match start.checked_add(byte_len) {
            Some(end) => end,
            None => return Err(UserRangeError::AddressOverflow),
        };
        if start < address_space.minimum_address || end > address_space.end_exclusive {
            return Err(UserRangeError::OutsideUserAddressSpace);
        }
        Ok(Self {
            address_space,
            start,
            byte_len,
            access,
        })
    }

    pub(crate) fn from_count_stride(
        address_space: UserAddressSpace,
        start: u64,
        count: u64,
        stride: u64,
        alignment: u64,
        access: UserAccess,
        empty_rule: EmptyAddressRule,
    ) -> Result<Self, UserRangeError> {
        if stride == 0 {
            return Err(UserRangeError::InvalidStride);
        }
        let byte_len = match count.checked_mul(stride) {
            Some(byte_len) => byte_len,
            None => return Err(UserRangeError::ByteLengthOverflow),
        };
        Self::new(
            address_space,
            start,
            byte_len,
            alignment,
            access,
            empty_rule,
        )
    }

    fn empty(
        address_space: UserAddressSpace,
        start: u64,
        alignment: u64,
        access: UserAccess,
        empty_rule: EmptyAddressRule,
    ) -> Result<Self, UserRangeError> {
        match empty_rule {
            EmptyAddressRule::Reject => return Err(UserRangeError::EmptyRange),
            EmptyAddressRule::NullOnly => {
                if start != 0 {
                    return Err(UserRangeError::NullRequired);
                }
            }
            EmptyAddressRule::UserOnly => {
                if start == 0 {
                    return Err(UserRangeError::NullAddress);
                }
                Self::validate_empty_user_address(address_space, start, alignment)?;
            }
            EmptyAddressRule::NullOrUser => {
                if start != 0 {
                    Self::validate_empty_user_address(address_space, start, alignment)?;
                }
            }
            EmptyAddressRule::Ignored => {}
        }
        Ok(Self {
            address_space,
            start,
            byte_len: 0,
            access,
        })
    }

    fn validate_empty_user_address(
        address_space: UserAddressSpace,
        start: u64,
        alignment: u64,
    ) -> Result<(), UserRangeError> {
        if start & (alignment - 1) != 0 {
            return Err(UserRangeError::InvalidAlignment);
        }
        if start < address_space.minimum_address || start >= address_space.end_exclusive {
            return Err(UserRangeError::OutsideUserAddressSpace);
        }
        Ok(())
    }

    pub(crate) const fn start(self) -> u64 {
        self.start
    }

    pub(crate) const fn byte_len(self) -> u64 {
        self.byte_len
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.byte_len == 0
    }

    pub(crate) const fn access(self) -> UserAccess {
        self.access
    }

    pub(crate) const fn end_exclusive(self) -> u64 {
        self.start + self.byte_len
    }

    pub(crate) const fn page_chunks(self) -> UserPageChunks {
        UserPageChunks {
            range: self,
            cursor: self.start,
        }
    }
}

/// The portion of a checked range contained in one user page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserPageChunk {
    page_start: u64,
    address: u64,
    byte_len: u64,
    access: UserAccess,
}

impl UserPageChunk {
    pub(crate) const fn page_start(self) -> u64 {
        self.page_start
    }

    pub(crate) const fn address(self) -> u64 {
        self.address
    }

    pub(crate) const fn byte_len(self) -> u64 {
        self.byte_len
    }

    pub(crate) const fn access(self) -> UserAccess {
        self.access
    }
}

pub(crate) struct UserPageChunks {
    range: UserRange,
    cursor: u64,
}

impl Iterator for UserPageChunks {
    type Item = UserPageChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == self.range.end_exclusive() {
            return None;
        }
        let page_size = self.range.address_space.page_size;
        let page_start = self.cursor & !(page_size - 1);
        let page_end = page_start + page_size;
        let chunk_end = page_end.min(self.range.end_exclusive());
        let chunk = UserPageChunk {
            page_start,
            address: self.cursor,
            byte_len: chunk_end - self.cursor,
            access: self.range.access,
        };
        self.cursor = chunk_end;
        Some(chunk)
    }
}

#[cfg(test)]
mod tests;
