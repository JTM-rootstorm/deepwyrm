//! All-or-nothing copies across a checked userspace address boundary.
//!
//! Raw page-table access and fault recovery remain outside this module. An
//! injected implementation pins the mapping, preflights every page, and then
//! supplies an infallible exact-copy primitive for recoverable address faults.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "DW0-C foundation is consumed by the pending address-space adapter"
    )
)]

use super::user_range::{UserAccess, UserPageChunk, UserRange};

/// Acquires a stable view of a user range for preflight and exact copy.
///
/// `pin` must prevent unmap/protect/remap from invalidating the returned guard
/// until it is dropped. It may fail without modifying user or kernel buffers.
pub(crate) trait UserPageAccess {
    type Error;
    type Pinned<'a>: PinnedUserPages<Error = Self::Error>
    where
        Self: 'a;

    fn pin(&mut self, range: UserRange) -> Result<Self::Pinned<'_>, Self::Error>;
}

/// Acquires up to three disjoint mapping-stable user ranges in one transaction.
///
/// Channel receive needs byte, handle-info, and result outputs to remain pinned
/// across one queue commit. This separate trait keeps ordinary single-range
/// callers simple while giving authority-sensitive adapters an all-ranges-first
/// preflight primitive.
pub(crate) trait UserPageBatchAccess: UserPageAccess {
    type PinnedBatch<'a>: PinnedUserBatchPages<Error = Self::Error>
    where
        Self: 'a;

    fn pin_batch(
        &mut self,
        ranges: [Option<UserRange>; 3],
    ) -> Result<Self::PinnedBatch<'_>, Self::Error>;
}

/// Acquires a writable userspace output whose mapping-stability authority can
/// outlive the short Rust borrow used to preflight it. Blocking syscalls use
/// this surface so no borrow-shaped usercopy guard crosses a context switch.
///
/// After successful preflight, commit/discard are infallible kernel invariants:
/// a recoverable userspace fault must have been detected before the owner was
/// detached. Implementations fail stopped if the owned token later drifts.
pub(crate) trait OwnedUserOutputAccess: UserPageAccess {
    type OwnedOutput;

    fn preflight_owned_output(
        &mut self,
        range: UserRange,
    ) -> Result<Self::OwnedOutput, Self::Error>;

    fn commit_owned_output(&mut self, output: Self::OwnedOutput, source: &[u8]);

    fn discard_owned_output(&mut self, output: Self::OwnedOutput);
}

pub(crate) trait PinnedUserBatchPages {
    type Error;

    fn preflight(&mut self, index: usize, chunk: UserPageChunk) -> Result<(), Self::Error>;

    fn write_exact(&mut self, index: usize, range: UserRange, source: &[u8]);
}

#[cfg(any(test, deepwyrm_integrated))]
mod pin_tracker {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::UserRange;
    use crate::memory::address_region::AddressSpaceKey;

    static NEXT_USER_PIN_DOMAIN: AtomicU64 = AtomicU64::new(1);

    fn mint_domain() -> u64 {
        NEXT_USER_PIN_DOMAIN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1).filter(|next| *next != 0)
            })
            .expect("user-pin tracker domain space exhausted")
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum UserPinError {
        Capacity,
        Conflict,
        InvalidMutationRange,
        ForeignToken,
        StaleToken,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PinnedRange {
        address_space: AddressSpaceKey,
        start: u64,
        end_exclusive: u64,
    }

    impl PinnedRange {
        const fn from_user_range(address_space: AddressSpaceKey, range: UserRange) -> Option<Self> {
            if range.is_empty() {
                None
            } else {
                Some(Self {
                    address_space,
                    start: range.start(),
                    end_exclusive: range.end_exclusive(),
                })
            }
        }

        fn overlaps(self, other: Self) -> bool {
            self.address_space == other.address_space
                && self.start < other.end_exclusive
                && other.start < self.end_exclusive
        }
    }

    #[derive(Clone, Copy)]
    struct PinSlot {
        generation: u32,
        range: Option<PinnedRange>,
    }

    const EMPTY_PIN_SLOT: PinSlot = PinSlot {
        generation: 0,
        range: None,
    };

    struct UserPinState<const CAPACITY: usize> {
        pins: [PinSlot; CAPACITY],
        mutation: Option<PinnedRange>,
    }

    /// Detached mapping-stability ownership suitable for blocked operations.
    ///
    /// Tokens are tracker-domain and slot-generation checked. They carry no
    /// Rust borrow, so the owner must explicitly validate and release them
    /// through the originating tracker before teardown.
    #[must_use = "owned user mapping pins must be released through their originating tracker"]
    #[derive(Debug, Eq, PartialEq)]
    pub(crate) struct UserRangePinToken {
        domain: u64,
        slot: u16,
        generation: u32,
        range: PinnedRange,
    }

    impl UserRangePinToken {
        const fn address_space(&self) -> AddressSpaceKey {
            self.range.address_space
        }

        #[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
        pub(crate) const fn start(&self) -> u64 {
            self.range.start
        }

        #[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
        pub(crate) const fn end_exclusive(&self) -> u64 {
            self.range.end_exclusive
        }
    }

    /// Range-scoped user-mapping stability authority.
    ///
    /// Pins and mapping mutations reserve non-overlapping ranges through one short
    /// spin-locked linearization point. The lock is never held across usercopy or
    /// page-table publication; move-only permits keep the reservation live instead.
    pub(crate) struct UserPinTracker<const CAPACITY: usize> {
        domain: u64,
        state: crate::sync::SpinMutex<UserPinState<CAPACITY>>,
    }

    impl<const CAPACITY: usize> UserPinTracker<CAPACITY> {
        pub(crate) fn new() -> Self {
            Self {
                domain: mint_domain(),
                state: crate::sync::SpinMutex::new(UserPinState {
                    pins: [EMPTY_PIN_SLOT; CAPACITY],
                    mutation: None,
                }),
            }
        }

        fn reserve_token(
            &self,
            address_space: AddressSpaceKey,
            range: UserRange,
        ) -> Result<UserRangePinToken, UserPinError> {
            let range = PinnedRange::from_user_range(address_space, range)
                .ok_or(UserPinError::InvalidMutationRange)?;
            let mut state = self.state.lock();
            if state
                .mutation
                .is_some_and(|mutation| mutation.overlaps(range))
            {
                return Err(UserPinError::Conflict);
            }
            for (index, slot) in state.pins.iter_mut().enumerate() {
                if slot.range.is_some() {
                    continue;
                }
                let Some(generation) = slot.generation.checked_add(1).filter(|value| *value != 0)
                else {
                    continue;
                };
                let slot_index = u16::try_from(index).map_err(|_| UserPinError::Capacity)?;
                slot.generation = generation;
                slot.range = Some(range);
                return Ok(UserRangePinToken {
                    domain: self.domain,
                    slot: slot_index,
                    generation,
                    range,
                });
            }
            Err(UserPinError::Capacity)
        }

        pub(crate) fn pin(
            &self,
            address_space: AddressSpaceKey,
            range: UserRange,
        ) -> Result<UserRangePin<'_, CAPACITY>, UserPinError> {
            Ok(UserRangePin {
                tracker: self,
                token: Some(self.reserve_token(address_space, range)?),
            })
        }

        pub(crate) fn pin_owned(
            &self,
            address_space: AddressSpaceKey,
            range: UserRange,
        ) -> Result<UserRangePinToken, UserPinError> {
            self.reserve_token(address_space, range)
        }

        pub(crate) fn validate_owned(
            &self,
            address_space: AddressSpaceKey,
            token: &UserRangePinToken,
        ) -> Result<(u64, u64), UserPinError> {
            if token.domain != self.domain || token.address_space() != address_space {
                return Err(UserPinError::ForeignToken);
            }
            let state = self.state.lock();
            let slot = state
                .pins
                .get(usize::from(token.slot))
                .ok_or(UserPinError::StaleToken)?;
            if slot.generation != token.generation || slot.range != Some(token.range) {
                return Err(UserPinError::StaleToken);
            }
            Ok((token.range.start, token.range.end_exclusive))
        }

        pub(crate) fn release_owned(
            &self,
            address_space: AddressSpaceKey,
            token: UserRangePinToken,
        ) -> Result<(), UserPinError> {
            if token.domain != self.domain || token.address_space() != address_space {
                return Err(UserPinError::ForeignToken);
            }
            let mut state = self.state.lock();
            let slot = state
                .pins
                .get_mut(usize::from(token.slot))
                .ok_or(UserPinError::StaleToken)?;
            if slot.generation != token.generation || slot.range != Some(token.range) {
                return Err(UserPinError::StaleToken);
            }
            slot.range = None;
            Ok(())
        }

        pub(crate) fn begin_mutation(
            &self,
            address_space: AddressSpaceKey,
            start: u64,
            byte_len: u64,
        ) -> Result<UserMutationPermit<'_, CAPACITY>, UserPinError> {
            if byte_len == 0 {
                return Err(UserPinError::InvalidMutationRange);
            }
            let end_exclusive = start
                .checked_add(byte_len)
                .ok_or(UserPinError::InvalidMutationRange)?;
            let mutation = PinnedRange {
                address_space,
                start,
                end_exclusive,
            };
            let mut state = self.state.lock();
            if state.mutation.is_some()
                || state
                    .pins
                    .iter()
                    .filter_map(|slot| slot.range)
                    .any(|pin| pin.overlaps(mutation))
            {
                return Err(UserPinError::Conflict);
            }
            state.mutation = Some(mutation);
            Ok(UserMutationPermit {
                tracker: self,
                range: mutation,
            })
        }
    }

    #[must_use = "user mapping pins must remain live through exact copy or deliberate discard"]
    pub(crate) struct UserRangePin<'a, const CAPACITY: usize> {
        tracker: &'a UserPinTracker<CAPACITY>,
        token: Option<UserRangePinToken>,
    }

    impl<const CAPACITY: usize> UserRangePin<'_, CAPACITY> {
        pub(crate) fn into_owned(mut self) -> UserRangePinToken {
            self.token
                .take()
                .expect("borrowed user pin retains its owned token")
        }
    }

    impl<const CAPACITY: usize> Drop for UserRangePin<'_, CAPACITY> {
        fn drop(&mut self) {
            let Some(token) = self.token.take() else {
                return;
            };
            self.tracker
                .release_owned(token.address_space(), token)
                .expect("borrowed user pin tracker slot drift");
        }
    }

    #[must_use = "mapping mutation permits must span the complete page-table publication"]
    pub(crate) struct UserMutationPermit<'a, const CAPACITY: usize> {
        tracker: &'a UserPinTracker<CAPACITY>,
        range: PinnedRange,
    }

    impl<const CAPACITY: usize> Drop for UserMutationPermit<'_, CAPACITY> {
        fn drop(&mut self) {
            let mut state = self.tracker.state.lock();
            assert_eq!(
                state
                    .mutation
                    .map(|range| (range.start, range.end_exclusive)),
                Some((self.range.start, self.range.end_exclusive)),
                "user mutation tracker drift"
            );
            state.mutation = None;
        }
    }
}

#[cfg(test)]
pub(crate) use pin_tracker::{UserPinError, UserPinTracker};
#[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
pub(crate) use pin_tracker::{UserPinError, UserPinTracker, UserRangePin, UserRangePinToken};

/// Mapping-stable page access held across full preflight and exact copy.
pub(crate) trait PinnedUserPages {
    type Error;

    /// Checks presence and the exact requested access for one page chunk.
    /// Failure must not modify either side of a prospective copy.
    fn preflight(&mut self, chunk: UserPageChunk) -> Result<(), Self::Error>;

    /// Copies a fully preflighted readable range into kernel staging memory.
    ///
    /// After successful full-range preflight, recoverable user-address faults
    /// must be impossible. Hardware-fatal failures are outside status recovery,
    /// so this primitive intentionally has no fallible mid-copy result.
    fn read_exact(&mut self, range: UserRange, destination: &mut [u8]);

    /// Copies kernel bytes into a fully preflighted writable user range.
    ///
    /// As with `read_exact`, a recoverable failure must occur during preflight,
    /// before the first destination byte is modified.
    fn write_exact(&mut self, range: UserRange, source: &[u8]);
}

#[must_use = "preflighted output must be committed or deliberately discarded before its mapping pin is released"]
pub(crate) struct PinnedUserOutput<P: PinnedUserPages> {
    pinned: P,
    range: UserRange,
    byte_len: usize,
}

impl<P: PinnedUserPages> PinnedUserOutput<P> {
    /// Commits bytes after successful full-range preflight. Length mismatch is
    /// an internal kernel bug rather than a recoverable userspace failure.
    pub(crate) fn commit(mut self, source: &[u8]) {
        assert_eq!(
            source.len(),
            self.byte_len,
            "preflighted output length drift"
        );
        self.pinned.write_exact(self.range, source);
    }
}

#[must_use = "preflighted output batch must be committed or deliberately discarded before its mapping pins are released"]
pub(crate) struct PinnedUserOutputs<P: PinnedUserBatchPages> {
    pinned: P,
    ranges: [Option<UserRange>; 3],
    byte_lens: [usize; 3],
}

impl<P: PinnedUserBatchPages> PinnedUserOutputs<P> {
    pub(crate) fn commit(mut self, sources: [Option<&[u8]>; 3]) {
        for (index, source) in sources.into_iter().enumerate() {
            match (self.ranges[index], source) {
                (None, None) => {}
                (Some(range), Some(source)) => {
                    assert_eq!(
                        source.len(),
                        self.byte_lens[index],
                        "preflighted output-batch length drift"
                    );
                    if !range.is_empty() {
                        self.pinned.write_exact(index, range, source);
                    }
                }
                _ => panic!("preflighted output-batch shape drift"),
            }
        }
    }

    pub(crate) fn commit_prefixes(mut self, sources: [Option<&[u8]>; 3]) {
        for (index, source) in sources.into_iter().enumerate() {
            match (self.ranges[index], source) {
                (None, None) => {}
                (Some(range), Some(source)) => {
                    assert!(
                        source.len() <= self.byte_lens[index],
                        "preflighted output-batch prefix exceeds pinned capacity"
                    );
                    if !source.is_empty() {
                        let prefix = range
                            .prefix(source.len())
                            .expect("preflighted output-batch prefix remains in range");
                        self.pinned.write_exact(index, prefix, source);
                    }
                }
                _ => panic!("preflighted output-batch shape drift"),
            }
        }
    }
}

/// Pins and preflights one complete userspace output before kernel business
/// mutation. Once this returns, [`PinnedUserOutput::commit`] has no recoverable
/// BAD_ADDRESS path.
pub(crate) fn preflight_user_output<'a, A: UserPageAccess>(
    access: &'a mut A,
    range: UserRange,
    byte_len: usize,
) -> Result<PinnedUserOutput<A::Pinned<'a>>, UserCopyError<A::Error>> {
    if !range.access().includes(UserAccess::WRITE) {
        return Err(UserCopyError::AccessIntent);
    }
    let range_len =
        usize::try_from(range.byte_len()).map_err(|_| UserCopyError::LengthDoesNotFitHost)?;
    if range_len != byte_len {
        return Err(UserCopyError::LengthMismatch);
    }
    let mut pinned = access.pin(range).map_err(UserCopyError::Access)?;
    preflight_all(&mut pinned, range)?;
    Ok(PinnedUserOutput {
        pinned,
        range,
        byte_len,
    })
}

/// Pins every present output range before any output is committed. Empty ranges
/// are retained for pointer-policy validation but require no physical pin.
pub(crate) fn preflight_user_outputs<'a, A: UserPageBatchAccess>(
    access: &'a mut A,
    outputs: [Option<(UserRange, usize)>; 3],
) -> Result<PinnedUserOutputs<A::PinnedBatch<'a>>, UserCopyError<A::Error>> {
    let mut ranges = [None; 3];
    let mut byte_lens = [0_usize; 3];
    for (index, output) in outputs.into_iter().enumerate() {
        let Some((range, byte_len)) = output else {
            continue;
        };
        if !range.access().includes(UserAccess::WRITE) {
            return Err(UserCopyError::AccessIntent);
        }
        let range_len =
            usize::try_from(range.byte_len()).map_err(|_| UserCopyError::LengthDoesNotFitHost)?;
        if range_len != byte_len {
            return Err(UserCopyError::LengthMismatch);
        }
        ranges[index] = Some(range);
        byte_lens[index] = byte_len;
    }
    let mut pinned = access.pin_batch(ranges).map_err(UserCopyError::Access)?;
    for (index, range) in ranges.into_iter().enumerate() {
        let Some(range) = range else {
            continue;
        };
        for chunk in range.page_chunks() {
            pinned
                .preflight(index, chunk)
                .map_err(UserCopyError::Access)?;
        }
    }
    Ok(PinnedUserOutputs {
        pinned,
        ranges,
        byte_lens,
    })
}

/// Takes a fully preflighted user snapshot directly into caller-owned staging.
/// Staging contents are unspecified on failure, so no second kernel scratch
/// buffer is needed before the caller decides whether to commit business state.
pub(crate) fn snapshot_from_user<A: UserPageAccess>(
    access: &mut A,
    range: UserRange,
    staging: &mut [u8],
) -> Result<(), UserCopyError<A::Error>> {
    if !range.access().includes(UserAccess::READ) {
        return Err(UserCopyError::AccessIntent);
    }
    let byte_len =
        usize::try_from(range.byte_len()).map_err(|_| UserCopyError::LengthDoesNotFitHost)?;
    if staging.len() != byte_len {
        return Err(UserCopyError::LengthMismatch);
    }
    if range.is_empty() {
        return Ok(());
    }
    let mut pinned = access.pin(range).map_err(UserCopyError::Access)?;
    preflight_all(&mut pinned, range)?;
    pinned.read_exact(range, staging);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserCopyError<E> {
    AccessIntent,
    LengthDoesNotFitHost,
    LengthMismatch,
    ScratchTooSmall,
    Access(E),
}

/// Copies from user memory without modifying `destination` on any recoverable
/// error. The caller-owned scratch buffer avoids allocation in this boundary.
///
/// User threads may still mutate source bytes concurrently. The successful
/// result is a staged byte snapshot suitable for subsequent kernel parsing,
/// not an atomicity guarantee over user writes.
pub(crate) fn copy_from_user<A: UserPageAccess>(
    access: &mut A,
    range: UserRange,
    destination: &mut [u8],
    scratch: &mut [u8],
) -> Result<(), UserCopyError<A::Error>> {
    if !range.access().includes(UserAccess::READ) {
        return Err(UserCopyError::AccessIntent);
    }
    let byte_len =
        usize::try_from(range.byte_len()).map_err(|_| UserCopyError::LengthDoesNotFitHost)?;
    if destination.len() != byte_len {
        return Err(UserCopyError::LengthMismatch);
    }
    if scratch.len() < byte_len {
        return Err(UserCopyError::ScratchTooSmall);
    }
    if range.is_empty() {
        return Ok(());
    }

    let mut pinned = access.pin(range).map_err(UserCopyError::Access)?;
    preflight_all(&mut pinned, range)?;
    let staging = &mut scratch[..byte_len];
    pinned.read_exact(range, staging);
    destination.copy_from_slice(staging);
    Ok(())
}

/// Copies to user memory only after every destination page has passed pinned
/// write preflight. A conforming backend performs no recoverably fallible work
/// after the first user byte is modified.
pub(crate) fn copy_to_user<A: UserPageAccess>(
    access: &mut A,
    range: UserRange,
    source: &[u8],
) -> Result<(), UserCopyError<A::Error>> {
    if !range.access().includes(UserAccess::WRITE) {
        return Err(UserCopyError::AccessIntent);
    }
    let byte_len =
        usize::try_from(range.byte_len()).map_err(|_| UserCopyError::LengthDoesNotFitHost)?;
    if source.len() != byte_len {
        return Err(UserCopyError::LengthMismatch);
    }
    if range.is_empty() {
        return Ok(());
    }

    let mut pinned = access.pin(range).map_err(UserCopyError::Access)?;
    preflight_all(&mut pinned, range)?;
    pinned.write_exact(range, source);
    Ok(())
}

fn preflight_all<P: PinnedUserPages>(
    pinned: &mut P,
    range: UserRange,
) -> Result<(), UserCopyError<P::Error>> {
    for chunk in range.page_chunks() {
        pinned.preflight(chunk).map_err(UserCopyError::Access)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::address_region::AddressSpaceKey;
    use crate::memory::user_range::{EmptyAddressRule, UserAddressSpace, UserRangeError};

    const PAGE_SIZE: u64 = 4096;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        Pin,
        Page(u64),
    }

    struct FakeAccess {
        user: [u8; 16],
        fail_pin: bool,
        fail_page: Option<u64>,
        preflight_count: usize,
        read_count: usize,
        write_count: usize,
    }

    impl FakeAccess {
        fn new(user: [u8; 16]) -> Self {
            Self {
                user,
                fail_pin: false,
                fail_page: None,
                preflight_count: 0,
                read_count: 0,
                write_count: 0,
            }
        }
    }

    struct FakePinned<'a> {
        access: &'a mut FakeAccess,
    }

    impl UserPageAccess for FakeAccess {
        type Error = Fault;
        type Pinned<'a> = FakePinned<'a>;

        fn pin(&mut self, _range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
            if self.fail_pin {
                return Err(Fault::Pin);
            }
            Ok(FakePinned { access: self })
        }
    }

    impl PinnedUserPages for FakePinned<'_> {
        type Error = Fault;

        fn preflight(&mut self, chunk: UserPageChunk) -> Result<(), Self::Error> {
            self.access.preflight_count += 1;
            if self.access.fail_page == Some(chunk.page_start()) {
                return Err(Fault::Page(chunk.page_start()));
            }
            Ok(())
        }

        fn read_exact(&mut self, _range: UserRange, destination: &mut [u8]) {
            self.access.read_count += 1;
            destination.copy_from_slice(&self.access.user[..destination.len()]);
        }

        fn write_exact(&mut self, _range: UserRange, source: &[u8]) {
            self.access.write_count += 1;
            self.access.user[..source.len()].copy_from_slice(source);
        }
    }

    fn range(access: UserAccess) -> Result<UserRange, UserRangeError> {
        let space = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap();
        UserRange::new(
            space,
            PAGE_SIZE * 2 - 4,
            8,
            1,
            access,
            EmptyAddressRule::Reject,
        )
    }

    #[test]
    fn cross_page_permission_failure_does_not_mutate_kernel_destination() {
        let mut backend = FakeAccess::new(*b"abcdefghijklmnop");
        backend.fail_page = Some(PAGE_SIZE * 2);
        let mut destination = [0xa5; 8];
        let before = destination;
        let mut scratch = [0x5a; 8];

        assert_eq!(
            copy_from_user(
                &mut backend,
                range(UserAccess::READ).unwrap(),
                &mut destination,
                &mut scratch,
            ),
            Err(UserCopyError::Access(Fault::Page(PAGE_SIZE * 2)))
        );
        assert_eq!(destination, before);
        assert_eq!(backend.preflight_count, 2);
        assert_eq!(backend.read_count, 0);
    }

    #[test]
    fn preflighted_output_is_exclusive_and_commit_is_exact() {
        let original = *b"abcdefghijklmnop";
        let mut backend = FakeAccess::new(original);
        {
            let output =
                preflight_user_output(&mut backend, range(UserAccess::WRITE).unwrap(), 8).unwrap();
            // The live output owns the mutable backend borrow here; safe Rust
            // cannot inspect or mutate the mapping until the pin is consumed.
            output.commit(b"12345678");
        }
        assert_eq!(&backend.user[..8], b"12345678");
        assert_eq!(backend.preflight_count, 2);
        assert_eq!(backend.write_count, 1);
    }

    #[test]
    fn dropping_preflighted_output_without_commit_changes_nothing() {
        let original = *b"abcdefghijklmnop";
        let mut backend = FakeAccess::new(original);
        {
            let output =
                preflight_user_output(&mut backend, range(UserAccess::WRITE).unwrap(), 8).unwrap();
            drop(output);
        }
        assert_eq!(backend.user, original);
        assert_eq!(backend.preflight_count, 2);
        assert_eq!(backend.write_count, 0);
    }

    #[test]
    fn preflighted_output_failure_never_returns_a_commit_authority() {
        let original = *b"abcdefghijklmnop";
        let mut backend = FakeAccess::new(original);
        backend.fail_page = Some(PAGE_SIZE * 2);
        assert!(
            preflight_user_output(&mut backend, range(UserAccess::WRITE).unwrap(), 8,).is_err()
        );
        assert_eq!(backend.user, original);
        assert_eq!(backend.write_count, 0);
    }

    #[test]
    fn cross_page_permission_failure_never_commits_to_user() {
        let original = *b"abcdefghijklmnop";
        let mut backend = FakeAccess::new(original);
        backend.fail_page = Some(PAGE_SIZE * 2);

        assert_eq!(
            copy_to_user(&mut backend, range(UserAccess::WRITE).unwrap(), b"12345678",),
            Err(UserCopyError::Access(Fault::Page(PAGE_SIZE * 2)))
        );
        assert_eq!(backend.user, original);
        assert_eq!(backend.preflight_count, 2);
        assert_eq!(backend.write_count, 0);
    }

    #[test]
    fn successful_exact_copies_commit_once_after_full_preflight() {
        let mut backend = FakeAccess::new(*b"abcdefghijklmnop");
        let mut destination = [0; 8];
        let mut scratch = [0; 8];
        copy_from_user(
            &mut backend,
            range(UserAccess::READ).unwrap(),
            &mut destination,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(&destination, b"abcdefgh");
        assert_eq!(backend.preflight_count, 2);
        assert_eq!(backend.read_count, 1);

        backend.preflight_count = 0;
        copy_to_user(&mut backend, range(UserAccess::WRITE).unwrap(), b"12345678").unwrap();
        assert_eq!(&backend.user[..8], b"12345678");
        assert_eq!(backend.preflight_count, 2);
        assert_eq!(backend.write_count, 1);
    }

    #[test]
    fn validates_lengths_scratch_and_access_before_pinning() {
        let mut backend = FakeAccess::new(*b"abcdefghijklmnop");
        let mut short_destination = [0; 7];
        let mut scratch = [0; 8];
        assert_eq!(
            copy_from_user(
                &mut backend,
                range(UserAccess::READ).unwrap(),
                &mut short_destination,
                &mut scratch,
            ),
            Err(UserCopyError::LengthMismatch)
        );

        let mut destination = [0; 8];
        let mut short_scratch = [0; 7];
        assert_eq!(
            copy_from_user(
                &mut backend,
                range(UserAccess::READ).unwrap(),
                &mut destination,
                &mut short_scratch,
            ),
            Err(UserCopyError::ScratchTooSmall)
        );
        assert_eq!(
            copy_to_user(
                &mut backend,
                range(UserAccess::EXECUTE).unwrap(),
                b"12345678",
            ),
            Err(UserCopyError::AccessIntent)
        );
        assert_eq!(backend.preflight_count, 0);
        assert_eq!(backend.read_count, 0);
        assert_eq!(backend.write_count, 0);
    }

    fn range_at(start: u64, byte_len: u64, access: UserAccess) -> UserRange {
        let space = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap();
        UserRange::new(space, start, byte_len, 1, access, EmptyAddressRule::Reject).unwrap()
    }

    fn scope(raw: u64) -> AddressSpaceKey {
        AddressSpaceKey::for_test(1, raw)
    }

    #[test]
    fn range_tracker_blocks_only_overlapping_mutations() {
        let tracker = UserPinTracker::<2>::new();
        let pin = tracker
            .pin(
                scope(1),
                range_at(PAGE_SIZE * 4 + 32, 64, UserAccess::WRITE),
            )
            .unwrap();
        assert!(matches!(
            tracker.begin_mutation(scope(1), PAGE_SIZE * 4, PAGE_SIZE),
            Err(UserPinError::Conflict)
        ));
        let disjoint = tracker
            .begin_mutation(scope(1), PAGE_SIZE * 8, PAGE_SIZE)
            .unwrap();
        drop(disjoint);
        drop(pin);
        let overlap_after_drop = tracker
            .begin_mutation(scope(1), PAGE_SIZE * 4, PAGE_SIZE)
            .unwrap();
        drop(overlap_after_drop);
    }

    #[test]
    fn detached_atomic_word_pin_blocks_intersecting_mapping_mutation() {
        let tracker = UserPinTracker::<1>::new();
        let word = UserRange::new(
            UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap(),
            PAGE_SIZE * 6 + 4,
            4,
            4,
            UserAccess::READ,
            EmptyAddressRule::Reject,
        )
        .unwrap();
        let pin = tracker.pin_owned(scope(1), word).unwrap();
        assert!(matches!(
            tracker.begin_mutation(scope(1), PAGE_SIZE * 6, PAGE_SIZE),
            Err(UserPinError::Conflict)
        ));
        tracker.release_owned(scope(1), pin).unwrap();
        let mutation = tracker
            .begin_mutation(scope(1), PAGE_SIZE * 6, PAGE_SIZE)
            .unwrap();
        drop(mutation);
    }

    #[test]
    fn active_mutation_rejects_new_overlapping_pin() {
        let tracker = UserPinTracker::<2>::new();
        let mutation = tracker
            .begin_mutation(scope(1), PAGE_SIZE * 4, PAGE_SIZE * 2)
            .unwrap();
        assert!(matches!(
            tracker.pin(scope(1), range_at(PAGE_SIZE * 5, 8, UserAccess::READ)),
            Err(UserPinError::Conflict)
        ));
        assert!(
            tracker
                .pin(scope(1), range_at(PAGE_SIZE * 9, 8, UserAccess::READ))
                .is_ok()
        );
        drop(mutation);
    }

    #[test]
    fn same_virtual_range_is_independent_between_address_spaces() {
        let tracker = UserPinTracker::<2>::new();
        let range = range_at(PAGE_SIZE * 4, PAGE_SIZE, UserAccess::WRITE);
        let parent = tracker.pin_owned(scope(1), range).unwrap();
        let child_mutation = tracker
            .begin_mutation(scope(2), PAGE_SIZE * 4, PAGE_SIZE)
            .unwrap();
        drop(child_mutation);
        assert!(matches!(
            tracker.begin_mutation(scope(1), PAGE_SIZE * 4, PAGE_SIZE),
            Err(UserPinError::Conflict)
        ));
        tracker.release_owned(scope(1), parent).unwrap();
    }

    #[test]
    fn owned_token_scope_is_authenticated_for_validation_and_release() {
        let tracker = UserPinTracker::<1>::new();
        let range = range_at(PAGE_SIZE * 5, 64, UserAccess::WRITE);
        let token = tracker.pin_owned(scope(1), range).unwrap();
        assert_eq!(
            tracker.validate_owned(scope(2), &token),
            Err(UserPinError::ForeignToken)
        );
        assert_eq!(
            tracker.release_owned(scope(2), token),
            Err(UserPinError::ForeignToken)
        );
    }

    #[test]
    fn empty_ignored_range_never_touches_backend() {
        let space = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap();
        let empty = UserRange::new(
            space,
            u64::MAX,
            0,
            8,
            UserAccess::READ_WRITE,
            EmptyAddressRule::Ignored,
        )
        .unwrap();
        let mut backend = FakeAccess::new(*b"abcdefghijklmnop");
        copy_from_user(&mut backend, empty, &mut [], &mut []).unwrap();
        copy_to_user(&mut backend, empty, &[]).unwrap();
        assert_eq!(backend.preflight_count, 0);
        assert_eq!(backend.read_count, 0);
        assert_eq!(backend.write_count, 0);
    }

    #[test]
    fn owned_pin_tokens_are_domain_and_generation_exact() {
        let first = UserPinTracker::<1>::new();
        let second = UserPinTracker::<1>::new();
        let range = range_at(PAGE_SIZE * 6, 64, UserAccess::WRITE);
        let token = first.pin_owned(scope(1), range).unwrap();
        assert_eq!(
            first.validate_owned(scope(1), &token),
            Ok((range.start(), range.end_exclusive()))
        );
        assert_eq!(
            second.validate_owned(scope(1), &token),
            Err(UserPinError::ForeignToken)
        );
        assert!(matches!(
            first.begin_mutation(scope(1), PAGE_SIZE * 6, PAGE_SIZE),
            Err(UserPinError::Conflict)
        ));
        first.release_owned(scope(1), token).unwrap();
        let replacement = first.pin_owned(scope(1), range).unwrap();
        assert_eq!(
            first.validate_owned(scope(1), &replacement),
            Ok((range.start(), range.end_exclusive()))
        );
        first.release_owned(scope(1), replacement).unwrap();
    }

    #[test]
    fn borrowed_pin_can_detach_into_owned_token_without_unpinning() {
        let tracker = UserPinTracker::<1>::new();
        let range = range_at(PAGE_SIZE * 7, 32, UserAccess::READ);
        let borrowed = tracker.pin(scope(1), range).unwrap();
        let token = borrowed.into_owned();
        assert!(matches!(
            tracker.begin_mutation(scope(1), PAGE_SIZE * 7, PAGE_SIZE),
            Err(UserPinError::Conflict)
        ));
        tracker.release_owned(scope(1), token).unwrap();
        let permit = tracker
            .begin_mutation(scope(1), PAGE_SIZE * 7, PAGE_SIZE)
            .unwrap();
        drop(permit);
    }
}
