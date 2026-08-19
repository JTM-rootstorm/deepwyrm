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
use crate::sync::SpinMutex;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserPinError {
    Capacity,
    Conflict,
    InvalidMutationRange,
}

#[derive(Clone, Copy)]
struct PinnedRange {
    start: u64,
    end_exclusive: u64,
}

impl PinnedRange {
    const fn from_user_range(range: UserRange) -> Option<Self> {
        if range.is_empty() {
            None
        } else {
            Some(Self {
                start: range.start(),
                end_exclusive: range.end_exclusive(),
            })
        }
    }

    const fn overlaps(self, other: Self) -> bool {
        self.start < other.end_exclusive && other.start < self.end_exclusive
    }
}

struct UserPinState<const CAPACITY: usize> {
    pins: [Option<PinnedRange>; CAPACITY],
    mutation: Option<PinnedRange>,
}

/// Range-scoped user-mapping stability authority.
///
/// Pins and mapping mutations reserve non-overlapping ranges through one short
/// spin-locked linearization point. The lock is never held across usercopy or
/// page-table publication; move-only permits keep the reservation live instead.
pub(crate) struct UserPinTracker<const CAPACITY: usize> {
    state: SpinMutex<UserPinState<CAPACITY>>,
}

impl<const CAPACITY: usize> UserPinTracker<CAPACITY> {
    pub(crate) const fn new() -> Self {
        Self {
            state: SpinMutex::new(UserPinState {
                pins: [None; CAPACITY],
                mutation: None,
            }),
        }
    }

    pub(crate) fn pin(&self, range: UserRange) -> Result<UserRangePin<'_, CAPACITY>, UserPinError> {
        let range =
            PinnedRange::from_user_range(range).ok_or(UserPinError::InvalidMutationRange)?;
        let mut state = self.state.lock();
        if state
            .mutation
            .is_some_and(|mutation| mutation.overlaps(range))
        {
            return Err(UserPinError::Conflict);
        }
        let slot = state
            .pins
            .iter()
            .position(Option::is_none)
            .ok_or(UserPinError::Capacity)?;
        state.pins[slot] = Some(range);
        Ok(UserRangePin {
            tracker: self,
            slot,
            range,
        })
    }

    pub(crate) fn begin_mutation(
        &self,
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
            start,
            end_exclusive,
        };
        let mut state = self.state.lock();
        if state.mutation.is_some()
            || state
                .pins
                .iter()
                .flatten()
                .copied()
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
    slot: usize,
    range: PinnedRange,
}

impl<const CAPACITY: usize> Drop for UserRangePin<'_, CAPACITY> {
    fn drop(&mut self) {
        let mut state = self.tracker.state.lock();
        assert_eq!(
            state.pins[self.slot].map(|range| (range.start, range.end_exclusive)),
            Some((self.range.start, self.range.end_exclusive)),
            "user pin tracker slot drift"
        );
        state.pins[self.slot] = None;
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

    #[test]
    fn range_tracker_blocks_only_overlapping_mutations() {
        let tracker = UserPinTracker::<2>::new();
        let pin = tracker
            .pin(range_at(PAGE_SIZE * 4 + 32, 64, UserAccess::WRITE))
            .unwrap();
        assert!(matches!(
            tracker.begin_mutation(PAGE_SIZE * 4, PAGE_SIZE),
            Err(UserPinError::Conflict)
        ));
        let disjoint = tracker.begin_mutation(PAGE_SIZE * 8, PAGE_SIZE).unwrap();
        drop(disjoint);
        drop(pin);
        let overlap_after_drop = tracker.begin_mutation(PAGE_SIZE * 4, PAGE_SIZE).unwrap();
        drop(overlap_after_drop);
    }

    #[test]
    fn active_mutation_rejects_new_overlapping_pin() {
        let tracker = UserPinTracker::<2>::new();
        let mutation = tracker
            .begin_mutation(PAGE_SIZE * 4, PAGE_SIZE * 2)
            .unwrap();
        assert!(matches!(
            tracker.pin(range_at(PAGE_SIZE * 5, 8, UserAccess::READ)),
            Err(UserPinError::Conflict)
        ));
        assert!(
            tracker
                .pin(range_at(PAGE_SIZE * 9, 8, UserAccess::READ))
                .is_ok()
        );
        drop(mutation);
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
}
