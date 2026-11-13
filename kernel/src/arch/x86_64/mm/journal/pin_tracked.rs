//! A page-table target that excludes user pins from what it rewrites (E5,
//! DW2 M4). Every write batch with invalidations reserves exactly their
//! span against overlapping user pins first. A batched publication may hold
//! one span across several batches instead, so it can always be undone;
//! each batch must then lie inside it.
//!
//! The live kernel wraps its scratch target in this; host tests wrap a
//! fake, so the pin rules are tested without the live target.

use super::{AtomicPageTableTarget, FrameAddress, JournalWrite, VirtualPage, target_seal};
use crate::memory::address_region::AddressSpaceKey;
use crate::memory::physical::BASE_PAGE_SIZE;
use crate::memory::usercopy::{UserMutationPermit, UserPinError, UserPinTracker};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinTrackedError<E> {
    Target(E),
    Pin(UserPinError),
}

pub(crate) struct PinTrackedTarget<'a, T, const PINS: usize> {
    pub(crate) scratch: T,
    pub(crate) pins: &'a UserPinTracker<PINS>,
    pub(crate) address_space: AddressSpaceKey,
    /// The span a batched publication holds against pins, as
    /// `[start, end)` with its permit.
    pub(crate) span: Option<(u64, u64, UserMutationPermit<'a, PINS>)>,
}

impl<T: AtomicPageTableTarget, const PINS: usize> target_seal::Sealed
    for PinTrackedTarget<'_, T, PINS>
{
}

#[allow(
    unsafe_code,
    reason = "the wrapper preserves the inner target's atomicity while adding range reservation before every write batch"
)]
// SAFETY: every write goes to the inner target's own atomic `apply`; this
// wrapper only reserves the batch's span against user pins before it.
unsafe impl<T: AtomicPageTableTarget, const PINS: usize> AtomicPageTableTarget
    for PinTrackedTarget<'_, T, PINS>
{
    type Error = PinTrackedError<T::Error>;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.scratch
            .read_entry(table, index)
            .map_err(PinTrackedError::Target)
    }

    fn apply(
        &mut self,
        writes: &[JournalWrite],
        invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error> {
        let permit = if invalidations.is_empty() {
            None
        } else if let Some((span_start, span_end, _)) = &self.span {
            // The held span already excludes pins; the batch must lie in it.
            if invalidations
                .iter()
                .any(|page| page.address() < *span_start || page.address() >= *span_end)
            {
                return Err(PinTrackedError::Pin(UserPinError::InvalidMutationRange));
            }
            None
        } else {
            let mut start = u64::MAX;
            let mut end = 0_u64;
            for page in invalidations {
                start = start.min(page.address());
                end = end.max(
                    page.address()
                        .checked_add(BASE_PAGE_SIZE)
                        .ok_or(PinTrackedError::Pin(UserPinError::InvalidMutationRange))?,
                );
            }
            Some(
                self.pins
                    .begin_mutation(self.address_space, start, end - start)
                    .map_err(PinTrackedError::Pin)?,
            )
        };
        let result = self
            .scratch
            .apply(writes, invalidations)
            .map_err(PinTrackedError::Target);
        drop(permit);
        result
    }

    fn zero_table_frame(&mut self, frame: FrameAddress) -> Result<(), Self::Error> {
        self.scratch
            .zero_table_frame(frame)
            .map_err(PinTrackedError::Target)
    }

    fn begin_mutation_span(&mut self, start: u64, byte_len: u64) -> Result<(), Self::Error> {
        if self.span.is_some() {
            return Err(PinTrackedError::Pin(UserPinError::Conflict));
        }
        let end = start
            .checked_add(byte_len)
            .ok_or(PinTrackedError::Pin(UserPinError::InvalidMutationRange))?;
        let permit = self
            .pins
            .begin_mutation(self.address_space, start, byte_len)
            .map_err(PinTrackedError::Pin)?;
        self.span = Some((start, end, permit));
        Ok(())
    }

    fn end_mutation_span(&mut self) {
        self.span = None;
    }
}
