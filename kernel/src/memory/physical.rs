//! Allocation-free physical-range and frame-allocation primitives.
//!
//! This module intentionally has no virtual-address or page-table dependency.
//! Architecture code supplies the physical-address limit, while higher layers
//! provide the ranges that must remain reserved during the boot transition.

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use core::mem::MaybeUninit;
use deepwyrm_abi::DW_BOOT_BASE_PAGE_SIZE;

/// The only frame size supported during DW0-C bootstrap allocation.
pub const BASE_PAGE_SIZE: u64 = DW_BOOT_BASE_PAGE_SIZE as u64;

const EMPTY_RANGE: PageRange = PageRange { start: 0, end: 0 };

/// A checked non-empty physical byte range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    physical_start: u64,
    byte_len: u64,
}

impl PhysicalRange {
    /// Creates a non-empty range after checking its exclusive end.
    pub fn new(physical_start: u64, byte_len: u64) -> Result<Self, PhysicalRangeError> {
        if byte_len == 0 {
            return Err(PhysicalRangeError::EmptyRange);
        }
        physical_start
            .checked_add(byte_len)
            .ok_or(PhysicalRangeError::AddressOverflow)?;
        Ok(Self {
            physical_start,
            byte_len,
        })
    }

    /// Physical address of the first byte.
    pub const fn physical_start(self) -> u64 {
        self.physical_start
    }

    /// Exact byte length, before page covering.
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }

    /// Checked exclusive end address.
    pub fn end(self) -> Result<u64, PhysicalRangeError> {
        self.physical_start
            .checked_add(self.byte_len)
            .ok_or(PhysicalRangeError::AddressOverflow)
    }

    /// Whether `physical_address` is within this half-open range.
    pub fn contains(self, physical_address: u64) -> bool {
        self.end()
            .is_ok_and(|end| self.physical_start <= physical_address && physical_address < end)
    }
}

/// Failure while validating a physical byte range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalRangeError {
    EmptyRange,
    AddressOverflow,
    InvalidAddressLimit,
}

/// Architecture-supplied exclusive physical-address limit.
///
/// This deliberately has no CPUID probing: architecture bring-up supplies the
/// reviewed fact, keeping portable allocator logic independent of a direct map
/// or architecture register access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalAddressLimit {
    exclusive: u64,
}

impl PhysicalAddressLimit {
    /// Validates a power-of-two exclusive physical limit no wider than the
    /// x86_64 four-level PTE address field. Architecture code must derive this
    /// value from one trusted MAXPHYADDR fact and pass the same token to the
    /// sanitizer, allocator, and page-table owner.
    pub fn new(exclusive: u64) -> Result<Self, PhysicalRangeError> {
        if exclusive < BASE_PAGE_SIZE || !exclusive.is_power_of_two() || exclusive > (1_u64 << 52) {
            return Err(PhysicalRangeError::InvalidAddressLimit);
        }
        Ok(Self { exclusive })
    }

    /// Constructs the shared exclusive limit from a validated physical-address
    /// width. This is the production architecture integration path.
    pub fn from_address_bits(bits: u8) -> Result<Self, PhysicalRangeError> {
        if !(12..=52).contains(&bits) {
            return Err(PhysicalRangeError::InvalidAddressLimit);
        }
        Self::new(1_u64 << bits)
    }

    /// First invalid physical address.
    pub const fn exclusive(self) -> u64 {
        self.exclusive
    }

    fn contains_page_range(self, range: PageRange) -> bool {
        range.end <= self.exclusive
    }
}

/// A page-aligned half-open physical range, private to physical-memory code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PageRange {
    pub(super) start: u64,
    pub(super) end: u64,
}

impl PageRange {
    pub(super) const fn empty() -> Self {
        EMPTY_RANGE
    }

    pub(super) fn from_page_count(
        physical_start: u64,
        page_count: u64,
        limit: PhysicalAddressLimit,
    ) -> Result<Self, PhysicalMemoryError> {
        if page_count == 0 || !physical_start.is_multiple_of(BASE_PAGE_SIZE) {
            return Err(PhysicalMemoryError::InvalidPageRange);
        }
        let byte_len = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(PhysicalMemoryError::AddressOverflow)?;
        let end = physical_start
            .checked_add(byte_len)
            .ok_or(PhysicalMemoryError::AddressOverflow)?;
        let range = Self {
            start: physical_start,
            end,
        };
        if !limit.contains_page_range(range) {
            return Err(PhysicalMemoryError::OutsidePhysicalLimit);
        }
        Ok(range)
    }

    pub(super) fn cover(
        range: PhysicalRange,
        limit: PhysicalAddressLimit,
    ) -> Result<Self, PhysicalMemoryError> {
        let start = range.physical_start & !(BASE_PAGE_SIZE - 1);
        let end = range
            .end()
            .map_err(|_| PhysicalMemoryError::AddressOverflow)?;
        let rounded_end = end
            .checked_add(BASE_PAGE_SIZE - 1)
            .ok_or(PhysicalMemoryError::AddressOverflow)?
            & !(BASE_PAGE_SIZE - 1);
        let page_range = Self {
            start,
            end: rounded_end,
        };
        if page_range.start == page_range.end {
            return Err(PhysicalMemoryError::InvalidPageRange);
        }
        if !limit.contains_page_range(page_range) {
            return Err(PhysicalMemoryError::OutsidePhysicalLimit);
        }
        Ok(page_range)
    }

    pub(super) const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    pub(super) const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub(super) const fn page_count(self) -> u64 {
        (self.end - self.start) / BASE_PAGE_SIZE
    }
}

/// A single allocated base-page frame.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PhysicalFrame {
    physical_start: u64,
}

#[cfg(test)]
impl PhysicalFrame {
    /// Physical address of this page-aligned base frame.
    pub(super) const fn physical_start(self) -> u64 {
        self.physical_start
    }
}

/// Errors shared by sanitization, reservation, and frame allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalMemoryError {
    InvalidPageRange,
    AddressOverflow,
    OutsidePhysicalLimit,
    CapacityExceeded,
    NoFramesAvailable,
    InvalidFrame,
    DoubleFree,
}

/// A simple first-fit allocator over sanitized, already-reserved physical
/// ranges. `RANGE_CAPACITY` is caller-selected so production bootstrap storage
/// remains fixed while host tests can exercise fragmentation explicitly.
pub(super) struct PhysicalFrameAllocator<const RANGE_CAPACITY: usize> {
    initial: [PageRange; RANGE_CAPACITY],
    initial_len: usize,
    free: [PageRange; RANGE_CAPACITY],
    free_len: usize,
    limit: PhysicalAddressLimit,
}

impl<const RANGE_CAPACITY: usize> PhysicalFrameAllocator<RANGE_CAPACITY> {
    /// Initializes the allocator from candidate ranges after subtracting every
    /// supplied reservation and the mandatory page-zero reservation.
    pub(super) fn from_candidates<I>(
        candidates: &[PageRange],
        limit: PhysicalAddressLimit,
        reservations: I,
    ) -> Result<Self, PhysicalMemoryError>
    where
        I: IntoIterator<Item = PhysicalRange>,
    {
        let mut allocator = Self {
            initial: [EMPTY_RANGE; RANGE_CAPACITY],
            initial_len: 0,
            free: [EMPTY_RANGE; RANGE_CAPACITY],
            free_len: 0,
            limit,
        };
        for candidate in candidates {
            allocator.validate_candidate(*candidate)?;
            allocator.insert_free(*candidate)?;
        }

        // Physical page zero is never allocatable, independently of firmware
        // classification or the caller's reservation list.
        allocator.subtract(PageRange {
            start: 0,
            end: BASE_PAGE_SIZE,
        })?;
        for reservation in reservations {
            allocator.subtract(PageRange::cover(reservation, limit)?)?;
        }

        allocator.initial[..allocator.free_len]
            .copy_from_slice(&allocator.free[..allocator.free_len]);
        allocator.initial_len = allocator.free_len;
        Ok(allocator)
    }

    /// Initializes an allocator directly in unique static bootstrap storage.
    ///
    /// # Safety
    ///
    /// `slot` must be uninitialized, uniquely owned storage that outlives all
    /// allocations issued by the returned allocator. A failure leaves the
    /// slot terminal and it must not be reused.
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    #[allow(
        unsafe_code,
        reason = "the BSP constructs the fixed-capacity allocator field in place to bound its bootstrap stack"
    )]
    pub(super) unsafe fn from_candidates_in<'a, I>(
        slot: &'a mut MaybeUninit<Self>,
        candidates: &[PageRange],
        limit: PhysicalAddressLimit,
        reservations: I,
    ) -> Result<&'a mut Self, PhysicalMemoryError>
    where
        I: IntoIterator<Item = PhysicalRange>,
    {
        let destination = slot.as_mut_ptr();
        unsafe {
            let initial = core::ptr::addr_of_mut!((*destination).initial).cast::<PageRange>();
            let free = core::ptr::addr_of_mut!((*destination).free).cast::<PageRange>();
            for index in 0..RANGE_CAPACITY {
                initial.add(index).write(EMPTY_RANGE);
                free.add(index).write(EMPTY_RANGE);
            }
            core::ptr::addr_of_mut!((*destination).initial_len).write(0);
            core::ptr::addr_of_mut!((*destination).free_len).write(0);
            core::ptr::addr_of_mut!((*destination).limit).write(limit);
            let allocator = &mut *destination;
            for candidate in candidates {
                allocator.validate_candidate(*candidate)?;
                allocator.insert_free(*candidate)?;
            }
            allocator.subtract(PageRange {
                start: 0,
                end: BASE_PAGE_SIZE,
            })?;
            for reservation in reservations {
                allocator.subtract(PageRange::cover(reservation, limit)?)?;
            }
            allocator.initial[..allocator.free_len]
                .copy_from_slice(&allocator.free[..allocator.free_len]);
            allocator.initial_len = allocator.free_len;
            Ok(allocator)
        }
    }

    /// Allocates the lowest available base frame.
    #[cfg(test)]
    pub(super) fn allocate_frame(&mut self) -> Result<PhysicalFrame, PhysicalMemoryError> {
        let range = self.allocate_run(1)?;
        Ok(PhysicalFrame {
            physical_start: range.start,
        })
    }

    /// Returns one frame if, and only if, it was previously allocated from this
    /// allocator. Reserved, foreign, and already-free frames are rejected.
    #[cfg(test)]
    pub(super) fn free_frame(&mut self, frame: PhysicalFrame) -> Result<(), PhysicalMemoryError> {
        if !frame.physical_start.is_multiple_of(BASE_PAGE_SIZE)
            || frame.physical_start >= self.limit.exclusive()
        {
            return Err(PhysicalMemoryError::InvalidFrame);
        }
        let end = frame
            .physical_start
            .checked_add(BASE_PAGE_SIZE)
            .ok_or(PhysicalMemoryError::InvalidFrame)?;
        let range = PageRange {
            start: frame.physical_start,
            end,
        };
        self.free_run(range)
    }

    /// Allocates the lowest available contiguous run with exactly
    /// `page_count` base pages.
    pub(super) fn allocate_run(
        &mut self,
        page_count: u64,
    ) -> Result<PageRange, PhysicalMemoryError> {
        if page_count == 0 {
            return Err(PhysicalMemoryError::InvalidPageRange);
        }
        let byte_len = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(PhysicalMemoryError::AddressOverflow)?;
        let index = self.free[..self.free_len]
            .iter()
            .position(|range| range.end - range.start >= byte_len)
            .ok_or(PhysicalMemoryError::NoFramesAvailable)?;
        let start = self.free[index].start;
        let end = start
            .checked_add(byte_len)
            .ok_or(PhysicalMemoryError::AddressOverflow)?;
        self.free[index].start = end;
        if self.free[index].start == self.free[index].end {
            self.remove_free(index);
        }
        Ok(PageRange { start, end })
    }

    /// Returns one previously allocated contiguous run. Callers above this
    /// mechanism must prove that no live role still owns the run.
    pub(super) fn free_run(&mut self, range: PageRange) -> Result<(), PhysicalMemoryError> {
        self.validate_candidate(range)?;
        if !self.initial[..self.initial_len]
            .iter()
            .any(|initial| initial.contains(range))
        {
            return Err(PhysicalMemoryError::InvalidFrame);
        }
        if self.free[..self.free_len]
            .iter()
            .any(|free| free.overlaps(range))
        {
            return Err(PhysicalMemoryError::DoubleFree);
        }
        self.insert_free(range)
    }

    /// Number of currently available frames.
    pub(super) fn available_frames(&self) -> u64 {
        self.free[..self.free_len]
            .iter()
            .fold(0_u64, |total, range| total + range.page_count())
    }

    pub(super) const fn physical_limit(&self) -> PhysicalAddressLimit {
        self.limit
    }

    pub(super) fn initial_frames(&self) -> u64 {
        self.initial[..self.initial_len]
            .iter()
            .fold(0_u64, |total, range| total + range.page_count())
    }

    pub(super) fn contains_initial(&self, range: PageRange) -> bool {
        self.initial[..self.initial_len]
            .iter()
            .any(|initial| initial.contains(range))
    }

    pub(super) fn overlaps_initial(&self, range: PageRange) -> bool {
        self.initial[..self.initial_len]
            .iter()
            .any(|initial| initial.overlaps(range))
    }

    pub(super) fn overlaps_free(&self, range: PageRange) -> bool {
        self.free[..self.free_len]
            .iter()
            .any(|free| free.overlaps(range))
    }

    fn subtract(&mut self, reservation: PageRange) -> Result<(), PhysicalMemoryError> {
        let mut index = 0;
        while index < self.free_len {
            let free = self.free[index];
            if !free.overlaps(reservation) {
                index += 1;
                continue;
            }
            if reservation.start <= free.start && free.end <= reservation.end {
                self.remove_free(index);
                continue;
            }
            if free.start < reservation.start && reservation.end < free.end {
                if self.free_len == RANGE_CAPACITY {
                    return Err(PhysicalMemoryError::CapacityExceeded);
                }
                self.shift_right(index + 1);
                self.free[index] = PageRange {
                    start: free.start,
                    end: reservation.start,
                };
                self.free[index + 1] = PageRange {
                    start: reservation.end,
                    end: free.end,
                };
                self.free_len += 1;
                index += 2;
                continue;
            }
            if reservation.start <= free.start {
                self.free[index].start = reservation.end;
            } else {
                self.free[index].end = reservation.start;
            }
            index += 1;
        }
        Ok(())
    }

    fn insert_free(&mut self, range: PageRange) -> Result<(), PhysicalMemoryError> {
        self.validate_candidate(range)?;
        if range.start == range.end {
            return Ok(());
        }
        let mut insertion = 0;
        while insertion < self.free_len && self.free[insertion].start < range.start {
            insertion += 1;
        }
        if insertion > 0 && self.free[insertion - 1].end > range.start {
            return Err(PhysicalMemoryError::DoubleFree);
        }
        if insertion < self.free_len && range.end > self.free[insertion].start {
            return Err(PhysicalMemoryError::DoubleFree);
        }
        if insertion > 0 && self.free[insertion - 1].end == range.start {
            self.free[insertion - 1].end = range.end;
            if insertion < self.free_len
                && self.free[insertion - 1].end == self.free[insertion].start
            {
                let right = self.free[insertion];
                self.free[insertion - 1].end = right.end;
                self.remove_free(insertion);
            }
            return Ok(());
        }
        if insertion < self.free_len && range.end == self.free[insertion].start {
            self.free[insertion].start = range.start;
            return Ok(());
        }
        if self.free_len == RANGE_CAPACITY {
            return Err(PhysicalMemoryError::CapacityExceeded);
        }
        self.shift_right(insertion);
        self.free[insertion] = range;
        self.free_len += 1;
        Ok(())
    }

    fn validate_candidate(&self, range: PageRange) -> Result<(), PhysicalMemoryError> {
        if range.start >= range.end
            || !range.start.is_multiple_of(BASE_PAGE_SIZE)
            || !range.end.is_multiple_of(BASE_PAGE_SIZE)
        {
            return Err(PhysicalMemoryError::InvalidPageRange);
        }
        if !self.limit.contains_page_range(range) {
            return Err(PhysicalMemoryError::OutsidePhysicalLimit);
        }
        Ok(())
    }

    fn shift_right(&mut self, index: usize) {
        for position in (index..self.free_len).rev() {
            self.free[position + 1] = self.free[position];
        }
    }

    fn remove_free(&mut self, index: usize) {
        for position in index..self.free_len - 1 {
            self.free[position] = self.free[position + 1];
        }
        self.free_len -= 1;
        self.free[self.free_len] = EMPTY_RANGE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: PhysicalAddressLimit = PhysicalAddressLimit {
        exclusive: 0x20_000,
    };

    fn range(start: u64, len: u64) -> PhysicalRange {
        PhysicalRange::new(start, len).unwrap()
    }

    #[test]
    fn page_cover_checks_overflow_and_limit() {
        assert_eq!(
            PageRange::cover(range(0x1fff, 2), LIMIT),
            Ok(PageRange {
                start: 0x1000,
                end: 0x3000
            })
        );
        assert_eq!(
            PageRange::cover(range(0x1f_fff, 2), LIMIT),
            Err(PhysicalMemoryError::OutsidePhysicalLimit)
        );
        assert_eq!(
            PhysicalRange::new(u64::MAX, 1),
            Err(PhysicalRangeError::AddressOverflow)
        );
        assert_eq!(
            PhysicalAddressLimit::from_address_bits(40),
            Ok(PhysicalAddressLimit::new(1_u64 << 40).unwrap())
        );
        assert_eq!(
            PhysicalAddressLimit::from_address_bits(53),
            Err(PhysicalRangeError::InvalidAddressLimit)
        );
        assert_eq!(
            PhysicalAddressLimit::new(0x3000),
            Err(PhysicalRangeError::InvalidAddressLimit)
        );
    }

    #[test]
    fn allocator_reserves_page_zero_and_rejects_invalid_frees() {
        let candidates = [PageRange {
            start: 0,
            end: 0x10_000,
        }];
        let mut allocator = PhysicalFrameAllocator::<4>::from_candidates(
            &candidates,
            LIMIT,
            [range(0x3000, 0x1000)],
        )
        .unwrap();
        assert_eq!(allocator.available_frames(), 14);

        let frame = allocator.allocate_frame().unwrap();
        assert_eq!(frame.physical_start(), 0x1000);
        assert_eq!(allocator.free_frame(frame), Ok(()));
        assert_eq!(
            allocator.free_frame(frame),
            Err(PhysicalMemoryError::DoubleFree)
        );
        assert_eq!(
            allocator.free_frame(PhysicalFrame {
                physical_start: 0x3000
            }),
            Err(PhysicalMemoryError::InvalidFrame)
        );
    }

    #[test]
    fn allocator_repeatedly_reports_oom_after_exhaustion() {
        let candidates = [PageRange {
            start: 0x1000,
            end: 0x2000,
        }];
        let mut allocator =
            PhysicalFrameAllocator::<1>::from_candidates(&candidates, LIMIT, []).unwrap();
        assert_eq!(allocator.allocate_frame().unwrap().physical_start(), 0x1000);
        assert_eq!(
            allocator.allocate_frame(),
            Err(PhysicalMemoryError::NoFramesAvailable)
        );
        assert_eq!(
            allocator.allocate_frame(),
            Err(PhysicalMemoryError::NoFramesAvailable)
        );
    }

    #[test]
    fn allocator_rejects_invalid_candidate_ranges() {
        for candidate in [
            PageRange {
                start: 0x3000,
                end: 0x2000,
            },
            PageRange {
                start: 1,
                end: 0x1000,
            },
            PageRange {
                start: 0x1000,
                end: 0x1001,
            },
        ] {
            assert!(matches!(
                PhysicalFrameAllocator::<1>::from_candidates(&[candidate], LIMIT, []),
                Err(PhysicalMemoryError::InvalidPageRange)
            ));
        }
        let at_limit = [PageRange {
            start: LIMIT.exclusive(),
            end: LIMIT.exclusive(),
        }];
        assert!(matches!(
            PhysicalFrameAllocator::<1>::from_candidates(&at_limit, LIMIT, []),
            Err(PhysicalMemoryError::InvalidPageRange)
        ));
        let outside = [PageRange {
            start: LIMIT.exclusive() - BASE_PAGE_SIZE,
            end: LIMIT.exclusive() + BASE_PAGE_SIZE,
        }];
        assert!(matches!(
            PhysicalFrameAllocator::<1>::from_candidates(&outside, LIMIT, []),
            Err(PhysicalMemoryError::OutsidePhysicalLimit)
        ));
    }
}
