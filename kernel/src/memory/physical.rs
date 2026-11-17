//! Allocation-free physical-range and frame-allocation primitives.
//!
//! This module intentionally has no virtual-address or page-table dependency.
//! Architecture code supplies the physical-address limit, while higher layers
//! provide the ranges that must remain reserved during the boot transition.

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use core::mem::MaybeUninit;
use deepwyrm_abi::DW_BOOT_BASE_PAGE_SIZE;

#[path = "physical/buddy.rs"]
mod buddy;
use buddy::Buddy;

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

/// The most free ranges a [`PhysicalFrameAllocator`] can ever hold, given at
/// most `candidates` disjoint candidate ranges, at most `reservations`
/// reservations, and at most `live_runs` runs allocated at any one time.
/// A `RANGE_CAPACITY` of at least this makes `CapacityExceeded`
/// unreachable, so a free never fails (DW2 large-memory plan, M1).
///
/// Construction: each reservation removes a piece of the free ranges, and
/// splits a range in two only when it lies strictly inside it, so it adds at
/// most one range. Page zero cannot split anything: a range containing it
/// starts at zero and is only trimmed. So construction ends with at most
/// `candidates + reservations` ranges, which become the initial ranges.
///
/// Afterwards an allocation takes the start of a free range and never adds
/// one, except an aligned boot-phase allocation
/// ([`PhysicalFrameAllocator::allocate_largest_aligned`]), which may take the
/// middle of a free range and split it in two: it adds one range and one live
/// run. A free returns exactly one allocated run, and every run lies inside
/// one initial range. Inside an initial range holding `k` live runs, the free
/// pages form at most `k + 1` maximal intervals, wherever the runs lie;
/// merging across adjacent initial ranges only lowers the count. Summed, the
/// free list holds at most the initial ranges plus the live runs.
pub const fn free_range_bound(candidates: usize, reservations: usize, live_runs: usize) -> usize {
    candidates + reservations + live_runs
}

/// Links of a free buddy block's first page: page positions stored plus one,
/// 0 for none (DW2 large-memory plan, M7 §12.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct FreeLink {
    next: u32,
    prev: u32,
}

impl FreeLink {
    /// A page that starts no free block.
    pub(super) const EMPTY: Self = Self { next: 0, prev: 0 };
}

/// The buddy allocator's per-page and per-range metadata, carved from the
/// grown role table's run: `tags` and `links` have one entry per allocator
/// page, `bases` one per initial range, `hints` one per granule of the
/// range lookup ([`PhysicalFrameAllocator::range_hint_count`]), and
/// `free_bits` one bit per allocator page, `tags.len().div_ceil(64)` words
/// (DW2 large-memory plan, M7 §12.12).
pub(super) struct BuddyStorage {
    pub(super) tags: &'static mut [u8],
    pub(super) links: &'static mut [FreeLink],
    pub(super) bases: &'static mut [u64],
    pub(super) hints: &'static mut [u32],
    pub(super) free_bits: &'static mut [u64],
}

/// The frame allocator over sanitized, already-reserved physical ranges, in
/// two phases (DW2 large-memory plan, M7 §12.2).
///
/// At boot it is first fit over a sorted list of free ranges held inline.
/// `RANGE_CAPACITY` is caller-selected so production bootstrap storage
/// remains fixed while host tests can exercise fragmentation explicitly;
/// production sizes it with [`free_range_bound`]. Once the frame-role table
/// grows, [`Self::adopt_buddy`] hands it per-page metadata in RAM, and a buddy
/// allocator seeded from the free list serves every later request: blocks
/// aligned by absolute page number, inside one initial range, with the free
/// lists' links outside the frames. A run keeps its exact length.
pub(super) struct PhysicalFrameAllocator<const RANGE_CAPACITY: usize> {
    initial: [PageRange; RANGE_CAPACITY],
    initial_len: usize,
    /// The boot phase's free ranges, sorted by address; unused once the
    /// buddy allocator is adopted.
    free: [PageRange; RANGE_CAPACITY],
    free_len: usize,
    limit: PhysicalAddressLimit,
    /// After growth, the allocator every request goes to.
    buddy: Option<Buddy>,
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
            buddy: None,
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
            core::ptr::addr_of_mut!((*destination).buddy).write(None);
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

    /// Allocates a contiguous run of exactly `page_count` base pages: the
    /// lowest that fits at boot, and after growth the first `page_count`
    /// pages of the most recently freed block of the smallest sufficient
    /// order, the rest of the block returned at once.
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
        if let Some(buddy) = self.buddy.as_mut() {
            return buddy.allocate_run(&self.initial[..self.initial_len], page_count);
        }
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

    /// Allocates a contiguous run whose exclusive end is no greater than
    /// `exclusive_ceiling`: the lowest at boot; after growth the head of the
    /// first non-empty sufficient order that qualifies, else the lowest
    /// qualifying free block, found by a scan of the tags below the ceiling.
    ///
    /// The ceiling is an additional caller-supplied constraint, not a second
    /// physical-address limit. Values above the allocator's validated limit
    /// are therefore harmlessly bounded by that limit. A non-page-aligned
    /// ceiling is also supported: every returned whole page is still strictly
    /// below it. Selection and all arithmetic complete before the free list is
    /// changed, so an error leaves allocator state untouched.
    pub(super) fn allocate_run_below(
        &mut self,
        page_count: u64,
        exclusive_ceiling: u64,
    ) -> Result<PageRange, PhysicalMemoryError> {
        if page_count == 0 {
            return Err(PhysicalMemoryError::InvalidPageRange);
        }
        let byte_len = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(PhysicalMemoryError::AddressOverflow)?;
        let ceiling = exclusive_ceiling.min(self.limit.exclusive());
        if let Some(buddy) = self.buddy.as_mut() {
            return buddy.allocate_run_below(
                &self.initial[..self.initial_len],
                page_count,
                ceiling,
            );
        }
        let index = self.free[..self.free_len]
            .iter()
            .position(|range| {
                range
                    .end
                    .min(ceiling)
                    .checked_sub(range.start)
                    .is_some_and(|available| available >= byte_len)
            })
            .ok_or(PhysicalMemoryError::NoFramesAvailable)?;
        let start = self.free[index].start;
        let end = start
            .checked_add(byte_len)
            .ok_or(PhysicalMemoryError::AddressOverflow)?;

        // `index` was selected only when this exact run ended at or below the
        // ceiling and inside the free range. Mutate only after that proof.
        self.free[index].start = end;
        if self.free[index].start == self.free[index].end {
            self.remove_free(index);
        }
        Ok(PageRange { start, end })
    }

    /// Boot phase only (DW2 M7 §12.9): among the free ranges, takes from the
    /// one whose interior aligned to `align_pages` is longest (the lowest of
    /// equals) `min(max_pages, that interior rounded down to a multiple of
    /// align_pages)` pages, starting at its first aligned page. The run may
    /// lie in the middle of the free range, which then splits in two; the
    /// free list stays within [`free_range_bound`], since the run is one more
    /// live run. `NoFramesAvailable` when no free range holds one aligned
    /// multiple; refused once the buddy allocator has taken over. Selection
    /// and all arithmetic complete before the free list changes.
    pub(super) fn allocate_largest_aligned(
        &mut self,
        max_pages: u64,
        align_pages: u64,
    ) -> Result<PageRange, PhysicalMemoryError> {
        if max_pages == 0 || align_pages == 0 || self.buddy.is_some() {
            return Err(PhysicalMemoryError::InvalidPageRange);
        }
        let align = align_pages
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(PhysicalMemoryError::AddressOverflow)?;
        // (index, aligned start, usable pages) of the best range so far.
        let mut best: Option<(usize, u64, u64)> = None;
        for (index, range) in self.free[..self.free_len].iter().enumerate() {
            let Some(start) = range.start.checked_next_multiple_of(align) else {
                continue;
            };
            let Some(interior) = range.end.checked_sub(start) else {
                continue;
            };
            let usable = interior / BASE_PAGE_SIZE / align_pages * align_pages;
            if usable > 0 && best.is_none_or(|(_, _, longest)| usable > longest) {
                best = Some((index, start, usable));
            }
        }
        let (index, start, usable) = best.ok_or(PhysicalMemoryError::NoFramesAvailable)?;
        let end = usable
            .min(max_pages)
            .checked_mul(BASE_PAGE_SIZE)
            .and_then(|bytes| start.checked_add(bytes))
            .ok_or(PhysicalMemoryError::AddressOverflow)?;
        let range = self.free[index];
        match (start == range.start, end == range.end) {
            (true, true) => self.remove_free(index),
            (true, false) => self.free[index].start = end,
            (false, true) => self.free[index].end = start,
            (false, false) => {
                if self.free_len == RANGE_CAPACITY {
                    return Err(PhysicalMemoryError::CapacityExceeded);
                }
                self.shift_right(index + 1);
                self.free[index].end = start;
                self.free[index + 1] = PageRange {
                    start: end,
                    end: range.end,
                };
                self.free_len += 1;
            }
        }
        Ok(PageRange { start, end })
    }

    /// Returns one previously allocated contiguous run. Callers above this
    /// mechanism must prove that no live role still owns the run.
    pub(super) fn free_run(&mut self, range: PageRange) -> Result<(), PhysicalMemoryError> {
        self.validate_candidate(range)?;
        if let Some(buddy) = self.buddy.as_mut() {
            return buddy.free_run(&self.initial[..self.initial_len], range);
        }
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

    /// Whether [`Self::adopt_buddy`] accepts storage of these lengths: this
    /// is the first adoption, `tags` and `links` hold one entry per initial
    /// frame, that count is below `u32::MAX`, `bases` holds one entry per
    /// initial range, `hints` [`Self::range_hint_count`] entries, and
    /// `free_bits` one bit per initial frame, `tags.div_ceil(64)` words.
    pub(super) fn accepts_buddy_storage(
        &self,
        tags: usize,
        links: usize,
        bases: usize,
        hints: usize,
        free_bits: usize,
    ) -> bool {
        self.buddy.is_none()
            && tags == links
            && u64::try_from(tags).is_ok_and(|tags| tags == self.initial_frames())
            && u32::try_from(tags).is_ok_and(|tags| tags < u32::MAX)
            && bases == self.initial_len
            && hints == self.range_hint_count()
            && free_bits == tags.div_ceil(64)
    }

    /// The hints the buddy allocator's range lookup needs: one per granule
    /// of at least 1 GiB up to the last initial range's last byte, at most
    /// 4096; 0 without initial ranges.
    pub(super) fn range_hint_count(&self) -> usize {
        buddy::hint_count(&self.initial[..self.initial_len])
    }

    /// Switches to the buddy allocator over `storage` (DW2 M7 §12.2), seeded
    /// from the boot free list in order. Refuses, returning `storage`, unless
    /// [`Self::accepts_buddy_storage`] holds; nothing fails after that check.
    pub(super) fn adopt_buddy(&mut self, storage: BuddyStorage) -> Result<(), BuddyStorage> {
        if !self.accepts_buddy_storage(
            storage.tags.len(),
            storage.links.len(),
            storage.bases.len(),
            storage.hints.len(),
            storage.free_bits.len(),
        ) {
            return Err(storage);
        }
        self.buddy = Some(Buddy::seed(
            storage,
            &self.initial[..self.initial_len],
            &self.free[..self.free_len],
        ));
        Ok(())
    }

    /// The initial ranges, which the buddy storage's `bases` follows.
    pub(super) const fn initial_range_count(&self) -> usize {
        self.initial_len
    }

    /// The position of the page holding `physical_start` in the
    /// concatenation of the initial ranges, or `None` outside them: a
    /// linear scan at boot, and after growth a walk from the hint of the
    /// address's granule.
    pub(super) fn page_position(&self, physical_start: u64) -> Option<usize> {
        let initial = &self.initial[..self.initial_len];
        if let Some(buddy) = self.buddy.as_ref() {
            return buddy.page_position(initial, physical_start);
        }
        let mut base = 0_u64;
        for range in initial {
            if range.start <= physical_start && physical_start < range.end {
                return usize::try_from(base + (physical_start - range.start) / BASE_PAGE_SIZE)
                    .ok();
            }
            base += range.page_count();
        }
        None
    }

    /// Checks the buddy allocator's invariants I1 to I7 (DW2 M7 §12.2); `Ok`
    /// before adoption. Linear in the allocator pages.
    pub(super) fn check_buddy(&self) -> Result<(), PhysicalMemoryError> {
        self.buddy.as_ref().map_or(Ok(()), |buddy| {
            buddy.check(&self.initial[..self.initial_len])
        })
    }

    /// The boot phase's free ranges, in address order.
    #[cfg(test)]
    pub(super) fn boot_free_ranges(&self) -> &[PageRange] {
        &self.free[..self.free_len]
    }

    /// The free buddy blocks in address order, as (physical start, order);
    /// empty before adoption.
    #[cfg(test)]
    pub(super) fn free_blocks(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        self.buddy
            .iter()
            .flat_map(|buddy| buddy.free_blocks(&self.initial[..self.initial_len]))
    }

    /// Pages in the largest free range (the largest free block after
    /// growth): the largest run one allocation can take now.
    pub(super) fn largest_free_pages(&self) -> u64 {
        if let Some(buddy) = self.buddy.as_ref() {
            return buddy.largest_free_pages();
        }
        self.free[..self.free_len]
            .iter()
            .map(|range| range.page_count())
            .max()
            .unwrap_or(0)
    }

    /// Number of currently available frames.
    pub(super) fn available_frames(&self) -> u64 {
        if let Some(buddy) = self.buddy.as_ref() {
            return buddy.free_pages();
        }
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

    /// The ranges the allocator may ever hand out, in address order.
    pub(super) fn initial_ranges(&self) -> impl Iterator<Item = PhysicalRange> + '_ {
        self.initial[..self.initial_len].iter().map(|range| {
            PhysicalRange::new(range.start, range.end - range.start)
                .expect("an initial range is a valid nonempty range")
        })
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
        if let Some(buddy) = self.buddy.as_ref() {
            return buddy.overlaps_free(&self.initial[..self.initial_len], range);
        }
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
        let len = self.free_len;
        self.free.copy_within(index..len, index + 1);
    }

    fn remove_free(&mut self, index: usize) {
        let len = self.free_len;
        let free = &mut self.free;
        free.copy_within(index + 1..len, index);
        free[len - 1] = EMPTY_RANGE;
        self.free_len -= 1;
    }
}

#[cfg(test)]
#[path = "physical/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "physical/buddy_tests.rs"]
mod buddy_tests;
