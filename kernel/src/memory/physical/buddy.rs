//! The buddy allocator the frame allocator switches to once the frame-role
//! table grows (DW2 large-memory plan, M7 §12.2).
//!
//! Its metadata is per allocator page and lives outside the frames, in the
//! slices [`BuddyStorage`] carries: a tag per page (0, or 1 + the order of the
//! free block starting there) and a pair of list links per page. A page's
//! *position* is its index in the concatenation of the initial ranges.
//! Blocks are aligned by absolute page number and lie inside one initial
//! range; two buddies merge only when the merged block still does.
//!
//! Invariants, checked by [`Buddy::check`]:
//! - I1. A non-zero tag `k + 1` sits only on a page whose page number is a
//!   multiple of 2^k, and the block of 2^k pages starting there lies inside
//!   one initial range.
//! - I2. Free blocks are pairwise disjoint, and no page inside a free block
//!   other than its first has a non-zero tag.
//! - I3. Every free block is on the list of its order exactly once; each list
//!   is a consistent doubly linked list; `nonempty` matches the heads.
//! - I4. No two free blocks are buddies of the same order whose union lies
//!   inside one initial range.
//! - I5. `free_pages` is the sum of the free blocks' pages.
//! - I6. `hints[g]` is the index of the first initial range whose end is
//!   above `g << hint_shift` (the first range that can hold an address in
//!   granule `g`), or the range count if there is none, for every granule up
//!   to the last initial range's last byte.
//! - I7. `free_bits` has `tags.len().div_ceil(64)` words, one bit per
//!   allocator page by position; a page's bit is set exactly while the page
//!   lies inside a free block, and every bit at a position at or past
//!   `tags.len()` is clear.
//!
//! Finding the initial range that holds an address starts at the hint of its
//! granule and walks upward over the ranges that share the granule, so the
//! common case costs one or two comparisons.
//!
//! The paths index the slices without bounds checks (DW2 M7 §12.12 part 2
//! item 4: measured faster than the bounds-checked form and than C). Every
//! unchecked index is a position below `tags.len()` (`links` has that
//! length, and `free_bits` covers it by I7), an order at most `MAX_ORDER`,
//! a range index below `bases.len()`, or a hint index just compared
//! against `hints.len()`. Positions come from the lists and tags, which
//! only this module writes (I1 to I7), or from a caller's range that
//! `range_index` has placed inside one initial range. The one fact this
//! module cannot establish is that the `ranges` a method is given are the
//! initial ranges the allocator was seeded with, so every method that takes
//! `ranges` and reaches an unchecked index is `unsafe` with that as its
//! requirement. Each helper `debug_assert!`s its preconditions.

use super::{BASE_PAGE_SIZE, BuddyStorage, FreeLink, PageRange, PhysicalMemoryError};

/// Orders 0 to 40: a block of 2^40 pages spans the 52-bit physical limit.
const BUDDY_ORDERS: usize = 41;
const MAX_ORDER: u32 = 40;

pub(super) struct Buddy {
    /// Per allocator page (by page position): 0, or 1 + the order of the
    /// free block that starts at this page.
    tags: &'static mut [u8],
    /// Per allocator page; meaningful only where `tags` is non-zero.
    links: &'static mut [FreeLink],
    /// Per initial range: the allocator pages before it.
    bases: &'static mut [u64],
    /// Per granule of 2^`hint_shift` bytes: the first initial range that
    /// can hold an address in it (I6).
    hints: &'static mut [u32],
    /// One bit per allocator page, by position: set while free (I7).
    free_bits: &'static mut [u64],
    hint_shift: u32,
    /// Per order: position + 1 of the first free block, 0 = empty.
    heads: [u32; BUDDY_ORDERS],
    /// Bit k is set iff `heads[k] != 0`.
    nonempty: u64,
    free_pages: u64,
}

const fn first_pfn(range: PageRange) -> u64 {
    range.start / BASE_PAGE_SIZE
}

const fn end_pfn(range: PageRange) -> u64 {
    range.end / BASE_PAGE_SIZE
}

/// The granule size, as a shift, of the hints over `ranges`: at least
/// 1 GiB, and large enough that at most 4096 granules reach the last
/// initial range's last byte.
fn hint_shift(ranges: &[PageRange]) -> u32 {
    let bits = ranges
        .last()
        .map_or(0, |last| 64 - (last.end - 1).leading_zeros());
    bits.saturating_sub(12).max(30)
}

/// How many hints the initial ranges `ranges` need: one per granule up to
/// the last range's last byte, and none without ranges.
pub(super) fn hint_count(ranges: &[PageRange]) -> usize {
    ranges.last().map_or(0, |last| {
        (((last.end - 1) >> hint_shift(ranges)) + 1) as usize
    })
}

/// The hint of granule `granule` by its definition (I6): the first range
/// whose end is above the granule's start.
fn hint_for(ranges: &[PageRange], shift: u32, granule: usize) -> u32 {
    let start = (granule as u64) << shift;
    ranges.partition_point(|range| range.end <= start) as u32
}

/// Whether the block of 2^`order` pages at `pfn` lies inside `range`.
fn block_inside(range: PageRange, pfn: u64, order: u32) -> bool {
    pfn >= first_pfn(range)
        && pfn
            .checked_add(1_u64 << order)
            .is_some_and(|end| end <= end_pfn(range))
}

/// The smallest order whose block holds `page_count` pages, if any.
fn order_for(page_count: u64) -> Option<u32> {
    page_count
        .checked_next_power_of_two()
        .map(u64::trailing_zeros)
        .filter(|order| *order <= MAX_ORDER)
}

/// The edge masks of the bit range `[start, end)`, `start < end`: the
/// words it spans and the masks of its first and last word.
#[inline]
const fn bit_span(start: usize, end: usize) -> (usize, usize, u64, u64) {
    let last = end - 1;
    (
        start / 64,
        last / 64,
        !0_u64 << (start % 64),
        !0_u64 >> (63 - last % 64),
    )
}

#[allow(
    unsafe_code,
    reason = "the buddy's paths index its per-page slices without bounds checks under I1 to I7 (DW2 M7 §12.12)"
)]
impl Buddy {
    /// Takes `storage` and frees every range of `free` (the boot free list)
    /// into it, in order.
    ///
    /// # Safety
    ///
    /// `initial` must be the allocator's initial ranges (page-aligned, in
    /// address order, never touching), and the storage's lengths must be
    /// the ones `accepts_buddy_storage` accepts for them. Every free range
    /// lies inside one initial range, since the initial ranges never touch:
    /// the boot list merges touching ranges and a reservation leaves a gap;
    /// a range that does not is a panic before anything is inserted for it.
    pub(super) unsafe fn seed(
        storage: BuddyStorage,
        initial: &[PageRange],
        free: &[PageRange],
    ) -> Self {
        let BuddyStorage {
            tags,
            links,
            bases,
            hints,
            free_bits,
        } = storage;
        debug_assert_eq!(bases.len(), initial.len());
        debug_assert_eq!(free_bits.len(), tags.len().div_ceil(64));
        tags.fill(0);
        links.fill(FreeLink::EMPTY);
        free_bits.fill(0);
        let mut base = 0_u64;
        for (entry, range) in bases.iter_mut().zip(initial) {
            *entry = base;
            base += range.page_count();
        }
        // The hints come before the first lookup below.
        let shift = hint_shift(initial);
        for (granule, hint) in hints.iter_mut().enumerate() {
            *hint = hint_for(initial, shift, granule);
        }
        let mut buddy = Self {
            tags,
            links,
            bases,
            hints,
            free_bits,
            hint_shift: shift,
            heads: [0; BUDDY_ORDERS],
            nonempty: 0,
            free_pages: 0,
        };
        let mut total = 0_u64;
        for range in free {
            let index = buddy
                .range_index(initial, range.start)
                .filter(|index| initial[*index].contains(*range))
                .expect("a boot free range lies inside one initial range");
            // SAFETY: `initial` is the seeded slice and the free range lies
            // inside `initial[index]`, as just checked.
            unsafe {
                buddy.insert_range(initial, index, first_pfn(*range), range.page_count());
            }
            // SAFETY: as above; the range's first page is inside it.
            let start = unsafe { buddy.position(initial, index, first_pfn(*range)) };
            // SAFETY: the range's positions run from `start` to at most
            // `tags.len()`, which is at most `free_bits.len() * 64` (I7).
            unsafe {
                Self::bits_update(
                    buddy.free_bits,
                    start,
                    start + range.page_count() as usize,
                    true,
                );
            }
            total += range.page_count();
        }
        buddy.free_pages = total;
        buddy
    }

    /// The initial range holding `physical`: from the hint of its granule,
    /// upward over the ranges that can still hold it. Returns only indices
    /// below `ranges.len()`.
    #[inline]
    pub(super) fn range_index(&self, ranges: &[PageRange], physical: u64) -> Option<usize> {
        let granule = usize::try_from(physical >> self.hint_shift).ok()?;
        if granule >= self.hints.len() {
            return None;
        }
        // SAFETY: `granule < hints.len()` was just checked.
        let mut index = unsafe { *self.hints.get_unchecked(granule) } as usize;
        while index < ranges.len() {
            // SAFETY: `index < ranges.len()` is the loop condition.
            let range = unsafe { ranges.get_unchecked(index) };
            if range.start > physical {
                return None;
            }
            if physical < range.end {
                return Some(index);
            }
            index += 1;
        }
        None
    }

    /// The position of the page at `pfn`, which lies inside `ranges[index]`.
    /// With `ranges` the seeded slice, it is below `tags.len()`.
    ///
    /// # Safety
    ///
    /// `index < ranges.len()` and `ranges.len() == bases.len()`.
    #[inline]
    unsafe fn position(&self, ranges: &[PageRange], index: usize, pfn: u64) -> usize {
        debug_assert!(index < ranges.len() && ranges.len() == self.bases.len());
        debug_assert!(pfn >= first_pfn(ranges[index]) && pfn < end_pfn(ranges[index]));
        // SAFETY: `index < ranges.len() == bases.len()` (caller).
        let base = unsafe { *self.bases.get_unchecked(index) };
        // SAFETY: as above.
        let first = first_pfn(unsafe { *ranges.get_unchecked(index) });
        (base + (pfn - first)) as usize
    }

    /// The initial range and the page number of the page at `position`.
    ///
    /// # Safety
    ///
    /// `position < tags.len()` and `ranges` is the seeded slice, so
    /// `ranges.len() == bases.len()`.
    #[inline]
    unsafe fn page_at(&self, ranges: &[PageRange], position: usize) -> (usize, u64) {
        debug_assert!(position < self.tags.len());
        debug_assert_eq!(ranges.len(), self.bases.len());
        let index = self.bases.partition_point(|base| *base <= position as u64) - 1;
        // SAFETY: there is a page, so a range: `bases[0] == 0 <= position`,
        // the partition point is at least 1, and `index < bases.len() ==
        // ranges.len()` (caller).
        let range = unsafe { *ranges.get_unchecked(index) };
        // SAFETY: as above.
        let base = unsafe { *self.bases.get_unchecked(index) };
        (index, first_pfn(range) + (position as u64 - base))
    }

    pub(super) fn page_position(&self, ranges: &[PageRange], physical: u64) -> Option<usize> {
        let index = self.range_index(ranges, physical)?;
        usize::try_from(self.bases[index] + (physical - ranges[index].start) / BASE_PAGE_SIZE).ok()
    }

    /// Puts the free block at `position` on the head of list `order`.
    ///
    /// # Safety
    ///
    /// `position < tags.len()` and `order <= MAX_ORDER`.
    #[inline]
    unsafe fn push(&mut self, order: u32, position: usize) {
        debug_assert!(position < self.tags.len() && order <= MAX_ORDER);
        let link = position as u32 + 1;
        // SAFETY: `order <= MAX_ORDER < BUDDY_ORDERS` (caller).
        let head = unsafe { *self.heads.get_unchecked(order as usize) };
        // SAFETY: `position < tags.len() == links.len()` (caller).
        unsafe {
            *self.links.get_unchecked_mut(position) = FreeLink {
                next: head,
                prev: 0,
            };
        }
        if head != 0 {
            // SAFETY: a non-zero head is a free block's position + 1 (I3),
            // a position below `links.len()`.
            unsafe { self.links.get_unchecked_mut(head as usize - 1).prev = link };
        }
        // SAFETY: as for `head` above.
        unsafe { *self.heads.get_unchecked_mut(order as usize) = link };
        self.nonempty |= 1 << order;
        // SAFETY: `position < tags.len()` (caller).
        unsafe { *self.tags.get_unchecked_mut(position) = order as u8 + 1 };
    }

    /// Takes the free block at `position` off list `order` and clears its tag.
    ///
    /// # Safety
    ///
    /// `position` is a free block of `order` on its list (I3), so
    /// `position < tags.len()` and `order <= MAX_ORDER`.
    #[inline]
    unsafe fn unlink(&mut self, order: u32, position: usize) {
        debug_assert!(order <= MAX_ORDER && position < self.tags.len());
        debug_assert_eq!(u32::from(self.tags[position]), order + 1);
        // SAFETY: `position < links.len()` (caller).
        let FreeLink { next, prev } = unsafe { *self.links.get_unchecked(position) };
        if prev == 0 {
            // SAFETY: `order <= MAX_ORDER < BUDDY_ORDERS` (caller).
            unsafe { *self.heads.get_unchecked_mut(order as usize) = next };
        } else {
            // SAFETY: a non-zero link is a listed block's position + 1 (I3).
            unsafe { self.links.get_unchecked_mut(prev as usize - 1).next = next };
        }
        if next != 0 {
            // SAFETY: as for `prev`.
            unsafe { self.links.get_unchecked_mut(next as usize - 1).prev = prev };
        }
        // SAFETY: as for the head write above.
        if unsafe { *self.heads.get_unchecked(order as usize) } == 0 {
            self.nonempty &= !(1 << order);
        }
        // SAFETY: `position < links.len() == tags.len()` (caller).
        unsafe {
            *self.links.get_unchecked_mut(position) = FreeLink::EMPTY;
            *self.tags.get_unchecked_mut(position) = 0;
        }
    }

    /// Frees the aligned block of 2^`order` pages at `pfn`, inside
    /// `ranges[index]`, merging it with its free buddies while the merged
    /// block stays inside that range.
    ///
    /// # Safety
    ///
    /// `ranges` is the seeded slice, `index < ranges.len()`, `order <=
    /// MAX_ORDER`, and the block lies inside `ranges[index]`.
    #[inline]
    unsafe fn insert_block(&mut self, ranges: &[PageRange], index: usize, pfn: u64, order: u32) {
        debug_assert!(index < ranges.len() && ranges.len() == self.bases.len());
        debug_assert!(order <= MAX_ORDER && block_inside(ranges[index], pfn, order));
        // SAFETY: `index < ranges.len()` (caller).
        let range = unsafe { *ranges.get_unchecked(index) };
        let (mut pfn, mut order) = (pfn, order);
        while order < MAX_ORDER {
            let buddy = pfn ^ (1_u64 << order);
            let merged = pfn.min(buddy);
            if !block_inside(range, merged, order + 1) {
                break;
            }
            // SAFETY: the merged block, and with it `buddy`, lies inside
            // `ranges[index]`.
            let position = unsafe { self.position(ranges, index, buddy) };
            // SAFETY: a page of a seeded range has a position below
            // `tags.len()`.
            if u32::from(unsafe { *self.tags.get_unchecked(position) }) != order + 1 {
                break;
            }
            // SAFETY: a tag of `order + 1` marks a listed free block of
            // `order` (I1, I3), and `order < MAX_ORDER`.
            unsafe { self.unlink(order, position) };
            pfn = merged;
            order += 1;
        }
        // SAFETY: `pfn` starts a block inside `ranges[index]`.
        let position = unsafe { self.position(ranges, index, pfn) };
        // SAFETY: `position < tags.len()`, as for the buddy above, and
        // `order <= MAX_ORDER`.
        unsafe { self.push(order, position) };
    }

    /// Frees `pages` pages from `pfn`, inside `ranges[index]`, as maximal
    /// aligned blocks. Never touches `free_pages`; its callers do.
    ///
    /// # Safety
    ///
    /// `ranges` is the seeded slice, `index < ranges.len()`, and the pages
    /// lie inside `ranges[index]`.
    #[inline]
    unsafe fn insert_range(&mut self, ranges: &[PageRange], index: usize, pfn: u64, pages: u64) {
        debug_assert!(index < ranges.len() && ranges.len() == self.bases.len());
        debug_assert!(
            pages == 0
                || (pfn >= first_pfn(ranges[index]) && pfn + pages <= end_pfn(ranges[index]))
        );
        let (mut pfn, mut pages) = (pfn, pages);
        while pages > 0 {
            let order = pfn.trailing_zeros().min(pages.ilog2()).min(MAX_ORDER);
            // SAFETY: the block of 2^order pages at `pfn` lies inside the
            // caller's pages, so inside `ranges[index]`.
            unsafe { self.insert_block(ranges, index, pfn, order) };
            pfn += 1_u64 << order;
            pages -= 1_u64 << order;
        }
    }

    /// Takes the free block of `order` at `position`: its first `page_count`
    /// pages are the run, the rest goes back at once.
    ///
    /// # Safety
    ///
    /// `ranges` is the seeded slice, `position` is a listed free block of
    /// `order` (so `position < tags.len()`, `order <= MAX_ORDER`), and
    /// `page_count <= 2^order`.
    #[inline]
    unsafe fn take(
        &mut self,
        ranges: &[PageRange],
        order: u32,
        position: usize,
        page_count: u64,
    ) -> PageRange {
        debug_assert!(ranges.len() == self.bases.len() && position < self.tags.len());
        debug_assert!(order <= MAX_ORDER && page_count <= 1_u64 << order);
        debug_assert_eq!(u32::from(self.tags[position]), order + 1);
        // SAFETY: a listed block's position is below `tags.len()` (I3).
        let (index, pfn) = unsafe { self.page_at(ranges, position) };
        // SAFETY: the block is listed at `order` (caller).
        unsafe { self.unlink(order, position) };
        // SAFETY: the run's positions lie in the block, below `tags.len()`
        // (I1), so below `free_bits.len() * 64` (I7).
        unsafe {
            Self::bits_update(
                self.free_bits,
                position,
                position + page_count as usize,
                false,
            );
        }
        let block = 1_u64 << order;
        if block > page_count {
            // SAFETY: the rest of the block lies inside `ranges[index]` (I1).
            unsafe { self.insert_range(ranges, index, pfn + page_count, block - page_count) };
        }
        self.free_pages -= page_count;
        PageRange {
            start: pfn * BASE_PAGE_SIZE,
            end: (pfn + page_count) * BASE_PAGE_SIZE,
        }
    }

    /// `page_count` is non-zero and its byte length does not overflow.
    ///
    /// # Safety
    ///
    /// `ranges` is the slice of initial ranges the buddy was seeded with:
    /// the same length as `bases` and the same contents.
    pub(super) unsafe fn allocate_run(
        &mut self,
        ranges: &[PageRange],
        page_count: u64,
    ) -> Result<PageRange, PhysicalMemoryError> {
        debug_assert_eq!(ranges.len(), self.bases.len());
        let order = order_for(page_count).ok_or(PhysicalMemoryError::NoFramesAvailable)?;
        let available = self.nonempty >> order;
        if available == 0 {
            return Err(PhysicalMemoryError::NoFramesAvailable);
        }
        let found = order + available.trailing_zeros();
        // SAFETY: `nonempty` has no bit at or above BUDDY_ORDERS (I3), so
        // `found <= MAX_ORDER`.
        let position = unsafe { *self.heads.get_unchecked(found as usize) } as usize - 1;
        // SAFETY: bit `found` of `nonempty` is set, so its head is a listed
        // block of order `found >= order`, which holds `page_count` pages
        // (I3); `ranges` is the seeded slice (caller).
        Ok(unsafe { self.take(ranges, found, position, page_count) })
    }

    /// `page_count` is non-zero and its byte length does not overflow;
    /// `ceiling` is already bounded by the physical limit.
    ///
    /// # Safety
    ///
    /// `ranges` is the slice of initial ranges the buddy was seeded with:
    /// the same length as `bases` and the same contents.
    pub(super) unsafe fn allocate_run_below(
        &mut self,
        ranges: &[PageRange],
        page_count: u64,
        ceiling: u64,
    ) -> Result<PageRange, PhysicalMemoryError> {
        debug_assert_eq!(ranges.len(), self.bases.len());
        let order = order_for(page_count).ok_or(PhysicalMemoryError::NoFramesAvailable)?;
        let fits = |pfn: u64| {
            pfn.checked_add(page_count)
                .and_then(|end| end.checked_mul(BASE_PAGE_SIZE))
                .is_some_and(|end| end <= ceiling)
        };
        // First the head of each non-empty sufficient order.
        for found in order..=MAX_ORDER {
            if self.nonempty & (1_u64 << found) == 0 {
                continue;
            }
            // SAFETY: `found <= MAX_ORDER < BUDDY_ORDERS`.
            let position = unsafe { *self.heads.get_unchecked(found as usize) } as usize - 1;
            // SAFETY: bit `found` of `nonempty` is set, so its head is a
            // listed block (I3), whose position is below `tags.len()`;
            // `ranges` is the seeded slice (caller).
            if fits(unsafe { self.page_at(ranges, position) }.1) {
                // SAFETY: that block is listed at `found >= order`, so it
                // holds `page_count` pages.
                return Ok(unsafe { self.take(ranges, found, position, page_count) });
            }
        }
        // Then the tags upward from the lowest allocator page.
        for (index, range) in ranges.iter().enumerate() {
            let mut pfn = first_pfn(*range);
            while pfn < end_pfn(*range) {
                if !fits(pfn) {
                    return Err(PhysicalMemoryError::NoFramesAvailable);
                }
                // SAFETY: `index < ranges.len()` and `pfn` lies inside
                // `ranges[index]`; `ranges` is the seeded slice (caller).
                let position = unsafe { self.position(ranges, index, pfn) };
                // SAFETY: a page of a seeded range has a position below
                // `tags.len()`.
                match unsafe { *self.tags.get_unchecked(position) } {
                    0 => pfn += 1,
                    tag => {
                        let found = u32::from(tag) - 1;
                        if found >= order {
                            // SAFETY: a non-zero tag marks a listed free
                            // block of `found` (I1, I3), and `found >=
                            // order`, so it holds `page_count` pages.
                            return Ok(unsafe { self.take(ranges, found, position, page_count) });
                        }
                        pfn += 1_u64 << found;
                    }
                }
            }
        }
        Err(PhysicalMemoryError::NoFramesAvailable)
    }

    /// Whether any bit of `[start, end)` is set.
    ///
    /// # Safety
    ///
    /// `start <= end <= bits.len() * 64`.
    #[inline]
    unsafe fn bits_any(bits: &[u64], start: usize, end: usize) -> bool {
        debug_assert!(start <= end && end <= bits.len() * 64);
        if start >= end {
            return false;
        }
        let (first, last, head, tail) = bit_span(start, end);
        // SAFETY: `first <= last < bits.len()` since `end - 1 < bits.len() *
        // 64` (caller).
        unsafe {
            if first == last {
                return *bits.get_unchecked(first) & head & tail != 0;
            }
            *bits.get_unchecked(first) & head != 0
                || bits
                    .get_unchecked(first + 1..last)
                    .iter()
                    .any(|word| *word != 0)
                || *bits.get_unchecked(last) & tail != 0
        }
    }

    /// Sets (`set`) or clears every bit of `[start, end)`.
    ///
    /// # Safety
    ///
    /// `start <= end <= bits.len() * 64`.
    #[inline]
    unsafe fn bits_update(bits: &mut [u64], start: usize, end: usize, set: bool) {
        debug_assert!(start <= end && end <= bits.len() * 64);
        if start >= end {
            return;
        }
        let (first, last, head, tail) = bit_span(start, end);
        let apply = |word: &mut u64, mask: u64| {
            if set {
                *word |= mask;
            } else {
                *word &= !mask;
            }
        };
        // SAFETY: `first <= last < bits.len()` (caller).
        unsafe {
            if first == last {
                apply(bits.get_unchecked_mut(first), head & tail);
                return;
            }
            apply(bits.get_unchecked_mut(first), head);
            for word in bits.get_unchecked_mut(first + 1..last) {
                apply(word, !0);
            }
            apply(bits.get_unchecked_mut(last), tail);
        }
    }

    /// `range` is a valid page range below the physical limit.
    ///
    /// # Safety
    ///
    /// `ranges` is the slice of initial ranges the buddy was seeded with:
    /// the same length as `bases` and the same contents. `range` is
    /// non-empty and page-aligned (`start < end`).
    pub(super) unsafe fn free_run(
        &mut self,
        ranges: &[PageRange],
        range: PageRange,
    ) -> Result<(), PhysicalMemoryError> {
        debug_assert_eq!(ranges.len(), self.bases.len());
        debug_assert!(
            range.start < range.end
                && range.start.is_multiple_of(BASE_PAGE_SIZE)
                && range.end.is_multiple_of(BASE_PAGE_SIZE)
        );
        let index = self
            .range_index(ranges, range.start)
            // SAFETY: `range_index` returns only indices below
            // `ranges.len()`.
            .filter(|index| unsafe { ranges.get_unchecked(*index) }.contains(range))
            .ok_or(PhysicalMemoryError::InvalidFrame)?;
        let pages = range.page_count() as usize;
        // SAFETY: the range lies inside `ranges[index]`, as just checked, and
        // `ranges` is the seeded slice (caller).
        let start = unsafe { self.position(ranges, index, first_pfn(range)) };
        // SAFETY: its positions run from `start` to at most `tags.len()`, so
        // to at most `free_bits.len() * 64` (I7).
        if unsafe { Self::bits_any(self.free_bits, start, start + pages) } {
            return Err(PhysicalMemoryError::DoubleFree);
        }
        // SAFETY: the range lies inside `ranges[index]`, as checked.
        unsafe { self.insert_range(ranges, index, first_pfn(range), range.page_count()) };
        // SAFETY: as for the check.
        unsafe { Self::bits_update(self.free_bits, start, start + pages, true) };
        self.free_pages += range.page_count();
        Ok(())
    }

    /// Whether any page of `range` is free.
    ///
    /// # Safety
    ///
    /// `ranges` is the slice of initial ranges the buddy was seeded with:
    /// the same length as `bases` and the same contents.
    pub(super) unsafe fn overlaps_free(&self, ranges: &[PageRange], range: PageRange) -> bool {
        debug_assert_eq!(ranges.len(), self.bases.len());
        let first = ranges.partition_point(|initial| initial.end <= range.start);
        ranges[first..]
            .iter()
            .enumerate()
            .take_while(|(_, initial)| initial.start < range.end)
            .any(|(offset, initial)| {
                let clipped = PageRange {
                    start: range.start.max(initial.start),
                    end: range.end.min(initial.end),
                };
                clipped.start < clipped.end && {
                    // SAFETY: `first + offset < ranges.len()` and the clipped
                    // range lies inside that initial range; `ranges` is the
                    // seeded slice (caller).
                    let start =
                        unsafe { self.position(ranges, first + offset, first_pfn(clipped)) };
                    // SAFETY: its positions end at most at `tags.len()`, so at
                    // most at `free_bits.len() * 64` (I7).
                    unsafe {
                        Self::bits_any(self.free_bits, start, start + clipped.page_count() as usize)
                    }
                }
            })
    }

    pub(super) const fn largest_free_pages(&self) -> u64 {
        if self.nonempty == 0 {
            0
        } else {
            1 << (63 - self.nonempty.leading_zeros())
        }
    }

    pub(super) const fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Checks I1 to I7; any violation is reported as `InvalidFrame`.
    ///
    /// # Safety
    ///
    /// `ranges` is the slice of initial ranges the buddy was seeded with:
    /// the same length as `bases` and the same contents.
    pub(super) unsafe fn check(&self, ranges: &[PageRange]) -> Result<(), PhysicalMemoryError> {
        const VIOLATION: Result<(), PhysicalMemoryError> = Err(PhysicalMemoryError::InvalidFrame);
        let total = ranges.iter().map(|range| range.page_count()).sum::<u64>();
        if self.bases.len() != ranges.len()
            || u64::try_from(self.tags.len()) != Ok(total)
            || self.links.len() != self.tags.len()
            || self.free_bits.len() != self.tags.len().div_ceil(64)
            // SAFETY: `free_bits.len() == tags.len().div_ceil(64)`, just
            // checked, so `tags.len() <= free_bits.len() * 64`.
            || unsafe { Self::bits_any(self.free_bits, self.tags.len(), self.free_bits.len() * 64) }
        {
            return VIOLATION;
        }
        // I6.
        if self.hint_shift != hint_shift(ranges)
            || self.hints.len() != hint_count(ranges)
            || self
                .hints
                .iter()
                .enumerate()
                .any(|(granule, hint)| *hint != hint_for(ranges, self.hint_shift, granule))
        {
            return VIOLATION;
        }
        let mut blocks = [0_u64; BUDDY_ORDERS];
        let mut pages = 0_u64;
        let mut base = 0_u64;
        for (index, range) in ranges.iter().enumerate() {
            if self.bases[index] != base {
                return VIOLATION;
            }
            let mut pfn = first_pfn(*range);
            while pfn < end_pfn(*range) {
                // SAFETY: `index < ranges.len() == bases.len()` (checked
                // above) and `pfn` lies inside `ranges[index]`.
                let position = unsafe { self.position(ranges, index, pfn) };
                let tag = self.tags[position];
                if tag == 0 {
                    // I7: a page outside every free block has its bit clear.
                    // SAFETY: `position < tags.len()`, just indexed, and
                    // `tags.len() <= free_bits.len() * 64`.
                    if unsafe { Self::bits_any(self.free_bits, position, position + 1) } {
                        return VIOLATION;
                    }
                    pfn += 1;
                    continue;
                }
                let order = u32::from(tag) - 1;
                // I1.
                if order > MAX_ORDER
                    || !pfn.is_multiple_of(1_u64 << order)
                    || !block_inside(*range, pfn, order)
                {
                    return VIOLATION;
                }
                // I2: the walk visits every page once, so blocks are disjoint.
                let size = 1_usize << order;
                if self.tags[position + 1..position + size]
                    .iter()
                    .any(|tag| *tag != 0)
                {
                    return VIOLATION;
                }
                // I4.
                if order < MAX_ORDER {
                    let buddy = pfn ^ (1_u64 << order);
                    if block_inside(*range, pfn.min(buddy), order + 1)
                        // SAFETY: the merged block, and with it `buddy`,
                        // lies inside `ranges[index]`.
                        && u32::from(self.tags[unsafe { self.position(ranges, index, buddy) }])
                            == order + 1
                    {
                        return VIOLATION;
                    }
                }
                // I7: every page of a free block has its bit set.
                if (position..position + size).any(|page| {
                    // SAFETY: the block's pages were just sliced from `tags`,
                    // so `page < tags.len() <= free_bits.len() * 64`.
                    !unsafe { Self::bits_any(self.free_bits, page, page + 1) }
                }) {
                    return VIOLATION;
                }
                blocks[order as usize] += 1;
                pages += 1_u64 << order;
                pfn += 1_u64 << order;
            }
            base += range.page_count();
        }
        // I5.
        if pages != self.free_pages {
            return VIOLATION;
        }
        // I3: each list is consistent, holds only blocks of its order, and
        // as many as there are; a repeat would break a `prev` link.
        for order in 0..=MAX_ORDER {
            let head = self.heads[order as usize];
            if ((self.nonempty >> order) & 1 == 1) != (head != 0) {
                return VIOLATION;
            }
            let mut previous = 0_u32;
            let mut link = head;
            let mut count = 0_u64;
            while link != 0 {
                let position = link as usize - 1;
                if position >= self.tags.len()
                    || u32::from(self.tags[position]) != order + 1
                    || self.links[position].prev != previous
                {
                    return VIOLATION;
                }
                count += 1;
                if count > blocks[order as usize] {
                    return VIOLATION;
                }
                previous = link;
                link = self.links[position].next;
            }
            if count != blocks[order as usize] {
                return VIOLATION;
            }
        }
        if self.nonempty >> BUDDY_ORDERS != 0 {
            return VIOLATION;
        }
        Ok(())
    }

    /// The hints, for tests that corrupt one.
    #[cfg(test)]
    pub(super) fn hints_mut(&mut self) -> &mut [u32] {
        self.hints
    }

    /// The free blocks in address order, as (physical start, order).
    ///
    /// # Safety
    ///
    /// `ranges` is the slice of initial ranges the buddy was seeded with:
    /// the same length as `bases` and the same contents.
    #[cfg(test)]
    pub(super) unsafe fn free_blocks<'a>(
        &'a self,
        ranges: &'a [PageRange],
    ) -> impl Iterator<Item = (u64, u32)> + 'a {
        ranges.iter().enumerate().flat_map(move |(index, range)| {
            (first_pfn(*range)..end_pfn(*range)).filter_map(move |pfn| {
                // SAFETY: `index < ranges.len()` and `pfn` lies inside
                // `ranges[index]`; `ranges` is the seeded slice (caller).
                let tag = self.tags[unsafe { self.position(ranges, index, pfn) }];
                (tag != 0).then(|| (pfn * BASE_PAGE_SIZE, u32::from(tag) - 1))
            })
        })
    }
}
