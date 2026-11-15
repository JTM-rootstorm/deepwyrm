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
//!
//! Finding the initial range that holds an address starts at the hint of its
//! granule and walks upward over the ranges that share the granule, so the
//! common case costs one or two comparisons.

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

/// Whether any of `tags[start..end]` is non-zero, eight at a time where the
/// position is aligned.
fn any_tag(tags: &[u8], start: usize, end: usize) -> bool {
    let aligned = start.next_multiple_of(8).min(end);
    let (words, rest) = tags[aligned..end].as_chunks::<8>();
    tags[start..aligned].iter().any(|tag| *tag != 0)
        || words.iter().any(|word| u64::from_ne_bytes(*word) != 0)
        || rest.iter().any(|tag| *tag != 0)
}

impl Buddy {
    /// Takes `storage` and frees every range of `free` (the boot free list)
    /// into it, in order. The caller has checked the storage's lengths
    /// against `initial` (`accepts_buddy_storage`), and every free range lies
    /// inside one initial range: the initial ranges never touch, since the
    /// boot list merges touching ranges and a reservation leaves a gap.
    pub(super) fn seed(storage: BuddyStorage, initial: &[PageRange], free: &[PageRange]) -> Self {
        let BuddyStorage {
            tags,
            links,
            bases,
            hints,
        } = storage;
        tags.fill(0);
        links.fill(FreeLink::EMPTY);
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
            hint_shift: shift,
            heads: [0; BUDDY_ORDERS],
            nonempty: 0,
            free_pages: 0,
        };
        let mut total = 0_u64;
        for range in free {
            let index = buddy
                .range_index(initial, range.start)
                .expect("a boot free range lies inside one initial range");
            buddy.insert_range(initial, index, first_pfn(*range), range.page_count());
            total += range.page_count();
        }
        buddy.free_pages = total;
        buddy
    }

    /// The initial range holding `physical`: from the hint of its granule,
    /// upward over the ranges that can still hold it.
    pub(super) fn range_index(&self, ranges: &[PageRange], physical: u64) -> Option<usize> {
        let granule = usize::try_from(physical >> self.hint_shift).ok()?;
        let mut index = *self.hints.get(granule)? as usize;
        while let Some(range) = ranges.get(index) {
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
    fn position(&self, ranges: &[PageRange], index: usize, pfn: u64) -> usize {
        (self.bases[index] + (pfn - first_pfn(ranges[index]))) as usize
    }

    /// The initial range and the page number of the page at `position`.
    fn page_at(&self, ranges: &[PageRange], position: usize) -> (usize, u64) {
        let index = self.bases.partition_point(|base| *base <= position as u64) - 1;
        (
            index,
            first_pfn(ranges[index]) + (position as u64 - self.bases[index]),
        )
    }

    pub(super) fn page_position(&self, ranges: &[PageRange], physical: u64) -> Option<usize> {
        let index = self.range_index(ranges, physical)?;
        usize::try_from(self.bases[index] + (physical - ranges[index].start) / BASE_PAGE_SIZE).ok()
    }

    /// Puts the free block at `position` on the head of list `order`.
    fn push(&mut self, order: u32, position: usize) {
        let link = position as u32 + 1;
        let head = self.heads[order as usize];
        self.links[position] = FreeLink {
            next: head,
            prev: 0,
        };
        if head != 0 {
            self.links[head as usize - 1].prev = link;
        }
        self.heads[order as usize] = link;
        self.nonempty |= 1 << order;
        self.tags[position] = order as u8 + 1;
    }

    /// Takes the free block at `position` off list `order` and clears its tag.
    fn unlink(&mut self, order: u32, position: usize) {
        let FreeLink { next, prev } = self.links[position];
        if prev == 0 {
            self.heads[order as usize] = next;
        } else {
            self.links[prev as usize - 1].next = next;
        }
        if next != 0 {
            self.links[next as usize - 1].prev = prev;
        }
        if self.heads[order as usize] == 0 {
            self.nonempty &= !(1 << order);
        }
        self.links[position] = FreeLink::EMPTY;
        self.tags[position] = 0;
    }

    /// Frees the aligned block of 2^`order` pages at `pfn`, inside
    /// `ranges[index]`, merging it with its free buddies while the merged
    /// block stays inside that range.
    fn insert_block(&mut self, ranges: &[PageRange], index: usize, pfn: u64, order: u32) {
        let range = ranges[index];
        let (mut pfn, mut order) = (pfn, order);
        while order < MAX_ORDER {
            let buddy = pfn ^ (1_u64 << order);
            let merged = pfn.min(buddy);
            if !block_inside(range, merged, order + 1) {
                break;
            }
            let position = self.position(ranges, index, buddy);
            if u32::from(self.tags[position]) != order + 1 {
                break;
            }
            self.unlink(order, position);
            pfn = merged;
            order += 1;
        }
        let position = self.position(ranges, index, pfn);
        self.push(order, position);
    }

    /// Frees `pages` pages from `pfn`, inside `ranges[index]`, as maximal
    /// aligned blocks. Never touches `free_pages`; its callers do.
    fn insert_range(&mut self, ranges: &[PageRange], index: usize, pfn: u64, pages: u64) {
        let (mut pfn, mut pages) = (pfn, pages);
        while pages > 0 {
            let order = pfn.trailing_zeros().min(pages.ilog2()).min(MAX_ORDER);
            self.insert_block(ranges, index, pfn, order);
            pfn += 1_u64 << order;
            pages -= 1_u64 << order;
        }
    }

    /// Takes the free block of `order` at `position`: its first `page_count`
    /// pages are the run, the rest goes back at once.
    fn take(
        &mut self,
        ranges: &[PageRange],
        order: u32,
        position: usize,
        page_count: u64,
    ) -> PageRange {
        let (index, pfn) = self.page_at(ranges, position);
        self.unlink(order, position);
        let block = 1_u64 << order;
        if block > page_count {
            self.insert_range(ranges, index, pfn + page_count, block - page_count);
        }
        self.free_pages -= page_count;
        PageRange {
            start: pfn * BASE_PAGE_SIZE,
            end: (pfn + page_count) * BASE_PAGE_SIZE,
        }
    }

    /// `page_count` is non-zero and its byte length does not overflow.
    pub(super) fn allocate_run(
        &mut self,
        ranges: &[PageRange],
        page_count: u64,
    ) -> Result<PageRange, PhysicalMemoryError> {
        let order = order_for(page_count).ok_or(PhysicalMemoryError::NoFramesAvailable)?;
        let available = self.nonempty >> order;
        if available == 0 {
            return Err(PhysicalMemoryError::NoFramesAvailable);
        }
        let found = order + available.trailing_zeros();
        let position = self.heads[found as usize] as usize - 1;
        Ok(self.take(ranges, found, position, page_count))
    }

    /// `page_count` is non-zero and its byte length does not overflow;
    /// `ceiling` is already bounded by the physical limit.
    pub(super) fn allocate_run_below(
        &mut self,
        ranges: &[PageRange],
        page_count: u64,
        ceiling: u64,
    ) -> Result<PageRange, PhysicalMemoryError> {
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
            let position = self.heads[found as usize] as usize - 1;
            if fits(self.page_at(ranges, position).1) {
                return Ok(self.take(ranges, found, position, page_count));
            }
        }
        // Then the tags upward from the lowest allocator page.
        for (index, range) in ranges.iter().enumerate() {
            let mut pfn = first_pfn(*range);
            while pfn < end_pfn(*range) {
                if !fits(pfn) {
                    return Err(PhysicalMemoryError::NoFramesAvailable);
                }
                let position = self.position(ranges, index, pfn);
                match self.tags[position] {
                    0 => pfn += 1,
                    tag => {
                        let found = u32::from(tag) - 1;
                        if found >= order {
                            return Ok(self.take(ranges, found, position, page_count));
                        }
                        pfn += 1_u64 << found;
                    }
                }
            }
        }
        Err(PhysicalMemoryError::NoFramesAvailable)
    }

    /// `range` is a valid page range below the physical limit.
    pub(super) fn free_run(
        &mut self,
        ranges: &[PageRange],
        range: PageRange,
    ) -> Result<(), PhysicalMemoryError> {
        let index = self
            .range_index(ranges, range.start)
            .filter(|index| ranges[*index].contains(range))
            .ok_or(PhysicalMemoryError::InvalidFrame)?;
        if self.overlaps_free_in(ranges, index, range) {
            return Err(PhysicalMemoryError::DoubleFree);
        }
        self.insert_range(ranges, index, first_pfn(range), range.page_count());
        self.free_pages += range.page_count();
        Ok(())
    }

    /// Whether any page of `range`, a non-empty page range inside
    /// `ranges[index]`, is free: exactly when a free block starts inside it,
    /// or one starting below it reaches into it.
    fn overlaps_free_in(&self, ranges: &[PageRange], index: usize, range: PageRange) -> bool {
        let pfn = first_pfn(range);
        let start = self.position(ranges, index, pfn);
        if any_tag(self.tags, start, start + range.page_count() as usize) {
            return true;
        }
        let low = first_pfn(ranges[index]);
        for order in 1..=MAX_ORDER {
            let head = pfn & !((1_u64 << order) - 1);
            if head < low {
                break;
            }
            if head < pfn && u32::from(self.tags[self.position(ranges, index, head)]) == order + 1 {
                return true;
            }
        }
        false
    }

    pub(super) fn overlaps_free(&self, ranges: &[PageRange], range: PageRange) -> bool {
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
                clipped.start < clipped.end
                    && self.overlaps_free_in(ranges, first + offset, clipped)
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

    /// Checks I1 to I6; any violation is reported as `InvalidFrame`.
    pub(super) fn check(&self, ranges: &[PageRange]) -> Result<(), PhysicalMemoryError> {
        const VIOLATION: Result<(), PhysicalMemoryError> = Err(PhysicalMemoryError::InvalidFrame);
        let total = ranges.iter().map(|range| range.page_count()).sum::<u64>();
        if self.bases.len() != ranges.len()
            || u64::try_from(self.tags.len()) != Ok(total)
            || self.links.len() != self.tags.len()
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
                let position = self.position(ranges, index, pfn);
                let tag = self.tags[position];
                if tag == 0 {
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
                        && u32::from(self.tags[self.position(ranges, index, buddy)]) == order + 1
                    {
                        return VIOLATION;
                    }
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
    #[cfg(test)]
    pub(super) fn free_blocks<'a>(
        &'a self,
        ranges: &'a [PageRange],
    ) -> impl Iterator<Item = (u64, u32)> + 'a {
        ranges.iter().enumerate().flat_map(move |(index, range)| {
            (first_pfn(*range)..end_pfn(*range)).filter_map(move |pfn| {
                let tag = self.tags[self.position(ranges, index, pfn)];
                (tag != 0).then(|| (pfn * BASE_PAGE_SIZE, u32::from(tag) - 1))
            })
        })
    }
}
