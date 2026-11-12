//! The kernel's direct map (DW2 large-memory plan, M2).
//!
//! Every frame the frame allocator can ever hand out is mapped once, at
//! [`DIRECT_MAP_BASE`] plus its physical address, in the kernel half of the
//! primordial root, and so in every root that copies the kernel half. The
//! mapping is read-write, no-execute and supervisor-only, and it never
//! changes after activation. It covers exactly the allocator's initial ranges:
//! not the kernel image, the boot modules, firmware tables or device memory,
//! which keep the per-CPU scratch window. So the kernel image has no writable
//! alias, and nothing but RAM the allocator owns is mapped write-back.
//!
//! Each range is mapped with the largest pages that fit: 1 GiB where the CPU
//! has them (`pdpe1gb`), 2 MiB otherwise, and 4 KiB only at a range's
//! unaligned ends, so no page reaches memory outside the range.

#![cfg_attr(
    not(any(test, all(target_os = "none", target_arch = "x86_64"))),
    allow(dead_code, reason = "the builder and live access are target-only")
)]

use crate::memory::physical::PhysicalRange;

use super::{HUGE, NO_EXECUTE, PAGE_SIZE, PRESENT, WRITABLE};

/// The first byte of the direct map: PML4 slot 256, the start of the
/// kernel half.
pub(crate) const DIRECT_MAP_BASE: u64 = 0xffff_8000_0000_0000;
/// The PML4 slots the direct map may use, from slot 256. The scratch window
/// (slot 510) and the kernel image (slot 511) lie above them.
pub(crate) const DIRECT_MAP_PML4_SLOTS: u64 = 128;
/// Physical memory at or above this (64 TiB) cannot be direct mapped; a boot
/// whose allocator would own such memory stops.
pub(crate) const DIRECT_MAP_SPAN: u64 = DIRECT_MAP_PML4_SLOTS << 39;
/// The most ranges the direct map holds: the allocator's initial ranges,
/// which are at most the sanitized usable ranges plus one split per
/// bootstrap reservation (`memory::physical::free_range_bound` with no live
/// runs).
pub(crate) const DIRECT_MAP_RANGE_CAPACITY: usize =
    crate::memory::boot_map::MAX_SANITIZED_USABLE_RANGES
        + crate::memory::boot_map::MAX_BOOTSTRAP_RESERVATIONS;

/// The flags of a 4 KiB direct-map leaf.
pub(crate) const DIRECT_MAP_PAGE_FLAGS: u64 = PRESENT | WRITABLE | NO_EXECUTE;
/// The flags of a 2 MiB or 1 GiB direct-map leaf.
pub(crate) const DIRECT_MAP_LARGE_FLAGS: u64 = PRESENT | WRITABLE | NO_EXECUTE | HUGE;

pub(crate) const TWO_MIB: u64 = 1 << 21;
pub(crate) const ONE_GIB: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectMapError {
    /// More ranges than [`DIRECT_MAP_RANGE_CAPACITY`].
    Capacity,
    /// A range is empty, unaligned, out of order or overlapping.
    InvalidRange,
    /// A range reaches [`DIRECT_MAP_SPAN`].
    BeyondSpan,
}

/// The physical ranges the direct map covers, sorted and disjoint, each a
/// whole number of pages below [`DIRECT_MAP_SPAN`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectMap {
    /// `(start, end)` byte addresses, end exclusive.
    ranges: [(u64, u64); DIRECT_MAP_RANGE_CAPACITY],
    len: usize,
    /// Whether 1 GiB leaves may appear: the CPU maps them.
    gigabyte_pages: bool,
}

impl DirectMap {
    #[cfg(test)]
    pub(crate) const fn empty() -> Self {
        Self {
            ranges: [(0, 0); DIRECT_MAP_RANGE_CAPACITY],
            len: 0,
            gigabyte_pages: false,
        }
    }

    /// Fills `self`, which may hold anything, with the map over `ranges`
    /// ([`Self::from_ranges`]), in place.
    pub(crate) fn fill(
        &mut self,
        ranges: impl IntoIterator<Item = PhysicalRange>,
        gigabyte_pages: bool,
    ) -> Result<(), DirectMapError> {
        self.len = 0;
        self.gigabyte_pages = gigabyte_pages;
        for range in ranges {
            self.push(range)?;
        }
        Ok(())
    }

    /// The direct map over `ranges`, which must be sorted, disjoint, page
    /// aligned and below [`DIRECT_MAP_SPAN`]. Adjacent ranges are kept
    /// apart, as the allocator keeps them.
    #[cfg(test)]
    pub(crate) fn from_ranges(
        ranges: impl IntoIterator<Item = PhysicalRange>,
    ) -> Result<Self, DirectMapError> {
        let mut map = Self::empty();
        for range in ranges {
            map.push(range)?;
        }
        Ok(map)
    }

    fn push(&mut self, range: PhysicalRange) -> Result<(), DirectMapError> {
        let start = range.physical_start();
        let end = range.end().map_err(|_| DirectMapError::InvalidRange)?;
        if start >= end || !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) {
            return Err(DirectMapError::InvalidRange);
        }
        if end > DIRECT_MAP_SPAN {
            return Err(DirectMapError::BeyondSpan);
        }
        if self.len > 0 && self.ranges[self.len - 1].1 > start {
            return Err(DirectMapError::InvalidRange);
        }
        if self.len == DIRECT_MAP_RANGE_CAPACITY {
            return Err(DirectMapError::Capacity);
        }
        self.ranges[self.len] = (start, end);
        self.len += 1;
        Ok(())
    }

    pub(crate) const fn gigabyte_pages(&self) -> bool {
        self.gigabyte_pages
    }

    #[cfg(test)]
    pub(crate) fn with_gigabyte_pages(mut self, gigabyte_pages: bool) -> Self {
        self.gigabyte_pages = gigabyte_pages;
        self
    }

    pub(crate) fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges[..self.len]
    }

    /// Bytes mapped in all.
    pub(crate) fn mapped_bytes(&self) -> u64 {
        self.ranges().iter().map(|(start, end)| end - start).sum()
    }

    /// Whether `[physical, physical + length)` lies inside one range.
    pub(crate) fn contains(&self, physical: u64, length: u64) -> bool {
        let Some(end) = physical.checked_add(length) else {
            return false;
        };
        // The last range starting at or below `physical`.
        let ranges = self.ranges();
        let index = ranges.partition_point(|(start, _)| *start <= physical);
        index > 0 && end <= ranges[index - 1].1
    }

    /// Whether any byte of `[physical, physical + length)` is mapped.
    pub(crate) fn overlaps(&self, physical: u64, length: u64) -> bool {
        let end = physical.saturating_add(length);
        let ranges = self.ranges();
        let index = ranges.partition_point(|(_, range_end)| *range_end <= physical);
        index < ranges.len() && ranges[index].0 < end
    }

    /// The direct-map address of `[physical, physical + length)`, when it
    /// lies inside one range.
    pub(crate) fn virtual_address(&self, physical: u64, length: u64) -> Option<u64> {
        self.contains(physical, length)
            .then(|| DIRECT_MAP_BASE + physical)
    }
}

/// Whether a kernel virtual address lies in the direct map's PML4 slots.
pub(crate) const fn in_direct_map_region(virtual_address: u64) -> bool {
    virtual_address >= DIRECT_MAP_BASE && virtual_address - DIRECT_MAP_BASE < DIRECT_MAP_SPAN
}

/// One leaf of the direct map: the physical address it maps and its level
/// (0 for 4 KiB, 1 for 2 MiB, 2 for 1 GiB).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectLeaf {
    pub(crate) physical: u64,
    pub(crate) level: u8,
}

impl DirectLeaf {
    pub(crate) const fn size(self) -> u64 {
        PAGE_SIZE << (9 * self.level as u32)
    }

    pub(crate) const fn virtual_address(self) -> u64 {
        DIRECT_MAP_BASE + self.physical
    }

    pub(crate) const fn entry(self) -> u64 {
        self.physical
            | if self.level == 0 {
                DIRECT_MAP_PAGE_FLAGS
            } else {
                DIRECT_MAP_LARGE_FLAGS
            }
    }
}

/// The largest leaf that maps `physical` and stays inside `[physical, end)`.
pub(crate) const fn leaf_at(physical: u64, end: u64, gigabyte_pages: bool) -> DirectLeaf {
    let level = if gigabyte_pages && physical.is_multiple_of(ONE_GIB) && end - physical >= ONE_GIB {
        2
    } else if physical.is_multiple_of(TWO_MIB) && end - physical >= TWO_MIB {
        1
    } else {
        0
    };
    DirectLeaf { physical, level }
}

/// The leaves that map `[start, end)`, in address order.
pub(crate) fn leaves(
    start: u64,
    end: u64,
    gigabyte_pages: bool,
) -> impl Iterator<Item = DirectLeaf> {
    let mut next = start;
    core::iter::from_fn(move || {
        if next >= end {
            return None;
        }
        let leaf = leaf_at(next, end, gigabyte_pages);
        next += leaf.size();
        Some(leaf)
    })
}

/// The kernel's one direct map, filled once while the deep root is built
/// and read-only from then on.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) static DIRECT_MAP: crate::one_shot::OneShotStorage<DirectMap> =
    crate::one_shot::OneShotStorage::new();

/// Whether the CPU maps 1 GiB pages (CPUID 0x8000_0001 EDX bit 26).
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn cpu_has_gigabyte_pages() -> bool {
    // Extended leaf 0x8000_0001 exists on every x86_64 CPU.
    let result = core::arch::x86_64::__cpuid(0x8000_0001);
    result.edx & (1 << 26) != 0
}

#[cfg(test)]
#[path = "direct_map/tests.rs"]
mod tests;
