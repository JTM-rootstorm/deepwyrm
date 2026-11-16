//! The grown frame-role table's kernel mapping (DW2 large-memory plan, M7
//! §12.9).
//!
//! The table's RAM is taken in pieces while the deep root is built, and the
//! pieces are mapped back to back from [`TABLE_MAP_BASE`]: piece `k` at the
//! base plus the lengths of the pieces before it. So the table is one
//! virtual range, and the role manager carves it from one base as it did
//! when the table was one run. The leaves are read-write, no-execute and
//! supervisor-only, the direct map's flags. Each is the largest of 1 GiB
//! (where the CPU has them), 2 MiB and 4 KiB for which the virtual and the
//! physical address are both aligned and the leaf ends inside its piece.
//! The mapping is made before the deep root is first loaded and never
//! changes.

#![cfg_attr(
    not(any(test, all(target_os = "none", target_arch = "x86_64"))),
    allow(dead_code, reason = "the builder and live access are target-only")
)]

use super::PAGE_SIZE;
use super::direct_map::{
    DIRECT_MAP_BASE, DIRECT_MAP_LARGE_FLAGS, DIRECT_MAP_PAGE_FLAGS, DIRECT_MAP_RANGE_CAPACITY,
    DIRECT_MAP_SPAN, ONE_GIB, TWO_MIB,
};

/// The first byte of the table map: PML4 slot 384, the first slot after the
/// direct map's 128.
pub(crate) const TABLE_MAP_BASE: u64 = 0xffff_c000_0000_0000;
/// The PML4 slots the table map may use, from slot 384.
pub(crate) const TABLE_MAP_PML4_SLOTS: u64 = 2;
/// 1 TiB: the table of the 64 TiB the direct map can span is 1.49% of it.
pub(crate) const TABLE_MAP_SPAN: u64 = TABLE_MAP_PML4_SLOTS << 39;
/// The most pieces: as many as the direct map has ranges, and as many as
/// the role manager stages.
pub(crate) const TABLE_MAP_CAPACITY: usize = DIRECT_MAP_RANGE_CAPACITY;

const _: () = {
    assert!((TABLE_MAP_BASE >> 39) & 0x1ff == 384);
    // The table map lies above the direct map and below the scratch window
    // (slot 510) and the kernel image (slot 511).
    assert!(DIRECT_MAP_BASE + DIRECT_MAP_SPAN <= TABLE_MAP_BASE);
    assert!(384 + TABLE_MAP_PML4_SLOTS <= 510);
    assert!(TABLE_MAP_CAPACITY == crate::memory::frame_roles::MAX_GROWTH_PARTS);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TableMapError {
    /// More pieces than [`TABLE_MAP_CAPACITY`].
    Capacity,
    /// A piece is empty, unaligned, overflows, or overlaps an earlier one.
    InvalidPiece,
    /// The pieces together pass [`TABLE_MAP_SPAN`].
    BeyondSpan,
}

/// One piece: its physical start and its bytes (whole pages), and where it
/// lies in the map, in bytes from the base.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TablePiece {
    pub(crate) physical: u64,
    pub(crate) bytes: u64,
    pub(crate) offset: u64,
}

/// The pieces the table map covers, in map order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TableMap {
    pieces: [TablePiece; TABLE_MAP_CAPACITY],
    len: usize,
    /// Bytes mapped in all: the offset after the last piece.
    bytes: u64,
    /// Whether 1 GiB leaves may appear: the CPU maps them.
    gigabyte_pages: bool,
}

impl TableMap {
    #[cfg(test)]
    pub(crate) const fn empty() -> Self {
        Self {
            pieces: [TablePiece {
                physical: 0,
                bytes: 0,
                offset: 0,
            }; TABLE_MAP_CAPACITY],
            len: 0,
            bytes: 0,
            gigabyte_pages: false,
        }
    }

    /// Fills `self`, which may hold anything, with the map of `pieces`
    /// (physical start, pages), in order, in place.
    pub(crate) fn fill(
        &mut self,
        pieces: impl IntoIterator<Item = (u64, u64)>,
        gigabyte_pages: bool,
    ) -> Result<(), TableMapError> {
        self.len = 0;
        self.bytes = 0;
        self.gigabyte_pages = gigabyte_pages;
        for (physical, pages) in pieces {
            self.push(physical, pages)?;
        }
        Ok(())
    }

    /// Appends the piece of `pages` pages at `physical`. Refuses an empty or
    /// unaligned piece, one that overflows or overlaps an earlier piece, one
    /// past the capacity and one past the span; a refusal changes nothing.
    pub(crate) fn push(&mut self, physical: u64, pages: u64) -> Result<(), TableMapError> {
        let bytes = pages
            .checked_mul(PAGE_SIZE)
            .filter(|bytes| *bytes > 0)
            .ok_or(TableMapError::InvalidPiece)?;
        let end = physical
            .checked_add(bytes)
            .filter(|_| physical.is_multiple_of(PAGE_SIZE))
            .ok_or(TableMapError::InvalidPiece)?;
        if self
            .pieces()
            .iter()
            .any(|piece| physical < piece.physical + piece.bytes && piece.physical < end)
        {
            return Err(TableMapError::InvalidPiece);
        }
        if self.len == TABLE_MAP_CAPACITY {
            return Err(TableMapError::Capacity);
        }
        let total = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= TABLE_MAP_SPAN)
            .ok_or(TableMapError::BeyondSpan)?;
        self.pieces[self.len] = TablePiece {
            physical,
            bytes,
            offset: self.bytes,
        };
        self.len += 1;
        self.bytes = total;
        Ok(())
    }

    pub(crate) fn pieces(&self) -> &[TablePiece] {
        &self.pieces[..self.len]
    }

    pub(crate) const fn gigabyte_pages(&self) -> bool {
        self.gigabyte_pages
    }

    #[cfg(test)]
    pub(crate) fn with_gigabyte_pages(mut self, gigabyte_pages: bool) -> Self {
        self.gigabyte_pages = gigabyte_pages;
        self
    }

    /// Bytes mapped in all.
    pub(crate) const fn mapped_bytes(&self) -> u64 {
        self.bytes
    }

    /// The physical address `virtual_address` maps to and the bytes left in
    /// its piece from there; `None` outside the mapped bytes.
    pub(crate) fn translate(&self, virtual_address: u64) -> Option<(u64, u64)> {
        let offset = virtual_address
            .checked_sub(TABLE_MAP_BASE)
            .filter(|offset| *offset < self.bytes)?;
        // The last piece starting at or below `offset`.
        let pieces = self.pieces();
        let index = pieces.partition_point(|piece| piece.offset <= offset);
        let piece = pieces.get(index.checked_sub(1)?)?;
        let into = offset - piece.offset;
        Some((piece.physical + into, piece.bytes - into))
    }

    /// The leaves that map every piece, in map order.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = TableLeaf> + '_ {
        let gigabyte_pages = self.gigabyte_pages;
        self.pieces().iter().flat_map(move |piece| {
            let mut into = 0;
            core::iter::from_fn(move || {
                if into >= piece.bytes {
                    return None;
                }
                let leaf = leaf_at(
                    TABLE_MAP_BASE + piece.offset + into,
                    piece.physical + into,
                    piece.bytes - into,
                    gigabyte_pages,
                );
                into += leaf.size();
                Some(leaf)
            })
        })
    }
}

/// One leaf of the table map: the address it maps, the physical address it
/// maps to, and its level (0 for 4 KiB, 1 for 2 MiB, 2 for 1 GiB).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TableLeaf {
    pub(crate) virtual_address: u64,
    pub(crate) physical: u64,
    pub(crate) level: u8,
}

impl TableLeaf {
    pub(crate) const fn size(self) -> u64 {
        PAGE_SIZE << (9 * self.level as u32)
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

/// The largest leaf at `virtual_address` mapping `physical` that stays
/// inside the `left` bytes of its piece.
pub(crate) const fn leaf_at(
    virtual_address: u64,
    physical: u64,
    left: u64,
    gigabyte_pages: bool,
) -> TableLeaf {
    let both = virtual_address | physical;
    let level = if gigabyte_pages && both.is_multiple_of(ONE_GIB) && left >= ONE_GIB {
        2
    } else if both.is_multiple_of(TWO_MIB) && left >= TWO_MIB {
        1
    } else {
        0
    };
    TableLeaf {
        virtual_address,
        physical,
        level,
    }
}

/// Whether a kernel virtual address lies in the table map's PML4 slots.
pub(crate) const fn in_table_map_region(virtual_address: u64) -> bool {
    virtual_address >= TABLE_MAP_BASE && virtual_address - TABLE_MAP_BASE < TABLE_MAP_SPAN
}

/// The kernel's one table map, filled once while the deep root is built and
/// read-only from then on.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) static TABLE_MAP: crate::one_shot::OneShotStorage<TableMap> =
    crate::one_shot::OneShotStorage::new();

#[cfg(test)]
#[path = "table_map/tests.rs"]
mod tests;
