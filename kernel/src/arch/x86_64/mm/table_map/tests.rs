//! The table map's pieces and leaves (DW2 M7 §12.9 item 1).

extern crate std;
use std::vec::Vec;

use super::*;

/// A fixed-seed xorshift generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Up to six disjoint pieces, in a shuffled physical order, with starts
/// and lengths aligned to 4 KiB, 2 MiB or 1 GiB at random.
fn generated_pieces(rng: &mut Rng) -> Vec<(u64, u64)> {
    let units = [1, 512, 512 * 512];
    let mut pieces = Vec::new();
    let mut next = 0x10_0000 / PAGE_SIZE;
    for _ in 0..1 + rng.below(6) {
        let unit = units[rng.below(3) as usize];
        let start = next.next_multiple_of(unit) + unit * rng.below(2) + rng.below(3);
        let pages = match rng.below(4) {
            0 => 1 + rng.below(700),
            1 => unit * (1 + rng.below(3)),
            2 => unit * (1 + rng.below(3)) + rng.below(600),
            _ => 512 * (1 + rng.below(40)) + rng.below(2),
        };
        pieces.push((start * PAGE_SIZE, pages));
        next = start + pages + rng.below(1000);
    }
    // Map order need not be physical order.
    for index in (1..pieces.len()).rev() {
        let other = rng.below(index as u64 + 1) as usize;
        pieces.swap(index, other);
    }
    pieces
}

fn map_of(pieces: &[(u64, u64)], gigabyte_pages: bool) -> TableMap {
    let mut map = TableMap::empty();
    map.fill(pieces.iter().copied(), gigabyte_pages).unwrap();
    map
}

#[test]
fn leaves_cover_every_piece_once_with_the_largest_aligned_leaf() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut levels = [0_usize; 3];
    for _ in 0..120 {
        let pieces = generated_pieces(&mut rng);
        for gigabyte_pages in [false, true] {
            let map = map_of(&pieces, gigabyte_pages);
            assert_eq!(map.gigabyte_pages(), gigabyte_pages);
            let mut leaves = map.leaves().peekable();
            let mut offset = 0;
            for &(physical, pages) in &pieces {
                let bytes = pages * PAGE_SIZE;
                let mut into = 0;
                while into < bytes {
                    let leaf = leaves.next().expect("a leaf for every byte");
                    let size = leaf.size();
                    assert_eq!(leaf.virtual_address, TABLE_MAP_BASE + offset + into);
                    assert_eq!(leaf.physical, physical + into, "{pieces:?}");
                    assert_eq!(leaf.virtual_address % size, 0);
                    assert_eq!(leaf.physical % size, 0);
                    assert!(into + size <= bytes, "the leaf ends inside its piece");
                    assert!(gigabyte_pages || leaf.level < 2);
                    // The largest: a bigger leaf is unaligned in one of the
                    // two spaces, ends past the piece, or is not allowed.
                    if leaf.level < 2 {
                        let bigger = size << 9;
                        assert!(
                            !(leaf.virtual_address | leaf.physical).is_multiple_of(bigger)
                                || into + bigger > bytes
                                || (leaf.level == 1 && !gigabyte_pages),
                            "{leaf:?} in {pieces:?}"
                        );
                    }
                    assert_eq!(
                        map.translate(leaf.virtual_address),
                        Some((leaf.physical, bytes - into))
                    );
                    assert_eq!(
                        map.translate(leaf.virtual_address + size - 1),
                        Some((leaf.physical + size - 1, bytes - into - size + 1))
                    );
                    levels[usize::from(leaf.level)] += 1;
                    into += size;
                }
                offset += bytes;
            }
            assert!(leaves.peek().is_none());
            assert_eq!(map.mapped_bytes(), offset);
            assert_eq!(map.translate(TABLE_MAP_BASE + offset), None);
            assert_eq!(map.translate(TABLE_MAP_BASE - 1), None);
        }
    }
    assert!(levels[1] > 1000 && levels[2] > 5, "{levels:?}");
}

#[test]
fn a_two_megabyte_piece_after_an_unaligned_one_maps_in_small_leaves() {
    // The first piece leaves the second's virtual start 4 KiB past a 2 MiB
    // boundary, so though the second is 2 MiB-aligned in RAM, it gets no
    // large leaf.
    let map = map_of(&[(0x20_0000, 1), (0x40_0000, 512)], true);
    assert!(map.leaves().all(|leaf| leaf.level == 0));
    assert_eq!(map.leaves().count(), 513);
    // Aligned in both spaces, it does.
    let map = map_of(&[(0x20_0000, 512), (0x60_0000, 512)], true);
    assert_eq!(map.leaves().filter(|leaf| leaf.level == 1).count(), 2);
}

#[test]
fn push_refuses_bad_pieces_and_changes_nothing() {
    let mut map = map_of(&[(0x10_0000, 16), (0x40_0000, 8)], false);
    let before = map;
    for (physical, pages, error) in [
        (0x80_0000, 0, TableMapError::InvalidPiece),
        (0x80_0800, 1, TableMapError::InvalidPiece),
        (!0xfff, 2, TableMapError::InvalidPiece),
        (0x10_f000, 2, TableMapError::InvalidPiece),
        (0x3f_f000, 2, TableMapError::InvalidPiece),
        (
            0x8000_0000,
            TABLE_MAP_SPAN / PAGE_SIZE,
            TableMapError::BeyondSpan,
        ),
        (0x8000_0000, u64::MAX / 2, TableMapError::InvalidPiece),
    ] {
        assert_eq!(map.push(physical, pages), Err(error), "{physical:#x}");
        assert_eq!(map, before);
    }
    // Exactly the span is accepted.
    let mut whole = TableMap::empty();
    assert_eq!(whole.push(0, TABLE_MAP_SPAN / PAGE_SIZE), Ok(()));
    assert_eq!(
        whole.push(TABLE_MAP_SPAN, 1),
        Err(TableMapError::BeyondSpan)
    );

    let mut full = TableMap::empty();
    for index in 0..TABLE_MAP_CAPACITY as u64 {
        full.push(index * 2 * PAGE_SIZE, 1).unwrap();
    }
    let before = full;
    assert_eq!(full.push(1 << 40, 1), Err(TableMapError::Capacity));
    assert_eq!(full, before);
}

#[test]
fn the_region_is_two_pml4_slots_from_slot_384() {
    assert!(in_table_map_region(TABLE_MAP_BASE));
    assert!(in_table_map_region(TABLE_MAP_BASE + TABLE_MAP_SPAN - 1));
    assert!(!in_table_map_region(TABLE_MAP_BASE + TABLE_MAP_SPAN));
    assert!(!in_table_map_region(TABLE_MAP_BASE - 1));
    assert!(!super::super::direct_map::in_direct_map_region(
        TABLE_MAP_BASE
    ));
    assert_eq!((TABLE_MAP_BASE + TABLE_MAP_SPAN - 1) >> 39 & 0x1ff, 385);
}

#[test]
fn leaf_entries_are_supervisor_no_execute_and_writable() {
    let map = map_of(&[(0x4000_0000, 512 * 512 + 513)], true);
    let leaves: Vec<_> = map.leaves().collect();
    assert_eq!(
        leaves.iter().map(|leaf| leaf.level).collect::<Vec<_>>(),
        [2, 1, 0]
    );
    assert_eq!(leaves[0].entry(), 0x4000_0000 | DIRECT_MAP_LARGE_FLAGS);
    assert_eq!(
        leaves[2].entry(),
        leaves[2].physical | DIRECT_MAP_PAGE_FLAGS
    );
    // Without 1 GiB pages the same piece takes 2 MiB leaves.
    let without = map.with_gigabyte_pages(false);
    assert_eq!(without.leaves().filter(|leaf| leaf.level == 1).count(), 513);
    assert!(without.leaves().all(|leaf| leaf.level < 2));
}
