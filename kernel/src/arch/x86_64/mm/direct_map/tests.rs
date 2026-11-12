extern crate std;
use std::vec::Vec;

use super::*;

fn range(start: u64, end: u64) -> PhysicalRange {
    PhysicalRange::new(start, end - start).unwrap()
}

fn covered(start: u64, end: u64, gigabyte_pages: bool) -> Vec<DirectLeaf> {
    leaves(start, end, gigabyte_pages).collect()
}

#[test]
fn leaves_tile_a_range_exactly_with_the_largest_pages_that_fit() {
    for gigabyte_pages in [false, true] {
        for (start, end) in [
            (0x1000, 0x9f000),
            (0x10_0000, 0x7fe0_0000),
            (0x1000, 3 * ONE_GIB + 0x5000),
            (ONE_GIB, 3 * ONE_GIB),
            (TWO_MIB - PAGE_SIZE, TWO_MIB + PAGE_SIZE),
        ] {
            let mut next = start;
            for leaf in covered(start, end, gigabyte_pages) {
                assert_eq!(leaf.physical, next, "leaves are contiguous");
                assert_eq!(leaf.physical % leaf.size(), 0, "leaves are aligned");
                assert!(
                    leaf.physical + leaf.size() <= end,
                    "no leaf leaves the range"
                );
                assert!(gigabyte_pages || leaf.level < 2);
                // The largest page: a bigger one would be unaligned or
                // cross the end.
                if leaf.level < 2 && (gigabyte_pages || leaf.level < 1) {
                    let bigger = leaf.size() << 9;
                    assert!(leaf.physical % bigger != 0 || leaf.physical + bigger > end);
                }
                next += leaf.size();
            }
            assert_eq!(next, end);
        }
    }
}

#[test]
fn gigabyte_pages_are_used_only_when_the_cpu_has_them() {
    let with = covered(ONE_GIB, 3 * ONE_GIB, true);
    assert_eq!(with.len(), 2);
    assert!(with.iter().all(|leaf| leaf.level == 2));
    let without = covered(ONE_GIB, 3 * ONE_GIB, false);
    assert_eq!(without.len(), 1024);
    assert!(without.iter().all(|leaf| leaf.level == 1));
}

#[test]
fn leaf_entries_are_supervisor_no_execute_and_writable() {
    let page = DirectLeaf {
        physical: 0x5000,
        level: 0,
    };
    assert_eq!(page.entry(), 0x5000 | PRESENT | WRITABLE | NO_EXECUTE);
    let large = DirectLeaf {
        physical: ONE_GIB,
        level: 2,
    };
    assert_eq!(
        large.entry(),
        ONE_GIB | PRESENT | WRITABLE | NO_EXECUTE | HUGE
    );
    assert_eq!(large.virtual_address(), DIRECT_MAP_BASE + ONE_GIB);
    for entry in [page.entry(), large.entry()] {
        assert_eq!(entry & super::super::USER, 0);
        assert_eq!(entry & super::super::GLOBAL, 0);
    }
}

#[test]
fn the_map_answers_only_for_bytes_inside_one_range() {
    let map =
        DirectMap::from_ranges([range(0x1000, 0x9f000), range(0x10_0000, 0x20_0000)]).unwrap();
    assert!(map.contains(0x1000, PAGE_SIZE));
    assert!(map.contains(0x9e000, PAGE_SIZE));
    assert!(!map.contains(0x9f000, PAGE_SIZE));
    assert!(!map.contains(0, PAGE_SIZE));
    assert!(
        !map.contains(0x9e000, 2 * PAGE_SIZE),
        "a span crossing a range's end"
    );
    assert!(
        !map.contains(0xff000, 2 * PAGE_SIZE),
        "a span starting in a gap"
    );
    assert!(map.contains(0x10_0000, 0x10_0000));
    assert!(!map.contains(0x1f_f000, 0x2000));
    assert!(!map.contains(u64::MAX - 1, 4));
    assert_eq!(
        map.virtual_address(0x10_0008, 8),
        Some(DIRECT_MAP_BASE + 0x10_0008)
    );
    assert_eq!(map.virtual_address(0x9f000, 8), None);
    assert!(map.overlaps(0x9e000, 0x2000));
    assert!(map.overlaps(0xff000, 0x2000));
    assert!(!map.overlaps(0x9f000, 0x61000));
    assert!(!map.overlaps(0x20_0000, PAGE_SIZE));
    assert_eq!(map.mapped_bytes(), 0x9e000 + 0x10_0000);
}

#[test]
fn the_map_refuses_unsorted_overlapping_or_unreachable_ranges() {
    assert_eq!(
        DirectMap::from_ranges([range(0x10_0000, 0x20_0000), range(0x1000, 0x2000)]),
        Err(DirectMapError::InvalidRange)
    );
    assert_eq!(
        DirectMap::from_ranges([range(0x1000, 0x3000), range(0x2000, 0x4000)]),
        Err(DirectMapError::InvalidRange)
    );
    assert_eq!(
        DirectMap::from_ranges([PhysicalRange::new(0x1800, 0x1000).unwrap()]),
        Err(DirectMapError::InvalidRange)
    );
    assert_eq!(
        DirectMap::from_ranges([range(
            DIRECT_MAP_SPAN - PAGE_SIZE,
            DIRECT_MAP_SPAN + PAGE_SIZE
        )]),
        Err(DirectMapError::BeyondSpan)
    );
    assert!(DirectMap::from_ranges([range(0x1000, 0x2000), range(0x2000, 0x3000)]).is_ok());
    let too_many = (0..=DIRECT_MAP_RANGE_CAPACITY as u64)
        .map(|index| range((2 * index + 1) * PAGE_SIZE, (2 * index + 2) * PAGE_SIZE));
    assert_eq!(
        DirectMap::from_ranges(too_many),
        Err(DirectMapError::Capacity)
    );
}

#[test]
fn the_region_is_the_direct_map_slots_only() {
    assert!(in_direct_map_region(DIRECT_MAP_BASE));
    assert!(in_direct_map_region(DIRECT_MAP_BASE + DIRECT_MAP_SPAN - 1));
    assert!(!in_direct_map_region(DIRECT_MAP_BASE + DIRECT_MAP_SPAN));
    assert!(!in_direct_map_region(DIRECT_MAP_BASE - 1));
    // The scratch window and the kernel image lie above it.
    assert!(!in_direct_map_region(0xffff_ff00_0000_0000));
    assert!(!in_direct_map_region(0xffff_ffff_8000_0000));
}

#[test]
fn filling_in_place_replaces_whatever_the_storage_held() {
    let ranges = [range(0x1000, 0x9f000), range(0x10_0000, 0x20_0000)];
    let mut map = DirectMap::from_ranges([range(0x50_0000, 0x60_0000)]).unwrap();
    map.fill(ranges, true).unwrap();
    assert_eq!(
        map,
        DirectMap::from_ranges(ranges)
            .unwrap()
            .with_gigabyte_pages(true)
    );
    assert_eq!(
        map.fill([range(0x2000, 0x3000), range(0x1000, 0x2000)], false),
        Err(DirectMapError::InvalidRange)
    );
}
