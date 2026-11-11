extern crate std;

use super::*;
use std::boxed::Box;
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

struct Memory(BTreeMap<u64, u8>);

impl Memory {
    fn place(&mut self, address: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().copied().enumerate() {
            self.0.insert(address + offset as u64, byte);
        }
    }
}

impl AcpiByteReader for Memory {
    fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        for (offset, byte) in destination.iter_mut().enumerate() {
            *byte = *self.0.get(&(physical_start + offset as u64)).ok_or(())?;
        }
        Ok(())
    }
}

const RSDP: u64 = 0x1000;
const XSDT: u64 = 0x2000;
const FIRST_TABLE: u64 = 0x3000;

fn sum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |total, byte| total.wrapping_add(*byte))
}

fn seal(mut table: Vec<u8>) -> Vec<u8> {
    let length = table.len() as u32;
    table[4..8].copy_from_slice(&length.to_le_bytes());
    table[9] = 0;
    table[9] = 0_u8.wrapping_sub(sum(&table));
    table
}

fn table(signature: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; SDT_HEADER_BYTES];
    bytes[..4].copy_from_slice(signature);
    bytes.extend_from_slice(body);
    seal(bytes)
}

fn drhd(flags: u8, segment: u16, base: u64) -> Vec<u8> {
    let mut bytes = vec![0_u8; 16];
    bytes[0..2].copy_from_slice(&STRUCTURE_DRHD.to_le_bytes());
    bytes[2..4].copy_from_slice(&16_u16.to_le_bytes());
    bytes[4] = flags;
    bytes[6..8].copy_from_slice(&segment.to_le_bytes());
    bytes[8..16].copy_from_slice(&base.to_le_bytes());
    bytes
}

fn structure(kind: u16, length: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8; usize::from(length.max(4))];
    bytes[0..2].copy_from_slice(&kind.to_le_bytes());
    bytes[2..4].copy_from_slice(&length.to_le_bytes());
    bytes
}

/// A structure whose length runs past the end of the table.
fn overrunning() -> Vec<u8> {
    let mut bytes = structure(9, 8);
    bytes[2..4].copy_from_slice(&64_u16.to_le_bytes());
    bytes
}

/// A DMAR body: host address width byte, flags, ten reserved bytes, structures.
fn dmar(width_minus_one: u8, flags: u8, structures: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![width_minus_one, flags];
    body.extend_from_slice(&[0; 10]);
    for item in structures {
        body.extend_from_slice(item);
    }
    table(b"DMAR", &body)
}

fn firmware(tables: &[Vec<u8>]) -> Memory {
    let mut memory = Memory(BTreeMap::new());
    let mut entries = Vec::new();
    for (index, bytes) in tables.iter().enumerate() {
        let address = FIRST_TABLE + index as u64 * 0x1000;
        memory.place(address, bytes);
        entries.extend_from_slice(&address.to_le_bytes());
    }
    memory.place(XSDT, &table(b"XSDT", &entries));
    let mut rsdp = vec![0_u8; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[15] = 2;
    rsdp[20..24].copy_from_slice(&36_u32.to_le_bytes());
    rsdp[24..32].copy_from_slice(&XSDT.to_le_bytes());
    rsdp[8] = 0_u8.wrapping_sub(sum(&rsdp[..20]));
    rsdp[32] = 0_u8.wrapping_sub(sum(&rsdp));
    memory.place(RSDP, &rsdp);
    memory
}

fn discover(tables: &[Vec<u8>]) -> Result<Option<DmarSnapshot>, DmarError> {
    let mut workspace = Box::new(AcpiSnapshotWorkspace::new());
    discover_dmar(&mut firmware(tables), RSDP, &mut workspace)
}

fn q35_dmar() -> Vec<u8> {
    dmar(38, 1, &[drhd(1, 0, 0xfed9_0000)])
}

#[test]
fn the_q35_unit_is_found_among_other_tables() {
    let snapshot = discover(&[table(b"FACP", &[0; 8]), q35_dmar()])
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.host_address_width(), 39);
    assert!(snapshot.interrupt_remapping());
    assert_eq!(snapshot.units().len(), 1);
    assert_eq!(snapshot.units()[0].register_base(), 0xfed9_0000);
    assert!(snapshot.units()[0].include_pci_all());
    assert_eq!(snapshot.reserved_memory_regions(), 0);
}

#[test]
fn no_dmar_means_no_remapping_hardware() {
    assert_eq!(discover(&[table(b"FACP", &[0; 8])]), Ok(None));
}

#[test]
fn two_dmars_are_refused() {
    assert_eq!(
        discover(&[q35_dmar(), q35_dmar()]),
        Err(DmarError::DuplicateDmar)
    );
}

#[test]
fn a_bad_checksum_is_refused() {
    let mut bad = q35_dmar();
    bad[20] ^= 1;
    assert_eq!(discover(&[bad]), Err(DmarError::InvalidDmar));
}

#[test]
fn other_structures_are_skipped_and_reserved_regions_counted() {
    let snapshot = parse_dmar(&dmar(
        38,
        0,
        &[
            structure(STRUCTURE_RMRR, 24),
            structure(2, 8),
            drhd(0, 0, 0xfed9_1000),
            drhd(1, 0, 0xfed9_0000),
        ],
    ))
    .unwrap();
    assert_eq!(snapshot.units().len(), 2);
    assert_eq!(snapshot.reserved_memory_regions(), 1);
    assert!(!snapshot.interrupt_remapping());
}

#[test]
fn malformed_units_are_refused() {
    let cases = [
        (dmar(38, 0, &[]), DmarError::NoUnits),
        (
            dmar(20, 0, &[drhd(1, 0, 0xfed9_0000)]),
            DmarError::InvalidHostAddressWidth,
        ),
        (
            dmar(60, 0, &[drhd(1, 0, 0xfed9_0000)]),
            DmarError::InvalidHostAddressWidth,
        ),
        (
            dmar(38, 0, &[drhd(1, 1, 0xfed9_0000)]),
            DmarError::UnsupportedSegment,
        ),
        (
            dmar(38, 0, &[drhd(1, 0, 0)]),
            DmarError::InvalidRegisterBase,
        ),
        (
            dmar(38, 0, &[drhd(1, 0, 0xfed9_0800)]),
            DmarError::InvalidRegisterBase,
        ),
        (
            dmar(31, 0, &[drhd(1, 0, 0x1_0000_0000)]),
            DmarError::InvalidRegisterBase,
        ),
        (
            dmar(38, 0, &[drhd(0, 0, 0xfed9_0000), drhd(1, 0, 0xfed9_0000)]),
            DmarError::DuplicateRegisterBase,
        ),
        (
            dmar(38, 0, &[drhd(1, 0, 0xfed9_0000), drhd(1, 0, 0xfed9_1000)]),
            DmarError::MultipleIncludeAll,
        ),
        (
            dmar(38, 0, &[structure(STRUCTURE_RMRR, 2)]),
            DmarError::InvalidStructure,
        ),
        (dmar(38, 0, &[overrunning()]), DmarError::InvalidStructure),
    ];
    for (bytes, expected) in cases {
        assert_eq!(parse_dmar(&bytes), Err(expected));
    }
}

#[test]
fn a_structure_shorter_than_its_header_is_refused() {
    let mut bytes = dmar(38, 0, &[drhd(1, 0, 0xfed9_0000)]);
    bytes.extend_from_slice(&[0, 0]);
    let bytes = seal(bytes);
    assert_eq!(parse_dmar(&bytes), Err(DmarError::InvalidStructure));
}

#[test]
fn more_units_than_the_kernel_takes_over_are_refused() {
    let units: Vec<Vec<u8>> = (0..=MAX_DMAR_UNITS as u64)
        .map(|index| drhd(0, 0, 0xfed9_0000 + index * 0x1000))
        .collect();
    assert_eq!(
        parse_dmar(&dmar(38, 0, &units)),
        Err(DmarError::TooManyUnits)
    );
}
