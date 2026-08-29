extern crate std;

use std::cell::Cell;
use std::vec;
use std::vec::Vec;

use deepwyrm_abi::{
    DW_BOOT_DEVICE_RESOURCE_V1_SIZE, DW_BOOT_DEVICE_RESOURCE_V1_VERSION,
    DW_BOOT_DEVICE_TABLE_RECORD_STRIDE, DW_BOOT_DEVICE_TABLE_V1_SIZE,
    DW_BOOT_DEVICE_TABLE_V1_VERSION, DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
};

use super::*;

const BOOT_INFO: u64 = 0x1000;
const MEMORY_MAP: u64 = 0x2000;
const MODULES: u64 = 0x3000;
const DEVICE_TABLE: u64 = 0x4000;
const PAGING_HANDOFF: u64 = 0x5000;
const PAGING_FRAMES: [u64; 4] = [0x60_0000, 0x61_0000, 0x62_0000, 0x63_0000];

struct Fixture {
    base: u64,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            base: BOOT_INFO,
            bytes: vec![0; 0x5000],
        }
    }

    fn bytes_at(&mut self, physical_start: u64, bytes: &[u8]) {
        let start = usize::try_from(physical_start - self.base).expect("fixture address");
        self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
    }
}

impl BootInfoByteReader for Fixture {
    fn read_exact(&self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        let start =
            usize::try_from(physical_start.checked_sub(self.base).ok_or(())?).map_err(|_| ())?;
        let end = start.checked_add(destination.len()).ok_or(())?;
        destination.copy_from_slice(self.bytes.get(start..end).ok_or(())?);
        Ok(())
    }
}

struct CountingReader {
    fixture: Fixture,
    paging_reads: Cell<usize>,
}

impl BootInfoByteReader for CountingReader {
    fn read_exact(&self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        if physical_start == PAGING_HANDOFF {
            let reads = self.paging_reads.get();
            self.paging_reads.set(reads + 1);
            if reads != 0 {
                return Err(());
            }
        }
        self.fixture.read_exact(physical_start, destination)
    }
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn memory_range(start: u64, pages: u64) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    put_u32(&mut bytes, 0, DW_BOOT_MEMORY_RANGE_V1_SIZE);
    put_u32(&mut bytes, 4, DW_BOOT_MEMORY_RANGE_V1_VERSION);
    put_u32(&mut bytes, 8, DW_BOOT_MEMORY_KIND_USABLE.0);
    put_u64(&mut bytes, 16, start);
    put_u64(&mut bytes, 24, pages);
    bytes
}

fn module(kind: u32, flags: u32, start: u64, byte_len: u64) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    put_u32(&mut bytes, 0, DW_BOOT_MODULE_V1_SIZE);
    put_u32(&mut bytes, 4, DW_BOOT_MODULE_V1_VERSION);
    put_u32(&mut bytes, 8, kind);
    put_u32(&mut bytes, 12, flags);
    put_u64(&mut bytes, 16, start);
    put_u64(&mut bytes, 24, byte_len);
    bytes
}

fn boot_device_resource(
    resource_id: u64,
    device_correlation_id: u64,
    pio_base: u16,
    pio_length: u16,
    interrupt_source: u32,
) -> [u8; 48] {
    let mut bytes = [0_u8; 48];
    put_u32(&mut bytes, 0, DW_BOOT_DEVICE_RESOURCE_V1_SIZE);
    put_u32(&mut bytes, 4, DW_BOOT_DEVICE_RESOURCE_V1_VERSION);
    put_u32(
        &mut bytes,
        8,
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT.0,
    );
    put_u64(&mut bytes, 16, resource_id);
    put_u64(&mut bytes, 24, device_correlation_id);
    bytes[32..34].copy_from_slice(&pio_base.to_le_bytes());
    bytes[34..36].copy_from_slice(&pio_length.to_le_bytes());
    put_u32(&mut bytes, 36, interrupt_source);
    bytes
}

fn install_boot_device_table(fixture: &mut Fixture, records: &[[u8; 48]]) {
    let count = u32::try_from(records.len()).expect("fixture record count");
    let total_byte_len = u64::from(DW_BOOT_DEVICE_TABLE_V1_SIZE)
        + u64::from(count) * u64::from(DW_BOOT_DEVICE_TABLE_RECORD_STRIDE);
    let mut header = [0_u8; 32];
    put_u32(&mut header, 0, DW_BOOT_DEVICE_TABLE_V1_SIZE);
    put_u32(&mut header, 4, DW_BOOT_DEVICE_TABLE_V1_VERSION);
    put_u32(&mut header, 8, count);
    put_u32(&mut header, 16, DW_BOOT_DEVICE_TABLE_RECORD_STRIDE);
    put_u64(&mut header, 24, total_byte_len);
    fixture.bytes_at(DEVICE_TABLE, &header);
    for (index, record) in records.iter().enumerate() {
        fixture.bytes_at(
            DEVICE_TABLE
                + u64::from(DW_BOOT_DEVICE_TABLE_V1_SIZE)
                + u64::try_from(index).expect("record index")
                    * u64::from(DW_BOOT_DEVICE_TABLE_RECORD_STRIDE),
            record,
        );
    }
    fixture.bytes_at(BOOT_INFO + 48, &4_u64.to_le_bytes());
    fixture.bytes_at(
        MODULES + 3 * u64::from(DW_BOOT_MODULE_V1_SIZE),
        &module(
            DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1.0,
            DW_BOOT_MODULE_FLAG_READ_ONLY.0,
            DEVICE_TABLE,
            total_byte_len,
        ),
    );
}

fn valid_device_fixture() -> Fixture {
    let mut fixture = valid_fixture();
    install_boot_device_table(&mut fixture, &[boot_device_resource(1, 1, 0x2f8, 8, 3)]);
    fixture
}

fn paging_handoff() -> [u8; 144] {
    let mut bytes = [0_u8; 144];
    put_u32(&mut bytes, 0, DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE);
    put_u32(&mut bytes, 4, DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION);
    put_u32(&mut bytes, 12, 52);
    put_u64(&mut bytes, 16, PAGING_FRAMES[0]);
    put_u32(
        &mut bytes,
        24,
        DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
    );
    put_u32(
        &mut bytes,
        28,
        DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT,
    );
    put_u32(
        &mut bytes,
        32,
        DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
    );
    put_u32(&mut bytes, 36, 144);
    put_u32(&mut bytes, 40, DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION);
    put_u64(
        &mut bytes,
        48,
        DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
    );
    bytes[56..58].copy_from_slice(&DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX.to_le_bytes());
    bytes[58..60].copy_from_slice(&DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX.to_le_bytes());
    bytes[60..62].copy_from_slice(&DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX.to_le_bytes());
    bytes[62..64].copy_from_slice(&DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX.to_le_bytes());
    put_u64(&mut bytes, 64, PAGING_FRAMES[1]);
    put_u64(&mut bytes, 72, PAGING_FRAMES[2]);
    put_u64(&mut bytes, 80, PAGING_FRAMES[3]);
    for (index, frame) in PAGING_FRAMES.iter().copied().enumerate() {
        put_u64(&mut bytes, 112 + index * 8, frame);
    }
    bytes
}

fn valid_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    let mut header = [0_u8; DW_BOOT_INFO_V1_SIZE as usize];
    put_u32(&mut header, 0, DW_BOOT_INFO_V1_SIZE);
    put_u32(&mut header, 4, DW_BOOT_INFO_V1_VERSION);
    put_u64(&mut header, 16, MEMORY_MAP);
    put_u64(&mut header, 24, 2);
    put_u32(&mut header, 32, DW_BOOT_MEMORY_RANGE_V1_SIZE);
    put_u64(&mut header, 40, MODULES);
    put_u64(&mut header, 48, 3);
    put_u32(&mut header, 56, DW_BOOT_MODULE_V1_SIZE);
    fixture.bytes_at(BOOT_INFO, &header);
    fixture.bytes_at(MEMORY_MAP, &memory_range(0x10_0000, 16));
    let mut paging_memory = memory_range(PAGING_FRAMES[0], 49);
    put_u32(&mut paging_memory, 8, DW_BOOT_MEMORY_KIND_RESERVED.0);
    fixture.bytes_at(
        MEMORY_MAP + u64::from(DW_BOOT_MEMORY_RANGE_V1_SIZE),
        &paging_memory,
    );
    fixture.bytes_at(
        MODULES,
        &module(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP.0,
            0,
            0x20_0000,
            0x1000,
        ),
    );
    fixture.bytes_at(
        MODULES + u64::from(DW_BOOT_MODULE_V1_SIZE),
        &module(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS.0,
            DW_BOOT_MODULE_FLAG_READ_ONLY.0,
            0x30_0000,
            0x2000,
        ),
    );
    fixture.bytes_at(
        MODULES + 2 * u64::from(DW_BOOT_MODULE_V1_SIZE),
        &module(
            DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1.0,
            DW_BOOT_MODULE_FLAG_READ_ONLY.0,
            PAGING_HANDOFF,
            144,
        ),
    );
    fixture.bytes_at(PAGING_HANDOFF, &paging_handoff());
    fixture
}

#[test]
fn validates_and_snapshots_the_fixed_width_handoff() {
    let fixture = valid_fixture();
    let boot_info = validate_boot_info(&fixture, BOOT_INFO).expect("valid handoff");

    assert_eq!(boot_info.memory_map().entry_count(), 2);
    assert_eq!(boot_info.modules().entry_count(), 3);
    assert_eq!(boot_info.memory_range(0).unwrap().page_count, 16);
    assert_eq!(
        boot_info.delegable_module(1).unwrap().range(),
        BootPhysicalRange {
            physical_start: 0x30_0000,
            byte_len: 0x2000,
        }
    );
    assert_eq!(
        boot_info.memory_range(2),
        Err(BootInfoValidationError::TableIndexOutOfBounds)
    );
    assert_eq!(boot_info.paging_handoff().table_frame_count(), 4);
    assert!(boot_info.boot_resource_grants().is_empty());
    assert_eq!(
        boot_info.paging_handoff().table_frame(0).unwrap(),
        PAGING_FRAMES[0]
    );
    let primordial = boot_info.primordial_modules().expect("primordial modules");
    assert_eq!(primordial.bootstrap().range().physical_start(), 0x20_0000);
    assert_eq!(primordial.bootstrap().range().byte_len(), 0x1000);
    assert_eq!(primordial.bootstrap().page_rounded_byte_len(), 0x1000);
    assert_eq!(primordial.bootfs().range().physical_start(), 0x30_0000);
    assert_eq!(primordial.bootfs().range().byte_len(), 0x2000);
    assert_eq!(primordial.bootfs().page_rounded_byte_len(), 0x2000);
}

#[test]
fn validates_and_snapshots_an_optional_boot_device_table() {
    let mut fixture = valid_device_fixture();
    let boot_info = validate_boot_info(&fixture, BOOT_INFO).expect("valid boot-device table");
    let grants = boot_info.boot_resource_grants();

    assert_eq!(grants.len(), 1);
    let grant = grants.grant(0).expect("COM2 grant");
    assert_eq!(grant.descriptor().resource_id, 1);
    assert_eq!(grant.descriptor().device_correlation_id, 1);
    assert_eq!(grant.descriptor().pio_base, 0x2f8);
    assert_eq!(grant.descriptor().pio_length, 8);
    assert_eq!(grant.descriptor().interrupt_source, 3);
    assert_ne!(grant.grant_generation(), 0);
    assert_eq!(
        grant.state(),
        crate::boot::BootResourceGrantState::Available
    );
    assert_eq!(grants.grant(1), None);

    fixture.bytes_at(DEVICE_TABLE + 32 + 16, &99_u64.to_le_bytes());
    assert_eq!(grants.grant(0).expect("retained grant"), grant);
}

#[test]
fn rejects_invalid_boot_device_table_headers_and_extents() {
    let cases = [
        (
            0_u64,
            0_u64,
            BootInfoValidationError::InvalidBootDeviceTable,
        ),
        (0, 4, BootInfoValidationError::UnsupportedVersion),
        (0, 12, BootInfoValidationError::UnknownFlags),
        (0, 20, BootInfoValidationError::NonZeroReserved),
    ];
    for (value, offset, expected) in cases {
        let mut fixture = valid_device_fixture();
        let replacement = if offset == 0 { 31 } else { value.max(2) as u32 };
        fixture.bytes_at(DEVICE_TABLE + offset, &replacement.to_le_bytes());
        assert_eq!(validate_boot_info(&fixture, BOOT_INFO), Err(expected));
    }

    let mut empty = valid_device_fixture();
    empty.bytes_at(DEVICE_TABLE + 8, &0_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&empty, BOOT_INFO),
        Err(BootInfoValidationError::InvalidBootDeviceTable)
    );

    let mut too_many = valid_device_fixture();
    too_many.bytes_at(DEVICE_TABLE + 8, &9_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&too_many, BOOT_INFO),
        Err(BootInfoValidationError::InvalidBootDeviceTable)
    );

    let mut malformed_stride = valid_device_fixture();
    malformed_stride.bytes_at(DEVICE_TABLE + 16, &49_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&malformed_stride, BOOT_INFO),
        Err(BootInfoValidationError::InvalidBootDeviceTable)
    );

    for byte_len in [31_u64, 79_u64, 81_u64] {
        let mut wrong_extent = valid_device_fixture();
        wrong_extent.bytes_at(MODULES + 3 * 64 + 24, &byte_len.to_le_bytes());
        assert_eq!(
            validate_boot_info(&wrong_extent, BOOT_INFO),
            Err(BootInfoValidationError::InvalidBootDeviceTable)
        );
    }

    let mut wrong_total = valid_device_fixture();
    wrong_total.bytes_at(DEVICE_TABLE + 24, &81_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&wrong_total, BOOT_INFO),
        Err(BootInfoValidationError::InvalidBootDeviceTable)
    );
}

#[test]
fn rejects_invalid_boot_device_records() {
    let mutations = [
        (
            0_u64,
            47_u64,
            BootInfoValidationError::InvalidBootDeviceResource,
        ),
        (4, 2, BootInfoValidationError::UnsupportedVersion),
        (8, 2, BootInfoValidationError::InvalidBootDeviceResource),
        (12, 1, BootInfoValidationError::UnknownFlags),
        (16, 0, BootInfoValidationError::InvalidBootDeviceResource),
        (36, 0, BootInfoValidationError::InvalidBootDeviceResource),
        (40, 1, BootInfoValidationError::NonZeroReserved),
    ];
    for (offset, value, expected) in mutations {
        let mut fixture = valid_device_fixture();
        let record = DEVICE_TABLE + 32 + offset;
        if matches!(offset, 16 | 40) {
            fixture.bytes_at(record, &value.to_le_bytes());
        } else {
            fixture.bytes_at(record, &(value as u32).to_le_bytes());
        }
        assert_eq!(validate_boot_info(&fixture, BOOT_INFO), Err(expected));
    }

    let mut zero_length = valid_device_fixture();
    zero_length.bytes_at(DEVICE_TABLE + 32 + 34, &0_u16.to_le_bytes());
    assert_eq!(
        validate_boot_info(&zero_length, BOOT_INFO),
        Err(BootInfoValidationError::InvalidBootDeviceResource)
    );

    let mut pio_overflow = valid_device_fixture();
    pio_overflow.bytes_at(DEVICE_TABLE + 32 + 32, &0xfff8_u16.to_le_bytes());
    pio_overflow.bytes_at(DEVICE_TABLE + 32 + 34, &9_u16.to_le_bytes());
    assert_eq!(
        validate_boot_info(&pio_overflow, BOOT_INFO),
        Err(BootInfoValidationError::InvalidBootDeviceResource)
    );
}

#[test]
fn rejects_protected_com1_and_irq4_resources() {
    for (base, length, irq) in [
        (0x3f8_u16, 8_u16, 3_u32),
        (0x3f0, 9, 3),
        (0x3ff, 2, 3),
        (0x2f8, 8, 4),
    ] {
        let mut fixture = valid_fixture();
        install_boot_device_table(
            &mut fixture,
            &[boot_device_resource(1, 1, base, length, irq)],
        );
        assert_eq!(
            validate_boot_info(&fixture, BOOT_INFO),
            Err(BootInfoValidationError::ProtectedBootDeviceResource)
        );
    }
}

#[test]
fn rejects_duplicate_and_overlapping_boot_device_resources_but_accepts_adjacency() {
    let cases = [
        (
            boot_device_resource(1, 2, 0x300, 8, 5),
            BootInfoValidationError::DuplicateBootDeviceResourceId,
        ),
        (
            boot_device_resource(2, 2, 0x300, 8, 3),
            BootInfoValidationError::DuplicateBootDeviceInterruptSource,
        ),
        (
            boot_device_resource(2, 2, 0x2ff, 8, 5),
            BootInfoValidationError::OverlappingBootDeviceResources,
        ),
    ];
    for (second, expected) in cases {
        let mut fixture = valid_fixture();
        install_boot_device_table(
            &mut fixture,
            &[boot_device_resource(1, 1, 0x2f8, 8, 3), second],
        );
        assert_eq!(validate_boot_info(&fixture, BOOT_INFO), Err(expected));
    }

    let mut adjacent = valid_fixture();
    install_boot_device_table(
        &mut adjacent,
        &[
            boot_device_resource(1, 1, 0x2f8, 8, 3),
            boot_device_resource(2, 2, 0x300, 8, 5),
        ],
    );
    let grants = validate_boot_info(&adjacent, BOOT_INFO)
        .expect("adjacent resources")
        .boot_resource_grants();
    assert_eq!(grants.len(), 2);
}

#[test]
fn accepts_the_exact_maximum_boot_device_table_capacity() {
    let mut fixture = valid_fixture();
    let records: [[u8; 48]; 8] = core::array::from_fn(|index| {
        let id = u64::try_from(index + 1).expect("resource id");
        let irq = [1_u32, 2, 3, 5, 6, 7, 8, 9][index];
        boot_device_resource(
            id,
            id,
            0x100 + u16::try_from(index * 8).expect("PIO offset"),
            8,
            irq,
        )
    });
    install_boot_device_table(&mut fixture, &records);

    let grants = validate_boot_info(&fixture, BOOT_INFO)
        .expect("maximum-capacity table")
        .boot_resource_grants();
    assert_eq!(grants.len(), 8);
}

#[test]
fn boot_device_validation_phases_have_deterministic_precedence() {
    let mut structural_late = valid_fixture();
    let mut malformed_second = boot_device_resource(2, 2, 0x300, 8, 5);
    put_u32(&mut malformed_second, 4, 2);
    install_boot_device_table(
        &mut structural_late,
        &[boot_device_resource(1, 1, 0x3f8, 8, 3), malformed_second],
    );
    assert_eq!(
        validate_boot_info(&structural_late, BOOT_INFO),
        Err(BootInfoValidationError::UnsupportedVersion)
    );

    let mut protected_before_pairs = valid_fixture();
    install_boot_device_table(
        &mut protected_before_pairs,
        &[
            boot_device_resource(1, 1, 0x2f8, 8, 3),
            boot_device_resource(1, 2, 0x300, 8, 5),
            boot_device_resource(3, 3, 0x3f8, 8, 6),
        ],
    );
    assert_eq!(
        validate_boot_info(&protected_before_pairs, BOOT_INFO),
        Err(BootInfoValidationError::ProtectedBootDeviceResource)
    );

    let mut ascending_pairs = valid_fixture();
    install_boot_device_table(
        &mut ascending_pairs,
        &[
            boot_device_resource(1, 1, 0x2f8, 8, 3),
            boot_device_resource(1, 2, 0x300, 8, 5),
            boot_device_resource(3, 3, 0x308, 8, 3),
        ],
    );
    assert_eq!(
        validate_boot_info(&ascending_pairs, BOOT_INFO),
        Err(BootInfoValidationError::DuplicateBootDeviceResourceId)
    );
}

#[test]
fn rejects_duplicate_or_mutable_boot_device_modules_without_partial_grants() {
    let mut duplicate = valid_device_fixture();
    duplicate.bytes_at(BOOT_INFO + 48, &5_u64.to_le_bytes());
    duplicate.bytes_at(
        MODULES + 4 * u64::from(DW_BOOT_MODULE_V1_SIZE),
        &module(
            DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1.0,
            DW_BOOT_MODULE_FLAG_READ_ONLY.0,
            DEVICE_TABLE,
            80,
        ),
    );
    assert_eq!(
        validate_boot_info(&duplicate, BOOT_INFO),
        Err(BootInfoValidationError::DuplicateBootDeviceModule)
    );

    let mut mutable = valid_device_fixture();
    mutable.bytes_at(MODULES + 3 * 64 + 12, &0_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&mutable, BOOT_INFO),
        Err(BootInfoValidationError::InvalidModuleFlags)
    );

    let mut late_failure = valid_fixture();
    install_boot_device_table(
        &mut late_failure,
        &[
            boot_device_resource(1, 1, 0x2f8, 8, 3),
            boot_device_resource(2, 2, 0x300, 8, 3),
        ],
    );
    assert_eq!(
        validate_boot_info(&late_failure, BOOT_INFO),
        Err(BootInfoValidationError::DuplicateBootDeviceInterruptSource)
    );

    let materialize_calls = Cell::new(0_u32);
    let result =
        device_table::parse_boot_resource_grants_with(&late_failure, DEVICE_TABLE, 128, |_| {
            materialize_calls.set(materialize_calls.get() + 1);
            BootResourceGrants::materialize(&[])
        });
    assert_eq!(
        result,
        Err(BootInfoValidationError::DuplicateBootDeviceInterruptSource)
    );
    assert_eq!(materialize_calls.get(), 0);
}

#[test]
fn accepts_a_reserved_memory_record_starting_at_physical_zero() {
    let mut fixture = valid_fixture();
    fixture.bytes_at(
        MEMORY_MAP + 8,
        &DW_BOOT_MEMORY_KIND_RESERVED.0.to_le_bytes(),
    );
    fixture.bytes_at(MEMORY_MAP + 16, &0_u64.to_le_bytes());

    let boot_info = validate_boot_info(&fixture, BOOT_INFO).expect("physical zero is valid");
    assert_eq!(boot_info.memory_range(0).unwrap().physical_start, 0);
}

#[test]
fn retains_snapshots_after_the_reader_backing_changes() {
    let mut fixture = valid_fixture();
    let boot_info = validate_boot_info(&fixture, BOOT_INFO).expect("valid handoff");

    fixture.bytes_at(MEMORY_MAP + 24, &1_u64.to_le_bytes());
    fixture.bytes_at(MODULES + 64 + 16, &0x40_0000_u64.to_le_bytes());
    fixture.bytes_at(PAGING_HANDOFF + 112, &0_u64.to_le_bytes());

    assert_eq!(boot_info.memory_range(0).unwrap().page_count, 16);
    assert_eq!(
        boot_info
            .delegable_module(1)
            .unwrap()
            .range()
            .physical_start(),
        0x30_0000
    );
    assert_eq!(
        boot_info.paging_handoff().table_frame(0).unwrap(),
        PAGING_FRAMES[0]
    );
}

#[test]
fn rejects_reserved_and_unknown_header_bits() {
    let mut fixture = valid_fixture();
    let reserved_offset = BOOT_INFO + 248;
    fixture.bytes_at(reserved_offset, &1_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::NonZeroReserved)
    );

    let mut fixture = valid_fixture();
    fixture.bytes_at(BOOT_INFO + 8, &2_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::UnknownFlags)
    );
}

#[test]
fn rejects_unbounded_or_overflowing_table_shapes() {
    let mut fixture = valid_fixture();
    fixture.bytes_at(BOOT_INFO + 24, &u64::MAX.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::EntryCountLimitExceeded)
    );

    let mut fixture = valid_fixture();
    fixture.bytes_at(BOOT_INFO + 16, &u64::MAX.wrapping_sub(7).to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::ArithmeticOverflow)
    );
}

#[test]
fn rejects_invalid_memory_range_arithmetic_and_classification() {
    let mut fixture = valid_fixture();
    fixture.bytes_at(MEMORY_MAP + 24, &0_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::EmptyRange)
    );

    let mut fixture = valid_fixture();
    fixture.bytes_at(MEMORY_MAP + 8, &0_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::UnknownMemoryKind)
    );
}

#[test]
fn rejects_duplicate_and_mutable_boot_modules() {
    let mut fixture = valid_fixture();
    fixture.bytes_at(
        MODULES + 64 + 8,
        &DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP.0.to_le_bytes(),
    );
    fixture.bytes_at(MODULES + 64 + 12, &0_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::DuplicateRequiredModule)
    );

    let mut fixture = valid_fixture();
    fixture.bytes_at(MODULES + 64 + 12, &0_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::InvalidModuleFlags)
    );

    let mut bootstrap_flags = valid_fixture();
    bootstrap_flags.bytes_at(MODULES + 12, &DW_BOOT_MODULE_FLAG_READ_ONLY.0.to_le_bytes());
    assert_eq!(
        validate_boot_info(&bootstrap_flags, BOOT_INFO),
        Err(BootInfoValidationError::InvalidModuleFlags)
    );
}

#[test]
fn rejects_overlapping_modules() {
    let mut fixture = valid_fixture();
    fixture.bytes_at(MODULES + 64 + 16, &0x20_0800_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::UnalignedAddress)
    );

    let mut fixture = valid_fixture();
    fixture.bytes_at(MODULES + 64 + 16, &0x20_0000_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::OverlappingModules)
    );
}

#[test]
fn paging_handoff_is_required_exactly_once_and_read_as_one_snapshot() {
    let mut missing = valid_fixture();
    missing.bytes_at(BOOT_INFO + 48, &2_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&missing, BOOT_INFO),
        Err(BootInfoValidationError::MissingRequiredModule)
    );

    let mut duplicate = valid_fixture();
    duplicate.bytes_at(BOOT_INFO + 48, &4_u64.to_le_bytes());
    duplicate.bytes_at(
        MODULES + 3 * u64::from(DW_BOOT_MODULE_V1_SIZE),
        &module(
            DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1.0,
            DW_BOOT_MODULE_FLAG_READ_ONLY.0,
            0x70_0000,
            144,
        ),
    );
    assert_eq!(
        validate_boot_info(&duplicate, BOOT_INFO),
        Err(BootInfoValidationError::DuplicateRequiredModule)
    );

    let mut mutable = valid_fixture();
    mutable.bytes_at(MODULES + 2 * 64 + 12, &0_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&mutable, BOOT_INFO),
        Err(BootInfoValidationError::InvalidModuleFlags)
    );

    let reader = CountingReader {
        fixture: valid_fixture(),
        paging_reads: Cell::new(0),
    };
    let info = validate_boot_info(&reader, BOOT_INFO).expect("valid one-snapshot carrier");
    assert_eq!(reader.paging_reads.get(), 1);
    assert_eq!(info.paging_handoff().table_frame_count(), 4);
}

#[test]
fn only_bootfs_has_a_delegable_module_view() {
    let fixture = valid_fixture();
    let info = validate_boot_info(&fixture, BOOT_INFO).expect("valid handoff");

    assert_eq!(
        info.delegable_module(0),
        Err(BootInfoValidationError::ModuleNotDelegable)
    );
    assert_eq!(
        info.delegable_module(2),
        Err(BootInfoValidationError::ModuleNotDelegable)
    );
    assert_eq!(
        info.delegable_module(3),
        Err(BootInfoValidationError::TableIndexOutOfBounds)
    );
    assert_eq!(
        info.delegable_module(1).unwrap().range(),
        BootPhysicalRange {
            physical_start: 0x30_0000,
            byte_len: 0x2000,
        }
    );
}

#[test]
fn paging_frames_require_exactly_one_reserved_memory_map_owner() {
    for kind in [DW_BOOT_MEMORY_KIND_USABLE, DW_BOOT_MEMORY_KIND_MMIO] {
        let mut fixture = valid_fixture();
        fixture.bytes_at(MEMORY_MAP + 64 + 8, &kind.0.to_le_bytes());
        assert_eq!(
            validate_boot_info(&fixture, BOOT_INFO),
            Err(BootInfoValidationError::PagingHandoffFrameNotReserved),
            "accepted paging frames classified as kind {}",
            kind.0
        );
    }

    let mut uncovered = valid_fixture();
    uncovered.bytes_at(MEMORY_MAP + 64 + 16, &0x70_0000_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&uncovered, BOOT_INFO),
        Err(BootInfoValidationError::PagingHandoffFrameNotReserved)
    );

    let mut duplicate_owner = valid_fixture();
    duplicate_owner.bytes_at(BOOT_INFO + 24, &3_u64.to_le_bytes());
    let mut duplicate_range = memory_range(PAGING_FRAMES[0], 49);
    put_u32(&mut duplicate_range, 8, DW_BOOT_MEMORY_KIND_RESERVED.0);
    duplicate_owner.bytes_at(MEMORY_MAP + 128, &duplicate_range);
    assert_eq!(
        validate_boot_info(&duplicate_owner, BOOT_INFO),
        Err(BootInfoValidationError::PagingHandoffFrameNotReserved)
    );
}

#[test]
fn paging_handoff_rejects_malformed_header_extent_and_frame_list_bytes() {
    for (offset, bytes) in [
        (0, 0_u32.to_le_bytes()),
        (4, 0_u32.to_le_bytes()),
        (8, 1_u32.to_le_bytes()),
        (12, 53_u32.to_le_bytes()),
        (24, 120_u32.to_le_bytes()),
        (28, 3_u32.to_le_bytes()),
        (32, 16_u32.to_le_bytes()),
        (36, 143_u32.to_le_bytes()),
        (40, 1_u32.to_le_bytes()),
        (44, 1_u32.to_le_bytes()),
    ] {
        let mut fixture = valid_fixture();
        fixture.bytes_at(PAGING_HANDOFF + offset, &bytes);
        assert_eq!(
            validate_boot_info(&fixture, BOOT_INFO),
            Err(BootInfoValidationError::InvalidPagingHandoff),
            "accepted malformed carrier field at offset {offset}"
        );
    }

    for (offset, value) in [
        (16, 0),
        (48, 0),
        (64, PAGING_FRAMES[0]),
        (88, 1),
        (112, 0),
        (120, PAGING_FRAMES[0]),
    ] {
        let mut fixture = valid_fixture();
        fixture.bytes_at(PAGING_HANDOFF + offset, &value.to_le_bytes());
        assert_eq!(
            validate_boot_info(&fixture, BOOT_INFO),
            Err(BootInfoValidationError::InvalidPagingHandoff),
            "accepted malformed carrier word at offset {offset}"
        );
    }

    let mut wrong_index = valid_fixture();
    wrong_index.bytes_at(PAGING_HANDOFF + 56, &511_u16.to_le_bytes());
    assert_eq!(
        validate_boot_info(&wrong_index, BOOT_INFO),
        Err(BootInfoValidationError::InvalidPagingHandoff)
    );

    let mut wrong_module_extent = valid_fixture();
    wrong_module_extent.bytes_at(MODULES + 2 * 64 + 24, &143_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&wrong_module_extent, BOOT_INFO),
        Err(BootInfoValidationError::InvalidPagingHandoff)
    );

    for (offset, bytes, expected) in [
        (
            0,
            u64::from(DW_BOOT_MODULE_V1_VERSION)
                .wrapping_shl(32)
                .to_le_bytes(),
            BootInfoValidationError::StructureTooSmall,
        ),
        (
            4,
            0_u64.to_le_bytes(),
            BootInfoValidationError::UnsupportedVersion,
        ),
        (
            32,
            1_u64.to_le_bytes(),
            BootInfoValidationError::NonZeroReserved,
        ),
    ] {
        let mut fixture = valid_fixture();
        fixture.bytes_at(MODULES + 2 * 64 + offset, &bytes);
        assert_eq!(validate_boot_info(&fixture, BOOT_INFO), Err(expected));
    }

    let mut unaligned_module = valid_fixture();
    unaligned_module.bytes_at(MODULES + 2 * 64 + 16, &(PAGING_HANDOFF + 8).to_le_bytes());
    assert_eq!(
        validate_boot_info(&unaligned_module, BOOT_INFO),
        Err(BootInfoValidationError::UnalignedAddress)
    );

    let mut overflowing_module = valid_fixture();
    overflowing_module.bytes_at(MODULES + 2 * 64 + 16, &(u64::MAX - 4095).to_le_bytes());
    overflowing_module.bytes_at(MODULES + 2 * 64 + 24, &8192_u64.to_le_bytes());
    assert_eq!(
        validate_boot_info(&overflowing_module, BOOT_INFO),
        Err(BootInfoValidationError::ArithmeticOverflow)
    );
}

#[test]
fn paging_table_frames_cannot_alias_any_enumerated_handoff_storage() {
    for conflicting_frame in [PAGING_HANDOFF, 0x20_0000, BOOT_INFO, MEMORY_MAP, MODULES] {
        let mut fixture = valid_fixture();
        fixture.bytes_at(PAGING_HANDOFF + 16, &conflicting_frame.to_le_bytes());
        fixture.bytes_at(PAGING_HANDOFF + 112, &conflicting_frame.to_le_bytes());
        assert_eq!(
            validate_boot_info(&fixture, BOOT_INFO),
            Err(BootInfoValidationError::PagingHandoffFrameRoleOverlap),
            "accepted table/data role alias at {conflicting_frame:#x}"
        );
    }

    let mut rsdp_tail_alias = valid_fixture();
    rsdp_tail_alias.bytes_at(BOOT_INFO + 64, &(PAGING_FRAMES[0] - 8).to_le_bytes());
    assert_eq!(
        validate_boot_info(&rsdp_tail_alias, BOOT_INFO),
        Err(BootInfoValidationError::PagingHandoffFrameRoleOverlap)
    );
}

#[test]
fn validates_framebuffer_and_entropy_presence_semantics() {
    let mut fixture = valid_fixture();
    fixture.bytes_at(
        BOOT_INFO + 8,
        &DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT.0.to_le_bytes(),
    );
    let framebuffer = BOOT_INFO + 72;
    fixture.bytes_at(framebuffer, &DW_BOOT_FRAMEBUFFER_V1_SIZE.to_le_bytes());
    fixture.bytes_at(
        framebuffer + 4,
        &DW_BOOT_FRAMEBUFFER_V1_VERSION.to_le_bytes(),
    );
    fixture.bytes_at(
        framebuffer + 8,
        &DW_BOOT_FRAMEBUFFER_FLAG_LINEAR.0.to_le_bytes(),
    );
    fixture.bytes_at(
        framebuffer + 12,
        &DW_BOOT_PIXEL_FORMAT_RGBX8.0.to_le_bytes(),
    );
    fixture.bytes_at(framebuffer + 16, &0x40_0000_u64.to_le_bytes());
    fixture.bytes_at(framebuffer + 24, &0x4000_u64.to_le_bytes());
    fixture.bytes_at(framebuffer + 32, &64_u32.to_le_bytes());
    fixture.bytes_at(framebuffer + 36, &64_u32.to_le_bytes());
    fixture.bytes_at(framebuffer + 40, &64_u32.to_le_bytes());
    let entropy = BOOT_INFO + 184;
    fixture.bytes_at(entropy, &DW_BOOT_ENTROPY_V1_SIZE.to_le_bytes());
    fixture.bytes_at(entropy + 4, &DW_BOOT_ENTROPY_V1_VERSION.to_le_bytes());
    fixture.bytes_at(
        entropy + 8,
        &DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL.0.to_le_bytes(),
    );
    fixture.bytes_at(entropy + 16, &0x50_0000_u64.to_le_bytes());
    fixture.bytes_at(entropy + 24, &64_u64.to_le_bytes());

    let info = validate_boot_info(&fixture, BOOT_INFO).expect("valid optional descriptors");
    assert!(info.framebuffer().is_some());
    assert_eq!(info.entropy().unwrap().byte_len(), 64);

    let mut fixture = valid_fixture();
    fixture.bytes_at(BOOT_INFO + 72, &1_u32.to_le_bytes());
    assert_eq!(
        validate_boot_info(&fixture, BOOT_INFO),
        Err(BootInfoValidationError::InvalidFramebuffer)
    );
}
