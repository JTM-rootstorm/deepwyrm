extern crate std;

use std::cell::Cell;
use std::vec;
use std::vec::Vec;

use super::*;

const BOOT_INFO: u64 = 0x1000;
const MEMORY_MAP: u64 = 0x2000;
const MODULES: u64 = 0x3000;
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
    assert_eq!(
        boot_info.paging_handoff().table_frame(0).unwrap(),
        PAGING_FRAMES[0]
    );
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
