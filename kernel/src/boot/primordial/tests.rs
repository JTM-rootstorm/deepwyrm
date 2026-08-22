extern crate std;

use std::vec;
use std::vec::Vec;

use super::*;

const HEADER_OFFSET: usize = ELF_HEADER_SIZE;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[allow(
    clippy::too_many_arguments,
    reason = "ELF64 program-header fields stay explicit in hostile-input fixtures"
)]
fn program_header(
    bytes: &mut [u8],
    index: usize,
    kind: u32,
    flags: u32,
    file_offset: u64,
    virtual_start: u64,
    file_byte_len: u64,
    memory_byte_len: u64,
    alignment: u64,
) {
    let offset = HEADER_OFFSET + index * ELF_PROGRAM_HEADER_SIZE;
    put_u32(bytes, offset, kind);
    put_u32(bytes, offset + 4, flags);
    put_u64(bytes, offset + 8, file_offset);
    put_u64(bytes, offset + 16, virtual_start);
    put_u64(bytes, offset + 32, file_byte_len);
    put_u64(bytes, offset + 40, memory_byte_len);
    put_u64(bytes, offset + 48, alignment);
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x3000];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = ELF_CLASS_64;
    bytes[5] = ELF_DATA_LITTLE_ENDIAN;
    bytes[6] = ELF_CURRENT_VERSION;
    put_u16(&mut bytes, 16, ELF_TYPE_EXECUTABLE);
    put_u16(&mut bytes, 18, ELF_MACHINE_X86_64);
    put_u32(&mut bytes, 20, u32::from(ELF_CURRENT_VERSION));
    put_u64(&mut bytes, 24, 0x401000);
    put_u64(&mut bytes, 32, HEADER_OFFSET as u64);
    put_u16(&mut bytes, 52, ELF_HEADER_SIZE as u16);
    put_u16(&mut bytes, 54, ELF_PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut bytes, 56, 3);
    program_header(
        &mut bytes,
        0,
        PT_LOAD,
        PF_R | PF_X,
        0x1000,
        0x401000,
        4,
        0x1000,
        PAGE_SIZE,
    );
    program_header(
        &mut bytes,
        1,
        PT_LOAD,
        PF_R | PF_W,
        0x2000,
        0x402000,
        8,
        0x1000,
        PAGE_SIZE,
    );
    program_header(&mut bytes, 2, PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16);
    bytes
}

#[test]
fn plans_valid_static_elf_and_preserves_bss_intent() {
    let plan = parse_primordial_elf(&fixture()).expect("valid primordial ELF");

    assert_eq!(plan.entry(), 0x401000);
    assert_eq!(plan.segment_count(), 2);
    assert_eq!(plan.mapped_byte_len(), 2 * PAGE_SIZE);
    let code = plan.segment(0).unwrap();
    assert!(code.permissions().readable());
    assert!(code.permissions().executable());
    assert!(!code.permissions().writable());
    let data = plan.segment(1).unwrap();
    assert_eq!(data.file_byte_len(), 8);
    assert_eq!(data.memory_byte_len(), PAGE_SIZE);
    assert_eq!(data.bss_byte_len(), PAGE_SIZE - 8);
    assert_eq!(data.page_start(), 0x402000);
    assert_eq!(data.page_end_exclusive(), 0x403000);
}

#[test]
fn rejects_truncated_and_wrong_identification_or_main_header_fields() {
    assert_eq!(
        parse_primordial_elf(&[]),
        Err(PrimordialElfError::InvalidFileSize)
    );
    assert_eq!(
        parse_primordial_elf(&vec![0_u8; MAX_PRIMORDIAL_ELF_BYTES + 1]),
        Err(PrimordialElfError::InvalidFileSize)
    );
    assert_eq!(
        parse_primordial_elf(&[0_u8; 63]),
        Err(PrimordialElfError::TruncatedHeader)
    );
    for (offset, value) in [(4, 1), (5, 2), (6, 0)] {
        let mut bytes = fixture();
        bytes[offset] = value;
        assert_eq!(
            parse_primordial_elf(&bytes),
            Err(PrimordialElfError::InvalidIdentification)
        );
    }
    for (offset, value, expected) in [
        (16, 3_u16, PrimordialElfError::UnsupportedType),
        (18, 3_u16, PrimordialElfError::UnsupportedMachine),
    ] {
        let mut bytes = fixture();
        put_u16(&mut bytes, offset, value);
        assert_eq!(parse_primordial_elf(&bytes), Err(expected));
    }
    let mut version = fixture();
    put_u32(&mut version, 20, 0);
    assert_eq!(
        parse_primordial_elf(&version),
        Err(PrimordialElfError::UnsupportedVersion)
    );
}

#[test]
fn rejects_header_count_and_table_arithmetic_failures() {
    let mut header_size = fixture();
    put_u16(&mut header_size, 52, 63);
    assert_eq!(
        parse_primordial_elf(&header_size),
        Err(PrimordialElfError::InvalidHeaderSize)
    );

    let mut entry_size = fixture();
    put_u16(&mut entry_size, 54, 55);
    assert_eq!(
        parse_primordial_elf(&entry_size),
        Err(PrimordialElfError::InvalidProgramHeaderSize)
    );

    for count in [0_u16, 17] {
        let mut bytes = fixture();
        put_u16(&mut bytes, 56, count);
        assert_eq!(
            parse_primordial_elf(&bytes),
            Err(PrimordialElfError::InvalidProgramHeaderCount)
        );
    }

    let mut overflowing_offset = fixture();
    put_u64(&mut overflowing_offset, 32, u64::MAX);
    assert_eq!(
        parse_primordial_elf(&overflowing_offset),
        Err(PrimordialElfError::ProgramHeaderTableOutOfRange)
    );
}

#[test]
fn rejects_segment_file_range_size_alignment_and_address_failures() {
    let mut out_of_file = fixture();
    put_u64(&mut out_of_file, HEADER_OFFSET + 8, 0x2fff);
    put_u64(&mut out_of_file, HEADER_OFFSET + 32, 2);
    assert_eq!(
        parse_primordial_elf(&out_of_file),
        Err(PrimordialElfError::SegmentFileRangeOutOfRange)
    );

    let mut filesz = fixture();
    put_u64(&mut filesz, HEADER_OFFSET + 32, 0x1001);
    assert_eq!(
        parse_primordial_elf(&filesz),
        Err(PrimordialElfError::FileSizeExceedsMemorySize)
    );

    let mut alignment = fixture();
    put_u64(&mut alignment, HEADER_OFFSET + 48, 3);
    assert_eq!(
        parse_primordial_elf(&alignment),
        Err(PrimordialElfError::InvalidSegmentAlignment)
    );

    let mut incongruent_alignment = fixture();
    put_u64(&mut incongruent_alignment, HEADER_OFFSET + 8, 0x1800);
    put_u64(&mut incongruent_alignment, HEADER_OFFSET + 48, 0x2000);
    assert_eq!(
        parse_primordial_elf(&incongruent_alignment),
        Err(PrimordialElfError::InvalidSegmentAlignment)
    );

    let mut overflow = fixture();
    put_u64(&mut overflow, HEADER_OFFSET + 16, u64::MAX - 0xfff);
    assert_eq!(
        parse_primordial_elf(&overflow),
        Err(PrimordialElfError::SegmentAddressOverflow)
    );
}

#[test]
fn rejects_page_zero_kernel_space_and_page_rounded_overlap() {
    let mut page_zero = fixture();
    put_u64(&mut page_zero, HEADER_OFFSET + 16, 0);
    assert_eq!(
        parse_primordial_elf(&page_zero),
        Err(PrimordialElfError::SegmentOutsideUserAddressSpace)
    );

    let mut kernel_half = fixture();
    put_u64(&mut kernel_half, HEADER_OFFSET + 16, USER_END_EXCLUSIVE);
    assert_eq!(
        parse_primordial_elf(&kernel_half),
        Err(PrimordialElfError::SegmentOutsideUserAddressSpace)
    );

    let mut overlap = fixture();
    put_u64(&mut overlap, HEADER_OFFSET + 40, 0x800);
    put_u64(
        &mut overlap,
        HEADER_OFFSET + ELF_PROGRAM_HEADER_SIZE + 16,
        0x401900,
    );
    put_u64(
        &mut overlap,
        HEADER_OFFSET + ELF_PROGRAM_HEADER_SIZE + 8,
        0x2900,
    );
    assert_eq!(
        parse_primordial_elf(&overlap),
        Err(PrimordialElfError::PageRoundedSegmentOverlap)
    );
}

#[test]
fn rejects_wx_executable_stack_unsupported_dynamic_and_bad_entry() {
    let mut writable_executable = fixture();
    put_u32(
        &mut writable_executable,
        HEADER_OFFSET + 4,
        PF_R | PF_W | PF_X,
    );
    assert_eq!(
        parse_primordial_elf(&writable_executable),
        Err(PrimordialElfError::WritableExecutableSegment)
    );

    let mut executable_stack = fixture();
    put_u32(
        &mut executable_stack,
        HEADER_OFFSET + 2 * ELF_PROGRAM_HEADER_SIZE + 4,
        PF_R | PF_W | PF_X,
    );
    assert_eq!(
        parse_primordial_elf(&executable_stack),
        Err(PrimordialElfError::ExecutableStack)
    );

    for kind in [2, 3] {
        let mut bytes = fixture();
        put_u32(
            &mut bytes,
            HEADER_OFFSET + 2 * ELF_PROGRAM_HEADER_SIZE,
            kind,
        );
        assert_eq!(
            parse_primordial_elf(&bytes),
            Err(PrimordialElfError::UnsupportedProgramHeader)
        );
    }

    let mut invalid_entry = fixture();
    put_u64(&mut invalid_entry, 24, 0x404000);
    assert_eq!(
        parse_primordial_elf(&invalid_entry),
        Err(PrimordialElfError::InvalidEntryPoint)
    );
}

#[test]
fn rejects_excessive_segments_and_image_footprint() {
    let mut too_many_segments = fixture();
    put_u16(&mut too_many_segments, 56, 9);
    for index in 0..9 {
        program_header(
            &mut too_many_segments,
            index,
            PT_LOAD,
            PF_R,
            0,
            0x500000 + (index as u64) * PAGE_SIZE,
            0,
            PAGE_SIZE,
            PAGE_SIZE,
        );
    }
    put_u64(&mut too_many_segments, 24, 0x500000);
    assert_eq!(
        parse_primordial_elf(&too_many_segments),
        Err(PrimordialElfError::TooManyLoadSegments)
    );

    let mut excessive_image = fixture();
    put_u16(&mut excessive_image, 56, 8);
    for index in 0..8 {
        program_header(
            &mut excessive_image,
            index,
            PT_LOAD,
            if index == 0 { PF_R | PF_X } else { PF_R },
            0,
            0x10_0000 + (index as u64) * 0x50_0000,
            0,
            0x40_0001,
            PAGE_SIZE,
        );
    }
    put_u64(&mut excessive_image, 24, 0x10_0000);
    assert_eq!(
        parse_primordial_elf(&excessive_image),
        Err(PrimordialElfError::ImageSizeLimitExceeded)
    );
}

#[test]
fn accepts_optional_program_header_metadata() {
    let mut bytes = fixture();
    put_u16(&mut bytes, 56, 4);
    program_header(
        &mut bytes,
        3,
        PT_PHDR,
        PF_R,
        HEADER_OFFSET as u64,
        0x400040,
        4 * ELF_PROGRAM_HEADER_SIZE as u64,
        4 * ELF_PROGRAM_HEADER_SIZE as u64,
        8,
    );
    assert!(parse_primordial_elf(&bytes).is_ok());
}
