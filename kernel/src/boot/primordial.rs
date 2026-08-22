//! DW0-G primordial module selection and narrow ELF64 load planning.
//!
//! This module is intentionally a pure validation boundary. It allocates no
//! pages, copies no module bytes, and publishes no task or capability state.
//! G2 consumes the immutable plan only after all fallible BootInfo and ELF
//! checks have completed.

use deepwyrm_abi::{
    DW_BOOT_BASE_PAGE_SIZE, DW_BOOT_MODULE_FLAG_READ_ONLY, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
};

use super::{BootPhysicalRange, ValidatedBootInfo};

const ELF_HEADER_SIZE: usize = 64;
const ELF_PROGRAM_HEADER_SIZE: usize = 56;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_CURRENT_VERSION: u8 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const KNOWN_PROGRAM_FLAGS: u32 = PF_X | PF_W | PF_R;

/// Maximum accepted primordial bootstrap module length.
pub const MAX_PRIMORDIAL_ELF_BYTES: usize = 16 * 1024 * 1024;
/// Maximum program headers accepted from the deliberately narrow ELF subset.
pub const MAX_PRIMORDIAL_PROGRAM_HEADERS: usize = 16;
/// Maximum `PT_LOAD` segments accepted from the deliberately narrow ELF subset.
pub const MAX_PRIMORDIAL_LOAD_SEGMENTS: usize = 8;
/// Maximum sum of page-rounded `PT_LOAD` mapping extents.
pub const MAX_PRIMORDIAL_IMAGE_BYTES: u64 = 32 * 1024 * 1024;

const PAGE_SIZE: u64 = DW_BOOT_BASE_PAGE_SIZE as u64;
const USER_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

/// One selected primordial module with its exact logical and page-rounded
/// capacity kept distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimordialModule {
    range: BootPhysicalRange,
    page_rounded_byte_len: u64,
}

impl PrimordialModule {
    /// Exact loader-declared logical module range.
    pub const fn range(self) -> BootPhysicalRange {
        self.range
    }

    /// Page-rounded backing capacity, computed without losing logical length.
    pub const fn page_rounded_byte_len(self) -> u64 {
        self.page_rounded_byte_len
    }
}

/// The only two loader modules eligible for the primordial construction path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimordialBootModules {
    bootstrap: PrimordialModule,
    bootfs: PrimordialModule,
}

impl PrimordialBootModules {
    /// Kernel-consumed fully static bootstrap ELF module.
    pub const fn bootstrap(self) -> PrimordialModule {
        self.bootstrap
    }

    /// Read-only bootfs module intended for the later child capability.
    pub const fn bootfs(self) -> PrimordialModule {
        self.bootfs
    }
}

/// Fail-closed module-selection errors for the primordial path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimordialModuleError {
    MissingRequiredModule,
    DuplicateRequiredModule,
    InvalidBootstrapFlags,
    InvalidBootfsFlags,
    InvalidModuleExtent,
    ModulePageOverlap,
}

/// Selects exactly the bootstrap and bootfs modules from a copied, validated
/// BootInfo snapshot. The internal paging carrier is never returned.
pub(super) fn select_primordial_boot_modules(
    boot_info: &ValidatedBootInfo,
) -> Result<PrimordialBootModules, PrimordialModuleError> {
    let mut bootstrap = None;
    let mut bootfs = None;

    for module in boot_info.module_entries[..boot_info.modules.entry_count as usize]
        .iter()
        .copied()
    {
        let selected = match module.kind.0 {
            kind if kind == DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP.0 => {
                if module.flags.0 != 0 {
                    return Err(PrimordialModuleError::InvalidBootstrapFlags);
                }
                &mut bootstrap
            }
            kind if kind == DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS.0 => {
                if module.flags != DW_BOOT_MODULE_FLAG_READ_ONLY {
                    return Err(PrimordialModuleError::InvalidBootfsFlags);
                }
                &mut bootfs
            }
            _ => continue,
        };
        let module = primordial_module(module.physical_start, module.byte_len)?;
        if selected.replace(module).is_some() {
            return Err(PrimordialModuleError::DuplicateRequiredModule);
        }
    }

    let (Some(bootstrap), Some(bootfs)) = (bootstrap, bootfs) else {
        return Err(PrimordialModuleError::MissingRequiredModule);
    };
    if ranges_overlap(bootstrap, bootfs)? {
        return Err(PrimordialModuleError::ModulePageOverlap);
    }
    Ok(PrimordialBootModules { bootstrap, bootfs })
}

fn primordial_module(
    physical_start: u64,
    byte_len: u64,
) -> Result<PrimordialModule, PrimordialModuleError> {
    if physical_start == 0 || byte_len == 0 || !physical_start.is_multiple_of(PAGE_SIZE) {
        return Err(PrimordialModuleError::InvalidModuleExtent);
    }
    let page_rounded_byte_len =
        align_up(byte_len, PAGE_SIZE).ok_or(PrimordialModuleError::InvalidModuleExtent)?;
    physical_start
        .checked_add(page_rounded_byte_len)
        .ok_or(PrimordialModuleError::InvalidModuleExtent)?;
    Ok(PrimordialModule {
        range: BootPhysicalRange {
            physical_start,
            byte_len,
        },
        page_rounded_byte_len,
    })
}

fn ranges_overlap(
    left: PrimordialModule,
    right: PrimordialModule,
) -> Result<bool, PrimordialModuleError> {
    let left_end = left
        .range
        .physical_start()
        .checked_add(left.page_rounded_byte_len)
        .ok_or(PrimordialModuleError::InvalidModuleExtent)?;
    let right_end = right
        .range
        .physical_start()
        .checked_add(right.page_rounded_byte_len)
        .ok_or(PrimordialModuleError::InvalidModuleExtent)?;
    Ok(left.range.physical_start() < right_end && right.range.physical_start() < left_end)
}

/// Read, write, and execute permissions for one planned load segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimordialSegmentPermissions(u8);

impl PrimordialSegmentPermissions {
    /// Segment may be read.
    pub const fn readable(self) -> bool {
        self.0 & PF_R as u8 != 0
    }

    /// Segment may be written.
    pub const fn writable(self) -> bool {
        self.0 & PF_W as u8 != 0
    }

    /// Segment may be executed.
    pub const fn executable(self) -> bool {
        self.0 & PF_X as u8 != 0
    }
}

/// One checked `PT_LOAD` record in an immutable primordial load plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimordialLoadSegment {
    file_offset: u64,
    file_byte_len: u64,
    memory_byte_len: u64,
    virtual_start: u64,
    page_start: u64,
    page_end_exclusive: u64,
    permissions: PrimordialSegmentPermissions,
}

impl PrimordialLoadSegment {
    /// Source offset inside the bootstrap module.
    pub const fn file_offset(self) -> u64 {
        self.file_offset
    }

    /// Number of initialized source bytes.
    pub const fn file_byte_len(self) -> u64 {
        self.file_byte_len
    }

    /// Total mapped bytes before page rounding.
    pub const fn memory_byte_len(self) -> u64 {
        self.memory_byte_len
    }

    /// Number of trailing BSS bytes that G2 must zero before publication.
    pub const fn bss_byte_len(self) -> u64 {
        self.memory_byte_len - self.file_byte_len
    }

    /// First virtual byte described by the ELF segment.
    pub const fn virtual_start(self) -> u64 {
        self.virtual_start
    }

    /// First page mapped for this segment.
    pub const fn page_start(self) -> u64 {
        self.page_start
    }

    /// Exclusive end of the page-rounded mapping.
    pub const fn page_end_exclusive(self) -> u64 {
        self.page_end_exclusive
    }

    /// Page-rounded mapping extent.
    pub const fn mapped_byte_len(self) -> u64 {
        self.page_end_exclusive - self.page_start
    }

    /// Final permissions that G2 must map without a W+X transition.
    pub const fn permissions(self) -> PrimordialSegmentPermissions {
        self.permissions
    }
}

/// Allocation-free ELF result consumed by the later primordial transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimordialElfLoadPlan {
    entry: u64,
    segments: [Option<PrimordialLoadSegment>; MAX_PRIMORDIAL_LOAD_SEGMENTS],
    segment_count: usize,
    mapped_byte_len: u64,
}

impl PrimordialElfLoadPlan {
    /// Validated executable entry point.
    pub const fn entry(self) -> u64 {
        self.entry
    }

    /// Number of `PT_LOAD` segments in this plan.
    pub const fn segment_count(self) -> usize {
        self.segment_count
    }

    /// Sum of page-rounded load mapping extents.
    pub const fn mapped_byte_len(self) -> u64 {
        self.mapped_byte_len
    }

    /// Returns a planned load segment by index.
    pub fn segment(&self, index: usize) -> Option<PrimordialLoadSegment> {
        self.segments.get(index).copied().flatten()
    }
}

/// Fail-closed reasons for the narrow primordial ELF64 subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimordialElfError {
    InvalidFileSize,
    TruncatedHeader,
    InvalidIdentification,
    UnsupportedType,
    UnsupportedMachine,
    UnsupportedVersion,
    InvalidHeaderSize,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderCount,
    ProgramHeaderTableOutOfRange,
    UnsupportedProgramHeader,
    DuplicateMetadataHeader,
    TooManyLoadSegments,
    SegmentFileRangeOutOfRange,
    FileSizeExceedsMemorySize,
    EmptyLoadSegment,
    InvalidSegmentAlignment,
    SegmentAddressOverflow,
    SegmentOutsideUserAddressSpace,
    UnsupportedSegmentPermissions,
    WritableExecutableSegment,
    ExecutableStack,
    PageRoundedSegmentOverlap,
    ImageSizeLimitExceeded,
    InvalidEntryPoint,
}

/// Parses the G0-locked static x86-64 ELF subset into an immutable load plan.
pub fn parse_primordial_elf(bytes: &[u8]) -> Result<PrimordialElfLoadPlan, PrimordialElfError> {
    if bytes.is_empty() || bytes.len() > MAX_PRIMORDIAL_ELF_BYTES {
        return Err(PrimordialElfError::InvalidFileSize);
    }
    if bytes.len() < ELF_HEADER_SIZE {
        return Err(PrimordialElfError::TruncatedHeader);
    }
    if bytes[..4] != *b"\x7fELF"
        || bytes[4] != ELF_CLASS_64
        || bytes[5] != ELF_DATA_LITTLE_ENDIAN
        || bytes[6] != ELF_CURRENT_VERSION
    {
        return Err(PrimordialElfError::InvalidIdentification);
    }
    if u16_at(bytes, 16)? != ELF_TYPE_EXECUTABLE {
        return Err(PrimordialElfError::UnsupportedType);
    }
    if u16_at(bytes, 18)? != ELF_MACHINE_X86_64 {
        return Err(PrimordialElfError::UnsupportedMachine);
    }
    if u32_at(bytes, 20)? != u32::from(ELF_CURRENT_VERSION) {
        return Err(PrimordialElfError::UnsupportedVersion);
    }
    if u16_at(bytes, 52)? as usize != ELF_HEADER_SIZE {
        return Err(PrimordialElfError::InvalidHeaderSize);
    }
    if u16_at(bytes, 54)? as usize != ELF_PROGRAM_HEADER_SIZE {
        return Err(PrimordialElfError::InvalidProgramHeaderSize);
    }
    let program_header_count = usize::from(u16_at(bytes, 56)?);
    if program_header_count == 0 || program_header_count > MAX_PRIMORDIAL_PROGRAM_HEADERS {
        return Err(PrimordialElfError::InvalidProgramHeaderCount);
    }
    let program_header_offset = usize::try_from(u64_at(bytes, 32)?)
        .map_err(|_| PrimordialElfError::ProgramHeaderTableOutOfRange)?;
    let program_header_len = program_header_count
        .checked_mul(ELF_PROGRAM_HEADER_SIZE)
        .ok_or(PrimordialElfError::ProgramHeaderTableOutOfRange)?;
    let program_header_end = program_header_offset
        .checked_add(program_header_len)
        .ok_or(PrimordialElfError::ProgramHeaderTableOutOfRange)?;
    if bytes
        .get(program_header_offset..program_header_end)
        .is_none()
    {
        return Err(PrimordialElfError::ProgramHeaderTableOutOfRange);
    }

    let entry = u64_at(bytes, 24)?;
    let mut segments = [None; MAX_PRIMORDIAL_LOAD_SEGMENTS];
    let mut segment_count = 0_usize;
    let mut mapped_byte_len = 0_u64;
    let mut seen_phdr = false;
    let mut seen_gnu_stack = false;

    for index in 0..program_header_count {
        let offset = program_header_offset + index * ELF_PROGRAM_HEADER_SIZE;
        let header = bytes
            .get(offset..offset + ELF_PROGRAM_HEADER_SIZE)
            .ok_or(PrimordialElfError::ProgramHeaderTableOutOfRange)?;
        let kind = u32_at(header, 0)?;
        let flags = u32_at(header, 4)?;
        match kind {
            PT_LOAD => {
                if segment_count == MAX_PRIMORDIAL_LOAD_SEGMENTS {
                    return Err(PrimordialElfError::TooManyLoadSegments);
                }
                let segment = parse_load_segment(header, bytes.len())?;
                for existing in segments[..segment_count].iter().flatten() {
                    if page_ranges_overlap(*existing, segment) {
                        return Err(PrimordialElfError::PageRoundedSegmentOverlap);
                    }
                }
                mapped_byte_len = mapped_byte_len
                    .checked_add(segment.mapped_byte_len())
                    .ok_or(PrimordialElfError::ImageSizeLimitExceeded)?;
                if mapped_byte_len > MAX_PRIMORDIAL_IMAGE_BYTES {
                    return Err(PrimordialElfError::ImageSizeLimitExceeded);
                }
                segments[segment_count] = Some(segment);
                segment_count += 1;
            }
            PT_PHDR => {
                if seen_phdr {
                    return Err(PrimordialElfError::DuplicateMetadataHeader);
                }
                seen_phdr = true;
                validate_metadata_file_range(header, bytes.len())?;
            }
            PT_GNU_STACK => {
                if seen_gnu_stack {
                    return Err(PrimordialElfError::DuplicateMetadataHeader);
                }
                seen_gnu_stack = true;
                if flags & PF_X != 0 {
                    return Err(PrimordialElfError::ExecutableStack);
                }
                if flags & !KNOWN_PROGRAM_FLAGS != 0 {
                    return Err(PrimordialElfError::UnsupportedSegmentPermissions);
                }
            }
            _ => return Err(PrimordialElfError::UnsupportedProgramHeader),
        }
    }

    if segment_count == 0
        || !segments[..segment_count].iter().flatten().any(|segment| {
            segment.permissions.executable()
                && entry >= segment.virtual_start
                && entry < segment.virtual_start + segment.memory_byte_len
        })
    {
        return Err(PrimordialElfError::InvalidEntryPoint);
    }

    Ok(PrimordialElfLoadPlan {
        entry,
        segments,
        segment_count,
        mapped_byte_len,
    })
}

fn parse_load_segment(
    header: &[u8],
    file_len: usize,
) -> Result<PrimordialLoadSegment, PrimordialElfError> {
    let flags = u32_at(header, 4)?;
    if flags & !KNOWN_PROGRAM_FLAGS != 0 {
        return Err(PrimordialElfError::UnsupportedSegmentPermissions);
    }
    if flags & PF_W != 0 && flags & PF_X != 0 {
        return Err(PrimordialElfError::WritableExecutableSegment);
    }
    if flags != PF_R && flags != PF_R | PF_W && flags != PF_R | PF_X {
        return Err(PrimordialElfError::UnsupportedSegmentPermissions);
    }
    let file_offset = u64_at(header, 8)?;
    let virtual_start = u64_at(header, 16)?;
    let file_byte_len = u64_at(header, 32)?;
    let memory_byte_len = u64_at(header, 40)?;
    let alignment = u64_at(header, 48)?;
    if file_byte_len > memory_byte_len {
        return Err(PrimordialElfError::FileSizeExceedsMemorySize);
    }
    if memory_byte_len == 0 {
        return Err(PrimordialElfError::EmptyLoadSegment);
    }
    let file_end = file_offset
        .checked_add(file_byte_len)
        .ok_or(PrimordialElfError::SegmentFileRangeOutOfRange)?;
    if file_end > file_len as u64 {
        return Err(PrimordialElfError::SegmentFileRangeOutOfRange);
    }
    if alignment > 1
        && (!alignment.is_power_of_two() || file_offset % alignment != virtual_start % alignment)
    {
        return Err(PrimordialElfError::InvalidSegmentAlignment);
    }
    let memory_end = virtual_start
        .checked_add(memory_byte_len)
        .ok_or(PrimordialElfError::SegmentAddressOverflow)?;
    let page_start = align_down(virtual_start, PAGE_SIZE);
    let page_end_exclusive =
        align_up(memory_end, PAGE_SIZE).ok_or(PrimordialElfError::SegmentAddressOverflow)?;
    if page_start < PAGE_SIZE || page_end_exclusive > USER_END_EXCLUSIVE {
        return Err(PrimordialElfError::SegmentOutsideUserAddressSpace);
    }
    Ok(PrimordialLoadSegment {
        file_offset,
        file_byte_len,
        memory_byte_len,
        virtual_start,
        page_start,
        page_end_exclusive,
        permissions: PrimordialSegmentPermissions(flags as u8),
    })
}

fn validate_metadata_file_range(header: &[u8], file_len: usize) -> Result<(), PrimordialElfError> {
    let offset = u64_at(header, 8)?;
    let byte_len = u64_at(header, 32)?;
    let end = offset
        .checked_add(byte_len)
        .ok_or(PrimordialElfError::SegmentFileRangeOutOfRange)?;
    if end > file_len as u64 {
        return Err(PrimordialElfError::SegmentFileRangeOutOfRange);
    }
    Ok(())
}

fn page_ranges_overlap(left: PrimordialLoadSegment, right: PrimordialLoadSegment) -> bool {
    left.page_start < right.page_end_exclusive && right.page_start < left.page_end_exclusive
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, PrimordialElfError> {
    let end = offset
        .checked_add(2)
        .ok_or(PrimordialElfError::TruncatedHeader)?;
    let bytes: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(PrimordialElfError::TruncatedHeader)?
        .try_into()
        .map_err(|_| PrimordialElfError::TruncatedHeader)?;
    Ok(u16::from_le_bytes(bytes))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, PrimordialElfError> {
    let end = offset
        .checked_add(4)
        .ok_or(PrimordialElfError::TruncatedHeader)?;
    let bytes: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(PrimordialElfError::TruncatedHeader)?
        .try_into()
        .map_err(|_| PrimordialElfError::TruncatedHeader)?;
    Ok(u32::from_le_bytes(bytes))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, PrimordialElfError> {
    let end = offset
        .checked_add(8)
        .ok_or(PrimordialElfError::TruncatedHeader)?;
    let bytes: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(PrimordialElfError::TruncatedHeader)?
        .try_into()
        .map_err(|_| PrimordialElfError::TruncatedHeader)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests;

#[allow(
    dead_code,
    reason = "DW0-G2 host construction gate precedes live boot-path wiring"
)]
#[cfg(deepwyrm_integrated)]
pub(crate) mod construction;
