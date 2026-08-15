//! Validated loader-to-kernel boot handoff intake.
//!
//! This module deliberately owns no early page-table or physical-memory
//! mapping policy.  Its caller supplies the narrow [`BootInfoByteReader`]
//! adapter appropriate for the architecture-entry environment. Intake copies
//! the fixed BootInfo header and every retained table record into bounded
//! snapshot storage before later code can inspect it.

use deepwyrm_abi::{
    DW_BOOT_BASE_PAGE_SIZE, DW_BOOT_ENTROPY_FLAG_CONDITIONED,
    DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM, DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE,
    DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL, DW_BOOT_ENTROPY_V1_SIZE, DW_BOOT_ENTROPY_V1_VERSION,
    DW_BOOT_FRAMEBUFFER_FLAG_LINEAR, DW_BOOT_FRAMEBUFFER_V1_SIZE, DW_BOOT_FRAMEBUFFER_V1_VERSION,
    DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT, DW_BOOT_INFO_V1_SIZE, DW_BOOT_INFO_V1_VERSION,
    DW_BOOT_MEMORY_KIND_ACPI_NVS, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM, DW_BOOT_MEMORY_KIND_MMIO,
    DW_BOOT_MEMORY_KIND_RESERVED, DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES,
    DW_BOOT_MEMORY_KIND_UNUSABLE, DW_BOOT_MEMORY_KIND_USABLE, DW_BOOT_MEMORY_RANGE_V1_SIZE,
    DW_BOOT_MEMORY_RANGE_V1_VERSION, DW_BOOT_MODULE_FLAG_READ_ONLY,
    DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DW_BOOT_MODULE_V1_SIZE, DW_BOOT_MODULE_V1_VERSION,
    DW_BOOT_PIXEL_FORMAT_BGRX8, DW_BOOT_PIXEL_FORMAT_BITMASK, DW_BOOT_PIXEL_FORMAT_RGBX8,
    DW_BOOT_X86_64_PAGING_HANDOFF_FLAGS_SUPPORTED_MASK,
    DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION, DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_PHYSICAL_ADDRESS_WIDTH,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_PHYSICAL_ADDRESS_WIDTH,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT, DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
    DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS, DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE,
    DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION, DwBootEntropyFlags, DwBootEntropySource,
    DwBootEntropyV1, DwBootFramebufferFlags, DwBootFramebufferV1, DwBootInfoFlags, DwBootInfoV1,
    DwBootMemoryKind, DwBootMemoryRangeV1, DwBootModuleFlags, DwBootModuleKind, DwBootModuleV1,
    DwBootPixelFormat, DwBootX86_64PagingHandoffFlags, DwBootX86_64PagingHandoffV1,
};

const KNOWN_BOOT_INFO_FLAGS: u64 = DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT.0;
const KNOWN_ENTROPY_FLAGS: u32 = DW_BOOT_ENTROPY_FLAG_CONDITIONED.0;
const KNOWN_FRAMEBUFFER_FLAGS: u32 = DW_BOOT_FRAMEBUFFER_FLAG_LINEAR.0;
const KNOWN_MODULE_FLAGS: u32 = DW_BOOT_MODULE_FLAG_READ_ONLY.0;

/// Maximum normalized memory-map records retained by the allocation-free
/// DW0-B BootInfo snapshot.
pub const MAX_BOOT_MEMORY_MAP_ENTRIES: usize = 128;

/// Maximum boot-module records retained by the allocation-free DW0-B BootInfo
/// snapshot.
pub const MAX_BOOT_MODULE_ENTRIES: usize = 16;

const MAX_PAGING_HANDOFF_TABLE_FRAMES: usize =
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as usize;
const MAX_PAGING_HANDOFF_BYTES: usize = DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN as usize;

/// An architecture-entry adapter that can copy bytes from a physical range.
///
/// The adapter is intentionally narrower than a physical mapping interface:
/// validating the handoff does not select page-table ownership or an early
/// direct-map convention.
pub trait BootInfoByteReader {
    /// Copies exactly `destination.len()` bytes from `physical_start`.
    #[allow(
        clippy::result_unit_err,
        reason = "the parser deliberately maps all architecture read failures to InvalidAddress"
    )]
    fn read_exact(&self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()>;
}

/// A checked, non-empty physical byte range retained after BootInfo intake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootPhysicalRange {
    physical_start: u64,
    byte_len: u64,
}

impl BootPhysicalRange {
    /// Physical start address of the range.
    pub const fn physical_start(self) -> u64 {
        self.physical_start
    }

    /// Exact byte length of the range.
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }
}

/// A loader module that may be wrapped in a read-only userspace capability.
///
/// Construction is private to validated BootInfo intake. In ABI V1 only the
/// Wyrmroot bootfs module is delegable; the bootstrap ELF is consumed by the
/// kernel and the kind-3 paging carrier remains kernel-internal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegableBootModule {
    range: BootPhysicalRange,
}

impl DelegableBootModule {
    /// Exact immutable payload range authorized for later read-only wrapping.
    pub const fn range(self) -> BootPhysicalRange {
        self.range
    }
}

/// A validated fixed-stride physical table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootInfoTable {
    physical_start: u64,
    entry_count: u64,
    entry_size: u32,
}

impl BootInfoTable {
    /// Physical start address of the table.
    pub const fn physical_start(self) -> u64 {
        self.physical_start
    }

    /// Number of entries in the table.
    pub const fn entry_count(self) -> u64 {
        self.entry_count
    }

    /// Fixed physical stride of each entry.
    pub const fn entry_size(self) -> u32 {
        self.entry_size
    }
}

/// Bounded validation work and snapshot storage for untrusted table counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootInfoValidationLimits {
    /// Maximum memory-map records accepted during early boot intake.
    pub max_memory_map_entries: u64,
    /// Maximum boot-module records accepted during early boot intake.
    pub max_module_entries: u64,
}

impl Default for BootInfoValidationLimits {
    fn default() -> Self {
        Self {
            max_memory_map_entries: MAX_BOOT_MEMORY_MAP_ENTRIES as u64,
            max_module_entries: MAX_BOOT_MODULE_ENTRIES as u64,
        }
    }
}

/// The copied header and immutable table snapshots retained by DW0-B intake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedBootInfo {
    header: DwBootInfoV1,
    memory_map: BootInfoTable,
    modules: BootInfoTable,
    command_line: Option<BootPhysicalRange>,
    entropy: Option<BootPhysicalRange>,
    framebuffer: Option<DwBootFramebufferV1>,
    memory_ranges: [DwBootMemoryRangeV1; MAX_BOOT_MEMORY_MAP_ENTRIES],
    module_entries: [DwBootModuleV1; MAX_BOOT_MODULE_ENTRIES],
    paging_handoff: ValidatedPagingHandoff,
}

/// Owned, one-snapshot structural interpretation of the loader's internal
/// paging carrier.
///
/// This snapshot does not attest the live CR3 graph, CPU control state, page
/// permissions, cache configuration, or ownership transfer. The architecture
/// transition boundary must compare those facts with this declaration before
/// it mutates the temporary leaf or replaces CR3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedPagingHandoff {
    header: DwBootX86_64PagingHandoffV1,
    table_frames: [u64; MAX_PAGING_HANDOFF_TABLE_FRAMES],
    table_frame_count: usize,
}

impl ValidatedPagingHandoff {
    /// Returns the copied fixed carrier header.
    pub const fn header(&self) -> &DwBootX86_64PagingHandoffV1 {
        &self.header
    }

    /// Number of copied transition page-table frame addresses.
    pub const fn table_frame_count(&self) -> usize {
        self.table_frame_count
    }

    /// Returns one copied transition page-table frame address.
    pub fn table_frame(&self, index: usize) -> Result<u64, BootInfoValidationError> {
        self.table_frames
            .get(index)
            .copied()
            .filter(|_| index < self.table_frame_count)
            .ok_or(BootInfoValidationError::TableIndexOutOfBounds)
    }
}

impl ValidatedBootInfo {
    /// Returns the copied ABI header for early diagnostics.
    pub const fn header(&self) -> &DwBootInfoV1 {
        &self.header
    }

    /// Returns the validated physical memory-map table description.
    pub const fn memory_map(&self) -> BootInfoTable {
        self.memory_map
    }

    /// Returns the validated physical boot-module table description.
    pub const fn modules(&self) -> BootInfoTable {
        self.modules
    }

    /// Returns the optional opaque command-line byte range.
    pub const fn command_line(&self) -> Option<BootPhysicalRange> {
        self.command_line
    }

    /// Returns the optional firmware entropy byte range.
    pub const fn entropy(&self) -> Option<BootPhysicalRange> {
        self.entropy
    }

    /// Returns the optional validated framebuffer descriptor.
    pub const fn framebuffer(&self) -> Option<DwBootFramebufferV1> {
        self.framebuffer
    }

    /// Returns one immutable memory-map record copied during intake.
    pub fn memory_range(&self, index: u64) -> Result<DwBootMemoryRangeV1, BootInfoValidationError> {
        let index = checked_snapshot_index(index, self.memory_map.entry_count)?;
        Ok(self.memory_ranges[index])
    }

    /// Returns a typed module payload only when the ABI permits delegation.
    ///
    /// The internal kind-3 paging carrier and the kernel-consumed bootstrap ELF
    /// fail closed instead of escaping through a generic module-record API.
    pub fn delegable_module(
        &self,
        index: u64,
    ) -> Result<DelegableBootModule, BootInfoValidationError> {
        let index = checked_snapshot_index(index, self.modules.entry_count)?;
        let module = self.module_entries[index];
        if module.kind != DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS {
            return Err(BootInfoValidationError::ModuleNotDelegable);
        }
        Ok(DelegableBootModule {
            range: module_range(module),
        })
    }

    /// Returns one module range solely for allocator reservation collection.
    pub(crate) fn module_reservation_range(
        &self,
        index: u64,
    ) -> Result<BootPhysicalRange, BootInfoValidationError> {
        let index = checked_snapshot_index(index, self.modules.entry_count)?;
        Ok(module_range(self.module_entries[index]))
    }

    /// Returns the copied and validated internal x86_64 paging handoff.
    pub const fn paging_handoff(&self) -> &ValidatedPagingHandoff {
        &self.paging_handoff
    }
}

/// Precise fail-closed reasons suitable for an early serial/panic path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootInfoValidationError {
    ReadFailure,
    UnalignedAddress,
    ArithmeticOverflow,
    EmptyRange,
    UnsupportedVersion,
    StructureTooSmall,
    StructureLargerThanStride,
    NonZeroReserved,
    UnknownFlags,
    UnknownMemoryKind,
    UnknownModuleKind,
    UnknownPixelFormat,
    UnknownEntropySource,
    InvalidTable,
    EntryCountLimitExceeded,
    MissingRequiredModule,
    DuplicateRequiredModule,
    OverlappingModules,
    InvalidModuleFlags,
    InvalidFramebuffer,
    InvalidEntropy,
    InvalidCommandLine,
    InvalidPagingHandoff,
    PagingHandoffFrameRoleOverlap,
    PagingHandoffFrameNotReserved,
    ModuleNotDelegable,
    TableIndexOutOfBounds,
}

/// Copies and validates a loader-supplied `DwBootInfoV1` handoff.
///
/// This is intentionally a structural boundary only.  It verifies every
/// encoded table and payload range before later boot code receives it. It also
/// requires every declared paging frame to have exactly one normalized
/// `RESERVED` memory-map owner before exposing the paging snapshot. It does not
/// establish a frame allocator or map physical pages.
pub fn validate_boot_info<R: BootInfoByteReader>(
    reader: &R,
    boot_info_physical_start: u64,
) -> Result<ValidatedBootInfo, BootInfoValidationError> {
    validate_boot_info_with_limits(
        reader,
        boot_info_physical_start,
        BootInfoValidationLimits::default(),
    )
}

/// As [`validate_boot_info`], with explicit bounded-work limits for hostile
/// table counts.
pub fn validate_boot_info_with_limits<R: BootInfoByteReader>(
    reader: &R,
    boot_info_physical_start: u64,
    limits: BootInfoValidationLimits,
) -> Result<ValidatedBootInfo, BootInfoValidationError> {
    if limits.max_memory_map_entries > MAX_BOOT_MEMORY_MAP_ENTRIES as u64
        || limits.max_module_entries > MAX_BOOT_MODULE_ENTRIES as u64
    {
        return Err(BootInfoValidationError::EntryCountLimitExceeded);
    }
    if boot_info_physical_start == 0 {
        return Err(BootInfoValidationError::EmptyRange);
    }
    let header_range = checked_range(boot_info_physical_start, u64::from(DW_BOOT_INFO_V1_SIZE), 8)?;
    let mut bytes = [0_u8; DW_BOOT_INFO_V1_SIZE as usize];
    read(reader, header_range.physical_start, &mut bytes)?;
    let header = parse_boot_info(&bytes)?;

    validate_record_header(
        header.size,
        header.version,
        DW_BOOT_INFO_V1_SIZE,
        DW_BOOT_INFO_V1_VERSION,
        None,
    )?;
    let boot_info_range = checked_range(boot_info_physical_start, u64::from(header.size), 8)?;
    validate_zeroes(&header.reserved)?;
    if header.reserved0 != 0 || header.reserved1 != 0 {
        return Err(BootInfoValidationError::NonZeroReserved);
    }
    if header.flags.0 & !KNOWN_BOOT_INFO_FLAGS != 0 {
        return Err(BootInfoValidationError::UnknownFlags);
    }

    let memory_map = validate_table(
        header.memory_map_physical_start,
        header.memory_map_entry_count,
        header.memory_map_entry_size,
        DW_BOOT_MEMORY_RANGE_V1_SIZE,
        limits.max_memory_map_entries,
    )?;
    let modules = validate_table(
        header.modules_physical_start,
        header.module_count,
        header.module_entry_size,
        DW_BOOT_MODULE_V1_SIZE,
        limits.max_module_entries,
    )?;

    let command_line = optional_range(
        header.command_line_physical_start,
        header.command_line_byte_len,
        1,
        BootInfoValidationError::InvalidCommandLine,
    )?;
    if header.acpi_rsdp_physical_address != 0 && header.acpi_rsdp_physical_address % 8 != 0 {
        return Err(BootInfoValidationError::UnalignedAddress);
    }

    let framebuffer = validate_framebuffer(header.flags, header.framebuffer)?;
    let entropy = validate_entropy(header.entropy)?;

    let mut memory_ranges = core::array::from_fn(|_| DwBootMemoryRangeV1::default());
    for (index, record) in memory_ranges
        .iter_mut()
        .take(memory_map.entry_count as usize)
        .enumerate()
    {
        let bytes = read_table_entry(reader, memory_map, index as u64)?;
        *record = parse_memory_range(&bytes, memory_map.entry_size)?;
    }

    let mut bootstrap = None;
    let mut bootfs = None;
    let mut paging_handoff_module = None;
    let mut module_entries = core::array::from_fn(|_| DwBootModuleV1::default());
    for (index, module) in module_entries
        .iter_mut()
        .take(modules.entry_count as usize)
        .enumerate()
    {
        let bytes = read_table_entry(reader, modules, index as u64)?;
        *module = parse_module(&bytes, modules.entry_size)?;
        let range = BootPhysicalRange {
            physical_start: module.physical_start,
            byte_len: module.byte_len,
        };
        match module.kind.0 {
            kind if kind == DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP.0 => {
                if bootstrap.replace(range).is_some() {
                    return Err(BootInfoValidationError::DuplicateRequiredModule);
                }
            }
            kind if kind == DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS.0 => {
                if module.flags != DW_BOOT_MODULE_FLAG_READ_ONLY {
                    return Err(BootInfoValidationError::InvalidModuleFlags);
                }
                if bootfs.replace(range).is_some() {
                    return Err(BootInfoValidationError::DuplicateRequiredModule);
                }
            }
            kind if kind == DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1.0 => {
                if module.flags != DW_BOOT_MODULE_FLAG_READ_ONLY {
                    return Err(BootInfoValidationError::InvalidModuleFlags);
                }
                if paging_handoff_module.replace(*module).is_some() {
                    return Err(BootInfoValidationError::DuplicateRequiredModule);
                }
            }
            _ => return Err(BootInfoValidationError::UnknownModuleKind),
        }
    }
    let (Some(_bootstrap), Some(_bootfs), Some(paging_handoff_module)) =
        (bootstrap, bootfs, paging_handoff_module)
    else {
        return Err(BootInfoValidationError::MissingRequiredModule);
    };

    let active_modules = &module_entries[..modules.entry_count as usize];
    for (left, module) in active_modules.iter().copied().enumerate() {
        let left_range = module_range(module);
        for right in active_modules.iter().copied().skip(left + 1) {
            if ranges_overlap(left_range, module_range(right))? {
                return Err(BootInfoValidationError::OverlappingModules);
            }
        }
    }

    let paging_handoff = parse_paging_handoff_snapshot(reader, paging_handoff_module)?;
    validate_paging_handoff_roles_and_reservation(
        &paging_handoff,
        boot_info_range,
        memory_map,
        modules,
        &module_entries[..modules.entry_count as usize],
        &memory_ranges[..memory_map.entry_count as usize],
        command_line,
        entropy,
        framebuffer,
        header.acpi_rsdp_physical_address,
    )?;

    Ok(ValidatedBootInfo {
        header,
        memory_map,
        modules,
        command_line,
        entropy,
        framebuffer,
        memory_ranges,
        module_entries,
        paging_handoff,
    })
}

fn checked_snapshot_index(index: u64, entry_count: u64) -> Result<usize, BootInfoValidationError> {
    if index >= entry_count {
        return Err(BootInfoValidationError::TableIndexOutOfBounds);
    }
    usize::try_from(index).map_err(|_| BootInfoValidationError::TableIndexOutOfBounds)
}

fn validate_table(
    physical_start: u64,
    entry_count: u64,
    entry_size: u32,
    minimum_entry_size: u32,
    maximum_entry_count: u64,
) -> Result<BootInfoTable, BootInfoValidationError> {
    if entry_count == 0 || entry_count > maximum_entry_count {
        return Err(BootInfoValidationError::EntryCountLimitExceeded);
    }
    if entry_size < minimum_entry_size || !entry_size.is_multiple_of(8) {
        return Err(BootInfoValidationError::InvalidTable);
    }
    let byte_len = entry_count
        .checked_mul(u64::from(entry_size))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    checked_range(physical_start, byte_len, 8)?;
    Ok(BootInfoTable {
        physical_start,
        entry_count,
        entry_size,
    })
}

fn read_table_entry<R: BootInfoByteReader>(
    reader: &R,
    table: BootInfoTable,
    index: u64,
) -> Result<[u8; DW_BOOT_MEMORY_RANGE_V1_SIZE as usize], BootInfoValidationError> {
    if index >= table.entry_count {
        return Err(BootInfoValidationError::TableIndexOutOfBounds);
    }
    let offset = index
        .checked_mul(u64::from(table.entry_size))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let physical_start = table
        .physical_start
        .checked_add(offset)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let mut bytes = [0_u8; DW_BOOT_MEMORY_RANGE_V1_SIZE as usize];
    read(reader, physical_start, &mut bytes)?;
    Ok(bytes)
}

fn parse_boot_info(
    bytes: &[u8; DW_BOOT_INFO_V1_SIZE as usize],
) -> Result<DwBootInfoV1, BootInfoValidationError> {
    Ok(DwBootInfoV1 {
        size: u32_at(bytes, 0)?,
        version: u32_at(bytes, 4)?,
        flags: DwBootInfoFlags(u64_at(bytes, 8)?),
        memory_map_physical_start: u64_at(bytes, 16)?,
        memory_map_entry_count: u64_at(bytes, 24)?,
        memory_map_entry_size: u32_at(bytes, 32)?,
        reserved0: u32_at(bytes, 36)?,
        modules_physical_start: u64_at(bytes, 40)?,
        module_count: u64_at(bytes, 48)?,
        module_entry_size: u32_at(bytes, 56)?,
        reserved1: u32_at(bytes, 60)?,
        acpi_rsdp_physical_address: u64_at(bytes, 64)?,
        framebuffer: parse_framebuffer(&bytes[72..168])?,
        command_line_physical_start: u64_at(bytes, 168)?,
        command_line_byte_len: u64_at(bytes, 176)?,
        entropy: parse_entropy(&bytes[184..248])?,
        reserved: u64_array(bytes, 248)?,
    })
}

fn parse_memory_range(
    bytes: &[u8; DW_BOOT_MEMORY_RANGE_V1_SIZE as usize],
    stride: u32,
) -> Result<DwBootMemoryRangeV1, BootInfoValidationError> {
    let record = DwBootMemoryRangeV1 {
        size: u32_at(bytes, 0)?,
        version: u32_at(bytes, 4)?,
        kind: DwBootMemoryKind(u32_at(bytes, 8)?),
        reserved0: u32_at(bytes, 12)?,
        physical_start: u64_at(bytes, 16)?,
        page_count: u64_at(bytes, 24)?,
        firmware_attributes: u64_at(bytes, 32)?,
        reserved: u64_array_at(bytes, 40, 3)?,
    };
    validate_record_header(
        record.size,
        record.version,
        DW_BOOT_MEMORY_RANGE_V1_SIZE,
        DW_BOOT_MEMORY_RANGE_V1_VERSION,
        Some(stride),
    )?;
    if record.reserved0 != 0 {
        return Err(BootInfoValidationError::NonZeroReserved);
    }
    validate_zeroes(&record.reserved)?;
    if !matches!(
        record.kind.0,
        kind if kind == DW_BOOT_MEMORY_KIND_USABLE.0
            || kind == DW_BOOT_MEMORY_KIND_RESERVED.0
            || kind == DW_BOOT_MEMORY_KIND_ACPI_RECLAIM.0
            || kind == DW_BOOT_MEMORY_KIND_ACPI_NVS.0
            || kind == DW_BOOT_MEMORY_KIND_MMIO.0
            || kind == DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES.0
            || kind == DW_BOOT_MEMORY_KIND_UNUSABLE.0
    ) {
        return Err(BootInfoValidationError::UnknownMemoryKind);
    }
    if record.page_count == 0 {
        return Err(BootInfoValidationError::EmptyRange);
    }
    let byte_len = record
        .page_count
        .checked_mul(u64::from(DW_BOOT_BASE_PAGE_SIZE))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    checked_range(
        record.physical_start,
        byte_len,
        u64::from(DW_BOOT_BASE_PAGE_SIZE),
    )?;
    Ok(record)
}

fn parse_module(
    bytes: &[u8; DW_BOOT_MODULE_V1_SIZE as usize],
    stride: u32,
) -> Result<DwBootModuleV1, BootInfoValidationError> {
    let record = DwBootModuleV1 {
        size: u32_at(bytes, 0)?,
        version: u32_at(bytes, 4)?,
        kind: DwBootModuleKind(u32_at(bytes, 8)?),
        flags: DwBootModuleFlags(u32_at(bytes, 12)?),
        physical_start: u64_at(bytes, 16)?,
        byte_len: u64_at(bytes, 24)?,
        reserved: u64_array_at(bytes, 32, 4)?,
    };
    validate_record_header(
        record.size,
        record.version,
        DW_BOOT_MODULE_V1_SIZE,
        DW_BOOT_MODULE_V1_VERSION,
        Some(stride),
    )?;
    validate_zeroes(&record.reserved)?;
    if record.flags.0 & !KNOWN_MODULE_FLAGS != 0 {
        return Err(BootInfoValidationError::UnknownFlags);
    }
    checked_range(
        record.physical_start,
        record.byte_len,
        u64::from(DW_BOOT_BASE_PAGE_SIZE),
    )?;
    Ok(record)
}

fn parse_paging_handoff_snapshot<R: BootInfoByteReader>(
    reader: &R,
    module: DwBootModuleV1,
) -> Result<ValidatedPagingHandoff, BootInfoValidationError> {
    if module.flags != DW_BOOT_MODULE_FLAG_READ_ONLY
        || module.byte_len < u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE)
        || module.byte_len > u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN)
    {
        return Err(BootInfoValidationError::InvalidPagingHandoff);
    }
    let byte_len = usize::try_from(module.byte_len)
        .map_err(|_| BootInfoValidationError::InvalidPagingHandoff)?;
    let mut snapshot = [0_u8; MAX_PAGING_HANDOFF_BYTES];
    read(reader, module.physical_start, &mut snapshot[..byte_len])?;
    let bytes = &snapshot[..byte_len];

    let header = DwBootX86_64PagingHandoffV1 {
        size: u32_at(bytes, 0)?,
        version: u32_at(bytes, 4)?,
        flags: DwBootX86_64PagingHandoffFlags(u32_at(bytes, 8)?),
        physical_address_width: u32_at(bytes, 12)?,
        cr3_root_physical: u64_at(bytes, 16)?,
        table_frames_offset: u32_at(bytes, 24)?,
        table_frame_count: u32_at(bytes, 28)?,
        table_frame_stride: u32_at(bytes, 32)?,
        total_byte_len: u32_at(bytes, 36)?,
        paging_layout_version: u32_at(bytes, 40)?,
        reserved0: u32_at(bytes, 44)?,
        temporary_virtual_address: u64_at(bytes, 48)?,
        pml4_index: u16_at(bytes, 56)?,
        pdpt_index: u16_at(bytes, 58)?,
        pd_index: u16_at(bytes, 60)?,
        pt_index: u16_at(bytes, 62)?,
        temporary_pdpt_frame_physical: u64_at(bytes, 64)?,
        temporary_pd_frame_physical: u64_at(bytes, 72)?,
        temporary_pt_frame_physical: u64_at(bytes, 80)?,
        reserved: u64_array_at(bytes, 88, 3)?,
    };
    if header.size != DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE
        || header.version != DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION
        || header.flags != DW_BOOT_X86_64_PAGING_HANDOFF_FLAGS_SUPPORTED_MASK
        || header.reserved0 != 0
        || header.reserved != [0; 3]
        || header.paging_layout_version != DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION
        || header.temporary_virtual_address
            != DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS
        || header.pml4_index != DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX
        || header.pdpt_index != DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX
        || header.pd_index != DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX
        || header.pt_index != DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX
    {
        return Err(BootInfoValidationError::InvalidPagingHandoff);
    }
    if !(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_PHYSICAL_ADDRESS_WIDTH
        ..=DW_BOOT_X86_64_PAGING_HANDOFF_MAX_PHYSICAL_ADDRESS_WIDTH)
        .contains(&header.physical_address_width)
    {
        return Err(BootInfoValidationError::InvalidPagingHandoff);
    }
    if header.table_frames_offset != DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
        || header.table_frame_stride != DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE
        || !(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT
            ..=DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT)
            .contains(&header.table_frame_count)
    {
        return Err(BootInfoValidationError::InvalidPagingHandoff);
    }
    let exact_byte_len = header
        .table_frame_count
        .checked_mul(header.table_frame_stride)
        .and_then(|list_len| header.table_frames_offset.checked_add(list_len))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    if header.total_byte_len != exact_byte_len
        || module.byte_len != u64::from(exact_byte_len)
        || usize::try_from(exact_byte_len).ok() != Some(byte_len)
    {
        return Err(BootInfoValidationError::InvalidPagingHandoff);
    }

    let frame_count = usize::try_from(header.table_frame_count)
        .map_err(|_| BootInfoValidationError::InvalidPagingHandoff)?;
    let list_offset = usize::try_from(header.table_frames_offset)
        .map_err(|_| BootInfoValidationError::InvalidPagingHandoff)?;
    let mut table_frames = [0_u64; MAX_PAGING_HANDOFF_TABLE_FRAMES];
    for (index, frame) in table_frames.iter_mut().take(frame_count).enumerate() {
        let offset = index
            .checked_mul(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE as usize)
            .and_then(|offset| list_offset.checked_add(offset))
            .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
        *frame = u64_at(bytes, offset)?;
    }
    let physical_limit = 1_u64
        .checked_shl(header.physical_address_width)
        .ok_or(BootInfoValidationError::InvalidPagingHandoff)?;
    let frames = &table_frames[..frame_count];
    if frames.windows(2).any(|pair| pair[0] >= pair[1])
        || frames.iter().any(|frame| {
            *frame == 0
                || !frame.is_multiple_of(u64::from(DW_BOOT_BASE_PAGE_SIZE))
                || *frame >= physical_limit
        })
    {
        return Err(BootInfoValidationError::InvalidPagingHandoff);
    }
    let required_frames = [
        header.cr3_root_physical,
        header.temporary_pdpt_frame_physical,
        header.temporary_pd_frame_physical,
        header.temporary_pt_frame_physical,
    ];
    for (index, frame) in required_frames.iter().copied().enumerate() {
        if frame == 0
            || !frame.is_multiple_of(u64::from(DW_BOOT_BASE_PAGE_SIZE))
            || frame >= physical_limit
            || required_frames[..index].contains(&frame)
            || !frames.contains(&frame)
        {
            return Err(BootInfoValidationError::InvalidPagingHandoff);
        }
    }

    Ok(ValidatedPagingHandoff {
        header,
        table_frames,
        table_frame_count: frame_count,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the complete ABI-enumerated handoff set is explicit at this trust boundary"
)]
fn validate_paging_handoff_roles_and_reservation(
    paging: &ValidatedPagingHandoff,
    boot_info: BootPhysicalRange,
    memory_map: BootInfoTable,
    modules: BootInfoTable,
    module_entries: &[DwBootModuleV1],
    memory_ranges: &[DwBootMemoryRangeV1],
    command_line: Option<BootPhysicalRange>,
    entropy: Option<BootPhysicalRange>,
    framebuffer: Option<DwBootFramebufferV1>,
    acpi_rsdp_physical_address: u64,
) -> Result<(), BootInfoValidationError> {
    let memory_map_range = table_physical_range(memory_map)?;
    let module_table_range = table_physical_range(modules)?;
    // The ABI carries only the RSDP start. Layout v2 permits a validated ACPI
    // 2.0 declared length through one base page, which can intersect two
    // physical pages when the 8-byte-aligned record begins near a page end.
    // Excluding the full maximum extent is conservative and prevents a table
    // frame from aliasing any possible retained RSDP tail.
    let acpi_rsdp_maximum_range = if acpi_rsdp_physical_address == 0 {
        None
    } else {
        Some(checked_range(
            acpi_rsdp_physical_address,
            u64::from(DW_BOOT_BASE_PAGE_SIZE),
            8,
        )?)
    };
    for index in 0..paging.table_frame_count {
        let frame = paging.table_frames[index];
        let frame_range = BootPhysicalRange {
            physical_start: frame,
            byte_len: u64::from(DW_BOOT_BASE_PAGE_SIZE),
        };
        if ranges_overlap(frame_range, boot_info)?
            || ranges_overlap(frame_range, memory_map_range)?
            || ranges_overlap(frame_range, module_table_range)?
            || command_line.is_some_and(|range| ranges_overlap(frame_range, range).unwrap_or(true))
            || entropy.is_some_and(|range| ranges_overlap(frame_range, range).unwrap_or(true))
            || framebuffer.is_some_and(|value| {
                ranges_overlap(
                    frame_range,
                    BootPhysicalRange {
                        physical_start: value.physical_start,
                        byte_len: value.byte_len,
                    },
                )
                .unwrap_or(true)
            })
            || acpi_rsdp_maximum_range
                .is_some_and(|range| ranges_overlap(frame_range, range).unwrap_or(true))
        {
            return Err(BootInfoValidationError::PagingHandoffFrameRoleOverlap);
        }
        for module in module_entries {
            if ranges_overlap(frame_range, module_range(*module))? {
                return Err(BootInfoValidationError::PagingHandoffFrameRoleOverlap);
            }
        }
        validate_paging_frame_reserved_coverage(frame_range, memory_ranges)?;
    }
    Ok(())
}

fn validate_paging_frame_reserved_coverage(
    frame: BootPhysicalRange,
    memory_ranges: &[DwBootMemoryRangeV1],
) -> Result<(), BootInfoValidationError> {
    let frame_end = frame
        .physical_start
        .checked_add(frame.byte_len)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let mut covering_records = 0_usize;

    for record in memory_ranges {
        let byte_len = record
            .page_count
            .checked_mul(u64::from(DW_BOOT_BASE_PAGE_SIZE))
            .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
        let range = BootPhysicalRange {
            physical_start: record.physical_start,
            byte_len,
        };
        if !ranges_overlap(frame, range)? {
            continue;
        }
        let range_end = range
            .physical_start
            .checked_add(range.byte_len)
            .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
        if record.kind != DW_BOOT_MEMORY_KIND_RESERVED
            || range.physical_start > frame.physical_start
            || range_end < frame_end
        {
            return Err(BootInfoValidationError::PagingHandoffFrameNotReserved);
        }
        covering_records = covering_records
            .checked_add(1)
            .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    }

    if covering_records != 1 {
        return Err(BootInfoValidationError::PagingHandoffFrameNotReserved);
    }
    Ok(())
}

fn module_range(module: DwBootModuleV1) -> BootPhysicalRange {
    BootPhysicalRange {
        physical_start: module.physical_start,
        byte_len: module.byte_len,
    }
}

fn table_physical_range(
    table: BootInfoTable,
) -> Result<BootPhysicalRange, BootInfoValidationError> {
    let byte_len = table
        .entry_count
        .checked_mul(u64::from(table.entry_size))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    checked_range(table.physical_start, byte_len, 8)
}

fn parse_framebuffer(bytes: &[u8]) -> Result<DwBootFramebufferV1, BootInfoValidationError> {
    if bytes.len() != DW_BOOT_FRAMEBUFFER_V1_SIZE as usize {
        return Err(BootInfoValidationError::ReadFailure);
    }
    Ok(DwBootFramebufferV1 {
        size: u32_at(bytes, 0)?,
        version: u32_at(bytes, 4)?,
        flags: DwBootFramebufferFlags(u32_at(bytes, 8)?),
        pixel_format: DwBootPixelFormat(u32_at(bytes, 12)?),
        physical_start: u64_at(bytes, 16)?,
        byte_len: u64_at(bytes, 24)?,
        width: u32_at(bytes, 32)?,
        height: u32_at(bytes, 36)?,
        pixels_per_scanline: u32_at(bytes, 40)?,
        reserved0: u32_at(bytes, 44)?,
        red_mask: u32_at(bytes, 48)?,
        green_mask: u32_at(bytes, 52)?,
        blue_mask: u32_at(bytes, 56)?,
        reserved_mask: u32_at(bytes, 60)?,
        reserved: u64_array_at(bytes, 64, 4)?,
    })
}

fn validate_framebuffer(
    info_flags: DwBootInfoFlags,
    framebuffer: DwBootFramebufferV1,
) -> Result<Option<DwBootFramebufferV1>, BootInfoValidationError> {
    if info_flags.0 & DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT.0 == 0 {
        if framebuffer != DwBootFramebufferV1::default() {
            return Err(BootInfoValidationError::InvalidFramebuffer);
        }
        return Ok(None);
    }
    validate_record_header(
        framebuffer.size,
        framebuffer.version,
        DW_BOOT_FRAMEBUFFER_V1_SIZE,
        DW_BOOT_FRAMEBUFFER_V1_VERSION,
        None,
    )
    .map_err(|_| BootInfoValidationError::InvalidFramebuffer)?;
    if framebuffer.flags.0 != KNOWN_FRAMEBUFFER_FLAGS
        || framebuffer.reserved0 != 0
        || framebuffer.reserved.iter().any(|word| *word != 0)
    {
        return Err(BootInfoValidationError::InvalidFramebuffer);
    }
    if !matches!(
        framebuffer.pixel_format.0,
        format if format == DW_BOOT_PIXEL_FORMAT_RGBX8.0
            || format == DW_BOOT_PIXEL_FORMAT_BGRX8.0
            || format == DW_BOOT_PIXEL_FORMAT_BITMASK.0
    ) {
        return Err(BootInfoValidationError::UnknownPixelFormat);
    }
    if framebuffer.width == 0
        || framebuffer.height == 0
        || framebuffer.pixels_per_scanline < framebuffer.width
    {
        return Err(BootInfoValidationError::InvalidFramebuffer);
    }
    let minimum_byte_len = u64::from(framebuffer.pixels_per_scanline)
        .checked_mul(u64::from(framebuffer.height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    if framebuffer.byte_len < minimum_byte_len {
        return Err(BootInfoValidationError::InvalidFramebuffer);
    }
    checked_range(framebuffer.physical_start, framebuffer.byte_len, 1)?;

    let masks = [
        framebuffer.red_mask,
        framebuffer.green_mask,
        framebuffer.blue_mask,
        framebuffer.reserved_mask,
    ];
    if framebuffer.pixel_format.0 == DW_BOOT_PIXEL_FORMAT_BITMASK.0 {
        if masks[..3].contains(&0) || masks_overlap(&masks) {
            return Err(BootInfoValidationError::InvalidFramebuffer);
        }
    } else if masks.iter().any(|mask| *mask != 0) {
        return Err(BootInfoValidationError::InvalidFramebuffer);
    }
    Ok(Some(framebuffer))
}

fn parse_entropy(bytes: &[u8]) -> Result<DwBootEntropyV1, BootInfoValidationError> {
    if bytes.len() != DW_BOOT_ENTROPY_V1_SIZE as usize {
        return Err(BootInfoValidationError::ReadFailure);
    }
    Ok(DwBootEntropyV1 {
        size: u32_at(bytes, 0)?,
        version: u32_at(bytes, 4)?,
        source: DwBootEntropySource(u32_at(bytes, 8)?),
        flags: DwBootEntropyFlags(u32_at(bytes, 12)?),
        physical_start: u64_at(bytes, 16)?,
        byte_len: u64_at(bytes, 24)?,
        reserved: u64_array_at(bytes, 32, 4)?,
    })
}

fn validate_entropy(
    entropy: DwBootEntropyV1,
) -> Result<Option<BootPhysicalRange>, BootInfoValidationError> {
    if entropy == DwBootEntropyV1::default() {
        return Ok(None);
    }
    validate_record_header(
        entropy.size,
        entropy.version,
        DW_BOOT_ENTROPY_V1_SIZE,
        DW_BOOT_ENTROPY_V1_VERSION,
        None,
    )
    .map_err(|_| BootInfoValidationError::InvalidEntropy)?;
    if entropy.flags.0 & !KNOWN_ENTROPY_FLAGS != 0 || entropy.reserved.iter().any(|word| *word != 0)
    {
        return Err(BootInfoValidationError::InvalidEntropy);
    }
    if !matches!(
        entropy.source.0,
        source if source == DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL.0
            || source == DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM.0
            || source == DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE.0
    ) {
        return Err(BootInfoValidationError::UnknownEntropySource);
    }
    let range = optional_range(
        entropy.physical_start,
        entropy.byte_len,
        1,
        BootInfoValidationError::InvalidEntropy,
    )?;
    Ok(range)
}

fn validate_record_header(
    size: u32,
    version: u32,
    minimum_size: u32,
    expected_version: u32,
    stride: Option<u32>,
) -> Result<(), BootInfoValidationError> {
    if version != expected_version {
        return Err(BootInfoValidationError::UnsupportedVersion);
    }
    if size < minimum_size {
        return Err(BootInfoValidationError::StructureTooSmall);
    }
    if stride.is_some_and(|stride| size > stride) {
        return Err(BootInfoValidationError::StructureLargerThanStride);
    }
    Ok(())
}

fn optional_range(
    physical_start: u64,
    byte_len: u64,
    alignment: u64,
    error: BootInfoValidationError,
) -> Result<Option<BootPhysicalRange>, BootInfoValidationError> {
    if physical_start == 0 && byte_len == 0 {
        return Ok(None);
    }
    checked_range(physical_start, byte_len, alignment)
        .map(Some)
        .map_err(|_| error)
}

fn checked_range(
    physical_start: u64,
    byte_len: u64,
    alignment: u64,
) -> Result<BootPhysicalRange, BootInfoValidationError> {
    if byte_len == 0 {
        return Err(BootInfoValidationError::EmptyRange);
    }
    if !physical_start.is_multiple_of(alignment) {
        return Err(BootInfoValidationError::UnalignedAddress);
    }
    physical_start
        .checked_add(byte_len)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    Ok(BootPhysicalRange {
        physical_start,
        byte_len,
    })
}

fn ranges_overlap(
    left: BootPhysicalRange,
    right: BootPhysicalRange,
) -> Result<bool, BootInfoValidationError> {
    let left_end = left
        .physical_start
        .checked_add(left.byte_len)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let right_end = right
        .physical_start
        .checked_add(right.byte_len)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    Ok(left.physical_start < right_end && right.physical_start < left_end)
}

fn masks_overlap(masks: &[u32; 4]) -> bool {
    for left in 0..masks.len() {
        for right in (left + 1)..masks.len() {
            if masks[left] != 0 && masks[right] != 0 && masks[left] & masks[right] != 0 {
                return true;
            }
        }
    }
    false
}

fn validate_zeroes(words: &[u64]) -> Result<(), BootInfoValidationError> {
    if words.iter().any(|word| *word != 0) {
        return Err(BootInfoValidationError::NonZeroReserved);
    }
    Ok(())
}

fn read<R: BootInfoByteReader>(
    reader: &R,
    physical_start: u64,
    destination: &mut [u8],
) -> Result<(), BootInfoValidationError> {
    reader
        .read_exact(physical_start, destination)
        .map_err(|()| BootInfoValidationError::ReadFailure)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, BootInfoValidationError> {
    let end = offset
        .checked_add(4)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let bytes: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(BootInfoValidationError::ReadFailure)?
        .try_into()
        .map_err(|_| BootInfoValidationError::ReadFailure)?;
    Ok(u32::from_le_bytes(bytes))
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, BootInfoValidationError> {
    let end = offset
        .checked_add(2)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let bytes: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(BootInfoValidationError::ReadFailure)?
        .try_into()
        .map_err(|_| BootInfoValidationError::ReadFailure)?;
    Ok(u16::from_le_bytes(bytes))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, BootInfoValidationError> {
    let end = offset
        .checked_add(8)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let bytes: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(BootInfoValidationError::ReadFailure)?
        .try_into()
        .map_err(|_| BootInfoValidationError::ReadFailure)?;
    Ok(u64::from_le_bytes(bytes))
}

fn u64_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u64; N], BootInfoValidationError> {
    u64_array_at(bytes, offset, N)
}

fn u64_array_at<const N: usize>(
    bytes: &[u8],
    offset: usize,
    count: usize,
) -> Result<[u64; N], BootInfoValidationError> {
    if count != N {
        return Err(BootInfoValidationError::ReadFailure);
    }
    let mut values = [0_u64; N];
    for (index, value) in values.iter_mut().enumerate() {
        let entry_offset = offset
            .checked_add(
                index
                    .checked_mul(8)
                    .ok_or(BootInfoValidationError::ArithmeticOverflow)?,
            )
            .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
        *value = u64_at(bytes, entry_offset)?;
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
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
            let start = usize::try_from(physical_start.checked_sub(self.base).ok_or(())?)
                .map_err(|_| ())?;
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
}
