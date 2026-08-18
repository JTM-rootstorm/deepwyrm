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

    /// Returns the exact bounded transition-frame declaration retained by
    /// this validated snapshot without copying its fixed-capacity backing.
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(crate) fn table_frames(&self) -> &[u64] {
        &self.table_frames[..self.table_frame_count]
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

mod validation;
use validation::*;

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

#[cfg(test)]
mod tests;
