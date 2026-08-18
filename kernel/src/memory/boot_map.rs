//! Sanitization of the copied `DwBootInfoV1` memory map and bootstrap
//! reservation collection.
//!
//! The loader's map is hostile until independently checked here. This module
//! deliberately does not map memory: it produces physical candidates and the
//! exact physical ranges which an architecture-owned transition must keep out
//! of the frame allocator.

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT;
use deepwyrm_abi::{
    DW_BOOT_BASE_PAGE_SIZE, DW_BOOT_INFO_V1_SIZE, DW_BOOT_MEMORY_KIND_ACPI_NVS,
    DW_BOOT_MEMORY_KIND_ACPI_RECLAIM, DW_BOOT_MEMORY_KIND_MMIO, DW_BOOT_MEMORY_KIND_RESERVED,
    DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES, DW_BOOT_MEMORY_KIND_UNUSABLE, DW_BOOT_MEMORY_KIND_USABLE,
    DwBootMemoryRangeV1,
};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use crate::boot::MAX_BOOT_MODULE_ENTRIES;
use crate::boot::{
    BootInfoValidationError, BootPhysicalRange, MAX_BOOT_MEMORY_MAP_ENTRIES, ValidatedBootInfo,
};

use super::physical::{
    PageRange, PhysicalAddressLimit, PhysicalFrameAllocator, PhysicalMemoryError, PhysicalRange,
};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use core::mem::MaybeUninit;

/// Maximum usable extents retained by allocation-free DW0-C map sanitization.
pub const MAX_SANITIZED_USABLE_RANGES: usize = MAX_BOOT_MEMORY_MAP_ENTRIES;

/// Maximum complete reservation set emitted by a structurally valid V1
/// handoff: three fixed tables, every module and transition table, plus four
/// optional singleton ranges.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) const MAX_BOOTSTRAP_RESERVATIONS: usize =
    3 + MAX_BOOT_MODULE_ENTRIES + DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as usize + 4;

const EMPTY_USABLE_RANGE: SanitizedUsableRange = SanitizedUsableRange {
    pages: PageRange::empty(),
    firmware_attributes: 0,
};

/// A usable range together with the opaque UEFI attributes recorded by the
/// loader. Attributes are retained for diagnostics only: their bit meaning is
/// not part of the Deepwyrm ABI and never grants allocation eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizedUsableRange {
    pages: PageRange,
    firmware_attributes: u64,
}

impl SanitizedUsableRange {
    /// Exact page-aligned physical range.
    pub fn physical_range(self) -> PhysicalRange {
        // `PageRange` is constructed only from checked non-empty ranges.
        PhysicalRange::new(self.pages.start, self.pages.end - self.pages.start)
            .expect("sanitized page range is non-empty and checked")
    }

    /// Opaque loader-provided UEFI memory attributes.
    pub const fn firmware_attributes(self) -> u64 {
        self.firmware_attributes
    }
}

/// Canonical usable candidates after strict validation of the complete map.
pub struct SanitizedBootMap {
    usable: [SanitizedUsableRange; MAX_SANITIZED_USABLE_RANGES],
    usable_len: usize,
    normalized: [DwBootMemoryRangeV1; MAX_BOOT_MEMORY_MAP_ENTRIES],
    normalized_len: usize,
    physical_limit: PhysicalAddressLimit,
}

impl SanitizedBootMap {
    /// Number of usable candidate extents before bootstrap reservations.
    pub const fn usable_range_count(&self) -> usize {
        self.usable_len
    }

    /// Returns a usable candidate and its diagnostic attributes.
    pub fn usable_range(&self, index: usize) -> Option<SanitizedUsableRange> {
        self.usable.get(..self.usable_len)?.get(index).copied()
    }
}

/// Exact normalized memory-map and bootstrap-reservation provenance consumed
/// by the sole production frame-role manager.
///
/// Construction stays inside the private ownership parent. Architecture code
/// may validate this witness but cannot pair an arbitrary map and reservation
/// slice after allocator initialization.
#[derive(Clone, Copy)]
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
pub(crate) struct BootstrapMemoryWitness<'a> {
    map: &'a SanitizedBootMap,
    reservations: &'a [BootstrapReservation],
}

/// Failure while proving that the executing kernel image is backed only by
/// normalized `RESERVED` memory disjoint from every bootstrap allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
pub(crate) enum KernelImageBoundaryError {
    InvalidRange {
        range_index: usize,
    },
    Uncovered {
        range_index: usize,
    },
    NotReserved {
        range_index: usize,
    },
    KernelRangeOverlap {
        left: usize,
        right: usize,
    },
    BootstrapReservationOverlap {
        range_index: usize,
        reservation: BootstrapReservationKind,
    },
}

/// Range provenance retained for focused diagnostics and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapReservationKind {
    BootInfo,
    MemoryMapTable,
    ModuleTable,
    ModuleData { index: u64 },
    CommandLine,
    Entropy,
    FramebufferPixels,
    AcpiRsdpMaximumExtent,
    PagingTableFrame { index: u32 },
}

/// One exact physical allocation that cannot be returned by the bootstrap
/// frame allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapReservation {
    kind: BootstrapReservationKind,
    range: PhysicalRange,
}

impl BootstrapReservation {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(crate) fn placeholder() -> Self {
        Self {
            kind: BootstrapReservationKind::BootInfo,
            range: PhysicalRange::new(0, 1).expect("one-byte placeholder range is valid"),
        }
    }

    /// Reservation provenance.
    pub const fn kind(self) -> BootstrapReservationKind {
        self.kind
    }

    /// Exact byte range before page-covering.
    pub const fn range(self) -> PhysicalRange {
        self.range
    }
}

/// Failure while turning a validated structural handoff into allocation facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootMapError {
    Snapshot(BootInfoValidationError),
    Physical(PhysicalMemoryError),
    UnsortedInput,
    OverlappingInput,
    OutputCapacityExceeded,
    UnknownMemoryKind,
    HandoffRangeUncovered { kind: BootstrapReservationKind },
    HandoffRangeUsable { kind: BootstrapReservationKind },
    HandoffRangeNotReserved { kind: BootstrapReservationKind },
}

impl From<PhysicalMemoryError> for BootMapError {
    fn from(error: PhysicalMemoryError) -> Self {
        Self::Physical(error)
    }
}

/// Strictly validates the complete copied map before extracting usable ranges.
///
/// The Wyrmroot loader is expected to normalize sorted, non-overlapping page
/// records, but the kernel repeats those checks. Any malformed ordering or
/// overlap fails closed instead of applying a locally invented precedence.
pub fn sanitize_boot_map(
    boot_info: &ValidatedBootInfo,
    boot_info_physical_start: u64,
    physical_limit: PhysicalAddressLimit,
) -> Result<SanitizedBootMap, BootMapError> {
    let mut records = [DwBootMemoryRangeV1::default(); MAX_BOOT_MEMORY_MAP_ENTRIES];
    let record_count = boot_info.memory_map().entry_count() as usize;
    for (index, slot) in records[..record_count].iter_mut().enumerate() {
        *slot = boot_info
            .memory_range(index as u64)
            .map_err(BootMapError::Snapshot)?;
    }
    let sanitized = sanitize_records(&records[..record_count], physical_limit)?;
    validate_enumerated_handoff_coverage(
        boot_info,
        &records[..record_count],
        boot_info_physical_start,
        physical_limit,
    )?;
    Ok(sanitized)
}

/// Sanitizes the production map directly into its final bootstrap storage.
///
/// # Safety
///
/// `slot` must be unique, uninitialized storage owned by the one-shot BSP
/// bootstrap. A failure is terminal for the slot and it must not be reused.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the sole BSP sanitizer initializes its bounded map witness in static storage"
)]
pub(crate) unsafe fn sanitize_boot_map_in<'a>(
    slot: &'a mut MaybeUninit<SanitizedBootMap>,
    boot_info: &ValidatedBootInfo,
    boot_info_physical_start: u64,
    physical_limit: PhysicalAddressLimit,
) -> Result<&'a mut SanitizedBootMap, BootMapError> {
    let destination = slot.as_mut_ptr();
    unsafe {
        let usable = core::ptr::addr_of_mut!((*destination).usable).cast::<SanitizedUsableRange>();
        for index in 0..MAX_SANITIZED_USABLE_RANGES {
            usable.add(index).write(EMPTY_USABLE_RANGE);
        }
        core::ptr::addr_of_mut!((*destination).usable_len).write(0);
        let normalized =
            core::ptr::addr_of_mut!((*destination).normalized).cast::<DwBootMemoryRangeV1>();
        for index in 0..MAX_BOOT_MEMORY_MAP_ENTRIES {
            normalized.add(index).write(DwBootMemoryRangeV1::default());
        }
        core::ptr::addr_of_mut!((*destination).normalized_len).write(0);
        core::ptr::addr_of_mut!((*destination).physical_limit).write(physical_limit);
    }
    let sanitized = unsafe { &mut *destination };
    let record_count = boot_info.memory_map().entry_count() as usize;
    for index in 0..record_count {
        let record = boot_info
            .memory_range(index as u64)
            .map_err(BootMapError::Snapshot)?;
        sanitized.push_normalized(record)?;
    }
    validate_enumerated_handoff_coverage(
        boot_info,
        sanitized.normalized_records(),
        boot_info_physical_start,
        physical_limit,
    )?;
    Ok(sanitized)
}

fn sanitize_records(
    records: &[DwBootMemoryRangeV1],
    physical_limit: PhysicalAddressLimit,
) -> Result<SanitizedBootMap, BootMapError> {
    let mut sanitized = SanitizedBootMap::empty(physical_limit);
    for record in records {
        sanitized.push_normalized(*record)?;
    }
    Ok(sanitized)
}

/// Collects every ABI-enumerated `DwBootInfoV1` physical range that must stay
/// unavailable to DW0-C frame allocation.
///
/// `boot_info_physical_start` is deliberately explicit because DW0-B snapshots
/// the header contents but does not retain an allocator-policy address field.
///
/// DW0-C intentionally performs no handoff-range reclamation. In particular,
/// unenumerated kernel `PT_LOAD`, loader transition page-table, and transition
/// stack backing rely on the locked `LOADER_DATA -> RESERVED` normalization and
/// remain withheld for all of DW0-C. Reclaim requires a paired manifest/ABI
/// revision with representable physical-allocation provenance.
#[allow(
    dead_code,
    reason = "DW0-C architecture integration consumes this after its page-table handoff boundary is wired"
)]
pub(crate) fn collect_bootstrap_reservations(
    boot_info: &ValidatedBootInfo,
    boot_info_physical_start: u64,
    output: &mut [BootstrapReservation],
) -> Result<usize, BootMapError> {
    let mut used = 0;
    push_reservation(
        output,
        &mut used,
        BootstrapReservationKind::BootInfo,
        physical_range(boot_info_physical_start, u64::from(DW_BOOT_INFO_V1_SIZE))?,
    )?;

    let memory_map = boot_info.memory_map();
    push_reservation(
        output,
        &mut used,
        BootstrapReservationKind::MemoryMapTable,
        table_range(
            memory_map.physical_start(),
            memory_map.entry_count(),
            memory_map.entry_size(),
        )?,
    )?;
    let modules = boot_info.modules();
    push_reservation(
        output,
        &mut used,
        BootstrapReservationKind::ModuleTable,
        table_range(
            modules.physical_start(),
            modules.entry_count(),
            modules.entry_size(),
        )?,
    )?;
    for index in 0..modules.entry_count() {
        let module = boot_info
            .module_reservation_range(index)
            .map_err(BootMapError::Snapshot)?;
        push_reservation(
            output,
            &mut used,
            BootstrapReservationKind::ModuleData { index },
            physical_range(module.physical_start(), module.byte_len())?,
        )?;
    }
    let paging = boot_info.paging_handoff();
    for index in 0..paging.table_frame_count() {
        let physical_start = paging.table_frame(index).map_err(BootMapError::Snapshot)?;
        push_reservation(
            output,
            &mut used,
            BootstrapReservationKind::PagingTableFrame {
                index: index as u32,
            },
            physical_range(physical_start, u64::from(DW_BOOT_BASE_PAGE_SIZE))?,
        )?;
    }
    if let Some(range) = boot_info.command_line() {
        push_boot_range(
            output,
            &mut used,
            BootstrapReservationKind::CommandLine,
            range,
        )?;
    }
    if let Some(range) = boot_info.entropy() {
        push_boot_range(output, &mut used, BootstrapReservationKind::Entropy, range)?;
    }
    if let Some(framebuffer) = boot_info.framebuffer() {
        push_reservation(
            output,
            &mut used,
            BootstrapReservationKind::FramebufferPixels,
            physical_range(framebuffer.physical_start, framebuffer.byte_len)?,
        )?;
    }

    if boot_info.header().acpi_rsdp_physical_address != 0 {
        push_reservation(
            output,
            &mut used,
            BootstrapReservationKind::AcpiRsdpMaximumExtent,
            physical_range(
                boot_info.header().acpi_rsdp_physical_address,
                u64::from(DW_BOOT_BASE_PAGE_SIZE),
            )?,
        )?;
    }
    Ok(used)
}

/// Initializes an allocation-free frame allocator from sanitized candidates
/// after subtracting every collected reservation.
pub(super) fn initialize_frame_allocator<const RANGE_CAPACITY: usize>(
    map: &SanitizedBootMap,
    reservations: &[BootstrapReservation],
) -> Result<PhysicalFrameAllocator<RANGE_CAPACITY>, BootMapError> {
    let mut candidates = [PageRange::empty(); MAX_SANITIZED_USABLE_RANGES];
    for (slot, usable) in candidates[..map.usable_len]
        .iter_mut()
        .zip(map.usable[..map.usable_len].iter())
    {
        *slot = usable.pages;
    }
    PhysicalFrameAllocator::from_candidates(
        &candidates[..map.usable_len],
        map.physical_limit,
        reservations.iter().map(|reservation| reservation.range),
    )
    .map_err(BootMapError::Physical)
}

/// Initializes the production allocator directly inside its final manager
/// field so fixed-capacity range arrays never become stack return values.
///
/// # Safety
///
/// `slot` must be unique, uninitialized bootstrap storage. A failure is
/// terminal for the slot and the caller must not retry initialization.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the sole BSP manager initializes its allocator field in place"
)]
pub(super) unsafe fn initialize_frame_allocator_in<'a, const RANGE_CAPACITY: usize>(
    slot: &'a mut MaybeUninit<PhysicalFrameAllocator<RANGE_CAPACITY>>,
    map: &SanitizedBootMap,
    reservations: &[BootstrapReservation],
) -> Result<&'a mut PhysicalFrameAllocator<RANGE_CAPACITY>, BootMapError> {
    let mut candidates = [PageRange::empty(); MAX_SANITIZED_USABLE_RANGES];
    for (slot, usable) in candidates[..map.usable_len]
        .iter_mut()
        .zip(map.usable[..map.usable_len].iter())
    {
        *slot = usable.pages;
    }
    unsafe {
        PhysicalFrameAllocator::from_candidates_in(
            slot,
            &candidates[..map.usable_len],
            map.physical_limit,
            reservations.iter().map(|reservation| reservation.range),
        )
    }
    .map_err(BootMapError::Physical)
}

impl SanitizedBootMap {
    fn empty(physical_limit: PhysicalAddressLimit) -> Self {
        Self {
            usable: [EMPTY_USABLE_RANGE; MAX_SANITIZED_USABLE_RANGES],
            usable_len: 0,
            normalized: [DwBootMemoryRangeV1::default(); MAX_BOOT_MEMORY_MAP_ENTRIES],
            normalized_len: 0,
            physical_limit,
        }
    }

    fn normalized_records(&self) -> &[DwBootMemoryRangeV1] {
        &self.normalized[..self.normalized_len]
    }

    fn push_normalized(&mut self, record: DwBootMemoryRangeV1) -> Result<(), BootMapError> {
        if !known_memory_kind(record.kind.0) {
            return Err(BootMapError::UnknownMemoryKind);
        }
        let pages = record_pages(record, self.physical_limit)?;
        if let Some(previous) = self.normalized_records().last().copied() {
            let previous = record_pages(previous, self.physical_limit)?;
            if pages.start < previous.start {
                return Err(BootMapError::UnsortedInput);
            }
            if pages.start < previous.end {
                return Err(BootMapError::OverlappingInput);
            }
        }
        let slot = self
            .normalized
            .get_mut(self.normalized_len)
            .ok_or(BootMapError::OutputCapacityExceeded)?;
        *slot = record;
        self.normalized_len += 1;
        if record.kind == DW_BOOT_MEMORY_KIND_USABLE {
            self.push_usable(pages, record.firmware_attributes)?;
        }
        Ok(())
    }

    fn push_usable(
        &mut self,
        pages: PageRange,
        firmware_attributes: u64,
    ) -> Result<(), BootMapError> {
        if let Some(previous) = self.usable[..self.usable_len].last_mut()
            && previous.pages.end == pages.start
            && previous.firmware_attributes == firmware_attributes
        {
            previous.pages.end = pages.end;
            return Ok(());
        }
        let slot = self
            .usable
            .get_mut(self.usable_len)
            .ok_or(BootMapError::OutputCapacityExceeded)?;
        *slot = SanitizedUsableRange {
            pages,
            firmware_attributes,
        };
        self.usable_len += 1;
        Ok(())
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
impl<'a> BootstrapMemoryWitness<'a> {
    pub(super) const fn new(
        map: &'a SanitizedBootMap,
        reservations: &'a [BootstrapReservation],
    ) -> Self {
        Self { map, reservations }
    }

    /// Proves all kernel image extents are exact page ranges covered solely by
    /// normalized `RESERVED` records and disjoint from every handoff range.
    pub(crate) fn validate_kernel_image_ranges(
        self,
        ranges: &[PhysicalRange; 3],
    ) -> Result<(), KernelImageBoundaryError> {
        for (left_index, left) in ranges.iter().copied().enumerate() {
            if !left
                .physical_start()
                .is_multiple_of(u64::from(DW_BOOT_BASE_PAGE_SIZE))
                || !left
                    .byte_len()
                    .is_multiple_of(u64::from(DW_BOOT_BASE_PAGE_SIZE))
            {
                return Err(KernelImageBoundaryError::InvalidRange {
                    range_index: left_index,
                });
            }
            for (right_index, right) in ranges.iter().copied().enumerate().skip(left_index + 1) {
                if ranges_overlap(left, right) {
                    return Err(KernelImageBoundaryError::KernelRangeOverlap {
                        left: left_index,
                        right: right_index,
                    });
                }
            }
            require_kernel_reserved_coverage(
                self.map.normalized_records(),
                left,
                left_index,
                self.map.physical_limit,
            )?;
            for reservation in self.reservations.iter().copied() {
                if ranges_overlap(left, reservation.range) {
                    return Err(KernelImageBoundaryError::BootstrapReservationOverlap {
                        range_index: left_index,
                        reservation: reservation.kind,
                    });
                }
            }
        }
        Ok(())
    }
}

fn known_memory_kind(kind: u32) -> bool {
    kind == DW_BOOT_MEMORY_KIND_USABLE.0
        || kind == DW_BOOT_MEMORY_KIND_RESERVED.0
        || kind == DW_BOOT_MEMORY_KIND_ACPI_RECLAIM.0
        || kind == DW_BOOT_MEMORY_KIND_ACPI_NVS.0
        || kind == DW_BOOT_MEMORY_KIND_MMIO.0
        || kind == DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES.0
        || kind == DW_BOOT_MEMORY_KIND_UNUSABLE.0
}

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
fn ranges_overlap(left: PhysicalRange, right: PhysicalRange) -> bool {
    let Ok(left_end) = left.end() else {
        return true;
    };
    let Ok(right_end) = right.end() else {
        return true;
    };
    left.physical_start() < right_end && right.physical_start() < left_end
}

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
fn require_kernel_reserved_coverage(
    records: &[DwBootMemoryRangeV1],
    range: PhysicalRange,
    range_index: usize,
    physical_limit: PhysicalAddressLimit,
) -> Result<(), KernelImageBoundaryError> {
    let end = range
        .end()
        .map_err(|_| KernelImageBoundaryError::InvalidRange { range_index })?;
    let mut covered_until = range.physical_start();
    for record in records {
        let pages = record_pages(*record, physical_limit)
            .map_err(|_| KernelImageBoundaryError::InvalidRange { range_index })?;
        if pages.end <= covered_until {
            continue;
        }
        if pages.start > covered_until {
            return Err(KernelImageBoundaryError::Uncovered { range_index });
        }
        if record.kind != DW_BOOT_MEMORY_KIND_RESERVED {
            return Err(KernelImageBoundaryError::NotReserved { range_index });
        }
        covered_until = core::cmp::min(pages.end, end);
        if covered_until == end {
            return Ok(());
        }
    }
    Err(KernelImageBoundaryError::Uncovered { range_index })
}

fn record_pages(
    record: DwBootMemoryRangeV1,
    physical_limit: PhysicalAddressLimit,
) -> Result<PageRange, BootMapError> {
    PageRange::from_page_count(record.physical_start, record.page_count, physical_limit)
        .map_err(BootMapError::Physical)
}

fn validate_enumerated_handoff_coverage(
    boot_info: &ValidatedBootInfo,
    records: &[DwBootMemoryRangeV1],
    boot_info_physical_start: u64,
    physical_limit: PhysicalAddressLimit,
) -> Result<(), BootMapError> {
    require_nonusable_coverage(
        records,
        physical_range(boot_info_physical_start, u64::from(DW_BOOT_INFO_V1_SIZE))?,
        BootstrapReservationKind::BootInfo,
        physical_limit,
    )?;
    let memory_map = boot_info.memory_map();
    require_nonusable_coverage(
        records,
        table_range(
            memory_map.physical_start(),
            memory_map.entry_count(),
            memory_map.entry_size(),
        )?,
        BootstrapReservationKind::MemoryMapTable,
        physical_limit,
    )?;
    let modules = boot_info.modules();
    require_nonusable_coverage(
        records,
        table_range(
            modules.physical_start(),
            modules.entry_count(),
            modules.entry_size(),
        )?,
        BootstrapReservationKind::ModuleTable,
        physical_limit,
    )?;
    for index in 0..modules.entry_count() {
        let module = boot_info
            .module_reservation_range(index)
            .map_err(BootMapError::Snapshot)?;
        require_nonusable_coverage(
            records,
            physical_range(module.physical_start(), module.byte_len())?,
            BootstrapReservationKind::ModuleData { index },
            physical_limit,
        )?;
    }
    let paging = boot_info.paging_handoff();
    for index in 0..paging.table_frame_count() {
        let physical_start = paging.table_frame(index).map_err(BootMapError::Snapshot)?;
        require_reserved_coverage(
            records,
            physical_range(physical_start, u64::from(DW_BOOT_BASE_PAGE_SIZE))?,
            BootstrapReservationKind::PagingTableFrame {
                index: index as u32,
            },
            physical_limit,
        )?;
    }
    if let Some(range) = boot_info.command_line() {
        require_nonusable_coverage(
            records,
            physical_range(range.physical_start(), range.byte_len())?,
            BootstrapReservationKind::CommandLine,
            physical_limit,
        )?;
    }
    if let Some(range) = boot_info.entropy() {
        require_nonusable_coverage(
            records,
            physical_range(range.physical_start(), range.byte_len())?,
            BootstrapReservationKind::Entropy,
            physical_limit,
        )?;
    }
    if let Some(framebuffer) = boot_info.framebuffer() {
        require_nonusable_coverage(
            records,
            physical_range(framebuffer.physical_start, framebuffer.byte_len)?,
            BootstrapReservationKind::FramebufferPixels,
            physical_limit,
        )?;
    }
    if boot_info.header().acpi_rsdp_physical_address != 0 {
        // The ABI carries no RSDP byte length. Conservatively cover the locked
        // maximum declared extent (one base page), which can intersect two
        // physical pages when the record starts near a page boundary.
        require_nonusable_coverage(
            records,
            physical_range(
                boot_info.header().acpi_rsdp_physical_address,
                u64::from(DW_BOOT_BASE_PAGE_SIZE),
            )?,
            BootstrapReservationKind::AcpiRsdpMaximumExtent,
            physical_limit,
        )?;
    }
    Ok(())
}

fn require_nonusable_coverage(
    records: &[DwBootMemoryRangeV1],
    range: PhysicalRange,
    kind: BootstrapReservationKind,
    physical_limit: PhysicalAddressLimit,
) -> Result<(), BootMapError> {
    let end = range
        .end()
        .map_err(|_| BootMapError::Physical(PhysicalMemoryError::AddressOverflow))?;
    let mut covered_until = range.physical_start();
    for record in records {
        let pages = record_pages(*record, physical_limit)?;
        if pages.end <= covered_until {
            continue;
        }
        if pages.start > covered_until {
            return Err(BootMapError::HandoffRangeUncovered { kind });
        }
        if record.kind == DW_BOOT_MEMORY_KIND_USABLE {
            return Err(BootMapError::HandoffRangeUsable { kind });
        }
        covered_until = core::cmp::min(pages.end, end);
        if covered_until == end {
            return Ok(());
        }
    }
    Err(BootMapError::HandoffRangeUncovered { kind })
}

fn require_reserved_coverage(
    records: &[DwBootMemoryRangeV1],
    range: PhysicalRange,
    kind: BootstrapReservationKind,
    physical_limit: PhysicalAddressLimit,
) -> Result<(), BootMapError> {
    let end = range
        .end()
        .map_err(|_| BootMapError::Physical(PhysicalMemoryError::AddressOverflow))?;
    let mut covered_until = range.physical_start();
    for record in records {
        let pages = record_pages(*record, physical_limit)?;
        if pages.end <= covered_until {
            continue;
        }
        if pages.start > covered_until {
            return Err(BootMapError::HandoffRangeUncovered { kind });
        }
        if record.kind != DW_BOOT_MEMORY_KIND_RESERVED {
            return Err(BootMapError::HandoffRangeNotReserved { kind });
        }
        covered_until = core::cmp::min(pages.end, end);
        if covered_until == end {
            return Ok(());
        }
    }
    Err(BootMapError::HandoffRangeUncovered { kind })
}

fn physical_range(physical_start: u64, byte_len: u64) -> Result<PhysicalRange, BootMapError> {
    PhysicalRange::new(physical_start, byte_len).map_err(|error| match error {
        super::physical::PhysicalRangeError::EmptyRange => {
            BootMapError::Physical(PhysicalMemoryError::InvalidPageRange)
        }
        super::physical::PhysicalRangeError::AddressOverflow => {
            BootMapError::Physical(PhysicalMemoryError::AddressOverflow)
        }
        super::physical::PhysicalRangeError::InvalidAddressLimit => {
            BootMapError::Physical(PhysicalMemoryError::OutsidePhysicalLimit)
        }
    })
}

fn table_range(
    physical_start: u64,
    entry_count: u64,
    entry_size: u32,
) -> Result<PhysicalRange, BootMapError> {
    let byte_len = entry_count
        .checked_mul(u64::from(entry_size))
        .ok_or(BootMapError::Physical(PhysicalMemoryError::AddressOverflow))?;
    physical_range(physical_start, byte_len)
}

#[allow(
    dead_code,
    reason = "used by the deferred architecture-integrated reservation collector"
)]
fn push_boot_range(
    output: &mut [BootstrapReservation],
    used: &mut usize,
    kind: BootstrapReservationKind,
    range: BootPhysicalRange,
) -> Result<(), BootMapError> {
    push_reservation(
        output,
        used,
        kind,
        physical_range(range.physical_start(), range.byte_len())?,
    )
}

#[allow(
    dead_code,
    reason = "used by the deferred architecture-integrated reservation collector"
)]
fn push_reservation(
    output: &mut [BootstrapReservation],
    used: &mut usize,
    kind: BootstrapReservationKind,
    range: PhysicalRange,
) -> Result<(), BootMapError> {
    let slot = output
        .get_mut(*used)
        .ok_or(BootMapError::OutputCapacityExceeded)?;
    *slot = BootstrapReservation { kind, range };
    *used += 1;
    Ok(())
}

#[cfg(test)]
#[path = "boot_map/tests.rs"]
mod tests;
