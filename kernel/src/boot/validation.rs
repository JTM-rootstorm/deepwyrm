use super::*;

pub(super) fn checked_snapshot_index(
    index: u64,
    entry_count: u64,
) -> Result<usize, BootInfoValidationError> {
    if index >= entry_count {
        return Err(BootInfoValidationError::TableIndexOutOfBounds);
    }
    usize::try_from(index).map_err(|_| BootInfoValidationError::TableIndexOutOfBounds)
}

pub(super) fn validate_table(
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

pub(super) fn read_table_entry<R: BootInfoByteReader>(
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

pub(super) fn parse_boot_info(
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

pub(super) fn parse_memory_range(
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

pub(super) fn parse_module(
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

pub(super) fn parse_paging_handoff_snapshot<R: BootInfoByteReader>(
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
pub(super) fn validate_paging_handoff_roles_and_reservation(
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

pub(super) fn validate_paging_frame_reserved_coverage(
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

pub(super) fn module_range(module: DwBootModuleV1) -> BootPhysicalRange {
    BootPhysicalRange {
        physical_start: module.physical_start,
        byte_len: module.byte_len,
    }
}

pub(super) fn table_physical_range(
    table: BootInfoTable,
) -> Result<BootPhysicalRange, BootInfoValidationError> {
    let byte_len = table
        .entry_count
        .checked_mul(u64::from(table.entry_size))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    checked_range(table.physical_start, byte_len, 8)
}

pub(super) fn parse_framebuffer(
    bytes: &[u8],
) -> Result<DwBootFramebufferV1, BootInfoValidationError> {
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

pub(super) fn validate_framebuffer(
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

pub(super) fn parse_entropy(bytes: &[u8]) -> Result<DwBootEntropyV1, BootInfoValidationError> {
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

pub(super) fn validate_entropy(
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

pub(super) fn validate_record_header(
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

pub(super) fn optional_range(
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

pub(super) fn checked_range(
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

pub(super) fn ranges_overlap(
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

pub(super) fn masks_overlap(masks: &[u32; 4]) -> bool {
    for left in 0..masks.len() {
        for right in (left + 1)..masks.len() {
            if masks[left] != 0 && masks[right] != 0 && masks[left] & masks[right] != 0 {
                return true;
            }
        }
    }
    false
}

pub(super) fn validate_zeroes(words: &[u64]) -> Result<(), BootInfoValidationError> {
    if words.iter().any(|word| *word != 0) {
        return Err(BootInfoValidationError::NonZeroReserved);
    }
    Ok(())
}

pub(super) fn read<R: BootInfoByteReader>(
    reader: &R,
    physical_start: u64,
    destination: &mut [u8],
) -> Result<(), BootInfoValidationError> {
    reader
        .read_exact(physical_start, destination)
        .map_err(|()| BootInfoValidationError::ReadFailure)
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, BootInfoValidationError> {
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

pub(super) fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, BootInfoValidationError> {
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

pub(super) fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, BootInfoValidationError> {
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

pub(super) fn u64_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u64; N], BootInfoValidationError> {
    u64_array_at(bytes, offset, N)
}

pub(super) fn u64_array_at<const N: usize>(
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
