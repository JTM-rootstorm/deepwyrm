use deepwyrm_abi::{
    DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, DW_BOOT_DEVICE_RESOURCE_V1_SIZE,
    DW_BOOT_DEVICE_RESOURCE_V1_VERSION, DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    DW_BOOT_DEVICE_TABLE_MAX_RESOURCES, DW_BOOT_DEVICE_TABLE_RECORD_STRIDE,
    DW_BOOT_DEVICE_TABLE_V1_SIZE, DW_BOOT_DEVICE_TABLE_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DwDeviceResourceKind,
};

use super::{
    BootInfoByteReader, BootInfoValidationError, BootResourceDescriptor, BootResourceGrantError,
    BootResourceGrants, MAX_BOOT_RESOURCE_GRANTS,
};

const COM1_PIO_START: u32 = 0x3f8;
const COM1_PIO_END: u32 = 0x400;
const COM1_INTERRUPT_SOURCE: u32 = 4;

pub(super) fn parse_boot_resource_grants<R: BootInfoByteReader>(
    reader: &R,
    physical_start: u64,
    module_byte_len: u64,
) -> Result<BootResourceGrants, BootInfoValidationError> {
    parse_boot_resource_grants_with(
        reader,
        physical_start,
        module_byte_len,
        BootResourceGrants::materialize,
    )
}

pub(super) fn parse_boot_resource_grants_with<R, F>(
    reader: &R,
    physical_start: u64,
    module_byte_len: u64,
    materialize: F,
) -> Result<BootResourceGrants, BootInfoValidationError>
where
    R: BootInfoByteReader,
    F: FnOnce(&[BootResourceDescriptor]) -> Result<BootResourceGrants, BootResourceGrantError>,
{
    if module_byte_len < u64::from(DW_BOOT_DEVICE_TABLE_V1_SIZE) {
        return Err(BootInfoValidationError::InvalidBootDeviceTable);
    }
    let mut header = [0_u8; DW_BOOT_DEVICE_TABLE_V1_SIZE as usize];
    reader
        .read_exact(physical_start, &mut header)
        .map_err(|()| BootInfoValidationError::ReadFailure)?;

    let size = u32_at(&header, 0)?;
    let version = u32_at(&header, 4)?;
    let resource_count = u32_at(&header, 8)?;
    let flags = u32_at(&header, 12)?;
    let record_stride = u32_at(&header, 16)?;
    let reserved0 = u32_at(&header, 20)?;
    let total_byte_len = u64_at(&header, 24)?;

    if size != DW_BOOT_DEVICE_TABLE_V1_SIZE {
        return Err(BootInfoValidationError::InvalidBootDeviceTable);
    }
    if version != DW_BOOT_DEVICE_TABLE_V1_VERSION {
        return Err(BootInfoValidationError::UnsupportedVersion);
    }
    if resource_count == 0 || resource_count > DW_BOOT_DEVICE_TABLE_MAX_RESOURCES {
        return Err(BootInfoValidationError::InvalidBootDeviceTable);
    }
    if flags & !DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK != 0 {
        return Err(BootInfoValidationError::UnknownFlags);
    }
    if record_stride != DW_BOOT_DEVICE_TABLE_RECORD_STRIDE {
        return Err(BootInfoValidationError::InvalidBootDeviceTable);
    }
    if reserved0 != 0 {
        return Err(BootInfoValidationError::NonZeroReserved);
    }

    let records_byte_len = u64::from(resource_count)
        .checked_mul(u64::from(record_stride))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let expected_byte_len = u64::from(DW_BOOT_DEVICE_TABLE_V1_SIZE)
        .checked_add(records_byte_len)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    if total_byte_len != expected_byte_len || module_byte_len != expected_byte_len {
        return Err(BootInfoValidationError::InvalidBootDeviceTable);
    }
    physical_start
        .checked_add(expected_byte_len)
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;

    let count = usize::try_from(resource_count)
        .map_err(|_| BootInfoValidationError::InvalidBootDeviceTable)?;
    if count > MAX_BOOT_RESOURCE_GRANTS {
        return Err(BootInfoValidationError::InvalidBootDeviceTable);
    }

    let mut descriptors = [None; MAX_BOOT_RESOURCE_GRANTS];
    for (index, slot) in descriptors.iter_mut().take(count).enumerate() {
        let index_offset = u64::try_from(index)
            .map_err(|_| BootInfoValidationError::ArithmeticOverflow)?
            .checked_mul(u64::from(record_stride))
            .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
        let record_start = physical_start
            .checked_add(u64::from(DW_BOOT_DEVICE_TABLE_V1_SIZE))
            .and_then(|start| start.checked_add(index_offset))
            .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
        let mut record = [0_u8; DW_BOOT_DEVICE_RESOURCE_V1_SIZE as usize];
        reader
            .read_exact(record_start, &mut record)
            .map_err(|()| BootInfoValidationError::ReadFailure)?;
        *slot = Some(parse_resource(&record)?);
    }

    let active = &descriptors[..count];
    for descriptor in active {
        let descriptor = descriptor.expect("validated boot descriptor slot");
        validate_platform_reservations(descriptor)?;
    }
    for (left_index, left) in active.iter().enumerate() {
        let left = left.expect("validated boot descriptor slot");
        for right in active.iter().skip(left_index + 1) {
            let right = right.expect("validated boot descriptor slot");
            if left.resource_id == right.resource_id {
                return Err(BootInfoValidationError::DuplicateBootDeviceResourceId);
            }
            if left.interrupt_source == right.interrupt_source {
                return Err(BootInfoValidationError::DuplicateBootDeviceInterruptSource);
            }
            if pio_ranges_overlap(left, right)? {
                return Err(BootInfoValidationError::OverlappingBootDeviceResources);
            }
        }
    }

    let mut compact = [BootResourceDescriptor {
        resource_id: 0,
        device_correlation_id: 0,
        kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
        pio_base: 0,
        pio_length: 0,
        interrupt_source: 0,
    }; MAX_BOOT_RESOURCE_GRANTS];
    for (destination, source) in compact.iter_mut().zip(active.iter()) {
        *destination = source.expect("validated boot descriptor slot");
    }

    materialize(&compact[..count]).map_err(|error| match error {
        BootResourceGrantError::Capacity => BootInfoValidationError::InvalidBootDeviceTable,
        BootResourceGrantError::GenerationExhausted => {
            BootInfoValidationError::BootResourceGrantGenerationExhausted
        }
    })
}

fn parse_resource(
    record: &[u8; DW_BOOT_DEVICE_RESOURCE_V1_SIZE as usize],
) -> Result<BootResourceDescriptor, BootInfoValidationError> {
    if u32_at(record, 0)? != DW_BOOT_DEVICE_RESOURCE_V1_SIZE {
        return Err(BootInfoValidationError::InvalidBootDeviceResource);
    }
    if u32_at(record, 4)? != DW_BOOT_DEVICE_RESOURCE_V1_VERSION {
        return Err(BootInfoValidationError::UnsupportedVersion);
    }
    let kind = DwDeviceResourceKind(u32_at(record, 8)?);
    if kind != DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT {
        return Err(BootInfoValidationError::InvalidBootDeviceResource);
    }
    let flags = u32_at(record, 12)?;
    if flags & !DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK != 0 {
        return Err(BootInfoValidationError::UnknownFlags);
    }
    let resource_id = u64_at(record, 16)?;
    let device_correlation_id = u64_at(record, 24)?;
    let pio_base = u16_at(record, 32)?;
    let pio_length = u16_at(record, 34)?;
    let interrupt_source = u32_at(record, 36)?;
    if u64_at(record, 40)? != 0 {
        return Err(BootInfoValidationError::NonZeroReserved);
    }
    if resource_id == 0 || pio_length == 0 || interrupt_source == 0 {
        return Err(BootInfoValidationError::InvalidBootDeviceResource);
    }

    let pio_end = u32::from(pio_base)
        .checked_add(u32::from(pio_length))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    if pio_end > 0x1_0000 {
        return Err(BootInfoValidationError::InvalidBootDeviceResource);
    }
    Ok(BootResourceDescriptor {
        resource_id,
        device_correlation_id,
        kind,
        pio_base,
        pio_length,
        interrupt_source,
    })
}

fn validate_platform_reservations(
    descriptor: BootResourceDescriptor,
) -> Result<(), BootInfoValidationError> {
    let pio_start = u32::from(descriptor.pio_base);
    let pio_end = pio_start
        .checked_add(u32::from(descriptor.pio_length))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    if pio_start < COM1_PIO_END && COM1_PIO_START < pio_end {
        return Err(BootInfoValidationError::ProtectedBootDeviceResource);
    }
    if descriptor.interrupt_source == COM1_INTERRUPT_SOURCE {
        return Err(BootInfoValidationError::ProtectedBootDeviceResource);
    }
    Ok(())
}

fn pio_ranges_overlap(
    left: BootResourceDescriptor,
    right: BootResourceDescriptor,
) -> Result<bool, BootInfoValidationError> {
    let left_end = u32::from(left.pio_base)
        .checked_add(u32::from(left.pio_length))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    let right_end = u32::from(right.pio_base)
        .checked_add(u32::from(right.pio_length))
        .ok_or(BootInfoValidationError::ArithmeticOverflow)?;
    Ok(u32::from(left.pio_base) < right_end && u32::from(right.pio_base) < left_end)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, BootInfoValidationError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(BootInfoValidationError::ReadFailure)?;
    Ok(u16::from_le_bytes(
        raw.try_into()
            .map_err(|_| BootInfoValidationError::ReadFailure)?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, BootInfoValidationError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(BootInfoValidationError::ReadFailure)?;
    Ok(u32::from_le_bytes(
        raw.try_into()
            .map_err(|_| BootInfoValidationError::ReadFailure)?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, BootInfoValidationError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(BootInfoValidationError::ReadFailure)?;
    Ok(u64::from_le_bytes(
        raw.try_into()
            .map_err(|_| BootInfoValidationError::ReadFailure)?,
    ))
}
