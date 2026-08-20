#![cfg_attr(
    not(all(target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "F3 ACPI discovery is target boot code with host model tests"
    )
)]

//! Bounded ACPI discovery required by the DW0-F3 reference clock.
//!
//! F3 retains only the validated PM-timer I/O descriptor. After Deepwyrm
//! replaces CR3, firmware tables are traversed through the authenticated
//! scratch mapper and only from boot-map ranges classified RESERVED,
//! ACPI_RECLAIM, or ACPI_NVS. No persistent ACPI mapping is retained.

use crate::time::{PmTimerDescriptor, PmTimerWidth};

const RSDP_V1_BYTES: usize = 20;
const RSDP_V2_BYTES: usize = 36;
const SDT_HEADER_BYTES: u32 = 36;
const MAX_ACPI_TABLE_BYTES: u32 = 64 * 1024;
const MAX_ROOT_ENTRIES: usize = 128;
const FADT_PM_TMR_BLK: u64 = 76;
const FADT_PM_TMR_LEN: u64 = 91;
const FADT_FLAGS: u64 = 112;
const FADT_X_PM_TMR_BLK: u64 = 208;
const FADT_MINIMUM_FLAGS_BYTES: u32 = 116;
const FADT_X_PM_TIMER_END: u32 = 220;
const FADT_TMR_VAL_EXT: u32 = 1 << 8;
const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;
const GAS_SYSTEM_IO: u8 = 1;
const GAS_DWORD_ACCESS: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcpiTimeError {
    ReadFailure,
    InvalidRsdp,
    InvalidRootTable,
    RootEntryLimit,
    MissingFadt,
    DuplicateFadt,
    InvalidFadt,
    HardwareReduced,
    MissingPmTimer,
}

#[derive(Clone, Copy)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
}

pub(crate) trait AcpiByteReader {
    fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()>;
}

pub(crate) fn discover_pm_timer<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
) -> Result<PmTimerDescriptor, AcpiTimeError> {
    if rsdp_physical == 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let root = parse_rsdp(reader, rsdp_physical)?;
    match root {
        RootTable::Xsdt(address) => find_fadt(reader, address, 8, *b"XSDT"),
        RootTable::Rsdt(address) => find_fadt(reader, address, 4, *b"RSDT"),
    }
}

#[derive(Clone, Copy)]
enum RootTable {
    Rsdt(u64),
    Xsdt(u64),
}

fn parse_rsdp<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
) -> Result<RootTable, AcpiTimeError> {
    let mut v1 = [0_u8; RSDP_V1_BYTES];
    read(reader, physical, &mut v1)?;
    if &v1[..8] != b"RSD PTR " || checksum(&v1) != 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let revision = v1[15];
    let rsdt = u64::from(u32::from_le_bytes(v1[16..20].try_into().unwrap()));
    if revision < 2 {
        return (rsdt != 0)
            .then_some(RootTable::Rsdt(rsdt))
            .ok_or(AcpiTimeError::InvalidRsdp);
    }

    let mut v2 = [0_u8; RSDP_V2_BYTES];
    read(reader, physical, &mut v2)?;
    let length = u32::from_le_bytes(v2[20..24].try_into().unwrap());
    if length < RSDP_V2_BYTES as u32 || length > 4096 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    if checksum_physical(reader, physical, length)? != 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let xsdt = u64::from_le_bytes(v2[24..32].try_into().unwrap());
    if xsdt != 0 {
        return Ok(RootTable::Xsdt(xsdt));
    }
    (rsdt != 0)
        .then_some(RootTable::Rsdt(rsdt))
        .ok_or(AcpiTimeError::InvalidRsdp)
}

fn find_fadt<R: AcpiByteReader>(
    reader: &mut R,
    root_physical: u64,
    entry_bytes: u32,
    expected_signature: [u8; 4],
) -> Result<PmTimerDescriptor, AcpiTimeError> {
    let root = read_sdt_header(reader, root_physical)?;
    if root.signature != expected_signature
        || checksum_physical(reader, root_physical, root.length)? != 0
    {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    let payload = root
        .length
        .checked_sub(SDT_HEADER_BYTES)
        .ok_or(AcpiTimeError::InvalidRootTable)?;
    if payload % entry_bytes != 0 {
        return Err(AcpiTimeError::InvalidRootTable);
    }

    let count =
        usize::try_from(payload / entry_bytes).map_err(|_| AcpiTimeError::RootEntryLimit)?;
    if count == 0 || count > MAX_ROOT_ENTRIES {
        return Err(AcpiTimeError::RootEntryLimit);
    }
    let mut fadt = None;
    for index in 0..count {
        let offset = u64::from(SDT_HEADER_BYTES)
            .checked_add((index as u64) * u64::from(entry_bytes))
            .ok_or(AcpiTimeError::InvalidRootTable)?;
        let address = if entry_bytes == 8 {
            read_u64(
                reader,
                root_physical
                    .checked_add(offset)
                    .ok_or(AcpiTimeError::InvalidRootTable)?,
            )?
        } else {
            u64::from(read_u32(
                reader,
                root_physical
                    .checked_add(offset)
                    .ok_or(AcpiTimeError::InvalidRootTable)?,
            )?)
        };
        if address == 0 {
            continue;
        }
        let header = read_sdt_header(reader, address)?;
        if header.signature != *b"FACP" {
            continue;
        }
        if fadt.replace((address, header)).is_some() {
            return Err(AcpiTimeError::DuplicateFadt);
        }
    }
    let (physical, header) = fadt.ok_or(AcpiTimeError::MissingFadt)?;
    if checksum_physical(reader, physical, header.length)? != 0 {
        return Err(AcpiTimeError::InvalidFadt);
    }
    parse_fadt_pm_timer(reader, physical, header.length)
}

fn parse_fadt_pm_timer<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    length: u32,
) -> Result<PmTimerDescriptor, AcpiTimeError> {
    if length < FADT_MINIMUM_FLAGS_BYTES {
        return Err(AcpiTimeError::InvalidFadt);
    }
    let flags = read_u32(
        reader,
        physical
            .checked_add(FADT_FLAGS)
            .ok_or(AcpiTimeError::InvalidFadt)?,
    )?;
    if flags & FADT_HW_REDUCED_ACPI != 0 {
        return Err(AcpiTimeError::HardwareReduced);
    }
    let width = if flags & FADT_TMR_VAL_EXT != 0 {
        PmTimerWidth::Bits32
    } else {
        PmTimerWidth::Bits24
    };
    if length >= FADT_X_PM_TIMER_END {
        let mut gas = [0_u8; 12];
        read(
            reader,
            physical
                .checked_add(FADT_X_PM_TMR_BLK)
                .ok_or(AcpiTimeError::InvalidFadt)?,
            &mut gas,
        )?;
        if let Some(port) = usable_pm_timer_gas(gas) {
            return PmTimerDescriptor::new(port, width).map_err(|_| AcpiTimeError::InvalidFadt);
        }
    }

    let mut legacy = [0_u8; 5];
    read(
        reader,
        physical
            .checked_add(FADT_PM_TMR_BLK)
            .ok_or(AcpiTimeError::InvalidFadt)?,
        &mut legacy[..4],
    )?;
    read(
        reader,
        physical
            .checked_add(FADT_PM_TMR_LEN)
            .ok_or(AcpiTimeError::InvalidFadt)?,
        &mut legacy[4..],
    )?;
    let address = u32::from_le_bytes(legacy[..4].try_into().unwrap());
    if legacy[4] != 4 || address == 0 || address > u32::from(u16::MAX) {
        return Err(AcpiTimeError::MissingPmTimer);
    }
    PmTimerDescriptor::new(address as u16, width).map_err(|_| AcpiTimeError::InvalidFadt)
}

fn usable_pm_timer_gas(gas: [u8; 12]) -> Option<u16> {
    let address = u64::from_le_bytes(gas[4..12].try_into().ok()?);
    (gas[0] == GAS_SYSTEM_IO
        && gas[1] == 32
        && gas[2] == 0
        && matches!(gas[3], 0 | GAS_DWORD_ACCESS)
        && address != 0
        && address <= u64::from(u16::MAX))
    .then_some(address as u16)
}

fn read_sdt_header<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
) -> Result<SdtHeader, AcpiTimeError> {
    let mut bytes = [0_u8; SDT_HEADER_BYTES as usize];
    read(reader, physical, &mut bytes)?;
    let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if !(SDT_HEADER_BYTES..=MAX_ACPI_TABLE_BYTES).contains(&length) {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    Ok(SdtHeader {
        signature: bytes[..4].try_into().unwrap(),
        length,
    })
}

fn checksum_physical<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    length: u32,
) -> Result<u8, AcpiTimeError> {
    if length == 0 || length > MAX_ACPI_TABLE_BYTES {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    let mut sum = 0_u8;
    let mut offset = 0_u32;
    let mut chunk = [0_u8; 128];
    while offset < length {
        let take = usize::try_from((length - offset).min(chunk.len() as u32)).unwrap();
        read(
            reader,
            physical
                .checked_add(u64::from(offset))
                .ok_or(AcpiTimeError::ReadFailure)?,
            &mut chunk[..take],
        )?;
        sum = chunk[..take]
            .iter()
            .fold(sum, |sum, byte| sum.wrapping_add(*byte));
        offset += take as u32;
    }
    Ok(sum)
}

fn read_u32<R: AcpiByteReader>(reader: &mut R, physical: u64) -> Result<u32, AcpiTimeError> {
    let mut bytes = [0_u8; 4];
    read(reader, physical, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64<R: AcpiByteReader>(reader: &mut R, physical: u64) -> Result<u64, AcpiTimeError> {
    let mut bytes = [0_u8; 8];
    read(reader, physical, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    destination: &mut [u8],
) -> Result<(), AcpiTimeError> {
    reader
        .read_exact(physical, destination)
        .map_err(|()| AcpiTimeError::ReadFailure)
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default)]
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

    fn fix_checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        let sum = checksum(bytes);
        bytes[checksum_offset] = 0_u8.wrapping_sub(sum);
    }

    fn sdt(signature: [u8; 4], length: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; length];
        bytes[..4].copy_from_slice(&signature);
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[8] = 1;
        bytes
    }

    fn fixture(extended_port: Option<u16>, legacy_port: u16, flags: u32) -> (Memory, u64) {
        const RSDP: u64 = 0x1000;
        const XSDT: u64 = 0x2000;
        const FADT: u64 = 0x3000;
        let mut memory = Memory::default();

        let mut fadt = sdt(*b"FACP", FADT_X_PM_TIMER_END as usize);
        fadt[FADT_PM_TMR_BLK as usize..FADT_PM_TMR_BLK as usize + 4]
            .copy_from_slice(&u32::from(legacy_port).to_le_bytes());
        fadt[FADT_PM_TMR_LEN as usize] = 4;
        fadt[FADT_FLAGS as usize..FADT_FLAGS as usize + 4].copy_from_slice(&flags.to_le_bytes());
        if let Some(port) = extended_port {
            let gas = &mut fadt[FADT_X_PM_TMR_BLK as usize..FADT_X_PM_TMR_BLK as usize + 12];
            gas[0] = GAS_SYSTEM_IO;
            gas[1] = 32;
            gas[2] = 0;
            gas[3] = GAS_DWORD_ACCESS;
            gas[4..12].copy_from_slice(&u64::from(port).to_le_bytes());
        }
        fix_checksum(&mut fadt, 9);
        memory.place(FADT, &fadt);

        let mut xsdt = sdt(*b"XSDT", SDT_HEADER_BYTES as usize + 8);
        xsdt[SDT_HEADER_BYTES as usize..].copy_from_slice(&FADT.to_le_bytes());
        fix_checksum(&mut xsdt, 9);
        memory.place(XSDT, &xsdt);

        let mut rsdp = [0_u8; RSDP_V2_BYTES];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[16..20].copy_from_slice(&0_u32.to_le_bytes());
        rsdp[20..24].copy_from_slice(&(RSDP_V2_BYTES as u32).to_le_bytes());
        rsdp[24..32].copy_from_slice(&XSDT.to_le_bytes());
        fix_checksum(&mut rsdp[..RSDP_V1_BYTES], 8);
        fix_checksum(&mut rsdp, 32);
        memory.place(RSDP, &rsdp);
        (memory, RSDP)
    }

    #[test]
    fn extended_system_io_pm_timer_is_preferred() {
        let (mut memory, rsdp) = fixture(Some(0x608), 0x1234, FADT_TMR_VAL_EXT);
        let descriptor = discover_pm_timer(&mut memory, rsdp).unwrap();
        assert_eq!(descriptor.port(), 0x608);
        assert_eq!(descriptor.width(), PmTimerWidth::Bits32);
    }

    #[test]
    fn unusable_extended_gas_falls_back_to_legacy_timer() {
        let (mut memory, rsdp) = fixture(Some(0x608), 0x4321, 0);
        let mut fadt = (0..FADT_X_PM_TIMER_END as usize)
            .map(|offset| *memory.0.get(&(0x3000 + offset as u64)).unwrap())
            .collect::<Vec<_>>();
        fadt[FADT_X_PM_TMR_BLK as usize] = 0;
        fix_checksum(&mut fadt, 9);
        memory.place(0x3000, &fadt);
        let descriptor = discover_pm_timer(&mut memory, rsdp).unwrap();
        assert_eq!(descriptor.port(), 0x4321);
        assert_eq!(descriptor.width(), PmTimerWidth::Bits24);
    }

    #[test]
    fn bad_root_checksum_fails_closed() {
        let (mut memory, rsdp) = fixture(Some(0x608), 0x608, 0);
        let byte = memory.0.get_mut(&(0x2000 + 10)).unwrap();
        *byte ^= 1;
        assert_eq!(
            discover_pm_timer(&mut memory, rsdp),
            Err(AcpiTimeError::InvalidRootTable)
        );
    }

    #[test]
    fn hardware_reduced_fadt_rejects_fixed_pm_timer_fields() {
        let (mut memory, rsdp) = fixture(Some(0x608), 0x608, FADT_HW_REDUCED_ACPI);
        assert_eq!(
            discover_pm_timer(&mut memory, rsdp),
            Err(AcpiTimeError::HardwareReduced)
        );
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct AcpiScratchReader<
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    paging: &'borrow mut crate::arch::x86_64::mm::ActiveDeepPaging<
        crate::arch::x86_64::mm::LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    boot: &'borrow crate::boot::ValidatedBootInfo,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    AcpiScratchReader<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(crate) fn new(
        paging: &'borrow mut crate::arch::x86_64::mm::ActiveDeepPaging<
            crate::arch::x86_64::mm::LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
        >,
        boot: &'borrow crate::boot::ValidatedBootInfo,
    ) -> Self {
        Self { paging, boot }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> AcpiByteReader
    for AcpiScratchReader<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        if !acpi_range_is_declared(self.boot, physical_start, destination.len()) {
            return Err(());
        }
        self.paging
            .read_physical_bytes(physical_start, destination)
            .map_err(|_| ())
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn acpi_range_is_declared(
    boot: &crate::boot::ValidatedBootInfo,
    physical_start: u64,
    byte_len: usize,
) -> bool {
    use deepwyrm_abi::{
        DW_BOOT_MEMORY_KIND_ACPI_NVS, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM,
        DW_BOOT_MEMORY_KIND_RESERVED,
    };
    if byte_len == 0 {
        return true;
    }
    let Some(end) = physical_start.checked_add(byte_len as u64) else {
        return false;
    };
    let mut cursor = physical_start;
    for index in 0..boot.memory_map().entry_count() {
        let Ok(range) = boot.memory_range(index) else {
            return false;
        };
        let Some(range_end) = range
            .physical_start
            .checked_add(range.page_count.saturating_mul(4096))
        else {
            return false;
        };
        if range_end <= cursor {
            continue;
        }
        if range.physical_start > cursor {
            return false;
        }
        if range.kind != DW_BOOT_MEMORY_KIND_ACPI_RECLAIM
            && range.kind != DW_BOOT_MEMORY_KIND_ACPI_NVS
            && range.kind != DW_BOOT_MEMORY_KIND_RESERVED
        {
            return false;
        }
        cursor = range_end.min(end);
        if cursor == end {
            return true;
        }
    }
    false
}
