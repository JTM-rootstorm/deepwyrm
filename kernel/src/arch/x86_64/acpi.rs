#![cfg_attr(
    not(all(target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "F3 ACPI discovery is target boot code with host model tests"
    )
)]

//! Bounded, snapshot-based ACPI discovery for the DW0-F3 reference clock.
//!
//! Firmware bytes are copied once into kernel-owned workspace, checksummed, and
//! parsed only from that immutable observation. Discovery yields a resource
//! proposal. The locked q35 profile separately authorizes the exact PM I/O port.

use crate::time::{PmTimerDescriptor, PmTimerWidth};

const RSDP_V1_BYTES: usize = 20;
const RSDP_V2_BYTES: usize = 36;
const MAX_RSDP_BYTES: usize = 4096;
const SDT_HEADER_BYTES: usize = 36;
const MAX_ACPI_TABLE_BYTES: usize = 64 * 1024;
const MAX_ROOT_ENTRIES: usize = 128;
const FADT_PM_TMR_BLK: usize = 76;
const FADT_PM_TMR_LEN: usize = 91;
const FADT_FLAGS: usize = 112;
const FADT_X_PM_TMR_BLK: usize = 208;
const FADT_MINIMUM_FLAGS_BYTES: usize = 116;
const FADT_X_PM_TIMER_END: usize = 220;
const FADT_TMR_VAL_EXT: u32 = 1 << 8;
const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;
const GAS_SYSTEM_IO: u8 = 1;
const GAS_DWORD_ACCESS: u8 = 3;
pub(crate) const Q35_PM_TIMER_PORT: u16 = 0x608;

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
    ConflictingPmTimer,
    UnauthorizedPmTimerPort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PmTimerProposal {
    port: u16,
    width: PmTimerWidth,
}

impl PmTimerProposal {
    pub(crate) const fn port(self) -> u16 {
        self.port
    }
    pub(crate) const fn width(self) -> PmTimerWidth {
        self.width
    }
}

pub(crate) struct AcpiSnapshotWorkspace {
    rsdp: [u8; MAX_RSDP_BYTES],
    table: [u8; MAX_ACPI_TABLE_BYTES],
    root_entries: [u64; MAX_ROOT_ENTRIES],
}

impl AcpiSnapshotWorkspace {
    pub(crate) const fn new() -> Self {
        Self {
            rsdp: [0; MAX_RSDP_BYTES],
            table: [0; MAX_ACPI_TABLE_BYTES],
            root_entries: [0; MAX_ROOT_ENTRIES],
        }
    }
}

pub(crate) trait AcpiByteReader {
    fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()>;
}

#[derive(Clone, Copy)]
enum RootTable {
    Rsdt(u64),
    Xsdt(u64),
}

pub(crate) fn discover_pm_timer_proposal<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<PmTimerProposal, AcpiTimeError> {
    if rsdp_physical == 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let root = snapshot_rsdp(reader, rsdp_physical, &mut workspace.rsdp)?;
    let (root_physical, entry_bytes, expected_signature) = match root {
        RootTable::Xsdt(address) => (address, 8_usize, *b"XSDT"),
        RootTable::Rsdt(address) => (address, 4_usize, *b"RSDT"),
    };
    let root_len = snapshot_sdt(
        reader,
        root_physical,
        &mut workspace.table,
        AcpiTimeError::InvalidRootTable,
    )?;
    let root_bytes = &workspace.table[..root_len];
    if root_bytes[..4] != expected_signature {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    let payload = root_len
        .checked_sub(SDT_HEADER_BYTES)
        .ok_or(AcpiTimeError::InvalidRootTable)?;
    if payload % entry_bytes != 0 {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    let count = payload / entry_bytes;
    if count == 0 || count > MAX_ROOT_ENTRIES {
        return Err(AcpiTimeError::RootEntryLimit);
    }
    for index in 0..count {
        let start = SDT_HEADER_BYTES + index * entry_bytes;
        workspace.root_entries[index] = if entry_bytes == 8 {
            u64::from_le_bytes(root_bytes[start..start + 8].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(
                root_bytes[start..start + 4].try_into().unwrap(),
            ))
        };
    }

    let mut proposal = None;
    for index in 0..count {
        let physical = workspace.root_entries[index];
        if physical == 0 {
            continue;
        }
        let header_len = snapshot_sdt_header(reader, physical, &mut workspace.table)?;
        if workspace.table[..4] != *b"FACP" {
            continue;
        }
        if proposal.is_some() {
            return Err(AcpiTimeError::DuplicateFadt);
        }
        let fadt_len = finish_sdt_snapshot(
            reader,
            physical,
            header_len,
            &mut workspace.table,
            AcpiTimeError::InvalidFadt,
        )?;
        proposal = Some(parse_fadt_pm_timer(&workspace.table[..fadt_len])?);
    }
    proposal.ok_or(AcpiTimeError::MissingFadt)
}

pub(crate) fn authorize_q35_pm_timer(
    proposal: PmTimerProposal,
) -> Result<PmTimerDescriptor, AcpiTimeError> {
    if proposal.port != Q35_PM_TIMER_PORT {
        return Err(AcpiTimeError::UnauthorizedPmTimerPort);
    }
    PmTimerDescriptor::new(proposal.port, proposal.width).map_err(|_| AcpiTimeError::InvalidFadt)
}

fn snapshot_rsdp<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    storage: &mut [u8; MAX_RSDP_BYTES],
) -> Result<RootTable, AcpiTimeError> {
    read(reader, physical, &mut storage[..RSDP_V1_BYTES])?;
    if &storage[..8] != b"RSD PTR " || checksum(&storage[..RSDP_V1_BYTES]) != 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let revision = storage[15];
    let rsdt = u64::from(u32::from_le_bytes(storage[16..20].try_into().unwrap()));
    if revision < 2 {
        return (rsdt != 0)
            .then_some(RootTable::Rsdt(rsdt))
            .ok_or(AcpiTimeError::InvalidRsdp);
    }
    read(
        reader,
        physical
            .checked_add(RSDP_V1_BYTES as u64)
            .ok_or(AcpiTimeError::InvalidRsdp)?,
        &mut storage[RSDP_V1_BYTES..RSDP_V2_BYTES],
    )?;
    let length = usize::try_from(u32::from_le_bytes(storage[20..24].try_into().unwrap()))
        .map_err(|_| AcpiTimeError::InvalidRsdp)?;
    if !(RSDP_V2_BYTES..=MAX_RSDP_BYTES).contains(&length) {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    if length > RSDP_V2_BYTES {
        read(
            reader,
            physical
                .checked_add(RSDP_V2_BYTES as u64)
                .ok_or(AcpiTimeError::InvalidRsdp)?,
            &mut storage[RSDP_V2_BYTES..length],
        )?;
    }
    if checksum(&storage[..length]) != 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let xsdt = u64::from_le_bytes(storage[24..32].try_into().unwrap());
    if xsdt != 0 {
        return Ok(RootTable::Xsdt(xsdt));
    }
    (rsdt != 0)
        .then_some(RootTable::Rsdt(rsdt))
        .ok_or(AcpiTimeError::InvalidRsdp)
}

fn snapshot_sdt<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    storage: &mut [u8; MAX_ACPI_TABLE_BYTES],
    invalid: AcpiTimeError,
) -> Result<usize, AcpiTimeError> {
    let length = snapshot_sdt_header(reader, physical, storage).map_err(|_| invalid)?;
    finish_sdt_snapshot(reader, physical, length, storage, invalid)
}

fn snapshot_sdt_header<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    storage: &mut [u8; MAX_ACPI_TABLE_BYTES],
) -> Result<usize, AcpiTimeError> {
    read(reader, physical, &mut storage[..SDT_HEADER_BYTES])?;
    let length = usize::try_from(u32::from_le_bytes(storage[4..8].try_into().unwrap()))
        .map_err(|_| AcpiTimeError::InvalidRootTable)?;
    if !(SDT_HEADER_BYTES..=MAX_ACPI_TABLE_BYTES).contains(&length) {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    Ok(length)
}

fn finish_sdt_snapshot<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    length: usize,
    storage: &mut [u8; MAX_ACPI_TABLE_BYTES],
    invalid: AcpiTimeError,
) -> Result<usize, AcpiTimeError> {
    if length > SDT_HEADER_BYTES {
        read(
            reader,
            physical
                .checked_add(SDT_HEADER_BYTES as u64)
                .ok_or(invalid)?,
            &mut storage[SDT_HEADER_BYTES..length],
        )?;
    }
    if checksum(&storage[..length]) != 0 {
        return Err(invalid);
    }
    Ok(length)
}

fn parse_fadt_pm_timer(bytes: &[u8]) -> Result<PmTimerProposal, AcpiTimeError> {
    if bytes.len() < FADT_MINIMUM_FLAGS_BYTES {
        return Err(AcpiTimeError::InvalidFadt);
    }
    let flags = u32::from_le_bytes(bytes[FADT_FLAGS..FADT_FLAGS + 4].try_into().unwrap());
    if flags & FADT_HW_REDUCED_ACPI != 0 {
        return Err(AcpiTimeError::HardwareReduced);
    }
    let width = if flags & FADT_TMR_VAL_EXT != 0 {
        PmTimerWidth::Bits32
    } else {
        PmTimerWidth::Bits24
    };

    let legacy_address = u32::from_le_bytes(
        bytes[FADT_PM_TMR_BLK..FADT_PM_TMR_BLK + 4]
            .try_into()
            .unwrap(),
    );
    let legacy = (bytes[FADT_PM_TMR_LEN] == 4
        && legacy_address != 0
        && legacy_address <= u32::from(u16::MAX))
    .then_some(legacy_address as u16);
    let extended = (bytes.len() >= FADT_X_PM_TIMER_END)
        .then(|| {
            let mut gas = [0_u8; 12];
            gas.copy_from_slice(&bytes[FADT_X_PM_TMR_BLK..FADT_X_PM_TMR_BLK + 12]);
            usable_pm_timer_gas(gas)
        })
        .flatten();
    if let (Some(extended), Some(legacy)) = (extended, legacy)
        && extended != legacy
    {
        return Err(AcpiTimeError::ConflictingPmTimer);
    }
    let port = extended.or(legacy).ok_or(AcpiTimeError::MissingPmTimer)?;
    Ok(PmTimerProposal { port, width })
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
    use std::boxed::Box;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default, Clone)]
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

    struct MutatingMemory {
        memory: Memory,
        reads: usize,
    }
    impl AcpiByteReader for MutatingMemory {
        fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
            self.memory.read_exact(physical_start, destination)?;
            self.reads += 1;
            for offset in 0..destination.len() {
                if let Some(byte) = self.memory.0.get_mut(&(physical_start + offset as u64)) {
                    *byte ^= 0x5a;
                }
            }
            Ok(())
        }
    }

    fn workspace() -> Box<AcpiSnapshotWorkspace> {
        Box::new(AcpiSnapshotWorkspace::new())
    }
    fn fix_checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        bytes[checksum_offset] = 0_u8.wrapping_sub(checksum(bytes));
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
        let mut fadt = sdt(*b"FACP", FADT_X_PM_TIMER_END);
        fadt[FADT_PM_TMR_BLK..FADT_PM_TMR_BLK + 4]
            .copy_from_slice(&u32::from(legacy_port).to_le_bytes());
        fadt[FADT_PM_TMR_LEN] = 4;
        fadt[FADT_FLAGS..FADT_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        if let Some(port) = extended_port {
            let gas = &mut fadt[FADT_X_PM_TMR_BLK..FADT_X_PM_TMR_BLK + 12];
            gas[0] = GAS_SYSTEM_IO;
            gas[1] = 32;
            gas[2] = 0;
            gas[3] = GAS_DWORD_ACCESS;
            gas[4..12].copy_from_slice(&u64::from(port).to_le_bytes());
        }
        fix_checksum(&mut fadt, 9);
        memory.place(FADT, &fadt);
        let mut xsdt = sdt(*b"XSDT", SDT_HEADER_BYTES + 8);
        xsdt[SDT_HEADER_BYTES..].copy_from_slice(&FADT.to_le_bytes());
        fix_checksum(&mut xsdt, 9);
        memory.place(XSDT, &xsdt);
        let mut rsdp = [0_u8; RSDP_V2_BYTES];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&(RSDP_V2_BYTES as u32).to_le_bytes());
        rsdp[24..32].copy_from_slice(&XSDT.to_le_bytes());
        fix_checksum(&mut rsdp[..RSDP_V1_BYTES], 8);
        fix_checksum(&mut rsdp, 32);
        memory.place(RSDP, &rsdp);
        (memory, RSDP)
    }
    fn proposal(
        memory: &mut impl AcpiByteReader,
        rsdp: u64,
    ) -> Result<PmTimerProposal, AcpiTimeError> {
        discover_pm_timer_proposal(memory, rsdp, &mut workspace())
    }

    #[test]
    fn q35_extended_timer_is_snapshot_parsed_and_authorized() {
        let (mut memory, rsdp) =
            fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, FADT_TMR_VAL_EXT);
        let proposal = proposal(&mut memory, rsdp).unwrap();
        assert_eq!(proposal.port(), Q35_PM_TIMER_PORT);
        assert_eq!(proposal.width(), PmTimerWidth::Bits32);
        assert_eq!(
            authorize_q35_pm_timer(proposal).unwrap().port(),
            Q35_PM_TIMER_PORT
        );
    }
    #[test]
    fn unusable_extended_gas_falls_back_to_matching_q35_legacy_timer() {
        let (mut memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, 0);
        *memory
            .0
            .get_mut(&(0x3000 + FADT_X_PM_TMR_BLK as u64))
            .unwrap() = 0;
        let mut fadt = (0..FADT_X_PM_TIMER_END)
            .map(|o| *memory.0.get(&(0x3000 + o as u64)).unwrap())
            .collect::<Vec<_>>();
        fix_checksum(&mut fadt, 9);
        memory.place(0x3000, &fadt);
        assert_eq!(
            authorize_q35_pm_timer(proposal(&mut memory, rsdp).unwrap())
                .unwrap()
                .port(),
            Q35_PM_TIMER_PORT
        );
    }
    #[test]
    fn conflicting_legacy_and_extended_ports_fail_closed() {
        let (mut memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), 0x1234, 0);
        assert_eq!(
            proposal(&mut memory, rsdp),
            Err(AcpiTimeError::ConflictingPmTimer)
        );
    }
    #[test]
    fn firmware_port_number_is_only_a_proposal_not_io_authority() {
        for port in [1_u16, 0x80, 0x607, 0x609, u16::MAX] {
            let (mut memory, rsdp) = fixture(None, port, 0);
            let proposal = proposal(&mut memory, rsdp).unwrap();
            assert_eq!(
                authorize_q35_pm_timer(proposal),
                Err(AcpiTimeError::UnauthorizedPmTimerPort)
            );
        }
    }
    #[test]
    fn snapshot_parsing_survives_mutation_after_each_physical_read() {
        let (memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, 0);
        let mut mutating = MutatingMemory { memory, reads: 0 };
        let proposal = proposal(&mut mutating, rsdp).unwrap();
        assert_eq!(proposal.port(), Q35_PM_TIMER_PORT);
        assert!(mutating.reads >= 6);
    }
    #[test]
    fn bad_root_checksum_fails_closed() {
        let (mut memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, 0);
        *memory.0.get_mut(&(0x2000 + 10)).unwrap() ^= 1;
        assert_eq!(
            proposal(&mut memory, rsdp),
            Err(AcpiTimeError::InvalidRootTable)
        );
    }
    #[test]
    fn hardware_reduced_fadt_rejects_fixed_pm_timer_fields() {
        let (mut memory, rsdp) = fixture(
            Some(Q35_PM_TIMER_PORT),
            Q35_PM_TIMER_PORT,
            FADT_HW_REDUCED_ACPI,
        );
        assert_eq!(
            proposal(&mut memory, rsdp),
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
