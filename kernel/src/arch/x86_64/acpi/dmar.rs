//! Bounded snapshot parsing of the ACPI DMAR table (Intel VT-d units).
//!
//! Like the rest of `acpi`, firmware bytes are copied once into the kernel's
//! workspace, checksummed, and parsed only from that copy. The result is the
//! set of remapping-unit register bases the kernel must take over; no DMAR
//! field is trusted as authority by itself (root `STORAGE_PLAN.md`, K0).

use super::{
    AcpiByteReader, AcpiSnapshotWorkspace, AcpiTimeError, MAX_ROOT_ENTRIES, RootTable,
    SDT_HEADER_BYTES, finish_sdt_snapshot, snapshot_rsdp, snapshot_sdt, snapshot_sdt_header,
};

/// Remapping units the kernel will take over. q35 has one.
pub(crate) const MAX_DMAR_UNITS: usize = 8;
const DMAR_HEADER_BYTES: usize = SDT_HEADER_BYTES + 12;
const DMAR_HOST_ADDRESS_WIDTH: usize = SDT_HEADER_BYTES;
const DMAR_FLAGS: usize = SDT_HEADER_BYTES + 1;
const DMAR_FLAG_INTR_REMAP: u8 = 1;
const STRUCTURE_HEADER_BYTES: usize = 4;
const STRUCTURE_DRHD: u16 = 0;
const STRUCTURE_RMRR: u16 = 1;
const DRHD_MIN_BYTES: usize = 16;
const DRHD_FLAG_INCLUDE_PCI_ALL: u8 = 1;
/// A device scope entry: type, length, reserved, enumeration ID, start bus,
/// then one (device, function) pair per hop (VT-d 4.x §8.3.1).
const SCOPE_HEADER_BYTES: usize = 6;
const SCOPE_PATH_BYTES: usize = 2;
const SCOPE_PCI_ENDPOINT: u8 = 1;
const PAGE: u64 = 4096;
/// The address widths VT-d can report and x86_64 can address.
const MIN_HOST_ADDRESS_WIDTH: u8 = 32;
const MAX_HOST_ADDRESS_WIDTH: u8 = 52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DmarError {
    ReadFailure,
    InvalidRootTable,
    DuplicateDmar,
    InvalidDmar,
    InvalidHostAddressWidth,
    InvalidStructure,
    UnsupportedSegment,
    InvalidRegisterBase,
    DuplicateRegisterBase,
    MultipleIncludeAll,
    TooManyUnits,
    NoUnits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DmarUnit {
    register_base: u64,
    include_pci_all: bool,
    /// Bus-0 functions this unit's device scope names as PCI endpoints, one
    /// bit per `device << 3 | function`.
    bus0_endpoints: Bus0Functions,
}

/// A set of segment-0, bus-0 functions, one bit per `device << 3 | function`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Bus0Functions(pub(crate) [u64; 4]);

impl Bus0Functions {
    pub(crate) const ALL: Self = Self([u64::MAX; 4]);

    pub(crate) const fn contains(self, devfn: u8) -> bool {
        self.0[(devfn >> 6) as usize] & (1 << (devfn & 63)) != 0
    }

    const fn insert(&mut self, devfn: u8) {
        self.0[(devfn >> 6) as usize] |= 1 << (devfn & 63);
    }

    const fn union(self, other: Self) -> Self {
        Self([
            self.0[0] | other.0[0],
            self.0[1] | other.0[1],
            self.0[2] | other.0[2],
            self.0[3] | other.0[3],
        ])
    }
}

impl DmarUnit {
    pub(crate) const fn register_base(self) -> u64 {
        self.register_base
    }

    /// The unit translates every function on its segment not claimed by
    /// another unit's explicit device scope.
    pub(crate) const fn include_pci_all(self) -> bool {
        self.include_pci_all
    }

    #[cfg(test)]
    pub(crate) const fn bus0_endpoints(self) -> Bus0Functions {
        self.bus0_endpoints
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DmarSnapshot {
    host_address_width: u8,
    interrupt_remapping: bool,
    reserved_memory_regions: usize,
    units: [DmarUnit; MAX_DMAR_UNITS],
    count: usize,
}

impl DmarSnapshot {
    /// Physical address bits a remapping unit can reach.
    pub(crate) const fn host_address_width(&self) -> u8 {
        self.host_address_width
    }

    #[cfg(test)]
    pub(crate) const fn interrupt_remapping(&self) -> bool {
        self.interrupt_remapping
    }

    /// RMRR structures: memory firmware says some device keeps using. The
    /// kernel maps none of them, so such devices lose that memory.
    pub(crate) const fn reserved_memory_regions(&self) -> usize {
        self.reserved_memory_regions
    }

    pub(crate) fn units(&self) -> &[DmarUnit] {
        &self.units[..self.count]
    }

    /// The bus-0 functions some unit translates: every function when a unit
    /// includes all PCI devices, else those named as endpoints in a device
    /// scope. Endpoints behind bridges (multi-hop paths, other buses) are not
    /// included, so they never get bus mastering.
    pub(crate) fn translated_bus0_functions(&self) -> Bus0Functions {
        self.units()
            .iter()
            .fold(Bus0Functions::default(), |functions, unit| {
                if unit.include_pci_all {
                    Bus0Functions::ALL
                } else {
                    functions.union(unit.bus0_endpoints)
                }
            })
    }
}

/// Snapshots and parses the unique DMAR. `Ok(None)` means the platform has no
/// remapping hardware, which is a supported configuration: the kernel then
/// admits no device DMA at all.
pub(crate) fn discover_dmar<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<Option<DmarSnapshot>, DmarError> {
    match snapshot_unique_table(reader, rsdp_physical, *b"DMAR", workspace)? {
        None => Ok(None),
        Some(length) => parse_dmar(&workspace.table[..length]).map(Some),
    }
}

/// Copies the one root-table entry with `signature` into `workspace.table`.
fn snapshot_unique_table<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    signature: [u8; 4],
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<Option<usize>, DmarError> {
    let read_error = |error| match error {
        AcpiTimeError::ReadFailure => DmarError::ReadFailure,
        _ => DmarError::InvalidRootTable,
    };
    if rsdp_physical == 0 {
        return Err(DmarError::InvalidRootTable);
    }
    let root = snapshot_rsdp(reader, rsdp_physical, &mut workspace.rsdp).map_err(read_error)?;
    let (root_physical, entry_bytes, expected) = match root {
        RootTable::Xsdt(address) => (address, 8_usize, *b"XSDT"),
        RootTable::Rsdt(address) => (address, 4_usize, *b"RSDT"),
    };
    let root_len = snapshot_sdt(
        reader,
        root_physical,
        &mut workspace.table,
        AcpiTimeError::InvalidRootTable,
    )
    .map_err(read_error)?;
    let root_bytes = &workspace.table[..root_len];
    if root_bytes[..4] != expected {
        return Err(DmarError::InvalidRootTable);
    }
    let payload = root_len - SDT_HEADER_BYTES;
    if !payload.is_multiple_of(entry_bytes) {
        return Err(DmarError::InvalidRootTable);
    }
    let count = payload / entry_bytes;
    if count == 0 || count > MAX_ROOT_ENTRIES {
        return Err(DmarError::InvalidRootTable);
    }
    for index in 0..count {
        let start = SDT_HEADER_BYTES + index * entry_bytes;
        workspace.root_entries[index] = if entry_bytes == 8 {
            le_u64(root_bytes, start)
        } else {
            u64::from(le_u32(root_bytes, start))
        };
    }
    let mut selected = None;
    for index in 0..count {
        let physical = workspace.root_entries[index];
        if physical == 0 {
            continue;
        }
        snapshot_sdt_header(reader, physical, &mut workspace.table).map_err(read_error)?;
        if workspace.table[..4] != signature {
            continue;
        }
        if selected.is_some() {
            return Err(DmarError::DuplicateDmar);
        }
        selected = Some(physical);
    }
    let Some(physical) = selected else {
        return Ok(None);
    };
    let length = snapshot_sdt_header(reader, physical, &mut workspace.table).map_err(read_error)?;
    finish_sdt_snapshot(
        reader,
        physical,
        length,
        &mut workspace.table,
        AcpiTimeError::InvalidRootTable,
    )
    .map(Some)
    .map_err(|error| match error {
        AcpiTimeError::ReadFailure => DmarError::ReadFailure,
        _ => DmarError::InvalidDmar,
    })
}

fn parse_dmar(bytes: &[u8]) -> Result<DmarSnapshot, DmarError> {
    if bytes.len() < DMAR_HEADER_BYTES || bytes[..4] != *b"DMAR" {
        return Err(DmarError::InvalidDmar);
    }
    let host_address_width = bytes[DMAR_HOST_ADDRESS_WIDTH]
        .checked_add(1)
        .filter(|width| (MIN_HOST_ADDRESS_WIDTH..=MAX_HOST_ADDRESS_WIDTH).contains(width))
        .ok_or(DmarError::InvalidHostAddressWidth)?;
    let address_limit = 1_u64 << host_address_width;
    let mut snapshot = DmarSnapshot {
        host_address_width,
        interrupt_remapping: bytes[DMAR_FLAGS] & DMAR_FLAG_INTR_REMAP != 0,
        reserved_memory_regions: 0,
        units: [DmarUnit {
            register_base: 0,
            include_pci_all: false,
            bus0_endpoints: Bus0Functions([0; 4]),
        }; MAX_DMAR_UNITS],
        count: 0,
    };
    let mut offset = DMAR_HEADER_BYTES;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(STRUCTURE_HEADER_BYTES)
            .filter(|end| *end <= bytes.len())
            .ok_or(DmarError::InvalidStructure)?;
        let kind = le_u16(bytes, offset);
        let length = usize::from(le_u16(bytes, offset + 2));
        let end = offset
            .checked_add(length)
            .filter(|end| length >= STRUCTURE_HEADER_BYTES && *end <= bytes.len())
            .ok_or(DmarError::InvalidStructure)?;
        debug_assert!(header_end <= end);
        match kind {
            STRUCTURE_DRHD => {
                let unit = parse_drhd(&bytes[offset..end], address_limit)?;
                if snapshot
                    .units()
                    .iter()
                    .any(|known| known.register_base == unit.register_base)
                {
                    return Err(DmarError::DuplicateRegisterBase);
                }
                if unit.include_pci_all
                    && snapshot.units().iter().any(|known| known.include_pci_all)
                {
                    return Err(DmarError::MultipleIncludeAll);
                }
                let slot = snapshot
                    .units
                    .get_mut(snapshot.count)
                    .ok_or(DmarError::TooManyUnits)?;
                *slot = unit;
                snapshot.count += 1;
            }
            STRUCTURE_RMRR => {
                snapshot.reserved_memory_regions = snapshot
                    .reserved_memory_regions
                    .checked_add(1)
                    .ok_or(DmarError::InvalidStructure)?;
            }
            // ATSR, RHSA, ANDD, SATC and later types grant nothing; skip them.
            _ => {}
        }
        offset = end;
    }
    if snapshot.count == 0 {
        return Err(DmarError::NoUnits);
    }
    Ok(snapshot)
}

fn parse_drhd(bytes: &[u8], address_limit: u64) -> Result<DmarUnit, DmarError> {
    if bytes.len() < DRHD_MIN_BYTES {
        return Err(DmarError::InvalidStructure);
    }
    if le_u16(bytes, 6) != 0 {
        return Err(DmarError::UnsupportedSegment);
    }
    let register_base = le_u64(bytes, 8);
    if register_base == 0 || !register_base.is_multiple_of(PAGE) || register_base >= address_limit {
        return Err(DmarError::InvalidRegisterBase);
    }
    Ok(DmarUnit {
        register_base,
        include_pci_all: bytes[4] & DRHD_FLAG_INCLUDE_PCI_ALL != 0,
        bus0_endpoints: parse_device_scopes(&bytes[DRHD_MIN_BYTES..])?,
    })
}

/// Walks a DRHD's device scope entries. Every entry must be well formed;
/// only single-hop PCI endpoints starting at bus 0 are recorded.
fn parse_device_scopes(bytes: &[u8]) -> Result<Bus0Functions, DmarError> {
    let mut functions = Bus0Functions::default();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < SCOPE_HEADER_BYTES {
            return Err(DmarError::InvalidStructure);
        }
        let kind = bytes[offset];
        let length = usize::from(bytes[offset + 1]);
        if length < SCOPE_HEADER_BYTES + SCOPE_PATH_BYTES
            || !(length - SCOPE_HEADER_BYTES).is_multiple_of(SCOPE_PATH_BYTES)
            || length > bytes.len() - offset
        {
            return Err(DmarError::InvalidStructure);
        }
        let start_bus = bytes[offset + 5];
        let path = &bytes[offset + SCOPE_HEADER_BYTES..offset + length];
        if kind == SCOPE_PCI_ENDPOINT && start_bus == 0 && path.len() == SCOPE_PATH_BYTES {
            let (device, function) = (path[0], path[1]);
            if device >= 32 || function >= 8 {
                return Err(DmarError::InvalidStructure);
            }
            functions.insert(device << 3 | function);
        }
        offset += length;
    }
    Ok(functions)
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests;
