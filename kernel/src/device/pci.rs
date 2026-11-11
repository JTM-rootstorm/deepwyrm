//! PCI function identity checks and BAR admission (storage K1).
//!
//! `DW2_PCI_DEVICE_DMA_CONTRACT.md` §3. At boot the kernel probes each
//! `PCI_FUNCTION` boot record through a [`ConfigSpace`]: the function must be
//! present with the recorded vendor and device IDs and a type-0 header, and
//! each memory BAR is sized and admitted only if it is page-granular, below
//! the CPU's physical limit, and clear of every memory-map range that is not
//! MMIO. Nothing here depends on the device's class or driver.

/// Standard configuration-space registers.
const REG_IDS: u8 = 0x00;
const REG_COMMAND: u8 = 0x04;
const REG_HEADER: u8 = 0x0c;
const REG_BAR0: u8 = 0x10;
pub(crate) const BAR_COUNT: usize = 6;

pub(crate) const COMMAND_IO_SPACE: u16 = 1 << 0;
pub(crate) const COMMAND_MEMORY_SPACE: u16 = 1 << 1;
pub(crate) const COMMAND_BUS_MASTER: u16 = 1 << 2;

const BAR_IO: u32 = 1;
const BAR_TYPE_MASK: u32 = 0b110;
const BAR_TYPE_64: u32 = 0b100;
const BAR_TYPE_32: u32 = 0b000;
const BAR_PREFETCHABLE: u32 = 1 << 3;
const PAGE: u64 = 4096;

/// A segment-0 bus/device/function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PciAddress {
    bus: u8,
    device: u8,
    function: u8,
}

impl PciAddress {
    /// Decodes the boot record's `pci_address`; the segment must be zero.
    pub(crate) const fn from_boot(raw: u32) -> Option<Self> {
        if raw >> 16 != 0 {
            return None;
        }
        Some(Self {
            bus: (raw >> 8) as u8,
            device: ((raw >> 3) & 0x1f) as u8,
            function: (raw & 0x7) as u8,
        })
    }

    pub(crate) const fn bus(self) -> u8 {
        self.bus
    }

    pub(crate) const fn device(self) -> u8 {
        self.device
    }

    pub(crate) const fn function(self) -> u8 {
        self.function
    }
}

/// Aligned 32-bit access to one function's standard configuration space.
pub(crate) trait ConfigSpace {
    fn read32(&mut self, address: PciAddress, offset: u8) -> u32;
    fn write32(&mut self, address: PciAddress, offset: u8, value: u32);
}

/// One admitted memory BAR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PciBar {
    base: u64,
    size: u64,
    prefetchable: bool,
}

impl PciBar {
    pub(crate) const fn base(self) -> u64 {
        self.base
    }

    pub(crate) const fn size(self) -> u64 {
        self.size
    }

    pub(crate) const fn prefetchable(self) -> bool {
        self.prefetchable
    }
}

/// Why a BAR slot holds no admitted memory range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BarSlot {
    Unimplemented,
    /// An I/O BAR, recorded but not admitted in this revision.
    Io,
    /// The upper half of the 64-bit BAR before it.
    Upper,
    Admitted(PciBar),
    Refused(BarRefusal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BarRefusal {
    /// Smaller than a page, or not page-aligned: it cannot be mapped alone.
    NotPageGranular,
    BeyondPhysicalLimit,
    OverlapsMemory,
    /// A 64-bit BAR in the last slot, or the reserved type encoding.
    Malformed,
}

/// A probed function the kernel can hand to a driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PciFunction {
    address: PciAddress,
    ids: u32,
    bars: [BarSlot; BAR_COUNT],
}

impl PciFunction {
    pub(crate) const fn address(&self) -> PciAddress {
        self.address
    }

    pub(crate) const fn ids(&self) -> u32 {
        self.ids
    }

    pub(crate) const fn bar(&self, index: usize) -> Option<BarSlot> {
        if index < BAR_COUNT {
            Some(self.bars[index])
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PciProbeError {
    InvalidAddress,
    Absent,
    IdentityMismatch { found: u32 },
    NotAnEndpoint { header_type: u8 },
}

/// Probes one boot-recorded function and sizes its BARs.
///
/// `physical_limit` is the CPU's exclusive physical-address limit;
/// `overlaps_memory(start, end)` reports whether `[start, end)` touches any
/// memory-map range other than MMIO.
pub(crate) fn probe<C: ConfigSpace>(
    config: &mut C,
    raw_address: u32,
    expected_ids: u32,
    physical_limit: u64,
    mut overlaps_memory: impl FnMut(u64, u64) -> bool,
) -> Result<PciFunction, PciProbeError> {
    let address = PciAddress::from_boot(raw_address).ok_or(PciProbeError::InvalidAddress)?;
    let ids = config.read32(address, REG_IDS);
    if ids & 0xffff == 0xffff {
        return Err(PciProbeError::Absent);
    }
    if ids != expected_ids {
        return Err(PciProbeError::IdentityMismatch { found: ids });
    }
    let header_type = ((config.read32(address, REG_HEADER) >> 16) & 0x7f) as u8;
    if header_type != 0 {
        return Err(PciProbeError::NotAnEndpoint { header_type });
    }

    // Size with decoding off, so a half-written BAR never claims addresses.
    let command_dword = config.read32(address, REG_COMMAND);
    let decode = u32::from(COMMAND_IO_SPACE | COMMAND_MEMORY_SPACE);
    // The upper half is the status register; writing zeros there clears nothing.
    config.write32(address, REG_COMMAND, command_dword & 0xffff & !decode);
    let mut bars = [BarSlot::Unimplemented; BAR_COUNT];
    let mut index = 0;
    while index < BAR_COUNT {
        let (slot, used) = size_bar(config, address, index, physical_limit, &mut overlaps_memory);
        bars[index] = slot;
        if used == 2 {
            bars[index + 1] = BarSlot::Upper;
        }
        index += used;
    }
    config.write32(address, REG_COMMAND, command_dword & 0xffff);
    Ok(PciFunction { address, ids, bars })
}

/// Sizes BAR `index`; returns its slot and how many BAR registers it used.
fn size_bar<C: ConfigSpace>(
    config: &mut C,
    address: PciAddress,
    index: usize,
    physical_limit: u64,
    overlaps_memory: &mut impl FnMut(u64, u64) -> bool,
) -> (BarSlot, usize) {
    let offset = REG_BAR0 + (index as u8) * 4;
    let original = config.read32(address, offset);
    if original & BAR_IO != 0 {
        return (BarSlot::Io, 1);
    }
    let kind = original & BAR_TYPE_MASK;
    let wide = kind == BAR_TYPE_64;
    if (!wide && kind != BAR_TYPE_32) || (wide && index + 1 >= BAR_COUNT) {
        return (BarSlot::Refused(BarRefusal::Malformed), 1);
    }
    config.write32(address, offset, u32::MAX);
    let low_mask = config.read32(address, offset);
    config.write32(address, offset, original);
    let (base, mask) = if wide {
        let upper_offset = offset + 4;
        let upper = config.read32(address, upper_offset);
        config.write32(address, upper_offset, u32::MAX);
        let high_mask = config.read32(address, upper_offset);
        config.write32(address, upper_offset, upper);
        (
            u64::from(upper) << 32 | u64::from(original & !0xf),
            u64::from(high_mask) << 32 | u64::from(low_mask & !0xf),
        )
    } else {
        (
            u64::from(original & !0xf),
            0xffff_ffff_0000_0000 | u64::from(low_mask & !0xf),
        )
    };
    let used = if wide { 2 } else { 1 };
    if mask & !0xf == 0 || (!wide && low_mask & !0xf == 0) {
        return (BarSlot::Unimplemented, used);
    }
    let size = (!mask).wrapping_add(1);
    let slot = admit(
        base,
        size,
        original & BAR_PREFETCHABLE != 0,
        physical_limit,
        overlaps_memory,
    );
    (slot, used)
}

fn admit(
    base: u64,
    size: u64,
    prefetchable: bool,
    physical_limit: u64,
    overlaps_memory: &mut impl FnMut(u64, u64) -> bool,
) -> BarSlot {
    if size < PAGE || !size.is_multiple_of(PAGE) || !base.is_multiple_of(PAGE) || base == 0 {
        return BarSlot::Refused(BarRefusal::NotPageGranular);
    }
    let Some(end) = base.checked_add(size).filter(|end| *end <= physical_limit) else {
        return BarSlot::Refused(BarRefusal::BeyondPhysicalLimit);
    };
    if overlaps_memory(base, end) {
        return BarSlot::Refused(BarRefusal::OverlapsMemory);
    }
    BarSlot::Admitted(PciBar {
        base,
        size,
        prefetchable,
    })
}

/// The standard configuration space a driver may read (`DW2` §4).
const CONFIG_SPACE_BYTES: u32 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PciAccessError {
    /// A width other than 1, 2 or 4, an unaligned offset, or one past 256.
    InvalidAccess,
    /// Bus mastering was requested but no remapping unit confines the function.
    DmaNotConfined,
}

/// Reads `width` bytes at `offset` of the function's standard config space.
pub(crate) fn config_read<C: ConfigSpace>(
    config: &mut C,
    address: PciAddress,
    offset: u32,
    width: u32,
) -> Result<u32, PciAccessError> {
    if !matches!(width, 1 | 2 | 4)
        || !offset.is_multiple_of(width)
        || offset
            .checked_add(width)
            .is_none_or(|end| end > CONFIG_SPACE_BYTES)
    {
        return Err(PciAccessError::InvalidAccess);
    }
    let dword = config.read32(address, (offset & !3) as u8);
    let shifted = dword >> ((offset & 3) * 8);
    Ok(match width {
        1 => shifted & 0xff,
        2 => shifted & 0xffff,
        _ => shifted,
    })
}

/// Sets the memory-space and bus-master command bits, preserves every other
/// bit, and always clears I/O-space decoding.
///
/// `dma_confined` says whether a remapping unit translates this function's
/// DMA. Without one, bus mastering would let the device reach any physical
/// address, so it is refused; clearing it is always allowed.
pub(crate) fn set_command<C: ConfigSpace>(
    config: &mut C,
    address: PciAddress,
    memory_space: bool,
    bus_master: bool,
    dma_confined: bool,
) -> Result<(), PciAccessError> {
    if bus_master && !dma_confined {
        return Err(PciAccessError::DmaNotConfined);
    }
    let command = config.read32(address, REG_COMMAND) & 0xffff;
    let mut updated =
        command & !u32::from(COMMAND_IO_SPACE | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER);
    if memory_space {
        updated |= u32::from(COMMAND_MEMORY_SPACE);
    }
    if bus_master {
        updated |= u32::from(COMMAND_BUS_MASTER);
    }
    // The upper half is the status register, whose error bits are
    // write-one-to-clear; writing zeros there changes nothing.
    config.write32(address, REG_COMMAND, updated);
    Ok(())
}

/// Set once at boot when every segment-0 function is behind a VT-d unit that
/// translates (an INCLUDE_PCI_ALL unit in default deny).
static DMA_CONFINED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg_attr(test, allow(dead_code, reason = "set by the live boot path only"))]
pub(crate) fn record_dma_confined() {
    DMA_CONFINED.store(true, core::sync::atomic::Ordering::Release);
}

pub(crate) fn dma_confined() -> bool {
    DMA_CONFINED.load(core::sync::atomic::Ordering::Acquire)
}

/// The boot-time probe result for each `PCI_FUNCTION` record, by resource ID.
/// Written once by the BSP before any process exists; read by claims.
pub(crate) struct PciProbeTable {
    entries: crate::sync::SpinMutex<[Option<ProbeEntry>; PROBE_CAPACITY]>,
}

/// A resource ID and what its boot-time probe found.
type ProbeEntry = (u64, Result<PciFunction, PciProbeError>);

const PROBE_CAPACITY: usize = crate::boot::MAX_BOOT_RESOURCE_GRANTS;

impl PciProbeTable {
    pub(crate) const fn new() -> Self {
        Self {
            entries: crate::sync::SpinMutex::new([None; PROBE_CAPACITY]),
        }
    }

    pub(crate) fn record(
        &self,
        resource_id: u64,
        result: Result<PciFunction, PciProbeError>,
    ) -> bool {
        let mut entries = self.entries.lock();
        if entries.iter().flatten().any(|(id, _)| *id == resource_id) {
            return false;
        }
        match entries.iter_mut().find(|entry| entry.is_none()) {
            Some(slot) => {
                *slot = Some((resource_id, result));
                true
            }
            None => false,
        }
    }

    /// The probed function, if the record named a present, matching endpoint.
    pub(crate) fn function(&self, resource_id: u64) -> Option<PciFunction> {
        self.entries
            .lock()
            .iter()
            .flatten()
            .find(|(id, _)| *id == resource_id)
            .and_then(|(_, result)| result.ok())
    }
}

pub(crate) static PCI_FUNCTIONS: PciProbeTable = PciProbeTable::new();

#[cfg(test)]
mod tests;
