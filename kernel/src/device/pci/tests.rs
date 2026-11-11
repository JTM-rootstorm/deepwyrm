extern crate std;

use super::*;
use std::vec;
use std::vec::Vec;

const VIRTIO_BLK: u32 = 0x1af4 | 0x1042 << 16;
const ADDRESS: u32 = 1 << 3;
/// TCG's default qemu64 CPU reports 40 physical-address bits.
const LIMIT: u64 = 1 << 40;

/// One function whose BARs answer sizing writes the way hardware does.
struct Function {
    ids: u32,
    header: u32,
    command: u32,
    bars: [u32; BAR_COUNT],
    /// What each BAR reads after all ones are written (size mask plus flags).
    masks: [u32; BAR_COUNT],
    /// Command values written while any BAR held all ones.
    decode_during_sizing: Vec<u32>,
}

impl Function {
    /// q35's modern virtio-blk: BAR1 4 KiB at 0x8000_1000, BAR4/5 a 64-bit
    /// 16 KiB prefetchable range at 0xc0_0000_0000.
    fn virtio_blk() -> Self {
        let mut bars = [0; BAR_COUNT];
        let mut masks = [0; BAR_COUNT];
        bars[1] = 0x8000_1000;
        masks[1] = 0xffff_f000;
        bars[4] = 0x0000_000c;
        masks[4] = 0xffff_c00c;
        bars[5] = 0xc0;
        masks[5] = 0xffff_ffff;
        Self {
            ids: VIRTIO_BLK,
            header: 0,
            command: 0x0010_0007,
            bars,
            masks,
            decode_during_sizing: vec![],
        }
    }
}

impl ConfigSpace for Function {
    fn read32(&mut self, address: PciAddress, offset: u8) -> u32 {
        assert_eq!(address, PciAddress::from_boot(ADDRESS).unwrap());
        match offset {
            REG_IDS => self.ids,
            REG_COMMAND => self.command,
            REG_HEADER => self.header,
            0x10..=0x24 => self.bars[usize::from((offset - REG_BAR0) / 4)],
            _ => panic!("unexpected read at {offset:#x}"),
        }
    }

    fn write32(&mut self, _address: PciAddress, offset: u8, value: u32) {
        match offset {
            REG_COMMAND => {
                if self
                    .bars
                    .iter()
                    .zip(&self.masks)
                    .any(|(bar, mask)| *mask != 0 && bar == mask)
                {
                    self.decode_during_sizing.push(value);
                }
                self.command = value;
            }
            0x10..=0x24 => {
                let index = usize::from((offset - REG_BAR0) / 4);
                self.bars[index] = if value == u32::MAX {
                    self.masks[index]
                } else {
                    value
                };
            }
            _ => panic!("unexpected write at {offset:#x}"),
        }
    }
}

fn no_memory(_: u64, _: u64) -> bool {
    false
}

#[test]
fn the_q35_virtio_disk_is_probed_and_its_bars_admitted() {
    let mut function = Function::virtio_blk();
    let before = function.bars;
    let probed = probe(&mut function, ADDRESS, VIRTIO_BLK, LIMIT, no_memory).unwrap();
    assert_eq!(probed.ids(), VIRTIO_BLK);
    assert_eq!(probed.address().device(), 1);
    assert_eq!(probed.bar(0), Some(BarSlot::Unimplemented));
    assert_eq!(
        probed.bar(1),
        Some(BarSlot::Admitted(PciBar {
            base: 0x8000_1000,
            size: 0x1000,
            prefetchable: false
        }))
    );
    assert_eq!(
        probed.bar(4),
        Some(BarSlot::Admitted(PciBar {
            base: 0xc0_0000_0000,
            size: 0x4000,
            prefetchable: true
        }))
    );
    assert_eq!(probed.bar(5), Some(BarSlot::Upper));
    assert_eq!(probed.bar(6), None);
    // Every BAR is left as it was found; the command register keeps only
    // memory decoding (and its other bits), never bus mastering or I/O.
    assert_eq!(function.bars, before);
    assert_eq!(function.command, 0x0010_0007 & 0xffff & !0x5);
}

#[test]
fn decoding_is_off_while_bars_hold_sizing_masks() {
    let mut function = Function::virtio_blk();
    probe(&mut function, ADDRESS, VIRTIO_BLK, LIMIT, no_memory).unwrap();
    assert!(function.decode_during_sizing.is_empty());
    assert_eq!(function.command & 0x3, u32::from(COMMAND_MEMORY_SPACE));
}

/// Review finding D1: firmware leaves functions bus-mastering, and a probe
/// that restored that let a driver DMA without `device_pci_command`'s
/// confinement check, even with no IOMMU or no interrupt remapping.
#[test]
fn probe_hands_every_function_over_with_bus_mastering_off() {
    let mut function = Function::virtio_blk();
    assert_ne!(function.command & u32::from(COMMAND_BUS_MASTER), 0);
    probe(&mut function, ADDRESS, VIRTIO_BLK, LIMIT, no_memory).unwrap();
    assert_eq!(function.command & u32::from(COMMAND_BUS_MASTER), 0);
    assert_eq!(function.command & u32::from(COMMAND_IO_SPACE), 0);
}

#[test]
fn identity_and_presence_are_checked_before_anything_is_written() {
    let mut absent = Function::virtio_blk();
    absent.ids = 0xffff_ffff;
    assert_eq!(
        probe(&mut absent, ADDRESS, VIRTIO_BLK, LIMIT, no_memory),
        Err(PciProbeError::Absent)
    );
    let mut other = Function::virtio_blk();
    other.ids = 0x1af4 | 0x1001 << 16;
    let before = (other.command, other.bars);
    assert_eq!(
        probe(&mut other, ADDRESS, VIRTIO_BLK, LIMIT, no_memory),
        Err(PciProbeError::IdentityMismatch {
            found: 0x1af4 | 0x1001 << 16
        })
    );
    assert_eq!((other.command, other.bars), before);
    let mut bridge = Function::virtio_blk();
    bridge.header = 0x0081_0000;
    assert_eq!(
        probe(&mut bridge, ADDRESS, VIRTIO_BLK, LIMIT, no_memory),
        Err(PciProbeError::NotAnEndpoint { header_type: 1 })
    );
    assert_eq!(
        probe(
            &mut Function::virtio_blk(),
            1 << 16 | ADDRESS,
            VIRTIO_BLK,
            LIMIT,
            no_memory
        ),
        Err(PciProbeError::InvalidAddress)
    );
}

#[test]
fn a_multifunction_endpoint_header_is_accepted() {
    let mut function = Function::virtio_blk();
    function.header = 0x0080_0000;
    assert!(probe(&mut function, ADDRESS, VIRTIO_BLK, LIMIT, no_memory).is_ok());
}

#[test]
fn bars_that_cannot_be_mapped_safely_are_refused() {
    // Smaller than a page.
    let mut small = Function::virtio_blk();
    small.masks[1] = 0xffff_ff80;
    small.bars[1] = 0x8000_1000;
    assert_eq!(
        probe(&mut small, ADDRESS, VIRTIO_BLK, LIMIT, no_memory)
            .unwrap()
            .bar(1),
        Some(BarSlot::Refused(BarRefusal::NotPageGranular))
    );
    // Beyond the CPU's physical limit.
    assert_eq!(
        probe(
            &mut Function::virtio_blk(),
            ADDRESS,
            VIRTIO_BLK,
            1 << 36,
            no_memory
        )
        .unwrap()
        .bar(4),
        Some(BarSlot::Refused(BarRefusal::BeyondPhysicalLimit))
    );
    // Over RAM or another non-MMIO range.
    let probed = probe(
        &mut Function::virtio_blk(),
        ADDRESS,
        VIRTIO_BLK,
        LIMIT,
        |start, end| start < 0x8000_2000 && 0x8000_1000 < end,
    )
    .unwrap();
    assert_eq!(
        probed.bar(1),
        Some(BarSlot::Refused(BarRefusal::OverlapsMemory))
    );
    assert!(matches!(probed.bar(4), Some(BarSlot::Admitted(_))));
    // An unassigned (zero) base.
    let mut unassigned = Function::virtio_blk();
    unassigned.bars[1] = 0;
    assert_eq!(
        probe(&mut unassigned, ADDRESS, VIRTIO_BLK, LIMIT, no_memory)
            .unwrap()
            .bar(1),
        Some(BarSlot::Refused(BarRefusal::NotPageGranular))
    );
}

#[test]
fn io_and_malformed_bars_are_never_admitted() {
    let mut function = Function::virtio_blk();
    function.bars[0] = 0x6001;
    function.masks[0] = 0xffff_ff81;
    function.bars[2] = 0x8000_2006;
    function.masks[2] = 0xffff_f006;
    let probed = probe(&mut function, ADDRESS, VIRTIO_BLK, LIMIT, no_memory).unwrap();
    assert_eq!(probed.bar(0), Some(BarSlot::Io));
    assert_eq!(probed.bar(2), Some(BarSlot::Refused(BarRefusal::Malformed)));
    // A 64-bit BAR in the last slot has no upper half.
    let mut last = Function::virtio_blk();
    last.bars[4] = 0;
    last.masks[4] = 0;
    last.bars[5] = 0x8000_3004;
    last.masks[5] = 0xffff_f004;
    assert_eq!(
        probe(&mut last, ADDRESS, VIRTIO_BLK, LIMIT, no_memory)
            .unwrap()
            .bar(5),
        Some(BarSlot::Refused(BarRefusal::Malformed))
    );
}

/// A flat 256-byte standard config space that records every dword write.
struct FlatSpace {
    bytes: [u8; 256],
    writes: Vec<(u8, u32)>,
}

impl FlatSpace {
    fn new() -> Self {
        let mut bytes = [0; 256];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        Self {
            bytes,
            writes: vec![],
        }
    }

    fn command(&self) -> u32 {
        u32::from_le_bytes(self.bytes[4..8].try_into().unwrap())
    }

    fn set_command_dword(&mut self, value: u32) {
        self.bytes[4..8].copy_from_slice(&value.to_le_bytes());
    }
}

impl ConfigSpace for FlatSpace {
    fn read32(&mut self, _address: PciAddress, offset: u8) -> u32 {
        assert_eq!(offset % 4, 0, "config reads are dword-aligned");
        let at = usize::from(offset);
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap())
    }

    fn write32(&mut self, _address: PciAddress, offset: u8, value: u32) {
        self.writes.push((offset, value));
        let at = usize::from(offset);
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn function_address() -> PciAddress {
    PciAddress::from_boot(ADDRESS).unwrap()
}

#[test]
fn config_reads_return_the_addressed_bytes_at_each_width() {
    let mut space = FlatSpace::new();
    let address = function_address();
    assert_eq!(config_read(&mut space, address, 0x13, 1), Ok(0x13));
    assert_eq!(config_read(&mut space, address, 0x12, 2), Ok(0x1312));
    assert_eq!(config_read(&mut space, address, 0x10, 4), Ok(0x1312_1110));
    assert_eq!(config_read(&mut space, address, 0xfc, 4), Ok(0xfffe_fdfc));
    assert_eq!(config_read(&mut space, address, 0xff, 1), Ok(0xff));
    assert!(space.writes.is_empty());
}

#[test]
fn config_reads_refuse_bad_widths_misalignment_and_extended_space() {
    let mut space = FlatSpace::new();
    let address = function_address();
    for (offset, width) in [
        (0, 0),
        (0, 3),
        (0, 8),
        (1, 2),
        (2, 4),
        (0x100, 1),
        (0x100, 4),
        (u32::MAX, 1),
        (u32::MAX - 3, 4),
    ] {
        assert_eq!(
            config_read(&mut space, address, offset, width),
            Err(PciAccessError::InvalidAccess),
            "offset {offset:#x} width {width}"
        );
    }
}

#[test]
fn the_command_filter_sets_only_memory_and_bus_master_and_clears_io() {
    let address = function_address();
    // Status 0xffff (every RW1C bit set) over command INTx-disable | SERR |
    // parity | I/O space.
    let original = 0xffff_0000 | 0x0400 | 0x0100 | 0x0040 | 0x0001;
    for (memory, bus_master) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut space = FlatSpace::new();
        space.set_command_dword(original);
        set_command(&mut space, address, memory, bus_master, true).unwrap();
        let mut expected = 0x0400 | 0x0100 | 0x0040;
        if memory {
            expected |= u32::from(COMMAND_MEMORY_SPACE);
        }
        if bus_master {
            expected |= u32::from(COMMAND_BUS_MASTER);
        }
        // One write, to the command register only, with zeros in the status half.
        assert_eq!(space.writes, vec![(REG_COMMAND, expected)]);
        assert_eq!(space.command(), expected);
    }
}

#[test]
fn bus_mastering_is_refused_without_dma_remapping_but_can_be_cleared() {
    let address = function_address();
    let mut space = FlatSpace::new();
    space.set_command_dword(0x0007);
    assert_eq!(
        set_command(&mut space, address, true, true, false),
        Err(PciAccessError::DmaNotConfined)
    );
    assert!(space.writes.is_empty());
    set_command(&mut space, address, true, false, false).unwrap();
    assert_eq!(space.command(), u32::from(COMMAND_MEMORY_SPACE));
}

fn probed_virtio_blk() -> PciFunction {
    let mut function = Function::virtio_blk();
    probe(&mut function, ADDRESS, VIRTIO_BLK, LIMIT, |_, _| false).unwrap()
}

#[test]
fn an_admitted_bar_backing_is_lent_once_and_taken_back() {
    let table = PciProbeTable::new();
    assert!(table.record(7, Ok(probed_virtio_blk())));
    let grant = crate::memory::frame_roles::synthetic_device_mmio_backing(0xc0_0000_0000, 4);
    table.install_bar_backing(7, 4, grant).unwrap();

    let lent = table.take_bar_backing(7, 4).unwrap();
    assert_eq!(lent.physical_start(), 0xc0_0000_0000);
    assert_eq!(table.take_bar_backing(7, 4), Err(BarBackingError::InUse));
    table.return_bar_backing(lent);
    let again = table.take_bar_backing(7, 4).unwrap();
    assert_eq!(again.byte_len(), 0x4000);
}

#[test]
fn only_admitted_memory_bars_of_recorded_functions_have_backing() {
    let table = PciProbeTable::new();
    assert!(table.record(7, Ok(probed_virtio_blk())));
    assert!(table.record(8, Err(PciProbeError::Absent)));
    // BAR1 is admitted but was given no backing; BAR5 is BAR4's upper half;
    // there is no BAR 6; resource 9 was never recorded.
    for (resource, bar) in [(7, 1), (7, 5), (7, 6), (7, u32::MAX), (8, 4), (9, 4)] {
        assert_eq!(
            table.take_bar_backing(resource, bar),
            Err(BarBackingError::NotFound),
            "resource {resource} BAR {bar}"
        );
    }
}

#[test]
fn a_backing_must_match_its_admitted_bar_exactly_and_only_once() {
    let table = PciProbeTable::new();
    assert!(table.record(7, Ok(probed_virtio_blk())));
    assert!(table.record(8, Err(PciProbeError::Absent)));
    let synthetic = crate::memory::frame_roles::synthetic_device_mmio_backing;
    // Wrong base, wrong size, a non-memory slot, and a failed probe.
    assert!(
        table
            .install_bar_backing(7, 4, synthetic(0xc0_0000_1000, 4))
            .is_err()
    );
    assert!(
        table
            .install_bar_backing(7, 4, synthetic(0xc0_0000_0000, 2))
            .is_err()
    );
    assert!(
        table
            .install_bar_backing(7, 5, synthetic(0xc0_0000_0000, 4))
            .is_err()
    );
    assert!(
        table
            .install_bar_backing(8, 4, synthetic(0xc0_0000_0000, 4))
            .is_err()
    );
    table
        .install_bar_backing(7, 4, synthetic(0xc0_0000_0000, 4))
        .unwrap();
    assert!(
        table
            .install_bar_backing(7, 4, synthetic(0xc0_0000_0000, 4))
            .is_err()
    );
}
