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
    // Every BAR and the command register are left as they were found.
    assert_eq!(function.bars, before);
    assert_eq!(function.command, 0x0010_0007 & 0xffff);
}

#[test]
fn decoding_is_off_while_bars_hold_sizing_masks() {
    let mut function = Function::virtio_blk();
    probe(&mut function, ADDRESS, VIRTIO_BLK, LIMIT, no_memory).unwrap();
    assert!(function.decode_during_sizing.is_empty());
    assert_eq!(function.command & 0x3, 0x3);
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
