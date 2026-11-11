extern crate std;

use super::*;
use std::vec;
use std::vec::Vec;

const IOTLB_OFFSET_UNITS: u64 = 0xf;
const IOTLB: u32 = 0xf * 16 + 8;
const ROOT: u64 = 0x7000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Write {
    W32(u32, u32),
    W64(u32, u64),
    Flush,
}

/// A remapping unit that acknowledges commands the way the specification says.
struct Unit {
    version: u32,
    capability: u64,
    extended: u64,
    status: u32,
    root: u64,
    context: u64,
    iotlb: u64,
    responsive: bool,
    log: Vec<Write>,
}

impl Unit {
    fn q35() -> Self {
        Self {
            version: 0x10,
            capability: CAPABILITY_DRAIN_READ | CAPABILITY_DRAIN_WRITE,
            extended: (IOTLB_OFFSET_UNITS << EXTENDED_IOTLB_OFFSET_SHIFT) | EXTENDED_COHERENT,
            status: 0,
            root: 0,
            context: 0,
            iotlb: 0,
            responsive: true,
            log: vec![],
        }
    }
}

impl VtdRegisters for Unit {
    fn read32(&mut self, offset: u32) -> u32 {
        match offset {
            REG_VERSION => self.version,
            REG_GLOBAL_STATUS => self.status,
            _ => panic!("unexpected 32-bit read at {offset:#x}"),
        }
    }

    fn write32(&mut self, offset: u32, value: u32) {
        self.log.push(Write::W32(offset, value));
        assert_eq!(offset, REG_GLOBAL_COMMAND, "only GCMD is written 32-bit");
        if !self.responsive {
            return;
        }
        if value & GLOBAL_SET_ROOT_TABLE != 0 {
            self.status |= GLOBAL_SET_ROOT_TABLE;
        }
        if value & GLOBAL_TRANSLATION_ENABLE != 0 {
            self.status |= GLOBAL_TRANSLATION_ENABLE;
        }
    }

    fn read64(&mut self, offset: u32) -> u64 {
        match offset {
            REG_CAPABILITY => self.capability,
            REG_EXTENDED_CAPABILITY => self.extended,
            REG_CONTEXT_COMMAND => self.context,
            IOTLB => self.iotlb,
            _ => panic!("unexpected 64-bit read at {offset:#x}"),
        }
    }

    fn write64(&mut self, offset: u32, value: u64) {
        self.log.push(Write::W64(offset, value));
        match offset {
            REG_ROOT_TABLE_ADDRESS => self.root = value,
            // A responsive unit finishes invalidations at once.
            REG_CONTEXT_COMMAND => self.context = if self.responsive { 0 } else { value },
            IOTLB => self.iotlb = if self.responsive { 0 } else { value },
            _ => panic!("unexpected 64-bit write at {offset:#x}"),
        }
    }

    fn flush_cpu_caches(&mut self) {
        self.log.push(Write::Flush);
    }
}

#[test]
fn translation_is_enabled_over_an_empty_root_table_after_both_invalidations() {
    let mut unit = Unit::q35();
    let state = enable_default_deny(&mut unit, ROOT, 39).unwrap();
    assert_eq!(state.version(), 0x10);
    assert_eq!(
        unit.log,
        [
            Write::W64(REG_ROOT_TABLE_ADDRESS, ROOT),
            Write::W32(REG_GLOBAL_COMMAND, GLOBAL_SET_ROOT_TABLE),
            Write::W64(REG_CONTEXT_COMMAND, CONTEXT_INVALIDATE | CONTEXT_GLOBAL),
            Write::W64(
                IOTLB,
                IOTLB_INVALIDATE | IOTLB_GLOBAL | IOTLB_DRAIN_READS | IOTLB_DRAIN_WRITES
            ),
            Write::W32(REG_GLOBAL_COMMAND, GLOBAL_TRANSLATION_ENABLE),
        ]
    );
    assert_ne!(unit.status & GLOBAL_TRANSLATION_ENABLE, 0);
    assert_eq!(unit.root, ROOT);
}

#[test]
fn persistent_status_is_kept_and_one_shot_bits_are_not_replayed() {
    let mut unit = Unit::q35();
    // Queued invalidation enabled (bit 26), a persistent status bit.
    unit.status = 1 << 26;
    enable_default_deny(&mut unit, ROOT, 39).unwrap();
    let commands: Vec<u32> = unit
        .log
        .iter()
        .filter_map(|write| match write {
            Write::W32(REG_GLOBAL_COMMAND, value) => Some(*value),
            _ => None,
        })
        .collect();
    assert_eq!(
        commands,
        [
            GLOBAL_SET_ROOT_TABLE | 1 << 26,
            GLOBAL_TRANSLATION_ENABLE | 1 << 26
        ]
    );
}

#[test]
fn a_unit_that_cannot_snoop_gets_the_cpu_caches_flushed_before_the_root_is_set() {
    let mut unit = Unit::q35();
    unit.extended &= !EXTENDED_COHERENT;
    enable_default_deny(&mut unit, ROOT, 39).unwrap();
    assert_eq!(unit.log[0], Write::Flush);
    assert_eq!(unit.log[1], Write::W64(REG_ROOT_TABLE_ADDRESS, ROOT));
}

#[test]
fn drain_bits_follow_the_capabilities() {
    let mut unit = Unit::q35();
    unit.capability = 0;
    enable_default_deny(&mut unit, ROOT, 39).unwrap();
    assert!(
        unit.log
            .contains(&Write::W64(IOTLB, IOTLB_INVALIDATE | IOTLB_GLOBAL))
    );
}

#[test]
fn firmware_translation_is_refused_without_touching_the_unit() {
    let mut unit = Unit::q35();
    unit.status = GLOBAL_TRANSLATION_ENABLE;
    assert_eq!(
        enable_default_deny(&mut unit, ROOT, 39),
        Err(VtdError::FirmwareTranslationEnabled)
    );
    assert!(unit.log.is_empty());
}

#[test]
fn bad_root_tables_are_refused_without_touching_the_unit() {
    for (root, width) in [(0, 39), (ROOT + 8, 39), (1 << 39, 39), (ROOT, 64)] {
        let mut unit = Unit::q35();
        assert_eq!(
            enable_default_deny(&mut unit, root, width),
            Err(VtdError::InvalidRootTable(root))
        );
        assert!(unit.log.is_empty());
    }
}

#[test]
fn an_iotlb_register_outside_the_mapped_page_is_refused() {
    let mut unit = Unit::q35();
    unit.extended = 0x3ff << EXTENDED_IOTLB_OFFSET_SHIFT;
    assert_eq!(
        enable_default_deny(&mut unit, ROOT, 39),
        Err(VtdError::IotlbOutsideRegisterPage(0x3ff * 16 + 8))
    );
    assert!(unit.log.is_empty());
}

#[test]
fn version_zero_is_refused() {
    let mut unit = Unit::q35();
    unit.version = 0x01;
    assert_eq!(
        enable_default_deny(&mut unit, ROOT, 39),
        Err(VtdError::UnsupportedVersion(0x01))
    );
}

#[test]
fn a_silent_unit_times_out_instead_of_hanging() {
    let mut unit = Unit::q35();
    unit.responsive = false;
    assert_eq!(
        enable_default_deny(&mut unit, ROOT, 39),
        Err(VtdError::Timeout("root-table pointer"))
    );
    assert_eq!(unit.status & GLOBAL_TRANSLATION_ENABLE, 0);
}
