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
            if value & GLOBAL_WRITE_BUFFER_FLUSH != 0 {
                self.status |= GLOBAL_WRITE_BUFFER_FLUSH;
            }
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

#[test]
fn features_decode_levels_width_domains_and_cache_rules() {
    let mut unit = Unit::q35();
    // SAGAW 3- and 4-level, MGAW 38 (39 bits), ND 2, caching mode, RWBF.
    unit.capability |= (0b0110 << CAPABILITY_SAGAW_SHIFT)
        | (38 << CAPABILITY_MGAW_SHIFT)
        | 2
        | CAPABILITY_CACHING_MODE
        | CAPABILITY_REQUIRED_WRITE_BUFFER_FLUSH;
    let features = enable_default_deny(&mut unit, ROOT, 39).unwrap().features();
    assert!(features.four_level());
    assert_eq!(features.input_bits(), 39);
    assert_eq!(features.domains(), 256);
    assert!(features.caching_mode());

    // 3-level only, and the reserved domain-count encoding.
    let mut unit = Unit::q35();
    unit.capability |= (0b0010 << CAPABILITY_SAGAW_SHIFT) | 7;
    let features = enable_default_deny(&mut unit, ROOT, 39).unwrap().features();
    assert!(!features.four_level());
    assert_eq!(features.domains(), 0);
    assert!(!features.caching_mode());
}

#[test]
fn a_domain_iotlb_invalidation_names_the_domain_and_drains() {
    let mut unit = Unit::q35();
    let features = enable_default_deny(&mut unit, ROOT, 39).unwrap().features();
    unit.log.clear();
    // A unit without queued invalidation takes both through its registers.
    let mut invalidator = Invalidator::Registers;
    let mut memory = Shared::default();
    invalidator
        .domain_iotlb(&mut unit, &mut memory, features, 5)
        .unwrap();
    invalidator.context_cache(&mut unit, &mut memory).unwrap();
    assert_eq!(
        unit.log,
        [
            Write::W64(
                IOTLB,
                IOTLB_INVALIDATE
                    | IOTLB_DOMAIN
                    | (5 << IOTLB_DOMAIN_ID_SHIFT)
                    | IOTLB_DRAIN_READS
                    | IOTLB_DRAIN_WRITES
            ),
            Write::W64(REG_CONTEXT_COMMAND, CONTEXT_INVALIDATE | CONTEXT_GLOBAL),
        ]
    );

    unit.responsive = false;
    assert_eq!(
        invalidate_domain_iotlb(&mut unit, features, 5),
        Err(VtdError::Timeout("IOTLB invalidation"))
    );
}

#[test]
fn the_write_buffer_is_flushed_only_when_the_unit_requires_it() {
    let mut unit = Unit::q35();
    let features = enable_default_deny(&mut unit, ROOT, 39).unwrap().features();
    unit.log.clear();
    flush_write_buffer(&mut unit, features).unwrap();
    assert!(unit.log.is_empty());

    let mut unit = Unit::q35();
    unit.capability |= CAPABILITY_REQUIRED_WRITE_BUFFER_FLUSH;
    let features = enable_default_deny(&mut unit, ROOT, 39).unwrap().features();
    unit.log.clear();
    flush_write_buffer(&mut unit, features).unwrap();
    // Translation stays on: the persistent status bit is carried.
    assert_eq!(
        unit.log,
        [Write::W32(
            REG_GLOBAL_COMMAND,
            GLOBAL_TRANSLATION_ENABLE | GLOBAL_WRITE_BUFFER_FLUSH
        )]
    );
    unit.responsive = false;
    assert_eq!(
        flush_write_buffer(&mut unit, features),
        Err(VtdError::Timeout("write-buffer flush"))
    );
}

/// Memory the unit and the kernel share: the invalidation queue and the
/// interrupt-remapping table, as 8-byte entries of 4 KiB frames.
#[derive(Clone, Default)]
struct Shared(std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<(u64, usize), u64>>>);

impl tables::TableMemory for Shared {
    fn allocate(&mut self) -> Option<u64> {
        unreachable!("the frames are chosen by the test")
    }
    fn free(&mut self, _table: u64) {
        unreachable!("interrupt-remapping frames are never freed")
    }
    fn read(&self, table: u64, index: usize) -> u64 {
        self.0.borrow().get(&(table, index)).copied().unwrap_or(0)
    }
    fn write(&mut self, table: u64, index: usize, value: u64) {
        self.0.borrow_mut().insert((table, index), value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Command(u32),
    TablePointerLatched(u64),
    InterruptCacheInvalidated,
    /// The low quadword of a context-cache or IOTLB descriptor.
    ContextInvalidated(u64),
    IotlbInvalidated(u64),
    StatusWritten,
}

/// A unit with queued invalidation and interrupt remapping that processes
/// descriptors when the tail moves, the way the specification describes.
struct IrUnit {
    status: u32,
    queue: u64,
    tail: u64,
    head: u64,
    table: u64,
    fault: u32,
    reject_descriptors: bool,
    memory: Shared,
    events: Vec<Event>,
}

const QUEUE: u64 = 0x9000;
const IR_TABLE: u64 = 0xa000;
const STATUS: u64 = 0xb000;
const STATUS_INDEX: usize = 3;

impl IrUnit {
    fn new(memory: Shared) -> Self {
        Self {
            status: GLOBAL_TRANSLATION_ENABLE,
            queue: 0,
            tail: 0,
            head: 0,
            table: 0,
            fault: 0,
            reject_descriptors: false,
            memory,
            events: vec![],
        }
    }

    fn process(&mut self) {
        use tables::TableMemory;
        while self.head != self.tail {
            let slot = (self.head / 16) as usize;
            let low = self.memory.read(self.queue, slot * 2);
            let high = self.memory.read(self.queue, slot * 2 + 1);
            if self.reject_descriptors {
                self.fault |= FAULT_QUEUE_ERROR;
                return;
            }
            match low & 0xf {
                DESCRIPTOR_INTERRUPT_ENTRY_CACHE => {
                    assert_ne!(self.status & GLOBAL_SET_INTERRUPT_TABLE, 0);
                    self.events.push(Event::InterruptCacheInvalidated);
                }
                DESCRIPTOR_CONTEXT_CACHE => {
                    assert_eq!(high, 0);
                    self.events.push(Event::ContextInvalidated(low));
                }
                DESCRIPTOR_IOTLB => {
                    assert_eq!(high, 0, "domain-selective: no address");
                    self.events.push(Event::IotlbInvalidated(low));
                }
                DESCRIPTOR_WAIT => {
                    assert_ne!(low & WAIT_STATUS_WRITE, 0);
                    assert_eq!(high & 3, 0, "status address is dword-aligned");
                    let frame = high & !0xfff;
                    let index = ((high & 0xfff) / 8) as usize;
                    let old = self.memory.read(frame, index);
                    self.memory
                        .write(frame, index, (old & !0xffff_ffff) | (low >> 32));
                    self.events.push(Event::StatusWritten);
                }
                other => panic!("unexpected descriptor type {other}"),
            }
            self.head = (self.head + 16) % 4096;
        }
    }
}

impl VtdRegisters for IrUnit {
    fn read32(&mut self, offset: u32) -> u32 {
        match offset {
            REG_GLOBAL_STATUS => self.status,
            REG_FAULT_STATUS => self.fault,
            _ => panic!("unexpected 32-bit read at {offset:#x}"),
        }
    }

    fn write32(&mut self, offset: u32, value: u32) {
        assert_eq!(offset, REG_GLOBAL_COMMAND);
        self.events.push(Event::Command(value));
        assert_eq!(
            value & GLOBAL_COMPATIBILITY_INTERRUPTS,
            0,
            "CFI is never set"
        );
        assert_ne!(value & GLOBAL_TRANSLATION_ENABLE, 0, "translation stays on");
        let enable_queue = value & GLOBAL_QUEUED_INVALIDATION != 0;
        if !enable_queue && self.status & GLOBAL_QUEUED_INVALIDATION != 0 {
            assert_eq!(
                self.head, self.tail,
                "the queue is disabled only when empty"
            );
        }
        self.status = (self.status & !GLOBAL_QUEUED_INVALIDATION)
            | if enable_queue {
                GLOBAL_QUEUED_INVALIDATION
            } else {
                0
            };
        if enable_queue && value & GLOBAL_SET_INTERRUPT_TABLE != 0 {
            self.events.push(Event::TablePointerLatched(self.table));
            self.status |= GLOBAL_SET_INTERRUPT_TABLE;
        }
        if value & GLOBAL_INTERRUPT_REMAPPING != 0 {
            self.status |= GLOBAL_INTERRUPT_REMAPPING;
        }
    }

    fn read64(&mut self, offset: u32) -> u64 {
        panic!("unexpected 64-bit read at {offset:#x}")
    }

    fn write64(&mut self, offset: u32, value: u64) {
        match offset {
            REG_QUEUE_ADDRESS => {
                assert_eq!(self.status & GLOBAL_QUEUED_INVALIDATION, 0);
                self.queue = value;
                self.head = 0;
            }
            REG_QUEUE_TAIL => {
                self.tail = value;
                if self.status & GLOBAL_QUEUED_INVALIDATION != 0 {
                    self.process();
                }
            }
            REG_INTERRUPT_TABLE_ADDRESS => self.table = value,
            _ => panic!("unexpected 64-bit write at {offset:#x}"),
        }
    }

    fn flush_cpu_caches(&mut self) {}
}

fn queued(unit: &mut IrUnit, kernel: &mut Shared) -> InvalidationQueue {
    enable_queued_invalidation(unit, kernel, QUEUE, STATUS, STATUS_INDEX).unwrap()
}

#[test]
fn interrupt_remapping_invalidates_the_entry_cache_and_keeps_the_queue_on() {
    let memory = Shared::default();
    let mut unit = IrUnit::new(memory.clone());
    let mut kernel = memory.clone();
    let mut queue = queued(&mut unit, &mut kernel);
    enable_interrupt_remapping(&mut unit, &mut kernel, &mut queue, IR_TABLE).unwrap();
    assert_eq!(unit.queue, QUEUE);
    assert_eq!(unit.table, IR_TABLE | 7);
    // Remapping is on, the queue stays on, and compatibility format is
    // blocked; translation stayed on throughout.
    assert_eq!(
        unit.status,
        GLOBAL_TRANSLATION_ENABLE
            | GLOBAL_QUEUED_INVALIDATION
            | GLOBAL_SET_INTERRUPT_TABLE
            | GLOBAL_INTERRUPT_REMAPPING
    );
    let base = GLOBAL_TRANSLATION_ENABLE | GLOBAL_QUEUED_INVALIDATION;
    assert_eq!(
        unit.events,
        [
            Event::Command(base),
            Event::Command(base | GLOBAL_SET_INTERRUPT_TABLE),
            Event::TablePointerLatched(IR_TABLE | 7),
            Event::InterruptCacheInvalidated,
            Event::StatusWritten,
            Event::Command(base | GLOBAL_INTERRUPT_REMAPPING),
        ]
    );
    // The wait wrote its own unit's status slot, not the queue page.
    use tables::TableMemory;
    assert_eq!(kernel.read(STATUS, STATUS_INDEX), WAIT_STATUS_DONE);
}

#[test]
fn inherited_interrupt_state_is_refused_without_touching_the_unit() {
    for inherited in [
        GLOBAL_QUEUED_INVALIDATION,
        GLOBAL_INTERRUPT_REMAPPING,
        GLOBAL_COMPATIBILITY_INTERRUPTS,
    ] {
        let memory = Shared::default();
        let mut unit = IrUnit::new(memory.clone());
        unit.status |= inherited;
        let mut kernel = memory.clone();
        assert_eq!(
            enable_queued_invalidation(&mut unit, &mut kernel, QUEUE, STATUS, STATUS_INDEX),
            Err(VtdError::FirmwareInterruptState(inherited))
        );
        assert!(unit.events.is_empty());
        assert_eq!(unit.queue, 0);
    }
}

#[test]
fn a_rejected_descriptor_fails_before_remapping_is_enabled() {
    let memory = Shared::default();
    let mut unit = IrUnit::new(memory.clone());
    let mut kernel = memory.clone();
    let mut queue = queued(&mut unit, &mut kernel);
    unit.reject_descriptors = true;
    assert_eq!(
        enable_interrupt_remapping(&mut unit, &mut kernel, &mut queue, IR_TABLE),
        Err(VtdError::QueueError)
    );
    assert_eq!(unit.status & GLOBAL_INTERRUPT_REMAPPING, 0);
}

#[test]
fn with_the_queue_on_dma_invalidations_go_through_it_and_never_the_registers() {
    let memory = Shared::default();
    let mut unit = IrUnit::new(memory.clone());
    let mut kernel = memory.clone();
    let mut queue = queued(&mut unit, &mut kernel);
    enable_interrupt_remapping(&mut unit, &mut kernel, &mut queue, IR_TABLE).unwrap();
    unit.events.clear();
    let features = UnitFeatures::read(
        CAPABILITY_DRAIN_READ | CAPABILITY_DRAIN_WRITE,
        IOTLB_OFFSET_UNITS << EXTENDED_IOTLB_OFFSET_SHIFT,
    )
    .unwrap();
    let mut invalidator = Invalidator::Queue(queue);
    // The model panics on any context-command or IOTLB register access.
    invalidator.context_cache(&mut unit, &mut kernel).unwrap();
    invalidator
        .domain_iotlb(&mut unit, &mut kernel, features, 0x1234)
        .unwrap();
    assert_eq!(
        unit.events,
        [
            Event::ContextInvalidated(0x1 | 1 << 4),
            Event::StatusWritten,
            // Domain-selective, drain writes and reads, DID in bits 31:16.
            Event::IotlbInvalidated(0x2 | 2 << 4 | 1 << 6 | 1 << 7 | 0x1234 << 16),
            Event::StatusWritten,
        ]
    );

    // Without drain support the drain bits stay clear.
    let plain = UnitFeatures::read(0, IOTLB_OFFSET_UNITS << EXTENDED_IOTLB_OFFSET_SHIFT).unwrap();
    assert_eq!(
        domain_iotlb_descriptor(plain, 7),
        (0x2 | 2 << 4 | 7 << 16, 0)
    );
}

#[test]
fn the_queue_wraps_and_each_submission_waits_for_its_own_status() {
    let memory = Shared::default();
    let mut unit = IrUnit::new(memory.clone());
    let mut kernel = memory.clone();
    let mut queue = queued(&mut unit, &mut kernel);
    // Each submission is two descriptors; 300 of them wrap the 256-slot
    // queue more than twice.
    for _ in 0..300 {
        queue
            .submit(&mut unit, &mut kernel, context_cache_descriptor())
            .unwrap();
        assert_eq!(unit.head, unit.tail, "the unit finished every descriptor");
    }
    let invalidations = unit
        .events
        .iter()
        .filter(|event| matches!(event, Event::ContextInvalidated(_)))
        .count();
    assert_eq!(invalidations, 300);
    assert_eq!(unit.tail, (600 % 256) * 16);
}

#[test]
fn a_unit_that_never_writes_the_status_times_out() {
    let memory = Shared::default();
    let mut unit = IrUnit::new(memory.clone());
    let mut kernel = memory.clone();
    let mut queue = queued(&mut unit, &mut kernel);
    // Turning the queue off behind the kernel's back means the tail write is
    // never processed.
    unit.status &= !GLOBAL_QUEUED_INVALIDATION;
    assert_eq!(
        queue.submit(&mut unit, &mut kernel, context_cache_descriptor()),
        Err(VtdError::Timeout("queued invalidation"))
    );
}

#[test]
fn an_ioapic_entry_is_fixed_physical_and_verifies_the_whole_requester_id() {
    let (low, high) = ioapic_interrupt_entry(0x30, 2, false, 0xff00);
    // Present, vector 0x30, xAPIC destination 2 in bits 47:40; edge, fixed,
    // physical, remapped (not posted), faults recorded.
    assert_eq!(low, 1 | 0x30 << 16 | 2 << 40);
    // SID 0xff00, SQ 0, SVT 01b.
    assert_eq!(high, 0xff00 | 1 << 18);
    let (level, _) = ioapic_interrupt_entry(0x41, 0, true, 0);
    assert_eq!(level, 1 | 1 << 4 | 0x41 << 16);

    // The present low half is written last.
    #[derive(Default)]
    struct Log(Vec<(usize, u64)>);
    impl tables::TableMemory for Log {
        fn allocate(&mut self) -> Option<u64> {
            None
        }
        fn free(&mut self, _: u64) {}
        fn read(&self, _: u64, _: usize) -> u64 {
            0
        }
        fn write(&mut self, _: u64, index: usize, value: u64) {
            self.0.push((index, value));
        }
    }
    let mut log = Log::default();
    install_interrupt_entry(&mut log, IR_TABLE, 3, (low, high));
    assert_eq!(log.0, [(7, high), (6, low)]);
}

#[test]
fn interrupt_remapping_needs_both_remapping_and_queued_invalidation() {
    for (extended, expected) in [
        (
            EXTENDED_INTERRUPT_REMAPPING | EXTENDED_QUEUED_INVALIDATION,
            true,
        ),
        (EXTENDED_INTERRUPT_REMAPPING, false),
        (EXTENDED_QUEUED_INVALIDATION, false),
    ] {
        let mut unit = Unit::q35();
        unit.extended |= extended;
        let features = enable_default_deny(&mut unit, ROOT, 39).unwrap().features();
        assert_eq!(features.interrupt_remapping(), expected);
    }
}

/// A register page that is not a VT-d unit the kernel can drive (all ones:
/// nothing decodes it; all zeros; any other value failing the version or
/// feature checks) makes the whole set of units fail the probe, judged by
/// reads alone with nothing written to any unit (reviews N6, N7).
#[test]
fn a_page_that_is_not_a_usable_unit_fails_the_probe_without_writes() {
    let mut good = [Unit::q35(), Unit::q35()];
    assert!(every_unit_probes(good.iter_mut()));
    let unusable: [fn(&mut Unit); 6] = [
        |unit| unit.version = u32::MAX,
        |unit| unit.capability = u64::MAX,
        |unit| unit.extended = u64::MAX,
        |unit| {
            unit.version = 0;
            unit.capability = 0;
            unit.extended = 0;
        },
        |unit| unit.version = 0x0f,
        // An IOTLB register beyond the mapped page.
        |unit| unit.extended = 0x3ff << EXTENDED_IOTLB_OFFSET_SHIFT,
    ];
    for (case, corrupt) in unusable.iter().enumerate() {
        // The bad unit is second: the first, good one is probed too, and
        // neither is written.
        let mut units = [Unit::q35(), Unit::q35()];
        corrupt(&mut units[1]);
        assert!(!every_unit_probes(units.iter_mut()), "case {case}");
        assert!(probe_unit(&mut units[1]).is_err(), "case {case}");
        assert!(units.iter().all(|unit| unit.log.is_empty()), "case {case}");
        // enable_default_deny refuses it the same way before any write.
        assert!(
            enable_default_deny(&mut units[1], ROOT, 39).is_err(),
            "case {case}"
        );
        assert!(units[1].log.is_empty(), "case {case}");
    }
}
