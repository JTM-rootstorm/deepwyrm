extern crate std;

use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use super::*;
use crate::arch::x86_64::vtd::tables::{TABLE_ENTRIES, install_root_entry, translate};
use crate::object::ObjectRegistry;
use deepwyrm_abi::{DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_MEMORY_OBJECT};

const CONTEXT: u64 = 0x10_0000;
const PAGE: u64 = 4096;
const RW: DeviceAccess = DeviceAccess {
    read: true,
    write: true,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    ContextWrite { devfn: u8, low: bool, value: u64 },
    LeafCleared,
    Free(u64),
    AfterInstall(u16),
    InvalidateDomain(u16),
    InvalidateContext,
}

/// Table frames in host memory, plus every write and invalidation in order.
struct Model {
    tables: BTreeMap<u64, Vec<u64>>,
    free: Vec<u64>,
    iova_end: u64,
    max_domain_id: u16,
    log: Vec<Event>,
}

impl Model {
    fn new(frames: u64) -> Self {
        let mut tables = BTreeMap::new();
        tables.insert(CONTEXT, vec![0; TABLE_ENTRIES]);
        Self {
            tables,
            free: (0..frames)
                .map(|frame| 0x20_0000 + frame * PAGE)
                .rev()
                .collect(),
            iova_end: 1 << 39,
            max_domain_id: 15,
            log: vec![],
        }
    }

    fn allocated(&self) -> usize {
        self.tables.len() - 1
    }

    fn context_present(&self, devfn: u8) -> bool {
        context_entry_present(self, CONTEXT, devfn)
    }

    fn context_domain(&self, devfn: u8) -> u16 {
        (self.tables[&CONTEXT][usize::from(devfn) * 2 + 1] >> 8) as u16
    }

    fn root_of(&self, devfn: u8) -> u64 {
        self.tables[&CONTEXT][usize::from(devfn) * 2] & !0xfff
    }
}

impl TableMemory for Model {
    fn allocate(&mut self) -> Option<u64> {
        let frame = self.free.pop()?;
        self.tables.insert(frame, vec![0; TABLE_ENTRIES]);
        Some(frame)
    }

    fn free(&mut self, table: u64) {
        let entries = self.tables.remove(&table).expect("freed table exists");
        assert!(
            entries.iter().all(|&entry| entry == 0),
            "freed table is empty"
        );
        self.log.push(Event::Free(table));
        self.free.push(table);
    }

    fn read(&self, table: u64, index: usize) -> u64 {
        self.tables[&table][index]
    }

    fn write(&mut self, table: u64, index: usize, value: u64) {
        if table == CONTEXT {
            self.log.push(Event::ContextWrite {
                devfn: (index / 2) as u8,
                low: index.is_multiple_of(2),
                value,
            });
        } else if value == 0 && self.tables[&table][index] != 0 {
            self.log.push(Event::LeafCleared);
        }
        self.tables.get_mut(&table).expect("written table exists")[index] = value;
    }
}

impl DmaHardware for Model {
    fn context_table(&self) -> u64 {
        CONTEXT
    }
    fn iova_end(&self) -> u64 {
        self.iova_end
    }
    fn max_domain_id(&self) -> u16 {
        self.max_domain_id
    }
    fn after_install(&mut self, domain_id: u16) {
        self.log.push(Event::AfterInstall(domain_id));
    }
    fn invalidate_domain(&mut self, domain_id: u16) {
        self.log.push(Event::InvalidateDomain(domain_id));
    }
    fn invalidate_context(&mut self) {
        self.log.push(Event::InvalidateContext);
    }
}

struct Fixture {
    registry: ObjectRegistry<16>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            registry: ObjectRegistry::new(),
        }
    }

    fn object(&mut self, object_type: deepwyrm_abi::DwObjectType) -> InternalRef {
        let creation = self.registry.create(object_type).unwrap();
        self.registry.creation_into_internal(creation).unwrap()
    }

    fn resource(&mut self) -> ObjectId {
        self.object(DW_OBJECT_TYPE_DEVICE_RESOURCE).id()
    }

    fn pin(&mut self) -> InternalRef {
        self.object(DW_OBJECT_TYPE_MEMORY_OBJECT)
    }
}

type Domains = DmaDomains<4, 8>;

#[test]
fn first_map_builds_a_domain_and_starts_at_one_mebibyte() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(16);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    let pin = fixture.pin();

    let iova = domains
        .map(&mut model, resource, 0x08, 0x4000_0000, 3, RW, pin)
        .unwrap();
    assert_eq!(iova, IOVA_BASE);
    assert!(model.context_present(0x08));
    assert_eq!(model.context_domain(0x08), 1);
    let root = model.root_of(0x08);
    for page in 0..3 {
        assert_eq!(
            translate(&model, root, iova + page * PAGE),
            Some((0x4000_0000 + page * PAGE, RW))
        );
    }
    assert_eq!(translate(&model, root, iova + 3 * PAGE), None);
    // The context entry's high word is written before its present bit.
    let context: Vec<_> = model
        .log
        .iter()
        .filter(|event| matches!(event, Event::ContextWrite { .. }))
        .collect();
    assert!(matches!(context[0], Event::ContextWrite { low: false, .. }));
    assert!(matches!(context[1], Event::ContextWrite { low: true, .. }));
    assert_eq!(
        model.log[model.log.len() - 2..],
        [Event::InvalidateContext, Event::AfterInstall(1)]
    );
    // PML4, PDPT, PD and one PT.
    assert_eq!(model.allocated(), 4);
}

#[test]
fn read_only_and_write_only_leaves_carry_exactly_the_requested_access() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(16);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    let read = DeviceAccess {
        read: true,
        write: false,
    };
    let write = DeviceAccess {
        read: false,
        write: true,
    };
    let a = domains
        .map(&mut model, resource, 1, 0x5000, 1, read, fixture.pin())
        .unwrap();
    let b = domains
        .map(&mut model, resource, 1, 0x6000, 1, write, fixture.pin())
        .unwrap();
    let root = model.root_of(1);
    assert_eq!(translate(&model, root, a), Some((0x5000, read)));
    assert_eq!(translate(&model, root, b), Some((0x6000, write)));
}

#[test]
fn iovas_are_first_fit_and_a_freed_range_is_reused_only_after_unmap() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(16);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    let a = domains
        .map(&mut model, resource, 2, 0x10_0000, 2, RW, fixture.pin())
        .unwrap();
    let b = domains
        .map(&mut model, resource, 2, 0x20_0000, 1, RW, fixture.pin())
        .unwrap();
    let c = domains
        .map(&mut model, resource, 2, 0x30_0000, 1, RW, fixture.pin())
        .unwrap();
    assert_eq!(
        (a, b, c),
        (IOVA_BASE, IOVA_BASE + 2 * PAGE, IOVA_BASE + 3 * PAGE)
    );

    // Too long for the hole a leaves; goes after c.
    let pin = domains.unmap(&mut model, resource, a, 2).unwrap();
    let d = domains
        .map(&mut model, resource, 2, 0x40_0000, 3, RW, pin)
        .unwrap();
    assert_eq!(d, IOVA_BASE + 4 * PAGE);
    // Fits the hole exactly.
    let e = domains
        .map(&mut model, resource, 2, 0x50_0000, 2, RW, fixture.pin())
        .unwrap();
    assert_eq!(e, IOVA_BASE);
}

#[test]
fn unmap_needs_the_exact_mapping_and_invalidates_before_returning_the_pin() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(16);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    let pin = fixture.pin();
    let pin_id = pin.id();
    let iova = domains
        .map(&mut model, resource, 3, 0x7000_0000, 2, RW, pin)
        .unwrap();

    for (iova, pages) in [(iova, 1), (iova + PAGE, 1), (iova, 3), (iova + PAGE, 2)] {
        assert_eq!(
            domains.unmap(&mut model, resource, iova, pages).err(),
            Some(DmaError::NotFound)
        );
    }
    let other = fixture.resource();
    assert_eq!(
        domains.unmap(&mut model, other, iova, 2).err(),
        Some(DmaError::NotFound)
    );

    model.log.clear();
    let returned = domains.unmap(&mut model, resource, iova, 2).unwrap();
    assert_eq!(returned.id(), pin_id);
    assert_eq!(
        model.log,
        [
            Event::LeafCleared,
            Event::LeafCleared,
            Event::InvalidateDomain(1)
        ]
    );
    assert_eq!(translate(&model, model.root_of(3), iova), None);
    // The domain and its context entry stay until teardown.
    assert!(model.context_present(3));
}

#[test]
fn running_out_of_tables_rolls_back_every_leaf_and_an_unpublished_domain() {
    let mut fixture = Fixture::new();
    // PML4, PDPT, PD, and one PT: a range crossing a 2 MiB boundary needs a
    // second PT that is not there.
    let mut model = Model::new(4);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    let pin = fixture.pin();
    let pin_id = pin.id();
    let pages = 512;
    let (error, returned) = domains
        .map(&mut model, resource, 4, 0x8000_0000, pages, RW, pin)
        .unwrap_err();
    assert_eq!(error, DmaError::NoResources);
    assert_eq!(returned.id(), pin_id);
    assert!(!model.context_present(4));
    assert_eq!(model.allocated(), 0);
    assert_eq!(domains.live_domains(), 0);
    assert!(
        !model
            .log
            .iter()
            .any(|event| matches!(event, Event::AfterInstall(_) | Event::InvalidateContext))
    );
}

#[test]
fn a_failed_map_into_a_live_domain_clears_its_leaves_and_invalidates() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(4);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    domains
        .map(&mut model, resource, 5, 0x9000_0000, 1, RW, fixture.pin())
        .unwrap();
    model.log.clear();
    let (error, _pin) = domains
        .map(&mut model, resource, 5, 0xa000_0000, 512, RW, fixture.pin())
        .unwrap_err();
    assert_eq!(error, DmaError::NoResources);
    assert_eq!(model.log.last(), Some(&Event::InvalidateDomain(1)));
    let root = model.root_of(5);
    // The first mapping survives; nothing of the failed one does.
    assert!(translate(&model, root, IOVA_BASE).is_some());
    for page in 1..512 {
        assert_eq!(translate(&model, root, IOVA_BASE + page * PAGE), None);
    }
}

#[test]
fn teardown_clears_the_context_then_invalidates_then_frees_then_returns_pins() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(16);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    let first = fixture.pin();
    let second = fixture.pin();
    let ids = [first.id(), second.id()];
    domains
        .map(&mut model, resource, 6, 0xb000_0000, 1, RW, first)
        .unwrap();
    domains
        .map(&mut model, resource, 6, 0xc000_0000, 600, RW, second)
        .unwrap();
    model.log.clear();

    let pins: Vec<_> = domains
        .teardown(&mut model, resource)
        .into_pins()
        .map(|pin| pin.id())
        .collect();
    assert_eq!(pins, ids);
    assert!(!model.context_present(6));
    assert_eq!(model.allocated(), 0);
    assert_eq!(domains.live_domains(), 0);

    // The present half of the context entry goes first; nothing is freed
    // before both invalidations.
    assert_eq!(
        model.log[0],
        Event::ContextWrite {
            devfn: 6,
            low: true,
            value: 0
        }
    );
    let invalidated = model
        .log
        .iter()
        .position(|event| *event == Event::InvalidateDomain(1))
        .unwrap();
    let context_invalidated = model
        .log
        .iter()
        .position(|event| *event == Event::InvalidateContext)
        .unwrap();
    let first_free = model
        .log
        .iter()
        .position(|event| matches!(event, Event::Free(_)))
        .unwrap();
    assert!(context_invalidated < first_free && invalidated < first_free);

    // A second teardown, or one for a resource with no domain, returns nothing.
    assert_eq!(
        domains.teardown(&mut model, resource).into_pins().count(),
        0
    );
}

#[test]
fn a_function_has_one_domain_and_domain_ids_stay_within_the_unit_limit() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(64);
    let mut domains = Domains::new();
    let owner = fixture.resource();
    domains
        .map(&mut model, owner, 7, 0x1000, 1, RW, fixture.pin())
        .unwrap();
    let intruder = fixture.resource();
    assert_eq!(
        domains
            .map(&mut model, intruder, 7, 0x2000, 1, RW, fixture.pin())
            .unwrap_err()
            .0,
        DmaError::FunctionBusy
    );

    model.max_domain_id = 2;
    let second = fixture.resource();
    domains
        .map(&mut model, second, 8, 0x3000, 1, RW, fixture.pin())
        .unwrap();
    assert_eq!(model.context_domain(8), 2);
    let third = fixture.resource();
    assert_eq!(
        domains
            .map(&mut model, third, 9, 0x4000, 1, RW, fixture.pin())
            .unwrap_err()
            .0,
        DmaError::NoResources
    );
    assert!(!model.context_present(9));
}

#[test]
fn per_domain_mapping_slots_and_iova_space_are_bounded() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(16);
    let mut domains = DmaDomains::<1, 2>::new();
    let resource = fixture.resource();
    for page in 0..2 {
        domains
            .map(&mut model, resource, 10, page * PAGE, 1, RW, fixture.pin())
            .unwrap();
    }
    assert_eq!(
        domains
            .map(&mut model, resource, 10, 0x9000, 1, RW, fixture.pin())
            .unwrap_err()
            .0,
        DmaError::NoResources
    );

    let mut model = Model::new(16);
    model.iova_end = IOVA_BASE + 4 * PAGE;
    let mut domains = Domains::new();
    let resource = fixture.resource();
    domains
        .map(&mut model, resource, 11, 0, 4, RW, fixture.pin())
        .unwrap();
    assert_eq!(
        domains
            .map(&mut model, resource, 11, 0, 1, RW, fixture.pin())
            .unwrap_err()
            .0,
        DmaError::NoAddressSpace
    );
}

#[test]
fn malformed_requests_change_nothing() {
    let mut fixture = Fixture::new();
    let mut model = Model::new(16);
    let mut domains = Domains::new();
    let resource = fixture.resource();
    let none = DeviceAccess {
        read: false,
        write: false,
    };
    for (physical, pages, access) in [(0x1000, 0, RW), (0x1001, 1, RW), (0x1000, 1, none)] {
        assert_eq!(
            domains
                .map(
                    &mut model,
                    resource,
                    12,
                    physical,
                    pages,
                    access,
                    fixture.pin()
                )
                .unwrap_err()
                .0,
            DmaError::InvalidRange
        );
    }
    assert!(model.log.is_empty());
    assert_eq!(model.allocated(), 0);
}

#[test]
fn the_root_entry_links_bus_zero_and_free_tree_returns_every_frame() {
    let mut model = Model::new(16);
    let root = model.allocate().unwrap();
    install_root_entry(&mut model, root, 0, CONTEXT);
    assert_eq!(model.read(root, 0), CONTEXT | 1);
    assert_eq!(model.read(root, 1), 0);

    let tree = model.allocate().unwrap();
    // 0 and 2 MiB share a PD; 1 GiB shares the PDPT; 512 GiB needs its own.
    for iova in [0, 1 << 21, 1 << 30, 1 << 39] {
        tables::map_page(&mut model, tree, iova, 0x1000, RW).unwrap();
    }
    assert_eq!(model.allocated(), 2 + 3 + 1 + 2 + 3);
    assert_eq!(
        tables::map_page(&mut model, tree, 0, 0x2000, RW),
        Err(TableError::Occupied)
    );
    assert_eq!(
        tables::map_page(&mut model, tree, 1 << 48, 0x1000, RW),
        Err(TableError::InvalidAddress)
    );
    assert_eq!(
        tables::unmap_page(&mut model, tree, 0x1000),
        Err(TableError::NotMapped)
    );
    tables::free_tree(&mut model, tree);
    // Only the root table is left.
    assert_eq!(model.allocated(), 1);
}
