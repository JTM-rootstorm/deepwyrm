extern crate std;

use std::collections::BTreeMap;
use std::{cell::RefCell, rc::Rc, vec::Vec};

use crate::memory::frame_roles::{FrameRoleManager, TableOwnerKey, synthetic_frame_role_manager};
use crate::memory::physical::PhysicalRange;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Preflight,
    Cr3Write(u64),
    TransitionRetired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScratchIoEvent {
    Load(u64),
    Store(u64, u64),
    CompareExchange {
        address: u64,
        current: u64,
        new: u64,
    },
    Invalidate(u64),
}

#[derive(Default)]
struct FakeActiveScratchIo {
    memory: BTreeMap<u64, u64>,
    events: Vec<ScratchIoEvent>,
    install_attempts: usize,
    fail_install_attempt: Option<usize>,
}

impl ActiveScratchIo for FakeActiveScratchIo {
    fn load(&mut self, address: u64) -> u64 {
        self.events.push(ScratchIoEvent::Load(address));
        *self.memory.get(&address).unwrap_or(&0)
    }

    fn store(&mut self, address: u64, value: u64) {
        self.events.push(ScratchIoEvent::Store(address, value));
        self.memory.insert(address, value);
    }

    fn compare_exchange(&mut self, address: u64, current: u64, new: u64) -> Result<(), u64> {
        self.events.push(ScratchIoEvent::CompareExchange {
            address,
            current,
            new,
        });
        if new != 0 {
            self.install_attempts += 1;
            if self.fail_install_attempt == Some(self.install_attempts) {
                return Err(0xfeed_0000);
            }
        }
        let observed = *self.memory.get(&address).unwrap_or(&0);
        if observed != current {
            return Err(observed);
        }
        self.memory.insert(address, new);
        Ok(())
    }

    fn invalidate(&mut self, virtual_address: u64) {
        self.events
            .push(ScratchIoEvent::Invalidate(virtual_address));
    }
}

struct FakeHandoff(Rc<RefCell<Vec<Event>>>);

impl FakeHandoff {
    fn retire_before_activation(self) {
        self.0.borrow_mut().push(Event::TransitionRetired);
    }
}

struct FakeTarget(Rc<RefCell<Vec<Event>>>);

impl target_seal::Sealed for FakeTarget {}

// SAFETY: this host fake records the modeled single write and exposes no
// architecture state; its preflight and activation are inseparable.
#[allow(
    unsafe_code,
    reason = "host fake models the sealed single-write architecture backend"
)]
unsafe impl Cr3ActivationTarget<FakeHandoff> for FakeTarget {
    type Error = ();
    type Active = ();

    fn observe(
        &mut self,
        _handoff: &mut FakeHandoff,
    ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error> {
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        let current_root = FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap();
        Ok((
            ActivationCpuState {
                processor_id: 0,
                physical_address_width: 40,
                current_root,
                cpl: 0,
                paging_enabled: true,
                long_mode_active: true,
                four_level_paging: true,
                no_execute_enabled: true,
                write_protect_enabled: true,
                interrupts_enabled: false,
                pcid_enabled: false,
                global_pages_enabled: false,
                smap_enabled: false,
                access_flag_set: false,
                pat_supported: true,
                pat_entry_zero: 6,
                stack_pointer: 0,
                code_selector: 0,
                gdt_base: 0,
                gdt_limit: 0,
                idt_base: 0,
                idt_limit: 0,
                task_register: 0,
            },
            capabilities,
        ))
    }

    fn preflight(
        &mut self,
        _handoff: &mut FakeHandoff,
        _root: &PageTableRoot,
        _identity: TableIdentity,
    ) -> Result<(), Self::Error> {
        self.0.borrow_mut().push(Event::Preflight);
        Ok(())
    }

    unsafe fn activate(self, handoff: FakeHandoff, root: FrameAddress) -> Self::Active {
        handoff.retire_before_activation();
        self.0.borrow_mut().push(Event::Cr3Write(root.address()));
    }
}

struct InvalidCpuTarget;

impl target_seal::Sealed for InvalidCpuTarget {}

#[allow(
    unsafe_code,
    reason = "host fake supplies one rejected observation and has no commit path"
)]
unsafe impl Cr3ActivationTarget<FakeHandoff> for InvalidCpuTarget {
    type Error = ();
    type Active = ();

    fn observe(
        &mut self,
        _handoff: &mut FakeHandoff,
    ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error> {
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        Ok((
            ActivationCpuState {
                processor_id: 0,
                physical_address_width: 40,
                current_root: FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
                cpl: 0,
                paging_enabled: true,
                long_mode_active: true,
                four_level_paging: true,
                no_execute_enabled: true,
                write_protect_enabled: true,
                interrupts_enabled: true,
                pcid_enabled: false,
                global_pages_enabled: false,
                smap_enabled: false,
                access_flag_set: false,
                pat_supported: true,
                pat_entry_zero: 6,
                stack_pointer: 0,
                code_selector: 0,
                gdt_base: 0,
                gdt_limit: 0,
                idt_base: 0,
                idt_limit: 0,
                task_register: 0,
            },
            capabilities,
        ))
    }

    fn preflight(
        &mut self,
        _handoff: &mut FakeHandoff,
        _root: &PageTableRoot,
        _identity: TableIdentity,
    ) -> Result<(), Self::Error> {
        panic!("invalid CPU state must reject before target preflight")
    }

    unsafe fn activate(self, _handoff: FakeHandoff, _root: FrameAddress) -> Self::Active {
        panic!("invalid CPU state must never reach activation")
    }
}

#[derive(Default)]
struct FakeGraphAccess {
    transition: BTreeMap<(u64, usize), u64>,
    inactive: BTreeMap<(u64, usize), u64>,
}

impl ActivationGraphAccess for FakeGraphAccess {
    type Error = ();

    fn read_transition(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        Ok(*self.transition.get(&(table.address(), index)).unwrap_or(&0))
    }

    fn read_inactive(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        Ok(*self.inactive.get(&(table.address(), index)).unwrap_or(&0))
    }
}

fn page_index(page: u64, level: usize) -> usize {
    ((page >> (12 + level * 9)) & 0x1ff) as usize
}

#[allow(
    unsafe_code,
    reason = "synthetic host tables model completed physical zeroing"
)]
fn commit_table<const ROLE_CAPACITY: usize>(
    roles: &mut FrameRoleManager<1, ROLE_CAPACITY>,
    owner: TableOwnerKey,
    level: TableLevel,
    parent: Option<TableIdentity>,
) -> TableIdentity {
    let allocation = roles.allocate(1).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let candidate = roles.prepare_table(zeroed, owner, level).unwrap();
    roles.commit_table(candidate, parent).unwrap()
}

fn add_path(entries: &mut BTreeMap<(u64, usize), u64>, page: u64, tables: [u64; 4], leaf: u64) {
    for level in (1..=3).rev() {
        entries.insert(
            (tables[3 - level], page_index(page, level)),
            tables[4 - level] | PRESENT | WRITABLE,
        );
    }
    if leaf != 0 {
        entries.insert((tables[3], page_index(page, 0)), leaf);
    }
}

fn test_ist_layout(guard_page: u64) -> IstStackLayout {
    fn stack(guard_page: u64) -> IstStackBounds {
        IstStackBounds {
            guard_page,
            bottom: guard_page + PAGE_SIZE,
            top: guard_page + 5 * PAGE_SIZE,
        }
    }
    IstStackLayout {
        double_fault: stack(guard_page),
        non_maskable_interrupt: stack(guard_page + 5 * PAGE_SIZE),
        machine_check: stack(guard_page + 10 * PAGE_SIZE),
    }
}

const FIXTURE_TEXT: u64 = 0xffff_8000_0000_0000;
const FIXTURE_RODATA: u64 = FIXTURE_TEXT + PAGE_SIZE;
const FIXTURE_DATA: u64 = FIXTURE_RODATA + PAGE_SIZE;
const FIXTURE_SCRATCH: u64 = 0xffff_ff00_0000_0000;

struct GraphFixture {
    access: FakeGraphAccess,
    roles: FrameRoleManager<1, 16>,
    staged: StagedKernelImageRoles,
    root: TableIdentity,
    kernel_tables: [u64; 4],
    scratch_tables: [u64; 4],
    scratch_pt: TableIdentity,
    extra_pdpt: TableIdentity,
    transition_tables: [u64; 4],
    capabilities: PagingCapabilities,
    segments: [KernelSegment; 3],
    ist: IstStackLayout,
    privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
}

impl GraphFixture {
    fn validate(&mut self) -> Result<(), InactiveGraphError<()>> {
        validate_inactive_graph(
            &mut self.access,
            &self.roles,
            &self.staged,
            self.root,
            FrameAddress::new(
                self.transition_tables[0],
                self.capabilities.physical_limit(),
            )
            .unwrap(),
            DeepScratchBinding {
                window_page: FIXTURE_SCRATCH,
                control_page: FIXTURE_SCRATCH + PAGE_SIZE,
                pt: self.scratch_pt,
            },
            &self.segments,
            self.ist,
            self.privilege_entry,
            self.capabilities,
        )
    }
}

#[allow(
    unsafe_code,
    reason = "synthetic host graph models typed page-table and kernel-image provenance"
)]
fn graph_fixture() -> GraphFixture {
    let ist = test_ist_layout(FIXTURE_DATA + PAGE_SIZE);
    let privilege_entry = crate::memory::kernel_stack::KernelStackBounds::new(
        FIXTURE_DATA + 16 * PAGE_SIZE,
        FIXTURE_DATA + 17 * PAGE_SIZE,
        FIXTURE_DATA + 21 * PAGE_SIZE,
    )
    .unwrap();
    let segments = [
        KernelSegment {
            start: FIXTURE_TEXT,
            end: FIXTURE_RODATA,
            kind: SegmentKind::Text,
        },
        KernelSegment {
            start: FIXTURE_RODATA,
            end: FIXTURE_DATA,
            kind: SegmentKind::ReadOnly,
        },
        KernelSegment {
            start: FIXTURE_DATA,
            end: FIXTURE_DATA + 21 * PAGE_SIZE,
            kind: SegmentKind::Writable,
        },
    ];
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x8000, 8);
    let owner = roles.create_table_owner().unwrap();
    let root = commit_table(&mut roles, owner, TableLevel::Pml4, None);
    let kernel_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
    let kernel_pd = commit_table(&mut roles, owner, TableLevel::Pd, Some(kernel_pdpt));
    let kernel_pt = commit_table(&mut roles, owner, TableLevel::Pt, Some(kernel_pd));
    let scratch_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
    let scratch_pd = commit_table(&mut roles, owner, TableLevel::Pd, Some(scratch_pdpt));
    let scratch_pt = commit_table(&mut roles, owner, TableLevel::Pt, Some(scratch_pd));
    let extra_pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
    let kernel_tables = [
        root.physical_start(),
        kernel_pdpt.physical_start(),
        kernel_pd.physical_start(),
        kernel_pt.physical_start(),
    ];
    let scratch_tables = [
        root.physical_start(),
        scratch_pdpt.physical_start(),
        scratch_pd.physical_start(),
        scratch_pt.physical_start(),
    ];
    let transition_tables = [0x1000, 0x2000, 0x3000, 0x4000];
    let mut access = FakeGraphAccess::default();
    for (page, physical, flags) in [
        (FIXTURE_TEXT, 0x20_0000, PRESENT),
        (FIXTURE_RODATA, 0x21_0000, PRESENT | NO_EXECUTE),
    ] {
        add_path(
            &mut access.transition,
            page,
            transition_tables,
            physical | flags,
        );
        add_path(&mut access.inactive, page, kernel_tables, physical | flags);
    }
    for offset in 0..21 {
        let page = FIXTURE_DATA + offset * PAGE_SIZE;
        let physical = 0x22_0000 + offset * PAGE_SIZE;
        let flags = PRESENT | WRITABLE | NO_EXECUTE;
        add_path(
            &mut access.transition,
            page,
            transition_tables,
            physical | flags,
        );
        if !is_kernel_guard(ist, &[], privilege_entry, page) {
            add_path(&mut access.inactive, page, kernel_tables, physical | flags);
        }
    }
    add_path(&mut access.inactive, FIXTURE_SCRATCH, scratch_tables, 0);
    access.inactive.insert(
        (
            scratch_pt.physical_start(),
            page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
        ),
        scratch_pt.physical_start() | PRESENT | WRITABLE | NO_EXECUTE,
    );
    let staged = unsafe {
        roles.stage_kernel_image_roles([
            (
                PhysicalRange::new(0x20_0000, PAGE_SIZE).unwrap(),
                KernelImageSegment::Text,
            ),
            (
                PhysicalRange::new(0x21_0000, PAGE_SIZE).unwrap(),
                KernelImageSegment::ReadOnlyData,
            ),
            (
                PhysicalRange::new(0x22_0000, 21 * PAGE_SIZE).unwrap(),
                KernelImageSegment::WritableData,
            ),
        ])
    }
    .unwrap();
    GraphFixture {
        access,
        roles,
        staged,
        root,
        kernel_tables,
        scratch_tables,
        scratch_pt,
        extra_pdpt,
        transition_tables,
        capabilities,
        segments,
        ist,
        privilege_entry,
    }
}

fn fake_active_scratch(
    scratch_pt: TableIdentity,
    fail_install_attempt: Option<usize>,
) -> ActiveScratchTarget<FakeActiveScratchIo> {
    ActiveScratchTarget {
        scratch: DeepScratchBinding {
            window_page: FIXTURE_SCRATCH,
            control_page: FIXTURE_SCRATCH + PAGE_SIZE,
            pt: scratch_pt,
        },
        io: FakeActiveScratchIo {
            fail_install_attempt,
            ..FakeActiveScratchIo::default()
        },
        poisoned: false,
        _not_send_sync: core::marker::PhantomData,
    }
}

#[test]
fn active_scratch_error_restores_private_leaf_without_owned_write_or_requested_invlpg() {
    let fixture = graph_fixture();
    let mut target = fake_active_scratch(fixture.scratch_pt, Some(2));
    let limit = fixture.capabilities.physical_limit();
    let writes = [
        JournalWrite::test_new(FrameAddress::new(0x90_000, limit).unwrap(), 7, 0x1111),
        JournalWrite::test_new(FrameAddress::new(0x91_000, limit).unwrap(), 8, 0x2222),
    ];
    let requested = VirtualPage::new(FIXTURE_TEXT).unwrap();
    assert_eq!(
        target.apply(&writes, &[requested]),
        Err(LiveActiveTargetError::Busy)
    );
    assert_eq!(
        target
            .io
            .memory
            .get(&target.scratch_leaf_address())
            .copied()
            .unwrap_or(0),
        0
    );
    assert!(
        target
            .io
            .events
            .iter()
            .all(|event| !matches!(event, ScratchIoEvent::Store(_, _))),
        "prepublication failure must not write an owned-root entry"
    );
    assert!(target.io.events.iter().all(|event| {
        !matches!(event, ScratchIoEvent::Invalidate(page) if *page == requested.address())
    }));
    assert!(target.io.events.iter().any(|event| {
        matches!(event, ScratchIoEvent::Invalidate(page) if *page == FIXTURE_SCRATCH)
    }));
}

#[test]
fn active_scratch_reserves_window_control_and_mmio_entries_without_io() {
    let fixture = graph_fixture();
    let mut target = fake_active_scratch(fixture.scratch_pt, None);
    let table = FrameAddress::new(
        fixture.scratch_pt.physical_start(),
        fixture.capabilities.physical_limit(),
    )
    .unwrap();
    for index in [
        target.scratch_leaf_index(),
        target.scratch_control_index(),
        target.mmio_leaf_index(),
    ] {
        assert_eq!(
            target.read_entry(table, index),
            Err(LiveActiveTargetError::ReservedScratchEntry)
        );
    }
    assert!(target.io.events.is_empty());
}

#[test]
fn active_scratch_installs_one_uc_nx_mmio_leaf_without_consuming_window() {
    let fixture = graph_fixture();
    let mut target = fake_active_scratch(fixture.scratch_pt, None);
    let frame = FrameAddress::new(0xfee0_0000, fixture.capabilities.physical_limit()).unwrap();
    let page = target.install_mmio_frame(frame).unwrap();
    assert_eq!(page, FIXTURE_SCRATCH + 2 * PAGE_SIZE);
    let leaf = target.scratch.control_page + (target.mmio_leaf_index() as u64) * 8;
    assert_eq!(
        target.io.memory.get(&leaf).copied(),
        Some(0xfee0_0000 | PRESENT | WRITABLE | WRITE_THROUGH | CACHE_DISABLE | NO_EXECUTE)
    );
    assert!(
        target.io.events.iter().any(|event| {
            matches!(event, ScratchIoEvent::Invalidate(address) if *address == page)
        })
    );
    assert_eq!(
        target.install_mmio_frame(frame),
        Err(LiveActiveTargetError::Busy)
    );
}

#[test]
fn graph_rejects_kernel_permission_drift() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (fixture.kernel_tables[3], page_index(FIXTURE_TEXT, 0)),
        0x20_0000 | PRESENT | NO_EXECUTE,
    );
    assert_eq!(fixture.validate(), Err(InactiveGraphError::InvalidEntry));
}

#[test]
fn graph_rejects_kernel_physical_mapping_drift() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (fixture.kernel_tables[3], page_index(FIXTURE_TEXT, 0)),
        0x23_0000 | PRESENT,
    );
    assert_eq!(fixture.validate(), Err(InactiveGraphError::MappingMismatch));
}

#[test]
fn graph_rejects_each_present_ist_guard_leaf() {
    for guard_index in 0..3 {
        let mut fixture = graph_fixture();
        let guard = fixture.ist.stacks()[guard_index].guard_page;
        let physical = 0x22_0000 + (guard - FIXTURE_DATA);
        fixture.access.inactive.insert(
            (fixture.kernel_tables[3], page_index(guard, 0)),
            physical | PRESENT | WRITABLE | NO_EXECUTE,
        );
        assert_eq!(
            fixture.validate(),
            Err(InactiveGraphError::MappedGuardPage),
            "guard {guard_index} must remain absent"
        );
    }
}

#[test]
fn graph_rejects_missing_ist_usable_page_and_fourth_hole() {
    let mut missing_usable = graph_fixture();
    let usable = missing_usable.ist.double_fault.bottom;
    missing_usable
        .access
        .inactive
        .remove(&(missing_usable.kernel_tables[3], page_index(usable, 0)));
    assert_eq!(
        missing_usable.validate(),
        Err(InactiveGraphError::MissingSegmentPage)
    );

    let mut fourth_hole = graph_fixture();
    fourth_hole
        .access
        .inactive
        .remove(&(fourth_hole.kernel_tables[3], page_index(FIXTURE_DATA, 0)));
    assert_eq!(
        fourth_hole.validate(),
        Err(InactiveGraphError::MissingSegmentPage)
    );
}

#[test]
fn graph_rejects_ist_usable_permission_drift() {
    let mut fixture = graph_fixture();
    let usable = fixture.ist.non_maskable_interrupt.bottom;
    let physical = 0x22_0000 + (usable - FIXTURE_DATA);
    fixture.access.inactive.insert(
        (fixture.kernel_tables[3], page_index(usable, 0)),
        physical | PRESENT | NO_EXECUTE,
    );
    assert_eq!(fixture.validate(), Err(InactiveGraphError::InvalidEntry));
}

#[test]
fn graph_rejects_ist_usable_physical_drift() {
    let mut fixture = graph_fixture();
    let usable = fixture.ist.machine_check.bottom;
    let physical = 0x22_0000 + (usable - FIXTURE_DATA) + PAGE_SIZE;
    fixture.access.inactive.insert(
        (fixture.kernel_tables[3], page_index(usable, 0)),
        physical | PRESENT | WRITABLE | NO_EXECUTE,
    );
    assert_eq!(fixture.validate(), Err(InactiveGraphError::MappingMismatch));
}

#[test]
fn graph_rejects_transition_ist_frame_without_the_exact_kernel_role() {
    let mut fixture = graph_fixture();
    let usable = fixture.ist.double_fault.bottom;
    fixture.access.transition.insert(
        (fixture.transition_tables[3], page_index(usable, 0)),
        0x40_0000 | PRESENT | WRITABLE | NO_EXECUTE,
    );
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::FrameRole(FrameRoleError::WrongRole))
    );
}

#[test]
fn ist_layout_rejects_malformed_or_conflicting_ranges() {
    let fixture = graph_fixture();
    assert_eq!(
        validate_ist_layout(
            &fixture.segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            fixture.ist,
        ),
        Ok(())
    );

    let mut shortened = fixture.ist;
    shortened.non_maskable_interrupt.top -= PAGE_SIZE;
    assert_eq!(
        validate_ist_layout(
            &fixture.segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            shortened,
        ),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );

    let outside = test_ist_layout(FIXTURE_SCRATCH);
    assert_eq!(
        validate_ist_layout(
            &fixture.segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            outside,
        ),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );
}

#[test]
fn e3_thread_stack_layout_rejects_overlap_size_and_scratch_conflicts() {
    let writable_start = 0xffff_8000_0100_0000;
    let segments = [
        KernelSegment {
            start: writable_start - 2 * PAGE_SIZE,
            end: writable_start - PAGE_SIZE,
            kind: SegmentKind::Text,
        },
        KernelSegment {
            start: writable_start - PAGE_SIZE,
            end: writable_start,
            kind: SegmentKind::ReadOnly,
        },
        KernelSegment {
            start: writable_start,
            end: writable_start + 3 * crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE,
            kind: SegmentKind::Writable,
        },
    ];
    let first = crate::memory::kernel_stack::KernelStackBounds::new(
        writable_start,
        writable_start + crate::memory::kernel_stack::E3_THREAD_STACK_GUARD_SIZE,
        writable_start
            + crate::memory::kernel_stack::E3_THREAD_STACK_GUARD_SIZE
            + crate::memory::kernel_stack::E3_THREAD_STACK_SIZE,
    )
    .unwrap();
    let second_guard = writable_start + crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE;
    let second = crate::memory::kernel_stack::KernelStackBounds::new(
        second_guard,
        second_guard + crate::memory::kernel_stack::E3_THREAD_STACK_GUARD_SIZE,
        second_guard
            + crate::memory::kernel_stack::E3_THREAD_STACK_GUARD_SIZE
            + crate::memory::kernel_stack::E3_THREAD_STACK_SIZE,
    )
    .unwrap();
    assert_eq!(
        validate_thread_stack_layout(
            &segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            &[first, second],
        ),
        Ok(())
    );
    assert!(is_thread_stack_guard(&[first, second], first.guard_page));
    assert!(is_kernel_guard(
        test_ist_layout(writable_start + 2 * crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE),
        &[first, second],
        crate::memory::kernel_stack::KernelStackBounds::new(
            writable_start + 3 * crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE,
            writable_start + 3 * crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE + PAGE_SIZE,
            writable_start
                + 3 * crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE
                + PAGE_SIZE
                + crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_SIZE
        )
        .unwrap(),
        second.guard_page
    ));

    assert_eq!(
        validate_thread_stack_layout(
            &segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            &[first, first],
        ),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );
    let short = crate::memory::kernel_stack::KernelStackBounds::new(
        second_guard,
        second_guard + PAGE_SIZE,
        second_guard + PAGE_SIZE + crate::memory::kernel_stack::E3_THREAD_STACK_SIZE - PAGE_SIZE,
    )
    .unwrap();
    assert_eq!(
        validate_thread_stack_layout(
            &segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            &[short],
        ),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );
    assert_eq!(
        validate_thread_stack_layout(&segments, first.bottom, FIXTURE_SCRATCH, &[first],),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );
}

#[test]
fn guard_leaf_absence_rejects_a_missing_parent_path() {
    let fixture = graph_fixture();
    let mut access = FakeGraphAccess::default();
    let root = FrameAddress::new(
        fixture.root.physical_start(),
        fixture.capabilities.physical_limit(),
    )
    .unwrap();
    assert_eq!(
        resolve_optional_leaf(
            &mut access,
            false,
            root,
            fixture.ist.double_fault.guard_page,
            fixture.capabilities,
        ),
        Err(InactiveGraphError::MissingSegmentPage)
    );
}

#[test]
fn graph_rejects_occupied_deep_scratch_leaf() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (fixture.scratch_tables[3], page_index(FIXTURE_SCRATCH, 0)),
        0x24_0000 | PRESENT | WRITABLE | NO_EXECUTE,
    );
    assert_eq!(fixture.validate(), Err(InactiveGraphError::ExtraLeaf));
}

#[test]
fn graph_rejects_missing_deep_scratch_path() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.remove(&(
        fixture.root.physical_start(),
        page_index(FIXTURE_SCRATCH, 3),
    ));
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::InvalidScratchPath)
    );
}

#[test]
fn graph_rejects_missing_scratch_control_alias() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.remove(&(
        fixture.scratch_pt.physical_start(),
        page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
    ));
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::InvalidScratchPath)
    );
}

#[test]
fn graph_rejects_wrong_scratch_control_frame() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (
            fixture.scratch_pt.physical_start(),
            page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
        ),
        fixture.kernel_tables[3] | PRESENT | WRITABLE | NO_EXECUTE,
    );
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::InvalidScratchPath)
    );
}

#[test]
fn graph_rejects_scratch_control_permission_drift() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (
            fixture.scratch_pt.physical_start(),
            page_index(FIXTURE_SCRATCH + PAGE_SIZE, 0),
        ),
        fixture.scratch_pt.physical_start() | PRESENT | WRITABLE,
    );
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::InvalidScratchPath)
    );
}

#[test]
fn graph_rejects_second_scratch_control_alias() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (
            fixture.scratch_pt.physical_start(),
            page_index(FIXTURE_SCRATCH + 2 * PAGE_SIZE, 0),
        ),
        fixture.scratch_pt.physical_start() | PRESENT | WRITABLE | NO_EXECUTE,
    );
    assert_eq!(fixture.validate(), Err(InactiveGraphError::ExtraLeaf));
}

#[test]
fn graph_rejects_wrong_table_role_or_parent_level() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (fixture.root.physical_start(), page_index(FIXTURE_TEXT, 3)),
        fixture.kernel_tables[2] | PRESENT | WRITABLE,
    );
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::FrameRole(FrameRoleError::WrongRole))
    );
}

#[test]
fn graph_rejects_duplicate_or_cyclic_table_reachability() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (
            fixture.root.physical_start(),
            page_index(FIXTURE_SCRATCH, 3),
        ),
        fixture.kernel_tables[1] | PRESENT | WRITABLE,
    );
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::DuplicateOrCyclicTable)
    );
}

#[test]
fn graph_rejects_extra_empty_lower_half_subtree() {
    let mut fixture = graph_fixture();
    fixture.access.inactive.insert(
        (fixture.root.physical_start(), 0),
        fixture.extra_pdpt.physical_start() | PRESENT | WRITABLE,
    );
    assert_eq!(fixture.validate(), Err(InactiveGraphError::ExtraTable));
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic host graph models a bounded hostile table fanout"
)]
fn graph_capacity_rejects_before_any_leaf_or_scratch_access() {
    const SPAN: u64 = 1_u64 << 39;
    const START: u64 = 0xffff_8000_0000_0000;
    const MID_ONE: u64 = START + 64 * SPAN;
    const MID_TWO: u64 = START + 128 * SPAN;
    const SCRATCH: u64 = START + 255 * SPAN;
    let segments = [
        KernelSegment {
            start: START,
            end: MID_ONE,
            kind: SegmentKind::Text,
        },
        KernelSegment {
            start: MID_ONE,
            end: MID_TWO,
            kind: SegmentKind::ReadOnly,
        },
        KernelSegment {
            start: MID_TWO,
            end: SCRATCH,
            kind: SegmentKind::Writable,
        },
    ];
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let mut roles = synthetic_frame_role_manager::<1, 300>(0x8000, 257);
    let owner = roles.create_table_owner().unwrap();
    let root = commit_table(&mut roles, owner, TableLevel::Pml4, None);
    let mut access = FakeGraphAccess::default();
    for index in 0..256 {
        let child = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(root));
        access.inactive.insert(
            (root.physical_start(), 256 + index),
            child.physical_start() | PRESENT | WRITABLE,
        );
    }
    let staged = unsafe {
        roles.stage_kernel_image_roles([
            (
                PhysicalRange::new(0x20_0000, PAGE_SIZE).unwrap(),
                KernelImageSegment::Text,
            ),
            (
                PhysicalRange::new(0x21_0000, PAGE_SIZE).unwrap(),
                KernelImageSegment::ReadOnlyData,
            ),
            (
                PhysicalRange::new(0x22_0000, PAGE_SIZE).unwrap(),
                KernelImageSegment::WritableData,
            ),
        ])
    }
    .unwrap();
    assert_eq!(
        validate_inactive_graph(
            &mut access,
            &roles,
            &staged,
            root,
            FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
            DeepScratchBinding {
                window_page: SCRATCH,
                control_page: SCRATCH + PAGE_SIZE,
                pt: root,
            },
            &segments,
            test_ist_layout(MID_TWO),
            crate::memory::kernel_stack::KernelStackBounds::new(
                MID_TWO + 15 * PAGE_SIZE,
                MID_TWO + 16 * PAGE_SIZE,
                MID_TWO + 20 * PAGE_SIZE
            )
            .unwrap(),
            capabilities,
        ),
        Err(InactiveGraphError::Capacity)
    );
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic host role setup models completed physical zeroing"
)]
fn full_owned_graph_matches_transition_segments_and_empty_scratch() {
    let mut fixture = graph_fixture();
    assert_eq!(fixture.validate(), Ok(()));
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic host role setup models completed physical zeroing"
)]
fn retirement_before_one_infallible_write() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 1);
    let allocation = roles.allocate(1).unwrap();
    // SAFETY: synthetic host frames are never dereferenced and the test
    // models the completed zeroing step explicitly.
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let owner = roles.create_table_owner().unwrap();
    let candidate = roles
        .prepare_table(zeroed, owner, TableLevel::Pml4)
        .unwrap();
    let identity = roles.commit_table(candidate, None).unwrap();
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    // SAFETY: the synthetic role manager authenticated this exact root.
    let root =
        unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }.unwrap();
    let prepared = prepare_activation(
        FakeHandoff(Rc::clone(&events)),
        FakeTarget(Rc::clone(&events)),
        root,
        identity,
    )
    .unwrap_or_else(|_| panic!("activation preparation succeeds"));
    let active = prepared.activate();

    assert_eq!(active.identity(), identity);
    assert_eq!(active.root().frame().address(), 0x8000);
    assert_eq!(
        events.borrow().as_slice(),
        &[
            Event::Preflight,
            Event::TransitionRetired,
            Event::Cr3Write(0x8000),
        ]
    );
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic host role setup models completed physical zeroing"
)]
fn cpu_rejection_returns_all_authority_with_zero_retire_or_write_events() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 1);
    let allocation = roles.allocate(1).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let owner = roles.create_table_owner().unwrap();
    let candidate = roles
        .prepare_table(zeroed, owner, TableLevel::Pml4)
        .unwrap();
    let identity = roles.commit_table(candidate, None).unwrap();
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root =
        unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }.unwrap();

    let failure = match prepare_activation(
        FakeHandoff(Rc::clone(&events)),
        InvalidCpuTarget,
        root,
        identity,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("enabled interrupts reject before preflight"),
    };
    let (error, _handoff, _target, root, returned_identity) = failure.into_parts();
    assert_eq!(error, ActivationPrepareError::InterruptsEnabled);
    assert_eq!(root.frame().address(), identity.physical_start());
    assert_eq!(returned_identity, identity);
    assert!(events.borrow().is_empty());
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic host role setup models one inactive owned root for pure CPU-profile validation"
)]
fn accepted_cpu_profile_rejects_smap_or_initial_access_flag() {
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 1);
    let allocation = roles.allocate(1).unwrap();
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let owner = roles.create_table_owner().unwrap();
    let candidate = roles
        .prepare_table(zeroed, owner, TableLevel::Pml4)
        .unwrap();
    let identity = roles.commit_table(candidate, None).unwrap();
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root =
        unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }.unwrap();
    let mut cpu = ActivationCpuState {
        processor_id: 0,
        physical_address_width: 40,
        current_root: FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
        cpl: 0,
        paging_enabled: true,
        long_mode_active: true,
        four_level_paging: true,
        no_execute_enabled: true,
        write_protect_enabled: true,
        interrupts_enabled: false,
        pcid_enabled: false,
        global_pages_enabled: false,
        smap_enabled: false,
        access_flag_set: false,
        pat_supported: true,
        pat_entry_zero: 6,
        stack_pointer: 0,
        code_selector: 0,
        gdt_base: 0,
        gdt_limit: 0,
        idt_base: 0,
        idt_limit: 0,
        task_register: 0,
    };
    assert!(InactiveDeepRoot::validate(&root, identity, capabilities, cpu).is_ok());

    cpu.smap_enabled = true;
    assert_eq!(
        InactiveDeepRoot::validate(&root, identity, capabilities, cpu),
        Err(ActivationPrepareError::WrongControlState)
    );
    cpu.smap_enabled = false;
    cpu.access_flag_set = true;
    assert_eq!(
        InactiveDeepRoot::validate(&root, identity, capabilities, cpu),
        Err(ActivationPrepareError::WrongControlState)
    );
}

#[test]
fn stack_and_descriptor_carriers_reject_drift() {
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let mut cpu = ActivationCpuState {
        processor_id: 0,
        physical_address_width: 40,
        current_root: FrameAddress::new(0x1000, capabilities.physical_limit()).unwrap(),
        cpl: 0,
        paging_enabled: true,
        long_mode_active: true,
        four_level_paging: true,
        no_execute_enabled: true,
        write_protect_enabled: true,
        interrupts_enabled: false,
        pcid_enabled: false,
        global_pages_enabled: false,
        smap_enabled: false,
        access_flag_set: false,
        pat_supported: true,
        pat_entry_zero: 6,
        stack_pointer: 0xffff_8000_0000_5800,
        code_selector: 0x08,
        gdt_base: 0xffff_8000_0000_2100,
        gdt_limit: 55,
        idt_base: 0xffff_8000_0000_2200,
        idt_limit: 0x0fff,
        task_register: 0x18,
    };
    let segments = [
        KernelSegment {
            start: 0xffff_8000_0000_0000,
            end: 0xffff_8000_0000_1000,
            kind: SegmentKind::Text,
        },
        KernelSegment {
            start: 0xffff_8000_0000_1000,
            end: 0xffff_8000_0000_2000,
            kind: SegmentKind::ReadOnly,
        },
        KernelSegment {
            start: 0xffff_8000_0000_2000,
            end: 0xffff_8000_0002_0000,
            kind: SegmentKind::Writable,
        },
    ];
    let ist = test_ist_layout(0xffff_8000_0000_8000);
    let ist_stacks = ist.stacks();
    let facts = ExecutionCarrierFacts {
        stack_bottom: 0xffff_8000_0000_4000,
        stack_top: 0xffff_8000_0000_6000,
        gdt_base: cpu.gdt_base,
        gdt_limit: cpu.gdt_limit,
        idt_base: cpu.idt_base,
        idt_limit: cpu.idt_limit,
        tss_base: 0xffff_8000_0000_3300,
        tss_limit: 0x0067,
        code_selector: 0x08,
        task_register: 0x18,
        ist,
        installed_ist_tops: [ist_stacks[0].top, ist_stacks[1].top, ist_stacks[2].top],
        privilege_entry: crate::memory::kernel_stack::KernelStackBounds::new(
            0xffff_8000_0001_7000,
            0xffff_8000_0001_8000,
            0xffff_8000_0001_c000,
        )
        .unwrap(),
        installed_privilege_stack0: 0xffff_8000_0001_c000,
    };
    assert!(execution_carriers_match(cpu, &segments, facts));

    cpu.stack_pointer = facts.stack_bottom + MIN_ACTIVATION_STACK_HEADROOM - 1;
    assert!(!execution_carriers_match(cpu, &segments, facts));
    cpu.stack_pointer = 0xffff_8000_0000_5800;
    cpu.code_selector = 0x10;
    assert!(!execution_carriers_match(cpu, &segments, facts));
    cpu.code_selector = facts.code_selector;
    cpu.gdt_base += PAGE_SIZE;
    assert!(!execution_carriers_match(cpu, &segments, facts));
    cpu.gdt_base = facts.gdt_base;
    cpu.gdt_limit += 1;
    assert!(!execution_carriers_match(cpu, &segments, facts));
    cpu.gdt_limit = facts.gdt_limit;
    cpu.idt_limit -= 1;
    assert!(!execution_carriers_match(cpu, &segments, facts));
    cpu.idt_limit = facts.idt_limit;
    cpu.task_register = 0;
    assert!(!execution_carriers_match(cpu, &segments, facts));

    cpu.task_register = facts.task_register;
    let wrong_ist_top = ExecutionCarrierFacts {
        installed_ist_tops: [
            facts.installed_ist_tops[0] - PAGE_SIZE,
            facts.installed_ist_tops[1],
            facts.installed_ist_tops[2],
        ],
        ..facts
    };
    assert!(!execution_carriers_match(cpu, &segments, wrong_ist_top));
    let wrong_rsp0 = ExecutionCarrierFacts {
        installed_privilege_stack0: facts.privilege_entry.top - 16,
        ..facts
    };
    assert!(!execution_carriers_match(cpu, &segments, wrong_rsp0));
    let crossing_idt = ExecutionCarrierFacts {
        idt_base: ist.double_fault.guard_page,
        ..facts
    };
    cpu.idt_base = crossing_idt.idt_base;
    assert!(!execution_carriers_match(cpu, &segments, crossing_idt));
}
