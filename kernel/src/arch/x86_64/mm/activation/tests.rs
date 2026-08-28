extern crate std;

use std::collections::BTreeMap;
use std::{cell::RefCell, rc::Rc, vec, vec::Vec};

use crate::cpu::CpuIndex;
use crate::memory::frame_roles::{FrameRoleManager, TableOwnerKey, synthetic_frame_role_manager};
use crate::memory::kernel_stack::KernelStackBounds;
use crate::memory::physical::PhysicalRange;
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::memory::usercopy::UserPinTracker;
use crate::object::ObjectRegistry;
use crate::task::{ExecutionDomain, SchedulerThreadState, TaskAuthority, ThreadStartState};

use super::*;

const TERMINAL_TEST_OBJECTS: usize = 16;
type TerminalTestTasks = TaskAuthority<2, 2, 4, 4>;

fn terminal_stack_bounds<const COUNT: usize>() -> [KernelStackBounds; COUNT] {
    core::array::from_fn(|index| {
        let stride = 0x11_000_u64;
        let guard = 0xffff_9000_0000_0000 + u64::try_from(index).unwrap() * stride;
        KernelStackBounds::new(guard, guard + 0x1000, guard + stride).unwrap()
    })
}

fn terminal_start_state(seed: u64) -> ThreadStartState {
    ThreadStartState::from_validated_user_state(
        0x0000_0000_4000_0000 + seed * 0x1000,
        0x0000_0000_5000_0000 + seed * 0x1000,
        seed,
        seed + 1,
    )
}

#[test]
#[allow(
    unsafe_code,
    reason = "the synthetic address-space authority supplies one typed scope for the live-capacity model"
)]
fn live_user_pin_capacity_covers_dw1c_retained_receives_and_channel_create_batch() {
    let mut spaces = unsafe { crate::memory::address_region::AddressSpaceAuthority::<1, 1>::new() };
    let address_space = spaces.create_address_space().unwrap();
    let user_space = UserAddressSpace::x86_64_four_level(PAGE_SIZE).unwrap();
    let tracker = UserPinTracker::<E5_USER_PIN_CAPACITY>::new();
    let range = |index: usize| {
        UserRange::new(
            user_space,
            PAGE_SIZE * (u64::try_from(index).unwrap() + 1),
            8,
            8,
            UserAccess::WRITE,
            EmptyAddressRule::Reject,
        )
        .unwrap()
    };

    let mut retained = Vec::with_capacity(DW1C_RETAINED_RECEIVE_PINS);
    for index in 0..DW1C_RETAINED_RECEIVE_PINS {
        retained.push(tracker.pin_owned(address_space, range(index)).unwrap());
    }

    let first_output = tracker
        .pin(address_space, range(DW1C_RETAINED_RECEIVE_PINS))
        .unwrap();
    let second_output = tracker
        .pin(address_space, range(DW1C_RETAINED_RECEIVE_PINS + 1))
        .unwrap();

    drop(second_output);
    drop(first_output);
    for pin in retained {
        tracker.release_owned(address_space, pin).unwrap();
    }
}

fn terminal_two_thread_fixture() -> (
    ObjectRegistry<TERMINAL_TEST_OBJECTS>,
    TerminalTestTasks,
    crate::object::InternalRef,
    crate::object::HandleRef,
    crate::task::ThreadKey,
    crate::object::HandleRef,
    crate::task::ThreadKey,
    crate::object::HandleRef,
) {
    let mut registry = ObjectRegistry::<TERMINAL_TEST_OBJECTS>::new();
    let mut tasks = TerminalTestTasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_handle)
        .unwrap();
    let (current, current_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (other, other_handle) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    (
        registry,
        tasks,
        root_owner,
        process_handle,
        current,
        current_handle,
        other,
        other_handle,
    )
}

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

struct FakeActiveScratchIo {
    memory: BTreeMap<u64, u64>,
    events: Vec<ScratchIoEvent>,
    install_attempts: usize,
    fail_install_attempt: Option<usize>,
    current_cpu: CpuIndex,
}

impl Default for FakeActiveScratchIo {
    fn default() -> Self {
        Self {
            memory: BTreeMap::new(),
            events: Vec::new(),
            install_attempts: 0,
            fail_install_attempt: None,
            current_cpu: CpuIndex::BOOTSTRAP,
        }
    }
}

impl ActiveScratchIo for FakeActiveScratchIo {
    fn current_cpu(&self) -> Option<CpuIndex> {
        Some(self.current_cpu)
    }

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
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x8000, 12);
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
    // Every fixed CPU owns a distinct leaf/control/MMIO triplet, even though
    // the control aliases intentionally reach the one stationary scratch PT.
    // The live path accesses only its selected atomic PTE cell; the fixture
    // must model each legitimate alias so graph validation can reject extras.
    for slot in PerCpuScratchBindings::new(DeepScratchBinding {
        window_page: FIXTURE_SCRATCH,
        control_page: FIXTURE_SCRATCH + PAGE_SIZE,
        pt: scratch_pt,
    })
    .slots()
    .unwrap()
    {
        add_path(&mut access.inactive, slot.window_page, scratch_tables, 0);
        access.inactive.insert(
            (
                scratch_pt.physical_start(),
                page_index(slot.control_page, 0),
            ),
            scratch_pt.physical_start() | PRESENT | WRITABLE | NO_EXECUTE,
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

#[test]
#[allow(
    unsafe_code,
    reason = "the host graph fixture attests complete AP trampoline initialization"
)]
fn graph_accepts_only_the_typed_low_rx_ap_trampoline_leaf() {
    let mut fixture = graph_fixture();
    let allocation = fixture
        .roles
        .allocate_below(1, super::super::super::AP_TRAMPOLINE_LIMIT)
        .unwrap();
    let trampoline_page = allocation.physical_start();
    let trampoline = unsafe {
        fixture.roles.assume_architecture_bootstrap_initialized(
            allocation,
            crate::memory::frame_roles::ArchitectureBootstrapKind::X86ApTrampoline,
        )
    }
    .unwrap();
    let owner = fixture.root.owner();
    let pdpt = commit_table(
        &mut fixture.roles,
        owner,
        TableLevel::Pdpt,
        Some(fixture.root),
    );
    let pd = commit_table(&mut fixture.roles, owner, TableLevel::Pd, Some(pdpt));
    let pt = commit_table(&mut fixture.roles, owner, TableLevel::Pt, Some(pd));
    add_path(
        &mut fixture.access.inactive,
        trampoline_page,
        [
            fixture.root.physical_start(),
            pdpt.physical_start(),
            pd.physical_start(),
            pt.physical_start(),
        ],
        trampoline_page | PRESENT,
    );
    let mut pending = [None; MAX_DEEP_TABLE_FRAMES];
    let mut visited = [0; MAX_DEEP_TABLE_FRAMES];
    assert_eq!(
        validate_inactive_graph_with_workspace(
            &mut fixture.access,
            &fixture.roles,
            &fixture.staged,
            Some(&trampoline),
            fixture.root,
            FrameAddress::new(
                fixture.transition_tables[0],
                fixture.capabilities.physical_limit(),
            )
            .unwrap(),
            PerCpuScratchBindings::new(DeepScratchBinding {
                window_page: FIXTURE_SCRATCH,
                control_page: FIXTURE_SCRATCH + PAGE_SIZE,
                pt: fixture.scratch_pt,
            }),
            &fixture.segments,
            fixture.ist,
            &[],
            fixture.privilege_entry,
            fixture.capabilities,
            &mut pending,
            &mut visited,
        ),
        Ok(())
    );

    fixture.access.inactive.insert(
        (pt.physical_start(), page_index(trampoline_page, 0)),
        trampoline_page | PRESENT | WRITABLE,
    );
    pending.fill(None);
    visited.fill(0);
    assert_eq!(
        validate_inactive_graph_with_workspace(
            &mut fixture.access,
            &fixture.roles,
            &fixture.staged,
            Some(&trampoline),
            fixture.root,
            FrameAddress::new(
                fixture.transition_tables[0],
                fixture.capabilities.physical_limit(),
            )
            .unwrap(),
            PerCpuScratchBindings::new(DeepScratchBinding {
                window_page: FIXTURE_SCRATCH,
                control_page: FIXTURE_SCRATCH + PAGE_SIZE,
                pt: fixture.scratch_pt,
            }),
            &fixture.segments,
            fixture.ist,
            &[],
            fixture.privilege_entry,
            fixture.capabilities,
            &mut pending,
            &mut visited,
        ),
        Err(InactiveGraphError::InvalidEntry)
    );
}

fn fake_active_scratch(
    scratch_pt: TableIdentity,
    fail_install_attempt: Option<usize>,
) -> ActiveScratchTarget<FakeActiveScratchIo> {
    ActiveScratchTarget {
        scratch: ScratchBinding {
            cpu: CpuIndex::BOOTSTRAP,
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
fn per_cpu_scratch_slots_have_disjoint_leaf_control_and_mmio_entries() {
    let fixture = graph_fixture();
    let slots = PerCpuScratchBindings::new(DeepScratchBinding {
        window_page: FIXTURE_SCRATCH,
        control_page: FIXTURE_SCRATCH + PAGE_SIZE,
        pt: fixture.scratch_pt,
    })
    .slots()
    .expect("four fixed scratch slots fit the authenticated scratch PT");
    assert_eq!(slots.len(), crate::cpu::CPU_CAPACITY);
    for (index, slot) in slots.iter().enumerate() {
        assert_eq!(slot.cpu.index(), index);
        assert_eq!(slot.pt, fixture.scratch_pt);
        assert_eq!(slot.control_page, slot.window_page + PAGE_SIZE);
        assert_eq!(slot.control_page >> 21, FIXTURE_SCRATCH >> 21);
        for prior in &slots[..index] {
            assert_ne!(slot.window_page, prior.window_page);
            assert_ne!(slot.control_page, prior.control_page);
            assert_ne!(
                slot.control_page + PAGE_SIZE,
                prior.control_page + PAGE_SIZE
            );
        }
    }
}

#[test]
fn scratch_binding_rejects_cross_cpu_before_touching_its_leaf() {
    let fixture = graph_fixture();
    let bindings = PerCpuScratchBindings::new(DeepScratchBinding {
        window_page: FIXTURE_SCRATCH,
        control_page: FIXTURE_SCRATCH + PAGE_SIZE,
        pt: fixture.scratch_pt,
    });
    let mut target = bindings
        .target_for_current_cpu(FakeActiveScratchIo::default())
        .unwrap();
    assert_eq!(target.scratch.cpu, CpuIndex::BOOTSTRAP);
    // Model a carrier migration after its immutable binding was selected.
    // Attestation must reject rather than silently retargeting CPU1's leaf.
    target.io.current_cpu = CpuIndex::new(1).unwrap();
    let frame = FrameAddress::new(0x90_000, fixture.capabilities.physical_limit()).unwrap();
    assert_eq!(
        target.install_mmio_frame(frame),
        Err(LiveActiveTargetError::WrongCpu)
    );
    assert!(target.io.events.is_empty());
}

#[test]
fn wrong_cpu_empty_apply_rejects_before_the_scratch_leaf_load() {
    let fixture = graph_fixture();
    let slot = PerCpuScratchBindings::new(DeepScratchBinding {
        window_page: FIXTURE_SCRATCH,
        control_page: FIXTURE_SCRATCH + PAGE_SIZE,
        pt: fixture.scratch_pt,
    })
    .for_cpu(CpuIndex::BOOTSTRAP)
    .unwrap();
    let mut target = ActiveScratchTarget {
        scratch: slot,
        io: FakeActiveScratchIo {
            current_cpu: CpuIndex::new(1).unwrap(),
            ..FakeActiveScratchIo::default()
        },
        poisoned: false,
        _not_send_sync: core::marker::PhantomData,
    };
    assert_eq!(target.apply(&[], &[]), Err(LiveActiveTargetError::WrongCpu));
    assert!(target.io.events.is_empty());
}

#[test]
fn cpu_scratch_migration_selects_a_new_window_and_clears_independently() {
    let fixture = graph_fixture();
    let bindings = PerCpuScratchBindings::new(DeepScratchBinding {
        window_page: FIXTURE_SCRATCH,
        control_page: FIXTURE_SCRATCH + PAGE_SIZE,
        pt: fixture.scratch_pt,
    });
    let first = bindings.for_cpu(CpuIndex::BOOTSTRAP).unwrap();
    let second_cpu = CpuIndex::new(1).unwrap();
    let second = bindings.for_cpu(second_cpu).unwrap();
    let table = FrameAddress::new(0x90_000, fixture.capabilities.physical_limit()).unwrap();
    let mut cpu0 = bindings
        .target_for_current_cpu(FakeActiveScratchIo::default())
        .unwrap();

    assert_eq!(cpu0.read_location(table, 7), Ok(0));
    let cpu0_leaf = cpu0.scratch_leaf_address();
    let cpu0_events = core::mem::take(&mut cpu0.io.events);
    let shared_leaf_memory = core::mem::take(&mut cpu0.io.memory);
    let mut cpu1 = bindings
        .target_for_current_cpu(FakeActiveScratchIo {
            memory: shared_leaf_memory,
            current_cpu: second_cpu,
            ..FakeActiveScratchIo::default()
        })
        .unwrap();
    assert_eq!(cpu1.scratch, second);
    assert_eq!(cpu1.read_location(table, 7), Ok(0));
    assert_ne!(cpu0_leaf, cpu1.scratch_leaf_address());
    assert_eq!(cpu1.io.memory.get(&cpu0_leaf), Some(&0));
    assert_eq!(cpu1.io.memory.get(&cpu1.scratch_leaf_address()), Some(&0));
    assert!(cpu0_events.iter().any(|event| {
        matches!(event, ScratchIoEvent::Invalidate(page) if *page == first.window_page)
    }));
    assert!(cpu1.io.events.iter().any(|event| {
        matches!(event, ScratchIoEvent::Invalidate(page) if *page == second.window_page)
    }));
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
fn active_scratch_reserves_the_entire_shared_control_pt_without_io() {
    let fixture = graph_fixture();
    let mut target = fake_active_scratch(fixture.scratch_pt, None);
    let table = FrameAddress::new(
        fixture.scratch_pt.physical_start(),
        fixture.capabilities.physical_limit(),
    )
    .unwrap();
    let cpu1 = PerCpuScratchBindings::new(DeepScratchBinding {
        window_page: FIXTURE_SCRATCH,
        control_page: FIXTURE_SCRATCH + PAGE_SIZE,
        pt: fixture.scratch_pt,
    })
    .for_cpu(CpuIndex::new(1).unwrap())
    .unwrap();
    for index in [
        0,
        target.scratch_leaf_index(),
        target.scratch_control_index(),
        target.mmio_leaf_index(),
        ((cpu1.window_page >> 12) & 0x1ff) as usize,
    ] {
        assert_eq!(
            target.read_entry(table, index),
            Err(LiveActiveTargetError::ReservedScratchEntry)
        );
    }
    assert!(target.io.events.is_empty());
}

#[test]
fn cpu0_cannot_journal_cpu1_scratch_leaf_or_control_entries() {
    let fixture = graph_fixture();
    let mut target = fake_active_scratch(fixture.scratch_pt, None);
    let table = FrameAddress::new(
        fixture.scratch_pt.physical_start(),
        fixture.capabilities.physical_limit(),
    )
    .unwrap();
    let cpu1 = PerCpuScratchBindings::new(DeepScratchBinding {
        window_page: FIXTURE_SCRATCH,
        control_page: FIXTURE_SCRATCH + PAGE_SIZE,
        pt: fixture.scratch_pt,
    })
    .for_cpu(CpuIndex::new(1).unwrap())
    .unwrap();
    for index in [
        ((cpu1.window_page >> 12) & 0x1ff) as usize,
        ((cpu1.control_page >> 12) & 0x1ff) as usize,
    ] {
        assert_eq!(
            target.read_entry(table, index),
            Err(LiveActiveTargetError::ReservedScratchEntry)
        );
        let write = JournalWrite::test_new(table, index, 0x1234);
        assert_eq!(
            target.apply(&[write], &[]),
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
fn terminal_reaper_layout_is_independent_guarded_and_conflict_free() {
    let writable_start = 0xffff_8000_0200_0000;
    let ist = test_ist_layout(writable_start);
    let thread_guard = writable_start + 15 * PAGE_SIZE;
    let thread = crate::memory::kernel_stack::KernelStackBounds::new(
        thread_guard,
        thread_guard + PAGE_SIZE,
        thread_guard + PAGE_SIZE + crate::memory::kernel_stack::E3_THREAD_STACK_SIZE,
    )
    .unwrap();
    let privilege_guard = thread.top;
    let privilege = crate::memory::kernel_stack::KernelStackBounds::new(
        privilege_guard,
        privilege_guard + PAGE_SIZE,
        privilege_guard + PAGE_SIZE + crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_SIZE,
    )
    .unwrap();
    let terminal_guard = privilege.top;
    let terminal = crate::memory::kernel_stack::KernelStackBounds::new(
        terminal_guard,
        terminal_guard + PAGE_SIZE,
        terminal_guard + PAGE_SIZE + crate::memory::kernel_stack::TERMINAL_REAPER_STACK_SIZE,
    )
    .unwrap();
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
            end: terminal.top,
            kind: SegmentKind::Writable,
        },
    ];
    assert_eq!(
        validate_terminal_reaper_stack_layout(
            &segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            ist,
            privilege,
            &[thread],
            terminal,
        ),
        Ok(())
    );

    for conflicting in [thread, privilege] {
        assert_eq!(
            validate_terminal_reaper_stack_layout(
                &segments,
                FIXTURE_SCRATCH,
                FIXTURE_SCRATCH + PAGE_SIZE,
                ist,
                privilege,
                &[thread],
                conflicting,
            ),
            Err(InactiveGraphError::InvalidSegmentLayout)
        );
    }
    assert_eq!(
        validate_terminal_reaper_stack_layout(
            &segments,
            terminal.guard_page,
            FIXTURE_SCRATCH + PAGE_SIZE,
            ist,
            privilege,
            &[thread],
            terminal,
        ),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );
    let short = crate::memory::kernel_stack::KernelStackBounds::new(
        terminal.guard_page,
        terminal.bottom,
        terminal.top - PAGE_SIZE,
    )
    .unwrap();
    assert_eq!(
        validate_terminal_reaper_stack_layout(
            &segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            ist,
            privilege,
            &[thread],
            short,
        ),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );
}

#[test]
fn h1_runtime_cpu_arena_validates_every_private_stack_and_guard() {
    let arena_start = 0xffff_8000_0400_0000;
    let arena_end = arena_start + 4 * 102 * PAGE_SIZE;
    let slots =
        crate::arch::x86_64::runtime_cpu_stack_layout_from_arena(arena_start, arena_end).unwrap();
    let segments = [
        KernelSegment {
            start: arena_start - 2 * PAGE_SIZE,
            end: arena_start - PAGE_SIZE,
            kind: SegmentKind::Text,
        },
        KernelSegment {
            start: arena_start - PAGE_SIZE,
            end: arena_start,
            kind: SegmentKind::ReadOnly,
        },
        KernelSegment {
            start: arena_start,
            end: arena_end,
            kind: SegmentKind::Writable,
        },
    ];
    assert_eq!(
        validate_runtime_cpu_stack_layout(
            &segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            &slots,
        ),
        Ok(())
    );
    for slot in slots {
        for stack in slot.stacks() {
            assert!(is_runtime_cpu_stack_guard(&slots, stack.guard_page));
            assert!(!is_runtime_cpu_stack_guard(&slots, stack.bottom));
        }
    }

    let mut drifted = slots;
    drifted[1].ap_bootstrap.top -= PAGE_SIZE;
    assert_eq!(
        validate_runtime_cpu_stack_layout(
            &segments,
            FIXTURE_SCRATCH,
            FIXTURE_SCRATCH + PAGE_SIZE,
            &drifted,
        ),
        Err(InactiveGraphError::InvalidSegmentLayout)
    );
    assert_eq!(
        validate_runtime_cpu_stack_layout(
            &segments,
            slots[2].terminal_reaper.guard_page,
            FIXTURE_SCRATCH + PAGE_SIZE,
            &slots,
        ),
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
    assert_eq!(
        fixture.validate(),
        Err(InactiveGraphError::InvalidScratchPath)
    );
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
            page_index(
                FIXTURE_SCRATCH + 3 * crate::cpu::CPU_CAPACITY as u64 * PAGE_SIZE,
                0,
            ),
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

struct FlatRootTarget {
    entries: BTreeMap<(u64, usize), u64>,
    fail_apply: bool,
}

fn empty_flat_root_target() -> FlatRootTarget {
    FlatRootTarget {
        entries: BTreeMap::new(),
        fail_apply: false,
    }
}

impl crate::arch::x86_64::mm::journal::target_seal::Sealed for FlatRootTarget {}

#[allow(
    unsafe_code,
    reason = "the host-only flat table target atomically applies an in-memory write batch"
)]
unsafe impl crate::arch::x86_64::mm::journal::AtomicPageTableTarget for FlatRootTarget {
    type Error = ();

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        Ok(*self.entries.get(&(table.address(), index)).unwrap_or(&0))
    }

    fn apply(
        &mut self,
        writes: &[crate::arch::x86_64::mm::journal::JournalWrite],
        _invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error> {
        if self.fail_apply {
            return Err(());
        }
        for write in writes {
            self.entries
                .insert((write.table().address(), write.index()), write.value());
        }
        Ok(())
    }
}

struct RecordedRootSwitches {
    cpu: Option<CpuIndex>,
    roots: Vec<u64>,
}

impl address_space::root_switch_seal::Sealed for RecordedRootSwitches {}

#[allow(
    unsafe_code,
    reason = "the host switch model records each infallible full-flush publication in order"
)]
unsafe impl RootSwitchTarget for RecordedRootSwitches {
    fn current_cpu(&self) -> Option<CpuIndex> {
        self.cpu
    }

    fn current_root_physical_start(&self) -> Option<u64> {
        self.roots.last().copied()
    }

    fn load_cr3_full_flush(&mut self, root_physical_start: u64) {
        self.roots.push(root_physical_start);
    }
}

fn process_keys() -> (crate::task::ProcessKey, crate::task::ProcessKey) {
    let mut registry = crate::object::ObjectRegistry::<16>::new();
    let mut tasks = crate::task::TaskAuthority::<1, 2, 1, 4>::new();
    let (_group, owner) = tasks.create_root_group(&mut registry).unwrap();
    let (first, _first_owner) = tasks.create_process(&mut registry, &owner).unwrap();
    let (second, _second_owner) = tasks.create_process(&mut registry, &owner).unwrap();
    (first, second)
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic typed roots and authority keys model the host-only root-binding contract"
)]
fn exact_roots_isolate_same_virtual_address_and_switch_a_b_a() {
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x20_000, 8);
    let owner_a = roles.create_table_owner().unwrap();
    let owner_b = roles.create_table_owner().unwrap();
    let identity_a = commit_table(&mut roles, owner_a, TableLevel::Pml4, None);
    let identity_b = commit_table(&mut roles, owner_b, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root_a =
        unsafe { PageTableRoot::from_owned_root(identity_a.physical_start(), capabilities) }
            .unwrap();
    let root_b =
        unsafe { PageTableRoot::from_owned_root(identity_b.physical_start(), capabilities) }
            .unwrap();
    let (process_a, process_b) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<3, 3>::new() };
    let key_a = authority.create_address_space().unwrap();
    let key_b = authority.create_address_space().unwrap();
    let missing_key = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<2, 2>::new();
    bindings
        .bind_primordial(&roles, key_a, process_a, &root_a, identity_a)
        .unwrap();
    bindings
        .bind_owned(&roles, key_b, process_b, root_b, identity_b)
        .unwrap_or_else(|_| panic!("child root binding succeeds"));

    let (selected_a, selected_a_identity, _) =
        bindings.root_for_process(&root_a, process_a).unwrap();
    let (selected_b, selected_b_identity, _) =
        bindings.root_for_process(&root_a, process_b).unwrap();
    assert_ne!(selected_a.frame(), selected_b.frame());
    assert_eq!(selected_a_identity, identity_a);
    assert_eq!(selected_b_identity, identity_b);

    let mut mappings = BTreeMap::new();
    mappings.insert((selected_a.frame().address(), 0x40_0000_u64), 0x90_000_u64);
    mappings.insert((selected_b.frame().address(), 0x40_0000_u64), 0xa0_000_u64);
    assert_eq!(
        mappings[&(identity_a.physical_start(), 0x40_0000)],
        0x90_000
    );
    assert_eq!(
        mappings[&(identity_b.physical_start(), 0x40_0000)],
        0xa0_000
    );

    let cpu = CpuIndex::BOOTSTRAP;
    let mut writes = RecordedRootSwitches {
        cpu: CpuIndex::new(1),
        roots: Vec::new(),
    };
    let initial_failure = bindings
        .activate_selection(
            bindings.prepare_selection(cpu, process_a, key_a).unwrap(),
            None,
            &mut writes,
        )
        .unwrap_err();
    assert_eq!(initial_failure.error(), RootBindingError::CpuMismatch);
    assert!(writes.roots.is_empty());
    let (_, prepared_a, previous) = initial_failure.into_parts();
    assert!(previous.is_none());
    writes.cpu = Some(cpu);
    let mut a0 = bindings
        .activate_selection(prepared_a, None, &mut writes)
        .unwrap_or_else(|failure| panic!("initial A switch failed: {:?}", failure.error()));
    assert_eq!(a0.identity(), identity_a);
    assert_eq!(
        bindings
            .active_root_for_process(&root_a, &a0, cpu, identity_b.physical_start(), process_a,),
        Err(RootBindingError::RootMismatch)
    );
    assert_eq!(
        bindings
            .active_root_for_process(&root_a, &a0, cpu, identity_a.physical_start(), process_a,)
            .unwrap()
            .1,
        identity_a
    );

    let cpu1 = CpuIndex::new(1).unwrap();
    let prepared_b = bindings.prepare_selection(cpu1, process_b, key_b).unwrap();
    writes.cpu = Some(cpu1);
    let mismatch = bindings
        .activate_selection(prepared_b, Some(a0), &mut writes)
        .unwrap_err();
    assert_eq!(mismatch.error(), RootBindingError::CpuMismatch);
    assert_eq!(writes.roots, [identity_a.physical_start()]);
    let (_, prepared_b, previous) = mismatch.into_parts();
    bindings.abandon_selection(prepared_b).unwrap();
    a0 = previous.unwrap();

    writes.cpu = Some(cpu);
    let prepared_b = bindings.prepare_selection(cpu, process_b, key_b).unwrap();
    let stale_a = a0.test_with_root(identity_a.physical_start() + PAGE_SIZE);
    let stale = bindings
        .activate_selection(prepared_b, Some(stale_a), &mut writes)
        .unwrap_err();
    assert_eq!(stale.error(), RootBindingError::RootMismatch);
    assert_eq!(writes.roots, [identity_a.physical_start()]);
    let (_, prepared_b, previous) = stale.into_parts();
    bindings.abandon_selection(prepared_b).unwrap();
    a0 = previous
        .unwrap()
        .test_with_root(identity_a.physical_start());

    let prepared_b = bindings.prepare_selection(cpu, process_b, key_b).unwrap();
    let missing_a = a0.test_with_address_space(missing_key);
    let missing = bindings
        .activate_selection(prepared_b, Some(missing_a), &mut writes)
        .unwrap_err();
    assert_eq!(missing.error(), RootBindingError::Missing);
    assert_eq!(writes.roots, [identity_a.physical_start()]);
    let (_, prepared_b, previous) = missing.into_parts();
    bindings.abandon_selection(prepared_b).unwrap();
    a0 = previous.unwrap().test_with_address_space(key_a);

    let b = bindings
        .activate_selection(
            bindings.prepare_selection(cpu, process_b, key_b).unwrap(),
            Some(a0),
            &mut writes,
        )
        .unwrap_or_else(|failure| panic!("A to B switch failed: {:?}", failure.error()));
    assert_eq!(b.identity(), identity_b);
    let a1 = bindings
        .activate_selection(
            bindings.prepare_selection(cpu, process_a, key_a).unwrap(),
            Some(b),
            &mut writes,
        )
        .unwrap_or_else(|failure| panic!("B to A switch failed: {:?}", failure.error()));
    assert_eq!(a1.identity(), identity_a);
    assert_eq!(
        writes.roots,
        vec![
            identity_a.physical_start(),
            identity_b.physical_start(),
            identity_a.physical_start()
        ]
    );
    assert!(a1.selects_exact(cpu, process_a, key_a));
    let pins = UserPinTracker::<1>::new();
    bindings
        .teardown_empty_owned(
            &mut roles,
            &mut empty_flat_root_target(),
            process_b,
            key_b,
            &pins,
            pins.reserve_teardown(key_b).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        bindings.root_for_process(&root_a, process_b),
        Err(RootBindingError::Missing)
    ));
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic roots model the no-successor terminal handoff before owned-root reclaim"
)]
fn last_runnable_child_switches_to_primordial_before_owned_root_teardown() {
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x34_000, 8);
    let primordial_owner = roles.create_table_owner().unwrap();
    let child_owner = roles.create_table_owner().unwrap();
    let primordial_identity = commit_table(&mut roles, primordial_owner, TableLevel::Pml4, None);
    let child_identity = commit_table(&mut roles, child_owner, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let primordial_root = unsafe {
        PageTableRoot::from_owned_root(primordial_identity.physical_start(), capabilities)
    }
    .unwrap();
    let child_root =
        unsafe { PageTableRoot::from_owned_root(child_identity.physical_start(), capabilities) }
            .unwrap();
    let (primordial_process, child_process) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<2, 2>::new() };
    let primordial_space = authority.create_address_space().unwrap();
    let child_space = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<2, 1>::new();
    bindings
        .bind_primordial(
            &roles,
            primordial_space,
            primordial_process,
            &primordial_root,
            primordial_identity,
        )
        .unwrap();
    bindings
        .bind_owned(
            &roles,
            child_space,
            child_process,
            child_root,
            child_identity,
        )
        .unwrap_or_else(|_| panic!("child root binding succeeds"));

    let cpu = CpuIndex::BOOTSTRAP;
    let mut switches = RecordedRootSwitches {
        cpu: Some(cpu),
        roots: Vec::new(),
    };
    let child = bindings
        .activate_selection(
            bindings
                .prepare_selection(cpu, child_process, child_space)
                .unwrap(),
            None,
            &mut switches,
        )
        .unwrap_or_else(|failure| panic!("initial child switch failed: {:?}", failure.error()));
    let resident_pins = UserPinTracker::<1>::new();
    assert_eq!(
        bindings.teardown_empty_owned(
            &mut roles,
            &mut empty_flat_root_target(),
            child_process,
            child_space,
            &resident_pins,
            resident_pins.reserve_teardown(child_space).unwrap(),
        ),
        Err(RootBindingError::Resident)
    );

    let primordial = bindings
        .activate_selection(
            bindings
                .prepare_selection(cpu, primordial_process, primordial_space)
                .unwrap(),
            Some(child),
            &mut switches,
        )
        .unwrap_or_else(|failure| {
            panic!("terminal safe-root switch failed: {:?}", failure.error())
        });
    assert!(primordial.selects_exact(cpu, primordial_process, primordial_space));
    assert_eq!(
        switches.roots,
        [
            child_identity.physical_start(),
            primordial_identity.physical_start()
        ]
    );
    let pins = UserPinTracker::<1>::new();
    bindings
        .teardown_empty_owned(
            &mut roles,
            &mut empty_flat_root_target(),
            child_process,
            child_space,
            &pins,
            pins.reserve_teardown(child_space).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        bindings.root_for_process(&primordial_root, child_process),
        Err(RootBindingError::Missing)
    ));
    assert_eq!(
        bindings
            .active_root_for_process(
                &primordial_root,
                &primordial,
                cpu,
                primordial_identity.physical_start(),
                primordial_process,
            )
            .unwrap()
            .1,
        primordial_identity
    );
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic PML4s exercise the architecture-private execution-root switch contract"
)]
fn kernel_execution_root_isolated_from_process_bindings_and_switches_both_directions() {
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x38_000, 8);
    let primordial_owner = roles.create_table_owner().unwrap();
    let child_owner = roles.create_table_owner().unwrap();
    let kernel_owner = roles.create_table_owner().unwrap();
    let primordial_identity = commit_table(&mut roles, primordial_owner, TableLevel::Pml4, None);
    let child_identity = commit_table(&mut roles, child_owner, TableLevel::Pml4, None);
    let kernel_identity = commit_table(&mut roles, kernel_owner, TableLevel::Pml4, None);
    assert_ne!(kernel_identity.owner(), primordial_identity.owner());
    assert_ne!(kernel_identity.owner(), child_identity.owner());
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let primordial_root = unsafe {
        PageTableRoot::from_owned_root(primordial_identity.physical_start(), capabilities)
    }
    .unwrap();
    let child_root =
        unsafe { PageTableRoot::from_owned_root(child_identity.physical_start(), capabilities) }
            .unwrap();
    let kernel_root =
        unsafe { PageTableRoot::from_owned_root(kernel_identity.physical_start(), capabilities) }
            .unwrap();
    let (primordial_process, child_process) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<2, 2>::new() };
    let primordial_space = authority.create_address_space().unwrap();
    let child_space = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<2, 1>::new();
    bindings
        .bind_primordial(
            &roles,
            primordial_space,
            primordial_process,
            &primordial_root,
            primordial_identity,
        )
        .unwrap();
    bindings
        .bind_owned(
            &roles,
            child_space,
            child_process,
            child_root,
            child_identity,
        )
        .unwrap_or_else(|_| panic!("child root binding succeeds"));
    let cpu = CpuIndex::BOOTSTRAP;
    let mut execution_roots = KernelExecutionRoots::<1>::new();
    execution_roots
        .bind(cpu, kernel_root, kernel_identity)
        .unwrap();
    assert_eq!(execution_roots.get(cpu).unwrap().cpu(), cpu);
    assert_eq!(
        bindings
            .root_for_process(&primordial_root, child_process)
            .unwrap()
            .1,
        child_identity
    );

    let mut switches = RecordedRootSwitches {
        cpu: Some(cpu),
        roots: Vec::new(),
    };
    let child = bindings
        .activate_selection(
            bindings
                .prepare_selection(cpu, child_process, child_space)
                .unwrap(),
            None,
            &mut switches,
        )
        .unwrap_or_else(|failure| panic!("initial Process switch failed: {:?}", failure.error()));
    // A Process token alone is not authority to leave the Process root: the
    // observed current CR3 must still name that exact root. The failed
    // preflight returns the move-only selection intact and performs no kernel
    // root load or residency release.
    switches
        .roots
        .push(child_identity.physical_start() + PAGE_SIZE);
    let failure = bindings
        .activate_kernel_execution_root(execution_roots.get(cpu).unwrap(), child, &mut switches)
        .unwrap_err();
    let (error, child) = failure;
    assert_eq!(error, RootBindingError::RootMismatch);
    assert!(child.selects_exact(cpu, child_process, child_space));
    assert_eq!(switches.roots.len(), 2);
    switches.roots.pop();
    let kernel = bindings
        .activate_kernel_execution_root(execution_roots.get(cpu).unwrap(), child, &mut switches)
        .unwrap();
    assert_eq!(kernel.cpu(), cpu);
    assert_eq!(
        kernel.root_physical_start(),
        kernel_identity.physical_start()
    );

    let child = bindings
        .activate_from_kernel_execution_root(
            bindings
                .prepare_selection(cpu, child_process, child_space)
                .unwrap(),
            kernel,
            &mut switches,
        )
        .unwrap_or_else(|failure| panic!("kernel-to-Process switch failed: {:?}", failure.error()));
    assert!(child.selects_exact(cpu, child_process, child_space));
    assert_eq!(
        switches.roots,
        [
            child_identity.physical_start(),
            kernel_identity.physical_start(),
            child_identity.physical_start(),
        ]
    );
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic CPU mismatch proves kernel-to-Process pre-CR3 token recovery"
)]
fn kernel_execution_root_switch_recovers_tokens_before_cr3_on_cpu_mismatch() {
    let mut roles = synthetic_frame_role_manager::<1, 12>(0x3a_000, 6);
    let process_owner = roles.create_table_owner().unwrap();
    let kernel_owner = roles.create_table_owner().unwrap();
    let process_identity = commit_table(&mut roles, process_owner, TableLevel::Pml4, None);
    let kernel_identity = commit_table(&mut roles, kernel_owner, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let process_root =
        unsafe { PageTableRoot::from_owned_root(process_identity.physical_start(), capabilities) }
            .unwrap();
    let kernel_root =
        unsafe { PageTableRoot::from_owned_root(kernel_identity.physical_start(), capabilities) }
            .unwrap();
    let (process, _) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<1, 1>::new() };
    let address_space = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<1, 2>::new();
    bindings
        .bind_owned(
            &roles,
            address_space,
            process,
            process_root,
            process_identity,
        )
        .unwrap_or_else(|_| panic!("process binding succeeds"));
    let cpu0 = CpuIndex::BOOTSTRAP;
    let cpu1 = CpuIndex::new(1).unwrap();
    let mut execution_roots = KernelExecutionRoots::<2>::new();
    execution_roots
        .bind(cpu0, kernel_root, kernel_identity)
        .unwrap();
    let mut switches = RecordedRootSwitches {
        cpu: Some(cpu1),
        roots: Vec::new(),
    };
    let prepared = bindings
        .prepare_selection(cpu0, process, address_space)
        .unwrap();
    let kernel = execution_roots.get(cpu0).unwrap().test_assume_active();
    let failure = bindings
        .activate_from_kernel_execution_root(prepared, kernel, &mut switches)
        .unwrap_err();
    let (error, prepared, recovered_kernel) = failure.into_parts();
    assert_eq!(error, RootBindingError::CpuMismatch);
    assert_eq!(recovered_kernel.cpu(), cpu0);
    assert_eq!(prepared.cpu(), cpu0);
    assert!(switches.roots.is_empty());
    bindings.abandon_selection(prepared).unwrap();

    let prepared = bindings
        .prepare_selection(cpu0, process, address_space)
        .unwrap();
    let kernel = execution_roots.get(cpu0).unwrap().test_assume_active();
    let mut wrong_root = RecordedRootSwitches {
        cpu: Some(cpu0),
        roots: vec![kernel_identity.physical_start() + PAGE_SIZE],
    };
    let failure = bindings
        .activate_from_kernel_execution_root(prepared, kernel, &mut wrong_root)
        .unwrap_err();
    let (error, prepared, recovered_kernel) = failure.into_parts();
    assert_eq!(error, RootBindingError::RootMismatch);
    assert_eq!(recovered_kernel.cpu(), cpu0);
    assert_eq!(prepared.cpu(), cpu0);
    assert_eq!(wrong_root.roots.len(), 1);
    bindings.abandon_selection(prepared).unwrap();
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic scheduler siblings exercise retained move-only root ownership without live CR3 access"
)]
fn same_process_sibling_switch_retains_exact_active_root_selection() {
    let mut registry = crate::object::ObjectRegistry::<16>::new();
    let mut tasks = crate::task::TaskAuthority::<1, 1, 2, 2>::new();
    let (_group, group_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &group_owner).unwrap();
    let process_owner = registry.retain_internal_from_handle(&process_ref).unwrap();
    let (first, _first_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (second, _second_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert_ne!(first, second);
    assert_eq!(tasks.thread_process(first).unwrap(), process);
    assert_eq!(tasks.thread_process(second).unwrap(), process);

    let mut roles = synthetic_frame_role_manager::<1, 8>(0x3c_000, 4);
    let owner = roles.create_table_owner().unwrap();
    let identity = commit_table(&mut roles, owner, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root =
        unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }.unwrap();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<1, 1>::new() };
    let address_space = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<1, 1>::new();
    bindings
        .bind_primordial(&roles, address_space, process, &root, identity)
        .unwrap();
    let cpu = CpuIndex::BOOTSTRAP;
    let mut writes = RecordedRootSwitches {
        cpu: Some(cpu),
        roots: Vec::new(),
    };
    let active = bindings
        .activate_selection(
            bindings
                .prepare_selection(cpu, process, address_space)
                .unwrap(),
            None,
            &mut writes,
        )
        .unwrap_or_else(|failure| {
            panic!("initial sibling root switch failed: {:?}", failure.error())
        });
    let mut carrier_thread = first;
    assert_eq!(carrier_thread, first);
    assert!(active.selects_exact(cpu, process, address_space));
    carrier_thread = second;
    assert_eq!(carrier_thread, second);
    assert!(active.selects_exact(cpu, process, address_space));
    assert_eq!(
        bindings
            .active_root_for_process(&root, &active, cpu, identity.physical_start(), process,)
            .unwrap()
            .1,
        identity
    );
    assert_eq!(writes.roots, [identity.physical_start()]);
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic roots exercise mismatch rejection without dereferencing physical frames"
)]
fn key_root_mismatch_is_rejected_and_residency_blocks_teardown() {
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x30_000, 8);
    let owner_a = roles.create_table_owner().unwrap();
    let owner_b = roles.create_table_owner().unwrap();
    let identity_a = commit_table(&mut roles, owner_a, TableLevel::Pml4, None);
    let identity_b = commit_table(&mut roles, owner_b, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root_a =
        unsafe { PageTableRoot::from_owned_root(identity_a.physical_start(), capabilities) }
            .unwrap();
    let mismatched =
        unsafe { PageTableRoot::from_owned_root(identity_a.physical_start(), capabilities) }
            .unwrap();
    let (process_a, process_b) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<2, 2>::new() };
    let key_a = authority.create_address_space().unwrap();
    let key_b = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<2, 1>::new();
    bindings
        .bind_primordial(&roles, key_a, process_a, &root_a, identity_a)
        .unwrap();
    let (error, _returned_root) = bindings
        .bind_owned(&roles, key_b, process_b, mismatched, identity_b)
        .unwrap_err();
    assert_eq!(error, RootBindingError::RootMismatch);

    let root_b =
        unsafe { PageTableRoot::from_owned_root(identity_b.physical_start(), capabilities) }
            .unwrap();
    bindings
        .bind_owned(&roles, key_b, process_b, root_b, identity_b)
        .unwrap_or_else(|_| panic!("correct child root binds"));
    let resident = bindings
        .prepare_selection(CpuIndex::BOOTSTRAP, process_b, key_b)
        .unwrap();
    // The rejected mismatched bind above must not consume or publish an
    // ambiguous epoch: primordial is generation 1, this first successful
    // child binding is generation 2.
    assert_eq!(resident.binding_generation(), 2);
    let resident_pins = UserPinTracker::<1>::new();
    assert_eq!(
        bindings.teardown_empty_owned(
            &mut roles,
            &mut empty_flat_root_target(),
            process_b,
            key_b,
            &resident_pins,
            resident_pins.reserve_teardown(key_b).unwrap(),
        ),
        Err(RootBindingError::Resident)
    );
    bindings.abandon_selection(resident).unwrap();
    let pins = UserPinTracker::<1>::new();
    bindings
        .teardown_empty_owned(
            &mut roles,
            &mut empty_flat_root_target(),
            process_b,
            key_b,
            &pins,
            pins.reserve_teardown(key_b).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        bindings.root_for_process(&root_a, process_b),
        Err(RootBindingError::Missing)
    ));
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic roots verify that a released Process/key pair never reuses its binding epoch"
)]
fn owned_root_rebind_mints_a_distinct_nonzero_binding_epoch() {
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x31_000, 16);
    let owner_a = roles.create_table_owner().unwrap();
    let owner_b = roles.create_table_owner().unwrap();
    let identity_a = commit_table(&mut roles, owner_a, TableLevel::Pml4, None);
    let identity_b = commit_table(&mut roles, owner_b, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root_a =
        unsafe { PageTableRoot::from_owned_root(identity_a.physical_start(), capabilities) }
            .unwrap();
    let root_b =
        unsafe { PageTableRoot::from_owned_root(identity_b.physical_start(), capabilities) }
            .unwrap();
    let (process_a, process_b) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<2, 2>::new() };
    let key_a = authority.create_address_space().unwrap();
    let key_b = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<2, 1>::new();
    bindings
        .bind_primordial(&roles, key_a, process_a, &root_a, identity_a)
        .unwrap();
    bindings
        .bind_owned(&roles, key_b, process_b, root_b, identity_b)
        .unwrap();
    let first = bindings
        .prepare_selection(CpuIndex::BOOTSTRAP, process_b, key_b)
        .unwrap();
    assert_eq!(first.binding_generation(), 2);
    bindings.abandon_selection(first).unwrap();
    let pins = UserPinTracker::<1>::new();
    bindings
        .teardown_empty_owned(
            &mut roles,
            &mut empty_flat_root_target(),
            process_b,
            key_b,
            &pins,
            pins.reserve_teardown(key_b).unwrap(),
        )
        .unwrap();
    let owner_c = roles.create_table_owner().unwrap();
    let identity_c = commit_table(&mut roles, owner_c, TableLevel::Pml4, None);
    let root_c =
        unsafe { PageTableRoot::from_owned_root(identity_c.physical_start(), capabilities) }
            .unwrap();
    bindings
        .bind_owned(&roles, key_b, process_b, root_c, identity_c)
        .unwrap();
    let rebound = bindings
        .prepare_selection(CpuIndex::BOOTSTRAP, process_b, key_b)
        .unwrap();
    assert_eq!(rebound.binding_generation(), 3);
    assert_ne!(rebound.binding_generation(), 0);
    bindings.abandon_selection(rebound).unwrap();
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic roots make binding-generation exhaustion deterministic without consuming a candidate root"
)]
fn binding_generation_exhaustion_fails_closed_without_publishing_a_root() {
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x32_000, 8);
    let owner_a = roles.create_table_owner().unwrap();
    let owner_b = roles.create_table_owner().unwrap();
    let identity_a = commit_table(&mut roles, owner_a, TableLevel::Pml4, None);
    let identity_b = commit_table(&mut roles, owner_b, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root_a =
        unsafe { PageTableRoot::from_owned_root(identity_a.physical_start(), capabilities) }
            .unwrap();
    let root_b =
        unsafe { PageTableRoot::from_owned_root(identity_b.physical_start(), capabilities) }
            .unwrap();
    let (process_a, process_b) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<2, 2>::new() };
    let key_a = authority.create_address_space().unwrap();
    let key_b = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<2, 1>::new();
    bindings.set_next_binding_generation_for_test(u64::MAX);
    bindings
        .bind_primordial(&roles, key_a, process_a, &root_a, identity_a)
        .unwrap();
    let (error, returned_root) = bindings
        .bind_owned(&roles, key_b, process_b, root_b, identity_b)
        .unwrap_err();
    assert_eq!(error, RootBindingError::GenerationExhausted);
    assert_eq!(returned_root.frame().address(), identity_b.physical_start());
    assert!(matches!(
        bindings.prepare_selection(CpuIndex::BOOTSTRAP, process_b, key_b),
        Err(RootBindingError::Missing)
    ));
    assert_eq!(
        bindings
            .prepare_selection(CpuIndex::BOOTSTRAP, process_a, key_a)
            .unwrap()
            .binding_generation(),
        u64::MAX
    );
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic flat tables model an inactive empty child hierarchy and retryable leaf rejection"
)]
fn empty_child_hierarchy_is_retired_bottom_up_and_nonempty_rejection_is_retryable() {
    let mut roles = synthetic_frame_role_manager::<1, 16>(0x38_000, 8);
    let initial = roles.available_frames();
    let owner = roles.create_table_owner().unwrap();
    let identity = commit_table(&mut roles, owner, TableLevel::Pml4, None);
    let pdpt = commit_table(&mut roles, owner, TableLevel::Pdpt, Some(identity));
    let pd = commit_table(&mut roles, owner, TableLevel::Pd, Some(pdpt));
    let pt = commit_table(&mut roles, owner, TableLevel::Pt, Some(pd));
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root =
        unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }.unwrap();
    let (process, _) = process_keys();
    let mut authority =
        unsafe { crate::memory::address_region::AddressSpaceAuthority::<1, 1>::new() };
    let key = authority.create_address_space().unwrap();
    let mut bindings = AddressSpaceRootBindings::<1, 1>::new();
    bindings
        .bind_owned(&roles, key, process, root, identity)
        .unwrap_or_else(|_| panic!("owned root binds"));
    let supervisor_sentinel = 0x88_000 | PRESENT | WRITABLE;
    let mut target = empty_flat_root_target();
    target.entries.insert(
        (identity.physical_start(), 0),
        pdpt.physical_start() | PRESENT | WRITABLE | USER,
    );
    target.entries.insert(
        (pdpt.physical_start(), 0),
        pd.physical_start() | PRESENT | WRITABLE | USER,
    );
    target.entries.insert(
        (pd.physical_start(), 2),
        pt.physical_start() | PRESENT | WRITABLE | USER,
    );
    target
        .entries
        .insert((identity.physical_start(), 256), supervisor_sentinel);
    target
        .entries
        .insert((pt.physical_start(), 0), 0x90_000 | PRESENT | USER);

    let pins = UserPinTracker::<1>::new();
    let foreign_pins = UserPinTracker::<1>::new();
    assert_eq!(
        bindings.teardown_empty_owned(
            &mut roles,
            &mut target,
            process,
            key,
            &pins,
            foreign_pins.reserve_teardown(key).unwrap(),
        ),
        Err(RootBindingError::RootMismatch)
    );
    assert_ne!(target.entries[&(identity.physical_start(), 0)], 0);
    assert_eq!(roles.available_frames(), initial - 4);
    assert_eq!(
        bindings.teardown_empty_owned(
            &mut roles,
            &mut target,
            process,
            key,
            &pins,
            pins.reserve_teardown(key).unwrap(),
        ),
        Err(RootBindingError::RootMismatch)
    );
    let primordial_placeholder =
        unsafe { PageTableRoot::from_owned_root(identity.physical_start(), capabilities) }.unwrap();
    assert_eq!(
        bindings
            .root_for_process(&primordial_placeholder, process)
            .unwrap()
            .1,
        identity
    );
    let prepared = bindings
        .prepare_selection(CpuIndex::BOOTSTRAP, process, key)
        .unwrap();
    bindings.abandon_selection(prepared).unwrap();
    target.entries.insert((pt.physical_start(), 0), 0);
    target.fail_apply = true;
    assert_eq!(
        bindings.teardown_empty_owned(
            &mut roles,
            &mut target,
            process,
            key,
            &pins,
            pins.reserve_teardown(key).unwrap(),
        ),
        Err(RootBindingError::RootMismatch)
    );
    assert_ne!(target.entries[&(identity.physical_start(), 0)], 0);
    assert_eq!(roles.available_frames(), initial - 4);
    assert_eq!(
        bindings
            .root_for_process(&primordial_placeholder, process)
            .unwrap()
            .1,
        identity
    );
    let prepared = bindings
        .prepare_selection(CpuIndex::BOOTSTRAP, process, key)
        .unwrap();
    bindings.abandon_selection(prepared).unwrap();
    target.fail_apply = false;
    bindings
        .teardown_empty_owned(
            &mut roles,
            &mut target,
            process,
            key,
            &pins,
            pins.reserve_teardown(key).unwrap(),
        )
        .unwrap();
    assert_eq!(
        target.entries[&(identity.physical_start(), 0)],
        0,
        "the child low half must be disconnected"
    );
    assert_eq!(target.entries[&(pdpt.physical_start(), 0)], 0);
    assert_eq!(target.entries[&(pd.physical_start(), 2)], 0);
    assert_eq!(
        target.entries[&(identity.physical_start(), 256)],
        supervisor_sentinel,
        "shared supervisor entries must remain untouched"
    );
    assert_eq!(roles.available_frames(), initial);
    assert_eq!(roles.check_invariants(), Ok(()));
    assert!(matches!(
        bindings.root_for_process(&primordial_placeholder, process),
        Err(RootBindingError::Missing)
    ));
}

#[test]
#[allow(
    unsafe_code,
    reason = "synthetic flat tables model typed kernel-half capture and child initialization"
)]
fn kernel_half_copy_is_supervisor_only_and_leaves_child_low_half_empty() {
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x40_000, 4);
    let owner_a = roles.create_table_owner().unwrap();
    let owner_b = roles.create_table_owner().unwrap();
    let identity_a = commit_table(&mut roles, owner_a, TableLevel::Pml4, None);
    let identity_b = commit_table(&mut roles, owner_b, TableLevel::Pml4, None);
    let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
    let root_a =
        unsafe { PageTableRoot::from_owned_root(identity_a.physical_start(), capabilities) }
            .unwrap();
    let mut target = FlatRootTarget {
        entries: BTreeMap::new(),
        fail_apply: false,
    };
    target.entries.insert(
        (identity_a.physical_start(), 256),
        0x80_000 | PRESENT | WRITABLE,
    );
    target.entries.insert(
        (identity_a.physical_start(), 511),
        0x81_000 | PRESENT | WRITABLE | NO_EXECUTE,
    );
    let shared = KernelHalfBinding::capture(&mut target, &roles, &root_a, identity_a).unwrap();
    assert_eq!(shared.primordial_identity(), identity_a);
    let child =
        FrameAddress::new(identity_b.physical_start(), capabilities.physical_limit()).unwrap();
    shared.install(&mut target, child).unwrap();
    for index in 0..256 {
        assert_eq!(target.entries.get(&(child.address(), index)), None);
    }
    assert_eq!(
        target.entries[&(child.address(), 256)],
        0x80_000 | PRESENT | WRITABLE
    );
    assert_eq!(
        target.entries[&(child.address(), 511)],
        0x81_000 | PRESENT | WRITABLE | NO_EXECUTE
    );
}

#[test]
fn terminal_reaper_reuses_replacement_selected_by_deferred_retirement() {
    let (
        mut registry,
        mut tasks,
        root_owner,
        process_handle,
        current,
        current_handle,
        replacement,
        replacement_handle,
    ) = terminal_two_thread_fixture();
    let execution = ExecutionDomain::<2>::new(terminal_stack_bounds::<2>()).unwrap();
    execution
        .start_thread(&mut tasks, current, terminal_start_state(11))
        .unwrap();
    execution
        .start_thread(&mut tasks, replacement, terminal_start_state(12))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));

    let pins = tasks.exit_thread(current, 0).unwrap();
    let (retired, deferred) = execution.retire_exit_pins_defer_current(pins, current);
    assert_eq!(execution.scheduler_state(current), None);
    assert_eq!(execution.suspended_claim_on(CpuIndex::BOOTSTRAP), None);
    let deferred_pins = execution.reclaim_deferred_current(deferred);
    assert_eq!(execution.suspended_claim_on(CpuIndex::BOOTSTRAP), None);

    // The old production path called `schedule_next` here and failed with
    // CurrentThreadRunning. The helper is the reaper's exact decision.
    assert_eq!(execution.terminal_reaper_next(), Some(replacement));
    assert_eq!(
        execution.scheduler_state(replacement),
        Some(SchedulerThreadState::Running)
    );

    let (process_pin, thread_pins) = retired.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let (process_pin, thread_pins) = deferred_pins.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    for reference in [current_handle, replacement_handle, process_handle] {
        let _ = registry.release_handle(reference).unwrap();
    }
    let _ = registry.release_internal(root_owner).unwrap();
}

#[test]
fn terminal_reaper_schedules_work_published_after_deferred_retirement() {
    let (
        mut registry,
        mut tasks,
        root_owner,
        process_handle,
        current,
        current_handle,
        awakened,
        awakened_handle,
    ) = terminal_two_thread_fixture();
    let execution = ExecutionDomain::<2>::new(terminal_stack_bounds::<2>()).unwrap();
    execution
        .start_thread(&mut tasks, current, terminal_start_state(13))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));

    let pins = tasks.exit_thread(current, 0).unwrap();
    let (retired, deferred) = execution.retire_exit_pins_defer_current(pins, current);
    assert_eq!(
        execution.current_thread_on(crate::cpu::CpuIndex::BOOTSTRAP),
        None
    );
    assert_eq!(execution.scheduler_state(current), None);

    // Model work published by the terminal EXITED cleanup before the reaper
    // chooses a fresh current Thread.
    execution
        .start_thread(&mut tasks, awakened, terminal_start_state(14))
        .unwrap();
    let deferred_pins = execution.reclaim_deferred_current(deferred);
    assert_eq!(execution.suspended_claim_on(CpuIndex::BOOTSTRAP), None);
    assert_eq!(execution.terminal_reaper_next(), Some(awakened));
    assert_eq!(
        execution.scheduler_state(awakened),
        Some(SchedulerThreadState::Running)
    );

    let (process_pin, thread_pins) = retired.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    let (process_pin, thread_pins) = deferred_pins.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        assert!(registry.release_internal(pin).unwrap().is_none());
    }
    for reference in [current_handle, awakened_handle, process_handle] {
        let _ = registry.release_handle(reference).unwrap();
    }
    let _ = registry.release_internal(root_owner).unwrap();
}
