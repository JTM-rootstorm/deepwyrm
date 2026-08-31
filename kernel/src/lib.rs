//! Deepwyrm kernel crate boundary.
//!
//! The portable boot-intake model remains host-testable. Freestanding x86_64
//! entry installs the kernel's own diagnostic and descriptor state before it
//! validates the loader-owned handoff.

#![no_std]
#![deny(unsafe_code)]

pub mod arch;
#[allow(
    dead_code,
    reason = "DW0-F9 atomic wait/wake foundations are consumed by the selector-16 runtime"
)]
pub(crate) mod atomic_wait;
pub mod boot;
pub(crate) mod cpu;
pub mod debug;
#[allow(
    dead_code,
    reason = "DW1-D2 DeviceResource payload and PIO authority precede D5 boot-grant publication"
)]
pub(crate) mod device;
#[allow(
    dead_code,
    reason = "DW0-D5 exposes handle/object services ahead of DW0-E syscall consumers"
)]
pub(crate) mod handle;
pub mod interrupt;
#[allow(
    dead_code,
    reason = "DW0-F5 Channel foundations precede F6 transfer and F7 live wait consumers"
)]
pub(crate) mod ipc;
pub mod memory;
#[allow(
    dead_code,
    reason = "DW0-D5 consumes generic lifetime primitives ahead of DW0-E process/syscall ownership"
)]
pub(crate) mod object;
#[path = "handle/service.rs"]
#[allow(
    dead_code,
    reason = "DW0-D5 services precede their DW0-E syscall adapters"
)]
pub(crate) mod service;
#[allow(
    dead_code,
    reason = "DW0-E3 synchronization precedes E4/E5 shared execution consumers"
)]
pub(crate) mod sync;
#[allow(
    dead_code,
    reason = "DW0-E1 syscall decoding precedes E4 architecture entry and E5 handler integration"
)]
pub(crate) mod syscall;
#[allow(
    dead_code,
    reason = "DW0-E2 task payload authority precedes E3 scheduling and E5 syscall consumers"
)]
pub(crate) mod task;
#[allow(
    dead_code,
    reason = "DW0-F3 time/deadline services precede F4 wait and F8 Timer consumers"
)]
pub(crate) mod time;
#[allow(
    dead_code,
    reason = "DW0-F4 wait/Event foundations precede F7 generic wait syscall activation"
)]
pub(crate) mod wait;

#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use boot::BootInfoByteReader;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const MAX_X86_PHYSICAL_ADDRESS_EXCLUSIVE: u64 = 1_u64 << 52;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const BOOTSTRAP_FRAME_RANGE_CAPACITY: usize = memory::boot_map::MAX_SANITIZED_USABLE_RANGES;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
// Selector 28 keeps the bootstrap/controller pair and ten actor address spaces
// resident together.  The former 544-slot registry exhausted while reserving
// the fourth live child root, before the workload could be armed.  Keep useful
// headroom for the complete twelve-process image and its mapping transactions;
// this is role-metadata capacity, not a physical-memory or ABI limit.
const BOOTSTRAP_FRAME_ROLE_CAPACITY: usize = 4096;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct BootstrapStorage<T>(core::cell::UnsafeCell<core::mem::MaybeUninit<T>>);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<T> BootstrapStorage<T> {
    const fn uninit() -> Self {
        Self(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()))
    }

    fn slot(&self) -> *mut core::mem::MaybeUninit<T> {
        self.0.get()
    }
}

// SAFETY: these cells are reachable only from the one-shot BSP `kernel_main`
// path before AP startup; no shared reference to their contents is issued.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one-shot BSP ownership serializes bootstrap static storage"
)]
unsafe impl<T> Sync for BootstrapStorage<T> {}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BOOTSTRAP_ROLE_MANAGER: BootstrapStorage<
    memory::frame_roles::FrameRoleManager<
        BOOTSTRAP_FRAME_RANGE_CAPACITY,
        BOOTSTRAP_FRAME_ROLE_CAPACITY,
    >,
> = BootstrapStorage::uninit();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BOOTSTRAP_RESERVATIONS: BootstrapStorage<
    [memory::boot_map::BootstrapReservation; memory::boot_map::MAX_BOOTSTRAP_RESERVATIONS],
> = BootstrapStorage::uninit();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BOOTSTRAP_SANITIZED_MAP: BootstrapStorage<memory::boot_map::SanitizedBootMap> =
    BootstrapStorage::uninit();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BOOTSTRAP_ACPI_WORKSPACE: BootstrapStorage<arch::x86_64::acpi::AcpiSnapshotWorkspace> =
    BootstrapStorage::uninit();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const H1_AP_PARK_POLL_LIMIT: usize = 10_000_000;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "an AP initialization failure cannot enable interrupts or resume shared execution"
)]
fn park_h1_application_processor() -> ! {
    loop {
        // SAFETY: H1 APs deliberately expose no runnable work. Keeping IF
        // clear prevents them from entering shared runtime state before H2.
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "an initialized H2 AP uses the STI-HLT interrupt shadow to sleep without losing a fixed-IPI wake"
)]
fn idle_h2_application_processor() -> ! {
    let cpu_index = arch::x86_64::syscall::current_cpu_index_for_diagnostics()
        .unwrap_or_else(|| park_h1_application_processor());
    loop {
        let snapshot = arch::x86_64::smp::live_cpu_registry()
            .snapshot(cpu_index)
            .unwrap_or_else(|_| park_h1_application_processor());
        if snapshot.lifecycle == arch::x86_64::smp::CpuLifecycle::Executing {
            break;
        }
        if snapshot.lifecycle != arch::x86_64::smp::CpuLifecycle::Parked {
            park_h1_application_processor();
        }
        core::hint::spin_loop();
    }
    arch::x86_64::syscall::enter_bound_idle_scheduler()
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn fail_h1_application_processor(cpu_index: usize, reason: u32) -> ! {
    let _ = arch::x86_64::smp::live_cpu_registry().fail(cpu_index, reason);
    park_h1_application_processor()
}

/// Higher-half H1 entry reached only from the validated low trampoline.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the AP consumes its private descriptor and machine-register slot before publication"
)]
extern "sysv64" fn dw_x86_64_ap_higher_half_entry(cpu_index: u32, local_apic_id: u32) -> ! {
    let cpu_index = cpu_index as usize;
    let Ok(local_apic_id) = u8::try_from(local_apic_id) else {
        park_h1_application_processor();
    };
    let registry = arch::x86_64::smp::live_cpu_registry();
    let Ok(snapshot) = registry.snapshot(cpu_index) else {
        park_h1_application_processor();
    };
    if cpu_index == 0
        || snapshot.lifecycle != arch::x86_64::smp::CpuLifecycle::Starting
        || snapshot.local_apic_id != local_apic_id
    {
        fail_h1_application_processor(cpu_index, 0x101);
    }

    // SAFETY: the trampoline entered the active Deep root on this CPU's
    // private bootstrap stack with IF clear and passes a registry-validated
    // nonzero slot exactly once.
    if unsafe { arch::x86_64::initialize_ap_runtime_slot(cpu_index) }.is_err() {
        fail_h1_application_processor(cpu_index, 0x102);
    }
    let Ok(local_apic_base) = arch::x86_64::smp::live_local_apic_physical_base() else {
        fail_h1_application_processor(cpu_index, 0x103);
    };
    if time::initialize_ap_local_apic(cpu_index, local_apic_id, local_apic_base).is_err() {
        fail_h1_application_processor(cpu_index, 0x104);
    }
    if registry
        .publish_online(cpu_index, local_apic_id, 1)
        .is_err()
    {
        fail_h1_application_processor(cpu_index, 0x105);
    }
    #[cfg(not(feature = "test-support"))]
    let _ = debug::emit_early_cpu_state_record(cpu_index, local_apic_id, "online");
    if registry.park(cpu_index).is_err() {
        park_h1_application_processor();
    }
    #[cfg(not(feature = "test-support"))]
    let _ = debug::emit_early_cpu_state_record(cpu_index, local_apic_id, "parked");
    idle_h2_application_processor()
}

/// Transfers from the raw architecture entry into validated DW0-B bring-up.
///
/// This symbol is architecture-internal. The loader enters through
/// `_dw_kernel_entry`, never by calling this Rust function directly.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "raw entry establishes the single-BSP descriptor-install preconditions"
)]
pub(crate) fn kernel_main(boot_info_physical: u64) -> ! {
    // SAFETY: the raw entry shim has already switched to the kernel-owned
    // stack and enforces the reconciled single-BSP, IF-clear entry contract.
    if let Err(error) = unsafe { arch::x86_64::install_early_descriptors() } {
        panic!("failed to install early x86_64 descriptors: {error:?}");
    }

    let reader = IdentityMappedBootInfoReader;
    let boot_info = boot::validate_boot_info(&reader, boot_info_physical)
        .unwrap_or_else(|error| panic!("invalid DwBootInfoV1 handoff: {error:?}"));
    let boot_resource_grants = boot_info.boot_resource_grants();

    #[cfg(not(feature = "test-support"))]
    let primordial_modules = boot_info
        .primordial_modules()
        .unwrap_or_else(|error| panic!("invalid primordial modules: {error:?}"));
    #[cfg(feature = "test-support")]
    let primordial_modules = test_support::BUILD_GUEST_TEST.is_primordial().then(|| {
        boot_info
            .primordial_modules()
            .unwrap_or_else(|error| panic!("invalid primordial modules: {error:?}"))
    });

    #[cfg(feature = "test-support")]
    match test_support::BUILD_GUEST_TEST {
        test_support::BuildGuestTest::BootHandoffPass => test_support::complete_pass(0),
        test_support::BuildGuestTest::ExceptionFailPath => {
            test_support::trigger_expected_invalid_opcode()
        }
        test_support::BuildGuestTest::PanicPath => panic!("DW0-B panic-path guest test"),
        test if test.is_memory_foundation() || test.is_task_userspace() => {}
        #[cfg(deepwyrm_f9_guest)]
        test if test.is_f9_userspace() => {}
        #[cfg(deepwyrm_f12_guest)]
        test if test.is_f12_userspace() => {}
        test if test.is_primordial() => {}
        _ => unreachable!("all build-selected guest tests have explicit dispatch"),
    }

    {
        let physical_width =
            u8::try_from(boot_info.paging_handoff().header().physical_address_width)
                .unwrap_or_else(|_| panic!("paging handoff physical width is not representable"));
        let physical_limit =
            memory::physical::PhysicalAddressLimit::from_address_bits(physical_width)
                .unwrap_or_else(|error| panic!("invalid paging physical limit: {error:?}"));
        // SAFETY: `kernel_main` is the sole BSP owner and this static slot is
        // uninitialized. A sanitizer failure terminates this boot attempt.
        let sanitized = unsafe {
            memory::boot_map::sanitize_boot_map_in(
                &mut *BOOTSTRAP_SANITIZED_MAP.slot(),
                &boot_info,
                boot_info_physical,
                physical_limit,
            )
        }
        .unwrap_or_else(|error| panic!("invalid bootstrap memory map: {error:?}"));
        let reservations = unsafe {
            let array = (*BOOTSTRAP_RESERVATIONS.slot()).as_mut_ptr();
            let element = array.cast::<memory::boot_map::BootstrapReservation>();
            for index in 0..memory::boot_map::MAX_BOOTSTRAP_RESERVATIONS {
                element
                    .add(index)
                    .write(memory::boot_map::BootstrapReservation::placeholder());
            }
            &mut *array
        };
        let reservation_count = memory::boot_map::collect_bootstrap_reservations(
            &boot_info,
            boot_info_physical,
            reservations,
        )
        .unwrap_or_else(|error| panic!("invalid bootstrap reservations: {error:?}"));
        // SAFETY: `kernel_main` is the non-reentrant BSP owner of the consumed
        // boot snapshot and has created no other allocator over its candidates.
        let (roles, memory_witness) = unsafe {
            memory::frame_roles::FrameRoleManager::<
                BOOTSTRAP_FRAME_RANGE_CAPACITY,
                BOOTSTRAP_FRAME_ROLE_CAPACITY,
            >::from_boot_map_in(
                &mut *BOOTSTRAP_ROLE_MANAGER.slot(),
                &sanitized,
                &reservations[..reservation_count],
            )
        }
        .unwrap_or_else(|error| panic!("failed to claim physical ownership: {error:?}"));
        // SAFETY: the raw entry and descriptor installer establish the sole-BSP,
        // CPL0, IF-clear, stationary stack/descriptor contract. No AP or other
        // mapper can run during this complete consuming activation session.
        let mut active_paging = unsafe {
            arch::x86_64::mm::activate_bootstrap_deep_paging(
                boot_info.paging_handoff(),
                roles,
                memory_witness,
            )
        }
        .unwrap_or_else(|error| panic!("failed to activate Deep-owned paging: {error:?}"));
        let pm_timer = {
            let workspace = unsafe {
                let slot = &mut *BOOTSTRAP_ACPI_WORKSPACE.slot();
                let workspace = slot.as_mut_ptr();
                // The workspace contains only integer arrays; all-zero is a valid
                // representation. Initialize the BSS-owned object in place so no
                // ~70 KiB temporary is materialized on the bootstrap stack.
                core::ptr::write_bytes(workspace, 0, 1);
                &mut *workspace
            };
            let mut acpi =
                arch::x86_64::acpi::AcpiScratchReader::new(&mut active_paging, &boot_info);
            let proposal = arch::x86_64::acpi::discover_pm_timer_proposal(
                &mut acpi,
                boot_info.header().acpi_rsdp_physical_address,
                workspace,
            )
            .unwrap_or_else(|error| panic!("DW0-F3 ACPI PM timer unavailable: {error:?}"));
            arch::x86_64::acpi::authorize_q35_pm_timer(proposal)
                .unwrap_or_else(|error| panic!("DW0-F3 PM timer port unauthorized: {error:?}"))
        };
        time::initialize(&mut active_paging, pm_timer)
            .unwrap_or_else(|error| panic!("failed to initialize DW0-F3 time service: {error:?}"));

        let (bsp_local_apic_id, bsp_local_apic_base) = time::bsp_local_apic_identity()
            .unwrap_or_else(|error| panic!("failed to identify the H1 bootstrap CPU: {error:?}"));
        let cpu_topology = {
            // The one-shot BSP owns this workspace serially. CPU discovery
            // snapshots every table again and does not retain workspace data.
            let workspace = unsafe { &mut *(*BOOTSTRAP_ACPI_WORKSPACE.slot()).as_mut_ptr() };
            let mut acpi =
                arch::x86_64::acpi::AcpiScratchReader::new(&mut active_paging, &boot_info);
            arch::x86_64::acpi::discover_cpu_topology(
                &mut acpi,
                boot_info.header().acpi_rsdp_physical_address,
                bsp_local_apic_id,
                true,
                workspace,
            )
            .unwrap_or_else(|error| panic!("failed to discover H1 CPU topology: {error:?}"))
        };
        if cpu_topology.local_apic_physical_address() != bsp_local_apic_base {
            panic!("MADT Local APIC base contradicts the BSP APIC MSR");
        }
        #[allow(
            unexpected_cfgs,
            reason = "E2B owns registration of the reserved DW1-E product cfg in kernel/build.rs"
        )]
        #[cfg(deepwyrm_dw1e_platform)]
        {
            // E2A re-snapshots only the bounded MADT facts needed to probe
            // candidate IOAPICs.  It publishes no binding, programs no route,
            // and leaves the validated redirection entry untouched/masked.
            let q35_snapshot = {
                let workspace = unsafe { &mut *(*BOOTSTRAP_ACPI_WORKSPACE.slot()).as_mut_ptr() };
                let mut acpi =
                    arch::x86_64::acpi::AcpiScratchReader::new(&mut active_paging, &boot_info);
                arch::x86_64::acpi::snapshot_q35_com2_madt(
                    &mut acpi,
                    boot_info.header().acpi_rsdp_physical_address,
                    bsp_local_apic_id,
                    true,
                    workspace,
                )
                .unwrap_or_else(|error| {
                    panic!("DW1-E2A q35 IOAPIC MADT snapshot failed: {error:?}")
                })
            };
            arch::x86_64::ioapic_live::initialize_q35_ioapic(&mut active_paging, q35_snapshot)
                .unwrap_or_else(|error| panic!("DW1-E2A q35 IOAPIC probe failed: {error:?}"));
        }
        arch::x86_64::smp::configure_live_cpu_registry(&cpu_topology)
            .unwrap_or_else(|error| panic!("failed to configure the H1 CPU registry: {error:?}"));
        let cpu_registry = arch::x86_64::smp::live_cpu_registry();
        cpu_registry
            .begin_start(0)
            .unwrap_or_else(|error| panic!("failed to start H1 BSP registration: {error:?}"));

        // SAFETY: the final Deep-owned root is active, the BSP remains at CPL0
        // with IF clear, and no AP has been released. Migration installs BSP
        // runtime slot zero before its CPU-local SYSCALL state is published.
        unsafe { arch::x86_64::migrate_bsp_to_runtime_slot0_after_deep_paging() }
            .unwrap_or_else(|error| panic!("failed to migrate the H1 BSP descriptors: {error:?}"));
        unsafe { arch::x86_64::syscall::install_syscall_boundary() }
            .unwrap_or_else(|error| panic!("failed to install E4 SYSCALL boundary: {error:?}"));
        active_paging
            .retire_bootstrap_scratch_binding()
            .unwrap_or_else(|error| {
                panic!("failed to retire the fixed BSP scratch binding: {error:?}")
            });
        cpu_registry
            .publish_online(0, bsp_local_apic_id, 1)
            .unwrap_or_else(|error| panic!("failed to publish the H1 BSP online: {error:?}"));
        arch::x86_64::idle::enable_live_cpu(cpu::CpuIndex::BOOTSTRAP)
            .unwrap_or_else(|error| panic!("failed to enable H4 BSP idle wake: {error:?}"));
        #[cfg(not(feature = "test-support"))]
        let _ = debug::emit_early_cpu_state_record(0, bsp_local_apic_id, "online");

        let runtime_stacks = arch::x86_64::linked_runtime_cpu_stack_layout()
            .unwrap_or_else(|error| panic!("invalid H1 per-CPU stack arena: {error:?}"));
        let (trampoline_template, trampoline_layout) =
            arch::x86_64::smp::linked_trampoline_template();
        let trampoline_plan = arch::x86_64::smp::TrampolinePlan::new(
            active_paging.ap_trampoline_physical_start(),
            trampoline_template.len() as u64,
            active_paging.root().frame().address(),
            dw_x86_64_ap_higher_half_entry as *const () as u64,
        )
        .unwrap_or_else(|error| panic!("invalid H1 AP trampoline plan: {error:?}"));
        for entry in cpu_topology.entries().skip(1) {
            let cpu_index = usize::from(entry.logical_index());
            let local_apic_id = entry.local_apic_id();
            cpu_registry
                .begin_start(cpu_index)
                .unwrap_or_else(|error| panic!("failed to begin AP {cpu_index}: {error:?}"));
            let mut image = [0_u8; arch::x86_64::smp::PAGE_SIZE as usize];
            arch::x86_64::smp::build_trampoline_image(
                &mut image,
                trampoline_template,
                trampoline_layout,
                trampoline_plan,
                cpu_index,
                local_apic_id,
                runtime_stacks[cpu_index].ap_bootstrap.top,
            )
            .unwrap_or_else(|error| panic!("failed to build AP {cpu_index} trampoline: {error:?}"));
            active_paging
                .install_ap_trampoline_image(&image)
                .unwrap_or_else(|error| {
                    panic!("failed to install AP {cpu_index} trampoline: {error:?}")
                });
            arch::x86_64::smp::deliver_ap_startup_sequence(
                &mut arch::x86_64::smp::LiveApStartupPlatform,
                local_apic_id,
                trampoline_plan.physical_start,
            )
            .unwrap_or_else(|error| panic!("failed to deliver AP {cpu_index} startup: {error:?}"));
            cpu_registry
                .wait_until_parked(cpu_index, H1_AP_PARK_POLL_LIMIT)
                .unwrap_or_else(|error| panic!("AP {cpu_index} did not park: {error:?}"));
        }
        active_paging
            .retire_ap_trampoline_mapping()
            .unwrap_or_else(|error| panic!("failed to retire the H1 AP trampoline: {error:?}"));
        #[cfg(deepwyrm_i1_evidence)]
        for entry in cpu_topology.entries() {
            test_support::I1_EVIDENCE
                .record(test_support::EvidenceEvent::cpu_online(
                    u8::try_from(entry.logical_index())
                        .unwrap_or_else(|_| panic!("I1 logical CPU does not fit evidence wire")),
                    u32::from(entry.local_apic_id()),
                ))
                .unwrap_or_else(|error| panic!("I1 CPU-online evidence failed: {error:?}"));
        }
        #[cfg(not(feature = "test-support"))]
        let _ = debug::emit_early_record(
            debug::DiagnosticLevel::Info,
            "boot",
            "activated Deep-owned page tables",
        );
        #[cfg(feature = "test-support")]
        match test_support::BUILD_GUEST_TEST {
            #[cfg(deepwyrm_memory_guest)]
            test if test.is_memory_foundation() => {
                test_support::run_memory_guest_test(active_paging)
            }
            #[cfg(deepwyrm_e7_guest)]
            test if test.is_task_userspace() => test_support::run_task_guest_test(active_paging),
            #[cfg(deepwyrm_f9_guest)]
            test if test.is_f9_userspace() => {
                active_paging.run_atomic_wait_userspace_test(test_support::BUILD_GUEST_TEST)
            }
            #[cfg(deepwyrm_f12_guest)]
            test if test.is_f12_userspace() => {
                active_paging.run_ipc_blocking_userspace_test(test_support::BUILD_GUEST_TEST)
            }
            test if test.is_primordial() => active_paging.run_primordial(
                primordial_modules.expect("primordial test selected its modules"),
                boot_resource_grants,
            ),
            _ => unreachable!("post-activation selector lacks an explicit runtime"),
        }
        #[cfg(not(feature = "test-support"))]
        active_paging.run_primordial(primordial_modules, boot_resource_grants)
    }
}

/// Reads the loader's temporary identity mappings under
/// `DW_BOOT_X86_64_ENTRY_V1`.
///
/// Construction is private to [`kernel_main`]. The loader contract guarantees
/// that BootInfo and each referenced handoff range remain mapped and immutable
/// until Deepwyrm replaces the transition page tables.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct IdentityMappedBootInfoReader;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl BootInfoByteReader for IdentityMappedBootInfoReader {
    #[allow(
        unsafe_code,
        reason = "audited identity-mapped physical handoff copy boundary"
    )]
    fn read_exact(&self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        if destination.is_empty() {
            return Ok(());
        }
        let byte_len = u64::try_from(destination.len()).map_err(|_| ())?;
        let physical_end = physical_start.checked_add(byte_len).ok_or(())?;
        if physical_start == 0 || physical_end > MAX_X86_PHYSICAL_ADDRESS_EXCLUSIVE {
            return Err(());
        }
        let source = usize::try_from(physical_start).map_err(|_| ())? as *const u8;

        // SAFETY: the private reader is used only during the locked loader
        // handoff lifetime. The source is a checked physical range below the
        // maximum x86_64 physical-address width and is identity-mapped and
        // immutable by contract. The destination is a live Rust slice on the
        // disjoint higher-half kernel stack.
        unsafe {
            core::ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), destination.len());
        }
        Ok(())
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    debug::handle_early_panic(info)
}
