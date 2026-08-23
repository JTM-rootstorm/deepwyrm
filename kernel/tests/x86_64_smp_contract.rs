const ARCH_SOURCE: &str = include_str!("../src/arch/x86_64/mod.rs");
const SMP_SOURCE: &str = include_str!("../src/arch/x86_64/smp.rs");
const ACPI_SOURCE: &str = include_str!("../src/arch/x86_64/acpi.rs");
const LINKER_SOURCE: &str = include_str!("../arch/x86_64/linker.ld");
const ACTIVATION_GRAPH_SOURCE: &str = include_str!("../src/arch/x86_64/mm/activation/graph.rs");
const ACTIVATION_BUILD_SOURCE: &str = include_str!("../src/arch/x86_64/mm/activation/build.rs");

#[test]
fn h1_runtime_storage_is_bounded_cpu_private_and_guarded() {
    assert!(ARCH_SOURCE.contains("pub(crate) mod smp;"));
    assert!(ACPI_SOURCE.contains("MAX_DW0_CPUS: usize = 64"));
    for private_stack in [
        "interrupt_stacks: [GuardedStack; 3]",
        "privilege_entry: GuardedStack",
        "terminal_reaper: GuardedStack",
        "ap_bootstrap: GuardedStack",
    ] {
        assert!(SMP_SOURCE.contains(private_stack));
    }
    assert!(SMP_SOURCE.contains("cpu_index >= H1_RUNTIME_CPU_CAPACITY"));
    assert!(!SMP_SOURCE.contains("[local_apic_id as usize]"));
}

#[test]
fn h1_online_publication_and_failure_are_explicit() {
    assert!(SMP_SOURCE.contains("Ordering::Release"));
    assert!(SMP_SOURCE.contains("Ordering::Acquire"));
    assert!(SMP_SOURCE.contains("CpuLifecycle::Failed"));
    assert!(SMP_SOURCE.contains("ZeroGeneration"));
    assert!(SMP_SOURCE.contains("ZeroFailureReason"));
}

#[test]
fn h1_trampoline_plan_is_bounded_to_one_low_nonzero_page() {
    let mm = include_str!("../src/arch/x86_64/mm/mod.rs");
    assert!(mm.contains("AP_TRAMPOLINE_LIMIT: u64 = 0x10_0000"));
    assert!(SMP_SOURCE.contains("super::mm::AP_TRAMPOLINE_LIMIT"));
    assert!(SMP_SOURCE.contains("AP_TRAMPOLINE_MAX_BYTES: u64 = PAGE_SIZE"));
    assert!(SMP_SOURCE.contains("physical_start < PAGE_SIZE"));
    assert!(SMP_SOURCE.contains("page_table_root >= 1_u64 << 32"));
    assert!(SMP_SOURCE.contains("startup_vector: (physical_start >> 12) as u8"));
}

#[test]
fn h1_runtime_stack_arena_is_linker_bounded_and_first_root_guarded() {
    assert!(LINKER_SOURCE.contains("__dw_runtime_cpu_stack_arena_start = .;"));
    assert!(LINKER_SOURCE.contains("__dw_runtime_cpu_stack_arena_end = .;"));
    assert!(LINKER_SOURCE.contains("4 * 70 * DW_KERNEL_BASE_PAGE_SIZE"));
    assert!(ARCH_SOURCE.contains("H1_RUNTIME_CPU_SLOT_COUNT: usize = 4"));
    assert!(ARCH_SOURCE.contains("H1_RUNTIME_AP_BOOTSTRAP_STACK_SIZE: u64 = 64 * 1024"));
    assert!(ARCH_SOURCE.contains("linked_runtime_cpu_stack_layout"));
    assert!(ACTIVATION_GRAPH_SOURCE.contains("fn is_runtime_cpu_stack_guard<T:"));
    assert!(ACTIVATION_GRAPH_SOURCE.contains("|| is_linked_runtime_cpu_stack_guard(page)"));
    assert!(ACTIVATION_BUILD_SOURCE.contains("validate_runtime_cpu_stack_layout("));
    assert!(ACTIVATION_BUILD_SOURCE.contains("is_kernel_guard("));
}

#[test]
fn h1_early_bsp_stack_carriers_remain_distinct_from_runtime_slots() {
    let early = LINKER_SOURCE
        .find("__dw_terminal_reaper_stack_top = .;")
        .expect("early BSP terminal carrier");
    let runtime = LINKER_SOURCE
        .find("__dw_runtime_cpu_stack_arena_start = .;")
        .expect("runtime CPU arena");
    assert!(early < runtime);
    assert!(
        LINKER_SOURCE
            .contains("__dw_terminal_reaper_stack_top <= __dw_runtime_cpu_stack_arena_start")
    );
    assert!(ARCH_SOURCE.contains("early BSP\n/// carriers remain separate"));
}

#[test]
fn h1_runtime_descriptor_bundles_are_fixed_private_and_release_published() {
    assert!(ARCH_SOURCE.contains("struct RuntimeCpuDescriptorSlot"));
    assert!(ARCH_SOURCE.contains("tss: UnsafeCell<MaybeUninit<TaskStateSegment>>"));
    assert!(ARCH_SOURCE.contains("gdt: UnsafeCell<MaybeUninit<GlobalDescriptorTable>>"));
    assert!(ARCH_SOURCE.contains("idt: UnsafeCell<MaybeUninit<InterruptDescriptorTable>>"));
    assert!(ARCH_SOURCE.contains("[RuntimeCpuDescriptorSlot; H1_RUNTIME_CPU_SLOT_COUNT]"));
    assert!(ARCH_SOURCE.contains("Ordering::Release"));
    assert!(ARCH_SOURCE.contains("Ordering::Acquire"));
    assert!(ARCH_SOURCE.contains("migrate_bsp_to_runtime_slot0_after_deep_paging"));
    assert!(ARCH_SOURCE.contains("initialize_ap_runtime_slot"));
    assert!(ARCH_SOURCE.contains("if cpu_index == 0"));
}
