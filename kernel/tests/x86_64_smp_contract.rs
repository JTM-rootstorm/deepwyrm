const ARCH_SOURCE: &str = include_str!("../src/arch/x86_64/mod.rs");
const SMP_SOURCE: &str = include_str!("../src/arch/x86_64/smp.rs");
const ACPI_SOURCE: &str = include_str!("../src/arch/x86_64/acpi.rs");

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
    assert!(SMP_SOURCE.contains("cpu_index >= MAX_DW0_CPUS"));
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
    assert!(SMP_SOURCE.contains("AP_TRAMPOLINE_LIMIT: u64 = 0x10_0000"));
    assert!(SMP_SOURCE.contains("AP_TRAMPOLINE_MAX_BYTES: u64 = PAGE_SIZE"));
    assert!(SMP_SOURCE.contains("physical_start < PAGE_SIZE"));
    assert!(SMP_SOURCE.contains("page_table_root >= 1_u64 << 32"));
    assert!(SMP_SOURCE.contains("startup_vector: (physical_start >> 12) as u8"));
}
