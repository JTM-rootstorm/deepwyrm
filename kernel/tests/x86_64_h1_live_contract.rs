use std::fs;
use std::path::PathBuf;

fn kernel_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn bsp_discovers_topology_migrates_then_releases_aps_serially() {
    let source = fs::read_to_string(kernel_root().join("src/lib.rs")).unwrap();
    let topology = source.find("discover_cpu_topology(").unwrap();
    let configure = source
        .find("configure_live_cpu_registry(&cpu_topology)")
        .unwrap();
    let migrate = source
        .find("migrate_bsp_to_runtime_slot0_after_deep_paging()")
        .unwrap();
    let syscall = source.find("syscall::install_syscall_boundary()").unwrap();
    let release = source
        .find("for entry in cpu_topology.entries().skip(1)")
        .unwrap();
    let wait = source.find("wait_until_parked(cpu_index").unwrap();

    assert!(topology < configure);
    assert!(configure < migrate);
    assert!(migrate < syscall);
    assert!(syscall < release);
    assert!(release < wait);
    assert!(source.contains("MADT Local APIC base contradicts the BSP APIC MSR"));
}

#[test]
fn ap_entry_publishes_only_after_private_architecture_and_local_apic_state() {
    let source = fs::read_to_string(kernel_root().join("src/lib.rs")).unwrap();
    let entry = source.find("fn dw_x86_64_ap_higher_half_entry").unwrap();
    let body = &source[entry..];
    let private = body.find("initialize_ap_runtime_slot(cpu_index)").unwrap();
    let apic = body
        .find("initialize_ap_local_apic(cpu_index, local_apic_id, local_apic_base)")
        .unwrap();
    let online = body.find("publish_online(cpu_index").unwrap();
    let parked = body.find(".park(cpu_index)").unwrap();
    let idle = body.find("idle_h2_application_processor()").unwrap();
    let failure_halt = body.find("park_h1_application_processor()").unwrap();

    assert!(private < apic);
    assert!(apic < online);
    assert!(online < parked);
    assert!(parked < idle);
    assert!(source.contains("core::arch::asm!(\"cli; hlt\""));
    assert!(source.contains("core::arch::asm!(\"sti; hlt; cli\""));
    assert!(
        failure_halt < private,
        "validation failures must park before initialization"
    );
}

#[test]
fn h1_live_gate_emits_cpu_and_apic_identity() {
    let source = fs::read_to_string(kernel_root().join("src/debug/mod.rs")).unwrap();
    assert!(source.contains("[DW0][INFO][smp] cpu={cpu_index} apic={local_apic_id} state="));
    assert!(source.contains("emit_early_cpu_state_record"));
}
