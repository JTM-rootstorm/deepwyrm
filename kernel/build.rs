use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const KERNEL_TARGET: &str = "x86_64-unknown-none";

pub(crate) const E7_USER_ENTRY: u64 = 0x0000_0000_4000_0000;
pub(crate) const E7_USER_DATA: u64 = 0x0000_0000_4000_1000;
pub(crate) const E7_USER_INFO: u64 = E7_USER_DATA;
pub(crate) const E7_USER_REQUIRED: u64 = E7_USER_DATA + 0x80;
pub(crate) const E7_USER_CLOCK: u64 = E7_USER_DATA + 0x100;
pub(crate) const E7_USER_STACK_BOTTOM: u64 = 0x0000_0000_5000_0000;
pub(crate) const E7_USER_STACK_TOP: u64 = E7_USER_STACK_BOTTOM + 4096;
pub(crate) const E7_SYSCALL_ABI_GET_INFO: u32 = 0x0000_0001;
pub(crate) const E7_SYSCALL_PROCESS_EXIT: u32 = 0x0001_0011;
pub(crate) const E7_SYSCALL_CLOCK_GET: u32 = 0x0005_0001;
pub(crate) const E7_UNKNOWN_SYSCALL: u32 = 0xffff_fffe;
pub(crate) const E7_STATUS_NOT_SUPPORTED: i32 = -14;
pub(crate) const E7_ABI_INFO_SIZE: u32 = 64;
pub(crate) const E7_ABI_VERSION: u32 = 0;
pub(crate) const E7_PAGE_SIZE: u32 = 4096;
pub(crate) const E7_CLOCK_MONOTONIC_ACTIVE: u32 = 0;

pub(crate) const F9_USER_ENTRY: u64 = 0x0000_0000_4000_2000;
pub(crate) const F9_USER_DATA: u64 = 0x0000_0000_4000_3000;
pub(crate) const F9_USER_STACK_BOTTOM: u64 = 0x0000_0000_5000_1000;
pub(crate) const F9_USER_STACK_TOP: u64 = F9_USER_STACK_BOTTOM + 4096;
pub(crate) const F9_USER_WAITER_STACK_TOP: u64 = F9_USER_STACK_BOTTOM + 2048;
pub(crate) const F9_USER_WAKER_STACK_TOP: u64 = F9_USER_STACK_TOP;
pub(crate) const F9_SYSCALL_ATOMIC_WAIT32: u32 = 0x0004_0020;
pub(crate) const F9_SYSCALL_ATOMIC_WAKE: u32 = 0x0004_0021;
pub(crate) const F9_SYSCALL_PROCESS_EXIT: u32 = E7_SYSCALL_PROCESS_EXIT;
pub(crate) const F9_STATUS_SUCCESS: i32 = 0;

pub(crate) const F12_USER_ENTRY: u64 = 0x0000_0000_4000_4000;
pub(crate) const F12_USER_DATA: u64 = 0x0000_0000_4000_5000;
pub(crate) const F12_USER_STACK_BOTTOM: u64 = 0x0000_0000_5000_2000;
pub(crate) const F12_USER_STACK_TOP: u64 = F12_USER_STACK_BOTTOM + 4096;
pub(crate) const F12_USER_SERVICE_STACK_TOP: u64 = F12_USER_STACK_BOTTOM + 2048;
pub(crate) const F12_USER_PRODUCER_STACK_TOP: u64 = F12_USER_STACK_TOP;

fn main() {
    if let Err(error) = run() {
        panic!("x86_64 entry build failed: {error}");
    }
}

fn run() -> Result<(), String> {
    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR")?);
    let layout_path = manifest_dir.join("arch/x86_64/layout.toml");
    let task_layout_path = manifest_dir.join("arch/x86_64/task_layout.toml");
    let linker_path = manifest_dir.join("arch/x86_64/linker.ld");
    let entry_path = manifest_dir.join("src/arch/x86_64/entry.S");
    let exceptions_path = manifest_dir.join("src/arch/x86_64/exceptions.S");
    let ipi_entry_path = manifest_dir.join("src/arch/x86_64/ipi_entry.S");
    let syscall_path = manifest_dir.join("src/arch/x86_64/syscall_entry.S");
    let kernel_context_path = manifest_dir.join("src/arch/x86_64/kernel_context.S");
    let ap_trampoline_path = manifest_dir.join("src/arch/x86_64/ap_trampoline.S");
    let guest_harness_path = manifest_dir.join("../tooling/guest-harness.toml");
    let e7_user_source = manifest_dir.join("tests/userspace/e7_task_smoke.S");
    let e7_user_linker = manifest_dir.join("tests/userspace/e7_user.ld");
    let f9_user_source = manifest_dir.join("tests/userspace/f9_atomic_wait_wake.S");
    let f9_user_linker = manifest_dir.join("tests/userspace/f9_user.ld");
    let f12_user_source = manifest_dir.join("tests/userspace/f12_ipc_blocking_smoke.S");
    let f12_user_linker = manifest_dir.join("tests/userspace/f12_user.ld");
    let syscall_veneer = manifest_dir.join("../abi/generated/syscall_veneer_x86_64.S");
    let generated_abi_path = manifest_dir.join("../abi/generated/deepwyrm_abi.rs");

    println!("cargo:rerun-if-changed={}", layout_path.display());
    println!("cargo:rerun-if-changed={}", task_layout_path.display());
    println!("cargo:rerun-if-changed={}", linker_path.display());
    println!("cargo:rerun-if-changed={}", entry_path.display());
    println!("cargo:rerun-if-changed={}", exceptions_path.display());
    println!("cargo:rerun-if-changed={}", ipi_entry_path.display());
    println!("cargo:rerun-if-changed={}", syscall_path.display());
    println!("cargo:rerun-if-changed={}", kernel_context_path.display());
    println!("cargo:rerun-if-changed={}", ap_trampoline_path.display());
    println!("cargo:rerun-if-changed={}", guest_harness_path.display());
    println!("cargo:rerun-if-changed={}", e7_user_source.display());
    println!("cargo:rerun-if-changed={}", e7_user_linker.display());
    println!("cargo:rerun-if-changed={}", f9_user_source.display());
    println!("cargo:rerun-if-changed={}", f9_user_linker.display());
    println!("cargo:rerun-if-changed={}", f12_user_source.display());
    println!("cargo:rerun-if-changed={}", f12_user_linker.display());
    println!("cargo:rerun-if-changed={}", syscall_veneer.display());
    println!("cargo:rerun-if-changed={}", generated_abi_path.display());
    println!("cargo:rerun-if-env-changed=DEEPWYRM_ACCEPTED_RUST_LLD");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_CLANG");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_SUPPORT");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_GUEST_TEST_SELECTOR");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_GUEST_TEST_ID");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_I1_EVIDENCE_NONCE");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_WYR1_EVIDENCE_NONCE");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_WYR1_EVIDENCE_SCENARIO");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1B_EVIDENCE_NONCE");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1B_CHALLENGE_DIGEST");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1B_BOOTFS_MAX_PAGES");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_WYR1B_EVIDENCE_NONCE");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1C_EVIDENCE_NONCE");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1C_PROGRESS_DIGEST");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_DW1C_BOOTFS_MAX_PAGES");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_c3_one_shot_ui)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_memory_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_e7_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_f9_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_f12_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_i1_evidence)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_i2_stress)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_wrcap_relay)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_wyr1_evidence)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_dw1b_evidence)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_wyr1b_evidence)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_dw1c_evidence)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_integrated)");
    println!("cargo:rustc-cfg=deepwyrm_integrated");

    let layout_source = fs::read_to_string(&layout_path)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;
    let layout = Layout::parse(&layout_source)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;
    let task_layout_source = fs::read_to_string(&task_layout_path)
        .map_err(|error| format!("{}: {error}", task_layout_path.display()))?;
    let task_layout = TaskLayout::parse(&task_layout_source)
        .map_err(|error| format!("{}: {error}", task_layout_path.display()))?;
    emit_task_layout_env(task_layout);

    configure_guest_test(&guest_harness_path)?;
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_memory_foundation_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_memory_guest");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_e7_userspace_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_e7_guest");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_f9_userspace_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_f9_guest");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_f12_userspace_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_f12_guest");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_i1_evidence_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_i1_evidence");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_i2_stress_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_i2_stress");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_wrcap_relay_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_wrcap_relay");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_wyr1_evidence_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_wyr1_evidence");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_dw1b_evidence_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_dw1b_evidence");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_wyr1b_evidence_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_wyr1b_evidence");
    }
    if env::var("DEEPWYRM_GUEST_TEST_SELECTOR")
        .ok()
        .as_deref()
        .is_some_and(is_dw1c_evidence_selector)
    {
        println!("cargo:rustc-cfg=deepwyrm_dw1c_evidence");
    }

    if required_env("TARGET")? != KERNEL_TARGET {
        return Ok(());
    }

    let out_dir = PathBuf::from(required_env("OUT_DIR")?);
    let entry_object = out_dir.join("deepwyrm-x86_64-entry.o");
    let exceptions_object = out_dir.join("deepwyrm-x86_64-exceptions.o");
    let ipi_entry_object = out_dir.join("deepwyrm-x86_64-ipi-entry.o");
    let syscall_object = out_dir.join("deepwyrm-x86_64-syscall.o");
    let kernel_context_object = out_dir.join("deepwyrm-x86_64-kernel-context.o");
    let ap_trampoline_object = out_dir.join("deepwyrm-x86_64-ap-trampoline.o");
    assemble_source(&entry_path, &entry_object, layout)?;
    assemble_source(&exceptions_path, &exceptions_object, layout)?;
    assemble_source(&ipi_entry_path, &ipi_entry_object, layout)?;
    assemble_source(&syscall_path, &syscall_object, layout)?;
    assemble_source(&kernel_context_path, &kernel_context_object, layout)?;
    assemble_source(&ap_trampoline_path, &ap_trampoline_object, layout)?;

    let mut link_objects = vec![
        entry_object.as_path(),
        exceptions_object.as_path(),
        ipi_entry_object.as_path(),
        syscall_object.as_path(),
        kernel_context_object.as_path(),
        ap_trampoline_object.as_path(),
    ];
    let e7_user_object = out_dir.join("deepwyrm-e7-user.o");
    let f9_user_object = out_dir.join("deepwyrm-f9-user.o");
    let f12_user_object = out_dir.join("deepwyrm-f12-user.o");
    let selector = env::var("DEEPWYRM_GUEST_TEST_SELECTOR").ok();
    if selector.as_deref().is_some_and(is_e7_userspace_selector) {
        let composite = out_dir.join("deepwyrm-e7-user.S");
        let elf = out_dir.join("deepwyrm-e7-user.elf");
        build_e7_user_artifact(
            &e7_user_source,
            &syscall_veneer,
            &e7_user_linker,
            &composite,
            &e7_user_object,
            &elf,
            layout,
        )?;
        emit_e7_user_env(&elf);
        link_objects.push(e7_user_object.as_path());
    }
    if selector.as_deref().is_some_and(is_f9_userspace_selector) {
        let composite = out_dir.join("deepwyrm-f9-user.S");
        let elf = out_dir.join("deepwyrm-f9-user.elf");
        build_f9_user_artifact(
            &f9_user_source,
            &syscall_veneer,
            &f9_user_linker,
            &composite,
            &f9_user_object,
            &elf,
            layout,
        )?;
        emit_f9_user_env(&elf);
        link_objects.push(f9_user_object.as_path());
    }
    if selector.as_deref().is_some_and(is_f12_userspace_selector) {
        let generated_abi = fs::read_to_string(&generated_abi_path)
            .map_err(|error| format!("{}: {error}", generated_abi_path.display()))?;
        let f12_constants = f12_assembler_constants(&generated_abi)?;
        let composite = out_dir.join("deepwyrm-f12-user.S");
        let elf = out_dir.join("deepwyrm-f12-user.elf");
        build_f12_user_artifact(
            &f12_user_source,
            &syscall_veneer,
            &f12_user_linker,
            &composite,
            &f12_user_object,
            &elf,
            layout,
            &f12_constants,
        )?;
        emit_f12_user_env(&elf);
        link_objects.push(f12_user_object.as_path());
    }

    for argument in linker_arguments(layout, task_layout, &linker_path, &link_objects) {
        println!("cargo:rustc-link-arg={argument}");
    }

    Ok(())
}

fn is_e7_userspace_selector(selector: &str) -> bool {
    matches!(
        selector,
        "task-syscall-smoke" | "task-syscall-sanitize" | "task-user-exception"
    )
}

fn is_memory_foundation_selector(selector: &str) -> bool {
    matches!(
        selector,
        "memory-mapping"
            | "memory-unmapping"
            | "memory-permissions"
            | "memory-invalid-pointer"
            | "memory-user-kernel-isolation"
            | "memory-shared-memory-object"
    )
}

fn is_f9_userspace_selector(selector: &str) -> bool {
    selector == "atomic-wait-wake"
}

fn is_f12_userspace_selector(selector: &str) -> bool {
    selector == "ipc-blocking-smoke"
}

fn is_i1_evidence_selector(selector: &str) -> bool {
    selector == "smp-runtime-acceptance"
}

fn is_i2_stress_selector(selector: &str) -> bool {
    selector == "smp-runtime-stress"
}

fn is_wrcap_relay_selector(selector: &str) -> bool {
    selector == "native-userspace-capability"
}

fn is_wyr1_evidence_selector(selector: &str) -> bool {
    selector == "permanent-supervisor-rrc"
}

fn is_dw1b_evidence_selector(selector: &str) -> bool {
    selector == "normal-preemption-up"
}

fn is_wyr1b_evidence_selector(selector: &str) -> bool {
    selector == "bootstrap-registry-launch"
}

fn is_dw1c_evidence_selector(selector: &str) -> bool {
    selector == "normal-preemption-smp"
}

fn emit_e7_user_env(elf: &Path) {
    for (name, value) in [
        ("DEEPWYRM_E7_USER_ENTRY", E7_USER_ENTRY),
        ("DEEPWYRM_E7_USER_DATA", E7_USER_DATA),
        ("DEEPWYRM_E7_USER_INFO", E7_USER_INFO),
        ("DEEPWYRM_E7_USER_REQUIRED", E7_USER_REQUIRED),
        ("DEEPWYRM_E7_USER_CLOCK", E7_USER_CLOCK),
        ("DEEPWYRM_E7_USER_STACK_BOTTOM", E7_USER_STACK_BOTTOM),
        ("DEEPWYRM_E7_USER_STACK_TOP", E7_USER_STACK_TOP),
    ] {
        println!("cargo:rustc-env={name}={value}");
    }
    println!("cargo:rustc-env=DEEPWYRM_E7_USER_ELF={}", elf.display());
}

fn emit_f9_user_env(elf: &Path) {
    for (name, value) in [
        ("DEEPWYRM_F9_USER_ENTRY", F9_USER_ENTRY),
        ("DEEPWYRM_F9_USER_DATA", F9_USER_DATA),
        ("DEEPWYRM_F9_USER_STACK_BOTTOM", F9_USER_STACK_BOTTOM),
        ("DEEPWYRM_F9_USER_STACK_TOP", F9_USER_STACK_TOP),
        (
            "DEEPWYRM_F9_USER_WAITER_STACK_TOP",
            F9_USER_WAITER_STACK_TOP,
        ),
        ("DEEPWYRM_F9_USER_WAKER_STACK_TOP", F9_USER_WAKER_STACK_TOP),
    ] {
        println!("cargo:rustc-env={name}={value}");
    }
    println!("cargo:rustc-env=DEEPWYRM_F9_USER_ELF={}", elf.display());
}

fn emit_f12_user_env(elf: &Path) {
    for (name, value) in [
        ("DEEPWYRM_F12_USER_ENTRY", F12_USER_ENTRY),
        ("DEEPWYRM_F12_USER_DATA", F12_USER_DATA),
        ("DEEPWYRM_F12_USER_STACK_BOTTOM", F12_USER_STACK_BOTTOM),
        ("DEEPWYRM_F12_USER_STACK_TOP", F12_USER_STACK_TOP),
        (
            "DEEPWYRM_F12_USER_SERVICE_STACK_TOP",
            F12_USER_SERVICE_STACK_TOP,
        ),
        (
            "DEEPWYRM_F12_USER_PRODUCER_STACK_TOP",
            F12_USER_PRODUCER_STACK_TOP,
        ),
    ] {
        println!("cargo:rustc-env={name}={value}");
    }
    println!("cargo:rustc-env=DEEPWYRM_F12_USER_ELF={}", elf.display());
}

#[allow(
    clippy::too_many_arguments,
    reason = "the E7 artifact builder keeps every source/output/tool boundary explicit"
)]
pub(crate) fn build_e7_user_artifact(
    user_source: &Path,
    generated_veneer: &Path,
    linker_script: &Path,
    composite_source: &Path,
    object: &Path,
    elf: &Path,
    layout: Layout,
) -> Result<(), String> {
    let body = fs::read_to_string(user_source)
        .map_err(|error| format!("{}: {error}", user_source.display()))?;
    let veneer = fs::read_to_string(generated_veneer)
        .map_err(|error| format!("{}: {error}", generated_veneer.display()))?;
    if !veneer.contains(".globl dw_syscall6") || !veneer.contains("syscall") {
        return Err("generated x86_64 syscall veneer lost dw_syscall6".into());
    }
    let mut composite = String::from(
        ".section .text.deepwyrm_test_e7_user,\"ax\",@progbits\n\
         .p2align 4\n\
         .globl __dw_test_e7_user_blob_start\n\
         __dw_test_e7_user_blob_start:\n",
    );
    for line in e7_assembler_constants() {
        composite.push_str(&line);
        composite.push('\n');
    }
    composite.push_str(&body);
    if !body.ends_with('\n') {
        composite.push('\n');
    }
    for line in veneer.lines() {
        if line.trim() == ".text" || line.trim().starts_with(".section .note.GNU-stack") {
            continue;
        }
        composite.push_str(line);
        composite.push('\n');
    }
    composite
        .push_str(".p2align 4\n.globl __dw_test_e7_user_blob_end\n__dw_test_e7_user_blob_end:\n");
    fs::write(composite_source, composite)
        .map_err(|error| format!("{}: {error}", composite_source.display()))?;
    assemble_source(composite_source, object, layout)?;

    let rust_lld = env::var_os("DEEPWYRM_ACCEPTED_RUST_LLD")
        .or_else(|| env::var_os("CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER"))
        .ok_or_else(|| "E7 target builds require the accepted Rust LLD path".to_owned())?;
    let status = Command::new(&rust_lld)
        .args([
            "-flavor",
            "gnu",
            "-static",
            "--no-dynamic-linker",
            "--build-id=none",
            "--gc-sections",
            "-z",
            "noexecstack",
            "-z",
            "max-page-size=4096",
        ])
        .arg(format!("-T{}", linker_script.display()))
        .arg(object)
        .arg("-o")
        .arg(elf)
        .status()
        .map_err(|error| format!("could not execute {:?}: {error}", rust_lld))?;
    if !status.success() {
        return Err(format!("E7 userspace link failed with {status}"));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the F9 artifact builder keeps every source/output/tool boundary explicit"
)]
pub(crate) fn build_f9_user_artifact(
    user_source: &Path,
    generated_veneer: &Path,
    linker_script: &Path,
    composite_source: &Path,
    object: &Path,
    elf: &Path,
    layout: Layout,
) -> Result<(), String> {
    let body = fs::read_to_string(user_source)
        .map_err(|error| format!("{}: {error}", user_source.display()))?;
    let veneer = fs::read_to_string(generated_veneer)
        .map_err(|error| format!("{}: {error}", generated_veneer.display()))?;
    if !veneer.contains(".globl dw_syscall6") || !veneer.contains("syscall") {
        return Err("generated x86_64 syscall veneer lost dw_syscall6".into());
    }
    let mut composite = String::from(
        ".section .text.deepwyrm_test_f9_user,\"ax\",@progbits\n\
         .p2align 4\n\
         .globl __dw_test_f9_user_blob_start\n\
         __dw_test_f9_user_blob_start:\n",
    );
    for line in f9_assembler_constants() {
        composite.push_str(&line);
        composite.push('\n');
    }
    composite.push_str(&body);
    if !body.ends_with('\n') {
        composite.push('\n');
    }
    for line in veneer.lines() {
        if line.trim() == ".text" || line.trim().starts_with(".section .note.GNU-stack") {
            continue;
        }
        composite.push_str(line);
        composite.push('\n');
    }
    composite
        .push_str(".p2align 4\n.globl __dw_test_f9_user_blob_end\n__dw_test_f9_user_blob_end:\n");
    fs::write(composite_source, composite)
        .map_err(|error| format!("{}: {error}", composite_source.display()))?;
    assemble_source(composite_source, object, layout)?;

    let rust_lld = env::var_os("DEEPWYRM_ACCEPTED_RUST_LLD")
        .or_else(|| env::var_os("CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER"))
        .ok_or_else(|| "F9 target builds require the accepted Rust LLD path".to_owned())?;
    let status = Command::new(&rust_lld)
        .args([
            "-flavor",
            "gnu",
            "-static",
            "--no-dynamic-linker",
            "--build-id=none",
            "--gc-sections",
            "-z",
            "noexecstack",
            "-z",
            "max-page-size=4096",
        ])
        .arg(format!("-T{}", linker_script.display()))
        .arg(object)
        .arg("-o")
        .arg(elf)
        .status()
        .map_err(|error| format!("could not execute {:?}: {error}", rust_lld))?;
    if !status.success() {
        return Err(format!("F9 userspace link failed with {status}"));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the F12 artifact builder keeps every source/output/tool boundary explicit"
)]
pub(crate) fn build_f12_user_artifact(
    user_source: &Path,
    generated_veneer: &Path,
    linker_script: &Path,
    composite_source: &Path,
    object: &Path,
    elf: &Path,
    layout: Layout,
    assembler_constants: &[String],
) -> Result<(), String> {
    let body = fs::read_to_string(user_source)
        .map_err(|error| format!("{}: {error}", user_source.display()))?;
    let veneer = fs::read_to_string(generated_veneer)
        .map_err(|error| format!("{}: {error}", generated_veneer.display()))?;
    if !veneer.contains(".globl dw_syscall6") || !veneer.contains("syscall") {
        return Err("generated x86_64 syscall veneer lost dw_syscall6".into());
    }
    let mut composite = String::from(
        ".section .text.deepwyrm_test_f12_user,\"ax\",@progbits\n\
         .p2align 4\n\
         .globl __dw_test_f12_user_blob_start\n\
         __dw_test_f12_user_blob_start:\n",
    );
    for line in assembler_constants {
        composite.push_str(line);
        composite.push('\n');
    }
    composite.push_str(&body);
    if !body.ends_with('\n') {
        composite.push('\n');
    }
    for line in veneer.lines() {
        if line.trim() == ".text" || line.trim().starts_with(".section .note.GNU-stack") {
            continue;
        }
        composite.push_str(line);
        composite.push('\n');
    }
    composite
        .push_str(".p2align 4\n.globl __dw_test_f12_user_blob_end\n__dw_test_f12_user_blob_end:\n");
    fs::write(composite_source, composite)
        .map_err(|error| format!("{}: {error}", composite_source.display()))?;
    assemble_source(composite_source, object, layout)?;

    let rust_lld = env::var_os("DEEPWYRM_ACCEPTED_RUST_LLD")
        .or_else(|| env::var_os("CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER"))
        .ok_or_else(|| "F12 target builds require the accepted Rust LLD path".to_owned())?;
    let status = Command::new(&rust_lld)
        .args([
            "-flavor",
            "gnu",
            "-static",
            "--no-dynamic-linker",
            "--build-id=none",
            "--gc-sections",
            "-z",
            "noexecstack",
            "-z",
            "max-page-size=4096",
        ])
        .arg(format!("-T{}", linker_script.display()))
        .arg(object)
        .arg("-o")
        .arg(elf)
        .status()
        .map_err(|error| format!("could not execute {:?}: {error}", rust_lld))?;
    if !status.success() {
        return Err(format!("F12 userspace link failed with {status}"));
    }
    Ok(())
}

fn e7_assembler_constants() -> Vec<String> {
    vec![
        format!(".equ DW_E7_USER_INFO_ADDRESS, {E7_USER_INFO:#x}"),
        format!(".equ DW_E7_USER_REQUIRED_ADDRESS, {E7_USER_REQUIRED:#x}"),
        format!(".equ DW_E7_USER_CLOCK_ADDRESS, {E7_USER_CLOCK:#x}"),
        format!(".equ DW_E7_SYSCALL_ABI_GET_INFO, {E7_SYSCALL_ABI_GET_INFO:#x}"),
        format!(".equ DW_E7_SYSCALL_PROCESS_EXIT, {E7_SYSCALL_PROCESS_EXIT:#x}"),
        format!(".equ DW_E7_SYSCALL_CLOCK_GET, {E7_SYSCALL_CLOCK_GET:#x}"),
        format!(".equ DW_E7_UNKNOWN_SYSCALL, {E7_UNKNOWN_SYSCALL:#x}"),
        format!(".equ DW_E7_STATUS_NOT_SUPPORTED, {E7_STATUS_NOT_SUPPORTED}"),
        format!(".equ DW_E7_ABI_INFO_SIZE, {E7_ABI_INFO_SIZE}"),
        format!(".equ DW_E7_ABI_VERSION, {E7_ABI_VERSION}"),
        format!(".equ DW_E7_PAGE_SIZE, {E7_PAGE_SIZE}"),
        format!(".equ DW_E7_CLOCK_MONOTONIC_ACTIVE, {E7_CLOCK_MONOTONIC_ACTIVE}"),
    ]
}

fn f9_assembler_constants() -> Vec<String> {
    vec![
        format!(".equ DW_F9_USER_DATA_ADDRESS, {F9_USER_DATA:#x}"),
        format!(".equ DW_F9_SYSCALL_ATOMIC_WAIT32, {F9_SYSCALL_ATOMIC_WAIT32:#x}"),
        format!(".equ DW_F9_SYSCALL_ATOMIC_WAKE, {F9_SYSCALL_ATOMIC_WAKE:#x}"),
        format!(".equ DW_F9_SYSCALL_PROCESS_EXIT, {F9_SYSCALL_PROCESS_EXIT:#x}"),
        format!(".equ DW_F9_STATUS_SUCCESS, {F9_STATUS_SUCCESS}"),
    ]
}

fn f12_assembler_constants(generated_abi: &str) -> Result<Vec<String>, String> {
    let generated = |name| generated_abi_constant(generated_abi, name);
    let constants = vec![
        format!(".equ DW_F12_USER_DATA_ADDRESS, {F12_USER_DATA:#x}"),
        ".equ DW_F12_TASK_GROUP, 0x00".into(),
        ".equ DW_F12_MAIN_RX, 0x08".into(),
        ".equ DW_F12_MAIN_TX, 0x10".into(),
        ".equ DW_F12_BOOTSTRAP_SOURCE, 0x18".into(),
        ".equ DW_F12_BOOTSTRAP_PEER, 0x20".into(),
        ".equ DW_F12_EVENT_SOURCE, 0x28".into(),
        ".equ DW_F12_EVENT_SIGNALER, 0x30".into(),
        ".equ DW_F12_MOVED_EVENT_SOURCE, 0x40".into(),
        ".equ DW_F12_CLOCK_NOW, 0x48".into(),
        ".equ DW_F12_DEADLINE, 0x50".into(),
        ".equ DW_F12_SYNC0, 0x58".into(),
        ".equ DW_F12_SYNC1, 0x5c".into(),
        ".equ DW_F12_WOKEN, 0x60".into(),
        ".equ DW_F12_MESSAGE_A, 0x80".into(),
        ".equ DW_F12_MESSAGE_B, 0x81".into(),
        ".equ DW_F12_TRANSFER, 0x100".into(),
        ".equ DW_F12_RECEIVE_BYTES, 0x140".into(),
        ".equ DW_F12_RECEIVED_HANDLE, 0x160".into(),
        ".equ DW_F12_RECEIVE_RESULT, 0x190".into(),
        ".equ DW_F12_WAIT_RESULT, 0x1d0".into(),
        ".equ DW_F12_PROCESS_ARGS, 0x210".into(),
        ".equ DW_F12_PROCESS_RESULT, 0x270".into(),
        ".equ DW_F12_TASK_INFO, 0x2b0".into(),
        ".equ DW_F12_INFO_REQUIRED, 0x2f0".into(),
        format!(
            ".equ DW_F12_SYSCALL_HANDLE_CLOSE, {}",
            generated("DW_SYSCALL_HANDLE_CLOSE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_HANDLE_DUPLICATE, {}",
            generated("DW_SYSCALL_HANDLE_DUPLICATE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_OBJECT_GET_INFO, {}",
            generated("DW_SYSCALL_OBJECT_GET_INFO_V1")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_PROCESS_CREATE, {}",
            generated("DW_SYSCALL_PROCESS_CREATE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_PROCESS_EXIT, {}",
            generated("DW_SYSCALL_PROCESS_EXIT")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_PROCESS_TERMINATE, {}",
            generated("DW_SYSCALL_PROCESS_TERMINATE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_CHANNEL_CREATE, {}",
            generated("DW_SYSCALL_CHANNEL_CREATE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_CHANNEL_SEND, {}",
            generated("DW_SYSCALL_CHANNEL_SEND")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_CHANNEL_RECEIVE, {}",
            generated("DW_SYSCALL_CHANNEL_RECEIVE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_WAIT_ONE, {}",
            generated("DW_SYSCALL_WAIT_ONE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_EVENT_CREATE, {}",
            generated("DW_SYSCALL_EVENT_CREATE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_EVENT_SIGNAL, {}",
            generated("DW_SYSCALL_EVENT_SIGNAL")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_ATOMIC_WAIT32, {}",
            generated("DW_SYSCALL_ATOMIC_WAIT32")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_ATOMIC_WAKE, {}",
            generated("DW_SYSCALL_ATOMIC_WAKE")?
        ),
        format!(
            ".equ DW_F12_SYSCALL_CLOCK_GET, {}",
            generated("DW_SYSCALL_CLOCK_GET")?
        ),
        format!(
            ".equ DW_F12_STATUS_SUCCESS, {}",
            generated("DW_STATUS_SUCCESS")?
        ),
        format!(
            ".equ DW_F12_STATUS_BAD_HANDLE, {}",
            generated("DW_STATUS_BAD_HANDLE")?
        ),
        format!(
            ".equ DW_F12_RIGHTS_CHANNEL, {}",
            generated("DW_OBJECT_COMPATIBLE_RIGHTS_CHANNEL")?
        ),
        format!(
            ".equ DW_F12_RIGHTS_EVENT, {}",
            generated("DW_OBJECT_COMPATIBLE_RIGHTS_EVENT")?
        ),
        format!(
            ".equ DW_F12_RIGHT_SIGNAL, {}",
            generated("DW_RIGHT_SIGNAL")?
        ),
        format!(".equ DW_F12_RIGHT_WAIT, {}", generated("DW_RIGHT_WAIT")?),
        format!(
            ".equ DW_F12_RIGHTS_PROCESS, {}",
            generated("DW_OBJECT_COMPATIBLE_RIGHTS_PROCESS")?
        ),
        format!(
            ".equ DW_F12_RIGHTS_ADDRESS_REGION, {}",
            generated("DW_OBJECT_COMPATIBLE_RIGHTS_ADDRESS_REGION")?
        ),
        format!(".equ DW_F12_RIGHT_READ, {}", generated("DW_RIGHT_READ")?),
        format!(
            ".equ DW_F12_SIGNAL_READABLE, {}",
            generated("DW_SIGNAL_READABLE")?
        ),
        format!(
            ".equ DW_F12_SIGNAL_SIGNALED, {}",
            generated("DW_SIGNAL_SIGNALED")?
        ),
        format!(
            ".equ DW_F12_DEADLINE_INFINITE, {}",
            generated("DW_DEADLINE_INFINITE")?
        ),
        format!(
            ".equ DW_F12_TRANSFER_MOVE, {}",
            generated("DW_HANDLE_TRANSFER_MOVE")?
        ),
        format!(
            ".equ DW_F12_RECEIVE_RESULT_SIZE, {}",
            generated("DW_CHANNEL_RECEIVE_RESULT_V1_SIZE")?
        ),
        format!(
            ".equ DW_F12_PROCESS_ARGS_SIZE, {}",
            generated("DW_PROCESS_CREATE_ARGS_V1_SIZE")?
        ),
        format!(
            ".equ DW_F12_PROCESS_RESULT_SIZE, {}",
            generated("DW_PROCESS_CREATE_RESULT_V1_SIZE")?
        ),
        format!(
            ".equ DW_F12_TASK_INFO_SIZE, {}",
            generated("DW_TASK_TERMINATION_INFO_V1_SIZE")?
        ),
        format!(
            ".equ DW_F12_OBJECT_INFO_TASK_STATE, {}",
            generated("DW_OBJECT_INFO_TASK_STATE_V1")?
        ),
        format!(
            ".equ DW_F12_TASK_STATE_CREATED, {}",
            generated("DW_TASK_STATE_CREATED")?
        ),
        format!(
            ".equ DW_F12_TASK_STATE_EXITED, {}",
            generated("DW_TASK_STATE_EXITED")?
        ),
        format!(
            ".equ DW_F12_TERMINATION_AUTHORIZED, {}",
            generated("DW_TERMINATION_AUTHORIZED")?
        ),
        format!(
            ".equ DW_F12_OBJECT_TYPE_EVENT, {}",
            generated("DW_OBJECT_TYPE_EVENT")?
        ),
    ];
    verify_f12_generated_layout(generated_abi)?;
    Ok(constants)
}

fn generated_abi_constant(source: &str, name: &str) -> Result<String, String> {
    let prefix = format!("pub const {name}:");
    let line = source
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("generated ABI omits `{name}`"))?;
    let value = line
        .split_once("= ")
        .and_then(|(_, value)| value.strip_suffix(';'))
        .ok_or_else(|| format!("generated ABI constant `{name}` has an unexpected shape"))?;
    let value = match value.split_once('(') {
        Some((_, wrapped)) => wrapped.strip_suffix(')').ok_or_else(|| {
            format!("generated ABI constant `{name}` has an unterminated wrapper")
        })?,
        None => value,
    };
    Ok(value.to_owned())
}

fn verify_f12_generated_layout(source: &str) -> Result<(), String> {
    for assertion in [
        "pub const DW_HANDLE_TRANSFER_V1_SIZE: u32 = 40;",
        "pub const DW_RECEIVED_HANDLE_INFO_V1_SIZE: u32 = 40;",
        "pub const DW_CHANNEL_RECEIVE_RESULT_V1_SIZE: u32 = 56;",
        "pub const DW_WAIT_RESULT_V1_SIZE: u32 = 48;",
        "pub const DW_PROCESS_CREATE_ARGS_V1_SIZE: u32 = 88;",
        "pub const DW_PROCESS_CREATE_RESULT_V1_SIZE: u32 = 64;",
        "pub const DW_TASK_TERMINATION_INFO_V1_SIZE: u32 = 64;",
        "assert_eq!(offset_of!(DwHandleTransferV1, handle), 0);",
        "assert_eq!(offset_of!(DwHandleTransferV1, requested_rights), 8);",
        "assert_eq!(offset_of!(DwHandleTransferV1, operation), 16);",
        "assert_eq!(offset_of!(DwHandleTransferV1, reserved0), 20);",
        "assert_eq!(offset_of!(DwHandleTransferV1, reserved), 24);",
        "assert_eq!(offset_of!(DwReceivedHandleInfoV1, handle), 0);",
        "assert_eq!(offset_of!(DwReceivedHandleInfoV1, rights), 8);",
        "assert_eq!(offset_of!(DwReceivedHandleInfoV1, object_type), 16);",
        "assert_eq!(offset_of!(DwChannelReceiveResultV1, actual_bytes), 8);",
        "assert_eq!(offset_of!(DwChannelReceiveResultV1, actual_handles), 12);",
        "assert_eq!(offset_of!(DwWaitResultV1, observed), 16);",
        "assert_eq!(offset_of!(DwProcessCreateArgsV1, task_group), 8);",
        "assert_eq!(offset_of!(DwProcessCreateArgsV1, bootstrap_channel), 16);",
        "assert_eq!(offset_of!(DwProcessCreateArgsV1, process_rights), 24);",
        "assert_eq!(offset_of!(DwProcessCreateArgsV1, root_region_rights), 32);",
        "assert_eq!(offset_of!(DwProcessCreateArgsV1, child_bootstrap_rights), 40);",
        "assert_eq!(offset_of!(DwProcessCreateResultV1, process), 8);",
        "assert_eq!(offset_of!(DwProcessCreateResultV1, root_address_region), 16);",
        "assert_eq!(offset_of!(DwProcessCreateResultV1, child_bootstrap_handle), 24);",
        "assert_eq!(offset_of!(DwTaskTerminationInfoV1, state), 8);",
        "assert_eq!(offset_of!(DwTaskTerminationInfoV1, reason), 12);",
    ] {
        if !source.contains(assertion) {
            return Err(format!("generated ABI layout assertion lost `{assertion}`"));
        }
    }
    Ok(())
}

fn configure_guest_test(harness_path: &Path) -> Result<(), String> {
    let feature_enabled = env::var_os("CARGO_FEATURE_TEST_SUPPORT").is_some();
    let selector = match env::var("DEEPWYRM_GUEST_TEST_SELECTOR") {
        Ok(selector) => Some(selector),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            return Err("DEEPWYRM_GUEST_TEST_SELECTOR must be valid UTF-8".into());
        }
    };
    let direct_id_present = env::var_os("DEEPWYRM_GUEST_TEST_ID").is_some();
    let harness_source = if feature_enabled {
        fs::read_to_string(harness_path)
            .map_err(|error| format!("{}: {error}", harness_path.display()))?
    } else {
        String::new()
    };

    if let Some(test_id) = select_guest_test(
        feature_enabled,
        selector.as_deref(),
        direct_id_present,
        &harness_source,
    )? {
        let selector = selector.expect("validated enabled configuration has a selector");
        println!("cargo:rustc-env=DEEPWYRM_GUEST_TEST_SELECTOR={selector}");
        println!("cargo:rustc-env=DEEPWYRM_GUEST_TEST_ID={test_id}");
        if is_i1_evidence_selector(&selector) {
            let nonce = required_i1_evidence_nonce()?;
            println!("cargo:rustc-env=DEEPWYRM_I1_EVIDENCE_NONCE={nonce}");
        }
        if is_wyr1_evidence_selector(&selector) {
            let nonce = required_wyr1_evidence_nonce()?;
            let scenario = required_wyr1_evidence_scenario()?;
            println!("cargo:rustc-env=DEEPWYRM_WYR1_EVIDENCE_NONCE={nonce}");
            println!("cargo:rustc-env=DEEPWYRM_WYR1_EVIDENCE_SCENARIO={scenario}");
        }
        if is_dw1b_evidence_selector(&selector) {
            let nonce = required_dw1b_hex("DEEPWYRM_DW1B_EVIDENCE_NONCE")?;
            let digest = required_dw1b_hex("DEEPWYRM_DW1B_CHALLENGE_DIGEST")?;
            let bootfs_pages = required_dw1b_bootfs_pages()?;
            println!("cargo:rustc-env=DEEPWYRM_DW1B_EVIDENCE_NONCE={nonce}");
            println!("cargo:rustc-env=DEEPWYRM_DW1B_CHALLENGE_DIGEST={digest}");
            println!("cargo:rustc-env=DEEPWYRM_DW1B_BOOTFS_MAX_PAGES={bootfs_pages}");
        }
        if is_wyr1b_evidence_selector(&selector) {
            let nonce = required_wyr1b_hex("DEEPWYRM_WYR1B_EVIDENCE_NONCE")?;
            let bootfs_pages = required_wyr1b_bootfs_pages()?;
            println!("cargo:rustc-env=DEEPWYRM_WYR1B_EVIDENCE_NONCE={nonce}");
            println!("cargo:rustc-env=DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES={bootfs_pages}");
        }
        if is_dw1c_evidence_selector(&selector) {
            let nonce = required_dw1c_hex("DEEPWYRM_DW1C_EVIDENCE_NONCE")?;
            let digest = required_dw1c_hex("DEEPWYRM_DW1C_PROGRESS_DIGEST")?;
            let bootfs_pages = required_dw1c_bootfs_pages()?;
            println!("cargo:rustc-env=DEEPWYRM_DW1C_EVIDENCE_NONCE={nonce}");
            println!("cargo:rustc-env=DEEPWYRM_DW1C_PROGRESS_DIGEST={digest}");
            println!("cargo:rustc-env=DEEPWYRM_DW1C_BOOTFS_MAX_PAGES={bootfs_pages}");
        }
    }
    Ok(())
}

fn required_dw1b_hex(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("normal-preemption-up requires {name}"))?;
    validate_upper_nonzero_hex_nonce(&value, name)?;
    Ok(value)
}

fn required_dw1b_bootfs_pages() -> Result<String, String> {
    let name = "DEEPWYRM_DW1B_BOOTFS_MAX_PAGES";
    let value =
        env::var(name).map_err(|_| format!("normal-preemption-up requires measured {name}"))?;
    validate_dw1b_bootfs_pages(&value)?;
    Ok(value)
}

fn validate_dw1b_bootfs_pages(value: &str) -> Result<usize, String> {
    let name = "DEEPWYRM_DW1B_BOOTFS_MAX_PAGES";
    let pages = value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be canonical decimal"))?;
    if pages == 0 || pages > 8192 || pages.to_string() != value {
        return Err(format!("{name} must be canonical decimal in 1..=8192"));
    }
    Ok(pages)
}

fn required_wyr1b_hex(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("bootstrap-registry-launch requires {name}"))?;
    validate_upper_nonzero_hex_nonce(&value, name)?;
    Ok(value)
}

fn required_dw1c_hex(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("normal-preemption-smp requires {name}"))?;
    validate_upper_nonzero_hex_nonce(&value, name)?;
    Ok(value)
}

fn required_dw1c_bootfs_pages() -> Result<String, String> {
    let name = "DEEPWYRM_DW1C_BOOTFS_MAX_PAGES";
    let value =
        env::var(name).map_err(|_| format!("normal-preemption-smp requires measured {name}"))?;
    let pages = value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be canonical decimal"))?;
    if pages == 0 || pages > 8192 || pages.to_string() != value {
        return Err(format!("{name} must be canonical decimal in 1..=8192"));
    }
    Ok(value)
}

fn required_wyr1b_bootfs_pages() -> Result<String, String> {
    let name = "DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES";
    let value = env::var(name)
        .map_err(|_| format!("bootstrap-registry-launch requires measured {name}"))?;
    validate_wyr1b_bootfs_pages(&value)?;
    Ok(value)
}

fn validate_wyr1b_bootfs_pages(value: &str) -> Result<usize, String> {
    let name = "DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES";
    let pages = value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be canonical decimal"))?;
    if pages == 0 || pages > 8192 || pages.to_string() != value {
        return Err(format!("{name} must be canonical decimal in 1..=8192"));
    }
    Ok(pages)
}

fn required_wyr1_evidence_nonce() -> Result<String, String> {
    let nonce = env::var("DEEPWYRM_WYR1_EVIDENCE_NONCE")
        .map_err(|_| "permanent-supervisor-rrc requires DEEPWYRM_WYR1_EVIDENCE_NONCE".to_owned())?;
    validate_wyr1_evidence_nonce(&nonce)?;
    Ok(nonce)
}

pub(crate) fn validate_wyr1_evidence_nonce(nonce: &str) -> Result<(), String> {
    validate_upper_nonzero_hex_nonce(nonce, "DEEPWYRM_WYR1_EVIDENCE_NONCE")
}

fn required_wyr1_evidence_scenario() -> Result<String, String> {
    let scenario = env::var("DEEPWYRM_WYR1_EVIDENCE_SCENARIO").map_err(|_| {
        "permanent-supervisor-rrc requires DEEPWYRM_WYR1_EVIDENCE_SCENARIO".to_owned()
    })?;
    validate_wyr1_evidence_scenario(&scenario)?;
    Ok(scenario)
}

pub(crate) fn validate_wyr1_evidence_scenario(scenario: &str) -> Result<(), String> {
    if matches!(scenario, "normal" | "degraded_recovery") {
        Ok(())
    } else {
        Err("DEEPWYRM_WYR1_EVIDENCE_SCENARIO must be normal or degraded_recovery".into())
    }
}

fn required_i1_evidence_nonce() -> Result<String, String> {
    let nonce = env::var("DEEPWYRM_I1_EVIDENCE_NONCE")
        .map_err(|_| "smp-runtime-acceptance requires DEEPWYRM_I1_EVIDENCE_NONCE".to_owned())?;
    validate_i1_evidence_nonce(&nonce)?;
    Ok(nonce)
}

pub(crate) fn validate_i1_evidence_nonce(nonce: &str) -> Result<(), String> {
    validate_upper_nonzero_hex_nonce(nonce, "DEEPWYRM_I1_EVIDENCE_NONCE")
}

fn validate_upper_nonzero_hex_nonce(nonce: &str, name: &str) -> Result<(), String> {
    if nonce.len() != 16
        || !nonce
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
        || nonce == "0000000000000000"
    {
        return Err(format!(
            "{name} must be an uppercase nonzero 16-hex-digit u64"
        ));
    }
    Ok(())
}

pub(crate) fn select_guest_test(
    feature_enabled: bool,
    selector: Option<&str>,
    direct_id_present: bool,
    harness_source: &str,
) -> Result<Option<u32>, String> {
    if direct_id_present {
        return Err(
            "DEEPWYRM_GUEST_TEST_ID is build-owned; select by DEEPWYRM_GUEST_TEST_SELECTOR".into(),
        );
    }
    if !feature_enabled {
        return match selector {
            Some(_) => {
                Err("DEEPWYRM_GUEST_TEST_SELECTOR requires the kernel test-support feature".into())
            }
            None => Ok(None),
        };
    }
    let selector = selector
        .ok_or_else(|| "test-support builds require DEEPWYRM_GUEST_TEST_SELECTOR".to_owned())?;
    validate_selector(selector)?;
    let mappings = parse_guest_test_mappings(harness_source)?;
    mappings
        .get(selector)
        .copied()
        .map(Some)
        .ok_or_else(|| format!("unknown guest-test selector `{selector}`"))
}

fn emit_task_layout_env(layout: TaskLayout) {
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_COUNT={}",
        layout.thread_kernel_stack_count
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_SIZE={}",
        layout.thread_kernel_stack_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_GUARD_SIZE={}",
        layout.thread_kernel_stack_guard_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_ALIGNMENT={}",
        layout.thread_kernel_stack_alignment
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_COUNT={}",
        layout.privilege_entry_stack_count
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_SIZE={}",
        layout.privilege_entry_stack_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE={}",
        layout.privilege_entry_stack_guard_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT={}",
        layout.privilege_entry_stack_alignment
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_COUNT={}",
        layout.terminal_reaper_stack_count
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_SIZE={}",
        layout.terminal_reaper_stack_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_GUARD_SIZE={}",
        layout.terminal_reaper_stack_guard_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_ALIGNMENT={}",
        layout.terminal_reaper_stack_alignment
    );
}

pub(crate) fn linker_arguments(
    layout: Layout,
    task_layout: TaskLayout,
    linker_path: &Path,
    objects: &[&Path],
) -> Vec<String> {
    let mut arguments = vec![
        "-static".to_owned(),
        "-no-pie".to_owned(),
        "--no-dynamic-linker".to_owned(),
        "--build-id=none".to_owned(),
        "--gc-sections".to_owned(),
        "-z".to_owned(),
        "noexecstack".to_owned(),
        "-z".to_owned(),
        format!("max-page-size={}", layout.base_page_size),
        format!("--defsym=DW_KERNEL_LINK_BASE={:#x}", layout.link_base),
        format!(
            "--defsym=DW_KERNEL_BASE_PAGE_SIZE={}",
            layout.base_page_size
        ),
        format!(
            "--defsym=DW_KERNEL_BOOT_STACK_SIZE={}",
            layout.kernel_boot_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_BOOT_STACK_ALIGNMENT={}",
            layout.kernel_boot_stack_alignment
        ),
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_COUNT={}",
            task_layout.thread_kernel_stack_count
        ),
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_SIZE={}",
            task_layout.thread_kernel_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_GUARD_SIZE={}",
            task_layout.thread_kernel_stack_guard_size
        ),
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_ALIGNMENT={}",
            task_layout.thread_kernel_stack_alignment
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_COUNT={}",
            task_layout.privilege_entry_stack_count
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_SIZE={}",
            task_layout.privilege_entry_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_GUARD_SIZE={}",
            task_layout.privilege_entry_stack_guard_size
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_ALIGNMENT={}",
            task_layout.privilege_entry_stack_alignment
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_COUNT={}",
            task_layout.terminal_reaper_stack_count
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_SIZE={}",
            task_layout.terminal_reaper_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_GUARD_SIZE={}",
            task_layout.terminal_reaper_stack_guard_size
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_ALIGNMENT={}",
            task_layout.terminal_reaper_stack_alignment
        ),
        format!("-T{}", linker_path.display()),
    ];
    for object in objects {
        arguments.push(object.display().to_string());
    }
    arguments
}

fn parse_guest_test_mappings(source: &str) -> Result<BTreeMap<String, u32>, String> {
    enum Section {
        TopLevel,
        Profile(String),
        GuestTest(String),
    }

    const PROFILE_KEYS: &[&str] = &[
        "machine",
        "vcpu",
        "memory_mib",
        "timeout_seconds",
        "gdb_port",
    ];

    let mut section = Section::TopLevel;
    let mut schema_seen = false;
    let mut profiles = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut guest_tests = BTreeMap::<String, BTreeMap<String, String>>::new();

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let name = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
                .ok_or_else(|| format!("line {line_number}: malformed section"))?;
            if let Some(name) = name.strip_prefix("profile.") {
                validate_name(name, "profile")?;
                if profiles.insert(name.into(), BTreeMap::new()).is_some() {
                    return Err(format!("line {line_number}: duplicate profile `{name}`"));
                }
                section = Section::Profile(name.into());
            } else if let Some(selector) = name.strip_prefix("guest_test.") {
                validate_selector(selector)?;
                if guest_tests
                    .insert(selector.into(), BTreeMap::new())
                    .is_some()
                {
                    return Err(format!(
                        "line {line_number}: duplicate guest-test selector `{selector}`"
                    ));
                }
                section = Section::GuestTest(selector.into());
            } else {
                return Err(format!("line {line_number}: unknown section `{name}`"));
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(format!("line {line_number}: malformed key or value"));
        }
        match &section {
            Section::TopLevel => {
                if key != "schema_version" || schema_seen {
                    return Err(format!(
                        "line {line_number}: unsupported or duplicate top-level key `{key}`"
                    ));
                }
                if parse_u64(value)? != 2 {
                    return Err("guest harness schema_version must be 2".into());
                }
                schema_seen = true;
            }
            Section::Profile(name) => {
                if !PROFILE_KEYS.contains(&key) {
                    return Err(format!(
                        "line {line_number}: unsupported profile key `{key}`"
                    ));
                }
                let values = profiles
                    .get_mut(name)
                    .expect("current profile was inserted at section start");
                if values.insert(key.into(), value.into()).is_some() {
                    return Err(format!(
                        "line {line_number}: duplicate key `{key}` in profile `{name}`"
                    ));
                }
            }
            Section::GuestTest(selector) => {
                if !matches!(key, "id" | "state") {
                    return Err(format!(
                        "line {line_number}: unsupported guest-test key `{key}`"
                    ));
                }
                let values = guest_tests
                    .get_mut(selector)
                    .expect("current guest test was inserted at section start");
                if values.insert(key.into(), value.into()).is_some() {
                    return Err(format!(
                        "line {line_number}: duplicate `{key}` for guest-test selector `{selector}`"
                    ));
                }
            }
        }
    }

    if !schema_seen {
        return Err("guest harness omits schema_version = 2".into());
    }
    for (name, values) in &profiles {
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected = PROFILE_KEYS.iter().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(format!(
                "profile `{name}` does not define the exact v1 key set"
            ));
        }
        parse_string(required_value(values, "machine")?)?;
        for key in ["vcpu", "memory_mib", "timeout_seconds", "gdb_port"] {
            if parse_u64(required_value(values, key)?)? == 0 {
                return Err(format!("profile `{name}` key `{key}` must be nonzero"));
            }
        }
    }

    let mut mappings = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for (selector, values) in guest_tests {
        if values.len() != 2 {
            return Err(format!(
                "guest-test selector `{selector}` must define exactly one id and state"
            ));
        }
        let raw_id = required_value(&values, "id")?;
        let id = parse_u64(raw_id).and_then(|id| {
            u32::try_from(id).map_err(|_| format!("guest-test id `{raw_id}` exceeds u32"))
        })?;
        if id == 0 {
            return Err(format!(
                "guest-test selector `{selector}` has reserved zero id"
            ));
        }
        if !ids.insert(id) {
            return Err(format!("duplicate guest-test id {id}"));
        }
        match parse_string(required_value(&values, "state")?)? {
            "implemented" => {
                mappings.insert(selector, id);
            }
            "reserved" => {}
            state => {
                return Err(format!(
                    "guest-test selector `{selector}` has invalid state `{state}`"
                ));
            }
        }
    }
    if mappings.is_empty() {
        return Err("guest harness defines no guest-test selectors".into());
    }
    Ok(mappings)
}

fn validate_name(value: &str, kind: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("invalid {kind} name `{value}`"));
    }
    Ok(())
}

fn validate_selector(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!("invalid guest-test selector `{value}`"));
    }
    Ok(())
}

pub(crate) fn assemble_source(source: &Path, output: &Path, layout: Layout) -> Result<(), String> {
    let clang = env::var_os("DEEPWYRM_CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(&clang)
        .arg("--no-default-config")
        .arg(format!("--target={KERNEL_TARGET}"))
        .args([
            "-ffreestanding",
            "-fno-pic",
            "-fno-stack-protector",
            "-mno-red-zone",
            "-mno-mmx",
            "-mno-sse",
            "-mno-sse2",
        ])
        .arg(format!(
            "-DDW_KERNEL_BOOT_STACK_SIZE={}",
            layout.kernel_boot_stack_size
        ))
        .arg(format!(
            "-DDW_KERNEL_BOOT_STACK_ALIGNMENT={}",
            layout.kernel_boot_stack_alignment
        ))
        .args(["-c"])
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .map_err(|error| format!("could not execute {:?}: {error}", clang))?;
    if !status.success() {
        return Err(format!(
            "{:?} failed to assemble {} with {status}",
            clang,
            source.display()
        ));
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|error| format!("missing build environment {name}: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskLayout {
    pub(crate) thread_kernel_stack_count: u64,
    pub(crate) thread_kernel_stack_size: u64,
    pub(crate) thread_kernel_stack_guard_size: u64,
    pub(crate) thread_kernel_stack_alignment: u64,
    pub(crate) privilege_entry_stack_count: u64,
    pub(crate) privilege_entry_stack_size: u64,
    pub(crate) privilege_entry_stack_guard_size: u64,
    pub(crate) privilege_entry_stack_alignment: u64,
    pub(crate) terminal_reaper_stack_count: u64,
    pub(crate) terminal_reaper_stack_size: u64,
    pub(crate) terminal_reaper_stack_guard_size: u64,
    pub(crate) terminal_reaper_stack_alignment: u64,
}

impl TaskLayout {
    pub(crate) fn parse(source: &str) -> Result<Self, String> {
        let values = parse_flat_toml(source)?;
        let expected = [
            "schema",
            "version",
            "thread_kernel_stack_count",
            "thread_kernel_stack_size",
            "thread_kernel_stack_guard_size",
            "thread_kernel_stack_alignment",
            "privilege_entry_stack_count",
            "privilege_entry_stack_size",
            "privilege_entry_stack_guard_size",
            "privilege_entry_stack_alignment",
            "terminal_reaper_stack_count",
            "terminal_reaper_stack_size",
            "terminal_reaper_stack_guard_size",
            "terminal_reaper_stack_alignment",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
            let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
            return Err(format!(
                "task-layout keys do not match contract; missing={missing:?}, unknown={unknown:?}"
            ));
        }
        expect_string(&values, "schema", "deepwyrm-x86_64-task-layout")?;
        expect_u64(&values, "version", 4)?;
        let count = parse_u64(required_value(&values, "thread_kernel_stack_count")?)?;
        let size = parse_u64(required_value(&values, "thread_kernel_stack_size")?)?;
        let guard = parse_u64(required_value(&values, "thread_kernel_stack_guard_size")?)?;
        let alignment = parse_u64(required_value(&values, "thread_kernel_stack_alignment")?)?;
        let privilege_count = parse_u64(required_value(&values, "privilege_entry_stack_count")?)?;
        let privilege_size = parse_u64(required_value(&values, "privilege_entry_stack_size")?)?;
        let privilege_guard =
            parse_u64(required_value(&values, "privilege_entry_stack_guard_size")?)?;
        let privilege_alignment =
            parse_u64(required_value(&values, "privilege_entry_stack_alignment")?)?;
        let terminal_count = parse_u64(required_value(&values, "terminal_reaper_stack_count")?)?;
        let terminal_size = parse_u64(required_value(&values, "terminal_reaper_stack_size")?)?;
        let terminal_guard =
            parse_u64(required_value(&values, "terminal_reaper_stack_guard_size")?)?;
        let terminal_alignment =
            parse_u64(required_value(&values, "terminal_reaper_stack_alignment")?)?;
        if count != 16
            || size != 524_288
            || guard != 4_096
            || alignment != 4_096
            || !size.is_multiple_of(alignment)
            || !guard.is_multiple_of(alignment)
        {
            return Err(
                "DW0-E3 thread stack pool must be 16 guarded 524288-byte stacks on 4096-byte boundaries"
                    .into(),
            );
        }
        if privilege_count != 1
            || privilege_size != 16_384
            || privilege_guard != 4_096
            || privilege_alignment != 4_096
            || !privilege_size.is_multiple_of(privilege_alignment)
            || !privilege_guard.is_multiple_of(privilege_alignment)
        {
            return Err("DW0-E4 BSP privilege-entry stack must be one guarded 16384-byte stack on a 4096-byte boundary".into());
        }
        if terminal_count != 1
            || terminal_size != 135_168
            || terminal_guard != 4_096
            || terminal_alignment != 4_096
            || !terminal_size.is_multiple_of(terminal_alignment)
            || !terminal_guard.is_multiple_of(terminal_alignment)
        {
            return Err("terminal reaper carrier must be one guarded 135168-byte stack on a 4096-byte boundary".into());
        }
        Ok(Self {
            thread_kernel_stack_count: count,
            thread_kernel_stack_size: size,
            thread_kernel_stack_guard_size: guard,
            thread_kernel_stack_alignment: alignment,
            privilege_entry_stack_count: privilege_count,
            privilege_entry_stack_size: privilege_size,
            privilege_entry_stack_guard_size: privilege_guard,
            privilege_entry_stack_alignment: privilege_alignment,
            terminal_reaper_stack_count: terminal_count,
            terminal_reaper_stack_size: terminal_size,
            terminal_reaper_stack_guard_size: terminal_guard,
            terminal_reaper_stack_alignment: terminal_alignment,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Layout {
    pub(crate) link_base: u64,
    pub(crate) base_page_size: u64,
    pub(crate) kernel_boot_stack_size: u64,
    pub(crate) kernel_boot_stack_alignment: u64,
    #[allow(
        dead_code,
        reason = "published intake limits are consumed by contract agreement tests"
    )]
    pub(crate) max_normalized_memory_map_entries: u64,
    #[allow(
        dead_code,
        reason = "published intake limits are consumed by contract agreement tests"
    )]
    pub(crate) max_module_entries: u64,
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) temporary_virtual_address: u64,
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) temporary_indices: [u16; 4],
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) minimum_table_frame_count: u64,
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) maximum_table_frame_count: u64,
}

impl Layout {
    pub(crate) fn parse(source: &str) -> Result<Self, String> {
        const EXPECTED_KEYS: &[&str] = &[
            "schema",
            "version",
            "entry_contract",
            "elf_type",
            "entry_symbol",
            "link_base",
            "base_page_size",
            "red_zone",
            "kernel_boot_stack_size",
            "kernel_boot_stack_alignment",
            "loader_transition_stack_size",
            "loader_transition_stack_alignment",
            "p_paddr_policy",
            "allowed_program_header_types",
            "load_policy.upper_canonical",
            "load_policy.non_overlapping",
            "load_policy.writable_xor_executable",
            "load_policy.entry_in_executable_segment",
            "entry_state.transfer",
            "entry_state.returns",
            "entry_state.boot_info_register",
            "entry_state.boot_info_address",
            "entry_state.boot_info_alignment",
            "entry_state.defined_incoming_gprs",
            "entry_state.loader_stack_owner",
            "entry_state.loader_stack_rsp",
            "entry_state.loader_stack_rsp_mod_16",
            "entry_state.loader_stack_lifetime",
            "entry_state.immediate_kernel_stack_switch",
            "entry_state.kernel_stack_owner",
            "entry_state.kernel_stack_rsp_mod_16_before_call",
            "entry_state.rust_entry_rsp_mod_16",
            "entry_state.rust_entry_abi",
            "entry_state.interrupts_enabled",
            "entry_state.direction_flag_set",
            "entry_state.cr0_write_protect",
            "entry_state.execute_disable",
            "entry_state.paging_mode",
            "entry_state.initial_processor",
            "entry_state.descriptor_state",
            "entry_state.tls_state",
            "entry_state.fp_simd_state",
            "entry_state.uefi_services_available",
            "entry_state.firmware_exit",
            "handoff_mappings.kernel_load_segments",
            "handoff_mappings.physical_allocation",
            "handoff_mappings.boot_info",
            "handoff_mappings.referenced_ranges",
            "handoff_mappings.lifetime",
            "handoff_mappings.referenced_ranges_mutable",
            "handoff_mappings.page_zero_mapped",
            "handoff_mappings.framebuffer_pixels_identity_mapped",
            "early_intake.max_normalized_memory_map_entries",
            "early_intake.max_module_entries",
            "early_intake.acpi_scope",
            "early_intake.acpi_guid_preference",
            "early_intake.acpi_duplicate_selected_guid",
            "early_intake.acpi_preferred_invalid",
            "early_intake.acpi_rsdp_signature",
            "early_intake.acpi_rsdp_length_rule",
            "early_intake.acpi_rsdp_checksum",
            "early_intake.acpi_rsdp_mapping",
            "early_intake.acpi_rsdp_max_intersecting_pages",
            "early_intake.acpi_mapping_overlap",
            "early_intake.acpi_table_traversal",
            "early_intake.acpi_memory_types_identity_mapped",
            "transition_tables.contract",
            "transition_tables.layout_version",
            "transition_tables.temporary_virtual_address",
            "transition_tables.temporary_page_count",
            "transition_tables.pml4_index",
            "transition_tables.pdpt_index",
            "transition_tables.pd_index",
            "transition_tables.pt_index",
            "transition_tables.minimum_table_frame_count",
            "transition_tables.maximum_table_frame_count",
            "transition_tables.initial_leaf",
            "transition_tables.temporary_leaf_permissions",
            "transition_tables.identity_alias_permissions",
            "transition_tables.identity_alias_mutable_by_deepwyrm",
            "transition_tables.cache_selection_bits",
            "transition_tables.pat_entry_zero",
            "transition_tables.mtrr_policy",
            "transition_tables.pcide_enabled",
            "transition_tables.pge_enabled",
            "transition_tables.cr3_low_bits_zero",
            "transition_tables.ownership_transfer",
            "transition_tables.lifetime",
            "transition_tables.concurrency",
            "transition_tables.physical_role_policy",
            "transition_tables.new_root_table_access",
        ];

        let values = parse_flat_toml(source)?;
        let expected = EXPECTED_KEYS.iter().copied().collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
            let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
            return Err(format!(
                "layout keys do not match contract; missing={missing:?}, unknown={unknown:?}"
            ));
        }

        expect_string(&values, "schema", "deepwyrm-x86_64-layout")?;
        expect_u64(&values, "version", 2)?;
        expect_string(&values, "entry_contract", "DW_BOOT_X86_64_ENTRY_V1")?;
        expect_string(&values, "elf_type", "ET_EXEC")?;
        expect_string(&values, "entry_symbol", "_dw_kernel_entry")?;
        expect_bool(&values, "red_zone", false)?;
        expect_u64(&values, "loader_transition_stack_size", 16_384)?;
        expect_u64(&values, "loader_transition_stack_alignment", 4_096)?;
        expect_string(&values, "p_paddr_policy", "ignored")?;
        let program_header_types =
            parse_string_array(required_value(&values, "allowed_program_header_types")?)?;
        if program_header_types != ["PT_LOAD"] {
            return Err(
                "allowed_program_header_types must contain only the canonical PT_LOAD".into(),
            );
        }
        for key in [
            "load_policy.upper_canonical",
            "load_policy.non_overlapping",
            "load_policy.writable_xor_executable",
            "load_policy.entry_in_executable_segment",
        ] {
            expect_bool(&values, key, true)?;
        }
        for (key, expected_value) in [
            ("entry_state.transfer", "jmp"),
            ("entry_state.boot_info_register", "RDI"),
            ("entry_state.boot_info_address", "identity-mapped-physical"),
            ("entry_state.loader_stack_rsp", "one-past-end"),
            ("entry_state.loader_stack_owner", "loader"),
            (
                "entry_state.loader_stack_lifetime",
                "until-kernel-page-table-replacement",
            ),
            ("entry_state.kernel_stack_owner", "kernel"),
            ("entry_state.rust_entry_abi", "sysv64"),
            ("entry_state.paging_mode", "x86_64-4-level"),
            ("entry_state.initial_processor", "BSP"),
            (
                "entry_state.descriptor_state",
                "valid-CS-SS-others-unspecified",
            ),
            ("entry_state.tls_state", "FS-GS-unspecified"),
            (
                "entry_state.fp_simd_state",
                "unavailable-until-kernel-initialization",
            ),
            ("entry_state.firmware_exit", "ExitBootServices-complete"),
            ("handoff_mappings.kernel_load_segments", "mapped-at-p_vaddr"),
            (
                "handoff_mappings.physical_allocation",
                "arbitrary-suitable-firmware-pages",
            ),
            ("handoff_mappings.boot_info", "identity-mapped"),
            ("handoff_mappings.referenced_ranges", "identity-mapped"),
            (
                "handoff_mappings.lifetime",
                "until-kernel-page-table-replacement",
            ),
            ("early_intake.acpi_scope", "rsdp-only"),
            (
                "early_intake.acpi_guid_preference",
                "ACPI_20_TABLE_GUID-then-ACPI_TABLE_GUID",
            ),
            ("early_intake.acpi_duplicate_selected_guid", "reject"),
            ("early_intake.acpi_preferred_invalid", "reject-no-downgrade"),
            ("early_intake.acpi_rsdp_signature", "RSD PTR "),
            (
                "early_intake.acpi_rsdp_length_rule",
                "revision-lt-2:20;revision-ge-2:declared-36..4096",
            ),
            (
                "early_intake.acpi_rsdp_checksum",
                "v1-first-20-and-v2-full-record",
            ),
            (
                "early_intake.acpi_rsdp_mapping",
                "validated-record-intersecting-base-pages-only",
            ),
            ("early_intake.acpi_mapping_overlap", "coalesce"),
            ("early_intake.acpi_table_traversal", "deferred-dw0-c"),
            (
                "transition_tables.contract",
                "DW_BOOT_X86_64_PAGING_HANDOFF_V1",
            ),
            ("transition_tables.initial_leaf", "exactly-zero-non-present"),
            (
                "transition_tables.temporary_leaf_permissions",
                "supervisor-rw-nx-base-page",
            ),
            (
                "transition_tables.identity_alias_permissions",
                "supervisor-rw-nx-base-page",
            ),
            ("transition_tables.pat_entry_zero", "observed-write-back"),
            (
                "transition_tables.mtrr_policy",
                "alias-consistent-no-effective-write-back-claim",
            ),
            (
                "transition_tables.ownership_transfer",
                "loader-to-deepwyrm-after-exit-boot-services",
            ),
            ("transition_tables.lifetime", "until-deepwyrm-cr3-switch"),
            (
                "transition_tables.concurrency",
                "bsp-aps-off-if-clear-nonreentrant",
            ),
            (
                "transition_tables.physical_role_policy",
                "exclusive-table-frames-no-kernel-module-data-alias",
            ),
            (
                "transition_tables.new_root_table_access",
                "deepwyrm-owned-before-cr3-switch",
            ),
        ] {
            expect_string(&values, key, expected_value)?;
        }
        expect_u64(&values, "entry_state.boot_info_alignment", 8)?;
        expect_u64(&values, "entry_state.loader_stack_rsp_mod_16", 0)?;
        expect_u64(
            &values,
            "entry_state.kernel_stack_rsp_mod_16_before_call",
            0,
        )?;
        expect_u64(&values, "entry_state.rust_entry_rsp_mod_16", 8)?;
        let incoming_gprs = parse_string_array(required_value(
            &values,
            "entry_state.defined_incoming_gprs",
        )?)?;
        if incoming_gprs != ["RDI"] {
            return Err("entry_state.defined_incoming_gprs must contain only RDI".into());
        }
        for key in [
            "entry_state.immediate_kernel_stack_switch",
            "entry_state.cr0_write_protect",
            "entry_state.execute_disable",
        ] {
            expect_bool(&values, key, true)?;
        }
        for key in [
            "entry_state.returns",
            "entry_state.interrupts_enabled",
            "entry_state.direction_flag_set",
            "entry_state.uefi_services_available",
            "handoff_mappings.referenced_ranges_mutable",
            "handoff_mappings.page_zero_mapped",
            "handoff_mappings.framebuffer_pixels_identity_mapped",
            "early_intake.acpi_memory_types_identity_mapped",
            "transition_tables.pcide_enabled",
            "transition_tables.pge_enabled",
        ] {
            expect_bool(&values, key, false)?;
        }
        expect_bool(
            &values,
            "transition_tables.identity_alias_mutable_by_deepwyrm",
            true,
        )?;
        expect_bool(&values, "transition_tables.cr3_low_bits_zero", true)?;

        let link_base = parse_hex_string(required_value(&values, "link_base")?)?;
        let base_page_size = parse_u64(required_value(&values, "base_page_size")?)?;
        let kernel_boot_stack_size = parse_u64(required_value(&values, "kernel_boot_stack_size")?)?;
        let kernel_boot_stack_alignment =
            parse_u64(required_value(&values, "kernel_boot_stack_alignment")?)?;
        let max_normalized_memory_map_entries = parse_u64(required_value(
            &values,
            "early_intake.max_normalized_memory_map_entries",
        )?)?;
        let max_module_entries =
            parse_u64(required_value(&values, "early_intake.max_module_entries")?)?;
        let temporary_virtual_address = parse_hex_string(required_value(
            &values,
            "transition_tables.temporary_virtual_address",
        )?)?;
        let temporary_indices = [
            parse_index(&values, "transition_tables.pml4_index")?,
            parse_index(&values, "transition_tables.pdpt_index")?,
            parse_index(&values, "transition_tables.pd_index")?,
            parse_index(&values, "transition_tables.pt_index")?,
        ];
        let minimum_table_frame_count = parse_u64(required_value(
            &values,
            "transition_tables.minimum_table_frame_count",
        )?)?;
        let maximum_table_frame_count = parse_u64(required_value(
            &values,
            "transition_tables.maximum_table_frame_count",
        )?)?;

        expect_u64(&values, "early_intake.acpi_rsdp_max_intersecting_pages", 2)?;
        expect_u64(&values, "transition_tables.layout_version", 2)?;
        expect_u64(&values, "transition_tables.temporary_page_count", 1)?;
        expect_u64(&values, "transition_tables.cache_selection_bits", 0)?;

        if link_base < 0xffff_8000_0000_0000 || link_base % base_page_size != 0 {
            return Err("link_base must be upper-canonical and base-page aligned".into());
        }
        if !base_page_size.is_power_of_two() || base_page_size != 4_096 {
            return Err("base_page_size must be 4096".into());
        }
        if !kernel_boot_stack_alignment.is_power_of_two()
            || kernel_boot_stack_alignment != base_page_size
        {
            return Err("kernel boot stack alignment must equal the base page size".into());
        }
        if kernel_boot_stack_size != 1_048_576
            || kernel_boot_stack_size % kernel_boot_stack_alignment != 0
        {
            return Err("kernel boot stack must be an aligned 1048576-byte range".into());
        }
        if max_normalized_memory_map_entries != 128 || max_module_entries != 16 {
            return Err("early intake limits must match the bounded BootInfo snapshots".into());
        }
        if temporary_virtual_address != 0xffff_ff00_0000_0000
            || temporary_virtual_address % base_page_size != 0
            || temporary_virtual_address < 0xffff_8000_0000_0000
        {
            return Err("temporary mapping address must be the dedicated upper-half page".into());
        }
        let derived_indices = [
            ((temporary_virtual_address >> 39) & 0x1ff) as u16,
            ((temporary_virtual_address >> 30) & 0x1ff) as u16,
            ((temporary_virtual_address >> 21) & 0x1ff) as u16,
            ((temporary_virtual_address >> 12) & 0x1ff) as u16,
        ];
        if temporary_indices != derived_indices || temporary_indices != [510, 0, 0, 0] {
            return Err("temporary mapping indices must be derived from the dedicated VA".into());
        }
        if minimum_table_frame_count != 4 || maximum_table_frame_count != 256 {
            return Err("transition table frame bounds must be 4..=256".into());
        }
        if temporary_indices[0] == ((link_base >> 39) & 0x1ff) as u16 {
            return Err("temporary mapping must not share the kernel PT_LOAD PML4 slot".into());
        }

        Ok(Self {
            link_base,
            base_page_size,
            kernel_boot_stack_size,
            kernel_boot_stack_alignment,
            max_normalized_memory_map_entries,
            max_module_entries,
            temporary_virtual_address,
            temporary_indices,
            minimum_table_frame_count,
            maximum_table_frame_count,
        })
    }
}

fn parse_flat_toml(source: &str) -> Result<BTreeMap<String, String>, String> {
    let mut section = "";
    let mut values = BTreeMap::new();
    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            let Some(name) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            else {
                return Err(format!("line {line_number}: malformed section"));
            };
            if !matches!(
                name,
                "load_policy"
                    | "entry_state"
                    | "handoff_mappings"
                    | "early_intake"
                    | "transition_tables"
            ) {
                return Err(format!("line {line_number}: unknown section `{name}`"));
            }
            section = name;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() || value.contains('#') {
            return Err(format!("line {line_number}: malformed key or value"));
        }
        let full_key = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        if values.insert(full_key.clone(), value.to_owned()).is_some() {
            return Err(format!("line {line_number}: duplicate key `{full_key}`"));
        }
    }
    Ok(values)
}

fn parse_index(values: &BTreeMap<String, String>, key: &str) -> Result<u16, String> {
    let value = parse_u64(required_value(values, key)?)?;
    u16::try_from(value)
        .ok()
        .filter(|value| *value < 512)
        .ok_or_else(|| format!("{key} must be a four-level page-table index"))
}

fn required_value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing key `{key}`"))
}

fn expect_string(
    values: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    let actual = parse_string(required_value(values, key)?)?;
    if actual != expected {
        return Err(format!("{key} must be `{expected}`, found `{actual}`"));
    }
    Ok(())
}

fn expect_u64(values: &BTreeMap<String, String>, key: &str, expected: u64) -> Result<(), String> {
    let actual = parse_u64(required_value(values, key)?)?;
    if actual != expected {
        return Err(format!("{key} must be {expected}, found {actual}"));
    }
    Ok(())
}

fn expect_bool(values: &BTreeMap<String, String>, key: &str, expected: bool) -> Result<(), String> {
    let actual = parse_bool(required_value(values, key)?)?;
    if actual != expected {
        return Err(format!("{key} must be {expected}, found {actual}"));
    }
    Ok(())
}

fn parse_string(value: &str) -> Result<&str, String> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.contains('"') && !value.contains('\\'))
        .ok_or_else(|| format!("expected a simple quoted string, found `{value}`"))
}

fn parse_hex_string(value: &str) -> Result<u64, String> {
    let value = parse_string(value)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("expected a hexadecimal string, found `{value}`"))?;
    u64::from_str_radix(digits, 16).map_err(|error| format!("invalid hexadecimal value: {error}"))
}

fn parse_string_array(value: &str) -> Result<Vec<&str>, String> {
    let contents = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("expected a string array, found `{value}`"))?;
    if contents.trim().is_empty() {
        return Ok(Vec::new());
    }
    contents
        .split(',')
        .map(|value| parse_string(value.trim()))
        .collect()
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if value.starts_with('+') || value.starts_with('-') || value.contains('_') {
        return Err(format!(
            "expected canonical unsigned decimal, found `{value}`"
        ));
    }
    value
        .parse()
        .map_err(|error| format!("invalid unsigned decimal `{value}`: {error}"))
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("invalid boolean `{value}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED_ABI: &str = include_str!("../abi/generated/deepwyrm_abi.rs");

    #[test]
    fn wyr1_selector_and_build_owned_fields_are_exact() {
        assert!(is_wyr1_evidence_selector("permanent-supervisor-rrc"));
        assert!(!is_wyr1_evidence_selector("native-userspace-capability"));
        for valid in ["0000000000000001", "0123456789ABCDEF", "FFFFFFFFFFFFFFFF"] {
            assert!(validate_wyr1_evidence_nonce(valid).is_ok());
        }
        for invalid in [
            "0000000000000000",
            "0123456789abcdef",
            "0123456789ABCDE",
            "G123456789ABCDEF",
        ] {
            assert!(validate_wyr1_evidence_nonce(invalid).is_err());
        }
        assert!(validate_wyr1_evidence_scenario("normal").is_ok());
        assert!(validate_wyr1_evidence_scenario("degraded_recovery").is_ok());
        assert!(validate_wyr1_evidence_scenario("degraded").is_err());
    }

    #[test]
    fn dw1b_selector_and_build_owned_hex_are_exact() {
        assert!(is_dw1b_evidence_selector("normal-preemption-up"));
        assert!(!is_dw1b_evidence_selector("permanent-supervisor-rrc"));
        for valid in ["0000000000000001", "0123456789ABCDEF", "FFFFFFFFFFFFFFFF"] {
            assert!(validate_upper_nonzero_hex_nonce(valid, "DW1B").is_ok());
        }
        for invalid in [
            "0000000000000000",
            "0123456789abcdef",
            "0123456789ABCDE",
            "G123456789ABCDEF",
        ] {
            assert!(validate_upper_nonzero_hex_nonce(invalid, "DW1B").is_err());
        }
        let manifest = include_str!("../tooling/guest-harness.toml");
        assert_eq!(
            select_guest_test(true, Some("normal-preemption-up"), false, manifest),
            Ok(Some(26))
        );
        for (value, pages) in [("1", 1), ("42", 42), ("8192", 8192)] {
            assert_eq!(validate_dw1b_bootfs_pages(value), Ok(pages));
        }
        for invalid in ["", "0", "01", "+1", "8193", "not-pages"] {
            assert!(validate_dw1b_bootfs_pages(invalid).is_err());
        }
    }

    #[test]
    fn wyr1b_selector_nonce_and_bootfs_bound_are_exact() {
        assert!(is_wyr1b_evidence_selector("bootstrap-registry-launch"));
        assert!(!is_wyr1b_evidence_selector("permanent-supervisor-rrc"));
        for valid in ["0000000000000001", "0123456789ABCDEF", "FFFFFFFFFFFFFFFF"] {
            assert!(validate_upper_nonzero_hex_nonce(valid, "WYR1B").is_ok());
        }
        for invalid in [
            "0000000000000000",
            "0123456789abcdef",
            "0123456789ABCDE",
            "G123456789ABCDEF",
        ] {
            assert!(validate_upper_nonzero_hex_nonce(invalid, "WYR1B").is_err());
        }
        let manifest = include_str!("../tooling/guest-harness.toml");
        assert_eq!(
            select_guest_test(true, Some("bootstrap-registry-launch"), false, manifest),
            Ok(Some(27))
        );
        for (value, pages) in [("1", 1), ("64", 64), ("8192", 8192)] {
            assert_eq!(validate_wyr1b_bootfs_pages(value), Ok(pages));
        }
        for invalid in ["", "0", "01", "+1", "8193", "not-pages"] {
            assert!(validate_wyr1b_bootfs_pages(invalid).is_err());
        }
    }

    #[test]
    fn dw1c_selector_and_three_build_owned_bindings_are_exact() {
        assert!(is_dw1c_evidence_selector("normal-preemption-smp"));
        assert!(!is_dw1c_evidence_selector("normal-preemption-up"));
        for valid in ["0000000000000001", "0123456789ABCDEF", "FFFFFFFFFFFFFFFF"] {
            assert!(validate_upper_nonzero_hex_nonce(valid, "DW1C").is_ok());
        }
        for invalid in [
            "0000000000000000",
            "0123456789abcdef",
            "0123456789ABCDE",
            "G123456789ABCDEF",
        ] {
            assert!(validate_upper_nonzero_hex_nonce(invalid, "DW1C").is_err());
        }
        let manifest = include_str!("../tooling/guest-harness.toml");
        assert_eq!(
            select_guest_test(true, Some("normal-preemption-smp"), false, manifest),
            Ok(Some(28))
        );
        for value in ["", "0", "01", "+1", "8193", "not-pages"] {
            assert!(required_dw1c_bootfs_pages_for_test(value).is_err());
        }
    }

    fn required_dw1c_bootfs_pages_for_test(value: &str) -> Result<(), String> {
        let pages = value.parse::<usize>().map_err(|_| "invalid".to_owned())?;
        if pages == 0 || pages > 8192 || pages.to_string() != value {
            return Err("invalid".to_owned());
        }
        Ok(())
    }

    #[test]
    fn f12_assembly_constants_are_derived_from_generated_abi() {
        let constants = f12_assembler_constants(GENERATED_ABI).unwrap();
        for expected in [
            ".equ DW_F12_SYSCALL_CHANNEL_CREATE, 0x00030001",
            ".equ DW_F12_SYSCALL_CHANNEL_SEND, 0x00030002",
            ".equ DW_F12_SYSCALL_CHANNEL_RECEIVE, 0x00030003",
            ".equ DW_F12_SYSCALL_WAIT_ONE, 0x00040001",
            ".equ DW_F12_SYSCALL_EVENT_CREATE, 0x00040010",
            ".equ DW_F12_SYSCALL_EVENT_SIGNAL, 0x00040011",
            ".equ DW_F12_SYSCALL_ATOMIC_WAIT32, 0x00040020",
            ".equ DW_F12_SYSCALL_ATOMIC_WAKE, 0x00040021",
            ".equ DW_F12_SYSCALL_PROCESS_CREATE, 0x00010010",
            ".equ DW_F12_RIGHTS_CHANNEL, 467",
            ".equ DW_F12_RIGHTS_EVENT, 496",
            ".equ DW_F12_RECEIVE_RESULT_SIZE, 56",
            ".equ DW_F12_PROCESS_ARGS_SIZE, 88",
            ".equ DW_F12_PROCESS_RESULT_SIZE, 64",
            ".equ DW_F12_TASK_INFO_SIZE, 64",
        ] {
            assert!(constants.iter().any(|constant| constant == expected));
        }
    }

    #[test]
    fn f12_shared_data_layout_is_compact_and_disjoint() {
        let ranges = [
            (0x00, 8),
            (0x08, 8),
            (0x10, 8),
            (0x18, 8),
            (0x20, 8),
            (0x28, 8),
            (0x30, 8),
            (0x40, 8),
            (0x48, 8),
            (0x50, 8),
            (0x58, 4),
            (0x5c, 4),
            (0x60, 4),
            (0x80, 2),
            (0x100, 40),
            (0x140, 16),
            (0x160, 40),
            (0x190, 56),
            (0x1d0, 48),
            (0x210, 88),
            (0x270, 64),
            (0x2b0, 64),
            (0x2f0, 8),
        ];
        for (index, (start, len)) in ranges.iter().enumerate() {
            assert!(*start + *len <= 4096);
            for (other_start, other_len) in ranges.iter().skip(index + 1) {
                assert!(*start + *len <= *other_start || *other_start + *other_len <= *start);
            }
        }
    }
}
