use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
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
    let pools_path = manifest_dir.join("arch/x86_64/pools.toml");
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
    println!("cargo:rerun-if-changed={}", pools_path.display());
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
    println!("cargo:rerun-if-env-changed=DEEPWYRM_BOOTFS_MAX_PAGES");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_c3_one_shot_ui)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_memory_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_e7_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_f9_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_f12_guest)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_dw1e_platform)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_production_product)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_integrated)");
    println!("cargo:rustc-cfg=deepwyrm_integrated");

    // DW1-F/WYR1-F F1A.2 moved the surface itself off the guest-test selector.
    // Every freestanding kernel now brings up the q35 IOAPIC and installs the
    // COM2 external-vector dispatch, because the whole WYR1 console spine
    // depends on interrupt-driven UART delivery: a kernel built without a
    // selector used to compile that path out entirely and could not reach a
    // prompt, which made the uninstrumented artifact something other than a
    // production system.
    //
    // Host builds stay excluded. The q35 modules already compile under
    // `cfg(test)` where host tests need them, and `idt.rs`'s
    // `only_approved_early_vectors_have_gates` asserts the non-q35 IDT shape
    // under `cfg(not(deepwyrm_dw1e_platform))`; emitting the cfg for host
    // builds would silently delete that coverage.
    if required_env("TARGET")? == KERNEL_TARGET {
        println!("cargo:rustc-cfg=deepwyrm_dw1e_platform");
    }

    // DW1-F/WYR1-F F2A.2. The production product is the freestanding kernel
    // that selects no guest test, and until F2A.1 nothing in the tree said so:
    // every capacity arm in `activation/primordial.rs` keys off an evidence
    // cfg, so a selectorless build fell through to the bootstrap-era DW0
    // geometry of three Processes and one TaskGroup and could not instantiate
    // the frozen six-role product. This marker is what the production arm
    // selects on. Host builds are excluded, so the model tests keep the
    // bootstrap-era shape they were written against; selector builds are
    // excluded because each already carries its own ledger.
    let selector = env::var("DEEPWYRM_GUEST_TEST_SELECTOR").ok();
    if selector.is_none() && required_env("TARGET")? == KERNEL_TARGET {
        println!("cargo:rustc-cfg=deepwyrm_production_product");
    }

    let layout_source = fs::read_to_string(&layout_path)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;
    let layout = Layout::parse(&layout_source)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;
    let task_layout_source = fs::read_to_string(&task_layout_path)
        .map_err(|error| format!("{}: {error}", task_layout_path.display()))?;
    let task_layout = TaskLayout::parse(&task_layout_source)
        .map_err(|error| format!("{}: {error}", task_layout_path.display()))?;
    let pools_source = fs::read_to_string(&pools_path)
        .map_err(|error| format!("{}: {error}", pools_path.display()))?;
    let pools = Pools::parse(&pools_source, task_layout)
        .map_err(|error| format!("{}: {error}", pools_path.display()))?;
    emit_task_layout_env(task_layout);
    pools.emit_env();

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
    let linked = fs::read(elf).map_err(|error| format!("{}: {error}", elf.display()))?;
    verify_e7_user_elf(&linked)
}

/// Checks the linked E7 userspace ELF, which is parsed, never executed, and
/// treated as hostile: every read is bounds-checked and every offset sum is
/// checked, and anything unexpected is an error.
///
/// It holds what the E7 contract needs of the linked program: a static
/// x86_64 executable entered at `_start` = `E7_USER_ENTRY`, one read+execute
/// (never writable) load segment that fits one base page, and every SYSCALL
/// instruction encoding (`0f 05`) in that segment inside the generated
/// `dw_syscall6` veneer, so the user body reaches the kernel only through it.
/// The byte scan does not decode instructions, so a `0f 05` pair inside
/// another instruction outside the veneer also fails: closed, not open.
fn verify_e7_user_elf(elf: &[u8]) -> Result<(), String> {
    const PT_LOAD: u32 = 1;
    const PT_GNU_STACK: u32 = 0x6474_e551;
    const PF_X: u32 = 1;
    const PF_R: u32 = 4;
    const SHT_SYMTAB: u32 = 2;
    const SHT_STRTAB: u32 = 3;
    const BASE_PAGE: u64 = 4096;

    let image = ElfImage::new(elf, "E7 userspace ELF")?;
    let header = image.bytes(0, 64)?;
    if header[..4] != *b"\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err("E7 userspace ELF is not a version-1 little-endian ELF64".into());
    }
    if image.u16(16)? != 2 || image.u16(18)? != 62 {
        return Err("E7 userspace ELF is not a static x86_64 executable".into());
    }
    let entry = image.u64(24)?;
    let program_headers = image.u64(32)?;
    let section_headers = image.u64(40)?;
    if image.u16(54)? != 56 || image.u16(58)? != 64 {
        return Err("E7 userspace ELF has unexpected header entry sizes".into());
    }
    let program_count = u64::from(image.u16(56)?);
    let section_count = u64::from(image.u16(60)?);

    let mut load = None;
    for index in 0..program_count {
        let at = image.entry(program_headers, index, 56)?;
        let kind = image.u32(at)?;
        let flags = image.u32(at + 4)?;
        match kind {
            PT_LOAD if load.is_none() => {
                if flags != PF_R | PF_X {
                    return Err(format!(
                        "E7 userspace load segment flags are {flags:#x}, not read+execute"
                    ));
                }
                let offset = image.u64(at + 8)?;
                let address = image.u64(at + 16)?;
                let file_size = image.u64(at + 32)?;
                let memory_size = image.u64(at + 40)?;
                if file_size != memory_size || memory_size == 0 || memory_size > BASE_PAGE {
                    return Err(format!(
                        "E7 userspace load segment is {file_size} file and {memory_size} memory bytes, not 1..={BASE_PAGE} file-backed bytes"
                    ));
                }
                image.bytes(offset, file_size)?;
                load = Some((offset, address, file_size));
            }
            PT_LOAD => return Err("E7 userspace ELF has more than one load segment".into()),
            PT_GNU_STACK if flags & PF_X == 0 => {}
            other => {
                return Err(format!(
                    "E7 userspace ELF has unexpected program header type {other:#x} flags {flags:#x}"
                ));
            }
        }
    }
    let (offset, address, size) =
        load.ok_or_else(|| "E7 userspace ELF has no load segment".to_owned())?;
    let end = address
        .checked_add(size)
        .ok_or_else(|| "E7 userspace load segment wraps".to_owned())?;

    let mut symbol_table = None;
    for index in 0..section_count {
        let at = image.entry(section_headers, index, 64)?;
        if image.u32(at + 4)? == SHT_SYMTAB {
            if symbol_table.is_some() {
                return Err("E7 userspace ELF has more than one symbol table".into());
            }
            symbol_table = Some(at);
        }
    }
    let symbol_table =
        symbol_table.ok_or_else(|| "E7 userspace ELF has no symbol table".to_owned())?;
    let symbols_offset = image.u64(symbol_table + 24)?;
    let symbols_size = image.u64(symbol_table + 32)?;
    if image.u64(symbol_table + 56)? != 24 || symbols_size % 24 != 0 {
        return Err("E7 userspace symbol table has an unexpected entry size".into());
    }
    let strings = image.entry(
        section_headers,
        u64::from(image.u32(symbol_table + 40)?),
        64,
    )?;
    if image.u32(strings + 4)? != SHT_STRTAB {
        return Err("E7 userspace symbol table does not link a string table".into());
    }
    let strings = image.bytes(image.u64(strings + 24)?, image.u64(strings + 32)?)?;
    image.bytes(symbols_offset, symbols_size)?;

    let mut start = None;
    let mut veneer = None;
    for index in 0..symbols_size / 24 {
        let at = image.entry(symbols_offset, index, 24)?;
        let name_offset = usize::try_from(image.u32(at)?)
            .map_err(|_| "E7 userspace symbol name offset does not fit".to_owned())?;
        let name = strings
            .get(name_offset..)
            .and_then(|tail| tail.split(|byte| *byte == 0).next())
            .ok_or_else(|| "E7 userspace symbol name is out of bounds".to_owned())?;
        let section = image.u16(at + 6)?;
        let value = image.u64(at + 8)?;
        let symbol_size = image.u64(at + 16)?;
        let slot = match name {
            b"_start" => &mut start,
            b"dw_syscall6" => &mut veneer,
            _ => continue,
        };
        if slot.is_some() || section == 0 {
            return Err(format!(
                "E7 userspace symbol {} is duplicated or undefined",
                String::from_utf8_lossy(name)
            ));
        }
        *slot = Some((value, symbol_size));
    }
    let (start, _) = start.ok_or_else(|| "E7 userspace ELF omits _start".to_owned())?;
    let (veneer, veneer_size) =
        veneer.ok_or_else(|| "E7 userspace ELF omits the dw_syscall6 veneer".to_owned())?;
    if entry != start || entry != E7_USER_ENTRY {
        return Err(format!(
            "E7 userspace entry {entry:#x} is not _start {start:#x} at {E7_USER_ENTRY:#x}"
        ));
    }
    let veneer_end = veneer
        .checked_add(veneer_size)
        .ok_or_else(|| "E7 userspace veneer wraps".to_owned())?;
    if veneer_size == 0 || veneer < address || veneer_end > end {
        return Err("E7 userspace veneer lies outside the load segment".into());
    }

    let text = image.bytes(offset, size)?;
    let mut veneer_syscalls = 0_usize;
    for (index, pair) in text.windows(2).enumerate() {
        if pair != [0x0f, 0x05] {
            continue;
        }
        let at = u64::try_from(index)
            .ok()
            .and_then(|index| address.checked_add(index))
            .ok_or_else(|| "E7 userspace text address wraps".to_owned())?;
        if at < veneer
            || at
                .checked_add(2)
                .is_none_or(|pair_end| pair_end > veneer_end)
        {
            return Err(format!(
                "E7 userspace SYSCALL encoding at {at:#x} lies outside the dw_syscall6 veneer"
            ));
        }
        veneer_syscalls += 1;
    }
    if veneer_syscalls != 1 {
        return Err(format!(
            "E7 userspace veneer holds {veneer_syscalls} SYSCALL encodings, not one"
        ));
    }
    Ok(())
}

/// Bounds-checked little-endian reads over an untrusted ELF image. Field
/// offsets are added only to an offset `entry` has proven lies inside the
/// image with the whole entry after it, so those sums cannot overflow.
struct ElfImage<'a> {
    bytes: &'a [u8],
    label: &'static str,
}

impl<'a> ElfImage<'a> {
    fn new(bytes: &'a [u8], label: &'static str) -> Result<Self, String> {
        Ok(Self { bytes, label })
    }

    fn bytes(&self, offset: u64, length: u64) -> Result<&'a [u8], String> {
        let start = usize::try_from(offset).ok();
        let end = offset
            .checked_add(length)
            .and_then(|end| usize::try_from(end).ok());
        match (start, end) {
            (Some(start), Some(end)) => self.bytes.get(start..end),
            _ => None,
        }
        .ok_or_else(|| {
            format!(
                "{} is truncated: {length} bytes at {offset:#x} exceed its {} bytes",
                self.label,
                self.bytes.len()
            )
        })
    }

    /// The offset of entry `index` of `size` bytes in a table at `base`.
    fn entry(&self, base: u64, index: u64, size: u64) -> Result<u64, String> {
        let at = index
            .checked_mul(size)
            .and_then(|delta| base.checked_add(delta))
            .ok_or_else(|| format!("{} table offset overflows", self.label))?;
        self.bytes(at, size)?;
        Ok(at)
    }

    fn u16(&self, offset: u64) -> Result<u16, String> {
        let bytes = self.bytes(offset, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&self, offset: u64) -> Result<u32, String> {
        let bytes = self.bytes(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&self, offset: u64) -> Result<u64, String> {
        let bytes = self.bytes(offset, 8)?;
        let mut word = [0_u8; 8];
        word.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(word))
    }
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

    // Emitted for every configuration, selector or not, so the production
    // `PRIMORDIAL_BOOTFS_MAX_PAGES` arm can read it with `env!` rather than
    // `option_env!` and a second default. The selector arms keep their own
    // per-selector variables; this one is only consulted by the no-selector
    // arm. F3A.6y.
    println!(
        "cargo:rustc-env=DEEPWYRM_BOOTFS_MAX_PAGES={}",
        production_bootfs_pages()?
    );

    if let Some(test_id) = select_guest_test(
        feature_enabled,
        selector.as_deref(),
        direct_id_present,
        &harness_source,
    )? {
        let selector = selector.expect("validated enabled configuration has a selector");
        println!("cargo:rustc-env=DEEPWYRM_GUEST_TEST_SELECTOR={selector}");
        println!("cargo:rustc-env=DEEPWYRM_GUEST_TEST_ID={test_id}");
    }
    Ok(())
}

/// The production bootfs page ceiling, measured by the producer when it is
/// available and otherwise the historical Wave 4 constant.
///
/// F3A.6y. The four selector arms derive this from the producer's measured
/// archive; production held a literal 17, which is a measurement of the Wave 4
/// archive and eleven revisions of F3A were spent discovering that the WYR1-F
/// archive is 203 pages. Selector 34's own comment already said why: "a
/// guessed constant is what made an oversized archive surface as an opaque
/// NO_RESOURCES from the bootstrap's bootfs mapping instead of a build error."
///
/// Unlike the selector arms this is **optional**, and that is deliberate. A
/// selector build is always driven by a producer that knows its archive, so a
/// missing variable there is a bug worth failing on. The production kernel
/// must also build standalone -- `cargo build`, the host gates, the target
/// clippy lane -- where no archive exists to measure. So an absent variable
/// keeps the historical value rather than failing, and a present one is
/// validated exactly as the selector arms validate theirs.
fn production_bootfs_pages() -> Result<String, String> {
    const NAME: &str = "DEEPWYRM_BOOTFS_MAX_PAGES";
    resolve_production_bootfs_pages(env::var(NAME).ok())
}

/// The production ceiling for a `DEEPWYRM_BOOTFS_MAX_PAGES` value, or for its
/// absence (`None`, which an unreadable value also is).
fn resolve_production_bootfs_pages(value: Option<String>) -> Result<String, String> {
    // The Wave 4 archive's measured size, retained so a build with no producer
    // behaves exactly as it did before this revision.
    const HISTORICAL_WAVE4_PAGES: &str = "17";
    match value {
        None => Ok(HISTORICAL_WAVE4_PAGES.to_owned()),
        Some(value) => {
            validate_production_bootfs_pages(&value)?;
            Ok(value)
        }
    }
}

fn validate_production_bootfs_pages(value: &str) -> Result<usize, String> {
    const NAME: &str = "DEEPWYRM_BOOTFS_MAX_PAGES";
    let pages = value
        .parse::<usize>()
        .map_err(|_| format!("{NAME} must be canonical decimal"))?;
    if pages == 0 || pages > 8192 || pages.to_string() != value {
        return Err(format!("{NAME} must be canonical decimal in 1..=8192"));
    }
    Ok(pages)
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
        "--no-eh-frame-hdr".to_owned(),
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
        .args(assembler_arguments(source, output, layout))
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

/// The kernel assembler's exact Clang argument list, in order.
fn assembler_arguments(source: &Path, output: &Path, layout: Layout) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = vec![
        "--no-default-config".into(),
        format!("--target={KERNEL_TARGET}").into(),
    ];
    arguments.extend(
        [
            "-ffreestanding",
            "-fno-pic",
            "-fno-stack-protector",
            "-mno-red-zone",
            "-mno-mmx",
            "-mno-sse",
            "-mno-sse2",
        ]
        .map(OsString::from),
    );
    arguments.push(
        format!(
            "-DDW_KERNEL_BOOT_STACK_SIZE={}",
            layout.kernel_boot_stack_size
        )
        .into(),
    );
    arguments.push(
        format!(
            "-DDW_KERNEL_BOOT_STACK_ALIGNMENT={}",
            layout.kernel_boot_stack_alignment
        )
        .into(),
    );
    arguments.push("-c".into());
    arguments.push(source.into());
    arguments.push("-o".into());
    arguments.push(output.into());
    arguments
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
        // W7 (root `STORAGE_PLAN.md`): the production ledger's thirty-two
        // identities, one guarded stack each.
        if count != 32
            || size != 524_288
            || guard != 4_096
            || alignment != 4_096
            || !size.is_multiple_of(alignment)
            || !guard.is_multiple_of(alignment)
        {
            return Err(
                "DW0-E3 thread stack pool must be 32 guarded 524288-byte stacks on 4096-byte boundaries"
                    .into(),
            );
        }
        if privilege_count != 1
            || privilege_size != 262_144
            || privilege_guard != 4_096
            || privilege_alignment != 4_096
            || !privilege_size.is_multiple_of(privilege_alignment)
            || !privilege_guard.is_multiple_of(privilege_alignment)
        {
            return Err("DW0-E4 BSP privilege-entry stack must be one guarded 262144-byte stack on a 4096-byte boundary".into());
        }
        if terminal_count != 1
            || terminal_size != 262_144
            || terminal_guard != 4_096
            || terminal_alignment != 4_096
            || !terminal_size.is_multiple_of(terminal_alignment)
            || !terminal_guard.is_multiple_of(terminal_alignment)
        {
            return Err("terminal reaper carrier must be one guarded 262144-byte stack on a 4096-byte boundary".into());
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

/// The production kernel's pool capacities (`arch/x86_64/pools.toml`).
#[allow(
    dead_code,
    reason = "the artifact contract tests include this build script and use only its layouts"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pools {
    pub(crate) values: [(&'static str, u32); POOL_KEYS.len()],
}

pub(crate) const POOL_KEYS: [&str; 11] = [
    "handles_per_process",
    "identities",
    "registry_objects",
    "memory_objects",
    "mapping_leases",
    "region_slots",
    "channel_pairs",
    "channel_depth",
    "wait_registrations",
    "timers",
    "events",
];

#[allow(
    dead_code,
    reason = "the artifact contract tests include this build script and use only its layouts"
)]
impl Pools {
    pub(crate) fn parse(source: &str, task_layout: TaskLayout) -> Result<Self, String> {
        let values = parse_flat_toml(source)?;
        let expected = ["schema", "version"]
            .into_iter()
            .chain(POOL_KEYS)
            .collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
            let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
            return Err(format!(
                "pool keys do not match contract; missing={missing:?}, unknown={unknown:?}"
            ));
        }
        expect_string(&values, "schema", "deepwyrm-x86_64-pools")?;
        expect_u64(&values, "version", 1)?;
        let mut pools = Self {
            values: POOL_KEYS.map(|key| (key, 0)),
        };
        for (key, slot) in POOL_KEYS
            .iter()
            .zip(pools.values.iter_mut().map(|(_, value)| value))
        {
            let value = parse_u64(required_value(&values, key)?)?;
            let value = u32::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| format!("`{key}` must be a nonzero 32-bit count"))?;
            *slot = value;
        }
        if u64::from(pools.get("identities")) > task_layout.thread_kernel_stack_count {
            return Err(format!(
                "`identities` ({}) exceeds the {} thread kernel stacks of task_layout.toml; \
                 every Thread needs one",
                pools.get("identities"),
                task_layout.thread_kernel_stack_count
            ));
        }
        Ok(pools)
    }

    pub(crate) fn get(&self, key: &str) -> u32 {
        self.values
            .iter()
            .find_map(|(name, value)| (*name == key).then_some(*value))
            .unwrap_or(0)
    }

    fn emit_env(&self) {
        for (key, value) in self.values {
            println!(
                "cargo:rustc-env=DEEPWYRM_POOL_{}={value}",
                key.to_ascii_uppercase()
            );
        }
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
        if kernel_boot_stack_size != 4_194_304
            || kernel_boot_stack_size % kernel_boot_stack_alignment != 0
        {
            return Err("kernel boot stack must be an aligned 4194304-byte range".into());
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

    /// F3A.6y. Production's ceiling is now measured when a producer measured
    /// it, and the historical Wave 4 value otherwise.
    ///
    /// The default matters as much as the validation: the production kernel
    /// must build standalone, and silently changing what a plain `cargo build`
    /// admits would be a behaviour change smuggled in behind a diagnostic fix.
    #[test]
    fn the_production_bootfs_bound_is_measured_when_measured_and_historical_otherwise() {
        // 203 is the WYR1-F archive that exposed the 17-page ceiling (F3A.6x);
        // the bound must accept it and the whole range the const parser asserts.
        for (value, pages) in [("1", 1), ("17", 17), ("203", 203), ("8192", 8192)] {
            assert_eq!(validate_production_bootfs_pages(value), Ok(pages));
        }
        // Non-canonical and out-of-range values are refused rather than
        // silently clamped -- a clamped ceiling is the guess this replaced.
        for invalid in ["", "0", "01", "+1", " 17", "17 ", "8193", "not-pages"] {
            assert!(
                validate_production_bootfs_pages(invalid).is_err(),
                "{invalid:?} must be refused"
            );
        }
    }

    #[test]
    fn an_unmeasured_production_build_admits_the_historical_seventeen_pages() {
        assert_eq!(resolve_production_bootfs_pages(None), Ok("17".to_owned()));
        assert_eq!(
            resolve_production_bootfs_pages(Some("40".to_owned())),
            Ok("40".to_owned())
        );
        for invalid in ["0", "017", "8193", "", "x"] {
            assert!(
                resolve_production_bootfs_pages(Some(invalid.to_owned())).is_err(),
                "{invalid:?} was accepted as a bootfs ceiling"
            );
        }
    }

    #[test]
    fn kernel_assembler_disables_clang_default_configuration_before_target_selection() {
        let layout = Layout::parse(include_str!("arch/x86_64/layout.toml")).unwrap();
        let arguments = assembler_arguments(Path::new("entry.S"), Path::new("entry.o"), layout);
        let position = |wanted: &str| {
            let mut matches = arguments
                .iter()
                .enumerate()
                .filter(|(_, argument)| *argument == wanted);
            let (index, _) = matches
                .next()
                .unwrap_or_else(|| panic!("assembler arguments omit {wanted}"));
            assert!(matches.next().is_none(), "{wanted} is passed twice");
            index
        };
        assert!(
            position("--no-default-config") < position(&format!("--target={KERNEL_TARGET}")),
            "Clang default configuration must be disabled before target selection"
        );
    }

    /// A minimal E7-shaped ELF: one load segment at `E7_USER_ENTRY` holding
    /// `text`, with `_start` at its start and `dw_syscall6` at
    /// `veneer_offset` for `veneer_size` bytes.
    fn e7_elf(text: &[u8], flags: u32, veneer_offset: u64, veneer_size: u64) -> Vec<u8> {
        let text_offset = 64 + 56;
        let strings: &[u8] = b"\0_start\0dw_syscall6\0";
        let strings_offset = text_offset + text.len();
        let symbols_offset = strings_offset + strings.len();
        let sections_offset = symbols_offset + 3 * 24;
        let mut elf = vec![0_u8; sections_offset + 3 * 64];
        let put = |elf: &mut Vec<u8>, at: usize, bytes: &[u8]| {
            elf[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut elf, 0, b"\x7fELF\x02\x01\x01");
        put(&mut elf, 16, &2_u16.to_le_bytes());
        put(&mut elf, 18, &62_u16.to_le_bytes());
        put(&mut elf, 20, &1_u32.to_le_bytes());
        put(&mut elf, 24, &E7_USER_ENTRY.to_le_bytes());
        put(&mut elf, 32, &64_u64.to_le_bytes());
        put(&mut elf, 40, &(sections_offset as u64).to_le_bytes());
        put(&mut elf, 52, &64_u16.to_le_bytes());
        put(&mut elf, 54, &56_u16.to_le_bytes());
        put(&mut elf, 56, &1_u16.to_le_bytes());
        put(&mut elf, 58, &64_u16.to_le_bytes());
        put(&mut elf, 60, &3_u16.to_le_bytes());
        // The load segment.
        put(&mut elf, 64, &1_u32.to_le_bytes());
        put(&mut elf, 68, &flags.to_le_bytes());
        put(&mut elf, 72, &(text_offset as u64).to_le_bytes());
        put(&mut elf, 80, &E7_USER_ENTRY.to_le_bytes());
        put(&mut elf, 96, &(text.len() as u64).to_le_bytes());
        put(&mut elf, 104, &(text.len() as u64).to_le_bytes());
        put(&mut elf, text_offset, text);
        put(&mut elf, strings_offset, strings);
        // Symbols 1 and 2: `_start` and `dw_syscall6`, both defined.
        for (index, name, value, size) in [
            (1, 1_u32, E7_USER_ENTRY, 0),
            (2, 8, E7_USER_ENTRY + veneer_offset, veneer_size),
        ] {
            let at = symbols_offset + index * 24;
            put(&mut elf, at, &name.to_le_bytes());
            put(&mut elf, at + 6, &1_u16.to_le_bytes());
            put(&mut elf, at + 8, &value.to_le_bytes());
            put(&mut elf, at + 16, &size.to_le_bytes());
        }
        // Section 1 is the symbol table, linked to section 2's strings.
        let at = sections_offset + 64;
        put(&mut elf, at + 4, &2_u32.to_le_bytes());
        put(&mut elf, at + 24, &(symbols_offset as u64).to_le_bytes());
        put(&mut elf, at + 32, &(3 * 24_u64).to_le_bytes());
        put(&mut elf, at + 40, &2_u32.to_le_bytes());
        put(&mut elf, at + 56, &24_u64.to_le_bytes());
        let at = sections_offset + 2 * 64;
        put(&mut elf, at + 4, &3_u32.to_le_bytes());
        put(&mut elf, at + 24, &(strings_offset as u64).to_le_bytes());
        put(&mut elf, at + 32, &(strings.len() as u64).to_le_bytes());
        elf
    }

    /// `_start` calls the veneer, which owns the only SYSCALL.
    fn e7_text() -> Vec<u8> {
        let mut text = vec![0x90; 16];
        text.extend_from_slice(&[0x48, 0x89, 0xf8, 0x0f, 0x05, 0xc3]);
        text
    }

    #[test]
    fn the_e7_elf_check_accepts_a_veneer_owned_syscall() {
        assert_eq!(verify_e7_user_elf(&e7_elf(&e7_text(), 5, 16, 6)), Ok(()));
    }

    #[test]
    fn the_e7_elf_check_rejects_what_the_contract_forbids() {
        let mut raw = e7_text();
        raw[4..6].copy_from_slice(&[0x0f, 0x05]);
        for (label, elf) in [
            ("raw SYSCALL in _start", e7_elf(&raw, 5, 16, 6)),
            ("writable text", e7_elf(&e7_text(), 7, 16, 6)),
            ("read-only text", e7_elf(&e7_text(), 4, 16, 6)),
            (
                "veneer symbol short of its SYSCALL",
                e7_elf(&e7_text(), 5, 0, 3),
            ),
            ("veneer past the segment", e7_elf(&e7_text(), 5, 16, 64)),
            ("text over one page", e7_elf(&[0x90; 4097], 5, 0, 1)),
        ] {
            assert!(verify_e7_user_elf(&elf).is_err(), "{label} was accepted");
        }
        let mut moved = e7_elf(&e7_text(), 5, 16, 6);
        moved[24..32].copy_from_slice(&(E7_USER_ENTRY + 1).to_le_bytes());
        assert!(
            verify_e7_user_elf(&moved).is_err(),
            "moved entry was accepted"
        );
    }

    #[test]
    fn the_e7_elf_check_fails_closed_on_every_truncation() {
        let elf = e7_elf(&e7_text(), 5, 16, 6);
        for length in 0..elf.len() {
            assert!(
                verify_e7_user_elf(&elf[..length]).is_err(),
                "a {length}-byte prefix was accepted"
            );
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
