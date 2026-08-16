#[allow(dead_code)]
#[path = "../build.rs"]
mod kernel_build;

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[test]
fn layout_manifest_is_exact_and_fails_closed_on_drift() {
    let source = fs::read_to_string(layout_path()).expect("read canonical layout manifest");
    let layout = kernel_build::Layout::parse(&source).expect("parse canonical layout manifest");
    assert_eq!(layout.link_base, 0xffff_ffff_8000_0000);
    assert_eq!(layout.base_page_size, 4_096);
    assert_eq!(layout.kernel_boot_stack_size, 131_072);
    assert_eq!(layout.kernel_boot_stack_alignment, 4_096);
    assert_eq!(layout.temporary_virtual_address, 0xffff_ff00_0000_0000);
    assert_eq!(layout.temporary_indices, [510, 0, 0, 0]);
    assert_eq!(
        layout.temporary_virtual_address,
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS
    );
    assert_eq!(
        layout.temporary_indices,
        [
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX,
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
        ]
    );
    assert_eq!(
        layout.minimum_table_frame_count,
        u64::from(deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT)
    );
    assert_eq!(
        layout.maximum_table_frame_count,
        u64::from(deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT)
    );
    assert_eq!(
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE
    );
    assert_eq!(
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN,
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
            + deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT
                * deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE
    );
    assert_eq!(
        layout.max_normalized_memory_map_entries,
        deepwyrm_kernel::boot::MAX_BOOT_MEMORY_MAP_ENTRIES as u64
    );
    assert_eq!(
        layout.max_module_entries,
        deepwyrm_kernel::boot::MAX_BOOT_MODULE_ENTRIES as u64
    );

    for malformed in [
        format!("{source}\nunknown_contract_key = true\n"),
        source.replacen("version = 2", "version = 2\nversion = 2", 1),
        source.replace("version = 2", "version = 1"),
        source.replace(
            "kernel_boot_stack_size = 131072",
            "kernel_boot_stack_size = 65536",
        ),
        source.replace(
            "allowed_program_header_types = [\"PT_LOAD\"]",
            "allowed_program_header_types = [\"PT_LOAD\", \"PT_NOTE\"]",
        ),
        source.replace(
            "defined_incoming_gprs = [\"RDI\"]",
            "defined_incoming_gprs = [\"RDI\", \"RSI\"]",
        ),
        source.replace(
            "p_paddr_policy = \"ignored\"",
            "p_paddr_policy = \"load-address\"",
        ),
        source.replace(
            "acpi_duplicate_selected_guid = \"reject\"",
            "acpi_duplicate_selected_guid = \"first\"",
        ),
        source.replace(
            "acpi_preferred_invalid = \"reject-no-downgrade\"",
            "acpi_preferred_invalid = \"fallback\"",
        ),
        source.replace(
            "acpi_rsdp_length_rule = \"revision-lt-2:20;revision-ge-2:declared-36..4096\"",
            "acpi_rsdp_length_rule = \"unbounded\"",
        ),
        source.replace(
            "acpi_table_traversal = \"deferred-dw0-c\"",
            "acpi_table_traversal = \"loader-walk\"",
        ),
        source.replace(
            "temporary_virtual_address = \"0xffffff0000000000\"",
            "temporary_virtual_address = \"0xffffffff80000000\"",
        ),
        source.replace("pml4_index = 510", "pml4_index = 511"),
        source.replace(
            "maximum_table_frame_count = 256",
            "maximum_table_frame_count = 257",
        ),
        source.replace(
            "initial_leaf = \"exactly-zero-non-present\"",
            "initial_leaf = \"present\"",
        ),
        source.replace("pcide_enabled = false", "pcide_enabled = true"),
        source.replace("pge_enabled = false", "pge_enabled = true"),
        source.replace(
            "identity_alias_mutable_by_deepwyrm = true",
            "identity_alias_mutable_by_deepwyrm = false",
        ),
    ] {
        assert!(kernel_build::Layout::parse(&malformed).is_err());
    }
}

#[test]
fn guest_test_identity_is_resolved_only_from_the_canonical_selector() {
    let harness = fs::read_to_string(guest_harness_path()).expect("read guest harness manifest");
    for (selector, id) in [
        ("boot-handoff-pass", 1),
        ("exception-fail-path", 2),
        ("panic-path", 3),
        ("memory-mapping", 4),
        ("memory-unmapping", 5),
        ("memory-permissions", 6),
        ("memory-invalid-pointer", 7),
        ("memory-user-kernel-isolation", 8),
        ("memory-shared-memory-object", 9),
    ] {
        assert_eq!(
            kernel_build::select_guest_test(true, Some(selector), false, &harness),
            Ok(Some(id)),
            "selector {selector} must retain its immutable harness ID"
        );
    }
    assert!(kernel_build::select_guest_test(true, Some("unknown-test"), false, &harness).is_err());
    assert!(kernel_build::select_guest_test(true, None, false, &harness).is_err());
    assert!(kernel_build::select_guest_test(false, Some("panic-path"), false, "").is_err());
    assert!(kernel_build::select_guest_test(true, Some("panic-path"), true, &harness).is_err());
    assert_eq!(
        kernel_build::select_guest_test(false, None, false, ""),
        Ok(None)
    );
}

#[test]
fn guest_test_manifest_rejects_ambiguous_or_reserved_ids() {
    for malformed in [
        "schema_version = 1\n[guest_test.a]\nid = 1\n[guest_test.a]\nid = 2\n",
        "schema_version = 1\n[guest_test.a]\nid = 1\n[guest_test.b]\nid = 1\n",
        "schema_version = 1\n[guest_test.a]\nid = 0\n",
        "schema_version = 1\n[guest_test.a]\nid = 4294967296\n",
        "schema_version = 1\n[guest_test.a]\nid = 1\nid = 2\n",
        "schema_version = 1\n[guest_test.a]\n",
        "schema_version = 1\n[guest_test.a]\nname = \"a\"\n",
        "schema_version = 1\n[unknown.a]\nid = 1\n",
        "schema_version = 2\n[guest_test.a]\nid = 1\n",
        "schema_version = 1\n[guest_test.INVALID]\nid = 1\n",
    ] {
        assert!(
            kernel_build::select_guest_test(true, Some("a"), false, malformed).is_err(),
            "accepted malformed guest harness:\n{malformed}"
        );
    }
}

#[test]
fn entry_shim_switches_stacks_before_its_first_push() {
    let assembly = fs::read_to_string(entry_assembly_path()).expect("read entry assembly");
    let entry = assembly
        .split_once("_dw_kernel_entry:")
        .expect("entry label")
        .1;
    let cli = entry.find("cli").expect("cli");
    let cld = entry.find("cld").expect("cld");
    let stack_switch = entry
        .find("leaq __dw_boot_stack_top(%rip), %rsp")
        .expect("kernel stack switch");
    let call = entry
        .find("callq dw_kernel_rust_entry")
        .expect("System V Rust call");
    assert!(stack_switch < cli && cli < cld && cld < call);

    let before_stack_switch = &entry[..stack_switch];
    for forbidden in ["push", "pop", "call", "ret", "%rsp"] {
        assert!(
            !before_stack_switch.contains(forbidden),
            "`{forbidden}` used before the kernel-owned stack switch"
        );
    }
    assert!(entry[call..].contains("hlt"));
    assert!(assembly.contains(".skip DW_KERNEL_BOOT_STACK_SIZE"));
    assert!(assembly.contains(".balign DW_KERNEL_BOOT_STACK_ALIGNMENT"));

    let rust_entry = fs::read_to_string(entry_rust_path()).expect("read Rust entry boundary");
    assert!(rust_entry.contains("extern \"sysv64\" fn dw_kernel_rust_entry"));
    let normalize = rust_entry
        .find("normalize_dw0_c_cpu_state();")
        .expect("consumer-owned CPU normalization call");
    let kernel_main = rust_entry
        .find("crate::kernel_main(boot_info_physical)")
        .expect("kernel main call");
    assert!(normalize < kernel_main);
    for required in [
        "\"pushfq\"",
        "\"mov {scratch}, cr4\"",
        "\"btr {scratch}, 21\"",
        "\"mov cr4, {scratch}\"",
        "\"btr qword ptr [rsp], 18\"",
        "\"popfq\"",
    ] {
        assert!(
            rust_entry.contains(required),
            "entry normalization omitted `{required}`"
        );
    }
    assert_eq!(rust_entry.matches("\"pushfq\"").count(), 1);
    assert_eq!(rust_entry.matches("\"popfq\"").count(), 1);
    assert_eq!(rust_entry.matches("\"mov cr4, {scratch}\"").count(), 1);
    assert!(!rust_entry.contains("options(nomem"));
    assert!(rust_entry.contains("crate::kernel_main(boot_info_physical)"));
    assert!(rust_entry.contains("#[allow("));
    assert!(rust_entry.contains("unsafe_code,"));
}

#[test]
fn kernel_assembler_disables_clang_default_configuration_discovery() {
    let build_script =
        fs::read_to_string(kernel_root().join("build.rs")).expect("read kernel build script");
    let assembler = build_script
        .split_once("pub(crate) fn assemble_source")
        .expect("assembler helper")
        .1
        .split_once("fn required_env")
        .expect("assembler helper terminator")
        .0;
    assert_eq!(
        assembler.matches(".arg(\"--no-default-config\")").count(),
        1
    );
    assert!(
        assembler.find(".arg(\"--no-default-config\")")
            < assembler.find("--target={KERNEL_TARGET}"),
        "Clang default configuration must be disabled before target selection"
    );
}

#[test]
fn linked_entry_and_rust_boundary_match_the_canonical_elf_policy() {
    let clang = env::var_os("DEEPWYRM_CLANG").unwrap_or_else(|| "clang".into());
    if !tool_available(&clang)
        || !tool_available(OsStr::new("rustc"))
        || !tool_available(OsStr::new("ld.lld"))
        || !tool_available(OsStr::new("llvm-nm"))
    {
        eprintln!("skipping x86_64 entry link probe: clang, rustc, ld.lld, or llvm-nm unavailable");
        return;
    }

    let source = fs::read_to_string(layout_path()).expect("read canonical layout manifest");
    let layout = kernel_build::Layout::parse(&source).expect("parse canonical layout manifest");
    let temporary = TemporaryDirectory::new("deepwyrm-x86_64-entry-contract");
    let entry_object = temporary.path.join("entry.o");
    let exceptions_object = temporary.path.join("exceptions.o");
    let rust_object = temporary.path.join("rust-boundary.o");
    let section_object = temporary.path.join("section-probe.o");
    let kernel_elf = temporary.path.join("deepwyrm-kernel.elf");

    let rust_source = temporary.path.join("rust-boundary.rs");
    let entry_path = entry_rust_path();
    fs::write(
        &rust_source,
        format!(
            r#"#![no_std]
#![deny(unsafe_code)]

#[path = "{}"]
mod entry;

#[inline(never)]
fn kernel_main(_boot_info_physical: u64) -> ! {{
    loop {{ core::hint::spin_loop(); }}
}}

#[allow(unsafe_code, reason = "fixed symbol required by the audited exception assembly boundary")]
#[unsafe(no_mangle)]
extern "sysv64" fn dw_x86_64_exception_dispatch(
    _vector: u64,
    _error_code: u64,
    _frame: *const u64,
) -> ! {{
    loop {{ core::hint::spin_loop(); }}
}}

#[allow(unsafe_code, reason = "fixed symbol required by the audited APIC assembly boundary")]
#[unsafe(no_mangle)]
extern "sysv64" fn dw_x86_64_terminal_interrupt_dispatch(_vector: u64) -> ! {{
    loop {{ core::hint::spin_loop(); }}
}}
"#,
            entry_path.display()
        ),
    )
    .expect("write Rust boundary probe");

    run_success(
        Command::new("rustc")
            .args([
                "--edition=2024",
                "--crate-type=lib",
                "--emit=obj",
                "-C",
                "panic=abort",
                "-C",
                "relocation-model=static",
                "-C",
                "code-model=kernel",
                "-C",
                "no-redzone=yes",
            ])
            .arg(&rust_source)
            .arg("-o")
            .arg(&rust_object),
        "compile the actual Rust entry boundary",
    );

    kernel_build::assemble_source(&entry_assembly_path(), &entry_object, layout)
        .expect("assemble the actual entry shim through the kernel build helper");
    kernel_build::assemble_source(&exceptions_assembly_path(), &exceptions_object, layout)
        .expect("assemble the actual exception stubs through the kernel build helper");

    let section_source = temporary.path.join("section-probe.S");
    fs::write(
        &section_source,
        r#".section .rodata,"a",@progbits
.globl dw_test_rodata_probe
dw_test_rodata_probe:
.quad 0x1122334455667788
.section .data,"aw",@progbits
.globl dw_test_data_probe
dw_test_data_probe:
.quad 0x8877665544332211
.section .bss,"aw",@nobits
.globl dw_test_bss_probe
dw_test_bss_probe:
.skip 64
.section .note.GNU-stack,"",@progbits
"#,
    )
    .expect("write section probe");
    run_success(
        Command::new(&clang)
            .arg("--no-default-config")
            .arg("--target=x86_64-unknown-none")
            .args(["-ffreestanding", "-fno-pic", "-c"])
            .arg(&section_source)
            .arg("-o")
            .arg(&section_object),
        "assemble the section-layout probe",
    );

    let link_arguments = kernel_build::linker_arguments(
        layout,
        &linker_path(),
        &[entry_object.as_path(), exceptions_object.as_path()],
    );
    run_success(
        Command::new("ld.lld")
            .args(["-m", "elf_x86_64"])
            .args(link_arguments)
            .args([
                "--undefined=dw_test_rodata_probe",
                "--undefined=dw_test_data_probe",
                "--undefined=dw_test_bss_probe",
            ])
            .arg(&rust_object)
            .arg(&section_object)
            .arg("-o")
            .arg(&kernel_elf),
        "link the entry artifact probe",
    );

    let elf = fs::read(&kernel_elf).expect("read linked ELF probe");
    validate_elf(&elf, layout);

    let symbols = run_success(
        Command::new("llvm-nm")
            .arg("--defined-only")
            .arg(&kernel_elf),
        "inspect retained entry symbols",
    );
    let symbols = String::from_utf8(symbols.stdout).expect("llvm-nm output is UTF-8");
    for symbol in [
        "_dw_kernel_entry",
        "dw_kernel_rust_entry",
        "dw_x86_64_exception_handler_table",
        "dw_x86_64_exception_vector_0",
        "dw_x86_64_exception_vector_31",
        "dw_x86_64_apic_error_entry",
        "dw_x86_64_apic_spurious_entry",
        "dw_x86_64_exception_dispatch",
        "dw_x86_64_terminal_interrupt_dispatch",
    ] {
        assert!(
            symbols.lines().any(|line| line.ends_with(symbol)),
            "missing retained symbol `{symbol}`"
        );
    }
}

fn validate_elf(bytes: &[u8], layout: kernel_build::Layout) {
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2, "ELFCLASS64");
    assert_eq!(bytes[5], 1, "ELFDATA2LSB");
    assert_eq!(u16_at(bytes, 16), 2, "ET_EXEC");
    assert_eq!(u16_at(bytes, 18), 62, "EM_X86_64");

    let entry = u64_at(bytes, 24);
    assert_eq!(entry, layout.link_base);
    let program_header_offset = usize::try_from(u64_at(bytes, 32)).expect("program header offset");
    let program_header_size = usize::from(u16_at(bytes, 54));
    let program_header_count = usize::from(u16_at(bytes, 56));
    assert_eq!(program_header_size, 56);

    let mut loads = Vec::new();
    for index in 0..program_header_count {
        let offset = program_header_offset + index * program_header_size;
        let header = ProgramHeader {
            kind: u32_at(bytes, offset),
            flags: u32_at(bytes, offset + 4),
            file_offset: u64_at(bytes, offset + 8),
            virtual_address: u64_at(bytes, offset + 16),
            file_size: u64_at(bytes, offset + 32),
            memory_size: u64_at(bytes, offset + 40),
            alignment: u64_at(bytes, offset + 48),
        };
        assert_eq!(header.kind, PT_LOAD, "only PT_LOAD is canonical");
        loads.push(header);
    }

    assert_eq!(loads.len(), 3);
    assert_eq!(
        loads.iter().map(|header| header.flags).collect::<Vec<_>>(),
        [PF_R | PF_X, PF_R, PF_R | PF_W]
    );
    for (index, header) in loads.iter().enumerate() {
        assert!(header.virtual_address >= 0xffff_8000_0000_0000);
        assert_eq!(header.alignment, layout.base_page_size);
        assert_eq!(
            header.file_offset % header.alignment,
            header.virtual_address % header.alignment
        );
        assert!(header.file_size <= header.memory_size);
        assert_ne!(header.flags & (PF_W | PF_X), PF_W | PF_X, "RWX PT_LOAD");
        let end = header
            .virtual_address
            .checked_add(header.memory_size)
            .expect("PT_LOAD range does not overflow");
        assert!(
            layout.temporary_virtual_address < header.virtual_address
                || layout.temporary_virtual_address >= end,
            "temporary mapping overlaps a PT_LOAD"
        );
        if let Some(next) = loads.get(index + 1) {
            assert!(end <= next.virtual_address, "overlapping PT_LOAD ranges");
        }
    }
    assert!(loads.iter().any(|header| {
        header.flags & PF_X != 0
            && entry >= header.virtual_address
            && entry < header.virtual_address + header.memory_size
    }));
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 field"))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
}

fn run_success(command: &mut Command, description: &str) -> Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("could not {description}: {error}");
    });
    assert!(
        output.status.success(),
        "could not {description}: status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn tool_available(program: &OsStr) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn kernel_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn layout_path() -> PathBuf {
    kernel_root().join("arch/x86_64/layout.toml")
}

fn linker_path() -> PathBuf {
    kernel_root().join("arch/x86_64/linker.ld")
}

fn guest_harness_path() -> PathBuf {
    kernel_root().join("../tooling/guest-harness.toml")
}

fn entry_assembly_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/entry.S")
}

fn entry_rust_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/entry.rs")
}

fn exceptions_assembly_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/exceptions.S")
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!("{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("create test temporary directory");
        Self { path }
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
