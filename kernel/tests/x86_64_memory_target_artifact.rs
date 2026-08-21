use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SELECTORS: [&str; 6] = [
    "memory-mapping",
    "memory-unmapping",
    "memory-permissions",
    "memory-invalid-pointer",
    "memory-user-kernel-isolation",
    "memory-shared-memory-object",
];
const E7_SELECTORS: [&str; 3] = [
    "task-syscall-smoke",
    "task-syscall-sanitize",
    "task-user-exception",
];
const OWNED_WORKSPACE_CARGO_CONFIG: &str = ".cargo/config.toml";
const LEGACY_WORKSPACE_CARGO_CONFIG: &str = ".cargo/config";

#[path = "x86_64_memory_target_artifact/artifact.rs"]
mod artifact;
#[path = "x86_64_memory_target_artifact/build_support.rs"]
mod build_support;
#[path = "x86_64_memory_target_artifact/environment.rs"]
mod environment;
#[path = "x86_64_memory_target_artifact/stack.rs"]
mod stack;

use artifact::*;
use build_support::*;
use environment::*;
use stack::*;

#[test]
#[ignore = "explicit accepted-toolchain x86_64 target-artifact gate"]
fn production_and_six_memory_selector_artifacts_are_separated() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kernel manifest has workspace parent")
        .to_path_buf();
    reject_ambient_build_overrides(&workspace);
    let cargo_path = required_path("DEEPWYRM_ACCEPTED_CARGO");
    let rustc_path = required_path("DEEPWYRM_ACCEPTED_RUSTC");
    let rust_lld_path = required_path("DEEPWYRM_ACCEPTED_RUST_LLD");
    let clang_path = required_path("DEEPWYRM_CLANG");
    let llvm_nm_path = required_path("DEEPWYRM_LLVM_NM");
    let llvm_objdump_path = required_path("DEEPWYRM_LLVM_OBJDUMP");
    let llvm_readelf_path = required_path("DEEPWYRM_LLVM_READELF");
    let toolchain_identity = fs::read_to_string(workspace.join("tooling/rust-toolchain.toml"))
        .expect("read trusted toolchain identity");
    let build_tools_identity = fs::read_to_string(workspace.join("tooling/build-tools.toml"))
        .expect("read trusted build-tools identity");
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        AcceptedToolPaths {
            cargo: &cargo_path,
            rustc: &rustc_path,
            rust_lld: &rust_lld_path,
            clang: &clang_path,
            llvm_nm: &llvm_nm_path,
            llvm_objdump: &llvm_objdump_path,
            llvm_readelf: &llvm_readelf_path,
        },
    );
    let runtime_artifacts = accepted_runtime_artifacts(&toolchain_identity, &cargo_path);
    let cargo = VerifiedExecutable::open(
        &cargo_path,
        manifest_value(&toolchain_identity, "cargo_sha256"),
        "cargo",
    );
    let rustc = VerifiedExecutable::open(
        &rustc_path,
        manifest_value(&toolchain_identity, "rustc_sha256"),
        "rustc",
    );
    let rust_lld = VerifiedExecutable::open(
        &rust_lld_path,
        manifest_value(&toolchain_identity, "rust_lld_sha256"),
        "rust-lld",
    );
    let clang = VerifiedExecutable::open(
        &clang_path,
        manifest_value(&build_tools_identity, "clang_sha256"),
        "clang",
    );
    let llvm_nm = VerifiedExecutable::open(
        &llvm_nm_path,
        manifest_value(&build_tools_identity, "llvm_nm_sha256"),
        "llvm-nm",
    );
    let llvm_objdump = VerifiedExecutable::open(
        &llvm_objdump_path,
        manifest_value(&build_tools_identity, "llvm_objdump_sha256"),
        "llvm-objdump",
    );
    let llvm_readelf = VerifiedExecutable::open(
        &llvm_readelf_path,
        manifest_value(&build_tools_identity, "llvm_readelf_sha256"),
        "llvm-readelf/readobj",
    );
    let build_tools = BuildTools {
        cargo: &cargo,
        rustc: &rustc,
        rust_lld: &rust_lld,
        clang: &clang,
        runtime_artifacts: &runtime_artifacts,
    };
    let output_root = ArtifactRoot::create();
    let build_environment = BuildEnvironment::create(output_root.path());
    validate_f2_kernel_context_object(
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &workspace,
        &output_root.path().join("f2-kernel-context.o"),
    );
    let build_environment_hash = normalized_build_environment_sha256(
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &llvm_readelf,
        &build_tools_identity,
    );
    let build_input_before = build_input_manifest_sha256(&workspace);
    validate_one_shot_ui(
        &workspace,
        &output_root.path().join("one-shot-ui"),
        &build_environment,
        build_tools,
    );

    let production = build_kernel(
        &workspace,
        &output_root.path().join("production"),
        &build_environment,
        build_tools,
        None,
    );
    validate_static_kernel_elf(&llvm_readelf, &production, "production");
    let production_symbols = symbols(&llvm_nm, &production);
    validate_kernel_stack_artifact_geometry(&production_symbols);
    let production_disassembly = disassembly(&llvm_objdump, &production);
    validate_entry_normalization(&production_disassembly);
    validate_fp_simd_unavailable(&production_disassembly);
    let production_stack_artifact = build_stack_kernel(
        &workspace,
        &output_root.path().join("production-stack-sizes"),
        &build_environment,
        build_tools,
        None,
    );
    let production_stack_disassembly = disassembly(&llvm_objdump, &production_stack_artifact);
    assert_eq!(
        text_disassembly(&production_stack_disassembly),
        text_disassembly(&production_disassembly),
        "production stack-size carrier changed the canonical production machine code"
    );
    validate_production_ist_stack_margin(
        &stack_sizes(&llvm_readelf, &production_stack_artifact),
        &production_stack_disassembly,
    );
    assert!(production_symbols.contains("activate_bootstrap_deep_paging"));
    for forbidden in [
        "test_support",
        "run_memory_foundation_test",
        "dw_test_unmapped_read",
        "dw_test_write_protected",
        "complete_known_outcome",
        "complete_pass",
        "complete_fail",
        "complete_panic",
        "EXPECTED_FAULT",
        "run_task_userspace_test",
        "__dw_test_e7_user_blob_start",
        "E7SmokeRuntime",
    ] {
        assert!(
            !production_symbols.contains(forbidden),
            "production artifact retained test-only symbol {forbidden}"
        );
    }
    let production_bytes = fs::read(&production).expect("read production kernel artifact");
    for forbidden in SELECTORS.into_iter().chain(E7_SELECTORS).chain([
        "DWTEST1",
        "dw_test_",
        "EXPECTED_FAULT",
        "complete_known_outcome",
        "QEMU_DEBUG_EXIT_PORT",
        "isa-debug-exit",
    ]) {
        assert!(
            !contains_bytes(&production_bytes, forbidden.as_bytes()),
            "production artifact retained test marker {forbidden}"
        );
    }
    for forbidden in ["mov\tdx, 0xf4", "out\tdx, eax"] {
        assert!(
            !production_disassembly.contains(forbidden),
            "production artifact retained debug-exit instruction evidence: {forbidden}"
        );
    }

    let mut hashes = BTreeSet::new();
    let production_hash = sha256(&production);
    eprintln!("production {production_hash}");
    hashes.insert(production_hash);
    for selector in SELECTORS {
        let artifact = build_kernel(
            &workspace,
            &output_root.path().join(selector),
            &build_environment,
            build_tools,
            Some(selector),
        );
        let selector_symbols = symbols(&llvm_nm, &artifact);
        let selector_disassembly = disassembly(&llvm_objdump, &artifact);
        for required in [
            "activate_bootstrap_deep_paging",
            "run_memory_foundation_test",
            "dw_test_unmapped_read_site",
            "dw_test_write_protected_site",
        ] {
            assert!(
                selector_symbols.contains(required),
                "{selector} artifact omitted {required}"
            );
        }
        let artifact_hash = sha256(&artifact);
        eprintln!("{selector} {artifact_hash}");
        assert!(
            hashes.insert(artifact_hash),
            "{selector} artifact is byte-identical to another build identity"
        );

        let stack_artifact = build_stack_kernel(
            &workspace,
            &output_root.path().join(format!("{selector}-stack-sizes")),
            &build_environment,
            build_tools,
            Some(selector),
        );
        let stack_disassembly = disassembly(&llvm_objdump, &stack_artifact);
        assert_eq!(
            text_disassembly(&stack_disassembly),
            text_disassembly(&selector_disassembly),
            "{selector} stack-size carrier changed the plain selector machine code"
        );
        validate_selector_stack_margin(
            selector,
            &stack_sizes(&llvm_readelf, &stack_artifact),
            &stack_disassembly,
        );
    }
    let build_input_after = build_input_manifest_sha256(&workspace);
    assert_eq!(
        build_input_after, build_input_before,
        "build-relevant source/configuration changed during the isolated builds"
    );
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        AcceptedToolPaths {
            cargo: cargo.source_path(),
            rustc: rustc.source_path(),
            rust_lld: rust_lld.source_path(),
            clang: clang.source_path(),
            llvm_nm: llvm_nm.source_path(),
            llvm_objdump: llvm_objdump.source_path(),
            llvm_readelf: llvm_readelf.source_path(),
        },
    );
    let build_environment_after = normalized_build_environment_sha256(
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &llvm_readelf,
        &build_tools_identity,
    );
    assert_eq!(
        build_environment_after, build_environment_hash,
        "accepted build/inspection tools changed during the isolated builds"
    );
    reject_ambient_build_overrides(&workspace);
    eprintln!("build-input-manifest {build_input_before}");
    eprintln!("normalized-build-environment {build_environment_hash}");
    output_root.cleanup();
}

#[test]
#[ignore = "explicit accepted-toolchain DW0-E7 target-artifact gate"]
fn e7_task_smoke_artifact_is_freestanding_and_separated() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kernel manifest has workspace parent")
        .to_path_buf();
    reject_ambient_build_overrides(&workspace);
    let cargo_path = required_path("DEEPWYRM_ACCEPTED_CARGO");
    let rustc_path = required_path("DEEPWYRM_ACCEPTED_RUSTC");
    let rust_lld_path = required_path("DEEPWYRM_ACCEPTED_RUST_LLD");
    let clang_path = required_path("DEEPWYRM_CLANG");
    let llvm_nm_path = required_path("DEEPWYRM_LLVM_NM");
    let llvm_objdump_path = required_path("DEEPWYRM_LLVM_OBJDUMP");
    let llvm_readelf_path = required_path("DEEPWYRM_LLVM_READELF");
    let toolchain_identity = fs::read_to_string(workspace.join("tooling/rust-toolchain.toml"))
        .expect("read trusted toolchain identity");
    let build_tools_identity = fs::read_to_string(workspace.join("tooling/build-tools.toml"))
        .expect("read trusted build-tools identity");
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        AcceptedToolPaths {
            cargo: &cargo_path,
            rustc: &rustc_path,
            rust_lld: &rust_lld_path,
            clang: &clang_path,
            llvm_nm: &llvm_nm_path,
            llvm_objdump: &llvm_objdump_path,
            llvm_readelf: &llvm_readelf_path,
        },
    );
    let runtime_artifacts = accepted_runtime_artifacts(&toolchain_identity, &cargo_path);
    let cargo = VerifiedExecutable::open(
        &cargo_path,
        manifest_value(&toolchain_identity, "cargo_sha256"),
        "cargo",
    );
    let rustc = VerifiedExecutable::open(
        &rustc_path,
        manifest_value(&toolchain_identity, "rustc_sha256"),
        "rustc",
    );
    let rust_lld = VerifiedExecutable::open(
        &rust_lld_path,
        manifest_value(&toolchain_identity, "rust_lld_sha256"),
        "rust-lld",
    );
    let clang = VerifiedExecutable::open(
        &clang_path,
        manifest_value(&build_tools_identity, "clang_sha256"),
        "clang",
    );
    let llvm_nm = VerifiedExecutable::open(
        &llvm_nm_path,
        manifest_value(&build_tools_identity, "llvm_nm_sha256"),
        "llvm-nm",
    );
    let llvm_objdump = VerifiedExecutable::open(
        &llvm_objdump_path,
        manifest_value(&build_tools_identity, "llvm_objdump_sha256"),
        "llvm-objdump",
    );
    let llvm_readelf = VerifiedExecutable::open(
        &llvm_readelf_path,
        manifest_value(&build_tools_identity, "llvm_readelf_sha256"),
        "llvm-readelf/readobj",
    );
    let tools = BuildTools {
        cargo: &cargo,
        rustc: &rustc,
        rust_lld: &rust_lld,
        clang: &clang,
        runtime_artifacts: &runtime_artifacts,
    };
    let output_root = ArtifactRoot::create();
    let environment = BuildEnvironment::create(output_root.path());
    validate_f2_kernel_context_object(
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &workspace,
        &output_root.path().join("f2-kernel-context.o"),
    );
    let build_input_before = build_input_manifest_sha256(&workspace);

    let production_target = output_root.path().join("e7-production");
    let production = build_kernel(&workspace, &production_target, &environment, tools, None);
    validate_static_kernel_elf(&llvm_readelf, &production, "E7 production");
    let production_symbols = symbols(&llvm_nm, &production);
    for forbidden in [
        "run_task_userspace_test",
        "__dw_test_e7_user_blob_start",
        "__dw_test_e7_user_blob_end",
        "E7SmokeRuntime",
        "task-syscall-smoke",
        "run_atomic_wait_userspace_test",
        "__dw_test_f9_user_blob_start",
        "__dw_test_f9_user_blob_end",
        "F9Runtime",
        "atomic-wait-wake",
    ] {
        assert!(
            !production_symbols.contains(forbidden),
            "production kernel retained E7 symbol {forbidden}"
        );
    }

    let smoke_target = output_root.path().join("task-syscall-smoke");
    let smoke = build_kernel(
        &workspace,
        &smoke_target,
        &environment,
        tools,
        Some("task-syscall-smoke"),
    );
    let smoke_symbols = symbols(&llvm_nm, &smoke);
    for required in [
        "run_task_userspace_test",
        "__dw_test_e7_user_blob_start",
        "__dw_test_e7_user_blob_end",
        "dw_x86_64_syscall_entry",
        "dw_x86_64_iret_to_user",
    ] {
        assert!(
            smoke_symbols.contains(required),
            "task-syscall-smoke kernel omitted {required}"
        );
    }
    let smoke_disassembly = disassembly(&llvm_objdump, &smoke);
    validate_fp_simd_unavailable(&smoke_disassembly);
    assert_ne!(sha256(&production), sha256(&smoke));

    let user = find_e7_user_artifact(&smoke_target);
    validate_static_native_user_elf(&llvm_nm, &llvm_objdump, &llvm_readelf, &user, "E7");
    eprintln!("task-syscall-smoke user {}", sha256(&user));

    let f9_target = output_root.path().join("atomic-wait-wake");
    let f9 = build_kernel(
        &workspace,
        &f9_target,
        &environment,
        tools,
        Some("atomic-wait-wake"),
    );
    let f9_symbols = symbols(&llvm_nm, &f9);
    for required in [
        "run_atomic_wait_userspace_test",
        "__dw_test_f9_user_blob_start",
        "__dw_test_f9_user_blob_end",
        "F9Runtime",
        "begin_atomic_wait",
        "claim_wake",
        "dw_x86_64_syscall_entry",
        "dw_x86_64_iret_to_user",
    ] {
        assert!(
            f9_symbols.contains(required),
            "atomic-wait-wake kernel omitted {required}"
        );
    }
    let f9_disassembly = disassembly(&llvm_objdump, &f9);
    validate_fp_simd_unavailable(&f9_disassembly);
    assert_ne!(sha256(&production), sha256(&f9));

    let f9_user = find_f9_user_artifact(&f9_target);
    validate_static_native_user_elf(&llvm_nm, &llvm_objdump, &llvm_readelf, &f9_user, "F9");
    eprintln!("atomic-wait-wake user {}", sha256(&f9_user));
    eprintln!("atomic-wait-wake kernel {}", sha256(&f9));

    let smoke_stack = build_stack_kernel(
        &workspace,
        &output_root.path().join("task-syscall-smoke-stack"),
        &environment,
        tools,
        Some("task-syscall-smoke"),
    );
    let smoke_stack_disassembly = disassembly(&llvm_objdump, &smoke_stack);
    assert_eq!(
        text_disassembly(&smoke_stack_disassembly),
        text_disassembly(&smoke_disassembly),
        "E7 stack-size carrier changed task-syscall-smoke machine code"
    );
    validate_e7_stack_margin(&stack_sizes(&llvm_readelf, &smoke_stack));

    let build_input_after = build_input_manifest_sha256(&workspace);
    assert_eq!(
        build_input_after, build_input_before,
        "build-relevant source/configuration changed during E7 artifact builds"
    );
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        AcceptedToolPaths {
            cargo: cargo.source_path(),
            rustc: rustc.source_path(),
            rust_lld: rust_lld.source_path(),
            clang: clang.source_path(),
            llvm_nm: llvm_nm.source_path(),
            llvm_objdump: llvm_objdump.source_path(),
            llvm_readelf: llvm_readelf.source_path(),
        },
    );
    let build_environment_hash = normalized_build_environment_sha256(
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &llvm_readelf,
        &build_tools_identity,
    );
    eprintln!("task-syscall-smoke kernel {}", sha256(&smoke));
    eprintln!("E7 build-input-manifest {build_input_before}");
    eprintln!("E7 normalized-build-environment {build_environment_hash}");
    reject_ambient_build_overrides(&workspace);
    output_root.cleanup();
}

#[test]
#[ignore = "explicit accepted-toolchain DW0-F12 target-artifact gate"]
fn implemented_f_selector_artifacts_are_freestanding_and_separated() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kernel manifest has workspace parent")
        .to_path_buf();
    reject_ambient_build_overrides(&workspace);
    let cargo_path = required_path("DEEPWYRM_ACCEPTED_CARGO");
    let rustc_path = required_path("DEEPWYRM_ACCEPTED_RUSTC");
    let rust_lld_path = required_path("DEEPWYRM_ACCEPTED_RUST_LLD");
    let clang_path = required_path("DEEPWYRM_CLANG");
    let llvm_nm_path = required_path("DEEPWYRM_LLVM_NM");
    let llvm_objdump_path = required_path("DEEPWYRM_LLVM_OBJDUMP");
    let llvm_readelf_path = required_path("DEEPWYRM_LLVM_READELF");
    let toolchain_identity = fs::read_to_string(workspace.join("tooling/rust-toolchain.toml"))
        .expect("read trusted toolchain identity");
    let build_tools_identity = fs::read_to_string(workspace.join("tooling/build-tools.toml"))
        .expect("read trusted build-tools identity");
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        AcceptedToolPaths {
            cargo: &cargo_path,
            rustc: &rustc_path,
            rust_lld: &rust_lld_path,
            clang: &clang_path,
            llvm_nm: &llvm_nm_path,
            llvm_objdump: &llvm_objdump_path,
            llvm_readelf: &llvm_readelf_path,
        },
    );
    let runtime_artifacts = accepted_runtime_artifacts(&toolchain_identity, &cargo_path);
    let cargo = VerifiedExecutable::open(
        &cargo_path,
        manifest_value(&toolchain_identity, "cargo_sha256"),
        "cargo",
    );
    let rustc = VerifiedExecutable::open(
        &rustc_path,
        manifest_value(&toolchain_identity, "rustc_sha256"),
        "rustc",
    );
    let rust_lld = VerifiedExecutable::open(
        &rust_lld_path,
        manifest_value(&toolchain_identity, "rust_lld_sha256"),
        "rust-lld",
    );
    let clang = VerifiedExecutable::open(
        &clang_path,
        manifest_value(&build_tools_identity, "clang_sha256"),
        "clang",
    );
    let llvm_nm = VerifiedExecutable::open(
        &llvm_nm_path,
        manifest_value(&build_tools_identity, "llvm_nm_sha256"),
        "llvm-nm",
    );
    let llvm_objdump = VerifiedExecutable::open(
        &llvm_objdump_path,
        manifest_value(&build_tools_identity, "llvm_objdump_sha256"),
        "llvm-objdump",
    );
    let llvm_readelf = VerifiedExecutable::open(
        &llvm_readelf_path,
        manifest_value(&build_tools_identity, "llvm_readelf_sha256"),
        "llvm-readelf/readobj",
    );
    let tools = BuildTools {
        cargo: &cargo,
        rustc: &rustc,
        rust_lld: &rust_lld,
        clang: &clang,
        runtime_artifacts: &runtime_artifacts,
    };
    let output_root = ArtifactRoot::create();
    let environment = BuildEnvironment::create(output_root.path());
    validate_f2_kernel_context_object(
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &workspace,
        &output_root.path().join("f2-kernel-context.o"),
    );
    let build_environment_hash = normalized_build_environment_sha256(
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &llvm_readelf,
        &build_tools_identity,
    );
    let build_input_before = build_input_manifest_sha256(&workspace);

    let production_target = output_root.path().join("production");
    let production = build_kernel(&workspace, &production_target, &environment, tools, None);
    validate_static_kernel_elf(&llvm_readelf, &production, "F12 production");
    let production_symbols = symbols(&llvm_nm, &production);
    validate_kernel_stack_artifact_geometry(&production_symbols);
    let production_disassembly = disassembly(&llvm_objdump, &production);
    validate_entry_normalization(&production_disassembly);
    validate_fp_simd_unavailable(&production_disassembly);
    for forbidden in [
        "test_support",
        "run_memory_foundation_test",
        "run_task_userspace_test",
        "run_atomic_wait_userspace_test",
        "run_ipc_blocking_userspace_test",
        "__dw_test_e7_user_blob_start",
        "__dw_test_e7_user_blob_end",
        "__dw_test_f9_user_blob_start",
        "__dw_test_f9_user_blob_end",
        "__dw_test_f12_user_blob_start",
        "__dw_test_f12_user_blob_end",
        "E7SmokeRuntime",
        "F9Runtime",
        "F12Runtime",
        "IpcBlockingSmoke",
    ] {
        assert!(
            !production_symbols.contains(forbidden),
            "production kernel retained test-only symbol {forbidden}"
        );
    }
    let production_bytes = fs::read(&production).expect("read production kernel artifact");
    for forbidden in SELECTORS.into_iter().chain(E7_SELECTORS).chain([
        "ipc-blocking-smoke",
        "atomic-wait-wake",
        "DWTEST1",
        "dw_test_",
        "test_support",
        "EXPECTED_FAULT",
        "complete_known_outcome",
        "QEMU_DEBUG_EXIT_PORT",
        "isa-debug-exit",
        "F9Runtime",
        "F12Runtime",
    ]) {
        assert!(
            !contains_bytes(&production_bytes, forbidden.as_bytes()),
            "production kernel retained test marker {forbidden}"
        );
    }
    for forbidden in ["mov\tdx, 0xf4", "out\tdx, eax"] {
        assert!(
            !production_disassembly.contains(forbidden),
            "production kernel retained debug-exit instruction evidence: {forbidden}"
        );
    }
    let production_stack = build_stack_kernel(
        &workspace,
        &output_root.path().join("production-stack-sizes"),
        &environment,
        tools,
        None,
    );
    let production_stack_disassembly = disassembly(&llvm_objdump, &production_stack);
    assert_eq!(
        text_disassembly(&production_stack_disassembly),
        text_disassembly(&production_disassembly),
        "F12 production stack-size carrier changed the canonical production machine code"
    );
    validate_production_ist_stack_margin(
        &stack_sizes(&llvm_readelf, &production_stack),
        &production_stack_disassembly,
    );

    let mut kernel_hashes = BTreeSet::new();
    let production_hash = sha256(&production);
    eprintln!("F12 production kernel {production_hash}");
    kernel_hashes.insert(production_hash);
    let mut user_hashes = BTreeSet::new();
    for (selector, user_artifact, required_symbols, label) in [
        (
            "ipc-blocking-smoke",
            find_f12_user_artifact as fn(&Path) -> PathBuf,
            &[
                "run_ipc_blocking_userspace_test",
                "__dw_test_f12_user_blob_start",
                "__dw_test_f12_user_blob_end",
                "F12Runtime",
                "dw_x86_64_syscall_entry",
                "dw_x86_64_iret_to_user",
            ][..],
            "F12",
        ),
        (
            "atomic-wait-wake",
            find_f9_user_artifact as fn(&Path) -> PathBuf,
            &[
                "run_atomic_wait_userspace_test",
                "__dw_test_f9_user_blob_start",
                "__dw_test_f9_user_blob_end",
                "F9Runtime",
                "begin_atomic_wait",
                "claim_wake",
                "dw_x86_64_syscall_entry",
                "dw_x86_64_iret_to_user",
            ][..],
            "F9",
        ),
    ] {
        let target = output_root.path().join(selector);
        let kernel = build_kernel(&workspace, &target, &environment, tools, Some(selector));
        validate_static_kernel_elf(&llvm_readelf, &kernel, label);
        let kernel_symbols = symbols(&llvm_nm, &kernel);
        for required in required_symbols {
            assert!(
                kernel_symbols.contains(required),
                "{selector} kernel omitted {required}"
            );
        }
        let cross_selector_markers: &[&str] = match selector {
            "ipc-blocking-smoke" => &[
                "run_atomic_wait_userspace_test",
                "__dw_test_f9_user_blob_start",
                "__dw_test_f9_user_blob_end",
                "F9Runtime",
            ],
            "atomic-wait-wake" => &[
                "run_ipc_blocking_userspace_test",
                "__dw_test_f12_user_blob_start",
                "__dw_test_f12_user_blob_end",
                "F12Runtime",
            ],
            _ => unreachable!("implemented F selector list is closed"),
        };
        for forbidden in cross_selector_markers {
            assert!(
                !kernel_symbols.contains(forbidden),
                "{selector} kernel retained cross-selector marker {forbidden}"
            );
        }
        let kernel_bytes = fs::read(&kernel).expect("read F-selector kernel artifact");
        for forbidden in cross_selector_markers {
            assert!(
                !contains_bytes(&kernel_bytes, forbidden.as_bytes()),
                "{selector} kernel retained cross-selector payload marker {forbidden}"
            );
        }
        let kernel_disassembly = disassembly(&llvm_objdump, &kernel);
        validate_fp_simd_unavailable(&kernel_disassembly);
        let kernel_hash = sha256(&kernel);
        assert!(
            kernel_hashes.insert(kernel_hash.clone()),
            "{selector} kernel is byte-identical to production or another implemented F selector"
        );
        eprintln!("{selector} kernel {kernel_hash}");

        let user = user_artifact(&target);
        validate_static_native_user_elf(&llvm_nm, &llvm_objdump, &llvm_readelf, &user, label);
        validate_user_stack_consumption(&llvm_objdump, &user, label, 2048);
        let user_hash = sha256(&user);
        assert!(
            user_hashes.insert(user_hash.clone()),
            "{selector} userspace ELF is byte-identical to another implemented F selector"
        );
        eprintln!("{selector} user {user_hash}");

        let stack_kernel = build_stack_kernel(
            &workspace,
            &output_root.path().join(format!("{selector}-stack-sizes")),
            &environment,
            tools,
            Some(selector),
        );
        let stack_disassembly = disassembly(&llvm_objdump, &stack_kernel);
        assert_eq!(
            text_disassembly(&stack_disassembly),
            text_disassembly(&kernel_disassembly),
            "{selector} stack-size carrier changed the selector machine code"
        );
        let stack_sizes = stack_sizes(&llvm_readelf, &stack_kernel);
        let resolved_stack_disassembly =
            resolved_read_only_indirect_disassembly(&llvm_objdump, &llvm_nm, &stack_kernel);
        if selector == "ipc-blocking-smoke" {
            validate_f12_stack_context_evidence(
                &stack_sizes,
                &kernel_symbols,
                &resolved_stack_disassembly,
            );
        } else {
            validate_f9_stack_context_evidence(
                &stack_sizes,
                &kernel_symbols,
                &resolved_stack_disassembly,
            );
        }
    }

    let build_input_after = build_input_manifest_sha256(&workspace);
    assert_eq!(
        build_input_after, build_input_before,
        "build-relevant source/configuration changed during F12 artifact builds"
    );
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        AcceptedToolPaths {
            cargo: cargo.source_path(),
            rustc: rustc.source_path(),
            rust_lld: rust_lld.source_path(),
            clang: clang.source_path(),
            llvm_nm: llvm_nm.source_path(),
            llvm_objdump: llvm_objdump.source_path(),
            llvm_readelf: llvm_readelf.source_path(),
        },
    );
    let build_environment_after = normalized_build_environment_sha256(
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &llvm_readelf,
        &build_tools_identity,
    );
    assert_eq!(
        build_environment_after, build_environment_hash,
        "accepted build/inspection tools changed during F12 artifact builds"
    );
    reject_ambient_build_overrides(&workspace);
    eprintln!("F12 build-input-manifest {build_input_before}");
    eprintln!("F12 normalized-build-environment {build_environment_hash}");
    output_root.cleanup();
}
