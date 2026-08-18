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
    let cargo = required_path("DEEPWYRM_ACCEPTED_CARGO");
    let rustc = required_path("DEEPWYRM_ACCEPTED_RUSTC");
    let rust_lld = required_path("DEEPWYRM_ACCEPTED_RUST_LLD");
    let clang = required_path("DEEPWYRM_CLANG");
    let llvm_nm = required_path("DEEPWYRM_LLVM_NM");
    let llvm_objdump = required_path("DEEPWYRM_LLVM_OBJDUMP");
    let llvm_readelf = required_path("DEEPWYRM_LLVM_READELF");
    let build_tools = BuildTools {
        cargo: &cargo,
        rustc: &rustc,
        rust_lld: &rust_lld,
        clang: &clang,
    };
    let toolchain_identity = fs::read_to_string(workspace.join("tooling/rust-toolchain.toml"))
        .expect("read trusted toolchain identity");
    let build_tools_identity = fs::read_to_string(workspace.join("tooling/build-tools.toml"))
        .expect("read trusted build-tools identity");
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
    );
    let output_root = ArtifactRoot::create();
    let build_environment = BuildEnvironment::create(output_root.path());
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
    let production_symbols = symbols(&llvm_nm, &production);
    validate_ist_artifact_geometry(&production_symbols);
    let production_disassembly = disassembly(&llvm_objdump, &production);
    validate_entry_normalization(&production_disassembly);
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
    ] {
        assert!(
            !production_symbols.contains(forbidden),
            "production artifact retained test-only symbol {forbidden}"
        );
    }
    let production_bytes = fs::read(&production).expect("read production kernel artifact");
    for forbidden in SELECTORS.into_iter().chain([
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
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
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
