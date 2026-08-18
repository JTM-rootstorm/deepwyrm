use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).into()).collect()
}
fn request(kind: &str, selector: &str) -> String {
    format!(
        "schema_version = 1\nproducer = \"wyrmroot\"\nkind = \"{kind}\"\nprofile = \"default\"\nselector = \"{selector}\"\ntest_id = 1\ntimeout_seconds = 120\nserial_log = \"artifacts/dw0-b/serial.log\"\nresult_json = \"artifacts/dw0-b/result.json\"\nno_host_share = true\ndeepwyrm_revision = \"{}\"\ndeepwyrm_dirty = false\nwyrmroot_revision = \"{}\"\nwyrmroot_dirty = true\nesp_image = \"images/wyrmroot-esp.img\"\nesp_sha256 = \"{}\"\nsystem_disk = \"images/wyrmroot-system.qcow2\"\nsystem_disk_sha256 = \"{}\"\novmf_code = \"firmware/OVMF_CODE.fd\"\novmf_code_sha256 = \"{}\"\novmf_vars = \"firmware/OVMF_VARS.fd\"\novmf_vars_sha256 = \"{}\"\ndeepwyrm_elf = \"artifacts/deepwyrm.elf\"\ndeepwyrm_elf_sha256 = \"{}\"\ndeepwyrm_symbols = \"artifacts/deepwyrm.debug\"\ndeepwyrm_symbols_sha256 = \"{}\"\nkernel_layout_sha256 = \"{}\"\nrust_toolchain_commit = \"{}\"\ntoolchain_config_sha256 = \"{}\"\ntoolchain_root_manifest_sha256 = \"{}\"\ntoolchain_cargo = \"/toolchain/bin/cargo\"\ntoolchain_cargo_sha256 = \"{}\"\ntoolchain_rustc = \"/toolchain/bin/rustc\"\ntoolchain_rustc_sha256 = \"{}\"\ntoolchain_rust_lld = \"/toolchain/bin/rust-lld\"\ntoolchain_rust_lld_sha256 = \"{}\"\ntoolchain_sysroot_manifest = \"/toolchain/sysroot-manifest\"\ntoolchain_sysroot_manifest_sha256 = \"{}\"\n",
        "a".repeat(40),
        "b".repeat(40),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64),
        "8".repeat(40),
        "4".repeat(64),
        "9".repeat(64),
        "5".repeat(64),
        "6".repeat(64),
        "7".repeat(64),
        "8".repeat(64)
    )
}
fn temp_file(contents: &str) -> PathBuf {
    let path = temp_path("toml");
    fs::write(&path, contents).unwrap();
    path
}

fn temp_path(extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "deepwyrm-xtask-{}-{}.{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
        extension
    ))
}

fn fake_sentinel_executable(sentinel: &Path) -> PathBuf {
    let path = temp_path("sh");
    fs::write(&path, format!("#!/bin/sh\ntouch {}\n", sentinel.display())).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[test]
fn available_commands_have_explicit_actions() {
    for (args, expected) in [
        (&["format"][..], Action::Command(Invocation::Format)),
        (&["check"][..], Action::Command(Invocation::Check)),
        (&["abi", "check"][..], Action::Command(Invocation::AbiCheck)),
        (
            &["test", "host", "abi"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Abi))),
        ),
        (
            &["test", "host", "memory"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Memory))),
        ),
        (
            &["test", "host", "handles"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Handles))),
        ),
        (
            &["test", "host", "tasks"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Tasks))),
        ),
        (
            &["run", "--plan", "--request", "request.toml"][..],
            Action::Command(Invocation::HarnessPlan(
                HarnessKind::Run,
                "request.toml".into(),
                None,
            )),
        ),
        (
            &["gdb", "--plan", "--request", "request.toml"][..],
            Action::Command(Invocation::HarnessPlan(
                HarnessKind::Gdb,
                "request.toml".into(),
                None,
            )),
        ),
        (
            &[
                "test",
                "guest",
                "arch.entry",
                "--plan",
                "--request",
                "request.toml",
            ][..],
            Action::Command(Invocation::HarnessPlan(
                HarnessKind::GuestTest,
                "request.toml".into(),
                Some("arch.entry".into()),
            )),
        ),
        (
            &[
                "toolchain",
                "verify-build-tools",
                "--root",
                "/opt/llvm-22",
                "--clang-config",
                "/etc/clang.cfg",
            ][..],
            Action::VerifyBuildTools {
                root: "/opt/llvm-22".into(),
                clang_config: "/etc/clang.cfg".into(),
            },
        ),
    ] {
        assert_eq!(parse(&strings(args)), expected);
    }
}

#[test]
fn handle_host_gate_covers_lifetime_and_authority_boundaries() {
    assert!(HANDLE_HOST_TEST_FILTERS.contains(&"memory::vm::object::tests::"));
    assert_eq!(
        HANDLE_HOST_INTEGRATION_TESTS,
        &[
            "object_registry_ui",
            "memory_authority_ui",
            "physical_ownership_ui"
        ]
    );
}

#[test]
fn task_host_gate_covers_scheduler_resources_and_target_guard_contracts() {
    for filter in [
        "sync::tests::",
        "task::tests::",
        "task::scheduler::tests::",
        "task::execution::tests::",
        "arch::x86_64::syscall::tests::",
        "arch::x86_64::exceptions::tests::",
        "object::finalizer::tests::",
        "root_region_handle_close_preserves_address_space_until_process_exit",
    ] {
        assert!(TASK_HOST_TEST_FILTERS.contains(&filter));
    }
    assert_eq!(
        TASK_HOST_INTEGRATION_TESTS,
        &[
            "task_authority_ui",
            "x86_64_activation_contract",
            "x86_64_entry_contract",
            "x86_64_syscall_contract",
            "x86_64_exception_contract",
            "x86_64_memory_guest_contract",
        ]
    );
}

#[test]
fn harness_request_requires_paired_identity_and_no_host_share() {
    let path = temp_file(&request("guest-test", "arch.entry"));
    let parsed = load_harness_request(&path).unwrap();
    validate_request(HarnessKind::GuestTest, &parsed, None).unwrap();
    fs::remove_file(path).unwrap();

    let invalid = request("guest-test", "arch.entry")
        .replace("no_host_share = true", "no_host_share = false");
    let path = temp_file(&invalid);
    let parsed = load_harness_request(&path).unwrap();
    assert!(validate_request(HarnessKind::GuestTest, &parsed, None).is_err());
    fs::remove_file(path).unwrap();

    let run = request("run", "").replace("test_id = 1", "test_id = 0");
    let path = temp_file(&run);
    let parsed = load_harness_request(&path).unwrap();
    validate_request(HarnessKind::Run, &parsed, None).unwrap();
    fs::remove_file(path).unwrap();
}

#[test]
fn qemu_plan_uses_real_media_and_test_only_selector_channel() {
    let request = load_harness_request(&temp_file(&request("guest-test", "arch.entry"))).unwrap();
    let profiles = load_profiles(&workspace_root().join(HARNESS_CONFIG)).unwrap();
    let profile = profiles.get("default").unwrap();
    let args = qemu_arguments(profile, &request, HarnessKind::GuestTest).join(" ");
    assert!(args.contains("if=virtio,format=raw,readonly=on,file=images/wyrmroot-esp.img"));
    assert!(args.contains("file:artifacts/dw0-b/serial.log"));
    assert!(args.contains("opt/org.deepwyrm.test.selector,string=arch.entry"));
    assert!(args.contains("isa-debug-exit,iobase=0xf4,iosize=0x04"));
    assert!(!args.contains("virtfs"));
    let run_args = qemu_arguments(profile, &request, HarnessKind::Run).join(" ");
    let gdb_args = qemu_arguments(profile, &request, HarnessKind::Gdb).join(" ");
    assert!(!run_args.contains("isa-debug-exit"));
    assert!(!gdb_args.contains("isa-debug-exit"));
    assert!(gdb_args.contains("tcp:127.0.0.1:1234"));
    assert!(!gdb_args.contains("tcp::"));
    let gdb_client = gdb_arguments(profile, &request).join(" ");
    assert!(gdb_client.contains("target remote 127.0.0.1:1234"));
}

#[test]
fn centralized_harness_config_loads_profiles_and_guest_test_metadata() {
    let config = workspace_root().join(HARNESS_CONFIG);
    let profiles = load_profiles(&config).unwrap();
    assert_eq!(profiles.get("default").unwrap().machine, "q35");
    assert_eq!(profiles.get("smp").unwrap().vcpu, 4);
    let parsed =
        load_harness_request(&temp_file(&request("guest-test", "boot-handoff-pass"))).unwrap();
    validate_guest_selector_metadata(&config, &parsed).unwrap();

    let invalid = temp_file(
        "schema_version = 1\n[profile.default]\nmachine = \"q35\"\nvcpu = 1\nmemory_mib = 1\ntimeout_seconds = 1\ngdb_port = 1234\n[guest_test.one]\nid = 1\nunexpected = 2\n",
    );
    assert!(load_profiles(&invalid).is_err());
    fs::remove_file(invalid).unwrap();
}

#[test]
fn dw0c_memory_selectors_have_stable_build_owned_ids() {
    let config = workspace_root().join(HARNESS_CONFIG);
    for (selector, test_id) in [
        ("memory-mapping", 4),
        ("memory-unmapping", 5),
        ("memory-permissions", 6),
        ("memory-invalid-pointer", 7),
        ("memory-user-kernel-isolation", 8),
        ("memory-shared-memory-object", 9),
    ] {
        let path = temp_file(
            &request("guest-test", selector)
                .replace("test_id = 1", &format!("test_id = {test_id}")),
        );
        let parsed = load_harness_request(&path).unwrap();
        validate_guest_selector_metadata(&config, &parsed).unwrap();
        assert_eq!(
            guest_build_selection(HarnessKind::GuestTest, &parsed),
            Some(GuestBuildSelection {
                selector: selector.into(),
                expected_test_id: test_id,
            })
        );
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn build_tools_identity_is_host_neutral_and_fixed() {
    let identity = load_build_tools_identity(&workspace_root().join(BUILD_TOOLS_CONFIG)).unwrap();
    assert_eq!(identity.clang_version, "22.1.8");
    assert_eq!(identity.clang_binary, "bin/clang-22");
    assert_eq!(identity.libclang_cpp, "lib64/libclang-cpp.so.22.1");
    assert_eq!(identity.host_llvm, "lib64/libLLVM.so.22.1");
}

#[test]
fn trusted_toolchain_binds_tree_and_internal_library_identities() {
    let trusted = load_trusted_toolchain(&workspace_root().join(TRUSTED_TOOLCHAIN_CONFIG)).unwrap();
    assert_eq!(
        trusted.toolchain_tree_sha256,
        "5d4275428555a7cd6ae7decc100456fe31cfa4562a7f5eb81a3cf7fe08aa03a5"
    );
    assert!(
        trusted
            .rustc_driver_internal_library
            .path
            .ends_with("lib/librustc_driver-7cb6fba0afdc0262.so")
    );
    assert!(
        trusted
            .llvm_internal_library
            .path
            .ends_with("lib/libLLVM.so.22.1-rust-1.97.1-stable")
    );
}

#[test]
fn result_parser_accepts_one_terminal_record_and_rejects_ambiguity() {
    let pass = parse_guest_terminal_record(&terminal("01", 1, 0), 1).unwrap();
    assert_eq!(pass.status, GuestTerminalStatus::Pass);
    let mut lower_hex = terminal("01", 1, 0);
    lower_hex[11] = b'a';
    let mut bad_delimiter = terminal("01", 1, 0);
    bad_delimiter[10] = b':';
    let mut bad_checksum = terminal("01", 1, 0);
    bad_checksum[29] = b'0';
    for serial in [
        [terminal("03", 1, 0), terminal("01", 1, 0)].concat(),
        [terminal("01", 1, 0), terminal("01", 1, 0)].concat(),
        terminal("01", 2, 0),
        terminal("01", 1, 0)[..37].to_vec(),
        lower_hex,
        bad_delimiter,
        bad_checksum,
    ] {
        assert!(parse_guest_terminal_record(&serial, 1).is_err());
    }
    let with_embedded_diagnostic = [
        b"diagnostic DWTEST1|01|00000001|00000000|00000000\n".as_slice(),
        terminal("01", 1, 0).as_slice(),
    ]
    .concat();
    assert!(parse_guest_terminal_record(&with_embedded_diagnostic, 1).is_ok());
    let on_second_line = [b"diagnostic\n".as_slice(), terminal("01", 1, 0).as_slice()].concat();
    assert_eq!(
        parse_guest_terminal_record(&on_second_line, 1)
            .unwrap()
            .line,
        2
    );
}

#[test]
fn guest_result_requires_the_bound_serial_path_and_matching_qemu_exit() {
    let directory = temp_path("dir");
    fs::create_dir(&directory).unwrap();
    let request_path = directory.join("request.toml");
    fs::write(
        &request_path,
        request("guest-test", "boot-handoff-pass")
            .replace("artifacts/dw0-b/serial.log", "serial.log"),
    )
    .unwrap();
    let serial_path = directory.join("serial.log");
    fs::write(&serial_path, terminal("01", 1, 0)).unwrap();

    assert_eq!(
        parse_guest_result_file(&serial_path, &request_path, 33).unwrap(),
        0
    );
    assert_eq!(
        parse_guest_result_file(&serial_path, &request_path, 35).unwrap(),
        1
    );
    assert_eq!(
        parse_guest_result_file(&directory.join("other.log"), &request_path, 33).unwrap(),
        1
    );

    let escaped_root = temp_path("escaped");
    fs::create_dir(&escaped_root).unwrap();
    let escaped_parent = escaped_root.join("dw0-b");
    fs::create_dir(&escaped_parent).unwrap();
    let escaped_serial = escaped_parent.join("serial.log");
    fs::write(&escaped_serial, terminal("01", 1, 0)).unwrap();
    let escape_request = directory.join("escape-request.toml");
    fs::write(&escape_request, request("guest-test", "boot-handoff-pass")).unwrap();
    let intermediate_link = directory.join("artifacts");
    symlink(&escaped_root, &intermediate_link).unwrap();
    assert_eq!(
        parse_guest_result_file(
            &directory.join("artifacts/dw0-b/serial.log"),
            &escape_request,
            33,
        )
        .unwrap(),
        1
    );

    fs::remove_file(serial_path).unwrap();
    fs::remove_file(request_path).unwrap();
    fs::remove_file(escape_request).unwrap();
    fs::remove_file(intermediate_link).unwrap();
    fs::remove_file(escaped_serial).unwrap();
    fs::remove_dir(escaped_parent).unwrap();
    fs::remove_dir(escaped_root).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn hostile_reads_are_bounded() {
    let oversized = temp_path("bin");
    fs::write(&oversized, vec![b'x'; MAX_REQUEST_BYTES + 1]).unwrap();
    assert!(read_bounded(&oversized, "request", MAX_REQUEST_BYTES).is_err());
    fs::remove_file(oversized).unwrap();

    let growing = temp_file("small");
    assert!(fs::metadata(&growing).unwrap().len() <= MAX_REQUEST_BYTES as u64);
    fs::OpenOptions::new()
        .append(true)
        .open(&growing)
        .unwrap()
        .write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1])
        .unwrap();
    assert!(read_bounded(&growing, "request", MAX_REQUEST_BYTES).is_err());
    fs::remove_file(growing).unwrap();

    let target = temp_file("bounded");
    let link = temp_path("link");
    symlink(&target, &link).unwrap();
    assert!(read_bounded(&link, "request", MAX_REQUEST_BYTES).is_err());
    fs::remove_file(link).unwrap();
    fs::remove_file(target).unwrap();

    let directory = temp_path("dir");
    let outside = temp_path("outside");
    fs::create_dir(&directory).unwrap();
    fs::create_dir(&outside).unwrap();
    let outside_file = outside.join("component.txt");
    fs::write(&outside_file, "bounded").unwrap();
    let component_link = directory.join("linked-component");
    symlink(&outside, &component_link).unwrap();
    assert!(
        read_bounded(
            &component_link.join("component.txt"),
            "request",
            MAX_REQUEST_BYTES
        )
        .is_err()
    );
    fs::remove_file(component_link).unwrap();
    fs::remove_file(outside_file).unwrap();
    fs::remove_dir(outside).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn malformed_commands_are_usage_errors() {
    for args in [
        strings(&[]),
        strings(&["run"]),
        strings(&["gdb", "--plan"]),
        strings(&["test", "guest", "bad selector", "--plan", "--request", "x"]),
        strings(&["guest-result"]),
    ] {
        assert!(matches!(parse(&args), Action::UsageError(_)));
    }
}

#[test]
fn request_paths_and_json_are_safe_for_planned_command_consumers() {
    for path in [
        "images/a,b",
        "images/a=1",
        "images/a:b",
        "images/a b",
        "images/a\nb",
        "images/../a",
    ] {
        let contents = request("guest-test", "arch.entry").replace("images/wyrmroot-esp.img", path);
        let parsed = load_harness_request(&temp_file(&contents));
        assert!(parsed.is_err(), "unsafe path `{path}` was accepted");
    }
    let gdb_injection = request("guest-test", "arch.entry")
        .replace("artifacts/deepwyrm.debug", "artifacts/debug;quit");
    assert!(load_harness_request(&temp_file(&gdb_injection)).is_err());
    assert_eq!(
        json_string("quote\" slash\\ newline\ncontrol\u{0001}"),
        "quote\\\" slash\\\\ newline\\ncontrol\\u0001"
    );
}

#[test]
fn sha256_matches_a_standard_test_vector() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn request_selected_toolchain_path_is_rejected_without_execution() {
    let trusted = load_trusted_toolchain(&workspace_root().join(TRUSTED_TOOLCHAIN_CONFIG)).unwrap();
    let request_path = temp_file(&request("run", ""));
    let mut parsed = load_harness_request(&request_path).unwrap();
    let sentinel = temp_path("sentinel");
    let fake_rustc = fake_sentinel_executable(&sentinel);
    parsed.toolchain_rustc = fake_rustc.display().to_string();

    assert!(validate_request_toolchain_identity(&parsed, &trusted).is_err());
    assert!(
        !sentinel.exists(),
        "request-selected executable was invoked"
    );

    fs::remove_file(request_path).unwrap();
    fs::remove_file(fake_rustc).unwrap();
}

#[test]
fn sysroot_manifest_requires_the_v1_identity_contract() {
    let trusted = load_trusted_toolchain(&workspace_root().join(TRUSTED_TOOLCHAIN_CONFIG)).unwrap();
    let missing_schema = temp_file("rust_toolchain_commit = \"not-a-contract\"\n");
    let mut fixture = trusted.clone();
    let core_hash = "a".repeat(64);
    let builtins_hash = "b".repeat(64);
    fixture.freestanding_core = Some(TrustedArtifact {
        path: missing_schema.clone(),
        sha256: core_hash.clone(),
    });
    fixture.freestanding_compiler_builtins = Some(TrustedArtifact {
        path: missing_schema.clone(),
        sha256: builtins_hash.clone(),
    });
    fixture.sysroot_manifest_path = missing_schema.clone();
    assert!(
        validate_sysroot_manifest(&fixture, b"rust_toolchain_commit = \"not-a-contract\"\n")
            .is_err()
    );
    fs::remove_file(missing_schema).unwrap();

    let valid = temp_file(&format!(
        "schema = \"deepwyrm-rust-sysroot-manifest-v1\"\nrust_toolchain_commit = \"{}\"\ntarget = \"{}\"\ntoolchain_config_sha256 = \"{}\"\ncargo_sha256 = \"{}\"\nrustc_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\ncore_sha256 = \"{core_hash}\"\ncompiler_builtins_sha256 = \"{builtins_hash}\"\n",
        trusted.rust_commit,
        trusted.target,
        trusted.config_sha256,
        trusted.cargo_sha256,
        trusted.rustc_sha256,
        trusted.rust_lld_sha256,
    ));
    fixture.sysroot_manifest_path = valid.clone();
    let valid_bytes = read_bounded(&valid, "test sysroot", MAX_CONFIG_BYTES).unwrap();
    validate_sysroot_manifest(&fixture, &valid_bytes).unwrap();
    let contradictory = valid_bytes.to_vec();
    let contradictory = String::from_utf8(contradictory)
        .unwrap()
        .replace(&core_hash, &"c".repeat(64));
    assert!(validate_sysroot_manifest(&fixture, contradictory.as_bytes()).is_err());
    fs::remove_file(valid).unwrap();
}

#[test]
fn root_manifest_binds_and_hashes_freestanding_rlibs_without_build_commands() {
    let directory = temp_path("artifact-dir");
    fs::create_dir(&directory).unwrap();
    let core_path = directory.join("core.rlib");
    let builtins_path = directory.join("builtins.rlib");
    fs::write(&core_path, "core").unwrap();
    fs::write(&builtins_path, "builtins").unwrap();
    let core_hash = sha256_hex(b"core");
    let builtins_hash = sha256_hex(b"builtins");
    let manifest = format!(
        "[build]\ncommand = \"must-not-run\"\n[artifacts.freestanding_core]\npath = \"core.rlib\"\nsha256 = \"{core_hash}\"\n[artifacts.freestanding_compiler_builtins]\npath = \"builtins.rlib\"\nsha256 = \"{builtins_hash}\"\n"
    );
    let core = extract_root_manifest_artifact(&manifest, "artifacts.freestanding_core", &directory)
        .unwrap();
    let builtins = extract_root_manifest_artifact(
        &manifest,
        "artifacts.freestanding_compiler_builtins",
        &directory,
    )
    .unwrap();
    verify_trusted_artifact(&core.path, &core.sha256, "core", MAX_REQUEST_BYTES).unwrap();
    verify_trusted_artifact(
        &builtins.path,
        &builtins.sha256,
        "builtins",
        MAX_REQUEST_BYTES,
    )
    .unwrap();

    let mismatch = TrustedArtifact {
        path: core_path.clone(),
        sha256: "0".repeat(64),
    };
    assert!(
        verify_trusted_artifact(&mismatch.path, &mismatch.sha256, "core", MAX_REQUEST_BYTES)
            .is_err()
    );
    let link = directory.join("core-link.rlib");
    symlink(&core_path, &link).unwrap();
    assert!(verify_trusted_artifact(&link, &core_hash, "core", MAX_REQUEST_BYTES).is_err());

    fs::remove_file(link).unwrap();
    fs::remove_file(core_path).unwrap();
    fs::remove_file(builtins_path).unwrap();
    fs::remove_dir(directory).unwrap();
}

fn terminal(status: &str, test_id: u32, detail: u32) -> Vec<u8> {
    let mut record = format!("DWTEST1|{status}|{test_id:08X}|{detail:08X}|").into_bytes();
    record.extend_from_slice(format!("{:08X}\n", fnv1a32(&record)).as_bytes());
    record
}
