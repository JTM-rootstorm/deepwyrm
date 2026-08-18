use super::*;

pub(super) fn emit_harness_plan(
    kind: HarnessKind,
    request_path: &Path,
    expected_selector: Option<&str>,
) -> io::Result<u8> {
    let config_path = workspace_root().join(HARNESS_CONFIG);
    let profiles = load_profiles(&config_path)?;
    let request = load_harness_request(request_path)?;
    validate_request(kind, &request, expected_selector)?;
    validate_guest_selector_metadata(&config_path, &request)?;
    validate_kernel_layout(
        &workspace_root().join("kernel/arch/x86_64/layout.toml"),
        &request.kernel_layout_sha256,
    )?;
    let trusted_toolchain = validate_toolchain_provenance(&request)?;
    let profile = profiles.get(&request.profile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "request names an unknown profile",
        )
    })?;
    if request.timeout_seconds != profile.timeout_seconds {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request timeout does not match the selected centralized profile",
        ));
    }

    let qemu_args = qemu_arguments(profile, &request, kind);
    let test_build = guest_build_selection(kind, &request);
    let mut stdout = io::stdout().lock();
    write!(
        stdout,
        "{{\"schema_version\":1,\"mode\":\"dry-run\",\"execution\":\"disabled\",\"kind\":\"{}\",\"profile\":\"{}\",\"timeout_seconds\":{},\"selector\":\"{}\",\"test_id\":{},\"serial_log\":\"{}\",\"result_json\":\"{}\",\"no_host_share\":true,\"artifact_identity\":{{\"deepwyrm_revision\":\"{}\",\"deepwyrm_dirty\":{},\"wyrmroot_revision\":\"{}\",\"wyrmroot_dirty\":{},\"esp_image\":\"{}\",\"esp_sha256\":\"{}\",\"system_disk\":\"{}\",\"system_disk_sha256\":\"{}\",\"ovmf_code\":\"{}\",\"ovmf_code_sha256\":\"{}\",\"ovmf_vars\":\"{}\",\"ovmf_vars_sha256\":\"{}\",\"deepwyrm_elf\":\"{}\",\"deepwyrm_elf_sha256\":\"{}\",\"deepwyrm_symbols\":\"{}\",\"deepwyrm_symbols_sha256\":\"{}\",\"kernel_layout\":\"kernel/arch/x86_64/layout.toml\",\"kernel_layout_sha256\":\"{}\"}},\"toolchain_identity\":{{\"request_id\":\"{}\",\"rust_commit\":\"{}\",\"target\":\"x86_64-unknown-none\",\"config_sha256\":\"{}\",\"root_manifest_sha256\":\"{}\",\"cargo_path\":\"{}\",\"cargo_sha256\":\"{}\",\"rustc_path\":\"{}\",\"rustc_sha256\":\"{}\",\"rust_lld_path\":\"{}\",\"rust_lld_sha256\":\"{}\",\"sysroot_manifest_path\":\"{}\",\"sysroot_manifest_sha256\":\"{}\"}},\"qemu\":{{\"program\":\"qemu-system-x86_64\",\"args\":{}}}",
        kind.request_kind(),
        json_string(&profile.name),
        request.timeout_seconds,
        json_string(&request.selector),
        request.test_id,
        json_string(&request.serial_log),
        json_string(&request.result_json),
        request.deepwyrm_revision,
        request.deepwyrm_dirty,
        request.wyrmroot_revision,
        request.wyrmroot_dirty,
        json_string(&request.esp_image),
        request.esp_sha256,
        json_string(&request.system_disk),
        request.system_disk_sha256,
        json_string(&request.ovmf_code),
        request.ovmf_code_sha256,
        json_string(&request.ovmf_vars),
        request.ovmf_vars_sha256,
        json_string(&request.deepwyrm_elf),
        request.deepwyrm_elf_sha256,
        json_string(&request.deepwyrm_symbols),
        request.deepwyrm_symbols_sha256,
        request.kernel_layout_sha256,
        trusted_toolchain.request_id,
        request.rust_toolchain_commit,
        request.toolchain_config_sha256,
        request.toolchain_root_manifest_sha256,
        json_string(&request.toolchain_cargo),
        request.toolchain_cargo_sha256,
        json_string(&request.toolchain_rustc),
        request.toolchain_rustc_sha256,
        json_string(&request.toolchain_rust_lld),
        request.toolchain_rust_lld_sha256,
        json_string(&request.toolchain_sysroot_manifest),
        request.toolchain_sysroot_manifest_sha256,
        json_array(&qemu_args),
    )?;
    if let Some(selection) = test_build {
        write!(
            stdout,
            ",\"test_build\":{{\"cargo_feature\":\"test-support\",\"environment\":{{\"DEEPWYRM_GUEST_TEST_SELECTOR\":\"{}\"}},\"expected_embedded_test_id\":{},\"id_source\":\"tooling/guest-harness.toml\"}}",
            json_string(&selection.selector),
            selection.expected_test_id,
        )?;
    }
    if kind == HarnessKind::Gdb {
        let gdb_args = gdb_arguments(profile, &request);
        write!(
            stdout,
            ",\"gdb\":{{\"program\":\"gdb\",\"args\":{}}}",
            json_array(&gdb_args)
        )?;
    }
    writeln!(
        stdout,
        ",\"result_contract\":{{\"serial_prefix\":\"DWTEST1|\",\"record_bytes\":38,\"terminal_statuses\":[\"PASS\",\"FAIL\",\"PANIC\"],\"host_outcomes\":[\"TIMEOUT\",\"INFRASTRUCTURE\"],\"debug_exit_status\":{{\"PASS\":33,\"FAIL\":35,\"PANIC\":37}},\"serial_exit_mismatch\":\"INFRASTRUCTURE\",\"exactly_one_terminal_record\":true}}}}"
    )?;
    Ok(0)
}

pub(super) fn guest_build_selection(
    kind: HarnessKind,
    request: &HarnessRequest,
) -> Option<GuestBuildSelection> {
    (kind == HarnessKind::GuestTest).then(|| GuestBuildSelection {
        selector: request.selector.clone(),
        expected_test_id: request.test_id,
    })
}

pub(super) fn qemu_arguments(
    profile: &HarnessProfile,
    request: &HarnessRequest,
    kind: HarnessKind,
) -> Vec<String> {
    let mut args = vec![
        "-machine".into(),
        profile.machine.clone(),
        "-m".into(),
        format!("{}M", profile.memory_mib),
        "-smp".into(),
        profile.vcpu.to_string(),
        "-nodefaults".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-no-reboot".into(),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            request.ovmf_code
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", request.ovmf_vars),
        "-drive".into(),
        format!(
            "if=virtio,format=raw,readonly=on,file={}",
            request.esp_image
        ),
        "-drive".into(),
        format!("if=virtio,format=qcow2,file={}", request.system_disk),
        "-serial".into(),
        format!("file:{}", request.serial_log),
    ];
    if kind == HarnessKind::GuestTest {
        args.extend([
            "-fw_cfg".into(),
            format!(
                "name=opt/org.deepwyrm.test.selector,string={}",
                request.selector
            ),
            "-device".into(),
            "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
        ]);
    }
    if kind == HarnessKind::Gdb {
        args.extend([
            "-S".into(),
            "-gdb".into(),
            format!("tcp:127.0.0.1:{}", profile.gdb_port),
        ]);
    }
    args
}

pub(super) fn gdb_arguments(profile: &HarnessProfile, request: &HarnessRequest) -> Vec<String> {
    vec![
        "-ex".into(),
        "set architecture i386:x86-64".into(),
        "-ex".into(),
        format!("file {}", request.deepwyrm_symbols),
        "-ex".into(),
        format!("target remote 127.0.0.1:{}", profile.gdb_port),
    ]
}

mod guest_result;
mod request;

pub(crate) use guest_result::*;
pub(crate) use request::*;
