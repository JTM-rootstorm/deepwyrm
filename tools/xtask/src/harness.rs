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

pub(super) fn parse_guest_result_file(
    path: &Path,
    request_path: &Path,
    exit_status: i32,
) -> io::Result<u8> {
    let request_bytes = match read_bounded(request_path, "guest-test request", MAX_REQUEST_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return emit_infrastructure_result(
                None,
                None,
                None,
                &format!("cannot read guest-test request: {error}"),
            );
        }
    };
    let request_digest = sha256_hex(&request_bytes);
    let request = match std::str::from_utf8(&request_bytes)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "guest-test request is not UTF-8",
            )
        })
        .and_then(|text| parse_harness_request(text, request_path))
    {
        Ok(request) => request,
        Err(error) => {
            return emit_infrastructure_result(
                None,
                None,
                Some(&request_digest),
                &format!("cannot read guest-test request: {error}"),
            );
        }
    };
    let harness_config = workspace_root().join(HARNESS_CONFIG);
    if let Err(error) = validate_request(HarnessKind::GuestTest, &request, None)
        .and_then(|()| load_profiles(&harness_config).map(|_| ()))
        .and_then(|()| validate_guest_selector_metadata(&harness_config, &request))
    {
        return emit_infrastructure_result(
            Some(&request.selector),
            Some(request.test_id),
            Some(&request_digest),
            &format!("invalid guest-test request: {error}"),
        );
    }
    let request_root = request_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let declared_serial = request_root.join(&request.serial_log);
    if declared_serial != path || !declared_serial.starts_with(request_root) {
        return emit_infrastructure_result(
            Some(&request.selector),
            Some(request.test_id),
            Some(&request_digest),
            "serial log path is not the request-declared path under the request root",
        );
    }
    let relative_parent = Path::new(&request.serial_log)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let canonical_root = match fs::canonicalize(request_root) {
        Ok(path) => path,
        Err(error) => {
            return emit_infrastructure_result(
                Some(&request.selector),
                Some(request.test_id),
                Some(&request_digest),
                &format!("cannot canonicalize request root: {error}"),
            );
        }
    };
    let declared_parent = declared_serial.parent().unwrap_or(request_root);
    let canonical_parent = match fs::canonicalize(declared_parent) {
        Ok(path) => path,
        Err(error) => {
            return emit_infrastructure_result(
                Some(&request.selector),
                Some(request.test_id),
                Some(&request_digest),
                &format!("cannot canonicalize declared serial parent: {error}"),
            );
        }
    };
    if canonical_parent != canonical_root.join(relative_parent) {
        return emit_infrastructure_result(
            Some(&request.selector),
            Some(request.test_id),
            Some(&request_digest),
            "declared serial parent escapes the canonical request-root boundary",
        );
    }
    let bytes = match read_bounded(path, "serial log", MAX_SERIAL_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return emit_infrastructure_result(
                Some(&request.selector),
                Some(request.test_id),
                Some(&request_digest),
                &format!("cannot read serial log: {error}"),
            );
        }
    };
    match parse_guest_terminal_record(&bytes, request.test_id) {
        Ok(record) => {
            if exit_status != record.status.debug_exit_status() {
                return emit_infrastructure_result(
                    Some(&request.selector),
                    Some(request.test_id),
                    Some(&request_digest),
                    "QEMU exit status does not match the serial terminal outcome",
                );
            }
            let mut stdout = io::stdout().lock();
            writeln!(
                stdout,
                "{{\"schema_version\":1,\"status\":\"{}\",\"selector\":\"{}\",\"test_id\":{},\"detail\":{},\"serial_line\":{},\"qemu_exit_status\":{},\"request_sha256\":\"{}\",\"freshness_proof\":false}}",
                record.status.as_str(),
                json_string(&request.selector),
                record.test_id,
                record.detail,
                record.line,
                exit_status,
                request_digest,
            )?;
            Ok(if record.status == GuestTerminalStatus::Pass {
                0
            } else {
                1
            })
        }
        Err(error) => emit_infrastructure_result(
            Some(&request.selector),
            Some(request.test_id),
            Some(&request_digest),
            &error,
        ),
    }
}

pub(super) fn emit_infrastructure_result(
    expected_selector: Option<&str>,
    expected_test_id: Option<u32>,
    request_digest: Option<&str>,
    detail: &str,
) -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "{{\"schema_version\":1,\"status\":\"INFRASTRUCTURE\",\"selector\":\"{}\",\"test_id\":{},\"request_sha256\":{},\"detail\":\"{}\"}}",
        json_string(expected_selector.unwrap_or("")),
        expected_test_id.map_or_else(|| "null".to_owned(), |id| id.to_string()),
        request_digest.map_or_else(|| "null".to_owned(), |hash| format!("\"{hash}\"")),
        json_string(detail)
    )?;
    Ok(1)
}

pub(super) fn parse_guest_terminal_record(
    bytes: &[u8],
    expected_test_id: u32,
) -> Result<GuestTerminalRecord, String> {
    let mut terminal = None;
    let mut line_number = 0;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        line_number += 1;
        if !line.starts_with(b"DWTEST1|") {
            continue;
        }
        if line.len() != 38 {
            return Err(format!(
                "serial line {line_number}: DWTEST1 terminal record must be exactly 38 bytes"
            ));
        }
        let record = line;
        if record[10] != b'|' || record[19] != b'|' || record[28] != b'|' || record[37] != b'\n' {
            return Err(format!(
                "serial line {line_number}: malformed DWTEST1 terminal delimiters"
            ));
        }
        let status = match &record[8..10] {
            b"01" => GuestTerminalStatus::Pass,
            b"02" => GuestTerminalStatus::Fail,
            b"03" => GuestTerminalStatus::Panic,
            _ => {
                return Err(format!(
                    "serial line {line_number}: invalid DWTEST1 outcome"
                ));
            }
        };
        let test_id = parse_hex_u32(&record[11..19])
            .ok_or_else(|| format!("serial line {line_number}: invalid DWTEST1 test id"))?;
        let detail = parse_hex_u32(&record[20..28])
            .ok_or_else(|| format!("serial line {line_number}: invalid DWTEST1 detail"))?;
        let checksum = parse_hex_u32(&record[29..37])
            .ok_or_else(|| format!("serial line {line_number}: invalid DWTEST1 checksum"))?;
        if checksum != fnv1a32(&record[..29]) {
            return Err(format!(
                "serial line {line_number}: DWTEST1 checksum mismatch"
            ));
        }
        if test_id != expected_test_id {
            return Err(format!(
                "serial line {line_number}: test id {test_id:08X} does not match request {expected_test_id:08X}"
            ));
        }
        if terminal.is_some() {
            return Err(format!(
                "serial line {line_number}: duplicate or conflicting terminal record"
            ));
        }
        terminal = Some(GuestTerminalRecord {
            status,
            test_id,
            detail,
            line: line_number,
        });
    }
    terminal.ok_or_else(|| {
        "serial log contains no DWTEST1 terminal record (host must classify timeout separately)"
            .into()
    })
}

pub(super) fn parse_hex_u32(value: &[u8]) -> Option<u32> {
    if value.len() != 8
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return None;
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| u32::from_str_radix(value, 16).ok())
}

pub(super) fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811C_9DC5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

pub(super) fn validate_kernel_layout(path: &Path, expected_sha256: &str) -> io::Result<()> {
    let bytes = read_bounded(path, "kernel layout manifest", MAX_CONFIG_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel layout manifest is not UTF-8",
        )
    })?;
    for required in [
        "schema = \"deepwyrm-x86_64-layout\"",
        "entry_contract",
        "p_paddr_policy",
        "allowed_program_header_types",
    ] {
        if !text.contains(required) {
            return invalid_input(format!(
                "kernel layout manifest omits required `{required}` contract field"
            ));
        }
    }
    if sha256_hex(&bytes) != expected_sha256.to_ascii_lowercase() {
        return invalid_input("kernel layout manifest SHA-256 does not match the request".into());
    }
    Ok(())
}

pub(super) fn sha256_hex(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ];
    const K: [u32; 64] = [
        0x428A_2F98,
        0x7137_4491,
        0xB5C0_FBCF,
        0xE9B5_DBA5,
        0x3956_C25B,
        0x59F1_11F1,
        0x923F_82A4,
        0xAB1C_5ED5,
        0xD807_AA98,
        0x1283_5B01,
        0x2431_85BE,
        0x550C_7DC3,
        0x72BE_5D74,
        0x80DE_B1FE,
        0x9BDC_06A7,
        0xC19B_F174,
        0xE49B_69C1,
        0xEFBE_4786,
        0x0FC1_9DC6,
        0x240C_A1CC,
        0x2DE9_2C6F,
        0x4A74_84AA,
        0x5CB0_A9DC,
        0x76F9_88DA,
        0x983E_5152,
        0xA831_C66D,
        0xB003_27C8,
        0xBF59_7FC7,
        0xC6E0_0BF3,
        0xD5A7_9147,
        0x06CA_6351,
        0x1429_2967,
        0x27B7_0A85,
        0x2E1B_2138,
        0x4D2C_6DFC,
        0x5338_0D13,
        0x650A_7354,
        0x766A_0ABB,
        0x81C2_C92E,
        0x9272_2C85,
        0xA2BF_E8A1,
        0xA81A_664B,
        0xC24B_8B70,
        0xC76C_51A3,
        0xD192_E819,
        0xD699_0624,
        0xF40E_3585,
        0x106A_A070,
        0x19A4_C116,
        0x1E37_6C08,
        0x2748_774C,
        0x34B0_BCB5,
        0x391C_0CB3,
        0x4ED8_AA4A,
        0x5B9C_CA4F,
        0x682E_6FF3,
        0x748F_82EE,
        0x78A5_636F,
        0x84C8_7814,
        0x8CC7_0208,
        0x90BE_FFFA,
        0xA450_6CEB,
        0xBEF9_A3F7,
        0xC671_78F2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut bytes = input.to_vec();
    bytes.push(0x80);
    while !(bytes.len() + 8).is_multiple_of(64) {
        bytes.push(0);
    }
    bytes.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in bytes.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(
                chunk[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("SHA-256 chunk word"),
            );
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state = [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ];
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

pub(super) fn load_profiles(path: &Path) -> io::Result<BTreeMap<String, HarnessProfile>> {
    let text = read_bounded_utf8(path, "guest harness config", MAX_CONFIG_BYTES)?;
    let mut profiles = BTreeMap::new();
    let mut values = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut guest_tests = BTreeMap::<String, Option<u32>>::new();
    enum Section {
        Profile(String),
        GuestTest(String),
    }
    let mut current = None::<Section>;
    let mut saw_schema = false;
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "schema_version = 1" {
            if saw_schema || current.is_some() {
                return invalid_input(format!(
                    "{}:{}: schema_version must appear once before sections",
                    path.display(),
                    line_number + 1
                ));
            }
            saw_schema = true;
            continue;
        }
        if line.starts_with("[profile.") && line.ends_with(']') {
            let name = &line[9..line.len() - 1];
            validate_name(name, "profile")?;
            if values.contains_key(name) {
                return invalid_input(format!(
                    "{}:{line_number}: duplicate profile `{name}`",
                    path.display()
                ));
            }
            values.insert(name.into(), BTreeMap::new());
            current = Some(Section::Profile(name.into()));
            continue;
        }
        if line.starts_with("[guest_test.") && line.ends_with(']') {
            let selector = &line[12..line.len() - 1];
            validate_selector(selector)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if guest_tests.insert(selector.into(), None).is_some() {
                return invalid_input(format!(
                    "{}:{}: duplicate guest-test selector `{selector}`",
                    path.display(),
                    line_number + 1
                ));
            }
            current = Some(Section::GuestTest(selector.into()));
            continue;
        }
        if line.starts_with('[') {
            return invalid_input(format!(
                "{}:{}: unsupported harness configuration section",
                path.display(),
                line_number + 1
            ));
        }
        let (key, value) = parse_toml_scalar(line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {error}", path.display(), line_number + 1),
            )
        })?;
        match current.as_ref() {
            Some(Section::Profile(section)) => {
                let profile_values = values
                    .get_mut(section)
                    .expect("current profile was inserted");
                if profile_values.insert(key.into(), value).is_some() {
                    return invalid_input(format!(
                        "{}:{}: duplicate key `{key}`",
                        path.display(),
                        line_number + 1
                    ));
                }
            }
            Some(Section::GuestTest(selector)) => {
                if key != "id" {
                    return invalid_input(format!(
                        "{}:{}: guest-test `{selector}` only accepts `id`",
                        path.display(),
                        line_number + 1
                    ));
                }
                let id = value.parse::<u32>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}:{}: guest-test id must be an integer",
                            path.display(),
                            line_number + 1
                        ),
                    )
                })?;
                if id == 0
                    || guest_tests
                        .insert(selector.clone(), Some(id))
                        .flatten()
                        .is_some()
                {
                    return invalid_input(format!(
                        "{}:{}: guest-test `{selector}` has an invalid or duplicate id",
                        path.display(),
                        line_number + 1
                    ));
                }
            }
            None => {
                return invalid_input(format!(
                    "{}:{}: value outside a supported section",
                    path.display(),
                    line_number + 1
                ));
            }
        }
    }
    if !saw_schema || guest_tests.values().any(Option::is_none) {
        return invalid_input(
            "guest harness configuration is missing schema or guest-test id".into(),
        );
    }
    let unique_ids = guest_tests
        .values()
        .filter_map(|id| *id)
        .collect::<BTreeSet<_>>();
    if unique_ids.len() != guest_tests.len() {
        return invalid_input("guest harness configuration has duplicate guest-test IDs".into());
    }
    for (name, values) in values {
        let profile = HarnessProfile {
            name: name.clone(),
            machine: required_string(&values, "machine")?,
            vcpu: required_number(&values, "vcpu")?,
            memory_mib: required_number(&values, "memory_mib")?,
            timeout_seconds: required_number(&values, "timeout_seconds")?,
            gdb_port: required_number(&values, "gdb_port")?,
        };
        if profile.machine != "q35"
            || profile.vcpu == 0
            || profile.memory_mib == 0
            || profile.timeout_seconds == 0
        {
            return invalid_input(format!("profile `{name}` has an invalid q35 harness value"));
        }
        profiles.insert(name, profile);
    }
    if profiles.is_empty() {
        return invalid_input("guest harness configuration contains no profiles".into());
    }
    Ok(profiles)
}

pub(super) fn load_harness_request(path: &Path) -> io::Result<HarnessRequest> {
    let text = read_bounded_utf8(path, "guest harness request", MAX_REQUEST_BYTES)?;
    parse_harness_request(&text, path)
}

pub(super) fn parse_harness_request(text: &str, path: &Path) -> io::Result<HarnessRequest> {
    let values = parse_flat_toml(text, path)?;
    if values.get("schema_version").map(String::as_str) != Some("1") {
        return invalid_input("guest harness request requires schema_version = 1".into());
    }
    if values.get("producer").map(String::as_str) != Some("wyrmroot") {
        return invalid_input("guest harness request producer must be `wyrmroot`".into());
    }
    let request = HarnessRequest {
        kind: required_string(&values, "kind")?,
        profile: required_string(&values, "profile")?,
        selector: required_value(&values, "selector")?,
        test_id: required_number(&values, "test_id")?,
        timeout_seconds: required_number(&values, "timeout_seconds")?,
        serial_log: required_relative_path(&values, "serial_log")?,
        result_json: required_relative_path(&values, "result_json")?,
        no_host_share: required_bool(&values, "no_host_share")?,
        deepwyrm_revision: required_revision(&values, "deepwyrm_revision")?,
        deepwyrm_dirty: required_bool(&values, "deepwyrm_dirty")?,
        wyrmroot_revision: required_revision(&values, "wyrmroot_revision")?,
        wyrmroot_dirty: required_bool(&values, "wyrmroot_dirty")?,
        esp_image: required_relative_path(&values, "esp_image")?,
        esp_sha256: required_sha256(&values, "esp_sha256")?,
        system_disk: required_relative_path(&values, "system_disk")?,
        system_disk_sha256: required_sha256(&values, "system_disk_sha256")?,
        ovmf_code: required_relative_path(&values, "ovmf_code")?,
        ovmf_code_sha256: required_sha256(&values, "ovmf_code_sha256")?,
        ovmf_vars: required_relative_path(&values, "ovmf_vars")?,
        ovmf_vars_sha256: required_sha256(&values, "ovmf_vars_sha256")?,
        deepwyrm_elf: required_relative_path(&values, "deepwyrm_elf")?,
        deepwyrm_elf_sha256: required_sha256(&values, "deepwyrm_elf_sha256")?,
        deepwyrm_symbols: required_relative_path(&values, "deepwyrm_symbols")?,
        deepwyrm_symbols_sha256: required_sha256(&values, "deepwyrm_symbols_sha256")?,
        kernel_layout_sha256: required_sha256(&values, "kernel_layout_sha256")?,
        rust_toolchain_commit: required_revision(&values, "rust_toolchain_commit")?,
        toolchain_config_sha256: required_sha256(&values, "toolchain_config_sha256")?,
        toolchain_root_manifest_sha256: required_sha256(&values, "toolchain_root_manifest_sha256")?,
        toolchain_cargo: required_absolute_path(&values, "toolchain_cargo")?,
        toolchain_cargo_sha256: required_sha256(&values, "toolchain_cargo_sha256")?,
        toolchain_rustc: required_absolute_path(&values, "toolchain_rustc")?,
        toolchain_rustc_sha256: required_sha256(&values, "toolchain_rustc_sha256")?,
        toolchain_rust_lld: required_absolute_path(&values, "toolchain_rust_lld")?,
        toolchain_rust_lld_sha256: required_sha256(&values, "toolchain_rust_lld_sha256")?,
        toolchain_sysroot_manifest: required_absolute_path(&values, "toolchain_sysroot_manifest")?,
        toolchain_sysroot_manifest_sha256: required_sha256(
            &values,
            "toolchain_sysroot_manifest_sha256",
        )?,
    };
    Ok(request)
}

pub(super) fn validate_request(
    kind: HarnessKind,
    request: &HarnessRequest,
    expected_selector: Option<&str>,
) -> io::Result<()> {
    if request.kind != kind.request_kind() {
        return invalid_input(format!(
            "request kind `{}` cannot be used for `{}` planning",
            request.kind,
            kind.request_kind()
        ));
    }
    validate_name(&request.profile, "profile")?;
    if kind == HarnessKind::GuestTest {
        validate_selector(&request.selector)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if request.test_id == 0 {
            return invalid_input("guest-test requests require a nonzero explicit test_id".into());
        }
        if let Some(expected_selector) = expected_selector
            && request.selector != expected_selector
        {
            return invalid_input("guest selector does not match the request".into());
        }
    } else if !request.selector.is_empty() || request.test_id != 0 {
        return invalid_input("only guest-test requests may carry a selector or test_id".into());
    }
    if request.timeout_seconds == 0 || !request.no_host_share {
        return invalid_input(
            "request must have a bounded timeout and no_host_share = true".into(),
        );
    }
    Ok(())
}

pub(super) fn validate_guest_selector_metadata(
    path: &Path,
    request: &HarnessRequest,
) -> io::Result<()> {
    if request.kind != HarnessKind::GuestTest.request_kind() {
        return Ok(());
    }
    let text = read_bounded_utf8(path, "guest harness config", MAX_CONFIG_BYTES)?;
    let mut current = None::<String>;
    let mut mappings = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with("[guest_test.") && line.ends_with(']') {
            let selector = &line[12..line.len() - 1];
            validate_selector(selector)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            current = Some(selector.into());
            continue;
        }
        if line.starts_with('[') {
            current = None;
            continue;
        }
        let Some(selector) = current.as_ref() else {
            continue;
        };
        if line.is_empty() {
            continue;
        }
        let (key, value) = parse_toml_scalar(line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if key == "id" {
            let id: u32 = value.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest test id must be an integer",
                )
            })?;
            if id == 0 || mappings.insert(selector.clone(), id).is_some() {
                return invalid_input("duplicate or zero guest-test selector mapping".into());
            }
        }
    }
    let expected_id = mappings.get(&request.selector).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest-test selector has no centralized ID mapping",
        )
    })?;
    if mappings.values().filter(|id| **id == *expected_id).count() != 1
        || *expected_id != request.test_id
    {
        return invalid_input(
            "guest-test request ID does not match a unique centralized selector mapping".into(),
        );
    }
    Ok(())
}

pub(super) fn parse_flat_toml(text: &str, path: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            return invalid_input(format!(
                "{}:{}: sections are not allowed",
                path.display(),
                line_number + 1
            ));
        }
        let (key, value) = parse_toml_scalar(line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {error}", path.display(), line_number + 1),
            )
        })?;
        if values.insert(key.into(), value).is_some() {
            return invalid_input(format!(
                "{}:{}: duplicate key `{key}`",
                path.display(),
                line_number + 1
            ));
        }
    }
    Ok(values)
}

pub(super) fn read_bounded(path: &Path, label: &str, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_no_symlinks(path, label)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return invalid_input(format!("{label} must be a regular file"));
    }
    if metadata.len() > limit as u64 {
        return invalid_input(format!("{label} exceeds the {limit}-byte limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return invalid_input(format!("{label} exceeds the {limit}-byte limit"));
    }
    Ok(bytes)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn open_no_symlinks(path: &Path, label: &str) -> io::Result<fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::raw::c_long;
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
    }

    // Linux x86_64 constants from asm/unistd.h and linux/openat2.h. This is the
    // only unsafe boundary: openat2 atomically rejects symlinks in every component.
    const SYS_OPENAT2: c_long = 437;
    const AT_FDCWD: c_long = -100;
    const O_CLOEXEC: u64 = 0o2_000_000;
    const O_NONBLOCK: u64 = 0o4_000;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;

    let raw_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} path contains an interior NUL"),
        )
    })?;
    let how = OpenHow {
        flags: O_CLOEXEC | O_NONBLOCK,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: raw_path and how remain valid for the syscall; the returned fd is
    // transferred immediately to File only when non-negative.
    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            AT_FDCWD,
            raw_path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("cannot open {label} without traversing symbolic links: {error}"),
        ));
    }
    // SAFETY: successful openat2 returns an owned file descriptor.
    Ok(unsafe { fs::File::from_raw_fd(fd as i32) })
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(super) fn open_no_symlinks(_path: &Path, label: &str) -> io::Result<fs::File> {
    invalid_input(format!(
        "{label} cannot be read safely: atomic no-symlink open is unavailable on this host"
    ))
}

pub(super) fn read_bounded_utf8(path: &Path, label: &str, limit: usize) -> io::Result<String> {
    String::from_utf8(read_bounded(path, label, limit)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{label} is not UTF-8")))
}

pub(super) fn parse_toml_scalar(line: &str) -> Result<(&str, String), String> {
    let (key, raw_value) = line
        .split_once('=')
        .ok_or_else(|| "expected `key = value`".to_owned())?;
    let key = key.trim();
    let raw_value = raw_value.trim();
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("invalid key".into());
    }
    let value = if raw_value.starts_with('"') && raw_value.ends_with('"') && raw_value.len() >= 2 {
        raw_value[1..raw_value.len() - 1].to_owned()
    } else if !raw_value.contains(char::is_whitespace) {
        raw_value.to_owned()
    } else {
        return Err("values must be one unescaped string, number, or boolean".into());
    };
    Ok((key, value))
}

pub(super) fn required_string(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing or empty `{key}`"),
            )
        })
}

pub(super) fn required_value(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing `{key}`")))
}

pub(super) fn required_number<T>(values: &BTreeMap<String, String>, key: &str) -> io::Result<T>
where
    T: std::str::FromStr,
{
    required_string(values, key)?.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{key}` must be an integer"),
        )
    })
}

pub(super) fn required_bool(values: &BTreeMap<String, String>, key: &str) -> io::Result<bool> {
    match required_string(values, key)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => invalid_input(format!("`{key}` must be true or false")),
    }
}

pub(super) fn required_relative_path(
    values: &BTreeMap<String, String>,
    key: &str,
) -> io::Result<String> {
    let value = required_string(values, key)?;
    let path = Path::new(&value);
    if path.is_absolute()
        || path.components().any(|component| match component {
            Component::Normal(part) => !part
                .as_encoded_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => true,
        })
    {
        return invalid_input(format!(
            "`{key}` must be a relative path without parent traversal"
        ));
    }
    Ok(value)
}

pub(super) fn required_absolute_path(
    values: &BTreeMap<String, String>,
    key: &str,
) -> io::Result<String> {
    let value = required_string(values, key)?;
    let path = Path::new(&value);
    if !path.is_absolute()
        || path.components().any(|component| match component {
            Component::Normal(part) => !part
                .as_encoded_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            Component::RootDir => false,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => true,
        })
    {
        return invalid_input(format!(
            "`{key}` must be an absolute portable path without traversal"
        ));
    }
    Ok(value)
}
