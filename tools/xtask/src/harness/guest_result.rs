use super::*;

pub(crate) fn parse_guest_result_file(
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

pub(crate) fn emit_infrastructure_result(
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

pub(crate) fn parse_guest_terminal_record(
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

pub(crate) fn parse_hex_u32(value: &[u8]) -> Option<u32> {
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

pub(crate) fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811C_9DC5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

pub(crate) fn validate_kernel_layout(path: &Path, expected_sha256: &str) -> io::Result<()> {
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

pub(crate) fn sha256_hex(input: &[u8]) -> String {
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
