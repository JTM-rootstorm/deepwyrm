use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const EXIT_NOT_IMPLEMENTED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;

const COMMANDS: &[&str] = &[
    "format",
    "check",
    "abi",
    "build",
    "image",
    "run",
    "inspect-image",
    "gdb",
    "test",
    "guest-result",
    "toolchain",
];
const TEST_TIERS: &[&str] = &["host", "guest", "integration"];
const HARNESS_CONFIG: &str = "tooling/guest-harness.toml";
const TRUSTED_TOOLCHAIN_CONFIG: &str = "tooling/rust-toolchain.toml";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_SERIAL_BYTES: usize = 4 * 1024 * 1024;
const HELP: &str = r#"Deepwyrm project tasks

Status: DW0-A host tooling and DW0-B dry-run harness planning are available.
Build, image, and integration operations remain planned and are not implemented.

Usage:
  cargo xtask <command>

Commands:
  format                             Verify Rust formatting
  check                              Run the workspace check
  abi generate                       Generate ABI-owned artifacts
  abi check                          Verify generated ABI artifacts have no drift
  test host [filter]                 Run focused host tests
  run --plan --request <path>        Emit the canonical QEMU run plan only
  gdb --plan --request <path>        Emit paused QEMU/GDB command plans only
  test guest <selector> --plan --request <path>
                                     Emit a filtered guest-test plan only
  guest-result <serial-log> --request <path> --exit-status <code>
                                     Classify one DWTEST1 terminal record and QEMU exit
  toolchain                          Report host tool availability
  build                              Build Deepwyrm [not implemented]
  image                              Construct boot media [not implemented]
  inspect-image                      Inspect boot media [not implemented]
  test integration [filter]          Run integration tests [not implemented]
  help [command]                     Show status and usage
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    Help(Option<String>),
    Command(Invocation),
    GuestResult {
        serial_log: PathBuf,
        request_path: PathBuf,
        exit_status: i32,
    },
    Toolchain,
    NotImplemented(String),
    UsageError(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Invocation {
    Format,
    Check,
    AbiGenerate,
    AbiCheck,
    HostTests(Option<String>),
    HarnessPlan(HarnessKind, PathBuf, Option<String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarnessKind {
    Run,
    GuestTest,
    Gdb,
}

impl HarnessKind {
    const fn request_kind(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::GuestTest => "guest-test",
            Self::Gdb => "gdb",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HarnessProfile {
    name: String,
    machine: String,
    vcpu: u32,
    memory_mib: u32,
    timeout_seconds: u32,
    gdb_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HarnessRequest {
    kind: String,
    profile: String,
    selector: String,
    test_id: u32,
    timeout_seconds: u32,
    serial_log: String,
    result_json: String,
    no_host_share: bool,
    deepwyrm_revision: String,
    deepwyrm_dirty: bool,
    wyrmroot_revision: String,
    wyrmroot_dirty: bool,
    esp_image: String,
    esp_sha256: String,
    system_disk: String,
    system_disk_sha256: String,
    ovmf_code: String,
    ovmf_code_sha256: String,
    ovmf_vars: String,
    ovmf_vars_sha256: String,
    deepwyrm_elf: String,
    deepwyrm_elf_sha256: String,
    deepwyrm_symbols: String,
    deepwyrm_symbols_sha256: String,
    kernel_layout_sha256: String,
    rust_toolchain_commit: String,
    toolchain_config_sha256: String,
    toolchain_root_manifest_sha256: String,
    toolchain_cargo: String,
    toolchain_cargo_sha256: String,
    toolchain_rustc: String,
    toolchain_rustc_sha256: String,
    toolchain_rust_lld: String,
    toolchain_rust_lld_sha256: String,
    toolchain_sysroot_manifest: String,
    toolchain_sysroot_manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedToolchain {
    request_id: String,
    rust_commit: String,
    target: String,
    config_sha256: String,
    root_manifest_path: PathBuf,
    root_manifest_sha256: String,
    cargo_path: PathBuf,
    cargo_sha256: String,
    rustc_path: PathBuf,
    rustc_sha256: String,
    rust_lld_path: PathBuf,
    rust_lld_sha256: String,
    sysroot_manifest_path: PathBuf,
    sysroot_manifest_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuestTerminalStatus {
    Pass,
    Fail,
    Panic,
}

impl GuestTerminalStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Panic => "PANIC",
        }
    }

    const fn debug_exit_status(self) -> i32 {
        match self {
            Self::Pass => 33,
            Self::Fail => 35,
            Self::Panic => 37,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuestTerminalRecord {
    status: GuestTerminalStatus,
    test_id: u32,
    detail: u32,
    line: usize,
}

pub fn run<I, S>(args: I) -> io::Result<u8>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args = args
        .into_iter()
        .map(Into::into)
        .map(|arg| arg.into_string())
        .collect::<Result<Vec<_>, _>>();

    match args {
        Ok(args) => dispatch(parse(&args)),
        Err(_) => {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "error: arguments must be valid UTF-8")?;
            writeln!(stderr, "Run `cargo xtask help` for usage.")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn dispatch(action: Action) -> io::Result<u8> {
    match action {
        Action::Help(command) => {
            let mut stdout = io::stdout().lock();
            print_help(&mut stdout, command.as_deref())?;
            Ok(0)
        }
        Action::Command(invocation) => run_invocation(invocation),
        Action::GuestResult {
            serial_log,
            request_path,
            exit_status,
        } => parse_guest_result_file(&serial_log, &request_path, exit_status),
        Action::Toolchain => print_toolchain_diagnostics(),
        Action::NotImplemented(command) => {
            let mut stderr = io::stderr().lock();
            writeln!(
                stderr,
                "error: `cargo xtask {command}` is planned but not implemented"
            )?;
            writeln!(
                stderr,
                "No build, image, VM, debugger, guest, or integration operation was performed."
            )?;
            Ok(EXIT_NOT_IMPLEMENTED)
        }
        Action::UsageError(message) => {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "error: {message}")?;
            writeln!(stderr, "Run `cargo xtask help` for usage.")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn run_invocation(invocation: Invocation) -> io::Result<u8> {
    let mut command = Command::new("cargo");
    command.current_dir(workspace_root());

    match invocation {
        Invocation::Format => {
            command.args(["fmt", "--all", "--", "--check"]);
        }
        Invocation::Check => {
            command.args(["check", "--locked", "--workspace", "--all-targets"]);
        }
        Invocation::AbiGenerate => {
            command.args(["run", "--locked", "--package", "abi-gen", "--", "generate"]);
        }
        Invocation::AbiCheck => {
            command.args(["run", "--locked", "--package", "abi-gen", "--", "check"]);
        }
        Invocation::HostTests(filter) => {
            command.args(["test", "--locked"]);
            if filter.as_deref() == Some("abi") {
                command.args(["--package", "abi-gen", "--package", "deepwyrm-abi"]);
            } else {
                command.args(["--workspace", "--all-targets"]);
                if let Some(filter) = filter {
                    command.args(["--", &filter]);
                }
            }
        }
        Invocation::HarnessPlan(kind, request_path, expected_selector) => {
            return emit_harness_plan(kind, &request_path, expected_selector.as_deref());
        }
    };

    let status = command.status()?;
    Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8)
}

fn emit_harness_plan(
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

fn qemu_arguments(
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
            format!("tcp::{}", profile.gdb_port),
        ]);
    }
    args
}

fn gdb_arguments(profile: &HarnessProfile, request: &HarnessRequest) -> Vec<String> {
    vec![
        "-ex".into(),
        "set architecture i386:x86-64".into(),
        "-ex".into(),
        format!("file {}", request.deepwyrm_symbols),
        "-ex".into(),
        format!("target remote :{}", profile.gdb_port),
    ]
}

fn parse_guest_result_file(path: &Path, request_path: &Path, exit_status: i32) -> io::Result<u8> {
    let request_digest = match read_bounded(request_path, "guest-test request", MAX_REQUEST_BYTES) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(error) => {
            return emit_infrastructure_result(
                None,
                None,
                None,
                &format!("cannot read guest-test request: {error}"),
            );
        }
    };
    let request = match load_harness_request(request_path) {
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
    if let Err(error) = validate_request(HarnessKind::GuestTest, &request, None).and_then(|()| {
        validate_guest_selector_metadata(&workspace_root().join(HARNESS_CONFIG), &request)
    }) {
        return emit_infrastructure_result(
            Some(&request.selector),
            Some(request.test_id),
            Some(&request_digest),
            &format!("invalid guest-test request: {error}"),
        );
    }
    let request_root = request_path.parent().unwrap_or_else(|| Path::new(""));
    let declared_serial = request_root.join(&request.serial_log);
    if declared_serial != path || !declared_serial.starts_with(request_root) {
        return emit_infrastructure_result(
            Some(&request.selector),
            Some(request.test_id),
            Some(&request_digest),
            "serial log path is not the request-declared path under the request root",
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

fn emit_infrastructure_result(
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

fn parse_guest_terminal_record(
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

fn parse_hex_u32(value: &[u8]) -> Option<u32> {
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

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811C_9DC5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn validate_kernel_layout(path: &Path, expected_sha256: &str) -> io::Result<()> {
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

fn sha256_hex(input: &[u8]) -> String {
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

fn load_profiles(path: &Path) -> io::Result<BTreeMap<String, HarnessProfile>> {
    let text = read_bounded_utf8(path, "guest harness config", MAX_CONFIG_BYTES)?;
    let mut profiles = BTreeMap::new();
    let mut current = None::<String>;
    let mut values = BTreeMap::<String, BTreeMap<String, String>>::new();
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line == "schema_version = 1" {
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
            current = Some(name.into());
            continue;
        }
        if line.starts_with('[') {
            current = None;
            continue;
        }
        let (key, value) = parse_toml_scalar(line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {error}", path.display(), line_number + 1),
            )
        })?;
        let section = current.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}:{}: value outside a profile",
                    path.display(),
                    line_number + 1
                ),
            )
        })?;
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

fn load_harness_request(path: &Path) -> io::Result<HarnessRequest> {
    let text = read_bounded_utf8(path, "guest harness request", MAX_REQUEST_BYTES)?;
    let values = parse_flat_toml(&text, path)?;
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

fn validate_request(
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

fn validate_guest_selector_metadata(path: &Path, request: &HarnessRequest) -> io::Result<()> {
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

fn parse_flat_toml(text: &str, path: &Path) -> io::Result<BTreeMap<String, String>> {
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

fn read_bounded(path: &Path, label: &str, limit: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.file_type().is_file() {
        return invalid_input(format!("{label} must be a regular file"));
    }
    if metadata.len() > limit as u64 {
        return invalid_input(format!("{label} exceeds the {limit}-byte limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return invalid_input(format!("{label} exceeds the {limit}-byte limit"));
    }
    Ok(bytes)
}

fn read_bounded_utf8(path: &Path, label: &str, limit: usize) -> io::Result<String> {
    String::from_utf8(read_bounded(path, label, limit)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{label} is not UTF-8")))
}

fn parse_toml_scalar(line: &str) -> Result<(&str, String), String> {
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

fn required_string(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
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

fn required_value(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing `{key}`")))
}

fn required_number<T>(values: &BTreeMap<String, String>, key: &str) -> io::Result<T>
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

fn required_bool(values: &BTreeMap<String, String>, key: &str) -> io::Result<bool> {
    match required_string(values, key)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => invalid_input(format!("`{key}` must be true or false")),
    }
}

fn required_relative_path(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
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

fn required_absolute_path(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
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

fn validate_toolchain_provenance(request: &HarnessRequest) -> io::Result<TrustedToolchain> {
    let trusted = load_trusted_toolchain(&workspace_root().join(TRUSTED_TOOLCHAIN_CONFIG))?;
    validate_request_toolchain_identity(request, &trusted)?;
    verify_trusted_toolchain_artifacts(&trusted)?;
    validate_sysroot_manifest(&trusted)?;
    Ok(trusted)
}

fn load_trusted_toolchain(path: &Path) -> io::Result<TrustedToolchain> {
    let values = parse_flat_toml(
        &read_bounded_utf8(path, "trusted toolchain config", 64 * 1024)?,
        path,
    )?;
    if values.get("schema").map(String::as_str) != Some("deepwyrm-rust-toolchain-identity-v1") {
        return invalid_input("trusted toolchain config has an unknown schema".into());
    }
    if values.get("request_id").map(String::as_str) != Some("RUST-PHASE0B-TOOLCHAIN-001") {
        return invalid_input("trusted toolchain config has an unexpected request ID".into());
    }
    let artifact_root = workspace_root()
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "workspace lacks a parent"))?
        .join(required_relative_path(&values, "artifact_root")?);
    let toolchain_root = artifact_root.join(required_relative_path(&values, "toolchain_root")?);
    let rust_commit = required_revision(&values, "rust_commit")?;
    if rust_commit != canonical_rust_commit(&workspace_root().join("toolchain/provenance.toml"))? {
        return invalid_input(
            "trusted toolchain Rust commit disagrees with canonical provenance".into(),
        );
    }
    let target = required_string(&values, "target")?;
    if target != "x86_64-unknown-none" {
        return invalid_input("trusted toolchain target must be x86_64-unknown-none".into());
    }
    Ok(TrustedToolchain {
        request_id: required_string(&values, "request_id")?,
        rust_commit,
        target,
        config_sha256: required_sha256(&values, "config_sha256")?,
        root_manifest_path: artifact_root.join(required_relative_path(&values, "root_manifest")?),
        root_manifest_sha256: required_sha256(&values, "root_manifest_sha256")?,
        cargo_path: toolchain_root.join(required_relative_path(&values, "cargo_binary")?),
        cargo_sha256: required_sha256(&values, "cargo_sha256")?,
        rustc_path: toolchain_root.join(required_relative_path(&values, "rustc_binary")?),
        rustc_sha256: required_sha256(&values, "rustc_sha256")?,
        rust_lld_path: toolchain_root.join(required_relative_path(&values, "rust_lld_binary")?),
        rust_lld_sha256: required_sha256(&values, "rust_lld_sha256")?,
        sysroot_manifest_path: artifact_root
            .join(required_relative_path(&values, "sysroot_manifest")?),
        sysroot_manifest_sha256: required_sha256(&values, "sysroot_manifest_sha256")?,
    })
}

fn validate_request_toolchain_identity(
    request: &HarnessRequest,
    trusted: &TrustedToolchain,
) -> io::Result<()> {
    let expected = [
        (
            "rust_toolchain_commit",
            request.rust_toolchain_commit.as_str(),
            trusted.rust_commit.as_str(),
        ),
        (
            "toolchain_config_sha256",
            request.toolchain_config_sha256.as_str(),
            trusted.config_sha256.as_str(),
        ),
        (
            "toolchain_root_manifest_sha256",
            request.toolchain_root_manifest_sha256.as_str(),
            trusted.root_manifest_sha256.as_str(),
        ),
        (
            "toolchain_cargo_sha256",
            request.toolchain_cargo_sha256.as_str(),
            trusted.cargo_sha256.as_str(),
        ),
        (
            "toolchain_rustc_sha256",
            request.toolchain_rustc_sha256.as_str(),
            trusted.rustc_sha256.as_str(),
        ),
        (
            "toolchain_rust_lld_sha256",
            request.toolchain_rust_lld_sha256.as_str(),
            trusted.rust_lld_sha256.as_str(),
        ),
        (
            "toolchain_sysroot_manifest_sha256",
            request.toolchain_sysroot_manifest_sha256.as_str(),
            trusted.sysroot_manifest_sha256.as_str(),
        ),
    ];
    for (name, actual, expected) in expected {
        if actual != expected {
            return invalid_input(format!(
                "request `{name}` does not match trusted toolchain identity"
            ));
        }
    }
    for (name, actual, expected) in [
        (
            "toolchain_cargo",
            Path::new(&request.toolchain_cargo),
            &trusted.cargo_path,
        ),
        (
            "toolchain_rustc",
            Path::new(&request.toolchain_rustc),
            &trusted.rustc_path,
        ),
        (
            "toolchain_rust_lld",
            Path::new(&request.toolchain_rust_lld),
            &trusted.rust_lld_path,
        ),
        (
            "toolchain_sysroot_manifest",
            Path::new(&request.toolchain_sysroot_manifest),
            &trusted.sysroot_manifest_path,
        ),
    ] {
        if actual != expected {
            return invalid_input(format!(
                "request `{name}` is not the trusted derived artifact path"
            ));
        }
    }
    Ok(())
}

fn verify_trusted_toolchain_artifacts(trusted: &TrustedToolchain) -> io::Result<()> {
    for (path, expected_hash, label, limit) in [
        (
            &trusted.root_manifest_path,
            &trusted.root_manifest_sha256,
            "root manifest",
            64 * 1024,
        ),
        (
            &trusted.cargo_path,
            &trusted.cargo_sha256,
            "cargo",
            512 * 1024 * 1024,
        ),
        (
            &trusted.rustc_path,
            &trusted.rustc_sha256,
            "rustc",
            512 * 1024 * 1024,
        ),
        (
            &trusted.rust_lld_path,
            &trusted.rust_lld_sha256,
            "rust-lld",
            512 * 1024 * 1024,
        ),
        (
            &trusted.sysroot_manifest_path,
            &trusted.sysroot_manifest_sha256,
            "sysroot manifest",
            64 * 1024,
        ),
    ] {
        let actual = sha256_hex(&read_bounded(path, label, limit)?);
        if actual != *expected_hash {
            return invalid_input(format!("trusted {label} hash does not match its identity"));
        }
    }
    Ok(())
}

fn canonical_rust_commit(path: &Path) -> io::Result<String> {
    let text = read_bounded_utf8(path, "canonical toolchain provenance", MAX_CONFIG_BYTES)?;
    let mut in_rust_section = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line == "[rust]" {
            in_rust_section = true;
            continue;
        }
        if line.starts_with('[') {
            in_rust_section = false;
            continue;
        }
        if !in_rust_section || line.is_empty() {
            continue;
        }
        let (key, value) = parse_toml_scalar(line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if key == "base_commit" {
            return validate_git_commit(&value, "canonical Rust base_commit");
        }
    }
    invalid_input("canonical toolchain provenance lacks [rust].base_commit".into())
}

fn validate_sysroot_manifest(trusted: &TrustedToolchain) -> io::Result<()> {
    let path = &trusted.sysroot_manifest_path;
    let text = read_bounded_utf8(path, "sysroot manifest", 64 * 1024)?;
    let values = parse_flat_toml(&text, path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "sysroot manifest content contract is not yet agreed; require schema = \"deepwyrm-rust-sysroot-manifest-v1\" with Rust commit, x86_64-unknown-none target, configuration hash, and component hashes",
        )
    })?;
    let schema = values.get("schema").map(String::as_str);
    if schema != Some("deepwyrm-rust-sysroot-manifest-v1") {
        return invalid_input(
            "sysroot manifest content contract is not yet agreed; require schema = \"deepwyrm-rust-sysroot-manifest-v1\" with Rust commit, x86_64-unknown-none target, configuration hash, and component hashes".into(),
        );
    }
    let required = [
        ("rust_toolchain_commit", trusted.rust_commit.as_str()),
        ("target", trusted.target.as_str()),
        ("toolchain_config_sha256", trusted.config_sha256.as_str()),
        ("cargo_sha256", trusted.cargo_sha256.as_str()),
        ("rustc_sha256", trusted.rustc_sha256.as_str()),
        ("rust_lld_sha256", trusted.rust_lld_sha256.as_str()),
    ];
    for (key, expected) in required {
        if values.get(key).map(String::as_str) != Some(expected) {
            return invalid_input(format!(
                "sysroot manifest `{key}` does not match the request"
            ));
        }
    }
    Ok(())
}

fn validate_git_commit(value: &str, label: &str) -> io::Result<String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid_input(format!("{label} must be a full 40-character Git revision"));
    }
    Ok(value.into())
}

fn required_revision(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    let value = required_string(values, key)?;
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid_input(format!("`{key}` must be a full 40-character Git revision"));
    }
    Ok(value)
}

fn required_sha256(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    let value = required_string(values, key)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid_input(format!("`{key}` must be a 64-character SHA-256 hex value"));
    }
    Ok(value)
}

fn validate_name(value: &str, kind: &str) -> io::Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return invalid_input(format!("invalid {kind} name `{value}`"));
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

fn invalid_input<T>(message: String) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn json_array(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|value| format!("\"{}\"", json_string(value)))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(","))
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32)
                    .expect("writing to String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn print_toolchain_diagnostics() -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Deepwyrm host tool availability")?;
    writeln!(
        stdout,
        "This report does not assert toolchain adoption or pinning."
    )?;
    for (name, program) in [
        ("cargo", "cargo"),
        ("rustc", "rustc"),
        ("clang", "clang"),
        ("clang++", "clang++"),
        ("ld.lld", "ld.lld"),
        ("llvm-ar", "llvm-ar"),
        ("llvm-readelf", "llvm-readelf"),
        ("llvm-objdump", "llvm-objdump"),
        ("llvm-objcopy", "llvm-objcopy"),
        ("llvm-symbolizer", "llvm-symbolizer"),
        ("llvm-nm", "llvm-nm"),
        ("gdb", "gdb"),
    ] {
        write!(stdout, "{name}: ")?;
        match Command::new(program).arg("--version").output() {
            Ok(output) if output.status.success() => {
                let version_output = String::from_utf8_lossy(&output.stdout);
                writeln!(
                    stdout,
                    "{}",
                    version_output.lines().next().unwrap_or("available")
                )?;
            }
            Ok(output) => writeln!(stdout, "unavailable (exit {})", output.status)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => writeln!(stdout, "not found")?,
            Err(error) => writeln!(stdout, "unavailable ({error})")?,
        }
    }
    Ok(0)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask manifest is nested under tools/xtask")
        .to_path_buf()
}

fn parse(args: &[String]) -> Action {
    let Some(command) = args.first().map(String::as_str) else {
        return Action::UsageError("a command is required".into());
    };
    if matches!(command, "help" | "-h" | "--help") {
        return parse_help(&args[1..]);
    }
    if !COMMANDS.contains(&command) {
        return Action::UsageError(format!("unknown command `{command}`"));
    }
    if args
        .get(1)
        .is_some_and(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        return if args.len() == 2 {
            Action::Help(Some(command.into()))
        } else {
            Action::UsageError(format!("unexpected arguments after `{command} --help`"))
        };
    }
    match command {
        "format" if args.len() == 1 => Action::Command(Invocation::Format),
        "check" if args.len() == 1 => Action::Command(Invocation::Check),
        "abi" => parse_abi(&args[1..]),
        "run" => parse_harness_command(HarnessKind::Run, &args[1..]),
        "gdb" => parse_harness_command(HarnessKind::Gdb, &args[1..]),
        "test" => parse_test(&args[1..]),
        "guest-result" => parse_guest_result(&args[1..]),
        "toolchain" if args.len() == 1 => Action::Toolchain,
        "build" | "image" | "inspect-image" if args.len() == 1 => {
            Action::NotImplemented(command.into())
        }
        _ => Action::UsageError(format!("`{command}` does not accept those arguments")),
    }
}

fn parse_abi(args: &[String]) -> Action {
    match args {
        [subcommand] if subcommand == "generate" => Action::Command(Invocation::AbiGenerate),
        [subcommand] if subcommand == "check" => Action::Command(Invocation::AbiCheck),
        [] => Action::UsageError("`abi` requires `generate` or `check`".into()),
        [subcommand] => Action::UsageError(format!(
            "unknown ABI operation `{subcommand}`; expected `generate` or `check`"
        )),
        _ => Action::UsageError("`abi` accepts exactly one operation".into()),
    }
}

fn parse_harness_command(kind: HarnessKind, args: &[String]) -> Action {
    match args {
        [plan, request_flag, request_path] if plan == "--plan" && request_flag == "--request" => {
            Action::Command(Invocation::HarnessPlan(kind, request_path.into(), None))
        }
        _ => Action::UsageError(format!(
            "`{}` requires `--plan --request <path>`; execution is unavailable",
            kind.request_kind()
        )),
    }
}

fn parse_test(args: &[String]) -> Action {
    let Some(tier) = args.first().map(String::as_str) else {
        return Action::UsageError("`test` requires one of: host, guest, integration".into());
    };
    if !TEST_TIERS.contains(&tier) {
        return Action::UsageError(format!(
            "unknown test tier `{tier}`; expected host, guest, or integration"
        ));
    }
    match tier {
        "host" if args.len() <= 2 => Action::Command(Invocation::HostTests(args.get(1).cloned())),
        "guest" => match args {
            [_, selector, plan, request_flag, request_path] if plan == "--plan" && request_flag == "--request" => {
                if let Err(error) = validate_selector(selector) { return Action::UsageError(error); }
                Action::Command(Invocation::HarnessPlan(HarnessKind::GuestTest, request_path.into(), Some(selector.into())))
            }
            _ => Action::UsageError("`test guest` requires `<selector> --plan --request <path>`; execution is unavailable".into()),
        },
        "integration" if args.len() <= 2 => Action::NotImplemented(display_test_command(tier, args.get(1).map(String::as_str))),
        "host" => Action::UsageError("`test host` accepts at most one filter".into()),
        _ => Action::UsageError("`test integration` accepts at most one filter".into()),
    }
}

fn parse_guest_result(args: &[String]) -> Action {
    match args {
        [
            serial_log,
            request_flag,
            request_path,
            exit_flag,
            exit_status,
        ] if request_flag == "--request" && exit_flag == "--exit-status" => match exit_status
            .parse()
        {
            Ok(exit_status) => Action::GuestResult {
                serial_log: serial_log.into(),
                request_path: request_path.into(),
                exit_status,
            },
            Err(_) => Action::UsageError("`guest-result --exit-status` must be an integer".into()),
        },
        _ => Action::UsageError(
            "`guest-result` requires `<serial-log> --request <path> --exit-status <code>`".into(),
        ),
    }
}

fn parse_help(args: &[String]) -> Action {
    match args {
        [] => Action::Help(None),
        [command] if COMMANDS.contains(&command.as_str()) => Action::Help(Some(command.clone())),
        [command] => Action::UsageError(format!("unknown help topic `{command}`")),
        _ => Action::UsageError("help accepts at most one command".into()),
    }
}

fn display_test_command(tier: &str, filter: Option<&str>) -> String {
    filter.map_or_else(
        || format!("test {tier}"),
        |filter| format!("test {tier} {filter}"),
    )
}

fn print_help(mut writer: impl Write, command: Option<&str>) -> io::Result<()> {
    match command {
        None => writer.write_all(HELP.as_bytes()),
        Some("abi") => write!(
            writer,
            "Usage: cargo xtask abi <generate|check>\n\n`generate` updates generator-owned artifacts; `check` rejects ABI drift.\n"
        ),
        Some("test") => write!(
            writer,
            "Usage: cargo xtask test <host|guest|integration> ...\n\n`test guest` emits a plan only; guest execution remains coordinator-owned.\n"
        ),
        Some(command @ ("run" | "gdb")) => write!(
            writer,
            "Usage: cargo xtask {command} --plan --request <path>\n\nThis emits commands and evidence contracts; it never launches QEMU.\n"
        ),
        Some("guest-result") => write!(
            writer,
            "Usage: cargo xtask guest-result <serial-log> --request <path> --exit-status <code>\n\nClassifies one fixed-width DWTEST1 terminal record against the observed QEMU exit status. It does not prove capture freshness.\n"
        ),
        Some(command @ ("format" | "check" | "toolchain")) => write!(
            writer,
            "Usage: cargo xtask {command}\n\nStatus: available host tooling.\n"
        ),
        Some(command) => write!(
            writer,
            "Usage: cargo xtask {command}\n\nStatus: planned but not implemented. Invoking this operation exits nonzero.\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
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
    fn dw0a_and_dw0b_commands_have_explicit_actions() {
        for (args, expected) in [
            (&["format"][..], Action::Command(Invocation::Format)),
            (&["check"][..], Action::Command(Invocation::Check)),
            (&["abi", "check"][..], Action::Command(Invocation::AbiCheck)),
            (
                &["test", "host", "abi"][..],
                Action::Command(Invocation::HostTests(Some("abi".into()))),
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
        ] {
            assert_eq!(parse(&strings(args)), expected);
        }
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
        let request =
            load_harness_request(&temp_file(&request("guest-test", "arch.entry"))).unwrap();
        let profile = HarnessProfile {
            name: "default".into(),
            machine: "q35".into(),
            vcpu: 1,
            memory_mib: 1024,
            timeout_seconds: 120,
            gdb_port: 1234,
        };
        let args = qemu_arguments(&profile, &request, HarnessKind::GuestTest).join(" ");
        assert!(args.contains("if=virtio,format=raw,readonly=on,file=images/wyrmroot-esp.img"));
        assert!(args.contains("file:artifacts/dw0-b/serial.log"));
        assert!(args.contains("opt/org.deepwyrm.test.selector,string=arch.entry"));
        assert!(args.contains("isa-debug-exit,iobase=0xf4,iosize=0x04"));
        assert!(!args.contains("virtfs"));
        let run_args = qemu_arguments(&profile, &request, HarnessKind::Run).join(" ");
        let gdb_args = qemu_arguments(&profile, &request, HarnessKind::Gdb).join(" ");
        assert!(!run_args.contains("isa-debug-exit"));
        assert!(!gdb_args.contains("isa-debug-exit"));
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

        fs::remove_file(serial_path).unwrap();
        fs::remove_file(request_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn hostile_reads_are_bounded() {
        let oversized = temp_path("bin");
        fs::write(&oversized, vec![b'x'; MAX_REQUEST_BYTES + 1]).unwrap();
        assert!(read_bounded(&oversized, "request", MAX_REQUEST_BYTES).is_err());
        fs::remove_file(oversized).unwrap();
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
            let contents =
                request("guest-test", "arch.entry").replace("images/wyrmroot-esp.img", path);
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
        let trusted =
            load_trusted_toolchain(&workspace_root().join(TRUSTED_TOOLCHAIN_CONFIG)).unwrap();
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
        let trusted =
            load_trusted_toolchain(&workspace_root().join(TRUSTED_TOOLCHAIN_CONFIG)).unwrap();
        let missing_schema = temp_file("rust_toolchain_commit = \"not-a-contract\"\n");
        let mut fixture = trusted.clone();
        fixture.sysroot_manifest_path = missing_schema.clone();
        assert!(validate_sysroot_manifest(&fixture).is_err());
        fs::remove_file(missing_schema).unwrap();

        let valid = temp_file(&format!(
            "schema = \"deepwyrm-rust-sysroot-manifest-v1\"\nrust_toolchain_commit = \"{}\"\ntarget = \"{}\"\ntoolchain_config_sha256 = \"{}\"\ncargo_sha256 = \"{}\"\nrustc_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\n",
            trusted.rust_commit,
            trusted.target,
            trusted.config_sha256,
            trusted.cargo_sha256,
            trusted.rustc_sha256,
            trusted.rust_lld_sha256,
        ));
        fixture.sysroot_manifest_path = valid.clone();
        validate_sysroot_manifest(&fixture).unwrap();
        fs::remove_file(valid).unwrap();
    }

    fn terminal(status: &str, test_id: u32, detail: u32) -> Vec<u8> {
        let mut record = format!("DWTEST1|{status}|{test_id:08X}|{detail:08X}|").into_bytes();
        record.extend_from_slice(format!("{:08X}\n", fnv1a32(&record)).as_bytes());
        record
    }
}
