use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

mod cli;
mod harness;
mod toolchain;

use cli::*;
use harness::*;
use toolchain::*;

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
const HANDLE_HOST_TEST_FILTERS: &[&str] = &[
    "handle::",
    "service::",
    "object::tests::",
    "memory::vm::object::tests::",
    "memory::vm::address_region::tests::",
];
const HANDLE_HOST_INTEGRATION_TESTS: &[&str] = &[
    "object_registry_ui",
    "memory_authority_ui",
    "physical_ownership_ui",
];
const TASK_HOST_TEST_FILTERS: &[&str] = &[
    "sync::tests::",
    "task::tests::",
    "task::scheduler::tests::",
    "task::execution::tests::",
    "object::finalizer::tests::",
    "object::finalizer::memory_route_tests::",
    "root_region_handle_close_preserves_address_space_until_process_exit",
];
const TASK_HOST_INTEGRATION_TESTS: &[&str] = &[
    "task_authority_ui",
    "x86_64_activation_contract",
    "x86_64_entry_contract",
    "x86_64_memory_guest_contract",
];
const HARNESS_CONFIG: &str = "tooling/guest-harness.toml";
const TRUSTED_TOOLCHAIN_CONFIG: &str = "tooling/rust-toolchain.toml";
const BUILD_TOOLS_CONFIG: &str = "tooling/build-tools.toml";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_SERIAL_BYTES: usize = 4 * 1024 * 1024;
const HELP: &str = r#"Deepwyrm project tasks

Status: host tooling plus DW0-B/C/D6 focused test and dry-run planning surfaces are available.
Build, image, and integration operations remain planned and are not implemented.

Usage:
  cargo xtask <command>

Commands:
  format                             Verify Rust formatting
  check                              Run the workspace check
  abi generate                       Generate ABI-owned artifacts
  abi check                          Verify generated ABI artifacts have no drift
  test host [abi|memory|handles|tasks] Run focused host tests
  run --plan --request <path>        Emit the canonical QEMU run plan only
  gdb --plan --request <path>        Emit paused QEMU/GDB command plans only
  test guest <selector> --plan --request <path>
                                     Emit a filtered guest-test plan only
  guest-result <serial-log> --request <path> --exit-status <code>
                                     Classify one DWTEST1 terminal record and QEMU exit
  toolchain                          Report host tool availability
  toolchain verify-build-tools --root <path> --clang-config <path>
                                     Verify accepted host Clang/LLVM identities
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
    VerifyBuildTools {
        root: PathBuf,
        clang_config: PathBuf,
    },
    NotImplemented(String),
    UsageError(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Invocation {
    Format,
    Check,
    AbiGenerate,
    AbiCheck,
    HostTests(Option<HostTestFilter>),
    HarnessPlan(HarnessKind, PathBuf, Option<String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostTestFilter {
    Abi,
    Memory,
    Handles,
    Tasks,
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
struct GuestBuildSelection {
    selector: String,
    expected_test_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedToolchain {
    request_id: String,
    rust_commit: String,
    target: String,
    config_sha256: String,
    artifact_root: PathBuf,
    toolchain_root: PathBuf,
    toolchain_tree_sha256: String,
    root_manifest_path: PathBuf,
    root_manifest_sha256: String,
    cargo_path: PathBuf,
    cargo_sha256: String,
    rustc_path: PathBuf,
    rustc_sha256: String,
    rust_lld_path: PathBuf,
    rust_lld_sha256: String,
    rustc_driver_internal_library: TrustedArtifact,
    llvm_internal_library: TrustedArtifact,
    sysroot_manifest_path: PathBuf,
    sysroot_manifest_sha256: String,
    freestanding_core: Option<TrustedArtifact>,
    freestanding_compiler_builtins: Option<TrustedArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedArtifact {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuildToolsIdentity {
    clang_version: String,
    clang_binary: String,
    clang_sha256: String,
    libclang_cpp: String,
    libclang_cpp_sha256: String,
    host_llvm: String,
    host_llvm_sha256: String,
    clang_config_sha256: String,
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
        Action::VerifyBuildTools { root, clang_config } => verify_build_tools(&root, &clang_config),
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
            match filter {
                Some(HostTestFilter::Abi) => {
                    command.args(["--package", "abi-gen", "--package", "deepwyrm-abi"]);
                }
                Some(HostTestFilter::Memory) => {
                    command.args(["--package", "deepwyrm-kernel", "--lib", "--tests"]);
                }
                Some(HostTestFilter::Handles) => {
                    return run_handle_host_tests();
                }
                Some(HostTestFilter::Tasks) => {
                    return run_task_host_tests();
                }
                None => {
                    command.args(["--workspace", "--all-targets"]);
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

fn run_handle_host_tests() -> io::Result<u8> {
    for filter in HANDLE_HOST_TEST_FILTERS {
        let status = Command::new("cargo")
            .current_dir(workspace_root())
            .args([
                "test",
                "--locked",
                "--package",
                "deepwyrm-kernel",
                "--lib",
                filter,
            ])
            .status()?;
        if !status.success() {
            return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
        }
    }
    for integration_test in HANDLE_HOST_INTEGRATION_TESTS {
        let status = Command::new("cargo")
            .current_dir(workspace_root())
            .args([
                "test",
                "--locked",
                "--package",
                "deepwyrm-kernel",
                "--test",
                integration_test,
            ])
            .status()?;
        if !status.success() {
            return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
        }
    }
    Ok(0)
}

fn run_task_host_tests() -> io::Result<u8> {
    for filter in TASK_HOST_TEST_FILTERS {
        let status = Command::new("cargo")
            .current_dir(workspace_root())
            .args([
                "test",
                "--locked",
                "--package",
                "deepwyrm-kernel",
                "--lib",
                filter,
            ])
            .status()?;
        if !status.success() {
            return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
        }
    }
    for integration_test in TASK_HOST_INTEGRATION_TESTS {
        let status = Command::new("cargo")
            .current_dir(workspace_root())
            .args([
                "test",
                "--locked",
                "--package",
                "deepwyrm-kernel",
                "--test",
                integration_test,
            ])
            .status()?;
        if !status.success() {
            return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
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

#[cfg(test)]
mod tests;
