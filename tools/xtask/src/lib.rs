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
    "arch::x86_64::syscall::tests::",
    "arch::x86_64::exceptions::tests::",
    "memory::user_range::tests::",
    "memory::usercopy::tests::",
    "syscall::abi_bytes::tests::",
    "syscall::adapters::tests::",
    "syscall::native::tests::",
    "service::tests::e_task_state_query_reuses_inspect_gated_service_lookup",
    "object::finalizer::tests::",
    "object::finalizer::memory_route_tests::",
    "memory::vm::object::tests::production_binding_consumes_creation_before_first_publication",
    "root_region_handle_close_preserves_address_space_until_process_exit",
];
const TASK_HOST_INTEGRATION_TESTS: &[&str] = &[
    "object_registry_ui",
    "memory_authority_ui",
    "task_authority_ui",
    "x86_64_activation_contract",
    "x86_64_entry_contract",
    "x86_64_syscall_contract",
    "x86_64_exception_contract",
    "x86_64_memory_guest_contract",
];
const IPC_HOST_TEST_FILTERS: &[&str] = &[
    "handle::table::tests::",
    "handle::model_tests::",
    "ipc::tests::",
    "wait::tests::",
    "wait::engine::tests::",
    "wait::operation::tests::",
    "time::deadline::tests::",
    "time::pm_timer::tests::",
    "time::timer::tests::",
    "atomic_wait::tests::",
    "task::blocked_operation::tests::",
    "task::scheduler::tests::",
    "task::execution::tests::",
    "object::finalizer::tests::channel_",
    "object::finalizer::tests::armed_timer_",
    "syscall::abi_bytes::tests::f1_",
    "syscall::adapters::tests::event_",
    "syscall::adapters::tests::channel_",
    "syscall::adapters::tests::timer_",
    "syscall::adapters::tests::wait_",
    "syscall::adapters::tests::public_finite_wait_",
    "syscall::adapters::tests::public_timer_wait_",
    "syscall::adapters::tests::public_wait_",
    "syscall::adapters::tests::native_timer_",
    "syscall::adapters::tests::native_wait_",
    "syscall::adapters::tests::native_process_create_",
    "syscall::adapters::tests::process_create_",
];
const IPC_HOST_INTEGRATION_TESTS: &[&str] = &[
    "object_registry_ui",
    "task_authority_ui",
    "x86_64_syscall_contract",
    "f11_ipc_ui",
    "f11_ownership_model",
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
  test host [abi|memory|handles|tasks|ipc]
                                     Run focused host tests
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
    Ipc,
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
    config_path: PathBuf,
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
    llvm_nm_binary: String,
    llvm_nm_sha256: String,
    llvm_objdump_binary: String,
    llvm_objdump_sha256: String,
    llvm_readelf_binary: String,
    llvm_readelf_sha256: String,
    system_tar_binary: String,
    system_tar_sha256: String,
    system_sha256sum_binary: String,
    system_sha256sum_sha256: String,
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
            let selectors = run_selector_library_checks()?;
            if selectors != 0 {
                return Ok(selectors);
            }
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
                Some(HostTestFilter::Ipc) => {
                    return run_ipc_host_tests();
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

/// The compile-time environment a selector needs before it will build at all.
///
/// `kernel/build.rs` refuses a selector whose nonce, digest or page ceiling is
/// absent, so a row here is what makes that selector compilable. The values are
/// placeholders: this gate compiles and never links, boots or records, so any
/// well-formed value answers the only question it asks. Real runs supply real
/// ones. A selector absent from this table is built with no extra environment,
/// and if it turns out to need some, this gate fails and names it -- which is
/// the correct outcome, not a gap.
const SELECTOR_ENVIRONMENTS: [(&str, &[(&str, &str)]); 12] = [
    (
        "smp-runtime-acceptance",
        &[("DEEPWYRM_I1_EVIDENCE_NONCE", "0000000000000001")],
    ),
    (
        "permanent-supervisor-rrc",
        &[
            ("DEEPWYRM_WYR1_EVIDENCE_NONCE", "0000000000000001"),
            ("DEEPWYRM_WYR1_EVIDENCE_SCENARIO", "normal"),
        ],
    ),
    (
        "normal-preemption-up",
        &[
            ("DEEPWYRM_DW1B_EVIDENCE_NONCE", "0000000000000001"),
            ("DEEPWYRM_DW1B_CHALLENGE_DIGEST", "0000000000000001"),
            ("DEEPWYRM_DW1B_BOOTFS_MAX_PAGES", "31"),
        ],
    ),
    (
        "bootstrap-registry-launch",
        &[
            ("DEEPWYRM_WYR1B_EVIDENCE_NONCE", "0000000000000001"),
            ("DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES", "117"),
        ],
    ),
    (
        "normal-preemption-smp",
        &[
            ("DEEPWYRM_DW1C_EVIDENCE_NONCE", "0000000000000001"),
            ("DEEPWYRM_DW1C_PROGRESS_DIGEST", "0000000000000001"),
            ("DEEPWYRM_DW1C_BOOTFS_MAX_PAGES", "53"),
        ],
    ),
    (
        "device-resource-interrupt-synthetic",
        &[
            ("DEEPWYRM_DW1D_EVIDENCE_NONCE", "0000000000000001"),
            ("DEEPWYRM_DW1D_EVIDENCE_CHALLENGE", "0000000000000001"),
        ],
    ),
    (
        "device-coordinator-restart",
        &[("DEEPWYRM_WYR1C_EVIDENCE_NONCE", "0000000000000001")],
    ),
    (
        "native-console-streams",
        &[("DEEPWYRM_WYR1D_EVIDENCE_NONCE", "0000000000000001")],
    ),
    (
        "interactive-wyrmsh",
        &[("DEEPWYRM_WYR1E7_EVIDENCE_NONCE", "0000000000000001")],
    ),
    (
        "q35-com2-interrupt",
        &[("DEEPWYRM_DW1E_EVIDENCE_NONCE", "0000000000000001")],
    ),
    (
        "dynamic-launch-saturation",
        &[
            ("DEEPWYRM_R1_EVIDENCE_NONCE", "0000000000000001"),
            ("DEEPWYRM_R1_BOOTFS_MAX_PAGES", "145"),
        ],
    ),
    // DW1-F/WYR1-F's final closure selector reuses `interactive-wyrmsh`'s WRE1
    // transport, so it takes the same evidence-nonce variable. The E8 variant
    // of that transport belongs to selector 33 alone.
    (
        "dw1-wyr1-interactive-closure",
        &[("DEEPWYRM_WYR1E7_EVIDENCE_NONCE", "0000000000000001")],
    ),
];

/// The E8 evidence surface: a second configuration of one selector rather than
/// a selector of its own, so the manifest does not list it separately.
/// The no-selector production kernel. `None` means the selector environment
/// variable is removed rather than set, which is the shape a product build of
/// the uninstrumented kernel actually has.
const PRODUCTION_KERNEL_ROW: (Option<&str>, &[(&str, &str)]) = (None, &[]);

const WYR1E8_SELECTOR: (&str, &[(&str, &str)]) = (
    "interactive-wyrmsh",
    &[
        ("DEEPWYRM_WYR1E8_EVIDENCE", "1"),
        ("DEEPWYRM_WYR1E8_EVIDENCE_NONCE", "E800000000000001"),
    ],
);

/// Reads the implemented guest selectors from the harness manifest.
///
/// Derived rather than listed, so a selector added to the manifest joins this
/// gate without anyone remembering to add it here -- the drift this gate exists
/// to catch is exactly the drift a second hand-maintained list would
/// reintroduce. `reserved` entries are skipped: they have no implementation to
/// compile, and `build.rs` refuses them by name.
fn implemented_guest_selectors(manifest: &str) -> Vec<String> {
    let mut selectors = Vec::new();
    let mut current = None;
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("[guest_test.") {
            current = rest.strip_suffix(']').map(str::to_owned);
        } else if line == "state = \"implemented\"" {
            if let Some(selector) = current.take() {
                selectors.push(selector);
            }
        } else if line.starts_with('[') {
            current = None;
        }
    }
    selectors
}

/// Compiles every implemented selector's kernel library.
///
/// Selector-gated code is `target_os = "none"`, so `check`'s host workspace
/// pass has never compiled any of it -- only the product paths that mint VM
/// images do. That is how R5D's rename survived with two stale call sites in
/// `ipc-blocking-smoke`, and it is the same shape as the two Wyrmroot selectors
/// that broke the same week. Running here means no selector's compilability
/// depends on anyone remembering its name.
///
/// This re-enters `tools/pinned-cargo` on the target lane rather than calling
/// Cargo directly, because only that lane verifies the accepted toolchain and
/// exports the freestanding linker a target build needs. `CARGO_HOME` is
/// cleared because the lane owns it and refuses to be handed one.
fn run_selector_library_checks() -> io::Result<u8> {
    let workspace = workspace_root();
    let lane = workspace.join("tools/pinned-cargo");
    let manifest = fs::read_to_string(workspace.join("tooling/guest-harness.toml"))?;
    let selectors = implemented_guest_selectors(&manifest);
    if selectors.is_empty() {
        let mut stderr = io::stderr().lock();
        writeln!(
            stderr,
            "error: the guest harness manifest lists no implemented selectors"
        )?;
        return Ok(EXIT_NOT_IMPLEMENTED);
    }
    let rows = selectors
        .iter()
        .map(|selector| {
            let environment = SELECTOR_ENVIRONMENTS
                .iter()
                .find(|(name, _)| name == selector)
                .map_or(&[][..], |(_, environment)| environment);
            (selector.as_str(), environment)
        })
        .chain(core::iter::once(WYR1E8_SELECTOR));
    // The production kernel is the shape no selector selects, and until
    // DW1-F/WYR1-F F1A.2 nothing ever compiled it on the target lane: every row
    // above sets `DEEPWYRM_GUEST_TEST_SELECTOR`. That gap is how the q35 IOAPIC
    // bring-up stayed reachable only under three selector strings without
    // anything noticing -- an uninstrumented kernel compiled fine, it just had
    // no interrupt-driven console. Check it first, because a production break
    // matters more than a selector break.
    let rows = core::iter::once(PRODUCTION_KERNEL_ROW).chain(rows.map(|(s, e)| (Some(s), e)));
    for (selector, environment) in rows {
        let mut command = Command::new(&lane);
        command.current_dir(&workspace).env_remove("CARGO_HOME");
        match selector {
            Some(selector) => {
                command.env("DEEPWYRM_GUEST_TEST_SELECTOR", selector);
            }
            None => {
                command.env_remove("DEEPWYRM_GUEST_TEST_SELECTOR");
            }
        }
        for (name, value) in environment {
            command.env(name, value);
        }
        let mut arguments = vec![
            "target",
            "check",
            "--locked",
            "--package",
            "deepwyrm-kernel",
            "--lib",
            "--target",
            "x86_64-unknown-none",
        ];
        // `test-support` is what a selector build needs; the production row is
        // checked without it, so this also proves the production kernel does
        // not depend on the test-support surface to compile.
        if selector.is_some() {
            arguments.extend(["--features", "test-support"]);
        }
        let status = command.args(arguments).status()?;
        if !status.success() {
            let mut stderr = io::stderr().lock();
            match selector {
                Some(selector) => writeln!(stderr, "error: selector {selector} does not compile")?,
                None => writeln!(stderr, "error: the production kernel does not compile")?,
            }
            return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
        }
    }
    Ok(0)
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

fn run_ipc_host_tests() -> io::Result<u8> {
    let temporary_state = workspace_root()
        .join(".tmp")
        .join("xtask-host-ipc")
        .join(std::process::id().to_string());
    let target_dir = temporary_state.join("target");
    fs::create_dir_all(&temporary_state)?;

    for filter in IPC_HOST_TEST_FILTERS {
        let status = Command::new("cargo")
            .current_dir(workspace_root())
            .env("TMPDIR", &temporary_state)
            .env("CARGO_TARGET_DIR", &target_dir)
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
    for integration_test in IPC_HOST_INTEGRATION_TESTS {
        let status = Command::new("cargo")
            .current_dir(workspace_root())
            .env("TMPDIR", &temporary_state)
            .env("CARGO_TARGET_DIR", &target_dir)
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
