use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod cli;
mod kernel_check;
mod lint_ratchet;
mod toolchain;

use cli::*;
use lint_ratchet::*;
use toolchain::*;

pub const EXIT_NOT_IMPLEMENTED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;

const COMMANDS: &[&str] = &[
    "format",
    "check",
    "clippy",
    "doc",
    "kernel-check",
    "abi",
    "build",
    "image",
    "inspect-image",
    "test",
    "toolchain",
];
const TEST_TIERS: &[&str] = &["host", "integration"];
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
    "x86_64_entry_contract",
    "x86_64_syscall_contract",
    "x86_64_exception_contract",
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
const HELP: &str = r#"Deepwyrm project tasks

Status: host tooling and focused host test surfaces are available.
Build, image, and integration operations remain planned and are not implemented.

Usage:
  cargo xtask <command>

Commands:
  format                             Verify Rust formatting
  check                              Run the workspace check
  clippy                             Warnings-denied Clippy: production kernel, then host
                                     workspace, then the lint ratchet
  doc                                Warnings-denied rustdoc over the workspace
  kernel-check                       Production kernel image checks and the static
                                     stack bound (DW2 plan §10.2)
  abi generate                       Generate ABI-owned artifacts
  abi check                          Verify generated ABI artifacts have no drift
  test host [abi|memory|handles|tasks|ipc]
                                     Run host tests: unfiltered is the workspace
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
    Toolchain,
    NotImplemented(String),
    UsageError(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Invocation {
    Format,
    Check,
    Clippy,
    Rustdoc,
    KernelCheck,
    AbiGenerate,
    AbiCheck,
    HostTests(Option<HostTestFilter>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostTestFilter {
    Abi,
    Memory,
    Handles,
    Tasks,
    Ipc,
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

/// `tools/pinned-cargo host`, run from the workspace root. `CARGO_HOME` is
/// cleared, as for the target lane: the lane selects its own and refuses one
/// supplied, which it is when xtask itself runs under `pinned-cargo host`.
pub(crate) fn pinned_host_cargo() -> Command {
    let workspace = workspace_root();
    let mut command = Command::new(workspace.join("tools/pinned-cargo"));
    command
        .current_dir(&workspace)
        .env_remove("CARGO_HOME")
        .arg("host");
    command
}

fn run_invocation(invocation: Invocation) -> io::Result<u8> {
    let mut command = Command::new("cargo");
    command.current_dir(workspace_root());

    match invocation {
        Invocation::Format => {
            command.args(["fmt", "--all", "--", "--check"]);
        }
        Invocation::Check => {
            let production = run_production_library_check()?;
            if production != 0 {
                return Ok(production);
            }
            command.args(["check", "--locked", "--workspace", "--all-targets"]);
        }
        Invocation::Clippy => {
            // The production kernel is gated in the shape it ships in --
            // freestanding target -- before the host workspace, for the same
            // reason `check` orders its rows that way. DW1-F/WYR1-F F2A found two dead surfaces that only this row
            // can see: the IOAPIC redirection decode instruments and a pair of
            // pre-WYR1-C syscall adapter re-exports.
            let production = run_production_kernel_warning_gate()?;
            if production != 0 {
                return Ok(production);
            }
            // Through the pinned host lane, never the host's own Cargo, whose
            // newer Clippy fails on deprecations the pinned toolchain does not
            // have. The lane refuses `--all-targets`; libraries and tests are
            // every target the ratchet baseline counts.
            let status = pinned_host_cargo()
                .args([
                    "clippy",
                    "--locked",
                    "--workspace",
                    "--lib",
                    "--tests",
                    "--",
                    "-D",
                    "warnings",
                ])
                .status()?;
            if !status.success() {
                return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
            }
            // Warn-level lints whose counts may only fall (S1.3); see
            // `lint_ratchet.rs` and `tooling/lint-ratchet.txt`.
            return run_lint_ratchet();
        }
        Invocation::KernelCheck => return kernel_check::run_kernel_check(),
        Invocation::Rustdoc => {
            command.env("RUSTDOCFLAGS", "-D warnings");
            command.args(["doc", "--locked", "--workspace", "--no-deps"]);
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
    };

    let status = command.status()?;
    Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8)
}

/// Compiles the production kernel's library on the target lane.
///
/// Until DW1-F/WYR1-F F1A.2 nothing ever compiled the production kernel on
/// the target lane, and that gap is how the q35 IOAPIC bring-up stayed
/// reachable only in instrumented builds without anything noticing -- an
/// uninstrumented kernel compiled fine, it just had no interrupt-driven
/// console. The host workspace check that follows never compiles the
/// `target_os = "none"` code.
///
/// This re-enters `tools/pinned-cargo` on the target lane rather than calling
/// Cargo directly, because only that lane verifies the accepted toolchain and
/// exports the freestanding linker a target build needs. `CARGO_HOME` is
/// cleared because the lane owns it and refuses to be handed one.
fn run_production_library_check() -> io::Result<u8> {
    let workspace = workspace_root();
    let status = Command::new(workspace.join("tools/pinned-cargo"))
        .current_dir(&workspace)
        .env_remove("CARGO_HOME")
        .args([
            "target",
            "check",
            "--locked",
            "--package",
            "deepwyrm-kernel",
            "--lib",
            "--target",
            "x86_64-unknown-none",
        ])
        .status()?;
    if !status.success() {
        let mut stderr = io::stderr().lock();
        writeln!(stderr, "error: the production kernel does not compile")?;
        return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
    }
    Ok(0)
}

/// Warnings-denied rustc over the production kernel: the build
/// `run_production_library_check` checks, on the target lane.
///
/// Not Clippy. The accepted Wyrmroot toolchain ships `cargo` and `rustc` only
/// (`tooling/rust-toolchain.toml`), so there is no `clippy-driver` that can see
/// the freestanding sysroot, and substituting the host lane's newer driver
/// would lint a different compiler's view of the code. `-D warnings` on the
/// accepted compiler is the strongest gate this shape can actually have, and
/// it is the one that matters: the surfaces F2A found dead here -- the IOAPIC
/// redirection decode instruments and two pre-WYR1-C syscall adapter
/// re-exports -- are ordinary rustc `dead_code`/`unused_imports` findings that
/// no other row in the tree denies.
fn run_production_kernel_warning_gate() -> io::Result<u8> {
    let workspace = workspace_root();
    let status = Command::new(workspace.join("tools/pinned-cargo"))
        .current_dir(&workspace)
        .env_remove("CARGO_HOME")
        .args([
            "target",
            "rustc",
            "--locked",
            "--package",
            "deepwyrm-kernel",
            "--lib",
            "--target",
            "x86_64-unknown-none",
            "--",
            "-D",
            "warnings",
        ])
        .status()?;
    if !status.success() {
        let mut stderr = io::stderr().lock();
        writeln!(
            stderr,
            "error: the production kernel does not compile warning-free"
        )?;
        return Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
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
