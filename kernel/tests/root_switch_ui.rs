//! Compile-fail cases for the primordial carrier's root-switch transactions
//! (`src/arch/x86_64/mm/activation/root_switch.rs`, S2K-2).
//!
//! They replace the source-text test that pinned the prepare/execute/commit
//! order at each call site: once a `Prepared*` value is consumed by its one
//! execution and only that execution can produce the `Executed*` value a
//! commit takes (or the `Failed*` value a cancel takes), the order is a type
//! fact at every call site, present and future.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct UiCase<'a> {
    fixture: &'a str,
    /// `None` for the control case, which must compile.
    expected_error: Option<&'a str>,
}

#[test]
fn root_switch_transactions_are_move_only_and_unforgeable() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("kernel is nested below the workspace root");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output_dir = workspace_dir
        .join(".tmp")
        .join("root-switch-ui")
        .join(std::process::id().to_string());
    fs::create_dir_all(&output_dir).expect("create project-local root-switch UI output directory");

    for case in [
        UiCase {
            fixture: "root_switch_compiles.rs",
            expected_error: None,
        },
        UiCase {
            fixture: "root_switch_prepared_reuse.rs",
            expected_error: Some("error[E0382]: use of moved value: `prepared`"),
        },
        UiCase {
            fixture: "root_switch_prepared_clone.rs",
            expected_error: Some(
                "error[E0277]: the trait bound `PreparedSchedulerRootSwitch: Clone` is not satisfied",
            ),
        },
        UiCase {
            fixture: "root_switch_executed_forge.rs",
            expected_error: Some(
                "error[E0451]: field `executed` of struct `ExecutedStopRootSwitch` is private",
            ),
        },
        UiCase {
            fixture: "root_switch_failed_forge.rs",
            expected_error: Some(
                "error[E0451]: fields `error` and `previous` of struct `FailedStopRootSwitch` are private",
            ),
        },
        // S2K-3: a CR3 switch takes a guard-free token, which a locked handle cannot mint.
        UiCase {
            fixture: "root_switch_execute_under_guard.rs",
            expected_error: Some(
                "error[E0499]: cannot borrow `*handle` as mutable more than once at a time",
            ),
        },
    ] {
        run_case(&rustc, &manifest_dir, &output_dir, &case);
    }

    fs::remove_dir_all(&output_dir)
        .expect("remove exact project-local root-switch UI output directory");
}

/// S2K-3: the guard-free token is a borrow-checker fact. A CPU locks only
/// through its one handle, a guard borrows that handle, and only the handle
/// (or `unsafe`) mints a token, so no physical boundary that takes one can run
/// under the runtime authority guard.
#[test]
fn guard_free_tokens_cannot_be_minted_under_the_runtime_guard() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("kernel is nested below the workspace root");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output_dir = workspace_dir
        .join(".tmp")
        .join("guard-free-ui")
        .join(std::process::id().to_string());
    fs::create_dir_all(&output_dir).expect("create project-local guard-free UI output directory");

    for case in [
        UiCase {
            fixture: "guard_free_compiles.rs",
            expected_error: None,
        },
        UiCase {
            fixture: "guard_free_while_locked.rs",
            expected_error: Some(
                "error[E0499]: cannot borrow `handle` as mutable more than once at a time",
            ),
        },
        UiCase {
            fixture: "guard_free_forged.rs",
            expected_error: Some(
                "error[E0133]: call to unsafe function `GuardFree::<'_>::assume` is unsafe and requires unsafe block",
            ),
        },
        // S2K-6: the interrupt-context handle has no `guard_free`.
        UiCase {
            fixture: "guard_free_from_interrupt_handle.rs",
            expected_error: Some(
                "error[E0599]: no method named `guard_free` found for struct `InterruptAuthorityHandle<'a, T>` in the current scope",
            ),
        },
        UiCase {
            fixture: "runtime_authority_lock_private.rs",
            expected_error: Some("error[E0624]: method `lock` is private"),
        },
        UiCase {
            fixture: "runtime_authority_handle_clone.rs",
            expected_error: Some(
                "error[E0277]: the trait bound `RuntimeAuthorityHandle<'_, u32>: Clone` is not satisfied",
            ),
        },
    ] {
        run_case(&rustc, &manifest_dir, &output_dir, &case);
    }

    fs::remove_dir_all(&output_dir)
        .expect("remove exact project-local guard-free UI output directory");
}

/// S2K-6 (design §11.1; TSV rows 72 and 96): a CPU's remotely read runtime
/// facts (its deferred current, wait control, root and identity) live in
/// `CpuSlots`, which hands a slot out mutably only for that slot's
/// `CpuOwner`. Owners are minted once, cannot be forged or cloned, and every
/// other CPU's slot is read-only, so owner-only mutation is a type fact.
#[test]
fn cpu_slots_mutate_only_through_their_owner() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("kernel is nested below the workspace root");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output_dir = workspace_dir
        .join(".tmp")
        .join("cpu-slots-ui")
        .join(std::process::id().to_string());
    fs::create_dir_all(&output_dir).expect("create project-local CPU-slot UI output directory");

    for case in [
        UiCase {
            fixture: "cpu_slots_compiles.rs",
            expected_error: None,
        },
        UiCase {
            fixture: "cpu_slots_remote_mutation.rs",
            expected_error: Some("error[E0594]: cannot assign to data in a `&` reference"),
        },
        UiCase {
            fixture: "cpu_slots_owner_forged.rs",
            expected_error: Some("error[E0451]: field `cpu` of struct `CpuOwner` is private"),
        },
        UiCase {
            fixture: "cpu_slots_owner_clone.rs",
            expected_error: Some(
                "error[E0599]: no method named `clone` found for struct `CpuOwner` in the current scope",
            ),
        },
    ] {
        run_case(&rustc, &manifest_dir, &output_dir, &case);
    }

    fs::remove_dir_all(&output_dir)
        .expect("remove exact project-local CPU-slot UI output directory");
}

fn run_case(rustc: &std::ffi::OsStr, manifest_dir: &Path, output_dir: &Path, case: &UiCase<'_>) {
    run_case_with(rustc, manifest_dir, output_dir, case, &[]);
}

/// Target-only items: `--cfg target_os="none"` makes rustc type-check the
/// `target_os = "none"` items of the included kernel sources on the host.
/// Only metadata is emitted, so nothing target-specific is generated or run.
const TARGET_ONLY_CFG: [&str; 4] = [
    "--cfg",
    "target_os=\"none\"",
    "-A",
    "explicit_builtin_cfgs_in_flags",
];

fn run_case_with(
    rustc: &std::ffi::OsStr,
    manifest_dir: &Path,
    output_dir: &Path,
    case: &UiCase<'_>,
    extra: &[&str],
) {
    let fixture = manifest_dir.join("tests/ui").join(case.fixture);
    let crate_name = case.fixture.trim_end_matches(".rs");
    let output = Command::new(rustc)
        .args(extra)
        .arg("--edition=2024")
        .arg("--crate-type=lib")
        .arg("--emit=metadata")
        .arg("--deny=unsafe-code")
        .arg("--crate-name")
        .arg(crate_name)
        .arg("--out-dir")
        .arg(output_dir)
        .env("TMPDIR", output_dir)
        .arg(&fixture)
        .output()
        .unwrap_or_else(|error| {
            panic!("failed to execute rustc for {}: {error}", fixture.display())
        });
    let stderr = String::from_utf8_lossy(&output.stderr);
    let Some(expected_error) = case.expected_error else {
        assert!(
            output.status.success(),
            "{} must compile; the stand-in context drifted:\n{stderr}",
            fixture.display()
        );
        return;
    };
    assert!(
        !output.status.success(),
        "{} unexpectedly compiled; a root-switch transaction became copyable or forgeable",
        fixture.display()
    );
    let first_error = stderr
        .lines()
        .find(|line| line.starts_with("error["))
        .unwrap_or_else(|| panic!("{} emitted no rustc error:\n{stderr}", fixture.display()));
    assert_eq!(
        first_error,
        expected_error,
        "{} failed with an unexpected first error:\n{stderr}",
        fixture.display()
    );
}

/// S2K-3: a CPL3 entry takes a `BoundKernelStack`, which only the live
/// boundary mints, when it binds the selected Thread's stack or re-checks the
/// binding a kernel context switch made. So no fresh entry can reach CPL3
/// without its stack binding (TSV row 93). Likewise the native usercopy
/// window takes the `SafePointClear` that only the syscall entry's mailbox
/// poll mints (TSV row 97, first seam).
#[test]
fn entry_boundaries_take_unforgeable_proofs() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("kernel is nested below the workspace root");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output_dir = workspace_dir
        .join(".tmp")
        .join("boundary-token-ui")
        .join(std::process::id().to_string());
    fs::create_dir_all(&output_dir)
        .expect("create project-local boundary-token UI output directory");

    for case in [
        UiCase {
            fixture: "boundary_tokens_compiles.rs",
            expected_error: None,
        },
        UiCase {
            fixture: "bound_kernel_stack_forged.rs",
            expected_error: Some(
                "error[E0133]: call to unsafe function `BoundKernelStack::assume` is unsafe and requires unsafe block",
            ),
        },
        UiCase {
            fixture: "bound_kernel_stack_clone.rs",
            expected_error: Some(
                "error[E0277]: the trait bound `BoundKernelStack: Clone` is not satisfied",
            ),
        },
        // TSV row 97, first seam: the usercopy window opens only with the entry poll's proof.
        UiCase {
            fixture: "safe_point_clear_forged.rs",
            expected_error: Some(
                "error[E0133]: call to unsafe function `SafePointClear::assume` is unsafe and requires unsafe block",
            ),
        },
        UiCase {
            fixture: "safe_point_clear_clone.rs",
            expected_error: Some(
                "error[E0277]: the trait bound `SafePointClear: Clone` is not satisfied",
            ),
        },
    ] {
        run_case(&rustc, &manifest_dir, &output_dir, &case);
    }

    fs::remove_dir_all(&output_dir)
        .expect("remove exact project-local boundary-token UI output directory");
}

/// S2K-3a: every frame-abandoning boundary takes the guard-free token. The
/// real `context::abandon_to_kernel_continuation` refuses a call without one
/// and refuses one minted under the guard. The token that execution roots
/// (AP bring-up, the detached idle entry) mint at their root frame and carry
/// by value to `enter_bound_idle_scheduler` can be neither copied nor sent to
/// another CPU.
#[test]
fn every_abandoning_boundary_takes_a_guard_free_token() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("kernel is nested below the workspace root");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output_dir = workspace_dir
        .join(".tmp")
        .join("abandon-ui")
        .join(std::process::id().to_string());
    fs::create_dir_all(&output_dir).expect("create project-local abandon UI output directory");

    for case in [
        UiCase {
            fixture: "context_abandon_compiles.rs",
            expected_error: None,
        },
        UiCase {
            fixture: "context_abandon_without_token.rs",
            expected_error: Some(
                "error[E0061]: this function takes 2 arguments but 1 argument was supplied",
            ),
        },
        UiCase {
            fixture: "context_abandon_under_guard.rs",
            expected_error: Some(
                "error[E0499]: cannot borrow `*handle` as mutable more than once at a time",
            ),
        },
    ] {
        run_case_with(&rustc, &manifest_dir, &output_dir, &case, &TARGET_ONLY_CFG);
    }
    for case in [
        UiCase {
            fixture: "guard_free_clone.rs",
            expected_error: Some(
                "error[E0277]: the trait bound `GuardFree<'_>: Clone` is not satisfied",
            ),
        },
        UiCase {
            fixture: "guard_free_send.rs",
            expected_error: Some("error[E0277]: `*mut ()` cannot be sent between threads safely"),
        },
    ] {
        run_case(&rustc, &manifest_dir, &output_dir, &case);
    }

    fs::remove_dir_all(&output_dir)
        .expect("remove exact project-local abandon UI output directory");
}
