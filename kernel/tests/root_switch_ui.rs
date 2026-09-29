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
    ] {
        run_case(&rustc, &manifest_dir, &output_dir, &case);
    }

    fs::remove_dir_all(&output_dir)
        .expect("remove exact project-local root-switch UI output directory");
}

fn run_case(rustc: &std::ffi::OsStr, manifest_dir: &Path, output_dir: &Path, case: &UiCase<'_>) {
    let fixture = manifest_dir.join("tests/ui").join(case.fixture);
    let crate_name = case.fixture.trim_end_matches(".rs");
    let output = Command::new(rustc)
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
