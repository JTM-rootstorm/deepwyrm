use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kernel crate has workspace parent")
        .to_owned()
}

fn unique_target(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("deepwyrm-pinned-cargo-{label}-{nonce}"))
}

fn rejected_with_env(arguments: &[&str], environment: &[(&str, &str)]) -> Output {
    let target = unique_target("rejection");
    let mut command = Command::new(workspace().join("tools/pinned-cargo"));
    command
        .args(arguments)
        .current_dir(workspace())
        .env_remove("CARGO_HOME")
        .env_remove("DEEPWYRM_GUEST_TEST_ID")
        .env("DEEPWYRM_PINNED_TARGET_DIR", &target);
    for (name, value) in environment {
        command.env(name, value);
    }
    let output = command.output().expect("run pinned Cargo rejection");
    assert!(
        !target.exists(),
        "rejected invocation created target lane {}",
        target.display()
    );
    output
}

fn rejected(arguments: &[&str]) -> Output {
    rejected_with_env(arguments, &[])
}

#[test]
fn host_lane_rejects_freestanding_cargo_admission_before_target_creation() {
    for arguments in [
        vec!["host", "test", "--all-features"],
        vec!["host", "test", "--features", "native-payloads"],
        vec!["host", "build", "--bin", "wyrmroot-dw1b-progress"],
        vec!["host", "build", "--workspace"],
        vec!["host", "check", "--workspace"],
        vec!["host", "clippy", "--workspace", "--all-targets"],
        vec!["host", "rustdoc", "--workspace"],
        vec!["host", "build", "--target", "x86_64-unknown-wyrmroot"],
        vec!["host", "check", "--manifest-path", "../wyrmroot/Cargo.toml"],
        vec![
            "host",
            "check",
            "--config",
            "build.target='x86_64-unknown-none'",
        ],
    ] {
        let output = rejected(&arguments);
        assert_eq!(output.status.code(), Some(2), "arguments: {arguments:?}");
        assert!(
            String::from_utf8(output.stderr)
                .expect("launcher diagnostic is UTF-8")
                .contains("host lane rejects"),
            "arguments: {arguments:?}"
        );
    }
}

#[test]
fn host_lane_owns_the_project_cargo_home() {
    let target = unique_target("host-version");
    let output = Command::new(workspace().join("tools/pinned-cargo"))
        .args(["host", "--version"])
        .current_dir(workspace())
        .env_remove("CARGO_HOME")
        .env("DEEPWYRM_PINNED_TARGET_DIR", &target)
        .output()
        .expect("run pinned host Cargo");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("cargo 1.98.1"));
    std::fs::remove_dir_all(&target).expect("remove test-owned target lane");

    let output = Command::new(workspace().join("tools/pinned-cargo"))
        .args(["host", "--version"])
        .current_dir(workspace())
        .env("CARGO_HOME", "/tmp")
        .env("DEEPWYRM_PINNED_TARGET_DIR", "/tmp/deepwyrm-unused-target")
        .output()
        .expect("run ambient Cargo-home rejection");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("CARGO_HOME is lane-owned"));
}

#[test]
fn canonical_invocation_owns_a_reusable_lane_target() {
    let output = Command::new(workspace().join("tools/pinned-cargo"))
        .args(["host", "--version"])
        .current_dir(workspace())
        .env_remove("CARGO_HOME")
        .env_remove("DEEPWYRM_PINNED_TARGET_DIR")
        .output()
        .expect("run canonical pinned host Cargo");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("cargo 1.98.1"));
    assert!(
        workspace()
            .join(".tmp/cargo-target/host-1.98.1/.deepwyrm-pinned-cargo-v1")
            .is_file()
    );
}
