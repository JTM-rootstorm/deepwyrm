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
        .env_remove("DEEPWYRM_GUEST_TEST_SELECTOR")
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("cargo 1.97.1"));
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
fn selector_test_support_mismatches_fail_before_cargo_admission() {
    for arguments in [
        vec![
            "host",
            "test",
            "-p",
            "deepwyrm-kernel",
            "--features",
            "test-support",
            "--lib",
        ],
        vec![
            "host",
            "test",
            "-p",
            "deepwyrm-kernel",
            "--features=test-support",
            "--lib",
        ],
        vec![
            "target",
            "check",
            "-p",
            "deepwyrm-kernel",
            "--features",
            "test-support",
        ],
        vec![
            "target",
            "check",
            "-p",
            "deepwyrm-kernel",
            "--features=test-support",
        ],
    ] {
        let output = rejected(&arguments);
        assert_eq!(output.status.code(), Some(2), "arguments: {arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("test-support requires DEEPWYRM_GUEST_TEST_SELECTOR"),
            "arguments: {arguments:?}"
        );
    }

    let output = rejected_with_env(
        &["host", "test", "-p", "deepwyrm-kernel", "--lib"],
        &[("DEEPWYRM_GUEST_TEST_SELECTOR", "normal-preemption-up")],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("DEEPWYRM_GUEST_TEST_SELECTOR requires explicit test-support")
    );

    for lane in ["host", "target"] {
        let output = rejected_with_env(
            &[lane, "check", "-p", "deepwyrm-kernel"],
            &[("DEEPWYRM_GUEST_TEST_ID", "26")],
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("DEEPWYRM_GUEST_TEST_ID is build-owned")
        );
    }
}

#[test]
fn host_selector_tests_require_an_explicit_library_only_shape() {
    let selector_environment = [
        ("DEEPWYRM_GUEST_TEST_SELECTOR", "normal-preemption-up"),
        ("DEEPWYRM_DW1B_EVIDENCE_NONCE", "D1B0A82600000001"),
        ("DEEPWYRM_DW1B_CHALLENGE_DIGEST", "5E4E054B5C244ACE"),
        ("DEEPWYRM_DW1B_BOOTFS_MAX_PAGES", "31"),
    ];
    for arguments in [
        vec![
            "host",
            "check",
            "-p",
            "deepwyrm-kernel",
            "--features",
            "test-support",
        ],
        vec![
            "host",
            "test",
            "-p",
            "deepwyrm-kernel",
            "--features",
            "test-support",
        ],
    ] {
        let output = rejected_with_env(&arguments, &selector_environment);
        assert_eq!(output.status.code(), Some(2), "arguments: {arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("host test-support is restricted")
        );
    }
}

#[test]
fn selector_26_environment_is_validated_before_cargo_admission() {
    let output = rejected_with_env(
        &[
            "host",
            "test",
            "-p",
            "deepwyrm-kernel",
            "--features",
            "test-support",
            "--lib",
        ],
        &[
            ("DEEPWYRM_GUEST_TEST_SELECTOR", "normal-preemption-up"),
            ("DEEPWYRM_DW1B_EVIDENCE_NONCE", "D1B0A82600000001"),
            ("DEEPWYRM_DW1B_CHALLENGE_DIGEST", "5E4E054B5C24_4ACE"),
            ("DEEPWYRM_DW1B_BOOTFS_MAX_PAGES", "31"),
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "DEEPWYRM_DW1B_CHALLENGE_DIGEST must be exactly 16 uppercase hexadecimal digits"
    ));
}

#[test]
fn both_toolchain_identities_pin_the_same_project_cargo_home() {
    for identity in [
        "tooling/host-rust-toolchain.toml",
        "tooling/rust-toolchain.toml",
    ] {
        let text = std::fs::read_to_string(workspace().join(identity)).expect("read identity");
        assert!(text.contains("cargo_home = \".tmp/cargo-home/offline-v1\""));
        assert!(text.contains("target_dir = \".tmp/cargo-target/"));
    }
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("cargo 1.97.1"));
    assert!(
        workspace()
            .join(".tmp/cargo-target/host-1.97.1/.deepwyrm-pinned-cargo-v1")
            .is_file()
    );
}

#[test]
fn metadata_uses_the_selected_lane_and_dangerous_ambient_overrides_are_removed() {
    let source = std::fs::read_to_string(workspace().join("tools/pinned-cargo"))
        .expect("read pinned Cargo launcher");
    let metadata = source
        .find("\"$cargo\" metadata --locked --offline")
        .expect("offline metadata preflight");
    for required_before_metadata in [
        "unset CARGO_BUILD_TARGET CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS CARGO_TARGET_DIR",
        "unset LD_LIBRARY_PATH LD_PRELOAD",
        "export CARGO_HOME=\"$cargo_home\"",
        "export CARGO_TARGET_DIR=\"$normalized_target\"",
        "export RUSTC=\"$rustc\"",
    ] {
        assert!(
            source
                .find(required_before_metadata)
                .is_some_and(|position| position < metadata),
            "{required_before_metadata} must precede metadata"
        );
    }
    assert!(source.contains("rustc_driver_internal_library_sha256"));
    assert!(source.contains("llvm_internal_library_sha256"));
}
