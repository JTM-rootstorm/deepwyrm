use super::*;

pub(super) fn build_kernel(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
    selector: Option<&str>,
) -> PathBuf {
    let mut command = tools.cargo.command();
    environment.apply(&mut command, tools, target_dir);
    command.current_dir(workspace).args([
        "build",
        "--locked",
        "--package",
        "deepwyrm-kernel",
        "--bin",
        "deepwyrm-kernel",
        "--target",
        "x86_64-unknown-none",
    ]);
    if let Some(selector) = selector {
        apply_selector_environment(&mut command, selector);
        command
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", selector)
            .args(["--features", "test-support"]);
    }
    run_success(&mut command, selector.unwrap_or("production"));
    let artifact = target_dir.join("x86_64-unknown-none/debug/deepwyrm-kernel");
    assert!(
        artifact.is_file(),
        "kernel artifact is missing: {}",
        artifact.display()
    );
    artifact
}

pub(super) fn validate_one_shot_ui(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
) {
    let mut command = tools.cargo.command();
    environment.apply(&mut command, tools, target_dir);
    let output = command
        .current_dir(workspace)
        .env("RUSTFLAGS", "--cfg deepwyrm_c3_one_shot_ui")
        .env("DEEPWYRM_GUEST_TEST_SELECTOR", "memory-mapping")
        .args([
            "build",
            "--locked",
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
            "--target",
            "x86_64-unknown-none",
            "--features",
            "test-support",
        ])
        .output()
        .expect("run one-shot target UI probe");
    assert!(
        !output.status.success(),
        "one-shot target UI probe unexpectedly duplicated the active session"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let first_error = stderr
        .lines()
        .find(|line| line.starts_with("error["))
        .unwrap_or_else(|| panic!("one-shot target UI probe emitted no compiler error:\n{stderr}"));
    assert_eq!(
        first_error, "error[E0382]: borrow of moved value: `active`",
        "one-shot target UI probe failed for an unexpected reason:\n{stderr}"
    );
}

pub(super) fn build_stack_kernel(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
    selector: Option<&str>,
) -> PathBuf {
    let mut command = tools.cargo.command();
    environment.apply(&mut command, tools, target_dir);
    command
        .current_dir(workspace)
        .env("RUSTFLAGS", "-Z emit-stack-sizes")
        .env("RUSTC_BOOTSTRAP", "1")
        .args([
            "build",
            "--locked",
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
            "--target",
            "x86_64-unknown-none",
        ]);
    if let Some(selector) = selector {
        apply_selector_environment(&mut command, selector);
        command
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", selector)
            .args(["--features", "test-support"]);
    }
    let identity = selector.unwrap_or("production");
    run_success(&mut command, &format!("{identity} stack-size build"));
    let artifact = target_dir.join("x86_64-unknown-none/debug/deepwyrm-kernel");
    assert!(
        artifact.is_file(),
        "stack-size kernel artifact is missing: {}",
        artifact.display()
    );
    artifact
}

pub(super) fn build_release_kernel(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
    selector: &str,
) -> PathBuf {
    let mut command = tools.cargo.command();
    environment.apply(&mut command, tools, target_dir);
    apply_selector_environment(&mut command, selector);
    command
        .current_dir(workspace)
        .env("DEEPWYRM_GUEST_TEST_SELECTOR", selector)
        .args([
            "build",
            "--locked",
            "--release",
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
            "--target",
            "x86_64-unknown-none",
            "--features",
            "test-support",
        ]);
    run_success(&mut command, &format!("{selector} release build"));
    let artifact = target_dir.join("x86_64-unknown-none/release/deepwyrm-kernel");
    assert!(
        artifact.is_file(),
        "release kernel artifact is missing: {}",
        artifact.display()
    );
    artifact
}

pub(super) fn build_release_stack_kernel(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
    selector: &str,
) -> PathBuf {
    let mut command = tools.cargo.command();
    environment.apply(&mut command, tools, target_dir);
    apply_selector_environment(&mut command, selector);
    command
        .current_dir(workspace)
        .env("RUSTFLAGS", "-Z emit-stack-sizes")
        .env("RUSTC_BOOTSTRAP", "1")
        .env("DEEPWYRM_GUEST_TEST_SELECTOR", selector)
        .args([
            "build",
            "--locked",
            "--release",
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
            "--target",
            "x86_64-unknown-none",
            "--features",
            "test-support",
        ]);
    run_success(
        &mut command,
        &format!("{selector} release stack-size build"),
    );
    let artifact = target_dir.join("x86_64-unknown-none/release/deepwyrm-kernel");
    assert!(
        artifact.is_file(),
        "release stack-size kernel artifact is missing: {}",
        artifact.display()
    );
    artifact
}

fn apply_selector_environment(command: &mut Command, selector: &str) {
    match selector {
        "permanent-supervisor-rrc" => {
            command
                .env("DEEPWYRM_WYR1_EVIDENCE_NONCE", "A025000000000001")
                .env("DEEPWYRM_WYR1_EVIDENCE_SCENARIO", "normal");
        }
        "normal-preemption-up" => {
            command
                .env("DEEPWYRM_DW1B_EVIDENCE_NONCE", "D1B0A82600000001")
                .env("DEEPWYRM_DW1B_CHALLENGE_DIGEST", "5E4E054B5C244ACE")
                .env("DEEPWYRM_DW1B_BOOTFS_MAX_PAGES", "31");
        }
        "bootstrap-registry-launch" => {
            command
                .env("DEEPWYRM_WYR1B_EVIDENCE_NONCE", "0123456789ABCDEF")
                .env("DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES", "117");
        }
        "normal-preemption-smp" => {
            command
                .env("DEEPWYRM_DW1C_EVIDENCE_NONCE", "D1C5000000000001")
                .env("DEEPWYRM_DW1C_PROGRESS_DIGEST", "D1C5A11CE5EED001")
                .env("DEEPWYRM_DW1C_BOOTFS_MAX_PAGES", "53");
        }
        "device-coordinator-restart" => {
            command.env("DEEPWYRM_WYR1C_EVIDENCE_NONCE", "C6C4000000000001");
        }
        _ => {}
    }
}

pub(super) fn find_e7_user_artifact(target_dir: &Path) -> PathBuf {
    find_user_artifact(target_dir, "deepwyrm-e7-user.elf", "E7")
}

pub(super) fn find_f9_user_artifact(target_dir: &Path) -> PathBuf {
    find_user_artifact(target_dir, "deepwyrm-f9-user.elf", "F9")
}

pub(super) fn find_f12_user_artifact(target_dir: &Path) -> PathBuf {
    find_user_artifact(target_dir, "deepwyrm-f12-user.elf", "F12")
}

fn find_user_artifact(target_dir: &Path, artifact_name: &str, phase: &str) -> PathBuf {
    let build_dir = target_dir.join("x86_64-unknown-none/debug/build");
    let mut matches = Vec::new();
    for entry in fs::read_dir(&build_dir).expect("read E7 build directory") {
        let entry = entry.expect("read E7 build entry");
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("deepwyrm-kernel-") {
            continue;
        }
        let artifact = entry.path().join("out").join(artifact_name);
        if artifact.is_file() {
            matches.push(artifact);
        }
    }
    assert_eq!(
        matches.len(),
        1,
        "expected one {phase} userspace artifact under {}: {matches:?}",
        target_dir.display()
    );
    matches.pop().unwrap()
}
