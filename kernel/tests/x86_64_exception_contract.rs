#[path = "support/host_tools.rs"]
mod host_tools;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Text test: the G5 completion oracle runs only on the target-only primordial terminal path.
#[test]
fn e4_exception_assembly_remains_freestanding() {
    let clang = host_tools::clang();
    let output =
        std::env::temp_dir().join(format!("deepwyrm-e4-exceptions-{}.o", std::process::id()));
    let status = Command::new(&clang)
        .args([
            "--no-default-config",
            "--target=x86_64-unknown-none",
            "-ffreestanding",
            "-fno-pic",
            "-mno-red-zone",
            "-c",
        ])
        .arg(root().join("src/arch/x86_64/exceptions.S"))
        .arg("-o")
        .arg(&output)
        .status()
        .expect("run clang for E4 exception assembly");
    assert!(status.success());
    let _ = fs::remove_file(output);
}
