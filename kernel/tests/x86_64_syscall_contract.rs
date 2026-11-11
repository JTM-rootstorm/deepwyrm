#[path = "support/host_tools.rs"]
mod host_tools;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn syscall_assembly_is_freestanding_and_calls_only_the_rust_dispatch() {
    let clang = host_tools::clang();
    let output = std::env::temp_dir().join(format!("deepwyrm-e4-syscall-{}.o", std::process::id()));
    let status = Command::new(&clang)
        .args([
            "--no-default-config",
            "--target=x86_64-unknown-none",
            "-ffreestanding",
            "-fno-pic",
            "-mno-red-zone",
            "-c",
        ])
        .arg(root().join("src/arch/x86_64/syscall_entry.S"))
        .arg("-o")
        .arg(&output)
        .status()
        .expect("run clang for E4 syscall assembly");
    assert!(status.success());
    let _ = fs::remove_file(output);
}
