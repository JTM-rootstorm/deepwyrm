//! Host tools that kernel integration tests run, resolved from central tooling.
//!
//! A test that needs one of these fails when it cannot be found; it never
//! passes by skipping (S1.2). Clang and the LLVM utilities come from system
//! packages and are resolved by name from `PATH`, never pinned by path or hash.
//! `tools/pinned-cargo` exports the host `rustc` as `RUSTC`.

#![allow(dead_code, reason = "each test crate uses a subset of these tools")]

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const RUN_THROUGH_LANE: &str = "run kernel tests through `tools/pinned-cargo host ...` or `tools/pinned-cargo host xtask test host`";

/// The system `clang`, resolved from `PATH`; it must run.
pub fn clang() -> PathBuf {
    let clang = PathBuf::from("clang");
    require_runs(&clang);
    clang
}

/// An LLVM utility resolved by name from `PATH`; it must run.
pub fn llvm_tool(name: &str) -> PathBuf {
    let tool = PathBuf::from(name);
    require_runs(&tool);
    tool
}

/// The pinned host `rustc` that `tools/pinned-cargo` exports as `RUSTC`.
pub fn rustc() -> PathBuf {
    let rustc = env::var_os("RUSTC").map(PathBuf::from).unwrap_or_else(|| {
        panic!("RUSTC is unset; {RUN_THROUGH_LANE}, which exports the pinned rustc")
    });
    require_runs(&rustc);
    rustc
}

fn require_runs(tool: &Path) {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("{} cannot run: {error}", tool.display()));
    assert!(
        output.status.success(),
        "{} --version failed: {}",
        tool.display(),
        output.status
    );
}
