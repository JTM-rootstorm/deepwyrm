//! Host tools that kernel integration tests run, resolved from central tooling.
//!
//! A test that needs one of these fails when it cannot be found; it never
//! passes by skipping (S1.2). `tools/pinned-cargo` verifies the Clang named by
//! `tooling/host-rust-toolchain.toml`'s `clang_binary` against its recorded hash
//! and exports it as `DEEPWYRM_CLANG`, and exports the pinned host `rustc` as
//! `RUSTC`. The LLVM utilities sit beside that Clang, in the layout
//! `tooling/build-tools.toml` records (`bin/clang-22`, `bin/llvm-nm`,
//! `bin/llvm-objdump`).

#![allow(dead_code, reason = "each test crate uses a subset of these tools")]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const RUN_THROUGH_LANE: &str = "run kernel tests through `tools/pinned-cargo host ...` or `tools/pinned-cargo host xtask test host`";

/// The verified host Clang: `DEEPWYRM_CLANG`, which must be the central
/// identity's `clang_binary` and must run.
pub fn clang() -> PathBuf {
    let clang = env::var_os("DEEPWYRM_CLANG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("DEEPWYRM_CLANG is unset; {RUN_THROUGH_LANE}, which exports the verified Clang")
        });
    let pinned = pinned_clang();
    assert_eq!(
        clang, pinned,
        "DEEPWYRM_CLANG must be tooling/host-rust-toolchain.toml's clang_binary"
    );
    require_runs(&clang);
    clang
}

/// An LLVM utility from the verified Clang's own `bin` directory.
pub fn llvm_tool(name: &str) -> PathBuf {
    let clang = clang();
    let tool = clang
        .parent()
        .expect("the verified Clang has a parent directory")
        .join(name);
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

fn pinned_clang() -> PathBuf {
    let identity =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tooling/host-rust-toolchain.toml");
    let source = fs::read_to_string(&identity)
        .unwrap_or_else(|error| panic!("read {}: {error}", identity.display()));
    let mut values = source.lines().filter_map(|line| {
        line.strip_prefix("clang_binary = \"")
            .and_then(|rest| rest.strip_suffix('"'))
    });
    let clang = values
        .next()
        .unwrap_or_else(|| panic!("{} names no clang_binary", identity.display()));
    assert!(
        values.next().is_none(),
        "{} names clang_binary twice",
        identity.display()
    );
    PathBuf::from(clang)
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
