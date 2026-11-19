# Deepwyrm Rust toolchain lanes

Deepwyrm has two repository-owned Cargo lanes. Run from the selected Deepwyrm
checkout: the launcher verifies offline metadata in the caller's working
directory, so invoking it from the coordination root fails before compilation.
Always invoke Cargo through
`tools/pinned-cargo`; do not call an ambient `cargo`, export `CARGO_HOME`, or
reuse the repository's canonical `target/` directory.

The launcher derives the shared offline Cargo home and a lane-specific reusable
target directory from the selected identity. It removes ambient target,
compiler, rustflags, loader, and wrapper overrides before Cargo metadata or
compilation runs. Concurrent or disposable lanes may override the target with
an absolute `DEEPWYRM_PINNED_TARGET_DIR` beneath `/tmp` or `deepwyrm/.tmp`.

In a registered `.worktrees/deepwyrm/<lane>` worktree, the wrapper verifies
the common Git directory and resolves the canonical OS-Project root. That root
supplies the regular, non-symlink `.tmp/cargo-home/offline-v1` and the immutable
`artifacts/toolchains/accepted/...` identity. Do not provision substitute
worktree-parent caches or weaken the wrapper's identity checks. Keep mutable
target output lane-local with `DEEPWYRM_PINNED_TARGET_DIR`.

The `host` lane is stable Rust 1.98.1 for host tests, Clippy, rustdoc,
formatting, and host tooling:

```sh
tools/pinned-cargo host test --locked --workspace
```

The installed host package must include matching `rust-src` and
`rust-analyzer` components as well as Clippy and rustfmt. All component hashes
remain mandatory; an incomplete host update is an installation blocker, not
permission to skip identity checks or substitute the accepted guest compiler.

Host `build`, `check`, `clippy`, and `rustdoc` commands must select only
`--lib`, `--tests`, `--test`, or `--doc` targets. Implicit workspace targets,
`--all-targets`, binaries, and examples are rejected before Cargo so the
freestanding kernel can never be admitted as a Linux-host binary by accident.

The `target` lane is the accepted Wyrmroot Rust fork for freestanding product
artifacts. Its command must select the freestanding target explicitly. Central
build/image tooling remains responsible for artifact provenance.

Both lane identities pin `.tmp/cargo-home/offline-v1`, and each pins its own
`.tmp/cargo-target/` directory. Caller omission of `CARGO_HOME` and
`DEEPWYRM_PINNED_TARGET_DIR` is the canonical reusable path: the launcher
supplies both, never Cargo's ambient defaults.

This document is first-party `GPL-2.0-or-later` project documentation.
