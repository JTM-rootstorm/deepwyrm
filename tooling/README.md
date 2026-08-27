# Deepwyrm Rust toolchain lanes

Deepwyrm has two repository-owned Cargo lanes. Always invoke Cargo through
`tools/pinned-cargo`; do not call an ambient `cargo`, export `CARGO_HOME`, or
reuse the repository's canonical `target/` directory.

The launcher derives the shared offline Cargo home and a lane-specific reusable
target directory from the selected identity. It removes ambient target,
compiler, rustflags, loader, and wrapper overrides before Cargo metadata or
compilation runs. Concurrent or disposable lanes may override the target with
an absolute `DEEPWYRM_PINNED_TARGET_DIR` beneath `/tmp` or `deepwyrm/.tmp`.

The `host` lane is stable Rust 1.97.1 for host tests, Clippy, rustdoc,
formatting, and host tooling:

```sh
tools/pinned-cargo host test --locked --workspace
```

Selector-configured kernel unit tests are the only host use of `test-support`.
They must name the selector and use an explicit library-only test shape:

```sh
DEEPWYRM_GUEST_TEST_SELECTOR=normal-preemption-up \
DEEPWYRM_DW1B_EVIDENCE_NONCE=D1B0A82600000001 \
DEEPWYRM_DW1B_CHALLENGE_DIGEST=5E4E054B5C244ACE \
DEEPWYRM_DW1B_BOOTFS_MAX_PAGES=31 \
    tools/pinned-cargo host test --locked -p deepwyrm-kernel \
        --features test-support --lib <test-filter>
```

The `target` lane is the accepted Wyrmroot Rust fork for freestanding product
and guest-test artifacts. Its command must select the freestanding target
explicitly; selector builds must pair `test-support` with the canonical named
selector environment. Central build/image tooling remains responsible for the
full selector environment and artifact provenance.

Both lane identities pin `.tmp/cargo-home/offline-v1`, and each pins its own
`.tmp/cargo-target/` directory. Caller omission of `CARGO_HOME` and
`DEEPWYRM_PINNED_TARGET_DIR` is the canonical reusable path: the launcher
supplies both, never Cargo's ambient defaults.

This document is first-party `GPL-2.0-or-later` project documentation.
