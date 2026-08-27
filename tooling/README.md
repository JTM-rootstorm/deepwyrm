# Deepwyrm Rust toolchain lanes

Deepwyrm has two repository-owned Cargo lanes. Always invoke Cargo through
`tools/pinned-cargo`; do not call an ambient `cargo`, export `CARGO_HOME`, or
reuse the repository's canonical `target/` directory.

The launcher derives the shared offline Cargo home from the selected identity,
requires an isolated target directory beneath `/tmp` or `deepwyrm/.tmp`, and
removes ambient target, compiler, rustflags, loader, and wrapper overrides
before Cargo metadata or compilation runs.

The `host` lane is stable Rust 1.97.1 for host tests, Clippy, rustdoc,
formatting, and host tooling:

```sh
DEEPWYRM_PINNED_TARGET_DIR=/tmp/deepwyrm-host-tests \
    tools/pinned-cargo host test --locked --workspace
```

Selector-configured kernel unit tests are the only host use of `test-support`.
They must name the selector and use an explicit library-only test shape:

```sh
DEEPWYRM_PINNED_TARGET_DIR=/tmp/deepwyrm-selector-host \
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

Both lane identities pin `.tmp/cargo-home/offline-v1`. Caller omission of
`CARGO_HOME` is required and means the launcher supplies that pinned cache; it
never means Cargo may fall back to a user or ambient home.

This document is first-party `GPL-2.0-or-later` project documentation.
