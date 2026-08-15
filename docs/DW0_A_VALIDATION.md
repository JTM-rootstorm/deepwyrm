# DW0-A Validation Record

## Disposition

Phase DW0-A's host-only ABI layout gate passes for Deepwyrm revision
`4751a2d3929675357e31389301d152f86e2ab7cb`.

This disposition covers the workspace, canonical ABI 0 schema, deterministic
generation, committed fixed-width Rust and C representations, drift checks,
focused host-test selection, and symbolized Cargo profiles. It does not claim a
bootable kernel, syscall implementation, guest-toolchain acceptance, Wyrmroot
consumer acceptance, VM evidence, or any DW0-B and later gate.

## Validation evidence

The following commands passed from the implementation checkout:

```text
cargo xtask abi generate
cargo xtask abi check
cargo xtask test host abi
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
cargo xtask check
cargo fmt --all -- --check
git diff --check
```

The focused host selector ran seven `abi-gen` tests and three generated ABI
tests. The full workspace run additionally passed eight `xtask` tests and the
currently empty kernel test target. The generator's C11 probe compiled the
generated header with Clang and its drift test detected and repaired stale
output in an isolated fixture.

A separate local clone was detached at the exact revision above. From that
clean checkout, `cargo xtask abi check`, `cargo xtask test host abi`,
`cargo test --locked --workspace --all-targets`, and
`cargo fmt --all -- --check` all passed; `git status --short` remained empty.

The committed generated-artifact SHA-256 identities at that revision are:

| Artifact | SHA-256 |
|---|---|
| `ABI.md` | `97d063e5d0d20b40c4810bbda9507abffcedae2fe44978c020293f49d342158f` |
| `deepwyrm_abi.h` | `8c8a3a9836c012ec4323fe90e291763d1d1ed4f9125db1de8f02f02a6c222953` |
| `deepwyrm_abi.rs` | `3708537e1fce5d96cf526f1457309148945d2babf2585bfcdc3ebc771aba7085` |
| `syscall_dispatch.rs` | `acb329505f9513345916cb048fd451f3af78ace1b2b2113865895b46482fe54b` |
| `syscall_wrappers.rs` | `a1b609565c5b16f6ccaba8e65b4170ebdfdcf4f972f82aea420dffc8da760efa` |

## Representation gate

Generated tests assert scalar size/alignment, every record's size/alignment and
field offsets, fundamental constants, and explicit syscall values. The C11
header contains matching fixed-width typedefs and static layout assertions.
`deepwyrm-abi` includes only the generated ABI definitions and remains `no_std`
with unsafe code forbidden.

## Environment and review

Exact observed host-tool versions are recorded in
[`toolchain/provenance.toml`](../toolchain/provenance.toml). That observation is
not a Wyrmroot Rust-fork artifact pin or a guest-toolchain acceptance claim.

The intermediate manual security disposition is recorded in
[`security/DW0_A_SECURITY_REVIEW.md`](../security/DW0_A_SECURITY_REVIEW.md).
Wyrmroot must consume the ABI from an exact Deepwyrm revision; its consumer pin
and validation are separate cross-repository evidence.

## Deferred work

Architecture entry, usercopy, object and handle tables, syscall dispatch,
queues, transfer rollback, blocking, wakeups, timers, atomic wait/wake, guest
tests, QEMU/UEFI integration, and concurrency stress remain assigned to later
DW0 phases. Generated syscall metadata documents the contract; it is not a
runtime implementation.
