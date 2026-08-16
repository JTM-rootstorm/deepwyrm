# DW0-B Validation Record

## Current disposition

The Deepwyrm DW0-B source, host, and freestanding build gates pass at signed
revision `a194194016b10dce269f286950dfa90b27851217`. It is the same-tree signed
equivalent of pre-signing revision
`0bc8e6667e27ebd6aa5e3d572f34b9a1dfddefc7`; both commits have tree
`5766bba49c27118f6fcf9a85f6edb9742a00f9a0`. Per Mike's publication
instruction, no build, test, or artifact was rerun or regenerated after the
signing rewrite. The evidence below remains attributed to the pre-signing
commit and carries forward only through that exact tree equivalence.

The coordinator-owned Q35/UEFI guest gate remains pending an exact Wyrmroot
image and request manifest; therefore this record does not yet claim complete
functional phase acceptance.

## Implemented scope

- `DW_BOOT_X86_64_ENTRY_V1` and a strict machine-readable ELF/layout contract;
- an immediate loader-stack to kernel-stack entry shim and nonreturning System
  V Rust boundary;
- bounded, owned BootInfo memory-map and module intake;
- early COM1 and panic diagnostics;
- emergency and final IDTs, GDT/TSS, dedicated exception IST stacks, normalized
  exception stubs, and APIC-ready interrupt-controller plumbing;
- production-separated PASS/FAIL/PANIC completion records; and
- centralized, dry-run Q35/UEFI/GDB planning with trusted immutable toolchain
  identity and bounded result classification.

This phase does not implement DW0-C memory ownership, objects, handles,
syscalls, scheduling, userspace execution, or later runtime behavior.

## Host and build evidence

The following commands passed from the implementation checkout:

```text
cargo xtask abi check
cargo xtask test host abi
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
cargo fmt --all -- --check
git diff --check
```

The full workspace run passed 80 tests: eight ABI-generator tests, three
generated ABI tests, 36 kernel unit tests, nine APIC model tests, five entry and
layout-contract tests, fifteen xtask unit tests, and four xtask command-surface
tests. Each of the three compile-time guest selectors also passed its 73-test
kernel host configuration.

The accepted immutable toolchain is coordinator request
`RUST-PHASE0B-TOOLCHAIN-001`, Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, configuration SHA-256
`63e532b52e6d4c2ef4ed4a003e2aafd7ec11b55e3de5a635c1aea8bfa849f332`,
and root-manifest SHA-256
`553cbfe6eb5cd9976c4f078a3731269f2a2ecd4f3ff5d574ab3813bae8fcf1f1`.
The canonical toolchain-tree digest is
`5d4275428555a7cd6ae7decc100456fe31cfa4562a7f5eb81a3cf7fe08aa03a5`.
Planning revalidated that digest, the selected Cargo, rustc, rust-lld, target
core and compiler-builtins libraries, and the rustc-driver and LLVM internal
libraries. The host-neutral build-tools identity gate then verified Clang
22.1.8, libclang-cpp, host LLVM, and the Clang configuration before the exact
compiler path was passed through `DEEPWYRM_CLANG`.

Two isolated builds of the production kernel and all three
`x86_64-unknown-none` selector kernels were byte-identical. The durable local
artifacts remain under the historical pre-signing path
`artifacts/dw0-b/0bc8e6667e27ebd6aa5e3d572f34b9a1dfddefc7/`. They were not
reattributed, rebuilt, moved, or regenerated for the signed commit.

## Kernel artifact evidence

| Artifact | SHA-256 |
|---|---|
| Production kernel ELF | `9360190ba6337f72ab2c8a7b1aaa59d74e3f6a93e4009be26da9e526dc5dcaa8` |
| `boot-handoff-pass` kernel ELF | `57ee0c5d84603fdfe4dfbb23395b9e69211f96fbb8fff991f95abb8d047fe9ae` |
| `exception-fail-path` kernel ELF | `74bd4ce857dc0096693bc4b3bf8a01ea3b42e71e056a5c9f3ad1b4b1c121d4d5` |
| `panic-path` kernel ELF | `d0384412f83b9815be1ad70dfce7fe50ab43b2902f19b5276627db655a6d8d9e` |
| x86_64 layout manifest | `481c40faa8dff4d2856846e6cb1fd4266ff113ba08da9944be62ab8493cab790` |
| trusted toolchain identity | `2cd16c0690e243b2d68add2fcbb23f78d4a91e324948e04f19b8209267ecdb93` |
| host-neutral build-tools identity | `ebf00477133c83f2bd4fc68242d04a8e1c3601880451fe517b926e7a74376674` |

The production artifact is ELF64 x86_64 `ET_EXEC`, enters at
`0xffffffff80000000`, and has exactly three 4 KiB-aligned non-overlapping
`PT_LOAD` segments with RX, R, and RW permissions. It has no RWX segment,
dynamic segment, relocation segment, TLS segment, interpreter, or production
test-completion symbol/string. The entry, Rust bridge, exception table and
representative exception/APIC symbols remain available in the host debug ELF.

## Pending coordinator-owned functional gate

The exact paired Wyrmroot revision, ESP/image identities, VM profile, selector
requests, fresh serial captures, observed QEMU exit statuses, and GDB entry
breakpoint evidence must be appended after the coordinator-owned VM run. The
request is not eligible to run until Wyrmroot produces a clean boot-ready image
that is bound to this exact Deepwyrm revision and artifact set. The required
outcomes are:

| Selector | Record | QEMU host status |
|---|---|---:|
| `boot-handoff-pass` | PASS, test ID 1 | 33 |
| `exception-fail-path` | FAIL, test ID 2, detail 6 | 35 |
| `panic-path` | PANIC, test ID 3 | 37 |

Every run requires a newly created or truncated bounded serial capture, one
exact terminal record, a matching exit status, a bounded timeout, and durable
request/revision/artifact hashes. Missing, stale, duplicate, or mismatched
evidence is `INFRASTRUCTURE`, never PASS.

The source-security disposition is recorded in
[`security/DW0_B_SECURITY_REVIEW.md`](../security/DW0_B_SECURITY_REVIEW.md).
