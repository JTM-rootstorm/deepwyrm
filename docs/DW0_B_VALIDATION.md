# DW0-B Validation Record

## Current disposition

The Deepwyrm DW0-B source, host, and freestanding build gates pass at revision
`d827dcbc3723904a2601fee3a9af42e27cdad693`. The manager-owned Q35/UEFI guest
gate remains pending an exact Wyrmroot image and request manifest; therefore
this record does not yet claim complete functional phase acceptance.

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

The full workspace run passed 76 tests: eight ABI-generator tests, three
generated ABI tests, 36 kernel unit tests, nine APIC model tests, five entry and
layout-contract tests, eleven xtask unit tests, and four xtask command-surface
tests. Each of the three compile-time guest selectors also passed its 73-test
host configuration.

The accepted immutable toolchain is coordinator request
`RUST-PHASE0B-TOOLCHAIN-001`, Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, configuration SHA-256
`63e532b52e6d4c2ef4ed4a003e2aafd7ec11b55e3de5a635c1aea8bfa849f332`,
and root-manifest SHA-256
`553cbfe6eb5cd9976c4f078a3731269f2a2ecd4f3ff5d574ab3813bae8fcf1f1`.
Explicit immutable Cargo and rustc paths built the production kernel and all
three `x86_64-unknown-none` selector kernels successfully.

## Kernel artifact evidence

| Artifact | SHA-256 |
|---|---|
| Production kernel ELF | `0b274e9a1f62cd3a86cc360e68a4f9c672335dc0aa2e474971b30bd505fcf61e` |
| `boot-handoff-pass` kernel ELF | `4ba6310df63c4936585f06be521a18eaab5410ce884cec079c28c5168e3552a5` |
| `exception-fail-path` kernel ELF | `47843b823f65855d2e1b24e3b13cd9b9a24c16662c71572b3282de9d75097566` |
| `panic-path` kernel ELF | `d131abfec24206b1793ff9a56c13658cdaf9963b1b5b4d853a668a2dc1494422` |
| x86_64 layout manifest | `481c40faa8dff4d2856846e6cb1fd4266ff113ba08da9944be62ab8493cab790` |
| trusted toolchain identity | `995f1f251acf4e65d7cfd686618dd82920d884de0e8b9b1ddd47d1ab826e9b39` |

The production artifact is ELF64 x86_64 `ET_EXEC`, enters at
`0xffffffff80000000`, and has exactly three 4 KiB-aligned non-overlapping
`PT_LOAD` segments with RX, R, and RW permissions. It has no RWX segment,
dynamic segment, relocation segment, TLS segment, interpreter, or production
test-completion symbol/string. The entry, Rust bridge, exception table and
representative exception/APIC symbols remain available in the host debug ELF.

## Pending manager-owned functional gate

The exact paired Wyrmroot revision, ESP/image identities, VM profile, selector
requests, fresh serial captures, observed QEMU exit statuses, and GDB entry
breakpoint evidence must be appended after the coordinator-owned VM run. The
required outcomes are:

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
