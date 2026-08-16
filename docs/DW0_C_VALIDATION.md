# DW0-C Candidate Validation Record

## Current disposition

The DW0-C physical/virtual-memory source, host, and freestanding artifact gates
pass for the uncommitted C3 candidate based on Deepwyrm revision
`2c32c82aef71c1e52cfde2fc368beb93a63d8f8c`. This is not a completed phase
claim. The mandatory final security review and the coordinator-owned execution
of all six guest selectors against an exact Deepwyrm/Wyrmroot image remain
pending.

## Implemented scope

- sanitized physical allocation with one generation-stamped frame-role
  registry and nonduplicable typed grants;
- page-backed `MemoryObject`, mapping-lease, and `AddressRegion` models with
  atomic model/page-table replacement and W^X enforcement;
- a bounded x86_64 shadow journal with typed table candidates, child-first
  publication, rollback before the first target write, and exact local
  invalidation;
- live transition-root attestation, a fixed one-page scratch mapper, a
  validated inactive Deep-owned root, and one-shot CR3 activation;
- consumer-owned entry normalization that clears exactly CR4.SMAP and
  RFLAGS.AC before C1, with both C1 and C2 rejecting subsequent drift;
- an architecture-private active scratch/control path retained after transition
  mappings retire; and
- immutable guest-test identities 4 through 9 with real mapping, unmapping,
  permission, invalid-pointer usercopy, user/kernel-isolation, and shared-object
  bodies bound to the exact active C2 session. The C3 runner consumes that
  session and diverges on every outcome; its model, object, role, and region
  authorities remain live in the terminal frame while published mappings
  exist.

The unmapping and permission bodies warm a live translation, publish the PTE
change and invalidation, then require an exact terminal page fault. The expected
tuple includes vector 14, CR2, error word, fixed fault-site RIP, and processor
identity. A mismatch is PANIC and a faulting instruction which falls through is
FAIL.

## Host and source evidence

The following focused gates passed:

```text
DEEPWYRM_GUEST_TEST_SELECTOR=memory-mapping cargo test -p deepwyrm-kernel --features test-support --lib test_support::identity::tests
cargo test -p deepwyrm-kernel --test x86_64_memory_guest_contract
cargo xtask test host memory
```

The selector/fault classifier passed 12 tests. The C3 dispatch, privacy,
terminal-fault, one-shot, CPU-profile, and backing-frame source contracts passed six tests. The corrected
canonical memory gate deliberately has no name filter: its observed run passed
148 kernel unit tests, nine APIC integration tests, one mapping-authority UI test, two
physical-ownership UI tests, four activation-contract tests, six entry-contract
tests, six C3 source-contract tests, and four host-only artifact/provenance tests.
The explicit target-artifact test is ignored in ordinary host runs and is invoked
separately with the accepted toolchain.

## Freestanding artifact evidence

The explicit target gate was run with repository request
`RUST-PHASE0B-TOOLCHAIN-001`: Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, configuration SHA-256
`63e532b52e6d4c2ef4ed4a003e2aafd7ec11b55e3de5a635c1aea8bfa849f332`,
and root-manifest SHA-256
`553cbfe6eb5cd9976c4f078a3731269f2a2ecd4f3ff5d574ab3813bae8fcf1f1`.
The gate rehashed the accepted toolchain tree, Cargo, rustc, rust-lld, rustc
driver, internal LLVM library, bootstrap configuration, root manifest, sysroot
manifest, Clang, and Clang's manifest-pinned `libclang-cpp` and host LLVM
libraries against the repository-owned identities in
[`tooling/rust-toolchain.toml`](../tooling/rust-toolchain.toml) and
[`tooling/build-tools.toml`](../tooling/build-tools.toml), both before and after
the builds. `llvm-nm`, `llvm-objdump`, and `llvm-readelf` were required host
inspection paths. Their observed binaries are bound into the normalized
environment hash below, but this record does not claim repository-pinned hashes
for those three inspectors. Each artifact used a separate target directory
under an atomically created, previously nonexistent temporary root with
failure-path cleanup.

Before spawning Cargo, the gate rejected ambient Cargo/Rust flag, wrapper,
tool, target, profile, registry, source, network, and HTTP overrides, as well as
Cargo configuration in the effective home or any directory above the workspace.
It then cleared each child environment and supplied an owned empty `HOME`, an owned empty
`CARGO_HOME`, an isolated target directory, exact compiler/linker/Clang paths,
offline Cargo policy, fixed locale and timestamp, and only the mode-specific
selector or UI/stack flags. Clang receives `--no-default-config`; every
inspection, hashing, and archive helper also runs with an explicitly cleared,
fixed environment. The normalized environment record, including the paths and
observed hashes of the build tools, Clang libraries, and three inspectors,
hashed to
`c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`.

Immediately before the first build and after the thirteenth, the gate hashed a
sorted `SHA-256 path` manifest over exact files `.cargo/config.toml`,
`Cargo.lock`, the workspace/kernel/deepwyrm-abi manifests, `kernel/build.rs`,
and the three tooling identity/harness files, plus every regular file under
`abi/generated`, `crates/deepwyrm-abi/src`, `kernel/arch`, and `kernel/src`.
The test file itself is deliberately outside that recipe. Both observations
were `7d5d9101c3214d4b959e26431ec8589762bf9cb5690a45a8c68e0574b422f909`.
Before the thirteen successful builds, an actual-source target UI build enabled a
checked private probe and required exact compiler error E0382 when code tried
to duplicate the active C2 session. A successful UI build is a gate failure.
The successful builds comprise production and the six canonical selectors,
plus a separate `-Z emit-stack-sizes` selector build for each of the six stack
oracles. For every selector, the complete `.text` disassembly of that stack-size
carrier exactly matched the corresponding canonical plain selector build.

```text
DEEPWYRM_ACCEPTED_CARGO=<accepted-cargo> \
DEEPWYRM_ACCEPTED_RUSTC=<accepted-rustc> \
DEEPWYRM_ACCEPTED_RUST_LLD=<accepted-rust-lld> \
DEEPWYRM_CLANG=/usr/lib/llvm/22/bin/clang \
DEEPWYRM_LLVM_NM=/usr/lib/llvm/22/bin/llvm-nm \
DEEPWYRM_LLVM_OBJDUMP=/usr/lib/llvm/22/bin/llvm-objdump \
DEEPWYRM_LLVM_READELF=/usr/lib/llvm/22/bin/llvm-readelf \
cargo test -p deepwyrm-kernel --test x86_64_memory_target_artifact -- \
  --ignored --exact production_and_six_memory_selector_artifacts_are_separated
```

| Artifact identity | SHA-256 |
|---|---|
| production | `6dc95666792f166d3ae86737770ed50660a2de0887b7c1dfeee8936f4a7cb6a5` |
| `memory-mapping` | `499a3b1bb45b9210886e90f35d11a6d9501466c438a4349573ddc10b4d98e67b` |
| `memory-unmapping` | `7e976b9c7ba4abfc0ac5156084d247be673a11207d4c7778916f8cb20a4bffe0` |
| `memory-permissions` | `30905ac087c27cd8e25e765fa4a167e5e5a1dc88040a97a1ce59a8d3ed4fbb8a` |
| `memory-invalid-pointer` | `7f2a19b4e788ffd2d05170fc11253194bca3389a384cb35615d6cda445f956e0` |
| `memory-user-kernel-isolation` | `04f525800285c61685f238e894790ea16de5674bb3f9d124ade39dde2b967b21` |
| `memory-shared-memory-object` | `9797ff850bf5b601ef842eb3159b6024f4e304a6042fc8ad9a9ce6d2cc8c38be` |

For every selector, the stack oracle separately derives explicit audited
publication, usercopy, normal-terminal, fault-arming, delivered-page-fault
diagnostic, and delivered-page-fault completion paths, then takes their
maximum. Publication enumerates lease replacement preparation, ticket access,
the complete owned-journal validation and mutation/logical-entry branches,
scratch location validation, physical entry access, restoration, backend CAS,
role publication, and the infallible prepared-lease commit. Every artifact
symbol matcher must resolve exactly once; every linear manifest rejects a
duplicate entry and checked-add overflow. Terminal paths include serial
and debug-exit completion, while fault paths retain the selector frames,
hardware and assembly exception snapshot, Rust dispatcher/reporter,
exact-fault classifier, panic serial diagnostic, and completion transport. The
oracle then charges 32 eight-byte return addresses, keeps a separate mandatory
4096-byte architectural reserve, and requires at least 32,768 bytes remain
unused within the 131,072-byte boot stack. The most constrained selector
remained within the bound:

| Selector | Measured chain | Returns | Required reserve | Total | Spare |
|---|---:|---:|---:|---:|---:|
| `memory-mapping` | 49,576 | 256 | 4,096 | 53,928 | 77,144 |
| `memory-unmapping` | 53,328 | 256 | 4,096 | 57,680 | 73,392 |
| `memory-permissions` | 55,264 | 256 | 4,096 | 59,616 | 71,456 |
| `memory-invalid-pointer` | 58,480 | 256 | 4,096 | 62,832 | 68,240 |
| `memory-user-kernel-isolation` | 51,672 | 256 | 4,096 | 56,024 | 75,048 |
| `memory-shared-memory-object` | 54,448 | 256 | 4,096 | 58,800 | 72,272 |

The production ELF contained C2 activation but no C3 runner, fault-site, or
test-completion symbols. Its disassembly contained one balanced entry
normalization, exactly one CR4 write, and the normalization call before
`kernel_main`. Production scanning also rejected all six selector strings,
`DWTEST1`, expected-fault/completion/debug-exit markers, test symbols, and the
debug-exit I/O instruction form. Every selector ELF retained C2 activation, the C3
runner, and both fixed terminal-fault sites. All seven canonical linked artifacts
were byte-distinct. The gate's isolated scratch artifacts were removed after
inspection; the hashes above identify that observed dirty-candidate run rather
than a retained release artifact set. They remain provisional until a clean,
committed candidate is rebuilt with the same gate.

## Pending coordinator-owned functional gate

No VM was operated for this record. The main/root coordinator must run these
selectors through the canonical Wyrmroot loader and Q35/UEFI image, with fresh
bounded serial capture, matching debug-exit status, exact paired revisions, and
artifact/image hashes:

| Selector | Test ID | Required terminal outcome |
|---|---:|---|
| `memory-mapping` | 4 | PASS |
| `memory-unmapping` | 5 | PASS after the exact expected page fault |
| `memory-permissions` | 6 | PASS after the exact expected page fault |
| `memory-invalid-pointer` | 7 | PASS |
| `memory-user-kernel-isolation` | 8 | PASS |
| `memory-shared-memory-object` | 9 | PASS |

Missing, stale, duplicate, mismatched, or nonterminal evidence is
`INFRASTRUCTURE`, never PASS. The source-security candidate disposition is in
[`security/DW0_C_SECURITY_REVIEW.md`](../security/DW0_C_SECURITY_REVIEW.md).
