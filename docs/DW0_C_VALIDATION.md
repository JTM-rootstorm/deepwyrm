# DW0-C Validation Record

## Current disposition

The DW0-C physical/virtual-memory source, host, freestanding artifact, and
source-security gates pass through committed Deepwyrm revision
`9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`. Its compatible Wyrmroot
source/pin revision is `15fa42dda23834a80197161249738f001bb2d76f`; the accepted
Wyrmroot evidence descendant is `89235c7feef2a89ef2882ee096428b456496fa39`.

All source, host, freestanding-artifact, cross-repository pin/build-evidence,
and source-security work attainable within the current DW0-C/WYR0-C scope is
complete for this exact pair. This is not formal DW0-C phase closure: no
canonical ESP/image exists yet, no VM was operated for this record, and the six
guest selectors have not executed through the real Wyrmroot loader. Guest, VM,
and completed-phase acceptance therefore remain pending on that image and
coordinator-owned execution. No physical-hardware acceptance claim is made;
VM execution cannot establish one. This record also does not close the earlier
pending DW0-B loader/guest execution gate.

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
- dedicated 16-KiB #DF, NMI, and #MC IST stacks, each preceded by one 4-KiB
  low/down-growth guard page. The first Deep-owned root leaves each guard leaf
  exactly zero, maps all twelve usable pages supervisor RW/NX/non-global with
  default cache selection, revalidates installed TSS/IDT facts, and activates
  the guards with the existing one-shot CR3 publication;
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
terminal-fault, one-shot, CPU-profile, backing-frame, and guarded-IST source
contracts passed. The final locked workspace run included 155 kernel tests and
all integration and compile-fail UI suites. The canonical unfiltered
`cargo xtask test host memory` gate, selector-aware strict all-target/all-
feature Clippy, release checks, formatting, and diff checks also passed. The
explicit target-artifact test is ignored in ordinary host runs and was invoked
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

Immediately before the first build and after the fourteenth, the gate hashed a
sorted `SHA-256 path` manifest over exact files `.cargo/config.toml`,
`Cargo.lock`, the workspace/kernel/deepwyrm-abi manifests, `kernel/build.rs`,
and the three tooling identity/harness files, plus every regular file under
`abi/generated`, `crates/deepwyrm-abi/src`, `kernel/arch`, and `kernel/src`.
The test file itself is deliberately outside that recipe. Both observations
were `1fab0e837ea97866eb5c8e5271da603e3865a6a8c55d27b7d697d8bfd306468e`.
Before the fourteen successful builds, an actual-source target UI build enabled a
checked private probe and required exact compiler error E0382 when code tried
to duplicate the active C2 session. A successful UI build is a gate failure.
The successful builds comprise production and the six canonical selectors,
plus separate `-Z emit-stack-sizes` builds for production and each selector.
For every mode, the complete `.text` disassembly of the stack-size carrier
exactly matched its canonical plain build.

```text
TMPDIR=/home/mike/Documents/Programming/OS-Project/deepwyrm/target/ist-oracle-tmp \
DEEPWYRM_ACCEPTED_CARGO=/home/mike/Documents/Programming/OS-Project/.artifacts/rust/RUST-PHASE0B-TOOLCHAIN-001/8bab26f4/63e532b52e6d4c2e/toolchains/wyrmroot-1.97.1-8bab26f4/bin/cargo \
DEEPWYRM_ACCEPTED_RUSTC=/home/mike/Documents/Programming/OS-Project/.artifacts/rust/RUST-PHASE0B-TOOLCHAIN-001/8bab26f4/63e532b52e6d4c2e/toolchains/wyrmroot-1.97.1-8bab26f4/bin/rustc \
DEEPWYRM_ACCEPTED_RUST_LLD=/home/mike/Documents/Programming/OS-Project/.artifacts/rust/RUST-PHASE0B-TOOLCHAIN-001/8bab26f4/63e532b52e6d4c2e/toolchains/wyrmroot-1.97.1-8bab26f4/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld \
DEEPWYRM_CLANG=/usr/lib/llvm/22/bin/clang \
DEEPWYRM_LLVM_NM=/usr/lib/llvm/22/bin/llvm-nm \
DEEPWYRM_LLVM_OBJDUMP=/usr/lib/llvm/22/bin/llvm-objdump \
DEEPWYRM_LLVM_READELF=/usr/lib/llvm/22/bin/llvm-readelf \
cargo test --locked -p deepwyrm-kernel \
  --test x86_64_memory_target_artifact -- \
  --ignored --exact production_and_six_memory_selector_artifacts_are_separated \
  --nocapture
```

The accepted run used
`/home/mike/Documents/Programming/OS-Project/deepwyrm/target/ist-oracle-tmp`
as its repository-owned `TMPDIR`; the accepted Cargo, rustc, and rust-lld came
from request `RUST-PHASE0B-TOOLCHAIN-001`, and the LLVM inspection paths were
the `/usr/lib/llvm/22/bin` paths shown above.

| Artifact identity | SHA-256 |
|---|---|
| production | `2c20b97290385fd171f4ec79d02eddca58ec3e4fa452631e10a2620d63596d5e` |
| `memory-mapping` | `8b77197bb731d66954f882936544b681f4e0f8b3d00e867111960b42bbc283ce` |
| `memory-unmapping` | `822249003e8322d74063e8157ce8d771cc0959afbcab5a1e44b37912ddc69bb9` |
| `memory-permissions` | `bb04f72b2c833285c38b4b1ff2ee9fff43ce520630ea76be5ba8b359ad1ff80b` |
| `memory-invalid-pointer` | `77935e4ce8b53c8057c06eb38f9e37a37623d0eb3a4d384bf49dc453af2ffd68` |
| `memory-user-kernel-isolation` | `679ae4cabd92223ff350763fe3e650782d47ce25d460c0db33a6b1d011a62bdf` |
| `memory-shared-memory-object` | `18aec22a4a3d452f6d7efc28055bb6bddb2fd95584eaa3c2c2059a566316d082` |

These are the current guarded-IST artifact identities for the exact source
state committed as `9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`.

### Historical pre-guard artifact checkpoint

The preceding clean `b263a7a912c79b9e7d4b2439370417d7ae2ee076`
checkpoint produced the following superseded identities. They are retained for
provenance only and are not compatible evidence for the guarded-IST revision:

Its build-input manifest was
`7d5d9101c3214d4b959e26431ec8589762bf9cb5690a45a8c68e0574b422f909`;
the normalized environment hash was the same
`c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`
identity recorded for the current gate.

| Artifact identity | Historical SHA-256 |
|---|---|
| production | `6dc95666792f166d3ae86737770ed50660a2de0887b7c1dfeee8936f4a7cb6a5` |
| `memory-mapping` | `499a3b1bb45b9210886e90f35d11a6d9501466c438a4349573ddc10b4d98e67b` |
| `memory-unmapping` | `7e976b9c7ba4abfc0ac5156084d247be673a11207d4c7778916f8cb20a4bffe0` |
| `memory-permissions` | `30905ac087c27cd8e25e765fa4a167e5e5a1dc88040a97a1ce59a8d3ed4fbb8a` |
| `memory-invalid-pointer` | `7f2a19b4e788ffd2d05170fc11253194bca3389a384cb35615d6cda445f956e0` |
| `memory-user-kernel-isolation` | `04f525800285c61685f238e894790ea16de5674bb3f9d124ade39dde2b967b21` |
| `memory-shared-memory-object` | `9797ff850bf5b601ef842eb3159b6024f4e304a6042fc8ad9a9ce6d2cc8c38be` |

Wyrmroot's superseded acknowledgment of that pre-guard checkpoint used
source/pin revision `6230d2c26b0260add3fad1e1cc55c878c0362ab5`, evidence
descendant `737728d256c8b3a246889d840903ac751f187ef6`, and pinned Deepwyrm
`b263a7a912c79b9e7d4b2439370417d7ae2ee076`. Its historical loader EFI was
`c2d15d31db924a235a46730aca3e9dbf4b8edf58c2d6ceddb7bae9e82f776675`, PDB
`810489525e70d3f57447709b523444ea018738d2b22876ed2cd9b1a5de486e6f`, and
schema-2 provenance
`47e7627da08fc783c74c21d705ed5c01e55fced4f9da320e876025865b51fe5a`.
Those revisions and artifacts remain historical and must not be paired with
the guarded Deepwyrm commit.

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
| `memory-mapping` | 49,592 | 256 | 4,096 | 53,944 | 77,128 |
| `memory-unmapping` | 53,344 | 256 | 4,096 | 57,696 | 73,376 |
| `memory-permissions` | 55,280 | 256 | 4,096 | 59,632 | 71,440 |
| `memory-invalid-pointer` | 58,496 | 256 | 4,096 | 62,848 | 68,224 |
| `memory-user-kernel-isolation` | 51,688 | 256 | 4,096 | 56,040 | 75,032 |
| `memory-shared-memory-object` | 54,464 | 256 | 4,096 | 58,816 | 72,256 |

The separate guarded-IST oracle enumerates the maximum production and selector
exception paths, including the previously omitted live formatter-padding
branch `pad_integral -> Com1::write_char -> encode_utf8_raw ->
from_raw_parts_mut::precondition_check -> is_aligned_to`. A shared builder used
by both validators and its host regression prevent that branch from silently
dropping out of the maximum candidate set.

| Mode | Panic chain | Other terminal chain | Entry bytes | Depth | Returns | Used | Required reserve | Spare |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| production | 2,176 | 904 halt | 207 | 19 | 152 | 2,535 | 4,096 | 13,849 |
| each selector | 2,272 | 1,685 completion | 207 | 19 | 152 | 2,631 | 4,096 | 13,753 |

The production ELF contained C2 activation but no C3 runner, fault-site, or
test-completion symbols. Its disassembly contained one balanced entry
normalization, exactly one CR4 write, and the normalization call before
`kernel_main`. Production scanning also rejected all six selector strings,
`DWTEST1`, expected-fault/completion/debug-exit markers, test symbols, and the
debug-exit I/O instruction form. Every selector ELF retained C2 activation, the C3
runner, and both fixed terminal-fault sites. All seven canonical linked artifacts
were byte-distinct. ELF inspection proved exactly three non-RWX `PT_LOAD`
segments, the expected 12-KiB writable `p_memsz` growth, the linked page-aligned
guard-region geometry, and three complete 16-KiB usable IST stacks. Source/host
graph tests plus artifact/code checks verify that the first Deep-owned root
leaves the three guard PTEs exactly zero and maps the twelve usable pages with
the required permissions. The gate's isolated scratch artifacts were removed
after inspection; the hashes above identify the exact guarded source state,
not a retained release artifact set.

## Compatible Wyrmroot evidence

Wyrmroot source/pin revision
`15fa42dda23834a80197161249738f001bb2d76f` consumes Deepwyrm
`9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`. Its accepted evidence descendant
is `89235c7feef2a89ef2882ee096428b456496fa39`:

| Wyrmroot evidence | SHA-256 |
|---|---|
| loader EFI | `e47f6aaae15d5e4f8cf34fcfa827cf95ff43e5ec1bab288b02bc65b98800c031` |
| loader PDB | `7655e2c3102d54268703617132aaf86acf47484c4ec7595e6cafdac67d26e911` |
| schema-2 provenance | `384841ca8c3c867a87e23e27d8ec5420ce47fc2db0b1ce3aafa276f9e90047be` |
| PE inspection report | `f616d99b1385ed13d3d59091f5c02db5966c0228532ea632868794831f151b11` |

Wyrmroot's bounded guarded-IST acknowledgment review found no new Critical,
High, Medium, or Low findings. This is not an absolute zero-findings statement:
existing accepted Medium limitations remain recorded in Wyrmroot's
`security/WYR0_B_SECURITY_REVIEW.md`. This revision pair and its artifact
records establish source/pin and loader-build compatibility only; they do not
establish an assembled image or guest execution.

## Pending coordinator-owned functional gate

No canonical ESP/image exists in the workspace and no VM was operated for this
record. Once Wyrmroot provides the canonical image path, the main/root
coordinator must run these selectors through the Wyrmroot loader and Q35/UEFI
image, with fresh bounded serial capture, matching debug-exit status, the exact
revision pair above, and artifact/image hashes:

| Selector | Test ID | Required terminal outcome |
|---|---:|---|
| `memory-mapping` | 4 | PASS |
| `memory-unmapping` | 5 | PASS after the exact expected page fault |
| `memory-permissions` | 6 | PASS after the exact expected page fault |
| `memory-invalid-pointer` | 7 | PASS |
| `memory-user-kernel-isolation` | 8 | PASS |
| `memory-shared-memory-object` | 9 | PASS |

Missing, stale, duplicate, mismatched, or nonterminal evidence is
`INFRASTRUCTURE`, never PASS. The source-security disposition is in
[`security/DW0_C_SECURITY_REVIEW.md`](../security/DW0_C_SECURITY_REVIEW.md).
Successful execution can satisfy the named DW0-C guest/VM evidence, but formal
DW0-C closure also requires the separate earlier DW0-B loader/guest gate to
close with the exact evidence required by that record. It cannot establish
physical-hardware acceptance.
