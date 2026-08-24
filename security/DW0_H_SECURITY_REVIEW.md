# DW0-H Security Review

**Status:** Final — PASS  
**Review date:** 2026-08-24  
**Reviewer model:** `gpt-daybreak-blue-latest`  
**Reasoning effort:** `xhigh`

## Reviewed revisions

Final tuple:

- Coordination root: `9a1c6ffc7b4924bc9b2186c528f767f8d196cabb`
- Deepwyrm: `5da17d0d2460936e171d0874ffd2262ad4a5cc97`
- Wyrmroot: `c6f2f6c10972983eeb76e3b686f4379cbab08c78`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`

Initial reviewed tuple:

- Deepwyrm: `08b6c99955d69a4febeead23f96db50051a80f82`
- Wyrmroot: `903fb7a20cca902337c9512ed49cd9aa0b8a5b5d`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`

Rust did not change during DW0-H or remediation. No unrelated Rust history was reviewed.

Remediation commits:

- Deepwyrm `cf2dd5f067632146088f63f1b4faa444abf0e4f8`
- Deepwyrm `5da17d0d2460936e171d0874ffd2262ad4a5cc97`
- Wyrmroot `f311d9d19d29be0495d2fb1b69679615ec7983e8`
- Wyrmroot `6be582df313749b8c22f9fecd42364e3c5b14a0c`
- Wyrmroot `9593466aabecb76733ea845fc45377fe914bdc6a`
- Wyrmroot `c6f2f6c10972983eeb76e3b686f4379cbab08c78`

All reviewed worktrees were clean.

## Scope

The review covered:

- SMP aliasing and per-CPU state;
- AP startup and privileged entry;
- IPI, rendezvous, shootdown, residency, and reclaim ordering;
- remote task and address-space teardown;
- object, handle, IPC, wait, timer, and supervision races;
- H-touched unsafe code;
- hostile ELF, bootfs, and startup parsing;
- W^X materialization;
- rollback and partial-child cleanup;
- capability minimization and descendant authority; and
- image and evidence artifact selection.

## Severity disposition

| Severity | Open product findings |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

## Remediated findings

### DB-DW0H-001 — READY transcript could skip a queued datagram

**Initial severity:** Medium  
**Disposition:** Closed

The initial implementation could accept `READABLE | PEER_CLOSED`, receive one READY, and accept
closure without freshly observing whether another datagram remained.

Wyrmroot now performs a fresh level-triggered wait after every receive. Peer closure is accepted
only from an observation containing no `READABLE` bit:

- `crates/wyrmroot-runtime/src/supervision.rs:234-266`
- `crates/wyrmroot-runtime/src/supervision.rs:295-357`

Regression coverage rejects duplicate, malformed, and capability-bearing second datagrams in
normal and exit-first paths:

- `crates/wyrmroot-runtime/src/supervision.rs:578-589`
- `crates/wyrmroot-runtime/src/supervision.rs:639-727`

The state machine remains bounded and fail-closed.

### DB-DW0H-002 — live scratch target remained bound to CPU0

**Initial severity:** Low  
**Disposition:** Closed

Live scratch targets now derive their immutable binding from the hardware-current GS-selected CPU
identity and re-attest that identity during leaf operations:

- `kernel/src/arch/x86_64/mm/activation.rs:184-202`
- `kernel/src/arch/x86_64/mm/activation.rs:630-675`
- `kernel/src/arch/x86_64/mm/activation.rs:1490-1495`

The fixed bootstrap binding is separately typed and permanently retired after BSP runtime identity
installation but before AP release:

- `kernel/src/arch/x86_64/mm/activation.rs:1527-1540`
- `kernel/src/lib.rs:380-411`

Tests cover disjoint CPU bindings, migration rejection, and independently cleared leaves. The
follow-up `5da17d0` removes only a stale mutable test-support receiver and does not weaken the
ownership boundary.

### DB-DW0H-003 — path checks did not identify the media QEMU consumed

**Initial severity:** Low, evidence/tooling  
**Disposition:** Original path-substitution defect closed; non-product residual accepted

Wyrmroot now:

- anchors output traversal to opened request-root and parent directory descriptors;
- rejects symlink components and creates fresh ancestors through those descriptors;
- copies inputs into run-local snapshots;
- passes inherited stable descriptors to QEMU through `/proc/self/fd`;
- hashes and revalidates the opened snapshot objects; and
- bounds ESP snapshots to the canonical 128 MiB image size.

Relevant implementation:

- `tools/xtask/src/h_request.rs:124-375`
- `tools/xtask/src/h_integration.rs:1228-1470`
- `tools/xtask/src/h_integration.rs:2205-2364`

Path replacement and ancestor-redirection races no longer change the inode QEMU opens.

Residual limitation: snapshot “immutability” uses owner mode `0400` and digest revalidation at
`h_integration.rs:2274-2326`. A malicious same-UID process could change permissions, mutate the
same inode while QEMU runs, and restore it before final hashing. Hostile-operator hardening of the
harness is outside the product-security scope established for DW0-H. If stronger evidence
authenticity is later required, use sealed `memfd` objects, fs-verity, or a separate immutable
ownership boundary.

## Final evidence

Evidence root:

`artifacts/dw0-d0/candidate-dw-5da17d0__wyr-c6f2f6c__rust-a92dc7f7`

All twelve result records identify the exact final tuple and set `no_host_share = true`. Recomputed
request, provenance, bootfs, ESP, kernel, and symbols hashes match every result record. All QEMU
stderr logs are empty.

Results:

- I0 default: PASS, normal outcome, detail `0`
- I1 SMP: PASS, proof mask `255`
- I2 SMP: five repeated PASSes
- malformed ELF: expected fail `0xB0000401`
- malformed startup: expected fail `0xB0000402`
- capability count: expected fail `0xB0000403`
- capability type: expected fail `0xB0000404`
- capability rights: expected fail `0xB0000405`

### I1 event-count determination

The I1 transcript contains 17 contiguous events, sequence `0..16`. This is valid.

It proves:

- `CPU_ONLINE` exactly once for CPUs 0–3;
- CPL3 syscall execution on CPUs 0 and 1 with distinct nonzero tokens;
- TLB publication mask `0x1` and exact CPU0 acknowledgement;
- cross-CPU wake from CPU0 to CPU1;
- rendezvous mask `0x2` and exact CPU1 acknowledgement;
- parent blocked on CPU0 followed by descendant execution on CPU1;
- child exit on CPU1 followed by cleanup on CPU0;
- reclaim only after the exact TLB and rendezvous acknowledgements; and
- a final zero-violation running invariant.

The earlier V0 transcript's eighteenth event was an additional CPL3 participation event on a third
CPU. The contract requires at least two distinct CPL3 CPUs and tokens, so its absence does not
weaken any required proof.

### Production kernel

Production kernel:

`.tmp/DW0-D0/deep-5da17d0-production/x86_64-unknown-none/release/deepwyrm-kernel`

SHA-256:

`33d15b5f6f36e28c62b06396db35e1b492eab57167d6a25d858db347b2d208b2`

Independent inspection found no `DWTEST1`, `DWEVID1`, SMP test-selector strings, or immediate
debug-exit port `0xF4` sequence.

Reported validation also includes both complete locked workspaces, focused tests, strict Clippy,
warning-denied rustdoc, source contracts, generated ABI drift checks, artifact gates, and
formatting/diff checks.

## Final disposition

DW0-H D0 passes at the exact final tuple.

No Critical, High, Medium, or Low product-security findings remain open. The accepted non-product
same-UID evidence-tooling residual does not weaken the kernel or Wyrmroot userspace security
boundary and does not block closure.
