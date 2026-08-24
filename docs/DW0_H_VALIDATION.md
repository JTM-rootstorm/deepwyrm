# DW0-H Final Validation Record

**Status:** FULL ACCEPTED; DW0 milestone closure criteria satisfied

**Acceptance date:** 2026-08-24

## Accepted product tuple

- Deepwyrm: `5da17d0d2460936e171d0874ffd2262ad4a5cc97`
- Wyrmroot: `c6f2f6c10972983eeb76e3b686f4379cbab08c78`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- production kernel SHA-256: `33d15b5f6f36e28c62b06396db35e1b492eab57167d6a25d858db347b2d208b2`
- final evidence root: `artifacts/dw0-d0/candidate-dw-5da17d0__wyr-c6f2f6c__rust-a92dc7f7`

The later Deepwyrm commits containing this validation record and the final security record are
documentation-only descendants. They do not change the reviewed product bytes or widen the accepted
security surface.

## Functional acceptance

The final D0 evidence contains twelve exact-tuple result records. The default I0 path passes the
complete `bootstrap -> init0 -> hello -> EXITED/0` chain. The four-vCPU I1 path passes schema-v3
validation with evidence mask `255`, 17 contiguous events (`0..16`), all CPUs online, real CPL3
execution on at least two CPUs, cross-CPU wake/descendant execution, operation-specific TLB and
rendezvous acknowledgement, reclaim-after-ack ordering, and zero running-ownership violations.

The I2 selector passes five consecutive unchanged four-vCPU runs. The five negative candidates fail
closed with the exact expected details `0xB0000401` through `0xB0000405` for malformed ELF,
malformed startup, capability count, capability type, and capability rights respectively. Every
result binds the exact Deepwyrm/Wyrmroot/Rust tuple and records `no_host_share = true`.

The production kernel contains no DW0 test/evidence marker and no debug-exit instruction sequence;
production correctness therefore does not depend on the QEMU test exit path.

## Fresh final-acceptance host replay

A final read-only/source-preserving acceptance replay was run from the clean canonical repositories
after D0 closure, using project-local Cargo/target state and offline dependency resolution:

- Deepwyrm `cargo test --locked --workspace --all-targets`: PASS, including 615 kernel unit tests.
- Deepwyrm `cargo fmt --all -- --check`: PASS.
- Deepwyrm `cargo xtask abi check`: PASS; generated ABI has no drift.
- Deepwyrm strict workspace/all-target Clippy with warnings denied: PASS.
- Deepwyrm warning-denied workspace rustdoc without dependencies: PASS.
- Wyrmroot `cargo test --locked --workspace --all-targets`: PASS.
- Wyrmroot xtask: 82 passed, 1 intentionally ignored accepted-toolchain positive environment gate.
- Wyrmroot formatting, strict workspace/all-target Clippy, and warning-denied rustdoc: PASS.

The Wyrmroot replay preserved its canonical pinned Deepwyrm Git source identity and used only the
documented process-local `file://` transport rewrite to the clean local Deepwyrm repository.

## Security and evidence disposition

The exact-model `gpt-daybreak-blue-latest` review at `xhigh` reasoning closed all confirmed
product findings. Final disposition is C0/H0/M0/L0. The original Medium READY transcript issue and
both Low findings were remediated, regression-tested, and rerun through the paired UP/SMP matrix.
See [`../security/DW0_H_SECURITY_REVIEW.md`](../security/DW0_H_SECURITY_REVIEW.md).

The accepted non-product residual is limited to same-UID host mutation of an already-open mode-0400
run snapshot. This is evidence-harness hostile-operator hardening, outside the DW0-H product threat
model, and does not weaken the kernel or Wyrmroot runtime boundary.

No separate sanitizer framework was added for DW0-H. The available acceptance environment instead
ran the existing architecture/source invariants, deterministic concurrency models, adversarial host
suites, live four-vCPU stress, artifact checks, and final Daybreak review. This follows the locked H
coordination rule not to add a new sanitizer/model-checker framework solely to satisfy closure.

## Scope boundary

DW0-H adds no ordinary timer-driven preemption, scheduler fairness/load-balancing policy, real-time
class, compatibility-personality kernel policy, VFS, general kernel `exec(path)`, or host-share boot
shortcut. WYR0-I remains a separate Wyrmroot gate. Physical-hardware and i386 validation are not
claimed by this record.

**Disposition:** DW0-H is FULL ACCEPTED and the Deepwyrm DW0 milestone may close. The concise
post-DW0 limitations and DW1 handoff are recorded in
[`DW0_COMPLETION_REPORT.md`](DW0_COMPLETION_REPORT.md).
