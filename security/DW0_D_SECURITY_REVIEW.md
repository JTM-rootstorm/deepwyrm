# DW0-D Security Review Record

## Disposition

**SOFT ACCEPT for the DW0-D host/core phase, pending proper Daybreak Blue /
Dawnbreak exact-candidate scanning.**

The manually reviewed implementation candidate is
`fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e`, reviewed on 2026-08-18.
The detailed manual review, tooling limits, threat-surface walk, confirmed
properties, and finding rationale are recorded in
[`DW0_D7_SECURITY_REVIEW_NOTE.md`](DW0_D7_SECURITY_REVIEW_NOTE.md).

The D8 functional/freestanding validation candidate
`db09ce173adfb6850765fe2a4547d50a1050ac10` is a documentation-only
descendant of that reviewed code candidate. The D8 records added after that
revision do not alter the reviewed object/handle implementation.

This record deliberately does not claim that `gpt-daybreak-blue-latest`,
Daybreak Blue, or Dawnbreak ran. The coordinator has authorized manual D7
soft-accept so development can continue while the specialized scan remains
pending.

## Security surfaces accepted for D

Manual review and adversarial tests support the following D claims:

- generated rights compatibility remains the canonical policy source;
- object/handle identity uses checked generation-based stale defense;
- strong reference tokens are move-only and cannot be reconstructed from IDs;
- `ObjectRegistry` owns generic strong-liveness and exact-zero finalization;
- handle lookup, close, duplicate, and drain preserve reference accounting;
- duplicate cannot increase rights and publishes only after fallible work;
- `INSPECT` gates object-info topic/type disclosure;
- MemoryObject backing retains typed reclamation authority;
- mapping authorization owns a strong pin before publication;
- mapping split/merge deltas are retained before publication and rolled back;
- committed mappings retain captured authority after source-handle close;
- effective mappings remain non-WX and immutable backing remains non-writable;
- process-local handles do not depend on raw global uniqueness; and
- the D object/handle/lifetime implementation adds no new production unsafe
  memory-manipulation boundary.

D7 remediation strengthened `cargo xtask test host handles` so MemoryObject
lifetime coverage is explicit and object/memory/physical compile-fail authority
suites are part of the focused gate.

No confirmed Critical or High vulnerability was found. No currently
user-reachable Medium vulnerability was found within implemented DW0-D scope.

## Accepted residuals

### D7-R1: generic versus typed finalizer dispatch

A trusted future kernel caller can technically bypass MemoryObject-specific
cleanup by directly completing a generic `FinalRelease`. Current production
callers do not do so and userspace has no D path to trigger it. Treat this as a
Medium-priority Dawnbreak/DW0-E integration target; prefer typed finalizer
dispatch before generic process teardown exists.
### D7-R2: MemoryObject construction sequencing

Payload registration and first generic handle publication are separate safe
crate operations, and multiple `MemoryObjectAuthority` values can technically
exist. Intended callers bind one payload before publishing one handle. This is
not presently user-triggerable, but DW0-E should make the construction sequence
and sole payload authority mechanically explicit. Review priority is Medium.

### D7-R3: mapping-lease generation exhaustion

Internal mapping-lease generation exhaustion fails closed but does not retire
and skip the exhausted slot. This is a roughly 2^32-reuse theoretical
availability edge, not stale-capability resurrection or authority escalation.
Accepted as Low for D; later lifetime hardening may add retirement.

### D7-R4: explicit token release discipline

Move-only reference tokens can still be accidentally dropped by trusted kernel
code without decrementing the registry count. That can leak liveness/resources
but cannot create a UAF or additional authority. Current D paths release tokens
explicitly and transaction guards cover mapping replacements. Accepted as Low;
future error-heavy E/F paths should preserve guarded cleanup discipline.

## Evidence and tooling limits

The reviewed candidate passed focused handles, full workspace tests, strict
Clippy, rustdoc warnings-as-errors, ABI drift, formatting/diff hygiene, and
optimized release-mode D tests. D8 then reran the complete host gate and the
accepted-toolchain x86_64 production plus six-selector artifact oracle.

Miri, cargo-audit, cargo-deny, cargo-geiger, Semgrep, and CodeQL were not
installed and did not run. The normal/build Cargo dependency graph contains no
third-party crates in the DW0-D runtime/build stack beyond local
`deepwyrm-abi`.
## Final D security disposition

The manual D7 result satisfies the coordinator-authorized soft-accept policy for
continuing beyond DW0-D. It does not satisfy the canonical requirement for a
proper specialized exact-candidate security scan before final DW0 milestone
closure.

DW0-E may proceed provided it treats D7-R1 and D7-R2 as explicit integration
hazards and wraps the reviewed D business logic rather than reimplementing it.
DW0-F/H must separately review transfer, rollback, synchronization, teardown,
and SMP-visible behavior when those surfaces exist.

No security blocker remains inside DW0-D beyond the explicitly accepted
residuals and pending proper Dawnbreak review above. The deferred formal review
is also indexed in [`DW0_DEFERRED_DAYBREAK_REVIEWS.md`](DW0_DEFERRED_DAYBREAK_REVIEWS.md).
