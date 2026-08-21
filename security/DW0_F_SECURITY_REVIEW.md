# DW0-F Daybreak Security Review

## Disposition

**PASS for the exact DW0-F13 product candidate.**

The reviewed product pair is:

- Deepwyrm `96fe554c0e4cb21335df4bbf5ebd2de1f9df21c5`, tree
  `0b7637e6ce8b236ff36699dddf8f3a2a659cf9c0`;
- Wyrmroot `edc1071f78f4418c05e5bd0762b1c3fb760df094`.

The cumulative review found two Medium product-code defects. Both were fixed,
given regression coverage, and re-reviewed on the exact resulting Deepwyrm
candidate. No Critical, High, or unresolved Medium product-security finding
remains. One Wyrmroot defense-in-depth Low is accepted below.

This record closes the F13 security gate. It does not close F14 final evidence,
DW0-H SMP/per-CPU review, physical-hardware acceptance, or a future runnable
userspace-exception path.

## Scope boundary

Per coordinator direction, F13 security conclusions primarily cover Deepwyrm
kernel/product code and paired Wyrmroot product and build-consumer code.
Coordination scripts, libvirt normalization, host configuration, and evidence
plumbing are operational reliability or provenance concerns unless they
provide a direct way to falsify, bypass, or compromise the claimed product
result. They are not independently promoted into F13 kernel/Wyrmroot findings.

The VM coordinator must still remain bounded, preserve evidence, and restore
the designated domain safely. That operational requirement does not turn the
effective libvirt XML into a product-security API or require every benign
libvirt-generated default to be enumerated as kernel security policy.

## Review lanes

Every substantive product-security lane used exact model
`gpt-daybreak-blue-latest` on 2026-08-21 and reported its reasoning effort,
scope, exact revision or diff, tests, and disposition directly to the root
coordinator.

| Lane | Reasoning | Exact review target | Final result |
|---|---:|---|---|
| Deepwyrm authority, Channel, handles, waits, atomic wait, process creation | High | F12 implementation `6de5af17` through `a6f9a954` | PASS, C0/H0/M0/L0 |
| Deepwyrm execution, scheduler, exception termination, stack/context ownership | xhigh | exact candidate `96fe554c`; remediation diff SHA-256 `2ee4b8f6611b3808a6d1eea0d7a6c3c795eb3cfd3965bd65795a318ab6914f95` | PASS, prior Medium closed |
| Deepwyrm selector and production/test separation | High | `a6f9a954..96fe554c` | PASS, prior Medium closed |
| Wyrmroot ABI pin and Cargo metadata consumer hardening | High | `b6ed32f1..edc1071f` | PASS, C0/H0/M0; one accepted Low |

No external vulnerability scanner was installed or used. The evidence consists
of exact-diff Daybreak source review, existing project-local ownership and
compile-fail contracts, focused regressions, broad host tests, warning-denied
builds, and the accepted-target artifact oracle.

## Confirmed findings and remediation

### F13-01: reserved E selectors were advertised as runnable

**Original severity: Medium. Status: fixed and exact-candidate re-review PASS.**

Guest selectors 11 and 12 were classified as implemented in the manifest even
though the E guest dispatcher implements selector 10 only and routes 11/12 to
the failure path. This could let build/evidence tooling claim executable guest
coverage that did not exist and substantively affected the historical E
evidence surface.

Commit `68313e5c8bd4f4f005d8347f8646089678089585` makes IDs 11 and 12 reserved
in the schema-owned guest manifest. xtask and kernel contract regressions now
prove that only selector 10 is runnable and that 11/12 are rejected before
artifact selection or guest dispatch.

The targeted Daybreak re-review at final candidate `96fe554c` passed with
C0/H0/M0/L0. The transient DW0-E reopen is therefore closed. No VM run is
required to prove that reserved selectors are unavailable; this record makes
no guest-execution claim for either selector.

### F13-02: current exception termination could reclaim its active stack

**Original severity: Medium. Status: fixed and exact-candidate re-review PASS.**

The exception-termination API could immediately retire a batch containing the
physically current Thread and reclaim its stack/context while Rust frames were
still executing on that stack. The API is currently dormant because selector
12 remains reserved, but its ownership contract was unsound.

Commit `96fe554c0e4cb21335df4bbf5ebd2de1f9df21c5` rejects current-containing
immediate retirement before scheduler or resource mutation, returns a
move-only deferred-current token from exception termination, verifies exact
scheduler-current identity and batch membership on consumption, and orders
group retirement so non-current batches complete before the exactly-one
current batch.

Regressions prove that a rejected immediate retirement preserves Running state
and live stack/context ownership, that the deferred token is single-consume and
fail-stops if abandoned, and that current resources cannot be reused before
deferred consumption. Exact-candidate Daybreak re-review passed C0/H0/M0/L0.

When selector 12 or another live exception caller is implemented, it requires
a new target/VM gate covering CPL3 fault, divergent reaper handoff, deferred
reclaim, sibling scheduling, GS correctness, and no return through or reuse of
the retired stack. That future integration gate is not evidence debt for the
currently reserved path.

## Confirmed product properties

The cumulative review supports these bounded claims on the exact candidate:

- Timer readiness is captured while Timer state remains locked, excluding a
  stale-expiry/rearm/new-waiter publication race.
- Channel publication repeats bounded reachability under the same lock that
  commits the queue insertion, and exact batch rollback preserves MOVE
  authority on every pre-commit failure.
- Receive capacity and `BUFFER_TOO_SMALL` failures preserve the head datagram
  and transfer tokens without partial consumption.
- Generic waits publish before their final state recheck, arbitrate winners by
  exact generation, and remove terminal registrations without stale wakeups.
- Atomic waits retain stable mapping identity and pins across predicate recheck,
  FIFO wake, timeout, terminal cleanup, and mapping ABA boundaries.
- Public `process_create` derives authority from handles, reduces rights
  monotonically, keeps hierarchy state unpublished through fallible work, and
  commits child/root/bootstrap publication as an all-or-nothing transaction.
- Scheduler wake keys and Timer artifact resolution remain bound to their
  issuing execution domain and exact stack owner.
- Production artifacts exclude F guest runtime, selector identity,
  debug-exit, and synthetic user blobs; each implemented selector remains
  independently identified and inspected.
- Wyrmroot structural pin, workspace-member, Cargo package, and generated ABI
  consumer checks reject comment, metadata, package, and multiline decoys.

The review independently rechecked the E8-F1 SWAPGS ordering and found no F
regression. No D surface was substantively reopened.

## Validation evidence

At exact Deepwyrm candidate `96fe554c`:

- full kernel unit suite: 463 passed;
- x86_64 syscall contracts: 18 passed;
- x86_64 exception contracts: 9 passed;
- x86_64 entry/selector contracts: 12 passed;
- focused execution tests: 14 passed;
- strict Clippy, rustdoc warning denial, formatting, ABI checks, focused host
  handle/memory/task/IPC gates, workspace all-target tests, and `git diff
  --check`: passed.

The accepted-toolchain oracle passed and recorded:

- production kernel SHA-256:
  `a57e67ede53ea6c7b14cf968f4ef6bd2fedbd446640e2f5a598ab491b21363f3`;
- selector-13 kernel SHA-256:
  `db6cd496c9253f63346c54c58aa919d1e49aa3db4d34d880e1a88c89a9efee37`;
- selector-13 user ELF SHA-256:
  `60c32bd4b3b2d04baccd07a4d7f654fcdf6a29a8ad145bffd349f375b16d1b3f`;
- selector-16 kernel SHA-256:
  `8aed48d090185e3b9effe2e5ca53870116dbb5c1db5069b1d41e6a4b068348ae`;
- selector-16 user ELF SHA-256:
  `0e29b37079cfabf931c0b9762d16d075280db8a8812fee6b2d67d47b1c65deda`;
- build-input manifest SHA-256:
  `660c6ffb2754ed76073f66f70e5932b9cbc70468e1c15f3a8e440dfdc00a61e9`;
- normalized environment SHA-256:
  `de9cf952e07da0d8d913e9a6635d711e613e51104435a9b3082f196916e96c8e`.

The narrow F13 remediations do not change the Deepwyrm ABI trees consumed by
Wyrmroot: the `abi` and `crates/deepwyrm-abi` trees are byte-identical between
Wyrmroot's pinned Deepwyrm `6de5af17` and the F13 candidate. Wyrmroot therefore
requires no consumer repin for the security disposition.

The prior F12 paired VM evidence remains the functional execution baseline.
The F13 product fixes do not create a runnable selector-11/12 path and do not
change the accepted selector-13 scenario's ABI contract. A fresh FD-bound
coordinator experiment did not produce guest evidence and is not cited as a
product-security result. Its final failed test instance was explicitly
destroyed, and the designated domain was restored shut off with UUID
`33005e22-d7c2-4b13-b1ac-b82eda95e584` and approved inactive-XML SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.

## Accepted residual risks and future gates

- **Low — Wyrmroot metadata path reads:** manifest/lock reads have structural
  path checks but are not explicitly size-bounded or inode-bound across the
  complete read, leaving denial-of-service and same-user path-swap
  defense-in-depth gaps. Future hardening should use bounded descriptor reads
  and add symlink/swap fixtures.
- **Phase-bounded — SMP/per-CPU:** current execution proofs assume the reviewed
  single-BSP model. DW0-H must re-review scheduler, GS, runtime pointer, reaper,
  timer, and cross-CPU publication assumptions before SMP activation.
- **Future feature gate — live exception delivery:** implementing selector 12
  or any nonterminal exception path reopens the exception/reaper/GS integration
  surface and requires target and designated-VM evidence.
- **Operational follow-up:** the experimental FD-bound coordinator path and
  libvirt state parsing are not F13 product-security gates. They must not be
  cited as accepted VM evidence until their own bounded live execution and
  automatic restoration path pass.

With these bounds, DW0-F13 is security-closed on the exact product pair above.
DW0-F14 final evidence and phase disposition remain open.
