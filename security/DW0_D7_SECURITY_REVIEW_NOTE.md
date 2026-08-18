# DW0-D7 Manual Security Review Note

## Review state

**Disposition: SOFT ACCEPT, pending proper Daybreak Blue / Dawnbreak review.**

This manual review covers Deepwyrm code candidate
`fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e` on 2026-08-18. The DW0-D0
architecture baseline is `4fb6e1fad9f32b8b48ff09ed4bc2b5422c2dba52`; the reviewed
candidate includes D1-D6 implementation, the subsequent structural refactor,
and a D7 hardening of the focused handle-security host gate.

This is an intermediate manual/security-tool review permitted by the DW0 plan
when Daybreak Blue is unavailable. It is not a substitute for the required
exact-candidate Dawnbreak scan and does not satisfy final DW0 milestone closure.
The documentation commit containing this note is intended to be a
source-behavior-neutral descendant of the reviewed candidate.

## Review method and tool limits

The review traced the D0 invariants through the canonical rights schema,
generator, object registry, handle table, D5 services, MemoryObject lifetime
ownership, mapping authorization, address-region replacement transactions, and
D6 adversarial/model gates. Production `unsafe`, authority visibility, panic /
fail-stop paths, integer/range arithmetic, and low-level escape patterns were
also reviewed.

The specialized local scanners `cargo-audit`, `cargo-deny`, `cargo-geiger`,
Miri, Semgrep, and CodeQL are not installed on the review host. No claim is
made that they ran. `cargo tree --workspace --edges normal,build` showed no
third-party runtime/build crate dependency in the DW0-D stack: Deepwyrm kernel
uses the local `deepwyrm-abi` crate and the host tools are dependency-free.

An additional `clippy::arithmetic_side_effects` advisory pass found only one
D-specific warning in production, the bounded `final_release_count += 1` in
`HandleTable::drain`; the count is bounded by table capacity and one increment
per removed live entry. No D production use of raw pointers, transmute,
`get_unchecked`, `mem::forget`, `ManuallyDrop`, inline assembly, or unchecked
memory construction was found.

## Threat surfaces reviewed

- generated object/right compatibility and syscall-required-right consistency;
- opaque object identities, domain separation, generation retirement, and ABA;
- move-only creation, handle, internal, and final-release reference tokens;
- checked strong-reference transitions, exact-zero finalization, and slot reuse;
- caller-local handle encoding, stale/malformed handle rejection, and teardown;
- object type checks, rights syntax, compatibility, held-right checks, and
  rights-reducing duplication;
- D5 validation/status ordering and `INSPECT`-gated object information;
- typed MemoryObject backing ownership and immutable-module reclamation policy;
- move-only region-bound `MapAuthorization` and captured permission ceilings;
- mapping split/merge pin deltas, rollback, W^X aliases, and publication order;
- address-region bounds, page zero, overlap, and publisher identity; and
- compile-fail authority boundaries around object references, mapping tokens,
  frame ownership, and architecture publication.

## Confirmed properties

The reviewed source implements the central D0 authority rules directly:

- `ObjectRegistry` is the sole strong-reference counter and transitions a live
  object to `Finalizing` before issuing one consuming `FinalRelease`.
- Object and handle generations advance with checked arithmetic; exhaustion of
  those public capability slots retires the slot rather than permitting ABA.
- Strong reference tokens and `MapAuthorization` are non-`Copy`/non-`Clone`;
  compile-fail tests also reject token fabrication and identity-only retain.
- Handle duplicate validates syntax, source identity, compatibility,
  `DUPLICATE`, and subset authority before destination publication.
- Handle close removes the table entry before releasing its generic reference;
  impossible registry divergence is fail-stop rather than recoverable.
- Mapping authorization owns the lookup pin before publication and captures the
  source READ/WRITE/EXECUTE ceiling for later protection changes.
- Mapping replacement pre-retains positive reference deltas, leaves old lease
  pins committed until page-table publication succeeds, and has explicit
  commit/rollback completion enforced by `Drop`.
- Effective mappings remain readable and non-WX, with object-wide W/X alias
  rejection and immutable boot-module write rejection.
- `object_get_info_v1` requires `INSPECT` before topic recognition/type probing,
  and task-state information remains reserved rather than fabricated in D.

No new production `unsafe` implementation was introduced by the DW0-D
object/handle/lifetime work. The D-adjacent unsafe boundary is the sealed
address-space publisher/root binding inherited from DW0-C and already covered
by ownership compile-fail and target-artifact tests.

## Remediated D7 finding

### D7-F1 - focused host gate did not explicitly bind all authority tests

The D6 `test host handles` selector relied on Cargo substring filtering for
MemoryObject lifetime coverage and ran only kernel-library tests. MemoryObject
tests happened to match the broad `object::tests::` substring, but that was an
implicit coupling, and the object/memory/physical compile-fail authority tests
were definitely outside the focused gate.

Candidate `fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e` makes the MemoryObject
suite explicit and adds `object_registry_ui`, `memory_authority_ui`, and
`physical_ownership_ui` to the focused handle gate. A unit test binds that gate
surface. The strengthened `cargo xtask test host handles` passes.

**Disposition:** remediated Low test-evidence weakness. No runtime authority bug
was found behind it.

## Residual review concerns pending Dawnbreak

The following are not confirmed user-reachable vulnerabilities in the current
DW0-D source. They require trusted in-kernel API misuse and there is not yet a
production syscall/process caller for the D5 services. They are nevertheless
important places where the locked invariant is enforced by call discipline
rather than a single mechanical type-state proof, so Dawnbreak should target
them explicitly.

### D7-R1 - subsystem finalization dispatch is not mechanically typed

`ObjectRegistry::complete_finalization(FinalRelease)` is crate-visible for all
object types. Correct MemoryObject cleanup first routes the token through
`MemoryObjectAuthority::take_finalization` and
`complete_memory_finalization`, which consumes the typed backing authority and
only then completes generic finalization. Current MemoryObject tests and service
fixtures follow that route.

A future kernel caller that directly completes a MemoryObject `FinalRelease`
could return the generic registry slot to reusable state while leaving the
payload/backing record behind. Current userspace cannot invoke this sequence,
but it would violate the D0 rule that payload presence must not become a second
liveness authority.

**Review priority:** Medium architectural concern before DW0-E wires generic
service finalizers into process/syscall teardown. Prefer a typed finalizer
dispatch or another construction that makes direct generic completion of a
payload-bearing object unrepresentable.

### D7-R2 - MemoryObject construction ordering/uniqueness is conventional

`MemoryObjectAuthority::grant_backing` borrows a `CreationRef` rather than
consuming a payload-registration token, while `creation_into_handle` remains a
separate generic operation. Multiple MemoryObject authorities are also safe to
construct. Intended callers register one payload in the sole authority before
publishing the first handle, and current fixtures consistently do so.

Safe crate code could nevertheless publish a MemoryObject handle before payload
registration, or bind the same creation identity into more than one payload
authority if it deliberately instantiated multiple authorities. Such misuse
would fail-stop or create divergent subsystem metadata rather than increase
userspace rights, but it is not prevented by the current type signatures.

**Review priority:** Medium architectural concern for the DW0-E creation path.
The process-facing object factory should mechanically establish the sole
payload authority and consume one construction state through payload binding
before handle publication.

### D7-R3 - mapping-lease generation exhaustion is fail-closed but not retired

Public object and handle capability slots permanently retire when their `u32`
generation is exhausted. Internal `MappingLease` slots reject generation
exhaustion, but do not mark the exhausted slot retired or skip it when choosing
a reusable slot. After roughly 2^32 reuse cycles of one lease slot, a mapping
transaction can therefore fail closed even if a later slot is available.

**Review priority:** Low theoretical availability issue. No stale lease can be
revalidated and no authority can increase. Later lifetime hardening can add an
explicit retired state or skip exhausted candidates.

### D7-R4 - move-only strong-reference tokens still require explicit release

The strong-reference wrappers are non-`Copy`/non-`Clone` and carry `#[must_use]`,
but Rust permits a trusted kernel caller to bind and then drop a token without
calling the registry release path. That loses the token while leaving its
accounted strong reference live, producing a resource/liveness leak rather
than use-after-free or authority escalation.

**Review priority:** Low engineering risk. Current paths and model tests release
owned tokens explicitly; future error-heavy syscall/IPC paths should continue
to use transaction guards or explicit cleanup objects rather than naked token
locals where early returns could strand references.

## Regression evidence at the reviewed candidate

The following passed against `fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e`:

- `cargo xtask test host handles`, including explicit MemoryObject lifetime,
  object-registry UI, memory-authority UI, and physical-ownership UI gates;
- `cargo test --locked --workspace --all-targets`;
- `cargo clippy --locked --workspace --all-targets -- -D warnings`;
- rustdoc for the workspace with `RUSTDOCFLAGS='-D warnings'`;
- `cargo xtask abi check`;
- `cargo fmt --all -- --check` and `git diff --check`; and
- optimized release-mode handle, service, generic-object, and MemoryObject
  model/unit tests.

The deterministic handle model exercises four fixed seeds for 4096 operations
each across duplicate, close, lookup, inspection, stale handles, malformed
rights, capacity, and reduced-rights behavior. Compile-fail tests prove the
strong references cannot be cloned or forged, an `ObjectId` cannot substitute
for reference authority, `MapAuthorization` cannot be cloned/reused, mapping
transaction internals remain private, and architecture ownership constructors
remain unsafe/private where required.

The kernel/ABI source tree at this candidate is unchanged from immediate parent
candidate `15d362d0ccc2f728e82fbc966d9b7024b0c9021f`; `fa4be89` changes only
the xtask focused-gate definition and its unit test. The parent candidate also
passed the accepted-toolchain production plus six-selector x86_64 artifact and
stack-budget gate after the structural refactor.

## Disposition

No confirmed Critical or High vulnerability, and no currently user-reachable
Medium vulnerability, was found in the reviewed DW0-D source. The principal D0
capability invariants are implemented and have direct positive, adversarial,
model, compile-fail, debug, and release-mode evidence.

The coordinator may therefore treat
`fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e` as a **DW0-D7 soft accept** for
continued development.

This is deliberately not a hard security PASS. Proper Daybreak Blue /
Dawnbreak scanning of the exact candidate remains pending and should focus in
particular on D7-R1 and D7-R2. Those concerns also become materially more
important when DW0-E adds process-owned handle tables, syscall entry, object
creation, and generic teardown/finalizer dispatch.

DW0-E must adapt the reviewed D service rules rather than duplicating them, and
DW0-F/H must re-review cross-process transfer, rollback, synchronization, and
SMP-visible teardown. This note makes no claim about those future surfaces,
ring-3 syscall/usercopy correctness, or final DW0 milestone closure.
