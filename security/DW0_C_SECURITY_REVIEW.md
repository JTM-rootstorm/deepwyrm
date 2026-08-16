# DW0-C Security Review Candidate

## Review state

This record describes the DW0-C security surface implemented through the C3
candidate based on `2c32c82aef71c1e52cfde2fc368beb93a63d8f8c`. It is input to,
not a substitute for, the mandatory final adversarial review. No final DW0-C
security PASS is claimed until that review identifies the integrated commit and
disposes every finding.

## Threat surfaces and enforced boundaries

- hostile, inconsistent, overlapping, or incorrectly typed firmware memory-map
  records and bootstrap reservations;
- stale, foreign-manager, duplicated, or role-confused physical-frame grants;
- malformed transition graphs, table/data aliasing, hostile PTE drift, and
  fabricated scratch paths;
- partial multi-page publication, candidate exhaustion, target conflicts, and
  requested-invalidation failures;
- page zero, noncanonical ranges, kernel-half user mappings, global mappings,
  permission widening, and writable/executable aliases;
- invalid user pointers and recoverable copy failures before destination
  mutation; and
- test-only selector, QEMU-exit, deliberate-fault, and live-root authority
  escaping into production artifacts.

The active C3 test authority is private, linear, and `!Send`/`!Sync`. The C3
runner consumes the exact `ActiveDeepPaging` session returned by C2 and returns
`!`; the selector cannot safely be registered or run twice. Test code cannot
supply a root, role manager, scratch backend, or raw address-space identity.
Its publisher construction remains an explicitly unsafe internal seam until
later address-space authority can issue a mechanical root-binding token.

Allocator pages are validated, zeroed through the authenticated active scratch
window, and unmapped before the frame-role manager accepts the zeroing fact.
Object backing and page-table candidates are then typed to the same manager and
root owner. The test-only successful alias probe is unsafe and has one call
site, after exact live-root walks prove both eight-byte user aliases present and
writable while the authority excludes mapping mutation.

Expected page faults use one atomic EMPTY -> WRITING -> ARMED -> CONSUMED state
machine. The arming selector is fixed to unmapping or permissions, and the
exception path compares vector, CR2, error code, fault-site RIP, and processor
identity before reporting PASS. C2 rejects CR4.SMAP set or an initially set
RFLAGS.AC bit at every live observation through final precommit, and C1 rejects
the same drift before transition authority exists. Wyrmroot does not promise
either incoming bit clear: Deepwyrm's first Rust architecture action clears
exactly SMAP and AC while preserving every other CR4/RFLAGS bit. The deliberate
supervisor access therefore tests the published page permission under a
consumer-established profile rather than relying on a test-only STAC/CLAC
branch.

## Regression evidence

- exact frame-role matrix, stale/foreign grants, staged-role rollback, typed
  object backing, and unsafe alias rejection;
- journal capacity, drift, target conflict, candidate ownership, atomic
  rollback, and requested-invalidation tests;
- transition graph, control-register, PAT, identity-alias, scratch CAS,
  restoration, privacy, linearity, and terminal-handoff tests;
- inactive-root role/parent/permission/physical/scratch/carrier validation and
  exactly-one-CR3-write source/target checks;
- C3 selector identity, exact expected-fault tuple, post-activation dispatch,
  nonescaping authority, consuming terminal runner, actual-source E0382
  duplication rejection, production-symbol exclusion, and six isolated target
  artifacts;
- fail-closed ambient Cargo/Rust override and home/ancestor-configuration
  rejection, cleared child environments with owned empty `HOME`/`CARGO_HOME`,
  manifest-pinned Clang runtime libraries, disabled Clang default-config
  discovery, normalized inspection/helper environments, immutable source-
  manifest observations around all builds, and per-selector accepted-
  target stack accounting through the journal, role registry, scratch target,
  and backend with return-address cost and at least 4 KiB of architectural
  headroom;
- page-zero and exact upper-half rejection, null/hole/kernel/overflow user-range
  rejection for both access intents, atomic first-writable/second-read-only
  cross-page usercopy with both live pages unchanged, nonidentity backing for
  every test mapping, and one-alias shared-object teardown with the second alias
  retained; and
- the canonical unfiltered host memory gate.

The exact commands and observed artifact hashes are recorded in
[`docs/DW0_C_VALIDATION.md`](../docs/DW0_C_VALIDATION.md).

## Explicit limitations and deferrals

- C1's first physical graph read is anchored in the reviewed loader's exact
  transition-table identity-alias contract. Live revalidation establishes
  consistency with that producer contract, not independent or cryptographic
  physical authenticity. A malicious loader, compromised firmware, unsafe
  corruption, or DMA remains outside this claim.
- DW0-C mutation is BSP-only with APs offline and maskable interrupts disabled.
  There is no SMP mutation lock or cross-CPU TLB shootdown yet.
- Committed page-table frames are not reclaimed. This is conservative and
  bounded for DW0-C, not a later lifetime policy.
- C3's guest bodies run at CPL0. They validate effective USER separation and
  terminal architectural faults, but do not claim a ring-3 transition; that
  belongs to DW0-E.
- The future handle layer has not yet supplied mapping-rights or mechanical
  address-space/root binding tokens. C3 confines those seams to the private,
  test-feature-only active session and does not expose a safe general
  post-activation publication API.
- The six guest artifacts have built and passed source/artifact gates, but have
  not been executed by this worker. Functional phase acceptance requires the
  coordinator-owned fresh VM gate.
- Recorded artifact hashes describe this dirty candidate and remain provisional
  until a clean committed rebuild reproduces the full immutable-input gate.

## Candidate disposition

Ready for mandatory adversarial review. Guest execution, final finding
disposition, and an integrated commit identity remain pending, so this document
does not yet record a DW0-C security PASS.
