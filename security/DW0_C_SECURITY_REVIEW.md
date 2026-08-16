# DW0-C Security Review Record

## Review state

This record describes the DW0-C security surface reviewed at pre-signing
Deepwyrm revision `9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`, whose signed
same-tree equivalent is `b424d7d89d9acc57ceff8d966c3931e26a51f614`. The final
review used `gpt-daybreak-blue-latest` at high reasoning on 2026-08-16 against
pre-signing base `b263a7a912c79b9e7d4b2439370417d7ae2ee076`, whose signed
same-tree equivalent is `bd9da0bb8b5c867556eff7e3e29764f9fec706ab`, plus binary diff SHA-256
`c634ed053fb6c3ae42205babea81b345c5096f94f1ef49170ee889aa3aa890bb`,
which is exactly the source state committed as
`9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`. Its disposition was C0/H0/M0/L0.

The pre-signing compatible Wyrmroot source/pin revision
`15fa42dda23834a80197161249738f001bb2d76f` and evidence descendant
`89235c7feef2a89ef2882ee096428b456496fa39` have same-tree signed equivalents
`ee1b899045a3294f140945e013ba42a60f57aa84` and
`2b16b94818632f562a0551205d94e62bba847502`. The current live signed repin is
`eaaba1491c2f45d4fbd8b02358989547e9a8d98a`; its signed no-rerun evidence
descendant is `a8f12ba5e86db8b93f4be68f727d6cd65204c895`.

Per Mike, no build, test, or artifact was rerun or regenerated after signing
and repinning. The Deep source-security disposition carries to
`b424d7d89d9acc57ceff8d966c3931e26a51f614` solely because it preserves tree
`4053153adfaca4a3582d53768c2a6fc11572ee7f`; the reviewed pre-signing base and
signed base both preserve tree `483f6255950320e75448d4d9a52829a9b906326b`.
Historical artifact evidence remains attributed to the pre-signing identities.

Wyrmroot's coordinator-supplied bounded guarded-IST acknowledgment review found
no new Critical, High, Medium, or Low findings. Existing accepted Medium
limitations remain recorded in Wyrmroot's `security/WYR0_B_SECURITY_REVIEW.md`;
the bounded result is not an absolute zero-findings disposition. All source,
host, freestanding-artifact, cross-repository pin/build-evidence, and source-
security work attainable within the current DW0-C/WYR0-C scope is complete for
the live signed pair on this no-rerun/tree-equivalence basis. Formal DW0-C
closure still requires the canonical image and coordinator-owned guest
execution. This record does not close the earlier pending DW0-B loader/guest
execution gate.

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
  mutation;
- contiguous terminal IST stacks without down-growth guards, guard-leaf drift,
  TSS/IDT carrier mismatch, and undercounted exception-path stack use; and
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
- linker, TSS, IDT, and active-root checks for one exact-zero 4-KiB guard and
  four supervisor RW/NX/non-global/default-cache pages per #DF, NMI, and #MC
  stack; exact installed IST top/vector facts; and a single activation CR3
  write;
- production and selector stack-size carriers with identical canonical
  `.text`, plus a shared formatter-padding branch builder covering
  `pad_integral`, COM1 `write_char`, UTF-8 encoding, slice precondition, and
  pointer-alignment frames. The production maximum used 2,535 of 16,384 bytes;
  each selector maximum used 2,631, leaving 13,849 and 13,753 bytes unused
  respectively, both beyond the independently required 4-KiB reserve;
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
- The six guest artifacts have built and passed source/artifact gates, but no
  canonical ESP/image exists and they have not executed through the Wyrmroot
  loader. Functional phase acceptance requires the coordinator-owned fresh VM
  gate against the exact recorded revision pair and image identity.
- The artifact hashes identify observed pre-signing builds of exact source
  state `9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`; the isolated scratch
  artifacts were removed and are not retained release artifacts. They were not
  regenerated or reattributed to the signed commit.

## Disposition

The reviewed pre-signing Deepwyrm source state and its exact same-tree signed
equivalent `b424d7d89d9acc57ceff8d966c3931e26a51f614` have an attainable
source-security PASS with C0/H0/M0/L0. The earlier adversarial C0/H0/M1/L0
result is retained as historical review provenance: its Medium finding
identified an omitted live formatter-padding branch in both IST stack oracles.
Pre-signing commit `9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`, now signed as
`b424d7d89d9acc57ceff8d966c3931e26a51f614`, resolves that finding with shared
production/selector enumeration and a host regression; the final exact-diff
re-review cleared it.

This is not a guest-security, VM, or formal phase-closure PASS. Those gates
remain pending on the canonical Wyrmroot image and coordinator-owned execution
evidence. No physical-hardware acceptance claim is made, and VM evidence cannot
establish one. The distinct pending DW0-B loader/guest execution gate also
remains open.
