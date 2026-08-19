# DW0-E Security Review Record

## Disposition

**SOFT ACCEPT for DW0-E phase progression, pending formal
`gpt-daybreak-blue-latest` exact-candidate review.**

The provisionally reviewed E code candidate is
`579e12074e1fe9ec89507e033381fed66676c12c`. E9 validation candidate
`e8394d6e6d160d9e4d04769943c2500cfd562c10` is a documentation-only
descendant with no kernel/ABI/schema/tooling/build-input delta from that code.

The provisional review was performed on 2026-08-19 by GPT-5.6 Sol using manual
and tool-assisted analysis. It was not Daybreak Blue, Dawnbreak, or an
equivalent-model claim. Detailed review method and evidence are retained in
[`DW0_E8_SOFT_SECURITY_REVIEW_NOTE.md`](DW0_E8_SOFT_SECURITY_REVIEW_NOTE.md).

By coordinator instruction, E may progress to DW0-F under the same soft-accept
policy already used for DW0-D. Formal Daybreak scanning of both D and E remains
security debt and must be completed before final DW0 security closure.

No hard E security PASS is asserted by this record.
## Reviewed E threat surface

The provisional review covered the E plan's security-sensitive boundaries:

- SYSCALL MSR setup, GS state, entry-stack switch, and frame construction;
- IRETQ canonicality, selectors, RFLAGS sanitation, and register disclosure;
- hostile RCX/R11/RSP/RIP and faulted/nested entry considerations;
- CPL3 exception-origin parsing versus kernel-fatal exception handling;
- pinned usercopy TOCTOU and output-preflight-before-mutation guarantees;
- generated syscall-number decoding and unknown/unimplemented fallthrough;
- process-local HandleTable selection and raw-handle collision isolation;
- task rights, hierarchy authority, termination, and descendant teardown;
- scheduler/context double-run, finalization, and kernel-stack ownership;
- D7-R1/R2 typed finalizer and construction-sequencing integration;
- task-state metadata disclosure under `INSPECT`;
- AddressRegion/MemoryObject teardown while pins remain live;
- scheduler/task/handle/object/memory lock and reentrancy boundaries;
- accidental PID/root/signal/ptrace/fd-style ambient authority; and
- production separation from test-only CPL3/completion mechanisms.

Optional local analyzers `cargo-audit`, `cargo-deny`, `cargo-geiger`, Miri,
Semgrep, and CodeQL were not installed and did not run. The normal/build runtime
stack has no third-party Cargo dependency beyond workspace crates.
## Confirmed High finding and remediation

### E8-F1: hostile CPL3 GS reload before SYSCALL

**Original severity: High, unprivileged kernel-fatal denial of service.**

Before `579e120`, syscall entry consumed `%gs:` scratch state before any
`SWAPGS`. CPL3 can load the legal user data selector `0x2b` into GS, replacing
the active effective base despite FSGSBASE not being the mechanism used. The
review reproduced that architectural behavior with a bounded local probe.

With the user-selected base zero, the old first supervisor `%gs:` access could
fault through the intentionally unmapped low page before the trusted kernel
stack transition. Under the current exception policy that becomes kernel-fatal.

Commit `579e120` makes unconditional `SWAPGS` the first syscall-entry
instruction and pairs the syscall-return and initial-user-entry IRETQ paths.
Source contracts enforce ordering/balance and reject SYSRET.

The synthetic userspace regression now executes `movw $0x2b, %gs` before its
first generated syscall. Fresh E9 accepted-toolchain builds reproduce kernel
SHA-256 `934782a1fe76e394312a0b6bba9bf7892bd4e9db3684cf408eba13dc00d34b89`
and userspace SHA-256
`65becbc03deee89b9eff7bd61f2baa6646228ce28f4e0abd48846d1166acfc0d`.
That exact kernel passed the designated Wyrmroot VM gate.

**Disposition: fixed provisionally; formal Daybreak must independently re-review
the transition and remediation.**
## Confirmed security properties

The provisional review and regression suite support these bounded E claims:

- user return requires validated lower-canonical RIP/RSP, exact selectors,
  sanitized flags, live mapping permissions, and current binding generation;
- entry treats user RCX/R11 and stack state as hostile and reconstructs approved
  return state rather than leaking kernel pointers;
- usercopy pins complete ranges before exact transfer and output-producing
  syscalls preflight copyout before business mutation;
- generated/schema-owned syscall decoding returns `NOT_SUPPORTED` for unknown
  and deferred calls instead of falling through into adjacent operations;
- caller process context selects its own HandleTable and rights-gated services;
- task teardown is bounded/iterative and execution resources are retired before
  reclaim, with generation checks rejecting stale task identities;
- E mechanically strengthens D7-R1/R2 through typed payload finalizers and
  construction-before-publication authority;
- task termination metadata remains behind `INSPECT` rather than ambient process
  enumeration/control authority;
- AddressRegion/MemoryObject pins fail safe against early backing reclamation;
- no production POSIX-style `kill(pid)`, UID-0, ptrace, signal, fd, or
  filesystem-exec shortcut was introduced; and
- accepted target inspection rejects test-only E7 completion/runtime symbols
  from production artifacts.

No unresolved Critical or High vulnerability is known from this provisional
review. No currently user-reachable Medium vulnerability was confirmed.
## Accepted residuals pending formal Daybreak/later phases

### E8-R1: exception-origin GS normalization

Current ordinary CPL3 exceptions are terminal/non-returning and do not consume
GS in exception assembly. A future nonterminal exception or exception-triggered
reschedule must establish the kernel/user GS invariant explicitly before a
generic return to userspace.

**Disposition:** Medium-priority architectural review target for the first such
path and again under SMP/NMI nesting.

### E8-R2: one-shot runtime pointer lifetime

The E runtime binding stores a raw erased context pointer plus typed handler.
Its unsafe caller contract supplies stationarity, lifetime, and exclusivity for
the current one-shot single-BSP runtime.

**Disposition:** Medium architectural hardening before general Wyrmroot process
runtime integration. Replace caller-proven lifetime with stronger mechanical
ownership when multiple long-lived runtimes exist.

### E8-R3: address-space retirement coordination

Mapping/runtime pins prevent early backing reuse, but general process teardown
must coordinate root AddressRegion unmap/retirement before final release.

**Disposition:** Medium liveness/integration concern. Current failure mode is
retained resources/liveness rather than demonstrated use-after-free.
### E8-R4: bounded generation exhaustion

Capability and execution generations advance with checked arithmetic and fail
closed on exhaustion. Practical exhaustion remains an availability edge, not a
known stale-authority resurrection.

**Disposition:** Low; revisit for long-lived/restart-heavy runtimes.

### E8-R5: E is single-BSP

Several return-time validation and mutation-exclusion arguments rely on the E
assumption that no second CPU can concurrently publish scheduler/page-table
state. That proof does not carry into SMP unchanged.

**Disposition:** Medium-priority re-review at DW0-H SMP activation. Do not infer
multi-vCPU security acceptance from E.

## Formal Daybreak debt

The exact Daybreak requirement is deliberately still open. When
`gpt-daybreak-blue-latest` is available, review frozen E code candidate
`579e12074e1fe9ec89507e033381fed66676c12c` and its transition from the E7
baseline, with explicit attention to E8-F1 and E8-R1 through E8-R5.

DW0-D separately retains its formal review debt for candidate
`fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e`. Neither historical debt may be
silently erased by later F/G implementation or by the final H review.

If a delayed Daybreak review finds a substantive defect, apply the remediation
to the current development branch, add a regression where practical, and rerun
the affected host/freestanding/VM gates before final DW0 acceptance.
## E9 evidence snapshot

Fresh E9 host and accepted-target gates passed at clean revision `e8394d6`.
The accepted target reproduced the exact bytes already exercised by the
post-remediation designated VM run.

- host log SHA-256:
  `5ca4633a26f5b25271c87e005f65aa37f05f7573026c3f9d108974b367836db6`;
- target log SHA-256:
  `3ba84f96ed82d3dfeda06a3e7897e2893093d018534ad92cf2c2e564c9611efc`;
- E8 soft-review note SHA-256:
  `88a847452ecf5d3d6bbe8acf84028dd04a1e451150ad8ef195de747101acd7d2`;
- selector-10 serial SHA-256:
  `1096aca3b5f3f7f99fb983ba28835c7541e175c559cc7d0a381148c50d720b47`.

The VM terminal record remained:
`DWTEST1|01|0000000A|00000000|5C9DAA15`.

Selectors 11 (`task-syscall-sanitize`) and 12 (`task-user-exception`) remain
reserved identities rather than accepted guest executions. The canonical E7
plan made selector 10 mandatory; this record does not manufacture evidence for
11/12. Host/model/source tests cover their relevant current invariants, and a
future hardening pass may promote them into real guest bodies.

With these bounds, the coordinator may proceed to DW0-F. Formal D/E Daybreak
review remains a mandatory debt item before final DW0 security acceptance and
is indexed in [`DW0_DEFERRED_DAYBREAK_REVIEWS.md`](DW0_DEFERRED_DAYBREAK_REVIEWS.md).
