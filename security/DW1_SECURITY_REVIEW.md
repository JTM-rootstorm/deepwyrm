# DW1 Security Review (F4)

**Status:** Final. No Critical, High or Low findings; one Medium (DW1-F4-M1), dispositioned below.
**Review date:** 2026-11-10
**Reviewer:** Claude Opus 5.5 (`claude-opus-5-5`), an independent read-only subagent. It did not write the code.
**Reasoning effort:** low (the session setting). This was a targeted review, not a line-by-line audit of the whole kernel.
**Companion record:** `wyrmroot/security/WYR1_SECURITY_REVIEW.md`

## Reviewed revisions

- Deepwyrm: `d09d3f4e1286cc133c593c4d086809d488584d3f`. This revision is unchanged by F4.
- Paired Wyrmroot: `4d9ac48ed9d0399f86d84fbb15ed16093deab8bb` when reviewed. The final compatible Wyrmroot is `37c818e`; its F4 changes touch no kernel interface.
- Baseline: the F3 freeze `e8aea8b`. Since that freeze, the post-F3 cleanup removed about 32k lines: selectors 18–35, the evidence cfgs, the G5 primordial probe and `bootfs_capacity`. Because of that change, F3 needs a new candidate freeze.

## Method

The reviewer used only read-only `git diff`, `grep` and `sed`. It ran no build, test, VM or network access.

It read:

- plan §F4;
- `Plans/ARCHITECTURE_INDEX.md`;
- `DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md` §3 and §5–7;
- the F2A hardening record and the F2A4 unsafe audit.

It checked every `cfg` arm removed between `e8aea8b` and `d09d3f4` against the arm that replaced it. It then read the current production code for:

- handle rights and transfer;
- DeviceResource;
- Interrupt and IOAPIC;
- production syscall dispatch;
- user RFLAGS sanitizing;
- the COM1 emitters;
- the cfg emission in `build.rs`.

## Findings

No Critical, High or Low findings.

### DW1-F4-M1: no per-process quotas on kernel object pools (Medium, accepted with a target)

**Finding.** The production pool sizes are global and fixed: registry 160, channel pairs 32, waits 48, timers 2, events 1 and identities 16 (`production_resource_geometry.rs`). Any process with ordinary create rights can use up a pool. A replacement service would then fail to start. For example, with only two timers, uart16550d's pacing timer could be left without one.

**Disposition: accepted for DW1.** `DEEPWYRM_PRE_PHASE0_INVARIANTS.md` §10 defers quotas to TaskGroup policy. In this product the only programs a user can launch are `bin/hello` and `bin/cpu-hog`, both checked by hash, so no untrusted code runs.

**Target.** Per-TaskGroup quotas must land before Wyrmroot runs any code that is not part of the shipped product, such as packages.

## Risks and questions

- **Deferred Interrupt retirement.** While an Interrupt's retirement is deferred, it keeps its q35 source in the Finalizing state. A replacement driver therefore waits for a bounded time. This is accepted by contract and does not expose a stale vector: delivery requires the exact source and generation.
- **Scheduler arms in host tests.** Host tests exercise the `cfg(test)` scheduler fixture arms, not the production `cfg(not(test))` steal and `need_resched` arms. The production arms are unchanged since F3. Tests that pin them directly are worth adding.
- **Unset bootfs page limit.** If `DEEPWYRM_BOOTFS_MAX_PAGES` is unset, `build.rs` defaults to 17 pages. A hand-built kernel then refuses the product bootfs (NO_RESOURCES), which fails closed. `xtask product` always sets the variable.

## Areas reviewed with no finding

- **Post-F3 deletions.** Every removed arm was gated on a selector cfg that production never sets. Every production arm survives with the same body. No unsafe code or assembly was added; 11 selector-only unsafe lines were removed.
- **Test-only code in production.**
  - `deepwyrm_production_product` is emitted only when no selector is set, and a selector requires the test-support feature.
  - Default features are empty.
  - All private raw evidence syscalls are deleted, so decoding them falls through to `NOT_SUPPORTED`.
- **Handle rights.**
  - `duplicate` requires DUPLICATE and grants at most a subset of the rights.
  - A move requires TRANSFER, grants a nonzero compatible subset, and rejects duplicate sources.
  - Interrupt handles cannot be duplicated, handles are checked by generation, and retired slots are never reused.
- **DeviceResource.**
  - A claim requires TASK_GROUP:RESOURCE, the exact owner domain, and membership revalidated at commit.
  - Descriptors that overlap COM1, or have zero or out-of-range length, are rejected.
  - Port I/O arithmetic is checked, and every I/O runs while this CPU exclusively holds the runtime core.
- **Interrupt and IOAPIC.**
  - Create requires DeviceResource:MODIFY and reserves the source exclusively. The record is committed as Armed before the source is unmasked.
  - Ack is exact by generation.
  - Finalization marks the record Finalizing before it retires, and the parent resource stays pinned until then.
- **User return.** RFLAGS are masked with `0x200cd5` and forced to `0x202`. The TSS has no I/O bitmap, so userspace cannot reach any port.
- **Leakage.** Production COM1 records carry numeric codes only, so a child process cannot forge COM1 markers. Info structs expose no kernel addresses.
- **Teardown and stale handles.** Handle tables are per process and are drained only after the process has exited.

## Not covered at this effort

None of these changed between `e8aea8b` and `d09d3f4` except for deleted selector observers. They rely on the DW0-H, DW1-E and F2A4 audits:

- the SMP terminal-stop and rendezvous proofs;
- wait and channel cancellation interleavings during process termination;
- usercopy and paging internals.
