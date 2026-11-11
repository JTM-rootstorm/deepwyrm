# DW1 Security Review (F4)

**Status:** Final. No Critical, High or Low findings; one Medium (DW1-F4-M1), fixed (see below).
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

### DW1-F4-M1: no per-process quotas on kernel object pools (Medium; fixed in `797347f`, `c7d7aae`, `b9bfb55`)

**Finding.** The production pool sizes are global and fixed: registry 160, channel pairs 32, waits 48, timers 2, events 1 and identities 16 (`production_resource_geometry.rs`). Any process with ordinary create rights can use up a pool. A replacement service would then fail to start. For example, with only two timers, uart16550d's pacing timer could be left without one.

**Original disposition** was "accepted for DW1, with a target": per-TaskGroup quotas before Wyrmroot runs code outside the shipped product. Mike chose to fix it now (full TaskGroup quotas).

**Fix.**

- `797347f` adds the `task_group_limit` syscall (0x00010003). It can only lower a per-class limit on a TaskGroup. The classes are channel, event, timer, memory object, thread, process, task group and wait. Each created object records the limited TaskGroups above its creator (at most four; deeper nesting is refused with NO_RESOURCES). A group's usage is counted from live registry slots that name it, and wait usage from live wait entries, so there is no release path to get wrong. Admission runs before anything is created, under the runtime lock, and returns NO_RESOURCES past a limit.
- `c7d7aae` sizes the production pools for four concurrent shell jobs (registry 192, channel pairs 40, waits 56) and checks the peaks in `production_resource_geometry.rs`.
- `b9bfb55` admits and charges the production MemoryObjectCreate path (`memory_object_create_owned`). `797347f` had charged only the test-only adapter (rereview finding D1).
- Wyrmroot `266b2b1` limits every shell job's TaskGroup to zero objects of every class and one wait, and caps shell jobs at four.

**Rereviews** (Claude Opus 5.5, `claude-opus-5-5`, effort low, 2026-11-10, read-only):

1. At `797347f`/`c7d7aae` with Wyrmroot `266b2b1`: not closed. D1: production MemoryObjectCreate was neither admitted nor charged, so a limited job could still drain the memory-object and registry pools.
2. At `b9bfb55`: no defects. Admission precedes both the registry create and backing allocation, and a refusal hands the early backing back to the caller's rollback with nothing leaked or freed twice. The one success path is charged. Status precedence is unchanged. Every production creation path of a limited class is admitted and charged; the remaining `registry.create` sites are unlimited types behind privileged grants, one root region per process, the capacity probe, boot construction and tests. The new test `the_live_memory_object_create_path_is_limited` fails if either the admission or the charge is removed. Verdict: closed for its scope.

**Validation** (development tier): host tests, clippy and fmt on Deepwyrm `b9bfb55`, the production target check, the full Wyrmroot `xtask test` on `f39b350`, and `dev-boot --check` on that pair, which runs `bin/hello` as a limited job.

**Residual risks.** Mike asked for these to be fixed (2026-11-10). Fixed in `5fa9b6a` and `3caecc3`, with Wyrmroot `d32c49f` and `5f00b55`:

| Residual risk | Fix | Follow-up review |
|---|---|---|
| Mapping leases are not a limit class | Lease pool sized for every job filling its 10-slot region (mappings 48 → 64; `REGION_SLOTS <= JOB_REGION_MAPPINGS` asserted) | Partially closed: still not a limit class. The bound holds because Wyrmroot gives jobs no handles to other processes; §10 now says so. |
| Frames allocated before admission | The facade asks the quota before allocating; a race falls back to NO_RESOURCES | Closed for quota refusals |
| Limits do not follow a process created into another TaskGroup | `confine_creation`: a limited process creates TaskGroups, Processes and Threads only inside its limited subtree, else ACCESS_DENIED | Closed for creation. Delegation (starting another process's thread, mapping into it) is not confined; §10 records this. |
| Wait admission before handle resolution; one wait per job | Admission after resolution, with the resolved pins released on refusal; job waits 1 → 4 (waits 56 → 68) | Closed |
| `count_waiting` under the IRQ-disabling lock | The lock is held per slot; the ancestry walk runs outside it | Closed |
| Duplicate test-only `memory_object_create` | Removed; tests drive `memory_object_create_owned` through a shim | Closed |

**Follow-up review** (Claude Opus 5.5, `claude-opus-5-5`, read-only, 2026-11-10, Deepwyrm `5fa9b6a` with Wyrmroot `d32c49f`): no Critical, High or Medium defects. The one Low defect was a doc comment taken by the new facade helper, fixed in `3caecc3`. Accepted Low notes:

- Wait admission counts the items of a deadline-now poll that would register nothing.
- Lease and wait slots retire permanently when their u32 generation runs out. This predates F4.
- No test covers the process-create refusal path, `wait_many`'s admission order, or the live facade's early check. By reading, each mirrors a tested path.

**Validation** (development tier, final pair Deepwyrm `3caecc3` / Wyrmroot `5f00b55`): host tests (1187 pass), clippy, fmt and the production target check; Wyrmroot `xtask test`; and `dev-boot --check`. The new tests were mutation-checked.

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
