# DW1 S2K Runtime Authority Design

**Status:** approved by Mike on 2026-09-28, with the decisions in §11. §11 overrides §5.2, §5.3 and §8 where they differ.

**Plan:** root `DW1_WYR1_STRUCTURAL_REFACTOR_PLAN.md` §4 S2K
**Prepared:** 2026-09-27 by the S2K-design worker (Claude Opus 5.5)
**Evidence revisions:** deepwyrm `ef1384d`, root `7c25dae`. Every `file:line`
below is at deepwyrm `ef1384d` unless it names another file. A parallel lane is
adding `SAFETY` comments to `primordial.rs` and `syscall/live.rs`, so these line
numbers will drift.

## 0. Decisions in brief

1. **`RuntimeCore` and `PagingAuthority` are replaced, not resumed.** Keep their
   good patterns: non-escaping closures, move-only phase reservations and the
   non-nesting witness. Delete the four types nothing uses. Choose lock domains
   at R3, from the borrow sets the adapters actually have.
2. **`PrimordialRuntimeCarrier` splits along six lines, not four.** The two extra
   lines are per-CPU execution identity and primordial supervision. Root
   switching and per-CPU identity move in S2. Terminal handoff and syscall
   dispatch are deferred. Object backing already has its seam.
3. **Type-enforced in S2:** rows 93, 97 (first seam), 100 and 103, plus the
   guard-free half of row 61. Rows 72, 85, 89, 96 and 101 follow if Mike
   approves step S2K-6. Every other kernel runtime row stays KEEP (§4.3).
4. **S2 carries six behavior-preserving steps (S2K-0 to S2K-5) and one semantic
   step (S2K-6) that needs Mike's separate yes.** Lock decomposition (R3),
   the terminal engine and the dispatch router are deferred until after the S3
   reassessment.
5. **The four orphaned target-only tests** move with the pure code they test into
   modules the host compiles. A ratchet counter keeps the count at zero.
6. **No public ABI change is needed.** None of the steps touches `abi/`, syscall
   numbers, statuses, `DwBootInfoV1`, or the Wyrmroot-pinned boot-stack size.

## 1. Sources read

- `AGENTS.md`; root `CLAUDE.md`.
- Root `DW1_WYR1_STRUCTURAL_REFACTOR_PLAN.md` (all of it).
- Root `DW1_WYR1_S1_SAFETY_NET_RECORD.md`, especially §4 and §6.
- Root `DW1_WYR1_S0_SOURCE_TEXT_TRIAGE.tsv`, deepwyrm rows (155 rows).
- `Plans/DW0_I1_STATIONARY_RUNTIME_FOUNDATION.md`.
- Root `DW1_WYR1_RUNTIME_RESET_IMPLEMENTATION_PLAN.md` §0-4, §9, §12-15.
- Root `DW1_WYR1_RESET_R0C_INVENTORY.md`, `DW1_WYR1_RESET_R1_VALIDATION.md` §9,
  `DW1_WYR1_RESET_R5E_STACK_ORACLE.md` §3-4.
- `Plans/DW0_H0_SMP_CONCURRENCY_CONTRACT.md` §5, §6, §10, §12.
- `Plans/DW1_C0_SMP_PREEMPTION_DESIGN.md` §3.2 and §6;
  `Plans/DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md` near lines 126 and 452.
- `Plans/ARCHITECTURE_INDEX.md`.
- Root `BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md` §1-2;
  `personality-plan/CROSS_PERSONALITY_KERNEL_MECHANISM_DOCTRINE.md` (skimmed).
  Neither doctrine binds S2K beyond "no new kernel primitive". BOOTSTRAP §2 is
  relevant to primordial supervision (§4.2, line 6).
- Code: `kernel/src/arch/x86_64/mm/activation/primordial.rs` (12,112 lines),
  `syscall/stationary_runtime.rs` (490), `syscall/live.rs` (2,043), `syscall.rs`,
  `mm/activation.rs`, `mm/activation/user_access.rs`,
  `test_support/x86_64.rs`, `syscall/native.rs` trait surface,
  `kernel/tests/x86_64_syscall_contract.rs`, `x86_64_entry_contract.rs`,
  and the UI compile-fail harness (`kernel/tests/*_ui.rs`, `kernel/tests/ui/`).
- Git history of the files above.

## 2. What the code is today

### 2.1 Runtime shape

- **One shared carrier behind one ticket lock.** `RuntimeAuthorityLock<T>`
  (`primordial.rs:1540`) wraps the whole `PrimordialRuntimeCarrier`
  (`:3289`). Its `Sync` impl (`:1611`) calls itself "the explicit DW0-H bridge".
- **The carrier lives on the boot stack.** It is built with `core::pin::pin!`
  at `:9961`. The per-CPU facade array is pinned there too, at `:10091`.
- **One facade per CPU.** `RuntimeCarrierFacade` (`:1734`) holds a `CpuIndex`,
  a shared `&RuntimeAuthorityLock`, and `&'static PrimordialRuntimeShared`.
  `live.rs` publishes each facade as a type-erased pointer per CPU
  (`live.rs:927`, `:1923`).
- **Some state is already permanent and stationary.** `PrimordialRuntimeShared`
  (`:1487`) holds execution, channels, events, timers, waits, devices and
  interrupts in static one-shot storage (`:1519-1533`). This is part of the
  reset plan's R2A, done early.
- **Per-CPU identity lives inside the shared carrier.** The carrier keeps
  "current" fields (`process`, `thread`, `stack_id`, `context_id`, `root_key`,
  `active_root`) plus per-slot arrays for the other CPUs. `switch_cpu_state`
  (`:3445-3481`) swaps them on every lock acquisition.
- **A second copy of per-CPU identity** lives in `PerCpuLiveCarrier`
  (`:2160`). A third is the R1B liveness mirror (`:3482`).
- **Ordinary syscalls run under the lock, usercopy included.** The facade's
  `handle` (`:8493`) special-cases four termination requests. Every other
  request goes through `with_synchronized_runtime_at_safe_point` (`:1910-1934`,
  called at `:8690`). That runs the carrier's `handle` (`:10144`) and
  `handle_fallthrough` (`:10444`) inside one lock hold. Those build
  `current_process_address_space(...)` and pass it to the usercopy adapters.

### 2.2 How it got here

All on 2026-08-23, all Codex-coauthored, with no message bodies:

| Time (-0500) | Commit | Subject |
|---|---|---|
| 16:21 | `c6a6f5a` | Prepare fixed per-CPU runtime carriers |
| 17:50 | `317f08d` | Add stationary runtime authority foundations |
| 17:57 | `7089d9f` | Stage stationary runtime carrier storage |
| 18:13 | `62523a7` | Stage stationary runtime adapter transactions |
| 20:11 | `83856db` | Release APs into the live cooperative runtime |

- `83856db` introduced `RuntimeAuthorityLock` and `RuntimeCarrierFacade`.
  APs were released through the coarse lock two hours after the stationary
  foundation was staged.
- `RuntimeCore` and `PagingAuthority` have never been instantiated outside
  their own tests. `git log -S RuntimeCore -- kernel/src` shows only
  `317f08d` and `62523a7`. At `62523a7`, `primordial.rs` referenced only
  `StationaryGuardDepth` (line 376).
- `DW1_C0_SMP_PREEMPTION_DESIGN.md` §6 then accepted the coarse lock as a
  "temporary correctness bridge". It said the `RuntimeCore`/`PagingAuthority`
  split is "not a prerequisite for four-vCPU correctness".
- `primordial.rs` has 214 commits after `62523a7` (`git rev-list --count
  62523a7..ef1384d -- <file>`); 244 in total. The plan's figure of 232 does not
  match either count. By date (`--since=2026-08-23`) it is 235. The difference
  does not change the argument.

### 2.3 Counts against the R0C deletion-proof baseline

| Measure | R0C (2026-09-10, `a086041`) | Now (`ef1384d`) |
|---|---:|---:|
| `runtime.lock()` acquisitions in `primordial.rs` | 56 | 56 |
| `switch_cpu`/`switch_cpu_state` call sites (external) | 36 (33) | 36 (33) |
| Boot-stack-owned permanent runtime constructions | 1 | 2 (carrier `:9961`, facades `:10091`) |
| Common syscall-path stack bytes (E8) | 1,501,744 | 50,528 (R5E §3) |

R0C counted only the carrier construction, so the second boot-stack item is a
counting difference, not new code. Since R0C, nothing has moved the R2 or R3
targets. R5 removed the giant frames.

### 2.4 Findings

These are confirmed from source unless labelled otherwise.

1. **The runtime guard-free check cannot fire.** `assert_guard_free_external_work`
   (`:5187-5189`) checks `STATIONARY_GUARD_DEPTH` (`:1534`). Only
   `RuntimeCore::prepare_on` and `PagingAuthority::prepare_on` ever raise that
   depth, and neither is instantiated. The check therefore always passes, even
   though every caller runs inside a `RuntimeAuthorityLock` hold (§2.1). TSV
   row 56 pins the check's presence and its position.
2. **Phase revalidation cannot see drift today either.** `reserve_runtime_phase`
   (`:10161`) and `commit_runtime_phase` (`:10342`) both run inside the closure
   passed at `:8690`, under one lock hold. The reservation is scaffolding for a
   future split. It is not a live check.
3. **Usercopy runs under the coarse lock.** This follows from §2.1. It meets
   C0 §6's conditions, which do not mention usercopy. It breaks H0 §12 rule 8
   and reset plan §4.3 (§3).
4. **`switch_cpu_state` can keep the previous CPU's identity.** If the target
   slot has no recorded Process (`:3466`), `process`, `thread`, `stack_id`,
   `context_id` and `root_key` keep the previous CPU's values. *Question:* does
   any path read those fields before `synchronize_scheduler_current` overwrites
   them? This decides whether S2K-6 is a pure cleanup or a real semantic change.
5. **Much of the carrier's own `NativeSyscallFrameRuntime` impl looks
   unreachable** (`:7021-8447`). The facade calls only `authorize_return`,
   `authorize_timer_return`, `has_reschedule_request`, `prepare_quantum`,
   `resume_suspended` and the `intercept_*` relays on it. The carrier's
   `terminate_current` (`:8093`) calls the non-detached
   `prepare_terminal_handoff` (`:4622`, about 540 lines). The facade never
   calls either. *Question:* verify by building every selector with those
   methods stubbed to `unreachable!()`.
6. **Four `#[test]` functions never run** (S1 §6):
   - `primordial.rs:10117`, `integration_bootfs_measurement_accepts_selector_local_capacity_and_rejects_larger_inputs`;
   - `user_access.rs:1210`, `e2_mailbox_releases_only_after_local_serialization_before_exact_ack`;
   - `user_access.rs:1244`, `e2_mailbox_rejects_overlapping_target_publication`;
   - `test_support/x86_64.rs:1371`, `dw1c_terminal_arbitration_has_one_success_or_failure_winner`.

   Each file is gated `target_os = "none"` (`mm/activation.rs:35`, `:57`;
   `test_support/mod.rs:139`). The host `cfg(test)` build never compiles them,
   and the target has no test harness.
7. **Two TSV replacements would create new orphans.** Row 25's replacement says
   "move the claim/move_out model into primordial.rs's own `#[cfg(test)]`
   module". Row 21's says to extract `PRIMORDIAL_BOOTFS_MAX_PAGES` selection
   into a pure fn, and that const is defined in `primordial.rs:796-835`. Either
   test would compile nowhere. S3 must target host-compiled modules instead.
8. **Row 56's slice is wider than it looks** (risk, not a defect).
   `x86_64_syscall_contract.rs:198` splits at the first
   `fn handle(&mut self, request: NativeSyscallRequest)`, which is the facade's
   (`:8493`). The order checks then search the rest of the file.

## 3. Where the authority documents agree and disagree

**They agree on:**
- shared authorities in stationary storage with their own synchronization;
- an exclusive execution carrier per CPU;
- no guard held across context switch, CR3 completion, idle, reaper handoff,
  user return or acknowledgement waits (H0 §12.8, C0 §6, reset §4.3,
  I1 foundation);
- prepare / guard-free work / revalidate-commit as the pattern;
- no public ABI change.

**They now disagree on:**

| Topic | Says | Code |
|---|---|---|
| Lock across usercopy | H0 §12.8 and reset §4.3 forbid it. C0 §6's conditions omit it. The I1 foundation argues against it. | Held (§2.4 finding 3). Follows C0 §6 only. |
| Fate of the coarse lock | C0 §6: temporary bridge. Reset §4.2: "to be retired, not preserved as the new shared-runtime wrapper". I1 foundation: never adopts it. | 56 acquisitions, unchanged since R0C. |
| Shape of the shared authority | I1 foundation: five authorities under one `RuntimeCore` IRQ lock, plus `PagingAuthority`. Reset §4.2: "locks scoped to the authority being mutated". H0 §12.3/12.5: non-nested subsystem locks, or one prepare/no-fail-commit transaction guard. | Neither shape. One ticket lock around everything. |
| Per-CPU identity | H0 §5.7 and reset §3.1: each CPU owns its carrier. "No CPU becomes current by rewriting a shared mutable carrier identity." C0 §3.2: the coarse lock "does not make carrier identity shared". | Identity is swapped into shared fields at 33 external sites (§2.3). C0's sentence holds only under the lock. |
| Runtime lifetime | Reset §3.8/§4.4: permanent storage, not the boot stack. H0 §12 asks only for "stationary storage". | Pinned on the boot stack. It never moves, so it meets H0 but not the reset plan. |
| AP status | I1 foundation status line: "AP execution remains parked". A0 near line 452: I1 work "does not yet admit ordinary AP userspace execution". Architecture index, I1 execution-root entry: "AP execution remains parked". | APs run userspace since `83856db`. All three statements are stale. |
| I1's three unfinished steps | I1: the adapters need owned prepare/commit payloads (1); map/unmap need an owned paging transaction (2); terminal and remote-stop need a reaper transaction (3). | All three still hold. `handle` and `handle_fallthrough` borrow the legacy fields (`:10144`, `:10444`). `map_memory` and `unmap_memory` (`:10830`, `:10980`) jointly borrow Registry, Memory, Tasks and Regions. Terminal paths (`:11136-12087`) mix Tasks, Registry, F-service state and cleanup. |

The usercopy conflict between H0 and C0 is a document conflict. This design
does not resolve it. S2 leaves the lock across usercopy in place, under C0 §6's
bridge. R3 (deferred) removes it. Open question 5 asks Mike which document
should change.

Reset invariants §3.3-§3.7 and §3.10-§3.12 belong to R4-R7 and Wyrmroot. S2K
does not claim them.

## 4. Decisions

### 4.1 `RuntimeCore` and `PagingAuthority`: replaced

**Why not resume them:**
- Nothing has used them in 214 commits. The runtime that shipped took a
  different route (`83856db`), and C0 §6 accepted that route.
- `RuntimeCore` puts five authorities behind one IRQ lock. That is a smaller
  coarse lock, which reset §4.2 rejects as the destination.
- Most adapters borrow paging (the user address space) and the object
  authorities at the same time, for example `handle_duplicate(&mut user,
  &mut registry, &mut tasks, ...)` inside `handle_fallthrough`. The strict
  non-nesting witness between `RuntimeCore` and `PagingAuthority` would force
  every such adapter to split first. That split is I1's step 1, and it is where
  the foundation stalled.

**What survives:**
- `RuntimePhaseReservation`: it is in use (14 references in `primordial.rs`)
  and becomes live once R3 drops the lock mid-syscall.
- The closure discipline: a guard cannot escape a `prepare`/`commit` closure.
- The non-nesting idea. S2K-3 turns it into a compile-time `GuardFree` token.
  The runtime depth counter goes, because it can never fire (§2.4 finding 1).
- The ideas behind `ThreadServiceSlots` (continuation state keyed by
  `ThreadKey`, not by CPU) and `PerCpuStaging`, carried into R3's design.

**What goes:** `RuntimeCore`, `RuntimeCoreState`, `PagingAuthority`,
`ThreadServiceSlots`, `PerCpuStaging`, `StationaryGuardDepth`, their host
tests, and the matching parts of rows 56 and 90. This happens in S2K-1 and
S2K-3. Git history keeps them.

**What replaces them:** R3 picks lock domains from measured borrow sets. It
first builds the dispatch router (deferred step D1). If that measurement shows
most syscalls need Registry, Tasks and paging together, one transaction guard
under H0 §12.5 may be the right answer. §7 lists that outcome as a falsifier of
the "replace" decision.

### 4.2 How `PrimordialRuntimeCarrier`'s responsibilities divide

| # | Responsibility | Where now | Destination | When |
|---|---|---|---|---|
| 1 | **Per-CPU execution identity**: current Process, Thread, stack, context and root key; `active_root(s)`; root-switch epoch and flight; `wait_controls`; `deferred_currents`; `pending_quantum_cancellations`; `channel_staging`; dw1b/dw1c evidence arrays | carrier fields and per-slot arrays, `:3289-3373`; swap at `:3445` | S2K-5 groups them into one `CpuRuntimeState`. S2K-6 moves it into the per-CPU facade (reset `PerCpuRuntime`), deletes `switch_cpu`, and folds `PerCpuLiveCarrier` into it. | S2 (S2K-6 needs approval) |
| 2 | **Root switching**: `Prepared/Executed/Failed*RootSwitch` types, `CarrierActiveRoot` | types `:3051-3288`; methods `:3494-3695`, `:5333-5520` | Transaction types move to a host-compiled module. They already delegate the CR3 effect to `RootSwitchTarget` (`LiveRootSwitchTarget`). `execute` gains a `GuardFree` parameter. Paging state (`active`) stays shared. | S2 (S2K-2, S2K-3) |
| 3 | **Terminal handoff, remote stop, termination**: `TerminalRetirementState`, `PreparedTerminalStep`, `stopping_claim`, `rendezvous_reaper`, `rendezvous_cleanup`, `cleanup`, remote-termination prepare/complete | `:1642-1712`, `:2039-2158`, `:3942-4622`, `:5549-5710`, `:6020-6110`, `:6616-7001`, `:11136-12087` | A terminal engine with a persistent reaper transaction (I1 step 3; reset §6.1 record model; row 24's replacement). S2 adds only the tokens from S2K-3. | Deferred (D2) |
| 4 | **Syscall dispatch**: `handle`, `handle_fallthrough`, `map_memory`, `unmap_memory`, `protect_memory` | `:10144-10355`, `:10444-11135` | A host-compiled router over an explicit authority view and a user-memory trait, with a live implementation and a host fake. It prepares I1 steps 1 and 2 and R3A. | Deferred (D1) |
| 5 | **Object backing**: `MemoryObjectBackingAccess`, `ProcessRootReservation`, `ThreadStartMappingAccess` for `LiveProcessAddressSpace` | `:3375-3433` | Already a trait seam in `crate::syscall`, with host fakes for two of the three (`syscall/adapters/tests.rs:172`, `:2001`). No change. | none |
| 6 | **Primordial supervision and evidence**: `primordial_*`, `kernel_peer`, `process_monitor`, `root_owner`, `channel_keys`, `evidence_init_*`, `g5_probe`, `PrimordialCompletionBackend`, `intercept_*_evidence_raw`, WRCAP, reporter enablement | fields `:3334-3369`; `:6109-6379`, `:6746`, `:6806`, `:7097-8053` | Not moved in S0-S3. Separating scenario code is explicitly unauthorized (plan §0 decision 2). BOOTSTRAP §2 says the primordial "must not remain merely because it was born first", which supports separating it later. | S3 reassessment |

Scheduler, preemption and idle glue (the `NativeSyscallFrameRuntime` impls at
`:7021` and `:8786`, `enter_idle_scheduler` at `:9239`) follows row 1 for its
per-CPU parts. Its locking follows R3.

### 4.3 Type-enforced orderings versus KEEP tests

Rows are line numbers in root `DW1_WYR1_S0_SOURCE_TEXT_TRIAGE.tsv` at root
`7c25dae`, counting the header as line 1. All are `repo=deepwyrm`.

**Mechanisms:**
- **`GuardFree<'a>`**: a zero-sized token that only
  `RuntimeCarrierFacade::guard_free(&mut self)` can create. All 56 acquisitions
  go through `facade.lock(&mut self)`. While a guard is alive, the borrow checker
  forbids creating a token. Physical boundaries take the token: root-switch
  `execute`, `await_remote_stop_permits`, reaper handoff, idle entry,
  `enter_bound_validated_user`, `abandon_to_kernel_continuation`, and
  `switch_kernel_context`.
- **`BoundKernelStack`**: returned by `bind_current_thread_stack` and
  `bind_current_switch_stack`, and required by `enter_bound_validated_user`.
  Today `live.rs:1885-1897` checks this at runtime and fails stopped.
- **`SafePointClear`**: returned by the first mailbox poll in
  `native_runtime_trampoline` (`live.rs:1486`) when the result is not `Stop`.
  `NativeUsercopyWindow::enter_current` requires it.
- **Witnesses:** UI compile-fail cases, using the existing harness in
  `kernel/tests/*_ui.rs`. The token types must live in modules the harness
  configuration compiles, because `primordial.rs` is target-only. The harness
  can pass cfgs (`f11_ipc_ui.rs:197`). Choosing the exact gating is S2K-2
  implementation work.

**Become type-enforced in S2 (the text test is deleted or trimmed in the same
commit, with the mutation check named in the message):**

| Row | Test | Becomes | Mutation |
|---|---|---|---|
| 100 | `dw1c1_root_switches_are_move_only_prepare_execute_commit_transactions` | STATIC (S2K-2): UI cases for reusing a `Prepared*` after `execute` (E0382) and building an `Executed*` outside its module (E0603/E0451) | derive `Clone` on `PreparedSchedulerRootSwitch`; make a field `pub(crate)` |
| 103 | `dw1c1_terminal_handoff_executes_every_root_switch_outside_the_runtime_guard` | STATIC (S2K-3): `execute` takes `GuardFree`; a UI case calls it with a guard alive (E0499/E0502) | pass a token built inside a `lock()` scope |
| 61 | `i1_remote_termination_waits_guard_free_for_exact_ack_before_reclaim` | guard-free half STATIC (S2K-3). The trampoline and ack-before-reclaim half stays KEEP. | as for row 103, on `await_remote_stop_permits` |
| 93 | `i1_ap_and_rendezvous_fresh_entries_bind_the_selected_thread_stack_before_cpl3` | STATIC (S2K-3): `BoundKernelStack` | call `enter_bound_validated_user` without the token |
| 97 | `i1_syscall_entry_polls_remote_stop_before_usercopy_or_dispatch` | first seam STATIC (S2K-3). The two post-dispatch rechecks stay KEEP. | open the usercopy window before the poll |
| 56 | `i1_native_adapter_phases_revalidate_exact_identity_after_guard_free_work` | trimmed (S2K-3): drop the `assert_guard_free_external_work` pins, because the check is a no-op (§2.4 finding 1). Reservation ordering stays KEEP until D1 makes it live. Anchor the slice on the carrier's `handle`. | remove `commit_runtime_phase` from `handle` |
| 90 | `i1_stationary_foundation_keeps_authority_and_carrier_boundaries_explicit` | trimmed (S2K-1): delete the assertions on the deleted types; keep the facade-binding assertions | remove `bind_runtime_carrier_facades` call |
| 23 | `wyr1_bootfs_capacity_owns_the_page_ceiling_without_recursive_media_identity` | DELETE closes (S2K-0): the duplicate it relies on now runs | break `integration_bootfs_page_count` rounding |

**Become type-enforced only with S2K-6 (Mike's call):**

| Row | Test | Becomes |
|---|---|---|
| 72 | `i2_terminal_reclaim_handoff_is_owned_by_the_exact_physical_cpu` | STATIC: `deferred_current` lives in the facade's own `CpuRuntimeState` |
| 85 | `i1_live_wait_suspension_uses_the_physical_current_cpu` | STATIC for the primordial CPU binding. The f_services and adapters reads stay. |
| 89 | `h2_syscall_entry_and_native_runtime_carriers_are_fixed_per_cpu` | primordial part STATIC. The `live.rs` and `runtime_binding.rs` parts stay KEEP. |
| 96 | `i1_live_wait_control_is_owned_by_each_physical_cpu_carrier` | STATIC: no shared `wait_controls` array exists to index |
| 101 | `dw1c_detach_commits_its_root_flight_without_ordinary_cpu_reselection` | DELETE: once `switch_cpu` is gone, no reselection exists |

Under S2K-5 alone, rows 72, 85, 89 and 96 are re-pinned to the new field paths
and stay KEEP.

**Candidates that need lane paths widened (open question 3):**
- Row 76, `live_return_boundary_publishes_final_release_effects_before_userspace_resume`:
  a `FinalizersDrained` token would have to go through
  `kernel/src/syscall/native.rs`.
- Row 102, `dw1c1_ap_carrier_enters_its_exact_kernel_root_before_ready_publication`:
  ready publication would take the `ExecutedApKernelRootEntry` proof, in
  `task/scheduler/carrier_admission.rs`.

**Stay KEEP.** The one-line reason is shared within each group:
- *Assembly or hardware instruction order that no Rust type can see:* 49, 50,
  51, 86, 87, 88, 112, 114, 118, 119, 122, 124, 125, 126, 127, 129, 130, 131,
  144.
- *Mailbox, IPI and safe-point races under the coarse lock, until D1/R3:* 60,
  62, 63, 70, 71, 78, 109, 113, 115, 145.
- *Terminal teardown ordering, until D2:* 57, 68, 69, 81, 82, 84, 108, 110,
  135, 136.
- *Selector evidence and capacity surfaces (scenario code, out of scope in
  S0-S3):* 6-13, 17, 18, 22, 41-45, 73, 74, 75, 79, 80, 83, 152-156.
- *Other live wiring S2K does not touch:* 29, 30, 52, 53, 58, 64, 66, 67, 91,
  92, 98, 107.

The kernel HOST rows (21, 24, 25) and STATIC row 59 stay in S3. S2K neither
blocks nor performs them. Per §2.4 finding 7, rows 21 and 25 must land in
host-compiled modules.

### 4.4 The four orphaned tests

Move each test, with the pure code it tests, into a module the host compiles.
A guest-side test runner would cost far more and prove less.

| Test | Move | Gate for the new module | Mutation |
|---|---|---|---|
| `primordial.rs:10117` | `integration_bootfs_page_count` (`:9729`, a `const fn`, today gated `any(test, <evidence cfgs>)` at `:9718-9728`) and its test | `cfg(any(test, <the same evidence cfgs>))` in a module outside `primordial.rs`, so the host `test` build compiles it | off-by-one in the rounding |
| `user_access.rs:1210`, `:1244` | `LiveTlbMailbox` and its state constants (`user_access.rs:15-60+`): atomics, `UnsafeCell`, and host-compiled `address_region` types | `cfg(any(test, all(target_os = "none", target_arch = "x86_64")))`, like `stationary_runtime` (`syscall.rs:9`) | drop the overlapping-publication rejection |
| `test_support/x86_64.rs:1371` | `claim_dw1c_terminal_on` (`:674`) and its test | host-compiled under `test` and the test-support target build | replace `compare_exchange` with `store` |

**Guard against recurrence:** add a counter to the S1.3 text ratchet
(`tooling/lint-ratchet.txt`): `#[test]` occurrences in target-only files,
baseline 0. The file list starts from S1 §4's list of code host clippy never
sees. The mutation check adds a `#[test]` to `primordial.rs` and confirms
`xtask clippy` fails. The list can drift (§6).

`test_support/x86_64.rs` is outside S2K's lane paths (plan §5). Moving the
helper needs the coordinator to widen the lane for that one file.

### 4.5 ABI boundary

- No step changes `abi/schema`, the generated ABI, syscall numbers, statuses,
  object types, rights, `DwBootInfoV1` or the primordial handoff.
- S2K-4 lowers boot-stack *use*. It does not change the linked boot-stack
  size, which is a Wyrmroot-pinned seam (`KERNEL_BOOT_STACK_BYTES` in
  wyrmroot `tools/xtask/src/deep_layout.rs`, per R5E §4).
- S2K-4 keeps `debug::liveness::publish_runtime_authority` (`:10044`). Root
  `tools/gdb/r1-liveness.gdb` still reads the ticket pair through that
  published pointer. The adjacency assertion at `:1555-1569` stays.
- If any step turns out to need a shared-contract change, it stops and goes
  through `AGENTS.md` §7. None is expected.

## 5. Staging and validation

**Every commit** runs the deepwyrm host gates through `tools/pinned-cargo`, as
S1 §3 ran them: `xtask format`, `check` (all selector builds), `clippy` with the
ratchet, `doc`, `abi check`, and the unfiltered `test host`. Each commit is one
kind (plan §3 rule 1). A move commit names the check that shows it preserved
behavior.

**Each step's integration** also runs the plan §6 native gates on a wyrmroot
pair and kernel `cargo test`.

**End of S2** runs the F qualifying matrix on the new exact pair. Evidence and
COM1 witnesses are compared by content (plan §6).

### 5.1 S2: behavior-preserving

| Step | Change | Extra validation |
|---|---|---|
| **S2K-0** | Move the four orphaned tests (§4.4), one commit per group. Delete row 23. Add the ratchet counter. | The host test count rises by 4. Each commit names its mutation. |
| **S2K-1** | Delete the unused stationary types (§4.1) and trim row 90. | `xtask check` across all selector builds shows no user. |
| **S2K-2** | Move the root-switch transaction types to a host-compiled module, generic over `RootSwitchTarget`. Add UI cases. Convert row 100. | UI cases fail against the named mutations. Native gates cover the live root switch; the SMP legs also exercise it. |
| **S2K-3** | Add `lock(&mut self)`, `GuardFree`, `BoundKernelStack` and `SafePointClear`. Move `RuntimeAuthorityLock` and its guard to a host-compiled module (they use only atomics). Remove the no-op depth check. Convert rows 103, 93, 97 (seam 1), 61 (half); trim row 56. | The compiler accepting every existing site is the evidence that no physical boundary runs under the guard. A site it rejects is a real C0 §6 defect: stop and report it (§7). |
| **S2K-4** | Permanent storage (reset R2D). Make `'roles` `'static`: `FrameRoleManager` already lives in `BOOTSTRAP_ROLE_MANAGER` (`lib.rs:119`). Move the lock and carrier, then the facade array, into one-shot static storage. | `tools/accepted-primordial-stack-gate`: boot chains shrink. Update the oracle's asserted figures in the same commit as a measured change. The GDB publication still resolves. |
| **S2K-5** | Group the per-CPU fields into `CpuRuntimeState`. `switch_cpu_state` becomes one struct swap and keeps the retain-previous fallback exactly (§2.4 finding 4), documented. Re-pin rows 72, 85, 89 and 96. | Selector builds cover the dw1b/dw1c evidence arrays that move with it. |

Order constraints:
- S2K-3 and S2K-4 move `unsafe` code into host-compiled files. Host clippy then
  sees those blocks, and the ratchet forbids a rise. Land them after the
  parallel `SAFETY`-comment lane merges. Fix wildcard matches in a preceding
  commit inside `primordial.rs`, then move.
- S2K-2 comes before S2K-3, because S2K-3's `execute` signature needs the moved
  types.
- S2K-4 is independent of S2K-2 and S2K-3. It could land first if the SAFETY
  lane is late.

### 5.2 S2: one semantic step, only with Mike's approval

**S2K-6: per-CPU split (reset R2B, R2C, R2E).**
- Move `CpuRuntimeState` into each facade. Carrier methods take
  `&mut CpuRuntimeState` explicitly. Delete `switch_cpu` and
  `switch_cpu_state`: 36 call sites become 0. Fold `PerCpuLiveCarrier` in, so
  each per-CPU fact has one source of truth.
- **Named behavior change:** an empty CPU slot no longer inherits another CPU's
  identity. Before the commit, answer finding 4's question with a probe. The
  probe is a host model of the swap, plus a review of every read that happens
  before `synchronize_scheduler_current`.
- Validation: host gates; every native gate; the F matrix UP and SMP; R0C
  deletion-proof numbers (`switch_cpu` 36 to 0). Convert rows 72, 85, 89 and
  96; delete row 101.
- **Recommendation: approve it for S2.**
  - Reset §15 requires R2 whatever else happens.
  - The end-of-S2 F matrix validates it anyway.
  - Without it, S3 re-pins rows 72, 85, 89, 96 and 101, and then re-pins them
    again later.
  - It is the step most likely to hit the plan §3 stop rule. It starts only
    after S2K-0 through S2K-5 are green.

### 5.3 Deferred until after the S3 reassessment

All of these are semantic. Each needs its own approval and SMP VM evidence.

- **D1 (R3A/R3B): lock decomposition.**
  - Build the host-compiled dispatch router (§4.2 row 4).
  - Measure each syscall family's borrow set.
  - Split adapters into owned copy-in, prepare, commit and copy-out payloads
    (I1 step 1).
  - Take `RuntimeAuthorityLock` off ordinary dispatch.
  - This resolves the H0 §12.8 conflict, and it needs R1's question-6
    instrument, which is still untested on a live stall (R1 record §8).
- **D2: terminal engine** (I1 step 3, reset §6.1, row 24). It converts the
  terminal KEEP group.
- **D3: owned paging transaction** (I1 step 2). This is the real successor to
  `PagingAuthority`.
- **D4: primordial supervision and evidence separation** (§4.2 row 6). Not
  authorized by this plan.
- **D5: rows 76 and 102**, if their lanes are widened.

## 6. Risks

- **Ratchet collisions.** Moving target-only code into host-compiled modules
  exposes it to host clippy. Counts can rise, and the ratchet forbids that.
  Mitigation: the order constraints in §5.1.
- **Guest runtimes share types.** The E7, F9 and F12 guest runtimes
  (`mm/activation/test_support/`, 3,700 lines) implement the same traits and
  use `RuntimePhaseReservation`. *Question:* does `xtask check` build every
  `deepwyrm_*_guest` cfg? If not, S2K-1 through S2K-3 can break them silently.
- **S2K-4 lifetime work may spread.** `'roles` threads through
  `LiveActivePagingTarget` (`mm/activation.rs:681`) and `ActiveDeepPaging`.
  Making it `'static` looks feasible, since the backing storage is already
  static. It is not yet verified.
- **Static storage needs concrete generics.** The carrier is generic over
  `RANGE_CAPACITY` and `ROLE_CAPACITY`. The offset assertion (`:1555`) names
  `<128, 4096>`. *Question:* is that the only instantiation in every build?
- **The S2K-5 and S2K-6 diffs are large.** They touch most of the 12k-line file
  and hundreds of `self.process` and `self.thread` reads. Review load is high.
  Rebases against other activation work are likely.
- **The orphan counter's file list can drift.** A new target-only file would
  escape it until someone adds the file.
- **S2K-3 may find a real defect.** If the compiler rejects a site, a physical
  boundary runs under the guard today. That is a product defect, fixed as a
  named semantic change (plan §2), not inside the refactor.
- **The IF-clear ticket lock stays through S2.** A CPU spinning on it cannot
  take interrupts (R0C §1). S2 does not change this. D1 does.
- **Stack oracle figures change on S2K-4.** They are asserted exactly. An
  unexplained change elsewhere in the same commit would hide a regression.

## 7. What would falsify this design

- **S2K-0 fails** if a moved test cannot compile on the host without pulling in
  target-only dependencies. Then that test needs a different runner.
- **S2K-3 fails** if some physical boundary legitimately needs to run while the
  guard is held. The design predicts none does (C0 §6). A rejected site means
  either a defect or a wrong token design; the evidence decides which.
- **S2K-4 is not behavior-preserving** if static storage changes any evidence
  record or COM1 witness by content.
- **S2K-6 is not a cleanup** if the finding-4 probe shows a live path reads the
  inherited identity. It is then a real behavior change, and it needs its own
  targeted tests before the F matrix.
- **"Replace" (§4.1) was wrong** if D1's measurement shows most syscall
  families need Registry, Tasks and paging together. One H0 §12.5 transaction
  guard, which is `RuntimeCore`-like, would then be the right shape.
- **The staging order is wrong** if S3 conversions need D1's router to be
  possible. Rows 21, 24 and 25 do not; this is checked in §4.3.

## 8. Open questions for Mike

1. Approve S2K-6 (the semantic per-CPU split) inside S2, or defer it until after
   S3? Recommendation: approve.
2. Delete the unused stationary types in S2 (S2K-1)? Recommendation: yes.
3. Widen S2K's lane paths to `kernel/src/test_support/x86_64.rs` for S2K-0?
   Separately, widen them to `kernel/src/syscall/native.rs` and
   `kernel/src/task/scheduler/carrier_admission.rs` for rows 76 and 102, or
   leave those two rows KEEP?
4. After approval, should the coordinator mark
   `DW0_I1_STATIONARY_RUNTIME_FOUNDATION.md` as superseded by this design, and
   fix the three stale "APs parked" statements (§3)?
5. H0 §12.8 and C0 §6 conflict on locks across usercopy. Should H0 record the
   coarse lock as an accepted bridge until D1, or should D1 be scheduled now as
   a committed phase?

## 9. Follow-ups outside this file (coordinator-owned)

- Correct the refactor plan's "232 commits" figure, or state how it was counted.
- Mark TSV rows 21 and 25: their replacements must target host-compiled modules
  (§2.4 finding 7).
- Record finding 1 (the no-op guard-free check) and finding 2 (the phase
  reservation cannot see drift under the coarse lock) in the S2 record.
- Update the architecture index I1 entries once this design is approved.

## 10. Nonclaims

- No code, test, build, gate or VM run was executed for this design. It rests
  on source reading, `git log`, `git grep` and line counts at deepwyrm
  `ef1384d`.
- Counts are static text counts, not compiler-verified. Findings 4 and 5 are
  labelled questions and remain unverified.
- No security review was done. The `GuardFree` and per-CPU work is
  soundness-relevant. Its security classification belongs to the
  implementation review.
- Nothing here claims R4, R5, R6 or R7 outcomes, or DW1/WYR1 closure.
- The step boundaries are proposals. Mike's approval, not this document,
  authorizes any S2K implementation.

## 11. Mike's decisions (2026-09-28)

Mike's instruction: "Proceed with the most proper solution we have at the time
for all items in S2K -- no temporary bandaids." Applied to §8:

1. **The design is approved.** S2K-0 through S2K-5 proceed as §5.1 stages them.
2. **S2K-6 proceeds inside S2**, after S2K-0 through S2K-5 are green. The
   finding-4 probe (§5.2) runs first, and its answer is recorded in S2K-6's
   commit message as the named behavior change or its absence.
3. **The unused stationary types are deleted** (S2K-1).
4. **The lane is widened to all three files:** `kernel/src/test_support/x86_64.rs`
   for S2K-0, and `kernel/src/syscall/native.rs` and
   `kernel/src/task/scheduler/carrier_admission.rs`. D5 (rows 76 and 102) is
   therefore not deferred. Those rows are type-enforced in S2, not left KEEP.
5. **The I1 foundation is marked superseded** by this design, and the three stale
   "APs parked" statements (§3) are corrected.
6. **The H0 §12.8 / C0 §6 conflict is resolved by D1, not by amending H0.**
   Recording the coarse lock as an accepted bridge would be the temporary
   measure the instruction rules out.
   - D1 (lock decomposition, §5.3) moves out of the deferred list and follows
     S2K-6.
   - H0 §12.8 stands as written: no runtime lock is held across usercopy.
   - D1 starts with a short design addendum in this file: the measured borrow
     set of each syscall family, and the prepare/commit split for each.
     Implementation follows it. Each semantic commit carries its own SMP VM
     evidence, per §5.3.
7. **The S2K SAFETY pass's findings get proper fixes, not comments.** They are
   recorded in root `DW1_WYR1_S2_SEAMS_RECORD.md` §1 S2K and in the
   `UNVERIFIED (S2K)` comments. Each fix is its own named semantic commit.
   - **F1:** the facades' admission state is set before carrier pointers are
     published, or the facades are held behind raw pointers from creation, so
     no `&mut` is taken after publication.
   - **Idle halts:** drop `nomem` from both `sti; hlt; cli` sequences.
   - **`iret_validated_user`'s 40-byte push:** measure it on the release kernel,
     and make the path correct by construction whatever codegen does.
   - **The quantum-expiry reborrow:** fixed by the per-CPU ownership S2K-6
     establishes, or directly if S2K-6 does not reach it.
   - **`copy_module`:** use `MaybeUninit`-correct writes.

   Each `UNVERIFIED (S2K)` comment is replaced by a real justification when its
   fix lands.

D2 (terminal engine) and D3 (owned paging transaction) were not questions to
Mike. They stay deferred until after the S3 reassessment. D4 remains outside
this plan's authority.

### 11.1 S2K-6 revised: owner-local facts move, remotely read facts stay under the lock (2026-10-14)

The S2K-6 worker stopped before step 2, as §7 and the stop rule require.
§5.2 moves all of `CpuRuntimeState` into each facade, but six of its facts
are read or written by *other* CPUs under the runtime lock. A facade is
exclusively `&mut` on its own CPU, so those accesses would alias it.
Confirmed from source at `2338f47` (`primordial.rs`):

- `terminal_stop_plan` reads each remote CPU's `identity`,
  `root_switch_flight` and `active_root`;
- `retire_unentered_terminal_replacements` stages a remote CPU's
  `pending_quantum_cancellation`;
- `service_state_is_quiescent`, `finish_terminal_teardown` and the dw1d
  event-0x17 check read every CPU's `wait_control`;
- `prepare_terminal_retirement_state` asserts no CPU holds a
  `deferred_current`.

Coordinator decision, under Mike's "most proper solution, no temporary
bandaids" instruction (§11). Mike may overrule it.

1. **Owner-local facts move into the facade:**
   - `channel_staging`;
   - `root_switch_epoch`;
   - the dw1b/dw1c evidence options;
   - `PerCpuLiveCarrier`, folded in as a plain field without its
     `IrqSpinMutex`. Every access goes through the current CPU's `local`,
     so nothing else ever touches it.

   Its `current_thread`, `current_stack` and `current_context` say what
   physically executes now, and are `None` when the CPU idles. That is a
   different fact from `identity`, the last scheduled identity that remote
   CPUs read. Both are kept, under names that say which is which. Neither
   copies the other.
2. **Remotely read facts stay in the lock-protected carrier `cpus[]`,** as
   the single source:
   - `identity`;
   - `active_root`;
   - `root_switch_flight`;
   - `wait_control`;
   - `deferred_current`;
   - `pending_quantum_cancellation`.

   Only the owning CPU's facade path may mutate its own slot, and the type
   system enforces it: carrier methods receive the owner's slot explicitly,
   and remote access is read-only. The one remote write,
   `stage_scheduler_quantum_cancellation_on` for another CPU, is its own
   named, documented operation.
3. **Deleted:**
   - the carrier's current-CPU copies: `cpu`, `local`, `active_root`,
     `process`, `thread`, `stack_id`, `context_id`, `root_key` and
     `channel_staging`;
   - `switch_cpu` and `switch_cpu_state`.

   The R0C count at `2338f47` is 38 call sites (37 `switch_cpu(self.cpu)`,
   1 dead `select_cpu`, 1 `switch_cpu_state` in `select_root_switch_flight`)
   plus 2 definitions. All go to 0. §5.2's figure of 36 was an undercount.
4. **Named behavior change** (finding-4 probe, recorded in the S2K-6 commit):
   - an empty slot reports no identity;
   - the liveness mirror no longer names another CPU's Thread or Process;
   - no decision output changes.
5. **[CARRIER] gaps 1 and 2** close by this ownership. If the
   quantum-expiry handler needs a per-CPU context outside the facade to do
   so, that context is owner-only and type-enforced. Its handle-locking
   rule is stated in the commit and in this section, not left implicit.
6. **Rows 72 and 96** become STATIC in this form: owner-only mutation is a
   type fact. They no longer rest on the premise that no shared array
   exists.

Rejected:

- **Keeping everything in `cpus[]` behind per-CPU tokens.** It is the
  smaller diff, but it leaves the owner-local facts shared and proves less.
- **Moving the six facts into the facades and reaching them remotely
  through raw pointers.** That is the aliasing the stop prevented.

### 11.2 D1 addendum: measured borrow sets and the prepare/commit split (2026-10-21)

This is D1's first step under §11 item 6: documents only, no kernel change.
H0 §12.8 stands. It was measured from source at deepwyrm `d2eef61` and
rests on reading, not a run. Path abbreviations: `P` is
`kernel/src/arch/x86_64/mm/activation/primordial.rs`, `A` is
`kernel/src/syscall/adapters.rs`, and `F` is `kernel/src/syscall/f_services.rs`.

#### 11.2.1 Borrow set of each syscall

**Today, every ordinary syscall runs in one hold.** The facade calls
`with_synchronized_runtime_at_safe_point` (`P:8287`). That function locks
(`P:1955`), runs the carrier's `handle` (`P:9870`), and returns through
`ready_to_return`. A suspended wait's result is written back on resume,
also inside a hold (`P:9298`, then the carrier's `resume_suspended` at
`P:7739`, which builds a user address space at `P:7754`). The F-service arms
reach their adapters through `dispatch_prepared` (`F:212`). Every other arm
goes through `handle_fallthrough` (`P:10217`) or `map_memory`,
`unmap_memory` and `protect_memory` (`P:10606`, `:10755`, `:10831`).

**How to read the table:**

- `w` means the path takes the authority as `&mut`. It is a borrow, not
  proof of a mutation.
- `r` means `&`.
- *Shared* lists members of `PrimordialRuntimeShared` (`P:1502`). Each has
  its own interior synchronization, so they are outside the question.
- *Paging* is the guarded `core.active` (`ActiveDeepPaging`):
  - `U` is a usercopy walk. `current_process_address_space` holds
    `&mut root_bindings` and `&mut FrameRoleManager` (`activation.rs:1886`,
    `user_access.rs:264`).
  - `M` is a page-table or frame-role mutation.
- *Copy* is where the path touches user memory.

| Syscall | Path | Registry | Tasks | Memory | Regions/Spaces | F-service/cleanup | Shared | Paging | Own CPU slot | Copy |
|---|---|---|---|---|---|---|---|---|---|---|
| AbiGetInfo | `P:10219`, `A:473` | | | | | | | U | root (r) | out |
| ClockGet | `F:455`, `A:514` | | | | | | clock | U | root (r) | out |
| HandleClose | `P:10236`, `A:774` | w | w | | | cleanup | | | | none |
| HandleDuplicate | `P:10272`, `A:799` | w | w | | | | | U | root (r) | out |
| ObjectGetInfoV1 | `P:10291`, `A:906` | w | r | r | | | devices, interrupts | U | root (r) | out |
| TaskGroupCreate | `P:10319`, `A:1471` | w | w | | | cleanup | | U | root (r) | out |
| ThreadCreate | `P:10342`, `A:5081` | w | w | | | cleanup | | U | root (r) | out |
| ThreadStart | `P:10362`, `A:6700` | w | w | | | cleanup | execution | U (validation walks) | root (r) | none |
| MemoryObjectCreate | `P:10413`, `A:6945` | w | w | w | | cleanup | | M (zeroed backing) | root (r) | out |
| ProcessCreate | `P:9895`, `A:2771` | w | w | | w / w | cleanup | | M (child root) | root (r) | in, out |
| ChannelCreate | `F:278`, `A:2879` | w | w | | | | channels | U | root (r) | out |
| ChannelSend | `F:292`, `A:3001` | w | w | | | cleanup | channels, waits, execution | U | staging (owner-local) | in (`A:3046`, `:3088`, before authority work) |
| ChannelReceive | `F:317`, `A:3212` | w | w | | | cleanup | channels, waits, execution | U | staging (owner-local) | out |
| WaitOne | `F:341`, `A:4560` | w | w | | | wait operations | events, timers, channels, interrupts, waits, execution, deadlines | U | `wait_control` (w) | out (owned, on resume) |
| WaitMany | `F:366`, `A:4679` | w | w | | | wait operations | same as WaitOne | U | `wait_control` (w) | in, out (owned, on resume) |
| EventCreate | `F:393`, `A:4837` | w | w | | | cleanup | events | U | root (r) | out |
| EventSignal | `F:406`, `A:4893` | w | r | | | cleanup | events, waits, execution | | | none |
| AtomicWait32 | `F:422`, `F:511` | (unused) | w | | regions (r) | atomic waits | execution, deadlines | U (pin) | `wait_control` (w) | in (atomic load under pin) |
| AtomicWake | `F:441` | | w | | regions (r) | atomic ops | execution | U | root (r) | out |
| TimerCreate | `F:464`, `A:4941` | w | w | | | cleanup | timers | U | root (r) | out |
| TimerSet | `F:477`, `A:4997` | w | r | | | cleanup | timers, deadlines, waits, execution | | | none |
| TimerCancel | `F:491`, `A:5045` | w | r | | | cleanup | timers, deadlines | | | none |
| DeviceResourceClaim | `P:10468`, `A:1547` | w | w | | | | grants, devices | U | root (r) | out |
| DevicePioRead | `P:10491`, `A:1884` | w | w | | | | devices, port I/O | U | root (r) | out |
| DevicePioWrite | `P:10515`, `A:1922` | w | w | | | | devices, port I/O | | | none |
| InterruptCreate | `P:10534`, `A:1954` | w | w | | | | devices, interrupts, platform | U | root (r) | out |
| InterruptAck | `P:10556`, `A:2004` | w | w | | | cleanup | interrupts, platform, waits, execution | | | none |
| AddressRegionMap | `P:10606` | w | w | w | regions (w) | cleanup | | M, then shootdown wait (`P:10701`) | root (r) | in (args), out (owned) |
| AddressRegionUnmap | `P:10755` | w | w | w | regions (w) | cleanup | | M, then shootdown wait (`P:10789`) | | none |
| AddressRegionProtect | `P:10831` | w | w | w | regions (w) | cleanup | | M, then shootdown wait (`P:10866`) | | none |
| ProcessExit, ProcessTerminate, TaskGroupTerminate, ThreadTerminate | facade `P:8086-8285` | w | w | w | w | services, cleanup, rendezvous | execution | M (Process-scope root teardown) | own (w), remote (r) | none |
| ThreadExit | `native.rs:783` (terminate-current path) | w | w | | | cleanup | execution | | own (w) | none |

**Totals over 35 syscalls:**

- **Registry and Tasks together: 31.** The four that need only one or
  neither are AbiGetInfo, ClockGet, AtomicWait32 and AtomicWake.
  - Every handle resolution goes through the Process handle table, which
    lives in `TaskAuthority`.
  - It retains or releases in the registry. That pairing is H0 §12.4's one
    standing nested exception.
- **Memory, Regions, Spaces and F-service state never appear without
  Tasks.**
- **Paging mutation (`M`): 8**, all of which also need Registry and Tasks:
  MemoryObjectCreate, ProcessCreate, the three AddressRegion calls, and the
  three Process-scope terminations.
- **Usercopy: 21 syscalls**, every one inside the hold.

#### 11.2.2 Where usercopy happens

- **All usercopy is inside the hold.** The adapters already order it in an
  F0-compatible way:
  - input is snapshotted before the authority work (`A:3046`, `:3088`,
    `:4273`);
  - an output is preflighted and pinned first (`preflight_output`,
    `A:350`), then committed after publication (`A:824`).
- **The mechanism that makes copying safe without the lock already
  exists.**
  - Usercopy pins its range in `UserPinTracker` (`user_access.rs:335`),
    which has its own spin lock.
  - A pin fails any overlapping page-table mutation or address-space
    teardown with `Conflict`, rather than waiting (`memory/usercopy.rs:293`,
    `reserve_teardown`).
  - The copy itself goes through the user virtual address once preflight
    has walked the tables (`user_access.rs:447`, `:462`).
  - What ties the copy to the guard is the walk. It reads the guarded
    `root_bindings` and the plain `&mut FrameRoleManager`
    (`user_access.rs:747-799`).
- **A second hold violation: the shootdown acknowledgement wait.** The three
  AddressRegion calls wait for remote TLB acknowledgement inside the hold,
  through `CoherentAddressSpacePublisher` (`coherency.rs:745-751`, bounded
  at `WAIT_STEPS`, then `panic!`). H0 §12.8 forbids that too.
  - **Risk, reasoned from source and not reproduced:**
    1. A target CPU runs a sibling Thread of the same address space.
    2. It enters any syscall, or takes a quantum-expiry interrupt that
       locks through `P:1785`, while the initiator is waiting.
    3. That CPU spins in the ticket lock with IF clear
       (`runtime_authority.rs:152`). It cannot take the shootdown IPI.
    4. The initiator therefore panics with "address-space shootdown
       acknowledgement timeout".
  - D1 commit 4 removes it. An SMP stress with a multithreaded unmapper
    would confirm the risk.

#### 11.2.3 The prepare / commit split for each family

**Every family has the same five parts:**

- **Copy-in:** an owned copy-in before any lock.
- **Prepare:** under the narrowest lock that suffices.
- **Commit:** cannot fail.
- **Copy-out:** into a range pinned during prepare, after release, so it
  cannot fail either.
- **Revalidation at commit:**
  - `RuntimePhaseReservation` (`reserve_runtime_phase` and
    `commit_runtime_phase`, `P:4669-4692`) checks that the scheduled Thread
    and root binding generation have not changed. A syscall runs with IF
    clear on one CPU and does not switch between its holds, so drift is an
    invariant violation and stays a `panic!`. §2.4 finding 2 closes: the
    check becomes live.
  - Changes made by *other* CPUs between holds are caught by state that
    already exists:
    - a `ProcessOperationLease` taken in prepare;
      `validate_process_operation` checks it at commit, and quiescing
      refuses new leases (`task/authority.rs:629-651`);
    - an object retain taken at resolution;
    - the Stop poll that every acquisition already does
      (`take_current_notification_at_safe_point`, `P:1958`).
  - **If any check fails,** the payload is aborted: release the lease and
    pins, cancel the reservations, `RuntimePhaseReservation::abort`. The
    syscall returns `service_rendezvous` (for a Stop) or its status, with no
    side effect published.

**The families:**

- **A. No authority** (AbiGetInfo, ClockGet). No runtime lock at all. Pin,
  preflight and copy-out run under the paging lock only, and the copy runs
  under the pin only.
- **B. Output only** (HandleDuplicate, ObjectGetInfoV1, TaskGroupCreate,
  ThreadCreate, ChannelCreate, EventCreate, TimerCreate,
  DeviceResourceClaim, DevicePioRead, InterruptCreate, AtomicWake,
  MemoryObjectCreate).
  - Preflight and pin the output under the paging lock, before the
    transaction guard.
  - Prepare and commit happen in one guard hold. These adapters already
    validate and publish atomically.
  - Copy out after release.
  - MemoryObjectCreate allocates its zeroed backing under the paging lock
    before the guard, and frees it there if the commit is refused.
  - **Named semantic change:** a sibling Thread can see, or close, a newly
    published handle before the caller's copy-out stores its value. Today
    the hold hides that window.
- **C. No usercopy** (HandleClose, EventSignal, TimerSet, TimerCancel,
  DevicePioWrite, InterruptAck). One short guard hold. The lock structure
  does not change these.
- **D. Copy-in** (ChannelSend, ProcessCreate, WaitMany items, map
  arguments).
  - Snapshot into owned storage before the guard. Channel staging is
    already owner-local (`CpuOwnedState`).
  - Transferred handle values are resolved under the guard.
- **E. Waits** (WaitOne, WaitMany, AtomicWait32, resume).
  - Register the waiter under the guard and decide on suspension there.
  - Write the owned output (`OwnedLiveUserOutput`) on resume, after
    release.
  - AtomicWait32's compare-load moves out of the hold, futex-style:
    1. register under the guard;
    2. release;
    3. load through the pin;
    4. reacquire and either commit the suspension or cancel on mismatch.
  - A wake after step 1 finds the waiter, so no wakeup is lost.
- **F. ChannelReceive.** Dequeue into owner-local staging and install
  handles under the guard. Copy the payload and handle values out after
  release.
- **G. AddressRegionMap, Unmap and Protect.**
  1. Prepare under the guard: resolve handles, reserve the region, and take
     table candidates under the paging lock beneath it.
  2. Publish the page tables under the paging lock, still beneath the
     guard.
  3. Release both and wait for shootdown acknowledgement guard-free.
  4. Reacquire the guard and commit lease release and reclamation, which
     H0 §12.6 requires to follow acknowledgement.
  - Publication is the point of no return, so that commit cannot fail.
  - **Named semantic change:** an unmap or protect over a range that a
    sibling Thread's in-flight syscall has pinned now fails on the pin
    `Conflict`. The returned status is chosen in that commit. Today this
    case cannot happen.
- **H. Termination** (the five terminal syscalls). These belong to D2. D1
  changes nothing here: they do no usercopy, and the remote-stop wait is
  already guard-free (`await_remote_stop_permits` takes `GuardFree`).

**Pin capacity** (`E5_USER_PIN_CAPACITY` = 32, `activation.rs:183`) must
cover four CPUs × three transient pins plus every suspended wait's owned
pin. The commit that introduces family B checks this.

#### 11.2.4 The lock structure

**Decision: one H0 §12.5 transaction guard for the object authorities,
plus a separate paging lock. Not a lock per authority.**

- **T, the runtime transaction guard,** is `RuntimeAuthorityLock`,
  narrowed. It covers:
  - Registry, Tasks, Memory, Regions and Spaces;
  - `FServiceState` and the cleanup queues;
  - the stopping, rendezvous and supervision fields;
  - the `cpus[]` slots.

  It is held only for prepare and commit, never across usercopy, a
  shootdown wait, CR3 completion, idle, `sti; hlt` or user return.
- **P, the paging lock,** covers `ActiveDeepPaging`: root bindings,
  `FrameRoleManager` and the scratch bindings. `user_pins` already has its
  own lock and becomes `&'static`, outside both.
- **The `PrimordialRuntimeShared` authorities are unchanged.**
- **Order:** T, then P. P is taken beneath T one component at a time
  (§12.5: sequential, never nested), or alone for pin, preflight and walk.
  Never P then T. The pin tracker's lock is a leaf. Shootdown waits and the
  copies themselves hold neither lock.
- **Families that need both T and P:** MemoryObjectCreate, ProcessCreate,
  the three AddressRegion calls, and Process-scope termination. That is 8
  of 35, and always sequential.

**Why the measurement points this way:**

- Registry and Tasks are written together by 31 of 35 syscalls.
- Memory, Regions, Spaces and F-service state are strict subsets of that
  group.

Separate Registry and Tasks locks would therefore be taken back to back by
nearly every syscall. That buys no parallelism, only an ordering obligation.
§7's falsifier fires for the object half: a transaction guard is the right
shape.

It does not fire for paging. Only 8 of 35 mutate paging, and usercopy needs
only a consistent walk. Paging must become separable anyway, so that copies
and shootdown waits can leave T.

The result is the `RuntimeCore`/`PagingAuthority` shape that §4.1 declined.
§4.1's objection was that the non-nesting witness would force every adapter
to split first. D1 is that split, so the objection no longer holds. The
deleted types are not revived: T is the existing lock with less under it.

**Quantum expiry may not need T at all.** `QuantumExpiryPublisher` locks T
(`P:1785`) only to reach `core.shared.execution`. Its scheduler state sits
behind its own `IrqSpinMutex` (`task/scheduler.rs:1788`), and tickets
carry generations.

- If no T-held transaction depends on excluding expiry publication,
  `InterruptAuthorityHandle` can go. T would then never be taken from
  interrupt context.
- **Hypothesis:** commit 2 must check this before relying on it.

#### 11.2.5 Token types

- **`GuardFree`** widens to mean "this CPU holds neither T nor P".
  - Both locks are acquired through the CPU's handle. P beneath T is
    reached through T's guard.
  - New consumers:
    - the usercopy step, which makes H0 §12.8 for usercopy a type fact;
    - the shootdown wait;
    - `soft_off_then_halt`.
- **`SafePointClear`** keeps its meaning (the entry poll before usercopy).
  It is no longer sufficient by itself: each later T acquisition re-polls
  Stop, as it does today.
- **`BoundKernelStack`** is unchanged.
- **`ReturnReady`** changes meaning.
  - Today it is minted under T after the finalizer drain.
  - Under D1 it also carries the pending copy-out, and a `GuardFree`
    consumes it before user return.
  - Its proof that finalizers are drained before userspace resumes still
    holds, because a copy-out queues no finalizer.
- **`CpuSlots`** is unchanged. The slots stay under T, and owner-only
  mutation stays a type fact. Prepare copies the owner's facts that the
  unguarded steps need (root identity and generation, Process) into the
  payload, instead of reading the slot without T.

#### 11.2.6 The stage-4 finding: `soft_off_then_halt`

`soft_off_then_halt` is reached inside a T hold, from
`prepare_terminal_handoff_detached` (`P:4260`) and
`finish_primordial_terminal_handoff` (`P:4665`). It then runs `sti; hlt`.
H0 §12.8 names `sti; hlt` explicitly.

**Resolution:**

- The decision stays under T, the `any_process_unexited_except` check
  included.
- The terminal step returns a power-off outcome.
- The facade drops the guard and calls `soft_off_then_halt(GuardFree)`, so
  calling it under a guard is a compile error.

If commit 2 removes the interrupt handle, the timer path also stops being
able to spin on T at all.

#### 11.2.7 Implementation sequence

Each commit is semantic and carries its own SMP VM evidence (§5.3).

1. **Power off only after the runtime guard is released** (§11.2.6). Add a
   UI case that calls `soft_off_then_halt` with a guard alive (E0499). The
   evidence is a normal SMP run that reaches power-off. *This is the first
   commit:* it is the smallest, it removes a present §12.8 violation, and
   it does not depend on the rest.
2. **Publish quantum expiry without T,** if the §11.2.4 hypothesis holds.
   Otherwise record why and skip it.
3. **Move `ActiveDeepPaging` under its own lock P.** All 53 `core.active`
   uses take P beneath T. Behavior is unchanged except for the lock
   structure, so this is the first commit that changes lock structure.
4. **Take the shootdown wait out of the hold** (family G's guard-free
   wait). This removes the §11.2.2 risk.
5. **Add the usercopy session that requires `GuardFree`.** Family A leaves
   T entirely.
6. **Families B and C.** This includes the visible-before-reported
   semantic change and the pin-capacity check.
7. **Families D and F.**
8. **Family E**, including AtomicWait32's reordering and resume copy-out.
9. **Map's copy-in and copy-out, then delete the unguarded-under-T
   constructor.** After this, `current_process_address_space` cannot be
   reached while a T guard is alive. The coordinator then triages the KEEP
   rows in §4.3's "coarse lock" group for conversion.

**What would falsify this plan:**

- A pin does not make copy-out infallible. For example, some teardown or
  reclaim path bypasses `UserPinTracker`. Then post-release copy-out can
  fail after publication, and family B needs a different shape.
- Some path must take P and then T: a root-switch commit, or a
  finalizer-driven reclaim. Then the T-then-P order is wrong and that path
  must split first.
- Publishing a handle before its copy-out breaks an F0 publication-order
  guarantee. Then family B keeps copy-out inside a hold, and §12.8 needs
  Mike's decision again.
- Profiling shows T contention dominates SMP throughput once usercopy is
  out. Then Registry and Tasks need splitting after all. This is a later
  measurement, not a D1 blocker.
