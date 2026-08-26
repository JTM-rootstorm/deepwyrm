# Deepwyrm DW1-A Validation and Closure Record

**Status:** DW1-A host/model closure accepted on integrated `main`; DW1-B/C live behavior remains open
**Original validation date:** 2026-08-25
**Original lane candidate:** `2e014d0002437b18952df0159f9389a9ae5d4000`
**Integrated implementation revision:** `1cd8ff09dff7fb627928cccc28b1a9813f25ddb2`
**Integrated closure record revision:** `de51c6c81bf719b488bb4d0e36fa34831a138fb9`
**Current-tree revalidation date:** 2026-08-26
**Current-tree revalidation revision:** `96155793c1c8d06dea0139832bd96d9572d40cd6`
**Starting revision:** `b7773515bf56e452a6c224bd72a5ad05a8b82fa1`
**Historical lane:** `lane/dw1a-closure`

## Scope and disposition

Revision `2e014d0002437b18952df0159f9389a9ae5d4000` closes the remaining
DW1-A host/model obligations:

- the reached scheduler contract now inventories the concrete cooperative
  scheduler, execution, wait, atomic-wait, terminal/reaper, remote-stop,
  userspace-return, timer/APIC, root, scratch, and execution-pin call paths;
- `kernel/src/task/scheduler/normal_policy_model.rs` is a fixed-capacity,
  allocation-free, `cfg(test)` model of the frozen future normal policy; and
- the model covers deterministic placement, per-CPU FIFO round-robin,
  eligibility and offline rejection, bounded cyclic idle stealing,
  migration success/rejection, quantum/timer generations and checked
  arithmetic, stale generation reuse, and competing block/wake/terminal
  transitions.

The live `CooperativeScheduler` remains cooperative. This revision adds no
Local APIC scheduler deadline, `need_resched`, involuntary preemption,
arbitrary kernel preemption, AP userspace execution, stable ABI, or Wyrmroot
change. DW1-B and DW1-C remain responsible for those live gates.

The lane candidate was integrated as
`1cd8ff09dff7fb627928cccc28b1a9813f25ddb2`. A direct path-scoped tree
comparison confirms that the reached contract, scheduler instrumentation, and
test-only normal-policy model are identical between the original candidate and
the integrated implementation revision. The closure record was then merged as
`de51c6c81bf719b488bb4d0e36fa34831a138fb9`. Both integrated revisions are
ancestors of the current revalidation revision.

## Required-source disposition

The active DW1-A sources were read before implementation:

- the root DW1/WYR1 plan, Deepwyrm architecture index, reached DW1-A0
  contract, and the DW0-H0/I1 execution-root, stationary-runtime, and
  per-CPU-scratch contracts defined the preserved CPU ownership,
  continuation, guard-free switch, remote acknowledgement, timer ownership,
  and non-migration rules;
- Fuchsia/Zircon `zircon/kernel/kernel/scheduler.cc` at
  `6a606ff7fd9b055edee6557566fb3f112df1a812` informed conceptual comparison
  for explicit queue/CPU ownership, placement revalidation, bounded stealing,
  preemption timer identity, accounting, and migration staging; and
- xv6-riscv `kernel/proc.c` and `kernel/trap.c` at
  `35b088427ef37611c38afdeed5a52a278cae38f9` informed the deliberately small
  state-transition and timer-versus-block test shape.

No external source code was copied or adapted. Zircon's fair/deadline and
ChainLock mechanisms and xv6's global process scan, RISC-V trap mechanics,
kernel-yield policy, and Unix process model were not imported because they do
not fit this reached contract.

## Validation results

The following commands ran from the Deepwyrm repository worktree against the
candidate that became exact revision
`2e014d0002437b18952df0159f9389a9ae5d4000`:

```text
cargo fmt --all -- --check
cargo test -p deepwyrm-kernel normal_policy_model --locked
cargo test -p deepwyrm-kernel task::scheduler::tests --locked
cargo xtask abi check
cargo xtask test host abi
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo xtask test host ipc
cargo test --locked --workspace --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

All commands above passed. The focused future-policy model reported 7 passed,
the existing cooperative scheduler suite reported 34 passed, and the full
kernel unit suite reported 643 passed. The full all-target run retained three
intentional explicit target-artifact ignores and reported no failure. ABI
checking found no generated drift. Rustdoc completed with warnings denied.

The coordinator rebound that historical lane result to current `main` on
2026-08-26 by running the following commands at exact revision
`96155793c1c8d06dea0139832bd96d9572d40cd6`:

```text
cargo fmt --all -- --check
cargo test --locked -p deepwyrm-kernel normal_policy_model
cargo test --locked -p deepwyrm-kernel task::scheduler::tests
cargo xtask abi check
cargo xtask test host abi
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo xtask test host ipc
cargo test --locked --workspace --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

All current-tree commands passed. The focused model again reported 7 passed,
the cooperative scheduler suite again reported 34 passed, ABI checking found
no generated drift, every canonical DW0 host gate and the full all-target
workspace run had no failures, the three intentional target-artifact ignores
remained explicit, and Rustdoc completed with warnings denied.

The proportionate all-target Clippy command was also attempted:

```text
cargo clippy --locked --workspace --all-targets -- -D warnings
```

It did not complete because the starting revision already contains these
three denied style lints, verified directly at
`b7773515bf56e452a6c224bd72a5ad05a8b82fa1`:

- `kernel/src/task/scheduler.rs:842`: `unnecessary_lazy_evaluations`;
- `kernel/src/task/scheduler/tests.rs:140`: `field_reassign_with_default`; and
- `kernel/src/task/scheduler/tests.rs:162`: `field_reassign_with_default`.

Two initially reported lane-local Clippy findings in the new model were fixed,
then the focused model tests and format check passed again. The baseline lint
cleanup is outside this closure's no-production-policy scope; it is not a
functional failure of the DW1-A model or an ABI drift.

## Evidence boundary

This is host/model evidence only. No QEMU, persistent `OS-Project` domain,
guest selector, default/SMP profile, media, or physical-hardware run was
performed for this record. The test-only model demonstrates the frozen policy
state machine; it does not demonstrate live timer delivery, a safe CPL3-return
preemption, AP carrier execution, real scheduler latency, or four-vCPU
fairness/stress. Those claims remain explicitly open for DW1-B/C.

No Daybreak security gate was run or claimed. No Wyrmroot repository state was
changed or validated by this Deepwyrm-only record.

## Closure conclusion

The integrated implementation revision satisfies the DW1-A contract/model gate
and preserves the existing DW0 host regression suite on the current-tree
revalidation revision. DW1-A is complete. DW1-B must still implement and
validate one-CPU timer-driven userspace preemption; DW1-C must still admit AP
carriers and validate the four-CPU live normal scheduler.
