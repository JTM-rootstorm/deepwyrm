# DW0-F11 Host and Model Validation

## Status

DW0-F11 is functionally closed on Deepwyrm implementation candidate
`f1e05b4df289043943f0acf688df9d93d00bc8e2`, descended from the F10-complete
baseline `e7ac17aca02e1a65982c8061c6e991b2f95d8c82`.

This record closes the focused host/model/compile-fail and failure-injection
gate in root `DW0_F_IMPLEMENTATION_PLAN.md` section 16. It does not close the
F12 freestanding scenario, the cumulative F13 security gate, F14 release
evidence, or all of DW0-F.

## Focused host command

`cargo xtask test host ipc` is now a distinct bounded command. It selects the
F handle-table and transfer models; Channel, wait, deadline, timer, atomic-wait,
blocked-operation, scheduler, and execution tests; the F ABI codecs; the
Event/Channel/Timer/wait/process-create adapters; typed payload finalizers; the
generic object/task compile-fail suites; the x86 syscall contract; and the new
F11 ownership suites.

The command is materially narrower than `cargo test --workspace --all-targets`:
it invokes named kernel-library filters and five named integration tests rather
than every crate, unit test, architecture contract, generator test, and target
artifact test. Each invocation owns a unique mutable root under
`.tmp/xtask-host-ipc/<pid>/` for both `TMPDIR` and `CARGO_TARGET_DIR`.

## Deterministic transaction models

The F11 additions supplement the existing exhaustive unit and failure tests
with reproducible state-machine traces:

- Channel uses four fixed seeds and 160 steps per seed. It covers direct and
  reserved send/receive, reservation cancellation, short-buffer
  non-consumption, depth-two backpressure and `WRITABLE`, peer close, and
  ordered draining of committed messages.
- Handle transfer uses four fixed seeds and 192 steps per seed. It covers
  prepare/extract/rollback, reduced-right destination publication, full
  destination rollback, close/recreate, and exact sender/receiver authority
  cardinality.
- Scheduler uses seed `0xd0f11000` across six bounded cycles. It covers
  reservation commit/cancel, FIFO schedule/yield, block prepare/cancel/commit,
  exact/stale/foreign wake, runnable and running retirement, and state/resource
  exclusivity after every transition.
- Timer uses two fixed seeds and 69 steps per seed over a one-slot deadline
  authority. It covers arm/rearm/cancel, immediate readiness, dequeue/deliver,
  stale delivery, generation replacement, capacity, and idempotence.
- Atomic wait uses two fixed seeds and 80 steps per seed. It covers predicate
  mismatch and barrier recheck, registration, bounded FIFO wake, timeout/wake
  exact-winner arbitration, terminal cleanup, capacity recovery, and stale
  identity.

The existing deterministic handle model remains four seeds by 4096 steps, and
the existing `process_create` suite retains three retries at every injected
precommit boundary followed by success and complete typed teardown. Random or
host-scheduled stress remains supplemental and is not used as the closure
evidence for these families.

## Output-preflight closure

Channel receive now injects a denied result, byte payload, and handle-info
output independently. Every failure preserves the queued head, transferred
Event authority, receiver HandleTable, owned-output count, and following FIFO
message; a subsequent receive proves the original head and transfer are still
consumable exactly once.

Atomic wake now routes through the host-testable `atomic_wake_with`
transaction. It pins the address, derives the stable key, validates and owns
`out_woken`, then and only then dispatches the wake. Pin/key/output and wake
failures release or discard every prepared owner without consuming a waiter;
success commits the exact count. A zero count still performs the full
address/key/output sequence.

The selector-16 F9 runtime uses the same helper. This is a narrowly F9-specific
correctness seam: no Channel, Event, Timer, `process_create`, or general F
service activation was added. The x86 source contract verifies that the target
runtime cannot bypass the host-tested transaction or special-case count zero
before output preflight.

## Ownership-cycle model and finalization

`f11_ownership_model` declares the permitted directed ownership dependencies
among mapping pins, page tables, HandleTables, task state, Channel, Timer, wait
registry, scheduler, ObjectRegistry, and finalizer. A topological assertion
rejects cycles. A second reachability assertion rejects task/HandleTable
nesting and any path between the finalizer and a mutation owner; typed
finalization remains outside every subsystem owner.

The focused gate also retains the concrete finalizer tests proving Channel
peer-close routing, queued Event reference cleanup, and armed Timer deadline
cancellation through the sole generic ObjectRegistry finalizer. Existing Event
wait pins and Timer/Channel typed cleanup tests prove that typed liveness is not
bypassed.

## Move-only and target-only boundaries

The new `f11_ipc_ui` suite has 16 compile-fail cases. It prevents cloning or
forging Handle transfer tokens/batches/reservations, prepared MOVE and rollback
owners, wait registration, atomic-wait operation, block reservation/token,
deadline registration, Channel send/finalization owners, Timer payload binding,
initial kernel continuation, and kernel switch plan. It also proves that the
Channel pair-side lease remains private.

`AtomicWaitRegistration` and `TimerExpiryToken` remain `Copy` intentionally:
they are generation-stamped registry/delivery identities, not liveness or
mutation owners. The non-Copy `AtomicWaitOperation`, `DeadlineRegistration`,
and typed Timer binding carry the authority, while existing stale/duplicate
tests prove copied identities cannot duplicate a live registration, deadline,
or wake.

`SyscallRuntimeBinding` is target-only and was not shadow-reimplemented in a
host UI fixture. It is a stationary, one-shot binding with a private
`PhantomData<&mut ()>` lifetime, not a movable continuation authority newly
introduced by F11. The existing x86 contract requires its `Pin<&mut R>`
construction and verifies that suspension ends the runtime borrow before the
kernel switch and reacquires it only after frame rebinding. The actual movable
unsafe owners introduced for block/resume, `InitialKernelContinuation` and
`KernelSwitchPlan`, are covered by compile-fail cases. This combination is the
accepted section-16 boundary; making the runtime binding host-visible, cloneable,
or otherwise movable would require a dedicated target-aware UI seam.

## Project-local test-state corrections

The complete host gate exposed two assumptions in older UI/environment tests
when `TMPDIR` was correctly placed below the project boundary:

- physical-ownership fixtures now declare an empty `[workspace]`, preventing a
  nested temporary crate from being mistaken for an undeclared Deepwyrm
  workspace member; and
- the target-artifact environment test now preserves and compares its ambient
  baseline instead of assuming the synthetic root has no outer Cargo config.

Neither change weakens the tested ownership or ambient-configuration rejection.
They make those checks independent of whether the authorized temporary root is
inside the repository.

## Validation commands and results

All mutable state was directed into project-local `.tmp/` paths. The following
gates passed on the implementation candidate:

```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo xtask test host ipc
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
git diff --check
```

The kernel library reported `436 passed; 0 failed`. The workspace all-targets
gate passed all unit, integration, compile-fail, architecture-contract,
generator, and xtask command-surface tests; the target-artifact suite retained
its two explicitly ignored accepted-toolchain gates. Clippy and rustdoc passed
with warnings denied. `cargo xtask abi check` confirmed no schema, syscall ID,
record layout, object type, signal, or rights drift.

Because F9 target code now consumes the generic atomic-wake transaction, the
accepted Rust 1.97.1 toolchain and accepted `rust-lld` also compiled selector
`atomic-wait-wake` (ID 16) successfully. That compile is a regression check,
not a new artifact inspection or guest-execution claim. Its only diagnostics
were two pre-existing ACPI dead-code warnings.

No optional fuzz, sanitizer, or property tool was installed. No VM or security
scan was run; those are not F11 gates.

## Commits

F11 implementation and validation substrate were recorded in these unsigned,
trailer-verified commits:

- `57a36f99b16d697e7f08305aed993c44979280a3` — model F ownership dependencies;
- `fdf18eebddc7c8b1e9b60bd6da7e5712ccd7443b` — lock move-only authority
  boundaries with compile-fail cases;
- `c5e05f34fbc13d346587f5e3141fd9f35fbac7c1` — add deterministic F transaction
  traces;
- `91a05d01fe616d804970d7774d71490eabeacc09` — close output-preflight gaps and
  route F9 atomic wake through the tested transaction;
- `e51ddbbfa11c1a453bfb7ff1d240e0e580f8bf96` — add the focused IPC host gate;
  and
- `f1e05b4df289043943f0acf688df9d93d00bc8e2` — keep compile-fail and artifact
  environment state valid under the project-local write boundary.

All commits retain the configured repository author and the required Codex
co-author trailer. None was signed or pushed.

## Non-claims and disposition

F11 adds no public ABI and requires no Wyrmroot or Rust-fork source change. It
does not activate selector 17, start a Thread, load an ELF, operate a VM, or
claim accepted production/all-selector artifact inspection. F12 retains the
complete synthetic CPL3 F scenario and paired VM gate. F13 retains cumulative
Daybreak review and security disposition.

Deepwyrm implementation candidate
`f1e05b4df289043943f0acf688df9d93d00bc8e2` satisfies the DW0-F11 focused and
full host gate with no known functional blocker before guest execution.
