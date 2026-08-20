# DW0-F8 Functional Validation

## Status

DW0-F8 is functionally closed for typed one-shot Timer objects, native `timer_create` / `timer_set` / `timer_cancel`, Timer wait integration, and interrupt-driven Timer expiry on Deepwyrm code candidate `1208ee905e06464635e6c79b9c47554629ef46ec`.

This record closes the F8 mechanism, host, and required target-interrupt gate only. It does not claim DW0-F milestone completion, the broader F12 synthetic F userspace/paired VM gate, F13 cumulative Daybreak security acceptance, SMP acceptance, or physical-hardware acceptance. Wyrmroot remained read-only and clean at `180ad0480db925a92222bccf9e2102a27b351370`.

## Implemented F8 boundary

F8 builds `TIMER` on the F3 monotonic/deadline engine and F4/F7 wait machinery rather than creating a parallel clock or waiter system.

Implemented behavior includes:

- typed Timer payload construction and finalization under sole generic `ObjectRegistry` liveness;
- `timer_create` returning an unarmed, unsignaled Timer with output preflight before object/handle publication;
- exact requested-right validation from generated Timer rights metadata;
- `timer_set` requiring `MODIFY`, rejecting `INFINITE`, and validating caller-controlled syntax before handle lookup/state mutation;
- one exact Timer arm generation per successful set/re-arm transaction;
- future arms clearing prior `SIGNALED` state and scheduling one typed expiry token;
- deadlines at or before current monotonic time committing `SIGNALED` immediately without waiting for a later interrupt;
- one-shot expiry that disarms the exact arm, asserts level-triggered `SIGNALED`, and produces waiter wake intents exactly once;
- re-arm invalidating a previously dequeued/in-flight old expiry token by Timer arm generation;
- `timer_cancel` disarming and clearing `SIGNALED`, with a dequeued stale expiry token becoming a harmless no-op;
- duplicate delivery of one consumed expiry token becoming a harmless no-op;
- in-place replacement of a still-live deadline registration, so an armed Timer can re-arm even when its current registration occupies the final deadline slot;
- replacement advancing the deadline-slot generation so the old registration is stale and cannot cancel or overwrite the new arm;
- capacity failure for a distinct Timer leaving the Timer's state unsignaled/unarmed and leaving the existing deadline intact;
- Timer current-signal observation and registration through the generic F7 `WaitSources` path;
- immediate `wait_one` readiness on an already-signaled Timer;
- blocked Timer waits using the ordinary F7 durable wait operation, detached result output, exact blocked-operation winner, and resume cleanup;
- IRQ-side Timer expiry producing wake intents without consuming wait-registration pins or touching `ObjectRegistry`;
- an IRQ-only wake-completion helper that claims the exact F7 signal winner and wakes the scheduler while deferring registration/pin cleanup to resume/terminal teardown;
- `WaitRegistry` using `IrqSpinMutex` so Timer interrupt readiness scans cannot self-deadlock the BSP;
- a typed Timer deadline lane in the live F3 time service, sharing the same Local APIC earliest-deadline programming with F7 scheduler deadlines and PM-counter maintenance;
- Timer expiry callbacks invoked only after the live time lock is released;
- central `PayloadFinalizer` routing for Timer final release, including cancellation of a still-armed deadline before generic payload completion; and
- crate-private F8 Timer adapter/runtime exports for the later F12 full synthetic userspace runtime.

No ABI schema, syscall number, object number, signal bit, rights bit, or Wyrmroot source change was required.

## Transaction and stale-event invariants

Timer arm generation is authoritative Timer state. `DeadlineRegistration` is scheduling authority only. A successful re-arm/cancel changes the Timer generation/state before an old expiry callback can be accepted; a token whose generation no longer matches is ignored.

For a live queued arm, replacement occurs in the exact existing deadline slot. Deadline replacement increments the slot generation before publishing the replacement payload. This prevents temporary capacity expansion and ensures an old registration token cannot act on the replacement.

If hardware/IRQ processing removes an expiry from the deadline queue before re-arm or cancel acquires Timer state, the dequeued token may still be delivered later. It cannot signal the Timer because the Timer arm generation has changed or the arm is no longer live.

Timer expiry does not release generic wait pins in interrupt context. The ISR-side path commits typed Timer state, obtains non-consuming wait wake intents, claims the exact blocked-operation winner, and transitions the matching scheduler generation to Runnable. The ordinary F7 resume or terminal cleanup path later consumes registrations, pins, and detached userspace output ownership.

## Focused F8 evidence

The Timer-focused checkpoint gate passed with formatting and diff checks clean and Clippy warnings denied.

Timer/state tests cover:

- initial unarmed/unsignaled construction;
- future set, replacement, immediate expiry, cancel, and reset-by-set;
- stale old expiry after re-arm;
- stale dequeued expiry after cancel;
- duplicate expiry delivery;
- one-slot in-place replacement under full deadline capacity;
- capacity failure of a second Timer without state mutation;
- 64 repeated dequeue-then-cancel-late-expiry traces;
- ready Timer wait registration and IRQ-safe wake-intent generation; and
- armed Timer finalization and immediate typed-slot reuse.

Syscall/wait tests cover output-preflight ordering, invalid requested rights, `INFINITE`, wrong object type, missing `MODIFY`, generated native Timer syscall IDs, immediate signaling, future arm, cancel/reset, already-ready `wait_one`, blocked Timer wait, IRQ-style wake, and exact F7 resume result publication.

## Broad host closure

The exact committed F8 candidate used project-local build state at `.artifacts/f8-validation/final-host-target` and passed under fail-fast execution:

```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo test --locked --workspace --all-targets --offline
cargo clippy --locked --workspace --all-targets --offline -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --offline
git diff --check
```

The kernel suite reported `402 passed; 0 failed`. Workspace testing also passed compile-fail/UI ownership contracts, architecture contracts, ABI generator/layout tests, and xtask command-surface tests. Clippy and rustdoc passed with warnings denied.

Preserved log: `.artifacts/f8-validation/logs/full-host-closure-final.log`
SHA-256: `72e474694569baf1fac8daef1556e9140c66155dcfaa420f5292fe80b56bbb66`.

## Accepted target interrupt evidence

The accepted-toolchain selector-10 artifact was rebuilt from code candidate `1208ee905e06464635e6c79b9c47554629ef46ec`. The existing F3 live deadline probe runs first, followed by the F8 Timer target probe before CPL3 entry.

The F8 target probe creates a typed Timer, binds the stationary Timer-expiry target, arms an absolute deadline through the live F3/LAPIC service, enters the race-free interrupt sleep, and requires the Timer to become `SIGNALED` from real timer-interrupt delivery before selector 10 may continue.

The accepted target gate passed:

```text
task-syscall-smoke stack bootstrap=97888 thread=13032
bootstrap-spare=33184 thread-spare=52504
test result: ok. 1 passed; 0 failed
```

Recorded artifact identities:

- user artifact SHA-256: `732286bc6c65b3a6ee669a53aa3d9b2c44f8ce55caa91fcceb3796d1bcdac80b`;
- kernel artifact SHA-256: `49505c1d5f9971eea101fc35da4a8e9d70fb0b66f07d37c47f9cda272732f8a4`;
- build-input manifest SHA-256: `6e28fdb49f0e4ab901927ac00972f73d8fcf81edb62dac057912ff642776f11b`;
- normalized build environment SHA-256: `de9cf952e07da0d8d913e9a6635d711e613e51104435a9b3082f196916e96c8e`.

Preserved log: `.artifacts/f8-validation/logs/accepted-target-final.log`
SHA-256: `f75ac5f06d34b46cc228dd038a13771c8de69969dc8ff21df79807fb3fa79111`.

One earlier validation invocation was rejected before target execution because an ambient `CARGO_TARGET_DIR` violated the target oracle's normalized-environment policy. The accepted rerun used Cargo's `--target-dir` CLI option instead, leaving the oracle environment clean. This was infrastructure invocation error, not a kernel/Timer failure.

## Explicit non-claims and next work

F8 does not implement `atomic_wait32` / `atomic_wake` (F9), public `process_create` (F10), the consolidated F11 closure command, the complete F12 synthetic F userspace/paired VM scenario, or cumulative F security acceptance (F13).

The selector-10 Timer probe proves real interrupt-driven Timer expiry but is not a substitute for F12's later full userspace Timer/wait scenario. F13 may reopen this surface if the cumulative Daybreak review finds a security defect.

## Disposition

Deepwyrm code candidate `1208ee905e06464635e6c79b9c47554629ef46ec` satisfies the DW0-F8 functional gate. F9 may proceed without reopening F8 absent a regression or later security finding.
