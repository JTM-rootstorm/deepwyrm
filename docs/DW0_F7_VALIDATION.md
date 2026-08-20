# DW0-F7 Functional Validation

## Status

DW0-F7 is functionally closed for `wait_one` and ABI-0 deterministic `wait_many` on Deepwyrm code candidate `fa1b89ba9499fa784cc0376c39f8c8015f41f0ad`.

This record closes the F7 mechanism/host gate only. It does not claim DW0-F milestone completion, the F12 freestanding wait/IPC guest and paired VM gate, F13 cumulative Daybreak security acceptance, Timer-object behavior owned by F8, atomic wait/wake owned by F9, or public process creation owned by F10. Wyrmroot remained read-only and clean at `180ad0480db925a92222bccf9e2102a27b351370`.

## Implemented F7 boundary

F7 connects the F4/F5 waitable signal core, F3 deadline foundation, and F2 resumable blocking machinery to typed native `WaitOne` / `WaitMany` requests.

Implemented behavior includes:

- structural signal validation before result-map preflight, with object-specific signal compatibility checked after handle resolution;
- detached, mapping-stable `DwWaitResultV1` output authority that can survive a blocked syscall without retaining a Rust usercopy borrow;
- `wait_one` output preflight before handle resolution/publication, then `WAIT` rights/type resolution and a stable generic object pin;
- ABI-0 `wait_many` count/mode validation followed by one complete fixed-width item-array snapshot before output preflight or handle resolution;
- no second userspace read of the staged `wait_many` item array after it has been structurally validated;
- complete handle resolution/pinning before readiness observation, with duplicate handles explicitly allowed;
- level-triggered immediate readiness and deterministic lowest input index for `WAIT_ANY`;
- ready state winning before `NOW`/already-expired deadline classification;
- transactional block preparation, registration publication, source recheck, and final scheduler block commit;
- one durable `WaitOperation` per blocked Thread owning the exact block-generation ledger reservation, detached output, and optional finite deadline registration;
- exact one-winner arbitration across signal, timeout, cancellation, and terminal retirement;
- IRQ-safe winner arbitration through `IrqSpinMutex`, preventing a LAPIC timeout interrupt from self-deadlocking on a thread-context-held winner ledger;
- signal wake coalescing by block generation, including duplicate registrations on one object, with all losing registrations consumed together;
- finite deadline registration through the live F3 deadline adapter, with heavy wait/object cleanup deferred out of IRQ context;
- `Blocked -> Runnable` timeout wake without usercopy or WaitRegistry work in the timer interrupt;
- exact resume semantics: signal commits `DwWaitResultV1`, timeout discards the detached output and returns `TIMED_OUT`;
- final-release propagation when a wait registration becomes the final generic owner after the userspace handle closes;
- terminal Thread/process cleanup that consumes blocked wait registrations, deadline ownership, blocked-operation ownership, and detached output before execution-resource reclaim;
- Process/Thread `EXITED` transitions publishing wait wakeups from the authoritative task state;
- single-runnable-Thread suspension using race-free `STI; HLT; CLI` idle rather than a fake context switch;
- FIFO-preserving post-IRQ idle scheduling that may resume the waiter in place or switch to another Runnable Thread;
- fresh Runnable Thread selection through a distinct audited first-run kernel continuation rather than manufacturing a fake suspended continuation;
- correct SysV first-run stack phase (`RSP % 16 == 8`) separated from genuine saved kernel continuation geometry (`RSP % 16 == 0`);
- a fixed trusted first-run runtime entry that reuses the already-pinned syscall/exception runtime bindings; and
- crate-visible `NativeWaitControl` / wait runtime surfaces for later F12 freestanding guest integration.

The typed native decoder is exercised with the real ABI syscall IDs and register-slot layouts for both `WaitOne` and `WaitMany`; the test handler routes those decoded requests through the same public wait transactions and suspension control used by a later target runtime.

## Waitable source coverage

F7 validates every waitable source that exists before F8:

- Event: manual-reset `SIGNALED`, immediate readiness, registration/recheck wake, close/finalize while waiting;
- Channel: `WRITABLE`, `READABLE` transition coverage inherited from F5, and `PEER_CLOSED` readiness/wake behavior;
- Process: authoritative `EXITED` observation from task state;
- Thread: authoritative `EXITED` observation plus a real blocked sibling wake during terminal transition.

`TIMER` is ABI-declared as waitable but its payload/syscalls do not exist until F8. Timer `SIGNALED` wait coverage therefore belongs to the F8 gate and is not fabricated inside F7.

## Focused F7 evidence

The final `cargo test --locked -p deepwyrm-kernel --offline wait -- --list` surface contains 35 wait-named host tests. Focused execution passes all of them.

Additional F7 regressions outside that name filter include:

- `native_wait_ids_route_through_real_wait_transactions_and_resume_control` — real `DwKnownSyscall::WaitOne` / `WaitMany` decode and dispatch, suspension, idle wake, per-Thread resume, and final copyout;
- `signal_timeout_race_has_exactly_one_winner_in_both_orders` — signal-first and timeout-first on the same finite Event wait, with the losing contender still arriving and no duplicate scheduler wake;
- `repeated_duplicate_wait_many_signal_trace_selects_index_zero_once` — 64 consecutive blocked generations using duplicate handles, one coalesced wake per generation, deterministic index zero, and zero residual registrations/operations/output pins;
- `public_finite_wait_idles_then_timeout_resumes_in_place_and_discards_output` — no-other-runnable idle suspension, timeout winner, in-place resume, and detached-output discard;
- `wait_suspend_plan_switches_to_fresh_runnable_sibling` — blocked caller switches to a never-run sibling through the first-run continuation path;
- `terminating_blocked_waiter_consumes_wait_without_userspace_resume` — terminal cleanup removes the durable wait owner before execution reclaim; and
- `public_wait_many_obeys_scalar_snapshot_output_then_handle_failure_order` plus the `wait_one` precedence regression — F0-observable validation ordering is pinned.

## Broad host closure

Final host validation used isolated project-local build state at `.artifacts/f7-validation/final-host-target` to prevent the accepted Rust 1.97.1 artifact oracle from contaminating the normal Rust 1.96.1 compile-fail/UI harness.

The following all passed:

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

The final kernel suite reported `392 passed; 0 failed`. Workspace testing also passed compile-fail/UI ownership contracts, APIC/interrupt models, x86 entry/syscall/exception source contracts, ABI generator tests, and xtask command-surface tests. The two accepted-toolchain artifact tests remained explicitly ignored in the ordinary workspace run under their existing dedicated-gate policy.

An earlier full-gate attempt reused the normal `target/` after an accepted-toolchain artifact run and produced Rust 1.97.1/1.96.1 rlib incompatibility in the compile-fail harness. That attempt is infrastructure-only contamination, not a functional F7 failure; the isolated final-host run above passed completely.

## Accepted freestanding regression artifact

The accepted E7 task-syscall-smoke artifact oracle was rerun against the final F7 code candidate to prove the F7 target-only entry/user-output changes still compile and preserve the existing freestanding userspace boundary. This is a regression artifact gate, not the F12 F7 wait guest/VM acceptance.

Accepted toolchain identities remained request `RUST-PHASE0B-TOOLCHAIN-001`, Rust commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`, and LLVM/Clang 22.1.8.

Final accepted artifact evidence:

- E7 userspace SHA-256: `732286bc6c65b3a6ee669a53aa3d9b2c44f8ce55caa91fcceb3796d1bcdac80b`;
- selector-10 kernel SHA-256: `8358989152effa589777934661524cb36e1867bbcf0ace709204aaa4d32ec6c4`;
- bootstrap stack bound: 97,824 / 131,072 bytes, 33,248 bytes spare;
- Thread syscall/exit stack bound: 13,032 / 65,536 bytes, 52,504 bytes spare;
- build-input manifest: `3bf4626c57af3c150dd26a23eeea1af04df900ee08ec1c856bcb5cd2897ebcaf`; and
- normalized build environment: `de9cf952e07da0d8d913e9a6635d711e613e51104435a9b3082f196916e96c8e`.

The oracle reported `1 passed; 0 failed`.

## Important implementation issues closed during F7

F7 implementation uncovered and fixed several defects that were not safe to defer:

1. wait-registration pins can become the final generic object owner after the last handle closes; timeout/terminal cleanup now returns bounded final-release authority for typed finalization;
2. the blocked-operation winner ledger was not IRQ-safe even though timer IRQs contend on it; it now uses the F3 IRQ-safe lock;
3. a blocked sole runnable Thread needs idle suspension rather than a context switch with no destination;
4. a selected never-run Runnable Thread needs a real first-run kernel entry rather than a fake saved continuation;
5. the staged initial-continuation validator previously used suspended-continuation alignment rather than the SysV first-run stack phase;
6. terminal task teardown must consume a blocked wait before reclaiming Thread execution resources;
7. F7 public waits need detached mapping-stability ownership so no borrow-shaped usercopy guard crosses a context switch;
8. `wait_many` validation must resolve the exact single userspace snapshot it structurally validated; and
9. the E7 stack-size artifact oracle had stale monomorphized task-exit signatures after wait-aware terminal cleanup and was repinned to the exact current symbols.

## ABI and Wyrmroot impact

F7 changes no syscall number, generated wire-record size, rights bit, signal bit, boot handoff, or Wyrmroot source. `cargo xtask abi check` passed with no generated drift.

Wyrmroot remained read-only and clean throughout F7 validation.

## Explicit non-claims and next work

F7 does not implement Timer payloads/syscalls (`F8`), `atomic_wait32` / `atomic_wake` (`F9`), public `process_create` (`F10`), the consolidated `cargo xtask test host ipc` F11 surface, the F12 synthetic F userspace/accepted F selector/canonical paired VM gate, SMP acceptance, physical-hardware acceptance, or F13 cumulative Daybreak security review.

The live F3 deadline adapter is connected to F7 wait registration, but the canonical interrupt-driven userspace wait proof and runtime binding belong to F12's real guest flow. The E7 regression artifact above must not be misrepresented as that proof.

## Disposition

Deepwyrm `fa1b89ba9499fa784cc0376c39f8c8015f41f0ad` satisfies the DW0-F7 functional implementation and host-validation gate. F8 may proceed without reopening F7 unless Timer integration or later F work exposes a regression in these invariants.
