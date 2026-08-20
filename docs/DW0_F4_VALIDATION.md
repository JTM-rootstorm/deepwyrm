# DW0-F4 Validation Record

Status: **FUNCTIONALLY CLOSED — working-tree candidate; Git commit identity pending**
Validation date: **2026-08-20**
Deepwyrm base revision: `3deef9584b6d8056780044708828c158348bfb5d`
Wyrmroot read-only revision observed during validation: `180ad0480db925a92222bccf9e2102a27b351370`
Accepted Rust request/commit: `RUST-PHASE0B-TOOLCHAIN-001` / `8bab26f4f68e0e26f0bb7960be334d5b520ea452`

This record closes the DW0-F4 functional gate for the exact uncommitted source
candidate recorded below. It does not create a durable Git identity for that
candidate; the eventual implementation/validation commit must supersede the
working-tree identity in the coordinator ledger without changing the validated
source. F13 remains the cumulative Daybreak security-review gate.

## 1. Candidate identity

The F4 candidate is the working tree over Deepwyrm base
`3deef9584b6d8056780044708828c158348bfb5d`.

Reconstructible patch:
`.artifacts/f4-validation/F4_SOURCE.patch`
SHA-256: `a413b563139ba5d3d7bb7fe0fcd75f4c34660d18c1ac7db7d63809ce2465b0f2`

Per-file source manifest:
`.artifacts/f4-validation/F4_SOURCE_MANIFEST.txt`
SHA-256: `7e02abb46506c4a8230126e41770aa381ca4f5514242ebffaa81d4ac7711c1fa`

## 2. Implemented F4 surface

The candidate adds one typed wait/Event foundation without changing the public
ABI schema, record layouts, syscall IDs, rights vocabulary, or signal values.

Implemented behavior includes:

- a bounded generation-protected `WaitRegistry` tied to exact F2 `BlockWakeKey`
  identities;
- one `InternalRef` lifetime pin per published wait registration;
- block-generation wake grouping suitable for duplicate `wait_many` views, with
  one scheduler wake intent and complete sibling-registration cleanup;
- deterministic lowest-item-index selection among ready duplicate views;
- typed signal observation for Process and Thread `EXITED` directly from
  `TaskAuthority`, with no duplicate task-state database;
- typed manual-reset Event payload ownership and finalization;
- Event creation in the unsignaled state;
- Event set/reset idempotence with exact `SIGNALED` mask validation;
- an Event registration barrier that holds Event state across registration,
  making a concurrent set either visible before registration or discover the
  published registration; and
- wake-intent collection under typed/wait locks with scheduler wake and generic
  pin release deferred until those locks are gone.

Channel and Timer signal sources remain owned by F5 and F8 respectively.
`wait_one` / `wait_many` syscall suspension, deadline arbitration, result copyout,
and terminal/timeout integration remain F7 work.

## 3. Event syscall adapter ordering

`event_create` validates requested rights and preflights the user output before
creating either a generic Event object or caller-local handle. Publication
failure rolls back through the typed Event/ObjectRegistry path, and successful
publication commits the output handle only after the kernel state is complete.

`event_signal` rejects empty, overlapping, unknown, or otherwise noncanonical
clear/set masks before mutation. It then resolves exactly an Event handle with
`SIGNAL`, commits the manual-reset state, collects eligible wait generations,
releases Event/wait locks, wakes each winning scheduler generation once, and
releases all consumed wait pins through the ordinary cleanup queue.

The Event finalizer is integrated into `PayloadFinalizer`. A waiter-held
`InternalRef` prevents final release while a registration exists, so closing the
source handle cannot race typed Event destruction. Once the registration wins or
is cancelled and its pin is released, ordinary typed finalization may proceed.

## 4. Focused F4 host evidence

Focused wait/Event coverage proves:

- already-signaled observation returns ready without publishing a registration;
- Event set is manual-reset and wakes every independently blocked generation;
- reset affects future observation without retracting an already-won wake;
- one signal wins once for a shared block generation and consumes sibling
  registrations while retaining the deterministic lowest ready item index;
- a registration pin defers Event finalization until registration cleanup;
- generated object/signal compatibility rejects zero and incompatible masks;
- HandleTable lookup enforces `WAIT`, object type, and `SIGNAL` authority; and
- Process/Thread `EXITED` is observed from committed task authority state.

Focused syscall-adapter coverage additionally proves:

- denied output preflight prevents Event object-generation and handle mutation;
- successful Event creation publishes exactly one caller handle;
- invalid Event signal masks do not mutate Event state; and
- a handle lacking `SIGNAL` cannot mutate Event state.

The complete kernel host suite passed with `329 passed; 0 failed`.

## 5. Canonical host closure

The preserved host closure is:
`.artifacts/f4-validation/logs/full-host-closure.log`
SHA-256: `e66326cd132f7c9ffe84502ed8c156061a560786cdeaf2dd78d52b26d1733c38`

It passed:

1. `cargo fmt --all -- --check`
2. `cargo xtask abi check`
3. `cargo xtask test host abi`
4. `cargo xtask test host handles`
5. `cargo xtask test host memory`
6. `cargo xtask test host tasks`
7. `cargo test --locked --workspace --all-targets --offline`
8. `cargo clippy --locked --workspace --all-targets --offline -- -D warnings`
9. `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --offline`
10. `git diff --check`

The first attempt to preserve that host closure reused `deepwyrm/target` after
the accepted Rust 1.97.1 artifact oracle had populated it. The Rust 1.96.1
compile-fail harness therefore encountered an incompatible `deepwyrm_abi` rlib.
That run is retained only as infrastructure evidence at
`.artifacts/f4-validation/logs/full-host-closure-contaminated.log`; it is not an
F4 functional failure. The accepted host closure above used the isolated
project-local `.artifacts/f4-validation/host-target` and passed completely.

## 6. Accepted freestanding artifact gate

The explicit accepted-toolchain production/six-selector oracle passed using the
repository-pinned Rust request and Clang/LLVM tool identities.

Log:
`.artifacts/f4-validation/logs/accepted-production-oracle.log`
SHA-256: `32502b7678439e6dae1f77efbc10f268de00bb9dabb2731a342c2bd445600d2d`

Production kernel SHA-256:
`1f4755762843b342c64ca0a35c5bfff3bb115bcef98d805ad6e8345cb0555adf`

Build-input manifest SHA-256:
`02659b4e51ebd935ff1d89ae3a88b77d70fec896a2694d87b14d8b70eae619a7`

Normalized build-environment SHA-256:
`de9cf952e07da0d8d913e9a6635d711e613e51104435a9b3082f196916e96c8e`

Selector artifact SHA-256 values:

- `memory-mapping`: `1c0087e1481d67b6cc7acfd418a62f268b1845b3aa0b35e7d26220248b67e440`
- `memory-unmapping`: `d16531d7c6150809696ab582cea8277f038c7819e8448839359ed0565320d63d`
- `memory-permissions`: `54560db8cd99da8bfdeb5c61b1e47ed083bcca570ae3b484fe71838221aadbbb`
- `memory-invalid-pointer`: `d8a5cc72f05ed9a7feb4aab0359e2f1d77da0e2bfde76376c14986f8896cba2b`
- `memory-user-kernel-isolation`: `7be971f3846daab1e5317da23d4465f5b88ee602496f1beff89b15fe48e462d2`
- `memory-shared-memory-object`: `5da80c32189a66d414b2460b8937605a3a482300ef836954322e490b74d22800`

Production IST accounting used 2,615 of 16,384 bytes, leaving 13,769 bytes
spare. Selector IST accounting used 2,711 bytes, leaving 13,673 bytes spare.
Every selector also retained at least 60 KiB of its audited ordinary kernel
stack carrier after required headroom.

The oracle passed `1 passed; 0 failed` and verified that production contains no
guest-test markers or debug-exit behavior while all six selector artifacts remain
separate and uniquely identified.

## 7. ABI and Wyrmroot impact

F4 changes no ABI schema, generated record layout, syscall number, signal bit,
rights value, boot handoff, or Wyrmroot source. `cargo xtask abi check` passed with
no generated drift.

Wyrmroot remained read-only and clean during validation at
`180ad0480db925a92222bccf9e2102a27b351370`. No paired Wyrmroot build or repin is
claimed by this F4-only record; the F1 generated-consumer review remains part of
the later paired F acceptance path.

## 8. Explicit non-claims and next work

This F4 closure does **not** claim:

- functional `wait_one` or `wait_many` syscall blocking/resume;
- deadline timeout versus signal versus terminal winner arbitration in a live
  userspace wait syscall;
- Channel readiness or peer-close signaling;
- Timer object signaling;
- `atomic_wait32` / `atomic_wake`;
- public `process_create` activation;
- a new F guest selector body or VM result;
- SMP correctness or physical-hardware acceptance; or
- cumulative F security acceptance.

Those remain assigned to later F phases. In particular, F7 owns live generic
wait syscall publication, owned result/mapping state across suspension, deadline
integration, and terminal/timeout cleanup around this F4 registration substrate.
F13 remains the exact-candidate cumulative Daybreak review.

## 9. Disposition

The exact working-tree candidate identified by the source patch/manifest satisfies
the DW0-F4 functional gate and accepted freestanding artifact gate. F4 may proceed
to F5 implementation work without reopening F0-F3.

Because Mike has not authorized a Git commit in this validation step, the durable
commit identity is intentionally still pending. Once the unchanged candidate is
committed, the coordinator ledger should replace the working-tree identity with
that commit rather than rerun F4 merely to obtain a hash.
