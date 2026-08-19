# DW0-E6 Validation Record

## Disposition

**E6 CLOSED for the defined Deepwyrm host/model/compile-fail scope.**

The validated code candidate is `8d3b87b68484cb88d4b349eb3f54a9769cca1c02`,
validated on 2026-08-19. E6 closes focused host, model, compile-fail, source-contract,
and accepted-toolchain freestanding evidence only. E7 still owns the synthetic
userspace artifact and mandatory CPL3/native-syscall/VM round trip.

This record is not a Daybreak security review and does not close E8. The interim
pre-E6 security hardening is included in the tested candidate, but formal
`gpt-daybreak-blue-latest` exact-candidate review remains pending.

## E6 implementation checkpoints

- `dbe66378f3c480e964ae17e81d3a8b3342944934` binds the focused task gate to
  user-range validation, task-state service semantics, typed MemoryObject
  construction, D7 construction/finalization compile-fail suites, and the E4/E5
  architecture contracts.
- `910575137d536980aa4cab5b9d586b51b51ab938` adds explicit process-local handle
  isolation, fixed-capacity TaskGroup teardown, and deterministic
  close/start/terminate/finalize lifetime traces.
- `e819fc90045c8dd259651159a0f7d4eef33a39f0` adds task-creation output-preflight
  and termination reason/type/rights adversarial tests.
- `8d3b87b68484cb88d4b349eb3f54a9769cca1c02` adds adapter-level exactly-once
  thread-start evidence and production test-hook source gating.

All four commits were created unsigned and contain the required Codex co-author
trailer. No push is part of E6 validation.

## Focused E6 gate

The canonical focused command passed:

```text
cargo xtask test host tasks
```

The gate is deliberately bounded rather than an alias for the entire workspace.
It covers task/scheduler/execution state, x86 syscall and exception state,
checked user ranges and pinned usercopy, ABI staging, syscall adapters/native
dispatch, typed payload finalizers, MemoryObject construction, AddressRegion
lifetime integration, and the relevant compile-fail suites.

### Required host coverage mapping

1. **Task hierarchy and liveness/finalization:** `task::tests` plus typed task
   finalizer routes.
2. **Process-local HandleTable isolation:** colliding raw handle values in two
   process-owned tables resolve to distinct objects; closing one does not affect
   the other.
3. **Task state and termination records:** normal exit, authorized termination,
   task-group teardown, and structured unhandled exceptions are checked.
4. **Scheduler queue/context state:** scheduler reservation, FIFO/yield,
   resource-pool generation, rollback, scheduling, and terminal reclamation are
   checked.
5. **Final-thread/process-exit policy:** final-thread termination closes the
   process and returns execution pins/resources exactly once.
6. **TaskGroup teardown and capacity:** recursive teardown is iterative and an
   exact process-capacity fixture terminates all four children without overflow.
7. **Thread start exactly once:** direct task state and the E5 syscall adapter
   both reject repeated start after successful publication.
8. **Termination validation:** invalid reason, wrong object type, and insufficient
   rights fail before target mutation; the authorized path is then exercised.
9. **Numeric dispatch:** generated E syscall IDs route through typed requests;
   unknown and post-E IDs remain `NOT_SUPPORTED`.
10. **User pointer/range cases:** null, canonical split, alignment, overflow,
    count/stride, page splitting, and access-intent cases are in the focused gate.
11. **Pinned copyout before mutation:** ABI, duplicate, MemoryObject, AddressRegion,
    TaskGroup, and Thread creation paths retain failure-before-mutation evidence.
12. **D7-R1/R2 regressions:** production generic direct publication/finalization
    are compile-fail inaccessible; typed MemoryObject binding precedes first
    publication; payload finalizers route cleanup through typed authorities.
13. **AddressRegion lifetime:** closing the root region handle preserves the
    process address-space lifetime until process exit.
14. **Deterministic interleavings:** fixed `close -> start -> terminate -> finalize`
    and `start -> close -> terminate -> finalize` traces preserve exactly one
    Thread lifetime and reject stale restart.

## Compile-fail authority coverage

The focused E6 gate runs `object_registry_ui`, `memory_authority_ui`, and
`task_authority_ui`. Together they prove non-clonability/move-only behavior for
generic creation/handle/internal/final-release tokens, mapping authorization,
and scheduler reservation, and reject direct production generic object
publication/finalization. No private field or unsafe constructor was widened for
E6 testing.

## Architecture source contracts

The focused gate also passed the existing x86_64 activation, entry, syscall,
exception, and memory guest-contract tests. These bind the E6-required user
selector/DPL and TSS privilege stack, syscall MSR/FMASK policy, assembly/Rust
frame offsets, stack switching before user-RSP memory use, canonical return
addresses, IRETQ selectors/RFLAGS sanitation, CPL3 old RSP/SS exception capture,
and runtime/return authorization contracts.

E6 additionally checks that the `test_support` module and both guest dispatch
sites in the production kernel root are locally feature-gated. The explicit
freestanding artifact oracle below is the stronger binary-level proof that test
completion markers do not survive in the production image.

## Full host validation

The following all passed against `8d3b87b68484cb88d4b349eb3f54a9769cca1c02`:

```text
cargo xtask test host tasks
cargo xtask abi check
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
git diff --check
```

The complete log is retained under
`OS-Project/.artifacts/e6-validation/final-host/full-validation.log`.

## Accepted-toolchain freestanding artifact gate

The explicit `x86_64-unknown-none` target oracle passed using accepted Rust
request `RUST-PHASE0B-TOOLCHAIN-001` at Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452` and LLVM/Clang 22.1.8.
It rebuilt and inspected production plus all six DW0-C memory selector images.

```text
cargo test --locked -p deepwyrm-kernel \
  --test x86_64_memory_target_artifact -- \
  --ignored --exact production_and_six_memory_selector_artifacts_are_separated \
  --nocapture
```

| Artifact | SHA-256 |
|---|---|
| production | `7bb3afef9adf551102dcae95cfdef268192cbe7243a28d594d241d86350ced61` |
| `memory-mapping` | `83c288ae36a0939f7bfe9a59eedfa3ca2f7a82db61827ff4453bff0ec7c0d52e` |
| `memory-unmapping` | `e023f0388cedbf516a01f70d7d4850359df0eb27aedb2083d843c2e4dfb26be9` |
| `memory-permissions` | `9172a0f146c6827ceee338baa55ab60805114ee489372bb2ca7b262398d3a94f` |
| `memory-invalid-pointer` | `1718ce3ec8acb074b144508ad2bdcc264d0543371727d00acbb7dd2ccd3d4965` |
| `memory-user-kernel-isolation` | `5f7f4a1d56f13b6b5fb2a9ec252a7bba5454ce6715c4a9a04e52d675b1ec6ed6` |
| `memory-shared-memory-object` | `b9fae329b5cc94a08281f6676d66bc2d1d9764d23e649fdf912f35e3b779a486` |

The build-input manifest was
`122e0286b5ff7a2014b7c7c0906292d03c8803b822b180e14481a0194fcb2dbf` and the
normalized build environment was
`c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`.
Production IST accounting used 2,615 of 16,384 bytes; selector IST accounting
used 2,711 bytes. The oracle also verified production/test-marker separation,
forbidden FP/SIMD-state use under the current CR0.TS policy, ELF/symbol shape,
and stack-size margins.

The target log is retained under
`OS-Project/.artifacts/e6-validation/final-target/accepted-artifact.log`.

## Non-claims and next gate

E6 does not claim a real CPL3 round trip, a freestanding userspace ELF, a
Wyrmroot repin/image handoff, or VM acceptance. Those are E7 requirements. It
also does not claim E8 Daybreak security acceptance, DW0-F IPC/waits/timers,
SMP acceptance, physical hardware acceptance, or full DW0 completion.

With those boundaries, no blocker remains inside the defined E6 scope.
