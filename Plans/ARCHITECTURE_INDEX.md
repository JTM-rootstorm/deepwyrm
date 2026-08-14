# Deepwyrm Architecture and Plan Index

**Status:** Canonical source-of-truth index  
**Repository:** `JTM-rootstorm/deepwyrm`

This file defines the minimum architecture reading set for Deepwyrm implementation work. Codex coordinators and human contributors should read the applicable documents before changing kernel or kernel/userspace contracts.

## Mandatory pre-DW0 reading order

1. [`README.md`](../README.md) - project identity and broad kernel goals.
2. [`Plans/DEEPWYRM_PRE_PHASE0_INVARIANTS.md`](DEEPWYRM_PRE_PHASE0_INVARIANTS.md) - kernel-side pre-phase-0 invariants.
3. [`Plans/DW0_IMPLEMENTATION_PLAN.md`](DW0_IMPLEMENTATION_PLAN.md) - DW0 milestone scope, phases, native ABI, and primordial userspace handoff.
4. [`Plans/DW0_IMPLEMENTATION_PLAN_IMAGE_DELIVERY_ADDENDUM.md`](DW0_IMPLEMENTATION_PLAN_IMAGE_DELIVERY_ADDENDUM.md) - canonical VM/media topology and no-host-share rule.
5. [`Plans/DW0_IMPLEMENTATION_PLAN_LIBC_POLICY_ADDENDUM.md`](DW0_IMPLEMENTATION_PLAN_LIBC_POLICY_ADDENDUM.md) - libc/POSIX independence of the native ABI and primordial userspace.
6. [`Plans/DW0_IMPLEMENTATION_PLAN_TOOLCHAIN_ADDENDUM.md`](DW0_IMPLEMENTATION_PLAN_TOOLCHAIN_ADDENDUM.md) - LLVM/Clang/LLD/compiler-rt policy and host GDB/QEMU debugging.
7. [`Plans/DW0_IMPLEMENTATION_PLAN_NATIVE_CONTROL_SURFACES_ADDENDUM.md`](DW0_IMPLEMENTATION_PLAN_NATIVE_CONTROL_SURFACES_ADDENDUM.md) - typed native control/introspection direction and Linux-compatibility boundaries.
8. Wyrmroot's corresponding `Plans/WYRMROOT_PLATFORM_CONVENTIONS.md`, WYR0 plan, and addenda for any shared boot/bootstrap/userspace work.

## Authority rules

- Deepwyrm owns kernel ABI, syscall numbers, object types, rights, statuses, `DwBootInfo`, kernel feature discovery, and kernel-side object semantics.
- Wyrmroot owns service naming/protocols, loader policy, bootfs content, userspace executable loading, platform configuration/state conventions, package/service policy, and compatibility personalities.
- `DEEPWYRM_PRE_PHASE0_INVARIANTS.md` applies to later milestones unless explicitly revised.
- A milestone may strengthen invariants but may not silently weaken them.
- ABI 0 remains intentionally revisable; changes must be coordinated through the canonical ABI schema and affected Wyrmroot contracts rather than locally patched around.

## Phase-0 freeze policy

The pre-phase-0 architecture is now considered sufficiently locked to begin implementation.

Do not add speculative kernel architecture merely because a distant subsystem will eventually exist. Revise/create architecture only when:

1. a concrete DW0/later implementation blocker exposes a missing kernel contract;
2. security review demonstrates an existing invariant is unsafe;
3. a later milestone reaches a subsystem intentionally deferred here; or
4. implementation evidence shows an ABI-0 choice should be revised before ABI stabilization.

The purpose of ABI 0 is to learn from real code, tests, and hardware rather than preserve speculative mistakes.
