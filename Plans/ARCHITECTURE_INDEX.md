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
8. Wyrmroot's corresponding `Plans/WYRMROOT_PLATFORM_CONVENTIONS.md`, WYR0 plan, and addenda for any shared boot/bootstrap/userspace work. For post-WYR0 block/storage/VFS/root work, also read Wyrmroot `Plans/WYRMROOT_STORAGE_FILESYSTEM_DIRECTION.md` (FAT32 ESP role, ext4 initial root, later native-filesystem direction).
9. When work touches compatibility personalities, personality hosting, or uses Linux/Windows/DOS/POSIX requirements to justify a native kernel change, the OS-Project coordination doctrine `../personality-plan/CROSS_PERSONALITY_KERNEL_MECHANISM_DOCTRINE.md` and the affected family plan are mandatory reading.

## Authority rules

- Deepwyrm owns kernel ABI, syscall numbers, object types, rights, statuses, `DwBootInfo`, kernel feature discovery, and kernel-side object semantics.
- Wyrmroot owns service naming/protocols, loader policy, bootfs content, userspace executable loading, platform configuration/state conventions, package/service policy, and compatibility personalities.
- `DEEPWYRM_PRE_PHASE0_INVARIANTS.md` applies to later milestones unless explicitly revised.
- A milestone may strengthen invariants but may not silently weaken them.
- ABI 0 remains intentionally revisable; changes must be coordinated through the canonical ABI schema and affected Wyrmroot contracts rather than locally patched around.
- For **compatibility-motivated admission**, the cross-personality doctrine is a hard overlay on this index: the current ABI/schema defines existing native semantics, but no older Deepwyrm plan/spec may be read as permission to add or widen a primitive merely because multiple foreign APIs can share it, it can be named generically, or another flag would make translation easier. New/widened primitives must be personality-blind and must independently prove a privileged/kernel-lifetime/atomicity/security need that cannot be cleanly composed above the kernel.

## Phase-0 freeze policy

The pre-phase-0 architecture is now considered sufficiently locked to begin implementation.

Do not add speculative kernel architecture merely because a distant subsystem will eventually exist. Revise/create architecture only when:

1. a concrete DW0/later implementation blocker exposes a missing kernel contract;
2. security review demonstrates an existing invariant is unsafe;
3. a later milestone reaches a subsystem intentionally deferred here; or
4. implementation evidence shows an ABI-0 choice should be revised before ABI stabilization.

The purpose of ABI 0 is to learn from real code, tests, and hardware rather than preserve speculative mistakes.

## Reached subsystem contracts

- [`DW0_D0_OBJECT_HANDLE_CONTRACT.md`](DW0_D0_OBJECT_HANDLE_CONTRACT.md) defines the locked DW0-D object/handle rights, liveness, reclamation, mapping-pin, transaction, and downstream-preservation contract. Read it before DW0-D implementation.
- [`DW0_E0_TASK_SYSCALL_CONTRACT.md`](DW0_E0_TASK_SYSCALL_CONTRACT.md) defines the locked DW0-E task lifecycle/ownership, typed construction/finalization, public `process_create` staging, and x86_64 CPL3/syscall-entry contract. Read it before DW0-E implementation.
- [`DW0_F0_IPC_WAIT_CONTRACT.md`](DW0_F0_IPC_WAIT_CONTRACT.md) defines the locked DW0-F Channel, transfer, blocking, wait/time, and public `process_create` transaction contract. Read it before changing F-era IPC/task publication semantics.
- [`DW0_G0_PRIMORDIAL_STARTUP_CONTRACT.md`](DW0_G0_PRIMORDIAL_STARTUP_CONTRACT.md) defines the paired primordial ELF, startup stack/registers, initial capability set, bootstrap handshake, bootfs lifetime, and rollback contract. Read it before DW0-G implementation.
- [`DW0_H0_SMP_CONCURRENCY_CONTRACT.md`](DW0_H0_SMP_CONCURRENCY_CONTRACT.md) defines the paired cooperative-SMP CPU identity, per-CPU ownership, IPI, rendezvous, TLB, timer-service, publication, lock-order, and userspace-loader enablement contract. Read it before DW0-H implementation.
- [`DW0_I0_ADDRESS_SPACE_ROOT_BINDING_DESIGN.md`](DW0_I0_ADDRESS_SPACE_ROOT_BINDING_DESIGN.md) refines H0 sections 5 and 9 with the implemented bounded `AddressSpaceKey`/Process-to-PML4 binding, typed lifetime-pinned kernel-half sharing, root-switch ordering, rollback, and conservative teardown boundary used by the I0 runtime lane.
- [`DW0_I1_KERNEL_EXECUTION_ROOT_DESIGN.md`](DW0_I1_KERNEL_EXECUTION_ROOT_DESIGN.md) defines the implemented CPU-private retained kernel/reaper roots, exact root-generation stop identity, and fail-closed Process/kernel transitions. AP execution remains parked.
- [`DW0_I1_STATIONARY_RUNTIME_FOUNDATION.md`](DW0_I1_STATIONARY_RUNTIME_FOUNDATION.md) defines the staged stationary-authority/carrier split, CPU-local guard accounting, and the remaining adapter transaction work. Read it before moving runtime authority behind synchronization.
- [`DW0_I1_PER_CPU_SCRATCH_DESIGN.md`](DW0_I1_PER_CPU_SCRATCH_DESIGN.md) defines fixed CPU-private scratch windows, atomic leaf ownership, and migration/session cleanup. Read it before changing live usercopy, MMIO scratch, or page-table scratch access.
- [`DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md`](DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md) defines the reached normal-class per-CPU FIFO round-robin policy, quantum/timer identity, safe userspace-return preemption boundary, eligibility/migration rules, instrumentation, lock ordering, and exact preservation of DW0-H/I execution invariants. Read it before DW1 scheduler implementation.
- [`DW1_B0_TIMER_RETURN_PREEMPTION_DESIGN.md`](DW1_B0_TIMER_RETURN_PREEMPTION_DESIGN.md) fixes the CPU0 unified Local APIC deadline ownership, exact CPL3 timer-return frame, asynchronous-return validation, generation-bound reschedule request, guard-free switch preparation/completion, and DW1-B live gate. Read it before implementing one-CPU timer-driven preemption.
- [`DW1_C0_SMP_PREEMPTION_DESIGN.md`](DW1_C0_SMP_PREEMPTION_DESIGN.md) reconciles the current AP idle/rendezvous carrier with DW1-A0, defines the generation-bound Parked-to-Schedulable publication order, inventories CPU-private root/entry/reaper/scratch/mailbox/deadline/return ownership, fixes the per-CPU quantum transition, and reserves selector 28's structured four-vCPU evidence contract. Read it before changing AP scheduler admission, per-CPU quantum ownership, placement, stealing, migration, or SMP preemption evidence.
- [`DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md`](DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md) defines the paired rights-scoped DeviceResource and waitable Interrupt ABI, immutable boot-device table, protected COM1 boundary, TaskGroup resource-domain claim custody, checked scalar PIO, generation-safe synthetic Interrupt state, typed finalization, and exact WYR1-C4 bundle handoff. Read it before activating object types 16/17 or changing device-resource, Interrupt, boot-device, resource-domain, PIO, or WYR1-C hardware-authority semantics.
- [`DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md`](DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md) defines the private q35 COM2 IRQ3 edge/high MADT/IOAPIC route, vector `0x30` BSP delivery, kernel EOI versus userspace ack, edge-unmasked platform seam, fixed-vector retirement quarantine, returning-entry/scheduler rule, and selector-31 evidence identities. Read it before changing external-vector IDT surface, IOAPIC/xAPIC delivery, physical Interrupt binding, or DW1-E evidence.
- [`WYR1_B0_REGISTRY_LAUNCH_EVIDENCE_DESIGN.md`](WYR1_B0_REGISTRY_LAUNCH_EVIDENCE_DESIGN.md) defines selector 27's test-build-only permanent-controller WRB1 relay, post-primordial reporter authority, exact 14-record validation, private raw operation, atomic terminal transcript, and selector-local capacities. Read it before changing Deepwyrm's WYR1-B live-evidence support.
- [`WYR1_C6_DEVICE_COORDINATOR_RESTART_EVIDENCE_DESIGN.md`](WYR1_C6_DEVICE_COORDINATOR_RESTART_EVIDENCE_DESIGN.md) defines selector 29's test-build-only permanent-controller WRC6 relay, exact 27-record restart/custody sequence, private raw operation `0xffff_ff1e`, atomic terminal transcript, selector-local capacities, and exact-pair live disposition. Read it before changing Deepwyrm's WYR1-C6 evidence support.
