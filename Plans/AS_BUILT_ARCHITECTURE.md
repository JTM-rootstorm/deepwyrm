# Deepwyrm as built

Status: **as-built description**, written 2026-11-13 at Deepwyrm `a34928e` (root `OS_STACK_ARCHITECTURE_PLAN.md` G1). It says what the code does, not what any plan intends. Where it and a contract in [`ARCHITECTURE_INDEX.md`](ARCHITECTURE_INDEX.md) disagree, the contract states the intent and this document states the fact; report the disagreement rather than resolving it here. Update this document in the change that alters what it describes. Paths are relative to the repository root, `K/` meaning `kernel/`.

## 1. Shape

Deepwyrm is a single x86_64 kernel (`K/`) with a generated native ABI. It runs one product, Wyrmroot's, on q35 UEFI under QEMU; nothing has run on physical hardware.

| Part | What it is |
|---|---|
| `abi/schema/*.toml` | The ABI's source of truth: types, statuses, rights, objects, records, 44 syscalls |
| `tools/abi-gen` | Generates `abi/generated/` (Rust and C definitions, kernel dispatch, guest veneer, `ABI.md`, the semantic SHA-256 fingerprint) |
| `crates/deepwyrm-abi` | The generated `no_std` definitions |
| `crates/deepwyrm-syscall` | The guest's raw `SYSCALL` veneer; also assembles the `.note.deepwyrm.abi` fingerprint note every native binary carries |
| `crates/deepwyrm-elf-corpus` | Host-only hostile-ELF corpus shared with Wyrmroot's loader tests |
| `K/arch/x86_64/{layout,task_layout,pools}.toml` | Link layout, kernel stack sizes, object pool sizes, read by `K/build.rs` |
| `tools/xtask` | `format`, `check`, `clippy` (production kernel, then host on the pinned lane, then the lint ratchet), `doc`, `kernel-check`, `abi generate|check`, host and guest test planning |

## 2. Boot

1. Wyrmroot's EFI loader enters `_dw_kernel_entry` with interrupts off and `RDI` naming `DwBootInfoV1`: memory map, modules (bootstrap ELF, bootfs, boot device table), ACPI RSDP, optional framebuffer, command line, entropy (`abi/generated/deepwyrm_abi.rs`, `K/arch/x86_64/layout.toml`).
2. `entry.S` moves to the 4 MiB boot stack; `kernel_main` (`K/src/lib.rs`) installs early descriptors and validates boot info (at most 128 memory entries, 16 modules).
3. Memory: the boot map is sanitized, frame roles are built, the kernel activates its own page tables with a direct map of allocator RAM (largest pages, NX, supervisor-only), then sizes the role table from RAM (`K/src/memory/growable.rs`).
4. Platform: ACPI PM timer, the clock and local APIC timer (§7), S5 discovery, MADT topology, the q35 IOAPIC route, DMAR with VT-d default-deny.
5. CPUs: up to four (`K/src/cpu.rs`); the BSP installs the `SYSCALL` boundary with SMEP and SMAP on, APs start through a trampoline and park until the scheduler admits them.
6. The kernel parses the bootstrap ELF with its own narrow parser (`K/src/boot/primordial.rs`: static ET_EXEC x86-64, at most 16 headers and 8 PT_LOADs, one bounded PT_NOTE, 32 MiB mapped), constructs the first Process with its TaskGroups and capabilities (`K/src/boot/primordial/construction.rs`), and enters it at CPL3 (`K/src/arch/x86_64/mm/activation/primordial.rs`, `enter`). Bootstrap checks its ABI fingerprint against the kernel's before anything else, then loads Wyrmroot's init.

## 3. Objects, handles, rights

- Object types: TaskGroup, Process, Thread, MemoryObject, AddressRegion, Channel, Event, Timer, Interrupt, DeviceResource (Exception is reserved) (`abi/schema/objects.toml`).
- One `ObjectRegistry` holds every object's identity; references are move-only tokens (creation, handle, internal, final release) with no second reference count (`K/src/object/`).
- Each Process has one handle table of slot-and-generation handles; rights are checked against generated per-type policy, and a transfer never widens them (`K/src/handle/`).
- Pools are fixed counts from `K/arch/x86_64/pools.toml` (C1): 96 handles per Process; 32 each of Processes, Threads, TaskGroups and address spaces; 640 registry objects; 384 MemoryObjects; 320 mapping leases; 64 slots per region; 96 Channel pairs of depth 2; 160 wait registrations; 2 Timers; 1 Event. The build refuses more identities than kernel stacks, more than 64 slots or more than 96 handles (the sizes `kernel-check` measured). `kernel_get_limits` reports them. TaskGroup limits (`task_group_limit`) divide them per class and only fall (`K/src/task/quota.rs`).

## 4. Tasks and scheduling

- TaskGroup → Process → Thread; children retain their parents (`K/src/task/`).
- One FIFO round-robin class per CPU, 5 ms quantum; a Thread that blocks keeps its unused quantum and runs ahead of those without one (`K/src/task/scheduler.rs`). No priorities.
- Kernel stacks: 32 Thread stacks of 512 KiB with guard pages; per CPU one 256 KiB privilege-entry stack, one 256 KiB terminal-reaper stack and three 16 KiB IST stacks (#DF, NMI, #MC) (`K/arch/x86_64/task_layout.toml`, `linker.ld`). `xtask kernel-check` bounds every direct call chain on each with a quarter spare; calls through function pointers are not bounded.
- A Thread's saved user state is every GPR, the FP/vector area, FS base and the DS/ES/FS/GS selectors (`K/src/arch/x86_64/user_state.rs`).

## 5. Memory

- Frames are granted with a generation-stamped role record (`K/src/memory/frame_roles.rs`); the physical allocator keeps a bounded free-range set (`K/src/memory/physical.rs`).
- MemoryObjects are eager or on demand (DW2 M6), backed by typed frame roles; mapping one takes a lease (`K/src/memory/object.rs`).
- AddressRegions publish through a coherent publisher that waits for every resident CPU's TLB acknowledgement (`K/src/memory/address_region.rs`, `K/src/arch/x86_64/mm/activation/tlb_mailbox.rs`); maps larger than one 4096-page journal batch run in steps (`K/src/syscall/region_steps.rs`).
- Usercopy is all-or-nothing: ranges are validated, preflighted and pinned before the first byte moves (`K/src/memory/usercopy.rs`, `user_range.rs`).
- DMA goes through one VT-d domain per PCI function with kernel-chosen IOVAs; a mapping pins its MemoryObject until the IOTLB is invalidated (`K/src/device/dma.rs`).

## 6. IPC and waiting

- Channels carry datagrams of up to 64 KiB and 16 handles, two messages deep per direction; payloads up to 1 KiB use per-queue slots, larger ones a shared pool of 16 (`K/src/ipc/mod.rs`). There is no flow control beyond WRITABLE and no port object.
- `wait_one` and `wait_many` (up to 64 items) scan linearly; Events are manual-reset; Timers signal when due; `atomic_wait32`/`atomic_wake` key on user addresses (`K/src/wait/`, `K/src/atomic_wait.rs`).

## 7. Time

- The ACPI PM timer is the reference clock, extended in software with an APIC maintenance deadline against its wrap (`K/src/time/pm_timer.rs`).
- At boot the TSC is calibrated against it and checked over a second window; the clock moves to the TSC only when CPUID reports an invariant TSC and the windows agree within 2,000 ppm (L1, `K/src/time/tsc.rs`). Every boot logs `[time] clock=... tsc-hz=... check-ppm=...`. QEMU's TCG CPU reports no invariant TSC, so the VM runs on the PM timer.
- Deadlines (64) live in one queue owned by CPU0, armed through the local APIC one-shot timer (`K/src/time/deadline.rs`, `live.rs`).

## 8. Interrupts, exceptions, devices

- Vectors: exceptions `0x00–0x1f`; one external vector, `0x30`, for q35 COM2 IRQ3 through the IOAPIC; internal IPIs `0xe0–0xfd` (`K/src/interrupt/mod.rs`, `K/src/arch/x86_64/idt.rs`).
- A user fault terminates the Thread with a structured record; there is no exception delivery to userspace.
- DeviceResources come from the boot device table (PCI functions and the COM2 port with its interrupt); drivers get checked PIO, config reads, filtered command writes, uncached BAR mappings and waitable Interrupt objects (`K/src/device/`).

## 9. Concurrency

- One coarse runtime lock (T) serializes kernel business state, ordered before the paging lock (P) and the shootdown lock (S); interrupt context never takes T (`runtime_authority.rs`).
- A `GuardFree` token, enforced by the type system, is required at every physical boundary: CR3 switch, remote-stop wait, reaper handoff, entry to idle or user mode, context switch.
- Some syscalls copy user memory with P alone (families A and B: ABI discovery, the clock, handle-returning calls); the rest run under T.

## 10. Syscalls

44 syscalls in eight families: core (ABI info, limits), handles, tasks, memory, channels, waits, time, devices (`abi/schema/syscalls.toml`). The assembly entry hands six registers to the generated decoder, `K/src/syscall/native.rs` turns them into a typed request, and the runtime serves it.

## 11. What it does not do yet

Each has an owner in root `OS_STACK_ARCHITECTURE_PLAN.md` or `CARRIED_OPEN_ITEMS.md`: no kernel heap or boot-sized pools (C2–C6); no port object or per-object waiter lists (P1–P5); one runtime lock and no priorities (L2–L6); one external interrupt and no exception delivery or thread control (I1–I5); no CSPRNG, Spectre controls or ASLR (MT1–MT4); no compatibility mode (E1–E4); no physical hardware (`HARDWARE_BRINGUP_PLAN.md`).
