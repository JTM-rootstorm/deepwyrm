# Deepwyrm

**Deepwyrm** is the kernel project for [Wyrmroot](https://github.com/JTM-rootstorm/wyrmroot), an experimental Rust-first operating system intended to provide a modern native substrate beneath multiple userspace personalities.

Deepwyrm is not intended to be a Linux fork or a Linux-compatible kernel implementation. The project will define its own kernel ABI and core primitives while borrowing proven architectural ideas where useful.

> **Status:** early architecture and bootstrap planning. The initial target is a small, testable x86_64 kernel that boots under UEFI/QEMU and can reach a native userspace shell.

## Design goals

- **Rust-first implementation.** Keep memory-unsafe code concentrated in narrow, auditable architecture and hardware boundaries. C and assembly remain available where they are genuinely the right tools.
- **Small native kernel ABI.** Expose modern process, memory, IPC, synchronization, interrupt, timer, and device primitives without making POSIX the kernel's internal model.
- **Userspace-first services and drivers where practical.** A failed driver or service should preferably terminate a process rather than the kernel.
- **Multiple userspace personalities.** Deepwyrm should be capable of supporting Wyrmroot's native interfaces, a Unix/POSIX personality, and later compatibility personalities without baking any one of them into every kernel abstraction.
- **Testable subsystem boundaries.** Core facilities should have host-side or synthetic tests before they are exercised only through full-system boots.
- **Virtual hardware first.** QEMU/UEFI and VirtIO are the initial hardware targets. Physical hardware support comes later.
- **Portable graphical foundation.** The kernel and native graphics/input services should eventually support [Glasswyrm](https://github.com/JTM-rootstorm/glasswyrm) without exposing Linux-specific DRM/KMS or input APIs as the native ABI.

## Initial scope

The first useful Deepwyrm milestone is intentionally small:

```text
UEFI loader
    |
Deepwyrm kernel
    |
physical + virtual memory
    |
processes / threads / scheduler
    |
IPC + timers
    |
basic device discovery
    |
filesystem access
    |
native userspace
    |
shell
```

Early development should favor deterministic progress in QEMU over broad hardware support.

## Kernel boundaries

Deepwyrm is expected to own facilities such as:

- CPU and architecture bring-up
- physical and virtual memory management
- processes, threads, and scheduling
- system call entry and the native ABI
- IPC and capability/handle primitives
- synchronization and wait primitives
- interrupts and timers
- PCI/ACPI and core device discovery
- DMA/IOMMU foundations
- low-level graphics, input, and storage interfaces needed by userspace services

Higher-level policy belongs outside the kernel whenever practical. Package management, networking policy, desktop sessions, logging, service dependency management, and similar facilities are Wyrmroot userspace concerns.

## Relationship to Wyrmroot

Deepwyrm is the kernel; Wyrmroot is the operating system built around it.

```text
Prismdrake Desktop Environment
            |
        Glasswyrm
            |
         Wyrmroot
            |
         Deepwyrm
            |
         hardware
```

The Linux versions of Glasswyrm and Prismdrake are expected to remain useful reference and development platforms while native Wyrmroot backends are developed.

## Boot philosophy

Deepwyrm will not require systemd. The intended boot architecture keeps responsibilities separate:

```text
UEFI firmware
    |
small Wyrmroot EFI loader
    |
Deepwyrm
    |
minimal PID 1
    |
one-shot bootstrap
    |
separate service supervision / dependency management
```

The bootloader loads the system. PID 1 keeps the minimum userspace root alive. Normal software service management is a separate component.

## Development principles

1. Keep platform-specific and unsafe code behind narrow interfaces.
2. Prefer small tests and synthetic harnesses over repeated full-system rebuild-and-boot loops.
3. Bring up one virtual device class at a time.
4. Do not prematurely reproduce Linux internal APIs merely to reuse a driver.
5. Preserve clean interfaces for future native, POSIX, Windows, and retro compatibility work.
6. Treat compatibility as observable behavior, not copied implementation detail.

## License

Deepwyrm is licensed under the **GNU General Public License v3.0**.
