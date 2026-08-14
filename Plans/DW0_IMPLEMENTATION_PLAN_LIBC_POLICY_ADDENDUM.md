# Deepwyrm DW0 Implementation Plan Addendum: libc Independence

**Status:** Canonical locked addendum to `Plans/DW0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/deepwyrm`  
**Milestone:** DW0  
**Scope:** Native ABI/runtime independence from libc and POSIX C-runtime assumptions

This document is part of the DW0 implementation contract. Codex and human contributors must treat the decisions below as **locked** unless an explicit architecture revision updates this addendum and the corresponding Wyrmroot WYR0 libc-policy addendum together.

The central rule is:

> **Deepwyrm and the native Wyrmroot ABI must not require libc to exist.**

A future libc implementation is a Wyrmroot POSIX-personality component. It is not part of the Deepwyrm kernel contract and must not become an implicit dependency of native process creation, memory management, IPC, synchronization, executable startup, or driver interfaces.

---

# 1. Locked kernel/ABI policy

Deepwyrm remains independent of libc and POSIX C-runtime semantics.

The native ABI must not make the following concepts fundamental kernel requirements:

- `errno`
- POSIX file descriptors as the universal object namespace
- `open` / `read` / `write` as universal kernel-object operations
- `fork()`
- filesystem-aware `exec(path)`
- POSIX signals as the native exception mechanism
- `pthread_*` as the native thread/synchronization ABI
- `mmap(fd, ...)` as the fundamental memory model
- libc allocator semantics
- C locale/environment machinery

Deepwyrm continues to expose its own native mechanisms:

```text
rights-bearing handles
TaskGroup / Process / Thread
MemoryObject / AddressRegion
Channel / Event / Timer
wait primitives
atomic_wait32 / atomic_wake
structured native status values
structured exception model
```

POSIX/libc implementations may translate these mechanisms into traditional Unix interfaces later.

---

# 2. Native syscall wrappers are not libc

The canonical ABI generator may produce:

- Rust ABI definitions
- Rust syscall wrappers
- C ABI headers
- C/assembly syscall veneers
- documentation and layout tests

These artifacts are **native Deepwyrm ABI bindings**, not a C standard library.

For example, a future freestanding C program may call a generated Deepwyrm process-exit or channel syscall wrapper without implying the presence of:

```text
stdio.h
stdlib.h
POSIX libc
malloc/free
pthread
Unix fd semantics
```

Do not label the generated native ABI layer `libc` or shape it around libc compatibility merely because C bindings exist.

---

# 3. DW0 primordial userspace requirement

The DW0 primordial Wyrmroot bootstrap process must be capable of running **without a guest libc**.

Acceptable early userspace shape:

```text
bootstrap.elf
    |
Rust core
    |
optional alloc + small native allocator/runtime
    |
generated Deepwyrm syscall wrappers
    |
Deepwyrm
```

The bootstrap image may use:

- `#![no_std]`
- Rust `core`
- Rust `alloc` when backed by a native Wyrmroot allocator/runtime
- compiler/runtime support required to generate correct machine code
- a tiny Wyrmroot-native startup/runtime layer

It must not require glibc, musl, newlib, or another libc merely to enter userspace, receive its bootstrap channel, map the bootfs `MemoryObject`, send IPC, or exit.

Compiler runtime support such as arithmetic helpers, unwinding support where deliberately enabled, or Rust/LLVM runtime components is not considered libc and is permitted when documented.

---

# 4. Memory allocation policy

Deepwyrm does not provide `malloc()` as a syscall.

Native userspace allocation should ultimately be layered as:

```text
Rust alloc / native allocator API
          |
Wyrmroot userspace allocator
          |
MemoryObject / AddressRegion operations
          |
Deepwyrm
```

DW0 may use a very small bootstrap allocator. The exact allocator algorithm is not ABI and may evolve.

A future libc may implement `malloc/free` over the same native Wyrmroot memory facilities without changing the Deepwyrm ABI.

---

# 5. Rust standard-library direction

Deepwyrm must preserve an ABI that allows the Wyrmroot-maintained Rust fork to implement a **native Wyrmroot `std` platform layer without routing normal operations through libc**.

Long-term desired direction:

```text
Rust application
      |
Rust std for Wyrmroot
      |
Wyrmroot native runtime/services
      |
Deepwyrm native ABI
```

rather than:

```text
Rust application
      |
Rust std
      |
libc / POSIX shim
      |
Deepwyrm
```

Deepwyrm should not add POSIX-shaped syscalls merely to reduce the amount of work required for the Rust `std` port.

---

# 6. Native C and C++ implications

DW0 does not require a native hosted C implementation.

The architecture must permit future layers in this order:

```text
freestanding C
    -> Deepwyrm native ABI bindings

native Wyrmroot C SDK
    -> native Wyrmroot libraries/services

POSIX C/C++
    -> optional libc/POSIX personality
```

Existing C/C++ software may initially be easier to port through the POSIX personality. That is acceptable and does not justify making libc foundational to Deepwyrm.

---

# 7. Host-tooling exception

The libc-independent rule applies to the **guest/native operating-system stack**, not to the Gentoo development host.

Host-side tools such as:

- `cargo`
- `rustc`
- `xtask`
- ABI generators
- image builders
- QEMU
- OVMF tooling
- fuzzers
- debuggers

may use the normal Gentoo host runtime and host libc.

Do not spend DW0 effort making every development utility freestanding merely to satisfy the guest libc policy.

The acceptance requirement is that the produced Deepwyrm kernel and native Wyrmroot bootstrap path do not depend on a libc being present inside the guest.

---

# 8. Implementation-phase changes

The following requirements amend the corresponding DW0 phases.

## DW0-A

- ABI schemas/generation must remain libc-neutral.
- Generated C bindings must expose native ABI types/functions without defining POSIX compatibility behavior.
- Add a dependency check/documented inspection showing the primordial guest artifact does not acquire a libc dependency.

## DW0-E/F

- Process/thread/synchronization syscalls must remain native and handle/object based.
- Do not introduce `pthread`, Unix fd, or POSIX signal concepts into kernel task/wait interfaces.

## DW0-G

- The primordial ELF must boot using only the Wyrmroot native runtime plus compiler/runtime support explicitly allowed by this addendum.
- The successful bootstrap path must not rely on glibc, musl, newlib, or a POSIX userspace layer.

## DW0-H

- Milestone closure must verify that libc is absent from the required guest boot/runtime dependency graph.
- Any dependency that appears to introduce libc must be investigated and either removed or explicitly shown to be host-only tooling.

---

# 9. Testing and validation

Add focused validation for the libc-independent architecture:

1. Build and inspect `bootstrap.elf` and any DW0 synthetic userspace test binaries.
2. Verify there is no `PT_INTERP` or dynamic libc dependency in the DW0 primordial ELF subset.
3. Verify native syscalls can exercise process exit, IPC, waits, and memory operations without POSIX wrappers.
4. Ensure host tests remain free to use the normal host environment.
5. Record any compiler runtime linked into primordial userspace and distinguish it from libc.

The security review should also flag accidental POSIX/libc authority shortcuts that bypass the locked handle/right model.

---

# 10. Future POSIX/libc boundary

A future Wyrmroot milestone may introduce an optional POSIX personality with a libc, likely by adapting an existing implementation such as musl rather than recreating a complete libc unnecessarily.

That future layer is expected to translate roughly as:

```text
POSIX application
      |
libc
      |
Wyrmroot POSIX personality
      |
Wyrmroot native services / Deepwyrm ABI
```

Deepwyrm must not depend on that layer in the reverse direction.

No future POSIX/libc package may become a hidden requirement for:

- booting Deepwyrm
- launching native Wyrmroot processes
- running native system services
- using native IPC/memory/task primitives
- bringing up Glasswyrm/Prismdrake native components that are implemented against Wyrmroot-native interfaces

unless an explicit architecture revision intentionally changes this policy.

---

# 11. Mandatory DW0 libc-independence gate

DW0 must not be tagged complete until:

- the primordial native bootstrap executes with no guest libc installed or linked
- native process/thread/memory/IPC/wait operations are exercised through Deepwyrm-native interfaces
- generated ABI bindings remain libc-neutral
- no DW0 kernel subsystem exposes a POSIX-only interface merely to support userspace
- any linked compiler/runtime helpers are documented separately from libc
- host-only libc dependencies are clearly separated from guest/runtime dependencies
- the DW0 security review does not identify a libc/POSIX shortcut that undermines the locked native capability/object model

This gate is additive to the existing DW0 functional, image-delivery, and security-validation gates.