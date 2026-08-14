# Deepwyrm Pre-Phase-0 Kernel Invariants

**Status:** Canonical pre-phase-0 kernel specification  
**Repository:** `JTM-rootstorm/deepwyrm`  
**Applies to:** DW0 and all later Deepwyrm milestones unless explicitly revised  
**Companion platform specification:** `JTM-rootstorm/wyrmroot/Plans/WYRMROOT_PLATFORM_CONVENTIONS.md`

This document pins the kernel-side invariants required by the Wyrmroot platform conventions. It does not expand DW0 scope. Its purpose is to prevent temporary bring-up shortcuts from becoming permanent kernel ABI.

The governing principle is:

> **Deepwyrm provides small, typed, rights-controlled mechanisms. Wyrmroot userspace supplies policy, naming, compatibility, configuration, service discovery, package management, and presentation.**

---

# 1. Native object and authority model remains canonical

Deepwyrm continues to use opaque process-local rights-bearing handles to typed kernel objects.

Locked rules:

- possession of a handle plus its rights is the primary kernel authority mechanism
- handles are not filesystem descriptors by definition
- object type and rights are validated on every handle-consuming syscall
- rights may be preserved or reduced through transfer/duplication, not implicitly increased
- handle values are opaque and nonpersistent
- native identity policy does not bypass object rights through a universal UID-0 rule

No later compatibility layer may require Deepwyrm to reinterpret all objects as Unix file descriptors or Windows handles internally.

---

# 2. Kernel ABI remains libc/POSIX independent

Deepwyrm does not require or define libc semantics.

The native kernel ABI does not make these foundational:

- `errno`
- `fork()`
- filesystem-aware `exec(path)`
- POSIX signals
- pthread APIs
- Unix fds as the universal object table
- `mmap(fd, ...)` as the fundamental VM model
- `/proc`, `/sys`, `/dev`, cgroupfs, or similar pseudo-filesystem APIs

POSIX/Linux compatibility is implemented above the kernel.

---

# 3. No universal `ioctl()` kernel escape hatch

Deepwyrm must not use a universal opaque `ioctl(request, void*)` mechanism as its normal extension strategy.

Preferred mechanisms:

- explicit typed syscalls for kernel mechanisms
- versioned ABI-safe structures
- typed kernel objects
- typed userspace service/driver protocols over Channels

A compatibility layer may decode Linux ioctl numbers and translate them into native operations.

---

# 4. Kernel does not own the global service namespace

Deepwyrm Channels and transferable handles are the IPC substrate.

Deepwyrm does not provide:

- D-Bus naming/routing
- global desktop service names
- package/service activation policy
- a mandatory system message broker

Wyrmroot builds service discovery in userspace and connects clients directly to services through Channel capabilities.

---

# 5. Structured query/introspection, not text pseudo-filesystems

Deepwyrm must preserve structured, rights-controlled ways for authorized userspace to inspect kernel objects and task state.

The kernel should be capable of exposing versioned typed information about, where appropriate:

- object type and rights
- process/thread/task-group state
- termination reason
- memory/accounting state
- scheduler/debug state
- handle inventory under explicit inspection authority
- kernel/system capabilities and supported ABI features

Do not make stable text layouts in pseudo-files such as `/proc/<pid>/stat` the canonical ABI.

Exact enumeration/accounting calls may be introduced after DW0 as needed.

---

# 6. Explicit feature discovery

Deepwyrm interfaces expose capabilities/version/feature support explicitly.

Userspace must not need to infer functionality from:

- kernel version strings
- object address/layout
- syscall-number ranges
- QEMU machine identity
- undocumented behavior

Unsupported optional features return a documented status such as `NOT_SUPPORTED` or are absent from an explicit feature query.

---

# 7. CSPRNG is a first-class kernel mechanism

Deepwyrm must grow a cryptographically secure random source before security-sensitive Wyrmroot components require one.

Locked direction:

- initial entropy may include UEFI-provided entropy supplied through `DwBootInfo`
- additional trustworthy hardware/platform entropy can be mixed in later
- Deepwyrm maintains the foundational entropy pool/CSPRNG state
- userspace obtains secure random bytes through a native typed operation, not by requiring a device file
- not-ready/failure behavior is explicit; the kernel never silently substitutes weak PRNG output

The exact DRBG algorithm and entropy-health implementation are deferred to the security/randomness milestone and require review.

---

# 8. Clock domains remain explicit

The existing native monotonic nanosecond deadline model is preserved.

Deepwyrm must support or leave room for separate clock domains including:

- monotonic active-time clock
- boottime/elapsed-since-boot clock for future suspend-aware behavior

Civil/UTC time, timezones, RTC synchronization, and NTP policy remain Wyrmroot userspace responsibilities.

A kernel timestamp is never assumed to be civil time unless explicitly identified as such.

---

# 9. Structured process termination

Deepwyrm process/task state must preserve more information than an 8-bit Unix exit code.

The native task termination model must be able to distinguish:

- normal application exit with a 32-bit code
- explicit authorized termination
- unhandled exception/fault
- resource/policy termination
- task-group/parent teardown where relevant

POSIX and Windows personalities translate this structured state to their own conventions.

---

# 10. TaskGroup is the future resource/accounting boundary

The TaskGroup hierarchy remains the kernel mechanism on which later Wyrmroot resource policy can be built.

Deepwyrm must not require Linux cgroups or cgroupfs.

The TaskGroup model must remain capable of supporting later:

- process/thread quotas
- memory accounting/limits
- CPU accounting/policy
- object/resource quotas
- recursive teardown
- sandbox/session/container-like policy

The scheduler/resource-control algorithms themselves remain deferred.

---

# 11. Driver/resource ABI remains explicitly unstable during early development

Deepwyrm driver-facing interfaces are ABI-0/unstable until deliberately declared otherwise.

Rules:

- do not promise a stable internal driver ABI during DW0/DW1 merely to avoid rebuilding drivers
- do not reproduce Linux internal driver APIs as the native contract
- user-space drivers receive explicit MMIO/I/O-port/IRQ/DMA/device-resource capabilities
- DMA APIs describe device-visible mappings rather than assuming physical address equals DMA address
- kernel/driver compatibility is checked explicitly
- once a stable driver ABI major is declared, incompatible changes require a new major

---

# 12. Hardware objects do not use enumeration order as identity

Deepwyrm may expose bus/topology enumeration information, but persistent Wyrmroot identity is userspace device-manager policy.

Do not define kernel object identity by names such as:

```text
gpu0
net0
disk0
```

or by the assumption that a particular enumeration index remains stable across boots/hardware changes.

The kernel exposes intrinsic identifiers/topology metadata where hardware provides them; Wyrmroot derives stable aliases/identity above that substrate.

---

# 13. Dynamic linking remains userspace

Deepwyrm's only ELF-loading responsibility remains the deliberately narrow primordial bootstrap path already pinned for DW0.

The kernel does not become responsible for:

- shared-library dependency graphs
- symbol resolution
- SONAME policy
- library search paths
- TLS library loading
- language runtime loading

Normal executable and dynamic-loader policy lives in Wyrmroot userspace.

---

# 14. Native tracing/debug foundation must not be Linux `ptrace`

Before ABI 1, preserve a kernel architecture that can support rights-controlled structured tracing/debugging of:

- syscalls
- task state/transitions
- exceptions
- register state
- relevant object/handle metadata
- IPC metadata where safe/authorized

Do not freeze Linux `ptrace` or `/proc` as the native debugger contract.

Host-side GDB through QEMU gdbstub remains the phase-0 live-debug mechanism and is separate from the eventual guest-native debug interface.

---

# 15. Debug/test ABI is isolated from production ABI

Any QEMU/test-only mechanism must be unmistakably separate from production behavior.

Examples include:

- QEMU test-exit ports
- host-injected test metadata
- debug-write syscalls
- test-only panic behavior
- privileged diagnostic backdoors

Rules:

- test/debug interfaces use an explicit build mode or dedicated namespace
- release components cannot require them
- dangerous debug facilities are disabled or capability-gated in production builds
- debug-only syscall numbers/interfaces do not become stable production ABI accidentally

---

# 16. Compatibility quirks do not flow backward by default

Deepwyrm may adopt a mechanism useful to a compatibility layer only when that mechanism is independently sound as a general kernel primitive.

Do not add kernel concepts solely because:

- Linux exposes a particular ioctl/procfs file
- Windows uses a particular legacy syscall name
- DOS expects a drive-letter or real-mode concept
- Win9x exposes a VxD behavior

Compatibility layers map their semantics onto native handles, MemoryObjects, waits, task groups, exceptions, Channels, and userspace services.

---

# 17. Native text stays out of kernel semantics

Deepwyrm ABI fields defined as opaque bytes remain opaque bytes. Fields defined as text use an explicit encoding at the Wyrmroot layer, normally UTF-8.

The kernel does not:

- localize messages
- perform locale-specific collation
- perform Unicode case folding for pathnames
- choose human-readable device names as identity

Numeric/typed status values are canonical; strings are diagnostic presentation.

---

# 18. Kernel logging remains mechanism only

A bounded kernel diagnostic/log facility is allowed and expected.

It must not grow into:

- a persistent journal database
- log rotation
- syslog policy
- network log forwarding
- service supervision

Where practical, kernel records should retain structured metadata such as monotonic timestamp, severity, and subsystem/source. Wyrmroot `logd` owns persistence/query/policy later.

---

# 19. Storage kernel mechanism stays below mount/filesystem policy

Deepwyrm may expose block-device and device-resource mechanisms, but mount policy, filesystem service policy, image-backed block services, and namespace composition live in Wyrmroot userspace.

Do not require Linux loop-device semantics or `/dev/loopN` as kernel primitives.

---

# 20. ABI source of truth and protocol separation

Deepwyrm remains authoritative for:

- syscall numbers
- native status values
- object types
- handle rights
- ABI-safe structures
- `DwBootInfo`
- kernel feature queries

These are generated/validated from the canonical ABI schema.

Wyrmroot service protocol schemas are separate and must not be copied into the kernel merely for convenience.

Kernel ABI versioning and userspace service-protocol versioning are independent.

---

# 21. Pre-phase-0 locks intentionally not made

The following remain implementation choices:

- physical frame allocator algorithm
- kernel heap algorithm
- scheduler algorithm/quantum
- exact per-CPU runqueue design
- exact CSPRNG/DRBG implementation
- final task-accounting schema
- final tracing implementation
- persistent filesystem
- network stack
- USB/audio/Bluetooth/Wi-Fi stacks
- graphics device ABI details beyond later explicit design
- Secure Boot

Do not infer a commitment from an early prototype implementation.

---

# 22. Phase-0 readiness statement

Together with `DW0_IMPLEMENTATION_PLAN.md`, its locked addenda, and the Wyrmroot Platform Conventions specification, these invariants are sufficient to begin DW0 implementation.

Do not continue speculative kernel architecture work before DW0 unless a concrete implementation blocker exposes a missing invariant. ABI 0 exists specifically so the project can learn from implementation and revise intentionally before stabilization.
