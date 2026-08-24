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

## 2.1 Native application ABI should terminate at a kernel-matched vDSO

The long-term native application ABI should follow the Zircon-style separation between the stable userspace symbol surface and the kernel's raw machine-entry ABI. Native applications should call schema-generated `dw_*` entry points supplied through a kernel-matched virtual DSO rather than treating raw syscall numbers, register assignments, or the `SYSCALL` instruction sequence as the permanent application contract.

The current ABI-0 generated `dw_syscall6` veneer and documented raw x86_64 convention remain valid bootstrap/test bindings until the dedicated vDSO milestone replaces that consumption path. Their existence during DW0 does **not** by itself promise that raw syscall numbering/calling convention as the stable post-ABI-0 application ABI.

Locked direction for that later milestone:

- the canonical Deepwyrm ABI schema generates the public native `dw_*` symbol contract, the vDSO implementation metadata, and the corresponding kernel dispatch metadata from one source of truth;
- the kernel and vDSO are built and matched as one ABI tuple, and Wyrmroot maps the immutable kernel-provided image into native processes without requiring `PT_INTERP` or a general dynamic linker;
- the vDSO stays freestanding and deterministic, with no libc/TLS dependency, no writable load segment, no W+X mapping, and no runtime relocation requirement for its normal bootstrap use;
- kernel-initialized read-only data may support safe syscall-free queries or clock fast paths when correctness permits, with a real kernel entry retained where necessary;
- once this path is active, ordinary native executables should not need to embed architecture syscall instructions or private syscall numbers; machine-checkable validation should keep raw native kernel-entry sites inside the generated vDSO/runtime boundary; and
- validating that every raw syscall originated from an approved vDSO call site is a later defense-in-depth option, not an authority boundary and not a requirement for the first vDSO milestone. Handle rights/capabilities remain the security boundary.

Foreign personalities do not inherit the native vDSO contract. Linux vDSO/vsyscall behavior, Windows/NT entry stubs, and other foreign observable ABI machinery remain personality-owned even when they ultimately consume the same admitted Deepwyrm mechanisms.

Primary prior art for the implementation milestone is Zircon's vDSO design and generated public/private syscall split:

- `https://fuchsia.dev/fuchsia-src/concepts/kernel/vdso`
- `https://fuchsia.googlesource.com/fuchsia/+/HEAD/zircon/vdso/`

Zircon currently describes its syscall definitions with a customized FIDL dialect and generates both public API and private vDSO/kernel implementation pieces. That generator architecture is useful prior art, but it does not change Deepwyrm ownership: the canonical Deepwyrm kernel ABI schema remains distinct from Wyrmroot's service-level WyrmIDL. Before adapting source, pin an exact upstream revision and verify file-level license/provenance.

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

## 4.1 Kernel does not own post-primordial boot orchestration

Deepwyrm's boot responsibility ends at creating the deliberately narrow primordial Wyrmroot process and transferring its initial capabilities. The kernel does not become init, a service supervisor, a dependency controller, a device manager, a VFS server, or a root-filesystem mount coordinator.

The intended post-WYR0 userspace dependency spine is Wyrmroot policy: primordial bootstrap -> small permanent supervisor -> separate discovery -> device coordinator/essential userspace drivers -> VFS/filesystem services -> persistent root -> ordinary services. Deepwyrm supplies the generic Process/TaskGroup, Channel, wait/timer, memory, device-resource, and capability mechanisms needed by those components without learning their service names or boot graph.

Persistent root is therefore not a prerequisite for entering userspace. Boot-critical drivers/filesystem services may be loaded from the Wyrmroot bootfs and receive explicit MMIO/IRQ/DMA/block-device/namespace authority as applicable. Failure to mount persistent root is a Wyrmroot recovery-policy event, not a reason to add filesystem-aware kernel `exec(path)` or kernel service-management policy.

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

## 10.1 General-purpose scheduling with a future real-time class

Deepwyrm remains a **general-purpose kernel**, not a hard-real-time operating system. The ordinary scheduler must optimize for a usable multi-purpose system and must not require every process, service, or application to participate in deadline scheduling.

The architecture must nevertheless preserve a later capability-authorized **firm/soft real-time execution class** for workloads such as pro audio, VR/tracking, media processing, and latency-sensitive display work. This direction is a scheduling/resource-policy extension over the same native Thread, TaskGroup, wait, Channel, memory, and capability mechanisms; it is not a second RT kernel and must not introduce subsystem-specific kernel semantics.

Locked direction:

- normal workloads remain in the general-purpose scheduling class by default;
- real-time scheduling authority is explicit and policy-controlled, expected to be granted through TaskGroup/resource-policy authority or an equivalently narrow typed mechanism rather than self-asserted by arbitrary applications;
- the first post-DW0 scheduler step is ordinary timer-driven preemption with SMP-safe scheduling state, CPU affinity/migration rules, and latency instrumentation before any real-time guarantee is claimed;
- a later DW1 phase may add fixed-priority and/or reservation-based real-time scheduling, including bounded execution budgets/periods/deadlines and throttling so one authorized RT task cannot monopolize the machine;
- blocking synchronization and synchronous Channel/service dependency chains must remain capable of later priority/deadline inheritance or urgency propagation so a high-urgency caller is not indefinitely blocked behind lower-urgency work;
- real-time working sets must be able to use prefaulted/pinned/committed memory or an equivalent bounded-fault path before real-time execution begins; ordinary pageable memory remains valid for normal workloads;
- IRQ, wait, timer, IPC, and scheduler paths intended for future real-time use should remain bounded where practical and measurable; latency claims require instrumentation and hardware-specific evidence rather than assumption;
- commodity x86_64 firmware/hardware may prevent meaningful hard-real-time guarantees, so Deepwyrm must not advertise hard-real-time correctness without a separately validated hardware/profile contract; and
- compatibility personalities may project foreign priority/scheduling APIs onto admitted native mechanisms, but they do not define or widen the native real-time model.

DW0's absolute monotonic deadlines, one-shot timer service, bounded Channel queues, and resumable blocking are useful foundations but **do not themselves constitute a real-time scheduler or latency guarantee**.

Sequencing is intentionally constrained: DW0-G4/G5 must not add real-time scheduler behavior; DW0-H validates the existing scheduler/task/wait machinery under SMP and hardens it without RT scope expansion; the next scheduler milestone should first establish normal preemptive scheduling; only a later DW1 phase should activate the real-time class once the ordinary preemptive/SMP foundation and useful Wyrmroot process/service dependency chains exist.

No public ABI, scheduler class identifier, priority scale, budget record, or admission-control syscall is reserved by this section. Those details remain deferred until the implementation milestone reaches them.

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

# 16. Compatibility requirements pass a strict kernel-admission test

Compatibility can reveal a missing native mechanism, but **being independently coherent, reusable, or generically named is necessary at most and not sufficient** for Deepwyrm admission. The OS-Project cross-personality doctrine is authoritative for compatibility-motivated growth.

Before adding or widening a primitive because Linux, Windows, DOS, POSIX, or another personality needs it, require all of the following:

- a genuinely new privileged operation, kernel-managed lifetime/state transition, or atomicity/security guarantee exists rather than merely a different ABI shape, flag set, default, error code, or inheritance rule;
- existing orthogonal primitives cannot safely express the required observable behavior through personality composition;
- a restartable personality adapter or shared Wyrmroot/userspace helper is insufficient for a concrete reason;
- the proposed primitive remains personality-blind and does not branch on Linux/Windows/DOS identity to choose semantics; and
- the change does not merely add another mode, policy hook, callback, or flag so an existing primitive more closely imitates a foreign API.

Do not add kernel concepts solely because:

- Linux exposes a particular ioctl/procfs file or syscall family;
- Windows exposes a particular HANDLE/object/API shape;
- two or more foreign systems expose approximately similar concepts;
- DOS expects a drive-letter, real-mode, or legacy-device concept; or
- Win9x exposes a VxD behavior.

A narrow generic personality/ABI routing token may select which personality component receives a foreign syscall or executable, but it must not alter the semantics of generic Process, VM, wait, VFS, or IPC primitives. Modest duplicated code between personality implementations is explicitly preferable to personality-aware kernel policy or an omnibus "generic" object.

Compatibility layers map their semantics onto admitted native handles, MemoryObjects, waits, task groups, exceptions, Channels, and userspace services. If composition exposes a true missing privileged mechanism, route that mechanism through the full admission test rather than widening the nearest existing object by convenience.

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

- native kernel-operation semantics and the stable public `dw_*` vDSO symbol contract once that milestone is reached
- ABI-0 raw syscall numbers/calling metadata while bootstrap consumers still require them, and the private kernel<->vDSO dispatch metadata that may replace them later
- native status values
- object types
- handle rights
- ABI-safe structures
- `DwBootInfo`
- kernel feature queries

These are generated/validated from the canonical ABI schema. Once the vDSO boundary exists, the schema/generator must distinguish the stable native application symbol ABI from private machine-entry/dispatch details rather than making implementation numbering stable merely because it is generated.

Wyrmroot service protocol schemas are separate and must not be copied into the kernel merely for convenience.

Kernel ABI versioning and userspace service-protocol versioning are independent.

---

# 21. Pre-phase-0 locks intentionally not made

The following remain implementation choices:

- physical frame allocator algorithm
- kernel heap algorithm
- scheduler algorithm/quantum
- exact per-CPU runqueue design
- exact normal/real-time scheduler-class representation, priority scale, reservation/admission ABI, and inheritance/propagation algorithm
- exact CSPRNG/DRBG implementation
- final task-accounting schema
- final tracing implementation
- persistent filesystem
- network stack
- USB/audio/Bluetooth/Wi-Fi stacks
- graphics device ABI details beyond later explicit design
- exact native vDSO ELF layout/startup-location carrier and optional syscall-origin enforcement beyond the locked symbol/private-entry direction above
- Secure Boot

Do not infer a commitment from an early prototype implementation.

---

# 22. Phase-0 readiness statement

Together with `DW0_IMPLEMENTATION_PLAN.md`, its locked addenda, and the Wyrmroot Platform Conventions specification, these invariants are sufficient to begin DW0 implementation.

Do not continue speculative kernel architecture work before DW0 unless a concrete implementation blocker exposes a missing invariant. ABI 0 exists specifically so the project can learn from implementation and revise intentionally before stabilization.
