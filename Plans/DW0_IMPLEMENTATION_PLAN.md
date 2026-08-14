# Deepwyrm DW0 Implementation Plan

**Status:** Canonical DW0 architecture and implementation contract  
**Repository:** `JTM-rootstorm/deepwyrm`  
**Milestone:** DW0 - kernel foundation and primordial userspace handoff

This plan pins the architectural decisions made before implementation. Codex and human contributors should treat the **Locked decisions** sections as requirements, not suggestions. A locked decision may be changed only by an explicit architecture revision that updates this plan and any affected Wyrmroot contract before implementation proceeds.

DW0 is intentionally narrow. Its job is to prove that Deepwyrm can boot on the reference virtual machine, establish its native object/handle ABI, create isolated userspace, and start the primordial Wyrmroot bootstrap process. DW0 is not the milestone for filesystems, networking, a desktop, POSIX compatibility, or broad hardware support.

---

## 1. DW0 success condition

DW0 is complete when the following path is reliable and covered by targeted tests:

```text
UEFI
  |
Wyrmroot loader.efi
  |
DwBootInfoV1 + loaded modules
  |
Deepwyrm x86_64 entry
  |
serial / panic / memory / interrupts
  |
native kernel objects + rights-bearing handles
  |
TaskGroup / Process / Thread
  |
MemoryObject / AddressRegion
  |
Channel / Event / Timer / waits
  |
minimal bootstrap ELF loader
  |
primordial Wyrmroot bootstrap process
  |
bootstrap channel + bootfs MemoryObject
```

The primordial process must execute in user mode, make Deepwyrm syscalls through the native ABI, receive its bootstrap capabilities, and be able to exit cleanly. WYR0 owns what happens after that point.

---

# 2. Locked architecture decisions

## 2.1 Kernel and native ABI model

1. Deepwyrm is **Rust-first** and `#![no_std]` at the kernel boundary.
2. C and assembly are permitted where they are the correct low-level tool, especially architecture entry, context switching, and hardware interfaces.
3. Unsafe Rust must be concentrated behind small, documented interfaces. Ordinary kernel subsystems should be safe Rust where practical.
4. Deepwyrm defines its **own native kernel ABI**. POSIX is a Wyrmroot personality and must not dictate kernel internals.
5. Native kernel objects are accessed through **opaque, process-local, rights-bearing handles**.
6. Handle possession and rights grant authority to an object. Deepwyrm does not make UID 0 or POSIX file descriptors fundamental kernel concepts.
7. Rights may be reduced during duplication or transfer. A process may not manufacture greater rights than it already possesses without a separate authority explicitly granting them.
8. The raw syscall ABI is documented and machine-generated, but normal native code should use generated syscall wrappers rather than inline syscall instructions.
9. ABI 0 is explicitly unstable. Until `DW_ABI_VERSION` becomes 1, Wyrmroot is expected to be rebuilt with Deepwyrm after ABI changes.

## 2.2 Native executable and calling convention

1. Native executable format is **ELF64**.
2. Native x86_64 userspace follows the **x86-64 System V calling convention** for normal function calls and process startup.
3. Deepwyrm syscalls use a Deepwyrm-specific ABI rather than Linux syscall semantics.
4. Normal process startup will use familiar `argc`, `argv`, `envp`, and auxiliary-vector conventions, with Wyrmroot-specific auxiliary entries added in a namespaced manner where needed.
5. Normal executable loading is a userspace responsibility. Deepwyrm contains only a deliberately narrow ELF loader for the primordial Wyrmroot bootstrap image.
6. The DW0 primordial ELF subset is x86_64, little-endian, fully static, and `PT_LOAD` based. `PT_INTERP`, dynamic linking, and general-purpose relocation processing are out of scope for the kernel bootstrap loader.

## 2.3 x86_64 raw syscall convention

For DW0, the x86_64 native syscall entry contract is:

```text
RAX = syscall number
RDI = argument 0
RSI = argument 1
RDX = argument 2
R10 = argument 3
R8  = argument 4
R9  = argument 5
SYSCALL
RAX = DwStatus, sign-extended
```

Rules:

- A syscall accepts at most six scalar register arguments.
- Larger or extensible calls use ABI-safe argument structures passed by validated userspace pointer.
- Syscalls return a `DwStatus`; additional output is returned through validated output pointers or transferred handles.
- Raw ABI structures use fixed-width integer types and explicit layout. Do not expose Rust enum layout, `usize`, implementation-defined `bool`, or kernel pointers.
- Extensible structures begin with `size` and/or version information as appropriate.
- Reserved fields must be zero on input.
- User pointers are always treated as untrusted and validated before access.

## 2.4 Native status model

`DwStatus` is a signed 32-bit native status namespace:

```text
0     = success
< 0   = failure
```

The initial namespace must include equivalents for:

- invalid arguments
- bad handle
- wrong object type
- access denied
- invalid/bad state
- not found
- already exists
- would block
- timed out
- interrupted
- peer closed
- no memory
- no resources
- not supported
- buffer too small
- bad address

Deepwyrm statuses describe kernel mechanisms. DNS, package, TLS, desktop, and other userspace failures do not become kernel status codes.

## 2.5 Handle model

```rust
type DwHandle = u64;
const DW_HANDLE_INVALID: DwHandle = 0;
```

Locked semantics:

- handles are opaque
- handles are process-local
- handles are not persistent identifiers
- handle bit layout is not ABI-visible
- transferred objects receive a new handle value in the receiving process
- closing a handle drops that process's reference and authority, but does not implicitly destroy a process or thread
- duplicate/transfer operations may preserve or reduce rights, never increase them without separate authority

The initial rights vocabulary must cover at least:

```text
READ
WRITE
EXECUTE
MAP
WAIT
SIGNAL
DUPLICATE
TRANSFER
INSPECT
MODIFY
```

Object-specific rights may be added through the ABI schema, but agents must not invent private rights outside the schema.

## 2.6 Initial kernel object taxonomy

DW0 implements the objects required for primordial userspace:

- `TaskGroup`
- `Process`
- `Thread`
- `MemoryObject`
- `AddressRegion`
- `Channel`
- `Event`
- `Timer`

The ABI reserves room for later objects such as:

- `Interrupt`
- `DeviceResource`
- exception objects/channels

`File`, `Directory`, `Socket`, `Window`, `AudioDevice`, `Service`, and user identities are not kernel object types in DW0.

## 2.7 Memory model

1. Backing memory and virtual mappings are distinct concepts.
2. `MemoryObject` represents page-backed/shareable memory.
3. `AddressRegion` represents a region of a process virtual address space and owns mappings/subregions.
4. The same `MemoryObject` may be mapped into multiple address spaces subject to rights.
5. The design must support later copy-on-write, executable images, graphics buffers, shared IPC buffers, and pager-backed memory without changing the basic object model.
6. W^X is the default policy. Ordinary mappings must not be writable and executable simultaneously.
7. JIT-style use is expected to transition `RW -> RX` using protection changes.

## 2.8 IPC model

1. Control-plane IPC uses **buffered bidirectional channels**.
2. A channel message is an atomic datagram containing a byte payload plus zero or more transferred handles.
3. Messages are ordered per endpoint and are never partially delivered.
4. If send cannot commit, transferred handles remain valid in the sender.
5. If send commits, transferred handles become invalid in the sender and new handles are created in the receiver.
6. Backpressure is explicit. A full queue returns `WOULD_BLOCK` and clears the writable signal until capacity returns.
7. Peer closure is observable as a channel signal.
8. DW0 begins with a conservative implementation limit of **64 KiB payload** and **16 handles per message**. These values are ABI 0 implementation limits and may be tuned before ABI 1.
9. Bulk data uses `MemoryObject` plus channel notifications rather than large copies through the IPC queue.

## 2.9 Waiting and synchronization

Waitable objects expose signal masks. DW0 must support at least:

```text
Channel: READABLE, WRITABLE, PEER_CLOSED
Process: EXITED
Thread:  EXITED
Timer:   SIGNALED
Event:   SIGNALED
```

Provide generic wait operations:

- wait on one handle
- wait on many handles with `WAIT_ANY`

Reserve the ABI design for `WAIT_ALL`, but it need not be implemented in DW0 unless required by tests.

Deepwyrm also provides a userspace-memory wait/wake primitive so uncontended mutexes remain in userspace:

- `atomic_wait32(address, expected, deadline)`
- `atomic_wake(address, count)`

Do not expose POSIX signals or Linux futex ABI directly.

## 2.10 Task hierarchy and lifetime

1. `TaskGroup` is hierarchical and can contain processes and child task groups.
2. A process contains one or more threads.
3. A thread belongs to exactly one process and cannot outlive it.
4. Closing a process/thread handle does not terminate the task.
5. Explicit task termination requires appropriate authority.
6. Terminating a task group recursively terminates descendants.
7. Exited process/thread objects remain waitable and inspectable while handles remain.
8. Initial process states are conceptually `CREATED -> RUNNING -> EXITED`.

The design must leave room for later resource policy, accounting, session teardown, sandboxes, containers, and Windows Job-like behavior without adding those policies to DW0.

## 2.11 Exceptions

Deepwyrm does not expose POSIX signals as its native exception model. The ABI must reserve a structured exception mechanism capable of representing at least:

- page fault
- illegal instruction
- breakpoint
- divide error
- general protection fault
- debug trap

Full userspace exception-channel delivery may be deferred to the first milestone that needs it, but architecture-specific fault handling must already create structured internal exception information rather than immediately translating faults into Unix concepts.

## 2.12 Time

Native kernel time is monotonic and represented in **nanoseconds**.

- deadlines are absolute monotonic deadlines
- waits and timers use absolute deadlines
- define representations for `NOW` and `INFINITE`
- calendar time, timezone, RTC policy, NTP, and civil time belong to Wyrmroot userspace

## 2.13 Machine baseline

DW0 reference machine is fixed:

```text
Architecture:       x86_64
Endianness:         little
Firmware:           UEFI 64-bit
QEMU machine:       q35
Paging:             4-level x86_64
Base page:          4 KiB
NX:                 required
Initial vCPU count: 1
SMP design:         required from the beginning
Interrupt model:    APIC family
PCI model:          PCI/PCIe
Initial virtual I/O direction: VirtIO PCI
Debug console:      COM1 serial
```

Do not require AVX, AVX2, AVX-512, or similarly optional instruction-set extensions for the base kernel. Optional CPU capabilities are discovered at runtime.

## 2.14 Virtual address-space invariants

- lower canonical address space is reserved for userspace
- upper canonical address space is reserved for the kernel
- page zero remains unmapped
- user mode cannot access kernel mappings
- MMIO mappings are never executable
- kernel stacks receive guard pages when practical
- 4 KiB pages are the baseline
- large pages are optional optimization work
- ASLR is supported by design but not required for DW0 completion
- 5-level paging may be introduced later without changing the native ABI

The exact higher-half kernel link base is an implementation constant, not a userspace ABI value. Once selected, keep it centralized in the linker/architecture configuration rather than duplicating magic numbers.

## 2.15 Concurrency

DW0 boots with one vCPU first, but the codebase must not assume single-threaded kernel execution as an architectural property.

- temporary coarse locking is allowed
- kernel objects should have explicit synchronization ownership
- architecture code must prepare for per-CPU data
- no subsystem may rely on "QEMU currently has one vCPU" for correctness
- SMP bring-up follows after the UP foundation is stable

## 2.16 Drivers

Normal hardware drivers are intended to run in userspace under a driver manager. Deepwyrm will eventually grant restricted capabilities for configuration, MMIO, I/O ports where required, IRQ delivery, and DMA mapping.

DW0 does **not** need the complete userspace driver framework. It must avoid designing itself into a kernel-driver-only architecture. PCI enumeration and device-resource objects may be stubbed/reserved until DW1 unless required for the primordial boot path.

The future DMA API must describe device-visible mappings, not assume physical address equals DMA address.

## 2.17 Security foundation

Deepwyrm security combines:

```text
identity/policy in Wyrmroot
        +
rights-bearing kernel handles
```

Deepwyrm does not make POSIX UID/GID the root authority model. The Unix personality may implement UID/GID and root semantics above the native capability model.

## 2.18 Path/VFS foundation

Deepwyrm does not make pathname parsing a core kernel ABI concern in DW0. When the VFS arrives:

- low-level path components are opaque byte sequences
- normal Wyrmroot policy expects UTF-8
- Wyrmroot exposes a Unix-style `/` namespace
- Windows drive letters and DOS pathname semantics belong to compatibility personalities
- opened objects should be manipulated through handles rather than repeated string resolution where possible

## 2.19 Rust toolchain direction

Deepwyrm is built using the Wyrmroot-maintained Rust toolchain once available. Wyrmroot intends to maintain a fork based on an explicitly adopted upstream **stable** Rust release.

Deepwyrm must not depend on a nightly-only kernel architecture by design. The toolchain version is pinned by Wyrmroot integration rather than silently following whatever host `rustup stable` happens to mean on a given day.

---

# 3. Canonical ABI ownership

Deepwyrm owns the native ABI. Wyrmroot consumes it.

Create a single source of truth similar to:

```text
deepwyrm/
├── abi/
│   ├── schema/
│   │   ├── abi.toml
│   │   ├── boot.toml
│   │   ├── objects.toml
│   │   ├── rights.toml
│   │   ├── status.toml
│   │   └── syscalls.toml
│   └── generated/
├── crates/
│   └── deepwyrm-abi/
├── kernel/
├── tests/
└── tools/
    └── abi-gen/
```

`deepwyrm-abi` must be `#![no_std]` and contain only ABI-safe types/constants/helpers.

The schema/generator must be able to produce, as the project matures:

- Rust ABI definitions
- kernel syscall dispatch metadata
- userspace syscall wrappers
- C headers
- human-readable ABI documentation
- ABI validation tests

Generated files may be committed for bootstrap convenience, but `xtask` or an equivalent local verification command must detect drift from the schemas.

Syscall numbers must be explicit in the schema. Do not derive them from list order and do not silently renumber existing entries. ABI 0 permits deliberate renumbering only when the schema and all consumers are changed together.

---

# 4. Loader -> kernel contract

`DwBootInfoV1` is owned by `deepwyrm-abi` and shared with Wyrmroot's EFI loader.

The first version must contain or reference at least:

- structure size and version
- UEFI-derived physical memory map
- loaded boot-module table
- ACPI RSDP address when available
- optional framebuffer description
- command line bytes and length
- entropy supplied by firmware/RNG facilities
- reserved zeroed fields for future extension

Boot modules must identify at least:

- primordial Wyrmroot bootstrap ELF
- bootfs image

Locked handoff rules:

1. Wyrmroot's loader completes firmware interaction and calls `ExitBootServices()` before entering Deepwyrm.
2. Deepwyrm does not depend on UEFI runtime services after handoff.
3. The x86_64 kernel entry receives a pointer to `DwBootInfoV1` in the first System V argument register (`RDI`).
4. Early kernel code validates and copies all information it needs before discarding loader mappings.
5. BootInfo version mismatch or malformed ranges must fail loudly through the serial/panic path rather than continuing with guessed semantics.

The exact physical and higher-half kernel loading arrangement is implementation detail, but loader and kernel must use one documented linker/handoff scheme and test it in QEMU. Do not duplicate untracked address constants between repositories.

---

# 5. Primordial process contract

Deepwyrm must be able to create the first userspace process without requiring a filesystem service.

DW0 sequence:

1. Locate the bootstrap ELF module from `DwBootInfoV1`.
2. Validate the narrow supported ELF64 subset.
3. Create the root `TaskGroup`.
4. Create the primordial `Process` and root `AddressRegion`.
5. Create `MemoryObject` instances or equivalent backing for bootstrap load segments.
6. Map bootstrap code/data/stack with correct permissions and W^X policy.
7. Create a bidirectional bootstrap `Channel` pair.
8. Represent the bootfs module as a read-only `MemoryObject` and transfer an appropriate handle through the bootstrap channel.
9. Supply any initial diagnostic/bootstrap capabilities required by WYR0.
10. Create/start the initial `Thread` at the ELF entry point in ring 3.

The bootstrap process receives conventional startup metadata plus a bootstrap channel capability. It does not receive ambient authority to arbitrary kernel objects.

Normal later program loading is done by Wyrmroot userspace.

---

# 6. Proposed DW0 repository layout

The implementation may refine names, but preserve subsystem boundaries:

```text
deepwyrm/
├── Cargo.toml
├── rust-toolchain.toml or integration note
├── abi/
├── crates/
│   └── deepwyrm-abi/
├── kernel/
│   └── src/
│       ├── arch/x86_64/
│       ├── boot/
│       ├── debug/
│       ├── memory/
│       ├── object/
│       ├── handle/
│       ├── task/
│       ├── ipc/
│       ├── sync/
│       ├── time/
│       └── syscall/
├── tests/
│   ├── host/
│   └── guest/
├── tools/
│   ├── abi-gen/
│   └── xtask/
└── Plans/
```

Avoid a giant `kernel.rs` or architecture code mixed into portable object logic.

---

# 7. Implementation phases

## Phase DW0-A - workspace, ABI schema, and deterministic tooling

### Tasks

- Create the Rust workspace and `deepwyrm-abi` `no_std` crate.
- Create ABI schema files and the first ABI generator.
- Define `DW_ABI_VERSION = 0`.
- Define fixed-width status, handle, rights, object type, boot-info, and syscall ABI types.
- Define explicit syscall numbers in the schema.
- Generate Rust kernel/userspace definitions from the same source.
- Add local commands for:
  - format/check
  - ABI generation
  - ABI drift verification
  - focused host tests
- Establish a symbolized debug build profile.

### Gate

A host-only test must prove generated kernel and userspace ABI representations agree on sizes, alignments, constants, and syscall numbers.

Do not begin parallel syscall implementation before this gate passes.

## Phase DW0-B - x86_64 entry, diagnostics, and QEMU harness

### Tasks

- Implement the documented loader entry contract.
- Bring up serial output immediately.
- Add a panic path that always attempts to print:
  - panic reason
  - CPU identifier where available
  - instruction pointer
  - fault address where relevant
  - symbolizable backtrace/frame information where practical
- Establish GDT/TSS/IDT and exception stubs.
- Establish APIC-ready interrupt plumbing, even if most device interrupts are not used yet.
- Add QEMU `q35`/UEFI run configuration shared with WYR0.
- Add host-side tooling to launch QEMU paused for GDB.
- Add a machine-readable guest-test completion path for test builds.

### Gate

Targeted QEMU tests must distinguish at least `PASS`, `FAIL`, and `PANIC` without relying only on screenshot inspection.

## Phase DW0-C - physical and virtual memory foundation

### Tasks

- Consume and sanitize the BootInfo physical memory map.
- Implement a simple, testable physical frame allocator. Algorithm choice is not ABI and may be replaced later.
- Establish Deepwyrm-owned page tables with the locked kernel/user split.
- Keep page zero unmapped.
- Apply NX and W^X rules.
- Add safe abstractions around page-table mutation.
- Implement userspace copy/validation helpers without dereferencing arbitrary user pointers directly throughout the kernel.
- Implement the first `MemoryObject` and `AddressRegion` backing/mapping operations required by process creation.

### Gate

Run focused guest tests for mapping, unmapping, permissions, invalid pointers, user/kernel isolation, and shared `MemoryObject` mappings.

## Phase DW0-D - kernel object and handle core

### Tasks

- Implement a common kernel-object ownership/lifetime model.
- Implement per-process handle tables.
- Implement rights checks and handle type validation.
- Implement close and rights-reducing duplicate operations.
- Ensure stale handle values cannot accidentally access a newly allocated object. Internal generation counters are acceptable, but their layout remains private.
- Add host tests for handle-table algorithms where possible.

### Gate

Focused tests must cover invalid handle, stale handle, wrong type, insufficient rights, duplicate-with-fewer-rights, and object lifetime after handle closure.

## Phase DW0-E - syscall entry and task model

### Tasks

- Implement x86_64 `SYSCALL/SYSRET` or documented safe return path.
- Sanitize user-controlled flags/register state on entry/return.
- Implement generated syscall dispatch.
- Implement root `TaskGroup`, `Process`, and `Thread` objects.
- Implement a simple preemptive or cooperative bootstrap scheduler sufficient to run kernel and user threads. Final scheduler policy is not frozen.
- Implement task start/exit/wait state transitions.
- Implement explicit task termination with rights checks.
- Keep synchronization structures SMP-safe even though DW0 runs one vCPU first.

### Gate

A synthetic ring-3 test process must enter userspace, perform at least one harmless native syscall, and return/exit without corrupting kernel state.

## Phase DW0-F - channels, waits, events, timers, and atomic wait

### Tasks

- Implement channel endpoint objects and bounded message queues.
- Implement atomic byte+handle transfer semantics.
- Implement channel readiness and peer-close signals.
- Implement `Event` and `Timer` objects.
- Implement absolute monotonic deadline handling.
- Implement wait-one and wait-many `WAIT_ANY`.
- Implement `atomic_wait32` and `atomic_wake` with strict user-address validation.
- Ensure blocking paths integrate with the scheduler rather than busy waiting.

### Gate

Targeted tests must cover channel ordering, queue full/backpressure, peer close, handle-transfer rollback on failure, successful rights-preserving/reducing transfer, timer deadline, multi-object wait, and lost-wakeup resistance.

## Phase DW0-G - primordial ELF and bootstrap launch

### Tasks

- Implement the deliberately narrow kernel bootstrap ELF parser/validator.
- Reject unsupported ELF classes, machine types, dynamic interpreter use, malformed load ranges, overlap, or invalid permission combinations.
- Create the primordial Wyrmroot process under the root task group.
- Build its userspace stack/start state.
- Create and transfer the bootfs `MemoryObject` through the bootstrap channel.
- Start the initial thread in ring 3.
- Report bootstrap-process exit cleanly through debug/test diagnostics.

### Gate

The WYR0 bootstrap binary must execute from the real Wyrmroot loader path in QEMU and successfully exchange at least one message/handle through the bootstrap channel.

## Phase DW0-H - hardening and milestone closure

### Tasks

- Enable QEMU SMP test mode with more than one vCPU and run concurrency smoke tests even if performance remains coarse-lock limited.
- Run sanitization/invariant checks available to the Rust/kernel environment.
- Verify no production kernel subsystem depends on debug-only QEMU exits.
- Verify ABI generated artifacts have no drift.
- Verify unsupported syscalls/flags fail deterministically.
- Document all `unsafe` blocks in architecture-facing code.
- Produce a short DW0 completion report with known limitations and DW1 blockers.

### Gate

All DW0 acceptance tests pass from a clean checkout using documented local commands.

---

# 8. Testing strategy

The testing model is designed specifically to avoid rebuilding and rerunning the entire OS for every small change.

## Tier 1 - host unit tests

Use ordinary host tests for pure logic:

- ABI schema/generator
- ELF parsing
- handle table algorithms
- rights validation
- queue/ring algorithms
- scheduler data structures where separable
- BootInfo validation

Example desired shape:

```text
cargo xtask test host abi
cargo xtask test host elf
cargo xtask test host handles
```

## Tier 2 - focused QEMU guest tests

Guest test selection must be filterable by subsystem through a build feature or boot/test argument, for example:

```text
cargo xtask test guest memory
cargo xtask test guest ipc
cargo xtask test guest task
```

Do not boot and execute the full integration suite when validating a two-line handle-table fix unless the changed contract crosses subsystem boundaries.

## Tier 3 - cross-subsystem integration

Run the real loader + kernel + WYR0 bootstrap path at phase gates and before merging milestone-complete work.

## Tier 4 - full DW0 validation

Run all host and guest tests, QEMU UP and SMP smoke runs, ABI drift checks, and WYR0 integration only for milestone closure or architecture-wide changes.

---

# 9. Debugging and observability requirements

DW0 must provide from the beginning:

- COM1 serial logging
- structured log prefixes or subsystem tags
- symbolized host-side panic decoding
- QEMU GDB launch support
- deterministic panic/failure exits in test builds
- test names and per-test PASS/FAIL output
- no silent triple-fault loops

Prefer failures such as:

```text
TEST ipc::transfer_rollback ... FAIL
expected sender handle valid after rejected send
observed sender handle invalid
```

instead of a generic black-screen timeout.

---

# 10. Parallel Codex execution model

This plan is suitable for one coordinating agent plus up to seven parallel workers. If fewer workers are available, merge adjacent lanes. The coordinator owns ABI changes and integration.

## Stage 1 parallel lanes

After repository bootstrap:

1. **ABI/schema lane** - schema, generator, `deepwyrm-abi`, layout tests.
2. **x86_64 lane** - entry, serial, GDT/TSS/IDT, exception stubs, GDB plumbing.
3. **host tooling lane** - `xtask`, QEMU configuration, filtered test runner, symbolization.
4. **memory-model lane** - host-testable range/map/permission abstractions before architecture mapping code.

Do not parallelize competing definitions of the same ABI types.

## Stage 2 parallel lanes

After ABI and architecture entry gates:

1. memory/page-table implementation
2. kernel-object/handle implementation
3. task/scheduler implementation
4. IPC/wait implementation
5. bootstrap ELF parser and validation
6. integration-test harness

Each lane must consume the canonical generated ABI rather than creating local copies.

## Integration rule

Every worker should return:

- files changed
- targeted tests run
- assumptions made
- ABI changes requested, if any

The coordinator resolves requested ABI changes centrally before workers continue against a new schema revision.

---

# 11. Explicit DW0 non-goals

Do not let DW0 expand to include:

- POSIX libc
- `fork()` or kernel `exec(path)`
- general filesystem/VFS implementation
- persistent root filesystem
- package manager
- service manager
- shell/TTY/PTY
- network stack
- USB
- audio
- Wi-Fi/Bluetooth
- complete userspace driver manager
- accelerated graphics
- Glasswyrm/Prismdrake
- Windows/DOS compatibility
- dynamic linker
- Rust `std` port
- Secure Boot
- installer
- custom filesystem

Reserve architecture hooks where already specified, then stop.

---

# 12. DW0 deliverables

At milestone completion the repository should contain at minimum:

- reproducible Rust workspace/build instructions
- canonical ABI schemas and generator
- `deepwyrm-abi` `no_std` crate
- `DwBootInfoV1`
- x86_64 UEFI handoff entry
- serial diagnostics and panic path
- memory and page-table foundation
- native syscall entry/dispatch
- rights-bearing handle tables
- TaskGroup/Process/Thread objects
- MemoryObject/AddressRegion objects
- Channel/Event/Timer and wait primitives
- atomic wait/wake primitive
- narrow bootstrap ELF loader
- primordial process launch
- host and guest test suites
- QEMU q35/UEFI runner integration
- GDB/symbolization tooling
- DW0 completion notes

---

# 13. Cross-repository handoff to WYR0

DW0 and WYR0 meet at exactly these contracts:

1. `DwBootInfoV1`
2. kernel ELF loading/handoff requirements
3. `deepwyrm-abi` native syscall/handle definitions
4. primordial bootstrap ELF restrictions
5. bootstrap channel protocol envelope
6. bootfs `MemoryObject` transfer

Deepwyrm is authoritative for items 1, 3, and kernel-facing portions of 2/4. Wyrmroot is authoritative for loader behavior, bootfs contents, and userspace bootstrap protocol semantics.

Wyrmroot must pin the Deepwyrm commit/ABI revision it is built against. Do not copy ABI definitions into Wyrmroot by hand.

---

# 14. Exit criteria

DW0 is finished only when all of the following are true:

- clean checkout builds with documented commands
- ABI generation is deterministic and drift-free
- QEMU `q35` + UEFI reaches Deepwyrm from the real Wyrmroot loader
- kernel switches to its own validated memory-management environment
- ring-3 native code executes
- rights-bearing handles enforce type and permission checks
- channels transfer bytes and handles atomically
- wait/timer primitives function without busy loops
- primordial Wyrmroot bootstrap ELF launches
- bootstrap receives the bootfs `MemoryObject` and channel capabilities
- targeted host/guest tests can run without executing the full suite
- UP reference boot passes
- multi-vCPU concurrency smoke test passes or any explicitly deferred SMP blocker is documented before DW1
- no DW0 non-goal has become a hidden prerequisite

Once these conditions hold, freeze a DW0 completion commit/tag and move hardware-driver/VFS expansion into DW1 rather than continuing to enlarge DW0.

---

# 15. Mandatory security validation flow and gate

Security review is a **required DW0 acceptance gate**. It complements functional testing and does not replace unit tests, QEMU tests, code review, or architectural invariants. Daybreak Blue / Codex Security should be used as a dedicated security-review lane when available, but Deepwyrm must not acquire a runtime or build dependency on that service.

## 15.1 Review flow

For security-sensitive changes and at every phase gate, use this sequence:

```text
implementation
    |
targeted functional tests
    |
static/lint/invariant checks + targeted fuzz/property tests
    |
Daybreak Blue security review of the exact revision/diff
    |
triage findings against Deepwyrm threat model and locked invariants
    |
remediate confirmed findings
    |
add regression tests reproducing the failure class
    |
rerun targeted + affected integration tests
    |
re-review security-relevant remediation
    |
coordinator records security-gate disposition
```

Security review must be performed against an identified commit or diff. A report against stale code does not satisfy the gate after security-sensitive changes have landed.

If Daybreak Blue is temporarily unavailable, the coordinator may use equivalent manual/security-tool review for an intermediate phase, but **DW0 milestone closure requires a recorded security review of the release candidate** before tagging.

## 15.2 Required DW0 security-review surfaces

Review at minimum:

- every production `unsafe` block and the safe abstraction that contains it
- x86_64 syscall entry/return register sanitization
- user pointer, length, alignment, range, and integer-overflow validation
- `DwBootInfoV1` and boot-module range validation
- physical/virtual mapping ownership and user/kernel isolation
- NX, W^X, page-zero, MMIO-execute, and permission-transition enforcement
- handle-table generation/stale-handle behavior
- object-type and rights validation on every handle-consuming syscall
- rights reduction, duplication, and transfer so authority cannot increase accidentally
- channel byte+handle transfer atomicity and rollback behavior
- queue/backpressure and peer-close races
- wait/wake paths for lost wakeups, use-after-free, and race-driven authority leaks
- task termination and TaskGroup descendant authority
- narrow bootstrap ELF parser arithmetic, segment overlap, permissions, and malformed-input rejection
- bootstrap capability construction so primordial userspace receives no unintended ambient authority
- future driver-resource stubs/interfaces for accidental unrestricted physical-memory, MMIO, IRQ, or DMA authority

## 15.3 Adversarial and negative tests

DW0 should accumulate reusable adversarial tests rather than one-off review notes. Include, where applicable:

- null, noncanonical, kernel-space, unmapped, page-boundary, and overflowed user pointers
- zero-length and maximum-length ABI structures/messages
- malformed structure sizes, versions, flags, and nonzero reserved fields
- stale, invalid, wrong-type, and insufficient-rights handles
- attempts to duplicate or transfer greater rights than possessed
- failed channel sends proving transferred handles remain with the sender
- successful transfers proving sender handles are invalidated exactly once
- mapping overlaps, integer wraparound, W+X requests, executable MMIO, and user mappings of kernel ranges
- malformed/truncated/overlapping ELF program headers and adversarial segment sizes
- concurrent close/wait/send/receive/terminate operations under multi-vCPU QEMU smoke testing

Host-side parsers and pure algorithms should use fuzzing/property testing when practical. Kernel-only paths should use deterministic adversarial guest tests and randomized stress only where failures remain reproducible enough to debug.

## 15.4 Finding disposition

Before a phase or milestone security gate can close:

- **Critical/High:** no confirmed unresolved finding may remain.
- **Medium:** must be fixed or have an explicit written disposition, rationale, compensating control if any, and target milestone for remediation.
- **Low/Informational:** may be tracked, but must not contradict a locked DW0 security invariant.
- False positives must be documented with enough technical reasoning to avoid repeated rediscovery.

Severity labels from automated tooling are inputs, not unquestionable truth. The coordinator validates exploitability and architectural impact before disposition.

## 15.5 Security review artifact

Maintain a milestone review record, for example:

```text
security/DW0_SECURITY_REVIEW.md
```

The record should include:

- reviewed Deepwyrm commit
- reviewed Wyrmroot integration commit when cross-repository behavior is relevant
- review date/tooling
- threat-model scope
- findings and dispositions
- regression tests added
- explicitly accepted residual risks
- final gate status

Do not include secrets, private prompts, credentials, or unnecessary proprietary scanner internals in the repository record.

## 15.6 Phase integration

Security is not deferred entirely to DW0-H:

- **DW0-A:** ABI schema/layout, generated boundary types, reserved fields, status/error behavior.
- **DW0-B:** BootInfo handoff, architecture entry, exception paths, register state.
- **DW0-C:** page tables, usercopy, mapping arithmetic, W^X, user/kernel isolation.
- **DW0-D:** handle lifetime, stale handles, object typing, rights monotonicity.
- **DW0-E:** syscall dispatch, task authority, ring transitions, task termination.
- **DW0-F:** IPC transfer atomicity, backpressure, waits, timers, wait/wake races.
- **DW0-G:** bootstrap ELF parser, initial process mappings, capability handoff.
- **DW0-H:** whole-milestone threat-model review, SMP stress, residual-risk triage, release-candidate review.

## 15.7 Mandatory DW0 security exit gate

The earlier DW0 exit criteria are necessary but not sufficient. DW0 **must not be tagged complete** until all of the following are also true:

- the release-candidate commit has completed the security-review flow
- all security-sensitive `unsafe` blocks are documented and reviewed
- no confirmed Critical/High finding remains unresolved
- every Medium finding has an explicit disposition
- confirmed security bugs have regression tests where technically practical
- handle/rights escalation tests pass
- user-pointer and VM isolation adversarial tests pass
- malformed bootstrap ELF/BootInfo tests fail closed
- IPC handle-transfer rollback/atomicity security tests pass
- multi-vCPU security/concurrency smoke tests complete without known authority or memory-safety violations
- `security/DW0_SECURITY_REVIEW.md` (or the canonical equivalent) records the reviewed revision and final `PASS`/accepted-risk state

Any security-sensitive code change after the recorded release-candidate review invalidates the final gate for the affected surface and requires targeted re-review before the DW0 tag is created.
