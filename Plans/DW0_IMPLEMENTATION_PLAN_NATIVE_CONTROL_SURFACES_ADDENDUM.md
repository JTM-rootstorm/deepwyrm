# Deepwyrm DW0 Implementation Plan Addendum: Native Control and Introspection Surfaces

**Status:** Canonical locked addendum to `Plans/DW0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/deepwyrm`  
**Milestone:** DW0 and forward architecture constraint  
**Scope:** Native introspection, device/control interfaces, tracing, logging foundations, storage objects, and Linux-compatibility boundaries

This document is part of the Deepwyrm implementation contract. Codex and human contributors must treat the architectural decisions below as **locked** unless an explicit revision updates this addendum and the matching Wyrmroot addendum together.

This addendum does **not** expand DW0 into implementing the later Wyrmroot management stack. Its purpose is to prevent early kernel APIs from accidentally fossilizing Linux-specific userspace conventions that Wyrmroot would later have to preserve forever.

The central rule is:

> **Deepwyrm exposes typed native objects, rights, queries, events, and IPC. Linux pseudo-filesystems, `ioctl` conventions, D-Bus, udev, syslog, cron, and similar interfaces are optional compatibility surfaces above the native architecture, not kernel foundations.**

---

# 1. No native `/proc`, `/sys`, or `/proc/sys` ABI

Deepwyrm must not make Linux-style pseudo-filesystems the canonical interface for process, kernel, device, or tuning information.

Do not require native software to obtain system information by opening and parsing paths such as:

```text
/proc/<pid>/stat
/proc/meminfo
/proc/sys/...
/sys/class/...
/sys/devices/...
```

Instead, Deepwyrm should expose structured information through ABI-safe query operations, task/object inspection, handles, and/or service IPC.

The native model should preserve explicit:

- object type
- field type
- permissions/rights
- versioning
- range validation
- mutability
- event/change notification where useful

A future Linux/POSIX compatibility layer may synthesize `/proc`, `/sys`, or `/proc/sys` views from native information. Deepwyrm must not depend on those views in the reverse direction.

---

# 2. Native task/system introspection foundation

Deepwyrm must leave room for Wyrmroot to implement structured task/system tools without scraping pseudo-filesystems.

The native task/object introspection model should be able to grow toward queries for:

- task hierarchy and identifiers
- process/thread state
- exit state
- CPU/accounting information
- memory/accounting information
- handle/object inventory subject to inspection rights
- object type and rights
- scheduler/debug state where authorized

Inspection is capability-controlled. Possessing a process identifier alone must not imply unrestricted authority to inspect that process.

DW0 does not need the final enumeration/accounting API, but ABI choices must not require Wyrmroot to reverse-engineer kernel-private text formats later.

---

# 3. No native `/dev` requirement

Deepwyrm device authority is based on typed capabilities/handles and userspace driver/service publication, not path names such as:

```text
/dev/dri/card0
/dev/input/event4
/dev/nvme0
```

A future POSIX/Linux personality may expose `/dev` nodes backed by native device/service objects.

Native Wyrmroot software should be able to acquire a device or service capability without opening a magic filesystem path.

Device naming and user-visible aliases are Wyrmroot policy rather than fundamental Deepwyrm object identity.

---

# 4. No universal native `ioctl()` escape hatch

Deepwyrm must not introduce a universal untyped `ioctl(fd, request, void *)`-style mechanism as its preferred native extension model.

Preferred native mechanisms are:

- explicit typed syscalls for true kernel mechanisms
- typed/versioned channel protocols for userspace services and drivers
- rights-bearing resource handles
- ABI-safe extensible structures with size/version fields

A Linux compatibility layer may translate Linux ioctl numbers and payloads into native calls where required.

If a later subsystem appears to require a generic control operation, the architecture must first determine whether a typed object/protocol can represent it. Generic opaque control blobs are a last resort, not the default.

---

# 5. Service discovery remains userspace

Deepwyrm Channels and transferable handles provide the IPC substrate. Global service naming/routing is a Wyrmroot userspace responsibility.

Deepwyrm must not grow a D-Bus-compatible broker, desktop service registry, or textual service-activation framework into the kernel.

The kernel should provide enough primitives for Wyrmroot to build a small typed service registry over Channels.

A future D-Bus compatibility bridge may map D-Bus names/messages to Wyrmroot-native services where needed.

---

# 6. Device-manager boundary

The previously locked userspace-driver model is strengthened as follows.

Deepwyrm owns mechanism such as:

- hardware enumeration substrate
- protected device-resource capabilities
- MMIO/I/O-port mapping authority where applicable
- IRQ objects/delivery
- DMA mapping authority
- IOMMU mechanism where available

Wyrmroot's userspace device manager owns policy such as:

- matching hardware to a driver
- launching/restarting driver processes
- assigning only the required resource handles
- device metadata and naming
- hotplug policy
- session/user access policy

Do not reproduce udev rule execution inside Deepwyrm.

---

# 7. Native tracing/debug observability must remain possible

Before Deepwyrm ABI 1, reserve an architecture capable of supporting native tracing/debugging without requiring Linux `ptrace` or `/proc` semantics.

The future native tracing model should be capable of observing, subject to explicit authority:

- syscall entry/exit
- task creation/exit
- exceptions/faults
- handle/object activity where diagnostically useful
- IPC/channel activity at an appropriate metadata level
- service-protocol tracing in userspace

Do not freeze Linux `ptrace` as the native debugger contract merely because existing tools use it.

Host GDB through QEMU remains the early DW0 debugging path and is unaffected by this rule.

A POSIX/Linux personality may later provide `ptrace`, `strace`, and related interfaces by adapting native tracing facilities.

---

# 8. Structured crash/exception foundation

The existing structured native exception model must remain suitable for a later Wyrmroot crash service.

Deepwyrm should preserve the ability to expose authorized structured state such as:

- exception type
- process/thread identity
- register state
- fault address
- address-space/mapping metadata
- task/object metadata where permitted

Native crash handling must not require ELF core dumps as the fundamental kernel representation.

A POSIX layer may generate traditional ELF core dumps from native crash information later. Windows compatibility may map the same substrate to its own exception/debug formats.

---

# 9. Logging foundation remains narrow

Deepwyrm may provide a bounded kernel diagnostic/log ring for kernel-originated records, especially during bring-up and fault handling.

The kernel logger should remain mechanism, not a complete system journal.

Deepwyrm must not absorb:

- syslog routing policy
- persistent journal storage
- log rotation
- per-service log retention policy
- network log forwarding
- service supervision

Those belong to a future Wyrmroot logging service.

Where practical, kernel records should have structured metadata such as monotonic timestamp, severity, subsystem/source, and payload rather than forcing userspace to reverse-engineer one giant text stream.

DW0 serial logging remains valid and may be simpler than the final logging record format.

---

# 10. Storage/control object direction

Deepwyrm should expose block/storage mechanism through handles/services rather than reproducing Linux loop-device and ioctl conventions.

The design must permit Wyrmroot to represent concepts such as:

```text
File/MemoryObject-backed image
        |
block-image service
        |
BlockDevice capability/service
```

without requiring `/dev/loopN`, `losetup`, or Linux-specific control ioctls.

Filesystem mounting, mount namespaces, filesystem discovery, partition policy, and image attachment policy remain Wyrmroot userspace responsibilities unless a minimal kernel mechanism is technically unavoidable.

---

# 11. Authorization, scheduled tasks, and account policy remain userspace

Deepwyrm must not make the following policies fundamental kernel concepts:

- `sudo`/`doas` command policy
- UID 0 omnipotence
- cron tables
- scheduled-job calendars
- password databases
- PAM-style authentication stacks
- service-manager policy

Deepwyrm supplies rights-bearing handles, task authority, identity/policy hooks, timers, and IPC from which Wyrmroot can build those facilities.

Privilege elevation should ultimately be expressible as delegated capabilities rather than automatically converting a process into an all-powerful root identity.

---

# 12. Compatibility boundary

Linux/POSIX compatibility may eventually synthesize familiar interfaces including:

```text
/proc
/sys
/dev
sysctl-compatible views
ioctl translation
ptrace
syslog sockets
cron-compatible frontends
D-Bus bridges
udev-compatible events/rules where required
```

These are adapters over the Wyrmroot/Deepwyrm native model.

Do not change Deepwyrm's native object model solely to make one compatibility adapter trivial unless the change is independently sound for the native ABI.

---

# 13. DW0 implementation implications

This addendum does not add large new DW0 deliverables. It amends DW0 implementation choices as follows:

## DW0-A through DW0-D

- Keep ABI objects/queries typed and versionable.
- Do not introduce native pseudo-filesystem conventions for early diagnostics.
- Keep handle/object inspection rights explicit.

## DW0-E/F

- Do not introduce `ptrace`, `ioctl`, POSIX signals, or Unix fd semantics as shortcuts for native task/IPC control.
- Keep native waits/events suitable for later control, tracing, and service tooling.

## DW0-G/H

- Primordial/bootstrap diagnostics may use explicitly temporary debug interfaces, but those interfaces must not silently become `/proc`, `/dev`, syslog, or final service-discovery APIs.
- Record any temporary diagnostic/control mechanism in completion notes so WYR1 does not mistake it for the final contract.

---

# 14. Security implications

Security review should flag designs that create unintended ambient authority through compatibility-shaped shortcuts.

Review especially for:

- task enumeration revealing protected information without `INSPECT` authority
- generic control operations bypassing object-type/rights validation
- device enumeration granting raw hardware authority implicitly
- tracing/debug authority that can be obtained from a PID alone
- log records leaking protected kernel pointers or cross-process secrets
- future pseudo-filesystem bridges accidentally becoming trusted kernel inputs

---

# 15. Locked Deepwyrm control-surface gate

Before ABI 1, architecture review must confirm:

- native process/system introspection does not require `/proc` or `/sys`
- native device access does not require `/dev`
- there is no universal native `ioctl` escape hatch defining subsystem APIs
- service naming/routing remains outside the kernel
- driver binding/policy remains userspace-managed
- structured tracing/crash support remains feasible without Linux `ptrace`
- kernel logging remains a bounded mechanism rather than a system journal/service manager
- block/storage interfaces do not require Linux loop-device semantics
- elevation, account, scheduled-task, and service policy remain userspace concerns
- Linux compatibility can be layered above these mechanisms without becoming the native ABI

This gate is architectural and additive to the existing DW0 functional, security, toolchain, libc-independence, and image-delivery contracts.