# Deepwyrm DW1-D0 DeviceResource and Interrupt Contract

**Status:** Reached DW1-D0 architecture and host-model gate
**Reached:** 2026-08-29
**Paired contract:**
[`wyrmroot/Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md`](../../wyrmroot/Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md)
**Implementation authority:** `DW1D_IMPLEMENTATION_PLAN.md`, Sections 0 through 5
**Scope:** Canonical device-authority identities, immutable boot-resource intake,
TaskGroup custody, checked PIO, synthetic-capable Interrupt semantics, typed
finalization, and the WYR1-C4 ownership seam

## 1. Disposition and phase boundary

DW1-D keeps the implementation plan's selected custody direction. Validated
boot resources are bound to one kernel-created, long-lived resource-domain
TaskGroup. `/system/init` receives management and transfer authority for that
group, but its Process remains in the parent group. A claim therefore requires
two independent facts:

1. possession of a handle to the exact resource-domain TaskGroup carrying the
   new `RESOURCE` right; and
2. structural membership of the calling Process in that TaskGroup or one of
   its live descendants.

Neither fact substitutes for the other. Names, paths, process IDs, Channel
peers, Wyrmroot roles, and numerically equal foreign identities are not claim
authority.

This D0 gate freezes the design and proves it with a bounded host model. It
does not mutate the canonical ABI, activate object types 16 or 17, implement a
syscall, parse a live boot-device table, access a port, bind a physical
interrupt, admit selector 30, or release WYR1-C4. Those actions begin only in
their dependent D1 through D6 packages.

Physical q35 COM2 IRQ3 routing remains DW1-E. UART initialization, byte I/O,
buffering, `uart16550d`, `consoled`, and `wyrmsh` remain WYR1-D or later.

## 2. Accepted baseline and transition inventory

D0 starts from these measured clean child-repository heads:

| Repository | Identity | Meaning |
| --- | --- | --- |
| Deepwyrm | `2e06491472c80ef110f4adefac4c0d96079b2c8d` | documentation descendant of accepted DW1-C |
| Wyrmroot | `01874a45854689dc3e6aeb21047b29bde1858e41` | reached WYR1-C3 construction seam |
| Rust | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` | accepted Wyrmroot toolchain fork |

The accepted DW1-C scheduler tuple remains the reference recorded in
`docs/DW1_C_VALIDATION.md`; D0 does not reinterpret its selector or evidence.

The complete D0 preflight recorded:

| Item | Measured identity/state |
| --- | --- |
| root coordination | `ddddce48c4bf0958a270a5035d64734c02d0f375`; only preserved untracked `DW1C5_HANDOFF.md` and `DW1D_IMPLEMENTATION_PLAN.md` |
| Deepwyrm ancestry | accepted `c5cfa1a5126259e88be5b5670e927f627a6e1086` is an ancestor of the clean starting head |
| Wyrmroot ancestry | reached C3 `01874a45854689dc3e6aeb21047b29bde1858e41` is the clean starting head |
| ABI schema Git tree | `298b72e6cff2d035e4e2d659dac1b0c855463ba3` |
| generated ABI Git tree | `844dca35e6f022ee600832395094aa199fd3b447` |
| accepted toolchain request/name | `RUST-WYR0-I-B-SYSROOTS-007` / `wyrmroot-1.97.1-a92dc7f7` |
| accepted `rustc` SHA-256 | `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70` |
| accepted Cargo SHA-256 | `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce` |
| accepted `rust-lld` SHA-256 | `38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721` |
| worktree lanes | strict zero-lane audit passed for Deepwyrm and Wyrmroot |
| occupied selectors | test IDs 25, 26, 27, and 28 remain implemented; 29 remains WYR1-C's conceptual reservation |
| D reservation | `device-resource-interrupt-synthetic`, test ID 30, remains provisional until D6 registry admission |
| machine profile | canonical q35 + OVMF; DW1-C reference is four vCPU/2048 MiB; no network or host shares |

The object/right/signal, syscall, boot-module, selector, and verified-runner
registries were inventoried before design. D0 changes none of them.

Current transition points are:

- the canonical schema reserves `INTERRUPT = 16` and
  `DEVICE_RESOURCE = 17`, with no compatible-rights rows;
- rights currently occupy bits through `MODIFY = 0x200`;
- `SIGNALED` currently applies only to Event and Timer;
- `DwAbiInfoV1.feature_bits` exists and is currently zero;
- syscall families currently occupy `0x0000xxxx` through `0x0005xxxx`;
- object-info topic families currently occupy basic `0`, task `1`, and memory
  `2`;
- BootInfo accepts at most 16 module entries and recognizes module kinds 1
  through 3;
- the loader and primordial path currently construct and consume exactly
  bootstrap, bootfs, and the internal paging handoff;
- TaskAuthority already owns a bounded parent tree and each Process retains
  its exact parent TaskGroup, but no public membership predicate exists;
- HandleTable duplicate and Channel MOVE already enforce nonzero subset rights
  and rollback-or-commit ownership;
- wait registrations retain `InternalRef` pins and the central typed finalizer
  is the only valid object-slot release path;
- Event, Timer, and Channel provide the existing register-or-observe,
  generation, wake-intent, and teardown patterns to preserve; and
- the COM1 diagnostic path contains the current direct x86 scalar `u8` port
  assembly and remains kernel-owned.

## 3. Canonical identities frozen for D1

### 3.1 Rights, objects, signals, and discovery

D1 adds exactly this right:

```text
DW_RIGHT_RESOURCE = 0x0000000000000400
```

Its meaning is: claim or derive kernel-managed resource authority explicitly
attached to the target object, subject to that object's additional ownership
and membership rules. `RESOURCE` is compatible only with `TASK_GROUP` in
DW1-D.

The compatible-rights masks are:

| Object | Rights | Numeric mask |
| --- | --- | ---: |
| `TASK_GROUP` | `MODIFY | DUPLICATE | TRANSFER | INSPECT | RESOURCE` | `0x7c0` |
| `DEVICE_RESOURCE` | `READ | WRITE | MODIFY | DUPLICATE | TRANSFER | INSPECT` | `0x3c3` |
| `INTERRUPT` | `WAIT | MODIFY | TRANSFER | INSPECT` | `0x390` |

`INTERRUPT` deliberately has no `DUPLICATE`. It can be moved once with reduced
rights because Channel MOVE transfers the existing generic reference.

`DW_SIGNAL_SIGNALED = 0x10` becomes compatible with
`EVENT,TIMER,INTERRUPT`; no new signal bit is added.

D1 defines:

```text
DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT = 0x0000000000000001
```

The schema generates that identity in D1, but the kernel reports the bit only
after D5 has made the complete claim/PIO/Interrupt runtime usable; D1 alone
continues to report zero. ABI version remains zero. Userspace discovers support through
`abi_get_info.feature_bits`, never by probing syscall gaps or module presence.

### 3.2 Syscall namespace

The device family is frozen as:

| Syscall | Number | Required authority |
| --- | ---: | --- |
| `device_resource_claim` | `0x00060001` | exact `TASK_GROUP:RESOURCE` plus caller membership |
| `device_pio_read` | `0x00060002` | `DEVICE_RESOURCE:READ` |
| `device_pio_write` | `0x00060003` | `DEVICE_RESOURCE:WRITE` |
| `interrupt_create` | `0x00060010` | `DEVICE_RESOURCE:MODIFY` |
| `interrupt_ack` | `0x00060011` | `INTERRUPT:MODIFY` |

The exact signatures are:

```text
device_resource_claim(
    resource_domain: DwHandle,
    resource_id: u64,
    requested_rights: DwRights,
    out_resource: DwUserAddress,
)

device_pio_read(
    resource: DwHandle,
    offset: u32,
    width: u32,
    out_value: DwUserAddress,
)

device_pio_write(
    resource: DwHandle,
    offset: u32,
    width: u32,
    value: u32,
)

interrupt_create(
    resource: DwHandle,
    requested_rights: DwRights,
    out_interrupt: DwUserAddress,
)

interrupt_ack(interrupt: DwHandle)
```

All requested-rights arguments must be nonzero, known, compatible subsets.
Every out pointer is fully validated and pinned before mutable authority or
hardware state is changed. Failure leaves output bytes unchanged.

For width 1 or 2 PIO writes, high value bits outside the selected width must be
zero; the kernel rejects rather than truncates them.

### 3.3 Object information

The object-info topics are:

```text
DW_OBJECT_INFO_DEVICE_RESOURCE_V1 = 0x00030001
DW_OBJECT_INFO_INTERRUPT_V1       = 0x00030002
```

`DwDeviceResourceInfoV1` is exactly 48 bytes:

```text
offset  type                     field
0x00    u32                      size = 48
0x04    u32                      version = 1
0x08    DwDeviceResourceKind     kind
0x0c    u32                      flags = 0
0x10    u64                      resource_id
0x18    u64                      lease_generation
0x20    u16                      pio_base
0x22    u16                      pio_length
0x24    u32                      interrupt_source
0x28    u64                      reserved = 0
```

`DwInterruptInfoV1` is exactly 64 bytes:

```text
offset  type                field
0x00    u32                 size = 64
0x04    u32                 version = 1
0x08    u32                 source
0x0c    DwInterruptState    state
0x10    u64                 object_generation
0x18    u64                 binding_generation
0x20    u64                 parent_resource_id
0x28    u64                 parent_lease_generation
0x30    DwInterruptInfoFlags flags
0x34    u32                 reserved0 = 0
0x38    u64                 reserved = 0
```

Public state values are `ARMED = 1`, `PENDING = 2`, and
`FINALIZING = 3`. `DW_INTERRUPT_INFO_FLAG_COALESCED = 0x1` is the sole V1
flag. No pointer, object-slot address, APIC register address, platform token,
or hidden route identity is exposed.

## 4. Immutable boot-device carrier

D1 adds module kind:

```text
DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1 = 4
```

The module is optional, unique, page-aligned, carries exactly `READ_ONLY`, and
is kernel-internal. It is never returned by `delegable_module`, mapped into a
Process, or treated as userspace authority. Existing selectors omit it and
retain their bytes and meaning.

The canonical payload is little-endian. `DwBootDeviceTableV1` is exactly 32
bytes:

```text
offset  type   field
0x00    u32    size = 32
0x04    u32    version = 1
0x08    u32    resource_count in 1..=8
0x0c    u32    flags = 0
0x10    u32    record_stride = 48
0x14    u32    reserved0 = 0
0x18    u64    total_byte_len = 32 + resource_count * 48
```

`DwBootDeviceResourceV1` is exactly 48 bytes:

```text
offset  type                    field
0x00    u32                     size = 48
0x04    u32                     version = 1
0x08    DwDeviceResourceKind    kind
0x0c    u32                     flags = 0
0x10    u64                     resource_id, nonzero
0x18    u64                     device_correlation_id, zero means absent
0x20    u16                     pio_base
0x22    u16                     pio_length, nonzero
0x24    u32                     interrupt_source, nonzero
0x28    u64                     reserved = 0
```

V1 admits only:

```text
DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT = 1
```

The table module's logical byte length must equal `total_byte_len`. Existing
page-rounded module allocation and overlap rules still apply. A present table
with zero records is invalid; absence of the optional module means no boot
device grants.

Validation is all-or-nothing and ordered:

1. validate generic BootInfo/table structure and intake capacity;
2. validate each module record, the three required existing kinds, exact flags,
   optional-table uniqueness, and all page-rounded module overlaps;
3. validate exact table header size, version, count, flags, stride, reserved
   fields, checked length, and containing-module extent;
4. validate each resource record in index order: exact size/version,
   supported kind, zero flags/reserved, nonzero identity/length/source, and
   checked PIO end at or below `0x10000`;
5. reject every half-open PIO overlap with protected COM1
   `[0x3f8,0x400)` and every interrupt source equal to protected IRQ4;
6. in ascending `(left,right)` record order, reject duplicate resource IDs,
   duplicate interrupt sources, and overlapping exclusive PIO ranges; and
7. only after the complete table passes, snapshot immutable descriptors and
   materialize `Available` grants.

No partial grant publication is permitted.

The WYR1-C selected q35 product supplies exactly:

```text
resource_id            = 1
device_correlation_id  = 1
kind                   = X86_PIO_WITH_PLATFORM_INTERRUPT
pio_base               = 0x2f8
pio_length             = 8
interrupt_source       = 3
```

The equal resource and correlation values are intentional for this one-role
product only. They remain different namespaces. Wyrmroot's WRDM role ID 1 and
driver path do not manufacture or replace kernel authority.

## 5. Resource domain and claim custody

When a validated table is present, the primordial construction transaction
creates this hierarchy before init starts:

```text
bootstrap TaskGroup
├── /system/init Process
└── boot resource-domain TaskGroup
    └── future devmgr-generation TaskGroup
        ├── /system/devmgr Process
        └── future driver-attempt TaskGroup
            └── driver Process
```

Every validated grant is bound immutably to the boot resource-domain
TaskGroup. The kernel sends init a fourth ordered bootstrap capability after
root AddressRegion, bootfs MemoryObject, and the existing bootstrap TaskGroup:

```text
TASK_GROUP:
    MODIFY | DUPLICATE | TRANSFER | INSPECT | RESOURCE
```

That handle refers to the resource-domain child, not init's own parent group.
Init is therefore outside the domain and cannot claim. The existing third
TaskGroup capability retains its old object and rights.

`RESOURCE` is non-manufacturable. `task_group_create` cannot mint it merely
because the new child object type is compatible; requesting it for a newly
created child returns `ACCESS_DENIED`. It may be preserved or reduced only by
duplicate/MOVE of a handle that already carries it. The kernel-created domain
handle is the boot root of this authority.

Init creates each devmgr-generation TaskGroup beneath the retained resource
domain, constructs devmgr inside that group, and gives it only a duplicate of
the exact resource-domain handle with `RESOURCE | INSPECT`. Driver-attempt
groups are children of the corresponding devmgr-generation group.

Claim membership is evaluated by TaskAuthority, not a syscall adapter:

- the caller Process and exact owner domain must both be active;
- start at the caller Process's retained parent TaskGroup;
- accept an exact owner match;
- otherwise follow bounded retained parent references toward the root;
- reject a missing, stale, terminating, terminated, cyclic, over-bound, or
  non-owner traversal; and
- revalidate the same process/domain generations at commit.

The grant is:

```text
ValidatedBootResourceGrant
    immutable descriptor
    owner resource-domain TaskGroup internal reference
    nonzero grant generation
    state:
        Available
        Leased(DeviceResource ObjectId, nonzero lease generation)
```

The claim transaction is:

```text
validate ABI syntax and output pin
resolve exact TaskGroup handle and RESOURCE right
validate active caller membership
find exact resource_id and require Available
reserve grant, object slot, typed payload capacity, and caller handle slot
bind DeviceResource payload and owner-domain/lease generations
publish the requested caller handle
commit Leased at one no-fail point
```

Every failure before commit cancels every reservation, restores `Available`,
publishes no handle, and leaves output bytes unchanged. The implementation
must not run a typed finalizer, scheduler operation, or platform call while
holding HandleTable ownership.

Failure precedence is:

1. malformed scalar/rights arguments: `INVALID_ARGUMENT`;
2. invalid output range: `BAD_ADDRESS`;
3. stale handle: `BAD_HANDLE`;
4. wrong object type: `WRONG_OBJECT_TYPE`;
5. missing `RESOURCE`, wrong domain handle, or membership failure:
   `ACCESS_DENIED`;
6. terminating caller/domain: `BAD_STATE`;
7. unknown resource ID: `NOT_FOUND`;
8. already leased grant: `ALREADY_EXISTS`;
9. bounded capacity failure: `NO_RESOURCES` or `NO_MEMORY` according to the
   exhausted existing authority; and
10. success.

## 6. DeviceResource and PIO semantics

One live `DeviceResource` payload contains the immutable resource ID,
nonzero lease generation, admitted kind, exact PIO range, exact interrupt
source, retained owner-domain identity, and live/finalizing state. It contains
no service, driver, path, PID, role, or compatibility policy.

PIO supports scalar widths 1, 2, and 4 only. Each operation performs, in
order:

1. exact live handle/type/right resolution;
2. admitted-kind check;
3. exact width validation;
4. checked `offset + width` and complete half-open range containment;
5. checked `base + offset` and final-port containment in `[0,0x10000)`;
6. write-value width validation;
7. release of generic/table guards required by the architecture boundary;
8. exactly one scalar architecture operation; and
9. read zero-extension or success return.

The kernel does not inspect UART registers. String I/O, REP I/O, batching,
MMIO, IOPL, TSS I/O bitmaps, userspace inline `in/out`, DMA, and IOMMU are not
admitted.

D2 centralizes x86 PIO in one architecture module supporting widths 1, 2, and
4. The existing COM1 diagnostic path becomes a narrow `u8` consumer of that
boundary without becoming a DeviceResource.

## 7. Interrupt state, wait, and finalization

`interrupt_create` consumes no source handle. It requires a live
`DeviceResource:MODIFY`, reserves the resource's exact source exclusively,
retains an internal reference to the parent DeviceResource, installs a
nonduplicable Interrupt with requested subset rights, and publishes it only
after the synthetic-capable platform binding reaches `Armed`.

V1 pending state is bounded to two facts:

```text
Armed
  delivery(binding_generation)
    -> Pending(SIGNALED, coalesced = false, source masked)

Pending(coalesced = false)
  another delivery
    -> Pending(SIGNALED, coalesced = true)

Pending(coalesced = true)
  another delivery
    -> Pending(SIGNALED, coalesced = true)
```

This is not a delivery count. `coalesced = true` means at least one additional
delivery fact must survive one acknowledgement.

`interrupt_ack` behaves as follows:

- `Armed` or no pending fact returns `BAD_STATE`;
- `Pending(coalesced = true)` consumes only the coalesced fact and remains
  `Pending(coalesced = false)`, masked and signaled;
- `Pending(coalesced = false)` performs a prepare/platform/commit rearm
  transaction for the exact binding generation;
- a delivery racing that transaction returns `Pending(coalesced = false)` and
  remains signaled; otherwise commit returns `Armed` and clears `SIGNALED`;
- a stale binding generation is inert and cannot wake or mutate a replacement.

Delivery publishes level state before taking generation-bound ready wake
intents. Wait registration uses the existing register-or-observe barrier and
retains one internal pin. Wake, timeout, interruption, and terminal cleanup
release every exact registration pin through the existing wait engine.

Finalization is strictly ordered:

```text
last public/internal Interrupt reference
  -> mark finalizing and invalidate delivery generation
  -> mask and unbind the platform source without wait/object/scheduler locks
  -> complete typed Interrupt cleanup
  -> release the parent DeviceResource internal reference
  -> cascade typed DeviceResource finalization if it is now last
  -> revalidate exact grant and lease generations
  -> return exactly that grant to Available
```

Source ownership cannot recycle before mask/unbind completes. The grant cannot
return while any reduced resource handle, queued Channel reference, Interrupt,
or wait registration pin remains.

## 8. Teardown and WYR1-C handoff

Resource-domain teardown is terminal and fail-closed, not a normal restart
operation. Marking the domain terminating immediately blocks new claims, then
recursively terminates descendants and drains their handles through ordinary
typed finalization. The domain and its grants are never rebound to another
TaskGroup in the same boot. A surviving or escaped reference keeps the lease
unavailable rather than permitting overlap.

Normal devmgr replacement terminates only the old devmgr-generation TaskGroup.
The resource-domain root survives. Replacement cannot claim until every old
driver resource and Interrupt has finalized and the exact grant is Available.

The paired WYR1-C4 bundle is exactly two Channel-MOVE handles in this order:

1. `DEVICE_RESOURCE` with `READ | WRITE | INSPECT` (`0x103`);
2. `INTERRUPT` with `WAIT | MODIFY | INSPECT` (`0x310`).

Devmgr retains its broad parent DeviceResource for the lease generation,
duplicates one reduced resource per driver attempt, and derives one fresh
Interrupt per attempt. Failed MOVE preserves both sender handles. Successful
MOVE transfers both exactly once and removes `TRANSFER` from the receiver.

The Wyrmroot `BundleGeneration` equals the kernel
`DeviceResource.lease_generation`; it is not an independent counter. A driver
restart under one devmgr keeps the lease/bundle generation but receives fresh
attempt, endpoint, and Interrupt object/binding generations. A devmgr restart
requires a fresh lease generation.

## 9. Required-source and licensing disposition

All root, Deepwyrm, and Wyrmroot sources named by the active D0 package were
read. The current object/finalizer, wait/Event/Timer/Channel, TaskGroup,
BootInfo/module, COM1, C3 construction, and product-tooling paths were
inspected. Their reusable native transactions and ownership boundaries are
preserved as described above.

Pinned external sources were used conceptually only:

- Fuchsia/Zircon `resource_dispatcher.cc` at
  `6a606ff7fd9b055edee6557566fb3f112df1a812` informed validate-before-publication,
  exclusive range lifetime, and release ordering. Its root-resource kinds,
  rights, and syscall model are rejected.
- Fuchsia/Zircon `interrupt_dispatcher.cc` at the same revision informed
  pending/ack separation and mask/unbind-before-recycle. Ports, packets,
  timestamps, flags, and ABI are rejected.
- xv6-riscv `kernel/uart.c` and `kernel/plic.c` at
  `35b088427ef37611c38afdeed5a52a278cae38f9` informed only small register and
  claim/service/complete ordering comparisons. RISC-V PLIC, global console,
  Unix, and locking assumptions are rejected.
- rust-osdev `uart_16550` `src/lib.rs`, `src/config.rs`,
  `src/backend/pio.rs`, and `src/spec.rs` at
  `176b07b076bdc1fe999a5e757ab53a0e24b4005c` confirmed the eight-register PIO
  footprint and scratch offset 7. Its driver configuration and implementation
  are not imported.

The reviewed sources use compatible MIT-style or `MIT OR Apache-2.0` terms.
No code or substantial expression was copied or adapted, so D0 introduces no
third-party code, notice, or license-boundary change. New model and contract
work remains first-party `GPL-3.0-or-later` under workspace policy.

## 10. Host-model gate

`kernel/tests/dw1_d0_custody_model.rs` is the bounded D0 model. It proves:

- init with full custody rights still fails membership;
- in-domain claim succeeds and a second claim while leased fails;
- claim failure at grant, object, or handle reservation leaves `Available`;
- duplicate and MOVE never amplify rights and failed MOVE preserves ownership;
- devmgr death cannot release a driver-held reduced resource or Interrupt;
- a coalesced second delivery survives one ack;
- delivery racing rearm remains pending;
- ack without pending is `BAD_STATE`;
- stale binding delivery is inert;
- a waiter pin defers unbind and parent release;
- Interrupt unbind precedes exactly one grant return;
- replacement receives a fresh lease generation and stale handles fail;
- domain teardown blocks later claims;
- exact COM2 scratch range arithmetic succeeds only for offset 7, width 1;
- overflow, one-past-end, duplicate grants, COM1 overlaps, and IRQ4 fail.

The focused test passes four cases on the reached source.

## 11. D0 closure and D1 entry

The paired Deepwyrm and Wyrmroot documents agree on object IDs, rights,
feature discovery, syscall and object-info numbers, boot-table layout, resource
ID 1, custody hierarchy, membership, lease identity, bundle order/rights,
MOVE ownership, cleanup ordering, failure precedence, and nonclaims. The host
model passes.

DW1-D0 is therefore closed. D1 may now mutate the canonical schema and
generated artifacts exactly as frozen here. Runtime implementation must still
proceed through D2 through D6 in order; D0 is not runtime or guest acceptance.
