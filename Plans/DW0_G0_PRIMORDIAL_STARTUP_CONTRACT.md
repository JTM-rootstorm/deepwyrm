# Deepwyrm DW0-G0 Primordial Startup Contract

**Status:** DW0-G0 architecture closure; authoritative for DW0-G implementation
**Prepared:** 2026-08-21
**Deepwyrm baseline:** `557f1d9aa801e90b76b7012d827e2bebba2109e1`
**Implementation anchor:** `f5de26fe96d071c636d53d6d39039f8fb2f2c275` — DW0-F14 FULL ACCEPTED
**Paired Wyrmroot baseline:** `92a33b4aae14dad29f1a2ae407cb5be10ccf7ffe`
**Paired contract:** `wyrmroot/Plans/WYR0_D0_PRIMORDIAL_STARTUP_CONTRACT.md`
**Milestone:** DW0-G primordial ELF and bootstrap launch

This contract locks the shared Deepwyrm/Wyrmroot seam required before G1/G2 and WYR0-D1 may implement against it. It refines the DW0 plan, D0/E0/F0 contracts, the active workspace G plan, and the paired Wyrmroot D0 contract without changing the public ABI-0 schema.

The baseline hashes above are the pre-contract design inputs. Because independent Git repositories cannot embed each other's final contract commit without a circular hash dependency, the OS-Project root closure record binds the final post-contract Deepwyrm/Wyrmroot commit pair.

The compatibility-personality doctrine remains an admission overlay. Nothing here is a POSIX `exec`, Windows process model, fd/HANDLE convention, signal ABI, or compatibility-personality shortcut.

## 1. G0 disposition: no public ABI change

The current ABI already contains every public mechanism required by G0:

- `DwThreadStartArgsV1.startup_argument0/1` are Wyrmroot-owned startup values;
- `DwProcessCreateResultV1.child_bootstrap_handle` proves child-local handle values need not be magic constants;
- `DW_OBJECT_INFO_BASIC_V1` reports object type and held rights under `INSPECT`;
- `DW_OBJECT_INFO_MEMORY_OBJECT_V1` reports exact immutable logical `byte_size`;
- `address_region_map` distinguishes exact logical size from page-rounded mappable capacity;
- F-era Channel transfer moves bytes and handles atomically with rights preservation/reduction; and
- F10 already establishes prepare/reserve/no-fail-commit patterns for Process/root-region/bootstrap-handle publication.

G0 therefore adds no syscall, ABI record, right, object type, signal, or boot record. If implementation later proves one is unavoidable, dependent G/WYR0-D work stops for an explicit ABI-0 contract revision and Wyrmroot repin.

Wyrmroot currently pins Deepwyrm `6de5af17dfef979aeadc150ce3958cd941fedbb2`. That revision is an ancestor of the F14 implementation anchor and already contains the public G0 surfaces named above, including exact MemoryObject-size introspection and `startup_argument0/1`. G0 therefore does not force an ABI-only repin. Accepted G target artifacts must still be repinned to the exact frozen Deepwyrm implementation candidate at the later paired-artifact gate; an older compatible ABI pin is not G runtime acceptance.

## 2. Ownership boundary

Deepwyrm owns:

- selecting and validating exactly one bootstrap module and one bootfs module from validated `DwBootInfoV1` state;
- the deliberately narrow primordial ELF parser/load plan;
- Process, root `AddressRegion`, segment mappings, guarded user stack, Channel, and initial Thread construction;
- minting/staging only the declared child capabilities;
- failure-atomic publication and cleanup; and
- observing structured bootstrap termination for the G acceptance gate.

Wyrmroot owns:

- the startup stack byte contract above `DwThreadStartArgsV1`;
- the meaning of `startup_argument0/1`;
- `BOOTSTRAP_INIT_V1` and `BOOTSTRAP_READY_V1` protocol bytes and capability roles;
- bootstrap-side capability validation and bootfs parsing; and
- all ordinary userspace executable-loading policy after the primordial process.

Deepwyrm never parses bootfs paths or application executables and does not gain filesystem-aware `exec(path)` behavior.

## 3. Boot-module intake

G accepts exactly one `DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP` and exactly one `DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS` from the already validated BootInfo snapshot.

The bootstrap module retains the current loader contract of zero module flags. The bootfs module must carry exactly `DW_BOOT_MODULE_FLAG_READ_ONLY`. Zero length, duplicate required kinds, unknown required flags, arithmetic overflow, overlap after page rounding, or a range outside retained owned/reserved module storage fails before primordial Process construction.

The bootfs `DwBootModuleV1.byte_len` is the authoritative logical content length. The loader's complete page-rounded allocation was zeroed before the payload copy. Deepwyrm may either retain/import those immutable pages or copy them into new page-backed storage, but the resulting `MemoryObject` must have:

- exact logical size equal to BootInfo `byte_len`;
- page-rounded mappable capacity computed with checked 4096-byte alignment;
- zero bytes in the final-page tail between logical size and mappable capacity;
- an immutable/non-writable backing ceiling for its lifetime; and
- no alias to unrelated allocator contents.

The paging-handoff module remains kernel-internal and is never eligible for primordial capability staging.

## 4. Primordial ELF subset

The kernel parses only the primordial bootstrap ELF and accepts this G0 subset:

- ELF64, little-endian, x86-64, ELF current version;
- static `ET_EXEC` only;
- file/module length `1..=16 MiB`;
- at most 16 program headers and at most 8 `PT_LOAD` segments;
- `PT_LOAD` plus optional `PT_PHDR` and optional `PT_GNU_STACK` only;
- no `PT_INTERP`, `PT_DYNAMIC`, `PT_TLS`, runtime relocations, PIE requirement, or dynamic linker;
- if `PT_GNU_STACK` exists, it must not request execute permission;
- every load range uses checked file and memory arithmetic with `filesz <= memsz`;
- file-offset/virtual-address alignment congruence is validated;
- every page-rounded virtual range is lower-canonical userspace, excludes page zero, and stays outside kernel space;
- no two page-rounded load ranges overlap even when their raw byte ranges do not;
- no load segment is writable and executable simultaneously;
- the entry point lies inside an executable load segment; and
- the sum of page-rounded mapped `PT_LOAD` extents is at most 32 MiB.

Unsupported program-header types fail closed rather than being guessed harmless. Section headers and symbols are irrelevant to loading. BSS bytes and all new segment-page slack are zero before executable publication.

These are ABI-0 G implementation limits, not a stable general ELF ABI. Wyrmroot deliberately links `bootstrap.elf` to this subset.

## 5. Primordial user stack and startup registers

The primordial stack has one 4 KiB unmapped guard page followed by exactly 64 KiB of RW/NX user mapping. No executable-stack transition is permitted.

The highest mapped 4 KiB page is the **Wyrmroot startup block**. Deepwyrm zeroes the full stack allocation, writes startup metadata only into that top page, and sets `RSP` to the base of the startup block (`stack_top - 4096`). The 60 KiB below `RSP` remains ordinary downward-growing stack space, so the existing return validator can require a writable byte immediately below `RSP`.

The startup block is an array of little-endian 64-bit words beginning at `RSP`:

```text
argc
argv[0] ... argv[argc-1]
0
envp[0] ... envp[n-1]
0
aux_type, aux_value
...
0, 0
string/data bytes referenced above
```

Every pointer reachable from the startup vector must refer wholly inside the same 4 KiB startup block. All strings are NUL-terminated UTF-8 for native Wyrmroot startup. Unused startup-block bytes remain zero.

The concrete primordial G0 startup is:

- `argc = 1`;
- `argv[0] = "wyrmroot-bootstrap"` stored inside the startup block;
- empty environment;
- no aux entries other than terminal `(0, 0)`; and
- 16-byte-aligned `RSP`.

Deepwyrm supplies the initial registers through the existing `ThreadStartState` path:

- `RIP` = validated bootstrap ELF entry;
- `RSP` = startup-block base;
- `RDI` / `startup_argument0` = actual child-local bootstrap Channel handle;
- `RSI` / `startup_argument1` = Wyrmroot native startup ABI version `1`;
- `RFLAGS = 0x202`; and
- all other initial general-purpose registers are zero as already defined by the E execution context.

The bootstrap handle is opaque and may vary between launches. No numeric handle value is reserved by ABI or convention.

## 6. Bootstrap Channel and Wyrmroot wire envelope

The child bootstrap Channel handle has exactly:

`READ | WRITE | WAIT | INSPECT`

It has no `DUPLICATE` or `TRANSFER` right in G0. Deepwyrm retains the peer endpoint only for the bounded primordial handshake/monitor path.

Wyrmroot owns the wire bytes. Deepwyrm constructs the initial bytes exactly as specified by the paired WYR0-D0 contract. The shared fixed header is 40 bytes:

| Offset | Width | Field | G0 rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `WRBP` |
| 4 | 2 | major | little-endian `1` |
| 6 | 2 | minor | little-endian `0` |
| 8 | 4 | message type | `1=INIT`, `2=READY` |
| 12 | 4 | flags | zero |
| 16 | 4 | total size | exact encoded bytes |
| 20 | 4 | capability count | exact transferred-role count |
| 24 | 8 | transaction id | nonzero; G0 INIT uses `1` |
| 32 | 8 | reserved | zero |

An INIT capability descriptor is 8 bytes: `role: u32` followed by zero `reserved: u32`. The protocol deliberately does **not** copy Deepwyrm object-type/right numeric constants into the Wyrmroot wire format. Role semantics below bind the expected Deepwyrm type and exact rights through the pinned ABI package.

`BOOTSTRAP_INIT_V1` is exactly 56 bytes, has message type `1`, capability count `2`, transaction id `1`, and descriptors in this exact order:

1. role `1 = SELF_ROOT_ADDRESS_REGION`;
2. role `2 = BOOTFS_MEMORY_OBJECT`.

It transfers exactly two handles in the same order as those descriptors. No additional payload or trailing bytes are valid.

`BOOTSTRAP_READY_V1` is exactly the 40-byte header, message type `2`, capability count `0`, transaction id echoed as `1`, no handles, and no trailing bytes.

Unknown magic/version/type/flags, nonzero reserved fields, wrong exact size, wrong role/count/order, duplicate role, unexpected handles, or trailing bytes fail closed.


### G0 golden wire vectors

The canonical payload bytes, excluding Channel handle metadata, are:

`BOOTSTRAP_INIT_V1` (56 bytes):

```text
57 52 42 50 01 00 00 00 01 00 00 00 00 00 00 00
38 00 00 00 02 00 00 00 01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
02 00 00 00 00 00 00 00
```

`BOOTSTRAP_READY_V1` (40 bytes):

```text
57 52 42 50 01 00 00 00 02 00 00 00 00 00 00 00
28 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
```

These vectors are shared test inputs. Changing either vector requires a coordinated G0/D0 contract revision; an implementation must not regenerate a different layout from local struct packing.

## 7. Exact initial capability set

The INIT transfer grants only:

1. `SELF_ROOT_ADDRESS_REGION`
   - object: `ADDRESS_REGION`
   - exact child rights: `MAP | MODIFY | INSPECT`
   - no `DUPLICATE`, `TRANSFER`, or unrelated rights
2. `BOOTFS_MEMORY_OBJECT`
   - object: `MEMORY_OBJECT`
   - exact child rights: `READ | MAP | INSPECT | DUPLICATE | TRANSFER`
   - no `WRITE` or `EXECUTE`

The root region needs both `MAP` and `MODIFY` because the existing `address_region_map` contract requires both on the target region. `INSPECT` permits explicit type/rights validation. Bootfs retains `DUPLICATE | TRANSFER` so primordial bootstrap can later delegate a reduced duplicate to `init0` without surrendering its own read-only view.

The kernel does not transfer a TaskGroup, Process, Thread, raw physical-memory capability, backing-grant identity, device authority, paging-handoff object, service registry, filesystem namespace, stdio handle, or hidden privileged object.

## 8. Ephemeral kernel bootstrap stager

G2 may use one bounded kernel-internal ephemeral HandleTable/stager to feed the real F-era Channel transfer machinery. It is not an ABI object, has no global name, has no userspace-visible handle table, and cannot persist after primordial handshake teardown.

The stager may temporarily own:

- a self-root handle with `MAP | MODIFY | INSPECT | TRANSFER`, moved into INIT with `MAP | MODIFY | INSPECT`; and
- a bootfs handle with `READ | MAP | INSPECT | DUPLICATE | TRANSFER`, moved into INIT with the same requested rights.

The extra source-only `TRANSFER` on self-root exists solely to use the ordinary F move transaction. It never reaches the child.

The INIT datagram must use the real F move/queue transaction. Rights can only be preserved or reduced. After commit the stager no longer owns either moved handle. Its teardown must deterministically release any remaining temporary owner/reference.

## 9. Capability validation expected from Wyrmroot

Deepwyrm's contract requires the paired bootstrap to validate, before mapping bootfs:

- one valid startup ABI version and the actual Channel from `RDI`;
- one exact INIT envelope with exactly two received handles;
- descriptor roles/order matching received-handle order;
- `DwReceivedHandleInfoV1` type and rights matching each role's exact contract;
- a fresh `DW_OBJECT_INFO_BASIC_V1` query on each received handle producing the same exact type and rights; and
- `DW_OBJECT_INFO_MEMORY_OBJECT_V1` on bootfs yielding a logical size in the WYR0-C accepted range.

A wrong-type or over-broad handle is rejected rather than accepted because it is "at least powerful enough".

## 10. Bootfs mapping and borrow lifetime

After validation, Wyrmroot maps bootfs through the received self-root `AddressRegion`:

- MemoryObject offset `0`;
- checked mapping length `align_up(byte_size, 4096)`;
- allocator-chosen address;
- protection exactly `READ`; and
- no write or execute transition.

The parser receives only `mapping[0..byte_size]`, never page-rounded padding. The mapping and source MemoryObject remain live and immutable for the complete lifetime of every `wyrmroot-bootfs` archive object or borrowed slice derived from it. Unmap, remap, protection change, or capability teardown waits until those borrows are dead.

The final-page padding is hardware-addressable because x86 maps pages, but it is zero-initialized and contains no unrelated bytes. It is never part of the logical bootfs archive.

## 11. Primordial construction transaction and rollback

G2 must preserve one failure-atomic construction boundary:

1. validate required BootInfo modules and the complete primordial ELF load plan;
2. reserve/prepare the root TaskGroup relationship, Process, root `AddressRegion`, segment backing/mappings, guarded stack, startup bytes, Channel pair, bootfs MemoryObject, stager handles, and initial Thread resources without making the Thread runnable;
3. enqueue the capability-bearing INIT datagram into the unpublished child's endpoint through the ordinary F transfer transaction;
4. commit Process/root-region hierarchy publication only after all recoverable allocations/reservations are complete; and
5. make the initial Thread runnable as the final no-fail publication action.

No recoverable error may occur after the first externally observable commit. A queued INIT inside an otherwise unpublished child is not externally observable.

Any failure before the initial Thread becomes runnable must leave no discoverable primordial Process, Thread, root region, mapping, stack/context allocation, Channel endpoint, queued transfer token, stager handle, or leaked boot-module MemoryObject reference. Queue drain must release any handle-transfer references already committed internally.

Once the Thread is runnable, the operation is no longer rollback-capable. Later user faults, peer closure, protocol failure, or explicit termination use the existing structured task lifecycle and normal teardown/reaping mechanisms.

## 12. Completion and diagnostic boundary

The G success sequence is:

```text
Deepwyrm sends INIT
    -> Wyrmroot validates capabilities and bootfs, including `system/init0` and `bin/hello`
    -> Wyrmroot sends READY
    -> Wyrmroot calls process_exit(0)
    -> Deepwyrm observes NORMAL_EXIT/application_code=0
```

A peer close before valid READY, malformed READY, `UNHANDLED_EXCEPTION`, explicit termination, or any nonzero normal application exit is a G failure.

F Channel semantics preserve a committed READY even if the child closes/exits immediately afterward, so Deepwyrm may consume the queued READY before final handshake disposition.

Production correctness depends only on the real loader/BootInfo path, native Channel handshake, capabilities, and structured task exit. Serial traces, test-build QEMU exit ports, test selectors, and extra diagnostic markers may report what happened after the kernel observes those facts, but the Wyrmroot bootstrap must not require them and they do not define stdio/TTY/service ABI.

## 13. Threat-question disposition

- **Wrong capability role/type:** exact role order/count, receive metadata, fresh object-info queries, and exact-right equality prevent role confusion and reject over-broad handles.
- **Partial Process/capability publication:** prepare/reserve work precedes publication; INIT is queued only inside an unpublished child; Thread runnable publication is the final no-fail step.
- **Bootfs tail disclosure:** loader allocation slack is zeroed, Deepwyrm preserves zero tail, size introspection returns exact logical bytes, and Wyrmroot parses only that exact slice.
- **ELF overlap after rounding:** G1 compares page-rounded load ranges, not only raw file/memory extents.
- **W+X or executable stack:** W+X load segments fail; user stack is fixed RW/NX; executable `PT_GNU_STACK` fails.
- **Rights escalation:** F transfer accepts only a subset of rights actually owned by the stager, and the child validates exact expected masks.
- **Failed-bootstrap residue:** every pre-runnable reservation/queue/mapping/object has an explicit cancellation/drain owner; after runnable publication ordinary task teardown owns cleanup.

## 14. Required tests opened by this contract

G1/G2 must add tests for at least:

- all accepted/rejected ELF forms and numeric limits above;
- page-rounded overlap, BSS/tail zeroing, W^X, NX stack, and entry containment;
- exact startup stack bytes, 16-byte `RSP`, and RDI/RSI startup values;
- child bootstrap handle opacity/nonconstancy across fresh Process tables;
- exact child Channel/root/bootfs rights and no undeclared startup authority;
- INIT golden bytes plus exact role/handle ordering;
- every construction/preparation/publication failure point with complete rollback;
- transfer rights monotonicity and stager teardown; and
- READY/normal-exit ordering, peer-close, malformed READY, exception, and nonzero-exit failure cases.

Cross-repository tests must compare the same INIT/READY golden byte vectors rather than maintaining two hand-written interpretations.

## 15. G0 closure

G0 is closed when this contract and the paired WYR0-D0 contract are committed against an exact compatible revision pair and their shared constants/layouts agree mechanically.

G0 closure is architecture evidence only. It does not claim the ELF parser, primordial transaction, Wyrmroot runtime/protocol implementation, native Rust target, VM path, or G security gate is implemented or accepted.
