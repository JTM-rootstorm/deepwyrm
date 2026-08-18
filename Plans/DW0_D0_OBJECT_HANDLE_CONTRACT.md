# Deepwyrm DW0-D0 Object and Handle Contract

**Status:** DW0-D0 contract closure; authoritative for DW0-D implementation
**Deepwyrm baseline:** `4fb6e1fad9f32b8b48ff09ed4bc2b5422c2dba52`
**Wyrmroot read-only review baseline:** `5678ebaf1bb16f56c2d635d1a7507d1dd7888de3`
**Milestone:** DW0-D kernel object and handle core

This contract closes the architecture decisions required before DW0-D code is
written. It refines the canonical DW0 plan without expanding the phase into
tasks, syscall entry, IPC, primordial launch, Wyrmroot implementation, or Rust
toolchain work.

The current Deepwyrm baseline differs from the DW0-D coordinator planning
baseline `9d3c53573604b0a75bd03d79da20b5ba4c199a83` only in repository licensing
and documentation. No kernel, ABI, memory, tooling, or test implementation
changed underneath this contract.

This record is not the DW0-D security gate. Exact-candidate Daybreak review and
remediation remain DW0-D7 work.

## 1. Rights compatibility is canonical ABI data

DW0-D1 will add `abi/schema/object_rights.toml` as the canonical object/right
compatibility relation. Kernel-private copies of this policy are forbidden.
The generator must emit the known-rights mask and per-object compatible-rights
masks/helpers for Rust, C, and generated documentation.

The ABI-0 matrix is:

| Object type | Compatible functional rights | Common compatible rights |
|---|---|---|
| `TASK_GROUP` | `MODIFY` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `PROCESS` | `WAIT`, `MODIFY` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `THREAD` | `EXECUTE`, `WAIT`, `MODIFY` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `MEMORY_OBJECT` | `READ`, `WRITE`, `EXECUTE`, `MAP` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `ADDRESS_REGION` | `MAP`, `MODIFY` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `CHANNEL` | `READ`, `WRITE`, `WAIT` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `EVENT` | `WAIT`, `SIGNAL` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `TIMER` | `WAIT`, `MODIFY` | `DUPLICATE`, `TRANSFER`, `INSPECT` |
| `NONE` and reserved object types | none | none |

The matrix was checked against every current typed object/right requirement in
`abi/schema/syscalls.toml`. Generic `ANY` operations do not make a right
compatible with every object: for example, `wait_one` accepts any handle but
only objects whose compatibility mask includes `WAIT` can possess `WAIT`.

Requested-rights validation uses generated data and rejects:

1. zero when the operation requires nonzero rights;
2. unknown bits;
3. rights incompatible with the resolved object type; and
4. escalation beyond authority already held when an operation derives rights
   from an existing handle.

## 2. Validation order is dependency-aware

There is no global status-precedence list that evaluates object-dependent facts
before resolving an object. DW0-D service operations use this order:

1. validate context-free scalar/flag/right syntax;
2. resolve the caller-local handle when one is consumed;
3. validate object-dependent compatibility, required type, and authority;
4. reserve bounded resources;
5. commit only after all fallible validation and reservation succeeds.

Context-free malformed input returns `INVALID_ARGUMENT`. Zero, malformed,
out-of-range, absent, or stale handles return `BAD_HANDLE`. A valid handle with
an operation-incompatible type returns `WRONG_OBJECT_TYPE`; insufficient held
authority returns `ACCESS_DENIED`; bounded capacity/refcount exhaustion returns
`NO_RESOURCES` unless an existing ABI operation specifies a more specific
resource status.

`handle_duplicate` is fixed to: validate nonzero/known requested rights, resolve
the source, validate object compatibility, require `DUPLICATE`, require an
equal-or-reduced subset, reserve destination capacity, retain the destination
reference, then publish the new handle. Every failure leaves source state,
destination publication state, and reference counts unchanged.

`object_get_info_v1` is fixed to: resolve handle, require `INSPECT`, recognize
topic, verify topic/object compatibility, then construct the typed result. This
prevents topic/type probing through that API when `INSPECT` is absent.

## 3. `ObjectRegistry` is the sole liveness authority

DW0-D uses one fixed-capacity generic `ObjectRegistry`. Subsystem registries may
own payload metadata, local keys, mapping records, and backing state, but may
not maintain an independent strong-liveness/refcount decision.

Conceptually each generic slot is one of:

```text
Vacant -> Live -> Finalizing -> Vacant
                         `----> Retired
```

`ObjectId` is opaque, non-pointer, and generation stamped. No kernel address is
encoded in or derivable from it. A slot is not reusable until final subsystem
cleanup completes. If advancing a slot generation would wrap or reach the
invalid generation, that slot is permanently retired rather than allowing ABA
identity reuse.

Every live object has checked strong-reference accounting divided into two
diagnostic ownership classes:

- **handle references**: exactly one per published handle-table entry;
- **internal references**: transient lookup pins and committed subsystem
  lifetime pins, including mapping leases.

Both classes participate in one total liveness decision. Neither may wrap,
underflow, saturate silently, or be reconstructed from an object ID.

Strong references are move-only tokens minted and released only through the
registry. Copying an `ObjectId` never creates authority or lifetime ownership.

The transition to zero total references atomically retires the live object from
new lookup/retain operations and yields one consuming typed final-release token.
Finalization is exact-once. Recoverable/user-triggerable failure is forbidden
after the final-release transaction commits; invariant corruption follows the
kernel bug/fail-stop policy.

Subsystem cleanup runs after handle-table ownership is released and outside any
future lock whose retention could permit destructor reentrancy or lock
inversion. Cleanup completion returns the generic slot to reusable `Vacant`
state only when its next generation remains representable; otherwise it becomes
`Retired`.

Object creation must never publish a zero-reference live slot. Construction
therefore begins with one move-only unpublished strong reference or equivalent
creation token, which is consumed by first-handle installation or another
explicit internal owner. Failed publication releases it normally.

## 4. Handles are caller-table-local capabilities

`DwHandle` remains an opaque `u64`; only zero is ABI-visible as invalid. The
private DW0-D encoding contains a slot/index plus nonzero generation sufficient
to reject stale reuse. Exact bit allocation is not ABI and is deliberately not
locked here.

Two process-local tables may emit the same raw numeric handle while referring
to different objects. Correctness must not depend on global uniqueness, a table
cookie, or authenticating another process's table domain from the raw value.
Only the selected caller-local table gives a handle number meaning.

Each live handle entry owns exactly one move-only generic handle reference plus
the generated object type and held `DwRights`. Lookup may mint a temporary
internal strong pin only after slot/generation validation and while the handle
entry remains stable. Closing invalidates the entry exactly once before its
handle reference is released.

Handle-slot generation exhaustion fails closed and permanently retires that
slot. Malformed, out-of-range, absent, zero, and stale encodings all resolve as
`BAD_HANDLE`; no case falls back to a pointer, object ID, or another table.

The table remains independent of `Process` in DW0-D. DW0-E will embed/own it in
a process and provide synchronization without changing these semantics.

## 5. `MemoryObject` finalization preserves typed backing authority

The current DW0-C `MemoryObjectAuthority` consumes an `ObjectBackingGrant` but
retains only identity/address metadata after successful creation. DW0-D must
change that: allocator-owned object payload state retains the original move-only
typed backing-release authority, or an equally strong typed token produced from
it, until final object cleanup.

Raw physical addresses, `BackingIdentity`, or copied metadata are never
sufficient to reconstruct reclamation authority.

For allocator-owned backing, final cleanup consumes the preserved typed token
through the `FrameRoleManager` object-backing cancellation/reclamation path.
For immutable boot-module backing, final object release is logical only: those
external immutable pages are not returned to the dynamic allocator.

`MemoryObjectAuthority` may retain payload records only as subsystem state bound
to a generic object identity. Record presence is not a second answer to whether
the object is live. Generic final release removes/consumes the payload through
a typed adapter and produces the backing-cleanup token; subsystem cleanup may
not independently free an object while generic references remain or keep one
live after generic final release.

Every committed mapping lease owns one generic internal strong reference to its
`MemoryObject`. Closing the final handle therefore prevents new handle-derived
authorization immediately but does not invalidate existing committed mappings.
Backing remains alive until the final mapping/internal reference is released.

No raw pointer to `FrameRoleManager` is stored in a `MemoryObject` merely to make
finalization convenient. The final-release path hands typed cleanup authority
back to the memory/frame-role owner explicitly.

## 6. Mapping authorization is a move-only strong proof

DW0-D replaces the temporary unsafe DW0-C handle-rights seam with a safe,
unforgeable `MapAuthorization` minted only after successful caller-local handle
resolution and validation of:

- object type `MEMORY_OBJECT`;
- `MAP` plus `READ`;
- `WRITE` when writable mapping authority is requested;
- `EXECUTE` when executable mapping authority is requested; and
- the object payload's protection ceiling.

The authorization owns a generic internal strong pin before any mapping
publication begins and is bound to the selected address space/region and the
captured READ/WRITE/EXECUTE ceiling. It is non-`Copy` and move-only.

For a new map, failure drops the authorization and releases its pin. Successful
publication transfers that exact pin into the committed mapping lease. The
implementation must not publish first and attempt a lifetime increment later.
Closing the source handle after authorization creation cannot invalidate the
already-held proof.

Protect/unmap replacement needs one stronger rule because one existing mapping
lease may split into multiple replacement leases. Reference accounting is
therefore transactional per object.

Preparation follows these rules:

1. old committed leases retain their existing internal references until
   publication succeeds;
2. preparation computes the old-to-new lease-count delta for each object;
3. any positive delta is retained before publication, and failure releases
   those temporary extra pins;
4. after successful publication, existing old-lease pins are transferred to as
   many replacement leases as possible, prepared extra pins satisfy any
   positive delta, and surplus old pins are released after commit; and
5. at every externally observable point, each committed lease owns exactly one
   internal reference.

Failed map/protect/unmap transactions therefore leave generic reference counts
and committed mappings unchanged. Successful split/merge operations neither
leak nor transiently under-pin object backing.

Captured mapping authority remains bounded by the source handle's rights at the
time it was minted. A reduced-rights duplicate can mint only a correspondingly
reduced authorization. Existing committed mappings retain their already
captured ceiling after the source handle closes.

## 7. Transaction boundaries and future lock order

DW0-D may serialize mutation with explicit `&mut` ownership instead of adding a
production spinlock. The semantic order that later locking must preserve is:

1. validate and reserve handle-table state;
2. retain the generic object reference while the table entry is stable;
3. publish/invalidate the table entry;
4. release handle-table ownership;
5. perform final registry transition and subsystem cleanup outside the table.

A future implementation may nest handle-table ownership around the narrow
registry retain/release operation, but must not call subsystem finalizers while
holding the handle table. Code requiring the reverse acquisition order must be
redesigned rather than creating a lock-order cycle.

Linearization points are:

- lookup: successful acquisition of the strong lookup pin;
- close: handle entry invalidation;
- duplicate: destination handle publication;
- map authorization: successful creation of the move-only pinned proof;
- mapping lifetime transfer: successful mapping publication followed by the
  infallible prepared lease/reference commit; and
- final destruction: registry transition from live to finalizing.

DW0-E/F/H must re-review these points once process ownership, real SMP-visible
synchronization, cross-process transfer, and teardown exist. Those later reviews
may strengthen locking but may not change D's capability semantics silently.

## 8. D service operations own business semantics

DW0-D implements syscall-independent service operations for `handle_close`,
`handle_duplicate`, and `object_get_info_v1`. They consume kernel values and
return kernel values/results only; they never dereference userspace pointers.

`handle_close` requires possession only. Success invalidates the table entry
exactly once. Object release/finalization follows after table ownership is
released, and a last handle close does not finalize while internal references
remain.

`handle_duplicate` follows section 2 and can only preserve or reduce rights.
Destination capacity is reserved before publication. No failure may create a
partial handle or alter the source handle.

`object_get_info_v1` implements basic handle metadata and MemoryObject logical
size in D. Task-state topic plumbing remains reserved until DW0-E creates task
objects; D must not fake task state.

DW0-E owns syscall entry/return, argument decoding, user-pointer validation,
copyin/copyout, output sizes/sentinels, and `BAD_ADDRESS`. Its handlers must be
near-mechanical adapters around D services and must not fork the validation,
rights, type, lifetime, or status-precedence rules recorded here.

## 9. Wyrmroot preservation review

Read-only review against Wyrmroot revision
`5678ebaf1bb16f56c2d635d1a7507d1dd7888de3` found no downstream contract
conflict. Its current `toolchain/versions.toml` still pins signed Deepwyrm
`b424d7d89d9acc57ceff8d966c3931e26a51f614`; DW0-D1 ABI changes will therefore
require a later explicit consumer repin rather than changing Wyrmroot in D0.

This contract preserves Wyrmroot's required properties:

- handles are opaque, process-local, nonpersistent capabilities;
- equal raw values in different tables need not identify the same object;
- future transfer creates receiver-local handles and can only preserve/reduce
  rights;
- payload plus transferred handles can later commit atomically in DW0-F;
- startup authority is delegated explicitly rather than through magic global
  handles;
- bootfs can be supplied as a `MEMORY_OBJECT` handle without `WRITE` authority,
  while its immutable payload ceiling independently prevents writable mapping;
- bootfs consumers can receive `READ`/`MAP` and only the additional delegation
  or inspection rights deliberately selected by the bootstrap path;
- committed mappings retain captured authority after the source handle closes;
- structured native introspection remains gated by `INSPECT`; and
- no POSIX fd, UID-0, `/proc`, `/dev`, universal `ioctl`, or ambient-root
  semantics enter the native object core.

No Wyrmroot source change is required by D0.

## 10. D0 disposition

DW0-D0 is closed for implementation when this contract is committed with no
unresolved contradiction against the canonical Deepwyrm/Wyrmroot documents.
The following decisions are now fixed for D1-D6:

- `object_rights.toml` is the canonical compatibility source;
- validation is dependency-aware and operation ordering is explicit;
- `ObjectRegistry` is the sole strong-liveness authority;
- strong references are move-only and checked;
- handle identity is process/table local with slot/generation stale defense;
- generation exhaustion retires slots permanently;
- finalization is exact-once and runs outside handle-table ownership;
- allocator-backed MemoryObjects preserve typed reclamation authority;
- immutable boot-module backing is never returned to the dynamic allocator;
- every committed mapping lease owns one generic internal reference;
- mapping authorization owns a strong pin before publication;
- split/merge replacement reference deltas are prepared transactionally;
- DW0-E adapts D service logic rather than reimplementing it; and
- Wyrmroot transfer/bootstrap requirements remain representable.

This D0 disposition authorizes architecture-consistent DW0-D1 implementation.
It does not claim D1-D6 implementation, a VM result, DW0-D host/core completion,
or the later Daybreak security gate.