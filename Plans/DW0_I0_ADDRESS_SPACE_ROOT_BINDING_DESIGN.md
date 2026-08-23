# DW0-I0 Exact Address-Space Root Binding Design

**Status:** Implemented foundation; carrier and process-creation integration follows in the serial I0 runtime lane  
**Repository:** `JTM-rootstorm/deepwyrm`  
**Authority refined:** `DW0_H0_SMP_CONCURRENCY_CONTRACT.md` sections 5 and 9

## 1. Problem and scope

The first live runtime used one BSP PML4 for every `ProcessKey` supplied to its
usercopy and address-region publisher helpers. An `AddressSpaceKey` was checked
only against the portable region authority domain; it did not mechanically
select a distinct architecture root. Two processes could therefore ask to map
the same user virtual address and mutate the same low-half hierarchy.

I0 replaces that shortcut with a bounded architecture registry. One entry
binds exactly:

- one authority-issued `AddressSpaceKey`;
- one owning `ProcessKey`;
- one committed PML4 `TableIdentity`; and
- one `PageTableRoot` storage class plus its H0 residency domain.

Duplicate keys, duplicate Processes, mismatched PML4 frames/identities, and
publisher requests whose key differs from the bound key are rejected. This is
kernel-private architecture state; it adds no public ABI or personality policy.

## 2. Primordial and child ownership

The already active primordial root remains linearly owned by
`ActiveDeepPaging`. Its registry entry is an explicit `Primordial` marker and
borrows that root; it does not manufacture a second root owner. Every child
gets a newly allocated, zeroed, child-owner PML4 and an owned `PageTableRoot` in
the registry. Its low 256 PML4 entries begin zero, so independent children may
map the same user VA, including an ET_EXEC base at `0x400000`, without sharing
or overwriting a user hierarchy.

## 3. Typed shared kernel half

The active root's upper 256 PML4 entries are captured once through the
authenticated scratch target into `KernelHalfBinding`. Capture validates the
source as the exact committed primordial PML4 and rejects user or huge-page
bits in every upper entry. Child-root initialization atomically copies only
those 256 entries into the new PML4.

This is a typed, lifetime-pinned borrow of the primordial kernel half, not a
second frame-role parent claim:

- upper-entry descendants retain their existing primordial `TableOwnerKey`
  and role-parent graph;
- no descendant is relabeled, duplicated, or registered as child-owned;
- `KernelHalfBinding` lives with the root registry and therefore cannot outlive
  the primordial paging owner;
- child low-half page-table candidates use only the child's distinct owner;
- ordinary user mapping policy accepts only canonical user-half pages; and
- child teardown never walks, clears, or reclaims PML4 indices 256 through 511
  or any primordial-owned descendant reachable through them.

An empty child root may be reclaimed only after its residency domain has
retired and the role manager proves no child-owned lower-level table remains.
A child that still has a low-half hierarchy must first have that hierarchy
removed by the serialized mapping/teardown lane; failure is conservative and
retains the root.

## 4. Root construction and rollback

Child reservation preflights binding capacity and duplicate identity before
allocating. It then creates a distinct table owner, allocates and zeroes one
frame through the active scratch mapping, prepares a PML4 candidate, installs
the typed kernel half, commits the table role, constructs the root token, and
publishes the binding.

Every recoverable failure before table commit cancels the exact allocation,
zeroed grant, or candidate grant. Binding publication is fully preflighted
before commit; a rejection after the PML4 role becomes live is therefore an
invariant violation and fails stopped rather than attempting to reclaim a
possibly active root. A committed PML4 cannot be reclaimed while it has a
role-tracked child table.

## 5. Selection, residency, and usercopy

Selection takes the exact `(CpuIndex, ProcessKey, AddressSpaceKey)` tuple.
Preparation Release-publishes residency in the selected root before CR3. Before
the irreversible write, the commit path verifies both binding identities, both
live residency generations, the previous-root leave precondition, same-CPU
pairing, and that the sealed architecture target reports that same CPU as the
physical current CPU. It then performs one CR3 load (a local full flush and
serialization under the current no-PCID/no-global-pages profile) and
Release-clears the old root's residency through an infallible-by-construction
post-write path. The move-only, non-`Send`, non-`Sync` active token carries the
exact Process, key, frame, identity, CPU, and residency across the next switch.
An unused prepared selection has an explicit abandonment path so failed carrier
setup does not leak residency.

Usercopy and address-region publication resolve the root through the same
Process binding. Runtime usercopy construction additionally requires the
CPU-owned active-root token and checks its Process, key, live residency,
physical current CPU, and the actual CR3 frame before any raw user VA is
dereferenced. The live publisher rejects any portable `AddressSpaceKey`
different from that resolved binding before entering the unsafe architecture
bridge.

## 6. Teardown boundary

Teardown is fail-closed:

1. the zero-resident check and teardown-gate closure occur atomically under the
   coherency lock, so a racing resident is rejected without publishing a
   teardown phase and the operation remains retryable after that CPU leaves;
2. primordial storage cannot be reclaimed through the child path;
3. the role manager issues a move-only empty-root grant while exclusively
   borrowed, rejecting any role-tracked low-half descendant before retirement;
4. the H0 teardown mutation gate is prepared, published, acknowledged, and
   retired; and
5. the sealed unsafe commit consumes the grant and returns the frame, with any
   post-retirement role drift treated as an invariant failure rather than a
   recoverable error.

The later I0 carrier/process-finalization integration must serialize removal of
the child's low-half mappings and tables before calling the empty-root teardown
operation. It must never treat the shared upper half as part of that reclaim
walk.

## 7. Focused evidence

Host models cover real journals and publishers mapping the same `0x400000` VA
through two roots to different leaf frames, key/root mismatch rejection,
`A -> B -> A` selection with exact identity and residency ordering, target and
token CPU mismatch before CR3, stale/missing prior bindings before CR3,
observed-CR3 usercopy rejection, supervisor-only upper-half copy with an
untouched child low half, allocation/root rollback and reclaim, retryable
nonempty-root teardown rejection, and resident-root teardown rejection. The
freestanding warning-clean primordial target build exercises the integrated
primordial binding and exact-root usercopy construction.
