# DW0-I1 Per-CPU Scratch Window Design

**Status:** Approved pre-AP carrier substrate
**Authority refined:** `DW0_H0_SMP_CONCURRENCY_CONTRACT.md` sections 5, 7, 9,
and 12; `DW0_I0_ADDRESS_SPACE_ROOT_BINDING_DESIGN.md`; `DW0_I1_KERNEL_EXECUTION_ROOT_DESIGN.md`

## Purpose

The initial Deep root used one transient scratch leaf.  That leaf is reachable
through the typed copied kernel half, so sharing it between fixed CPU carriers
would allow one CPU to retarget another CPU's active scratch window.  I1
instead reserves one disjoint three-page window per fixed `CpuIndex`:

1. an initially empty transient mapping leaf;
2. a read/write/NX control alias of the shared scratch PT; and
3. two initially empty permanent MMIO leaves.

The four windows occupy distinct PTE indexes in the existing scratch PT.  Each
window's two permanent MMIO leaves are distinct as well. They
therefore need no process-specific PML4 entries and no new upper-level
subtree: every Process root and retained kernel execution root receives the
same typed kernel-half mapping, while CPU-local selection chooses only that
CPU's leaf/control pair.

## Ownership and sessions

The committed scratch-PT table identity and the four immutable virtual-slot
descriptors are stationary architecture metadata.  A `ScratchBinding` is
derived only from a fixed `CpuIndex`; it is not an address-space or process
token.  A live `ScratchSession` is move-only, names exactly one binding and is
held only while its leaf maps a physical frame.  It invalidates locally after
install and again after clearing.  A second session on the same CPU rejects
before mapping; a cross-CPU or stale binding rejects before touching a leaf.

The four control aliases intentionally map the same physical PT. They never
produce `&mut [u64; 512]`, a page reference, or another whole-table mutable
alias. A binding accesses only its proven-disjoint leaf through an aligned
atomic/volatile PTE-cell operation; pre-publication graph construction is the
only whole-table mutation phase, and post-publication whole-table inspection
requires every carrier quiescent.

The design independently applies the general temporary-mapping lessons of
Linux's documented CPU-local local mappings and the Intel paging-invalidation
rule: the running carrier is CPU-pinned/non-migratable while a leaf is live,
interrupt/reaper paths never reuse that slot, and each atomic leaf install and
clear has a local `invlpg`. This is conceptual provenance only; no Linux or
BSD source is imported or adapted.

No scheduler, object, address-space, or usercopy guard may contain a live
scratch session.  Frame-role and root metadata preparation may be briefly
serialized, but a carrier retains only its CPU-local session while it performs
the mapped operation.

## Mapping and migration rules

All slots are present and empty/control-attested before Process or kernel-root
publication.  Process root migration does not edit its PML4 or copied kernel
half.  On the destination CPU it selects the destination slot and therefore a
different leaf/control address.  The old CPU must have dropped its session
before suspension/release.  Kernel execution roots expose the identical four
slot addresses, but no CPU may select another slot.

AP execution release and e2 functionality remain outside this change.

## Permanent MMIO leaves

The first permanent MMIO leaf is retained by the xAPIC owner. The second is
reserved for the one validated q35 IOAPIC controller admitted by DW1-E2A. Both
are kernel-only, writable, NX, PWT/PCD UC mappings. The transient scratch leaf
may perform a bounded probe of an ACPI-proposed controller before a controller
is selected, but it is cleared before returning and never exports a pointer.
Only the selected controller obtains a permanent leaf. No Process, resource
handle, or userspace mapping reaches either leaf.

## Required evidence

Host models prove CPU0 and CPU1 can install and clear independent frames,
cannot reuse a live leaf on one CPU, and reject cross-CPU/stale bindings.
Graph/source tests prove each Process and retained kernel root sees all four
reserved slots, while runtime selection is indexed by current `CpuIndex`.
