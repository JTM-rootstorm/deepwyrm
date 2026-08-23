# DW0-I1 Kernel Execution Root Design

**Status:** Implemented D2 foundation and BSP safe-point path; I1 carrier/AP execution join remains incomplete
**Authority refined:** `DW0_H0_SMP_CONCURRENCY_CONTRACT.md` sections 5, 9, 10, and 12; `DW0_I0_ADDRESS_SPACE_ROOT_BINDING_DESIGN.md`

## Purpose

Each fixed runtime CPU slot owns one permanently retained, architecture-private
PML4 used only for kernel safe-point and reaper execution.  It gives a stopped
carrier somewhere valid to run after it has left a Process root, including the
primordial Process, without treating the primordial root as a universal
fallback.

## Shape and ownership

For every fixed CPU slot, construction allocates and commits one distinct PML4
with a distinct table owner.  Its low 256 entries are zeroed and remain zero.
The typed `KernelHalfBinding` captured from the active kernel root copies the
upper 256 supervisor-only entries.  The execution root has no `ProcessKey`,
`AddressSpaceKey`, user publisher, usercopy session, residency domain, teardown
path, or ordinary reclamation path.  It is retained for the lifetime of its
CPU slot and cannot be selected by normal process/root APIs.

The root is therefore neither a synthetic portable address space nor a hidden
primordial Process alias.  Its owner/root identity is architecture-private and
distinct per CPU; no two live slots may share a PML4 or table-owner identity.

Every Process binding also carries a registry-owned monotonically nonzero
epoch. It is assigned only on successful binding publication, never reused
after unbind/rebind, and is carried by prepared/active selection tokens. Stop
publication derives its root generation only from that active token; counter
exhaustion fails closed.

## Selection protocol

`Process -> Kernel` first preflights the exact active Process selection and the
target CPU.  The sealed switch loads the CPU's execution-root PML4 with the
existing full local CR3 flush/serialization.  Only after that write may the
old Process residency token be Release-cleared.  The carrier retains the
execution-root token as CPU-private state.

`Kernel -> Process` first prepares the selected Process root, thereby
Release-publishing its residency.  It validates that the carrier owns its
matching execution root, loads the Process PML4 with the same full local
serialization, then Release-clears the execution-root selection.  Failure
before CR3 returns every move-only Process token unchanged; failure after CR3
is an invariant failure and does not resume a mixed root identity.

## Remote-stop use

Vector `0xe1` only latches work after EOI.  The real per-CPU carrier consumes
the latch on its safe/reaper path.  Its precommit verifies exact CPU, Thread,
execution generation, Process-root generation, CPU-private safe stack,
a released CPU-private native-usercopy window, and prevented user return.  It then switches to the
slot's kernel execution root, releases the Process residency and scheduler
Running claim in H0 order, and consumes the move-only exact-safe witness to
Release-publish acknowledgement.  Deferred Thread/root/stack reclamation
remains forbidden until the initiator Acquire-observes that acknowledgement.

The BSP safe-point path now uses this root before releasing the stopped
Process residency and Running claim, publishes the witness-only
acknowledgement, clears its CPU-local retired continuation slot after ACK, and
then either selects another Runnable Thread or idles on the retained kernel
root. Late duplicate `HoldSafe` notifications remain on that root and do not
return the stopped frame or publish a second acknowledgement. Pending completed
syscall releases are transferred to the post-ACK continuation before the
irreversible stop transition and finalized only there. The idle-suspend loop
uses the same handoff both for a pre-halt rescan and after `sti; hlt` returns:
it finishes the exact idle generation, consumes the latch, stages the exact
request, and diverges to the reaper rather than halting or returning the
suspended frame.

No AP release, e2 shootdown completion, or initiator/reclaim live gate is
implied by this design. Those remaining carrier publication and delivery gates
must be complete before AP userspace execution is enabled.

## Required evidence

Host tests cover distinct construction/owners, zero low halves, typed copied
kernel halves, exclusion from Process APIs and reclamation, both switch
directions with pre-CR3 token recovery, and stop acknowledgement ordering.
The freestanding build covers the architecture-private implementation without
claiming AP userspace activation.
