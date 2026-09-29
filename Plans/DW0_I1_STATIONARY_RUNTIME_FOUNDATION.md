# DW0-I1 Stationary Runtime Foundation

**Status:** superseded on 2026-09-28 by
[`DW1_S2K_RUNTIME_AUTHORITY_DESIGN.md`](DW1_S2K_RUNTIME_AUTHORITY_DESIGN.md),
which Mike approved that day. Kept as the historical record of the staged
foundation; it is no longer authority for runtime-authority work.

**Correction:** this document's original status line said "AP execution
remains parked". That stopped being true at `83856db` (2026-08-23, "Release
APs into the live cooperative runtime"), which released the APs into ordinary
userspace execution through the coarse `RuntimeAuthorityLock`. DW1-C then
accepted four-vCPU scheduling (`docs/DW1_C_VALIDATION.md`). The paragraphs
below describe the tree before that release.

**What the S2K design decides about this foundation** (its §4.1):

- `RuntimeCore` and `PagingAuthority` are replaced, not resumed. They and
  `RuntimeCoreState`, `ThreadServiceSlots`, `PerCpuStaging` and
  `StationaryGuardDepth` were never instantiated outside their own tests, and
  the S2K steps delete them.
- `RuntimePhaseReservation`, the non-escaping closure discipline and the
  non-nesting idea survive; the non-nesting idea becomes a compile-time
  guard-free token.
- The three unfinished steps listed at the end of this document are carried
  by the S2K design's D1 (lock decomposition and owned adapter payloads), D3
  (owned paging transaction) and D2 (terminal engine).

The existing primordial adapter owns `Registry`, `Memory`, `Tasks`, `Spaces`,
and `Regions` as plain mutable fields. Moving that adapter wholesale behind a
single IRQ lock would violate H0: its syscall and terminal methods synchronously
perform usercopy, wait/timer work, CR3 transitions, reaper handoff, and idle
operations. This checkpoint therefore introduces the storage and proof shape
without manufacturing a broad runtime guard.

`RuntimeCore` owns the five non-paging authorities under an IRQ-safe lock and
offers only short non-escaping `prepare`/`commit` closures. `PagingAuthority`
has the same closure boundary for frame roles, root bindings, coherency, and
scratch metadata. Their shared depth witness rejects nesting and must be clear
before usercopy, a blocking callback, context switch, user return, reaper,
idle, or e2 acknowledgement wait.

`ThreadServiceSlots` keeps F-service continuation state by exact `ThreadKey`,
not CPU, so migration cannot move or duplicate service ownership. A move-only
lease rejects after its exact slot is released. `PerCpuStaging` uses a distinct
IRQ-safe buffer for each fixed `CpuIndex`.

The target-side construction now initializes four stationary
`PerCpuLiveCarrier` cells before the BSP binds any parked AP callback. AP
callbacks remain reject-only. The BSP's primordial carrier references slot zero
and checks its CPU identity, but it continues to own its active root and live
adapter fields until the following split is complete.

The first BSP adapter split now carries a move-only `RuntimePhaseReservation`
from prepare through guard-free work and revalidates its exact `ThreadKey` and
active-root binding generation before return. `map_memory` and `unmap_memory`
also use a move-only `PreparedAddressRegionMutation`: lookup/reservation is
complete before target-root selection and publisher work, and commit
revalidates the exact process/region/address-space/region-key tuple. Terminal
and remote-stop entry points assert that no stationary guard reached their
external/reaper boundary. These reservations contain no user pointers, paging
publisher, scratch session, or lock guard.

F-service dispatch now has the same explicit identity seam:
`PreparedFServiceDispatch` captures the decoded request plus exact current
`ThreadKey` and root-binding generation and validates before adapter/usercopy
work. The enclosing native `RuntimePhaseReservation`, rather than copied
adapter arguments, performs the post-dispatch live revalidation. The
primordial and F12 target adapters supply the live binding generation; host
models use a fixed nonzero fixture generation. This is not yet a transfer of
the legacy authority fields into `RuntimeCore`.

The remaining required migration is intentionally explicit:

1. `NativeSyscallHandler::handle` and `handle_fallthrough` still borrow the
   legacy BSP authority fields during each adapter call. F-service adapters
   need per-operation owned prepare/commit payloads before `RuntimeCore` can
   become their live owner.
2. `map_memory` and `unmap_memory` now split delegated target preparation from
   publisher commit, but the map-model and table-candidate transaction still
   jointly borrow the legacy Registry/Memory/Tasks/Regions fields. It needs an
   owned paging transaction before `PagingAuthority` can own that commit side.
3. terminal cleanup and remote-stop paths have guard-free boundary checks, but
   still mix Tasks, Registry, F-service state, and deferred cleanup. They need
   an exact reaper transaction before either authority may be briefly acquired
   at its commit point.

No AP release, e2 acknowledgement, public ABI, or scheduler-policy change is
implied by this foundation.
(As staged. The AP release came separately at `83856db`; see the correction
at the top.)
