# DW0-I1 Stationary Runtime Foundation

**Status:** staged foundation; AP execution remains parked

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

The remaining required migration is intentionally explicit:

1. `NativeSyscallHandler::handle` and `handle_fallthrough` currently need
   Registry/Tasks/Regions/Spaces while they hold a live user-access object.
   They must become validate/reserve -> usercopy -> short commit phases.
2. `map_memory` and `unmap_memory` mix root publisher work with Registry,
   Memory, Tasks, and Regions. Their table-candidate and output-pin flows need
   explicit owned transactions before `PagingAuthority` can own the paging
   side.
3. terminal cleanup and remote-stop paths mix Tasks, Registry, F-service
   state, and deferred cleanup. They require an exact reaper transaction before
   either authority may be briefly acquired at its commit point.

No AP release, e2 acknowledgement, public ABI, or scheduler-policy change is
implied by this foundation.
