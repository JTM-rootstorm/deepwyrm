# Deepwyrm DW0-H0 SMP and Concurrency Contract

**Status:** DW0-H0 architecture closure; authoritative for DW0-H implementation  
**Prepared:** 2026-08-22  
**Deepwyrm baseline:** `cbc27fd4d09378ff0dee04e3dd66da6763e7083d`  
**Paired Wyrmroot baseline:** `1b091043762fbb1aff65ce8ea5ef855d99fb4de3`  
**Paired contract:** `wyrmroot/Plans/WYR0_E0_USERSPACE_PROCESS_LOADING_CONTRACT.md`  
**Milestone:** DW0-H cooperative SMP and WYR0 userspace-loader enablement

This contract removes the single-BSP ownership assumptions that DW0-E through
DW0-G deliberately left for H. It refines the D0/E0/F0/G0 contracts without
adding ordinary scheduler preemption, a scheduler-policy ABI, or a
filesystem-aware kernel execution operation.

The baseline hashes are pre-contract design inputs. The OS-Project coordination
plan binds the final compatible Deepwyrm/Wyrmroot contract commit pair after both
independent repositories commit their side of H0.

## 1. H0 disposition: no public kernel ABI addition

The generated ABI already supplies the generic objects and operations needed by
the paired userspace loader: TaskGroup, Process, Thread, MemoryObject,
AddressRegion, Channel, handle duplication/transfer, waits, structured task
state, and mapping protection. H0 adds no syscall, object type, right, signal,
status, process-by-path shortcut, or scheduler-policy promise.

The public `deepwyrm-syscall` consumer crate does not yet provide typed wrappers
for every implemented generated operation. H implementation may add wrappers
for existing generated calls, but the generated IDs, records, rights, and
kernel semantics remain the authority. A wrapper gap is not a missing kernel
primitive.

One capability-distribution gap is real: the G0 primordial child receives no
TaskGroup handle, while generated `process_create` requires an authorized
TaskGroup carrying `MODIFY`. The H canonical chain therefore delegates one
existing TaskGroup capability to primordial bootstrap through the ordinary F
Channel-transfer mechanism. Section 13 pins that coordinated G0 refinement. It
does not add ambient authority or a new ABI operation.

## 2. CPU identity and canonical topology

`CpuIndex` is an architecture-private, bounded logical index. It is never a
userspace ABI value and its storage width does not become a stable promise.

- logical CPU index `0` is always the processor that entered `kernel_main` and
  whose `IA32_APIC_BASE.BSP` bit is set;
- every online CPU has exactly one firmware Local APIC ID and every accepted
  Local APIC ID maps to exactly one logical index;
- the BSP's live xAPIC ID must match exactly one enabled MADT Processor Local
  APIC record and that record maps to index `0`;
- accepted AP records are sorted by unsigned Local APIC ID, then assigned
  indices `1..`; firmware entry order does not select scheduler identity; and
- the implementation bound must be at least four CPUs. CPUs beyond the bound
  make topology intake fail explicitly; they are not silently omitted from an
  otherwise successful SMP claim.

The `default` profile requires exactly the live BSP and remains the canonical
one-vCPU regression path. The `smp` profile requires four enabled xAPIC CPUs,
indices `0..=3`, and all four must reach the online barrier for H acceptance.

Diagnostics identify both logical index and firmware Local APIC ID. A raw APIC
ID is not used as an array index, and CPUID leaf values are not treated as a
stable logical CPU identity.

## 3. MADT intake and rejection

H1 consumes the MADT only after the existing RSDP/XSDT/SDT length, containment,
and checksum validation succeeds. MADT-specific intake is bounded and uses
checked arithmetic for the fixed header, every variable entry, and table end.

DW0-H accepts:

- one MADT with a valid ACPI SDT header and a usable 32-bit Local APIC MMIO
  address;
- Processor Local APIC entries (type `0`) whose record length is exact for the
  fields consumed; and
- unknown entry types only when their declared length is at least the common
  entry header and remains wholly inside the validated table. They are skipped
  as unsupported, not interpreted.

The complete topology is rejected for any of the following:

- truncated headers or entries, zero/undersized entry length, length overflow,
  trailing partial bytes, or a checksum/containment failure;
- more than one MADT selected by the established ACPI-table policy;
- duplicate Local APIC IDs among Processor Local APIC records, including a
  duplicate split between enabled and disabled records;
- duplicate ACPI processor UIDs that describe contradictory processors;
- an enabled x2APIC processor entry or another enabled processor form that DW0-H
  cannot start through xAPIC;
- a missing, disabled, duplicated, or live-ID-mismatched BSP record;
- an enabled Local APIC ID outside the xAPIC destination-ID range; or
- enabled CPU count zero or greater than the implementation bound.

A type-0 record with the enabled flag clear is recorded only for duplicate and
contradiction checks, then excluded from the runnable topology. The ACPI
online-capable flag does not authorize DW0 hotplug: a processor that is not
enabled at boot is not started during H. Disabled entries therefore do not
consume logical CPU indices or satisfy a requested profile count.

The MADT PC-AT compatibility flag may direct the existing legacy-PIC masking
path but does not alter CPU identity. MADT Local APIC address override entries
are rejected in DW0-H if they select an address that cannot be represented and
validated by the established xAPIC MMIO path. x2APIC remains out of DW0-H.

## 4. CPU lifecycle and publication

Each accepted CPU slot moves monotonically through bounded internal states:

```text
Discovered -> Starting -> Online -> Parked/Executing -> Stopping -> Offline
```

AP failure before `Online` records a stable reason and cannot be mistaken for a
usable CPU. APs publish fully initialized private architecture state with a
Release operation; the BSP observes online state with Acquire before releasing
the shared H1 barrier. No AP may enter the shared userspace scheduler before H2
has installed the SMP-safe runtime and scheduler representation.

The canonical four-vCPU profile fails rather than degrading to fewer CPUs.
Bounded startup timeout is diagnostic failure, not permission to reuse an AP's
bootstrap data or stack while it may still execute.

## 5. Exact per-CPU state

Every online CPU owns a distinct instance of all state below. No two CPUs may
name the same writable storage or guarded stack range:

1. runtime GDT, TSS, and loaded GDTR/TR state;
2. double-fault, NMI, and machine-check IST stacks and their guard pages;
3. CPL3 privilege-entry/SYSCALL entry stack and guard;
4. terminal-reaper stack and guard;
5. `PerCpuEntryState`, including current kernel-stack top, binding generation,
   and staged user return fields;
6. the `IA32_GS_BASE`/`IA32_KERNEL_GS_BASE` state that selects that entry record;
7. physical execution carrier: logical current Thread, active or suspended
   kernel continuation identity, current Process/root, and idle state;
8. Local APIC controller state, local APIC ID, EOI/error state, and local timer
   state;
9. address-space residency/shootdown mailbox and acknowledged generations; and
10. diagnostic logical CPU index plus firmware Local APIC ID.

The Local APIC MMIO page and immutable IDT contents may be shared mappings. The
GDT/TSS objects, ISTs, entry/reaper stacks, entry record, execution carrier,
mailboxes, and mutable Local APIC software state may not be shared.

The current Thread's ordinary kernel stack remains Thread-owned rather than
CPU-owned. It may move only while that Thread is not Running and after the old
CPU has acknowledged a safe suspension. CPU-owned entry and reaper stacks never
migrate with a Thread.

## 6. BSP bootstrap-to-runtime transition

The existing linker/static BSP descriptor, IST, privilege-entry, reaper, entry,
and one-shot `BootstrapStorage` objects remain legal only while:

- the BSP is the sole executing CPU;
- interrupts and entry paths obey their existing early contracts; and
- no AP has been released from its private bootstrap stack.

H1 may use those objects to reach the allocation/runtime-construction point, but
it must construct the complete bounded per-CPU array, copy or re-establish the
BSP's architectural facts into slot `0`, load slot `0`'s runtime GDT/TSS and GS
entry state, validate the installed values, and retire the early aliases before
AP release. After that transition, every architecture/current-CPU lookup,
including on the BSP, resolves through the runtime CPU slot.

Early writable storage must not remain as a second live alias to slot `0`.
Linker-owned early stacks may be left mapped for diagnostics only when no live
entry path can select them; they are not runtime fallbacks.

## 7. Cooperative multi-CPU scheduler invariants

DW0-H retains one shared FIFO runnable policy and cooperative scheduling. Its
representation must enforce:

- each CPU owns zero or one Running Thread;
- each Thread is Running on zero or one CPU;
- Reserved, Runnable, Running, Blocked, and terminal ownership are mutually
  exclusive for one Thread generation;
- claiming Runnable work and publishing Running ownership is one serialized
  state transition that records the claiming CPU;
- yielding or blocking validates both Thread identity and calling CPU;
- `pending_block`, the physically active/suspended continuation, and every wake
  token are generation- and CPU-aware; and
- terminal Threads cannot return to Runnable, even when a stale remote wake or
  IPI is delivered later.

A running user Thread remains on its CPU until it voluntarily yields/blocks,
terminates/faults, or a correctness rendezvous stops it. Enqueueing work does
not displace a running Thread. An idle CPU atomically claims the oldest eligible
Runnable Thread. A wake IPI only makes an idle/halted CPU rescan; it is not a
time slice and carries no priority, affinity, fairness, or migration promise.

The scheduler/execution lock is never held across usercopy, a wait/deadline
registration callback, context-switch assembly, user return, or terminal
reaper handoff.

## 8. Internal interrupt-vector assignments

The H vector layout is fixed for DW0:

| Vector | Owner | Purpose |
|---:|---|---|
| `0xe0` | Local APIC timer | designated timer-service CPU deadline/maintenance |
| `0xe1` | SMP rendezvous | idle wake and bounded stop/observe rendezvous |
| `0xe2` | TLB shootdown | address-space invalidation request/ack |
| `0xfe` | Local APIC error | existing error path |
| `0xff` | Local APIC spurious | existing spurious path |

`0xe1` uses mailbox state to distinguish a harmless idle wake from a required
rendezvous. Coalescing is permitted only when every requested generation is
still acknowledged. `0xe2` is not shared with generic rendezvous so TLB
completion cannot be inferred from an unrelated acknowledgement.

Both IPI handlers are bounded, perform no usercopy or object finalization, and
acknowledge the Local APIC. They may publish an acknowledgement or force the
current CPU into an already prepared safe state. They do not choose ordinary
scheduler policy. No H implementation may allocate another vector that
collides with the table above.

## 9. Address-space residency and TLB ordering

Every live user root owns a synchronized residency set and monotonically
nonzero shootdown generation.

Before loading a Process root into CR3, a CPU publishes itself resident with
Release ordering while the root is still pinned against teardown. The
transition protocol must make it impossible for mapping mutation to snapshot a
set that omits a CPU which can subsequently use the old mappings. After
switching away and completing the required local serialization, the CPU clears
residency with Release ordering.

For unmap, protection reduction, page-table removal, or teardown:

1. hold the mapping/root transaction authority and finish page-table writes;
2. publish a new shootdown generation with Release ordering;
3. snapshot the resident targets, including the initiating CPU when relevant;
4. perform the local invalidation and send vector `0xe2` to remote targets;
5. each target acquires the request, invalidates the named root/range or performs
   the contract-approved full local flush, then Release-publishes acknowledgement;
6. the initiator Acquire-observes every required acknowledgement; and only then
7. return the mutation, release mapping leases, reclaim page-table pages, or
   permit physical backing reuse.

Joining residency while a mutation is in flight must either observe the new
page tables and generation before CR3 use or join the target set and
acknowledge. Timeout is a kernel correctness failure and never permits reclaim.
An offline CPU must have proven it holds no root residency before its slot can
be excluded.

## 10. Remote terminal-stop and reclamation

Logical task termination may mark a remote Running Thread terminal, but it may
not reclaim that Thread's stack, continuation slot, task pins, Process root, or
address-space backing until its owner CPU reaches a safe point.

The terminator publishes a generation-bound stop request and sends vector
`0xe1`. The target enters with its CPU-owned entry state, prevents return to the
terminal user context, saves or abandons the Thread continuation according to
the execution-domain contract, removes its Running/residency ownership, and
Release-acknowledges from a CPU-owned safe stack. Only an Acquire-observed
acknowledgement permits terminal reaping.

Races between exit, exception, close, wait, wake, process-wide termination, and
remote stop retain the existing single terminal winner and generation rules.
A stale acknowledgement cannot satisfy a newer stop generation. The initiating
CPU may help with deferred finalization only after all required CPU and TLB
acknowledgements are complete.

## 11. DW0-H time and idle model

Logical CPU `0`, initially the BSP, is the sole timer-service CPU for DW0-H. It
owns Local APIC one-shot deadline programming, PM-timer wrap maintenance, and
advancement of the synchronized global monotonic/deadline authority.

Every AP initializes its own Local APIC for IPI, error, and spurious delivery,
but its Local APIC timer remains masked with initial count zero. AP timer
vectors do not drive scheduler decisions or local deadline queues.

Channel, Event, Timer, deadline, terminal, or atomic wake activity on any CPU
may publish Runnable work. If an eligible CPU is idle, the publisher sends or
coalesces vector `0xe1`; the target rechecks under scheduler synchronization
before `hlt` and after wake. The existing wait-registration/block-commit winner
rules remain authoritative, so a wake between registration and physical
suspension is not lost.

Changing the designated timer-service CPU, adding per-CPU scheduler timers, or
using timer interrupts for ordinary involuntary scheduling is outside DW0-H.

## 12. Synchronization, publication, and lock order

H preserves the D0/E0/F0 semantic orders and adopts these SMP rules:

1. interrupts are disabled locally before acquiring an IRQ-shared lock and the
   prior IF state is restored only after release;
2. no NMI, double-fault, or machine-check path takes an ordinary or IRQ-shared
   runtime lock;
3. subsystem locks are non-nested by default. Scheduler/execution, TaskAuthority,
   Wait/Timer/Channel state, Process HandleTable, ObjectRegistry finalization,
   address-space mapping, residency/shootdown, and per-CPU mailbox ownership are
   acquired and released in phases;
4. the sole standing nested exception remains D0's narrow HandleTable-to-registry
   retain/release operation; it never invokes a subsystem finalizer;
5. an F10-style cross-subsystem observation/transaction guard may cover a
   prepare/no-fail-commit sequence, but component locks beneath it are acquired
   sequentially, never nested;
6. mapping mutation precedes shootdown publication; shootdown acknowledgement
   precedes mapping-lease release and reclamation;
7. scheduler Running removal precedes remote-stop acknowledgement; stop and TLB
   acknowledgement precede task/root reclamation; and
8. no lock or exclusive shared-runtime borrow spans usercopy, blocking,
   context-switch assembly, `sti; hlt`, user return, terminal handoff, or a
   callback able to reacquire the same subsystem.

Code that requires a reverse acquisition or nested component-lock cycle must be
split into validate/reserve, no-fail commit, and deferred cleanup phases. Lock
order may not define user-visible queue order, wait winners, rights, or task
termination semantics.

The raw `UnsafeCell<u64>` continuation slots are replaced by atomic storage or
by storage whose scheduler/execution lock proves a single reader/writer and an
explicit Release-to-Acquire handoff. Volatile access is not inter-CPU
synchronization.

The single published `Pin<&mut R>` syscall runtime is not extended to APs. H2
must place shared runtime state in stationary storage with interior
synchronization and give each CPU an exclusive execution carrier, or provide an
equivalent ownership proof. No entry path may manufacture overlapping mutable
references to shared runtime state.

## 13. Paired primordial capability refinement

G0 `BOOTSTRAP_INIT_V1` and its two-capability golden vector remain the accepted
DW0-G regression protocol. The canonical H userspace-loader chain uses
`BOOTSTRAP_INIT_V2`, encoded by the paired Wyrmroot E0 contract:

1. self root AddressRegion: exact `MAP | MODIFY | INSPECT`;
2. immutable bootfs MemoryObject: exact
   `READ | MAP | INSPECT | DUPLICATE | TRANSFER`; and
3. loader TaskGroup: exact `MODIFY | INSPECT | DUPLICATE | TRANSFER`.

Deepwyrm creates or selects a TaskGroup already owned beneath the established
primordial hierarchy and stages a handle to it through the same ephemeral
stager and F move transaction used for the other INIT capabilities. It grants
no root/global TaskGroup magic handle and no implicit self lookup. The extra
source-only transfer authority follows the existing G0 staging rule.

The bootstrap uses this capability only as the explicit `task_group` argument
to generated process construction and to create reduced duplicates for its
authorized descendant loader. It does not imply scheduler priority, resource
budget, service-manager status, or authority over ancestors/siblings.

## 14. H0 closure and implementation gates

H0 closes when this contract and the paired Wyrmroot E0 contract are committed
as a named compatible pair and review confirms:

- the generated ABI already expresses every required operation;
- the only G0 refinement is explicit TaskGroup capability distribution through
  existing objects and transfer semantics;
- CPU identity, per-CPU state, IPI vectors, timer ownership, rendezvous,
  shootdown, publication, and lock rules are explicit; and
- no ordinary preemption, load balancing, affinity, real-time policy, or kernel
  executable-path primitive entered H.

H1 may then implement topology/AP substrate, and WYR0-E may add consumer
wrappers/parser/layout work. No AP enters shared userspace scheduling until H2,
and no executable child becomes runnable until the paired loader transaction's
final `thread_start` commit.
