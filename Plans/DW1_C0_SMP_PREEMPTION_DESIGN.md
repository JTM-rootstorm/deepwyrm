# Deepwyrm DW1-C0 SMP Preemption and AP Carrier Design

**Status:** Reached design; authoritative for DW1-C1 through DW1-C5

**Prepared:** 2026-08-27

**Deepwyrm baseline:** `d891f27d45cc6f2825e7527f5f5cc3410a29d1da`

**Paired Wyrmroot checkout:** `020e8e58ed0ae9b6ef397fcfeccf0fcaa58677eb`

**Accepted WYR1-B product:** `a47f7bf7e03f378abdc884bb61bc6fabef5d1a78`

**Rust/toolchain:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` / `RUST-WYR0-I-B-SYSROOTS-007`
**Selector:** `normal-preemption-smp`, test ID `28`

This design turns the AP prerequisite in
`DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md` into a concrete current-tree
transition contract. It does not implement AP scheduling. It fixes what later
DW1-C slices must preserve while they turn the existing cooperative AP
userspace/idle/rendezvous carrier into an explicitly admitted normal-preemption
carrier, add one local scheduler deadline source per CPU, and admit the reached
placement and migration policy.

## 1. Authority, scope, and non-goals

`DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md` remains authoritative for scheduler
ownership, placement, migration, FIFO policy, the 5 ms quantum, deadline
identity, safe-boundary preemption, accounting, and validation. This document
does not redefine those semantics. `DW1_B0_TIMER_RETURN_PREEMPTION_DESIGN.md`
remains authoritative for the CPU0 timer-return frame and switch gate; DW1-C
generalizes its CPU identity without weakening it.

DW0-H/I remain authoritative for:

- logical CPU and Local APIC identity;
- CPU-private descriptor, entry, reaper, root, scratch, and mailbox ownership;
- Process-root residency and invalidation ordering;
- e1 remote-stop and e2 TLB acknowledgement identity;
- continuation, terminal, and reclamation ordering; and
- guard-free architecture transitions.

DW1-C adds no public ABI, scheduler class, priority, affinity operation,
reservation, hard latency promise, arbitrary kernel preemption, CPU hotplug,
x2APIC policy, general Timer-object service on APs, DeviceResource, Interrupt,
PIO, COM2, UART, console, stream, or shell behavior.

## 2. Execution preflight and current-tree reconciliation

The execution preflight established:

- the root coordination repository is clean at
  `39ba9fc1d6d54baab07fed00c72dc7bfecaf6728`;
- Deepwyrm is clean at the exact accepted WYR1-B product revision named above;
- Wyrmroot is clean at a documentation/validation descendant of accepted
  product `a47f7bf7e03f378abdc884bb61bc6fabef5d1a78`;
- Rust is clean at the exact accepted revision;
- the accepted `rustc`, Cargo, and `rust-lld` SHA-256 values are respectively
  `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70`,
  `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce`,
  and `38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721`;
- the accepted compiler reports `rustc 1.97.1-dev`, exact commit
  `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`, and LLVM `22.1.6`;
- selector IDs through 27 are allocated and selector 28 is unallocated in the
  current registry; and
- the canonical SMP profile remains q35, four vCPUs, 2048 MiB, and 180 seconds
  in `tooling/guest-harness.toml`. Wyrmroot remains the owner of OVMF media and
  the exact designated-VM request/run/receipt workflow.

The strict zero-lane audit found no registered lane worktrees. It also found
pre-existing unregistered `.tmp` and `artifacts` directories under the root
`.worktrees` tree. They are operator/build state, not DW1-C lanes, and were not
removed or treated as product evidence.

### 2.1 Current state is beyond the old parked-AP prose

The I1 design documents truthfully recorded their original implementation
boundary: AP execution and live e2 completion were then deferred. Current
Deepwyrm `main` has since advanced. The current source:

1. starts each AP and publishes private descriptor, GS-entry, and Local APIC
   state;
2. transitions the AP through `Online` to `Parked`;
3. constructs and Release-publishes a `PerCpuLiveCarrier` for every fixed CPU;
4. binds a CPU-branded `RuntimeCarrierFacade` while each AP is still Parked;
5. initializes the live TLB mailbox transport;
6. enables the AP idle-wake slot, releases its runtime binding, and moves the
   CPU registry to `Executing`; and
7. lets the AP enter the common idle scheduler and e1/e2 safe-point machinery.

Accordingly, DW1-C0 does not design AP startup or cooperative userspace
execution from scratch. Current APs can enter the shared scheduler, execute
ordinary CPL3 Threads, and return through the established carrier. What is
missing is one explicit generation-bound publication that joins the current
descriptor, runtime, CPU, wake, scheduler, root, scratch, and mailbox domains
before DW1-C placement and preemption treat the AP as admitted. Later
implementation must not cite the historical I1 parked-AP status as evidence
that the current cooperative path is absent.

## 3. Current lifecycle and transition inventory

The current lifecycle is:

```text
Offline -> Discovered -> Starting -> Online -> Parked -> Executing
```

`Stopping` and `Offline` enum values after execution have no live transition
implementation. DW1-C does not claim CPU offlining.

### 3.1 Discovery through Parked

The BSP owns topology and startup serialization. For each AP it performs:

```text
begin_start
  -> build and install one trampoline image
  -> INIT assert/deassert
  -> SIPI and bounded retry
  -> wait_until_parked
```

The AP entry validates the `Starting` state and exact Local APIC identity,
installs its private descriptor/GS-entry state, initializes its private Local
APIC controller with the timer masked, Release-publishes `Online`, transitions
to `Parked`, and spins until the CPU registry reaches `Executing`.

`Online` proves architectural initialization. `Parked` proves the AP has
reached the bounded holding loop. Neither state means that scheduler placement
may target the AP.

### 3.2 Parked through the current Executing idle carrier

The BSP constructs the shared scheduler/runtime and every fixed CPU-local
carrier before binding AP façades. Each AP façade is CPU-branded but points to
the same pinned `RuntimeAuthorityLock<PrimordialRuntimeCarrier>`. This coarse
lock is the current correctness bridge for shared legacy authorities; it does
not make carrier identity shared.

Current release uses three distinct publication domains:

- `RuntimeCpuDescriptorLifecycle`, for GDT/TSS/IDT and GS entry readiness;
- `RuntimeCarrierLifecycle`, for callback binding; and
- `CpuLifecycle`, for leaving the AP Parked loop.

The current code enables idle wake before both later lifecycle publications.
That is safe only because a wake is persistent and grants no Running
ownership. It is not the DW1-C schedulability publication order and must not be
used as one.

### 3.3 Idle, runnable delivery, and userspace execution

An Executing AP enters `RuntimeCarrierFacade::enter_idle_scheduler`. It asks the
shared `ExecutionDomain` for `schedule_next_on(cpu)`. A selected fresh Thread
uses the established first-run entry; a suspended Thread resumes its owned
continuation; no work enters the generation-bound idle prepare/commit/halt/
finish loop.

Runnable delivery publishes the target queue before it publishes an e1 Wake.
The e1 interrupt handler performs EOI and latches only CPU-local work. The
carrier safe point consumes the latch and rescans. The IPI never grants Running
ownership and a repeated or late Wake is harmless.

Syscall entry copies the transient privilege-entry frame onto the Thread-owned
kernel stack before Rust code may retain it. User return requires exact current
CPU, Thread, Process, execution generation, root selection, mapping, selector,
RFLAGS, and return-address validation. These rules already apply to an AP
carrier and remain mandatory when placement begins targeting APs.

### 3.4 Block, switch, stop, and reaper

The destination carrier completes a physical switch handoff only after its
incoming stack, root, and carrier identity are live. Only then may the outgoing
suspended continuation become acquirable. No shared runtime, scheduler,
paging, wait, scratch, or timer guard may survive the physical switch.

Terminal and e1 Stop paths pivot non-returningly to the current CPU's private
reaper stack. A Stop request is bound to exact CPU-online, Thread execution,
and root-binding generations. The target must establish a CPU-private safe
stack, disabled user access, and prevented user return before the irreversible
sequence:

```text
Process root -> retained CPU kernel root
  -> remove exact Running or suspended claim
  -> prove deferred cleanup quiescent
  -> Release-publish exact Stop acknowledgement
  -> initiator Acquire-observes acknowledgement
  -> reclaim
```

The direct mailbox poll and post-EOI latch poll cover different IF-clear race
windows and both remain required. e2 remains a separate mailbox and may
acknowledge only its exact invalidation generation after local serialization.

## 4. Exact current ownership map

| Concern | Current owner and DW1-C disposition |
| --- | --- |
| Retained kernel root | `ActiveDeepPaging::kernel_execution_roots` owns one move-only private root per fixed CPU. It has no Process, usercopy, residency, or teardown identity and never migrates. |
| TSS/RSP0 and entry stack | `RUNTIME_CPU_DESCRIPTOR_SLOTS[cpu]` owns the private TSS/GDT and installs RSP0 at that CPU's guarded privilege-entry stack. `ENTRY_STATE[cpu]` and GS identify the active record. |
| Per-CPU entry stack | The guarded `RuntimeCpuStackLayout::privilege_entry` span. A retained return frame must move to the Thread-owned stack before a switch. |
| Reaper stack and action | The guarded `terminal_reaper` span plus per-CPU `TERMINAL_ACTION` and `RENDEZVOUS_ACTION`. Assembly stack pivot and the move-only reaper entry are authoritative. `PerCpuCarrierLocal::reaper_staged` has no current writer and is not accepted as evidence until wired or removed. |
| Scratch | `PerCpuScratchBindings` owns one CPU-branded leaf/control pair. `ActiveScratchTarget` reattests the hardware-current CPU at each live access. `scratch_cpu` in the carrier is only a consistency check. Scratch sessions never migrate. |
| Current Thread/Process/root | The pinned shared runtime owns exact per-CPU arrays and the scheduler claims; `PerCpuLiveCarrier` is the physical CPU-local mirror. `switch_cpu` and `synchronize_scheduler_current` must agree with actual CR3/root residency before local publication. |
| e1 mailbox | `LIVE_IDLE_WAKE` owns one `RendezvousMailbox` and post-EOI latch per CPU. Wake, Stop, and HoldSafe retain distinct semantics. |
| e2 mailbox | `LIVE_TLB_MAILBOXES[cpu]` owns one exact request/ack slot per CPU, separate from e1. |
| Local APIC | `LOCAL_APIC_SLOTS[cpu]` owns one controller/MMIO binding. EOI is CPU-local and lock-free with respect to the mutable controller guard. |
| Scheduler deadline | CPU0 alone currently owns `LiveTimeState`, the unified wait/Timer/quantum arbiter, and hardware arm sequence. AP timers are masked. DW1-C2 must add one AP-local quantum-only state, not share CPU0 state. |
| Idle wake | `IdleWakeSet` owns the generation-bound `Active -> Preparing -> Halted -> Active` state. Wake publication precedes e1 send. |
| Return authorization | GS binding generation, copied Thread frame, exact scheduler/root binding, mapping validation, and the final assembly authorization bit jointly authorize return. |

CPU-private state never migrates with a Thread. A Thread continuation may move
only after the old CPU has acknowledged safe suspension, and then only the
Thread-owned continuation state moves.

## 5. Reached scheduler-capable publication contract

### 5.1 One authoritative predicate

`CpuLifecycle::Executing` is not by itself a schedulability predicate. DW1-C1
must add or expose one scheduler-owned, generation-bound carrier admission
state with these logical values:

```text
Unavailable -> Preparing -> CarrierReady -> Schedulable
                         \-> Failed
```

The representation is internal. It may extend an existing fixed scheduler CPU
slot; it must not create public CPU ABI. The `Schedulable` record names:

- exact `CpuIndex` and Local APIC ID;
- nonzero CPU-online generation;
- nonzero carrier-admission generation;
- validated immutable descriptor-slot and runtime-binding-slot identities plus
  their one-shot Online/Executing lifecycle states;
- scheduler queue/current-slot generation;
- retained kernel-root binding generation or immutable slot identity;
- validated immutable e1/e2 mailbox slot identities and ready states (with
  per-operation Stop/TLB generations remaining owned by those protocols); and
- a scheduler-owned wake-admission-ready bit sampled only after the fixed
  idle-wake slot is enabled.

The carrier-admission generation is minted once at `Preparing` and remains
unchanged through `CarrierReady` and `Schedulable`. It is distinct from the
transient idle-halt generation minted by `IdleWakeSet::prepare`; admission does
not invent an idle-wake generation that the current owner does not expose.

Placement, wake, stealing, migration, and evidence code must consult this
scheduler-owned state. No caller may infer eligibility from descriptor Online,
runtime-binding Executing, CPU lifecycle Executing, or idle-wake Active alone.

### 5.2 Exact Parked-to-Schedulable order

For each AP, while scheduler admission remains `Unavailable`, the BSP and AP
perform the following order:

1. BSP Acquire-validates the exact `Parked` CPU slot and nonzero online
   generation.
2. BSP validates that the descriptor/GS entry slot is Online and names the
   same CPU/APIC identity, private TSS/RSP0, entry stack, and reaper stack.
3. BSP validates the CPU's retained kernel root and CPU-branded scratch leaf,
   and that no Process/root/scratch session is active for the parked carrier.
4. BSP initializes the empty scheduler current/queue slot and publishes
   `Preparing`; the CPU is still excluded from all placement masks.
5. BSP validates the independent e1 and e2 mailbox slots and binds the exact
   `RuntimeCarrierFacade` in runtime state `Parked`.
6. BSP Release-publishes the runtime binding as `Executing`, then transitions
   `CpuLifecycle` to `Executing`. Idle wake is still not a scheduler target.
7. AP Acquire-observes both publications, enters its private carrier, verifies
   current GS CPU identity, TSS/RSP0, entry/reaper stack bounds, retained kernel
   root, scratch brand, empty current/queue slot, e1/e2 identity, runtime
   binding, and masked local scheduler timer. It does not call
   `schedule_next_on` or inspect ordinary runnable work in this admission path.
8. AP records CPU-local idle ownership and Release-publishes `CarrierReady` with
   the exact admission tuple, then Acquire-waits for `Schedulable`. It still
   cannot receive Runnable work.
9. BSP Acquire-observes that exact `CarrierReady`, then, with local interrupts
   masked and scheduler authority held, revalidates every element needed for
   the final transition and prepares the placement-mask update. Enabling the
   fixed idle-wake slot is the irreversible commit point. After it succeeds,
   only infallible in-memory operations remain: Release-publish `Schedulable`
   with wake-admission-ready set and add the CPU to the placement mask before
   dropping authority or restoring interrupts. No recoverable error branch is
   permitted between enable and publication; an invariant failure there is
   fail-stop before any queue ownership, timer unmask, or continued boot.
10. AP Acquire-observes `Schedulable` and enters the common idle scheduler.
    Only after step 9 may a queue transition select the AP; it publishes the
    queue target before sending e1, and a wake that arrives before step 10 is
    retained for the first rescan.

This AP-to-BSP `CarrierReady` acknowledgement is the missing join in the current
three-domain publication sequence. It prevents the BSP from advertising an AP
that has not actually acquired its private carrier.

The implementation supplies a dedicated AP admission function between the
current AP entry's observation of `CpuLifecycle::Executing` and
`enter_bound_idle_scheduler`. That function publishes `CarrierReady`, waits for
the matching `Schedulable` generation, and only then calls the common idle
scheduler. It may not fall through into `prepare_current_idle` while the
idle-wake owner is unavailable.

### 5.3 CPU0 normalization

CPU0 reaches admission from an already Running primordial carrier rather than
the AP parked path. Immediately after live e2 initialization and before any AP
release, the BSP must:

1. Acquire-validate CPU registry state `Online`, descriptor/GS entry state
   Online, exact BSP/APIC identity, private entry/reaper stacks, CPU0 scratch,
   and the already enabled CPU0 idle-wake slot;
2. under scheduler authority publish CPU0 `Preparing` with a nonzero admission
   generation while preserving its exact current primordial Running claim;
3. validate the current Thread/Process/execution generation, Thread-owned
   kernel stack, active Process root and residency, retained CPU0 kernel root,
   e1/e2 mailboxes, runtime/exception bindings, and CPU0 deadline arbiter;
4. Release-publish CPU0 `CarrierReady` from that exact Running tuple; and
5. under scheduler authority Release-publish CPU0 `Schedulable` with
   wake-admission-ready set.

CPU0 does not enter Parked, does not clear or recreate its Running claim, and
does not use the AP `RuntimeCarrierLifecycle` bind/release loop. If any tuple
element fails, AP release stops and the boot fails. From step 5 onward, CPU0
and AP placement code consult the same scheduler-owned `Schedulable` state.

### 5.4 Bring-up failure

Failure before architectural `Online` retains the existing stable AP failure
record. Any failure from `Online` through the final step-9 revalidation, before
the idle-wake commit point, latches `Failed` in the new scheduler admission
state and leaves the CPU absent from every placement mask. It must not enable
idle wake, accept queue ownership, or unmask its timer. Once idle wake has been
enabled there is no rollback path: the already-prepared `Schedulable` and mask
publication completes without a fallible operation, or the kernel fail-stops.

The canonical four-vCPU selector fails instead of degrading to three CPUs. A
default one-vCPU product never depends on absent APs. DW1-C does not attempt to
offline or recycle a partly released AP, reuse its bootstrap storage, or map
the unimplemented `Stopping`/`Offline` enum values onto recovery.

After `Schedulable`, a carrier-identity or scheduler-ownership invariant
failure is fail-stop and reboot-class. It is not converted into hot-unplug or
userspace status. Recovery code may report the exact first failure, but it may
not continue on a scheduler substrate whose unique ownership is untrusted.

## 6. Shared runtime authority and guard-free transitions

DW1-C accepts the existing coarse
`RuntimeAuthorityLock<PrimordialRuntimeCarrier>` as a temporary correctness
bridge. Completing the previously proposed `RuntimeCore`/`PagingAuthority`
split is not a prerequisite for four-vCPU correctness and lock splitting is
not admitted as speculative optimization.

This acceptance is conditional:

- per-CPU physical carrier, root, scratch, entry, reaper, APIC, mailbox, and
  scheduler identities remain distinct despite serialized shared mutation;
- no scheduler authority is held while acquiring the shared runtime or paging
  authority;
- the shared runtime guard is dropped before APIC MMIO, e1/e2 acknowledgement
  waits, idle entry, context-switch assembly, CR3 completion, reaper handoff,
  or userspace return;
- architecture preparation captures move-only exact identities under the
  necessary authority, drops all guards, performs the physical operation, and
  revalidates/commits afterward; and
- destination arrival completes the outgoing continuation publication only
  after the incoming stack/root/carrier is live.

Host/source-contract tests must name each divergent boundary and fail if the
coarse guard can span it. If implementation cannot satisfy this with the
current bridge, the dependent slice stops and reaches a narrower authority
revision; it must not hide the problem with unsafe aliases or longer-held
locks.

## 7. Queue, placement, wake, steal, and migration transitions

DW1-C retains one bounded IRQ-safe scheduler-state lock around all four logical
queues unless measurement later justifies a separate revision. Under that
authority:

1. one Thread generation occupies one scheduler state;
2. a CPU owns at most one Running claim;
3. a Thread generation is Running on at most one CPU;
4. a Running Thread appears in no queue;
5. a queued Thread appears exactly once;
6. terminal state is monotonic; and
7. every transition uses checked counters and exact generations.

Initial and wake placement order is unchanged:

1. required continuation CPU;
2. eligible online last CPU;
3. eligible online requesting CPU; and
4. lowest-index eligible online CPU.

Here, online and eligible means the scheduler-owned `Schedulable` predicate,
not the architecture lifecycle alone. Queue admission is the ownership
transition; CPU selection before lock/revalidation is only a proposal.

An idle CPU rescans locally, then performs one bounded cyclic victim scan. It
steals only the oldest eligible migratable entry from the first admissible
victim. Migration is one source-dequeue/target-enqueue transaction, preserves
FIFO age, advances a nonzero migration generation, and on any failed
revalidation leaves the Thread at the source exactly once.

Migration is rejected while the Thread is Running, block-preparing,
continuation-bound, execution- or scratch-pinned, root-switching,
stop/rendezvous-pending, terminal/reaper-bound, or otherwise not exactly
revalidatable. Neither e1 nor a timer interrupt can confer queue or Running
ownership.

## 8. Per-CPU quantum/deadline transition

DW1-C2 adds one scheduler-deadline owner per `Schedulable` CPU.

- CPU0 retains the existing unified wait, Timer-object, and scheduler-quantum
  sources and remains the only general Timer/wait service owner.
- Each AP receives only a scheduler-quantum logical source, source generation,
  physical-arm generation, bounded outcome scratch, and local APIC one-shot
  ownership.
- AP state is selected from the hardware-current GS CPU identity. An AP never
  uses `BSP_TIMER_SERVICE` to arm or cancel its scheduler quantum.
- Vector `0xe0` EOI and source dispatch are CPU-local. The handler validates
  CPU, Thread, execution generation, source generation, physical arm
  generation, and deadline before publishing `need_resched`.
- AP timer hardware remains masked until the AP is `Schedulable`, its quantum
  state is initialized, the handler can resolve that exact state, and a first
  dispatch supplies a valid ticket.
- A stale vector performs bounded reconciliation only. It cannot clear a later
  ticket or affect another CPU's deadline source.
- The interrupt requests scheduling; it never switches. The existing complete
  160-byte CPL3 timer frame, Thread-stack copy, return validation, precedence,
  and guard-free switch rules apply on every CPU.

The AP quantum path must not acquire or mutate CPU0's general deadline queues.
Independent CPU0-through-CPU3 arm, expire, cancel, rearm, immediate-due, and
cross-CPU stale-ticket tests precede live use.

## 9. Selector 28 structured evidence contract

The current selector registry reserves:

```toml
[guest_test.normal-preemption-smp]
id = 28
state = "reserved"
```

The reservation becomes `implemented` only with the selector-specialized
kernel dispatch and host verifier. Selector 28 reserves test-private raw
operation `0xFFFF_FF1C`, absent from the generated ABI and production kernels.
It does not reuse selectors 25, 26, or 27.

### 9.1 Build and transport binding

The selector build requires `DEEPWYRM_DW1C_EVIDENCE_NONCE` as a nonzero
16-uppercase-hex build nonce, `DEEPWYRM_DW1C_PROGRESS_DIGEST` as a nonzero
16-uppercase-hex progress challenge digest, and
`DEEPWYRM_DW1C_BOOTFS_MAX_PAGES` as the exact measured selector-local bootfs
page ceiling in canonical decimal `1..=8192`. Wyrmroot product tooling
binds the exact source, accepted ABI, toolchain, payload, bootfs, ESP, OVMF,
request, run, and receipt hashes. Deepwyrm independently joins the transcript
to canonical `DWTEST1` test ID 28/detail zero and the matching QEMU debug-exit
status. Serial text without that host-observed join is never acceptance.

The kernel collector, not a child, observes scheduler transitions, CPU
ownership, quantum/preemption, migration, terminal/reap, and accounting. A
child may submit bounded workload progress only after the kernel has bound its
exact Process and Thread generations. A forged `DW1C` record or a
different Process using the private operation latches failure.

The selector-private collector is installed before the primordial controller
returns to userspace. Its fixed ten-entry task-transition table records exact
Process creation and first-Thread start keys/generations for later ARM
correlation; it is not populated from controller claims. Overflow, a second
Thread, or an actor created before collector installation fails the selector.
`CPU_READY` is the sole pre-install relation: carrier admission retains it
before the selector process exists, while actor, ARM, raw-operation, and
workload facts cannot satisfy the collector before installation.

### 9.2 Raw operation and reporter authority

`0xFFFF_FF1C` accepts exactly three argument forms:

```text
ARM:
    arg0 = 1
    arg1 = userspace address of ten ActorBindV1 entries
    arg2 = 10
    arg3 = 240
    arg4 = 0
    arg5 = 0

PROGRESS:
    arg0 = 2
    arg1 = actor token in 1..=5
    arg2 = nonzero bounded progress count
    arg3 = build-owned progress challenge digest
    arg4 = 0
    arg5 = 0

WORKLOAD_COMPLETE:
    arg0 = 3
    arg1 = 0x1f
    arg2 = build-owned progress challenge digest
    arg3 = 0
    arg4 = 0
    arg5 = 0
```

One `ActorBindV1` is exactly three little-endian `u64` values: actor token,
role code, and Process handle. The ten entries are in token order `1..=10`,
have the exact role codes below, and contain ten distinct live Process handles.
ARM is accepted once from the exact committed primordial first child/controller
used by the selector. Reporter authority is checked before usercopy and again
before commit. The kernel resolves each Process handle through ordinary typed
inspection with `INSPECT`, requires exactly one started live Thread in each
Process, records the exact ProcessKey, ThreadKey, and execution generation, and
rejects a terminal, unstarted, multiply threaded, duplicated, or wrong-role
subject. Tokens 9 and 10 are both created and started after collector
installation but before ARM. ARM must join their handles to the collector's
exact CREATE and START observations; the fixed workload then drives their exit
and reap in token order.

A committed Runnable Thread retains one private, nonzero started-execution
generation until its first Running claim consumes it. Placement, wake, steal,
and transactional migration preserve that identity; later dispatches mint
fresh execution generations as before. This is an internal scheduler invariant,
not a userspace query or ABI field.

ARM borrows handles for inspection. It does not MOVE, duplicate, close, retain,
or otherwise change controller ownership. The collector retains only exact
generation-safe keys/tokens, not object pins that would prevent later exit or
reap. Failed usercopy or validation leaves handle ownership unchanged and
publishes no partial actor map.

PROGRESS is accepted once per token 1..5, only from the exact bound Process for
that token, with the matching live execution generation and frozen digest. The
count is bounded by the selector request and cannot replace kernel-observed RUN,
QUANTUM, PREEMPT, migration, terminal, or accounting facts.

WORKLOAD_COMPLETE is accepted once from the exact ARM controller only after
all five PROGRESS submissions. Its mask and digest are correlation and workload
intent only; they prove none of the five bits. The paired Wyrmroot product/model
fixes the workload construction, while Deepwyrm sets each `RACE_MATRIX` bit only
from the independently observed joins in section 9.4.

Malformed arguments, an early/late/replayed operation, wrong caller, wrong
digest, wrong count, wrong role/token/order, invalid handle, non-distinct
subject, stale execution, or partial ARM latches selector failure. None of the
three forms enters the public ABI.

### 9.3 Fixed transcript

The selector uses a kernel-originated `DW1C` stream modeled on the current
fixed `WRB1` framing. One record is exactly 96 bytes with no newline:

```text
DW1C|01|NNNNNNNNNNNNNNNN|SSSSSSSS|EE|OOOOOOOOOOOOOOOO|GGGGGGGGGGGGGGGG|VVVVVVVVVVVVVVVV|CCCCCCCC
```

The fields are the nonzero build nonce, zero-based sequence, event, nonzero
selector-local subject token where required, exact event generation, event
value, and uppercase FNV-1a-32 over bytes `0..88`. The checksum occupies bytes
`88..96`. Record length, offsets, uppercase syntax, delimiters, version, nonce,
sequence, event, subject, generation, value, checksum, order, and cardinality
are kernel- and host-validated.

`ProcessKey`, `ThreadKey`, and internal object IDs have no public raw encoding.
The record therefore uses request-manifest actor tokens. The kernel collector
binds each token to the exact internal Process, Thread, and execution
generation and validates every later event against that private map. No child
may choose or reinterpret an actor token after binding, and the transcript
does not create a public object-ID format.

The frozen workload has ten actor tokens and exact role codes:

| Token | Role code | Role |
| ---: | ---: | --- |
| 1 | `0x01` | uncooperative CPU hog |
| 2 | `0x02` | CPU-bound actor 2 |
| 3 | `0x03` | CPU-bound actor 3 |
| 4 | `0x04` | CPU-bound actor 4 |
| 5 | `0x05` | CPU-bound actor 5 |
| 6 | `0x06` | mixed blocking/progress actor |
| 7 | `0x07` | Channel backpressure actor |
| 8 | `0x08` | termination-versus-quantum actor |
| 9 | `0x09` | first create/start/exit/reap actor |
| 10 | `0x0a` | second create/start/exit/reap actor |

The transcript contains exactly 46 records in this order, immediately followed
by canonical `DWTEST1` test ID 28/detail zero:

| Sequence | Event | Cardinality | Exact relation |
| ---: | --- | ---: | --- |
| 0..3 | `01 CPU_READY` | 4 | CPU order 0..3. Subject packs `CpuIndex + 1` in the high 32 bits and Local APIC ID in the low 32 bits; generation is the CPU-online generation; value is the nonzero carrier-admission generation. |
| 4..13 | `02 ACTOR_BIND` | 10 | Subject is actor token 1..10; generation is the exact execution generation; value is the exact role code above. The collector privately binds exact Process/Thread keys. |
| 14..17 | `03 RUN` | 4 | CPU order 0..3. Subject is one bound actor token, generation matches its exact execution, and value is the CPU index. The collector observes the Running claim, not child text. |
| 18..21 | `04 QUANTUM` | 4 | CPU order 0..3. Subject/generation identify the exact Running actor; value is the CPU-local nonzero quantum arm generation observed to expire. |
| 22..25 | `05 PREEMPT` | 4 | CPU order 0..3. Subject/generation identify the exact outgoing Running actor; value is the nonzero completed-switch generation joined to that CPU's quantum event. |
| 26..30 | `06 PROGRESS` | 5 | Actor token order 1..5. Generation matches the binding; value is a nonzero bounded progress count obtained through the fixed workload protocol. |
| 31..34 | `07 REMOTE_WAKE` | 4 | Target CPU order 0..3. Subject is the exact actor woken; generation matches its execution; value packs target CPU in bits 0..7, source CPU in bits 8..15, and a nonzero 48-bit wake generation in bits 16..63. An unrepresentable generation fails the selector. |
| 35 | `08 STEAL_MIGRATE` | 1 | Subject/generation identify the stolen actor and nonzero migration generation; value packs distinct source and target CPUs in bits 8..15 and 0..7. All other bits are zero. |
| 36 | `09 MIGRATION_REJECT` | 1 | Subject/generation identify the rejected token-6 actor; value packs CPU in bits 0..7 and required reason `0x04 EXECUTION_PINNED` in bits 8..15. All other bits are zero. |
| 37 | `0A RACE_MATRIX` | 1 | Subject is token 8; generation matches; value is exact fact mask `0x1f` for mixed blocking/progress, Channel backpressure, termination-versus-expiry, repeated lifecycle, and bounded completion. |
| 38..39 | `0B EXIT` | 2 | Actor Process token order 9..10; generation is the exact terminal Thread generation sampled from the authoritative caller, which may be another member of that Process; value is normal exit code zero. |
| 40..41 | `0C REAP` | 2 | Actor token order 9..10; generation matches the reaped Process generation privately joined at bind/exit; value is exact reap count one. |
| 42 | `0D READY_DELAY` | 1 | Subject is a nonzero scheduler snapshot token; generation is its nonzero snapshot generation; value is maximum ready-to-run delay in ns. |
| 43 | `0E BOOTSTRAP_NORMAL` | 1 | Subject is the primordial completion token; generation is the exact terminal product execution generation sampled from its deferred current claim; value is zero only at genuine normal bootstrap completion. |
| 44 | `0F ACCOUNTING_SOUND` | 1 | Subject is the scheduler snapshot token; generation matches record 42; value is exact fact mask `0x3f` for no overflow, no underflow/regression, no duplicate Running, no Running-plus-queued, no duplicate queue entry, and no terminal runnable identity. |
| 45 | `FF TERMINAL` | 1 | Subject, generation, and value are all zero. It atomically claims terminal authority only after every prior relation succeeds. |

The kernel may observe additional diagnostic transitions internally, but it
retains only one exact relation needed for each fixed record. The table is the
terminal serialization order, not a chronological scheduler trace and not
permission to infer a later fact early. Actor Process and Thread identities are
each unique in the ARM table; a Thread cannot name two actor tokens. For
each CPU, the collector normally first buffers a bounded RUN candidate,
advances it with an exact same-identity QUANTUM, and commits all three fixed
RUN/QUANTUM/PREEMPT records atomically only after the matching involuntary
switch completes. ARM is concurrent with the other CPUs: an actor may already
be Running, or dispatch between its generation sample and the ARM commit,
before a separate RUN callback can be observed. Each CPU therefore has one
ARM-boundary allowance for its first scheduler-validated published quantum to
establish that exact current Thread/generation. The scheduler accepts that
ticket only while the same claim is still current, so this is a retained kernel
fact rather than an inference from userspace. The allowance closes after that
quantum or any observed RUN; later missing-RUN transitions remain failures. A
later RUN may replace an incomplete RUN candidate. Every scheduler transition
that consumes a published expiry without an involuntary switch explicitly
resolves that live QUANTUM chain. No-peer retention republishes the exact
unchanged Thread/generation as RUN because the scheduler proves it remained
current and may rearm it without another dispatch. Voluntary yield/block and
ordinary terminal cleanup clear the outgoing chain. Only token 8's terminal consumer
may additionally select the terminal-versus-expiry race fact. A RUN after a
still-unconsumed QUANTUM, a QUANTUM without its RUN, or a PREEMPT without its
exact QUANTUM remains out of order and latches a failure. The first completed
ARM-generation chain whose RUN identity is not
already retained for another CPU owns that CPU's fixed records; later distinct
completed chains are valid surplus and cannot replace them. A nonzero later
execution generation for a known actor always enters a non-serializing CPU
chain, regardless of whether that CPU's fixed slot is empty or complete. Its
matching RUN/QUANTUM/PREEMPT callbacks are order-checked and consumed but can
never fill or replace a fixed record. Once a CPU's fixed chain is complete,
later scheduler-validated unique QUANTUM/PREEMPT callbacks may also advance
and clear a non-serializing surplus candidate without another retained RUN
callback.
RUN has no separate dispatch-event generation with which the collector could
distinguish callback replay from a valid continuation resume, so an exact RUN
re-observation is idempotent: it may retain or resume only the same bounded
candidate and cannot by itself fill a fixed record. Unique quantum-arm and
completed-switch generations remain replay-checked. A later token-8 CPU chain
is non-serializing for the fixed CPU records, but its pending quantum may
independently win the terminal-expiry join at that same later execution
generation. Outside the one-shot ARM boundary, a QUANTUM without either its
observed RUN or an already-complete fixed CPU slot remains a hard missing fact.
Later token-6 and token-7 scheduler
surplus cannot advance their independent private race joins; those joins retain
their own exact wake/block generation rules. This selection preserves the host
requirement that all four retained RUN identities are distinct.

The collector serializes the 46 records only after every fact is joined.
Original transition generations and ordering remain part of those relations.
A distinct scheduler-originated wake carrying either the exact bound execution
generation or a nonzero later continuation generation, or a local wake which
is not a remote-wake record candidate, is one such additional transition: a
later generation cannot fill an empty fixed slot, replace a retained payload,
or latch a selector failure. A later committed idle-steal migration is likewise
non-serializing activity even before the one fixed `STEAL_MIGRATE` relation has
been retained. The scheduler's committed migration identity is
the bound Thread, distinct source/target CPUs, and nonzero migration generation;
a migrated continuation may legitimately carry execution generation zero
before its destination dispatch mints the next execution claim. The first
retained steal still requires the exact ARM-bound execution identity, while a
distinct later committed migration generation is non-serializing surplus even
when that auxiliary execution field is zero or newer. Token 6's independently
required wait/wake join
still advances when its valid wake does not own a target slot, including when
that scheduler publication is local; its wait/wake/run and migration-rejection
proof does not substitute for any of the four distinct remote-wake records.
After that one wake/rejection join is selected, a distinct later token-6 wake
or execution-pinned rejection is valid scheduler surplus and cannot retrigger
the selector's synthetic rejection probe or replace record 36. Exact selected
wake or rejection identity replay remains a failure.
Exact replay of a retained wake or migration relation remains a duplicate,
while reuse of its retained scheduler generation for a different relation is
contradictory. Any terminally incomplete transcript, exact selected duplicate,
out-of-order, malformed, overflowed, or contradictory observation latches one
selector failure and cannot be repaired by later activity. Once failure is
latched or the normal terminal permit seals the immutable certificate, all
observer callbacks stop admitting further observations; activity racing with
the serial flush cannot mutate or invalidate the selected 46 records.

Token 7's first full-send observation binds the selector-owned Channel flight
to its fixed actor identity; repeated or unrelated capacity and wait activity
is ignored once it cannot advance that exact flight. The later block binds the authoritative nonzero execution
generation carried by that registered wait, which may be newer than ARM after
ordinary preemption. Its peer-drain wake and resumed RUN must match that same
block generation. A newer-generation RUN advances only this private race join;
it cannot fill or replace a fixed per-CPU RUN record that requires the ARM
generation. The userspace controller does not infer fullness from a level
`READABLE` signal: token 7 transfers a private side Channel, reports `FULL`
only after its send receives `WOULD_BLOCK`, and reports `WOKE` only after the
capacity-producing drain resumes it. Likewise, lifecycle EXIT records retain
the exact nonzero terminal Thread generation sampled from the committed exit
rather than requiring the earlier ARM generation or ARM-bound Thread.
`BOOTSTRAP_NORMAL` retains the exact terminal product generation from the
primordial deferred-current claim; ARM's live product generation authenticates
ARM itself but is not assumed to survive intervening blocking or preemption.

Token 8's terminal-versus-expiry join is independent of the one fixed
per-CPU transcript chain. Publishing an expiry consumes the physical timer
source and leaves an exact scheduler request; terminal cleanup carries that
already-published ticket to selector evidence separately from any still-armed
ticket that must be physically cancelled. A nonterminal no-peer resolution,
voluntary yield/block, or ordinary actor termination explicitly consumes the
pending selector candidate without selecting token 8's race fact. A later
expiry ticket may carry either the ARM generation or a later nonzero execution
generation; it remains non-serializing for fixed CPU records but may join token
8's terminal winner and set race bit 2. A physically cancelled terminal-first
ticket or an expiry already consumed by another committed transition cannot do
so.

The selector-private rejection codes are fixed for validation and diagnostics:
`01 RUNNING`, `02 BLOCK_PREPARING`, `03 CONTINUATION_BOUND`,
`04 EXECUTION_PINNED`, `05 SCRATCH_PINNED`, `06 ROOT_SWITCHING`,
`07 STOP_PENDING`, `08 RENDEZVOUS_PENDING`, `09 TERMINAL`, and
`0A NOT_REVALIDATABLE`. Selector 28's positive workload must emit `04`; host
negative fixtures cover all codes and reject unknown values.

### 9.4 Required facts and relations

PASS requires the complete fixed transcript and all of these joins:

- four distinct scheduler-capable CPUs and Local APIC identities;
- ordinary exact actor execution on every CPU;
- one exact quantum expiration and completed involuntary preemption on every
  CPU, which is stronger than the minimum beyond-CPU0 relation;
- nonzero progress for all five CPU-bound actors before the selector-local
  generous bounded-progress deadline;
- one exact remote wake targeting every CPU;
- one exact bounded idle steal/migration with distinct source/target and a
  nonzero migration generation;
- one deliberate migration rejection for an A0 non-migratable state;
- `RACE_MATRIX` bit 0 only after the kernel observes token 6 enter a bound wait,
  become Runnable from the matching wake source, and run while at least one of
  tokens 1..5 makes separately bound progress;
- bit 1 only after the kernel observes token 7 block on a full selector-owned
  Channel, the peer drain that creates capacity, its matching block-generation
  wake, and a later Running claim for that same generation;
- bit 2 only after the kernel joins token 8's exact quantum expiry with the
  competing terminal transition, proves a single terminal winner, and observes
  no requeue or Running claim for that generation afterward;
- bit 3 only after ARM correlates tokens 9 and 10 to two distinct
  kernel-observed CREATE and START transitions and the kernel then observes
  each exact Process identity, authoritative terminal Thread generation, and
  reap once. EXIT and REAP observations may arrive in either cross-actor order;
  each actor's EXIT must precede its own REAP, while fixed serialization remains
  token 9 then token 10;
- bit 4 only after the kernel's monotonic interval from accepted ARM to the
  complete terminal fact set is at most the ARM bound of 240 seconds; the host
  verifier additionally requires completion inside the frozen request deadline;
- exact per-actor EXIT-before-REAP order and one reap for each lifecycle actor;
- normal primordial/Wyrmroot bootstrap completion;
- checked accounting and ownership facts; and
- a matching terminal/debug-exit/request/product evidence join.

`READY_DELAY` is diagnostic regression evidence. Wyrmroot's frozen request
also binds the deliberately generous selector-local bounded-progress deadline;
the verifier compares the record to that test bound. This is not a production
latency ABI.

Negatives include forged child `DW1C` text, a wrong reporter, unknown actor,
wrong internal object/generation join, CPU out of range, missing CPU or actor,
stale nonce, bad checksum/version/case/sequence/event/order/cardinality,
mismatched QUANTUM/PREEMPT, progress from an unbound actor, invalid migration,
REAP before EXIT, duplicate terminal, text inserted inside the atomic stream,
wrong `DWTEST1` ID/detail, and serial/QEMU result mismatch.

## 10. Required tests before selector admission

### 10.1 Bootstrap stack budget

Selector 28 raises Deepwyrm's private x86_64 bootstrap stack from 512 KiB to
1 MiB and the guarded per-Thread kernel stacks from 256 KiB to 512 KiB. These
are internal kernel implementation budgets, not native ABI, boot ABI, or
Wyrmroot platform ABI changes.

The first frozen C5 release artifact measured 493,816 bytes in the retained
`kernel_main -> run_primordial -> primordial::enter` frame chain. The prior
512 KiB allocation left 30,472 bytes, below the existing 4 KiB architectural
headroom plus 32 KiB required spare. The 1 MiB allocation restores useful
headroom without reducing selector capacities merely to preserve the earlier
budget. Retained bootstrap-frame pressure remains explicit optimization debt.
Selector 28 is included in the accepted-target primordial stack-margin gate so
future capacity or compiler-layout growth fails before live acceptance.

The first corrected live admission candidate then reached CPL3 and exposed a
separate per-Thread stack overflow. QEMU recorded the first fault as a kernel
write through `RSP` into the first Thread stack's guard page while selector
28's address-region commit path was active; the exception-frame push faulted
again and became vector 8. The 512 KiB Thread stack restores functional
headroom. Selector 28's accepted-target gate therefore also binds the exact
target-emitted frames in that trace-witnessed syscall chain and requires 4 KiB
architectural headroom plus 32 KiB spare against the linked per-Thread payload.
It is a regression for the observed overflow path rather than a whole-program
call-graph proof. Retained large-frame pressure remains explicit optimization
debt.

The next frozen candidate progressed through that per-Thread path and exposed
an independent terminal-reaper budget defect during real selector-28 process
teardown. The first page fault was the stack probe in
`MemoryObjectAuthority::prepare_replace`, with `RSP == CR2` 3,416 bytes inside
CPU0's terminal-reaper guard. The live terminal chain had descended 138,584
bytes from the reaper top, beyond the old 132 KiB payload, before the exception
frame faulted again as vector 8. This was kernel execution, not an artifact or
verifier failure. The guarded terminal-reaper payload is therefore 256 KiB per
runtime CPU, leaving useful functional headroom rather than preserving the old
soft budget through another packing iteration. The selector-28 accepted-target
gate binds this observed high-water mark to the linked terminal payload and
charges growth in the exact target-emitted teardown anchors. Large teardown
frames remain explicit optimization debt; no native, boot, or Wyrmroot ABI is
changed.

The corrected twelve-entry bootfs then exposed a fourth independent kernel
budget defect before ARM: the live `ProcessCreate` transaction for the next
actor returned `DW_STATUS_NO_RESOURCES`. A designated-VM GDB trace proved that
the process shell, child bootstrap slot, and portable root-region preparation
all succeeded, while the transaction stopped in the live child-root
reservation before parent result slots. The 544-entry frame-role registry was
exhausted there even though selector 28 was only creating its fourth process
transaction. The registry now carries 4,096 role entries, enough useful
headroom for the complete primordial/controller/ten-actor resident image and
its mapping transactions. This is bounded kernel bookkeeping capacity, not a
physical-memory, native ABI, boot ABI, or Wyrmroot ABI change. Reducing the
metadata footprint after measuring a complete successful campaign remains
optimization debt.

The next corrected candidate reached the ninth actor's `ChannelCreate` and
returned `DW_STATUS_BAD_ADDRESS` even though both output addresses were valid,
mapped, and identical to the preceding seven successful calls. A bounded live
GDB trace proved that those seven actors were blocked on launch Channels and
each retained one owned mapping-stability pin. The ninth load atomically needed
two additional pins for its two `ChannelCreate` outputs, exceeding the former
kernel-global eight-slot user-pin tracker. The complete ten-actor workload has
a twelve-pin floor before accounting for other overlapping pinned outputs or
atomic words. The tracker therefore carries 32 bounded slots in the integrated
kernel, with a selector-28 geometry assertion and host regression covering ten
retained receive pins plus the two-output batch. This changes no pointer,
usercopy, mapping-mutation, native ABI, boot ABI, or Wyrmroot ABI rule. Reducing
the fixed metadata footprint after measuring the complete successful campaign
remains optimization debt.

DW1-C implementation must add host/source/model coverage for:

- every Parked-to-Schedulable step, reordered/omitted publication, stale
  generation, and failure-before-admission case, plus a fault injected after
  successful idle-wake enable to prove that the only outcome is complete
  scheduler publication or fail-stop with no continued boot;
- distinct descriptor, entry/reaper stack, root, scratch, carrier, mailbox,
  APIC, queue/current slot, and deadline identities for CPUs 0..3;
- the coarse runtime guard being absent across every divergent boundary;
- queue uniqueness, placement order, publish-before-IPI, repeated IPI, bounded
  victim scan, FIFO-age preservation, and transactional migration rollback;
- every migration rejection state named by A0;
- independent per-CPU quantum arm/expire/cancel/rearm and cross-CPU stale
  events;
- syscall- and timer-origin safe-return precedence on an AP;
- AP block/wake, terminal/reaper, exception, remote Stop, e1, e2, root, and
  scratch races;
- fixed `DW1C` encoding/decoding, all malformed fields and relations,
  wrong reporter/subject, forged child text, duplicate terminal, capacity, and
  debug-exit join; one negative fixture per `RACE_MATRIX` bit that supplies a
  valid `WORKLOAD_COMPLETE` but omits that bit's kernel-observed relation;
  token 8's exact terminal-versus-quantum join; ordinary tracked-actor terminal,
  block, yield, and no-peer consumption of published expiries; and tokens
  9/10's two distinct kernel-observed CREATE/START generations followed by
  per-actor EXIT-before-REAP joins in either cross-actor order; and
- fixed-seed trace assertions after every scheduler mutation.

No live claim follows from C0. C1 through C4 must pass their focused host gates
before selector 28 runs. C5 then requires one clean four-vCPU smoke, five
consecutive stress passes, selector-26 one-vCPU regression, affected
selector-25/27 regressions, and the full Deepwyrm format/Clippy/Rustdoc/ABI and
host/model gates on one frozen product tuple.

## 11. Prior-art and provenance disposition

Fuchsia/Zircon `zircon/kernel/kernel/scheduler.cc` at revision
`6a606ff7fd9b055edee6557566fb3f112df1a812` was consulted for conceptual
comparison of exact per-CPU current ownership, target admission revalidation,
explicit migration state, deferred preemption, and per-CPU accounting. Its file
has the Fuchsia MIT-style header. Deepwyrm does not import Fuchsia's fair or
deadline policies, affinity/power policy, energy accounting, priority
inheritance, chain locks, work-stealing implementation, C++ structures, ABI,
or tracing infrastructure.

xv6-riscv `kernel/proc.c` and `kernel/trap.c` at revision
`35b088427ef37611c38afdeed5a52a278cae38f9` were consulted for the deliberately
small per-CPU current-owner and timer-to-reschedule test shape. The repository
LICENSE is MIT. Deepwyrm does not import xv6's global process-table scan,
CPU0-only tick model, direct trap-time yield, RISC-V trampoline/root mechanics,
Unix process model, lock discipline, code, names, layouts, or ABI.

No upstream code was copied or substantially adapted. This document is
first-party work within Deepwyrm's existing `GPL-2.0-or-later` component
boundary. Existing file and component license declarations remain unchanged.

## 12. Reached implementation gates

DW1-C1 may begin only against this design and must stop after four CPUs reach
the exact `Schedulable` idle/rescan state without duplicate or premature work.
DW1-C2 then adds only per-CPU quantum/deadline ownership. DW1-C3 admits the
reached placement, steal, and migration policy. DW1-C4 closes cross-subsystem
races. DW1-C5 alone makes the selector-28 live acceptance claim.

No slice may silently change the schedulability predicate, publication order,
timer ownership, placement order, migration eligibility, return precedence,
or evidence schema. A required change first revises this design and the A0
contract when A0 semantics are affected.
