# Deepwyrm DW1-A0 Normal Preemptive Scheduler Contract

**Status:** Reached contract; authoritative for DW1-A through DW1-C
**Prepared:** 2026-08-25
**Deepwyrm baseline:** `5a8bb0a75979bb3ecde9bd7209619e924ec5e36d`
**Paired Wyrmroot baseline:** `120fafa36e0e32402656b23d5a4b0c03b949c7b6`
**Milestone:** DW1 normal timer-preemptive SMP scheduling

This contract refines the cooperative scheduler accepted by DW0-H/WYR0-I into
the first normal preemptive scheduler. It preserves the H0/I0/I1 execution,
root, continuation, wait, remote-stop, and terminal-reaper invariants. It adds
no userspace ABI, scheduler class, priority, reservation, deadline, or
hard-latency promise.

The baselines above are the accepted design inputs. Later implementation and
validation records bind the exact compatible Deepwyrm/Wyrmroot product pair.

## 1. Scope and authority

DW1-A through DW1-C implement only the ordinary normal scheduling class:

- per-CPU FIFO round-robin queues;
- a fixed `5_000_000 ns` default quantum;
- timer-requested involuntary preemption of userspace at a safe return boundary;
- bounded idle stealing for eligible non-running work; and
- internal accounting and test instrumentation.

The quantum and queue policy are internal implementation policy, not stable
ABI. DW1 does not add real-time classes, public priorities or affinity,
budgets, reservations, priority inheritance, arbitrary kernel preemption, or
compatibility-shaped scheduler calls.

The canonical ABI schema remains unchanged for DW1-A. Scheduler counters and
trace records remain internal/test-visible. If a later milestone exposes them,
it must do so through a typed, rights-checked inspection contract rather than
text scraping, ambient process identity, `/proc`, or `ioctl`.

## 2. Preserved DW0 ownership model

One exact `ThreadKey` generation occupies exactly one logical scheduler state:

```text
Reserved -> Runnable -> Running -> Runnable
                         |   |
                         |   +-> Blocked -> Runnable
                         +------> terminal retirement
```

The physical continuation state used during blocking, remote stop, context
switch, root handoff, and reaping refines this logical state; it does not create
a second runnable or Running identity.

A committed no-peer block may therefore pass through two physical substates
without changing its logical `Blocked` state:

```text
Blocked + suspended on Thread stack
    -> Blocked + detached on the CPU-private idle-carrier stack
```

The first state is transient.  Before that CPU may remain idle indefinitely,
the carrier must save the exact Thread continuation, move through the retained
CPU kernel root onto its CPU-private idle-carrier stack, and only then publish
switch completion.  The detached state has no Running owner and does not make
the blocked Thread Runnable.  An idle-wake IPI may request this rescan and
handoff, but it never performs or proves the ownership transfer.

The following remain hard invariants:

1. one CPU owns zero or one Running claim;
2. one Thread generation is Running on zero or one CPU;
3. a Running Thread is not present in any run queue;
4. a queued Thread appears exactly once;
5. `pending_block`, suspended-continuation, wake, switch, stop, timer, and
   migration records name the exact Thread and execution generation;
6. terminal state is monotonic and stale activity cannot revive it;
7. the Thread-owned kernel continuation moves only after the old CPU has
   acknowledged safe suspension;
8. CPU-private entry/reaper stacks, active root, scratch state, and local timer
   state never migrate with a Thread; and
9. task/execution pins are released exactly once, after the corresponding
   terminal or ownership transition makes execution impossible.

For a no-peer detach, safe suspension means physical arrival on the exact
CPU-private idle-carrier stack under the retained CPU kernel root.  Merely
publishing `Blocked`, waking the CPU, rescanning the run queue, or observing
that no peer is Runnable is not switch completion.

An invariant failure in live kernel state means the scheduler substrate cannot
be trusted. It is a fail-stop kernel error, not a recoverable userspace status.
Host models return structured errors so negative tests can inspect the exact
rejected transition.

## 3. Scheduler ownership and queue representation

Every online `CpuIndex` owns one logical normal run queue and one optional
Running claim. Queue membership records:

- exact `ThreadKey`;
- scheduler-domain identity;
- nonzero enqueue generation;
- target CPU;
- last execution CPU, when any;
- eligibility mask;
- ready timestamp in test/instrumented builds; and
- any continuation CPU/generation that temporarily forbids migration.

DW1 may initially retain one IRQ-safe scheduler-state lock around the bounded
array of per-CPU queues. Per-CPU ownership is a semantic partition, not a
requirement to introduce multiple locks prematurely. A later lock split must
preserve the transitions and ordering in this contract and must receive its own
model/stress coverage.

The scheduler lock is never held across:

- usercopy or scratch-window access;
- wait/deadline registration callbacks;
- Local APIC programming;
- context-switch assembly;
- CR3/root-switch completion;
- userspace return;
- terminal-reaper handoff;
- idle entry; or
- rendezvous/TLB acknowledgement waits.

No scheduler transition acquires the stationary runtime or paging-authority
guard while holding the scheduler lock. Preparation under one authority,
guard-free architecture work, and exact revalidation/commit remain distinct.

## 4. Eligibility, placement, and migration

Eligibility is an internal bounded bitset over the accepted logical CPU
capacity. During DW1, ordinary Threads begin eligible on every online CPU. No
public affinity operation is introduced.

Initial placement and wake placement use this deterministic preference order:

1. a continuation-bound Thread remains on its required continuation CPU;
2. otherwise retain the last CPU when it is online and eligible;
3. otherwise use the requesting CPU when it is online and eligible; and
4. otherwise use the lowest-index online eligible CPU.

Placement publishes one target queue identity before any idle-wake IPI is sent.
An IPI is only a rescan notification; it never grants Running ownership or
serves as proof that the target consumed the work.

A Thread is non-migratable while it is:

- Running;
- in block preparation;
- owned by a suspended continuation;
- execution-pinned or scratch-pinned;
- in a Process/root switch transaction;
- the subject of an unacknowledged remote stop or TLB/rendezvous operation;
- committed to terminal/reaper handoff; or
- in any state whose exact generation cannot be revalidated at commit.

Migration is one serialized source-dequeue/target-enqueue transaction under the
scheduler authority. It preserves FIFO age, advances a nonzero migration
generation, and changes no task/capability authority. Failure leaves the Thread
at the source exactly once.

## 5. Local FIFO round-robin policy

Each CPU selects the oldest eligible Runnable entry from its local queue.
Dispatch atomically removes that entry and publishes the CPU's Running claim.

When a normal Thread exhausts its quantum and another eligible local Thread is
Runnable, the current Thread moves to the local queue tail and the oldest
eligible peer runs. A voluntary yield has the same queue-order effect but is
accounted separately. Blocking and terminal transitions do not enqueue the
outgoing Thread.

If no peer is locally runnable, quantum expiry may retain the current Thread,
clear the consumed reschedule request, and arm a fresh quantum. It still records
the expiration; it must not manufacture a context switch.

An idle CPU first rescans its local queue, then performs one bounded victim scan
in cyclic logical-CPU order. It steals the oldest eligible migratable entry
from the first victim with admissible work. The shared scheduler lock makes the
DW1 scan deadlock-free. A failed/stale candidate is skipped or rejected without
moving another identity. Stealing is load recovery for idle CPUs, not a
fairness, NUMA, or long-term balancing ABI.

Under bounded runnable load, repeated local dispatch and bounded idle stealing
must ensure every continuously eligible normal Thread eventually runs. No hard
real-time or fixed worst-case latency follows from this property.

## 6. Quantum accounting and timer identity

The default normal quantum is exactly `5_000_000 ns`. A dispatch records:

- CPU identity;
- exact execution generation;
- monotonic-active dispatch time;
- checked deadline; and
- a nonzero local timer-arm generation.

Normal runtime consumption includes time spent executing on behalf of the
Thread in userspace and kernel entry. DW1 switches involuntarily only at the
safe userspace-return boundary; time inside a non-preemptible kernel path still
consumes the quantum and causes deferred rescheduling.

Each online CPU owns its scheduler deadline source. The interrupt validates CPU,
source-arm generation, execution generation, and deadline before it can request
rescheduling. A stale, early, duplicated, or cancelled event cannot mutate a
later dispatch. Local APIC EOI and bounded interrupt acknowledgement occur
independently of whether a later safe boundary performs a switch.

### 6.1 Unified Local APIC deadline arbiter

One CPU has one physical Local APIC one-shot timer and vector `0xe0`. Scheduler
quantum code and the existing Timer/wait service must never program that timer
independently.

Every online CPU owns one internal local-deadline arbiter. It has a scheduler-
quantum source. CPU0 also has the existing general Timer/wait-service source;
APs do not acquire general Timer-object ownership during DW1. Both sources use
the same monotonic-active clock and carry independent nonzero arm generations.

Publishing, replacing, or cancelling a source deadline occurs under the
bounded arbiter lock. The arbiter selects the earliest armed deadline and is
the only runtime owner allowed to program, stop, or reprogram the physical
one-shot timer. Equal deadlines are dispatched in deterministic order:

1. collect all exact source generations due at the sampled time;
2. service CPU0 Timer/wait expirations and publish their bounded wakes;
3. publish the scheduler quantum-expiry request for the matching execution;
4. recompute the earliest remaining deadline; and
5. arm the physical timer before leaving the interrupt path when a deadline
   remains.

The arbiter lock is dropped before wait wake callbacks, scheduler mutation,
Local APIC MMIO programming, or userspace-return scheduling. A prepare record
captures the intended hardware arm generation; after guard-free programming,
commit revalidates that no newer source update won. If it did, the newer
earliest deadline is programmed before return. An already-due deadline causes
bounded immediate source dispatch rather than a zero-count hardware arm.

Cancel and interrupt paths validate both source and arm generation. A stale
quantum cancel cannot remove a new Timer-object deadline, and a stale timer-
service event cannot clear a later quantum. Checked deadline conversion rejects
zero/unrepresentable hardware counts and never silently delays the other
source.

This arbitration changes no Timer-object ABI and preserves CPU0 as the DW1
general timer-service owner. Host/model tests must cover earlier/later/equal
source deadlines, cross-source cancel/rearm races, generation reuse, immediate
expiry, hardware-count bounds, and reprogramming that races a newer source.

## 7. `need_resched` and preemption-disable semantics

Each CPU has internal scheduler-return state containing:

- a coalescing `need_resched` request;
- the validated timer/execution generation that produced it;
- reason bits for quantum expiry and other internal scheduling requests; and
- a checked preemption-disable depth.

The Local APIC timer handler may publish/coalesce this request, but it does not
perform the context switch. Nested disable increments and decrements use
checked arithmetic; overflow, underflow, or return with an unbalanced depth is
an invariant failure.

A request remains pending while the CPU is not at a safe boundary. Coalescing
must retain a request applicable to the current execution generation. A stale
request is cleared without affecting the replacement Thread. Clearing or
consuming a request is ordered with timer cancellation/rearm so an old event
cannot clear a new dispatch request.

## 8. Safe involuntary-preemption boundary

DW1's first involuntary switch is allowed only immediately before a validated
return to CPL3, after the complete syscall/interrupt frame has been sanitized.
At that boundary:

- the current Thread and CPU/execution generation still match;
- preemption-disable depth is zero;
- no scheduler, runtime, paging, registry, wait, or usercopy guard is held;
- no scratch session, block preparation, switch completion, root transaction,
  terminal handoff, or unacknowledged stop owns the carrier;
- the current Process/root binding and return frame are valid; and
- pending rendezvous/stop work has been polled in the established order.

If any condition is false, the request remains deferred or the competing
terminal/block/stop transition wins by its exact generation. Arbitrary
preemption inside kernel critical sections is outside DW1.

The switch preparation sequence is:

1. revalidate the request and current execution identity;
2. decide retain/requeue/next under scheduler authority;
3. publish a move-only switch plan and drop all guards;
4. perform the existing root/carrier switch ordering;
5. complete the outgoing suspended-continuation publication; and
6. arm the selected non-idle Thread's local quantum before CPL3 return.

No scheduler lock crosses steps 3 through 6.

## 9. Wake, block, terminal, and remote-stop races

- Block preparation keeps the exact Thread Running until wait/deadline
  registration commits. Quantum expiry during preparation is deferred.
- A committed block removes Running ownership once and transfers its exact wake
  token to the waiter. A simultaneous timer cannot requeue it.
- A committed block with no selected Runnable successor must not idle forever
  on the blocked Thread's stack.  It prepares one generation-bound detach,
  drops scheduler/runtime/root guards, switches to the exact CPU-private
  idle-carrier stack and kernel root, and publishes continuation release only
  after destination arrival.  Failure or a competing stop before commit leaves
  the original suspended claim intact; a stale detach cannot clear a later
  claim.
- Wake consumes one matching blocked generation and enqueues it once. A stale
  or competing wake is rejected and does not consume another waiter's budget.
- Terminal retirement wins monotonically over wake, timer, steal, and migration
  and removes queued/Running/suspended ownership once.
- Remote stop identifies the exact root and execution generation, moves the CPU
  to its retained kernel root, leaves Process residency, removes Running, and
  acknowledges before reclaim. Quantum expiry cannot acknowledge or replace
  that stop transaction.
- Switch completion and timer cancellation name the old execution generation;
  neither can clear or publish state for a later run of the same Thread.

## 10. Internal assertions and counters

Every scheduler mutation validates at least:

- queue length/capacity and unique membership;
- unique Running ownership;
- no Running/queued overlap;
- CPU/eligibility validity;
- exact block, continuation, execution, timer, and migration generations;
- terminal non-membership; and
- checked counter/time arithmetic.

Each CPU owns bounded counters for:

- current runnable count;
- context switches;
- quantum expirations;
- involuntary userspace preemptions;
- voluntary blocks;
- voluntary yields;
- wakeups;
- steals in/out;
- migrations in/out;
- idle entries and monotonic-active idle time; and
- longest observed ready-to-run delay in test/instrumented builds.

Event counters use checked addition. On overflow, the value freezes at its last
valid value and a sticky internal overflow fault is set; acceptance treats the
fault as failure. Gauge updates reject underflow/overflow before scheduler state
publication. Time subtraction/addition is checked and rejects regression.
Telemetry failure never grants execution or weakens a scheduler transition.

Trace records are fixed-capacity, structured, generation-bound, and test-only
for DW1. They do not rely on serial text and cannot become a production
acceptance channel.

## 11. DW1-A transition inventory

Implementation must instrument and test the current transition surfaces before
changing policy:

| Transition surface | Concrete current owner/call path | DW1 preservation point |
| --- | --- | --- |
| reserve, commit, cancel, and initial Runnable publication | `CooperativeScheduler::{reserve,commit,cancel}` in `kernel/src/task/scheduler.rs`; task creation reaches it through `ExecutionAuthority` in `kernel/src/task/execution.rs` | Reservation tokens and enqueue generations remain exact; the normal-policy model is separate and test-only. |
| idle claim and Running publication | `CooperativeScheduler::{schedule_next_on,schedule_from_idle_on}`; façade `ExecutionAuthority::{schedule_next_on,schedule_from_idle_on}` | Claim removes one queue identity and publishes one CPU/execution generation. AP live scheduling is still parked. |
| voluntary yield and continuation publication | `CooperativeScheduler::{yield_current_on,complete_switch_on,complete_switch_on_with_runnable_publication}`; `ExecutionAuthority::{yield_current_on,complete_switch_on}`; physical switch preparation in `ExecutionAuthority::prepare_kernel_switch_inner` | No scheduler guard crosses the root/carrier switch; the suspended continuation remains CPU/generation-bound until completion. |
| block prepare, cancel, and commit | `CooperativeScheduler::{prepare_block_current_on,cancel_block_on,commit_block_on}` via `ExecutionAuthority`; callers in `kernel/src/wait/operation.rs`, `kernel/src/atomic_wait.rs`, and the primordial syscall adapter | Registration commits before Running removal; timer/quantum work must defer while preparation owns the exact claim. |
| ordinary wait and deadline wake | `kernel/src/wait/engine.rs` and `kernel/src/wait/operation.rs` produce exact `BlockWakeKey`; `ExecutionAuthority::wake` calls `CooperativeScheduler::wake_with_affinity`; `kernel/src/time/live.rs::wake_trampoline` reaches the bound deadline target | One matching block generation is consumed; stale/competing wakes cannot enqueue. |
| atomic-wait winner and wake | `kernel/src/atomic_wait.rs::{begin_atomic_wait,complete_atomic_wait,wake_atomic_waiters}` and `BlockedOperations` winner ownership, followed by `ExecutionAuthority::wake` | Predicate, registration, pin, deadline, and scheduler wake ownership remain one transaction. |
| terminal retirement and reaper handoff | `CooperativeScheduler::retire_on`; `ExecutionAuthority::{retire_exit_pins_on,retire_exit_pins_after_remote_stops,terminal_physical_claim_on,terminal_reaper_next_on}`; primordial terminal/reaper paths in `kernel/src/arch/x86_64/mm/activation/primordial.rs` | Terminal state wins monotonically; task/execution pins and physical continuation are released only after the exact stop/switch acknowledgement. |
| remote stop and Running/suspended removal | mailbox/state validation in `kernel/src/arch/x86_64/rendezvous.rs`; delivery and root handoff in primordial `prepare_suspend_stationary`/`poll_idle_suspend_stationary`; `ExecutionAuthority::{stop_running_claim_on,stop_suspended_claim_on}` | Exact CPU, Thread, execution, and root generation are revalidated before acknowledgement; scheduler removal precedes ACK. |
| user entry, syscall/interrupt return, and idle loop | `kernel/src/arch/x86_64/syscall/live.rs` entry/carrier code and primordial live carrier dispatch/return/idle-rescan paths | DW1-B may consume `need_resched` only at the later validated CPL3-return boundary; DW1-A changes none of these paths. |
| idle accounting publication | `ExecutionAuthority::{publish_idle_on,finish_idle_on}` -> matching `CooperativeScheduler` operations; primordial carrier idle entry/exit | Accounting begins only after the architecture publishes an exact idle generation and ends once. |
| Timer/wait deadline queue and interrupt service | `kernel/src/time/live.rs::{register_deadline,cancel_deadline,dw_x86_64_timer_interrupt_dispatch}` plus `LiveTimerDeadlineAuthority`; general Timer objects in `kernel/src/time/timer.rs` | CPU0 remains sole live Timer/wait-service owner in DW1-A; no scheduler deadline source is live yet. |
| Local APIC one-shot programming | `LocalApic::program_one_shot_timer`/`stop_timer` in `kernel/src/arch/x86_64/apic.rs`, called by `LiveTimeState::reprogram` and time initialization in `kernel/src/time/live.rs` | The future unified arbiter must become the sole programmer before DW1-B adds a quantum source. |
| stationary runtime/root guards and root switch | depth/phase witnesses in `kernel/src/arch/x86_64/syscall/stationary_runtime.rs`; runtime binding in `kernel/src/arch/x86_64/syscall/runtime_binding.rs`; root selection in `kernel/src/arch/x86_64/mm/activation/` | No stationary/paging guard or root-switch transaction may cross a scheduler switch/preemption boundary. |
| scratch and execution-pin migration exclusion | CPU-local scratch sessions under `kernel/src/arch/x86_64/mm/`; task exit pins in `kernel/src/task/mod.rs` and `kernel/src/task/execution.rs` | Live scratch, execution pins, root switch, suspended continuation, block preparation, and unacknowledged stop all reject migration. |
| DW1 future-policy host model | `kernel/src/task/scheduler/normal_policy_model.rs`, compiled only under `cfg(test)` | Fixed-capacity model covers placement, per-CPU FIFO rotation, eligibility/offline rejection, bounded cyclic idle stealing, migration guards, quantum generations/arithmetic, and block/wake/terminal races without changing cooperative production behavior. |

New transition surfaces must be added to this inventory or to the DW1
validation record before their behavior is accepted.

## 12. Host model and phase gates

The allocation-free host/model suite must cover, at minimum:

- reserve/commit/cancel;
- local FIFO selection and round-robin rotation;
- duplicate enqueue/Running rejection;
- block preparation/commit/cancel;
- wake versus timeout/terminal;
- quantum versus block/terminal/remote stop;
- timer and switch-completion generation reuse;
- continuation-bound migration rejection;
- bounded idle stealing;
- eligibility and offline-CPU rejection;
- accounting overflow/regression; and
- fixed-seed state-machine traces with invariant checks after every operation.

DW1-A closes only when this contract is indexed, the transition inventory and
internal instrumentation exist, the host/model suite proves unique queued and
Running ownership, and the existing DW0 host regression set remains green.

DW1-B then proves one-vCPU involuntary userspace preemption on CPU0.

At the accepted baseline, APs reach the online barrier and remain parked; the
current I1 stationary runtime/carrier work does not yet admit ordinary AP
userspace execution. Before DW1-C schedules a Thread on any AP, implementation
and focused tests must complete and validate:

- per-AP stationary runtime authority and live carrier publication;
- CPU-private retained kernel/root, entry, reaper, scratch, and return state;
- exact runnable-delivery and idle-wake handling on the AP;
- e2/rendezvous/root-generation acknowledgement on the active AP carrier; and
- guard-free context-switch/user-return boundaries identical in strength to
  CPU0.

That prerequisite is part of DW1-C, not inherited acceptance. DW1-C then proves
the four-vCPU policy and stress matrix. Neither later gate may weaken this
contract without an explicit reached revision.

## 13. Required-source and provenance disposition

Required project sources were read as listed in the paired DW1/WYR1 plan,
including the accepted H/I contracts, validation, completion, security record,
and canonical ABI schema. Those sources prove SMP topology, CPU-private state,
remote acknowledgement, and cooperative scheduler invariants, but the current
baseline still parks AP execution. This contract therefore treats AP carrier
enablement as an explicit DW1-C prerequisite rather than accepted prior state.

Pinned prior art was used conceptually only:

- Fuchsia/Zircon `scheduler.cc` at
  `6a606ff7fd9b055edee6557566fb3f112df1a812` informed explicit CPU ownership,
  queue assertions, deferred preemption, timer identity, and event accounting;
- xv6-riscv `kernel/proc.c` and `kernel/trap.c` at
  `35b088427ef37611c38afdeed5a52a278cae38f9` informed small transition-model
  and timer-preemption test shapes.

No source code was copied or adapted. Fuchsia's mature fair/deadline and
ChainLock design and xv6's RISC-V global process scan, kernel-yield, Unix, and
process-table assumptions do not fit this milestone. This document and its
implementation remain first-party work in Deepwyrm's existing
`GPL-2.0-or-later` component lane.
