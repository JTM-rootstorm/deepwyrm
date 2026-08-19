# Deepwyrm DW0-F0 IPC and Wait Contract

**Status:** DW0-F0 architecture closure; authoritative for DW0-F implementation  
**Prepared:** 2026-08-19  
**Deepwyrm baseline:** `4d13e4d03a7a4c21c83519d601d5c735ef1ce752`  
**Wyrmroot read-only baseline:** `bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`  
**Milestone:** DW0-F channels, blocking, waits, time, and process-create activation

This contract closes the remaining architecture questions that must be settled
before DW0-F implementation begins. It refines the canonical DW0 plan and E0
task/syscall contract without changing the already-generated ABI-0 syscall IDs,
record layouts, rights vocabulary, signal bits, or implementation-phase labels.

DW0-D and DW0-E remain soft-accepted for development with their formal Daybreak
reviews still pending in `security/DW0_DEFERRED_DAYBREAK_REVIEWS.md`. F0 does not
reinterpret that debt, perform the formal F security review, or claim F runtime
evidence. F13 remains the F security-review gate.

The contract is deliberately mechanism-first. It does not introduce POSIX file
descriptors, signals, futex ABI, pthread semantics, `/proc`, `ioctl`, service
naming, filesystem execution, or libc dependencies.

---

## 1. ABI-0 preservation and F staging
The current ABI schema already defines every DW0-F public object, signal, record,
constant, and syscall required by the master plan. F0 therefore makes **no ABI
schema or generated-layout change**. Implementation must consume the existing
canonical definitions rather than creating private copies.

F owns activation of:

- `process_create`;
- `channel_create`, `channel_send`, and `channel_receive`;
- `wait_one` and `wait_many` with ABI-0 `WAIT_ANY` only;
- `event_create` and `event_signal`;
- `atomic_wait32` and `atomic_wake`;
- `clock_get` for `DW_CLOCK_MONOTONIC_ACTIVE`; and
- `timer_create`, `timer_set`, and `timer_cancel`.

`DW_CLOCK_BOOTTIME` and `DW_WAIT_MODE_ALL` remain reserved and return
`NOT_SUPPORTED`. Message maxima remain 64 KiB payload and 16 handles. The
`wait_many` maximum remains 64 items.

Zero-byte, zero-handle Channel datagrams are valid and still consume one bounded
message admission slot. A zero pointer is accepted only for an ABI buffer whose
corresponding byte/item capacity is zero and which the operation will not touch.

---

## 2. Common validation and publication doctrine
F preserves the existing dependency-aware validation model. Unless a syscall's
specific section below says otherwise, observable failure ordering is:

1. scalar syntax, count, flag, mode, version, size, reserved-field, signal-mask,
   and requested-right syntax;
2. userspace input-range validation and exact pinned copy-in needed to understand
   the request;
3. mandatory result-storage preflight when later mutation would otherwise create,
   consume, or move authority;
4. caller-local handle existence, accepted object type, required rights, and
   source-right subset validation;
5. target object state and operation-specific semantic checks;
6. bounded resource/slot/queue/wait reservation; and
7. one no-fail commit sequence followed by deferred cleanup/finalization.

`INVALID_ARGUMENT` caused by malformed caller-controlled ABI syntax therefore
wins before probing object existence. After syntax is valid, ordinary D/E handle
status ordering remains `BAD_HANDLE`, `WRONG_OBJECT_TYPE`, then `ACCESS_DENIED`.
No recoverable failure may occur after a transaction's first externally visible
commit mutation.

ObjectRegistry release may remain a narrow inner bookkeeping operation, but no
typed payload finalizer runs while a HandleTable, Channel pair, wait registry,
scheduler, timer-queue, task-state, or address-space mutation lock is held.
Cleanup authorities are deferred until those owners are released.

---

## 3. Channel endpoint and pair lifetime
Each public endpoint is one generic `CHANNEL` object with one typed endpoint
payload. The two endpoint objects never hold persistent generic strong references
to each other.

A bounded internal Channel-pair pool may hold shared queue and peer-state data,
but a pair slot is not an ABI object and cannot mint generic object authority.
Each endpoint payload owns exactly one move-only side lease containing pair slot,
pair generation, and side identity. A pair slot is reclaimed only after both side
leases have been consumed and all queued transfer references have been released.
Generation mismatch is always stale/fail-closed and may never alias a later pair.

Typed endpoint finalization performs this order outside generic-object locks:

1. mark the side closed in pair state;
2. drain that closed side's own inbound queue, because no future receiver for
   that endpoint can exist, deferring release of any queued transfer references;
3. publish `PEER_CLOSED` and recomputed `WRITABLE` state to the surviving side;
4. notify eligible waiters; and
5. consume the endpoint side lease, reclaiming pair storage only if it was the
   final side lease and both queues are empty.

Messages already committed **from** the closing endpoint into the surviving
peer's inbound queue remain receivable. Peer closure never retroactively revokes
a committed datagram.

---

## 4. Channel queue accounting, signals, and linearization
Queue depth, total payload storage, and transfer-token storage are bounded kernel
implementation resources and are not new ABI constants in F0. Before send commit,
the implementation reserves one destination datagram slot plus the exact payload
and transfer storage required by that message.

`WRITABLE` means the peer is still open and at least one minimal datagram
admission can currently be reserved. It does **not** promise that an arbitrary
maximum-size racing send will fit. `READABLE` means the endpoint's inbound queue
contains at least one committed datagram. `PEER_CLOSED` is level-triggered after
the peer side closes.

The Channel send linearization point is the atomic publication of a fully prepared
datagram into the peer's inbound queue together with the committed source-handle
moves, if any. No byte prefix, partial transfer list, or half-invalidated source
set is observable.

The receive linearization point is removal of the selected head datagram together
with publication of all destination handles. Receive is FIFO per endpoint.

After a send or receive commit, signals are recomputed from committed state before
eligible waiter notification. A waiter may observe multiple simultaneously true
signals; `DwWaitResultV1.observed` reports the full current signal state.

For a syntactically valid send whose Channel and transfer sources are valid,
peer closure wins over queue/resource exhaustion. Thus a closed peer returns
`PEER_CLOSED`; an open peer lacking reservation capacity returns `WOULD_BLOCK`.

For receive, a queued message wins over peer closure. An empty queue returns
`PEER_CLOSED` when the peer is closed and `WOULD_BLOCK` while the peer remains
open.
---

## 5. Handle-transfer transaction contract

`DwHandleTransferV1` validation order is fixed:

1. transfer-array count/range and every record's reserved fields;
2. reject duplicate source handle values within one send;
3. require ABI-0 operation `DW_HANDLE_TRANSFER_MOVE`;
4. resolve every source handle in the sending Process;
5. require `TRANSFER` on each source;
6. validate requested rights as nonzero, known, object-compatible, and a subset
   of the source handle's held rights;
7. apply the Channel-specific self-reference rule below; and
8. reserve queue/message resources before any source handle is invalidated.

A prepared move set is move-only and generation-bound to the exact source table
slots. Commit transfers each source entry's existing generic handle reference into
the queued message with the reduced requested-rights metadata. It does not create
a second authority reference merely to emulate a move.

Failure before commit leaves every source handle valid with its original rights.
Commit invalidates every source handle exactly once, advances/retire-generates its
source slot exactly as ordinary close would, and transfers the reference exactly
once to the queued datagram.

Transfer of the **sending endpoint itself** is permitted. The syscall's temporary
operation pin keeps it valid through commit, after which the queued move reference
or any other remaining reference determines its lifetime.
Transfer of the **destination/peer endpoint object into its own inbound queue** is
rejected with `INVALID_ARGUMENT`, including through a duplicate handle to that
same endpoint object. Allowing this would let the queue hold the final generic
reference to the endpoint whose own finalization is required to drain that queue,
creating an uncollectable self-reference cycle.

Other object types, including Process, Thread, MemoryObject, AddressRegion, Event,
Timer, and unrelated Channel endpoints, may be moved when ordinary object/right
validation succeeds. A moved source may be its object's final external handle;
the queued reference then owns the transferred liveness until receive or queue
drain.

The implementation may use bounded reservation structures or a coarse internal
transaction serializer, but lock acquisition must not define user-visible
semantics. F6 must prove the same all-or-nothing result under concurrent close,
duplicate, send, receive, and task teardown.

---

## 6. Receive publication and rollback

`channel_receive` first validates scalar capacities and `out_result`. The result
structure is preflighted/pinned before queue mutation because it reports both
success and `BUFFER_TOO_SMALL` sizing information.

The head datagram is then inspected without consuming it. If byte or handle
capacity is insufficient, receive writes `size`/`version`, sets
`actual_bytes = 0` and `actual_handles = 0`, reports the head datagram sizes in
`required_bytes`/`required_handles`, returns `BUFFER_TOO_SMALL`, and leaves the
datagram and all transfer references untouched. Data/handle output buffers need
not be probed when their declared capacities are already insufficient.
When capacities are sufficient, receive preflights/pins exactly the payload bytes
and handle-info records that will be written, then reserves enough destination
HandleTable slots for the entire transfer set. Reservation failure returns
`NO_RESOURCES`, consumes nothing, and creates no destination handles.

Successful commit removes the datagram, installs every receiver-local handle
exactly once using the queued requested rights, writes the already-pinned payload,
handle metadata, and result structure, and consumes the queue's transfer tokens.
There is no recoverable copyout step after the datagram/handle commit.

Receiver-local raw handle values are newly allocated capabilities. A transferred
raw source value has no meaning in the receiving process. `DwReceivedHandleInfoV1`
reports the newly installed handle, transferred rights, and object type only after
successful publication.

---

## 7. Generic wait signals and `WAIT_ANY`

Signal compatibility is derived from the canonical object/signal schema, not a
second hand-maintained policy table. ABI-0 valid waitable signals are:

- Channel: `READABLE | WRITABLE | PEER_CLOSED`;
- Process: `EXITED`;
- Thread: `EXITED`;
- Event: `SIGNALED`; and
- Timer: `SIGNALED`.

A zero desired mask or a bit not applicable to the resolved object is
`INVALID_ARGUMENT`. Handle resolution still requires `WAIT` before publication
of a wait registration.
`wait_many` requires 1..=`DW_WAIT_MANY_MAX_ITEMS` items. `WAIT_ANY` is supported;
`WAIT_ALL` returns `NOT_SUPPORTED`. Duplicate handles/items are allowed. If more
than one item is ready, including duplicate views of one object, the lowest input
index whose requested mask intersects current signals wins deterministically.

Generic wait signals are level-triggered and generic waits do not return
spuriously. At the wait linearization barrier:

1. pin every waited object and the result output;
2. read current signal state;
3. if any desired signal is already satisfied, return the deterministic ready
   item immediately, even when the finite deadline is already expired;
4. otherwise, if the deadline is `NOW` or already expired, return `TIMED_OUT`;
5. prepare one generation-protected scheduler block token;
6. publish bounded wait registrations; and
7. re-read signal state under the registration barrier before making the Thread
   actually Blocked.

Signal mutation publishes the new level state before scanning registrations.
The register-then-recheck rule guarantees that a signal transition either is
seen by the final recheck or sees the published registration; it cannot fall
between them and be lost.

Each registration owns exactly one wait-object lifetime pin and exactly one
association with the Thread's current block generation. Signal, timeout, or task
terminal retirement wins once and consumes every registration for that block
generation exactly once.
The result buffer remains mapping-stable for the blocked operation. F2/F7 may
replace E's borrow-shaped usercopy pin with an owned process/mapping pin suitable
for sleep, but they may not weaken output failure atomicity merely because a
wait spans a context switch.

Closing a waited handle after registration does not cancel the wait; the wait
owns its own generic pin. If the waiting Thread or Process becomes terminal,
terminal retirement cancels the registration and the Thread does not resume to
userspace merely to return `INTERRUPTED`. `INTERRUPTED` remains reserved for a
future resumable interruption mechanism.

---

## 8. Resumable blocking and scheduler state

DW0-F replaces E's terminal-only reschedule assumption. Scheduler state becomes:

```text
Reserved -> Runnable -> Running <-> Blocked
                         |             |
                         +-----> terminal retirement
```

Only the currently Running Thread may prepare its own Blocked transition. A
move-only block token contains scheduler-domain identity, Thread identity, and a
nonzero generation. Publication of Blocked consumes that token into the wait or
deadline registration. A wake carrying a stale/foreign generation is rejected and
can never make a later blocking generation runnable.

A blocked syscall retains its Thread-owned kernel stack and saved kernel/syscall
continuation. It does **not** return through E's `reschedule() -> !` contract and
later jump back into a Rust frame that was declared non-returning.
F2 must introduce a valid resumable architecture/runtime boundary that saves the
callee-preserved kernel execution context required to suspend inside a syscall,
switches to another runnable Thread's owned kernel stack/context, and later
returns normally from the suspension primitive. The resumed path then finishes
its syscall, authorizes the existing IRETQ user return, and returns the final
`DwStatus`/output to the original caller.

Blocking publication is a transaction: registration and block generation are
prepared before the Thread ceases to be Running, and failure to publish either
leaves it Running with no live registration. Waking removes the registration
before making the exact generation Runnable. A Thread is never both Runnable and
Blocked, and no scheduler queue contains two entries for one Thread.

Terminal retirement is legal from Running, Runnable, Reserved, or Blocked. If
Blocked, it first cancels/consumes the wait registration and block generation,
then performs the existing execution-resource and typed-task teardown. No wake
may resurrect a terminal Thread.

The existing one-shot raw syscall runtime binding remains an E8-R2 review target.
F2 may reuse it only if the stationary owner remains valid across context
switches and its current-Thread selection is explicit; otherwise F2 must replace
it with mechanically stable runtime ownership before general blocking is live.

---

## 9. Clock, deadline, timer interrupt, and IRQ-lock contract

ABI time remains absolute monotonic nanoseconds. `DW_DEADLINE_NOW == 0` requests
immediate deadline evaluation; `DW_DEADLINE_INFINITE` means no finite timeout.
`DW_CLOCK_BOOTTIME` stays unsupported in F.
For the DW0 q35 reference profile, F0 selects the **ACPI Power Management Timer**
as the `DW_CLOCK_MONOTONIC_ACTIVE` counter backend and the **Local APIC one-shot
timer** as the finite-deadline interrupt source.

This choice matches the accepted VM topology evidence: ACPI and APIC are enabled,
PIT exists, and HPET is explicitly disabled. F3 must locate and validate the PM
Timer through the FADT (`X_PM_TMR_BLK` when usable, otherwise `PM_TMR_BLK`),
verify a supported 24- or 32-bit fixed-rate counter, and prove it advances before
publishing the clock backend. If the designated q35 profile does not expose a
usable PM Timer, F3 stops and requests an F0 architecture revision; it must not
silently substitute an unreviewed TSC/HPET/PIT clock.

The PM counter is extended across wraps in kernel state. The timer service must
sample it often enough that at most one hardware wrap can occur between extension
updates; the implementation should schedule an internal maintenance deadline no
later than half the hardware wrap interval when no earlier user deadline exists.
Tick-to-nanosecond conversion uses checked wide arithmetic and never emits the
`DW_DEADLINE_INFINITE` sentinel as a real clock value.

The Local APIC timer is calibrated against the validated monotonic counter and is
programmed one-shot for the earliest of user/kernel deadline and PM-counter wrap
maintenance. Deadline programming rounds **outward** so a finite timeout is never
reported early merely because hardware ticks are coarse. An earlier inserted
deadline causes reprogramming.

TSC and TSC-deadline mode are permitted later optimizations only after explicit
capability/calibration proof. They are not required by F0/F3 correctness.
F3 introduces a small IRQ-safe lock/critical-section primitive for state shared
with the timer interrupt. On x86_64 its local-CPU acquisition disables maskable
interrupts before attempting the underlying SMP-safe lock and restores the prior
IF state on guard release. NMI/#DF/#MC paths never acquire this lock.

The timer ISR performs bounded operations only: acknowledge/EOI as required,
advance/read monotonic time, remove expired deadline registrations, publish wake
tokens, and select/reprogram the next deadline. It does not perform usercopy,
typed object finalization, process HandleTable mutation, or unbounded traversal.
Deferred cleanup runs after interrupt/shared-state ownership is released.

`timer_set(deadline)` atomically replaces the prior arm and clears prior
`SIGNALED` state. `INFINITE` is `INVALID_ARGUMENT`; a deadline at or before the
current clock becomes signaled as part of the set transaction. Timer expiration
is one-shot and leaves `SIGNALED` asserted until `timer_set` or `timer_cancel`.
`timer_cancel` disarms and clears `SIGNALED`.

---

## 10. Event and waitable-signal publication

Event is a manual-reset waitable object. Creation starts unsignaled.
`event_signal` accepts exactly one of:

- `clear_mask = SIGNALED`, `set_mask = 0`; or
- `clear_mask = 0`, `set_mask = SIGNALED`.

Any unknown bit, overlap, or both-empty request is `INVALID_ARGUMENT` before
mutation. Repeating set or clear is successful and idempotent.
All waitable objects expose a current level signal snapshot through one typed
wait interface. Implementations may cache the derived signal bitset atomically,
but that cache is observability state, not a second lifetime/task/queue authority.
Its value must be updated at the owning subsystem's committed state transition.

Process/Thread `EXITED` is published only after the terminal task state is
committed. Channel signals are derived from committed pair/queue state. Event and
Timer `SIGNALED` are derived from their typed payload state. Signal notification
occurs after committed state is visible.

Wait registration owns generic InternalRef pins to each target object, so typed
finalization cannot race a sleeping wait. A finalizer therefore never needs to
walk dangling wait registrations; by the time generic final release exists, no
wait pin for that object can remain.

---

## 11. `atomic_wait32` stable identity and lost-wakeup rule

The ABI key is **not** a raw virtual address. F9 resolves an aligned mapped
userspace word to stable backing identity:

```text
AtomicWaitKey = (MemoryObjectKey generation, byte offset within MemoryObject)
```

Two virtual addresses, including addresses in different Processes, address the
same wait key when they resolve to the same live MemoryObject generation and the
same four-byte object offset. This permits native shared-memory synchronization
without adopting Linux futex ABI.

Both wait and wake require a lower-canonical, nonzero, 4-byte-aligned userspace
range that resolves completely to one currently readable MemoryObject mapping.
Misaligned, kernel, unmapped, overflowed, or noncanonical ranges fail
`BAD_ADDRESS` before waiter publication.
`atomic_wait32` holds a mapping/backing pin for the complete blocked interval. An
intersecting `AddressRegion` unmap/protect operation therefore returns the existing
`BAD_STATE` mapping-mutation conflict while that wait pin is live. This is an
accepted DW0 liveness limitation; it prevents mapping ABA and stale physical-word
identity while preserving correctness.

The wait algorithm is fixed:

1. validate/pin the four-byte range and derive `AtomicWaitKey`;
2. acquire the bounded wait-key bucket/registry barrier;
3. perform the aligned architecture-safe 32-bit load through the still-live pin;
4. if the value differs from `expected`, release and return `WOULD_BLOCK`, even
   when the supplied deadline is already expired;
5. otherwise evaluate the deadline, prepare/register the exact block generation,
   re-read the word under the registration barrier, and block only if it still
   equals `expected`.

The re-read plus `atomic_wake` using the same key registry closes the
compare/register lost-wakeup window. `atomic_wake` does not modify userspace
memory; userspace changes its atomic predicate before wake according to its own
memory-order protocol.

Wake count zero is a successful no-op with `out_woken = 0`, but address identity
and output storage are still validated. `DW_ATOMIC_WAKE_ALL` wakes every currently
registered waiter for the exact key; other counts wake at most that many in
stable registration order. Woken waiters may return successfully even when the
word still equals the old expected value; this primitive explicitly permits that
spurious/predicate-race outcome and callers must recheck their predicate.

---

## 12. Public `process_create` all-or-nothing transaction
F10 activates the E0-staged syscall by composing, not replacing, E's typed
Process/AddressRegion lifetime rules with F's handle-move machinery.

Validation/preparation order is:

1. exact `DwProcessCreateArgsV1` size/version/zero-reserved/zero-flags checks;
2. process/root-region/child-bootstrap requested-right syntax and compatibility;
3. exact `DwProcessCreateResultV1` output preflight/pin;
4. resolve parent TaskGroup with `MODIFY`;
5. resolve bootstrap handle as `CHANNEL` with `TRANSFER` and validate
   `child_bootstrap_rights` as a nonzero compatible subset;
6. reserve parent TaskGroup construction/attachment capacity without publishing a
   child;
7. prepare an unpublished Process plus root AddressRegion through the existing E
   typed factories/lifetime authorities;
8. reserve two parent result HandleTable slots and one child bootstrap slot;
9. prepare the parent bootstrap-handle MOVE without invalidating it; and
10. enter the no-fail commit sequence.

F10 may refactor the existing internal `create_process` factory into explicit
prepare/commit pieces, but it must preserve the E typed-construction, execution
pin, parent ownership, root-region, and finalizer invariants rather than creating
an F-specific parallel task model.

A cross-subsystem reservation may temporarily prevent parent TaskGroup teardown
or conflicting HandleTable mutation, but unpublished child state must not be
visible as a normal Process/child relationship during preparation. Reservation
objects are generation-bound, move-only, and must be cancelable without leaving
payload or generic-object liveness behind.
The F10 commit uses a coarse cross-subsystem transaction guard or an equivalent
proof that prevents another kernel operation from observing the covered parent
TaskGroup/parent HandleTable/child HandleTable surfaces between component
commits. Internal task and HandleTable locks are still acquired sequentially,
never nested, preserving E0 lock ordering.

While that observation barrier is held, commit is no-fail and performs:

1. extract/invalidate the parent's reserved bootstrap Channel source slot exactly
   once, yielding its existing generic handle reference as the move value;
2. publish that moved reference into the child's reserved HandleTable slot with
   `child_bootstrap_rights`;
3. commit the Process/root-region typed construction and parent-group attachment;
4. publish the parent Process and root-region result handles into their reserved
   slots; and
5. release the observation barrier, making the complete creation transaction
   visible as one logical commit.

The already-pinned result structure is then filled with the two parent-local
handles and the child-local bootstrap raw value. No copyout failure remains.
`child_bootstrap_handle` is metadata only; lookup in the creating parent's table
must not resolve it unless an unrelated parent handle coincidentally has the same
opaque bits.

Any failure before commit cancels every reservation and unpublished construction,
leaves the bootstrap Channel handle valid in the parent with unchanged rights,
and publishes no child Process, root region, child bootstrap handle, parent result
handle, or hierarchy membership.

Process creation does not start a Thread, parse an ELF, map an executable, or
create the DW0-G primordial bootstrap protocol. The returned Process remains
`CREATED` until ordinary E thread creation/start operations make it run.

---

## 13. Lock ordering, waiter lifetime, and deferred cleanup
No F spin/IRQ lock may be held across a scheduler context switch or while a
Thread sleeps. Blocking always consumes prepared registrations/tokens after all
short critical sections are released.

Subsystem transitions collect wake intents while owning their typed state, then
release that state before making Threads Runnable. The timer ISR similarly
collects exact block-generation wake tokens under IRQ-safe state and performs only
the bounded scheduler handoff permitted by F3's reviewed interrupt boundary.
Typed finalizers and generic final completion remain deferred beyond both.

The preferred dependency order for ordinary thread-context operations is:

```text
usercopy / mapping pins and transaction reservations
        -> process HandleTable mutation
        -> typed Channel/Event/Timer state
        -> wait/deadline registry
        -> scheduler wake/block state
        -> narrow ObjectRegistry retain/release bookkeeping
```

An implementation may avoid nesting entirely through prepare/commit tokens. If it
nests, it may only follow the documented direction and must still preserve E0's
specific prohibition on simultaneous task hierarchy/state and Process HandleTable
locks. IRQ context uses only the explicitly IRQ-safe subset.

Channel finalization, queue drain, wait cancellation, task termination, and Timer
cancellation may yield generic final-release authorities. Those are accumulated
into bounded cleanup queues and routed through the existing typed finalizer
mechanism only after lock ownership is gone.

---

## 14. Status and edge-case matrix
F implementations and model tests must preserve at least these outcomes:

| Case | Required status / behavior |
|---|---|
| Channel payload or transfer count exceeds ABI maximum | `INVALID_ARGUMENT`, no mutation |
| Nonzero Channel buffer count with invalid userspace range | `BAD_ADDRESS`, no mutation |
| Duplicate source handle in one transfer list | `INVALID_ARGUMENT`, no mutation |
| Transfer operation other than MOVE | `INVALID_ARGUMENT`, no mutation |
| Transfer requests unknown/zero/incompatible rights | `INVALID_ARGUMENT`, no mutation |
| Transfer requests rights not held by source | `ACCESS_DENIED`, no mutation |
| Transfer source lacks `TRANSFER` | `ACCESS_DENIED`, no mutation |
| Destination endpoint is transferred into its own inbound queue | `INVALID_ARGUMENT`, no mutation |
| Valid send to closed peer | `PEER_CLOSED`, sources unchanged |
| Valid send to open peer with no reservation capacity | `WOULD_BLOCK`, sources unchanged |
| Receive head does not fit supplied capacities | `BUFFER_TOO_SMALL`, head remains queued |
| Receive has capacity but destination HandleTable cannot reserve all slots | `NO_RESOURCES`, head remains queued |
| Empty receive queue with open peer | `WOULD_BLOCK` |
| Empty receive queue with closed peer | `PEER_CLOSED` |
| Wait mask zero/incompatible with resolved object | `INVALID_ARGUMENT` |
| Wait signal already ready and deadline expired | ready `SUCCESS` wins |
| No signal ready and finite deadline already expired | `TIMED_OUT` |
| `atomic_wait32` value already differs from expected | `WOULD_BLOCK` wins over timeout |
| `atomic_wait32` invalid/misaligned mapping | `BAD_ADDRESS`, no registration |
| `atomic_wake` count zero | `SUCCESS`, zero woken after normal validation |
| Timer set with `INFINITE` | `INVALID_ARGUMENT`, prior arm unchanged |
| `WAIT_ALL` / `DW_CLOCK_BOOTTIME` in F | `NOT_SUPPORTED` |

Statuses caused by bounded internal pool exhaustion use `NO_RESOURCES` when the
operation is object/slot capacity allocation and `WOULD_BLOCK` when the exhausted
resource is specifically current Channel queue admission/backpressure.

---

## 15. F guest-test identities and evidence boundary
F0 reserves these build-owned identities in `tooling/guest-harness.toml` without
claiming that guest bodies exist yet:

- ID 13 `ipc-blocking-smoke` — mandatory F end-to-end Channel/block/resume gate;
- ID 14 `ipc-transfer-rollback` — handle move/rights/rollback adversarial gate;
- ID 15 `wait-deadline-timer` — generic wait, finite deadline, Event/Timer gate;
- ID 16 `atomic-wait-wake` — shared backing wait/wake gate; and
- ID 17 `process-create-bootstrap` — public process creation/bootstrap move gate.

E IDs 10-12 remain unchanged. A reserved identity is not executable evidence.
Build/test code should add each F selector to target dispatch only when its real
body exists and the accepted-toolchain artifact oracle can distinguish it from
production.

F12 may use ID 13 as the single mandatory canonical VM selector if it exercises
the shared architecture path required by the F plan; IDs 14-17 remain targeted
follow-on selectors unless their individual VM execution is needed to resolve a
failure or acceptance ambiguity. Host/model tests remain the stronger evidence
for exhaustive rollback interleavings.

---

## 16. Wyrmroot consumer impact

F0 changes no Deepwyrm ABI schema, generated ABI file, boot contract, or
`kernel/arch/x86_64/layout.toml`. Wyrmroot's current compatible Deepwyrm
ABI/layout pin therefore requires **no F0 consumer change or repin**.

Later F implementation can still pair with the current Wyrmroot loader for a
Deepwyrm-owned synthetic guest if those compatibility surfaces remain unchanged.
Any later ABI/layout delta must be routed explicitly through the coordinator and
may change the F12 pairing requirement.

Public `process_create` semantics become live in F, but Wyrmroot need not consume
that syscall during F0. DW0-G remains responsible for the real primordial
Wyrmroot bootstrap process and bootstrap protocol.
---

## 17. Required implementation handoff

F1-F10 implementation must treat the following as fixed F0 outputs:

- no F ABI schema/layout amendment is required to start implementation;
- Channel pair storage is non-ABI, generation-protected, and cannot own peer
  generic-object liveness;
- destination-endpoint self-enqueue is the one explicit ABI-0 Channel transfer
  rejection beyond ordinary rights/type validation;
- committed datagrams survive sender-side peer closure while the receiving
  endpoint remains live;
- handle MOVE and receive publication are batch all-or-nothing transactions;
- generic wait is level-triggered, non-spurious, duplicate-item tolerant, and
  deterministic lowest-index `WAIT_ANY`;
- the scheduler gains a generation-protected Blocked state and a real resumable
  kernel continuation boundary before blocking syscalls become active;
- the reference F clock is ACPI PM Timer with Local APIC one-shot deadline IRQs
  and a new IRQ-safe critical-section primitive;
- `atomic_wait32` keys on MemoryObject generation + byte offset and pins the
  mapping/backing across sleep; and
- public `process_create` uses a fully prepared cross-subsystem transaction and
  reuses E task factories/lifetime rules.

Any implementation evidence that requires changing one of these items stops at
the owning phase and routes an explicit F0 contract revision before dependent
work continues. ABI 0 is unstable, but accidental drift is still prohibited.

F0 does not require an F target build, VM run, Daybreak review, or Wyrmroot
mutation. Those belong to later F gates.

---

## 18. Reference specifications for F3 implementation
F3 should validate its implementation against the architecture/vendor sources,
while Deepwyrm's ABI schema remains the software contract:

- ACPI Specification 6.6, FADT and PM Timer fixed-hardware sections: PM timer
  discovery, 24/32-bit width, fixed-rate free-running counter, and extended GAS;
- Intel 64 and IA-32 Architectures Software Developer's Manual, Local APIC timer
  and interrupt-delivery sections; and
- the exact accepted q35/libvirt profile recorded by Deepwyrm VM evidence.

The accepted E7/E8 transient q35 profiles currently record `<acpi/>`, `<apic/>`,
PIT enabled, and HPET explicitly absent. That repository-local evidence is why
F0 does not select HPET as the DW0 reference clock.

No implementation should infer the presence of PM Timer, xAPIC timer mode, or
frequency from the machine name alone. F3 must validate the actual booted
reference machine before enabling finite deadlines.

---

## 19. DW0-F0 disposition

F0 closes the architecture questions intentionally left open after E:

- Channel endpoint/pair lifetime and peer-close queue ownership;
- send/receive linearization and backpressure status ordering;
- exact handle MOVE validation, rollback, and self-reference behavior;
- receive HandleTable reservation/publication semantics;
- generic signal compatibility and race-free `WAIT_ANY` registration;
- resumable blocking control flow and generation-protected scheduler state;
- reference monotonic clock, deadline interrupt, and IRQ-lock ownership;
- stable cross-mapping `atomic_wait32` identity and pin behavior;
- all-or-nothing public `process_create`; and
- canonical F guest-test identities and evidence boundaries.

With this contract committed and the reserved harness IDs verified, F1 may begin.
No statement in this document claims that any F runtime mechanism is implemented,
that any F guest selector has executed, or that formal F Daybreak review has run.
