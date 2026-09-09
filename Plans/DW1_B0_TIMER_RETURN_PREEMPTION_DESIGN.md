# Deepwyrm DW1-B0 CPU0 Timer-Return Preemption Design

**Status:** Reached design; authoritative for DW1-B implementation
**Prepared:** 2026-08-26
**Deepwyrm baseline:** `419af582b3beca0208dfa802a113e4547e4f5620`
**Paired Wyrmroot baseline:** `f6d4044be33a812a91eb7da2a8c9b9251e5736e0`
**Parent contract:** `DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md`
**Milestone:** one-CPU timer-driven userspace preemption

This design closes the architecture seam between the existing Local APIC timer
interrupt, the normal scheduler contract, and the first involuntary switch of
an uncooperative CPL3 Thread. It adds no syscall, object, right, status, stable
record, userspace scheduler control, AP scheduling, or Wyrmroot ABI.

The DW1-A0 contract remains authoritative. This document makes its CPU0
timer-return boundary concrete before source implementation.

## 1. Scope

DW1-B implements only:

- CPU0's normal FIFO round-robin queue;
- the fixed `5_000_000 ns` normal quantum;
- one scheduler source in the existing CPU0 Local APIC deadline owner;
- an exact-generation coalescing reschedule request; and
- involuntary switching at a validated CPL3-origin timer-return boundary.

AP Local APIC timers and ordinary AP userspace scheduling remain disabled for
this phase. Work stealing, migration, four-CPU fairness, public affinity,
priorities, scheduler classes, arbitrary kernel preemption, and hard latency
promises remain DW1-C or later work.

## 2. Physical timer ownership

`kernel/src/time/live.rs` remains the sole CPU0 owner allowed to program, stop,
or reprogram Local APIC vector `0xe0`. Scheduler code must not call
`LocalApic::program_one_shot_timer` directly.

The CPU0 deadline arbiter owns three logical sources:

1. the existing wait/deadline queue;
2. the existing Timer-object deadline queue; and
3. one scheduler quantum source.

Each source has an independent nonzero generation. The physical arm also has a
nonzero generation and records the sampled monotonic-active deadline it was
intended to serve. The xAPIC vector carries no arm generation; a delivered
interrupt is therefore only a request to sample and reconcile current arbiter
state. A late vector from an older physical arm may cause a harmless rescan and
reprogram, but it cannot expire, cancel, or clear a newer logical source.

Under the arbiter's IRQ-safe state lock, source replacement or interrupt
service:

1. samples monotonic-active time;
2. validates and collects every exact source generation due at that sample;
3. computes the earliest remaining source deadline; and
4. produces a move-only hardware-arm intent.

The arbiter lock is dropped before Local APIC MMIO, wait/timer callbacks,
scheduler mutation, or a userspace-return decision. After guard-free MMIO, the
arbiter revalidates the intended physical-arm generation. If a newer source
update won, the actual earliest deadline is programmed before return.

Equal due deadlines are serviced in this order:

1. publish existing wait and Timer-object expirations;
2. publish the matching scheduler quantum-expiry request;
3. recompute the earliest remaining deadline;
4. program the physical one-shot when a deadline remains; and
5. acknowledge/EOI the interrupt independently of later switch eligibility.

Already-due sources are dispatched in a bounded loop rather than programmed as
a zero hardware count. Conversion remains outward-rounded, checked, and inside
the PM-timer maintenance bound.

## 3. Quantum and reschedule identity

Every CPU0 dispatch that may return to CPL3 owns:

```text
QuantumTicket {
    cpu,
    thread,
    execution_generation,
    source_arm_generation,
    deadline_ns,
}
```

All identities and generations are exact and nonzero. A quantum begins
immediately before the selected execution's first permitted CPL3 return,
including first entry, syscall resume, and timer-origin resume. Returns within
an existing quantum preserve its exact budget. Dispatch deadline construction
uses checked addition from a fresh monotonic-active sample taken only after
the carrier's synchronized runtime preparation, immediately before calling
scheduler quantum preparation. Waiting to acquire the coarse runtime guard
does not consume a budget that has not yet begun.

The timer source may publish one coalescing request only when the ticket, CPU0
Running claim, and execution generation still match. Repeated matching vectors
retain one request. A stale vector or ticket clears no state belonging to a
later dispatch.

Quantum expiry always increments the exact CPU counter. It increments
involuntary-preemption accounting only when a peer is selected and a physical
switch is committed. If no eligible peer is runnable, the current Thread is
retained, the exact request is consumed, and a fresh ticket is armed without a
manufactured context switch.

## 4. Raw CPL3 timer-return frame

The existing timer entry's stack image becomes one typed in-place frame:

```rust
#[repr(C)]
struct RawCpl3TimerReturnFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}
```

The frame is exactly 160 bytes and eight-byte aligned. Offsets are:

| Field | Offset |
| --- | ---: |
| `r15` | 0 |
| `rax` | 112 |
| `rip` | 120 |
| `cs` | 128 |
| `rflags` | 136 |
| `rsp` | 144 |
| `ss` | 152 |

Assembly constants and Rust compile-time/source-contract tests bind the same
layout. As required by the locked E0 entry contract, the architectural frame
initially lands on the CPU-private privilege-entry stack selected by TSS RSP0.
After source dispatch and EOI, but before the pre-IRET gate can retain a kernel
continuation, assembly copies the complete frame onto the interrupted Thread's
owned kernel stack. The CPU-private image is then abandoned and may be reused;
only the Thread-owned image may survive a preemptive switch.

Kernel-origin timer interrupts retain the current bounded dispatch-and-return
path and never call the CPL3 preemption gate.

For CPL3 origin, assembly:

1. preserves all GPRs in the exact frame above;
2. normalizes GS as it does today;
3. calls the timer interrupt dispatcher, which services sources and EOI;
4. copies the complete frame from the E0 CPU-private landing stack to the
   currently bound Thread kernel stack;
5. restores the Thread-owned frame pointer and passes it to
   `dw_x86_64_timer_pre_iret_gate`;
6. restores user GS and GPRs only after that gate returns; and
7. executes `iretq`.

The gate returns normally only when the same frame belongs to the current
Running Thread and is authorized for CPL3 return. If it switches away, the
saved kernel continuation later resumes inside the gate and repeats current
carrier, scheduler, root, mailbox, and return-frame validation before assembly
may consume the retained frame.

## 5. Asynchronous return validation

Every eventual timer-frame `iretq` requires:

- exact user code selector `0x33` and user data selector `0x2b`;
- lower-canonical, nonzero RIP and RSP;
- the canonical userspace `RFLAGS` sanitization policy;
- an executable/readable RIP mapping for the current Process;
- a writable byte immediately below RSP in that Process;
- the exact CPU0 Thread/Process/execution/root binding; and
- no pending terminal or authoritative remote-stop transition.

Validation uses the current Process mapping authority after the runtime/root
binding has been re-established. Failure becomes the existing structured
invalid-user-return terminal path and pivots to the CPU-private reaper. It is
never repaired into a different userspace frame and never returns to CPL3.

## 6. Scheduler transition

`preempt_current_on(CPU0, exact_claim)` is distinct from voluntary yield.

With an eligible local peer it atomically:

1. validates the current Running claim and request generation;
2. moves the current Thread to CPU0's FIFO tail with exact continuation
   ownership;
3. claims the oldest eligible peer as Running;
4. records the move-only suspended-continuation/switch identities; and
5. produces a switch decision after scheduler invariants pass.

With no eligible peer it retains the current Thread as described in Section 3.
Block preparation, committed block, terminal transition, unacknowledged remote
stop, scratch/root transaction, preemption-disable depth, or a stale identity
prevents requeue. Terminal and Stop win monotonically. A committed block wins
over quantum expiry. A wake committed before the gate's scheduler decision may
make its peer eligible through the ordinary queue path.

## 7. Guard-free physical switch

The timer-return gate uses a dedicated move-only preparation/finish interface;
it must not retain the coarse runtime, scheduler, paging, mapping, wait, or
arbiter guard across a switch.

Preparation validates and captures:

- outgoing and incoming exact Thread/Process/execution identities;
- outgoing continuation stack ownership;
- incoming fresh or suspended continuation;
- root-binding and CPU0 carrier transition tokens; and
- the architecture-owned fresh-entry or resume target.

After all guards are dropped, the gate binds the incoming Thread stack and
executes the existing kernel context switch. Destination arrival completes the
outgoing suspended-continuation publication only after the incoming stack,
root, and carrier are live.

A fresh Thread enters through the existing fixed first-run entry. A
syscall-suspended Thread resumes its syscall trampoline. A timer-suspended
Thread resumes the timer gate, reacquires CPU0's immutable carrier binding,
completes the physical handoff, revalidates its retained frame, arms a fresh
quantum, and returns to assembly.

## 8. Safe-boundary precedence

Before consuming a reschedule request and again before CPL3 return, the timer
gate polls the same authoritative mailbox ordering as syscall return:

1. remote Stop or terminal handoff;
2. committed block/suspension ownership;
3. exact reschedule request;
4. ordinary authorized CPL3 return.

Preemption-disable depth is checked arithmetic. A matching request remains
deferred while depth is nonzero or another non-preemptible transition owns the
carrier. Overflow, underflow, or an unbalanced return is fail-stop.

The normal syscall-return path also checks the same request after usercopy,
adapter dispatch, frame sanitization, and rendezvous polling have released all
guards. This prevents an expiry during kernel work from waiting for a second
hardware interrupt. Both syscall-origin and timer-origin paths use the same
scheduler preparation and physical completion rules.

The live return seam supplies a deferred one-shot clock sampler through the
native runtime interface. The facade forwards it into the synchronized
operation without invoking it. The carrier samples after acquiring runtime
authority, releases the independent clock guard, then enters scheduler
preparation with the fresh timestamp. Clock and scheduler guards are never
nested. The scheduler still mints only a genuinely absent quantum; preserved
budgets and pending requests do not refresh their deadlines. Stopped return
preparation does not invoke the sampler. All runtime/scheduler guards are
dropped before hardware reconciliation.

A delay after quantum minting can still consume a complete quantum before
hardware reconciliation. When that reconciliation finds the new ticket
already due, it publishes the exact request synchronously. On an AP the
consumed scheduler source was its only
timer source, so this path masks the physical timer. Returning directly to a
CPU-bound userspace Thread would then leave no timer to cause the next safe
boundary.

The arm seam therefore reports synchronous expiry to its caller. Both timer
and syscall return repeat the established Stop, validation, scheduling, and
arm sequence until arming leaves a live source instead of publishing another
request. First entry's existing IRET helper pivots from the bootstrap, idle, or
reaper carrier onto the bound Thread stack before saving all initial registers
as the same 160-byte asynchronous-return frame. Only then may its shared gate
retain a preempted continuation; restoration consumes the gate-authorized
values. An already-due ticket is never silently replaced with a later
deadline, and repeated syscall return still preserves the current budget.
The fresh sample excludes pre-runtime-lock preparation contention from the new
budget; it does not bound subsequent scheduler-lock or post-mint delays, or
prove the retry loop always ends.
The exact immediate-expiry rule, quantum, scheduling policy, interrupt entry,
and native ABI remain unchanged.

## 9. Validation

Host/model tests must cover:

- exact frame size, offsets, selectors, canonicality, mapping checks, and
  RFLAGS sanitization;
- timer assembly ordering: source dispatch/EOI, pre-IRET gate, GS/GPR restore,
  then `iretq`;
- arbiter earlier/later/equal deadlines, cancel/rearm, immediate expiry,
  checked conversion, stale physical vectors, and reprogram races;
- matching and stale request coalescing;
- peer switch, no-peer retain/rearm, block/terminal/Stop precedence;
- continuation ownership and Thread-generation reuse;
- first entry, syscall resume, and timer resume quantum arms;
- delayed synchronized preparation starting a fresh full budget, while
  preserved budgets and unconsumed expiry requests retain their deadlines; and
- source/lock-order assertions that no forbidden guard spans APIC MMIO,
  context switch, or userspace return.

The live gate uses canonical one-vCPU q35/OVMF media and proves:

- a ring-3 CPU hog performing no syscall, yield, or block is involuntarily
  preempted;
- a second runnable native Process makes bounded progress;
- the ordinary WYR0 bootstrap/init/hello chain still succeeds;
- one-runnable and idle cases manufacture no switch;
- deferred expiry during kernel work is consumed at the next safe return;
- a hog plus repeated Channel wakeups preserves progress; and
- structured scheduler evidence records matching quantum-expiration and
  involuntary-preemption facts.

Serial text alone is not acceptance evidence. The selector and evidence
identity are reserved through the canonical harness before implementation.

## 10. Required-source and provenance disposition

The root DW1-B plan, Deepwyrm architecture index, DW1-A0 contract/validation,
and reached DW0-F/H/I timer, scheduler, carrier, root, blocking, remote-stop,
and reaper contracts were used as authority.

Fuchsia/Zircon `zircon/kernel/kernel/scheduler.cc` at
`6a606ff7fd9b055edee6557566fb3f112df1a812` informed exact CPU ownership,
generation-bound preemption-deadline reset, and deferred-preemption comparison.
xv6-riscv `kernel/proc.c` and `kernel/trap.c` at
`35b088427ef37611c38afdeed5a52a278cae38f9` informed only the deliberately
small timer-to-reschedule test shape. Both were used conceptually; no upstream
source code or ABI was copied or adapted.

This document is first-party `GPL-2.0-or-later` work. Existing component/file
license declarations remain unchanged.

## 11. Selector-26 paired evidence contract

Selector `normal-preemption-up`, test ID `26`, uses one test-build-only raw
operation number, `0xFFFF_FF1A`. It is absent from the generated public ABI and
production kernels. Selector 25 retains its distinct `0xFFFF_FF19` operation,
collector, capacity, and transcript.

The raw argument forms are exact:

```text
ARM:
    arg0 = 1
    arg1 = CPU-hog Process handle
    arg2 = progress Process handle
    arg3 = 8
    arg4 = 0
    arg5 = 0

PROGRESS:
    arg0 = 2
    arg1 = 8
    arg2 = fixed challenge/reply digest
    arg3 = 0
    arg4 = 0
    arg5 = 0
```

The selector build binds a nonzero uppercase-hex evidence nonce and expected
challenge digest through `DEEPWYRM_DW1B_EVIDENCE_NONCE` and
`DEEPWYRM_DW1B_CHALLENGE_DIGEST`. PROGRESS must match those frozen values.

ARM is accepted only from the exact committed first child of primordial, the
existing init0 Process. It resolves two distinct live Process handles, each
with exactly one live Thread, and records their generation-safe kernel
identities. The hog Thread must be Runnable or Running. The progress Thread may
also be Blocked; the paired Wyrmroot product audit establishes that it waits on
its empty data Channel after READY and that the first post-ARM challenge wakes
it. PROGRESS is accepted once, after ARM, only from the exact bound progress
Process. The Wyrmroot product freezes the challenge/reply digest and audits that
this child submits PROGRESS only after its eight correlated Channel exchanges;
Deepwyrm checks the exact count and digest without admitting them to the public
ABI.

The selector collector observes scheduler transitions independently of
userspace. It must see the exact registered hog Thread Running after ARM and at
least one involuntary switch whose outgoing identity is that exact Thread.
Repeated exact outgoing-hog preemptions are legitimate and idempotent;
aggregate CPU counters alone cannot establish this fact.

Successful `complete_primordial_launch` accepted by the existing G5 probe is
the ordinary WYR0 bootstrap/init0/hello proof: hello READY, exit zero, cleanup,
and primordial completion were normal. Deepwyrm sets both the ordinary-hello
and primordial-normal facts only at that genuine completion boundary. This is
joined with the exact progress-child submission and the global `wakeups >= 8`
relation; the paired Wyrmroot payload/model audit proves those wakes represent
the child's correlated exchange loop.

At normal primordial completion, Deepwyrm emits exactly one fixed 122-byte
summary immediately before the canonical PASS `DWTEST1` terminal:

```text
DWPRE1|01|NNNNNNNNNNNNNNNN|00000000|QQQQQQQQQQQQQQQQ|PPPPPPPPPPPPPPPP|CCCCCCCCCCCCCCCC|WWWWWWWWWWWWWWWW|FFFFFFFF|CCCCCCCC\n
```

The fields are, in order: build-owned nonzero nonce, CPU ID, quantum-expiration
delta, involuntary-preemption delta, context-switch delta, wakeup delta,
required fact mask, and uppercase FNV-1a-32 checksum over every byte preceding
the checksum field. The fact mask is exactly `0x000000FF`:

1. exact hog and progress identities bound;
2. the exact hog observed Running after ARM;
3. the exact outgoing hog involuntarily preempted;
4. the progress actor completed eight Channel exchanges;
5. ordinary hello READY, exit-zero, and cleanup completed;
6. exact hog termination and reap completed once;
7. primordial/bootstrap completion was normal; and
8. scheduler accounting remained non-overflowed.

PASS additionally requires `1 <= involuntary_preemptions <=
quantum_expirations <= 256`, `context_switches >=
involuntary_preemptions`, `wakeups >= 8`, the exact outgoing-hog fact, and
canonical `DWTEST1` test ID 26/detail zero. The host must require the matching
debug-exit status; serial text alone remains insufficient.

Selector 26 has an independent four-descendant-capable runtime budget. Its
bootfs mapping-page ceiling remains pending measurement of the frozen Wyrmroot
payload and must not reuse or change selector 25's measured 42-page exception.
The selector build therefore requires the measured canonical-decimal
`DEEPWYRM_DW1B_BOOTFS_MAX_PAGES` input (bounded to `1..=8192`) and compiles that
value into selector-local mapping journal, invalidation, and admission bounds.
