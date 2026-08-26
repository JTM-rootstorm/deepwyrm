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
immediately before each permitted CPL3 return, including first entry, syscall
resume, and timer-origin resume. Dispatch deadline construction uses checked
addition from a fresh monotonic-active sample.

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
layout. The frame remains on the interrupted Thread's owned kernel stack. It is
not copied into CPU-private storage or another Thread's memory.

Kernel-origin timer interrupts retain the current bounded dispatch-and-return
path and never call the CPL3 preemption gate.

For CPL3 origin, assembly:

1. preserves all GPRs in the exact frame above;
2. normalizes GS as it does today;
3. calls the timer interrupt dispatcher, which services sources and EOI;
4. restores the frame pointer and passes it to
   `dw_x86_64_timer_pre_iret_gate`;
5. restores user GS and GPRs only after that gate returns; and
6. executes `iretq`.

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
- first entry, syscall resume, and timer resume quantum arms; and
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
