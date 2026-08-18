# Deepwyrm DW0-E0 Task and Syscall Contract

**Status:** DW0-E0 contract closure; authoritative for DW0-E implementation  
**Deepwyrm baseline:** `f9ba441ba4b2536033cf88a58afc29c85cd00e62`  
**Wyrmroot read-only baseline:** `5678ebaf1bb16f56c2d635d1a7507d1dd7888de3`  
**Milestone:** DW0-E syscall entry and task model

This contract closes the architecture questions that must be settled before
DW0-E task, scheduler, syscall-entry, and CPL3 implementation begins. It
refines the canonical DW0 plan without pulling Channel queues/transfer, waits,
timers, primordial ELF loading, or later resource policy into E.

The canonical DW0 plan, pre-phase-zero invariants, locked addenda, generated
ABI schema, and DW0-D validation/security records remain authoritative. Where
this document tightens an ABI-0 staging choice, it is an explicit architecture
revision rather than an implementation accident.

DW0-D's D7 residuals R1/R2 become E implementation prerequisites: task objects
must not enter production on top of protocol-only payload construction or
untyped finalization completion.

---

## 1. `process_create` activation is deferred to DW0-F

The current `DwProcessCreateArgsV1` requires a `CHANNEL` handle with `TRANSFER`
and requires that handle to move into the child only on complete success. Real
Channel objects and handle-transfer transactions belong to DW0-F.
DW0-E therefore owns the reusable **process construction core**, but the public
bootstrap-channel-bearing `process_create` syscall is activated in DW0-F. Its
numeric syscall ID and V1 record layouts remain unchanged; only its generated
implementation-phase metadata moves from `DW0-E` to `DW0-F`.

Rules:

- E implements an internal process factory that requires no Channel object.
- E's generated dispatcher returns `NOT_SUPPORTED` for `process_create`.
- F reuses the E process factory and adds the required sender validation,
  rights reduction, receiver-local publication, and atomic Channel-handle move.
- F must not reimplement E's process/task lifetime or rights semantics.
- G may construct the primordial process through the internal kernel factory,
  then attach its real bootstrap Channel before the initial thread starts.
- No fake Channel type, placeholder queue, magic bootstrap handle, or
  transfer-shaped ambient authority is permitted in E.

This staging preserves WYR0's eventual native process-creation contract while
keeping the E/F dependency graph acyclic.

---

## 2. Task lifecycle is explicit and monotonic

Thread ABI state is exactly:

```text
CREATED -> RUNNING -> EXITED
```
A thread starts at most once. `thread_start` on RUNNING or EXITED returns
`BAD_STATE`. Closing its handle never changes task state. A created or running
thread owns one generic execution/scheduler internal reference so closing the
last external handle cannot terminate it.

Process ABI state is exactly:

```text
CREATED -> RUNNING -> EXITED
```

A newly created process may temporarily contain zero threads while CREATED;
this is the construction interval implied by separate process/thread creation.
The first successful thread start transitions the process to RUNNING. No thread
may start in an EXITED process.

`thread_exit(code)` records normal exit for only the calling thread. If another
live thread remains, the process stays RUNNING. If it was the final live thread,
the process atomically transitions to EXITED with `NORMAL_EXIT` and the same
32-bit application code.

`process_exit(code)` is process-wide. The process transitions to EXITED with
`NORMAL_EXIT` and `application_code = code`; every live thread is made terminal
before the process can be observed EXITED. The calling thread records the same
normal-exit code. Other live threads are terminated as part of that process-wide
operation and record `AUTHORIZED` with zero application code/detail.

Terminal Process and Thread states never transition again. Exited objects remain
inspectable and later waitable while generic references remain.
### 2.1 Unhandled userspace exceptions are process-fatal in DW0-E

Until a later structured userspace exception-delivery mechanism exists, an
unhandled CPL3 exception terminates the faulting process rather than panicking
the kernel or synthesizing a POSIX signal.

The process records `UNHANDLED_EXCEPTION` plus the native exception type,
reason-specific detail, and fault address where applicable. The faulting thread
records the same structured exception termination. Any sibling live threads are
terminated with `AUTHORIZED`; they must not falsely claim to have faulted.

Kernel-origin exceptions retain the existing fail-stop policy. DW0-E does not
make arbitrary ring-0 faults resumable merely because CPL3 handling exists.
Double fault, machine check, and other explicitly terminal architecture paths
remain terminal kernel paths.

### 2.2 TaskGroup teardown

TaskGroups use an internal monotonic lifecycle:

```text
ACTIVE -> TERMINATING -> TERMINATED
```

`TERMINATING` rejects new child attachment. Recursive teardown snapshots or
otherwise pins each direct descendant before mutation, then terminates child
groups/processes without holding locks across subsystem finalization.
Descendant Process/Thread termination records use `TASK_GROUP_TEARDOWN`.
TaskGroup state is kernel-internal in E; `DW_OBJECT_INFO_TASK_STATE_V1` remains
valid only for Process and Thread as already specified by DW0-D.

---

## 3. Termination reasons have one ABI meaning

The termination-control syscall arguments use `DwTerminationReason`, not raw
`u32`. The wire width remains 32 bits.

For DW0-E, callers may supply exactly `DW_TERMINATION_AUTHORIZED` to:

- `task_group_terminate`;
- `process_terminate`; and
- `thread_terminate`.

Zero, unknown values, `NORMAL_EXIT`, `UNHANDLED_EXCEPTION`,
`RESOURCE_POLICY`, and `TASK_GROUP_TEARDOWN` are invalid caller-supplied
termination reasons and return `INVALID_ARGUMENT` before handle resolution.

Reason ownership is:

- `NORMAL_EXIT`: minted only by `process_exit`, `thread_exit`, or final-thread
  normal exit;
- `AUTHORIZED`: accepted by explicit rights-checked terminate operations;
- `UNHANDLED_EXCEPTION`: minted by the architecture/task exception path;
- `RESOURCE_POLICY`: reserved for future kernel/Wyrmroot resource policy; and
- `TASK_GROUP_TEARDOWN`: minted by recursive TaskGroup teardown.

For `AUTHORIZED` termination, the syscall `code` is stored in `detail`;
`application_code`, `exception_type`, and `fault_address` are zero. Normal exit
uses `application_code` and leaves `detail` zero.
---

## 4. Task ownership is acyclic

ObjectRegistry remains the sole strong-liveness authority. Task payload state
may own generic `InternalRef` tokens but never a second refcount.

The strong graph points from child to parent, not parent to child:

```text
root kernel pin -> root TaskGroup
child TaskGroup -> parent TaskGroup
Process         -> parent TaskGroup
Thread          -> parent Process
root AddressRegion -> owning Process
```

Parent payloads keep child `ObjectId` metadata/index entries for traversal but
do not strongly retain children. This prevents parent/child reference cycles
while ensuring a child object cannot outlive the parent object it names.

A created/running Process or Thread also owns exactly one execution/scheduler
internal reference independent of external handles. That pin is released only
after terminal state is published and the task can no longer execute. Exited
objects can then remain live solely because ordinary handles or other explicit
internal references still exist.

The root TaskGroup owns one kernel-lifetime internal reference for DW0. A child
TaskGroup with live descendants remains alive because those children hold parent
references; an empty unreachable child group may finalize normally.

A Process owns its caller-local `HandleTable` by value. Process-wide exit drains
that table before releasing the process execution pin, which breaks possible
self-handle or task-handle ownership cycles before generic finalization.
Thread-to-Process and Process-to-TaskGroup parent references survive task exit and
are released only during typed payload finalization. This preserves the locked
rule that a Thread object cannot outlive its Process object even when an exited
Thread remains inspectable through a handle.

The root AddressRegion similarly retains its owning Process until region
finalization. Region operations against an EXITED process fail `BAD_STATE`;
retained identity is not permission to mutate a dead address space.

### 4.1 Lock and finalizer ordering

Do not hold a task hierarchy/state lock and a process HandleTable lock at the
same time. Handle-consuming syscalls resolve/pin under the HandleTable, release
that table ownership, then enter task state. Task teardown marks/unlinks state,
releases task locks, and drains a HandleTable as a separate transaction.

ObjectRegistry retain/release may be a narrow innermost operation under either
owner, preserving D's ordering. Subsystem cleanup and generic final completion
run outside HandleTable, task hierarchy/state, scheduler, and address-space
mutation locks.

Scheduler queue mutation must likewise not call task finalizers. A terminal
thread is first made non-runnable, then task state is committed, then ownership
references are released outside scheduler ownership.

---

## 5. D7-R1/R2 are closed mechanically before task publication

DW0-E adopts typed construction and typed cleanup proofs as the required shape.
Exact Rust names remain implementation detail, but these properties are fixed.
### 5.1 Construction

A production payload-bearing object begins with one move-only unpublished
creation authority. Payload binding **consumes** that authority and returns a
move-only bound-construction proof. Only the bound proof may become the first
HandleRef or explicit internal owner.

Therefore:

- payload registration necessarily precedes first public-handle publication;
- the same generic object cannot be bound into two payload authorities because
  the sole creation authority has already been consumed;
- raw `ObjectId`, backing identity, task ID metadata, or addresses cannot
  reconstruct construction authority; and
- production task, MemoryObject, and AddressRegion factories use the same
  construction rule.

The existing generic `CreationRef -> HandleRef` convenience path must not remain
a production escape hatch for payload-bearing objects after E's factory work.
Test-only payloadless helpers may exist behind explicit test configuration.

### 5.2 Finalization

A payload-bearing `FinalRelease` cannot directly return its generic slot to
Vacant. Its typed payload owner must first consume subsystem state and produce a
move-only cleanup-complete proof. Only the object core may consume that proof to
complete generic finalization.

This removes direct crate-wide generic completion as a valid production path for
MemoryObject, AddressRegion, TaskGroup, Process, Thread, and later payload
objects. Cleanup failure after the final-release transaction commits remains an
invariant failure/fail-stop condition, never a user-recoverable half-finalized
state.
---

## 6. x86_64 CPL3/syscall boundary

DW0-E uses `SYSCALL` for entry and `IRETQ` for return. `SYSRET` is not enabled
or used in E. The design is checked against the Intel 64/IA-32 and AMD64
architectural definitions, while Deepwyrm's ABI/schema remains the software
source of truth.

### 6.1 GDT selectors

The Deepwyrm GDT order becomes:

```text
0: null
1: kernel 64-bit code
2: kernel data
3: TSS low
4: TSS high
5: user data
6: user 64-bit code
```

Selectors are fixed for DW0-E:

- kernel code `0x08`;
- kernel data `0x10`;
- TSS `0x18`;
- user data `0x2b` (index `0x28`, RPL3); and
- user 64-bit code `0x33` (index `0x30`, RPL3).

The user descriptors are DPL3. User code is long-mode executable/readable; user
data is writable data. CPL3 return frames always use CS `0x33`, SS `0x2b`.
### 6.2 Per-CPU privilege entry stack and GS policy

TSS `RSP0` points to a **per-CPU privilege-entry stack**, not a per-thread
kernel stack. It is installed during CPU task/syscall initialization and does
not change on ordinary E context switches. Every CPU must eventually own a
distinct guard-paged supervisor RW/NX entry stack.

The same trusted entry-stack top is available through a supervisor-only per-CPU
structure addressed by GS for `SYSCALL`, because the instruction itself does not
switch stacks.

DW0-E deliberately does **not** use `SWAPGS`. GS remains the kernel per-CPU base
while CPL3 executes; user page permissions prevent access to the referenced
higher-half supervisor memory. Before entering CPL3, CR4.FSGSBASE must be clear,
and E exposes no userspace FS/GS-base mutation API. FS/GS TLS is deferred.

On syscall entry:

1. no load/store/push/pop may use the user RSP as a kernel stack;
2. user RSP/RCX/R11 and any required entry scalars may be staged only in
   supervisor-only per-CPU scratch addressed through trusted GS;
3. RSP is replaced with the per-CPU entry-stack top; and
4. only then may the first kernel stack write occur.

After a complete entry frame exists, the dispatcher/scheduler may move execution
to the current Thread's kernel stack. The per-CPU entry stack is an architecture
landing pad, not the scheduler's long-lived execution stack.
### 6.3 SYSCALL MSRs and entry flags

Before CPL3 execution, E verifies architectural SYSCALL support and programs:

- IA32_EFER.SCE = 1 while preserving unrelated EFER state;
- IA32_STAR kernel-call selector field to kernel code selector `0x08`;
- IA32_STAR SYSRET/user-return selector field to zero because SYSRET is not an
  E return mechanism;
- IA32_LSTAR to the reviewed canonical kernel syscall-entry symbol; and
- IA32_FMASK to clear TF, IF, DF, IOPL, NT, RF, VM, AC, VIF, and VIP.

For the locked x86 RFLAGS layout, the E FMASK value is `0x001f7700`.
Interrupts therefore remain disabled until the entry frame and current-thread
state are trusted; kernel direction state is forward; and user privilege/debug
control bits cannot leak into the kernel execution context.

MSR setup is one explicit unsafe architecture boundary. Failure to establish or
revalidate the exact programmed state before first CPL3 entry is a kernel
initialization failure, not a user-visible partial feature.

### 6.4 Return-state sanitization

IRETQ return accepts only a lower-canonical userspace RIP/RSP under the existing
four-level user/kernel split. RIP must resolve to a user-executable mapping. The
stack must have a user-writable byte immediately below the returned RSP so the
one-past-top conventional stack pointer remains representable without accepting
an unmapped stack.

The return RFLAGS value is reconstructed rather than blindly trusting saved
R11. E preserves only CF, PF, AF, ZF, SF, DF, OF, and ID from the user image,
forces reserved bit 1 and IF, and clears every other bit.
The exact E return formula is:

```text
safe_user_flags = saved_user_rflags & 0x00200cd5
return_rflags    = safe_user_flags | 0x00000202
```

This deliberately clears TF until native debugging/tracing is implemented.
Initial thread entry uses `RFLAGS = 0x202`.

The raw ABI preserves all general-purpose registers not declared clobbered,
except RAX which carries the sign-extended `DwStatus`. RCX and R11 are ABI
clobbers and must be restored from user-derived values or cleared; they must
never return kernel pointers, stack addresses, selectors, or privileged state.

### 6.5 Exception origin is part of the architecture frame contract

E replaces the B-only assumption that every exception path is terminal with an
origin-aware frame parser while preserving terminal kernel policy.

For an exception whose saved CS has RPL3, the architecture entry must consume
and validate the hardware-supplied old RSP/SS tail, create structured native
exception metadata, and enter the task-termination path above. It must never
attempt to resume a malformed frame.

For an exception whose saved CS has RPL0, the existing fail-stop reporter
remains authoritative. Terminal IST paths such as double fault and machine
check remain terminal regardless of interrupted CPL. NMI remains architecture
control flow, not a userspace exception object.

No userspace exception path may turn a kernel-origin fault into a recoverable
process event.

---

## 7. Syscall adapters preserve D/C business boundaries
Generated syscall IDs/register metadata are the dispatch source of truth. E does
not hand-copy syscall numbers into assembly or Rust `match` tables.

D's `handle_close`, `handle_duplicate`, and `object_get_info_v1` service
semantics remain the business-logic owners. E adapters add only syscall frame
decoding, caller Process selection, pinned usercopy/copyout, and status/result
transport. C's user-range/usercopy boundary remains the sole ordinary path for
userspace memory access.

All output-producing syscalls preflight and pin required copyout storage before
business mutation when failure would otherwise create or consume authority.
No operation may successfully create a handle/task and then discover that its
result pointer is unusable.

`DW_OBJECT_INFO_TASK_STATE_V1` becomes implemented only after a valid Process or
Thread handle has passed `INSPECT`. It reports the structured state/termination
record defined here and preserves D's no-probing validation order.

Unknown syscall IDs and schema-defined syscalls not yet active in the current
phase return `NOT_SUPPORTED` deterministically. This includes public
`process_create` throughout DW0-E.

---

## 8. DW0-E0 disposition

E0 closes the following implementation blockers:

- public `process_create` activation moves to F without changing its ID/layout;
- Process/Thread lifecycle and final-thread behavior are monotonic and explicit;
- caller-supplied termination reasons are typed and restricted to AUTHORIZED;
- task lifetime uses an acyclic child-to-parent strong graph;
- D7-R1/R2 are resolved by mandatory typed construction/cleanup proofs; and
- the x86_64 CPL3/SYSCALL/IRETQ boundary has fixed selectors, entry-stack,
  GS/FSGSBASE, MSR, RFLAGS, return-validation, and exception-origin rules.
The following remain implementation work for E1-E9, not claims made by this
contract: task payloads/factories, scheduler queues, kernel/entry stacks, GDT/TSS
changes, syscall assembly/MSRs, user exception dispatch, syscall adapters,
freestanding userspace, VM execution, security review, and evidence closure.

DW0-F still owns Channel queues/transfer, waits/events/timers, blocking wakeup
semantics, and public process-creation activation. DW0-G still owns primordial
ELF parsing/loading and the real bootstrap capability handoff. DW0-H still owns
whole-milestone SMP/security closure.

Wyrmroot was reviewed read-only. Its current pin remains the older DW0-C
Deepwyrm revision, so this ABI-0 contract change requires a later explicit
consumer repin before paired E/F integration evidence can be claimed.

This contract authorizes E1 implementation only after generated ABI outputs and
ABI drift/parity tests reflect the E0 schema changes below.
