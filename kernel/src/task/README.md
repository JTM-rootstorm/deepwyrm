# Task boundary

The task subsystem owns typed `TaskGroup`, `Process`, and `Thread` payload state.
Generic strong liveness remains owned exclusively by `ObjectRegistry`; task
payloads hold move-only parent and execution references rather than a second
reference count.

The lifetime graph is intentionally acyclic: child task groups retain parents,
processes retain task groups, and threads retain processes. Parent payloads keep
only child identities for traversal. A process owns its caller-local handle
table by value and task teardown returns handle finalizers/execution authority
for release outside task mutation.

DW0-E3 layers a deterministic cooperative scheduler and bounded execution-
resource authority over that payload model. Scheduler admission is reserved
before publication, so a half-started Thread is never runnable. RUNNABLE,
RUNNING, and terminal ownership are mutually exclusive scheduler states.

Each runnable Thread owns one move-only kernel-stack/context pair. The saved
context records every GPR plus user RIP/RSP/RFLAGS, keeps startup arguments
explicit for E4 placement, fixes initial RFLAGS to `0x202`, records user TLS as
unavailable under the E0 kernel-GS policy, and records FP/SIMD as unavailable.
No loader register/TLS/FP state is inherited implicitly.

E3 stack/context pools use generation-tagged identities and private spin locks;
stale identities cannot reclaim a reused slot. Terminal scheduling/resource
retirement completes before generic task pins are returned for finalization.

Architecture context entry/switch assembly remains E4 work. Native waits,
blocking/wakeup behavior, event/timer integration, and timer-driven preemption
remain outside this boundary.
