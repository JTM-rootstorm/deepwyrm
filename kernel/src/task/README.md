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

Thread payloads retain validated initial user start scalars plus opaque kernel-
stack and saved-context identities. The task core does not define either stack
storage or an architecture register layout; E3/E4 own those resources and must
return them explicitly when a thread becomes terminal.

Scheduling policy, architecture context switching, syscall entry, and
blocking/wakeup behavior remain separate boundaries layered on this payload
authority. Native task state is capability-controlled and does not encode POSIX
process, signal, or file-descriptor semantics.
