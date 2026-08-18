# Synchronization boundary

DW0-E3 provides a small non-sleeping `SpinMutex` for bounded kernel critical
sections. It uses Acquire/Release ownership and is safe to share when its
payload is `Send`.

E3 scheduler/resource owners keep their locks private and never return guards.
Their methods acquire at most one E3 lock at a time, so task finalization,
process handle-table work, usercopy, and page-table publication occur only after
scheduler/resource lock release. Interrupt handlers do not acquire these locks
in E; an IRQ-safe synchronization layer belongs to later architecture work.

This is not the native wait subsystem. Events, wait queues, atomic wait/wake,
blocking synchronization, and timeout integration remain DW0-F work.
