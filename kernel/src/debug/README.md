# Early diagnostic boundary

This directory owns kernel-only COM1 diagnostics and bounded panic records.
It does not define a syscall, userspace protocol, persistent logger, or
test-completion ABI. Panic records carry every field in every build: the
source location and message, the CPU, the instruction pointer, the fault
address and the backtrace frames. COM1 is the trusted diagnostic channel, and
a production crash must say what failed and where.
