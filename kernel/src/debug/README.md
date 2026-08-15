# Early diagnostic boundary

This directory owns kernel-only COM1 diagnostics and bounded panic records.
It does not define a syscall, userspace protocol, persistent logger, or
test-completion ABI. Address-bearing panic fields are emitted only by debug
builds; release builds redact them.
