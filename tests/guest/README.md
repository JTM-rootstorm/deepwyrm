# Guest tests

Guest tests are intended for behavior that requires the Deepwyrm kernel and the
centrally defined reference environment. Examples include architecture entry,
user/kernel isolation, page-table permissions, syscall transitions, scheduling,
IPC, waits, and timer behavior.

Guest execution must be driven by centralized tooling with bounded
timeouts, filtered selectors, serial capture, and a machine-readable test-only
completion mechanism. It must distinguish completion, failure, panic, timeout,
and infrastructure errors without treating a screenshot or serial substring as
sufficient evidence.

The test-build completion record is exactly 38 bytes:

```text
DWTEST1|KK|TTTTTTTT|DDDDDDDD|CCCCCCCC\n
```

- all numeric fields use uppercase, fixed-width hexadecimal;
- `KK` is `01` PASS, `02` FAIL, or `03` PANIC;
- `T` is a test-build-internal `u32` test identifier;
- `D` is a bounded test-specific `u32` detail code;
- `C` is FNV-1a32 over every preceding byte, including the final delimiter;
- the checksum detects corruption and is not authentication.

The parser accepts one exact record only. Truncation, lowercase hex, malformed
delimiters, bad checksums, trailing bytes, and concatenated terminal records are
rejected. The serial record is emitted before the outcome-only QEMU debug-exit
value. If QEMU does not exit, the test kernel enters a terminal halt path.

This protocol, its identifiers, and QEMU exit values are test-harness internals,
not Deepwyrm ABI. They require the kernel `test-support` build feature and must
not be compiled into or consumed by production builds. A test build selects a
canonical selector through `DEEPWYRM_GUEST_TEST_SELECTOR`; central build tooling
resolves and embeds its unique nonzero ID from `tooling/guest-harness.toml`.
Firmware, BootInfo, and runtime inputs cannot supply or override that ID.

Nothing in this directory authorizes VM operation or defines a private QEMU
profile.
Test-only control and completion channels must remain separate from production
ABI and must not deliver ordinary boot or runtime artifacts.
