# Guest test scaffold

**Status:** Structure only; no guest harness or guest tests are implemented here.

Guest tests are intended for behavior that requires the Deepwyrm kernel and the
centrally defined reference environment. Examples include architecture entry,
user/kernel isolation, page-table permissions, syscall transitions, scheduling,
IPC, waits, and timer behavior.

Future guest execution must be driven by centralized tooling with bounded
timeouts, filtered selectors, serial capture, and a machine-readable test-only
completion mechanism. It must distinguish completion, failure, panic, timeout,
and infrastructure errors without treating a screenshot or serial substring as
sufficient evidence.

Nothing in this directory authorizes VM operation or defines a QEMU profile.
Test-only control and completion channels must remain separate from production
ABI and must not deliver ordinary boot or runtime artifacts.
