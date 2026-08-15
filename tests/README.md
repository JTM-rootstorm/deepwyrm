# Deepwyrm test scaffold

**Status:** Structure only; no tests or test runner are implemented here.

This directory reserves the test-suite boundaries required by the DW0 plan. Its
presence is not evidence that Deepwyrm builds, boots, runs guest code, or passes
any DW0 phase gate.

## Test categories

| Directory | Intended scope | What it cannot establish alone |
|---|---|---|
| `host/` | Pure logic that can run in the host environment | Kernel or guest behavior |
| `guest/` | Focused Deepwyrm tests executed in the reference guest environment | The full Wyrmroot integration path |
| `integration/` | Cross-component and, where required, paired Deepwyrm/Wyrmroot gates | Acceptance for any unrecorded revision or artifact |

Future test implementations must use the centralized repository tooling and
test selectors. Do not add private QEMU commands, VM profiles, host-share
artifact paths, or subsystem-specific completion protocols under this tree.

## Evidence requirements

When a runnable harness is introduced, its reports must distinguish selection,
execution, completion, failure, panic, timeout, and infrastructure error. A
selected or discovered test is not a completed test, and a host result is not a
guest result.

Guest and integration evidence must identify the exact source revisions and
the artifacts or media actually consumed. Cross-repository acceptance must
record the compatible Deepwyrm/Wyrmroot revision pair; separate commits are not
atomic.

The planned `cargo xtask test ...` command forms remain documentation until the
repository tooling implements and validates them.
