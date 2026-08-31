# Deepwyrm DW1-E3A Implementation Status

**Status:** Selector-31 kernel foundation and first raw COM2 challenge path
implemented; live cross-repository extraction remains coordinator acceptance
work and selector PASS remains deliberately absent.

**Date:** 2026-08-31

**Base:** `87f08753aff53b48bbdf8115d593d5eb46f02c4e`

**Authority:** `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, DW1-E3/E3A;
`DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md`, sections 11-13; and the reached
E1/E2A/E2B/E2C implementation statuses.

## Reached scope

The central guest manifest now makes `q35-com2-interrupt` selector 31
runnable. The build validates an exact 16-character uppercase nonzero nonce
and activates mutually exclusive selector-private platform/evidence cfgs.
No public ABI schema, generated definition, syscall, right, status, or object
contract changed.

The private raw operation `0xffff_ff1f` retains the native six-`u64` carrier
but accepts exactly four nonce-bound actions:

1. bind the caller to an exact resolved Interrupt handle and nonzero driver
   attempt generation;
2. bind the caller's Process identity as the raw probe;
3. arm one nonzero stream/challenge/length/FNV-1a-64 tuple; and
4. submit only the driver UART-drain or probe response event admitted by E3A.

Reserved words must be zero. Required values are nonzero. Driver binding
derives object, binding, route, and parent-lease generations from the resolved
kernel object; probe identity comes from the dispatch caller. Userspace cannot
supply those kernel generations by value.

The collector reserves all 26 E3B slots while E3A can materialize and flush
only records 0 through 8. Route discovery, U1 source reserve/commit, physical
entry, pending/coalesced delivery, exact Interrupt wait block/wake, driver
drain, public ack completion, and probe response join the actual reached E2C
transitions. Driver/probe observations are accepted only from their bound raw
reporters. The collector does not manufacture hardware events or opaque
generations.

## Wire and operational synchronization

The DWE3E1 encoder emits exact 204-byte uppercase records with fixed offsets,
newline termination, and FNV-1a-32 over the first 195 bytes. The paired parser
and E3A extraction model validate only the exact records 0 through 8 tuple and
relations. The raw ID has a source guard proving it is absent from the public
ABI schema and generated kernel dispatch.

After action 3 commits, the kernel emits the exact 90-byte operational marker:

```text
DWE3READY|01|<NONCE16>|<STREAM16>|<CHALLENGE16>|<PAYLOAD_FNV64_16>|<FNV1A32_8>\n
```

Its checksum covers the 81-byte prefix through the final separator. This line
only synchronizes the host's first COM2 transmission; it is not a DWE3E1
record, certificate evidence, or terminal acceptance.

E3A's response path emits the nine-record partial transcript and halts. It
does not call the QEMU debug-exit device or append `DWTEST1 31 PASS`. Any
accidental generic PASS request is converted to selector failure.

## Validation and nonclaims

Lane-local pinned outputs established:

| Gate | Result |
| --- | --- |
| focused selector-31 collector/protocol tests | **pass**, 6 passed |
| focused selector-31 identity tests | **pass**, 12 passed |
| full default host tests | **pass** |
| default host library tests | **pass**, 789 passed |
| host Clippy for library/tests with warnings denied | **pass** |
| host formatting check | **pass** |
| default freestanding target check | **pass** |
| selector-31 freestanding target check with exact nonce | **pass** |

The freestanding checks retain pre-existing dead-code warnings in the staged
q35 ACPI surface; the new selector-private module adds no target warning.

E3A does not prove live COM2 delivery, one-/four-vCPU progress, restart,
retirement quarantine evidence, U2 replacement, stale-U1 rejection, final
accounting, the complete atomic 26-record transaction, or selector 31 PASS.
Those remain E3B and coordinator-owned live acceptance work. Wyrmroot still
must provide the exact caller sequencing, binary-safe deterministic payloads,
COM2 response reporter, readiness wait, and partial-host extraction against an
exact Deepwyrm revision.

## Required-source and provenance receipt

The active root plan, the E0 sections 11-13 contract, the architecture index,
and the E1/E2A/E2B/E2C statuses supplied the selector identity, exact codec,
authority boundaries, transition hooks, and E3A stop line. No external source,
implementation, expression, ABI, or license text was copied. All new source
and documentation is first-party GPL-3.0-or-later.
