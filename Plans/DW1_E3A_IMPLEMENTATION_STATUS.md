# Deepwyrm DW1-E3A Implementation Status

**Status:** Selector-31 kernel foundation and first raw COM2 challenge path
implemented and live-extracted on the exact UP/SMP pair; selector PASS remains
deliberately absent.

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
2. bind the controller caller plus the exact raw-probe Process resolved from
   its retained handle;
3. arm one nonzero stream/challenge/length/FNV-1a-64 tuple; and
4. submit only the driver UART-drain or probe response event admitted by E3A.

Reserved words must be zero. Required values are nonzero. Driver binding
derives object, binding, route, and parent-lease generations from the resolved
kernel object. Probe binding resolves the controller's retained Process handle
in the controller caller's table and requires both processes to remain live;
userspace cannot supply either process generation or any kernel object
generation by value.

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

E3A's response path emits the nine-record partial transcript, then returns to
userspace so the production driver can finish draining the queued WRST response
to physical COM2. This ordering is required because a successful Channel send
only commits the WRST record to the driver; it is not evidence that the driver
has serviced its transmit interrupt or that the host observed the response.
The host runner independently joins the exact post-prelude COM2 response; the
partial nine-record transcript is not a certificate. The partial path still
does not call the QEMU debug-exit device or append `DWTEST1 31 PASS`. Any
accidental generic PASS request is converted to selector failure, and the host
runner remains responsible for stopping the non-accepting E3A extraction run.

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
| exact selector-31 default/UP VM extraction | **PARTIAL_PASS**, nine records plus exact 24-byte COM2 response |
| exact selector-31 four-vCPU/SMP VM extraction | **PARTIAL_PASS**, nine records plus exact 24-byte COM2 response |

The freestanding checks retain pre-existing dead-code warnings in the staged
q35 ACPI surface; the new selector-private module adds no target warning.

The accepted E3A extraction used Deepwyrm
`6b00f82ca075571581532bb3c15f5b2ff57d3ec3` with Wyrmroot
`6587baa0c999e4db089338f8707099e11298fe34` and request SHA-256
`bcf434bd24608e748ad8ae5b8c4b1be5a02bc1bf745d66e2ac54d703f333bbf3`.
Both profiles independently joined the same COM2 raw transcript SHA-256
`f4ae130048d01363a990d335564042b2b7771cdbf345bd321615732d68e64977`
and response SHA-256
`3e6d96cb77a7aadea4a092f52d2d9e277814f08e07f4493c127f047e05ad0c9e`.
The default evidence SHA-256 is
`b4ee0b4750e46ec424aa8b6ca4a86fe7e5e2a8978eb5fb79d2ff84dd794678f8`;
the SMP evidence SHA-256 is
`b21ab0800a4ebfabdf9f36041989036cad5529b590a73a6bd346bc1e8bb54750`.
The runner restored the persistent `OS-Project` domain to its canonical
shutoff XML baseline SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`
after each profile. Preserved evidence lives under root project path
`.tmp/dw1e3a-6b00f82-6587baa-selector31/`.

E3A still does not prove restart, retirement quarantine evidence, U2
replacement, stale-U1 rejection, final accounting, the complete atomic
26-record transaction, or selector 31 PASS. Those remain E3B and
coordinator-owned full live acceptance work. `PARTIAL_PASS` is deliberately a
non-acceptance result.

## Required-source and provenance receipt

The active root plan, the E0 sections 11-13 contract, the architecture index,
and the E1/E2A/E2B/E2C statuses supplied the selector identity, exact codec,
authority boundaries, transition hooks, and E3A stop line. No external source,
implementation, expression, ABI, or license text was copied. All new source
and documentation is first-party GPL-3.0-or-later.
