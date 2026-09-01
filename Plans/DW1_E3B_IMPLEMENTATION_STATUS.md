# Deepwyrm DW1-E3B Implementation Status

**Status:** Selector-31 kernel collector and terminal path implemented; paired
Wyrmroot integration and live UP/SMP acceptance remain coordinator work.

**Date:** 2026-09-01

**Base:** `6b00f82ca075571581532bb3c15f5b2ff57d3ec3`

**Authority:** `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, DW1-E3/E3B;
`DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md`, sections 11-13;
`ARCHITECTURE_INDEX.md`; `DW1_E3A_IMPLEMENTATION_STATUS.md`; and the reached
E1/E2A/E2B/E2C statuses.

## Reached kernel scope

The selector-private collector now completes the exact 26-record DWE3E1
sequence. Records 9 through 14 join the controller-observed U1 peer close to
the actual q35 retirement transitions: logical Retiring publication, physical
mask/readback plus bounded Delivery Status polling, zero in-handler proof,
fresh mask/idle revalidation plus CPU0 IRR/ISR-clear proof, and final source
release. Records 15 through 22 require a fresh Interrupt object/binding,
driver, probe, attempt, stream, challenge, payload, and response while
retaining the exact parent lease.

The first real U1 `InterruptDelivery` is saved at the physical-entry hook.
After U1 release and complete U2 response, only the permanently bound
controller may claim terminal completion. The kernel replays that saved value
through `InterruptAuthority::deliver_classified`, requires `Rejected` and an
empty wake batch, then credits the bounded stale/orphan counter. This avoids
the invalid physical-orphan construction when physical entries and exact
deliveries must remain equal.

The accounting record is admitted only when its byte-packed counters and both
per-leg sums satisfy the frozen ranges. The stale result carries the complete
U1 tuple with current B2/O2 in `V/X`; accounting carries the complete U2
tuple; the final record is the all-zero-generation kernel `FF TERMINAL`.
One COM1 transaction emits all 26 records followed by exact `DWTEST1 31 0`
and the matching PASS debug exit. No E3B runtime path exposes the E3A
nine-record partial transcript.

## Private raw contract for paired Wyrmroot work

The public ABI/schema and generated definitions are unchanged. Private raw ID
`0xffff_ff1f` retains six `u64` words and exactly four numeric action tags:

1. `1 BIND_DRIVER` is accepted for U1 and exactly once more after U1 release
   for a fresh U2 Interrupt/driver attempt.
2. `2 BIND_PROBE` is accepted for U1 and exactly once more for a fresh U2
   probe while preserving the permanent controller identity.
3. `3 ARM_CHALLENGE` is accepted for G1/Q1 and exactly once more for strictly
   newer G2/Q2 with a different payload length/hash tuple.
4. `4 REPORT` admits actor-owned evidence events only `0x07`, `0x09`, `0x0A`,
   `0x15`, and `0x17`. A distinct action-4 control shape
   `event=0xFF, V=0, X=0` is the controller-only terminal claim; it does not
   append a controller evidence record. Nonzero terminal-claim values, a wrong
   caller, an early claim, or a duplicate claim fail closed.

Every action repeats the exact build nonce and preserves its frozen reserved
zero words. Wyrmroot-private TEMT, reap, and connector observations are causal
guards only; they must not become new kernel action or evidence tags.

## Validation and nonclaims

Fresh lane-local pinned targets established:

| Gate | Result |
| --- | --- |
| focused selector-31 model/source/private-authority tests | **pass**, 9 passed |
| focused q35 platform tests | **pass**, 2 passed |
| focused Interrupt authority tests | **pass**, 13 passed |
| full default host library tests | **pass**, 789 passed |
| host Clippy for library/tests with warnings denied | **pass** |
| host formatting and diff checks | **pass** |
| default freestanding target check | **pass** |
| selector-31 freestanding target check with exact nonce | **pass** |

No VM, libvirt, QEMU, network, or remote operation was performed. These
results do not prove live COM2 delivery, real Wyrmroot replacement, UP/SMP
selector acceptance, host transcript extraction, selector-30/29/28
regression, final ABI drift, or DW1-E closure. Those remain E3B integration
and E4 acceptance work owned by the coordinator.

## Required-source and provenance receipt

The root implementation plan; E0 sections 11-13; the architecture index; the
E1/E2A/E2B/E2C/E3A status records; and the E0 in-tree interrupt, q35,
architecture-entry, wait, and evidence sources were read and adapted for the
exact lifecycle hooks, tuple relations, authority checks, and atomic terminal
ordering.

The active phase's pinned external sources were also read at their named
revisions: Fuchsia/Zircon `interrupt_dispatcher.cc` and
`resource_dispatcher.cc` at
`6a606ff7fd9b055edee6557566fb3f112df1a812` supplied conceptual lifetime,
deactivation, and resource separation comparisons; xv6-riscv `trap.c`,
`plic.c`, `uart.c`, and `console.c` at
`35b088427ef37611c38afdeed5a52a278cae38f9` supplied returning-dispatch and
negative monolithic UART/console comparisons. rust-osdev `uart_16550`
`src/lib.rs`, revision-selected register/config modules, and README at
`176b07b076bdc1fe999a5e757ab53a0e24b4005c` were not applicable to this
kernel collector beyond confirming UART ownership remains in Wyrmroot.
linenoise at `a473823d74b93eab2ba83480df16ed37617493f2` and the available Fuchsia
driver-framework inventory were likewise not applicable to the kernel E3B
mechanism.

No external source, implementation, expression, ABI, or license text was
copied. All source and documentation changes are first-party
GPL-3.0-or-later.
