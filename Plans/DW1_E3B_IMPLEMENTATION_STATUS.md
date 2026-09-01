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
sequence. E3B full mode is selected only by exact build environment
`DEEPWYRM_DW1E_E3B_FULL=1`, which emits the checked private cfg
`deepwyrm_dw1e_e3b_full` only for `q35-com2-interrupt`. The variable must be
absent for E3A; any other value, or setting it for another selector, fails
build admission. This preserves E3A's response-time records 0-8 materialize,
partial flush, and return behavior while keeping E3B's additional lifecycle
authority compile-time explicit.

In E3B full mode, a probe response stores the response relation but does not
materialize an immutable leg while a later valid transmit IRQ/ack epoch can
still arrive. The exact controller's U1 peer-close/TEMT barrier materializes
records 3-8 and appends record 9 under one collector lock. The terminal claim,
after Wyrmroot's U2 TEMT barrier, materializes records 17-22 and claims the
saved/current pair under the same lock. Focused models include a valid
post-response transmit epoch on both legs.

Records 9 through 14 join the controller-observed U1 peer close to
the actual q35 retirement transitions: logical Retiring publication, physical
mask/readback plus bounded Delivery Status polling, zero in-handler proof,
fresh mask/idle revalidation plus CPU0 IRR/ISR-clear proof, and final source
release. Records 15 through 22 require a fresh Interrupt object/binding,
driver, probe, attempt, stream, challenge, payload, and response while
retaining the exact parent lease.

The first real U1 `InterruptDelivery` is saved at the physical-entry hook.
After U1 release and complete U2 response, only the permanently bound
controller may claim terminal completion. A selector-private terminal freeze
authenticates the saved U1 and current U2 generations, masks and reads back the
current U2 route, prevents new delivery snapshots, and then releases the
source lock while any handler that started before the freeze completes its
pending bookkeeping and handler accounting. It boundedly observes Delivery
Status idle, reacquires the source lock, and revalidates the exact frozen/live
generation, zero in-handler count, masked/idle route, BSP execution, and clear
LAPIC vector before replay and snapshot.

Under that final source serialization, the kernel replays the saved U1 value
through `InterruptAuthority::deliver_classified`, requires `Rejected` and a
fully empty wake-and-pin batch before any scheduler publication, credits the
bounded stale/orphan counter, and returns one coherent counter snapshot. This
avoids the invalid physical-orphan construction when physical entries and
exact deliveries must remain equal. The terminal U2 mask is selector-private
quiescence, not U2 retirement, release, or a reusable-source claim; selector
31 halts after its single terminal outcome.

The accounting record is admitted only when its byte-packed counters and both
per-leg sums satisfy the frozen ranges. The stale result carries the complete
U1 tuple with current B2/O2 in `V/X`; accounting carries the complete U2
tuple; the final record is the all-zero-generation kernel `FF TERMINAL`.
One COM1 transaction emits all 26 records followed by exact `DWTEST1 31 0`
and the matching PASS debug exit. Success, failure, and panic contend for one
atomic selector-31 terminal owner before serial or debug-exit output. Deferred
Interrupt finalization also has an exact in-progress claim, so two carrier
safe points cannot retry the same retirement concurrently. No E3B-full runtime
path exposes the E3A nine-record partial transcript.

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
| focused selector-31 E3A model/source/private-authority tests | **pass**, 9 passed |
| focused selector-31 E3B-full model/source/private-authority tests | **pass**, 11 passed |
| full selector-31 E3A host library tests | **pass**, 911 passed |
| full selector-31 E3B-full host library tests | **pass**, 913 passed |
| focused q35 platform tests | **pass**, 4 passed, including pre-freeze-handler interleaving |
| focused Interrupt authority tests | **pass**, 14 passed, including two-carrier retry |
| full default host library tests | **pass**, 792 passed |
| host Clippy for library/tests with warnings denied | **pass** |
| host formatting and diff checks | **pass** |
| default freestanding target check | **pass** |
| selector-31 E3A freestanding target check with exact nonce and full mode absent | **pass** |
| selector-31 E3B freestanding target check with exact nonce and `DEEPWYRM_DW1E_E3B_FULL=1` | **pass** |
| ambient E3B-full variable without selector 31 | **expected rejection**, build fails closed |

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
