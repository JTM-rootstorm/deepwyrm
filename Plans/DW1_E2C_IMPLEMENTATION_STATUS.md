# Deepwyrm DW1-E2C Implementation Status

**Status:** Source/model/target-build implementation reached; live COM2 VM
observation remains coordinator acceptance work.

**Date:** 2026-08-31
**Base:** E2A+E2B integrated revision
`b4ecd7ba75210a6ddf1f7e786a4595b2e170e5d0`
**Authority:** `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, DW1-E2C;
`DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md`; and the E2A/E2B implementation
statuses.

## Reached scope

E2C adds one generation-exact q35 `InterruptPlatform` for logical source 3.
The logical identity remains IRQ3 even when the validated MADT override maps
it to another edge/high GSI. The backend consumes only E2A's permanent
`ValidatedQ35IoApic`, derives the selected redirection registers from the
resolved GSI/controller base, and programs the exact E1 vector-`0x30`, fixed,
physical-destination, edge/high route.

The creation order closes the first-edge race. Every fallible object,
reference, and handle-destination step completes while the route is masked;
the exact typed Interrupt becomes `Armed`; then the platform performs its
no-fail logical-live/final-unmask commit; finally the already-validated handle
destination publishes. The q35 source guard publishes logical-live and drops
before the final serialized controller transaction. Because the selected route
remains masked until that transaction, the BSP entry cannot classify an
unmasked `ReservedMasked` generation. The final handle
publication is deliberately invariant-only: the same-table destination permit
and compatible rights were already validated, so no unsafe recoverable
post-unmask rollback path exists.

The E2B handler binding now snapshots exactly `LiveUnmasked`, `Retiring`, or
orphan state. A live snapshot increments bounded generation-owned in-handler
accounting, delivers through `InterruptAuthority`, commits the IRQ-safe
`WakeBatch`, returns a scalar generation token, EOIs through E2B, and decrements
the same handler generation only in the post-EOI callback. Retiring delivery
is consumed without userspace wake. Orphan and handler-accounting failure are
bounded, saturating, nonallocating, and fail-safe mask the selected route.

The private acknowledgement seam is outcome-exact:

- synthetic selector-30 delivery remains physically/logically masked until a
  clean ack rearms it, while a raced ack remains masked; and
- q35 clean and raced acknowledgements both validate the exact live binding
  and leave the edge route unmasked.

No public syscall, object state, rights, signal, wait, or generated ABI changed.

## Retirement quarantine and safe-point staging

Final release transitions the exact live slot to logical `Retiring`, masks and
reads back the IOAPIC entry, advances only then to `RetiringMasked`, polls the
read-only Delivery Status bit at most 65,536 times, requires generation-bound
handler quiescence, revalidates mask-one/Delivery-Status-idle, and observes
CPU0 xAPIC IRR `0x210` bit 16 and ISR `0x110` bit 16 through a narrow local-APIC
method. A clear proof is revalidated before the slot becomes vacant. Readback
comparison ignores only the read-only Delivery Status and edge-route Remote
IRR observations; every writable route bit remains exact.

If Delivery Status, handler accounting, or CPU0 IRR/ISR is not clear, the
typed Interrupt retains its move-only `FinalRelease`, parent pin, and exact
binding in `Finalizing`. Source reservation remains in use. An off-BSP retry
publishes a bounded rendezvous request carrying source, vector, platform
generation, and nonzero request generation. CPU0 retries only from the
existing carrier finalizer safe point; stale request identity cannot release a
replacement. Controller faults retain `Retiring` or `RetiringMasked` rather
than claiming release.

## Lock and ordering record

The implemented partial order is:

```text
q35 source slot -> drop -> E2A IOAPIC selector/window lock -> drop
Interrupt object -> WaitRegistry -> ExecutionDomain wake publication
IOAPIC masked/idle proof -> generation handler quiescence -> CPU0 IRR/ISR proof
```

No IOAPIC/source guard is held while delivering into the Interrupt authority,
publishing waits/scheduler wakes, issuing LAPIC EOI, completing the post-EOI
token, or entering ObjectRegistry/typed finalization. Local-APIC EOI never
depends on userspace acknowledgement.

## Model and source coverage

Focused coverage establishes:

- a non-identity resolved GSI (GSI 5) for logical source 3;
- masked reserve, typed-Armed-before-unmask commit, and an adversarial delivery
  injected inside the platform commit boundary reaching `Pending`;
- q35 route continuity across raced acknowledgement;
- logical retirement before mask/readback, in-handler delay, off-BSP
  generation-bound request, nonzero IRR/ISR deferral, and later clear release;
- 65,536-read Delivery Status timeout retaining quarantine and source-in-use,
  followed by exact clear release;
- deferred typed finalization retaining the generic final release and parent
  until a later safe-point retry;
- orphan fail-safe masking, strictly newer replacement generation, saturating
  counters, and E2A readback rules; and
- unchanged selector-30 synthetic ack/rearm/race tests.

## Required-source and provenance receipt

| Source | Disposition |
| --- | --- |
| Active plan, E0 contract, E1 status, E2A/E2B statuses, architecture index, and reached DW1-D Interrupt/finalizer tests | **adapt** exact edge-unmasked ack, fixed-vector quarantine, ephemeral handler, WakeBatch, and typed-finalization ownership. |
| Fuchsia/Zircon `6a606ff7fd9b055edee6557566fb3f112df1a812`, `interrupt_dispatcher.cc` SHA-256 `8fcf75bfa8d47d99549266f2b097041d754cccf05dbeb052d18fea3f374f6a70`, `resource_dispatcher.cc` SHA-256 `db1bfb63e8175d25916d1abcdd4f0a0c13f6c1cc379e57145f0ec7ead7f7e678` | **concept only** pending/ack separation, mask-before-unregister, and exclusive lifetime authority; no code, ABI, state machine, or expression copied. |
| xv6-riscv `35b088427ef37611c38afdeed5a52a278cae38f9`, `trap.c` SHA-256 `6b7d192e64c49ce729dd3b597d8ba65e452e4c37d15942bab65660a032b3de60`, `plic.c` SHA-256 `125fc60925cae8cfff87450c88faa30634e4406f1e5a16234ff49ffba5dca7ab` | **concept only** bounded external dispatch followed by controller completion; RISC-V/PLIC claim-complete semantics were rejected for xAPIC/IOAPIC. |
| `uart_16550`, linenoise, Fuchsia driver-manager, and xv6 UART/console sources in the phase cache | **not applicable** to the kernel route/binding/quarantine card; UART and connector policy remain WYR1-D ownership. |

All implementation and documentation are first-party GPL-3.0-or-later. No
external implementation, expression, ABI, or license text was copied.

## Validation and nonclaims

The lane used separate pinned host and target output directories. At the lane
revision recorded in the final handoff:

| Gate | Result |
| --- | --- |
| `tools/pinned-cargo host fmt --all -- --check` | **pass** |
| `tools/pinned-cargo host test -p deepwyrm-kernel --lib` | **pass**, 789 passed |
| focused `device::q35_interrupt::tests::` | **pass**, 2 passed |
| focused `device::interrupt_tests::` | **pass**, 13 passed |
| `tools/pinned-cargo host clippy -p deepwyrm-kernel --lib --tests -- -D warnings` | **pass** |
| default `tools/pinned-cargo target check -p deepwyrm-kernel` | **pass** |
| selected target check with `RUSTFLAGS='--cfg deepwyrm_dw1e_platform'` | **pass** |

E2C does not add selector 31, a test actor, COM2 UART policy, a userspace
driver, D3B/D3D behavior, or public ABI. Host/model and target-build results do
not establish live Delivery Status reliability, a host-generated COM2 pending
transition, one-/four-vCPU progress, restart/rebind, or VM acceptance. Those
remain coordinator-owned live gates after integration with the exact
Wyrmroot revision.
