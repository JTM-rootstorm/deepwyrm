# Deepwyrm DW1-E2B Implementation Status

**Status:** Reached source/model/target-build seam; physical-vector observation remains E2C integration work.

**Date:** 2026-08-31
**Implementation authority:** `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, DW1-E2 card E2B; `DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md`, sections 6, 8, and 9.

## Reached scope

E2B adds the selected-product vector surface and its returning entry without
claiming q35 controller ownership or a userspace `Interrupt` transition.

- `DEEPWYRM_GUEST_TEST_SELECTOR=q35-com2-interrupt` emits the private
  `deepwyrm_dw1e_platform` cfg. Selector 31 remains reserved: the existing
  test-support selection validation still rejects it as non-runnable until E3
  owns its actor and evidence protocol.
- The selected product installs exactly one external IDT interrupt gate,
  vector `0x30`; normal and historical/default product construction retains an
  empty external pool.
- `dw_x86_64_q35_com2_entry` preserves every interrupted GPR, inspects the
  saved CS, applies `swapgs` only for CPL3 origin, maintains SysV call
  alignment, returns through `iretq`, and never retains the frame or enters a
  timer pre-IRET scheduler gate.
- E2C receives one immutable, one-shot q35 dispatch binding. The entry calls
  it with IF clear, then uses the current CPU's already-published local-APIC
  transport for EOI. An unexpected delivery without a bound handler wakes no
  userspace but is still EOIed; failed EOI stops rather than returning with an
  in-service interrupt.

The exact E2 dispatch order is therefore:

```text
ephemeral returning frame
  -> E2C exact q35 binding snapshot/delivery/WakeBatch publication
  -> local-APIC EOI
  -> restore same frame / iretq
```

E2C must bind the handler before a q35 route can be unmasked and owns all
IOAPIC mask/readback, generation, stale/orphan, quarantine, and finalization
policy. This card neither changes the public `Interrupt` ABI nor reuses the
synthetic selector-30 platform.

## Validation

All commands use lane-local pinned target directories.

| Command | Result |
| --- | --- |
| `tools/pinned-cargo host fmt --all -- --check` | passed |
| `tools/pinned-cargo host test -p deepwyrm-kernel arch::x86_64::idt::tests --lib` | 7 passed |
| `tools/pinned-cargo host test -p deepwyrm-kernel arch::x86_64::external_interrupt::tests --lib` | 1 passed |
| `tools/pinned-cargo host test -p deepwyrm-kernel arch::x86_64::ipi::tests --lib` | 2 passed |
| `tools/pinned-cargo target check -p deepwyrm-kernel` | passed; assembles the returning entry |
| `RUSTFLAGS=--cfg=deepwyrm_dw1e_platform tools/pinned-cargo target check -p deepwyrm-kernel` | passed; type-checks the selected IDT shape without making reserved selector 31 runnable |

The IDT model asserts the selected product has vector `0x30` and no other
external gates; the existing default-surface test asserts the entire external
pool remains absent. The q35 binding model asserts one-shot publication before
route unmask. The build-script unit assertion preserves selector 31 as
non-runnable while recognizing its product-shape key.

## Required-source and provenance receipt

| Source | Exact identity / disposition |
| --- | --- |
| Active plan, E0 contract, architecture index, E1 status, and reached timer/IPI entry seams | **adapt** the fixed vector, full returning-frame discipline, frame ephemerality, EOI order, and default-product absence. |
| Fuchsia/Zircon `6a606ff7fd9b055edee6557566fb3f112df1a812`, `interrupt_dispatcher.cc`, SHA-256 `8fcf75bfa8d47d99549266f2b097041d754cccf05dbeb052d18fea3f374f6a70` | **concept** pending/ack separation and bounded handler-side delivery only; no source, ABI, or state machine copied. |
| Same revision, `resource_dispatcher.cc`, SHA-256 `db1bfb63e8175d25916d1abcdd4f0a0c13f6c1cc379e57145f0ec7ead7f7e678` | **concept** exclusive authority publication only; no resource model imported. |
| xv6-riscv `35b088427ef37611c38afdeed5a52a278cae38f9`, `trap.c` SHA-256 `6b7d192e64c49ce729dd3b597d8ba65e452e4c37d15942bab65660a032b3de60`, `plic.c` SHA-256 `125fc60925cae8cfff87450c88faa30634e4406f1e5a16234ff49ffba5dca7ab` | **concept** returning controller dispatch/acknowledgement only; RISC-V and PLIC specifics rejected. |
| Same xv6 revision, `uart.c` SHA-256 `6c284f94eb8fcca9c723015f366a849a441f462b99d16e3cca5880439df6a493`, `console.c` SHA-256 `d3088059d9591e367b7b15706590e472fe38cc505b22d7d8cf03b8da5de5d699` | **not applicable**: UART policy belongs to WYR1-D, not the external-vector entry. |

All E2B code and documentation are first-party GPL-3.0-or-later. No external
implementation, expression, ABI, or license text was copied.

## Nonclaims and next seam

E2B does not claim IOAPIC mapping/probe, MADT live consumption, q35 route
installation, `InterruptPlatform` lifecycle, an `Interrupt` pending
transition, WakeBatch behavior, stale/orphan diagnostics, IRR/ISR proof,
selector-31 actor/evidence, UART initialization, VM acceptance, or a complete
UART driver. E2C consumes `Q35ExternalInterruptHandler` and must bind it before
unmasking the exact validated q35 route.
