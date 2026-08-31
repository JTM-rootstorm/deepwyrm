# Deepwyrm DW1-E2A Implementation Status

**Status:** E2A implementation lane — target integration awaits E2B's reserved
product cfg hook

**Date:** 2026-08-31
**Authority:** `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, DW1-E2A/E2;
`DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md`; and
`DW0_I1_PER_CPU_SCRATCH_DESIGN.md`.

## Reached scope

E2A creates `arch/x86_64/ioapic_live.rs`, a target-only IOAPIC boundary. It
uses the permanent UC/NX mapping path already used by the xAPIC but extends the
stationary per-CPU scratch layout from one permanent MMIO leaf to two: one
remains the LAPIC leaf and the second is reserved for the validated q35 IOAPIC.
Neither leaf is a Process mapping or a `DeviceResource` capability.

The `deepwyrm_dw1e_platform` boot path is intentionally cfg-gated. It takes a
fresh bounded MADT snapshot, temporarily maps each candidate UC/NX only long
enough to read ID and version/max-redirection registers, resolves E1's exact
route using those measured capacities, then permanently maps and re-probes
only the selected controller. The published `ValidatedQ35IoApic` retains the
exact route/probe fact and serializes every IOREGSEL/IOWIN 32-bit volatile
transaction through an `IrqSpinMutex`. After permanent reprobe, E2A computes
the selected redirection low-register index from checked `GSI - GSI base`
arithmetic, reads it through that serialized owner, and rejects the platform
unless the existing mask bit is set.

IOREGSEL is an 8-bit selector. E2A admits only one through 120 redirection
entries: the final 120th entry occupies selectors `0xfe` and `0xff`. It rejects
a reported 121st entry and any read/write selector above `0xff` before volatile
MMIO, so malformed capacity facts cannot set reserved selector bits or alias a
different register.

No redirection entry is written in E2A. Therefore a validated route remains
whatever masked firmware/default state E2A observed; E2C alone owns reserve,
route programming, unmask, acknowledgement, quarantine, and final release.
E2B owns registration of the reserved cfg in `kernel/build.rs`, keyed to the
product identity without making selector 31 runnable.

## Lock/order record

Candidate probing uses the bootstrap scratch mapping before publication and
holds no scheduler, wait, process, object, or route-lifecycle lock. The
permanent controller owner serializes each selector/window transaction using
only its IRQ-safe controller lock. It does not call wait/scheduler/object
machinery while locked. E2C must retain this boundary and drop the controller
lock before delivery or EOI.

## Required-source receipt

| Source | Disposition |
| --- | --- |
| E0 contract, E1 status, architecture index, and I1 scratch design | **adapt** fixed route, UC/NX ownership, staged validation, and no-userspace-mapping invariants. |
| Fuchsia/Zircon `6a606ff7fd9b055edee6557566fb3f112df1a812`, `interrupt_dispatcher.cc` SHA-256 `8fcf75bfa8d47d99549266f2b097041d754cccf05dbeb052d18fea3f374f6a70`, `resource_dispatcher.cc` SHA-256 `db1bfb63e8175d25916d1abcdd4f0a0c13f6c1cc379e57145f0ec7ead7f7e678` | **concept only** bounded pending/lifetime and exclusive-controller validation; no source, ABI, or license text copied. |
| xv6-riscv `35b088427ef37611c38afdeed5a52a278cae38f9`, `trap.c` SHA-256 `6b7d192e64c49ce729dd3b597d8ba65e452e4c37d15942bab65660a032b3de60`, `plic.c` SHA-256 `125fc60925cae8cfff87450c88faa30634e4406f1e5a16234ff49ffba5dca7ab` | **concept only** controller ownership and bounded probe-before-dispatch; RISC-V/PLIC mechanisms rejected. |
| `uart_16550`, linenoise, and Fuchsia driver-manager sources in the phase cache | **not applicable** to target-only IOAPIC mapping/probe. |

All E2A code and documentation are first-party GPL-3.0-or-later. No external
implementation, expression, ABI, or license text was copied.

## Validation

The lane used separate pinned host/target directories:

| Command | Result |
| --- | --- |
| `tools/pinned-cargo host test -p deepwyrm-kernel --lib` | 783 passed. |
| `tools/pinned-cargo host clippy -p deepwyrm-kernel --lib --tests -- -D warnings` | passed. |
| `tools/pinned-cargo host fmt --all -- --check` | passed. |
| `tools/pinned-cargo target check -p deepwyrm-kernel` | passed. |
| Target check with temporary `--cfg deepwyrm_dw1e_platform` | passed; this compile-only check verifies the gated E2A boot path before E2B registers the canonical build hook. |

## Nonclaims and released seam

E2A does not add vector `0x30`, an IDT gate, assembly entry, LAPIC EOI,
`InterruptPlatform`, a route write/unmask, `Interrupt` delivery, UART policy,
selector 31, a complete UART driver, or VM acceptance. It does not claim that
the reserved cfg is active until E2B adds the build hook and the joined target
product is exercised.

**Released E2B/E2C seam:** `q35_ioapic()` returns only a release-published,
generation-neutral exact route/probe fact with its serialized register owner.
E2B may add vector entry independently. E2C must consume the owner for the
private generation-exact platform lifecycle and retain E0's edge-unmasked
acknowledgement rule.
