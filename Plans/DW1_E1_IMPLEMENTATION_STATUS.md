# Deepwyrm DW1-E1 Implementation Status

**Status:** Reached host/model gate

**Date:** 2026-08-31
**Implementation authority:** `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`,
section 6, DW1-E1; and `DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md`.
**Base Deepwyrm revision:** `16722c1b86ff9da7ed18208c78bb0c690b7d5215`
**E1 implementation revision:** `b90a1dc3abe2fc35924e7d018749091cb8fa77e1`

## Reached scope

E1 adds a bounded, immutable-snapshot q35 COM2 route model in
`kernel/src/arch/x86_64/acpi.rs`.  It reads only a selected MADT snapshot and
does not install an IDT gate, map an IOAPIC, execute volatile MMIO, alter a
public ABI, or add selector dispatch.

The model preserves the reached CPU-topology parser and fixtures while adding:

- exact MADT type-1 IOAPIC (12-byte) and type-2 interrupt-source-override
  (10-byte) validation;
- bounded IOAPIC descriptors (ID, physical page, GSI base) plus explicitly
  supplied later-probe redirection capacities;
- exact COM2 ISA IRQ3 resolution: absent override is GSI3 edge/high; only a
  bus-0/source-3 override resolving edge/high is admitted;
- one covering probed IOAPIC, physical BSP xAPIC destination, and fixed vector
  `0x30`; and
- a pure redirection-entry codec and one-source reserve/commit/retire/mask/
  release lifecycle, all independent of volatile hardware state.

Malformed records, zero/unaligned MMIO proposals, duplicate controller facts,
duplicate IRQ3 overrides, reserved polarity/trigger fields, active-low/level
IRQ3, empty/overflowing or ambiguous coverage, and mismatched probes fail
closed.  Firmware remains a proposal; E2 still owns mapping, controller ID/
version verification, and route publication.

## Changed files

| File | Change |
| --- | --- |
| `kernel/src/arch/x86_64/acpi.rs` | Snapshot parser, route resolver, redirection codec, pure lifecycle, and host negative corpus. |
| `Plans/ARCHITECTURE_INDEX.md` | Indexes this reached E1 record. |
| `Plans/DW1_E1_IMPLEMENTATION_STATUS.md` | This implementation/provenance/status record. |

## Validation

All commands used `tools/pinned-cargo` with lane-owned target directories.

| Command | Result |
| --- | --- |
| `tools/pinned-cargo host test -p deepwyrm-kernel acpi::tests --lib` | 16 passed, including all prior CPU-topology fixtures and four E1 route/codec/lifecycle tests. |
| `tools/pinned-cargo host clippy -p deepwyrm-kernel --lib --tests -- -D warnings` | passed. |
| `tools/pinned-cargo host fmt --all -- --check` | passed. |
| `tools/pinned-cargo target check -p deepwyrm-kernel` | passed. |

The E1 corpus covers normal q35 default and explicit edge/high routes; no
IOAPIC; zero/unaligned address; range overflow; no and overlapping coverage;
duplicate controller identity; reserved/unsupported polarity/trigger;
duplicate IRQ3 override; malformed type-1/type-2 records; masked/unmasked
redirection encoding; delivery-status decoding; and generation-exact pure
lifecycle transitions.  Existing topology tests remain green.

## Required-source and provenance receipt

| Source | Exact identity / disposition |
| --- | --- |
| `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, E0 contract, architecture index, DW1-D contract/validation, and ACPI/interrupt/APIC in-tree seams | **adapt** the bounded snapshot, fixed route, topology preservation, generation, and no-live-hardware constraints. |
| Fuchsia/Zircon `6a606ff7fd9b055edee6557566fb3f112df1a812`, `interrupt_dispatcher.cc` SHA-256 `8fcf75bfa8d47d99549266f2b097041d754cccf05dbeb052d18fea3f374f6a70` | **concept** bounded pending/ack lifecycle only; no source or ABI copied. |
| Same revision, `resource_dispatcher.cc` SHA-256 `db1bfb63e8175d25916d1abcdd4f0a0c13f6c1cc379e57145f0ec7ead7f7e678` | **concept** exclusive validation/lifetime only; no resource model imported. |
| xv6-riscv `35b088427ef37611c38afdeed5a52a278cae38f9`, `trap.c` SHA-256 `6b7d192e64c49ce729dd3b597d8ba65e452e4c37d15942bab65660a032b3de60`, `plic.c` SHA-256 `125fc60925cae8cfff87450c88faa30634e4406f1e5a16234ff49ffba5dca7ab` | **concept** controller ownership and returning dispatch only; RISC-V/PLIC details rejected. |
| Same xv6 revision, `uart.c` SHA-256 `6c284f94eb8fcca9c723015f366a849a441f462b99d16e3cca5880439df6a493`, `console.c` SHA-256 `d3088059d9591e367b7b15706590e472fe38cc505b22d7d8cf03b8da5de5d699` | **not applicable**: UART/console policy belongs to WYR1-D, not E1. |
| `uart_16550` `176b07b076bdc1fe999a5e757ab53a0e24b4005c`, linenoise `a473823d74b93eab2ba83480df16ed37617493f2`, Fuchsia driver-manager cache archive SHA-256 `fc55c4fd35903416f9ac152c1d75d76af4e9c0cb5a00a9f6b442192def2560c4` | **not applicable**: serial, terminal, and driver-framework policy are outside host-only kernel route discovery. |

All E1 code and documentation are first-party GPL-3.0-or-later. No external
implementation, expression, ABI, or license text was copied.

## Risks, nonclaims, and released seam

E1 does not claim live MADT use during boot, IOAPIC MMIO or version probing,
UC/PAT mapping, an IDT gate, vector `0x30` entry, LAPIC EOI, physical IRQ3,
selector 31, UART policy, MSI/MSI-X, level/active-low routes, x2APIC, PCI,
hotplug, or VM acceptance.  The pure model's supplied probe capacity is not a
hardware observation.

**Released E2 seam:** consume `PlatformIrqRoute`, obtain and verify the exact
descriptor/controller capacity through a permanent serialized IOAPIC MMIO
owner, and couple the pure lifecycle to masked write/readback plus the E0
delivery-status quarantine rule.  Preserve the private edge-unmasked
acknowledgement seam; no public `Interrupt` ABI change is released or needed.
