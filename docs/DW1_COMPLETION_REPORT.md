# Deepwyrm DW1 Completion Report

**Status:** DW1 complete, 2026-11-10.

DW1 closes on Deepwyrm `831e2ad3d40c530d0182938b19844f13f579b2f7` (code identical to `3caecc3`) paired with Wyrmroot `45a45e05631104ccb4ad145cc502f73b9907dca8`. The production kernel SHA-256 is `13db636a47f440522f85f5b6a38483fa6d53cc7b1ddbddeb7bfa7f485251a312`. The paired certificate is the OS-Project root's `DW1_WYR1_INTERACTIVE_SHELL_CAPABILITY_CERTIFICATE.md`, and the live and reproducibility record is the root's `DW1F_WYR1F_F3_RECORD.md` §6. That record and this report are the DW1 validation record; there is no separate `DW1_VALIDATION.md`.

## What DW1 adds to DW0

- timer-driven preemption of userspace, on one CPU and on four;
- a normal-class per-CPU round-robin scheduler, under which a CPU-bound thread cannot starve the others;
- the typed DeviceResource and Interrupt objects, with exact PIO and IRQ authority for the q35 COM2 UART;
- a real q35 IOAPIC route for COM2's interrupt;
- TaskGroup limits, enforced by the kernel, that bound a shell's jobs, together with containment of creation inside a limited subtree (F4).

## Evidence

- Phase records: `DW1_A_VALIDATION.md`, `DW1_C_VALIDATION.md`, `DW1_D_VALIDATION.md`, `DW1_E_VALIDATION.md` in this directory.
- Security: [`../security/DW1_SECURITY_REVIEW.md`](../security/DW1_SECURITY_REVIEW.md). No Critical or High findings. The one Medium is fixed, and the residual risks are fixed or accepted as Low.
- Final pair: host tests, clippy, fmt and the production target check pass. The product boots and runs the shell scenario on one and four vCPUs, and two builds are byte-identical (root F3 record §6).

## Nonclaims and deferred work

- No physical hardware acceptance.
- Delegation of an existing process handle is not confined by TaskGroup limits; the mapping-pool bound relies on Wyrmroot never giving jobs foreign process handles (`Plans/DEEPWYRM_PRE_PHASE0_INVARIANTS.md` §10).
- Device authority covers port I/O and one legacy interrupt. MMIO, DMA and IOMMU are the next kernel work, as the storage driver needs them.
