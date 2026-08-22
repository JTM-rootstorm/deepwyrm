# DW0-G Validation Record

**Status:** DW0-G FULL ACCEPTED for progression to DW0-H; G5 accepted and P0 accounting reconciled

**Date:** 2026-08-22

The accepted paired artifact root is
`artifacts/dw0-g3/accepted/dw-91d9b204c1ed__wyr-f433baf36d67__rust-a92dc7f7464/`.
Its final `MANIFEST.sha256` hashes to
`67c88666079db335d5aa81414c553c140e394a5ebdee2706267ae6e8bd58aac0` and verifies all 97
entries, including both evidence TOMLs. No accepted-root symlinks exist.

## Source and toolchain identity

- Deepwyrm: `91d9b204c1ed0bdd4cef934e1be6203d41e9e5c3`;
- Wyrmroot executable/artifact source: `f433baf36d671f3f8b515adf5f613bd01dc8bbb9`;
- Wyrmroot provenance descendant: `21e4c1a05a62a00ee7a97babdcecea97bba909f1`;
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`;
- rustc: 1.97.1-dev with LLVM 22.1.6;
- resolved Wyrmroot cfg: no `x87` or `fxsr` target feature.

Deepwyrm and Wyrmroot full locked workspace/all-target tests, strict Clippy, warning-denied docs,
formatting, diff checks, and Deepwyrm ABI drift checks pass. Rust target tests pass 329/329. All
production and selector kernels are static ELF64 `ET_EXEC` images with three W^X load segments, no
dynamic section, and no undefined symbols. All native Wyrmroot variants pass their exact artifact
oracle and contain no hardware FP/vector instructions. Three independent production ESP builds are
byte-identical, and every production/test ESP re-inspects to its exact loader, kernel, bootstrap,
and bootfs inputs.

## Designated-VM evidence

Canonical campaign `artifacts/dw0-g5/run-01-canonical/` ran the designated `OS-Project` domain on
`qemu:///system` under the uninterrupted exclusive lease. Every run used q35, OVMF/UEFI, one vCPU,
2 GiB memory, host-passthrough CPU, one read-only request-local ESP, request-local NVRAM, no guest
network, no host filesystem share, and no graphics device.

| Selector | Proof | Terminal record |
|---|---|---|
| 18 `primordial-bootstrap` | normal INIT, bootfs validation, READY, exit zero, full teardown | `DWTEST1|01|00000012|00000000|1B75A741` |
| 19 `primordial-blocking-cleanup` | GenericWait and AtomicWait idle suspension/resume with timeout, then full teardown | `DWTEST1|01|00000013|00000000|429CFD1E` |
| 20 `primordial-user-exception` | READY, vector-6 `UD2`, structured exception termination, full teardown | `DWTEST1|01|00000014|00000000|68A714A7` |
| 21 `primordial-invalid-return` | READY, rejected `RSP=0` return, structured termination, full teardown | `DWTEST1|01|00000015|00000000|8F29724C` |

Each record is unique and checksum-valid. Each run ended with libvirt's guest-request shutdown. The
inactive domain XML was restored byte-for-byte after every selector and at campaign end to SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`. The primary disk remained
detached and its device, inode, size, capacity, allocation, and physical-size bookends are identical.

## Security and scope

The exact `gpt-daybreak-blue-latest` rereviews pass C0/H0/M0/L0 after all findings and the final
provenance request were remediated. See `security/DW0_G_SECURITY_REVIEW.md`.

G5 is accepted and the separate P0 accounting lane was closed from exact retained F12/F14 loader/VM
evidence plus WYR0-C library/contract continuity. The one-off root reconciliation record has since been
retired with the completed G coordination material and remains available in Git history. **DW0-G is FULL
ACCEPTED for progression to DW0-H.** This still makes no SMP, preemption, real-time, general-exec, physical-hardware, i386,
full-WYR0-F, or full-Wyrmroot claim.
