# WYR1-C6 selector-29 evidence seam

Status: Deepwyrm selector integration and exact-pair live Wyrmroot acceptance complete.

This document defines the test-build-only transport consumed by the Wyrmroot
C6 controller. It is not a native ABI addition and does not claim physical
IRQ3, PIO, UART, stream, console, or shell behavior. Those boundaries remain
in `wyrmroot/Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md`; physical IRQ routing is
deferred to DW1-E.

## Exact private seam

The selector registry is `tooling/guest-harness.toml`, with ID 29. The kernel
build emits `cfg(deepwyrm_wyr1c_evidence)` only for that selector and requires
`DEEPWYRM_WYR1C_EVIDENCE_NONCE`, exactly 16 uppercase hexadecimal digits and
nonzero. The raw operation is `0xffff_ff1e`; it is routed only by the selected
test kernel and is intentionally absent from `abi/generated/deepwyrm_abi.rs`.

Each submission is a fixed 113-byte ASCII record:

```
WRC6|01|NNNNNNNNNNNNNNNN|SSSSSSSS|EE|LLLLLLLLLLLLLLLL|BBBBBBBBBBBBBBBB|VVVVVVVVVVVVVVVV|AAAAAAAAAAAAAAAA|CCCCCCCC
```

`N` is the build nonce, `S` is the zero-based sequence, `E` is the event,
`L/B/V/A` are opaque Wyrmroot lease, binding, value, and auxiliary fields,
and `C` is uppercase FNV-1a-32 over bytes 0..104. A nonterminal event requires
nonzero `L`; terminal event `FF` requires all four tuple fields to be zero.
The collector accepts exactly 27 records and rejects malformed, out-of-order,
wrong-nonce, checksum-invalid, duplicate, early, full, or post-terminal input.

The ordered events are:

1. `D1_BEGIN`
2. `D1_LEASE`
3. `U1_START`
4. `U1_READY`
5. `P1_PUBLISH`
6. `U1_FAILURE`
7. `P1_RETIRE`
8. `U1_REAP`
9. `OLD_IRQ_RELEASED`
10. `U2_START` (same D1 lease)
11. `U2_READY` (same D1 lease)
12. `P2_PUBLISH` (same D1 lease)
13. `STALE_REJECT`
14. `D1_FAILURE`
15. `P2_RETIRE`
16. `U2_REAP`
17. `D1_GENERATION_CLEAN`
18. `D1_GRANT_AVAILABLE`
19. `D2_LEASE` (different lease generation)
20. `D2_START`
21. `D2_CLAIM`
22. `D2_READY`
23. `NO_AUTHORITY`
24. `NO_IO`
25. `ACCOUNTING`
26. `BOUNDED`
27. `FF` terminal

Deepwyrm preserves the opaque fields and validates framing/order only;
Wyrmroot proves rights, custody/reclaim, generation relations, stale rejection,
authority absence, no-I/O, and accounting semantics.

## Reporter and terminal invariants

The reporter is the exact first child created by the primordial process (the
permanent system-init/controller). Its root, executable entry mapping, fixed
stack geometry, RW/NX stack protection, and guard absence are checked using the
selector-27 startup facts. The one-shot bind occurs only after primordial
quiescence, root retirement, kernel/monitor peer release, finalizer drain, and
retention of the private primordial PML4. Authority is checked before usercopy.

The terminal reporter claims one atomic COM1 transaction, writes all 27 WRC6
records, appends `DWTEST1` 29/0, flushes, and issues the matching debug exit.
Failure paths claim the same one-shot terminal owner and publish only a bounded
completion failure; no partial WRC6 prefix is relabeled as PASS.

## Required-source and provenance disposition

The seam follows `Plans/WYR1_B0_REGISTRY_LAUNCH_EVIDENCE_DESIGN.md` for
selector registry identity, exact permanent-controller authority, fixed startup
facts, private raw-operation routing, and atomic terminal transport. It follows
`Plans/DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md` and
`docs/DW1_D_VALIDATION.md` for DeviceResource/Interrupt ownership boundaries
and the no-physical-I/O stop line. The Wyrmroot event order and nonclaims are
from `wyrmroot/Plans/DW1C_WYR1C_IMPLEMENTATION_PLAN.md` and
`wyrmroot/Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md`.

No external code was copied. The collector is a selector-local adaptation of
the existing first-party WRB1 framing/terminal pattern. C5 bundle wire shapes,
physical IRQ/PIO, and C6 Wyrmroot lifecycle execution remain owned by Wyrmroot.

## Target integration validation

Selector 29 is a resource-domain product profile, not only a host collector
model. Its freestanding build therefore selects the canonical name (the build
script derives ID 29), supplies the WRC6 nonce, admits exactly one boot resource,
uses resource READY, and compiles the permanent-reporter and resource syscalls
together. The profile has explicit bounded capacities: eight live Process
identities, 24 Channel pairs, 32 handles per Process, 28 memory objects and
leases, 160 registry objects, and a 256-page bootfs ceiling. These bounds do not
apply to ordinary production or other selectors.

The accepted product compiler gate is:

```text
RUSTFLAGS="-D warnings" DEEPWYRM_GUEST_TEST_SELECTOR=device-coordinator-restart \
DEEPWYRM_WYR1C_EVIDENCE_NONCE=<16 uppercase nonzero hex> \
tools/pinned-cargo target build --locked --offline --release \
  --target x86_64-unknown-none --package deepwyrm-kernel \
  --bin deepwyrm-kernel --features test-support
```

The separately installed host Clippy cannot validate the custom freestanding
sysroot and must not be treated as a target product result. Use warnings denied
on the accepted target build plus the pinned host collector/source tests; do not
install or substitute a host target during closure.

## Exact-pair live disposition

WYR1-C accepted selector 29 on 2026-08-31 at Deepwyrm
`6ba05d6706a0f376c0af0b4ce86305af01748cce`, Wyrmroot product
`b872e3bd465e3f6d9c9e90adbceb3756dc490dc2`, and Rust
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`. The canonical verified
`qemu:///system` runner accepted both the one-vCPU and four-vCPU q35/OVMF
profiles. Each emitted all 26 ordered semantic facts plus the zero-tuple `FF`
terminal and a selector-29 `DWTEST1` PASS.

The byte-identical WRC6E1 transcripts have SHA-256
`570aef9dc493555f89c2204f084f94afee972e503f7147a824dfdb42f5b8902e`.
They prove D1 lease 1, same-lease fresh U2, newer P2, stale U1/P1 rejection,
D1 cleanup and grant availability, distinct D2 lease 2, exact D2 custody
transitions, three non-coordinator principals without direct device authority,
zero physical I/O, and bounded restart accounting. The exact Wyrmroot product,
artifact, regression, and nonclaim record is
`wyrmroot/Plans/WYR1_C_VALIDATION.md` in the paired workspace.
