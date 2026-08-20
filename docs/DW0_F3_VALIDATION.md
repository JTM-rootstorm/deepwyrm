# DW0-F3 Validation Record

Status: **CLOSED — functional F3 gate passed**  
F3 implementation/evidence candidate: `635efab449234beecd5ef3d667efba7b8f3471b3`  
F2 baseline: `d8c226ccefe53ccb19a42e08b47924485103cf79`  
Wyrmroot paired revision: `bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`

This record closes only DW0-F3: the monotonic clock, finite-deadline engine,
IRQ-safe timer foundation, and live `clock_get(DW_CLOCK_MONOTONIC_ACTIVE)` path.
It is not an F-wide security or completion record.

## 1. Implemented F3 surface

F3 now supplies one reference time domain for later waits and Timer objects:

- validated ACPI PM Timer discovery from the FADT;
- `X_PM_TMR_BLK` System-I/O GAS preference with legacy `PM_TMR_BLK` fallback;
- explicit rejection of malformed/checksum-invalid, hardware-reduced, or missing PM timers;
- 24-bit and 32-bit PM-counter support at the ACPI fixed 3,579,545 Hz rate;
- checked counter extension and tick-to-nanosecond conversion;
- a half-wrap maintenance deadline so the reference configuration samples often enough to avoid ambiguous wrap extension;
- a bounded 64-entry generation-protected finite-deadline queue;
- outward-rounded Local APIC one-shot programming;
- Local APIC timer calibration against the validated PM counter;
- internal timer vector `0xe0` with a returning x86_64 interrupt path;
- an IRQ-safe spin-lock wrapper that disables local maskable interrupts before spin ownership and restores the prior IF state after release;
- scheduler state ownership moved to the IRQ-safe wrapper so timer wakeup cannot re-enter a plain scheduler spin lock on the interrupted BSP; and
- `clock_get(DW_CLOCK_MONOTONIC_ACTIVE)` with complete output preflight before clock read/copyout.

`DW_CLOCK_BOOTTIME` and other unsupported clock IDs remain deterministic
`NOT_SUPPORTED` results.

## 2. ACPI and MMIO ownership

The loader handoff guarantees the RSDP record, not arbitrary transitive ACPI table
identity mappings. An early exploratory F3 VM run exposed this boundary by faulting
when code attempted to follow the XSDT/FADT using the retired loader mapping.

The accepted implementation therefore traverses ACPI after Deepwyrm CR3 activation
through the authenticated C2 scratch mapper. The reader accepts only ranges covered
by the validated boot map as `RESERVED`, `ACPI_RECLAIM`, or `ACPI_NVS`; it rejects
USABLE, MMIO, runtime-services, unusable, unspecified, gaps, and overflow. No
persistent ACPI table mapping is retained after discovery.

The local APIC page is mapped separately through one reserved Deep-owned leaf as
supervisor read/write, NX, PWT+PCD. Before publication F3 reads `IA32_PAT` and
requires PAT entry 3, selected by PAT=0/PCD=1/PWT=1, to be architectural UC.
The transient scratch leaf remains available for normal page-table/user-copy work.

## 3. Deadline and interrupt semantics

The PM clock begins at the F3 initialization epoch; all ABI-0 finite deadlines and
`clock_get` observations use that same monotonically increasing nanosecond domain.
Real clock values never equal `DW_DEADLINE_INFINITE`.

The deadline queue stores the exact F2 generation-protected `BlockWakeKey`. Queue
capacity, invalid deadlines, stale cancellation, and generation exhaustion fail
closed. A failed live deadline registration returns the exact wake key to its owner,
including rollback after failed APIC reprogramming, so later wait code need not
strand a blocked Thread on a recoverable publication failure.

The timer ISR is bounded. While holding the IRQ-safe time lock it samples/extends the
PM counter, collects expired wake keys into fixed-capacity storage, selects and arms
the next user-or-maintenance deadline, and sends local-APIC EOI. It releases the
time lock before invoking the registered scheduler wake target. It performs no
usercopy, HandleTable mutation, typed finalization, or unbounded allocation.

A user-origin timer interrupt saves every GPR, conditionally `SWAPGS`es before Rust,
restores the interrupted state, and returns with `IRETQ`. Kernel-origin timer
interrupts do not swap GS. The local-APIC spurious vector is a direct returning
`IRETQ` path with no EOI or Rust dispatch; the APIC error vector remains terminal.

## 4. Host/model closure

The final host closure ran against the exact F3 source tree before the implementation
commit and passed:

1. `cargo fmt --all -- --check`
2. `cargo xtask abi check`
3. `cargo xtask test host abi`
4. `cargo xtask test host handles`
5. `cargo xtask test host memory`
6. `cargo xtask test host tasks`
7. `cargo test --locked --workspace --all-targets --offline`
8. `cargo clippy --locked --workspace --all-targets --offline -- -D warnings`
9. `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --offline`
10. `git diff --check`

Log:
`.artifacts/f3-implementation/final-validation/logs/full-host-closure.log`

SHA-256:
`1c7f104f59f62e459f9414b7fc403b4d40541ee6a1bd55c8100964e89dd991eb`

Focused F3 coverage includes PM conversion overflow/sentinel exclusion, 24-bit wrap
extension, missed-half-wrap rejection, NOW/finite/INFINITE classification, deadline
ordering/cancel/stale generations, outward APIC rounding, FADT/GAS validation,
IRQ-lock ordering, timer/spurious entry contracts, UC/NX LAPIC publication, and
`clock_get` output/domain validation.

## 5. Accepted-toolchain artifact gate

The accepted Rust identity remains `RUST-PHASE0B-TOOLCHAIN-001`, Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, with LLVM/Clang 22.1.8 tooling.
No Rust-fork or Wyrmroot change was required by F3.

Final selector-10 accepted oracle:
`.artifacts/f3-implementation/final-validation/logs/accepted-e7-closure.log`

Log SHA-256:
`c74a41583cc5eebe9f8625392908332ad9b2cd51ce61673390883b9ba310297c`

Accepted selector artifacts/facts:

- user ELF SHA-256: `732286bc6c65b3a6ee669a53aa3d9b2c44f8ce55caa91fcceb3796d1bcdac80b`
- kernel SHA-256: `3809b08b0be4d4df56dd29deb2273baa4c230c0356b214b491e2d480bbd54c6c`
- build-input manifest: `19eae74cb29809e1fc4d775d00f64186fe2d5745ce1f4c9da596cfc68147b1e0`
- normalized build environment: `c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`
- bootstrap stack: 94,688 / 131,072 bytes, 36,384 spare
- Thread stack: 11,976 / 65,536 bytes, 53,560 spare

The selector kernel was then independently rebuilt from committed revision
`635efab449234beecd5ef3d667efba7b8f3471b3` using the same normalized accepted
toolchain environment and reproduced the exact `3809b08b...4c6c` hash.

Final production/six-memory-selector oracle:
`.artifacts/f3-implementation/final-validation/logs/accepted-production-closure.log`

Log SHA-256:
`829342f80ebefe2db4190a5da904698450c6aa64d341c97cafc66e4c77b11c2a`

Production kernel SHA-256:
`d2832745c56c726a0b0ed0dc7ca54828e4f8febd0d7b036fdea445bfbb9578a0`

All six inherited memory-selector artifacts remained distinct and their stack/IST
margins passed. The production artifact remained separated from test-only markers.

## 6. Target/VM proof

Selector 10 remains `task-syscall-smoke`. F3 deliberately reuses this implemented
selector rather than pretending reserved F selector 15 already has a guest body.
Before CPL3 entry selector 10 now performs:

1. the accepted F2 two-stack/two-resume kernel-continuation round trip;
2. a synthetic F3 scheduler Thread transition to `Blocked`;
3. registration of an absolute deadline 20 ms in the future;
4. `STI; HLT` sleep, not a busy polling loop;
5. wake by the real Local APIC timer ISR using the exact F2 block generation;
6. validation that observed monotonic time is not earlier than the requested deadline; and
7. validation that APIC calibration produced a nonzero rate.

Only after that proof succeeds does the test enter CPL3. The userspace body then:

- performs the inherited hostile-GS selector reload before its first syscall;
- calls `abi_get_info` through the generated syscall veneer;
- calls live `clock_get(DW_CLOCK_MONOTONIC_ACTIVE)` and requires a nonzero result;
- verifies an unknown syscall returns `NOT_SUPPORTED`; and
- exits through the existing task/scheduler cleanup path.

The exact committed kernel was embedded in a fresh clone of the accepted F2 ESP and
re-extracted byte-for-byte before VM execution.

Final ESP SHA-256:
`b5635da36d062b0ff0874a3634ab0b78e74a3b42f0eddead9ebd894dea8225a4`

Final serial log:
`.artifacts/f3-implementation/final-vm-run/serial.log`

Serial SHA-256:
`7a93a31f2c09d3aa1b4cfe4e97ea2b97dbd9c4b4e64010a0d84f9be4799cf97b`

Accepted terminal output:

```text
wyrmroot-loader: UEFI adapter online
wyrmroot-loader: final UEFI memory map / ExitBootServices
wyrmroot-loader: ExitBootServices complete
wyrmroot-loader: entering Deepwyrm
DWTEST1|01|0000000A|00000000|5C9DAA15
```

The PASS therefore proves the q35 reference machine exposed a usable F0-selected PM
Timer and xAPIC timer path, ACPI traversal/checks succeeded, calibration succeeded,
the interrupt-driven finite deadline woke the blocked scheduler generation, and the
same clock domain was readable from CPL3. The test does not currently serialize the
actual discovered PM I/O port or measured APIC rate into the terminal record, so this
record does not invent those values.

## 7. VM restoration/provenance

The designated libvirt domain remained:

- URI `qemu:///system`
- domain `OS-Project`
- UUID `33005e22-d7c2-4b13-b1ac-b82eda95e584`
- one vCPU q35/UEFI F3 test profile
- no NIC or host share
- HPET explicitly absent
- selector supplied only through the existing test-only `fw_cfg` channel

Original and restored inactive XML SHA-256 are both:
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`

After the accepted run the domain was shut off, autostart remained disabled, the
external libvirt NVRAM path remained absent, and the primary
`/var/lib/libvirt/images/OSProj.qcow2` inode/size/mtime tuple was unchanged:
`1610625208 10739318784 1786749003`.

Paired immutable inputs retained:

- Wyrmroot system disk SHA-256: `8cf73f8d367b56e81afc7e25dba3226168f8f05790ccf7e846de51e931478133`
- OVMF code SHA-256: `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a`
- disposable pristine OVMF vars SHA-256 before run: `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc`

## 8. ABI/Wyrmroot impact

F3 changes no ABI schema, wire-record layout, syscall number, generated native wrapper,
or boot handoff layout. It activates the already-defined `clock_get` runtime behavior
and adds kernel-private time/interrupt implementation. Wyrmroot therefore remained
read-only and clean at `bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`.

The F1 additive generated-signal-helper consumer review/repin requirement still exists
for later paired F acceptance; F3 neither resolves nor worsens it.

## 9. Explicit non-claims and remaining work

F3 does **not** claim:

- functional `wait_one` or `wait_many` syscalls;
- generic wait registration or Event signaling;
- Timer object create/set/cancel semantics;
- Channel/handle-transfer behavior;
- atomic wait/wake;
- public `process_create` activation;
- a real sleeping userspace syscall continuation; F4 is the first generic wait consumer of F2+F3;
- selector 15 (`wait-deadline-timer`) is implemented or executed;
- SMP timer correctness or multi-vCPU interrupt routing;
- physical-hardware timing validation;
- formal F Daybreak review; or
- resolution of the existing deferred D/E Daybreak debt.

F13 remains the required F security-review gate. Nothing in this F3 functional closure
is a substitute for that review.

The F3 coordinator checkpoint is recorded in the workspace-root
`DW0_F_IMPLEMENTATION_PLAN.md`, SHA-256
`1bb9ca474e25b59479fd7dda6b69eb0626598a33a7a419c8bf61011ebf4d9f0e`.
The retained project-local evidence manifest is
`.artifacts/f3-implementation/F3_EVIDENCE_MANIFEST.txt`, SHA-256
`cfed48779ba652709476a26f5a891dce703d0facffbe67f1eb328bd8388da69d`.

## 10. Disposition

**DW0-F3 is functionally CLOSED.** The accepted q35 reference configuration now has a
validated monotonic nanosecond clock, bounded absolute-deadline engine, IRQ-safe timer
ownership, real interrupt-driven finite wake path, and live CPL3 `clock_get` access.

The next implementation phase is **DW0-F4 — waitable signal core and Event objects**.
