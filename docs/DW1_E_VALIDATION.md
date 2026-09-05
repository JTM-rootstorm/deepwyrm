# Deepwyrm DW1-E Validation and Closure Record

**Status:** Accepted on the exact frozen selector-31 profile pair and affected
selector regression matrix

**Validation date:** 2026-09-04

**Deepwyrm implementation revision:**
`689320ba29bcac3e13181f4e5f6e2ea80d96d2f0`

**Wyrmroot integration revision:**
`06299cf0a2f8f5db8b582b862b278e8b2bd9eb38`

**Generated ABI revision:**
`085b184c32ae1fa3d5ec322c86957dd5d036595c`

**Generated ABI Git tree:**
`a9b067107ec38e2be44630f4dce428dab0f48de8`

**Rust revision:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`

**Primary selector:** `q35-com2-interrupt` / test ID 31

The frozen products all record the same accepted compiler/toolchain:

| Toolchain item | Exact identity |
| --- | --- |
| name | `wyrmroot-1.97.1-a92dc7f7` |
| `rustc` SHA-256 | `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70` |
| `cargo` SHA-256 | `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce` |
| `rust-lld` SHA-256 | `38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721` |
| toolchain manifest SHA-256 | `cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2` |
| toolchain tree SHA-256 | `dce57d31def1f509ce537f96ae6b6dd320da11c9f321382cb93d142f558a32ca` |

This record closes only DW1-E's q35 COM2 external-interrupt kernel/platform
scope. The accepted implementation and products are the exact revisions and
hashes below. The commit containing this document is a documentation-only
descendant and does not replace those frozen identities. DW1 remains open.

## Reached implementation

DW1-E was implemented through these reached Deepwyrm checkpoints:

| Slice | Revision | Reached behavior |
| --- | --- | --- |
| E0 | `16722c1b86ff9da7ed18208c78bb0c690b7d5215` | fixed q35 COM2 IRQ3 edge/high contract, vector and delivery-status rules |
| E1 | `16d5778bfe083fbd60009cb792f96897c65e76e0` | bounded MADT IOAPIC/override snapshot, exact route resolution and redirection model |
| E2A | `570aa03d213c3361ed6b4137839f43320fee3046` | permanent UC/NX IOAPIC owner, checked selector/window access and masked-route probe |
| E2B | `b4ecd7ba75210a6ddf1f7e786a4595b2e170e5d0` | returning vector-`0x30` entry, one-shot dispatch binding and post-dispatch LAPIC EOI |
| E2C | `80f4c29d892ae038d6c855a2dbcf3c05094ba5a7` | generation-exact physical Interrupt delivery, edge-unmasked ack and retirement quarantine |
| E3A | `bafcfc6414df415c42933aabf1a8da1e811c6826` | first live raw COM2 challenge and records 0 through 8 on UP/SMP |
| E3B | `8f4b1b8cac877f8a040ab2990050b154483f7828` | complete restart/rebind, two host challenges, 26-record terminal evidence and accepted UP/SMP pair |
| E4 repair 1 | `ab09900df907ca68b61f080960b9c198c7adae0f` | corrected the stale IPI EOI source contract after E2B extraction |
| E4 repair 2 | `1c8ffe3b631a25afc4ff4bc63abc3f36a61c5c5a` | kept q35 retirement helpers private to selector 31 so historical products build unchanged |
| E4 repair 3 | `fb7cb148788efe21d3410edb0ff60f2e7cbf3ffa` | drained CPU0 timer-expiry inbox work before idle scheduling |
| E4 closure | `689320ba29bcac3e13181f4e5f6e2ea80d96d2f0` | preserved terminal scheduler-current root ownership and routed exact remote Stops through the reaper |

The public ABI and generated definitions did not change during DW1-E. The
kernel admits only the fixed q35 COM2 source: logical IRQ3, MADT-resolved GSI,
active-high edge trigger, fixed physical vector `0x30`, and CPU0's discovered
xAPIC destination. The source drives the existing DW1-D `Interrupt` object;
userspace acknowledgement and IOAPIC completion remain separate.

## Accepted selector-31 product

The primary immutable candidate is rooted at:

```text
../../artifacts/dw1-e/s31-final-689320b-c4
```

It uses q35 (`pc-q35-10.2`) plus OVMF, 2048 MiB, no network, no host share,
no system disk, COM1 for structured evidence, and COM2 through the verified
task-owned Unix socket. The default profile uses one vCPU and the SMP profile
uses four vCPUs.

| Item | SHA-256 or identity |
| --- | --- |
| evidence nonce | `0000000000000142` |
| challenge 1 nonce | `0000000000000143` |
| challenge 2 nonce | `0000000000000144` |
| request | `68db869a295feae3884ca1507bb4fb46a3a119319f8eeca468df17e01e531fbe` |
| profile pair | `a6a1710b7812cf546934e36ec066a94b072b25bac75e5fb9dbffa4dfcb977bcd` |
| profile-pair result | `018fabd3fdeaab2c0e91dadb75e8c4c44bf88f5d35a3c3b9edc99c00f88787fc` |
| freeze receipt | `1caea89e855f0f2f8b78182fd8a3ba3863fb7754a2848ecfccefb5de46280fda` |
| kernel and symbols | `88058772b56053024fa5b288fb8b57b297f930ee4383702930b88a8725b85376` |
| bootfs | `99bace24d5d2bc4803a32b78bc84e80d093beff313d45dec045b219cf35f9396` |
| ESP | `705d560dbdbbba134a38e01e766fe20d3771b7ff6470e3a3362c0426056d5cfb` |
| default result/acceptance receipt | `d8cedff3c2c0354ca41c938734b08b343c73f9be9aded856d990207ee7bb9074` |
| SMP result/acceptance receipt | `68e476ef2eef3bfa872f6fb32920fbc9bfd0e29279b8177420ca8129e41928ec` |

## Structured live selector-31 evidence

Both canonical `qemu:///system` runs on the designated `OS-Project` domain
passed. Each emitted the complete ordered 26-record `DWE3E1` sequence,
`DWTEST1 31 0`, and debug exit 33. Default evidence SHA-256 is
`ed43dbe71ed6d0e8c71347e12805dace7a7c971ca3c1128dcea5e05fc2788eb7`;
SMP evidence SHA-256 is
`197a775673954aec5219622df93e3f19c651a4cc58ae0382efadfe2d61ddd280`.

The raw COM2 transcript is byte-identical in both profiles, SHA-256
`ccc001ec41ec19c8d4f7b2e73e5b7c7363acd68288c64fc928322a3a39a9c2f0`.
The two request-bound challenges and responses are:

| Leg | Challenge SHA-256 | Response SHA-256 |
| --- | --- | --- |
| U1 | `1c41261dafceeaeac94270bf879011f0020b7e21e02ddad6dfd68ab40cef6224` | `06b2e5bb999f5970ac55492159f3569a4374210353a881f7e0ac3360fb726a6d` |
| U2 | `f83b6e59cfda4db7a244a0ef1321a529ba9ee6adc9aeec6655ba0a60b6aa39a9` | `a358824385eae855817c81443628aead71f944cbf9e9df33d3456fb385a43178` |

The evidence proves the validated route is initially masked; U1 obtains the
exact device lease, Interrupt, driver, stream, challenge and response; real
physical entries join typed delivery, wait wake, UART drain and userspace
ack; retirement masks and quiesces the old route before release; U2 receives
fresh object, route, binding, attempt, stream and challenge generations; a
saved U1 delivery is rejected as stale; coherent accounting is frozen; and a
single trusted terminal owner publishes success. The SMP result proves this
same CPU0-targeted IRQ/wake path while the reached four-CPU scheduler is live;
it does not claim balanced IRQ steering.

## GDB-led failures and broad reconciliation

GDB was used with the canonical active-debugger runner against exact frozen
products. It was diagnostic evidence, not a substitute for the request-bound
verified runs. The investigation deliberately included timer/wait delivery,
scheduler callers and callees, terminal preparation, resource lifetime,
root-switch mirrors, migration, reaping, selector harnesses, recent changes,
and all phase-required prior art.

### CPU0 timer-expiry inbox

The first E4 selector-29 SMP replay at Deepwyrm `1c8ffe3...` failed with
`DWTEST1|03|0000001D|057C03AF|F5C1178C`. The retained diagnostic roots are:

```text
../../.tmp/dw1e4-s29-gdb-inbox-r1
active.gdb.log SHA-256 7196c97c40728047860ec4555fd3a42d979aa4dd48e16149ad4515a8a7998e81
hooks.gdb      SHA-256 469609311f41664e1cb238308de46ce7631dbec943a156012dd415e88cf76320
serial.log     SHA-256 03053ee57ab34ea2b68ab7356a0048cdb7efd4c085817ac9b10c7a78214cc3b4

../../.tmp/dw1e4-s29-gdb-origin-r2
active.gdb.log SHA-256 9102efec92ddc09bc6c221f8fbb604f91c7f802de6f2049cf6447a9bcf522297
hooks.gdb      SHA-256 6d2192509ea7b8d0ba37bdfbf1f4889b6238f22055ae8b007a5550e7ffb01b8b
serial.log     SHA-256 2b39a6b3a04ccda459126dc8eb9c59e2af0dd7acfc2741112d3d0252197e7e42
```

The first trace observed 65 timer-expiry callbacks after system-init and no
matching CPU0 idle drain before the fixed-capacity 64-slot inbox overflowed.
The origin trace showed kernel-origin timer returns cycling through the late
drain while debugger timing allowed selector 29 to pass. The repair drains
the CPU0 timer-expiry inbox before the idle path calls `schedule_next_on`, and
source contracts bind that ordering. It changes no timer or selector
capacity.

### Terminal scheduler-current ownership

After that repair, selector-28 stress-1 at `fb7cb14...` failed on CPU1 with
`DWTEST1|03|0000001C|057C1194|CEBC853A`, mapped to
`prepare_scheduler_root_switch()` reporting that its scheduler-current Thread
had no execution resources. The exact panic breakpoint was exercised against
the frozen symbols at:

```text
../../.tmp/dw1e4-s28-gdb-r1
active.gdb.log SHA-256 de47e6cff85ad4f334a76eef906d8eb68f317d68d764d70aeea8cc82223a148c
hooks.gdb      SHA-256 85b1ad2218f55e5888ca77fe990c07fc173ca13b76e4d629a0cd7734e54d656b
serial.log     SHA-256 75e1671fd06b2b510dfe303ccf2a5be18912d9b47741d5e8e21ab6a41e476574
symbols        SHA-256 9f1501f639f56d49fa241d2bff4da8423e69e696de8f74bf2cb1f413f1011e86
```

That debugger run did not hit the breakpoint because its timing was
perturbative; it is not claimed as a reproducing pass. The exact failure and
symbol mapping, followed by the broad source audit, established the ownership
gap: terminal preparation can move the current Thread's stack/context into
its exit pins while the scheduler-current claim remains temporarily live.
Direct detached root synchronization could then inspect those deliberately
detached resources before the exact remote Stop or local terminal handoff.

The closure fix returns the typed terminal scheduler-current identity rather
than a boolean hint. All three direct detached root-sync callers now arbitrate
the exact Stop before root preparation and pivot through the dedicated
rendezvous reaper. The local self-terminal post-permit path instead verifies
the exact Thread and Process owner and retains its active Process root until
the prepared terminal handoff consumes it. Independent review covered direct
Stop, local self-terminal completion, root assertions, lock/lifetime order,
all three callers, late wake, migration and reaper replacement; it found no
blocking adjacent defect.

## Affected selector regression matrix

Every affected selector was rebuilt and rerun after the final scheduler fix
on the exact accepted Deepwyrm/Wyrmroot/Rust tuple.

### Selector 28: four-CPU scheduler campaign

The immutable root is
`../../artifacts/dw1-e/2026-09-04-selector28-dw-689320b-wyr-06299cf-c4`.
Request SHA-256 is
`4ef27a11d9a2969799b2b71b3272bc5425550b5a30759e48c594bdb49fc4e6a2`;
campaign SHA-256 is
`0779fa31e4350e7b5d51bcaf631b7e5daeecf9e69f858192b0b9ef86cc46ef73`;
campaign-result SHA-256 is
`ece483ab4c3a5baaf58a78eec5011a275651a503d010cd0ab3f0b6e7d7339e3c`.
Smoke and stress 1 through 5 all passed with 46 records, detail zero, debug
exit 33 and maximum ready delays from 25,088,384 ns through 29,282,772 ns.
Their evidence SHA-256 values, in order, are:

```text
19d2f82486982bb03c66834f553dd2f3b6c1a7732ff9ba0f2791986bb05e57a7
d4eae2bfec93e2f7c8043afa15f32a3d91e68f86cd54d04fdaecb12c73f35db7
b132642ff4a4cfd2302aa00af15fa0b248333dece34e920522ab3ecee5c832e0
b0c8e2ecda6e05a95fd948d769158c3ccff7a9af42175dc84630b8bd5d3acdd0
221a862f065cee0d82f82f6ab59e3961d6c121e5ee04d50e65d20e912777e8e1
c8f207cafe8c67b34848e7f6a828bc88ab4bd5885835f57dae1b979f202db56e
```

The matching per-pass result SHA-256 values, smoke through stress-5, are:

```text
1eca438b3efc64741108b08c7d2f5e32dc6ef0585f2049a3ed553007314b7ee8
4c3fb2fa7581f49b37a920b401f28d270138b9f0ecd5abdcbe88633dae2955e1
5b54dc63ecfb00400e04b79fffc596a15ee3e00c7aa8f7ca771733c3a53a4297
2342756985370c5a34a9c592cb446ce17d889719d91bcb573a11e98bec8c4f88
9aa9110ba311ef63ff7faf5b56ae8b98d42fa9097ee41a194802fbbb157f53e6
7eca53ac7e651970acf74f2f6012c7b566acf72d0dc254dc55f8ef5af2943dc0
```

The product build receipt is `e5fb699c8bb3de1b2859aeec61a4cf0f235083f2e3e229f96c5e128c2e3fc628`;
kernel/symbols are `63a4b1234ca9b944224dd4714aa6b34a2804324daeacf56cf82e0900bbf487d5`;
bootfs is `a2fba1c3ffd9ffadee2815e54ac79a6cf8c181f43d4bcbe9535774243b7a1cc7`;
and ESP is `79d7f465be400dd308ad4de6dd0e03f3e62c10190e939f3ee8e303d4ea76cc0d`.

### Selector 29: device-coordinator restart

The immutable root is
`../../artifacts/dw1-e/2026-09-04-selector29-dw-689320b-wyr-06299cf-c5`.
The default and four-vCPU SMP profiles both passed with the same ordered 27
`WRC6E1` records, detail zero and debug exit 33. Evidence SHA-256 is
`0f0f8af7fc052871bc3c408d3a0e809272f04a53f1630200a9bfb4fa2b50d4ff`;
profile-pair result SHA-256 is
`be3d896293ceeef362711f6bc3a07bc0ff2c6689eb3e79f5f5985868c31f261b`.
Default/SMP run-receipt SHA-256 values are
`ac4b98ae535b187bef2e22c607973cdb775f8522e847b156230eeb68d3bf9a10`
and `42e45dbb4d296f46ce70c8403079a7f914b4be35c6299dc7c971174fb9ffa043`.
The request is `dae648e782fce9879029567f09feaca0d9b1b16205843ce47443d077ee9eeb79`;
build receipt is `e3427441114564a373c6e824f2e76c74fe7ee6bb0775856b1be540e44592dd86`;
kernel/symbols are `035fda35163e035d2192fed99d3ae293b758d5f23c88a2b260e457df608c4118`;
bootfs is `9b34b27b8c1c83acf348e1908e36a76cd0dc0b6ae436b8248bb110c122a6fb5c`;
and ESP is `13eff49e1c0033aeac00cec7097cffc73ded62ff8e2fd8cb43cee31cb1387d09`.
The accepted selector remains virtual-only and explicitly records
`physical_io = not-performed`.

### Selector 30: synthetic DeviceResource/Interrupt

The immutable root is
`../../artifacts/dw1-e/2026-09-04-selector30-dw-689320b-wyr-06299cf-c4`.
Smoke and four-vCPU coexistence both passed with identical ordered 40-record
evidence, detail zero and debug exit 33. Evidence SHA-256 is
`9851a01004c79fadc34f4a9cb30e5342877e0884460e1b8d5e998f0ae47f8397`;
profile-pair result SHA-256 is
`4325b31e602eba8363a67b22580c2c39b642d2f06b1abcc27f08adf60b3b54e7`.
Smoke/coexist result SHA-256 values are
`b59f5eda236b617d341424c587e1705b46d055f78791df5856990243b53ef37a`
and `28465719a4f6c00ff7fbdf70132c529099b9a782db2a6ffff38fa7eac0d4e069`.
The smoke/coexist requests are
`a20ce2135d1ae965e99e9cb86f40d3e2b6482d7a93587240cbb090bab9af33df`
and `7ed0f64848e9c45b10721c5c0591c62f8402c2e32a3b8675d7eeeb6032d61608`.
The build receipt is `a93d6d96a028e081e6079cac470d4092b9bba9ffd298575ce2c209f9c154b329`;
kernel/symbols are `df5d91092afa59f6f1c54ce142c64f920fffae07d7160f74adf2c41175eb67d3`;
bootfs is `94c83f765c03e469ed0f0696304ebdda70429d98d35c944c7c48ab57dc1cd1bd`;
and ESP is `40346f0b67e28336d2705a0eb409a9f2a93a5c4f6eadcfae97726cf6c47d8544`.

## Host, model and tooling gates

At Deepwyrm `689320b...`, the full locked workspace passed, including 807
kernel tests and all ABI, syscall, source-contract, model and tooling suites;
four target-artifact cases retained their accepted environment-gated ignores.
Focused task-execution (24), scheduler (71), syscall-contract (55) and
exception-contract (14) suites passed. Workspace library/test Clippy with
warnings denied, formatting, ABI generator/schema drift and diff checks all
passed.

The E0-E3 narrow gates were also rerun explicitly at that final revision:

| Reached seam | Final focused/model/native evidence |
| --- | --- |
| E1 MADT/route model | `arch::x86_64::acpi::tests`: 16 passed, including snapshot, override, malformed-record, overlap/capacity and exact redirection lifecycle cases |
| E2A IOAPIC model | `arch::x86_64::ioapic_live::tests`: 9 passed, including capacity, selector bounds, GSI-relative register and masked readback |
| E2B vector/return seam | `arch::x86_64::idt::tests`: 7 passed; `arch::x86_64::external_interrupt::tests`: 1 passed with exact handler -> EOI -> completion order |
| E2C physical platform | `device::q35_interrupt::tests`: 13 passed; generic `device::interrupt_tests`: 17 passed |
| E3A collector | exact selector-31/test-support host model: 10 passed with full mode absent |
| E3B collector/authority | exact selector-31/test-support host model: 12 passed with `DEEPWYRM_DW1E_E3B_FULL=1` |
| freestanding native build | default target check and exact selector-31 E3B target check both passed |

The immutable selector-31 build receipt and successful UP/SMP execution bind
those host/model results to the selected native product; host-only checks are
not treated as live acceptance.

At Wyrmroot `06299cf...`, the full locked host workspace passed with 244
tests and one accepted immutable-toolchain ignore. Workspace library/test
Clippy with warnings denied and formatting passed. The exact generated-ABI
revision/tree and accepted Rust toolchain identities above were rechecked.

The root runner's full suite passed 185 tests after adding a fail-closed
pre-bind check for Linux's 107-byte `AF_UNIX` pathname payload. That prevents
an overlong task path from being misdiagnosed as a selector or VM failure.
The canonical Wyrmroot build variable is `WYRMROOT_PINNED_TARGET_DIR`; the
launcher rejects an unmarked or stale directory.

## Unsafe-boundary review

No E4 repair adds a new production `unsafe` block. The reached DW1-E
boundaries remain narrow and locally documented:

1. E2A's one-shot IOAPIC owner uses release/acquire publication around an
   immutable `UnsafeCell` slot. All IOREGSEL/IOWIN volatile 32-bit accesses
   require a checked selector, aligned permanent UC/NX mapping and the one
   IRQ-safe controller lock.
2. E2B's one-shot external-handler slot pairs an erased static reference with
   its exact dispatch trampoline. The vector-`0x30` assembly preserves the
   interrupted frame, conditionally performs `swapgs`, maintains call
   alignment and returns only after LAPIC EOI. Failed EOI enters the explicit
   `cli; hlt` fail-closed loop.
3. The target-only q35 completion hook observes the already release-published
   shared runtime and completes only the generation token returned before
   EOI. It cannot retain the interrupt frame or enter scheduler/object work
   while holding the controller lock.
4. Bootstrap's mutable ACPI scratch borrow is BSP-only before shared-runtime
   publication. Candidate mappings remain transient; only the exact validated
   controller is permanently retained.
5. Selector-only completion transports own the existing debug-exit/serial
   hardware boundary after one atomic terminal claim. COM2 data is never the
   trusted terminal certificate.

## Required-source and provenance receipt

The active implementation plan, E0 contract, architecture index, E1/E2A/E2B/
E2C/E3A/E3B status records, DW1-D validation, affected scheduler/Interrupt/
wait/VM harness code, and bootstrap/recovery architecture were read and used.
The E4 failure audit also re-read every external source named by the active
phase: Fuchsia/Zircon `interrupt_dispatcher.cc` and
`resource_dispatcher.cc` at
`6a606ff7fd9b055edee6557566fb3f112df1a812`; xv6-riscv `trap.c`, `plic.c`,
`uart.c` and `console.c` at
`35b088427ef37611c38afdeed5a52a278cae38f9`; rust-osdev `uart_16550` at
`176b07b076bdc1fe999a5e757ab53a0e24b4005c`; and linenoise at
`a473823d74b93eab2ba83480df16ed37617493f2`.

Fuchsia supplied conceptual lifetime/deactivation and authority-separation
comparisons. xv6 supplied a conceptual returning-dispatch comparison and a
negative monolithic UART/console comparison. `uart_16550`, linenoise and the
available Fuchsia driver-framework inventory did not supply an applicable
kernel mechanism because UART, stream and console policy remain Wyrmroot
work. No external source, implementation, expression, ABI, wire format or
license text was copied. All DW1-E source and documentation changes are
first-party GPL-3.0-or-later.

## Cleanup and nonclaims

After the final matrix, `OS-Project` is shut off. Its inactive
`qemu:///system` dumpxml SHA-256 is the exact baseline
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.
The task-owned GDB and frozen artifact roots named above are retained evidence.

DW1-E closes only q35 COM2 active-high edge interrupt routing through the
existing `Interrupt` object and the exact selector-31 proof. It does not claim
a console, consoled, a shell or real `wyrmsh`; physical-hardware support;
general IOAPIC routing or allocation; MSI/MSI-X; balanced IRQ steering; a
POSIX TTY/fd layer; WYR1-D completion; the final WYR1 security gate; or DW1
completion. No repository was pushed, tagged, signed or published.

## WYR1-D6 exact-current regression addendum

**Accepted:** 2026-09-04 (America/Chicago). This addendum preserves the
historical DW1-E closure above and records the later compatible regression
pair: Deepwyrm `784adb253ff4c0065b8b85e05b938f374a139e96` / Wyrmroot
`f95262f832f0efbe42cf9359462bca261a6a5b58`. The generated ABI revision/tree
and Rust revision remain those recorded above. Publication commits are
documentation-only descendants, not replacement frozen source identities.

All WYR1-D6 gates pass: selector31 and32 UP/SMP; selector30 one-vCPU smoke
and four-vCPU coexist; selector29 UP/SMP; selector28's six-run SMP campaign;
and selector27's canonical one-vCPU registry/launch run. Actual normal and
degraded selector25 products retain stub consoled, so their conditional D6
live gate is not triggered. The full product/receipt matrix and independent
raw audits are in [Wyrmroot's WYR1-D validation](../../wyrmroot/Plans/WYR1_D_VALIDATION.md).

The fresh accepted selector31 pair is
`../../artifacts/wyr1d6-20260904-a2/s31`, evidence nonce
`D600000000000111`, challenge nonces `D600000000000112` and
`D600000000000113`.

| Item | SHA-256 |
| --- | --- |
| request | `53bb5cd2afd6ce65bf4389928263b3386eb3469523ffe509160f824a8d0ca35b` |
| pair result | `0d8107b0a99708d34e2a82b659958217fb481e01f2806248ecb7e666c73a2dbf` |
| kernel and symbols | `642bcbfd9eb1a7be2367384434b9e79f5ff7feade0b37cccd32b1f357d15e36e` |
| bootfs | `85fbda805efe87a36cb8b127d620e268662352dd213647008220f9d6e2bfc284` |
| ESP | `e76d26363ac9e640d6fec6e1e2f207d663e090b48b022038ba8e95787e6d6d27` |
| UP certificate | `353327a51b51d211d3ad590831193e54d3c5712c46420f2e8c9af63bee7cbccc` |
| SMP certificate | `775ded79eab8206d6afee042c45a0eb4176a0e8e96e274b8ef0909f74946bf3e` |
| COM2 both profiles | `e4d6c1b04f9edb207cdff315e64781a967774885f7f5b246a097f886c5832bf0` |
| UP observed-send audit | `62feef09b96a6a7d34c86bc97612f425c6376e08c0dc6052554bbd4a6a421738` |
| SMP observed-send audit | `fc43a03dba94b7f5023aa5eca67e36b8bd64291a14b45c2e5e8c4217ec0fefac` |

Each profile has all 26 ordered DWE3E1 records, both readiness/generation joins,
two observed 24-byte sends, both exact responses, valid accounting and
`DWTEST1 31 0`. Full raw COM1 includes the host's exact closing CRLF; it is
retained in the raw hashes, not treated as guest certificate content.

D6's kernel deltas are comment/test-only: `31fa345` adds two local SAFETY
proofs for selector32 completion calls; `784adb2` repairs stale cfg/source
tests and adds the exact selector32 capacity assertion. Final kernel gates
pass: 1116 workspace tests (4 accepted ignores), 934 selector32 and 936 selector31
library tests, ABI drift, formatting, warnings-denied workspace Clippy and
target31/32/29 checks (13/9/25 existing target warnings respectively).

The initial a1 selector31 pair's SMP capture failed on a 28/38-byte terminal
fragment. Its evidence is preserved, not promoted. Broad host-reader review
repaired complete-frame guards, independent response/readiness and EOF
ordering, and exact libvirt12.0.0 footer handling in root `e78f087` and
`77f5ca4`. Root 222 tests pass; the fresh pair above replaces that failed attempt.
No guest runtime fix was needed during D6.

The exact scoped Daybreak review is recorded in
[`WYR1D_D6_BOUNDARY_REVIEW.md`](../../validations/WYR1D_D6_BOUNDARY_REVIEW.md).
The final leased VM audit confirmed shutdown and the same baseline XML hash
above; the lease is released and test COM2 sockets are absent. All registered
worker lanes are retired; the pre-existing unregistered
`.worktrees/deepwyrm/.tmp` is preserved and remains the sole strict-audit
exception. No push, signing, tag or external publication occurred.

WYR1-D's native byte-transport seam is now accepted and released to WYR1-E.
This does not claim real wyrmsh, an interactive shell, POSIX TTY/fds, physical
hardware, general IOAPIC/MSI, final WYR1 security closure, or all of DW1/WYR1.
