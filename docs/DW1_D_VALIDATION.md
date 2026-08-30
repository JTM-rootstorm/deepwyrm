# Deepwyrm DW1-D Validation and Closure Record

**Status:** Accepted on the exact frozen selector-30 profile pair
**Validation date:** 2026-08-30
**Deepwyrm implementation revision:** `c153ab9af4d80c3b51c0140fb4ad1f6be962bb35`
**Wyrmroot integration revision:** `6aa6cc38595dad805af07d89e78393943b835490`
**Generated ABI revision:** `dc26df4a3d701e2cdf8b495e2c87ce979969a9c4`
**Generated ABI Git tree:** `a9b067107ec38e2be44630f4dce428dab0f48de8`
**Rust revision:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
**Selector:** `device-resource-interrupt-synthetic` / test ID 30

This record closes DW1-D's DeviceResource and synthetic Interrupt scope. The
accepted implementation and product are the exact revisions above; the commit
containing this document is a documentation-only descendant and does not
replace those frozen identities.

## Reached implementation

DW1-D was implemented through the following exact Deepwyrm revisions:

| Slice | Revision | Reached behavior |
| --- | --- | --- |
| D0 | `a75050b8c87119fb1f538976f54e1c042ca4a6fd` | device-authority contract and custody model |
| D1 | `dc26df4a3d701e2cdf8b495e2c87ce979969a9c4` | canonical ABI activation and generated definitions |
| D2 | `3277a9aac876256fd7c9a0a062993bec29a9e3eb` | checked DeviceResource PIO foundation |
| D3 | `2a037f70302173774916608c8b0bb25bd5b20cd5` | exclusive synthetic Interrupt lifecycle |
| D4 | `f281b98d2e57c1be2d3b1ee65fdc9883f0c49e9e` | validated boot-device table and boot grants |
| D5 | `38c05aea151b8fcfa688617abe9caef6f2ae5856` | primordial resource-domain custody producer |
| D5 formatting | `028ece648701ab217d54174f1b332e00129dbeeb` | formatting-only syscall export follow-up |
| D6 base | `1415592e2250fb431f6565d235738cb26ac4ea3d` | selector-private structured evidence integration |
| D6 closure | `c153ab9af4d80c3b51c0140fb4ad1f6be962bb35` | final capacity, lifecycle, readiness, and terminal Stop publication fixes |

The Wyrmroot side reached its handoff contract at
`f006d4590401104cc71b9d114f82161fc1dda7de`, pinned D1 at
`7d39a67a83c71a9ce8cace3a70c40c66b0966e81`, implemented D5 custody through
`91fa8fbcaf7eb9e517716b19c201cd6cad200cb8`, and implemented the D6 actors,
product freezer, verifier, and lifecycle integration through
`acc09e54eb2a3e4f0c7e8b244d7722c78e2b09e0`. The accepted Wyrmroot revision
`6aa6cc38595dad805af07d89e78393943b835490` adds only the final formatting of
the generated-ABI lineage assertion.

The final kernel provides rights-scoped DeviceResource claims, checked scalar
PIO widths 1/2/4, structured object information, exclusive generation-bound
Interrupt creation, normal WAIT/SIGNALED integration, generation-safe
delivery and ack/rearm, typed close/finalization, parent retention, boot-grant
reclamation, and replacement generations. The selector-private trigger is
nonce/challenge/caller bound, addresses only the selected IRQ3 descriptor, and
is absent outside the selector-30 build.

## Accepted selector-30 product

The immutable candidate is rooted at:

```text
../artifacts/dw1-d/2026-08-30-d6-dw-c153ab9-wyr-6aa6cc3-c12
```

Its profile is q35 (`pc-q35-10.2`) plus OVMF, 2048 MiB, no network, no host
share, no system disk, COM1 reserved for kernel diagnostics and structured
evidence, and COM2 present only for the bounded scratch-register proof. The
smoke profile uses one vCPU and the coexistence profile uses four vCPUs.

| Item | SHA-256 or identity |
| --- | --- |
| evidence nonce | `D1D600000000000C` |
| evidence challenge | `5A5A30D6C0DEC0E9` |
| profile pair | `1a8728f3842315765a0eccf77399e1630be49011e53dd0d0d9aa8fb86f495212` |
| profile-pair result | `1994514d51d8574c57444e15f9c6e6a0d2004cd52c0a84b9c67e7f93add3df3e` |
| smoke request | `18bfd92e158bc0434a6fa93361aedadb0ff736c1c1b6b8c3015f6508ea3a889d` |
| coexistence request | `6847bfd47d60556fbf0509af81fc917159f01672cf2b2a23fa087574e52a8741` |
| build receipt | `d125a7121f53facc6ff9360de4c4f053866c32521f520558f4f6d3d1613fd22f` |
| boot-device table | `0b65678aba6f7b9241ecef0469536835ff7bad90f8348e268609a1abf0194962` |
| kernel and symbols | `8e5d85c10021be26fe3122f11af7e999c8affe497b72f30b30f23876298e1812` |
| bootfs | `0614b670e014403f8ce2f0f5a5f8a4c8e49738215437c2beb14e4a5c0009d7ea` |
| ESP | `53af733a63fa0e160f5fbce09cc376614ba1995cd5e57148f0eaa35903af13a3` |
| bootstrap | `1f4b1b1761ed78fcf59ecc3c2631b73a9c08fb773c47b9ab633155e000aea694` |
| loader | `a0da9b2f6e3a995954cdd5f26211c79b9eb425aa3c850def3af9dbe04de2d538` |
| resource-owner actor | `e18cdf70a628f9f54aaef65324987c56c7fed99141e01350f7c45f8dcd71001d` |
| synthetic-trigger actor | `cc44efe19b4e7b1ca29a3cbc3aa4f3292b86ce9b07a4e3f0c47a71efc9c6363e` |
| product provenance | `b57566fb736f06a687c351dd86948158a4c233778ba0b0c016a28cb8c9b676d2` |
| OVMF code | `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a` |
| OVMF variables template | `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc` |

The generated ABI consumer is pinned to Deepwyrm revision
`dc26df4a3d701e2cdf8b495e2c87ce979969a9c4` and tree
`a9b067107ec38e2be44630f4dce428dab0f48de8`. The accepted Rust toolchain is
`wyrmroot-1.97.1-a92dc7f7`, request `RUST-WYR0-I-B-SYSROOTS-007`, from fork
revision `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` and upstream stable 1.97.1
revision `8bab26f4f68e0e26f0bb7960be334d5b520ea452`.

## Structured live evidence

Both verified `qemu:///system` runs on the designated `OS-Project` domain
passed with a test-ID-30, detail-zero terminal. Each emitted exactly 40 ordered
`DWD6E1` records with evidence SHA-256
`3155e6487042a9fa28741137e3ce72b6e0e48e8af582098cfedd2b6ee07aac21`
and serial SHA-256
`1ed54d582a08b50131c32cfae2266c5713f4bde0ba45a0f4fadc589dab01714a`.

The relational record sequence proves:

- the accepted boot table excludes COM1 and exposes the exact COM2/IRQ3
  resource;
- an unrelated/public actor cannot claim the resource;
- the resource-domain owner claims lease generation 1;
- COM2 scratch port `0x2ff` is saved, receives challenge byte `0xe9`, reads it
  back, and is restored without UART interrupt setup or RX/TX use;
- Interrupt binding generation 1 completes five blocked-wait, synthetic
  delivery, SIGNALED wake, and ack/rearm cycles;
- a delivery/ack race retains the newer pending fact;
- Interrupt finalization precedes grant return;
- stale operations against the old lease/binding are rejected;
- replacement lease and binding generations are both 2;
- close while pending terminates the registered waiter and releases authority;
- accounting and normal bootstrap remain healthy before the terminal record.

The one-vCPU and four-vCPU evidence transcripts are byte-identical. The
four-vCPU coexistence run additionally proves the accepted SMP scheduler stays
healthy while the same ring-3 lifecycle executes. The exact inactive domain
baseline SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`
was restored after every designated-domain run.

## Active GDB evidence

The final smoke product was replayed with descriptor-bound active GDB hooks and
the opt-in `dw1d-registry` profile. The retained diagnostic root is:

```text
../.tmp/dw1d6-c12-gdb-smoke
active.gdb.log SHA-256 670fde2694ad9f2a490ac691d346e4eb4f70c0fdb8f9b59a593b9f37a151b11a
serial.log     SHA-256 7131484ef2bb2ad8d194c8b0b495be85ef250ff42cb519b1e51121dbeadaee4f
domain.xml     SHA-256 6db5228ec03170c2fec22da61aa60131cf09213e9da26cb7a72c8d06e8d9fb5b
symbols        SHA-256 8e5d85c10021be26fe3122f11af7e999c8affe497b72f30b30f23876298e1812
```

GDB observed one `DW1D_REGISTRY_CAPACITY_PROOF`, all 32 audited slots as
`SlotState::Vacant` at the proof point, six `DW1D_WAIT_BLOCKED` hooks, six
`DW1D_OBSERVE_DELIVERY` hooks, and one clean D6 evidence terminal. It did not
hit the generic failure, early panic, scheduler-current missing-resource,
complete-fail, panic, or exception hooks. This supplements the structured
guest record with debugger-visible capacity and transition evidence; it does
not replace the request-bound VM verifier.

The debugger also exposed a terminal Stop publication race during D6 closure:
resource teardown could detach a scheduler-owned thread while the exact Stop
publication still waited outside the shared runtime guard. Revision
`c153ab9...` adds a safe-point retry only while that exact terminal publication
is pending. Three lean selector-28 debugger replays and the complete
post-fix selector-28 campaign passed without the prior missing-resource trap.

## Affected selector regressions

The required post-integration regressions passed:

- selector 28 at Deepwyrm `c153ab9...` and Wyrmroot `acc09e5...`: smoke plus
  stress 1 through 5 all passed with 46 records and detail zero. Campaign
  result SHA-256 is
  `db73423a0b9cacf00308c06f8af26aebee5bc92b916e6080dea827035ab189b0`;
  evidence SHA-256 values are
  `825f47df0e74fbe0c55432eb02dfb0b18f1a57813958522abb5f531e2d3f52c5`,
  `d674a520e16a91e32718a1c45e1be73811b478de975023de125d8dcb19fea07e`,
  `50e4ed671eaaf408b46eba84cb2ca23799f99618b396aaed1662b86a4782a38f`,
  `1b1c3b361318f017f71647348fb823ce59d347a22d8cc0eb28cd21928e2bbea4`,
  `603264000a34b1103fe243109c05dc8ba4fd7c6583b1a1bf441ed660ad1aa0fc`,
  and
  `05139f14d6b7da912d362a76f24d7d736a592bcacb731e21a3c7a9295f3cc5b6`.
  Wyrmroot `6aa6cc3...` differs only by host-test formatting.
- selector 27 at the final `c153ab9...` / `6aa6cc3...` pair: PASS with 14
  ordered records and detail zero. Run-receipt SHA-256 is
  `abb95e24f6f858bf630eb138a95e2916db667866523b26229e9b7ba1b484735e`,
  bootfs SHA-256 is
  `fc67430304befa879555d650f9531cbf8f73594974b4fdc7c7528d8e66cc0391`,
  and ESP SHA-256 is
  `8f27e312e7d21914d838881732f1d71b032bd5b6c173e186e1ab3b18af49e07c`.
- selector 25 normal, default and SMP: PASS with evidence SHA-256
  `88cca5606530512514400ed1817346225979da3c5f1f39754a082c789adc9d4f`
  and paired-result SHA-256
  `b20bfb0c73f5d2f5b507331522fd0645007761a674cc0a95f169f970022652e8`.
- selector 25 degraded, default and SMP: PASS with evidence SHA-256
  `07953691957c7932a26759375971998a31b3b0d0ed73728195fbe1f789897242`
  and paired-result SHA-256
  `19b034808a7ac514a0792017b1ebeda124d6294b0f14e46fa206164566efe7f2`.
- selector 26: PASS only through its accepted tool-pinned historical path,
  Deepwyrm `0d7c928d845d3875a21e7f1d17e56b01617ff0c1`, generated ABI revision
  `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`, ABI tree
  `1c6a74f130e386eee95b3780c75950beefd0037d`, and Wyrmroot
  `17ac1815c3d060cfe2425bee7cf06966bf5f8fbf`. Its run-receipt SHA-256 is
  `ccebd476eb2cf294b7fe356a20ef74566bd7512e8018c22cd275a8f0f321749f`
  and its accepted evidence reports quantum 9, involuntary 9, switches 29,
  and wakeups 18. No selector-26 acceptance claim is made for the D kernel.

## Host, model, and tooling gates

The following final Deepwyrm gates passed at `c153ab9...`:

```text
tools/pinned-cargo fmt --all -- --check
tools/pinned-cargo host xtask check
tools/pinned-cargo host xtask abi check
tools/pinned-cargo host test --locked --workspace
tools/pinned-cargo host clippy --locked --workspace --lib --tests -- -D warnings
warnings-denied rustdoc for abi-gen, deepwyrm-abi, deepwyrm-kernel,
deepwyrm-syscall, and xtask
```

The kernel suite reported 767 passed. The workspace test gate also passed all
ABI, syscall, source-contract, compile-fail, model, and tooling suites.
Focused tests cover range arithmetic, rights reduction, widths 1/2/4, boot
table validation, COM1 protection, claim atomicity, exclusive source binding,
wait/ack races, coalescing, finalizer ordering, parent retention, stale
generation rejection, terminal publication, and selector-private transcript
validation.

At Wyrmroot `6aa6cc3...`, formatting, the full locked workspace test suite,
warnings-denied workspace Clippy, warnings-denied Rustdoc for the affected
bootstrap/bootfs/loader/runtime/D6 crates, exact generated-ABI consumer checks,
and selector-30 native builds passed. The xtask suite reported 217 passed and
one ignored. Feature-specific freeze builds emitted only their known
selector-shape unused-import warnings; the canonical warning-denied host gates
were clean.

The root request/runner/verifier and active-GDB hook suite reported 139 passed.
It checks exact request/product/media joins, immutable source and ABI lineage,
boot-resource-table identity, evidence relations, fd-bound VM media, baseline
restoration, and correct GDB profile ordering.

## Production unsafe boundary record

DW1-D added or refactored the following production `unsafe` boundaries:

1. `kernel/src/arch/x86_64/io_port.rs` is the single architecture instruction
   boundary. It contains exactly six blocks: scalar `in` and `out` for u8,
   u16, and u32. The prior COM1 byte operations were moved into this module;
   word and doubleword operations were added for DeviceResource. Every block
   executes one non-string instruction. Rights checks, checked range
   arithmetic, width validation, and effective port calculation occur in safe
   code before entry. There is no IOPL, string/REP I/O, or userspace direct-I/O
   surface.
2. `crates/deepwyrm-syscall/src/lib.rs` adds five narrow userspace wrapper
   calls to the established `syscall6` boundary: DeviceResource claim, PIO
   read, PIO write, Interrupt create, and Interrupt ack. Arguments are generated
   scalar ABI values; output addresses remain uniquely borrowed for the whole
   call. These wrappers add no kernel memory dereference authority.

The selector-private synthetic trigger reuses the established native syscall
entry frame and CPL3 transport and adds no new raw-entry `unsafe` block. The
terminal Stop publication correction is safe-Rust lock/ownership ordering and
adds no unsafe boundary. New `AddressSpaceAuthority::new()` uses in finalizer
tests and the test completion transport are test-only, not production
boundaries. DW1-D adds no interrupt-controller, MMIO, DMA, or IOMMU unsafe code.

## Required sources and provenance

The root DW1-D implementation plan, Deepwyrm and Wyrmroot architecture
indexes, reached D0/handoff/custody contracts, bootstrap/recovery architecture,
and the current in-tree object, wait, finalizer, TaskGroup, COM1, boot-info,
loader, bootstrap, and verified-VM contracts governed implementation.

The pinned Fuchsia/Zircon resource and interrupt dispatchers at revision
`6a606ff7fd9b055edee6557566fb3f112df1a812` informed conceptual comparison of
ranged ownership, exclusive source reservation, wait/ack separation, pending
delivery, and destruction ordering. xv6-riscv UART/PLIC at revision
`35b088427ef37611c38afdeed5a52a278cae38f9` informed only the small 16550
register and claim/complete ordering comparison. rust-osdev `uart_16550` 0.8.0
at revision `176b07b076bdc1fe999a5e757ab53a0e24b4005c` informed register offsets,
scratch-register test shape, and no_std typed-access comparison. Existing
Deepwyrm COM1 code governed centralization of the x86 port-I/O boundary.

All use was conceptual. No external code, ABI, object kinds, root-resource
model, dispatcher state, RISC-V controller assumptions, console state, Unix
process/fd semantics, or locking architecture was copied or adapted. The
observed source licenses were compatible with conceptual study: MIT-style for
the pinned Fuchsia and xv6 files and `MIT OR Apache-2.0` for `uart_16550`.

## Acceptance boundary and nonclaims

DW1-D proves that a real ring-3 process can claim an exact rights-scoped boot
resource, perform bounded COM2 scratch-register PIO, create/wait/ack/rearm a
generation-safe exclusive Interrupt through selector-private synthetic
delivery, close pending/waiting state safely, release all derived and parent
authority, reject stale generations, and reclaim a fresh replacement lease.
This reached authority seam unblocks WYR1-C4.

It does **not** claim:

- q35 IOAPIC or physical IRQ3 delivery into the Interrupt object;
- COM2 or any UART RX/TX behavior, UART initialization, buffering, or driver;
- selector 29 or WYR1-C live closure;
- physical-hardware behavior;
- MMIO DeviceResource, DMA, or IOMMU support;
- a final Daybreak security/soundness closure.

No production `uart16550d`, `consoled`, `wyrmsh`, PCI/ACPI discovery, hotplug,
or permanent resource broker is introduced. Those remain later milestones.

At the exact identities and evidence above, DW1-D is accepted and WYR1-C4 may
consume the reached seam.
