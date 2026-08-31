# Deepwyrm DW1-C Validation and Closure Record

**Status:** Accepted on the exact frozen selector-28 candidate
**Validation date:** 2026-08-29
**Deepwyrm implementation revision:** `c5cfa1a5126259e88be5b5670e927f627a6e1086`
**Wyrmroot product revision:** `17ac1815c3d060cfe2425bee7cf06966bf5f8fbf`
**Rust revision:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
**Selector:** `normal-preemption-smp` / test ID 28

This record closes DW1-C's normal four-vCPU scheduler scope. The accepted
implementation is the Deepwyrm revision above; this documentation commit does
not replace that frozen product identity.

## Accepted product and campaign

The immutable candidate is rooted at:

```text
../artifacts/dw1-c/2026-08-29-dw-c5cfa1a-wyr-17ac181-c35
```

Its exact identities are:

| Item | Identity |
| --- | --- |
| evidence nonce | `D1C5000000000035` |
| progress digest | `D1C5A11CE5EED035` |
| request SHA-256 | `bd9dd5eb7db0a24243b339369b02821728a2c9242b39e613321d86b67132261b` |
| campaign SHA-256 | `00a98d55459d3310ad62e1e0ed204ccd086b4aba1b74027d0747577e6fcc9057` |
| campaign-result SHA-256 | `45227935a626c5d8e00013ebdd05a45b64a9d6e3c7f53a15a22eecc41ee3b151` |
| kernel and symbols SHA-256 | `b9529ed1fd9801ef77c9fdf30aa4ea5391c76b85bdc2f32184a108bcfa37b46c` |
| bootfs SHA-256 | `a090d307f98197758c4b59a4deaecd0b651dd9c589ccc3768e74c676543ee253` |
| ESP SHA-256 | `6dc9d83aaa7d72c7b8b9b800d28ab13dd159d6fa72c5437c79f3c1f0ab20c332` |
| bootstrap SHA-256 | `8ca4a6256c897b8f730e429519f48ba237bc759fae968f2e4df5c3976abaad0c` |
| loader SHA-256 | `dd2ab479245f4b11bcd96ac6234f96abbba6f43249fa5284c6bf59b1974cdb14` |
| OVMF code SHA-256 | `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a` |
| OVMF variables template SHA-256 | `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc` |
| bootfs budget | 59 pages |
| machine | q35 + OVMF, 4 vCPUs, 2048 MiB, no network or host share |

The verified `qemu:///system` runner accepted one smoke boot followed by five
consecutive stress boots on the designated `OS-Project` domain. Every boot
emitted exactly 46 ordered `DW1C` records immediately before a checksum-valid
selector-28 `DWTEST1` PASS terminal and exited with the expected debug-exit
status.

| Pass | Evidence SHA-256 | Serial SHA-256 | Max ready delay (ns) |
| --- | --- | --- | ---: |
| smoke | `839833ba589e2e0b3e4c768178ef9a68f370aef9e3b1ba1457d9f7f61ba9cab2` | `9786a69a9042f8e7fd75e094c230518dc7d37e0feb682eb447570a355375ece0` | 25,782,048 |
| stress-1 | `186879ba79b5437f3754357fcfa82b69b7cb3b2557f67da59eb00e6a95fc8252` | `eb667820aa68483594d25d971cb24d0664fa2b1723e8d49f0459f6a9285c4adb` | 27,603,508 |
| stress-2 | `43472d950507e66d5b1e7e3d2ffb0302e60ded9cbcf96b2baf379d74cf6f0a2c` | `cccd9b329a2c33df16d79fb563fd103f01aeb06754d500bd4c6a8959858f5c58` | 25,690,137 |
| stress-3 | `08c1f7afa9459dac4d33e44a126b22db11557fb4608c0cac042543701d159a63` | `f19bb12ccd56140e85b928d2abe25179edba4da9a21fec47860ef6f38fe1df28` | 30,484,600 |
| stress-4 | `005cffded18b58cb680a3cb33c0f8ca690e870794b43446fc99d33ac9e1ac423` | `e1ce09a159e5090e3042bc881343b3c5826a7613a4dc4cf6f29b881e1f79e9a4` | 25,532,854 |
| stress-5 | `4d3b89faba5b0bf16f9df12ad0b9375ced06f63039af27605e6df5da579d5350` | `a9154ea72940e520874816817ebf78a1fa860e6f13ffce9df47275645a6d8620` | 26,260,321 |

The records prove all four CPUs scheduler-capable, ordinary execution and
involuntary preemption on every CPU, progress by more Runnable actors than
CPUs, remote wake coverage, bounded steal/migration, pinned-state migration
rejection, the race matrix, exit/reap completion, normal bootstrap, and sound
accounting. The maximum ready delay is diagnostic regression evidence, not a
production latency ABI.

## Active debugger evidence

The accepted smoke was also run with descriptor-bound active GDB hooks rather
than waiting for the outer campaign timeout. The durable diagnostic is:

```text
../artifacts/dw1-c/diagnostics/2026-08-29-c5cfa1a-17ac181-c35-smoke-active-gdb
active.gdb.log SHA-256 e8f0d562a0795f4f519db6a2d77b67380be0639aa7e054234fe65dd33141ca8d
serial.log     SHA-256 e86a7023184789e24a031607b60371100266488d46c95ffba8ed74c1e582209f
```

GDB observed `live_cpu_count = 4`, carrier-resource tuples for CPUs 0 through
3, AP admission and bootstrap normalization, and the selector-owned
`DW1C_EVIDENCE_TERMINAL`. It did not hit the carrier-admission failure, early
panic, generic failure, panic, or exception breakpoints.

This mechanism also resolved the last cross-selector regression. A selector-27
boot at pre-fix Deepwyrm revision `9fc58c5...` reached
`bind_runtime_carrier_facades` and panicked because four-CPU DW1-C policy had
leaked into the common one-CPU product path. Revision `c5cfa1a...` preserves
four facade storage slots but binds and prepares only the live registry prefix;
the exact-four assertion remains selector-28-only. The post-fix selector-27
GDB trace observed `live_cpu_count = 1`, only CPU0's resource tuple, and the
WYR1-B evidence terminal.

## Paired live regressions

The final current Deepwyrm/Wyrmroot product passed the required affected
regressions:

- selector 25 normal, default and SMP: PASS with five records, evidence
  SHA-256 `88cca5606530512514400ed1817346225979da3c5f1f39754a082c789adc9d4f`,
  paired-result SHA-256
  `94fc17a5b90b5daf93c058052b8874958e5e5fa286dafb3dd5a216c7aeceefbb`;
- selector 25 degraded recovery, default and SMP: PASS with nine records,
  evidence SHA-256
  `07953691957c7932a26759375971998a31b3b0d0ed73728195fbe1f789897242`,
  paired-result SHA-256
  `7bc62b57c7ead41fbed95b2f6241cbb0eacb1bd2e0dd88f05a5ffc750b0e99bf`;
- selector 27 one-vCPU current-product regression: PASS with 14 ordered WRB1
  records and a selector-27 terminal. The request SHA-256 is
  `ee451f3123973f75fec8d07948cf921a73a4ceb8627437f13a5615be55f1d783`,
  bootfs SHA-256 is
  `163cc676cdd6ea43a4c53933d066745742805d79b0c73a4ffc7607bcb3ff50b3`,
  ESP SHA-256 is
  `27b94e8bade3b9915c7f0b891423d0e06c505befd9ba9feaeab46808fa3b2909`,
  and the active-GDB/serial SHA-256 values are
  `c9cd6037dc6e10768843aa820e4ff2dd86968906daf462a266966651e6cf3414`
  and `a870b0d5b1de2145719c626ce2334c27b756691291cd20ebd80d60b5fd2700c8`;
- selector 26 one-vCPU regression: PASS against its tool-pinned historical
  Deepwyrm `0d7c928d845d3875a21e7f1d17e56b01617ff0c1` and the current Wyrmroot
  `17ac181...`. Its request SHA-256 is
  `af77c0b1baa4b2220e98f009bc2ae0c362dd0a384f74541d8cb74180519f9b3d`;
  GDB observed the DW1-B evidence terminal, and the serial ended in a
  selector-26 PASS terminal.

The selector-25 paired results are the canonical verified designated-VM
regression authority. The selector-26 tool intentionally pins its accepted
historical Deepwyrm implementation; rebuilding it with the selector-28 kernel
would not be the DW1-B regression contract. The selector-27 run is affected
current-product regression evidence, not a replacement for WYR1-B's separately
accepted original tuple.

## Host and tooling gates

The following final gates passed at Deepwyrm `c5cfa1a...`:

```text
cargo fmt --all -- --check
cargo xtask check
cargo xtask abi check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

The kernel library/model suite reported 719 passed. The x86 syscall/source
contract suite reported 53 passed. The exact selector-28 freestanding release
build and the canonical selector-25/26/27/28 linked-artifact and accepted-stack
gate passed; selector-28 remained within its measured stack budgets.

The exact Wyrmroot revision passed formatting, the full locked workspace
all-target suite, warnings-denied Clippy, warnings-denied Rustdoc, and seven
DW1-C feature-specific init0 library tests. The root runner/verifier suite
reported 117 passed. The feature-specific init0 warnings are expected from the
selector-only build shape; the ordinary workspace Clippy gate is warning-free.

Every designated-domain run ended with `OS-Project` shut off and restored the
exact inactive definition SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.

## 2026-08-31 exact-current WYR1-C regression

WYR1-C6 subsequently exercised selector 28 against current Deepwyrm
`6ba05d6706a0f376c0af0b4ce86305af01748cce` and Wyrmroot
`b872e3bd465e3f6d9c9e90adbceb3756dc490dc2`. This is a post-acceptance
current-product regression; it does not replace DW1-C's original frozen
candidate above.

The first stronger terminal-root synchronization candidate failed selector 28
at `primordial.rs:1185`. Active GDB was attached before any retry or source
change. It showed a valid exact-root no-op after the remote stop completed,
with another CPU still inside `complete_remote_stop`; the helper had mistaken
that valid state for a lost terminal-root claim. The exact GDB trace SHA-256 is
`113a41b65e2c007564cd2b917b9c65588e7b00429cf05fab65ce706f5a0cdcae`
and its exact symbols SHA-256 is
`d9ecb019a3bf3d23e56b8e729fd1b6dcbe3823311e8c545a75291deb4e76223f`.

Revision `6ba05d67...` accepts only that exact-root no-op while retaining the
physical terminal-owner invariant. Its fresh selector-28 request SHA-256 is
`f9f021ab8deab107e60272314ce9c250ca3bb479301c0f75ee190645ed132619`,
with progress digest `D1C6A11CE5EED041`. The verified designated-VM
campaign then passed one smoke and five consecutive stress boots, each with
exactly 46 ordered records and a selector-28 PASS terminal. The campaign-result
SHA-256 is
`b78b8e06d4738e4058597a56768dd5e9471ba7c70a809beab14dcea1b610c7b1`.

The same Deepwyrm revision then passed WYR1-C selector 29 on both one-vCPU and
four-vCPU profiles. That separate device-coordinator acceptance is recorded in
`wyrmroot/Plans/WYR1_C_VALIDATION.md`; it does not broaden DW1-C into device or
physical-I/O ownership.

## Required sources and provenance

The root DW1-C/WYR1-C plan, Deepwyrm architecture index, reached DW1-A0
contract, DW1-C0 design, bootstrap/recovery architecture, and the CPU-private
root, scratch, stack, timer, idle-wake, terminal, and reaper contracts governed
the implementation and closure. The active phase's xv6 scheduling sources at
revision `35b088427ef37611c38afdeed5a52a278cae38f9` and Fuchsia scheduler source
at revision `6a606ff7fd9b055edee6557566fb3f112df1a812` were re-read during the wide
liveness investigation. They informed the explicit carrier-detach comparison;
no external code, ABI, lock discipline, scheduler class, or policy was copied.

The interrupted candidate-34 freeze left only partial one-shot output and was
excluded from evidence. Candidate 35 used a fresh output root, nonce, digest,
request, and six-pass campaign.

## Acceptance boundary

DW1-C proves the ordinary normal scheduler on exactly four q35 vCPUs for the
bounded selector-28 workload and preserves the named prior selectors. It does
not claim a public CPU-affinity or scheduler-policy ABI, real-time scheduling,
NUMA or long-term fairness, production latency bounds, CPU hotplug/offlining,
physical hardware, DeviceResource, Interrupt, COM2, WYR1-C device coordination,
or later DW1/WYR1 milestone closure. No Daybreak security gate is claimed by
this functional closure.

At the exact identities and evidence above, DW1-C is accepted.
