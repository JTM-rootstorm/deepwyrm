# DW0-F12 Freestanding CPL3 and Paired-VM Validation

## Status

DW0-F12 is functionally closed on Deepwyrm implementation revision
`6de5af17dfef979aeadc150ce3958cd941fedbb2`, paired with Wyrmroot revision
`b6ed32f104bb4579dbeaa815ab7bd0e0a7c18311`.

The accepted selector-13 kernel and user ELF passed the production/selector
artifact oracle, and the designated `OS-Project` system-libvirt domain executed
the complete two-Thread CPL3 scenario through the real Wyrmroot-to-Deepwyrm
boot path. The canonical runtime record reports test ID 13, detail zero, and a
valid terminal checksum.

This record closes root `DW0_F_IMPLEMENTATION_PLAN.md` section 17. It does not
establish the cumulative DW0-F13 Daybreak security disposition, SMP or i386
acceptance, a general userspace ELF loader, physical-hardware acceptance, or
release closure.

## Implemented selector and service boundary

Selector `ipc-blocking-smoke` is build-owned test ID 13. Reserved F selector
IDs 14, 15, and 17 remain unavailable; selector `atomic-wait-wake` remains the
independently implemented F9 test ID 16.

The selector-13 user artifact is a static, no-libc ELF64 image. Its assembly
uses the generated `dw_syscall6` veneer as the sole `SYSCALL` owner. Build-time
derivation reads the generated Deepwyrm ABI source for every syscall number,
status, right, signal, record size, and record offset used by the scenario and
fails closed on drift.

The target-only `FServiceState` composes the existing public F adapters rather
than copying their transactions into the test runtime. It routes:

- Channel create, send, and receive;
- Event create and signal;
- wait-one and wait-many suspend/resume;
- clock and Timer create/set/cancel services;
- atomic wait and wake; and
- public `process_create`.

E/basic inspection, termination, and scenario control remain typed
fallthrough operations owned by the runtime. Generic waits, atomic waiter and
operation registries, and native wait-control state have an authoritative
combined quiescence observation that must be clear before PASS. Typed payload
cleanup is returned to the runtime and routed through the central
`PayloadFinalizer`; no test-only parallel object lifetime was introduced.

## Mandatory CPL3 scenario

The accepted guest executes two userspace Threads in one synthetic Process.
The service Thread and producer Thread perform this ordered flow:

1. create a main Channel pair, a bootstrap Channel pair, an Event, and a
   reduced `SIGNAL` duplicate;
2. obtain the monotonic clock and construct a finite absolute deadline;
3. block the service Thread in `wait_one` for main-Channel readability;
4. run the fresh producer, which sends one byte-only datagram followed by a
   second datagram carrying an Event handle with reduced rights;
5. resume the service Thread, receive both messages in FIFO order, and verify
   the received Event has `WAIT` only and a receiver-local raw handle value;
6. block the producer in `atomic_wait32`, wake it exactly once with
   `atomic_wake`, and resume it through the real scheduler/continuation path;
7. block the service Thread on the received Event with the finite absolute
   deadline, signal it from the producer, and cancel the exact deadline during
   successful resume;
8. call public `process_create`, move the bootstrap endpoint into a CREATED
   child, inspect the returned Process/root-region/bootstrap metadata, prove
   the parent source handle is stale, and terminate the child without starting
   a Thread or loading an ELF; and
9. exit the main Process while the sibling owns a blocked atomic operation,
   then terminal-clean every wait, pin, scheduler resource, mapping, typed
   payload, HandleTable, stack, context, and task record before PASS.

The controlling F0/root F12 contract requires Event **or** Timer readiness with
an absolute deadline. This selector exercises the Event branch and does not
claim a target Timer syscall. The Timer service remains host-composed and
tested. This record supersedes older F8/F9/F10 forward-looking wording that
described the eventual F12 scenario as exercising both Event and Timer.

## Terminal execution-resource remediation

F12 integration exposed a current-stack retirement defect: terminal adapters
could reclaim the physically executing Thread's kernel stack and context, then
return through Rust frames still resident on that released stack. The same
ordering could release dependent Thread and Process pins before the E3
resources were actually reclaimed.

Commit `22d1cab175cef822879639c3c8db42e767342c4c` corrected the generic
`TerminateCurrent` boundary:

- the physical current Thread is snapshotted before scheduler retirement;
- non-current siblings are reclaimed immediately;
- a non-Copy, must-drain deferred-current owner retains the current stack,
  context, continuation, Thread pin, and Process pin;
- process exit, thread exit, self thread termination, current-process
  termination, and caller-containing TaskGroup termination all select the
  deferred path only for the exact effects batch containing the caller;
- a divergent assembly handoff resets `RSP` onto a dedicated guarded terminal
  reaper stack before reborrowing the runtime; and
- only the reaper-side callback consumes the deferred owner, reclaims the old
  E3 resources, releases the retained pins, and continues terminal
  finalization. It cannot return to the retired stack.

The dedicated BSP reaper has an independently mapped guard and 128-KiB
payload. Its ownership is included in inactive-root construction, active-root
validation, layout contracts, and target artifact stack evidence. This is a
correct uniprocessor boundary; a future SMP implementation requires a
per-CPU reaper carrier and deferred-current owner.

### Targeted Daybreak disposition

The current-stack defect was substantive security/soundness remediation, so
its design, implementation, and exact-diff re-review ran in a dedicated lane
using model `gpt-daybreak-blue-latest` with `xhigh` reasoning on 2026-08-21.
The lane began from revision
`c86f7afc39e42eacd22ec9a9c477e14e93c8f40c`; the scoped remediation diff had
SHA-256 `f2c01501cfe4958065d618271ba106c13926be90734f838dd9bd748cac82cc1e`.

The targeted Daybreak re-review disposition was PASS for the deferred-current
ownership, reaper-stack handoff, pin-release ordering, affected terminal
adapters, guard/layout integration, and regression coverage. This disposition
is deliberately narrow. It is not the cumulative F13 threat-model, scanner,
or security-acceptance gate and must not be cited as broad DW0-F security
closure.

## Accepted artifact and stack evidence

The final accepted-toolchain oracle ran at exact Deepwyrm revision
`6de5af17dfef979aeadc150ce3958cd941fedbb2` and passed in 46.45 seconds. It
independently built production, selector 13, and selector 16. It verified:

- production contains no F test runtime, debug-exit, selector identity, or
  synthetic user blob;
- each implemented F selector rejects the other selector's runtime/blob
  markers and has a kernel hash distinct from production and its peer;
- both user ELFs are static `ET_EXEC`, have no `PT_INTERP`, no W+X segment, and
  contain exactly one `SYSCALL` owned by the generated veneer;
- all F guest assembly and linker inputs participate in the build-input
  manifest;
- environment and accepted-tool identities are normalized and recorded; and
- fresh-entry, syscall, IRQ-preemption, suspend/resume, terminal-reaper, IST,
  user-stack, and saved-context carriers remain within their linked bounds.

Recorded hashes:

- production kernel SHA-256:
  `acde7976e22160de69f63ca2418b671fd82f009870c76fcae4d2d2d48901e155`;
- selector-13 kernel SHA-256:
  `e90def460adfe958932ed8317f7bc4acd962463439af813e2404bbee31e04ab3`;
- selector-13 user ELF SHA-256:
  `60c32bd4b3b2d04baccd07a4d7f654fcdf6a29a8ad145bffd349f375b16d1b3f`;
- selector-16 kernel SHA-256:
  `a8529c8f39d2162ceb9efaa20928ce8148840fc00a26f84c099fed17aa3c29a9`;
- selector-16 user ELF SHA-256:
  `0e29b37079cfabf931c0b9762d16d075280db8a8812fee6b2d67d47b1c65deda`;
- F12 build-input manifest SHA-256:
  `f9603fa51fe9bf4aa7e7d206d32f784fc742ed8b0ffaa6042b1dad0001f8beff`;
  and
- normalized build-environment SHA-256:
  `de9cf952e07da0d8d913e9a6635d711e613e51104435a9b3082f196916e96c8e`.

The accepted Rust toolchain is the pinned `8bab26f4` Wyrmroot 1.97.1 artifact;
guest assembly used Clang/LLVM 22 and the accepted `rust-lld`. No host or guest
package was installed for this gate.

Exact carrier maxima were:

- F12 setup: 152,048 of 262,144 bytes, 110,096 spare;
- F12 E3 syscall plus nested timer IRQ: 119,208 of 262,144 bytes, 142,936
  spare; fresh entry used 21,336 bytes;
- F12 terminal reaper: 96,584 of 131,072 bytes, 34,488 spare;
- F12 selector IST: 13,673 bytes spare;
- F12 user stacks: 24 of 2,048 bytes per role;
- F9 setup: 92,160 of 262,144 bytes, 169,984 spare;
- F9 E3 syscall: 31,768 of 262,144 bytes, 230,376 spare; fresh entry used
  21,336 bytes;
- F9 terminal reaper: 24,072 of 131,072 bytes, 107,000 spare; and
- F9 user stacks: 24 of 2,048 bytes per role.

The functional-first resolution raised the retained boot and E3 Thread stack
payloads to 256 KiB after exact accepted-artifact paths proved smaller carriers
could not retain the required 32-KiB spare under setup and IRQ nesting. The
128-KiB reaper remains independently sufficient. Approximately 42 KiB of
target debug dispatcher/setup frame use is recorded as optimization debt; it
may be reduced after functional closure, but it is not hidden by an unproven
margin or a relaxed safety boundary.

## Broad host and target-build closure

All mutable test/build state was redirected into project-local `.tmp/` or
`.artifacts/` paths. The following final gates passed:

```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo xtask test host ipc
cargo test --offline --locked --workspace --all-targets
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --offline --locked --workspace --no-deps
git diff --check
```

The final kernel library suite reported `449 passed; 0 failed`. The workspace
gate passed ABI generation/layout, xtask, compile-fail ownership, architecture,
syscall, artifact, and command-surface tests. Clippy and rustdoc passed with
warnings denied. The accepted target toolchain also built F12, F9, and the E7
regression selector successfully.

`cargo xtask abi check` confirmed that F12 introduced no schema, syscall ID,
record-layout, object-type, signal, or rights change. Wyrmroot was nevertheless
rebuilt and paired at an exact revision because the consumed kernel/boot stack
layout changed.

## Canonical paired VM gate

The main/root coordinator alone operated the designated `OS-Project` domain
on `qemu:///system` under the workspace lease and restoration policy. The
canonical media bound:

- Deepwyrm revision:
  `6de5af17dfef979aeadc150ce3958cd941fedbb2`;
- Wyrmroot revision:
  `b6ed32f104bb4579dbeaa815ab7bd0e0a7c18311`;
- loader SHA-256:
  `4afac804d519fcbd9e41db25614e3d274b83e5815494d466a791b33d276191dc`;
- loader provenance SHA-256:
  `1e39ea62a082d1097465a1697aaa56bf608712c7a8df570a29bc1fae13691d8f`;
- ESP SHA-256:
  `ab38dbb6aa56d973bad8bc2e024465a043ac0bd30fbe397f1de400fdc30f8377`;
- F12 kernel SHA-256:
  `e90def460adfe958932ed8317f7bc4acd962463439af813e2404bbee31e04ab3`;
  and
- F12 user ELF SHA-256:
  `60c32bd4b3b2d04baccd07a4d7f654fcdf6a29a8ad145bffd349f375b16d1b3f`.

The canonical run-2 terminal record was:

```text
DWTEST1|01|0000000D|00000000|1AD68686
```

The lifecycle was `Resumed`, `Started`, `Shutdown Finished after guest
request`, then `Stopped`. The result classifier accepted the single PASS
record for selector 13, test ID 13, detail zero, and the contractually expected
debug-exit process status 33.

Libvirt does not expose the underlying QEMU child-process status for this
domain lifecycle. Status 33 was therefore supplied from the fixed debug-exit
contract and corroborated by the matching single PASS record and
guest-request-triggered shutdown; it was not independently read from a QEMU
wait status.

Canonical evidence hashes:

- classified result SHA-256:
  `c3929434f5eb27a098e1350b47a2a2dceed6bdd1808ed7a19b46c40ec4aa4fd5`;
- serial SHA-256:
  `e78a1b9d5a8f4148d762327bbf88997b519399c874b085c3f0423737e37a0a78`;
- lifecycle SHA-256:
  `db9a203f376708709a7cbb31b9ea9a23a8577d6beb75da7b20552be8f87ccdb4`;
- harness request SHA-256:
  `0bfb6d4bcb65712f14ad5ef6bccb23b6ae29f20561fd5dc4a074f053e2f84650`;
- effective run-2 XML SHA-256:
  `03bec2d421374ff112e8a7d200bbc07331abe604313f86f9ac86064a10ec8de7`;
  and
- byte-identical preflight/restored XML SHA-256:
  `a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`;
- final `dominfo` SHA-256:
  `faf945fd52dfa9e65ad5491110f9689620b32d13ee8f8f077155a28929445a49`;
  and
- final block-device listing SHA-256:
  `d3bf526d3c10d6b3e30ff7f996714384e2820be46e42a3967a3dcf717695c444`.

The coordinator's consolidated retained record is
`/home/mike/Documents/Programming/OS-Project/.artifacts/f12-validation/vm-run/results/coordinator-summary.txt`,
with SHA-256
`c093914b54e9308316f9842d30f11cc300feb0c8da6b6081d0b326fc9cd63b57`.

Run 1 was infrastructure-only. Direct-file serial capture succeeded, but the
result became unreadable after creation with mode `0600` and owner `nobody`;
it supplied no acceptance result. The coordinator restored the domain XML
byte-for-byte before run 2. Canonical run 2 used loopback COM1 capture and
fresh request-local copies.

The final lease audit passed: the domain was shut off; its UUID matched the
designated domain; autostart remained disabled; no managed-save image existed;
and the original primary configuration and disk attachment were restored. The
baseline XML retained its configured external NVRAM path
`/var/lib/libvirt/qemu/nvram/OS-Project_VARS.qcow2`, and that backing file
remained absent before and after the gate.

## Implementation commits

F12 was implemented in these reviewed, unsigned, trailer-verified commits:

- `9dcec1a7c755f182aec1182a3580980522307b02` — add the selector-13 guest,
  generated-ABI assembly inputs, and build identity;
- `cc91a7000818c29bc6dc3d44b88a7521b440c43e` — correct the F12
  source-generation lint;
- `13ad94a09afe89d8b935d70efa545b60b02addad` — compose the public F syscall
  services and host lifecycle tests;
- `c86f7afc39e42eacd22ec9a9c477e14e93c8f40c` — add the complete synthetic
  CPL3 runtime and source contract;
- `22d1cab175cef822879639c3c8db42e767342c4c` — defer current execution
  retirement and add the guarded terminal-reaper handoff;
- `c4f934e3b9127b9c68dea1ac89ddc1d9bb1b3cea` — close the accepted F artifact,
  stack, context, and selector-separation oracle; and
- `6de5af17dfef979aeadc150ce3958cd941fedbb2` — satisfy the final
  warning-denied artifact lint without changing resolution semantics.

All commits retain the configured repository author and required Codex
co-author trailer. None was signed or pushed.

## Explicit non-claims and disposition

The CREATED child in this scenario is inspected and terminated without an ELF
load or Thread start, as permitted by F12; general process bootstrap remains a
later phase. The fixed three-object MemoryObject fixture proves typed-memory
cleanup by invalidating all three authority-issued keys and observing zero
active leases, rather than adding a broad production count API solely for the
test. Full generic ObjectRegistry capacity is also recovered.

The selector runtime and debug-exit path remain test-support-only. Production
is independently proven free of their symbols and bytes. No Wyrmroot or Rust
fork source was edited by the Deepwyrm F12 lane, no VM was operated by a
Deepwyrm agent, and no package or toolchain was installed.

The exact Deepwyrm/Wyrmroot revision pair and canonical run-2 evidence above
satisfy the DW0-F12 freestanding-artifact and paired-VM gate. DW0-F13 may
perform its cumulative exact-candidate Daybreak security review without
reopening F12 absent a regression or new soundness finding.
