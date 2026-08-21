# DW0-F9 Functional Validation

## Status

DW0-F9 is functionally closed for native `atomic_wait32` / `atomic_wake` on the
dirty Deepwyrm working-tree candidate based on
`7c74fbd8411ffa487a4db4e695a0b536a0d5edfd`.

The accepted selector-16 kernel has SHA-256
`5e2c9d31f6b611c4874ab897ad027556f5637a61d3cc0d14181d06061324b79d`.
The required q35/UEFI gate executed its real two-Thread CPL3 path and emitted
the canonical PASS record for test ID 16.

Wyrmroot remained source-unchanged by F9 at
`180ad0480db925a92222bccf9e2102a27b351370`. Its working tree already contained
the coordinator-owned toolchain/provenance-pin updates in
`toolchain/versions.toml` and
`toolchain/templates/build-provenance.toml`; the VM request recorded Wyrmroot
as dirty rather than representing those edits as a clean revision.

This record closes only the F9 mechanism and its focused target gate. It does
not claim F10 public `process_create`, F11 consolidated IPC host tooling, the
full F12 multi-service userspace/paired-VM scenario, F13 cumulative Daybreak
security acceptance, SMP acceptance, i386 compatibility, or physical-hardware
acceptance.

## Implemented F9 boundary

F9 builds on the existing MemoryObject, AddressRegion, scheduler, deadline,
blocked-operation, and native syscall-frame authorities. It does not create a
parallel scheduler or userspace address model.

Implemented behavior includes:

- stable wait identity derived from the current live Process root mapping as
  `(MemoryObject generation, object byte offset)`, never a raw virtual address;
- complete four-byte, non-null, aligned, lower-canonical, readable userspace
  validation before key derivation;
- an owned live mapping pin retained through suspension, wake, timeout, or
  terminal cleanup, preventing intersecting mapping mutation and backing ABA;
- acquire-ordered atomic `u32` loads through the pinned word;
- initial predicate comparison before timeout classification, so mismatch
  returns `WOULD_BLOCK` even when a finite deadline has already expired;
- waiter registration and predicate reread under the same IRQ-safe registry
  barrier used by wake selection, closing the compare-to-sleep lost-wakeup
  interval;
- a bounded generation-protected FIFO wait registry keyed by stable backing
  identity;
- exact bounded wake counts and `DW_ATOMIC_WAKE_ALL` in registration order;
- shared `BlockedOperationRegistry` arbitration between atomic wake, timeout,
  cancellation, and terminal teardown, with one winner per scheduler block
  generation;
- output preflight for `out_woken` before any wake mutation, including when
  count is zero;
- exact release of wait registration, deadline registration, scheduler block,
  and mapping pin on immediate mismatch, immediate timeout, wake resume, and
  process/thread termination; and
- typed native decode/dispatch through the existing F ABI without changing
  syscall numbers, record layouts, object types, signals, or rights.

The target-only selector bridge is deliberately limited to F9. It does not
activate Channel, Event, Timer, or public `process_create` services ahead of
F12.

## Focused model and contract evidence

The focused atomic-wait filter passed 12 tests. Coverage includes:

- FIFO bounded wake and `DW_ATOMIC_WAKE_ALL` across multiple waiters;
- initial mismatch before `NOW` and before an already-expired finite deadline;
- mismatch on the under-barrier reread without registration or scheduling;
- equal predicate with an expired finite deadline;
- timeout-first and wake-first exact-winner interleavings;
- zero-count wake preserving a live registration;
- source-locked adapter ordering proving zero count cannot bypass address, key,
  or output validation;
- terminal operation cleanup returning the pin, registration, and deadline
  exactly once;
- two distinct virtual mappings of the same MemoryObject generation and byte
  offset resolving to the same key;
- unrelated MemoryObjects, stale object generations, and different offsets
  resolving to different keys; and
- a complete four-byte word being required within one readable mapping, with
  crossing and overflow failures rejected.

The existing user-range tests exercised null/page-zero, alignment, overflow,
canonical-hole, kernel-half, access-intent, and page-walk validation used by
the F9 live pin. The new detached-pin test proved that an intersecting mapping
mutation is rejected until the atomic-word pin is released. Native syscall
routing and scalar-width tests continued to pass for the generated F requests.

## Broad host closure

Project-local build state under `target/f9-host-system` passed:

```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo test --locked --workspace --all-targets --offline
cargo clippy --locked --workspace --all-targets --offline -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --offline
git diff --check
```

The final kernel unit suite reported `415 passed; 0 failed`. The final syscall
contract suite reported `16 passed; 0 failed`. Workspace testing also passed
the compile-fail/UI authority contracts, architecture contracts, ABI
generator/layout tests, and xtask command-surface tests.

## Accepted target artifact evidence

The selector `atomic-wait-wake` is build-owned ID 16. Its accepted-toolchain
artifact oracle passed freestanding, production-separation, symbol, ELF
program-header, no-interpreter, no-W+X, and generated-syscall-veneer checks.
It also verified that the selector's `_start` does not issue `SYSCALL`
directly.

Recorded artifact identities:

- F9 user ELF SHA-256:
  `0e29b37079cfabf931c0b9762d16d075280db8a8812fee6b2d67d47b1c65deda`;
- selector-16 kernel ELF SHA-256:
  `5e2c9d31f6b611c4874ab897ad027556f5637a61d3cc0d14181d06061324b79d`;
- Rust toolchain identity SHA-256:
  `2cd16c0690e243b2d68add2fcbb23f78d4a91e324948e04f19b8209267ecdb93`;
- build-tools identity SHA-256:
  `e4e6beea9b1a7b9bf803bc5badb0517bf8e18db76ef4dedf81d1645d330593fd`;
  and
- kernel layout SHA-256:
  `aaebb83203efaaae5b495e59484f9e0003bae6a30067ee63f02c9ea48db54e5d`.

The artifact oracle is build and inspection evidence only. It did not execute
CPL3 and was not used as a substitute for the following VM gate.

## Required two-Thread CPL3 gate

The main/root coordinator alone operated the designated `OS-Project` domain
on `qemu:///system` under the workspace VM policy. The canonical run used the
q35 profile with one vCPU, 1024 MiB, a 120-second bound, no network, no host
share, selector `atomic-wait-wake`, and test ID 16.

The selector created one Process and two Threads sharing one data mapping. The
waiter entered CPL3 and called `atomic_wait32` on value zero with an infinite
deadline. The syscall suspended that Thread and scheduled the fresh sibling.
The waker entered CPL3, stored one, called `atomic_wake` with count one,
observed `out_woken == 1`, and then blocked in its own `atomic_wait32`. The
original waiter resumed from its syscall with `SUCCESS` and exited the
Process. Terminal cleanup required the sibling, scheduler resources, atomic
operation registry, blocked-operation ledger, and cleanup queue to be in their
expected final states before PASS. Neither successful userspace path contains
a predicate spin loop.

Canonical serial terminal record:

```text
DWTEST1|01|00000010|00000000|174A99BB
```

The lifecycle record showed `Resumed`, `Started`, `Shutdown Finished after
guest request`, then `Stopped Shutdown`. The existing xtask result classifier
accepted selector `atomic-wait-wake`, test ID 16, detail zero, serial line 7,
and the contractually expected debug-exit process status 33.

Libvirt does not expose the underlying QEMU child process status for this
domain lifecycle. Therefore status 33 was supplied to the classifier from the
fixed debug-exit contract and corroborated by the matching PASS serial record
and debug-exit-triggered guest-request shutdown; it was not independently read
from a QEMU process wait status. This qualification is retained explicitly and
does not convert the artifact-only gate into runtime evidence: the serial and
lifecycle were captured from the real selector execution.

Recorded VM evidence:

- harness request SHA-256:
  `93f90e594b21f1bd040b39050626b537f58babed7ee0456a281e05e8071fad2c`;
- ESP SHA-256:
  `8ebd036bb6e6975e44ec535d3fe32839800b00648bae3e7f797c3fd9b88f362a`;
- system disk SHA-256:
  `8cf73f8d367b56e81afc7e25dba3226168f8f05790ccf7e846de51e931478133`;
- canonical serial SHA-256:
  `ffaf2a72045b6222088f12bd6140b70ad6bb51f927eef67cf4ca3af3a56ddf42`;
- classified result SHA-256:
  `59b68fc8ca6a4de75909edcd6228e12df875f63974a4615e6f2404005ceb1f9b`;
  and
- lifecycle record SHA-256:
  `db9a203f376708709a7cbb31b9ea9a23a8577d6beb75da7b20552be8f87ccdb4`.

Evidence is retained under
`/home/mike/Documents/Programming/OS-Project/.artifacts/f9-validation/vm-run`.
Post-run hashing confirmed the ESP, system disk, and kernel remained
byte-identical. The original and restored persistent domain XML both hash to
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.
The final domain state was shut off; the original 2 GiB configuration and
primary disk were restored. The baseline XML retained its configured NVRAM
path `/var/lib/libvirt/qemu/nvram/OS-Project_VARS.qcow2`, whose backing file
remained absent before and after the gate.

The first launch was an infrastructure-only capture miss: the fast guest had
already stopped before the one-shot serial client connected. It supplied no
acceptance result. Canonical run 2 used retrying serial capture and is the sole
runtime result cited above.

## Explicit non-claims and next work

F9 does not activate the complete F native service set in production. The
narrow selector runtime exists only to prove F9's required live mechanism;
F12 remains responsible for the consolidated F userspace runtime and paired
scenario.

F9 does not implement public `process_create` (F10), add the consolidated IPC
host command (F11), close the full F12 Channel/Event/Timer/transfer/process
scenario, or establish cumulative F security acceptance (F13). No Daybreak
scan was run at this ordinary implementation checkpoint; the dedicated
end-of-sprint security gate remains authoritative.

## Disposition

The dirty Deepwyrm candidate based on
`7c74fbd8411ffa487a4db4e695a0b536a0d5edfd`, with selector-16 kernel SHA-256
`5e2c9d31f6b611c4874ab897ad027556f5637a61d3cc0d14181d06061324b79d`,
satisfies the DW0-F9 functional gate. F10 may proceed without reopening F9
absent a regression or later security finding.
