# DW0-F5 Functional Validation

## Status

DW0-F5 is functionally closed for its host-testable Channel scope on the current
uncommitted Deepwyrm working-tree candidate based on
`3deef9584b6d8056780044708828c158348bfb5d`.

This record does not claim DW0-F phase completion, a VM/guest gate, a security
review, or a committed revision. DW0-F6 handle transfer remains deliberately
unimplemented. Wyrmroot was read-only during this work and remained at
`180ad0480db925a92222bccf9e2102a27b351370`.

## F5 boundary implemented

The F5 candidate provides:

- atomic reservation and publication of both Channel handles;
- typed, generation-protected Channel pair/side lifetime tied to
  `ObjectRegistry` payload finalization;
- bounded FIFO byte datagrams with zero-byte support and a generated 64 KiB
  maximum payload;
- a bounded generation-protected static payload pool;
- derived `READABLE`, `WRITABLE`, and `PEER_CLOSED` signal state;
- byte-only `channel_create`, `channel_send`, and `channel_receive` syscall
  adapters with nonzero `transfer_count` rejected as `NOT_SUPPORTED`;
- non-consuming `BUFFER_TOO_SMALL` sizing behavior;
- a move-only receive-head reservation that keeps the selected FIFO head stable
  across exact output preflight and sizing publication;
- endpoint operation-pin lifetime through successful or sizing-result user
  publication, preventing a racing close from finalizing the payload mid-call;
- peer-close behavior that preserves datagrams already committed to the
  surviving endpoint;
- Channel integration with the F4 generic wait registry and deferred
  `WakeBatch` ownership; and
- central `PayloadFinalizer` routing for Channel endpoint finalization.

Capability-transfer descriptors, source-handle move transactions, queued
capability ownership, receiver handle reservation/publication, rights reduction,
and transfer self-reference checks remain F6 work.

## Focused F5 evidence

With build state isolated under `.artifacts/f5-validation/host-target`:

```text
cargo test --locked -p deepwyrm-kernel --offline ipc::tests -- --nocapture
```

passed 11 IPC tests covering ordered zero/nonzero datagrams, descriptor
backpressure and `WRITABLE`, non-consuming `BUFFER_TOO_SMALL`, maximum and
oversized payload boundaries, peer-close preservation, both empty-queue close
orders, stale pair generations, receive reservation contention/cancellation,
readiness waiter wakeup, and concurrent send/receive/close FIFO behavior.

```text
cargo test --locked -p deepwyrm-kernel --offline channel_ -- --nocapture
```

passed 4 Channel adapter/finalizer tests, including atomic pair creation,
byte send/receive and sizing transactionality, exact head-length output
preflight, peer-close send behavior, and central `PayloadFinalizer` routing.

The receive adapter regression deliberately supplies a caller capacity larger
than the mapped fake output tail while the queued head itself still fits. The
call succeeds, proving F5 pins the exact selected payload length rather than the
entire caller-declared capacity.

## Broad closure evidence

The final source state passed:

```text
cargo test --locked --workspace --all-targets --offline
cargo clippy --locked --workspace --all-targets --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --offline
cargo xtask abi check
cargo fmt --all -- --check
git diff --check
```

The kernel unit suite reported 344 passing tests. Workspace all-target testing
also passed the ABI generator, generated ABI contract tests, compile-fail/UI
contracts, architecture contract suites, and xtask command-surface tests; the two
accepted-toolchain target-artifact tests remained explicitly ignored by their
existing gate policy.

Clippy and rustdoc completed with warnings denied. Generated ABI drift checking,
formatting, and whitespace/diff checks were clean.

## Finalization and concurrency audit

The receive reservation changes queue coordination without holding a Channel
lock across usercopy. A second receiver receives `WOULD_BLOCK` while the head is
reserved; cancellation leaves the datagram untouched. The syscall endpoint
`InternalRef` remains live until result publication and reservation completion,
so endpoint finalization cannot race the selected head's sizing or success
copyout.

Endpoint finalization drains only the closing side's inbound queue, preserves
messages already committed to the peer, recomputes peer readiness from committed
state, and returns waiter wakes for deferred scheduler/pin cleanup outside the
Channel lock. A dedicated central-finalizer regression verifies that routing a
Channel `FinalRelease` through `PayloadFinalizer` publishes `PEER_CLOSED` and
completes both endpoint lifetimes without bypassing typed cleanup.

## Remaining DW0-F work

F5 adds no handle-transfer implementation. Proceed next to DW0-F6 for the
all-or-nothing move-only handle-transfer transaction contract. Later F7-F11 work
still owns public wait syscalls, timers/sleep, guest coverage, adversarial
stress, and phase-level closure/security evidence.
