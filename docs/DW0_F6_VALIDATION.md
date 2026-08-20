# DW0-F6 Functional Validation

## Status

DW0-F6 is functionally closed for its host-testable atomic Channel handle-transfer scope on the current uncommitted Deepwyrm working-tree candidate based on `3deef9584b6d8056780044708828c158348bfb5d`.

This record does not claim DW0-F phase completion, a guest/VM gate, cumulative Daybreak security acceptance, or a committed revision. DW0-F7 remains the next mechanism phase and owns public `wait_one` / `wait_many` blocking. Wyrmroot remained read-only and clean at `180ad0480db925a92222bccf9e2102a27b351370`.

The exact working-tree source candidate excluding generated validation artifacts and this record is captured by `.artifacts/f6-validation/F6_SOURCE.patch`, SHA-256 `85c835029077164839b81cb5f69bab83efabd39ab14c4277da36fc7208dae238`. The per-file source manifest is `.artifacts/f6-validation/F6_SOURCE_MANIFEST.txt`, SHA-256 `3522087b3885da43e2e33e3cd6ef674fdbddc5a891ae6c400f2b9ec680205457`.

## F6 boundary implemented

F6 extends the F5 byte-datagram Channel with bounded move-only handle transfer while retaining `ObjectRegistry` as the sole generic liveness authority.

Implemented behavior includes:

- complete `DwHandleTransferV1` snapshot/validation before source mutation;
- duplicate-source, reserved-field, and non-MOVE operation rejection;
- one exclusive HandleTable preparation interval for all source entries;
- required `TRANSFER`, known/object-compatible nonzero requested rights, and no rights escalation;
- true movement of each existing generic `HandleRef` into the queued datagram rather than retain-plus-close emulation;
- queue/payload reservation before any source extraction;- exact rollback that restores every extracted source at its original raw handle and original rights when Channel publication fails;
- successful commit invalidation of every sender source exactly once;
- queue-owned transfer tokens carrying object type, reduced rights, and the moved generic handle reference;
- F0 self-reference policy: moving the sending endpoint is supported, while moving the destination endpoint into its own inbound queue is rejected by ObjectId even through another handle;
- receive sizing that reports required handle count without consuming the head;
- exact handle-info output preflight plus complete destination HandleTable reservation before dequeue;
- `NO_RESOURCES` destination-capacity failure that leaves the handle-bearing datagram and its authority intact;
- direct publication of queued references into new receiver-local handles with no rights regain;
- queue teardown that releases queued transfer references exactly once; and
- central `PayloadFinalizer` fan-out for multiple final releases produced by one Channel teardown.

No new ABI schema, record layout, syscall ID, rights bit, signal bit, or Wyrmroot source change was required.

## Focused F6 evidence

The transfer-focused HandleTable suite passes 19 tests. It covers invalid and stale raw sources, duplicate sources, missing `TRANSFER`, zero/unknown/incompatible/escalating rights, extraction rollback, committed rights reduction, destination capacity failure, raw handle-value collision across independent tables, and deterministic mixed-object transfer counts for every count from zero through `DW_CHANNEL_MAX_HANDLES` (16).

The Channel suite passes 12 tests, retaining all F5 FIFO/readiness/peer-close coverage and adding the exact race where peer finalization occurs after transfer extraction but before Channel commit. The failed commit returns the move batch and the rollback restores the source handle exactly.

The Channel syscall-adapter suite passes 8 tests. F6-specific coverage proves a real Event handle send/receive round trip with reduced rights, invalid descriptor validation before mutation, queue-full rollback, receiver HandleTable exhaustion without datagram consumption, peer-endpoint self-reference rejection, and successful movement/republication of the sending endpoint itself.Two central-finalizer Channel tests pass. The new teardown regression queues an Event's final external handle reference, closes the destination endpoint before receive, and proves Channel teardown routes the resulting Event `FinalRelease` through typed Event finalization by immediately reusing the one-slot Event authority.

## Broad host closure

The final source state used project-local build state at `.artifacts/f6-validation/host-target` and passed, under fail-fast shell execution:

```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo test --locked --workspace --all-targets --offline
cargo clippy --locked --workspace --all-targets --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --offline
git diff --check
```

The kernel suite reported `355 passed; 0 failed`. Workspace testing also passed ABI generator/layout tests, compile-fail/UI contracts, architecture contracts, and xtask command-surface tests. The two accepted-toolchain target-artifact tests remained explicitly ignored under their existing dedicated gate policy.

Clippy and rustdoc passed with warnings denied. Generated ABI drift, formatting, and diff whitespace checks were clean.

Preserved log: `.artifacts/f6-validation/logs/full-host-closure-final.log`
SHA-256: `c0feec972c722fd281221c77d618e7ef1917b936dc6f5b363596d88a917b3d0e`.
## Atomicity and lifetime audit

Prepared source moves borrow the caller HandleTable mutably until extraction is either finished or rolled back, so no competing table mutation can invalidate preparation assumptions inside the current ownership model. Source slot generations do not advance on preparation or failed publication; rollback reinstalls the same references and rights. Commit leaves the slots empty for the ordinary next-generation allocation path, making the old raw values stale.

A reserved Channel send consumes descriptor and payload capacity before source extraction. Peer closure after reservation is detected before datagram publication and returns the complete transfer batch to the HandleTable rollback owner. Once publication commits, all bytes and moved references become visible together as one FIFO datagram.

Receive holds a stable head reservation across exact output preflight and destination slot reservation. The datagram is removed only after all destination capacity exists; destination publication then consumes the queued references directly. Endpoint operation pins continue to prevent typed Channel finalization from racing syscall publication.

Queued final references never become an independent liveness database. Channel teardown releases their ordinary generic `HandleRef`s through `ObjectRegistry`; any resulting final releases are fed back through the central typed finalizer stack.

## Explicit non-claims and next work

F6 does not implement `wait_one` or `wait_many`, Timer objects, `atomic_wait32` / `atomic_wake`, public `process_create`, an F guest selector body, canonical paired VM evidence, SMP acceptance, physical-hardware acceptance, or cumulative F security acceptance.

F7 may now build public generic waits on the existing F2 blocking continuation, F3 deadline foundation, and F4/F5 waitable signal sources. F10 remains dependent on this F6 transfer transaction machinery. F13 still owns exact-candidate cumulative Daybreak review and may reopen earlier surfaces if later F work regresses them.

## Disposition

The current uncommitted working-tree candidate satisfies the DW0-F6 functional host gate. It may proceed to F7 without reopening F5. No Git staging, commit, signing, or push was performed.
