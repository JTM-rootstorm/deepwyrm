# DW0-F10 Functional Validation

## Status

DW0-F10 is functionally closed for the public native `process_create` adapter
on Deepwyrm revision `222f0cd3c28469f7b2bf705da6f31527e3d735ff`.

F10 composes the existing E typed Process/root AddressRegion factories with
the F6 HandleTable MOVE machinery as one all-or-nothing transaction. It does
not create a parallel Process lifetime, Channel transfer path, or address-space
model.

This record closes the F10 host/model gate. It does not activate selector 17,
execute a target or VM gate, start a Thread, load an ELF, wire the complete F
native service runtime, implement F11 host-command consolidation, close F12,
or establish the cumulative F13 security disposition.

## Implemented transaction boundary

The public adapter now:

- requires the exact 88-byte `DwProcessCreateArgsV1` and 64-byte
  `DwProcessCreateResultV1` scalar sizes;
- copies and decodes the complete input record before inspecting any handle;
- rejects nonzero flags/reserved fields and zero, unknown, or incompatible
  Process, root-region, and child-bootstrap rights;
- preflights and owns the exact result range before resolving or mutating
  kernel authority;
- resolves the parent TaskGroup with `MODIFY`, then the bootstrap Channel with
  `TRANSFER`, preserving the F0 status precedence;
- validates the requested child Channel rights as a nonzero compatible subset
  of the source handle rights;
- prepares one generation- and HandleTable-domain-bound source MOVE without
  invalidating the parent handle;
- reserves an unpublished Process shell and parent hierarchy slot;
- reserves one destination in the new Process's private HandleTable;
- prepares the root AddressRegion, address space, typed payload, Process parent
  pin, and root-attachment reservation without normal hierarchy visibility;
- reserves a heterogeneous pair of parent result slots with independently
  requested Process and AddressRegion rights; and
- performs the remaining publication sequence without a recoverable step:
  extract the source, publish the child handle, retire the source generation,
  commit root/process typed state and hierarchy, publish both parent results,
  release lookup pins, then commit the already-pinned result bytes.

All pre-commit exits discard inert HandleTable reservations and cancel typed
construction child-before-parent. Cancellation releases the root-region and
address-space identities, Process parent/runtime/execution references, generic
object liveness, and the reserved hierarchy slot. A reserved Process is
explicitly excluded from ordinary TaskGroup teardown traversal.

The current DW0 single-owner kernel uses the adapter's exclusive mutable
authority set as the coarse observation barrier. Owned tokens are bound to the
exact authority domain and slot generation, so task, HandleTable, address-space,
and ObjectRegistry ownership is still acquired sequentially rather than nested.

## Child-HandleTable ordering refinement

The root F10 plan describes child-slot reservation and typed construction as
separate preparation steps. The child HandleTable does not exist until the E
Process shell is materialized by value, so that wording cannot be implemented
literally without inventing a second HandleTable or publishing a Process too
early.

The accepted refinement keeps the root plan's observable status precedence and
all fallible work before commit:

1. validate/copy arguments and preflight the result;
2. resolve TaskGroup and Channel authority;
3. prepare the source MOVE;
4. prepare an invisible, cancelable Process shell and hierarchy reservation;
5. reserve the bootstrap destination in that shell's private HandleTable;
6. prepare the unpublished root AddressRegion component;
7. reserve the heterogeneous parent result pair last; and
8. enter the observation-guarded no-fail commit.

This is the smallest split that materializes the child table while retaining E
lifetime ownership and F6 transfer authority. It changes no public ABI or
failure status.

## Focused failure and success evidence

The focused `process_create` filter passed six tests. Coverage includes:

- outer argument/result sizes, copied record size/version/flags/reserved fields,
  and each requested-right class;
- distinct input-copy and result-preflight `BAD_ADDRESS` paths with no generic
  generation, output-ownership, or caller-state mutation;
- stale TaskGroup and bootstrap handles, live wrong object types, missing
  `MODIFY`/`TRANSFER`, child-right escalation, and exact status precedence;
- a terminating target TaskGroup returning `BAD_STATE` before construction;
- a naturally full parent HandleTable returning `NO_RESOURCES` during the real
  heterogeneous result-pair reservation while preserving the source;
- injected failure after each of the five preparation boundaries: source MOVE,
  Process shell, child destination, root component, and parent result pair;
- three consecutive failures at every injected boundary in the same bounded
  fixture, followed by an ordinary successful creation and complete typed
  teardown, proving Process, root-region, address-space, hierarchy, HandleTable,
  and generic-object capacity returned;
- successful parent Process/root handles with exactly the requested rights;
- a reduced-right child Channel handle and an invalidated parent source only
  after complete success;
- `child_bootstrap_handle` treated only as child-table metadata;
- a CREATED Process with an attached root region and no Thread start; and
- native typed decode/dispatch reaching the real adapter for both success and
  output-preflight failure.

The lower-level substrate tests additionally cover exact single-MOVE rollback,
generation/domain drift rejection, mutation-free destination cancellation,
heterogeneous pair publication, type drift before partial publication, reserved
Process invisibility during TaskGroup teardown, and prepared Process/root
cancellation.

## Validation commands

All mutable build state was kept under project-local `.tmp/` paths. The
following gates passed:

```text
cargo fmt --all -- --check
git diff --check
cargo test --locked -p deepwyrm-kernel --lib process_create
cargo test --locked -p deepwyrm-kernel --lib
cargo clippy --locked -p deepwyrm-kernel --lib --tests -- -D warnings
cargo xtask abi check
cargo xtask test host tasks
cargo test --locked --workspace --all-targets --offline
cargo clippy --locked --workspace --all-targets --offline -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --offline
```

The focused F10 filter reported `6 passed; 0 failed`. The kernel library suite
reported `427 passed; 0 failed`. The task host gate included 43 adapter tests,
10 native request tests, task/scheduler/execution tests, finalizer tests, ABI
codecs, and the applicable compile-fail and x86_64 contract suites. The full
workspace gate also passed ABI generator/layout, xtask, and all-target contract
tests. Clippy and rustdoc passed with warnings denied.

`cargo xtask abi check` confirmed that F10 required no schema, syscall number,
record layout, object type, signal, or rights change.

## Commits

F10 was implemented in two reviewed, unsigned commits:

- `721b988ee1d3bfd8bf5e6fe14113c69248f3650b` — prepare the owned HandleTable
  transaction tokens and the cancelable E Process/root factories; and
- `222f0cd3c28469f7b2bf705da6f31527e3d735ff` — activate the public adapter,
  native route coverage, exhaustive rollback tests, and strict-lint cleanup.

Both commits retain the configured repository author and the required Codex
co-author trailer. Neither commit was signed or pushed.

## Explicit non-claims and next work

Selector `process-create-bootstrap` (ID 17) remains reserved metadata. F10's
plan gate is the exhaustive host/model transaction gate above; it does not
require a separate target body or VM run. F12 owns the complete live F service
runtime and the synthetic userspace scenario that will exercise Process create,
Channel, Event, Timer, waits, and transfer together.

No Wyrmroot, Rust-fork, Thread-start, ELF-loader, or VM change was made. No
Daybreak scan was run at this ordinary implementation checkpoint; the dedicated
end-of-sprint F13 security gate remains authoritative.

## Disposition

Deepwyrm revision `222f0cd3c28469f7b2bf705da6f31527e3d735ff`
satisfies the DW0-F10 functional gate. F11 may proceed without reopening F10
absent a regression or later security finding.
