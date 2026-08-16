# Deepwyrm Bootstrap Status

Deepwyrm is implementing DW0 in the order defined by the architecture and DW0
planning documents.

## Current claim boundary

Phase DW0-A passed its host-only ABI layout gate at revision
`37338e8d44c08ef039eb34a01292a6b6cb5cac3a`. DW0-B source and freestanding build
gates passed at `0bc8e6667e27ebd6aa5e3d572f34b9a1dfddefc7`, while its exact
Wyrmroot/Q35 execution gate remains pending. The detailed records are
[`DW0_A_VALIDATION.md`](DW0_A_VALIDATION.md) and
[`DW0_B_VALIDATION.md`](DW0_B_VALIDATION.md).

DW0-C now has committed physical ownership, mapping authority, atomic
publication, transition attestation, and one-shot Deep-root activation through
revision `2c32c82aef71c1e52cfde2fc368beb93a63d8f8c`. An uncommitted C3 candidate
adds real build-selected memory guest bodies and passes its host and target
artifact gates. [`DW0_C_VALIDATION.md`](DW0_C_VALIDATION.md) records the exact
qualified evidence and pending gates. DW0-C is not complete until mandatory
security review and coordinator-owned execution of all six selectors pass
against an exact paired image.

The repository still does not provide DW0-D handles, DW0-E tasks/syscalls,
later IPC/synchronization/time behavior, a primordial Wyrmroot process, or a
completed DW0 release-candidate security and end-to-end gate. No source or
artifact result in these records establishes a compatible Wyrmroot revision
pair or VM behavior that was not actually tested.

## Authority

The canonical reading order and authority rules are in
[`Plans/ARCHITECTURE_INDEX.md`](../Plans/ARCHITECTURE_INDEX.md). The DW0 plan
and its locked addenda define intended work and acceptance requirements; they
are not a record of completed implementation.

Status claims must be backed by current repository evidence. A future phase
gate report must identify the exact tested revision, relevant artifact hashes,
commands or selectors actually run, results, security disposition, and any
cross-repository Wyrmroot revision required by the gate.

Until that evidence exists, planned command examples such as `cargo xtask
build`, `cargo xtask image`, `cargo xtask run`, and the planned test selectors
must not be reported as supported or passing solely because they appear in a
plan or placeholder command surface.
