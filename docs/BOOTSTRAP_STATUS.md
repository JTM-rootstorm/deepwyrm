# Deepwyrm Bootstrap Status

Deepwyrm is implementing DW0 in the order defined by the architecture and DW0
planning documents.

## Current claim boundary

Phase DW0-A passed its host-only ABI layout gate at Deepwyrm revision
`37338e8d44c08ef039eb34a01292a6b6cb5cac3a`. The detailed command, clean-checkout,
review, and limitation record is in
[`DW0_A_VALIDATION.md`](DW0_A_VALIDATION.md).

The repository now provides a canonical ABI 0 schema, deterministic generator,
fixed-width Rust and C definitions, committed drift-checked outputs, a `no_std`
`deepwyrm-abi` crate, and focused host commands. It does not currently provide:

- a bootable x86_64 Deepwyrm kernel, UEFI handoff, serial/panic path, or guest
  test completion path;
- implemented memory, object, handle, task, syscall, IPC, synchronization, or
  time behavior;
- a primordial ELF loader or primordial Wyrmroot process launch;
- a canonical Deepwyrm/Wyrmroot image, QEMU integration result, or tested
  compatible revision pair; or
- a completed DW0 release-candidate security, libc-independence, toolchain,
  image-delivery, or milestone-closure gate.

DW0-A evidence establishes only the host ABI/schema/tooling gate. It does not
establish kernel behavior, guest toolchain acceptance, boot reproducibility,
guest execution, or any later phase gate.

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
