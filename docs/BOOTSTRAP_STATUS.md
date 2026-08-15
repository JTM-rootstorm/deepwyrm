# Deepwyrm Bootstrap Status

Deepwyrm is currently a bootstrap scaffold governed by the architecture and
DW0 planning documents.

## Current claim boundary

No DW0 phase gate has been completed. In particular, the repository does not
currently provide:

- a canonical native ABI schema, generator, generated contract, or passing ABI
  layout/drift gate;
- a bootable x86_64 Deepwyrm kernel, UEFI handoff, serial/panic path, or guest
  test completion path;
- implemented memory, object, handle, task, syscall, IPC, synchronization, or
  time behavior;
- a primordial ELF loader or primordial Wyrmroot process launch;
- a canonical Deepwyrm/Wyrmroot image, QEMU integration result, or tested
  compatible revision pair; or
- a completed DW0 security, libc-independence, toolchain, image-delivery, or
  milestone-closure gate.

Existing package manifests, placeholder modules, directory boundaries,
toolchain provenance metadata, workflow files, and command-surface scaffolding
only establish repository structure. They do not establish kernel behavior,
ABI values, toolchain usability, build reproducibility, guest execution, or a
passing phase gate.

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
