# Contributing to Deepwyrm

Deepwyrm is implementing DW0 in ordered phases. The native ABI schema and its
host validation tooling exist, but the repository does not yet contain a
bootable kernel or implemented syscall behavior. See
[the bootstrap status](docs/BOOTSTRAP_STATUS.md) for the current claim boundary.

## Read the architecture first

Before implementation, follow the mandatory reading order in
[`Plans/ARCHITECTURE_INDEX.md`](Plans/ARCHITECTURE_INDEX.md). Treat the locked
plans and addenda as requirements. Do not invent local ABI values, boot
contracts, architecture constants, QEMU profiles, or userspace policy when a
contract is missing.

Deepwyrm owns the kernel-facing native ABI and kernel object semantics.
Wyrmroot owns loader policy, bootfs contents, userspace protocols, image
assembly, and the canonical QEMU/OVMF/media workflow. Shared-contract changes
must be coordinated across both repositories and validated against an exact
Deepwyrm/Wyrmroot revision pair.

## Keep changes bounded

- Preserve subsystem boundaries and keep architecture-specific or unsafe code
  behind narrow interfaces.
- Keep guest and kernel code freestanding and libc-independent. Host-only
  tooling may use the host environment.
- Treat firmware, boot information, ELF, IPC, and generated inputs as hostile.
  Use checked arithmetic, strict bounds, explicit versions, and fail-closed
  validation.
- Add focused regression tests for confirmed defects and security findings when
  technically practical.
- Do not add speculative architecture or expand DW0 with a documented non-goal.

Use the smallest relevant validation available for the change. A command named
in a plan is only a desired interface until the checked-out repository both
implements it and documents its current validation status. Record commands that
were actually run, their exact results, and any remaining unverified claims.

## Licensing changes

Read [`LICENSING.md`](LICENSING.md) and the workspace
[`LICENSING_POLICY.md`](../LICENSING_POLICY.md) before adding copied/adapted
third-party code or changing a package license. The existing Deepwyrm tree
currently retains its `GPL-2.0-or-later` declarations, but new wholly
first-party components default to `GPL-3.0-or-later`. Do not choose 2+ merely
to reserve a hypothetical future Linux import path.

When actual GPLv2-family material or another compatibility requirement enters
a component, preserve the upstream license exactly and use the narrowest
sensible GPLv2-compatible project-owned boundary. In particular, do not
relabel imported `GPL-2.0-only` source as `GPL-2.0-or-later`. Check non-GPL
licenses for compatibility before import, and never infer permission from where
a file lives in the repository.

## Generated files and local artifacts

The ABI schema is the canonical source of truth. Generator-owned ABI outputs
are committed, so `abi/generated/` is deliberately not ignored. Changes to
generated files must originate in the schema or generator and pass
`cargo xtask abi check`.

Rust build output and repository-local staging directories are ignored. Keep
boot media, VM disks, logs, and transient test results out of source paths.
Canonical acceptance artifacts require source revision and hash identity; a
locally named `latest` artifact is not acceptance evidence. See
[`docs/ARTIFACT_HYGIENE.md`](docs/ARTIFACT_HYGIENE.md) for the detailed
boundary.

## Commit and review discipline

Keep commits reviewable and scoped to one coherent change. Every Deepwyrm
commit created with Codex assistance must retain the configured human author
and include this final trailer after a blank line:

```text
Co-authored-by: Codex <codex@openai.com>
```

Do not cryptographically sign, push, rebase, or publish changes unless the
current task explicitly authorizes it. Security-sensitive work requires the
review and disposition flow defined by the DW0 implementation plan before a
phase or milestone gate can close.
