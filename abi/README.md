# Deepwyrm ABI workspace

This directory contains Deepwyrm's canonical native ABI schema and generated
artifacts.

The human-maintained source of truth is under `schema/`. The dependency-free
`abi-gen` host tool renders the committed files under `generated/`.

From the repository root:

```text
cargo xtask abi generate
cargo xtask abi check
cargo xtask test host abi
```

Change schema or generator sources, never a derived file as an independent
contract. `abi check` rejects missing, stale, or unexpected generated output.

`generated/abi_fingerprint.toml` is a SHA-256 semantic fingerprint over the
normalized schema. It covers the syscall convention, numbers, arguments,
directions and rights, objects, rights, signals, statuses, boot enumerations,
constants, and record layouts. It excludes documentation text and the
implementation-phase metadata. Wyrmroot's revision-pairing gates compare this
fingerprint rather than the `abi/` tree, so a documentation-only schema edit
still regenerates `generated/` but does not force a Wyrmroot repin.
