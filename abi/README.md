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
