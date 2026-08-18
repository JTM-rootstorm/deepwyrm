# Generated Deepwyrm ABI artifacts

This directory is owned by `abi-gen`. Do not edit generated files directly.

Generated surfaces include the Rust/C ABI definitions, string-free kernel syscall routing, host-side dispatch/wrapper metadata, the libc-independent x86_64 syscall veneer, and ABI documentation.

From the Deepwyrm repository root:

```text
cargo xtask abi generate
cargo xtask abi check
```

`check` regenerates the expected files in memory and fails on missing, stale, or unexpected output.
