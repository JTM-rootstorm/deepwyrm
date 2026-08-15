# deepwyrm-abi

`deepwyrm-abi` is the `no_std` consumer crate for definitions generated from
Deepwyrm's canonical ABI schema.

It exports fixed-width ABI-safe types, constants, BootInfo and syscall records,
and explicit syscall identifiers. Generated textual dispatch/wrapper metadata
stays outside this crate because its strings and slices are tooling inputs, not
ABI-safe values. This crate does not implement a syscall instruction or kernel
behavior. Both kernel and userspace consumers use the same fixed-width
representation.

Do not edit generated files directly. Change `abi/schema`, run `cargo xtask abi
generate`, and verify `cargo xtask abi check` plus the focused host tests.
