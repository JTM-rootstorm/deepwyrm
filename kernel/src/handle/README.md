# Handle boundary

The handle core owns the fixed-capacity caller-local `HandleTable` in `table.rs`
and generated-policy rights validation in `rights.rs`. Handle values use private
slot/generation encoding and deliberately have no global/table-domain identity.

The syscall-independent object/handle service composition lives at crate scope
from `service.rs`: it maps table failures to ABI statuses and combines resolved
handles with typed payload authorities such as `MemoryObject`. Keeping that
composition outside `handle/mod.rs` preserves the handle core as an independent
authority boundary for compile-fail tests and later per-process ownership.

Process ownership, syscall usercopy/copyout, and cross-process channel transfer
remain outside this boundary.
