# Object boundary

The generic `ObjectRegistry` in `mod.rs` is the sole DW0 object-liveness core.
It owns opaque identity, generation retirement, checked strong references, and
typed final-release authority without knowing about process-local handles or
subsystem payload storage.

Caller-local handle policy lives under `kernel/src/handle/`. Typed payload
owners such as `MemoryObjectAuthority` retain generic object identity while
keeping backing-specific state in their own subsystem, and crate-level services
compose those boundaries without moving liveness authority out of this module.
