# Object boundary

DW0-D2 implements the fixed-capacity generic `ObjectRegistry` in `mod.rs`.
Per-process handle tables, service operations, and MemoryObject integration land
in later DW0-D subphases; this directory remains the sole generic liveness core.
