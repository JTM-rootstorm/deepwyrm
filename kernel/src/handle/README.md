# Handle boundary

DW0-D3 implements the fixed-capacity caller-local `HandleTable` in `table.rs`
and generated-policy rights validation in `rights.rs`. Handle values use private
slot/generation encoding and deliberately have no global/table-domain identity.

Process ownership, MemoryObject integration, service/status adapters, syscall
copyout, and cross-process channel transfer remain later DW0 work.
