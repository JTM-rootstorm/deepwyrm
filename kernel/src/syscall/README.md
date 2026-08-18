# Syscall boundary

The syscall core consumes schema-generated `DwKnownSyscall` identities rather
than maintaining a private syscall-number table. `mod.rs` owns only phase-aware
numeric decoding and the six raw scalar argument slots captured by the
architecture entry path.

Architecture-specific SYSCALL entry/return belongs under `arch/x86_64`.
Syscall handlers adapt generated identities to typed kernel services and the
pinned usercopy boundary; they do not reimplement handle rights, task lifetime,
or memory business rules. Unknown IDs and operations not active in the current
implementation phase fail closed as `DW_STATUS_NOT_SUPPORTED`.
