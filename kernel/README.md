# Deepwyrm kernel crate

The x86_64 kernel: boot intake, objects and handles, tasks and scheduling,
memory, IPC and waits, time, devices and the native syscall surface. Its build
inputs are `arch/x86_64/{layout,task_layout,pools}.toml` and `linker.ld`, read
by `build.rs`. [`../Plans/AS_BUILT_ARCHITECTURE.md`](../Plans/AS_BUILT_ARCHITECTURE.md)
describes what it does.
