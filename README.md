# Deepwyrm

Deepwyrm is the Rust-first kernel project for [Wyrmroot](https://github.com/JTM-rootstorm/wyrmroot). Its architecture defines a small, native, capability-oriented substrate for operating-system services without adopting the Linux ABI or POSIX as its internal model.

## Intent

Deepwyrm is designed around typed kernel objects, opaque process-local rights-bearing handles, and an explicit, schema-defined native ABI. Its architecture separates typed, rights-controlled kernel mechanisms from naming, service policy, compatibility behavior, and other higher-level userspace decisions.

Portable kernel code is written in Rust where practical. Architecture-specific, hardware-facing, assembly, C, and unsafe Rust code is kept behind narrow, documented boundaries. Subsystem boundaries are designed to support focused host-side and synthetic testing as well as full-system validation.

Compatibility environments may translate POSIX, Linux, Windows, or retro APIs onto the native object and handle model. Those environments are consumers of the kernel ABI rather than foundations of it.

## Relationship to Wyrmroot

Deepwyrm owns the native kernel ABI and kernel-side object semantics. Wyrmroot owns loader, platform, and userspace policy, including system-image construction.

Shared boot and ABI contracts are coordinated across both projects. Wyrmroot consumes generated ABI definitions from an exact Deepwyrm revision, allowing its policies and compatibility layers to evolve without becoming kernel foundations.

## Documentation

- [Architecture and plan index](Plans/ARCHITECTURE_INDEX.md)
- [Pre-phase-zero invariants](Plans/DEEPWYRM_PRE_PHASE0_INVARIANTS.md)
- [DW0 implementation plan](Plans/DW0_IMPLEMENTATION_PLAN.md)
- [Native ABI schema and generated artifacts](abi/README.md)
- [Bootstrap and validation status](docs/BOOTSTRAP_STATUS.md)
- [Contributing](CONTRIBUTING.md)

## License

Deepwyrm is licensed under [GPL-2.0-or-later](LICENSE).
