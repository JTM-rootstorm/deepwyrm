# Deepwyrm DW0 Implementation Plan Addendum: LLVM Toolchain and Debugging

**Status:** Canonical locked addendum to `Plans/DW0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/deepwyrm`  
**Milestone:** DW0  
**Scope:** Canonical non-Rust compiler toolchain, linker/runtime support, binary utilities, and host-side debugging

This document is part of the DW0 implementation contract. Codex and human contributors must treat the decisions below as **locked** unless an explicit architecture revision updates this addendum and the matching Wyrmroot WYR0 toolchain addendum together.

The central rule is:

> **Deepwyrm uses the LLVM toolchain family as its canonical non-Rust build environment, while host-side GDB remains a supported and preferred debugger for the QEMU guest.**

LLVM/Clang is canonical because the Wyrmroot Rust toolchain already uses LLVM code generation, because Clang/LLD work well for explicit cross/freestanding targets, and because `compiler-rt` fits the project's libc-independent runtime policy. This choice does not prohibit GCC or GNU binutils from being supported later as alternate toolchains.

---

# 1. Locked canonical toolchain

For DW0 and subsequent Deepwyrm bring-up, the canonical non-Rust tool family is:

```text
C compiler:             Clang
C++ compiler:           Clang++ when required
Linker:                 LLD (`ld.lld`)
Compiler builtins:      compiler-rt where required
Assembler:              Clang integrated assembler and/or LLVM tooling
Archiver:               llvm-ar
Object inspection:      llvm-readelf / llvm-objdump
Binary manipulation:    llvm-objcopy
Symbolization:           llvm-symbolizer
Rust compiler:           Wyrmroot-maintained rustc fork using LLVM backend
Debugger:                host-side GDB against QEMU gdbstub
```

GNU GCC/binutils are not required for DW0 completion.

They may later be supported as alternate compilers/tooling, but they do not define the Deepwyrm ABI and must not become hidden build dependencies for the canonical milestone path.

---

# 2. Rust remains the primary implementation language

This addendum does not change the Rust-first kernel policy.

Expected Deepwyrm source balance is conceptually:

```text
Deepwyrm
├── Rust
│   └── normal kernel subsystems
├── assembly
│   └── architecture entry/context-transition work where justified
└── C/C++
    └── only where imported code or a concrete implementation reason justifies it
```

Clang exists as the canonical C/C++/assembly escape hatch, not as a replacement for the Rust-first architecture.

---

# 3. Freestanding C/C++ policy

Any C/C++ that executes as part of Deepwyrm must be built as an explicit freestanding target.

Requirements:

- no accidental host include paths
- no accidental host library search paths
- no host libc linkage
- no POSIX assumption merely because the build host is Gentoo
- explicit target/cpu/code-model configuration owned by Deepwyrm build tooling
- kernel-specific options centralized rather than copied into per-file scripts

The final compiler flags are implementation details until the kernel link model is proven, but the build must use the equivalent of an explicit freestanding environment rather than inheriting host defaults.

Clang may still emit low-level calls such as `memcpy`, `memmove`, or `memset`. Deepwyrm may provide small kernel/runtime implementations or equivalent compiler-compatible intrinsics. These helpers are not considered libc and must remain narrow, auditable runtime facilities.

---

# 4. Linker policy

LLD is the canonical DW0 linker.

The kernel linker configuration must:

- be explicit and reproducible
- define the Deepwyrm ELF layout and higher-half arrangement in one canonical place
- generate useful debug/symbol information for host tooling
- avoid dependence on GNU `ld` behavior that is not represented in the documented linker configuration
- keep architecture-specific constants centralized

If linker scripts are used, they should remain compatible with the chosen LLD behavior rather than relying on incidental GNU linker quirks.

LTO is **not** required for DW0.

Debug and early release builds should favor transparency and debuggability over whole-program optimization. ThinLTO or broader LTO may be evaluated only after the baseline build/test/debug workflow is stable.

---

# 5. compiler-rt and libc independence

`compiler-rt` is the preferred source of compiler-generated low-level builtins when those helpers are required by Clang/LLVM-produced code.

The following distinction is locked:

```text
compiler/runtime support       permitted
libc / POSIX runtime           not required
```

Examples of allowed compiler/runtime support include arithmetic helpers, selected atomic helpers, sanitizer support in host tests, and other compiler-generated primitives that do not impose POSIX/libc semantics on Deepwyrm.

Do not introduce glibc, musl, newlib, or libgcc merely because generated code needs a helper if the same requirement can be satisfied cleanly by compiler-rt or a small Deepwyrm runtime implementation.

---

# 6. ABI independence from compiler choice

Deepwyrm ABI behavior is defined by:

```text
ABI schema/specification
        |
        +-- Rust bindings
        +-- Clang/C bindings
        +-- future GCC/C bindings
```

It is **not** defined by whatever Clang happens to emit.

Rules:

- compiler-specific structure layout must never substitute for an explicit ABI definition
- generated C/Rust bindings consume fixed-width ABI-safe types
- no Clang extension becomes ABI simply because it is convenient
- no future GCC support may require changing a stable ABI merely to match GCC defaults
- compiler bugs/workarounds remain toolchain concerns, not kernel-interface semantics

This preserves the option to validate Deepwyrm with multiple compilers later.

---

# 7. Host-side GDB is canonical and explicitly allowed

LLVM/Clang as the compiler family does **not** require LLVM's debugger to be used.

For DW0/WYR0 development, host-side GDB against QEMU's remote debugging stub is a canonical debugging path.

Desired workflow:

```text
Gentoo host
    |
    +-- build Deepwyrm with Rust/LLVM/Clang/LLD
    |
    +-- launch QEMU paused with gdbstub enabled
    |
    +-- launch host GDB with Deepwyrm symbols
    |
    `-- inspect guest registers/memory/breakpoints/backtraces
```

Tooling should provide a stable command similar to:

```text
cargo xtask gdb
```

or an equivalent documented command that:

1. starts QEMU in the canonical DW0 VM configuration with the CPU paused before normal execution where appropriate
2. enables the QEMU GDB remote stub on a deterministic or safely selected local port
3. loads the correct Deepwyrm symbol file into host GDB
4. establishes the architecture/remote target settings required for x86_64
5. allows breakpoints from early kernel entry onward

GDB remains host-side development tooling and therefore may use the Gentoo host libc/runtime normally.

LLDB may be supported later as an additional debugger, but it is not required for DW0 and does not replace the GDB requirement.

---

# 8. LLVM binary utilities complement GDB

The canonical debug/inspection workflow may use:

- `llvm-symbolizer` for panic/backtrace symbolization
- `llvm-objdump` for disassembly and section inspection
- `llvm-readelf` for ELF/program-header validation
- `llvm-nm` for symbol inspection
- `llvm-objcopy` for debug/symbol image preparation where required

These tools complement rather than replace GDB.

The preferred failure workflow is:

```text
serial/panic record
       |
llvm-symbolizer / build metadata
       |
reproduce under QEMU
       |
host GDB if live inspection is needed
```

---

# 9. Sanitizer and analysis policy

LLVM sanitizers are valuable where the code can run meaningfully on the host, but DW0 must not assume that guest-side ASan/UBSan/TSan/MSan runtimes already work on Deepwyrm.

Immediately useful host-side targets include:

- ABI parsers/generator
- ELF validation code where factored into host-testable libraries
- handle/rights algorithms
- queue/ring algorithms
- image/BootInfo helpers that can be exercised outside the kernel

Use host-side sanitizer/fuzz/property tests as additional validation where practical.

Guest-side sanitizer runtimes are a later porting project and are not a DW0 prerequisite.

---

# 10. GCC and GNU binutils future support

GCC and GNU binutils remain valid future compatibility/alternative toolchains.

Potential later goals include:

```text
x86_64-wyrmroot-gcc
x86_64-wyrmroot-binutils
```

or equivalent packaged targets.

Reasons to support them later include:

- compiler-diversity testing
- detecting accidental Clang-specific source assumptions
- supporting software that strongly prefers GCC
- giving developers toolchain choice

However:

- GCC is not required to build DW0
- GNU `ld` is not the canonical linker
- libgcc is not the canonical compiler-runtime dependency
- alternate toolchain support must consume the existing ABI rather than redefine it

---

# 11. Implementation-phase amendments

## DW0-A

- Record the canonical host LLVM/Clang/LLD tool versions used by the milestone build environment.
- Keep Rust and non-Rust target settings centralized in `xtask`/build configuration.
- Add tool-detection diagnostics for Clang, LLD, LLVM utilities, and GDB.
- Do not require GCC/binutils for the canonical build.

## DW0-B

- Add the host-side GDB/QEMU gdbstub workflow as a first-class development command.
- Preserve symbol-rich debug builds.
- Verify an early-entry breakpoint can be hit before relying on GDB for later phase debugging.

## DW0-C through DW0-G

- Any C/assembly additions must remain freestanding and free of host-runtime leakage.
- Use LLVM object-inspection tools in targeted validation where useful.
- Keep compiler-generated helper dependencies documented and libc-independent.

## DW0-H

- Milestone closure must build through the documented canonical LLVM/Clang/LLD path.
- Run at least one documented host-GDB smoke session or automated equivalent proving the debug symbols and gdbstub configuration remain usable.
- Verify the final required guest artifacts contain no accidental host/libc dependencies.

---

# 12. DW0 toolchain/debug gate

DW0 must not be tagged complete until:

- the canonical build succeeds using the pinned/documented LLVM/Clang/LLD environment
- non-Rust guest/kernel code is compiled as an explicit freestanding target
- LLD is the canonical linker for the reference build
- compiler-generated runtime helpers are satisfied without introducing guest libc
- LLVM object/symbol inspection works against produced Deepwyrm artifacts
- host-side GDB can connect to the canonical QEMU gdbstub configuration and debug the generated kernel image with correct symbols
- no DW0 ABI contract depends on undocumented Clang-specific layout or behavior
- GCC/GNU binutils are not hidden prerequisites for milestone completion

This gate is additive to the existing DW0 functional, libc-independence, image-delivery, and security-validation gates.
