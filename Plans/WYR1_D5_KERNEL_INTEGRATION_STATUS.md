# WYR1-D5 kernel integration

Date: 2026-09-04

This is the selector-32 kernel integration record. Product integration and
the live UP/SMP COM2 gate remain coordinator-owned and pending. D6 and WYR1-D
closure are not claimed.

`native-console-streams` selects test ID 32, the existing q35 COM2 platform,
and a distinct private WRD1 collector. The public generated ABI is unchanged.
The private raw operation `0xffff_ff20` remains bound to the first permanent
system-init process after exact primordial retirement. Mode zero accepts one
192-byte WRD1 record; mode one accepts one 178-byte D5READY trigger. All unused
arguments are zero. Readiness joins record counts 2, 9, and 11; twelve WRD1
records remain buffered until one atomic COM1 transaction emits the complete
certificate followed by test-32/detail-zero DWTEST1 and its debug exit.

The resume repairs complete both terminal fallback paths, selector diagnostic
tags, the primordial expectation match, and the platform acknowledgement's
terminal-retry helper. The helper is compiled with its enclosing q35 module
because ordinary platform acknowledgement can call it independently of the
selector-31 evidence collector. Primordial completion alone cannot pass D5.

Replacement semantics follow the frozen serial-stream contract and the actual
Wyrmroot allocator. Driver-only replacement preserves role and bundle lease;
attempt, attach transaction, stream, console, and child advance strictly. The
endpoint `(id, generation)` pair changes; a fresh ID can retain generation 1.
Child-only replacement preserves the complete driver/raw-stream/console tuple,
including the attach transaction, and advances only child generation.

## Source disposition

The active root D5 plan, Wyrmroot serial-stream contract section 9, Deepwyrm
architecture index, and WYR1-C6 evidence design provide the adapted framing,
reporter-retirement, and terminal pattern. The DW1-D device/Interrupt contract
and validation record, DW1-E0 q35 contract, E3B implementation status, root
bootstrap/recovery architecture, and reached interrupt, ACPI, APIC, IDT and
returning IPI paths provide the ownership and cfg constraints.

Pinned external sources retained under root `.tmp/e2-d3-prior-art` were
consulted before repairs: Fuchsia
`6a606ff7fd9b055edee6557566fb3f112df1a812` interrupt/resource dispatchers and
driver host are conceptual lifetime/separation references; xv6-riscv
`35b088427ef37611c38afdeed5a52a278cae38f9` UART, console, trap and PLIC;
uart_16550 `176b07b076bdc1fe999a5e757ab53a0e24b4005c` lib/config/spec/README;
and linenoise `a473823d74b93eab2ba83480df16ed37617493f2` are not applicable to
these selector/cfg repairs. No external source code was copied or adapted.

## Validation boundary

The canonical pinned host and target commands are in `tooling/README.md`.
Host tests cover collector framing/readiness, complete atomic flushing,
same-bundle replacement with endpoint generation 1, rejected lease drift and
endpoint reuse, ordered identity regressions, and preserved child attach
transaction. The entry/build contract suite includes selector-32 isolation and
selector-27/29 preservation. Target checks cover selector 32 and regressions
for selector 29 and full selector 31. Target ACPI dead-code warnings are
reported separately; compilation does not constitute live acceptance.

The completed lane gates passed 933 selector-32 kernel library tests (including
six WRD1 tests), all 35 entry/build contract tests, host Clippy with warnings
denied, formatting, and `git diff --check`. Accepted-toolchain freestanding
checks passed for selector 32, selector 29, and selector 31 with E3B full mode.
The target checks emitted respectively 9, 25, and 13 existing unused-code
warnings; they were not run with warnings denied. Outputs are isolated in the
lane's `.tmp/d5-resume-*` and `.tmp/d5-regression*-target` directories.

No VM, libvirt, GDB endpoint, physical UART, general interrupt-routing,
security-gate, or WYR1-D closure result is provided by this lane.
