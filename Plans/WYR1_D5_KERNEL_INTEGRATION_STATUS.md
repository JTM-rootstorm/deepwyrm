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

## Selector-local wait capacity

Selector 32 uses 32 wait-registration slots. Selectors 29 and 31 retain 16.
Each wait item consumes a slot, including duplicate views of one Channel in a
single wait-many operation. The joined graph has a demonstrated lower bound
of 20 simultaneous items: consoled 9, UART 3, devmgr 3, registryd at least 3,
console-echo 1, and system-init's Timer 1. Queued stdin adds one consoled item,
raising the lower bound to 21. This bound comes from the first-party product
actor graph; it is not a numeric quota imported from external prior art.

The selector-private geometry asserts that capacity covers the 21-item bound.
Its host regression exercises the real WaitRegistry with six distinct blocked
Thread generations and inert Channel lifetime pins standing in for the actors'
wait sources. Both 20- and 21-item graphs exhaust a 16-slot registry and fit in
32. Three successive generations verify exact cancellation, no leftover
registrations, and final release of every source pin. This is a registration
capacity test, not an execution of the userspace actors or IRQ/readiness path.
The additional slots provide headroom; 21 is not claimed as a maximum across
all recovery interleavings. Other resource budgets and the public ABI remain
unchanged. This correction does not identify wait exhaustion as the cause of
the early `AF010006` failure; the coordinator's frozen-A1 investigation caught
a separate publication-generation mismatch before wait exhaustion.

Validation of this capacity correction passed all 934 selector-32 kernel
library tests, 35 entry/build contract tests, host library/test Clippy with
warnings denied, formatting, and `git diff --check`. The accepted-toolchain
freestanding checks passed selector 32, selector 29, and selector 31 in E3B
full mode, with their existing 9, 25, and 13 unused-code warnings respectively.
These checks used `tools/pinned-cargo` with isolated `.tmp/wait-budget-host`
and `.tmp/wait-budget-target-{32,29,31}` output in the assigned worktree.
No VM or security-gate result is claimed for this correction.

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
