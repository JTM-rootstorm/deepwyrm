# DW0-B Intermediate Security Review

## Reviewed identity and method

This manual intermediate-phase review originally covered pre-signing Deepwyrm
commit `0bc8e6667e27ebd6aa5e3d572f34b9a1dfddefc7`, including the raw x86_64
entry boundary, BootInfo intake, early diagnostics, descriptor and exception
setup, APIC model, test-only completion transport, and host harness planning.
Its signed equivalent is `a194194016b10dce269f286950dfa90b27851217`; both commits
have tree `5766bba49c27118f6fcf9a85f6edb9742a00f9a0` and preserve the author and
complete commit message. Per Mike, no build, test, or artifact was rerun or
regenerated after signing. The source-security disposition carries to the
signed commit solely through exact tree equivalence; historical artifacts
remain attributed to the pre-signing identity.

Seven bounded implementation and review lanes examined architecture state,
hostile handoff parsing, unsafe boundaries, descriptor and exception state,
interrupt-controller sequencing, test-channel separation, artifact provenance,
and result-evidence integrity. This review is an intermediate DW0 phase review;
it does not replace the required security review of a future release candidate.

## Threat surfaces reviewed

- loader-provided register, stack, mapping, BootInfo, and ELF state;
- bounded memory-map and module snapshots and mutation-after-validation behavior;
- COM1 polling, reentrancy, panic redaction, and exact machine-record output;
- GDT, TSS, emergency and final IDTs, IST ownership, exception normalization,
  CR2 capture, and assembly-to-Rust pointer contracts;
- APIC discovery, disabled/xAPIC/x2APIC state, vector allocation, source masking,
  and fail-stopped controller transitions;
- production exclusion of QEMU selector and debug-exit channels; and
- request paths, toolchain identity, artifact hashes, serial parsing, and
  serial/exit result agreement.

## Remediated findings

- BootInfo validation now copies bounded memory-map and module records into
  owned storage, preventing a mutable-reader time-of-check/time-of-use bypass.
- Arbitrary x86 port I/O and QEMU completion construction are private narrow
  boundaries. Machine records use exact bytes and wait for transmitter drain
  before debug exit.
- The emergency IDT is installed before fault-prone handoff parsing. The final
  IDT uses separate 16 KiB IST stacks for double fault, NMI, and machine check.
- Exception assembly snapshots the required general registers and CR2 before
  entering Rust, normalizes hardware error codes, and calls unsafe System V
  pointer boundaries with explicit preconditions.
- Test outcomes require one strict fixed-width record and a matching QEMU exit
  status. Inputs are bounded and serial scanning is linear.
- Harness planning derives executable paths and hashes from committed trusted
  configuration. A Wyrmroot request cannot authorize execution of an arbitrary
  host binary; planning executes no request-selected code.
- Guest-result hashing and parsing use one bounded request buffer, preventing a
  concurrent request replacement from changing the parsed identity after the
  digest is computed.
- Root and sysroot manifests are each read once through an atomic no-symlink
  boundary, then hashed and parsed from those exact bytes. The selected target
  libraries and rustc internal libraries are independently rehashed.
- The approved deterministic toolchain-tree digest is revalidated without
  dereferencing its source symlink entries. Host Clang, libclang-cpp, LLVM, and
  configuration identities are verified before canonical artifact builds.
- Guest planning validates the complete central profile and selector metadata
  and binds the GDB stub to loopback only. Bounded request, configuration, and
  result readers reject symlink traversal.

No Critical or High source-security finding remains within DW0-B scope.

## Accepted deferrals

The terminal ring-0 exception path does not decode the optional old `RSP` and
`SS` frame tail. It rejects CPL3 frames, never resumes, and reads only mandatory
frame words. Distinct resumable or user-mode exception stubs must close this
diagnostic limitation before CPL3 delivery or `iretq` return is implemented.

The dedicated IST stacks do not yet have guard pages or per-CPU ownership.
That is accepted only for DW0-B's single-BSP, interrupts-disabled, terminal
paths. DW0-C page-table ownership must add guard pages, and SMP or nonterminal
reuse requires per-CPU stacks.

DW0-B snapshots structurally valid memory-map records but does not establish
semantic ownership of their physical ranges. DW0-C must validate physical
width and range semantics, overlaps, reservations, and ownership before it
constructs replacement mappings.

Command-line and entropy payloads remain physical ranges under the loader's
immutable transition mappings. DW0-B does not consume them or replace those
mappings; they must be copied or consumed before the transition CR3 is retired.
ACPI table traversal is likewise deferred: DW0-B retains only the validated
RSDP address and never identity-maps all ACPI reclaim or NVS memory.

The fixed system `tar` and `sha256sum` executables, host libc, libstdc++,
libgcc, kernel, and other ordinary host runtime components remain Medium
platform assumptions. The accepted Rust artifact also retains absolute source
symlink entries and historical command text. They are included as
non-dereferenced tree-digest entries but are not runtime-authorized inputs.

The build-tools verifier and `kernel/build.rs` remain separate commands.
Canonical rebuild evidence must therefore record the verified absolute Clang
and configuration paths and set that exact Clang path through
`DEEPWYRM_CLANG`. Same-user replacement between verification and process
execution remains a Medium host-integrity limitation.

`guest-result` deliberately reports `freshness_proof: false`. The coordinator
must create a fresh bounded capture, bind it to the exact request and artifacts,
and retain the observed exit status; parser success alone is not VM evidence.

## Disposition

PASS for the DW0-B source-security gate at the reviewed pre-signing revision
and its exact same-tree signed equivalent. Functional phase acceptance still
requires the coordinator-owned fresh QEMU capture gate against an exact
Deepwyrm/Wyrmroot artifact pair. Any security-relevant tree change to the
reviewed surfaces invalidates this disposition until re-review.
