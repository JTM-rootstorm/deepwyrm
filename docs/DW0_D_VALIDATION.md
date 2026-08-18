# DW0-D Validation Record

## Disposition

**DW0-D host/core gate passed for the recorded Deepwyrm revision.**

Fresh D8 validation was run on 2026-08-18 against clean Deepwyrm revision
`db09ce173adfb6850765fe2a4547d50a1050ac10`. That revision is a
documentation-only descendant of the manually security-reviewed code candidate
`fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e`.

DW0-D is soft-accepted for continued development. The security disposition is
manual D7 **SOFT ACCEPT**, not a hard Daybreak Blue / Dawnbreak PASS. Proper
exact-candidate Dawnbreak scanning remains recorded security debt and is not
silently converted into completed scanner evidence by this D8 disposition.

No DW0-D VM run exists or is required by the D plan. This record does not close
the inherited DW0-B/C Wyrmroot/Q35 execution debt, does not claim ring-3 or
syscall functionality, and does not claim completed DW0 milestone acceptance.

## Implemented D scope

- generated object-compatible rights policy with drift and Rust/C parity checks;
- one generic `ObjectRegistry` as the strong-liveness authority;
- move-only creation, handle, internal, and final-release reference tokens;
- caller-local slot/generation `HandleTable` with stale-handle retirement;
- type, compatibility, held-right, and rights-reduction validation;
- syscall-independent close, duplicate, and V1 object-info services;
- typed MemoryObject payload/backing ownership integrated with generic lifetime;
- move-only mapping authorization carrying a strong object pin;
- transactional mapping-lease replacement with pre-retained positive deltas;
- exact logical MemoryObject size reporting and captured mapping ceilings;
- deterministic handle model traces and explicit lifetime linearization tests;
- focused host handle tooling including compile-fail authority-boundary suites.

DW0-E remains responsible for process ownership, synchronization, syscall entry,
copyin/copyout, task objects, and user-pointer status handling. DW0-F remains
responsible for cross-process handle transfer and IPC transactionality.

## Exact D8 commands

The repository was clean before and after the validation sequence. Mutable test
state used project-local
`/home/mike/Documents/Programming/OS-Project/.artifacts/d8-validation/tmp`.

```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host abi
cargo xtask test host handles
cargo xtask test host memory
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
git diff --check
```

Every command above passed. The strengthened handles gate includes explicit
MemoryObject lifetime tests plus `object_registry_ui`, `memory_authority_ui`,
and `physical_ownership_ui` compile-fail/ownership suites.
## Accepted freestanding toolchain

The explicit target/artifact gate used repository identity
`RUST-PHASE0B-TOOLCHAIN-001`:

- Rust commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`;
- target `x86_64-unknown-none`;
- toolchain tree SHA-256
  `5d4275428555a7cd6ae7decc100456fe31cfa4562a7f5eb81a3cf7fe08aa03a5`;
- toolchain config SHA-256
  `63e532b52e6d4c2ef4ed4a003e2aafd7ec11b55e3de5a635c1aea8bfa849f332`;
- root manifest SHA-256
  `553cbfe6eb5cd9976c4f078a3731269f2a2ecd4f3ff5d574ab3813bae8fcf1f1`;
- Clang/LLVM 22.1.8 from `/usr/lib/llvm/22/bin`.

The production plus six-selector artifact oracle was invoked with the accepted
Cargo, rustc, rust-lld, Clang, llvm-nm, llvm-objdump, and llvm-readelf paths.
It performs isolated freestanding builds, production/test-marker separation,
ELF/symbol/disassembly inspection, stack-size accounting, and build-input and
environment identity checks.

```text
cargo test --locked -p deepwyrm-kernel \
  --test x86_64_memory_target_artifact -- \
  --ignored --exact production_and_six_memory_selector_artifacts_are_separated \
  --nocapture
```

The explicit target gate passed.
## D8 artifact identities

Fresh D8 target builds produced:

| Artifact | SHA-256 |
|---|---|
| production | `f411bbf9679d60ad83dedd60f64b01d3a7d621cde9464e01e5afb0db85f4deeb` |
| `memory-mapping` | `0214560c19945d8b897b2c9fcf2c1cb591c2604743fa7ee42b848cbdc04cc5f3` |
| `memory-unmapping` | `cccfecf3c89d0ebbddc86ff3bcebb7c2a5e211412e7ac6f22fde79d7d6b78ab1` |
| `memory-permissions` | `b6e108cdda6740693099789853a47ff022b1241ddd1cac02f0d5a59ce038e599` |
| `memory-invalid-pointer` | `3a471437fecbea3c27fcb1be2549ac551ea91fd6d73c7b379c529a9d96f4354a` |
| `memory-user-kernel-isolation` | `2fd7d77ef7dc91888c7df1b338aa1548d8b893a3423fa5eb51f22e40309fbea0` |
| `memory-shared-memory-object` | `292590a60b4551436f5f7258aca4497bb3cf7719018351d5825df031ec32630b` |

The build-input manifest was
`5206be1137b7034eb7a425b21498176a455b6374f5bbf47c2485045afe24f697`.
The normalized build environment was
`c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`.
Production IST accounting used 2,535 of 16,384 bytes. Selector IST accounting
used 2,631 bytes, leaving 13,753 bytes unused. The selector boot-stack maxima
also retained more than the required 32-KiB spare.

The D8 logs and their SHA-256 manifest are retained under
`OS-Project/.artifacts/d8-validation/`.
## Security disposition

The manually reviewed implementation candidate is
`fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e`. The detailed D7 record is
[`DW0_D7_SECURITY_REVIEW_NOTE.md`](../security/DW0_D7_SECURITY_REVIEW_NOTE.md).
It found no confirmed Critical or High vulnerability and no currently
user-reachable Medium vulnerability. One Low evidence weakness in the focused
handle gate was remediated before the reviewed candidate was frozen.

The final D security summary is
[`DW0_D_SECURITY_REVIEW.md`](../security/DW0_D_SECURITY_REVIEW.md).
D7 residuals R1 and R2 remain explicit Medium-priority architectural review
targets for proper Dawnbreak and DW0-E integration. R3 and R4 are accepted Low
theoretical/engineering risks. None is being represented as a completed
Dawnbreak finding disposition.

## Completion audit and non-claims

The standalone DW0-D execution-plan checklist was audited against this evidence.
D0-D6 implementation and functional requirements are satisfied. D7 is accepted
only under the coordinator-authorized manual soft-review exception. D8 records
that exception rather than marking a specialized scanner as having run.

No D guest selector was invented and no VM request was sent. No Wyrmroot build,
pin update, or consumer evidence was run for D8, so no Wyrmroot revision is
attributed to this phase record.

Inherited DW0-B loader/Q35 execution and DW0-C six-selector VM execution remain
open. DW0-D also makes no claim about process-owned handle synchronization,
ring-3 syscall entry, task lifecycle, IPC transfer, waits/timers, SMP behavior,
primordial launch, or full DW0 release-candidate closure.

With those bounded exceptions, no blocker remains inside the defined DW0-D
host/core scope.
## Standalone execution-plan retirement

The completed coordinator execution plan had SHA-256
`738e9cc92457d34a4e33a0a48bc629b84fcab92b990ff3c0a84b26c7caf6c078` as
`OS-Project/DW0_D_IMPLEMENTATION_PLAN.md`.

Its D0-D8 checklist was audited before retirement. Every implementation,
functional, ABI, memory, tooling, freestanding, documentation, and scope-control
item is supported by the records above. The plan's specialized Daybreak item is
the sole nonliteral checkbox: by coordinator instruction it is dispositioned as
D7 manual **SOFT ACCEPT**, with proper Dawnbreak scanning still pending and
preserved in the D security record.

After that audit and with no other D-scope blocker remaining, the standalone
execution plan was removed from the OS-Project root. Canonical architecture,
D0 contract, validation, and security records remain in the Deepwyrm repository.
