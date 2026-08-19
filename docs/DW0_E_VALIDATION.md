# DW0-E Validation Record

## Disposition

**DW0-E is SOFT ACCEPTED for progression to DW0-F. Formal E security closure
remains pending the required `gpt-daybreak-blue-latest` exact-candidate review.**

E9 validation was run on 2026-08-19 against clean Deepwyrm revision
`e8394d6e6d160d9e4d04769943c2500cfd562c10`, paired where guest behavior is
relevant with unchanged Wyrmroot
`bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`.

The E behavior/security-remediation candidate is
`579e12074e1fe9ec89507e033381fed66676c12c`. Revision `e8394d6` is a
documentation-only descendant: `kernel`, ABI/schema, generated material, tools,
and workspace build inputs have no delta from `579e120`.

By coordinator instruction, E follows the same exception already recorded for
DW0-D: functional, architecture, target-artifact, and VM evidence may close the
phase for forward development while formal Daybreak scanning remains explicit
security debt. This record does not claim that Daybreak ran or that E has a hard
security PASS.

DW0-D also retains its own formal Daybreak debt. Both D and E must be revisited
before final DW0 security closure.
## Implemented E scope

- root `TaskGroup`, `Process`, and `Thread` objects with typed payload/finalizer
  integration under generic `ObjectRegistry` liveness;
- one process-local `HandleTable` per Process with preserved D rights semantics;
- typed AddressRegion object/handle integration and process address-space pins;
- cooperative scheduler/run queue and bounded per-thread kernel stacks;
- x86_64 ring-3 selectors, TSS `RSP0`, SYSCALL MSRs, supervisor entry stack,
  validated IRETQ return, and structured CPL3 exception capture;
- generated numeric syscall dispatch and E task syscall adapters;
- pinned production usercopy with output preflight before business mutation;
- task start, exit, explicit termination, task-group teardown, and structured
  termination metadata behind `INSPECT`;
- deterministic unknown/unimplemented syscall `NOT_SUPPORTED` behavior;
- no-libc synthetic userspace using the generated native syscall veneer; and
- canonical Wyrmroot -> Deepwyrm -> CPL3 -> syscall -> CPL3 -> process-exit VM
  evidence through `task-syscall-smoke`.

`process_create`, Channels, Events, Timers, waits, atomic wait/wake, and blocking
scheduler integration remain DW0-F work. General primordial ELF/bootstrap launch
remains DW0-G work. SMP activation remains DW0-H work.

## Fresh E9 host validation

Mutable host-test state was kept under
`OS-Project/.artifacts/e9-validation/`. The tree was clean before the sequence.
The accepted project Rust toolchain ran the following host gates:

```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
git diff --check
clean-tree assertion
```

Every gate passed against `e8394d6`. The complete log is
`OS-Project/.artifacts/e9-validation/logs/full-host.log`, SHA-256
`5ca4633a26f5b25271c87e005f65aa37f05f7573026c3f9d108974b367836db6`.

The workspace run includes the focused object/memory/task authority suites,
compile-fail boundaries, x86 entry/syscall/exception source contracts, and the
E task lifecycle/scheduler/usercopy model coverage.

## Accepted freestanding toolchain and artifact gate

Target evidence used accepted request `RUST-PHASE0B-TOOLCHAIN-001`, Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, target
`x86_64-unknown-none`, and LLVM/Clang 22.1.8.
The exact E selector oracle passed at the E9 candidate:

```text
cargo test --locked -p deepwyrm-kernel \
  --test x86_64_memory_target_artifact -- \
  --ignored --exact e7_task_smoke_artifact_is_freestanding_and_separated \
  --nocapture
```

Fresh E9 identities:

- synthetic userspace SHA-256
  `65becbc03deee89b9eff7bd61f2baa6646228ce28f4e0abd48846d1166acfc0d`;
- selector-10 kernel SHA-256
  `934782a1fe76e394312a0b6bba9bf7892bd4e9db3684cf408eba13dc00d34b89`;
- build-input manifest
  `48370784b2694aa1065baa16a1a484acb20d82420d4273b818b82e132f255a04`;
- normalized environment
  `c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`;
- bootstrap stack 91,168 / 131,072 bytes, 39,904 bytes spare; and
- Thread syscall/exit stack 11,624 / 65,536 bytes, 53,912 bytes spare.

The oracle inspects production/test separation, ELF/symbol/disassembly shape,
forbidden FP/SIMD use under the current policy, userspace static/no-libc shape,
segment permissions, and generated syscall-veneer ownership.

Target log: `OS-Project/.artifacts/e9-validation/logs/target-artifact.log`,
SHA-256 `3ba84f96ed82d3dfeda06a3e7897e2893093d018534ad92cf2c2e564c9611efc`.
## Canonical VM evidence by reproduced artifact identity

The E9 oracle reproduced the exact selector-10 kernel bytes used by the
post-remediation E8 designated-VM run. E9 therefore reuses that canonical run
by artifact identity, not merely by source-tree assumption. No second VM boot
was required for documentation-only revision `e8394d6`.

The run used system libvirt domain `OS-Project` on `qemu:///system`, UUID
`33005e22-d7c2-4b13-b1ac-b82eda95e584`, under the exclusive
`/tmp/os-project-vm.lock` lease. The transient profile was q35, 1 vCPU,
1024 MiB, OVMF, COM1 capture, no NIC, no host filesystem share, read-only
project test media, and selector `task-syscall-smoke` (ID 10).

Relevant identities:

- Wyrmroot revision `bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`;
- compatible Deepwyrm ABI/layout pin
  `75d60926f82b703e7d7afbeb77be0a3252f6cd35`;
- E8/E9 selector kernel
  `934782a1fe76e394312a0b6bba9bf7892bd4e9db3684cf408eba13dc00d34b89`;
- E8 ESP `44615b5f4594c2934f18e14ab5fc396e757eba446c1a4e312dd18c3afc273deb`;
- Wyrmroot system disk
  `8cf73f8d367b56e81afc7e25dba3226168f8f05790ccf7e846de51e931478133`;
- OVMF code
  `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a`.

The synthetic userspace deliberately reloads GS selector `0x2b` before its
first syscall, carrying the E8 SWAPGS regression through the real VM path.
Canonical terminal output was:

```text
wyrmroot-loader: UEFI adapter online
wyrmroot-loader: final UEFI memory map / ExitBootServices
wyrmroot-loader: ExitBootServices complete
wyrmroot-loader: entering Deepwyrm
DWTEST1|01|0000000A|00000000|5C9DAA15
```

Serial SHA-256:
`1096aca3b5f3f7f99fb983ba28835c7541e175c559cc7d0a381148c50d720b47`.
The domain self-shut down with reason `shutdown`.

The original inactive VM XML was restored byte-for-byte at SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`;
autostart remained disabled, the original external NVRAM remained absent, and
the primary `OSProj.qcow2` inode/size/mtime tuple was unchanged.

## Security disposition

The provisional E8 review was performed by GPT-5.6 Sol, not Daybreak. It found
one confirmed High denial-of-service defect in the syscall GS transition.
Commit `579e120` fixed it by establishing the SWAPGS transition before the first
GS-relative access and pairing the user-return paths; selector 10 now carries a
hostile CPL3 GS reload regression through the accepted target and VM gates.

No unresolved Critical/High finding is known from that provisional review.
Residual E8-R1 through E8-R5 remain recorded in
`../security/DW0_E8_SOFT_SECURITY_REVIEW_NOTE.md` and are summarized in the
canonical E security record.
Formal `gpt-daybreak-blue-latest` review remains mandatory before final DW0
security closure. By coordinator instruction, that pending review does not block
starting DW0-F. Any later Daybreak remediation affecting E must receive targeted
host/target/VM revalidation for the changed surface.

## Reserved negative selectors and non-claims

Selectors 11 (`task-syscall-sanitize`) and 12 (`task-user-exception`) remain
canonical reserved identities, but they do not yet have accepted guest bodies.
The E7 plan explicitly made selector 10 the mandatory VM gate and described 11
and 12 as follow-on scenarios.

E9 does not fabricate PASS evidence for them. Selector 10 now includes the
hostile GS reload regression, while hostile return state, pointer validation,
and CPL3 exception behavior remain covered by host/model/source-contract tests.
A future Daybreak/hardening pass may promote selectors 11/12 into real VM cases.

This record does not claim DW0-F IPC/waits/timers, DW0-G primordial ELF launch,
DW0-H SMP acceptance, physical-hardware acceptance, or completed DW0 milestone
security closure. It also preserves the existing DW0-D formal Daybreak debt.

## Standalone E plan retirement

The coordinator execution plan at `OS-Project/DW0_E_IMPLEMENTATION_PLAN.md` has
SHA-256
`8d4d1216dd5bf8611bfe8250cff52f83dfdb85f82c3f4a290d0d71ccd4b752c6`.

Its functional E0-E7 requirements and E9 evidence requirements are satisfied
within the bounded claims above. E8's exact Daybreak item is intentionally
nonliteral under the coordinator-authorized soft-accept exception, and the
reserved negative selectors remain explicit follow-on evidence rather than
invented executions. The plan may therefore be retired after this durable E9
record is committed, while the security debt survives in repository records.

Project-local evidence identities are also frozen in
`OS-Project/.artifacts/e9-validation/E9_EVIDENCE_MANIFEST.txt`, SHA-256
`311fb2e5aa9c2c8d7922b891dac2d8d33b92ac248437b3742d98599eaf2ece05`.
