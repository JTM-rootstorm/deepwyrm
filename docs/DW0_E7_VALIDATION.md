# DW0-E7 Validation Record

## Disposition

**E7 CLOSED for the defined freestanding userspace and mandatory VM scope.**

The accepted Deepwyrm revision is `9832707205725d68590ef77990599f150ab65027`,
validated on 2026-08-19 with Wyrmroot
`bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`. The mandatory selector is
`task-syscall-smoke`, canonical guest-test ID 10.

Wyrmroot consumes Deepwyrm ABI/layout policy from its pinned compatible revision
`75d60926f82b703e7d7afbeb77be0a3252f6cd35`. There is no ABI, generated-ABI,
or `kernel/arch/x86_64/layout.toml` delta between that pin and the accepted E7
Deepwyrm revision. A selector-10 kernel rebuilt from `9832707` is byte-identical
to the kernel placed on the accepted VM media.

This record does not close E8. Formal exact-candidate security review still
requires `gpt-daybreak-blue-latest` under workspace policy.

## Deepwyrm implementation checkpoints

- `9d3d15992dcf353d393bb6285426c344257d7ee1` adds the E7 userspace artifact
  contract and canonical selector identities.
- `60d62b826a6f6ff22c2a9e64c54db145975c2381` adds the synthetic task runtime.
- `75d60926f82b703e7d7afbeb77be0a3252f6cd35` adds the accepted-target E7
  artifact oracle.
- `9379680fd1e7d658f666a80cf5f269227203ce2e` splits E7 mapping failures into
  stable model/publisher evidence codes.
- `ddbfe31958176c87e1a2a5a084bf53c3a7e26437` gives the code mapping an RWX
  permission-transition authority while keeping its active setup mapping RW.
- `0fc8c2e8e4b45cab504bffc3f5ab8c14d99dd97e` splits initial user-return
  validation failures into stable E7 evidence codes.
- `f5cd87cdb1f2fc3822d42aabe83ac5bc1c447559` fixes live user page-table walks
  to validate the containing page for arbitrary byte RIP/RSP/usercopy addresses.
- `9832707205725d68590ef77990599f150ab65027` updates the inherited C3 source
  contract so memory selectors remain proven deferred after E7 task selectors
  join the same pre-activation branch.

All E7 Deepwyrm commits were created unsigned and contain the required
`Co-authored-by: Codex <codex@openai.com>` trailer. No push is part of E7.

## Wyrmroot integration checkpoints

The E7 handoff required a bounded Wyrmroot detour rather than a general WYR
image milestone:

- `14913d772ce090ea987fae24d1a3518606cb62f6` repins the Deepwyrm ABI consumer
  and build provenance to the E7-compatible revision.
- `4514e0dd3e1f92e3b39638943f2a82758c67b13c` reports bounded pre-EBS failure
  stages without adding post-EBS firmware output authority.
- `ae900e61d7ae81e8254e9c25d5009a64ee745aa8` normalizes canonical `/` paths at
  the low-level UEFI filesystem boundary.
- `bd2f0629206de3a47f5a20cb0842a4e76ec88aaf` accepts UEFI configuration-table
  RSDP pointers without applying the legacy BIOS 16-byte search-alignment rule.

Wyrmroot's complete accepted UEFI loader gate passed after those fixes. The
accepted loader used for the E7 image has SHA-256
`a0489550134b3ddfaf449bd3914b6485c3dba4989ef91b9be9ac51f4217dd2e6`.

## Freestanding userspace artifact

The Deepwyrm-owned synthetic userspace is an ELF64 x86_64 static/freestanding
`ET_EXEC` image with entry `0x40000000`, one RX `PT_LOAD`, no `PT_INTERP`, no
host libc dependency, and no writable-executable segment. Its SHA-256 is:

```text
688a20f6e15e5350a99b96a6969c552e6dabf8cd4e15c4dbddb6d2fbdffcbe29
```

The image uses the generated `dw_syscall6` veneer. `_start` contains no copied
`syscall` convention; the generated veneer owns the artifact's single `syscall`
instruction.

The mandatory userspace flow is:

1. enter a scheduled synthetic Thread at CPL3;
2. call `abi_get_info` into writable user memory;
3. return through the native syscall/IRETQ path to the same CPL3 program;
4. validate the returned ABI information;
5. require an unknown syscall to return `NOT_SUPPORTED`; and
6. call `process_exit(0)`, retire scheduler/task resources, finalize the task
   hierarchy, and emit PASS.

This proves entry and return rather than only proving that CPL3 was reached.

## Accepted-toolchain target artifact gate

The explicit E7 artifact oracle passed on the accepted Rust request
`RUST-PHASE0B-TOOLCHAIN-001`, Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, with LLVM/Clang 22.1.8.

```text
cargo test --locked -p deepwyrm-kernel \
  --test x86_64_memory_target_artifact -- \
  --ignored --exact e7_task_smoke_artifact_is_freestanding_and_separated \
  --nocapture
```

Final oracle identities and bounds:

- userspace: `688a20f6e15e5350a99b96a6969c552e6dabf8cd4e15c4dbddb6d2fbdffcbe29`;
- selector-10 kernel: `3603cfd638928c679d0b6b2c9ead47319d5d75420a952e297d4f8fec2d5affd7`;
- bootstrap stack bound: 91,168 / 131,072 bytes, 39,904 bytes spare;
- Thread syscall/exit bound: 11,624 / 65,536 bytes, 53,912 bytes spare;
- build-input manifest: `96a93a1a317f7fa553a78c559d181e97f865833539d0246d6a18dc03b51e4372`;
- normalized build environment:
  `c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`.

The oracle independently rebuilds production and rejects E7 runtime/blob/test
symbols there. It also enforces the current forbidden FP/SIMD instruction
policy and the inspected userspace ELF shape.

Log: `OS-Project/.artifacts/e7-validation/final-target/accepted-artifact.log`.

## Full host validation

The following passed against Deepwyrm `9832707205725d68590ef77990599f150ab65027`:

```text
cargo xtask test host tasks
cargo xtask abi check
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
git diff --check
```

The workspace run includes 279 kernel unit tests, the object/memory/task
compile-fail suites, all seven inherited C3 memory guest-contract tests, and all
11 x86 syscall-contract tests. The two explicit target-artifact tests remain
ignored during ordinary host execution and are exercised separately by their
accepted-toolchain gates.

Log: `OS-Project/.artifacts/e7-validation/final-host/full-validation.log`.

## Canonical designated-VM gate

Final acceptance used the workspace-designated system-libvirt domain
`OS-Project` on `qemu:///system`, UUID
`33005e22-d7c2-4b13-b1ac-b82eda95e584`. The coordinator held the nonblocking
exclusive `/tmp/os-project-vm.lock` for preflight, transient configuration,
execution, evidence capture, shutdown, restoration, and final-state checks.
The accepted transient profile was q35 (`pc-q35-10.2`), 1 vCPU, 1024 MiB,
TCG/QEMU, raw non-Secure-Boot OVMF, two project-local read-only virtio disks,
COM1, no NIC, and no host filesystem share. The localhost-only serial TCP
transport was a COM1 capture channel, not guest networking.

Preflight identities for the accepted run were retained in
`OS-Project/.artifacts/e7-validation/libvirt-final/preflight6-identities.sha256`:

| Input | SHA-256 |
|---|---|
| ESP | `bb0b81a470ea5a75bb5d36c1e2d6c8a82b0872beff2ea3895da6f058807c7d4c` |
| disposable system disk | `8cf73f8d367b56e81afc7e25dba3226168f8f05790ccf7e846de51e931478133` |
| Deepwyrm kernel | `3603cfd638928c679d0b6b2c9ead47319d5d75420a952e297d4f8fec2d5affd7` |
| OVMF code | `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a` |
| initial disposable NVRAM | `250139dfd26c4f76f7699f163ab815bf3f2abb8db75208ef170e3bd3aae6eff5` |

The transient libvirt definition is retained at
`OS-Project/.artifacts/e7-validation/libvirt-final/e7-domain-minimal3.xml`,
SHA-256 `42cdf04af0fbe503e7d851f86785a778eef5e9005031e8378f07b7450a2194b8`.

The real Wyrmroot path reported:

```text
wyrmroot-loader: UEFI adapter online
wyrmroot-loader: final UEFI memory map / ExitBootServices
wyrmroot-loader: ExitBootServices complete
wyrmroot-loader: entering Deepwyrm
DWTEST1|01|0000000A|00000000|5C9DAA15
```

That record is selector 10, status PASS, detail 0. The domain shut itself off
with libvirt reason `shutdown` seven polling ticks after resume. The serial
capture SHA-256 is
`1096aca3b5f3f7f99fb983ba28835c7541e175c559cc7d0a381148c50d720b47`.
The final disposable NVRAM SHA-256 is
`100579c8a1b895e09afd7f2d1b06d8ea5342f6a20abc5ffa09a7fb92c11bf365`.

Canonical serial evidence:
`OS-Project/.artifacts/e7-validation/libvirt-final/serial-final.log`.
Final artifact identities:
`OS-Project/.artifacts/e7-validation/libvirt-final/final-run-artifacts.sha256`.

Earlier direct-QEMU and richer-libvirt attempts were debugging evidence only,
not acceptance. The final gate above is the designated-domain acceptance run.

## VM restoration

Before releasing the VM lease, the coordinator restored the original inactive
libvirt definition, SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.
The final domain state was `shut off`, 1 vCPU, 2 GiB RAM, autostart disabled,
and the originally absent external
`/var/lib/libvirt/qemu/nvram/OS-Project_VARS.qcow2` was absent again.

The root-owned primary disk `/var/lib/libvirt/images/OSProj.qcow2` was not
attached to the accepted E7 run. The final gate used only project-local test
media, so no primary-disk guest writes were part of E7 acceptance.

## Bugs removed while reaching the gate

1. **Code-page permission-transition authority:** E7 initially mapped the code
   page with an RW authorization ceiling, so a later RW -> RX transition was
   correctly rejected even though the MemoryObject ceiling was RWX. E7 now
   captures RWX transition authority while the active mapping is RW during copy
   and RX afterward; no active W+X mapping is introduced.
2. **Live byte-address page walks:** `LiveProcessAddressSpace::walk_leaf()` fed
   arbitrary RIP/RSP/usercopy byte addresses to the exact-page constructor,
   rejecting valid non-page-aligned addresses. `VirtualPage::containing()` now
   preserves canonical-address validation while walking the containing page.
3. **UEFI path conversion:** Wyrmroot passed canonical `/EFI/...` strings
   directly to low-level `EFI_FILE_PROTOCOL.Open()`. The UEFI boundary now
   converts them to firmware path separators without changing Wyrmroot's
   canonical path convention.
4. **UEFI RSDP pointer policy:** Wyrmroot applied the legacy IA-PC 16-byte RSDP
   search alignment to a pointer supplied directly by the UEFI configuration
   table. The UEFI path now requires nonzero/bounded address arithmetic and
   retains signature, length, revision, and checksum validation instead.

## Non-claims and next gate

Selectors 11 (`task-syscall-sanitize`) and 12 (`task-user-exception`) remain
reserved canonical E test identities, but the E7 plan names selector 10 as the
mandatory phase gate. E7 closure therefore does not claim those optional
follow-on guest scenarios have been accepted.

E7 also does not claim E8 Daybreak security acceptance, DW0-F IPC/waits/timers,
SMP acceptance, physical-hardware acceptance, a general Wyrmroot image command,
or full DW0 completion.

With those boundaries, no blocker remains inside the defined E7 scope. E8 is
the next DW0-E gate.
