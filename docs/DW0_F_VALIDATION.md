# DW0-F Final Validation and Phase Disposition

## Status

**DW0-F is FULL ACCEPTED for progression to DW0-G.**

The exact Daybreak-reviewed Deepwyrm product candidate is `96fe554c0e4cb21335df4bbf5ebd2de1f9df21c5`. Final F14 evidence ran from clean Deepwyrm descendant `e599d5b75346d80075fa097cce47a7974888b9fa`, paired with clean Wyrmroot `edc1071f78f4418c05e5bd0762b1c3fb760df094`.

The descendant changes after the security candidate are limited to the durable F security records, repository artifact-ignore hygiene, and rustfmt-only host xtask test formatting. They do not modify `kernel/**`, `abi/**`, or the generated Deepwyrm ABI. A fresh accepted-toolchain oracle at `e599d5b` reproduced the exact selector-13 machine code reviewed at F13, binding the designated-VM evidence below to the same product bytes.

This record closes DW0-F14 and the DW0-F milestone. It does not establish DW0-G primordial ELF/bootstrap launch, DW0-H SMP/per-CPU correctness, i386 support, physical-hardware acceptance, or full DW0 release acceptance.

## F14 gate candidate and retained evidence

All mutable host build/test state was directed to project-local task-owned paths. Deepwyrm and Wyrmroot were clean before the paired VM run. Host logs are under `deepwyrm/.artifacts/f14-validation/`; coordinator VM evidence is under workspace `.artifacts/f14-validation/vm-run/`.

The project-local evidence manifest is `.artifacts/f14-validation/F14_EVIDENCE_MANIFEST.txt`, SHA-256 `ea10a6493a397aa48c6f195df963b3183384cf2079363fcdf7f4a76dd1587d07`.

Its standard hash list has SHA-256 `07927cdc511030ac98b9c9c8f936f270ab4fb1399f553fbefd561d6f2e2dbc28`; `sha256sum -c` reproduced every retained entry and its verification log has SHA-256 `57372887381d2e825b3c6bbc5e56379878b5e70e408b3ff134c9bb687a41a9cf`.

The final audited root `DW0_F_IMPLEMENTATION_PLAN.md` has SHA-256 `2b2de0a79efc8087b45693da8a223bf8e956dbeaf2a4fd076dda31d262157b26`. Every F0-F14 checklist item was checked against durable repository/evidence records before standalone-plan retirement.

## Required host and ABI gates

The final ordered host gate ran on 2026-08-21 from clean Deepwyrm `e599d5b`. The required formatter, ABI, focused host, workspace, Clippy, and rustdoc commands all passed.
```text
cargo fmt --all -- --check
cargo xtask abi check
cargo xtask test host handles
cargo xtask test host memory
cargo xtask test host tasks
cargo xtask test host ipc
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

The full workspace run included the kernel library suite with **463 passed, 0 failed**, plus architecture, syscall, exception, ownership/UI, artifact, model, ABI-generator, xtask, and command-surface suites. The three deliberately ignored accepted-target tests remain governed by their explicit gate policy; the implemented-F accepted-target test was run separately below. Clippy and rustdoc passed with warnings denied.

The formatter failure found by the initial F14 review was rustfmt drift in the F13 selector-classification host test. Commit `e599d5b75346d80075fa097cce47a7974888b9fa` applies that formatting and teaches Deepwyrm to ignore the `.artifacts/` and `.tmp/` roots already used for project-local phase evidence/build state. It changes no product machine code.

## Accepted-toolchain artifact and separation gate

The explicit `implemented_f_selector_artifacts_are_freestanding_and_separated` gate passed using accepted Rust 1.97.1 request `RUST-PHASE0B-TOOLCHAIN-001`, Rust commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`, and the repository-pinned LLVM/Clang 22.1.8 tools.

Fresh F14 identities were:

- production kernel: `a57e67ede53ea6c7b14cf968f4ef6bd2fedbd446640e2f5a598ab491b21363f3`;
- selector-13 `ipc-blocking-smoke` kernel: `db6cd496c9253f63346c54c58aa919d1e49aa3db4d34d880e1a88c89a9efee37`;
- selector-13 user ELF: `60c32bd4b3b2d04baccd07a4d7f654fcdf6a29a8ad145bffd349f375b16d1b3f`;
- selector-16 `atomic-wait-wake` kernel: `8aed48d090185e3b9effe2e5ca53870116dbb5c1db5069b1d41e6a4b068348ae`;
- selector-16 user ELF: `0e29b37079cfabf931c0b9762d16d075280db8a8812fee6b2d67d47b1c65deda`;
- build-input manifest: `660c6ffb2754ed76073f66f70e5932b9cbc70468e1c15f3a8e440dfdc00a61e9`;
- normalized accepted environment: `de9cf952e07da0d8d913e9a6635d711e613e51104435a9b3082f196916e96c8e`.

The oracle re-proved static/no-libc userspace, generated native syscall-veneer ownership, no `PT_INTERP`, no W+X user segment, production/test separation, selector independence, no debug-exit/test-marker leakage into production, accepted tool identities, and bounded stack/context carriers.
The selector-13 kernel hash exactly matches the F13 Daybreak record, closing the machine-code identity bridge from `96fe554c` to the clean F14 evidence descendant.

## Exact paired Wyrmroot/Deepwyrm VM gate

The main/root coordinator alone operated designated domain `OS-Project` on `qemu:///system` under `/tmp/os-project-vm.lock`. The run used q35 `pc-q35-10.2`, one vCPU, non-Secure-Boot OVMF/UEFI, COM1 loopback capture, no guest network dependency, no host filesystem share, project-local read-only ESP/system media, and the existing debug-exit test completion device.

The exact clean repository pair was:

- Deepwyrm F14 evidence descendant: `e599d5b75346d80075fa097cce47a7974888b9fa`;
- Wyrmroot: `edc1071f78f4418c05e5bd0762b1c3fb760df094`.

Wyrmroot still consumes the F12 Deepwyrm ABI/layout pin because F13/F14 do not alter consumed ABI or layout. Its current loader is byte-identical to the accepted F12 loader.

Executed media identities were:

- Wyrmroot loader EFI: `4afac804d519fcbd9e41db25614e3d274b83e5815494d466a791b33d276191dc`;
- selector-13 Deepwyrm kernel: `db6cd496c9253f63346c54c58aa919d1e49aa3db4d34d880e1a88c89a9efee37`;
- ESP image: `312259cc7aa3b27339aa4fe3135768cf8982b0434f459fcbfa0e0e48ff5e6233`;
- disposable system image: `8cf73f8d367b56e81afc7e25dba3226168f8f05790ccf7e846de51e931478133`;
- OVMF code: `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a`;
- initial request-local OVMF vars: `7f9d6cd7d8fb4a50f278e4d62692b0738bc106dab3e2753bcfc3cc64cb48a8e9`;
- harness request: `42a36e13ceea9ac25addf0ce7dbbad42c69e9eedf7e9a6eedf2eee7b2a6e29b5`.

The guest emitted exactly one terminal record:

```text
DWTEST1|01|0000000D|00000000|1AD68686
```

The result classifier reported `PASS`, selector `ipc-blocking-smoke`, test ID 13, detail zero, and fixed test-contract debug-exit status 33.
The lifecycle was `Resumed Unpaused`, `Started Booted`, `Shutdown Finished after guest request`, then `Stopped Shutdown`.

Canonical VM evidence hashes include:

- serial: `e78a1b9d5a8f4148d762327bbf88997b519399c874b085c3f0423737e37a0a78`;
- lifecycle: `db9a203f376708709a7cbb31b9ea9a23a8577d6beb75da7b20552be8f87ccdb4`;
- classified result: `d442c55484fbac42bb08df20f4b12d1d4dd6eef158e8c7164b36ad5453afeb0e`;
- effective test-domain XML: `4aae3e6e78a63ad9c8f27b163285b902523abddd7e7eda58ab1eeda754c69b5b`.

The run did not mutate the designated primary disk. Preflight original, immediate restored, and final-audit inactive domain XML are byte-identical at SHA-256 `a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.

Final audit found the exact designated UUID, domain shut off, autostart disabled, `Managed save: no`, and original `/var/lib/libvirt/images/OSProj.qcow2` primary disk restored. Final `dominfo` and block-device-list hashes are `faf945fd52dfa9e65ad5491110f9689620b32d13ee8f8f077155a28929445a49` and `d3bf526d3c10d6b3e30ff7f996714384e2820be46e42a3967a3dcf717695c444`.

The request-local OVMF-VARS file was allowed to change through ordinary guest firmware execution. Read-only ESP, system image, and kernel identities remained unchanged. No host-side primary-image rewrite, mount, package installation, or network delivery was used.

## F13 exact Daybreak disposition

`security/DW0_F_SECURITY_REVIEW.md` records a formal **PASS** for the exact F13 product candidate. All substantive security lanes used exact model `gpt-daybreak-blue-latest` on 2026-08-21.

Two Medium product defects were found, fixed, covered by regressions, and re-reviewed against the exact resulting candidate:

1. F13-01 reserved E selectors were incorrectly advertised as runnable;
2. F13-02 current exception termination could reclaim its physically active kernel stack before divergent handoff.

The final product-security disposition is no Critical, High, or unresolved Medium finding. One Wyrmroot metadata path-read Low remains explicitly accepted as defense-in-depth hardening debt.

F13 independently rechecked E8-F1 SWAPGS ordering and found no regression. The transient E selector finding reopened and then reclosed the affected historical E surface.
The D/E historical Daybreak register remains preserved. Their former soft-accept debts were closed by the S5 remediation record and are not silently reintroduced by F14; future regressions or DW0-H SMP activation can reopen specific recorded surfaces under the existing rules.

## Required F outcome disposition

The F0 contract, generated ABI, scheduler blocking/resume path, monotonic time, Channel queues and atomic transfer, generic waits, Event/Timer semantics, shared-memory atomic wait/wake, and public `process_create` transaction all have host/model evidence.

Selector 13 supplies the required real CPL3 integration proof through the real Wyrmroot loader for blocking, context switching, wake and resume, reduced-right handle transfer, a finite deadline, atomic wait/wake, and CREATED-child process creation with clean terminal teardown.

The security row is a hard PASS rather than a soft exception, so the strongest permitted phase statement is **DW0-F FULL ACCEPTED for progression to DW0-G**.

## Explicit non-claims and next phase

The selector-13 child remains CREATED and is inspected/terminated without a general ELF loader or primordial process start. F therefore does not claim the DW0-G bootstrap path.

The reviewed scheduler/reaper/GS model remains single-BSP; DW0-H must perform its required SMP/per-CPU re-review before SMP activation. VM evidence is not physical-hardware evidence and says nothing about future i386 compatibility.

The next implementation phase is **DW0-G — primordial ELF and bootstrap launch**. This F14 record closes F only; it does not declare the complete DW0 milestone finished.
