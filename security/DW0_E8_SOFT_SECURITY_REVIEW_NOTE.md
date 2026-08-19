# DW0-E8 Provisional Security Review Note

## Review state

**Disposition: SOFT ACCEPT for continued DW0-E development, pending the required
`gpt-daybreak-blue-latest` exact-candidate review. Formal E8 remains OPEN.**

This provisional review covers Deepwyrm code candidate
`579e12074e1fe9ec89507e033381fed66676c12c` on 2026-08-19, paired for the
mandatory guest regression with unchanged Wyrmroot
`bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`.

Review model: **GPT-5.6 Sol**, extended manual/tool-assisted reasoning. This is
explicitly not Daybreak Blue, Dawnbreak, or an equivalent-model claim. The
coordinator authorized only a soft/provisional result until the proper model is
available. No E8 CLOSED/PASS claim is made by this note.

The reviewed candidate is the remediation descendant of E7 documentation HEAD
`11dbd3098548c2a3792dea30508c576242853a3f`. The security remediation itself is
commit `579e12074e1fe9ec89507e033381fed66676c12c`; this note is intended to be a
documentation-only descendant of that exact code candidate.

## Review method and tooling limits

The review walked the E implementation from the previously reviewed D baseline
through task ownership, scheduling, x86_64 CPL3 transition, native syscall,
usercopy, task teardown, E7 synthetic runtime, and target/VM evidence.
The E8 plan threat list was traced explicitly: SYSCALL MSRs/entry/IRETQ and GS
state; hostile entry registers; CPL3 exception normalization; pinned usercopy;
numeric dispatch/fallthrough; process-local handles and rights; task hierarchy
and recursive termination; scheduler/context/stack ownership; typed finalizers;
termination metadata disclosure; MemoryObject/AddressRegion teardown;
lock/reentrancy boundaries; ambient-POSIX shortcuts; and test-only leakage.

Production `unsafe`, raw pointer/function-pointer publication, assembly, panic /
fail-stop paths, integer/range arithmetic, atomic orderings, and unexpected
POSIX-like authority vocabulary were also inventoried. The D7-R1/R2 integration
hazards were rechecked against the E typed finalizer/construction path.

`cargo tree --workspace --edges normal,build` shows no third-party normal/build
crate dependency in the reviewed runtime/build stack beyond workspace crates.
The optional local analyzers `cargo-audit`, `cargo-deny`, `cargo-geiger`, Miri,
Semgrep, and CodeQL are not installed and did not run. No claim is made that
manual review substitutes for those tools or for Daybreak.

An advisory `clippy::arithmetic_side_effects` pass was used to focus review on
user-controlled lengths and counters. Memory-object rounding/allocation and
AddressRegion range construction use checked arithmetic and validation before
trusted-model helpers; no wrap-to-small allocation or wraparound user mapping
primitive was confirmed.

## Confirmed high-severity finding and remediation

### E8-F1 - CPL3 could replace the GS base consumed before the syscall stack switch

**Severity before remediation: High (unprivileged kernel-fatal denial of service).**
Before `579e120`, E4 programmed `IA32_GS_BASE` with the supervisor-only syscall
entry record and left `IA32_KERNEL_GS_BASE` zero. `dw_x86_64_syscall_entry`
then wrote `%rsp`, `%rcx`, and `%r11` through `%gs:` and loaded the trusted
kernel stack through `%gs:` before any stack switch.

Disabling FSGSBASE did not make that active GS base immutable to CPL3. A bounded
host architecture probe retained under `.artifacts/e8-security/gs-probe/`
first installed a nonzero GS base, then loaded the E contract's DPL3 data
selector `0x2b` into GS. The observed effective base changed from `0x12345000`
to zero. Deepwyrm's `0x2b` descriptor likewise has base zero.

A malicious E userspace context could therefore reload GS immediately before
SYSCALL. The first supervisor `%gs:` scratch access would resolve against the
user-selected zero base. Page zero is forbidden/unmapped by the locked memory
contract, so the resulting CPL0 fault follows the kernel-fatal exception path.
No privilege escalation was demonstrated; the confirmed present impact was a
reliable unprivileged kernel denial of service.

Commit `579e120` remediates this by making unconditional `SWAPGS` the first
instruction of `dw_x86_64_syscall_entry`, before any GS-relative access or
user-RSP memory use. The syscall return and initial CPL3 IRET helpers each pair
that transition with one `SWAPGS` immediately before `IRETQ`.

The installed MSR state remains `GS_BASE = entry_state_base` and
`KERNEL_GS_BASE = 0` while boot code is resident. The first IRET moves the
kernel entry-state base behind `IA32_KERNEL_GS_BASE`; later SYSCALL entry swaps
it active before consuming `%gs`. The current exception assembly never consumes
GS, while NMI/#DF/#MC retain dedicated IST stacks.
Regression coverage is deliberately hostile rather than source-only:
`kernel/tests/userspace/e7_task_smoke.S` now executes `movw $0x2b, %gs`
immediately before its first generated native syscall. Source-contract tests
require entry `SWAPGS` before the first GS access, balanced SWAPGS/IRET pairs,
and no SYSRET. The accepted-toolchain artifact oracle and designated VM both
passed with this hostile reload present.

**E8-F1 disposition: FIXED at `579e120`; no unresolved Critical/High finding is
known from this provisional review.** The required Daybreak re-review must
independently revisit the complete transition diff and this remediation.

## Other confirmed properties

- IRETQ return validates lower-canonical nonzero user RIP/RSP, exact selectors,
  sanitized RFLAGS, live mapping permissions, and the current binding generation.
- RCX/R11 are treated as hostile entry state; normal syscall return does not
  expose kernel pointers and explicitly reconstructs approved user state.
- Usercopy preflights and pins the complete range before mutation/copyout, while
  live x86 page-table mutation reserves the affected virtual interval before
  applying the journaled write batch.
- Every staged x86 mapping mutation contributes its changed page to the journal
  invalidation set; the current reservation may over-block gaps but does not
  under-cover changed pages.
- Numeric syscall decoding is generated/schema-owned; unknown and post-E calls
  remain `NOT_SUPPORTED` instead of falling into adjacent operations.
- Process-local HandleTables permit raw-handle collisions without cross-process
  authority confusion, and task information/control remains rights-gated.
- Process/group termination is iterative/bounded, scheduler retirement precedes
  execution-resource reclaim, and generation-protected IDs reject stale reuse.
- D7-R1/R2 are mechanically strengthened in E: payload-bearing final releases
  route through typed cleanup proofs, and production MemoryObject binding
  consumes construction before first publication. Compile-fail tests reject the
  prior generic-finalization bypass shape.
- Task termination metadata is surfaced through the existing `INSPECT`-gated
  object-info path rather than an ambient PID/process-information channel.
- AddressRegion/MemoryObject teardown rejects/defers reclamation while mapping or
  runtime pins remain; the failure mode is liveness/resource retention rather
  than reuse of still-referenced backing.
- No production `kill(pid)`, UID/GID-root, signal, ptrace, file-descriptor, or
  filesystem-exec ambient authority shortcut was found in the E task/syscall
  implementation.
- E7 CPL3/test completion symbols remain feature/selector-owned and are rejected
  from the production target by the accepted-toolchain artifact oracle.

## Residual review concerns pending Daybreak and later phases

These are not confirmed current user-reachable Critical/High vulnerabilities.
They are boundaries that should be targeted by the required Daybreak pass and
by the phase that makes the deferred behavior real.

### E8-R1 - general exception/reschedule paths must normalize GS state

Current ordinary CPL3 exceptions are terminal/non-returning, and the current
exception assembly does not consume GS. `enter_validated_user()` also validates
the exact live GS/KERNEL_GS MSR plan before its IRET helper. A future nonterminal
exception path or process-fatal handler that schedules a different userspace
thread must first establish the same kernel/user GS transition invariant rather
than calling the IRET helper from an arbitrary GS state.

**Target:** first general production exception-reschedule path; re-review again
for SMP/NMI nesting if that path becomes nonterminal.
### E8-R2 - one-shot runtime pointer lifetime is caller-proven

The E5 target runtime binding stores an opaque raw context pointer plus typed
handler in a one-shot atomic publication. Its unsafe contract requires the
context to remain stationary, live, and exclusively owned for all later CPL3
syscalls. E7 satisfies that with one stationary runtime, but a future general
runtime should replace this convention with a mechanically stable owner/binding.

**Priority:** Medium architectural hardening before general Wyrmroot process
runtime integration; no current userspace primitive can replace the binding.

### E8-R3 - address-space retirement remains a coordination responsibility

Mapping/runtime pins fail safe against early reclamation, but general task
teardown must still coordinate unmap/root retirement before final address-space
release. Failure to do so is expected to strand liveness/resources rather than
create a use-after-free in the reviewed paths.

**Priority:** Medium liveness/integration concern for general process teardown.

### E8-R4 - bounded generation exhaustion is fail-closed availability debt

Public capability generations retire on exhaustion and current internal
mapping-lease tests skip exhausted slots when later capacity exists. Other fixed
E execution/binding generations use checked advancement and fail closed. Their
practical exhaustion is an availability edge rather than stale authority reuse.

**Priority:** Low; revisit if long-lived/restart-heavy runtimes make exhaustion
reachable.

### E8-R5 - the E concurrency proof is deliberately single-BSP

Several immediate-before-IRET validation and mutation-exclusion arguments rely
on the locked E assumption that IF is clear and no second CPU can concurrently
publish scheduler or page-table state. SMP invalidates that reasoning boundary.

**Target:** DW0-H/SMP activation; do not carry this soft acceptance across SMP.
## Post-remediation regression evidence

The exact clean candidate `579e12074e1fe9ec89507e033381fed66676c12c`
passed the following host gates with project-local mutable state:

- `cargo xtask test host tasks`;
- `cargo xtask test host handles`;
- `cargo xtask test host memory`;
- `cargo xtask abi check`;
- `cargo fmt --all -- --check`;
- `cargo test --locked --workspace --all-targets`;
- `cargo clippy --locked --workspace --all-targets -- -D warnings`;
- `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps`; and
- `git diff --check` plus clean-tree checks before exact artifact/VM execution.

The accepted-toolchain selector-10 artifact oracle was rerun after the fix was
committed and while the Deepwyrm tree was clean. It passed with:

- userspace SHA-256
  `65becbc03deee89b9eff7bd61f2baa6646228ce28f4e0abd48846d1166acfc0d`;
- kernel SHA-256
  `934782a1fe76e394312a0b6bba9bf7892bd4e9db3684cf408eba13dc00d34b89`;
- build-input-manifest SHA-256
  `48370784b2694aa1065baa16a1a484acb20d82420d4273b818b82e132f255a04`;
- normalized-build-environment SHA-256
  `c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`; and
- audited stack bounds `bootstrap=91168`, `thread=11624`, with spare margins
  `39904` and `53912` bytes respectively.
The exact kernel was independently rebuilt from committed `579e120` in an
isolated accepted-toolchain environment and reproduced the same kernel hash.
A copy of the accepted E7 ESP was modified only in the existing
`EFI/WYRMROOT/DEEPWYRM.ELF` allocation; re-extraction proved byte identity with
that exact kernel. E8 ESP SHA-256:
`44615b5f4594c2934f18e14ab5fc396e757eba446c1a4e312dd18c3afc273deb`.

The designated `OS-Project` domain on `qemu:///system` was run under the
nonblocking `/tmp/os-project-vm.lock` lease. Wyrmroot remained at
`bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`; there is still no Deepwyrm ABI,
generated-ABI, or `kernel/arch/x86_64/layout.toml` delta from Wyrmroot's pinned
compatible Deepwyrm revision `75d60926f82b703e7d7afbeb77be0a3252f6cd35`.

Selector 10 deliberately reloaded GS with `0x2b` before its first syscall and
produced exactly one terminal PASS record:

`DWTEST1|01|0000000A|00000000|5C9DAA15`

The domain self-shut down with shutdown reason. The original inactive-domain XML
was restored byte-for-byte at SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`,
autostart remained disabled, the original external NVRAM remained absent, and
the primary `/var/lib/libvirt/images/OSProj.qcow2` inode/size/mtime tuple was
unchanged. The E8 NVRAM was disposable project-local state.

Initial target-oracle rehearsal attempts with ambient Cargo overrides or missing
accepted-tool variables were rejected by the oracle's environment guard as
designed; they are not counted as code-test failures. The normalized clean
post-commit run above is the accepted provisional artifact evidence.
## Provisional disposition

This GPT-5.6 Sol review found one confirmed High vulnerability in the E x86_64
syscall transition and remediated it at exact code candidate
`579e12074e1fe9ec89507e033381fed66676c12c`. The hostile GS reload now has host,
accepted-target artifact, and designated-VM regression coverage.

No unresolved Critical or High vulnerability is known from this provisional
review. No currently user-reachable Medium vulnerability was confirmed in the
reviewed E scope; E8-R1 through E8-R5 are explicit forward/integration concerns
with target phases above.

The coordinator may therefore treat `579e120` as **SOFT ACCEPTED for continued
development/evidence preparation**. This does not satisfy the canonical E8
security gate, does not authorize E9 to claim final E security closure, and does
not replace the exact-candidate `gpt-daybreak-blue-latest` review.

When Daybreak is available, run it against the exact resulting candidate and
explicitly re-review E8-F1/SWAPGS, hostile GS/RCX/R11/RSP/RIP state, exception
origin/GS normalization, usercopy mutation exclusion, typed finalization,
teardown ordering, and test-only exclusion. Any substantive remediation from
that review requires rerunning the affected host/artifact/VM evidence before E9
can issue the final `DW0_E_SECURITY_REVIEW.md` disposition.