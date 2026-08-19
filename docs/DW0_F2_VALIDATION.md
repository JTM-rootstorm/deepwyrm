# DW0-F2 Validation Record

## Disposition

**DW0-F2 is CLOSED for its scheduler-blocking, resumable kernel-continuation,
x86_64 target-execution, and regression-VM scope.**

The final Deepwyrm implementation/evidence candidate is
`f05a4dbe20c543c80981cdd07b27a7abbb277ea8`, validated on 2026-08-19.
It descends from F1 closure `81f00820c25f4820b44d581998568bb18527e959`.
Wyrmroot remained unchanged and clean at
`bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`.

F2 does **not** implement Channel, Event, Timer, `wait_one`, `wait_many`,
`atomic_wait32`, `atomic_wake`, or `process_create` behavior. No production F
syscall currently returns `SyscallControl::SuspendCurrent`; those consumers
belong to later F phases. F2 provides the substrate they require.

This is functional/architecture validation, not a Daybreak security review and
not an F security-gate conclusion. D/E deferred Daybreak debt remains unchanged.
## Implementation checkpoints

F2 was deliberately split into reviewable commits:

- `33ef86fb7c0318bf726e6a7d884f997b6c5c7a43` adds generation-protected
  scheduler `Blocked` state, move-only block ownership, exact wake tokens, and
  blocked-resource retention/retirement tests.
- `396f7b272d0b5bb4100ac13b663fb3c79b73c7e6` adds the x86_64 SysV kernel
  continuation switch, Thread-owned syscall-frame migration, continuation
  storage/validation, three-way syscall control, and pinned runtime binding.
- `f05a4dbe20c543c80981cdd07b27a7abbb277ea8` adds a target-only selector-10
  round-trip probe plus its accepted-target stack audit and closure lint fixes.

All commits are unsigned and contain the required
`Co-authored-by: Codex <codex@openai.com>` trailer. No push is part of F2.

There is no F2 ABI schema, wire-record, syscall-number, generated-ABI, or
`kernel/arch/x86_64/layout.toml` change relative to F1. The additive generated
signal APIs introduced by F1 remain the only pending Wyrmroot consumer delta.
## Scheduler and execution ownership

The cooperative scheduler now admits the state transition:

```text
Reserved -> Runnable -> Running <-> Blocked
                         |             |
                         +-----> terminal retirement
```

`block_current()` is valid only for the exact running Thread. It publishes a
nonzero generation token, makes the Thread `Blocked`, and selects the next
runnable Thread in one scheduler transaction. `wake()` accepts only the exact
scheduler domain, Thread identity, and block generation; the first successful
wake changes `Blocked -> Runnable` and clears the token.

Foreign, duplicate, stale, post-retirement, and competing wakes fail closed.
A blocked Thread keeps its task execution pin, kernel-stack generation, and
Thread-context generation. Terminal retirement removes it from the scheduler,
invalidates later wakes, then reclaims its execution resources exactly once.

Host tests also exercise concurrent competing wake attempts and deterministic
FIFO scheduling after a successful wake.
## Kernel continuation and syscall-frame ownership

`kernel/src/arch/x86_64/kernel_context.S` is a separate SysV kernel-continuation
boundary. It saves `RFLAGS`, `RBX`, `RBP`, and `R12-R15`, stores the suspended
kernel `RSP`, switches to the destination `RSP`, restores that continuation,
and returns normally. It contains no IRET/SYSRET/SWAPGS/MSR transition logic.

A critical F2 correction moved each complete `RawSyscallFrame` off the reusable
per-CPU privilege-entry stack and onto the current Thread-owned kernel stack
**before** Rust syscall dispatch. A later SYSCALL therefore cannot overwrite the
suspended caller's raw frame while that caller is blocked.

`ExecutionDomain` owns one private saved-kernel-RSP slot for each live
`ThreadContextId`. Destination continuation plans require:

- previous Thread state exactly `Blocked`;
- destination Thread state exactly `Running`;
- both task execution-resource generations still live;
- a nonzero destination saved RSP;
- the saved RSP and complete switch frame inside the destination kernel stack.

The plan constructor is an explicit unsafe boundary because its raw save-slot
pointer requires the execution owner to remain stationary until consumption.
## Resumable native-syscall control and runtime lifetime

The former E terminal-only `Reschedule` control became three explicit outcomes:

- `ReturnToCaller`;
- `TerminateCurrent`; and
- `SuspendCurrent`.

`dispatch_frame()` no longer performs terminal/suspend scheduling itself. It
sets the status, authorizes only an immediate user return, and returns the
control decision to the architecture trampoline. A suspended user frame remains
unauthorized until its kernel continuation later resumes.

After resume, `RawSyscallFrame::rebind_after_kernel_resume()` updates the exact
scheduler/entry binding generation before normal mapping/user-return validation.
This prevents a frame captured under an old Thread-stack binding from passing
return authorization merely because its user RIP/RSP remain valid.

F2 also materially strengthens E8-R2. Public raw runtime-pointer binding was
removed. `bind_native_syscall_runtime()` now accepts `Pin<&mut R>` and returns a
lifetime-branded binding retaining the exclusive pinned borrow for CPL3 lifetime.
The trampoline takes only short runtime reborrows, and no `&mut R` borrow spans
`execute_kernel_switch()`. This is required before multiple Threads may suspend
inside the shared live runtime.
## Target-executed continuation proof

Selector 10 now executes an F2-only target probe before constructing the E7
userspace runtime. The probe owns a private 16-KiB aligned alternate kernel
stack and performs this sequence with the real target switch assembly:

1. build the documented initial SysV switch frame on the alternate stack;
2. switch from the bootstrap kernel frame to the alternate stack;
3. the alternate frame marks stage 1 and switches back, becoming suspended;
4. the bootstrap frame switches to that exact saved alternate RSP;
5. the alternate frame resumes after its prior switch call, marks stage 2, and
   switches back again; and
6. selector execution continues only if both stages were observed.

Failure returns the selector-specific test failure detail `0xbb` before CPL3.
The target stack oracle separately audits the probe's bootstrap frames and the
alternate stack against its 16-KiB capacity.

This does not turn selector 10 into an F wait/IPC test. It proves only the F2
kernel-continuation substrate before the unchanged hostile-GS E userspace flow.
Fresh runnable userspace Thread launch remains distinct from resuming an existing
kernel continuation; F2 does not manufacture a fake suspended kernel frame for
a Thread that has never run.
## Clean host validation

Final validation ran from clean Deepwyrm `f05a4db` with mutable state under
`OS-Project/.artifacts/f2-implementation/`. The following passed:

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
clean-tree assertions before and after
```

Host/model coverage includes generation-safe block/wake, competing wake winners,
blocked retirement, execution-resource retention, continuation geometry and
stale generations, live host execution of the exact switch assembly, suspended
syscall control without premature user-return authorization, frame rebinding,
and F2 architecture source contracts.

Final host log SHA-256:
`235d74913cea0d5d35d8ad794d4047cb37ab384c779fc1b76f5adc0915edf04e`.
## Accepted-toolchain target validation

Both explicit accepted-toolchain artifact oracles passed using
`RUST-PHASE0B-TOOLCHAIN-001`, Rust commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, target
`x86_64-unknown-none`, and LLVM/Clang 22.1.8.

The production + six inherited memory-selector oracle passed with production
SHA-256:
`b3cb990592836fe2e0ce76fda3b92f478ca8d78a0acf70748ad8123f570a5968`.
It independently assembles/disassembles the F2 switch object before final-link
garbage collection and enforces the exact SysV switch instruction sequence.

The final selector-10 oracle passed with:

- userspace `65becbc03deee89b9eff7bd61f2baa6646228ce28f4e0abd48846d1166acfc0d`;
- kernel `e35279bb105be2c4dcf12d6646a610bbda000bf0360c76ca8ab2c60ef4e5f2f2`;
- bootstrap stack 94,592 / 131,072 bytes, 36,480 bytes spare;
- Thread syscall/exit stack 11,848 / 65,536 bytes, 53,688 bytes spare;
- build-input manifest `69ce671e2ded9e4c421d99260eaf9689f3a5d7164ef809e3f02e9801e5797a24`;
- normalized environment `c770c18880ac0215dfad43e5afe99ff2e9f31627c046c7dcd01dc74b5423626c`.
Target logs:

- production/memory oracle SHA-256
  `2f3b6ca5a281398d9535c421109f1d6b0a20cef46211fae18f8e37881bc19b1e`;
- selector-10 oracle SHA-256
  `fab594fa5953e31a3722e57c6966ed2511bf6b01a8bf3a4abc6cc53d8fb1e3d5`.

The final selector kernel was also rebuilt independently for VM media from the
same clean commit and reproduced the exact
`e35279bb105be2c4dcf12d6646a610bbda000bf0360c76ca8ab2c60ef4e5f2f2`
bytes. The final kernel size is 7,316,952 bytes.

## Final ESP construction

The accepted E8 ESP was cloned into project-local disposable F2 media. Because
the F2 kernel exceeded the existing FAT32 allocation, the project-local extender
allocated 120 previously free 512-byte clusters, updated both FAT mirrors and
FSInfo, then replaced only `EFI/WYRMROOT/DEEPWYRM.ELF` in the clone.

Final ESP SHA-256:
`bf83e1880d5a09f39aa4ad040f01a0e3ad8579538a1e5d61500d5162aafb0079`.
Re-extraction with 7z and `cmp` proved the embedded kernel is byte-identical to
the independently reproduced accepted selector kernel.
## Designated VM regression

The final regression used system-libvirt domain `OS-Project` on
`qemu:///system`, UUID `33005e22-d7c2-4b13-b1ac-b82eda95e584`, while holding
the exclusive `/tmp/os-project-vm.lock` lease.

The transient profile remained bounded to q35 (`pc-q35-10.2`), 1 vCPU,
1024 MiB, OVMF, read-only project ESP/system media, no NIC, no host filesystem
share, COM1 through a PTY, selector `task-syscall-smoke` (ID 10), and the
existing test-only `isa-debug-exit` completion channel.

Relevant final inputs:

- Deepwyrm `f05a4dbe20c543c80981cdd07b27a7abbb277ea8`;
- Wyrmroot `bd2f0629206de3a47f5a20cb0842a4e76ec88aaf`;
- selector kernel `e35279bb105be2c4dcf12d6646a610bbda000bf0360c76ca8ab2c60ef4e5f2f2`;
- ESP `bf83e1880d5a09f39aa4ad040f01a0e3ad8579538a1e5d61500d5162aafb0079`;
- Wyrmroot system disk `8cf73f8d367b56e81afc7e25dba3226168f8f05790ccf7e846de51e931478133`;
- OVMF code `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a`.
The disposable NVRAM began from the pristine project-selected OVMF template at
SHA-256 `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc`
and finished the successful boot at
`250139dfd26c4f76f7699f163ab815bf3f2abb8db75208ef170e3bd3aae6eff5`.
The transient domain template SHA-256 was
`e81af45e30a8cf9c42120b8d2594f428b4a9b02c6f7fc9c52f44291cc2322cc4`;
the libvirt-canonicalized active definition was
`7790d66c0a6dade4100051efbd1fcd5168a90fdf54c0ab6ebd0cb6cbd8f7d77b`.

The real loader/kernel path reported:

```text
wyrmroot-loader: UEFI adapter online
wyrmroot-loader: final UEFI memory map / ExitBootServices
wyrmroot-loader: ExitBootServices complete
wyrmroot-loader: entering Deepwyrm
DWTEST1|01|0000000A|00000000|5C9DAA15
```

Because the F2 target continuation probe executes before CPL3 setup, that final
PASS proves its two-stack/two-resume target round trip completed before the
hostile-GS native-syscall regression and normal E7 teardown also completed.
Final serial SHA-256:
`7a93a31f2c09d3aa1b4cfe4e97ea2b97dbd9c4b4e64010a0d84f9be4799cf97b`.

Several earlier F2 VM attempts were **infrastructure-only capture failures**:
fast guest shutdown outran TCP attachment, a TCP-connect capture produced no
bytes, a libvirt file backend made its project-local capture root-owned/mode 600,
and one PTY attempt lacked a controlling terminal. Every attempt used the VM
restoration trap and restored the canonical definition before the next try.
None produced contradictory guest terminal evidence. Final acceptance used the
same PTY + `script(1)` controlling-terminal pattern already proven during E7.

## VM restoration

After final PASS, the original inactive domain definition was restored at exact
SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.
The final state was `shut off (shutdown)`, original 2-GiB memory configuration,
autostart disabled, and the originally absent external
`/var/lib/libvirt/qemu/nvram/OS-Project_VARS.qcow2` remained absent.

The primary `OSProj.qcow2` inode/size/mtime tuple remained exactly
`1610625208 10739318784 1786749003` before and after the regression.
## Boundaries carried forward

F2 deliberately remains single-BSP. `KernelContinuationSlot` uses scheduler and
execution-owner serialization rather than an SMP publication primitive; DW0-H
must re-review this storage, scheduler state transitions, per-CPU entry stacks,
and cross-CPU wake/context-switch publication before SMP activation.

A `KernelSwitchPlan` accepts only a real/seeded suspended kernel continuation.
It is **not** the fresh-Thread launch mechanism. Later F integration must choose
between resuming an existing kernel continuation and entering a never-run
userspace Thread through its validated initial user state without conflating the
two operations.

No generic wait registration exists yet, so F2 does not itself prove
registration-vs-state lost-wakeup resistance. F3/F4 own deadline/waiter
integration over the exact block-generation and continuation substrate proven
here.

No F2 change claims to resolve formal D/E Daybreak debt. The pinned runtime
mechanically improves the E8-R2 lifetime concern, but the delayed Daybreak review
must independently reassess that changed implementation when it eventually runs.

With these bounds, no functional blocker remains inside the defined F2 scope.
DW0-F3 is the next implementation gate.
