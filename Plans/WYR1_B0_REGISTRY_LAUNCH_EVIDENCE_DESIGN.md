# WYR1-B Selector-27 Registry and Launch Evidence Design

**Status:** Implemented Deepwyrm test-support contract; live acceptance remains external
**Selector:** `bootstrap-registry-launch`, test ID `27`
**Paired authority:** Wyrmroot `Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md`

This design admits the Deepwyrm half of WYR1-B's live gate without changing
the public native ABI. Deepwyrm validates and atomically relays the permanent
controller's fixed WRB1 transcript. Wyrmroot remains the sole owner of
registry, publication, launch/job, generation, and reap meanings.

## 1. Selector and build identity

Selector 27 is implemented only with `test-support`. Its private raw operation
is `0xFFFF_FF1B`, deliberately absent from the generated ABI and production
kernels. Selectors 25 and 26 retain their independent raw IDs, collectors,
records, capacities, failure details, and terminal paths.

The selector build requires:

- `DEEPWYRM_WYR1B_EVIDENCE_NONCE`: exactly 16 uppercase hexadecimal digits
  encoding a nonzero `u64`; and
- `DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES`: the frozen candidate's exact measured
  bootfs pages as canonical decimal in `1..=8192`.

Wyrmroot product tooling owns both candidate inputs. Deepwyrm compiles them
into the selector-specialized artifact, rejects missing or malformed values,
and applies the page value to its mapping journal, invalidation storage, and
bootfs admission check. A retry against a changed bootfs requires a new frozen
build input; no selector-25 or selector-26 capacity is reused.

## 2. Reporter authority

The reporter is the exact first child created by primordial, the permanent
`/system/init` controller. The raw submission path is disabled until Deepwyrm
has independently established all of the following:

1. primordial is quiesced;
2. primordial's userspace root region is retired;
3. primordial monitor and kernel-peer handles are released;
4. pending finalizers are drained; and
5. the architecture-private primordial PML4 remains retained for the boot.

The reporter must remain a distinct live Process accepting operations. Binding
is one-shot. Early submission, a different Process, reporter replacement, or
reporter exit before terminal evidence latches failure and reaches selector
27's sole failing terminal path.

## 3. Raw operation and WRB1 validation

The only accepted raw argument form is:

```text
arg0 = userspace address of one WRB1 record
arg1 = 96
arg2 = 0
arg3 = 0
arg4 = 0
arg5 = 0
```

Reporter authority is checked before touching user memory and repeated when
the record commits. One record is exactly 96 bytes:

```text
WRB1|01|NNNNNNNNNNNNNNNN|SSSSSSSS|EE|IIIIIIIIIIIIIIII|GGGGGGGGGGGGGGGG|VVVVVVVVVVVVVVVV|CCCCCCCC
```

The fields are the build nonce, zero-based sequence, event, nonzero subject,
nonzero generation, event value, and uppercase FNV-1a-32 checksum over bytes
`0..88`. The checksum field occupies bytes `88..96`; WRB1 records contain no
newline or handles.

The collector accepts exactly 14 records. Sequences are `0..13`, and event
bytes are exactly `1..13, FF` in that order. Events `1..13` require nonzero
subject and generation. Terminal `FF` requires subject, generation, and value
all zero. The nonce must exactly match the selector build.

Any framing, delimiter, case, version, nonce, checksum, sequence, event,
subject/generation, terminal-shape, capacity, duplicate-terminal, or reporter
failure is latched. A valid later record cannot repair the transcript.

## 4. Atomic terminal transcript

The first valid terminal record atomically claims selector 27's terminal
reporter. Deepwyrm then holds the exclusive COM1 test transaction while it:

1. writes all 14 accepted WRB1 records byte-for-byte;
2. appends the canonical `DWTEST1` PASS record with test ID 27 and detail zero;
3. drains the transmitter; and
4. issues the matching QEMU debug-exit value.

Kernel-detected FAIL or PANIC claims the same one-shot terminal authority,
writes only the already accepted WRB1 prefix, then appends its canonical
`DWTEST1` terminal and matching debug exit. Competing terminals halt rather
than interleave or manufacture a second result. Serial evidence without the
matching host-observed debug exit remains insufficient.

## 5. Selector-local runtime capacity

Selector 27 uses bounded test-artifact pools for at most eight simultaneous
Process/address-space roots, 24 Channel pairs, 16 wait registrations, eight
TaskGroups, 32 handles per Process table, 28 MemoryObjects/mapping leases, and
160 registry objects. These values admit the fixed controller, resident
registry, gate actors, direct endpoint exchange, and bounded launched-job
topology. They are test-build storage limits, not public ABI or Wyrmroot
service limits. Live evidence must still fail closed on resource exhaustion;
host tests do not certify peak utilization.

### 5.1 Bootstrap stack budget

Deepwyrm's private x86_64 bootstrap stack is 512 KiB for WYR1-B. Thread kernel
stacks remain 256 KiB. This is an internal bootstrap implementation budget,
not a native ABI, boot ABI, or Wyrmroot platform ABI change.

The increase preserves all selector capacities after the accepted selector-27
release artifact measured 268,808 bytes of retained
`kernel_main -> run_primordial -> primordial::enter` frames after direct
final-location pinning. The three exact call/return words raise that chain to
268,832 bytes. The prior 256 KiB stack could not contain it, even before the
required 4 KiB architectural headroom and 32 KiB spare. The additional 256 KiB
is explicit optimization debt: future work may reduce bootstrap frame
pressure, but WYR1-B admission does not trade away registry, memory, task,
Channel, wait, handle, or mapping-journal capacity to meet the old
implementation budget.

The accepted linked-artifact gate derives the boot-stack payload from linker
symbols and checks selectors 25, 26, and 27 independently. For each selector,
the retained bootstrap chain, exact call/return words, 4 KiB architectural
headroom, and 32 KiB spare must fit the linked payload.

Worktree execution supplies `DEEPWYRM_ACCEPTED_REQUEST` as an absolute path to
the exact hash-pinned Rust007 request record. This keeps request provenance
explicit when the lane is not adjacent to the Wyrmroot checkout; accepted
artifacts and Cargo state still resolve only from separately provisioned,
non-symlink lane-parent trees rather than a canonical mutable cache.

## 6. Evidence boundary

Deepwyrm validates only transport facts: exact reporter authority, retirement,
record framing, build binding, order/cardinality, and atomic terminal output.
The Wyrmroot controller must establish the 14 relational joins defined by its
reached WYR1-B contract before producing the corresponding event labels.

Host/model tests cover the byte validator, all retirement facts, early/wrong
reporters, malformed records, event order, exact cardinality, duplicate
terminal exclusion, selector/build admission, absence from the public ABI, and
terminal ordering. Live q35/OVMF execution and selector-25 regression are
external paired gates and are not claimed by this document.

## 7. Required-source and provenance disposition

The root DW1/WYR1 plan, Bootstrap and Recovery Architecture, reached Wyrmroot
WYR1-B contract and WRB1 producer/verifier, Deepwyrm Channel/atomic-transfer
contract, and WYR0-I generation/replay contract were used as authority. The
pinned Fuchsia/Zircon Channel source at revision
`6a606ff7fd9b055edee6557566fb3f112df1a812` was consulted conceptually for
move ownership and endpoint lifetime. No upstream code, ABI, routing policy,
or service semantics were copied or adapted.

This document and implementation are first-party `GPL-2.0-or-later` work.
Existing component and file declarations remain unchanged.
