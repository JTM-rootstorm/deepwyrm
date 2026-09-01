# Deepwyrm DW1-E0 q35 External-Interrupt Contract

**Status:** Reached DW1-E0 architecture/model gate

**Reached:** 2026-08-31
**Implementation authority:**
`../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, sections 0 through 6

**Starting Deepwyrm revision:**
`8adb1792c2b1bd08adb576ac647215bb13fa003a`
**Scope:** Private q35 MADT/IOAPIC discovery, one edge/high COM2 route, one
returning external-vector entry, generation-exact binding and retirement,
existing DW1-D Interrupt delivery, and selector-31 evidence identities

## 1. Gate disposition and stop line

The E0 architecture review passes: a real q35 COM2 edge can drive the reached
DW1-D `InterruptAuthority::deliver()` path without changing any public object,
right, signal, syscall, object-info, boot-resource, or generated-ABI semantic.
The existing `Interrupt` object remains the only userspace-visible interrupt
abstraction.

That conclusion has one mandatory private E2 prerequisite. The current
synthetic `InterruptPlatformModel::prepare_delivery()` changes its source from
`Armed` to `Masked`, and `InterruptAckTransaction::complete()` calls
`mask_source()` again when a delivery races the prepared acknowledgement. Those
calls correctly express selector-30's synthetic mask/rearm model, but they do
not express a live edge/high IOAPIC route, which must remain physically
unmasked throughout `Pending`, `AckPrepared`, and coalesced epochs. E2 must
factor the private platform acknowledgement outcome described in section 6. It
must not reuse those current calls unchanged or reinterpret `mask_source()` as
a harmless validation operation.

This is not a public-ABI blocker. The object state machine already accepts an
exact generation-bound delivery, publishes `DW_SIGNAL_SIGNALED`, coalesces a
bounded repeated fact, retains wait pins, and finalizes through the typed
platform seam. E1 and E2 may refine only the private platform/lifecycle
interface and target integration needed to supply real deliveries.

E0 introduces no hardware code, live gate, public ABI, UART policy, or guest
acceptance claim. E1 owns the pure route model. E2 owns live MMIO, the vector
entry, private platform refactoring, delivery, and quarantine. E3 owns live
selector 31. E4 owns closure and regression evidence.

## 2. One admitted route

The WYR1 q35 product admits exactly one external source:

| Fact | Frozen value |
| --- | --- |
| device role | legacy COM2 |
| ISA IRQ | 3 |
| selected GSI | MADT-resolved IRQ3 GSI |
| trigger | edge |
| polarity | active high |
| external vector | `0x30` |
| vector pool | reached `0x30..=0xdf` external pool |
| delivery mode | fixed, physical destination |
| destination | BSP / logical CPU0's live xAPIC ID |
| public object | reached DW1-D `Interrupt` |
| userspace PIO grant | only `[0x2f8,0x300)` through `DeviceResource` |

Vector `0x30` is a fixed milestone assignment, not a general vector allocator.
No other external vector gains a present IDT gate. COM1/IRQ4 remains the
loader/kernel diagnostic domain and is never routed or delegated by DW1-E.

The destination is the physical xAPIC ID discovered for logical CPU0, not an
assumption that the APIC ID's numeric value is zero. x2APIC is unsupported and
fails the selected profile closed.

## 3. MADT discovery and route resolution

E1 extends the existing snapshot-based ACPI intake. Firmware bytes remain an
immutable proposal copied into bounded kernel-owned storage before parsing.
They do not create routing or MMIO authority by themselves.

The MADT records needed by this product are:

- IOAPIC, type 1, exact length 12: controller ID, 32-bit physical address, and
  GSI base;
- interrupt-source override, type 2, exact length 10: bus, source IRQ, GSI,
  and polarity/trigger flags; and
- the already-reached local-APIC records used to identify the BSP destination.

An IOAPIC address must be nonzero, 4 KiB aligned, within the admitted physical
address width, and safe under checked page/range arithmetic. Its eventual
version probe supplies the redirection-entry count; the MADT entry alone does
not claim a GSI end.

For ISA IRQ3:

1. absence of an override means ISA-conforming active-high, edge-triggered
   GSI3;
2. an override is considered only when `bus = 0` and `source = 3`;
3. `conforms` polarity resolves to active high and `conforms` trigger resolves
   to edge for this ISA source;
4. an explicit active-high/edge override is accepted;
5. active-low or level-triggered resolution is unsupported and fails closed;
6. reserved polarity or trigger encodings fail closed; and
7. every duplicate IRQ3 override fails, even if byte-identical, so no firmware
   order becomes policy.

After live redirection capacity is probed, exactly one validated IOAPIC must
cover the resolved GSI. Zero coverage, overlapping coverage, duplicate or
conflicting controller identity/address/GSI facts, range overflow, malformed
entry length, or a selected GSI outside every probed table fails closed. The
route is not published in a partially validated state.

E1 must preserve all current CPU-topology behavior and fixtures. It does not
add PCI enumeration, ACPI namespace/device discovery, hotplug, or generic ISA
routing.

## 4. Controller ownership and redirection encoding

The IOAPIC page and its selector/window register pair are permanent kernel
controller state. They are not part of the COM2 userspace `DeviceResource`,
cannot be mapped into a Process, and do not broaden that object's PIO-only
kind. ACPI and a validated boot profile propose the controller; the kernel's
target mapping and probe authorize it.

E1 provides a pure redirection-entry encoder/decoder. For the selected route it
accepts only:

- vector `0x30`;
- fixed delivery mode;
- physical destination mode;
- active-high polarity;
- edge trigger;
- a zeroed delivery-status template bit, decoded separately as the read-only
  redirection Delivery Status bit on hardware readback;
- a zeroed remote-IRR bit on construction;
- BSP xAPIC destination in the high dword; and
- the explicit mask bit selected by the lifecycle state.

All reserved or unsupported fields remain zero. Decode/re-encode tests must
prove both the masked and unmasked forms exactly and must expose Delivery
Status bit 12 as `Idle` for zero and `SendPending` for one without treating the
read-only observation as a writable route field.

E2 maps one validated IOAPIC page permanently with the reached UC/PAT
invariants. IOREGSEL and IOWIN are volatile aligned 32-bit accesses behind one
IRQ-safe controller lock, because the selector/window pair is shared mutable
state. The version/maximum-redirection register is probed before route
publication, and controller ID/version/capacity must agree with the selected
descriptor. Mapping or probe drift fails closed.

Every reserve, reprogram, rollback, and physical release operation begins with
the exact selected redirection entry masked. Retirement first removes the
binding from live delivery classification, then masks the physical entry as
specified in section 7. A committed live edge route is unmasked once and stays
unmasked until rollback, terminal fault, or retirement. Write completion
required by retirement is established by reading the same redirection entry
back through the serialized selector/window boundary. That mask readback alone
does not establish that an interrupt message accepted just before the write is
no longer in transit; section 7 separately requires the read-only Delivery
Status bit to become idle.

## 5. Platform binding lifecycle

One source-3 slot owns a monotonically increasing, nonzero platform generation
and this private state:

```text
Vacant
  -> ReservedMasked(exact generation)
  -> LiveUnmasked(exact generation)
  -> Retiring(exact generation)
  -> RetiringMasked(exact generation)
  -> Vacant
```

Generation exhaustion retains the slot unavailable and fails closed. A
reservation is invisible to userspace and may be cancelled only while its
exact entry remains masked. Commit programs and verifies the exact route,
publishes the exact binding, and unmasks only at the no-fail creation commit.
`Retiring` is a logical quarantine state: it prevents new user delivery
snapshots but makes no claim yet about the physical mask bit. Only successful
mask write/readback advances it to `RetiringMasked`. Publication rollback from
an entry already proved masked may enter `RetiringMasked` directly. Both
retirement paths use the remaining release proof and may not make a published
or replacement generation observe an old vector.

`InterruptBinding` remains generation-exact. The q35 backend rejects any
domain/source/generation mismatch. Source number 3 alone is never enough to
select an `Interrupt`.

The IOAPIC route stays unmasked during these existing object states:

- `Armed`;
- `Pending { coalesced: false }`;
- `Pending { coalesced: true }`; and
- `AckPrepared`, including a raced delivery.

Repeated physical edges therefore reach the kernel while the object is
pending and exercise DW1-D's existing bounded coalescing fact. DW1-E adds no
second delivery counter or userspace-visible hardware state machine.

## 6. Delivery, acknowledgement, and EOI

The vector-`0x30` ISR performs this bounded order with IF clear:

1. acquire the source slot only long enough to snapshot the exact live or
   retiring generation and increment its bounded in-handler count;
2. drop all route/controller state locks;
3. for `LiveUnmasked`, construct the exact `InterruptDelivery`, call
   `InterruptAuthority::deliver()`, and drain its IRQ-safe `WakeBatch` through
   the existing blocked-operation/scheduler wake path;
4. for logical `Retiring`, `RetiringMasked`, stale, or unresolved state,
   publish no userspace wake;
5. issue local xAPIC EOI in the kernel;
6. decrement the exact generation's in-handler count with release ordering;
   and
7. restore the complete interrupted register frame and return with `iretq`.

No IOAPIC selector/window lock, platform-slot lock, Interrupt lock, wait lock,
scheduler lock, Process lock, ObjectRegistry guard, or finalizer guard is held
across local-APIC EOI.

EOI and userspace acknowledgement are distinct:

- local-APIC EOI ends this CPU's in-service ownership before ISR return;
- `interrupt_ack` declares that userspace drained the device causes and may
  consume/clear the existing object pending/coalesced fact; and
- `interrupt_ack` never delays, performs, substitutes for, or owns LAPIC EOI.

### 6.1 Mandatory private acknowledgement seam

E2 must make platform completion depend on the final object acknowledgement
outcome rather than using `mask_source()` as the raced-delivery fallback. A
private shape such as the following is sufficient; exact Rust names may vary:

```text
acknowledge_source(exact binding) -> validated prepared acknowledgement
complete_ack(exact binding, Armed | PendingAfterRace)
mask_for_retirement(exact binding)
```

The synthetic platform preserves selector-30 behavior: its logical source is
masked after synthetic delivery, becomes armed after a clean ack, and remains
masked after a raced ack. The q35 edge backend validates the same exact binding
for both ack outcomes but leaves the physical redirection entry unmasked for
both. `mask_for_retirement` is reserved for creation rollback, finalization,
terminal fault, and the quarantine in section 7.

This private refactor may change trait methods and internal call sites. It may
not change public `interrupt_ack`, public states/flags, wait semantics,
coalescing, rights, finalization ownership, or selector-30's observable
behavior.

## 7. Stale delivery and fixed-vector retirement quarantine

A vector that cannot resolve to the exact current binding is an orphan/stale
entry. It must not call `InterruptAuthority::deliver()`, wake a waiter, or
alias a replacement. It increments a saturating selector-only diagnostic,
EOIs the local APIC, and fail-safe masks the selected route when the route can
be identified safely. An unidentifiable entry still EOIs and remains bounded;
it never guesses from numeric source 3.

Release of source 3 uses this exact quarantine:

1. atomically change the exact live binding to logical `Retiring`, preventing
   new delivery snapshots from being classified live without yet asserting a
   physical mask state;
2. mask the selected IOAPIC entry, read back mask bit 16 as one, and only then
   advance the unchanged generation to `RetiringMasked`;
3. after the masked readback, perform at most
   `DELIVERY_STATUS_POLL_LIMIT = 65_536` serialized volatile reads of that
   entry's low dword and require read-only Delivery Status bit 12 to be zero
   (`Idle`); bit one is `SendPending` and means an old edge may still be in
   transit;
4. poll boundedly for that generation's in-handler count to become zero;
5. reacquire the IOAPIC selector/window lock and revalidate the unchanged
   redirection entry with mask bit 16 one and Delivery Status bit 12 zero;
6. on BSP/CPU0, strictly after that delivery-status revalidation and handler
   quiescence, read the xAPIC IRR and ISR banks for vector `0x30` and require
   both bits clear;
7. if retirement runs on another CPU, publish one generation-bound private
   check to CPU0 using the reached e1 rendezvous transport, and let CPU0 perform
   the check at its post-EOI carrier-safe point;
8. acquire the exact check result and revalidate the unchanged retiring
   generation plus mask-one/Delivery-Status-idle redirection entry;
9. consume and EOI any vector observed while retiring without forwarding it;
   then repeat the bounded delivery-status, handler, and BSP checks; and
10. only after a clear result remove the old binding and make the slot
   reservable with a later generation.

Retirement must not spin indefinitely with IF clear. In particular, a vector
already present in the BSP IRR cannot run while its closing syscall retains an
IF-clear carrier. E2 therefore adds one bounded private deferred-finalization
slot alongside the one admitted source. It owns the move-only Interrupt final
release, parent pin, exact binding, and retirement request while quarantine is
incomplete. The close removes the last public reference and may return with
the typed object still `Finalizing`; source reservation continues to report in
use. A retiring vector is then consumed/EOI'd normally when the BSP regains an
interruptible boundary, and an existing runtime/finalizer safe-point drain
retries the bounded BSP proof. Only that drain may take the ready finalization
back into ObjectRegistry, complete typed cleanup, release the parent, and make
the grant eligible to return. This is private finalization staging, not a new
asynchronous public object state or syscall result.

The xAPIC IRR register for vector `0x30` is bit 16 in the `0x210` bank and the
ISR bit is bit 16 in the `0x110` bank. E2 must add narrow validated reads
through the existing local-APIC boundary; raw offsets do not escape that
module.

The private rendezvous request contains the source, vector, platform
generation, and a nonzero request generation. A stale or duplicate response
cannot complete another retirement. It allocates no memory and admits at most
one outstanding request because WYR1 has only one source. A Delivery Status
poll timeout, controller fault after successful mask readback, status returning
`SendPending` during revalidation, a nonzero IRR/ISR bit after the bounded
retry, or generation drift leaves the route and binding quarantined in
`RetiringMasked`. Failure before mask readback succeeds leaves logical
`Retiring` quarantined and does not falsely claim a physical mask. Neither
state releases or replaces optimistically.

This is the required fixed-vector reuse proof. E2 live q35 validation must
establish that redirection Delivery Status is implemented and reliable for
this route. If the bit cannot be relied upon, or if either the IOAPIC
Delivery-Status observation or the live xAPIC observation cannot make the
ordered proof reliable, E2 must stop and switch to the already admitted,
separately documented bounded vector-generation/quarantine design before E2
lands. Hoping that an old vector has drained is forbidden.

## 8. Returning entry and scheduler rule

Vector `0x30` gains one returning interrupt gate only in the reached DW1-E
product. Historical/default IDT constructions keep the complete external pool
absent. The entry follows the reached timer/IPI frame discipline:

- interrupt-gate entry with IF clear and `cld`;
- preserve all 15 interrupted general-purpose registers;
- inspect saved CS and perform `swapgs` only for a CPL3 origin;
- maintain SysV call alignment;
- call one fixed Rust dispatch symbol;
- restore the same ephemeral frame, reverse `swapgs` for CPL3, and `iretq`.

Unlike the reached timer entry, the external entry does not copy its frame to
a Thread kernel stack and does not call the timer pre-iret switch gate. It may
wake blocked threads through `complete_irq_signal_wakes()`, which commits a
generation-bound scheduler wake without ObjectRegistry/finalizer work. The
existing idle path rescans after any interrupt returns from `sti; hlt; cli`,
and an already-running CPU retains the reached timer-driven scheduling
boundary. Therefore a device wake need not retain or switch away from the
external frame merely for lower latency.

E2 target evidence must nevertheless prove progress in both one-CPU and
four-CPU profiles. If a runnable driver can remain indefinitely stranded after
a correctly committed wake, E2 stops and factors the smallest generic
scheduler-return/rescan seam from the reached timer/carrier path. Such a seam
must apply to generic IRQ wakeups, preserve an ephemeral external frame, and
contain no UART, COM2, source-3, or selector policy.

## 9. Locks, ordering, and bounded execution

E2 documents the actual types before implementation and preserves this partial
order:

```text
platform source slot (snapshot/in-handler accounting only)
  -> drop
IOAPIC selector/window lock (one bounded controller transaction only)
  -> drop
InterruptAuthority record
  -> drop before WaitRegistry readiness scan
WaitRegistry readiness scan
  -> drop before blocked-operation/scheduler wake publication
Execution/scheduler wake publication
  -> drop before EOI and return
```

Finalization first validates the exact typed Interrupt, drops that lock, and
publishes the platform binding's logical `Retiring` quarantine. Only after the
platform can no longer issue a live delivery snapshot does finalization
reacquire the exact typed record and mark it `Finalizing`. It then performs the
physical platform-retirement proof without holding wait, scheduler, Process,
handle-table, ObjectRegistry, or typed-object locks. This ordering prevents a
crossing delivery from observing a live platform generation paired with a
typed object that has already become non-live. The platform binding remains
retained until mask, in-handler quiescence, IRR/ISR proof, and release all
succeed. If proof cannot complete synchronously, the one source's bounded
deferred-finalization slot retains the exact generic/typed ownership; it is
polled only at existing runtime/finalizer safe points and never in a busy-wait
loop with IF clear. Parent `DeviceResource` release and grant return remain
after exact Interrupt platform release as in DW1-D.

No interrupt or retirement path allocates, usercopies, blocks on userspace,
logs without a bound, recursively finalizes, or grows a queue. ISR loops,
controller polls, retirement checks, record storage, and counters have fixed
capacities. Diagnostic counters saturate rather than wrap:

- physical external entries;
- exact binding deliveries;
- deliveries while the Interrupt is already pending or ack-prepared;
- userspace acknowledgements;
- stale/orphan entries;
- route masks;
- route unmasks;
- final releases; and
- generation replacements.

These counters are selector-only observations, not a production syscall or
public object-info extension.

## 10. Required model and static gates

E1 must add pure host/model coverage for:

- normal q35 IRQ3 -> edge/high GSI3 resolution;
- an explicit edge/high override;
- no IOAPIC, zero/unaligned/overflowing IOAPIC address, uncovered GSI, and GSI
  range overflow;
- duplicate controller coverage and duplicate identical/conflicting IRQ3
  overrides;
- reserved polarity/trigger encodings, active-low, and level trigger;
- malformed MADT type-1/type-2 lengths without CPU-topology drift; and
- exact masked/unmasked redirection encoding for vector `0x30` and the BSP
  physical destination, plus Delivery Status decode as idle/send-pending.

E2 must add model/source/target coverage for:

- reserve masked, exact commit unmasked, and final release masked;
- route unmasked throughout first Pending, coalesced Pending, AckPrepared,
  clean ack, and raced ack;
- selector-30 synthetic mask/rearm behavior unchanged after the private seam
  refactor;
- no wake for stale, unresolved, retiring, wrong-domain, wrong-source, or
  wrong-generation delivery;
- logical `Retiring` before the physical mask write, and no
  `RetiringMasked` state until mask/readback succeeds;
- mask/readback followed by Delivery Status idle before handler/BSP proof;
- Delivery Status clearing within the 65,536-read bound, followed by an exact
  mask/idle revalidation and successful release;
- Delivery Status remaining send-pending through the bound retaining
  quarantine with no release or vector reuse;
- Delivery Status returning send-pending on the post-handler revalidation
  retaining quarantine without taking an early IRR/ISR snapshot;
- an in-flight old handler delaying release;
- a BSP IRR-pending close staging exact finalization, returning without source
  reuse, consuming/EOIing the retiring vector, and completing later at the
  exact finalizer safe point;
- nonzero IRR/ISR or a stale rendezvous response retaining quarantine;
- exact clear proof allowing a strictly newer generation;
- EOI on exact, stale, retiring, and unresolved entries;
- complete register preservation and CPL3-only `swapgs` source checks;
- vector `0x30` present only in the selected DW1-E product and all other
  external vectors absent; and
- bounded/saturating counters and no allocation in ISR/stale/retirement paths.

E0 itself is contract-only. Its gate is formatting, plan/index/registry source
checks, selector uniqueness, documentation links, and review against current
code. Host/model tests that execute kernel code are not runtime acceptance and
are not required merely to publish this document.

## 11. Selector 31 and byte-defined evidence

The canonical `tooling/guest-harness.toml` inventory was checked at E0: IDs 31
and 32 were free. E0 reserves:

- `q35-com2-interrupt`, test ID 31, for DW1-E3; and
- `native-console-streams`, test ID 32, for paired WYR1-D5.

Both remain `reserved`; E0 adds no dispatch. Selector 31 alone may later
compile `cfg(deepwyrm_dw1e_evidence)`. Its private raw operation is reserved as
`0xffff_ff1f`, requires a nonzero 16-uppercase-hex
`DEEPWYRM_DW1E_EVIDENCE_NONCE`, and is absent from the generated/native ABI.
No D0-specific raw operation is reserved here.

The private operation must keep the established six-`u64` raw-call boundary
and decode only four selector-local actions: bind the exact current driver
reporter to an Interrupt handle plus nonzero attempt generation; bind the exact
controller-launched raw probe reporter; arm one stream/challenge generation
with expected byte length and payload hash before host transmission; and
submit one actor-owned userspace event/value/auxiliary tuple. The permanent
controller is bound through the reached reporter-custody path and remains the
only terminal claimant. Each action repeats the build nonce, rejects nonzero
reserved words, resolves caller/handle/process generations before accepting
state, and is one-shot for its expected sequence. E3 may choose numeric action
tags and argument positions only in a checked source constant table; it may not
add more authority or accept opaque generation fields.

The driver's bind resolves `O/B/L` from its actual Interrupt and parent lease;
`R` must equal that resolved `B`, and the supplied `T` becomes valid only for
that exact reporter Process. Challenge arm is accepted only from the current
driver/controller generation after stream attach and establishes `G/Q` for
subsequent direct kernel events. Thus kernel events do not guess Wyrmroot
attempt/stream generations, and userspace cannot supply kernel object/binding
generations by value.

Selector 31 uses q35/OVMF, 2048 MiB, explicit COM1 structured capture, and an
explicit task-owned COM2 host socket in both one-vCPU and four-vCPU runs. COM2
bytes can never manufacture a pass record.

### 11.1 Record bytes

The selector-31 collector emits exactly 26 newline-terminated, 204-byte
uppercase ASCII records on COM1 before the ordinary `DWTEST1` 31/0 terminal:

```text
DWE3E1|01|NNNNNNNNNNNNNNNN|SSSSSSSS|EE|AA|RRRRRRRRRRRRRRRR|OOOOOOOOOOOOOOOO|BBBBBBBBBBBBBBBB|LLLLLLLLLLLLLLLL|TTTTTTTTTTTTTTTT|GGGGGGGGGGGGGGGG|QQQQQQQQQQQQQQQQ|VVVVVVVVVVVVVVVV|XXXXXXXXXXXXXXXX|CCCCCCCC\n
```

The byte offsets are:

| Range | Meaning |
| --- | --- |
| `0..6` | magic `DWE3E1` |
| `6`, `9`, `26`, `35`, `38`, `41`, `58`, `75`, `92`, `109`, `126`, `143`, `160`, `177`, `194` | literal `|` |
| `7..9` | version `01` |
| `10..26` | build/run nonce `N` |
| `27..35` | zero-based sequence `S` |
| `36..38` | event `E` |
| `39..41` | actor `A`: kernel `00`, driver `01`, raw probe `02`, controller `03` |
| `42..58` | private platform route generation `R` |
| `59..75` | Interrupt object generation `O` |
| `76..92` | public Interrupt binding generation `B` |
| `93..109` | DeviceResource lease/bundle generation `L` |
| `110..126` | driver attempt generation `T` |
| `127..143` | raw-stream generation `G` |
| `144..160` | challenge generation `Q` |
| `161..177` | event value `V` |
| `178..194` | event auxiliary `X` |
| `195..203` | uppercase FNV-1a-32 over offsets `0..=194`, the first 195 bytes including the final `|` before the checksum |
| `203` | newline |

All integers are fixed-width uppercase hexadecimal without prefixes. The
collector rejects malformed width/case/delimiters, wrong version/nonce,
checksum failure, wrong actor, out-of-order/duplicate/early/post-terminal
input, zero required generations, or a full collector.

### 11.2 Exact event order and generation joins

The 26 events are:

| Sequence | Event | Actor | Required tuple/result |
| ---: | --- | --- | --- |
| 0 | `01 ROUTE_DISCOVERED` | kernel `00` | zero generations; exact `V/X` layout below |
| 1 | `02 U1_RESERVED` | kernel `00` | nonzero `R1/O1/B1/L1/T1`; stream/challenge zero |
| 2 | `03 U1_COMMITTED` | kernel `00` | exact U1 tuple, committed/unmasked |
| 3 | `04 C1_PHYSICAL` | kernel `00` | U1 tuple plus nonzero `G1/Q1`; bounded physical-entry delta in `V` |
| 4 | `05 C1_PENDING` | kernel `00` | exact U1 delivery made object pending; bounded delivery/repeat deltas in `V/X` |
| 5 | `06 C1_WAIT_WAKE` | kernel `00` | the blocked U1 wait generation won and became runnable; `V = 1`, `X = 0` |
| 6 | `07 C1_UART_DRAIN` | driver `01` | driver reports exact U1 bytes/hash in `V/X` |
| 7 | `08 C1_ACK` | kernel `00` | exact U1 ack after device drain; LAPIC EOI was already complete |
| 8 | `09 C1_RESPONSE` | raw probe `02` | probe/host observed exact deterministic COM2 response bytes/hash in `V/X` |
| 9 | `0A U1_PEER_CLOSED` | controller `03` | old raw stream closed after intentional U1 termination; `V = G1`, `X = 0` |
| 10 | `0B U1_RETIRE_BEGIN` | kernel `00` | exact U1 binding is Retiring, never reusable |
| 11 | `0C U1_ROUTE_MASKED` | kernel `00` | R1 mask readback followed by Delivery Status idle; exact bit-defined `V` and bounded poll count `X` below |
| 12 | `0D U1_HANDLER_QUIESCENT` | kernel `00` | R1 in-handler count is zero; `V = X = 0` |
| 13 | `0E U1_LAPIC_CLEAR` | kernel `00` | final R1 mask/Delivery-Status revalidation followed by clear CPU0 IRR/ISR; exact bit-defined `V/X` below |
| 14 | `0F U1_RELEASED` | kernel `00` | exact R1 release completed after the preceding proof; `V = 1`, `X = 0` |
| 15 | `10 U2_RESERVED` | kernel `00` | fresh `R2/O2/B2/T2`; same `L1`, stream/challenge zero |
| 16 | `11 U2_COMMITTED` | kernel `00` | exact U2 tuple, committed/unmasked |
| 17 | `12 C2_PHYSICAL` | kernel `00` | U2 tuple plus nonzero `G2/Q2`; bounded physical-entry delta in `V` |
| 18 | `13 C2_PENDING` | kernel `00` | exact U2 delivery made object pending; bounded delivery/repeat deltas in `V/X` |
| 19 | `14 C2_WAIT_WAKE` | kernel `00` | the blocked U2 wait generation won and became runnable; `V = 1`, `X = 0` |
| 20 | `15 C2_UART_DRAIN` | driver `01` | driver reports exact U2 bytes/hash in `V/X` |
| 21 | `16 C2_ACK` | kernel `00` | exact U2 ack after drain |
| 22 | `17 C2_RESPONSE` | raw probe `02` | probe/host observed exact second response bytes/hash in `V/X` |
| 23 | `18 STALE_U1_REJECTED` | kernel `00` | U1 tuple is rejected; `V = B2`, `X = O2`, and no U2 wake/delivery delta is credited to U1 |
| 24 | `19 ACCOUNTING` | kernel `00` | packed final bounded counters described below |
| 25 | `FF TERMINAL` | kernel `00` | every generation/value/auxiliary field zero |

`ROUTE_DISCOVERED.V` has this exact little-to-high bit layout:

- bits `0..31`: selected GSI;
- bits `32..39`: vector, exactly `0x30`;
- bits `40..47`: live BSP xAPIC ID; and
- bits `48..63`: zero.

`ROUTE_DISCOVERED.X` is:

- bits `0..15`: ISA source, exactly 3;
- bits `16..17`: resolved polarity, `01 = active high`;
- bits `18..19`: resolved trigger, `01 = edge`;
- bits `20..27`: validated IOAPIC ID;
- bits `28..59`: that controller's GSI base; and
- bits `60..63`: zero.

`U1_ROUTE_MASKED` is emitted only after the physical mask readback and the
first subsequent idle Delivery Status observation. Its `V` bit 0 is the
mask-one readback, bit 1 is Delivery-Status-idle, and bits `2..63` are zero, so
the accepted value is exactly 3. Its `X` is the number of low-dword reads up to
and including the idle observation in `1..=65_536`; send-pending through the
bound emits no success event and retains quarantine.

`U1_LAPIC_CLEAR` is emitted only after handler quiescence, a fresh serialized
redirection readback, and the later BSP snapshot. Its `V` uses the same mask
and Delivery-Status bits and is exactly 3. Its `X` bit 0 is the BSP IRR
vector-`0x30` bit, bit 1 is the BSP ISR vector-`0x30` bit, and bits `2..63` are
zero; the only accepted value is zero. A revalidated send-pending bit prevents
the BSP snapshot and emits no success event.

For one devmgr lease, `L2 = L1`; replacement generations satisfy
`R2 > R1`, `O2 != O1`, `B2 > B1`, `T2 > T1`, `G2 > G1`, and `Q2 > Q1`.
Within each driver leg the platform route generation equals the public binding
generation (`R1 = B1`, `R2 = B2`). Every C1 record carries exactly the U1
tuple, every C2 record carries exactly the U2 tuple, and no record may mix
fields. The second challenge bytes/hash and response differ from the first.

Sequences 1-2 and 15-16 carry their exact `R/O/B/L/T` tuple with `G = Q = 0`.
Sequences 3-14 carry the complete U1 tuple including `G1/Q1`; sequences 17-22
carry the complete U2 tuple including `G2/Q2`. `STALE_U1_REJECTED` carries the
complete U1 tuple while its `V/X` identify current B2/O2. `ACCOUNTING` carries
the complete current U2 tuple. Only `ROUTE_DISCOVERED` and `TERMINAL` have all
generation fields zero.

For each `C*_PHYSICAL`, `V` is a per-challenge physical-entry delta in
`1..=254` and `X = 0`. The collector fails on saturation (`0xff`) rather than
accepting an ambiguous count. The corresponding `C*_PENDING.V` is the exact
binding-delivery delta and must equal the physical delta; `C*_PENDING.X` is the
already-pending/ack-prepared repeat delta in `0..=V - 1`. `C*_ACK.V` is the
per-challenge acknowledgement delta in `1..=C*_PENDING.V` and `X = 0`.
These are the only nondeterministic per-leg ranges; their relations are exact.

For `C1_UART_DRAIN` and `C2_UART_DRAIN`, `V` is the exact challenge byte length
and `X` is FNV-1a-64 over the bytes drained from the UART into the stream. For
`C1_RESPONSE` and `C2_RESPONSE`, `V` is the exact response byte length and `X`
is FNV-1a-64 over the binary-safe response. The host run request additionally
freezes full SHA-256 identities for both nonce-bound payloads and expected
responses. Each challenge contains CR, LF, NUL, DEL, and printable bytes and
receives no newline normalization.

`ACCOUNTING.V` packs saturating eight-bit counts, low to high: physical
entries, exact deliveries, already-pending deliveries, acknowledgements,
stale/orphan entries, masks, unmasks, and releases. `ACCOUNTING.X` bits `0..7`
hold generation replacements and all other bits are zero. No accepted field
may equal `0xff`. Physical and exact-delivery totals are equal and in
`2..=254`; already-pending is in `0..=physical - 2`; acknowledgements are in
`2..=physical`; stale/orphan is in `1..=254`; masks are in `2..=254`; unmasks
are exactly 2; releases are exactly 1 at this pre-U2-finalization summary; and
replacements are exactly 1. Per-leg deltas must sum to the corresponding total
except stale/orphan, mask, and retirement activity, which occurs outside the
two live challenge windows. This permits real UART edge timing to vary without
leaving any accepted relation undefined.

The permanent controller remains the sole terminal reporter. Kernel-owned
events are recorded directly; driver/probe submissions are accepted only from
their exact generation-correlated reporter identities. An old U1 reporter,
endpoint, binding, sequence, or tuple cannot submit or satisfy a U2 event.

## 12. Required-source and provenance receipt

The following in-tree files were read before this contract or registry/index
change:

| Source | Disposition |
| --- | --- |
| `../../DW1E_WYR1D_IMPLEMENTATION_PLAN.md` | **adapt** the E0 route, edge-unmasked, quarantine, return, selector, test, and nonclaim requirements as the active authority |
| `Plans/DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md` | **adapt** the exact binding, pending/coalesced, wait, ack, finalization, COM1 protection, and parent-release invariants; replace only private physical mask policy |
| `docs/DW1_D_VALIDATION.md` | **concept** accepted selector-30 facts and explicit no-physical-IRQ stop line |
| `kernel/src/device/interrupt.rs` | **adapt** `InterruptAuthority::deliver`, wait readiness, exact binding, typed finalization; mandatory private ack-outcome refactor identified |
| `kernel/src/device/interrupt_tests.rs` | **adapt** generation/race/coalescing model coverage; retain synthetic expectations |
| `kernel/src/interrupt/mod.rs` | **adapt** vector class and external-pool reservation; no allocator imported |
| `kernel/src/arch/x86_64/acpi.rs` | **adapt** bounded immutable MADT snapshot/parsing and current CPU-topology preservation |
| `kernel/src/arch/x86_64/apic.rs` | **adapt** xAPIC validation, physical destination, EOI, and narrow IRR/ISR access boundary |
| `kernel/src/arch/x86_64/apic_live.rs` | **adapt** permanent UC volatile MMIO boundary; IOAPIC gets a separate selector/window owner |
| `kernel/src/arch/x86_64/idt.rs` and `kernel/src/arch/x86_64/mod.rs` | **adapt** one fixed present gate and selected-product-only IDT construction |
| `kernel/src/arch/x86_64/exceptions.S` | **adapt** complete timer GPR frame and CPL3 `swapgs` entry shape, not retained-frame switching |
| `kernel/src/arch/x86_64/ipi_entry.S` and `kernel/src/arch/x86_64/ipi.rs` | **adapt** complete returning IPI frame, post-EOI bounded callback, and existing e1 transport concept |
| `kernel/src/time/live.rs` | **concept** target EOI and wake publication ordering; do not import timer service policy |
| `kernel/src/wait/mod.rs` and `kernel/src/syscall/adapters.rs` | **adapt** bounded IRQ wake intents and scheduler publication after dropping object/wait locks |
| `kernel/src/arch/x86_64/rendezvous.rs`, `kernel/src/arch/x86_64/idle.rs`, and `kernel/src/arch/x86_64/syscall/live.rs` | **concept** generation-bound e1 request, post-EOI carrier safe point, idle rescan, and timer-only frame switching |
| `Plans/WYR1_C6_DEVICE_COORDINATOR_RESTART_EVIDENCE_DESIGN.md` and `kernel/src/test_support/dw1d_evidence.rs` | **adapt** selector-private identity, byte-defined checksum framing, exact reporter/generation joins, and atomic terminal transcript |

Pinned external sources were read at the exact plan revisions:

| Revision and exact file | SHA-256 | Disposition |
| --- | --- | --- |
| Fuchsia/Zircon `6a606ff7fd9b055edee6557566fb3f112df1a812`, `zircon/kernel/object/interrupt_dispatcher.cc` | `8fcf75bfa8d47d99549266f2b097041d754cccf05dbeb052d18fea3f374f6a70` | **concept** edge retrigger retention, ack distinct from delivery, and mask/deactivate/unregister before destruction; flags/ports/timestamps/ABI rejected |
| same revision, `zircon/kernel/object/resource_dispatcher.cc` | `db1bfb63e8175d25916d1abcdd4f0a0c13f6c1cc379e57145f0ec7ead7f7e678` | **concept** exclusive range validation and release lifetime; root-resource kinds and allocation model rejected |
| xv6-riscv `35b088427ef37611c38afdeed5a52a278cae38f9`, `kernel/trap.c` | `6b7d192e64c49ce729dd3b597d8ba65e452e4c37d15942bab65660a032b3de60` | **concept** returning trap, dispatch, device completion, and later scheduler decision; RISC-V/monolithic policy rejected |
| same revision, `kernel/plic.c` | `125fc60925cae8cfff87450c88faa30634e4406f1e5a16234ff49ffba5dca7ab` | **concept** controller-owned enable/claim/complete sequence; PLIC per-hart semantics are not IOAPIC/xAPIC semantics |
| same revision, `kernel/uart.c` | `6c284f94eb8fcca9c723015f366a849a441f462b99d16e3cca5880439df6a493` | **not-applicable** to E0 hardware policy except as a negative reminder that cause drain belongs to WYR1-D userspace, not the kernel ISR |
| same revision, `kernel/console.c` | `d3088059d9591e367b7b15706590e472fe38cc505b22d7d8cf03b8da5de5d699` | **not-applicable** to E0; monolithic console parsing/echo and Unix device state remain outside Deepwyrm |

The retirement review also required this supplemental official hardware
source:

| Source | Version/date | Disposition |
| --- | --- | --- |
| Intel 400 Series Chipset On-Package Platform Controller Hub Online Register Database, ID 615146, [Redirection Table Entry 0 (RTE0)](https://edc.intel.com/content/www/it/it/design/products-and-solutions/processors-and-chipsets/comet-lake-u/intel-400-series-chipset-on-package-platform-controller-hub-register-database/1.2/redirection-table-entry-0-rte0-offset-10/) | version 1.2; published date `08/09/2019`; accessed `2026-08-31` | **concept** bit 12 is RO/V Delivery Status: zero is idle and one is an injected interrupt whose delivery remains pending; masking does not retroactively cancel an already accepted message, so E0 adds the ordered idle observation before LAPIC-clear reuse proof; chipset-specific register naming is not imported |

The pinned rust-osdev `uart_16550` and linenoise sources are not E0
interrupt-controller inputs. Their register/UART and terminal/editing
dispositions remain owned by paired WYR1-D0/D2 and later WYR1-E respectively;
E0 does not use or adapt them. The plan's unspecified Fuchsia driver-framework
pieces are likewise not needed for the private kernel route: the reached DW1-D
and WYR1-C contracts already own Process/resource separation, and E0 changes no
driver framework.

All E0 external use is conceptual. No source, ABI, expression, controller
code, or license text is copied. This contract and registry metadata remain
first-party `GPL-3.0-or-later`; no notice or license-boundary change results.

## 13. Nonclaims and released seams

E0 does not claim implementation or acceptance of:

- live MADT type-1/type-2 parsing or IOAPIC MMIO;
- a present external IDT gate or physical IRQ3 delivery;
- selector 31 build, host COM2 exchange, UP/SMP run, or evidence;
- general IOAPIC/vector allocation, PIC delivery, level sources, active-low
  sources, MSI/MSI-X, x2APIC, PCI, hotplug, or physical hardware;
- UART initialization, IIR/LSR draining, FIFOs, rings, streams, `uart16550d`,
  `consoled`, console-echo, or shell behavior;
- MMIO `DeviceResource`, DMA, IOMMU, `/dev`, POSIX descriptors, or a new kernel
  stream/TTY object; or
- final DW1-E or WYR1-D security/closure review.

E1 is released to implement only the bounded MADT/route/redirection pure model.
E2 is released only after preserving this contract's private ack-outcome seam,
edge-unmasked lifecycle, lock/EOI order, stale handling, and fixed-vector
quarantine proof. Any need for a public syscall/object/ABI change, unreliable
retirement proof, or non-ephemeral external frame stops the lane for an
architecture revision rather than inventing around this gate.
