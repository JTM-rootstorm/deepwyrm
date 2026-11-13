# DW2 large-memory plan

**Status:** decided by Mike 2026-11-12 (§3). M1 is done. M2 is done at the development tier: the direct map, usercopy through it, SMEP/SMAP (§5.1–§5.2) and the RAM-sized role table (§5.3), each with its independent review. M3 is designed (§6).

**Goal:** Wyrmroot is meant to run on real machines with 64 GiB of RAM or more. On those machines one program should be able to use most of that memory. The kernel's bookkeeping should grow with the RAM installed, not with constants chosen for a small QEMU guest. The cost of a request should follow what a program actually touches.

Today one shell job gets 16 MiB, and the kernel itself would stop well short of 64 GiB even with that budget removed. This plan lists every limit found, in the order a large job would hit them, and stages the fixes so that each stage is useful on its own.

## 1. Limits today

Found by reading Deepwyrm `d26bd40` and Wyrmroot `eaa759a`. The timings come from the D7 diagnostic run in QEMU.

| # | Limit | Where | What breaks at 64 GiB |
|---|---|---|---|
| L1 | A job's budget: 4096 pages (16 MiB), 4 MemoryObjects, 10 mapping slots (3 used by its image) | Wyrmroot `system-init/src/jobs.rs` (`JOB_MEMORY_PAGES`, `JOB_MEMORY_OBJECTS`); Deepwyrm `REGION_SLOTS` | Policy. It is the first wall a job hits, but the cheapest to raise. The `MEMORY_PAGES` limit is a `u32` of pages, so the ABI allows up to 16 TiB |
| L2 | One map call publishes at most 4096 pages (16 MiB). The page-table journal records every page, about 105 bytes per page, in static storage sized for that ceiling (about 420 KiB) | `activation/primordial.rs` (`PRIMORDIAL_MAX_USER_MAPPING_PAGES`), `mm/journal.rs` | A 1 GiB map would need about 27 MiB of journal; 64 GiB, about 1.7 GiB |
| L3 | A MemoryObject's backing is one physically contiguous run | `activation/user_access.rs` `allocate_zeroed_backing` → `roles.allocate(page_count)` | A large object needs a hole of its full size. Fragmentation refuses it long before RAM runs out, and the machine's own holes (firmware, MMIO, the PCI hole below 4 GiB) cap a single object at the largest usable range |
| L4 | The free list holds at most 128 ranges, the same constant as the boot memory map | `memory/physical.rs` `PhysicalFrameAllocator<RANGE_CAPACITY>`, `lib.rs` `BOOTSTRAP_FRAME_RANGE_CAPACITY` = 128 | A free that would create a 129th hole fails with `CapacityExceeded`. Some callers panic on a failed free (for example the backing rollback in `allocate_zeroed_backing`). Long-running systems with interleaved small and large frees will reach it. Firmware maps on large machines can also come close to 128 usable entries |
| L5 | 4096 frame-role slots for the whole kernel, one per allocation, including every page-table frame | `lib.rs` `BOOTSTRAP_FRAME_ROLE_CAPACITY` | Mapping 64 GiB in 4 KiB pages needs about 32,800 page-table frames on its own |
| L6 | No direct map. The kernel reaches a physical frame through one temporary page-table entry: install it, `invlpg`, write 512 words, clear it | `mm/transition/private.rs` `with_frame`, `zero_frame_unchecked` | Zeroing costs about 6 µs per page beyond a fixed cost: 4 MiB took 50.4 ms and 8 MiB 56.7 ms. At that rate 1 GiB takes about 1.6 s and 64 GiB about 100 s, all under the global locks (D7's R1). The fixed cost of about 44 ms per new arena is not yet explained |
| L7 | Everything is eager: a map allocates, zeroes and publishes every page before it returns. A user page fault is reported as an exception, never served | `arch/x86_64/exceptions.rs`; D7 | `malloc` reserving a large arena pays for all of it at once, even if it touches little |
| L8 | 4 KiB pages only | DW0 plan §2.14 ("large pages are optional optimization work") | 512 times more page-table frames, journal entries and TLB misses than 2 MiB pages would need |
| L9 | The kernel graph check walks at most 256 table frames | `mm/activation.rs` `MAX_DEEP_TABLE_FRAMES` | Not a user limit today. A direct map built from 4 KiB pages would exceed it; one built from 1 GiB or 2 MiB pages fits |

What scales already: the frame allocator keeps no per-frame metadata, so its size does not grow with RAM. Physical addresses are checked against the CPU's reported width, up to 52 bits. The ABI's limit is per page, not per byte.

## 2. Stages

Each stage is a Deepwyrm change with its own tests, and each is useful without the ones after it. M1 is a correctness fix even at today's sizes. M2–M4 remove the scaling walls. M5 is the Wyrmroot policy that uses them.

| Stage | Change | Removes | ABI |
|---|---|---|---|
| **M1** | Make a failed free impossible. Every allocator run holds one role slot for its whole life and is freed whole, and an allocation never adds a free range. So the free list never holds more than the initial ranges plus the live runs (`free_range_bound`, with its proof, in `memory/physical.rs`), and production sizes it to that bound. The same bound covers boot reservations that split usable ranges, which could also fail the boot before. **Done 2026-11-12.** Sizing the role table and the free list from installed RAM moved to M2: storage carved from RAM needs the direct map to reach it | L4; L5 moves to M2 | none |
| **M2** | Size the frame-role table and the free list from installed RAM, carving their storage from usable RAM through the direct map. A direct map: all usable RAM mapped once in the kernel half, read-write, no-execute, supervisor-only, built from 1 GiB pages where the CPU has them (`pdpe1gb`) and 2 MiB pages otherwise. Zeroing uses `rep stosq` through it. The temporary window stays only for the bootstrap paths that run before the direct map exists. SMAP and SMEP are enabled with it | L5, L6, keeps L9 satisfied | none |
| **M3** | Scattered backing: a MemoryObject is backed by a bounded list of runs (extents), allocated largest-first, so a large object needs free memory, not a large hole. Reclamation and finalization (DW0 D0 §5) carry the list | L3 | none |
| **M4** | Chunked publication: a map call publishes in batches of at most the journal's capacity. Each batch is a complete D7 journal. If a later batch fails, the call unmaps the batches it already published and returns the error, so the call is still all-or-nothing as userspace sees it. The global locks are released between batches, which also bounds the lock-hold time (R1) | L2 | none |
| **M5** | Wyrmroot: init gives a job a budget derived from installed RAM (Mike to set the rule, for example half of RAM less the resident set), more MemoryObjects, and the D6 mapping slots. The SDK layer drops the four-arena scheme for one `mmap` per large allocation | L1 | Wyrmroot policy only |
| **M6** | Allocate on first touch: a map of anonymous memory reserves the range and publishes nothing; the first touch allocates, zeroes and maps the page, charged to the job's budget then. A fault the kernel cannot serve (budget spent, no frames) is delivered as today's exception. This shrinks M4's job to maps of existing objects | L7 | a map flag or object kind for lazily backed memory, and the fault outcome, in the schema |
| later | 2 MiB user pages for objects whose backing has 2 MiB-aligned runs (needs M3) | L8 | none |

Order: M1, then M2, then M3, M4 and M6 (M6 after M3, since it allocates into scattered backing), then M5. M2, M3 and M6 change the boot path, object finalization and fault handling, so each needs the independent security review of CLAUDE.md §1. M2 especially: a direct map gives the kernel a writable alias of every user page, which widens what a kernel bug can reach. Its mappings must be supervisor-only and no-execute. Deepwyrm currently clears CR4.SMAP at entry (`arch/x86_64/entry.rs`) and does not set SMEP. A direct map raises the value of both, so M2's review should decide whether they are enabled with it.

## 3. Decisions (Mike, 2026-11-12)

1. **Direct map, with SMAP and SMEP:** yes to both (M2).
2. **Allocate on first touch:** yes, as stage M6, not deferred.
3. **The job budget rule:** both: a fraction of installed RAM, capped or overridden by a size in the platform config (M5).
4. **Order:** M1 now; then SQLite; then M2–M6 before any port that needs large memory.

## 4. Sources used

- Deepwyrm code at `d26bd40`: `memory/physical.rs`, `memory/frame_roles/manager.rs`, `arch/x86_64/mm/transition/private.rs`, `arch/x86_64/mm/activation/{primordial.rs, user_access.rs, graph.rs}`, `arch/x86_64/mm/journal.rs`, `arch/x86_64/exceptions.rs`, `lib.rs`.
- `DW0_IMPLEMENTATION_PLAN.md` §2.14, `DW0_D0_OBJECT_HANDLE_CONTRACT.md` §5.
- Root `TOOLCHAIN_POSIX_LAYER_DESIGN.md` §5 and §8 (D6, D7), and the D7 review (`.tmp/toolchain-review/d7-journal-review.md`).
- Not read for this draft: `DW1_S2K_RUNTIME_AUTHORITY_DESIGN.md` in full. M2 changes the kernel's physical-access boundaries, so its implementation must read that design first.

## 5. M2 as built (2026-11-12)

### 5.1 The direct map (Deepwyrm `fb395be`)

- **What it covers:** exactly the allocator's initial ranges, mapped at `0xffff_8000_0000_0000 + physical` (PML4 slots 256–383, so at most 64 TiB of physical address space; a boot whose allocator owns memory above that stops). Nothing else is mapped: not the kernel image, the boot modules, firmware tables or devices. Those keep the per-CPU scratch window.
- **Leaves:** read-write, no-execute, supervisor-only. 1 GiB pages where the CPU has `pdpe1gb`, 2 MiB pages otherwise, and 4 KiB pages only at a range's unaligned ends, so no page reaches outside a range.
- **Build:** the deep-root build fills the map and maps it before activation. The PML4 entries exist before `KernelHalfBinding` captures the kernel half, so every root shares them.
- **Graph check:** accepts a direct-map leaf only with the exact flags, mapping `virtual - base`, inside one range, and as a 1 GiB page only when the CPU has them. The leaves must cover the ranges exactly, which is checked by summing their bytes. A map that overlaps the kernel image is refused. `MAX_DEEP_TABLE_FRAMES` rose from 256 to 2048 (L9). A machine without 1 GiB pages and with more than about 1.9 TiB would exceed it and stop at boot.
- **After activation:** page-table entries, zeroing (`rep stosq`) and physical byte copies of allocator frames go through the map.
- **No second memory type:** a UC leaf over direct-mapped RAM is refused. So the VT-d table pool moved onto the map, as WB, and flushes the line of each entry it writes or reads (`clflush` + `mfence`), for units that do not snoop, as Linux does. Its 64 UC leaves are gone.
- **Cost:** dev-boot `--check --sdk` time is unchanged (40 s).

### 5.2 Usercopy and SMEP/SMAP (Deepwyrm `7e2d64c`, Wyrmroot `6e0f0e6`)

- **Usercopy:** every copy re-walks each pinned, preflighted page and copies through the direct map. This covers deferred outputs and the atomic-wait load. The kernel never dereferences a user address, and a copy no longer needs CR3 to hold the target root.
- **New refusal:** preflight refuses a user page with no direct-map address, such as mapped device registers.
- **SMEP and SMAP:** each CPU turns them on, where it has them, when it installs its syscall boundary. The first CPU's set is recorded, and a CPU with a different set fails its install. The IF-clear boundary check also requires the recorded bits to stay set. AC is never set, because no STAC window exists.
- **dev-boot CPU:** dev-boot now gives the guest `qemu64,+pdpe1gb,+smep,+smap`.

### 5.2a Security review of 5.1–5.2

**Reviewer:** Claude Opus 5.5 (low effort), 2026-11-12, at Deepwyrm `fb395be` and `7e2d64c` (base `ae3c872`) and Wyrmroot `6e0f0e6`. Method: code reading plus the host unit tests; no guest runs. No Critical defect.

- **D1 (High, confirmed): fixed.**
  - The defect: user code may set RFLAGS.AC, interrupt delivery keeps it, and only SYSCALL cleared it. So interrupt and exception handlers entered from such a thread ran with SMAP lifted. Before M2, it also let an e1 stop rendezvous halt the CPU on its AC check.
  - The fix: every stub now clears AC (`e57eb60`).
  - The regression test: the timer handler fails closed on AC (`b5670ea`), and `bin/cpu-hog` spins with AC set (Wyrmroot `6c5170f`). With the check but without the stub fix, dev-boot stopped on "timer interrupt handler entered with RFLAGS.AC set"; with the fix it passes.
- **R1 (High risk), Meltdown: resolved by Mike's decision (2026-11-12) to refuse affected CPUs.**
  - The risk: every root maps all allocator RAM supervisor-only, and there is no KPTI. Before M2 the kernel image was already exposed the same way.
  - The decision: an Intel CPU without RDCL_NO in IA32_ARCH_CAPABILITIES fails its syscall-boundary install, before any user code runs. KPTI would be needed only to support such CPUs.
- **R2 (Low), indirect SMAP evidence: fixed.** The kernel reports on serial which protections every CPU runs with. dev-boot requires `smep and smap on`, and the guest CPU has both. A CPU without SMEP or SMAP still boots, without that protection, and the serial line says so.
- **R3 (Low), accepted:** the AP trampoline page has a writable direct-map alias. Its executable identity mapping is retired once the APs park.
- **R4 (Low), accepted:** 1 GiB pages are gated on the bootstrap CPU's CPUID only. Every CPU in one machine reports the same paging features.
- **R5 (Low), accepted:** a memory map fragmented enough to exceed 2048 tables stops the boot; it is not unsafe. The quadratic edge lookup affects only boot time.
- **R6 (Low), accepted:** a large leaf could straddle an MTRR boundary only inside one usable range, and usable RAM is write-back throughout.
- **R7 (Low), intended:** usercopy refuses user pages that are not allocator RAM.
- **R8 (Low): fixed.** The layout check now tests a kernel segment's whole interval.
- **R9 (Low): fixed.** Two stale comments.
- **R10 (Low), accepted:** the guest-test-only usercopy in `activation/test_support.rs` still uses user addresses. It is in no product, and under SMAP it would fault loudly, not silently.

### 5.3 The RAM-sized role table (Deepwyrm `e6a07c3`, review fix `aae63fc`)

Designed below, approved by Mike (2026-11-12); §5.3a records what was built.

The table is more than one array. Three things the plan did not list scale with it:

1. **Hot linear scans.** `table_identity` runs three times on every user page walk, which means on every usercopy and every return to user. It, `next_slot` and the lookups by physical address scan every slot.
   - Design: a free-slot stack, and a per-frame index over the direct-mapped ranges (one `u32` slot number per 4 KiB page, 0.1% of RAM).
   - Roles outside allocator RAM (image, modules, device MMIO) are few, and keep a bounded list.
2. **Slot-indexed stack arrays.** The empty-hierarchy proof (`observed`, `levels`) and process teardown (`disconnects`) keep arrays sized by role capacity on the stack. At 4096 roles that is about 100 KiB already.
   - Design: the proof marks slots with an epoch stored in the table, and keeps a per-owner table count, so finishing needs no full scan.
   - Teardown disconnects the root's 256 low-half entries atomically, then reclaims the subtree bottom-up by walking it again. The hardware can no longer reach it, so it needs no journal.
3. **Growth.** The manager starts with today's static capacity, then, right after activation, re-homes its slots, free list and index into one run carved from RAM through the direct map. Slot numbers and generations are kept, so issued identities stay valid. Size: one slot per 2 MiB of allocator RAM plus 4096, and the free list by `free_range_bound`.

Teardown (item 2) changes object and address-space finalization, so it needs the independent review this plan already requires of M2.

### 5.3a As built

- **Growth** (`memory/growable.rs`, `FrameRoleManager::grown_layout`/`adopt_storage`, `ActiveDeepPaging::grow_frame_roles`, called in `lib.rs` right after activation): the slots, the free-slot stack, the start index and the allocator's free list move into one run allocated first-fit and reached through the direct map. Slots: the 4096 boot slots plus one per 2 MiB of allocator RAM; the dev-boot guest (2 GiB) logs `[DW0][INFO][memory] frame-role slots=5079`. The free list is `free_range_bound(initial ranges, 0, slots)`, and at least one entry longer than the boot list. Slot numbers and generations are kept. The run takes the permanent `RoleTableStorage` role, which no API frees.
- **Slots and lookups:** a slot comes off the free-slot stack; a slot whose generation is spent is retired, not reused. The start index holds, for each allocator page, one plus the slot of the dynamic role starting there; `table_identity` reads it (it scans the boot table only before growth).
- **Proof and teardown:** each committed PML4 counts the committed tables below it (`publish_staged_table` adds, `reclaim_preflighted_table` subtracts; the count is per root, which is per owner because an owner has one PML4). The proof marks observed slots with an epoch, and finishes only when the observed count equals the root's count and no role changed since it began (a role version). Teardown clears only the root's 256 low-half entries in one batch, then, after the H0 barrier, walks the disconnected tables again and reclaims each after its children. Freed tables keep their entries; every consumer of a fresh allocation zeroes or writes it first (`FrameRoleKind::AllocatedUninitialized`).
- **Deviation:** roles outside allocator RAM (kernel image, transition tables, modules, BARs) have no separate bounded list. Their lookups (`validate_external_pages`, `validate_kernel_image_page`, `owns_any`) still scan every slot, but run only at boot. The duplicate-root check on PML4 creation also still scans (review R4).
- **Validation:** kernel host tests (1156, five new for growth, refusals, slot retirement, the grown free list and proof invalidation, one for D1), fmt and clippy. dev-boot `--check --sdk` with Wyrmroot `d5ac3af`: 11 of 12 runs passed at 35–37 s, against 63 s before; the scans this removes ran on every user page walk, which is the likely cause of the 41 s/63 s spread seen before. One run (on `e6a07c3`) hung after the shell exited: QEMU did not exit in the check's 180 s, and COM1 shows no retirement or panic record after the boot lines. Its cause is not found; it has not recurred in 11 runs.
- **Independent review:** Claude Opus 5.5, default effort, 2026-11-12, Deepwyrm `e6a07c3` against `31d352d`. No Critical or High. D1 (Medium: below about 780 MiB of allocator RAM growth was refused and boot panicked, since the free-list bound is shorter than the 4503-entry boot list) fixed in `aae63fc` with a production-shaped test that fails without it. R2 (freed tables keep stale entries) taken as documentation. Accepted, Low: R1 (the run is one contiguous first-fit allocation, 64 MiB of index at 64 GiB; a map too fragmented for it panics at boot), R3 (a second proof on the same root between finish and reclaim panics; the only caller holds the manager exclusively throughout), R4 (the remaining O(slots) scans above), R5 (`start_position` scans the initial ranges per lookup, at most about 400). Open question from the review, not new in this change: the proof does not check that no other owner's tables point into this owner's hierarchy.


## 6. M3 design (2026-11-12)

Read for this design: Deepwyrm `ebfc46b` (`memory/object.rs`, `memory/object/lease.rs`, `memory/address_region*.rs`, `memory/frame_roles*.rs`, `arch/x86_64/mm/journal{.rs,/publisher.rs}`, `arch/x86_64/mm/activation/{user_access.rs,primordial.rs}`, `boot/primordial/construction/authority.rs`, `device/dma{.rs,/live.rs}`, `device/pci.rs`, `syscall/adapters{.rs,/address_region.rs}`, `object/finalizer.rs`) and `DW0_D0_OBJECT_HANDLE_CONTRACT.md` §5.

### 6.1 What assumes one run today

- `object_range()` (object.rs) computes `physical_start = record.physical_start + offset` for every map, protect and unmap rebuild, and for `dma_physical_range`. `ObjectRecord.physical_start` duplicates the grant's start.
- The publisher: `validate_mapping_batch` checks a whole mapping against one role record, and `page_descriptor` computes `physical_start + offset`. `publish_pages` compares only the first page of a run between the old and new mappings and skips the run when they match, which is sound only if both are linear.
- `allocate_zeroed_backing` (user_access.rs) and its boot twin `LivePlatform::allocate` (primordial.rs) take one run; `write_backing` (boot ELF segments, stack, bootfs up to 32 MiB) writes linearly from the start.
- `dma_map` resolves one physical start; `DmaDomains::map` already maps page by page onto a contiguous IOVA range.
- Not affected: usercopy translates through the page tables and the direct map, never through object backing; futex keys use object offsets; the journal's per-leaf `authorize_leaf` and publish recheck already work per page. DeviceMmio (one BAR) and ImmutableBootModule (no production caller) stay single-run.

### 6.2 Where the run list lives: the frame-role manager

The publisher holds only `&mut FrameRoleManager` while the object authority is held by the prepared replace for the whole call, and `Mapping` is copied into each of a job's 10 region slots. So a mapping cannot carry a list of runs, and the publisher cannot ask the object authority. The role manager can: every run is already its own role slot.

- An allocator-owned object backing is a **chain of runs**. Each run is one role slot with record `ObjectBacking { head, object_offset, next }`: the head run's identity names the backing, `object_offset` is where the run starts in the object, `next` is the following run's slot and generation (or none). The head is the run at offset 0.
- `ObjectBackingGrant` stays the one move-only typed token D0 §5 requires: the head identity, the total length and the run count. Cancelling it walks the chain and frees every run whole, so M1's invariant (each run holds one slot for life and is freed whole) and the free-list bound still hold.
- A chain holds at most `MAX_BACKING_RUNS` = 64 runs. That bounds a page lookup and makes a request that would need more runs fail with no memory rather than degrade.
- `MemoryObjectRange` keeps the head identity and the object offset and drops `physical_start`; `ObjectRecord.physical_start` goes. Resolution is the role manager's: `resolve_object_page(head, offset) → (run identity, physical)`, walking the chain (at most 64 steps). A sequential walk over a mapping keeps its place in the chain, so a whole mapping costs one chain walk.

### 6.3 Allocation: largest first

`allocate_scattered(pages)` takes runs of `min(remaining, largest free run)` until the request is met, failing (and freeing what it took) past 64 runs or when memory runs out. The physical allocator gains a largest-free-run query. When memory is not fragmented this is one run, exactly as today. Zeroing goes through the direct map run by run. The user path and the boot path share one function instead of today's two copies.

### 6.4 Consumers

- **Publisher:** `validate_mapping_batch` validates a mapping as the runs that cover `[offset, offset + len)`, each against its own record. `page_descriptor` resolves through the chain. The skip-a-run check compares the backing head and object offset instead of the first page's physical address: two mappings of the same object at the same offset map the same frames page by page, linear or not.
- **Boot writes:** `write_backing` writes page by page through `resolve_object_page`.
- **DMA:** `dma_physical_range` returns the validated range; the carrier resolves it page by page through the role manager and `DmaDomains::map` takes the page list (or a resolver) instead of one start, keeping the contiguous IOVA. A DMA range may cross runs.
- **Finalization:** `complete_memory_finalization` and the two boot rollback paths cancel the whole chain through the grant.

### 6.5 Steps

1. Role manager: chain records, `allocate_scattered`, `resolve_object_page`, range validation over a chain, whole-chain cancel; host tests including fragmentation (a request larger than the largest hole succeeds), the 64-run limit, and rollback.
2. Object authority and ranges: drop `physical_start` from records and ranges.
3. Publisher: per-page resolution, chain validation, the skip check.
4. Allocation users: `allocate_zeroed_backing`, the boot allocator and `write_backing`.
5. DMA.
6. Independent security review (CLAUDE.md §1: object finalization and the physical-access boundary change), then `dev-boot --check --sdk`.

Each step keeps the tree building and its tests passing; until step 4 every backing is one run, so behavior does not change before it.

### 6.6 Open choices (defaults taken unless Mike says otherwise)

- `MAX_BACKING_RUNS` = 64. Larger costs only lookup time; smaller fails earlier under fragmentation.
- No minimum run size: a fragmented request may use 4 KiB runs. 2 MiB user pages (later stage) will want 2 MiB-aligned runs and can add a preference then.
