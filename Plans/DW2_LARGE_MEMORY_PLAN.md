# DW2 large-memory plan

**Status:** decided by Mike 2026-11-12 (§3). M1 is done. M2 is done at the development tier: the direct map, usercopy through it, SMEP/SMAP (§5.1–§5.2) and the RAM-sized role table (§5.3), each with its independent review. M3 is done at the development tier (§6.9), with its independent review (§6.9a). M4 is done at the development tier: batched publication (§7) and, as M4b, calls made in steps so the global locks are held one step at a time (§7.2), each with its independent review. M6 is done at the development tier (§8.10), with its independent review (§8.11).

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
| **M7** | Fragmentation that stays fast (§6.8): the buddy allocator with the smaller role table, the object index for fragmented eager backings, then compaction. Carries M3 R1 and R4 and M4b R2 (§9) | L3's slow path | none |
| **M8** | Lock scope and accounting: per-group usage counters instead of the linear registry scan, a first touch that does not serialise every CPU on the global T, and stepped calls that yield the CPU at their safe points. Carries M4b R3 and the M6 open items (§9) | — | none |
| **M9** | The OOM killer (§6.7): kernel mechanism (per-job accounting, a low-memory signal) with Wyrmroot choosing the victim. Carries M6's overcommit (§9) | — | Wyrmroot policy |
| later | 2 MiB user pages for objects whose backing has 2 MiB-aligned runs (needs M3) | L8 | none |

Order: M1, then M2, then M3, M4 and M6 (M6 after M3, since it allocates into scattered backing), then M5. Then M7, M8 and M9 (Mike, 2026-11-13). M2, M3 and M6 change the boot path, object finalization and fault handling, so each needs the independent security review of CLAUDE.md §1. M2 especially: a direct map gives the kernel a writable alias of every user page, which widens what a kernel bug can reach. Its mappings must be supervisor-only and no-execute. Deepwyrm currently clears CR4.SMAP at entry (`arch/x86_64/entry.rs`) and does not set SMEP. A direct map raises the value of both, so M2's review should decide whether they are enabled with it.

## 3. Decisions (Mike, 2026-11-12)

1. **Direct map, with SMAP and SMEP:** yes to both (M2).
2. **Allocate on first touch:** yes, as stage M6, not deferred.
3. **The job budget rule:** both: a fraction of installed RAM, capped or overridden by a size in the platform config (M5). **The fraction (Mike, 2026-11-13):** half of the RAM free at boot, after the kernel and resident services, for each job, capped by the platform config's size when one is set.
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
- A chain has no run limit (Mike, 2026-11-12: a request fails only when RAM is actually exhausted, §6.7). A lookup is bounded by the object's page count, since every run is at least one page.
- `MemoryObjectRange` keeps the head identity and the object offset and drops `physical_start`; `ObjectRecord.physical_start` goes. Resolution is the role manager's: `resolve_object_page(head, offset) → (run identity, physical)`, walking the chain. A sequential walk over a mapping keeps its place in the chain, so a whole mapping costs one chain walk.

### 6.3 Allocation: largest first

`allocate_scattered(pages)` takes runs of `min(remaining, largest free run)` until the request is met, failing (and freeing what it took) only when memory runs out. The physical allocator gains a largest-free-run query. When memory is not fragmented this is one run, exactly as today. Zeroing goes through the direct map run by run. The user path and the boot path share one function instead of today's two copies.

### 6.4 Consumers

- **Publisher:** `validate_mapping_batch` validates a mapping as the runs that cover `[offset, offset + len)`, each against its own record. `page_descriptor` resolves through the chain. The skip-a-run check compares the backing head and object offset instead of the first page's physical address: two mappings of the same object at the same offset map the same frames page by page, linear or not.
- **Boot writes:** `write_backing` writes page by page through `resolve_object_page`.
- **DMA:** `dma_physical_range` returns the validated range; the carrier resolves it page by page through the role manager and `DmaDomains::map` takes the page list (or a resolver) instead of one start, keeping the contiguous IOVA. A DMA range may cross runs.
- **Finalization:** `complete_memory_finalization` and the two boot rollback paths cancel the whole chain through the grant.

### 6.5 Steps

1. Role manager: chain records, `allocate_scattered`, `resolve_object_page`, range validation over a chain, whole-chain cancel; host tests including fragmentation (a request larger than the largest hole succeeds) and rollback. (The 64-run limit test went with the limit, §6.7.)
2. Object authority and ranges: drop `physical_start` from records and ranges.
3. Publisher: per-page resolution, chain validation, the skip check.
4. Allocation users: `allocate_zeroed_backing`, the boot allocator and `write_backing`.
5. DMA.
6. Independent security review (CLAUDE.md §1: object finalization and the physical-access boundary change), then `dev-boot --check --sdk`.

Each step keeps the tree building and its tests passing; until step 4 every backing is one run, so behavior does not change before it.

### 6.6 Open choices (defaults taken unless Mike says otherwise)

- ~~`MAX_BACKING_RUNS` = 64~~: dropped, see §6.7.
- No minimum run size: a fragmented request may use 4 KiB runs. 2 MiB user pages (later stage) will want 2 MiB-aligned runs and can add a preference then.

### 6.7 Allocation fails only at real exhaustion (Mike, 2026-11-12)

Mike: any number of programs should run as long as together they do not ask for more RAM than exists; an OOM killer may come later. Two parts of the design above broke that, and change:

- **No run limit per object.** A 64-run cap would fail a fragmented request with RAM still free. Lookup cost grows with the run count instead; sequential walks (publisher, zeroing, boot writes, DMA) keep their place in the chain, so they stay linear in pages.
- **One role slot per allocator page** instead of one per 2 MiB. Every run takes one slot and holds at least one page, so slots cannot run out before pages do; the free-list bound (M1) follows the slot count. This costs one `RoleSlot` per 4 KiB of RAM, so `RoleSlot` is kept small. The grown-table change lands with M3 step 1.
- **Not in M3:** other fixed per-kernel limits that could stop a new program while RAM is free (object, handle, task tables) need their own survey, and an OOM killer is policy: the kernel would supply mechanism (per-job memory accounting, a low-memory signal, job termination already exists) and Wyrmroot would choose the victim (CLAUDE.md §6).

### 6.8 Later: fragmentation that stays fast (Mike, 2026-11-12; not M3)

Mike: fragmented memory must not make the kernel slow; this and the OOM killer come after M3. Three places get slow as fragmentation grows, and each has a fix that keeps M3's interfaces (`resolve_object_page` and the in-order segment walk), so M3 does not need redoing:

1. **Page lookup in an object** (a chain walk, linear in runs). Once a backing exceeds a small run count (about 16), it gets a **per-object index**: a 512-way radix tree keyed by object page, shaped like a page table, whose leaves name the run and physical page. Lookup is at most 4 steps however fragmented the object is. Index nodes are allocator pages under their own role, owned by the backing and freed with it, about one node per 2 MiB of object. Short chains keep the plain walk.
2. **The physical allocator** (first-fit over a sorted free list, and the largest-run query, both linear in free ranges). Replace it with a **buddy allocator**: power-of-two blocks in per-order free lists with a bitmap, so allocation, freeing, merging and the largest-free-block query are each O(log memory). The M1 free-list bound goes away with it. Scattered allocation then takes the largest available blocks.
3. **Fragmentation itself.** Buddy merging keeps fragmentation low. Where it does not, **compaction** moves object pages to make room: copy, republish the mappings through the journal, and shoot down stale TLB entries. Pages pinned for DMA or by an in-flight operation are not moved. It runs when a large request fails, before the OOM path.

4. **The role table's size** (M3 review R1). M3 gives every allocator page a role slot, about 104 bytes per 4 KiB page (2.5% of RAM) in one contiguous run carved at boot. With the buddy allocator, shrink `RoleSlot` (move the fields only page tables use out of it) to roughly halve that, and carve the table from the largest buddy blocks rather than one run, so a fragmented boot map cannot stop the boot.

Order: the buddy allocator first, since it also speeds up today's single-run allocation, then the object index, then compaction; the role-table work goes with the buddy allocator. The OOM killer (§6.7) comes after compaction, so it only runs when memory is really full, not merely fragmented.

### 6.9 M3 as built (2026-11-12)

Deepwyrm `502ad10` (step 1), `18b1622` (steps 2, 3 and 5 together: the publisher and DMA were the users of the removed physical start), `c4ba18e` (step 4), review fixes `7f1b688` and the commit recording this section.

- **Chains** (`memory/frame_roles/chain.rs`): role variants `BackingAllocated(ChainLink)` and `ObjectBacking(ChainLink)`, a link being head, object page and next run. Every walk checks each run's role, head and starting page, so stale, foreign and cyclic links fail. `allocate_backing` takes the largest free run first; `allocate_zeroed_backing` is the one path for the boot and user allocators and frees every run if a page fails to zero. Boot modules and BARs are one-run chains.
- **Lookup:** `object_segments` validates a range once; `BackingCursor` with `resolve_at` keeps a place in the chain, so the publisher (one cursor per side), journal leaf authorization, DMA and boot writes cost pages plus runs. A cursor grants nothing: each step revalidates against the head, and a stale place restarts there.
- **Consumers:** object records and ranges carry no physical start. The publisher's protect-in-place and skip checks compare backing and object offset. DMA resolves each page under P, taken before the DMA lock, onto one contiguous IOVA range.
- **Slots:** one per allocator page (`GROWN_SLOT_PAGES` = 1), so slots run out only with pages. `RoleSlot` is 80 bytes; with the start index, free-slot stack and free list the grown table costs about 104 bytes per 4 KiB page, about 2.5% of RAM, in one contiguous run carved right after activation (review R1).
- **Validation (development tier):** 1172 kernel host tests and clippy pass; the production kernel and the `memory-mapping` selector compile for `x86_64-unknown-none`; one `dev-boot --check --sdk` passed at `c4ba18e` and again at `7f1b688`.

### 6.9a Security review of M3

**Reviewer:** Claude Opus 5.5 (low effort), 2026-11-12, at Deepwyrm `c4ba18e` (base `37c37ae`), then the fix at `7f1b688` (base `c4ba18e`). Method: code reading plus host unit tests; no guest runs. No Critical or High defect; no way found for a mapping, DMA mapping or boot write to reach a frame the object does not own, no double or partial free, and no panic userspace can reach. The P → `LIVE_DMA` order was checked: no `LIVE_DMA` section takes P.

- **D1 (Medium, confirmed): fixed** (`7f1b688`). Every page was resolved from the chain head, twice, so a publish, DMA map or boot write cost pages × runs, contrary to §6.2 and §6.7. The cursor makes in-order walks linear; the re-review found no defect in it and confirmed the cost. Its one Low test gap (a cursor aimed at another live backing's run) is closed by a test in the commit recording this section.
- **R1 (Low/Medium), deferred to §6.8 (Mike, 2026-11-13):** the grown table is about 2.5% of RAM in one contiguous run, and boot stops if no such run exists. Shrinking `RoleSlot` (fields only page tables use) would roughly halve it; that is §6.8 item 4.
- **R2 (Low), accepted:** whole-table scans (`owns_any`, external imports, `check_invariants`) are now linear in pages; every caller is at boot or in tests.
- **R3 (Low): fixed** (`7f1b688`). A run being allocated reports `FrameRoleKind::BackingAllocated`, not `AllocatedUninitialized`.
- **R4 (Low), deferred to §6.8:** allocation costs runs × free ranges (the allocator's linear scans).

## 7. M4 as built (2026-11-13)

Deepwyrm `321571d`, with review fixes in `35daf2e`; both pass `dev-boot --check --sdk`. Committed unsigned (Mike, 2026-11-13); re-sign before any push.

- **Batches.** `X86AddressSpacePublisher::publish_pages` publishes a change in address order, one journal at a time. A batch ends before a page that might not fit (`has_room_for_page`: every page stages exactly four entries and one invalidation) or that needs a table the pool has run out of. A batch may start mid-stretch: two linear mappings that agree at one page agree on the whole stretch.
- **Tables.** Between batches the pool is refilled to what the caller gave it, through `AtomicPageTableTarget::zero_table_frame`. The map syscall sizes its pool for one 16 MiB batch.
- **Pins.** Once a change needs a second batch, the whole changed span is closed to new user pins (`begin_mutation_span`, held by `TrackedActiveTarget`) until the call ends.
- **Failure.** If a later batch or a refill fails, the published batches are undone by publishing the reverse change, which only rewrites leaves under tables left in place, so it needs no candidates. The call returns the error with the mappings unchanged; the tables built stay with the root until teardown. `failed_after_publishing` makes the coherency publisher shoot the span down anyway.
- **Not yet:** the global locks T and P are still held for the whole call (M4b).
- **Not exercised in a guest:** no guest program maps more than 16 MiB while a job's budget is 16 MiB (L1, M5). The host tests (`journal/batch_tests.rs`) cover batching, refills and undoing a map, an unmap and a protect.

### 7.1 Security review of M4

**Reviewer:** Claude Opus 5.5 (default effort), 2026-11-13, at Deepwyrm `321571d` (base `e2bbd41`). Method: code reading plus host unit tests. No Critical or High defect. Batch cuts, mid-stretch starts, the room bound, the undo's independence from candidates, the pin span and candidate accounting were checked and found sound, and a failed call's shootdown still precedes the release of its leases.

- **D1 (Medium, confirmed): fixed by M4b (§7.2; Mike's choice of design, 2026-11-13).** One call now holds T and P for time that grows with the size userspace asks for (tens of milliseconds per 16 MiB, twice on failure), contrary to §2's M4 row. Object creation already zeroes its backing under P alone, so M4b bounds both: the locks are released between batches, and creation zeroes in chunks.
- **R1 (Low): fixed** (`35daf2e`). A call refused on identity could report a stale undone-batches flag; `publish_replace` now clears it first.
- **R2 (Low), open:** teardown of a mapping over 16 MiB holds the pin span over the whole mapping; a pin overlapping it panics, as a pin overlapping one batch did before.
- **R3 (Low), accepted:** a racing usercopy pin in the same address space now sees `Conflict` for the whole call, not one batch.
- **R4 (Low), accepted:** tables built by undone batches stay until teardown, uncharged, as after a map and unmap.
- **Test gaps:** G2 and G3 (undoing an unmap and a protect, a failed refill) are closed in `35daf2e`. Open: G1, `TrackedActiveTarget`'s span on the host (it wraps the live scratch target); G4, a batch starting mid-run of a multi-run backing; G5, a bound on lock-hold cost, which M4b addresses.

### 7.2 M4b as built (2026-11-13)

Deepwyrm `0e02d55` (calls in steps), `3017325` (creation zeroed in steps), review fixes `72bbcfb`; each passes `dev-boot --check --sdk`. Committed unsigned.

Mike chose (2026-11-13) to run a large call as a chain of ordinary calls rather than reserve an in-flight range: S cannot be held across a release of T and P (lock order T, P, S), and a lease held across holds would turn ProcessExit into `BAD_STATE`.

- **Steps.** An `AddressRegionMap`, `Unmap` or `Protect` larger than 16 MiB (one journal batch) is a chain of complete family-G transactions of at most 16 MiB, each through its own holds and shootdown, with a safe point between them (`syscall/region_steps.rs` plans the chain; `handle_address_region_mutation` runs it). A call of 16 MiB or less, or a misaligned one, runs exactly as before.
- **Placement.** The first step of an allocator-placed map finds room for the whole map (`map_anywhere_with_room`); later steps are FIXED after it.
- **Merging.** Pieces of one object that continue each other in address, object offset, captured authority (object and ceiling) and protection merge in the model (`push_spec`), so a chain leaves the slots and leases one call would. A merging map gives its authorization pin to the merged lease; the displaced pin is released as surplus. This applies to every map, unmap and protect.
- **Before the first step** an unmap or protect checks its whole range (rights, inside the region, wholly mapped) and snapshots the protections over it; a failure is refused with one call's status before any change.
- **Failure.** A failed map step unmaps the steps made; a failed protect step restores the snapshot. The undo is best effort: an undo step that fails is skipped. A failed unmap step is retried four times, each after a safe point, then the call returns the error with the steps made left unmapped; after the whole-range check only a transient pin or a concurrent change can fail one.
- **Creation.** `MemoryObjectCreate` allocates its backing under P, zeroes it 16 MiB at a time with P taken per step, and makes it the object's backing under P (`zero_backing_in_steps`). The frames are reachable only through the `BackingAllocation` in the facade frame.
- **Semantics that changed (§2's M4 row said all-or-nothing):** other threads can see a call's intermediate state; a caller stopped between steps leaves the steps it made, and an allocator-placed map's address is then never returned; an unmap can end partial as above. Mike accepted these with the design.
- **Not exercised in a guest** until M5 raises the job budget past 16 MiB; the host tests cover the plan, merging, the whole-range check and zeroing in parts.

### 7.3 Security review of M4b

**Reviewer:** Claude Opus 5.5 (default effort), 2026-11-13, at Deepwyrm `0e02d55` and `3017325` (base `aa0b569`). Method: code reading plus host unit tests. No Critical or High defect. Phase revalidation across steps, a caller stopped between steps, pin and lease accounting with merging, what may merge, protect's undo (rechecked for ceiling and W^X), FIXED placement after the first step, and creation's frames between zeroing steps were checked and found sound.

- **D1 (Medium): fixed** (`72bbcfb`). An unmap in steps over a gap, or past the region's end, unmapped the steps before it; the whole range is now checked first.
- **D2 (Low): fixed** by this section (the code cited it before it existed).
- **D3 (Low): fixed** (`72bbcfb`). A full region again reports `Capacity` before `Overlap` for a piece that merges with nothing.
- **R1 (Low), accepted:** each step resolves its handles again, so a handle closed and reused between steps retargets later steps or the undo. It needs MODIFY on the region, so nothing gains authority.
- **R2 (Low), open:** one step's hold still grows with the backing's run count (`chain_totals` per mapping, zeroing from the chain's head); §6.8's object index addresses it.
- **R3 (Low), open:** a call in steps passes safe points but never yields the CPU; creation's zeroing has no safe point, its time bounded by the quota.
- **R4 (Low), accepted:** a protect in steps can refuse a W+X alias that one call would have avoided, by creating it mid-chain. Stricter, not a bypass.
- **R5 (Low), accepted:** pieces left by a stopped caller or a failed undo keep their leases until region teardown.
- **R6 (Low), open:** §7.1 R2's window widens, since a map's output pin lives for the whole chain.
- **R7 (Low), open:** concurrent creates can still allocate past the quota before admission, as before.
- **Test gaps, open:** the facade loop (stop between steps, a published inner step, the output) and the snapshot capture are live-only; no test finalizes an object after a merge; no test of a zeroing step failing mid-allocation.


## 8. M6 design: allocate on first touch (2026-11-13)

Sources: this plan's §2, §6.8 and §7, `DW0_D0_OBJECT_HANDLE_CONTRACT.md` §5–§7, `DW0_H0_SMP_CONCURRENCY_CONTRACT.md` §12, `DW1_B0_TIMER_RETURN_PREEMPTION_DESIGN.md` (the returning-entry precedent), the cross-personality doctrine §8 and §13, `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md`, and Deepwyrm code at `861ff86`. This text is the design as revised after two review rounds (§8.9).

### 8.1 Decisions (Mike, 2026-11-13)

1. **An object create flag**, not a map flag. Whether a page has a frame yet is a property of the object's backing, and every map of the object behaves the same.
2. **The §6.8 per-object radix index, built now,** for objects with the flag. Eager objects keep their chains.
3. **Kernel touches fill pages in.** A syscall copy, an address wait and `dma_map` give a missing page a frame first.
4. **The creator pays, and a commit call gives receivers a guarantee.**
   - Every frame an on-demand object gains (its pages and its index nodes) is charged to the object's own registry slot, under the tag it was created with, whoever touched it.
   - A new `memory_object_commit` fills in a range up front. When it cannot, it returns a status rather than killing anyone.
   - A process that receives an on-demand object and needs its touches to be safe commits the range on receipt, or refuses the object. Object info reports the flag.
   - The first round chose "the toucher pays". The second round showed it does not protect the receiver (§8.9 N2), and that it needs an account table that dead groups can fill (N4), so Mike chose this instead.
5. **Everything a touch allocates is charged.** The page and index nodes go to the object. Page tables built by a fault or a fill-in go to the faulting Process's own registry slot, under the Process's tag. Page tables built by an eager map stay uncharged; they are at most 1/512 of the charged backing.

Admission (doctrine §13): serving a page fault is a privileged VM state transition that userspace cannot compose. Deepwyrm has no user exception delivery, and a commit syscall alone would leave every touch racing a fault that kills the process. The operation is native and personality-blind. `memory_object_commit` passes on its own: only the kernel can give an object frames, and it is the one recoverable way to learn that it cannot. Reservation and commit modes as a mapping property, a shared zero page and decommit stay out of the kernel.

### 8.2 ABI

- **The create flag.**
  - `DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND = 0x1` is the first create flag, and the supported mask becomes 0x1.
  - Every page reads as zero until it is written, as today.
  - Creation charges one `MEMORY_OBJECT` and one page, the index root.
  - `byte_len` is bounded by the index's four levels, 2^36 pages.
- **Object info reports the flag.**
- **`memory_object_commit(memory_object, offset, byte_len)`** needs `MAP` on the object, the right a holder needs to map and touch it anyway.
  - It gives every page of the range a frame, charged as a touch is. It works in steps of at most 16 MiB, releasing the locks between steps.
  - It returns `SUCCESS`, `NO_RESOURCES` (quota) or `NO_MEMORY` (frames).
  - Pages committed before a failure stay committed.
  - On an eager object it succeeds and changes nothing. Ranges are checked as for a map.
- **Unservable faults.** A user fault on an on-demand page that cannot be served terminates the process with `DW_TERMINATION_RESOURCE_POLICY`, a constant that exists and is unused today.
  - The record carries the page-fault exception type, the fault address, and the `#PF` error code in its detail, as every page-fault record does.
  - Quota and frame exhaustion share the reason, because the supervisor's recovery is the same. Cause-carriage §3.1 permits that collapse.
  - Every other fault ends exactly as today, with a byte-identical record.
- **Fill-in failures.** Syscall copies and address waits that cannot fill in a page return `NO_RESOURCES` or `NO_MEMORY`, and so does `dma_map`. An address outside any on-demand mapping stays `BAD_ADDRESS`.
- **Wyrmroot repins** (CLAUDE.md §7), since the schema change alters the ABI fingerprint.

### 8.3 Backing: the per-object index

- **Shape.** An on-demand backing is a 512-way radix tree keyed by object page, sized at creation to the object's page count, at most four levels. The root and interior nodes are allocator pages with new roles: `IndexRoot { pages, levels }` and `IndexNode { owner, place }`.
- **Entries.** An entry holds the raw role identity of a child node, or of a committed page with role `ObjectPage { owner, object_page }`. Zero is the empty entry. Role identities are never zero, so an empty entry cannot decode to a frame.
- **Checked walks.** Every step checks the entry's role against the root (`owner`), its level and its place. A stale, foreign or misplaced entry fails, as chain walks do.
- **Node access.** The manager reads and writes node pages only through a narrow access trait: the direct map in the kernel, and a model in host tests.
- **Adding pages and nodes.** They are added only under P. A frame is zeroed before any entry names it. A commit takes every frame it needs before linking any of them, so it either links all of them or changes nothing.
- **The grant** names the root, with kind `OnDemand`. Release walks and checks the whole tree, then frees every page and node.
- **Resolution.** The resolution interface (`resolve_at`, `object_segments` and the cursor) gains a third answer: *absent*, for a page inside the object that has no frame. Only an on-demand backing gives it. Eager backings are unchanged.

### 8.4 Charging

- **Usage stays derived from live registry slots** (`task/quota.rs`, `object/charge.rs`). Nothing is counted up and down outside a slot.
  - An on-demand object's slot weight (`set_charge_pages`) is its committed pages plus its index nodes, root included. It is raised in the same T+P hold that commits the frames.
  - A Process's slot weight is the page tables that faults and fill-ins built in its root.
  - Both weights disappear with their slot, as every charge does today.
- **Admission.**
  1. Under T+P, walk the index and the page tables to count the frames the touch needs: the page, any missing index nodes, and, for a fault or copy fill-in, any missing tables.
  2. Admit the object's share against the object's tag, and the tables against the Process's tag, both with `admit_quota`.
  3. Take the frames, commit, and raise both weights.

  All three steps run in one hold, with no window between them.
- **A creator outside every limit** has an empty tag and is unlimited, as today. A tag with more than four limited ancestors was already refused at creation.

### 8.5 Serving a user page fault

**Entry**
- Every CPL3 `#PF` takes a new returning entry.
  - It does `swapgs`; user GS base is always zero.
  - It copies the interrupted frame, minus the vector and error words, onto `gs:CURRENT_STACK_TOP` in the timer entry's return-frame layout.
  - It calls a gate with the CR2 and error code captured at entry.
- The gate decides in Rust whether the fault can be served. It hands every fault it does not serve to today's terminal path, with the same record. Every other CPL3 exception, and every kernel-origin one, is unchanged.

**The gate**
1. Check the error code: P=0, U=1, and RSVD, PK, SS and SGX clear. CR2 must be a canonical lower-half address. If any check fails, the fault is terminal.
2. Poll Stop. Take T and recheck the thread binding, as `authorize_timer_return` does.
3. Under T, then P, find the mapping containing CR2 in the process's root region. Its object must be on demand, and the access the error code names (read, write or fetch; NXE is always on) must be within the mapping's protection.
4. Admit and commit as in §8.4. A page already committed, by any touch in any address space, skips the commit.
5. Publish the one leaf through a dedicated one-leaf operation. It is valid only when the old entry is zero, so it needs no shootdown and no pin span.
   - It asserts the old entry is zero. A present entry or a pin conflict is a kernel invariant failure, not a quota failure.
   - A pin over an absent page cannot exist: a failed preflight drops it under the same hold.
6. Drop the locks and join the ordinary pre-IRET path: Stop, preemption and frame validation. A fault is therefore also a preemption point.

**When the gate cannot serve the fault**
- A lookup or protection mismatch, including a mapping removed or protected before T was taken, gives today's terminal record.
- A charge or frame failure gives `RESOURCE_POLICY`.
- A leaf already present with the right protection was a spurious fault on another CPU: return.
- Loop guard, as defence in depth: a thread that faults again with the same RIP, CR2 and error code, after a gate pass that committed nothing, published nothing and found the same mapping, is terminal. *(Replaced as built: §8.10.)*

**Return validation stays read-only.** It accepts a missing entry at any page-table level when the model maps an on-demand page there with the needed protection. The return then raises the fault, and the gate serves it.

**No shootdown.** Not present to present needs none. x86 caches neither a not-present leaf nor a not-present upper-level entry, and new tables are built from zeroed candidates.

### 8.6 Consumers of absent pages, and kernel touches

- **Each address space's leaves are its own.** A committed page may be present in one address space's tables and absent in another's.
  - When the publisher unmaps or protects a page that is committed in the object, it accepts a not-present leaf and skips it. A present leaf must still map exactly the resolved frame. A page absent in the object publishes nothing.
  - The same rules hold in teardown (`unmap_inactive_userspace`) and every undo path. Each gets a test with two mappings of one object and with two processes sharing one.
  - Calls over 16 MiB stay stepwise, as M4b made them.
- **The journal** authorizes and rechecks a leaf only for a committed page, as today.
- **Syscall copies and address waits.** No copy runs under T, and none may (H0 §12.8). The guard-free types enforce this. So fill-in is its own phase, before the copy:
  - A syscall that copies user memory, or pins a user word to wait or wake on, first fills in its declared user ranges under T+P. Every such syscall takes its ranges and lengths as top-level arguments.
  - Each page is committed and charged as in §8.4, and **its leaf is published in the caller's address space** through the same one-leaf operation. The copy finds frames by walking the page tables, so a commit without a publish would still fail.
  - The fill-in runs in steps of at most 16 MiB, releasing T and P between steps.
  - Then the syscall pins and preflights as today, pinning first. A page found absent there (raced by an unmap or remap) fails the copy cleanly.
  - A whole output buffer is filled in even if the syscall then writes only part of it. Pages filled in stay committed if the copy fails.
- **`dma_map`** commits its range through `memory_object_commit`'s steps before mapping it into the IOMMU. It resolves frames through the object, so it needs no publish. Pages stay committed after `dma_unmap`.
- **The flag is refused** on device MMIO, boot-module and uncached objects. Boot objects (images, stacks, blobs) stay eager.

### 8.7 Steps

1. **The index.** In `frame_roles`: the roles, the access trait, root allocation, the commit cost and the commit, lookup with absent, release, and invariant checks. Host tests.
2. **Object, ABI and consumers.**
   - The create flag, object info, `memory_object_commit`, the schema and generated ABI, and the object kind.
   - Creation, slot weights and admission, and finalization.
   - The publisher and journal changes for leaves that differ by address space, with alias and shared-object tests.
   - `dma_map` commits first.
   - The Wyrmroot repin.
3. **The fault gate.** The returning `#PF` entry, the gate, the one-leaf publish, return validation that accepts absent pages, the termination record, the Process slot's table weight, and the loop guard.
4. **Kernel touches.** The fill-in phase for syscall copies and address waits.
5. **A guest test** at the development tier:
   - touch a large on-demand object sparsely;
   - read untouched pages as zero;
   - commit a range and run out of quota with a status;
   - pass an object to another process;
   - run out of quota on a touch and observe `RESOURCE_POLICY`.
6. **The independent security review** (CLAUDE.md §1) of the whole stage.

### 8.8 Not in M6

Decommit (giving pages back), a shared zero page for read-only touches, fault-around (committing neighbours), 2 MiB pages, swap, and the OOM killer (§6.7).

### 8.9 Design reviews

**Reviewer:** Claude Opus 5.5 (low effort), 2026-11-13. Round 1 at Deepwyrm `cd55b22` and round 2 at `eab597b`. Both rounds read code only. This section's text already includes each fix.

**Round 1** found two High and four Medium defects:
- **D1 (High): fixed by §8.6.** The design treated "the object page has no frame" as "this address space has no leaf". Unmapping a second alias that was never touched would fail, and process exit would then panic the kernel.
- **D2 (High): fixed by §8.6.** Pages were filled in during a copy, under locks no copy may hold. Fill-in is now its own phase.
- **D3 (High): fixed by §8.1 item 4.** A giver could kill a receiver on its first write by exhausting its own quota. Receivers now commit on receipt or refuse the object.
- **D4 (Medium): fixed by §8.4.** Uncharged index nodes and page tables let sparse touches hold several pages for each one charged.
- **D5 (Medium): fixed by §8.6.** `dma_map` filled in its whole range in one lock hold.
- **D6 (Medium): fixed by §8.5.** Filling pages in during return validation hid the cause and mutated state in a read-only path.
- **D7, D8, D9 (Low): fixed** by §8.2's statuses and record, §8.5's checks, and §8.6's wording.

**Round 2** found the round-1 fixes sound except D2 and D3:
- **N1 (High): fixed by §8.6.** Fill-in without a publish leaves the leaf absent, so every copy into an untouched page would still fail.
- **N2 (High): fixed by §8.1 item 4.** Charging the toucher let a giver grow a receiver's charge for as long as it kept the object alive.
- **N3 and N4 (Medium): fixed by §8.4,** which needs no accounts. One account per root mixed tags as limits changed, and dead groups' accounts could fill the account table.
- **N5 (Low–Medium): fixed by §8.6.** Address waits are filled in too.
- **N6 (Low): fixed by §8.5's loop guard.**

**Accepted (Mike, 2026-11-13).** A receiver that maps an on-demand object without committing it can be killed when the creator's quota runs out, and the commit call is its defence.

**Open:**
- Every first touch takes the global T. A group's usage scan is linear in objects, so touching 1 GiB takes about 262,000 holds of T.
- Global frame exhaustion still kills whichever process touches next. That is overcommit, as §2's M6 row decided. The OOM killer (§6.7) comes later.

### 8.10 M6 as built (2026-11-13)

Deepwyrm `bc0b6cf` (index), `915b58a` (ABI, creation, commit, publisher), `829d7f1` (fault gate), `9939167` (fill-in), `1b689c9` (wrapper), review fixes `9dc2d21` and `40c0f23`; Wyrmroot `7a4f2a0` (pin of `915b58a` with the info-record consumer), `cbd55fa` and `dfb06aa` (probes). Every step passed `dev-boot --check --sdk`; the last run was Deepwyrm `40c0f23` with Wyrmroot `dfb06aa`. Wyrmroot pins `1b689c9`, whose ABI `9dc2d21` leaves unchanged. Committed unsigned; re-sign before any push. `f05ef16` repaired the kernel's test binaries first (§9's pinned, no-fail-fast run) and deleted seven source-text tests.

- **Index.** `frame_roles/index.rs`: a 512-way radix index of at most four levels (`IndexRoot`, `IndexNode`, `ObjectPage` roles). Frames for a commit are all taken and zeroed through the direct map before any is linked, so a commit is all or nothing. Eager objects keep their chains.
- **ABI.** `DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND`; `memory_object_commit` (0x00020002, phase DW2-M, needs MAP; 2 MiB per step since `40c0f23`); the info record's `flags`.
- **Publisher.** Each address space's leaves are its own: an absent leaf is skipped on unmap and protect, a map publishes none for an on-demand page, and `publish_touched_leaf` publishes one where the entry is zero.
- **Fault gate.** The vector-14 stub sends CPL3 faults to `dw_x86_64_user_page_fault_gate` on the thread's stack. Only not-present user faults below the canonical hole are served. Page and tables are admitted together (§8.4), then committed and published in one hold of T and P. Any other fault ends with the record the terminal path built before. A quota or frame failure ends the process with `RESOURCE_POLICY`.
- **Loop guard replaced** (review M6-3): a leaf already present counts as served only when it is exactly the leaf a publish would write (accessed and dirty ignored). Since only not-present faults are served, the retry then succeeds, and any other leaf ends the fault; so no per-CPU guard is needed.
- **Fill-in.** Before a syscall's handler, the on-demand pages under its buffers (`NativeSyscallRequest::user_buffers`, each capped at what the syscall copies) are served as touches. A `dma_map` range is committed first, only when `dma_map`'s resource checks would pass, with MAP added to its rights. Nothing runs while no on-demand object is live.
- **Guest proof.** `bin/hello on-demand` maps 64 MiB (four times the job's budget), touches it, reads untouched pages as zero, has a syscall write an untouched page and commits a page; `on-demand-exhaust` spends the quota and must end as `resource-policy`.

### 8.11 Security review of M6

**Reviewer:** Claude Opus 5.5 (low effort), 2026-11-13, at Deepwyrm `6382483..1b689c9` and Wyrmroot `7a4f2a0..dfb06aa`. Method: code reading; no tests run. No Critical or High defect. The entry assembly, the record's equality with the old path, index zeroing and release, the publisher's absent leaves, read-only return validation, the live-object counter and the weights were checked and found sound.

- **M6-1 (Medium): fixed** (`9dc2d21`). `dma_map`'s fill-in committed the range before any of `dma_map`'s checks, with READ alone, so a READ holder with a bogus resource could spend the creator's quota.
- **M6-2 (Medium): fixed** (`9dc2d21`). The fill-in walked a user-chosen length before the syscall checked it, up to 2^35 page lookups, without servicing BSP timers. Buffers are now capped (at most 17 pages each) and steps service the BSP's expiries.
- **M6-3 (Low): fixed** (`9dc2d21`) as above. The per-CPU guard ignored the thread and the mapping and could end a correct program.
- **M6-4 (Low): fixed** (`9dc2d21`). Page and tables were admitted separately, so a shared group could be overshot by up to three pages; a refusal other than quota is no longer reported as exhaustion.
- **Behaviour changes, accepted:** a missing stack top is a kernel `ud2` and a missing runtime binding halts, as at the other gates; a thread or binding mismatch in the gate ends the process with its page-fault record.
- **R1 (Low): fixed** (`40c0f23`). One commit step admitted each page with a linear registry scan and zeroed up to 16 MiB in a hold of T. A step is now 2 MiB, admitted once at its whole cost (nodes shared by its pages counted once); past the quota the longest start that fits is found by halving, at most ten admissions, so a commit still fills the quota exactly.
- **Test gaps:** §8.6's teardown and undo cases are closed in `40c0f23` (two Processes sharing an object with one torn down; an unmap and a protect over two mappings whose second batch fails). Open: the gate, the fill-in and the commit step run only in the guest probe, which does not reach a spurious fault, a table refusal or a read-only buffer; a weight-equals-frames check after mixed commits and faults; BSP expiries during a long fill-in.

## 9. Open-item ledger (2026-11-13)

Mike (2026-11-13): nothing stays "open" without an owner. Every finding, risk and test gap in this plan is fixed, accepted by Mike, or scheduled into a named stage whose exit depends on it. A stage does not close while any item below names it.

**Fixed in the 2026-11-13 sweep** (each with its commit when it lands):

| Item | From | Fix |
|---|---|---|
| Root proof does not check that another owner's tables point into this hierarchy | §5.3a | Reviewed safe by construction (below). Its tests found the fault path trusting a present leaf without checking whose tables it walked; fixed, with tests for a foreign candidate and a planted foreign entry (`e3edf97`) |
| A pin overlapping a large teardown's span panics (R2); a map's output pin widens it (R6) | §7.1, §7.3 | Reviewed safe (below): no pin or permit can exist then. The precondition is now checked before any unmap (`e3edf97`) |
| G1: `TrackedActiveTarget`'s span untested on the host | §7.1 | Generic `PinTrackedTarget`, host-tested (`4b2b7ab`) |
| G4: a batch starting mid-run of a multi-run backing untested | §7.1 | Tested (`e16e961`) |
| R7: concurrent creates allocate past the quota before admission | §7.3 | Per-CPU page reservations counted in usage (`e16e961`) |
| No test finalizes an object after a merge; none fails a zeroing step mid-allocation | §7.3 | Tested (`e16e961`) |
| No check that an on-demand object's weight equals its frames after commits and faults | §8.11 | Tested for commits (`e16e961`); a fault records its frames through the same `record_charged_pages` |
| No guest touch of a read-only syscall buffer on an untouched on-demand page | §8.11 | `bin/hello on-demand` sends a Channel message from an untouched page (Wyrmroot `43f8bc2`) |

**Review of the two soundness questions:** Claude Opus 5.5 (default effort), 2026-11-13, at Deepwyrm `e16e961`, read-only. Q1 (§7.1 R2): safe. Permits borrow the tracker under P, which teardown holds; every owned pin is drained with its blocked operation or held by a CPU still resident on the root, which teardown refuses. Q2 (§5.3a): safe for the low half. Every link goes through the journal's owner checks, and teardown walks only indices 0..256; the kernel half's primordial tables are never reclaimed.

**Also fixed outside the ledger (2026-11-13):** the SDK had drifted from Wyrmroot's Deepwyrm pin through M2–M6. Wyrmroot `5b62761` makes dev-boot refuse an SDK that does not pair, and SDK `f1fca4c` repins it.

**Already fixed, recorded here:** M4's "not yet" (locks held for the whole call) and G5 (lock-hold bound) were fixed by M4b (§7.2).

**Scheduled:**

| Item | From | Stage |
|---|---|---|
| M4 and M4b never exercised in a guest (no job maps over 16 MiB) | §7, §7.2 | M5 (its guest proof maps past 16 MiB) |
| The stepped-call facade loop (stop between steps, a published inner step, the output) is live-only | §7.3 | M5 (a guest probe stopped between steps) |
| L6's 44 ms fixed cost per new arena, never explained | §1 | M5 (re-measured on the direct map with large maps) |
| R1: the role table is one contiguous run of about 2.5% of RAM (§6.9a), and its first-fit carve (§5.3a R1) | §5.3a, §6.9a | M7 |
| R4: allocation costs runs × free ranges | §6.9a | M7 |
| R2: a step's hold grows with the backing's run count | §7.3 | M7 |
| R3: stepped calls never yield the CPU; creation's zeroing has no safe point | §7.3 | M8 |
| Every first touch takes the global T, and usage is a linear scan | §8.9 | M8 |
| The fault gate, fill-in and commit step have no host tests (spurious fault, table refusal, BSP expiries during a long fill-in) | §8.11 | M8 (its lock work makes them host-testable units) |
| Global frame exhaustion kills whichever process touches next | §8.9 | M9 |

**Accepted by Mike (2026-11-13)**, as recommended; §5.3a R1 is instead superseded by M7, which carves the role table from buddy blocks:
§5.2a R3 (AP trampoline's writable alias), R4 (1 GiB pages gated on the BSP's CPUID), R5 (a map needing over 2048 tables stops the boot), R6 (large leaves and MTRRs), R10 (guest-test usercopy uses user addresses); §5.3a R3 (a second proof on one root panics), R4 (O(slots) scans), R5 (`start_position` scans); §6.9a R2 (whole-table scans at boot); §7.1 R3 (a racing pin sees `Conflict` for the whole call), R4 (tables built by undone batches stay uncharged until teardown); §7.3 R1 (handles re-resolved per step), R4 (a protect in steps can refuse a W+X alias), R5 (pieces left by a stopped caller keep their leases).

