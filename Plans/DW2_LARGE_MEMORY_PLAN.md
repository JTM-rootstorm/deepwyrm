# DW2 large-memory plan

**Status:** draft for Mike's decisions (2026-11-12). Nothing here is implemented.

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
| **M1** | Size the allocator's free-range storage and the frame-role table from the boot memory map, carving their storage from usable RAM at boot instead of fixed statics. Make a failed free impossible by construction: either the free-range storage is large enough for the worst case (one range per two frames is the trivial bound, so a bitmap or a buddy allocator over each usable range is the likelier shape), or table frames are tracked per address space rather than in the global role table | L4, L5 | none |
| **M2** | A direct map: all usable RAM mapped once in the kernel half, read-write, no-execute, supervisor-only, built from 1 GiB pages where the CPU has them (`pdpe1gb`) and 2 MiB pages otherwise. Zeroing uses `rep stosq` through it. The temporary window stays only for the bootstrap paths that run before the direct map exists | L6, keeps L9 satisfied | none |
| **M3** | Scattered backing: a MemoryObject is backed by a bounded list of runs (extents), allocated largest-first, so a large object needs free memory, not a large hole. Reclamation and finalization (DW0 D0 §5) carry the list | L3 | none |
| **M4** | Chunked publication: a map call publishes in batches of at most the journal's capacity. Each batch is a complete D7 journal. If a later batch fails, the call unmaps the batches it already published and returns the error, so the call is still all-or-nothing as userspace sees it. The global locks are released between batches, which also bounds the lock-hold time (R1) | L2 | none |
| **M5** | Wyrmroot: init gives a job a budget derived from installed RAM (Mike to set the rule, for example half of RAM less the resident set), more MemoryObjects, and the D6 mapping slots. The SDK layer drops the four-arena scheme for one `mmap` per large allocation | L1 | Wyrmroot policy only |
| later | 2 MiB user pages for objects whose backing has 2 MiB-aligned runs (needs M3); demand-zero paging (a map reserves, the first touch allocates and zeroes) | L8, L7 | demand-zero needs a fault-service path in the kernel and a schema decision on how a refused fault is reported |

Order: M1, then M2, then M3 and M4 (independent of each other), then M5. M2 and M3 change the boot path and object finalization, so each needs the independent security review of CLAUDE.md §1. M2 especially: a direct map gives the kernel a writable alias of every user page, which widens what a kernel bug can reach. Its mappings must be supervisor-only and no-execute. Deepwyrm currently clears CR4.SMAP at entry (`arch/x86_64/entry.rs`) and does not set SMEP. A direct map raises the value of both, so M2's review should decide whether they are enabled with it.

## 3. Decisions for Mike

1. **Direct map (M2), and with it SMAP/SMEP.** Recommended: yes to both. The alternative, a pool of per-CPU windows, removes the per-page `invlpg` but keeps the window design's other costs. The direct map is what other kernels of this kind do.
2. **Demand paging.** Recommended: later. M4's chunked eager map gets large allocations working without a fault-service path. Demand-zero is worth doing when programs reserve much more than they touch, which a database with a large cache will.
3. **The job budget rule (M5).** A fraction of RAM, a fixed size set in the platform config, or both.
4. **Where this sits relative to SQLite.** SQLite at its default cache size fits in 16 MiB, so it does not need this plan. Recommended order: M1 now, since it is a latent panic at any size; then SQLite; then M2–M5 before any port that needs large memory.

## 4. Sources used

- Deepwyrm code at `d26bd40`: `memory/physical.rs`, `memory/frame_roles/manager.rs`, `arch/x86_64/mm/transition/private.rs`, `arch/x86_64/mm/activation/{primordial.rs, user_access.rs, graph.rs}`, `arch/x86_64/mm/journal.rs`, `arch/x86_64/exceptions.rs`, `lib.rs`.
- `DW0_IMPLEMENTATION_PLAN.md` §2.14, `DW0_D0_OBJECT_HANDLE_CONTRACT.md` §5.
- Root `TOOLCHAIN_POSIX_LAYER_DESIGN.md` §5 and §8 (D6, D7), and the D7 review (`.tmp/toolchain-review/d7-journal-review.md`).
- Not read for this draft: `DW1_S2K_RUNTIME_AUTHORITY_DESIGN.md` in full. M2 changes the kernel's physical-access boundaries, so its implementation must read that design first.
