# Deepwyrm PCI function, device-MMIO and IOMMU DMA contract (storage K1–K4)

**Status:** implemented, 2026-11-11; the live DMA round trip waits for W3's driver (§7). K0 (VT-d default deny) is reached at `49a35e3`/`d508a5c`, K1 at `8964ed8`, K2 at `c7374c4`, K3 at `a597e1b` (its finalizer fix at `b6366f2`), K4 in the commit that records this status. The new syscalls carry implementation phase `DW2-S`.
**Plan:** OS-Project root `STORAGE_PLAN.md` §2–§3 (Mike's decision: IOMMU first).
**Extends:** `DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md`. Everything there stays true for kind 1.

K1–K4 land as one ABI revision. Wyrmroot re-pins once (root `CLAUDE.md` §7).

## 1. What this adds

A driver for a PCI function receives one DeviceResource of a new kind. With it, and nothing else, the driver can:

- read the function's standard configuration space (256 bytes);
- set or clear only the command register's memory-space and bus-master bits;
- map the function's memory BARs into its own AddressRegion, uncached;
- make its own MemoryObjects visible to the device at device addresses (IOVAs) that the kernel chooses, inside an IOMMU domain only that function uses.

It never learns a physical address, never writes a BAR, bus number, capability or any other config register, and never touches another function. Nothing here branches on vendor, class or driver.

## 2. Boot device table V2

The V1 record has no room for a PCI address. Table and record move to version 2. V1 is no longer accepted; Wyrmroot's producer moves in the same pair.

`DwBootDeviceTableV2` keeps the V1 header layout with `version = 2` and `record_stride = 64`.

`DwBootDeviceResourceV2` is exactly 64 bytes:

```text
offset type                  field
0x00   u32                   size = 64
0x04   u32                   version = 2
0x08   DwDeviceResourceKind  kind
0x0c   u32                   flags = 0
0x10   u64                   resource_id            nonzero, unique
0x18   u64                   device_correlation_id  non-authoritative; 0 = absent
0x20   u16                   pio_base               kind 1 only, else 0
0x22   u16                   pio_length             kind 1 only, else 0
0x24   u32                   interrupt_source       kind 1 only, else 0
0x28   u32                   pci_address            kind 2 only: segment<<16 | bus<<8 | device<<3 | function
0x2c   u32                   pci_ids                kind 2 only: vendor | device<<16
0x30   u64                   reserved0 = 0
0x38   u64                   reserved1 = 0
```

`DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION = 2`. The segment must be 0. Two records may not name the same function, and fields belonging to the other kind must be zero. `DW_BOOT_DEVICE_TABLE_MAX_RESOURCES` stays 8.

## 3. Enumeration and the claim check (K1)

At boot the kernel reads each PCI-function record's vendor and device ID through configuration mechanism #1 (ports 0xCF8/0xCFC; standard space only, so no MCFG/ECAM is needed yet). It also sizes the BARs: it saves each BAR, writes all ones, reads the size back, and restores the BAR with memory decoding disabled for the duration. A function whose IDs differ from the record, which is absent, or whose BARs fail validation is **unavailable**: its claim fails with `DW_STATUS_NOT_FOUND`, and COM1 says why. Other records are unaffected.

A memory BAR is admitted only if it is non-empty and page-aligned, has a page-multiple size, lies below the CPU's physical-address limit, and overlaps no range the boot memory map marks usable, ACPI, kernel or module, no page the kernel maps for itself as MMIO (local APIC, the routed IOAPIC, VT-d registers and tables, all mapped before the probe), and not the interrupt window 0xFEE00000–0xFEFFFFFF. Other IOAPICs and the HPET, which the kernel does not map, are not excluded. A DMAR unit's register page may lie only in MMIO or RESERVED memory-map ranges (physical firmware commonly reports chipset registers as RESERVED) or outside the map, and never on a handoff range (boot info, its tables, every module, the paging handoff tables) or a frame the kernel accounts for (its image, allocator memory and tables), which the loader also reports as RESERVED. If any unit's page fails this, the kernel ignores the whole DMAR: no device is confined and none gets DMA, and every unit's register page still stays closed to BARs. I/O BARs are recorded but not admitted in this revision.

The kernel serializes all 0xCF8/0xCFC access under one IRQ-safe lock. Userspace never gets those ports.

## 4. PCI-function operations (K2, K3)

New syscalls in the device family:

| Syscall | Number | Authority | Effect |
|---|---:|---|---|
| `device_pci_config_read` | `0x00060020` | `DEVICE_RESOURCE:READ` | width 1, 2 or 4 at an aligned offset < 256 |
| `device_pci_command` | `0x00060021` | `DEVICE_RESOURCE:WRITE` | sets the memory-space and bus-master bits to the two given booleans (each 0 or 1); every other command bit is preserved; I/O-space decoding is always cleared. Setting bus mastering fails with `DW_STATUS_NOT_SUPPORTED` unless a VT-d unit in default deny translates this function (§5, *Confinement*), since otherwise the device could reach any physical address; clearing it always succeeds |
| `device_mmio_object_create` | `0x00060022` | `DEVICE_RESOURCE:MAP` | creates a MemoryObject over one whole admitted memory BAR; the caller maps it with the ordinary `address_region_map`. Its ceiling is read/write, so it is never executable, and its pages map strong-uncacheable. Requested rights exclude EXECUTE. A slot that is not an admitted memory BAR is `NOT_FOUND`; a BAR another live object covers is `ALREADY_EXISTS` |
| `dma_map` | `0x00060023` | `DEVICE_RESOURCE:MODIFY` plus `MEMORY_OBJECT:READ` (and `WRITE` for a device-writable mapping) | `dma_map(resource, memory_object, offset, byte_len, access, out_iova)`: maps a page-aligned range of a page-backed MemoryObject into the function's IOMMU domain and returns the IOVA. `access` is a nonzero mask of `DW_DMA_ACCESS_DEVICE_READ` and `DW_DMA_ACCESS_DEVICE_WRITE`. Device-MMIO and boot-module objects are `NOT_SUPPORTED` |
| `dma_unmap` | `0x00060024` | `DEVICE_RESOURCE:MODIFY` | `dma_unmap(resource, iova, byte_len)`: removes exactly one whole mapping, invalidates the IOTLB, and only then releases the MemoryObject; anything else is `NOT_FOUND` |

At boot, after K1 admits a BAR, the kernel gives its pages a permanent `ExternalDeviceMmio` frame role (outside the allocator, like immutable modules) and keeps the backing grant in the PCI probe table. `device_mmio_object_create` lends that grant to one `DeviceMmio` MemoryObject, which also holds a reference on the DeviceResource. When the object finalizes (its last handle and mapping gone), the grant returns to the table and only then is the DeviceResource reference released, so a new lease never sees a BAR an older object still names. Leaves for these objects carry PCD|PWT with PAT clear, which selects the boot PAT's PA3 (UC).

This replaces the earlier `device_mmio_map(resource, bar, offset, length, region, …)` design (2026-11-11): returning a MemoryObject reuses the whole map, protect, unmap and lease path instead of a second mapping path, and needs no runtime frame-role changes.

`device_mmio_object_create` uses the existing generic `MAP` right (0x8), which `object_rights.toml` adds to `DEVICE_RESOURCE`'s admitted rights. A driver that should only read config space can be handed a resource without it.

## 5. IOMMU domains (K4)

- **Tables.** At boot, with a DMAR present, the kernel takes a fixed pool of 64 zeroed frames and maps each permanently strong-uncacheable in the kernel half, so a unit that does not snoop CPU caches still sees every table write and no cache flushing is needed. The root table and the bus-0 context table come from the pool; the root entry for bus 0 is installed before translation is enabled, so K0's default deny is unchanged (every context entry is absent). Every second-level table also comes from the pool, and a table is zeroed before it returns.
- **Domains.** One domain per PCI_FUNCTION DeviceResource, created on its first `dma_map` and keyed by the resource object. Its context entry points at a 4-level second-level table (48-bit IOVA) and is written only after the first mapping is complete, high word first. Every unit must report SAGAW 4-level support, else no domain is ever created and `dma_map` is `NOT_SUPPORTED`. The domain ID is the domain's slot plus 1 (1–8), within every unit's ND limit; the plan's "lease slot" was not needed. A second live resource on a function that already has a domain is `BAD_STATE`. Only bus 0 is supported; another bus is `NOT_SUPPORTED`.
- **Invalidation.** Every invalidation goes to every unit: one shared root table serves them all. A unit with interrupt remapping takes every invalidation through its queue (below); any other unit takes them through its registers. A new context entry is followed by a global context-cache invalidation. New leaves are followed by a domain-selective IOTLB invalidation when any unit is in caching mode, otherwise by a write-buffer flush on units that report RWBF. Removed leaves are followed by a domain-selective IOTLB invalidation with read and write draining where supported. A unit that never completes an invalidation stops the kernel, since it may still be using a translation about to be freed.
- **IOVAs.** Per domain, first-fit from 1 MiB up to the smallest input width of all units (at most 2^48). A range is reused only after its `dma_unmap` invalidated the IOTLB.
- **Pins.** Each mapping holds one reference on its MemoryObject. Objects never shrink, so the reference keeps every mapped frame allocated until `dma_unmap` or teardown releases it.
- **Limits instead of charging.** The plan said mapped pages count against the TaskGroup's memory limit. They already do: the TaskGroup that created the MemoryObject was charged for its pages, and a mapping adds no memory. The kernel memory a mapping uses (table frames) comes from the fixed pool, and each of the at most 8 domains holds at most 64 mappings, so `dma_map` cannot grow kernel memory. Exhausting a pool, domain or mapping slot is `NO_RESOURCES`; no free IOVA range is `NO_MEMORY`.
- **Confinement.** A function is confined when a unit in default deny translates it: every segment-0 function when some DRHD sets INCLUDE_PCI_ALL, else each bus-0 function that a DRHD's device scope names as a single-hop PCI endpoint (VT-d §8.3.1). Bridges, multi-hop paths and other buses are not recorded, so the functions behind them stay unconfined. Every scope entry must be well formed (length, path, device < 32, function < 8) or the DMAR is refused. QEMU 10.2's q35 DMAR has INCLUDE_PCI_ALL clear and lists every device this way (`hw/i386/acpi-build.c`, `build_dmar_q35`); the K4 revision honoured only INCLUDE_PCI_ALL, so no function there was confined (fixed 2026-11-11, found by W3's live bring-up). The set is recorded once at boot, before any process exists.
- **Interrupt remapping** (2026-11-11, milestone security finding R1). DMA translation alone does not confine a device: a write to the interrupt address range (0xFEEx_xxxx) is not translated as DMA but delivered as an interrupt, so without remapping a driver could make its device raise any vector, an NMI or an INIT. At bring-up, once every unit is in default deny, the kernel therefore also turns interrupt remapping on in every unit, with compatibility-format interrupts blocked, when the platform supports it: the DMAR's INTR_REMAP flag, ECAP.IR and ECAP.QI on every unit, and a single-hop IOAPIC device scope naming the q35 IOAPIC's requester ID. The remapping table (one pool frame, 256 entries) holds exactly one present entry, the COM2 route: vector 0x30, fixed, physical, to the BSP, accepted only from the IOAPIC's requester ID (SVT 01b). The IOAPIC route is then written in remappable format naming that entry. The interrupt-entry cache can only be invalidated through the queue, so each unit first gets its own queue (one pool frame), and the queue stays on for good: VT-d §6.5.2 forbids the register-based interface while it is enabled, so from then on that unit's context-cache and IOTLB invalidations go through the queue as descriptors too, each followed by a wait descriptor whose status write (into the unit's own slot of one shared status frame) the kernel polls for; a rejected descriptor (IQE) or a missing status write stops the kernel. The interrupt-entry cache is invalidated once after the table pointer is set, and entries never change while remapping is on. (Until 2026-11-11 the queue was turned off again after that one invalidation and DMA invalidations stayed register-based; that toggle was never exercised on physical VT-d, review risk K1, and is gone.) A unit that inherits queued invalidation, remapping or compatibility pass-through from firmware stops the boot. A device's write to the interrupt range now faults (no entry, or the wrong requester) instead of interrupting.
- **Confinement needs both.** A function counts as confined only when interrupts are remapped as well; otherwise none is, so bus mastering and `dma_map` stay `NOT_SUPPORTED` and the kernel log says why. QEMU needs `intel-iommu,intremap=on`.
- **Ownership** (2026-11-11, milestone security finding R2). A domain belongs to the process whose `dma_map` created it. Only that process can map into or unmap from it; another process's `dma_unmap` is `NOT_FOUND`. When any other process calls `device_pci_command`, `device_mmio_object_create`, `dma_map` or `dma_unmap` on the resource, the kernel first revokes the domain exactly as teardown does (bus mastering cleared, context entry cleared, caches invalidated, tables freed, MemoryObject references released) and the call then proceeds. A replacement driver, which needs one of those calls to drive the function, therefore never inherits its predecessor's IOVAs or the buffers they pin. A domain whose owner exits without unmapping keeps its pins, with bus mastering as the driver left it, until another process drives the function or the resource finalizes; nothing but that function can reach those pages.
- **BAR objects belong to one process at a time** (review risk K2, closed 2026-11-11). The probe table records which process created each live BAR object. While a process other than the caller holds one, `device_mmio_object_create` (any BAR of the function), `dma_map` and `device_pci_command` turning bus mastering on are `DW_STATUS_BAD_STATE`, and nothing is revoked: that process can program the device, so nobody else may give the function DMA reach. Clearing bus mastering always proceeds. A replacement driver therefore starts only after its predecessor's BAR objects have finalized (their handles closed and mappings gone, as when the predecessor is reaped); a BAR object handed to a third process keeps the function closed to everyone else until it is gone.
- **Who may revoke** (review risk K3, closed 2026-11-11). Only a caller whose handle carries WRITE or MODIFY, the rights that drive the function's DMA, takes another process's domain over. `device_pci_command` (WRITE), `dma_map` and `dma_unmap` (MODIFY) always qualify; `device_mmio_object_create` needs only MAP, and a MAP-only caller meets a foreign domain with `DW_STATUS_BAD_STATE` and leaves it untouched.
- **Inert at probe** (review finding D1, 2026-11-11). K1's probe restores the command register after sizing with bus mastering and I/O decoding cleared, whatever firmware left (OVMF hands its virtio disks over at 0x7); memory decoding is kept. Bus mastering is therefore on only where `device_pci_command` turned it on for a confined function.
- **No IOMMU.** With K0's `Absent`, or for a function no unit translates, `dma_map` and bus mastering are `NOT_SUPPORTED`. There is no pass-through mode.
- **Teardown** runs when the DeviceResource finalizes, before its boot lease returns for a new claim: memory decoding and bus mastering are cleared in the command register (for every PCI function, whether or not it had a domain), the context entry is cleared (present half first), the context cache and the domain's IOTLB are invalidated, the tables are zeroed and returned to the pool, and only then are the MemoryObject references released. The device can therefore never reach a page after it is freed.

## 6. Out of scope

MSI/MSI-X (K5): its remapping entries change at run time, so K5 adds interrupt-entry invalidations to the queue that is already on. Also PCI bridges and buses other than 0, extended config space, ATS/PRI/PASID, I/O BARs, hotplug and multi-segment systems.

## 7. Tests required

Host: the V2 table parser, including mixed kinds and every rejection; BAR sizing and admission against a fake config space and memory map; the command-bit filter; the IOVA allocator; second-level table construction and teardown against the VT-d register model from K0, including the teardown order. (Done: `device::dma::tests` drives domains, IOVAs, rollback, teardown order and owner revocation through a table and invalidation model; `vtd::tests` drives interrupt-remapping bring-up, queued context and IOTLB invalidation, queue wrap-around and a silent unit through a unit model that processes the invalidation queue and rejects register-based invalidation; `acpi::dmar::tests` covers IOAPIC scopes; `vtd::tests` covers feature decoding and the invalidation commands; `syscall::adapters::tests::dma` covers rights, kinds, ranges, statuses, pin release, a predecessor's live BAR object blocking DMA, bus mastering and BAR objects, and MAP-only callers refused a foreign domain; `device::pci::tests` covers BAR holders; `object::finalizer` covers the DeviceMmio parent chain.)

Live: `dev-boot` with a q35 virtio-blk function claimed by a test path that maps its common-config BAR and reads `device_feature`, and a DMA round trip once W3's driver exists.
