# Deepwyrm PCI function, device-MMIO and IOMMU DMA contract (storage K1–K4)

**Status:** contract for implementation, 2026-11-10. K0 (VT-d default deny) is reached at `49a35e3`/`d508a5c`, K1 at `8964ed8`. The new syscalls carry implementation phase `DW2-S`.
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

A memory BAR is admitted only if it is non-empty and page-aligned, has a page-multiple size, lies below the CPU's physical-address limit, and overlaps no range the boot memory map marks usable, ACPI, kernel or module. I/O BARs are recorded but not admitted in this revision.

The kernel serializes all 0xCF8/0xCFC access under one IRQ-safe lock. Userspace never gets those ports.

## 4. PCI-function operations (K2, K3)

New syscalls in the device family:

| Syscall | Number | Authority | Effect |
|---|---:|---|---|
| `device_pci_config_read` | `0x00060020` | `DEVICE_RESOURCE:READ` | width 1, 2 or 4 at an aligned offset < 256 |
| `device_pci_command` | `0x00060021` | `DEVICE_RESOURCE:WRITE` | sets the memory-space and bus-master bits to the two given booleans (each 0 or 1); every other command bit is preserved; I/O-space decoding is always cleared. Setting bus mastering fails with `DW_STATUS_NOT_SUPPORTED` unless a VT-d unit with INCLUDE_PCI_ALL is in default deny, since without one the device could reach any physical address; clearing it always succeeds |
| `device_mmio_map` | `0x00060022` | `DEVICE_RESOURCE:MAP` | maps `[offset, offset+length)` of BAR `bar` (page-aligned, inside the BAR) into an AddressRegion the caller can map into, with read/write rights only, uncached, never executable |
| `dma_map` | `0x00060023` | `DEVICE_RESOURCE:MODIFY` plus `MEMORY_OBJECT:READ` (and `WRITE` for a device-writable mapping) | maps pages of a MemoryObject into the function's IOMMU domain; returns the IOVA |
| `dma_unmap` | `0x00060024` | `DEVICE_RESOURCE:MODIFY` | removes a mapping by IOVA and length, then invalidates the IOTLB before returning |

`device_mmio_map` installs a mapping whose backing is a new `ObjectBackingKind::DeviceMmio` range: frames outside the allocator, like the existing immutable-module backing, mapped with PCD|PWT. It holds a reference on the DeviceResource, so the BAR cannot be handed to a new lease while it is mapped.

`device_mmio_map` uses the existing generic `MAP` right (0x8), which `object_rights.toml` adds to `DEVICE_RESOURCE`'s admitted rights. A driver that should only read config space can be handed a resource without it.

## 5. IOMMU domains (K4)

- One domain per claimed PCI function, created on the first `dma_map`. Its context entry (under K0's root table) points at a 4-level second-level page table (48-bit IOVA; the unit must report SAGAW 4-level support, or `dma_map` fails with `DW_STATUS_NOT_SUPPORTED`). The domain ID is the resource's lease slot.
- The IOVA allocator is per domain, starts at 1 MiB, and never reuses an IOVA until it has been unmapped and the IOTLB invalidated.
- Mapped MemoryObject pages are pinned: the object cannot shrink and its frames cannot be freed while any IOVA maps them. Mapped pages count against the caller's TaskGroup memory limit.
- With no IOMMU (K0's `Absent`), `dma_map` fails with `DW_STATUS_NOT_SUPPORTED`. There is no pass-through mode.
- Teardown when the DeviceResource finalizes: clear bus mastering, unmap every IOVA, invalidate the context entry, the domain's IOTLB entries and the context cache, free the page tables, then drop the pins. The order guarantees the device cannot reach a page after it is freed.

## 6. Out of scope

MSI/MSI-X and interrupt remapping (K5), PCI bridges and buses other than 0, extended config space, ATS/PRI/PASID, I/O BARs, hotplug and multi-segment systems.

## 7. Tests required

Host: the V2 table parser, including mixed kinds and every rejection; BAR sizing and admission against a fake config space and memory map; the command-bit filter; the IOVA allocator; second-level table construction and teardown against the VT-d register model from K0, including the teardown order.

Live: `dev-boot` with a q35 virtio-blk function claimed by a test path that maps its common-config BAR and reads `device_feature`, and a DMA round trip once W3's driver exists.
