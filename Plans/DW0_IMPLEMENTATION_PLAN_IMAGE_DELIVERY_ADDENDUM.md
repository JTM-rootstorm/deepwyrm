# Deepwyrm DW0 Implementation Plan Addendum: VM and Image Delivery

**Status:** Canonical locked addendum to `Plans/DW0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/deepwyrm`  
**Milestone:** DW0  
**Scope:** Reference VM sizing, boot-media construction, and host-to-guest artifact delivery

This document is part of the DW0 implementation contract. Codex and human contributors must treat the decisions below as **locked** unless an explicit architecture revision updates this addendum and the corresponding Wyrmroot WYR0 addendum together.

The central rule is simple:

> **The canonical Deepwyrm/Wyrmroot boot and test path must not depend on a host filesystem share.**

No 9p, VirtioFS, NFS-mounted source tree, shared host directory, or equivalent convenience path may be required for DW0 or WYR0 success. The guest must receive boot/runtime artifacts through real virtual media in a form that can later be written to physical media with equivalent semantics.

---

# 1. Locked DW0 reference VM profile

The canonical DW0 development VM is:

```text
Machine:        QEMU q35
Firmware:       x86_64 UEFI / OVMF
vCPU:           1
RAM:            1024 MiB
ESP image:      256 MiB FAT32
System disk:    4 GiB sparse qcow2, reserved for later milestones
Serial:         COM1
Networking:     absent for DW0/WYR0 canonical path
Graphics:       not required for DW0/WYR0
```

The 4 GiB system disk is intentionally sparse and may remain unused during DW0/WYR0. It exists to keep the VM topology stable as Wyrmroot adds persistent storage later.

Additional standard test profiles should be supported by host tooling:

| Profile | vCPU | RAM | Disk | Purpose |
|---|---:|---:|---:|---|
| `default` | 1 | 1024 MiB | 4 GiB | Canonical DW0/WYR0 development |
| `minimal` | 1 | 256 MiB | 1 GiB or same sparse 4 GiB disk | Detect accidental large-memory assumptions |
| `smp` | 4 | 2048 MiB | 4 GiB | Early SMP/concurrency smoke testing |
| `debug` | 1 | 2048 MiB | 4 GiB | GDB, verbose diagnostics, heavy instrumentation |

The `default` profile is authoritative for milestone acceptance. The `minimal` and `smp` profiles are regression/stress profiles and do not change the canonical machine contract.

---

# 2. Canonical boot-media model

DW0 receives boot artifacts from the Wyrmroot-built EFI System Partition image:

```text
Gentoo development host
        |
        +-- build loader.efi
        +-- build deepwyrm.elf
        +-- build bootstrap.elf
        +-- build bootfs.img
        |
        v
Wyrmroot image tooling
        |
        v
wyrmroot-esp.img  (FAT32)
        |
        v
QEMU virtual disk
        |
        v
UEFI firmware
        |
        v
/EFI/Wyrmroot/loader.efi
        |
        +-- deepwyrm.elf
        +-- bootstrap.elf
        +-- bootfs.img
        |
        v
DwBootInfoV1
        |
        v
Deepwyrm
```

Deepwyrm must not know or care that these artifacts originated on a Gentoo host. From the kernel's perspective, UEFI/Wyrmroot loader supplied validated boot modules through the documented boot contract.

---

# 3. ESP contents for DW0/WYR0

The initial EFI System Partition image contains at least:

```text
/EFI/Wyrmroot/
├── loader.efi
├── deepwyrm.elf
├── bootstrap.elf
└── bootfs.img
```

An optional minimal loader configuration file may live alongside these files if required by WYR0.

The ESP is a real FAT32 image attached to QEMU as virtual block media. The canonical path does **not** mount a host directory into the guest and does not rely on firmware/QEMU magic to provide normal OS files.

---

# 4. `bootfs.img` remains the DW0 primordial-userspace transport

During DW0/WYR0, no persistent filesystem driver is required merely to launch primordial userspace.

The path remains:

```text
bootfs.img on ESP
      |
Wyrmroot EFI loader reads file through UEFI
      |
records module in DwBootInfoV1
      |
Deepwyrm validates module range
      |
wraps bootfs as read-only MemoryObject
      |
transfers capability to primordial Wyrmroot bootstrap
```

Deepwyrm does not parse the internal bootfs archive as a filesystem. Wyrmroot owns the archive format and userspace parser.

This separation is required so DW0 does not accidentally acquire a filesystem-aware `exec(path)` path or a permanent kernel bootfs API.

---

# 5. Host tooling requirements

The canonical workflow should become:

```text
cargo xtask build
cargo xtask image
cargo xtask run
```

or the equivalent coordinated command from Wyrmroot tooling.

`xtask`/image tooling owns:

- collecting the exact pinned Deepwyrm ELF
- collecting Wyrmroot EFI/bootstrap/bootfs artifacts
- constructing or updating the deterministic FAT32 ESP image
- verifying required files exist in the image
- constructing/locating the sparse system disk when required
- launching QEMU with a canonical machine/profile definition
- capturing COM1 serial output
- exposing GDB/test runner integration

Codex workers must not each maintain private hand-written QEMU commands with differing RAM, CPU, disk, or firmware assumptions.

---

# 6. No root-required image build as a design goal

Image construction should not require the normal development workflow to perform:

```text
sudo losetup ...
sudo mount ...
sudo cp ...
sudo umount ...
```

Prefer host-side FAT/image tooling that manipulates image files directly without mounting them into the host VFS.

During earliest bootstrap, a well-scoped external image utility is acceptable if needed, but the stable `xtask image` interface must hide the implementation and remain usable as an ordinary developer user.

This is a tooling requirement, not a Deepwyrm kernel ABI requirement.

---

# 7. Separate ESP and future system disk

Keep boot-critical media and persistent Wyrmroot storage distinct:

```text
QEMU
├── wyrmroot-esp.img
│   └── UEFI loader + Deepwyrm + bootstrap + bootfs
│
└── wyrmroot-system.qcow2
    └── persistent Wyrmroot system data in later milestones
```

DW0/WYR0 may leave `wyrmroot-system.qcow2` completely unused.

When storage/VFS arrives, Deepwyrm/Wyrmroot must exercise an actual virtual block-device path rather than replacing it with a host directory share.

Rebuilding the ESP must not inherently destroy or rebuild the persistent system disk.

---

# 8. Future software-delivery progression

The planned progression is:

```text
DW0 / WYR0
===========
Host-built FAT32 ESP
        +
bootfs archive loaded into RAM

        |
        v

Early persistent-storage milestones
===================================
ESP
        +
real virtual system disk

        |
        v

Package-management milestones
=============================
ESP
        +
system disk
        +
packages delivered by removable virtual media or Wyrmroot networking

        |
        v

Self-hosting
============
Wyrmroot builds/installs its own packages and kernel updates
```

Host filesystem sharing is not part of the canonical progression.

---

# 9. Removable development media is allowed later

Once Wyrmroot has block-device/filesystem support, host tooling may create an additional virtual-media image such as:

```text
dev-media.img
└── packages/
    ├── foo.pkg
    └── test-build.pkg
```

QEMU may attach this as an ordinary virtual disk/removable device. Wyrmroot must access it through its own storage/filesystem stack.

This is explicitly different from a host filesystem share and is encouraged for offline package/install testing.

---

# 10. QEMU debug/test injection boundary

QEMU-specific mechanisms such as firmware configuration channels, debug-exit devices, or test-control metadata may be used for **test harness control only**.

Acceptable examples include:

- selected guest-test name
- deterministic test seed
- debug/test completion signal
- other tiny harness metadata

They must not become the normal path for supplying:

- Deepwyrm ELF images
- Wyrmroot executables
- bootfs contents
- package payloads
- configuration that a physical machine would normally read from storage

A test must not pass only because QEMU secretly supplies an ordinary file that the physical boot/storage path cannot provide.

---

# 11. Disposable test disks and overlays

Persistent-storage tests should eventually use disposable qcow2 overlays:

```text
wyrmroot-system-base.qcow2
          |
          v
temporary-test-overlay.qcow2
          |
          v
QEMU test
          |
          v
delete overlay
```

This permits corruption, update, rollback, and crash-recovery tests without damaging the canonical base image.

DW0 does not need to implement the storage behavior yet, but host tooling should not preclude this layout.

---

# 12. Image inspection and reproducibility

Wyrmroot tooling should provide an inspection command or equivalent capability, conceptually:

```text
cargo xtask inspect-image
```

which can report at least:

```text
ESP:
  /EFI/Wyrmroot/loader.efi
  /EFI/Wyrmroot/deepwyrm.elf
  /EFI/Wyrmroot/bootstrap.elf
  /EFI/Wyrmroot/bootfs.img

Bootfs:
  /system/init0
  /bin/hello
```

Exact byte sizes are build outputs, not ABI constants.

Milestone validation should verify that the expected artifacts were actually placed into the image used by QEMU rather than assuming a successful host build means the guest consumed the same files.

---

# 13. DW0 integration requirements

The Deepwyrm side must preserve these rules:

1. DW0 boots from the real Wyrmroot ESP/UEFI path during cross-repository integration.
2. Deepwyrm accepts boot modules only through the canonical `DwBootInfoV1` contract.
3. Deepwyrm does not depend on 9p, VirtioFS, a host mount, host network access, or a host-visible source tree.
4. The primordial bootfs is a boot module/`MemoryObject`, not a magical host filesystem namespace.
5. QEMU-only debug channels remain test plumbing and are not production file delivery APIs.
6. A future persistent system disk must appear as real virtual hardware through the normal driver/storage architecture.
7. The same architectural boot path should remain applicable when the ESP/system image is placed onto real media for physical x86_64 hardware.

---

# 14. DW0 image-delivery acceptance gate

DW0 integration is not complete until:

- the canonical `default` profile runs with 1 vCPU and 1024 MiB RAM
- QEMU boots from a real 256 MiB FAT32 ESP image generated by Wyrmroot tooling
- the ESP contains the exact Deepwyrm/Wyrmroot artifacts expected by the build manifest
- `loader.efi` obtains `deepwyrm.elf`, `bootstrap.elf`, and `bootfs.img` from the virtual ESP rather than a host share
- Deepwyrm receives those modules only through `DwBootInfoV1`
- primordial Wyrmroot userspace receives the read-only bootfs `MemoryObject`
- the end-to-end DW0/WYR0 path succeeds with host filesystem sharing disabled/not configured
- the host image/run workflow does not require root as part of ordinary development
- the QEMU profile is centralized in tooling rather than duplicated across subsystem agents

Any host-share path added for developer experimentation must be optional and must not participate in milestone acceptance tests.
