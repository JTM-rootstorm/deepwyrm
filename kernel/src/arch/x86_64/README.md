# x86_64

Everything that touches the CPU or the platform directly: entry and
descriptors (GDT, IDT, TSS), the syscall boundary, paging and the direct map
(`mm/`), the local APIC, IOAPIC and IPIs, SMP bring-up, ACPI, VT-d and PCI
configuration access. Portable kernel code reaches it through narrow,
documented interfaces; `unsafe` stays here behind them.
