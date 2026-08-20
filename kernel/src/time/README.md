# Time boundary

DW0-F3 implements the reference monotonic time foundation: validated ACPI PM
timer discovery/readout, checked wrap extension and nanosecond conversion, a
bounded generation-protected deadline queue, calibrated local-APIC one-shot
interrupts, and the IRQ-safe lock used by timer/scheduler shared state.

`clock_get(DW_CLOCK_MONOTONIC_ACTIVE)` is active. Generic object waits, Event,
Timer objects, and atomic wait/wake consume this foundation in later F phases.
