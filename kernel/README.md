# Deepwyrm kernel crate

This directory reserves the crate boundary for the Deepwyrm kernel.

The current bootstrap is intentionally inert: it has no executable entry
point, target configuration, linker configuration, architecture constants, or
kernel behavior. Subsystem directories are boundary markers only until their
DW0 prerequisites and phase gates are satisfied.
