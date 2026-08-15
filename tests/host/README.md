# Host test scaffold

**Status:** Structure only; no host tests are implemented here.

Host tests are intended for logic that can be exercised without booting
Deepwyrm, such as parsers, checked range calculations, generated-layout checks,
handle-table algorithms, rights validation, and bounded queue algorithms.

Host tests may use the normal development-host runtime. They must keep
guest/kernel dependencies explicit so a host result is not reported as proof
of freestanding linkage, architecture behavior, kernel isolation, or a QEMU
phase gate.

Future tests should be deterministic, narrowly selectable, and include negative
cases for hostile inputs where relevant. Confirmed defects should receive a
regression test when technically practical.
