# Tests

Deepwyrm's tests live beside the code: unit tests in `#[cfg(test)]` modules,
and integration, compile-fail and artifact tests in `kernel/tests/`. Run them
on the pinned host lane:

    tools/pinned-cargo host test -p deepwyrm-kernel --no-fail-fast

`cargo xtask kernel-check` builds the production kernel and bounds its stacks.
Guest runs go through Wyrmroot's `xtask dev-boot`.
