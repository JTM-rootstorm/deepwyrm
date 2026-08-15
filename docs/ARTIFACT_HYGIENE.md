# Artifact Hygiene

Deepwyrm separates authored source, potentially versioned generated ABI
outputs, and disposable local artifacts.

## Authored and generated source

The ABI schema and generator are authored source. Files under `abi/generated/`
are committed, generator-owned outputs and are therefore not blanket-ignored.

For every ABI change:

- change the canonical schema or generator rather than editing derived output
  as an independent contract;
- regenerate deterministically;
- run the implemented drift verification; and
- review schema and generated changes together.

`cargo xtask abi check` rejects missing, stale, and unexpected generated files.

## Disposable local output

The repository ignores Cargo output in `target/` and local staging under
`.cache/`, `artifacts/`, `build/`, `dist/`, `images/`, `logs/`, and `tmp/`.
These locations are for reproducible output or transient evidence, never for
authoritative source.

Do not place fixtures, fuzz corpora, source schemas, or review records in an
ignored output directory. Do not rely on an ignored artifact as the only copy
of evidence that must survive review.

## Boot media and VM state

Wyrmroot owns canonical image assembly and the QEMU/OVMF/media workflow.
Deepwyrm must not introduce private image or QEMU variants. Generated ESP
images, system disks, qcow2 overlays, firmware-variable state, serial logs, and
test results are local artifacts unless a coordinated workflow explicitly
records otherwise.

Rebuilding boot media must not wipe or recreate persistent system-disk state.
Destructive or corruption tests should use disposable overlays or dedicated
test media. Canonical boot and test paths must not depend on a host filesystem
share.

## Acceptance identity

A build output becomes acceptance evidence only when the validation record can
identify the source used to produce it. Cross-repository evidence must include
the exact Deepwyrm and Wyrmroot revisions and dirty-state qualification, plus
the relevant artifact or image hashes and manifest identity.

Do not use mutable `latest` paths or filenames alone as provenance. Do not
infer that QEMU consumed a newly built artifact without inspecting or otherwise
verifying the media used for that run.
