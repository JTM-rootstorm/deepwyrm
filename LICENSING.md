# Deepwyrm licensing policy

## Current repository state

Deepwyrm currently uses `GPL-2.0-or-later` as its repository fallback, and all current Deepwyrm Cargo components inherit or explicitly retain that license. Existing file/package/component declarations remain authoritative until an intentional relicensing change updates them.

This current state is **not** the project-wide selection default for new first-party code. The workspace rule in `../LICENSING_POLICY.md` is authoritative for future license selection: wholly first-party new code defaults to `GPL-3.0-or-later` unless it joins an already-2+-licensed component or an actual provenance/compatibility requirement calls for a GPLv2-compatible lane.

The full license texts carried by this repository are:

- `LICENSES/GPL-2.0-or-later.txt`
- `LICENSES/GPL-3.0-or-later.txt`

## Guidance for Codex and contributors

Do not mass-relicense existing Deepwyrm files merely to make the tree visually uniform. Check the component's actual provenance and combination boundary first.

For new first-party components, prefer `GPL-3.0-or-later`. Do **not** keep new kernel, ABI, generator, or driver work at GPL-2.0-or-later solely because Linux-derived code might be useful someday. Move or retain the affected boundary in a GPLv2-compatible lane when a real copied/adapted/incorporated source or combination requirement exists.

When GPLv2-family third-party material is involved:

1. record the upstream project, source revision/location, affected files or concepts, and exact upstream license;
2. determine the narrowest file/component boundary that must remain GPLv2-compatible;
3. use `GPL-2.0-or-later` for project-owned surrounding code when appropriate;
4. preserve `GPL-2.0-only` on imported material that is licensed only that way rather than relabeling it 2+; and
5. update package metadata, SPDX notices, provenance records, and this component map together.

Non-GPL imports require an explicit compatibility check against the destination lane before implementation lands. Preserve upstream attribution, notices, patent terms, reciprocal-file rules, source obligations, and other license conditions.

## Existing GPL-2.0-or-later surface

At the time of this policy update, the existing Deepwyrm repository remains GPL-2.0-or-later across its current components, including:

- `kernel/**`;
- `crates/deepwyrm-abi/**`;
- `crates/deepwyrm-syscall/**`;
- `abi/schema/**` and `abi/generated/**`;
- `tools/abi-gen/**` and `tools/xtask/**`; and
- kernel-coupled tests and test-support code.

That list records current declarations, not a permanent architectural requirement. A future provenance audit may move wholly first-party components to GPL-3.0-or-later. Conversely, components that actually incorporate GPLv2-constrained source may remain or become GPLv2-compatible.

## Relicensing first-party code

Where the project owns the relevant copyright, first-party components may be relicensed between the GPL-3.0-or-later and GPLv2-compatible lanes as implementation provenance evolves. Make such changes explicitly and coherently at the affected component boundary.

Relicensing project-owned code never grants authority to broaden a third-party license. Imported source keeps the rights and restrictions granted by its upstream copyright holders.

## Generated code

Check both the generator and its generated outputs when a licensing boundary changes. Generated files should have an explicit, documented license source and must not accidentally inherit a broader grant than their inputs permit.

A repository location does not determine license by itself. Explicit SPDX notices and package/component declarations control the code they cover.
