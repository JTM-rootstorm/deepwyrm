# Deepwyrm licensing policy

## Repository default

Unless a file or component explicitly says otherwise, Deepwyrm is licensed under `GPL-2.0-or-later`.

As of the policy introduction, **all current Deepwyrm code remains `GPL-2.0-or-later`**. This is intentional. Kernel, ABI, and closely coupled foundation code should preserve compatibility with GPL-2.0-only sources that may later be adapted or incorporated where legally and technically appropriate.

The full license texts carried by this repository are:

- `LICENSES/GPL-2.0-or-later.txt`
- `LICENSES/GPL-3.0-or-later.txt`

## Guidance for Codex and contributors

Do not change a component from `GPL-2.0-or-later` merely because GPLv3 is available.

A future component may be marked `GPL-3.0-or-later` when all of the following are true:

1. the project has authority to apply that license to the component;
2. every incorporated dependency or copied/adapted source permits the resulting work to be distributed under GPLv3-or-later terms;
3. tightening the component does not block a planned GPL-2.0-only compatibility/import path;
4. the component boundary is clear enough that the new license does not accidentally change the licensing requirements of a combined kernel/foundation work; and
5. the change is explicit in package metadata and/or SPDX file notices and is recorded in this document.

Prefer `GPL-3.0-or-later`, not `GPL-3.0-only`, when a 3.x floor is appropriate.

## Components that should remain GPL-2.0-or-later by default

The following are compatibility-sensitive and require an explicit licensing review before any narrower floor is adopted:

- `kernel/**`;
- `crates/deepwyrm-abi/**`;
- `abi/schema/**`;
- `abi/generated/**`;
- `tools/abi-gen/**`;
- kernel-coupled tests and test-support code; and
- future code that is compiled or linked directly into the Deepwyrm kernel or canonical native ABI implementation.

Independent host utilities or future userspace tools are the most plausible candidates for `GPL-3.0-or-later`, but they still require the checks above. `tools/xtask/**` remains `GPL-2.0-or-later` today.

## Adding GPL-3.0-or-later code later

When a component is approved for `GPL-3.0-or-later`:

- set its Cargo/package metadata to `license = "GPL-3.0-or-later"` rather than inheriting the workspace default;
- add `SPDX-License-Identifier: GPL-3.0-or-later` to standalone files when practical, especially scripts that have no package manifest;
- add the component path to an explicit exception list in this document;
- verify that generated outputs have the intended license before changing a generator's license; and
- do not silently relicense imported third-party code.

A repository location does not determine license by itself. Explicit component/file metadata wins over the repository default.

## Current exception list

None. All current Deepwyrm components are `GPL-2.0-or-later`.
