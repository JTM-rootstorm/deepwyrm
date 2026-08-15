# Deepwyrm ABI schema

These files are the human-maintained source of truth for Deepwyrm ABI 0. They
use a deliberately small, strict TOML subset parsed by `abi-gen` without third-
party dependencies.

- Numeric namespace values and syscall numbers are explicit and never derived
  from declaration order.
- Records use only fixed-width scalar types, transparent fixed-width newtypes,
  fixed-size arrays, and previously declared records.
- Unknown sections, keys, malformed values, duplicate names/IDs, composite
  right bits, and nonzero real-object sentinel values are rejected.
- Generated artifacts under `../generated/` must be refreshed with
  `abi-gen generate` and verified with `abi-gen check` from the repository root.

Schema version 1 accepts only full-line comments. Inline comments and general
TOML features are intentionally unsupported so ambiguous input fails closed.
