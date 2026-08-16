# Deepwyrm Bootstrap Status

Deepwyrm is implementing DW0 in the order defined by the architecture and DW0
planning documents.

## Current claim boundary

Phase DW0-A passed its host-only ABI layout gate at revision
`37338e8d44c08ef039eb34a01292a6b6cb5cac3a`. DW0-B source and freestanding build
gates passed at `0bc8e6667e27ebd6aa5e3d572f34b9a1dfddefc7`, while its exact
Wyrmroot/Q35 execution gate remains pending. The detailed records are
[`DW0_A_VALIDATION.md`](DW0_A_VALIDATION.md) and
[`DW0_B_VALIDATION.md`](DW0_B_VALIDATION.md).

DW0-C now has committed physical ownership, mapping authority, atomic
publication, transition attestation, one-shot Deep-root activation, six real
build-selected memory guest bodies, and guarded #DF/NMI/#MC IST stacks through
revision `9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`. Its source, host,
freestanding artifact, and final source-security review gates pass with
C0/H0/M0/L0.
[`DW0_C_VALIDATION.md`](DW0_C_VALIDATION.md) and
[`DW0_C_SECURITY_REVIEW.md`](../security/DW0_C_SECURITY_REVIEW.md) record the
exact qualified evidence.

The compatible Wyrmroot source/pin revision is
`15fa42dda23834a80197161249738f001bb2d76f`, with accepted evidence descendant
`89235c7feef2a89ef2882ee096428b456496fa39`. That evidence records loader EFI
SHA-256 `e47f6aaae15d5e4f8cf34fcfa827cf95ff43e5ec1bab288b02bc65b98800c031`,
PDB `7655e2c3102d54268703617132aaf86acf47484c4ec7595e6cafdac67d26e911`,
schema-2 provenance
`384841ca8c3c867a87e23e27d8ec5420ce47fc2db0b1ce3aafa276f9e90047be`,
and PE report
`f616d99b1385ed13d3d59091f5c02db5966c0228532ea632868794831f151b11`.
Wyrmroot's bounded guarded-IST acknowledgment review found no new Critical,
High, Medium, or Low findings. Existing accepted Medium limitations remain
recorded in Wyrmroot's `security/WYR0_B_SECURITY_REVIEW.md`; this is not an
absolute zero-findings disposition.

All source, host, freestanding-artifact, cross-repository pin/build-evidence,
and source-security work attainable within the current DW0-C/WYR0-C scope is
complete for this exact pair. DW0-C is not formally complete: no canonical
ESP/image exists yet and none of the six selectors has executed through the
real Wyrmroot loader in the coordinator-owned VM gate. The pair above
establishes source/pin and loader-build compatibility, not guest, VM, image, or
completed-phase acceptance. No physical-hardware acceptance claim is made;
VM execution cannot establish one. This DW0-C record also does not close the
earlier pending DW0-B loader/guest execution gate.

The repository still does not provide DW0-D handles, DW0-E tasks/syscalls,
later IPC/synchronization/time behavior, a primordial Wyrmroot process, or a
completed DW0 release-candidate end-to-end gate. No source or artifact result
in these records establishes VM behavior that was not actually tested.

## Authority

The canonical reading order and authority rules are in
[`Plans/ARCHITECTURE_INDEX.md`](../Plans/ARCHITECTURE_INDEX.md). The DW0 plan
and its locked addenda define intended work and acceptance requirements; they
are not a record of completed implementation.

Status claims must be backed by current repository evidence. A future phase
gate report must identify the exact tested revision, relevant artifact hashes,
commands or selectors actually run, results, security disposition, and any
cross-repository Wyrmroot revision required by the gate.

Until that evidence exists, planned command examples such as `cargo xtask
build`, `cargo xtask image`, `cargo xtask run`, and the planned test selectors
must not be reported as supported or passing solely because they appear in a
plan or placeholder command surface.
