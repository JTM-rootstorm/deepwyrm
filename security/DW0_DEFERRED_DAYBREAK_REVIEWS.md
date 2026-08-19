# DW0 Deferred Daybreak Review Register

## Purpose

This register tracks coordinator-authorized security-review debt that is allowed
to coexist with forward DW0 development but must not be mistaken for formal
security closure.

DW0-D and DW0-E are both SOFT ACCEPTED for phase progression. Neither phase has
yet received its required exact-candidate `gpt-daybreak-blue-latest` review.
Later implementation does not erase this debt.

## DW0-D

- frozen review candidate:
  `fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e`;
- validated documentation descendant:
  `db09ce173adfb6850765fe2a4547d50a1050ac10`;
- current record: [`DW0_D_SECURITY_REVIEW.md`](DW0_D_SECURITY_REVIEW.md);
- detailed manual note:
  [`DW0_D7_SECURITY_REVIEW_NOTE.md`](DW0_D7_SECURITY_REVIEW_NOTE.md);
- formal status: **PENDING DAYBREAK**.

The delayed review should explicitly revisit D7-R1 typed/generic finalizer
routing and D7-R2 construction/publication sequencing, while rechecking the full
D rights, lifetime, stale-handle, mapping-pin, and rollback surfaces.
## DW0-E

- frozen review/remediation candidate:
  `579e12074e1fe9ec89507e033381fed66676c12c`;
- E9 validation/documentation candidate:
  `e8394d6e6d160d9e4d04769943c2500cfd562c10`;
- current record: [`DW0_E_SECURITY_REVIEW.md`](DW0_E_SECURITY_REVIEW.md);
- detailed provisional note:
  [`DW0_E8_SOFT_SECURITY_REVIEW_NOTE.md`](DW0_E8_SOFT_SECURITY_REVIEW_NOTE.md);
- formal status: **PENDING DAYBREAK**.

The delayed review must independently revisit E8-F1/SWAPGS, hostile
GS/RCX/R11/RSP/RIP state, exception-origin GS normalization, pinned usercopy,
typed finalization/construction, teardown ordering, runtime-binding lifetime,
and the single-BSP assumptions captured by E8-R1 through E8-R5.

## Debt exit rule

For each phase, run the exact required model and record model identity, review
date/reasoning level, exact candidate/diff, findings, dispositions, and tests.
Any substantive fix must be applied to the then-current development branch and
receive targeted regression plus affected host/freestanding/VM revalidation.

DW0-H may perform a broader release-candidate review, but it may not silently
substitute that review for these historical D/E exact-surface obligations.
Final DW0 security acceptance remains blocked until both entries are resolved.
