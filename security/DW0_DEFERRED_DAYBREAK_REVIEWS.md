# DW0 D/E Daybreak Historical Review Register

## Purpose

This register preserves the former coordinator-authorized D/E soft-accept debt
and its closure history. It must not be deleted merely because the entries are
now closed; later F/H work can reopen a phase if it materially regresses these
surfaces.

As of 2026-08-20, **DW0-D and DW0-E are FULL ACCEPTED for phase accounting**
under Mike's S5 closure direction. The 2026-08-19 current-tree Daybreak review
used exact model `gpt-daybreak-blue-latest` at High reasoning and explicitly
compared the historical D and E surfaces to current revision
`797d8561d59fdbe6c55d25fa1620110f4f85acee`. Sol then implemented the
Daybreak-authored DB-01 through DB-07 plan through cumulative candidate
`ef3abd93aa9d003ca8f576fdf50a696a045c79b8`, with full S5 regression evidence.

This is not a claim that Daybreak re-reviewed `ef3abd93`. Mike explicitly
deferred the next cumulative Daybreak re-review to the end-of-F F13 gate.

## DW0-D — CLOSED

- historical frozen candidate:
  `fa4be89efc14aff1301b4a5ea6a9f4af9d11e29e`;
- historical validation descendant:
  `db09ce173adfb6850765fe2a4547d50a1050ac10`;
- original record: [`DW0_D_SECURITY_REVIEW.md`](DW0_D_SECURITY_REVIEW.md);
- historical manual note:
  [`DW0_D7_SECURITY_REVIEW_NOTE.md`](DW0_D7_SECURITY_REVIEW_NOTE.md);
- dedicated Daybreak closure:
  [`DW0_D_DAYBREAK_CLOSURE.md`](DW0_D_DAYBREAK_CLOSURE.md);
- formal phase-accounting status: **FULL ACCEPT / HISTORICAL DEBT CLOSED**.

The Daybreak current-tree review explicitly disposed D7-R1 typed/generic
finalizer routing and D7-R2 construction/publication sequencing and rechecked
rights, stale generations, mapping pins, W^X accounting, and rollback without a
new D vulnerability. D7-R3/R4 remain Low engineering debt.

## DW0-E — CLOSED

- historical remediation candidate:
  `579e12074e1fe9ec89507e033381fed66676c12c`;
- historical E9 validation candidate:
  `e8394d6e6d160d9e4d04769943c2500cfd562c10`;
- original record: [`DW0_E_SECURITY_REVIEW.md`](DW0_E_SECURITY_REVIEW.md);
- historical provisional note:
  [`DW0_E8_SOFT_SECURITY_REVIEW_NOTE.md`](DW0_E8_SOFT_SECURITY_REVIEW_NOTE.md);
- dedicated Daybreak/S5 closure:
  [`DW0_E_DAYBREAK_CLOSURE.md`](DW0_E_DAYBREAK_CLOSURE.md);
- formal phase-accounting status: **FULL ACCEPT / HISTORICAL DEBT CLOSED**.

The Daybreak current-tree review independently confirmed E8-F1/SWAPGS remained
fixed and found no new E Critical/High defect. E8-R3 address-space retirement
was carried into DB-04 and remediated by S3's move-only blocked-operation/root
retirement proof. Mike explicitly deferred DB-04's intermediate targeted
Daybreak re-review to the final F13 cumulative scan.

E8-R1 nonterminal-exception GS state, E8-R2 per-CPU/runtime ownership, and
E8-R5 SMP assumptions remain phase-bounded H/future-path Medium gates rather
than historical E acceptance blockers. E8-R4 remains Low fail-closed
availability debt.

### 2026-08-21 F13 reopen and reclosure

F13 temporarily reopened DW0-E after exact Daybreak review found guest
selectors 11 and 12 classified as implemented even though the E dispatcher has
no runnable bodies for them. Deepwyrm commit `68313e5c8bd4f4f005d8347f8646089678089585`
reclassified both identities as reserved and added tooling/kernel regressions
that reject them before artifact selection or guest dispatch. The targeted
`gpt-daybreak-blue-latest` High-reasoning re-review passed on final F13
candidate `96fe554c0e4cb21335df4bbf5ebd2de1f9df21c5` with no remaining finding.
DW0-E is therefore CLOSED again; no execution claim is made for selectors 11
or 12.

## Closure evidence

Cumulative remediation candidate:
`ef3abd93aa9d003ca8f576fdf50a696a045c79b8`.

S5 implementation/regression record:
[`DW0_DAYBREAK_REMEDIATION_S5_CLOSURE.md`](DW0_DAYBREAK_REMEDIATION_S5_CLOSURE.md).

S5 artifact manifest SHA-256:
`4e12b1a0ac8cd77b8f6a19cc5066dd90fdc02a541633aadb78e99181de1c3253`.

The designated VM passed selector 10 after 10.937 seconds of wall time, covering
two complete 24-bit PM-timer full-wrap intervals, and restored the original
OS-Project domain definition byte-identically.

## Reopen rule

F13 must recheck that F did not regress D/E surfaces and must run the planned
`gpt-daybreak-blue-latest` cumulative scan. A substantive F13 finding affecting
D or E reopens the corresponding entry. DW0-H must separately re-review SMP and
per-CPU assumptions; that review does not erase this historical record.
