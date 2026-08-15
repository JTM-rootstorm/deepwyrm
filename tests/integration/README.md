# Integration test scaffold

**Status:** Structure only; no integration harness or tests are implemented here.

Integration tests are intended for contracts that cross Deepwyrm subsystems or
the Deepwyrm/Wyrmroot boundary. Shared boot and bootstrap gates must exercise
the real Wyrmroot loader, boot media, `DwBootInfoV1` handoff, Deepwyrm kernel,
and primordial userspace path when those components exist.

Future results must record:

- the exact Deepwyrm and Wyrmroot revisions and any dirty-state qualification;
- the selected artifact and media identities, including hashes where available;
- the effective centralized machine profile and test selector;
- the timeout, structured outcome, and durable log locations; and
- any deviation or unverified claim.

An integration result applies only to the recorded revision pair and consumed
artifacts. This scaffold does not provide or claim that acceptance evidence.
