# IPC boundary

DW0-F5/F6 own the typed Channel endpoint, pair lifetime, bounded datagram,
readiness, and atomic handle-transfer foundation in `ipc/mod.rs`. Generic object
liveness remains owned solely by `ObjectRegistry`; Channel pair, payload, send,
and receive generations protect only kernel-internal resource identities.

Channel queues are bounded FIFO datagram queues. Zero-byte messages are valid and
byte payloads are limited by generated `DW_CHANNEL_MAX_PAYLOAD`. Readiness is
derived from committed state: `READABLE` means an inbound datagram exists,
`WRITABLE` means the peer remains open with descriptor capacity, and
`PEER_CLOSED` means the peer endpoint payload has finalized.

F6 extends each datagram with zero through `DW_CHANNEL_MAX_HANDLES` move-only
transfer tokens. `channel_send` validates the complete descriptor array before
mutation, rejects duplicate sources and the peer-endpoint self-reference cycle,
requires `TRANSFER`, and permits rights only to stay equal or decrease. Queue and
payload capacity are reserved before any source handle is extracted.

Commit moves each source HandleTable entry's existing `HandleRef` into the queued
token. It does not mint a duplicate authority reference. A failed send restores
all extracted entries with their original raw handles and rights. Moving the
sending endpoint itself is supported because the syscall operation pin preserves
its typed lifetime through commit; moving the destination endpoint into its own
inbound queue is rejected even through another handle to that object.

Receive uses a move-only head reservation so output preflight cannot race another
receiver into a different FIFO head. `BUFFER_TOO_SMALL` and destination
HandleTable capacity failure consume nothing. On success, the complete destination
slot set is reserved before dequeue, queued references move directly into new
caller-local handles, and already-pinned byte/handle/result outputs commit only
after authority publication can no longer fail.

Endpoint finalization closes that side, drains only messages addressed to the
closing endpoint, preserves messages already committed to the surviving peer,
and releases queued transfer references through the central typed finalizer path.
Waiter wake ownership remains deferred outside the Channel lock. Generic
`wait_one`/`wait_many` syscall blocking remains DW0-F7 work.
