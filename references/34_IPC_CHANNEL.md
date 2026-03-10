# 34 - channel

Part of the Axle IPC subsystem.

See also:
- `11_SYSCALL_DISPATCH.md` - channel syscall entry points
- `12_WAIT_SIGNAL_PORT_TIMER.md` - wait semantics used by channels
- `20_HANDLE_CAPABILITY.md` - handle transfer model
- `21_OBJECT_MODEL.md` - channel object records and lifetime
- `33_IPC.md` - IPC index
- `32_SCHEDULER_LIFECYCLE.md` - blocked sender/receiver wakeups
- `40_VM.md` - VM overview for page-loan context
- `42_VM_FAULT_COW_LOAN.md` - VM-assisted page-loan path
- `90_CONFORMANCE.md` - channel scenarios and contracts

## Scope

This file describes the current channel object behavior in the repository.

## Current implementation

- Channels are created as paired endpoints.
- Each endpoint stores:
  - peer object id
  - owner process id
  - message queue
  - `peer_closed` and `closed` state
- Each message stores:
  - payload
  - transferred handles

Current payload forms are:

- copied bytes
- loaned user pages
- fragmented payloads:
  - copied head bytes
  - optional loaned full-page body
  - copied tail bytes

Each endpoint's inbound queue is currently capped at `64` messages.

## Current signals

- `CHANNEL_READABLE` when the endpoint queue is non-empty
- `CHANNEL_WRITABLE` when the peer queue has room
- `CHANNEL_PEER_CLOSED` when the peer endpoint is gone

These are computed from endpoint state and participate in both `wait_one` and `wait_async`.

## Write path

- `channel_write()` supports ordinary copied payloads.
- It also supports a loan fast path for page-aligned full-page user ranges.
- For mixed-shape user buffers, the kernel copy service can now build a fragmented payload:
  - copied head/tail fragments
  - loaned aligned body pages when possible
  - sender-side COW arming now works on the aligned body subrange even when that body sits inside a
    larger anonymous mapping
- Message enqueue is all-or-nothing: the whole message plus transferred handles lands on the peer, or the call fails.
- Handle transfer uses `TransferredCap` snapshots from the sender CSpace, then installs them into the receiver process on read.
- Receiver-side transferred-handle install now runs through a typed install batch.
  - partial install rollback no longer depends on an open-coded cleanup loop
- Backpressure is surfaced as `ZX_ERR_SHOULD_WAIT`.
- Peer shutdown is surfaced as `ZX_ERR_PEER_CLOSED`.

## Read path

- `channel_read()` dequeues one message and reports:
  - actual bytes
  - actual handle count
  - installed receiver handles
- Reads are message-atomic. If caller buffers are too small, the message remains queued and the actual counts are still reported.
- For copied payloads, data is copied to the receiver buffer.
- For loaned payloads, the kernel copy service first tries a remap fast path and falls back to copy-fill when remap is not possible.
- Fragmented payloads use the same service:
  - copied head/tail fragments are filled explicitly
  - loaned body pages are remapped when possible, or copy-filled otherwise
  - bootstrap conformance now covers both the exact-body remap shape and the ordinary contiguous
    fallback-copy shape

## Close behavior

- Closing one endpoint drains its queued messages and releases transferred resources.
- The surviving peer sees `peer_closed`.
- Reads from an empty queue with a closed peer return the peer-closed condition rather than waiting forever.

## Current limitations

- The mixed-shape channel path now exists, but fragment storage is still simple copied byte vectors rather than dedicated fragment-page objects or a reusable fragment pool.
- `owner_process_id` is fixed at endpoint creation and is still part of the current loan/remap assumptions.
- The planner and bulk copy execution now live in the kernel copy-service slice, but channel payload ownership still spans `object.rs`, `transport.rs`, `task.rs`, and `copy.rs`.
- Loaned payload ownership is now consuming rather than clone-based.
  - releasing one queued payload consumes the loan token and tears down its backing resources
- Receiver-side fragmented remap is still stricter than the fallback path.
  - the loaned body currently expects a compatible exact anonymous destination mapping span
  - a normal contiguous user buffer still works, but it takes the copy-fill path instead of remap
