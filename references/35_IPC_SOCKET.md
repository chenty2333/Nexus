# 35 - socket

Part of the Axle IPC subsystem.

See also:
- `12_WAIT_SIGNAL_PORT_TIMER.md` - wait semantics used by sockets
- `11_SYSCALL_DISPATCH.md` - socket syscall entry points
- `20_HANDLE_CAPABILITY.md` - socket handle ownership and rights
- `21_OBJECT_MODEL.md` - socket object records and lifetime
- `33_IPC.md` - IPC index
- `36_NET_DATAPLANE.md` - current queue-owned network dataplane bootstrap direction
- `32_SCHEDULER_LIFECYCLE.md` - wakeup and blocked-state interactions
- `90_CONFORMANCE.md` - socket scenario coverage

## Scope

This file describes the current socket object behavior in the repository.

## Current implementation

- Socket endpoints come in pairs and share one `SocketCore`.
- `SocketCore` currently implements two directional byte rings:
  - A -> B
  - B -> A
- Each endpoint records:
  - shared core id
  - peer object id
  - side A or B

## Current supported mode

- `ZX_SOCKET_STREAM`: supported
- `ZX_SOCKET_DATAGRAM`: supported

Current Starnix exposure is still intentionally narrow:

- `AF_UNIX` `socketpair(..., SOCK_STREAM, ...)`: supported
- `AF_UNIX` `socketpair(..., SOCK_DGRAM, ...)`: supported
- broader addressed datagram families are not yet present

## Current stream semantics

- Writes append bytes into the peer-facing ring.
- Reads consume bytes from the incoming ring.
- `ZX_SOCKET_PEEK` reads without consuming.
- Short writes are possible when buffer capacity is exhausted.
- `ZX_ERR_SHOULD_WAIT` is returned when zero bytes fit; partial writes can still succeed as short writes.

Each socket pair currently uses two `4096`-byte byte rings, one per direction.

## Current datagram semantics

- Datagram sockets keep one bounded message queue per direction.
- Writes are message-atomic:
  - the whole datagram is enqueued
  - or the write fails with `ZX_ERR_SHOULD_WAIT`
- Datagram writes never degrade into short writes.
- Oversize datagrams currently fail with `ZX_ERR_OUT_OF_RANGE`.
- Reads consume at most one queued datagram.
- `ZX_SOCKET_PEEK` returns the first queued datagram without consuming it.
- Current bootstrap reads truncate an oversized datagram to the requested byte count and consume the
  message in one step.
  The current syscall surface does not yet export the original full packet length separately.

Each datagram socket pair currently uses:

- two bounded per-direction queues
- `4096` bytes of total buffered payload capacity per direction
- up to `64` queued datagrams per direction

## Current signals

- `SOCKET_READABLE` when incoming bytes are present
- `SOCKET_WRITABLE` when outgoing space is available
- `SOCKET_PEER_CLOSED` when the remote endpoint has closed

These feed both synchronous waits and async waits on ports.

## Duplication and close

- Duplicating a socket handle creates another reference to the same endpoint object.
- Closing the final handle to one endpoint updates the shared `SocketCore`.
- Peer-closed behavior is observable through both read/write errors and signal transitions.

## Telemetry

The object layer already tracks basic stream telemetry such as:

- current buffered bytes
- peak buffered bytes
- short-write count
- write-should-wait count

It now also tracks datagram-specific telemetry such as:

- peak buffered datagram bytes
- peak buffered datagram messages
- datagram write/read counts
- datagram write-should-wait count
- truncated datagram read count

## Current limitations

- The implementation is deliberately simple and paired-endpoint oriented; it is not yet a full
  cross-family socket subsystem.
- Datagram semantics are present but still intentionally narrow:
  - no address families beyond paired endpoints
  - no ancillary in-kernel datagram policy
  - no exposed original-packet-length writeback on truncating reads
- Socket state currently lives entirely inside the kernel object layer rather than in a reusable lower-level crate.
- The current stream socket should not be treated as the final network dataplane shape.
  Queue-owned shared-memory network work now has its own separate bootstrap track.
