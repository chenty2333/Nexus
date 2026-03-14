# 33 - IPC

Part of the Axle IPC reference set.

See also:
- `11_SYSCALL_DISPATCH.md` - IPC syscall entry and argument surfaces
- `12_WAIT_SIGNAL_PORT_TIMER.md` - waitable state and ports
- `20_HANDLE_CAPABILITY.md` - handle transfer across IPC objects
- `21_OBJECT_MODEL.md` - channel and socket object records
- `32_SCHEDULER_LIFECYCLE.md` - wakeups and blocked thread transitions
- `34_IPC_CHANNEL.md` - message and transfer semantics
- `35_IPC_SOCKET.md` - stream socket behavior
- `42_VM_FAULT_COW_LOAN.md` - VM support used by channel page-loan
- `90_CONFORMANCE.md` - IPC contract and scenario coverage
- `AxleKernel_Roadmap_v0.3.md` - intended IPC direction

## Scope

This document is the IPC index for split Axle references.
Detailed content is split into:

- `34_IPC_CHANNEL.md`
- `35_IPC_SOCKET.md`

## Current shape

- Channel and socket are both exposed as kernel object types today.
- Their control-plane entry points now live in `kernel/axle-kernel/src/object/transport.rs`.
- `object.rs` still defines the transport-owned object records, but message-queue, handle-transfer, and loan/remap orchestration no longer live in the root object module.
- Channel is the more advanced path because it already integrates:
  - handle transfer
  - waitable signals
  - copied payloads
  - a limited page-loan fast path
- Socket is currently stream-only and focuses on byte-stream semantics plus wait behavior.
