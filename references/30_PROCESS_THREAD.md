# 30 - process / thread

Part of the Axle task and execution reference set.

See also:
- `12_WAIT_SIGNAL_PORT_TIMER.md` - thread blocking and wake surfaces
- `20_HANDLE_CAPABILITY.md` - per-process handle ownership
- `21_OBJECT_MODEL.md` - process, thread, and suspend-token objects
- `11_SYSCALL_DISPATCH.md` - syscall surface that drives these objects
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` - bootstrap launch path
- `32_SCHEDULER_LIFECYCLE.md` - run queue, blocking, and lifecycle
- `33_IPC.md` - IPC and wait states interact with thread scheduling
- `40_VM.md` - address-space and process-image VM pieces
- `41_VM_VMO_VMAR.md` - root VMAR and address-space metadata

## Scope

This document is the process/thread index for split Axle references.
Detailed content is split into:

- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md`
- `32_SCHEDULER_LIFECYCLE.md`

## Current shape

- Process and thread state currently live in `kernel/axle-kernel/src/task.rs`.
- Process/thread object-service entry points now live in `kernel/axle-kernel/src/object/process.rs`.
- The kernel currently has:
  - global process map
  - global thread map
  - one bootstrap scheduler state
  - per-process CSpaces
- The object layer still exposes process, thread, and suspend-token objects, but `object.rs` itself is now mostly registry/state glue.

## What to read first

- Read `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` for bootstrap userspace entry, process creation, and process image setup.
- Read `32_SCHEDULER_LIFECYCLE.md` for run queue shape, blocking states, kill/suspend behavior, and current scheduler limits.
