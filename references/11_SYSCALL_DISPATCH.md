# 11 - syscall dispatch

Part of the Axle syscall surface.

See also:
- `10_ARCH_X86_64_STARTUP.md` - `int 0x80` entry path
- `12_WAIT_SIGNAL_PORT_TIMER.md` - wait and signal syscall families
- `20_HANDLE_CAPABILITY.md` - handle validation and rights checks
- `21_OBJECT_MODEL.md` - object-layer syscall targets
- `30_PROCESS_THREAD.md` - process and thread syscalls
- `33_IPC.md` - IPC syscall families
- `40_VM.md` - VM syscall families
- `90_CONFORMANCE.md` - syscall-level contract coverage

## Scope

This file describes the current syscall-number source, trap entry, argument copy helpers, and dispatch structure in the repository.

## Number source

- Syscall numbers come from the shared spec and generated Rust output under `syscalls/generated/`.
- `tools/syscalls-gen` regenerates the number table from `syscalls/spec/syscalls.toml`.
- `just check-syscalls` is the guard that the generated file matches the spec.
- The shared spec now names its ABI surface in native `ax_*` types (`ax_handle_t`, `ax_status_t`,
  `ax_signals_t`, ...).
- The live trap path now decodes handle arguments at full native width instead of truncating them
  through the older 32-bit compat codec.

## Current dispatch shape

- `kernel/axle-kernel/src/syscall/mod.rs` is the main syscall layer.
- `dispatch_syscall()` handles supported syscalls from a `[u64; 6]` argument array.
- `invoke_from_trapframe()` is the architecture-facing path.
- The current bootstrap syscall ABI surface is `49` generated syscall numbers.
- `AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC` is now the distinct Linux-facing
  exec-prepare helper. It accepts one opaque exec-spec blob and produces the
  prepared entry/stack pair without overloading the generic native launch path.
- `AXLE_SYS_AX_GUEST_SESSION_CREATE` and `AXLE_SYS_AX_GUEST_SESSION_RESUME`
  are the Round-1 control plane for generic supervised guest execution:
  - create binds one target thread, one sidecar VMO, and one supervisor port
  - resume lets userspace update the sidecar register snapshot and wake the guest
- `AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY` and `AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY`
  are the first generic guest-memory data plane for that supervision model:
  - read copies guest userspace bytes out to the supervisor
  - write copies kernel-owned bytes back into the guest address space
  - neither syscall interprets Linux ABI structures or Linux syscall semantics
- `AXLE_SYS_AX_THREAD_SET_GUEST_X64_FS_BASE` and
  `AXLE_SYS_AX_THREAD_GET_GUEST_X64_FS_BASE` are the current generic x86_64
  guest-thread TLS hooks:
  - they operate on one existing thread carrier
  - they cache and expose that carrier's guest-visible `fs_base`
  - they do not encode Linux `arch_prctl` or `CLONE_SETTLS` policy in-kernel;
    the Starnix executive remains responsible for those semantics
- `SyscallCtx` is now the syscall front-end authority for:
  - scalar argument decoding
  - extra syscall stack argument recovery
  - typed pointer / sink decode and output probe planning
  - trap-exit / restartable tail handling through `finish_syscall()`
- `invoke_from_trapframe()` now does only three things:
  - build `SyscallCtx`
  - resolve one syscall descriptor by number and invoke it
  - write the returned status and run `ctx.finish()`
- Supported syscalls now dispatch through one lightweight descriptor pipeline:
  - `decode(ctx, raw_args) -> Request + writeback plan`
  - `run(request) -> Response`
  - `writeback(ctx, plan, response)`
- `AXLE_SYS_VMAR_MAP` and `AXLE_SYS_CHANNEL_READ` are no longer structural exceptions in trap entry
  or dispatch. Their extra stack-argument and buffer handling now lives entirely in their decode /
  writeback stages.

## Copyin / copyout rules

- `kernel/axle-kernel/src/copy.rs` is the only syscall-facing usercopy service.
- `SyscallCtx` calls into that service for:
  - typed scalar / slice copyin
  - typed writeback for values, bytes, handles, and channel payloads
  - extra stack-argument reads
  - early output probes that must happen before object creation, mapping, transfer, or read-side dequeue
- The copy service owns:
  - user-range validation and residency for synchronous bulk copies
  - channel payload planning (`copied` vs `fragmented` vs `loaned`)
  - remap-or-copy fallback on channel read
  - probe policy as well as the actual data movement
- Syscall `run()` stages now consume only decoded kernel values and opaque validated sink tokens; they
  no longer parse raw user pointers or extra stack arguments themselves.
- Synchronous read/write families such as socket and VMO now split the copy path the same way:
  - decode copies input bytes or validates output buffers
  - run performs the kernel object operation on kernel-owned values
  - writeback copies results back to userspace

## Current supported families

The current bootstrap syscall surface includes:

- handle close / duplicate / replace
- object wait one / wait async / signal / signal peer
- port create / queue / wait
- timer create / set / cancel
- VMO create / read / write / set size
- VMAR allocate / destroy / map / unmap / protect
- channel create / write / read
- eventpair create
- futex wait / wake / requeue / get owner
- process create / prepare start / start
- Linux exec prepare
- guest session create / resume / read-memory / write-memory
- guest-thread x86_64 FS-base set / get
- thread create / start
- task kill / suspend
- socket create / read / write

## Error-handling shape

- Unknown syscall numbers return `ZX_ERR_BAD_SYSCALL`.
- Known-but-unimplemented paths use `ZX_ERR_NOT_SUPPORTED`.
- Type, rights, pointer, and object-state checks are largely delegated into the object layer after the syscall shell validates raw arguments.
- A syscall can leave the thread blocked; trap-exit handling then decides whether to return to user mode, switch threads, or block current execution.
- For output-producing syscalls that can create, dequeue, or otherwise commit kernel-visible state,
  the syscall shell now probes user outputs before the run stage so copyout failures do not trail
  committed side effects.

## Current limitations

- Long-lived blocked waits still complete their final user writes in the wake path rather than in the
  original syscall shell. The tightened boundary is:
  - syscall front-end owns pointer decode and probe
  - the wait core stores an opaque validated sink token for delayed completion
- The current ABI surface is substantial for early system work, but not every planned Zircon-facing syscall family exists yet.
- The public `ax_*` naming and the live handle codec are now aligned: handles travel through the
  syscall boundary at full native 64-bit width.
