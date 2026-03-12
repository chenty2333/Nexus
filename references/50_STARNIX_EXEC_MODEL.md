# 50 - Starnix executive model

Part of the Nexus / Linux-adaptation reference set.

See also:
- `11_SYSCALL_DISPATCH.md` - current syscall entry and `ax_*` helper shape
- `12_WAIT_SIGNAL_PORT_TIMER.md` - wait / port / async-wait substrate
- `30_PROCESS_THREAD.md` - process/thread carrier model
- `40_VM.md` - VM substrate and fault/COW ownership
- `44_DATAFS_PREP_MODEL.md` - read-only `GetVmo` and early filesystem constraints
- `Nexus_Roadmap_v0.3.md` - system-layer roadmap phase that introduces Starnix
- `docs/futex_semantics.md` - current Axle futex-key divergence from stock Zircon

## Scope

This draft freezes the round-0 contract for Starnix-facing Axle/Nexus work.
It does not claim that the full subsystem already exists in-tree.

The purpose of this file is narrower:

- freeze the kernel/userspace responsibility split before J1/J2/J3 work starts
- freeze the small set of new generic kernel-facing capabilities that future
  Starnix work is allowed to depend on
- avoid later refactors that would come from accidentally pushing Linux
  semantics into Axle kernel objects or bootstrap-only helpers

Exact syscall numbers, final C/Rust ABI struct layouts, and the final spelling
of some `ax_*` helpers may still move while the first implementation lands.
The architectural boundaries and object responsibilities in this file should be
treated as frozen unless a later design update explicitly changes them.

## Current in-tree state

The current repository now has the first three Starnix bootstrap slices in-tree:

- `process_create`, `thread_create`, `process_start`, `thread_start`
- `ax_process_prepare_start` as a generic child-image prepare helper
- `ax_process_prepare_linux_exec` as the separate Linux-flavored launch helper
- generic guest-session supervision with guest-memory read/write helpers
- wait / async-wait / port / timer substrate
- futex wait / wake / requeue / owner query substrate
- VMO / VMAR / lazy fault / COW / pager-backed groundwork
- stream sockets, channels, and channel handle transfer
- `nexus-io` fd and namespace substrate, including read-only `GetVmo`
- a component runner / resolver / bootstrap namespace stack
- a minimal Starnix runner + userspace executive
- J2-A single-process Linux task/mm/fs/socket bootstrap
- J2-B task/process state for:
  - `clone(CLONE_THREAD)`
  - `fork`
  - `execve`
  - `wait4`
  - zombie reap
  - reparent-to-root
- the current Round-4 signal bootstrap slice now also has:
  - process-directed and thread-directed signal queueing through the executive
  - minimal caught-signal delivery via user handler + restorer + `rt_sigreturn`
  - interruptible `wait4`
  - baseline `EINTR` / `SA_RESTART` behavior for that wait path
  - interruptible blocking pipe-backed `read`
- the current Round-4 futex bootstrap slice now also has:
  - Linux `FUTEX_WAIT_PRIVATE`
  - Linux `FUTEX_WAKE_PRIVATE`
  - Linux `FUTEX_REQUEUE_PRIVATE`
  - guest-task futex parking kept in the Starnix executive while the carrier
    thread remains stopped at the supervised syscall boundary

## Frozen architectural split

### Axle kernel keeps mechanism

Axle remains the substrate layer. Starnix work may extend it only with generic
mechanisms that are useful beyond one Linux runtime:

- execution carriers: process/thread objects and scheduling
- generic guest supervision / trap handoff
- VM substrate: VMAR/VMO, page tables, fault handling, COW, frame retirement,
  loan/remap, and TLB visibility
- wait / port / timer / async-wait substrate
- futex parking primitives
- transport primitives: stream socket, channel, handle transfer
- generic loader helpers
- generic address-space clone helpers

Axle must not gain a Linux-only syscall mode, Linux PID/TID state, Linux VMA
trees, Linux signal queues, or a kernel epoll object.

### Starnix executive keeps Linux semantics

The Starnix executive is a userspace semantic layer. It owns:

- Linux task/process identities:
  - `Task`
  - `ThreadGroup`
  - `ProcessGroup`
  - `Session`
  - `PidNamespace`
  - `TaskImage`
  - `TaskCarrier`
- Linux memory-control objects:
  - `LinuxMm`
  - `LinuxMapTree`
- Linux filesystem objects:
  - `FsNode`
  - `DirEntry`
  - `FileDescription`
  - `Mount`
  - `Namespace`
  - `FsContext`
  - Linux fd table state
- Linux signal state:
  - blocked masks
  - per-task pending
  - thread-group shared pending
  - `sigaction`
  - `sigaltstack`
  - restart state
- Linux event demultiplexing:
  - `EpollInstance`
  - `EpollEntry`
  - ready lists / poll masks

Linux identities must never be treated as the same thing as Axle
`process_id`/`thread_id`/`koid`.

## Round-0 frozen contract decisions

### `ax_process_prepare_start` stays generic

The existing `ax_process_prepare_start` helper remains the generic native /
bootstrap child-image prepare path.

Starnix work must not overload it with Linux-specific semantics such as:

- Linux `argv` / `envp` policy
- Linux-flavored `auxv`
- TLS model
- vDSO / vvar placement
- signal trampoline placement

It may continue to serve existing component and native Axle launch flows.

### A dedicated Linux exec helper is expected

Starnix launch and later `execve` work should use a distinct `ax_*` helper
rather than stretching `zx_process_start` or `ax_process_prepare_start`.

Round-0 froze the existence and purpose of this helper. Round-1 now reserves
that surface as `ax_process_prepare_linux_exec`, while intentionally leaving
the exact exec-spec blob layout opaque for the first implementation wave.

The helper is expected to:

- consume one Linux executable image VMO (or equivalent image source)
- accept one Linux exec specification carrying the initial stack / auxv /
  userspace runtime policy that the generic helper intentionally avoids
- prepare a fresh Linux task image for J1
- later serve as the control-plane base for true `execve` replacement in J2-B

Round-0 does not require J1 to implement full in-place `execve` replacement.
J1 may launch a fresh carrier process for the first Linux task. The real
`execve` semantics remain a J2-B executive concern.

At the current code state, the helper exists as a real Round-1 launch path:

- the syscall surface is shared as `ax_process_prepare_linux_exec`
- the exec-spec remains opaque at the syscall boundary but is now backed by one
  fixed shared header plus appended stack-image bytes
- the kernel still does only generic image mapping and stack installation; it
  does not decode Linux syscall numbers or Linux signal policy

### A generic supervised guest-thread facility is expected

Starnix syscall emulation should run on top of a generic supervised
guest-thread mechanism, not a Linux-specific kernel mode.

Round-0 freezes these properties:

- one guest thread binds to one explicit supervisor authority
- the guest thread also binds to one sidecar shared state object
  (page/VMO-backed)
- on selected trap/syscall entry, the kernel writes stop metadata into that
  sidecar state, blocks the guest, and wakes the supervisor
- the supervisor performs ABI-specific policy in userspace and resumes the
  guest thread

Round-0 also freezes what v1 does not do:

- no Linux-specific kernel syscall decoding
- no restricted-mode shared-process optimization yet
- no userspace takeover of ordinary anonymous faults, COW materialization, loan
  commit, or TLB consistency

The preferred control surface is one explicit object or session-like authority
rather than hidden thread mode bits. The exact object name may still move while
the first implementation lands.

Round-1 now lands this as `GuestSession`:

- one target Axle thread
- one sidecar VMO carrying the stop-state snapshot
- one supervisor port that receives user packets for guest stops
- one minimal guest-memory bridge:
  - `ax_guest_session_read_memory`
  - `ax_guest_session_write_memory`

These guest-memory helpers are still generic substrate. They move raw bytes
between supervisor-owned buffers and the guest address space; they do not carry
Linux-specific struct decoding or syscall policy.

On x86_64 v1, guest `syscall` is still trap-driven rather than a new in-kernel
Linux syscall fast path: with `EFER.SCE` disabled, a bound guest thread takes
`#UD` on `syscall`, and the kernel converts that into the generic guest stop.

### A generic MM clone helper is expected for `fork`

J2-B needs a way to clone one carrier address space for `fork`.

Round-0 freezes that this helper must stay generic:

- it clones Axle VM state, not Linux PID/VMA state
- it operates on carrier address spaces, VMARs, VMOs, and COW/share semantics
- it preserves the existing Axle fault/COW/TLB contracts
- it does not import Linux VMA trees or Linux process identity into the kernel

The Linux `LinuxMapTree` remains userspace control-plane state even when the
kernel gains an MM clone helper.

## Frozen Starnix semantic model

### Task / process mapping

The first Starnix mapping is:

- one Linux process carrier = one Axle process
- one Linux thread carrier = one Axle thread

The semantic objects above that carrier stay in userspace.

Required model:

- `clone(CLONE_VM | CLONE_THREAD)`:
  - same `LinuxMm`
  - same `ThreadGroup`
  - new Axle thread carrier
- `fork` / `clone(!CLONE_VM)`:
  - new `LinuxMm`
  - new `ThreadGroup` / PID identity as required by Linux semantics
  - new Axle process/thread carrier
- `execve`:
  - same Linux task identity
  - new image and MM state
  - carrier replacement is allowed as an internal implementation detail, but it
    must not leak into Linux-visible PID/TID/wait semantics

### Memory model

Linux VMA policy stays in userspace.

Starnix should keep one `LinuxMapTree` or equivalent userspace control-plane
structure that tracks Linux mapping policy such as:

- address range
- `prot` / `flags`
- file vs anon vs shared backing class
- `pgoff`
- grow-down stack policy
- Linux-side advisory or lock metadata

Axle kernel remains responsible for:

- ordinary anonymous faults
- lazy VMO faults
- COW materialization
- loan/remap commit
- frame retirement
- TLB consistency

This intentionally preserves the current Axle VM split:

- control plane: VMAR / VMO / `MapRec`
- hot path truth: `PteMeta`, `FrameTable`, `FaultInFlight`

### Filesystem model

Linux VFS semantics stay in Starnix.

The executive should keep Linux-facing objects such as:

- `FsNode`
- `DirEntry`
- `FileDescription`
- `Mount`
- namespace / cwd state

Backend policy is split:

- native backend:
  - regular files, directories, symlinks, devices, and native sockets through
    `nexus-io` plus filesystem / service backends
- synthetic backend:
  - `/proc`
  - `sysfs`
  - `devpts`
  - `anon_inode:*` objects such as `eventfd`, `signalfd`, `epoll`

This means Starnix borrows native storage and transport backends when useful,
but not native VFS semantics.

### Socket and pipe model

Linux socket families stay in userspace.

Early mapping strategy is frozen as:

- `pipe2()` and `socketpair(AF_UNIX, SOCK_STREAM)` may map directly onto Axle
  stream-socket pairs
- `AF_UNIX` datagram / seqpacket semantics stay in the Starnix socket layer and
  should not be forced into the current Axle stream socket object
- `SCM_RIGHTS` should reuse Axle channel handle transfer as the transport
  mechanism underneath Linux file-description passing
- large message optimization may reuse Axle channel loan/remap/fallback-copy
  substrate underneath Linux-facing abstractions

### Signal model

Linux signals are executive state, not Axle object signals.

Axle only supplies carrier mechanisms:

- kill
- suspend / resume
- wakeup
- trap / exception return to supervisor
- timer / wait / port primitives

The Starnix executive owns:

- pending sets
- blocked masks
- thread-group shared pending
- `sigaction`
- `sigaltstack`
- `SA_RESTART`
- job-control stop / continue state
- child-notify generation such as `SIGCHLD`

### Futex model

Futex support is hybrid:

- Axle kernel:
  - wait / wake / requeue / owner handoff parking primitive
- Starnix executive:
  - Linux futex op decoding
  - private/shared distinction
  - bitset semantics
  - signal interruption
  - restart bookkeeping
  - realtime-clock policy where needed

Shared futex identity should continue to align with Axle's shared/global VMO
truth rather than any Linux-only VMA tree.

The current in-tree Round-4 futex slice is intentionally narrower than the
full model above:

- the executive directly owns the live wait queues for supervised Linux tasks
- only `FUTEX_*_PRIVATE` wait/wake/requeue is implemented so far
- timeout, bitset, and restart-block policy are still deferred
- a future generic Axle helper may later let the supervisor park a guest carrier
  on the kernel futex substrate without blocking the supervisor thread itself

### Epoll model

Epoll remains a userspace object.

Round-0 freezes that Starnix should build epoll on top of:

- Linux `FileDescription` identity
- `poll_mask()`-style backend readiness queries
- Axle `wait_async` + `port_wait` substrate

Axle should not gain a kernel epoll object for this work.

## Syscall routing model

Starnix syscall handling is split into three classes:

- pure executive syscall:
  - Linux semantic tables only
  - examples: `getpid`, `gettid`, `dup`, `close`, `epoll_ctl`
- direct substrate syscall:
  - executive decides policy, then calls `zx_*` / `ax_*` directly
  - examples: `mmap`, `munmap`, `mprotect`, `pipe2`, `socketpair`, futex
    blocking primitives
- backend/service-backed syscall:
  - executive routes to native or synthetic backend objects
  - examples: `openat`, `getdents`, `ioctl`, `connect`, `sendmsg`

This split is frozen because it keeps Linux semantics in userspace without
forcing every syscall through one uniform RPC layer.

## J1 / J2 / J3 staging assumptions

- J1:
  - one container runner
  - one Starnix executive instance
  - one Linux process, one Linux thread
  - minimal startup and minimal syscall surface
- J2-A:
  - `LinuxMm`, VFS/backend adaptor, stream sockets/pipes, read-only file-backed
    `mmap`, and single-process userspace utilities
- J2-B:
  - task/process state machines, `clone`, `fork`, `execve`, `waitpid`, zombie /
    reparent behavior
- J3-A:
  - Linux signal state, interruptible waits, futex hybrid semantics
- J3-B:
  - userspace epoll on top of `wait_async` / `port_wait`

## Current limitations

- This document freezes boundaries and expected helper families, not the full
  implementation.
- The current task/process implementation is now in the first J3-A slice:
  - `getpid` / `gettid`
  - `rt_sigaction` for `SIG_DFL` / `SIG_IGN`
  - `rt_sigprocmask`
  - `kill` / `tgkill`
  - signal dequeue and default/ignore delivery checks at the syscall-resume boundary
  - one minimal userspace signal-handler trampoline path via `rt_sigreturn`
  - interruptible waits now cover `wait4` and blocking pipe-backed `read`
  - baseline `EINTR` / `SA_RESTART` behavior now exists for those wait paths
  - no restart blocks / `sigaltstack` yet
  - no epoll model yet
- `fork` currently clones the Linux-side control plane and eagerly copies the
  writable guest image/stack regions into a fresh carrier address space. It
  does not yet use the future generic MM clone helper or fork-style COW.
- `fork` clones Linux fd tables by sharing `FileDescription` identity across
  parent and child. Closing one side must not tear down the underlying
  description until the last cross-table reference is gone.
- `execve` already preserves Linux task identity while replacing carrier and
  address-space resources, but later rounds still need the remaining Linux
  process semantics such as signal reset and `CLOEXEC` cleanup.
- Restricted-mode style shared-process execution remains later optimization
  work, not a J1 requirement.
