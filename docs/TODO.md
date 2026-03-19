# Axle / Nexus TODO

For AI agents:

- This file tracks unfinished work only.
- `references/` remains the semantic source of truth.
- This file is the implementation plan for freezing the current Starnix bootstrap
  path into a maintainable long-term architecture.
- Prefer updating this file when priorities or sequencing change.

Legend:

- `[~]` partially underway
- `[ ]` not yet started

## Current position

- Axle already has enough generic substrate to host a bootstrap Starnix path.
- The current risk is not "missing substrate"; it is that
  `user/nexus-init/src/starnix.rs` has become a monolithic prototype.
- The highest-value work is now boundary freeze, responsibility split, and
  semantic tests.
- New Linux syscall slices are lower priority unless they directly unblock the
  rounds below.

## Working definition

> Starnix in Nexus is a shared Linux environment launched by a runner and
> implemented as a userspace executive over Axle's generic carrier / VM /
> waitable / transport substrate.

## Hard constraints

1. Axle does not gain Linux-only object families or Linux-only kernel modes.
2. Axle keeps generic mechanisms only:
   carrier objects, guest supervision, VM substrate, wait/port/timer,
   futex parking primitives, transport primitives, generic loader helpers, and
   generic address-space clone helpers.
3. `libax`, `nexus-rt`, and `nexus-io` stay narrow and generic.
4. `nexus-io` does not become the Linux VFS. Linux mount, namespace, procfs,
   anon-inode, and Linux file-description semantics stay in Starnix.
5. Starnix is treated as one shared Linux environment with shared pid,
   process-group, session, mount, socket, and signal state. It is not modeled as
   per-binary glue.
6. Semantic object tests are a required gate for Starnix work. Smoke binaries
   and QEMU scenarios remain integration tests, not the only source of truth.
7. Bootstrap-only payload helpers must not remain on the main production exec
   path.
8. Short-term `fork` performance is explicitly secondary to correctness and
   architectural shape.

## Immediate critical path

### R1. Freeze boundaries and stop growth `[~]`

Goal:

- Stop `starnix` from continuing to grow as one large executive file.
- Freeze the architectural split before more Linux slices land.

Work:

- Treat `references/50_STARNIX_EXEC_MODEL.md` as the frozen kernel/userspace
  split.
- Stop adding features that deepen the current `starnix.rs` monolith unless
  they directly help the refactor.
- Use the following standing rule:
  Starnix work now defaults to "split responsibilities and add semantic tests"
  before "add more syscall surface".

Exit criteria:

- The architectural split and narrow-waist rules are documented and treated as
  active constraints during review.
- New Starnix changes stop broadening the monolith by default.

### R2. In-crate modularization and bootstrap-path demotion `[~]`

Goal:

- Split the current monolith into stable internal layers without changing
  external behavior or workspace shape.

Work:

- Replace `user/nexus-init/src/starnix.rs` with `user/nexus-init/src/starnix/`.
- Keep one crate for now.
- Production exec/image load now resolves only through the Starnix namespace.
  Embedded payload tables remain bootstrap-namespace population helpers, not
  production exec fallback.
- Target internal layout:

```text
user/nexus-init/src/starnix/
  mod.rs

  substrate/
    guest.rs
    packet_loop.rs
    restart.rs

  task/
    task.rs
    thread_group.rs
    process_group.rs
    session.rs
    wait.rs
    exit.rs

  signal/
    action.rs
    queue.rs
    delivery.rs
    signalfd.rs

  mm/
    elf.rs
    stack.rs
    tls.rs
    auxv.rs
    mmap.rs
    exec.rs
    fork.rs

  fs/
    fd.rs
    file_description.rs
    namespace.rs
    mount.rs
    procfs.rs
    anon_inode.rs
    unix.rs

  poll/
    epoll.rs
    readiness.rs

  sys/
    table.rs
    fs.rs
    process.rs
    signal.rs
    mm.rs
    poll.rs
    futex.rs
    net.rs
```

- Keep `sys/` thin: decode guest registers, call semantic objects, write back
  stop-state results.
- Demote `payload_path_for` / `payload_bytes_for` and similar bootstrap tables
  to test-only or bootstrap-smoke-only mechanisms.
- Keep production exec/image load paths namespace-backed.

Exit criteria:

- `starnix.rs` is no longer a monolithic file.
- Production exec flow no longer depends on embedded payload lookup helpers.
- `sys/` is visibly a dispatch layer rather than the main semantic home.

### R3. Generic supervised guest substrate and blocking-op model `[~]`

Goal:

- Introduce one narrow substrate layer between Linux semantics and raw Axle
  guest/VM/wait primitives.
- Replace ad-hoc per-syscall blocking logic with one restart discipline.

Work:

- Extract a generic supervised guest substrate that owns:
  guest session, sidecar, guest memory r/w, resume, syscall completion, and
  packet demux.
- Promote `WaitState` / `WaitKind` into a first-class blocked-operation model.
- Waiting syscalls now enter the stopped state through one `begin_wait` /
  `begin_async_wait` path, and retry through one `WaitKind`-driven restart
  path. Remaining work is to finish migrating semantic subsystems onto that
  shape instead of open-coding new wait logic.
- Make all blocking Linux syscalls converge on one protocol:
  `start -> Ready / Blocked / Interrupted`,
  `resume -> Ready / StillBlocked / Restart`.
- Preserve the current synthetic-object direction for
  `eventfd`, `timerfd`, `signalfd`, and `pidfd`.
- Systematize those objects behind a shared synthetic waitable / readiness
  bridge so `epoll` depends only on wait registration plus readiness
  translation.

Exit criteria:

- Starnix semantic code no longer talks directly to scattered raw
  `ax_guest_session_*` helpers.
- `epoll`, `wait4`, futex, blocking fd I/O, and message I/O all flow through
  one restart discipline.
- Synthetic waitable fds share one common integration path with `epoll`.

### R4. Semantic core objectization and tests `[~]`

Goal:

- Turn the executive into explicit Linux semantic objects that can be tested in
  isolation.

Work:

- Replace the current "big resource bag" shape with explicit semantic objects:
  - `TaskModel`
  - `SignalModel`
  - `MmContext`
  - `FsContext`
- Keep Starnix centered on one shared Linux environment rather than per-binary
  bootstrap glue.
- Host-side Starnix semantic tests now need to remain merge-blocking under
  `just xtest`, not only as QEMU smoke scenarios.
- Those host-side semantic checks should live in focused internal modules
  (for example `starnix/tests/{fd,process,signal,poll,procfs}.rs`) rather than
  accreting back into one large `mod.rs` test block.
- The current first-wave host semantic gate now already covers:
  - `dup2` / `dup3` open-file-description sharing
  - `fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC` descriptor-table duplication rules
  - `FsContext::fork_clone()` preserving shared open-file-description identity
    plus namespace / directory-offset state
  - process-group / session identity updates through `wait4` target matching and `setsid`
  - `rt_sigreturn` plus pure restart-frame handling for `EINTR` / `SA_RESTART`
  - `epoll` interactions with one synthetic waitable plus level-triggered and
    oneshot delivery rules
  - `execve`-side `CLOEXEC` cleanup and caught-signal reset helpers
  - one narrow exec-mm reset rule for writable-range tracking
  - `/proc/self/fd/*` anon-inode projection for `signalfd` / `pidfd` /
    `eventpoll`
- Add host-side semantic tests for at least:
  - `dup` / `dup2` / `dup3` open-file-description sharing
  - process-group / session / `wait4` target matching
  - signal interrupt / restart / `rt_sigreturn`
  - `epoll` interactions with synthetic waitables
  - `fork` / `execve` mm, fd, and signal inheritance/reset behavior
- Keep smoke binaries and conformance scenarios as integration coverage on top
  of those semantic tests.

Exit criteria:

- Each major Linux semantic subsystem has focused unit tests.
- Starnix behavior can be reasoned about without booting a guest payload.
- Shared-environment semantics are primary in the code structure.

### R5. Post-freeze extraction and performance follow-on `[ ]`

Goal:

- Only after semantic boundaries stabilize, extract crates and pursue the more
  expensive VM/performance follow-on work.

Work:

- Consider extracting stable internal layers into dedicated crates:
  - `crates/nexus-starnix-substrate`
  - `crates/nexus-starnix-core`
  - `crates/nexus-starnix-mm`
  - `crates/nexus-starnix-fs`
- Continue VM and Starnix follow-on on top of stable boundaries:
  - pager-backed and file-backed VMO externalization
  - generic MM clone helper
  - better `fork`
  - broader Linux fs/socket/signal semantics

Exit criteria:

- Crate boundaries reflect semantic boundaries rather than temporary file size.
- Performance work no longer forces major architectural reshaping.

## Semantic test inventory

The near-term Starnix test gate should grow around semantic objects, not only
around guest smoke binaries.

Priority test families:

- task/process/session/process-group identity and wait semantics
- Linux signal queueing, interruption, restart, and return
- `MmContext` exec/fork inheritance and reset rules
- Linux file-description sharing and descriptor-table operations
- `epoll` level/edge behavior across native and synthetic waitables
- procfs and anon-inode behavior that projects executive state into fd-visible
  objects

## Deferred but still important

These remain real project tasks, but they are outside the immediate Starnix
architecture-freeze loop:

- external revocation / job / policy tree
- device-facing VM primitives and interrupt objects for DFv2
- user-mode L1 scheduler
- broader FIDL/runtime/component follow-on
- real DataFS implementation beyond the current model/checker

## Practical sequencing

If the immediate goal is "turn the current Starnix bootstrap into a maintainable
system with the least detour", the rough order is:

1. Freeze boundaries and stop monolith growth.
2. Split `starnix.rs` into internal layers while keeping one crate.
3. Introduce the guest substrate and unified blocked-op model.
4. Add semantic-object tests and make them a real gate.
5. Only then extract crates and optimize the slower paths.

## Notes For Agents

- Do not treat "more syscall coverage" as the default next step.
- Prefer semantic tests over new smoke binaries unless integration coverage is
  the missing piece.
- Prefer internal module boundaries before workspace/crate boundaries.
- Do not widen `nexus-io` into a Linux VFS.
- Do not add Linux-only Axle objects to simplify Starnix work.
