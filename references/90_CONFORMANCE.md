# 90 - conformance

Part of the Axle test and contract layer.

See also:
- `Axle_v0.3.md` - engineering and gate expectations
- `10_ARCH_X86_64_STARTUP.md` - startup path exercised by QEMU scenarios
- `11_SYSCALL_DISPATCH.md` - syscall surface under test
- `12_WAIT_SIGNAL_PORT_TIMER.md` - many early MUST contracts live here
- `30_PROCESS_THREAD.md` - process/thread scenarios
- `33_IPC.md` - IPC scenarios and contract coverage
- `34_IPC_CHANNEL.md` - channel-specific scenario surface
- `35_IPC_SOCKET.md` - socket-specific scenario surface
- `36_NET_DATAPLANE.md` - queue-owned network dataplane bootstrap direction
- `40_VM.md` - VM scenarios and contract coverage

## Scope

This file describes the current host-test, fuzz, loom, and QEMU conformance structure in the repository.

## Test layers

The repository currently uses several layers:

- host unit tests for core crates
- host unit tests for `nexus-init` Starnix semantic objects
- loom tests for concurrency-sensitive code
- fuzz smoke for state-machine-heavy subsystems
- host-side concurrent seed replay and triage for schedule-sensitive subsystem boundaries
- QEMU conformance scenarios for syscall and early-kernel behavior

## Current command entry points

Main just targets include:

- `just fmt-check`
- `just xlint`
- `just xtest`
- `just loom`
- `just fuzz-smoke`
- `just concurrency-smoke`
- `just test-kernel`
- `just perf-smoke-qemu`
- `just perf-smoke-bundle`
- `just perf-smoke-kvm`
- `just perf-smoke-parse <serial-log>`
- `just perf-smoke-perfetto <serial-log>`
- `just perf-smoke-archive <serial-log> <label> [cpuinfo]`
- `just perf-smoke-kvm-archive [label]`
- `just check-conformance-contracts`
- `just test-all`

`just xlint` and `just xtest` now both include `nexus-init`, so Starnix host-side semantic tests
are part of the default merge-blocking host gate rather than living only behind QEMU smoke.
Those host-side semantic checks now live in focused internal modules under
`user/nexus-init/src/starnix/tests/{fd,net,poll,procfs,process,signal}.rs` rather
than one monolithic inline `starnix/mod.rs` test block.
That host gate now explicitly covers:
- `dup2` / `dup3` open-file-description sharing
- `fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC` descriptor-table duplication rules
- `FsContext::fork_clone()` preserving shared open-file-description identity
  plus namespace / directory-offset state
- `wait4` target matching and `setsid` session rebinding
- pure `EINTR` / `SA_RESTART` restart-frame handling plus `rt_sigreturn`
- synthetic-waitable to `epoll` readiness bridging plus level-triggered and
  oneshot delivery rules
- `execve`-side `CLOEXEC` cleanup and caught-signal reset helpers
- `/proc/self/fd/*` anon-inode projection for `signalfd` / `pidfd` /
  `eventpoll`
- one first inet loopback semantic slice:
  - listener accept plus bidirectional stream bytes
  - readiness projection into `epoll`
  - inet sockets projecting as `S_IFSOCK` in proc/stat metadata

## Contract catalog

- Contract definitions live in `specs/conformance/contracts.toml`.
- Scenarios declare which contract ids they cover.
- Every MUST contract now also carries explicit concurrent-harness metadata:
  - either `mode = "seeded"` with `system`, `hook_classes`, `state_projections`, and
    `expected_failure_kinds`
  - or `mode = "not_applicable"` with a reason when the current host-side concurrent harness does
    not model that contract
- The `expected_failure_kinds` list is now kept aligned with failures the current
  healthy host-side model can actually surface, rather than with hypothetical
  invariant names that the model itself cannot produce without first modeling a
  bug in the queue or waiter bookkeeping implementation.
- `tools/axle-conformance` checks:
  - unknown contract references
  - uncovered MUST contracts
  - missing / malformed MUST concurrency metadata
- Current MUST gates now include core `wait_async`, `port`, `channel`, and same-page fault serialization contracts in addition to the earlier syscall/handle/timer/SMP basics.
- SMP bring-up coverage now uses two narrow scenario shapes rather than one broad default-int80 run:
  - `kernel.smp.ipi_ack` keeps the 2-core fixed-vector IPI sanity gate
  - `kernel.smp.ap_online_4` now uses one dedicated `smp_smoke` runner under `-smp 4` to assert:
    - all requested APs report online
    - one AP acknowledges one fixed-vector IPI
    - ring3 reaches a breakpoint smoke without depending on the full default-int80 suite under 4-way QEMU fallback timers
- Bootstrap channel coverage now also includes one fragmented mixed-payload gate:
  - one exact-body remap read shape
  - one fallback-copy read shape
  - current assertions now also pin the fragment-pool reuse path:
    - fragmented descriptor count / bytes total
    - pool new/reuse/local-free/current-cache/peak-cache counts
- Bootstrap channel coverage now also includes one async-signal gate:
  - `CHANNEL_WRITABLE` recovery through `wait_async` + `port_wait`
  - `CHANNEL_PEER_CLOSED` delivery through the same path without stale writable republish
- Bootstrap userspace runtime coverage now also includes one Phase-3 gate:
  - Rust ring3 code using `libzircon` can drive channel, socket, timer, port, and handle-close syscalls without handwritten per-syscall assembly
  - `nexus-rt` now exercises a single-thread dispatcher/executor shape:
    - generation-safe signal registration ids
    - one dispatcher timer instead of one kernel timer per sleep future
    - task wakeups routed through user packets on the dispatcher port
    - async channel receive/call and socket readiness paths
- Bootstrap performance-smoke coverage now also includes one minimal measurement gate:
  - a bootstrap ring3 runner can execute `null_syscall`, `wait_one` ping-pong, and cross-core
    wake-path smoke loops under QEMU
  - the kernel exports one bootstrap VMO-backed trace summary covering syscall, scheduler,
    timer, and TLB events, including irq enter/exit edges on timer and reschedule handlers
  - the scheduler slice now also exports one minimal L0 wake telemetry set:
    - run-queue depth
    - blocked-wake handoff count
    - remote-wake latency count / max
    - one global steal counter reserved for future L0 migration work; healthy runs currently keep it at zero
  - the same summary now distinguishes syscall dispatch completion from actual return-to-user
    retirement through `sys_enter` / `sys_exit` / `sys_retire` counts for the deterministic
    null-syscall phase, and now also pins:
    - one native-entry `sys_native_enter` count
    - one native fast-return `sys_native_sysret` count
    for that same phase
  - the same runner now proves one explicit `zx_thread_start()` launch onto a different CPU, then
    reuses that peer worker across the phase-3 wake benchmark, the active-peer TLB slice, and the
    same-page fault slice instead of depending on repeated cross-CPU launches
  - the same runner now also executes one narrow VMAR map/protect/unmap churn slice so TLB-local
    page-flush telemetry is exercised and parsed through the same key=value summary path
  - the same runner now also executes one trap-facing same-page fault slice and exports
    `fault_enter / fault_block / fault_resume / fault_handled / fault_unhandled` counts through
    the same summary path
  - the same runner now also executes one fragmented channel slice:
    - one unaligned `head/body/tail` write path using pooled fragment pages
    - one fallback-copy read path into an ordinary userspace buffer
    - `ax_ipc` enqueue/dequeue/reclaim trace counts plus fragment-pool counters exported through
      the same summary line
  - the same runner now also executes one same-image child-process roundtrip slice:
    - one narrow address-space-switch benchmark built on `zx_process_create` +
      `ax_process_prepare_start` + `zx_process_start`
    - one derived `trace_tlb_phase8_ok` bit proving that phase saw address-space-switch telemetry
  - the same summary now also exports support-aware x86 depth signals:
    - `perf_pmu_supported`, `perf_pmu_version`, `perf_pmu_fixed_counters`
    - PMU deltas for `null_syscall`, local TLB churn, and address-space switch when available
    - `trace_tlb_as_switch_*` counts plus `trace_tlb_invpcid_single`
    - `trace_tlb_pcid_enabled` / `trace_tlb_invpcid_enabled`
  - the same peer-worker reuse also keeps the active-address-space TLB and fault slices from
    depending on a second synthetic launch rule
  - the phase-3 wake-path gate is now frozen as a minimum-contract check rather than as one exact
    raw counter:
    - current native-syscall L0 runs now commonly land in the `55..=60` range for the phase-3
      remote-wake / handoff / latency counters on QEMU
    - the summary therefore exports one derived `trace_sched_phase3_ok` bit while still printing
      the raw phase-3 counters for diagnosis
  - the scenario currently acts as a wiring and attribution gate, not as a stable performance
    regression threshold
  - the new `just perf-smoke-bundle` + `just perf-smoke-parse` flow is the current minimal
    bare-metal baseline path:
    - build one kernel + perf-smoke runner bundle
    - capture one serial log from a real machine
    - extract the same key=value perf summary into one JSON baseline
    - export the same trace stream into one Perfetto-compatible JSON timeline
    - archive one baseline capture under `target/perf-smoke-baselines/<timestamp>-<label>/`
      with:
      - `serial.log`
      - `perf-smoke.json`
      - `baseline.json`
      - `perfetto-trace.json`
      - `manifest.json`
  - `just perf-smoke-kvm` is the current minimal KVM-hosted baseline path:
    - reuses the same bundle
    - runs `qemu-system-x86_64` with `-machine q35,accel=kvm -cpu host`
    - writes the serial log to `target/perf-smoke-kvm/serial.log`
    - writes `perf-smoke.json` with the guest summary
    - writes `baseline.json` with host CPU flags plus guest x86 feature signals
    - writes `perfetto-trace.json` with the full bootstrap trace timeline
  - `just perf-smoke-kvm-archive` then snapshots that run into the same
    `target/perf-smoke-baselines/` archive layout used by real-machine captures
- Bootstrap VM coverage now also includes one narrow object-metadata gate:
  - `kernel.vmo.info_bootstrap`
  - one anonymous VMO must report the current public local-private object
    contract:
    - `Anonymous`
    - `LocalPrivate`
    - resizable + COW-capable + kernel-readable/kernel-writable flags
    - size `4096`
  - one bootstrap code-image VMO must report the current public
    pager-backed/shared object contract:
    - `PagerBacked`
    - `GlobalShared`
    - read-only shared behavior flags
    - non-zero logical size
- Bootstrap VM coverage now also includes one narrow shared-handle behavior
  gate:
  - `kernel.vmo.shared_bootstrap`
  - one bootstrap code-image VMO must prove the current shared pager-backed
    source-handle behavior:
    - `vmo_read()` succeeds
    - the first bytes match the current bootstrap code window mapping
    - direct `vmo_write()` returns `ZX_ERR_ACCESS_DENIED`
    - direct `vmo_set_size()` returns `ZX_ERR_ACCESS_DENIED`
- Nexus-root VM coverage now also includes one narrow staged shared-anonymous
  source-handle gate:
  - `kernel.vmo.staged_shared_nexus_bootstrap`
  - one `/boot/...` staged shared-anonymous `GetVmo` handle must prove the
    current public source-handle contract:
    - `ax_vmo_get_info()` reports `Anonymous + GlobalShared`
    - the exported size is page-aligned and large enough for the staged asset
    - `vmo_read()` succeeds and the bytes match the boot asset payload
    - direct `vmo_write()` returns `ZX_ERR_ACCESS_DENIED`
    - direct `vmo_set_size()` returns `ZX_ERR_ACCESS_DENIED`
- Bootstrap VM coverage now also includes one narrow anonymous-promotion gate:
  - `kernel.vmo.promotion_bootstrap`
  - one fresh anonymous VMO must first report the current local-private object
    contract:
    - `Anonymous`
    - `LocalPrivate`
  - after one explicit cross-process handle transfer/install:
    - the imported child handle must report `Anonymous + GlobalShared`
    - the parent's original remaining handle must also report
      `Anonymous + GlobalShared`
- Bootstrap VM coverage now also includes one narrow private-clone source/shadow
  gate:
  - `kernel.vmo.private_clone_bootstrap`
  - one shared pager-backed source handle must prove the current
    `PRIVATE_CLONE` split:
    - the initial private-clone mapping bytes match the shared source bytes
    - a write through the mapping becomes visible through that mapping
    - the same write does not mutate bytes read back through the shared source
      handle
    - `ax_vmo_get_info()` on the source handle remains
      `PagerBacked + GlobalShared` before and after the mapping-local write
- Starnix runtime/TLS coverage now also freezes the first generic MM clone
  slice used by `fork`:
  - `kernel.starnix.runtime_tls_bootstrap`
  - the child still inherits the parent's `fs_base`
  - one writable direct image/data location modified in the parent before
    `fork` must remain visible in the child after `fork`
  - one `brk()`-grown heap location modified in the parent before `fork` must
    remain visible in the child after `fork`
  - one anonymous `mmap()` location modified in the parent before `fork` must
    remain visible in the child after `fork`
  - this now proves that Starnix `fork` uses VM truth for:
    - root direct mappings
    - heap backing-handle reconstruction
    - anonymous `mmap()` backing-handle reconstruction
- Bootstrap runtime coverage now also includes one narrow queue-owned net dataplane gate:
  - two ring3 worker threads act as minimal device-side peers, one queue pair each
  - one bootstrap `PciDevice` handle is now seeded into the runner shared-slot window
  - the runner now queries device info plus one generic config/BAR/interrupt resource index
    through the public device syscall surface instead of synthesizing a separate userspace config page
  - one contiguous VMO supplies the shared queue/buffer memory
  - explicit `DmaRegion` objects now pin:
    - the shared queue/buffer memory
    - the exported BAR0 VMO
    - with explicit `DEVICE_READ | DEVICE_WRITE` pin options
  - DMA-region IOVA lookup, not raw VMO lookup, now freezes the DMA-style address handoff shape
  - DMA-region segment lookup now also freezes the current "one segment per pinned BAR0/queue
    region" bootstrap assumption
  - driver mapping of the exported BAR0 window now consumes the BAR-exported map options and
    therefore explicitly exercises `ZX_VM_MAP_MMIO`
  - one BAR0 register window now freezes one first narrow virtio-style control-plane shape:
    - device identity/version
    - device feature bits plus driver-acknowledged feature bits
    - device status
    - queue-select plus selected-queue size / enable / notify-off state
    - selected-queue desc / avail / used DMA addresses
    - one queue-state array behind that view carrying runtime notify/completion counts
  - one ready interrupt, one TX-kick interrupt, and one RX-complete interrupt per queue pair carry
    control flow
  - the runner now also cross-checks those exported interrupts through `interrupt_get_info()`:
    - mode/vector metadata must agree with the PCI-exported snapshot
    - the current synthetic transport requires triggerable interrupt objects
  - the runner now also queries the device's virtual interrupt-mode capability through
    `ax_pci_device_get_interrupt_mode()` and pins:
    - supported / active / triggerable flags
    - base vector `0`
    - vector count `queue_pairs * interrupt_groups`
  - the runner now also probes one synthetic `MSI` round-trip through the same public contract:
    - `MSI` mode reports `SUPPORTED` but not `ACTIVE`
    - `ax_pci_device_set_interrupt_mode(..., MSI)` succeeds
    - one re-fetched interrupt handle reports `ZX_INTERRUPT_MODE_MSI` and is not triggerable
    - the driver then restores `VIRTUAL` mode before it starts using queue interrupts
  - the runner now also discovers the transport through `ax_pci_device_get_config()` and pins:
    - config export status
    - config export flags (`MMIO | READ_ONLY`)
    - config export map options (`ZX_VM_MAP_MMIO`)
    - capability discovery success
    - BAR/common/notify/isr/device offsets
    - explicit `ax_pci_device_set_interrupt_mode(..., VIRTUAL)` success
  - the runner now also queries both DMA-region objects through `ax_dma_region_get_info()` and
    pins:
    - identity-IOVA and physically-contiguous flags
    - base device-visible address for BAR0 and queue memory
    - one coalesced segment count of `1` for the current bootstrap BAR0 and queue regions
  - one reusable split TX/RX virtio-style transport slice now completes one eight-packet batched
    loopback round without channel/socket data-plane help, and the driver now exercises a
    virtio-style feature/status/queue-select bring-up sequence before the first kick
  - the summary now also exports:
    - `config_backing_create`
    - `config_pin_create`
    - `config_dma_lookup`
    - `config_alias_create`
    - `pci_config_info`
    - `pci_config_flags`
    - `pci_config_map_options`
    - `config_alias_pin_create`
    - `config_alias_dma_lookup`
    - `config_alias_match`
    - `config_alias_map`
    - `pci_config_map`
    - `pci_config_caps_ok`
    - `pci_config_common_bar`
    - `pci_config_common_offset`
    - `pci_config_notify_offset`
    - `pci_config_isr_offset`
    - `pci_config_device_offset`
    - `reg_backing_create`
    - `reg_pin_create`
    - `reg_dma_lookup`
    - `reg_backing_map`
    - `pci_irq_mode_info`
    - `pci_irq_mode_flags`
    - `pci_irq_mode_base_vector`
    - `pci_irq_mode_vector_count`
    - `pci_irq_mode_set`
    - `bar0_create`
    - `bar0_pin_create`
    - `bar0_dma_lookup`
    - `bar0_dma_info`
    - `bar0_dma_flags`
    - `bar0_dma_iova`
    - `bar0_match`
    - `bar0_map`
    - `queue_pin_create`
    - `queue_dma_lookup`
    - `queue_dma_info`
    - `queue_dma_flags`
    - `queue_dma_iova`
    - `mmio_ready`
    - `mmio_device_features`
    - `mmio_driver_features`
    - `mmio_status`
    - `pci_vendor_id`
    - `queue_pairs`
    - `tx_notify_count`
    - `rx_complete_count`
    - `tx_notify_mask`
    - `rx_complete_mask`
    - `tx_ready_mask`
    - `rx_ready_mask`
    - `packet_count`
    - `packet_match_count`
    - `batch_cycles`
- Bootstrap socket coverage now also includes one narrow datagram gate:
  - datagram create succeeds through the normal socket object family
  - one peek/read pair proves message preservation without stream fallback
  - one truncating read proves the current bootstrap consume-on-truncate behavior
  - one bounded-fill loop proves datagram writes stay atomic and fail with `SHOULD_WAIT` rather
    than degrading into short writes
  - one peer-close wait/write pair proves peer-closed signaling and error propagation still match
    the shared socket signal family
- Component-framework bootstrap coverage now also includes one eager-topology gate:
  - a minimal `nexus-init` can resolve a root manifest and launch eager ELF children
  - one protocol route through `/svc` is exercised end-to-end
  - child `OnTerminated` controller events are observed back in the manager
- The round-three component gate extends that with lazy lifecycle coverage:
  - one provider is lazy-started on first routed `/svc` open
  - `Stop` / `Kill` controller requests are exercised through the minimal component-manager path
  - `OnTerminated` controller events, not raw task-handle waits, are the lifecycle contract at this layer
- The Round-1 Starnix bootstrap scenario also runs under `-smp 2` and continues to guard the
  scheduler's first-run child-launch path against gross regressions:
  - the scenario explicitly forbids a kernel `#GP` during that launch path
  - first-run child activation now stays on the normal preferred-CPU / wake-affine path; the
    bootstrap gate no longer depends on a special remote-first launch exception
- The first Round-2 Starnix fd scenario now extends that same bootstrap path with one narrow
  Linux-fd slice:
  - `read` / `write` / `close`
  - `pipe2`
  - `socketpair(AF_UNIX, SOCK_STREAM)`
  - the guest path relies on the generic guest-session memory read/write helpers rather than on a
    Linux-specific kernel syscall mode
- The comprehensive Round-2 Starnix bootstrap scenario now closes the intended single-process
  task/mm/fs/socket loop:
  - `openat` / `fstat` / `newfstatat` / `getdents64`
  - `brk`
  - anonymous `mmap` / `mprotect` / `munmap`
  - read-only file-backed `mmap` through `FdOps::as_vmo()` / `GetVmo`
  - the supervisor keeps one Linux-side `LinuxMm` / map-tree control plane while continuing to
    rely on Axle VMAR/VMO syscalls for the real mapping work
- The Round-3 Starnix bootstrap scenario now closes the minimal task/process loop:
  - `clone(CLONE_THREAD)`
  - `fork`
  - `execve`
  - `wait4`
  - zombie reap and reparent-to-root behavior
  - the guest still sees stable Linux task identity even when `execve` swaps the underlying Axle
    carrier process/thread resources
- The current Round-4 Starnix signal scenario now closes the current pure-executive signal slice:
  - `getpid` / `gettid`
  - `rt_sigaction` with `SIG_DFL`, `SIG_IGN`, and one minimal caught-handler path
  - `rt_sigprocmask`
  - `kill` / `tgkill`
  - signal dequeue and delivery on the syscall-resume boundary
  - `rt_sigreturn`
  - `wait4` interruption with `EINTR`
  - `wait4` restart when the installed action carries `SA_RESTART`
  - blocking pipe-backed `read` interruption with `EINTR`
  - blocking pipe-backed `read` restart when the installed action carries `SA_RESTART`
- The current Round-4 Starnix futex scenario now closes the first futex-hybrid slice:
  - `FUTEX_WAIT_PRIVATE`
  - `FUTEX_WAKE_PRIVATE`
  - `FUTEX_REQUEUE_PRIVATE`
  - waiters are Linux tasks parked in the userspace executive rather than the
    supervisor thread itself
  - this gate intentionally excludes timeout, bitset, robust-list, and
    shared-futex identity semantics, which remain later work
- The first Round-6 Starnix long-tail scenario now closes one narrow anon-inode slice:
  - `eventfd2`
  - nonblocking empty-read `EAGAIN`
  - epoll-visible readability after one counter write
  - the current implementation keeps the counter and policy in the Starnix
    executive while driving readiness through one synthetic wait handle rather
    than adding a dedicated kernel eventfd object
- The second Round-6 Starnix long-tail scenario now closes one narrow timerfd
  slice:
  - `timerfd_create(CLOCK_MONOTONIC)`
  - one-shot `timerfd_settime(..., TFD_TIMER_ABSTIME, ...)`
  - `read` returning one expiration count
  - epoll-visible readability through the native timer object's signaled state
  - interval timers and `timerfd_gettime` remain outside the current slice
- The third Round-6 Starnix long-tail scenario now closes one narrow signalfd
  slice:
  - `signalfd4`
  - one blocked `SIGUSR1` queued through the existing executive signal state
  - `read` returning one minimal `signalfd_siginfo`
  - epoll-visible readability through one synthetic signalfd wait handle
  - the current bootstrap implementation ties each signalfd object to the
    creating task's blocked/pending view plus its thread-group shared pending
    set; full shared-fd cross-thread semantics remain later work
- The fourth Round-6 Starnix long-tail scenario now closes the next futex tail
  slice:
  - `FUTEX_WAIT_BITSET_PRIVATE`
  - `FUTEX_WAKE_BITSET_PRIVATE`
  - `set_robust_list`
  - `get_robust_list`
  - owner-died marking on thread exit for one private robust futex word
  - the current bootstrap gate still excludes timeout, shared-futex identity,
    and PI robust-futex policy
- The fifth Round-6 Starnix long-tail scenario now closes one narrow SCM_RIGHTS
  slice:
  - `sendmsg`
  - `recvmsg`
  - one `SCM_RIGHTS` control message carrying one shared open-file description
    over a tracked `AF_UNIX` `SOCK_STREAM` socketpair
  - the current bootstrap gate intentionally keeps ancillary parsing narrow:
    one rights cmsg, no `msg_name`, and no broader UNIX datagram/seqpacket
    coverage yet
- The sixth Round-6 Starnix long-tail scenario now closes one narrow pidfd
  slice:
  - `pidfd_open`
  - `pidfd_send_signal`
  - pidfd readability after the target thread group becomes zombie / exited
  - the current bootstrap gate intentionally keeps the pidfd object synthetic in
    the executive and excludes `waitid(P_PIDFD)` plus broader pidfd lifecycle
    features
- The seventh Round-6 Starnix long-tail scenario now closes one narrow `/proc`
  + job-control slice:
  - `getpgrp` / `getpgid` / `getsid`
  - `setpgid` / `setsid`
  - `wait4` target matching for `pid == 0` and explicit negative process-group
    targets
  - `kill` routing for caller process-group and explicit process-group targets
  - synthetic `/proc/self/status`, `/proc/self/stat`, `/proc/self/fd`, and
    `/proc/self/fd/<n>` access, including one proxied write through
    `/proc/self/fd/1`
  - this gate also locks in Linux x86_64 integer-argument decoding at the
    executive boundary: syscall parameters such as `AT_FDCWD == -100` must be
    interpreted from the low 32 bits of the guest register, not by trying to
    downcast the raw 64-bit register value
- The eighth Round-6 Starnix long-tail scenario now extends that with one
  `/proc` + stop/continue slice:
  - synthetic `/proc/self/comm`
  - synthetic `/proc/self/cmdline`
  - synthetic `/proc/self/task`
  - synthetic `/proc/self/task/<tid>/status`
  - synthetic `/proc/<pid>/task/<tid>/{comm,status}` for one stopped child
  - `SIGTSTP` default-delivery entering thread-group stop state while retaining
    the originating job-control stop signal in wait status
  - `SIGCONT` resuming the stopped thread group
  - parent-observable `SIGCHLD` stop / continue metadata through one blocked
    `signalfd`
  - `wait4(..., WUNTRACED, ...)` observing the stop event
  - `wait4(..., WCONTINUED, ...)` observing the continue event
- The ninth Round-6 Starnix long-tail scenario now pushes that job-control view
  through one tty-oriented slice:
  - background `read(0, ...)` on the controlling stdio set stops the child with
    `SIGTTIN`
  - background `write(1, ...)` on the same controlling stdio set stops the
    child with `SIGTTOU`
  - `wait4(..., WUNTRACED, ...)` and blocked `signalfd(SIGCHLD)` both observe
    those concrete tty stop causes
  - `/proc/<pid>/task/<tid>/stat` now exposes stopped thread-state for the
    child while it remains in group-stop
  - the bootstrap gate intentionally keeps tty ownership policy narrow:
    foreground/background is modeled only for the inherited stdio set over one
    shared executive tty core and its controlling slave pty
  - the same shell-facing console slice now also proves:
    - `TCGETS` / `TCSETS*`
    - `TIOCGWINSZ` / `TIOCSWINSZ`
    - `TIOCGPGRP` / `TIOCSPGRP`
    - shell-visible character echo over the inherited stdio set
    - `/dev/ptmx`
    - `/dev/pts/0`
    - slave-pty-backed controlling tty for the shell stdio set
  - the bootstrap gate still intentionally excludes:
    - pty readiness through `poll` / `epoll`
    - packet mode and broader tty ioctl coverage
    - network-facing pty sessions such as `sshd`
- The first post-R7 loader/runtime scenario now closes one narrow dynamic-ELF
  bootstrap slice:
  - `execve` of one ET_EXEC or fixed-bias ET_DYN main image carrying `PT_INTERP`
  - namespace resolution of the requested interpreter path
  - ET_DYN interpreter mapping at one explicit load bias
  - `AT_BASE` handed to the initial stack image
  - first userspace entry through the interpreter rather than the main image
  - the current bootstrap gate intentionally keeps the slice narrow:
    - one static interpreter payload
    - no shared-library dependency graph
    - no relocations beyond the fixed entry path
    - no general `PT_INTERP` package/runtime search policy yet
- The next post-R7 loader/runtime scenario now closes one narrow dynamic-TLS
  bootstrap slice:
  - static `PT_TLS` parsing for:
    - one ET_EXEC or fixed-bias ET_DYN main image launched through the existing `PT_INTERP` path
    - one ET_DYN interpreter image
  - one initial-thread TLS/TCB allocation in the executive-owned Linux mm
    with the main-image TLS block remaining adjacent to the TCB
  - `fs_base` pointed at that TCB before the first main-image instruction
  - richer initial auxv entries:
    - `AT_UID`
    - `AT_EUID`
    - `AT_GID`
    - `AT_EGID`
    - `AT_PLATFORM`
    - `AT_HWCAP`
    - `AT_CLKTCK`
    - `AT_RANDOM`
    - `AT_EXECFN`
    - `AT_SECURE`
    - `AT_HWCAP2`
  - the current gate intentionally keeps the slice narrow:
    - only one ET_EXEC-or-ET_DYN main image plus one ET_DYN interpreter image
    - no general shared-object TLS dependency graph
    - no final libc TLS relocation/runtime model yet
- The next dynamic-userspace scenario now closes one real glibc bootstrap gate:
  - one glibc-linked PIE hello payload started through the packaged
    `ld-linux` + `libc.so.6` runtime path
  - loader-driven file-backed `MAP_FIXED` remaps, including one writable
    private segment seeded through the executive's narrow anonymous-copy path
  - main-image RELRO `mprotect` succeeding even though the executable image
    itself was installed through the native exec helper instead of the generic
    `mmap` control plane
  - the current gate intentionally keeps the slice narrow:
    - one small real program rather than a general distro userspace claim
    - no full shared-object dependency graph beyond `ld-linux` + `libc.so.6`
    - no `vDSO` / `vvar`
    - no `gs_base`
- The next post-R7 libc/runtime scenario now closes one narrow cwd/fd-management
  slice:
  - `getcwd`
  - `chdir`
  - `dup2`
  - `dup3`
  - `fcntl(F_GETFD / F_SETFD / F_GETFL / F_DUPFD_CLOEXEC)`
  - cwd policy remains in the executive's `ProcessNamespace`, not in Axle
    kernel task state
  - fd duplication and `CLOEXEC` remain Linux-fd semantics over the existing
    shared open-file-description substrate
  - this gate intentionally excludes `arch_prctl`, TLS setup, positional I/O,
    and broader libc startup dependencies, which remain later
    runtime-enablement work
- The next post-R7 runtime/process scenario now closes one narrow
  identity/access/limit slice:
  - `getuid`
  - `geteuid`
  - `getgid`
  - `getegid`
  - `getppid`
  - `access`
  - `faccessat`
  - `faccessat2`
  - `prlimit64`
  - the current gate intentionally keeps that contract narrow:
    - identity syscalls currently report one root-style bootstrap identity
    - `prlimit64` currently supports self queries for `RLIMIT_STACK` and
      `RLIMIT_NOFILE`
    - `faccessat*` currently checks mode bits over existing local and
      synthetic backends without introducing a full DAC policy model
- The next post-R7 runtime/filesystem scenario now closes one narrow positional
  I/O and metadata slice:
  - `pread64`
  - `pwrite64`
  - `statx`
  - `newfstatat(..., AT_EMPTY_PATH, ...)`
  - relative `readlinkat` against synthetic `/proc` directory fds
  - the current gate intentionally keeps positional I/O narrow:
    - local bootstrap file backends and synthetic proc text/proxy objects are
      covered
    - no new native `FdOps` offset-I/O contract is introduced yet
    - remote/service-backed files still remain outside this bootstrap slice
- The next post-R7 runtime/TLS scenario now closes one narrow guest-thread TLS
  slice:
  - `arch_prctl(ARCH_SET_FS)`
  - `arch_prctl(ARCH_GET_FS)`
  - `clone(..., CLONE_SETTLS, ...)`
  - fork inheriting the parent's `fs_base`
  - the gate intentionally keeps the kernel-side helper generic:
    - one thread-carrier `fs_base` set/get control plane
    - no Linux-only syscall mode
    - no `gs_base`
    - no broader ELF TLS or `arch_prctl` subcommand surface yet
- VMAR lifecycle is now also a MUST gate for bootstrap VM/TLB semantics:
  - map / protect / unmap must remain stable at the syscall surface
  - the calling thread must observe the committed mapping / protection state on return
- The first post-bootstrap substrate push now also reserves MUST gate ids for:
  - per-CPU L0 scheduler wake and reschedule behavior
  - generic process launch
  - executable mappings
  - strict TLB visibility
  Some of these gates currently start with minimal QEMU scenario definitions and tighten as kernel-visible telemetry lands.

This makes contract coverage part of the repo workflow, not just informal documentation.

## Scenario model

- Scenario specs live under `specs/conformance/scenarios/`.
- They cover current bootstrap subsystems such as:
  - waits / ports / timers
  - channel behavior
  - fragmented channel payload remap/copy coverage
  - virtual interrupt plus physical/contiguous VMO bootstrap smoke
  - socket behavior
  - VMO / VMAR behavior
  - process / thread behavior
  - SMP smoke
  - VM fault contention and loan/COW paths
  - Nexus root-manager bring-up slices
  - staged Starnix bootstrap/runtime slices, including dynamic ELF and libc/runtime follow-on gates
  - one interactive Starnix shell slice:
    - `kernel.starnix.busybox_shell_bootstrap` boots `boot://root-starnix-shell`
      and drives `busybox ash` over the QEMU serial console
    - the current gate proves one narrow command set:
      `echo`, `ls`, `cat`, `mkdir`, `rm`, and `ps`
    - the gate uses a host-side shell driver so command pacing is stable and
      does not depend on one best-effort `printf` burst into serial stdin
    - the same driver now also asserts:
      - the shell no longer reports `can't access tty`
      - typed commands are echoed before execution
      - `/dev/ptmx`, `/dev/pts`, and `/dev/pts/0` are present inside the shell
  - the older `kernel.starnix.round6_proc_tty_bootstrap` smoke has now been
    retired
    - its job-control and `/proc` coverage is superseded by:
      - host semantic tests under `starnix/tests/{process,procfs}.rs`
      - the pty-backed shell slice above

## Runner model

- `tools/axle-conformance` is the host-side runner and reporting tool.
- It supports running, listing, replaying, and garbage-collecting scenario runs.
- Results are written under `target/axle-conformance/`.
- Scenarios are now grouped by exact `command` vector before execution:
  - one command-group run can satisfy many scenario assertions
  - each run still emits per-scenario `result.json`
  - shared `stdout.log` / `stderr.log` and group-level result metadata now live under each run's
    `groups/` subtree
- Most kernel scenarios build the kernel plus the current userspace runner, boot QEMU, and treat the printed summary line as the stable observable contract.
- QEMU scenarios that boot `nexus-test-runner` now copy the built runner binary to one unique temp
  path per command-group attempt before launching QEMU.
  - this avoids cross-group contamination when the same Cargo target is rebuilt concurrently with
    different entrypoint or assembly payload environment variables
- The runtime/reactor bootstrap scenario is the first case where the userspace runner entrypoint itself is defined in Rust instead of a standalone hand-written `.S` payload.
- That scenario now asserts structured dispatcher metrics instead of relying only on process exit:
  - registration slot reuse with generation advance after cancel
  - channel receive and channel call/reply correctness
  - sleep completion through one dispatcher timer
  - socket readiness and follow-on read correctness
- The eager component-topology bootstrap scenario is the first case where the
  component gate boots a dedicated `nexus-init` / `ElfRunner` root manager
  instead of reusing `nexus-test-runner` as both harness and manager.
- That component gate now boots a dedicated `nexus-init` image plus separate
  `echo-provider`, `echo-client`, and `controller-worker` ELFs through QEMU
  loader slots, rather than having `nexus-test-runner` impersonate every role
  from one self image.
- The eager and lazy component scenarios now rebuild the same `nexus-init`
  binary with different root-manifest URLs via `NEXUS_INIT_ROOT_URL`; topology
  selection is no longer driven by a separate smoke-mode branch in the manager.
- Those component scenarios now also exercise the current bootstrap `/boot`
  asset tree indirectly:
  - the built-in boot resolver opens compiled manifests from `/boot/manifests`
  - `ElfRunner` opens `/boot/bin/*` objects and requests read-only executable VMOs
- Because those dedicated userspace binaries are still linked at the
  long-standing bootstrap userspace VA above 4 GiB, the component scenarios
  build them with `RUSTFLAGS='-C code-model=large'` instead of changing the
  whole `x86_64-unknown-none` target configuration.
- The `nexus-init`-based component and Starnix scenarios now also force
  `-C debuginfo=0` for those QEMU raw-loader builds:
  - the bootstrap loader path imports the final userspace image as one raw ELF
    blob rather than as a relocatable debug-aware image format
  - leaving full debug sections enabled made the Rust ELFs large enough to
    regress earlier scenarios into QEMU timeouts even when the underlying
    behavior was still correct
- The component scenarios now use wider QEMU loader spacing than the first
  round-two version because the dedicated Rust ELFs outgrew the older 4 MiB
  gaps, and the kernel bootstrap PMM reserved floor now follows that loader
  span instead of assuming a fixed 32 MiB ceiling is always sufficient.
- The root bootstrap runner now stages at `0x0700_0000` instead of the old
  `0x0100_0000` slot because the fixed 4 MiB bootstrap code backing lives in
  the same low-RAM identity map during bring-up; the higher slot keeps the raw
  QEMU loader image from being overwritten before the loader imports it.
- The repo now also ships one user-facing Starnix shell recipe:
  - `just starnix-shell`
  - it boots the same `boot://root-starnix-shell` manifest used by the
    conformance shell gate and leaves QEMU attached to the interactive serial
    console instead of driving commands automatically
  - when stdin is a tty, the recipe now temporarily switches the host terminal
    to raw/no-echo mode before launching QEMU so character-at-a-time shell
    input reaches the guest instead of being line-buffered by the host
  - `just starnix-shell-kvm`
  - same shell path, but under `-machine q35,accel=kvm -cpu host`
  - this is the preferred day-to-day interactive entrypoint because busybox
    applet `execve` latency is dramatically lower than under pure TCG
- The bootstrap code window above 4 GiB now spans 16 MiB, which keeps the
  runtime dispatcher runner, current `nexus-init` manager images, and the
  shared summary pages from overlapping in the fixed bootstrap mapping.
- Some bootstrap channel metrics currently come from a second structured summary line rather than
  the main `int80 conformance ok (...)` line.
  - the fragmented channel payload scenario uses this to report both remap-path and fallback-copy
    results without overloading the older monolithic line further
- The device-facing bootstrap smoke now also reports through its own structured summary line:
  - `kernel: device vm interrupt smoke (...)`
  - current assertions cover:
    - virtual interrupt create / get-info / wait / trigger / mask / unmask / ack
    - contiguous VMO creation, physical-address lookup, and contiguity check
    - contiguous VMO pin into one `DmaRegion` object with explicit DMA permission bits plus
      pinned-range paddr lookup
- The narrow net dataplane transport now has two conformance shapes:
  - `kernel.runtime.net_dataplane_bootstrap`
    - boots `nexus-test-runner` directly into the current queue-owned net smoke entrypoint
  - `kernel.runtime.net_dataplane_nexus_bootstrap`
    - boots `nexus-init` with `NEXUS_INIT_ROOT_URL=boot://root-net-dataplane`
    - verifies that the same synthetic PCI-shaped transport and `DmaRegion`-backed queue memory
      can be consumed through the current Nexus root bootstrap path rather than only through the
      dedicated test runner
    - physical VMO aliasing over an existing contiguous page
    - physical VMO pin into one `DmaRegion` object with explicit DMA permission bits plus
      pinned-range paddr lookup
  - Starnix inet coverage now has its first QEMU guest-facing loopback gate:
  - `kernel.starnix.runtime_net_bootstrap`
  - one guest payload now proves:
    - `socket(AF_INET, SOCK_STREAM)`
    - `bind` / `listen` / `accept4`
    - `connect`
    - `shutdown`
    - `getsockname` / `getpeername`
    - minimal `SO_REUSEADDR` / `TCP_NODELAY`
    - stream byte exchange plus EOF after half-close
  - Starnix remote shell coverage now has its first QEMU host-forwarded gate:
    - `kernel.starnix.remote_shell_bootstrap`
    - one host driver now proves:
      - QEMU user-net `hostfwd` into the guest network path
      - remote prompt / echo / command output round-tripping through the
        socket-backed tty bridge
      - remote `/dev/ptmx`, `/dev/pts/0`, and `ps` shell commands over the
        network shell path
  - no sshd gate exists yet
  - those remain the next network-facing vertical-slice cuts after the current
    shell + loopback milestone
- `tools/axle-concurrency` is a host-side Snowcat-lite runner for concurrent seeds:
  - seeds carry both operation programs and schedule hints
  - replay metadata includes runner version, logical CPU count, flags, PRNG seed, and step budget
  - each replay now also records stable hook classes and state projections in addition to the older
    semantic edge strings and hashed state signatures
  - the corpus predictor now scores seeds by rare semantic edges, rare state signatures, failure kinds,
    hint richness, and short-program density
  - mutation now chooses parents from the top predicted retained seeds instead of simple round-robin reuse
  - the corpus keeps seeds when they add semantic edge coverage, state signatures, or failure kinds
  - retained seeds are written under `target/axle-concurrency/host-corpus/`
  - each smoke run also writes `contract-coverage.json` under the host corpus directory and prints:
    - uncovered contract -> hook-class bindings
    - uncovered contract -> state-projection bindings
    - uncovered contract -> expected-failure-kind bindings
  - retained seeds now first try a direct guest-side replay path:
    - `tools/axle-concurrency` generates a dedicated bootstrap userspace runner assembly payload for
      the seed and boots it in QEMU
  - if the direct guest path does not converge, QEMU triage currently falls back to the closest
    existing bootstrap conformance scenario bundle through `tools/axle-conformance`

## Concurrent seed model

- The current concurrent runner starts with:
  - `wait / port / timer`
  - `futex / fault`
  - `channel / handle`
- It does not fuzz raw bytes directly at the subsystem level.
- Instead, it mutates short two-actor programs plus schedule hints such as:
  - `YieldHere`
  - `PauseThread`
  - `DelayTimerFire`
  - `ForceRemoteWake`
- Hints are attached to stable semantic hook ids rather than source locations.

## State-signature model

- The concurrent runner keeps abstract state signatures in addition to semantic edge hits.
- Signatures intentionally exclude raw addresses, handle values, and object ids.
- Current signatures summarize things such as:
  - blocked waiter counts
  - port queue occupancy and readiness
  - timer signal summary
  - futex queue occupancy
  - fault in-flight leader/waiter shape
- This exists because concurrent failures often appear under the same code coverage but different abstract state.
- The contract layer now also tracks named state projections alongside these hashes so retained-seed
  coverage can be reported back against contract metadata instead of staying only in the seed corpus.

## In-kernel / ring3 bridge

There are currently two closely related early test paths:

- an older in-kernel `int80_conformance` bridge under `kernel/axle-kernel/src/bringup/`
- the newer `user/test-runner` ring3 path used by the kernel bootstrap runner

The current tree still carries some bootstrap testing infrastructure in both places because the system is in transition from early kernel-only checks to more normal ring3-driven conformance.

## Current limitations

- Conformance coverage is strongest for the current bootstrap syscall surface, not for future subsystem families that are still missing.
- Some bring-up tests still depend on special bootstrap userspace plumbing.
- Loom coverage now extends beyond `axle-sync` into:
  - host-side `axle-core` wait-core winner races (`wake/timeout/cancel/requeue`)
  - host-side `axle-mm` fault/loan accounting models
- `axle-core` port/observer lifecycle and backpressure are currently covered by host unit tests and
  QEMU conformance, not loom state-space exploration.
- A local Stage-3 timer-backend profile currently does not justify replacing the binary-heap
  deadline backend with a wheel:
  - `BinaryHeap` push/pop churn stayed in the tens-of-nanoseconds range in a synthetic host-side
    profile up through ~16K pending entries
  - current QEMU conformance workloads do not show timer-backend pressure large enough to justify a
    more complex wheel / hybrid design yet
- The concurrent runner is currently strongest on the host-side semantic models.
- QEMU replay now prefers direct guest-side seed execution by generating a dedicated bootstrap runner
  from each retained seed.
- The direct guest path is still intentionally conservative:
  - it is a seed-driven runner generator, not yet a general-purpose in-guest bytecode interpreter
  - some retained seeds still fall back to existing scenario bundles when the direct path does not
    converge
- It still does not cover the full in-kernel wait/fault orchestration path under the real trap /
  scheduler bridge.
- The test architecture is already useful and real, but it is not yet the final long-term system-test stack for NexusOS.
