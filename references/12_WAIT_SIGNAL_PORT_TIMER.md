# 12 - wait / signal / port / timer

Part of the Axle waitable-object layer.

See also:
- `11_SYSCALL_DISPATCH.md` - syscall entry points for waits and signals
- `20_HANDLE_CAPABILITY.md` - rights and handle ownership around waitable objects
- `21_OBJECT_MODEL.md` - object families that expose waitable state
- `30_PROCESS_THREAD.md` - thread blocking and wake relationships
- `34_IPC_CHANNEL.md` - channel signal semantics
- `35_IPC_SOCKET.md` - socket signal semantics
- `32_SCHEDULER_LIFECYCLE.md` - blocked and runnable task-state transitions
- `90_CONFORMANCE.md` - contract and scenario coverage

## Scope

This file describes the current wait-one, wait-async, signal, port, and timer behavior in the repository.

## Signals

- Signal bits are modeled in `axle_core::Signals`.
- Signals are level-triggered object state, not edge-triggered event logs.
- Common bits already in use:
  - `OBJECT_READABLE`
  - `OBJECT_WRITABLE`
  - `OBJECT_PEER_CLOSED`
  - `OBJECT_SIGNALED`
  - user signal bits 24..31
- Object-specific aliases reuse those base bits for channels, sockets, timers, and task termination.
- `INTERRUPT_SIGNALED` is now a public alias over `OBJECT_SIGNALED` for interrupt objects.

## wait_one

- `object_wait_one()` checks the current signal snapshot first.
- The syscall front-end now decodes and probes one opaque userspace sink before calling into
  `object_wait_one()`.
- If the watched mask is already satisfied, `object_wait_one()` returns an immediate completion value
  and the syscall shell performs the writeback.
- Otherwise the current thread parks through the kernel wait core until:
  - matching signals become visible
  - the deadline expires
  - the object becomes invalid or otherwise completes with an error
- Delayed completions keep only the opaque sink token in the wait registration; the wake path still
  performs the eventual write into that sink.
- Delayed signal and port completions now split kernel bookkeeping from user-buffer writeback:
  the wake path first decides the completion under the global kernel lock, then resolves user-page
  residency and performs the copyout outside that lock before publishing the final wake reason.
  This avoids doing VM fault / resident work while the kernel core lock is held.
- Infinite and finite waits now use the same parked-thread path; finite waits are driven by the
  same per-thread wait registration plus the shared reactor timer backend.
- Timeout delivery rechecks signal state at the timeout boundary before returning `TIMED_OUT`.

## wait_async

- `object_wait_async()` registers a one-shot observer on a port.
- Async observer authority now lives in `axle_core::ObserverRegistry`.
- The registry owns registration uniqueness, reverse indexing by `waitable_id`, edge/level rules,
  and pending-overflow merge behavior.
- Async registrations now also retain the revocation provenance of both the source waitable handle
  and the destination port handle.
  After `ax_revocation_group_revoke()` bumps one group's epoch, stale observers created through
  handles from older epochs are removed eagerly instead of continuing to deliver packets.
- Revocation is now broader than observer teardown alone.
  The kernel eagerly cancels every still-pending control-plane effect that carries revoked
  provenance:
  - blocked `wait_one` / `port_wait` registrations
  - `wait_async` observers
  - armed timer deadlines
  - queued kernel-generated signal packets already sitting in ports
- That cleanup path no longer relies on revoke-time global scans.
  Current mainline keeps per-group reverse indexes for observer registrations, revocable blocked
  waits, armed timers, and queued kernel packets, then re-checks live provenance only for the
  candidate registrations of the revoked group.
- Revocation does **not** roll back already committed data-plane effects.
  Channel messages, socket bytes/datagrams, completed handle transfer, and completed VM/object
  operations remain committed even if the originating handle epoch is later revoked.
- Observer cleanup now eagerly removes pending-overflow entries when one registration is canceled or
  when the watched object is destroyed.
  It no longer relies on later `flush_port()` calls to lazily skip stale pending registrations.
- Reactor observer keys are generation-aware `ObjectKey`s, so retained async state stays tied to
  one object incarnation even after numeric object ids are recycled.
- `RevocationManager` epoch and generation counters are now `u64` (previously `u32`) and use
  `saturating_add` to prevent wraparound.
- Delivery complexity is now proportional to the observing ports of one waitable, not the total
  number of ports in the system.
- Current options include:
  - edge-triggered delivery
  - monotonic timestamp delivery
  - boot timestamp delivery
- In the current bootstrap system model, boot and monotonic timestamps are sourced from the same monotonic clock.
- Signal producers now publish `(waitable_id, current_signals)` directly into the reactor path.
  The wait slice no longer pulls current signal snapshots from the global object table during
  async delivery.
- BFS signal propagation now enforces a `MAX_PROPAGATION_DEPTH` of 1024, bounding the traversal
  depth to prevent unbounded recursion or runaway propagation chains.
- Bootstrap conformance now explicitly covers both timer/object waits and transport-object delivery
  through this path, including channel `WRITABLE` recovery and `PEER_CLOSED` packets.

## Port model

- `axle-core` provides the semantic port state machine:
  - fixed capacity (asserted non-zero at construction via `KernelPortQueue::new`)
  - kernel reserve slots
  - pending-merge behavior when kernel packets overflow
- Async observer state is no longer stored inside the port state machine; ports are pure queues
  plus readiness signals.
- Internal kernel-generated enqueue paths now also use one typed reserve ticket instead of relying
  on open-coded "queue has space" checks.
- Current kernel defaults are capacity `64` and kernel reserve `16`.
- The kernel wraps this in `KernelPort`, whose queue storage is backed by a kernel-created VMO-like page range.
- `ax_port_get_info()` now exports one first explicit telemetry snapshot for that queue/observer
  boundary:
  - capacity / kernel reserve
  - current / peak queue depth
  - queue-depth percentiles
  - user/kernel enqueue and `SHOULD_WAIT` counts
  - pending async-wait overflow / merge / flush counts for that port
- User packets and signal packets are translated to and from native `ax_port_packet_t`.
  Frozen `zx_port_packet_t` remains available as a compat alias over the same layout.
- Kernel-generated packets now also carry revocation provenance internally.
  Port purge on `ax_revocation_group_revoke()` removes only queued kernel packets whose provenance
  is now stale; user packets are left untouched.
- `zx_port_wait` is FIFO over queued packets and flushes pending kernel events when space becomes available.
- The syscall front-end now owns packet-output pointer decode and probe before `zx_port_wait` runs.
- Immediate packet delivery returns one completed packet back to the syscall shell for writeback;
  blocked waits retain only an opaque sink token in the parked wait registration.
- Blocking `zx_port_wait` also parks through the same wait core used by signal waits and futex waits.
- Port readiness transitions produced by packet enqueue/pop/flush now republish through the same
  reactor path as other waitables, so blocked port waits and async observers see one consistent
  signal authority.
- Timeout delivery re-polls the queue once at the timeout boundary before returning `TIMED_OUT`.

## Timer model

- Timers and blocked-wait deadlines are backed by one shared `axle_core::ReactorTimerCore`.
- Current timers are one-shot.
- Virtual interrupt objects are also waitable:
  - `interrupt_create(ZX_INTERRUPT_VIRTUAL)` creates one software-driven interrupt object
  - `ax_interrupt_trigger(handle, count)` increments one pending count and republishes
    `INTERRUPT_SIGNALED` when the object is unmasked
  - `interrupt_mask()` suppresses signal visibility without dropping pending counts
  - `interrupt_unmask()` republishes the current pending state
  - `interrupt_ack()` drains one pending count at a time
- `set(deadline)` arms or re-arms and clears `SIGNALED`.
- `TimerService` now triggers heap compaction on re-arm when the deadline heap grows beyond four
  times the number of active timers, preventing unbounded heap growth from repeated arm/cancel
  cycles.
- When polled at or after the deadline, the timer becomes signaled and disarms.
- `cancel()` clears both arm state and signal state.
- Armed timers now retain the revocation provenance of the handle epoch that armed them.
  `ax_revocation_group_revoke()` eagerly cancels timers armed through revoked handle epochs before
  they can fire later.
- The unified backend produces two event families:
  - timer object fire
  - blocked wait deadline expiry
- User-mode timer interrupts poll that backend once per tick, then:
  - publishes timer-object `SIGNALED` transitions
  - wakes expired blocked waits
  - syncs current CPU TLB state
  - any invariant break in that poll / publish / TLB-sync path now enters the kernel fatal handler
    and halts/bugchecks the affected runtime rather than being silently dropped
  - one online CPU that has not yet bound a runnable thread is treated as an expected empty state;
    timer-driven TLB sync is a no-op there instead of a fatal `BAD_STATE`
- Kernel-mode timer interrupts no longer run the full wait/reactor poll path on an already
  suspended trap stack; instead, trap-blocking wait paths poll the same backend immediately after
  they wake from the `hlt` edge.
- Deadline-boundary re-polls in `object_wait_one()` / `zx_port_wait()` now share that same
  fail-closed rule:
  - they may still complete successfully or return `TIMED_OUT`
  - but internal wait/timer invariant breaks are not converted into user-visible soft errors
- Backend storage is slot-owned by CPU, so timer objects and wait deadlines already share the same
  enqueue/cancel/poll path and telemetry surface.
- When x86_64 TSC-deadline timers are available, each online CPU now drives its own timer poll.
- Without TSC-deadline support, the BSP remains the coarse fallback tick source and may still poll
  all slots.

## Thread-state integration

Current blocking waits all park the thread through one canonical wait registration plus:

- one source-specific wait list or source queue
- one optional deadline entry in the shared reactor timer backend

The current scheduler-facing blocked state is `Blocked { source }`, where `source` identifies:

- `Signals(object_id)`
- `PortReadable(port_id)`
- `Futex(key)`
- `Fault(key)`
- `None` for deadline-only sleep

Futex `enqueue_waiter` now includes a `debug_assert` check to detect duplicate enqueue of the same
waiter, catching potential double-park bugs during development.

Futex wait now supports single-level priority inheritance (PI):
- when a high-weight thread blocks on a futex with a known owner, the owner's effective scheduler
  weight is boosted to the maximum weight among all waiters
- on wake or requeue, the owner's effective weight is recomputed from remaining waiters and
  its own `base_weight`
- the PI boost is transparent to the EEVDF scheduler: it sees the boosted `weight` field directly
- `thread_id_for_koid` lookups use a `BTreeMap<koid, ThreadId>` reverse index for O(log n) access
- chain propagation is bounded at 16 levels but currently only single-level (depth 1) is implemented

Wait completion eventually makes the thread runnable again through kernel task-state transitions.

## Current limitations

- Timer slack is currently ignored.
- `HANDLE_CLOSED` exists in the core signal vocabulary but is not yet wired into general kernel wait cancellation semantics.
- `object_signal` and `object_signal_peer` are effectively eventpair-focused today and only allow user signal bits.
- The scheduler now has real per-CPU runnable ownership and remote wakeup, but it is still the
  simple L0 policy layer rather than the eventual full scheduler architecture.
- There is no interrupt object yet; timers are the main kernel-generated waitable event source today.
- `wait_async` still uses persistent port observers rather than the per-thread blocking wait node.
- Timer interrupt ownership is per-CPU when the platform exposes TSC-deadline timers; otherwise the
  BSP remains the shared fallback tick source.
- Interrupt objects are currently only the narrow virtual/software shape:
  - no hardware IRQ routing
  - no port packet delivery model
  - no direct DMA / device binding yet
