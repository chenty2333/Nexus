# 32 - scheduler / lifecycle

Part of the Axle process/thread subsystem.

See also:
- `12_WAIT_SIGNAL_PORT_TIMER.md` - blocking states driven by waits
- `10_ARCH_X86_64_STARTUP.md` - SMP and IPI groundwork
- `11_SYSCALL_DISPATCH.md` - blocked syscalls and trap-exit flow
- `21_OBJECT_MODEL.md` - process, thread, and suspend-token object shape
- `30_PROCESS_THREAD.md` - process/thread index
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` - process and thread creation/start
- `33_IPC.md` - IPC wakeups and peer-driven state changes
- `35_IPC_SOCKET.md` - stream wakeups and blocked-state interaction
- `90_CONFORMANCE.md` - scheduler-adjacent scenarios

## Scope

This file describes the current task-state, scheduler, kill, suspend, and reap behavior in the repository.

## Current scheduler shape

- The scheduler now tracks runnable ownership per CPU.
- `Kernel` owns one `CpuSchedulerState` per online CPU, each with:
  - one local `run_queue`
  - one local `current_thread_id`
  - one local `reschedule_requested`
  - one local runtime-accounting window plus slice deadline
  - an `online` bit used by wakeup targeting
- Wakeup targeting is now CPU-aware, but scheduling policy is still intentionally simple.
- Wakeup targeting now honors a thread's preferred / last CPU before falling back to a least-loaded
  eligible CPU.
- Brand-new threads still inherit the creator CPU as `last_cpu`.
- `start_thread()` / explicit `zx_thread_start()` may place a brand-new thread onto an already-idle
  peer CPU when the creator CPU is currently busy.
- `process_start()` and guest process-start now share the same narrow donation rule:
  - they still enqueue on the preferred / wake-affine CPU first
  - but they may donate that brand-new queued child to a true-idle peer CPU when the
    donor would otherwise keep more than one runnable
- Basic local time slicing and runtime accounting now exist, and the current L0 fairness /
  load-balance policy is now explicit rather than accidental.

## L0 fairness and load balance contract

- Intra-CPU fairness is now EEVDF (Eligible Earliest Virtual Deadline First):
  - each thread tracks `vruntime` (virtual runtime weighted by 1024/weight), `vdeadline`, and
    `eligible_time`
  - pick-next selects the eligible thread with the smallest `vdeadline`; if no thread is eligible,
    the smallest `vdeadline` unconditionally (starvation prevention)
  - runtime accounting advances `vruntime` by `real_ns * 1024 / weight`, giving higher-weight
    threads more CPU time
  - time slices are weight-proportional: `DEFAULT_TIME_SLICE_NS * weight / 1024`
  - all threads default to weight 1024 (nice 0), making equal-weight threads behave as round-robin
  - `min_vruntime` is monotonically non-decreasing per CPU
  - newly woken threads have `eligible_time = min_vruntime` and `vruntime` clamped to at most one
    weighted slice below `min_vruntime` to prevent infinite credit after long sleep
- Cross-CPU placement stays intentionally narrow:
  - ordinary wakeups keep `last_cpu` affinity as long as that choice does not exceed the
    least-loaded eligible CPU by more than one runnable
  - if the preferred CPU would exceed that skew bound, the wake goes to the current least-loaded
    eligible CPU instead
  - explicit brand-new `zx_thread_start()` may still spill to an already-idle peer CPU immediately
  - `process_start()` and guest process-start do not force immediate peer placement, but they may
    donate the newly queued child to one true-idle peer under the same narrow donation path
- Migration is queued-thread-only:
  - the scheduler may move one runnable thread from the donor run-queue tail to a receiver
  - the currently running thread is never migrated directly
  - blocked-current direct resume remains local and observable rather than being rewritten into
    generic migration
- Load-balance triggers are:
  - enqueue-time idle nudge: if a donor CPU would otherwise hold more than one runnable, one queued
    runnable may be donated to a true-idle peer CPU
  - periodic rebalance: once per local slice window, a CPU may compare the most-loaded and
    least-loaded eligible CPUs and migrate one queued runnable when the donor exceeds the receiver
    by more than one runnable

## L1 event / decision contract

- L1 remains optional and asynchronous.
- L0 must never synchronously depend on L1 to complete:
  - wakeup delivery
  - pick-next
  - timeout completion
  - trap-exit reschedule
- The current frozen observation surface for future L1 policy is the scheduler trace / telemetry
  family already exported by the kernel:
  - run-queue depth changes
  - handoff counts
  - steal counts
  - remote-wake latency
- The current frozen decision boundary is:
  - L1 may eventually suggest placement / rebalance / yield-style policy
  - L0 may ignore or defer those suggestions
  - L0 correctness, forward progress, and wake visibility may not depend on L1 availability

## Scheduler locality matrix

| Structure | Hot owner | Remote touch shape | Current rule |
| --- | --- | --- | --- |
| `CpuSchedulerState.current_thread_id` | local CPU | read for wake targeting / diagnostics | single-writer per CPU |
| `CpuSchedulerState.run_queue` | local CPU | donor-tail dequeue during narrow migration | queued-thread-only migration |
| `CpuSchedulerState.reschedule_requested` | target CPU | remote wake / rebalance may set it | cross-CPU IPI-visible flag |
| `Thread.last_cpu` | last running CPU | read during wake placement | updated on activation |
| `Thread.queued_on_cpu` | queue owner CPU | read/retarget during migration | one runnable queue owner at a time |
| `Thread.runtime_ns` | local running CPU | diagnostics only | accumulated on local tick / trap-exit accounting |
| remote-wake timestamps | target CPU activation path | written by wake/migrate source, consumed by receiver | latency-only accounting, not ownership |

## Current thread states

Threads may currently be in states such as:

- `New`
- `Runnable`
- `Suspended`
- `Blocked { source }`
- `TerminationPending`
- `Terminated`

The `Suspended` state now correctly interacts with run-queue ownership:
- suspending a running thread removes it from the run queue before entering `Suspended`
- resuming a suspended thread re-enqueues it through the normal `make_thread_runnable` path
- `running_cpu` is tracked per-thread so suspend/wake can target the correct CPU in O(1)

Processes currently move through states such as:

- `Created`
- `Started`
- `Suspended`
- `Terminating`
- `Terminated`

## Blocking and wakeup

- Blocking syscalls now park through one wait-core path:
  - the thread enters `Blocked { source }`
  - the thread records one canonical wait registration
  - finite waits also arm one deadline-heap entry in the current CPU's wait-timer shard
- `finish_trap_exit()` decides whether to:
  - resume current thread
  - switch to another runnable thread
  - block the current CPU when no runnable thread exists
- Wakeup and timeout paths both complete the parked wait first, then feed back into
  `make_thread_runnable()`.
- Wakeups from blocked states are still pushed to the front of the selected CPU run queue.
- Remote wakeup may target another CPU and request a fixed-vector reschedule IPI.
- Scheduler tracing now exports:
  - run-queue depth changes
  - steal events
  - blocked-wake handoff events
  - remote-wake latency, including the direct blocked-current resume path that does not enqueue
- The deadline backend is per-CPU at the storage layer.
- When x86_64 TSC-deadline timers are available, each online CPU now drives its own scheduler tick,
  timeout polling, and local slice accounting.
- On platforms without TSC-deadline support, the BSP remains the coarse fallback tick source.

## Kill / suspend / reap

- `task_kill()` can target a process, thread, or job object.
- Killing a job recursively terminates descendant processes currently owned by that subtree.
- Suspending a process, thread, or job produces suspend-token-backed state.
- Suspending a job recursively increments the suspend depth of descendant processes until the token
  closes.
- Terminated thread/process objects expose `TASK_TERMINATED` signals.
- Reaping removes fully terminated task records once object and handle state allow it.
- Lifecycle sync may run from trap-exit or idle-loop paths on different CPUs, so zero-handle task
  object reaping is intentionally idempotent against already-reaped kernel task records.

## SMP status

- SMP AP startup exists.
- Fixed-vector test IPI, TLB IPI, and reschedule IPI paths exist.
- APs now enter the scheduler's idle loop after `init_ap()`, rather than staying in a pure
  `hlt` bring-up loop.
- The AP bring-up path no longer depends on raw APIC ids being `0..cpu_count-1`; the kernel keeps
  raw APIC ids for transport/IPI routing while mapping AP-local stack/TSS state onto bounded
  logical CPU slots.
- The 4-core AP-online conformance gate now uses one dedicated narrow ring3 smoke after bring-up
  rather than requiring the full default-int80 suite to complete under `-smp 4` QEMU fallback
  timer conditions.
- The system now has a real per-CPU L0 runnable topology, but it is still not the final scheduler
  architecture.

## Phase-one gate contract

The first "non-bootstrap substrate" scheduler contract is now implemented.

- Public task states stay in the current family:
  - `New`
  - `Runnable`
  - `Suspended`
  - `Blocked { source }`
  - `TerminationPending`
  - `Terminated`
- The gate is about scheduling topology and wake delivery, not about adding new user-visible task states.
- Required end-state:
  - one runnable-state owner and run queue per CPU
  - remote wakeup may enqueue work on another CPU and request a reschedule IPI
  - an explicit brand-new thread start may use an already-idle peer CPU without changing the
    ordinary wake-affine / preferred-CPU rules for generic wakeups or process-start
  - one CPU carrying a blocked current thread may still resume that current thread directly without
    queueing, but the remote wake and wake-to-resume latency must remain observable
  - signal, port, futex, fault, timer, and timeout completion all converge on one blocked-to-runnable handoff path
  - trap-exit, timeout, and wake paths may preempt or reschedule, but must not lose one completed wake
  - the current global run queue is bootstrap scaffolding, not a compatibility contract
- Conformance gate:
  - contract: `must.scheduler.l0_per_cpu_wake_phase1`
  - minimal scenario: `kernel.scheduler.l0_phase1`

## Current limitations

- Blocked current execution still relies on `sti; hlt` when the current CPU has no runnable work.
- Page-fault trap handling now enforces a bounded spin limit (`MAX_SPIN_ITERATIONS`) on fault
  contention, preventing infinite fault-retry loops from starving the scheduler.
- The `Suspended` trap-exit path now correctly checks suspension state after the trap completes,
  preventing a window where a suspended thread could be accidentally re-enqueued.
- Bootstrap perf smoke now reuses one proven peer worker across wake, active-peer TLB, and fault
  phases, so those gates no longer depend on repeated synthetic cross-CPU launches.
- Scheduler fairness is now EEVDF with per-thread vruntime, weight, and vdeadline tracking.
  The previous fixed-slice FIFO/RR policy has been replaced.
  such as weighted fairness, vruntime tracking, or EEVDF.
- The receiver set for general runnable donation is still conservative:
  - true-idle peers remain the migration target
- The kernel still has no topology / NUMA-aware balancing layer.
- L1 remains a documented contract boundary, not an implemented shared-VMO scheduler protocol yet.
