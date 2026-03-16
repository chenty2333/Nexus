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
- Wakeup targeting now honors a thread's preferred / last CPU before opportunistically handing work
  to some other idle CPU.
- Brand-new threads still inherit the creator CPU as `last_cpu`, but first activation now has one
  narrower exception:
  - if the creator CPU is already occupied
  - and one idle peer CPU exists
  - then `start_thread()` / `start_thread_guest()` may enqueue that never-run thread on the idle
    peer CPU instead of forcing first activation to stay local
- Normal wakeups still preserve wake-affine / last-CPU behavior; the remote-first exception only
  applies at brand-new thread start.
- Basic local time slicing and runtime accounting now exist, but there is still no finished fairness
  or load-balancing policy layer.

## Current thread states

Threads may currently be in states such as:

- `New`
- `Runnable`
- `Suspended`
- `Blocked { source }`
- `TerminationPending`
- `Terminated`

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
- The deadline backend is per-CPU at the storage layer.
- When x86_64 TSC-deadline timers are available, each online CPU now drives its own scheduler tick,
  timeout polling, and local slice accounting.
- On platforms without TSC-deadline support, the BSP remains the coarse fallback tick source.

## Kill / suspend / reap

- `task_kill()` can target either a process or a thread object.
- Suspending a process or thread produces suspend-token-backed state.
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
  - signal, port, futex, fault, timer, and timeout completion all converge on one blocked-to-runnable handoff path
  - trap-exit, timeout, and wake paths may preempt or reschedule, but must not lose one completed wake
  - the current global run queue is bootstrap scaffolding, not a compatibility contract
- Conformance gate:
  - contract: `must.scheduler.l0_per_cpu_wake_phase1`
  - minimal scenario: `kernel.scheduler.l0_phase1`

## Current limitations

- Blocked current execution still relies on `sti; hlt` when the current CPU has no runnable work.
- Cross-CPU load balancing and work stealing do not exist yet.
- Scheduler fairness is still simple fixed-slice FIFO/RR rather than a richer policy such as
  weighted fairness or vruntime tracking.
