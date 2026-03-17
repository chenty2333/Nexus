# 10 - x86_64 startup

Part of the Axle architecture layer.

See also:
- `11_SYSCALL_DISPATCH.md` - syscall dispatch reached through native `SYSCALL` or legacy `int 0x80`
- `12_WAIT_SIGNAL_PORT_TIMER.md` - timer and trap-side wake behavior
- `30_PROCESS_THREAD.md` - process and thread execution context
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` - ring3 entry after bootstrap setup
- `32_SCHEDULER_LIFECYCLE.md` - SMP and task-switch implications
- `40_VM.md` - page-table and userspace mapping context
- `41_VM_VMO_VMAR.md` - address-space control plane used during startup
- `90_CONFORMANCE.md` - conformance scenarios that exercise this path

## Scope

This file describes the current x86_64-only startup path, trap entry, timer, and SMP shape in the repository.

## Current architecture modules

`kernel/axle-kernel/src/arch/x86_64/` currently contains startup and trap pieces for:

- serial logging
- CPUID logging
- GDT / TSS
- IDT
- native x86_64 `SYSCALL` entry
- `int 0x80` syscall entry
- PCID / local TLB policy helpers
- minimal fixed-counter PMU enablement
- page-fault / GP fault / double-fault stubs
- local APIC support
- timer interrupt entry
- per-CPU setup
- breakpoint handling
- fixed-vector and TLB IPIs
- QEMU / PVH helpers

## BSP startup

Current BSP init does the following early:

- initialize serial
- log CPU features
- install GDT/TSS
- initialize per-CPU data
- enable x87/SSE execution (`CR0.MP/NE`, `CR4.OSFXSR/OSXMMEXCPT`) and seed a clean FXSAVE state
- later install the IDT through `trap::init()`

The kernel then:

- masks the legacy PIC
- initializes timekeeping
- brings up the BSP timer
- prepares bootstrap userspace
- starts AP startup

## Syscall entry

- Native x86_64 userspace now prefers one `SYSCALL` entry path.
- The logical syscall register contract remains:
  - `rax` = syscall number
  - `rdi/rsi/rdx/r10/r8/r9` = args 0..5
- The native entry stub currently:
  - uses `swapgs`
  - switches to the per-CPU `RSP0` kernel stack
  - synthesizes the same logical `TrapFrame + cpu_frame` layout used by the legacy trap path
  - returns through `sysretq` only when the shared trap-exit path proves that the same native
    thread can retire directly back to userspace without blocking or switching
  - falls back to `iretq` for the wider blocked / switched / compatibility cases
- The legacy `int 0x80` path still exists for bootstrap compatibility and targeted conformance.
- The bootstrap trace stream now exposes four syscall edges:
  - `sys_native_enter` when ring3 entered through native `SYSCALL`
  - `sys_enter` when the trap frame first reaches the syscall layer
  - `sys_exit` after dispatch returns a status
  - `sys_retire` only after trap-exit completion has finished and the thread is about to return to
    user mode
- The current fast path is intentionally narrow:
  - native entry exists
  - native `sysretq` is currently only the same-thread, non-blocked fast-return path
  - local CR3/TLB maintenance now prefers one support-aware policy:
    - plain CR3 reload fallback when PCID is unavailable
    - per-context PCID switch with flush/no-flush distinction when PCID is available
    - local `INVPCID single-context` when both PCID and INVPCID are available
  - the current QEMU bootstrap target often reports `pcid=false`, `invpcid=false`, and `pmu=false`,
    so the bootstrap gate currently proves wiring and support detection first, not final x86 gains
  - ring3 bootstrap perf smoke can now also read the first three fixed PMU counters when the
    kernel enables `CR4.PCE` and the CPU reports the architectural PMU shape

## SMP startup

- AP startup uses an AP trampoline in low physical memory.
- APs run a minimal `init_ap()` sequence:
  - serial
  - GDT/TSS
  - IDT load
  - per-CPU setup
  - x87/SSE enablement
  - local APIC init
- After APs come online, they enter the kernel's idle scheduler loop.
- The BSP performs a simple fixed-vector IPI acknowledgement test during bring-up.
- The BSP no longer assumes that APIC ids are the contiguous range `1..cpu_count-1`.
  Instead, it keeps one raw-APIC-id trampoline stack table, probes candidate APIC ids until the
  requested AP count comes online, and lets AP-local code translate raw APIC ids onto the kernel's
  bounded logical CPU slots for per-CPU stack/TSS state.
- Bring-up logs still print `cpu1`, `cpu2`, ... in logical-CPU order even when the raw APIC ids
  used for INIT/SIPI or IPI delivery are sparse.

## Current interrupt / exception wiring

`trap::init()` installs handlers for:

- syscall entry
- breakpoint
- invalid opcode
- page fault
- general protection fault
- double fault
- timer interrupt
- APIC spurious/error interrupts
- test IPI
- TLB IPI
- reschedule IPI

Current stack contract:

- ring3 -> ring0 syscalls enter on the per-CPU `RSP0` stack
- timer, APIC, breakpoint, and fixed-vector IPI entry stay on the current kernel stack
- `#PF` / `#GP` use a separate per-CPU fault IST
- `#UD` currently also uses the fault IST because supervised guest-stop v1 is trap-driven
- `#DF` keeps its own dedicated IST
- x87/SSE state for user threads currently uses legacy `FXSAVE64/FXRSTOR64` images captured on
  trap exit and restored before resuming another user thread

Axle previously used a shared IRQ IST for timer/IPI/breakpoint entry, but that shape breaks once a
blocked trap path re-enables interrupts and idles: a nested IRQ would reset `rsp` back to the same
IST top and corrupt the suspended return chain. Keeping regular IRQ/IPI entry on the current kernel
stack preserves nested interrupt frames, while `#PF` / `#GP` still keep a dedicated fault IST.

## Current limitations

- The architecture layer is x86_64-only today.
- Native syscall entry now exists, and the direct same-thread fast return can use `sysretq`, but
  the broader x86 fast path is still incomplete.
- `EFER.SCE` is now enabled on CPUs that advertise native syscall support.
- `CR4.PCIDE` is now enabled on CPUs that advertise PCID support and satisfy the required CR3
  low-bit precondition; address-space roots can therefore carry one bounded PCID tag today.
- Local full-context flush currently prefers `INVPCID single-context` when available; otherwise it
  falls back to one PCID-local or legacy CR3 flush.
- x86_64 supervised guest execution now intercepts native `SYSCALL` only for guest-started carrier
  threads that are still bound to one guest session, then converts that stop into the same generic
  guest-session sidecar + port handoff used by the wider Starnix executive.
- The older trap-driven guest-stop helpers remain in-tree as fallback machinery, but they no longer
  define the native syscall fast path.
- The architecture layer currently enables only legacy x87/SSE state management. `XSAVE`/AVX and
  wider extended-state contracts are still out of scope.
- The initial userspace model still uses a fixed bootstrap window and special bootstrap assumptions.
- Ring3 is entered through bootstrap state rather than a fully general process-loader path.
- AP local timers are enabled after `init_ap()` when TSC-deadline hardware is available; otherwise
  the BSP remains the coarse fallback scheduler tick source.
- SMP now includes the minimum scheduler/IPI glue needed for per-CPU runnable ownership, but it is
  still not the final architecture.
- The bootstrap trace stream now also marks timer and reschedule IRQ boundaries explicitly with
  `irq_enter` / `irq_exit`, and records scheduler context switches as separate events.
- The bootstrap perf runner now also includes one same-image child-process roundtrip slice so
  address-space switch policy can be observed through the same key=value summary path.
