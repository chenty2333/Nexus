# 10 - x86_64 startup

Part of the Axle architecture layer.

See also:
- `11_SYSCALL_DISPATCH.md` - syscall dispatch reached through `int 0x80`
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
- `int 0x80` syscall entry
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
- later install the IDT through `trap::init()`

The kernel then:

- masks the legacy PIC
- initializes timekeeping
- brings up the BSP timer
- prepares bootstrap userspace
- starts AP startup

## Syscall entry

- The current userspace ABI enters the kernel through `int 0x80`.
- The register contract is:
  - `rax` = syscall number
  - `rdi/rsi/rdx/r10/r8/r9` = args 0..5
- The assembly stub saves a full register snapshot and hands control to the Rust syscall layer.
- Return status is written back to `rax` before `iretq`.
- There is no `SYSCALL/SYSRET` path yet.

This is a deliberate bootstrap path, not yet a final fast syscall mechanism.

## SMP startup

- AP startup uses an AP trampoline in low physical memory.
- APs run a minimal `init_ap()` sequence:
  - serial
  - GDT/TSS
  - IDT load
  - per-CPU setup
  - local APIC init
- After APs come online, they enter the kernel's idle scheduler loop.
- The BSP performs a simple fixed-vector IPI acknowledgement test during bring-up.

## Current interrupt / exception wiring

`trap::init()` installs handlers for:

- syscall entry
- breakpoint
- page fault
- general protection fault
- double fault
- timer interrupt
- APIC spurious/error interrupts
- test IPI
- TLB IPI
- reschedule IPI

## Current limitations

- The architecture layer is x86_64-only today.
- The syscall mechanism is `int 0x80`, not yet a later optimized path.
- The initial userspace model still uses a fixed bootstrap window and special bootstrap assumptions.
- Ring3 is entered through bootstrap state rather than a fully general process-loader path.
- AP local timers are enabled after `init_ap()` when TSC-deadline hardware is available; otherwise
  the BSP remains the coarse fallback scheduler tick source.
- SMP now includes the minimum scheduler/IPI glue needed for per-CPU runnable ownership, but it is
  still not the final architecture.
