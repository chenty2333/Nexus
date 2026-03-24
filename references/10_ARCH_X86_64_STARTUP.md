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
  - the `sysretq` path now performs a strict user-space address check on the return RIP,
    allowing only low-half canonical addresses to prevent non-canonical address attacks
  - falls back to `iretq` for the wider blocked / switched / compatibility cases
- The legacy `int 0x80` path still exists for bootstrap compatibility and targeted conformance.
- The legacy `int 0x80` path now includes `swapgs` on ring3 entry, correctly switching the GS base
  when entering from userspace.
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
  - the current KVM-hosted baseline path should be interpreted against both the guest perf summary
    and the host CPU flags:
    - some hosts may expose `invpcid` to the guest while still withholding `pcid`
    - some hosts may not expose the architectural PMU shape at all, so PMU deltas remain zero
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
- `#PF` uses a dedicated per-CPU fault IST (IST3)
- `#GP` uses its own separate per-CPU fault IST (IST4), independent from `#PF`
- `#UD` does not use an IST (IST=0) and runs on the current kernel stack
- `#DF` keeps its own dedicated IST
- Ring0 and IST stacks are now 32 KiB per CPU (previously 16 KiB)
- x87/SSE state for user threads now uses XSAVE64/XRSTOR64 when the CPU advertises XSAVE support
  (CPUID leaf 1, ECX bit 26), with automatic detection of AVX and AVX-512 components via CPUID
  leaf 0xD.  When XSAVE is not available, the kernel falls back to legacy FXSAVE64/FXRSTOR64.
  Per-thread FPU state buffers are 2688 bytes (64-byte aligned) to cover AVX-512.
  CR4.OSXSAVE is enabled and XCR0 is programmed on every CPU (BSP and APs).

Axle previously used a shared IRQ IST for timer/IPI/breakpoint entry, but that shape breaks once a
blocked trap path re-enables interrupts and idles: a nested IRQ would reset `rsp` back to the same
IST top and corrupt the suspended return chain. Keeping regular IRQ/IPI entry on the current kernel
stack preserves nested interrupt frames, while `#PF` and `#GP` each keep their own dedicated fault IST.

Current architecture hardening and correctness notes:

- x2APIC mode IPI sends now bypass the `LocalApic` structure and write the ICR MSR directly,
  eliminating a data-race surface across multiple cores
- serial output now uses `try_lock` to prevent deadlock when logging from interrupt context
- PCI configuration space access is now protected by a global spinlock to ensure atomicity of
  multi-register accesses
- the TLB shootdown handler now reads its parameters before sending EOI, preventing a window where
  new parameters could overwrite the in-flight request
- per-CPU data access on hot paths now uses a `gs:` segment prefix instead of `rdmsr`, improving
  performance for frequent per-CPU reads
- the APIC spurious interrupt handler no longer sends EOI, conforming to the Intel SDM requirement
  that spurious interrupts must not issue end-of-interrupt
- xAPIC MMIO mappings now set PCD/PWT bits to ensure uncacheable (UC) memory type
- timer flag loads and stores now use `Release`/`Acquire` ordering instead of `Relaxed`
- APs no longer redundantly store `APIC_MODE`; only the BSP sets it during initialization
- the IDT is now wrapped in `UnsafeCell` instead of using `static mut`
- `lidt` uses `addr_of!` to avoid taking a reference to a packed struct field
- a minimal IOAPIC driver exists at `arch/x86_64/ioapic.rs`:
  - programs redirection entries to route legacy IRQ pins to APIC vectors
  - provides init/route_pin/mask_pin/unmask_pin helpers
  - the standard MMIO base 0xFEC0_0000 is used
  - ISR stubs for device vectors 0x30-0x4F are not yet wired into the IDT
- a kernel IRQ routing table exists at `irq.rs`:
  - maps vectors to bound InterruptObject instances
  - supports Virtual, IoApic, and Msi delivery modes
  - provides alloc_vector / bind_object / handle_irq entry points

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
- The architecture layer now supports XSAVE/AVX extended FPU state when the CPU advertises it,
  with automatic fallback to legacy FXSAVE for older CPUs.
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
