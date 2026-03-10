# Axle / Nexus TODO Tree

For AI agents:

- This file tracks unfinished work only.
- Completed work is intentionally omitted.
- Treat this as a dependency map, not as the semantic source of truth.
- `references/` remains the source of truth for contracts and intended behavior.

Legend:

- `[~]` partially implemented
- `[ ]` largely missing

Current rough status:

- Axle kernel is around "late Phase C / early Phase D".
- Nexus system-layer work is still mostly out-of-tree or not started.

## Axle Core Unfinished Tree

### A. Scheduler / Execution Model `[~]`

#### A1. per-CPU L0 scheduler follow-on `[~]`

= phase-one per-CPU runnable ownership, remote wakeup, reschedule IPI, unified blocked/runnable states, and basic preemption/time slicing have landed
= remaining work is scheduler policy follow-on: load balancing, richer fairness/accounting, lock-granularity cleanup, and L1 handoff points
depends on: existing SMP bring-up, thread/process model, wait/futex/port blocking paths

#### A2. generic userspace launch follow-on `[~]`

= phase-one generic image launch, `process_start(arg_handle)`, and executable child start have landed
= remaining work is broader launcher coverage: fuller ELF support, init/service launch, and less bootstrap-specific bring-up for the very first userspace entry
depends on: A1, C1

#### A3. user-mode L1 scheduler `[ ]`

= add the higher-level policy layer described in the roadmap  
= event ring, decision ring, L0 fallback when L1 is absent or stuck, CPU-domain aware policy hooks  
depends on: A1, stable wait/port semantics, stable shared-memory ring transport

### B. Capability / Governance `[~]`

#### B1. external revocation model `[ ]`

= turn revocation into a real object-level contract instead of internal-only machinery  
= revocation-group object, revoker authority handle/right, revoke syscall, inheritance/propagation rules, revoke conformance coverage  
depends on: existing CSpace, existing `RevocationManager`

#### B2. job / policy / quota tree `[ ]`

= add governance structure above raw objects and handles  
= process/job hierarchy, quotas for handles/ports/vmos/vmars/revocation groups, policy surface, accounting/diagnostics  
depends on: B1, A2

### C. VM Mainline Completion `[~]`

#### C1. Execute VM / code mappings follow-on `[~]`

= phase-one executable mapping support and launch-time validation have landed
= remaining work is broader ecosystem coverage around pager/file-backed execution and additional hardening/tests
depends on: existing page-table, VMAR, VMO, loader path

#### C2. pager-backed / file-backed VMO externalization `[~]`

= turn the current internal pager-backed path into a stable object-facing contract  
= public semantics for fault/read/map, backing-source rules, write/resize restrictions, file-like source model  
depends on: existing lazy-VMO materialization path

#### C3. device VM primitives `[ ]`

= add the VM-side primitives needed by a userspace driver framework  
= Physical/MMIO VMO, Contiguous/DMA-capable memory, DMA grant or `DmaContext`, IOMMU-facing isolation hooks  
depends on: C1, B2

#### C4. TLB / invalidate hardening `[~]`

= phase-one strict visibility and active-peer shootdown support have landed
= remaining work is scalability: finer active-CPU tracking, better batching, and stronger SMP correctness tests
depends on: existing epoch/shootdown base

### D. IPC Mainline Completion `[~]`

#### D1. Channel scatter page-loan `[ ]`

= complete the roadmap design beyond the current full-page fast path  
= head/tail fragment pages, body full-page loan, mixed descriptor format, mixed remap/copy read path  
depends on: existing full-page loan, pin/refcount/loan accounting, COW support

#### D2. Channel race hardening `[~]`

= make channel cleanup and concurrency behavior robust enough for broader runtime use  
= close/cancel/read/write race cleanup, quota/telemetry refinement, more stress coverage, more differential-style validation  
depends on: D1

### E. Object Family Expansion `[~]`

#### E1. Socket datagram `[ ]`

= add message-oriented socket semantics on top of the current stream-only implementation  
= message boundaries, truncation rules, datagram backpressure, signal/wait contract  
depends on: existing stream socket

#### E2. InterruptObject / device waitable objects `[ ]`

= expose the minimal waitable interrupt surface needed by userspace drivers  
= IRQ object, wait/port integration, ack/mask/unmask primitives, ownership rules  
depends on: C3, A1

## Outer Tree Toward Starnix

### F. Zircon-compatible runtime `[ ]`

#### F1. thin `libzircon`

= userspace `zx_*` stubs, ABI types/struct glue, syscall wrappers, low-logic mapping onto Axle  
depends on: Axle syscall/object semantics being stable enough to wrap cleanly

#### F2. async/reactor base

= event loop built on port/timer/channel semantics  
= enough runtime glue for non-busy async waiting and dispatch  
depends on: F1

#### F3. FIDL runtime / bindings

= typed RPC over channels with executor integration  
= transport, encoding/decoding, async binding support  
depends on: F2

### G. Component Framework `[ ]`

#### G1. runner abstraction

= a generic process/component launch interface

#### G2. capability routing

= structured capability passing and restriction between components

#### G3. init / service manager / minimal resolver

= enough system topology to start and connect core services

depends on: F1-F3, A2, B2

### H. Driver Framework `[ ]`

#### H1. user-mode driver manager

= central manager for driver lifecycle and binding

#### H2. DFv2-style driver components

= driver processes/components instead of in-kernel driver growth

#### H3. devfs / protocol exposure

= a clean way for the rest of the system to talk to drivers

depends on: C3, E2, G

### I. I/O Stack `[ ]`

#### I1. zxio/fdio-like fd abstraction

= bridge channel/protocol objects into fd-shaped userspace APIs

#### I2. namespace / VFS / pipe / socket glue

= the core glue layer that makes filesystem and socket use practical

#### I3. filesystem and network services

= the service side needed for meaningful program execution

depends on: F, H, E1

### J. Starnix `[ ]`

#### J1. starnix runner

= component/runner integration for launching Linux-facing tasks

#### J2. Linux task/mm/fs/socket/syscall adaptation

= the broad Linux compatibility layer itself

#### J3. signal/futex/epoll/process semantic alignment

= the Linux-visible behavior polishing needed to run real software reliably

depends on: F, G, I  
full shape will also depend on: H

## Practical Critical Path

If the immediate goal is "move toward Starnix with the least detour", the rough path is:

1. D1/D2 channel completion and hardening
2. F1 thin `libzircon`
3. F2 async runtime
4. G minimal component framework
5. I minimal fd/I/O stack
6. J initial Starnix runner and Linux adaptation work

## Notes For Agents

- The first substrate-closing pass is in; the next priorities are the outer runtime layers and
  remaining IPC hardening.
- B1/B2 are not the shortest path to a demo, but delaying them too far can create later refactors.
- C3 and E2 matter more for DFv2 than for the earliest Starnix-facing work.
- D1 is one of the main remaining gaps between the current channel implementation and the full roadmap design.
