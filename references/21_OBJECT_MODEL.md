# 21 - object model

Part of the Axle kernel object layer.

See also:
- `20_HANDLE_CAPABILITY.md` - handle and capability storage
- `11_SYSCALL_DISPATCH.md` - object-layer syscall entry points
- `12_WAIT_SIGNAL_PORT_TIMER.md` - waitable behavior shared by objects
- `30_PROCESS_THREAD.md` - process and thread lifecycle
- `33_IPC.md` - channel and socket object families
- `40_VM.md` - VMO and VMAR object families
- `90_CONFORMANCE.md` - object-facing contract coverage

## Scope

This file describes the current kernel object table, object kinds, and lifetime rules in the repository.

## Current implementation

- The object layer is rooted at `kernel/axle-kernel/src/object.rs`.
- `KernelState` is now an immutable handle container over split slice state:
  - `Kernel` for process/thread/futex/run-queue core state
  - `ObjectRegistry` for the global object table, bootstrap handles, timer reverse index, and object-handle refcounts
  - `TransportCore` for shared socket runtime state and transport telemetry
  - `Reactor` for observers, waiter indexes, and unified timer backend state
  - `VmFacade` for VM and fault authority
- `object.rs` is still the public kernel object façade, but mutable runtime ownership is no longer centralized in `KernelState`.
- Object-family service code is now split by slice:
  - `kernel/axle-kernel/src/object/handle.rs`
  - `kernel/axle-kernel/src/object/process.rs`
  - `kernel/axle-kernel/src/object/transport.rs`
  - `kernel/axle-kernel/src/object/vm.rs`
- Object ids are global within `ObjectRegistry` and distinct from per-process handles.
- Handles point at object ids through per-process CSpaces owned by `Process`.

## Current object kinds

The current `KernelObject` enum includes:

- `Process`
- `Thread`
- `SuspendToken`
- `GuestSession`
- `Port`
- `Timer`
- `Channel`
- `EventPair`
- `Socket`
- `Interrupt`
- `PciDevice`
- `DmaRegion`
- `Job`
- `RevocationGroup`
- `Vmo`
- `Vmar`

There is still no public Resource object.

Current job shape:

- `Job` is the first narrow governance tree object
- it is not waitable
- it currently exports:
  - one parent/child topology:
    - one root job seeded at bootstrap
    - child jobs created through `ax_job_create()`
    - child processes created either from a parent process handle or directly from a job handle
  - one metadata query through `ax_job_get_info()`:
    - stable `job_id`
    - stable koid / parent koid
    - child job count
    - child process count
    - current policy rights ceiling
  - one policy path through `ax_job_set_policy()`:
    - policy is currently one monotonic handle-rights ceiling
    - lowering that ceiling recursively updates descendant jobs and processes
    - future handle duplicate/replace/transfer-install paths intersect their rights with the
      owning process ceiling
  - existing task lifecycle calls may now also target jobs:
    - `task_kill(job)` recursively terminates descendant processes
    - `task_suspend(job)` returns one suspend token that holds descendant processes suspended until
      the token closes
  - task lifecycle authorization is currently object-specific:
    - `task_kill(process)` / `task_suspend(process)` require `MANAGE_PROCESS`
    - `task_kill(thread)` / `task_suspend(thread)` require `MANAGE_THREAD`
    - `task_kill(job)` / `task_suspend(job)` require `MANAGE_JOB`
    - there is no extra `DESTROY` baseline gate for these lifecycle calls

Current revocation-group shape:

- `RevocationGroup` is one narrow governance/control object
- it is not waitable
- it currently exports:
  - one metadata query through `ax_revocation_group_get_info()`:
    - stable `group_id`
    - token generation (`u64`)
    - current epoch (`u64`, saturating increment to prevent wraparound)
  - one revoke path through `ax_revocation_group_revoke()`:
    - revoke = `epoch++`
    - any delegated handle carrying an older epoch snapshot fails future lookup
- ordinary handles only become revocable when userspace explicitly creates one delegated copy
  through `ax_handle_duplicate_revocable()`

Current interrupt shape:

- only one narrow virtual/software interrupt object is public today
- it is waitable and exposes `INTERRUPT_SIGNALED`
- it tracks one pending count plus one masked/unmasked bit
- `interrupt_ack()` drains one pending count
- `interrupt_get_info()` now exposes one narrow metadata snapshot:
  - delivery mode
  - vector / line index
  - triggerable flag
- `ax_interrupt_trigger()` is the current Axle-native software injection helper

Current PCI-device shape:

- `PciDevice` is one narrow bootstrap device-resource object
- it is not waitable
- it currently exports:
  - one immutable device-info snapshot
  - one synthetic PCI config-space export plus:
    - config size
    - MMIO + read-only flags
    - suggested VM map options for the config alias
  - one BAR VMO handle per supported BAR index plus:
    - BAR size
    - BAR flags
    - suggested VM map options for that BAR window
  - one interrupt-object handle per `(group, queue_pair)` tuple plus:
    - delivery mode
    - opaque vector / line index metadata
  - one generic resource index through `ax_pci_device_get_resource_count()` /
    `ax_pci_device_get_resource()`:
    - one config resource
    - one BAR resource per supported BAR
    - one interrupt resource per `(group, queue_pair)` tuple
    - each resource carries:
      - kind / index / subindex
      - flags
      - suggested VM map options
      - size
      - interrupt mode/vector metadata where relevant
  - one interrupt-mode capability snapshot per delivery mode through
    `ax_pci_device_get_interrupt_mode()`:
    - supported / active / triggerable flags
    - base vector
    - vector count
  - one interrupt-mode activation path through `ax_pci_device_set_interrupt_mode()`:
    - `VIRTUAL` remains the current bootstrap delivery mode
    - `LEGACY` / `MSI` / `MSI-X` may now also be selected so ring3 can validate that exported
      interrupt objects track the selected mode/vector metadata
    - real hardware-backed routing/programming still remains intentionally unimplemented
- one narrow config-write path now also exists through `ax_pci_device_set_command()`:
  - userspace may update the live PCI command register on a discovered device handle
  - the current concrete user is the first QEMU `virtio-net-pci` bootstrap slice, which enables:
    - `MEMORY_SPACE`
    - `BUS_MASTER`
  - the kernel mirrors that write back into the exported read-only config snapshot so userspace
    keeps one coherent control-plane view
- the first concrete user is the queue-owned bootstrap net dataplane slice
- the kernel may now also seed one second bootstrap `PciDevice` handle for the first discovered
  x86 network function when one virtio-style device is present:
  - config export becomes one page-aligned read-only snapshot over the discovered config space
  - BAR exports may carry multiple MMIO windows, not only the earlier synthetic BAR0 singleton
  - queue-pair / interrupt-group metadata may remain `0` until userspace interprets the device's
    own virtio config/capability layout
- it is not yet a full PCI bus/discovery object:
  - no generic enumeration beyond "first matching network function"
  - no general config-space read/write ABI beyond the narrow command-register helper
  - no MSI/MSI-X model
  - no resource rebinding or hotplug semantics

Current DMA-region shape:

- `DmaRegion` is one narrow device-memory lifetime object
- it is created through `ax_vmo_pin()` over one page-aligned range of one physical or contiguous
  VMO
- it owns one explicit frame-pin token, so closing the last handle releases the pinned pages
- it now also freezes one first DMA-permission surface on creation:
  - `DEVICE_READ`
  - `DEVICE_WRITE`
- it currently exposes two narrow metadata queries:
- it currently exposes three narrow metadata queries:
  - `ax_dma_region_get_info()`:
    - size in bytes
    - creation-time DMA permission bits
    - region flags (`IDENTITY_IOVA`, `PHYSICALLY_CONTIGUOUS`)
    - coalesced segment count
    - base physical / device-visible addresses
  - `ax_dma_region_get_segment()`:
    - segment offset / size in bytes
    - identity-IOVA / physically-contiguous flags
    - segment base physical / device-visible addresses
  - `ax_dma_region_lookup_paddr()` for one offset inside the pinned range
  - `ax_dma_region_lookup_iova()` for one first device-visible address view of that same range
- it is not waitable and it does not yet imply any BTI/IOMMU grant or cache-policy contract

Current socket shape:

- `Socket` remains one object family rather than splitting into separate stream/datagram kinds
- paired socket endpoints still share one `SocketCore`
- the shared core now carries one mode:
  - `stream` with directional byte rings
  - `datagram` with directional bounded message queues

## VMO object shape

- `VmoObject` now keeps stable control-plane state:
  - creator process id
  - kernel-global VMO id
  - backing scope (`LocalPrivate` or `GlobalShared`)
  - kind
  - size
- It does not cache resident / writable / COW / loaned per-page state.
- Cross-address-space map and cross-process transfer can promote one anonymous VMO object from
  `LocalPrivate` to `GlobalShared`.

## Bootstrap objects

At initialization, `KernelState::new()` seeds bootstrap objects and stores the resulting bootstrap handles in `ObjectRegistry` for:

- self process
- self thread
- root job
- root VMAR
- bootstrap code VMO when one bootstrap image is imported

These bootstrap handles are used by bootstrap execution paths and conformance paths.

## Lifetime shape

- `ObjectRegistry` is now a slot table. Each slot holds:
  - generation
  - state (`Live`, `Dying`, `Retired`)
  - external handle refcount
  - internal kernel refcount
  - optional `KernelObject` payload
- Public handle lookup only succeeds against `Live` slots with a matching `(object_id, generation)`.
- Teardown is split into two phases:
  - logical destroy: remove the payload from live lookup and move the slot to `Dying`
  - physical retire: once handle refs and kernel refs both reach zero, bump generation and return
    the numeric object id to the free list
- Closing the last handle now triggers control-plane teardown for:
  - channel endpoint close drains queued messages and marks the peer as `peer_closed`
  - eventpair close marks the peer as `peer_closed`
  - socket endpoint close updates the shared `SocketCore`
  - port close destroys the underlying kernel queue backing
  - timer close tears down the reactor timer object and its reverse index entry
  - dma-region close releases the pinned frame set carried by that region object
  - VMO / VMAR close retires the control object record even if backing VM state still exists
- Task objects are still synchronized against thread/process lifecycle reaping; they are not
  retired until the task lifecycle says they can disappear.
- A logically destroyed stale handle is no longer usable for normal object operations, but one
  `handle_close` may still succeed so the stale reference can drain.

## Signals and waitability

- Signal state is derived from object state rather than stored in one generic field for every object.
- Waitable object families currently include:
  - channel
  - eventpair
  - socket
  - port
  - timer
  - interrupt
  - process/thread termination
- `object_signals()` computes per-object signal snapshots on demand.

## Rights defaults

The object layer assigns default rights per object family, for example:

- channel/socket: duplicate, transfer, wait, read, write
- eventpair: duplicate, transfer, wait, signal, signal-peer
- port: duplicate, transfer, wait, inspect, read, write
- interrupt: duplicate, transfer, wait, write
- pci-device: duplicate, transfer, inspect
- dma-region: duplicate, transfer, inspect
- job: duplicate, transfer, inspect, enumerate, get-policy, set-policy, manage-job
- revocation-group: duplicate, transfer, inspect, write
- process/thread: duplicate, transfer, wait, inspect, manage-*
- guest-session: duplicate, transfer, read, write
- vmo/vmar: duplicate, transfer, read, map, plus write where supported

These defaults are interpreted through `HandleRights` and currently live in `object/handle.rs`.

## Current limitations

- There is still one global bootstrap object namespace; the new job tree governs process
  authority but does not yet virtualize the kernel into multiple isolated namespaces.
- The root object module is thinner than before, but close/signal flows still coordinate multiple slices from one façade rather than through a fully explicit command graph.
- Process and thread object slots still depend on lifecycle reaping before their numeric object ids
  can be reused.
- Several future object families from the roadmap are absent.
- `GuestSession` is a new Round-1 execution-control object rather than a Linux semantic object:
  it binds one carrier thread to one sidecar VMO and one supervisor port so userspace can emulate
  guest ABI policy outside the kernel.
- Guest-session memory access syscalls (`read_memory` / `write_memory`) now snapshot the guest
  thread's address-space identity before performing the copy, preventing a TOCTOU window where
  the supervisor could race against guest address-space replacement.
