# 11 - syscall dispatch

Part of the Axle syscall surface.

See also:
- `10_ARCH_X86_64_STARTUP.md` - native `SYSCALL` and legacy `int 0x80` entry paths
- `12_WAIT_SIGNAL_PORT_TIMER.md` - wait and signal syscall families
- `20_HANDLE_CAPABILITY.md` - handle validation and rights checks
- `21_OBJECT_MODEL.md` - object-layer syscall targets
- `30_PROCESS_THREAD.md` - process and thread syscalls
- `33_IPC.md` - IPC syscall families
- `40_VM.md` - VM syscall families
- `90_CONFORMANCE.md` - syscall-level contract coverage

## Scope

This file describes the current syscall-number source, trap entry, argument copy helpers, and dispatch structure in the repository.

## Number source

- Syscall numbers come from the shared spec and generated Rust output under `syscalls/generated/`.
- `tools/syscalls-gen` regenerates the number table from `syscalls/spec/syscalls.toml`.
- `just check-syscalls` is the guard that the generated file matches the spec.
- The shared spec now names its ABI surface in native `ax_*` types (`ax_handle_t`, `ax_status_t`,
  `ax_signals_t`, ...).
- The live trap path now decodes handle arguments at full native width instead of truncating them
  through the older 32-bit compat codec.

## Current dispatch shape

- `kernel/axle-kernel/src/syscall/mod.rs` is the main syscall layer.
- `dispatch_syscall()` handles supported syscalls from a `[u64; 6]` argument array.
- `invoke_from_trapframe()` is the shared trap-facing path once a logical trap frame exists.
- `invoke_from_native_syscall()` is the native x86_64 `SYSCALL` entry hook:
  - it first gives guest-started carrier threads one chance to divert into the generic
    guest-session stop boundary
  - ordinary native userspace then falls through to the same shared syscall shell
- The current bootstrap syscall ABI surface is `72` generated syscall numbers.
- `AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC` is now the distinct Linux-facing
  exec-prepare helper. It accepts one opaque exec-spec blob and produces the
  prepared entry/stack pair without overloading the generic native launch path.
- `AXLE_SYS_AX_GUEST_SESSION_CREATE` and `AXLE_SYS_AX_GUEST_SESSION_RESUME`
  are the Round-1 control plane for generic supervised guest execution:
  - create binds one target thread, one sidecar VMO, and one supervisor port
  - resume lets userspace update the sidecar register snapshot and wake the guest
- `AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY` and `AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY`
  are the first generic guest-memory data plane for that supervision model:
  - read copies guest userspace bytes out to the supervisor
  - write copies kernel-owned bytes back into the guest address space
  - neither syscall interprets Linux ABI structures or Linux syscall semantics
- `AXLE_SYS_AX_THREAD_SET_GUEST_X64_FS_BASE` and
  `AXLE_SYS_AX_THREAD_GET_GUEST_X64_FS_BASE` are the current generic x86_64
  guest-thread TLS hooks:
  - they operate on one existing thread carrier
  - they cache and expose that carrier's guest-visible `fs_base`
  - they do not encode Linux `arch_prctl` or `CLONE_SETTLS` policy in-kernel;
    the Starnix executive remains responsible for those semantics
- `SyscallCtx` is now the syscall front-end authority for:
  - scalar argument decoding
  - extra syscall stack argument recovery
  - typed pointer / sink decode and output probe planning
  - trap-exit / restartable tail handling through `finish_syscall()`
- `invoke_from_trapframe()` now does only four things:
  - build `SyscallCtx`
  - resolve one syscall descriptor by number and invoke it
  - write the returned status and run `ctx.finish()`
  - emit one `sys_retire` trace event only after trap-exit completion has finished
- Supported syscalls now dispatch through one lightweight descriptor pipeline:
  - `decode(ctx, raw_args) -> Request + writeback plan`
  - `run(request) -> Response`
  - `writeback(ctx, plan, response)`
- `AXLE_SYS_VMAR_MAP` and `AXLE_SYS_CHANNEL_READ` are no longer structural exceptions in trap entry
  or dispatch. Their extra stack-argument and buffer handling now lives entirely in their decode /
  writeback stages.

## Copyin / copyout rules

- `kernel/axle-kernel/src/copy.rs` is the only syscall-facing usercopy service.
- `SyscallCtx` calls into that service for:
  - typed scalar / slice copyin
  - typed writeback for values, bytes, handles, and channel payloads
  - extra stack-argument reads
  - early output probes that must happen before object creation, mapping, transfer, or read-side dequeue
- The copy service owns:
  - user-range validation and residency for synchronous bulk copies
  - channel payload planning (`copied` vs `fragmented` vs `loaned`)
  - remap-or-copy fallback on channel read
  - probe policy as well as the actual data movement
- Syscall `run()` stages now consume only decoded kernel values and opaque validated sink tokens; they
  no longer parse raw user pointers or extra stack arguments themselves.
- Synchronous read/write families such as socket and VMO now split the copy path the same way:
  - decode copies input bytes or validates output buffers
  - run performs the kernel object operation on kernel-owned values
  - writeback copies results back to userspace

## Current supported families

The current bootstrap syscall surface includes:

- handle close / duplicate / replace
- object wait one / wait async / signal / signal peer
- port create / queue / wait
- timer create / set / cancel
- interrupt create / ack / mask / unmask
- interrupt get-info
- VMO create / read / write / set size
- VMO get-info
- VMO create physical / create contiguous / lookup backing paddr / pin DMA region
- DMA-region lookup backing paddr
- DMA-region lookup device-visible IOVA
- DMA-region lookup coalesced segment metadata
- PCI/device info / BAR / interrupt export
- PCI/device generic resource-count and resource export
- VMAR allocate / destroy / map / unmap / protect
- VMAR clone-mappings / mapping-backed VMO capture
- channel create / write / read
- eventpair create
- futex wait / wake / requeue / get owner
- process create / prepare start / start
- Linux exec prepare
- guest session create / resume / read-memory / write-memory
- guest-thread x86_64 FS-base set / get
- thread create / start
- task kill / suspend
- socket create / read / write
- Axle-native interrupt trigger

## Error-handling shape

- Unknown syscall numbers return `ZX_ERR_BAD_SYSCALL`.
- Known-but-unimplemented paths use `ZX_ERR_NOT_SUPPORTED`.
- Type, rights, pointer, and object-state checks are largely delegated into the object layer after the syscall shell validates raw arguments.
- A syscall can leave the thread blocked; trap-exit handling then decides whether to return to user mode, switch threads, or block current execution.
- The bootstrap perf trace now distinguishes:
  - native entry (`sys_native_enter`)
  - native fast return (`sys_native_sysret`)
  - dispatch completion (`sys_exit`)
  - actual return-to-user retirement (`sys_retire`)
  so blocked or scheduler-mediated syscall completion can be observed separately from plain dispatch.
- For output-producing syscalls that can create, dequeue, or otherwise commit kernel-visible state,
  the syscall shell now probes user outputs before the run stage so copyout failures do not trail
  committed side effects.

## Current limitations

- The native x86_64 fast path still shares most of the same logical trap shell as `int 0x80`;
  only the direct same-thread fast return now peels off into one `sysretq` path.
- Long-lived blocked waits still complete their final user writes in the wake path rather than in the
  original syscall shell. The tightened boundary is:
  - syscall front-end owns pointer decode and probe
  - the wait core stores an opaque validated sink token for delayed completion
- The current ABI surface is substantial for early system work, but not every planned Zircon-facing syscall family exists yet.
- The public `ax_*` naming and the live handle codec are now aligned: handles travel through the
  syscall boundary at full native 64-bit width.
- The current device-facing syscall surface is intentionally narrow:
  - `ax_vmar_clone_mappings()` is now the first narrow VMAR-to-VMAR clone helper:
    - it clones only mappings whose mapping-level clone policy is already frozen
      in VM metadata
    - `CLONE_COW` mappings re-arm source and child ranges for normal VM COW
    - `CLONE_SHARE` mappings rebind both sides onto the same shared/global VMO
      identity
    - it does not externalize Linux VMA trees or any process identity model
  - `ax_vmar_get_mapping_vmo()` is now the first narrow mapping-backed VMO
    capture helper:
    - it returns one handle naming the current backing VMO of the mapping that
      covers one address inside one VMAR
    - returned rights are derived from the current mapping permissions plus the
      captured VMO's stable behavior
    - it is a control-plane synchronization helper for userspace executives,
      not a residency / dirty-page / per-page inspection API
  - `ax_vmo_get_info()` is now the first narrow public VMO object-metadata query:
    - logical size in bytes
    - VMO kind (`Anonymous` / `Physical` / `Contiguous` / `PagerBacked`)
    - backing scope (`LocalPrivate` / `GlobalShared`)
    - behavior flags such as resizable / COW-capable / kernel-readable
    - effective handle rights for the queried VMO handle
    - it does not expose hot residency, dirty state, or per-page fault truth
  - `ax_vmo_create_private_clone()` is now the first narrow object-level private-shadow helper:
    - it clones one shared COW-capable source into one new local-private anonymous VMO
    - the clone starts as a byte-identical snapshot of the source
    - direct `vmo_write()` / `vmo_set_size()` then apply to that clone without mutating the source
  - `ax_vmo_promote_shared()` is now the first narrow control-plane promotion hook
    over that same VMO family:
    - it upgrades one local-private VMO object to the shared/global backing domain
    - the bootstrap staged-asset `GetVmo` path uses it to freeze byte-backed boot
      assets into the same shared source-handle shape as imported pager-backed code
      images
  - `interrupt_create()` only accepts `ZX_INTERRUPT_VIRTUAL`
  - `interrupt_get_info()` is now the first narrow metadata query over an interrupt object:
    - delivery mode
    - vector / line index
    - triggerable flag
  - `ax_interrupt_trigger()` is an Axle-native helper rather than a fully generic IRQ delivery ABI
  - `ax_vmo_lookup_paddr()` is a narrow bootstrap helper
  - `ax_vmo_pin()` + `ax_dma_region_get_info()` + `ax_dma_region_lookup_paddr()` +
    `ax_dma_region_lookup_iova()` + `ax_dma_region_get_segment()` now add one first explicit DMA
    lifetime object without yet
    becoming a full BTI/IOMMU contract:
    - `ax_vmo_pin()` now also freezes one first DMA-permission bit surface
      (`DEVICE_READ` / `DEVICE_WRITE`)
    - `ax_dma_region_get_info()` now exposes one narrow metadata snapshot:
      - size in bytes
      - creation-time DMA permission bits
      - region flags (`IDENTITY_IOVA`, `PHYSICALLY_CONTIGUOUS`)
      - coalesced segment count
      - base physical and device-visible addresses
    - `ax_dma_region_get_segment()` then exposes each coalesced physically contiguous segment:
      - offset / size in bytes
      - identity-IOVA / physically-contiguous flags
      - base physical and device-visible addresses
  - `ax_pci_device_get_info()` / `ax_pci_device_get_config()` / `ax_pci_device_get_bar()` /
    `ax_pci_device_get_interrupt()` / `ax_pci_device_get_interrupt_mode()` /
    `ax_pci_device_get_resource_count()` / `ax_pci_device_get_resource()` /
    `ax_pci_device_set_interrupt_mode()` currently export one narrow bootstrap device contract:
    - one capability already seeded into the bootstrap runner
    - one generic resource index:
      - resource count
      - config resource export
      - BAR resource export
      - interrupt resource export
    - one synthetic PCI config-space export:
      - MMIO + read-only flags
      - VM map options for the config alias
      - virtio-style region discovery for BAR0/common/notify/isr/device
    - one BAR VMO export result plus BAR flags / VM map-option metadata
    - one interrupt-object export result per queue-pair/group plus delivery-mode / vector metadata
    - one interrupt-mode capability query exposing:
      - whether a delivery mode is supported / active
      - whether the current transport routes through triggerable objects
      - base vector and vector count for that mode
    - one first interrupt-mode activation entry point:
      - `VIRTUAL` remains the only triggerable/bootstrap delivery mode
      - `LEGACY` / `MSI` / `MSI-X` can now be selected so ring3 can validate exported interrupt
        metadata and mode transitions against the same handles
      - real hardware routing and MSI/MSI-X programming are still future work
    - no generic PCI enumeration or bus-management ABI yet
  - `ZX_VM_MAP_MMIO` is now the first narrow public VM mapping attribute bit:
    - it requests device/MMIO cache attributes on the installed mapping
    - it is currently intended only for physical/contiguous VMOs
    - `vmar_protect()` still treats cache policy as fixed mapping truth rather than one mutable
      protect-time knob
