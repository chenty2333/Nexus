# 43 - execute / pager / device VM

Part of the Axle VM subsystem.

See also:
- `10_ARCH_X86_64_STARTUP.md` - x86_64 page-table and trap context around bootstrap userspace entry
- `11_SYSCALL_DISPATCH.md` - current public mapping surface
- `20_HANDLE_CAPABILITY.md` - rights and handle-side gating for future VM features
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` - current process image launch path
- `40_VM.md` - VM index
- `41_VM_VMO_VMAR.md` - current VMO / VMAR control plane
- `42_VM_FAULT_COW_LOAN.md` - fault and COW mechanics that neighbor this work
- `44_DATAFS_PREP_MODEL.md` - host-side storage-model constraints for read-only `GetVmo` and later recovery work

## Scope

This file collects the VM areas that already have partial infrastructure but are not yet complete as stable public object contracts.

## Execute mappings

Current state:

- The mapping-permission model already includes execute in `MappingPerms`.
- Root VMAR capability metadata also carries execute in its maximum-permission shape.
- Public VMAR option decoding now accepts:
  - `ZX_VM_PERM_EXECUTE`
  - `ZX_VM_CAN_MAP_EXECUTE`
- Leaf page-table mappings now carry execute/NX state all the way down to x86_64 `NO_EXECUTE`.
- BSP and AP bring-up both enable `EFER.NXE`, so the hardware actually enforces user NX on every online CPU.
- Execute map / protect is gated by the normal handle-right and VMAR-capability path.
- Process and thread launch now reject:
  - entry PCs that do not currently resolve to executable user mappings
  - stacks that do not currently resolve to writable user mappings

Practical meaning:

- execute mappings are no longer a bootstrap-only metadata shape
- generic process-image launch now depends on the same public execute contract as normal VMAR map / protect
- the remaining gaps are around pager externalization and broader generic-launch completion, not missing NX plumbing

## Phase-one gate contract

The first public execute-mapping contract is now implemented.

- `ZX_VM_PERM_EXECUTE` and `ZX_VM_CAN_MAP_EXECUTE` become public VMAR options rather than rejected inputs.
- Execute install and protect must be gated by the normal capability path:
  - VMAR mapping caps
  - relevant handle rights
  - normal map / protect validation
- Launch-time validation must reject an entry PC that does not currently resolve to an executable user mapping.
- Internal pager-backed code VMOs may be the first executable-mapping consumer, but the bootstrap runner gets no private execute-only path.
- Strict TLB barriers are part of the same gate for operations that would otherwise leave stale translations observable:
  - execute install or execute permission change
  - writable-to-readonly transitions used for COW / loan snapshot safety
  - remaps that replace live destination frames
- Conformance gate:
  - contract: `must.vm.execute_mapping_phase1`
  - minimal scenario: `kernel.vm.execute_mapping_phase1`

## Pager-backed VMOs

Current state:

- The kernel already has internal pager source abstractions:
  - `StaticPagerSource`
  - `FilePagerSource`
  - `PagerSourceHandle`
- Bootstrap code images can be imported from:
  - embedded bytes
  - QEMU loader-provided blobs
- Global VMO state can materialize pager-backed pages on fault.
- The bootstrap userspace service tree can now hand out read-only `GetVmo`
  handles for boot/package files:
  - seeded boot-loaded ELF images reuse the imported pager-backed code VMOs
  - byte-backed assets such as compiled manifests and staged runtime libraries
    synthesize one cached page-rounded anonymous VMO on first request, promote
    that VMO object into the shared/global backing domain through
    `ax_vmo_promote_shared()`, and then duplicate one narrowed handle for later
    callers
- The narrow public pager/file-backed mapping contract is now:
  - the handle names one shared read-only mapping source:
    - imported pager-backed/file-backed VMOs when the boot image already has
      one
    - otherwise one staged shared anonymous VMO containing the file bytes
  - the shared source handle itself is now frozen as a read/inspect/map handle:
    - `vmo_read()` may read shared source bytes
    - direct `vmo_write()` on that shared handle is denied
    - direct `vmo_set_size()` on that shared handle is denied
  - `AX_VM_PRIVATE_CLONE` / `ZX_VM_PRIVATE_CLONE` may map any shared COW-capable
    source through a
    writable mapping-local shadow view
  - the shared pager/file source remains unchanged; first write allocates one
    private page for that mapping instead of mutating the source VMO
  - this mapping-local private-clone path does not require VMO write rights on
    the source file-backed handle
- `ax_vmo_get_info()` now exposes the first narrow public object snapshot over
  that same contract:
  - bootstrap code-image VMOs report `PagerBacked + GlobalShared`
  - staged shared-anonymous `GetVmo` handles report `Anonymous + GlobalShared`
  - anonymous private-clone destinations report `Anonymous + LocalPrivate`
  - the public fields now include:
    - logical size
    - kind
    - backing scope
    - stable behavior flags
    - effective handle rights for the queried handle
- the bootstrap shared-handle gate now also freezes the current source-handle
  access pattern for pager-backed/file-backed VMOs:
  - readable
  - not directly writable
  - not directly resizable
- one narrow object-level private-shadow helper now also exists through
  `ax_vmo_create_private_clone()`:
  - it accepts one shared COW-capable source handle
  - it returns one `Anonymous + LocalPrivate` VMO handle
  - the clone begins with the source bytes visible through direct `vmo_read()`
  - later direct `vmo_write()` / `vmo_set_size()` apply only to the clone and
    leave the shared source unchanged
- the bootstrap private-clone gate now also freezes the current source-vs-shadow
  split for shared pager-backed source handles:
  - one `ZX_VM_PRIVATE_CLONE` mapping may install a writable mapping-local view
    over the shared source handle
  - bytes read back through the shared source handle remain unchanged after the
    mapping writes its private shadow
  - `ax_vmo_get_info()` on the shared source handle remains
    `PagerBacked + GlobalShared` before and after the mapping-local write
- the staged shared-anonymous `GetVmo` gate now freezes that same exported
  source-handle behavior for boot/package assets that are still byte-backed:
  - readable
  - not directly writable
  - not directly resizable

What is not complete yet:

- pager-backed VMOs are still only a narrow user-facing contract:
  - read-only shared handles
  - writable private-clone mappings
  - writable object-level private clones
- `ax_vmo_get_info()` is query-only:
  - it does not externalize one pager object
  - it does not provide a public write / resize / dirty-page interface for
    pager-backed objects
- there is no external pager object or full file-backed VMO interface
- write/resize semantics for pager-backed objects are still intentionally
  narrow:
  - object-level private clones
  - mapping-local private-clone faults
  and not one shared-source dirty/writeback interface
- the generic VMAR clone helper now exists only for the first root-direct
  mapping slice plus the current heap/mmap backing-handle follow-on:
  - mapping-level clone policy is now part of VM truth
  - `ax_vmar_clone_mappings()` can clone those mappings into one child VMAR
  - Starnix `fork` uses that helper for root direct mappings
  - `ax_vmar_get_mapping_vmo()` is now the first narrow userspace helper for
    reifying the child mapping's current backing VMO after that clone
  - Starnix `fork` now uses that helper to rebuild:
    - heap backing handles
    - anonymous `mmap()` backing handles
    - shared file mapping source handles
    - private-clone shadow backing handles
  - the kernel still does not export Linux VMA trees or one public pager object
- DataFS-prep only freezes read-only `GetVmo` and recovery/model constraints on
  the host side; it does not yet provide a real writable file-backed VMO path

## Device-facing VM primitives

Current state:

- one narrow bootstrap `PciDevice` contract is now public:
  - kernel seeds one device handle into the bootstrap runner shared-slot window
  - `ax_pci_device_get_info()` exports one immutable resource summary
  - `ax_pci_device_get_resource_count()` / `ax_pci_device_get_resource()` now export one generic
    resource index over that same bootstrap handle:
    - one config resource
    - one BAR resource per supported BAR
    - one interrupt resource per `(group, queue_pair)` tuple
  - `ax_pci_device_get_bar()` exports one BAR VMO handle plus BAR flags / suggested VM map options
  - `ax_pci_device_get_interrupt()` exports one interrupt-object handle per queue-pair/group plus
    interrupt mode / vector metadata
- `zx_vmo_create_physical(base_paddr, size, 0, out)` is now public and creates a shared
  physical/MMIO-style VMO over an existing page-aligned physical span.
  - Creation is now gated by root-job membership: only processes running in the root job may create
    physical VMOs, preventing unprivileged processes from mapping arbitrary physical memory.
  - There is still no public Resource object; root-job authority is the current explicit policy
    boundary for this surface.
- `zx_vmo_create_contiguous(size, 0, out)` is now public and creates a shared contiguous VMO.
- `ZX_VM_MAP_MMIO` is now public on `vmar_map()` and requests one device/MMIO cache policy for
  the installed mapping.
- `ax_vmo_lookup_paddr(handle, offset, out_paddr)` is the current narrow Axle-native helper for
  resolving the backing physical address of one physical/contiguous VMO offset.
- `ax_vmo_pin(handle, offset, len, 0, out)` is now public and creates one `DmaRegion` object over
  one page-aligned range of one physical/contiguous VMO:
  - `DEVICE_READ`
  - `DEVICE_WRITE`
  are now the first narrow public DMA-permission bits on that pin contract.
- `ax_dma_region_lookup_paddr(handle, offset, out_paddr)` is the first narrow query on that pinned
  DMA-region object.
- `ax_dma_region_lookup_iova(handle, offset, out_iova)` is the first narrow device-visible address
  query on that same pinned DMA-region object.
- `ax_dma_region_get_info(handle, out)` is now the first narrow metadata query on that same pinned
  DMA-region object:
  - size in bytes
  - DMA-permission bits
  - identity-IOVA / physical-contiguity flags
  - coalesced segment count
  - base physical / device-visible addresses
- `ax_dma_region_get_segment(handle, segment_index, out)` is now the first narrow segment query on
  that same pinned DMA-region object:
  - segment offset / size in bytes
  - identity-IOVA / physical-contiguity flags
  - segment base physical / device-visible addresses
- `interrupt_create(ZX_INTERRUPT_VIRTUAL)` is now public as a narrow virtual/software interrupt
  object, and `ax_interrupt_trigger()` is the matching Axle-native injection helper.
- `interrupt_get_info(handle, out)` is now the first narrow metadata query over an interrupt
  object:
  - delivery mode
  - vector / line index
  - triggerable flag
- `ax_pci_device_get_interrupt_mode(handle, mode, out)` is now the first narrow interrupt-mode
  capability query on the bootstrap `PciDevice` object:
  - supported / active / triggerable flags
  - base vector
  - vector count
- `ax_pci_device_get_config(handle, out)` is now the first narrow config-space export on that same
  bootstrap `PciDevice` object:
  - config size in bytes
  - MMIO + read-only flags
  - VM map options for the config alias mapping
- `ax_pci_device_set_command(handle, command)` is now the first narrow config-write helper on that
  same device family:
  - it updates the live PCI command register on one discovered real-device handle
  - it also updates the exported config snapshot backing so userspace keeps one coherent view of
    the command bits it just programmed
- `ax_pci_device_set_interrupt_mode(handle, mode)` is now the first narrow interrupt-mode
  activation path on that same bootstrap `PciDevice` object:
  - `VIRTUAL` remains the current bootstrap delivery mode
  - `LEGACY` / `MSI` / `MSI-X` may now also be selected so userspace can validate exported
    interrupt-handle metadata against the selected mode
  - real hardware-backed routing/programming still remains future work

What is still intentionally narrow:

- the current `PciDevice` object is still a narrow resource-export object, not yet a generic PCI
  bus or full config-space ABI:
  - one synthetic bootstrap device handle may be seeded for conformance/runtime smoke
  - one first discovered x86 network function may also be seeded as one real-device bootstrap
    handle
- the current pin contract is one direct VMO -> `DmaRegion` path, not yet a fuller BTI/grant
  object model
- only physical and contiguous VMOs may currently be pinned
- the pin contract now has:
  - one first identity-like device-visible IOVA query
  - one first metadata query over that pinned DMA lifetime object
  - one first coalesced segment query over that same pinned lifetime object
  - one first DMA-permission bit surface
  but there is still no map/unmap token or richer translation/isolation model yet
- there is no IOMMU-facing isolation contract
- there is no hardware IRQ routing or real MSI/MSI-X programming model yet; current non-virtual
  interrupt modes are still synthetic metadata/activation scaffolding
- contiguous allocation is a bootstrap DMA-oriented primitive, not yet a richer device-memory policy
- physical/MMIO VMOs do not yet expose cache-policy or mapping-attribute controls
  beyond the first narrow `ZX_VM_MAP_MMIO` bit

## Current guidance

- Treat execute mappings as part of the supported phase-one VM contract rather than bootstrap-only
  metadata.
- Treat pager-backed/file-backed support as one narrow page-object contract:
  shared read-only source plus:
  - mapping-local private shadow on write
  - one object-level private clone helper when userspace needs direct
    write/resize semantics on a detached shadow object
- Treat `ax_vmo_get_info()` as the current public metadata face of that
  contract, not as evidence that pager/file-backed objects are already fully
  externalized.
- Treat the current physical / contiguous / interrupt surface as one minimal device-facing substrate:
  enough for bootstrap smoke, the current queue-owned user-mode net dataplane slice, the current
  bootstrap `PciDevice` + BAR0 transport smoke, the current generic PCI-resource discovery path,
  the now-explicit `DmaRegion`-backed queue and control-window lifetime slice, the first MMIO-
  attributed driver BAR/config mappings, the first narrow user-mode virtio-style
  feature/status/queue-select bring-up path, and later
  DMA/IOMMU integration, but not yet the final DFv2 device contract.
