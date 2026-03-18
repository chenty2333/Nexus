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
    synthesize one cached page-rounded anonymous VMO on first request and
    duplicate that handle for later callers
- The narrow public pager/file-backed mapping contract is now:
  - the handle names one shared read-only mapping source:
    - imported pager-backed/file-backed VMOs when the boot image already has
      one
    - otherwise one staged shared anonymous VMO containing the file bytes
  - `AX_VM_PRIVATE_CLONE` / `ZX_VM_PRIVATE_CLONE` may map any shared COW-capable
    source through a
    writable mapping-local shadow view
  - the shared pager/file source remains unchanged; first write allocates one
    private page for that mapping instead of mutating the source VMO
  - this mapping-local private-clone path does not require VMO write rights on
    the source file-backed handle

What is not complete yet:

- pager-backed VMOs are still only a narrow user-facing contract:
  - read-only shared handles
  - writable private-clone mappings
- there is no external pager object or full file-backed VMO interface
- write/resize semantics for pager-backed objects are not public beyond
  mapping-local private-clone faults
- DataFS-prep only freezes read-only `GetVmo` and recovery/model constraints on
  the host side; it does not yet provide a real writable file-backed VMO path

## Device-facing VM primitives

Current state:

- `zx_vmo_create_physical(base_paddr, size, 0, out)` is now public and creates a shared
  physical/MMIO-style VMO over an existing page-aligned physical span.
- `zx_vmo_create_contiguous(size, 0, out)` is now public and creates a shared contiguous VMO.
- `ax_vmo_lookup_paddr(handle, offset, out_paddr)` is the current narrow Axle-native helper for
  resolving the backing physical address of one physical/contiguous VMO offset.
- `interrupt_create(ZX_INTERRUPT_VIRTUAL)` is now public as a narrow virtual/software interrupt
  object, and `ax_interrupt_trigger()` is the matching Axle-native injection helper.

What is still intentionally narrow:

- there is no BTI/pinning/grant object
- there is no IOMMU-facing isolation contract
- there is no hardware IRQ routing or MSI/MSI-X model yet
- contiguous allocation is a bootstrap DMA-oriented primitive, not yet a richer device-memory policy
- physical/MMIO VMOs do not yet expose cache-policy or mapping-attribute controls

## Current guidance

- Treat execute mappings as part of the supported phase-one VM contract rather than bootstrap-only
  metadata.
- Treat pager-backed/file-backed support as one narrow page-object contract:
  shared read-only source plus mapping-local private shadow on write.
- Treat the current physical / contiguous / interrupt surface as one minimal device-facing substrate:
  enough for bootstrap smoke, the first queue-owned user-mode net dataplane slice, future
  user-mode virtio transport work, and later DMA/IOMMU integration, but not yet the final DFv2
  device contract.
