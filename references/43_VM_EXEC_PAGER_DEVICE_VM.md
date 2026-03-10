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

What is not complete yet:

- pager-backed VMOs are not yet a normal user-facing VMO object contract
- there is no external pager object or full file-backed VMO interface
- write/resize semantics for pager-backed objects are not public contracts yet

## Device-facing VM primitives

The metadata layer already knows about `Physical` and `Contiguous` VMO kinds, but the external system model is not there yet.

Missing or incomplete areas include:

- Physical / MMIO VMO object exposure
- DMA-oriented allocation or grant model
- IOMMU-facing isolation hooks
- interrupt object integration with device mappings

These are relevant for the future driver framework more than for the earliest bootstrap userspace path.

## Current guidance

- Treat execute mappings as part of the supported phase-one VM contract rather than bootstrap-only
  metadata.
- Treat internal pager-backed code as bootstrap infrastructure, not as a stable pager ABI.
- Treat physical / contiguous VMO support in `axle-mm` as groundwork for later device work, not as a fully surfaced subsystem today.
