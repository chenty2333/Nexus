# 41 - VMO / VMAR

Part of the Axle VM subsystem.

See also:
- `11_SYSCALL_DISPATCH.md` - VMO / VMAR syscall surface
- `20_HANDLE_CAPABILITY.md` - VMO / VMAR handles and rights
- `21_OBJECT_MODEL.md` - VMO and VMAR object records
- `40_VM.md` - VM index
- `42_VM_FAULT_COW_LOAN.md` - fault and COW paths
- `43_VM_EXEC_PAGER_DEVICE_VM.md` - execute, pager, and device-facing gaps
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` - process image and root VMAR creation

## Scope

This file describes the current VMO, VMAR, VMA, and address-space control-plane shape in the repository.

## Current implementation layers

- `crates/axle-mm` is the metadata core:
  - `AddressSpace`
  - `Vmo`
  - `Vmar`
  - `Vma`
  - `MapRec`
  - `FrameTable`
  - reverse-map metadata and per-page metadata stores
- `FrameTable` now uses a `BTreeMap<FrameId, FrameDescRecord>` internally instead of a linear
  `Vec`, giving O(log n) frame lookup instead of O(n) linear scan for large physical memory.
- `kernel/axle-kernel/src/task.rs` wraps this in `VmDomain` and ties it to page tables and process ownership.
- `kernel/axle-kernel/src/object.rs` exposes VMO and VMAR syscalls through object handles.

## Truth split

- Object-layer VMO state is now intentionally narrow:
  - stable identity
  - size
  - kind
  - backing scope (`LocalPrivate` vs `GlobalShared`)
- `ax_vmo_get_info()` now exports that same narrow object snapshot as the current public VMO info
  contract:
  - logical size in bytes
  - kind
  - backing scope
  - stable behavior flags such as resizable / COW-capable / kernel-readable
  - effective rights on the queried handle
- Hot page state is not cached in the object layer.
- `MapRec` is the coarse mapping/control-plane identity:
  - `(address_space, vmar_id, map_id, va range)`
  - source VMO id and offset
  - maximum permissions
- `Vma` is now a thinner runtime mapping record:
  - `map_id`
  - `vmar_id`
  - `base / len`
  - current permissions
  - mapping-wide COW bit
  - mapping-level clone policy (`None` / `SharedAlias` / `PrivateCow`)
- Per-page hot state lives in `PteMeta`.
- Physical frame / reverse-map / pin / loan truth lives in `FrameTable`.
- `FrameRef`, `PinToken`, and `LoanToken` `Drop` implementations now use hard `assert!` (not
  `debug_assert!`) so resource leaks panic even in release builds, preventing silent physical
  frame leakage.
- Reverse-map state is no longer only diagnostic metadata.
  - the kernel now consumes it to decide whether dropped or replaced frames are actually retireable
  - precise frame-reuse planning is based on the live anchor set plus frame ref / pin / loan state,
    not just on importer ownership or coarse VMO identity

## VMO kinds

The metadata layer already knows about:

- `Anonymous`
- `Physical`
- `Contiguous`
- `PagerBacked`

Current user-facing object creation is much narrower:

- `zx_vmo_create` currently creates anonymous VMOs.
- Pager-backed VMOs exist internally for bootstrap code images and loader-backed sources.
- `zx_vmo_create_physical(base_paddr, size, 0, out)` now creates one shared physical/MMIO-style VMO
  over an existing page-aligned physical span.
- `zx_vmo_create_contiguous(size, 0, out)` now creates one shared contiguous VMO suitable for the
  current narrow DMA-oriented bootstrap path.
- `ax_vmo_lookup_paddr(handle, offset, out_paddr)` is the current Axle-native helper for resolving
  the physical address backing one physical/contiguous VMO offset.
- `ax_vmo_get_info(handle, out_info)` is the first narrow public object-level metadata query over
  those same VMO families:
  - it reports size / kind / backing scope / behavior flags / effective rights
  - it intentionally does not expose live residency, dirty/writeback state, or per-page mappings
- `ax_vmo_create_private_clone(source, out)` is now the first narrow object-level
  private-shadow helper:
  - it requires one shared COW-capable source handle
  - it returns one new `Anonymous + LocalPrivate` VMO handle seeded with the
    current source bytes
  - later direct write/resize apply to that clone only and do not mutate the shared source
- `ax_vmo_promote_shared(handle)` is now the first narrow control-plane promotion hook over
  anonymous VMOs:
  - it upgrades one local-private VMO object into the shared/global backing domain
  - the staged boot-asset `GetVmo` path uses it before it exports one read-only
    shared source handle
- `ax_vmar_get_mapping_vmo(vmar, addr, out_vmo)` is now the first narrow
  mapping-backed VMO capture hook:
  - it snapshots the current backing VMO of the mapping that covers `addr`
    inside `vmar`
  - it exposes one new handle over that backing using the current mapping
    permissions as the public rights ceiling
  - it intentionally captures one control-plane view of mapping truth rather
    than per-page state

## VMAR model

- Each address space has one root VMAR.
- The logical root user range currently spans the bootstrap userspace window starting at `USER_CODE_VA`.
- VMAR allocation supports:
  - specific placement
  - compact placement
  - randomized placement
  - alignment control
  - upper-limit placement mode
- Child VMAR allocation and recursive destroy are implemented.
- Mapping metadata tracks:
  - base / len
  - source VMO and offset
  - current and maximum permissions
  - owning VMAR subtree

## Current exposed operations

Current object/syscall paths support:

- create process address space plus root VMAR
- create anonymous VMO
- query narrow VMO object metadata
- VMO read / write / resize
- VMAR allocate / destroy
- VMAR map / unmap / protect
- VMAR clone for mappings whose clone policy is already part of VM truth:
  - `ax_vmar_clone_mappings(src_vmar, dst_vmar)`
  - the helper stays generic and clones Axle VM mappings, not Linux VMA trees
- VMAR capture of the current mapping-backed VMO for one address:
  - `ax_vmar_get_mapping_vmo(vmar, addr, out_vmo)`
  - the helper stays generic and names the backing VMO currently installed for
    that mapping rather than exporting Linux VMA metadata
- one narrow subrange split path for `unmap` / `protect`:
  - one exact-range fast path still exists for whole-mapping operations
  - one single-covering-VMA subrange path now exists for dynamic-loader style
    `MAP_FIXED` / `mprotect` surgery inside one larger mapping
  - multi-VMA range surgery is still intentionally out of scope
- execute-capable VMAR map / protect when VMAR caps and handle rights allow it
- mapping-level clone policy bits on `vmar_map()`:
  - `ZX_VM_CLONE_COW`
  - `ZX_VM_CLONE_SHARE`
  - `ZX_VM_PRIVATE_CLONE` remains the source-handle-facing pager/file-backed
    shadow path

The metadata layer also validates overlap, mapping range, resize legality, and VMAR subtree ownership.

## Anonymous backing model

- `zx_vmo_create` now creates a local-private anonymous VMO first.
- A fresh anonymous VMO is owned by one address space through its local `VmoId`.
- It does not immediately register one shared/global anonymous backing source just because it has a kernel-global id.
- Cross-address-space map or cross-process handle transfer promotes that VMO to `GlobalShared`.
- Imported anonymous VMOs are treated as shared/global-backed aliases from the start.
- That promotion rule is now also frozen at the public object-info surface:
  - one fresh anonymous VMO must report `Anonymous + LocalPrivate`
  - after one cross-process handle transfer/install, both:
    - the importer's handle
    - the exporter's remaining original handle
    must report `Anonymous + GlobalShared`

## Identity model

- VMOs have both local `VmoId` values and kernel-global `GlobalVmoId` values.
- VMARs are identified by `VmarId` within one address space.
- The kernel-global id is now a stable shared identity, not proof that the current backing is already shared/global-backed.
- Shared/global backing is decided by backing scope and import/promotion, not by the mere presence of a non-zero global id.
- The kernel uses global VMO ids to synchronize genuinely shared state across address spaces and page-loan paths.

## Phase-one gate contract

The first VM control-plane stabilization gate is frozen here.
It is not fully implemented yet.

- No new VM object types are introduced for this phase.
- The existing truth split stays in place:
  - `MapRec` / `Vma` for mapping control plane
  - `PteMeta` for hot per-page state
  - `FrameTable` for frame / reverse-map / pin / loan truth
- Execute capability must propagate through the normal VMAR control plane rather than through a bootstrap-only shortcut:
  - root and child VMAR capability metadata
  - VMAR allocate option decode
  - map / protect permission validation
- The external visibility rule is frozen even though the implementation detail stays internal:
  - relaxed vs strict commit remains an internal classification
  - syscall-return visibility and frame-reuse safety are externally visible and therefore fixed by contract
- Mapping-level child-clone semantics are now also part of that public control
  plane:
  - `ZX_VM_CLONE_COW` freezes one child-visible COW clone policy on a mapping
  - `ZX_VM_CLONE_SHARE` freezes one child-visible shared-alias clone policy on
    a mapping
  - `ax_vmar_clone_mappings()` is the first narrow public consumer of those
    policies
- Conformance gate:
  - contract: `must.vm.strict_tlb_visibility_phase1`
  - minimal scenario: `kernel.vm.strict_tlb_visibility_phase1`

## Current limitations

- Execute mappings are now wired through the normal VMAR path, but the surrounding pager / file-backed object model is still incomplete; see `43_VM_EXEC_PAGER_DEVICE_VM.md`.
- `ax_vmo_get_info()` is intentionally object-level only:
  - it freezes the public size / kind / backing-scope / behavior-flag snapshot
  - it is not a public residency, dirty-page, or page-cache inspection API
- The current shared pager-backed/file-backed handle contract is also now
  explicitly gated at the syscall surface:
  - `vmo_read()` is allowed on the shared source handle
  - direct `vmo_write()` is denied
  - direct `vmo_set_size()` is denied
- The current staged shared-anonymous `GetVmo` source-handle contract is now
  frozen to the same public shape:
  - `ax_vmo_get_info()` reports `Anonymous + GlobalShared`
  - `vmo_read()` is allowed on the exported shared handle
  - direct `vmo_write()` is denied
  - direct `vmo_set_size()` is denied
- The current anonymous-promotion contract is now also explicitly gated at the
  syscall/object-info surface:
  - one fresh anonymous VMO reports `LocalPrivate`
  - one cross-process transfer/install promotes that same backing to
    `GlobalShared`
  - the promotion is visible through both the imported handle and the original
    exporting handle that remains open in the parent
- Root direct `fork` mappings now also have a first generic clone contract:
  - Starnix `fork` no longer copies writable image ranges or the initial user
    stack through guest byte loops
  - instead it clones root-VMAR mappings through `ax_vmar_clone_mappings()`
    using the same mapping-level clone policy already stored in VM truth
- Heap / mmap `fork` backing handles now also follow the same VM truth instead
  of guest byte copies:
  - Starnix captures child heap and `mmap()` backing handles through
    `ax_vmar_get_mapping_vmo()`
  - anonymous mappings, shared file mappings, and private-clone shadow mappings
    now rebuild child-side userspace control-plane state from the child's actual
    VM mappings
- Physical / contiguous VMOs are now public as narrow bootstrap primitives, but the broader device
  model is still incomplete:
  - no BTI/pinning object
  - no IOMMU isolation contract
  - no richer MMIO cache-policy surface yet
- Public allocation defaults are still simpler than the full internal placement machinery; some compact/per-CPU placement paths are internal rather than normal syscall behavior.
- The crate is structurally large and still concentrated in one file, even though the semantic layers are already distinct.
