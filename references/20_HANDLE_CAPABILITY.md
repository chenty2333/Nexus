# 20 - handle / capability

Part of the Axle core object model.

See also:
- `21_OBJECT_MODEL.md` - kernel object table and object kinds
- `11_SYSCALL_DISPATCH.md` - handle lookup and rights checks at the syscall boundary
- `12_WAIT_SIGNAL_PORT_TIMER.md` - waitable signals carried by objects
- `30_PROCESS_THREAD.md` - per-process handle ownership
- `33_IPC.md` - handle transfer across IPC objects
- `40_VM.md` - VMO / VMAR handles use the same capability model
- `AxleKernel_Roadmap_v0.3.md` - intended long-term model

## Scope

This file describes the current handle, capability, CSpace, rights, and revocation shape in the repository.
It is a current-state reference, not a roadmap.

## Current implementation

- Native user-visible handles are `ax_handle_t = u64` at the public UAPI layer.
- `zx_handle_t` now survives only as a source-level compatibility alias over the same 64-bit width;
  the old live 32-bit handle width is retired.
- The live kernel/user handle codec is now the native 64-bit `axle_core::handle::Handle` shape:
  - raw handle = `[slot_index:32][slot_tag:32]`
  - `0` is invalid
  - `slot_tag == 0` is reserved and never allocated
- Kernel capabilities are now stored as an explicit `Capability { object_id, rights, generation }`
  struct instead of a packed `u128`.
- Per-process handle storage is `axle_core::CSpace`:
  - O(1) lookup by slot index
  - ABA protection via slot tag
  - FIFO free list plus quarantine window to avoid hot slot reuse
  - handle capacity is now a policy knob (`max_slots`), not a 14-bit codec limit
- The bootstrap kernel wraps `CSpace` inside each `Process` in `kernel/axle-kernel/src/task.rs`.
- Rights checking happens after handle lookup and is represented internally by `HandleRights`, which mirrors Zircon rights bits.
- Kernel-facing handle service entry points now live in `kernel/axle-kernel/src/object/handle.rs`.
- `object.rs` no longer owns duplicate/replace/transfer helpers directly; it keeps the global object table and thin close/signal entry points.

## Key files

- `crates/axle-core/src/handle.rs`
- `crates/axle-core/src/capability.rs`
- `crates/axle-core/src/cspace.rs`
- `crates/axle-core/src/revocation.rs`
- `kernel/axle-kernel/src/task.rs`
- `kernel/axle-kernel/src/object.rs`
- `kernel/axle-kernel/src/object/handle.rs`

## Invariants

- A closed handle must never successfully resolve again, even if its slot is later reused.
- Rights may be reduced through duplicate/replace flows, but never expanded.
- Handle transfer moves capability payloads between per-process CSpaces; the object id remains global.
- Revocation checks happen on lookup when a stored handle entry carries a revocation reference.
- Capability lookup is generation-aware: the kernel validates `(object_id, generation)` against the
  current live object slot, not just `object_id`.
- Once one object enters logical destroy, ordinary handle use must fail with `ZX_ERR_BAD_HANDLE`.
- `handle_close` is the one exception: one stale handle may still close successfully so the final
  external reference can drain and let the slot retire.
- An object id may be reused only after the old slot reaches physical retirement and bumps its
  generation.

## Current kernel shape

- `crates/axle-types` now exposes the native/public ABI narrow waist:
  - `ax_handle_t = u64`
  - `ax_status_t`, `ax_rights_t`, `ax_signals_t`, `ax_vaddr_t`, and friends
- `zx_*` aliases remain available as a compat naming surface, but new native userspace code is
  expected to grow against `ax_*` or `libax` rather than directly against `libzircon`.
- Native Nexus crates now treat `libax` as the only public userspace syscall facade; any legacy
  `zx_*` wrapper reach-through is expected to happen under `libax::compat`, not by adding new
  direct `libzircon` dependencies.

- `KernelState::alloc_handle_for_object()` currently wraps one object id into a `Capability` and installs it in the current process CSpace.
- The handle façade still lives on `KernelState`, but object-handle ref tracking now lives in `ObjectRegistry` rather than a single mutable `KernelState` bag.
- Lookup, duplicate, replace, transfer snapshot, and transferred-handle install are implemented from `object/handle.rs` by coordinating:
  - per-process `CSpace` mutations in `Kernel`
  - object-handle refcount updates in `ObjectRegistry`
  - public revocation-group lookup and delegated-handle duplication now also live on that same
    handle/object boundary:
    - `ax_revocation_group_create()`
    - `ax_revocation_group_get_info()`
    - `ax_revocation_group_revoke()`
    - `ax_handle_duplicate_revocable()`
- `ResolvedHandle` carries:
  - process id
  - slot index / slot tag
  - object key `(object id, generation)`
  - rights
- `ObjectRegistry` is now a generation-aware slot table rather than a monotonic `object_id ->
  object` map.
- Object allocation returns `ObjectKey { object_id, generation }`, and capabilities carry that full
  identity.
- Logical destroy removes the object from live lookup while the slot remains in `Dying` until all
  handle refs and kernel refs drain.
- Physical retirement bumps generation and returns the slot to the free list so the numeric object
  id may be reused safely.

## Revocation status

- `axle-core` already has `RevocationManager`, `RevocationGroupToken`, and `RevocationRef`.
- `CSpace` can allocate revocable entries and validate them on lookup.
- `CSpace` `duplicate_derived`, `replace_derived`, and `duplicate_revocable` now validate that
  the requested new rights are a subset of the original capability's rights, returning
  `AccessDenied` when the caller attempts to expand rights through a derive operation.
- The bootstrap kernel now exposes one narrow public revocation-group object family:
  - `ax_revocation_group_create()` returns one group handle that carries revoke authority
  - `ax_revocation_group_revoke()` bumps the group's epoch
  - `ax_revocation_group_get_info()` reports `group_id`, `generation`, and `epoch`
- Public revocable delegation now starts through `ax_handle_duplicate_revocable()`:
  - it duplicates one source handle with equal-or-fewer rights
  - it snapshots the target revocation group's current epoch onto the duplicate
  - later duplicate/replace/transfer of that delegated handle preserve the same revocation
    association through the ordinary `CSpace` paths
- `wait_async` registrations now retain handle-level revocation provenance too:
  - if a waitable handle or destination port handle came from one revocable delegation epoch,
    `ax_revocation_group_revoke()` removes the stale observer when that epoch is revoked
  - this keeps async packet delivery aligned with the same epoch validity rule used for ordinary
    handle lookup and transfer
- Revocation provenance is now also carried by deferred control-plane state beyond `wait_async`:
  - blocked `wait_one` / `port_wait` registrations
  - armed timer state
  - queued kernel-generated port packets
- `ax_revocation_group_revoke()` now eagerly purges that deferred state when it still depends on a
  revoked handle epoch.
  The revocation boundary is intentionally precise:
  - future control-plane effects that the kernel still owns are canceled
  - already committed data-plane effects are not rolled back
- There is now one narrow public job-governance layer above ordinary handles:
  - `ax_process_get_job()` returns the current owning job for one process handle
  - `ax_job_create()` creates a child job under a parent job handle
  - `ax_job_get_info()` reports stable `job_id`, parent koid, child counts, and the current
    rights ceiling
  - `ax_job_set_policy()` monotonically narrows a job's policy ceiling and pushes that ceiling
    into descendant jobs/processes
  - future handle derivation/install paths cache that ceiling by intersecting derived or imported
    handle rights with the owning process policy ceiling
- Ordinary object handles are still non-revocable by default; revocation remains one deliberate
  delegation opt-in rather than a property of every handle family.

## What is intentionally not true yet

- Revocation is still independent from generation-based stale-handle isolation.
- There is now one minimal public job tree for authority scoping, but it is intentionally narrow:
  - no quota accounting
  - no resource object family
  - no install-time policy program beyond one rights ceiling
- Revocation-group quotas or ownership are not yet job-governed.
- Public revocation-group lifecycle is intentionally modest today:
  - closing the last group handle drops revoke authority
  - full group-slot reclamation / quota governance remains later work
- Revocation is still not a transactional rollback facility:
  - it cancels deferred authority
  - it does not undo already-enqueued channel/socket payloads or other completed operations

## Current object-right examples

- interrupt handles now use the narrow default set:
  - duplicate
  - transfer
  - wait
  - write
- physical / contiguous VMO handles currently reuse the normal VMO default-right shape.
