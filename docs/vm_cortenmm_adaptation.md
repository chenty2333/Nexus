# VM CortenMM Adaptation

This note supplements `references/Axle_v0.3.md` and
`references/AxleKernel_Roadmap_v0.3.md`.

Axle is borrowing CortenMM's internal structure, not its full end-state.
The goal is to make page-table updates, page-local metadata, fault handling,
COW, and page-loan share one coherent source of truth without changing Axle's
external VM model.

- Axle keeps `VMAR` and `VMO` as the control-plane and object-semantics
  boundary. It does not delete region-level structure or turn the kernel into a
  Linux-style `mmap` implementation.
- Axle now routes page-table mutation through `axle-page-table` transaction
  interfaces shaped as `lock(range) -> query / map / unmap / protect / commit`.
  The current backend is still the bootstrap `USER_PT`, but the API shape is no
  longer tied to that implementation detail.
- Axle now has stable coarse mapping identity through `MapId` and `MapRec`.
  These records connect `VMAR` control metadata to page-local state without
  making `VMA` the long-term hot-path truth source.
- Axle now has a software `PteMeta` plane keyed by `(address_space, vpn)`.
  Fault classification, page-local COW state, and bootstrap `LazyAnon`
  materialization already flow through this metadata layer.
- Axle's channel page-loan path now uses ordered cross-address-space
  transactions, sender-side COW arming, and a conservative bootstrap
  `remap-fill` fast path. Channel `close/read` and `WRITABLE` recovery behavior
  is covered by conformance tests.
- Channel ownership no longer depends on a create-time address-space snapshot.
  Endpoints resolve the owner through `process_id -> address_space_id` at use
  time, which removes one bootstrap-only assumption from the loan/remap path.
- Axle's physical-frame bookkeeping has been pushed toward a `VmPageDesc` shape.
  `FrameTable` now tracks `ref_count`, `map_count`, `pin_count`, `loan_count`,
  and a per-frame reverse-mapping anchor set.
- The current reverse-mapping implementation is intentionally modest. It can
  answer "which known mappings currently point at this frame?" and the kernel
  uses it for `remap-fill -> COW split` telemetry and validation. It is useful
  and correct for the current bootstrap VM, but it is not yet the final
  high-efficiency reverse-mapping design.

What is intentionally deferred for later work:

- per-PT-page descriptors
- upper-level uniform metadata
- lazy TLB shootdown
- per-core VA allocation
- a higher-efficiency reverse-mapping structure than the current anchor set

So the current state is: the correctness-oriented migration is largely in
place, while the CortenMM-style performance package is still deferred.

This note does not change syscall ABI, handle encoding, rights semantics,
signal semantics, or the external `VMAR` / `VMO` / `Channel` object model. If
future VM work changes externally visible behavior, the roadmap documents should
be updated first.
