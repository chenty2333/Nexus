# VM CortenMM Adaptation

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
- `TxCursor` now batches invalidation work until `commit`, so the transaction
  boundary is also the current place where local TLB flush work is published.
- The x86_64 backend now also carries a fixed-shape descriptor set for
  `root/pdpt/user_pd/user_pt`; only the leaf PT currently carries page-local
  metadata, and upper-level uniform metadata remains deferred.
- The fixed `user_pd/user_pt` descriptors now classify the current 2 MiB user
  subtree as either `Uniform(template)` or `Leaf`, which is the first concrete
  upper-level uniform metadata hook for later generalization.
- The x86_64 walker and metadata stores are now sparse and no longer tied to a
  single fixed `USER_PT` leaf. The logical root VMAR spans the lower canonical
  user half above `USER_CODE_VA`, while the original 2 MiB bootstrap `USER_PT`
  remains only as an early wired-in bridge.
- Bootstrap conformance now covers a far-range VMAR mapping that lands well
  beyond the old 2 MiB bridge and crosses into a newly allocated upper page
  table path.
- TLB invalidation is now lazy across CPUs: page-table commits still flush the
  local active CPU immediately, but remote CPUs observe descriptor epochs and
  catch up at kernel-return / scheduling boundaries instead of taking an eager
  per-page IPI shootdown.
- Axle now has stable coarse mapping identity through `MapId` and `MapRec`.
  These records connect `VMAR` control metadata to page-local state without
  making `VMA` the long-term hot-path truth source.
- Axle now has a software `PteMeta` plane keyed by `(address_space, vpn)`.
  Fault classification, page-local COW state, bootstrap `LazyAnon`, and
  global-VMO-backed `LazyVmo` materialization already flow through this
  metadata layer.
- `PteMeta` ownership is now tightened through `MapRec`: page-local consumers
  resolve `(address_space, vmar_id, map_id)` through metadata first and only
  then recover mutable mapping state, which keeps child-VMAR identity explicit
  even on COW and destroy paths.
- Global anonymous VMO aliases now fault through one shared `GlobalVmo` source
  of truth instead of allocating per-address-space pages on first touch. The
  child-process conformance path now covers this lazy shared-VMO case.
- Bootstrap user-range prefaulting no longer holds the object layer and kernel
  locks across an entire multi-page range. It validates once, then resolves one
  page at a time through the VM kernel path, which narrows the fault-critical
  section before finer same-page serialization work.
- The object layer now enters VM through a separate `VmDomain` lock domain
  instead of running fault / prefault / VMAR / page-loan work under the main
  kernel core lock. Scheduling, process/thread bookkeeping, and futex state are
  still under the core lock; VM state now has its own boundary ahead of more
  precise same-page fault serialization.
- Trap-exit now has a common block primitive for scheduler-backed waits. An
  infinite `futex_wait`, `object_wait_one`, or `port_wait` can mark the current
  thread blocked even when there is no immediately runnable peer thread; trap
  exit idles until the current thread becomes runnable again, then restores the
  saved user context instead of re-capturing the blocked syscall frame.
- Same-page fault serialization now has an explicit `FaultInFlight` table.
  Fault handling is split into three phases: classify and claim a leader,
  prepare heavy work outside the main VM lock, then re-enter VM to revalidate
  and commit. Local `LazyAnon` / COW faults serialize on `(address_space,
  page_base)`, while shared `LazyVmo` faults serialize on `(global_vmo_id,
  page_offset)` so one shared page is materialized only once.
- Trap-driven page-fault waiters now reuse the same blocked trap-exit primitive
  as scheduler-backed wait syscalls. A contending fault can park the current
  thread in `VmFaultWait`, switch to another runnable thread, and later resume
  the saved fault context once the leader completes. User-pointer prefault paths
  still use the simpler spin-and-retry fallback because they run inside an
  in-flight syscall body rather than a restartable trap exit.
- Bootstrap fault-contention coverage now uses a test-only one-shot
  leader-pause hook so the single-current-thread bootstrap scheduler can force
  both local `(address_space, page)` contention and shared
  `(global_vmo_id, page_offset)` contention deterministically.
- Fault contention telemetry is now exported through the bootstrap shared
  summary slots. The kernel records leader/wait claims, spin loops, retries,
  commit outcomes, and prepare counts for `COW`, `LazyAnon`, and `LazyVmo`
  allocation paths before any finer VM lock splitting.
- Shared `GlobalVmo` state is no longer stored directly in the main `VmDomain`
  map. It now sits behind a dedicated `GlobalVmoStore` mutex, and the `LazyVmo`
  path only touches it for slot snapshot/revalidate/publish while heavy fault
  work remains outside the main VM lock.
- Physical frame state is likewise no longer embedded directly as a plain field
  inside `VmDomain`. `FrameTable` now sits behind its own mutex-backed store so
  mapping mutation, COW, lazy fault materialization, and loan pin/loan-count
  updates already have a distinct boundary ahead of any finer frame-side lock
  splitting.
- `Physical` and `Contiguous` VMO mappings now have explicit non-COW boundaries:
  they must already be resident when mapped, and COW arming rejects them.
- VMO object semantics have started to catch up with the fault path: bootstrap
  `zx_vmo_read` / `zx_vmo_write` now operate on the shared global VMO backing,
  anonymous writes materialize missing pages on demand, and
  `zx_vmo_set_size` supports page-aligned grow/shrink for anonymous VMOs while
  rejecting shrink across live mapped tails. `Physical` / `Contiguous` VMOs
  remain non-demand-paged and reject resize. The kind-to-operation matrix is now
  explicit: `Physical` rejects kernel byte I/O and page-loan, `Contiguous`
  allows kernel byte I/O but still rejects resize/COW/loan, and imported
  `Physical` / `Contiguous` aliases stay non-demand-paged instead of degrading
  into `LazyVmo`.
- The global VMO backing path now has a first backing-source split instead of
  treating every VMO as just `{kind, frames[]}`: `Anonymous`, `Physical`,
  `Contiguous`, and `PagerBacked` now live behind one internal
  `VmoBackingSource` enum. Pager-backed sources now hang off an internal
  `PagerSourceHandle` instead of a raw byte slice, so the current static-bytes
  source and a future file/pager source share one read/materialize interface.
  The first real file-like source is now wired to the QEMU loader runner ELF:
  bootstrap VM state seeds one internal pager-file VMO from that blob, ready to
  be imported into an address space without first copying the whole image into
  anonymous backing. The bootstrap ELF loader now also reads ELF headers and
  segment bytes through that same source path instead of indexing the whole raw
  blob directly.
  The first pager-backed step remains read-only and internal-only: a
  pager-backed `LazyVmo` can fault in one page from its source, `zx_vmo_read`
  can read directly from that source without materializing every page first,
  and `zx_vmo_write` / `zx_vmo_set_size` remain rejected for that kind.
- VM resource governance has started to move under one accounting surface:
  private COW pages and in-flight channel loan pages now keep current/peak
  counters, quota-hit telemetry, and a bootstrap loan-page quota that returns
  `ZX_ERR_SHOULD_WAIT` before channel queue capacity is exhausted.
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
- That reverse-mapping set is now maintained through an arena-backed frame→node
  structure plus an `(address_space, vpn)` side index, so add/remove paths no
  longer rely on scanning a per-frame `Vec`.
- The current reverse-mapping implementation is intentionally modest. It can
  answer "which known mappings currently point at this frame?" and the kernel
  uses it for `remap-fill -> COW split` telemetry and validation. It is useful
  and correct for the current bootstrap VM, but it is not yet the final
  high-efficiency reverse-mapping design.
- The kernel now has a direct internal `frame_mappings(frame_id)` snapshot
  helper, so diagnostics and invariants no longer need to manually rebuild
  `anchor -> address_space -> mapping` resolution at each call site.
- Detailed frame-mapping invariant walks are now off the hot path in normal
  release builds. They stay enabled under `debug_assertions` or the explicit
  `vm-diagnostics` kernel feature, so the diagnostic surface remains available
  without paying the full cost on every fault, COW, or loan path.
- Kernel diagnostics now dump frame mappings as `(address_space, vmar, map)`
  identities, and child-VMAR destroy / far-range root mappings have a combined
  conformance scenario to catch mixed control-plane/data-plane regressions.
- The `LazyVmo` materialization path now uses dedicated helpers to
  `ensure_global_vmo_frame(...)` and `bind_lazy_vmo_frame(...)`, which keeps
  the `GlobalVmoStore` touchpoints narrow and leaves `address_space + frames`
  binding on the main VM side.

What is intentionally deferred for later work:

- richer VMAR control-plane options beyond the current nested-child baseline
  (`offset != 0` still requires `ZX_VM_SPECIFIC` unless
  `ZX_VM_OFFSET_IS_UPPER_LIMIT` is used; compact child policy, alignment flags,
  and upper-limit placement now work, but broader allocate flags and stronger
  per-process ASLR policy still remain deferred)
- more selective invalidation and shootdown strategies beyond the current
  transaction-batched + epoch-lazy baseline
- a more mature reverse-mapping consumer layer built on top of the current
  arena-backed frame→mapping structure

Per-core VA allocation is now present in `axle-mm` as an internal root-VMAR
control-plane allocator. It hands out child-VMAR reservations through CPU-local
magazine hints, and the control-plane is now surfaced externally through
`zx_vmar_allocate`. That path now supports nested child-of-child allocation,
specific placement via `ZX_VM_SPECIFIC`, `ZX_VM_OFFSET_IS_UPPER_LIMIT` for
bounded non-specific placement, `ZX_VM_COMPACT` as a compact child policy,
alignment flags, and a simple non-specific ASLR-style placement policy inside
the chosen parent VMAR. Child VMARs currently enforce `ZX_VM_CAN_MAP_*` /
`ZX_VM_CAN_MAP_SPECIFIC` ceilings. Child VMARs also support recursive
`zx_vmar_destroy`, and non-specific `zx_vmar_map` now follows the child VMAR's
placement policy instead of a hard-coded first-fit path.

So the current state is: the correctness-oriented migration is largely in
place, while the CortenMM-style performance package is still deferred.

Most of this note is still about internal structure. The externally visible VM
changes that have landed are `zx_vmar_allocate` / `zx_vmar_destroy` for nested
child-VMAR control and non-specific `zx_vmar_map` inside child VMARs. Handle
encoding, signal semantics, and the broader `VMAR` / `VMO` / `Channel` object
model remain unchanged. If future VM work changes more external behavior, the
roadmap documents should be updated first.
