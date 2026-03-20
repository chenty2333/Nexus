# 42 - fault / COW / loan

Part of the Axle VM subsystem.

See also:
- `11_SYSCALL_DISPATCH.md` - trap-facing VMAR map and channel read special cases
- `12_WAIT_SIGNAL_PORT_TIMER.md` - blocked fault wait behavior
- `32_SCHEDULER_LIFECYCLE.md` - fault-induced blocking and wake transitions
- `34_IPC_CHANNEL.md` - channel page-loan integration
- `40_VM.md` - VM index
- `41_VM_VMO_VMAR.md` - VMO / VMAR metadata and mapping control plane
- `43_VM_EXEC_PAGER_DEVICE_VM.md` - neighboring incomplete VM work
- `90_CONFORMANCE.md` - scenarios that exercise these paths

## Scope

This file describes the current page-fault, copy-on-write, and channel page-loan behavior in the repository.

## Fault classification

- `axle-mm::AddressSpace::classify_page_fault()` distinguishes:
  - unmapped faults
  - protection violations
  - copy-on-write faults
  - lazy anonymous faults
  - lazy VMO-backed faults
- Per-page metadata (`PteMeta`) is the main source of truth for that classification.

## Fault serialization

- The kernel maintains a `FaultTable` keyed by either:
  - one local page in one address space
  - one shared VMO page
- The first claimant becomes the leader for that fault key.
- Trap-path contenders block through the same parked wait-core machinery used by signal / port /
  futex waits, with source `Fault(key)`.
- Resident-range helper contention still uses a local spin/retry helper in the non-trap path.
- Completion wakes waiters and advances an epoch-like completion counter for the in-flight fault record.
- The bootstrap trace recorder now exports one minimal trap-facing fault timeline:
  - `fault_enter`
  - `fault_block`
  - `fault_resume`
  - `fault_handled`
  - `fault_unhandled`
- The current bootstrap perf-smoke phase exercises one same-page contention shape through the
  existing leader-pause test hook, and the stable gate today is:
  - three fault entries
  - two blocked trap paths
  - two preserve-context resumes
  - one handled resolution
  - zero unhandled exits

This is the current mechanism that prevents duplicate materialization or inconsistent COW races on the same page.

- Trap-facing page-fault handling and current-process user-range residency checks now enter through
  a dedicated kernel fault bridge, instead of living in the object layer.

## COW behavior

- Anonymous writable mappings can enter a shared COW state.
- The COW-sharing arm is treated as the dangerous step for stale writable translations.
- The later fault-side install of one private page is currently treated as a relaxed commit:
  it must be visible to the faulting thread before user return, but it is not the global
  strict-sync boundary by itself.
- On a write fault:
  - a private page reservation token is acquired
  - a new frame is allocated and populated
  - the local mapping becomes writable on the new frame
  - reverse-map and resource-accounting state is updated
- The reservation is now a typed internal token rather than one bool carried across the whole fault
  path.
  - commit consumes the token
  - early error paths explicitly release it
  - quota accounting now tracks pending reservations separately from committed private COW pages
- VM resource tracking records:
  - current and peak private COW pages
  - current and peak in-flight loan pages
  - quota-hit counters
- COW now covers:
  - anonymous mappings
  - mapping-local private-clone views over pager-backed / file-backed sources
  - root direct mappings cloned into a child VMAR through mapping-level
    `PrivateCow` policy
- COW still does not apply to physical or contiguous mappings.

## Lazy materialization

- Private lazy anonymous pages allocate on first fault and stay local to the owning address space by default.
- They no longer publish every newly materialized page into shared/global backing as a side effect.
- Shared/global anonymous aliases and imported VMOs still fault through the shared/global backing source.
- Lazy VMO-backed pages bind to a shared/global source frame on first fault.
- Pager-backed global VMOs materialize through the kernel's pager source abstraction.
- `ZX_VM_PRIVATE_CLONE` / `AX_VM_PRIVATE_CLONE` now accepts any shared source whose VMO kind
  supports COW:
  - pager-backed / file-backed sources stay on that shared source for first materialization, then
    rebind one mapping-local private frame on the first write fault
  - staged byte-backed boot assets currently ride one page-rounded shared anonymous VMO through the
    same private-clone path
- The current bootstrap gate also now freezes the public source-vs-shadow
  consequence of that path for shared pager-backed handles:
  - writes through the `PRIVATE_CLONE` mapping become visible through the
    mapping-local shadow
  - reads through the shared source handle still observe the original source
    bytes
- The VM control plane now also carries child-clone policy as part of mapping
  truth:
  - `ZX_VM_CLONE_COW` / `AX_VM_CLONE_COW` mark one mapping as child-clonable
    through the normal COW machinery
  - `ZX_VM_CLONE_SHARE` / `AX_VM_CLONE_SHARE` mark one mapping as child-clonable
    as a shared alias over one shared/global source
  - `ax_vmar_clone_mappings()` is the first narrow public helper that consumes
    those policy bits without importing Linux VMA metadata into the kernel
- The first live user of that path is Starnix `fork` for root direct mappings:
  - writable image ranges and the initial user stack now clone through VM truth
    instead of guest-side byte copies
  - heap and `mmap()` child backing handles now also resynchronize through VM
    truth:
    - the child heap mapping is captured through one child-side
      `ax_vmar_get_mapping_vmo()` query
    - anonymous and private-shadow `mmap()` entries rebuild child backing
      handles from the child mapping's actual VMO
    - shared file mappings rebuild child backing handles from the same
      child-visible shared/global source
- Kernel VMO byte I/O can also materialize anonymous pages.
  When that happens for a page that is already mapped somewhere, the kernel now attaches the new
  frame to existing mapping aliases:
  - reverse-map nodes are installed
  - frame map/ref counts are updated
  - page tables are refreshed from the software VM truth

This keeps post-bind kernel I/O on VMO pages consistent with later unmap / resize / fault paths.

## Reverse-map consumers

- Reverse-map is now part of the retirement mechanism, not only validation / telemetry.
- VMO shrink no longer barriers every importer or owner address space by default.
  - after truncation, the kernel retires dropped tail frames only if reverse-map resolution and
    frame accounting agree that they have no remaining mappings, refs, pins, or loans
  - exact frame reuse safety is therefore keyed to the dropped frame set, not to the full set of
    VMO importers
- The same retire planner now also runs after mapping replacement and loan teardown:
  - receiver-side loan remap can retire old destination frames that lost their final mapping
  - releasing a loan token can retire orphaned source frames whose final non-VM reference just
    disappeared
- Strict TLB synchronization is still used where the current operation changed one mapping.
  - for example, receiver-side remap retires old frames only after the receiver address space has
    crossed the strict barrier for that remap
- Strict shootdown is now fail-closed.
  - if one remote CPU does not acknowledge the required invalidate before the timeout window, the
    kernel returns an error and does not mark that CPU's epoch as observed for the strict commit

## Channel page-loan

- Channel write can avoid copying when the payload is page-aligned and spans full pages.
- Mixed-shape buffers now use the kernel copy service to split:
  - copied head bytes
  - optional loaned full-page body
  - copied tail bytes
- The current fast path:
  - validates sender pages
  - acquires pinned-frame ownership tokens
  - reserves in-flight loan quota through one typed reservation
  - prepares sender/receiver address-space transaction state
  - arms sender-side COW and receiver-side remap behavior
- Sender-side COW arming now works page-locally across the aligned loaned body range.
  - the body no longer needs to be its own standalone mapping as long as the aligned page range is
    fully covered by writable anonymous pages
- The resulting loaned-page object is now a consuming ownership token.
  - frame pins and loan counts are no longer released through naked `dec_loan/unpin` pairs
  - releasing a channel payload consumes the loan object and tears down both the frame loan and the
    in-flight loan budget
- Channel read can either:
  - remap the loaned pages into the receiver buffer fast path
  - or fall back to a copy-fill path through the same internal copy service
- Receiver-side remap is intentionally strict and expects a compatible writable anonymous destination mapping.
  - for fragmented payloads, the remapped body still expects an exact anonymous destination-body
    mapping span
  - ordinary contiguous receiver buffers continue to work through the fallback-copy path
- When remap replaces an existing anonymous destination frame, reverse-map now decides whether that
  replaced frame can retire immediately after the strict barrier or must stay alive for other
  mappings.
- Sender-side loan preparation now treats the COW arm as a strict commit surface, because stale
  writable translations would break the snapshot guarantee.
- When the loan object is later released, the kernel also checks whether any of the loaned source
  frames became fully orphaned and can now retire.

## Important current limitation

The current page-loan path is still not the full scatter design from the roadmap.

- full-page aligned body: supported
- head/tail fragments: supported as copied fragments, but not yet as dedicated fragment-page objects
- mixed scatter descriptor: partially present through fragmented channel payloads, but not yet a general reusable VM scatter descriptor
- Loaning is currently anonymous-only, resident-only, and page-granular.
- Fragmented sender bodies can now be loaned out of subranges inside a larger anonymous mapping,
  but receiver-side remap is still stricter than the fallback path and has not been generalized to
  every compatible destination shape.

This is the main gap between the current channel VM path and the intended final design.

## Current limitations

- Fault serialization now lives in a dedicated kernel fault slice, but it still depends on `VmDomain`
  planning / commit internals and bootstrap page-allocation helpers.
- The current strict TLB path can flush active peer CPUs and now runs on top of the phase-one
  per-CPU scheduler / incoming-wake substrate.
  - the correctness gate is now fail-closed
  - the remaining gap is scalability shape for a future multi-core shared-address-space execution
    model, not silent success on missed shootdown ack
- Physical / contiguous VMOs are not part of the normal fault-on-demand userspace object flow.
- Loan behavior depends on anonymous/shared-user mappings and is not yet generalized to every future VMO kind.
