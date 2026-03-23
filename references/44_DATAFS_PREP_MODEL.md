# 44 - DataFS-prep model and checker

Part of the Nexus I/O and storage groundwork.

See also:
- `00_REPO_MAP.md` - repository index
- `31_PROCESS_THREAD_BOOTSTRAP_LAUNCH.md` - current userspace bootstrap and root-manager path
- `43_VM_EXEC_PAGER_DEVICE_VM.md` - read-only `GetVmo` and pager-backed file mapping context
- `Nexus_Roadmap_v0.3.md` - larger system-layer roadmap

## Scope

This file covers the host-side scaffolding that freezes the first DataFS design
constraints before a real filesystem implementation exists.

It is intentionally not a runtime filesystem contract yet. The current tree only
commits to:

- one reference model for inode/object metadata state
- one logical journal/checkpoint replay model
- invariant checks suitable for a future minimal fsck
- fault-injection and crash-replay hooks
- reserved recovery and transport identity fields

## Current implementation

The current tree now carries two host-side DataFS-prep artifacts:

- `crates/nexus-fs-model`
  - one small reference model over object ids, directory bindings, link counts,
    extents, and object lifecycle
  - high-level operations for:
    - `CreateDir`
    - `CreateFile`
    - `Write`
    - `Link`
    - `Rename`
    - `Unlink`
    - `Fsync`
  - logical journal records for begin / mutation / commit / checkpoint
  - invariant checking over recovered state and journal structure
- `tools/datafs-check`
  - `list` for built-in scenarios
  - `explore` for scenario-wide state-space replay under injected faults
  - `inject` for emitting explicit replay-case bundles
  - `replay` for running one saved case or one saved case set back through the
    checker

The built-in scenarios are intentionally small and metadata-heavy:

- `rename-fsync`
- `link-unlink`
- `extent-checkpoint`

The injected fault classes are also intentionally small and checkable:

- drop the journal after one sequence number
- corrupt the checksum of one record
- drop every checkpoint record

## Frozen DataFS v1 constraints

The current host-side contract freezes these design choices for the first
implementation:

- userspace filesystem service, not an in-kernel VFS
- single logical volume
- 64-bit object/inode ids
- extent-based regular-file layout
- indexed directory representation
- logical metadata journal
- checksummed journal/checkpoint records
- checkpoint-based recovery boundary
- minimal fsck-style invariant checking
- read-only `GetVmo`
- no writable `mmap` in v1

Practical meaning:

- package/resource-style pager-backed reads are in scope
- read-only `GetVmo` now explicitly includes both:
  - shared pager-backed/file-backed source handles
  - staged shared-anonymous source handles for byte-backed assets
  and freezes them as readable but not directly writable/resizable
- the live channel protocol is still the control plane, but ordinary remote
  file `read` / `write` traffic may now also use one VMO-backed bulk path for
  larger payloads instead of always serializing every byte through the channel
  body
- coherent writable mappings, writeback invalidation, and mmap-driven dirty-page
  ownership are explicitly out of scope for v1

## Recovery and transport reservations

The current model also freezes the fields and hooks that later recovery work
will need:

- stable `session_id`
- stable open-file-description identity
- reconnect/rebind intent carried in recovery metadata
- transport abstraction that currently allows:
  - `ChannelRpc`
  - `SharedRing`

This is only a reservation layer today. The live filesystem service protocol is
still small and channel-based, now with one VMO-backed bulk transfer option for
ordinary read/write payloads, but the model and checker already assume that the
transport and reconnect identity must not be retrofitted later.

## Current invariants

The current checker validates a small set of structural and crash-consistency
properties:

- root object exists, remains a live directory, and keeps its directory index
- every directory entry points to a live object record
- object `link_count` matches the inbound directory-entry count
- orphaned regular files remain `OrphanPendingDelete` until a checkpoint
- checkpoint replay reclaims orphaned objects
- extents in a regular file do not overlap
- journal sequence numbers remain monotonic
- checkpoint records only follow committed transactions
- record checksums must still match at replay time

## Current limitations

This is not yet a real filesystem implementation.

Current gaps include:

- no on-disk layout or allocator model
- no real block device integration
- no concurrent transaction or lock-order model
- no real pager object or writeback engine
- no writable `mmap`
- no fsck repair path beyond invariant reporting
- no transparent service restart / reconnect implementation yet

The main purpose of this layer is to let G/I progress without blocking on the
full DataFS implementation, while still freezing the recovery and transport
constraints early enough to avoid later rewrites.
