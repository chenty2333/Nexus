# Nexus OSTD VirtIO safe facade

`nexus-ostd-virtio` is the reusable safe boundary around the PCI, DMA, queue,
reset, and IOTLB substrate first exercised by the separate-boot Stage 5B
experiment. Its crate root denies unsafe code; only the private `pci`, `dma`,
`portal`, and `production` modules receive local allowances. Downstream crates cannot name
the raw HAL, raw PCI root, raw MMIO pointers, or DMA owners.

The facade preserves these ownership invariants:

- one opaque `Root` owns the discovered block device and all acquired memory
  BARs, and grants exactly one portal claim;
- one production device retains that claimed BDF and admits only one active
  request/reset/IOTLB lifecycle; preparation returns a recoverable result,
  rejects overlap before hardware mutation, and on later validation failure
  resets status, restores the PCI command, destroys the unexposed queue and
  request DMA, and releases transport claims without consuming a session ID;
- every transport MMIO subrange is claimed once and remains backed by its BAR
  owner until that transport is destroyed;
- the fixed VirtIO block owner retains the INTx line/pin read from PCI
  configuration offset `0x3c`; the copyable route remains descriptive, while a
  one-shot masked claim and owner/epoch-checked masked/unmasked tokens form the
  transition authority. Each transition consumes the prior token, changes only
  PCI Command `INTERRUPT_DISABLE`, and returns a typed readback mismatch instead
  of leaving recoverable software state inconsistent with the observed command.
  Unmasking first requires hardware readback to agree with the token's masked
  state; unexpected unmasking is immediately remasked without advancing the
  token epoch, or poisons the root if exact recovery fails. A one-way
  fail-closed recovery masks INTx, invalidates every older token, and returns a
  new masked epoch; it can never authorize unmasking;
- queue and request DMA allocations remain in the static ledger after device
  exposure, through whole-device reset, and until IOTLB completion;
- pinned request buffers remain alive through a matching used-chain pop or an
  acknowledged whole-device reset;
- reset and IOTLB closure authority are linear, and dropping a tombstone fails
  closed by retaining owners;
- the legacy Stage 5B `Portal` keeps service actions, device completion, reset,
  and rebind fenced by its shared `cser-transition-gates::io::IoGate` identity;
- the separate production typestate owns no scope, effect, binding, or commit
  authority. It exposes reconstructible descriptive PCI/queue/token/generation
  coordinates, failure-atomic publication preflight, an infallible split
  `avail.idx` Release, exact-buffer cancellation, and prevalidated linear
  hardware intents for unpublished cancel+reset, published reset, and reset
  from each completed, pending, or failed completion-actor owner. The unified
  completion reset intent preserves the actor wrapper's exact pop state: live
  descriptors require the published `(3, 0)` DMA projection, while popped
  descriptors require `(3, 3)`. Those intents retain the real request owners,
  cannot be reconstructed from descriptive identity, return the unchanged
  owner on read-only preflight failure, and carry no scope or Registry
  operation. The facade also provides
  a prevalidated infallible reset-generation update for a registry-owned
  adapter. The legacy preparation keeps used-buffer notifications disabled,
  while `prepare_read_sector0_irq` enables them before publication. The
  hard-IRQ top half may call only
  `ack_interrupt`, which performs the sole VirtIO ISR read and returns the exact
  request identity plus a typed queue/configuration/spurious cause. It must hand
  that receipt to a task-context actor: `complete_after_interrupt` has no polling
  loop, but a ready descriptor is recycled through the DMA ledger lock and is
  therefore not hard-IRQ-safe. A non-queue cause or not-yet-ready used ring
  returns the unchanged published owner for reinsertion into the actor's slot.
  A public one-step task-context probe likewise consumes the actor-slot owner
  for one non-spinning attempt and returns it unchanged when no used entry is
  ready. Polling, IRQ delivery, and the one-step actor API use one descriptor-pop
  and response-validation implementation. Reset tombstones similarly expose a
  one-observation `probe_ack_once` for runtime-resident actors; injected or
  hardware-pending results return the exact tombstone, while the legacy bounded
  retry and the actor probe share one bus-master fence, ISR acknowledgement,
  reset acknowledgement, and queue-retirement implementation. Bounded polling
  still returns the legacy linear complete/pending/failed successor;
  notification suppression is accepted without losing the owner, while timeout,
  wrong token, pop rejection, incomplete used length, device status failure,
  and share-accounting failure all retain a reset path and record whether the
  descriptor was popped. Final IOTLB
  closure likewise uses read-only receipt validation followed by an infallible
  direct apply, so registry acknowledgement and facade `active = None` need not
  split.

## Preparation evidence boundary

The production constructor now has an owner-bound start boundary intended for
the normal Nexus adapter. The adapter first obtains a `PreparationStartPermit`
while its Registry record is still pre-apply, retains that permit while the
Registry enters hardware apply, and then consumes it. The permit exclusively
borrows the facade and PCI root and owns a process-global software preparation
gate. Every rejection before permit consumption is `NotStarted`; after
consumption the failure type has no such variant and must return either verified
rollback or `PreparationIndeterminate`. Dropping the permit or returning from
any started path releases the software gate. Attempt identity is allocated by
the unique `ProductionDevice`, is not publicly constructible, and follows every
prepared, published, reset, IOTLB, completion, and closure successor.

A successful constructor does not return a detached claim. The facade consumes
the exact `PreparedRequest`, revalidates its owner, attempt, active session, BDF,
queue, descriptor token, device generation, transport status, all three DMA
owners and active shares, and all live MMIO transport claims, and returns a
`ReceiptedPreparedRequest`. Its fixed-size, non-copyable `PreparationReceipt`
can only be borrowed while that wrapper still owns the real hardware lifecycle.
The digest is a deterministic fingerprint, not authenticity or authority.
Publication is similarly non-bypassable: the facade revalidates the complete
live projection and coupled receipt, then returns the sole
`PreparedPublishIntent` which can execute the underlying `avail.idx` Release.

Rollback evidence has two explicit generation lineages. A constructor failure
which never returned a prepared owner closes in generation `G -> G`; cancelling
a returned prepared owner requires acknowledged whole-device reset and complete
IOTLB closure and closes in `G -> G+1`. The public, non-copyable
`PreparationRollbackReceipt` is constructed only after the projected facade is
inactive and the live DMA and transport observations are exactly zero. If PCI
command/status readback, the DMA ledger, the transport-claim ledger, active
state, or generation lineage is uncertain, no rollback receipt is fabricated.
Instead the facade permanently latches the attempt as quarantined and returns a
complete read-only `PreparationIndeterminate` observation. That observation
exposes attempt and BDF, attempt/current generations, active state, every DMA
generation/exposure/reset/owner/share field, transport state, and a
hardware-certainty bit plus a domain-separated observation digest. The digest
supports comparison and durable diagnostics; it is not a MAC, capability, or
recovery authority. This crate has no API which clears that latch yet.

`cancel_prepared` and `cancel_unregistered` prove only facade ownership
transitions. They cannot inspect a semantic Registry and therefore cannot prove
that a device cohort was absent or that a reset/IOTLB acknowledgement was
causally installed. A normal enrolled adapter must retain the
`ReceiptedPreparedRequest` in its Nexus-owned slot, use `preflight_cancel`, and
couple the returned hardware plans to Registry apply. The unregistered path is
only for the failure-atomic window where the adapter independently proves under
its Registry transition gate that cohort installation never happened.

The implementation is pinned to `ostd = 0.18.0` and
`virtio-drivers = 0.13.0`. Complete DMA closure additionally requires the
repository-wide audited OSTD patch at `patches/ostd-0.18.0-cser.patch`. Split
preparation/publication additionally requires the canonical MIT
`patches/virtio-drivers-0.13.0-cser.patch` overlay (SHA-256
`7576d6810af8ff4a2d4cbcd0dc02373946031aa2e3f7ae0528b0127b5ea33762`).
Both build graphs verify the exact crates.io archives, patch hashes, clean
reverse application, installed-source equivalence, upstream tests, and source
mutation negatives. The upstream VirtIO license text is retained at
`patches/virtio-drivers-0.13.0-LICENSE-MIT`; this is not part of the MPL-2.0
OSTD overlay.

This facade lands atomically with the feature-gated Nexus sibling adapter. The
adapter reserves Registry credits before hardware work, stores each exact owner
before acknowledgement, maps the private receipts through provider-neutral
read-only views, and consumes the materialized Registry bearer only after reset
and IOTLB closure. The bounded runtime-filesystem lane therefore uses this
production typestate in the same boot under one causal root. The witness remains
polling-only with INTx masked: it does not install an OSTD `IrqLine`, execute a
real IRQ path, establish SMP safety, survive reboot, or provide a persistent
retained-worker/operator recovery loop.
In particular, registry envelopes alone do not exclude two roots claiming the
same physical function and do not prove whole-function reset blast radius; the
opaque facade owner is the singleton enforcement boundary.
