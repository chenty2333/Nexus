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

This crate is source/build substrate. It does not install an OSTD `IrqLine` or
prove that `nexus-kernel` uses the production typestate in the same boot,
executes a real IRQ path, is SMP-safe, or preserves one causal identity through
the production registry.
In particular, registry envelopes alone do not exclude two roots claiming the
same physical function and do not prove whole-function reset blast radius; the
opaque facade owner is the singleton enforcement boundary.
