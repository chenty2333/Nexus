# Nexus OSTD VirtIO safe facade

`nexus-ostd-virtio` is the reusable safe boundary around the PCI, DMA, queue,
reset, and IOTLB substrate first exercised by the separate-boot Stage 5B
experiment. Its crate root denies unsafe code; only the private `pci`, `dma`,
and `portal` modules receive local allowances. Downstream crates cannot name
the raw HAL, raw PCI root, raw MMIO pointers, or DMA owners.

The facade preserves these ownership invariants:

- one opaque `Root` owns the discovered block device and all acquired memory
  BARs, and grants exactly one portal claim;
- every transport MMIO subrange is claimed once and remains backed by its BAR
  owner until that transport is destroyed;
- queue and request DMA allocations remain in the static ledger after device
  exposure, through whole-device reset, and until IOTLB completion;
- pinned request buffers remain alive through a matching used-chain pop or an
  acknowledged whole-device reset;
- reset and IOTLB closure authority are linear, and dropping a tombstone fails
  closed by retaining owners;
- service actions, device completion, reset, and rebind are fenced by the
  shared `cser-transition-gates::io::IoGate` identity.

The implementation is pinned to `ostd = 0.18.0` and
`virtio-drivers = 0.13.0`. Complete DMA closure additionally requires the
audited OSTD patch at
`experiments/ostd-virtio-cser-spike/patches/ostd-0.18.0-dma-closure.patch`;
the experiment Docker build verifies that patch against the exact crates.io
archive before compiling this crate.

This crate is extraction and equivalence infrastructure. Its existence does
not prove same-boot use by `nexus-kernel`, a real IRQ path, SMP safety, or
production causal-identity preservation.
