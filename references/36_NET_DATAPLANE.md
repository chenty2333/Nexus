# 36 - net dataplane

Part of the Axle transport and device-facing runtime substrate.

See also:
- `35_IPC_SOCKET.md` - current stream/datagram socket object shape and current socket limits
- `43_VM_EXEC_PAGER_DEVICE_VM.md` - current device-facing interrupt / physical / contiguous VMO surface
- `32_SCHEDULER_LIFECYCLE.md` - owner-local wakeup and per-CPU runnable substrate used by later queue ownership
- `90_CONFORMANCE.md` - bootstrap runtime scenario coverage

## Scope

This file describes the current narrow network-dataplane bootstrap shape in the repository.

It is not yet a full PCI transport or a generic production netstack.
It now covers two concrete slices:
- one synthetic/bootstrap queue-owned shared-memory dataplane
- one first real QEMU `virtio-net-pci` bring-up path used by the remote-shell bootstrap
Both prove that the current device-facing Axle substrate is already enough to support a
queue-owned shared-memory + interrupt dataplane in ring3 through one kernel-exported device
contract.

## Current transport slice

The repository now includes one narrow ring3 net dataplane slice built around one reusable
`axle-virtio-transport` `no_std` crate plus three current userspace consumers:

- `user/test-runner` `net_smoke`
- `user/nexus-init` `boot://root-net-dataplane`
- `user/nexus-init` `boot://root-starnix-net-shell`

The current bootstrap transport includes:

- one bootstrap `PciDevice` handle seeded by the kernel into the runner shared-slot window
- one generic PCI resource discovery step through:
  - `ax_pci_device_get_resource_count()`
  - `ax_pci_device_get_resource()`
  - one config resource carrying MMIO + read-only flags and suggested map options
  - one BAR0 resource carrying MMIO flags and suggested map options
  - one interrupt resource per queue pair and per interrupt group
- one config resource export then reinterpreted as the synthetic PCI config-space window:
  - MMIO + read-only flags
  - map options used for the config alias mapping
  - virtio-style capability discovery for BAR0/common/notify/isr/device regions
- one BAR0 VMO exported from that same generic resource path, plus BAR MMIO metadata
- one interrupt-object export per queue pair and per interrupt group, plus interrupt mode/vector
  metadata carried through that same generic resource path
- one interrupt-mode capability query through `ax_pci_device_get_interrupt_mode()`:
  - supported / active / triggerable flags
  - base vector
  - vector count
- one synthetic MSI/restore round-trip before the data path starts:
  - ring3 queries `MSI` capability metadata
  - ring3 selects `MSI`
  - ring3 re-fetches one interrupt handle and verifies the object metadata now reports
    `ZX_INTERRUPT_MODE_MSI` and no triggerable flag
  - ring3 then switches back to `VIRTUAL` before driving the current bootstrap transport
- one shared queue/buffer window allocated through `zx_vmo_create_contiguous()`
- one explicit `DmaRegion` lifetime object over:
  - the queue memory
  - the exported BAR0 VMO
- both current DMA-region creations now also freeze one first DMA-permission shape:
  - `DEVICE_READ`
  - `DEVICE_WRITE`
- one DMA-region address lookup through `ax_dma_region_lookup_iova()` rather than one raw
  `ax_vmo_lookup_paddr()` handoff
- one DMA-region metadata query through `ax_dma_region_get_info()`:
  - size in bytes
  - DMA-permission bits
  - identity-IOVA / physical-contiguity flags
  - coalesced segment count
  - base physical / device-visible addresses
- one DMA-region segment query through `ax_dma_region_get_segment()` for segment `0` on both BAR0
  and queue memory:
  - the current bootstrap transport pins exactly one segment for each of those regions
  - the driver/device pair now treats that returned segment IOVA as the programmed queue/control
    address instead of assuming "base IOVA == whole region truth"
- driver mapping of the BAR0 window now uses the BAR-exported VM map options and therefore
  explicitly requests `ZX_VM_MAP_MMIO`
- driver mapping of the synthetic PCI config window also uses `ZX_VM_MAP_MMIO`
- the driver now explicitly switches the bootstrap device into `VIRTUAL` interrupt mode before it
  starts consuming queue interrupts
- one second mapping of that same BAR0 export is used by the synthetic device-side worker
- one BAR0 register window now carries one first narrow virtio-style common-config shape:
  - device identity/version
  - device feature bits plus driver-accepted feature bits
  - device status
  - queue-select
  - selected-queue size / enable / notify-off view
  - selected-queue desc / avail / used DMA addresses
- one queue-state array behind that common-config view now carries:
  - per-queue ready state
  - last notify value
  - interrupt status
  - notify / completion counts
  - programmed TX/RX desc / avail / used DMA addresses
- two queue-local virtual interrupt triplets:
  - one worker-ready interrupt per queue pair
  - one TX-kick interrupt per queue pair
  - one RX-complete interrupt per queue pair
- the driver now also validates the exported interrupt handles through `interrupt_get_info()`:
  - exported PCI interrupt metadata and object metadata must agree on mode/vector
  - the current bootstrap transport requires those interrupt objects to be triggerable
- two user-mode worker threads acting as minimal device-side peers
- one driver-side thread acting as the queue owner and verifier
- one `nexus-init` root bring-up path that consumes the same synthetic PCI-shaped export through
  the normal bootstrap resolver / root-manifest flow instead of one runner-only entrypoint
- one narrow kernel-exported device-resource discovery step:
  - vendor/device/class fields
  - BAR count, queue-pair count, and queue size metadata
  - generic resource enumeration
  - config/BAR/interrupt handle export through that generic resource path
- one first real-device follow-on now also exists when QEMU exposes `virtio-net-pci`:
  - the kernel discovers the first x86 network PCI function during bootstrap
  - the kernel seeds one second bootstrap `PciDevice` handle carrying:
    - one read-only config snapshot
    - one BAR export per discovered MMIO window
  - userspace enables `MEMORY_SPACE | BUS_MASTER` through `ax_pci_device_set_command()`
  - `nexus-init` then drives the device through a smoltcp-backed userspace transport path
    suitable for the current host-forwarded remote shell slice

## Current queue shape

The current bootstrap gate uses one deliberately narrow split-ring layout:

- two queue pairs
- one TX queue and one RX queue per pair
- four descriptor slots per queue
- one `virtio_net_hdr`-shaped prefix plus one payload buffer per descriptor slot
- one reusable split-ring layout module instead of one fully ad-hoc smoke-local encoding

Ownership is intentionally one-writer-per-substructure:

- driver side writes:
  - every TX descriptor table entry
  - every TX avail ring
  - every RX descriptor table entry
  - every RX avail ring
  - the BAR0 common-config state
- worker/device side writes:
  - the TX used ring for its owned queue pair
  - the RX used ring for its owned queue pair
  - the queue-state runtime counters for its owned TX/RX queues
- driver side now performs one first narrow virtio-style bring-up sequence before the first kick:
  - accept features
  - set `ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK`
  - select each TX/RX queue in BAR0
  - program desc / avail / used DMA addresses for that selected queue
  - enable the selected queue
- worker/device side consumes those programmed queue DMA addresses rather than relying on one fixed
  shared-memory offset convention
- readiness/notification uses interrupt objects rather than channels or ports in the data path

The current smoke now completes one batched transport round:

- one `PciDevice` info query plus BAR0 export
- one virtio-style feature/status/queue-select bring-up handshake over BAR0
- one four-packet TX publish on each queue pair
- one TX kick interrupt per queue pair
- one batched device-side copy/completion pass per queue pair
- one RX-complete interrupt per queue pair
- one driver-side payload verification pass over all eight packets

This is still a bootstrap slice, but it already matches the intended owner-based direction better
than treating networking as "stream socket but faster".

## What this proves

The current bootstrap slice proves three things:

1. The current public `InterruptObject` + contiguous/physical VMO surface is sufficient to drive one
   user-mode shared-memory dataplane loop with one kernel-exported device handle, one BAR0
   register window, and one first narrow public MMIO mapping attribute bit.
2. Queue-owned multi-queue transport can already be exercised through one first narrow user-mode
   virtio-style bring-up path without inventing a kernel-resident network stack.
3. The current `DmaRegion` object is already enough to express one explicit DMA lifetime contract
   for queue memory and driver-visible control windows, and the driver/device pair can now pass
   queue ownership through explicit programmed DMA addresses instead of one fully synthetic offset
   convention; the next device/net cuts should build on that object rather than on ad-hoc physical
   address helpers.
4. The current bootstrap `PciDevice` contract is now explicit enough for ring3 code to validate
   interrupt delivery mode capabilities before it starts treating exported queue interrupts as one
   usable transport substrate.
5. Ring3 code can now discover the transport through a PCI-shaped config export first and only then
   map BAR0, which is closer to the eventual user-mode virtio-net bring-up than the earlier direct
   BAR0-only smoke.
6. The transport is no longer trapped inside one smoke-only binary. `nexus-init` can now consume
   the same transport crate and bootstrap device export as one root component, which means the
   current user-mode virtio-style path is becoming system substrate rather than only test harness.
7. The current device-memory contract is no longer just "lookup one paddr and hope." The bootstrap
   net path now proves that ring3 can discover a device through generic PCI resources, select an
   interrupt mode, and then program queue/control addresses from explicit `DmaRegion` segment
   metadata.
8. The device-facing substrate is no longer limited to one synthetic transport-only proof.
   The current remote-shell slice proves that the same public `PciDevice` / BAR / DMA / MMIO
   contract is already enough to bring up one real QEMU `virtio-net-pci` function in userspace.

## What this is not yet

- no PCI bus enumeration
- no real PCI config space or BAR management contract from the kernel
- no generic PCI enumeration yet; current discovery is still "first matching network function"
- no broad config-space read/write ABI yet; only one narrow command-register write helper plus the
  exported read-only snapshot
- no MMIO cache-policy / mapping-attribute controls beyond the first narrow `ZX_VM_MAP_MMIO` bit
- only one first narrow identity-like IOVA contract exists; the next step is still a fuller
  DMA map/unmap or IOVA-token model beyond the current explicit `DmaRegion`
- no hardware interrupt routing or MSI/MSI-X programming surface yet; the current MSI/legacy/MSI-X
  mode handling is still metadata/activation scaffolding rather than real hardware delivery
- no full virtio PCI capability layout or generic config-space ABI
- no general reusable userspace TCP/IP stack beyond the current smoltcp-backed remote-shell slice
- no RSS / scheduler-domain queue placement policy
- no generic multi-device or driver-manager-owned real virtio-net bring-up yet

## Current guidance

- Treat the current `net_smoke` as a device-substrate proof plus one reusable transport slice, not
  as the final driver shape.
- Keep the next net cuts focused on:
  - moving from the current "synthetic bootstrap device + first discovered real function" shape to
    a fuller PCI resource model
  - keeping queue memory and control windows on explicit `DmaRegion` lifetime objects
  - keeping the current common-config / queue-select bring-up path aligned with later real
    virtio-net transport work instead of growing more smoke-local control-plane shortcuts
  - queue ownership
  - interrupt/kick/completion batching
  - shared-memory data movement
  - eventual user-mode virtio-net queue bring-up
- Do not route future real NIC datapaths back through the current stream-socket ring as if it were
  the final network substrate.
