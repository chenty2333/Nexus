# 36 - net dataplane

Part of the Axle transport and device-facing runtime substrate.

See also:
- `35_IPC_SOCKET.md` - current stream/datagram socket object shape and current socket limits
- `43_VM_EXEC_PAGER_DEVICE_VM.md` - current device-facing interrupt / physical / contiguous VMO surface
- `32_SCHEDULER_LIFECYCLE.md` - owner-local wakeup and per-CPU runnable substrate used by later queue ownership
- `90_CONFORMANCE.md` - bootstrap runtime scenario coverage

## Scope

This file describes the current narrow network-dataplane bootstrap shape in the repository.

It is not yet a full PCI transport, a full virtio-net driver, or a full userspace netstack.
It is the first proof that the current device-facing Axle substrate is already enough to support a
queue-owned shared-memory + interrupt dataplane in ring3.

## Current transport slice

The repository now includes one narrow ring3 `net_smoke` path built around one reusable
`virtio_net_transport` slice in `user/test-runner` with:

- one shared queue/buffer window allocated through `zx_vmo_create_contiguous()`
- one dedicated register-backing page allocated through `zx_vmo_create_contiguous()`
- one dedicated PCI-shaped config page allocated through `zx_vmo_create_contiguous()`
- one explicit `DmaRegion` lifetime object over:
  - the queue memory
  - the PCI config page
  - the register page
  - the driver-visible BAR0 physical alias
- one DMA-region address lookup through `ax_dma_region_lookup_paddr()` rather than one raw
  `ax_vmo_lookup_paddr()` handoff
- one driver-side physical alias VMO over the PCI-shaped config page
- one driver-side BAR0 physical VMO created only after reading that config page
- driver mappings of the config alias and BAR0 window now request `ZX_VM_MAP_MMIO`
- one device-side config/register backing mapping through the original contiguous VMOs
- one MMIO-style control page carrying:
  - device identity/version
  - feature bits plus driver-accepted feature bits
  - queue-pair count and stride metadata
  - one queue-local control block per queue pair for:
    - ready bits
    - last notify value
    - interrupt status
    - notify / completion counts
- two queue-local virtual interrupt triplets:
  - one worker-ready interrupt per queue pair
  - one TX-kick interrupt per queue pair
  - one RX-complete interrupt per queue pair
- two user-mode worker threads acting as minimal device-side peers
- one driver-side thread acting as the queue owner and verifier
- one synthetic PCI-shaped discovery step:
  - vendor/device/class fields
  - BAR0 physical address and size
  - queue-pair count and queue size metadata

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
  - the global MMIO header
- worker/device side writes:
  - the TX used ring for its owned queue pair
  - the RX used ring for its owned queue pair
  - the MMIO queue-local control block for its owned queue pair
- driver side writes the MMIO driver-ready / feature-ack state before the first kick
- readiness/notification uses interrupt objects rather than channels or ports in the data path

The current smoke now completes one batched transport round:

- one PCI-shaped config read plus BAR0 discovery
- one MMIO-style ready/feature/queue-ready handshake
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
   user-mode shared-memory dataplane loop with one PCI-shaped config page, one BAR0 register
   window, and one first narrow public MMIO mapping attribute bit.
2. Queue-owned multi-queue transport can already be exercised without inventing a kernel-resident
   network stack.
3. The current `DmaRegion` object is already enough to express one explicit DMA lifetime contract
   for queue memory and driver-visible control windows; the next device/net cuts should build on
   that object rather than on ad-hoc physical-address helpers.

## What this is not yet

- no PCI bus enumeration
- no real PCI config space or BAR management contract from the kernel
- no public PCI resource-export contract yet
- no MMIO cache-policy / mapping-attribute controls beyond the first narrow `ZX_VM_MAP_MMIO` bit
- no DMA map/unmap or IOVA model yet
- no MSI/MSI-X or hardware IRQ routing
- no real virtio feature negotiation
- no userspace TCP/IP stack
- no RSS / scheduler-domain queue placement policy
- no real PCI-backed virtio transport bring-up yet

## Current guidance

- Treat the current `net_smoke` as a device-substrate proof plus one reusable transport slice, not
  as the final driver shape.
- Keep the next net cuts focused on:
  - moving from the current synthetic PCI-shaped config page to a real PCI-backed config source
  - keeping queue memory and control windows on explicit `DmaRegion` lifetime objects
  - queue ownership
  - interrupt/kick/completion batching
  - shared-memory data movement
  - eventual user-mode virtio-net queue bring-up
- Do not route future real NIC datapaths back through the current stream-socket ring as if it were
  the final network substrate.
