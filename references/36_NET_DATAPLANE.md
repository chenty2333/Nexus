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

- one queue-owned shared-memory dataplane buffer allocated through `zx_vmo_create_contiguous()`
- one physical-address lookup through `ax_vmo_lookup_paddr()`
- one mapped ring/buffer window through the normal VMAR map path
- one shared MMIO-style register page carrying:
  - device identity/version
  - feature bits
  - driver-accepted feature bits
  - queue-ready bits
  - notify / interrupt status
  - notify / completion counts
- three virtual interrupt objects:
  - one worker-ready interrupt
  - one TX-kick interrupt
  - one RX-complete interrupt
- one user-mode worker thread acting as a minimal device-side peer
- one driver-side thread acting as the queue owner and verifier

## Current queue shape

The current bootstrap gate uses one deliberately narrow split-ring layout:

- one TX queue
- one RX queue
- four descriptor slots per queue
- one `virtio_net_hdr`-shaped prefix plus one payload buffer per descriptor slot
- one reusable split-ring layout module instead of one fully ad-hoc smoke-local encoding

Ownership is intentionally one-writer-per-substructure:

- driver side writes:
  - TX descriptor table entry
  - TX avail ring
  - RX descriptor table entry
  - RX avail ring
- worker/device side writes:
  - TX used ring
  - RX used ring
- driver side writes the MMIO driver-ready / feature-ack state before the first kick
- worker/device side writes MMIO notify / completion state after the queue handoff
- readiness/notification uses interrupt objects rather than channels or ports in the data path

The current smoke now completes one batched transport round:

- one MMIO-style ready/feature/queue-ready handshake
- one batched TX publish over four descriptors
- one TX kick interrupt
- one batched device-side copy/completion pass
- one RX-complete interrupt
- one driver-side payload verification pass over all four packets

This is still a bootstrap slice, but it already matches the intended owner-based direction better
than treating networking as "stream socket but faster".

## What this proves

The current bootstrap slice proves three things:

1. The current public `InterruptObject` + contiguous/physical VMO surface is sufficient to drive one
   user-mode shared-memory dataplane loop with a minimal virtio-style control plane.
2. Queue-owned transport can already be exercised without inventing a kernel-resident network stack.
3. The next net step should build on queue ownership and batching, not on growing generic socket
   semantics first.

## What this is not yet

- no PCI enumeration
- no MMIO device register model
- no MSI/MSI-X or hardware IRQ routing
- no real virtio feature negotiation
- no userspace TCP/IP stack
- no RSS / multi-queue policy
- no real PCI-backed virtio transport bring-up yet

## Current guidance

- Treat the current `net_smoke` as a device-substrate proof plus one reusable transport slice, not
  as the final driver shape.
- Keep the next net cuts focused on:
  - queue ownership
  - interrupt/kick/completion batching
  - shared-memory data movement
  - eventual user-mode virtio-net queue bring-up
- Do not route future real NIC datapaths back through the current stream-socket ring as if it were
  the final network substrate.
