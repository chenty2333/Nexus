#!/usr/bin/env bash
set -euo pipefail

log=${1:?usage: assert-serial.sh COMBINED_QEMU_LOG}

patterns=(
    'DMA_CLOSURE BEGIN ostd=0.18.0 device_dma=false reset=false scope=single_coherent'
    'DMA_CLOSURE Boundary api=one_page begin_bounded=true poll_bounded=true iommu_lock_wait=false init_handshake_sync=true smp=not_proven'
    'DMA_CLOSURE Alloc remapped=true'
    'DMA_CLOSURE Begin pte_removed=true iotlb_submitted=true owner_retained=true'
    'DMA_CLOSURE Pending injected=true result=Pending owner_retained=true iova_retained=true backing_retained=true credit_retained=true'
    'DMA_CLOSURE Ack observed=true iotlb_complete=true iova_freed=true paddr_tracking_released=true'
    'DMA_CLOSURE BackingDrop after_ack=true'
    'DMA_CLOSURE IrqGuard paired=true begin_return=true pending_return=true completion_return=true backing_drop=true'
    'DMA_CLOSURE IovaReuse same_size=true'
    'DMA_CLOSURE PASS queued_iotlb=true wait_completion=true pending_owner=true iova_reuse=true device_dma=false device_reset=false'
)

previous=0
for pattern in "${patterns[@]}"; do
    line=$(grep -nF -m1 "$pattern" "$log" | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo "missing serial assertion: $pattern" >&2
        exit 1
    fi
    if (( line < previous )); then
        echo "out-of-order serial assertion: $pattern" >&2
        exit 1
    fi
    previous=$line
done

if [[ $(grep -cF 'DMA_CLOSURE Pending injected=true result=Pending' "$log") -ne 1 ]]; then
    echo 'the injected Pending result was not observed exactly once' >&2
    exit 1
fi
if [[ $(grep -cF 'DMA_CLOSURE Ack observed=true iotlb_complete=true' "$log") -ne 1 ]]; then
    echo 'the ownership-carrying invalidation did not complete exactly once' >&2
    exit 1
fi
if [[ $(grep -cF 'vtd_inv_desc_iotlb_global' "$log") -lt 2 ]]; then
    echo 'QEMU did not observe both queued global IOTLB invalidations' >&2
    exit 1
fi
if [[ $(grep -cF 'vtd_inv_desc_wait_irq' "$log") -lt 2 ]]; then
    echo 'QEMU did not process both ordered wait descriptors' >&2
    exit 1
fi
if ! grep -Eq 'DMA_CLOSURE IovaReuse same_size=true old=0x[0-9a-f]+ new=0x[0-9a-f]+ reused=true' "$log"; then
    echo 'IOVA reuse receipt is malformed' >&2
    exit 1
fi

for forbidden in \
    'IOMMU engine entered a retained failure state' \
    'panicked at' \
    'Non-resettable panic!' \
    'device_dma=true' \
    'device_reset=true'; do
    if grep -Fq "$forbidden" "$log"; then
        echo "forbidden evidence: $forbidden" >&2
        exit 1
    fi
done

echo 'DMA closure serial/trace assertions: PASS'
