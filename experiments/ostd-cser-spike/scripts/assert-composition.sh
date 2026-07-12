#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

composition_log=${1:?usage: assert-composition.sh OSTD_SERIAL_LOG VIRTIO_KERNEL_LOG}
virtio_log=${2:?usage: assert-composition.sh OSTD_SERIAL_LOG VIRTIO_KERNEL_LOG}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

awk -f "$script_dir/assert-composition.awk" "$composition_log"

patterns=(
    'VIRTIO_CSER KERNEL_MARKER stage=5b oracle_suffix=true'
    'IO Register request=1 authority_epoch=1 binding_epoch=1 device_generation=1 operation=read_sector0'
    'IO Commit request=1 token=0 point=avail_idx_release notify_sent=false published=true'
    'IO Completion request=1 generation=1 used_len=513 status=OK duplicate_call_rejected=true'
    'IO Terminal request=1 state=Completed'
    'RESET Pending generation=1 timeout_injected=true hardware_timeout=false retained=true'
    'REVOKE Result=TimedOut tombstone=true retained_dma_pages=3 owners_retained=true'
    'RESET Retry generation=1 ack=true bus_master=false isr_read=true terminal=Completed receipt_bound=true'
    'RESET Fence old_generation=1 new_generation=2 unterminated_effects=0'
    'IOTLB Pending generation=1 owner=request timeout_injected=true hardware_timeout=false retained_dma_pages=3 tombstone=true'
    'IOTLB Complete generation=1 owners=3 ack_before_free=true quiescence_receipt_bound=true'
    'REVOKE Quiesced generation=1 retained_dma_pages=0 dma_pages_released=3'
    'REBIND binding_epoch=2 device_generation=2 old_completion_rejected=true'
    'IO Register request=3 authority_epoch=2 binding_epoch=2 device_generation=2 operation=read_sector0'
    'IO Commit request=3 token=0 point=avail_idx_release notify_sent=false published=true'
    'IO Crash request=3 old_binding=2 new_binding=3 service_action_rejected=true committed_completion_raceable=true notify_sent=false late_notify_rejected=true'
    'RESET Fence old_generation=2 new_generation=3 terminalized_effects=1 stale_completion_rejected=true'
    'IOTLB Complete generation=2 owners=3 ack_before_free=true quiescence_receipt_bound=true'
    'VIRTIO_CSER PASS device_dma=true device_reset=true mediated=true iotlb_completion=true timeout_injected=true hardware_timeout=false polling=true smp=not_proven portal_type_state=true'
)

previous=0
for pattern in "${patterns[@]}"; do
    line=$(grep -nF -m1 "$pattern" "$virtio_log" | cut -d: -f1 || true)
    if [[ -z "$line" ]]; then
        echo "composition/VirtIO adapter missing Stage 5B evidence: $pattern" >&2
        exit 1
    fi
    if (( line < previous )); then
        echo "composition/VirtIO adapter evidence out of order: $pattern" >&2
        exit 1
    fi
    previous=$line
done

require_count() {
    local expected=$1
    local pattern=$2
    local actual
    actual=$(grep -cF "$pattern" "$virtio_log" || true)
    if [[ "$actual" -ne "$expected" ]]; then
        echo "composition/VirtIO adapter count mismatch: expected $expected, observed $actual ($pattern)" >&2
        exit 1
    fi
}

require_count 2 'point=avail_idx_release notify_sent=false published=true'
require_count 1 'IO Register request=1 authority_epoch=1 binding_epoch=1 device_generation=1 operation=read_sector0'
require_count 1 'IO Completion request=1 generation=1 used_len=513 status=OK duplicate_call_rejected=true'
require_count 1 'IO Terminal request=1 state=Completed'
require_count 1 'RESET Pending generation=1 timeout_injected=true hardware_timeout=false retained=true'
require_count 1 'REVOKE Result=TimedOut tombstone=true retained_dma_pages=3 owners_retained=true'
require_count 1 'RESET Retry generation=1 ack=true bus_master=false isr_read=true terminal=Completed receipt_bound=true'
require_count 1 'IO Register request=3 authority_epoch=2 binding_epoch=2 device_generation=2 operation=read_sector0'
require_count 1 'IO Crash request=3 old_binding=2 new_binding=3 service_action_rejected=true committed_completion_raceable=true notify_sent=false late_notify_rejected=true'
require_count 1 'RESET Fence old_generation=2 new_generation=3 terminalized_effects=1 stale_completion_rejected=true'
require_count 1 'IOTLB Complete generation=1 owners=3 ack_before_free=true quiescence_receipt_bound=true'
require_count 1 'IOTLB Complete generation=2 owners=3 ack_before_free=true quiescence_receipt_bound=true'
require_count 1 'VIRTIO_CSER PASS device_dma=true device_reset=true mediated=true iotlb_completion=true timeout_injected=true hardware_timeout=false polling=true smp=not_proven portal_type_state=true'

echo 'composition + external Stage 5B VirtIO component-consistency assertions: PASS identity_preserving=false'
