#!/usr/bin/env bash
set -euo pipefail

log=${1:?usage: assert-serial.sh KERNEL_SUFFIX_LOG}

patterns=(
    'VIRTIO_CSER KERNEL_MARKER stage=5b oracle_suffix=true'
    'VIRTIO_CSER BEGIN device=blk mode=polling irq_masked=true smp=not_proven hardware=QEMU'
    'PCI Found bdf=00:05.0 vendor=1af4 device=1042 modern=true'
    'IO WriteReject operation=write_sector0 error=ReadOnly before_add=true effects_before=0 effects_after=0 next_request_unchanged=true'
    'IO Register request=1 authority_epoch=1 binding_epoch=1 device_generation=1 operation=read_sector0'
    'FEATURES offered_required=true negotiated=0x0000000300000020 ro=true version1=true access_platform=true indirect=false event_idx=false'
    'DMA Owners queue=2 request=1 total=3 remapped=true access_platform=true'
    'DMA Owner generation=1 kind=queue_driver'
    'DMA Owner generation=1 kind=queue_device'
    'DMA Owner generation=1 kind=request'
    'IO Commit request=1 token=0 point=avail_idx_release notify_sent=false published=true'
    'IO Notify request=1 one_shot=true notify_sent=false action=kick'
    'virtio_pci_notify_write'
    'virtio_blk_handle_read'
    'IO Completion request=1 generation=1 used_len=513 status=OK duplicate_call_rejected=true'
    'IO Read magic_ok=true zero_tail=true fnv1a=0xc4b4ad9059afd22e'
    'IO Terminal request=1 state=Completed'
    'REVOKE Begin generation=1 submission_gate=closed reset_required=true'
    'REVOKE Gate request=2 state=AbortedBeforeCommit stale_publish_rejected=true register_while_closing_rejected=true'
    'RESET Pending generation=1 timeout_injected=true hardware_timeout=false retained=true'
    'REVOKE Result=TimedOut tombstone=true retained_dma_pages=3 owners_retained=true'
    'RESET Retry generation=1 ack=true bus_master=false isr_read=true terminal=Completed receipt_bound=true'
    'RESET Fence old_generation=1 new_generation=2 unterminated_effects=0'
    'IOTLB Pending generation=1 owner=request timeout_injected=true hardware_timeout=false retained_dma_pages=3 tombstone=true'
    'IOTLB Complete generation=1 owners=3 ack_before_free=true quiescence_receipt_bound=true'
    'REVOKE Quiesced generation=1 retained_dma_pages=0 dma_pages_released=3'
    'REBIND binding_epoch=2 device_generation=2 old_completion_rejected=true'
    'IO Register request=3 authority_epoch=2 binding_epoch=2 device_generation=2 operation=read_sector0'
    'DEVICE Reenable generation=2 after_quiescence=true'
    'IO Commit request=3 token=0 point=avail_idx_release notify_sent=false published=true'
    'IO Crash request=3 old_binding=2 new_binding=3 service_action_rejected=true committed_completion_raceable=true notify_sent=false late_notify_rejected=true'
    'RESET Begin generation=2 published=true notified=false whole_device=true'
    'RESET Ack generation=2 ack=true bus_master=false isr_read=true terminal=IndeterminateAfterReset receipt_bound=true'
    'RESET Fence old_generation=2 new_generation=3 terminalized_effects=1 stale_completion_rejected=true'
    'IO Terminal request=3 state=IndeterminateAfterReset cancelled=false duplicate_terminal_call_rejected=true'
    'IOTLB Complete generation=2 owners=3 ack_before_free=true quiescence_receipt_bound=true'
    'COMPLETION Fence stale_generation_rejected=true stale_binding_rejected=true duplicate_terminal_rejected=true'
    'VIRTIO_CSER PASS device_dma=true device_reset=true mediated=true iotlb_completion=true timeout_injected=true hardware_timeout=false polling=true smp=not_proven portal_type_state=true'
    'FIXTURE Hash before=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 after=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 readonly=true'
)

previous=0
for pattern in "${patterns[@]}"; do
    line=$(grep -nF -m1 "$pattern" "$log" | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo "missing Stage 5B receipt: $pattern" >&2
        exit 1
    fi
    if (( line < previous )); then
        echo "out-of-order Stage 5B receipt: $pattern" >&2
        exit 1
    fi
    previous=$line
done

if [[ $(grep -Ec 'virtio_blk_handle_read .* sector 0 nsectors 1$' "$log") -lt 1 ]]; then
    echo 'QEMU did not execute the mediated sector-0 read' >&2
    exit 1
fi
if grep -E 'virtio_blk_handle_read' "$log" | grep -Evq 'sector 0 nsectors 1$'; then
    echo 'kernel suffix contains an unexpected block read' >&2
    exit 1
fi
grep -Eq 'virtio_blk_rw_complete .* ret 0$' "$log"
grep -Eq 'virtio_blk_req_complete .* status 0$' "$log"

if ! awk '
    $1 == "DMA" && $2 == "Owner" && $3 == "generation=1" {
        split($5, paddr, "=")
        split($6, iova_field, "=")
        if (paddr[2] == iova_field[2]) {
            identity_owner = 1
        }
        owners[iova_field[2]] = 1
    }
    $1 == "vtd_dmar_translate" && $3 == "00:05.00" {
        if ($5 == $8) {
            identity_trace = 1
        }
        traced[$5] = 1
    }
    END {
        owner_count = 0
        missing = 0
        for (key in owners) {
            owner_count++
            if (!(key in traced)) {
                missing = 1
            }
        }
        exit identity_owner || identity_trace || missing || owner_count != 3
    }
' "$log"; then
    echo 'expected three distinct non-identity owner IOVAs in the 00:05.0 VT-d trace' >&2
    exit 1
fi

if [[ $(grep -cF 'vtd_inv_desc_iotlb_global' "$log") -ne 6 ]]; then
    echo 'expected exactly one global IOTLB completion chain per retained DMA page' >&2
    exit 1
fi
if [[ $(grep -cF 'vtd_inv_desc_wait_irq' "$log") -ne 6 ]]; then
    echo 'expected six ordered VT-d wait descriptors' >&2
    exit 1
fi

if ! awk '
    /REVOKE Begin generation=1/ { in_reset = 1 }
    in_reset && /virtio_set_status .* val 0$/ { saw_zero = 1 }
    /RESET Retry generation=1/ { exit !saw_zero }
    END { if (!saw_zero) exit 1 }
' "$log"; then
    echo 'generation-1 reset did not include a real status=0 write' >&2
    exit 1
fi
if ! awk '
    /RESET Begin generation=2/ { in_reset = 1 }
    in_reset && /virtio_set_status .* val 0$/ { saw_zero = 1 }
    /RESET Ack generation=2/ { exit !saw_zero }
    END { if (!saw_zero) exit 1 }
' "$log"; then
    echo 'generation-2 reset did not include a real status=0 write' >&2
    exit 1
fi

if ! awk '
    /IO Commit request=1/ { in_window = 1; next }
    /IO Completion request=1/ { in_window = 0 }
    in_window && $1 == "virtio_queue_notify" { notify_count++ }
    in_window && $1 == "virtio_pci_notify_write" { doorbell_count++ }
    END { exit notify_count != 1 || doorbell_count != 1 }
' "$log"; then
    echo 'request 1 must emit exactly one PCI doorbell and queue notify between commit and completion' >&2
    exit 1
fi

if awk '
    /IO Commit request=3/ { in_window = 1 }
    /RESET Begin generation=2/ { in_window = 0 }
    in_window && ($1 == "virtio_queue_notify" || $1 == "virtio_pci_notify_write") { found = 1 }
    END { exit !found }
' "$log"; then
    echo 'request 3 publish-without-notify window emitted a queue kick' >&2
    exit 1
fi

if ! awk '
    /RESET Retry generation=1/ { in_window = 1; next }
    /DEVICE Reenable generation=2/ { in_window = 0 }
    in_window && ($1 == "vtd_dmar_translate" || $1 == "virtio_queue_notify" || $1 == "virtio_pci_notify_write" || $1 ~ /^virtio_blk_/) {
        activity = 1
    }
    END { exit activity }
' "$log"; then
    echo 'generation 1 emitted device activity after reset acknowledgement and before re-enable' >&2
    exit 1
fi

if ! awk '
    /RESET Ack generation=2/ { in_window = 1; next }
    /FIXTURE Hash before=/ { in_window = 0 }
    in_window && ($1 == "vtd_dmar_translate" || $1 == "virtio_queue_notify" || $1 == "virtio_pci_notify_write" || $1 ~ /^virtio_blk_/) {
        activity = 1
    }
    END { exit activity }
' "$log"; then
    echo 'generation 2 emitted device activity after reset acknowledgement' >&2
    exit 1
fi

for forbidden in \
    'virtio_blk_handle_write' \
    'blk_co_pwritev' \
    'vtd_dmar_fault' \
    'panicked at' \
    'Non-resettable panic!' \
    'device_dma=false' \
    'device_reset=false' \
    'hardware_timeout=true' \
    'state=Cancelled' \
    'terminal=Cancelled' \
    'DMA free before IOTLB ack' \
    'Quiesced before reset ack'; do
    if grep -Fq "$forbidden" "$log"; then
        echo "forbidden Stage 5B evidence: $forbidden" >&2
        exit 1
    fi
done

echo 'Mediated VirtIO CSER serial/trace assertions: PASS'
