#!/usr/bin/env bash
set -euo pipefail

kernel_log=${1:?usage: assert-serial.sh KERNEL_LOG QEMU_DEBUG_LOG}
debug_log=${2:?usage: assert-serial.sh KERNEL_LOG QEMU_DEBUG_LOG}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# The kernel suffix is a serial-only receipt: after CR normalization it has no
# firmware or QEMU trace noise, so every line and its order are contractual.
# `prefix` is used only for the three runtime-addressed DMA owner records; the
# two-input AWK oracle validates their complete shape and identity mapping.
receipts=(
    'exact|VIRTIO_CSER KERNEL_MARKER stage=5b oracle_suffix=true'
    'exact|VIRTIO_CSER BEGIN device=blk mode=polling irq_masked=true smp=not_proven hardware=QEMU'
    'exact|PCI Found bdf=00:05.0 vendor=1af4 device=1042 modern=true memory_bar_owners=1'
    'exact|IO WriteReject operation=write_sector0 error=ReadOnly before_add=true effects_before=0 effects_after=0 next_request_unchanged=true'
    'exact|IO Register request=1 authority_epoch=1 binding_epoch=1 device_generation=1 operation=read_sector0'
    'exact|FEATURES offered_required=true negotiated=0x0000000300000020 ro=true version1=true access_platform=true indirect=false event_idx=false'
    'exact|DMA Owners queue=2 request=1 total=3 remapped=true access_platform=true'
    'prefix|DMA Owner generation=1 kind=queue_driver '
    'prefix|DMA Owner generation=1 kind=queue_device '
    'prefix|DMA Owner generation=1 kind=request '
    'exact|IO Commit request=1 token=0 point=avail_idx_release notify_sent=false published=true'
    'exact|IO Notify request=1 one_shot=true notify_sent=false action=kick'
    'exact|IO Completion request=1 generation=1 used_len=513 status=OK duplicate_call_rejected=true'
    'exact|IO Read magic_ok=true zero_tail=true fnv1a=0xc4b4ad9059afd22e'
    'exact|IO Terminal request=1 state=Completed'
    'exact|REVOKE Begin generation=1 submission_gate=closed reset_required=true'
    'exact|REVOKE Gate request=2 state=AbortedBeforeCommit stale_publish_rejected=true register_while_closing_rejected=true'
    'exact|RESET Pending generation=1 timeout_injected=true hardware_timeout=false retained=true'
    'exact|REVOKE Result=TimedOut tombstone=true retained_dma_pages=3 owners_retained=true'
    'exact|RESET Retry generation=1 ack=true bus_master=false isr_read=true terminal=Completed receipt_bound=true'
    'exact|RESET Fence old_generation=1 new_generation=2 unterminated_effects=0'
    'exact|IOTLB Pending generation=1 owner=request timeout_injected=true hardware_timeout=false retained_dma_pages=3 tombstone=true'
    'exact|IOTLB Complete generation=1 owners=3 ack_before_free=true quiescence_receipt_bound=true'
    'exact|REVOKE Quiesced generation=1 retained_dma_pages=0 dma_pages_released=3'
    'exact|REBIND binding_epoch=2 device_generation=2 old_completion_rejected=true'
    'exact|IO Register request=3 authority_epoch=2 binding_epoch=2 device_generation=2 operation=read_sector0'
    'exact|DEVICE Reenable generation=2 after_quiescence=true'
    'exact|IO Commit request=3 token=0 point=avail_idx_release notify_sent=false published=true'
    'exact|IO Crash request=3 old_binding=2 new_binding=3 service_action_rejected=true committed_completion_raceable=true notify_sent=false late_notify_rejected=true'
    'exact|RESET Begin generation=2 published=true notified=false whole_device=true'
    'exact|RESET Ack generation=2 ack=true bus_master=false isr_read=true terminal=IndeterminateAfterReset receipt_bound=true'
    'exact|RESET Fence old_generation=2 new_generation=3 terminalized_effects=1 stale_completion_rejected=true'
    'exact|IO Terminal request=3 state=IndeterminateAfterReset cancelled=false duplicate_terminal_call_rejected=true'
    'exact|IOTLB Complete generation=2 owners=3 ack_before_free=true quiescence_receipt_bound=true'
    'exact|COMPLETION Fence stale_generation_rejected=true stale_binding_rejected=true duplicate_terminal_rejected=true'
    'exact|VIRTIO_CSER PASS device_dma=true device_reset=true mediated=true iotlb_completion=true timeout_injected=true hardware_timeout=false polling=true smp=not_proven portal_type_state=true'
    'exact|FIXTURE Hash before=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 after=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 readonly=true'
)

previous=0
for receipt in "${receipts[@]}"; do
    mode=${receipt%%|*}
    wanted=${receipt#*|}
    matches=$(awk -v mode="$mode" -v wanted="$wanted" '
        {
            gsub(/\r/, "")
            if ((mode == "exact" && $0 == wanted) ||
                (mode == "prefix" && index($0, wanted) == 1))
                print NR
        }
    ' "$kernel_log" || true)
    count=$(awk 'NF { count++ } END { print count + 0 }' <<<"$matches")
    if [[ "$count" -ne 1 ]]; then
        echo "Stage 5B guest receipt count mismatch: expected 1, observed $count ($wanted)" >&2
        exit 1
    fi
    line=$matches
    if (( line <= previous )); then
        echo "out-of-order Stage 5B guest receipt: $wanted" >&2
        exit 1
    fi
    previous=$line
done

if [[ $(wc -l <"$kernel_log") -ne ${#receipts[@]} ]]; then
    echo "Stage 5B guest serial contains a missing or additional receipt" >&2
    exit 1
fi

for forbidden in \
    'virtio_set_status' \
    'virtio_pci_notify_write' \
    'virtio_queue_notify' \
    'virtio_blk_' \
    'vtd_dmar_' \
    'vtd_inv_desc_' \
    'panicked at' \
    'Non-resettable panic!' \
    'device_dma=false' \
    'device_reset=false' \
    'hardware_timeout=true' \
    'state=Cancelled' \
    'terminal=Cancelled' \
    'DMA free before IOTLB ack' \
    'Quiesced before reset ack'; do
    if grep -Fq "$forbidden" "$kernel_log"; then
        echo "forbidden Stage 5B guest evidence: $forbidden" >&2
        exit 1
    fi
done

awk -f "$script_dir/assert-debug-trace.awk" "$kernel_log" "$debug_log"

# Keep the independent debug oracle honest. It must reject both a missing
# IOTLB descriptor and any device activity appended after final quiescence.
mutation_dir=$(mktemp -d)
trap 'rm -rf "$mutation_dir"' EXIT
awk '
    !changed && /^vtd_inv_desc_iotlb_global / {
        changed = sub(/^vtd_inv_desc_iotlb_global/, "vtd_inv_desc_iotlb_missing")
    }
    { print }
    END { if (!changed) exit 2 }
' "$debug_log" >"$mutation_dir/missing-iotlb.log"
if awk -f "$script_dir/assert-debug-trace.awk" \
    "$kernel_log" "$mutation_dir/missing-iotlb.log" >/dev/null 2>&1; then
    echo 'Stage 5B debug oracle accepted a missing IOTLB descriptor' >&2
    exit 1
fi
cp "$debug_log" "$mutation_dir/post-quiescence-activity.log"
printf '%s\n' \
    'virtio_pci_notify_write 0x0 = 0x0 (2)' \
    >>"$mutation_dir/post-quiescence-activity.log"
if awk -f "$script_dir/assert-debug-trace.awk" \
    "$kernel_log" "$mutation_dir/post-quiescence-activity.log" >/dev/null 2>&1; then
    echo 'Stage 5B debug oracle accepted a duplicate post-quiescence notify' >&2
    exit 1
fi
cp "$debug_log" "$mutation_dir/write-trace.log"
printf '%s\n' \
    'virtio_blk_handle_write vdev 0x1 req 0x2 sector 0 nsectors 1' \
    >>"$mutation_dir/write-trace.log"
if awk -f "$script_dir/assert-debug-trace.awk" \
    "$kernel_log" "$mutation_dir/write-trace.log" >/dev/null 2>&1; then
    echo 'Stage 5B debug oracle accepted a forbidden write trace' >&2
    exit 1
fi
awk '
    /^virtio_queue_notify / {
        sub(/ vdev 0x[[:xdigit:]]+ /, " vdev 0xdeadbeef ")
    }
    { print }
' "$debug_log" >"$mutation_dir/wrong-queue-vdev.log"
if awk -f "$script_dir/assert-debug-trace.awk" \
    "$kernel_log" "$mutation_dir/wrong-queue-vdev.log" >/dev/null 2>&1; then
    echo 'Stage 5B debug oracle accepted a queue from another vdev' >&2
    exit 1
fi
awk '
    /^virtio_blk_handle_read / {
        sub(/ vdev 0x[[:xdigit:]]+ /, " vdev 0xdeadbeef ")
    }
    { print }
' "$debug_log" >"$mutation_dir/wrong-read-vdev.log"
if awk -f "$script_dir/assert-debug-trace.awk" \
    "$kernel_log" "$mutation_dir/wrong-read-vdev.log" >/dev/null 2>&1; then
    echo 'Stage 5B debug oracle accepted a read from another vdev' >&2
    exit 1
fi
awk '
    /^virtio_blk_rw_complete / {
        sub(/ req 0x[[:xdigit:]]+ /, " req 0xdeadbeef ")
    }
    { print }
' "$debug_log" >"$mutation_dir/wrong-completion-req.log"
if awk -f "$script_dir/assert-debug-trace.awk" \
    "$kernel_log" "$mutation_dir/wrong-completion-req.log" >/dev/null 2>&1; then
    echo 'Stage 5B debug oracle accepted a completion from another request' >&2
    exit 1
fi
cp "$kernel_log" "$mutation_dir/duplicate-guest-receipt.log"
grep -F -m1 \
    'IO Commit request=1 token=0 point=avail_idx_release' \
    "$kernel_log" >>"$mutation_dir/duplicate-guest-receipt.log"
if "$0" "$mutation_dir/duplicate-guest-receipt.log" "$debug_log" \
    >/dev/null 2>&1; then
    echo 'Stage 5B guest oracle accepted a duplicate commit receipt' >&2
    exit 1
fi

echo 'Mediated VirtIO CSER split serial/debug assertions: PASS cross_fd_total_order=not_claimed qemu_request_identity=bound'
