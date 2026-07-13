#!/usr/bin/env bash
set -euo pipefail

tmp=
archive=/opt/nexus-source/ostd-0.18.0.crate
if [[ -f $archive ]]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    tar -xzf "$archive" -C "$tmp"
    source_root=$tmp/ostd-0.18.0/src/mm/dma/util.rs
else
    source_root=$(find "${CARGO_HOME:-/root/.cargo}/registry/src" \
        -path '*/ostd-0.18.0/src/mm/dma/util.rs' -print -quit)
fi
if [[ -z ${source_root:-} || ! -f $source_root ]]; then
    echo "pinned pristine OSTD 0.18.0 source is unavailable" >&2
    exit 1
fi

if ! grep -Fq 'FIXME: Flush IOTLBs to prevent any future DMA access to the frames.' "$source_root"; then
    echo "expected OSTD 0.18.0 IOTLB gap marker is absent; re-audit the adapter" >&2
    exit 1
fi

unmap_body=$(sed -n '/^fn unmap_dma_remap/,/^}/p' "$source_root")
if ! grep -Fq 'TODO: Free `da_range`' <<<"$unmap_body"; then
    echo "expected fail-safe no-free TODO is absent; re-audit IOVA lifetime" >&2
    exit 1
fi
if grep -Eq 'daddr_allocator.*free|\.free\(' <<<"$unmap_body"; then
    echo "the unmap path now frees IOVA space; re-audit reuse after invalidation" >&2
    exit 1
fi

iommu_mod=${source_root%/mm/dma/util.rs}/arch/x86/mod.rs
if ! grep -Eq 'pub\(crate\)[[:space:]]+mod[[:space:]]+iommu' "$iommu_mod"; then
    echo "OSTD IOMMU visibility changed; re-audit whether an external adapter is now possible" >&2
    exit 1
fi

descriptor_mod=${source_root%/mm/dma/util.rs}/arch/x86/iommu/invalidate/descriptor/mod.rs
if grep -Eqi 'struct[[:space:]]+.*iotlb|iotlb.*descriptor' "$descriptor_mod"; then
    echo "queued IOTLB descriptor support appeared; re-audit the fail-closed adapter" >&2
    exit 1
fi

registers_mod=${source_root%/mm/dma/util.rs}/arch/x86/iommu/registers/mod.rs
global_body=$(sed -n '/^    fn global_invalidation/,/^    }/p' "$registers_mod")
if ! grep -Fq 'iotlb_invalidate' <<<"$global_body"; then
    echo "register-based IOTLB code moved; re-audit completion semantics" >&2
    exit 1
fi
after_iotlb_write=$(sed -n '/iotlb_invalidate/,$p' <<<"$global_body")
if grep -Eq 'while|completion_status|IVT.*set to 0' <<<"$after_iotlb_write"; then
    echo "register IOTLB path gained a completion wait; re-audit the adapter" >&2
    exit 1
fi

echo "IOTLB pristine-source probe: PASS (no IOVA free; no unmap flush; register path has no completion wait; no queued IOTLB descriptor; API is crate-private; runtime_adapter=fail_closed)"
