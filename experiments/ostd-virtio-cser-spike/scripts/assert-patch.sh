#!/usr/bin/env bash
set -euo pipefail

virtio_sha=cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7
virtio_archive=${NEXUS_VIRTIO_ARCHIVE:-/opt/nexus-source/virtio-drivers-0.13.0.crate}
virtio_patched=${NEXUS_VIRTIO_PATCHED_ROOT:-/opt/nexus-virtio/virtio-drivers-0.13.0}
patched=${NEXUS_OSTD_PATCHED_ROOT:-/opt/nexus-ostd/ostd-0.18.0}
facade_root=${NEXUS_OSTD_VIRTIO_FACADE_ROOT:-/crates/nexus-ostd-virtio}

if [[ -f /repo/patches/ostd-0.18.0-cser.patch ]]; then
    canonical_patch=/repo/patches/ostd-0.18.0-cser.patch
    canonical_assert=/repo/tools/ostd/assert-cser-patch.sh
    virtio_patch=/repo/patches/virtio-drivers-0.13.0-cser.patch
    virtio_assert=/repo/tools/virtio/assert-cser-patch.sh
    production_assert=/repo/tools/virtio/assert-production-substrate.sh
else
    canonical_patch=/tmp/nexus-patches/ostd-0.18.0-cser.patch
    canonical_assert=/usr/local/bin/assert-ostd-cser-patch
    virtio_patch=/tmp/nexus-patches/virtio-drivers-0.13.0-cser.patch
    virtio_assert=/usr/local/bin/assert-virtio-cser-patch
    production_assert=/usr/local/bin/assert-production-virtio-substrate
fi

"$canonical_assert" "$canonical_patch" "$patched"
"$virtio_assert" "$virtio_patch" "$virtio_patched"
"$production_assert" \
    "$facade_root/src/production.rs" \
    "$facade_root/src/lib.rs" \
    "$facade_root/src/portal.rs"
echo "$virtio_sha  $virtio_archive" | sha256sum -c - >/dev/null
cmp /work/LICENSE-MPL-2.0 /opt/nexus-ostd/LICENSE-MPL-2.0 >/dev/null

coherent=$patched/src/mm/dma/dma_coherent.rs
grep -Fq 'dma.as_non_null_ptr_exclusive()' "$facade_root/src/dma.rs"
if grep -Fq 'dma.writer().cursor()' "$facade_root/src/dma.rs"; then
    echo 'Nexus bypasses the owner-bound exclusive raw DMA API' >&2
    exit 1
fi
grep -Fq 'retain this `DmaCoherent` owner for the entire pointer' "$coherent"
grep -Fq 'overlapping access through `VmReader`, `VmWriter`' "$coherent"
grep -Fq 'Raw access must stop before DMA teardown' "$coherent"

io_mem=$patched/src/io/io_mem/mod.rs
grep -Fq 'The pointer is owner-bound: it does not keep the mapping' "$io_mem"
grep -Fq 'The caller must retain this `IoMem` owner for every use' "$io_mem"
grep -Fq 'overlapping alias access through this pointer' "$io_mem"

queue_source=$(<"$virtio_patched/src/queue.rs")
hal_source=$(<"$virtio_patched/src/hal.rs")
publish_block=$(sed -n '/fn publish_prepared_in_place/,/^    }/p' <<<"$queue_source")
fence_line=$(grep -nF 'fence(Ordering::SeqCst);' <<<"$publish_block" | cut -d: -f1)
store_line=$(grep -nF '.store(self.avail_idx, Ordering::Release);' \
    <<<"$publish_block" | cut -d: -f1)
test -n "$fence_line"
test -n "$store_line"
test "$fence_line" -lt "$store_line"

grep -Fq 'virtio-drivers = { version = "=0.13.0", default-features = false }' \
    "$facade_root/Cargo.toml"
grep -Fq 'layout: VirtQueueLayout<H>,' <<<"$queue_source"
if grep -Fq 'Drop for VirtQueue' <<<"$queue_source"; then
    echo 'pinned VirtQueue gained an explicit Drop implementation' >&2
    exit 1
fi
dma_drop=$(sed -n '/impl<H: Hal> Drop for Dma<H>/,/^}/p' <<<"$hal_source")
grep -Fq 'H::dma_dealloc(self.paddr, self.vaddr, self.pages)' <<<"$dma_drop"
if grep -Fq 'H::unshare' <<<"$dma_drop"; then
    echo 'queue DMA Drop unexpectedly accesses request-share state' >&2
    exit 1
fi

echo 'OSTD/VirtIO source assertions: PASS canonical_ostd_patch=shared canonical_virtio_patch=shared owner_bound_dma_mmio=true split_avail_idx_release=true reset_abandon_drop=true'
