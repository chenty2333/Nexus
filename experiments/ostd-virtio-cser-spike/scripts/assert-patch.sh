#!/usr/bin/env bash
set -euo pipefail

expected_sha=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
archive=/opt/nexus-source/ostd-0.18.0.crate
virtio_sha=cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7
virtio_archive=/opt/nexus-source/virtio-drivers-0.13.0.crate
patched=/opt/nexus-ostd/ostd-0.18.0
patch_file=/work/patches/ostd-0.18.0-dma-closure.patch
facade_root=${NEXUS_OSTD_VIRTIO_FACADE_ROOT:-/crates/nexus-ostd-virtio}

echo "$expected_sha  $archive" | sha256sum -c - >/dev/null
echo "$virtio_sha  $virtio_archive" | sha256sum -c - >/dev/null
test -d "$patched"
cmp /work/LICENSE-MPL-2.0 /opt/nexus-ostd/LICENSE-MPL-2.0 >/dev/null
patch --batch --dry-run --reverse -d "$patched" -p1 < "$patch_file" >/dev/null

begin_block=$(sed -n \
    '/^pub(crate) fn begin_unmap_invalidate/,/^pub(crate) fn poll_unmap_invalidate/p' \
    "$patched/src/arch/x86/iommu/mod.rs")
grep -Fq 'daddr: Daddr' <<<"$begin_block"
grep -Fq 'irq::disable_local()' <<<"$begin_block"
if grep -Fq 'arch::irq' "$patched/src/arch/x86/iommu/mod.rs"; then
    echo 'single-page begin imported the raw non-RAII architecture IRQ API' >&2
    exit 1
fi
grep -Fq 'unmap(daddr)' <<<"$begin_block"
grep -Fq '.submit_dma_invalidation(ticket)' <<<"$begin_block"
if grep -Eq '^[[:space:]]*(while|loop)[[:space:]{]' <<<"$begin_block"; then
    echo 'single-page begin contains an unbounded loop' >&2
    exit 1
fi

register_runtime=$(sed -n \
    '/pub(super) fn reap_completed_invalidation/,/fn write_global_command/p' \
    "$patched/src/arch/x86/iommu/registers/mod.rs")
if grep -Eq '^[[:space:]]*(while|loop)[[:space:]{]' <<<"$register_runtime"; then
    echo 'runtime invalidation waits while the IOMMU register API is active' >&2
    exit 1
fi
grep -Fq 'InvalidationPath::Queued' <<<"$register_runtime"
grep -Fq 'InvalidationPath::DmaRegister' <<<"$register_runtime"
grep -Fq 'Ordering::Release' "$patched/src/arch/x86/iommu/registers/mod.rs"

coherent="$patched/src/mm/dma/dma_coherent.rs"
grep -Fq 'self.size(),' "$coherent"
grep -Fq 'PAGE_SIZE,' "$coherent"
grep -Fq 'pub fn poll_complete(mut self) -> Result<UnmappedDma, Self>' "$coherent"
grep -Fq 'pub fn stage5a_local_irq_enabled() -> bool' "$coherent"
grep -Fq 'dma: ManuallyDrop<DmaCoherent>' "$coherent"
grep -Fq 'quarantining abandoned DMA unmap owner' "$coherent"
raw_dma_api=$(sed -n \
    '/pub unsafe fn as_non_null_ptr_exclusive/,/^    }/p' \
    "$coherent")
test "$(grep -Fc 'pub unsafe fn as_non_null_ptr_exclusive(&self) -> NonNull<u8>' "$coherent")" -eq 1
grep -Fq 'retain this `DmaCoherent` owner for the entire pointer' "$coherent"
grep -Fq 'overlapping access through `VmReader`, `VmWriter`' "$coherent"
grep -Fq 'Raw access must stop before DMA teardown' "$coherent"
grep -Fq 'NonNull::new(self.writer().cursor())' <<<"$raw_dma_api"
grep -Fq 'dma.as_non_null_ptr_exclusive()' "$facade_root/src/dma.rs"
if grep -Fq 'dma.writer().cursor()' "$facade_root/src/dma.rs"; then
    echo 'Nexus bypasses the owner-bound exclusive raw DMA API' >&2
    exit 1
fi

util="$patched/src/mm/dma/util.rs"
grep -Fq 'for page_offset in (0..pa_range.len()).step_by(PAGE_SIZE)' "$util"
grep -Fq 'begin_dma_unmap(Some(first_daddr + page_offset))' "$util"
grep -Fq 'allocator::daddr_allocator(&irq_guard).free(daddr_range)' "$util"

registers="$patched/src/arch/x86/iommu/registers/mod.rs"
grep -Fq '_io_mem: IoMem<Sensitive>' "$registers"
grep -Fq 'io_mem_builder.reserve(' "$registers"
if grep -Fq 'paddr_to_vaddr(base_address' "$registers"; then
    echo 'VT-d registers still use the unmapped physical direct-map address' >&2
    exit 1
fi

iomem="$patched/src/io/io_mem/mod.rs"
raw_mmio_api=$(sed -n '/^impl IoMem<Insensitive> {/,/^}/p' "$iomem")
generic_iomem=$(sed -n \
    '/^impl<SecuritySensitivity> IoMem<SecuritySensitivity> {/,/^}/p' \
    "$iomem")
sensitive_iomem=$(sed -n '/^impl IoMem<Sensitive> {/,/^}/p' "$iomem")
test "$(grep -Fc 'pub unsafe fn as_non_null_ptr(&self) -> NonNull<u8>' "$iomem")" -eq 1
grep -Fq 'pub unsafe fn as_non_null_ptr(&self) -> NonNull<u8>' <<<"$raw_mmio_api"
grep -Fq 'The pointer is owner-bound: it does not keep the mapping' <<<"$raw_mmio_api"
grep -Fq 'The caller must retain this `IoMem` owner for every use' <<<"$raw_mmio_api"
grep -Fq 'overlapping alias access through this pointer' <<<"$raw_mmio_api"
grep -Fq 'NonNull::new(self.base() as *mut u8)' <<<"$raw_mmio_api"
grep -Fq 'pub(crate) fn base(&self) -> usize' <<<"$generic_iomem"
if grep -Fq 'as_non_null_ptr' <<<"$generic_iomem$sensitive_iomem" || \
    grep -Fq 'pub fn base(&self) -> usize' "$iomem"; then
    echo 'raw MMIO escape hatch was exported beyond IoMem<Insensitive>' >&2
    exit 1
fi

queue_source=$(tar -xOf "$virtio_archive" \
    virtio-drivers-0.13.0/src/queue.rs)
hal_source=$(tar -xOf "$virtio_archive" \
    virtio-drivers-0.13.0/src/hal.rs)
add_block=$(sed -n '/pub unsafe fn add/,/^    }/p' <<<"$queue_source")
fence_line=$(grep -nF 'fence(Ordering::SeqCst);' <<<"$add_block" | cut -d: -f1)
store_line=$(grep -nF '.store(self.avail_idx, Ordering::Release);' \
    <<<"$add_block" | cut -d: -f1)
test -n "$fence_line"
test -n "$store_line"
test "$fence_line" -lt "$store_line"

# Reset-without-pop relies on the exact no-alloc VirtQueue Drop shape: the
# queue owns only its layout DMA guard, and Dma::drop calls dma_dealloc without
# touching request buffers through Hal::unshare.
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

echo 'OSTD/VirtIO source assertions: PASS (bounded begin/poll; owner-bound raw DMA/MMIO; audited avail.idx Release commit; reset-abandon Drop shape)'
