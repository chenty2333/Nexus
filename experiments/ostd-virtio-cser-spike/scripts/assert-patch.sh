#!/usr/bin/env bash
set -euo pipefail

expected_sha=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
archive=/opt/nexus-source/ostd-0.18.0.crate
patched=/opt/nexus-ostd/ostd-0.18.0
patch_file=/work/patches/ostd-0.18.0-dma-closure.patch

echo "$expected_sha  $archive" | sha256sum -c - >/dev/null
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

echo 'OSTD DMA patch assertions: PASS (runtime begin/poll bounded; one-page ownership API; exact source checksum)'
