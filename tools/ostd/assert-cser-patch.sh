#!/usr/bin/env bash
set -euo pipefail

expected_archive_sha=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
expected_patch_sha=296dd6033d77dc10d0ed90236f1f0dfb18d261ca6bc266ac5f15220f0db56bfe
archive=${NEXUS_OSTD_ARCHIVE:-/opt/nexus-source/ostd-0.18.0.crate}
patched=${2:-${NEXUS_OSTD_PATCHED_ROOT:-/opt/nexus-ostd/ostd-0.18.0}}

if [[ $# -ge 1 ]]; then
    patch_file=$1
elif [[ -f /repo/patches/ostd-0.18.0-cser.patch ]]; then
    patch_file=/repo/patches/ostd-0.18.0-cser.patch
else
    script_dir=$(cd "$(dirname "$0")" && pwd)
    patch_file=$(cd "$script_dir/../.." && pwd)/patches/ostd-0.18.0-cser.patch
fi

fail() {
    echo "canonical OSTD CSER patch assertion failed: $*" >&2
    exit 1
}

[[ -f $archive ]] || fail "missing upstream archive: $archive"
[[ -f $patch_file ]] || fail "missing canonical patch: $patch_file"
[[ -d $patched/src ]] || fail "missing patched OSTD tree: $patched"
echo "$expected_archive_sha  $archive" | sha256sum -c - >/dev/null \
    || fail 'upstream OSTD archive digest mismatch'
echo "$expected_patch_sha  $patch_file" | sha256sum -c - >/dev/null \
    || fail 'canonical patch digest mismatch'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$archive" -C "$tmp"
pristine=$tmp/ostd-0.18.0
patch --batch --forward -d "$pristine" -p1 < "$patch_file" >/dev/null \
    || fail 'canonical patch does not apply to the pinned archive'
patch --batch --dry-run --reverse -d "$pristine" -p1 < "$patch_file" >/dev/null \
    || fail 'freshly patched tree does not reverse cleanly'
patch --batch --dry-run --reverse -d "$patched" -p1 < "$patch_file" >/dev/null \
    || fail 'installed patched tree does not reverse cleanly'
diff -ru "$pristine/src" "$patched/src" >/dev/null \
    || fail 'installed source differs from canonical patch output'

iommu=$patched/src/arch/x86/iommu/mod.rs
registers=$patched/src/arch/x86/iommu/registers/mod.rs
coherent=$patched/src/mm/dma/dma_coherent.rs
dma_util=$patched/src/mm/dma/util.rs
io_mem=$patched/src/io/io_mem/mod.rs

begin_block=$(sed -n \
    '/^pub(crate) fn begin_unmap_invalidate/,/^pub(crate) fn poll_unmap_invalidate/p' \
    "$iommu")
grep -Fq 'irq::disable_local()' <<<"$begin_block" \
    || fail 'DMA invalidation begin lost its RAII local-IRQ guard'
grep -Fq 'unmap(daddr)' <<<"$begin_block" \
    || fail 'DMA invalidation no longer removes the owner PTE'
grep -Fq '.submit_dma_invalidation(ticket)' <<<"$begin_block" \
    || fail 'DMA invalidation ticket is not submitted'
if grep -Eq '^[[:space:]]*(while|loop)[[:space:]{]' <<<"$begin_block"; then
    fail 'DMA invalidation begin regained an unbounded completion wait'
fi
grep -Fq 'InvalidationPath::Queued' "$registers" \
    || fail 'queued invalidation path is missing'
grep -Fq 'InvalidationPath::DmaRegister' "$registers" \
    || fail 'register invalidation fallback is missing'
grep -Fq 'Ordering::Release' "$registers" \
    || fail 'invalidation completion publication lost Release ordering'
grep -Fq 'pub fn poll_complete(mut self) -> Result<UnmappedDma, Self>' "$coherent" \
    || fail 'ownership-carrying DMA poll API is missing'
grep -Fq 'dma: ManuallyDrop<DmaCoherent>' "$coherent" \
    || fail 'pending DMA owner is no longer retained linearly'
grep -Fq 'quarantining abandoned DMA unmap owner' "$coherent" \
    || fail 'abandoned DMA tombstone no longer fails closed'
grep -Fq 'pub unsafe fn as_non_null_ptr_exclusive(&self) -> NonNull<u8>' "$coherent" \
    || fail 'owner-bound exclusive DMA pointer API is missing'
grep -Fq 'begin_dma_unmap(Some(first_daddr + page_offset))' "$dma_util" \
    || fail 'per-page DMA invalidation sequence is missing'
grep -Fq 'allocator::daddr_allocator(&irq_guard).free(daddr_range)' "$dma_util" \
    || fail 'IOVA release is no longer guarded after invalidation'
grep -Fq 'pub unsafe fn as_non_null_ptr(&self) -> NonNull<u8>' "$io_mem" \
    || fail 'owner-bound BAR pointer API is missing'

chip=$patched/src/arch/x86/irq/chip/mod.rs
ioapic=$patched/src/arch/x86/irq/chip/ioapic.rs
irq_remapping=$patched/src/arch/x86/irq/remapping.rs
irte=$patched/src/arch/x86/iommu/interrupt_remapping/table.rs
irte_handle=$patched/src/arch/x86/iommu/interrupt_remapping/mod.rs
irq_line=$patched/src/irq/top_half.rs

for fragment in \
    'pub enum GsiPolarity {' \
    'ActiveHigh,' \
    'ActiveLow,' \
    'pub enum GsiTriggerMode {' \
    'Edge,' \
    'Level,' \
    'pub struct GsiConfig {' \
    'pub const EDGE_HIGH: Self = Self::new(GsiPolarity::ActiveHigh, GsiTriggerMode::Edge);' \
    'pub fn map_gsi_pin_to_with_config('; do
    grep -Fq "$fragment" "$chip" || fail "GSI API lacks $fragment"
done
legacy_map=$(sed -n '/pub fn map_gsi_pin_to(/,/^    }/p' "$chip")
grep -Fq 'self.map_gsi_pin_to_with_config(irq_line, gsi_index, GsiConfig::EDGE_HIGH)' \
    <<<"$legacy_map" || fail 'legacy map_gsi_pin_to no longer delegates to edge/high'
grep -Fq 'irq_line.claim_remapping_trigger_mode(config.is_level_triggered())?' "$chip" \
    || fail 'configured mapping does not claim a synchronized trigger mode'
grep -Fq 'irq_line.release_remapping_trigger_mode();' "$chip" \
    || fail 'configured mapping does not release its trigger-mode claim'

grep -Fq 'const RTE_ACTIVE_LOW: u32 = 1 << 13;' "$ioapic" \
    || fail 'I/O APIC polarity is not encoded in RTE bit 13'
grep -Fq 'const RTE_LEVEL_TRIGGERED: u32 = 1 << 15;' "$ioapic" \
    || fail 'I/O APIC trigger mode is not encoded in RTE bit 15'
grep -Fq 'u64::from(rte_config_bits(config))' "$ioapic" \
    || fail 'remappable I/O APIC entry omits polarity/trigger bits'
grep -Fq 'irq.num() as u32 | rte_config_bits(config)' "$ioapic" \
    || fail 'non-remappable I/O APIC entry omits polarity/trigger bits'

grep -Fq 'handle.enable(irq_num as u32, false);' "$irq_remapping" \
    || fail 'initial IRTE behavior is no longer edge-triggered'
grep -Fq 'handle.enable(irq_num as u32, level_triggered);' "$irq_remapping" \
    || fail 'configured trigger mode does not reach the IRTE handle'
grep -Fq 'table::IrtEntry::new_enabled(vector, level_triggered)' "$irte_handle" \
    || fail 'IRTE handle drops the configured trigger mode'
grep -Fq 'let trigger_mode = (level_triggered as u128) << 4;' "$irte" \
    || fail 'IRTE trigger mode is not encoded in TM bit 4'

grep -Fq 'claim.users != 0 && claim.level_triggered != level_triggered' "$irq_line" \
    || fail 'conflicting concurrent trigger-mode mappings are not rejected'
grep -Fq '.checked_add(1)' "$irq_line" \
    || fail 'trigger-mode claim counter does not check overflow'
grep -Fq '.checked_sub(1)' "$irq_line" \
    || fail 'trigger-mode release does not check underflow'

echo 'canonical OSTD CSER patch: PASS archive=pinned patch=hash-bound apply=true reverse=true dma_closure=true gsi=edge+level/high+low ioapic_bits=13+15 irte_tm_bit=4 legacy=edge-high'
