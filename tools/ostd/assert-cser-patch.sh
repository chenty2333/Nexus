#!/usr/bin/env bash
set -euo pipefail

expected_archive_sha=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
expected_patch_sha=8b914b775dcc52b64ccb701e3df1dc2df699a727f3f0deacdad0fdf591f8829f
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

assert_first_task_entry_contract() {
    local task_source=$1
    awk '
        $0 == "static FIRST_TASK_ENTRY_HANDLER: Once<fn()> = Once::new();" {
            handler_statics++
        }
        $0 == "pub fn inject_first_task_entry_handler(handler: fn()) {" {
            injection_apis++
        }
        $0 == "    FIRST_TASK_ENTRY_HANDLER.call_once(|| handler);" {
            injection_installs++
        }
        $0 == "        unsafe extern \"C\" fn kernel_task_entry() -> ! {" {
            entry_functions++
            in_entry = 1
        }
        in_entry && $0 == "            unsafe { processor::after_switching_to() };" {
            after_switch_calls++
            after_switch_line = NR
        }
        in_entry && $0 == "            if let Some(handler) = FIRST_TASK_ENTRY_HANDLER.get() {" {
            entry_handler_lookups++
            entry_handler_lookup_line = NR
        }
        in_entry && $0 == "                handler();" {
            entry_handler_calls++
            entry_handler_call_line = NR
        }
        in_entry && $0 == "            let current_task = Task::current()" {
            current_task_reads++
            current_task_line = NR
        }
        in_entry && $0 == "            let task_func = unsafe { current_task.func.get() };" {
            task_func_reads++
            task_func_read_line = NR
        }
        in_entry && $0 == "                .take()" {
            task_func_takes++
            task_func_take_line = NR
        }
        in_entry && $0 == "            task_func();" {
            task_func_calls++
            task_func_call_line = NR
        }
        in_entry && $0 == "            scheduler::exit_current();" {
            in_entry = 0
        }
        END {
            if (handler_statics != 1 || injection_apis != 1 ||
                injection_installs != 1 || entry_functions != 1 ||
                after_switch_calls != 1 || entry_handler_lookups != 1 ||
                entry_handler_calls != 1 || current_task_reads != 1 ||
                task_func_reads != 1 || task_func_takes != 1 ||
                task_func_calls != 1)
                exit 1
            if (!(after_switch_line < entry_handler_lookup_line &&
                  entry_handler_lookup_line < entry_handler_call_line &&
                  entry_handler_call_line < current_task_line &&
                  current_task_line < task_func_read_line &&
                  task_func_read_line < task_func_take_line &&
                  task_func_take_line < task_func_call_line))
                exit 1
        }
    ' "$task_source"
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
patch --fuzz=0 --batch --forward -d "$pristine" -p1 < "$patch_file" >/dev/null \
    || fail 'canonical patch does not apply to the pinned archive'
patch --fuzz=0 --batch --dry-run --reverse -d "$pristine" -p1 < "$patch_file" >/dev/null \
    || fail 'freshly patched tree does not reverse cleanly'
patch --fuzz=0 --batch --dry-run --reverse -d "$patched" -p1 < "$patch_file" >/dev/null \
    || fail 'installed patched tree does not reverse cleanly'
diff -ru "$pristine/src" "$patched/src" >/dev/null \
    || fail 'installed source differs from canonical patch output'

task_mod=$patched/src/task/mod.rs
assert_first_task_entry_contract "$task_mod" \
    || fail 'first-task-entry handler is absent or outside the trampoline entry boundary'

missing_entry_call=$tmp/task-missing-first-entry-call.rs
sed \
    '0,/if let Some(handler) = FIRST_TASK_ENTRY_HANDLER.get()/s//if let Some(handler) = None::<\&fn()>/' \
    "$task_mod" >"$missing_entry_call"
if assert_first_task_entry_contract "$missing_entry_call"; then
    fail 'first-task-entry oracle accepted a deleted handler lookup'
fi

late_entry_call=$tmp/task-late-first-entry-call.rs
awk '
    $0 == "            if let Some(handler) = FIRST_TASK_ENTRY_HANDLER.get() {" {
        first = $0
        if ((getline second) <= 0 || second != "                handler();") exit 2
        if ((getline third) <= 0 || third != "            }") exit 2
        removed = 1
        next
    }
    {
        print
        if (removed && !inserted && $0 == "            task_func();") {
            print first
            print second
            print third
            inserted = 1
        }
    }
    END { if (!removed || !inserted) exit 2 }
' "$task_mod" >"$late_entry_call"
if assert_first_task_entry_contract "$late_entry_call"; then
    fail 'first-task-entry oracle accepted a handler call after task_func'
fi

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

echo 'canonical OSTD CSER patch: PASS archive=pinned patch=hash-bound apply=true reverse=true first_task_entry=post-switch-tail+before-func dma_closure=true gsi=edge+level/high+low ioapic_bits=13+15 irte_tm_bit=4 legacy=edge-high'
