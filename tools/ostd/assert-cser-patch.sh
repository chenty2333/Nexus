#!/usr/bin/env bash
set -euo pipefail

expected_archive_sha=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
expected_patch_sha=0950caa05bfa08467acd00a150246865af82b6ff7f0fc728a33ecf493ffb4912
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
        in_entry && $0 == "            unsafe { processor::after_switching_to(processor::SwitchTailKind::FirstTask) };" {
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

assert_first_task_pre_irq_contract() {
    local task_source=$1
    local processor_source=$2

    awk '
        $0 == "static FIRST_TASK_PRE_IRQ_HANDLER: Once<fn(&DisabledLocalIrqGuard)> = Once::new();" {
            handler_statics++
        }
        $0 == "pub fn inject_first_task_pre_irq_handler(handler: fn(&DisabledLocalIrqGuard)) {" {
            injection_apis++
        }
        $0 == "    FIRST_TASK_PRE_IRQ_HANDLER.call_once(|| handler);" {
            injection_installs++
        }
        $0 == "            unsafe { processor::after_switching_to(processor::SwitchTailKind::FirstTask) };" {
            first_task_calls++
        }
        END {
            exit !(handler_statics == 1 && injection_apis == 1 &&
                   injection_installs == 1 && first_task_calls == 1)
        }
    ' "$task_source" || return 1

    awk '
        $0 == "pub(super) enum SwitchTailKind {" { kinds++ }
        $0 == "    FirstTask," { first_variants++ }
        $0 == "    ResumedTask," { resumed_variants++ }
        $0 == "    unsafe { after_switching_to(SwitchTailKind::ResumedTask) };" {
            resumed_calls++
        }
        $0 == "pub(super) unsafe fn after_switching_to(tail_kind: SwitchTailKind) {" {
            tail_functions++
        }
        /if let Some\(handler\) = POST_SCHEDULE_HANDLER.get\(\)/ {
            post_lookups++
            post_lookup_line = NR
        }
        $0 == "    if tail_kind == SwitchTailKind::FirstTask {" {
            first_guards++
            first_guard_line = NR
            in_first = 1
        }
        in_first && /!crate::arch::irq::is_local_enabled\(\)/ {
            irq_assertions++
            if (irq_assertions == 1)
                pre_handler_irq_assertion_line = NR
            else if (irq_assertions == 2)
                post_handler_irq_assertion_line = NR
        }
        in_first && $0 == "        let admission_guard = crate::irq::disable_local();" {
            guard_creations++
            guard_creation_line = NR
        }
        /super::FIRST_TASK_PRE_IRQ_HANDLER.get\(\)/ {
            pre_irq_lookups++
            pre_irq_lookup_line = NR
            if (!in_first) outside_first = 1
        }
        /handler\(&admission_guard\);/ {
            pre_irq_calls++
            pre_irq_call_line = NR
            if (!in_first) outside_first = 1
        }
        in_first && /crate::arch::irq::enable_local\(\);/ {
            premature_irq_enables++
        }
        in_first && $0 == "        core::mem::forget(admission_guard);" {
            guard_forgets++
            guard_forget_line = NR
        }
        in_first && $0 == "    }" { in_first = 0 }
        $0 == "    crate::arch::irq::enable_local();" {
            irq_enables++
            irq_enable_line = NR
        }
        END {
            if (kinds != 1 || first_variants != 1 || resumed_variants != 1 ||
                resumed_calls != 1 || tail_functions != 1 || post_lookups != 1 ||
                first_guards != 1 || irq_assertions != 2 || guard_creations != 1 ||
                pre_irq_lookups != 1 || pre_irq_calls != 1 || guard_forgets != 1 ||
                irq_enables != 1 || premature_irq_enables != 0 ||
                outside_first || in_first)
                exit 1
            exit !(post_lookup_line < first_guard_line &&
                   first_guard_line < pre_handler_irq_assertion_line &&
                   pre_handler_irq_assertion_line < guard_creation_line &&
                   guard_creation_line < pre_irq_lookup_line &&
                   pre_irq_lookup_line < pre_irq_call_line &&
                   pre_irq_call_line < post_handler_irq_assertion_line &&
                   post_handler_irq_assertion_line < guard_forget_line &&
                   guard_forget_line < irq_enable_line)
        }
    ' "$processor_source"
}

assert_callback_rearmed_timer_contract() {
    local apic_source=$1
    local timer_source=$2
    local trap_source=$3
    local user_context_source=$4
    local timer_api_source=$5
    local jiffies_source=$6

    grep -Fq 'Config::CallbackRearmedOneShot { init_count }' "$apic_source" || return 1
    grep -Fq 'apic.set_lvt_timer(timer_irq.num() as u64);' "$apic_source" || return 1
    grep -Fq 'apic.set_timer_init_count(*init_count);' "$apic_source" || return 1
    if grep -Fq '1 << 17' "$apic_source"; then
        return 1
    fi
    awk '
        /fn init_callback_rearmed_oneshot\(/ { in_init = 1; init_functions++ }
        in_init && /set_timer_div_config\(DivideConfig::Divide64\)/ { divisor = NR }
        in_init && /set_lvt_timer\(timer_irq.num\(\) as u64\)/ { lvt = NR }
        in_init && /set_timer_init_count\(init_count\)/ { arm = NR; in_init = 0 }
        END {
            exit !(init_functions == 1 && divisor < lvt && lvt < arm)
        }
    ' "$apic_source" || return 1
    awk '
        /^fn timer_callback\(trapframe: &TrapFrame\)/ { callback = NR }
        /call_timer_callback_functions\(trapframe\)/ { logical_callbacks = NR }
        /^pub\(super\) fn complete_irq\(irq_num: u8\)/ { complete = NR }
        /if timer_irq.num\(\) == irq_num/ { dynamic_vector = NR }
        /apic::rearm_timer\(\);/ { rearms++; rearm = NR }
        END {
            exit !(callback < logical_callbacks && logical_callbacks < complete &&
                   complete < dynamic_vector && dynamic_vector < rearm && rearms == 1)
        }
    ' "$timer_source" || return 1
    awk '
        /^unsafe extern "sysv64" fn trap_handler\(f: &mut TrapFrame\)/ {
            handlers++
            in_handler = 1
            next
        }
        in_handler && /^}$/ { in_handler = 0 }
        in_handler && /^        None => \{$/ {
            irq_branches++
            in_irq_branch = 1
            next
        }
        in_irq_branch && /call_irq_callback_functions\(/ {
            callbacks++
            callbacks_line = NR
        }
        in_irq_branch && /super::timer::complete_irq\(f.trap_num as u8\);/ {
            completes++
            complete_line = NR
        }
        in_irq_branch && /^        }$/ {
            branch_closes++
            if (last_statement !~ /super::timer::complete_irq\(f.trap_num as u8\);/)
                bad_tail = 1
            in_irq_branch = 0
        }
        in_irq_branch && !/^[[:space:]]*$/ && !/^        }$/ {
            last_statement = $0
        }
        END {
            exit !(handlers == 1 && irq_branches == 1 && branch_closes == 1 &&
                   callbacks == 1 && completes == 1 &&
                   callbacks_line < complete_line &&
                   !in_irq_branch && !bad_tail)
        }
    ' "$trap_source" || return 1
    awk '
        /^impl UserContextApiInternal for UserContext \{$/ {
            implementations++
            in_implementation = 1
            next
        }
        in_implementation && /^    fn execute<F>/ {
            executes++
            in_execute = 1
            next
        }
        in_execute && /^    fn as_trap_frame/ { in_execute = 0 }
        in_execute && /^                None => \{$/ {
            irq_branches++
            in_irq_branch = 1
            next
        }
        in_irq_branch && /call_irq_callback_functions\(/ {
            callbacks++
            callbacks_line = NR
        }
        in_irq_branch && /crate::arch::timer::complete_irq\(self.as_trap_frame\(\).trap_num as u8\);/ {
            completes++
            complete_line = NR
            require_enable = 1
        }
        in_irq_branch && require_enable && NR > complete_line && !/^[[:space:]]*$/ {
            if ($0 !~ /^[[:space:]]*crate::arch::irq::enable_local\(\);[[:space:]]*$/)
                bad_adjacency = 1
            require_enable = 0
        }
        in_irq_branch && /crate::arch::irq::enable_local\(\);/ {
            irq_enables++
            irq_enable_line = NR
        }
        in_irq_branch && /^                }$/ {
            branch_closes++
            if (last_statement !~ /crate::arch::irq::enable_local\(\);/)
                bad_tail = 1
            in_irq_branch = 0
        }
        in_irq_branch && !/^[[:space:]]*$/ && !/^                }$/ {
            last_statement = $0
        }
        END {
            exit !(implementations == 1 && executes == 1 && irq_branches == 1 &&
                   branch_closes == 1 && callbacks == 1 && completes == 1 &&
                   irq_enables == 1 && callbacks_line < complete_line &&
                   complete_line < irq_enable_line && !require_enable &&
                   !in_irq_branch && !bad_adjacency && !bad_tail)
        }
    ' "$user_context_source" || return 1
    grep -Fq 'The nominal maximum timer callback frequency in Hz.' "$timer_api_source" \
        || return 1
    grep -Fq 'the nominal conversion rate, not a wall-clock progress guarantee.' \
        "$jiffies_source" || return 1
    if grep -Eq 'complete_irq\((0x21|33)\)|irq_num == (0x21|33)' \
        "$timer_source" "$trap_source" "$user_context_source"; then
        return 1
    fi
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
processor_source=$patched/src/task/processor.rs
assert_first_task_entry_contract "$task_mod" \
    || fail 'first-task-entry handler is absent or outside the trampoline entry boundary'
assert_first_task_pre_irq_contract "$task_mod" "$processor_source" \
    || fail 'first-task admission is not first-only, IRQ-off, and before local IRQ enable'
apic_timer_source=$patched/src/arch/x86/timer/apic.rs
timer_source=$patched/src/arch/x86/timer/mod.rs
trap_source=$patched/src/arch/x86/trap/mod.rs
user_context_source=$patched/src/arch/x86/cpu/context/mod.rs
timer_api_source=$patched/src/timer/mod.rs
jiffies_source=$patched/src/timer/jiffies.rs
assert_callback_rearmed_timer_contract \
    "$apic_timer_source" "$timer_source" "$trap_source" "$user_context_source" \
    "$timer_api_source" "$jiffies_source" \
    || fail 'APIC timer is not callback-rearmed from both dynamic IRQ-tail paths'

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

missing_pre_irq_lookup=$tmp/processor-missing-first-task-pre-irq.rs
sed \
    '0,/if let Some(handler) = super::FIRST_TASK_PRE_IRQ_HANDLER.get()/s//if let Some(handler) = None::<\&fn(\&DisabledLocalIrqGuard)>/' \
    "$processor_source" >"$missing_pre_irq_lookup"
if assert_first_task_pre_irq_contract "$task_mod" "$missing_pre_irq_lookup"; then
    fail 'first-task pre-IRQ oracle accepted a deleted admission lookup'
fi

first_task_as_resumed=$tmp/task-first-entry-as-resumed.rs
sed \
    '0,/processor::SwitchTailKind::FirstTask/s//processor::SwitchTailKind::ResumedTask/' \
    "$task_mod" >"$first_task_as_resumed"
if assert_first_task_pre_irq_contract "$first_task_as_resumed" "$processor_source"; then
    fail 'first-task pre-IRQ oracle accepted a first entry marked as resumed'
fi

resumed_task_as_first=$tmp/processor-resume-as-first.rs
sed \
    '0,/after_switching_to(SwitchTailKind::ResumedTask)/s//after_switching_to(SwitchTailKind::FirstTask)/' \
    "$processor_source" >"$resumed_task_as_first"
if assert_first_task_pre_irq_contract "$task_mod" "$resumed_task_as_first"; then
    fail 'first-task pre-IRQ oracle accepted repeated admission on task resume'
fi

unconditional_pre_irq=$tmp/processor-unconditional-first-task-pre-irq.rs
sed '0,/if tail_kind == SwitchTailKind::FirstTask/s//if true/' \
    "$processor_source" >"$unconditional_pre_irq"
if assert_first_task_pre_irq_contract "$task_mod" "$unconditional_pre_irq"; then
    fail 'first-task pre-IRQ oracle accepted unconditional admission'
fi

late_pre_irq=$tmp/processor-late-first-task-pre-irq.rs
awk '
    $0 == "        if let Some(handler) = super::FIRST_TASK_PRE_IRQ_HANDLER.get() {" {
        first = $0
        if ((getline second) <= 0 || second != "            handler(&admission_guard);") exit 2
        if ((getline third) <= 0 || third != "        }") exit 2
        removed = 1
        next
    }
    {
        print
        if (removed && !inserted && $0 == "    crate::arch::irq::enable_local();") {
            print first
            print second
            print third
            inserted = 1
        }
    }
    END { if (!removed || !inserted) exit 2 }
' "$processor_source" >"$late_pre_irq"
if assert_first_task_pre_irq_contract "$task_mod" "$late_pre_irq"; then
    fail 'first-task pre-IRQ oracle accepted admission after local IRQ enable'
fi

unguarded_pre_irq_api=$tmp/task-unguarded-first-task-pre-irq.rs
sed \
    '0,/static FIRST_TASK_PRE_IRQ_HANDLER: Once<fn(\&DisabledLocalIrqGuard)>/s//static FIRST_TASK_PRE_IRQ_HANDLER: Once<fn()>/' \
    "$task_mod" >"$unguarded_pre_irq_api"
if assert_first_task_pre_irq_contract "$unguarded_pre_irq_api" "$processor_source"; then
    fail 'first-task pre-IRQ oracle accepted an admission API without an IRQ guard'
fi

handler_enabled_irq=$tmp/processor-handler-enabled-local-irq.rs
awk '
    !added && $0 == "        core::mem::forget(admission_guard);" {
        print "        crate::arch::irq::enable_local();"
        added = 1
    }
    { print }
    END { if (!added) exit 2 }
' "$processor_source" >"$handler_enabled_irq"
if assert_first_task_pre_irq_contract "$task_mod" "$handler_enabled_irq"; then
    fail 'first-task pre-IRQ oracle accepted a handler that returned with local IRQs enabled'
fi

periodic_timer=$tmp/apic-periodic-timer.rs
sed '0,/apic.set_lvt_timer(timer_irq.num() as u64);/s//apic.set_lvt_timer(timer_irq.num() as u64 | (1 << 17));/' \
    "$apic_timer_source" >"$periodic_timer"
if assert_callback_rearmed_timer_contract \
    "$periodic_timer" "$timer_source" "$trap_source" "$user_context_source" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted periodic LVT mode'
fi

top_half_rearm=$tmp/timer-top-half-rearm.rs
awk '
    { print }
    !added && /call_timer_callback_functions\(trapframe\);/ {
        print "    apic::rearm_timer();"
        added = 1
    }
    END { if (!added) exit 2 }
' "$timer_source" >"$top_half_rearm"
if assert_callback_rearmed_timer_contract \
    "$apic_timer_source" "$top_half_rearm" "$trap_source" "$user_context_source" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted rearm in the top-half callback'
fi

missing_kernel_tail=$tmp/trap-missing-timer-tail.rs
sed '0,/super::timer::complete_irq(f.trap_num as u8);/s//let _ = f.trap_num;/' \
    "$trap_source" >"$missing_kernel_tail"
if assert_callback_rearmed_timer_contract \
    "$apic_timer_source" "$timer_source" "$missing_kernel_tail" "$user_context_source" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted a missing kernel IRQ-tail rearm'
fi

work_after_kernel_tail=$tmp/trap-work-after-timer-tail.rs
awk '
    { print }
    !added && /super::timer::complete_irq\(f.trap_num as u8\);/ {
        print "            let _ = f.trap_num;"
        added = 1
    }
    END { if (!added) exit 2 }
' "$trap_source" >"$work_after_kernel_tail"
if assert_callback_rearmed_timer_contract \
    "$apic_timer_source" "$timer_source" "$work_after_kernel_tail" "$user_context_source" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted work after the kernel IRQ-tail rearm'
fi

missing_user_tail=$tmp/context-missing-timer-tail.rs
sed '0,/crate::arch::timer::complete_irq(self.as_trap_frame().trap_num as u8);/s//let _ = self.as_trap_frame().trap_num;/' \
    "$user_context_source" >"$missing_user_tail"
if assert_callback_rearmed_timer_contract \
    "$apic_timer_source" "$timer_source" "$trap_source" "$missing_user_tail" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted a missing user IRQ-tail rearm'
fi

work_between_user_tail=$tmp/context-work-between-timer-tail-and-enable.rs
awk '
    { print }
    !added && /crate::arch::timer::complete_irq\(self.as_trap_frame\(\).trap_num as u8\);/ {
        print "                    core::hint::spin_loop();"
        added = 1
    }
    END { if (!added) exit 2 }
' "$user_context_source" >"$work_between_user_tail"
if assert_callback_rearmed_timer_contract \
    "$apic_timer_source" "$timer_source" "$trap_source" "$work_between_user_tail" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted work between user IRQ-tail rearm and IRQ enable'
fi

missing_tail_rearm=$tmp/timer-missing-rearm.rs
sed '0,/apic::rearm_timer();/s//let _ = irq_num;/' "$timer_source" >"$missing_tail_rearm"
if assert_callback_rearmed_timer_contract \
    "$apic_timer_source" "$missing_tail_rearm" "$trap_source" "$user_context_source" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted a tail that did not rearm the timer'
fi

missing_count_rearm=$tmp/apic-missing-count-rearm.rs
sed '0,/apic.set_timer_init_count(\*init_count);/s//apic.set_timer_init_count(0);/' \
    "$apic_timer_source" >"$missing_count_rearm"
if assert_callback_rearmed_timer_contract \
    "$missing_count_rearm" "$timer_source" "$trap_source" "$user_context_source" \
    "$timer_api_source" "$jiffies_source"; then
    fail 'APIC timer oracle accepted a one-shot mode without count rearm'
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

echo 'canonical OSTD CSER patch: PASS archive=pinned patch=hash-bound apply=true reverse=true first_task_pre_irq=post-schedule+guarded+preserved+first-only+before-irq pre_irq_mutations=7 first_task_entry=post-irq+before-func apic_timer=callback-rearmed-one-shot irq_tail=kernel+user dynamic_vector=true timer_mutations=8 dma_closure=true gsi=edge+level/high+low ioapic_bits=13+15 irte_tm_bit=4 legacy=edge-high'
