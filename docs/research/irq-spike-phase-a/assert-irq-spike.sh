#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

# Phase A IRQ spike oracle.
#
# This oracle checks that the spike lane executed its bounded observation and
# reported one internally consistent outcome. It is not a capability oracle: a
# PASS here means one interrupt delivery was observed under one pinned QEMU
# configuration, nothing more. In particular it does not check interrupt-driven
# completion, fence enforcement, exactly-once delivery, deadline policy, or SMP.
#
# A NEGATIVE outcome is a legitimate spike result. The oracle reports it as a
# recorded finding and still fails the lane, so that a negative can never be
# mistaken for a positive by exit status alone.

log=${1:?usage: assert-irq-spike.sh KERNEL_LOG}

fail() {
    echo "IRQ spike oracle: FAIL: $*" >&2
    exit 1
}

[[ -f $log && ! -L $log ]] || fail "kernel log is not a regular non-symlink file: $log"

require_exact_count() {
    local pattern=$1
    local expected=$2
    local observed
    observed=$(grep -Fc -- "$pattern" "$log" || true)
    [[ $observed == "$expected" ]] \
        || fail "expected $expected occurrences of '$pattern', observed $observed"
}

require_regex_once() {
    local pattern=$1
    local observed
    observed=$(grep -Ec -- "$pattern" "$log" || true)
    [[ $observed == 1 ]] \
        || fail "expected exactly one line matching /$pattern/, observed $observed"
}

# The lane must have reached each ordered stage exactly once. Missing stages
# mean the observation window never opened and no delivery claim is meaningful.
require_exact_count 'IRQ_SPIKE KERNEL_MARKER stage=phase_a oracle_suffix=true' 1
require_exact_count 'IRQ_SPIKE BEGIN device=blk completion=polling delivery=intx' 1
require_regex_once '^IRQ_SPIKE Route bdf=[0-9a-f:.]+ firmware_line=[0-9]+ pin=[0-9]+ source=pci_config_0x3c$'
require_regex_once '^IRQ_SPIKE Masked stage=claimed line=[0-9]+$'
require_regex_once '^IRQ_SPIKE Prepared .* notifications_enabled=true$'
require_regex_once '^IRQ_SPIKE Published commit_point=avail_idx_release '
require_regex_once '^IRQ_SPIKE Unmasking stage=window_open line=[0-9]+ isr_unread=true reentry_expected=true$'
require_regex_once '^IRQ_SPIKE Remasked stage=window_closed .*deliveries=[0-9]+$'

# At least one candidate GSI must have been armed, otherwise the negative would
# only record that nothing was listening.
armed=$(grep -Ec '^IRQ_SPIKE Armed gsi=[0-9]+ ' "$log" || true)
(( armed >= 1 )) || fail "no candidate GSI was armed; a delivery result would be vacuous"

# The full INTx token discipline must have been exercised: claim, unmask, and
# remask each exactly once, with no stage-level failure in between.
if grep -Eq '^IRQ_SPIKE FAIL stage=' "$log"; then
    stage=$(grep -Eo '^IRQ_SPIKE FAIL stage=[a-z_]+' "$log" | head -n 1)
    fail "spike aborted at $stage"
fi

terminal=$(grep -Ec '^IRQ_SPIKE (PASS|NEGATIVE) ' "$log" || true)
[[ $terminal == 1 ]] || fail "expected exactly one terminal line, observed $terminal"

if grep -Eq '^IRQ_SPIKE NEGATIVE ' "$log"; then
    echo "IRQ spike oracle: recorded negative result"
    grep -E '^IRQ_SPIKE NEGATIVE ' "$log" >&2
    exit 1
fi

# A positive result must have at least one candidate whose counter advanced,
# and the per-candidate lines must account for exactly the reported total. More
# than one delivering GSI is expected on q35, where the same INTA# assertion
# reaches both the ISA-compatibility line and the PCI link entry, so it is
# reported rather than treated as a contradiction.
total=$(grep -Eo '^IRQ_SPIKE PASS delivery=observed deliveries=[0-9]+' "$log" \
    | grep -Eo '[0-9]+$') || fail 'positive terminal line lacks a delivery count'
(( total >= 1 )) || fail "positive terminal line reported $total deliveries"

summed=0
while read -r count; do
    summed=$(( summed + count ))
done < <(grep -E '^IRQ_SPIKE Candidate gsi=[0-9]+ ' "$log" | grep -Eo 'deliveries=[0-9]+$' \
    | grep -Eo '[0-9]+$')
[[ $summed == "$total" ]] \
    || fail "per-candidate deliveries sum to $summed but the terminal line reports $total"

delivering=$(grep -E '^IRQ_SPIKE Candidate gsi=[0-9]+ ' "$log" \
    | grep -Evc 'deliveries=0$' || true)
(( delivering >= 1 )) || fail 'no candidate recorded a delivery on a positive line'

firmware=$(grep -Eo 'firmware_line_delivered=(true|false)' "$log" | head -n 1)
pirq=$(grep -Eo 'pirq_gsi=(Some\([0-9]+\)|None)' "$log" | head -n 1)
completion=$(grep -Eo '^IRQ_SPIKE Completion source=polling observed=(true|false)' "$log" \
    | grep -Eo '(true|false)$')

echo "IRQ spike oracle: PASS delivery=observed deliveries=$total delivering_gsis=$delivering $firmware $pirq armed_candidates=$armed completion_source=polling completion_observed=$completion intx_tokens=claim+unmask+remask trigger=edge claim=none checkpoint=false"
