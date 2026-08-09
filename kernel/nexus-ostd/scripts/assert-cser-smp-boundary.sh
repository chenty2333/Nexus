#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

# This boundary gate protects the five historical one-vCPU evidence/comparison
# profiles while requiring the separate real-SMP smoke to declare its distinct
# two-vCPU, multi-threaded-TCG envelope.

set -euo pipefail

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
manifest="$root/OSDK.toml"
runtime="$root/src/cser/core_runtime.rs"

[[ -f $manifest && -f $runtime ]] || {
    echo "missing OSDK manifest or CSER runtime" >&2
    exit 1
}

schemes=(
    cser-production
    cser-core-reply-recovery
    cser-core-dma-recovery
    tool-dma-cser
    tool-dma-baseline
)

extract_scheme() {
    local scheme=$1
    awk -v header="[scheme.\"$scheme\"]" '
        $0 == header { found = 1; next }
        found && /^\[scheme\./ { exit }
        found { print }
    ' "$manifest"
}

for scheme in "${schemes[@]}"; do
    block=$(extract_scheme "$scheme")
    [[ -n $block ]] || {
        echo "missing QEMU scheme: $scheme" >&2
        exit 1
    }
    if [[ $(grep -Ec -- '^[[:space:]]*-smp 1 \\$' <<<"$block") -ne 1 ]]; then
        echo "$scheme is not pinned to exactly one vCPU" >&2
        exit 1
    fi
    if [[ $(grep -Ec -- '^[[:space:]]*-accel tcg,thread=single \\$' <<<"$block") -ne 1 ]]; then
        echo "$scheme is not pinned to single-threaded TCG" >&2
        exit 1
    fi
done

smp_smoke=$(extract_scheme cser-smp-smoke)
[[ -n $smp_smoke ]] || {
    echo "missing QEMU scheme: cser-smp-smoke" >&2
    exit 1
}
if [[ $(grep -Ec -- '^[[:space:]]*-smp 2 \\$' <<<"$smp_smoke") -ne 1 ]]; then
    echo 'cser-smp-smoke is not pinned to exactly two vCPUs' >&2
    exit 1
fi
if [[ $(grep -Ec -- '^[[:space:]]*-accel tcg,thread=multi \\$' <<<"$smp_smoke") -ne 1 ]]; then
    echo 'cser-smp-smoke is not pinned to multi-threaded TCG' >&2
    exit 1
fi

grep -Fq 'state: Mutex<RuntimeState<P>>' "$runtime" || {
    echo "CSER runtime no longer exposes the reviewed single-writer mutex" >&2
    exit 1
}
grep -Fq 'manager/task context which may block' "$runtime" || {
    echo "CSER runtime lost its blocking-context boundary" >&2
    exit 1
}

echo "CSER_SMP_BOUNDARY PASS one_vcpu_profiles=${#schemes[@]} configured_vcpus=1 tcg_threads=single smp_smoke_vcpus=2 smp_smoke_tcg_threads=multi runtime_writer=ostd_mutex portable_loom=separate-gate kernel_smp_execution=separate-smoke kernel_smp_safety=bounded-bsp-only"
