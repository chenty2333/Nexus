#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Provisions the exact development NV layout consumed by core_tpm_anchor.rs.
# The runtime receives only empty per-index fixture auth; platform hierarchy
# authority remains outside the guest. The resulting swtpm directory is test
# evidence only and can be rolled back by its host.

set -euo pipefail

mode=cser
if [[ ${1:-} == --experiment-blank ]]; then
    mode=experiment-blank
    shift
fi
if { [[ $mode == cser ]] && (($# < 1 || $# > 4)); } \
    || { [[ $mode == experiment-blank ]] && (($# != 1)); }; then
    echo "usage: $0 [--experiment-blank] STATE_DIR [CATALOG_SHA256_HEX [TIP_REVISION TIP_HEAD_SHA256_HEX]]" >&2
    exit 2
fi

for command in swtpm tpm2_nvdefine tpm2_nvreadpublic tpm2_nvread \
    tpm2_nvwrite tpm2_nvincrement tpm2_startauthsession \
    tpm2_policycommandcode tpm2_flushcontext xxd sha256sum cmp stat \
    cut flock realpath sleep; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing required command: $command" >&2
        exit 1
    fi
done

readonly mode
state_dir=$1
catalog_hex=${2:-}
tip_revision=${3:-0}
tip_head_hex=${4:-}
if [[ $mode == cser && -z $catalog_hex ]]; then
    for _ in {1..32}; do
        catalog_hex+=42
    done
fi
if [[ $mode == cser && ! $catalog_hex =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "catalog digest must be exactly 64 hexadecimal characters" >&2
    exit 2
fi
catalog_hex=${catalog_hex,,}
if [[ $mode == cser ]] && { ! [[ $tip_revision =~ ^(0|[1-9][0-9]*)$ ]] \
    || (( ${#tip_revision} > 20 )) \
    || { (( ${#tip_revision} == 20 )) \
        && [[ $tip_revision > 18446744073709551615 ]]; }; }; then
    echo "tip revision must be an unsigned 64-bit decimal" >&2
    exit 2
fi
if [[ $mode == cser && -z $tip_head_hex ]]; then
    for _ in {1..32}; do
        tip_head_hex+=00
    done
fi
if [[ $mode == cser && ! $tip_head_hex =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "tip head must be exactly 64 hexadecimal characters" >&2
    exit 2
fi
tip_head_hex=${tip_head_hex,,}
zero_head_hex=
for _ in {1..32}; do
    zero_head_hex+=00
done
if [[ $mode == cser ]] && { { [[ $tip_revision == 0 ]] && [[ $tip_head_hex != "$zero_head_hex" ]]; } \
    || { [[ $tip_revision != 0 ]] && [[ $tip_head_hex == "$zero_head_hex" ]]; }; }; then
    echo "tip revision and head must name genesis together or a non-genesis tip together" >&2
    exit 2
fi
printf -v tip_revision_hex '%016x' "$tip_revision"
readonly catalog_hex tip_revision tip_revision_hex tip_head_hex zero_head_hex
mkdir -p -- "$state_dir"
state_dir=$(realpath -e -- "$state_dir")
state_lock_key=$(printf '%s' "$state_dir" | sha256sum | cut -c1-32)
state_lock="/tmp/cser-tpm-nv-provision-$state_lock_key.lock"
exec 9>"$state_lock"
if ! flock -n 9; then
    echo "TPM state directory is already owned by another provisioner: $state_dir" >&2
    exit 1
fi
readonly state_dir state_lock_key state_lock
if [[ -n $(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "TPM state directory must be empty before provisioning: $state_dir" >&2
    exit 1
fi

work_dir=$(mktemp -d /tmp/cser-tpm-nv-provision.XXXXXX)
swtpm_pid=

wait_for_swtpm_exit() {
    local pid=$1
    for _ in {1..500}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 0.01
    done
    echo "swtpm did not exit after SIGKILL: pid=$pid" >&2
    return 1
}

stop_swtpm() {
    local pid=${swtpm_pid:-}
    if [[ -z $pid ]]; then
        return 0
    fi
    if [[ ! $pid =~ ^[1-9][0-9]*$ ]]; then
        echo "swtpm returned an invalid pid: $pid" >&2
        return 1
    fi
    if kill -0 "$pid" 2>/dev/null; then
        if ! kill -KILL "$pid" 2>/dev/null && kill -0 "$pid" 2>/dev/null; then
            echo "failed to send SIGKILL to swtpm: pid=$pid" >&2
            return 1
        fi
        wait_for_swtpm_exit "$pid" || return 1
    fi
    swtpm_pid=
}

cleanup() {
    local status=$?
    trap - EXIT
    if ! stop_swtpm; then
        status=1
    fi
    rm -rf -- "$work_dir"
    exit "$status"
}
trap cleanup EXIT

server_socket="$work_dir/server.sock"
control_socket="$server_socket.ctrl"
pid_file="$work_dir/swtpm.pid"
tcti="swtpm:path=$server_socket"
swtpm_flags=not-need-init,startup-clear
if ! swtpm_capabilities=$(swtpm socket --print-capabilities); then
    echo "failed to query swtpm capabilities" >&2
    exit 1
fi
# v0.8 introduced both automatic TPM2_Shutdown and this opt-out. Older swtpm
# releases need no flag to retain the same crash-style process lifecycle.
if grep -Fq '"flags-opt-disable-auto-shutdown"' <<<"$swtpm_capabilities"; then
    swtpm_flags+=,disable-auto-shutdown
fi
readonly swtpm_capabilities swtpm_flags

# The host flock above gives this daemon exclusive custody. The optional swtpm
# backend lock is unnecessary and is not available in Ubuntu 24.04's 0.7.3.
swtpm socket \
    --tpm2 \
    --tpmstate "dir=$state_dir" \
    --ctrl "type=unixio,path=$control_socket" \
    --server "type=unixio,path=$server_socket" \
    --flags "$swtpm_flags" \
    --pid "file=$pid_file" \
    --daemon
swtpm_pid=$(tr -d '\n' <"$pid_file")
if [[ ! $swtpm_pid =~ ^[1-9][0-9]*$ ]] \
    || ! kill -0 "$swtpm_pid" 2>/dev/null; then
    echo "swtpm did not start the provisioning daemon" >&2
    exit 1
fi

readonly TIP_COUNTER=0x01800100
readonly TIP_SLOT_0=0x01800101
readonly TIP_SLOT_1=0x01800102
readonly LEASE_COUNTER=0x01800103
readonly LEASE_SLOT_0=0x01800104
readonly LEASE_SLOT_1=0x01800105
readonly TIP_SIZE=180
readonly LEASE_SIZE=140
readonly COUNTER_ATTRIBUTES=0x42040414
readonly SLOT_ATTRIBUTES=0x42041404
readonly DELETE_POLICY_SHA256=47ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f

tpm2_startauthsession -Q -T "$tcti" --policy-session -S "$work_dir/policy.ctx"
tpm2_policycommandcode \
    -Q -T "$tcti" -S "$work_dir/policy.ctx" 0x0000014e \
    -L "$work_dir/delete-policy.bin"
tpm2_flushcontext -Q -T "$tcti" "$work_dir/policy.ctx"
if [[ $(xxd -p -c 32 "$work_dir/delete-policy.bin") != "$DELETE_POLICY_SHA256" ]]; then
    echo "unexpected immutable deletion policy digest" >&2
    exit 1
fi

tpm2_nvdefine -Q -T "$tcti" "$TIP_COUNTER" -C p -s 8 \
    -a "$COUNTER_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$TIP_SLOT_0" -C p -s "$TIP_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$TIP_SLOT_1" -C p -s "$TIP_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
if [[ $mode == cser ]]; then
    tpm2_nvdefine -Q -T "$tcti" "$LEASE_COUNTER" -C p -s 8 \
        -a "$COUNTER_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
    tpm2_nvdefine -Q -T "$tcti" "$LEASE_SLOT_0" -C p -s "$LEASE_SIZE" \
        -a "$SLOT_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
    tpm2_nvdefine -Q -T "$tcti" "$LEASE_SLOT_1" -C p -s "$LEASE_SIZE" \
        -a "$SLOT_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
fi

readonly one=0000000000000001
readonly zero=0000000000000000
readonly prefix_tip=4353455254504d31000101000000000000000001
readonly prefix_lease=4353455254504d31000102000000000000000001
readonly binding_hex="${catalog_hex}${one}${one}"
readonly freshness_hex="${one}${one}${one}${one}${one}"
readonly tip_body_hex="${prefix_tip}${binding_hex}${freshness_hex}${tip_revision_hex}${tip_head_hex}"
readonly lease_body_hex="${prefix_lease}${binding_hex}${freshness_hex}"

make_slot() {
    local body_hex=$1
    local expected_size=$2
    local output=$3
    local body="$work_dir/body.bin"
    local checksum
    printf '%s' "$body_hex" | xxd -r -p >"$body"
    checksum=$(sha256sum "$body" | cut -d ' ' -f1)
    printf '%s%s' "$body_hex" "$checksum" | xxd -r -p >"$output"
    if [[ $(stat -c %s "$output") != "$expected_size" ]]; then
        echo "encoded slot has wrong size: $output" >&2
        exit 1
    fi
}

if [[ $mode == cser ]]; then
    make_slot "$tip_body_hex" "$TIP_SIZE" "$work_dir/tip-genesis.bin"
    make_slot "$lease_body_hex" "$LEASE_SIZE" "$work_dir/lease-genesis.bin"

    # Sequence one selects slot one for each independent protocol.
    tpm2_nvwrite -Q -T "$tcti" -C "$TIP_SLOT_1" \
        -i "$work_dir/tip-genesis.bin" "$TIP_SLOT_1"
    tpm2_nvwrite -Q -T "$tcti" -C "$LEASE_SLOT_1" \
        -i "$work_dir/lease-genesis.bin" "$LEASE_SLOT_1"
    tpm2_nvincrement -Q -T "$tcti" -C "$TIP_COUNTER" "$TIP_COUNTER"
    tpm2_nvincrement -Q -T "$tcti" -C "$LEASE_COUNTER" "$LEASE_COUNTER"
else
    # TPM counters cannot be read while still NV-uninitialized. Give the
    # independent baseline an authenticated revision-zero selector instead of
    # asking the guest to infer blankness from that provider error.
    readonly experiment_magic=4e45584558504e31
    readonly experiment_version=0001
    readonly experiment_reserved=000000000000
    readonly experiment_body_hex="${experiment_magic}${experiment_version}${experiment_reserved}${one}${zero}${zero_head_hex}"
    printf '%s' "$experiment_body_hex" | xxd -r -p >"$work_dir/experiment-body.bin"
    experiment_checksum=$(sha256sum "$work_dir/experiment-body.bin" | cut -d ' ' -f1)
    experiment_padding=
    for _ in {1..84}; do experiment_padding+=00; done
    printf '%s%s%s' "$experiment_body_hex" "$experiment_checksum" "$experiment_padding" \
        | xxd -r -p >"$work_dir/experiment-genesis.bin"
    if [[ $(stat -c %s "$work_dir/experiment-genesis.bin") != "$TIP_SIZE" ]]; then
        echo "encoded experiment genesis has wrong size" >&2
        exit 1
    fi
    tpm2_nvwrite -Q -T "$tcti" -C "$TIP_SLOT_1" \
        -i "$work_dir/experiment-genesis.bin" "$TIP_SLOT_1"
    tpm2_nvincrement -Q -T "$tcti" -C "$TIP_COUNTER" "$TIP_COUNTER"
fi

specifications=(
    "$TIP_COUNTER:$COUNTER_ATTRIBUTES:8" \
    "$TIP_SLOT_0:$SLOT_ATTRIBUTES:$TIP_SIZE" \
    "$TIP_SLOT_1:$SLOT_ATTRIBUTES:$TIP_SIZE"
)
if [[ $mode == cser ]]; then
    specifications+=(
        "$LEASE_COUNTER:$COUNTER_ATTRIBUTES:8"
        "$LEASE_SLOT_0:$SLOT_ATTRIBUTES:$LEASE_SIZE"
        "$LEASE_SLOT_1:$SLOT_ATTRIBUTES:$LEASE_SIZE"
    )
fi
for specification in "${specifications[@]}"; do
    IFS=: read -r index attributes size <<<"$specification"
    public=$(tpm2_nvreadpublic -T "$tcti" "$index")
    observed_attributes=$(awk '
        /^  attributes:/ { in_attributes = 1; next }
        in_attributes && /^    value:/ { print $2; exit }
    ' <<<"$public")
    stable_attributes=$(printf '0x%08x' \
        "$((observed_attributes & ~0x20000000))")
    expected_attributes=$(printf '0x%08x' "$((attributes))")
    if [[ "$stable_attributes" != "$expected_attributes" ]]; then
        echo "unexpected stable NV attributes for $index: $observed_attributes" >&2
        exit 1
    fi
    grep -q "size: $size" <<<"$public"
    grep -qi "$DELETE_POLICY_SHA256" <<<"$public"
done

if [[ $mode == cser ]]; then
for counter in "$TIP_COUNTER" "$LEASE_COUNTER"; do
    tpm2_nvread -Q -T "$tcti" -C "$counter" -s 8 \
        -o "$work_dir/counter.bin" "$counter"
    if [[ $(xxd -p -c 8 "$work_dir/counter.bin") != "$one" ]]; then
        echo "genesis counter is not one: $counter" >&2
        exit 1
    fi
done
tpm2_nvread -Q -T "$tcti" -C "$TIP_SLOT_1" -s "$TIP_SIZE" \
    -o "$work_dir/tip-readback.bin" "$TIP_SLOT_1"
tpm2_nvread -Q -T "$tcti" -C "$LEASE_SLOT_1" -s "$LEASE_SIZE" \
    -o "$work_dir/lease-readback.bin" "$LEASE_SLOT_1"
cmp "$work_dir/tip-genesis.bin" "$work_dir/tip-readback.bin"
cmp "$work_dir/lease-genesis.bin" "$work_dir/lease-readback.bin"
else
    tpm2_nvread -Q -T "$tcti" -C "$TIP_COUNTER" -s 8 \
        -o "$work_dir/counter.bin" "$TIP_COUNTER"
    if [[ $(xxd -p -c 8 "$work_dir/counter.bin") != "$one" ]]; then
        echo "experiment genesis counter is not one" >&2
        exit 1
    fi
    tpm2_nvread -Q -T "$tcti" -C "$TIP_SLOT_1" -s "$TIP_SIZE" \
        -o "$work_dir/experiment-readback.bin" "$TIP_SLOT_1"
    cmp "$work_dir/experiment-genesis.bin" "$work_dir/experiment-readback.bin"
fi

# Stop without TPM2_Shutdown. ORDERLY is clear on every index, so successful
# writes and increments must already be in the NV version.
stop_swtpm

if [[ $mode == cser ]]; then
    echo \
        "CSER_TPM_NV_PROVISION PASS indices=6 selectors=tip+lease sequence=1 tip_revision=$tip_revision tip_head=$tip_head_hex platform_created=true policy_delete=true writeall=true orderly=false fixture_auth=empty swtpm_state_rollbackable=true physical_antirollback=false"
else
    echo \
        "EXPERIMENT_TPM_NV_PROVISION PASS indices=3 selector=tip sequence=1 revision=0 genesis_authenticated=true platform_created=true policy_delete=true writeall=true orderly=false fixture_auth=empty swtpm_state_rollbackable=true physical_antirollback=false"
fi
