#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Provisions the exact development NV layout consumed by core_tpm_anchor.rs.
# The runtime receives only empty per-index fixture auth; platform hierarchy
# authority remains outside the guest. The resulting swtpm directory is test
# evidence only and can be rolled back by its host.

set -euo pipefail

if (($# < 1 || $# > 2)); then
    echo "usage: $0 STATE_DIR [CATALOG_SHA256_HEX]" >&2
    exit 2
fi

for command in swtpm tpm2_nvdefine tpm2_nvreadpublic tpm2_nvread \
    tpm2_nvwrite tpm2_nvincrement tpm2_startauthsession \
    tpm2_policycommandcode tpm2_flushcontext xxd sha256sum cmp stat; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing required command: $command" >&2
        exit 1
    fi
done

state_dir=$1
catalog_hex=${2:-}
if [[ -z $catalog_hex ]]; then
    for _ in {1..32}; do
        catalog_hex+=42
    done
fi
if [[ ! $catalog_hex =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "catalog digest must be exactly 64 hexadecimal characters" >&2
    exit 2
fi
catalog_hex=${catalog_hex,,}
readonly catalog_hex
mkdir -p -- "$state_dir"
if [[ -n $(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "TPM state directory must be empty before provisioning: $state_dir" >&2
    exit 1
fi

work_dir=$(mktemp -d /tmp/cser-tpm-nv-provision.XXXXXX)
swtpm_pid=

cleanup() {
    if [[ -n "$swtpm_pid" ]] && kill -0 "$swtpm_pid" 2>/dev/null; then
        kill -KILL "$swtpm_pid" 2>/dev/null || true
        wait "$swtpm_pid" 2>/dev/null || true
    fi
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

server_socket="$work_dir/server.sock"
control_socket="$server_socket.ctrl"
pid_file="$work_dir/swtpm.pid"
tcti="swtpm:path=$server_socket"

swtpm socket \
    --tpm2 \
    --tpmstate "dir=$state_dir,lock" \
    --ctrl "type=unixio,path=$control_socket" \
    --server "type=unixio,path=$server_socket" \
    --flags not-need-init,startup-clear,disable-auto-shutdown \
    --pid "file=$pid_file" \
    --daemon
swtpm_pid=$(tr -d '\n' <"$pid_file")

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
tpm2_nvdefine -Q -T "$tcti" "$LEASE_COUNTER" -C p -s 8 \
    -a "$COUNTER_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$LEASE_SLOT_0" -C p -s "$LEASE_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$work_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$LEASE_SLOT_1" -C p -s "$LEASE_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$work_dir/delete-policy.bin"

head_hex=
for _ in {1..32}; do
    head_hex+=00
done
readonly head_hex
readonly one=0000000000000001
readonly zero=0000000000000000
readonly prefix_tip=4353455254504d31000101000000000000000001
readonly prefix_lease=4353455254504d31000102000000000000000001
readonly binding_hex="${catalog_hex}${one}${one}"
readonly freshness_hex="${one}${one}${one}${one}${one}"
readonly tip_body_hex="${prefix_tip}${binding_hex}${freshness_hex}${zero}${head_hex}"
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

make_slot "$tip_body_hex" "$TIP_SIZE" "$work_dir/tip-genesis.bin"
make_slot "$lease_body_hex" "$LEASE_SIZE" "$work_dir/lease-genesis.bin"

# Sequence one selects slot one for each independent protocol.
tpm2_nvwrite -Q -T "$tcti" -C "$TIP_SLOT_1" \
    -i "$work_dir/tip-genesis.bin" "$TIP_SLOT_1"
tpm2_nvwrite -Q -T "$tcti" -C "$LEASE_SLOT_1" \
    -i "$work_dir/lease-genesis.bin" "$LEASE_SLOT_1"
tpm2_nvincrement -Q -T "$tcti" -C "$TIP_COUNTER" "$TIP_COUNTER"
tpm2_nvincrement -Q -T "$tcti" -C "$LEASE_COUNTER" "$LEASE_COUNTER"

for specification in \
    "$TIP_COUNTER:$COUNTER_ATTRIBUTES:8" \
    "$LEASE_COUNTER:$COUNTER_ATTRIBUTES:8" \
    "$TIP_SLOT_0:$SLOT_ATTRIBUTES:$TIP_SIZE" \
    "$TIP_SLOT_1:$SLOT_ATTRIBUTES:$TIP_SIZE" \
    "$LEASE_SLOT_0:$SLOT_ATTRIBUTES:$LEASE_SIZE" \
    "$LEASE_SLOT_1:$SLOT_ATTRIBUTES:$LEASE_SIZE"; do
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

# Stop without TPM2_Shutdown. ORDERLY is clear on every index, so successful
# writes and increments must already be in the NV version.
kill -KILL "$swtpm_pid"
wait "$swtpm_pid" 2>/dev/null || true
swtpm_pid=

echo \
    "CSER_TPM_NV_PROVISION PASS indices=6 selectors=tip+lease sequence=1 platform_created=true policy_delete=true writeall=true orderly=false fixture_auth=empty swtpm_state_rollbackable=true physical_antirollback=false"
