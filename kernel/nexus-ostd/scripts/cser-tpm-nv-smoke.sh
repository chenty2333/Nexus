#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Real TPM2-command smoke test for the CSER two-slot/counter protocol.
#
# This deliberately talks to swtpm through the TPM2 tools, kills the emulator
# without TPM2_Shutdown, and reopens the same TPM state.  It proves TPM2 NV
# command shape and crash-window selection.  It does not prove physical
# anti-rollback: a hostile host can copy or roll back the swtpm state directory.

set -euo pipefail

for command in swtpm tpm2_nvdefine tpm2_nvreadpublic tpm2_nvread \
    tpm2_nvwrite tpm2_nvincrement tpm2_nvundefine tpm2_startauthsession \
    tpm2_policycommandcode tpm2_flushcontext tpm2_clear cmp xxd dd; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing required command: $command" >&2
        exit 1
    fi
done

fixture_dir=$(mktemp -d /tmp/cser-tpm-nv-smoke.XXXXXX)
swtpm_pid=

cleanup() {
    if [[ -n "$swtpm_pid" ]] && kill -0 "$swtpm_pid" 2>/dev/null; then
        kill "$swtpm_pid" 2>/dev/null || true
        wait "$swtpm_pid" 2>/dev/null || true
    fi
    rm -rf -- "$fixture_dir"
}
trap cleanup EXIT

server_socket="$fixture_dir/server.sock"
control_socket="$server_socket.ctrl"
pid_file="$fixture_dir/swtpm.pid"
tcti="swtpm:path=$server_socket"

start_swtpm() {
    rm -f -- "$server_socket" "$control_socket" "$pid_file"
    swtpm socket \
        --tpm2 \
        --tpmstate "dir=$fixture_dir,lock" \
        --ctrl "type=unixio,path=$control_socket" \
        --server "type=unixio,path=$server_socket" \
        --flags not-need-init,startup-clear,disable-auto-shutdown \
        --pid "file=$pid_file" \
        --daemon
    swtpm_pid=$(tr -d '\n' <"$pid_file")
}

crash_swtpm() {
    kill -KILL "$swtpm_pid"
    wait "$swtpm_pid" 2>/dev/null || true
    swtpm_pid=
}

counter_hex() {
    local index=$1
    local output=$2
    tpm2_nvread -Q -T "$tcti" -C "$index" -s 8 -o "$output" "$index"
    xxd -p -c 8 "$output" | tr -d '\n'
}

read_slot() {
    local index=$1
    local size=$2
    local output=$3
    tpm2_nvread -Q -T "$tcti" -C "$index" -s "$size" -o "$output" "$index"
}

write_slot() {
    local index=$1
    local input=$2
    tpm2_nvwrite -Q -T "$tcti" -C "$index" -i "$input" "$index"
}

make_slot() {
    local output=$1
    local size=$2
    local marker=$3
    dd if=/dev/zero of="$output" bs="$size" count=1 status=none
    printf '%s' "$marker" | dd of="$output" conv=notrunc status=none
}

assert_counter() {
    local index=$1
    local expected=$2
    local observed
    observed=$(counter_hex "$index" "$fixture_dir/counter.bin")
    if [[ "$observed" != "$expected" ]]; then
        echo "counter $index: expected $expected, observed $observed" >&2
        exit 1
    fi
}

TIP_COUNTER=0x01800100
TIP_SLOT_0=0x01800101
TIP_SLOT_1=0x01800102
LEASE_COUNTER=0x01800103
LEASE_SLOT_0=0x01800104
LEASE_SLOT_1=0x01800105
TIP_SIZE=180
LEASE_SIZE=140
COUNTER_ATTRIBUTES=0x42040414
SLOT_ATTRIBUTES=0x42041404

start_swtpm

# The deletion policy is deliberately bound to NV_Read.  Because
# TPMA_NV_POLICY_DELETE makes deletion require NV_UndefineSpaceSpecial, this
# PolicyCommandCode can never authorize deletion.
tpm2_startauthsession -Q -T "$tcti" --policy-session -S "$fixture_dir/policy.ctx"
tpm2_policycommandcode \
    -Q -T "$tcti" -S "$fixture_dir/policy.ctx" 0x0000014e \
    -L "$fixture_dir/delete-policy.bin"
tpm2_flushcontext -Q -T "$tcti" "$fixture_dir/policy.ctx"
if [[ $(xxd -p -c 32 "$fixture_dir/delete-policy.bin") != \
    47ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f ]]; then
    echo "unexpected immutable deletion policy digest" >&2
    exit 1
fi

tpm2_nvdefine -Q -T "$tcti" "$TIP_COUNTER" -C p -s 8 \
    -a "$COUNTER_ATTRIBUTES" -L "$fixture_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$TIP_SLOT_0" -C p -s "$TIP_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$fixture_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$TIP_SLOT_1" -C p -s "$TIP_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$fixture_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$LEASE_COUNTER" -C p -s 8 \
    -a "$COUNTER_ATTRIBUTES" -L "$fixture_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$LEASE_SLOT_0" -C p -s "$LEASE_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$fixture_dir/delete-policy.bin"
tpm2_nvdefine -Q -T "$tcti" "$LEASE_SLOT_1" -C p -s "$LEASE_SIZE" \
    -a "$SLOT_ATTRIBUTES" -L "$fixture_dir/delete-policy.bin"

for counter in "$TIP_COUNTER" "$LEASE_COUNTER"; do
    public=$(tpm2_nvreadpublic -T "$tcti" "$counter")
    grep -q 'value: 0x42040414' <<<"$public"
    grep -q 'size: 8' <<<"$public"
done
for slot in "$TIP_SLOT_0" "$TIP_SLOT_1"; do
    public=$(tpm2_nvreadpublic -T "$tcti" "$slot")
    grep -q 'value: 0x42041404' <<<"$public"
    grep -q "size: $TIP_SIZE" <<<"$public"
done
for slot in "$LEASE_SLOT_0" "$LEASE_SLOT_1"; do
    public=$(tpm2_nvreadpublic -T "$tcti" "$slot")
    grep -q 'value: 0x42041404' <<<"$public"
    grep -q "size: $LEASE_SIZE" <<<"$public"
done

# Ordinary platform undefine is rejected by TPMA_NV_POLICY_DELETE.  TPM2_Clear
# also leaves platform-created indices intact.
if tpm2_nvundefine -Q -T "$tcti" -C p "$TIP_SLOT_0" \
    >"$fixture_dir/undefine.out" 2>"$fixture_dir/undefine.err"; then
    echo "policy-delete index was unexpectedly removable" >&2
    exit 1
fi
tpm2_clear -Q -T "$tcti" -c p
tpm2_nvreadpublic -Q -T "$tcti" "$TIP_SLOT_0"

make_slot "$fixture_dir/tip-old.bin" "$TIP_SIZE" CSER_TIP_SEQUENCE_1
make_slot "$fixture_dir/tip-new.bin" "$TIP_SIZE" CSER_TIP_SEQUENCE_2
make_slot "$fixture_dir/lease-old.bin" "$LEASE_SIZE" CSER_LEASE_SEQUENCE_1
make_slot "$fixture_dir/lease-new.bin" "$LEASE_SIZE" CSER_LEASE_SEQUENCE_2

# Provisioned genesis: counter value 1 selects slot 1.
write_slot "$TIP_SLOT_1" "$fixture_dir/tip-old.bin"
write_slot "$LEASE_SLOT_1" "$fixture_dir/lease-old.bin"
tpm2_nvincrement -Q -T "$tcti" -C "$TIP_COUNTER" "$TIP_COUNTER"
tpm2_nvincrement -Q -T "$tcti" -C "$LEASE_COUNTER" "$LEASE_COUNTER"
assert_counter "$TIP_COUNTER" 0000000000000001
assert_counter "$LEASE_COUNTER" 0000000000000001

# Crash window A: complete/read-back candidate slot 0 but do not increment.
write_slot "$TIP_SLOT_0" "$fixture_dir/tip-new.bin"
read_slot "$TIP_SLOT_0" "$TIP_SIZE" "$fixture_dir/readback.bin"
cmp "$fixture_dir/tip-new.bin" "$fixture_dir/readback.bin"
crash_swtpm
start_swtpm

# Selector remains 1, so the old slot is still authoritative.
assert_counter "$TIP_COUNTER" 0000000000000001
read_slot "$TIP_SLOT_1" "$TIP_SIZE" "$fixture_dir/selected-old.bin"
cmp "$fixture_dir/tip-old.bin" "$fixture_dir/selected-old.bin"

# Crash window B: one counter increment commits the already complete slot 0.
tpm2_nvincrement -Q -T "$tcti" -C "$TIP_COUNTER" "$TIP_COUNTER"
assert_counter "$TIP_COUNTER" 0000000000000002
crash_swtpm
start_swtpm

# Selector 2 now names slot 0 and survives non-orderly emulator restart.
assert_counter "$TIP_COUNTER" 0000000000000002
read_slot "$TIP_SLOT_0" "$TIP_SIZE" "$fixture_dir/selected-new.bin"
cmp "$fixture_dir/tip-new.bin" "$fixture_dir/selected-new.bin"

# Exercise the independent recovery-lease selector too.
write_slot "$LEASE_SLOT_0" "$fixture_dir/lease-new.bin"
read_slot "$LEASE_SLOT_0" "$LEASE_SIZE" "$fixture_dir/readback-lease.bin"
cmp "$fixture_dir/lease-new.bin" "$fixture_dir/readback-lease.bin"
tpm2_nvincrement -Q -T "$tcti" -C "$LEASE_COUNTER" "$LEASE_COUNTER"
assert_counter "$LEASE_COUNTER" 0000000000000002
crash_swtpm
start_swtpm
read_slot "$LEASE_SLOT_0" "$LEASE_SIZE" "$fixture_dir/selected-lease.bin"
cmp "$fixture_dir/lease-new.bin" "$fixture_dir/selected-lease.bin"

echo \
    "CSER_TPM_NV_SMOKE PASS real_tpm2_commands=true selectors=tip+lease slots=2+2 counters=2 platform_created=true policy_delete=true writeall=true clear_survives=true non_orderly_restart=true preincrement_crash=old postincrement_crash=new qemu_tis=false physical_antirollback=false"
