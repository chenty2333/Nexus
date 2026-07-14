#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=qemu-stream-capture.sh
source "$script_dir/qemu-stream-capture.sh"

fixture() {
    # Exact write shape observed in GitHub Actions run 29191490459: one guest
    # record spans multiple stdout writes while complete trace records arrive
    # on stderr.
    printf 'RESET Begin generation='
    printf 'virtio_set_status vdev 0x1 val 0\n' >&2
    printf 'virtio_set_status vdev 0x1 val 0\n' >&2
    printf '2 published=true notified=false whole_device=true\n'
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
legacy_log="$work/legacy.log"
serial_log="$work/serial.log"
debug_log="$work/debug.log"

# Prove the fixture exercises the old bug instead of merely testing two
# ordinary complete lines.
fixture >"$legacy_log" 2>&1
if ! grep -Fq \
    'RESET Begin generation=virtio_set_status vdev 0x1 val 0' \
    "$legacy_log"; then
    echo 'stream-capture fixture did not reproduce byte-level 2>&1 interleaving' >&2
    exit 1
fi

capture_qemu_streams "$serial_log" "$debug_log" fixture >/dev/null 2>&1

reset='RESET Begin generation=2 published=true notified=false whole_device=true'
trace='virtio_set_status vdev 0x1 val 0'
if [[ $(grep -cFx "$reset" "$serial_log" || true) -ne 1 ]] ||
    [[ $(wc -l <"$serial_log") -ne 1 ]]; then
    echo 'split capture did not retain the complete guest serial record' >&2
    exit 1
fi
if [[ $(grep -cFx "$trace" "$debug_log" || true) -ne 2 ]] ||
    [[ $(wc -l <"$debug_log") -ne 2 ]]; then
    echo 'split capture did not retain the independent QEMU trace records' >&2
    exit 1
fi
if grep -Fq 'virtio_set_status' "$serial_log" ||
    grep -Fq 'RESET Begin' "$debug_log"; then
    echo 'split capture leaked records across oracle inputs' >&2
    exit 1
fi

failure_fixture() {
    printf 'before-failure\n'
    false
    printf 'after-failure\n'
}
set +e
capture_qemu_streams \
    "$work/failure-serial.log" "$work/failure-debug.log" \
    failure_fixture >/dev/null 2>&1
failure_status=$?
set -e
if [[ "$failure_status" -eq 0 ]] ||
    ! grep -Fxq 'before-failure' "$work/failure-serial.log" ||
    grep -Fq 'after-failure' "$work/failure-serial.log"; then
    echo 'split capture swallowed an intermediate errexit failure' >&2
    exit 1
fi

status_fixture() {
    printf 'status-preserved'
    return 23
}
set +e
capture_qemu_streams \
    "$work/status-serial.log" "$work/status-debug.log" \
    status_fixture >/dev/null 2>&1
status_result=$?
set -e
if [[ "$status_result" -ne 23 ]] ||
    [[ $(<"$work/status-serial.log") != 'status-preserved' ]]; then
    echo 'split capture did not preserve a nonzero command status and partial record' >&2
    exit 1
fi

partial_fixture() {
    printf 'serial-without-newline'
    printf 'debug-without-newline' >&2
}
capture_qemu_streams \
    "$work/partial-serial.log" "$work/partial-debug.log" \
    partial_fixture >/dev/null 2>&1
if [[ $(<"$work/partial-serial.log") != 'serial-without-newline' ]] ||
    [[ $(<"$work/partial-debug.log") != 'debug-without-newline' ]]; then
    echo 'split capture lost a final record without a newline' >&2
    exit 1
fi

long_fixture() {
    head -c 131072 /dev/zero | tr '\0' S
    printf '\n'
    head -c 131072 /dev/zero | tr '\0' D >&2
    printf '\n' >&2
}
capture_qemu_streams \
    "$work/long-serial.log" "$work/long-debug.log" \
    long_fixture >/dev/null 2>&1
if [[ $(wc -c <"$work/long-serial.log") -ne 131073 ]] ||
    [[ $(wc -c <"$work/long-debug.log") -ne 131073 ]] ||
    grep -Fq D "$work/long-serial.log" ||
    grep -Fq S "$work/long-debug.log"; then
    echo 'split capture corrupted or cross-contaminated a long record' >&2
    exit 1
fi

echo 'QEMU split-stream capture assertions: PASS legacy_byte_interleave=reproduced raw_inputs_isolated=true errexit=preserved partial=preserved long_record=preserved'
