#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

# Usage: capture_qemu_streams SERIAL_LOG DEBUG_LOG COMMAND [ARG...]
#
# QEMU's stdio chardev is stdout. Cargo diagnostics and QEMU trace events are
# stderr. They must never share one destination file descriptor: the guest
# console may emit one semantic record through several writes, and `2>&1`
# permits a complete trace write to split that record byte-for-byte.
capture_qemu_streams() (
    if (( $# < 3 )); then
        echo 'usage: capture_qemu_streams SERIAL_LOG DEBUG_LOG COMMAND [ARG...]' >&2
        exit 2
    fi

    local serial_log=$1
    local debug_log=$2
    shift 2

    local capture_dir
    capture_dir=$(mktemp -d)
    local serial_pipe="$capture_dir/serial.pipe"
    local debug_pipe="$capture_dir/debug.pipe"
    mkfifo "$serial_pipe" "$debug_pipe"
    : >"$serial_log"
    : >"$debug_log"

    local serial_reader=
    local debug_reader=
    cleanup() {
        if [[ -n "$serial_reader" ]]; then
            kill "$serial_reader" 2>/dev/null || true
            wait "$serial_reader" 2>/dev/null || true
        fi
        if [[ -n "$debug_reader" ]]; then
            kill "$debug_reader" 2>/dev/null || true
            wait "$debug_reader" 2>/dev/null || true
        fi
        rm -rf "$capture_dir"
    }
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    tee "$serial_log" <"$serial_pipe" &
    serial_reader=$!
    tee "$debug_log" <"$debug_pipe" >&2 &
    debug_reader=$!

    # Do not put the target function on the left side of `||` or `if`: Bash
    # would disable errexit throughout that function and could let a failed
    # build continue into QEMU. The explicit subshell owns a fresh `set -e`;
    # only its enclosing capture shell disables errexit long enough to retain
    # the exact exit status and drain both tee readers.
    set +e
    (
        set -e
        "$@"
    ) >"$serial_pipe" 2>"$debug_pipe"
    local command_status=$?
    wait "$serial_reader"
    local serial_status=$?
    serial_reader=
    wait "$debug_reader"
    local debug_status=$?
    debug_reader=

    trap - HUP INT TERM
    cleanup
    trap - EXIT

    if (( command_status != 0 )); then
        exit "$command_status"
    fi
    if (( serial_status != 0 )); then
        exit "$serial_status"
    fi
    exit "$debug_status"
)
