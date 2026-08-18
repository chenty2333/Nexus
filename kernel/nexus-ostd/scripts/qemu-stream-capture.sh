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
    set -e

    local serial_log=$1
    local debug_log=$2
    shift 2

    # EXIT traps run after function-local variables leave scope. This function
    # already owns a subshell, so keep trap state in that isolated shell.
    capture_dir=
    serial_pipe=
    debug_pipe=
    serial_reader=
    debug_reader=
    target_pid=
    capture_dir=$(mktemp -d)
    serial_pipe="$capture_dir/serial.pipe"
    debug_pipe="$capture_dir/debug.pipe"

    terminate_target() {
        local still_running=false
        target_group_live() {
            local process_group process_state found=false
            # ``kill -0 -- -PGID`` reports a group containing only zombies as
            # live.  Inspect the group states so cleanup can reap the wrapper
            # without treating zombie-only residue as an unkillable helper.
            while read -r process_group process_state; do
                [[ $process_group == "$target_pid" ]] || continue
                found=true
                [[ $process_state == Z* ]] || return 0
            done < <(ps -eo pgid=,stat= 2>/dev/null || true)
            [[ $found == true ]] || return 1
            return 1
        }
        if [[ -n ${target_pid:-} ]]; then
            # `set -m` below gives the asynchronous target wrapper its own
            # process group.  Kill the group first so QEMU helpers cannot
            # survive a signal delivered to this capture shell.
            if target_group_live; then
                kill -- "-$target_pid" 2>/dev/null || kill "$target_pid" 2>/dev/null || true
            fi
            for _ in {1..20}; do
                if ! target_group_live; then
                    still_running=false
                    break
                fi
                still_running=true
                sleep 0.05
            done
            if [[ $still_running == true ]]; then
                kill -KILL -- "-$target_pid" 2>/dev/null || kill -KILL "$target_pid" 2>/dev/null || true
                for _ in {1..20}; do
                    if ! target_group_live; then
                        still_running=false
                        break
                    fi
                    sleep 0.05
                done
            fi
            if [[ $still_running == true ]]; then
                echo 'qemu split-stream capture: target process group did not stop after bounded cleanup' >&2
            fi
            # Reap only after the bounded liveness check.  If a hostile target
            # remains unkillable, `wait` must not turn signal cleanup into an
            # unbounded hang.
            # Reap the wrapper when the group is gone, or when the group is
            # visible only as a zombie: `kill -0` remains true for a zombie,
            # but the parent-side wait is what removes that process-table
            # entry.  A still-running unkillable target is reported without
            # turning signal handling into an unbounded wait.
            target_state=
            if [[ -r /proc/$target_pid/stat ]]; then
                target_state=$(sed 's/.*) //' "/proc/$target_pid/stat" | cut -c1)
            fi
            if [[ $still_running == false || $target_state == Z ]]; then
                wait "$target_pid" 2>/dev/null || true
            fi
            target_pid=
        fi
    }

    cleanup() {
        # The target owns the FIFO writers. Stop it before the readers so a
        # signal cannot strand a writer blocked on a FIFO with no tee.
        terminate_target
        if [[ -n ${serial_reader:-} ]]; then
            kill "$serial_reader" 2>/dev/null || true
            wait "$serial_reader" 2>/dev/null || true
        fi
        if [[ -n ${debug_reader:-} ]]; then
            kill "$debug_reader" 2>/dev/null || true
            wait "$debug_reader" 2>/dev/null || true
        fi
        if [[ -n ${capture_dir:-} ]]; then
            rm -rf "$capture_dir"
        fi
    }
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    mkfifo "$serial_pipe" "$debug_pipe"
    : >"$serial_log"
    : >"$debug_log"

    # QEMU's stdio chardev must never inherit backpressure from the caller's
    # terminal or CI log consumer. Drain both FIFOs directly to files while
    # QEMU is live; bounded diagnostics are replayed only after it exits.
    tee "$serial_log" <"$serial_pipe" >/dev/null &
    serial_reader=$!
    tee "$debug_log" <"$debug_pipe" >/dev/null &
    debug_reader=$!

    # Enable job control in this non-interactive shell so the asynchronous
    # target wrapper receives its own process group. Do not put the target
    # function on the left side of `||` or `if`: Bash would disable errexit
    # throughout that function and could let a failed build continue into
    # QEMU. The explicit subshell owns a fresh `set -e`; only its enclosing
    # capture shell disables errexit long enough to retain the exact exit
    # status and drain both tee readers.
    set -m
    set +e
    (
        set -e
        "$@"
    ) >"$serial_pipe" 2>"$debug_pipe" &
    target_pid=$!
    wait "$target_pid"
    local command_status=$?
    # A target can reap its direct wrapper while a helper inherited one of
    # the FIFO writers.  Terminate the complete PGID before waiting for either
    # reader, otherwise tee can wait forever for EOF on the inherited writer.
    terminate_target
    wait "$serial_reader"
    local serial_status=$?
    serial_reader=
    wait "$debug_reader"
    local debug_status=$?
    debug_reader=
    target_pid=
    set +m

    trap - HUP INT TERM
    cleanup
    trap - EXIT

    if (( command_status != 0 || serial_status != 0 || debug_status != 0 )); then
        {
            echo "QEMU split-stream capture failed: command_status=$command_status serial_reader_status=$serial_status debug_reader_status=$debug_status"
            echo "serial_log=$serial_log"
            echo '--- serial tail (last 65536 bytes) ---'
            tail -c 65536 "$serial_log" || true
            echo
            echo "debug_log=$debug_log"
            echo '--- QEMU debug tail (last 65536 bytes) ---'
            tail -c 65536 "$debug_log" || true
            echo
        } >&2
    fi

    if (( command_status != 0 )); then
        exit "$command_status"
    fi
    if (( serial_status != 0 )); then
        exit "$serial_status"
    fi
    exit "$debug_status"
)
