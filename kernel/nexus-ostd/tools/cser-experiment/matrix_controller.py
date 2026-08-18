#!/usr/bin/env python3
"""Host-controlled crash trial controller and common JSONL metric writer."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from matrix_protocol import (BarrierProtocolError, UART_WRITE_INTER_CHUNK_SECONDS, barrier_ack,
                             config_response, paced_sendall, parse_barrier, parse_config_hello)

SCHEMA_VERSION = 2
VARIANTS = frozenset(("cser", "baseline"))
_CID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_RECOVERY_METRICS_PREFIX = "TOOL_DMA_RECOVERY_METRICS "
_RECOVERY_DEFERRED_PREFIX = "TOOL_DMA_DEFERRED "
_MAX_RECOVERY_SERIAL_LINE_BYTES = 64 * 1024
_RECOVERY_STDERR_TAIL_BYTES = 4096
_PROCESS_KILL_ATTEMPTS = 3
_PROCESS_KILL_WAIT_SECONDS = 0.2
_CONTAINER_KILL_ATTEMPTS = 3
_CONTAINER_KILL_TIMEOUT_SECONDS = 5
# Legacy fake-guest compatibility only. Real QEMU rows always receive a fresh
# host-generated identity through the explicit COM3 configuration handshake.
_CURRENT_GUEST_RUN_ID = "42" * 16
_TERMINAL_COUNTER_FIELDS = (
    "retired_by_evidence",
    "retained_claims",
)


def _write_stage_timings(trial_dir: Path, stages: dict[str, int]) -> None:
    """Persist controller-owned monotonic stage boundaries for one trial."""
    path = trial_dir / "stage-timings.json"
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps({"schema_version": 1, "clock": "monotonic_ns", "stages": stages}, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _validate_dma_gate(metrics: dict[str, Any], field: str, *, retained: bool, result: str) -> None:
    """Validate an optional exact-coordinate, read-only core gate receipt."""
    value = metrics.get(field)
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != {
        "resource_id_raw", "generation", "retained", "gate_result",
        "revision_unchanged", "head_unchanged",
    }:
        raise ValueError(f"recovery terminal metric {field} has invalid schema")
    if any(isinstance(value[name], bool) or not isinstance(value[name], int) or value[name] <= 0
           for name in ("resource_id_raw", "generation")):
        raise ValueError(f"recovery terminal metric {field} lacks an exact coordinate")
    if (value["retained"], value["gate_result"]) != (retained, result):
        raise ValueError(f"recovery terminal metric {field} contradicts gate state")
    if value["revision_unchanged"] is not True or value["head_unchanged"] is not True:
        raise ValueError(f"recovery terminal metric {field} is not read-only")


def _validate_dma_gate_pair(metrics: dict[str, Any]) -> None:
    retained, reusable = metrics.get("dma_retained_gate"), metrics.get("dma_reusable_gate")
    if retained is not None and reusable is not None and (
        retained["resource_id_raw"], retained["generation"]
    ) != (reusable["resource_id_raw"], reusable["generation"]):
        raise ValueError("DMA gate receipts must bind the same resource coordinate")


def _validate_dma_quiescence(metrics: dict[str, Any]) -> None:
    value = metrics.get("dma_quiescence_evidence")
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "run_id", "resource_id_raw", "generation", "reset", "irq_drained", "iotlb",
    }:
        raise ValueError("DMA quiescence evidence has invalid schema")
    if value["schema_version"] != 1 or value["run_id"] != metrics.get("run_id"):
        raise ValueError("DMA quiescence evidence has invalid version or run binding")
    if any(isinstance(value[name], bool) or not isinstance(value[name], int) or value[name] <= 0
           for name in ("resource_id_raw", "generation")):
        raise ValueError("DMA quiescence evidence lacks an exact coordinate")
    if any(value[name] is not True for name in ("reset", "irq_drained", "iotlb")):
        raise ValueError("DMA quiescence evidence lacks a complete verified closure")
    reusable = metrics.get("dma_reusable_gate")
    if reusable is None or (value["resource_id_raw"], value["generation"]) != (
        reusable["resource_id_raw"], reusable["generation"]
    ):
        raise ValueError("DMA quiescence evidence must bind the admitted gate coordinate")


def _read_one_frame(client: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= 1024:
        # Do not consume a following control/barrier frame in the same socket
        # read: COM3 is a byte stream and a guest may write hello+barrier
        # back-to-back once the host answers promptly.
        block = client.recv(1)
        if not block:
            break
        data.extend(block)
        if block == b"\n":
            return bytes(data)
    preview = bytes(data[:64]).hex()
    raise BarrierProtocolError(
        f"truncated or oversized barrier: bytes={len(data)} prefix_hex={preview}"
    )


def _connect_qemu_server(socket_path: Path, timeout_seconds: float) -> socket.socket:
    """Connect to QEMU's sole COM3 Unix-socket server, retrying its startup."""
    _validate_timeout(timeout_seconds, "QEMU connection timeout")
    deadline = __import__("time").monotonic() + timeout_seconds
    last_error: OSError | None = None
    while __import__("time").monotonic() < deadline:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(socket_path))
            client.settimeout(timeout_seconds)
            return client
        except OSError as exc:
            client.close(); last_error = exc
            __import__("time").sleep(0.05)
    raise RuntimeError(f"QEMU COM3 server unavailable at {socket_path}: {last_error}")


def _validate_timeout(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{label} must be finite and positive")
    return float(value)


def observe_barriers(
    client: socket.socket, run_id: str, target_cutpoint: int, *, pass_through: bool,
    catalog_digest: str | None = None, namespace_id: str | None = None, authority_id: str | None = None, effect_id: str | None = None,
    uart_pace_seconds: float = 0.0,
) -> bool:
    """ACK exactly the in-order prefix, then close at the selected target.

    The guest's numeric cutpoints are a closed sequence 1..7.  A duplicate,
    skipped, reversed, or unexpected value is fail-closed instead of becoming
    an accidental timing-based crash point.
    """
    if not 1 <= target_cutpoint <= 7:
        raise BarrierProtocolError("target cutpoint is outside the seven-cutpoint matrix")
    if catalog_digest is not None:
        if namespace_id is None or authority_id is None or effect_id is None:
            raise BarrierProtocolError("configuration requires endpoint namespace, authority, and effect")
        parse_config_hello(_read_one_frame(client))
        paced_sendall(client, config_response(run_id, catalog_digest, namespace_id, authority_id, effect_id), inter_chunk_seconds=uart_pace_seconds)
    expected = 1
    while True:
        observed = parse_barrier(_read_one_frame(client), expected_run_id=run_id)
        print(f"matrix controller: observed cutpoint={observed}", file=sys.stderr, flush=True)
        if observed != expected:
            raise BarrierProtocolError(f"unexpected cutpoint {observed}; expected {expected}")
        if observed == target_cutpoint:
            if pass_through:
                paced_sendall(client, barrier_ack(run_id, observed), inter_chunk_seconds=uart_pace_seconds)
                return True
            # Closing before the destructive action is intentional: a target
            # barrier must leave the guest blocked/notified only by QEMU death.
            client.shutdown(socket.SHUT_RDWR)
            return False
        paced_sendall(client, barrier_ack(run_id, observed), inter_chunk_seconds=uart_pace_seconds)
        expected += 1


def _safe_child_path(trial_dir: Path, candidate: Path) -> Path:
    resolved_trial, resolved = trial_dir.resolve(), candidate.resolve()
    if resolved != resolved_trial and resolved_trial not in resolved.parents:
        raise ValueError(f"path escapes trial directory: {candidate}")
    return resolved


def _guest_metrics(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid guest metrics: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("guest metrics must be a JSON object")
    return value


def _recovery_metrics_from_serial_lines(
    lines: Iterable[bytes], *, variant: str, run_id: str
) -> dict[str, Any]:
    """Read the one terminal receipt emitted by the recovery guest itself.

    The real-QEMU path intentionally does not trust an arbitrary host-side
    metrics file.  A launcher may capture serial output, but the terminal and
    invariant assertions must be a guest marker from the recovered kernel.
    """
    marker: str | None = None
    deferred: str | None = None
    for raw_line in lines:
        try:
            decoded = raw_line.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError(f"recovery serial is not UTF-8: {exc}") from exc
        # QEMU's serial stream may use a bare carriage return before a guest
        # line.  `bytes.splitlines()` was the original accepted framing, so
        # preserve that behavior while the outer file iterator keeps memory
        # bounded by the LF-delimited chunk limit.
        for line in decoded.splitlines():
            if line.startswith(_RECOVERY_METRICS_PREFIX):
                if marker is not None or deferred is not None:
                    raise ValueError("recovery serial must contain one terminal or deferred marker")
                marker = line[len(_RECOVERY_METRICS_PREFIX):]
            if line.startswith(_RECOVERY_DEFERRED_PREFIX):
                if marker is not None or deferred is not None:
                    raise ValueError("recovery serial must contain one terminal or deferred marker")
                deferred = line[len(_RECOVERY_DEFERRED_PREFIX):]
    if marker is None and deferred is None:
        raise ValueError("recovery serial must contain one terminal or deferred marker")
    try:
        value = json.loads(marker if marker is not None else deferred)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid recovery serial metrics: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("recovery serial metrics must be a JSON object")
    if value.get("variant") != variant or value.get("run_id") != run_id:
        raise ValueError("recovery serial metrics identity mismatch")
    if deferred is not None:
        if value.get("terminal") is not False or value.get("claims_retained") is not True or value.get("post_authorized") is not False:
            raise ValueError("deferred recovery receipt must retain claims and forbid POST")
        return value
    if value.get("terminal") is not True or value.get("invariants_ok") is not True:
        raise ValueError("recovery guest did not publish terminal invariants_ok metrics")
    _require_terminal_metrics(value)
    return value


def _recovery_metrics_from_serial(stdout: bytes, *, variant: str, run_id: str) -> dict[str, Any]:
    """Parse bounded in-memory serial used by focused protocol unit tests."""
    return _recovery_metrics_from_serial_lines(stdout.splitlines(), variant=variant, run_id=run_id)


def _recovery_metrics_from_serial_log(path: Path, *, variant: str, run_id: str) -> dict[str, Any]:
    """Parse the terminal serial receipt with bounded line buffering.

    Launcher output belongs in the trial log, not an unbounded controller
    buffer.  A malformed serial sender cannot make recovery parsing retain a
    giant line in host memory.
    """
    def bounded_lines() -> Iterable[bytes]:
        with path.open("rb") as handle:
            while True:
                line = handle.readline(_MAX_RECOVERY_SERIAL_LINE_BYTES + 1)
                if not line:
                    return
                if len(line) > _MAX_RECOVERY_SERIAL_LINE_BYTES:
                    raise ValueError(
                        f"recovery serial line exceeds {_MAX_RECOVERY_SERIAL_LINE_BYTES} byte limit"
                    )
                yield line

    return _recovery_metrics_from_serial_lines(bounded_lines(), variant=variant, run_id=run_id)


def _require_terminal_metrics(metrics: dict[str, Any]) -> None:
    """Require the measured terminal counters, rather than host-side guesses.

    The two counters are part of the recovered guest's execution receipt: the
    experiment has no valid result if a terminal guest omits either.  `bool` is
    deliberately not accepted even though Python makes it an `int` subtype.

    This bounded matrix does *not* measure wall-clock reconciliation latency or
    contention-driven gate rejections.  It must say so explicitly rather than
    recording a convenient-looking zero.  A reconciliation step count remains
    a useful non-temporal recovery observation.
    """
    for field in _TERMINAL_COUNTER_FIELDS:
        value = metrics.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"recovery terminal metric {field} must be a non-negative integer")
    for field in ("reconciliation_delay_ms", "gate_rejections"):
        if field not in metrics or metrics[field] is not None:
            raise ValueError(f"recovery terminal metric {field} must be explicitly null when unmeasured")
    steps = metrics.get("reconciliation_steps")
    if isinstance(steps, bool) or not isinstance(steps, int) or steps < 0:
        raise ValueError("recovery terminal metric reconciliation_steps must be a non-negative integer")
    if metrics.get("reconciliation_delay_unit") != "unmeasured":
        raise ValueError("recovery terminal metric reconciliation_delay_unit must be unmeasured")
    _validate_dma_gate(metrics, "dma_retained_gate", retained=True, result="rejected_retained")
    _validate_dma_gate(metrics, "dma_reusable_gate", retained=False, result="admitted_reusable")
    _validate_dma_gate_pair(metrics)
    _validate_dma_quiescence(metrics)


def _validate_real_qemu_launcher(args: argparse.Namespace) -> None:
    """Keep fake/unit-test guests out of the dedicated QEMU campaign.

    This is a workflow boundary, not a claim that a pathname authenticates a
    VM.  The initial boot is authenticated by the COM3 barrier; recovery is
    accepted only through the recovered guest's serial receipt.
    """
    if args.recovery_guest is None or not args.recovery_output_metrics:
        raise ValueError("real QEMU trials require a recovery launcher and serial recovery metrics")
    expected = Path(__file__).with_name("qemu_boot.sh").resolve()
    if Path(args.guest[0]).resolve() != expected or args.recovery_guest.resolve() != expected:
        raise ValueError("real QEMU trials must use the dedicated qemu_boot.sh launcher for both boots")
    if args.catalog_digest is None:
        raise ValueError("real QEMU trials require an explicit catalog digest for COM3 configuration")
    if args.namespace_id is None or args.authority_id is None or args.effect_id is None:
        raise ValueError("real QEMU trials require endpoint namespace, authority, and effect configuration")
    # qemu_boot's OSDK invocation has a 90-second internal timeout.  The
    # controller's envelope must leave room to collect its terminal receipt
    # and logs instead of racing that inner timeout.
    if args.recovery_timeout_seconds <= 90:
        raise ValueError(
            "real QEMU recovery stage requires --recovery-timeout-seconds greater than the internal 90s launcher timeout"
        )


def _kill_process_group(process: subprocess.Popen[bytes], *, stage: str = "launcher", force: bool = False) -> None:
    """Kill and reap a launcher process group with a bounded retry budget.

    A launcher can outlive its direct child (QEMU, ``timeout``, and swtpm are
    all present in the real path), so a single ``killpg`` call is not enough
    evidence that the stage is gone.  Retry transient races, then fail
    explicitly rather than allowing cleanup to silently leak a process.
    """
    def has_live_group_member() -> bool:
        """Return whether this PGID contains a non-zombie process.

        ``killpg(pgid, 0)`` considers zombie entries live.  The launcher can
        reap its own leader while a same-PGID helper remains, so the leader's
        ``poll()`` state is not sufficient evidence for cleanup.
        """
        proc_root = Path("/proc")
        try:
            entries = list(proc_root.iterdir())
        except OSError:
            entries = []
        found_procfs_member = False
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                fields = entry.joinpath("stat").read_text(encoding="ascii").rpartition(")")[2].split()
                # The fields after the final comm delimiter start at stat's
                # state (field 3); process group is the third value there.
                state, group = fields[0], fields[2]
            except (OSError, UnicodeError, IndexError):
                continue
            if group != str(process.pid):
                continue
            found_procfs_member = True
            if state != "Z":
                return True
        if found_procfs_member:
            return False
        # Keep a portable fallback for hosts without procfs.  On Linux the
        # procfs branch above is what filters zombie-only residue.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            return True
        return process.poll() is None

    failures: list[str] = []
    for attempt in range(1, _PROCESS_KILL_ATTEMPTS + 1):
        if not has_live_group_member() and process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            # The group leader may have exited while its child is being
            # reaped.  A bounded wait distinguishes that race from a live
            # process whose group could not be signalled.
            try:
                process.wait(timeout=_PROCESS_KILL_WAIT_SECONDS)
                if not has_live_group_member():
                    return
                failures.append("process group remained after leader exit")
            except subprocess.TimeoutExpired:
                failures.append("process group disappeared but launcher remained")
        except OSError as exc:
            failures.append(f"attempt {attempt}: {exc}")
        try:
            process.wait(timeout=_PROCESS_KILL_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            failures.append(f"attempt {attempt}: launcher still running")
            continue
        # A normal launcher exit can leave a helper in the same dedicated
        # session.  Verify the complete group in both normal and forced modes;
        # only non-zombie members keep cleanup incomplete.
        if not has_live_group_member():
            return
        if force:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            except OSError as exc:
                failures.append(f"attempt {attempt}: process-group probe failed: {exc}")
            else:
                failures.append(f"attempt {attempt}: process group still running")
                continue
        failures.append(f"attempt {attempt}: process group still running")
    raise RuntimeError(
        f"{stage} process group did not stop after {_PROCESS_KILL_ATTEMPTS} bounded kill attempts"
        + (f" ({'; '.join(failures)})" if failures else "")
    )


def _finish_process_capture(
    process: subprocess.Popen[bytes], stdout_log: Any, stderr_log: Any, *, stage: str
) -> None:
    """Close directly-streamed launcher logs after the process group has stopped.

    QEMU and its launcher can produce more than a pipe buffer before the first
    COM3 barrier.  Keeping either stream in an unread PIPE would therefore let
    launcher logging prevent the very crash point that the controller is
    waiting to observe.  The file descriptors below are inherited directly by
    the child and kernel-backed files continuously consume the output.
    """
    try:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_process_group(process, stage=stage)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"{stage} launcher remained after bounded process-group cleanup") from exc
    except subprocess.SubprocessError as exc:
        raise RuntimeError(f"{stage} launcher did not stop after termination: {exc}") from exc
    finally:
        stdout_log.close()
        stderr_log.close()


def _run_recovery_launcher(
    command: Path, *, env: dict[str, str], trial_dir: Path, timeout_seconds: float
) -> tuple[int, Path, str]:
    """Run recovery with streaming logs and a recovery-specific envelope."""
    timeout_seconds = _validate_timeout(timeout_seconds, "recovery timeout")
    stdout_path = trial_dir / "recovery.stdout.log"
    stderr_path = trial_dir / "recovery.stderr.log"
    with stdout_path.open("wb") as stdout_log, stderr_path.open("wb") as stderr_log:
        process = subprocess.Popen(
            command,
            env=env,
            start_new_session=True,
            stdout=stdout_log,
            stderr=stderr_log,
        )
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process, stage="recovery", force=True)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired as wait_exc:
                raise RuntimeError("recovery stage launcher did not stop after timeout termination") from wait_exc
            raise RuntimeError(
                f"recovery stage exceeded its {timeout_seconds:g}s envelope"
            ) from exc
        except BaseException:
            _kill_process_group(process, stage="recovery", force=True)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            raise
        # A launcher that returns while leaving a helper behind is not a
        # complete recovery.  The dedicated process group makes this cleanup
        # exact even after the leader has reaped itself.
        _kill_process_group(process, stage="recovery", force=True)
    # The serial terminal receipt is parsed only after the launcher exits. No
    # child PIPE is involved, and only a bounded tail is read for diagnostics.
    with stderr_path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        handle.seek(max(0, handle.tell() - _RECOVERY_STDERR_TAIL_BYTES), os.SEEK_SET)
        stderr_tail = handle.read(_RECOVERY_STDERR_TAIL_BYTES).decode("utf-8", errors="replace").strip()
    return returncode, stdout_path, stderr_tail


def _kill_container(cid_path: Path, command_prefix: list[str]) -> str:
    try:
        cid = cid_path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError(f"container cid unavailable: {exc}") from exc
    if not _CID.fullmatch(cid):
        raise RuntimeError("invalid container cid")
    failures: list[str] = []
    for attempt in range(1, _CONTAINER_KILL_ATTEMPTS + 1):
        try:
            completed = subprocess.run(
                command_prefix + [cid], check=False, capture_output=True, text=True,
                timeout=_CONTAINER_KILL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            failures.append(f"attempt {attempt}: timeout after {_CONTAINER_KILL_TIMEOUT_SECONDS}s")
            continue
        if completed.returncode == 0:
            return cid
        failures.append(f"attempt {attempt}: exit {completed.returncode}: {completed.stderr.strip()}")
    raise RuntimeError(
        f"container kill failed after {_CONTAINER_KILL_ATTEMPTS} bounded attempts for {cid}: "
        + "; ".join(failures)
    )


def _metric(*, run_id: str, variant: str, trial: int, cutpoint: str, cutpoint_id: int, crash_method: str,
            trial_dir: Path, media: list[Path], guest: dict[str, Any], recovery: dict[str, Any] | None,
            recovery_metrics_authoritative: bool, container_id: str | None) -> dict[str, Any]:
    # Null is intentional: a finite horizon cannot establish permanence or an
    # administrative disposition path that this experiment does not implement.
    if recovery_metrics_authoritative:
        if recovery is None:
            raise ValueError("authoritative recovery metrics requested without a recovery receipt")
        # Real QEMU results have exactly one authority for these counters: the
        # terminal receipt emitted after recovery.  Never substitute the
        # initial guest's host-captured file, which necessarily predates it.
        # `_metric` is also used by focused controller tests with a validated
        # terminal counter shape but without the serial marker's redundant
        # `terminal: true`.  Only an explicit false is nonterminal here.
        if recovery.get("terminal") is not False:
            _require_terminal_metrics(recovery)
            metric_source = recovery
            metrics_source = "recovery_terminal"
            completion_state = "recovery_verified"
        else:
            metric_source = {}
            metrics_source = "recovery_deferred"
            completion_state = "deferred_retained"
    else:
        # Keep generic controller/fake-guest users working.  They do not claim
        # that this optional host file is an authentic terminal measurement.
        metric_source = guest
        metrics_source = "initial_guest_file"
        completion_state = "recovery_verified" if recovery is not None else "crashed_unrecovered"
    return {
        "schema_version": SCHEMA_VERSION, "run_id": run_id, "variant": variant,
        "trial": trial, "cutpoint": cutpoint, "cutpoint_id": cutpoint_id, "crash_method": crash_method,
        "barrier_observed": True, "barrier_acknowledged": False, "trial_dir": str(trial_dir),
        "completion_state": completion_state,
        "retention_horizon": "bounded_observation", "permanent_retention": None,
        "admin_disposition": None, "admin_disposition_count": None,
        "metrics_source": metrics_source,
        "retired_by_evidence": metric_source.get("retired_by_evidence"),
        "retained_claims": metric_source.get("retained_claims"),
        "reconciliation_delay_ms": metric_source.get("reconciliation_delay_ms"),
        "gate_rejections": metric_source.get("gate_rejections"),
        "reconciliation_steps": metric_source.get("reconciliation_steps"),
        "reconciliation_delay_unit": metric_source.get("reconciliation_delay_unit"),
        "dma_retained_gate": metric_source.get("dma_retained_gate"),
        "dma_reusable_gate": metric_source.get("dma_reusable_gate"),
        "container_id": container_id, "media": [str(path) for path in media], "guest": guest, "recovery": recovery,
    }


def run_trial(args: argparse.Namespace) -> dict[str, Any]:
    if args.variant not in VARIANTS:
        raise ValueError("variant must be cser or baseline")
    args.timeout_seconds = _validate_timeout(args.timeout_seconds, "QEMU timeout")
    args.recovery_timeout_seconds = _validate_timeout(args.recovery_timeout_seconds, "recovery timeout")
    trial_dir = args.trial_dir.resolve()
    if trial_dir.exists() and not args.prepared_trial_dir:
        raise ValueError(f"trial directory already exists: {trial_dir}")
    if args.prepared_trial_dir:
        if not trial_dir.is_dir():
            raise ValueError(f"prepared trial path is not a directory: {trial_dir}")
    else:
        trial_dir.mkdir(parents=True, mode=0o700)
    cid_path, metrics_path = trial_dir / "container.cid", trial_dir / "guest_metrics.json"
    recovery_metrics_path = trial_dir / "recovery_metrics.json"
    socket_path = args.barrier_socket.resolve()
    media = [_safe_child_path(trial_dir, Path(value)) for value in args.media]
    if any(not item.exists() for item in media):
        raise ValueError("trial media missing")
    env = os.environ.copy()
    env.update({"CSER_EXPERIMENT_RUN_ID": args.run_id, "CSER_EXPERIMENT_CUTPOINT": str(args.cutpoint_id),
                "CSER_EXPERIMENT_BARRIER_SOCKET": str(socket_path), "CSER_EXPERIMENT_TRIAL_DIR": str(trial_dir),
                "CSER_EXPERIMENT_GUEST_METRICS": str(metrics_path), "CSER_EXPERIMENT_CID_FILE": str(cid_path),
                "CSER_EXPERIMENT_VARIANT": args.variant})
    if args.catalog_digest is not None:
        env["CSER_EXPERIMENT_CATALOG_DIGEST"] = args.catalog_digest
    if args.namespace_id is not None:
        env["CSER_EXPERIMENT_NAMESPACE_ID"] = args.namespace_id
    if args.authority_id is not None:
        env["CSER_EXPERIMENT_AUTHORITY_ID"] = args.authority_id
    if args.effect_id is not None:
        env["CSER_EXPERIMENT_EFFECT_ID"] = args.effect_id
    initial_stdout = (trial_dir / "initial.stdout.log").open("wb")
    initial_stderr = (trial_dir / "initial.stderr.log").open("wb")
    stage_timings: dict[str, int] = {"initial_start_ns": time.monotonic_ns()}
    _write_stage_timings(trial_dir, stage_timings)
    try:
        process = subprocess.Popen(
            args.guest,
            env=env,
            start_new_session=True,
            stdout=initial_stdout,
            stderr=initial_stderr,
        )
    except BaseException:
        initial_stdout.close()
        initial_stderr.close()
        raise
    crash_method, container_id = "pid_sigkill", None
    initial_captured = False
    try:
        with _connect_qemu_server(socket_path, args.timeout_seconds) as client:
            observe_barriers(
                client, args.run_id, args.cutpoint_id, pass_through=args.pass_through,
                catalog_digest=args.catalog_digest,
                namespace_id=args.namespace_id, authority_id=args.authority_id, effect_id=args.effect_id,
                uart_pace_seconds=UART_WRITE_INTER_CHUNK_SECONDS if args.real_qemu else 0.0,
            )
        if args.kill_mode == "pid":
            _kill_process_group(process)
        else:
            container_id = _kill_container(cid_path, args.container_kill_command)
            crash_method = "container_kill"
            _kill_process_group(process)  # kill any launcher outside the container too
        _finish_process_capture(process, initial_stdout, initial_stderr, stage="initial")
        initial_captured = True
        stage_timings["initial_end_ns"] = time.monotonic_ns()
        _write_stage_timings(trial_dir, stage_timings)
        recovery = None
        if args.recovery_guest is not None:
            recovery_env = env.copy()
            recovery_env.update({"CSER_EXPERIMENT_PHASE": "recovery", "CSER_EXPERIMENT_RECOVERY_METRICS": str(recovery_metrics_path)})
            stage_timings["recovery_start_ns"] = time.monotonic_ns()
            _write_stage_timings(trial_dir, stage_timings)
            recovery_returncode, recovery_stdout_log, recovery_stderr = _run_recovery_launcher(
                args.recovery_guest,
                env=recovery_env,
                trial_dir=trial_dir,
                timeout_seconds=args.recovery_timeout_seconds,
            )
            stage_timings["recovery_end_ns"] = time.monotonic_ns()
            _write_stage_timings(trial_dir, stage_timings)
            if recovery_returncode != 0:
                raise RuntimeError(
                    f"recovery stage exited {recovery_returncode}: {recovery_stderr}"
                )
            recovery = (
                _recovery_metrics_from_serial_log(recovery_stdout_log, variant=args.variant, run_id=args.run_id)
                if args.recovery_output_metrics
                else _guest_metrics(recovery_metrics_path)
            )
            if not args.recovery_output_metrics and (
                recovery.get("terminal") is not True or recovery.get("invariants_ok") is not True
            ):
                raise RuntimeError("recovery guest did not publish terminal invariants_ok metrics")
        return _metric(run_id=args.run_id, variant=args.variant, trial=args.trial, cutpoint=args.cutpoint, cutpoint_id=args.cutpoint_id,
                       crash_method=crash_method, trial_dir=trial_dir, media=media,
                       guest=_guest_metrics(metrics_path), recovery=recovery,
                       recovery_metrics_authoritative=args.recovery_output_metrics,
                       container_id=container_id)
    except BaseException as original:
        cleanup_errors: list[BaseException] = []
        # A container kill is an authority boundary separate from the host
        # launcher process group.  Always retry the exact recorded container
        # on an exception path; killing only the launcher can leave QEMU (and
        # its attached media) running outside this controller.
        if args.kill_mode == "container" and container_id is None:
            try:
                container_id = _kill_container(cid_path, args.container_kill_command)
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            _kill_process_group(process, stage="initial")
        except BaseException as exc:
            cleanup_errors.append(exc)
        if not initial_captured:
            try:
                _finish_process_capture(process, initial_stdout, initial_stderr, stage="initial")
                stage_timings["initial_end_ns"] = time.monotonic_ns()
                _write_stage_timings(trial_dir, stage_timings)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            details = "; ".join(str(error) for error in cleanup_errors)
            raise RuntimeError(f"matrix cleanup failed explicitly after {type(original).__name__}: {details}") from cleanup_errors[0]
        raise
def append_jsonl(path: Path, metric: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(metric, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", required=True, choices=sorted(VARIANTS)); parser.add_argument("--run-id", required=True)
    parser.add_argument("--catalog-digest", default=None)
    parser.add_argument("--namespace-id", default=None)
    parser.add_argument("--authority-id", default=None)
    parser.add_argument("--effect-id", default=None)
    parser.add_argument("--trial", required=True, type=int); parser.add_argument("--cutpoint", required=True); parser.add_argument("--cutpoint-id", required=True, type=int)
    parser.add_argument("--barrier-socket", required=True, type=Path)
    parser.add_argument("--trial-dir", required=True, type=Path); parser.add_argument("--metrics-jsonl", required=True, type=Path)
    parser.add_argument("--prepared-trial-dir", action="store_true")
    parser.add_argument("--media", action="append", default=[]); parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--recovery-timeout-seconds", type=float, default=None,
                        help="outer recovery-launcher budget; defaults to --timeout-seconds")
    parser.add_argument("--kill-mode", choices=("pid", "container"), default="pid")
    parser.add_argument("--pass-through", action="store_true", help="ACK a non-target barrier; never use for a crash target")
    parser.add_argument("--recovery-guest", type=Path, default=None, help="executable recovery boot launched on the retained trial media")
    parser.add_argument("--recovery-output-metrics", action="store_true", help="require the recovery terminal receipt in guest serial output")
    parser.add_argument("--real-qemu", action="store_true", help="restrict this trial to the dedicated two-boot QEMU launcher")
    parser.add_argument("--container-kill-command", nargs="+", default=None); parser.add_argument("guest", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        _validate_timeout(args.timeout_seconds, "--timeout-seconds")
    except ValueError as exc:
        parser.error(str(exc))
    if args.recovery_timeout_seconds is None:
        args.recovery_timeout_seconds = args.timeout_seconds
    try:
        _validate_timeout(args.recovery_timeout_seconds, "--recovery-timeout-seconds")
    except ValueError as exc:
        parser.error(str(exc))
    if args.catalog_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", args.catalog_digest):
        parser.error("--catalog-digest must be exactly 64 lowercase hexadecimal characters")
    if args.namespace_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.namespace_id):
        parser.error("--namespace-id is invalid")
    if args.authority_id is not None and not re.fullmatch(r"[0-9a-f]{32}", args.authority_id):
        parser.error("--authority-id must be exactly 32 lowercase hexadecimal characters")
    if args.effect_id is not None and not re.fullmatch(r"[0-9a-f]{32}", args.effect_id):
        parser.error("--effect-id must be exactly 32 lowercase hexadecimal characters")
    if not args.guest or args.guest[0] != "--": parser.error("guest command must follow --")
    args.guest = args.guest[1:]
    if not args.guest: parser.error("missing guest command")
    if args.pass_through and args.recovery_guest is not None: parser.error("pass-through is not a crash trial")
    if args.recovery_output_metrics and args.recovery_guest is None: parser.error("serial recovery metrics require --recovery-guest")
    if args.kill_mode == "container" and not args.container_kill_command: parser.error("--container-kill-command is required for container kill mode")
    try:
        if args.real_qemu:
            _validate_real_qemu_launcher(args)
        append_jsonl(args.metrics_jsonl, run_trial(args))
    except (BarrierProtocolError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"matrix controller: {exc}", file=sys.stderr); raise SystemExit(1) from exc


if __name__ == "__main__": main()
