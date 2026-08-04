#!/usr/bin/env python3
"""Host-controlled crash trial controller and common JSONL metric writer."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

from matrix_protocol import BarrierProtocolError, barrier_ack, parse_barrier

SCHEMA_VERSION = 2
VARIANTS = frozenset(("cser", "baseline"))
_CID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_RECOVERY_METRICS_PREFIX = "TOOL_DMA_RECOVERY_METRICS "
_CURRENT_GUEST_RUN_ID = "42" * 16
_TERMINAL_COUNTER_FIELDS = (
    "retired_by_evidence",
    "retained_claims",
)


def _read_one_frame(client: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= 1024:
        block = client.recv(min(256, 1025 - len(data)))
        if not block:
            break
        data.extend(block)
        if b"\n" in block:
            if data.count(b"\n") != 1 or not data.endswith(b"\n"):
                raise BarrierProtocolError("invalid barrier framing")
            return bytes(data)
    preview = bytes(data[:64]).hex()
    raise BarrierProtocolError(
        f"truncated or oversized barrier: bytes={len(data)} prefix_hex={preview}"
    )


def _connect_qemu_server(socket_path: Path, timeout_seconds: float) -> socket.socket:
    """Connect to QEMU's sole COM3 Unix-socket server, retrying its startup."""
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


def observe_barriers(client: socket.socket, run_id: str, target_cutpoint: int, *, pass_through: bool) -> bool:
    """ACK exactly the in-order prefix, then close at the selected target.

    The guest's numeric cutpoints are a closed sequence 1..7.  A duplicate,
    skipped, reversed, or unexpected value is fail-closed instead of becoming
    an accidental timing-based crash point.
    """
    if not 1 <= target_cutpoint <= 7:
        raise BarrierProtocolError("target cutpoint is outside the seven-cutpoint matrix")
    expected = 1
    while True:
        observed = parse_barrier(_read_one_frame(client), expected_run_id=run_id)
        print(f"matrix controller: observed cutpoint={observed}", file=sys.stderr, flush=True)
        if observed != expected:
            raise BarrierProtocolError(f"unexpected cutpoint {observed}; expected {expected}")
        if observed == target_cutpoint:
            if pass_through:
                client.sendall(barrier_ack(run_id, observed))
                return True
            # Closing before the destructive action is intentional: a target
            # barrier must leave the guest blocked/notified only by QEMU death.
            client.shutdown(socket.SHUT_RDWR)
            return False
        client.sendall(barrier_ack(run_id, observed))
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


def _recovery_metrics_from_serial(stdout: bytes, *, variant: str, run_id: str) -> dict[str, Any]:
    """Read the one terminal receipt emitted by the recovery guest itself.

    The real-QEMU path intentionally does not trust an arbitrary host-side
    metrics file.  A launcher may capture serial output, but the terminal and
    invariant assertions must be a guest marker from the recovered kernel.
    """
    try:
        lines = stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"recovery serial is not UTF-8: {exc}") from exc
    markers = [line[len(_RECOVERY_METRICS_PREFIX):] for line in lines if line.startswith(_RECOVERY_METRICS_PREFIX)]
    if len(markers) != 1:
        raise ValueError("recovery serial must contain exactly one terminal metrics marker")
    try:
        value = json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid recovery serial metrics: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("recovery serial metrics must be a JSON object")
    if value.get("variant") != variant or value.get("run_id") != run_id:
        raise ValueError("recovery serial metrics identity mismatch")
    if value.get("terminal") is not True or value.get("invariants_ok") is not True:
        raise ValueError("recovery guest did not publish terminal invariants_ok metrics")
    _require_terminal_metrics(value)
    return value


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
    # The current bounded guest has a compile-time run identity. Each matrix
    # row nevertheless owns isolated media and endpoint state, so reusing this
    # identity across rows cannot cross-contaminate an experiment. Do not
    # silently generate a random host id until the guest receives one through
    # a durable boot configuration channel.
    if args.run_id != _CURRENT_GUEST_RUN_ID:
        raise ValueError("real QEMU trials must use the current guest run id 4242…4242")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _capture_process(process: subprocess.Popen[bytes], trial_dir: Path, prefix: str) -> None:
    """Drain and retain launcher output after its process group has stopped."""
    stdout, stderr = process.communicate(timeout=10)
    (trial_dir / f"{prefix}.stdout.log").write_bytes(stdout)
    (trial_dir / f"{prefix}.stderr.log").write_bytes(stderr)


def _write_completed_capture(completed: subprocess.CompletedProcess[bytes], trial_dir: Path, prefix: str) -> None:
    (trial_dir / f"{prefix}.stdout.log").write_bytes(completed.stdout)
    (trial_dir / f"{prefix}.stderr.log").write_bytes(completed.stderr)


def _kill_container(cid_path: Path, command_prefix: list[str]) -> str:
    try:
        cid = cid_path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError(f"container cid unavailable: {exc}") from exc
    if not _CID.fullmatch(cid):
        raise RuntimeError("invalid container cid")
    completed = subprocess.run(command_prefix + [cid], check=False, capture_output=True, text=True, timeout=15)
    if completed.returncode != 0:
        raise RuntimeError(f"container kill failed ({completed.returncode}): {completed.stderr.strip()}")
    return cid


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
        _require_terminal_metrics(recovery)
        metric_source = recovery
        metrics_source = "recovery_terminal"
    else:
        # Keep generic controller/fake-guest users working.  They do not claim
        # that this optional host file is an authentic terminal measurement.
        metric_source = guest
        metrics_source = "initial_guest_file"
    return {
        "schema_version": SCHEMA_VERSION, "run_id": run_id, "variant": variant,
        "trial": trial, "cutpoint": cutpoint, "cutpoint_id": cutpoint_id, "crash_method": crash_method,
        "barrier_observed": True, "barrier_acknowledged": False, "trial_dir": str(trial_dir),
        "completion_state": "recovery_verified" if recovery is not None else "crashed_unrecovered",
        "retention_horizon": "bounded_observation", "permanent_retention": None,
        "admin_disposition": None, "admin_disposition_count": None,
        "metrics_source": metrics_source,
        "retired_by_evidence": metric_source.get("retired_by_evidence"),
        "retained_claims": metric_source.get("retained_claims"),
        "reconciliation_delay_ms": metric_source.get("reconciliation_delay_ms"),
        "gate_rejections": metric_source.get("gate_rejections"),
        "reconciliation_steps": metric_source.get("reconciliation_steps"),
        "reconciliation_delay_unit": metric_source.get("reconciliation_delay_unit"),
        "container_id": container_id, "media": [str(path) for path in media], "guest": guest, "recovery": recovery,
    }


def run_trial(args: argparse.Namespace) -> dict[str, Any]:
    if args.variant not in VARIANTS:
        raise ValueError("variant must be cser or baseline")
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
    process = subprocess.Popen(args.guest, env=env, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    crash_method, container_id = "pid_sigkill", None
    initial_captured = False
    try:
        with _connect_qemu_server(socket_path, args.timeout_seconds) as client:
            observe_barriers(client, args.run_id, args.cutpoint_id, pass_through=args.pass_through)
        if args.kill_mode == "pid":
            _kill_process_group(process)
        else:
            container_id = _kill_container(cid_path, args.container_kill_command)
            crash_method = "container_kill"
            _kill_process_group(process)  # kill any launcher outside the container too
        _capture_process(process, trial_dir, "initial")
        initial_captured = True
        recovery = None
        if args.recovery_guest is not None:
            recovery_env = env.copy()
            recovery_env.update({"CSER_EXPERIMENT_PHASE": "recovery", "CSER_EXPERIMENT_RECOVERY_METRICS": str(recovery_metrics_path)})
            recovered = subprocess.run(args.recovery_guest, env=recovery_env, capture_output=True, timeout=args.timeout_seconds)
            _write_completed_capture(recovered, trial_dir, "recovery")
            if recovered.returncode != 0:
                raise RuntimeError(
                    f"recovery guest exited {recovered.returncode}: {recovered.stderr.decode('utf-8', errors='replace').strip()}"
                )
            recovery = (
                _recovery_metrics_from_serial(recovered.stdout, variant=args.variant, run_id=args.run_id)
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
    except BaseException:
        _kill_process_group(process)
        if not initial_captured:
            _capture_process(process, trial_dir, "initial")
        raise
def append_jsonl(path: Path, metric: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(metric, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", required=True, choices=sorted(VARIANTS)); parser.add_argument("--run-id", required=True)
    parser.add_argument("--trial", required=True, type=int); parser.add_argument("--cutpoint", required=True); parser.add_argument("--cutpoint-id", required=True, type=int)
    parser.add_argument("--barrier-socket", required=True, type=Path)
    parser.add_argument("--trial-dir", required=True, type=Path); parser.add_argument("--metrics-jsonl", required=True, type=Path)
    parser.add_argument("--prepared-trial-dir", action="store_true")
    parser.add_argument("--media", action="append", default=[]); parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--kill-mode", choices=("pid", "container"), default="pid")
    parser.add_argument("--pass-through", action="store_true", help="ACK a non-target barrier; never use for a crash target")
    parser.add_argument("--recovery-guest", type=Path, default=None, help="executable recovery boot launched on the retained trial media")
    parser.add_argument("--recovery-output-metrics", action="store_true", help="require the recovery terminal receipt in guest serial output")
    parser.add_argument("--real-qemu", action="store_true", help="restrict this trial to the dedicated two-boot QEMU launcher")
    parser.add_argument("--container-kill-command", nargs="+", default=None); parser.add_argument("guest", nargs=argparse.REMAINDER)
    args = parser.parse_args()
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
