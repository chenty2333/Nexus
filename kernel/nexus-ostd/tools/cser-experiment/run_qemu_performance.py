#!/usr/bin/env python3
"""Run a small OFAT real-QEMU performance lane from durable trial artifacts.

Endpoint workers are host dispatchers, never CSER writers.  Every output line
is one primary QEMU trial; it is derived after the run from that trial's
endpoint SQLite database and launcher/recovery log artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import re
from pathlib import Path
from typing import Any

from summarize_performance import summarize


_PERF_PREFIX = "TOOL_DMA_PERF_V2 "
_COMPACTION_PREFIX = "CSER_VNEXT_COMPACTION "
_MAX_RUNTIME_PERF_LINE_BYTES = 4096
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_PERF_NUMERIC_UNITS = {
    "runtime_transactions": "count", "mutex_wait_cycles": "cycles", "mutex_max_wait_cycles": "cycles",
    "mutex_hold_cycles": "cycles", "mutex_max_hold_cycles": "cycles", "checkpoints": "count",
    "commit_gate_wait_cycles": "cycles", "max_commit_gate_wait_cycles": "cycles",
    "checkpoint_lock_wait_cycles": "cycles", "max_checkpoint_lock_wait_cycles": "cycles",
    "checkpoint_lock_hold_cycles": "cycles", "max_checkpoint_lock_hold_cycles": "cycles",
    "journal_sectors_read": "count",
    "journal_sectors_written": "count", "journal_flushes": "count", "journal_hash_bytes": "bytes",
    "journal_image_bytes": "bytes", "journal_capacity_bytes": "bytes", "tpm_lease_advances": "count",
    "tpm_tip_advances": "count", "tpm_lease_cycles": "cycles", "tpm_tip_cycles": "cycles",
}
_JOURNAL_PHASE_TSC = (
    "journal_payload_written_tsc", "journal_payload_flushed_tsc",
    "journal_header_written_tsc", "journal_header_flushed_tsc",
    "journal_readback_validated_tsc", "journal_cache_updated_tsc",
)
_PERF_KEYS = frozenset({"version", "run_id", "phase", "clock", "calibrated", "journal_format", "journal_phase_scope"} | set(_PERF_NUMERIC_UNITS) | set(_JOURNAL_PHASE_TSC))
_COMPACTION_KEYS = frozenset({"version", "run_id", "journal_format", "phase", "revision_before", "head_before", "revision_after", "head_after", "logical_bytes_before", "logical_bytes_after", "sectors_read_delta", "sectors_written_delta", "flushes_delta"})


def points(journal: str, delay_ms: int, workers: int) -> list[tuple[str, dict[str, str]]]:
    journal_env = "1" if journal == "vnext" else "0"
    return [
        ("control", {"CSER_EXPERIMENT_JOURNAL_VNEXT": journal_env, "CSER_EXPERIMENT_PROVIDER_DELAY_MS": "0", "CSER_EXPERIMENT_WORKER_COUNT": "1", "CSER_EXPERIMENT_BACKGROUND_JOBS": "0"}),
        ("delayed_endpoint", {"CSER_EXPERIMENT_JOURNAL_VNEXT": journal_env, "CSER_EXPERIMENT_PROVIDER_DELAY_MS": str(delay_ms), "CSER_EXPERIMENT_WORKER_COUNT": "1", "CSER_EXPERIMENT_BACKGROUND_JOBS": "0"}),
        # A bounded host-local background queue overlaps the primary endpoint
        # request. It has no guest/CSER claim meaning; artifact extraction
        # below rejects a run that did not actually overlap it.
        ("endpoint_concurrency", {"CSER_EXPERIMENT_JOURNAL_VNEXT": journal_env, "CSER_EXPERIMENT_PROVIDER_DELAY_MS": str(max(delay_ms, 100)), "CSER_EXPERIMENT_WORKER_COUNT": str(workers), "CSER_EXPERIMENT_BACKGROUND_JOBS": str(workers * 64)}),
    ]


def _stage_duration_ms(trial: Path, stage: str) -> float:
    path = trial / "stage-timings.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        stages = document["stages"]
        start, end = stages[f"{stage}_start_ns"], stages[f"{stage}_end_ns"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"trial misses valid controller stage timing for {stage}") from exc
    if document.get("schema_version") != 1 or document.get("clock") != "monotonic_ns" or not isinstance(start, int) or not isinstance(end, int) or end < start:
        raise ValueError(f"trial has invalid controller stage timing for {stage}")
    return (end - start) / 1_000_000


def _runtime_perf_marker(
    trial: Path, log_name: str, label: str, journal: str, expected_run_id: str,
    expected_phase: str, *, require_transaction: bool, allow_compaction: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Parse one exact phase-bound diagnostic marker from one bounded log."""
    perf: dict[str, Any] | None = None
    compaction: dict[str, Any] | None = None
    path = trial / log_name
    try:
        with path.open("rb") as handle:
            while True:
                raw = handle.readline(_MAX_RUNTIME_PERF_LINE_BYTES + 1)
                if not raw:
                    break
                if len(raw) > _MAX_RUNTIME_PERF_LINE_BYTES:
                    raise ValueError(f"{label} runtime telemetry line exceeds 4 KiB")
                try:
                    line = raw.decode("utf-8", errors="strict").rstrip("\r\n")
                except UnicodeDecodeError as exc:
                    raise ValueError(f"{label} runtime telemetry is not UTF-8") from exc
                target: str | None = None
                if line.startswith(_PERF_PREFIX):
                    if perf is not None: raise ValueError(f"{label} must contain exactly one performance marker")
                    target = line[len(_PERF_PREFIX):]
                    try: perf = json.loads(target)
                    except json.JSONDecodeError as exc: raise ValueError(f"malformed {label} performance marker") from exc
                elif line.startswith(_COMPACTION_PREFIX):
                    if compaction is not None: raise ValueError(f"{label} must contain at most one compaction marker")
                    target = line[len(_COMPACTION_PREFIX):]
                    try: compaction = json.loads(target)
                    except json.JSONDecodeError as exc: raise ValueError(f"malformed {label} compaction marker") from exc
    except OSError as exc:
        raise ValueError(f"trial misses {label} stdout telemetry") from exc
    if not isinstance(perf, dict) or set(perf) != _PERF_KEYS:
        raise ValueError(f"{label} performance marker has an unexpected schema")
    if (not _RUN_ID.fullmatch(expected_run_id) or perf.get("version") != 2 or perf.get("run_id") != expected_run_id
            or perf.get("phase") != expected_phase or perf.get("clock") != "guest_tsc"
            or perf.get("calibrated") is not False or perf.get("journal_format") != journal):
        raise ValueError(f"{label} performance marker has mismatched phase, clock, calibration, or journal format")
    if perf.get("journal_phase_scope") != "last-complete-publication":
        raise ValueError(f"{label} performance marker has an unsupported journal phase scope")
    for key in _PERF_NUMERIC_UNITS:
        if not isinstance(perf[key], int) or isinstance(perf[key], bool) or perf[key] < 0:
            raise ValueError(f"{label} performance marker has invalid {key}")
    if require_transaction and perf["runtime_transactions"] == 0:
        raise ValueError(f"{label} performance marker must include a runtime transaction")
    phase_tsc = [perf[key] for key in _JOURNAL_PHASE_TSC]
    if (any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in phase_tsc)
            or phase_tsc != sorted(phase_tsc)):
        raise ValueError(f"{label} performance marker has missing or nonmonotonic publication phases")
    if not allow_compaction and compaction is not None:
        raise ValueError(f"{label} must not emit a compaction marker")
    return perf, compaction


def _phase_measurements(prefix: str, perf: dict[str, Any]) -> dict[str, dict[str, int | str]]:
    """Convert same-publication absolute guest TSC stamps into phase intervals.

    The raw V2 receipt retains absolute stamps for audit, while campaign rows
    expose only within-publication deltas.  They remain uncalibrated guest TSC
    cycles and must not be compared as host wall-clock latency.
    """
    measurements = {f"{prefix}_{key}": {"value": perf[key], "unit": unit}
                    for key, unit in _PERF_NUMERIC_UNITS.items()}
    payload_written, payload_flushed, header_written, header_flushed, readback, cache = (
        perf[key] for key in _JOURNAL_PHASE_TSC
    )
    measurements.update({
        f"{prefix}_journal_payload_write_to_flush_cycles": {"value": payload_flushed - payload_written, "unit": "cycles"},
        f"{prefix}_journal_header_written_to_redundancy_flushed_cycles": {"value": header_flushed - header_written, "unit": "cycles"},
        f"{prefix}_journal_header_flush_to_readback_cycles": {"value": readback - header_flushed, "unit": "cycles"},
        f"{prefix}_journal_readback_to_cache_publication_cycles": {"value": cache - readback, "unit": "cycles"},
    })
    return measurements


def _runtime_measurements(trial: Path, journal: str, expected_run_id: str) -> dict[str, dict[str, int | str]]:
    """Bind cut-3 initial and terminal-recovery telemetry, then prefix both."""
    initial, initial_compaction = _runtime_perf_marker(
        trial, "initial.stdout.log", "initial", journal, expected_run_id,
        "post-endpoint-precrash", require_transaction=True, allow_compaction=False,
    )
    recovery, compaction = _runtime_perf_marker(
        trial, "recovery.stdout.log", "recovery", journal, expected_run_id,
        "terminal-recovery", require_transaction=False, allow_compaction=True,
    )
    if initial_compaction is not None:
        raise ValueError("initial must not emit a compaction marker")
    if journal == "legacy":
        if compaction is not None: raise ValueError("legacy recovery must not emit vNext compaction")
    elif journal == "vnext":
        if not isinstance(compaction, dict) or set(compaction) != _COMPACTION_KEYS:
            raise ValueError("vNext recovery must contain exactly one compaction marker")
        scalar = ("version", "revision_before", "revision_after", "logical_bytes_before", "logical_bytes_after")
        if (compaction.get("version") != 1 or compaction.get("run_id") != expected_run_id
                or compaction.get("journal_format") != "vnext" or compaction.get("phase") != "recovery"
                or any(not isinstance(compaction[key], int) or isinstance(compaction[key], bool) or compaction[key] < 0 for key in scalar)
                or not all(isinstance(compaction[key], str) and _HEX64.fullmatch(compaction[key]) for key in ("head_before", "head_after"))
                or not isinstance(compaction["sectors_read_delta"], int) or isinstance(compaction["sectors_read_delta"], bool) or compaction["sectors_read_delta"] < 0
                or not isinstance(compaction["sectors_written_delta"], int) or isinstance(compaction["sectors_written_delta"], bool) or compaction["sectors_written_delta"] <= 0
                or not isinstance(compaction["flushes_delta"], int) or isinstance(compaction["flushes_delta"], bool) or compaction["flushes_delta"] <= 0
                or compaction["revision_after"] != compaction["revision_before"] + 1
                or compaction["head_after"] == compaction["head_before"]
                or compaction["logical_bytes_after"] >= compaction["logical_bytes_before"]):
            raise ValueError("vNext compaction marker is invalid")
    else:
        raise ValueError("unknown journal format")
    measurements = _phase_measurements("initial", initial) | _phase_measurements("recovery", recovery)
    if compaction is not None:
        measurements.update({
            "compaction_revision_before": {"value": compaction["revision_before"], "unit": "count"},
            "compaction_revision_after": {"value": compaction["revision_after"], "unit": "count"},
            "compaction_logical_bytes_before": {"value": compaction["logical_bytes_before"], "unit": "bytes"},
            "compaction_logical_bytes_after": {"value": compaction["logical_bytes_after"], "unit": "bytes"},
            "compaction_sectors_read_delta": {"value": compaction["sectors_read_delta"], "unit": "count"},
            "compaction_sectors_written_delta": {"value": compaction["sectors_written_delta"], "unit": "count"},
            "compaction_flushes_delta": {"value": compaction["flushes_delta"], "unit": "count"},
        })
    return measurements


def extract_trial(
    trial: Path,
    point: str,
    trial_number: int,
    expected_run_id: str,
    journal: str = "legacy",
) -> dict[str, Any]:
    database = trial / "tool-endpoint.sqlite"
    if not database.is_file():
        raise ValueError(f"trial misses endpoint database: {trial}")
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            """SELECT run_id, operation_key, accepted_at_ns, pending_at_ns, provider_applied_at_ns, terminal_at_ns
               FROM operations WHERE operation_key NOT LIKE 'perf-bg-%'"""
        ).fetchall()
        if len(rows) != 1:
            raise ValueError(f"trial must contain exactly one primary endpoint operation, found {len(rows)}")
        run_id, operation_key, accepted, pending, applied, terminal = rows[0]
        if run_id != expected_run_id:
            raise ValueError("primary endpoint operation does not match trial run identity")
        if not all(isinstance(value, int) and value > 0 for value in (accepted, pending, applied, terminal)):
            raise ValueError("primary operation has unknown performance timestamps")
        if not accepted <= pending <= applied <= terminal:
            raise ValueError("primary operation timing boundaries are not monotonic")
        max_inflight = connection.execute(
            "SELECT value FROM adapter_metadata WHERE key='max_inflight'"
        ).fetchone()
        if max_inflight is None or not str(max_inflight[0]).isdigit():
            raise ValueError("trial misses durable max inflight metric")
        if point == "endpoint_concurrency":
            overlap = connection.execute(
                """SELECT 1 FROM operations WHERE operation_key LIKE 'perf-bg-%'
                   AND pending_at_ns > 0 AND terminal_at_ns >= ? AND pending_at_ns <= ? LIMIT 1""",
                (pending, applied),
            ).fetchone()
            if overlap is None:
                raise ValueError("concurrency point did not overlap a background endpoint job with the primary")
    finally:
        connection.close()
    return {
        "schema_version": 1, "point": point, "trial": trial_number, "trial_dir": str(trial),
        "operation_key": operation_key,
        "measurements": {
            "accepted_to_pending": {"value": (pending - accepted) / 1_000_000, "unit": "ms"},
            "pending_to_provider_apply": {"value": (applied - pending) / 1_000_000, "unit": "ms"},
            "provider_apply_to_terminal": {"value": (terminal - applied) / 1_000_000, "unit": "ms"},
            "initial_launcher": {"value": _stage_duration_ms(trial, "initial"), "unit": "ms"},
            "recovery_launcher": {"value": _stage_duration_ms(trial, "recovery"), "unit": "ms"},
            "max_inflight": {"value": int(max_inflight[0]), "unit": "count"},
        } | _runtime_measurements(trial, journal, expected_run_id),
    }


def _trial_artifacts(campaign: Path, expected: int) -> list[tuple[Path, str]]:
    rows = [json.loads(line) for line in (campaign / "metrics.jsonl").read_text(encoding="utf-8").splitlines() if line]
    try:
        artifacts = [(Path(row["trial_dir"]), row["run_id"]) for row in rows]
    except (KeyError, TypeError) as exc:
        raise ValueError("QEMU campaign artifact metrics lack trial identity") from exc
    directories = [item[0] for item in artifacts]
    if len(directories) != expected or len(set(directories)) != expected or any(not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id) for _, run_id in artifacts):
        raise ValueError("QEMU campaign did not produce exactly one artifact row per requested trial")
    return artifacts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("cser", "baseline"), required=True)
    parser.add_argument("--output", required=True, type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--base-media-dir", type=Path); source.add_argument("--base-media", action="append", type=Path)
    parser.add_argument("--trials", default=1, type=int); parser.add_argument("--provider-delay-ms", default=25, type=int)
    parser.add_argument("--worker-count", default=2, type=int); parser.add_argument("--journal", choices=("legacy", "vnext"), default="legacy")
    args = parser.parse_args()
    if args.trials < 1 or args.provider_delay_ms < 0 or args.worker_count < 1:
        raise SystemExit("trials/worker count must be positive and delay must not be negative")
    root = Path(__file__).resolve().parent; args.output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for point, overrides in points(args.journal, args.provider_delay_ms, args.worker_count):
        campaign = args.output / point
        command = [str(root / "run_qemu_matrix.sh"), "--variant", args.variant, "--output", str(campaign), "--trials", str(args.trials), "--only-cutpoint", "post_endpoint_apply"]
        if args.base_media_dir is not None:
            command += ["--base-media-dir", str(args.base_media_dir)]
        else:
            for medium in args.base_media: command += ["--base-media", str(medium)]
        subprocess.run(command, cwd=root, env=os.environ | overrides, check=True)
        rows.extend(
            extract_trial(trial, point, index, run_id, args.journal)
            for index, (trial, run_id) in enumerate(
                _trial_artifacts(campaign, args.trials), 1
            )
        )
    output = args.output / "performance.jsonl"
    output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    (args.output / "summary.json").write_text(json.dumps(summarize(rows), sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
