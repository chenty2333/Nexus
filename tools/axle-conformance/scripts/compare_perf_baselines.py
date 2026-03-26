#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path


MetricThreshold = tuple[str, str, float]

METRIC_THRESHOLDS: tuple[MetricThreshold, ...] = (
    ("perf_null_cycles", "perf_null_iters", 1.20),
    ("perf_wait_cycles", "perf_wait_iters", 1.20),
    ("perf_wake_cycles", "perf_wake_iters", 1.30),
    ("perf_tlb_cycles", "perf_tlb_iters", 1.30),
    ("perf_fault_cycles", "perf_fault_iters", 1.30),
    ("perf_channel_fragment_cycles", "perf_channel_fragment_iters", 1.30),
    ("perf_as_switch_cycles", "perf_as_switch_iters", 1.30),
)

EXACT_FIELDS: tuple[tuple[str, int], ...] = (
    ("perf_failure_step", 0),
    ("trace_dropped", 0),
    ("trace_sched_phase3_ok", 1),
    ("trace_tlb_phase8_ok", 1),
)

STATUS_FIELDS: tuple[str, ...] = (
    "perf_null_status",
    "perf_wait_status",
    "perf_wake_status",
    "perf_tlb_status",
    "perf_tlb_peer_status",
    "perf_fault_status",
    "perf_channel_fragment_status",
    "perf_as_switch_status",
)


def load_payload(path: Path) -> tuple[dict[str, int], dict[str, int] | None]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if "perf_smoke" in payload:
        perf_smoke = payload["perf_smoke"]
        guest_features = payload.get("guest_features")
        if not isinstance(perf_smoke, dict):
            raise SystemExit(f"{path}: baseline payload has non-object perf_smoke section")
        if guest_features is not None and not isinstance(guest_features, dict):
            raise SystemExit(f"{path}: baseline payload has non-object guest_features section")
        return perf_smoke, guest_features
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return payload, None


def require_int(fields: dict[str, int], key: str, path: Path) -> int:
    value = fields.get(key)
    if not isinstance(value, int):
        raise SystemExit(f"{path}: missing integer field {key}")
    return value


def format_ratio(ratio: float) -> str:
    return f"{ratio:.3f}x"


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: compare_perf_baselines.py <baseline.json|perf-smoke.json> "
            "<current.json|perf-smoke.json>"
        )

    baseline_path = Path(sys.argv[1]).resolve()
    current_path = Path(sys.argv[2]).resolve()
    baseline, baseline_features = load_payload(baseline_path)
    current, current_features = load_payload(current_path)

    failures: list[str] = []
    lines: list[str] = []

    if baseline_features is not None and current_features is not None:
        for key, expected in baseline_features.items():
            current_value = current_features.get(key)
            if current_value != expected:
                failures.append(
                    f"guest feature mismatch for {key}: baseline={expected} current={current_value}"
                )

    for key, expected in EXACT_FIELDS:
        current_value = require_int(current, key, current_path)
        if current_value != expected:
            failures.append(f"{key}: expected {expected}, got {current_value}")

    for key in STATUS_FIELDS:
        current_value = current.get(key)
        if current_value is None:
            continue
        if not isinstance(current_value, int):
            failures.append(f"{key}: expected integer status, got {type(current_value).__name__}")
            continue
        if current_value != 0:
            failures.append(f"{key}: expected 0, got {current_value}")

    for cycles_key, iters_key, limit in METRIC_THRESHOLDS:
        baseline_cycles = require_int(baseline, cycles_key, baseline_path)
        baseline_iters = require_int(baseline, iters_key, baseline_path)
        current_cycles = require_int(current, cycles_key, current_path)
        current_iters = require_int(current, iters_key, current_path)

        if baseline_iters <= 0 or current_iters <= 0:
            failures.append(
                f"{cycles_key}: iteration counts must stay positive "
                f"(baseline={baseline_iters}, current={current_iters})"
            )
            continue

        baseline_per_iter = baseline_cycles / baseline_iters
        current_per_iter = current_cycles / current_iters
        ratio = current_per_iter / baseline_per_iter if baseline_per_iter > 0 else float("inf")

        lines.append(
            f"{cycles_key}: baseline={baseline_per_iter:.2f} cyc/iter "
            f"current={current_per_iter:.2f} cyc/iter ratio={format_ratio(ratio)} "
            f"limit={limit:.2f}x"
        )

        if ratio > limit:
            failures.append(
                f"{cycles_key}: regression exceeds threshold "
                f"(baseline={baseline_per_iter:.2f}, current={current_per_iter:.2f}, "
                f"ratio={format_ratio(ratio)}, limit={limit:.2f}x)"
            )

    print(f"baseline={baseline_path}")
    print(f"current={current_path}")
    for line in lines:
        print(line)

    if failures:
        print("regressions:")
        for failure in failures:
            print(f"  - {failure}")
        raise SystemExit(1)

    print("result=ok")


if __name__ == "__main__":
    main()
