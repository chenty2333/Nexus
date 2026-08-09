#!/usr/bin/env python3
"""Summarize performance.jsonl emitted by run_qemu_performance.py."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile: stable and explicit for small OFAT samples."""
    if not values:
        raise ValueError("cannot calculate a percentile of no samples")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int((len(ordered) * fraction + 0.999999999) - 1)))]


def summarize(rows: list[dict[str, object]]) -> dict[str, object]:
    groups: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for row in rows:
        point, measurements = row.get("point"), row.get("measurements")
        if not isinstance(point, str) or not isinstance(measurements, dict) or not measurements:
            raise ValueError("performance row must contain point and nonempty measurements")
        for metric, observation in measurements.items():
            if (not isinstance(metric, str) or not isinstance(observation, dict)
                    or set(observation) != {"value", "unit"}
                    or not isinstance(observation["value"], (int, float))
                    or observation["unit"] not in ("ms", "count", "cycles", "bytes")):
                raise ValueError("performance measurements must contain numeric value and explicit unit")
            groups[(point, metric, observation["unit"])].append(float(observation["value"]))
    return {"schema_version": 1, "groups": [
        {"point": point, "metric": metric, "unit": unit, "n": len(values), "min": min(values), "p50": percentile(values, .50),
         "p95": percentile(values, .95), "max": max(values),
         "p95_resolution": "low" if len(values) < 20 else "normal"}
        for (point, metric, unit), values in sorted(groups.items())
    ]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line]
    args.output.write_text(json.dumps(summarize(rows), sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
