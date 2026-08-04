#!/usr/bin/env python3
"""Validate and aggregate the common CSER/baseline crash-matrix JSONL schema."""
from __future__ import annotations
import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
COUNTER_FIELDS = ("retired_by_evidence", "retained_claims", "reconciliation_steps")
NULLABLE_UNMEASURED_FIELDS = ("reconciliation_delay_ms", "gate_rejections")
METRIC_FIELDS = (*COUNTER_FIELDS, *NULLABLE_UNMEASURED_FIELDS)
CUTPOINTS = {
    "pre_escape": 1,
    "post_register": 2,
    "post_endpoint_apply": 3,
    "post_effect_fact": 4,
    "post_quiescence": 5,
    "pre_discharge": 6,
    "post_discharge": 7,
}
REQUIRED = frozenset(("schema_version", "run_id", "variant", "trial", "cutpoint", "cutpoint_id", "crash_method", "barrier_observed", "barrier_acknowledged", "completion_state", "retention_horizon", "permanent_retention", "admin_disposition", "admin_disposition_count", "metrics_source", "reconciliation_delay_unit", *METRIC_FIELDS))

def load_metrics(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line: continue
        try: item = json.loads(line)
        except json.JSONDecodeError as exc: raise ValueError(f"invalid JSONL at line {number}") from exc
        if not isinstance(item, dict) or REQUIRED - item.keys(): raise ValueError(f"metric {number} lacks common schema fields")
        if item["schema_version"] != SCHEMA_VERSION: raise ValueError(f"metric {number} has unsupported schema version")
        if item["variant"] not in ("cser", "baseline"): raise ValueError(f"metric {number} has invalid variant")
        if item["cutpoint"] not in CUTPOINTS or item["cutpoint_id"] != CUTPOINTS[item["cutpoint"]]: raise ValueError(f"metric {number} has invalid cutpoint binding")
        if not isinstance(item["barrier_observed"], bool) or not isinstance(item["barrier_acknowledged"], bool): raise ValueError(f"metric {number} has invalid barrier observations")
        if item["completion_state"] not in ("recovery_verified", "crashed_unrecovered"): raise ValueError(f"metric {number} has invalid completion state")
        if item["retention_horizon"] != "bounded_observation": raise ValueError(f"metric {number} overclaims retention horizon")
        if item["permanent_retention"] is not None or item["admin_disposition"] is not None or item["admin_disposition_count"] is not None: raise ValueError(f"metric {number} overclaims permanence or administrative support")
        if item["metrics_source"] not in ("initial_guest_file", "recovery_terminal"): raise ValueError(f"metric {number} has invalid metrics source")
        if item["metrics_source"] == "recovery_terminal" and item["completion_state"] != "recovery_verified": raise ValueError(f"metric {number} has terminal metrics without verified recovery")
        for field in COUNTER_FIELDS:
            value = item[field]
            if isinstance(value, bool) or (value is not None and (not isinstance(value, int) or value < 0)):
                raise ValueError(f"metric {number} has invalid {field}")
            if item["metrics_source"] == "recovery_terminal" and value is None:
                raise ValueError(f"metric {number} lacks authoritative terminal {field}")
        for field in NULLABLE_UNMEASURED_FIELDS:
            value = item[field]
            if isinstance(value, bool) or (value is not None and (not isinstance(value, int) or value < 0)):
                raise ValueError(f"metric {number} has invalid {field}")
            if item["metrics_source"] == "recovery_terminal" and value is not None:
                raise ValueError(f"metric {number} must leave unmeasured {field} explicitly null")
        if item["metrics_source"] == "recovery_terminal" and item["reconciliation_delay_unit"] != "unmeasured":
            raise ValueError(f"metric {number} has invalid authoritative reconciliation delay unit")
        rows.append(item)
    return rows

def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    identities: set[tuple[Any, ...]] = set()
    for row in rows:
        identity = (row["variant"], row["run_id"], row["trial"], row["cutpoint_id"])
        if identity in identities:
            raise ValueError(f"duplicate metric identity: {identity}")
        identities.add(identity)
    coverage = {
        variant: {(row["trial"], row["cutpoint"], row["cutpoint_id"]) for row in rows if row["variant"] == variant}
        for variant in ("cser", "baseline")
    }
    if coverage["cser"] and coverage["baseline"] and coverage["cser"] != coverage["baseline"]:
        raise ValueError("CSER and baseline metric coverage differs")
    variants: dict[str, dict[str, Any]] = {}
    for variant in ("cser", "baseline"):
        selected = [row for row in rows if row["variant"] == variant]
        values = {
            key: [row[key] for row in selected if isinstance(row[key], int) and not isinstance(row[key], bool)]
            for key in METRIC_FIELDS
        }
        variants[variant] = {
            "trials": len(selected),
            "barriers_observed": sum(1 for row in selected if row["barrier_observed"]),
            "cutpoints": dict(sorted(Counter(row["cutpoint"] for row in selected).items())),
            "metric_sources": dict(sorted(Counter(row["metrics_source"] for row in selected).items())),
            "measured_trials": {key: len(values[key]) for key in METRIC_FIELDS},
            "sums": {key: sum(values[key]) if values[key] else None for key in METRIC_FIELDS},
            "reconciliation_delay_units": dict(sorted(Counter(row["reconciliation_delay_unit"] for row in selected if row["reconciliation_delay_unit"] is not None).items())),
        }
    return {"schema_version": SCHEMA_VERSION, "retention_horizon": "bounded_observation", "variants": variants}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, action="append", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = [row for path in args.input for row in load_metrics(path)]
    args.output.write_text(
        json.dumps(summarize(rows), sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
if __name__ == "__main__": main()
