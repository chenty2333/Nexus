#!/usr/bin/env python3
"""Validate and summarize the matched logical-handoff matrix."""
from __future__ import annotations
import argparse, json
from collections import Counter
from pathlib import Path
from typing import Any
from handoff_matrix_controller import _CID, CUTPOINTS, DEFAULT_CUTPOINTS, SCHEMA_VERSION, VARIANTS, compare_recoveries, validate_receipt

def load_rows(path: Path) -> list[dict[str, Any]]:
    rows=[]
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line: continue
        try: row=json.loads(line)
        except json.JSONDecodeError as exc: raise ValueError(f"invalid JSONL at line {number}") from exc
        if not isinstance(row, dict) or row.get("schema_version") != SCHEMA_VERSION or row.get("variant") not in VARIANTS: raise ValueError(f"invalid handoff row {number}")
        if row.get("cutpoint") not in CUTPOINTS or row.get("cutpoint_id") != CUTPOINTS[row["cutpoint"]]: raise ValueError(f"invalid cutpoint in row {number}")
        if row.get("scope") != "logical" or row.get("barrier_observed") is not True or row.get("barrier_acknowledged") is not False: raise ValueError(f"invalid crash provenance in row {number}")
        validate_receipt(row.get("recovery1"), variant=row["variant"], run_id=row.get("run_id")); validate_receipt(row.get("recovery2"), variant=row["variant"], run_id=row["run_id"]); compare_recoveries(row["recovery1"], row["recovery2"])
        records = row.get("endpoint_records")
        if not isinstance(records, dict) or set(records) != {"source", "child"}:
            raise ValueError(f"handoff row {number} lacks host-verified endpoint records")
        for name, record in records.items():
            if not isinstance(record, dict) or record.get("endpoint_terminal_rows") != 1 or record.get("provider_application_rows") != 1 or record.get("dedup_consistent") is not True:
                raise ValueError(f"handoff row {number} has invalid {name} endpoint verification")
        rows.append(row)
    return rows

def summarize(rows: list[dict[str, Any]], *, require_matched: bool = True) -> dict[str, Any]:
    if not rows:
        raise ValueError("handoff summary has no rows")
    if require_matched:
        for number, row in enumerate(rows, 1):
            container_id = row.get("container_id")
            if row.get("crash_method") != "container_kill" or not isinstance(container_id, str) or not _CID.fullmatch(container_id):
                raise ValueError(f"strict handoff row {number} lacks real-QEMU container-kill provenance")
    seen=set()
    for row in rows:
        identity=(row["variant"],row["trial"],row["cutpoint_id"])
        if identity in seen: raise ValueError(f"duplicate handoff row {identity}")
        seen.add(identity)
    coverage={variant:{(r["trial"],r["cutpoint"]) for r in rows if r["variant"]==variant} for variant in VARIANTS}
    matched = False
    if require_matched:
        if coverage["cser"] != coverage["baseline"]: raise ValueError("CSER/baseline handoff coverage differs")
        expected={(trial, cut) for trial in {r["trial"] for r in rows} for cut in DEFAULT_CUTPOINTS}
        if coverage["cser"] != expected: raise ValueError("handoff matrix is missing a default matched cut")
        matched = True
    return {"schema_version": SCHEMA_VERSION, "scope":"logical",
            "acceptance":f"matched {len(DEFAULT_CUTPOINTS)} cuts x 2 variants" if matched else "partial handoff coverage (not matched)",
            "matched": matched,
            "variants": {v:{"trials":sum(r["variant"]==v for r in rows), "cutpoints":dict(Counter(r["cutpoint"] for r in rows if r["variant"]==v))} for v in sorted(VARIANTS)}}
def main() -> None:
    p=argparse.ArgumentParser(); p.add_argument("--input", action="append", type=Path, required=True); p.add_argument("--output", type=Path, required=True); p.add_argument("--allow-partial", action="store_true"); a=p.parse_args(); rows=[r for source in a.input for r in load_rows(source)]; a.output.write_text(json.dumps(summarize(rows, require_matched=not a.allow_partial),sort_keys=True,indent=2)+"\n",encoding="utf-8")
if __name__ == "__main__": main()
