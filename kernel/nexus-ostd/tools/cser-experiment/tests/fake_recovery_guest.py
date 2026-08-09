#!/usr/bin/env python3
from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path


def proc_starttime(pid: int) -> str:
    # Field 22, after the comm field which may itself contain spaces.
    return Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rpartition(")")[2].split()[19]


if os.environ.get("CSER_EXPERIMENT_RECOVERY_SPAWN_LONG_CHILD"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=False)
    Path(os.environ["CSER_EXPERIMENT_RECOVERY_CHILD_FILE"]).write_text(
        f"{child.pid} {proc_starttime(child.pid)}", encoding="ascii"
    )
    while True:
        time.sleep(1)

emit_bytes = int(os.environ.get("CSER_EXPERIMENT_RECOVERY_EMIT_BYTES", "0"))
if emit_bytes:
    # Keep individual serial lines below the controller's hostile-input bound:
    # the regression is about total streamed output, not accepting giant lines.
    line = b"R" * 8191 + b"\n"
    err_line = b"E" * 8191 + b"\n"
    for _ in range((emit_bytes + len(line) - 1) // len(line)):
        sys.stdout.buffer.write(line)
        sys.stderr.buffer.write(err_line)
    sys.stdout.buffer.flush(); sys.stderr.buffer.flush()

Path(os.environ["CSER_EXPERIMENT_RECOVERY_METRICS"]).write_text(
    json.dumps({"terminal": True, "invariants_ok": True, "retained_claims": 0}), encoding="utf-8"
)

if os.environ.get("CSER_EXPERIMENT_RECOVERY_SERIAL"):
    print("TOOL_DMA_RECOVERY_METRICS " + json.dumps({
        "invariants_ok": True,
        "run_id": os.environ["CSER_EXPERIMENT_RUN_ID"],
        "terminal": True,
        "variant": os.environ["CSER_EXPERIMENT_VARIANT"],
        "retired_by_evidence": 1,
        "retained_claims": 0,
        "reconciliation_delay_ms": None,
        "gate_rejections": None,
        "reconciliation_steps": 1,
        "reconciliation_delay_unit": "unmeasured",
    }), flush=True)
