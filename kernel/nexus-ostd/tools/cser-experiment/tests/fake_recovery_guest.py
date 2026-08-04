#!/usr/bin/env python3
from __future__ import annotations
import json, os
from pathlib import Path
Path(os.environ["CSER_EXPERIMENT_RECOVERY_METRICS"]).write_text(
    json.dumps({"terminal": True, "invariants_ok": True, "retained_claims": 0}), encoding="utf-8"
)
