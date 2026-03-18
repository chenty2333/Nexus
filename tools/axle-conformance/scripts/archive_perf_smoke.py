#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from perf_smoke_baseline import build_baseline
from perf_smoke_perfetto import build_perfetto_trace


def slugify(label: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", label.strip()).strip("-")
    return slug or "baseline"


def git_rev(repo_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except Exception:
        return None


def archive_perf_smoke(
    serial_log: Path,
    archive_root: Path,
    label: str,
    cpuinfo_path: Path | None,
    repo_root: Path,
) -> Path:
    text = serial_log.read_text(encoding="utf-8", errors="replace")
    baseline = build_baseline(serial_log, cpuinfo_path or Path("/proc/cpuinfo"))
    perfetto = build_perfetto_trace(text)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = archive_root / f"{stamp}-{slugify(label)}"
    out_dir.mkdir(parents=True, exist_ok=False)

    serial_out = out_dir / "serial.log"
    perf_smoke_out = out_dir / "perf-smoke.json"
    baseline_out = out_dir / "baseline.json"
    perfetto_out = out_dir / "perfetto-trace.json"
    manifest_out = out_dir / "manifest.json"

    shutil.copy2(serial_log, serial_out)
    perf_smoke_out.write_text(
        json.dumps(baseline["perf_smoke"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    baseline_out.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    perfetto_out.write_text(
        json.dumps(perfetto, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    cpuinfo_copy = None
    if cpuinfo_path is not None and cpuinfo_path.exists():
        cpuinfo_copy = out_dir / "cpuinfo.txt"
        shutil.copy2(cpuinfo_path, cpuinfo_copy)

    manifest = {
        "schema_version": 1,
        "label": label,
        "created_at_utc": stamp,
        "git_rev": git_rev(repo_root),
        "source_serial_log": str(serial_log),
        "artifacts": {
            "serial_log": serial_out.name,
            "perf_smoke": perf_smoke_out.name,
            "baseline": baseline_out.name,
            "perfetto_trace": perfetto_out.name,
            "cpuinfo": cpuinfo_copy.name if cpuinfo_copy is not None else None,
        },
        "guest_features": baseline["guest_features"],
        "host_flags": baseline["host_flags"],
    }
    manifest_out.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out_dir


def main() -> None:
    if len(sys.argv) not in (4, 5):
        raise SystemExit(
            "usage: archive_perf_smoke.py <serial-log> <archive-root> <label> [cpuinfo]"
        )

    serial_log = Path(sys.argv[1]).resolve()
    archive_root = Path(sys.argv[2]).resolve()
    label = sys.argv[3]
    cpuinfo_path = Path(sys.argv[4]).resolve() if len(sys.argv) == 5 else None
    repo_root = Path(__file__).resolve().parents[3]

    out_dir = archive_perf_smoke(serial_log, archive_root, label, cpuinfo_path, repo_root)
    print(out_dir)


if __name__ == "__main__":
    main()
