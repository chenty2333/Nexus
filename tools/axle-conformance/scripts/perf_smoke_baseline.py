#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

import json
from pathlib import Path

from extract_perf_smoke import extract_summary


HOST_FLAGS = (
    "pcid",
    "invpcid",
    "arch_perfmon",
    "rdpmc",
    "pdpe1gb",
    "tsc_deadline_timer",
)


def read_host_flags(cpuinfo_path: Path) -> dict[str, int]:
    text = cpuinfo_path.read_text(encoding="utf-8", errors="replace")
    return {flag: int(flag in text) for flag in HOST_FLAGS}


def build_baseline(serial_log: Path, cpuinfo_path: Path) -> dict[str, object]:
    summary = extract_summary(serial_log.read_text(encoding="utf-8", errors="replace"))
    return {
        "host_flags": read_host_flags(cpuinfo_path),
        "guest_features": {
            "trace_tlb_pcid_enabled": summary.get("trace_tlb_pcid_enabled", 0),
            "trace_tlb_invpcid_enabled": summary.get("trace_tlb_invpcid_enabled", 0),
            "perf_pmu_supported": summary.get("perf_pmu_supported", 0),
            "perf_pmu_version": summary.get("perf_pmu_version", 0),
            "perf_pmu_fixed_counters": summary.get("perf_pmu_fixed_counters", 0),
        },
        "perf_smoke": summary,
    }


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: perf_smoke_baseline.py <serial-log> [cpuinfo]")

    serial_log = Path(sys.argv[1])
    cpuinfo_path = Path(sys.argv[2]) if len(sys.argv) == 3 else Path("/proc/cpuinfo")
    json.dump(build_baseline(serial_log, cpuinfo_path), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
