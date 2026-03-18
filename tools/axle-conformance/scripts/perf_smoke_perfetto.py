#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path

from extract_perf_smoke import extract_summary


TRACE_LINE_RE = re.compile(
    r"^trace: seq=(?P<seq>\d+) ts_ns=(?P<ts_ns>\d+) phase=(?P<phase>\d+) "
    r"cpu=(?P<cpu>\d+) cat=(?P<cat>[a-z0-9_]+) ev=(?P<ev>[a-z0-9_]+) "
    r"arg0=(?P<arg0>-?\d+) arg1=(?P<arg1>-?\d+)$"
)
TRACE_TRUNCATED_RE = re.compile(
    r"^trace: truncated logged_records=(?P<logged>\d+) remaining=(?P<remaining>\d+)$"
)


def parse_trace_records(text: str) -> tuple[list[dict[str, int | str]], tuple[int, int] | None]:
    records: list[dict[str, int | str]] = []
    truncated: tuple[int, int] | None = None
    for line in text.splitlines():
        match = TRACE_LINE_RE.match(line)
        if match:
            records.append(
                {
                    "seq": int(match.group("seq")),
                    "ts_ns": int(match.group("ts_ns")),
                    "phase": int(match.group("phase")),
                    "cpu": int(match.group("cpu")),
                    "cat": match.group("cat"),
                    "ev": match.group("ev"),
                    "arg0": int(match.group("arg0")),
                    "arg1": int(match.group("arg1")),
                }
            )
            continue
        match = TRACE_TRUNCATED_RE.match(line)
        if match:
            truncated = (int(match.group("logged")), int(match.group("remaining")))
    return records, truncated


def metadata_event(*, pid: int, tid: int, name: str, value: str | int) -> dict[str, object]:
    return {
        "ph": "M",
        "pid": pid,
        "tid": tid,
        "name": name,
        "args": {"name": value} if isinstance(value, str) else {"sort_index": value},
    }


def build_perfetto_trace(text: str) -> dict[str, object]:
    summary = extract_summary(text)
    records, truncated = parse_trace_records(text)
    if truncated is not None:
        logged, remaining = truncated
        raise SystemExit(
            f"serial trace is truncated (logged_records={logged}, remaining={remaining}); "
            "rerun perf smoke with full trace dumping enabled"
        )
    if not records:
        raise SystemExit("no bootstrap trace records found in serial log")

    categories: list[str] = []
    for record in records:
        cat = str(record["cat"])
        if cat not in categories:
            categories.append(cat)
    pid_by_cat = {cat: index + 1 for index, cat in enumerate(categories)}

    trace_events: list[dict[str, object]] = []
    cpu_threads: dict[tuple[str, int], None] = {}
    for cat, pid in pid_by_cat.items():
        trace_events.append(metadata_event(pid=pid, tid=0, name="process_name", value=cat))
        trace_events.append(metadata_event(pid=pid, tid=0, name="process_sort_index", value=pid))
    for record in records:
        cpu_threads[(str(record["cat"]), int(record["cpu"]))] = None
    for (cat, cpu) in sorted(cpu_threads):
        pid = pid_by_cat[cat]
        trace_events.append(metadata_event(pid=pid, tid=cpu, name="thread_name", value=f"cpu{cpu}"))
        trace_events.append(metadata_event(pid=pid, tid=cpu, name="thread_sort_index", value=cpu))

    for record in records:
        cat = str(record["cat"])
        cpu = int(record["cpu"])
        trace_events.append(
            {
                "name": record["ev"],
                "cat": cat,
                "ph": "i",
                "s": "t",
                "pid": pid_by_cat[cat],
                "tid": cpu,
                "ts": int(record["ts_ns"]) / 1000.0,
                "args": {
                    "seq": record["seq"],
                    "phase": record["phase"],
                    "arg0": record["arg0"],
                    "arg1": record["arg1"],
                },
            }
        )

    return {
        "traceEvents": trace_events,
        "otherData": {
            "perf_smoke": summary,
            "trace_record_count": len(records),
        },
    }


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: perf_smoke_perfetto.py <serial-log> [output-json]")

    serial_log = Path(sys.argv[1])
    text = serial_log.read_text(encoding="utf-8", errors="replace")
    perfetto = build_perfetto_trace(text)
    output = json.dumps(perfetto, indent=2, sort_keys=False)
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(output + "\n", encoding="utf-8")
    else:
        sys.stdout.write(output)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
