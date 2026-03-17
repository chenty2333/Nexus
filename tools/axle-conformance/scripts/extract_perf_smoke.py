#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path


def extract_summary(text: str) -> dict[str, int | str]:
    match = re.search(r"kernel: bootstrap perf smoke \((.*)\)", text)
    if not match:
        raise SystemExit("bootstrap perf smoke summary line not found")

    fields: dict[str, int | str] = {}
    for part in match.group(1).split(", "):
        key, value = part.split("=", 1)
        value = value.strip()
        try:
            fields[key] = int(value)
        except ValueError:
            fields[key] = value
    return fields


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: extract_perf_smoke.py <serial-log>")

    text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    json.dump(extract_summary(text), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
