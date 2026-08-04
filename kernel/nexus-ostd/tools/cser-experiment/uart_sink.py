#!/usr/bin/env python3
"""Hold an otherwise-unused QEMU UART socket open for a recovery boot."""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

from matrix_protocol import BarrierProtocolError, parse_barrier


MAX_FIRMWARE_PREAMBLE_BYTES = 64 * 1024


def consume_recovery_uart(client: socket.socket, expected_run_id: str) -> None:
    """Accept bounded firmware noise but reject every recovery crash barrier."""
    data = bytearray()
    while len(data) <= MAX_FIRMWARE_PREAMBLE_BYTES:
        block = client.recv(256)
        if not block:
            if b"CSER1 BARRIER " in data:
                raise RuntimeError("recovery boot emitted a truncated crash barrier")
            return
        data.extend(block)
        while b"\n" in data:
            line, _, tail = data.partition(b"\n")
            data = bytearray(tail)
            marker = line.find(b"CSER1 BARRIER ")
            if marker >= 0:
                try:
                    parse_barrier(line[marker:] + b"\n", expected_run_id=expected_run_id)
                except BarrierProtocolError as exc:
                    raise RuntimeError(f"malformed recovery crash barrier: {exc}") from exc
                raise RuntimeError("recovery boot unexpectedly emitted a crash barrier")
    raise RuntimeError("recovery UART firmware preamble exceeded bound")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--connect-timeout", type=float, default=90.0)
    args = parser.parse_args()

    deadline = time.monotonic() + args.connect_timeout
    last_error: OSError | None = None
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while time.monotonic() < deadline:
        try:
            client.connect(str(args.socket.resolve()))
            break
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    else:
        raise RuntimeError(f"UART socket unavailable: {last_error}")

    consume_recovery_uart(client, args.run_id)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"uart sink: {exc}", file=sys.stderr)
        raise SystemExit(1)
