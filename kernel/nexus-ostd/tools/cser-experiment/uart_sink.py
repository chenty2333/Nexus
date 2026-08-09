#!/usr/bin/env python3
"""Hold an otherwise-unused QEMU UART socket open for a recovery boot."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path

from matrix_protocol import (BarrierProtocolError, UART_WRITE_INTER_CHUNK_SECONDS, config_response,
                             paced_sendall, parse_barrier, parse_config_hello)


MAX_FIRMWARE_PREAMBLE_BYTES = 64 * 1024


def _write_signal(path: Path | None, state: str, *, stage: str | None = None,
                  detail: str | None = None) -> None:
    """Write a trusted-local, atomic supervisor status (never guest evidence)."""
    if path is None:
        return
    document: dict[str, str] = {"state": state}
    if stage is not None:
        document["stage"] = stage
    if detail is not None:
        document["detail"] = detail[:512]
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def consume_recovery_uart(
    client: socket.socket, expected_run_id: str, catalog_digest: str | None = None,
    namespace_id: str | None = None, authority_id: str | None = None, effect_id: str | None = None,
    uart_pace_seconds: float = 0.0,
) -> None:
    """Accept bounded firmware noise but reject every recovery crash barrier."""
    data = bytearray()
    configured = False
    while len(data) <= MAX_FIRMWARE_PREAMBLE_BYTES:
        block = client.recv(256)
        if not block:
            if b"CSER1 BARRIER " in data:
                raise RuntimeError("recovery boot emitted a truncated crash barrier")
            if catalog_digest is not None and not configured:
                raise RuntimeError("recovery boot closed COM3 without a configuration hello")
            return
        data.extend(block)
        while b"\n" in data:
            line, _, tail = data.partition(b"\n")
            data = bytearray(tail)
            marker = line.find(b"CSER1 BARRIER ")
            config_marker = line.find(b"CSER1 CONFIG_HELLO ")
            if config_marker >= 0:
                if catalog_digest is None or namespace_id is None or authority_id is None or effect_id is None:
                    raise RuntimeError("legacy recovery sink does not accept configuration hello")
                if configured:
                    raise RuntimeError("recovery boot emitted a duplicate configuration hello")
                try:
                    parse_config_hello(line[config_marker:] + b"\n")
                    paced_sendall(client, config_response(expected_run_id, catalog_digest, namespace_id, authority_id, effect_id), inter_chunk_seconds=uart_pace_seconds)
                except (BarrierProtocolError, OSError) as exc:
                    raise RuntimeError(f"malformed recovery configuration hello: {exc}") from exc
                configured = True
                continue
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
    parser.add_argument("--catalog-digest", required=True)
    parser.add_argument("--namespace-id", required=True)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--effect-id", required=True)
    parser.add_argument("--connect-timeout", type=float, default=90.0)
    parser.add_argument("--startup-ready-file", type=Path)
    parser.add_argument("--status-file", type=Path)
    parser.add_argument("--uart-pace-seconds", type=float, default=UART_WRITE_INTER_CHUNK_SECONDS)
    args = parser.parse_args()

    _write_signal(args.startup_ready_file, "ready")
    _write_signal(args.status_file, "starting")
    try:
        deadline = time.monotonic() + args.connect_timeout
        last_error: OSError | None = None
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while time.monotonic() < deadline:
            try:
                client.connect(str(args.socket.resolve()))
                _write_signal(args.status_file, "connected")
                break
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        else:
            raise RuntimeError(f"UART socket unavailable: {last_error}")

        consume_recovery_uart(client, args.run_id, args.catalog_digest, args.namespace_id, args.authority_id, args.effect_id, args.uart_pace_seconds)
        _write_signal(args.status_file, "closed")
    except (OSError, RuntimeError, ValueError) as exc:
        _write_signal(args.status_file, "failed", stage="recovery-receipt", detail=str(exc))
        raise


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"uart sink: {exc}", file=sys.stderr)
        raise SystemExit(1)
