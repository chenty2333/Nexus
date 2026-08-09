#!/usr/bin/env python3
"""Bounded concurrent soak for the durable tool endpoint."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import tempfile
import threading
import time
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from pathlib import Path

from tool_endpoint import Endpoint, Store


RUN_ID = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"


def post(port: int, key: str, payload: bytes) -> int:
    body = json.dumps(
        {
            "run_id": RUN_ID,
            "operation_key": key,
            "payload_digest": hashlib.sha256(payload).hexdigest(),
            "payload_b64": b64encode(payload).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST", "/v1/operations", body, {"Content-Type": "application/json"}
        )
        reply = connection.getresponse()
        reply.read()
        return reply.status
    finally:
        connection.close()


def run(seconds: float, workers: int, keys: int) -> dict[str, int | float]:
    with tempfile.TemporaryDirectory(prefix="cser-endpoint-soak-") as temp:
        database = Path(temp) / "tool.db"
        store = Store(database)
        server = Endpoint(("127.0.0.1", 0), store, False)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        port = server.server_port
        created = replayed = conflicts = batches = 0
        try:
            for index in range(keys):
                status = post(port, f"op-{index}", f"payload-{index}".encode())
                if status != HTTPStatus.CREATED:
                    raise RuntimeError(f"seed operation {index} returned {status}")
                created += 1

            deadline = time.monotonic() + seconds
            sequence = 0
            with ThreadPoolExecutor(max_workers=workers) as executor:
                while time.monotonic() < deadline:
                    jobs: list[tuple[str, bytes, bool]] = []
                    for offset in range(workers * 2):
                        index = (sequence + offset) % keys
                        conflicting = (sequence + offset) % 13 == 0
                        payload = (
                            f"conflict-{sequence + offset}".encode()
                            if conflicting
                            else f"payload-{index}".encode()
                        )
                        jobs.append((f"op-{index}", payload, conflicting))
                    statuses = list(
                        executor.map(lambda job: post(port, job[0], job[1]), jobs)
                    )
                    for status, (_, _, conflicting) in zip(statuses, jobs, strict=True):
                        expected = HTTPStatus.CONFLICT if conflicting else HTTPStatus.OK
                        if status != expected:
                            raise RuntimeError(
                                f"unexpected concurrent status {status}, expected {expected}"
                            )
                        if conflicting:
                            conflicts += 1
                        else:
                            replayed += 1
                    sequence += len(jobs)
                    batches += 1
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)
            store.close()

        reopened = Store(database)
        try:
            for index in range(keys):
                record = reopened.get(RUN_ID, f"op-{index}")
                expected = hashlib.sha256(f"payload-{index}".encode()).hexdigest()
                if record is None or record["payload_digest"] != expected:
                    raise RuntimeError(f"cold reopen mismatch for op-{index}")
        finally:
            reopened.close()

    return {
        "seconds": seconds,
        "workers": workers,
        "keys": keys,
        "batches": batches,
        "created": created,
        "replayed": replayed,
        "conflicts": conflicts,
        "errors": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=5.0)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--keys", type=int, default=32)
    args = parser.parse_args()
    if not 0 < args.seconds <= 300 or not 1 <= args.workers <= 64 or not 1 <= args.keys <= 1024:
        parser.error("require 0 < seconds <= 300, 1 <= workers <= 64, 1 <= keys <= 1024")
    summary = run(args.seconds, args.workers, args.keys)
    print("CSER_ENDPOINT_SOAK PASS " + json.dumps(summary, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
