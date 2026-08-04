#!/usr/bin/env python3
"""Independent durable HTTP endpoint for the CSER tool experiment.

The endpoint stores an applied operation before it sends a success response.
It intentionally has no dependency on Nexus or on the UART bridge.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from protocol import MAX_PAYLOAD_BYTES, ProtocolError, digest, record_digest, validate_run_id


def _valid_id(value: object) -> bool:
    import re

    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None


class Store:
    def __init__(self, database: Path) -> None:
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(database), check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=DELETE")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS operations (
                   run_id TEXT NOT NULL,
                   operation_key TEXT NOT NULL,
                   payload_digest TEXT NOT NULL,
                   payload BLOB NOT NULL,
                   status TEXT NOT NULL CHECK(status = 'applied'),
                   result TEXT NOT NULL CHECK(result = 'success'),
                   PRIMARY KEY(run_id, operation_key)
               )"""
        )

    @staticmethod
    def _record(run_id: str, operation_key: str, payload_digest: str, status: str, result: str) -> dict[str, str]:
        return {
            "run_id": run_id,
            "operation_key": operation_key,
            "payload_digest": payload_digest,
            "status": status,
            "result": result,
            "record_digest": record_digest(run_id, operation_key, payload_digest, status, result),
        }

    def apply(self, run_id: str, operation_key: str, payload_digest: str, payload: bytes) -> tuple[int, dict[str, str]]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT payload_digest, status, result FROM operations WHERE run_id = ? AND operation_key = ?",
                    (run_id, operation_key),
                ).fetchone()
                if existing is not None:
                    if existing[0] != payload_digest:
                        self._connection.execute("ROLLBACK")
                        return HTTPStatus.CONFLICT, {"error": "operation_key_payload_conflict"}
                    self._connection.execute("COMMIT")
                    return HTTPStatus.OK, self._record(run_id, operation_key, existing[0], existing[1], existing[2]) | {"replayed": "true"}
                self._connection.execute(
                    "INSERT INTO operations(run_id, operation_key, payload_digest, payload, status, result) VALUES (?, ?, ?, ?, 'applied', 'success')",
                    (run_id, operation_key, payload_digest, payload),
                )
                self._connection.execute("COMMIT")
                return HTTPStatus.CREATED, self._record(run_id, operation_key, payload_digest, "applied", "success") | {"replayed": "false"}
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def get(self, run_id: str, operation_key: str) -> dict[str, str] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_digest, status, result FROM operations WHERE run_id = ? AND operation_key = ?",
                (run_id, operation_key),
            ).fetchone()
        if row is None:
            return None
        return self._record(run_id, operation_key, row[0], row[1], row[2])

    def close(self) -> None:
        self._connection.close()


class Endpoint(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], store: Store, fault_after_apply_once: bool) -> None:
        super().__init__(address, Handler)
        self.store = store
        self.fault_after_apply_once = fault_after_apply_once
        self._fault_lock = threading.Lock()

    def take_fault(self) -> bool:
        with self._fault_lock:
            if not self.fault_after_apply_once:
                return False
            self.fault_after_apply_once = False
            return True


class Handler(BaseHTTPRequestHandler):
    server: Endpoint
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, status: int, document: dict[str, str]) -> None:
        data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _bad(self, message: str) -> None:
        self._json(HTTPStatus.BAD_REQUEST, {"error": message})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/operations":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        length = self.headers.get("Content-Length")
        try:
            size = int(length) if length is not None else -1
        except ValueError:
            size = -1
        if not 0 <= size <= MAX_PAYLOAD_BYTES * 2 + 1024:
            self._bad("invalid_content_length")
            return
        try:
            document = json.loads(self.rfile.read(size).decode("utf-8"))
            run_id = document["run_id"]
            operation_key = document["operation_key"]
            payload_digest = document["payload_digest"]
            encoded_payload = document["payload_b64"]
            payload = b"" if encoded_payload == "-" else base64.b64decode(encoded_payload.encode("ascii"), validate=True)
        except (AttributeError, KeyError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
            self._bad("invalid_request")
            return
        try:
            validate_run_id(run_id)
        except (ProtocolError, TypeError):
            self._bad("invalid_identifier")
            return
        if not _valid_id(operation_key) or not isinstance(payload_digest, str):
            self._bad("invalid_identifier")
            return
        if len(payload) > MAX_PAYLOAD_BYTES or len(payload_digest) != 64 or digest(payload) != payload_digest:
            self._bad("payload_digest_mismatch")
            return
        status, result = self.server.store.apply(run_id, operation_key, payload_digest, payload)
        # This models the important ambiguity: apply is durable, reply is lost.
        if status < 300 and self.server.take_fault():
            self.close_connection = True
            return
        self._json(status, result)

    def do_GET(self) -> None:  # noqa: N802
        prefix = "/v1/operations/"
        if not self.path.startswith(prefix):
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        parts = self.path[len(prefix):].split("/")
        try:
            valid_run = len(parts) == 2 and validate_run_id(parts[0])
        except (ProtocolError, TypeError):
            valid_run = False
        if not valid_run or not _valid_id(parts[1]):
            self._bad("invalid_identifier")
            return
        result = self.server.store.get(parts[0], parts[1])
        if result is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._json(HTTPStatus.OK, result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--port-file", type=Path)
    parser.add_argument("--fault-after-apply-once", action="store_true")
    args = parser.parse_args()
    endpoint = Endpoint((args.host, args.port), Store(args.database), args.fault_after_apply_once)
    if args.port_file is not None:
        args.port_file.write_text(f"{endpoint.server_port}\n", encoding="ascii")
    try:
        endpoint.serve_forever()
    finally:
        endpoint.server_close()
        endpoint.store.close()


if __name__ == "__main__":
    main()
