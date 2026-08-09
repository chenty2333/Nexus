from __future__ import annotations

import hashlib
import http.client
import json
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol import request
from tool_endpoint import Endpoint, Store
from uart_http_bridge import BridgeStageError, _serve_client


RUN_ID = "0123456789abcdef0123456789abcdef"


def _post(port: int, key: str, payload: bytes) -> tuple[int, dict[str, str]]:
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
        return reply.status, json.loads(reply.read())
    finally:
        connection.close()


class EndpointConcurrencyFaultTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "tool.db"
        self.store = Store(self.database)
        self.server = Endpoint(("127.0.0.1", 0), self.store, False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.store.close()
        self.temp.cleanup()

    def test_concurrent_same_key_linearizes_to_one_create_and_one_record(self) -> None:
        with ThreadPoolExecutor(max_workers=16) as executor:
            replies = list(
                executor.map(
                    lambda _: _post(self.server.server_port, "same-key", b"same-payload"),
                    range(64),
                )
            )
        statuses = [status for status, _ in replies]
        self.assertEqual(statuses.count(HTTPStatus.CREATED), 1)
        self.assertEqual(statuses.count(HTTPStatus.OK), 63)
        digests = {document["record_digest"] for _, document in replies}
        self.assertEqual(len(digests), 1)

    def test_concurrent_conflicting_payloads_choose_exactly_one_identity(self) -> None:
        jobs = [b"left"] * 32 + [b"right"] * 32
        with ThreadPoolExecutor(max_workers=16) as executor:
            replies = list(
                executor.map(
                    lambda payload: _post(self.server.server_port, "conflict-key", payload),
                    jobs,
                )
            )
        statuses = [status for status, _ in replies]
        self.assertEqual(statuses.count(HTTPStatus.CREATED), 1)
        self.assertEqual(statuses.count(HTTPStatus.CONFLICT), 32)
        self.assertEqual(statuses.count(HTTPStatus.OK), 31)
        durable = self.store.get(RUN_ID, "conflict-key")
        self.assertIsNotNone(durable)
        self.assertIn(
            durable["payload_digest"],
            {hashlib.sha256(b"left").hexdigest(), hashlib.sha256(b"right").hexdigest()},
        )

    def test_lost_reply_survives_endpoint_shutdown_and_cold_reopen(self) -> None:
        self.server.fault_after_apply_once = True
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=5
        )
        payload = b"durable-before-reply"
        body = json.dumps(
            {
                "run_id": RUN_ID,
                "operation_key": "lost-reply",
                "payload_digest": hashlib.sha256(payload).hexdigest(),
                "payload_b64": b64encode(payload).decode("ascii"),
            }
        )
        connection.request(
            "POST", "/v1/operations", body, {"Content-Type": "application/json"}
        )
        with self.assertRaises(http.client.RemoteDisconnected):
            connection.getresponse()
        connection.close()

        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.store.close()
        reopened = Store(self.database)
        try:
            record = reopened.get(RUN_ID, "lost-reply")
            self.assertIsNotNone(record)
            self.assertEqual(record["status"], "applied")
            self.assertEqual(record["payload_digest"], hashlib.sha256(payload).hexdigest())
        finally:
            reopened.close()

        # Prevent tearDown from closing the already closed objects twice.
        self.store = Store(self.database)
        self.server = Endpoint(("127.0.0.1", 0), self.store, False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_corrupt_sqlite_file_is_rejected_instead_of_reinitialized(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.store.close()
        self.database.write_bytes(b"not-a-sqlite-database")
        with self.assertRaises(sqlite3.DatabaseError):
            Store(self.database)

        # Replace the fixture so tearDown remains deterministic.
        self.database.unlink()
        self.store = Store(self.database)
        self.server = Endpoint(("127.0.0.1", 0), self.store, False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()


class _MalformedRecordHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        request_document = json.loads(self.rfile.read(length))
        document = {
            "run_id": request_document["run_id"],
            "operation_key": request_document["operation_key"],
            "payload_digest": request_document["payload_digest"],
            "status": "applied",
            "result": "success",
            "record_digest": "0" * 64,
        }
        body = json.dumps(document).encode("utf-8")
        self.send_response(HTTPStatus.CREATED)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class BridgeFaultTest(unittest.TestCase):
    def _exchange(self, endpoint: tuple[str, int]) -> tuple[BridgeStageError, bytes]:
        host, guest = socket.socketpair()
        failures: list[BridgeStageError] = []
        outcomes: list[bool] = []

        thread = threading.Thread(
            target=lambda: outcomes.append(
                _serve_client(host, endpoint, RUN_ID, 2.0, failure=failures)
            ),
            daemon=True,
        )
        thread.start()
        try:
            guest.sendall(request(RUN_ID, "bridge-fault", b"payload"))
            reply = guest.recv(2048)
        finally:
            guest.close()
            host.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes, [False])
        self.assertEqual(len(failures), 1)
        return failures[0], reply

    def test_unavailable_endpoint_returns_only_nonterminal_503(self) -> None:
        reserve = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        reserve.close()
        error, reply = self._exchange(("127.0.0.1", port))
        self.assertEqual(error.stage, "endpoint-connect")
        self.assertIn(b" 503 ", reply)
        self.assertIn(b" - - - - ", reply)

    def test_malformed_endpoint_record_returns_only_nonterminal_503(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _MalformedRecordHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            error, reply = self._exchange(("127.0.0.1", server.server_port))
            self.assertEqual(error.stage, "frame-complete")
            self.assertIn(b" 503 ", reply)
            self.assertIn(b" - - - - ", reply)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
