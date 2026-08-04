from __future__ import annotations

import http.client
import json
import socket
import sys
import tempfile
import threading
import unittest
from base64 import b64encode
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol import ProtocolError, parse_request, record_digest, request, response
from tool_endpoint import Endpoint, Store
from uart_http_bridge import serve
from uart_sink import consume_recovery_uart


class EndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "tool.db")
        self.server = Endpoint(("127.0.0.1", 0), self.store, False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.store.close()
        self.temp.cleanup()

    def post(self, key: str, payload: bytes) -> tuple[int, dict[str, str]]:
        import hashlib

        body = json.dumps(
            {"run_id": "0123456789abcdef0123456789abcdef", "operation_key": key, "payload_digest": hashlib.sha256(payload).hexdigest(), "payload_b64": b64encode(payload).decode()}
        )
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        conn.request("POST", "/v1/operations", body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        result = response.status, json.loads(response.read())
        conn.close()
        return result

    def test_idempotent_and_conflicting_posts(self) -> None:
        first_status, first = self.post("op-1", b"one")
        self.assertEqual(first_status, 201)
        self.assertEqual(first["status"], "applied")
        self.assertEqual(first["result"], "success")
        self.assertEqual(first["record_digest"], record_digest(
            first["run_id"], first["operation_key"], first["payload_digest"],
            first["status"], first["result"],
        ))
        status, document = self.post("op-1", b"one")
        self.assertEqual(status, 200)
        self.assertEqual(document["replayed"], "true")
        self.assertEqual(self.post("op-1", b"two")[0], 409)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        conn.request("GET", "/v1/operations/0123456789abcdef0123456789abcdef/op-1")
        reply = conn.getresponse()
        self.assertEqual(reply.status, 200)
        queried = json.loads(reply.read())
        self.assertEqual(queried["status"], "applied")
        self.assertEqual(queried["record_digest"], first["record_digest"])
        conn.close()

    def test_apply_before_response_fault_leaves_durable_operation(self) -> None:
        self.server.fault_after_apply_once = True
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        payload = b"ambiguous"
        import hashlib

        body = json.dumps({"run_id": "0123456789abcdef0123456789abcdef", "operation_key": "op-fault", "payload_digest": hashlib.sha256(payload).hexdigest(), "payload_b64": b64encode(payload).decode()})
        conn.request("POST", "/v1/operations", body, {"Content-Type": "application/json"})
        with self.assertRaises(http.client.RemoteDisconnected):
            conn.getresponse()
        conn.close()
        self.assertEqual(self.store.get("0123456789abcdef0123456789abcdef", "op-fault")["status"], "applied")


class ProtocolTest(unittest.TestCase):
    def test_request_round_trip_and_bad_checksum_rejected(self) -> None:
        run = "0123456789abcdef0123456789abcdef"
        frame = request(run, "op-1", b"hello")
        self.assertEqual(parse_request(frame)[0:3], ("POST", run, "op-1"))
        with self.assertRaises(ProtocolError):
            parse_request(frame[:-2] + b"0\n")

    def test_empty_payload_and_non_hex_run_id(self) -> None:
        run = "0123456789abcdef0123456789abcdef"
        self.assertEqual(parse_request(request(run, "empty", b""))[4], b"")
        self.assertEqual(parse_request(request(run, "empty", b"", "GET", "a" * 64))[0], "GET")
        with self.assertRaises(ProtocolError):
            request(run, "op-1", b"payload", "GET")
        with self.assertRaises(ProtocolError):
            request("run-1", "op-1", b"")

    def test_success_response_requires_complete_canonical_terminal_record(self) -> None:
        run = "0123456789abcdef0123456789abcdef"
        payload = b"hello"
        import hashlib

        payload_hash = hashlib.sha256(payload).hexdigest()
        digest = record_digest(run, "op-1", payload_hash, "applied", "success")
        frame = response(run, "op-1", 201, payload_hash, "applied", "success", digest)
        self.assertIn(digest.encode("ascii"), frame)
        with self.assertRaises(ProtocolError):
            response(run, "op-1", 201, payload_hash, "applied", "success", "0" * 64)
        with self.assertRaises(ProtocolError):
            response(run, "op-1", 201, None, "applied", "success", None)


class BridgeTest(unittest.TestCase):
    def test_bridge_ignores_bounded_firmware_preamble_before_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "tool.db")
            server = Endpoint(("127.0.0.1", 0), store, False)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            path = Path(temp) / "uart.sock"
            run = "0123456789abcdef0123456789abcdef"
            bridge = threading.Thread(
                target=serve,
                args=(path, ("127.0.0.1", server.server_port), run),
                daemon=True,
            )
            bridge.start()
            try:
                for _ in range(100):
                    if path.exists():
                        break
                    threading.Event().wait(0.01)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(path))
                client.sendall(b"\x1b[2JOVMF boot console\n\r" + request(run, "op-1", b"payload"))
                fields = client.recv(2048).decode("ascii").strip().split(" ")
                client.close()
                self.assertEqual(fields[0:5], ["CSER1", "RESP", run, "op-1", "201"])
            finally:
                server.shutdown()
                server.server_close()
                store.close()

    def test_get_absence_preserves_request_identity_without_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "tool.db")
            server = Endpoint(("127.0.0.1", 0), store, False)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            path = Path(temp) / "uart.sock"
            run = "0123456789abcdef0123456789abcdef"
            bridge = threading.Thread(
                target=serve,
                args=(path, ("127.0.0.1", server.server_port), run),
                daemon=True,
            )
            bridge.start()
            try:
                for _ in range(100):
                    if path.exists():
                        break
                    threading.Event().wait(0.01)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(path))
                client.sendall(request(run, "missing-op", b"", "GET", "a" * 64))
                fields = client.recv(2048).decode("ascii").strip().split(" ")
                client.close()
                self.assertEqual(fields[0:5], ["CSER1", "RESP", run, "missing-op", "404"])
                self.assertEqual(fields[5:9], ["-", "-", "-", "-"])
            finally:
                server.shutdown()
                server.server_close()
                store.close()

    def test_bridge_forwards_only_a_validated_durable_record_for_post_and_get(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "tool.db")
            server = Endpoint(("127.0.0.1", 0), store, False)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            path = Path(temp) / "uart.sock"
            run = "0123456789abcdef0123456789abcdef"
            bridge = threading.Thread(target=serve, args=(path, ("127.0.0.1", server.server_port), run), daemon=True)
            bridge.start()
            try:
                for _ in range(100):
                    if path.exists():
                        break
                    threading.Event().wait(0.01)
                import hashlib

                payload = b"durable"
                payload_hash = hashlib.sha256(payload).hexdigest()
                replies = []
                for frame in (
                    request(run, "op-1", payload),
                    request(run, "op-1", b"", "GET", payload_hash),
                ):
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.connect(str(path))
                    client.sendall(frame)
                    replies.append(client.recv(2048))
                    client.close()
                for index, reply in enumerate(replies):
                    fields = reply.decode("ascii").strip().split(" ")
                    self.assertEqual(fields[0:5], ["CSER1", "RESP", run, "op-1", "201" if index == 0 else "200"])
                    self.assertEqual(fields[5:8], [payload_hash, "applied", "success"])
                    self.assertEqual(fields[8], record_digest(run, "op-1", payload_hash, "applied", "success"))
            finally:
                server.shutdown()
                server.server_close()
                store.close()

    def test_wrong_run_id_is_not_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "uart.sock"
            expected = "0123456789abcdef0123456789abcdef"
            other = "fedcba9876543210fedcba9876543210"
            thread = threading.Thread(target=serve, args=(path, ("127.0.0.1", 1), expected), daemon=True)
            thread.start()
            for _ in range(100):
                if path.exists():
                    break
                threading.Event().wait(0.01)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(path))
            client.sendall(request(other, "op-1", b"body"))
            reply = client.recv(2048)
            client.close()
            self.assertIn(b" 503 ", reply)
            self.assertIn(b" - - - - ", reply)


class RecoveryUartSinkTest(unittest.TestCase):
    def test_firmware_preamble_is_allowed_but_barrier_is_rejected(self) -> None:
        from matrix_protocol import barrier

        host, guest = socket.socketpair()
        guest.sendall(b"OVMF boot console\n")
        guest.close()
        consume_recovery_uart(host, "a" * 32)
        host.close()

        host, guest = socket.socketpair()
        guest.sendall(b"OVMF boot console\n" + barrier("a" * 32, 1))
        guest.close()
        with self.assertRaises(RuntimeError):
            consume_recovery_uart(host, "a" * 32)
        host.close()


if __name__ == "__main__":
    unittest.main()
