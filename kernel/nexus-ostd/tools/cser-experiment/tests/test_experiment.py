from __future__ import annotations

import http.client
import json
import socket
import sys
import tempfile
import threading
import unittest
from base64 import b64decode, b64encode
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol import (MAX_LINE_BYTES, MAX_PAYLOAD_BYTES, ProtocolError, digest,
                      evidence_record_digest, evidence_record_digest_v3, parse_request, parse_request_v2, parse_request_v3, record_digest,
                      request, request_v2, request_v3, response, response_v2, response_v3)
from tool_endpoint import Endpoint, Store
from uart_http_bridge import BridgeStageError, _serve_client, _serve_client_v2, connect_and_serve, serve
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
        self.server.fault_after_response_commit_once = True
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
    def test_cser2_golden_identity_frame_and_expiry_is_nonterminal(self) -> None:
        namespace, authority, effect, run, operation = "tool-dma-a", "a" * 32, "b" * 32, "c" * 32, "op-1"
        catalog, payload = "d" * 64, b"body"
        expected_request = b"CSER2 REQ POST tool-dma-a aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccc op-1 230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd Ym9keQ== 91b54ca0980cc688c385c23b3c1fec77a39dbe74401f057d488bad3430eac202\n"
        frame = request_v2(namespace, authority, effect, run, operation, payload, catalog)
        self.assertEqual(frame, expected_request)
        self.assertEqual(parse_request_v2(frame), ("POST", namespace, authority, effect, run, operation, digest(payload), catalog, payload))
        expired = response_v2(namespace, authority, effect, run, operation, digest(payload), catalog, 410, "expired", "retention_expired", None)
        self.assertEqual(expired, b"CSER2 RESP 410 tool-dma-a aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccc op-1 230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd expired retention_expired - edb2a26ce22598c4772f866fee78e16a1cd34b03d65ea608f3e953924c2fd375\n")
        evidence = evidence_record_digest(namespace, authority, effect, run, operation, digest(payload), catalog, 2, "succeeded", "success")
        self.assertEqual(response_v2(namespace, authority, effect, run, operation, digest(payload), catalog, 201, "succeeded", "success", evidence), b"CSER2 RESP 201 tool-dma-a aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccc op-1 230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd succeeded success f687e1c2ba5433cb134e961e490b7c35ef900f39b14f8a1634fd92a7d6941613 b1e977c1b3fc1d5120666a3373257d0e6967d16c61595da124e99ab096c38233\n")
        failed = evidence_record_digest(namespace, authority, effect, run, operation, digest(payload), catalog, 2, "failed", "remote_failed")
        self.assertEqual(response_v2(namespace, authority, effect, run, operation, digest(payload), catalog, 409, "failed", "remote_failed", failed), b"CSER2 RESP 409 tool-dma-a aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccc op-1 230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd failed remote_failed a6e9f8f63fd0a76931527d63a8849d6c73b18fbbd20ed96dbea88cfcd47d5ab2 aba8c48cddfcffec81624d5bf3ac99ea6e385ad608a525500ba904b6cfd95d8e\n")
        self.assertEqual(response_v2(namespace, authority, effect, run, operation, digest(payload), catalog, 404, "absent", "not_found", None), b"CSER2 RESP 404 tool-dma-a aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccc op-1 230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd absent not_found - df3447d5f56d7db483a1a2e8a9ed74d64f87f68c48fa75f66d21c08879ec3710\n")

    def test_uart_limits_match_guest_codec(self) -> None:
        run = "a" * 32
        with self.assertRaises(ProtocolError):
            request(run, "op", b"x" * 577)
        with self.assertRaises(ProtocolError):
            parse_request(b"x" * MAX_LINE_BYTES + b"\n")

    def test_cser3_output_is_terminal_only_and_digest_bound(self) -> None:
        namespace, authority, effect, run, operation, catalog = "tool", "a" * 32, "b" * 32, "c" * 32, "op", "d" * 64
        payload, output = b"body", b"NXSCHD01" + b"x" * 120
        self.assertEqual(parse_request_v3(request_v3(namespace, authority, effect, run, operation, payload, catalog))[0], "POST")
        evidence = evidence_record_digest_v3(namespace, authority, effect, run, operation, digest(payload), catalog,
                                             "succeeded", "success", "child_descriptor_v1", output)
        self.assertIn(b"child_descriptor_v1", response_v3(namespace, authority, effect, run, operation,
                                                             digest(payload), catalog, 200, "succeeded", "success",
                                                             "child_descriptor_v1", output, evidence))
        with self.assertRaises(ProtocolError):
            response_v3(namespace, authority, effect, run, operation, digest(payload), catalog, 202,
                        "pending", "working", "child_descriptor_v1", output, evidence)

    def test_maximum_guest_v2_request_fits_and_round_trips(self) -> None:
        payload = b"x" * MAX_PAYLOAD_BYTES
        frame = request_v2(
            "n" * 128, "a" * 32, "b" * 32, "c" * 32,
            "o" * 64, payload, "d" * 64,
        )
        self.assertGreater(len(frame), 1024)
        self.assertLessEqual(len(frame), MAX_LINE_BYTES)
        parsed = parse_request_v2(frame)
        self.assertEqual(parsed[1:8], (
            "n" * 128, "a" * 32, "b" * 32, "c" * 32,
            "o" * 64, digest(payload), "d" * 64,
        ))
        self.assertEqual(parsed[8], payload)

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
    def test_cser3_bridge_forwards_pending_then_evidence_bound_terminal_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            namespace, authority, effect = "tool-dma-v3", "a" * 32, "b" * 32
            run, catalog, operation = "c" * 32, "d" * 64, "descriptor-op"
            store = Store(
                Path(temp) / "tool.db", namespace_id=namespace, authority_id=authority,
                effect_id=effect, catalog_digest=catalog,
            )
            server = Endpoint(("127.0.0.1", 0), store, False)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            identity = (namespace, authority, effect, run, catalog)
            payload = b"discover-child-v1:0000000000000077:0000000000000002:00000005"

            def exchange(frame: bytes) -> bytes:
                host, guest = socket.socketpair()
                errors: list[BaseException] = []
                def serve_v3() -> None:
                    try:
                        _serve_client_v2(host, ("127.0.0.1", server.server_port), identity, cser3=True)
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        host.close()
                worker = threading.Thread(target=serve_v3, daemon=True)
                guest.settimeout(2)
                worker.start()
                guest.sendall(frame)
                try:
                    reply = guest.recv(2048)
                finally:
                    guest.close()
                    worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                return reply

            self.assertIn(
                b" RESP 202 ",
                exchange(request_v3(namespace, authority, effect, run, operation, payload, catalog)),
            )
            self.assertTrue(server.worker.run_once())
            terminal = exchange(request_v3(
                namespace, authority, effect, run, operation, b"", catalog,
                method="GET", expected_input_digest=digest(payload),
            ))
            self.assertIn(b" RESP 200 ", terminal)
            self.assertIn(b" child_descriptor_v1 187 ", terminal)
            self.assertEqual(b"NXSCHD03", b64decode(terminal.split()[15])[:8])
            server.shutdown(); server.server_close(); store.close()

    def test_v2_bridge_post_get_absence_and_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "tool.db", namespace_id="tool-dma-a", authority_id="a" * 32,
                          effect_id="b" * 32, catalog_digest="d" * 64, retention_seconds=1)
            server = Endpoint(("127.0.0.1", 0), store, False)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            namespace, authority, effect, run, catalog = "tool-dma-a", "a" * 32, "b" * 32, "c" * 32, "d" * 64
            identity = (namespace, authority, effect, run, catalog)
            payload = b"body"; operation = "op-v2"; frame = request_v2(namespace, authority, effect, run, operation, payload, catalog)
            def exchange(request_frame: bytes) -> bytes:
                host, guest = socket.socketpair()
                errors: list[BaseException] = []
                def serve_v2() -> None:
                    try:
                        _serve_client_v2(host, ("127.0.0.1", server.server_port), identity)
                    except BaseException as error:
                        errors.append(error)
                worker = threading.Thread(target=serve_v2, daemon=True)
                guest.settimeout(2)
                worker.start(); guest.sendall(request_frame)
                try:
                    reply = guest.recv(1024)
                finally:
                    worker.join(2)
                    guest.close(); host.close()
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors)
                return reply
            self.assertIn(b" RESP 202 ", exchange(frame))
            self.assertTrue(server.worker.run_once())
            query = request_v2(namespace, authority, effect, run, operation, b"", catalog, method="GET", expected_input_digest=digest(payload))
            self.assertIn(b" RESP 200 ", exchange(query))
            missing = request_v2(namespace, authority, effect, run, "missing", b"", catalog, method="GET", expected_input_digest="e" * 64)
            self.assertIn(b" RESP 404 ", exchange(missing))
            store._connection.execute("UPDATE operations SET expires_at_ns=0")
            self.assertIn(b" RESP 410 ", exchange(query))
            server.shutdown(); server.server_close(); store.close()
    def test_bridge_labels_missing_first_uart_byte(self) -> None:
        host, guest = socket.socketpair()
        try:
            with self.assertRaises(BridgeStageError) as raised:
                _serve_client(host, ("127.0.0.1", 1), "a" * 32, 0.01)
            self.assertEqual(raised.exception.stage, "first-byte")
        finally:
            host.close(); guest.close()

    def test_real_bridge_publishes_served_status_after_one_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "tool.db")
            server = Endpoint(("127.0.0.1", 0), store, False)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            path = Path(temp) / "uart.sock"
            status = Path(temp) / "bridge-status.json"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path)); listener.listen(1)
            run = "0123456789abcdef0123456789abcdef"
            errors: list[BaseException] = []

            def run_bridge() -> None:
                try:
                    connect_and_serve(path, ("127.0.0.1", server.server_port), run, 1, 1, status)
                except BaseException as error:
                    errors.append(error)

            bridge = threading.Thread(target=run_bridge, daemon=True)
            bridge.start()
            peer, _ = listener.accept()
            try:
                peer.sendall(request(run, "op-1", b"payload"))
                self.assertIn(b" 201 ", peer.recv(2048))
            finally:
                peer.close(); listener.close()
            bridge.join(1)
            self.assertFalse(bridge.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(json.loads(status.read_text())["state"], "served")
            server.shutdown(); server.server_close(); store.close()

    def test_real_v2_bridge_serves_exact_404_then_one_post_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            namespace, authority, effect = "tool-dma-retry", "a" * 32, "b" * 32
            run, catalog = "c" * 32, "d" * 64
            store = Store(
                Path(temp) / "tool.db",
                namespace_id=namespace,
                authority_id=authority,
                effect_id=effect,
                catalog_digest=catalog,
            )
            server = Endpoint(("127.0.0.1", 0), store, False)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            path = Path(temp) / "uart.sock"
            status = Path(temp) / "bridge-status.json"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path)); listener.listen(1)
            identity = (namespace, authority, effect, run, catalog)
            payload = b"recovery-retry"
            errors: list[BaseException] = []

            def run_bridge() -> None:
                try:
                    connect_and_serve(
                        path,
                        ("127.0.0.1", server.server_port),
                        run,
                        1,
                        1,
                        status,
                        identity,
                    )
                except BaseException as error:
                    errors.append(error)

            bridge = threading.Thread(target=run_bridge, daemon=True)
            bridge.start()
            peer, _ = listener.accept()
            try:
                peer.sendall(request_v2(
                    namespace, authority, effect, run, "op-retry", b"", catalog,
                    method="GET", expected_input_digest=digest(payload),
                ))
                self.assertIn(b" RESP 404 ", peer.recv(2048))
                peer.sendall(request_v2(
                    namespace, authority, effect, run, "op-retry", payload, catalog,
                ))
                self.assertIn(b" RESP 202 ", peer.recv(2048))
            finally:
                peer.close(); listener.close()
            bridge.join(1)
            self.assertFalse(bridge.is_alive())
            self.assertEqual(errors, [])
            # v2 POST is asynchronous: without a worker, the accepted row is
            # an honest deferred run, not a terminal endpoint result.
            self.assertEqual(json.loads(status.read_text())["state"], "deferred")
            server.shutdown(); server.server_close(); store.close()

    def test_v2_bridge_rejects_changed_404_retry_before_endpoint_submit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            namespace, authority, effect = "tool-dma-retry", "a" * 32, "b" * 32
            run, catalog = "c" * 32, "d" * 64
            store = Store(
                Path(temp) / "tool.db", namespace_id=namespace,
                authority_id=authority, effect_id=effect, catalog_digest=catalog,
            )
            server = Endpoint(("127.0.0.1", 0), store, False)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            host, guest = socket.socketpair()
            payload = b"changed-retry"
            input_digest = digest(payload)
            errors: list[BaseException] = []

            def serve_retry() -> None:
                try:
                    first = _serve_client_v2(
                        host, ("127.0.0.1", server.server_port),
                        (namespace, authority, effect, run, catalog),
                    )
                    _serve_client_v2(
                        host, ("127.0.0.1", server.server_port),
                        (namespace, authority, effect, run, catalog),
                        expected_retry=(first[2], first[3]),
                    )
                except BaseException as error:
                    errors.append(error)
                finally:
                    host.close()

            worker = threading.Thread(target=serve_retry, daemon=True)
            worker.start()
            guest.sendall(request_v2(
                namespace, authority, effect, run, "original", b"", catalog,
                method="GET", expected_input_digest=input_digest,
            ))
            self.assertIn(b" RESP 404 ", guest.recv(2048))
            guest.sendall(request_v2(
                namespace, authority, effect, run, "different", payload, catalog,
            ))
            self.assertEqual(guest.recv(2048), b"")
            worker.join(1); guest.close()
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], BridgeStageError)
            self.assertIsNone(store.get(run, "different"))
            server.shutdown(); server.server_close(); store.close()

    def test_recovery_bridge_reports_unused_after_firmware_only_close(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "uart.sock"
            status = Path(temp) / "bridge-status.json"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path)); listener.listen(1)
            run = "c" * 32
            identity = ("tool-dma-unused", "a" * 32, "b" * 32, run, "d" * 64)
            errors: list[BaseException] = []

            def run_bridge() -> None:
                try:
                    connect_and_serve(
                        path, ("127.0.0.1", 1), run, 1, 1, status,
                        identity, 0.0, True,
                    )
                except BaseException as error:
                    errors.append(error)

            bridge = threading.Thread(target=run_bridge, daemon=True)
            bridge.start()
            peer, _ = listener.accept()
            peer.sendall(b"OVMF boot console\n")
            peer.close(); listener.close()
            bridge.join(1)
            self.assertFalse(bridge.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(json.loads(status.read_text())["state"], "unused")

    def test_real_bridge_publishes_endpoint_connect_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "uart.sock"
            status = Path(temp) / "bridge-status.json"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path)); listener.listen(1)
            run = "0123456789abcdef0123456789abcdef"
            errors: list[BaseException] = []

            def run_bridge() -> None:
                try:
                    connect_and_serve(path, ("127.0.0.1", 1), run, 1, 0.1, status)
                except BaseException as error:
                    errors.append(error)

            bridge = threading.Thread(target=run_bridge, daemon=True)
            bridge.start()
            peer, _ = listener.accept()
            try:
                peer.sendall(request(run, "op-1", b"payload"))
                self.assertIn(b" 503 ", peer.recv(2048))
            finally:
                peer.close(); listener.close()
            bridge.join(1)
            self.assertFalse(bridge.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], BridgeStageError)
            signal = json.loads(status.read_text())
            self.assertEqual(signal["state"], "failed")
            self.assertEqual(signal["stage"], "endpoint-connect")

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
    def test_recovery_configuration_is_required_when_a_catalog_is_supplied(self) -> None:
        from matrix_protocol import config_response
        import hashlib

        hello = b"CSER1 CONFIG_HELLO"
        host, guest = socket.socketpair()
        guest.sendall(hello + b" " + hashlib.sha256(hello).hexdigest().encode() + b"\n")
        guest.shutdown(socket.SHUT_WR)
        thread = threading.Thread(target=consume_recovery_uart, args=(host, "a" * 32, "b" * 64, "tool", "c" * 32, "d" * 32))
        thread.start()
        self.assertEqual(guest.recv(1024), config_response("a" * 32, "b" * 64, "tool", "c" * 32, "d" * 32))
        thread.join(1)
        guest.close(); host.close()

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
