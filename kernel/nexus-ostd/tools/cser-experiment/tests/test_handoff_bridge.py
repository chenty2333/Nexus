from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from handoff_identity import (  # noqa: E402
    ParentDescriptorContext,
    child_transport_effect_id,
    expected_child_request,
    validate_child_descriptor_v1,
)
from protocol import ProtocolError  # noqa: E402
from protocol import digest, evidence_record_digest_v3, request_v3  # noqa: E402
from tool_provider import ProviderStore  # noqa: E402
import uart_http_bridge as bridge  # noqa: E402


class HandoffIdentityTests(unittest.TestCase):
    namespace = "tool-dma"
    authority = "b" * 32
    parent_effect = "c" * 32
    run_id = "d" * 32
    catalog = "a" * 64
    operation = "handoff-op"
    payload = b"discover-child-v1:0000000000000077:0000000000000002:00000005"

    def test_child_transport_effect_golden_vector_and_full_identity_binding(self) -> None:
        # Rust golden: SHA-256(domain || u64le(len(field)) || field ...),
        # fields namespace UTF-8, then decoded 16B authority/effect/run and
        # decoded 32B catalog; first 16 bytes.
        derived = child_transport_effect_id(self.namespace, self.authority, self.parent_effect, self.run_id, self.catalog)
        self.assertEqual(derived, "18f228fd72ac7f086085493528698c05")
        self.assertNotEqual(derived, child_transport_effect_id(self.namespace, self.authority, "e" * 32, self.run_id, self.catalog))
        self.assertNotEqual(derived, "0" * 32)

    def test_provider_descriptor_requires_exact_parent_input_catalog_and_route(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            provider = ProviderStore(Path(directory) / "provider.sqlite")
            try:
                input_digest = hashlib.sha256(self.payload).hexdigest()
                identity = (self.namespace, self.authority, self.parent_effect, self.catalog, self.run_id, self.operation)
                wire = provider.apply(identity, input_digest, self.payload).output
                parent = ParentDescriptorContext(0x77, 2, 5)
                validate_child_descriptor_v1(wire, parent=parent, catalog_digest=self.catalog, input_digest=input_digest)
                damaged = bytearray(wire); damaged[38] ^= 1  # route digest
                with self.assertRaises(ProtocolError):
                    validate_child_descriptor_v1(bytes(damaged), parent=parent, catalog_digest=self.catalog, input_digest=input_digest)
                with self.assertRaises(ProtocolError):
                    validate_child_descriptor_v1(wire, parent=ParentDescriptorContext(0x78, 2, 5), catalog_digest=self.catalog, input_digest=input_digest)
            finally:
                provider.close()


class HandoffSessionTests(unittest.TestCase):
    namespace = "tool-dma"
    authority = "b" * 32
    parent_effect = "c" * 32
    run_id = "d" * 32
    catalog = "a" * 64
    operation = "handoff-op"
    payload = b"discover-child-v1:0000000000000077:0000000000000002:00000005"
    class Socket:
        def settimeout(self, timeout: float) -> None: pass

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.provider = ProviderStore(Path(self.directory.name) / "provider.sqlite")
        self.parent = (self.namespace, self.authority, self.parent_effect, self.run_id, self.catalog)
        self.context = ParentDescriptorContext(0x77, 2, 5)
        self.parent_input = digest(self.payload)
        self.wire = self.provider.apply((*self.parent[:3], self.catalog, self.run_id, self.operation), self.parent_input, self.payload).output
        self.child_effect = child_transport_effect_id(*self.parent)
        self.child_operation, self.child_payload, self.child_input = expected_child_request(self.wire, parent=self.context)

    def tearDown(self) -> None:
        self.provider.close(); self.directory.cleanup()

    def _record(self, identity: tuple[str, str, str, str, str], operation: str, input_digest: str,
                *, output_kind: str, output: bytes, state: str = "succeeded") -> dict[str, str]:
        namespace, authority, effect, run, catalog = identity
        result = "success"
        return {"contract_version": "3", "namespace_id": namespace, "authority_id": authority, "effect_id": effect,
                "run_id": run, "operation_key": operation, "input_digest": input_digest, "catalog_digest": catalog,
                "record_schema_version": "3", "state": state, "result": result, "output_kind": output_kind,
                "output_len": str(len(output)), "output_digest": digest(output),
                "output_b64": __import__("base64").b64encode(output).decode() if output else "-",
                "evidence_record_digest": evidence_record_digest_v3(namespace, authority, effect, run, operation, input_digest, catalog, state, result, output_kind, output),
                "created_at_ns": "1", "updated_at_ns": "1", "expires_at_ns": "2", "replayed": "false"}

    def _run(self, frames: list[bytes], posts: list[tuple[int, dict[str, str]]],
             gets: list[tuple[int, dict[str, str]]]) -> None:
        with patch.object(bridge, "_read_request_frame", side_effect=frames), \
             patch.object(bridge, "post_v3", side_effect=posts), \
             patch.object(bridge, "get_v3", side_effect=gets), \
             patch.object(bridge, "paced_sendall"):
            bridge.serve_handoff_session(self.Socket(), parent_endpoint=("p", 1), child_endpoint=("c", 2),
                                         parent_identity=self.parent, parent_descriptor=self.context)

    def test_happy_parent_then_exact_child(self) -> None:
        child = (self.namespace, self.authority, self.child_effect, self.run_id, self.catalog)
        frames = [request_v3(*self.parent[:3], self.run_id, self.operation, b"", self.catalog,
                             method="GET", expected_input_digest=self.parent_input),
                  request_v3(*self.parent[:3], self.run_id, self.operation, self.payload, self.catalog),
                  request_v3(*child[:3], self.run_id, self.child_operation, b"", self.catalog,
                             method="GET", expected_input_digest=self.child_input),
                  request_v3(*child[:3], self.run_id, self.child_operation, self.child_payload, self.catalog)]
        self._run(frames, [(200, self._record(self.parent, self.operation, self.parent_input, output_kind="child_descriptor_v1", output=self.wire)),
                           (200, self._record(child, self.child_operation, self.child_input, output_kind="none", output=b""))],
                  [(404, {}), (404, {})])

    def test_rejects_child_before_parent_and_cross_effect_and_bad_child_request(self) -> None:
        child = (self.namespace, self.authority, self.child_effect, self.run_id, self.catalog)
        for frame in (
            request_v3(*child[:3], self.run_id, self.child_operation, self.child_payload, self.catalog),
            request_v3(self.namespace, self.authority, "e" * 32, self.run_id, self.child_operation, self.child_payload, self.catalog),
        ):
            with patch.object(bridge, "_read_request_frame", return_value=frame):
                with self.assertRaises(bridge.BridgeStageError):
                    bridge.serve_handoff_session(self.Socket(), parent_endpoint=("p", 1), child_endpoint=("c", 2), parent_identity=self.parent, parent_descriptor=self.context)
        parent_get = request_v3(*self.parent[:3], self.run_id, self.operation, b"", self.catalog,
                                method="GET", expected_input_digest=self.parent_input)
        parent_frame = request_v3(*self.parent[:3], self.run_id, self.operation, self.payload, self.catalog)
        bad_child = request_v3(*child[:3], self.run_id, "wrong", b"bad", self.catalog)
        with patch.object(bridge, "_read_request_frame", side_effect=[parent_get, parent_frame, bad_child]), \
             patch.object(bridge, "post_v3", return_value=(200, self._record(self.parent, self.operation, self.parent_input, output_kind="child_descriptor_v1", output=self.wire))), \
             patch.object(bridge, "get_v3", return_value=(404, {})), \
             patch.object(bridge, "paced_sendall"):
            with self.assertRaises(bridge.BridgeStageError):
                bridge.serve_handoff_session(self.Socket(), parent_endpoint=("p", 1), child_endpoint=("c", 2), parent_identity=self.parent, parent_descriptor=self.context)

    def test_rejects_cser2_and_post_404(self) -> None:
        cser2 = request_v3(*self.parent[:3], self.run_id, self.operation, self.payload, self.catalog).replace(b"CSER3", b"CSER2", 1)
        with patch.object(bridge, "_read_request_frame", return_value=cser2):
            with self.assertRaises(ProtocolError):
                bridge.serve_handoff_session(self.Socket(), parent_endpoint=("p", 1), child_endpoint=("c", 2), parent_identity=self.parent, parent_descriptor=self.context)
        frame = request_v3(*self.parent[:3], self.run_id, self.operation, self.payload, self.catalog)
        with patch.object(bridge, "_read_request_frame", return_value=frame):
            with self.assertRaisesRegex(bridge.BridgeStageError, "GET/404"):
                bridge.serve_handoff_session(self.Socket(), parent_endpoint=("p", 1), child_endpoint=("c", 2), parent_identity=self.parent, parent_descriptor=self.context)

    def test_child_terminal_get_binds_operation_and_input_but_has_empty_wire_payload(self) -> None:
        child = (self.namespace, self.authority, self.child_effect, self.run_id, self.catalog)
        frames = [request_v3(*self.parent[:3], self.run_id, self.operation, b"", self.catalog,
                             method="GET", expected_input_digest=self.parent_input),
                  request_v3(*self.parent[:3], self.run_id, self.operation, self.payload, self.catalog),
                  request_v3(*child[:3], self.run_id, self.child_operation, b"", self.catalog,
                             method="GET", expected_input_digest=self.child_input)]
        parent_record = self._record(self.parent, self.operation, self.parent_input, output_kind="child_descriptor_v1", output=self.wire)
        child_record = self._record(child, self.child_operation, self.child_input, output_kind="none", output=b"")
        with patch.object(bridge, "_read_request_frame", side_effect=frames), \
             patch.object(bridge, "post_v3", return_value=(200, parent_record)), \
             patch.object(bridge, "get_v3", side_effect=[(404, {}), (200, child_record)]), \
             patch.object(bridge, "paced_sendall"):
            bridge.serve_handoff_session(self.Socket(), parent_endpoint=("p", 1), child_endpoint=("c", 2),
                                         parent_identity=self.parent, parent_descriptor=self.context)

    def test_child_get_404_allows_only_exact_following_post(self) -> None:
        child = (self.namespace, self.authority, self.child_effect, self.run_id, self.catalog)
        frames = [request_v3(*self.parent[:3], self.run_id, self.operation, b"", self.catalog,
                             method="GET", expected_input_digest=self.parent_input),
                  request_v3(*self.parent[:3], self.run_id, self.operation, self.payload, self.catalog),
                  request_v3(*child[:3], self.run_id, self.child_operation, b"", self.catalog,
                             method="GET", expected_input_digest=self.child_input),
                  request_v3(*child[:3], self.run_id, self.child_operation, self.child_payload, self.catalog)]
        parent_record = self._record(self.parent, self.operation, self.parent_input, output_kind="child_descriptor_v1", output=self.wire)
        child_record = self._record(child, self.child_operation, self.child_input, output_kind="none", output=b"")
        with patch.object(bridge, "_read_request_frame", side_effect=frames), \
             patch.object(bridge, "post_v3", side_effect=[(200, parent_record), (200, child_record)]), \
             patch.object(bridge, "get_v3", side_effect=[(404, {}), (404, {})]), \
             patch.object(bridge, "paced_sendall"):
            bridge.serve_handoff_session(self.Socket(), parent_endpoint=("p", 1), child_endpoint=("c", 2),
                                         parent_identity=self.parent, parent_descriptor=self.context)


if __name__ == "__main__":
    unittest.main()
