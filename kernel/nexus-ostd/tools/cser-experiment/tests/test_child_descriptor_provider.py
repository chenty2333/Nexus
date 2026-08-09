from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol import (
    CHILD_DESCRIPTOR_V1_ROUTE_DIGEST,
    CHILD_DESCRIPTOR_V1_WIRE_LEN,
    CHILD_DISCOVERY_V1_PREFIX,
)
from tool_provider import ProviderStore


CATALOG = "a" * 64
IDENTITY = ("tool-dma", "b" * 32, "c" * 32, CATALOG, "d" * 32, "handoff-op")
PAYLOAD = b"discover-child-v1:0000000000000077:0000000000000002:00000005"


def derived_u64(
    label: bytes, identity: tuple[str, str, str, str, str, str], input_digest: str,
) -> int:
    """Independent, deliberately non-provider implementation of the preimage."""
    hasher = hashlib.sha256(label)
    for field in (*identity, input_digest):
        encoded = field.encode("ascii")
        hasher.update(len(encoded).to_bytes(8, "little"))
        hasher.update(encoded)
    value = int.from_bytes(hasher.digest()[:8], "little")
    return value or 1


def parse_wire(wire: bytes) -> dict[str, int | bytes]:
    """Independent fixed-width parser used to keep the provider honest."""
    if len(wire) != CHILD_DESCRIPTOR_V1_WIRE_LEN or wire[:8] != b"NXSCHD03":
        raise ValueError("not a NXSCHD03 descriptor")
    offset = 8

    def take(count: int) -> bytes:
        nonlocal offset
        value = wire[offset:offset + count]
        if len(value) != count:
            raise ValueError("truncated descriptor")
        offset += count
        return value

    little = lambda count: int.from_bytes(take(count), "little")
    parsed: dict[str, int | bytes] = {
        "schema": little(2), "sequence": little(8), "parent_root": little(8),
        "parent_sequence": little(8), "parent_component": little(4),
        "route_digest": take(32), "child_kind": little(4), "child_component": little(4),
        "claim": little(8), "claim_kind": little(4), "scope_tag": little(1),
        "scope_id": little(8), "resource": little(8), "generation": little(8),
        "units": little(8), "input_digest": take(32), "catalog_digest": take(32),
    }
    if offset != len(wire):
        raise ValueError("trailing descriptor")
    return parsed


class ChildDescriptorProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "provider.sqlite"
        self.provider = ProviderStore(self.path)

    def tearDown(self) -> None:
        self.provider.close()
        self.temp.cleanup()

    def test_golden_discovery_is_provider_derived_fixed_wire(self) -> None:
        input_digest = hashlib.sha256(PAYLOAD).hexdigest()
        outcome = self.provider.apply(IDENTITY, input_digest, PAYLOAD)
        self.assertEqual((outcome.state, outcome.result, outcome.output_kind),
                         ("succeeded", "success", "child_descriptor_v1"))
        self.assertEqual(outcome.output.hex(), (
            "4e585343484430330100010000000000000077000000000000000200000000000000"
            "0500000028732d535f4e48d410ef5b7493245641b32de7a5fa0dfa7b5dfcf044fd001"
            "60c0500000005000000dbf7972e18a57fe401000000000000000000000000ffb19957"
            "5b0cfb0d0100000000000000010000000000000090f0bb7ee79f25008d7d8810e667fb"
            "d453f3d3480527870fb38110c71fb5ccd2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ))
        parsed = parse_wire(outcome.output)
        self.assertEqual(parsed, {
            "schema": 1, "sequence": 1, "parent_root": 0x77,
            "parent_sequence": 2, "parent_component": 5,
            "route_digest": CHILD_DESCRIPTOR_V1_ROUTE_DIGEST,
            "child_kind": 5, "child_component": 5,
            "claim": derived_u64(b"nexus-cser-tool-provider-child-claim-v1", IDENTITY, input_digest),
            "claim_kind": 1, "scope_tag": 0, "scope_id": 0,
            "resource": derived_u64(b"nexus-cser-tool-provider-child-resource-v1", IDENTITY, input_digest),
            "generation": 1, "units": 1,
            "input_digest": bytes.fromhex(input_digest), "catalog_digest": bytes.fromhex(CATALOG),
        })
        self.assertNotEqual(parsed["claim"], 0)
        self.assertNotEqual(parsed["resource"], 0)

    def test_dedup_and_provider_restart_preserve_identical_descriptor_bytes(self) -> None:
        input_digest = hashlib.sha256(PAYLOAD).hexdigest()
        first = self.provider.apply(IDENTITY, input_digest, PAYLOAD)
        self.assertEqual(self.provider.apply(IDENTITY, input_digest, PAYLOAD).output, first.output)
        self.provider.close()
        self.provider = ProviderStore(self.path)
        self.assertEqual(self.provider.apply(IDENTITY, input_digest, PAYLOAD).output, first.output)

    def test_different_operation_derives_a_different_exact_resource(self) -> None:
        input_digest = hashlib.sha256(PAYLOAD).hexdigest()
        first = parse_wire(self.provider.apply(IDENTITY, input_digest, PAYLOAD).output)
        other_identity = (*IDENTITY[:-1], "handoff-op-other")
        second = parse_wire(self.provider.apply(other_identity, input_digest, PAYLOAD).output)
        self.assertNotEqual(first["resource"], second["resource"])
        self.assertNotEqual(first["claim"], second["claim"])

    def test_malformed_or_oversized_discovery_is_verified_failure_without_output(self) -> None:
        for suffix in (b"not-hex", b"0" * 600):
            payload = CHILD_DISCOVERY_V1_PREFIX + suffix
            identity = (*IDENTITY[:-1], hashlib.sha256(payload).hexdigest())
            outcome = self.provider.apply(identity, hashlib.sha256(payload).hexdigest(), payload)
            self.assertEqual((outcome.state, outcome.result, outcome.output_kind, outcome.output),
                             ("failed", "invalid_child_discovery", "none", b""))

    def test_ordinary_payload_never_becomes_descriptor_output(self) -> None:
        payload = b"child-descriptor-v1:NXSCHD03" + b"x" * 187
        outcome = self.provider.apply(IDENTITY, hashlib.sha256(payload).hexdigest(), payload)
        self.assertEqual((outcome.state, outcome.output_kind, outcome.output), ("succeeded", "none", b""))


if __name__ == "__main__":
    unittest.main()
