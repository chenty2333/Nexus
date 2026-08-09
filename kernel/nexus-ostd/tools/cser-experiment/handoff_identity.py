"""Canonical host-side identities for the bounded CSER3 handoff lane."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from protocol import CHILD_DESCRIPTOR_V1_ROUTE_DIGEST, CHILD_DESCRIPTOR_V1_WIRE_LEN, ProtocolError, digest

_DOMAIN = b"nexus-cser-handoff-child-transport-effect-v1"


def child_transport_effect_id(namespace_id: str, authority_id: str, parent_effect_id: str,
                              run_id: str, catalog_digest: str) -> str:
    """Derive the child transport effect from the complete parent identity.

    The digest preimage is domain-separated and each ASCII field is u64-LE
    length-delimited.  The first 16 digest bytes are the wire identifier; the
    astronomically unlikely all-zero value is canonically remapped to one.
    Rust must use this exact construction.
    """
    hasher = hashlib.sha256(_DOMAIN)
    for encoded in (namespace_id.encode("ascii"), bytes.fromhex(authority_id),
                    bytes.fromhex(parent_effect_id), bytes.fromhex(run_id), bytes.fromhex(catalog_digest)):
        hasher.update(len(encoded).to_bytes(8, "little"))
        hasher.update(encoded)
    value = bytearray(hasher.digest()[:16])
    if not any(value):
        value[-1] = 1
    return bytes(value).hex()


@dataclass(frozen=True)
class ParentDescriptorContext:
    root: int
    sequence: int
    component: int


def validate_child_descriptor_v1(wire: bytes, *, parent: ParentDescriptorContext,
                                 catalog_digest: str, input_digest: str) -> None:
    """Validate the bounded provider descriptor before child observation."""
    if len(wire) != CHILD_DESCRIPTOR_V1_WIRE_LEN or wire[:8] != b"NXSCHD03":
        raise ProtocolError("invalid child descriptor wire")
    take = memoryview(wire)[8:]
    def little(offset: int, size: int) -> int:
        return int.from_bytes(take[offset:offset + size], "little")
    if little(0, 2) != 1 or little(2, 8) != 1:
        raise ProtocolError("unsupported child descriptor schema or sequence")
    if (little(10, 8), little(18, 8), little(26, 4)) != (parent.root, parent.sequence, parent.component):
        raise ProtocolError("child descriptor parent mismatch")
    if bytes(take[30:62]) != CHILD_DESCRIPTOR_V1_ROUTE_DIGEST:
        raise ProtocolError("child descriptor route mismatch")
    # Fixed catalog coordinates: logical outcome child 5/5, one unit at gen 1.
    if (little(62, 4), little(66, 4), little(78, 4), take[82], little(83, 8),
        little(99, 8), little(107, 8)) != (5, 5, 1, 0, 0, 1, 1):
        raise ProtocolError("child descriptor product mismatch")
    if bytes(take[115:147]) != bytes.fromhex(input_digest) or bytes(take[147:179]) != bytes.fromhex(catalog_digest):
        raise ProtocolError("child descriptor input or catalog mismatch")
    if not little(70, 8) or not little(91, 8):
        raise ProtocolError("child descriptor contains zero coordinate")


def _hash_parts(label: bytes, parts: tuple[bytes, ...]) -> bytes:
    hasher = hashlib.sha256(label)
    for part in parts:
        hasher.update(len(part).to_bytes(8, "little"))
        hasher.update(part)
    return hasher.digest()


def expected_child_request(wire: bytes, *, parent: ParentDescriptorContext) -> tuple[str, bytes, str]:
    """Derive the only child POST identity permitted by a parent descriptor."""
    descriptor_digest = hashlib.sha256(wire).digest()
    sequence = int.from_bytes(hashlib.sha256(
        b"CSER3-single-hop-child-effect-v1" + descriptor_digest
    ).digest()[:8], "little") or 1
    if sequence == parent.sequence:
        raise ProtocolError("child sequence aliases parent")
    component = int.from_bytes(wire[74:78], "little")
    claim = int.from_bytes(wire[78:86], "little")
    payload = _hash_parts(b"nexus-cser-tool-handoff-child-payload-v1", (wire,))
    operation = _hash_parts(
        b"nexus-cser-tool-key-v1",
        (parent.root.to_bytes(8, "little"), sequence.to_bytes(8, "little"),
         component.to_bytes(4, "little"), claim.to_bytes(8, "little")),
    ).hex()
    return operation, payload, digest(payload)
