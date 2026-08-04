"""The deliberately small, strict wire contract for the CSER tool experiment."""

from __future__ import annotations

import base64
import hashlib
import re


MAX_LINE_BYTES = 16 * 1024
MAX_PAYLOAD_BYTES = 8 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")


class ProtocolError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _id(value: str, name: str) -> str:
    if not _ID.fullmatch(value):
        raise ProtocolError(f"invalid {name}")
    return value


def validate_run_id(value: str) -> str:
    if not _RUN_ID.fullmatch(value):
        raise ProtocolError("invalid run id")
    return value


def _digest(value: str) -> str:
    if not _HEX64.fullmatch(value):
        raise ProtocolError("invalid payload digest")
    return value


def record_digest(
    run_id: str,
    operation_key: str,
    payload_digest: str,
    terminal_status: str,
    result: str,
) -> str:
    """Digest the endpoint's *durable* terminal record canonically.

    This deliberately does not hash a JSON response.  The five protocol
    fields are length-delimited under a domain separator, so HTTP formatting,
    replay markers, and field ordering cannot become accidental evidence.
    """
    run_id = validate_run_id(run_id)
    operation_key = _id(operation_key, "operation key")
    payload_digest = _digest(payload_digest)
    terminal_status = _id(terminal_status, "terminal status")
    result = _id(result, "terminal result")
    hasher = hashlib.sha256()
    hasher.update(b"nexus-cser-tool-record-v1")
    for field in (run_id, operation_key, payload_digest, terminal_status, result):
        encoded = field.encode("ascii")
        hasher.update(len(encoded).to_bytes(8, "little"))
        hasher.update(encoded)
    return hasher.hexdigest()


def _decode_payload(value: str) -> bytes:
    if value == "-":
        return b""
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ProtocolError("invalid payload base64") from exc
    if len(decoded) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("payload too large")
    return decoded


def _checksum(tokens: list[str]) -> str:
    return digest(" ".join(tokens).encode("ascii"))


def parse_request(line: bytes) -> tuple[str, str, str, str, bytes]:
    """Parse exactly one UART request frame and validate all self-descriptions."""
    if not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES:
        raise ProtocolError("invalid frame length")
    try:
        fields = line[:-1].decode("ascii").split(" ")
    except UnicodeDecodeError as exc:
        raise ProtocolError("frame is not ASCII") from exc
    if len(fields) != 8 or fields[0:2] != ["CSER1", "REQ"]:
        raise ProtocolError("invalid request frame")
    prefix, supplied_checksum = fields[:-1], fields[-1]
    if not _HEX64.fullmatch(supplied_checksum) or supplied_checksum != _checksum(prefix):
        raise ProtocolError("invalid request checksum")
    method = fields[2]
    if method not in ("POST", "GET"):
        raise ProtocolError("invalid request method")
    run_id = validate_run_id(fields[3])
    operation_key = _id(fields[4], "operation key")
    payload_digest = _digest(fields[5])
    payload = _decode_payload(fields[6])
    if method == "POST" and digest(payload) != payload_digest:
        raise ProtocolError("payload digest mismatch")
    if method == "GET" and payload:
        raise ProtocolError("GET must not carry a payload")
    return method, run_id, operation_key, payload_digest, payload


def response(
    run_id: str,
    operation_key: str,
    status: int,
    payload_digest: str | None,
    terminal_status: str | None,
    result: str | None,
    endpoint_record_digest: str | None,
) -> bytes:
    """Construct one bridge response.

    A success-shaped bridge response must carry the complete terminal record
    and its independently recomputable digest.  Error responses use `-` for
    all endpoint-record fields and are intentionally unusable as evidence.
    """
    if not 100 <= status <= 599:
        raise ProtocolError("invalid HTTP status")
    run_id = validate_run_id(run_id)
    _id(operation_key, "operation key")
    if None in (payload_digest, terminal_status, result, endpoint_record_digest):
        if any(value is not None for value in (payload_digest, terminal_status, result, endpoint_record_digest)):
            raise ProtocolError("incomplete terminal record")
        tokens = ["CSER1", "RESP", run_id, operation_key, str(status), "-", "-", "-", "-"]
    else:
        assert payload_digest is not None
        assert terminal_status is not None
        assert result is not None
        assert endpoint_record_digest is not None
        expected = record_digest(run_id, operation_key, payload_digest, terminal_status, result)
        if endpoint_record_digest != expected:
            raise ProtocolError("record digest mismatch")
        tokens = [
            "CSER1", "RESP", run_id, operation_key, str(status), payload_digest,
            terminal_status, result, endpoint_record_digest,
        ]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")


def request(
    run_id: str,
    operation_key: str,
    payload: bytes,
    method: str = "POST",
    expected_payload_digest: str | None = None,
) -> bytes:
    """Test/kernel helper: construct a canonical request frame."""
    run_id = validate_run_id(run_id)
    _id(operation_key, "operation key")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("payload too large")
    if method not in ("POST", "GET") or (method == "GET" and payload):
        raise ProtocolError("invalid request method")
    payload_hash = digest(payload) if expected_payload_digest is None else _digest(expected_payload_digest)
    if method == "POST" and payload_hash != digest(payload):
        raise ProtocolError("payload digest mismatch")
    encoded = base64.b64encode(payload).decode("ascii") or "-"
    tokens = ["CSER1", "REQ", method, run_id, operation_key, payload_hash, encoded]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")
