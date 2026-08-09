"""The deliberately small, strict wire contract for the CSER tool experiment."""

from __future__ import annotations

import base64
import hashlib
import re


# Must stay exactly aligned with the guest's bounded `core_tool_uart` codec.
MAX_LINE_BYTES = 1536
MAX_PAYLOAD_BYTES = 576
ENDPOINT_RECORD_SCHEMA_VERSION = 3
ENDPOINT_HTTP_CONTRACT_VERSION = 3
LEGACY_V2_RECORD_SCHEMA_VERSION = 2
LEGACY_V2_HTTP_CONTRACT_VERSION = 2
MAX_TERMINAL_OUTPUT_BYTES = 256
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


def evidence_record_digest(
    namespace_id: str,
    authority_id: str,
    effect_id: str,
    run_id: str,
    operation_key: str,
    input_digest: str,
    catalog_digest: str,
    schema_version: int,
    state: str,
    result: str,
) -> str:
    """Digest a v2 local-evidence record.

    ``record_digest`` above remains only for isolated v1 compatibility tests.
    This digest is the authoritative record identity for the trusted-local v2
    adapter and the strict real-QEMU UART path: it
    binds the durable local authority, namespace/effect identity, input and
    catalog contract as well as the terminal state.  It is deliberately not a
    signature; this adapter is explicitly a trusted-local sidecar.
    """
    namespace_id = _id(namespace_id, "namespace id")
    authority_id = validate_run_id(authority_id)
    effect_id = validate_run_id(effect_id)
    run_id = validate_run_id(run_id)
    operation_key = _id(operation_key, "operation key")
    input_digest = _digest(input_digest)
    catalog_digest = _digest(catalog_digest)
    if schema_version != LEGACY_V2_RECORD_SCHEMA_VERSION:
        raise ProtocolError("unsupported endpoint record schema")
    state = _id(state, "state")
    result = _id(result, "result")
    hasher = hashlib.sha256()
    hasher.update(b"nexus-cser-local-evidence-record-v2")
    for field in (
        namespace_id,
        authority_id,
        effect_id,
        run_id,
        operation_key,
        input_digest,
        catalog_digest,
        str(schema_version),
        state,
        result,
    ):
        encoded = field.encode("ascii")
        hasher.update(len(encoded).to_bytes(8, "little"))
        hasher.update(encoded)
    return hasher.hexdigest()


def evidence_record_digest_v3(
    namespace_id: str, authority_id: str, effect_id: str, run_id: str,
    operation_key: str, input_digest: str, catalog_digest: str, state: str,
    result: str, output_kind: str, output: bytes,
) -> str:
    """Digest the CSER3 terminal record, including its typed bounded output."""
    namespace_id = _id(namespace_id, "namespace id")
    authority_id = validate_run_id(authority_id); effect_id = validate_run_id(effect_id)
    run_id = validate_run_id(run_id); operation_key = _id(operation_key, "operation key")
    input_digest = _digest(input_digest); catalog_digest = _digest(catalog_digest)
    state = _id(state, "state"); result = _id(result, "result")
    output_kind = _id(output_kind, "output kind")
    if output_kind not in ("none", "child_descriptor_v1"):
        raise ProtocolError("unsupported terminal output kind")
    if (state == "failed" and output_kind != "none") or len(output) > MAX_TERMINAL_OUTPUT_BYTES or (output_kind == "none") != (not output):
        raise ProtocolError("invalid terminal output")
    hasher = hashlib.sha256()
    hasher.update(b"nexus-cser-local-evidence-record-v3")
    for field in (namespace_id, authority_id, effect_id, run_id, operation_key, input_digest,
                  catalog_digest, "3", state, result, output_kind, str(len(output)), digest(output)):
        encoded = field.encode("ascii")
        hasher.update(len(encoded).to_bytes(8, "little")); hasher.update(encoded)
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


def parse_request_v2(line: bytes) -> tuple[str, str, str, str, str, str, str, str, bytes]:
    """Parse the strict, identity-bound COM2 request used by real QEMU runs.

    V1 remains only for isolated compatibility tests.  A v2 request makes the
    endpoint authority and catalog part of the checksum-bound request, rather
    than trusting the bridge launch arguments implicitly.
    """
    if not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES:
        raise ProtocolError("invalid frame length")
    try:
        fields = line[:-1].decode("ascii").split(" ")
    except UnicodeDecodeError as exc:
        raise ProtocolError("frame is not ASCII") from exc
    if len(fields) != 12 or fields[:2] != ["CSER2", "REQ"]:
        raise ProtocolError("invalid v2 request frame")
    if not _HEX64.fullmatch(fields[-1]) or fields[-1] != _checksum(fields[:-1]):
        raise ProtocolError("invalid request checksum")
    method = fields[2]
    if method not in ("POST", "GET"):
        raise ProtocolError("invalid request method")
    namespace, authority, effect, run, operation, input_digest, catalog = fields[3:10]
    namespace = _id(namespace, "namespace id")
    authority = validate_run_id(authority)
    effect = validate_run_id(effect)
    run = validate_run_id(run)
    operation = _id(operation, "operation key")
    input_digest = _digest(input_digest)
    catalog = _digest(catalog)
    payload = _decode_payload(fields[10])
    if method == "POST" and digest(payload) != input_digest:
        raise ProtocolError("payload digest mismatch")
    if method == "GET" and payload:
        raise ProtocolError("GET must not carry a payload")
    return method, namespace, authority, effect, run, operation, input_digest, catalog, payload


def response_v2(namespace_id: str, authority_id: str, effect_id: str, run_id: str,
                operation_key: str, input_digest: str, catalog_digest: str,
                status: int, state: str, result: str, evidence_digest: str | None) -> bytes:
    """Construct a strict v2 response; only terminal records carry evidence."""
    if not 100 <= status <= 599:
        raise ProtocolError("invalid HTTP status")
    namespace_id = _id(namespace_id, "namespace id")
    authority_id = validate_run_id(authority_id)
    effect_id = validate_run_id(effect_id)
    run_id = validate_run_id(run_id)
    operation_key = _id(operation_key, "operation key")
    input_digest = _digest(input_digest)
    catalog_digest = _digest(catalog_digest)
    state = _id(state, "state")
    result = _id(result, "result")
    terminal = state in ("succeeded", "failed")
    if terminal:
        if evidence_digest != evidence_record_digest(namespace_id, authority_id, effect_id, run_id,
                                                     operation_key, input_digest, catalog_digest,
                                                     LEGACY_V2_RECORD_SCHEMA_VERSION, state, result):
            raise ProtocolError("evidence digest mismatch")
    elif evidence_digest is not None:
        raise ProtocolError("nonterminal response must not carry evidence")
    tokens = ["CSER2", "RESP", str(status), namespace_id, authority_id, effect_id, run_id,
              operation_key, input_digest, catalog_digest, state, result, evidence_digest or "-"]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")


def request_v2(namespace_id: str, authority_id: str, effect_id: str, run_id: str,
               operation_key: str, payload: bytes, catalog_digest: str,
               method: str = "POST", expected_input_digest: str | None = None) -> bytes:
    """Canonical identity-bound request frame for the production QEMU path."""
    namespace_id = _id(namespace_id, "namespace id")
    authority_id = validate_run_id(authority_id)
    effect_id = validate_run_id(effect_id)
    run_id = validate_run_id(run_id)
    operation_key = _id(operation_key, "operation key")
    catalog_digest = _digest(catalog_digest)
    if len(payload) > MAX_PAYLOAD_BYTES or method not in ("POST", "GET") or (method == "GET" and payload):
        raise ProtocolError("invalid request")
    input_digest = digest(payload) if expected_input_digest is None else _digest(expected_input_digest)
    if method == "POST" and input_digest != digest(payload):
        raise ProtocolError("payload digest mismatch")
    encoded = base64.b64encode(payload).decode("ascii") or "-"
    tokens = ["CSER2", "REQ", method, namespace_id, authority_id, effect_id, run_id,
              operation_key, input_digest, catalog_digest, encoded]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")


def request_v3(namespace_id: str, authority_id: str, effect_id: str, run_id: str,
               operation_key: str, payload: bytes, catalog_digest: str,
               method: str = "POST", expected_input_digest: str | None = None) -> bytes:
    """CSER3 uses the CSER2 request identity but asks for a typed output reply."""
    frame = request_v2(namespace_id, authority_id, effect_id, run_id, operation_key, payload,
                       catalog_digest, method, expected_input_digest)
    return b"CSER3" + frame[len(b"CSER2"):]


def response_v3(namespace_id: str, authority_id: str, effect_id: str, run_id: str,
                operation_key: str, input_digest: str, catalog_digest: str,
                status: int, state: str, result: str, output_kind: str | None,
                output: bytes | None, evidence_digest: str | None) -> bytes:
    """Construct a strict CSER3 reply with an evidence-bound bounded output."""
    if not 100 <= status <= 599:
        raise ProtocolError("invalid HTTP status")
    namespace_id = _id(namespace_id, "namespace id")
    authority_id = validate_run_id(authority_id); effect_id = validate_run_id(effect_id)
    run_id = validate_run_id(run_id); operation_key = _id(operation_key, "operation key")
    input_digest = _digest(input_digest); catalog_digest = _digest(catalog_digest)
    state = _id(state, "state"); result = _id(result, "result")
    terminal = state in ("succeeded", "failed")
    if terminal:
        if output_kind is None or output is None:
            raise ProtocolError("terminal response lacks output fields")
        output_kind = _id(output_kind, "output kind")
        if output_kind not in ("none", "child_descriptor_v1"):
            raise ProtocolError("unsupported terminal output kind")
        if (state == "failed" and output_kind != "none") or len(output) > MAX_TERMINAL_OUTPUT_BYTES or (output_kind == "none") != (not output):
            raise ProtocolError("invalid terminal output")
        expected = evidence_record_digest_v3(namespace_id, authority_id, effect_id, run_id,
                                             operation_key, input_digest, catalog_digest,
                                             state, result, output_kind, output)
        if evidence_digest != expected:
            raise ProtocolError("evidence digest mismatch")
        fields = [output_kind, str(len(output)), digest(output),
                  base64.b64encode(output).decode("ascii") or "-", evidence_digest]
    else:
        if output_kind is not None or output is not None or evidence_digest is not None:
            raise ProtocolError("nonterminal response must not carry output or evidence")
        fields = ["-", "-", "-", "-", "-"]
    tokens = ["CSER3", "RESP", str(status), namespace_id, authority_id, effect_id, run_id,
              operation_key, input_digest, catalog_digest, state, result, *fields]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")


def parse_request_v3(line: bytes) -> tuple[str, str, str, str, str, str, str, str, bytes]:
    """Parse the CSER3 request; its field layout intentionally matches CSER2."""
    if not line.startswith(b"CSER3 "):
        raise ProtocolError("invalid v3 request frame")
    return parse_request_v2(b"CSER2" + line[len(b"CSER3"):])


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
