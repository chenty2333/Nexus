#!/usr/bin/env python3
"""Fail-closed Unix-socket UART to CSER tool endpoint bridge."""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import socket
import sys
import time
from http import HTTPStatus
from pathlib import Path

from matrix_protocol import UART_WRITE_INTER_CHUNK_SECONDS, paced_sendall
from protocol import (MAX_LINE_BYTES, ProtocolError, digest, parse_request, parse_request_v2, parse_request_v3, record_digest,
                      response, response_v2, response_v3, evidence_record_digest, evidence_record_digest_v3, validate_run_id)
from handoff_identity import (ParentDescriptorContext, child_transport_effect_id,
                              expected_child_request, validate_child_descriptor_v1)

MAX_FIRMWARE_PREAMBLE_BYTES = 64 * 1024
# Development-tunable bound for one boot's same-identity reconciliation.  It
# is deliberately a protocol backpressure bound, not a claim about endpoint
# completion latency.  The guest retains on exhaustion and reconnects on a
# later boot.
MAX_V2_EXCHANGES = 8
_V2_ENDPOINT_RECORD_KEYS = frozenset({
    "contract_version", "namespace_id", "authority_id", "effect_id", "run_id",
    "operation_key", "payload_digest", "input_digest", "catalog_digest",
    "record_schema_version", "state", "status", "result", "record_digest",
    "evidence_record_digest", "created_at_ns", "updated_at_ns", "expires_at_ns", "replayed",
})
_V3_TERMINAL_OUTPUT_KEYS = frozenset({"output_kind", "output_len", "output_digest", "output_b64", "cser3_evidence_digest"})
_V3_ENDPOINT_RECORD_KEYS = frozenset({
    "contract_version", "namespace_id", "authority_id", "effect_id", "run_id", "operation_key",
    "input_digest", "catalog_digest", "record_schema_version", "state", "result", "output_kind",
    "output_len", "output_digest", "output_b64", "evidence_record_digest", "created_at_ns",
    "updated_at_ns", "expires_at_ns", "replayed",
})


def _write_signal(path: Path | None, state: str, *, stage: str | None = None,
                  detail: str | None = None) -> None:
    """Publish a tiny atomic, trusted-local supervisor signal.

    The experiment parent uses this only to distinguish a bridge that never
    initialized from one which connected to QEMU and serviced its one request.
    It is deliberately *not* endpoint evidence and is never read by Nexus.
    """
    if path is None:
        return
    document: dict[str, str] = {"state": state}
    if stage is not None:
        document["stage"] = stage
    if detail is not None:
        document["detail"] = detail[:512]
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


class BridgeStageError(RuntimeError):
    def __init__(self, stage: str, cause: BaseException) -> None:
        self.stage = stage
        self.cause = cause
        super().__init__(f"{stage}: {type(cause).__name__}: {cause}")


class FrameReadError(ProtocolError):
    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(message)


class NoRequestBeforeClose(FrameReadError):
    """QEMU closed COM2 after firmware output without issuing a request."""


def post(endpoint: tuple[str, int], run_id: str, operation_key: str, payload_digest: str, payload: bytes) -> tuple[int, dict[str, str]]:
    body = json.dumps(
        {
            "run_id": run_id,
            "operation_key": operation_key,
            "payload_digest": payload_digest,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    connection = http.client.HTTPConnection(*endpoint, timeout=5)
    try:
        connection.request("POST", "/v1/operations", body, {"Content-Type": "application/json"})
        result = connection.getresponse()
        document = json.loads(result.read().decode("utf-8"))
        if not isinstance(document, dict) or not all(isinstance(value, str) for value in document.values()):
            raise ProtocolError("invalid endpoint response")
        return result.status, document
    finally:
        connection.close()


def get(endpoint: tuple[str, int], run_id: str, operation_key: str) -> tuple[int, dict[str, str]]:
    connection = http.client.HTTPConnection(*endpoint, timeout=5)
    try:
        connection.request("GET", f"/v1/operations/{run_id}/{operation_key}")
        result = connection.getresponse()
        document = json.loads(result.read().decode("utf-8"))
        if not isinstance(document, dict) or not all(isinstance(value, str) for value in document.values()):
            raise ProtocolError("invalid endpoint response")
        return result.status, document
    finally:
        connection.close()


def post_v2(endpoint: tuple[str, int], namespace: str, authority: str, effect: str, run: str,
            operation: str, input_digest: str, catalog: str, payload: bytes) -> tuple[int, dict[str, str]]:
    body = json.dumps({"contract_version": "2", "namespace_id": namespace, "authority_id": authority,
                       "effect_id": effect, "run_id": run, "operation_key": operation,
                       "input_digest": input_digest, "catalog_digest": catalog,
                       "payload_b64": base64.b64encode(payload).decode("ascii")},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    connection = http.client.HTTPConnection(*endpoint, timeout=5)
    try:
        connection.request("POST", "/v2/operations", body, {"Content-Type": "application/json"})
        result = connection.getresponse()
        document = json.loads(result.read().decode("utf-8"))
        if not isinstance(document, dict) or not all(isinstance(value, str) for value in document.values()):
            raise ProtocolError("invalid endpoint response")
        return result.status, document
    finally:
        connection.close()


def get_v2(endpoint: tuple[str, int], namespace: str, authority: str, effect: str, run: str,
           operation: str, input_digest: str, catalog: str) -> tuple[int, dict[str, str]]:
    connection = http.client.HTTPConnection(*endpoint, timeout=5)
    try:
        connection.request("GET", f"/v2/operations/{namespace}/{authority}/{effect}/{run}/{operation}/{input_digest}/{catalog}")
        result = connection.getresponse()
        document = json.loads(result.read().decode("utf-8"))
        if not isinstance(document, dict) or not all(isinstance(value, str) for value in document.values()):
            raise ProtocolError("invalid endpoint response")
        return result.status, document
    finally:
        connection.close()


def post_v3(endpoint: tuple[str, int], namespace: str, authority: str, effect: str, run: str,
            operation: str, input_digest: str, catalog: str, payload: bytes) -> tuple[int, dict[str, str]]:
    body = json.dumps({"contract_version": "3", "namespace_id": namespace, "authority_id": authority,
                       "effect_id": effect, "run_id": run, "operation_key": operation,
                       "input_digest": input_digest, "catalog_digest": catalog,
                       "payload_b64": base64.b64encode(payload).decode("ascii")}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    connection = http.client.HTTPConnection(*endpoint, timeout=5)
    try:
        connection.request("POST", "/v3/operations", body, {"Content-Type": "application/json"})
        result = connection.getresponse(); document = json.loads(result.read().decode("utf-8"))
        if not isinstance(document, dict) or not all(isinstance(value, str) for value in document.values()): raise ProtocolError("invalid endpoint response")
        return result.status, document
    finally: connection.close()


def get_v3(endpoint: tuple[str, int], namespace: str, authority: str, effect: str, run: str,
           operation: str, input_digest: str, catalog: str) -> tuple[int, dict[str, str]]:
    connection = http.client.HTTPConnection(*endpoint, timeout=5)
    try:
        connection.request("GET", f"/v3/operations/{namespace}/{authority}/{effect}/{run}/{operation}/{input_digest}/{catalog}")
        result = connection.getresponse(); document = json.loads(result.read().decode("utf-8"))
        if not isinstance(document, dict) or not all(isinstance(value, str) for value in document.values()): raise ProtocolError("invalid endpoint response")
        return result.status, document
    finally: connection.close()


def _serve_client_v2(client: socket.socket, endpoint: tuple[str, int], identity: tuple[str, str, str, str, str],
                     request_timeout: float = 5.0, uart_pace_seconds: float = 0.0,
                     expected_retry: tuple[str, str] | None = None,
                     expected_operation: tuple[str, str] | None = None,
                     cser3: bool = False) -> tuple[str, int, str, str]:
    """Strict real-QEMU bridge: CSER1 is not a tolerated fallback here."""
    client.settimeout(request_timeout)
    try:
        line = _read_request_frame(client, marker=b"CSER3 " if cser3 else b"CSER2 ")
        parser = parse_request_v3 if cser3 else parse_request_v2
        method, namespace, authority, effect, run, operation, input_digest, catalog, payload = parser(line)
        if (namespace, authority, effect, run, catalog) != identity:
            raise ProtocolError("unexpected v2 experiment identity")
        if expected_operation is not None and (operation, input_digest) != expected_operation:
            raise ProtocolError("same-identity reconciliation changed its durable key")
        if expected_retry is not None and (method, operation, input_digest) != (
            "POST", expected_retry[0], expected_retry[1]
        ):
            # Check before forwarding: a different operation must not acquire
            # external side effects merely because it followed a valid 404.
            raise ProtocolError("GET/404 recovery retry changed its durable key")
        if method == "POST":
            status, record = (post_v3 if cser3 else post_v2)(endpoint, namespace, authority, effect, run, operation, input_digest, catalog, payload)
        else:
            status, record = (get_v3 if cser3 else get_v2)(endpoint, namespace, authority, effect, run, operation, input_digest, catalog)
        if status == HTTPStatus.NOT_FOUND:
            renderer = response_v3 if cser3 else response_v2
            reply = (renderer(namespace, authority, effect, run, operation, input_digest, catalog, status, "absent", "not_found", None, None, None)
                     if cser3 else renderer(namespace, authority, effect, run, operation, input_digest, catalog, status, "absent", "not_found", None))
            paced_sendall(client, reply, inter_chunk_seconds=uart_pace_seconds)
            return method, status, operation, input_digest
        if (not cser3 and set(record) != _V2_ENDPOINT_RECORD_KEYS) or (cser3 and set(record) != _V3_ENDPOINT_RECORD_KEYS):
            raise ProtocolError("unexpected endpoint record shape")
        if record["contract_version"] != ("3" if cser3 else "2") or record["record_schema_version"] != ("3" if cser3 else "2"):
            raise ProtocolError("unexpected endpoint record version")
        if tuple(record[key] for key in ("namespace_id", "authority_id", "effect_id", "run_id", "catalog_digest")) != identity or \
           (record["operation_key"], record["input_digest"]) != (operation, input_digest):
            raise ProtocolError("v2 endpoint record identity mismatch")
        state, result, evidence = record["state"], record["result"], record["evidence_record_digest"]
        if not cser3 and state in ("succeeded", "failed"):
            expected = evidence_record_digest(namespace, authority, effect, run, operation, input_digest,
                                              catalog, 2, state, result)
            if evidence != expected:
                raise ProtocolError("v2 endpoint evidence digest mismatch")
        elif not cser3 and (state not in ("accepted", "pending", "expired") or evidence != "-"):
            raise ProtocolError("invalid nonterminal v2 record")
        # 410 is deliberately rendered as expired/non-evidence: the guest may
        # retain and reconcile, but must never infer retry authority from it.
        if cser3:
            output = None if state not in ("succeeded", "failed") else (b"" if record["output_b64"] == "-" else base64.b64decode(record["output_b64"].encode("ascii"), validate=True))
            output_kind = None if output is None else record["output_kind"]
            evidence = None if output is None else record["evidence_record_digest"]
            if state not in ("succeeded", "failed") and any(record[key] != "-" for key in ("output_kind", "output_len", "output_digest", "output_b64", "evidence_record_digest")):
                raise ProtocolError("nonterminal v3 record carries output or evidence")
            if output is not None and (record["output_len"] != str(len(output)) or record["output_digest"] != digest(output)):
                raise ProtocolError("v3 terminal output metadata mismatch")
            if output is not None and evidence != evidence_record_digest_v3(namespace, authority, effect, run, operation,
                                                                             input_digest, catalog, state, result,
                                                                             output_kind, output):
                raise ProtocolError("v3 endpoint evidence digest mismatch")
            paced_sendall(client, response_v3(namespace, authority, effect, run, operation, input_digest, catalog,
                                               status, state, result, output_kind, output, evidence), inter_chunk_seconds=uart_pace_seconds)
        else:
            paced_sendall(client, response_v2(namespace, authority, effect, run, operation, input_digest, catalog,
                                               status, state, result, evidence if evidence != "-" else None), inter_chunk_seconds=uart_pace_seconds)
        return method, status, operation, input_digest
    except (OSError, http.client.HTTPException, json.JSONDecodeError, ProtocolError) as exc:
        raise BridgeStageError("frame-complete" if isinstance(exc, ProtocolError) else "endpoint-connect", exc) from exc


def serve_handoff_session(client: socket.socket, *, parent_endpoint: tuple[str, int], child_endpoint: tuple[str, int],
                          parent_identity: tuple[str, str, str, str, str],
                          parent_descriptor: ParentDescriptorContext,
                          request_timeout: float = 5.0, uart_pace_seconds: float = 0.0) -> None:
    """Serve the strict two-identity CSER3 handoff conversation on one COM2.

    Only the parent may produce the single descriptor.  A child cannot be
    forwarded until that terminal descriptor has passed independent wire and
    transport-identity validation.  Per-identity POST/retry state prevents a
    parent 404 or operation key from authorizing a child side effect.
    """
    namespace, authority, parent_effect, run, catalog = parent_identity
    child_identity = (namespace, authority,
                      child_transport_effect_id(namespace, authority, parent_effect, run, catalog), run, catalog)
    states: dict[tuple[str, str, str, str, str], dict[str, object]] = {
        parent_identity: {"operation": None, "retry": None, "posts": 0},
        child_identity: {"operation": None, "retry": None, "posts": 0},
    }
    child_authorized = False
    expected_child: tuple[str, bytes, str] | None = None
    client.settimeout(request_timeout)
    for _ in range(MAX_V2_EXCHANGES * 2):
        line = _read_request_frame(client, marker=b"CSER3 ")
        method, namespace, authority, effect, run, operation, input_digest, catalog, payload = parse_request_v3(line)
        identity = (namespace, authority, effect, run, catalog)
        if identity not in states:
            raise BridgeStageError("frame-complete", ProtocolError("handoff request names a non-allowlisted effect"))
        is_child = identity == child_identity
        if is_child and not child_authorized:
            raise BridgeStageError("frame-complete", ProtocolError("child observed before validated parent descriptor"))
        if is_child and expected_child is not None:
            expected_operation, expected_payload, expected_input = expected_child
            if (operation, input_digest) != (expected_operation, expected_input) or \
               (method == "POST" and payload != expected_payload) or (method == "GET" and payload):
                raise BridgeStageError("frame-complete", ProtocolError("child request does not match parent descriptor"))
        state = states[identity]
        seen = (operation, input_digest)
        if state["operation"] is not None and state["operation"] != seen:
            raise BridgeStageError("frame-complete", ProtocolError("identity changed durable operation key"))
        if state["retry"] is not None and (method != "POST" or state["retry"] != seen):
            raise BridgeStageError("frame-complete", ProtocolError("GET/404 retry changed durable key"))
        endpoint = child_endpoint if is_child else parent_endpoint
        if method == "POST":
            if state["retry"] != seen:
                raise BridgeStageError(
                    "frame-complete",
                    ProtocolError("POST lacks exact GET/404 retry authority"),
                )
            if state["posts"]:
                raise BridgeStageError("frame-complete", ProtocolError("identity issued a second POST"))
            status, record = post_v3(endpoint, namespace, authority, effect, run, operation, input_digest, catalog, payload)
            state["posts"] = 1
        else:
            status, record = get_v3(endpoint, namespace, authority, effect, run, operation, input_digest, catalog)
        state["operation"] = seen
        if status == HTTPStatus.NOT_FOUND:
            if method != "GET":
                raise BridgeStageError("frame-complete", ProtocolError("only GET/404 authorizes same-key retry"))
            paced_sendall(client, response_v3(namespace, authority, effect, run, operation, input_digest, catalog,
                                               status, "absent", "not_found", None, None, None), inter_chunk_seconds=uart_pace_seconds)
            state["retry"] = seen
            continue
        if set(record) != _V3_ENDPOINT_RECORD_KEYS or record["contract_version"] != "3" or record["record_schema_version"] != "3":
            raise BridgeStageError("frame-complete", ProtocolError("handoff endpoint downgraded CSER3 record"))
        if tuple(record[key] for key in ("namespace_id", "authority_id", "effect_id", "run_id", "catalog_digest")) != identity or (record["operation_key"], record["input_digest"]) != seen:
            raise BridgeStageError("frame-complete", ProtocolError("handoff endpoint identity mismatch"))
        terminal = record["state"] in ("succeeded", "failed")
        output = b"" if record["output_b64"] == "-" else base64.b64decode(record["output_b64"], validate=True)
        kind = record["output_kind"]
        if not terminal and any(record[key] != "-" for key in ("output_kind", "output_len", "output_digest", "output_b64", "evidence_record_digest")):
            raise BridgeStageError("frame-complete", ProtocolError("nonterminal handoff output"))
        if terminal and (record["output_len"] != str(len(output)) or record["output_digest"] != digest(output) or record["evidence_record_digest"] != evidence_record_digest_v3(namespace, authority, effect, run, operation, input_digest, catalog, record["state"], record["result"], kind, output)):
            raise BridgeStageError("frame-complete", ProtocolError("handoff terminal evidence mismatch"))
        if is_child and terminal and kind != "none":
            raise BridgeStageError("frame-complete", ProtocolError("child returned non-none output"))
        if not is_child and terminal:
            if kind != "child_descriptor_v1":
                raise BridgeStageError("frame-complete", ProtocolError("parent terminal missing child descriptor"))
            validate_child_descriptor_v1(output, parent=parent_descriptor, catalog_digest=catalog, input_digest=input_digest)
            expected_child = expected_child_request(output, parent=parent_descriptor)
            child_authorized = True
        paced_sendall(client, response_v3(namespace, authority, effect, run, operation, input_digest, catalog,
                                           status, record["state"], record["result"], kind if terminal else None,
                                           output if terminal else None, record["evidence_record_digest"] if terminal else None), inter_chunk_seconds=uart_pace_seconds)
        state["retry"] = None
        if is_child and terminal:
            return
    raise BridgeStageError("frame-complete", ProtocolError("handoff exchange limit exhausted"))


def connect_and_serve_handoff(socket_path: Path, *, parent_endpoint: tuple[str, int], child_endpoint: tuple[str, int],
                              parent_identity: tuple[str, str, str, str, str], parent_descriptor: ParentDescriptorContext,
                              timeout: float = 30.0, request_timeout: float = 30.0,
                              uart_pace_seconds: float = 0.0, status_file: Path | None = None) -> None:
    """Connect to QEMU-owned COM2 and run one bounded dual-endpoint session."""
    deadline = time.monotonic() + timeout
    while True:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(socket_path))
            _write_signal(status_file, "connected")
            with client:
                serve_handoff_session(client, parent_endpoint=parent_endpoint, child_endpoint=child_endpoint,
                                      parent_identity=parent_identity, parent_descriptor=parent_descriptor,
                                      request_timeout=request_timeout, uart_pace_seconds=uart_pace_seconds)
            _write_signal(status_file, "served")
            return
        except (FileNotFoundError, ConnectionRefusedError):
            pass
        except BridgeStageError as exc:
            _write_signal(status_file, "failed", stage=exc.stage, detail=str(exc))
            raise
        finally:
            client.close()
        if time.monotonic() >= deadline:
            error = TimeoutError(f"QEMU COM2 socket did not accept bridge: {socket_path}")
            _write_signal(status_file, "failed", stage="bridge-ready", detail=str(error))
            raise error
        time.sleep(0.05)


def _serve_client(
    client: socket.socket,
    endpoint: tuple[str, int],
    expected_run_id: str,
    request_timeout: float = 5.0,
    failure: list[BridgeStageError] | None = None,
) -> bool:
    client.settimeout(request_timeout)
    try:
        try:
            line = _read_request_frame(client)
            method, run_id, operation_key, payload_digest, payload = parse_request(line)
        except FrameReadError as exc:
            raise BridgeStageError(exc.stage, exc) from exc
        except (OSError, ProtocolError) as exc:
            raise BridgeStageError("frame-complete", exc) from exc
        print(f"tool bridge request method={method} operation={operation_key}", file=sys.stderr, flush=True)
        if run_id != expected_run_id:
            raise BridgeStageError("frame-complete", ProtocolError("unexpected run id"))
        try:
            if method == "POST":
                status, record = post(endpoint, run_id, operation_key, payload_digest, payload)
            else:
                status, record = get(endpoint, run_id, operation_key)
        except (OSError, http.client.HTTPException, json.JSONDecodeError, ProtocolError) as exc:
            raise BridgeStageError("endpoint-connect", exc) from exc
        if method == "GET" and status == HTTPStatus.NOT_FOUND:
            # A checksum-bound absence response is not retirement evidence,
            # but it is the one negative fact that permits the recovered guest
            # to retry the *same* durable idempotency key. Preserve the exact
            # request identity so the guest can distinguish it from a bridge
            # or transport failure.
            try:
                paced_sendall(client, response(run_id, operation_key, status, None, None, None, None))
            except OSError as exc:
                raise BridgeStageError("frame-complete", exc) from exc
            print("tool bridge response status=404 terminal=false", file=sys.stderr, flush=True)
            return True
        try:
            _validate_terminal_record(run_id, operation_key, payload_digest, status, record)
            paced_sendall(client, response(
                run_id, operation_key, status, record["payload_digest"], record["status"],
                record["result"], record["record_digest"],
            ))
        except (OSError, ProtocolError, KeyError) as exc:
            raise BridgeStageError("frame-complete", exc) from exc
        print(f"tool bridge response status={status} terminal=true", file=sys.stderr, flush=True)
        return True
    except BridgeStageError as exc:
        # A malformed/unavailable request has no success-shaped reply.
        # The guest must retain custody and reconcile rather than infer success.
        try:
            paced_sendall(client, response(expected_run_id, "bridge-error", 503, None, None, None, None))
        except OSError:
            pass
        print(f"tool bridge fail-closed stage={exc.stage} error={exc.cause!r}", file=sys.stderr, flush=True)
        if failure is not None:
            failure.append(exc)
            return False
        raise


def serve(socket_path: Path, endpoint: tuple[str, int], expected_run_id: str) -> None:
    """Legacy listener used only by the isolated protocol unit test.

    Real QEMU profiles own the Unix socket (`server=on`); use
    :func:`connect_and_serve` for them so there is never a double server.
    """
    validate_run_id(expected_run_id)
    if socket_path.exists() or socket_path.is_symlink():
        raise RuntimeError(f"refusing to replace existing socket path: {socket_path}")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(8)
        while True:
            client, _ = listener.accept()
            with client:
                # The legacy listener is intentionally long-lived for
                # protocol tests. A bad local client gets a fail-closed 503
                # but cannot take down the listener or leak a traceback.
                try:
                    _serve_client(client, endpoint, expected_run_id)
                except BridgeStageError:
                    continue
    finally:
        listener.close()
        if socket_path.exists():
            socket_path.unlink()


def connect_and_serve(
    socket_path: Path,
    endpoint: tuple[str, int],
    expected_run_id: str,
    timeout: float = 30.0,
    request_timeout: float = 30.0,
    status_file: Path | None = None,
    identity: tuple[str, str, str, str, str] | None = None,
    uart_pace_seconds: float = 0.0,
    allow_no_request: bool = False,
    cser3: bool = False,
) -> None:
    """Connect to QEMU's COM2 socket and serve one bounded guest request.

    QEMU owns creation of the pathname. Retrying connection races safely with
    QEMU startup without ever replacing a socket supplied by another process.
    """
    validate_run_id(expected_run_id)
    deadline = time.monotonic() + timeout
    while True:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(socket_path))
            print(f"tool bridge connected socket={socket_path}", file=sys.stderr, flush=True)
            _write_signal(status_file, "connected")
            with client:
                # A boot has a bounded same-identity reconciliation sequence:
                # one POST at most, followed only by GET polls of that exact
                # operation.  A GET/404 is the sole authority for that one
                # POST.  Accepted/Pending are ordinary nonterminal progress,
                # so retain the socket long enough for guest polling without
                # turning COM2 into an unbounded request loop.
                try:
                    if identity is None:
                        _serve_client(client, endpoint, expected_run_id, request_timeout)
                    else:
                        operation: tuple[str, str] | None = None
                        retry: tuple[str, str] | None = None
                        posts = 0
                        for _ in range(MAX_V2_EXCHANGES):
                            try:
                                method, status, seen_operation, seen_input = _serve_client_v2(
                                    client,
                                    endpoint,
                                    identity,
                                    request_timeout,
                                    uart_pace_seconds,
                                    retry,
                                    operation,
                                    cser3,
                                )
                            except BridgeStageError as error:
                                # After a valid Accepted/Pending reply the
                                # guest may exhaust its own smaller poll budget
                                # and power off.  That is a retained/deferred
                                # run, not an endpoint or wire failure.
                                if operation is not None and isinstance(error.cause, NoRequestBeforeClose):
                                    _write_signal(status_file, "deferred")
                                    return
                                raise
                            operation = (seen_operation, seen_input)
                            if method == "POST":
                                posts += 1
                                if posts > 1:
                                    raise ProtocolError("bounded reconciliation issued a second POST")
                            retry = operation if (method, status) == ("GET", HTTPStatus.NOT_FOUND) else None
                            # A 404 GET is the one deliberate continuation:
                            # its next frame must be the exact same POST.
                            if status != HTTPStatus.ACCEPTED and retry is None:
                                return _write_signal(status_file, "served")
                except BridgeStageError as error:
                    if allow_no_request and isinstance(error.cause, NoRequestBeforeClose):
                        _write_signal(status_file, "unused")
                        return
                    _write_signal(status_file, "failed", stage=error.stage, detail=str(error))
                    raise
            _write_signal(status_file, "served")
            return
        except FileNotFoundError:
            pass
        except ConnectionRefusedError:
            pass
        except BridgeStageError as exc:
            _write_signal(status_file, "failed", stage=exc.stage, detail=str(exc))
            raise
        finally:
            client.close()
        if time.monotonic() >= deadline:
            error = TimeoutError(f"QEMU COM2 socket did not accept bridge: {socket_path}")
            _write_signal(status_file, "failed", stage="bridge-ready", detail=str(error))
            raise error
        time.sleep(0.05)


def _read_request_frame(client: socket.socket, marker: bytes = b"CSER1 ") -> bytes:
    """Skip bounded firmware console preamble, then return one CSER frame.

    OVMF writes its boot console to every configured ISA UART before Nexus
    takes ownership of COM2. Those lines are transport noise, not endpoint
    input. Once the protocol marker appears it and the remaining line are
    returned without normalization so the ordinary parser remains the sole authority over
    framing, identity, and checksum.
    """
    line = bytearray()
    tail = bytearray()
    consumed = 0
    while consumed < MAX_FIRMWARE_PREAMBLE_BYTES:
        try:
            byte = client.recv(1)
        except socket.timeout as exc:
            stage = "first-byte" if consumed == 0 else "frame-complete"
            raise FrameReadError(stage, f"UART {stage} timeout after {consumed} bytes") from exc
        if not byte:
            stage = "first-byte" if consumed == 0 else "frame-complete"
            error_type = NoRequestBeforeClose if line.find(marker) < 0 else FrameReadError
            raise error_type(
                stage,
                f"truncated UART preamble or request after {consumed} bytes; "
                f"tail={bytes(tail).hex()}",
            )
        consumed += 1
        tail.extend(byte)
        if len(tail) > 128:
            del tail[:-128]
        line.extend(byte)
        if byte != b"\n":
            marker_at = line.find(marker)
            if marker_at >= 0 and len(line) - marker_at > MAX_LINE_BYTES:
                raise ProtocolError("oversized CSER request frame")
            continue
        frame = bytes(line)
        marker_at = frame.find(marker)
        if marker_at >= 0:
            frame = frame[marker_at:]
            if len(frame) > MAX_LINE_BYTES:
                raise ProtocolError("oversized CSER request frame")
            return frame
        line.clear()
    raise ProtocolError("firmware preamble exceeded bound")


def _validate_terminal_record(
    run_id: str,
    operation_key: str,
    payload_digest: str,
    http_status: int,
    record: dict[str, str],
) -> None:
    """Reject any HTTP response that is not the exact durable operation record."""
    required = {"run_id", "operation_key", "payload_digest", "status", "result", "record_digest"}
    if not required.issubset(record):
        raise ProtocolError("incomplete endpoint record")
    if http_status not in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.CONFLICT):
        raise ProtocolError("nonterminal endpoint response")
    if (record["run_id"], record["operation_key"], record["payload_digest"]) != (
        run_id, operation_key, payload_digest,
    ):
        raise ProtocolError("endpoint record identity mismatch")
    terminal = (record["status"], record["result"])
    if terminal != ("applied", "success") and not (
        terminal[0] == "failed" and terminal[1] and terminal[1].replace("-", "").replace("_", "").isalnum()
    ):
        raise ProtocolError("unexpected endpoint terminal state")
    if record["record_digest"] != record_digest(
        run_id, operation_key, payload_digest, record["status"], record["result"],
    ):
        raise ProtocolError("endpoint record digest mismatch")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--endpoint-host", default="127.0.0.1")
    parser.add_argument("--endpoint-port", required=True, type=int)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--namespace-id")
    parser.add_argument("--authority-id")
    parser.add_argument("--effect-id")
    parser.add_argument("--catalog-digest")
    parser.add_argument("--cser2", action="store_true")
    parser.add_argument("--cser3", action="store_true")
    parser.add_argument("--handoff-cser3", action="store_true")
    parser.add_argument("--child-endpoint-port", type=int)
    parser.add_argument("--handoff-parent-root", type=lambda value: int(value, 0))
    parser.add_argument("--handoff-parent-sequence", type=lambda value: int(value, 0))
    parser.add_argument("--handoff-parent-component", type=lambda value: int(value, 0))
    parser.add_argument("--uart-pace-seconds", type=float, default=UART_WRITE_INTER_CHUNK_SECONDS)
    parser.add_argument("--allow-no-request", action="store_true")
    parser.add_argument("--connect-timeout", default=30.0, type=float)
    parser.add_argument("--request-timeout", default=30.0, type=float)
    parser.add_argument("--startup-ready-file", type=Path)
    parser.add_argument("--status-file", type=Path)
    args = parser.parse_args()
    try:
        validate_run_id(args.run_id)
        _write_signal(args.startup_ready_file, "ready")
        _write_signal(args.status_file, "starting")
        identity = None
        if args.cser2 or args.cser3 or args.handoff_cser3:
            if None in (args.namespace_id, args.authority_id, args.effect_id, args.catalog_digest):
                raise ValueError("CSER2/CSER3 bridge requires namespace, authority, effect, and catalog")
            validate_run_id(args.authority_id); validate_run_id(args.effect_id)
            identity = (args.namespace_id, args.authority_id, args.effect_id, args.run_id, args.catalog_digest)
        if args.handoff_cser3:
            if args.cser2 or args.cser3 or args.allow_no_request or args.child_endpoint_port is None or identity is None or \
               None in (args.handoff_parent_root, args.handoff_parent_sequence, args.handoff_parent_component):
                raise ValueError("handoff CSER3 requires only exact parent identity, child endpoint, and parent coordinate")
            if args.handoff_parent_root <= 0 or args.handoff_parent_sequence < 0 or args.handoff_parent_component <= 0:
                raise ValueError("handoff parent coordinate is out of range")
            connect_and_serve_handoff(
                args.socket, parent_endpoint=(args.endpoint_host, args.endpoint_port),
                child_endpoint=(args.endpoint_host, args.child_endpoint_port), parent_identity=identity,
                parent_descriptor=ParentDescriptorContext(args.handoff_parent_root, args.handoff_parent_sequence,
                                                          args.handoff_parent_component), timeout=args.connect_timeout,
                request_timeout=args.request_timeout, uart_pace_seconds=args.uart_pace_seconds,
                status_file=args.status_file,
            )
        else:
            connect_and_serve(
                args.socket,
                (args.endpoint_host, args.endpoint_port),
                args.run_id,
                args.connect_timeout,
                args.request_timeout,
                args.status_file,
                identity,
                args.uart_pace_seconds,
                args.allow_no_request,
                args.cser3,
            )
    except (BridgeStageError, OSError, ProtocolError, TimeoutError, ValueError) as exc:
        stage = exc.stage if isinstance(exc, BridgeStageError) else "bridge-ready"
        _write_signal(args.status_file, "failed", stage=stage, detail=str(exc))
        print(f"tool bridge failed stage={stage}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
