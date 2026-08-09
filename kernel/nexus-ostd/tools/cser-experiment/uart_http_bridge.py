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
from protocol import (MAX_LINE_BYTES, ProtocolError, parse_request, parse_request_v2, record_digest,
                      response, response_v2, evidence_record_digest, validate_run_id)

MAX_FIRMWARE_PREAMBLE_BYTES = 64 * 1024
_V2_ENDPOINT_RECORD_KEYS = frozenset({
    "contract_version", "namespace_id", "authority_id", "effect_id", "run_id",
    "operation_key", "payload_digest", "input_digest", "catalog_digest",
    "record_schema_version", "state", "status", "result", "record_digest",
    "evidence_record_digest", "created_at_ns", "updated_at_ns", "expires_at_ns", "replayed",
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


def _serve_client_v2(client: socket.socket, endpoint: tuple[str, int], identity: tuple[str, str, str, str, str],
                     request_timeout: float = 5.0, uart_pace_seconds: float = 0.0,
                     expected_retry: tuple[str, str] | None = None) -> tuple[str, int, str, str]:
    """Strict real-QEMU bridge: CSER1 is not a tolerated fallback here."""
    client.settimeout(request_timeout)
    try:
        line = _read_request_frame(client, marker=b"CSER2 ")
        method, namespace, authority, effect, run, operation, input_digest, catalog, payload = parse_request_v2(line)
        if (namespace, authority, effect, run, catalog) != identity:
            raise ProtocolError("unexpected v2 experiment identity")
        if expected_retry is not None and (method, operation, input_digest) != (
            "POST", expected_retry[0], expected_retry[1]
        ):
            # Check before forwarding: a different operation must not acquire
            # external side effects merely because it followed a valid 404.
            raise ProtocolError("GET/404 recovery retry changed its durable key")
        if method == "POST":
            status, record = post_v2(endpoint, namespace, authority, effect, run, operation, input_digest, catalog, payload)
        else:
            status, record = get_v2(endpoint, namespace, authority, effect, run, operation, input_digest, catalog)
        if status == HTTPStatus.NOT_FOUND:
            paced_sendall(client, response_v2(namespace, authority, effect, run, operation, input_digest, catalog,
                                               status, "absent", "not_found", None), inter_chunk_seconds=uart_pace_seconds)
            return method, status, operation, input_digest
        if set(record) != _V2_ENDPOINT_RECORD_KEYS:
            raise ProtocolError("unexpected v2 endpoint record shape")
        if record["contract_version"] != "2" or record["record_schema_version"] != "2":
            raise ProtocolError("unexpected v2 endpoint record version")
        if tuple(record[key] for key in ("namespace_id", "authority_id", "effect_id", "run_id", "catalog_digest")) != identity or \
           (record["operation_key"], record["input_digest"]) != (operation, input_digest):
            raise ProtocolError("v2 endpoint record identity mismatch")
        state, result, evidence = record["state"], record["result"], record["evidence_record_digest"]
        if state in ("succeeded", "failed"):
            expected = evidence_record_digest(namespace, authority, effect, run, operation, input_digest,
                                              catalog, 2, state, result)
            if evidence != expected:
                raise ProtocolError("v2 endpoint evidence digest mismatch")
        elif state not in ("accepted", "pending", "expired") or evidence != "-":
            raise ProtocolError("invalid nonterminal v2 record")
        # 410 is deliberately rendered as expired/non-evidence: the guest may
        # retain and reconcile, but must never infer retry authority from it.
        paced_sendall(client, response_v2(namespace, authority, effect, run, operation, input_digest, catalog,
                                           status, state, result, evidence if evidence != "-" else None), inter_chunk_seconds=uart_pace_seconds)
        return method, status, operation, input_digest
    except (OSError, http.client.HTTPException, json.JSONDecodeError, ProtocolError) as exc:
        raise BridgeStageError("frame-complete" if isinstance(exc, ProtocolError) else "endpoint-connect", exc) from exc


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
                # A boot normally has one bounded tool operation. Recovery has
                # one deliberately narrow exception: an exact-key GET/404 is
                # the authority to retry that same durable operation once.
                # Serve precisely that POST and never turn COM2 into an
                # unbounded request loop.
                try:
                    if identity is None:
                        _serve_client(client, endpoint, expected_run_id, request_timeout)
                    else:
                        first_method, first_status, first_operation, first_input = _serve_client_v2(
                            client, endpoint, identity, request_timeout, uart_pace_seconds
                        )
                        if (first_method, first_status) == ("GET", HTTPStatus.NOT_FOUND):
                            _serve_client_v2(
                                client,
                                endpoint,
                                identity,
                                request_timeout,
                                uart_pace_seconds,
                                (first_operation, first_input),
                            )
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
        if args.cser2:
            if None in (args.namespace_id, args.authority_id, args.effect_id, args.catalog_digest):
                raise ValueError("CSER2 bridge requires namespace, authority, effect, and catalog")
            validate_run_id(args.authority_id); validate_run_id(args.effect_id)
            identity = (args.namespace_id, args.authority_id, args.effect_id, args.run_id, args.catalog_digest)
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
        )
    except (BridgeStageError, OSError, ProtocolError, TimeoutError, ValueError) as exc:
        stage = exc.stage if isinstance(exc, BridgeStageError) else "bridge-ready"
        _write_signal(args.status_file, "failed", stage=stage, detail=str(exc))
        print(f"tool bridge failed stage={stage}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
