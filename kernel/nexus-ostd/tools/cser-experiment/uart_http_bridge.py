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

from protocol import MAX_LINE_BYTES, ProtocolError, parse_request, record_digest, response, validate_run_id

MAX_FIRMWARE_PREAMBLE_BYTES = 64 * 1024


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


def _serve_client(
    client: socket.socket,
    endpoint: tuple[str, int],
    expected_run_id: str,
    request_timeout: float = 5.0,
) -> bool:
    client.settimeout(request_timeout)
    try:
        line = _read_request_frame(client)
        method, run_id, operation_key, payload_digest, payload = parse_request(line)
        print(f"tool bridge request method={method} operation={operation_key}", file=sys.stderr, flush=True)
        if run_id != expected_run_id:
            raise ProtocolError("unexpected run id")
        if method == "POST":
            status, record = post(endpoint, run_id, operation_key, payload_digest, payload)
        else:
            status, record = get(endpoint, run_id, operation_key)
        if method == "GET" and status == HTTPStatus.NOT_FOUND:
            # A checksum-bound absence response is not retirement evidence,
            # but it is the one negative fact that permits the recovered guest
            # to retry the *same* durable idempotency key. Preserve the exact
            # request identity so the guest can distinguish it from a bridge
            # or transport failure.
            client.sendall(response(run_id, operation_key, status, None, None, None, None))
            print("tool bridge response status=404 terminal=false", file=sys.stderr, flush=True)
            return True
        _validate_terminal_record(run_id, operation_key, payload_digest, status, record)
        client.sendall(response(
            run_id, operation_key, status, record["payload_digest"], record["status"],
            record["result"], record["record_digest"],
        ))
        print(f"tool bridge response status={status} terminal=true", file=sys.stderr, flush=True)
        return True
    except (OSError, ProtocolError, http.client.HTTPException, json.JSONDecodeError) as exc:
        # A malformed/unavailable request has no success-shaped reply.
        # The guest must retain custody and reconcile rather than infer success.
        try:
            client.sendall(response(expected_run_id, "bridge-error", 503, None, None, None, None))
        except OSError:
            pass
        print(f"tool bridge fail-closed error={type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return False


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
                _serve_client(client, endpoint, expected_run_id)
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
            with client:
                while _serve_client(client, endpoint, expected_run_id, request_timeout):
                    pass
            return
        except FileNotFoundError:
            pass
        except ConnectionRefusedError:
            pass
        finally:
            client.close()
        if time.monotonic() >= deadline:
            raise TimeoutError(f"QEMU COM2 socket did not accept bridge: {socket_path}")
        time.sleep(0.05)


def _read_request_frame(client: socket.socket) -> bytes:
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
        byte = client.recv(1)
        if not byte:
            raise ProtocolError(
                f"truncated UART preamble or request after {consumed} bytes; "
                f"tail={bytes(tail).hex()}"
            )
        consumed += 1
        tail.extend(byte)
        if len(tail) > 128:
            del tail[:-128]
        line.extend(byte)
        if byte != b"\n":
            marker = line.find(b"CSER1 ")
            if marker >= 0 and len(line) - marker > MAX_LINE_BYTES:
                raise ProtocolError("oversized CSER request frame")
            continue
        frame = bytes(line)
        marker = frame.find(b"CSER1 ")
        if marker >= 0:
            frame = frame[marker:]
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
    if http_status not in (HTTPStatus.OK, HTTPStatus.CREATED):
        raise ProtocolError("nonterminal endpoint response")
    if (record["run_id"], record["operation_key"], record["payload_digest"]) != (
        run_id, operation_key, payload_digest,
    ):
        raise ProtocolError("endpoint record identity mismatch")
    if record["status"] != "applied" or record["result"] != "success":
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
    parser.add_argument("--connect-timeout", default=30.0, type=float)
    parser.add_argument("--request-timeout", default=30.0, type=float)
    args = parser.parse_args()
    connect_and_serve(
        args.socket,
        (args.endpoint_host, args.endpoint_port),
        args.run_id,
        args.connect_timeout,
        args.request_timeout,
    )


if __name__ == "__main__":
    main()
