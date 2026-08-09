"""Strict host/guest barrier framing for crash-matrix trials.

This protocol is intentionally separate from the tool-request UART protocol.
The host must only kill a guest after the checksum-protected frame names the
exact run and cutpoint, rather than after an inferred delay in the guest log.
The checksum detects framing corruption; it is not sender authentication.
"""

from __future__ import annotations

import hashlib
import re
import time


MAX_LINE_BYTES = 1024
# QEMU's Unix chardev can accept a whole host frame while the emulated 16550
# has not yet made the prior byte visible to the polling guest.  A nominal
# sub-FIFO chunk still lost bytes under single-thread TCG, so the real-QEMU
# control path deliberately sends one byte at a time with a conservative drain
# window.  This is an experiment control/evidence channel, not a data path.
UART_WRITE_CHUNK_BYTES = 1
UART_WRITE_INTER_CHUNK_SECONDS = 0.002
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_CUTPOINT = re.compile(r"^(0|[1-9][0-9]{0,4})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class BarrierProtocolError(ValueError):
    pass


def paced_sendall(sock: object, frame: bytes, *, chunk_bytes: int = UART_WRITE_CHUNK_BYTES,
                  inter_chunk_seconds: float = 0.0) -> None:
    """Write one bounded UART frame without overrunning QEMU's 16550 RX FIFO.

    The socket remains a byte stream: this deliberately preserves frame order
    and does not add framing or retry semantics. Tests may set a zero delay,
    but real launch paths opt into the conservative delay explicitly.
    """
    if not frame or len(frame) > MAX_LINE_BYTES:
        raise BarrierProtocolError("invalid paced UART frame")
    if not 1 <= chunk_bytes <= 16 or inter_chunk_seconds < 0:
        raise ValueError("invalid UART pacing")
    sender = getattr(sock, "sendall", None)
    if sender is None:
        raise TypeError("UART peer does not provide sendall")
    # Unit/socketpair callers intentionally use the zero-delay path: retain a
    # single write there so their ordinary one-recv assertions keep modeling a
    # byte stream rather than a hardware FIFO.
    if inter_chunk_seconds == 0:
        sender(frame)
        return
    for offset in range(0, len(frame), chunk_bytes):
        sender(frame[offset:offset + chunk_bytes])
        if offset + chunk_bytes < len(frame) and inter_chunk_seconds:
            time.sleep(inter_chunk_seconds)


def _checksum(tokens: list[str]) -> str:
    return hashlib.sha256(" ".join(tokens).encode("ascii")).hexdigest()


def _validate(run_id: str, cutpoint: int) -> None:
    if not _RUN_ID.fullmatch(run_id):
        raise BarrierProtocolError("run_id must be exactly 32 lowercase hexadecimal characters")
    if not 0 <= cutpoint <= 65535:
        raise BarrierProtocolError("cutpoint must fit u16")


def barrier(run_id: str, cutpoint: int) -> bytes:
    """Build ``CSER1 BARRIER <run_id> <cutpoint> <sha256>\\n``."""
    _validate(run_id, cutpoint)
    tokens = ["CSER1", "BARRIER", run_id, str(cutpoint)]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")


def barrier_ack(run_id: str, cutpoint: int) -> bytes:
    """Build the same-shaped acknowledgement for a verified barrier."""
    _validate(run_id, cutpoint)
    tokens = ["CSER1", "ACK", run_id, str(cutpoint)]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")


def config_response(run_id: str, catalog_digest: str, namespace_id: str, authority_id: str, effect_id: str) -> bytes:
    """Build the trusted-local, pre-plan control response.

    COM3 is an experiment control channel, not endpoint evidence.  The
    checksum makes malformed/mixed rows fail closed; the host-side launcher is
    the trusted authority for selecting the freshly generated run namespace.
    """
    _validate(run_id, 0)
    if not _DIGEST.fullmatch(catalog_digest):
        raise BarrierProtocolError("catalog digest must be 64 lowercase hexadecimal characters")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", namespace_id):
        raise BarrierProtocolError("invalid endpoint namespace")
    if not _RUN_ID.fullmatch(authority_id):
        raise BarrierProtocolError("invalid endpoint authority")
    if not _RUN_ID.fullmatch(effect_id):
        raise BarrierProtocolError("invalid endpoint effect")
    tokens = ["CSER1", "CONFIG", run_id, catalog_digest, namespace_id, authority_id, effect_id]
    return (" ".join(tokens + [_checksum(tokens)]) + "\n").encode("ascii")


def parse_config_hello(line: bytes) -> None:
    """Validate the guest's strict configuration hello."""
    if not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES:
        raise BarrierProtocolError("invalid configuration hello frame length")
    try:
        fields = line[:-1].decode("ascii").split(" ")
    except UnicodeDecodeError as exc:
        raise BarrierProtocolError("configuration hello is not ASCII") from exc
    if len(fields) != 3 or fields[:2] != ["CSER1", "CONFIG_HELLO"]:
        raise BarrierProtocolError("invalid configuration hello frame")
    if not _DIGEST.fullmatch(fields[-1]) or fields[-1] != _checksum(fields[:-1]):
        raise BarrierProtocolError("invalid configuration hello checksum")


def parse_barrier(line: bytes, *, expected_run_id: str, expected_cutpoint: int | None = None) -> int:
    """Validate one barrier line and bind it to this exact trial."""
    if not _RUN_ID.fullmatch(expected_run_id):
        raise BarrierProtocolError("run_id must be exactly 32 lowercase hexadecimal characters")
    if expected_cutpoint is not None and not 0 <= expected_cutpoint <= 65535:
        raise BarrierProtocolError("cutpoint must fit u16")
    if not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES:
        raise BarrierProtocolError("invalid barrier frame length")
    try:
        fields = line[:-1].decode("ascii").split(" ")
    except UnicodeDecodeError as exc:
        raise BarrierProtocolError("barrier is not ASCII") from exc
    if len(fields) != 5 or fields[:2] != ["CSER1", "BARRIER"]:
        raise BarrierProtocolError("invalid barrier frame")
    if not _DIGEST.fullmatch(fields[-1]) or fields[-1] != _checksum(fields[:-1]):
        raise BarrierProtocolError("invalid barrier checksum")
    if not _CUTPOINT.fullmatch(fields[3]):
        raise BarrierProtocolError("invalid cutpoint")
    _validate(fields[2], int(fields[3]))
    cutpoint = int(fields[3])
    if fields[2] != expected_run_id or (expected_cutpoint is not None and cutpoint != expected_cutpoint):
        raise BarrierProtocolError("barrier does not name this trial")
    return cutpoint
