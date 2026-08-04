"""Strict host/guest barrier framing for crash-matrix trials.

This protocol is intentionally separate from the tool-request UART protocol.
The host must only kill a guest after the checksum-protected frame names the
exact run and cutpoint, rather than after an inferred delay in the guest log.
The checksum detects framing corruption; it is not sender authentication.
"""

from __future__ import annotations

import hashlib
import re


MAX_LINE_BYTES = 1024
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_CUTPOINT = re.compile(r"^(0|[1-9][0-9]{0,4})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class BarrierProtocolError(ValueError):
    pass


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
