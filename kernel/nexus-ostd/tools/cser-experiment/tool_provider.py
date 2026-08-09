"""Independently durable, exact-key provider for the async reference endpoint.

This is intentionally small: it models the external tool authority which can
be queried after an adapter crash.  It is not a remote security boundary.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from protocol import (
    CHILD_DESCRIPTOR_V1_ROUTE_DIGEST,
    CHILD_DESCRIPTOR_V1_WIRE_LEN,
    CHILD_DISCOVERY_V1_PREFIX,
    MAX_TERMINAL_OUTPUT_BYTES,
)


_CHILD_DISCOVERY_V1 = re.compile(
    rb"^discover-child-v1:([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{8})$"
)


def _nonzero_u64(value: bytes) -> int:
    """Decode the low canonical lane of a descriptor-derived identifier."""
    result = int.from_bytes(value[:8], "little")
    return result if result else 1


def _descriptor_u64(
    label: bytes,
    identity: tuple[str, str, str, str, str, str],
    input_digest: str,
) -> int:
    """Derive an exact child coordinate from the complete provider identity.

    Each textual field is length-delimited.  In particular, the operation key
    is present even though it is the final identity member: this keeps a
    future identity-layout change from accidentally turning an ambiguous
    concatenation into the same resource coordinate.
    """
    hasher = hashlib.sha256()
    hasher.update(label)
    for field in (*identity, input_digest):
        encoded = field.encode("ascii")
        hasher.update(len(encoded).to_bytes(8, "little"))
        hasher.update(encoded)
    return _nonzero_u64(hasher.digest())


def _child_descriptor_v1(
    identity: tuple[str, str, str, str, str, str],
    input_digest: str,
    payload: bytes,
) -> bytes | None:
    """Build the provider-owned fixed child descriptor for one valid request.

    The request only identifies the parent coordinate.  Every child field
    which is not that parent coordinate is either a fixed experimental catalog
    coordinate or derived by this provider from the durable exact identity.
    This deliberately prevents the former ``child-descriptor-v1:`` echo path.
    """
    match = _CHILD_DISCOVERY_V1.fullmatch(payload)
    if match is None:
        return None
    parent_root, parent_sequence, parent_component = (
        int(group, 16) for group in match.groups()
    )
    if parent_root == 0 or parent_component == 0:
        return None
    try:
        input_digest_bytes = bytes.fromhex(input_digest)
        catalog_digest_bytes = bytes.fromhex(identity[3])
    except ValueError:
        return None
    if len(input_digest_bytes) != 32 or len(catalog_digest_bytes) != 32:
        return None

    wire = bytearray()
    wire += b"NXSCHD03"
    wire += (1).to_bytes(2, "little")          # schema
    wire += (1).to_bytes(8, "little")          # one permitted child
    wire += parent_root.to_bytes(8, "little")
    wire += parent_sequence.to_bytes(8, "little")
    wire += parent_component.to_bytes(4, "little")
    wire += CHILD_DESCRIPTOR_V1_ROUTE_DIGEST
    wire += (5).to_bytes(4, "little")          # TOOL_HANDOFF_CHILD_COMPOSITE
    wire += (5).to_bytes(4, "little")          # TOOL_HANDOFF_COMPONENT
    wire += _descriptor_u64(
        b"nexus-cser-tool-provider-child-claim-v1", identity, input_digest
    ).to_bytes(8, "little")
    wire += (1).to_bytes(4, "little")          # TOOL_CLAIM_OUTCOME_SLOT
    wire += b"\x00" + (0).to_bytes(8, "little") # logical scope, scope id zero
    wire += _descriptor_u64(
        b"nexus-cser-tool-provider-child-resource-v1", identity, input_digest
    ).to_bytes(8, "little")
    wire += (1).to_bytes(8, "little")          # generation
    wire += (1).to_bytes(8, "little")          # units
    wire += input_digest_bytes
    wire += catalog_digest_bytes
    if len(wire) != CHILD_DESCRIPTOR_V1_WIRE_LEN:
        raise AssertionError("child descriptor wire layout changed")
    return bytes(wire)


@dataclass(frozen=True)
class ProviderOutcome:
    state: str
    result: str
    output_kind: str = "none"
    output: bytes = b""
    # The provider's durable commit boundary, not the time a caller observed
    # it.  It lets the adapter preserve an apply-before-terminal recovery gap.
    applied_at_ns: int = 0


# Observation is intentionally post-durability and best-effort.  It is not a
# provider decision input, and a recorder fault must not change exact-key
# idempotency or whether a caller observes an infrastructure failure.
ProviderObserver = Callable[[str, tuple[str, str, str, str, str, str], str, ProviderOutcome | None], None]


class ProviderStore:
    """A separate SQLite durability domain with exact identity idempotency."""

    def __init__(self, database: Path, *, fault_after_apply_once: bool = False,
                 delay_ms: int = 0, observer: ProviderObserver | None = None) -> None:
        if delay_ms < 0:
            raise ValueError("provider delay must not be negative")
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(database), check_same_thread=False, isolation_level=None)
        try:
            self._fault_after_apply_once = fault_after_apply_once
            self._delay_seconds = delay_ms / 1000.0
            self._observer = observer
            self._counters = {"query": 0, "applied": 0, "dedup": 0, "telemetry_dropped": 0}
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._open()
        except BaseException:
            self._connection.close()
            raise

    def _observe(self, event: str, identity: tuple[str, str, str, str, str, str],
                 input_digest: str, outcome: ProviderOutcome | None) -> None:
        if self._observer is None:
            return
        try:
            self._observer(event, identity, input_digest, outcome)
        except BaseException:
            # Observability is never allowed to alter provider availability or
            # its durable answer.  The counter makes loss explicit to callers.
            with self._lock:
                self._counters["telemetry_dropped"] += 1

    def _open(self) -> None:
        expected_columns = {
            "namespace_id", "authority_id", "effect_id", "catalog_digest", "run_id", "operation_key",
            "input_digest", "payload", "state", "result", "output_kind", "output", "applied_at_ns",
        }
        v1_columns = expected_columns - {"output_kind", "output"}
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                version = self._connection.execute("PRAGMA user_version").fetchone()[0]
                if version > 1:
                    raise ValueError("provider database uses a newer unsupported schema")
                columns = {row[1] for row in self._connection.execute("PRAGMA table_info(provider_operations)")}
                if columns and columns not in (expected_columns, v1_columns):
                    raise ValueError("provider database has an unknown or unmigratable operations schema")
                if columns == v1_columns:
                    self._connection.execute("ALTER TABLE provider_operations ADD COLUMN output_kind TEXT NOT NULL DEFAULT 'none'")
                    self._connection.execute("ALTER TABLE provider_operations ADD COLUMN output BLOB NOT NULL DEFAULT X''")
                if not columns:
                    self._connection.execute(
                        """CREATE TABLE provider_operations (
                               namespace_id TEXT NOT NULL, authority_id TEXT NOT NULL, effect_id TEXT NOT NULL,
                               catalog_digest TEXT NOT NULL, run_id TEXT NOT NULL, operation_key TEXT NOT NULL,
                               input_digest TEXT NOT NULL, payload BLOB NOT NULL,
                               state TEXT NOT NULL CHECK(state IN ('succeeded','failed')), result TEXT NOT NULL,
                               output_kind TEXT NOT NULL, output BLOB NOT NULL,
                               applied_at_ns INTEGER NOT NULL,
                               PRIMARY KEY(namespace_id, authority_id, effect_id, catalog_digest, run_id, operation_key)
                           )"""
                    )
                self._connection.execute("CREATE TABLE IF NOT EXISTS provider_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                metadata_columns = {row[1] for row in self._connection.execute("PRAGMA table_info(provider_metadata)")}
                if metadata_columns != {"key", "value"}:
                    raise ValueError("provider database has an unknown metadata schema")
                metadata = dict(self._connection.execute("SELECT key, value FROM provider_metadata"))
                if not metadata:
                    self._connection.execute("INSERT INTO provider_metadata(key, value) VALUES ('schema_version', '1')")
                elif metadata != {"schema_version": "1"}:
                    raise ValueError("provider database metadata differs from its durable contract")
                self._connection.execute("PRAGMA user_version=1")
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def query(self, identity: tuple[str, str, str, str, str, str], input_digest: str) -> ProviderOutcome | None:
        with self._lock:
            self._counters["query"] += 1
            outcome = self._query_locked(identity, input_digest)
        self._observe("provider_query_hit" if outcome is not None else "provider_query_miss",
                      identity, input_digest, outcome)
        return outcome

    def _query_locked(self, identity: tuple[str, str, str, str, str, str], input_digest: str) -> ProviderOutcome | None:
        row = self._connection.execute(
            """SELECT input_digest, state, result, output_kind, output, applied_at_ns FROM provider_operations
               WHERE namespace_id=? AND authority_id=? AND effect_id=? AND catalog_digest=? AND run_id=? AND operation_key=?""",
            identity,
        ).fetchone()
        if row is None:
            return None
        if row[0] != input_digest:
            raise ValueError("provider exact-key input conflict")
        return ProviderOutcome(row[1], row[2], row[3], row[4], row[5])

    def apply(self, identity: tuple[str, str, str, str, str, str], input_digest: str, payload: bytes) -> ProviderOutcome:
        """Apply once, or return the previously durable exact-key outcome.

        ``app-fail:`` is a deliberately controlled verified application result
        for the reference experiment.  SQLite/transport errors are not mapped
        to it and must leave the adapter operation Pending.
        """
        # Check without holding the lock while the deliberately injected
        # provider latency elapses.  A second exact-key check below makes this
        # race harmless and retains one durable application.
        with self._lock:
            existing = self._query_locked(identity, input_digest)
            if existing is not None:
                self._counters["dedup"] += 1
                outcome, observation = existing, "provider_apply_deduplicated"
            else:
                outcome = None
                observation = ""
        if outcome is not None:
            self._observe(observation, identity, input_digest, outcome)
            return outcome
        if self._delay_seconds:
            time.sleep(self._delay_seconds)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._query_locked(identity, input_digest)
                if existing is not None:
                    self._counters["dedup"] += 1
                    self._connection.execute("COMMIT")
                    outcome, observation = existing, "provider_apply_deduplicated"
                else:
                    discovery = payload.startswith(CHILD_DISCOVERY_V1_PREFIX)
                    output = _child_descriptor_v1(identity, input_digest, payload) if discovery else None
                    # A discovery request is an application-level request for
                    # an exact descriptor, not a transport of one supplied by
                    # the caller.  Its grammar and output bound are therefore
                    # verified before the durable terminal decision.
                    invalid_discovery = discovery and output is None
                    oversized_descriptor = output is not None and len(output) > MAX_TERMINAL_OUTPUT_BYTES
                    applied_at_ns = time.time_ns()
                    outcome = ProviderOutcome(
                        "failed" if payload.startswith(b"app-fail:") or invalid_discovery or oversized_descriptor else "succeeded",
                        "application_failed" if payload.startswith(b"app-fail:") else (
                            "invalid_child_discovery" if invalid_discovery else (
                                "descriptor_too_large" if oversized_descriptor else "success"
                            )
                        ),
                        "child_descriptor_v1" if output is not None and not oversized_descriptor else "none",
                        output if output is not None and not oversized_descriptor else b"", applied_at_ns,
                    )
                    self._connection.execute(
                        """INSERT INTO provider_operations(namespace_id, authority_id, effect_id, catalog_digest,
                           run_id, operation_key, input_digest, payload, state, result, output_kind, output, applied_at_ns)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (*identity, input_digest, payload, outcome.state, outcome.result,
                         outcome.output_kind, outcome.output, outcome.applied_at_ns),
                    )
                    self._connection.execute("COMMIT")
                    self._counters["applied"] += 1
                    observation = "provider_apply_durable"
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        self._observe(observation, identity, input_digest, outcome)
        if self._fault_after_apply_once:
            self._fault_after_apply_once = False
            raise OSError("injected provider loss after durable apply")
        return outcome

    def metrics(self) -> dict[str, str]:
        with self._lock:
            return {f"provider_{key}": str(value) for key, value in self._counters.items()}

    def close(self) -> None:
        self._connection.close()
