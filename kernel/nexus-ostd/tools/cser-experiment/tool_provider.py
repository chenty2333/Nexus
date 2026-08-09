"""Independently durable, exact-key provider for the async reference endpoint.

This is intentionally small: it models the external tool authority which can
be queried after an adapter crash.  It is not a remote security boundary.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from protocol import MAX_TERMINAL_OUTPUT_BYTES


@dataclass(frozen=True)
class ProviderOutcome:
    state: str
    result: str
    output_kind: str = "none"
    output: bytes = b""


# Observation is intentionally post-durability and best-effort.  It is not a
# provider decision input, and a recorder fault must not change exact-key
# idempotency or whether a caller observes an infrastructure failure.
ProviderObserver = Callable[[str, tuple[str, str, str, str, str, str], str, ProviderOutcome | None], None]


class ProviderStore:
    """A separate SQLite durability domain with exact identity idempotency."""

    def __init__(self, database: Path, *, fault_after_apply_once: bool = False,
                 observer: ProviderObserver | None = None) -> None:
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(database), check_same_thread=False, isolation_level=None)
        try:
            self._fault_after_apply_once = fault_after_apply_once
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
            """SELECT input_digest, state, result, output_kind, output FROM provider_operations
               WHERE namespace_id=? AND authority_id=? AND effect_id=? AND catalog_digest=? AND run_id=? AND operation_key=?""",
            identity,
        ).fetchone()
        if row is None:
            return None
        if row[0] != input_digest:
            raise ValueError("provider exact-key input conflict")
        return ProviderOutcome(row[1], row[2], row[3], row[4])

    def apply(self, identity: tuple[str, str, str, str, str, str], input_digest: str, payload: bytes) -> ProviderOutcome:
        """Apply once, or return the previously durable exact-key outcome.

        ``app-fail:`` is a deliberately controlled verified application result
        for the reference experiment.  SQLite/transport errors are not mapped
        to it and must leave the adapter operation Pending.
        """
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._query_locked(identity, input_digest)
                if existing is not None:
                    self._counters["dedup"] += 1
                    self._connection.execute("COMMIT")
                    outcome, observation = existing, "provider_apply_deduplicated"
                else:
                    descriptor_prefix = b"child-descriptor-v1:"
                    output = payload[len(descriptor_prefix):] if payload.startswith(descriptor_prefix) else b""
                    oversized_descriptor = len(output) > MAX_TERMINAL_OUTPUT_BYTES
                    outcome = ProviderOutcome(
                        "failed" if payload.startswith(b"app-fail:") or oversized_descriptor else "succeeded",
                        "application_failed" if payload.startswith(b"app-fail:") else ("descriptor_too_large" if oversized_descriptor else "success"),
                        "none" if oversized_descriptor else ("child_descriptor_v1" if output else "none"),
                        b"" if oversized_descriptor else output,
                    )
                    self._connection.execute(
                        """INSERT INTO provider_operations(namespace_id, authority_id, effect_id, catalog_digest,
                           run_id, operation_key, input_digest, payload, state, result, output_kind, output, applied_at_ns)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (*identity, input_digest, payload, outcome.state, outcome.result,
                         outcome.output_kind, outcome.output, time.time_ns()),
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
