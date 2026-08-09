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


@dataclass(frozen=True)
class ProviderOutcome:
    state: str
    result: str


class ProviderStore:
    """A separate SQLite durability domain with exact identity idempotency."""

    def __init__(self, database: Path, *, fault_after_apply_once: bool = False) -> None:
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(database), check_same_thread=False, isolation_level=None)
        try:
            self._fault_after_apply_once = fault_after_apply_once
            self._counters = {"query": 0, "applied": 0, "dedup": 0}
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._open()
        except BaseException:
            self._connection.close()
            raise

    def _open(self) -> None:
        expected_columns = {
            "namespace_id", "authority_id", "effect_id", "catalog_digest", "run_id", "operation_key",
            "input_digest", "payload", "state", "result", "applied_at_ns",
        }
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                version = self._connection.execute("PRAGMA user_version").fetchone()[0]
                if version > 1:
                    raise ValueError("provider database uses a newer unsupported schema")
                columns = {row[1] for row in self._connection.execute("PRAGMA table_info(provider_operations)")}
                if columns and columns != expected_columns:
                    raise ValueError("provider database has an unknown or unmigratable operations schema")
                if not columns:
                    self._connection.execute(
                        """CREATE TABLE provider_operations (
                               namespace_id TEXT NOT NULL, authority_id TEXT NOT NULL, effect_id TEXT NOT NULL,
                               catalog_digest TEXT NOT NULL, run_id TEXT NOT NULL, operation_key TEXT NOT NULL,
                               input_digest TEXT NOT NULL, payload BLOB NOT NULL,
                               state TEXT NOT NULL CHECK(state IN ('succeeded','failed')), result TEXT NOT NULL,
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
            return self._query_locked(identity, input_digest)

    def _query_locked(self, identity: tuple[str, str, str, str, str, str], input_digest: str) -> ProviderOutcome | None:
        row = self._connection.execute(
            """SELECT input_digest, state, result FROM provider_operations
               WHERE namespace_id=? AND authority_id=? AND effect_id=? AND catalog_digest=? AND run_id=? AND operation_key=?""",
            identity,
        ).fetchone()
        if row is None:
            return None
        if row[0] != input_digest:
            raise ValueError("provider exact-key input conflict")
        return ProviderOutcome(row[1], row[2])

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
                    return existing
                outcome = ProviderOutcome(
                    "failed" if payload.startswith(b"app-fail:") else "succeeded",
                    "application_failed" if payload.startswith(b"app-fail:") else "success",
                )
                self._connection.execute(
                    """INSERT INTO provider_operations(namespace_id, authority_id, effect_id, catalog_digest,
                       run_id, operation_key, input_digest, payload, state, result, applied_at_ns)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (*identity, input_digest, payload, outcome.state, outcome.result, time.time_ns()),
                )
                self._connection.execute("COMMIT")
                self._counters["applied"] += 1
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        if self._fault_after_apply_once:
            self._fault_after_apply_once = False
            raise OSError("injected provider loss after durable apply")
        return outcome

    def metrics(self) -> dict[str, str]:
        with self._lock:
            return {f"provider_{key}": str(value) for key, value in self._counters.items()}

    def close(self) -> None:
        self._connection.close()
