#!/usr/bin/env python3
"""Trusted-local durable evidence endpoint for the CSER tool experiment.

This is a *reference sidecar*, not a remote attestation service.  Its
authority is the host-local process and SQLite database selected by the
launcher.  A v2 evidence record consequently binds the randomly generated,
durably stored local authority id, namespace, generated effect id, operation
and input, catalog digest, schema version and state.  The older five-field
``record_digest`` is retained only for isolated v1 compatibility tests; real
QEMU runs consume the fully bound v2 evidence digest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from protocol import (
    ENDPOINT_HTTP_CONTRACT_VERSION,
    ENDPOINT_RECORD_SCHEMA_VERSION,
    MAX_PAYLOAD_BYTES,
    ProtocolError,
    digest,
    evidence_record_digest,
    record_digest,
    validate_run_id,
)
from tool_provider import ProviderStore
from tool_worker import AsyncWorker


_DEFAULT_CATALOG_DIGEST = hashlib.sha256(b"nexus-cser-local-evidence-unbound-v2").hexdigest()
_DEFAULT_NAMESPACE = "trusted-local"
_ASYNC_QUEUE_SCHEMA_VERSION = 1


def _valid_id(value: object) -> bool:
    import re

    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None


def _valid_digest(value: object) -> bool:
    import re

    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


class OperationState(str, Enum):
    ACCEPTED = "accepted"
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"

    @property
    def terminal(self) -> bool:
        return self in (self.SUCCEEDED, self.FAILED)


@dataclass(frozen=True)
class EndpointRecord:
    namespace_id: str
    authority_id: str
    effect_id: str
    run_id: str
    operation_key: str
    input_digest: str
    catalog_digest: str
    state: OperationState
    result: str
    record_schema_version: int
    created_at_ns: int
    updated_at_ns: int
    expires_at_ns: int

    def evidence_digest(self) -> str:
        if self.record_schema_version != ENDPOINT_RECORD_SCHEMA_VERSION or not self.state.terminal:
            # Migrated records are retained solely as fail-closed tombstones;
            # they must never acquire a v2 evidence identity retroactively.
            return "-"
        return evidence_record_digest(
            self.namespace_id,
            self.authority_id,
            self.effect_id,
            self.run_id,
            self.operation_key,
            self.input_digest,
            self.catalog_digest,
            self.record_schema_version,
            self.state.value,
            self.result,
        )

    def legacy_record_digest(self) -> str | None:
        if self.state == OperationState.SUCCEEDED:
            return record_digest(self.run_id, self.operation_key, self.input_digest, "applied", "success")
        if self.state == OperationState.FAILED:
            return record_digest(self.run_id, self.operation_key, self.input_digest, "failed", self.result)
        return None

    def document(self, *, replayed: bool = False) -> dict[str, str]:
        legacy = self.legacy_record_digest()
        return {
            "contract_version": str(ENDPOINT_HTTP_CONTRACT_VERSION),
            "namespace_id": self.namespace_id,
            "authority_id": self.authority_id,
            "effect_id": self.effect_id,
            "run_id": self.run_id,
            "operation_key": self.operation_key,
            "payload_digest": self.input_digest,
            "input_digest": self.input_digest,
            "catalog_digest": self.catalog_digest,
            "record_schema_version": str(self.record_schema_version),
            "state": self.state.value,
            # Retain these two v1 names only for the isolated compatibility API.
            "status": "applied" if self.state == OperationState.SUCCEEDED else self.state.value,
            "result": "success" if self.state == OperationState.SUCCEEDED else self.result,
            "record_digest": legacy or "-",
            "evidence_record_digest": self.evidence_digest(),
            "created_at_ns": str(self.created_at_ns),
            "updated_at_ns": str(self.updated_at_ns),
            "expires_at_ns": str(self.expires_at_ns),
            "replayed": "true" if replayed else "false",
        }


@dataclass(frozen=True)
class WorkItem:
    namespace_id: str
    authority_id: str
    effect_id: str
    catalog_digest: str
    run_id: str
    operation_key: str
    input_digest: str
    payload: bytes
    lease_token: str


class Store:
    """SQLite-backed v2 evidence store with fail-closed expiry.

    Reopening the same database preserves its random authority id.  Changing
    namespace, catalog digest, or retention policy against that database is a
    configuration error rather than a silent reinterpretation of evidence.
    """

    def __init__(
        self,
        database: Path,
        *,
        namespace_id: str = _DEFAULT_NAMESPACE,
        catalog_digest: str = _DEFAULT_CATALOG_DIGEST,
        authority_id: str | None = None,
        effect_id: str | None = None,
        retention_seconds: int = 24 * 60 * 60,
        fault_before_commit_once: bool = False,
    ) -> None:
        if not _valid_id(namespace_id):
            raise ValueError("invalid namespace id")
        if not _valid_digest(catalog_digest):
            raise ValueError("invalid catalog digest")
        if authority_id is not None:
            try:
                validate_run_id(authority_id)
            except ProtocolError as exc:
                raise ValueError("invalid authority id") from exc
        if effect_id is not None:
            try:
                validate_run_id(effect_id)
            except ProtocolError as exc:
                raise ValueError("invalid effect id") from exc
        if retention_seconds <= 0:
            raise ValueError("retention seconds must be positive")
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(database), check_same_thread=False, isolation_level=None)
        try:
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._namespace_id = namespace_id
            self._catalog_digest = catalog_digest
            self._configured_authority_id = authority_id
            self._configured_effect_id = effect_id
            self._database = database
            self._retention_ns = retention_seconds * 1_000_000_000
            self._fault_before_commit_once = fault_before_commit_once
            self._counters = {
                "submit": 0, "replay": 0, "conflict": 0, "expired": 0, "transition": 0,
                "infrastructure_retry": 0, "infrastructure_backoff": 0,
            }
            self._migrate_and_open()
        except BaseException:
            # A corrupt, newer, or unmigratable database is a hard startup
            # failure. Do not leave its SQLite fd alive merely because the
            # fail-closed validation happened during construction.
            self._connection.close()
            raise

    def _migrate_and_open(self) -> None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                on_disk_version = self._connection.execute("PRAGMA user_version").fetchone()[0]
                if on_disk_version > ENDPOINT_RECORD_SCHEMA_VERSION:
                    raise ValueError("endpoint database uses a newer unsupported schema")
                columns = {
                    row[1] for row in self._connection.execute("PRAGMA table_info(operations)").fetchall()
                }
                v2_columns = {
                    "namespace_id", "authority_id", "effect_id", "run_id", "operation_key",
                    "input_digest", "payload", "state", "result", "catalog_digest",
                    "record_schema_version", "created_at_ns", "updated_at_ns", "expires_at_ns",
                }
                legacy_columns = {"run_id", "operation_key", "payload_digest", "payload", "status", "result"}
                if columns and columns != v2_columns and columns != legacy_columns:
                    raise ValueError("endpoint database has an unknown or unmigratable operations schema")
                if columns == legacy_columns:
                    # Preserve the old bytes for diagnosis but make their old,
                    # unbound evidence unavailable after migration.  A caller
                    # must re-establish a v2 record instead of treating a
                    # newly attached authority/catalog as historical proof.
                    self._connection.execute("ALTER TABLE operations RENAME TO operations_v1_unbound")
                    self._create_operations_table()
                    now = time.time_ns()
                    self._connection.execute(
                        """INSERT INTO operations(namespace_id, authority_id, effect_id, run_id, operation_key,
                           input_digest, payload, state, result, catalog_digest, record_schema_version,
                           created_at_ns, updated_at_ns, expires_at_ns)
                           SELECT 'legacy', '00000000000000000000000000000000',
                                  '00000000000000000000000000000000', run_id, operation_key,
                                  payload_digest, payload, 'expired', result, ?, 1, ?, ?, 0
                           FROM operations_v1_unbound""",
                        (_DEFAULT_CATALOG_DIGEST, now, now),
                    )
                    self._connection.execute("DROP TABLE operations_v1_unbound")
                elif not columns:
                    self._create_operations_table()
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS adapter_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                queue_columns = self._connection.execute("PRAGMA table_info(operation_queue)").fetchall()
                if not queue_columns:
                    self._create_operation_queue_table()
                else:
                    self._validate_operation_queue_schema(queue_columns)
                metadata = dict(self._connection.execute("SELECT key, value FROM adapter_metadata").fetchall())
                if not metadata:
                    metadata = {
                        "schema_version": str(ENDPOINT_RECORD_SCHEMA_VERSION),
                        "authority_id": self._configured_authority_id or secrets.token_hex(16),
                        "effect_id": self._configured_effect_id or secrets.token_hex(16),
                        "namespace_id": self._namespace_id,
                        "catalog_digest": self._catalog_digest,
                        "retention_ns": str(self._retention_ns),
                        "async_queue_schema_version": str(_ASYNC_QUEUE_SCHEMA_VERSION),
                        "created_at_ns": str(time.time_ns()),
                    }
                    self._connection.executemany(
                        "INSERT INTO adapter_metadata(key, value) VALUES (?, ?)", metadata.items()
                    )
                # Existing v2 databases had no queue.  Adding this explicit
                # marker is the one-way migration boundary for the async
                # durable schema; malformed pre-existing queues are rejected.
                if "async_queue_schema_version" not in metadata:
                    self._connection.execute(
                        "INSERT INTO adapter_metadata(key, value) VALUES ('async_queue_schema_version', ?)",
                        (str(_ASYNC_QUEUE_SCHEMA_VERSION),),
                    )
                    metadata["async_queue_schema_version"] = str(_ASYNC_QUEUE_SCHEMA_VERSION)
                expected = {
                    "schema_version": str(ENDPOINT_RECORD_SCHEMA_VERSION),
                    "namespace_id": self._namespace_id,
                    "catalog_digest": self._catalog_digest,
                    "retention_ns": str(self._retention_ns),
                    "async_queue_schema_version": str(_ASYNC_QUEUE_SCHEMA_VERSION),
                }
                if any(metadata.get(key) != value for key, value in expected.items()):
                    raise ValueError("endpoint database configuration differs from its durable evidence contract")
                authority = metadata.get("authority_id")
                effect = metadata.get("effect_id")
                try:
                    if authority is None:
                        raise ProtocolError("missing authority")
                    validate_run_id(authority)
                except (ProtocolError, TypeError) as exc:
                    raise ValueError("endpoint database has invalid durable authority id") from exc
                self._authority_id = authority
                if self._configured_authority_id is not None and authority != self._configured_authority_id:
                    raise ValueError("endpoint database authority differs from launcher configuration")
                try:
                    if effect is None:
                        raise ProtocolError("missing effect")
                    validate_run_id(effect)
                except (ProtocolError, TypeError) as exc:
                    raise ValueError("endpoint database has invalid durable effect id") from exc
                self._effect_id = effect
                if self._configured_effect_id is not None and effect != self._configured_effect_id:
                    raise ValueError("endpoint database effect differs from launcher configuration")
                self._connection.execute(f"PRAGMA user_version={ENDPOINT_RECORD_SCHEMA_VERSION}")
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def _create_operations_table(self) -> None:
        self._connection.execute(
            """CREATE TABLE operations (
                   namespace_id TEXT NOT NULL,
                   authority_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   run_id TEXT NOT NULL,
                   operation_key TEXT NOT NULL,
                   input_digest TEXT NOT NULL,
                   payload BLOB NOT NULL,
                   state TEXT NOT NULL CHECK(state IN ('accepted','pending','succeeded','failed','expired')),
                   result TEXT NOT NULL,
                   catalog_digest TEXT NOT NULL,
                   record_schema_version INTEGER NOT NULL,
                   created_at_ns INTEGER NOT NULL,
                   updated_at_ns INTEGER NOT NULL,
                   expires_at_ns INTEGER NOT NULL,
                   PRIMARY KEY(namespace_id, run_id, operation_key)
               )"""
        )

    def _create_operation_queue_table(self) -> None:
        self._connection.execute(
            """CREATE TABLE operation_queue (
                   namespace_id TEXT NOT NULL, run_id TEXT NOT NULL, operation_key TEXT NOT NULL,
                   lease_token TEXT, lease_until_ns INTEGER, attempts INTEGER NOT NULL DEFAULT 0,
                   PRIMARY KEY(namespace_id, run_id, operation_key),
                   FOREIGN KEY(namespace_id, run_id, operation_key)
                     REFERENCES operations(namespace_id, run_id, operation_key)
               )"""
        )

    def _validate_operation_queue_schema(self, columns: list[tuple[Any, ...]]) -> None:
        expected = {
            "namespace_id": ("TEXT", 1, None, 1), "run_id": ("TEXT", 1, None, 2),
            "operation_key": ("TEXT", 1, None, 3), "lease_token": ("TEXT", 0, None, 0),
            "lease_until_ns": ("INTEGER", 0, None, 0), "attempts": ("INTEGER", 1, "0", 0),
        }
        actual = {
            row[1]: (str(row[2]).upper(), row[3], None if row[4] is None else str(row[4]), row[5])
            for row in columns
        }
        if actual != expected:
            raise ValueError("endpoint database has an unknown or unmigratable operation_queue schema")
        foreign = self._connection.execute("PRAGMA foreign_key_list(operation_queue)").fetchall()
        actual_foreign = {(row[2], row[3], row[4]) for row in foreign}
        expected_foreign = {
            ("operations", "namespace_id", "namespace_id"), ("operations", "run_id", "run_id"),
            ("operations", "operation_key", "operation_key"),
        }
        if actual_foreign != expected_foreign:
            raise ValueError("operation_queue is missing its operations foreign key")
        orphan = self._connection.execute(
            """SELECT 1 FROM operation_queue q LEFT JOIN operations o
                 ON (o.namespace_id, o.run_id, o.operation_key) = (q.namespace_id, q.run_id, q.operation_key)
                 WHERE o.namespace_id IS NULL OR o.state IN ('succeeded','failed','expired') LIMIT 1"""
        ).fetchone()
        if orphan is not None:
            raise ValueError("operation_queue contains orphaned or terminal work")

    @property
    def authority_id(self) -> str:
        return self._authority_id

    @property
    def effect_id(self) -> str:
        return self._effect_id

    @property
    def namespace_id(self) -> str:
        return self._namespace_id

    @property
    def catalog_digest(self) -> str:
        return self._catalog_digest

    @property
    def database(self) -> Path:
        return self._database

    def _from_row(self, row: tuple[Any, ...]) -> EndpointRecord:
        return EndpointRecord(
            namespace_id=row[0], authority_id=row[1], effect_id=row[2], run_id=row[3],
            operation_key=row[4], input_digest=row[5], state=OperationState(row[6]), result=row[7],
            catalog_digest=row[8], record_schema_version=row[9], created_at_ns=row[10],
            updated_at_ns=row[11], expires_at_ns=row[12],
        )

    @staticmethod
    def _now() -> int:
        return time.time_ns()

    def _select(self, run_id: str, operation_key: str) -> EndpointRecord | None:
        row = self._connection.execute(
            """SELECT namespace_id, authority_id, effect_id, run_id, operation_key, input_digest,
                      state, result, catalog_digest, record_schema_version, created_at_ns, updated_at_ns,
                      expires_at_ns FROM operations WHERE namespace_id=? AND run_id=? AND operation_key=?""",
            (self._namespace_id, run_id, operation_key),
        ).fetchone()
        # A migrated v1 row deliberately remains an expired tombstone rather
        # than becoming an apparent absence. The database is bound to one v2
        # namespace, so a fallback can only expose legacy quarantine, never a
        # second live tenant.
        if row is None:
            row = self._connection.execute(
                """SELECT namespace_id, authority_id, effect_id, run_id, operation_key, input_digest,
                          state, result, catalog_digest, record_schema_version, created_at_ns, updated_at_ns,
                          expires_at_ns FROM operations WHERE run_id=? AND operation_key=?""",
                (run_id, operation_key),
            ).fetchone()
        return None if row is None else self._from_row(row)

    def _expire_if_needed(self, record: EndpointRecord, now: int) -> EndpointRecord:
        # Retention begins only after immutable terminal evidence exists.
        # Accepted/Pending are recovery obligations, never expirable completion.
        if not record.state.terminal or record.state == OperationState.EXPIRED or now < record.expires_at_ns:
            return record
        self._connection.execute(
            "UPDATE operations SET state='expired', result='retention_expired', updated_at_ns=? "
            "WHERE namespace_id=? AND run_id=? AND operation_key=?",
            (now, record.namespace_id, record.run_id, record.operation_key),
        )
        self._counters["expired"] += 1
        return self._select(record.run_id, record.operation_key)  # type: ignore[return-value]

    def submit(
        self,
        run_id: str,
        operation_key: str,
        input_digest: str,
        payload: bytes,
        *,
        initial_state: OperationState = OperationState.SUCCEEDED,
        result: str = "success",
    ) -> tuple[int, dict[str, str]]:
        if initial_state == OperationState.EXPIRED or not _valid_id(result):
            raise ValueError("invalid initial operation state")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._select(run_id, operation_key)
                if existing is not None:
                    existing = self._expire_if_needed(existing, now)
                    if existing.state == OperationState.EXPIRED:
                        self._connection.execute("COMMIT")
                        return HTTPStatus.GONE, existing.document(replayed=True)
                    if existing.input_digest != input_digest:
                        self._counters["conflict"] += 1
                        self._connection.execute("COMMIT")
                        return HTTPStatus.CONFLICT, {"error": "operation_key_input_conflict"}
                    self._counters["replay"] += 1
                    self._connection.execute("COMMIT")
                    return self._status_for(existing, replayed=True), existing.document(replayed=True)
                expires = now + self._retention_ns
                self._connection.execute(
                    """INSERT INTO operations(namespace_id, authority_id, effect_id, run_id, operation_key,
                       input_digest, payload, state, result, catalog_digest, record_schema_version,
                       created_at_ns, updated_at_ns, expires_at_ns)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self._namespace_id, self._authority_id, self._effect_id, run_id, operation_key,
                     input_digest, payload, initial_state.value, result, self._catalog_digest,
                     ENDPOINT_RECORD_SCHEMA_VERSION, now, now, expires),
                )
                record = self._select(run_id, operation_key)
                assert record is not None
                if self._fault_before_commit_once:
                    self._fault_before_commit_once = False
                    raise RuntimeError("injected endpoint failure before durable commit")
                self._connection.execute("COMMIT")
                self._counters["submit"] += 1
                return self._status_for(record, replayed=False), record.document(replayed=False)
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _status_for(record: EndpointRecord, *, replayed: bool) -> int:
        if record.state == OperationState.SUCCEEDED:
            return HTTPStatus.OK if replayed else HTTPStatus.CREATED
        if record.state in (OperationState.ACCEPTED, OperationState.PENDING):
            return HTTPStatus.ACCEPTED
        if record.state == OperationState.FAILED:
            return HTTPStatus.CONFLICT
        return HTTPStatus.GONE

    def get(self, run_id: str, operation_key: str) -> dict[str, str] | None:
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                record = self._select(run_id, operation_key)
                if record is None:
                    self._connection.execute("COMMIT")
                    return None
                record = self._expire_if_needed(record, now)
                self._connection.execute("COMMIT")
                return record.document(replayed=True)
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def enqueue(self, run_id: str, operation_key: str, input_digest: str, payload: bytes) -> tuple[int, dict[str, str]]:
        """Durably accept a v2 operation and its work item before returning 202."""
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._select(run_id, operation_key)
                if existing is not None:
                    existing = self._expire_if_needed(existing, now)
                    if existing.state == OperationState.EXPIRED:
                        self._connection.execute("COMMIT")
                        return HTTPStatus.GONE, existing.document(replayed=True)
                    if existing.input_digest != input_digest:
                        self._counters["conflict"] += 1
                        self._connection.execute("COMMIT")
                        return HTTPStatus.CONFLICT, {"error": "operation_key_input_conflict"}
                    self._counters["replay"] += 1
                    self._connection.execute("COMMIT")
                    return self._status_for(existing, replayed=True), existing.document(replayed=True)
                self._connection.execute(
                    """INSERT INTO operations(namespace_id, authority_id, effect_id, run_id, operation_key,
                       input_digest, payload, state, result, catalog_digest, record_schema_version,
                       created_at_ns, updated_at_ns, expires_at_ns)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'accepted', 'queued', ?, ?, ?, ?, 0)""",
                    (self._namespace_id, self._authority_id, self._effect_id, run_id, operation_key,
                     input_digest, payload, self._catalog_digest, ENDPOINT_RECORD_SCHEMA_VERSION, now, now),
                )
                self._connection.execute(
                    "INSERT INTO operation_queue(namespace_id, run_id, operation_key) VALUES (?, ?, ?)",
                    (self._namespace_id, run_id, operation_key),
                )
                record = self._select(run_id, operation_key)
                assert record is not None
                if self._fault_before_commit_once:
                    self._fault_before_commit_once = False
                    raise RuntimeError("injected endpoint failure before durable commit")
                self._connection.execute("COMMIT")
                self._counters["submit"] += 1
                return HTTPStatus.ACCEPTED, record.document(replayed=False)
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def claim_next(self, worker_id: str, lease_seconds: float) -> WorkItem | None:
        if not _valid_id(worker_id) or lease_seconds <= 0:
            raise ValueError("invalid worker lease")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """SELECT o.namespace_id, o.authority_id, o.effect_id, o.catalog_digest, o.run_id, o.operation_key,
                              o.input_digest, o.payload
                       FROM operation_queue q JOIN operations o
                         ON (o.namespace_id, o.run_id, o.operation_key) =
                            (q.namespace_id, q.run_id, q.operation_key)
                       WHERE o.state IN ('accepted','pending')
                         AND (q.lease_until_ns IS NULL OR q.lease_until_ns < ?)
                       ORDER BY o.created_at_ns LIMIT 1""",
                    (now,),
                ).fetchone()
                if row is None:
                    self._connection.execute("COMMIT")
                    return None
                token = secrets.token_hex(16)
                until = now + int(lease_seconds * 1_000_000_000)
                changed = self._connection.execute(
                    """UPDATE operation_queue SET lease_token=?, lease_until_ns=?, attempts=attempts+1
                       WHERE namespace_id=? AND run_id=? AND operation_key=?
                         AND (lease_until_ns IS NULL OR lease_until_ns < ?)""",
                    (token, until, row[0], row[4], row[5], now),
                ).rowcount
                if changed != 1:
                    self._connection.execute("COMMIT")
                    return None
                self._connection.execute(
                    """UPDATE operations SET state='pending', result='working', updated_at_ns=?
                       WHERE namespace_id=? AND run_id=? AND operation_key=? AND state='accepted'""",
                    (now, row[0], row[4], row[5]),
                )
                self._counters["transition"] += 1
                self._connection.execute("COMMIT")
                return WorkItem(*row, token)
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def complete_lease(self, item: WorkItem, state: str, result: str) -> bool:
        if state not in ("succeeded", "failed") or not _valid_id(result):
            raise ValueError("invalid provider outcome")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                changed = self._connection.execute(
                    """UPDATE operations SET state=?, result=?, updated_at_ns=?, expires_at_ns=?
                       WHERE namespace_id=? AND run_id=? AND operation_key=? AND state IN ('accepted','pending')
                         AND EXISTS (SELECT 1 FROM operation_queue q WHERE q.namespace_id=operations.namespace_id
                           AND q.run_id=operations.run_id AND q.operation_key=operations.operation_key
                           AND q.lease_token=?)""",
                    (state, result, now, now + self._retention_ns, item.namespace_id, item.run_id,
                     item.operation_key, item.lease_token),
                ).rowcount
                if changed:
                    self._connection.execute(
                        "DELETE FROM operation_queue WHERE namespace_id=? AND run_id=? AND operation_key=? AND lease_token=?",
                        (item.namespace_id, item.run_id, item.operation_key, item.lease_token),
                    )
                    self._counters["transition"] += 1
                self._connection.execute("COMMIT")
                return changed == 1
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def release_lease(self, item: WorkItem) -> None:
        with self._lock:
            self._connection.execute(
                """UPDATE operation_queue SET lease_token=NULL, lease_until_ns=NULL
                   WHERE namespace_id=? AND run_id=? AND operation_key=? AND lease_token=?""",
                (item.namespace_id, item.run_id, item.operation_key, item.lease_token),
            )

    def record_infrastructure_retry(self) -> None:
        with self._lock:
            self._counters["infrastructure_retry"] += 1

    def record_infrastructure_backoff(self) -> None:
        with self._lock:
            self._counters["infrastructure_backoff"] += 1

    def transition(self, run_id: str, operation_key: str, state: OperationState, result: str) -> dict[str, str] | None:
        """Advance a nonterminal local job; terminal/expired facts are immutable."""
        if not _valid_id(result) or state == OperationState.EXPIRED:
            raise ValueError("invalid transition")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                record = self._select(run_id, operation_key)
                if record is None:
                    self._connection.execute("COMMIT")
                    return None
                record = self._expire_if_needed(record, now)
                if record.state.terminal or record.state == OperationState.EXPIRED:
                    self._connection.execute("COMMIT")
                    return record.document(replayed=True)
                allowed = {
                    OperationState.ACCEPTED: {OperationState.PENDING, OperationState.SUCCEEDED, OperationState.FAILED},
                    OperationState.PENDING: {OperationState.SUCCEEDED, OperationState.FAILED},
                }
                if state not in allowed[record.state]:
                    self._connection.execute("COMMIT")
                    return record.document(replayed=True)
                expires = now + self._retention_ns if state.terminal else record.expires_at_ns
                self._connection.execute(
                    "UPDATE operations SET state=?, result=?, updated_at_ns=?, expires_at_ns=? WHERE namespace_id=? AND run_id=? AND operation_key=?",
                    (state.value, result, now, expires, self._namespace_id, run_id, operation_key),
                )
                if state.terminal:
                    # Manual/test terminal publication must not leave a queue
                    # row capable of redispatching the same operation.
                    self._connection.execute(
                        "DELETE FROM operation_queue WHERE namespace_id=? AND run_id=? AND operation_key=?",
                        (self._namespace_id, run_id, operation_key),
                    )
                self._counters["transition"] += 1
                updated = self._select(run_id, operation_key)
                assert updated is not None
                self._connection.execute("COMMIT")
                return updated.document(replayed=False)
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def metrics(self) -> dict[str, str]:
        with self._lock:
            counts = dict(self._connection.execute("SELECT state, COUNT(*) FROM operations GROUP BY state").fetchall())
            queue = self._connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(attempts), 0), COALESCE(SUM(lease_token IS NOT NULL), 0) FROM operation_queue"
            ).fetchone()
            return {
                "adapter_schema_version": str(ENDPOINT_RECORD_SCHEMA_VERSION),
                "contract_version": str(ENDPOINT_HTTP_CONTRACT_VERSION),
                "authority_id": self._authority_id,
                "namespace_id": self._namespace_id,
                "catalog_digest": self._catalog_digest,
                "retention_ns": str(self._retention_ns),
                **{f"operations_{state}": str(counts.get(state, 0)) for state in OperationState},
                "queue_queued": str(queue[0]),
                "queue_attempts": str(queue[1]),
                "queue_leased": str(queue[2]),
                **{f"requests_{name}": str(value) for name, value in self._counters.items()},
            }

    def close(self) -> None:
        self._connection.close()


class Endpoint(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], store: Store, fault_after_response_commit_once: bool,
                 *, provider_database: Path | None = None, start_worker: bool = False,
                 provider_fault_after_apply_once: bool = False) -> None:
        super().__init__(address, Handler)
        self.store = store
        self.fault_after_response_commit_once = fault_after_response_commit_once
        self._fault_lock = threading.Lock()
        self.provider = ProviderStore(
            provider_database or store.database.with_suffix(".provider.sqlite"),
            fault_after_apply_once=provider_fault_after_apply_once,
        )
        self.worker = AsyncWorker(store, self.provider, worker_id="endpoint-worker")
        self._async_closed = False
        if start_worker:
            self.worker.start()

    def take_lost_response_fault(self) -> bool:
        with self._fault_lock:
            if not self.fault_after_response_commit_once:
                return False
            self.fault_after_response_commit_once = False
            return True

    def close_async(self) -> None:
        if self._async_closed:
            return
        if not self.worker.stop():
            raise RuntimeError("async worker did not stop before provider close")
        self.provider.close()
        self._async_closed = True

    def server_close(self) -> None:
        self.close_async()
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server: Endpoint
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, status: int, document: dict[str, str]) -> None:
        data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _bad(self, message: str) -> None:
        self._json(HTTPStatus.BAD_REQUEST, {"error": message})

    def _document(self, *, v2: bool) -> tuple[str, str, str, bytes] | None:
        length = self.headers.get("Content-Length")
        try:
            size = int(length) if length is not None else -1
        except ValueError:
            size = -1
        if not 0 <= size <= MAX_PAYLOAD_BYTES * 2 + 1024:
            self._bad("invalid_content_length")
            return None
        try:
            document = json.loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(document, dict):
                raise ValueError("request is not an object")
            # V1 remains an explicitly delimited compatibility contract for
            # focused host tests. Real QEMU rows use the strict v2 branch;
            # unknown extension fields are never silently ignored.
            legacy_fields = {"run_id", "operation_key", "payload_digest", "payload_b64"}
            v2_fields = {"contract_version", "namespace_id", "authority_id", "effect_id",
                         "run_id", "operation_key", "input_digest", "catalog_digest", "payload_b64"}
            fields = set(document)
            if not v2 and fields == legacy_fields:
                pass
            elif v2 and fields == v2_fields and document["contract_version"] == str(ENDPOINT_HTTP_CONTRACT_VERSION):
                if (document["namespace_id"], document["authority_id"], document["effect_id"],
                    document["catalog_digest"]) != (self.server.store.namespace_id,
                    self.server.store.authority_id, self.server.store.effect_id,
                    self.server.store.catalog_digest):
                    raise ValueError("v2 identity does not match durable endpoint contract")
            else:
                raise ValueError("unsupported endpoint request contract")
            run_id = document["run_id"]
            operation_key = document["operation_key"]
            input_digest = document["input_digest"] if fields == v2_fields else document["payload_digest"]
            encoded_payload = document["payload_b64"]
            payload = b"" if encoded_payload == "-" else base64.b64decode(encoded_payload.encode("ascii"), validate=True)
        except (AttributeError, KeyError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
            self._bad("invalid_request")
            return None
        try:
            validate_run_id(run_id)
        except (ProtocolError, TypeError):
            self._bad("invalid_identifier")
            return None
        if not _valid_id(operation_key) or not _valid_digest(input_digest):
            self._bad("invalid_identifier")
            return None
        if len(payload) > MAX_PAYLOAD_BYTES or digest(payload) != input_digest:
            self._bad("payload_digest_mismatch")
            return None
        return run_id, operation_key, input_digest, payload

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/v1/operations", "/v2/operations"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        values = self._document(v2=self.path == "/v2/operations")
        if values is None:
            return
        # v1 remains an explicit synchronous compatibility endpoint used by
        # isolated legacy tests. v2 is the real asynchronous CSER contract.
        status, record = self.server.store.enqueue(*values) if self.path == "/v2/operations" else self.server.store.submit(*values)
        # The client can lose either the durable v2 acceptance response or a
        # v1 terminal response; recovery always queries this exact key.
        if status < 300 and self.server.take_lost_response_fault():
            self.close_connection = True
            return
        self._json(status, record)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/metrics":
            self._json(HTTPStatus.OK, self.server.store.metrics() | self.server.provider.metrics())
            return
        prefix = "/v1/operations/"
        v2_prefix = "/v2/operations/"
        if not self.path.startswith(prefix) and not self.path.startswith(v2_prefix):
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        v2 = self.path.startswith(v2_prefix)
        parts = self.path[len(v2_prefix if v2 else prefix):].split("/")
        if v2:
            # v2 path is exactly namespace/authority/effect/run/operation/input/catalog.
            # Validate before slicing so a short or surplus path can never be
            # accidentally reinterpreted as a different key.
            if len(parts) != 7:
                self._bad("invalid_identifier")
                return
            namespace, authority, effect, run_id, operation_key, input_digest, catalog_digest = parts
            if (namespace, authority, effect, catalog_digest) != (
                self.server.store.namespace_id, self.server.store.authority_id,
                self.server.store.effect_id, self.server.store.catalog_digest,
            ):
                self._bad("invalid_identifier")
                return
            parts = [run_id, operation_key, input_digest]
        try:
            valid_run = len(parts) == (3 if v2 else 2) and validate_run_id(parts[0])
        except (ProtocolError, TypeError):
            valid_run = False
        if not valid_run or not _valid_id(parts[1]) or (v2 and not _valid_digest(parts[2])):
            self._bad("invalid_identifier")
            return
        if v2:
            # The input digest is part of the query identity; a mismatch is a
            # rejected request, never an apparent absence that could authorize retry.
            current = self.server.store.get(parts[0], parts[1])
            if current is not None and current["input_digest"] != parts[2]:
                self._json(HTTPStatus.CONFLICT, {"error": "operation_key_input_conflict"})
                return
            result = current
        else:
            result = self.server.store.get(parts[0], parts[1])
        if result is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        state = OperationState(result["state"])
        self._json(
            HTTPStatus.OK if state == OperationState.SUCCEEDED
            else HTTPStatus.ACCEPTED if state in (OperationState.ACCEPTED, OperationState.PENDING)
            else HTTPStatus.CONFLICT if state == OperationState.FAILED
            else HTTPStatus.GONE,
            result,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--port-file", type=Path)
    parser.add_argument("--namespace", default=_DEFAULT_NAMESPACE)
    parser.add_argument("--catalog-digest", default=_DEFAULT_CATALOG_DIGEST)
    parser.add_argument("--authority-id", default=None)
    parser.add_argument("--effect-id", default=None)
    parser.add_argument("--retention-seconds", default=24 * 60 * 60, type=int)
    parser.add_argument("--fault-after-response-commit-once", action="store_true",
                        help="commit an adapter record, then drop one client response")
    parser.add_argument("--provider-fault-after-apply-once", action="store_true",
                        help="durably apply once in the provider, then leave the adapter Pending")
    parser.add_argument("--provider-database", type=Path)
    args = parser.parse_args()
    endpoint = Endpoint(
        (args.host, args.port),
        Store(args.database, namespace_id=args.namespace, catalog_digest=args.catalog_digest, authority_id=args.authority_id, effect_id=args.effect_id, retention_seconds=args.retention_seconds),
        args.fault_after_response_commit_once, provider_database=args.provider_database, start_worker=True,
        provider_fault_after_apply_once=args.provider_fault_after_apply_once,
    )
    if args.port_file is not None:
        args.port_file.write_text(f"{endpoint.server_port}\n", encoding="ascii")
    try:
        endpoint.serve_forever()
    finally:
        endpoint.server_close()
        endpoint.close_async()
        endpoint.store.close()


if __name__ == "__main__":
    main()
