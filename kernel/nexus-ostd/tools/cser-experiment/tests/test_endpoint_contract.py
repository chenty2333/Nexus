from __future__ import annotations

import hashlib
import http.client
import json
import gc
import sqlite3
import sys
import tempfile
import threading
import unittest
import warnings
from base64 import b64encode
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol import ENDPOINT_HTTP_CONTRACT_VERSION, evidence_record_digest
from tool_endpoint import Endpoint, OperationState, Store


RUN = "0123456789abcdef0123456789abcdef"
CATALOG = "a" * 64


class EndpointContractTests(unittest.TestCase):
    def submit(self, store: Store, key: str = "op-1", payload: bytes = b"payload", **kwargs: object) -> tuple[int, dict[str, str]]:
        return store.submit(RUN, key, hashlib.sha256(payload).hexdigest(), payload, **kwargs)

    def test_v2_record_binds_full_durable_identity_and_authority_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "evidence.sqlite"
            store = Store(database, namespace_id="local-tool", catalog_digest=CATALOG)
            status, record = self.submit(store)
            self.assertEqual(status, 201)
            self.assertEqual(record["contract_version"], str(ENDPOINT_HTTP_CONTRACT_VERSION))
            self.assertEqual(record["record_schema_version"], "2")
            self.assertEqual(record["namespace_id"], "local-tool")
            self.assertEqual(record["catalog_digest"], CATALOG)
            self.assertEqual(record["state"], "succeeded")
            self.assertEqual(
                record["evidence_record_digest"],
                evidence_record_digest(
                    record["namespace_id"], record["authority_id"], record["effect_id"],
                    record["run_id"], record["operation_key"], record["input_digest"],
                    record["catalog_digest"], int(record["record_schema_version"]),
                    record["state"], record["result"],
                ),
            )
            authority, effect, evidence = record["authority_id"], record["effect_id"], record["evidence_record_digest"]
            store.close()
            reopened = Store(database, namespace_id="local-tool", catalog_digest=CATALOG)
            recovered = reopened.get(RUN, "op-1")
            assert recovered is not None
            self.assertEqual((reopened.authority_id, recovered["authority_id"], recovered["effect_id"], recovered["evidence_record_digest"]), (authority, authority, effect, evidence))
            reopened.close()

    def test_monotonic_states_and_expiry_are_never_reclassified_as_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "evidence.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            _, accepted = self.submit(store, initial_state=OperationState.ACCEPTED, result="queued")
            self.assertEqual(accepted["state"], "accepted")
            pending = store.transition(RUN, "op-1", OperationState.PENDING, "working")
            assert pending is not None
            self.assertEqual(pending["state"], "pending")
            self.assertEqual(pending["evidence_record_digest"], "-")

            # Pending is durable recovery state, not terminal evidence.  A
            # cold sidecar restart must preserve it rather than reinterpret it
            # as absence, success, or retry authority.
            authority = store.authority_id
            store.close()
            store = Store(database, catalog_digest=CATALOG)
            recovered_pending = store.get(RUN, "op-1")
            assert recovered_pending is not None
            self.assertEqual(store.authority_id, authority)
            self.assertEqual(recovered_pending["state"], "pending")
            self.assertEqual(recovered_pending["evidence_record_digest"], "-")

            # Pending cannot return to accepted: the transition is a no-op,
            # not a reinterpretation of the evidence history.
            self.assertEqual(store.transition(RUN, "op-1", OperationState.ACCEPTED, "queued")["state"], "pending")
            succeeded = store.transition(RUN, "op-1", OperationState.SUCCEEDED, "success")
            assert succeeded is not None
            self.assertEqual(succeeded["state"], "succeeded")
            store._connection.execute("UPDATE operations SET expires_at_ns=0")
            expired = store.get(RUN, "op-1")
            assert expired is not None
            self.assertEqual(expired["state"], "expired")
            status, duplicate = self.submit(store)
            self.assertEqual(status, 410)
            self.assertEqual(duplicate["state"], "expired")
            store.close()

    def test_injected_precommit_failure_leaves_no_retry_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "evidence.sqlite", catalog_digest=CATALOG, fault_before_commit_once=True)
            with self.assertRaises(RuntimeError):
                self.submit(store, key="precommit")
            self.assertIsNone(store.get(RUN, "precommit"))
            # The next submit has the same identity but is a new first durable
            # commit, not a replay of an uncommitted local action.
            status, record = self.submit(store, key="precommit")
            self.assertEqual((status, record["state"]), (201, "succeeded"))
            store.close()

    def test_legacy_migration_retains_a_fail_closed_tombstone_and_newer_schema_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "legacy.sqlite"
            connection = sqlite3.connect(database)
            connection.execute(
                """CREATE TABLE operations (
                    run_id TEXT NOT NULL, operation_key TEXT NOT NULL, payload_digest TEXT NOT NULL,
                    payload BLOB NOT NULL, status TEXT NOT NULL, result TEXT NOT NULL,
                    PRIMARY KEY(run_id, operation_key))"""
            )
            connection.execute("INSERT INTO operations VALUES (?, ?, ?, ?, 'applied', 'success')", (RUN, "old", hashlib.sha256(b"old").hexdigest(), b"old"))
            connection.commit(); connection.close()
            store = Store(database, catalog_digest=CATALOG)
            migrated = store.get(RUN, "old")
            assert migrated is not None
            self.assertEqual(migrated["state"], "expired")
            store.close()
            connection = sqlite3.connect(database)
            connection.execute("PRAGMA user_version=99")
            connection.commit(); connection.close()
            with self.assertRaises(ValueError):
                Store(database, catalog_digest=CATALOG)
            unknown = Path(temp) / "unknown.sqlite"
            connection = sqlite3.connect(unknown)
            connection.execute(
                """CREATE TABLE operations (
                    run_id TEXT, operation_key TEXT, payload_digest TEXT, payload BLOB,
                    status TEXT, result TEXT, unknown_column TEXT)"""
            )
            connection.commit(); connection.close()
            with self.assertRaises(ValueError):
                Store(unknown, catalog_digest=CATALOG)
            corrupt = Path(temp) / "corrupt.sqlite"
            corrupt.write_bytes(b"not a sqlite database")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                with self.assertRaises(sqlite3.DatabaseError):
                    Store(corrupt, catalog_digest=CATALOG)
                gc.collect()
            self.assertFalse(any(item.category is ResourceWarning for item in caught))

    def test_v2_http_contract_rejects_unknown_fields_and_lost_reply_remains_queryable_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "endpoint.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            server = Endpoint(("127.0.0.1", 0), store, True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            payload = b"crash-window"
            body = {
                "contract_version": str(ENDPOINT_HTTP_CONTRACT_VERSION),
                "namespace_id": store.namespace_id,
                "authority_id": store.authority_id,
                "effect_id": store.effect_id,
                "run_id": RUN,
                "operation_key": "op-lost-reply",
                "input_digest": hashlib.sha256(payload).hexdigest(),
                "catalog_digest": store.catalog_digest,
                "payload_b64": b64encode(payload).decode(),
            }
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("POST", "/v2/operations", json.dumps(body), {"Content-Type": "application/json"})
            with self.assertRaises(http.client.RemoteDisconnected):
                connection.getresponse()
            connection.close()
            server.shutdown(); server.server_close(); store.close(); thread.join(timeout=5)
            reopened = Store(database, catalog_digest=CATALOG)
            recovered = reopened.get(RUN, "op-lost-reply")
            assert recovered is not None
            self.assertEqual(recovered["state"], "succeeded")
            self.assertEqual(recovered["catalog_digest"], CATALOG)
            reopened.close()

            # Strict v2 parsing prevents a field from silently escaping the
            # evidence binding. Reopen with the durable identity selected by
            # the first server, as the real recovery launcher does.
            store = Store(database, catalog_digest=CATALOG)
            server = Endpoint(("127.0.0.1", 0), store, False)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            body.update({
                "namespace_id": store.namespace_id,
                "authority_id": store.authority_id,
                "effect_id": store.effect_id,
            })
            body["ignored"] = "not-permitted"
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("POST", "/v2/operations", json.dumps(body), {"Content-Type": "application/json"})
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()

            body.pop("ignored")
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("POST", "/v1/operations", json.dumps(body), {"Content-Type": "application/json"})
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()
            legacy_body = {
                "run_id": RUN,
                "operation_key": "legacy-on-v2",
                "payload_digest": hashlib.sha256(payload).hexdigest(),
                "payload_b64": b64encode(payload).decode(),
            }
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("POST", "/v2/operations", json.dumps(legacy_body), {"Content-Type": "application/json"})
            self.assertEqual(connection.getresponse().status, 400)
            connection.close(); server.shutdown(); server.server_close(); store.close(); thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
