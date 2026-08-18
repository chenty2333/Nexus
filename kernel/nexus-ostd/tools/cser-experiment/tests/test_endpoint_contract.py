from __future__ import annotations

import hashlib
import http.client
import json
import gc
import sqlite3
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from base64 import b64encode
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol import (ENDPOINT_HTTP_CONTRACT_VERSION, LEGACY_V2_HTTP_CONTRACT_VERSION,
                      evidence_record_digest, evidence_record_digest_v3)
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
            self.assertEqual(record["record_schema_version"], "3")
            self.assertEqual(record["namespace_id"], "local-tool")
            self.assertEqual(record["catalog_digest"], CATALOG)
            self.assertEqual(record["state"], "succeeded")
            self.assertEqual(
                record["evidence_record_digest"],
                evidence_record_digest_v3(
                    record["namespace_id"], record["authority_id"], record["effect_id"],
                    record["run_id"], record["operation_key"], record["input_digest"],
                    record["catalog_digest"], record["state"], record["result"], "none", b"",
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

    def test_v2_rows_keep_v2_evidence_after_v3_storage_migration(self) -> None:
        """A schema upgrade may add columns but may not rewrite evidence facts."""
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "old-v2.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            _, created = self.submit(store, key="old-v2")
            store._connection.execute("UPDATE adapter_metadata SET value='2' WHERE key='schema_version'")
            store._connection.execute("UPDATE operations SET record_schema_version=2 WHERE operation_key='old-v2'")
            store._connection.commit()
            store.close()

            reopened = Store(database, catalog_digest=CATALOG)
            row = reopened._connection.execute(
                "SELECT record_schema_version FROM operations WHERE operation_key='old-v2'"
            ).fetchone()
            self.assertEqual(row[0], 2)
            # Its legacy view remains independently verifiable, while a v3
            # evidence digest is deliberately unavailable.
            legacy = reopened._select(RUN, "old-v2")
            assert legacy is not None
            self.assertEqual(legacy.legacy_evidence_digest(), evidence_record_digest(
                legacy.namespace_id, legacy.authority_id, legacy.effect_id, legacy.run_id,
                legacy.operation_key, legacy.input_digest, legacy.catalog_digest, 2,
                legacy.state.value, legacy.result,
            ))
            self.assertEqual(legacy.evidence_digest(), "-")
            reopened.close()

    def test_v2_http_contract_rejects_unknown_fields_and_lost_reply_remains_queryable_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "endpoint.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            server = Endpoint(("127.0.0.1", 0), store, True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            payload = b"crash-window"
            body = {
                "contract_version": str(LEGACY_V2_HTTP_CONTRACT_VERSION),
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
            self.assertEqual(recovered["state"], "accepted")
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
            v3_body = dict(body)
            v3_body["contract_version"] = "2"
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("POST", "/v3/operations", json.dumps(v3_body), {"Content-Type": "application/json"})
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()
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

    def test_store_direct_calls_validate_identity_digest_and_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "direct.sqlite", catalog_digest=CATALOG)
            payload = b"direct-validation"
            payload_digest = hashlib.sha256(payload).hexdigest()
            with self.assertRaisesRegex(ValueError, "run id"):
                store.submit("not-a-run", "op", payload_digest, payload)
            with self.assertRaisesRegex(ValueError, "operation key"):
                store.enqueue(RUN, "", payload_digest, payload)
            with self.assertRaisesRegex(ValueError, "input digest"):
                store.submit(RUN, "bad-digest", "f" * 63, payload)
            with self.assertRaisesRegex(ValueError, "payload digest"):
                store.enqueue(RUN, "mismatch", "0" * 64, payload)
            with self.assertRaisesRegex(ValueError, "invalid transition"):
                store.transition(RUN, "missing", "pending", "working")  # type: ignore[arg-type]
            store.close()

    def test_store_rejects_corrupt_rows_and_queue_lease_pairs_at_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b"durable-corruption"
            payload_digest = hashlib.sha256(payload).hexdigest()

            database = root / "payload.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            store.enqueue(RUN, "payload-row", payload_digest, payload)
            store.close()
            connection = sqlite3.connect(database)
            connection.execute("UPDATE operations SET payload=? WHERE operation_key='payload-row'", (b"tampered",))
            connection.commit(); connection.close()
            with self.assertRaisesRegex(ValueError, "payload digest"):
                Store(database, catalog_digest=CATALOG)

            database = root / "queue.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            store.enqueue(RUN, "queue-row", payload_digest, payload)
            store.close()
            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE operation_queue SET lease_token=? WHERE operation_key='queue-row'",
                ("a" * 32,),
            )
            connection.commit(); connection.close()
            with self.assertRaisesRegex(ValueError, "lease token/deadline"):
                Store(database, catalog_digest=CATALOG)

            database = root / "timestamps.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            self.submit(store, key="timestamp-row")
            store.close()
            connection = sqlite3.connect(database)
            connection.execute("UPDATE operations SET updated_at_ns=-1 WHERE operation_key='timestamp-row'")
            connection.commit(); connection.close()
            with self.assertRaisesRegex(ValueError, "updated timestamp"):
                Store(database, catalog_digest=CATALOG)

            database = root / "metadata.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            store.close()
            connection = sqlite3.connect(database)
            connection.execute("ALTER TABLE adapter_metadata ADD COLUMN unexpected TEXT")
            connection.commit(); connection.close()
            with self.assertRaisesRegex(ValueError, "adapter_metadata schema"):
                Store(database, catalog_digest=CATALOG)

    def test_complete_lease_requires_provider_time_between_pending_and_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "timestamps.sqlite", catalog_digest=CATALOG)
            payload = b"provider-time"
            digest = hashlib.sha256(payload).hexdigest()
            store.enqueue(RUN, "provider-time", digest, payload)
            item = store.claim_next("worker", 60.0)
            assert item is not None
            pending = int(store.get(RUN, "provider-time")["pending_at_ns"])  # type: ignore[index]
            with self.assertRaisesRegex(ValueError, "provider timestamp"):
                store.complete_lease(item, "succeeded", "success", provider_applied_at_ns=pending - 1)
            with self.assertRaisesRegex(ValueError, "timestamp"):
                store.complete_lease(item, "succeeded", "success", provider_applied_at_ns=(1 << 63) - 1)
            current = store.get(RUN, "provider-time")
            assert current is not None
            self.assertEqual(current["state"], "pending")
            self.assertTrue(store.complete_lease(item, "succeeded", "success"))
            store.close()

    def test_hostname_is_resolved_once_to_the_validated_numeric_loopback_address(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "dns.sqlite", catalog_digest=CATALOG)
            info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
            with mock.patch("tool_endpoint.socket.getaddrinfo", return_value=info) as resolve:
                endpoint = Endpoint(("loopback.test", 0), store, False)
            self.assertEqual(endpoint.server_address[0], "127.0.0.1")
            self.assertEqual(resolve.call_count, 1)
            endpoint.server_close(); store.close()

    def test_bind_failure_preserves_oserror_and_closes_owned_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "bind-error.sqlite", catalog_digest=CATALOG)
            bind_error = OSError("exact bind failure")
            with mock.patch("tool_endpoint.HTTPServer.server_bind", side_effect=bind_error):
                with self.assertRaises(OSError) as raised:
                    Endpoint(("127.0.0.1", 0), store, False)
            self.assertIs(raised.exception, bind_error)
            self.assertTrue(store._closed)

    def test_nonlocal_bind_requires_explicit_cli_danger_switch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "bind.sqlite"
            result = subprocess.run(
                [
                    sys.executable, str(ROOT / "tool_endpoint.py"),
                    "--database", str(database), "--host", "0.0.0.0", "--port", "0",
                ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("non-loopback", result.stderr)
            self.assertFalse(database.exists())

            store = Store(database, catalog_digest=CATALOG)
            with self.assertRaisesRegex(ValueError, "non-loopback"):
                Endpoint(("0.0.0.0", 0), store, False)
            store.close()

    def test_shutdown_timeout_keeps_provider_open_until_inflight_handler_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "shutdown.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            endpoint = Endpoint(
                ("127.0.0.1", 0), store, False,
                provider_database=Path(temp) / "provider.sqlite",
                start_worker=False, shutdown_timeout_seconds=0.05,
            )
            serving = threading.Thread(target=endpoint.serve_forever, daemon=True)
            serving.start()
            entered = threading.Event()
            release = threading.Event()
            original_submit = store.submit

            def blocking_submit(*args: object, **kwargs: object) -> tuple[int, dict[str, str]]:
                entered.set()
                release.wait(2)
                return original_submit(*args, **kwargs)

            store.submit = blocking_submit  # type: ignore[method-assign]
            response: list[int] = []

            def post() -> None:
                connection = http.client.HTTPConnection("127.0.0.1", endpoint.server_port, timeout=5)
                try:
                    payload = b"shutdown-inflight"
                    body = json.dumps({
                        "run_id": RUN,
                        "operation_key": "shutdown",
                        "payload_digest": hashlib.sha256(payload).hexdigest(),
                        "payload_b64": b64encode(payload).decode("ascii"),
                    })
                    connection.request("POST", "/v1/operations", body, {"Content-Type": "application/json"})
                    reply = connection.getresponse()
                    response.append(reply.status)
                    reply.read()
                finally:
                    connection.close()

            request_thread = threading.Thread(target=post, daemon=True)
            request_thread.start()
            self.assertTrue(entered.wait(2))
            with self.assertRaisesRegex(RuntimeError, "handler did not stop"):
                endpoint.shutdown()
            self.assertFalse(endpoint._async_closed)
            # A failed stop must not close the provider while a handler can
            # still reach the Store/provider dependency graph.
            self.assertIn("provider_query", endpoint.provider.metrics())
            release.set()
            request_thread.join(timeout=5)
            self.assertEqual(response, [201])
            endpoint.server_close()
            serving.join(timeout=5)
            store.close()

    def test_worker_stop_timeout_fails_closed_before_provider_close(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "worker-shutdown.sqlite", catalog_digest=CATALOG)
            endpoint = Endpoint(
                ("127.0.0.1", 0), store, False,
                provider_database=Path(temp) / "provider.sqlite", start_worker=False,
            )
            serving = threading.Thread(target=endpoint.serve_forever, daemon=True)
            serving.start()
            endpoint.worker.stop = lambda: False  # type: ignore[method-assign]
            with self.assertRaisesRegex(RuntimeError, "worker did not stop"):
                endpoint.shutdown()
            self.assertFalse(endpoint._async_closed)
            self.assertIn("provider_query", endpoint.provider.metrics())
            endpoint.worker.stop = lambda: True  # type: ignore[method-assign]
            endpoint.server_close()
            serving.join(timeout=5)
            store.close()


if __name__ == "__main__":
    unittest.main()
