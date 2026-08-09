from __future__ import annotations

import hashlib
import http.client
import json
import sqlite3
import sys
import tempfile
import time
import unittest
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol import ENDPOINT_HTTP_CONTRACT_VERSION
from tool_endpoint import Endpoint, OperationState, Store
from tool_provider import ProviderStore
from tool_worker import AsyncWorker


RUN = "0123456789abcdef0123456789abcdef"
CATALOG = "a" * 64


class AsyncEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.adapter_db = root / "adapter.sqlite"
        self.provider_db = root / "provider.sqlite"
        self.store = Store(self.adapter_db, catalog_digest=CATALOG)
        self.provider = ProviderStore(self.provider_db)

    def tearDown(self) -> None:
        self.provider.close()
        self.store.close()
        self.temp.cleanup()

    def enqueue(self, key: str = "op", payload: bytes = b"payload") -> tuple[int, dict[str, str]]:
        return self.store.enqueue(RUN, key, hashlib.sha256(payload).hexdigest(), payload)

    def test_enqueue_is_durable_nonterminal_and_terminal_retention_starts_only_on_completion(self) -> None:
        status, accepted = self.enqueue()
        self.assertEqual((status, accepted["state"], accepted["evidence_record_digest"]), (202, "accepted", "-"))
        self.assertEqual(accepted["expires_at_ns"], "0")
        self.store.close()
        self.store = Store(self.adapter_db, catalog_digest=CATALOG)
        recovered = self.store.get(RUN, "op")
        assert recovered is not None
        self.assertEqual((recovered["state"], recovered["expires_at_ns"]), ("accepted", "0"))
        worker = AsyncWorker(self.store, self.provider, worker_id="one")
        self.assertTrue(worker.run_once())
        terminal = self.store.get(RUN, "op")
        assert terminal is not None
        self.assertEqual((terminal["state"], terminal["result"]), ("succeeded", "success"))
        self.assertNotEqual(terminal["expires_at_ns"], "0")

    def test_provider_apply_before_adapter_terminal_recovers_by_query_without_second_apply(self) -> None:
        self.provider.close()
        self.provider = ProviderStore(self.provider_db, fault_after_apply_once=True)
        self.enqueue("cut")
        worker = AsyncWorker(self.store, self.provider, worker_id="first")
        self.assertTrue(worker.run_once())
        pending = self.store.get(RUN, "cut")
        assert pending is not None
        self.assertEqual(pending["state"], "pending")
        self.assertIsNotNone(self.provider.query(
            (self.store.namespace_id, self.store.authority_id, self.store.effect_id,
             self.store.catalog_digest, RUN, "cut"), hashlib.sha256(b"payload").hexdigest(),
        ))
        self.provider.close()
        self.provider = ProviderStore(self.provider_db)
        self.assertTrue(AsyncWorker(self.store, self.provider, worker_id="second").run_once())
        recovered = self.store.get(RUN, "cut")
        assert recovered is not None
        self.assertEqual((recovered["state"], recovered["result"]), ("succeeded", "success"))

    def test_verified_application_failure_is_terminal_but_infrastructure_failure_is_pending(self) -> None:
        self.enqueue("app", b"app-fail: controlled")
        AsyncWorker(self.store, self.provider, worker_id="app-worker").run_once()
        failed = self.store.get(RUN, "app")
        assert failed is not None
        self.assertEqual((failed["state"], failed["result"]), ("failed", "application_failed"))

    def test_provider_and_worker_restart_reconcile_exact_key_without_redispatch(self) -> None:
        self.enqueue("restart")
        first = AsyncWorker(self.store, self.provider, worker_id="first")
        self.assertTrue(first.run_once())
        self.provider.close()
        self.provider = ProviderStore(self.provider_db)
        # A fresh worker sees the durable provider outcome and makes the
        # adapter terminal without calling provider apply again.
        self.assertFalse(AsyncWorker(self.store, self.provider, worker_id="after-restart").run_once())
        terminal = self.store.get(RUN, "restart")
        assert terminal is not None
        self.assertEqual(terminal["state"], "succeeded")
        status, duplicate = self.enqueue("restart")
        self.assertEqual((status, duplicate["state"]), (HTTPStatus.OK, "succeeded"))

    def test_competing_workers_receive_one_lease_and_duplicate_enqueue_replays_exact_state(self) -> None:
        self.enqueue("race")
        with ThreadPoolExecutor(max_workers=8) as executor:
            claimed = list(executor.map(lambda n: self.store.claim_next(f"worker-{n}", 60.0), range(8)))
        winners = [item for item in claimed if item is not None]
        self.assertEqual(len(winners), 1)
        status, duplicate = self.enqueue("race")
        self.assertEqual((status, duplicate["state"]), (202, "pending"))
        assert winners[0] is not None
        self.assertTrue(self.store.complete_lease(winners[0], "succeeded", "success"))
        self.assertFalse(self.store.complete_lease(winners[0], "succeeded", "success"))

    def test_manual_terminal_transition_removes_queued_work_and_reports_queue_metrics(self) -> None:
        self.enqueue("manual")
        self.assertEqual(self.store.metrics()["queue_queued"], "1")
        terminal = self.store.transition(RUN, "manual", OperationState.SUCCEEDED, "success")
        assert terminal is not None
        self.assertEqual(terminal["state"], "succeeded")
        self.assertEqual(self.store.metrics()["queue_queued"], "0")
        self.assertIsNone(self.store.claim_next("later", 1.0))

    def test_old_v2_reopen_migrates_queue_marker_but_malformed_queue_fails_closed(self) -> None:
        self.store.close()
        connection = sqlite3.connect(self.adapter_db)
        connection.execute("DROP TABLE operation_queue")
        connection.execute("DELETE FROM adapter_metadata WHERE key='async_queue_schema_version'")
        connection.commit(); connection.close()
        self.store = Store(self.adapter_db, catalog_digest=CATALOG)
        self.assertEqual(
            self.store._connection.execute(
                "SELECT value FROM adapter_metadata WHERE key='async_queue_schema_version'"
            ).fetchone()[0],
            "1",
        )
        self.store.close()
        connection = sqlite3.connect(self.adapter_db)
        connection.execute("DROP TABLE operation_queue")
        connection.execute("CREATE TABLE operation_queue (namespace_id TEXT)")
        connection.commit(); connection.close()
        with self.assertRaises(ValueError):
            Store(self.adapter_db, catalog_digest=CATALOG)
        self.store = Store(Path(self.temp.name) / "replacement-adapter.sqlite", catalog_digest=CATALOG)

    def test_provider_outage_releases_lease_with_bounded_backoff_and_counts_it(self) -> None:
        self.enqueue("outage")
        self.provider.close()
        worker = AsyncWorker(self.store, self.provider, worker_id="outage-worker",
                             retry_backoff_min_seconds=0.001, retry_backoff_max_seconds=0.002)
        self.assertTrue(worker.run_once())
        pending = self.store.get(RUN, "outage")
        assert pending is not None
        self.assertEqual(pending["state"], "pending")
        metrics = self.store.metrics()
        self.assertEqual((metrics["queue_leased"], metrics["requests_infrastructure_retry"],
                          metrics["requests_infrastructure_backoff"]), ("0", "1", "1"))

    def test_provider_identity_is_catalog_bound_and_rejects_unknown_schema(self) -> None:
        identity = (self.store.namespace_id, self.store.authority_id, self.store.effect_id,
                    CATALOG, RUN, "catalog-bound")
        digest = hashlib.sha256(b"payload").hexdigest()
        self.provider.apply(identity, digest, b"payload")
        changed_catalog = (*identity[:3], "b" * 64, *identity[4:])
        self.assertIsNone(self.provider.query(changed_catalog, digest))
        self.assertEqual(self.provider.apply(changed_catalog, digest, b"payload").state, "succeeded")
        self.provider.close()
        self.provider = ProviderStore(self.provider_db)
        self.assertEqual(self.provider.metrics()["provider_applied"], "0")

        malformed = Path(self.temp.name) / "malformed-provider.sqlite"
        connection = sqlite3.connect(malformed)
        connection.execute("CREATE TABLE provider_operations (unknown TEXT)")
        connection.commit(); connection.close()
        with self.assertRaises(ValueError):
            ProviderStore(malformed)
        newer = Path(self.temp.name) / "newer-provider.sqlite"
        connection = sqlite3.connect(newer)
        connection.execute("PRAGMA user_version=2")
        connection.commit(); connection.close()
        with self.assertRaises(ValueError):
            ProviderStore(newer)
        corrupt = Path(self.temp.name) / "corrupt-provider.sqlite"
        corrupt.write_bytes(b"not sqlite")
        with self.assertRaises(sqlite3.DatabaseError):
            ProviderStore(corrupt)

    def test_v2_http_post_returns_202_before_worker_completion(self) -> None:
        endpoint = Endpoint(("127.0.0.1", 0), self.store, False, provider_database=self.provider_db, start_worker=False)
        # Endpoint owns a separate handle to the provider DB; this test's
        # direct provider handle is no longer needed.
        self.provider.close()
        self.provider = ProviderStore(self.provider_db)
        import threading
        thread = threading.Thread(target=endpoint.serve_forever, daemon=True)
        thread.start()
        try:
            payload = b"http"
            body = {
                "contract_version": str(ENDPOINT_HTTP_CONTRACT_VERSION),
                "namespace_id": self.store.namespace_id, "authority_id": self.store.authority_id,
                "effect_id": self.store.effect_id, "run_id": RUN, "operation_key": "http",
                "input_digest": hashlib.sha256(payload).hexdigest(), "catalog_digest": CATALOG,
                "payload_b64": b64encode(payload).decode(),
            }
            connection = http.client.HTTPConnection("127.0.0.1", endpoint.server_port)
            connection.request("POST", "/v2/operations", json.dumps(body), {"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(response.status, HTTPStatus.ACCEPTED)
            self.assertEqual(json.loads(response.read())["state"], "accepted")
            connection.close()
            accepted = self.store.get(RUN, "http")
            assert accepted is not None
            self.assertEqual(accepted["state"], "accepted")
            self.assertTrue(endpoint.worker.run_once())
            terminal = self.store.get(RUN, "http")
            assert terminal is not None
            self.assertEqual(terminal["state"], "succeeded")
        finally:
            endpoint.shutdown(); endpoint.server_close(); thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
