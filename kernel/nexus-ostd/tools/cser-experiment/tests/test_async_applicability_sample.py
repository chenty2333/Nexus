from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from applicability_trace import EventKind, SourceAvailability, load_trace
from async_applicability_sample import run_sample
from tool_endpoint import Store
from tool_provider import ProviderStore
from tool_worker import AsyncWorker


class AsyncApplicabilitySampleTests(unittest.TestCase):
    def test_controlled_sample_exports_real_recovery_and_explicit_missing_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sample"
            result = run_sample(output, study_id="bounded_async_test", key=b"k" * 32)
            endpoint_events = load_trace([result.endpoint_trace])
            worker_events = load_trace([result.worker_provider_trace])
            aggregate = json.loads(result.aggregate_path.read_text(encoding="utf-8"))

            endpoint_facts = [event for event in endpoint_events if event["event_type"] == "effect_observation"]
            worker_facts = [event for event in worker_events if event["event_type"] == "effect_observation"]
            self.assertEqual([event["event_kind"] for event in endpoint_facts],
                             [EventKind.ACCEPTED.value, EventKind.TERMINAL.value])
            self.assertEqual(worker_facts[0]["reason_code"], "worker_pending_durable")
            self.assertIn("provider_exact_key_query_absent", [event["reason_code"] for event in worker_facts])
            self.assertIn("provider_exact_key_apply_durable", [event["reason_code"] for event in worker_facts])
            self.assertEqual(worker_facts[-1]["reason_code"], "worker_terminal_durable")
            self.assertTrue(all(not event["right_censored"] for event in endpoint_facts + worker_facts))
            statuses = {event["source_id"]: event["source_availability"] for event in endpoint_events
                        if event["event_type"] == "source_status"}
            self.assertEqual(statuses["device"], SourceAvailability.MISSING.value)
            self.assertEqual(statuses["allocator_gate"], SourceAvailability.MISSING.value)
            self.assertEqual(aggregate["missing_sources"], ["allocator_gate", "device", "guest"])
            self.assertEqual(aggregate["final_quiescence"]["observed_effects"], 0)
            self.assertEqual(aggregate["final_gates"]["final_resource_coordinates"], 0)
            self.assertEqual(aggregate["controlled_execution"]["provider_exact_key_table"], "existing_coordinator")

    def test_refuses_to_mix_an_existing_sample_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sample"
            run_sample(output, study_id="bounded_async_test", key=b"k" * 32)
            with self.assertRaises(ValueError):
                run_sample(output, study_id="bounded_async_test", key=b"k" * 32)

    def test_refuses_existing_state_and_observer_failures_cannot_change_durable_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            (state / "preexisting").write_text("not a sample state", encoding="utf-8")
            with self.assertRaises(ValueError):
                run_sample(root / "output", study_id="bounded_async_test", key=b"k" * 32, state_dir=state)

            adapter = Store(root / "adapter.sqlite", catalog_digest="a" * 64)
            provider = ProviderStore(root / "provider.sqlite", observer=lambda *_: (_ for _ in ()).throw(RuntimeError("sink")))
            try:
                payload = b"observer failure does not alter outcome"
                adapter.enqueue("0123456789abcdef0123456789abcdef", "observer", hashlib.sha256(payload).hexdigest(), payload)
                worker = AsyncWorker(adapter, provider, worker_id="observer-worker",
                                     observer=lambda *_: (_ for _ in ()).throw(RuntimeError("sink")))
                self.assertTrue(worker.run_once())
                record = adapter.get("0123456789abcdef0123456789abcdef", "observer")
                assert record is not None
                self.assertEqual(record["state"], "succeeded")
                self.assertGreaterEqual(int(provider.metrics()["provider_telemetry_dropped"]), 2)
                self.assertEqual(worker.telemetry_dropped, 2)
            finally:
                provider.close()
                adapter.close()


if __name__ == "__main__":
    unittest.main()
