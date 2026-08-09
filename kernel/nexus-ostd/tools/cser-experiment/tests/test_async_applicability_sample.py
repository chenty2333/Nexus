from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from applicability_trace import EventKind, SourceAvailability, StudyPseudonymizer, aggregate, aggregate_raw_trace, load_published_trace, load_raw_trace, load_trace
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

    def test_optional_raw_traces_are_external_and_match_sanitized_sample(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = run_sample(root / "sample", study_id="bounded_async_test", key=b"k" * 32,
                                raw_trace_dir=root / "local-raw")
            assert result.raw_endpoint_trace is not None
            assert result.raw_worker_provider_trace is not None
            published = load_trace([result.endpoint_trace, result.worker_provider_trace])
            pseudonymizer = StudyPseudonymizer("bounded_async_test", b"k" * 32)
            retained = load_raw_trace([result.raw_endpoint_trace, result.raw_worker_provider_trace], pseudonymizer)
            self.assertEqual(aggregate_raw_trace(retained, pseudonymizer), aggregate(published))
            self.assertIn("bounded-async-sample", result.raw_endpoint_trace.read_text(encoding="utf-8"))
            self.assertNotIn("bounded-async-sample", result.endpoint_trace.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "outside"):
                run_sample(root / "nested", study_id="bounded_async_test", key=b"k" * 32,
                           raw_trace_dir=root / "nested" / "raw")

    def test_workflow_failure_exitstack_aborts_raw_traces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "sample"
            raw = root / "local-raw"
            with mock.patch("async_applicability_sample.AsyncWorker.run_once", side_effect=RuntimeError("worker failed")):
                with self.assertRaisesRegex(RuntimeError, "worker failed"):
                    run_sample(output, study_id="bounded_async_test", key=b"k" * 32,
                               raw_trace_dir=raw)
            for name in ("endpoint.jsonl", "worker_provider.jsonl"):
                trace = output / name
                self.assertFalse(trace.exists())
                marker = json.loads(trace.with_name(trace.name + ".publication.json").read_text())
                self.assertEqual(marker["state"], "incomplete")
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    load_published_trace([trace])

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
