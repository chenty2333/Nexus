from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from summarize_performance import summarize
from matrix_controller import _write_stage_timings
from run_qemu_performance import _recovery_runtime_measurements, extract_trial
from tool_endpoint import Store
from tool_provider import ProviderStore
from tool_worker import AsyncWorker

RUN = "0123456789abcdef0123456789abcdef"
CATALOG = "a" * 64


class PerformanceLaneTests(unittest.TestCase):
    @staticmethod
    def _perf_line(*, journal: str = "legacy", phase: str = "terminal-recovery", run_id: str = RUN) -> str:
        fields = {
            "version": 1, "run_id": run_id, "phase": phase, "clock": "guest_tsc", "calibrated": False, "journal_format": journal,
            "runtime_transactions": 1, "mutex_wait_cycles": 2, "mutex_max_wait_cycles": 3,
            "mutex_hold_cycles": 4, "mutex_max_hold_cycles": 5, "journal_sectors_read": 6,
            "journal_sectors_written": 7, "journal_flushes": 8, "journal_hash_bytes": 9,
            "journal_image_bytes": 10, "journal_capacity_bytes": 11, "tpm_lease_advances": 12,
            "tpm_tip_advances": 13, "tpm_lease_cycles": 14, "tpm_tip_cycles": 15,
        }
        return "TOOL_DMA_PERF_V1 " + json.dumps(fields, sort_keys=True) + "\n"

    @staticmethod
    def _compaction_line(*, run_id: str = RUN) -> str:
        return "CSER_VNEXT_COMPACTION " + json.dumps({"version": 1, "run_id": run_id, "journal_format": "vnext", "phase": "recovery", "revision_before": 1, "head_before": "a" * 64, "revision_after": 2, "head_after": "b" * 64, "logical_bytes_before": 10, "logical_bytes_after": 5, "sectors_read_delta": 0, "sectors_written_delta": 4, "flushes_delta": 1}, sort_keys=True) + "\n"
    def test_timestamps_survive_restart_and_apply_precedes_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); store = Store(root / "adapter.sqlite", catalog_digest=CATALOG)
            provider = ProviderStore(root / "provider.sqlite", fault_after_apply_once=True)
            payload = b"timed"; store.enqueue(RUN, "timed", hashlib.sha256(payload).hexdigest(), payload)
            self.assertTrue(AsyncWorker(store, provider, worker_id="timed-worker").run_once())
            pending = store.get(RUN, "timed"); assert pending is not None
            self.assertEqual(pending["state"], "pending")
            identity = (store.namespace_id, store.authority_id, store.effect_id, CATALOG, RUN, "timed")
            applied = provider.query(identity, hashlib.sha256(payload).hexdigest()); assert applied is not None
            self.assertGreater(applied.applied_at_ns, 0)
            record = store.get(RUN, "timed"); assert record is not None
            self.assertGreater(int(record["accepted_at_ns"]), 0)
            self.assertGreaterEqual(int(record["pending_at_ns"]), int(record["accepted_at_ns"]))
            store.close(); provider.close()
            reopened = Store(root / "adapter.sqlite", catalog_digest=CATALOG)
            recovered_provider = ProviderStore(root / "provider.sqlite")
            self.assertTrue(AsyncWorker(reopened, recovered_provider, worker_id="restart-worker").run_once())
            recovered = reopened.get(RUN, "timed"); assert recovered is not None
            self.assertEqual(int(recovered["provider_applied_at_ns"]), applied.applied_at_ns)
            self.assertGreaterEqual(int(recovered["terminal_at_ns"]), int(recovered["provider_applied_at_ns"]))
            recovered_provider.close(); reopened.close()

    def test_delay_does_not_hold_provider_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provider = ProviderStore(Path(temporary) / "provider.sqlite", delay_ms=100)
            identity = ("trusted-local", "0" * 32, "1" * 32, CATALOG, RUN, "delay")
            digest = hashlib.sha256(b"payload").hexdigest()
            thread = threading.Thread(target=provider.apply, args=(identity, digest, b"payload"))
            thread.start(); time.sleep(.02)
            started = time.monotonic(); self.assertIsNone(provider.query(identity, digest))
            self.assertLess(time.monotonic() - started, .05)
            thread.join(); provider.close()

    def test_multiple_workers_preserve_one_exact_key_application(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); store = Store(root / "adapter.sqlite", catalog_digest=CATALOG)
            provider = ProviderStore(root / "provider.sqlite", delay_ms=20)
            payload = b"same"; store.enqueue(RUN, "same", hashlib.sha256(payload).hexdigest(), payload)
            workers = [AsyncWorker(store, provider, worker_id=f"worker-{index}") for index in range(4)]
            threads = [threading.Thread(target=worker.run_once) for worker in workers]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(provider.metrics()["provider_applied"], "1")
            self.assertEqual(store.get(RUN, "same")["state"], "succeeded")
            provider.close(); store.close()

    def test_percentile_schema_marks_small_samples_low_resolution(self) -> None:
        result = summarize([{"point": "control", "measurements": {"accepted_to_pending": {"value": value, "unit": "ms"}}} for value in (1, 2, 3)])
        group = result["groups"][0]
        self.assertEqual((group["n"], group["unit"], group["p50"], group["p95"], group["p95_resolution"]), (3, "ms", 2.0, 3.0, "low"))

    def test_trial_rows_produce_n_equal_to_requested_trials(self) -> None:
        result = summarize([
            {"point": "control", "trial": 1, "measurements": {"accepted_to_pending": {"value": 1, "unit": "ms"}, "max_inflight": {"value": 1, "unit": "count"}}},
            {"point": "control", "trial": 2, "measurements": {"accepted_to_pending": {"value": 2, "unit": "ms"}, "max_inflight": {"value": 1, "unit": "count"}}},
        ])
        self.assertTrue(all(group["n"] == 2 for group in result["groups"]))

    def test_v3_timing_migration_keeps_historical_boundaries_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "old.sqlite"
            store = Store(database, catalog_digest=CATALOG)
            payload = b"old"; store.submit(RUN, "old", hashlib.sha256(payload).hexdigest(), payload)
            store._connection.execute("ALTER TABLE operations DROP COLUMN terminal_at_ns")
            store._connection.execute("ALTER TABLE operations DROP COLUMN provider_applied_at_ns")
            store._connection.execute("ALTER TABLE operations DROP COLUMN pending_at_ns")
            store._connection.execute("ALTER TABLE operations DROP COLUMN accepted_at_ns")
            store._connection.execute("DELETE FROM adapter_metadata WHERE key IN ('performance_timing_schema_version', 'max_inflight')")
            store._connection.commit(); store.close()
            reopened = Store(database, catalog_digest=CATALOG)
            row = reopened._connection.execute("SELECT accepted_at_ns, pending_at_ns, provider_applied_at_ns, terminal_at_ns FROM operations WHERE operation_key='old'").fetchone()
            self.assertEqual(row, (0, 0, 0, 0))
            reopened.close()

    def test_extract_trial_reads_one_primary_artifact_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary); database = trial / "tool-endpoint.sqlite"
            store = Store(database, catalog_digest=CATALOG); provider = ProviderStore(trial / "provider.sqlite")
            payload = b"primary"; store.enqueue(RUN, "primary", hashlib.sha256(payload).hexdigest(), payload)
            AsyncWorker(store, provider, worker_id="one").run_once(); provider.close(); store.close()
            (trial / "stage-timings.json").write_text(
                '{"clock":"monotonic_ns","schema_version":1,"stages":{"initial_start_ns":100,"initial_end_ns":200,"recovery_start_ns":300,"recovery_end_ns":500}}\n', encoding="utf-8")
            (trial / "recovery.stdout.log").write_text(self._perf_line(), encoding="utf-8")
            row = extract_trial(trial, "control", 1, expected_run_id=RUN)
            self.assertEqual((row["trial"], row["operation_key"], row["measurements"]["max_inflight"]), (1, "primary", {"value": 1, "unit": "count"}))

    def test_controller_stage_artifact_is_explicit_monotonic_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _write_stage_timings(Path(temporary), {"initial_start_ns": 1, "initial_end_ns": 2})
            self.assertEqual(json.loads((Path(temporary) / "stage-timings.json").read_text()),
                             {"schema_version": 1, "clock": "monotonic_ns", "stages": {"initial_start_ns": 1, "initial_end_ns": 2}})

    def test_runtime_perf_parser_requires_exactly_one_well_formed_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary); log = trial / "recovery.stdout.log"
            log.write_text(self._perf_line(), encoding="utf-8")
            values = _recovery_runtime_measurements(trial, "legacy", RUN)
            self.assertEqual(values["guest_journal_hash_bytes"], {"value": 9, "unit": "bytes"})
            for contents in ("", self._perf_line() + self._perf_line(), "TOOL_DMA_PERF_V1 {bad}\n", self._perf_line(phase="terminal-initial"), self._perf_line(run_id="f" * 32)):
                log.write_text(contents, encoding="utf-8")
                with self.assertRaises(ValueError): _recovery_runtime_measurements(trial, "legacy", RUN)

    def test_runtime_perf_parser_enforces_format_and_vnext_compaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary); log = trial / "recovery.stdout.log"
            log.write_text(self._perf_line(journal="legacy"), encoding="utf-8")
            with self.assertRaises(ValueError): _recovery_runtime_measurements(trial, "vnext", RUN)
            log.write_text(self._perf_line(journal="vnext") + self._compaction_line(), encoding="utf-8")
            self.assertEqual(_recovery_runtime_measurements(trial, "vnext", RUN)["compaction_logical_bytes_after"], {"value": 5, "unit": "bytes"})
            self.assertEqual(_recovery_runtime_measurements(trial, "vnext", RUN)["compaction_sectors_written_delta"], {"value": 4, "unit": "count"})
            log.write_text(self._perf_line(journal="vnext") + self._compaction_line(run_id="e" * 32), encoding="utf-8")
            with self.assertRaises(ValueError): _recovery_runtime_measurements(trial, "vnext", RUN)
            log.write_text(self._perf_line() + self._compaction_line(), encoding="utf-8")
            with self.assertRaises(ValueError): _recovery_runtime_measurements(trial, "legacy", RUN)

    def test_runtime_parser_measurements_are_accepted_by_unit_aware_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary); (trial / "recovery.stdout.log").write_text(self._perf_line(), encoding="utf-8")
            result = summarize([{"point": "control", "measurements": _recovery_runtime_measurements(trial, "legacy", RUN)}])
            units = {group["unit"] for group in result["groups"]}
            self.assertTrue({"bytes", "count", "cycles"}.issubset(units))
