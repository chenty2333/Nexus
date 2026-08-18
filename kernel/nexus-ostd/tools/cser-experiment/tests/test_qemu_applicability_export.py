from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from applicability_trace import StudyPseudonymizer, aggregate, aggregate_raw_trace, load_raw_trace, load_trace
from qemu_applicability_export import _operation_hint, _row_value, export_trial


class QemuApplicabilityExportTests(unittest.TestCase):
    @staticmethod
    def _terminal(identity: dict[str, str], **extra: object) -> str:
        receipt = {
            "variant": "cser", "run_id": identity["run_id"], "terminal": True,
            "invariants_ok": True, "retired_by_evidence": 2, "retained_claims": 0,
            "reconciliation_delay_ms": None, "gate_rejections": None,
            "reconciliation_steps": 1, "reconciliation_delay_unit": "unmeasured",
        }
        receipt.update(extra)
        return "TOOL_DMA_RECOVERY_METRICS " + json.dumps(receipt) + "\n"

    def test_export_input_rows_require_terminal_state_key_grammar_and_sha256_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "operation key"):
            _operation_hint({}, "bad/key")
        with self.assertRaisesRegex(ValueError, "operation key"):
            _row_value(("bad/key", "b" * 64, "succeeded"), True)
        with self.assertRaisesRegex(ValueError, "terminal"):
            _row_value(("primary", "b" * 64, "pending"), True)
        with self.assertRaisesRegex(ValueError, "input digest"):
            _row_value(("primary", "not-a-digest", "succeeded"), True)

    def test_exports_only_receipt_backed_terminal_and_sanitized_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect-secret",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            database = trial / "tool-endpoint.sqlite"; con = sqlite3.connect(database)
            con.execute("CREATE TABLE operations (namespace_id TEXT, authority_id TEXT, effect_id TEXT, catalog_digest TEXT, run_id TEXT, operation_key TEXT, state TEXT)")
            con.execute("INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?)", (*identity.values(), "operation-secret", "succeeded")); con.commit(); con.close()
            retained = {"resource_id_raw": 24836, "generation": 1, "retained": True, "gate_result": "rejected_retained", "revision_unchanged": True, "head_unchanged": True}
            reusable = {"resource_id_raw": 24836, "generation": 1, "retained": False, "gate_result": "admitted_reusable", "revision_unchanged": True, "head_unchanged": True}
            (trial / "recovery.stdout.log").write_text(self._terminal(identity, dma_retained_gate=retained, dma_reusable_gate=reusable))
            (trial / "bridge.status.json").write_text('{"state":"served"}\n')
            output = Path(temporary) / "out"
            local_raw = Path(temporary) / "local-only.raw.jsonl"
            result = export_trial(trial, output, study_id="qemu_test_v1", key=b"x" * 32,
                                  raw_trace_output=local_raw)
            events = load_trace([result.trace])
            observations = [event for event in events if event["event_type"] == "effect_observation"]
            self.assertEqual(len(observations), 4)
            self.assertEqual(observations[0]["source_id"], "endpoint")
            self.assertEqual(observations[0]["effect_state"], "succeeded")
            gates = [event for event in observations if event["source_id"] == "allocator_gate"]
            self.assertEqual([event["gate_decision"] for event in gates], ["rejected", "admitted"])
            self.assertTrue(all(event["resource_pseudonym"].startswith("r1_") for event in gates))
            self.assertFalse(gates[-1]["right_censored"])
            device_end = [event for event in observations if event["source_id"] == "device"]
            self.assertEqual(len(device_end), 1)
            self.assertEqual(device_end[0]["event_kind"], "observation_ended")
            self.assertEqual(device_end[0]["quiescence_observation"], "unknown")
            self.assertTrue(device_end[0]["right_censored"])
            summary = json.loads(result.aggregate.read_text())
            self.assertEqual(summary["final_claims"]["final_resource_coordinates"], 1)
            self.assertEqual(summary["raw_events"]["by_kind"]["gate_rejected"], 1)
            self.assertEqual(summary["final_gates"]["rejected_resource_coordinates"], 0)
            self.assertEqual(summary["final_gates"]["admitted_resource_coordinates"], 1)
            self.assertIn("device", summary["partial_sources"])
            self.assertGreaterEqual(summary["right_censored_effects"], 1)
            self.assertNotIn("allocator_gate", summary["partial_sources"])
            bundle_text = "".join(path.read_text() for path in result.bundle.iterdir())
            self.assertNotIn("effect-secret", bundle_text)
            self.assertNotIn("operation-secret", bundle_text)
            self.assertNotIn("24836", bundle_text)
            self.assertEqual(result.raw_trace, local_raw)
            pseudonymizer = StudyPseudonymizer("qemu_test_v1", b"x" * 32)
            retained = load_raw_trace([local_raw], pseudonymizer)
            self.assertEqual(aggregate_raw_trace(retained, pseudonymizer), aggregate(events))
            self.assertIn("effect-secret", local_raw.read_text(encoding="utf-8"))
            manifest = json.loads((result.bundle / "manifest.json").read_text())
            self.assertEqual({entry["role"] for entry in manifest["inputs"]}, {"experiment_identity", "endpoint_database", "recovery_serial_log", "bridge_status"})
            source = json.loads((result.bundle / "source.json").read_text())
            self.assertEqual(source["repository"], "Nexus")
            self.assertIn("source_tree_sha256", source)

    def test_refuses_raw_trace_nested_in_published_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            output = Path(temporary) / "out"
            with self.assertRaisesRegex(ValueError, "outside"):
                export_trial(trial, output, study_id="qemu_test_v1", key=b"x" * 32,
                             raw_trace_output=output / "raw.jsonl")

    def test_rejects_gate_receipt_without_read_only_revision_and_head_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            bad = {"resource_id_raw": 1, "generation": 1, "retained": True,
                   "gate_result": "rejected_retained", "revision_unchanged": False, "head_unchanged": True}
            (trial / "recovery.stdout.log").write_text(self._terminal(identity, dma_retained_gate=bad))
            with self.assertRaises(ValueError):
                export_trial(trial, Path(temporary) / "out", study_id="qemu_test_v1", key=b"x" * 32)

    def test_missing_coordinate_receipts_remain_partial_without_counter_inference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            (trial / "recovery.stdout.log").write_text(self._terminal(identity))
            result = export_trial(trial, Path(temporary) / "out", study_id="qemu_test_v1", key=b"x" * 32)
            summary = json.loads(result.aggregate.read_text())
            self.assertIn("allocator_gate", summary["partial_sources"])
            self.assertEqual(summary["final_gates"]["final_resource_coordinates"], 0)
            events = load_trace([result.trace])
            device = [event for event in events if event.get("source_id") == "device" and event["event_type"] == "effect_observation"]
            self.assertEqual(device[0]["event_kind"], "observation_ended")
            self.assertTrue(device[0]["right_censored"])
            self.assertGreaterEqual(summary["right_censored_effects"], 1)

    def test_rejects_mismatched_gate_coordinate_and_nonterminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            retained = {"resource_id_raw": 1, "generation": 1, "retained": True, "gate_result": "rejected_retained", "revision_unchanged": True, "head_unchanged": True}
            reusable = {"resource_id_raw": 1, "generation": 2, "retained": False, "gate_result": "admitted_reusable", "revision_unchanged": True, "head_unchanged": True}
            (trial / "recovery.stdout.log").write_text(self._terminal(identity, dma_retained_gate=retained, dma_reusable_gate=reusable))
            with self.assertRaises(ValueError):
                export_trial(trial, Path(temporary) / "out", study_id="qemu_test_v1", key=b"x" * 32)
            (trial / "recovery.stdout.log").write_text('TOOL_DMA_RECOVERY_METRICS ' + json.dumps({"variant": "cser", "run_id": identity["run_id"], "terminal": False}) + "\n")
            with self.assertRaises(ValueError):
                export_trial(trial, Path(temporary) / "out2", study_id="qemu_test_v1", key=b"x" * 32)

    def test_missing_recovery_receipt_ends_device_observation_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            (trial / "initial.stdout.log").write_text("initial log only\n")
            result = export_trial(trial, Path(temporary) / "out", study_id="qemu_test_v1", key=b"x" * 32)
            summary = json.loads(result.aggregate.read_text())
            self.assertIn("device", summary["partial_sources"])
            self.assertGreaterEqual(summary["right_censored_effects"], 1)
            events = load_trace([result.trace])
            device = [event for event in events if event.get("source_id") == "device" and event["event_type"] == "effect_observation"]
            self.assertEqual((device[0]["event_kind"], device[0]["quiescence_observation"], device[0]["right_censored"]), ("observation_ended", "unknown", True))

    def test_selects_one_primary_key_and_cross_checks_modern_ledgers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            input_digest = "b" * 64
            endpoint = trial / "tool-endpoint.sqlite"
            provider = trial / "tool-endpoint.provider.sqlite"
            with closing(sqlite3.connect(endpoint)) as db:
                db.execute("CREATE TABLE operations(namespace_id,authority_id,effect_id,catalog_digest,run_id,operation_key,input_digest,state)")
                db.executemany("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?)", [
                    (*identity.values(), "primary", input_digest, "succeeded"),
                    (*identity.values(), "perf-bg-0", input_digest, "succeeded"),
                ])
                db.commit()
            with closing(sqlite3.connect(provider)) as db:
                db.execute("CREATE TABLE provider_operations(namespace_id,authority_id,effect_id,catalog_digest,run_id,operation_key,input_digest,state)")
                db.executemany("INSERT INTO provider_operations VALUES(?,?,?,?,?,?,?,?)", [
                    (*identity.values(), "primary", input_digest, "succeeded"),
                    (*identity.values(), "perf-bg-0", input_digest, "succeeded"),
                ])
                db.commit()
            result = export_trial(trial, Path(temporary) / "out", study_id="qemu_test_v1", key=b"x" * 32)
            events = [event for event in load_trace([result.trace]) if event["event_type"] == "effect_observation"]
            self.assertEqual({event["source_id"] for event in events}, {"endpoint", "worker_provider"})

            with closing(sqlite3.connect(provider)) as db:
                db.execute("UPDATE provider_operations SET input_digest='c' WHERE operation_key='primary'")
                db.commit()
            with self.assertRaisesRegex(ValueError, "invalid input digest"):
                export_trial(trial, Path(temporary) / "out-mismatch", study_id="qemu_test_v1", key=b"x" * 32)

    def test_rejects_ambiguous_or_background_only_operation_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary) / "trial"; trial.mkdir()
            identity = {"namespace_id": "ns", "authority_id": "authority", "effect_id": "effect",
                        "catalog_digest": "a" * 64, "run_id": "r" * 32}
            (trial / "experiment-identity.json").write_text(json.dumps(identity))
            database = trial / "tool-endpoint.sqlite"
            with closing(sqlite3.connect(database)) as db:
                db.execute("CREATE TABLE operations(namespace_id,authority_id,effect_id,catalog_digest,run_id,operation_key,input_digest,state)")
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?)", (*identity.values(), "perf-bg-0", "b" * 64, "succeeded"))
                db.commit()
            with self.assertRaisesRegex(ValueError, "background"):
                export_trial(trial, Path(temporary) / "out-background", study_id="qemu_test_v1", key=b"x" * 32)
            with closing(sqlite3.connect(database)) as db:
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?)", (*identity.values(), "primary-1", "b" * 64, "succeeded"))
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?)", (*identity.values(), "primary-2", "b" * 64, "succeeded"))
                db.commit()
            with self.assertRaisesRegex(ValueError, "exactly one"):
                export_trial(trial, Path(temporary) / "out-ambiguous", study_id="qemu_test_v1", key=b"x" * 32)


if __name__ == "__main__":
    unittest.main()
