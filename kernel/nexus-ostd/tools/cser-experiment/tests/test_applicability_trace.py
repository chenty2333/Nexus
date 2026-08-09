from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from applicability_trace import (
    ClaimState, EffectState, GateDecision, Observation, OutcomeCapability,
    ProviderCoordination, QuiescenceCapability, RecoveryCapability,
    SourceAvailability, StudyPseudonymizer, TraceRecorder, aggregate, load_trace,
    SourceRole, StudyClaimBoundary, EventKind,
)


class ApplicabilityTraceTests(unittest.TestCase):
    def _record(self, recorder: TraceRecorder, effect: str, **changes: object) -> bool:
        fields: dict[str, object] = {
            "source_id": "local_adapter", "raw_effect_id": effect, "raw_operation_id": "private-operation",
            "event_kind": EventKind.CLAIM_RETAINED, "operation_kind": "local_tool",
            "effect_state": EffectState.PENDING, "outcome_capability": OutcomeCapability.VERIFIABLE,
            "quiescence_capability": QuiescenceCapability.VERIFIABLE,
            "outcome_recovery": RecoveryCapability.RECOVERABLE,
            "quiescence_recovery": RecoveryCapability.RECOVERABLE,
            "outcome_observation": Observation.UNKNOWN, "quiescence_observation": Observation.UNKNOWN,
            "claim_state": ClaimState.RETAINED, "gate_decision": GateDecision.REJECTED,
            "provider_coordination": ProviderCoordination.IDEMPOTENCY_RECORD,
            "executor_domain": "guest", "endpoint_domain": "trusted_local_adapter",
            "resource_authority_domain": "device_custody", "relative_time_bucket": "lt_1s",
            "right_censored": True, "reason_code": "pending_poll_budget",
        }
        fields.update(changes)
        return recorder.record(**fields)  # type: ignore[arg-type]

    def test_recorder_pseudonymizes_and_accounts_for_drop_and_missing_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            pseudo = StudyPseudonymizer("study_local_v1", b"k" * 32)
            recorder = TraceRecorder(trace, pseudo, max_events=1)
            recorder.describe_source("local_adapter", SourceRole.ENDPOINT, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            recorder.describe_source("lost_agent", SourceRole.WORKER_PROVIDER, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(recorder, "private-effect-a"))
            self.assertFalse(self._record(recorder, "private-effect-b"))
            recorder.close({"local_adapter": SourceAvailability.PARTIAL, "lost_agent": SourceAvailability.MISSING})
            raw = trace.read_text(encoding="utf-8")
            self.assertNotIn("private-effect-a", raw)
            self.assertNotIn("private-effect-b", raw)
            self.assertNotIn("private-operation", raw)
            result = aggregate(load_trace([trace]))
            self.assertEqual(result["denominator"]["eligible_effects"], 1)
            self.assertEqual(result["right_censored_effects"], 1)
            self.assertEqual(result["dropped_events"], 1)
            self.assertEqual(result["missing_sources"], ["lost_agent"])
            self.assertEqual(result["final_claims"]["retained_effects"], 1)
            self.assertEqual(result["final_gates"]["rejected_effects"], 1)

    def test_validator_rejects_unknown_fields_and_terminal_censoring(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            recorder = TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"x" * 32))
            recorder.describe_source("local_adapter", SourceRole.ENDPOINT, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(recorder, "effect", effect_state=EffectState.SUCCEEDED, right_censored=False,
                                         outcome_observation=Observation.OBSERVED, claim_state=ClaimState.RELEASED,
                                         gate_decision=GateDecision.ADMITTED, event_kind=EventKind.TERMINAL))
            recorder.close()
            item = next(
                json.loads(line)
                for line in trace.read_text(encoding="utf-8").splitlines()
                if json.loads(line)["event_type"] == "effect_observation"
            )
            item["right_censored"] = True
            bad = Path(temp) / "bad.jsonl"
            bad.write_text(json.dumps(item) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "right-censored"):
                load_trace([bad])

    def test_bounded_reference_sample_is_valid_but_not_prevalence(self) -> None:
        fixture = ROOT / "samples" / "applicability_reference_adapter_v1.jsonl"
        events = load_trace([fixture])
        result = aggregate(events)
        self.assertEqual(result["scope"], "bounded_source_sample_not_prevalence")
        self.assertEqual(result["denominator"]["eligible_effects"], 2)
        self.assertEqual(result["final_outcomes"]["terminal_effects"], 1)
        self.assertEqual(result["final_claims"], {"retained_effects": 1, "released_effects": 1})

    def test_cli_exports_only_aggregate(self) -> None:
        fixture = ROOT / "samples" / "applicability_reference_adapter_v1.jsonl"
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp) / "summary.json"
            command = [sys.executable, str(ROOT / "applicability_trace.py"), "aggregate", "--input", str(fixture), "--output", str(result)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            exported = json.loads(result.read_text(encoding="utf-8"))
            self.assertNotIn("effect_pseudonym", json.dumps(exported))
            self.assertEqual(exported["denominator"]["eligible_effects"], 2)

    def test_thread_safe_sequence_and_final_effect_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            recorder = TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"z" * 32), max_events=16)
            recorder.describe_source("local_adapter", SourceRole.ENDPOINT, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)

            def pending() -> None:
                self.assertTrue(self._record(recorder, "same-effect"))

            workers = [threading.Thread(target=pending) for _ in range(4)]
            for worker in workers: worker.start()
            for worker in workers: worker.join()
            self.assertTrue(self._record(recorder, "same-effect", event_kind=EventKind.TERMINAL,
                                         effect_state=EffectState.SUCCEEDED, right_censored=False,
                                         outcome_observation=Observation.OBSERVED, quiescence_observation=Observation.OBSERVED,
                                         claim_state=ClaimState.RELEASED, gate_decision=GateDecision.ADMITTED))
            recorder.close()
            events = load_trace([trace])
            self.assertEqual(sorted(event["sequence"] for event in events), list(range(len(events))))
            result = aggregate(events)
            self.assertEqual(result["denominator"]["eligible_effects"], 1)
            self.assertEqual(result["denominator"]["raw_effect_observations"], 5)
            self.assertEqual(result["final_claims"]["released_effects"], 1)
            self.assertEqual(result["final_claims"]["retained_effects"], 0)

    def test_refuses_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            trace.write_text("already a trace\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to append"):
                TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"q" * 32))


if __name__ == "__main__":
    unittest.main()
