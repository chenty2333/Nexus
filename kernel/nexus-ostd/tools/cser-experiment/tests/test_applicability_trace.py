from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from applicability_trace import (
    ClaimState, EffectState, GateDecision, Observation, OutcomeCapability,
    ProviderCoordination, QuiescenceCapability, RecoveryCapability,
    SourceAvailability, StudyPseudonymizer, TraceRecorder, aggregate, aggregate_raw_trace,
    load_published_trace, load_raw_trace, load_trace,
    SourceRole, StudyClaimBoundary, EventKind,
)


class ApplicabilityTraceTests(unittest.TestCase):
    def _record(self, recorder: TraceRecorder, effect: str, **changes: object) -> bool:
        fields: dict[str, object] = {
            "source_id": "local_adapter", "raw_effect_id": effect, "raw_operation_id": "private-operation",
            "raw_resource_id": "private-resource",
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
            recorder.describe_source("local_adapter", SourceRole.GUEST, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            recorder.describe_source("lost_agent", SourceRole.WORKER_PROVIDER, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(recorder, "private-effect-a"))
            self.assertFalse(self._record(recorder, "private-effect-b"))
            recorder.close({"lost_agent": SourceAvailability.MISSING})
            raw = trace.read_text(encoding="utf-8")
            self.assertNotIn("private-effect-a", raw)
            self.assertNotIn("private-effect-b", raw)
            self.assertNotIn("private-operation", raw)
            result = aggregate(load_trace([trace]))
            self.assertEqual(result["denominator"]["eligible_effects"], 1)
            self.assertEqual(result["right_censored_effects"], 1)
            self.assertEqual(result["dropped_events"], 1)
            self.assertEqual(result["missing_sources"], ["lost_agent"])
            self.assertEqual(result["partial_sources"], ["local_adapter"])
            self.assertEqual(result["final_claims"]["retained_resource_coordinates"], 1)
            self.assertEqual(result["final_gates"]["rejected_resource_coordinates"], 1)

    def test_optional_raw_retention_reaggregates_exact_sanitized_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trace = root / "published" / "trace.jsonl"
            raw_trace = root / "local-only" / "trace.raw.jsonl"
            pseudonymizer = StudyPseudonymizer("study_local_v1", b"r" * 32)
            recorder = TraceRecorder(trace, pseudonymizer,
                                     max_events=1, raw_output=raw_trace)
            recorder.describe_source("local_adapter", SourceRole.GUEST,
                                     StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(recorder, "private-effect-a"))
            self.assertFalse(self._record(recorder, "private-effect-b"))
            recorder.close()
            published = load_trace([trace])
            self.assertEqual(load_published_trace([trace]), published)
            retained = load_raw_trace([raw_trace], pseudonymizer)
            self.assertEqual([row["sanitized_event"] for row in retained], published)
            self.assertEqual(aggregate_raw_trace(retained, pseudonymizer), aggregate(published))
            self.assertEqual(retained[1]["raw_identifiers"], {
                "effect_id": "private-effect-a", "operation_id": "private-operation",
                "resource_id": "private-resource",
            })
            published_text = trace.read_text(encoding="utf-8")
            self.assertNotIn("private-effect-a", published_text)
            self.assertNotIn("private-operation", published_text)
            self.assertNotIn("private-resource", published_text)
            self.assertIn("private-effect-a", raw_trace.read_text(encoding="utf-8"))
            self.assertEqual(aggregate_raw_trace(retained, pseudonymizer)["dropped_events"], 1)
            marker_text = trace.with_name(trace.name + ".publication.json").read_text(encoding="utf-8")
            self.assertNotIn("private-effect-a", marker_text)
            self.assertNotIn("private-operation", marker_text)
            self.assertIn("raw_hmac_sha256", marker_text)
            trace.write_bytes(trace.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                load_published_trace([trace])

            for field, message in (
                ("effect_id", "effect id"), ("operation_id", "operation id"),
                ("resource_id", "resource id"),
            ):
                tampered = json.loads(json.dumps(retained))
                tampered[1]["raw_identifiers"][field] = "tampered-" + field
                candidate = root / (field + ".raw.jsonl")
                candidate.write_text("\n".join(json.dumps(row) for row in tampered) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    load_raw_trace([candidate], pseudonymizer)

    def test_raw_retention_refuses_sanitized_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            with self.assertRaisesRegex(ValueError, "must differ"):
                TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"r" * 32),
                              raw_output=trace)

    def test_raw_publication_create_failure_leaves_no_incomplete_set(self) -> None:
        original_open = Path.open
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for failed_name in ("marker", "raw"):
                trace = root / (failed_name + ".jsonl")
                raw_trace = root / (failed_name + ".raw.jsonl")
                marker = trace.with_name(trace.name + ".publication.json")
                target = marker if failed_name == "marker" else raw_trace

                def failing_open(path: Path, *args: object, **kwargs: object) -> object:
                    if path == target:
                        raise OSError("injected create failure")
                    return original_open(path, *args, **kwargs)

                with mock.patch.object(Path, "open", new=failing_open):
                    with self.assertRaisesRegex(RuntimeError, "raw authoritative trace"):
                        TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"r" * 32),
                                      raw_output=raw_trace)
                self.assertFalse(trace.exists())
                self.assertFalse(raw_trace.exists())
                self.assertFalse(marker.exists())

    def test_raw_append_failure_poison_keeps_publication_incomplete(self) -> None:
        class FailingStream:
            def __init__(self, stream: object, method: str, *, fail_rollback: bool = False) -> None:
                self.stream = stream
                self.method = method
                self.fail_rollback = fail_rollback

            def tell(self) -> int:
                return self.stream.tell()  # type: ignore[no-any-return,union-attr]

            def write(self, value: bytes) -> int:
                if self.method == "write":
                    raise OSError("injected write failure")
                return self.stream.write(value)  # type: ignore[no-any-return,union-attr]

            def flush(self) -> None:
                self.stream.flush()  # type: ignore[union-attr]
                if self.method == "flush":
                    raise OSError("injected flush failure")

            def fileno(self) -> int:
                return self.stream.fileno()  # type: ignore[no-any-return,union-attr]

            def seek(self, offset: int) -> int:
                return self.stream.seek(offset)  # type: ignore[no-any-return,union-attr]

            def truncate(self) -> int:
                if self.fail_rollback:
                    raise OSError("injected rollback failure")
                return self.stream.truncate()  # type: ignore[no-any-return,union-attr]

            def close(self) -> None:
                self.stream.close()  # type: ignore[union-attr]

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for method, fail_rollback in (("write", False), ("flush", True)):
                trace = root / (method + ".jsonl")
                raw_trace = root / (method + ".raw.jsonl")
                recorder = TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"r" * 32),
                                         raw_output=raw_trace)
                recorder.describe_source("local_adapter", SourceRole.GUEST,
                                         StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
                raw_before = raw_trace.read_bytes()
                recorder._raw_stream = FailingStream(recorder._raw_stream, method,
                                                     fail_rollback=fail_rollback)
                with self.assertRaisesRegex(RuntimeError, "poisoned"):
                    self._record(recorder, "private-effect")
                with self.assertRaisesRegex(RuntimeError, "poisoned"):
                    self._record(recorder, "later-effect")
                with self.assertRaisesRegex(RuntimeError, "poisoned"):
                    recorder.close()
                self.assertFalse(trace.exists())
                self.assertTrue(raw_trace.exists())
                self.assertTrue(raw_trace.read_bytes().startswith(raw_before))
                marker = json.loads(trace.with_name(trace.name + ".publication.json").read_text())
                self.assertEqual(marker["state"], "incomplete")
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    load_published_trace([trace])

    def test_interrupted_or_unmarked_raw_derivation_is_not_public(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pseudonymizer = StudyPseudonymizer("study_local_v1", b"r" * 32)
            trace = root / "interrupted.jsonl"
            raw_trace = root / "interrupted.raw.jsonl"
            recorder = TraceRecorder(trace, pseudonymizer, raw_output=raw_trace)
            recorder.describe_source("local_adapter", SourceRole.GUEST,
                                     StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(recorder, "private-effect"))
            with mock.patch("applicability_trace.os.replace", side_effect=OSError("injected derive interruption")):
                with self.assertRaisesRegex(RuntimeError, "publication failed"):
                    recorder.close()
            self.assertFalse(trace.exists())
            self.assertEqual(json.loads(trace.with_name(trace.name + ".publication.json").read_text())["state"], "incomplete")
            self.assertEqual(aggregate_raw_trace(load_raw_trace([raw_trace], pseudonymizer), pseudonymizer)["dropped_events"], 0)
            with self.assertRaisesRegex(ValueError, "incomplete"):
                load_published_trace([trace])

            # A crash can also leave a truncated raw log plus its incomplete
            # marker. Even a forged nearby JSONL is not a completed public set.
            crash_trace = root / "crash.jsonl"
            crash_raw = root / "crash.raw.jsonl"
            crashed = TraceRecorder(crash_trace, pseudonymizer, raw_output=crash_raw)
            crashed.describe_source("local_adapter", SourceRole.GUEST,
                                    StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            crashed._raw_stream.flush()
            crashed._raw_stream.close()
            crashed._raw_stream = None
            crashed._closed = True
            crash_trace.write_text(trace.read_text(encoding="utf-8") if trace.exists() else "", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                load_trace([crash_trace])
            crash_marker = crash_trace.with_name(crash_trace.name + ".publication.json")
            crash_marker.unlink()
            with self.assertRaisesRegex(ValueError, "lacks completion marker"):
                load_published_trace([crash_trace])

    def test_context_exception_aborts_raw_publication_without_finalize(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trace = root / "exception.jsonl"
            raw_trace = root / "exception.raw.jsonl"
            pseudonymizer = StudyPseudonymizer("study_local_v1", b"r" * 32)
            with self.assertRaisesRegex(RuntimeError, "workflow failed"):
                with TraceRecorder(trace, pseudonymizer, raw_output=raw_trace) as recorder:
                    recorder.describe_source("local_adapter", SourceRole.GUEST,
                                             StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
                    self.assertTrue(self._record(recorder, "partial-effect"))
                    raise RuntimeError("workflow failed")
            self.assertFalse(trace.exists())
            self.assertTrue(raw_trace.exists())
            marker = json.loads(trace.with_name(trace.name + ".publication.json").read_text())
            self.assertEqual(marker["state"], "incomplete")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                load_published_trace([trace])

    def test_complete_marker_replace_failure_cannot_publish_readable_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trace = root / "marker-pivot.jsonl"
            raw_trace = root / "marker-pivot.raw.jsonl"
            recorder = TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"r" * 32),
                                     raw_output=raw_trace)
            recorder.describe_source("local_adapter", SourceRole.GUEST,
                                     StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(recorder, "effect"))
            original_replace = os.replace
            replace_count = 0

            def fail_marker_replace(source: object, destination: object) -> None:
                nonlocal replace_count
                replace_count += 1
                if replace_count == 2:
                    raise OSError("injected complete-marker pivot failure")
                original_replace(source, destination)

            with mock.patch("applicability_trace.os.replace", side_effect=fail_marker_replace):
                with self.assertRaisesRegex(RuntimeError, "publication failed"):
                    recorder.close()
            self.assertEqual(replace_count, 2)
            self.assertTrue(trace.exists())
            marker = json.loads(trace.with_name(trace.name + ".publication.json").read_text())
            self.assertEqual(marker["state"], "incomplete")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                load_trace([trace])
            with self.assertRaisesRegex(ValueError, "incomplete"):
                load_published_trace([trace])

    def test_validator_rejects_unknown_fields_and_terminal_censoring(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            recorder = TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"x" * 32))
            recorder.describe_source("local_adapter", SourceRole.ENDPOINT, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(recorder, "effect", effect_state=EffectState.SUCCEEDED, right_censored=False,
                                         outcome_observation=Observation.OBSERVED, claim_state=ClaimState.NOT_APPLICABLE,
                                         gate_decision=GateDecision.NOT_OBSERVED, event_kind=EventKind.TERMINAL))
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
        self.assertEqual(result["final_quiescence"]["observed_effects"], 1)
        self.assertEqual(result["final_claims"], {"retained_resource_coordinates": 1, "released_resource_coordinates": 1, "final_resource_coordinates": 2})

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
            recorder.describe_source("local_adapter", SourceRole.GUEST, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)

            def pending() -> None:
                self.assertTrue(self._record(recorder, "same-effect"))

            workers = [threading.Thread(target=pending) for _ in range(4)]
            for worker in workers: worker.start()
            for worker in workers: worker.join()
            self.assertTrue(self._record(recorder, "same-effect", event_kind=EventKind.CLAIM_RELEASED,
                                         effect_state=EffectState.PENDING, right_censored=True,
                                         outcome_observation=Observation.UNKNOWN, quiescence_observation=Observation.UNKNOWN,
                                         claim_state=ClaimState.RELEASED, gate_decision=GateDecision.ADMITTED))
            recorder.close()
            events = load_trace([trace])
            self.assertEqual(sorted(event["sequence"] for event in events), list(range(len(events))))
            result = aggregate(events)
            self.assertEqual(result["denominator"]["eligible_effects"], 1)
            self.assertEqual(result["denominator"]["raw_effect_observations"], 5)
            self.assertEqual(result["final_claims"]["released_resource_coordinates"], 1)
            self.assertEqual(result["final_claims"]["retained_resource_coordinates"], 0)

    def test_multisource_endpoint_and_device_use_local_ordering_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            endpoint_trace = Path(temp) / "endpoint.jsonl"
            device_trace = Path(temp) / "device.jsonl"
            pseudo = StudyPseudonymizer("study_local_v1", b"m" * 32)
            endpoint = TraceRecorder(endpoint_trace, pseudo)
            endpoint.describe_source("endpoint_observer", SourceRole.ENDPOINT, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(endpoint, "shared-effect", source_id="endpoint_observer", event_kind=EventKind.TERMINAL,
                                         effect_state=EffectState.SUCCEEDED, right_censored=False,
                                         outcome_observation=Observation.OBSERVED, quiescence_observation=Observation.UNKNOWN,
                                         claim_state=ClaimState.NOT_APPLICABLE, gate_decision=GateDecision.NOT_OBSERVED))
            endpoint.close()
            device = TraceRecorder(device_trace, pseudo)
            device.describe_source("device_observer", SourceRole.DEVICE, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            self.assertTrue(self._record(device, "shared-effect", source_id="device_observer", event_kind=EventKind.QUIESCENT,
                                         effect_state=EffectState.PENDING, right_censored=True,
                                         outcome_observation=Observation.UNKNOWN, quiescence_observation=Observation.OBSERVED,
                                         claim_state=ClaimState.NOT_APPLICABLE, gate_decision=GateDecision.NOT_OBSERVED))
            device.close()
            events = load_trace([endpoint_trace, device_trace])
            self.assertEqual([event["sequence"] for event in events if event["event_type"] == "source_profile"], [0, 0])
            result = aggregate(events)
            self.assertEqual(result["denominator"]["eligible_effects"], 1)
            self.assertEqual(result["denominator"]["final_source_effects"], 2)
            self.assertEqual(result["final_outcomes"]["terminal_effects"], 1)
            self.assertEqual(result["final_quiescence"]["observed_effects"], 1)

    def test_refuses_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            trace.write_text("already a trace\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to append"):
                TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"q" * 32))

    def test_aggregate_rejects_profile_without_status_and_role_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "trace.jsonl"
            recorder = TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"w" * 32))
            recorder.describe_source("endpoint_observer", SourceRole.ENDPOINT, StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE)
            with self.assertRaisesRegex(ValueError, "not authoritative"):
                self._record(recorder, "effect", source_id="endpoint_observer", event_kind=EventKind.QUIESCENT,
                             quiescence_observation=Observation.OBSERVED, claim_state=ClaimState.NOT_APPLICABLE,
                             gate_decision=GateDecision.NOT_OBSERVED)
            # The profile was durable, but a simulated crashed producer never
            # emitted its required status/accounting event.
            with self.assertRaisesRegex(ValueError, "no source status"):
                aggregate(load_trace([trace]))
            # Preserve that crash-shaped file while closing this test's local
            # descriptor; calling close() would write the missing status.
            recorder._closed = True
            recorder._close_streams()

    def test_operator_disposition_is_counted_but_cannot_attest_safety_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            trace = Path(temp) / "operator.jsonl"
            recorder = TraceRecorder(trace, StudyPseudonymizer("study_local_v1", b"o" * 32))
            recorder.describe_source(
                "operator_observer",
                SourceRole.OPERATOR,
                StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE,
            )
            self.assertTrue(self._record(
                recorder,
                "effect",
                source_id="operator_observer",
                raw_resource_id=None,
                event_kind=EventKind.ADMIN_DISPOSITION,
                claim_state=ClaimState.NOT_APPLICABLE,
                gate_decision=GateDecision.NOT_OBSERVED,
                right_censored=False,
                reason_code="operator_accepted_residual_risk",
            ))
            with self.assertRaisesRegex(ValueError, "not authoritative"):
                self._record(
                    recorder,
                    "unsafe-effect",
                    source_id="operator_observer",
                    event_kind=EventKind.TERMINAL,
                    effect_state=EffectState.SUCCEEDED,
                    outcome_observation=Observation.OBSERVED,
                    claim_state=ClaimState.NOT_APPLICABLE,
                    gate_decision=GateDecision.NOT_OBSERVED,
                    right_censored=False,
                )
            recorder.close()
            result = aggregate(load_trace([trace]))
            self.assertEqual(result["administrative_dispositions"]["observed_effects"], 1)


if __name__ == "__main__":
    unittest.main()
