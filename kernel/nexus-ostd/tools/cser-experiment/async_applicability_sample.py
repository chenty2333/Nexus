#!/usr/bin/env python3
"""Run one bounded, honest asynchronous CSER applicability sample.

The sample is deliberately a *controlled reference-adapter execution*, not a
claim about endpoint prevalence or a CSER-vs-baseline result.  It drives the
real durable ``Store``, independently durable exact-key ``ProviderStore``, and
``AsyncWorker`` through an apply-before-terminal crash window.  It exports two
source-owned JSONL traces with the same study HMAC key:

* ``endpoint.jsonl`` records durable acceptance and later endpoint query; and
* ``worker_provider.jsonl`` records the worker/provider Pending and recovered
  terminal observations.

The provider's exact-key table is explicitly labelled as an *existing
coordinator*.  No guest, device-quiescence, allocator-claim, or allocator-gate
fact is invented: those source roles are present in the endpoint trace's
source-status manifest as ``missing``.  Consequently the aggregate reports a
bounded outcome-recovery demonstration and missing physical/gate sources,
never a release, quiescence, or admission result.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from applicability_trace import (
    ClaimState,
    EffectState,
    EventKind,
    GateDecision,
    Observation,
    OutcomeCapability,
    ProviderCoordination,
    QuiescenceCapability,
    RecoveryCapability,
    SourceAvailability,
    SourceRole,
    StudyClaimBoundary,
    StudyPseudonymizer,
    TraceRecorder,
    aggregate,
    load_trace,
)
from tool_endpoint import Store
from tool_provider import ProviderOutcome, ProviderStore
from tool_worker import AsyncWorker


_CATALOG_DIGEST = hashlib.sha256(b"cser-async-applicability-sample-v1").hexdigest()
_DEFAULT_RUN_ID = "0123456789abcdef0123456789abcdef"
_OPERATION_KEY = "bounded-async-sample"
_PAYLOAD = b"bounded asynchronous applicability sample"
_BOUNDARY = StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE


@dataclass(frozen=True)
class SampleOutputs:
    endpoint_trace: Path
    worker_provider_trace: Path
    aggregate_path: Path
    state_dir: Path


def _close_quietly(resource: object) -> None:
    """Cleanup must not turn an already-raised sample error into bad JSONL."""
    try:
        getattr(resource, "close")()
    except BaseException:
        pass


def _record_endpoint(recorder: TraceRecorder, *, raw_effect: str, state: EffectState,
                     event: EventKind, right_censored: bool, reason: str) -> None:
    recorder.record(
        source_id="endpoint", raw_effect_id=raw_effect, raw_operation_id=_OPERATION_KEY,
        event_kind=event, operation_kind="trusted_local_async_operation", effect_state=state,
        outcome_capability=OutcomeCapability.VERIFIABLE,
        quiescence_capability=QuiescenceCapability.ABSENT,
        outcome_recovery=RecoveryCapability.RECOVERABLE,
        quiescence_recovery=RecoveryCapability.ABSENT,
        outcome_observation=Observation.OBSERVED if state.terminal else Observation.UNKNOWN,
        quiescence_observation=Observation.UNKNOWN,
        claim_state=ClaimState.NOT_APPLICABLE, gate_decision=GateDecision.NOT_OBSERVED,
        provider_coordination=ProviderCoordination.IDEMPOTENCY_RECORD,
        executor_domain="guest_unknown", endpoint_domain="trusted_local_endpoint",
        resource_authority_domain="not_observed", relative_time_bucket="bounded_run",
        right_censored=right_censored, reason_code=reason,
    )


def _record_worker(recorder: TraceRecorder, *, raw_effect: str, state: EffectState,
                   event: EventKind, right_censored: bool, reason: str) -> None:
    recorder.record(
        source_id="worker_provider", raw_effect_id=raw_effect, raw_operation_id=_OPERATION_KEY,
        event_kind=event, operation_kind="trusted_local_async_operation", effect_state=state,
        outcome_capability=OutcomeCapability.VERIFIABLE,
        quiescence_capability=QuiescenceCapability.ABSENT,
        outcome_recovery=RecoveryCapability.RECOVERABLE,
        quiescence_recovery=RecoveryCapability.ABSENT,
        outcome_observation=Observation.OBSERVED if state.terminal else Observation.UNKNOWN,
        quiescence_observation=Observation.UNKNOWN,
        claim_state=ClaimState.NOT_APPLICABLE, gate_decision=GateDecision.NOT_OBSERVED,
        provider_coordination=ProviderCoordination.IDEMPOTENCY_RECORD,
        executor_domain="endpoint_worker", endpoint_domain="trusted_local_provider",
        resource_authority_domain="not_observed", relative_time_bucket="bounded_run",
        right_censored=right_censored, reason_code=reason,
    )


class WorkerProviderTraceSink:
    """A configured sink, invoked only by real worker/provider transitions.

    The runner constructs this object but never calls its producer methods;
    ``ProviderStore`` invokes ``provider_observer`` after a query/apply and
    ``AsyncWorker`` invokes ``worker_observer`` after its durable Pending or
    terminal transition.  Their host classes swallow callback exceptions, so
    this recorder cannot affect the experiment's trusted decisions.
    """

    def __init__(self, recorder: TraceRecorder) -> None:
        self._recorder = recorder

    @staticmethod
    def _effect(identity: tuple[str, str, str, str, str, str]) -> str:
        _, _, effect_id, _, run_id, operation_key = identity
        return f"{effect_id}:{run_id}:{operation_key}"

    def _write(self, raw_effect: str, state: EffectState, event: EventKind, reason: str) -> None:
        _record_worker(self._recorder, raw_effect=raw_effect, state=state,
                       event=event, right_censored=False, reason=reason)

    def provider_observer(self, event: str, identity: tuple[str, str, str, str, str, str],
                          _input_digest: str, outcome: ProviderOutcome | None) -> None:
        raw_effect = self._effect(identity)
        if event == "provider_query_miss":
            self._write(raw_effect, EffectState.PENDING, EventKind.PENDING,
                        "provider_exact_key_query_absent")
        elif event in {"provider_query_hit", "provider_apply_durable", "provider_apply_deduplicated"}:
            if outcome is None:
                raise ValueError("provider terminal observation lacks outcome")
            state = EffectState.SUCCEEDED if outcome.state == "succeeded" else EffectState.FAILED
            self._write(raw_effect, state, EventKind.TERMINAL,
                        "provider_exact_key_" + event.removeprefix("provider_"))
        else:
            raise ValueError("unknown provider observation")

    def worker_observer(self, event: str, item: object, outcome: ProviderOutcome | None) -> None:
        # WorkItem is intentionally duck-typed here so the tracing module does
        # not import endpoint internals or participate in worker authority.
        effect_id = getattr(item, "effect_id")
        run_id = getattr(item, "run_id")
        operation_key = getattr(item, "operation_key")
        raw_effect = f"{effect_id}:{run_id}:{operation_key}"
        if event == "worker_pending_committed":
            self._write(raw_effect, EffectState.PENDING, EventKind.PENDING,
                        "worker_pending_durable")
        elif event == "worker_terminal_committed":
            if outcome is None:
                raise ValueError("worker terminal observation lacks outcome")
            state = EffectState.SUCCEEDED if outcome.state == "succeeded" else EffectState.FAILED
            self._write(raw_effect, state, EventKind.TERMINAL,
                        "worker_terminal_durable")
        else:
            raise ValueError("unknown worker observation")


def run_sample(output_dir: Path, *, study_id: str, key: bytes,
               state_dir: Path | None = None, run_id: str = _DEFAULT_RUN_ID) -> SampleOutputs:
    """Execute one controlled recovery and write source-owned trace files.

    ``output_dir`` must be absent or empty so a result can never silently mix
    executions.  The durable SQLite files are retained under ``state_dir`` for
    local inspection; their raw identifiers are never copied into JSONL.
    """
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output directory must be absent or empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    durable_state = state_dir or output_dir / "state"
    if durable_state.exists() and any(durable_state.iterdir()):
        raise ValueError("state directory must be absent or empty for an independent sample")
    durable_state.mkdir(parents=True, exist_ok=True)
    endpoint_path = output_dir / "endpoint.jsonl"
    worker_path = output_dir / "worker_provider.jsonl"
    aggregate_path = output_dir / "aggregate.json"
    if aggregate_path.exists():
        raise ValueError("aggregate output already exists")

    pseudonymizer = StudyPseudonymizer(study_id, key)
    with ExitStack() as cleanup:
        endpoint_trace = TraceRecorder(endpoint_path, pseudonymizer)
        endpoint_trace.describe_source("endpoint", SourceRole.ENDPOINT, _BOUNDARY)
        # These profiles/statuses are a manifest of required but unavailable
        # observation authorities.  They are intentionally not endpoint facts.
        endpoint_trace.describe_source("guest", SourceRole.GUEST, _BOUNDARY)
        endpoint_trace.describe_source("device", SourceRole.DEVICE, _BOUNDARY)
        endpoint_trace.describe_source("allocator_gate", SourceRole.ALLOCATOR_GATE, _BOUNDARY)
        cleanup.callback(endpoint_trace.close, {
            "endpoint": SourceAvailability.AVAILABLE,
            "guest": SourceAvailability.MISSING,
            "device": SourceAvailability.MISSING,
            "allocator_gate": SourceAvailability.MISSING,
        })
        worker_trace = TraceRecorder(worker_path, pseudonymizer)
        worker_trace.describe_source("worker_provider", SourceRole.WORKER_PROVIDER, _BOUNDARY)
        cleanup.callback(worker_trace.close, {"worker_provider": SourceAvailability.AVAILABLE})
        sink = WorkerProviderTraceSink(worker_trace)

        store = Store(durable_state / "endpoint.sqlite", catalog_digest=_CATALOG_DIGEST)
        cleanup.callback(_close_quietly, store)
        raw_effect = f"{store.effect_id}:{run_id}:{_OPERATION_KEY}"
        digest = hashlib.sha256(_PAYLOAD).hexdigest()
        status, accepted = store.enqueue(run_id, _OPERATION_KEY, digest, _PAYLOAD)
        if status != 202 or accepted["state"] != "accepted":
            raise RuntimeError("fresh bounded sample was not durably accepted")
        _record_endpoint(endpoint_trace, raw_effect=raw_effect, state=EffectState.ACCEPTED,
                         event=EventKind.ACCEPTED, right_censored=False,
                         reason="durable_accepted_before_worker_completion")

        # The provider commits first, then injects a process-visible loss. The
        # first worker leaves the adapter Pending; the second worker must query
        # the existing exact-key coordinator before it can publish terminal
        # outcome evidence.  All worker/provider facts below originate in the
        # source's optional observer invocation, not a post-hoc Store read.
        provider = ProviderStore(durable_state / "provider.sqlite", fault_after_apply_once=True,
                                 observer=sink.provider_observer)
        cleanup.callback(_close_quietly, provider)
        first = AsyncWorker(store, provider, worker_id="sample-first",
                            retry_backoff_min_seconds=0.0001, retry_backoff_max_seconds=0.0001,
                            observer=sink.worker_observer)
        if not first.run_once():
            raise RuntimeError("bounded sample worker did not claim accepted operation")
        pending = store.get(run_id, _OPERATION_KEY)
        if pending is None or pending["state"] != "pending":
            raise RuntimeError("apply-before-terminal cut did not leave durable Pending state")
        first_provider_dropped = int(provider.metrics()["provider_telemetry_dropped"])
        provider.close()
        # The first callback remains registered but SQLite close is idempotent;
        # the replacement is separately registered for exceptional cleanup.
        provider = ProviderStore(durable_state / "provider.sqlite", observer=sink.provider_observer)
        cleanup.callback(_close_quietly, provider)
        recovered = AsyncWorker(store, provider, worker_id="sample-recovery", observer=sink.worker_observer)
        if not recovered.run_once():
            raise RuntimeError("recovery worker did not reclaim pending operation")
        terminal = store.get(run_id, _OPERATION_KEY)
        if terminal is None or terminal["state"] != "succeeded":
            raise RuntimeError("recovery did not publish provider outcome")
        _record_endpoint(endpoint_trace, raw_effect=raw_effect, state=EffectState.SUCCEEDED,
                         event=EventKind.TERMINAL, right_censored=False,
                         reason="endpoint_query_observed_durable_terminal_outcome")
        if (first_provider_dropped or int(provider.metrics()["provider_telemetry_dropped"])
                or first.telemetry_dropped or recovered.telemetry_dropped):
            raise RuntimeError("source-owned trace telemetry was dropped")

    summary = aggregate(load_trace([endpoint_path, worker_path]))
    # This is an explicit result qualifier, not an inferred endpoint fact.
    summary["controlled_execution"] = {
        "provider_exact_key_table": "existing_coordinator",
        "physical_quiescence": "not_observed",
        "guest_claims": "not_observed",
        "allocator_gate": "not_observed",
    }
    with aggregate_path.open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return SampleOutputs(endpoint_path, worker_path, aggregate_path, durable_state)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--study-id", default="bounded_async_reference_v1")
    parser.add_argument("--key-file", type=Path, required=True,
                        help="private >=32-byte study HMAC key; never copied into trace output")
    parser.add_argument("--state-dir", type=Path,
                        help="durable Store/ProviderStore directory (defaults under output-dir)")
    parser.add_argument("--run-id", default=_DEFAULT_RUN_ID)
    args = parser.parse_args()
    key = args.key_file.read_bytes()
    outputs = run_sample(args.output_dir, study_id=args.study_id, key=key,
                         state_dir=args.state_dir, run_id=args.run_id)
    print(json.dumps({
        "endpoint_trace": str(outputs.endpoint_trace),
        "worker_provider_trace": str(outputs.worker_provider_trace),
        "aggregate": str(outputs.aggregate_path),
        "state_dir": str(outputs.state_dir),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
