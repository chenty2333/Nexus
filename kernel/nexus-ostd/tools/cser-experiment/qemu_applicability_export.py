#!/usr/bin/env python3
"""Export one real Tool+DMA QEMU trial without turning absent evidence into facts.

Inputs stay local: the output contains only HMAC pseudonyms, controlled labels,
counts, and SHA-256 digests.  In particular a terminal endpoint/provider row
does not imply DMA quiescence, claim release, or allocator admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from applicability_trace import (ClaimState, EffectState, EventKind, GateDecision,
    Observation, OutcomeCapability, ProviderCoordination, QuiescenceCapability,
    RecoveryCapability, SourceAvailability, SourceRole, StudyClaimBoundary,
    StudyPseudonymizer, TraceRecorder, aggregate, load_trace)
from matrix_controller import _recovery_metrics_from_serial_log

_BOUNDARY = StudyClaimBoundary.BOUNDED_APPLICABILITY_SAMPLE
_IDENTITY = {"namespace_id", "authority_id", "effect_id", "catalog_digest", "run_id"}


@dataclass(frozen=True)
class ExportOutputs:
    trace: Path
    aggregate: Path
    bundle: Path


def _object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return value


def _identity(trial: Path) -> dict[str, str]:
    value = _object(trial / "experiment-identity.json")
    if set(value) != _IDENTITY or not all(isinstance(value[key], str) and value[key] for key in _IDENTITY):
        raise ValueError("experiment identity is incomplete")
    return {key: value[key] for key in _IDENTITY}


def _terminal_receipt(path: Path | None, identity: dict[str, str]) -> dict[str, Any] | None:
    """Use the matrix's bounded parser; exports accept only CSER terminal receipts."""
    if path is None or not path.is_file():
        return None
    receipt = _recovery_metrics_from_serial_log(path, variant="cser", run_id=identity["run_id"])
    if receipt.get("terminal") is not True or receipt.get("invariants_ok") is not True:
        raise ValueError("export requires a CSER terminal invariants_ok receipt")
    return receipt


def _endpoint_row(database: Path, identity: dict[str, str]) -> dict[str, Any] | None:
    if not database.is_file(): return None
    con = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        columns = {row[1] for row in con.execute("PRAGMA table_info(operations)")}
        needed = _IDENTITY | {"operation_key", "state"}
        if not needed <= columns: return None
        row = con.execute("SELECT operation_key,state FROM operations WHERE namespace_id=? AND authority_id=? AND effect_id=? AND catalog_digest=? AND run_id=?", (identity["namespace_id"], identity["authority_id"], identity["effect_id"], identity["catalog_digest"], identity["run_id"])).fetchone()
        return None if row is None else {"operation_key": row[0], "state": row[1]}
    finally: con.close()


def _provider_row(database: Path, identity: dict[str, str]) -> dict[str, Any] | None:
    if not database.is_file(): return None
    con = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        columns = {row[1] for row in con.execute("PRAGMA table_info(provider_operations)")}
        needed = _IDENTITY | {"operation_key", "state"}
        if not needed <= columns: return None
        row = con.execute("SELECT operation_key,state FROM provider_operations WHERE namespace_id=? AND authority_id=? AND effect_id=? AND catalog_digest=? AND run_id=?", (identity["namespace_id"], identity["authority_id"], identity["effect_id"], identity["catalog_digest"], identity["run_id"])).fetchone()
        return None if row is None else {"operation_key": row[0], "state": row[1]}
    finally: con.close()


def _exported_record(path: Path | None, identity: dict[str, str]) -> dict[str, Any] | None:
    """Accept an endpoint/provider export only when it binds the trial identity."""
    if path is None or not path.is_file(): return None
    record = _object(path)
    if not _IDENTITY <= set(record) or any(record[key] != identity[key] for key in _IDENTITY):
        raise ValueError("exported record identity mismatch")
    if not isinstance(record.get("operation_key"), str) or not isinstance(record.get("state"), str):
        raise ValueError("exported record lacks operation state")
    return {"operation_key": record["operation_key"], "state": record["state"]}


def _terminal(state: Any) -> EffectState | None:
    return {"succeeded": EffectState.SUCCEEDED, "failed": EffectState.FAILED}.get(state)


def _status(path: Path | None) -> bool:
    if path is None or not path.is_file(): return False
    value = _object(path)
    return value.get("state") in {"closed", "served", "unused", "deferred"}


def _dma_gate_receipt(receipt: dict[str, Any] | None, field: str) -> dict[str, Any] | None:
    """Accept only the fixed, provenance-bearing core gate observation."""
    if receipt is None or field not in receipt:
        return None
    value = receipt[field]
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "resource_id_raw", "generation", "retained", "gate_result",
        "revision_unchanged", "head_unchanged",
    }:
        raise ValueError("DMA gate receipt has an invalid schema")
    for name in ("resource_id_raw", "generation"):
        if isinstance(value[name], bool) or not isinstance(value[name], int) or value[name] <= 0:
            raise ValueError("DMA gate receipt lacks an exact positive coordinate")
    if not all(isinstance(value[name], bool) for name in ("retained", "revision_unchanged", "head_unchanged")):
        raise ValueError("DMA gate receipt has invalid boolean provenance")
    expected = {
        "dma_retained_gate": (True, "rejected_retained"),
        "dma_reusable_gate": (False, "admitted_reusable"),
    }[field]
    if (value["retained"], value["gate_result"]) != expected:
        raise ValueError("DMA gate receipt contradicts its retained/reuse state")
    if not value["revision_unchanged"] or not value["head_unchanged"]:
        raise ValueError("DMA gate receipt does not prove a read-only gate check")
    return value


def _dma_gate_pair(receipt: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    retained = _dma_gate_receipt(receipt, "dma_retained_gate")
    reusable = _dma_gate_receipt(receipt, "dma_reusable_gate")
    if retained is not None and reusable is not None and (
        retained["resource_id_raw"], retained["generation"]
    ) != (reusable["resource_id_raw"], reusable["generation"]):
        raise ValueError("DMA gate receipts must bind one exact resource coordinate")
    return retained, reusable


def _dma_quiescence_evidence(receipt: dict[str, Any] | None, reusable_gate: dict[str, Any] | None) -> dict[str, Any] | None:
    if receipt is None:
        return None
    value = receipt.get("dma_quiescence_evidence")
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"schema_version", "run_id", "resource_id_raw", "generation", "reset", "irq_drained", "iotlb"}:
        raise ValueError("DMA quiescence evidence has invalid schema")
    if value["schema_version"] != 1 or value["run_id"] != receipt["run_id"]:
        raise ValueError("DMA quiescence evidence has invalid version or run binding")
    if any(isinstance(value[name], bool) or not isinstance(value[name], int) or value[name] <= 0 for name in ("resource_id_raw", "generation")):
        raise ValueError("DMA quiescence evidence lacks an exact coordinate")
    if any(value[name] is not True for name in ("reset", "irq_drained", "iotlb")):
        raise ValueError("DMA quiescence evidence lacks a complete verified closure")
    if reusable_gate is None or (value["resource_id_raw"], value["generation"]) != (
        reusable_gate["resource_id_raw"], reusable_gate["generation"]
    ):
        raise ValueError("DMA quiescence evidence must bind the admitted gate coordinate")
    return value


def _record_quiescent_dma(recorder: TraceRecorder, evidence: dict[str, Any], *, effect: str, run_id: str) -> None:
    recorder.record(source_id="device", raw_effect_id=effect,
        raw_operation_id=f"dma-quiescence:{run_id}", raw_resource_id=f"{evidence['resource_id_raw']}:{evidence['generation']}",
        event_kind=EventKind.QUIESCENT, operation_kind="tool_dma_qemu", effect_state=EffectState.PENDING,
        outcome_capability=OutcomeCapability.ABSENT, quiescence_capability=QuiescenceCapability.VERIFIABLE,
        outcome_recovery=RecoveryCapability.ABSENT, quiescence_recovery=RecoveryCapability.RECOVERABLE,
        outcome_observation=Observation.UNKNOWN, quiescence_observation=Observation.OBSERVED,
        claim_state=ClaimState.NOT_APPLICABLE, gate_decision=GateDecision.NOT_OBSERVED,
        provider_coordination=ProviderCoordination.UNKNOWN, executor_domain="qemu_guest",
        endpoint_domain="not_observed", resource_authority_domain="cser_exact_coordinate",
        relative_time_bucket="trial", right_censored=False, reason_code="reset_irq_iotlb_receipt")


def _record_dma_gate(recorder: TraceRecorder, gate: dict[str, Any], *, effect: str, run_id: str) -> None:
    rejected = gate["gate_result"] == "rejected_retained"
    recorder.record(source_id="allocator_gate", raw_effect_id=effect,
        raw_operation_id=f"dma-reuse-gate:{run_id}", raw_resource_id=f"{gate['resource_id_raw']}:{gate['generation']}",
        event_kind=EventKind.GATE_REJECTED if rejected else EventKind.CLAIM_RELEASED,
        operation_kind="tool_dma_qemu", effect_state=EffectState.PENDING,
        outcome_capability=OutcomeCapability.ABSENT, quiescence_capability=QuiescenceCapability.ABSENT,
        outcome_recovery=RecoveryCapability.ABSENT, quiescence_recovery=RecoveryCapability.ABSENT,
        outcome_observation=Observation.UNKNOWN, quiescence_observation=Observation.UNKNOWN,
        claim_state=ClaimState.RETAINED if rejected else ClaimState.RELEASED,
        gate_decision=GateDecision.REJECTED if rejected else GateDecision.ADMITTED,
        provider_coordination=ProviderCoordination.UNKNOWN, executor_domain="qemu_guest",
        endpoint_domain="not_observed", resource_authority_domain="cser_exact_coordinate",
        relative_time_bucket="trial", right_censored=rejected,
        reason_code="dma_live_reuse_rejected" if rejected else "dma_evidence_retired_reuse_admitted")


def _record_terminal(recorder: TraceRecorder, source: str, state: EffectState, effect: str, operation: str) -> None:
    recorder.record(source_id=source, raw_effect_id=effect, raw_operation_id=operation,
        event_kind=EventKind.TERMINAL, operation_kind="tool_dma_qemu", effect_state=state,
        outcome_capability=OutcomeCapability.VERIFIABLE, quiescence_capability=QuiescenceCapability.ABSENT,
        outcome_recovery=RecoveryCapability.RECOVERABLE, quiescence_recovery=RecoveryCapability.ABSENT,
        outcome_observation=Observation.OBSERVED, quiescence_observation=Observation.UNKNOWN,
        claim_state=ClaimState.NOT_APPLICABLE, gate_decision=GateDecision.NOT_OBSERVED,
        provider_coordination=ProviderCoordination.IDEMPOTENCY_RECORD, executor_domain="qemu_guest",
        endpoint_domain="trusted_local_endpoint", resource_authority_domain="not_observed",
        relative_time_bucket="trial", right_censored=False, reason_code="durable_terminal_record")


def _record_device_observation_ended(recorder: TraceRecorder, *, effect: str, run_id: str) -> None:
    """Record that the bounded device observation ended without quiescence evidence."""
    recorder.record(source_id="device", raw_effect_id=effect,
        raw_operation_id=f"dma-device-observation:{run_id}", event_kind=EventKind.OBSERVATION_ENDED,
        operation_kind="tool_dma_qemu", effect_state=EffectState.PENDING,
        outcome_capability=OutcomeCapability.ABSENT, quiescence_capability=QuiescenceCapability.ABSENT,
        outcome_recovery=RecoveryCapability.ABSENT, quiescence_recovery=RecoveryCapability.ABSENT,
        outcome_observation=Observation.UNKNOWN, quiescence_observation=Observation.UNKNOWN,
        claim_state=ClaimState.NOT_APPLICABLE, gate_decision=GateDecision.NOT_OBSERVED,
        provider_coordination=ProviderCoordination.UNKNOWN, executor_domain="qemu_guest",
        endpoint_domain="not_observed", resource_authority_domain="not_observed",
        relative_time_bucket="trial", right_censored=True, reason_code="quiescence_receipt_unavailable")


def _source_binding(exclude: Path) -> dict[str, Any]:
    """Bind exports to this Nexus checkout, including dirty working-tree input."""
    repository = Path(__file__).resolve()
    root = subprocess.check_output(["git", "-C", str(repository.parent), "rev-parse", "--show-toplevel"], text=True).strip()
    commit = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"], text=True).strip()
    tracked = subprocess.check_output(["git", "-C", root, "diff", "--binary", "HEAD"])
    untracked = subprocess.check_output(["git", "-C", root, "ls-files", "--others", "--exclude-standard", "-z"])
    untracked_digest = hashlib.sha256()
    excluded = exclude.resolve()
    for raw in filter(None, untracked.split(b"\0")):
        relative = raw.decode("utf-8", errors="strict")
        candidate = (Path(root) / relative).resolve()
        if candidate == excluded or excluded in candidate.parents:
            continue
        untracked_digest.update(raw + b"\0")
        untracked_digest.update(hashlib.sha256(candidate.read_bytes()).digest())
    dirty = bool(tracked or untracked)
    diff_digest = hashlib.sha256(tracked + b"\0" + untracked_digest.digest()).hexdigest()
    tree_digest = hashlib.sha256(commit.encode("ascii") + b"\0" + bytes.fromhex(diff_digest)).hexdigest()
    return {"repository": "Nexus", "commit": commit, "dirty": dirty,
            "source_diff_sha256": diff_digest, "source_tree_sha256": tree_digest,
            "exporter": "qemu_applicability_export_v1"}


def _write_bundle(destination: Path, summary: dict[str, Any], inputs: list[tuple[str, Path]], source: dict[str, Any]) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    manifest = [{"role": role, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for role, path in inputs if path.is_file()]
    (destination / "source.json").write_text(json.dumps(source, sort_keys=True)+"\n")
    (destination / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2)+"\n")
    (destination / "manifest.json").write_text(json.dumps({"schema_version": 1, "inputs": manifest}, sort_keys=True, indent=2)+"\n")
    return destination


def export_trial(trial_dir: Path, output_dir: Path, *, study_id: str, key: bytes,
                 endpoint_db: Path | None = None, provider_db: Path | None = None,
                 endpoint_record: Path | None = None, provider_record: Path | None = None,
                 initial_receipt: Path | None = None, recovery_receipt: Path | None = None,
                 bridge_status: Path | None = None, sink_status: Path | None = None) -> ExportOutputs:
    if output_dir.exists() and any(output_dir.iterdir()): raise ValueError("output directory must be empty")
    source_binding = _source_binding(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    identity = _identity(trial_dir); effect = identity["effect_id"] + ":" + identity["run_id"]
    endpoint_db = endpoint_db or trial_dir / "tool-endpoint.sqlite"; provider_db = provider_db or trial_dir / "tool-endpoint.provider.sqlite"
    initial_receipt = initial_receipt or trial_dir / "initial.stdout.log"; recovery_receipt = recovery_receipt or trial_dir / "recovery.stdout.log"
    bridge_status = bridge_status or trial_dir / "bridge.status.json"; sink_status = sink_status or trial_dir / "recovery-sink.status.json"
    endpoint = _exported_record(endpoint_record, identity) or _endpoint_row(endpoint_db, identity)
    provider = _exported_record(provider_record, identity) or _provider_row(provider_db, identity)
    # Initial logs are never authority for a completed recovery observation.
    initial = initial_receipt.is_file()
    recovery = _terminal_receipt(recovery_receipt, identity)
    trace = output_dir / "applicability.jsonl"; recorder = TraceRecorder(trace, StudyPseudonymizer(study_id, key))
    for source, role in (("endpoint", SourceRole.ENDPOINT), ("worker_provider", SourceRole.WORKER_PROVIDER), ("guest", SourceRole.GUEST), ("device", SourceRole.DEVICE), ("allocator_gate", SourceRole.ALLOCATOR_GATE)): recorder.describe_source(source, role, _BOUNDARY)
    availability = {"endpoint": SourceAvailability.MISSING, "worker_provider": SourceAvailability.MISSING, "guest": SourceAvailability.MISSING, "device": SourceAvailability.MISSING, "allocator_gate": SourceAvailability.MISSING}
    if endpoint:
        availability["endpoint"] = SourceAvailability.AVAILABLE
        terminal = _terminal(endpoint["state"])
        if terminal: _record_terminal(recorder, "endpoint", terminal, effect, endpoint["operation_key"])
        else: availability["endpoint"] = SourceAvailability.PARTIAL
    if provider:
        availability["worker_provider"] = SourceAvailability.AVAILABLE
        terminal = _terminal(provider["state"])
        if terminal: _record_terminal(recorder, "worker_provider", terminal, effect, provider["operation_key"])
        else: availability["worker_provider"] = SourceAvailability.PARTIAL
    # Receipts prove a bounded guest ran, but their aggregate counters name no
    # coordinate; never turn claims_retained/retired_by_evidence into a claim.
    if initial or recovery is not None: availability["guest"] = SourceAvailability.PARTIAL
    # Plain launcher/serial text is not a versioned, identity- and
    # coordinate-bound quiescence receipt. Keep the device source partial.
    retained_gate, reusable_gate = _dma_gate_pair(recovery)
    quiescence = _dma_quiescence_evidence(recovery, reusable_gate)
    if quiescence is not None:
        _record_quiescent_dma(recorder, quiescence, effect=effect, run_id=identity["run_id"])
        availability["device"] = SourceAvailability.AVAILABLE
    elif initial or recovery is not None:
        _record_device_observation_ended(recorder, effect=effect, run_id=identity["run_id"])
        availability["device"] = SourceAvailability.PARTIAL
    for gate in (retained_gate, reusable_gate):
        if gate is not None:
            _record_dma_gate(recorder, gate, effect=effect, run_id=identity["run_id"])
    if retained_gate is not None or reusable_gate is not None:
        availability["allocator_gate"] = SourceAvailability.AVAILABLE
    # Status documents supervise transport only; they cannot prove a gate fact.
    elif initial or recovery is not None or _status(bridge_status) or _status(sink_status):
        availability["allocator_gate"] = SourceAvailability.PARTIAL
    recorder.close(availability)
    summary = aggregate(load_trace([trace])); summary["export_limits"] = {"claim_coordinates": "exported_only_from_exact_core_gate_receipt", "gate_decisions": "exported_only_from_exact_core_gate_receipt", "bridge_sink": "supervisor_status_not_effect_evidence", "physical_dma_quiescence": "not_inferred_from_allocator_gate"}
    aggregate_path = output_dir / "aggregate.json"; aggregate_path.write_text(json.dumps(summary, sort_keys=True, indent=2)+"\n")
    bundle = _write_bundle(output_dir / "evidence-bundle", summary, [
        ("experiment_identity", trial_dir / "experiment-identity.json"),
        ("endpoint_database", endpoint_db), ("provider_database", provider_db),
        ("endpoint_record", endpoint_record or Path("/nonexistent")),
        ("provider_record", provider_record or Path("/nonexistent")),
        ("initial_serial_log", initial_receipt), ("recovery_serial_log", recovery_receipt),
        ("bridge_status", bridge_status), ("recovery_sink_status", sink_status),
    ], source_binding)
    return ExportOutputs(trace, aggregate_path, bundle)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--trial-dir", type=Path, required=True); parser.add_argument("--output-dir", type=Path, required=True); parser.add_argument("--study-id", default="tool_dma_qemu_v1"); parser.add_argument("--key-file", type=Path, required=True); parser.add_argument("--endpoint-db", type=Path); parser.add_argument("--provider-db", type=Path); parser.add_argument("--endpoint-record", type=Path); parser.add_argument("--provider-record", type=Path); parser.add_argument("--initial-receipt", type=Path); parser.add_argument("--recovery-receipt", type=Path); parser.add_argument("--bridge-status", type=Path); parser.add_argument("--sink-status", type=Path)
    args = parser.parse_args(); outputs = export_trial(args.trial_dir, args.output_dir, study_id=args.study_id, key=args.key_file.read_bytes(), endpoint_db=args.endpoint_db, provider_db=args.provider_db, endpoint_record=args.endpoint_record, provider_record=args.provider_record, initial_receipt=args.initial_receipt, recovery_receipt=args.recovery_receipt, bridge_status=args.bridge_status, sink_status=args.sink_status); print(json.dumps({"trace": str(outputs.trace), "aggregate": str(outputs.aggregate), "bundle": str(outputs.bundle)}, sort_keys=True))


if __name__ == "__main__": main()
