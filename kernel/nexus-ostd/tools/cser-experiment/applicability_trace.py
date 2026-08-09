#!/usr/bin/env python3
"""Privacy-bounded applicability traces for CSER endpoint studies.

This module is deliberately independent of the endpoint and guest protocols.
Producers submit a small, validated observation through :class:`TraceRecorder`;
the recorder replaces the producer's local effect identifier with a per-study
HMAC pseudonym before it reaches JSONL.  The resulting trace describes one
bounded source/sample, not workload or industry prevalence.

The schema separates an endpoint's declared capability from an observation,
the system result, and the research inference.  In particular, missing input
is represented as source loss or right censoring and is never exported as an
absence claim.  ``source_id``, domains, operation kinds, time buckets, and
reason codes are *public controlled labels*: they must use the restricted
label grammar below and are never automatically pseudonymized.  Callers must
therefore not put hostnames, URLs, payloads, tenant names, or raw IDs in them.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping


TRACE_SCHEMA_VERSION = 1
_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}\Z")
_PSEUDONYM = re.compile(r"e1_[0-9a-f]{64}\Z")
_OPERATION_PSEUDONYM = re.compile(r"o1_[0-9a-f]{64}\Z")
_RESOURCE_PSEUDONYM = re.compile(r"r1_[0-9a-f]{64}\Z")


class OutcomeCapability(str, Enum):
    VERIFIABLE = "verifiable"
    ABSENT = "absent"


class QuiescenceCapability(str, Enum):
    VERIFIABLE = "verifiable"
    ABSENT = "absent"


class RecoveryCapability(str, Enum):
    RECOVERABLE = "recoverable"
    EPHEMERAL = "ephemeral"
    ABSENT = "absent"


class Observation(str, Enum):
    OBSERVED = "observed"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class EffectState(str, Enum):
    ACCEPTED = "accepted"
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in (self.SUCCEEDED, self.FAILED)


class ClaimState(str, Enum):
    LIVE = "live"
    RELEASED = "released"
    RETAINED = "retained"
    NOT_APPLICABLE = "not_applicable"


class GateDecision(str, Enum):
    ADMITTED = "admitted"
    REJECTED = "rejected"
    NOT_OBSERVED = "not_observed"


class ProviderCoordination(str, Enum):
    NONE_OBSERVED = "none_observed"
    IDEMPOTENCY_RECORD = "idempotency_record"
    LEASE = "lease"
    SCHEDULER = "scheduler"
    ATTACHMENT_GATE = "attachment_gate"
    WORKFLOW_DATABASE = "workflow_database"
    PROVIDER_NATIVE = "provider_native"
    UNKNOWN = "unknown"


class SourceAvailability(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    PARTIAL = "partial"


class SourceRole(str, Enum):
    """The observation authority, not an endpoint product category."""
    ENDPOINT = "endpoint"
    WORKER_PROVIDER = "worker_provider"
    GUEST = "guest"
    DEVICE = "device"
    ALLOCATOR_GATE = "allocator_gate"
    OPERATOR = "operator"


class StudyClaimBoundary(str, Enum):
    """What an exported sample is allowed to claim."""
    PIPELINE_VALIDATION_ONLY = "pipeline_validation_only"
    BOUNDED_APPLICABILITY_SAMPLE = "bounded_applicability_sample_not_prevalence"


class EventKind(str, Enum):
    """A lifecycle observation; it does not itself imply retirement evidence."""
    REGISTERED = "registered"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    PENDING = "pending"
    TERMINAL = "terminal"
    QUIESCENT = "quiescent"
    CLAIM_RETAINED = "claim_retained"
    CLAIM_RELEASED = "claim_released"
    GATE_REJECTED = "gate_rejected"
    ADMIN_DISPOSITION = "admin_disposition"
    OBSERVATION_ENDED = "observation_ended"


_ENUMS: dict[str, type[Enum]] = {
    "outcome_capability": OutcomeCapability,
    "quiescence_capability": QuiescenceCapability,
    "outcome_recovery": RecoveryCapability,
    "quiescence_recovery": RecoveryCapability,
    "outcome_observation": Observation,
    "quiescence_observation": Observation,
    "effect_state": EffectState,
    "claim_state": ClaimState,
    "gate_decision": GateDecision,
    "provider_coordination": ProviderCoordination,
    "source_availability": SourceAvailability,
    "source_role": SourceRole,
    "study_claim_boundary": StudyClaimBoundary,
    "event_kind": EventKind,
}


def _label(value: object, name: str) -> str:
    """Validate a controlled, publication-safe label; this is not anonymization."""
    if not isinstance(value, str) or _LABEL.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")
    return value


def _enum(value: object, kind: type[Enum], name: str) -> str:
    if not isinstance(value, str) or value not in {item.value for item in kind}:
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class StudyPseudonymizer:
    """Derives unlinkable per-study effect identifiers without persisting input."""

    study_id: str
    key: bytes

    def __post_init__(self) -> None:
        _label(self.study_id, "study id")
        if len(self.key) < 32:
            raise ValueError("study HMAC key must contain at least 32 bytes")

    def _derive(self, prefix: str, raw_id: str, label: str) -> str:
        if not isinstance(raw_id, str) or not raw_id or len(raw_id) > 512:
            raise ValueError(f"invalid local {label} id")
        material = self.study_id.encode("utf-8") + b"\0" + label.encode("utf-8") + b"\0" + raw_id.encode("utf-8")
        return prefix + hmac.new(self.key, material, hashlib.sha256).hexdigest()

    def effect(self, raw_effect_id: str) -> str:
        return self._derive("e1_", raw_effect_id, "effect")

    def operation(self, raw_operation_id: str) -> str:
        return self._derive("o1_", raw_operation_id, "operation")

    def resource(self, raw_resource_id: str) -> str:
        return self._derive("r1_", raw_resource_id, "resource")


def validate_event(item: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one JSON-compatible event and return a detached dictionary."""
    if not isinstance(item, Mapping):
        raise ValueError("trace event must be an object")
    event = dict(item)
    if event.get("schema_version") != TRACE_SCHEMA_VERSION:
        raise ValueError("unsupported trace schema version")
    event_type = event.get("event_type")
    if event_type == "source_profile":
        required = {"schema_version", "event_type", "study_id", "source_id", "source_role", "study_claim_boundary", "sequence", "relative_ns"}
        if set(event) != required:
            raise ValueError("source profile has unknown or missing fields")
        _label(event["study_id"], "study id")
        _label(event["source_id"], "source id")
        _enum(event["source_role"], SourceRole, "source role")
        _enum(event["study_claim_boundary"], StudyClaimBoundary, "study claim boundary")
        _ordering(event)
        return event
    if event_type == "source_status":
        required = {"schema_version", "event_type", "study_id", "source_id", "source_availability", "dropped_events", "sequence", "relative_ns"}
        if set(event) != required:
            raise ValueError("source status has unknown or missing fields")
        _label(event["study_id"], "study id")
        _label(event["source_id"], "source id")
        _enum(event["source_availability"], SourceAvailability, "source availability")
        if isinstance(event["dropped_events"], bool) or not isinstance(event["dropped_events"], int) or event["dropped_events"] < 0:
            raise ValueError("invalid dropped event count")
        _ordering(event)
        return event
    if event_type != "effect_observation":
        raise ValueError("unknown trace event type")
    required = {
        "schema_version", "event_type", "study_id", "source_id", "effect_pseudonym", "operation_kind",
        "effect_state", "outcome_capability", "quiescence_capability", "outcome_recovery", "quiescence_recovery",
        "outcome_observation", "quiescence_observation", "claim_state", "gate_decision", "provider_coordination",
        "executor_domain", "endpoint_domain", "resource_authority_domain", "relative_time_bucket", "right_censored",
        "source_role", "study_claim_boundary", "event_kind", "sequence", "relative_ns",
        "operation_pseudonym", "resource_pseudonym",
        "reason_code",
    }
    if set(event) != required:
        raise ValueError("effect observation has unknown or missing fields")
    for name in ("study_id", "source_id", "operation_kind", "executor_domain", "endpoint_domain", "resource_authority_domain", "relative_time_bucket", "reason_code"):
        _label(event[name], name.replace("_", " "))
    if not isinstance(event["effect_pseudonym"], str) or _PSEUDONYM.fullmatch(event["effect_pseudonym"]) is None:
        raise ValueError("invalid effect pseudonym")
    if not isinstance(event["operation_pseudonym"], str) or _OPERATION_PSEUDONYM.fullmatch(event["operation_pseudonym"]) is None:
        raise ValueError("invalid operation pseudonym")
    if event["resource_pseudonym"] is not None and (not isinstance(event["resource_pseudonym"], str) or _RESOURCE_PSEUDONYM.fullmatch(event["resource_pseudonym"]) is None):
        raise ValueError("invalid resource pseudonym")
    for name, enum_type in _ENUMS.items():
        if name != "source_availability":
            _enum(event[name], enum_type, name.replace("_", " "))
    if not isinstance(event["right_censored"], bool):
        raise ValueError("invalid right-censored value")
    _ordering(event)
    if event["effect_state"] in (EffectState.SUCCEEDED.value, EffectState.FAILED.value) and event["right_censored"]:
        raise ValueError("terminal observation cannot be right-censored")
    if event["event_kind"] == EventKind.TERMINAL.value and event["effect_state"] not in (EffectState.SUCCEEDED.value, EffectState.FAILED.value):
        raise ValueError("terminal event must carry terminal state")
    if event["event_kind"] == EventKind.QUIESCENT.value and event["quiescence_observation"] != Observation.OBSERVED.value:
        raise ValueError("quiescent event requires observed quiescence")
    if event["event_kind"] == EventKind.CLAIM_RETAINED.value and event["claim_state"] != ClaimState.RETAINED.value:
        raise ValueError("claim-retained event requires retained claim")
    if event["event_kind"] == EventKind.CLAIM_RELEASED.value and event["claim_state"] != ClaimState.RELEASED.value:
        raise ValueError("claim-released event requires released claim")
    if event["event_kind"] == EventKind.GATE_REJECTED.value and event["gate_decision"] != GateDecision.REJECTED.value:
        raise ValueError("gate-rejected event requires rejected gate")
    return event


def _ordering(event: Mapping[str, Any]) -> None:
    for name in ("sequence", "relative_ns"):
        value = event[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid {name}")


def _validate_role_fact(event: Mapping[str, Any]) -> None:
    """Reject a fact that its declared source authority cannot attest.

    Unknown/not-applicable values are allowed as diagnostic context.  A fact
    which would affect an aggregate must come from the authority role that
    owns it, so role filtering can never silently erase a claimed result.
    """
    if event.get("event_type") != "effect_observation":
        return
    role = event["source_role"]
    if role in (SourceRole.ENDPOINT.value, SourceRole.WORKER_PROVIDER.value):
        invalid = (
            event["quiescence_observation"] == Observation.OBSERVED.value
            or event["claim_state"] in (ClaimState.RETAINED.value, ClaimState.RELEASED.value)
            or event["gate_decision"] in (GateDecision.ADMITTED.value, GateDecision.REJECTED.value)
        )
    elif role == SourceRole.DEVICE.value:
        invalid = (
            event["outcome_observation"] == Observation.OBSERVED.value
            or event["claim_state"] in (ClaimState.RETAINED.value, ClaimState.RELEASED.value)
            or event["gate_decision"] in (GateDecision.ADMITTED.value, GateDecision.REJECTED.value)
        )
    elif role == SourceRole.OPERATOR.value:
        invalid = (
            event["outcome_observation"] == Observation.OBSERVED.value
            or event["quiescence_observation"] == Observation.OBSERVED.value
            or event["claim_state"] in (ClaimState.RETAINED.value, ClaimState.RELEASED.value)
            or event["gate_decision"] in (GateDecision.ADMITTED.value, GateDecision.REJECTED.value)
            or event["event_kind"]
            not in (EventKind.ADMIN_DISPOSITION.value, EventKind.OBSERVATION_ENDED.value)
        )
    else:  # guest and allocator-gate provenance owns custody facts, not endpoint/device facts.
        invalid = (
            event["outcome_observation"] == Observation.OBSERVED.value
            or event["quiescence_observation"] == Observation.OBSERVED.value
        )
    if invalid:
        raise ValueError("source role is not authoritative for recorded fact")
    if (event["claim_state"] in (ClaimState.RETAINED.value, ClaimState.RELEASED.value)
            or event["gate_decision"] in (GateDecision.ADMITTED.value, GateDecision.REJECTED.value)) and event["resource_pseudonym"] is None:
        raise ValueError("claim or gate fact requires a resource pseudonym")


@dataclass
class TraceRecorder:
    """Bounded generic producer API that persists privacy-safe JSONL only."""

    output: Path
    pseudonymizer: StudyPseudonymizer
    max_events: int = 10_000
    max_sources: int = 64
    _written: int = field(default=0, init=False)
    _dropped: Counter[str] = field(default_factory=Counter, init=False)
    _sources: set[str] = field(default_factory=set, init=False)
    _profiles: dict[str, tuple[str, str]] = field(default_factory=dict, init=False)
    _closed: bool = field(default=False, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _sequence: int = field(default=0, init=False)
    _started_ns: int = field(default_factory=time.monotonic_ns, init=False)

    def __post_init__(self) -> None:
        if self.max_events <= 0 or self.max_sources <= 0:
            raise ValueError("trace bounds must be positive")
        self.output.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.output.open("x", encoding="utf-8").close()
        except FileExistsError as exc:
            raise ValueError("trace output already exists; refusing to append") from exc

    def _ordered(self, event: dict[str, Any]) -> dict[str, Any]:
        event["sequence"] = self._sequence
        event["relative_ns"] = time.monotonic_ns() - self._started_ns
        self._sequence += 1
        return event

    def _write(self, event: dict[str, Any]) -> None:
        checked = validate_event(self._ordered(event))
        _validate_role_fact(checked)
        with self.output.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(checked, sort_keys=True, separators=(",", ":")) + "\n")

    def describe_source(self, source_id: str, role: SourceRole | str,
                        claim_boundary: StudyClaimBoundary | str) -> None:
        """Durably declare an observation authority and the sample's claim limit."""
        with self._lock:
            if self._closed:
                raise RuntimeError("trace recorder is closed")
            _label(source_id, "source id")
            role_value = str(getattr(role, "value", role))
            boundary_value = str(getattr(claim_boundary, "value", claim_boundary))
            profile = {"schema_version": TRACE_SCHEMA_VERSION, "event_type": "source_profile",
                       "study_id": self.pseudonymizer.study_id, "source_id": source_id,
                       "source_role": role_value, "study_claim_boundary": boundary_value}
            # Validate fields before assigning the event's recorder-owned ordering.
            _enum(role_value, SourceRole, "source role")
            _enum(boundary_value, StudyClaimBoundary, "study claim boundary")
            prior = self._profiles.get(source_id)
            shape = (role_value, boundary_value)
            if prior is not None:
                if prior != shape:
                    raise ValueError("source profile cannot change within a study")
                return
            if len(self._profiles) >= self.max_sources:
                raise ValueError("source profile bound exceeded")
            self._write(profile)
            self._profiles[source_id] = shape

    def record(self, *, source_id: str, raw_effect_id: str, raw_operation_id: str,
               event_kind: EventKind | str, operation_kind: str,
               effect_state: EffectState | str, outcome_capability: OutcomeCapability | str,
               quiescence_capability: QuiescenceCapability | str,
               outcome_recovery: RecoveryCapability | str, quiescence_recovery: RecoveryCapability | str,
               outcome_observation: Observation | str, quiescence_observation: Observation | str,
               claim_state: ClaimState | str, gate_decision: GateDecision | str,
               provider_coordination: ProviderCoordination | str, executor_domain: str,
               endpoint_domain: str, resource_authority_domain: str, relative_time_bucket: str,
               right_censored: bool, reason_code: str, raw_resource_id: str | None = None) -> bool:
        with self._lock:
            if self._closed:
                raise RuntimeError("trace recorder is closed")
            _label(source_id, "source id")
            if source_id not in self._profiles:
                raise ValueError("source must be described before recording")
            if source_id not in self._sources and len(self._sources) >= self.max_sources:
                self._dropped[source_id] += 1
                return False
            self._sources.add(source_id)
            if self._written >= self.max_events:
                self._dropped[source_id] += 1
                return False
            values = {
            "schema_version": TRACE_SCHEMA_VERSION, "event_type": "effect_observation",
            "study_id": self.pseudonymizer.study_id, "source_id": source_id,
            "source_role": self._profiles[source_id][0], "study_claim_boundary": self._profiles[source_id][1],
            "event_kind": str(getattr(event_kind, "value", event_kind)),
            "effect_pseudonym": self.pseudonymizer.effect(raw_effect_id),
            "operation_pseudonym": self.pseudonymizer.operation(raw_operation_id),
            "resource_pseudonym": self.pseudonymizer.resource(raw_resource_id) if raw_resource_id is not None else None,
            "operation_kind": operation_kind,
            "effect_state": str(getattr(effect_state, "value", effect_state)),
            "outcome_capability": str(getattr(outcome_capability, "value", outcome_capability)),
            "quiescence_capability": str(getattr(quiescence_capability, "value", quiescence_capability)),
            "outcome_recovery": str(getattr(outcome_recovery, "value", outcome_recovery)),
            "quiescence_recovery": str(getattr(quiescence_recovery, "value", quiescence_recovery)),
            "outcome_observation": str(getattr(outcome_observation, "value", outcome_observation)),
            "quiescence_observation": str(getattr(quiescence_observation, "value", quiescence_observation)),
            "claim_state": str(getattr(claim_state, "value", claim_state)),
            "gate_decision": str(getattr(gate_decision, "value", gate_decision)),
            "provider_coordination": str(getattr(provider_coordination, "value", provider_coordination)),
            "executor_domain": executor_domain, "endpoint_domain": endpoint_domain,
            "resource_authority_domain": resource_authority_domain, "relative_time_bucket": relative_time_bucket,
            "right_censored": right_censored, "reason_code": reason_code,
            }
            # Ordering is recorder-owned, but validate all producer-owned fields first.
            _enum(values["event_kind"], EventKind, "event kind")
            self._write(values)
            self._written += 1
            return True

    def close(self, availability: Mapping[str, SourceAvailability | str] | None = None) -> None:
        with self._lock:
            if self._closed:
                return
            available = availability or {}
            source_ids = sorted(self._sources | set(self._dropped) | set(available) | set(self._profiles))
            if any(source_id not in self._profiles for source_id in source_ids):
                raise ValueError("source status needs a source profile")
            for source_id in source_ids:
                state = str(getattr(available.get(source_id, SourceAvailability.AVAILABLE), "value", available.get(source_id, SourceAvailability.AVAILABLE)))
                if self._dropped[source_id] and state == SourceAvailability.AVAILABLE.value:
                    state = SourceAvailability.PARTIAL.value
                self._write({"schema_version": TRACE_SCHEMA_VERSION, "event_type": "source_status",
                             "study_id": self.pseudonymizer.study_id, "source_id": source_id,
                             "source_availability": state, "dropped_events": self._dropped[source_id]})
            self._closed = True

    def __enter__(self) -> "TraceRecorder":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def load_trace(paths: Iterable[Path]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL in {path}:{line_number}") from exc
            try:
                events.append(validate_event(parsed))
            except ValueError as exc:
                raise ValueError(f"invalid trace event in {path}:{line_number}: {exc}") from exc
    return events


def aggregate(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    items = list(events)
    observations = [validate_event(event) for event in items if event.get("event_type") == "effect_observation"]
    statuses = [validate_event(event) for event in items if event.get("event_type") == "source_status"]
    profiles = [validate_event(event) for event in items if event.get("event_type") == "source_profile"]
    studies = {event["study_id"] for event in observations + statuses + profiles}
    if len(studies) != 1:
        raise ValueError("aggregate requires exactly one study id")
    source_status: dict[str, dict[str, Any]] = {}
    for status in statuses:
        if status["source_id"] in source_status:
            raise ValueError("duplicate source status")
        source_status[status["source_id"]] = status
    source_profiles: dict[str, dict[str, Any]] = {}
    for profile in profiles:
        prior = source_profiles.get(profile["source_id"])
        semantic = {key: profile[key] for key in ("study_id", "source_id", "source_role", "study_claim_boundary")}
        if prior is not None:
            prior_semantic = {key: prior[key] for key in semantic}
            if prior_semantic != semantic:
                raise ValueError("conflicting source profile")
            continue
        source_profiles[profile["source_id"]] = profile
    missing_status = set(source_profiles) - set(source_status)
    if missing_status:
        raise ValueError(f"source profile has no source status: {sorted(missing_status)[0]}")
    extra_status = set(source_status) - set(source_profiles)
    if extra_status:
        raise ValueError(f"source status has no source profile: {sorted(extra_status)[0]}")
    effects = {event["effect_pseudonym"] for event in observations}
    by_source: dict[str, int] = Counter(event["source_id"] for event in observations)
    for source_id in by_source:
        if source_id not in source_status:
            raise ValueError("observation has no source-status accounting")
        if source_id not in source_profiles:
            raise ValueError("observation has no source profile")
    by_source_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in observations + statuses + profiles:
        by_source_events[event["source_id"]].append(event)
    for source_id, source_events in by_source_events.items():
        sequences = [event["sequence"] for event in source_events]
        if len(sequences) != len(set(sequences)):
            raise ValueError(f"trace sequence is not unique for source {source_id}")
        ordered = sorted(source_events, key=lambda event: event["sequence"])
        if any(later["relative_ns"] < earlier["relative_ns"] for earlier, later in zip(ordered, ordered[1:])):
            raise ValueError(f"trace relative time regressed for source {source_id}")
    by_effect: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in observations:
        profile = source_profiles[event["source_id"]]
        if event["source_role"] != profile["source_role"] or event["study_claim_boundary"] != profile["study_claim_boundary"]:
            raise ValueError("observation does not match its source profile")
        _validate_role_fact(event)
        by_effect[(event["source_id"], event["effect_pseudonym"])].append(event)
    final = {
        effect: max(history, key=lambda event: event["sequence"])
        for effect, history in by_effect.items()
    }
    final_events = list(final.values())

    def unique_role_effects(roles: set[str], predicate: Any) -> set[str]:
        return {
            event["effect_pseudonym"] for event in final_events
            if event["source_role"] in roles and predicate(event)
        }

    outcome_roles = {SourceRole.ENDPOINT.value, SourceRole.WORKER_PROVIDER.value}
    claim_roles = {SourceRole.GUEST.value, SourceRole.ALLOCATOR_GATE.value}
    device_roles = {SourceRole.DEVICE.value}
    operator_roles = {SourceRole.OPERATOR.value}
    role_final_counts = Counter(event["source_role"] for event in final_events)
    outcome_effects = unique_role_effects(outcome_roles, lambda _: True)
    terminal_effects = unique_role_effects(outcome_roles, lambda event: event["effect_state"] in (EffectState.SUCCEEDED.value, EffectState.FAILED.value))
    succeeded_effects = unique_role_effects(outcome_roles, lambda event: event["effect_state"] == EffectState.SUCCEEDED.value)
    failed_effects = unique_role_effects(outcome_roles, lambda event: event["effect_state"] == EffectState.FAILED.value)
    terminal_conflicts = succeeded_effects & failed_effects
    claim_history: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in observations:
        if event["source_role"] in claim_roles and event["resource_pseudonym"] is not None:
            claim_history[(event["source_id"], event["effect_pseudonym"], event["resource_pseudonym"])].append(event)
    claim_final = [max(history, key=lambda event: event["sequence"]) for history in claim_history.values()]
    retained = sum(event["claim_state"] == ClaimState.RETAINED.value for event in claim_final)
    released = sum(event["claim_state"] == ClaimState.RELEASED.value for event in claim_final)
    gate_rejected = sum(event["gate_decision"] == GateDecision.REJECTED.value for event in claim_final)
    gate_admitted = sum(event["gate_decision"] == GateDecision.ADMITTED.value for event in claim_final)
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "study_id": next(iter(studies)),
        "scope": "bounded_source_sample_not_prevalence",
        "study_claim_boundaries": sorted({profile["study_claim_boundary"] for profile in source_profiles.values()}),
        "source_roles": dict(sorted(Counter(profile["source_role"] for profile in source_profiles.values()).items())),
        "denominator": {"eligible_effects": len(effects), "final_source_effects": len(final_events), "raw_effect_observations": len(observations), "sources": len(source_status)},
        "raw_events": {"effect_observations": len(observations), "by_kind": dict(sorted(Counter(e["event_kind"] for e in observations).items()))},
        "final_source_effects_by_role": dict(sorted(role_final_counts.items())),
        "final_outcomes": {"eligible_effects": len(outcome_effects), "terminal_effects": len(terminal_effects),
                           "succeeded_effects": len(succeeded_effects - terminal_conflicts), "failed_effects": len(failed_effects - terminal_conflicts),
                           "conflicting_terminal_effects": len(terminal_conflicts),
                           "outcome_observed_effects": len(unique_role_effects(outcome_roles, lambda e: e["outcome_observation"] == Observation.OBSERVED.value))},
        "final_quiescence": {"observed_effects": len(unique_role_effects(device_roles, lambda e: e["quiescence_observation"] == Observation.OBSERVED.value)),
                             "right_censored_effects": len(unique_role_effects(device_roles, lambda e: e["right_censored"]))},
        "final_claims": {"retained_resource_coordinates": retained, "released_resource_coordinates": released,
                         "final_resource_coordinates": len(claim_final)},
        "final_gates": {"rejected_resource_coordinates": gate_rejected, "admitted_resource_coordinates": gate_admitted,
                        "final_resource_coordinates": len(claim_final)},
        "administrative_dispositions": {
            "observed_effects": len(unique_role_effects(
                operator_roles,
                lambda event: event["event_kind"] == EventKind.ADMIN_DISPOSITION.value,
            )),
        },
        "right_censored_effects": len({event["effect_pseudonym"] for event in final_events if event["right_censored"]}),
        "missing_sources": sorted(source for source, status in source_status.items() if status["source_availability"] == SourceAvailability.MISSING.value),
        "partial_sources": sorted(source for source, status in source_status.items() if status["source_availability"] == SourceAvailability.PARTIAL.value),
        "dropped_events": sum(status["dropped_events"] for status in source_status.values()),
        "provider_coordination": dict(sorted(Counter(e["provider_coordination"] for e in observations).items())),
        "events_by_source": dict(sorted(by_source.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate privacy-safe trace JSONL")
    validate.add_argument("--input", action="append", type=Path, required=True)
    summary = commands.add_parser("aggregate", help="write a bounded-sample aggregate")
    summary.add_argument("--input", action="append", type=Path, required=True)
    summary.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    events = load_trace(args.input)
    if args.command == "validate":
        # Aggregate performs cross-event source-profile, source-status, role,
        # and per-source ordering validation without exporting any identities.
        aggregate(events)
        print(json.dumps({"valid_events": len(events), "schema_version": TRACE_SCHEMA_VERSION}, sort_keys=True))
        return
    result = aggregate(events)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
