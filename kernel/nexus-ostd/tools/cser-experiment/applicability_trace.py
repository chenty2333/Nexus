#!/usr/bin/env python3
"""Privacy-bounded applicability traces for CSER endpoint studies.

This module is deliberately independent of the endpoint and guest protocols.
Producers submit a small, validated observation through :class:`TraceRecorder`;
its primary output replaces the producer's local effect identifier with a
per-study HMAC pseudonym before it reaches JSONL. An explicit, separate
local-only raw-retention sink can preserve the source-labelled identifiers for
audit, but it is never a replacement for the publishable trace. The resulting
trace describes one bounded source/sample, not workload or industry prevalence.

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
import os
import re
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping


TRACE_SCHEMA_VERSION = 1
RAW_TRACE_SCHEMA_VERSION = 1
RAW_PUBLICATION_SCHEMA_VERSION = 1
_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}\Z")
_PSEUDONYM = re.compile(r"e1_[0-9a-f]{64}\Z")
_OPERATION_PSEUDONYM = re.compile(r"o1_[0-9a-f]{64}\Z")
_RESOURCE_PSEUDONYM = re.compile(r"r1_[0-9a-f]{64}\Z")


def _publication_marker(output: Path) -> Path:
    return output.with_name(output.name + ".publication.json")


def _fsync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_fsynced(path: Path, payload: bytes, *, exclusive: bool) -> None:
    mode = "xb" if exclusive else "wb"
    with path.open(mode) as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


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


def validate_raw_event(item: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a local-only raw-retention record.

    Raw retention is deliberately a separate envelope, never an alternate
    published trace format.  Its embedded sanitized event makes every retained
    row independently comparable with its public counterpart while the raw
    identifiers permit local re-aggregation when the study key is available.
    """
    if not isinstance(item, Mapping):
        raise ValueError("raw trace event must be an object")
    record = dict(item)
    required = {"raw_schema_version", "raw_event_type", "sanitized_event", "raw_identifiers"}
    if set(record) != required or record["raw_schema_version"] != RAW_TRACE_SCHEMA_VERSION:
        raise ValueError("unsupported raw trace schema")
    sanitized = validate_event(record["sanitized_event"])
    if record["raw_event_type"] != sanitized["event_type"]:
        raise ValueError("raw trace event type does not match sanitized event")
    identifiers = record["raw_identifiers"]
    if sanitized["event_type"] != "effect_observation":
        if identifiers is not None:
            raise ValueError("raw source metadata cannot carry identifiers")
    else:
        if not isinstance(identifiers, Mapping) or set(identifiers) != {
            "effect_id", "operation_id", "resource_id",
        }:
            raise ValueError("raw observation identifiers are incomplete")
        for name in ("effect_id", "operation_id"):
            value = identifiers[name]
            if not isinstance(value, str) or not value or len(value) > 512:
                raise ValueError(f"invalid raw {name}")
        resource = identifiers["resource_id"]
        if resource is not None and (not isinstance(resource, str) or not resource or len(resource) > 512):
            raise ValueError("invalid raw resource_id")
    return record


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
    """Bounded producer API with an optional, separate local raw-retention sink.

    ``output`` is always the publication-safe HMAC-pseudonymized trace.
    ``raw_output`` is opt-in local evidence retention and must be a distinct
    path; callers are responsible for keeping it outside any publish bundle.
    """

    output: Path
    pseudonymizer: StudyPseudonymizer
    max_events: int = 10_000
    max_sources: int = 64
    raw_output: Path | None = None
    _written: int = field(default=0, init=False)
    _dropped: Counter[str] = field(default_factory=Counter, init=False)
    _sources: set[str] = field(default_factory=set, init=False)
    _profiles: dict[str, tuple[str, str]] = field(default_factory=dict, init=False)
    _closed: bool = field(default=False, init=False)
    _poisoned: bool = field(default=False, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _sequence: int = field(default=0, init=False)
    _started_ns: int = field(default_factory=time.monotonic_ns, init=False)
    _output_stream: Any = field(init=False, default=None, repr=False)
    _raw_stream: Any = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if self.max_events <= 0 or self.max_sources <= 0:
            raise ValueError("trace bounds must be positive")
        if self.raw_output is not None and self.raw_output.resolve() == self.output.resolve():
            raise ValueError("raw trace output must differ from sanitized output")
        self.output.parent.mkdir(parents=True, exist_ok=True)
        if self.raw_output is None:
            if self.output.exists():
                raise ValueError("trace output already exists; refusing to append")
            try:
                self._output_stream = self.output.open("xb+")
            except FileExistsError as exc:
                raise ValueError("trace output already exists; refusing to append") from exc
            return

        self.raw_output.parent.mkdir(parents=True, exist_ok=True)
        marker = _publication_marker(self.output)
        temporary = self.output.with_name(self.output.name + ".tmp")
        marker_temporary = marker.with_name(marker.name + ".tmp")
        if any(path.exists() for path in (self.output, self.raw_output, marker, temporary, marker_temporary)):
            raise ValueError("raw publication output already exists or is incomplete; refusing to append")
        incomplete = json.dumps({
            "publication_schema_version": RAW_PUBLICATION_SCHEMA_VERSION,
            "mode": "raw_authoritative_derivation",
            "state": "incomplete",
        }, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            # The marker becomes durable before raw observation begins. A
            # crash can therefore never make a raw-mode trace look complete.
            _write_fsynced(marker, incomplete, exclusive=True)
            _fsync_parent(marker)
            self._raw_stream = self.raw_output.open("xb+")
        except (FileExistsError, OSError) as exc:
            if self._raw_stream is not None:
                self._raw_stream.close()
            for path in (self.raw_output, marker):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            if isinstance(exc, FileExistsError):
                raise ValueError("raw publication output already exists or is incomplete; refusing to append") from exc
            raise RuntimeError("unable to create raw authoritative trace") from exc

    def _ordered(self, event: dict[str, Any]) -> dict[str, Any]:
        event["sequence"] = self._sequence
        event["relative_ns"] = time.monotonic_ns() - self._started_ns
        self._sequence += 1
        return event

    def _assert_active(self) -> None:
        if self._closed:
            raise RuntimeError("trace recorder is closed")
        if self._poisoned:
            raise RuntimeError("trace recorder is poisoned after output failure")

    def _rollback(self, streams: list[tuple[Any, int]]) -> None:
        for stream, offset in streams:
            try:
                stream.seek(offset)
                stream.truncate()
                stream.flush()
            except Exception:
                # The recorder is poisoned regardless; the caller must retain
                # neither file as a complete measurement if rollback itself
                # fails on the host filesystem.
                pass

    def _write(self, event: dict[str, Any], *, raw_identifiers: Mapping[str, str | None] | None = None) -> None:
        self._assert_active()
        checked = validate_event(self._ordered(event))
        _validate_role_fact(checked)
        raw: dict[str, Any] | None = None
        if self.raw_output is not None:
            raw = validate_raw_event({
                "raw_schema_version": RAW_TRACE_SCHEMA_VERSION,
                "raw_event_type": checked["event_type"],
                "sanitized_event": checked,
                "raw_identifiers": None if raw_identifiers is None else dict(raw_identifiers),
            })
        # Serialize and validate before changing a recorder-owned stream.
        sanitized_line = (json.dumps(checked, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        raw_line = None if raw is None else (json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if self.raw_output is not None:
            assert self._raw_stream is not None and raw_line is not None
            raw_offset = self._raw_stream.tell()
            try:
                self._raw_stream.write(raw_line)
                self._raw_stream.flush()
                os.fsync(self._raw_stream.fileno())
            except Exception as exc:
                self._rollback([(self._raw_stream, raw_offset)])
                self._poisoned = True
                raise RuntimeError("raw authoritative trace write failed; recorder is poisoned") from exc
            return

        assert self._output_stream is not None
        output_offset = self._output_stream.tell()
        try:
            self._output_stream.write(sanitized_line)
            self._output_stream.flush()
        except Exception as exc:
            self._rollback([(self._output_stream, output_offset)])
            self._poisoned = True
            raise RuntimeError("trace recorder output failed; recorder is poisoned") from exc

    def _close_streams(self) -> None:
        first_error: Exception | None = None
        for stream in (self._output_stream, self._raw_stream):
            if stream is None:
                continue
            try:
                stream.close()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise RuntimeError("trace recorder output close failed") from first_error

    def _finalize_raw_publication(self) -> None:
        """Derive a publishable trace only from a closed, fsynced raw log."""
        assert self.raw_output is not None and self._raw_stream is not None
        marker = _publication_marker(self.output)
        temporary = self.output.with_name(self.output.name + ".tmp")
        marker_temporary = marker.with_name(marker.name + ".tmp")
        try:
            self._raw_stream.flush()
            os.fsync(self._raw_stream.fileno())
            self._raw_stream.close()
            self._raw_stream = None
            records = load_raw_trace([self.raw_output], self.pseudonymizer)
            sanitized = [record["sanitized_event"] for record in records]
            # Cross-event validation makes the completed marker mean more than
            # successful JSON decoding (profiles and source statuses agree).
            aggregate(sanitized)
            payload = b"".join(
                (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                for event in sanitized
            )
            _write_fsynced(temporary, payload, exclusive=True)
            os.replace(temporary, self.output)
            _fsync_parent(self.output)
            completed = {
                "publication_schema_version": RAW_PUBLICATION_SCHEMA_VERSION,
                "mode": "raw_authoritative_derivation",
                "state": "complete",
                "study_id": self.pseudonymizer.study_id,
                # Do not publish even an unsalted raw-log fingerprint: the
                # completed set exposes only a study-keyed HMAC commitment.
                "raw_hmac_sha256": hmac.new(self.pseudonymizer.key, self.raw_output.read_bytes(), hashlib.sha256).hexdigest(),
                "sanitized_sha256": hashlib.sha256(payload).hexdigest(),
                "event_count": len(sanitized),
            }
            _write_fsynced(marker_temporary,
                           json.dumps(completed, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n",
                           exclusive=True)
            # This atomic replacement is the process-crash publication pivot.
            # It is deliberately the final fallible action: all derived output
            # and its directory, plus this marker temporary, were fsynced
            # above. We make no physical-power-loss durability claim here.
            os.replace(marker_temporary, marker)
        except Exception as exc:
            self._poisoned = True
            for path in (temporary, marker_temporary):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            raise RuntimeError("raw trace publication failed; completion marker remains incomplete") from exc

    def describe_source(self, source_id: str, role: SourceRole | str,
                        claim_boundary: StudyClaimBoundary | str) -> None:
        """Durably declare an observation authority and the sample's claim limit."""
        with self._lock:
            self._assert_active()
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
            self._assert_active()
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
            self._write(values, raw_identifiers={
                "effect_id": raw_effect_id,
                "operation_id": raw_operation_id,
                "resource_id": raw_resource_id,
            })
            self._written += 1
            return True

    def close(self, availability: Mapping[str, SourceAvailability | str] | None = None) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._assert_active()
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
                if self.raw_output is not None:
                    self._finalize_raw_publication()
            finally:
                self._closed = True
                self._close_streams()

    def abort(self) -> None:
        """Stop without synthesizing source status or publishing raw output.

        For raw-authoritative traces the durable marker deliberately remains
        ``incomplete``. This is the only cleanup action permitted after a
        producer/workflow exception.
        """
        with self._lock:
            if self._closed:
                return
            self._poisoned = True
            self._closed = True
            self._close_streams()

    def __enter__(self) -> "TraceRecorder":
        return self

    def __exit__(self, exception_type: object, *_: object) -> None:
        if exception_type is None:
            self.close()
        else:
            self.abort()


def _verify_publication(path: Path, *, require_marker: bool) -> None:
    marker = _publication_marker(path)
    if not marker.exists():
        if require_marker:
            raise ValueError(f"published trace lacks completion marker: {path}")
        return
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"published trace has invalid completion marker: {path}") from exc
    expected = {
        "publication_schema_version", "mode", "state", "study_id",
        "raw_hmac_sha256", "sanitized_sha256", "event_count",
    }
    if not isinstance(value, Mapping) or set(value) != expected or value.get("publication_schema_version") != RAW_PUBLICATION_SCHEMA_VERSION or value.get("mode") != "raw_authoritative_derivation" or value.get("state") != "complete":
        raise ValueError(f"published trace is incomplete: {path}")
    if not path.is_file():
        raise ValueError(f"published trace missing finalized JSONL: {path}")
    payload = path.read_bytes()
    if value["sanitized_sha256"] != hashlib.sha256(payload).hexdigest():
        raise ValueError(f"published trace digest mismatch: {path}")
    if not isinstance(value["event_count"], int) or value["event_count"] < 0:
        raise ValueError(f"published trace has invalid event count: {path}")
    if sum(bool(line) for line in payload.splitlines()) != value["event_count"]:
        raise ValueError(f"published trace event count mismatch: {path}")


def load_trace(paths: Iterable[Path], *, require_publication_marker: bool = False) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in paths:
        _verify_publication(path, require_marker=require_publication_marker)
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


def load_published_trace(paths: Iterable[Path]) -> list[dict[str, Any]]:
    """Load only a completed raw-authoritative publication set."""
    return load_trace(paths, require_publication_marker=True)


def _validate_raw_binding(record: Mapping[str, Any], pseudonymizer: StudyPseudonymizer) -> dict[str, Any]:
    """Validate that local identifiers reproduce the embedded HMAC projection."""
    checked = validate_raw_event(record)
    event = checked["sanitized_event"]
    if event["study_id"] != pseudonymizer.study_id:
        raise ValueError("raw trace study does not match pseudonymizer")
    identifiers = checked["raw_identifiers"]
    if event["event_type"] == "effect_observation":
        assert isinstance(identifiers, Mapping)
        if event["effect_pseudonym"] != pseudonymizer.effect(identifiers["effect_id"]):
            raise ValueError("raw effect id does not match pseudonym")
        if event["operation_pseudonym"] != pseudonymizer.operation(identifiers["operation_id"]):
            raise ValueError("raw operation id does not match pseudonym")
        resource = identifiers["resource_id"]
        expected_resource = None if resource is None else pseudonymizer.resource(resource)
        if event["resource_pseudonym"] != expected_resource:
            raise ValueError("raw resource id does not match pseudonym")
    return checked


def load_raw_trace(paths: Iterable[Path], pseudonymizer: StudyPseudonymizer) -> list[dict[str, Any]]:
    """Load the explicitly local-only raw-retention envelope.

    This function intentionally requires the study pseudonymizer: raw IDs are
    useful local evidence only when they recompute every embedded public HMAC
    pseudonym. It does not accept a sanitized trace.
    """
    records: list[dict[str, Any]] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid raw JSONL in {path}:{line_number}") from exc
            try:
                records.append(_validate_raw_binding(parsed, pseudonymizer))
            except ValueError as exc:
                raise ValueError(f"invalid raw trace event in {path}:{line_number}: {exc}") from exc
    return records


def aggregate_raw_trace(records: Iterable[Mapping[str, Any]], pseudonymizer: StudyPseudonymizer) -> dict[str, Any]:
    """Re-aggregate local raw retention through the exact sanitized projection."""
    return aggregate([_validate_raw_binding(record, pseudonymizer)["sanitized_event"] for record in records])


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
