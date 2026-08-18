#!/usr/bin/env python3
"""Matched CSER3 logical-handoff crash controller.

This is intentionally separate from ``matrix_controller.py``: the existing
Tool+DMA schema must not acquire handoff-only observations.  A row is accepted
only after an initial cut, a terminal recovery, and a second stable reopen all
produce compatible guest-owned receipts.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import hashlib
import math
import os
import re
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from matrix_controller import (_connect_qemu_server, _kill_process_group, _read_one_frame,
                               _run_recovery_launcher)
from matrix_protocol import BarrierProtocolError, UART_WRITE_INTER_CHUNK_SECONDS, barrier_ack, config_response, paced_sendall, parse_barrier, parse_config_hello
from handoff_identity import (ParentDescriptorContext, child_transport_effect_id,
                              expected_child_request, expected_source_request,
                              validate_child_descriptor_v1)

SCHEMA_VERSION = 1
VARIANTS = frozenset(("cser", "baseline"))
CUTPOINTS = {
    "descriptor_discovered": 21,
    "parent_ack_or_descriptor_durable": 22,
    "child_installed": 23,
    "handoff_committed": 24,
    "child_first_observed": 25,
}
DEFAULT_CUTPOINTS = tuple(CUTPOINTS)
_TERMINAL_PREFIX = "CSER_HANDOFF_TERMINAL "
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_TRIAL_TOKEN = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_KILL_ATTEMPTS = 3
_CONTAINER_KILL_TIMEOUT_SECONDS = 5
_MEDIA_HASH_CHUNK_BYTES = 1024 * 1024
_HANDOFF_CONTAINER_LABELS = {
    "nexus.cser-experiment": "handoff",
}


def _validate_timeout(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{label} must be finite and positive")
    return float(value)


def observe_handoff_barriers(client: socket.socket, run_id: str, target: int, *, catalog_digest: str,
                             namespace_id: str, authority_id: str, effect_id: str,
                             uart_pace_seconds: float = 0.0) -> bool:
    """Send CONFIG, ACK exactly the strict ordered prefix, then cut at target."""
    if target not in CUTPOINTS.values():
        raise BarrierProtocolError("target is outside the handoff barrier sequence")
    parse_config_hello(_read_one_frame(client))
    paced_sendall(client, config_response(run_id, catalog_digest, namespace_id, authority_id, effect_id),
                  inter_chunk_seconds=uart_pace_seconds)
    expected = 21
    while True:
        observed = parse_barrier(_read_one_frame(client), expected_run_id=run_id)
        if observed != expected or observed > 25:
            raise BarrierProtocolError(f"unexpected handoff barrier {observed}; expected {expected}")
        if observed == target:
            client.shutdown(socket.SHUT_RDWR)
            return False
        paced_sendall(client, barrier_ack(run_id, observed), inter_chunk_seconds=uart_pace_seconds)
        expected += 1


def _one_terminal(lines: Iterable[bytes], *, variant: str, run_id: str) -> dict[str, Any]:
    values: list[str] = []
    for raw in lines:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("handoff recovery serial is not UTF-8") from exc
        values.extend(line[len(_TERMINAL_PREFIX):] for line in text.splitlines() if line.startswith(_TERMINAL_PREFIX))
    if len(values) != 1:
        raise ValueError("recovery must emit exactly one CSER_HANDOFF_TERMINAL receipt")
    try:
        receipt = json.loads(values[0])
    except json.JSONDecodeError as exc:
        raise ValueError("invalid handoff terminal receipt JSON") from exc
    if not isinstance(receipt, dict):
        raise ValueError("handoff terminal receipt must be an object")
    validate_receipt(receipt, variant=variant, run_id=run_id)
    return receipt


def receipt_from_log(path: Path, *, variant: str, run_id: str) -> dict[str, Any]:
    def lines() -> Iterable[bytes]:
        with path.open("rb") as handle:
            while line := handle.readline(65537):
                if len(line) > 65536:
                    raise ValueError("handoff recovery serial line is too large")
                yield line
    return _one_terminal(lines(), variant=variant, run_id=run_id)


def validate_receipt(value: dict[str, Any], *, variant: str, run_id: str) -> None:
    if not isinstance(value, dict):
        raise ValueError("handoff terminal receipt must be an object")
    required = {"version", "variant", "run_id", "descriptor_digest", "parent_transferred", "child_installed",
                "child_intent", "child_terminal", "coordinate_gate", "recovery_steps", "scope", "device_actions"}
    if set(value) != required:
        raise ValueError("handoff terminal receipt has invalid schema")
    if value["version"] != 1 or value["variant"] != variant or value["run_id"] != run_id:
        raise ValueError("handoff terminal receipt identity mismatch")
    if not isinstance(value["descriptor_digest"], str) or not _HEX64.fullmatch(value["descriptor_digest"]):
        raise ValueError("handoff receipt lacks descriptor digest")
    if any(value[name] is not True for name in ("parent_transferred", "child_installed", "child_intent", "child_terminal")):
        raise ValueError("handoff receipt is not terminally committed")
    if isinstance(value["recovery_steps"], bool) or not isinstance(value["recovery_steps"], int) or value["recovery_steps"] < 0:
        raise ValueError("handoff receipt has invalid recovery_steps")
    if value["scope"] != "logical" or value["device_actions"] != 0:
        raise ValueError("handoff receipt overclaims physical scope")
    gate = value["coordinate_gate"]
    if not isinstance(gate, dict) or set(gate) != {"live_gate_observed", "reject_while_live", "admit_after_terminal", "revision_unchanged", "head_unchanged"}:
        raise ValueError("handoff receipt has invalid coordinate gate")
    if not isinstance(gate["live_gate_observed"], bool) or not isinstance(gate["admit_after_terminal"], bool) or gate["admit_after_terminal"] is not True:
        raise ValueError("handoff receipt lacks terminal coordinate admission")
    if gate["reject_while_live"] not in (True, None) or (gate["live_gate_observed"] != (gate["reject_while_live"] is True)):
        raise ValueError("handoff receipt makes a dishonest live-gate claim")
    for key in ("revision_unchanged", "head_unchanged"):
        if gate[key] not in (True, None):
            raise ValueError("handoff receipt has invalid read-only provenance")


def verify_endpoint_ledgers(trial_dir: Path, *, namespace_id: str, authority_id: str, parent_effect_id: str,
                            run_id: str, catalog_digest: str, descriptor_digest: str) -> dict[str, dict[str, Any]]:
    """Verify both independent durable stores, never receipt-supplied counters.

    The reference provider persists one row per exact key; a single matching
    endpoint terminal plus a single matching provider row is its durable
    apply-once/dedup witness.  There is intentionally no host counter guess.
    """
    child_effect_id = child_transport_effect_id(namespace_id, authority_id, parent_effect_id, run_id, catalog_digest)
    records: dict[str, dict[str, Any]] = {}
    exact: dict[str, tuple[Any, ...]] = {}
    for name, file_role, effect in (("source", "parent", parent_effect_id),
                                    ("child", "child", child_effect_id)):
        endpoint_path = trial_dir / f"handoff-{file_role}-endpoint.sqlite"
        provider_path = trial_dir / f"handoff-{file_role}-provider.sqlite"
        if not endpoint_path.is_file() or not provider_path.is_file():
            raise ValueError(f"{name} endpoint/provider ledger is missing")
        with closing(sqlite3.connect(f"file:{endpoint_path}?mode=ro", uri=True)) as endpoint, closing(sqlite3.connect(f"file:{provider_path}?mode=ro", uri=True)) as provider:
            endpoint_rows = endpoint.execute(
                "SELECT operation_key,input_digest,payload,state,result,catalog_digest,output_kind,output,provider_applied_at_ns FROM operations "
                "WHERE namespace_id=? AND authority_id=? AND effect_id=? AND run_id=?",
                (namespace_id, authority_id, effect, run_id),
            ).fetchall()
            if len(endpoint_rows) != 1:
                raise ValueError(f"{name} endpoint must contain exactly one source-bound operation")
            operation_key, input_digest, payload, state, result, catalog, output_kind, output, applied_at_ns = endpoint_rows[0]
            if state != "succeeded" or result != "success" or catalog != catalog_digest:
                raise ValueError(f"{name} endpoint operation is not a matching succeeded terminal")
            provider_rows = provider.execute(
                "SELECT operation_key,input_digest,payload,state,result,output_kind,output,applied_at_ns FROM provider_operations WHERE namespace_id=? AND authority_id=? AND effect_id=? AND catalog_digest=? AND run_id=?",
                (namespace_id, authority_id, effect, catalog_digest, run_id),
            ).fetchall()
            if len(provider_rows) != 1 or tuple(provider_rows[0]) != (operation_key, input_digest, payload, "succeeded", "success", output_kind, output, applied_at_ns):
                raise ValueError(f"{name} provider/endpoint exact-key outcome differs")
        exact[name] = (operation_key, input_digest, payload, output_kind, output)
        records[name] = {"operation_key": operation_key, "input_digest": input_digest,
                         "endpoint_terminal_rows": 1, "provider_application_rows": 1,
                         "dedup_consistent": True}
    source_key, source_input, source_payload, source_kind, source_output = exact["source"]
    child_key, child_input, child_payload, child_kind, child_output = exact["child"]
    parent = ParentDescriptorContext(root=0x4841_4e44, sequence=1, component=6)
    expected_source_key, expected_source_payload, expected_source_input = expected_source_request(
        parent=parent
    )
    if (source_key, source_input, source_payload) != (
        expected_source_key,
        expected_source_input,
        expected_source_payload,
    ):
        raise ValueError("source endpoint/provider request is not canonical")
    if source_kind != "child_descriptor_v1":
        raise ValueError("source endpoint/provider output is not a child descriptor")
    import hashlib
    if hashlib.sha256(source_output).hexdigest() != descriptor_digest:
        raise ValueError("source endpoint/provider descriptor output does not bind the guest receipt")
    try:
        validate_child_descriptor_v1(source_output, parent=parent, catalog_digest=catalog_digest, input_digest=source_input)
        expected_key, expected_payload, expected_input = expected_child_request(source_output, parent=parent)
    except Exception as exc:
        raise ValueError("source descriptor cannot derive the exact child request") from exc
    if (child_key, child_input, child_payload) != (expected_key, expected_input, expected_payload):
        raise ValueError("child endpoint/provider request does not match the source descriptor")
    if (child_kind, child_output) != ("none", b""):
        raise ValueError("child endpoint/provider must have none/empty output")
    return records


def compare_recoveries(first: dict[str, Any], second: dict[str, Any]) -> None:
    # A stable reopen cannot retroactively claim an observation made only in
    # recovery one.  Its coordinate identity must otherwise remain stable.
    if (second["coordinate_gate"]["live_gate_observed"]
            or second["coordinate_gate"]["reject_while_live"] is not None
            or second["coordinate_gate"]["revision_unchanged"] is not None
            or second["coordinate_gate"]["head_unchanged"] is not None):
        raise ValueError("second recovery claims an unobserved live gate")
    keys = ("version", "variant", "run_id", "descriptor_digest", "parent_transferred", "child_installed", "child_intent", "child_terminal", "scope", "device_actions")
    if any(first[key] != second[key] for key in keys):
        raise ValueError("handoff terminal identity changed across stable recovery")
    if first["coordinate_gate"]["admit_after_terminal"] != second["coordinate_gate"]["admit_after_terminal"]:
        raise ValueError("handoff coordinate identity changed across stable recovery")


def _kill(process: subprocess.Popen[bytes]) -> None:
    _kill_process_group(process, stage="handoff initial", force=True)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_MEDIA_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _source_snapshot(path: Path) -> tuple[int, int, int, int, int]:
    stat = path.lstat()
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"base media is not a regular non-symlink file: {path}")
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_mode


def _media_fingerprint(path: Path) -> tuple[int, int, int, int, int, str]:
    """Capture one stable staged-file identity and content digest."""
    before = _source_snapshot(path)
    digest = _sha256_file(path)
    after = _source_snapshot(path)
    if before != after:
        raise ValueError(f"staged media changed while being verified: {path}")
    return (*after, digest)


def _verify_staged_media(expected: dict[Path, tuple[int, int, int, int, int, str]]) -> None:
    """Revalidate every staged path immediately before launching the guest."""
    for path, fingerprint in expected.items():
        try:
            current = _media_fingerprint(path)
        except (OSError, ValueError) as exc:
            raise ValueError(f"staged media is not stable at execution boundary: {path}") from exc
        if current != fingerprint:
            raise ValueError(f"staged media was replaced or modified before execution: {path}")


def _stage_media(trial_dir: Path, sources: Iterable[str | Path]) -> list[Path]:
    """Copy stable, non-aliased media into a trial-owned directory.

    Handoff rows are independent evidence artifacts.  A symlink or a silent
    basename overwrite would let two rows claim the same bytes while the
    controller records only the last destination.  Hashing both sides before
    and after the copy also makes a concurrent source mutation fail closed.
    """
    media_dir = trial_dir / "media"
    media_dir.mkdir()
    resolved_sources: list[Path] = []
    basenames: set[str] = set()
    for source in sources:
        original = Path(source)
        component = original
        has_symlink_component = False
        while component != component.parent:
            if component.is_symlink():
                has_symlink_component = True
                break
            component = component.parent
        if has_symlink_component:
            raise ValueError(f"base media must not be a symlink: {original}")
        resolved = original.resolve()
        if not resolved.is_file() or resolved.is_symlink():
            raise ValueError(f"base media is not a regular non-symlink file: {original}")
        if resolved.name in basenames:
            raise ValueError(f"base media basename conflict: {resolved.name}")
        basenames.add(resolved.name)
        resolved_sources.append(resolved)

    media: list[Path] = []
    for source in resolved_sources:
        destination = media_dir / source.name
        source_before = _source_snapshot(source)
        before = _sha256_file(source)
        subprocess.run(
            ["cp", "--reflink=auto", "--preserve=mode,timestamps", str(source), str(destination)],
            check=True,
        )
        copied = _sha256_file(destination)
        source_after = _source_snapshot(source)
        after = _sha256_file(source)
        if source_before != source_after or before != after or copied != before:
            raise ValueError(
                f"base media changed or copy digest mismatched: source={source} destination={destination}"
            )
        media.append(destination)
    return media


def _container_labels(container_id: str) -> dict[str, str]:
    completed = subprocess.run(
        ["/usr/bin/docker", "inspect", "--format", "{{json .Config.Labels}}", container_id],
        check=False, capture_output=True, text=True, timeout=15,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"container inspect failed ({completed.returncode}): {completed.stderr.strip()}")
    try:
        labels = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("container inspect returned invalid labels") from exc
    if not isinstance(labels, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in labels.items()):
        raise RuntimeError("container inspect returned invalid labels")
    return labels


def _matching_handoff_container(run_id: str, trial_token: str, *, allow_absent: bool) -> str | None:
    """Return the sole running container bearing this controller's labels."""
    completed = subprocess.run(
        ["/usr/bin/docker", "ps", "--quiet", "--filter", "label=nexus.cser-experiment=handoff",
         "--filter", f"label=nexus.cser-run-id={run_id}",
         "--filter", f"label=nexus.cser-trial-token={trial_token}"],
        check=False, capture_output=True, text=True, timeout=15,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"handoff container discovery failed ({completed.returncode}): {completed.stderr.strip()}")
    raw_candidates = [value for value in completed.stdout.splitlines() if value]
    if any(not _CID.fullmatch(value) for value in raw_candidates):
        raise RuntimeError("handoff container discovery returned an invalid container id")
    candidates = raw_candidates
    if not candidates and allow_absent:
        return None
    if len(candidates) != 1:
        raise RuntimeError(f"handoff container identity is uncertain (found {len(candidates)} matching running containers)")
    return candidates[0]


def _kill_container(cid_path: Path, *, run_id: str, trial_token: str, allow_absent: bool = False) -> str | None:
    """Crash only the exact labelled handoff container, even without a cidfile."""
    if not (_HEX32.fullmatch(run_id) and _TRIAL_TOKEN.fullmatch(trial_token)):
        raise RuntimeError("invalid handoff container identity")
    try:
        cid = cid_path.read_text(encoding="ascii").strip()
    except OSError:
        cid = _matching_handoff_container(run_id, trial_token, allow_absent=allow_absent)
        if cid is None:
            return None
    else:
        if not _CID.fullmatch(cid):
            raise RuntimeError("invalid container cid")
    expected_labels = _HANDOFF_CONTAINER_LABELS | {
        "nexus.cser-run-id": run_id,
        "nexus.cser-trial-token": trial_token,
    }
    labels = _container_labels(cid)
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise RuntimeError("container identity is uncertain: handoff labels do not match")
    failures: list[str] = []
    for attempt in range(1, _CONTAINER_KILL_ATTEMPTS + 1):
        try:
            completed = subprocess.run(["/usr/bin/docker", "kill", cid], check=False,
                                       capture_output=True, text=True,
                                       timeout=_CONTAINER_KILL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            failures.append(f"attempt {attempt}: timeout after {_CONTAINER_KILL_TIMEOUT_SECONDS}s")
            continue
        if completed.returncode == 0:
            return cid
        failures.append(f"attempt {attempt}: exit {completed.returncode}: {completed.stderr.strip()}")
    raise RuntimeError(
        f"container kill failed after {_CONTAINER_KILL_ATTEMPTS} bounded attempts for {cid}: "
        + "; ".join(failures)
    )


def run_trial(args: argparse.Namespace) -> dict[str, Any]:
    args.timeout_seconds = _validate_timeout(args.timeout_seconds, "QEMU timeout")
    args.recovery_timeout_seconds = _validate_timeout(args.recovery_timeout_seconds, "recovery timeout")
    trial_dir = args.trial_dir.resolve(); trial_dir.mkdir(parents=True, exist_ok=False)
    cid_path = trial_dir / "container.cid"
    trial_token = __import__("hashlib").sha256(str(trial_dir).encode("utf-8")).hexdigest()
    media = _stage_media(trial_dir, args.media)
    staged_media = {path: _media_fingerprint(path) for path in media}
    env = os.environ.copy(); env.update({"CSER_EXPERIMENT_LANE": "handoff", "CSER_EXPERIMENT_VARIANT": args.variant,
        "CSER_EXPERIMENT_RUN_ID": args.run_id, "CSER_EXPERIMENT_TRIAL_DIR": str(trial_dir),
        "CSER_EXPERIMENT_CATALOG_DIGEST": args.catalog_digest, "CSER_EXPERIMENT_NAMESPACE_ID": args.namespace_id,
        "CSER_EXPERIMENT_AUTHORITY_ID": args.authority_id, "CSER_EXPERIMENT_EFFECT_ID": args.effect_id,
        "CSER_EXPERIMENT_BARRIER_SOCKET": str(args.barrier_socket),
        "CSER_EXPERIMENT_CID_FILE": str(cid_path),
        "CSER_EXPERIMENT_TRIAL_TOKEN": trial_token})
    initial_out, initial_err = (trial_dir / "initial.stdout.log").open("wb"), (trial_dir / "initial.stderr.log").open("wb")
    try:
        # The staged destination is mutable until this point (and is later
        # updated by recovery).  Recheck inode, mode, size, and digest at the
        # execution boundary so a symlink or replacement cannot be silently
        # consumed by the initial QEMU launcher.
        _verify_staged_media(staged_media)
        process = subprocess.Popen(args.guest, env=env, start_new_session=True, stdout=initial_out, stderr=initial_err)
    except BaseException:
        initial_out.close(); initial_err.close()
        raise
    container_id: str | None = None
    container_terminated = False
    try:
        with _connect_qemu_server(args.barrier_socket, args.timeout_seconds) as client:
            observe_handoff_barriers(client, args.run_id, args.cutpoint_id, catalog_digest=args.catalog_digest,
                namespace_id=args.namespace_id, authority_id=args.authority_id, effect_id=args.effect_id,
                uart_pace_seconds=UART_WRITE_INTER_CHUNK_SECONDS if args.real_qemu else 0.0)
        if args.real_qemu:
            container_id = _kill_container(cid_path, run_id=args.run_id, trial_token=trial_token)
            container_terminated = True
    finally:
        cleanup_errors: list[BaseException] = []
        # Do not rely on the launcher process group: Docker containers are
        # outside it.  A second attempt is intentional after any failure
        # before the normal cut kill, and remains label-bound.
        if args.real_qemu and not container_terminated:
            try:
                found = _kill_container(cid_path, run_id=args.run_id, trial_token=trial_token, allow_absent=True)
                if found is not None:
                    container_id = found
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            _kill(process)
        except BaseException as exc:
            cleanup_errors.append(exc)
        try:
            process.wait(timeout=10)
        except BaseException as exc:
            cleanup_errors.append(exc)
        finally:
            initial_out.close(); initial_err.close()
        if cleanup_errors:
            details = "; ".join(str(error) for error in cleanup_errors)
            raise RuntimeError(f"handoff cleanup failed explicitly: {details}") from cleanup_errors[0]
    receipts = []
    for index in (1, 2):
        recovery_env = env | {"CSER_EXPERIMENT_PHASE": "recovery", "CSER_HANDOFF_RECOVERY_INDEX": str(index)}
        recovery_dir = trial_dir / f"recovery-{index}"
        recovery_dir.mkdir()
        code, log, stderr = _run_recovery_launcher(args.recovery_guest, env=recovery_env, trial_dir=recovery_dir, timeout_seconds=args.recovery_timeout_seconds)
        if code: raise RuntimeError(f"handoff recovery {index} exited {code}: {stderr}")
        receipts.append(receipt_from_log(log, variant=args.variant, run_id=args.run_id))
    compare_recoveries(*receipts)
    endpoint_records = verify_endpoint_ledgers(trial_dir, namespace_id=args.namespace_id,
        authority_id=args.authority_id, parent_effect_id=args.effect_id, run_id=args.run_id,
        catalog_digest=args.catalog_digest, descriptor_digest=receipts[0]["descriptor_digest"])
    return {"schema_version": SCHEMA_VERSION, "variant": args.variant, "run_id": args.run_id, "trial": args.trial,
        "cutpoint": args.cutpoint, "cutpoint_id": args.cutpoint_id,
        "crash_method": "container_kill" if args.real_qemu else "pid_sigkill", "container_id": container_id,
        "scope": "logical",
        "barrier_observed": True, "barrier_acknowledged": False, "media": [str(path) for path in media],
        "recovery1": receipts[0], "recovery2": receipts[1], "endpoint_records": endpoint_records}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", required=True, choices=sorted(VARIANTS)); parser.add_argument("--run-id", required=True)
    parser.add_argument("--catalog-digest", required=True); parser.add_argument("--namespace-id", required=True); parser.add_argument("--authority-id", required=True); parser.add_argument("--effect-id", required=True)
    parser.add_argument("--trial", type=int, required=True); parser.add_argument("--cutpoint", required=True, choices=sorted(CUTPOINTS)); parser.add_argument("--cutpoint-id", type=int, required=True)
    parser.add_argument("--barrier-socket", type=Path, required=True); parser.add_argument("--trial-dir", type=Path, required=True); parser.add_argument("--metrics-jsonl", type=Path, required=True)
    parser.add_argument("--media", action="append", default=[]); parser.add_argument("--timeout-seconds", type=float, default=90); parser.add_argument("--recovery-timeout-seconds", type=float, default=150); parser.add_argument("--real-qemu", action="store_true")
    parser.add_argument("--recovery-guest", type=Path, required=True); parser.add_argument("guest", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.guest or args.guest[0] != "--": parser.error("guest command must follow --")
    args.guest = args.guest[1:]
    if args.cutpoint_id != CUTPOINTS[args.cutpoint]: parser.error("cutpoint name/id mismatch")
    if not (_HEX32.fullmatch(args.run_id) and _HEX64.fullmatch(args.catalog_digest) and _HEX32.fullmatch(args.authority_id) and _HEX32.fullmatch(args.effect_id)): parser.error("invalid experiment identity")
    try:
        _validate_timeout(args.timeout_seconds, "--timeout-seconds")
        _validate_timeout(args.recovery_timeout_seconds, "--recovery-timeout-seconds")
    except ValueError as exc:
        parser.error(str(exc))
    if args.real_qemu and (Path(args.guest[0]).resolve() != Path(__file__).with_name("qemu_boot.sh").resolve() or args.recovery_guest.resolve() != Path(__file__).with_name("qemu_boot.sh").resolve()): parser.error("real handoff trials require qemu_boot.sh")
    if args.real_qemu and args.recovery_timeout_seconds <= 130:
        parser.error("real handoff trials require recovery timeout greater than the internal 130s launcher timeout")
    try:
        row = run_trial(args); args.metrics_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.metrics_jsonl.open("a", encoding="utf-8") as handle: handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, BarrierProtocolError) as exc:
        print(f"handoff matrix controller: {exc}", file=sys.stderr); raise SystemExit(1) from exc

if __name__ == "__main__": main()
