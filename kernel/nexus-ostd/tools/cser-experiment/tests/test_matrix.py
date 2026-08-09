from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, unittest
from pathlib import Path
TOOLS = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(TOOLS))
from matrix_controller import _CURRENT_GUEST_RUN_ID, _RECOVERY_METRICS_PREFIX, _metric, _recovery_metrics_from_serial, observe_barriers
from matrix_protocol import BarrierProtocolError, barrier, parse_barrier
from summarize_metrics import load_metrics, summarize

class MatrixProtocolTests(unittest.TestCase):
    def test_barrier_binds_exact_run_and_cutpoint(self) -> None:
        value = barrier("a" * 32, 2)
        parse_barrier(value, expected_run_id="a" * 32, expected_cutpoint=2)
        with self.assertRaises(BarrierProtocolError): parse_barrier(value, expected_run_id="b" * 32, expected_cutpoint=2)

    def test_target_barrier_is_closed_without_ack(self) -> None:
        host, guest = socket.socketpair()
        try:
            guest.sendall(barrier("a" * 32, 1))
            self.assertFalse(observe_barriers(host, "a" * 32, 1, pass_through=False))
            self.assertEqual(guest.recv(1024), b"")
        finally:
            host.close(); guest.close()

    def test_repeated_or_out_of_order_barrier_fails_closed(self) -> None:
        host, guest = socket.socketpair()
        try:
            guest.sendall(barrier("a" * 32, 2))
            with self.assertRaises(BarrierProtocolError): observe_barriers(host, "a" * 32, 3, pass_through=False)
        finally:
            host.close(); guest.close()

    def test_recovery_metrics_must_be_one_guest_serial_marker_with_matching_identity(self) -> None:
        marker = (
            b'TOOL_DMA_RECOVERY_METRICS {"invariants_ok":true,"run_id":"'
            + b"a" * 32
            + b'","terminal":true,"variant":"cser","retired_by_evidence":1,"retained_claims":0,"reconciliation_delay_ms":null,"gate_rejections":null,"reconciliation_steps":1,"reconciliation_delay_unit":"unmeasured"}\n'
        )
        result = _recovery_metrics_from_serial(marker, variant="cser", run_id="a" * 32)
        self.assertTrue(result["terminal"])
        self.assertTrue(
            _recovery_metrics_from_serial(b"\r" + marker, variant="cser", run_id="a" * 32)["terminal"]
        )
        with self.assertRaises(ValueError):
            _recovery_metrics_from_serial(b"", variant="cser", run_id="a" * 32)
        with self.assertRaises(ValueError):
            _recovery_metrics_from_serial(marker, variant="baseline", run_id="a" * 32)
        with self.assertRaises(ValueError):
            _recovery_metrics_from_serial(marker + marker, variant="cser", run_id="a" * 32)

    def test_current_real_guest_identity_is_the_explicit_42_value(self) -> None:
        self.assertEqual(_CURRENT_GUEST_RUN_ID, "42" * 16)

    def test_recovery_terminal_requires_measured_counters_and_explicit_unmeasured_fields(self) -> None:
        base = {
            "invariants_ok": True, "run_id": "a" * 32, "terminal": True, "variant": "cser",
            "retired_by_evidence": 1, "retained_claims": 0,
            "reconciliation_delay_ms": None, "gate_rejections": None,
            "reconciliation_steps": 1, "reconciliation_delay_unit": "unmeasured",
        }
        serial = _RECOVERY_METRICS_PREFIX + json.dumps(base) + "\n"
        self.assertEqual(_recovery_metrics_from_serial(serial.encode(), variant="cser", run_id="a" * 32)["retired_by_evidence"], 1)
        for field, bad in (("retired_by_evidence", -1), ("retained_claims", True), ("reconciliation_delay_ms", 0), ("gate_rejections", 1), ("reconciliation_steps", -1), ("reconciliation_delay_unit", "ms")):
            malformed = dict(base); malformed[field] = bad
            with self.assertRaises(ValueError):
                _recovery_metrics_from_serial((_RECOVERY_METRICS_PREFIX + json.dumps(malformed) + "\n").encode(), variant="cser", run_id="a" * 32)

    def test_authoritative_recovery_metrics_win_over_initial_host_file(self) -> None:
        recovery = {
            "retired_by_evidence": 4, "retained_claims": 0,
            "reconciliation_delay_ms": None, "gate_rejections": None,
            "reconciliation_steps": 7, "reconciliation_delay_unit": "unmeasured",
        }
        row = _metric(
            run_id="a" * 32, variant="cser", trial=1, cutpoint="post_register", cutpoint_id=2,
            crash_method="pid_sigkill", trial_dir=Path("/trial"), media=[],
            guest={"retired_by_evidence": 99, "retained_claims": 99, "reconciliation_delay_ms": 99, "gate_rejections": 99, "reconciliation_steps": 99, "reconciliation_delay_unit": "ms"},
            recovery=recovery, recovery_metrics_authoritative=True, container_id=None,
        )
        self.assertEqual(row["metrics_source"], "recovery_terminal")
        self.assertEqual({key: row[key] for key in recovery}, recovery)

    def test_summary_preserves_explicitly_unmeasured_terminal_fields(self) -> None:
        row = _metric(
            run_id="a" * 32, variant="cser", trial=1, cutpoint="post_register", cutpoint_id=2,
            crash_method="pid_sigkill", trial_dir=Path("/trial"), media=[], guest={},
            recovery={
                "retired_by_evidence": 4, "retained_claims": 0,
                "reconciliation_delay_ms": None, "gate_rejections": None,
                "reconciliation_steps": 1, "reconciliation_delay_unit": "unmeasured",
            },
            recovery_metrics_authoritative=True, container_id=None,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metrics.jsonl"
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            summary = summarize(load_metrics(path))["variants"]["cser"]
        self.assertEqual(summary["measured_trials"]["retired_by_evidence"], 1)
        self.assertEqual(summary["measured_trials"]["reconciliation_delay_ms"], 0)
        self.assertIsNone(summary["sums"]["reconciliation_delay_ms"])
        self.assertEqual(summary["measured_trials"]["gate_rejections"], 0)

    def test_summary_rejects_duplicate_rows_and_mismatched_arm_coverage(self) -> None:
        def row(variant: str, cutpoint: str, cutpoint_id: int) -> dict:
            return _metric(
                run_id="a" * 32, variant=variant, trial=1,
                cutpoint=cutpoint, cutpoint_id=cutpoint_id,
                crash_method="pid_sigkill", trial_dir=Path("/trial"), media=[], guest={},
                recovery={
                    "retired_by_evidence": 2, "retained_claims": 0,
                    "reconciliation_delay_ms": None, "gate_rejections": None,
                    "reconciliation_steps": 1, "reconciliation_delay_unit": "unmeasured",
                },
                recovery_metrics_authoritative=True, container_id=None,
            )

        first = row("cser", "pre_escape", 1)
        with self.assertRaises(ValueError):
            summarize([first, dict(first)])
        with self.assertRaises(ValueError):
            summarize([first, row("baseline", "post_register", 2)])

class MatrixControllerIntegrationTests(unittest.TestCase):
    @staticmethod
    def _proc_identity(pid: int) -> tuple[str, str] | None:
        try:
            fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rpartition(")")[2].split()
        except FileNotFoundError:
            return None
        return fields[0], fields[19]  # state, then Linux proc stat field 22

    def test_launcher_output_streams_past_pipe_capacity_before_barrier(self) -> None:
        """A noisy launcher must still reach the barrier before its crash.

        This is deliberately larger than the typical pipe capacity on Linux.
        If matrix_controller changes back to an unread stdout/stderr PIPE, the
        fake guest blocks before binding COM3 and this controller invocation
        times out instead of producing a recovery row.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); trial_dir = root / "trial"; media = trial_dir / "media"
            media.mkdir(parents=True); image = media / "fresh.img"; image.write_bytes(b"fresh media")
            env = os.environ.copy(); env["CSER_EXPERIMENT_EMIT_BYTES"] = str(1_200_000)
            subprocess.run(
                [sys.executable, str(TOOLS / "matrix_controller.py"), "--variant", "cser", "--run-id", "a" * 32,
                 "--trial", "1", "--cutpoint", "pre_escape", "--cutpoint-id", "1",
                 "--barrier-socket", str(trial_dir / "com3-crash.sock"), "--trial-dir", str(trial_dir),
                 "--prepared-trial-dir", "--metrics-jsonl", str(root / "metrics.jsonl"), "--media", str(image),
                 "--recovery-guest", str(TOOLS / "tests" / "fake_recovery_guest.py"), "--",
                 sys.executable, str(TOOLS / "tests" / "fake_barrier_guest.py")],
                check=True, cwd=TOOLS, timeout=20, env=env,
            )
            self.assertGreater((trial_dir / "initial.stdout.log").stat().st_size, 1_000_000)
            self.assertGreater((trial_dir / "initial.stderr.log").stat().st_size, 1_000_000)

    def test_recovery_output_streams_past_pipe_capacity_and_parses_terminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); trial_dir = root / "trial"; media = trial_dir / "media"
            media.mkdir(parents=True); image = media / "fresh.img"; image.write_bytes(b"fresh media")
            env = os.environ.copy()
            env.update({"CSER_EXPERIMENT_RECOVERY_EMIT_BYTES": str(1_200_000), "CSER_EXPERIMENT_RECOVERY_SERIAL": "1"})
            subprocess.run(
                [sys.executable, str(TOOLS / "matrix_controller.py"), "--variant", "cser", "--run-id", "b" * 32,
                 "--trial", "1", "--cutpoint", "pre_escape", "--cutpoint-id", "1",
                 "--barrier-socket", str(trial_dir / "com3-crash.sock"), "--trial-dir", str(trial_dir),
                 "--prepared-trial-dir", "--metrics-jsonl", str(root / "metrics.jsonl"), "--media", str(image),
                 "--recovery-guest", str(TOOLS / "tests" / "fake_recovery_guest.py"), "--recovery-output-metrics", "--",
                 sys.executable, str(TOOLS / "tests" / "fake_barrier_guest.py")],
                check=True, cwd=TOOLS, timeout=20, env=env,
            )
            self.assertGreater((trial_dir / "recovery.stdout.log").stat().st_size, 1_000_000)
            self.assertGreater((trial_dir / "recovery.stderr.log").stat().st_size, 1_000_000)
            row = load_metrics(root / "metrics.jsonl")[0]
            self.assertEqual(row["metrics_source"], "recovery_terminal")
            self.assertEqual(row["retired_by_evidence"], 1)

    def test_recovery_timeout_kills_its_process_group_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); trial_dir = root / "trial"; media = trial_dir / "media"; child_file = root / "child"
            media.mkdir(parents=True); image = media / "fresh.img"; image.write_bytes(b"fresh media")
            env = os.environ.copy()
            env.update({
                "CSER_EXPERIMENT_RECOVERY_SPAWN_LONG_CHILD": "1",
                "CSER_EXPERIMENT_RECOVERY_CHILD_FILE": str(child_file),
            })
            result = subprocess.run(
                [sys.executable, str(TOOLS / "matrix_controller.py"), "--variant", "cser", "--run-id", "c" * 32,
                 "--trial", "1", "--cutpoint", "pre_escape", "--cutpoint-id", "1",
                 "--barrier-socket", str(trial_dir / "com3-crash.sock"), "--trial-dir", str(trial_dir),
                 "--prepared-trial-dir", "--metrics-jsonl", str(root / "metrics.jsonl"), "--media", str(image),
                 "--recovery-guest", str(TOOLS / "tests" / "fake_recovery_guest.py"), "--recovery-timeout-seconds", "0.2", "--",
                 sys.executable, str(TOOLS / "tests" / "fake_barrier_guest.py")],
                cwd=TOOLS, timeout=20, env=env, text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recovery stage exceeded", result.stderr)
            pid_text, starttime = child_file.read_text(encoding="ascii").split()
            pid = int(pid_text)
            # Compare the proc starttime as well as PID: a rapid PID recycle is
            # evidence that our exact descendant is gone, not a false success.
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                identity = self._proc_identity(pid)
                if identity is None or identity[1] != starttime:
                    break
                time.sleep(0.02)
            else:
                self.fail(f"recovery descendant {pid} remained after timeout cleanup")

    def test_real_qemu_recovery_budget_cannot_race_internal_launcher_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [str(TOOLS / "run_qemu_matrix.sh"), "--variant", "cser", "--output", str(Path(temporary) / "out"),
                 "--base-media", str(Path(temporary) / "unneeded.raw"), "--recovery-timeout-seconds", "90"],
                cwd=TOOLS, text=True, capture_output=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("recovery timeout must exceed", result.stderr)

    def test_fake_guest_is_killed_only_after_bound_barrier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); metrics = root / "metrics.jsonl"
            cutpoints = ("pre_escape", "post_register", "post_endpoint_apply", "post_effect_fact", "post_quiescence", "pre_discharge", "post_discharge")
            for target, cutpoint in enumerate(cutpoints, 1):
                trial_dir = root / f"trial-{target}"; media = trial_dir / "media"; media.mkdir(parents=True); image = media / "fresh.img"; image.write_bytes(b"fresh media")
                subprocess.run([sys.executable, str(TOOLS / "matrix_controller.py"), "--variant", "cser", "--run-id", f"{target:032x}", "--trial", "1", "--cutpoint", cutpoint, "--cutpoint-id", str(target), "--barrier-socket", str(trial_dir / "com3-crash.sock"), "--trial-dir", str(trial_dir), "--prepared-trial-dir", "--metrics-jsonl", str(metrics), "--media", str(image), "--recovery-guest", str(TOOLS / "tests" / "fake_recovery_guest.py"), "--", sys.executable, str(TOOLS / "tests" / "fake_barrier_guest.py")], check=True, cwd=TOOLS, timeout=20)
            rows = load_metrics(metrics)
            self.assertEqual(len(rows), 7); self.assertEqual([row["cutpoint_id"] for row in rows], list(range(1, 8))); self.assertTrue(all(row["barrier_observed"] for row in rows)); self.assertTrue(all(not row["barrier_acknowledged"] for row in rows)); self.assertTrue(all(row["completion_state"] == "recovery_verified" for row in rows)); self.assertTrue(all(row["recovery"]["retained_claims"] == 0 for row in rows)); self.assertTrue(all(row["crash_method"] == "pid_sigkill" for row in rows)); self.assertTrue(all(row["permanent_retention"] is None for row in rows)); self.assertTrue(all(row["admin_disposition"] is None for row in rows)); self.assertTrue(all(Path(row["media"][0]).exists() for row in rows)); self.assertEqual(summarize(rows)["variants"]["baseline"]["trials"], 0)
if __name__ == "__main__": unittest.main()
