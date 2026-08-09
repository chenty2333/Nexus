"""Focused contract checks for the matched real-QEMU handoff launcher.

These do not start QEMU.  They lock the shell boundary to the two-endpoint
CSER3 topology; bridge and endpoint protocol behavior is covered separately.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from handoff_identity import child_transport_effect_id  # noqa: E402


LAUNCHER = TOOLS / "qemu_boot.sh"
IDENTITY_ENV = {
    "CSER_EXPERIMENT_VARIANT": "cser",
    "CSER_EXPERIMENT_TRIAL_DIR": "/definitely-not-a-trial",
    "CSER_EXPERIMENT_RUN_ID": "a" * 32,
    "CSER_EXPERIMENT_CATALOG_DIGEST": "b" * 64,
    "CSER_EXPERIMENT_NAMESPACE_ID": "handoff-test",
    "CSER_EXPERIMENT_AUTHORITY_ID": "c" * 32,
    "CSER_EXPERIMENT_EFFECT_ID": "d" * 32,
}


class QemuBootHandoffTests(unittest.TestCase):
    def test_shell_syntax_is_valid(self) -> None:
        subprocess.run(["bash", "-n", str(LAUNCHER)], check=True)

    def test_invalid_lane_is_rejected_before_trial_media_is_inspected(self) -> None:
        env = os.environ | IDENTITY_ENV | {"CSER_EXPERIMENT_LANE": "wrong"}
        result = subprocess.run(["bash", str(LAUNCHER)], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid experiment lane: wrong", result.stderr)
        self.assertNotIn("trial media", result.stderr)

    def test_handoff_vnext_combination_is_rejected_before_trial_media_is_inspected(self) -> None:
        env = os.environ | IDENTITY_ENV | {
            "CSER_EXPERIMENT_LANE": "handoff",
            "CSER_EXPERIMENT_JOURNAL_VNEXT": "1",
        }
        result = subprocess.run(["bash", str(LAUNCHER)], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("handoff lane does not select the vNext journal", result.stderr)
        self.assertNotIn("trial media", result.stderr)

    def test_handoff_topology_uses_the_canonical_child_identity_and_independent_cleanup(self) -> None:
        source = LAUNCHER.read_text(encoding="utf-8")
        child = child_transport_effect_id(
            IDENTITY_ENV["CSER_EXPERIMENT_NAMESPACE_ID"], IDENTITY_ENV["CSER_EXPERIMENT_AUTHORITY_ID"],
            IDENTITY_ENV["CSER_EXPERIMENT_EFFECT_ID"], IDENTITY_ENV["CSER_EXPERIMENT_RUN_ID"],
            IDENTITY_ENV["CSER_EXPERIMENT_CATALOG_DIGEST"],
        )
        self.assertRegex(child, r"^[0-9a-f]{32}$")
        self.assertIn("from handoff_identity import child_transport_effect_id", source)
        self.assertIn("child_transport_effect_id(*sys.argv[1:])", source)
        self.assertIn('"$trial_dir/handoff-parent-endpoint.sqlite"', source)
        self.assertIn('"$trial_dir/handoff-child-endpoint.sqlite"', source)
        self.assertIn('"$trial_dir/handoff-parent-provider.sqlite"', source)
        self.assertIn('"$trial_dir/handoff-child-provider.sqlite"', source)
        self.assertIn("--handoff-cser3 --child-endpoint-port", source)
        self.assertIn("--handoff-parent-root 0x48414e44 --handoff-parent-sequence 1 --handoff-parent-component 6", source)
        self.assertIn('kill "$child_endpoint_pid"', source)
        self.assertIn('wait "${child_endpoint_pid:-}"', source)

    def test_recorded_handoff_container_has_controller_scoped_identity_labels(self) -> None:
        source = (TOOLS.parents[1] / "x").read_text(encoding="utf-8")
        self.assertIn('nexus.cser-experiment=handoff', source)
        self.assertIn('nexus.cser-run-id=$handoff_run_id', source)
        self.assertIn('nexus.cser-trial-token=$handoff_trial_token', source)
        self.assertIn('CSER_EXPERIMENT_TRIAL_TOKEN', source)

    def test_only_handoff_recovery_gets_the_extended_inner_timeout(self) -> None:
        source = (TOOLS.parents[1] / "x").read_text(encoding="utf-8")
        self.assertIn('launcher_timeout_seconds=90', source)
        self.assertIn('${CSER_EXPERIMENT_PHASE:-initial} == recovery', source)
        self.assertIn('$scheme == tool-handoff-cser || $scheme == tool-handoff-baseline', source)
        self.assertIn('launcher_timeout_seconds=130', source)
        self.assertIn('${launcher_timeout_seconds}s cargo osdk run --scheme $scheme', source)


if __name__ == "__main__":
    unittest.main()
