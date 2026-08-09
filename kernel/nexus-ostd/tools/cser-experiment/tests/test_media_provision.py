from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1]


class ToolDmaMediaProvisionTests(unittest.TestCase):
    def test_preparer_creates_and_revalidates_the_fixed_qemu_media_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "media"
            command = [str(TOOLS / "prepare_base_media.sh"), str(base)]
            first = subprocess.run(command, check=True, text=True, capture_output=True)
            self.assertIn("TOOL_DMA_BASE_MEDIA PASS", first.stdout)
            expected = {"journal.raw": 4 * 1024 * 1024, "outbox.raw": 4 * 1024 * 1024, "ram.raw": 1024 * 1024 * 1024}
            self.assertEqual(
                {path.name: path.stat().st_size for path in base.iterdir() if path.name.endswith(".raw")}, expected
            )
            subprocess.run(command, check=True, text=True, capture_output=True)

    def test_concurrent_first_provision_serializes_one_shared_base_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "media"
            command = [str(TOOLS / "prepare_base_media.sh"), str(base)]
            first = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            second = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            first_out, first_err = first.communicate(timeout=20)
            second_out, second_err = second.communicate(timeout=20)
            self.assertEqual((first.returncode, second.returncode), (0, 0), first_err + second_err)
            self.assertIn("TOOL_DMA_BASE_MEDIA PASS", first_out)
            self.assertIn("TOOL_DMA_BASE_MEDIA PASS", second_out)
            self.assertEqual(
                {path.name: path.stat().st_size for path in base.iterdir() if path.name.endswith(".raw")},
                {"journal.raw": 4 * 1024 * 1024, "outbox.raw": 4 * 1024 * 1024, "ram.raw": 1024 * 1024 * 1024},
            )

    def test_runner_records_and_verifies_each_trial_base_media_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); base = root / "base.img"; base.write_bytes(b"base-media-content")
            output = root / "matrix"
            subprocess.run(
                [str(TOOLS / "run_matrix.sh"), "--variant", "cser", "--output", str(output),
                 "--base-media", str(base), "--only-cutpoint", "pre_escape",
                 "--recovery-guest", str(TOOLS / "tests" / "fake_recovery_guest.py"), "--",
                 sys.executable, str(TOOLS / "tests" / "fake_barrier_guest.py")],
                check=True, cwd=TOOLS, timeout=20,
            )
            manifest = next(output.glob("*/base-media.sha256"))
            self.assertEqual(manifest.read_text(encoding="ascii"), f"{hashlib.sha256(base.read_bytes()).hexdigest()}  base.img\n")

    def test_preparer_rejects_a_wrong_sized_preexisting_medium(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "journal.raw").write_bytes(b"wrong-size")
            result = subprocess.run([str(TOOLS / "prepare_base_media.sh"), str(base)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("wrong size", result.stderr)

    def test_real_launcher_binds_cser_tpm_to_computed_catalog_and_baseline_to_blank_selector(self) -> None:
        launcher = (TOOLS / "qemu_boot.sh").read_text(encoding="utf-8")
        self.assertIn("cser-catalog-digest -- tool-dma", launcher)
        self.assertIn('"$root/scripts/provision-cser-tpm-nv.sh"', launcher)
        self.assertIn("--experiment-blank", launcher)
        self.assertIn("require_medium journal.raw", launcher)


if __name__ == "__main__":
    unittest.main()
