from __future__ import annotations

import subprocess
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
            self.assertEqual({path.name: path.stat().st_size for path in base.iterdir()}, expected)
            subprocess.run(command, check=True, text=True, capture_output=True)

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
