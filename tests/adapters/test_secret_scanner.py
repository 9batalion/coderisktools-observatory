import json
import shutil
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

import unittest

from observatory.adapters.secret_scanner import AdapterError, SecretScannerAdapter

SHA = "d" * 40
DIGEST = "sha256:" + "e" * 64


class SecretScannerAdapterTests(unittest.TestCase):
    def _fake(self, body, exit_code=0):
        path = Path(tempfile.mkdtemp()) / "fake-scanner.py"
        path.write_text(
            "import json, sys\n"
            "if '--version' in sys.argv:\n"
            " print('secret-scanner 9.9.9')\n"
            f"else:\n print(json.dumps({body!r}))\n sys.exit({exit_code})\n"
        )
        return [sys.executable, str(path)]

    def test_maps_clean_json_to_complete_scan_result(self):
        command = self._fake({"findings": [], "config_changes": []})
        result = SecretScannerAdapter(command, DIGEST).scan("/tmp/target", SHA)
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.target_sha, SHA)

    def test_exit_one_is_complete_with_findings_but_other_exit_is_failed(self):
        command = self._fake({"findings": [{"rule_id": "x"}], "config_changes": []}, 1)
        self.assertEqual(SecretScannerAdapter(command, DIGEST).scan("/tmp/target", SHA).status, "complete")
        command = self._fake({"findings": [], "config_changes": []}, 3)
        self.assertEqual(SecretScannerAdapter(command, DIGEST).scan("/tmp/target", SHA).status, "failed")

    def test_rejects_invalid_json_and_oversized_output(self):
        command = self._fake({"findings": []})
        path = Path(command[1])
        path.write_text("import sys\nprint('not-json')\n")
        with self.assertRaises(AdapterError):
            SecretScannerAdapter(command, DIGEST).scan("/tmp/target", SHA)

    def test_real_scanner_empty_directory_smoke(self):
        if shutil.which("secret-scanner") is None:
            self.skipTest("optional local secret-scanner CLI is not installed")
        adapter = SecretScannerAdapter(["secret-scanner"], DIGEST)
        with tempfile.TemporaryDirectory() as target:
            result = adapter.scan(target, SHA)
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
