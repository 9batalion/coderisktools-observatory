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

    def test_rejects_invalid_scanner_version(self):
        command = self._fake({"findings": []})
        Path(command[1]).write_text("import sys\nif '--version' in sys.argv:\n sys.stdout.write('scanner\\nversion\\n')\nelse:\n print('{}')\n")
        with self.assertRaises(AdapterError):
            SecretScannerAdapter(command, DIGEST).version()

    def test_rejects_non_hex_ruleset_digest(self):
        with self.assertRaises(AdapterError):
            SecretScannerAdapter(["secret-scanner"], "sha256:" + "g" * 64)
        with self.assertRaises(AdapterError):
            SecretScannerAdapter(["secret-scanner"], "SHA256:" + "e" * 64)

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

    def test_timeout_is_a_failed_scan_result_with_diagnostic(self):
        path = Path(tempfile.mkdtemp()) / "slow-scanner.py"
        path.write_text(
            "import sys, time\n"
            "if '--version' in sys.argv: print('secret-scanner 9.9.9')\n"
            "else: time.sleep(0.2)\n"
        )
        result = SecretScannerAdapter([sys.executable, str(path)], DIGEST, timeout_seconds=0.2).scan('/tmp/target', SHA)
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.errors, ['scanner_timeout'])

    def test_profiles_have_increasing_resource_limits(self):
        small = SecretScannerAdapter.profile('small')
        medium = SecretScannerAdapter.profile('medium')
        large = SecretScannerAdapter.profile('large')
        self.assertLess(small.timeout_seconds, medium.timeout_seconds)
        self.assertLess(medium.timeout_seconds, large.timeout_seconds)
        self.assertLess(small.max_output_bytes, medium.max_output_bytes)

    def test_explicit_profile_is_applied(self):
        command = self._fake({"findings": [], "config_changes": []})
        adapter = SecretScannerAdapter(command, DIGEST, profile='large')
        adapter.scan('/tmp/target', SHA)
        self.assertEqual(adapter.active_profile, 'large')

    def test_auto_profile_uses_tree_size(self):
        with tempfile.TemporaryDirectory() as target:
            for index in range(3):
                Path(target, f'file-{index}.txt').write_text('x' * 10)
            self.assertEqual(SecretScannerAdapter.profile_for_target(target).name, 'small')

    def test_relativizes_only_paths_inside_target(self):
        with tempfile.TemporaryDirectory() as target:
            findings = [{"file": str(Path(target) / "config.env")}, {"file": "/outside/config.env"}]
            normalized = SecretScannerAdapter._relative_finding_paths(findings, target)
        self.assertEqual(normalized[0]["file"], "config.env")
        self.assertEqual(normalized[1]["file"], "/outside/config.env")

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
