import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

SHA = "a" * 40
SCAN = {
    "scanner_id": "secret-scanner", "scanner_version": "1.0",
    "ruleset_digest": "sha256:" + "b" * 64, "target_sha": SHA,
    "status": "complete", "findings": [], "errors": [], "warnings": [],
}


class DecideCommandTests(unittest.TestCase):
    def run_decide(self, scan, findings, license_status="recognized"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "scan.json"
            findings_path = root / "findings.json"
            output_path = root / "decision.json"
            scan_path.write_text(json.dumps(scan))
            findings_path.write_text(json.dumps(findings))
            env = os.environ.copy(); env["PYTHONPATH"] = "src"
            return subprocess.run([
                sys.executable, "-m", "observatory", "decide",
                "--scan", str(scan_path), "--findings", str(findings_path),
                "--license-status", license_status, "--output", str(output_path),
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), output_path.read_text() if output_path.exists() else None

    def test_clean_complete_scan_writes_publish_decision(self):
        result, output = self.run_decide(SCAN, [])
        self.assertEqual(result.returncode, 0)
        decision = json.loads(output)
        self.assertEqual(decision["decision"], "PUBLISH")
        self.assertEqual(decision["reviewer"], "policy-engine")

    def test_invalid_scan_fails_closed_without_decision_output(self):
        broken = dict(SCAN, status="partial")
        result, output = self.run_decide(broken, [], license_status="unknown")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(output)["decision"], "HOLD")


if __name__ == "__main__":
    unittest.main()
