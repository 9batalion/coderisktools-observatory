import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

SHA = "8" * 40
FP = "sha256:" + "9" * 64


def scanner_finding(redacted=True):
    return {
        "type": "secret", "pattern_name": "TOKEN", "severity": "high",
        "file": "src/config.py", "line": 4,
        "matched_text": "[REDACTED]" if redacted else "REAL_SECRET",
        "line_content": "[REDACTED]" if redacted else "TOKEN=REAL_SECRET",
        "rule": "token", "rule_id": "CRT-SEC-001", "category": "secret",
        "confidence": "high", "remediation": "Rotate it", "fingerprint": FP,
    }


class NormalizeCommandTests(unittest.TestCase):
    def run_command(self, payload, output):
        source = Path(output).parent / "scanner.json"
        source.write_text(json.dumps(payload))
        env = os.environ.copy(); env["PYTHONPATH"] = "src"
        return subprocess.run([
            sys.executable, "-m", "observatory", "normalize",
            "--input", str(source), "--sha", SHA,
            "--scanner-id", "secret-scanner", "--output", str(output),
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_normalize_writes_redacted_finding_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "normalized.json"
            result = self.run_command({"findings": [scanner_finding()]}, output)
            self.assertEqual(result.returncode, 0)
            data = json.loads(output.read_text())
            self.assertEqual(data[0]["location"]["commit"], SHA)
            self.assertEqual(data[0]["evidence_refs"], [FP])
            self.assertNotIn("matched_text", output.read_text())

    def test_normalize_rejects_unredacted_evidence_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "normalized.json"
            result = self.run_command({"findings": [scanner_finding(False)]}, output)
            self.assertEqual(result.returncode, 3)
            self.assertFalse(output.exists())
            self.assertNotIn("REAL_SECRET", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
