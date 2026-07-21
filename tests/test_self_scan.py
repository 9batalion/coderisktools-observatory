import tempfile
import unittest
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from observatory.contracts import ScanResult
from observatory.self_scan import SelfScanError, run_self_scan

DIGEST = "sha256:" + "a" * 64


def git_repo():
    root = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    (root / "README.md").write_text("clean fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
    return root


class Adapter:
    scanner_id = "self-scan-test"
    def __init__(self, findings=None):
        self.findings = findings or []
    def scan(self, target_path, target_sha):
        return ScanResult(self.scanner_id, "test", DIGEST, target_sha, "complete", self.findings, [], [])


class SelfScanTests(unittest.TestCase):
    def test_clean_self_scan_is_publishable_summary(self):
        root = git_repo()
        result = run_self_scan(root, Adapter(), DIGEST)
        self.assertEqual(result["scan_status"], "complete")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["decision"], "PUBLISH")
        self.assertEqual(result["errors"], [])

    def test_self_scan_holds_on_findings_without_raw_output(self):
        root = git_repo()
        finding = {
            "matched_text": "[REDACTED]", "line_content": "[REDACTED]",
            "fingerprint": "sha256:" + "b" * 64, "file": "README.md",
            "rule_id": "CRT-SEC-001", "severity": "high", "confidence": "confirmed",
            "category": "secret", "type": "secret",
        }
        result = run_self_scan(root, Adapter([finding]), DIGEST)
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["finding_count"], 1)
        self.assertNotIn("matched_text", result)

    def test_self_scan_rejects_non_git_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SelfScanError):
                run_self_scan(Path(tmp), Adapter(), DIGEST)


if __name__ == "__main__":
    unittest.main()
