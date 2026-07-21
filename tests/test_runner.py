import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.contracts import ScanResult
from observatory.reporting.runner import run_pipeline

DIGEST = "sha256:" + "6" * 64


class FakeAdapter:
    scanner_id = "fake-scanner"

    def scan(self, target_path, target_sha):
        return ScanResult("fake-scanner", "1", DIGEST, target_sha, "complete", [], [], [])


class FindingAdapter(FakeAdapter):
    def scan(self, target_path, target_sha):
        return ScanResult(
            "fake-scanner", "1", DIGEST, target_sha, "complete",
            [{"rule_id": "raw", "location": {"path": "config.env", "line": 1, "commit": target_sha}, "evidence": {"value": "raw-secret", "redacted": False}}],
            [], [],
        )


def fixture_repo():
    root = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    (root / "README.md").write_text("synthetic\n")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    return root, sha


class LocalRunnerTests(unittest.TestCase):
    def test_pipeline_acquires_scans_decides_and_builds_report(self):
        source, sha = fixture_repo()
        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as output:
            result = run_pipeline(source, sha, Path(work), Path(output), "https://github.com/owner/repo", "recognized", FakeAdapter(), "operator")
            self.assertEqual(result.decision.decision, "PUBLISH")
            self.assertEqual(result.scan.target_sha, sha)
            self.assertTrue((Path(output) / "manifest.json").exists())
            self.assertEqual(list(Path(work).iterdir()), [])

    def test_pipeline_holds_on_normalization_failure(self):
        source, sha = fixture_repo()
        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as output:
            result = run_pipeline(source, sha, Path(work), Path(output), "https://github.com/owner/repo", "recognized", FindingAdapter(), "operator")
            self.assertEqual(result.decision.decision, "HOLD")
            self.assertEqual(result.scan.status, "failed")
            self.assertEqual(result.findings, [])
            self.assertTrue(any(error.startswith("normalization_failed:") for error in result.scan.errors))

    def test_cli_help_exposes_scan_and_offline_options(self):
        completed = subprocess.run([sys.executable, "-m", "observatory", "--help"], env={"PYTHONPATH": "src"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        self.assertIn("scan", completed.stdout)
        self.assertIn("benchmark", completed.stdout)
        self.assertIn("self-scan", completed.stdout)
        self.assertIn("--offline", completed.stdout)


if __name__ == "__main__":
    unittest.main()
