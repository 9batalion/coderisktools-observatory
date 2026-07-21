import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

SHA = "c" * 40
DIGEST = "sha256:" + "d" * 64
TARGET = {
    "target_id": "owner-repo", "repository_url": "https://github.com/owner/repo",
    "requested_ref": "main", "resolved_sha": SHA, "source": "operator",
    "selection_reason": "test", "license_status": "recognized",
    "execution_allowed": False, "publication_mode": "public-summary", "status": "scanned",
}
SCAN = {
    "scanner_id": "secret-scanner", "scanner_version": "1", "ruleset_digest": DIGEST,
    "target_sha": SHA, "status": "complete", "findings": [], "errors": [], "warnings": [],
}
DECISION = {
    "decision": "PUBLISH", "reviewer": "policy-engine",
    "reason_codes": ["COMPLETE_SCAN_NO_FINDINGS"],
    "approved_artifacts": ["report.json"], "full_findings_public": False,
    "override": False, "override_reason": None,
}


class ReportCommandTests(unittest.TestCase):
    def test_report_builds_bundle_and_verify_accepts_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"; target.write_text(json.dumps(TARGET))
            scan = root / "scan.json"; scan.write_text(json.dumps(SCAN))
            findings = root / "findings.json"; findings.write_text("[]")
            decision = root / "decision.json"; decision.write_text(json.dumps(DECISION))
            bundle = root / "bundle"
            env = os.environ.copy(); env["PYTHONPATH"] = "src"
            report = subprocess.run([
                sys.executable, "-m", "observatory", "report",
                "--target", str(target), "--scan", str(scan), "--findings", str(findings),
                "--decision", str(decision), "--repository-name", "owner/repo",
                "--output-dir", str(bundle),
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(report.returncode, 0, report.stderr)
            self.assertEqual(len(list(bundle.iterdir())), 8)
            verified = subprocess.run([
                sys.executable, "-m", "observatory", "verify", str(bundle), "--json",
            ], env=env, stdout=subprocess.PIPE, text=True)
            self.assertEqual(verified.returncode, 0)
            self.assertTrue(json.loads(verified.stdout)["valid"])

    def test_report_rejects_sha_mismatch_without_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"; target.write_text(json.dumps(TARGET))
            broken_scan = dict(SCAN, target_sha="e" * 40)
            scan = root / "scan.json"; scan.write_text(json.dumps(broken_scan))
            findings = root / "findings.json"; findings.write_text("[]")
            decision = root / "decision.json"; decision.write_text(json.dumps(DECISION))
            bundle = root / "bundle"
            env = os.environ.copy(); env["PYTHONPATH"] = "src"
            result = subprocess.run([
                sys.executable, "-m", "observatory", "report",
                "--target", str(target), "--scan", str(scan), "--findings", str(findings),
                "--decision", str(decision), "--repository-name", "owner/repo",
                "--output-dir", str(bundle),
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 3)
            self.assertFalse(bundle.exists())


if __name__ == "__main__":
    unittest.main()
