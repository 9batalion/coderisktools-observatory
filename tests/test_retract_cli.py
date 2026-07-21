import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.contracts import PublicationDecision, ScanResult, Target
from observatory.publishing.pr import prepare_publication
from observatory.publishing.retract import PublicationError, create_retraction_pr, prepare_retraction
from observatory.reporting.builder import ReportModel, build_report_bundle

SHA = "e" * 40
DIGEST = "sha256:" + "2" * 64
URL = "https://github.com/owner/repo"


def make_reports_repo(root):
    target = Target.from_dict({"target_id": "owner-repo", "repository_url": URL, "requested_ref": "main", "resolved_sha": SHA, "source": "operator", "selection_reason": "test", "license_status": "recognized", "execution_allowed": False, "publication_mode": "public-summary", "status": "scanned"})
    scan = ScanResult.from_dict({"scanner_id": "scanner", "scanner_version": "1", "ruleset_digest": DIGEST, "target_sha": SHA, "status": "complete", "findings": [], "errors": [], "warnings": []})
    decision = PublicationDecision.from_dict({"decision": "PUBLISH", "reviewer": "operator", "reason_codes": ["COMPLETE_SCAN_NO_FINDINGS"], "approved_artifacts": ["report.json"], "full_findings_public": False})
    bundle = root / "bundle"
    build_report_bundle(ReportModel(target, scan, [], decision, ["test limitation"]), bundle, "owner-repo")
    repo = root / "reports"
    prepare_publication(repo, bundle, revision=2)
    return repo


class RetractionTests(unittest.TestCase):
    def test_prepare_retraction_writes_withdrawn_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = make_reports_repo(root)
            plan = prepare_retraction(repo, URL, SHA, revision=2, reason="Source evidence was superseded.", retracted_at="2026-07-21T12:00:00Z")
            payload = json.loads(plan.path.read_text())
            self.assertEqual(payload["status"], "WITHDRAWN")
            self.assertEqual(payload["head_commit"], SHA)
            self.assertEqual(payload["retracted_at"], "2026-07-21T12:00:00Z")
            with self.assertRaises(PublicationError):
                prepare_retraction(repo, URL, SHA, revision=2, reason="second")

    def test_cli_retract_stages_existing_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = make_reports_repo(root)
            env = os.environ.copy(); env["PYTHONPATH"] = "src"
            result = subprocess.run([sys.executable, "-m", "observatory", "retract", "--reports-repo", str(repo), "--repository-url", URL, "--sha", SHA, "--revision", "2", "--reason", "Withdrawn by operator.", "--timestamp", "2026-07-21T12:00:00Z"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["staged"])

    def test_retraction_pr_lifecycle_is_fail_closed_and_returns_url(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); repo = make_reports_repo(root)
            outputs = iter(["", "", "", "", "", "abc", "", "git@github.com:9batalion/coderisktools-observatory-reports.git"])
            gh = subprocess.CompletedProcess(["gh"], 0, "https://github.com/9batalion/coderisktools-observatory-reports/pull/12\n", "")
            with mock.patch("observatory.publishing.retract._run_git", side_effect=lambda *args: next(outputs)), mock.patch("observatory.publishing.retract.subprocess.run", return_value=gh):
                result = create_retraction_pr(repo, URL, SHA, revision=2, reason="Withdrawn by operator.", retracted_at="2026-07-21T12:00:00Z", branch="retract/test-r2")
            self.assertEqual(result.url, "https://github.com/9batalion/coderisktools-observatory-reports/pull/12")
            self.assertEqual(result.commit, "abc")


if __name__ == "__main__":
    unittest.main()
