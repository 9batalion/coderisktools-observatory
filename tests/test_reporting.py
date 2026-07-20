import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.contracts import PublicationDecision, ScanResult, Target
from observatory.reporting.builder import ReportModel, build_report_bundle

SHA = "3" * 40
DIGEST = "sha256:" + "4" * 64


class ReportBuilderTests(unittest.TestCase):
    def _model(self):
        target = Target.from_dict({
            "target_id": "github-owner-repo",
            "repository_url": "https://github.com/owner/repo",
            "requested_ref": "main", "resolved_sha": SHA, "source": "operator",
            "selection_reason": "test", "license_status": "recognized",
            "execution_allowed": False, "publication_mode": "public-summary", "status": "scanned",
        })
        scan = ScanResult.from_dict({"scanner_id": "scanner", "scanner_version": "1", "ruleset_digest": DIGEST, "target_sha": SHA, "status": "complete", "findings": [], "errors": [], "warnings": []})
        decision = PublicationDecision.from_dict({"decision": "PUBLISH", "reviewer": "operator", "reason_codes": ["COMPLETE_SCAN_NO_FINDINGS"], "approved_artifacts": ["report.json"], "full_findings_public": False})
        return ReportModel(target, scan, [], decision, ["Synthetic test report"])

    def test_builds_all_core_artifacts_and_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = build_report_bundle(self._model(), Path(directory), repository_name='repo"><script>alert(1)</script>')
            names = {path.name for path in paths}
            self.assertIn("report.json", names)
            self.assertIn("index.html", names)
            self.assertIn("manifest.json", names)
            self.assertIn("checksums.txt", names)
            html = (Path(directory) / "index.html").read_text()
            self.assertNotIn("<script>alert", html)
            self.assertIn("&lt;script&gt;", html)

    def test_identical_models_produce_identical_bytes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            build_report_bundle(self._model(), Path(first), repository_name="repo")
            build_report_bundle(self._model(), Path(second), repository_name="repo")
            for name in ["report.json", "report.md", "index.html", "manifest.json", "checksums.txt"]:
                self.assertEqual((Path(first) / name).read_bytes(), (Path(second) / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
