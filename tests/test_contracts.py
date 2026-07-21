import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.contracts import (
    ContractError,
    NormalizedFinding,
    PublicationDecision,
    ScanResult,
    Target,
)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


class ContractTests(unittest.TestCase):
    def test_target_accepts_complete_github_target(self):
        target = Target.from_dict({
            "target_id": "github-owner-repo",
            "repository_url": "https://github.com/owner/repo",
            "requested_ref": "main",
            "resolved_sha": SHA,
            "source": "operator",
            "selection_reason": "bootstrap",
            "license_status": "recognized",
            "execution_allowed": False,
            "publication_mode": "public-summary",
            "status": "candidate",
        })
        self.assertEqual(target.resolved_sha, SHA)

    def test_target_rejects_moving_ref_and_bad_url(self):
        with self.assertRaises(ContractError):
            Target.from_dict({"repository_url": "https://github.com/o/r", "requested_ref": "main"})
        with self.assertRaises(ContractError):
            Target.from_dict({"repository_url": "https://user:pass@github.com/o/r", "resolved_sha": SHA})

    def test_scan_result_distinguishes_statuses_and_requires_sha(self):
        result = ScanResult.from_dict({
            "scanner_id": "test",
            "scanner_version": "1",
            "ruleset_digest": DIGEST,
            "target_sha": SHA,
            "status": "partial",
            "findings": [],
            "errors": ["timeout"],
            "warnings": [],
        })
        self.assertEqual(result.status, "partial")
        with self.assertRaises(ContractError):
            ScanResult.from_dict({"status": "clean", "target_sha": SHA})

    def test_finding_requires_evidence_for_confirmed(self):
        base = {
            "finding_id": "finding-1", "rule_id": "CRT-SECRET-001",
            "category": "secret-exposure", "severity": "high",
            "confidence": "confirmed", "visibility": "MAINTAINER_ONLY",
            "evidence_refs": [], "location": {"path": "redacted", "commit": SHA},
            "summary": "Potential credential material detected", "remediation": "Rotate it",
            "source_scanners": ["test"],
        }
        with self.assertRaises(ContractError):
            NormalizedFinding.from_dict(base)
        base["evidence_refs"] = [DIGEST]
        self.assertEqual(NormalizedFinding.from_dict(base).rule_id, "CRT-SECRET-001")

    def test_decision_rejects_override_without_reason(self):
        base = {
            "decision": "PUBLISH", "reviewer": "operator-1",
            "reason_codes": ["CONFIDENCE_THRESHOLD_MET"],
            "approved_artifacts": ["report.json"], "full_findings_public": False,
            "override": True,
        }
        with self.assertRaises(ContractError):
            PublicationDecision.from_dict(base)
        base["override_reason"] = "documented correction"
        self.assertTrue(PublicationDecision.from_dict(base).override)


if __name__ == "__main__":
    unittest.main()
