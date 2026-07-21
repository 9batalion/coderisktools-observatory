import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import unittest

from observatory.contracts import NormalizedFinding
from observatory.policy.engine import evaluate_publication, PolicyError

SHA = "1" * 40
FP = "sha256:" + "2" * 64


def finding(**overrides):
    data = {
        "finding_id": "finding-1", "rule_id": "CRT-SEC-001", "category": "secret-exposure",
        "severity": "high", "confidence": "confirmed", "visibility": "MAINTAINER_ONLY",
        "evidence_refs": [FP], "location": {"path": "x", "commit": SHA},
        "summary": "Potential credential material detected", "remediation": "Rotate it",
        "source_scanners": ["scanner"],
    }
    data.update(overrides)
    return NormalizedFinding.from_dict(data)


class PolicyEngineTests(unittest.TestCase):
    def test_complete_clean_scan_proposes_publish_but_not_override(self):
        decision = evaluate_publication("complete", "recognized", [], [])
        self.assertEqual(decision.decision, "PUBLISH")
        self.assertFalse(decision.override)
        self.assertIn("COMPLETE_SCAN_NO_FINDINGS", decision.reason_codes)

    def test_partial_scan_is_hold_not_clean(self):
        decision = evaluate_publication("partial", "recognized", [], ["timeout"])
        self.assertEqual(decision.decision, "HOLD")
        self.assertIn("SCAN_NOT_COMPLETE", decision.reason_codes)

    def test_active_secret_is_hold_and_unknown_license_is_hold(self):
        decision = evaluate_publication("complete", "recognized", [finding()], [])
        self.assertEqual(decision.decision, "HOLD")
        self.assertIn("ACTIVE_SECRET_REQUIRES_REVIEW", decision.reason_codes)
        decision = evaluate_publication("complete", "unknown", [], [])
        self.assertEqual(decision.decision, "HOLD")
        self.assertIn("LICENSE_UNRESOLVED", decision.reason_codes)

    def test_low_confidence_secret_is_rejected(self):
        decision = evaluate_publication("complete", "recognized", [finding(confidence="low")], [])
        self.assertEqual(decision.decision, "REJECT")
        self.assertIn("LOW_CONFIDENCE_SECRET", decision.reason_codes)

    def test_invalid_status_is_rejected_by_contract(self):
        with self.assertRaises(PolicyError):
            evaluate_publication("clean", "recognized", [], [])


if __name__ == "__main__":
    unittest.main()
